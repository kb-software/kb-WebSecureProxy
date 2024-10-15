/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
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
#define COLL_CMA_SUFFIX     "/ck_coll"
#define MGMT_CMA_SUFFIX     "/ck_mgmt"
#define STOR_CMA_SUFFIX     "/ck_stor"

#define CK_SCRIPT_PREFACE   "HOB_set"
#define CK_SCRIPT_SEMICOLON "HOBscol"
#define CK_DELETE_TIME      "Thu, 01 Jan 1970 01:00:00 UTC"

#define DEF_CK_HASH_LOAD    0.75
#define DEF_CK_RESIZE       2

#define CK_HASH_TABLE_FILE  "ck_hash_table.txt"
#define CK_MGMT_TABLE_FILE  "ck_mgmt_table.txt"
#define CK_MEM_TABLE_FILE   "ck_memory_table.txt"
#define CK_COOKIE_IN_FILE   "ck_cookie_input.txt"

#ifndef HL_UNIX
    #define LOGFILE_PATH "..\\log\\"
#else
    #define LOGFILE_PATH "../log/"
#endif

/*+---------------------------------------------------------------------+*/
/*| helper variables:                                                   |*/
/*+---------------------------------------------------------------------+*/
struct dsd_capacity {
    int in_free;                                // count free entries
    int in_capacity;                            // element capacity in cma
};

struct dsd_ck_hash {
    bool         bo_occupied;                       // sign if this structure is in use
    unsigned int uin_hash;                          // hash over user and host
    char         rch_host[CK_MAX_HOST_LEN];         // host "www.hob.de/test1/test2/"
    int          in_points_to;                      // pointer to position in ds_cookie_mgmt_table
    int          in_next_in_rest;                   // pointer to next in rest with equal hash!
};

struct dsd_ck_mgmt {
    bool         bo_occupied;                       // sign if this structure is in use
    int          in_occ_indices;                    // count oocupied indices in rin_indices
    int          rin_indices[CK_MAX_PER_DOMAIN];    // links to cookies in ds_cookie_memory
    int          in_par_domain;                     // pointer to parent element domain (old: father)
    int          in_par_path;                       // pointer to parent element path   (old: mother)
    int          in_count_childs;                   // count child elements
};

#include <time.h>

struct dsd_ck_stor {
    int         in_length;                      // 0 = empty!
    char        rch_cookie[CK_MEM_SIZE];        // name=value
    char        rch_domain[CK_MAX_DOMAIN_LEN];  // domain of cookie "www.hob.de"
    char        rch_path  [CK_MAX_PATH_LEN];    // path of cooke "/path1/path2/"
    time_t      t_expires;                      // -1 = delete at logout
    bool        bo_secure;                      // true = cookie only for secure connections
    int         in_next;                        // next cookie mem (if larger than CK_MEM_SIZE)
};

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include "ds_cookie.h"
#define USE_COOKIE_VECTOR
#include <ds_hvector2.h>
#include "ds_ck_mgmt.h"
#include <align.h>
#include <hob-xslunic1.h>

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_ck_mgmt::ds_ck_mgmt()
{
    adsc_wsp_helper = NULL;
    boc_trace       = false;

    dsc_hash_cma.chrc_name[0] = 0;
    dsc_hash_cma.avc_handle   = NULL;
    dsc_hash_cma.adsc_cap     = NULL;
    dsc_hash_cma.bo_write     = false;
    dsc_hash_cma.in_def_elem  = DEFAULT_SIZE_HASH_CMA;
    dsc_hash_cma.in_size_elem = ALIGN_INT( sizeof(dsd_ck_hash) );

    dsc_coll_cma.chrc_name[0] = 0;
    dsc_coll_cma.avc_handle   = NULL;
    dsc_coll_cma.adsc_cap     = NULL;
    dsc_coll_cma.bo_write     = false;
    dsc_coll_cma.in_def_elem  = DEFAULT_SIZE_COLL_CMA;
    dsc_coll_cma.in_size_elem = ALIGN_INT( sizeof(dsd_ck_hash) );

    dsc_mgmt_cma.chrc_name[0] = 0;
    dsc_mgmt_cma.avc_handle   = NULL;
    dsc_mgmt_cma.adsc_cap     = NULL;
    dsc_mgmt_cma.bo_write     = false;
    dsc_mgmt_cma.in_def_elem  = DEFAULT_SIZE_MGMT_CMA;
    dsc_mgmt_cma.in_size_elem = ALIGN_INT( sizeof(dsd_ck_mgmt) );

    dsc_stor_cma.chrc_name[0] = 0;
    dsc_stor_cma.avc_handle   = NULL;
    dsc_stor_cma.adsc_cap     = NULL;
    dsc_stor_cma.bo_write     = false;
    dsc_stor_cma.in_def_elem  = DEFAULT_SIZE_STOR_CMA;
    dsc_stor_cma.in_size_elem = ALIGN_INT( sizeof(dsd_ck_stor) );
    
    dsc_cache.dsc_domain.m_setup( NULL );
    dsc_cache.dsc_path.m_setup  ( NULL );
    ds_trace_path.m_setup       ( NULL );
} // end of ds_ck_mgmt::ds_ck_mgmt


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_ck_mgmt::m_init
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
} // end of ds_ck_mgmt::m_init


/**
 * function ds_ck_mgmt::m_set_cookie
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
bool ds_ck_mgmt::m_set_cookie( const char* ach_cookie, int in_len_cookie,
                               const char* ach_domain, int in_len_domain,
                               const char* ach_path,   int in_len_path,
                               const char* ach_cmabase                   )
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
    if (    ach_domain  == NULL || in_len_domain < 1
         || ach_path    == NULL || in_len_path   < 1
         || ach_path[0] != '/'                       ) {
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
    bo_ret = m_prepare( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // set requested host url:
    //------------------------------------------------
    dsl_cookie.m_set_req_host( ach_domain, in_len_domain,
                               ach_path,   in_len_path   );

    while ( in_pos < in_len_cookie ) {
        //--------------------------------------------
        // get single cookie:
        //--------------------------------------------
        m_get_single_cookie( ach_cookie, in_len_cookie, in_pos, &in_single_len );
        
        //--------------------------------------------
        // parse imcomming cookie:
        //--------------------------------------------
        bo_ret = dsl_cookie.m_parse_cookie( &ach_cookie[in_pos], in_single_len );
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

    
    //------------------------------------------------
    // finish cmas:
    //------------------------------------------------
    m_finish();

    return bo_success;
} // end of ds_ck_mgmt::m_set_cookie


/**
 * function ds_ck_mgmt::m_set_script_cookie
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
bool ds_ck_mgmt::m_set_script_cookie( const char* ach_cookie, int in_len_cookie,
                                      const char* ach_domain, int in_len_domain,
                                      const char* ach_path,   int in_len_path,
                                      const char* ach_cmabase                    )
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
    if (    ach_domain  == NULL || in_len_domain < 1
         || ach_path    == NULL || in_len_path   < 1
         || ach_path[0] != '/'                       ) {
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
    bo_ret = m_prepare( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // set requested host url:
    //------------------------------------------------
    dsl_cookie.m_set_req_host( ach_domain, in_len_domain,
                               ach_path,   in_len_path   );

    while ( in_pos < in_len_cookie ) {
        //--------------------------------------------
        // get single cookie:
        //--------------------------------------------
        ds_ck_str = m_get_single_script_cookie( ach_cookie, in_len_cookie,
                                                &in_pos, &ds_prefix       );
        
        //--------------------------------------------
        // add srcipt cookie to delete list:
        //--------------------------------------------
        dsc_sc_cookies.m_add( ds_prefix );

        //--------------------------------------------
        // parse imcomming cookie:
        //--------------------------------------------
        bo_ret = dsl_cookie.m_parse_cookie( ds_ck_str.m_get_ptr(),
                                            ds_ck_str.m_get_len() );
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

    //------------------------------------------------
    // finish cmas:
    //------------------------------------------------
    m_finish();

    return bo_success;
} // end of ds_ck_mgmt::m_set_script_cookie


/**
 * function ds_ck_mgmt::m_rm_script_cookies
 *
 * @return  ds_hvector2<ds_hstring>
*/
ds_hvector2<ds_hstring> ds_ck_mgmt::m_rm_script_cookies()
{
    // initialize some variables:
    ds_hvector2<ds_hstring> ds_rm_cookies( adsc_wsp_helper );
    ds_hstring              ds_rm_cookie ( adsc_wsp_helper );
    int                     in_index;

    for ( in_index = 0; in_index < (int)dsc_sc_cookies.m_size(); in_index++ ) {
        ds_rm_cookie.m_write( dsc_sc_cookies[in_index].m_get_ptr(),
                               dsc_sc_cookies[in_index].m_get_len() );
        ds_rm_cookie.m_write( "=delete; expires=" );
        ds_rm_cookie.m_write( CK_DELETE_TIME );
        ds_rm_cookie.m_write( "; path=/" );

        ds_rm_cookies.m_add( ds_rm_cookie );
        ds_rm_cookie.m_reset();
    }

    dsc_sc_cookies.m_clear();


    return ds_rm_cookies;
} // end of ds_ck_mgmt::m_rm_script_cookies


/**
 * function ds_ck_mgmt::m_set_cookie
 * get cookies for current user for requested url
 *
 * @param[in]   const char*             ach_domain          pointer to requested domain
 * @param[in]   int                     in_len_domain       length of requested domain
 * @param[in]   const char*             ach_path            pointer to requested path
 * @param[in]   int                     in_len_path         length of requested path
 * @param[in]   const char*             ach_cmabase         base cma name
 * @return      ds_hvector2<ds_cookie>                      chain of found cookies
*/
ds_hvector2<ds_cookie> ds_ck_mgmt::m_get_cookies( const char* ach_domain, int in_len_domain,
                                                  const char* ach_path,   int in_len_path,
                                                  const char* ach_cmabase                    )
{
    // initialize some variables:
    bool                   bo_ret;                          // return from several function calls
    int                    in_pos_mgmt;                     // position in mgmt table
    int                    in_pos;                          // working variable
    ds_cookie              dsl_cookie ( adsc_wsp_helper );  // working variable
    ds_hvector2<int>       ds_pos_stor( adsc_wsp_helper );  // positions in storage table
    ds_hvector2<ds_cookie> ds_cookies ( adsc_wsp_helper );  // our return value


    //------------------------------------------------
    // check input data:
    //------------------------------------------------
    if (    ach_domain  == NULL || in_len_domain < 1
         || ach_path    == NULL || in_len_path   < 1
         || ach_path[0] != '/'                       ) {
        return ds_cookies;
    }

    //------------------------------------------------
    // remove filename from path:
    //------------------------------------------------
    for ( ; in_len_path > 0; in_len_path-- ) {
        if ( ach_path[in_len_path - 1] == '/' ) {
            break;
        }
    }
    
    //------------------------------------------------
    // have a look inside getcookies cache:
    //------------------------------------------------
    if ( dsc_cache.dsc_cookies.m_empty() == false ) {
        if (    dsc_cache.dsc_domain.m_equals( ach_domain, in_len_domain, true ) == true
             && dsc_cache.dsc_path.m_equals  ( ach_path,   in_len_path,   true ) == true ) {
            return dsc_cache.dsc_cookies;
        }
        m_clear_cache();
    }

    //------------------------------------------------
    // prepare cmas:
    //------------------------------------------------
    bo_ret = m_prepare( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // find first subdomain/subpath entry in hash:
    //------------------------------------------------
    in_pos_mgmt = m_get_first_subentry( ach_domain, in_len_domain,
                                        ach_path,   in_len_path    );
    if ( in_pos_mgmt > -1 ) {
        //--------------------------------------------
        // get pointers to storage table:
        //--------------------------------------------
        ds_pos_stor = m_mgmt_points_to( in_pos_mgmt, true );
        if ( ds_pos_stor.m_empty() == false ) {
            //----------------------------------------
            // get cookies itself:
            //----------------------------------------
            for ( in_pos = 0; in_pos < (int)ds_pos_stor.m_size(); in_pos++ ) {
                bo_ret = m_get_ck_from_stor( ds_pos_stor[in_pos], &dsl_cookie );
                if ( bo_ret == true ) {
                    dsc_cache.dsc_cookies.m_add( dsl_cookie );
                }
                dsl_cookie.m_reset();
            }
        }
    }

    //------------------------------------------------
    // finish cmas:
    //------------------------------------------------
    m_finish();

    //------------------------------------------------
    // cache domain and path:
    //------------------------------------------------
    dsc_cache.dsc_domain.m_write( ach_domain, in_len_domain );
    dsc_cache.dsc_path.m_write  ( ach_path,   in_len_path   );

    return dsc_cache.dsc_cookies;
} // end of ds_ck_mgmt::m_get_cookies


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_ck_mgmt::m_delete_cookie
 * delete a cookie from storage position
 *
 * @param[in]   int     in_stor_pos             position in storage table
 * @return      bool    
*/
bool ds_ck_mgmt::m_delete_cookie( int in_stor_pos )
{
    // initialize some variables:
    bool             bo_ret;                        // return from several function calls
    int              in_index;                      // loop variable
    ds_hvector2<int> ds_hashs( adsc_wsp_helper );   // entries in hash table

    //------------------------------------------------
    // delete storage entry:
    //------------------------------------------------
    bo_ret = m_delete_stor( in_stor_pos );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // delete managment entries:
    //------------------------------------------------
    ds_hashs = m_delete_mgmt( in_stor_pos );

    //------------------------------------------------
    // delete hash entries:
    //------------------------------------------------
    for ( in_index = 0; in_index < (int)ds_hashs.m_size(); in_index++ ) {
        bo_ret &= m_delete_hash( ds_hashs[in_index] );
    }

    return bo_ret;
} // end of ds_ck_mgmt::m_delete_cookie


/**
 * function ds_ck_mgmt::m_delete_stor
 *
 * @param[in]   int     in_index
 * @return      bool                true = success
*/
bool ds_ck_mgmt::m_delete_stor( int in_index )
{
    // initialize some variables:
    bool         bo_ret;
    dsd_ck_stor* ads_stor;

    //------------------------------------------------
    // open storage cma for writing:
    //------------------------------------------------
    bo_ret = m_open_cma( &dsc_stor_cma, true );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // get requested element:
    //------------------------------------------------
    bo_ret = m_get_element( &dsc_stor_cma, in_index, &ads_stor );
    if (    bo_ret   == false
         || ads_stor == NULL  ) {
        return false;
    }

    //------------------------------------------------
    // free entry:
    //------------------------------------------------
    ads_stor->in_length = 0;
    dsc_stor_cma.adsc_cap->in_free++;    
    return true;
} // end of ds_ck_mgmt::m_delete_stor


/**
 * function ds_ck_mgmt::m_delete_mgmt
 *
 * @param[in]   int                 in_points_to
 * @return      ds_hvector2<int>                    positions to search in hashtable
*/
ds_hvector2<int> ds_ck_mgmt::m_delete_mgmt( int in_points_to )
{
    // initialize some variables:
    bool                bo_ret;
    int                 in_pos;
    int                 in_par_domain;
    int                 in_par_path;
    dsd_ck_mgmt*        ads_mgmt;
    ds_hvector2<int>    ds_positions( adsc_wsp_helper );

    //------------------------------------------------
    // open managment cma for writing:
    //------------------------------------------------
    bo_ret = m_open_cma( &dsc_mgmt_cma, true );
    if ( bo_ret == false ) {
        return ds_positions;
    }

    //------------------------------------------------
    // search entry which point to in_points_to:
    //------------------------------------------------
    in_pos = m_get_mgmt_from_stor( in_points_to );
    bo_ret = m_get_element( &dsc_mgmt_cma, in_pos, &ads_mgmt );
    if (    in_pos    < 0
         || bo_ret   == false 
         || ads_mgmt == NULL  ) {
        return ds_positions;
    }

    //------------------------------------------------
    // remove pointer to storage:
    //------------------------------------------------
    bo_ret = m_mgmt_rm_index( ads_mgmt, in_points_to );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // remove parent elements:
    //------------------------------------------------
    in_par_path = in_pos;
    while (    in_par_path            > -1
            && bo_ret                == true
            && ads_mgmt              != NULL
            && ads_mgmt->bo_occupied == true ) {
        in_par_domain = ads_mgmt->in_par_domain;
        bo_ret = m_get_element( &dsc_mgmt_cma, in_par_domain, &ads_mgmt );

        while (    in_par_domain          > -1
                && bo_ret                == true
                && ads_mgmt              != NULL
                && ads_mgmt->bo_occupied == true ) {
            // decrease child counter:
            if ( ads_mgmt->in_count_childs > 0 ) {
                ads_mgmt->in_count_childs--;
            }

            // delete entry if no childs anymore and no indices
            if (    ads_mgmt->in_occ_indices  == 0
                 && ads_mgmt->in_count_childs == 0 ) {
                // add to position vector:
                ds_positions.m_add( in_par_domain );

                // get next entry:
                in_par_domain = ads_mgmt->in_par_domain;

                // free current entry:
                ads_mgmt->bo_occupied = false;
                dsc_mgmt_cma.adsc_cap->in_free++;

                bo_ret = m_get_element( &dsc_mgmt_cma, in_par_domain, &ads_mgmt );
            } else {
                break;
            }
        } // end of in_par_domain loop

        // get path parent again:
        m_get_element( &dsc_mgmt_cma, in_par_path, &ads_mgmt );

        // decrease child counter:
        if ( ads_mgmt->in_count_childs > 0 ) {
            ads_mgmt->in_count_childs--;
        }

        // delete entry if no childs anymore and no indices
        if (    ads_mgmt->in_occ_indices  == 0
             && ads_mgmt->in_count_childs == 0 ) {
            // add to position vector:
            ds_positions.m_add( in_par_path );

            // get next entry:
            in_par_path = ads_mgmt->in_par_path;

            // free current entry:
            ads_mgmt->bo_occupied = false;
            dsc_mgmt_cma.adsc_cap->in_free++;

            bo_ret = m_get_element( &dsc_mgmt_cma, in_par_path, &ads_mgmt );
        } else {
            break;
        }
    } // end of path parent loop

    return ds_positions;
} // ds_ck_mgmt::m_delete_mgmt


/**
 * function ds_ck_mgmt::m_delete_hash
 *
 * @param[in]   int     in_points_to        points to entry in mgmt table
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_delete_hash( int in_points_to )
{
    // initialize some variables:
    bool         bo_ret;
    int          in_index;
    dsd_ck_hash* ads_hash;
    dsd_ck_hash* ads_coll;

    //--------------------------------------------------
    // open hash cma for writing:
    //--------------------------------------------------
    bo_ret = m_open_cma( &dsc_hash_cma, true );
    if ( bo_ret == false ) {
        return false;
    }

    //--------------------------------------------------
    // search in hash table for matching entry:
    //--------------------------------------------------
    for ( in_index = 0; in_index < dsc_hash_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_hash_cma, in_index, &ads_hash );
        if (    bo_ret                 == true
             && ads_hash               != NULL
             && ads_hash->bo_occupied  == true
             && ads_hash->in_points_to == in_points_to ) {
            //------------------------------------------
            // check for element in coll table:
            //------------------------------------------
            if ( ads_hash->in_next_in_rest > -1 ) {
                /*
                    element in coll table found
                */

                //--------------------------------------
                // open coll cma for writing:
                //--------------------------------------
                bo_ret = m_open_cma( &dsc_coll_cma, true );
                if ( bo_ret == false ) {
                    ads_hash->bo_occupied = false;
                    dsc_hash_cma.adsc_cap->in_free++;
                    return false;
                }

                bo_ret = m_get_element( &dsc_coll_cma, ads_hash->in_next_in_rest, &ads_coll );
                //--------------------------------------
                // replace ads_hash with ads_coll
                //--------------------------------------
                if (    bo_ret                == true
                     && ads_coll              != NULL
                     && ads_coll->bo_occupied == true ) {
                    memcpy( ads_hash, ads_coll, sizeof(dsd_ck_hash) );
                    ads_coll->bo_occupied = false;
                    dsc_coll_cma.adsc_cap->in_free++;
                } else {
                    ads_hash->bo_occupied = false;
                    dsc_hash_cma.adsc_cap->in_free++;
                }

                //--------------------------------------
                // close coll cma:
                //--------------------------------------
                m_close_cma( &dsc_coll_cma );
                return bo_ret;
            } else {
                /*
                    no element in coll table
                */
                ads_hash->bo_occupied = false;
                dsc_hash_cma.adsc_cap->in_free++;
                return true;
            }
        }
    } // end of loop through hash table

    /*
        if we reach this point, we haven't found a
        matching entry in hash table!
    */

    //--------------------------------------------------
    // open coll cma for writing:
    //--------------------------------------------------
    bo_ret = m_open_cma( &dsc_coll_cma, true );
    if ( bo_ret == false ) {
        return false;
    }
    
    //--------------------------------------------------
    // search in coll table for matching entry:
    //--------------------------------------------------
    for ( in_index = 0; in_index < dsc_coll_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_hash_cma, in_index, &ads_hash );
        if (    bo_ret                 == true
             && ads_hash               != NULL
             && ads_hash->bo_occupied  == true
             && ads_hash->in_points_to == in_points_to ) {
            //------------------------------------------
            // check for next element in coll table:
            //------------------------------------------
            if ( ads_hash->in_next_in_rest > -1 ) {
                /*
                    next element in coll table found
                */

                bo_ret = m_get_element( &dsc_coll_cma, ads_hash->in_next_in_rest, &ads_coll );
                //--------------------------------------
                // replace ads_hash with ads_coll
                //--------------------------------------
                if (    bo_ret                == true
                     && ads_coll              != NULL
                     && ads_coll->bo_occupied == true ) {
                    memcpy( ads_hash, ads_coll, sizeof(dsd_ck_hash) );
                    ads_coll->bo_occupied = false;
                } else {
                    ads_hash->bo_occupied = false;
                }
                dsc_coll_cma.adsc_cap->in_free++;

                //--------------------------------------
                // close coll cma:
                //--------------------------------------
                m_close_cma( &dsc_coll_cma );
                return bo_ret;
            } else {
                /*
                    no next element in coll table
                */
                ads_hash->bo_occupied = false;
                dsc_coll_cma.adsc_cap->in_free++;

                //--------------------------------------
                // close coll cma:
                //--------------------------------------
                m_close_cma( &dsc_coll_cma );
                return true;
            }
        }
    } // end of loop through coll table

    //--------------------------------------
    // close coll cma:
    //--------------------------------------
    m_close_cma( &dsc_coll_cma );
    return false;
} // end of ds_ck_mgmt::m_delete_hash


/**
 * ds_ck_mgmt::m_get_mgmt_from_stor
 * find mgmt entry by pointer to storage
 *
 * @param[in]   int in_stor_pos         position from storage
 * @return      int                     position in mgmt
*/
int ds_ck_mgmt::m_get_mgmt_from_stor( int in_stor_pos )
{
    // initialize some variables:
    bool         bo_ret;
    int          in_pos;
    int          in_index;
    dsd_ck_mgmt* ads_mgmt;

    for ( in_pos = 0; in_pos < dsc_mgmt_cma.adsc_cap->in_capacity; in_pos++ ) {
        bo_ret = m_get_element( &dsc_mgmt_cma, in_pos, &ads_mgmt );
        if (    bo_ret                   == true
             && ads_mgmt                 != NULL
             && ads_mgmt->bo_occupied    == true
             && ads_mgmt->in_occ_indices >  0    ) {
            for ( in_index = 0; in_index < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_index++ ) {
                if ( ads_mgmt->rin_indices[in_index] == in_stor_pos ) {
                    return in_pos;
                }
            }
        }
    }
    return -1;
} // end of ds_ck_mgmt::m_get_mgmt_from_stor


/**
 * function ds_ck_mgmt::m_mgmt_rm_index
 *
 * @param[in]   dsd_ck_mgmt*    ads_mgmt
 * @param[in]   int             in_stor_pos
 * @return      bool
*/
bool ds_ck_mgmt::m_mgmt_rm_index( dsd_ck_mgmt* ads_mgmt, int in_stor_pos )
{
    int in_index;
    for ( in_index = 0; in_index < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_index++ ) {
        if ( ads_mgmt->rin_indices[in_index] == in_stor_pos ) {
            ads_mgmt->rin_indices[in_index] = -1;
            ads_mgmt->in_occ_indices--;
            return true;
        }
    }
    return false;
} // end of ds_ck_mgmt::m_mgmt_rm_index


/**
 * function ds_ck_mgmt::m_prepare
 * prepare cma names and open cmas
 *
 * @param[in]   const char* ach_cmabase         base cma name
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_prepare( const char* ach_cmabase )
{
    // initialize some variables:
    bool bo_ret;

    //------------------------------------------------
    // setup cma names for current user:
    //------------------------------------------------
    bo_ret = m_setup_cma_names( ach_cmabase );
    if ( bo_ret == false ) {
        return false;
    }

    //------------------------------------------------
    // open all cmas for reading access:
    // -> cmas will switch to write mode automaticly
    //    (if needed)
    // -> we will not open coll cma
    //------------------------------------------------
    bo_ret = m_open_cma( &dsc_hash_cma, false );
    if ( bo_ret == false ) {
        return false;
    }
    bo_ret = m_open_cma( &dsc_mgmt_cma, false );
    if ( bo_ret == false ) {
        //--------------------------------------------
        // close hash cma:
        //--------------------------------------------
        m_close_cma( &dsc_hash_cma );
        return false;
    }
    bo_ret = m_open_cma( &dsc_stor_cma, false );
    if ( bo_ret == false ) {
        //--------------------------------------------
        // close hash and mgmt cma:
        //--------------------------------------------
        m_close_cma( &dsc_hash_cma );
        m_close_cma( &dsc_mgmt_cma );
        return false;
    }
    return true;
} // end of ds_ck_mgmt::m_prepare


/**
 * function ds_ck_mgmt::m_finish
 * close cmas
 *
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_finish()
{
    // initialize some variables:
    bool bo_ret;

    //------------------------------------------------
    // close cmas:
    //------------------------------------------------
    bo_ret  = m_close_cma( &dsc_hash_cma );
    bo_ret &= m_close_cma( &dsc_mgmt_cma );
    bo_ret &= m_close_cma( &dsc_stor_cma );
    
    return bo_ret;
} // end of ds_ck_mgmt::m_finish


/**
 * function ds_ck_mgmt::m_clear_cache
 * clear get cookie cache
*/
void ds_ck_mgmt::m_clear_cache()
{
    dsc_cache.dsc_domain.m_reset();
    dsc_cache.dsc_path.m_reset();

    for ( size_t in_pos = 0; in_pos < dsc_cache.dsc_cookies.m_size(); in_pos++ ) {
        dsc_cache.dsc_cookies[in_pos].m_init( adsc_wsp_helper );
    }
    dsc_cache.dsc_cookies.m_clear();
} // end of ds_ck_mgmt::m_clear_cache


/**
 * function ds_ck_mgmt::m_save_cookie
 * save a single cookie inside cma
 *
 * @param[in]   ds_cookie*   ads_cookie     pointer to cookie class
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_save_cookie( ds_cookie* ads_cookie )
{
    // initialize some variables:
    bool             bo_ret;                            // return value for several functions
    bool             bo_actual;                         // cookie is actual?
    bool             bo_overwrite     = false;          // overwrite existing cookie?
    int              in_pos_mgmt;                       // position in mgmt table
    int              in_pos_stor      = -1;             // position in storage table
    ds_hvector2<int> ds_pos_stor( adsc_wsp_helper );    // position indices in storage
    ds_hstring       ds_host    ( adsc_wsp_helper );    // host (means domain/path) of cookie
    

    //----------------------------------------------------
    // 1. search if entry for this cookie already exists:
    //----------------------------------------------------
    ds_host.m_write( ads_cookie->m_get_domain() );
    ds_host.m_write( ads_cookie->m_get_path()   );

    //----------------------------------------------------
    // 1.1 search in hash table for entry in mgmt table:
    //----------------------------------------------------
    in_pos_mgmt = m_hash_points_to( ds_host.m_get_ptr(), ds_host.m_get_len() );
    if ( in_pos_mgmt > -1 ) {
        //------------------------------------------------
        // 1.2 search in mgmt table for entries in stor:
        //------------------------------------------------
        ds_pos_stor = m_mgmt_points_to( in_pos_mgmt, false );

        if ( ds_pos_stor.m_size() > 0 ) {
            //--------------------------------------------
            // 1.3 search for cookie name:
            //--------------------------------------------
            in_pos_stor  = m_search_cookie( ads_cookie, ds_pos_stor );
            bo_overwrite = (in_pos_stor > -1);
        }
    }

    //------------------------------------------------
    // 2. check lifetime of incomming cookie:
    //------------------------------------------------
    bo_actual = ads_cookie->m_check_lifetime();

    //------------------------------------------------
    // 3. save cookie:
    //------------------------------------------------
    if (    bo_actual    == true    /* insert actual cookie      */
         || bo_overwrite == true    /* overwrite existing cookie */ ) {
        /*
            if bo_actual == false && bo_overwrite == true -> delete an existing cookie
        */

        //--------------------------------------------
        // 3.1 save cookie in user cookie storage:
        //--------------------------------------------
        in_pos_stor = m_store_cookie( ads_cookie, in_pos_stor );
        if ( in_pos_stor < 0 ) {
            return false;
        }

        //--------------------------------------------
        // 3.2 create entries in hash and mgmt tables:
        //--------------------------------------------
        bo_ret = m_create_tables( ads_cookie, in_pos_stor, bo_overwrite );
        if ( bo_ret == false ) {
            return false;
        }
    }

    //------------------------------------------------
    // 4. do trace:
    //------------------------------------------------
    if ( boc_trace == true ) {
        m_trace_cookie( ads_cookie );
        m_create_trace();
    }

    return true;
} // end of ds_ck_mgmt::m_save_cookie


/**
 * function ds_ck_mgmt::m_store_cookie
 * store a cookie inside user cookie storage cma
 *
 * @param[in]   ds_cookie*   ads_cookie     pointer to cookie class
 * @param[in]   int          in_old_index   position of old cookie (in case of overwrite)
 * @return      int                         saved at position
 *                                          -1 in error cases
*/
int ds_ck_mgmt::m_store_cookie( ds_cookie* ads_cookie, int in_old_cookie )
{
    // initialize some variables:
    int          in_old_pos      = -1;      // used if cookie doesn't fit inside one buffer
    int          in_first_id     = -1;      // index to first buffer (used for return)
    int          in_index        = -1;      // current index
    bool         bo_overwrite    = false;   // overwrite mode?
    bool         bo_ret;                    // return value
    char*        ach_domain;                // cookies domain
    char*        ach_path;                  // cookies path
    char*        ach_cookie;                // cookie itself (name=value)
    int          in_len_cookie;             // length of cookie
    dsd_ck_stor* ads_ck_in;                 // cookie form old index
    dsd_ck_stor* ads_ck_stor = NULL;        // pointer to actual cookie storage

    //---------------------------------------
    // change mode store cma to writing:
    //---------------------------------------
    bo_ret = m_open_cma( &dsc_stor_cma, true );
    if ( bo_ret == false ) {
        return -1;
    }

    //---------------------------------------
    // get cookie data:
    //---------------------------------------
    ach_domain = ads_cookie->m_get_domain();
    ach_path   = ads_cookie->m_get_path();
    ach_cookie = ads_cookie->m_get_cookie();
    if ( ach_cookie == NULL ) {
        return -1;
    }
    in_len_cookie = (int)strlen( ach_cookie );


    //---------------------------------------
    // get old cookie:
    //---------------------------------------
    m_get_element( &dsc_stor_cma, in_old_cookie, &ads_ck_in );

    //---------------------------------------
    // save the cookie:
    //---------------------------------------
    for ( ; ; ) {
        //-----------------------------------
        // get storage for saving:
        //-----------------------------------
        if ( ads_ck_in == NULL ) {
            // get next free storage:
            ads_ck_stor = m_get_free_stor( &in_index );
        } else {
            // overwrite mode:
            if ( in_old_pos < 0 ) {
                // first run through loop
                bo_overwrite = true;
                in_index     = in_old_cookie;
                ads_ck_stor  = ads_ck_in;
            } else if ( ads_ck_stor->in_next > -1 ) {
                bo_overwrite = true;
                in_index     = ads_ck_stor->in_next;
                m_get_element( &dsc_stor_cma, in_index, &ads_ck_stor );
            } else {
                // get next free storage:
                bo_overwrite = false;
                ads_ck_stor  = m_get_free_stor( &in_index );
            }
        }

        if ( ads_ck_stor == NULL ) {
            // big error, should never happen!
            break;    // finish loop
        }

        //-----------------------------------
        // decrease free counter:
        //-----------------------------------
        if ( bo_overwrite == false ) {
            dsc_stor_cma.adsc_cap->in_free--;
        }


        //-----------------------------------
        // save first pointer of memory:
        //-----------------------------------
        if ( in_first_id == -1 ) {
            in_first_id = in_index;
        }

        //-----------------------------------
        // set old next pointer:
        //-----------------------------------
        if ( in_old_pos > -1 ) {
            dsd_ck_stor* ads_ck_old;
            m_get_element( &dsc_stor_cma, in_old_pos, &ads_ck_old );
            if ( ads_ck_old != NULL ) {
                ads_ck_old->in_next = in_index;
            }
        }

        //-----------------------------------
        // save expiration time:
        //-----------------------------------
        if ( ads_cookie->m_is_discard() ) {
            ads_ck_stor->t_expires = -1;
        } else {
            ads_ck_stor->t_expires = ads_cookie->m_get_expires();
        }

        //-----------------------------------
        // save secure information:
        //-----------------------------------
        ads_ck_stor->bo_secure = ads_cookie->m_is_secure();

        //-----------------------------------
        // save domain and path:
        //-----------------------------------
        if ( ach_domain != NULL ) {
            memcpy( ads_ck_stor->rch_domain, ach_domain,
                    min( strlen(ach_domain), CK_MAX_DOMAIN_LEN-1 ) );
            ads_ck_stor->rch_domain[min( strlen(ach_domain), CK_MAX_DOMAIN_LEN-1 )] = 0;
        }
        if ( ach_path != NULL ) {
            memcpy( ads_ck_stor->rch_path, ach_path,
                    min( strlen(ach_path), CK_MAX_PATH_LEN-1 ) );
            ads_ck_stor->rch_path[min( strlen(ach_path), CK_MAX_PATH_LEN-1 )] = 0;
        }

        //-----------------------------------
        // save cookie itself:
        //-----------------------------------
        if ( in_len_cookie < CK_MEM_SIZE ) {
            /*
                cookie fit in one container
            */
            ads_ck_stor->in_length = in_len_cookie;
            memcpy( ads_ck_stor->rch_cookie, ach_cookie, in_len_cookie );
            ads_ck_stor->in_next = -1;
            break;    // finish loop
        } else {
            /*
                cookie doesn't fit in one container
                -> we must create a list of containers!
            */
            ads_ck_stor->in_length = CK_MEM_SIZE;
            memcpy( ads_ck_stor->rch_cookie, ach_cookie, CK_MEM_SIZE );
            // save old pointer to set next pointer
            in_old_pos = in_index;
            // move ach_cookie
            ach_cookie    += CK_MEM_SIZE;
            in_len_cookie -= CK_MEM_SIZE;
        }
    }

    return in_first_id;
} // end of ds_ck_mgmt::m_store_cookies


/**
 * function ds_ck_mgmt::m_store_cookie
 * store a cookie inside user cookie storage cma
 *
 * @param[in]   ds_cookie*  ads_cookie      pointer to cookie class
 * @param[in]   int         in_mem_index    position of cookie in storage table
 * @param[in]   bool        bo_overwrite    entry in storage was overwritten
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_create_tables( ds_cookie* ads_cookie, int in_mem_index, bool bo_overwrite )
{
    // initialize some variables:
    bool                                 bo_return = false;             // return value
    int                                  in_add_child;                  // number of childs to be added
    int                                  in_saved_at;                   // saved at index ...
    int                                  in_path;
    int                                  in_domain;
    ds_hstring                           ds_host;
    ds_hvector2<ds_hvector2<ds_hstring>> ds_hosts   (adsc_wsp_helper);
    ds_hvector2<int>                     ds_par_path(adsc_wsp_helper);
    
    int in_par_domain   = -1;
    int in_par_path   = -1;
    int in_position = -1;

    //---------------------------------------------
    // get all (parent) subdomains
    //---------------------------------------------
    ds_hosts = m_get_parent_hosts( ads_cookie->m_get_domain(), strlen(ads_cookie->m_get_domain()),
                                   ads_cookie->m_get_path(),   strlen(ads_cookie->m_get_path())   );
    if ( ds_hosts.m_empty() ) {
        return false;
    }

    //---------------------------------------------
    // setup path parent vector:
    //---------------------------------------------
    for ( in_path = 0; in_path < (int)ds_hosts.m_get_last().m_size(); in_path++ ) {
        ds_par_path.m_add( -1 );
    }

    //---------------------------------------------
    // run (backward!) through all subdomains:
    //---------------------------------------------
    for ( in_domain = (int)ds_hosts.m_size() - 1; in_domain >= 0; in_domain-- ) {
        in_saved_at = -1;

        //-----------------------------------------
        // run (backward!) through all subpaths:
        //-----------------------------------------
        for ( in_path = (int)ds_hosts[in_domain].m_size() - 1; in_path >= 0; in_path-- ) {
            //-------------------------------------
            // reset return value:
            //-------------------------------------
            bo_return = false;

            //-------------------------------------
            // get host:
            //-------------------------------------
            ds_host = ds_hosts[in_domain][in_path];

            //-------------------------------------
            // check if entrie already exists in hash table:
            //-------------------------------------
            in_position = m_hash_points_to( ds_host.m_get_ptr(), ds_host.m_get_len() );
            
            //-------------------------------------
            // set parent indices:
            //-------------------------------------
            in_par_domain = in_saved_at;
            in_par_path   = ds_par_path[in_path];

            //-------------------------------------
            // evaluate number of added childs:
            //-------------------------------------
            if ( bo_overwrite == true ) {
                in_add_child = 0;
            } else if ( in_path == 0 ) {
                in_add_child = 1;
            } else {
                in_add_child = 2;
            }

            //-------------------------------------
            // insert mgmt entry:
            //  -> in_mem_index is the index of the saved cookie to host
            //     all other (sub-)domains, should not point to this index
            //     therefore, only insert in_mem_index in original host
            //  -> At orginal host, there are no childs to add
            //-------------------------------------
            if ( in_domain == 0 && in_path == 0 ) {
                in_saved_at = m_insert_mgmt( in_position, in_mem_index, in_par_domain, in_par_path, 0 );
            } else {
                in_saved_at = m_insert_mgmt( in_position, -1, in_par_domain, in_par_path, in_add_child );
            }

            //-------------------------------------
            // insert hash entry:
            //-------------------------------------
            if ( in_saved_at > -1 ) {
                if ( in_position < 0 ) {
                    bo_return = m_insert_hash( ds_host.m_get_ptr(), ds_host.m_get_len(), in_saved_at );
                } else {
                    bo_return = true;
                }
            }

            //-------------------------------------
            // check return:
            //-------------------------------------
            if ( bo_return == false ) {
                return false;
            }

            //-------------------------------------
            // set parent element:
            //-------------------------------------
            ds_par_path.m_set( in_path, in_saved_at );
        }
    }
    return bo_return;
} // end of ds_ck_mgmt::m_create_tables


/**
 * function ds_ck_mgmt::m_search_cookie
 *
 * @param[in]   ds_cookie*          ads_cookie          cookie to search for
 * @param[in]   ds_hvector2<int>    ds_pos_stor         position indices to search
 * @return      int                                     found cookie index
 *                                                      -1 if nothing found
*/
int ds_ck_mgmt::m_search_cookie( ds_cookie* ads_cookie, ds_hvector2<int> ds_pos_stor )
{
    // initialize some variables:
    int       in_pos;
    bool      bo_ret;
    ds_cookie dsl_cookie( adsc_wsp_helper );

    for ( in_pos = 0; in_pos < (int)ds_pos_stor.m_size(); in_pos++ ) {
        bo_ret = m_get_ck_from_stor( ds_pos_stor[in_pos], &dsl_cookie );
        if (    bo_ret == true
             && ads_cookie->m_name_equals( &dsl_cookie ) == true ) {
            return ds_pos_stor[in_pos];
        }
        dsl_cookie.m_reset();
    }

    return -1;
} // end of ds_ck_mgmt::m_search_cookie


/**
 * function ds_ck_mgmt::m_create_trace
*/
void ds_ck_mgmt::m_create_trace()
{
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
        ds_trace_path.m_write( rch_path );
        ds_trace_path.m_write( LOGFILE_PATH );
    }

    //-------------------------------------------
    // trace hash table:
    //-------------------------------------------
    ds_file.m_write( ds_trace_path.m_get_ptr(), ds_trace_path.m_get_len(), false );
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
    ds_file.m_write( ds_trace_path.m_get_ptr(), ds_trace_path.m_get_len(), false );
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
    ds_file.m_write( ds_trace_path.m_get_ptr(), ds_trace_path.m_get_len(), false );
    ds_file.m_write( CK_MEM_TABLE_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "w" );
    if ( a_file != NULL ) {
        ds_content = m_get_stor_overview();
        fprintf( a_file, "%s", ds_content.m_get_ptr() );
        fclose( a_file );
    }
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
        ds_trace_path.m_write( rch_path );
        ds_trace_path.m_write( LOGFILE_PATH );
    }

    //-------------------------------------------
    // trace cookie:
    //-------------------------------------------
    ds_file.m_write( ds_trace_path.m_get_ptr(), ds_trace_path.m_get_len(), false );
    ds_file.m_write( CK_COOKIE_IN_FILE );
    a_file = fopen( ds_file.m_get_ptr(), "a" );
    if ( a_file != NULL ) {
        fprintf( a_file, "-----------------------------------------------------------\n" );
        fprintf( a_file, "%s\n", ads_cookie->m_get_cookie() );
        fprintf( a_file, "Domain: %s\n", ads_cookie->m_get_domain() );
        fprintf( a_file, "Path:   %s\n", ads_cookie->m_get_path() );
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
 * function ds_ck_mgmt::m_get_hash_overview
 *
 * @return ds_hstring
*/
ds_hstring ds_ck_mgmt::m_get_hash_overview()
{
    // initialize some variables:
    int          in_index;
    bool         bo_ret;
    int          in_used;
    ds_hstring   ds_out(adsc_wsp_helper);
    dsd_ck_hash* ads_hash;

    
    //-------------------------------------------
    // open coll cma for reading:
    //-------------------------------------------
    bo_ret = m_open_cma( &dsc_coll_cma, false );
    if ( bo_ret == false ) {
        return ds_out;
    }

    //-------------------------------------------
    // total overview:
    //-------------------------------------------
    in_used  = dsc_hash_cma.adsc_cap->in_capacity - dsc_hash_cma.adsc_cap->in_free;
    in_used += dsc_coll_cma.adsc_cap->in_capacity - dsc_coll_cma.adsc_cap->in_free;
    ds_out.m_writef( "TOTAL used entries:        %d\n\n", in_used );
    ds_out.m_write ( "---------------------------\n" );

    //-------------------------------------------
    // hash table overview:
    //-------------------------------------------
    in_used = dsc_hash_cma.adsc_cap->in_capacity - dsc_hash_cma.adsc_cap->in_free;
    ds_out.m_writef( "hash table - capacity:     %d\n", dsc_hash_cma.adsc_cap->in_capacity );
    ds_out.m_writef( "           - used entries: %d\n", in_used );
    
    //-------------------------------------------
    // get entries from hash table:
    //-------------------------------------------
    for ( in_index = 0; in_index < dsc_hash_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_hash_cma, in_index, &ads_hash );
        if (    bo_ret   == false
             || ads_hash == NULL  ) {
            ds_out.m_write( "\t error: NULL pointer\n" );
            continue;
        }

        ds_out.m_writef( "position: %d\n", in_index );
        ds_out.m_write ( "\t entry in use:       " );
        if ( ads_hash->bo_occupied == true ) {
            ds_out.m_write( "YES\n" );
        } else {
            ds_out.m_write( "NO\n" );
        }
        ds_out.m_write ( "\t host:               " );
        ds_out.m_write ( &ads_hash->rch_host[0] );
        ds_out.m_write ( "\n" );
        ds_out.m_writef( "\t next in rest table: %d\n", ads_hash->in_next_in_rest );
        ds_out.m_writef( "\t points to:          %d\n", ads_hash->in_points_to );
    }
    ds_out.m_write( "---------------------------\n" );

    //-------------------------------------------
    // coll table overview:
    //-------------------------------------------
    in_used = dsc_coll_cma.adsc_cap->in_capacity - dsc_coll_cma.adsc_cap->in_free;
    ds_out.m_writef( "coll table - capacity:     %d\n", dsc_coll_cma.adsc_cap->in_capacity );
    ds_out.m_writef( "           - used entries: %d\n", in_used );
    
    //-------------------------------------------
    // get entries from coll table:
    //-------------------------------------------
    for ( in_index = 0; in_index < dsc_coll_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_coll_cma, in_index, &ads_hash );
        if (    bo_ret   == false
             || ads_hash == NULL  ) {
            ds_out.m_write( "\t error: NULL pointer\n" );
            continue;
        }

        ds_out.m_writef( "position: %d\n", in_index );
        ds_out.m_write ( "\t entry in use:       " );
        if ( ads_hash->bo_occupied == true ) {
            ds_out.m_write( "YES\n" );
        } else {
            ds_out.m_write( "NO\n" );
        }
        ds_out.m_write ( "\t host:               " );
        ds_out.m_write ( &ads_hash->rch_host[0] );
        ds_out.m_write ( "\n" );
        ds_out.m_writef( "\t next in rest table: %d\n", ads_hash->in_next_in_rest );
        ds_out.m_writef( "\t points to:          %d\n", ads_hash->in_points_to );
    }

    
    //-------------------------------------------
    // close coll cma:
    //-------------------------------------------
    m_close_cma( &dsc_coll_cma );

    return ds_out;
} // end of ds_ck_mgmt::m_get_hash_overview


/**
 * function ds_ck_mgmt::m_get_mgmt_overview
 *
 * @return  ds_hstring
*/
ds_hstring ds_ck_mgmt::m_get_mgmt_overview()
{
    // initialize some variables:
    int          in_index;
    int          in_pos;
    bool         bo_ret;
    int          in_used;
    int          in_insert;
    ds_hstring   ds_out(adsc_wsp_helper);
    ds_hstring   ds_tmp(adsc_wsp_helper);
    dsd_ck_mgmt* ads_mgmt;

    //-------------------------------------------
    // mgmt table overview:
    //-------------------------------------------
    in_used = dsc_mgmt_cma.adsc_cap->in_capacity - dsc_mgmt_cma.adsc_cap->in_free;
    ds_out.m_writef( "mgmt table - capacity:     %d\n", dsc_mgmt_cma.adsc_cap->in_capacity );
    ds_out.m_writef( "           - used entries: %d\n", in_used );
    ds_out.m_writef( "pointer to memory - capacity: %d\n", dsc_mgmt_cma.adsc_cap->in_capacity * CK_MAX_PER_DOMAIN );
    ds_out.m_write ( "                  - used:     " );
    in_insert = ds_out.m_get_len();
    ds_out.m_write ( "\n\n" );

    //-------------------------------------------
    // get entries from mgmt table:
    //-------------------------------------------
    in_used = 0;
    for ( in_index = 0; in_index < dsc_mgmt_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_mgmt_cma, in_index, &ads_mgmt );
        if (    bo_ret   == false
             || ads_mgmt == NULL  ) {
            ds_out.m_write( "error: NULL pointer\n" );
            continue;
        }
        in_used += ads_mgmt->in_occ_indices;

        ds_out.m_writef( "position: %d\n", in_index );
        ds_out.m_write ( "\t entry in use:       " );
        if ( ads_mgmt->bo_occupied == true ) {
            ds_out.m_write( "YES\n" );
        } else {
            ds_out.m_write( "NO\n" );
        }
        ds_out.m_write ( "\t pointers to memory: " );
        if ( ads_mgmt->in_occ_indices > 0 ) { 
            for ( in_pos = 0; in_pos < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_pos++ ) {
                if ( ads_mgmt->rin_indices[in_pos] > -1 ) {
                    ds_out.m_writef( "%d, ", ads_mgmt->rin_indices[in_pos] );
                }
            }
        }
        ds_out.m_write ( "\n" );
        ds_out.m_writef( "\t domain parent entry: %d\n", ads_mgmt->in_par_domain );
        ds_out.m_writef( "\t path parent entry:   %d\n", ads_mgmt->in_par_path );
        ds_out.m_writef( "\t number of childs:    %d\n", ads_mgmt->in_count_childs );
    }

    ds_tmp.m_writef( "%d", in_used );
    ds_out.m_insert( in_insert, ds_tmp.m_get_ptr(), ds_tmp.m_get_len() ); 
    return ds_out;
} // end of ds_ck_mgmt::m_get_mgmt_overview


/**
 * function ds_ck_mgmt::m_get_stor_overview
 *
 * @return  ds_hstring
*/
ds_hstring ds_ck_mgmt::m_get_stor_overview()
{
    // initialize some variables:
    int          in_index;
    bool         bo_ret;
    int          in_used;
    ds_hstring   ds_out(adsc_wsp_helper);
    dsd_ck_stor* ads_stor;

    //-------------------------------------------
    // storage table overview:
    //-------------------------------------------
    in_used = dsc_stor_cma.adsc_cap->in_capacity - dsc_stor_cma.adsc_cap->in_free;
    ds_out.m_writef( "memory table - capacity:     %d\n", dsc_stor_cma.adsc_cap->in_capacity );
    ds_out.m_writef( "             - used entries: %d\n\n", in_used );

    //-------------------------------------------
    // get entries from storage table:
    //-------------------------------------------
    for ( in_index = 0; in_index < dsc_stor_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_stor_cma, in_index, &ads_stor );
        if (    bo_ret == false
             || ads_stor == NULL ) {
            ds_out.m_write( "error: NULL pointer\n" );
            continue;
        }

        ds_out.m_writef( "position: %d\n", in_index );
        ds_out.m_write ( "\t entry in use:       " );
        if ( ads_stor->in_length > 0 ) {
            ds_out.m_write( "YES\n" );
        } else {
            ds_out.m_write( "NO\n" );
        }
        ds_out.m_write ( "\t cookie:             " );
        ds_out.m_write ( &ads_stor->rch_cookie[0], ads_stor->in_length );
        ds_out.m_write ( "\n" );
        ds_out.m_write ( "\t domain:             " );
        ds_out.m_write ( &ads_stor->rch_domain[0] );
        ds_out.m_write ( "\n" );
        ds_out.m_write ( "\t path:               " );
        ds_out.m_write ( &ads_stor->rch_path[0] );
        ds_out.m_write ( "\n" );
        ds_out.m_write ( "\t lifetime:           " );
        if ( ads_stor->t_expires == -1 ) {
            ds_out.m_write("delete at logout\n");
        } else {
            ds_out.m_writef( "%lld\n", ads_stor->t_expires );
        }
        ds_out.m_writef( "\t next:               %d\n", ads_stor->in_next );
        if ( ads_stor->in_length > 0 ) {
            if ( ads_stor->in_next > -1 ) {
                ds_out.m_write( "\t recomposed cookie:  " );
                ds_out.m_write( &ads_stor->rch_cookie[0], ads_stor->in_length );
                m_get_element( &dsc_stor_cma, ads_stor->in_next, &ads_stor );
                while ( ads_stor != NULL ) {
                    ds_out.m_write( &ads_stor->rch_cookie[0], ads_stor->in_length );
                    m_get_element( &dsc_stor_cma, ads_stor->in_next, &ads_stor );
                }
                ds_out.m_write( "\n" );
            }
        }
    }
    return ds_out;
} // end of ds_ck_mgmt::m_get_stor_overview


/**
 * function ds_ck_mgmt::m_get_ck_from_stor
 *
 * @param[in]   int         in_index        position in storage
 * @param[out]  ds_cookie*  ads_out         cookie output
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_get_ck_from_stor( int in_index, ds_cookie* ads_out )
{
    // initialize some variables:
    bool         bo_ret;
    dsd_ck_stor* ads_stored;
    time_t       il_current;

    //---------------------------------------------
    // 1. get cookie at requested index:
    //---------------------------------------------
    bo_ret = m_get_element( &dsc_stor_cma, in_index, &ads_stored );
    if (    bo_ret                == false
         || ads_stored            == NULL
         || ads_stored->in_length  < 1    ) {
        return false;
    }

    //---------------------------------------------
    // 1.1. check type of cookie
    //---------------------------------------------
    if ( ads_stored->t_expires == -1 ) {
        /*
            it's a session cookie
        */
        
        //-----------------------------------------
        // 2.1 init cookie class:
        //-----------------------------------------
        ads_out->m_set_domain( ads_stored->rch_domain, strlen(ads_stored->rch_domain) );
        ads_out->m_set_path  ( ads_stored->rch_path,   strlen(ads_stored->rch_path)   );
        if ( ads_stored->bo_secure == true ) {
            ads_out->m_set_secure();
        }

        //-----------------------------------------
        // 2.2 save cookie itself:
        //-----------------------------------------
        ads_out->m_set_cookie( ads_stored->rch_cookie, ads_stored->in_length );
        
        //-----------------------------------------
        // 2.2.1 loop through next chain:
        //-----------------------------------------
        while ( ads_stored->in_next > -1 ) {
            bo_ret = m_get_element( &dsc_stor_cma, ads_stored->in_next, &ads_stored );
            if (    bo_ret                == false
                 || ads_stored            == NULL
                 || ads_stored->in_length  < 1    ) {
                return false;
            }
            ads_out->m_set_cookie( ads_stored->rch_cookie, ads_stored->in_length );
        }
    } else {
        /*
            lifetime cookie
        */
        il_current = adsc_wsp_helper->m_cb_get_time();

        //-----------------------------------------
        // 3.1 check lifetime:
        //-----------------------------------------
        if ( il_current >= ads_stored->t_expires ) {
            /*
                cookie has expired -> delete it
            */
            ads_out->m_reset();
            m_delete_cookie( in_index );
            return false;
        }
        
        //-----------------------------------------
        // 3.2 init cookie class:
        //-----------------------------------------
        ads_out->m_set_domain( ads_stored->rch_domain, strlen(ads_stored->rch_domain) );
        ads_out->m_set_path  ( ads_stored->rch_path,   strlen(ads_stored->rch_path)   );
        if ( ads_stored->bo_secure == true ) {
            ads_out->m_set_secure();
        }
        ads_out->m_set_expires( ads_stored->t_expires );

        //-----------------------------------------
        // 3.3 save cookie itself:
        //-----------------------------------------
        ads_out->m_set_cookie( ads_stored->rch_cookie, ads_stored->in_length );
        
        //-----------------------------------------
        // 3.3.1 loop through next chain:
        //-----------------------------------------
        while ( ads_stored->in_next > -1 ) {
            bo_ret = m_get_element( &dsc_stor_cma, ads_stored->in_next, &ads_stored );
            if (    bo_ret                == false
                 || ads_stored            == NULL
                 || ads_stored->in_length  < 1    ) {
                return false;
            }
            ads_out->m_set_cookie( ads_stored->rch_cookie, ads_stored->in_length );
        }
    }
    return true;
} // end of ds_ck_mgmt::m_get_ck_from_stor


/**
 * function ds_ck_mgmt::m_mgmt_points_to
 *
 * @param[in]   int                 in_index        index
 * @param[in]   bool                bo_get_parent   true:  get also entries from parent chain
 *                                                  false: get only exact matching entries
 *                                                  default = true
 * @return      ds_hvector2<int>
*/
ds_hvector2<int> ds_ck_mgmt::m_mgmt_points_to( int in_index, bool bo_get_parent )
{
    // initialize some variables:
    ds_hvector2<int>    ds_pointers( adsc_wsp_helper ); // return value
    ds_hvector2<int>    ds_parents ( adsc_wsp_helper ); // parent entries
    dsd_ck_mgmt*        ads_mgmt;                       // managment structure
    bool                bo_ret;                         // return from function calls
    int                 in_parent;                      // position in parents vector
    int                 in_pos;                         // position in indice array
    int                 in_count;                       // avoid looping through all elements

    //---------------------------------------------
    // get exact entries:
    //---------------------------------------------
    bo_ret = m_get_element( &dsc_mgmt_cma, in_index, &ads_mgmt );
    if (    bo_ret                   == true
         && ads_mgmt                 != NULL
         && ads_mgmt->bo_occupied    == true
         && ads_mgmt->in_occ_indices >  0    )
    {
        in_count = 0;
        for ( in_pos = 0; in_pos < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_pos++ ) {
            if ( ads_mgmt->rin_indices[in_pos] > -1 ) {
                in_count++;
                ds_pointers.m_add( ads_mgmt->rin_indices[in_pos] );
                if ( in_count == ads_mgmt->in_occ_indices ) {
                    break;
                }
            }
        }
    }

    //---------------------------------------------
    // get parent entries:
    //---------------------------------------------
    if ( bo_get_parent == true ) {
        ds_parents = m_get_mgmt_parents( in_index );

        for ( in_parent = 0; in_parent < (int)ds_parents.m_size(); in_parent++ ) {
            bo_ret = m_get_element( &dsc_mgmt_cma, ds_parents[in_parent], &ads_mgmt );
            if (    bo_ret                   == true
                 && ads_mgmt                 != NULL
                 && ads_mgmt->bo_occupied    == true
                 && ads_mgmt->in_occ_indices >  0   )
            {
                in_count = 0;
                for ( in_pos = 0; in_pos < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_pos++ ) {
                    if ( ads_mgmt->rin_indices[in_pos] > -1 ) {
                        in_count++;
                        ds_pointers.m_add( ads_mgmt->rin_indices[in_pos] );
                        if ( in_count == ads_mgmt->in_occ_indices ) {
                            break;
                        }
                    }
                }
            }
        }

    }

    return ds_pointers;
} // end of ds_ck_mgmt::m_mgmt_points_to


/**
 * function ds_ck_mgmt::m_get_parents
 *
 * @param[in]   int     in_mgmt_pos
 * @return      vector<int>
*/
ds_hvector2<int> ds_ck_mgmt::m_get_mgmt_parents( int in_index )
{
    // initialize some variables:
    int              in_par_path;
    int              in_par_domain;
    bool             bo_ret;
    dsd_ck_mgmt*     ads_mgmt;
    ds_hvector2<int> ds_parents( adsc_wsp_helper );

    in_par_path = in_index;
    bo_ret      = m_get_element( &dsc_mgmt_cma, in_index, &ads_mgmt );

    //------------------------------------------
    // run through path parent elements:
    //------------------------------------------
    while (    in_par_path           > -1
            && bo_ret                == true
            && ads_mgmt              != NULL
            && ads_mgmt->bo_occupied == true )
    {
        if ( in_par_path != in_index ) {
            ds_parents.m_add( in_par_path );
        }
        //--------------------------------------
        // get parent path element:
        //--------------------------------------
        in_par_path = ads_mgmt->in_par_path;

        //--------------------------------------
        // get parent domain element:
        //--------------------------------------
        in_par_domain = ads_mgmt->in_par_domain;
        bo_ret = m_get_element( &dsc_mgmt_cma, in_par_domain, &ads_mgmt );

        //--------------------------------------
        // loop through domain parent elements:
        //--------------------------------------
        while (    in_par_domain          > -1
                && bo_ret                == true
                && ads_mgmt              != NULL
                && ads_mgmt->bo_occupied == true )
        {
            ds_parents.m_add( in_par_domain );
            in_par_domain = ads_mgmt->in_par_domain;
            bo_ret        = m_get_element( &dsc_mgmt_cma, in_par_domain, &ads_mgmt );
        }
        //--------------------------------------
        // get next path parent element
        //--------------------------------------
        bo_ret = m_get_element( &dsc_mgmt_cma, in_par_path, &ads_mgmt );
    }

    return ds_parents;
} // end of ds_ck_mgmt::m_get_parents


/**
 * function ds_ck_mgmt::m_insert_mgmt
 *
 * @param[in]   int     in_save_at      position where entry should be saved at
 *                                      give -1 to create a new one
 * @param[in]   int     in_points_to    pointer to position in ds_cookie_memory 
 * @param[in]   int     in_par_domain   pointer to father element in ds_cookie_mgmt_table
 * @param[in]   int     in_par_path     pointer to mother element in ds_cookie_mgmt_table
 * @param[in]   int     in_add_childs   increase child counter with this number
 * @return      int                     position where entry is saved at
 *                                      -1 if error occured
*/
int ds_ck_mgmt::m_insert_mgmt( int in_save_at, int in_points_to,
                               int in_par_domain, int in_par_path,
                               int in_add_childs )
{
    // initialize some variables:
    int             in_return = -1;
    dsd_ck_mgmt*    ads_mgmt;           // managment structure
    int             in_pos    = -1;
    bool            bo_ret;

    //---------------------------------------
    // change mgmt cma mode to writing:
    //---------------------------------------
    bo_ret = m_open_cma( &dsc_mgmt_cma, true );
    if ( bo_ret == false ) {
        return -1;
    }

    if ( in_save_at > -1 ) {
        // an entry already exists -> just add new informations:
        bo_ret = m_get_element( &dsc_mgmt_cma, in_save_at, &ads_mgmt );
        if (    bo_ret   == true
             && ads_mgmt != NULL ) {
            bo_ret = m_fill( ads_mgmt, in_points_to, in_par_domain, in_par_path, in_add_childs );
            if ( bo_ret == true ) {
                // set return value:
                in_return = in_save_at;
            }            
        }
    } else {
        // take next free entry:
        ads_mgmt = m_get_free_mgmt( &in_pos );
        if ( ads_mgmt != NULL && in_pos > -1 ) {
            bo_ret = m_fill( ads_mgmt, in_points_to, in_par_domain, in_par_path, in_add_childs );
            if ( bo_ret == true ) {
                // decrease free counter:
                dsc_mgmt_cma.adsc_cap->in_free--;
                // set return value:
                in_return = in_pos;
            }
        }
    }

    return in_return;
} // end of ds_ck_mgmt::m_insert_mgmt


/**
 *
 * function ds_ck_mgmt::m_hash_points_to
 *
 * @param[in]   const char* ach_host    host ( www.hob.de/test1/test2/ )
 * @param[in]   int         in_len_host length of host
 *
 * @return      int                     pointer to managment
 *                                      -1 if no entry found
 *
*/
int ds_ck_mgmt::m_hash_points_to( const char* ach_host, int in_len_host )
{
    // initialize some variables:
    bool         bo_ret;                    // return for some function calls
    int          in_points_to = -1;         // return value
    unsigned int uin_hash;                  // hash from host
    int          in_hash_pos;               // position index from hash
    dsd_ck_hash* ads_hash;                  // hash structure

    //-------------------------------------------
    // get hash and position in table:
    //-------------------------------------------
    uin_hash    = m_get_hash( ach_host, in_len_host );
    in_hash_pos = (uin_hash)%(dsc_hash_cma.adsc_cap->in_capacity);

    //-------------------------------------------
    // get hash at evaluated position:
    //-------------------------------------------
    bo_ret = m_get_element( &dsc_hash_cma, in_hash_pos, &ads_hash );
    if (    bo_ret == false
         || ads_hash == NULL
         || ads_hash->bo_occupied == false ) {
        return -1;
    }

    //-------------------------------------------
    // check if found hash is our entry:
    //-------------------------------------------
    if (    in_len_host        >= (int)strlen(ads_hash->rch_host)
         && ads_hash->uin_hash == uin_hash
         && m_equals( ach_host, in_len_host, ads_hash->rch_host, strlen(ads_hash->rch_host) ) == true ) {
        /*
            we have found the matching entry in hash table!
        */
        in_points_to = ads_hash->in_points_to;
    } else if ( ads_hash->in_next_in_rest > -1 ) {
        /*
            there is no matching entry in hash table, but next pointer is set
            -> search in next pointer chain for the requested entry
        */

        //---------------------------------------
        // open coll cma for reading
        //---------------------------------------
        bo_ret = m_open_cma( &dsc_coll_cma, false );
        if ( bo_ret == false ) { 
            return -1;
        }

        while ( ads_hash->in_next_in_rest > -1 ) {
            bo_ret = m_get_element( &dsc_coll_cma, ads_hash->in_next_in_rest, &ads_hash );
            if (    bo_ret == false 
                 || ads_hash == NULL
                 || ads_hash->bo_occupied == false ) {
                //-------------------------------
                // close cmas:
                //-------------------------------
                m_close_cma( &dsc_coll_cma );
                return -1;
            }
            if (    in_len_host        >= (int)strlen(ads_hash->rch_host)
                 && ads_hash->uin_hash == uin_hash
                 && m_equals( ach_host, in_len_host, ads_hash->rch_host, strlen(ads_hash->rch_host) ) == true ) {
                in_points_to = ads_hash->in_points_to;
                break;
            }
        } // end of while

        //---------------------------------------
        // close coll cma:
        //---------------------------------------
        m_close_cma( &dsc_coll_cma );
    }

    return in_points_to;
} // end of ds_ck_mgmt::m_hash_points_to


/**
 * function ds_ck_mgmt::m_insert_hash
 *
 * @param[in]   const char* ach_host        host of cookie
 * @param[in]   int         in_len_host     length of host
 * @param[in]   int         in_pos_mgmt     position to point to in mgmt table
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_insert_hash( const char* ach_host, int in_len_host, int in_pos_mgmt )
{
    // initialize some variables:
    bool         bo_ret;
    unsigned int uin_hash;
    int          in_hash_pos;
    int          in_last;
    int          in_rest_pos;
    dsd_ck_hash* ads_hash;
    dsd_ck_hash* ads_coll;


    //-------------------------------------------
    // change hash cma mode to writing:
    //-------------------------------------------
    bo_ret = m_open_cma( &dsc_hash_cma, true );
    if ( bo_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // check load of hash table:
    //-------------------------------------------
    if ( dsc_hash_cma.adsc_cap->in_free <= (1-DEF_CK_HASH_LOAD) * dsc_hash_cma.adsc_cap->in_capacity ) {
        bo_ret = m_hash_resize();
        if ( bo_ret == false ) {
            return false;
        }
    }

    //-------------------------------------------
    // get hash and position in table:
    //-------------------------------------------
    uin_hash    = m_get_hash( ach_host, in_len_host );
    in_hash_pos = (uin_hash)%(dsc_hash_cma.adsc_cap->in_capacity);

    //-------------------------------------------
    // get hash at evaluated position:
    //-------------------------------------------
    bo_ret = m_get_element( &dsc_hash_cma, in_hash_pos, &ads_hash );
    if ( bo_ret == false || ads_hash == NULL ) {
        return false;
    }

    //-------------------------------------------
    // check if hash at position is free:
    //-------------------------------------------
    if ( ads_hash->bo_occupied == false ) {
        /*
            hash table is free at requested position
            -> insert entry
        */
        bo_ret = m_fill( ads_hash, uin_hash, ach_host, in_len_host, in_pos_mgmt );
        if ( bo_ret == true ) {
            dsc_hash_cma.adsc_cap->in_free--;
        }
    } else {
        /*
            hash table is not free at requested position
            -> insert entry in collusion table
        */

        //---------------------------------------
        // open coll cma for writing:
        //---------------------------------------
        bo_ret = m_open_cma( &dsc_coll_cma, true );
        if ( bo_ret == false ) {
            return false;
        }

        //---------------------------------------
        // get last entry with same hash pos:
        //---------------------------------------
        in_last = m_get_last_next_pointer( in_hash_pos );
        
        //---------------------------------------
        // get next free entry in coll table:
        //---------------------------------------
        ads_coll = m_get_free_coll( &in_rest_pos );
        if (    ads_coll == NULL
             || in_rest_pos < 0 ) {
            //-----------------------------------
            // close coll cma:
            //-----------------------------------
            m_close_cma( &dsc_coll_cma );
            return false;
        }

        //---------------------------------------
        // fill hash entry:
        //---------------------------------------
        bo_ret = m_fill( ads_coll, uin_hash, ach_host, in_len_host, in_pos_mgmt );
        if ( bo_ret == true ) {
            dsc_coll_cma.adsc_cap->in_free--;

            //-----------------------------------
            // set next pointer:
            //-----------------------------------
            if ( in_last < 0 ) {
                // in hash table:
                ads_hash->in_next_in_rest = in_rest_pos;
            } else {
                // in coll table:
                m_get_element( &dsc_coll_cma, in_last, &ads_coll );
                ads_coll->in_next_in_rest = in_rest_pos;
            }
        }

        //---------------------------------------
        // close coll cma:
        //---------------------------------------
        m_close_cma( &dsc_coll_cma );
    }
  
    return bo_ret;
} // end of ds_ck_mgmt::m_insert_hash


/**
 * function ds_ck_mgmt::m_hash_resize
 * resize hash cma
 * in that case all the entries inside hash table must get reorderd
 * also entries from the collosion table will be reinserted.
 *
 * @return  bool
*/
bool ds_ck_mgmt::m_hash_resize()
{
    // initialize some variables:
    dsd_ck_cma    dsl_hash_bac;             // backup from hash cma
    dsd_ck_cma    dsl_coll_bac;             // backup from coll cma
    bool          bo_ret;
    int           in_min_elements;
    
    //-------------------------------------------
    // open coll cma for writing:
    //-------------------------------------------
    bo_ret = m_open_cma( &dsc_coll_cma, true );
    if ( bo_ret == false ) {
        return false;
    }
    
    //-------------------------------------------
    // do the backup from hash cma:
    //-------------------------------------------
    dsl_hash_bac = m_backup_cma( &dsc_hash_cma );
    if ( dsl_hash_bac.adsc_cap == NULL ) {
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }

    //-------------------------------------------
    // do the backup from coll cma:
    //-------------------------------------------
    dsl_coll_bac = m_backup_cma( &dsc_coll_cma );
    if ( dsl_coll_bac.adsc_cap == NULL ) {
        // free backup memory:
        adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }

    //-------------------------------------------
    // enlarge hash cma:
    //-------------------------------------------
    in_min_elements = (int)(   ( 2 - DEF_CK_HASH_LOAD )
                             * (   DEF_CK_RESIZE * dsc_hash_cma.adsc_cap->in_capacity
                                 + dsc_coll_cma.adsc_cap->in_capacity ) );
    bo_ret = m_enlarge_cma( &dsc_hash_cma, in_min_elements );
    if ( bo_ret == false ) {
        // free backup memory:
        adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
        adsc_wsp_helper->m_cb_free_memory( dsl_coll_bac.adsc_cap );
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }
    
    //-------------------------------------------
    // reset hash entries:
    //-------------------------------------------
    bo_ret = m_hash_reset( &dsc_hash_cma );
    if ( bo_ret == false ) {
        // free backup memory:
        adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
        adsc_wsp_helper->m_cb_free_memory( dsl_coll_bac.adsc_cap );
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }
    
    //-------------------------------------------
    // reset coll entries:
    //-------------------------------------------
    bo_ret = m_hash_reset( &dsc_coll_cma );
    if ( bo_ret == false ) {
        // free backup memory:
        adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
        adsc_wsp_helper->m_cb_free_memory( dsl_coll_bac.adsc_cap );
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }

    //-------------------------------------------
    // insert backuped hash entries:
    //-------------------------------------------
    bo_ret = m_copy_hash_from_backup( &dsl_hash_bac );
    if ( bo_ret == false ) {
        // free backup memory:
        adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
        adsc_wsp_helper->m_cb_free_memory( dsl_coll_bac.adsc_cap );
        // close coll cma:
        m_close_cma( &dsc_coll_cma );
        return false;
    }

    //-------------------------------------------
    // insert backuped coll entries:
    //-------------------------------------------
    bo_ret = m_copy_hash_from_backup( &dsl_coll_bac );

    //-------------------------------------------
    // free backup memory:
    //-------------------------------------------
    adsc_wsp_helper->m_cb_free_memory( dsl_hash_bac.adsc_cap );
    adsc_wsp_helper->m_cb_free_memory( dsl_coll_bac.adsc_cap );

    //-------------------------------------------
    // close coll cma:
    //-------------------------------------------
    m_close_cma( &dsc_coll_cma );

    return bo_ret;
} // end of ds_ds_ck_mgmt::m_hash_resize


/**
 * function ds_ck_mgmt::m_copy_hash_from_backup
 *
 * @param[in]   dsd_ck_cma* ads_ck_backup
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_copy_hash_from_backup( dsd_ck_cma* ads_ck_backup )
{
    // initialize some variables:
    int           in_index;
    bool          bo_ret;
    dsd_ck_hash*  ads_backup;

     for ( in_index = 0; in_index < ads_ck_backup->adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( ads_ck_backup, in_index, &ads_backup );
        if (    bo_ret     == false
             || ads_backup == NULL ) {
            return false;
        }

        if ( ads_backup->bo_occupied == false ) {
            continue;
        }
        
        //---------------------------------------
        // insert backup:
        //---------------------------------------
        bo_ret = m_insert_hash( ads_backup );
        if ( bo_ret == false ) {
            return false;
        }
    }

    return true;
} // end of ds_ck_mgmt::m_copy_hash_from_backup


/**
 * function ds_ck_mgmt::m_hash_reset
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_hash_reset( dsd_ck_cma* ads_ck_cma )
{
    // initialize some variables:
    int           in_index;
    bool          bo_ret;
    dsd_ck_hash*  ads_hash;

    for ( in_index = 0; in_index < ads_ck_cma->adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( ads_ck_cma, in_index, &ads_hash );
        if (    bo_ret == false
             || ads_hash == NULL ) {
            return false;
        }
        if ( ads_hash->bo_occupied == true ) {
            ads_hash->bo_occupied = false;
        }
    }
    
    ads_ck_cma->adsc_cap->in_free = ads_ck_cma->adsc_cap->in_capacity;
    return true;
} // end of ds_ck_mgmt::m_hash_reset


/**
 * function ds_ck_mgmt::m_insert_hash
 *
 * @param[in]   dsd_ck_hash*    ads_in
 * @return      dsd_ck_hash*                  backup of cma
*/
bool ds_ck_mgmt::m_insert_hash( dsd_ck_hash* ads_in )
{
    // initialize some variables:
    bool         bo_ret;
    int          in_hash_pos;
    int          in_last;
    int          in_rest_pos;
    dsd_ck_hash* ads_hash;
    dsd_ck_hash* ads_coll;

    //---------------------------------------
    // evaluate new position:
    //---------------------------------------
    in_hash_pos = (ads_in->uin_hash)%(dsc_hash_cma.adsc_cap->in_capacity);

    //---------------------------------------
    // get hash at evaluated position:
    //---------------------------------------
    bo_ret = m_get_element( &dsc_hash_cma, in_hash_pos, &ads_hash );
    if ( bo_ret == false || ads_hash == NULL ) {
        return false;
    }

    //---------------------------------------
    // check if hash at position is free:
    //---------------------------------------
    if ( ads_hash->bo_occupied == false ) {
        /*
            hash table is free at requested position
            -> insert entry
        */
        bo_ret = m_fill( ads_hash, ads_in->uin_hash,
                         ads_in->rch_host, (int)strlen(ads_in->rch_host),
                         ads_in->in_points_to );
        if ( bo_ret == true ) {
            dsc_hash_cma.adsc_cap->in_free--;
        }
    } else {
        /*
            hash table is not free at requested position
            -> insert entry in collusion table
        */
        //-----------------------------------
        // get last entry with same hash pos:
        //-----------------------------------
        in_last = m_get_last_next_pointer( in_hash_pos );
        
        //-----------------------------------
        // get next free entry in coll table:
        //-----------------------------------
        ads_coll = m_get_free_coll( &in_rest_pos );
        if (    ads_coll == NULL
             || in_rest_pos < 0 ) {
            return false;
        }

        //-----------------------------------
        // fill hash entry:
        //-----------------------------------
        bo_ret = m_fill( ads_coll, ads_in->uin_hash,
                         ads_in->rch_host, (int)strlen(ads_in->rch_host),
                         ads_in->in_points_to );
        if ( bo_ret == true ) {
            dsc_coll_cma.adsc_cap->in_free--;

            //-------------------------------
            // set next pointer:
            //-------------------------------
            if ( in_last < 0 ) {
                // in hash table:
                ads_hash->in_next_in_rest = in_rest_pos;
            } else {
                // in coll table:
                m_get_element( &dsc_coll_cma, in_last, &ads_coll );
                ads_coll->in_next_in_rest = in_rest_pos;
            }
        }
    } // end of ads_hash->bo_occupied
    return true;
} // end of ds_ck_mgmt::m_insert_hash


/**
 * function ds_ck_mgmt::m_backup_cma
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma      cma to backup
 * @return      dsd_ck_cma                  backup of cma
*/
dsd_ck_cma ds_ck_mgmt::m_backup_cma( dsd_ck_cma* ads_ck_cma )
{
    // initialize some variables:
    dsd_ck_cma    dsl_backup;               // backup cma
    int           in_len_backup;            // length of backup

    dsl_backup.chrc_name[0] = 0;
    dsl_backup.avc_handle   = ads_ck_cma->avc_handle;
    dsl_backup.in_def_elem  = ads_ck_cma->in_def_elem;
    dsl_backup.in_size_elem = ads_ck_cma->in_size_elem;
    dsl_backup.bo_write     = false;

    //-------------------------------------------
    // evaluate length of coll cma:
    //-------------------------------------------
    in_len_backup =   (int)sizeof(dsd_capacity)
                    + (ads_ck_cma->in_size_elem
                    * ads_ck_cma->adsc_cap->in_capacity);

    //-------------------------------------------
    // do the backup from cma:
    //-------------------------------------------
    dsl_backup.adsc_cap = (dsd_capacity*)adsc_wsp_helper->m_cb_get_memory( in_len_backup, false );
    if ( dsl_backup.adsc_cap != NULL ) {
        memcpy( dsl_backup.adsc_cap, ads_ck_cma->adsc_cap, in_len_backup );
    }
    return dsl_backup;
} // end of ds_ck_mgmt::m_backup_cma


/**
 * function ds_ck_mgmt::m_get_last_next_pointer
 *
 * @param[in]   int     in_hash_pos     start point in hash table
 * @return      int
*/
int ds_ck_mgmt::m_get_last_next_pointer( int in_hash_pos )
{
    // intialize some variables:
    int          in_return = -1;
    int          in_next   = -1;
    dsd_ck_hash* ads_hash  = NULL;

    m_get_element( &dsc_hash_cma, in_hash_pos, &ads_hash );
    if (    ads_hash != NULL 
         && ads_hash->bo_occupied ) {
        in_next = ads_hash->in_next_in_rest;

        // loop through next elements:
        while ( in_next > -1 ) {
            in_return = in_next;
            m_get_element( &dsc_coll_cma, in_next, &ads_hash );
            if (    ads_hash != NULL
                 && ads_hash->bo_occupied ) {
                in_next = ads_hash->in_next_in_rest;
            } else {
                break;
            }
        }
    }

    return in_return;
} // end of ds_ck_mgmt::m_get_last_next_pointer


/**
 * function ds_ck_mgmt::m_fill
 *
 * @param[in]   dsd_ck_hash*    ads_hash
 * @param[in]   unsigned int    uin_hash
 * @param[in]   const char*     ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int             in_len_host     length of host
 * @param[in]   int             in_points_to
 * @return      bool                            true = success
*/
bool ds_ck_mgmt::m_fill( dsd_ck_hash* ads_hash, unsigned int uin_hash,
                         const char* ach_host, int in_len_host, int in_points_to )
{
    if ( ads_hash != NULL && ads_hash->bo_occupied == false ) {
        if ( in_len_host >= (int)sizeof(ads_hash->rch_host) ) {
            in_len_host = (int)sizeof(ads_hash->rch_host) - 1;
        }
        memcpy( &(ads_hash->rch_host)[0], ach_host, in_len_host );
        ads_hash->rch_host[in_len_host] = '\0';

        ads_hash->bo_occupied     = true;
        ads_hash->uin_hash        = uin_hash;
        ads_hash->in_points_to    = in_points_to;
        ads_hash->in_next_in_rest = -1;
        return true;
    }

    return false;
} // end of ds_ck_mgmt::m_fill


/**
 * function ds_ck_mgmt::m_get_hash
 *
 * @param[in]   const char*     ach_in
 * @param[in]   int             in_len_in
 * @return      unsigned int
*/
unsigned int ds_ck_mgmt::m_get_hash( const char* ach_in, int in_len_in )
{
    unsigned int in_hash = 5381;

    for(int in_1 = 0; in_1 < in_len_in; in_1++) {
        in_hash = ((in_hash << 5) + in_hash) + ach_in[in_1];
    }
    return in_hash;
} // end of ds_ck_mgmt::m_get_hash


/**
 * function ds_ck_mgmt::m_equals
 *
 * @param[in]   const char* ach_1
 * @param[in]   int         in_len_1
 * @param[in]   const char* ach_2
 * @param[in]   int         in_len_2
 * @return      bool                    true = strings are equal
*/
bool ds_ck_mgmt::m_equals( const char* ach_1, int in_len_1,
                           const char* ach_2, int in_len_2 )
{
    // initialize some variables:
    int  in_compare;
    BOOL bo_ret;

    bo_ret = m_cmpi_vx_vx( &in_compare,
                           (void*)ach_1, min(in_len_1,in_len_2), ied_chs_utf_8,
                           (void*)ach_2, min(in_len_1,in_len_2), ied_chs_utf_8 );
    if ( bo_ret == TRUE && in_compare == 0 ) {
        return true;
    }
    return false;
} // end of ds_ck_mgmt::m_equals


/**
 * function ds_ck_mgmt::m_fill
 *
 * @param[in]   dsd_ck_mgmt*    ads_mgmt        structure that should be filled
 * @param[in]   int             in_points_to    pointer to position in ds_cookie_memory 
 * @param[in]   int             in_par_domain   pointer to father element in ds_cookie_mgmt_table
 * @param[in]   int             in_par_path     pointer to mother element in ds_cookie_mgmt_table
 * @param[in]   int             in_add_childs   increase child counter with this number
 * @return      int                             position where entry is saved at
 *                                              -1 if error occured
*/
bool ds_ck_mgmt::m_fill( dsd_ck_mgmt* ads_mgmt,
                         int in_points_to, int in_par_domain,
                         int in_par_path, int in_add_childs )
{
    // initialize some variables:
    bool bo_ret = false;
    int  in_pos;

    if ( ads_mgmt != NULL ) {
        if ( ads_mgmt->bo_occupied == false ) {
            ads_mgmt->bo_occupied = true;

            // initialize index list:
            for ( in_pos = 0; in_pos < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_pos++ ) {
                ads_mgmt->rin_indices[in_pos] = -1;
            }

            ads_mgmt->in_par_domain = -1;
            ads_mgmt->in_par_path   = -1;
        }
        bo_ret = m_add_index( ads_mgmt, in_points_to );
        if ( bo_ret == true ) {
            bo_ret = m_set_parents( ads_mgmt, in_par_domain, in_par_path );
            if ( in_add_childs > 0 ) {
                ads_mgmt->in_count_childs += in_add_childs;
            }
        }
    }

    return bo_ret;
} // end of ds_ck_mgmt::m_fill


/**
 * function ds_ck_mgmt::m_add_index
 *
 * @param[in]   dsd_ck_mgmt*    ads_mgmt
 * @param[in]   int             in_mem_index    index that should be added
 * @return      bool            true = success
*/
bool ds_ck_mgmt::m_add_index( dsd_ck_mgmt* ads_mgmt, int in_mem_index )
{
    if ( in_mem_index < 0 ) {
        return true;
    }

    for ( int in_1 = 0; in_1 < (int)(sizeof(ads_mgmt->rin_indices)/sizeof(int)); in_1++ ) {
        if ( ads_mgmt->rin_indices[in_1] == -1 ) {
            ads_mgmt->rin_indices[in_1] = in_mem_index;
            ads_mgmt->in_occ_indices++;
            return true;
        } else if ( ads_mgmt->rin_indices[in_1] == in_mem_index ) {
            return true;
        }
    }

    return false;
} // end of ds_ck_mgmt::m_add_index


/**
 * function ds_ck_mgmt::m_set_parents
 *
 * @param[in]   dsd_ck_mgmt*    ads_mgmt
 * @param[in]   int             in_par_domain
 * @param[in]   int             in_par_path
 * @return      bool                        true = success
*/
bool ds_ck_mgmt::m_set_parents( dsd_ck_mgmt* ads_mgmt, int in_par_domain, int in_par_path )
{
    bool bo_1 = false;
    bool bo_2 = false;

    if ( in_par_domain > -1 ) {
        if ( ads_mgmt->in_par_domain == -1 ) {
            ads_mgmt->in_par_domain = in_par_domain;
            bo_1 = true;
        } else if ( ads_mgmt->in_par_domain == in_par_domain ) {
            bo_1 = true;
        }
    } else {
        bo_1 = true;
    }

    if ( in_par_path > -1 ) {
        if ( ads_mgmt->in_par_path == -1 ) {
            ads_mgmt->in_par_path = in_par_path;
            bo_2 = true;
        } else if ( ads_mgmt->in_par_path == in_par_path ) {
            bo_2 = true;
        }
    } else {
        bo_2 = true;
    }

    return (bo_1 && bo_2);
} // end of ds_ck_mgmt::m_set_parents


/**
 * function ds_ck_mgmt::m_get_parent_hosts
 *
 * @param[in]   const char*                             ach_domain
 * @param[in]   int                                     in_len_domain
 * @param[in]   const char*                             ach_path
 * @param[in]   int                                     in_len_path
 * @return      ds_hvector2<ds_hvector2<ds_hstring>>
*/
ds_hvector2<ds_hvector2<ds_hstring>> ds_ck_mgmt::m_get_parent_hosts( const char* ach_domain, int in_len_domain,
                                                                     const char* ach_path,   int in_len_path    )
{
    // initialize some variables:
    ds_hvector2<ds_hvector2<ds_hstring>> ds_hosts  ( adsc_wsp_helper );
    ds_hvector2<ds_hstring>              ds_domains( adsc_wsp_helper );
    ds_hvector2<ds_hstring>              ds_paths  ( adsc_wsp_helper );

    ds_domains = m_get_parent_domains( ach_domain, in_len_domain );
    ds_paths   = m_get_parent_paths  ( ach_path,   in_len_path   );

    for ( int in_1 = 0; in_1 < (int)ds_domains.m_size(); in_1++ ) {
        ds_hvector2<ds_hstring> dsl_temp(adsc_wsp_helper);
        for ( int in_2 = 0; in_2 < (int)ds_paths.m_size(); in_2++ ) {
            dsl_temp.m_add( ds_domains[in_1] + ds_paths[in_2] );
        }
        ds_hosts.m_add( dsl_temp );
    }

    return ds_hosts;
} // end of ds_ds_ck_mgmt::m_get_parent_hosts


/**
 * function ds_ck_mgmt::m_get_first_subentry
 *
 * @param[in]   const char* ach_domain
 * @param[in]   int         in_len_domain
 * @param[in]   const char* ach_path
 * @param[in]   int         in_len_path
*/
int ds_ck_mgmt::m_get_first_subentry( const char* ach_domain, int in_len_domain,
                                      const char* ach_path,   int in_len_path    )
{
    // initialize some variables:
    int                                  in_domain;
    int                                  in_path;
    int                                  in_pos_mgmt;
    ds_hstring                           ds_host ( adsc_wsp_helper );
    ds_hvector2<ds_hvector2<ds_hstring>> ds_hosts( adsc_wsp_helper );

    //------------------------------------------
    // create all subdomains/subpaths pairs:
    //------------------------------------------
    ds_hosts = m_get_parent_hosts( ach_domain, in_len_domain,
                                   ach_path,   in_len_path   );
    if ( ds_hosts.m_empty() == true ) {
        return -1;
    }

    //------------------------------------------
    // find first subentry:
    //------------------------------------------
    for ( in_domain = 0; in_domain < (int)ds_hosts.m_size(); in_domain++ ) {
        for ( in_path = 0; in_path < (int)ds_hosts[in_domain].m_size(); in_path++ ) {
            ds_host = ds_hosts[in_domain][in_path];
            in_pos_mgmt = m_hash_points_to( ds_host.m_get_ptr(), ds_host.m_get_len() );
            if ( in_pos_mgmt > -1 ) {
                return in_pos_mgmt;
            }
        }
    }

    return -1;
} // end of ds_ck_mgmt::m_get_first_subentry


/**
 * function ds_ck_mgmt::m_get_parent_domains
 *
 * @param[in]   const char*             ach_domain  incomming domain
 * @param[in]   int                     in_len      length of domain
 * @return      ds_hvector2<ds_hstring>             parent domain (including input itself!)
*/
ds_hvector2<ds_hstring> ds_ck_mgmt::m_get_parent_domains( const char* ach_domain, int in_len )
{
    // intialize some variables:
    int                     in_pos;
    ds_hstring              dsl_domain ( adsc_wsp_helper );
    ds_hvector2<ds_hstring> dsl_domains( adsc_wsp_helper );
    
    dsl_domain.m_write( ach_domain, in_len );

    if (    dsl_domain.m_get_len() < 1
         || dsl_domain.m_search( "." ) == -1 ) {
        dsl_domains.m_add( dsl_domain );
        return dsl_domains;
    }

    if ( dsl_domain[0] != '.' ) {
        dsl_domains.m_add( dsl_domain );
    }

    in_pos = dsl_domain.m_search( "." );

    while ( in_pos > -1 ) {
        dsl_domains.m_add( dsl_domain.m_substr( in_pos ) );
        in_pos = dsl_domain.m_search( ".", false, in_pos + 1 );
    }

    // remove last entry ".de":
    dsl_domains.m_delete_last();

    return dsl_domains;
} // end of ds_ck_mgmt::m_get_parent_domains


/**
 * function ds_ck_mgmt::m_get_parent_paths
 *
 * @param[in]   const char*             ach_path    incomming path
 * @param[in]   int                     in_len      length of path
 * @return      ds_hvector2<ds_hstring>             parent paths (including input itself!)
*/
ds_hvector2<ds_hstring> ds_ck_mgmt::m_get_parent_paths( const char* ach_path, int in_len )
{
    // intialize some variables:
    int                     in_pos;
    ds_hstring              dsl_path( adsc_wsp_helper );
    ds_hvector2<ds_hstring> dsl_paths( adsc_wsp_helper );

    dsl_path.m_write( ach_path, in_len );
#ifdef _DEBUG
    // MJ TESTING
    //dsl_path.m_write( "test1/test2/" );
#endif
    in_pos = dsl_path.m_search_last( "/" );
    
    while ( in_pos > -1 ) {
        dsl_paths.m_add( dsl_path.m_substr( 0, in_pos + 1 ) );
        if ( in_pos == 0 ) {
            break;
        }
        in_pos = dsl_path.m_search_last( "/", false, in_pos - 1 );
    }

    return dsl_paths;
} // end of ds_ck_mgmt::m_get_parent_paths


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
        ds_cookie.m_replace( CK_SCRIPT_SEMICOLON, ";" );
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
    // initialize some variables:
    void* av_data;                              // pointer to cma content
    int   in_len;                               // length of cma content
    bool  bo_created = false;                   // cma created
    bool  bo_ret;                               // return for some function calls

    //-----------------------------------------------
    // check if cma is already open:
    //-----------------------------------------------
    if (    ads_ck_cma->avc_handle != NULL 
         && ads_ck_cma->adsc_cap   != NULL ) {
        //-------------------------------------------
        // check write mode of cma:
        //-------------------------------------------
        if (    ads_ck_cma->bo_write == false 
             && bo_write              == true  ) {
            /*
                cma is open in read mode but we request write access
                -> close it and open again in write mode
            */
            m_close_cma( ads_ck_cma );
        } else {
            return true;
        }
    } else {
        //-------------------------------------------
        // check if cma exists:
        //-------------------------------------------
        bo_ret = adsc_wsp_helper->m_cb_exist_cma( &ads_ck_cma->chrc_name[0],
                                                  strlen(ads_ck_cma->chrc_name) );
        if ( bo_ret == false ) {
            /*
                cma does not exists yet -> create it
            */
            bo_created = m_create_cma( ads_ck_cma );
            if ( bo_created == false ) {
                return false;
            }
        }
    }

    //-----------------------------------------------
    // open cma:
    //-----------------------------------------------
    ads_ck_cma->avc_handle = adsc_wsp_helper->m_cb_open_cma( &ads_ck_cma->chrc_name[0],
                                                             strlen(ads_ck_cma->chrc_name),
                                                             &av_data, &in_len, bo_write );
    if ( ads_ck_cma->avc_handle == NULL ) {
        return false;
    }

    //-----------------------------------------------
    // check return data:
    //-----------------------------------------------
    if (    av_data == NULL
         || in_len  <  (int)sizeof(dsd_capacity) ) {
        m_close_cma( ads_ck_cma );
        return false;
    }

    //-----------------------------------------------
    // initialize content pointer:
    //-----------------------------------------------
    ads_ck_cma->adsc_cap = (dsd_capacity*)av_data;
    if ( bo_created == true ) {
        ads_ck_cma->adsc_cap->in_free     = ads_ck_cma->in_def_elem;
        ads_ck_cma->adsc_cap->in_capacity = ads_ck_cma->in_def_elem;
    }

    //-----------------------------------------------
    // save write mode:
    //-----------------------------------------------
    ads_ck_cma->bo_write = bo_write;
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
    ads_ck_cma->adsc_cap = NULL;
    ads_ck_cma->bo_write = false;
    return adsc_wsp_helper->m_cb_close_cma( &ads_ck_cma->avc_handle );
} // end of ds_ck_mgmt::m_close_cma


/**
 * function ds_ck_mgmt::m_create_cma
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma  cookie cma structure
 * @return      bool                    true = success
*/
bool ds_ck_mgmt::m_create_cma( dsd_ck_cma* ads_ck_cma )
{
    return adsc_wsp_helper->m_cb_create_cma( &ads_ck_cma->chrc_name[0],
                                             strlen(ads_ck_cma->chrc_name),
                                             NULL,
                                               (int)sizeof(dsd_capacity)
                                             + (ads_ck_cma->in_def_elem
                                             * ads_ck_cma->in_size_elem) );
} // end of ds_ck_mgmt::m_create_cma


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
    void* av_data;                                  // pointer to cma content
    int   in_used;                                  // used entries
    int   in_new_size;                              // new size

    // check if cma is opened already:
    if ( ads_ck_cma->avc_handle == NULL ) {
        return false;
    }

    // save number off used entries:
    in_used = ads_ck_cma->adsc_cap->in_capacity - ads_ck_cma->adsc_cap->in_free;
#ifdef _DEBUG
    if ( in_used < 0 ) {
        printf("stop");
    }
#endif

    // evaluate new size:
    if ( in_min_elements < DEF_CK_RESIZE * ads_ck_cma->adsc_cap->in_capacity ) {
        in_min_elements = DEF_CK_RESIZE * ads_ck_cma->adsc_cap->in_capacity;
    }
    in_new_size =   (int)sizeof(dsd_capacity)
                  + ( in_min_elements * ads_ck_cma->in_size_elem );

    // do the resize:
    bo_ret = adsc_wsp_helper->m_cb_resize_cma( ads_ck_cma->avc_handle,
                                               &av_data, in_new_size );
    if ( bo_ret == false ) {
        return false;
    }
    ads_ck_cma->adsc_cap = (dsd_capacity*)av_data;
    ads_ck_cma->adsc_cap->in_capacity = in_min_elements;
    ads_ck_cma->adsc_cap->in_free     = in_min_elements - in_used;
    return true;
} // end of ds_ck_mgmt::m_enlarge_cma


/**
 * ds_ck_mgmt::m_setup_cma_names
 *
 * @param[in]   const char* ach_cmabase
 * @return      bool
*/
bool ds_ck_mgmt::m_setup_cma_names( const char* ach_cmabase )
{
    // initialize some variables:
    bool bo_ret;

    bo_ret  = m_create_name( dsc_hash_cma.chrc_name,
                             sizeof(dsc_hash_cma.chrc_name),
                             ach_cmabase, HASH_CMA_SUFFIX );
    bo_ret &= m_create_name( dsc_coll_cma.chrc_name,
                             sizeof(dsc_coll_cma.chrc_name),
                             ach_cmabase, COLL_CMA_SUFFIX );
    bo_ret &= m_create_name( dsc_mgmt_cma.chrc_name,
                             sizeof(dsc_mgmt_cma.chrc_name),
                             ach_cmabase, MGMT_CMA_SUFFIX );
    bo_ret &= m_create_name( dsc_stor_cma.chrc_name,
                             sizeof(dsc_stor_cma.chrc_name),
                             ach_cmabase, STOR_CMA_SUFFIX );
    return bo_ret;
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
bool ds_ck_mgmt::m_create_name( char* ach_out,        int in_max_len,
                                const char* ach_base, const char* ach_suffix )
{
    // check input:
    if (    ach_base   == NULL
         || ach_suffix == NULL
         || ach_out    == NULL ) {
        return false;
    }

    // initialize some variables:
    int in_len_base = (int)strlen(ach_base);
    int in_len_suff = (int)strlen(ach_suffix);
    
    if ( in_len_base + in_len_suff < in_max_len ) {
        memcpy( &ach_out[0], ach_base, in_len_base );
        memcpy( &ach_out[in_len_base], ach_suffix, in_len_suff );
        ach_out[in_len_base + in_len_suff] = 0;
        return true;
    }
    return false;
} // end of ds_ck_mgmt::m_create_name


/**
 * function ds_ck_mgmt::m_get_element
 * get element from ads_ck_cma by index
 *
 * @param[in]   dsd_ck_cma* ads_ck_cma  cookie cma structure
 * @param[in]   int         in_index    index of requested element
 * @param[out]  T**         aads_out    pointer to found element
 * @return      bool                    true = success
*/
template <class T> bool ds_ck_mgmt::m_get_element( dsd_ck_cma* ads_ck_cma,
                                                   int in_index, T** aads_out )
{
    // initialize some variables:
    int in_offset;

    if (    ads_ck_cma->avc_handle == NULL
         || ads_ck_cma->adsc_cap   == NULL ) {
        *aads_out = NULL;
        return false;
    }

    if (    in_index < 0
         || in_index > ads_ck_cma->adsc_cap->in_capacity ) {
        *aads_out = NULL;
        return false;
    }

    in_offset  = (int)sizeof(dsd_capacity);
    in_offset += ads_ck_cma->in_size_elem * in_index;

    *aads_out = (T*)(((char*)ads_ck_cma->adsc_cap) + in_offset );
    return true;
} // end of ds_ck_mgmt::m_get_element


/**
 * function ds_ck_mgmt::m_get_free_stor
 *
 * @param[out]  int*            ain_index
 * @return      dsd_ck_stor*            
*/
dsd_ck_stor* ds_ck_mgmt::m_get_free_stor( int* ain_index )
{
    // initialize some variables:
    int          in_index;
    bool         bo_ret;
    dsd_ck_stor* ads_ck_stor;

    //-------------------------------
    // check if cma is open:
    //-------------------------------
    if (    dsc_stor_cma.avc_handle == NULL
         || dsc_stor_cma.adsc_cap   == NULL ) {
        return NULL;
    }

    //-------------------------------
    // check if free entries exists:
    //-------------------------------
    if ( dsc_stor_cma.adsc_cap->in_free < 1 ) {
        bo_ret = m_enlarge_cma( &dsc_stor_cma );
        if (    bo_ret == false 
             || dsc_stor_cma.adsc_cap->in_free < 1 ) {
            return NULL;
        }
    }

    //-------------------------------
    // search first free element:
    //-------------------------------
    for ( in_index = 0; in_index < dsc_stor_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_stor_cma, in_index, &ads_ck_stor );
        if ( bo_ret == false ) {
            return NULL;
        }
        if ( ads_ck_stor->in_length == 0 ) {
            *ain_index = in_index;
            return ads_ck_stor;
        }
    }
    return NULL;
} // end of ds_ck_mgmt::m_get_free_stor


/**
 * function ds_ck_mgmt::m_get_free_mgmt
 *
 * @param[out]  int*            ain_index
 * @return      dsd_ck_mgmt*            
*/
dsd_ck_mgmt* ds_ck_mgmt::m_get_free_mgmt( int* ain_index )
{
    // initialize some variables:
    int          in_index;
    bool         bo_ret;
    dsd_ck_mgmt* ads_ck_mgmt;

    //-------------------------------
    // check if cma is open:
    //-------------------------------
    if (    dsc_mgmt_cma.avc_handle == NULL
         || dsc_mgmt_cma.adsc_cap   == NULL ) {
        return NULL;
    }

    //-------------------------------
    // check if free entries exists:
    //-------------------------------
    if ( dsc_mgmt_cma.adsc_cap->in_free < 1 ) {
        bo_ret = m_enlarge_cma( &dsc_mgmt_cma );
        if (    bo_ret == false 
             || dsc_mgmt_cma.adsc_cap->in_free < 1 ) {
            return NULL;
        }
    }

    //-------------------------------
    // search first free element:
    //-------------------------------
    for ( in_index = 0; in_index < dsc_mgmt_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_mgmt_cma, in_index, &ads_ck_mgmt );
        if ( bo_ret == false ) {
            return NULL;
        }
        if ( ads_ck_mgmt->bo_occupied == false ) {
            *ain_index = in_index;
            return ads_ck_mgmt;
        }
    }
    return NULL;
} // end of ds_ck_mgmt::m_get_free_mgmt


/**
 * function ds_ck_mgmt::m_get_free_coll
 *
 * @param[out]  int*            ain_index
 * @return      dsd_ck_hash*            
*/
dsd_ck_hash* ds_ck_mgmt::m_get_free_coll( int* ain_index )
{
    // initialize some variables:
    int          in_index;
    bool         bo_ret;
    dsd_ck_hash* ads_ck_hash;

    //-------------------------------
    // check if cma is open:
    //-------------------------------
    if (    dsc_coll_cma.avc_handle == NULL
         || dsc_coll_cma.adsc_cap   == NULL ) {
        return NULL;
    }

    //-------------------------------
    // check if free entries exists:
    //-------------------------------
    if ( dsc_coll_cma.adsc_cap->in_free < 1 ) {
        bo_ret = m_enlarge_cma( &dsc_coll_cma );
        if (    bo_ret == false 
             || dsc_coll_cma.adsc_cap->in_free < 1 ) {
            return NULL;
        }
    }

    //-------------------------------
    // search first free element:
    //-------------------------------
    for ( in_index = 0; in_index < dsc_coll_cma.adsc_cap->in_capacity; in_index++ ) {
        bo_ret = m_get_element( &dsc_coll_cma, in_index, &ads_ck_hash );
        if ( bo_ret == false ) {
            return NULL;
        }
        if ( ads_ck_hash->bo_occupied == false ) {
            *ain_index = in_index;
            return ads_ck_hash;
        }
    }
    return NULL;
} // end of ds_ck_mgmt::m_get_free_coll
