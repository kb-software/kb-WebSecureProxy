/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include "ds_cookie_hash_table.h"

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
wstring wst_cma_name_wsp_wsg_ck_hash = L"cma_wsp_wsg_ck_hash"; // hash table CMA
wstring wst_cma_name_wsp_wsg_ck_rest = L"cma_wsp_wsg_ck_rest"; // rest hash table CMA

/**
 *
 * function ds_cookie_hash_table::m_setup
 *
*/
void ds_cookie_hash_table::m_setup( ds_wsp_helper* adsl_wsp_helper, int in_hash_items, int in_rest_items )
{
    adsc_wsp_helper = adsl_wsp_helper;
    in_count_hash_locks = 0;

    // setup Common Memory Area (CMA) for hash table:
    memset(&ds_cma_hash, 0, sizeof(struct dsd_hl_aux_c_cma_1));
#ifdef HL_UNIX
    // structure dsd_hl_aux_c_cma_1 cannot handle 4-byte-WCHARS; therefore we must convert to 2-byte-WCHAR
    memset(awc_cma_name_wsp_wsg_ck_hash, 0, LEN_ATTR);
    ads_session->dsc_str_helper.m_conv_utf32_to_utf16((char*)&awc_cma_name_wsp_wsg_ck_hash, LEN_ATTR, (char*)wst_cma_name_wsp_wsg_ck_hash.c_str(), wst_cma_name_wsp_wsg_ck_hash.length()*4);
    ds_cma_hash.ac_cma_name = (void*)awc_cma_name_wsp_wsg_ck_hash;
    ds_cma_hash.inc_len_cma_name = m_len_u16z((HL_WCHAR*)ds_cma_hash.ac_cma_name);
#else
    ds_cma_hash.ac_cma_name = (void*)wst_cma_name_wsp_wsg_ck_hash.c_str();
    ds_cma_hash.inc_len_cma_name = static_cast<int>(wst_cma_name_wsp_wsg_ck_hash.length());
#endif // HL_UNIX
    ds_cma_hash.iec_chs_name = ied_chs_utf_16;

    // create CMA buffer
    m_create_hash_cma_buf( in_hash_items );

    // setup Common Memory Area (CMA) for rest hash table:
    memset(&ds_cma_rest, 0, sizeof(struct dsd_hl_aux_c_cma_1));
#ifdef HL_UNIX
    // structure dsd_hl_aux_c_cma_1 cannot handle 4-byte-WCHARS; therefore we must convert to 2-byte-WCHAR
    memset(awc_cma_name_wsp_wsg_ck_rest, 0, LEN_ATTR);
    ads_session->dsc_str_helper.m_conv_utf32_to_utf16((char*)&awc_cma_name_wsp_wsg_ck_rest, LEN_ATTR, (char*)wst_cma_name_wsp_wsg_ck_rest.c_str(), wst_cma_name_wsp_wsg_ck_rest.length()*4);
    ds_cma_rest.ac_cma_name = (void*)awc_cma_name_wsp_wsg_ck_rest;
    ds_cma_rest.inc_len_cma_name = m_len_u16z((HL_WCHAR*)ds_cma_rest.ac_cma_name);
#else
    ds_cma_rest.ac_cma_name = (void*)wst_cma_name_wsp_wsg_ck_rest.c_str();
    ds_cma_rest.inc_len_cma_name = static_cast<int>(wst_cma_name_wsp_wsg_ck_rest.length());
#endif // HL_UNIX
    ds_cma_rest.iec_chs_name = ied_chs_utf_16;

    // create CMA buffer
    m_create_rest_cma_buf( in_rest_items );
} // end of ds_cookie_hash_table::m_setup


/**
 *
 * function ds_cookie_hash_table::m_insert_entry
 *
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 * @param[in]   int     in_points_to    
 *
 * @return      bool                    true = success
 *
*/
bool ds_cookie_hash_table::m_insert_entry( char* ach_user, int in_len_user,
                                           char* ach_host, int in_len_host,
                                           int in_points_to )
{
    // get cma locks:
    if ( !m_get_lock() ) {
        return false;
    }

    // check free entries in hash table
    if ( ads_hash_cap->in_free < 1 ) {
        bool bo_enlarge = m_set_size_hash_cma( 2*ads_hash_cap->in_capacity );
        if ( !bo_enlarge ) {
            // release cma locks:
            m_release_lock();
            return bo_enlarge;
        }
    }

    // initialize some variables:
    bool            bo_return    = false;
    string          str_hash     = "";
    unsigned int    uin_hash     =  0;
    int             in_hash_pos  = -1;
    ds_cookie_hash* ads_hash     = NULL;
    int             in_last_next = -1;       // index of last next pointer
    int             in_saved_at  = -1;       // position in rest hash table


    // get hash string:
    str_hash.append( ach_user, in_len_user );
    str_hash.append( ach_host, in_len_host );

    // get hash and hash position
    uin_hash    = m_get_hash( (char*)str_hash.c_str(), (int)str_hash.length() );
    in_hash_pos = (uin_hash)%(ads_hash_cap->in_capacity);

    
    if ( m_is_hash_free( in_hash_pos ) ) {
        // hash table is free at in_hash_pos -> insert entry
        ads_hash = m_get_hash_by_pos( in_hash_pos );
        if ( ads_hash != NULL ) {
            // decrease free counter:
            ads_hash_cap->in_free--;
            // fill ads_hash:
            bo_return = m_fill( ads_hash, uin_hash, ach_user, in_len_user, ach_host, in_len_host, in_points_to );
        }
    } else {
        // hash table is not free at in_hash_pos

        // get last next pointer:
        in_last_next = m_get_last_next_pointer( in_hash_pos );

        // check free entries in memory:
        if ( ads_rest_cap->in_free < 1 ) {
            m_set_size_rest_cma( 2*ads_rest_cap->in_capacity );
        }
        
        // -> look for a free entry in hash rest table
        ads_hash = m_get_free_in_rest( &in_saved_at );
        if ( ads_hash != NULL && in_saved_at > -1 ) {
            // free entry in hash rest table is found
            // decrease free counter:
            ads_rest_cap->in_free--;
            // fill ads_hash:
            bo_return = m_fill( ads_hash, uin_hash, ach_user, in_len_user, ach_host, in_len_host, in_points_to );
            // set next pointer:
            if ( in_last_next < 0 ) {
                ads_hash = m_get_hash_by_pos( in_hash_pos );
                if ( in_saved_at != in_hash_pos ) {
                    ads_hash->in_next_in_rest = in_saved_at;
                }
            } else {
                ads_hash = m_get_rest_by_pos( in_last_next );
                if ( in_saved_at != in_last_next ) {
                    ads_hash->in_next_in_rest = in_saved_at;
                }
            }
        }
    }

    // release cma locks:
    m_release_lock();

    return bo_return;
} // end of ds_cookie_hash_table::m_insert_entry


/**
 *
 * function ds_cookie_hash_table::m_delete_entry
 *
 * @param[in]   int     in_points_to    
 *
 * @return      bool                    true = success
 *
*/
bool ds_cookie_hash_table::m_delete_entry( int in_points_to )
{
    // get cma locks:
    if ( !m_get_lock() ) {
        return false;
    }

    // initialize some variables:
    bool            bo_return    = false;
    bool            bo_found     = false;
    ds_cookie_hash* ads_hash     = NULL;
    ds_cookie_hash* ads_hash_new = NULL;
    ds_cookie_hash* ads_hash_parent = NULL;

    // search in hash table for in_points_to:
    for ( int in_pos = 0; in_pos < ads_hash_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_hash_by_pos( in_pos );
        if (    ads_hash != NULL                        /* valid hash    */
             && ads_hash->bo_occupied                   /* used memory   */
             && ads_hash->in_points_to == in_points_to  /* right pointer */ )
        {
            if ( ads_hash->in_next_in_rest > -1 ) {
                // there exists an entry in rest hash table 
                // with same hash value -> insert it at this place
                ads_hash_new = m_get_rest_by_pos( ads_hash->in_next_in_rest );
            }

            if ( ads_hash_new == NULL ) {
                // no element with same hash in rest table
                // -> just free this entry
                bo_return = m_free( ads_hash );
                if ( bo_return ) {
                    // increase free counter:
                    ads_hash_cap->in_free++;
                }
            } else {
                // an element with same hash in rest table is found
                // -> replace element in hash table with the one from rest table
                //    and delete entry in rest table!
                bo_return = m_replace( ads_hash, ads_hash_new );
                if ( m_free( ads_hash_new ) ) {
                    // increase free counter:
                    ads_rest_cap->in_free++;
                }
            }
            bo_found = true;
        }
    } // end of for loop about hash table

    if ( bo_found ) {
        // everthing is done -> exit 
        // release cma locks:
        m_release_lock();
        return bo_return;
    }

    // if we get here, no entry is found in hash table itself,
    // so we must search in rest hash table!

    for ( int in_pos = 0; in_pos < ads_rest_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_rest_by_pos( in_pos );
        if (    ads_hash != NULL                        /* valid hash    */
             && ads_hash->bo_occupied                   /* used memory   */
             && ads_hash->in_points_to == in_points_to  /* right pointer */ )
        {
            if ( ads_hash->in_next_in_rest > -1 ) {
                // there exists an entry in rest hash table 
                // with same hash value -> insert it at this place
                ads_hash_new = m_get_rest_by_pos( ads_hash->in_next_in_rest );
            }

            if ( ads_hash_new == NULL ) {
                // no element with same hash in rest table
                // -> just free this entry
                bo_return = m_free( ads_hash );
                ads_hash_parent = m_get_parent( in_pos );
                if ( ads_hash_parent != NULL ) {
                    ads_hash_parent->in_next_in_rest = -1;
                }
                if ( bo_return ) {
                    // increase free counter:
                    ads_rest_cap->in_free++;
                }
            } else {
                // an element with same hash in rest table is found
                // -> replace element in rest hash table with the next one from rest table
                //    and delete next entry in rest table!
                bo_return = m_replace( ads_hash, ads_hash_new );
                if ( m_free( ads_hash_new ) ) {
                    // increase free counter:
                    ads_rest_cap->in_free++;
                }
            }
            bo_found = true;
        }
    }

    // release cma locks:
    m_release_lock();

    return bo_return;
} // end of ds_cookie_hash_table::m_delete_entry


/**
 * function ds_cookie_hash_table::m_get_parent
 * get element thats next pointer is in_index
 *
 * @param[in]   int in_index
*/
ds_cookie_hash* ds_cookie_hash_table::m_get_parent( int in_index )
{
    // get cma locks:
    if ( !m_get_lock() ) {
        return NULL;
    }

    // initialize some variables:
    ds_cookie_hash* ads_hash = NULL;

    // search in hash table for in_points_to:
    for ( int in_pos = 0; in_pos < ads_hash_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_hash_by_pos( in_pos );
        if (    ads_hash != NULL                        /* valid hash    */
             && ads_hash->bo_occupied                   /* used memory   */
             && ads_hash->in_next_in_rest == in_index   /* right pointer */ )
        {
            // everthing is done -> exit 
            // release cma locks:
            m_release_lock();
            return ads_hash;
        }
    } // end of for loop about hash table

    // if we get here, no entry is found in hash table itself,
    // so we must search in rest hash table!
    for ( int in_pos = 0; in_pos < ads_rest_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_rest_by_pos( in_pos );
        if (    ads_hash != NULL                        /* valid hash    */
             && ads_hash->bo_occupied                   /* used memory   */
             && ads_hash->in_next_in_rest == in_index   /* right pointer */ )
        {
            // everthing is done -> exit 
            // release cma locks:
            m_release_lock();
            return ads_hash;
        }
    }

    // release cma locks:
    m_release_lock();
    return NULL;
} // end of ds_cookie_hash_table::m_get_parent


/**
 *
 * function ds_cookie_hash_table::m_get_entry
 *
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 *
 * @return      int                     pointer to managment
 *                                      -1 if no entry found
 *
*/
int ds_cookie_hash_table::m_get_entry( char* ach_user, int in_len_user,
                                       char* ach_host, int in_len_host )
{
    // get cma locks:
    if ( !m_get_lock() ) {
        return -1;
    }

    // initialize some variables:
    int             in_return   = -1;
    string          str_hash    = "";
    unsigned int    uin_hash    =  0;
    int             in_hash_pos = -1;
    ds_cookie_hash* ads_hash    = NULL;

    // get hash string:
    str_hash.append( ach_user, in_len_user );
    str_hash.append( ach_host, in_len_host );

    // get hash and hash position
    uin_hash    = m_get_hash( (char*)str_hash.c_str(), (int)str_hash.length() );
    in_hash_pos = (uin_hash)%(ads_hash_cap->in_capacity);

    if ( !m_is_hash_free( in_hash_pos ) ) {
        // hash table has entry at in_hash_pos:
        // get it and check hash:
        ads_hash = m_get_hash_by_pos( in_hash_pos );
        if (    ads_hash != NULL                /* valid pointer    */
             && ads_hash->bo_occupied           /* memory is in use */
             && ads_hash->uin_hash == uin_hash  /* equal hashs      */
             && m_are_strings_equal( ads_hash, ach_user, in_len_user, ach_host, in_len_host ) )
        {
            // valid entry found!
            in_return = ads_hash->in_points_to;
        } else if ( ads_hash->in_next_in_rest > -1 ) {
            // entry in hash table is invalid and an entry in rest hash table exists:
            // check this entry:
            while ( ads_hash->in_next_in_rest > -1 ) {
                ads_hash = m_get_rest_by_pos( ads_hash->in_next_in_rest );
                if (    ads_hash != NULL                /* valid pointer    */
                     && ads_hash->bo_occupied           /* memory is in use */
                     && ads_hash->uin_hash == uin_hash  /* equal hashs      */
                     && m_are_strings_equal( ads_hash, ach_user, in_len_user, ach_host, in_len_host ) )
                {
                    // valid entry found!
                    in_return = ads_hash->in_points_to;
                }
            } // end of while ( ads_hash->in_next_in_rest > -1 )
        }
    }

    // release cma locks:
    m_release_lock();

    return in_return;
} // end of ds_cookie_hash_table::m_get_entry


/**
 *
 * function ds_cookie_hash_table::m_get_all_user_entries
 *
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 *
 * @return      vector<int>             positions in mgmt_table
 *
*/
vector<int> ds_cookie_hash_table::m_get_all_user_entries( char* ach_user, int in_len_user )
{
    // initialize return value:
    vector<int> vin_user_entries;

    // get cma locks:
    if ( !m_get_lock() ) {
        return vin_user_entries;
    }

    // initialize some variables:
    ds_cookie_hash* ads_hash      = NULL;
    unsigned int    uin_user_hash = 0;
    int             in_compare    = 0;

    // get hash:
    uin_user_hash = m_get_hash( ach_user, in_len_user );

    // go through hash table:
    for ( int in_pos = 0; in_pos < ads_hash_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_hash_by_pos( in_pos );
        if (    ads_hash != NULL                         /* valid pointer   */
             && ads_hash->bo_occupied                    /* used entry      */
             && ads_hash->uin_user_hash == uin_user_hash /* equal user hash */ ) 
        {
            in_compare = strncmp( ach_user, &ads_hash->rch_user[0], in_len_user );
            if ( in_compare == 0 ) {
                vin_user_entries.push_back( ads_hash->in_points_to );
            }
        }
    }

    // go through rest hash table:
    for ( int in_pos = 0; in_pos < ads_rest_cap->in_capacity; in_pos++ ) {
        ads_hash = m_get_rest_by_pos( in_pos );
        if (    ads_hash != NULL                         /* valid pointer   */
             && ads_hash->bo_occupied                    /* used entry      */
             && ads_hash->uin_user_hash == uin_user_hash /* equal user hash */ ) 
        {
            in_compare = strncmp( ach_user, &ads_hash->rch_user[0], in_len_user );
            if ( in_compare == 0 ) {
                vin_user_entries.push_back( ads_hash->in_points_to );
            }
        }
    }
    
    // release cma locks:
    m_release_lock();

    return vin_user_entries;
} // end of ds_cookie_hash_table::m_get_all_user_entries

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_hash_table::m_fill
 *
 * @param[in]   ds_cookie_hash* ads_hash
 * @param[in]   unsigned int    uin_hash
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 * @param[in]   int             in_points_to
 *
 * @return      bool                            true = success
 *
*/
bool ds_cookie_hash_table::m_fill( ds_cookie_hash* ads_hash,
                                   unsigned int uin_hash,
                                   char* ach_user, int in_len_user,
                                   char* ach_host, int in_len_host,
                                   int in_points_to )
{
    bool bo_return = false;

    if ( ads_hash != NULL && !ads_hash->bo_occupied ) {
        if ( in_len_user >= LEN_ATTR ) {
            in_len_user = LEN_ATTR - 1;
        }
        memcpy( &(ads_hash->rch_user)[0], ach_user, in_len_user );
        ads_hash->rch_user[in_len_user] = '\0';
        if ( in_len_host >= CK_MAX_HOST_LEN ) {
            in_len_host = CK_MAX_HOST_LEN - 1;
        }
        memcpy( &(ads_hash->rch_host)[0], ach_host, in_len_host );
        ads_hash->rch_host[in_len_host] = '\0';
        ads_hash->uin_user_hash = m_get_hash( ach_user, in_len_user );

        ads_hash->bo_occupied  = true;
        ads_hash->uin_hash     = uin_hash;
        ads_hash->in_points_to = in_points_to;
        bo_return = true;
    }

    return bo_return;
} // end of ds_cookie_hash_table::m_fill


/**
 *
 * function ds_cookie_hash_table::m_free
 *
 * @param[in]   ds_cookie_hash* ads_hash
 *
 * @return      bool                            true = success
 *
*/
bool ds_cookie_hash_table::m_free( ds_cookie_hash* ads_hash )
{
    bool bo_return = false;

    if ( ads_hash != NULL && ads_hash->bo_occupied ) {
        ads_hash->bo_occupied     = false;
        ads_hash->uin_hash        =  0;
        ads_hash->uin_user_hash   =  0;
        ads_hash->in_points_to    = -1;
        ads_hash->in_next_in_rest = -1;
        bo_return = true;
    }

    return bo_return;
} // end of ds_cookie_hash_table::m_free


/**
 *
 * function ds_cookie_hash_table::m_replace
 *
 * @param[in]   ds_cookie_hash* ads_hash_replace_this
 * @param[in]   ds_cookie_hash* ads_hash_replace_with
 *
 * @return      bool
 *
*/
bool ds_cookie_hash_table::m_replace( ds_cookie_hash* ads_hash_replace_this,
                                      ds_cookie_hash* ads_hash_replace_with )
{
    // initialize some variables:
    bool bo_return          = false;
    ds_cookie_hash* ads_out = ads_hash_replace_this;
    ds_cookie_hash* ads_in  = ads_hash_replace_with;

    if (    ads_out != NULL
         && ads_in != NULL )
    {
        ads_out->bo_occupied     = ads_in->bo_occupied;
        ads_out->in_next_in_rest = ads_in->in_next_in_rest;
        ads_out->in_points_to    = ads_in->in_points_to;
        ads_out->uin_hash        = ads_in->uin_hash;
        ads_out->uin_user_hash   = ads_in->uin_user_hash;
        memcpy( &ads_out->rch_user[0], &ads_in->rch_user[0], LEN_ATTR );
        memcpy( &ads_out->rch_host[0], &ads_in->rch_host[0], CK_MAX_HOST_LEN );

        bo_return = true;
    }

    return bo_return;
} // end of ds_cookie_hash_table::m_replace


/**
 *
 * function ds_cookie_hash_table::m_are_strings_equal
 *
 * @param[in]   ds_cookie_hash* ads_hash
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 *
 * @return      bool
 *
*/
bool ds_cookie_hash_table::m_are_strings_equal( ds_cookie_hash* ads_hash,
                                                char* ach_user, int in_len_user,
                                                char* ach_host, int in_len_host )
{
    // initialize some variables:
    bool bo_return  = false;
    int  in_compare = 0;

    if (    ads_hash != NULL 
        && ads_hash->bo_occupied )
    {
        in_compare = strncmp( ach_user, &ads_hash->rch_user[0], in_len_user );
        if ( in_compare == 0 ) {
            in_compare = strncmp( ach_host, &ads_hash->rch_host[0], in_len_host );
            if ( in_compare == 0 ) {
                bo_return = true;
            }
        }
    }

    return bo_return;
} // end of ds_cookie_hash_table::m_are_strings_equal


/**
 *
 * function ds_cookie_hash_table::m_get_last_next_pointer
 *
 * @param[in]   int     in_hash_pos     start point in hash table
 *
 * @return      int
 *
*/
int ds_cookie_hash_table::m_get_last_next_pointer( int in_hash_pos )
{
    // intialize some variables:
    int             in_return = -1;
    int             in_next   = -1;
    ds_cookie_hash* ads_hash  = NULL;

    ads_hash = m_get_hash_by_pos( in_hash_pos );
    if (    ads_hash != NULL 
         && ads_hash->bo_occupied ) 
    {
        in_next = ads_hash->in_next_in_rest;
    }

    // loop through next elements:
    while ( in_next > -1 ) {
        in_return = in_next;
        ads_hash = m_get_rest_by_pos( in_next );
        if (    ads_hash != NULL
             && ads_hash->bo_occupied )
        {
            in_next = ads_hash->in_next_in_rest;
        } else {
            in_next = -1;
        }
    }

    return in_return;
} // end of ds_cookie_hash_table::m_get_last_next_pointer


/**
 *
 * function ds_cookie_hash_table::m_create_hash_cma_buf
 *
 * @param[in]   int in_items
 *
*/
bool ds_cookie_hash_table::m_create_hash_cma_buf( int in_items )
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    int in_buf_size = (int)(sizeof(ds_capacity) + in_items * sizeof(ds_cookie_hash));

    // query size (NO LOCK required)
    ds_cma_hash.iec_ccma_def = ied_ccma_query;
    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                      &ds_cma_hash, sizeof(dsd_hl_aux_c_cma_1));
    if (!bo_cma) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE500E: query size of CMA failed" );
        return false;
    }

    if ( (ds_cma_hash.inc_len_cma_area == 0) || (ds_cma_hash.inc_len_cma_area < in_buf_size) ) { // 1st: no CMA exists -> create it; 2nd: CMA exists but is too small -> resize it
        // get lock
        if (!m_get_hash_cma_lock()) {
            return false;
        }
        m_set_size_hash_cma(in_items);
        // release lock
        m_release_hash_cma_lock();
    }
    
    return true;
} // end of ds_cookie_hash_table::m_create_hash_cma_buf


/**
 *
 * function ds_cookie_hash_table::m_create_rest_cma_buf
 *
 * @param[in]   int in_items
 *
*/
bool ds_cookie_hash_table::m_create_rest_cma_buf( int in_items )
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    int in_buf_size = (int)(sizeof(ds_capacity) + in_items * sizeof(ds_cookie_hash));

    // query size (NO LOCK required)
    ds_cma_rest.iec_ccma_def = ied_ccma_query;
    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA, &ds_cma_rest, sizeof(dsd_hl_aux_c_cma_1));
    if (!bo_cma) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE501E: query size of CMA failed" );
        return false;
    }

    if ( (ds_cma_rest.inc_len_cma_area == 0) || (ds_cma_rest.inc_len_cma_area < in_buf_size) ) { // 1st: no CMA exists -> create it; 2nd: CMA exists but is too small -> resize it
        // get lock
        if (!m_get_rest_cma_lock()) {
            return false;
        }
        m_set_size_rest_cma(in_items);
        // release lock
        m_release_rest_cma_lock();
    }
    
    return true;
} // end of ds_cookie_hash_table::m_create_rest_cma_buf


/**
 *
 * function ds_cookie_hash_table::m_get_hash_cma_lock
 *
*/
bool ds_cookie_hash_table::m_get_hash_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_hash_locks++;
    if ( in_count_hash_locks < 2 ) {
        ds_cma_hash.iec_ccma_def = ied_ccma_lock_global; // get a lock
        ds_cma_hash.imc_lock_type = D_CMA_ALL_ACCESS;

        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_hash, sizeof(dsd_hl_aux_c_cma_1) );
        if ( (!bo_cma) ) { // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE502E: no CMA-lock available" );
            return  false;
        }
        
        ads_hash_cap = (ds_capacity*)ds_cma_hash.achc_cma_area;
    }
    return true;
} // end of ds_cookie_hash_table::m_get_hash_cma_lock


/**
 *
 * function ds_cookie_hash_table::m_release_hash_cma_lock
 *
*/
bool ds_cookie_hash_table::m_release_hash_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_hash_locks--;
    if ( in_count_hash_locks < 1 ) {
        ds_cma_hash.iec_ccma_def = ied_ccma_lock_rel_upd;
        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_hash, sizeof(dsd_hl_aux_c_cma_1) );
        if (!bo_cma) {   // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE503E: cannot release lock on CMA" );
            return false;
        }

        ads_hash_cap = NULL;
    }
    return true;
} // end of ds_cookie_hash_table::m_release_hash_cma_lock


/**
 *
 * function ds_cookie_hash_table::m_get_rest_cma_lock
 *
*/
bool ds_cookie_hash_table::m_get_rest_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_rest_locks++;
    if ( in_count_rest_locks < 2 ) {
        ds_cma_rest.iec_ccma_def = ied_ccma_lock_global; // get a lock
        ds_cma_rest.imc_lock_type = D_CMA_ALL_ACCESS;

        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_rest, sizeof(dsd_hl_aux_c_cma_1));
        if ( (!bo_cma) ) { // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE504E: no CMA-lock available" );
            return  false;
        }
        
        ads_rest_cap = (ds_capacity*)ds_cma_rest.achc_cma_area;
    }
    return true;
} // end of ds_cookie_hash_table::m_get_rest_cma_lock


/**
 *
 * function ds_cookie_hash_table::m_release_rest_cma_lock
 *
*/
bool ds_cookie_hash_table::m_release_rest_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_rest_locks--;
    if ( in_count_rest_locks < 1 ) {
        ds_cma_rest.iec_ccma_def = ied_ccma_lock_rel_upd;
        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_rest, sizeof(dsd_hl_aux_c_cma_1));
        if (!bo_cma) {   // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE505E: cannot release lock on CMA" );
            return false;
        }

        ads_rest_cap = NULL;
    }
    return true;
} // end of ds_cookie_hash_table::m_release_rest_cma_lock


/**
 *
 * function ds_cookie_hash_table::m_get_lock
 *
*/
bool ds_cookie_hash_table::m_get_lock()
{
    bool bo_1 = m_get_hash_cma_lock();
    bool bo_2 = m_get_rest_cma_lock();
    return ( bo_1 && bo_2 );
} // end of ds_cookie_hash_table::m_get_lock


/**
 *
 * function ds_cookie_hash_table::m_release_lock
 *
*/
bool ds_cookie_hash_table::m_release_lock()
{
    bool bo_1 = m_release_hash_cma_lock();
    bool bo_2 = m_release_rest_cma_lock();
    return ( bo_1 && bo_2 );
} // end of ds_cookie_hash_table::m_release_lock


/**
 *
 * function ds_cookie_hash_table::m_set_size_hash_cma
 *
*/
bool ds_cookie_hash_table::m_set_size_hash_cma(int in_items)
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    // initialize some variables:
    void* av_hash      = NULL;
    void* av_rest      = NULL;
    int   in_len_hash  = 0;
    int   in_len_rest  = 0;
    bool  bo_backup    = false;
    int   in_min_items = 0;

    // make backup:
    av_hash = m_backup_hash_table( &in_len_hash );
    if ( in_len_hash > 0 ) {
        av_rest = m_backup_rest_table( &in_len_rest );
        if ( in_len_rest > 0 ) {
            bo_backup = true;
        }
    }
    // take care, that we get enough memory, to get rest table in hash table in rest table
    if ( bo_backup ) {
        in_min_items = ads_hash_cap->in_capacity + ads_rest_cap->in_capacity + 1;
        if ( in_items < in_min_items ) {
            in_items = in_min_items;
        }
    }
    
    ds_cma_hash.iec_ccma_def = ied_ccma_set_size;
    ds_cma_hash.inc_len_cma_area =              ((sizeof(ds_capacity)    + 7) & (~ 0x07))
                                   + in_items * ((sizeof(ds_cookie_hash) + 7) & (~ 0x07));

    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                      &ds_cma_hash, sizeof(dsd_hl_aux_c_cma_1));
    if ((!bo_cma) || (ds_cma_hash.achc_cma_area == NULL) ) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE506E: cannot set CMA size" );
        return false;
    }

    ads_hash_cap = (ds_capacity*)ds_cma_hash.achc_cma_area;
    ads_hash_cap->in_capacity = in_items;
    

    if ( bo_backup ) {
        // overwrite cmas:
        m_setup_hash_structs( true );
        m_setup_rest_structs( true );

        // refill cmas:
        bool bo_fill = m_refill_cmas( av_hash, av_rest );
        if ( !bo_fill ) {
            adsc_wsp_helper->m_cb_print_out( "HWSGE507E: cannot refill hash CMAs" );
            return false;
        }

        // free memory:
        adsc_wsp_helper->m_cb_free_memory( (char*)av_hash, in_len_hash );
        adsc_wsp_helper->m_cb_free_memory( (char*)av_rest, in_len_rest );
    } else {
        m_setup_hash_structs();
    }
    
    return true;
} // end of ds_cookie_hash_table::m_set_size_hash_cma


/**
 *
 * function ds_cookie_hash_table::m_refill_cmas
 *
 * @param[in]  void*    av_hash     pointer to copy of hash table
 * @param[in]  void*    av_rest     pointer to copy of rest table
 *
 * @return      bool
 *
*/
bool ds_cookie_hash_table::m_refill_cmas( void* av_hash, void* av_rest )
{
    if ( av_hash == NULL ||av_rest == NULL ) {
        return false;
    }

    // initialize some variables:
    int             in_hash_pos  = -1;
    int             in_last_next = -1;
    int             in_saved_at  = -1;
    ds_capacity*    ads_cap      = NULL;
    ds_cookie_hash* ads_hash_old = NULL;
    ds_cookie_hash* ads_hash_new = NULL;

    // handle av_hash:
    ads_cap = (ds_capacity*)av_hash;

    // loop through av_hash:
    for ( int in_pos = 0; in_pos < ads_cap->in_capacity; in_pos++ ) {
        ads_hash_old = m_get_hash_by_pos( av_hash, in_pos );
        if (    ads_hash_old != NULL        /* valid pointer */
             && ads_hash_old->bo_occupied   /* used memory   */ ) 
        {
            // check free entries in memory:
            if ( ads_hash_cap->in_free < 1 ) {
                return false;
            }
            // get new position in hash table
            // take care to use ads_hash_cap->in_capacity !!!
            in_hash_pos = (ads_hash_old->uin_hash)%(ads_hash_cap->in_capacity);
            // put value in hash table:
            if ( m_is_hash_free( in_hash_pos ) ) {
                ads_hash_new = m_get_hash_by_pos( in_hash_pos );
                // fill ads_hash_new:
                m_replace( ads_hash_new, ads_hash_old );
                // change next pointer:
                ads_hash_new->in_next_in_rest = -1;
                // decrease free counter:
                ads_hash_cap->in_free--;
            } else {
                // get last next pointer:
                in_last_next = m_get_last_next_pointer( in_hash_pos );

                // check free entries in memory:
                if ( ads_rest_cap->in_free < 1 ) {
                    m_set_size_rest_cma( 2*ads_rest_cap->in_capacity );
                }
        
                // -> look for a free entry in hash rest table
                ads_hash_new = m_get_free_in_rest( &in_saved_at );
                if ( ads_hash_new != NULL && in_saved_at > -1 ) {
                    // free entry in hash rest table is found
                    // decrease free counter:
                    ads_rest_cap->in_free--;
                    // fill ads_hash_new:
                    m_replace( ads_hash_new, ads_hash_old );
                    // change next pointer:
                    ads_hash_new->in_next_in_rest = -1;
                    // set next pointer:
                    if ( in_last_next < 0 ) {
                        ads_hash_new = m_get_hash_by_pos( in_hash_pos );
                        ads_hash_new->in_next_in_rest = in_saved_at;
                    } else {
                        ads_hash_new = m_get_rest_by_pos( in_last_next );
                        ads_hash_new->in_next_in_rest = in_saved_at;
                    }
                }
            }
        } // end of if ( ads_hash_old->bo_occupied )
    } // end of for loop through av_hash


    // handle av_rest:
    ads_cap = (ds_capacity*)av_rest;

    // loop through av_rest:
    for ( int in_pos = 0; in_pos < ads_cap->in_capacity; in_pos++ ) {
        ads_hash_old = m_get_hash_by_pos( av_rest, in_pos );
        if (    ads_hash_old != NULL        /* valid pointer */
             && ads_hash_old->bo_occupied   /* used memory   */ ) 
        {
            // check free entries in memory:
            if ( ads_hash_cap->in_free < 1 ) {
                return false;
            }
            // get new position in hash table 
            // take care to use ads_hash_cap->in_capacity !!!
            in_hash_pos = (ads_hash_old->uin_hash)%(ads_hash_cap->in_capacity);
            // put value in hash table:
            if ( m_is_hash_free( in_hash_pos ) ) {
                ads_hash_new = m_get_hash_by_pos( in_hash_pos );
                // fill ads_hash_new:
                m_replace( ads_hash_new, ads_hash_old );
                // change next pointer:
                ads_hash_new->in_next_in_rest = -1;
                // decrease free counter:
                ads_hash_cap->in_free--;
            } else {
                // get last next pointer:
                in_last_next = m_get_last_next_pointer( in_hash_pos );

                // check free entries in memory:
                if ( ads_rest_cap->in_free < 1 ) {
                    m_set_size_rest_cma( 2*ads_rest_cap->in_capacity );
                }
        
                // -> look for a free entry in hash rest table
                ads_hash_new = m_get_free_in_rest( &in_saved_at );
                if ( ads_hash_new != NULL && in_saved_at > -1 ) {
                    // free entry in hash rest table is found
                    // decrease free counter:
                    ads_rest_cap->in_free--;
                    // fill ads_hash_new:
                    m_replace( ads_hash_new, ads_hash_old );
                    // change next pointer:
                    ads_hash_new->in_next_in_rest = -1;
                    // set next pointer:
                    if ( in_last_next < 0 ) {
                        ads_hash_new = m_get_hash_by_pos( in_hash_pos );
                        ads_hash_new->in_next_in_rest = in_saved_at;
                    } else {
                        ads_hash_new = m_get_rest_by_pos( in_last_next );
                        ads_hash_new->in_next_in_rest = in_saved_at;
                    }
                }
            }
        } // end of if ( ads_hash_old->bo_occupied )
    } // end of loop through av_rest


    return true;
} // end of ds_cookie_hash_table::m_refill_cmas


/**
 *
 * function ds_cookie_hash_table::m_get_hash_by_pos
 *
 * @param[in]  void*    av_input    pointer to start of hash table
 * @param[in]  int      in_pos
 *
 * @return     ds_cookie_hash*
 *
*/
ds_cookie_hash* ds_cookie_hash_table::m_get_hash_by_pos( void* av_input, int in_pos ) 
{
    // initialize some variables:
    ds_cookie_hash* ads_hash = NULL;
    ds_capacity*    ads_cap  = NULL;

    ads_cap = (ds_capacity*) av_input;
    if (    ads_cap != NULL
         && in_pos > -1
         && in_pos < ads_cap->in_capacity ) 
    {
        void* av_start = ((char*)ads_cap) + sizeof(ds_capacity);
        // try to align on 8byte boundary
        av_start = DO_ALIGN(av_start);
        av_start = ((char*)av_start) + in_pos * sizeof(ds_cookie_hash);
        ads_hash = (ds_cookie_hash*)av_start;
    }

    return ads_hash;
} // end of ds_cookie_hash_table::m_get_hash_by_pos


/**
 *
 * function ds_cookie_hash_table::m_backup_hash_table
 *  
 * @param[out]  int*    ain_len     length of backup
 *
 * @return      void*               pointer to copy of hash table
 *                                  NULL if nothing to backup
 *
*/
void* ds_cookie_hash_table::m_backup_hash_table( int* ain_len )
{    
    void* av_hash = NULL;
    *ain_len = 0;
    if (    ads_hash_cap != NULL
         && ds_cma_hash.inc_len_cma_area > 0 )
    {
        *ain_len =                               ((sizeof(ds_capacity)    + 7) & (~ 0x07))
                   + ads_hash_cap->in_capacity * ((sizeof(ds_cookie_hash) + 7) & (~ 0x07));
    }

    if ( *ain_len > 0 ) {
        av_hash = adsc_wsp_helper->m_cb_get_memory( *ain_len, true );
        memcpy( av_hash, ads_hash_cap, *ain_len );
    }

    return av_hash;
} // end of ds_cookie_hash_table::m_backup_hash_table


/**
 *
 * function ds_cookie_hash_table::m_backup_rest_table
 * 
 * @param[out]  int*    ain_len     length of backup
 *
 * @return      void*               pointer to copy of hash table
 *                                  NULL if nothing to backup
 *
*/
void* ds_cookie_hash_table::m_backup_rest_table( int* ain_len )
{
    void* av_rest = NULL;
    *ain_len = 0;
    if (    ads_rest_cap != NULL 
         && ds_cma_rest.inc_len_cma_area > 0 ) 
    {
        *ain_len =                               ((sizeof(ds_capacity)    + 7) & (~ 0x07))
                   + ads_rest_cap->in_capacity * ((sizeof(ds_cookie_hash) + 7) & (~ 0x07));
    }

    if ( *ain_len > 0 ) {
        av_rest = adsc_wsp_helper->m_cb_get_memory( *ain_len, true );
        memcpy( av_rest, ads_rest_cap, *ain_len );
    }

    return av_rest;
} // end of ds_cookie_hash_table::m_backup_rest_table


/**
 *
 * function ds_cookie_hash_table::m_set_size_rest_cma
 *
*/
bool ds_cookie_hash_table::m_set_size_rest_cma( int in_items )
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    ds_cma_rest.iec_ccma_def = ied_ccma_set_size;
    ds_cma_rest.inc_len_cma_area =              ((sizeof(ds_capacity) + 7) & (~ 0x07))
                                   + in_items * ((sizeof(ds_cookie_hash)    + 7) & (~ 0x07));

    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                      &ds_cma_rest, sizeof(dsd_hl_aux_c_cma_1));
    if ((!bo_cma) || (ds_cma_rest.achc_cma_area == NULL) ) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE508E: cannot set CMA size" );
        return false;
    }

    ads_rest_cap = (ds_capacity*)ds_cma_rest.achc_cma_area;
    ads_rest_cap->in_capacity = in_items;
    m_setup_rest_structs();
    return true;
} // end of ds_cookie_hash_table::m_set_size_rest_cma


/**
 *
 * function ds_cookie_hash_table::m_get_hash_by_pos
 *
 * @param[in]   int             in_pos      position index (starting at 0)
 *
 * @return      ds_cookie_hash*              pointer to entry at in_pos
 *
*/
ds_cookie_hash* ds_cookie_hash_table::m_get_hash_by_pos( int in_pos )
{
    return m_get_hash_by_pos( ads_hash_cap, in_pos );
} // end of ds_cookie_hash_table::m_get_hash_by_pos


/**
 *
 * function ds_cookie_hash_table::m_get_rest_by_pos
 *
 * @param[in]   int             in_pos      position index (starting at 0)
 *
 * @return      ds_cookie_hash*              pointer to entry at in_pos
 *
*/
ds_cookie_hash* ds_cookie_hash_table::m_get_rest_by_pos( int in_pos )
{
    return m_get_hash_by_pos( ads_rest_cap, in_pos );
} // end of ds_cookie_hash_table::m_get_rest_by_pos


/**
 *
 * function ds_cookie_hash_table::m_is_hash_locked
 *
 * @return    bool   true = we have lock on cma, otherwise false
 *
*/
bool ds_cookie_hash_table::m_is_hash_locked()
{
    if ( in_count_hash_locks > 0 ) {
        return true;
    } else {
        return false;
    }
} // end of ds_cookie_hash_table::m_is_hash_locked


/**
 *
 * function ds_cookie_hash_table::m_is_rest_locked
 *
 * @return    bool   true = we have lock on cma, otherwise false
 *
*/
bool ds_cookie_hash_table::m_is_rest_locked()
{
    if ( in_count_rest_locks > 0 ) {
        return true;
    } else {
        return false;
    }
} // end of ds_cookie_hash_table::m_is_rest_locked


/**
 *
 * function ds_cookie_hash_table::m_is_hash_free
 *
 * @param[in]   int     in_index
 *
 * @return      bool
 *
*/
bool ds_cookie_hash_table::m_is_hash_free( int in_index )
{
    ds_cookie_hash* ads_hash = m_get_hash_by_pos( in_index );
    return !ads_hash->bo_occupied;
} // end of ds_cookie_hash_table::m_is_hash_free


/**
 *
 * function ds_cookie_hash_table::m_get_free_in_rest
 *
 * @param[out]  int*            ain_position    index of return value in rest hash table
 *
 * @return      ds_cookie_hash*
 *
*/
ds_cookie_hash* ds_cookie_hash_table::m_get_free_in_rest( int *ain_position ) 
{
    // initialize some variables:
    ds_cookie_hash* ads_hash = NULL;
    bool            bo_found = false;
    
    if (     m_is_rest_locked()
         &&  ads_rest_cap->in_free > 0 )
    {
        for ( int in_pos = 0; in_pos < ads_rest_cap->in_capacity; in_pos++ ) {
            ads_hash = m_get_rest_by_pos( in_pos );
            if (    ads_hash != NULL
                 && !ads_hash->bo_occupied )
            {
                *ain_position = in_pos;
                bo_found = true;
                break;
            }
        }
    }

    if ( !bo_found ) {
        *ain_position = -1;
        ads_hash = NULL;
    }
    return ads_hash;
} // end of ds_cookie_hash_table::m_get_free_in_rest


/**
 *
 * function ds_cookie_hash_table::m_setup_hash_structs
 *
*/
void ds_cookie_hash_table::m_setup_hash_structs( bool bo_overwrite )
{
    if ( m_is_hash_locked() ) {
        // initialize some variables:
        vector<ds_cookie_hash> v_hashs;
        ds_cookie_hash* ads_hash       = NULL;
        ads_hash_cap->in_free          =  0;
        
        // reset structs:
        for ( int in_pos = 0; in_pos < ads_hash_cap->in_capacity; in_pos++ ) {
            ads_hash = m_get_hash_by_pos( in_pos );
            if ( ads_hash != NULL ) {
                if ( bo_overwrite ) {
                    ads_hash->bo_occupied = false;
                }
                if ( !ads_hash->bo_occupied ) {
                    ads_hash->in_points_to    = -1;
                    ads_hash->uin_hash        =  0;
                    ads_hash->in_next_in_rest = -1;
                    ads_hash->uin_user_hash   =  0;
                    memset( &ads_hash->rch_user[0], 0, LEN_ATTR );
                    memset( &ads_hash->rch_host[0], 0, CK_MAX_HOST_LEN );
                    // increase free counter:
                    ads_hash_cap->in_free++;
                } 
            }
        }
    }
} // end of ds_cookie_hash_table::m_setup_hash_structs


/**
 *
 * function ds_cookie_hash_table::m_setup_rest_structs
 *
*/
void ds_cookie_hash_table::m_setup_rest_structs( bool bo_overwrite )
{
    if ( m_is_rest_locked() ) {
        // initialize some variables:
        ds_cookie_hash* ads_hash;
        ads_rest_cap->in_free = 0;

        for ( int in_pos = 0; in_pos < ads_rest_cap->in_capacity; in_pos++ ) {
            ads_hash = m_get_rest_by_pos( in_pos );
            if ( ads_hash != NULL ) {
                if ( bo_overwrite ) {
                    ads_hash->bo_occupied = false;
                }
                if ( !ads_hash->bo_occupied ) {
                    ads_hash->in_points_to    = -1;
                    ads_hash->uin_hash        =  0;
                    ads_hash->in_next_in_rest = -1;
                    ads_hash->uin_user_hash   =  0;
                    memset( &ads_hash->rch_user[0], 0, LEN_ATTR );
                    memset( &ads_hash->rch_host[0], 0, CK_MAX_HOST_LEN );
                    // increase free counter:
                    ads_rest_cap->in_free++;
                }
            }
        }
    }
} // end of ds_cookie_hash_table::m_setup_hash_structs


/**
 *
 * function ds_cookie_hash_table::m_get_hash
 *
 * @param[in]   char*   ach_in
 * @param[in]   int     in_len_in
 *
 * @return      unsigned int
 *
*/
unsigned int ds_cookie_hash_table::m_get_hash( char* ach_in, int in_len_in )
{
   unsigned int in_hash = 5381;

   for(int in_1 = 0; in_1 < in_len_in; in_1++)
   {
      in_hash = ((in_hash << 5) + in_hash) + ach_in[in_1];
   }

   return in_hash;
} // end of ds_cookie_hash_table::m_get_hash

/*+-------------------------------------------------------------------------+*/
/*| analysing functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/
