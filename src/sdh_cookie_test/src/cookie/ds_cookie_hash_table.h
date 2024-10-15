/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_cookie_hash_table                                                   |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   April/Mai 2008                                                        |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#ifndef DS_COOKIE_HASH_TABLE_H
#define DS_COOKIE_HASH_TABLE_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "cookie_structures.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
struct dsd_hl_clib_1; // forward defintion
class ds_wsp_helper;

class ds_cookie_hash_table
{
public:
    // setup functions:
    void m_setup( ds_wsp_helper* adsl_wsp_helper, int in_hash_items, int in_rest_items );

    // functions:
    bool m_insert_entry( char* ach_user, int in_len_user, char* ach_host, int in_len_host, int in_points_to );
    bool m_delete_entry( int in_points_to );
    int  m_get_entry   ( char* ach_user, int in_len_user, char* ach_host, int in_len_host );
    vector<int> m_get_all_user_entries( char* ach_user, int in_len_user );

    // analysing functions:
    //string m_get_overview();

private:
    // variables:
    int in_count_hash_locks;
    int in_count_rest_locks;

    ds_wsp_helper*        adsc_wsp_helper;
    dsd_hl_aux_c_cma_1    ds_cma_hash;
    dsd_hl_aux_c_cma_1    ds_cma_rest;
    ds_capacity*          ads_hash_cap;
    ds_capacity*          ads_rest_cap;

#ifdef HL_UNIX
    char awc_cma_name_wsp_wsg_ck_hash[LEN_ATTR];
    char awc_cma_name_wsp_wsg_ck_rest[LEN_ATTR];
#endif // HL_UNIX
    
    // functions:
    ds_cookie_hash* m_get_hash_by_pos( void* av_input, int in_pos );
    ds_cookie_hash* m_get_hash_by_pos( int in_pos );
    ds_cookie_hash* m_get_rest_by_pos( int in_pos );
    bool            m_is_hash_free( int in_index );
    ds_cookie_hash* m_get_free_in_rest( int* ain_position );
    bool            m_fill   ( ds_cookie_hash* ads_hash, unsigned int uin_hash, char* ach_user, int in_len_user, char* ach_host, int in_len_host, int in_points_to );
    bool            m_free   ( ds_cookie_hash* ads_hash );
    bool            m_replace( ds_cookie_hash* ads_hash_replace_this, ds_cookie_hash* ads_hash_replace_with );
    bool            m_are_strings_equal( ds_cookie_hash* ads_hash, char* ach_user, int in_len_user, char* ach_host, int in_len_host );
    int             m_get_last_next_pointer( int in_hash_pos );

    // MJ 05.10.09, Ticket [18595]:
    ds_cookie_hash* m_get_parent( int in_index );

    // backup functions:
    void* m_backup_hash_table( int* ain_len );
    void* m_backup_rest_table( int* ain_len );
    bool m_refill_cmas      ( void* av_hash, void* av_rest );

    // setup functions for "arrays"
    void m_setup_hash_structs( bool bo_overwrite = false );
    void m_setup_rest_structs( bool bo_overwrite = false );

    // cma functions for hash table:
    bool m_create_hash_cma_buf( int in_items );
    bool m_set_size_hash_cma  ( int in_items );
    bool m_get_hash_cma_lock();
    bool m_release_hash_cma_lock();
    bool m_is_hash_locked();
    // cma functions for rest hash table:
    bool m_create_rest_cma_buf( int in_items );
    bool m_set_size_rest_cma  ( int in_items );
    bool m_get_rest_cma_lock();
    bool m_release_rest_cma_lock();
    bool m_is_rest_locked();
    // cma functions for both:
    bool m_get_lock();
    bool m_release_lock();

    // hash function:
    unsigned int m_get_hash( char* ach_in, int in_len_in );

    // analysing functions:
    string m_view( ds_cookie_hash* ads_hash, int in_pos );
};
#endif //DS_COOKIE_HASH_TABLE_H
