/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_cookie_memory                                                      |*/
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

#ifndef DS_COOKIE_MEMORY_H
#define DS_COOKIE_MEMORY_H

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <cstring>
#include <vector>
using namespace std;

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "cookie_structures.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;

class ds_cookie_memory
{
public:
    // setup function:
    void   m_setup( ds_wsp_helper* adsl_wsp_helper, int in_items );

    // functions:
    int            m_insert_entry        ( char* ach_cookie, int in_len_cookie, char* ach_host, int in_len_host, time_t t_expires, bool bo_secure, int in_old_index );
    bool           m_delete_entry        ( int in_index );
    string         m_get_entries         ( vector<int> v_indices, bool bo_secure, int* ain_counter );
    vector<string> m_get_detailed_entries( vector<int> v_indices, bool bo_secure );
    string         m_get_name            ( int in_index, bool bo_secure );
    bool           m_is_persistent       ( int in_index );
    void           m_delete_all_expired  ();
    ds_cookie      m_get_struct_cookie   ( int in_index );

    // analysing functions:
    string m_get_overview();

private:
    // variables:
    int in_count_locks;

    ds_wsp_helper* adsc_wsp_helper;

    dsd_hl_aux_c_cma_1  ds_cma_memory;
    ds_capacity*        ads_capacity;
#ifdef HL_UNIX
    char awc_cma_name_wsp_wsg_ck_mem[LEN_ATTR];
#endif // HL_UNIX

    // functions:
    string     m_get_entry   ( int in_index, bool bo_secure, bool bo_detailed_output );
    ds_cookie* m_get_ck_by_pos( int in_index );
    int        m_find_next_free();
    void       m_setup_structs( bool bo_overwrite = false );
    string     m_get_path    ( int in_index );
    string     m_get_domain  ( int in_index );

    // cma functions:
    void* m_create_cma_buf( int in_items );
    bool  m_set_cma_size(int in_items);
    bool  m_get_cma_lock();
    bool  m_release_cma_lock();

    // analysing functions:
    string m_view( ds_cookie* ads_cookie, int in_pos );
};
#endif //DS_COOKIE_MEMORY_H
