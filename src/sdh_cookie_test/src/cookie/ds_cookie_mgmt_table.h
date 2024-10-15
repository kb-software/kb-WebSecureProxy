/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_cookie_mgmt_table                                                   |*/
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

#ifndef DS_COOKIE_MGMT_TABLE_H
#define DS_COOKIE_MGMT_TABLE_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "cookie_structures.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;

class ds_cookie_mgmt_table
{
public:
    // setup functions:
    void m_setup( ds_wsp_helper* adsl_wsp_helper, int in_items );

    // functions:
    int         m_insert_entry     ( int in_save_at, int in_points_to, int in_father, int in_mother, int in_add_childs );
    vector<int> m_delete_entry     ( int in_points_to, bool bo_ignore_dependencies = false );
    vector<int> m_get_entries      ( int in_pos );
    vector<int> m_get_exact_entries( int in_pos );
    
    // analysing functions:
    string m_get_overview();
    
private:
    // variables:
    int in_count_locks;
    ds_wsp_helper* adsc_wsp_helper;

    dsd_hl_aux_c_cma_1  ds_cma_man;
    ds_capacity*        ads_man_cap;

#ifdef HL_UNIX
    char awc_cma_name_wsp_wsg_ck_man[LEN_ATTR];
#endif // HL_UNIX

    // functions:
    ds_cookie_link* m_get_link_by_pos    ( int in_pos );
    bool            m_fill               ( ds_cookie_link* ads_link, int in_points_to, int in_father, int in_mother, int in_add_childs );
    bool            m_free               ( ds_cookie_link* ads_link );
    bool            m_add_index          ( ds_cookie_link* ads_link, int in_mem_index );
    bool            m_remove_index       ( ds_cookie_link* ads_link, int in_mem_index );
    void            m_remove_child       ( ds_cookie_link* ads_link );
    bool            m_set_parents        ( ds_cookie_link* ads_link, int in_father, int in_mother );
    vector<int>     m_get_parents        ( int in_mgmt_pos );
    ds_cookie_link* m_get_next_free      ( int* ain_pos );
    ds_cookie_link* m_get_link_by_pointer( int in_points_to, int *ain_pos );

    // setup functions for "array":
    void m_setup_structs();
    
    // cma functions for hash table:
    bool m_create_cma_buf( int in_items );
    bool m_set_size_cma  ( int in_items );
    bool m_get_cma_lock();
    bool m_release_cma_lock();
    bool m_is_cma_locked();

    // analysing functions:
    string m_view( ds_cookie_link* ads_link, int in_pos );
};
#endif //DS_COOKIE_MGMT_TABLE_H
