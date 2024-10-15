/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_cookie_table                                                       |*/
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

#ifndef DS_COOKIE_TABLE_H
#define DS_COOKIE_TABLE_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "cookie_structures.h"
#include "ds_cookie_mgmt_table.h"
#include "ds_cookie_hash_table.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;

class ds_cookie_table
{
public:
    // setup functions:
    void m_setup( ds_wsp_helper* adsl_wsp_helper, int in_hash_items, int in_rest_items );

    // functions:
    bool        m_insert_entry     ( char* ach_user, int in_len_user, char* ach_host, int in_len_host, bool bo_overwrite, int in_mem_index );
    bool        m_delete_entry     ( int in_points_to, bool bo_ignore_dependencies =false );
    vector<int> m_get_entries      ( char* ach_user, int in_len_user, char* ach_host, int in_len_host, bool bo_secure );
    vector<int> m_get_exact_entries( char* ach_user, int in_len_user, char* ach_host, int in_len_host );
    vector<int> m_get_user_entries ( char* ach_user, int in_len_user );

    // callback functions:
    string m_cb_get_hash_overview();
    string m_cb_get_mgmt_overview();

private:
    // variables:
    ds_cookie_mgmt_table dc_mgmt_table;
    ds_cookie_hash_table dc_hash_table;
    ds_wsp_helper* adsc_wsp_helper;

    // functions:
    vector< vector<string> > m_get_parent_hosts    ( char* ach_host, int in_len_host );
    vector<string>           m_get_parent_domains  ( string str_domain );
    vector<string>           m_get_parent_paths    ( string str_path );
    bool m_is_value_in( vector<int> vin_search_in, int in_find );
    int  m_find_first_subdomain( char* ach_user, int in_len_user, char* ach_host, int in_len_host );
    
    int m_remove_std_port( char* ach_url, int in_len, bool bo_secure );
};
#endif //DS_COOKIE_TABLE_H
