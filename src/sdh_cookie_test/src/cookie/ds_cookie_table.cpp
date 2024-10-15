/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_cookie_table.h"

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
void ds_cookie_table::m_setup( ds_wsp_helper* adsl_wsp_helper, int in_hash_items, int in_rest_items )
{
    dc_hash_table.m_setup( adsl_wsp_helper, in_hash_items, in_rest_items );
    dc_mgmt_table.m_setup( adsl_wsp_helper, in_hash_items );
} // end of ds_cookie_table::m_setup


/**
 *
 * function ds_cookie_table::m_insert_entry
 *
 * @param[in]   char*   ach_user        session id of current user
 * @param[in]   int     in_len_user     length of ach_user
 * @param[in]   char*   ach_host        reqesting host "www.hob.de/test/" but not "www.hob.de/test/side.html"
 * @param[in]   int     in_len_host     length of host
 * @param[in]   bool    bo_overwrite    true -> cookie was only overwritten (exists already!)
 * @param[in]   int     in_mem_index    index in memory, where cookie is saved
 *
 * @return      bool                    true = success
 *
*/
bool ds_cookie_table::m_insert_entry( char* ach_user, int in_len_user, 
                                      char* ach_host, int in_len_host, 
                                      bool bo_overwrite, int in_mem_index )
{
    // initialize some variables:
    bool   bo_return    = false;        // return value
    int    in_add_child = 0;            // number of childs to be added
    string str_host     = "";           // temporary value for host (in for loop)
    vector< vector<string> > v_hosts;     // container for all subdomains!
    vector<int>            v_mothers;
    
    int in_father   = -1;
    int in_mother   = -1;
    int in_saved_at = -1;               // saved at index ...
    int in_position = -1;

    // get all (parent) subdomains
    v_hosts = m_get_parent_hosts( ach_host, in_len_host );

    if ( v_hosts.empty() ) {
        return false;
    }

    // start inserting ...
    int in_1 = (int)v_hosts.size() - 1;
    int in_2 = 0;

    // setup v_mothers vector!
    for ( ; in_2 < (int)v_hosts.at(in_1).size(); in_2++ ) {
        v_mothers.push_back(-1);
    }

    
    // run (backward!) through all subdomains:
    for ( ; in_1 >= 0; in_1-- ) {
        in_saved_at = -1;
        in_2 = (int)v_hosts.at(in_1).size() - 1;
        for ( ; in_2 >= 0; in_2-- ) {
            // reset return value:
            bo_return = false;

            // get host:
            ach_host    = (char*)(v_hosts.at(in_1).at(in_2)).c_str();
            in_len_host = (int)(v_hosts.at(in_1).at(in_2)).length();

            // check if entrie already exists in hash table:
            in_position = dc_hash_table.m_get_entry( ach_user, in_len_user, ach_host, in_len_host );

            // get saved index:
            in_father = in_saved_at;
            in_mother = v_mothers.at(in_2);
            // get in_add_child:
            if ( bo_overwrite ) {
                in_add_child = 0;
            } else if ( in_2 == 0 ) {
                in_add_child = 1;
            } else {
                in_add_child = 2;
            }
            // save data:
            // take care:
            // in_mem_index is the index of the saved cookie to the host ach_host
            // all other (sub-)domains, must not point to this index!
            // therefore, only insert in_mem_index in original host!
            // At orginal host, there are no childs to add !!!
            if ( in_1 == 0 && in_2 == 0 ) {
                in_saved_at = dc_mgmt_table.m_insert_entry( in_position, in_mem_index, in_father, in_mother, 0 );
                if ( in_saved_at > -1 && in_position < 0 ) {
                    bo_return = dc_hash_table.m_insert_entry( ach_user, in_len_user, ach_host, in_len_host, in_saved_at ); 
                } else if ( in_saved_at > -1 ) {
                    bo_return = true;
                }
            } else {
                in_saved_at = dc_mgmt_table.m_insert_entry( in_position, -1, in_father, in_mother, in_add_child );
                if ( in_saved_at > -1 && in_position < 0 ) {
                    bo_return = dc_hash_table.m_insert_entry( ach_user, in_len_user, ach_host, in_len_host, in_saved_at ); 
                } else if ( in_saved_at > -1 ) {
                    bo_return = true;
                }
            }
            v_mothers.at(in_2) = in_saved_at;
            if ( !bo_return ) {
                return bo_return;
            }
        }
    }

    return bo_return;
} // end of ds_cookie_table::m_insert_entry


/**
 *
 * function ds_cookie_table::m_delete_entry
 *
 * @param[in]   int     in_points_to        pointer in memory, where cookie is saved
 * @param[in]   bool    bo_ignore_dependencies    true = entry will be deleted, even if there 
 *                                          exists some childs
 *                                          default should be false!!!
 *
 * @return      bool                        true = success
 *
*/
bool ds_cookie_table::m_delete_entry( int in_points_to, bool bo_ignore_dependencies )
{
    // initialize some variables:
    bool bo_return = false;
    vector<int> vin_hash_entries;

    vin_hash_entries = dc_mgmt_table.m_delete_entry( in_points_to, bo_ignore_dependencies );

    for ( int in_pos = 0; in_pos < (int)vin_hash_entries.size(); in_pos++ ) {
        bo_return = dc_hash_table.m_delete_entry( vin_hash_entries.at(in_pos) );
        if ( !bo_return ) {
            break;
        }
    }

    return bo_return;
} // end of ds_cookie_table::m_delete_entry

/**
 *
 * function ds_cookie_table::m_get_entries
 *
 * @param[in]   char*   ach_user        session id of current user
 * @param[in]   int     in_len_user     length of ach_user
 * @param[in]   char*   ach_host        reqesting host "www.hob.de/test/" but not "www.hob.de/test/side.html"
 * @param[in]   int     in_len_host     length of host
 * @param[in]   bool    bo_secure       is ssl connection?
 *
 * @return      vector<int>             indices of entries in ds_cookie_memory
 *
*/
vector<int> ds_cookie_table::m_get_entries( char* ach_user, int in_len_user, char* ach_host, int in_len_host, bool bo_secure )
{
    // initialize some variables:
    vector<int> vin_return;
    int         in_mgmt_pos = 0;

    in_len_host = m_remove_std_port( ach_host, in_len_host, bo_secure );
    in_mgmt_pos = m_find_first_subdomain( ach_user, in_len_user, ach_host, in_len_host );

    if ( in_mgmt_pos > -1 ) {
        vin_return = dc_mgmt_table.m_get_entries( in_mgmt_pos );
    }

    return vin_return;
} // end of ds_cookie_table::m_get_entries


/**
 *
 * function ds_cookie_table::m_remove_std_port
 *
 * @param[in]   char* ach_url
 * @param[in]   int   in_len
 * @param[in]   bool  bo_secure       is ssl connection?
 *
 * @return      int                 new length
 *
*/
int ds_cookie_table::m_remove_std_port( char* ach_url, int in_len, bool bo_secure )
{
    // initialize some variables:
    int in_return   = in_len;
    int in_position =  0;
    int in_port     =  0;
    int in_offset   = -1;

    for ( ; in_position < in_len; in_position++ ) {
        if ( ach_url[in_position] == ':' ) {
            in_port = atoi(ach_url + in_position + 1);
            if (    bo_secure == false 
                 && in_port   == 80    ) {
                in_offset = in_position;
                in_return = in_len - 3;
                in_position += 3;
                for ( ; in_position < in_len; in_position++ ) {
                    ach_url[in_offset]   = ach_url[in_position];
                    ach_url[in_position] = 0;
                    in_offset++;
                }
            }
            // MJ 02.05.09, Ticket[17354]:
            if (    bo_secure == true 
                 && in_port   == 443   ) {
                in_offset = in_position;
                in_return = in_len - 4;
                in_position += 4;
                for ( ; in_position < in_len; in_position++ ) {
                    ach_url[in_offset]   = ach_url[in_position];
                    ach_url[in_position] = 0;
                    in_offset++;
                }
            }
        }
    }
    return in_return;
} // end of ds_cookie_table::m_remove_std_port


/**
 *
 * function ds_cookie_table::m_get_exact_entries
 *
 * @param[in]   char*   ach_user        session id of current user
 * @param[in]   int     in_len_user     length of ach_user
 * @param[in]   char*   ach_host        reqesting host "www.hob.de/test/" but not "www.hob.de/test/side.html"
 * @param[in]   int     in_len_host     length of host
 *
 * @return      vector<int>             indices of entries in ds_cookie_memory
 *
*/
vector<int> ds_cookie_table::m_get_exact_entries( char* ach_user, int in_len_user, char* ach_host, int in_len_host )
{
    // initialize some variables:
    vector<int> vin_return;
    int         in_mgmt_pos = 0;

    in_mgmt_pos = dc_hash_table.m_get_entry( ach_user, in_len_user, ach_host, in_len_host );

    if ( in_mgmt_pos > -1 ) {
        vin_return = dc_mgmt_table.m_get_exact_entries( in_mgmt_pos );
    }

    return vin_return;
} // end of ds_cookie_table::m_get_exact_entries


/**
 *
 * function ds_cookie_table::m_get_user_entries
 *
 * @param[in]   char* ach_user
 * @param[in]   int   in_len_user
 *
 * @return      vector<int>         indices of entries in ds_cookie_memory
 *
*/
vector<int> ds_cookie_table::m_get_user_entries( char* ach_user, int in_len_user )
{
    // initialize some variables:
    vector<int> vin_user_entries;
    vector<int> vin_temp;  
    vector<int> vin_mgmt_pos;

    vin_mgmt_pos = dc_hash_table.m_get_all_user_entries( ach_user, in_len_user );

    for ( int in_pos = 0; in_pos < (int)vin_mgmt_pos.size(); in_pos++ ) {
        vin_temp = dc_mgmt_table.m_get_entries( vin_mgmt_pos.at(in_pos) );
        // put all values in our vector:
        for ( int in_1 = 0; in_1 < (int)vin_temp.size(); in_1++ ) {
            if ( !m_is_value_in( vin_user_entries, vin_temp.at(in_1) ) ) {
                vin_user_entries.push_back( vin_temp.at(in_1) );
            }
        }
    }

    return vin_user_entries;
} // end of ds_cookie_table::m_get_user_entries


/**
 *
 * function ds_cookie_table::m_is_value_in
 *
 * @param[in]   vector<int> vin_search_in
 * @param[in]   int         in_find
 *
 * @return      bool
 *
*/
bool ds_cookie_table::m_is_value_in( vector<int> vin_search_in, int in_find )
{
    for ( int in_1 = 0; in_1 < (int)vin_search_in.size(); in_1++ ) {
        if ( vin_search_in.at(in_1) == in_find ) {
            return true;
        }
    }
    return false;
} // end of ds_cookie_table::m_is_value_in


/**
 *
 * function ds_cookie_table::m_cb_get_hash_overview
 *
 * @return      string
 *
*/
string ds_cookie_table::m_cb_get_hash_overview()
{
    return "";//dc_hash_table.m_get_overview();
} // end of ds_cookie_table::m_cb_get_hash_overview


/**
 *
 * function ds_cookie_table::m_cb_get_mgmt_overview
 *
 * @return      string
 *
*/
string ds_cookie_table::m_cb_get_mgmt_overview()
{
    return dc_mgmt_table.m_get_overview();
} // end of ds_cookie_table::m_cb_get_mgmt_overview

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_table::m_find_first_subdomain
 *
 * get pos in r_mgmt for first subdomain in list!
 *
 * @param[in]   char*   ach_user        session id of current user
 * @param[in]   int     in_len_user     length of ach_user
 * @param[in]   char*   ach_host        reqesting host "www.hob.de/test/"
 * @param[in]   int     in_len_host     length of host
 *
 * @return      int
 *
*/
int ds_cookie_table::m_find_first_subdomain( char* ach_user, int in_len_user,
                                             char* ach_host, int in_len_host )
{
    // initialize some variables:
    int in_mgmt_pos = -1;
    vector< vector<string> > v_hosts;
    
    // get all subdomains:
    v_hosts = m_get_parent_hosts( ach_host, in_len_host );
    
    if ( v_hosts.empty() ) {
        return in_mgmt_pos;
    }

    // search first of them in list:
    for ( int in_1 = 0; in_1 < (int)v_hosts.size(); in_1++ ) {
        for ( int in_2 = 0; in_2 < (int)v_hosts.at(in_1).size(); in_2++ ) {
            ach_host    = (char*)v_hosts.at(in_1).at(in_2).c_str();
            in_len_host = (int)v_hosts.at(in_1).at(in_2).length();
            in_mgmt_pos = dc_hash_table.m_get_entry( ach_user, in_len_user, ach_host, in_len_host );
            if ( in_mgmt_pos > -1 ) {
                in_1 = (int)v_hosts.size(); // break first loop too
                break;
            }
        }
    }
    return in_mgmt_pos;
} // end of ds_cookie_table::m_find_first_subdomain


/**
 *
 * function ds_cookie_table::m_get_parent_hosts
 *
 * @param[in]   char*           ach_host
 * @param[in]   int             in_len_host
 *
 * @return      vector<string>  parent domains (including input itself!)
 *
*/
vector< vector<string> > ds_cookie_table::m_get_parent_hosts( char* ach_host, int in_len_host )
{
    // initialize some variables:
    vector< vector<string> > v_hosts;
    vector<string> v_paths;
    vector<string> v_domains;
    string str_host( ach_host, in_len_host );

    // get url and path:
    string str_url  = "";
    string str_path = "";
    size_t in_pos   = 0;

    in_pos = str_host.find("/");
    if ( in_pos == string::npos ) {
        str_url  = str_host;
        str_path = "/";
    } else {
        str_url  = str_host.substr(0, in_pos);
        str_path = str_host.substr(in_pos, str_host.length());
    }
    
    //v_paths   = m_get_parent_paths( "/test1/test2/" );
    v_paths   = m_get_parent_paths( str_path );
    v_domains = m_get_parent_domains( str_url );

    for ( int in_1 = 0; in_1 < (int)v_domains.size(); in_1++ ) {
        vector<string> v_temp;
        for ( int in_2 = 0; in_2 < (int)v_paths.size(); in_2++ ) {
            v_temp.push_back( v_domains.at(in_1) + v_paths.at(in_2) );
        }
        v_hosts.push_back(v_temp);
    }

    return v_hosts;
} // end of ds_cookie_table::m_get_parent_hosts

/**
 *
 * function ds_cookie_table::m_get_parent_paths
 *
 * @param[in]   string          str_path
 *
 * @return      vector<string>  parent paths (including input itself!)
 *
*/
vector<string> ds_cookie_table::m_get_parent_paths( string str_path )
{
    vector<string> v_paths;
    size_t  in_pos = 0;

    in_pos = str_path.find_last_of( "/" );

    while (in_pos != string::npos ) {
        v_paths.push_back( str_path.substr(0, in_pos + 1) );
        if ( in_pos == 0 ) {
            break;
        }
        in_pos = str_path.find_last_of( "/", in_pos - 1 );
    }

    return v_paths;
} // end of ds_cookie_table::m_get_parent_paths


/**
 *
 * function ds_cookie_table::m_get_parent_domains
 *
 * @param[in]   string          str_domain
 *
 * @return      vector<string>  parent domains (including input itself!)
 *
*/
vector<string> ds_cookie_table::m_get_parent_domains( string str_domain )
{
    vector<string> v_domains;
    size_t  in_pos = 0;

    if (    (int)str_domain.length() < 1 
         || str_domain.find(".") == string::npos ) 
    {
        v_domains.push_back( str_domain );
        return v_domains;
    }

    if ( str_domain.at(0) != '.' ) {
        v_domains.push_back( str_domain );
    }
    in_pos = str_domain.find(".", 0);

    while ( in_pos != string::npos ) {
        v_domains.push_back( str_domain.substr( in_pos, str_domain.length() ) );
        in_pos = str_domain.find( ".", in_pos + 1 );
    }

    // remove last entry ".de" is not a valid url
    v_domains.pop_back();

    return v_domains;
} // end of ds_cookie_table::m_get_parent_domains
