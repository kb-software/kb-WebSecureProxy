/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_hstring.h>
#include <ds_wsp_helper.h>
#include "ds_cookie_manager.h"

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_cookie_manager::ds_cookie_manager(void)
{
}

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_manager::m_setup
 *
 * @return      bool    false in error case, otherwise true
 *
*/
bool ds_cookie_manager::m_setup( ds_wsp_helper* adsl_wsp_helper )
{
    adsc_wsp_helper = adsl_wsp_helper;

    int in_start_count_cookie  = 2;
    int in_start_count_rest_ck = 1;
    ds_cookie_store.m_setup ( adsc_wsp_helper, in_start_count_cookie );
    ds_cookie_tables.m_setup( adsc_wsp_helper, in_start_count_cookie, in_start_count_rest_ck );
    return true;
} // end of ds_cookie_manager::m_setup


/**
 *
 * function ds_cookie_manager::m_set_cookie
 *
 * @param[in]   char*   ach_cookie
 * @param[in]   int     in_len_cookie
 *
 * @return      bool    false in error case, otherwise true
 *
*/
bool ds_cookie_manager::m_set_cookie( string str_host_in, char* ach_cookie, int in_len_cookie )
{
    // initialize some variables:
    int  in_pos        = 0;
    int  in_single_len = 0;
    ds_single_cookie dc_cookie( adsc_wsp_helper );

    // get requesting host information:
#if 0
    if ( ads_session->dsc_ws_gate.m_is_hob_net() ) {
        m_get_host( ads_session->dsc_ws_gate.m_get_ext_host() + str_url );
    } else {
#endif
        m_get_host( str_host_in );
#if 0
    }
#endif

    while ( in_pos < in_len_cookie ) {
        dc_cookie.m_setup( str_host );
        m_get_single_cookie( ach_cookie, in_len_cookie, in_pos, &in_single_len );
        // read in cookie:
        dc_cookie.m_parse_cookie( &ach_cookie[in_pos], in_single_len );
        in_pos += in_single_len + 1;
        if ( !m_save_cookie( &dc_cookie ) ) {
            return false;
        }
    }

    return true;
} // end of ds_cookie_manager::m_set_cookie


/**
 *
 * function ds_cookie_manager::m_get_cookie
 *
 * get cookies in http-header form "name0=value0;name1=value1 ..."
 *
 * @return      string                  cookie string
 *
*/
string ds_cookie_manager::m_get_cookie( string str_host_in )
{
    // initialize some variables:
    ds_hstring  ds_user;
    vector<int> vin_indices;
    string      str_cookie  = "";
    int         in_counter = 0;
    bool        bo_secure  = false;

    struct dsd_sdh_ident_set_1 ds_ident;
    memset( &ds_ident, 0, sizeof(dsd_sdh_ident_set_1) );
    adsc_wsp_helper->m_cb_get_ident( &ds_ident );

    ds_user.m_write( (char*)ds_ident.dsc_userid.ac_str, ds_ident.dsc_userid.imc_len_str );
#if 0
    ds_user = ads_session->dsc_auth.m_get_username();

    // get requesting host information:
    if ( (int)str_host_in.length() < 1 ) {
        string str_url(ads_session->dsc_http_hdr_in.dsc_url.hstr_url_no_id.m_get_ptr());
        m_get_host( str_url );
    } else {
#endif
        m_get_host( str_host_in );
#if 0
    }
#endif
    if ( (int)str_host.length() < 1 ) {
        return "";
    }

    for (int i=0; i< (int)str_host.length(); i++) {
        str_host[i] = (char)tolower(str_host[i]);
    }

    if ( ien_proto == ie_https ) {
        bo_secure = true;
    }
       
    // get indices to user and host information:
    vin_indices = ds_cookie_tables.m_get_entries( ds_user.m_get_ptr(), ds_user.m_get_len(),
                                                  (char*)str_host.c_str(), (int)str_host.length(),
                                                  bo_secure );
    
    // get cookies to indice information:
    str_cookie = ds_cookie_store.m_get_entries( vin_indices, bo_secure, &in_counter );

#if 0
    // print message:
    ds_hstring hstr_msg(ads_session->ads_wsp_helper, "HWSGI518I: ds_cookie_manager::m_get_cookie returns ");
    hstr_msg += in_counter;
    hstr_msg += " cookies";
    ads_session->dsc_transaction.m_print_to_console(&hstr_msg, helper::ien_level_info);
#endif

    return str_cookie;
} // end of ds_cookie_manager::m_get_cookie


/**
 *
 * function ds_cookie_manager::m_trim_cokies
 *
*/
void ds_cookie_manager::m_trim_cokies()
{
    ds_cookie_store.m_delete_all_expired();
} // end of ds_cookie_manager::m_trim_cokies


/**
 *
 * function ds_cookie_manager::m_cb_delete_cookie
 *
 * @param[in]   int     in_points_to        position in ds_cookie_memory
 * @param[in]   bool    bo_ignore_dependencies      true = entry will be deleted, even if there 
 *                                                  exists some childs
 *                                          default should be false!!!
 *
 * @return      bool                        true = success
 *
*/
bool ds_cookie_manager::m_cb_delete_cookie( int in_points_to, bool bo_ignore_dependencies )
{
    bool bo_1 = false;
    bool bo_2 = false;

    if ( in_points_to > -1 ) 
    {
        bo_1 = ds_cookie_store.m_delete_entry( in_points_to );
        bo_2 = ds_cookie_tables.m_delete_entry( in_points_to, bo_ignore_dependencies );
    }

    //adsc_wsp_helper->m_cb_printf_out( "HWSGI519I: ds_cookie_manager::m_cb_delete_cookie delete cookie at position %d", in_points_to );
    return (bo_1 && bo_2);
} // end of ds_cookie_manager::m_cb_delete_cookie


/**
 *
 * function ds_cookie_manager::m_export_cookies
 *
 * export all permanent cookies in xml format
 *
 * @return      bool
 *
*/
bool ds_cookie_manager::m_export_cookies()
{
    // initialize some variables:
    ds_hstring  ds_user;
    vector<int> vin_my_cookies;

#if 0
    // get username:
    ds_user = ads_session->dsc_auth.m_get_username();
#endif
    struct dsd_sdh_ident_set_1 ds_ident;
    memset( &ds_ident, 0, sizeof(dsd_sdh_ident_set_1) );
    adsc_wsp_helper->m_cb_get_ident( &ds_ident );

    ds_user.m_write( (char*)ds_ident.dsc_userid.ac_str, ds_ident.dsc_userid.imc_len_str );
    
    // get all cookies containing to this user:
    vin_my_cookies = ds_cookie_tables.m_get_user_entries( ds_user.m_get_ptr(), ds_user.m_get_len() );

    // get xml:
    for ( int in_pos = 0; in_pos < (int)vin_my_cookies.size(); in_pos++ ) {
        if ( ds_cookie_store.m_is_persistent( vin_my_cookies.at(in_pos) ) ) {
        }
        // until ldap is ready, we only delete nonpersistent cookies
        // the others will stay in memory!!!
        else {
            // delete cookie:
            m_cb_delete_cookie( vin_my_cookies.at(in_pos), false );
        }
    }


    return true;
} // end of ds_cookie_manager::m_export_cookies


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 *
 * function ds_cookie_manager::m_get_single_cookie
 *
 * "Set-Cookie:" can contain more than one cookie, seperatet by ","
 *
 * @param[in]       char*   ach_cookie
 * @param[in]       int     in_len_cookie
 * @param[in]       int     in_pos
 * @param[in/out]   int*    ain_single_len
 *
*/
void ds_cookie_manager::m_get_single_cookie( char* ach_cookie, int in_len_cookie,
                                             int in_pos, int* ain_single_len )
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
} // end of ds_cookie_manager::m_get_single_cookie


/**
 *
 * function ds_cookie_manager::m_get_single_script_cookie
 *
 * "Set-Cookie:" can contain more than one cookie, seperatet by ","
 *
 * @param[in]       char*   ach_cookie
 * @param[in]       int     in_len_cookie
 * @param[in/out]   int     in_pos
 *
 * @return          string
 *
*/
string ds_cookie_manager::m_get_single_script_cookie( char* ach_cookie, int in_len_cookie,
                                                     int* ain_pos, string& str_prefix )
{
    int    in_start_pos  = -1;
    int    in_state      = 0;
    string str_test      = CK_SCRIPT_PREFACE;
    int    in_test_pos   = 0;
    string str_return    = "";
    int    in_single_len = 0;
    size_t in_pos;
    int    in_pref_start = -1;
    str_prefix           = "";

    for ( ; *ain_pos < in_len_cookie; (*ain_pos)++ ) {
        switch ( in_state ) {
            case 0: // search for "HOB_set" prefix
                if ( ach_cookie[*ain_pos] == str_test.at(in_test_pos) ) {
                    if ( in_test_pos == 0 ) {
                        in_pref_start = *ain_pos;
                    }
                    in_test_pos++;
                    if ( in_test_pos == (int)str_test.length() ) {
                        in_state = 1; // cookie is one from script (starting with "HOB_set")
                    }
                } else {
                    in_test_pos = 0;
                }
                continue;
            case 1: // get prefix
                switch ( ach_cookie[*ain_pos] ) {
                    case '=':
                        str_prefix.append( &ach_cookie[in_pref_start], *ain_pos - in_pref_start );
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
        str_return.append( &ach_cookie[in_start_pos], in_single_len );
        // do the replacement
        while ((in_pos = str_return.find(CK_SCRIPT_SEMICOLON)) != string::npos) {
            str_return.replace(in_pos, (string::size_type)strlen(CK_SCRIPT_SEMICOLON), ";");
        }
    }
    return str_return;
} // end of ds_cookie_manager::m_get_single_script_cookie


/**
 *
 * function ds_cookie_manager::m_get_single_xml_cookie
 *
 * @param[in]       char*   ach_data
 * @param[in]       int     in_len_data
 * @param[in/out]   int*    ain_pos
 * @param[in/out]   int*    ain_single_len
 *
*/
void ds_cookie_manager::m_get_single_xml_cookie( char* ach_data, int in_len_data, int* ain_pos, int* ain_single_len )
{
    // initialize some variables:
    int     in_start_pos = 0;
    char*   ach_tag      = NULL;
    int     in_len_tag   = 0;
    bool    bo_found     = true;
    char    rch_tag[10];
    *ain_single_len      = 0;

    while ( *ain_pos < in_len_data ) {
        memset( rch_tag, 0, 10 );
        // get tag:
        m_get_tag( ach_data, in_len_data, ain_pos, &ach_tag, &in_len_tag );
        if ( in_len_tag < 10 ) {
            memcpy( rch_tag, ach_tag, in_len_tag );
            if ( strcmp( rch_tag, "<cookie>" ) == 0 ) {
                bo_found = true;
                break;
            }
        }
    }

    if ( bo_found ) {
        in_start_pos = *ain_pos;
        m_get_value( ach_data, in_len_data, ain_pos, ach_tag, in_len_tag );
        *ain_single_len = *ain_pos - in_start_pos;
        *ain_pos = in_start_pos;
    }
} // end of ds_cookie_manager::m_get_single_xml_cookie


/**
 *
 * function ds_cookie_manager::m_get_tag
 *
 * @param[in]       char*   ach_xml
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[out]      char**  aach_tag
 * @param[out]      int*    ain_len_tag
 *
*/
void ds_cookie_manager::m_get_tag( char* ach_xml, int in_len, int* ain_pos, char** aach_tag, int* ain_len_tag )
{
    int in_start_pos = 0;
    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ach_xml[*ain_pos] ) {
            case '<':
                *aach_tag = &ach_xml[*ain_pos];
                in_start_pos = *ain_pos;
                break;
            default:
                continue;
        }
        break;
    }
    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ach_xml[*ain_pos] ) {
            case '>':
                (*ain_pos)++;
                *ain_len_tag = *ain_pos - in_start_pos;
                break;
            default:
                continue;
        }
        break;
    }
} // end of ds_cookie_manager::m_get_tag


/**
 *
 * function ds_cookie_manager::m_get_value
 *
 * @param[in]       char*   ach_xml
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[in]       char*   ach_tag     tag which value should be found
 * @param[in]       int     in_len_tag  length of ach_tag
 *
 * @return          string  str_value
 *
*/
string ds_cookie_manager::m_get_value( char* ach_xml, int in_len, int* ain_pos, char* ach_tag, int in_len_tag )
{
    // initialize some variables:
    int in_start_pos = *ain_pos;
    string str_end_tag = "</";
    str_end_tag.append( &ach_tag[1], in_len_tag - 1 );

    for ( ; *ain_pos < in_len; (*ain_pos)++ ) {
        switch ( ach_xml[*ain_pos] ) {
            case '<': {
                string str_test(&ach_xml[*ain_pos], str_end_tag.length() );
                if ( str_end_tag == str_test ) {
                    break;
                } else {
                    continue;
                }
            }
            default:
                continue;
        }
        break;
    }
    string strl_value( &ach_xml[in_start_pos], *ain_pos - in_start_pos );
    return strl_value;
} // end of ds_cookie_manager::m_get_value


/**
 *
 * function ds_cookie_manager::m_save_cookie
 *
 * @param[in]   ds_single_cookie   dc_cookie
 *
*/
bool ds_cookie_manager::m_save_cookie( ds_single_cookie* adc_cookie )
{
    // initialize some variables:
    bool    bo_ret        = false;  // return value for several functions
    int     in_mem_index  = -1;     // index, where Cookie is saved to in memory
    bool    bo_overwrite  = false;  // true = cookie exist already and will be overwritten
    bool    bo_actual     = false;  // true = cookies lifetime is ok

    ds_hstring ds_user;
    string  str_cookie    = adc_cookie->m_get_cookie();
    string  strl_name     = adc_cookie->m_get_name();
    string  str_host_in   = adc_cookie->m_get_host();
    time_t  t_expires     = adc_cookie->m_get_lifetime();
    bool    bo_secure     = adc_cookie->m_get_secure();
    char*   ach_host      = (char*)str_host_in.c_str();
    int     in_len_host   = (int)str_host_in.length();
    vector<int> vin_ck_indices;

#if 0
    // get username:
    ds_user = ads_session->dsc_auth.m_get_username();
#endif
    
    struct dsd_sdh_ident_set_1 ds_ident;
    memset( &ds_ident, 0, sizeof(dsd_sdh_ident_set_1) );
    adsc_wsp_helper->m_cb_get_ident( &ds_ident );

    ds_user.m_write( (char*)ds_ident.dsc_userid.ac_str, ds_ident.dsc_userid.imc_len_str  );

    // check if cookie already exists:
    vin_ck_indices = ds_cookie_tables.m_get_exact_entries( ds_user.m_get_ptr(), ds_user.m_get_len(), ach_host, in_len_host );
    in_mem_index   = m_is_name_in_indices( strl_name, vin_ck_indices, bo_secure );
    if ( in_mem_index > -1 ) {
        bo_overwrite = true;
    }

    // check lifetime:
    bo_actual = m_check_lifetime( t_expires );

    if ( bo_actual || bo_overwrite ) {
        // if bo_actual == false and bo_overwrite == true, an existing cookie will be "deleted"

        // save cookie:
        in_mem_index = ds_cookie_store.m_insert_entry( (char*)str_cookie.c_str(), (int)str_cookie.length(),
                                                       ach_host, in_len_host,
                                                       t_expires, bo_secure, in_mem_index );

        if ( in_mem_index < 0 ) {
            adsc_wsp_helper->m_cb_print_out( "HWSGE520E: ds_cookie_manager - error while storing cookie to memory" );
            return false;
        }
        
        // set managment:
        bo_ret = ds_cookie_tables.m_insert_entry( ds_user.m_get_ptr(), ds_user.m_get_len(),
                                                  ach_host, in_len_host,
                                                  bo_overwrite, in_mem_index );
        if ( !bo_ret ) {
            adsc_wsp_helper->m_cb_print_out( "HWSGE521E: ds_cookie_manager - error while storing cookie to tables" );
            return false;
        }
    }

    // print message:
    //adsc_wsp_helper->m_cb_printf_out( "HWSGI517I: ds_cookie_manager::m_save_cookie saved cookie: %s",  str_cookie.c_str() );
    return true;
} // end of ds_cookie_manager::m_save_cookie

/**
 * function ds_cookie_manager::m_get_host
 *
 * @param[in]   string str_url
 *
*/
void ds_cookie_manager::m_get_host( string str_url )
{
    str_host = "";
    if ( str_url.find("https://") != string::npos ) {
        ien_proto = ie_https;
    } else {
        ien_proto = ie_http;
    }

    size_t in_pos1 = 0;
    size_t in_pos2 = 0;
    in_pos1 = str_url.find("://");
    if ( in_pos1 != string::npos ) {
        str_host = str_url.substr(in_pos1 + 3, str_url.length());
        in_pos2 = str_host.find_last_of( "/" );
        if ( in_pos2 != string::npos ) {
            str_host = str_host.substr( 0, in_pos2 + 1 );
        }
    }
} // end of ds_cookie_manager::m_get_host


/**
 *
 * function ds_cookie_manager::m_is_name_in_indices
 *
 * @param[in]   string      strl_name        name of cookie
 * @param[in]   vector<int> vin_ck_indices
 * @param[in]   bool        bo_secure
 *
 * @return      int         pos of str_name in vin_ck_indices
 *                          -1 if not found
 *
*/
int ds_cookie_manager::m_is_name_in_indices( string strl_name, vector<int> vin_ck_indices, bool bo_secure )
{
    if ( vin_ck_indices.empty() ) {
        return -1;
    }

    for ( int in_1 = 0; in_1 < (int)vin_ck_indices.size(); in_1++ ) {
        if ( strl_name == ds_cookie_store.m_get_name( vin_ck_indices.at(in_1), bo_secure ) ) {
            return vin_ck_indices.at(in_1);
        }
    }
    
    return -1;
} // end of ds_cookie_manager::m_is_name_in_indices


/**
 *
 * function ds_cookie_manager::m_check_lifetime
 *
 * @param[in]   time_t      t_expires
 *
 * @return      bool
 *
*/
bool ds_cookie_manager::m_check_lifetime( time_t t_expires )
{
    if ( t_expires < 0 ) {
        // sign for delete at logout:
        return true;
    }

    time_t  t_now;
    time( &t_now );
    if ( t_expires - t_now > 0 ) {
        return true;
    } else {
        return false;
    }
} // end of ds_cookie_manager::m_check_lifetime


/**
 *
 * function ds_cookie_manager::m_sort_cookies
 *
 * @param[in]   vector<ds_single_cookie> v_cookies
 *
 * @return      vector<ds_single_cookie>
 *
*/
vector<ds_single_cookie> ds_cookie_manager::m_sort_cookies( vector<ds_single_cookie> v_input )
{
    // initialize some variables:
    vector<ds_single_cookie> v_output;
    vector< vector<ds_single_cookie> > v_sort;
    string strl_domain;
    int in_1;
    int in_2;

    for ( in_1 = 0; in_1 < (int)v_input.size(); in_1++ ) {
        strl_domain = v_input.at(in_1).m_get_domain();
        for ( in_2 = 0; in_2 < (int)v_sort.size(); in_2++ ) {
            if (    !v_sort.at(in_2).empty()
                 && v_sort.at(in_2).at(0).m_get_domain() == strl_domain ) 
            {
                break;
            }
        }
        if ( in_2 < (int)v_sort.size() ) {
            v_sort.at(in_2).push_back( v_input.at(in_1) );
        } else {
            vector<ds_single_cookie> v_temp;
            v_temp.push_back( v_input.at(in_1) );
            v_sort.push_back( v_temp );
        }
    }

    // build output:
    for ( in_1 = 0; in_1 < (int)v_sort.size(); in_1++ ) {
        for ( in_2 = 0; in_2 < (int)v_sort.at(in_1).size(); in_2++ ) {
            v_output.push_back( v_sort.at(in_1).at(in_2) );
        }
    }

    return v_output;
} // end of ds_cookie_manager::m_sort_cookies


/*+-------------------------------------------------------------------------+*/
/*| analysing functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_manager::m_create_trace
 *
*/
void ds_cookie_manager::m_create_trace()
{
    // intialize some variables:
    FILE*  file;
    string str_data = "";

    // print hash table:
    str_data = ds_cookie_tables.m_cb_get_hash_overview();
    file = fopen( CK_HASH_TABLE_FILE, "w" );
    fprintf( file, "%s", (char*)str_data.c_str() );
    fclose(file);

    // print mgmt table:
    str_data = ds_cookie_tables.m_cb_get_mgmt_overview();
    file = fopen( CK_MGMT_TABLE_FILE, "w" );
    fprintf( file, "%s", (char*)str_data.c_str() );
    fclose(file);

    // print memory table:
    str_data = ds_cookie_store.m_get_overview();
    file = fopen( CK_MEM_TABLE_FILE, "w" );
    fprintf( file, "%s", (char*)str_data.c_str() );
    fclose(file);

} // end of ds_cookie_manager::m_create_trace()
