/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_cookie_manager                                                     |*/
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

#ifndef DS_COOKIE_MANAGER_H
#define DS_COOKIE_MANAGER_H

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

//#define EXPORT_COOKIES_TO_FILE      // export cookies to file (just for the time being )
                                    // later export should write data to ldap
#ifdef EXPORT_COOKIES_TO_FILE
    #define CK_FILE_TYPE        ".xml"
    #define CK_FILE_DIR         "cookie"
#endif //EXPORT_COOKIES_TO_FILE

#define CK_HASH_TABLE_FILE  "ck_hash_table.txt"
#define CK_MGMT_TABLE_FILE  "ck_mgmt_table.txt"
#define CK_MEM_TABLE_FILE   "ck_memory_table.txt"
#define CK_COOKIE_IN_FILE   "ck_cookie_input.txt"
#define CK_SCRIPT_PREFACE   "HOB_set"
#define CK_SCRIPT_SEMICOLON "HOBscol"
#define CK_DELETE_TIME      "Thu, 01 Jan 1970 01:00:00 UTC"


/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <time.h>
#include <string>
#include <stdio.h>
using namespace std;

#ifdef EXPORT_COOKIES_TO_FILE
    // for directory handling:
    #ifdef HL_UNIX
        #include <sys/types.h>
        #include <sys/stat.h>
    #else // Windows
        #include <direct.h>
    #endif // HL_UNIX
#endif // EXPORT_COOKIES_TO_FILE

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_single_cookie.h"
#include "ds_cookie_memory.h"
#include "ds_cookie_table.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;

class ds_cookie_manager
{
public:
    // constructor:
    ds_cookie_manager(void);

    // setup function:
    bool   m_setup( ds_wsp_helper* adsl_wsp_helper );

    // functions:
    bool           m_set_cookie           ( string str_host_in, char* ach_cookie, int in_len_cookie );
    string         m_get_cookie           ( string str_host_in = "" );
    
    void   m_trim_cokies   ();
    bool   m_export_cookies();

    // callback functions:
    bool   m_cb_delete_cookie( int in_points_to, bool bo_ignore_dependencies = false );

private:
    // variables:
    ds_cookie_memory    ds_cookie_store;
    ds_cookie_table     ds_cookie_tables;
    ds_wsp_helper*      adsc_wsp_helper;

    vector<string> vstr_delete_cookies;

    string str_host;
    enum ien_protocol {
        ie_http,
        ie_https
    } ien_proto;
    

    // functions:
    void m_get_single_cookie( char* ach_cookie, int in_len_cookie, int in_pos, int* ain_single_len );
    void m_get_single_xml_cookie( char* ach_data, int in_len_data, int* ain_pos, int* ain_single_len );
    bool m_save_cookie( ds_single_cookie* adc_cookie );
    void m_get_host( string str_url );
    int  m_is_name_in_indices( string strl_name, vector<int> vin_ck_indices, bool bo_secure );
    bool m_check_lifetime( time_t t_expires );
#ifdef EXPORT_COOKIES_TO_FILE
    bool m_create_dir( string str_dir );
#endif // EXPORT_COOKIES_TO_FILE
    bool m_import_xml( char* ach_data, int in_len );
    void m_get_tag( char* ach_xml, int in_len, int* ain_pos, char** aach_tag, int* ain_len_tag );
    string m_get_value( char* ach_xml, int in_len, int* ain_pos, char* ach_tag, int in_len_tag );
    string m_get_single_script_cookie( char* ach_cookie, int in_len_cookie, int* ain_pos, string& str_prefix );

    vector<ds_single_cookie> m_sort_cookies( vector<ds_single_cookie> v_input );

    // analysing functions:
    void m_create_trace();
};
#endif //DS_COOKIE_MANAGER_H
