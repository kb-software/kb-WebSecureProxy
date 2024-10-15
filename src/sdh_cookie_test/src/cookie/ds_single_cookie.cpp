/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include "ds_single_cookie.h"


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/


ds_single_cookie::ds_single_cookie( ds_wsp_helper* adsl_wsp_helper )
{
    adsc_wsp_helper = adsl_wsp_helper;
}
/**
 *
 * function s_single_cookie::m_setup
 *
 * @param[in]   string str_host
 *
*/
void ds_single_cookie::m_setup( string str_host )
{
    in_state = 0;

    memset( &rch_name[0],    0, CK_MAX_SIZE );
    memset( &rch_value[0],   0, CK_VALUE_SIZE );
    memset( &rch_domain[0],  0, CK_MAX_SIZE );
    memset( &rch_path[0],    0, CK_MAX_SIZE );
    memset( &rch_comment[0], 0, CK_MAX_SIZE );

    t_expires           = -1;
    bo_secure           = false;
    bo_delete_at_logout = true;
    in_version          = 0;

    string str_domain = "";
    string str_path   = "";
    size_t in_pos = str_host.find("/");
    if ( in_pos != string::npos ) {
        str_domain = str_host.substr(0, in_pos);
        str_path   = str_host.substr(in_pos, str_host.length());
    } else {
        str_domain = str_host;
        str_path = "/";
    }
    m_set_domain( (char*)str_domain.c_str(), (int)str_domain.length() );
    m_set_path  ( (char*)str_path.c_str(),   (int)str_path.length() );

    
    m_set_cookie_words();
} // end of s_single_cookie::m_setup


/**
 *
 * function ds_single_cookie::m_parse_cookie
 *
 * parse the incomming cookie string
 * 
 * @param[in]   char*       ach_cookie          pointer to cookie string
 * @param[in]   int         in_len_cookie       length of cookie string
 *
*/
void ds_single_cookie::m_parse_cookie( char* ach_cookie, int in_len_cookie )
{
    // initialize some variables:
    int         in_position  = 0;       // reading position
    char*       ach_word     = NULL;    // pointer to actual word
    int         in_len_word  = 0;       // length of ach_word
    char*       ach_value    = NULL;    // pointer to actual value
    int         in_len_value = 0;       // length of ach_value
    int         in_word_key  = -1;      // key for found word

    while ( in_position < in_len_cookie ) {
        m_get_next_word( ach_cookie, in_len_cookie, &in_position, &ach_word, &in_len_word );
        in_word_key = m_is_word_in_list( ach_word, in_len_word );
        if ( in_word_key == -2 ) {
            // word is empty
            continue;
        } else if ( in_word_key != CK_SECURE ) {
            // the secure flag does not contain a value
            // read value for all others
            m_get_value( ach_cookie, in_len_cookie, &in_position, &ach_value, &in_len_value );
        }

        // save values:
        switch ( in_word_key ) {
            case CK_COMMENT:
                m_set_comment( ach_value, in_len_value );
                break;
            case CK_DOMAIN:
                m_set_domain( ach_value, in_len_value );
                break;
            case CK_EXPIRES:
                m_set_expires( ach_value, in_len_value );
                break;
            case CK_MAX_AGE:
                m_set_max_age( ach_value, in_len_value );
                break;
            case CK_PATH:
                if ( ach_value[in_len_value - 1] != '/' ) {
                    string str_value( ach_value, in_len_value );
                    str_value += "/";
                    m_set_path( (char*)str_value.c_str(), in_len_value + 1 );
                } else {
                    m_set_path( ach_value, in_len_value );
                }
                break;
            case CK_SECURE:
                m_set_secure();
                break;
            case CK_VERSION:
                m_set_version( ach_value, in_len_value );
                break;
            default:
                if ( m_set_name( ach_word, in_len_word ) ) {
                    m_set_value( ach_value, in_len_value );
                }
                break;
        }
    } // end of while(in_position<in_len_cookie)
} // end of ds_single_cookie::m_parse_cookie


/**
 *
 * function ds_single_cookie::m_parse_xml
 *
 * parse the incomming xml cookie string
 * 
 * @param[in]   char*       ach_xml     pointer to cookie xml string
 * @param[in]   int         in_len      length of cookie xml string
 *
*/
void ds_single_cookie::m_parse_xml( char* ach_xml, int in_len )
{
    if ( ach_xml == NULL || in_len < 1 ) {
        return;
    }
    m_set_cookie_xmls();
    
    // initialize some variables:
    int   in_position   = 0;
    int   in_key        = 0;
    char* ach_tag       = NULL;
    int   in_len_tag    = 0;
    string str_value    = "";

    while ( in_position < in_len ) {
        m_get_tag( ach_xml, in_len, &in_position, &ach_tag, &in_len_tag );
        str_value = m_get_value( ach_xml, in_len, &in_position, ach_tag, in_len_tag );
        in_key = m_is_tag_in_list( ach_tag, in_len_tag );
        switch ( in_key ) {
            case ds_single_cookie::XML_NAME:
                m_set_name( (char*)str_value.c_str(), (int)str_value.length() );
                break;
            case ds_single_cookie::XML_VALUE:
                m_set_value( (char*)str_value.c_str(), (int)str_value.length() );
                break;
            case ds_single_cookie::XML_EXPIRES:
                t_expires = (time_t)(atoi( (char*)str_value.c_str() ));
                bo_delete_at_logout = false;
                break;
            case ds_single_cookie::XML_SECURE:
                if ( str_value == "YES" ) {
                    m_set_secure();
                }
                break;
            case ds_single_cookie::XML_HOST: {
                size_t in_pos = str_value.find( "/" );
                if ( in_pos != string::npos ) {
                    string str_domain = str_value.substr(0, in_pos);
                    string str_path   = str_value.substr(in_pos, str_value.length());
                    m_set_path( (char*)str_path.c_str(), (int)str_path.length() );
                    m_set_domain( (char*)str_domain.c_str(), (int)str_domain.length() );
                }
                break; }
            default:
                // unkonwn tag -> get next
                break;
        }
        in_position += in_len_tag + 1;
    }

} // end of ds_single_cookie::m_parse_xml


/**
 *
 * function ds_single_cookie::m_get_tag
 *
 * @param[in]       char*   ach_xml
 * @param[in]       int     in_len
 * @param[in/out]   int*    ain_pos
 * @param[out]      char**  aach_tag
 * @param[out]      int*    ain_len_tag
 *
*/
void ds_single_cookie::m_get_tag( char* ach_xml, int in_len, int* ain_pos, char** aach_tag, int* ain_len_tag )
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
} // end of ds_single_cookie::m_get_tag


/**
 *
 * function ds_single_cookie::m_is_tag_in_list
 *
 * @param[in]       char*   ach_tag
 * @param[in]       int     in_len_tag
 *
*/
int ds_single_cookie::m_is_tag_in_list( char* ach_tag, int in_len_tag )
{
    // initialize some variables:
    int    in_return = -1;
    string str_tag( ach_tag, in_len_tag); 

    for ( int in_1 = 0; in_1 < NUM_COOKIE_XMLS; in_1++ ) {
        if ( str_tag == cookie_xmls[in_1] ) {
            in_return = in_1;
        }
    }
    return in_return;
} // end of ds_single_cookie::m_is_tag_in_list


/**
 *
 * function ds_single_cookie::m_get_value
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
string ds_single_cookie::m_get_value( char* ach_xml, int in_len, int* ain_pos, char* ach_tag, int in_len_tag )
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
    string str_value( &ach_xml[in_start_pos], *ain_pos - in_start_pos );
    return str_value;
} // end of ds_single_cookie::m_get_value


/**
 *
 * function ds_single_cookie::m_set_name
 *
 * @param[in]   char* ach_name
 * @param[in]   int   in_len_name
 *
*/
bool ds_single_cookie::m_set_name( char* ach_name, int in_len_name )
{
    bool bo_return = false;
    if ( in_len_name < CK_MAX_SIZE && (in_state & CK_ST_NAME) != CK_ST_NAME ) {
        in_state |= CK_ST_NAME;
        memcpy( &rch_name[0], ach_name, in_len_name );
        rch_name[in_len_name] = '\0';
        bo_return = true;
    }
    return bo_return;
} // end of ds_single_cookie::m_set_name


/**
 *
 * function ds_single_cookie::m_set_value
 *
 * @param[in]   char* ach_value
 * @param[in]   int   in_len_value
 *
*/
bool ds_single_cookie::m_set_value( char* ach_value, int in_len_value )
{
    bool bo_return = false;
    if ( in_len_value < CK_VALUE_SIZE ) {
        memset( &rch_value[0],   0, CK_VALUE_SIZE );
        in_state |= CK_ST_VALUE;
        memcpy( &rch_value[0], ach_value, in_len_value );
        rch_value[in_len_value] = '\0';
        bo_return = true;
    }
    return bo_return;
} // end of ds_single_cookie::m_set_value


/**
 *
 * function ds_single_cookie::m_set_domain
 *
 * @param[in]   char* ach_domain
 * @param[in]   int   in_len_domain
 *
*/
bool ds_single_cookie::m_set_domain( char* ach_domain, int in_len_domain )
{
    bool bo_return = false;
    in_len_domain = m_remove_std_port( ach_domain, in_len_domain );
    if ( in_len_domain < CK_MAX_SIZE ) {
        memset( &rch_domain[0],  0, CK_MAX_SIZE );
        // convert domain to lower case:
        for ( int in_count = 0; in_count < in_len_domain; in_count++ ) {
            rch_domain[in_count] = (char)tolower(ach_domain[in_count]);
        }
        rch_domain[in_len_domain] = '\0';
        bo_return = true;
    }
    return bo_return;
} // end of ds_single_cookie::m_set_domain


/**
 *
 * function ds_single_cookie::m_remove_std_port
 *
 * @param[in]   char* ach_domain
 * @param[in]   int   in_len_domain
 *
 * @return      int                 new length
 *
*/
int ds_single_cookie::m_remove_std_port( char* ach_domain, int in_len_domain )
{
    // initialize some variables:
    int in_return   = in_len_domain;
    int in_position =  0;
    int in_port     =  0;

    for ( ; in_position < in_len_domain; in_position++ ) {
        if ( ach_domain[in_position] == ':' ) {
            in_port = atoi(ach_domain + in_position + 1);
            if ( in_port == 80 ) {
                in_return = in_position;
                for ( ; in_position < in_len_domain; in_position++ ) {
                    ach_domain[in_position] = 0;
                }
            }
            break;
        }
    }
    return in_return;
} // end of ds_single_cookie::m_remove_std_port

/**
 *
 * function ds_single_cookie::m_set_path
 *
 * @param[in]   char* ach_path
 * @param[in]   int   in_len_path
 *
*/
bool ds_single_cookie::m_set_path( char* ach_path, int in_len_path )
{
    bool bo_return = false;
    if ( in_len_path < CK_MAX_SIZE ) {
        // convert domain to lower case:
        for ( int in_count = 0; in_count < in_len_path; in_count++ ) {
            rch_path[in_count] = (char)tolower(ach_path[in_count]);
        }
        rch_path[in_len_path] = '\0';
        bo_return = true;
    }
    return bo_return;
} // end of ds_single_cookie::m_set_path


/**
 *
 * function ds_single_cookie::m_set_comment
 *
 * @param[in]   char* ach_comment
 * @param[in]   int   in_len_comment
 *
*/
bool ds_single_cookie::m_set_comment( char* ach_comment, int in_len_comment )
{
    bool bo_return = false;
    if ( in_len_comment < CK_MAX_SIZE ) {
        memcpy( &rch_comment[0], ach_comment, in_len_comment );
        rch_comment[in_len_comment] = '\0';
        bo_return = true;
    }
    return bo_return;
} // end of ds_single_cookie::m_set_comment


/**
 *
 * function ds_single_cookie::m_set_expires
 *
 * @param[in]   char* ach_expires
 * @param[in]   int   in_len_expires
 *
*/
bool ds_single_cookie::m_set_expires( char* ach_expires, int in_len_expires )
{   
    if ( ach_expires == NULL || in_len_expires < 1 ) {
        return false;
    }
    if ( ach_expires[0] == '"' || ach_expires[0] == '\'' ) {
        ach_expires++;
    }

    struct dsd_hl_aux_epoch_1 dsd_epoch;
    dsd_epoch.ac_epoch_str  = (void*)ach_expires;
    dsd_epoch.inc_len_epoch = in_len_expires;
    dsd_epoch.iec_chs_epoch = ied_chs_utf_8;

    bool bo_ret = m_epoch_from_string( &dsd_epoch );
    if ( bo_ret || dsd_epoch.imc_epoch_val == -1 ) {
        t_expires = dsd_epoch.imc_epoch_val;
        bo_delete_at_logout = false;
        return true;
    } else {
        adsc_wsp_helper->m_cb_printf_out( "HWSGW522W: ds_single_cookie - error while parsing time: %.*s", in_len_expires, ach_expires );
        return false;
    }
} // end of ds_single_cookie::m_set_expires


/**
 *
 * function ds_single_cookie::m_set_max_age
 *
 * @param[in]   char* ach_max_age
 * @param[in]   int   in_len_max_age
 *
*/
bool ds_single_cookie::m_set_max_age( char* ach_max_age, int in_len_max_age )
{
    if ( ach_max_age == NULL || in_len_max_age < 1 ) {
        return false;
    }

    time_t t_now;
    time( &t_now );
    int in_max_age = -1;

    if ( ach_max_age[0] == '"' || ach_max_age[0] == '\'' ) {
        ach_max_age++;
    }
    
    if ( in_len_max_age > 0 ) {
        in_max_age = atoi( ach_max_age );
    }
    if ( in_max_age >= 0 ) {
        t_expires = t_now + in_max_age;
        bo_delete_at_logout = false;
    }
    return true;
} // end of ds_single_cookie::m_set_max_age


/**
 *
 * function ds_single_cookie::m_set_version
 *
 * @param[in]   char* ach_version
 * @param[in]   int   in_len_version
 *
*/
bool ds_single_cookie::m_set_version( char* ach_version, int in_len_version )
{
    if ( in_len_version > 0 ) {
        int in_v = atoi(ach_version);
        if ( in_v >= 0 ) {
            in_version = in_v;
        }
    }
    return true;
} // end of ds_single_cookie::m_set_version


/**
 *
 * function ds_single_cookie::m_set_secure
 *
*/
bool ds_single_cookie::m_set_secure()
{
    bo_secure = true;
    return true;
} // end of ds_single_cookie::m_set_secure


/**
 *
 * function ds_single_cookie::m_get_cookie
 *
 * @return      string
 *
*/
string ds_single_cookie::m_get_cookie( )
{
    string str_cookie = "";
    str_cookie.append( &rch_name[0], strlen(rch_name) );
    str_cookie.append( "=" );
    str_cookie.append( &rch_value[0], strlen(rch_value) );

    return str_cookie;
} // end of ds_single_cookie::m_get_cookie


/**
 *
 * function ds_single_cookie::m_get_name
 *
 * @return      string
 *
*/
string ds_single_cookie::m_get_name()
{
    string str_name = "";
    str_name.append( &rch_name[0], strlen(rch_name) );
    return str_name;
} // end of ds_single_cookie::m_get_name


/**
 *
 * function ds_single_cookie::m_get_value
 *
 * @return      string
 *
*/
string ds_single_cookie::m_get_value()
{
    string str_value = "";
    str_value.append( &rch_value[0], strlen(rch_value) );
    return str_value;
} // end of ds_single_cookie::m_get_value


/**
 *
 * function ds_single_cookie::m_get_host
 *
 * @return string
*/
string ds_single_cookie::m_get_host( )
{
    string str_return;
    str_return.append( &rch_domain[0], strlen(rch_domain) );
    str_return.append( &rch_path[0],   strlen(rch_path) );

    return str_return;
} // end of ds_single_cookie::m_get_host


/**
 *
 * function ds_single_cookie::m_get_domain
 *
 * @return string
*/
string ds_single_cookie::m_get_domain( )
{
    string str_return;
    str_return.append( &rch_domain[0], strlen(rch_domain) );
    return str_return;
} // end of ds_single_cookie::m_get_domain


/**
 *
 * function ds_single_cookie::m_get_path
 *
 * @return string
*/
string ds_single_cookie::m_get_path( )
{
    string str_return;
    str_return.append( &rch_path[0], strlen(rch_path) );
    return str_return;
} // end of ds_single_cookie::m_get_path


/**
 *
 * function ds_single_cookie::m_get_lifetime
 *
 * @return      time_t  -1 if delete with logout
 *
*/
time_t ds_single_cookie::m_get_lifetime()
{
    if ( bo_delete_at_logout || t_expires < 0 ) {
        return -1;
    } else {
        return t_expires;
    }
} // end of ds_single_cookie::m_get_lifetime


/**
 *
 * function ds_single_cookie::m_get_secure
 *
 * @return     bool
 *
*/
bool ds_single_cookie::m_get_secure() 
{
    return bo_secure;
} // end of ds_single_cookie::m_get_secure


/**
 *
 * function ds_single_cookie::m_is_word_in_list
 * 
 * @param[in]   char*   ach_word      pointer to word string
 * @param[in]   int     in_len_word   length of word string
 *
 * @return      int     wordkey,
 *                      -1 if not in list
 *                      -2 if string is empty
 *
*/
int ds_single_cookie::m_is_word_in_list( char* ach_word, int in_len_word )
{
    if ( in_len_word < 1 || ach_word == NULL ) {
        return -2;
    }

    // initialize some variables:
    int    in_return = -1;
    string str_word( ach_word, in_len_word );
    string str_lower = "";
    // convert str_attribute to lower case:
    for ( int in_count = 0; in_count < in_len_word; in_count++ ) {
        str_lower += (char)tolower(str_word[in_count]);
    }

    for ( int in_1 = 0; in_1 < NUM_COOKIE_WORDS; in_1++ ) {
        if ( str_lower == cookie_words[in_1] ) {
            in_return = in_1;
            break;
        }
    }

    return in_return;
} // end of ds_single_cookie::m_is_word_in_list


/**
 *
 * function ds_single_cookie::m_get_next_word
 * 
 * @param[in]       char*   ach_cookie      pointer to cookie string
 * @param[in]       int     in_len_cookie   length of cookie string
 * @param[in/out]   int*    ain_position    actual reading position in cookie
 * @param[out]      char**  aach_word       pointer to found word
 * @param[out]      int*    ain_len_word    length of found word
 *
*/
void ds_single_cookie::m_get_next_word( char* ach_cookie, int in_len_cookie, 
                                         int* ain_position,
                                         char** aach_word, int* ain_len_word )
{
    m_pass_signs( ach_cookie, in_len_cookie, ain_position, "= ;,\f\n\t\v" );
    
    // initialize some variables:
    int in_start_pos = *ain_position;
    *aach_word       = NULL;
    *ain_len_word    = 0;

    // get word:
    for ( ; *ain_position < in_len_cookie; (*ain_position)++ ) {
        switch ( ach_cookie[*ain_position] ) {
            case '\f':
            case '\n':
            case '\r':
            case '\t':
            case '\v':
            case ' ':
            case '=':
            case ';':
                break;
            default:
                continue;
        }
        break;
    }
    *aach_word    = &ach_cookie[in_start_pos];
    *ain_len_word = *ain_position - in_start_pos;
} // end of ds_single_cookie::m_get_next_word


/**
 *
 * function ds_single_cookie::m_get_value
 * 
 * @param[in]       char*   ach_cookie      pointer to cookie string
 * @param[in]       int     in_len_cookie   length of cookie string
 * @param[in/out]   int*    ain_position    actual reading position in cookie
 * @param[out]      char**  aach_value      pointer to found value
 * @param[out]      int*    ain_len_value   length of found value
 *
*/
void ds_single_cookie::m_get_value( char* ach_cookie, int in_len_cookie, 
                                     int* ain_position,
                                     char** aach_value, int* ain_len_value )
{
    m_pass_signs( ach_cookie, in_len_cookie, ain_position, "= ,\f\n\t\v" );

    // initialize some variables:
    int in_start_pos = *ain_position;
    *aach_value      = NULL;
    *ain_len_value   = 0;

    for ( ; *ain_position < in_len_cookie; (*ain_position)++ ) {
        switch ( ach_cookie[*ain_position] ) {
            case '\f':
            case '\n':
            case '\r':
            case '\t':
            case '\v':
            case ';':
                break;
            case '"':
            case '\'':
                if ( *ain_position == in_start_pos ) {
                    m_get_quote_end( ach_cookie, in_len_cookie, ain_position );
                } else {
                    continue;
                }
            default:
                continue;
        }
        break;
    }

    *aach_value    = &ach_cookie[in_start_pos];
    *ain_len_value = *ain_position - in_start_pos;
} // end of ds_single_cookie::m_get_value


/**
 *
 * function ds_single_cookie::m_pass_signs
 *
 * @param[in]       char*           ach_data
 * @param[in]       int             in_len_data
 * @param[in/out]   int*            ain_position
 * @param[in]       const char[]    chr_sign_list
 *
*/
void ds_single_cookie::m_pass_signs( char* ach_data, int in_len_data,
                                      int* ain_position, const char chr_sign_list[] )
{
    // initialize some variables:
    int  in_len_signs  = (int)strlen( chr_sign_list );
    int  in_sign       = 0;
    bool bo_sign_found = false;

    if ( in_len_signs < 1 ) {
        return;
    }

    for ( ; *ain_position < in_len_data; (*ain_position)++ ) {
        bo_sign_found = false;
        for ( in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
            if ( ach_data[*ain_position] == chr_sign_list[in_sign] ) {
                bo_sign_found = true;
                break;
            }
        }
        if ( !bo_sign_found ) {
            // no sign of list found, exit
            break;
        }
    }
    return;
} // end of ds_single_cookie::m_pass_signs


/**
 *
 * function ds_single_cookie:m_get_quote_end
 *
 * @param[in]       char*           ach_cookie
 * @param[in]       int             in_len_cookie
 * @param[in/out]   int*            ain_position
 *
*/
void ds_single_cookie::m_get_quote_end( char* ach_cookie, int in_len_cookie, int* ain_position )
{
    const char ch_quote = ach_cookie[*ain_position];
    (*ain_position)++;

    for ( ; *ain_position < in_len_cookie; (*ain_position)++ ) {
        switch ( ach_cookie[*ain_position] ) {
            case '\\':
                (*ain_position)++;
                continue;
            default:
                if ( ach_cookie[*ain_position] == ch_quote ) {
                    break;
                } else {
                    continue;
                }
        }
        break; // break for loop
    }
    return;
} // end of ds_single_cookie::m_get_quote_end
