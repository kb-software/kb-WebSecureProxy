/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include "ds_cookie.h"
#include <hob-xslunic1.h>

/*+---------------------------------------------------------------------+*/
/*| helper variables:                                                   |*/
/*+---------------------------------------------------------------------+*/
static const char* achr_cookie_words[] = {
    "Version",
    "Expires",
    "Max-age",
    "Domain",
    "Path",
    "Port",
    "Comment",
    "CommentURL",
    "Secure",
    "Discard",
    "HttpOnly",
    NULL
};

enum ied_cookie_words {
    ied_ck_empty     = -2,
    ied_ck_unknown   = -1,
    ied_ck_version   =  0,
    ied_ck_expires,
    ied_ck_maxage,
    ied_ck_domain,
    ied_ck_path,
    ied_ck_port,
    ied_ck_comment,
    ied_ck_commenturl,
    ied_ck_secure,
    ied_ck_discard,
    ied_ck_httponly
};

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_cookie::ds_cookie()
{
    adsc_wsp_helper = NULL;
} // end of ds_cookie::ds_cookie


ds_cookie::ds_cookie( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;

    //----------------------------------------
    // setup strings:
    //----------------------------------------
    dsc_cookie.m_setup    ( adsc_wsp_helper );
    dsc_domain.m_setup    ( adsc_wsp_helper );
    dsc_path.m_setup      ( adsc_wsp_helper );
    dsc_comment.m_setup   ( adsc_wsp_helper );
    dsc_commenturl.m_setup( adsc_wsp_helper );
    dsc_req_domain.m_setup( adsc_wsp_helper );
    dsc_req_path.m_setup  ( adsc_wsp_helper );

    //----------------------------------------
    // set default values:
    //----------------------------------------
    inc_version   = 1;
    ilc_expires   = 0;
    uisc_port     = 0;
    boc_secure    = false;
    boc_http_only = false;
    boc_discard   = true;
} // end of ds_cookie::ds_cookie


ds_cookie::ds_cookie( const ds_cookie& ds_copy )
{
    adsc_wsp_helper = ds_copy.adsc_wsp_helper;
    dsc_cookie      = ds_copy.dsc_cookie;
    inc_version     = ds_copy.inc_version;
    ilc_expires     = ds_copy.ilc_expires;
    dsc_domain      = ds_copy.dsc_domain;
    dsc_path        = ds_copy.dsc_path;
    uisc_port       = ds_copy.uisc_port;
    dsc_comment     = ds_copy.dsc_comment;
    dsc_commenturl  = ds_copy.dsc_commenturl;
    boc_secure      = ds_copy.boc_secure;
    boc_http_only   = ds_copy.boc_http_only;
    boc_discard     = ds_copy.boc_discard;
    dsc_req_domain  = ds_copy.dsc_req_domain;
    dsc_req_path    = ds_copy.dsc_req_path;
} // end of ds_cookie::ds_cookie


void ds_cookie::m_init( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;

    dsc_cookie.m_init( adsc_wsp_helper );
    dsc_domain.m_init( adsc_wsp_helper );
    dsc_path.m_init( adsc_wsp_helper );
    dsc_comment.m_init( adsc_wsp_helper );
    dsc_commenturl.m_init( adsc_wsp_helper );
    dsc_req_domain.m_init( adsc_wsp_helper );
    dsc_req_path.m_init( adsc_wsp_helper );
} // end of ds_cookie::m_init

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_cookie::m_set_req_host
 * save requested url (i.e. "http://www.hob.de/path" )
 * used to check with incomming in cookie or set default values
 *
 * @param[in]   const char* ach_domain          pointer to requested domain
 * @param[in]   int         in_len_domain       length of requested domain
 * @param[in]   const char* ach_path            pointer to requested path
 * @param[in]   int         in_len_path         length of requested path
*/
void ds_cookie::m_set_req_host( const char* ach_domain, int in_len_domain,
                                const char* ach_path,   int in_len_path   )
{
    // initialize some variables:
    int in_pos;

    // save requested domain and path
    dsc_req_domain.m_write( ach_domain, in_len_domain, false );
    dsc_req_path.m_write  ( ach_path,   in_len_path,   false );

    // remove ports in domain:
    in_pos = dsc_req_domain.m_search( ":" );
    if ( in_pos > 0 ) {
        dsc_req_domain = dsc_req_domain.m_substr( 0, in_pos );
    }

    // remove file from path:
    in_pos = dsc_req_path.m_search_last( "/" );
    if ( in_pos > 0 && in_pos < dsc_req_path.m_get_len() ) {
        dsc_req_path = dsc_req_path.m_substr( 0, in_pos + 1 );
    }
} // end of ds_cookie::m_set_req_host


/**
 *
 * function ds_cookie::m_parse_cookie
 * parse the incomming cookie string
 * 
 * @param[in]   const char* ach_cookie          pointer to cookie string
 * @param[in]   int         in_len_cookie       length of cookie string
 * @return      bool                            true = success
*/
bool ds_cookie::m_parse_cookie( const char* ach_cookie, int in_len_cookie )
{
    // initialize some variables:
    bool             bo_ret;                    // return value
    int              in_position  = 0;          // reading position
    char*            ach_word;                  // pointer to actual word
    int              in_len_word;               // length of ach_word
    char*            ach_value    = NULL;       // pointer to actual value
    int              in_len_value = 0;          // length of ach_value
    ied_cookie_words ien_word;                  // key for found word

    while ( in_position < in_len_cookie ) {
        m_get_next_word( ach_cookie, in_len_cookie, &in_position, &ach_word, &in_len_word );
        ien_word = (ied_cookie_words)m_is_word_in_list( ach_word, in_len_word );
        if ( ien_word == ied_ck_empty ) {
            // word is empty
            continue;
        } else if (    ien_word != ied_ck_secure
                    && ien_word != ied_ck_discard
                    && ien_word != ied_ck_httponly ) {
            // this flags does not contain a value
            // read value for all others
            m_get_value( ach_cookie, in_len_cookie, &in_position, &ach_value, &in_len_value );
        }

        //----------------------------------------------
        // save values:
        //----------------------------------------------
        switch ( ien_word ) {
            case ied_ck_version: {
                ds_hstring ds_temp( adsc_wsp_helper, ach_value, in_len_value );
                ds_temp.m_to_int( &inc_version );
                break; }

            case ied_ck_expires:
                m_set_expires( ach_value, in_len_value );
                break;

            case ied_ck_maxage:
                m_set_max_age( ach_value, in_len_value );
                break;

            case ied_ck_domain:
                dsc_domain.m_write( ach_value, in_len_value, false );
                break;

            case ied_ck_path:
                dsc_path.m_write( ach_value, in_len_value, false );
                break;

            case ied_ck_port:
                break;

            case ied_ck_comment:
                dsc_comment.m_write( ach_value, in_len_value, false );
                break;

            case ied_ck_commenturl:
                dsc_commenturl.m_write( ach_value, in_len_value, false );
                break;

            case ied_ck_secure:
                boc_secure = true;
                break;

            case ied_ck_discard:
                boc_discard = true;
                break;

            case ied_ck_httponly:
                boc_http_only = true;
                break;

            default:
                dsc_cookie.m_write( ach_word, in_len_word, false );
                dsc_cookie.m_write( "=" );
                dsc_cookie.m_write( ach_value, in_len_value );
                break;
        } // end of switch
    } // end of while(in_position<in_len_cookie)

    //--------------------------------------------------
    // name and value are required to be a valid cookie:
    //--------------------------------------------------
    if ( dsc_cookie.m_get_len() < 1 ) {
        return false;
    }

    //--------------------------------------------------
    // check if domain is valid:
    //--------------------------------------------------
    if ( dsc_domain.m_get_len() > 0 ) {
        //----------------------------------------------
        // domain must be a subdomain of requested one:
        //----------------------------------------------
        bo_ret = dsc_req_domain.m_end_with( dsc_domain.m_get_ptr(),
                                            dsc_domain.m_get_len(),
                                            true );
        if ( bo_ret == false ) {
            return false;
        }

        //----------------------------------------------
        // domain must contain a "." (not last sign)
        //----------------------------------------------
        in_position = dsc_domain.m_search( "." );
        if (    in_position < 0
             || in_position == dsc_domain.m_get_len() ) {
            return false;
        }
    } else {
        //----------------------------------------------
        // set to default if not set:
        //----------------------------------------------
        dsc_domain = dsc_req_domain;
    }

    //--------------------------------------------------
    // check if path is valid:
    //--------------------------------------------------
    if ( dsc_path.m_get_len() > 0 ) {
        //----------------------------------------------
        // path must be u subpath of requested one:
        //----------------------------------------------
        in_position = dsc_req_path.m_search( dsc_path.m_get_ptr(),
                                             dsc_path.m_get_len(),
                                             true );
        if ( in_position != 0 ) {
            return false;
        }
    } else {
        //----------------------------------------------
        // set to default if not set:
        //----------------------------------------------
        dsc_path = dsc_req_path;
    }
    return true;
} // end of ds_cookie::m_parse_cookie


/**
 * function ds_cookie::m_reset
*/
void ds_cookie::m_reset()
{
    //----------------------------------------
    // reset strings:
    //----------------------------------------
    dsc_cookie.m_reset    ();
    dsc_domain.m_reset    ();
    dsc_path.m_reset      ();
    dsc_comment.m_reset   ();
    dsc_commenturl.m_reset();

    //----------------------------------------
    // set default values:
    //----------------------------------------
    inc_version   = 1;
    ilc_expires   = 0;
    uisc_port     = 0;
    boc_secure    = false;
    boc_http_only = false;
    boc_discard   = true;
} // end of ds_cookie::m_reset


/**
 * function ds_cookie::m_check_lifetime
 * check if saved lifetime is still valid
 *
 * @return      bool                true = still valid
*/
bool ds_cookie::m_check_lifetime()
{
    // initialize some variables:
    time_t il_now;

    if ( boc_discard == true ) {
        return true;
    }

    il_now = adsc_wsp_helper->m_cb_get_time();
    if ( ilc_expires < il_now ) {
        return true;
    }
    return false;
} // end of ds_cookie::m_check_lifetime


/**
 * function ds_cookie::m_name_equals
 * check if name of given cookie equals our name
 *
 * @param[in]   ds_cookie* ads_compare
 * @return      bool                        true = equals
*/
bool ds_cookie::m_name_equals( ds_cookie* ads_compare )
{
    // initialize some variables:
    int   in_pos;
    char* ach_cookie;

    // get cookie:
    ach_cookie = ads_compare->m_get_cookie();
    if (    ach_cookie    == NULL
         || ach_cookie[0] == 0    ) {
        return false;
    }
    
    // search first "=":
    in_pos = dsc_cookie.m_search( "=" );
    if (    in_pos < 1
         || in_pos > (int)strlen(ach_cookie) - 1 ) {
        return false;
    }

    return ( dsc_cookie.m_search( ach_cookie, in_pos + 1 ) == 0 );
} // end of d_cookie::m_name_equals


/**
 * function ds_cookie::m_get_cookie
*/
char* ds_cookie::m_get_cookie()
{
    return dsc_cookie.m_get_ptr();
} // end of ds_cookie::m_get_name


/**
 * function ds_cookie::m_get_version
*/
int ds_cookie::m_get_version()
{
    return inc_version;
} // end of ds_cookie::m_get_version


/**
 * function ds_cookie::m_get_expires
*/
time_t ds_cookie::m_get_expires()
{
    return ilc_expires;
} // end of ds_cookie::m_get_expires


/**
 * function ds_cookie::m_get_domain
*/
char* ds_cookie::m_get_domain()
{
    return dsc_domain.m_get_ptr();
} // end of ds_cookie::m_get_domain


/**
 * function ds_cookie::m_get_path
*/
char* ds_cookie::m_get_path()
{
    return dsc_path.m_get_ptr();
} // end of ds_cookie::m_get_path


/**
 * function ds_cookie::m_get_port
*/
unsigned short ds_cookie::m_get_port()
{
    return uisc_port;
} // end of ds_cookie::m_get_port


/**
 * function ds_cookie::m_get_comment
*/
char* ds_cookie::m_get_comment()
{
    return dsc_comment.m_get_ptr();
} // end of ds_cookie::m_get_comment


/**
 * function ds_cookie::m_get_commenturl
*/
char* ds_cookie::m_get_commenturl()
{
    return dsc_commenturl.m_get_ptr();
} // end of ds_cookie::m_get_commenturl


/**
 * function ds_cookie::m_is_secure
*/
bool ds_cookie::m_is_secure()
{
    return boc_secure;
} // end of ds_cookie::m_is_secure


/**
 * function ds_cookie::m_is_httponly
*/
bool ds_cookie::m_is_httponly()
{
    return boc_http_only;
} // end of ds_cookie::m_is_httponly


/**
 * function ds_cookie::m_is _discard
*/
bool ds_cookie::m_is_discard()
{
    return boc_discard;
} // end of ds_cookie::m_is_discard


/**
 * function ds_cookie::m_set_cookie
 *
 * @param[in]   const char* ach_add
 * @param[in]   int         in_len
*/
void ds_cookie::m_set_cookie( const char* ach_add, int in_len )
{
    dsc_cookie.m_write( ach_add, in_len );
} // end of ds_cookie::m_set_cookie


/**
 * function ds_cookie::m_set_version
 *
 * @param[in]   int         in_version
*/
void ds_cookie::m_set_version( int in_version )
{
    inc_version = in_version;
} // end of ds_cookie::m_set_version


/**
 * function ds_cookie::m_set_expires
 *
 * @param[in]   time_t      il_expires
*/
void ds_cookie::m_set_expires( time_t il_expires )
{
    boc_discard = false;
    ilc_expires = il_expires;
} // end of ds_cookie::m_set_expires


/**
 * function ds_cookie::m_set_domain
 *
 * @param[in]   const char* ach_add
 * @param[in]   int         in_len
*/
void ds_cookie::m_set_domain( const char* ach_add, int in_len )
{
    dsc_domain.m_write( ach_add, in_len );
} // end of ds_cookie::m_set_domain


/**
 * function ds_cookie::m_set_path
 *
 * @param[in]   const char* ach_add
 * @param[in]   int         in_len
*/
void ds_cookie::m_set_path( const char* ach_add, int in_len )
{
    dsc_path.m_write( ach_add, in_len );
} // end of ds_cookie::m_set_path


/**
 * function ds_cookie::m_set_port
 *
 * @param[in]   unsigned short  uis_port
*/
void ds_cookie::m_set_port( unsigned short uis_port )
{
    uisc_port = uis_port;
} // end of ds_cookie::m_set_port


/**
 * function ds_cookie::m_set_comment
 *
 * @param[in]   const char* ach_add
 * @param[in]   int         in_len
*/
void ds_cookie::m_set_comment( const char* ach_add, int in_len )
{
    dsc_comment.m_write( ach_add, in_len );
} // end of ds_cookie::m_set_comment


/**
 * function ds_cookie::m_set_commenturl
 *
 * @param[in]   const char* ach_add
 * @param[in]   int         in_len
*/
void ds_cookie::m_set_commenturl( const char* ach_add, int in_len )
{
    dsc_commenturl.m_write( ach_add, in_len );
} // end of ds_cookie::m_set_commenturl


/**
 * function ds_cookie::m_set_secure
*/
void ds_cookie::m_set_secure()
{
    boc_secure = true;
} // end of ds_cookie::m_set_secure


/**
 * function ds_cookie::m_set_httponly
*/
void ds_cookie::m_set_httponly()
{
    boc_http_only = true;
} // end of ds_cookie::m_set_httponly


/**
 * function ds_cookie::m_set_discard
*/
void ds_cookie::m_set_discard()
{
    boc_discard = true;
} // end of ds_cookie::m_set_discard


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_cookie::m_get_next_word
 * 
 * @param[in]       const char* ach_cookie      pointer to cookie string
 * @param[in]       int         in_len_cookie   length of cookie string
 * @param[in/out]   int*        ain_position    actual reading position in cookie
 * @param[out]      char**      aach_word       pointer to found word
 * @param[out]      int*        ain_len_word    length of found word
*/
void ds_cookie::m_get_next_word( const char* ach_cookie, int in_len_cookie, 
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
    *aach_word    = (char*)&ach_cookie[in_start_pos];
    *ain_len_word = *ain_position - in_start_pos;
} // end of ds_cookie::m_get_next_word


/**
 *
 * function ds_cookie::m_get_value
 * 
 * @param[in]       const char* ach_cookie      pointer to cookie string
 * @param[in]       int         in_len_cookie   length of cookie string
 * @param[in/out]   int*        ain_position    actual reading position in cookie
 * @param[out]      char**      aach_value      pointer to found value
 * @param[out]      int*        ain_len_value   length of found value
 *
*/
void ds_cookie::m_get_value( const char* ach_cookie, int in_len_cookie, 
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

    *aach_value    = (char*)&ach_cookie[in_start_pos];
    *ain_len_value = *ain_position - in_start_pos;
} // end of ds_cookie::m_get_value


/**
 * function ds_cookie::m_pass_signs
 *
 * @param[in]       const char*     ach_data
 * @param[in]       int             in_len_data
 * @param[in/out]   int*            ain_position
 * @param[in]       const char[]    chr_sign_list
*/
void ds_cookie::m_pass_signs( const char* ach_data, int in_len_data,
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
} // end of ds_cookie::m_pass_signs

/**
 * function ds_cookie:m_get_quote_end
 *
 * @param[in]       const char*     ach_cookie
 * @param[in]       int             in_len_cookie
 * @param[in/out]   int*            ain_position
*/
void ds_cookie::m_get_quote_end( const char* ach_cookie, int in_len_cookie, int* ain_position )
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
} // end of ds_cookie::m_get_quote_end


/**
 * function ds_cookie::m_is_word_in_list
 * 
 * @param[in]   char*   ach_word      pointer to word string
 * @param[in]   int     in_len_word   length of word string
 * @return      int     wordkey,
 *                      -1 if not in list
 *                      -2 if string is empty
*/
int ds_cookie::m_is_word_in_list( char* ach_word, int in_len_word )
{
    if ( in_len_word < 1 || ach_word == NULL ) {
        return (int)ied_ck_empty;
    }

    // initialize some variables:
    BOOL bo_ret;
    int  in_compare;
    int  in_element = 0;

    while( achr_cookie_words[in_element] != NULL ) {
        bo_ret = m_cmpi_vx_vx( &in_compare, 
                               ach_word, in_len_word, ied_chs_utf_8,
                               (void*)achr_cookie_words[in_element],
                               (int)strlen(achr_cookie_words[in_element]),
                               ied_chs_utf_8 );
        if ( bo_ret == TRUE && in_compare == 0 ) {
            return in_element;
        }
        in_element++;
    }

    return (int)ied_ck_unknown;
} // end of ds_cookie::m_is_word_in_list


/**
 * function ds_cookie::m_set_expires
 *
 * @param[in]   char* ach_expires
 * @param[in]   int   in_len_expires
*/
bool ds_cookie::m_set_expires( char* ach_expires, int in_len_expires )
{   
    if ( ach_expires == NULL || in_len_expires < 1 ) {
        return false;
    }
    if ( ach_expires[0] == '"' || ach_expires[0] == '\'' ) {
        ach_expires++;
        in_len_expires -= 2;
    }

    // initialize some variables:
    bool               bo_ret;
    dsd_hl_aux_epoch_1 ds_epoch;

    // get timestamp from string:
    ds_epoch.ac_epoch_str  = (void*)ach_expires;
    ds_epoch.inc_len_epoch = in_len_expires;
    ds_epoch.iec_chs_epoch = ied_chs_utf_8;

    bo_ret = adsc_wsp_helper->m_cb_string_from_epoch( &ds_epoch );
    if (    bo_ret == true 
         && ds_epoch.imc_epoch_val > 0 ) {
        /*
            check if expire date is already set
            -> if not set, just set it to new value
            -> if set, choose the smaller value
        */
        if (    ilc_expires == 0 
             || ilc_expires > ds_epoch.imc_epoch_val ) {
            ilc_expires = ds_epoch.imc_epoch_val;
            boc_discard = false;
        }
        return true;
    }
    return false;
} // end of ds_cookie::m_set_expires


/**
 * function ds_cookie::m_set_max_age
 *
 * @param[in]   char* ach_max_age
 * @param[in]   int   in_len_max_age
*/
bool ds_cookie::m_set_max_age( char* ach_max_age, int in_len_max_age )
{
    if ( ach_max_age == NULL || in_len_max_age < 1 ) {
        return false;
    }

    if ( ach_max_age[0] == '"' || ach_max_age[0] == '\'' ) {
        ach_max_age++;
        in_len_max_age -= 2;
    }

    // initialize some variables:
    bool       bo_ret;
    int        in_maxage;
    time_t     il_now;
    ds_hstring ds_temp( adsc_wsp_helper, ach_max_age, in_len_max_age );

    // convert string to int:
    bo_ret = ds_temp.m_to_int( &in_maxage );
    if ( bo_ret == false || in_maxage < 0 ) {
        return false;
    }

    // get current time:
    il_now = adsc_wsp_helper->m_cb_get_time();
    
    /*
        check if expire date is already set
        -> if not set, just set it to new value
        -> if set, choose the smaller value
    */
    if (    ilc_expires == 0 
         || ilc_expires > il_now + in_maxage ) {
        ilc_expires = il_now + in_maxage;
        boc_discard = false;
    }
    return true;
} // end of ds_cookie::m_set_max_age
