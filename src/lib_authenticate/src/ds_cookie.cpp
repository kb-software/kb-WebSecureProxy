/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_cookie.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include <ds_xml.h>

/*+---------------------------------------------------------------------+*/
/*| helper variables:                                                   |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_cookie_words[] = {
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
    "HttpOnly"
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
	boc_domain    = false;
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
    in_stor_pos     = ds_copy.in_stor_pos;
    dsc_req_domain  = ds_copy.dsc_req_domain;
    dsc_req_path    = ds_copy.dsc_req_path;
	boc_domain      = ds_copy.boc_domain;
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
 * \ingroup authlib
 *
 * function ds_cookie::m_set_req_host
 * save requested url (i.e. "http://www.hob.de/path" )
 * used to check with incoming in cookie or set default values
 *
 * @param[in]   const char* ach_domain          pointer to requested domain
 * @param[in]   int         in_len_domain       length of requested domain
 * @param[in]   const char* ach_path            pointer to requested path
 * @param[in]   int         in_len_path         length of requested path
*/
void ds_cookie::m_set_req_host( const dsd_const_string& rdsp_domain,
                                const dsd_const_string& rdsp_path )
{
    // save requested domain and path

    dsd_const_string dsl_domain(rdsp_domain);
	// TODO: Use parser for domain
    // remove ports in domain:
    int in_pos = dsl_domain.m_last_index_of( ":" );
    if ( in_pos > 0 ) {
        dsl_domain = dsl_domain.m_substring( 0, in_pos );
    }
    dsc_req_domain.m_set( dsl_domain );

    dsd_const_string dsl_path(rdsp_path);
    // remove file from path:
    in_pos = dsl_path.m_last_index_of( "/" );
    if ( in_pos >= 0 )
        dsl_path = dsl_path.m_substring( 0, in_pos );
	if(dsl_path.m_get_len() <= 0)
		dsl_path = "/";
    dsc_req_path.m_set  ( dsl_path );
} // end of ds_cookie::m_set_req_host


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_parse_cookie
 * parse the incoming cookie string
 * 
 * @param[in]   const char* ach_cookie          pointer to cookie string
 * @param[in]   int         in_len_cookie       length of cookie string
 * @return      bool                            true = success
*/
bool ds_cookie::m_parse_cookie( const dsd_const_string& rdsp_cookie )
{
    // initialize some variables:
    bool             bo_ret;                    // return value
    int              in_position  = 0;          // reading position
    char*            ach_word;                  // pointer to actual word
    int              in_len_word;               // length of ach_word
    char*            ach_value    = NULL;       // pointer to actual value
    int              in_len_value = 0;          // length of ach_value
    ied_cookie_words ien_word;                  // key for found word

    const char* ach_cookie = rdsp_cookie.m_get_ptr();
    int in_len_cookie = rdsp_cookie.m_get_len();

	m_get_next_word( ach_cookie, in_len_cookie, &in_position, &ach_word, &in_len_word );
    m_get_value( ach_cookie, in_len_cookie, &in_position, &ach_value, &in_len_value );
	dsc_cookie.m_set( ach_word, in_len_word );
    dsc_cookie.m_write( "=" );
    dsc_cookie.m_write( ach_value, in_len_value );

    while ( in_position < in_len_cookie ) {
        m_get_next_word( ach_cookie, in_len_cookie, &in_position, &ach_word, &in_len_word );
        ien_word = (ied_cookie_words)m_is_word_in_list( ach_word, in_len_word );
        if ( ien_word == ied_ck_empty ) {
            // word is empty
            continue;
        }
		if (    ien_word != ied_ck_secure
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

            case ied_ck_domain: {
				dsd_const_string dsl_domain( ach_value, in_len_value );
				// Specifies those hosts to which the cookie will be sent.
				// If not specified, defaults to the host portion of the current document location (but not including subdomains).
				// Contrary to earlier specifications, leading dots in domain names are ignored.
				// If a domain is specified, subdomains are always included.
				if(dsl_domain.m_starts_with("."))
					dsl_domain = dsl_domain.m_substring(1);
                dsc_domain.m_set(dsl_domain);
                break;
			}
            case ied_ck_path:
                dsc_path.m_set( ach_value, in_len_value );
                break;

            case ied_ck_port:
                break;

            case ied_ck_comment:
                dsc_comment.m_set( ach_value, in_len_value );
                break;

            case ied_ck_commenturl:
                dsc_commenturl.m_set( ach_value, in_len_value );
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
#if 0
                dsc_cookie.m_set( ach_word, in_len_word );
                dsc_cookie.m_write( "=" );
                dsc_cookie.m_write( ach_value, in_len_value );
#endif
				adsc_wsp_helper->m_logf(ied_sdh_log_warning, "m_parse_cookie: found an unknown attribute %.*s=%.*s\n",
					in_len_word, ach_word, in_len_value, ach_value);
                break;
        } // end of switch
    } // end of while(in_position<in_len_cookie)

    //--------------------------------------------------
    // name and value are required to be a valid cookie:
    //--------------------------------------------------
    if ( dsc_cookie.m_get_len() <= 0 ) {
        return false;
    }

    //--------------------------------------------------
    // check if domain is valid:
    //--------------------------------------------------
    if ( dsc_domain.m_get_len() > 0 ) {
		if(dsc_req_domain.m_get_len() > 0) {
			//----------------------------------------------
			// domain must be a subdomain of requested one:
			//----------------------------------------------
			bo_ret = dsc_req_domain.m_ends_with_ic( dsc_domain );
			if ( bo_ret == false ) {
				return false;
			}
		}
#if 0
        //----------------------------------------------
        // domain must contain a "." (not last sign)
        //----------------------------------------------
        in_position = dsc_domain.m_search( "." );
        if (    in_position < 0
             || in_position == dsc_domain.m_get_len() ) {
            return false;
        }
#endif
		boc_domain = true;
    } else {
        //----------------------------------------------
        // set to default if not set:
        //----------------------------------------------
        dsc_domain = dsc_req_domain;
		boc_domain = false;
    }

    //--------------------------------------------------
    // check if path is valid:
    //--------------------------------------------------
    if ( dsc_path.m_get_len() > 0 ) {
        //----------------------------------------------
        // check ending of path
        //----------------------------------------------

		//A request-path path-matches a given cookie-path if at least one of
		//the following conditions holds:
		// The cookie-path and the request-path are identical.
		// The cookie-path is a prefix of the request-path, and the last character of the cookie-path is %x2F ("/").
		// The cookie-path is a prefix of the request-path, and the first character of the request-path that is not included in the cookie- path is a %x2F ("/") character.
#if 0
        if ( dsc_path.m_ends_with( "/" ) == false ) {
            dsc_path.m_write( "/" );
        }
        //----------------------------------------------
        // path must be u subpath of requested one:
        //----------------------------------------------
        in_position = dsc_req_path.m_search_ic( dsc_path );
        if ( in_position != 0 ) {
            return false;
        }
#endif
    } else {
        //----------------------------------------------
        // set to default if not set:
        //----------------------------------------------
        dsc_path = dsc_req_path;
    }
    return true;
} // end of ds_cookie::m_parse_cookie


/**
 * \ingroup authlib
 *
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
	boc_domain    = false;
} // end of ds_cookie::m_reset


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_check_lifetime
 * check if saved lifetime is still valid
 *
 * @return      bool                true = still valid
*/
bool ds_cookie::m_check_lifetime() const
{
    // initialize some variables:
    hl_time_t il_now;

    if ( boc_discard == true ) {
        return true;
    }

    il_now = adsc_wsp_helper->m_cb_get_time();
    if ( ilc_expires > il_now ) {
        return true;
    }
    return false;
} // end of ds_cookie::m_check_lifetime


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_name_equals
 * check if name of given cookie equals our name
 *
 * @param[in]   ds_cookie* ads_compare
 * @return      bool                        true = equals
*/
bool ds_cookie::m_name_equals( ds_cookie* ads_compare )
{
    // get cookie:
    const dsd_const_string ach_cookie = ads_compare->m_get_cookie();
    // search first "=":
    int in_pos = dsc_cookie.m_search( "=" );
    if(in_pos < 1)
        return false;
    dsd_const_string dsl_key(dsc_cookie.m_substring(0, in_pos+1));
    if(!ach_cookie.m_starts_with(dsl_key))
        return false;
    return true;
} // end of ds_cookie::m_name_equals


/**
 * \ingroup authlib
 *
 * public ds_cookie::m_domain_equals
 *
 * @param[in]   ds_cookie* ads_compare
 * @return      bool                        true = equals
*/
bool ds_cookie::m_domain_equals( ds_cookie* ads_compare )
{
    return dsc_domain.m_equals_ic( ads_compare->m_get_domain() );
} // end of ds_cookie::m_domain_equals


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_cookie
*/
const dsd_const_string ds_cookie::m_get_cookie() const
{
    return dsc_cookie.m_const_str();
} // end of ds_cookie::m_get_cookie

/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_name
 *
 * @param[out]  char**  aach_name
 * @param[out]  int*    ain_len
*/
void ds_cookie::m_get_name( const char** aach_name,  int *ain_len ) const
{
    // initialize some variables:
    int in_pos;

    // check input data:
    if (    aach_name == NULL
         || ain_len   == NULL ) {
        return;
    }
    
    // search first "=":
    in_pos = dsc_cookie.m_search( "=" );
    if ( in_pos < 1 ) {
        *aach_name = (char*)"";
        *ain_len   = 0;
        return;
    }

    *aach_name = dsc_cookie.m_get_ptr();
    *ain_len   = in_pos;
    return;
} // end of ds_cookie::m_get_name


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_value
 *
 * @param[out]  char**  aach_value
 * @param[out]  int*    ain_len
*/
void ds_cookie::m_get_value( const char** aach_value, int *ain_len ) const
{
    // initialize some variables:
    int in_pos;

    // check input data:
    if (    aach_value == NULL
         || ain_len    == NULL ) {
        return;
    }
    
    // search first "=":
    in_pos = dsc_cookie.m_search( "=" );
    if ( in_pos < 1 ) {
        *aach_value = "";
        *ain_len    = 0;
        return;
    }

    *aach_value = dsc_cookie.m_get_ptr() + in_pos + 1;
    *ain_len    = dsc_cookie.m_get_len() - in_pos - 1;
    return;
} // end of ds_cookie::m_get_value


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_version
*/
int ds_cookie::m_get_version() const
{
    return inc_version;
} // end of ds_cookie::m_get_version


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_expires
*/
hl_time_t ds_cookie::m_get_expires() const
{
    return ilc_expires;
} // end of ds_cookie::m_get_expires


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_domain
*/
const dsd_const_string ds_cookie::m_get_domain() const
{
    return dsc_domain.m_const_str();
} // end of ds_cookie::m_get_domain


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_path
*/
const dsd_const_string ds_cookie::m_get_path() const
{
    return dsc_path.m_const_str();
} // end of ds_cookie::m_get_path


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_port
*/
unsigned short ds_cookie::m_get_port() const
{
    return uisc_port;
} // end of ds_cookie::m_get_port


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_comment
*/
const dsd_const_string ds_cookie::m_get_comment() const
{
    return dsc_comment.m_const_str();
} // end of ds_cookie::m_get_comment


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_get_commenturl
*/
const dsd_const_string ds_cookie::m_get_commenturl() const
{
    return dsc_commenturl.m_const_str();
} // end of ds_cookie::m_get_commenturl


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_is_secure
*/
bool ds_cookie::m_is_secure() const
{
    return boc_secure;
} // end of ds_cookie::m_is_secure


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_is_httponly
*/
bool ds_cookie::m_is_httponly() const
{
    return boc_http_only;
} // end of ds_cookie::m_is_httponly


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_is _discard
*/
bool ds_cookie::m_is_discard() const
{
    return boc_discard;
} // end of ds_cookie::m_is_discard

/**
 * \ingroup authlib
 *
 * function ds_cookie::m_is_domain
*/
bool ds_cookie::m_is_domain() const
{
    return boc_domain;
} // end of ds_cookie::m_is_domain

/**
 * \ingroup authlib
 *
 * public function ds_cookie::m_get_stor_pos
*/
int ds_cookie::m_get_stor_pos() const
{
    return in_stor_pos;
} // end of ds_cookie::m_get_stor_pos

bool ds_cookie::m_matches_path(const dsd_const_string& rdsp_cookie_path, const dsd_const_string& rdsp_req_path)
{
	//
	// A request-path path-matches a given cookie-path if at least one of the following conditions holds:
	//    The cookie-path and the request-path are identical.
	//    The cookie-path is a prefix of the request-path, and the last character of the cookie-path is %x2F ("/").
	//    The cookie-path is a prefix of the request-path, and the first character of the request-path that is not included in the cookie-
	//    path is a %x2F ("/") character.
	//

#if SM_COOKIE_PATH_CASE_SENSITIVE
	bool bol_ret = rdsp_req_path.m_starts_with(rdsp_cookie_path);
#else
	bool bol_ret = rdsp_req_path.m_starts_with_ic(rdsp_cookie_path);
#endif
	if(!bol_ret)
		return false;
	if(rdsp_cookie_path.m_get_len() == rdsp_req_path.m_get_len())
		return true;
	if(rdsp_cookie_path.m_ends_with("/"))
		return true;
	if(rdsp_req_path[rdsp_cookie_path.m_get_len()] == '/')
		return true;
	return false;
}

bool ds_cookie::m_matches_path(const dsd_const_string& rdsp_path) const
{
	return m_matches_path(this->m_get_path(), rdsp_path);
} // end of ds_cookie::m_matches_path

/**
 * \ingroup authlib
 *
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
 * \ingroup authlib
 *
 * function ds_cookie::m_set_version
 *
 * @param[in]   int         in_version
*/
void ds_cookie::m_set_version( int in_version )
{
    inc_version = in_version;
} // end of ds_cookie::m_set_version


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_set_expires
 *
 * @param[in]   hl_time_t      il_expires
*/
void ds_cookie::m_set_expires( hl_time_t il_expires )
{
    boc_discard = false;
    ilc_expires = il_expires;
} // end of ds_cookie::m_set_expires


/**
 * \ingroup authlib
 *
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
 * \ingroup authlib
 *
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
 * \ingroup authlib
 *
 * function ds_cookie::m_set_port
 *
 * @param[in]   unsigned short  uis_port
*/
void ds_cookie::m_set_port( unsigned short uis_port )
{
    uisc_port = uis_port;
} // end of ds_cookie::m_set_port


/**
 * \ingroup authlib
 *
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
 * \ingroup authlib
 *
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
 * \ingroup authlib
 *
 * function ds_cookie::m_set_secure
*/
void ds_cookie::m_set_secure(bool bop_value)
{
    boc_secure = bop_value;
} // end of ds_cookie::m_set_secure


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_set_httponly
*/
void ds_cookie::m_set_httponly(bool bop_value)
{
    boc_http_only = bop_value;
} // end of ds_cookie::m_set_httponly


/**
 * \ingroup authlib
 *
 * function ds_cookie::m_set_discard
*/
void ds_cookie::m_set_discard(bool bop_value)
{
    boc_discard = bop_value;
} // end of ds_cookie::m_set_discard

/**
 * \ingroup authlib
 *
 * function ds_cookie::m_set_domain
*/
void ds_cookie::m_set_domain(bool bop_value)
{
    boc_domain = bop_value;
} // end of ds_cookie::m_set_domain

/**
 * \ingroup authlib
 *
 * public function ds_cookie::m_set_stor_pos
 *
 * @param[in]   int in_pos
*/
void ds_cookie::m_set_stor_pos( int in_pos )
{
    in_stor_pos = in_pos;
} // end of ds_cookie::m_set_stor_pos


/**
 * \ingroup authlib
 *
 * ds_cookie::m_to_xml
 * fill class from xml
 *
 * @param[in]   ds_hstring* ads_out
 * @return      bool                    true = success
*/
bool ds_cookie::m_to_xml( ds_hstring* ads_out ) const
{
    // initialize some variables:
    ds_xml       dsl_xml;
    dsd_xml_tag* ads_tag_main;
    dsd_xml_tag* ads_tag_child;
    ds_hstring   ds_version( adsc_wsp_helper );
    ds_hstring   ds_expires( adsc_wsp_helper );
    ds_hstring   ds_port   ( adsc_wsp_helper );
    bool         bo_ret;

    // check input data:
    if ( ads_out == NULL ) {
        return false;
    }

    // init xml class:
    dsl_xml.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // create main tag:
    //-------------------------------------------
    ads_tag_main = dsl_xml.m_create_tag( "cookie" );
    if ( ads_tag_main == NULL ) {
        return false;
    }

    //-------------------------------------------
    // create child tags:
    //-------------------------------------------
    // value itself:
    if ( dsc_cookie.m_get_len() < 1 ) {
        return false;
    }
    ads_tag_child = dsl_xml.m_add_child( ads_tag_main, "value" );
    if ( ads_tag_child == NULL ) {
        return false;
    }
    bo_ret = dsl_xml.m_add_value( ads_tag_child, dsc_cookie.m_get_ptr(), dsc_cookie.m_get_len() );
    if ( bo_ret == false ) {
        return false;
    }

    // version:
    if ( inc_version != 1 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_version] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        ds_version.m_writef( "%d", inc_version );
        bo_ret = dsl_xml.m_add_value( ads_tag_child, ds_version.m_get_ptr(), ds_version.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // expires:
    if ( ilc_expires != 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_expires] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        ds_expires.m_writef( "%lld", ilc_expires );
        bo_ret = dsl_xml.m_add_value( ads_tag_child, ds_expires.m_get_ptr(), ds_expires.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // domain:
    if ( dsc_domain.m_get_len() > 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_domain] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, dsc_domain.m_get_ptr(), dsc_domain.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // path:
    if ( dsc_path.m_get_len() > 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_path] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, dsc_path.m_get_ptr(), dsc_path.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // port:
    if ( uisc_port != 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_port] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
		ds_port.m_write_int(uisc_port);
        bo_ret = dsl_xml.m_add_value( ads_tag_child, ds_port.m_get_ptr(), ds_port.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // comment
    if ( dsc_comment.m_get_len() > 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_comment] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, dsc_comment.m_get_ptr(), dsc_comment.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // comment-url
    if ( dsc_commenturl.m_get_len() > 0 ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_commenturl] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, dsc_commenturl.m_get_ptr(), dsc_commenturl.m_get_len() );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // secure:
    if ( boc_secure == true ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_secure] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, "yes" );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // http-only:
    if ( boc_http_only == true ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_httponly] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, "yes" );
        if ( bo_ret == false ) {
            return false;
        }
    }

    // discard:
    if ( boc_discard == false ) {
        ads_tag_child = dsl_xml.m_add_child( ads_tag_main,
                                             achr_cookie_words[ied_ck_discard] );
        if ( ads_tag_child == NULL ) {
            return false;
        }
        bo_ret = dsl_xml.m_add_value( ads_tag_child, "no" );
        if ( bo_ret == false ) {
            return false;
        }
    }

    dsl_xml.m_to_xml( ads_tag_main, ads_out );
    return true;
} // end of ds_cookie::m_to_xml


/**
 * \ingroup authlib
 *
 * ds_cookie::m_from_xml
 * fill class from xml
 *
 * @param[in]   const char* ach_xml
 * @param[in]   int         in_len
 * @return      bool                    true = success
*/
bool ds_cookie::m_from_xml( const char* ach_xml, int in_len )
{
    // initialize some variables:
    ds_xml              dsl_xml;
    dsd_xml_tag*        ads_tag_main;
    int                 in_word;
    const char*               ach_value;
    int                 in_len_value;

    // check input data:
    if ( ach_xml == NULL || in_len < 1 ) {
        return false;
    }

    //-------------------------------------------
    // init xml class:
    //-------------------------------------------
    dsl_xml.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // read in xml:
    //-------------------------------------------
    ads_tag_main = dsl_xml.m_from_xml( (char*)ach_xml, in_len );
    if ( ads_tag_main == NULL ) {
        return false;
    }
    
    //-------------------------------------------
    // get cookie itself:
    //-------------------------------------------
    dsl_xml.m_get_value( ads_tag_main,
                         "value",
                         &ach_value, &in_len_value );
    if ( ach_value == NULL || in_len_value < 1 ) {
        return false;
    }
    dsc_cookie.m_set( ach_value, in_len_value );

    //-------------------------------------------
    // get other values:
    //-------------------------------------------
    for ( in_word = (int)ied_ck_version; in_word <= (int)ied_ck_httponly; in_word++ ) {
        dsl_xml.m_get_value( ads_tag_main,
                             achr_cookie_words[in_word].m_get_ptr(),
                             achr_cookie_words[in_word].m_get_len(),
                             &ach_value, &in_len_value );
        if ( ach_value != NULL && in_len_value > 0 ) {
            switch ( in_word ) {
                case ied_ck_version: {
                    ds_hstring ds_temp( adsc_wsp_helper, ach_value, in_len_value );
                    ds_temp.m_to_int( &inc_version );
                    break; }

                case ied_ck_expires: {                    
                    ds_hstring ds_temp( adsc_wsp_helper, ach_value, in_len_value );
                    ds_temp.m_to_longlong( &ilc_expires );
                    break; }

                case ied_ck_maxage:
                    m_set_max_age( ach_value, in_len_value );
                    break;

                case ied_ck_domain:
                    dsc_domain.m_set( ach_value, in_len_value );
                    break;

                case ied_ck_path:
                    dsc_path.m_set( ach_value, in_len_value );
                    break;

                case ied_ck_port:
                    break;

                case ied_ck_comment:
                    dsc_comment.m_set( ach_value, in_len_value );
                    break;

                case ied_ck_commenturl:
                    dsc_commenturl.m_set( ach_value, in_len_value );
                    break;

                case ied_ck_secure:
                    boc_secure = dsl_xml.m_is_yes( ach_value, in_len_value );
                    break;

                case ied_ck_discard:
                    boc_discard = dsl_xml.m_is_yes( ach_value, in_len_value );
                    break;

                case ied_ck_httponly:
                    boc_http_only = dsl_xml.m_is_yes( ach_value, in_len_value );
                    break;
            }
        }
    }
    return true;
} // end of ds_cookie::m_to_xml


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
                              int* ain_position, const dsd_const_string& chr_sign_list )
{
    dsd_const_string dsl_data(ach_data, in_len_data);
    int inl_pos = dsl_data.m_find_first_not_of(chr_sign_list, *ain_position);
    if(inl_pos < 0)
        inl_pos = dsl_data.m_get_len();
    *ain_position = inl_pos;
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
int ds_cookie::m_is_word_in_list( const char* ach_word, int in_len_word )
{
    if ( in_len_word <= 0 || ach_word == NULL ) {
        return (int)ied_ck_empty;
    }
    dsd_const_string dsl_key(ach_word, in_len_word);
    return (int)ds_wsp_helper::m_search_equals_ic2(achr_cookie_words, dsl_key, ied_ck_unknown);
} // end of ds_cookie::m_is_word_in_list


/**
 * function ds_cookie::m_set_expires
 *
 * @param[in]   char* ach_expires
 * @param[in]   int   in_len_expires
*/
bool ds_cookie::m_set_expires( const char* ach_expires, int in_len_expires )
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

    bo_ret = adsc_wsp_helper->m_cb_epoch_from_string( &ds_epoch );
    if (!bo_ret)
		return false;
	if(ds_epoch.imc_epoch_val < 0)
		ds_epoch.imc_epoch_val = 0;
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
} // end of ds_cookie::m_set_expires


/**
 * function ds_cookie::m_set_max_age
 *
 * @param[in]   char* ach_max_age
 * @param[in]   int   in_len_max_age
*/
bool ds_cookie::m_set_max_age( const char* ach_max_age, int in_len_max_age )
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
    hl_time_t     il_now;
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
