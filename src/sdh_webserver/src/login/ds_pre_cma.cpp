/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define PRECMA_DELETE_TIME  15*60    // 15 minutes
#define DEF_CHS_QUOTIENT    0x04c11db7

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
//#include <basetype.h>
#include <ds_hstring.h>
#include <ds_wsp_helper.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#include "ds_pre_cma.h"
#include <rdvpn_globals.h>

/*+-------------------------------------------------------------------------+*/
/*| some definitions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Structure to store data in the CMA
 *
 * @ingroup authentication
 *
 * Structure to store data in the CMA
 */
struct dsd_usercma_pre {
    int          inc_state;                 //!< working state
    bool         boc_lang_set;              //!< use default language?
    int          inc_lang;                  //!< user selected language
    int          inc_len_username;          //!< length of user name (saved in case of challenge)
    int          inc_len_password;          //!< length of password  (saved in case of take others session)
    int          inc_len_domain;            //!< lenght of domain    (saved in case of take others session)
	int          inc_len_userdn;
    int          inc_len_bpage;             //!< length of requested page (before login)
    unsigned int uinc_msg_url;              //!< url for message
    int          inc_msg_type;              //!< type of message
    int          inc_msg_code;              //!< message code (like error code)
    int          inc_len_msg;               //!< length of message
    int          inc_len_radius_state;      //!< length of radius state
    /*
        kicked out data:
    */
    dsd_aux_query_client dsc_ko_by;         //!< client ip: who did the kick-out
    hl_time_t               tm_ko_time;        //!< login time: when happend the kick-out
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_pre_cma::ds_pre_cma()
{
    adsc_wsp_helper   = NULL;
#if SM_USE_PRECMA_CACHE
	inc_len_pre_cma   = -1;
#else
	dsc_cma.ac_cma_handle = NULL;
#endif
	ads_pre_cma       = NULL;
    achc_username     = NULL;
    achc_password     = NULL;
    achc_domain       = NULL;
	achc_userdn       = NULL;
    achc_bpage        = NULL;
    achc_msg          = NULL;
    achc_radius_state = NULL;
} // end of ds_pre_cma::ds_pre_cma


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Pre_CMA Class initializer
 *
 * @ingroup authentication
 *
 * Sets some default values
 */
void ds_pre_cma::m_init( ds_wsp_helper* ads_wsp_helper )
{
    adsc_wsp_helper = ads_wsp_helper;
#if SM_USE_PRECMA_CACHE
	inc_len_pre_cma = -1;
	boc_cma_changed = false;
#else
	dsc_cma.ac_cma_handle  = NULL;
#endif
	ads_pre_cma     = NULL;
} // end of ds_pre_cma::m_init

/*! \brief Create a CMA
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_create_cookie
 * create a CMA
 *
 * @return	bool	true = success
 */
bool ds_pre_cma::m_create_cookie()
{
    return m_create();
} // end of ds_pre_cma::m_create_cookie


/*! \brief Delete already opened CMA
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_delete_cookie
 * delete already opened cma (means set size to zero!)
 * ATTENTION: a call to m_close_cookie is still needed!
 *
 * @return      bool                                true = success
 */
bool ds_pre_cma::m_delete_cookie()
{
    // initialize some variables:
    bool bo_ret;

    bo_ret = m_open_cma( true );
    if ( bo_ret == false ) {
        return false;
    }

	bo_ret = m_resize_cma( 0 );

    m_close_cma();
    return bo_ret;
} // end of ds_pre_cma::m_delete_cookie

/*! \brief Sets name
 *
 * @ingroup authentication
 *
  * ds_pre_cma::m_set_name
 *
 * @param[in]   const char* ach_cookie
 * @param[in]   int         in_len_cookie
 * @return      bool                            true = success 
 */
bool ds_pre_cma::m_set_name( const char* ach_cookie, int in_len_cookie )
{
    if ( in_len_cookie != LEN_NOAUTH_COOKIE ) {
        return false;
    }

    // check if first LEN_WSP_ID are numbers:
    for ( int in_pos = 0; in_pos < LEN_WSP_ID; in_pos++ ) {
        switch( ach_cookie[in_pos] ) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                break;
            default:
                return false;
        }
    }

    memcpy( &chr_cmaname[0], ach_cookie, LEN_NOAUTH_COOKIE );
    return true;
} // end of ds_pre_cma::m_set_cma


/*! \brief Check for a specific cookie format
 *
 * @ingroup authentication
 *
 * public method ds_pre_cma::m_has_cookie_format
 * check if given string has a common "nonauth" cookie format
 *
 * @param[in]   const char  *achp_cookie    cookie string
 * @param[in]   int         inp_length      length of cookie
 */
bool ds_pre_cma::m_has_cookie_format( const char *achp_cookie, int inp_length )
{
    int inl_off;        /* offset in cookie */

    /* a non auth cookie has a special length */
    if ( inp_length != LEN_NOAUTH_COOKIE ) {
        return false;
    }

    /* first LEN_WSP_ID bytes are just numbers */
    for ( inl_off = 0; inl_off < LEN_WSP_ID; inl_off++ ) {
        switch( achp_cookie[inl_off] ) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                break;
            default:
                return false;
        }
    }

    return true;
} /* end of ds_pre_cma::m_has_cookie_format */

/*! \brief Create a pre auth CMA
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_create
 * create a pre auth cma
 */
bool ds_pre_cma::m_create()
{
    // initialize some variables:
    bool bo_cma_exists;          // does cma exists already?
    bool bol_ret;

    //----------------------------------
    // find a non existing cma:
    //----------------------------------
    do {
        //------------------------------
        // create cma name:
        //------------------------------
        bol_ret = m_create_cma_name( true );
        if ( bol_ret == false ) {
            return false;
        }
        
		struct dsd_hl_aux_c_cma_1 dsl_cma;
		if(!adsc_wsp_helper->m_cb_open_or_create_cma(&chr_cmaname[0], LEN_NOAUTH_COOKIE, &dsl_cma, PRECMA_DELETE_TIME))
			return false;
        //------------------------------
        // check if cma exists already:
        //------------------------------
		bo_cma_exists = (dsl_cma.inc_len_cma_area >= sizeof(dsd_usercma_pre));
		if(!bo_cma_exists) {
			if(!adsc_wsp_helper->m_cb_resize_cma2(&dsl_cma, sizeof(dsd_usercma_pre)))
				return false;
			memset(dsl_cma.achc_cma_area, 0, sizeof(dsd_usercma_pre));
		}
		if(!adsc_wsp_helper->m_cb_close_cma2(&dsl_cma))
			return false;
    } while ( bo_cma_exists == true );

	return true;
} // end of ds_pre_cma::m_create


/*! \brief Gets a cookie
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_cookie
 *
 * @param[in]   char**  aach_cookie
 * @param[in]   int*    *ain_len
 */
void ds_pre_cma::m_get_cookie( const char** aach_cookie, int* ain_len )
{
    *aach_cookie = &chr_cmaname[0];
    if ( chr_cmaname[0] != 0 ) {
        *ain_len = LEN_NOAUTH_COOKIE;
    } else {
        *ain_len = 0;
    }
} // end of ds_pre_cma::m_get_cookie


/*! \brief Initializes a state
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_init_state
 * initialize state with given value
 *
 * @param[in]   int in_state 
 */
void ds_pre_cma::m_init_state( int in_state )
{
    // initialize some variables:
    bool bo_open;

    // open cma for writting:
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return;
    }

#if SM_USE_PRECMA_CACHE
	int inl_old = ads_pre_cma->inc_state;
#endif
	// set state:
    ads_pre_cma->inc_state = in_state;
#if SM_USE_PRECMA_CACHE
	if(inl_old != ads_pre_cma->inc_state)
		this->boc_cma_changed = true;
#endif

    // close cma:
    m_close_cma();
} // end of ds_pre_cma::m_init_state


/*! \brief Sets a state
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_set_state
 * OR state with given value
 *
 * @param[in]   int in_state 
 */
void ds_pre_cma::m_set_state( int in_state )
{
    // initialize some variables:
    bool bo_open;

    // open cma for writting:
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return;
    }

#if SM_USE_PRECMA_CACHE
	int inl_old = ads_pre_cma->inc_state;
#endif
	// set state:
    ads_pre_cma->inc_state |= in_state;
#if SM_USE_PRECMA_CACHE
	if(inl_old != ads_pre_cma->inc_state)
		this->boc_cma_changed = true;
#endif

    // close cma:
    m_close_cma();
} // end of ds_pre_cma::m_set_state


/*! \brief Unset a state
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_unset_state
 * un-OR state with given value
 *
 * @param[in]   int in_state
 */
void ds_pre_cma::m_unset_state ( int in_state )
{
    // initialize some variables:
    bool bo_open;

    // open cma for writting:
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return;
    }

#if SM_USE_PRECMA_CACHE
	int inl_old = ads_pre_cma->inc_state;
#endif
    // set state:
    ads_pre_cma->inc_state = ads_pre_cma->inc_state & ~in_state;
#if SM_USE_PRECMA_CACHE
	if(inl_old != ads_pre_cma->inc_state)
		this->boc_cma_changed = true;
#endif

    // close cma:
    m_close_cma();
} // end of ds_pre_cma::m_unset_state


/*! \brief Check state
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_check_state
 * check if state contains given value
 *
 * @param[in]   int     in_state
 * @return      bool                        true = state is set
 */
bool ds_pre_cma::m_check_state( int in_state )
{
    // initialize some variables:
    bool bo_open;
    bool bo_ret;

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return false;
    }

    // check state:
    if ( (ads_pre_cma->inc_state & in_state) == in_state ) {
        bo_ret = true;
    } else {
        bo_ret = false;
    }

    // close cma:
    m_close_cma();
    return bo_ret;
} // end of ds_pre_cma::m_check_state


/*! \brief Get state
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_state
 *
 * @return      int
 */
int ds_pre_cma::m_get_state()
{
    // initialize some variables:
    bool bo_open;
    int  in_ret;

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return 0;
    }

    // get state:
    in_ret = ads_pre_cma->inc_state;

    // close cma:
    m_close_cma();
    return in_ret;
} // end of ds_pre_cma::m_get_state


/*! \brief Get Language
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_lang
 *
 * @return      ied_language
 */
int ds_pre_cma::m_get_lang()
{
    // initialize some variables:
    bool bo_open;
    int  in_lang;

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return -1;
    }

    // get lang:
    if ( ads_pre_cma->boc_lang_set == true ) {
        in_lang = ads_pre_cma->inc_lang;
    } else {
        in_lang = -1;
    }

    // close cma:
    m_close_cma();
    return in_lang;
} // end of ds_pre_cma::m_get_lang


/*! \brief Set language
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_lang
 *
 * @param[in]   int    in_lang
 * @return      bool                            true = success
 */
bool ds_pre_cma::m_set_lang( int in_lang )
{
    // initialize some variables:
    bool bo_open;

    // open cma for writing:
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

#if SM_USE_PRECMA_CACHE
	int inl_old = ads_pre_cma->inc_lang;
#endif
	// set lang:  
    ads_pre_cma->inc_lang = in_lang;
#if SM_USE_PRECMA_CACHE
	if(inl_old != ads_pre_cma->inc_lang)
		this->boc_cma_changed = true;
#endif
#if SM_USE_PRECMA_CACHE
	bool bol_old = ads_pre_cma->boc_lang_set;
#endif
    ads_pre_cma->boc_lang_set = true;
#if SM_USE_PRECMA_CACHE
	if(bol_old != ads_pre_cma->boc_lang_set)
		this->boc_cma_changed = true;
#endif

    // close cma:
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_lang
    

/*! \brief Get username
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_get_user
 *
 * @return  ds_hstring
 */
ds_hstring ds_pre_cma::m_get_user()
{
    // initialize some variables:
    bool        bo_open;
    ds_hstring  ds_out;                // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return 0;
    }

    // get state:
    ds_out.m_write( achc_username, ads_pre_cma->inc_len_username );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_user

/*! \brief Get userdn
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_get_userdn
 *
 * @return  ds_hstring
 */
ds_hstring ds_pre_cma::m_get_userdn()
{
    // initialize some variables:
    bool        bo_open;
    ds_hstring  ds_out;                // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return 0;
    }

    // get state:
    ds_out.m_write( achc_userdn, ads_pre_cma->inc_len_userdn );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_user

/*! \brief Get password
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_get_password
 *
 * @return  ds_hstring
 */
ds_hstring ds_pre_cma::m_get_password()
{
    // initialize some variables:
    bool        bo_open;
    ds_hstring  ds_out;                // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return 0;
    }

    // get state:
    ds_out.m_write( achc_password, ads_pre_cma->inc_len_password );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_password


/*! \brief Get domain
 *
 * @ingroup authentication
 *
 * function ds_pre_cma::m_get_domain
 *
 * @return  ds_hstring
 */
ds_hstring ds_pre_cma::m_get_domain()
{
    // initialize some variables:
    bool        bo_open;
    ds_hstring  ds_out;                // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return 0;
    }

    // get state:
    ds_out.m_write( achc_domain, ads_pre_cma->inc_len_domain );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_domain


/*! \brief Set username
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_user
 *
 * @param[in]   const char* ach_username
 * @param[in]   int         in_len_username
 * @return      bool
 */
bool ds_pre_cma::m_set_user( const char* ach_username, int in_len_username )
{
    // initialize some variables:
    bool  bo_open;
    char* ach_insert;            // insert position
    char* ach_save  = NULL;      // save old values
    int   in_save   = 0;         // length of saved data

    if ( in_len_username < 0 ) {
        return false;
    }
    if ( ach_username == NULL ) {
        in_len_username = 0;
    }

    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // check length:
    //-----------------------------------------------
    if ( in_len_username != ads_pre_cma->inc_len_username ) {
        //-------------------------------------------
        // save old values (will be overwritten while resize):
        //-------------------------------------------
        in_save =   ads_pre_cma->inc_len_password
                  + ads_pre_cma->inc_len_domain
                  + ads_pre_cma->inc_len_bpage
                  + ads_pre_cma->inc_len_msg
                  + ads_pre_cma->inc_len_radius_state;
        if ( in_save > 0 ) {
            ach_save = adsc_wsp_helper->m_cb_get_memory( in_save, false );
            if ( ach_save == NULL ) {
                m_close_cma();
                return false;
            }
            ach_insert =   (char*)ads_pre_cma
                         + sizeof(dsd_usercma_pre)
                         + ads_pre_cma->inc_len_username;
            memcpy( ach_save, ach_insert, in_save );
        }

        //-------------------------------------------
        // resize cma:
        //-------------------------------------------
        bo_open = m_resize_cma(   (int)sizeof(dsd_usercma_pre)
                                + in_len_username
                                + ads_pre_cma->inc_len_password
                                + ads_pre_cma->inc_len_domain
                                + ads_pre_cma->inc_len_bpage
                                + ads_pre_cma->inc_len_msg
                                + ads_pre_cma->inc_len_radius_state );
        if ( bo_open == false ) {
            m_close_cma();
            adsc_wsp_helper->m_cb_free_memory( ach_save );
            return false;
        }

        //-------------------------------------------
        // save new length:
        //-------------------------------------------
        ads_pre_cma->inc_len_username = in_len_username;
    }

    //-----------------------------------------------
    // save new username:
    //-----------------------------------------------
    ach_insert = (char*)ads_pre_cma + sizeof(dsd_usercma_pre);
    if ( in_len_username > 0 && ach_username != NULL ) {
        memcpy( ach_insert, ach_username, in_len_username );
    }
    achc_username = ach_insert;

    //-----------------------------------------------
    // write old data again:
    //-----------------------------------------------
    ach_insert += in_len_username;
    if (    ach_save != NULL 
         && in_save > 0 ) {
        memcpy( ach_insert, ach_save, in_save );
        adsc_wsp_helper->m_cb_free_memory( ach_save );
    }
#if SM_USE_PRECMA_CACHE
	this->boc_cma_changed = true;
#endif
    //-----------------------------------------------
    // set string pointers:
    //-----------------------------------------------
    m_setup_strings();

    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_user


/*! \brief Set user data
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_user
 *
 * @param[in]   const char* ach_domain
 * @param[in]   int         in_len_domain
 * @param[in]   const char* ach_username
 * @param[in]   int         in_len_username
 * @param[in]   const char* ach_password
 * @param[in]   int         in_len_password
 * @return      bool
 */
bool ds_pre_cma::m_set_user( const char* ach_domain,   int in_len_domain,
                             const char* ach_username, int in_len_username,
                             const char* ach_password, int in_len_password,
							 const char* ach_userdn,   int in_len_userdn)
{
    // initialize some variables:
    bool  bo_open;
    char* ach_insert;            // insert position
    char* ach_save  = NULL;      // save old values
    int   in_save   = 0;         // length of saved data

    if (    in_len_domain   < 0
         || in_len_username < 0
         || in_len_password < 0
		 || in_len_userdn < 0) {
        return false;
    }
    if ( ach_domain == NULL ) {
        in_len_domain = 0;
    }
    if ( ach_username == NULL ) {
        in_len_username = 0;
    }
    if ( ach_password == NULL ) {
        in_len_password = 0;
    }
	if ( ach_userdn == NULL ) {
        in_len_userdn = 0;
    }
    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // save old values (will be overwritten while resize):
    //-----------------------------------------------
    in_save =   ads_pre_cma->inc_len_bpage
              + ads_pre_cma->inc_len_msg
              + ads_pre_cma->inc_len_radius_state;
    if ( in_save > 0 ) {
        ach_save = adsc_wsp_helper->m_cb_get_memory( in_save, false );
        if ( ach_save == NULL ) {
            m_close_cma();
            return false;
        }
        ach_insert =   (char*)ads_pre_cma
                     + sizeof(dsd_usercma_pre)
                     + ads_pre_cma->inc_len_username
                     + ads_pre_cma->inc_len_password
                     + ads_pre_cma->inc_len_domain
					 + ads_pre_cma->inc_len_userdn;
        memcpy( ach_save, ach_insert, in_save );
    }

    //-------------------------------------------
    // resize cma:
    //-------------------------------------------
    bo_open = m_resize_cma(   (int)sizeof(dsd_usercma_pre)
                            + in_len_username
                            + in_len_password
                            + in_len_domain
							+ in_len_userdn
                            + ads_pre_cma->inc_len_bpage
                            + ads_pre_cma->inc_len_msg
                            + ads_pre_cma->inc_len_radius_state );
    if ( bo_open == false ) {
        m_close_cma();
        adsc_wsp_helper->m_cb_free_memory( ach_save );
        return false;
    }

    //-------------------------------------------
    // save new length:
    //-------------------------------------------
    ads_pre_cma->inc_len_username = in_len_username;
    ads_pre_cma->inc_len_password = in_len_password;
    ads_pre_cma->inc_len_domain   = in_len_domain;
	ads_pre_cma->inc_len_userdn   = in_len_userdn;

    //-----------------------------------------------
    // save new data:
    //-----------------------------------------------
    ach_insert = (char*)ads_pre_cma + sizeof(dsd_usercma_pre);
    if ( in_len_username > 0 && ach_username != NULL ) {
        memcpy( ach_insert, ach_username, in_len_username );
    }
    achc_username = ach_insert;
    ach_insert += in_len_username;

    if ( in_len_password > 0 && ach_password != NULL ) {
        memcpy( ach_insert, ach_password, in_len_password );
    }
    achc_password = ach_insert;
    ach_insert += in_len_password;

    if ( in_len_domain > 0 && ach_domain != NULL ) {
        memcpy( ach_insert, ach_domain, in_len_domain );
    }
    achc_domain = ach_insert;
    ach_insert += in_len_domain;
	if ( in_len_userdn > 0 && ach_userdn != NULL ) {
        memcpy( ach_insert, ach_userdn, in_len_userdn );
    }
    achc_userdn = ach_insert;
    ach_insert += in_len_userdn;

    //-----------------------------------------------
    // write old data again:
    //-----------------------------------------------
    if (    ach_save != NULL 
         && in_save > 0 ) {
        memcpy( ach_insert, ach_save, in_save );
        adsc_wsp_helper->m_cb_free_memory( ach_save );
    }
#if SM_USE_PRECMA_CACHE
	this->boc_cma_changed = true;
#endif

    //-----------------------------------------------
    // set string pointers:
    //-----------------------------------------------
    m_setup_strings();

    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_user


/*! \brief Get requested page
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_bpage
 * get bpage from cma
 *
 * @return      ds_hstring                  bpage
 */
ds_hstring ds_pre_cma::m_get_bpage()
{
    // initialize some variables:
    bool       bo_open;
    ds_hstring ds_out;               // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return ds_out;
    }

    // get bpage:
    ds_out.m_write( achc_bpage, ads_pre_cma->inc_len_bpage );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_bpage


/*! \brief Set requested page
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_bpage
 * set booked page in cma
 *
 * @param[in]   const char*   ach_page      booked page
 * @param[in]   int           in_len        length of bpage
 * @return      bool                        true = success
 */
bool ds_pre_cma::m_set_bpage( const char* ach_page, int in_len )
{
    // initialize some variables:
    bool   bo_open;
    char*  ach_insert;            // insert position
    char*  ach_save = NULL;       // save old values
    int    in_save  = 0;          // length of saved data

    if ( in_len < 0 ) {
        return false;
    }
    if ( ach_page == NULL ) {
        in_len = 0;
    }

    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

#if SM_USE_PRECMA_CACHE
	if(!(dsd_const_string(ach_page, in_len).m_equals(dsd_const_string(this->achc_bpage, ads_pre_cma->inc_len_bpage))))
		this->boc_cma_changed = true;
#endif
    //-----------------------------------------------
    // check length:
    //-----------------------------------------------
    if ( in_len != ads_pre_cma->inc_len_bpage ) {
        //-------------------------------------------
        // save old values (will be overwritten while resize):
        //-------------------------------------------
        in_save =   ads_pre_cma->inc_len_msg
                  + ads_pre_cma->inc_len_radius_state;
        if ( in_save > 0 ) {
            ach_save = adsc_wsp_helper->m_cb_get_memory( in_save, false );
            if ( ach_save == NULL ) {
                m_close_cma();
                return false;
            }
            ach_insert =   (char*)ads_pre_cma
                         + sizeof(dsd_usercma_pre)
                         + ads_pre_cma->inc_len_username
                         + ads_pre_cma->inc_len_password
                         + ads_pre_cma->inc_len_domain
                         + ads_pre_cma->inc_len_bpage;
            memcpy( ach_save, ach_insert, in_save );
        }

        //-------------------------------------------
        // resize cma:
        //-------------------------------------------
        bo_open = m_resize_cma(   (int)sizeof(dsd_usercma_pre)
                                + ads_pre_cma->inc_len_username
                                + ads_pre_cma->inc_len_password
                                + ads_pre_cma->inc_len_domain
                                + in_len
                                + ads_pre_cma->inc_len_msg
                                + ads_pre_cma->inc_len_radius_state );
        if ( bo_open == false ) {
            m_close_cma();
            adsc_wsp_helper->m_cb_free_memory( ach_save );
            return false;
        }

        //-------------------------------------------
        // save new length:
        //-------------------------------------------
        ads_pre_cma->inc_len_bpage = in_len;
    }

    //-----------------------------------------------
    // save new booked page:
    //-----------------------------------------------
    ach_insert = (char*)ads_pre_cma + sizeof(dsd_usercma_pre)
                                    + ads_pre_cma->inc_len_username
                                    + ads_pre_cma->inc_len_password
                                    + ads_pre_cma->inc_len_domain;
    if ( in_len > 0 && ach_page != NULL ) {
        memcpy( ach_insert, ach_page, in_len );
    }
    achc_bpage = ach_insert;

    //-----------------------------------------------
    // write old data again:
    //-----------------------------------------------
    ach_insert += in_len;
    if (    ach_save != NULL 
         && in_save > 0 ) {
        memcpy( ach_insert, ach_save, in_save );
        adsc_wsp_helper->m_cb_free_memory( ach_save );
    }

    //-----------------------------------------------
    // set string pointers:
    //-----------------------------------------------
    m_setup_strings();

    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_bpage


/*! \brief Clear page
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_clear_bpage
 * clear bpage in cma
 *
 * @return      bool                        true = success
 */
bool ds_pre_cma::m_clear_bpage()
{
    return m_set_bpage( NULL, 0 );
} // end of ds_pre_cma::m_clear_bpage


/*! \brief Get message from CMA
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_message
 * get message for given url from cma
 *
 * @param[in]   const char* ach_url         current url
 * @param[in]   int         in_len_url      length of url
 * @param[out]  int*        ain_type        message type
 * @param[out]  int*        ain_code        message code
 * @return      ds_hstring                  message
 */
ds_hstring ds_pre_cma::m_get_message( const char* ach_url, int in_len_url,
                                      int* ain_type, int *ain_code         )
{
    // initialize some variables:
    bool       bo_open;
    ds_hstring ds_out;               // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return ds_out;
    }

    
    // check given url:
    if (    ach_url    == NULL 
         || in_len_url  < 1
         || ads_pre_cma->uinc_msg_url == m_build_checksum( (char*)ach_url, in_len_url ) ) {
        // get message:
        ds_out.m_write( achc_msg, ads_pre_cma->inc_len_msg );

        // get type and code:
        *ain_type = ads_pre_cma->inc_msg_type;
        *ain_code = ads_pre_cma->inc_msg_code;
    }

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_message


/*! \brief Set message in the CMA
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_message
 * set message in cma
 *
 * @param[in]   int           in_msg_type   message type
 * @param[in]   int           in_msg_code   message code
 * @param[in]   const char*   ach_msg       message
 * @param[in]   int           in_len        length of message
 * @param[in]   const char*   ach_url       message url
 * @param[in]   int           in_len_url    length of url
 * @return      bool                        true = success
 */
bool ds_pre_cma::m_set_message( int in_msg_type,     int in_msg_code,
                                const dsd_const_string& ach_msg,
                                const dsd_const_string& ach_url  )
{
    // initialize some variables:
    bool  bo_open;
    char* ach_insert;            // insert position
    char* ach_save = NULL;       // save old values
    int   in_save  = 0;          // length of saved data

    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // check length:
    //-----------------------------------------------
     if ( (int)ach_msg.m_get_len() != ads_pre_cma->inc_len_msg ) {
        //-------------------------------------------
        // save old values (will be overwritten while resize):
        //-------------------------------------------
        in_save = ads_pre_cma->inc_len_radius_state;
        if ( in_save > 0 ) {
            ach_save = adsc_wsp_helper->m_cb_get_memory( in_save, false );
            if ( ach_save == NULL ) {
                m_close_cma();
                return false;
            }
            ach_insert =   (char*)ads_pre_cma
                         + sizeof(dsd_usercma_pre)
                         + ads_pre_cma->inc_len_username
                         + ads_pre_cma->inc_len_password
                         + ads_pre_cma->inc_len_domain
                         + ads_pre_cma->inc_len_bpage
                         + ads_pre_cma->inc_len_msg;
            memcpy( ach_save, ach_insert, in_save );
        }

        //-------------------------------------------
        // resize cma:
        //-------------------------------------------
        bo_open = m_resize_cma(   (int)sizeof(dsd_usercma_pre)
                                + ads_pre_cma->inc_len_username
                                + ads_pre_cma->inc_len_password
                                + ads_pre_cma->inc_len_domain
                                + ads_pre_cma->inc_len_bpage
                                + (int)ach_msg.m_get_len()
                                + ads_pre_cma->inc_len_radius_state );
        if ( bo_open == false ) {
            m_close_cma();
            adsc_wsp_helper->m_cb_free_memory( ach_save );
            return false;
        }

        //-------------------------------------------
        // save new length:
        //-------------------------------------------
        ads_pre_cma->inc_len_msg = ach_msg.m_get_len();
    }

    //-----------------------------------------------
    // save new message:
    //-----------------------------------------------
    ach_insert = (char*)ads_pre_cma + sizeof(dsd_usercma_pre)
                                    + ads_pre_cma->inc_len_username
                                    + ads_pre_cma->inc_len_password
                                    + ads_pre_cma->inc_len_domain
                                    + ads_pre_cma->inc_len_bpage;
    if ( ach_msg.m_get_len() > 0 ) {
        memcpy( ach_insert, ach_msg.m_get_start(), ach_msg.m_get_len() );
    }
    achc_msg = ach_insert;

    //-----------------------------------------------
    // write old data again:
    //-----------------------------------------------
    ach_insert += ach_msg.m_get_len();
    if (    ach_save != NULL 
         && in_save > 0 ) {
        memcpy( ach_insert, ach_save, in_save );
        adsc_wsp_helper->m_cb_free_memory( ach_save );
    }

    //-----------------------------------------------
    // set string pointers:
    //-----------------------------------------------
    m_setup_strings();

    //-----------------------------------------------
    // save url as hash value:
    //-----------------------------------------------
    if ( ach_url.m_get_len() <= 0 ) {
        ads_pre_cma->uinc_msg_url = 0;
    } else {
        ads_pre_cma->uinc_msg_url = m_build_checksum( ach_url.m_get_start(), ach_url.m_get_len() );
    }

    //-----------------------------------------------
    // save message type and code:
    //-----------------------------------------------
    ads_pre_cma->inc_msg_type = in_msg_type;
    ads_pre_cma->inc_msg_code = in_msg_code;

#if SM_USE_PRECMA_CACHE
	this->boc_cma_changed = true;
#endif

    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_message


/*! \brief Get radius state
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_get_radius
 * get radius state from cma
 *
 * @return      ds_hstring                  radius state
 */
ds_hstring ds_pre_cma::m_get_radius()
{
    // initialize some variables:
    bool       bo_open;
    ds_hstring ds_out;                // output
    ds_out.m_setup( adsc_wsp_helper );

    // open cma for reading:
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return ds_out;
    }

    // get message:
    ds_out.m_write( achc_radius_state, ads_pre_cma->inc_len_radius_state );

    // close cma:
    m_close_cma();
    return ds_out;
} // end of ds_pre_cma::m_get_radius


/*! \brief Set radius state
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_set_radius
 * set radius state in cma
 *
 * @param[in]   const char*   ach_rad       radius state
 * @param[in]   int           in_len        length of radius state
 * @return      bool                        true = success
 */
bool ds_pre_cma::m_set_radius( const char* ach_rad, int in_len )
{
    // initialize some variables:
    bool  bo_open;
    char* ach_insert;            // insert position

    if ( in_len < 0 ) {
        return false;
    }
    if ( ach_rad == NULL ) {
        in_len = 0;
    }

    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // check length:
    //-----------------------------------------------
    if ( in_len != ads_pre_cma->inc_len_radius_state ) {
        //-------------------------------------------
        // resize cma:
        //-------------------------------------------
        bo_open = m_resize_cma(   (int)sizeof(dsd_usercma_pre)
                                + ads_pre_cma->inc_len_username
                                + ads_pre_cma->inc_len_password
                                + ads_pre_cma->inc_len_domain
                                + ads_pre_cma->inc_len_bpage
                                + ads_pre_cma->inc_len_msg
                                + in_len );
        if ( bo_open == false ) {
            m_close_cma();
            return false;
        }

        //-------------------------------------------
        // save new length:
        //-------------------------------------------
        ads_pre_cma->inc_len_radius_state = in_len;
    }

    //-----------------------------------------------
    // save new radius state:
    //-----------------------------------------------
    ach_insert = (char*)ads_pre_cma + sizeof(dsd_usercma_pre)
                                    + ads_pre_cma->inc_len_username
                                    + ads_pre_cma->inc_len_password
                                    + ads_pre_cma->inc_len_domain
                                    + ads_pre_cma->inc_len_bpage
                                    + ads_pre_cma->inc_len_msg;
    if ( in_len > 0 && ach_rad != NULL ) {
        memcpy( ach_insert, ach_rad, in_len );
    }
    achc_radius_state = ach_insert;

    //-----------------------------------------------
    // setup strings:
    //-----------------------------------------------
    m_setup_strings();

#if SM_USE_PRECMA_CACHE
	this->boc_cma_changed = true;
#endif
    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_set_radius


/*! \brief Clear radius state
 *
 * @ingroup authentication
 *
 * ds_pre_cma::m_clear_radius
 * clear radius state in cma
 *
 * @return      bool                        true = success
 */
bool ds_pre_cma::m_clear_radius()
{
    return m_set_radius( NULL, 0 );
} // end of ds_pre_cma::m_set_radius


/*! \brief Save information about the kicked out user
 *
 * @ingroup authentication
 *
 * public function ds_pre_cma::m_saved_kicked_out
 *
 * @param[in]   dsd_kicked_out_t*   ads_kicked_out
 * @return      bool
 */
bool ds_pre_cma::m_save_kicked_out( dsd_kicked_out_t* ads_kicked_out )
{
    // initialize some variables:
    bool  bo_open;

    //-----------------------------------------------
    // open cma for writing:
    //-----------------------------------------------
    bo_open = m_open_cma( true );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // copy kicked out data:
    //-----------------------------------------------
    memcpy( &ads_pre_cma->dsc_ko_by,
            &ads_kicked_out->ds_client,
            sizeof(dsd_aux_query_client) );
    ads_pre_cma->tm_ko_time = ads_kicked_out->tm_login;

#if SM_USE_PRECMA_CACHE
	this->boc_cma_changed = true;
#endif
	//-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_save_kicked_out


/*! \brief Get kicked out informations
 *
 * @ingroup authentication
 *
 * public function ds_pre_cma::m_get_kicked_out
 *
 * @param[in]   dsd_kicked_out_t*   ads_kicked_out
 * @return      bool
 */
bool ds_pre_cma::m_get_kicked_out( dsd_kicked_out_t* ads_kicked_out )
{
    // initialize some variables:
    bool  bo_open;

    //-----------------------------------------------
    // open cma for reading:
    //-----------------------------------------------
    bo_open = m_open_cma( false );
    if ( bo_open == false ) {
        return false;
    }

    //-----------------------------------------------
    // copy kicked out data:
    //-----------------------------------------------
    memcpy( &ads_kicked_out->ds_client,
            &ads_pre_cma->dsc_ko_by,
            sizeof(dsd_aux_query_client) );
    ads_kicked_out->tm_login = ads_pre_cma->tm_ko_time;

    //-----------------------------------------------
    // close cma:
    //-----------------------------------------------
    m_close_cma();
    return true;
} // end of ds_pre_cma::m_get_kicked_out


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * ds_pre_cma::m_create_cma_name
 *
 * @param[in]   bool    bo_force_new                force new creation of name
*/
bool ds_pre_cma::m_create_cma_name( bool bo_force_new )
{
    // initialize some variables:
    int in_sess_id;
    bool bol_ret;
   
    bol_ret = false;
    // check if name is already filled:
    if ( bo_force_new == false && chr_cmaname[0] != 0 ) {
        return true;
    }

    // get session id:
    in_sess_id = adsc_wsp_helper->m_get_session_id();

    // create cookie string:    
    m_hlsnprintf( &chr_cmaname[0], LEN_NOAUTH_COOKIE,
                  ied_chs_utf_8, "%08d", in_sess_id );

    // create random part of cookie:
    bol_ret = adsc_wsp_helper->m_cb_get_random_cookie( &chr_cmaname[LEN_WSP_ID], LEN_RANDOM );
    return bol_ret;
} // end of ds_pre_cma::m_create_cma_name


#if 0
/**
 * ds_pre_cma::m_create_cma
 *
 * @return      bool                                true = success
*/
bool ds_pre_cma::m_create_cma()
{
    // initialize some variables:
    bool bo_created;

    bo_created = adsc_wsp_helper->m_cb_create_cma( &chr_cmaname[0],
                                                   LEN_NOAUTH_COOKIE,
                                                   NULL,
                                                   sizeof(dsd_usercma_pre),
												   PRECMA_DELETE_TIME );
    return bo_created;
} // end of ds_pre_cma::m_create_cma()
#endif

/**
 * function ds_pre_cma::m_open_cma
 *
 * @param[in]   bool                bo_write        open cma for write access?
 * @return      bool                                true = success
*/
bool ds_pre_cma::m_open_cma( bool bo_write )
{
    // initialize some variables:
	 if(chr_cmaname[0] == 0)
		 return false;
#if SM_USE_PRECMA_CACHE
	 if(this->inc_len_pre_cma >= 0) {
		if (this->inc_len_pre_cma <  (int)sizeof(dsd_usercma_pre))
			return false;
		return true;
	 }
	 dsd_hl_aux_c_cma_1 dsl_cma;
	 bo_write = false;
#else
	 dsd_hl_aux_c_cma_1& dsl_cma = this->dsc_cma;
#endif
    //-----------------------------------------------
    // open cma:
    //-----------------------------------------------
	if(!adsc_wsp_helper->m_cb_open_cma2( &chr_cmaname[0], LEN_NOAUTH_COOKIE, &dsl_cma, bo_write))
		return false;

    //-----------------------------------------------
    // check return data:
    //-----------------------------------------------
	if (dsl_cma.inc_len_cma_area  <  (int)sizeof(dsd_usercma_pre)) {
#if SM_USE_PRECMA_CACHE
		adsc_wsp_helper->m_cb_close_cma2(&dsl_cma);
		this->ads_pre_cma = NULL;
		this->inc_len_pre_cma = 0;
#else
        m_close_cma();
#endif
		return false;
    }

    //-----------------------------------------------
    // initialize content pointer:
    //-----------------------------------------------
	dsd_usercma_pre* adsl_pre_cma = (dsd_usercma_pre*)dsl_cma.achc_cma_area;

    //-----------------------------------------------
    // compare total length with our length pointers:
    //-----------------------------------------------
    if (dsl_cma.inc_len_cma_area != (int)sizeof(dsd_usercma_pre)
                   + adsl_pre_cma->inc_len_username
                   + adsl_pre_cma->inc_len_password
                   + adsl_pre_cma->inc_len_domain
                   + adsl_pre_cma->inc_len_userdn
                   + adsl_pre_cma->inc_len_bpage
                   + adsl_pre_cma->inc_len_msg
                   + adsl_pre_cma->inc_len_radius_state ) {
#if SM_USE_PRECMA_CACHE
		adsc_wsp_helper->m_cb_close_cma2(&dsl_cma);
#else
        m_close_cma();
#endif
        return false;
    }
#if SM_USE_PRECMA_CACHE
	dsd_usercma_pre* adsl_pre_cma2 = (dsd_usercma_pre*)this->adsc_wsp_helper->m_cb_get_memory(dsl_cma.inc_len_cma_area, false);
	memcpy(adsl_pre_cma2, adsl_pre_cma, dsl_cma.inc_len_cma_area);
	adsc_wsp_helper->m_cb_close_cma2(&dsl_cma);
	this->ads_pre_cma = adsl_pre_cma2;
	this->inc_len_pre_cma = dsl_cma.inc_len_cma_area;
#else
	this->ads_pre_cma = adsl_pre_cma;
#endif
    //-----------------------------------------------
    // set string pointers:
    //-----------------------------------------------
    m_setup_strings();

    return true;
} // end of ds_pre_cma::m_open_cma


/**
 * function ds_pre_cma::m_resize_cma
 *
 * @param[in]   int                 in_size         new requested size
 * @return      bool                                true = success
*/
bool ds_pre_cma::m_resize_cma( int in_size )
{
#if SM_USE_PRECMA_CACHE
	if(this->inc_len_pre_cma == in_size)
		return true;
	dsd_usercma_pre* adsl_pre_cma2 = (dsd_usercma_pre*)this->adsc_wsp_helper->m_cb_get_memory(in_size, false);
	int inl_min = min(in_size, this->inc_len_pre_cma);
	memcpy(adsl_pre_cma2, this->ads_pre_cma, inl_min);
	if(this->ads_pre_cma != NULL)
		this->adsc_wsp_helper->m_cb_free_memory(this->ads_pre_cma, this->inc_len_pre_cma);
	this->ads_pre_cma = adsl_pre_cma2;
	this->inc_len_pre_cma = in_size;
	this->boc_cma_changed = true;
#else
	// initialize some variables:
    bool  bo_ret;                                   // return from resize

    // check if cma is opened already:
	if ( this->dsc_cma.ac_cma_handle == NULL ) {
        return false;
    }

    // do the resize:
    bo_ret = adsc_wsp_helper->m_cb_resize_cma2( &this->dsc_cma, in_size );
    if ( bo_ret == false ) {
        ads_pre_cma = NULL;
        return false;
    }

    // init return pointer:
	ads_pre_cma = (dsd_usercma_pre*)this->dsc_cma.achc_cma_area;
#endif
    return true;
} // end of ds_pre_cma::m_resize_cma


/**
 * function ds_pre_cma::m_close_cma
*/
bool ds_pre_cma::m_close_cma()
{
#if SM_USE_PRECMA_CACHE
	return true;
#else
	achc_username     = NULL;
    achc_password     = NULL;
    achc_domain       = NULL;
    achc_userdn       = NULL;
    achc_bpage        = NULL;
    achc_msg          = NULL;
    achc_radius_state = NULL;

    ads_pre_cma       = NULL;
	return adsc_wsp_helper->m_cb_close_cma2(&this->dsc_cma);
#endif
} // end of ds_pre_cma::m_close_cma

bool ds_pre_cma::m_commit() {
#if SM_USE_PRECMA_CACHE
	if(chr_cmaname[0] == 0)
		return true;
	if(this->inc_len_pre_cma < 0)
		return true;
	if(!this->boc_cma_changed)
		return true;
	dsd_hl_aux_c_cma_1 dsl_cma;
	if(!adsc_wsp_helper->m_cb_open_cma2( &chr_cmaname[0], LEN_NOAUTH_COOKIE, &dsl_cma, true))
		return false;
	// do the resize:
	bool bol_ret = adsc_wsp_helper->m_cb_resize_cma2(&dsl_cma, this->inc_len_pre_cma);
    if ( !bol_ret ) {
        goto LBL_CLOSE;
    }
	memcpy(dsl_cma.achc_cma_area, this->ads_pre_cma, this->inc_len_pre_cma);
LBL_CLOSE:
	adsc_wsp_helper->m_cb_close_cma2(&dsl_cma);
	if(this->ads_pre_cma != NULL)
		adsc_wsp_helper->m_cb_free_memory(this->ads_pre_cma, this->inc_len_pre_cma);
	this->ads_pre_cma = NULL;
	this->inc_len_pre_cma = -1;
	this->boc_cma_changed = false;
	return bol_ret;
#else
	return true;
#endif
}

/**
 * private function ds_pre_cma::m_setup_strings
*/
void ds_pre_cma::m_setup_strings()
{
    // initialize some variables:
    char* ach_data  = (char*)ads_pre_cma;
    int   in_offset = (int)sizeof(dsd_usercma_pre);

    if ( ads_pre_cma->inc_len_username > 0 ) {
        achc_username = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_username;

    if ( ads_pre_cma->inc_len_password > 0 ) {
        achc_password = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_password;

    if ( ads_pre_cma->inc_len_domain > 0 ) {
        achc_domain = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_domain;

	if ( ads_pre_cma->inc_len_userdn > 0 ) {
        achc_userdn = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_userdn;

    if ( ads_pre_cma->inc_len_bpage > 0 ) {
        achc_bpage = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_bpage;

    if ( ads_pre_cma->inc_len_msg > 0 ) {
        achc_msg = ach_data + in_offset;
    }
    in_offset += ads_pre_cma->inc_len_msg;

    if ( ads_pre_cma->inc_len_radius_state > 0 ) {
        achc_radius_state = ach_data + in_offset;
    }
} // end of ds_pre_cma::m_setup_strings


/**
 * private function ds_pre_cma::m_build_checksum
 * this algorithm is taken from 
 * http://www.cl.cam.ac.uk/research/srg/bluebook/21/crc/node6.html#SECTION00060000000000000000
 *
 * @param[in]   char*           ach_data        data to build checksum from
 * @param[in]   int             in_len          length of data
 * @return      unsigned int    checksum
*/
unsigned int ds_pre_cma::m_build_checksum( const char* ach_data, int in_len )
{
    // initialize some variables:
    unsigned int        uin_result;
    int                 in_pos;
    int                 in_bit;
    unsigned char       rch_octet;
    unsigned char*      auch_data = (unsigned char*)ach_data;
    
    if ( in_len < 4 ) {
        return 0;
    }

    uin_result  = *auch_data++ << 24;
    uin_result |= *auch_data++ << 16;
    uin_result |= *auch_data++ << 8;
    uin_result |= *auch_data++;
    uin_result  = ~ uin_result;
    in_len -=4;
    
    for ( in_pos = 0; in_pos < in_len; in_pos++ ) {
        rch_octet = *(auch_data++);
        for ( in_bit = 0; in_bit < 8; in_bit++ ) {
            if (uin_result & 0x80000000) {
                uin_result = (uin_result << 1) ^ DEF_CHS_QUOTIENT ^ (rch_octet >> 7);
            } else {
                uin_result = (uin_result << 1) ^ (rch_octet >> 7);
            }
            rch_octet <<= 1;
        }
    }
    
    return ~uin_result; // the complement of the remainder
} // end of ds_pre_cma::m_build_checksum
