/*+-------------------------------------------------------------------------+*/
/*| includes:                                                               |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_session.h"
#include <auth_callback.h>

/*+-------------------------------------------------------------------------+*/
/*| function declarations:                                                  |*/
/*+-------------------------------------------------------------------------+*/
static bool m_parse_lang( ds_session* ads_session, dsd_acb_language* ads_lang );
static bool m_get_lang  ( ds_session* ads_session, dsd_acb_language* ads_lang );

/*+-------------------------------------------------------------------------+*/
/*| "public" functions:                                                     |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Callback function for authentication library
 *
 * @ingroup authentication
 *
 * public function m_auth_callback
 * callback function for authentication library
 *
 * @param[in]   void*   av_session              pointer to our session class
 * @param[in]   int     in_mode                 workmode
 * @param[in]   void*   av_param                pointer to calling parameter
 * @param[in]   int     in_param_len            length of calling parameter
 * @return      int                             0 = success
*/
int m_auth_callback( void* av_session, int in_mode, void* av_param, int in_param_len )
{
    // initialize some variables:
    ds_session* adsl_session;                   // session class
    bool        bol_ret;                        // return for several function calls


    //-------------------------------------------
    // get session class:
    //-------------------------------------------
    adsl_session = (ds_session*)av_session;
    if ( adsl_session == NULL ) {
        return -1;
    }

    switch ( in_mode ) {
        /*
            parse language
        */
        case DEF_AUTH_CB_PARSE_LANG:
            if (    av_param     == NULL
                 || in_param_len != (int)sizeof(struct dsd_acb_language) ) {
                return -1;
            }
            bol_ret = m_parse_lang( adsl_session, (dsd_acb_language*)av_param );
            if ( bol_ret == false ) {
                return -1;
            }
            break;

        /*
            get language name
        */
        case DEF_AUTH_CB_GET_LANG:
            if (    av_param     == NULL
                 || in_param_len != (int)sizeof(struct dsd_acb_language) ) {
                return -1;
            }
            bol_ret = m_get_lang( adsl_session, (dsd_acb_language*)av_param );
            if ( bol_ret == false ) {
                return -1;
            }
            break;

        /*
            unknown mode
        */
        default:
            return -1;
    }

    return 0;
} // end of m_auth_callback


/*+-------------------------------------------------------------------------+*/
/*| "private" functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/
/**
 * private function m_parse_lang
 * parse given language string
 *
 * @param[in]   ds_session*         ads_session pointer to our session class
 * @param[in]   dsd_acb_language*   ads_lang    language structure pointer
 * @return      bool                            true = success
*/
static bool m_parse_lang( ds_session* ads_session, dsd_acb_language* ads_lang )
{
    // initialize some variables:
    const ds_resource*    adsl_resource;              // resource class

    //-------------------------------------------
    // get resource class:
    //-------------------------------------------
    adsl_resource = ((ds_resource*)(ads_session->ads_config->av_resource));
    if ( adsl_resource == NULL ) {
        return false;
    }

    //-------------------------------------------
    // parse language:
    //-------------------------------------------
    ads_lang->inc_key = adsl_resource->m_parse_lang( ads_lang->achc_lang,
                                                     ads_lang->inc_len_lang );
    return true;
} // end of m_parse_lang


/**
 * private function m_get_lang
 * get language name by its key
 *
 * @param[in]   ds_session*         ads_session pointer to our session class
 * @param[in]   dsd_acb_language*   ads_lang    language structure pointer
 * @return      bool                            true = success
*/
static bool m_get_lang( ds_session* ads_session, dsd_acb_language* ads_lang )
{
    // initialize some variables:
    ds_resource*    adsl_resource;              // resource class

    //-------------------------------------------
    // get resource class:
    //-------------------------------------------
    adsl_resource = ((ds_resource*)(ads_session->ads_config->av_resource));
    if ( adsl_resource == NULL ) {
        return false;
    }

    //-------------------------------------------
    // get language name:
    //-------------------------------------------
    return adsl_resource->m_get_lang( ads_lang->inc_key,
                                      &ads_lang->achc_lang,
                                      &ads_lang->inc_len_lang );
} // end of m_get_lang
