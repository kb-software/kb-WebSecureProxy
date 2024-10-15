/*+---------------------------------------------------------------------------------------------------------+*/
/*|                                                                                                         |*/
/*| Program:                                                                                                |*/
/*| ========                                                                                                |*/
/*|   sdh_ea_ldap                                                                                           |*/
/*|   SDH to convert protocol data in EA-format to LDAP format                                              |*/
/*|                                                                                                         |*/
/*| Author:                                                                                                 |*/
/*| =======                                                                                                 |*/
/*|   Joachim Frank, 2010/03/26                                                                             |*/
/*|                                                                                                         |*/
/*| Copyright:                                                                                              |*/
/*| ==========                                                                                              |*/
/*|   HOB GmbH 2010                                                                                         |*/
/*|                                                                                                         |*/
/*|                                                                                                         |*/
/*| Version:                                                                                                |*/
/*| ========                                                                                                |*/
/*|   2.3.0.16 AKre     18.06.12    1) set ACIs for domains under dc=root (ldap server == opends)           |*/
/*|                                 2) add a domain administrator group in this domain                      |*/
/*|                                    ( depending on the entry in the                                      |*/
/*|                                      config-section <domainadministrator-group> )                       |*/
/*|                                 3) add additional rights for users in this group                        |*/
/*|   2.3.0.15 MJ       21.02.12    due to some changes in LDAP modul, we had to change the fallback bind   |*/
/*|   2.3.0.14 AKre     21.02.12    replaced hstrc_bind_dn by hstrc_real_user_dn for the                    |*/
/*|   2.3.0.13 MJ       12.02.12    added password reset for admin users in openDS                          |*/
/*|   2.3.0.12 AKre     19.01.12    Multiple changes in LDAP bind:                                          |*/
/*|     ...                          * We are not using the "searchAdmin" for more things as needed         |*/
/*|                                  * therefor we have introduced a DomainAdmin which should be used in    |*/
/*|                                    cases where authentication method is not storage ldap                |*/
/*                                   * added a admin-group, which is allowed to configure the whole domain  |*/
/*|   2.3.0.7  J.Frank  11.02.11    1) Writing to attribute "aci" is prohibited.                            |*/
/*|                                 2) Method ds_ea_ldap::m_write_attributes centralizes all writing.       |*/
/*|   2.3.0.6  J.Frank  07.12.10    Return tag 'eatype' at connect. It signals to the client, to which type |*/
/*|                                 of EA Server it is connected. In case of real EA Server this value is 0 |*/
/*|                                 (default). In case of sdh_ea_ldap (simulated EA Server) this value is 1.|*/
/*|   2.3.0.5  J.Frank  30.11.10    Wish of E.Galea: Return the session ticket instead of the password in   |*/
/*|                                 the connect-PNode.                                                      |*/
/*|                     26.11.10    If we want to delete an attribute, which does not exist, LDAP responds  |*/
/*|                                 a NoSuchAttributeError. Ignore it and go on.                            |*/
/*|   2.3.0.4  J.Frank  20.10.10    When in mode ied_auth_user (up to now we are ALWAYS in this mode), then |*/
/*|                                 ensure, that users write only to their own DN.                          |*/
/*|   2.3.0.3  J.Frank  02.06.10    Saving to multi-valued attributes now works.                            |*/
/*|   2.3.0.1  J.Frank  16.04.10    First proto type.                                                       |*/
/*+---------------------------------------------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------------------------------------------+*/
/*| defines:                                                                                                |*/
/*+---------------------------------------------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------------------------------------------+*/
/*| includes:                                                                                               |*/
/*+---------------------------------------------------------------------------------------------------------+*/
#ifdef HL_UNIX
#else // windows
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "sdh_ea_ldap.h"
#include "./config/ds_config.h"
#include "ds_ea_ldap.h"
#include <limits.h>
#include <hob-libwspat.h>

//#define TRACE_SDH_EALD
#ifdef TRACE_SDH_EALD
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achptext, ... );

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};
#endif
/*+---------------------------------------------------------------------+*/
/*| dll start functions:                                                |*/
/*+---------------------------------------------------------------------+*/
/**
 * function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf* ads_conf )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( ads_conf == NULL ) {
        printf("HEALDE001E: ads_conf == NULL\n");
        return FALSE;
    }
#endif

    // initialize some variables:
    bool          bo_ret;
    ds_wsp_helper dsc_wsp_helper;
    ds_config     dsc_config( &dsc_wsp_helper );
    dsc_wsp_helper.m_init_conf( ads_conf );

    //-----------------------------------------
    // print startup message:
    //-----------------------------------------
    dsc_wsp_helper.m_cb_printf_out( "HEALDI%03dI %s V%s initialized", 1, SDH_LONGNAME, SDH_VERSION_STRING );

    //-----------------------------------------
    // read and save configuration section:
    //-----------------------------------------
    bo_ret = dsc_config.m_read_config();
    if ( bo_ret == false ) {
        dsc_wsp_helper.m_log(ied_sdh_log_error, "HEALDE006E: error while reading config - fallback to default" );
    }
    bo_ret = dsc_config.m_save_config();

    return (bo_ret == true) ? TRUE : FALSE;
} // end of m_hlclib_conf


#if 0

#ifndef D_MAXCMA_NAME
    #ifndef DEF_MAX_LEN_CMA_NAME        // wsp/include/hob-wspsu1.h
        #define D_MAXCMA_NAME 128
    #else
        #define D_MAXCMA_NAME DEF_MAX_LEN_CMA_NAME
    #endif
#endif

#ifndef LEN_SESSTICKET
    #define LEN_SESSTICKET          32

    struct dsd_usercma_login {
        hl_time_t       tmc_login;                      // login time
        bool            boc_anonymous;                  // is anonymous user
        int             inc_auth_method;                // used method for authentication
        char            chc_session;                    // session number
        int             inc_pwd_expires;                // password expires in x days
        int             inc_len_username;               // length of username
        int             inc_len_userdomain;             // length of userdomain
        int             inc_len_password;               // length of password
        int             inc_len_userdn;                 // length of userdn
        int             inc_len_wspgroup;               // length of wsp userdomain
        int             inc_len_role;                   // length of assigned role
        char            chr_sticket[LEN_SESSTICKET];    // session ticket
        dsd_aux_query_client dsc_client;                // client information
    };
#endif
#ifndef USERCMA_LOGIN_SUFFIX
    #define USERCMA_LOGIN_SUFFIX    "/lgn"
#endif
#ifndef USERCMA_NAME_PREFIX
    #define USERCMA_NAME_PREFIX     "usr"
#endif

/**
 * private method m_create_cma_name
 *
 * @param[in]   const char  *achp_user      username
 * @param[in]   int         inp_ulen        length of username
 * @param[in]   const char  *achp_group     groupname
 * @param[in]   int         inp_glen        length of groupname
 * @param[in]   char        chp_session     session number
 * @param[out]  char        *achp_buffer    buffer to be filled
 * @param[in]   int         inp_blen        length of output buffer
 * @return      int                         needed length of buffer
*/
static int m_create_cma_name( const char *achp_user, int inp_ulen,
                              const char *achp_group, int inp_glen,
                              char chp_session,
                              char *achp_buffer, int inp_blen )
{
    int inl_pos;
    int inl_count;

    /*
        login cma name will look like this:

        +-----+---+------...-+---+---------...-+---+----------------+---+-----+
        | usr | / | group    | / | username    | / | session number | / | lgn |
        +-----+---+------...-+---+---------...-+---+----------------+---+-----+
        |  3  | 1 | variable | 1 | variable    | 1 |        1       | 1 |  3  |
    */

    // check minimal length
    inl_pos = (int)sizeof(USERCMA_NAME_PREFIX) - 1;
    if ( inp_blen <   inl_pos  + 1  /* prefix /     */
                    + inp_glen + 1  /* group  /     */
                    + inp_ulen + 1  /* user   /     */
                    + 1             /* session      */
                    + 4             /* login suffix */ ) {
        return -1;
    }

    memcpy( achp_buffer, USERCMA_NAME_PREFIX, inl_pos );
    achp_buffer[inl_pos] = '/';
    inl_pos++;

    if ( inp_glen > 0 ) {
        memcpy( &achp_buffer[inl_pos], achp_group, inp_glen );
        inl_pos += inp_glen;
        achp_buffer[inl_pos] = '/';
        inl_pos++;
    }

    for ( inl_count = 0; inl_count < inp_ulen; inl_count++ ) {
        achp_buffer[inl_pos] = (char)tolower( achp_user[inl_count] );
        inl_pos++;
    }
    achp_buffer[inl_pos] = '/';
    inl_pos++;

    achp_buffer[inl_pos] = chp_session;
    inl_pos++;

    memcpy( &achp_buffer[inl_pos], USERCMA_LOGIN_SUFFIX,
            sizeof(USERCMA_LOGIN_SUFFIX) - 1 );
    inl_pos += (int)sizeof(USERCMA_LOGIN_SUFFIX) - 1;

    return inl_pos;
} /* end of m_create_cma_name */


/**
 * private method m_get_user_credentials
 *
 * @param[in]   dsd_hl_clib1        *adsp_clib1     sdh calling structure
 * @param[out]  dsd_unicode_string  *adsp_userid    user id
 * @param[out]  dsd_unicode_string  *adsp_group     user group
 * @param[out]  dsd_unicode_string  *adsp_password  user password
 * @return      BOOL                                TRUE = success
 *                                                  FALSE otherwise
*/
static BOOL m_get_user_credentials( struct dsd_hl_clib_1 *adsp_clib1,
                                    struct dsd_unicode_string *adsp_userid,
                                    struct dsd_unicode_string *adsp_group,
                                    struct dsd_unicode_string *adsp_password )
{
    BOOL                        bol_ret;        /* return for aux calls  */
    struct dsd_sdh_ident_set_1  dsl_ident;      /* get ident structure   */
    char            chrl_buffer[D_MAXCMA_NAME]; /* cma name with max len */
    int                         inl_len;        /* length cma name       */
    struct dsd_hl_aux_c_cma_1   dsl_cma;        /* cma request           */
    struct dsd_usercma_login    *adsl_lgn_cma;  /* cma content           */

    /*
        get user ident from wsp tcp connection
    */
#define DSL_USER    (dsl_ident.dsc_userid)
#define DSL_GROUP   (dsl_ident.dsc_user_group)
#define CHL_SESSION (dsl_ident.achc_userfld[0])

    memset( &DSL_USER,  0, sizeof(struct dsd_unicode_string) );
    memset( &DSL_GROUP, 0, sizeof(struct dsd_unicode_string) );
    dsl_ident.achc_userfld    = NULL;
    dsl_ident.imc_len_userfld = 0;

    bol_ret = adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                                   DEF_AUX_GET_IDENT_SETTINGS, &dsl_ident,
                                   sizeof(struct dsd_sdh_ident_set_1) );
    if (    bol_ret                    == FALSE           /* error while call */
         || DSL_USER.imc_len_str        < 1               /* no user name     */
         || DSL_USER.iec_chs_str       != ied_chs_utf_8   /* invalid encoding */
         || (    DSL_GROUP.imc_len_str  > 0
              && DSL_GROUP.iec_chs_str != ied_chs_utf_8 ) /* invalid encoding */
         || dsl_ident.imc_len_userfld  != 1 ) {           /* wrong session    */
        return FALSE;
    }


    /*
        create name of user cma
    */
    inl_len = m_create_cma_name( (char*)DSL_USER.ac_str, DSL_USER.imc_len_str,
                                 (char*)DSL_GROUP.ac_str, DSL_GROUP.imc_len_str,
                                 CHL_SESSION, chrl_buffer, D_MAXCMA_NAME );
#undef DSL_USER
#undef DSL_GROUP
#undef CHL_SESSION
    if ( inl_len < 1 ) {
        return FALSE;
    }

    /*
        open user cma for reading
    */
    memset( &dsl_cma, 0, sizeof(struct dsd_hl_aux_c_cma_1) );
    dsl_cma.ac_cma_name      = chrl_buffer;
    dsl_cma.inc_len_cma_name = inl_len;
    dsl_cma.iec_chs_name     = ied_chs_utf_8;
    dsl_cma.iec_ccma_def     = ied_ccma_lock_global;
    dsl_cma.imc_lock_type    = D_CMA_READ_DATA | D_CMA_SHARE_READ;

    bol_ret = adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                                   DEF_AUX_COM_CMA, &dsl_cma,
                                   sizeof(struct dsd_hl_aux_c_cma_1) );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }

    if (    dsl_cma.achc_cma_area    == NULL
         || dsl_cma.inc_len_cma_area <  (int)sizeof(struct dsd_usercma_login) ) {
        /* close cma again */
        dsl_cma.iec_ccma_def = ied_ccma_lock_release;
        adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                             DEF_AUX_COM_CMA, &dsl_cma,
                             sizeof(struct dsd_hl_aux_c_cma_1) );
        return FALSE;
    }

    adsl_lgn_cma = (struct dsd_usercma_login*)dsl_cma.achc_cma_area;
    if ( dsl_cma.inc_len_cma_area !=   (int)sizeof(struct dsd_usercma_login)
                                     + adsl_lgn_cma->inc_len_username
                                     + adsl_lgn_cma->inc_len_userdomain
                                     + adsl_lgn_cma->inc_len_password
                                     + adsl_lgn_cma->inc_len_userdn
                                     + adsl_lgn_cma->inc_len_wspgroup
                                     + adsl_lgn_cma->inc_len_role ) {
        /* close cma again */
        dsl_cma.iec_ccma_def = ied_ccma_lock_release;
        adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                             DEF_AUX_COM_CMA, &dsl_cma,
                             sizeof(struct dsd_hl_aux_c_cma_1) );
        return FALSE;
    }

    /* init output structures */
    if ( adsp_userid ) {
        adsp_userid->imc_len_str = 0;
    }
    if ( adsp_group ) {
        adsp_group->imc_len_str = 0;
    }
    if ( adsp_password ) {
        adsp_password->imc_len_str = 0;
    }

    /* copy data to our memory */
    if (    adsp_userid
         && adsl_lgn_cma->inc_len_username > 0 ) {
        bol_ret = adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                                       DEF_AUX_MEMGET, &adsp_userid->ac_str,
                                       adsl_lgn_cma->inc_len_username );
        if ( bol_ret == TRUE ) {
            adsp_userid->iec_chs_str = ied_chs_utf_8;
            adsp_userid->imc_len_str = adsl_lgn_cma->inc_len_username;
            memcpy( adsp_userid->ac_str,
                    (char*)(adsl_lgn_cma + 1),
                    adsl_lgn_cma->inc_len_username );
        }
    }
    if (    adsp_group
         && adsl_lgn_cma->inc_len_userdomain > 0 ) {
        bol_ret = adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                                       DEF_AUX_MEMGET, &adsp_group->ac_str,
                                       adsl_lgn_cma->inc_len_userdomain );
        if ( bol_ret == TRUE ) {
            adsp_group->iec_chs_str = ied_chs_utf_8;
            adsp_group->imc_len_str = adsl_lgn_cma->inc_len_userdomain;
            memcpy( adsp_group->ac_str,
                      (char*)(adsl_lgn_cma + 1)
                    + adsl_lgn_cma->inc_len_username,
                    adsl_lgn_cma->inc_len_userdomain );
        }
    }
    if (    adsp_password
         && adsl_lgn_cma->inc_len_password > 0 ) {
        bol_ret = adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                                       DEF_AUX_MEMGET, &adsp_password->ac_str,
                                       adsl_lgn_cma->inc_len_password );
        if ( bol_ret == TRUE ) {
            adsp_password->iec_chs_str = ied_chs_utf_8;
            adsp_password->imc_len_str = adsl_lgn_cma->inc_len_password;
            memcpy( adsp_password->ac_str,
                      (char*)(adsl_lgn_cma + 1)
                    + adsl_lgn_cma->inc_len_username
                    + adsl_lgn_cma->inc_len_userdomain,
                    adsl_lgn_cma->inc_len_password );
        }
    }

    /* close cma again */
    dsl_cma.iec_ccma_def = ied_ccma_lock_release;
    adsp_clib1->amc_aux( adsp_clib1->vpc_userfld,
                         DEF_AUX_COM_CMA, &dsl_cma,
                         sizeof(struct dsd_hl_aux_c_cma_1) );
    return TRUE;
}
#endif

/**
 * function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1*    ads_trans
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1* ads_trans )
{
#ifdef _DEBUG
    // check incoming parameter:
    if ( ads_trans == NULL ) {
        printf("HEALDE002E: ads_trans == NULL\n");
        return;
    }
#endif

    // initialize some variables:
    //bool                   bo_ret;
    int in_ret;
#ifdef _DEBUG
    int                    in_locks;
#endif // _DEBUG
    class  ds_wsp_helper   dsc_wsp_helper;
    class  ds_ea_ldap*     ads_ea_ldap = (ds_ea_ldap*)ads_trans->ac_ext;
    struct dsd_ea_config*  ads_config  = (dsd_ea_config*)ads_trans->ac_conf;
    dsc_wsp_helper.m_init_trans( ads_trans );

    if ( ads_config == NULL ) {
        dsc_wsp_helper.m_log(ied_sdh_log_error, "HEALDE008E: config pointer == NULL" );
        dsc_wsp_helper.m_return_error();
        return;
    }

    if (ads_ea_ldap != NULL) {
        // init storage container: MJ 10.03.2010
        dsc_wsp_helper.m_use_storage( &(ads_ea_ldap->av_storage), SDH_STORAGE_SIZE );
        // init main session class:
        ads_ea_ldap->m_init(&dsc_wsp_helper);
    }

#ifdef TRACE_SDH_EALD
        dsd_sdh_call_1 dsl_sdh_call_1;
        dsl_sdh_call_1.amc_aux     = ads_trans->amc_aux;
        dsl_sdh_call_1.vpc_userfld = ads_trans->vpc_userfld;

        m_sdh_printf( &dsl_sdh_call_1, "SDH-EALDAP: in working function m_hlclib01, inc_func=%d\n", ads_trans->inc_func);
#endif
    switch ( ads_trans->inc_func ) {

        //-----------------------------------------
        // start session:
        //-----------------------------------------
        case DEF_IFUNC_START: {
            // get memory for our working class
            // and put in ac_ext pointer -> we will get it again on every call
            ads_trans->ac_ext = dsc_wsp_helper.m_cb_get_memory( sizeof(ds_ea_ldap), true );
            if ( ads_trans->ac_ext == NULL ) {
                dsc_wsp_helper.m_log(ied_sdh_log_error, "HEALDE003E: cannot get session memory" );
                dsc_wsp_helper.m_return_error();
                return;
            }

            // setup our main working class:
            ads_ea_ldap = new(ads_trans->ac_ext) ds_ea_ldap();

            // setup storage container:
            dsc_wsp_helper.m_use_storage( &(ads_ea_ldap->av_storage), SDH_STORAGE_SIZE );

            // log start of connection:
            dsc_wsp_helper.m_log_input();

            dsd_wspat_pconf_t* adsl_wspat_config = dsc_wsp_helper.m_get_wspat_config();
            /* read configuration from disk   */
            dsd_sdh_ident_set_1 dsl_g_idset1;
            memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );
            ads_trans->amc_aux( ads_trans->vpc_userfld,
                                          DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                          &dsl_g_idset1,
                                          sizeof(struct dsd_sdh_ident_set_1) );
            break;
        }
        //-----------------------------------------
        // end session:
        //-----------------------------------------
        case DEF_IFUNC_CLOSE:
            // check our class pointer
            if ( ads_ea_ldap == NULL ) {
                dsc_wsp_helper.m_log(ied_sdh_log_warning, "HEALDW019W: session pointer is null" );
                return;
            }
            // log end of connection:
            dsc_wsp_helper.m_log_output();

            // call destructor for our working class:
            ads_ea_ldap->ds_ea_ldap::~ds_ea_ldap();

            // clear storage container:
            dsc_wsp_helper.m_no_storage( &(ads_ea_ldap->av_storage) );

            // free working class memory:
            dsc_wsp_helper.m_cb_free_memory( (char*)ads_trans->ac_ext, sizeof(ds_ea_ldap) );

            break;

        //-----------------------------------------
        // working session modes:
        //-----------------------------------------
        // JF do not support: case DEF_IFUNC_CONT:
        case DEF_IFUNC_FROMSERVER:
			// check our class pointer
            if ( ads_ea_ldap == NULL ) {
                dsc_wsp_helper.m_log(ied_sdh_log_warning, "HEALDW019W: session pointer is null" );
                return;
            }
            ads_ea_ldap->m_recv_msg_from_mgmt();
            break;
        case DEF_IFUNC_TOSERVER:
			// check our class pointer
            if ( ads_ea_ldap == NULL ) {
                dsc_wsp_helper.m_log(ied_sdh_log_warning, "HEALDW019W: session pointer is null" );
                return;
            }
#define ADSL_INPUT (ads_trans->adsc_gather_i_1_in)
            if (    ADSL_INPUT                == NULL
                 || ADSL_INPUT->achc_ginp_end <= ADSL_INPUT->achc_ginp_cur ) {
				ads_ea_ldap->m_send_msg_to_mgmt();
                ads_ea_ldap->boc_callagain = FALSE;
				break;
            }
#undef ADSL_INPUT

        case DEF_IFUNC_REFLECT:
            // check our class pointer
            if ( ads_ea_ldap == NULL ) {
                dsc_wsp_helper.m_log(ied_sdh_log_warning, "HEALDW020W: session pointer is null" );
                dsc_wsp_helper.m_return_close();
                return;
            }
            if ( ads_ea_ldap->boc_callagain == FALSE ) {
            in_ret = ads_ea_ldap->m_run();
            if ( in_ret != 0 ) {
                dsc_wsp_helper.m_log(ied_sdh_log_warning, "HEALDW021W: working class returned error " );
            }
                ads_ea_ldap->boc_callagain = ads_trans->boc_callagain;
            } else {
                ads_ea_ldap->m_send_msg_to_mgmt();
                ads_ea_ldap->boc_callagain = FALSE;
            }
            break;

        //-----------------------------------------
        // unknown session modes:
        //-----------------------------------------
        default:
            dsc_wsp_helper.m_cb_printf_out("HEALDW022W: %s: %d", "unsupported inc_func selected", ads_trans->inc_func);

            dsc_wsp_helper.m_return_close();
            break;

    } // end of switch ( ads_trans->inc_func )

#ifdef _DEBUG
    in_locks = dsc_wsp_helper.m_count_cma_lock();
    if ( in_locks > 0 ) {
        dsc_wsp_helper.m_cb_printf_out( "Number of CMA-LOCKS = %d\n", in_locks );
        //dsd_unicode_string* ads_crash = NULL;
        //ads_crash->ac_str = NULL;
    }
#endif

    return;
} // end of m_hlclib01

#ifdef TRACE_SDH_EALD
/* subroutine for output to console                                    */
static int m_sdh_printf( struct dsd_sdh_call_1* ads_trans, char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*ads_trans->amc_aux)( ads_trans->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf() */
#endif