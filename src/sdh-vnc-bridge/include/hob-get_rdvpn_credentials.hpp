#pragma once
#ifndef __HOB_GET_RDVPN_CREDENTIALS__
#define __HOB_GET_RDVPN_CREDENTIALS__

// Code, gotten from Mr. Jacobs, 08.02.2012
#include <rdvpn_globals.h>

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
        time_t          tmc_login;                      // login time
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
         || dsl_ident.imc_len_userfld  != sizeof(dsd_aux_ident_session_info) ) {           /* wrong session    */
        return FALSE;
    }

	 dsd_aux_ident_session_info* adsl_aux_ident_session_info = (dsd_aux_ident_session_info*)dsl_ident.achc_userfld;

    /*
        create name of user cma
    */
    inl_len = m_create_cma_name( (char*)DSL_USER.ac_str, DSL_USER.imc_len_str,
                                 (char*)DSL_GROUP.ac_str, DSL_GROUP.imc_len_str,
                                 adsl_aux_ident_session_info->ucc_session_no, chrl_buffer, D_MAXCMA_NAME );
#undef DSL_USER
#undef DSL_GROUP
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

static BOOL m_release_user_credentials( struct dsd_hl_clib_1 *adsp_clib1,
                                        struct dsd_unicode_string *adsp_userid,
                                        struct dsd_unicode_string *adsp_group,
                                        struct dsd_unicode_string *adsp_password ){

   BOOL bol_ret; 
   if(!adsp_clib1->amc_aux( adsp_clib1->vpc_userfld, DEF_AUX_MEMFREE, &adsp_userid->ac_str, 0))
      return FALSE;
   adsp_userid->imc_len_str = 0;
   if(!adsp_clib1->amc_aux( adsp_clib1->vpc_userfld, DEF_AUX_MEMFREE, &adsp_group->ac_str, 0))
      return FALSE;
   adsp_group->imc_len_str = 0;
   if(!adsp_clib1->amc_aux( adsp_clib1->vpc_userfld, DEF_AUX_MEMFREE, &adsp_password->ac_str, 0))
      return FALSE;
   adsp_password->imc_len_str = 0;

   return TRUE;
}

#endif