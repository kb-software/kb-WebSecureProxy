/*+---------------------------------------------------------------------+*/
/*| global includes:                                                    |*/
/*+---------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <hob-libwspat.h>
#include <align.h>
#include <time.h>
#ifdef HL_UNIX
#include <ctype.h>
#define sprintf_s snprintf
    #define min(a,b) (((a) < (b)) ? (a) : (b))
    #define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>
#include <ds_workstation.h>
#include <ds_portlet.h>
#include <ds_jwtsa_conf.h>
#include <ds_hobte_conf.h>
#include <ds_wsp_admin.h>
#include <ds_usercma.h>
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SM_USE_CMA_ITERATOR      1
#define SM_USE_MAIN_CMA_ONLY     1
#define SM_AUTHENTICATE_CASE_SENSITIVE2	1

#define LEN_SESSTICKET          HL_RDVPN_LEN_SESSTICKET
#define DEF_CHS_QUOTIENT        0x04c11db7
#define DEF_LEN_B64CS            8
#define USERCMA_VERSION          9
#define LEN_SUPR_SSO            30
#define DEF_INETA_GROUP_PPP      0
#define DEF_INETA_GROUP_HTCP     1

#define USERCMA_LOGIN_SUFFIX    "/lgn"
#define USERCMA_SETTING_SUFFIX  "/set"
#define USERCMA_WSG_SUFFIX      "/wsg"
#define USERCMA_INETA_SUFFIX    "/ips"
#define USERCMA_ROLES_SUFFIX    "/rls"
#define USERCMA_AXSS_SUFFIX     "/axss"
#define USERCMA_SID_SUFFIX      "/sid"

/*
    15.03.2010 
        I have seen a place inside KBs code (xslnetw1.cpp, line 223), where he
        is not aligning the "struct dsd_ineta_single_1" structures.
        I have asked KB if this is correct, he told me thats this is correct 
        (even on funny UNIX machines).
        I decided to keep the code thats aligns my data, but set a define to
        disable this code.
*/
#define DEF_DONT_ALIGN_SINGLE   1       // so comment above

/*+---------------------------------------------------------------------+*/
/*| declarations:                                                       |*/
/*+---------------------------------------------------------------------+*/

/*! \brief session ticket checksum
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_sticket_cs {
    union {
        unsigned int uinc_checksum;
        char         chrc_checksum[sizeof(unsigned int)];
    };
    char         chc_session;
};

/*+---------------------------------------------------------------------+*/
/*| cma content structs:                                                |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Status information about a connected user
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_usercma_main {
    int          inc_version;       //!< internal version number
    int          inc_state;         //!< status variable
    int          inc_port;          //!< listen port where user has connected to
    hl_time_t       tmc_laction;       //!< last action timestamp
    unsigned int uinc_msg_url;      //!< hash of message url
    int          inc_msg_type;      //!< message type
    int          inc_msg_code;      //!< message code
    int          inc_len_message;   //!< length of message
    int          inc_len_bpage;     //!< length of bookedpage
};


/*! \brief Authentication Details
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_usercma_login {
    hl_time_t          tmc_login;                      //!< login time
    ied_usercma_login_flags iec_auth_flags;         //!< flags
    int             inc_auth_method;                //!< used method for authentication
    dsd_cma_session_no chc_session;                    //!< session number
    int             inc_pwd_expires;                //!< password expires in x days
    int             inc_len_username;               //!< length of username
    int             inc_len_userdomain;             //!< length of userdomain
    int             inc_len_password;               //!< length of password
    int             inc_len_userdn;                 //!< length of userdn
    int             inc_len_wspgroup;               //!< length of wsp userdomain
    int             inc_len_role;                   //!< length of assigned role
    char            chr_sticket[LEN_SESSTICKET];    //!< session ticket
    dsd_aux_query_client dsc_client;                //!< client information
};


/*! \brief Bookmark structure
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_cma_wsg_bmark {
    bool boc_is_own;                //!< is bookmark of current user
    int  inc_len_name;              //!< length of name
    int  inc_len_url;               //!< length of url
};

/*! \brief WebFileAccess bookmark
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_cma_wfa_bmark {
    bool boc_is_own;                //!< is bookmark of current user
    int  inc_len_name;              //!< length of name
    int  inc_len_url;               //!< length of url
    int  inc_len_user;              //!< length of userid
    int  inc_len_pwd;               //!< length of password
    int  inc_len_domain;            //!< length of domain
};


/*! \brief Keeps Information about a workstation
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_cma_workstation {
    int           inc_len_name;     //!< length of name
    int           inc_len_ineta;    //!< length of ineta
    unsigned char chrc_mac[6];      //!< mac address
    int           inc_port;         //!< port
    int           inc_wait;         //!< wait connect
};


/*! \brief Portlet informations
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_cma_portlet {
    bool boc_open;                  //!< is portlet open?
    int  inc_len_name;              //!< length of name
};

/*! \brief Structure for storing a jwtsa config name in the CMA
 *
 * \ingroup authlib
 */
struct dsd_cma_jwtsaconf
{
	int			inc_len_name;		/*!< length of the name, which is in the memory behind this structure */
};

#if BO_HOBTE_CONFIG
struct dsd_cma_hobteconf
{
	int			inc_len_name;		/*!< length of the name, which is in the memory behind this structure */
    ied_webterm_subprotocol iec_subprotocol;
};
#endif

/*! \brief Keeps track of user specific settings
 *
 * \ingroup authlib
 *
 * user settings cma looks like this:
 *
 *     +----------------------+ ...
 *     | dsd_usercma_settings |
 *     +----------------------+ ...
 *     | size of struct       |
 *
 * ... +--------------------------+ ...
 *     | user message             |
 * ... +--------------------------+ ...
 *     | inc_len_umsg             |
 *
 * ... +--------------------------+ ...
 *     | default portlet name     |
 * ... +--------------------------+ ...
 *     | inc_len_default_portlet  |
 *
 *     |  inc_ws_bookmarks = inc_wsg_bookmarks + inc_rdvpn_bookmarks  times          |
 * ... +- ... -+------------------+- ... -+- ... -+ ...
 *     | ALIGN | dsd_cma_wsg_bmark | name | url   |
 * ... +- ... -+------------------+- ... -+- ... -+ ...
 *     |  0-7  | size of struct   |  from struct  |
 *
 *     |         inc_wfa_bookmarks times          |
 * ... +- ... -+------------------+- ... -+- ... -+ ...
 *     | ALIGN | dsd_cma_wfa_bmark | name | url   |
 * ... +- ... -+------------------+- ... -+- ... -+ ...
 *     |  0-7  | size of struct   |  from struct  |
 *
 *     |         inc_workstations times              |
 * ... +- ... -+---------------------+- ... -+- ... -+ ...
 *     | ALIGN | dsd_cma_workstation | name  | ineta |
 * ... +- ... -+---------------------+- ... -+- ... -+ ...
 *     |  0-7  | size of struct      |  from struct  |
 *
 *     |         inc_portlets times     |
 * ... +- ... -+----------------+- ... -+
 *     | ALIGN | dsd_cma_porlet | name  |
 * ... +- ... -+----------------+- ... -+
 *     |  0-7  | size of struct |       |
 *
 *     |         inc_hobte_confs times     |
 * ... +- ... -+-------------------+- ... -+
 *     | ALIGN | dsd_cma_hobteconf | name  |
 * ... +- ... -+-------------------+- ... -+
 *     |  0-7  | size of struct    |       |
 *
 *     |         inc_jwtsa_confs times     |
 * ... +- ... -+-------------------+- ... -+
 *     | ALIGN | dsd_cma_jwtsaconf | name  |
 * ... +- ... -+-------------------+- ... -+
 *     |  0-7  | size of struct    |       |
 */
struct dsd_usercma_settings {
    int                         inc_lang;               //!< selected language
    bool                        boc_flyer;              //!< show flyer
    int                         inc_len_umsg;           //!< length of following user message
    int                         inc_len_default_portlet;//!< length of following default portlet name
    int                         inc_ws_bookmarks;       //!< number of following WSG+RDVPN bookmarks
    int                         inc_wsg_bookmarks;      //!< number of WSG bookmarks
    int                         inc_rdvpn_bookmarks;    //!< number of RDVPN (user portal) bookmarks
    int                         inc_wfa_bookmarks;      //!< number of following WFA bookmarks
    int                         inc_workstations;       //!< number of following workstations
    int                         inc_portlets;           //!< number of following portlets
#if BO_HOBTE_CONFIG
    int							inc_hobte_confs;		//!< number of following HOBTE configs
#endif
	int							inc_jwtsa_confs;		//!< number of following JWTSA configs
};

/*! \brief Keeps track of WebServerGate usage
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_usercma_wsg {
    int             inc_proto_lastws;               //!< protocol of last webserver
    int             inc_len_lastws;                 //!< length of last webserver
    int             inc_port_lastws;                //!< port of last webserver
    hl_time_t          tmrc_supress_sso[LEN_SUPR_SSO]; //!< suppress single sign on
    int             inc_ica_visits;                 //!< count visits on ica site
    int             inc_ica_port;                   //!< ica port for ica interpreter
    hl_time_t          unc_ica_active_last;
};


/*! \brief Memory Offset tracking
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_ineta_cma_data {
    int inc_off_ppp;            //!< offset from beginning of cma to ppp inetas
    int inc_off_htcp;           //!< offset from beginning of cma to htcp inetas
};


/*! \brief timestamp for anti cross site scripting
 *
 * \ingroup authlib
 *
 *  Details follow
 */
struct dsd_usercma_axss {
    hl_time_t          tmc_expire;                     //!< expiration of antixss
};

enum ied_pred_result {
	iec_continue,
	iec_done,
	iec_abort
};

static int m_digit(char chp_digit) {
	if(chp_digit < '0')
		return -1;
	if(chp_digit > '9')
		return -1;
	return chp_digit-'0';
}

static bool m_parse_int(const dsd_const_string& rdsp_word, int& rinp_out) {
	int inl_ret = 0;
	for(int inl_i=0; inl_i<rdsp_word.m_get_len(); inl_i++) {
		int inl_val = m_digit(rdsp_word[inl_i]);
		if(inl_val < 0)
			return false;
		inl_ret *= 10;
		inl_ret += inl_val;
	}
	rinp_out = inl_ret;
	return true;
}

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
ds_usercma::ds_usercma()
{
	//memset(this, 0, sizeof(ds_usercma));

    // this pointer points to wspat config memory
    // so there is no need to reset it at every sdh call (init function)
    // configuration reload is only for new connections, so this 
    // pointer is save for the lifetime of the current connection.
    adsc_srole = NULL;
    adsc_domain = NULL;

    inc_main         = 0;
	 inc_pwcma_namelen = 0;
    inc_login        = 0;
    inc_settings     = 0;
    inc_wsg          = 0;
    inc_ineta        = 0;
    inc_roles        = 0;
    inc_axss         = 0;
    inc_idle_timeout = AT_DEF_MAX_PERIOD;
} // end of ds_usercma::ds_usercma


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_init
 *
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper
*/
void ds_usercma::m_init( ds_wsp_helper *adsp_wsp_helper )
{
    adsc_wsp_helper = adsp_wsp_helper;
} // end of ds_usercma::m_init


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_create
 * create user cma
 *
 * @param[in]   const char  *achp_user      username
 * @param[in]   int         inp_unlen       length of username
 * @param[in]   const char  *achp_group     user group
 * @param[in]   int         inp_uglen       length of user group
 * @param[in]   char        chl_session     session number
 * @param[in]   const char  *achp_pwd       password
 * @param[in]   int         inp_pwlen       length of password
 * @param[in]   const char  *achp_dn        ldap dn
 * @param[in]   int         inp_dnlen       length of ldap dn
 * @param[in]   const char  *achp_wspg      wsp group
 * @param[in]   int         inp_wglen       length of wsp group
 * @param[in]   int         inp_auth        auth method
 * @param[in]   bool        bop_anonymous   anonymous login
 * @param[in]   int         inp_idle_tout   idle timeout
 * @return      bool
*/
ds_wsp_helper::ied_cma_result ds_usercma::m_create( const char *achp_user,  int inp_unlen,
                           const char *achp_group, int inp_uglen,
                           const dsd_cma_session_no& chp_session,
                           const char *achp_pwd,   int inp_pwlen,
                           const char *achp_dn,    int inp_dnlen,
                           const char *achp_wspg,  int inp_wglen,
                           int inp_auth,  enum ied_usercma_login_flags iep_auth_flags,
									struct dsd_aux_ident_session_info* adsp_aux_ident_session_info)
{
    // create session ticket:
	 adsp_aux_ident_session_info->ucc_session_no = chp_session.ucc_session_no;
    if(!m_create_sticket( chp_session, adsp_aux_ident_session_info->chrc_session_ticket,
                      sizeof(adsp_aux_ident_session_info->chrc_session_ticket) ))
    {
        return ds_wsp_helper::iec_cma_failed;
    }
#if 0
    //-------------------------------------------
    // create cma names:
    //-------------------------------------------
    inc_main = m_create_name( achp_user, inp_unlen, achp_group, inp_uglen,
                              chl_session, chrc_main, D_MAXCMA_NAME        );
    if ( inc_main < 1 ) {
        return false;
    }
    bol_ret = m_set_names();
    if ( bol_ret == false ) {
        return false;
    }
#endif
    //-------------------------------------------
    // create main cma:
    //-------------------------------------------
    ds_wsp_helper::ied_cma_result inl_ret = m_create_main();
	if ( inl_ret != ds_wsp_helper::iec_cma_success )
		return inl_ret;

	//-------------------------------------------
    // create cma with encrypted password:
    //-------------------------------------------
	bool bol_ret = m_create_pwcma( achp_user, inp_unlen, achp_group, inp_uglen, achp_pwd, inp_pwlen );
	if ( bol_ret == false )
		return ds_wsp_helper::iec_cma_failed;

    //-------------------------------------------
    // save user stuff:
    //-------------------------------------------
    bol_ret = m_set_user( achp_user, inp_unlen, achp_group, inp_uglen,
                          adsp_aux_ident_session_info, achp_pwd, inp_pwlen, achp_dn, inp_dnlen,
                          achp_wspg, inp_wglen, inp_auth, iep_auth_flags );
	 if(!bol_ret)
		 return ds_wsp_helper::iec_cma_failed;
	 return ds_wsp_helper::iec_cma_success;
} // end of ds_usercma::m_create


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_delete
 * delete all existing user cmas
 *
 * @return bool
*/
bool ds_usercma::m_delete()
{
    // initialize some variables:
    bool bol_ret;
    void *avl_data;

    // main cma:
	 if ( this->inc_main != 0 && m_open_main(true) ) {
        bol_ret = m_resize_main( 0 );
        m_close_main();
    } else {
        // open failed -> cma not existing -> no error
        bol_ret = true;
    }

	// encrypted pwcma
	 if ( this->inc_pwcma_namelen != 0 && m_open_pwcma(true) ) {
        bol_ret |= m_resize_pwcma( 0 );
        m_close_pwcma();
    }

    // login cma:
	 if ( this->inc_login != 0 && m_open_login(true) ) {
        bol_ret |= m_resize_login( 0 );
        m_close_login();
    }

    // settings cma:
	 if ( this->inc_settings != 0 && m_open_settings(true) ) {
        bol_ret |= m_resize_settings( 0 );
        m_close_settings();
    }

    // wsg cma:
	 if ( this->inc_wsg != 0 && m_open_wsg(true) ) {
        bol_ret |= m_resize_wsg( 0 );
        m_close_wsg();
    }

    // ineta cma:
	 if ( this->inc_ineta != 0 && m_open_ineta(true) ) {
        bol_ret |= adsc_wsp_helper->m_cb_resize_cma( avc_ineta, &avl_data, 0 );
        m_close_ineta();
    }

    // roles cma:
    if ( this->inc_roles != 0 && m_open_roles(true) ) {
        bol_ret |= m_resize_roles( 0 );
        m_close_roles();
    }

    // axss cma:
	 if ( this->inc_axss != 0 && m_open_axss(true) ) {
        bol_ret |= m_resize_axss( 0 );
        m_close_axss();
    }
    return bol_ret;
} // end of ds_usercma::m_delete


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_delete
 * delete roles cma
 *
 * @return bool
*/
bool ds_usercma::m_delete_roles()
{
    bool bol_ret = true;
    if ( m_open_roles(true) ) {
        bol_ret = m_resize_roles( 0 );
        m_close_roles();
    }
    return bol_ret;
} // end of ds_usercma::m_delete_roles


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_basename
 *
 * @return      char*
*/
dsd_const_string ds_usercma::m_get_basename()
{
    return dsd_const_string(chrc_main, inc_main);
} // end of ds_usercma::m_get_basename


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_name
 * set name for all cmas
 *
 * @param[in]   const char  *achp_name
 * @param[in]   int         inp_len
 * @return      bool
*/
bool ds_usercma::m_set_name( const char *achp_name, int inp_len )
{
    if ( inp_len + 1 > D_MAXCMA_NAME ) {
        return false;
    }
    memcpy( chrc_main, achp_name, inp_len );
    chrc_main[inp_len] = 0;
    inc_main = inp_len;

    return m_set_names();
} // end of ds_usercma::m_set_name


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_init_state
 *
 * @param[in]   int inp_state
*/
void ds_usercma::m_init_state( int inp_state )
{
    if ( m_open_main(true) ) {
		  adsc_main->inc_state = inp_state;
        m_close_main();
    }
} // end of ds_usercma::m_init_state


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_state
 *
 * @param[in]   int inp_state
*/
void ds_usercma::m_set_state( int inp_state )
{
    if ( m_open_main(true) ) {
		  adsc_main->inc_state |= inp_state;
        m_close_main();
    }
} // end of ds_usercma::m_set_state


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_unset_state
 *
 * @param[in]   int inp_state
*/
void ds_usercma::m_unset_state( int inp_state )
{
    if ( m_open_main(true) ) {
		  adsc_main->inc_state = adsc_main->inc_state & ~inp_state;
        m_close_main();
    }
} // end of ds_usercma::m_unset_state


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_check_state
 *
 * @param[in]   int     inp_state           new state
 * @return      bool
*/
bool ds_usercma::m_check_state( int inp_state )
{
    // initialize some variables:
    bool bol_ret = false;

    if ( m_open_main(false) ) {
		 if ( (adsc_main->inc_state & inp_state) == inp_state ) {
            bol_ret = true;
        }
        m_close_main();
		  return bol_ret;
    }
    return bol_ret;
} // end of ds_usercma::m_check_state


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_state
 *
 * @return      int
*/
int ds_usercma::m_get_state()
{
    // initialize some variables:
    int inl_ret = 0;

    if ( m_open_main(false) ) {
        inl_ret = adsc_main->inc_state;
        m_close_main();
    }
    return inl_ret;
} // end of ds_usercma::m_get_state


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_check_port
 *
 * @param[in]   int     inp_port
 * @return      bool
*/
bool ds_usercma::m_check_port( int inp_port )
{
    // initialize some variables:
    bool bol_ret = false;

    if ( m_open_main(false) ) {
        if ( adsc_main->inc_port == inp_port ) {
            bol_ret = true;
        }
        m_close_main();
    }
    return bol_ret;
} // end of ds_usercma::m_check_port


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_lastaction
 *
 * @param[in]   bool
*/
hl_time_t ds_usercma::m_get_lastaction()
{
    hl_time_t ill_ret = 0;
    if ( m_open_main(false) ) {
        ill_ret = adsc_main->tmc_laction;
        m_close_main();
    }
    return ill_ret;
} // end of ds_usercma::m_get_lastaction


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_lastaction
 *
 * @param[in]   bool
*/
bool ds_usercma::m_set_lastaction()
{
    if ( !m_open_main(true) )
		return false;
    adsc_main->tmc_laction = adsc_wsp_helper->m_cb_get_time();
    m_close_main();
	// Touch all other CMA's to update the last access time
	adsc_wsp_helper->m_cb_exist_cma(chrc_login, inc_login);
	adsc_wsp_helper->m_cb_exist_cma(chrc_settings, inc_settings);
	adsc_wsp_helper->m_cb_exist_cma(chrc_wsg, inc_wsg);
	adsc_wsp_helper->m_cb_exist_cma(chrc_ineta, inc_ineta);
	adsc_wsp_helper->m_cb_exist_cma(chrc_roles, inc_roles);
	adsc_wsp_helper->m_cb_exist_cma(chrc_axss, inc_axss);
    return true;
} // end of ds_usercma::m_set_lastaction

/**
 * \ingroup authlib
 *
 * ds_usercma::m_get_message
 * get message from main cma for given url
 * url == NULL means return msg in every case
 *
 * @param[in]   const char  *achp_url       message url
 * @param[in]   int         inp_ulen        length of url
 * @param[out]  int         *ainp_type      message type
 * @param[out]  int         *ainp_code      message code
 * @return      ds_hstring                  message
*/
ds_hstring ds_usercma::m_get_message( const char *achp_url, int inp_ulen,
                                      int *ainp_type, int *ainp_code      )
{
    // initialize some variables:
    char        *achl_msg;
    ds_hstring  dsl_msg( adsc_wsp_helper );

    if ( m_open_main(false) ) {
        if (    achp_url == NULL
             || inp_ulen  < 1
             || adsc_main->uinc_msg_url == m_build_cs(achp_url, inp_ulen) ) {
            achl_msg = (char*)(adsc_main + 1);
            dsl_msg.m_write( achl_msg, adsc_main->inc_len_message );
            *ainp_type = adsc_main->inc_msg_type;
            *ainp_code = adsc_main->inc_msg_code;
        }
        m_close_main();
    }
    return dsl_msg;
} // end of ds_usercma::m_get_message


/**
 * \ingroup authlib
 *
 * public ds_usercma::m_set_message
 * set message in main cma
 *
 * @param[in]   int         inp_msg_type    message type
 * @param[in]   int         inp_msg_code    message code
 * @param[in]   const char  *achp_msg       message
 * @param[in]   int         inp_mlen        length of message
 * @param[in]   const char  *achp_url       message url
 * @param[in]   int         inp_ulen        length of url
 * @return      bool                        true = success
*/
bool ds_usercma::m_set_message( int inp_msg_type,     int inp_msg_code,
                                const dsd_const_string& achp_msg,
                                const dsd_const_string& achp_url      )
{
    // initialize some variables:
    bool bol_open;
    char *achl_save = NULL;                 // save old booked page
    char *achl_msg;
    char *achl_bpage;

    // open cma for writing:
    bol_open = m_open_main( true );
    if ( bol_open == false ) {
        return false;
    }

    // check length:
    if ( achp_msg.m_get_len() != adsc_main->inc_len_message ) {
        // save old booked page (will be overwritten while resize):
        if ( adsc_main->inc_len_bpage > 0 ) {
            achl_save = adsc_wsp_helper->m_cb_get_memory( adsc_main->inc_len_bpage, false );
            if ( achl_save == NULL ) {
                m_close_main();
                return false;
            }
            achl_bpage = (char*)(adsc_main + 1) + adsc_main->inc_len_message;
            memcpy( achl_save, achl_bpage, adsc_main->inc_len_bpage );
        }

        // resize cma:
        bol_open = m_resize_main(   (int)sizeof(dsd_usercma_main)
                                  + achp_msg.m_get_len()
                                  + adsc_main->inc_len_bpage );
        if ( bol_open == false ) {
            m_close_main();
            return false;
        }

        // save new length:
        adsc_main->inc_len_message = achp_msg.m_get_len();
    }

    // save new message:
    achl_msg = (char*)(adsc_main + 1);
    if ( achp_msg.m_get_len() > 0 ) {
        memcpy( achl_msg, achp_msg.m_get_start(), achp_msg.m_get_len() );
    }

    // write old booked page again:
    if (    achl_save != NULL 
         && adsc_main->inc_len_bpage > 0 ) {
        achl_bpage = achl_msg + achp_msg.m_get_len();
        memcpy( achl_bpage, achl_save, adsc_main->inc_len_bpage );
        adsc_wsp_helper->m_cb_free_memory( achl_save );
    }

    // save url as hash value:
    if (    achp_url.m_get_len()  <= 0    ) {
        adsc_main->uinc_msg_url = 0;
    } else {
        adsc_main->uinc_msg_url = m_build_cs( achp_url.m_get_start(), achp_url.m_get_len() );
    }

    // save message type and code:
    adsc_main->inc_msg_type = inp_msg_type;
    adsc_main->inc_msg_code = inp_msg_code;

    // close cma:
    m_close_main();
    return true;
} // end of ds_usercma::m_set_message


/**
 * \ingroup authlib
 *
 * ds_usercma::m_get_bpage
 * get booked page from main cma
 *
 * @return      ds_hstring
*/
ds_hstring ds_usercma::m_get_bpage()
{
    // initialize some variables:
    char        *achl_page;
    ds_hstring  dsl_page( adsc_wsp_helper );

    if ( m_open_main(false) ) {
        achl_page = (char*)(adsc_main + 1) + adsc_main->inc_len_message;
        dsl_page.m_write( achl_page, adsc_main->inc_len_bpage );
        m_close_main();
    }
    return dsl_page;
} // end of ds_usercma::m_get_bpage


/**
 * \ingroup authlib
 *
 * ds_usercma::m_set_bpage
 * set booked page in main cma
 *
 * @param[in]   const char  *achp_page      booked page
 * @param[in]   int         inp_len         length of booked page
 * @return      bool
*/
bool ds_usercma::m_set_bpage( const char* achp_page, int inp_len )
{
    // initialize some variables:
    bool bol_open;
    char *achl_bpage;

    if ( inp_len < 0 ) {
        return false;
    }
    if ( achp_page == NULL ) {
        inp_len = 0;
    }

    // open cma for writing:
    bol_open = m_open_main( true );
    if ( bol_open == false ) {
        return false;
    }

    // check length:
    if ( inp_len != adsc_main->inc_len_bpage ) {
        // resize cma:
        bol_open = m_resize_main(   (int)sizeof(dsd_usercma_main)
                                  + adsc_main->inc_len_message
                                  + inp_len                       );
        if ( bol_open == false ) {
            m_close_main();
            return false;
        }

        // save new length:
        adsc_main->inc_len_bpage = inp_len;
    }

    // save new booked page:
    achl_bpage = (char*)(adsc_main + 1) + adsc_main->inc_len_message;
    if ( inp_len > 0 && achp_page != NULL ) {
        memcpy( achl_bpage, achp_page, inp_len );
    }

    // close cma:
    m_close_main();
    return true;
} // end of ds_usercma::m_set_bpage


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_username
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_username()
{
    // initialize some variables:
    char        *achl_user;
    ds_hstring  dsl_user( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_user = (char*)(adsc_login + 1);
        dsl_user.m_write( achl_user, adsc_login->inc_len_username );
        m_close_login();
    }
    return dsl_user;
} // end of ds_usercma::m_get_username


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_userdomain
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_userdomain()
{
    char        *achl_domain;
    ds_hstring  dsl_domain( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_domain = (char*)(adsc_login + 1) + adsc_login->inc_len_username;
        dsl_domain.m_write( achl_domain, adsc_login->inc_len_userdomain );
        m_close_login();
    }
    return dsl_domain;
} // end of ds_usercma::m_get_userdomain


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_authmethod
 *
 * @return  int
*/
int ds_usercma::m_get_authmethod(enum ied_usercma_login_flags &riep_auth_flags)
{
    // initialize some variables:
    if ( m_open_login(false) ) {
        int inl_auth = adsc_login->inc_auth_method;
        riep_auth_flags = adsc_login->iec_auth_flags; 
        m_close_login();
        return inl_auth;
    }
    riep_auth_flags = (enum ied_usercma_login_flags)0;
    return 0;
} // end of ds_usercma::m_get_authmethod


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_hobsocks_name
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_hobsocks_name()
{
    // initialize some variables:
    char        *achl_user;
    char        *achl_domain;
    int         inl_offset;
    ds_hstring  dsl_hsocks( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_user  = (char*)(adsc_login + 1);
        achl_domain = achl_user + adsc_login->inc_len_username;

        dsl_hsocks.m_write( achl_domain, adsc_login->inc_len_userdomain );
        dsl_hsocks.m_replace( "\\", "\\\\" );
        dsl_hsocks.m_write( "\\", 1 );
        inl_offset = dsl_hsocks.m_get_len();

        dsl_hsocks.m_write( achl_user, adsc_login->inc_len_username );
        dsl_hsocks.m_replace( "\\", "\\\\", inl_offset );

        m_close_login();
    }
    return dsl_hsocks;
} // end of ds_usercma::m_get_hobsocks_name


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_userdn
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_userdn()
{
    // initialize some variables:
    char        *achl_dn;
    ds_hstring  dsl_dn( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_dn =   (char*)(adsc_login + 1)
                  + adsc_login->inc_len_username
                  + adsc_login->inc_len_userdomain
                  + adsc_login->inc_len_password;
        dsl_dn.m_write( achl_dn, adsc_login->inc_len_userdn );
        m_close_login();
    }
    return dsl_dn;
} // end of ds_usercma::m_get_userdn


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_userrole
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_userrole()
{
    // initialize some variables:
    char        *achl_role;
    ds_hstring  dsl_role( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_role =   (char*)(adsc_login + 1)
                    + adsc_login->inc_len_username
                    + adsc_login->inc_len_userdomain
                    + adsc_login->inc_len_password
                    + adsc_login->inc_len_userdn
                    + adsc_login->inc_len_wspgroup;
        dsl_role.m_write( achl_role, adsc_login->inc_len_role );
        m_close_login();
    }
    return dsl_role;
} // end of ds_usercma::m_get_userrole


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_role
 *
 * @param[in]   const char  *achp_role
 * @param[in]   int         inp_len
 * @return      bool
*/
bool ds_usercma::m_set_role( const char *achp_role, int inp_len )
{
    // initialize some variables:
    bool bol_ret;
    char *achl_role;

    if ( inp_len < 0 ) {
        return false;
    }

    if (    achp_role  == NULL
         && inp_len    == 0
         && adsc_srole != NULL ) {
        achp_role = adsc_srole->achc_name;
        inp_len   = adsc_srole->inc_len_name;
    }

    // open cma for writing:
    bol_ret = m_open_login( true );
    if ( bol_ret == false ) {
        return false;
    }

    // resize cma:
    if ( adsc_login->inc_len_role != inp_len ) {
        bol_ret = m_resize_login(   (int)sizeof(dsd_usercma_login)
                                  + adsc_login->inc_len_username
                                  + adsc_login->inc_len_userdomain
                                  + adsc_login->inc_len_password
                                  + adsc_login->inc_len_userdn
                                  + adsc_login->inc_len_wspgroup
                                  + inp_len                         );
        if ( bol_ret == false ) {
            m_close_login();
            return false;
        }
        adsc_login->inc_len_role = inp_len;
    }

    // save role:
    if ( inp_len > 0 && achp_role != NULL ) {
        achl_role =   (char*)(adsc_login + 1)
                    + adsc_login->inc_len_username
                    + adsc_login->inc_len_userdomain
                    + adsc_login->inc_len_password
                    + adsc_login->inc_len_userdn
                    + adsc_login->inc_len_wspgroup;
        memcpy( achl_role, achp_role, inp_len );
    }

    // close cma:
    m_close_login();
    return true;
} // end of ds_usercma::m_set_role


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_user
 *
 * @param[out]  dsd_getuser *adsp_user
 * @return      bool
*/
bool ds_usercma::m_get_user( struct dsd_getuser *adsp_user )
{
    // initialize some variables:
    char    *achl_user;
    char    *achl_domain;
    char    *achl_dn;
    char    *achl_wspgroup;
    char    *achl_role;
    bool    bol_ret;

    bol_ret = m_open_login(false);
    if ( bol_ret == true ) {
        achl_user     = (char*)(adsc_login + 1);
        achl_domain   = achl_user + adsc_login->inc_len_username;
        achl_dn       =   achl_domain
                        + adsc_login->inc_len_userdomain
                        + adsc_login->inc_len_password;
        achl_wspgroup = achl_dn + adsc_login->inc_len_userdn;
        achl_role     = achl_wspgroup + adsc_login->inc_len_wspgroup;
        
        adsp_user->dsc_username.m_setup( adsc_wsp_helper );
        adsp_user->dsc_userdomain.m_setup( adsc_wsp_helper );
        adsp_user->dsc_wspgroup.m_setup( adsc_wsp_helper );
        adsp_user->dsc_role.m_setup( adsc_wsp_helper );
        adsp_user->dsc_userdn.m_setup( adsc_wsp_helper );

        adsp_user->tmc_login       = adsc_login->tmc_login;
        adsp_user->iec_auth_flags   = adsc_login->iec_auth_flags;
        adsp_user->inc_auth_method = adsc_login->inc_auth_method;
        adsp_user->chc_session     = adsc_login->chc_session;

        adsp_user->dsc_username.m_write( achl_user, adsc_login->inc_len_username );
        adsp_user->dsc_userdomain.m_write( achl_domain, adsc_login->inc_len_userdomain );
        adsp_user->dsc_wspgroup.m_write( achl_wspgroup, adsc_login->inc_len_wspgroup );
        adsp_user->dsc_role.m_write( achl_role, adsc_login->inc_len_role );
        adsp_user->dsc_userdn.m_write( achl_dn, adsc_login->inc_len_userdn );

        memcpy( &adsp_user->dsc_client, &adsc_login->dsc_client,
                sizeof(dsd_aux_query_client) );

        m_close_login();
    }
    return bol_ret;
} // end of ds_usercma::m_get_user


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_sticket
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_sticket()
{
    // initialize some variables:
    ds_hstring  dsl_ticket( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        dsl_ticket.m_write( adsc_login->chr_sticket, LEN_SESSTICKET );
        m_close_login();
    }
    return dsl_ticket;
} // end of ds_usercma::m_get_sticket


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_check_sticket
 *
 * @param[in]   const char  *achp_sticket
 * @param[in]   int         inp_len
 * @return      bool
*/
bool ds_usercma::m_check_sticket( const char *achp_sticket, int inp_len )
{
    // initialize some variables:
    int inl_ret;

    if (    achp_sticket == NULL
         || inp_len      != LEN_SESSTICKET ) {
        return false;
    }

    if ( m_open_login(false) ) {
        inl_ret = memcmp( &adsc_login->chr_sticket[0],
                          achp_sticket, LEN_SESSTICKET );
        m_close_login();
        return (inl_ret == 0);
    }
    return false;
} // end of ds_usercma::m_check_sticket


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_size_sticket
 *
 * @return  int
*/
int ds_usercma::m_size_sticket()
{
    return LEN_SESSTICKET;
} // end of ds_usercma::m_size_sticket


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_password
 *
 * @return  ds_hstring
*/
ds_hstring ds_usercma::m_get_password()
{
    // initialize some variables:
    char        *achl_pwd;
    ds_hstring  dsl_pwd( adsc_wsp_helper );

    if ( m_open_login(false) ) {
        achl_pwd =   (char*)(adsc_login + 1)
                   + adsc_login->inc_len_username
                   + adsc_login->inc_len_userdomain;
        dsl_pwd.m_write( achl_pwd, adsc_login->inc_len_password );
        m_close_login();
		  return dsl_pwd;
    }
    return dsl_pwd;
} // end of ds_usercma::m_get_password


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_check_password
 *
 * @param[in]   const char  *achp_pwd
 * @param[in]   int         inp_len
 * @return      bool
*/
bool ds_usercma::m_check_password( const char *achp_pwd, int inp_len )
{
    // initialize some variables:
    char *achl_pwd;
    int  inl_ret;

    if ( achp_pwd == NULL ) {
        return false;
    }

    if ( m_open_login(false) ) {
        if ( inp_len != adsc_login->inc_len_password ) {
            m_close_login();
            return false;
        }
        achl_pwd =   (char*)(adsc_login + 1)
                   + adsc_login->inc_len_username
                   + adsc_login->inc_len_userdomain;
        inl_ret = memcmp( achl_pwd, achp_pwd, inp_len );
        m_close_login();
        return (inl_ret == 0);
    }
    return false;
} // end of ds_usercma::m_check_password


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_logintime
 *
 * @return hl_time_t
*/
hl_time_t ds_usercma::m_get_logintime()
{
    // initialize some variables:
    hl_time_t ill_login = 0;

    if ( m_open_login(false) ) {
        ill_login = adsc_login->tmc_login;
        m_close_login();
    }
    return ill_login;
} // end of ds_usercma::m_get_logintime


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_clientip
 *
 * @param[out]  unsigned char uchrp_client_ineta[16]
 * @return      bool
*/
bool ds_usercma::m_get_clientip( unsigned char uchrp_client_ineta[16] )
{
    // initialize some variables:
    bool bol_ret;

    bol_ret = m_open_login( false );
    if ( bol_ret == true ) {
        memcpy( &uchrp_client_ineta[0],
                adsc_login->dsc_client.chrc_client_ineta, 16 );
        m_close_login();
    }
    return bol_ret;
} // end of ds_usercma::m_get_clientip


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_client_ineta
 *
 * @return      dsd_aux_query_client
*/
dsd_aux_query_client ds_usercma::m_get_client_ineta()
{
    // initialize some variables:
    dsd_aux_query_client dsl_ineta;

    if ( m_open_login(false) ) {
        memcpy( &dsl_ineta, &adsc_login->dsc_client,
                sizeof(dsd_aux_query_client) );
        m_close_login();
        return dsl_ineta;
    }
    memset( &dsl_ineta, 0, sizeof(dsd_aux_query_client) );
    return dsl_ineta;
} // end of ds_usercma::m_get_client_ineta


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_pwd_expires
 * get time in days when password expires
 * if this time is smaller a confugred value this function
 * will return its value, otherwise DEF_DONT_EXPIRE is returned
 *
 * @return  int     expires time in days
*/
int ds_usercma::m_pwd_expires()
{
    int inl_days;
    if ( m_open_login(false) ) {
        inl_days = adsc_login->inc_pwd_expires;
        m_close_login();
        return inl_days;
    }
    return DEF_DONT_EXPIRE;
} // end of ds_usercma::m_pwd_expires


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_pwd_expires
 * set expires time of password in days
 *
 * @param[in]   int inp_days
 * @return      bool
*/
bool ds_usercma::m_set_pwd_expires( int inp_days )
{
    if ( m_open_login(true) ) {
        adsc_login->inc_pwd_expires = inp_days;
        m_close_login();
        return true;
    }
    return false;
} // end of ds_usercma::m_set_pwd_expires


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_reset_pwd_expires
 * reset expires time of password in days
 *
 * @return      bool
*/
bool ds_usercma::m_reset_pwd_expires()
{
    return m_set_pwd_expires(DEF_DONT_EXPIRE);
} // end of ds_usercma::m_reset_pwd_expires


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_lang
 * get selected user language
 *
 * @return int
*/
int ds_usercma::m_get_lang()
{
    int inl_lang = -1;
    if ( m_open_settings(false) ) {
        inl_lang = adsc_settings->inc_lang;
        m_close_settings();
    }
    return inl_lang;
} // end of ds_usercma::m_get_lang


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_lang
 * set selected user language
 *
 * @param[in]   int    inp_lang                 language
 * @return      bool                            true = success
*/
bool ds_usercma::m_set_lang( int inp_lang )
{
    if ( m_open_settings(true) ) {
        adsc_settings->inc_lang = inp_lang;
        m_close_settings();
        return true;
    }
    return false;
} // end of ds_usercma::m_set_lang


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_wsg_bookmark
 * get users webservergate bookmark from index number
 *
 * @param[in]   int             inp_index           index number
 * @param[out]  ds_bookmark*    adsp_bmark          output bmark
 * @return      bool                                true = success
*/
bool ds_usercma::m_get_wsg_bookmark( int inp_index, ds_bookmark* adsp_bmark )
{
    return m_get_ws_bookmark( ied_bookmark_wsg, inp_index, adsp_bmark);
} // end of ds_usercma::m_get_wsg_bookmark


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_count_wsg_bookmarks
 * get number of users webservergate bookmarks
 *
 * @return      int
*/
int ds_usercma::m_count_wsg_bookmarks()
{
    int inl_ret = 0;
    if ( m_open_settings(false) ) {
        inl_ret = adsc_settings->inc_wsg_bookmarks;
        m_close_settings();
    }
    return inl_ret;
} // end of ds_usercma::m_get_wsg_bookmark


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_wsg_bookmarks
 * get users webservergate bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    adsp_bmarks      output buffer
 * @return      bool
*/
bool ds_usercma::m_get_wsg_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    return m_get_ws_bookmarks( ied_bookmark_wsg, adsp_bmarks);
} // end of ds_usercma::m_get_wsg_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_wsg_bookmarks
 * save webservergate bookmarks in cma 
 * ATTENTION: this call will overwrite existing bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_set_wsg_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    return m_set_ws_bookmarks( ied_bookmark_wsg, adsp_bmarks, false);
} // end of ds_usercma::m_set_wsg_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_rdvpn_bookmark
 * get users rdvpn (user portal) bookmark from index number
 *
 * @param[in]   int             inp_index           index number
 * @param[out]  ds_bookmark*    adsp_bmark          output bmark
 * @return      bool                                true = success
*/
bool ds_usercma::m_get_rdvpn_bookmark( int inp_index, ds_bookmark* adsp_bmark )
{
    return m_get_ws_bookmark( ied_bookmark_rdvpn, inp_index, adsp_bmark);
} // end of ds_usercma::m_get_rdvpn_bookmark


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_count_rdvpn_bookmarks
 * get number of users rdvpn (user portal) bookmarks
 *
 * @return      int
*/
int ds_usercma::m_count_rdvpn_bookmarks()
{
    int inl_ret = 0;
    if ( m_open_settings(false) ) {
        inl_ret = adsc_settings->inc_rdvpn_bookmarks;
        m_close_settings();
    }
    return inl_ret;
} // end of ds_usercma::m_get_rdvpn_bookmark


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_rdvpn_bookmarks
 * get users rdvpn (user portal) bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    adsp_bmarks      output buffer
 * @return      bool
*/
bool ds_usercma::m_get_rdvpn_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    return m_get_ws_bookmarks( ied_bookmark_rdvpn, adsp_bmarks);
} // end of ds_usercma::m_get_rdvpn_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_wsg_bookmarks
 * save rdvpn (user portal) bookmarks in cma 
 * ATTENTION: this call will overwrite existing bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_set_rdvpn_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    return m_set_ws_bookmarks( ied_bookmark_rdvpn, adsp_bmarks, false);
} // end of ds_usercma::m_set_rdvpn_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_jwtsa_set_configs
 * save jwtsa targets in cma
 *
 * @param[in]   ds_hvector<ds_jwtsa_conf>* adsp_configs		config names to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_jwtsa_set_configs( ds_hvector<ds_jwtsa_conf>* adsp_configs )
{
	bool					bol_ret;						/* return code for some funcs */
	const char					*achl_name;						/* the name of the current config */
	int						inl_len_name;					/* the length */
	dsd_cma_jwtsaconf		*adsl_cma_conf;					/* the struct which is written into the CMA */
	int						inl_size;						/* size of the data before we can insert our stuff */
	int						inl_pos;

	// open cma for writing:
    bol_ret = m_open_settings( true );
	if ( bol_ret == false ){ return false; }

	/* no backup created because this is the last entry of the config CMA */

	// get the size till the end of the portlets
	// we insert our stuff after the portlets
	inl_size = m_eval_size( ied_jwtsa_conf, false, NULL );

    // now get the size of the configuration names:
    for( HVECTOR_FOREACH(ds_jwtsa_conf, adsl_cur, *adsp_configs) )
	{
        const ds_jwtsa_conf& dsl_config = HVECTOR_GET(adsl_cur);
        dsl_config.m_get_name ( &achl_name, &inl_len_name );
        
        if ( inl_len_name  > 0 )
		{
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof( dsd_cma_jwtsaconf )
                       + inl_len_name;
        }
    }

	// resize cma to hold our new data, too
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false )
	{
        m_close_settings();
        return false;
    }

    // insert new config names:
	adsc_settings->inc_jwtsa_confs = (int)adsp_configs->m_size();

    inl_pos = 0;
    for (HVECTOR_FOREACH(ds_jwtsa_conf, adsl_cur, *adsp_configs)) {
        const ds_jwtsa_conf& dsl_config = HVECTOR_GET(adsl_cur);
        // get buffer in cma, every round we get the endpointer
		adsl_cma_conf = m_jwtsa_get_config( inl_pos++ );
        if ( adsl_cma_conf == NULL ) {
            continue;
        }

        // get incoming config:
        dsl_config.m_get_name( &achl_name,  &inl_len_name  );

        // copy data:
        adsl_cma_conf->inc_len_name = inl_len_name;
        memcpy( (char*)adsl_cma_conf + sizeof( struct dsd_cma_jwtsaconf), achl_name, inl_len_name );
    }

	// close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_jwtsa_set_configs

#if BO_HOBTE_CONFIG
bool ds_usercma::m_hobte_set_configs( ds_hvector<ds_hobte_conf>* adsp_configs )
{
	bool					bol_ret;						/* return code for some funcs */
	const char					*achl_name;						/* the name of the current config */
	int						inl_len_name;					/* the length */
	dsd_cma_hobteconf		*adsl_cma_conf;					/* the struct which is written into the CMA */
	int						inl_size;						/* size of the data before we can insert our stuff */
	int						inl_pos;

	// open cma for writing:
    bol_ret = m_open_te_settings( true );
	if ( bol_ret == false ){ return false; }

	/* no backup created because this is the last entry of the config CMA */
    //TODO create backup
    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_hobte_conf);
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }
	// get the size till the end of the portlets
	// we insert our stuff after the jwt config
    inl_size = m_eval_size( ied_hobte_conf, false, NULL );

    // now get the size of the configuration names:
    for( HVECTOR_FOREACH(ds_hobte_conf, adsl_cur, *adsp_configs) )
	{
        const ds_hobte_conf& dsl_config = HVECTOR_GET(adsl_cur);
        dsl_config.m_get_name ( &achl_name, &inl_len_name );
        
        if ( inl_len_name  > 0 )
		{
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof( dsd_cma_hobteconf )
                       + inl_len_name;
        }
    }

	// resize cma to hold our new data, too
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false )
	{
        m_close_settings();
        return false;
    }

    // insert new config names:
	adsc_settings->inc_hobte_confs = (int)adsp_configs->m_size();

    inl_pos = 0;
    for (HVECTOR_FOREACH(ds_hobte_conf, adsl_cur, *adsp_configs)) {
        const ds_hobte_conf& dsl_config = HVECTOR_GET(adsl_cur);
        // get buffer in cma, every round we get the endpointer
		adsl_cma_conf = m_hobte_get_config( inl_pos++ );
        if ( adsl_cma_conf == NULL ) {
            continue;
        }

        // get incoming config:
        dsl_config.m_get_name( &achl_name,  &inl_len_name  );

        // copy data:
        adsl_cma_conf->inc_len_name = inl_len_name;
        adsl_cma_conf->iec_subprotocol = dsl_config.m_get_subprotocol();
        //TODO!!! DO NOT COMMIT - buffer overflow
        memcpy( (char*)adsl_cma_conf + sizeof( struct dsd_cma_hobteconf), achl_name, inl_len_name );
    }

        // copy saved data back:
    bol_ret = m_free_backup( ied_hobte_conf);
	// close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_hobte_set_configs

int ds_usercma::m_hobte_count_configs()
{
    int inl_ret = 0;
    if ( m_open_te_settings(false) )
	{
		inl_ret = adsc_settings->inc_hobte_confs;
        m_close_settings();
    }
    return inl_ret;
}

dsd_cma_hobteconf*	ds_usercma::m_hobte_get_config ( int inp_index )
{
    // initialize some variables:
    int                  inl_offset;				// offset in memory
    int                  inl_counter;				// loop variable
    dsd_cma_workstation  *adsl_wstat;				// workstation structure
    dsd_cma_wfa_bmark    *adsl_wfa_bmark;			// last wfa bookmark structure
    dsd_cma_wsg_bmark    *adsl_wsg_bmark;			// last wsg bookmark structure
    dsd_cma_portlet      *adsl_portlet;				// portlet structure
    dsd_cma_jwtsaconf   *adsl_jwtsaconf;
	dsd_cma_hobteconf	 *adsl_hobteconf = NULL;	// hobte configurations

	if ( inp_index >= adsc_settings->inc_hobte_confs ){ return NULL; }

    //get last jwtconf
    adsl_jwtsaconf = m_jwtsa_get_config(adsc_settings->inc_jwtsa_confs-1);
    if (adsl_jwtsaconf == NULL)
    {
	    adsl_portlet = m_get_portlet( adsc_settings->inc_portlets -1 );
	    if( adsl_portlet == NULL ) // no portlet yet -> get last workstation
	    {
		    adsl_wstat = m_get_workstation( adsc_settings->inc_workstations - 1 );
		    if( adsl_wstat == NULL ) // no workstation yet -> get last bookmark
		    {        
			    adsl_wfa_bmark = m_get_wfa_bmark( adsc_settings->inc_wfa_bookmarks - 1 );
			    if( adsl_wfa_bmark == NULL )
			    {
				    adsl_wsg_bmark = m_get_ws_bmark( adsc_settings->inc_ws_bookmarks - 1 );
				    if( adsl_wsg_bmark == NULL ) // no bookmark yet
				    {
					    inl_offset =   (int)sizeof(dsd_usercma_settings)
								     + adsc_settings->inc_len_umsg
                                     + adsc_settings->inc_len_default_portlet;
				    }
				    else // go to end of bookmark:
				    {
					    inl_offset =   (int)((char*)adsl_wsg_bmark - (char*)adsc_settings)
								     + (int)sizeof(dsd_cma_wsg_bmark)
								     + adsl_wsg_bmark->inc_len_name
								     + adsl_wsg_bmark->inc_len_url;
				    }
			    }
			    else // go to end of bookmark:
			    {
				    inl_offset =   (int)((char*)adsl_wfa_bmark - (char*)adsc_settings)
							     + (int)sizeof(dsd_cma_wfa_bmark)
							     + adsl_wfa_bmark->inc_len_name
							     + adsl_wfa_bmark->inc_len_url
							     + adsl_wfa_bmark->inc_len_user
							     + adsl_wfa_bmark->inc_len_pwd
							     + adsl_wfa_bmark->inc_len_domain;
			    }
		    }
		    else // go to end of workstation:
		    {
			    inl_offset =   (int)((char*)adsl_wstat - (char*)adsc_settings)
						     + (int)sizeof(dsd_cma_workstation)
						     + adsl_wstat->inc_len_ineta
						     + adsl_wstat->inc_len_name;
		    }
	    }
	    else //go to end of portlet
	    {
		    inl_offset =	(int)( (char*)adsl_portlet - (char*)adsc_settings )
					    +	(int) sizeof( dsd_cma_portlet )
					    +	adsl_portlet->inc_len_name;
	    }
    }
    else //go to end of jwtsa
    {
         inl_offset = (int)( (char*)adsl_jwtsaconf - (char*)adsc_settings )
             +	(int) sizeof( dsd_cma_jwtsaconf )
					    +	adsl_jwtsaconf->inc_len_name;

    }

    //-------------------------------------------
    // loop through configs:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current portlet struct:
        adsl_hobteconf = (dsd_cma_hobteconf*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_hobteconf)
                          + adsl_hobteconf->inc_len_name;
        }
    }

    return adsl_hobteconf;
}


bool ds_usercma::m_hobte_get_config( int inp_index, ds_hobte_conf* adsp_hobte_config )
{
    // initialize some variables:
    bool               bol_ret;                 // return for some func calls
    dsd_cma_hobteconf *adsl_cma_config;         // current config in cma
    char*              achl_name;               // name

    // init variable:
    adsp_hobte_config->m_init( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_te_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get config at index:
    adsl_cma_config = m_hobte_get_config( inp_index );
    if ( adsl_cma_config == NULL ) {
        m_close_settings();
        return false;
    }

    // get name:
    achl_name = (char*)adsl_cma_config + sizeof(dsd_cma_hobteconf);

    // set name:
    adsp_hobte_config->m_set_name( achl_name, adsl_cma_config->inc_len_name );

    //set subprotocol
    adsp_hobte_config->m_set_subprotocol(adsl_cma_config->iec_subprotocol);

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_hobte_get_config

bool ds_usercma::m_open_te_settings(bool bop_write)
{
     // initialize some variables:
    void *avl_data;                         // pointer to cma content
    bool bol_ret;                           // return value
    int  inl_req_len;                       // required length of cma

    // open cma:
    avc_settings = adsc_wsp_helper->m_cb_open_cma( chrc_settings, inc_settings,
                                                   &avl_data, &inc_sclen,
                                                   bop_write );
    if ( avc_settings == NULL ) {
        if ( bop_write == false ) {
            return false;
        }

        // cma does not exist, create it:
        bol_ret = m_create_settings();
        if ( bol_ret == false ) {
            return false;
        }

        // try to open is again:
        avc_settings = adsc_wsp_helper->m_cb_open_cma( chrc_settings, inc_settings,
                                                       &avl_data, &inc_sclen,
                                                       bop_write );
        if ( avc_settings == NULL ) {
            return false;
        }
    }

    // check return data:
    if (    avl_data    == NULL
         || inc_sclen <  (int)sizeof(dsd_usercma_settings) ) {
        m_close_settings();
        return false;
    }

    // initialize content pointer:
    adsc_settings = (dsd_usercma_settings*)avl_data;

	// compare total length with our length pointers:
	inl_req_len = m_eval_size( ied_max_setting , false, NULL );
    if ( inc_sclen != inl_req_len ) {
        m_close_settings();
        return false;
    }

    return true;
}

#endif

/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_own_wsg_bookmarks
 * save own webservergate bookmarks in cma 
 * ATTENTION: this call will overwrite existing own bookmarks
 *            but keep other bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
 * 
*/
bool ds_usercma::m_set_own_wsg_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    /*
        first wsg bookmarks in cma are inherited bookmarks
        following are our own bookmarks!
    */

    return m_set_ws_bookmarks( ied_bookmark_wsg, adsp_bmarks, true);
} // end of ds_usercma::m_set_own_wsg_bookmarks

/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_own_rdvpn_bookmarks
 * save own rdvpn (user portal) bookmarks in cma 
 * ATTENTION: this call will overwrite existing own bookmarks
 *            but keep other bookmarks
 *
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
 * 
*/
bool ds_usercma::m_set_own_rdvpn_bookmarks( ds_hvector<ds_bookmark> *adsp_bmarks )
{
    /*
        first wsg bookmarks in cma are inherited bookmarks
        following are our own bookmarks!
    */

    return m_set_ws_bookmarks( ied_bookmark_rdvpn, adsp_bmarks, true);
} // end of ds_usercma::m_set_own_rdvpn_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_count_wfa_bookmarks
 * get number of users webfileaccess bookmarks
 *
 * @return      int
*/
int ds_usercma::m_count_wfa_bookmarks()
{
    int inl_ret = 0;
    if ( m_open_settings(false) ) {
        inl_ret = adsc_settings->inc_wfa_bookmarks;
        m_close_settings();
    }
    return inl_ret;
} // end of ds_usercma::m_count_wfa_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_wfa_bookmark
 * get users webfileaccess bookmark from index number
 *
 * @param[in]   int             in_index            index number
 * @param[out]  dsd_wfa_bmark*  ads_bmark           output bmark
 * @return      bool                                true = success
*/
bool ds_usercma::m_get_wfa_bookmark( int inp_index, dsd_wfa_bmark *adsp_bmark )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    dsd_cma_wfa_bmark *adsl_bm_cma;             // current bookmark in cma
    char              *achl_url;                // url
    char              *achl_name;               // name
    char              *achl_user;               // userid
    char              *achl_pwd;                // password
    char              *achl_domain;             // domain


    // init variable:
    adsp_bmark->m_init( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get bookmark at index:
    adsl_bm_cma = m_get_wfa_bmark( inp_index );
    if ( adsl_bm_cma == NULL ) {
        m_close_settings();
        return false;
    }

    // get strings:
    achl_name   = (char*)adsl_bm_cma + sizeof(dsd_cma_wfa_bmark);
    achl_url    = achl_name + adsl_bm_cma->inc_len_name;
    achl_user   = achl_url  + adsl_bm_cma->inc_len_url;
    achl_pwd    = achl_user + adsl_bm_cma->inc_len_user;
    achl_domain = achl_pwd  + adsl_bm_cma->inc_len_pwd;

    // set strings:
    adsp_bmark->m_set_name  ( achl_name, adsl_bm_cma->inc_len_name     );
    adsp_bmark->m_set_url   ( achl_url,  adsl_bm_cma->inc_len_url      );
    adsp_bmark->m_set_user  ( achl_user, adsl_bm_cma->inc_len_user     );
    adsp_bmark->m_set_pwd   ( achl_pwd,  adsl_bm_cma->inc_len_pwd      );
    adsp_bmark->m_set_domain( achl_domain, adsl_bm_cma->inc_len_domain );

    // set ownership and position:
    adsp_bmark->m_set_own     ( adsl_bm_cma->boc_is_own );
    adsp_bmark->m_set_position( inp_index );

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_wfa_bookmark


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_wfa_bookmarks
 * get users webfileaccess bookmarks
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*  ads_bmarks      output buffer
 * @return      bool
*/
bool ds_usercma::m_get_wfa_bookmarks( ds_hvector<dsd_wfa_bmark> *adsp_bmarks )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_pos;                  // loop variable
    dsd_wfa_bmark     dsl_bmark;                // current bookmark
    dsd_cma_wfa_bmark *adsl_bm_cma;             // current bookmark in cma
    char              *achl_url;                // url
    char              *achl_name;               // name
    char              *achl_user;               // user
    char              *achl_pwd;                // password
    char              *achl_domain;             // domain

    // init incoming vector:
    adsp_bmarks->m_init( adsc_wsp_helper );
    dsl_bmark.m_init   ( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // loop through all wsg bookmarks:
    for ( inl_pos = 0; inl_pos < adsc_settings->inc_wfa_bookmarks; inl_pos++ ) {
        adsl_bm_cma = m_get_wfa_bmark( inl_pos );
        if ( adsl_bm_cma == NULL ) {
            m_close_settings();
            return false;
        }

        // get name and url:
        achl_name   = (char*)adsl_bm_cma + sizeof(dsd_cma_wfa_bmark);
        achl_url    = achl_name + adsl_bm_cma->inc_len_name;
        achl_user   = achl_url  + adsl_bm_cma->inc_len_url;
        achl_pwd    = achl_user + adsl_bm_cma->inc_len_user;
        achl_domain = achl_pwd  + adsl_bm_cma->inc_len_pwd;

        // set strings:
        dsl_bmark.m_set_name  ( achl_name, adsl_bm_cma->inc_len_name     );
        dsl_bmark.m_set_url   ( achl_url,  adsl_bm_cma->inc_len_url      );
        dsl_bmark.m_set_user  ( achl_user, adsl_bm_cma->inc_len_user     );
        dsl_bmark.m_set_pwd   ( achl_pwd,  adsl_bm_cma->inc_len_pwd      );
        dsl_bmark.m_set_domain( achl_domain, adsl_bm_cma->inc_len_domain );

        // set ownership and position:
        dsl_bmark.m_set_own     ( adsl_bm_cma->boc_is_own );
        dsl_bmark.m_set_position( inl_pos );

        // add to vector:
        adsp_bmarks->m_add( dsl_bmark );
    }

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_wfa_bookmarks


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_wfa_bookmarks
 * save webfileaccess bookmarks in cma
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*  ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_set_wfa_bookmarks( ds_hvector<dsd_wfa_bmark> *adsp_bmarks )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_size;                 // new size of cma
    const char              *achl_url;                // url
    int               inl_len_url;              // length of url
    const char              *achl_name;               // name
    int               inl_len_name;             // length of name
    const char              *achl_user;               // user
    int               inl_len_user;             // length of user
    const char              *achl_pwd;                // password
    int               inl_len_pwd;              // length of password
    const char              *achl_domain;             // domain
    int               inl_len_domain;           // length of domain
    dsd_cma_wfa_bmark *adsl_bm_cma;             // current bookmark in cma
    char              *achl_offset;             // offset for memcpy

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_workstats );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
	inl_size = m_eval_size( ied_wfa_bmarks, false, NULL );

    // loop through incoming wfa bookmarks:
    for ( HVECTOR_FOREACH(dsd_wfa_bmark, adsl_cur, *adsp_bmarks) ) {
        const dsd_wfa_bmark& dsl_bmark = HVECTOR_GET(adsl_cur);
        dsl_bmark.m_get_url   ( &achl_url,    &inl_len_url    );
        dsl_bmark.m_get_name  ( &achl_name,   &inl_len_name   );
        dsl_bmark.m_get_user  ( &achl_user,   &inl_len_user   );
        dsl_bmark.m_get_pwd   ( &achl_pwd,    &inl_len_pwd    );
        dsl_bmark.m_get_domain( &achl_domain, &inl_len_domain );

        if ( inl_len_url > 0 ) {
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof(dsd_cma_wfa_bmark)
                       + inl_len_url
                       + inl_len_name
                       + inl_len_user
                       + inl_len_pwd
                       + inl_len_domain;
        }
    }

    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new bookmarks:
    adsc_settings->inc_wfa_bookmarks = (int)adsp_bmarks->m_size();
    int inl_pos = 0;
    for ( HVECTOR_FOREACH(dsd_wfa_bmark, adsl_cur, *adsp_bmarks) ) {
        const dsd_wfa_bmark& dsl_bmark = HVECTOR_GET(adsl_cur);
        // get buffer in cma:
        adsl_bm_cma = m_get_wfa_bmark( inl_pos++ );
        if ( adsl_bm_cma == NULL ) {
            continue;
        }

        // get incoming bookmark:
        dsl_bmark.m_get_url   ( &achl_url,    &inl_len_url    );
        dsl_bmark.m_get_name  ( &achl_name,   &inl_len_name   );
        dsl_bmark.m_get_user  ( &achl_user,   &inl_len_user   );
        dsl_bmark.m_get_pwd   ( &achl_pwd,    &inl_len_pwd    );
        dsl_bmark.m_get_domain( &achl_domain, &inl_len_domain );

        if ( inl_len_url < 1 ) {
            continue;
        }

        // copy ownership
        adsl_bm_cma->boc_is_own   = dsl_bmark.m_is_own();

        // copy length:
        adsl_bm_cma->inc_len_name   = inl_len_name;
        adsl_bm_cma->inc_len_url    = inl_len_url;
        adsl_bm_cma->inc_len_user   = inl_len_user;
        adsl_bm_cma->inc_len_pwd    = inl_len_pwd;
        adsl_bm_cma->inc_len_domain = inl_len_domain;

        // copy data itself:
        achl_offset = (char*)adsl_bm_cma + sizeof(dsd_cma_wfa_bmark);
        if ( inl_len_name > 0 ) {
            memcpy( achl_offset, achl_name, inl_len_name );
            achl_offset += inl_len_name;
        }
        if ( inl_len_url > 0 ) {
            memcpy( achl_offset, achl_url, inl_len_url );
            achl_offset += inl_len_url;
        }
        if ( inl_len_user > 0 ) {
            memcpy( achl_offset, achl_user, inl_len_user );
            achl_offset += inl_len_user;
        }
        if ( inl_len_pwd > 0 ) {
            memcpy( achl_offset, achl_pwd, inl_len_pwd );
            achl_offset += inl_len_pwd;
        }
        if ( inl_len_domain > 0 ) {
            memcpy( achl_offset, achl_domain, inl_len_domain );
        }
    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_workstats );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_wfa_bookmarks


#if SM_USE_OWN_WFA_BOOKMARKS
/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_own_wfa_bookmarks
 * save own webfileaccess bookmarks in cma 
 * ATTENTION: this call will overwrite existing own bookmarks
 *            but keep other bookmarks
 *
 * @param[in]   ds_hvector<dsd_wfa_bmark>*  ads_bmarks      bookmarks to be saved
 * @return      bool                                        true = success
 * 
*/
bool ds_usercma::m_set_own_wfa_bookmarks( ds_hvector<dsd_wfa_bmark> *adsp_bmarks )
{
    /*
        first wfa bookmarks in cma are inherited bookmarks
        following are our own bookmarks!
    */

    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_size;                 // new size of cma
    int               inl_inherited;            // number of inherited bookmarks
    int               inl_pos;                  // loop variable
    const char              *achl_url;                // url
    int               inl_len_url;              // length of url
    const char              *achl_name;               // name
    int               inl_len_name;             // length of name
    const char              *achl_user;               // user
    int               inl_len_user;             // length of user
    const char              *achl_pwd;                // password
    int               inl_len_pwd;              // length of password
    const char              *achl_domain;             // domain
    int               inl_len_domain;           // length of domain
    dsd_cma_wfa_bmark *adsl_bm_cma;             // current bookmark in cma
    char              *achl_offset;             // offset for memcpy
    
    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_workstats );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
	inl_size = m_eval_size( (ied_usercma_settings)(ied_wfa_bmarks+1), true, &inl_inherited );

    // new own bookmarks:    
    for (HVECTOR_FOREACH(dsd_wfa_bmark, adsl_cur, *adsp_bmarks)) {
        const dsd_wfa_bmark& dsl_bmark = HVECTOR_GET(adsl_cur);
        dsl_bmark.m_get_url   ( &achl_url,    &inl_len_url    );
        dsl_bmark.m_get_name  ( &achl_name,   &inl_len_name   );
        dsl_bmark.m_get_user  ( &achl_user,   &inl_len_user   );
        dsl_bmark.m_get_pwd   ( &achl_pwd,    &inl_len_pwd    );
        dsl_bmark.m_get_domain( &achl_domain, &inl_len_domain );

        if ( inl_len_url > 0 ) {
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof(dsd_cma_wfa_bmark)
                       + inl_len_url
                       + inl_len_name
                       + inl_len_user
                       + inl_len_pwd
                       + inl_len_domain;
        }
    }

    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new own bookmarks:
    adsc_settings->inc_wfa_bookmarks = inl_inherited + (int)adsp_bmarks->m_size();
    for ( inl_pos = inl_inherited; inl_pos < adsc_settings->inc_wfa_bookmarks; inl_pos++ ) {
        // get buffer in cma:
        adsl_bm_cma = m_get_wfa_bmark( inl_pos );
        if ( adsl_bm_cma == NULL ) {
            continue;
        }

        // get incoming bookmark:
        const dsd_wfa_bmark& dsl_bmark = adsp_bmarks->m_get(inl_pos);
        dsl_bmark.m_get_url   ( &achl_url,    &inl_len_url    );
        dsl_bmark.m_get_name  ( &achl_name,   &inl_len_name   );
        dsl_bmark.m_get_user  ( &achl_user,   &inl_len_user   );
        dsl_bmark.m_get_pwd   ( &achl_pwd,    &inl_len_pwd    );
        dsl_bmark.m_get_domain( &achl_domain, &inl_len_domain );

        if ( inl_len_url < 1 ) {
            continue;
        }

        // copy ownership and position
        adsl_bm_cma->boc_is_own   = dsl_bmark.m_is_own();

        // copy length:
        adsl_bm_cma->inc_len_name   = inl_len_name;
        adsl_bm_cma->inc_len_url    = inl_len_url;
        adsl_bm_cma->inc_len_user   = inl_len_user;
        adsl_bm_cma->inc_len_pwd    = inl_len_pwd;
        adsl_bm_cma->inc_len_domain = inl_len_domain;

        // copy data itself:
        achl_offset = (char*)adsl_bm_cma + sizeof(dsd_cma_wfa_bmark);
        if ( inl_len_name > 0 ) {
            memcpy( achl_offset, achl_name, inl_len_name );
            achl_offset += inl_len_name;
        }
        if ( inl_len_url > 0 ) {
            memcpy( achl_offset, achl_url, inl_len_url );
            achl_offset += inl_len_url;
        }
        if ( inl_len_user > 0 ) {
            memcpy( achl_offset, achl_user, inl_len_user );
            achl_offset += inl_len_user;
        }
        if ( inl_len_pwd > 0 ) {
            memcpy( achl_offset, achl_pwd, inl_len_pwd );
            achl_offset += inl_len_pwd;
        }
        if ( inl_len_domain > 0 ) {
            memcpy( achl_offset, achl_domain, inl_len_domain );
        }
    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_workstats );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_own_wfa_bookmarks
#endif

/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_add_wfa_bookmark
 * add wfa bookmark to cma
 *
 * @param[in]   ds_bookmark*    ads_bmark
 * @return      bool
*/
bool ds_usercma::m_add_wfa_bookmark( dsd_wfa_bmark *adsp_bmark )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_size;                 // new size of cma
    const char              *achl_url;                // url
    int               inl_len_url;              // length of url
    const char              *achl_name;               // name
    int               inl_len_name;             // length of name
    const char              *achl_user;               // user
    int               inl_len_user;             // length of user
    const char              *achl_pwd;                // password
    int               inl_len_pwd;              // length of password
    const char              *achl_domain;             // domain
    int               inl_len_domain;           // length of domain
    dsd_cma_wfa_bmark *adsl_bm_cma;             // current bookmark in cma
    char              *achl_offset;             // offset for memcpy

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_workstats );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // get size of currently saved bookmarks:
    inl_size = m_eval_size( (ied_usercma_settings)(ied_wfa_bmarks+1), false, NULL );

    // add size of new bookmark:
    adsp_bmark->m_get_url   ( &achl_url,    &inl_len_url    );
    adsp_bmark->m_get_name  ( &achl_name,   &inl_len_name   );
    adsp_bmark->m_get_user  ( &achl_user,   &inl_len_user   );
    adsp_bmark->m_get_pwd   ( &achl_pwd,    &inl_len_pwd    );
    adsp_bmark->m_get_domain( &achl_domain, &inl_len_domain );

    inl_size =   ALIGN_INT(inl_size)
               + (int)sizeof(dsd_cma_wfa_bmark)
               + inl_len_url
               + inl_len_name
               + inl_len_user
               + inl_len_pwd
               + inl_len_domain;

    // add saved size:
    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new bookmarks:
    adsc_settings->inc_wfa_bookmarks++;

    // get buffer in cma:
    adsl_bm_cma = m_get_wfa_bmark( adsc_settings->inc_wfa_bookmarks - 1 );
    if ( adsl_bm_cma == NULL ) {
        m_close_settings();
        return false;
    }

    // copy ownership
    adsl_bm_cma->boc_is_own   = adsp_bmark->m_is_own();

    // copy length:
    adsl_bm_cma->inc_len_name   = inl_len_name;
    adsl_bm_cma->inc_len_url    = inl_len_url;
    adsl_bm_cma->inc_len_user   = inl_len_user;
    adsl_bm_cma->inc_len_pwd    = inl_len_pwd;
    adsl_bm_cma->inc_len_domain = inl_len_domain;

    // copy data itself:
    achl_offset = (char*)adsl_bm_cma + sizeof(dsd_cma_wfa_bmark);
    if ( inl_len_name > 0 ) {
        memcpy( achl_offset, achl_name, inl_len_name );
        achl_offset += inl_len_name;
    }
    if ( inl_len_url > 0 ) {
        memcpy( achl_offset, achl_url, inl_len_url );
        achl_offset += inl_len_url;
    }
    if ( inl_len_user > 0 ) {
        memcpy( achl_offset, achl_user, inl_len_user );
        achl_offset += inl_len_user;
    }
    if ( inl_len_pwd > 0 ) {
        memcpy( achl_offset, achl_pwd, inl_len_pwd );
        achl_offset += inl_len_pwd;
    }
    if ( inl_len_domain > 0 ) {
        memcpy( achl_offset, achl_domain, inl_len_domain );
    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_workstats );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_add_wfa_bookmark


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_usr_msg
 * set user message
 *
 * @param[in]   const char* achp_msg
 * @param[in]   int         inp_length
 * @return      bool
*/
bool ds_usercma::m_set_usr_msg( const char* achp_msg, int inp_length )
{
    // initialize some variables:
    bool  bol_ret;                          // return for some func calls
    int   inl_size;                         // new size of cma
    char* achl_target;                      // target address (string copy)

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_default_portlet );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
    inl_size  = m_eval_size( ied_usr_msg, false, NULL );
    inl_size += inp_length;    
    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // copy message:
    achl_target = (char*)(adsc_settings + 1);
    memcpy( achl_target, achp_msg, inp_length );
    adsc_settings->inc_len_umsg = inp_length;

    // copy saved data back:
    bol_ret = m_free_backup( ied_default_portlet );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_usr_msg


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_usr_msg
 * get user message
 *
 * @param[in]   ds_hstring* adsp_msg
 * @return      bool
*/
bool ds_usercma::m_get_usr_msg( ds_hstring* adsp_msg )
{
    char* achl_msg;

    if ( m_open_settings(false) ) {
        achl_msg = (char*)(adsc_settings + 1);
        adsp_msg->m_write( achl_msg, adsc_settings->inc_len_umsg );
        m_close_settings();
        return true;
    }
    return false;
} // end of ds_usercma::m_get_usr_msg

/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_default_portlet
 * set default portlet
 *
 * @param[in]   const char* achp_default_portlet
 * @param[in]   int         inp_length
 * @return      bool
*/
bool ds_usercma::m_set_default_portlet( const char* achp_default_portlet, int inp_length )
{
    // initialize some variables:
    bool  bol_ret;                          // return for some func calls
    int   inl_size;                         // new size of cma
    char* achl_target;                      // target address (string copy)

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_wsg_bmarks );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
    inl_size  = m_eval_size( ied_default_portlet, false, NULL );
    inl_size += inp_length;    
    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // copy message:
	achl_target = (char*)(adsc_settings + 1) + adsc_settings->inc_len_umsg;
    memcpy( achl_target, achp_default_portlet, inp_length );
    adsc_settings->inc_len_default_portlet = inp_length;

    // copy saved data back:
    bol_ret = m_free_backup( ied_wsg_bmarks );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_default_portlet


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_default_portlet
 * get default portlet
 *
 * @param[in]   ds_hstring* adsp_default_portlet
 * @return      bool
*/
bool ds_usercma::m_get_default_portlet( ds_hstring* adsp_default_portlet )
{
    char* achl_msg;

    if ( m_open_settings(false) ) {
        achl_msg = (char*)(adsc_settings + 1) + adsc_settings->inc_len_umsg;
        adsp_default_portlet->m_write( achl_msg, adsc_settings->inc_len_default_portlet );
        m_close_settings();
        return true;
    }
    return false;
} // end of ds_usercma::m_get_default_portlet


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_has_default_portlet
 * check if default portlet is set
 *
 * @return      bool
*/
bool ds_usercma::m_has_default_portlet( ) {
    bool bol_set = false;
    if ( m_open_settings(false) ) {
        bol_set = adsc_settings->inc_len_default_portlet > 0;
        m_close_settings();
        return bol_set;
    }
    return false;
}


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_count_workstations
 * count workstations for current user
 *
 * @return  int
*/
int ds_usercma::m_count_workstations()
{
    int inl_ret = 0;
    if ( m_open_settings(false) ) {
        inl_ret = adsc_settings->inc_workstations;
        m_close_settings();
    }
    return inl_ret;
} // end of ds_usercma::m_count_workstations


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_workstation
 * get workstation by index
 *
 * @param[in]   int             in_index                    index of workstation
 * @param[out]  ds_workstation* ads_wstat                   found workstation
 * @return      bool                                        true = workstation found
 *                                                          otherwise false
*/
bool ds_usercma::m_get_workstation( int inp_index, ds_workstation *adsp_wstat )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    dsd_cma_workstation* adsl_ws_cma;           // current workstation in cma
    char*                achl_name;             // name
    char*                achl_ineta;            // ineta

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get workstation from cma:
    adsl_ws_cma = m_get_workstation( inp_index );
    if ( adsl_ws_cma == NULL ) {
        m_close_settings();
        return false;
    }
    adsp_wstat->m_init( adsc_wsp_helper );

    // set name and ineta:
    achl_name  = (char*)adsl_ws_cma + sizeof(dsd_cma_workstation);
    achl_ineta = achl_name + adsl_ws_cma->inc_len_name;
    adsp_wstat->m_set_name ( achl_name,  adsl_ws_cma->inc_len_name  );
    adsp_wstat->m_set_ineta( achl_ineta, adsl_ws_cma->inc_len_ineta );

    // set other values:
    adsp_wstat->m_set_port( adsl_ws_cma->inc_port );
    adsp_wstat->m_set_mac ( adsl_ws_cma->chrc_mac );
    adsp_wstat->m_set_wait( adsl_ws_cma->inc_wait );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_get_workstation


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_workstation
 * get desktop-on-demand workstation from cma by name
 *
 * @param[in]   const char*     ach_name                    name of requested wstat
 * @param[in]   int             in_len                      length of name
 * @param[out]  ds_workstation* ads_wstat                   found workstation
 * @return      bool                                        true = workstation found
 *                                                          otherwise false
*/
bool ds_usercma::m_get_workstation( const char *achp_name, int inp_len,
                                    ds_workstation *adsp_wstat )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    int                  inl_pos;               // loop variable
    dsd_cma_workstation* adsl_ws_cma;           // current workstation in cma
    char*                achl_name;             // name
    char*                achl_ineta;            // ineta

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // loop through all workstations:
    bol_ret = false;
    for ( inl_pos = 0; inl_pos < adsc_settings->inc_workstations; inl_pos++ ) {
        adsl_ws_cma = m_get_workstation( inl_pos );
        if ( adsl_ws_cma == NULL ) {
            m_close_settings();
            return false;
        }

        if ( inp_len == adsl_ws_cma->inc_len_name ) {
            // get name:
            achl_name  = (char*)adsl_ws_cma + sizeof(dsd_cma_workstation);

            if ( memcmp( achl_name, achp_name, inp_len ) == 0 ) {
                adsp_wstat->m_init( adsc_wsp_helper );

                // get ineta:
                achl_ineta = achl_name + adsl_ws_cma->inc_len_name;

                // set name and ineta:
                adsp_wstat->m_set_name ( achl_name,  adsl_ws_cma->inc_len_name  );
                adsp_wstat->m_set_ineta( achl_ineta, adsl_ws_cma->inc_len_ineta );

                // set other values:
                adsp_wstat->m_set_port( adsl_ws_cma->inc_port );
                adsp_wstat->m_set_mac ( adsl_ws_cma->chrc_mac );
                adsp_wstat->m_set_wait( adsl_ws_cma->inc_wait );

                bol_ret = true;
                break;
            }
        }
    }

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_get_workstation


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_workstations
 * get desktop-on-demand workstations from cma
 *
 * @param[in]   ds_hvector<ds_workstation>* ads_wstats      workstations to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_get_workstations( ds_hvector<ds_workstation> *adsp_wstats )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    int                  inl_pos;               // loop variable
    ds_workstation       dsl_wstat;             // current workstation
    dsd_cma_workstation* adsl_ws_cma;           // current workstation in cma
    char*                achl_name;             // name
    char*                achl_ineta;            // ineta

    // init incoming vector:
    adsp_wstats->m_init( adsc_wsp_helper );
    dsl_wstat.m_init   ( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // loop through all wsg bookmarks:
    for ( inl_pos = 0; inl_pos < adsc_settings->inc_workstations; inl_pos++ ) {
        adsl_ws_cma = m_get_workstation( inl_pos );
        if ( adsl_ws_cma == NULL ) {
            m_close_settings();
            return false;
        }

        // get name and ineta:
        achl_name  = (char*)adsl_ws_cma + sizeof(dsd_cma_workstation);
        achl_ineta = achl_name + adsl_ws_cma->inc_len_name;

        // set name and ineta:
        dsl_wstat.m_set_name ( achl_name,  adsl_ws_cma->inc_len_name  );
        dsl_wstat.m_set_ineta( achl_ineta, adsl_ws_cma->inc_len_ineta );

        // set other values:
        dsl_wstat.m_set_port( adsl_ws_cma->inc_port );
        dsl_wstat.m_set_mac ( adsl_ws_cma->chrc_mac );
        dsl_wstat.m_set_wait( adsl_ws_cma->inc_wait );

        // add to vector:
        adsp_wstats->m_add( dsl_wstat );
    }

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_workstations


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_workstations
 * save desktop-on-demand workstations in cma
 *
 * @param[in]   ds_hvector<ds_workstation>* ads_wstats      workstations to be saved
 * @return      bool                                        true = success
*/
bool ds_usercma::m_set_workstations( ds_hvector<ds_workstation> *adsp_wstats )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    int                  inl_size;              // new size of cma
    int                  inl_pos;               // loop variable
    const char*          achl_name;             // name
    int                  inl_len_name;          // length of name
    const char*          achl_ineta;            // ineta
    int                  inl_len_ineta;         // length of ineta
    dsd_cma_workstation* adsl_ws_cma;           // current workstation in cma

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_portlets );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
    inl_size = m_eval_size( ied_workstats, false, NULL );

    // loop through incoming workstations:
    for ( HVECTOR_FOREACH(ds_workstation, adsl_cur, *adsp_wstats) ) {
        const ds_workstation& dsl_wstat = HVECTOR_GET(adsl_cur);
        dsl_wstat.m_get_name ( &achl_name, &inl_len_name );
        dsl_wstat.m_get_ineta( &achl_ineta, &inl_len_ineta );
        
        if (    inl_len_name  > 0
             && inl_len_ineta > 0 ) {
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof(dsd_cma_workstation)
                       + inl_len_name
                       + inl_len_ineta;
        }
    }

    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new workstations:
    adsc_settings->inc_workstations = (int)adsp_wstats->m_size();
    inl_pos = 0;
    for ( HVECTOR_FOREACH(ds_workstation, adsl_cur, *adsp_wstats) ) {
        const ds_workstation& dsl_wstat = HVECTOR_GET(adsl_cur);
        // get buffer in cma:
        adsl_ws_cma = m_get_workstation( inl_pos++ );
        if ( adsl_ws_cma == NULL ) {
            continue;
        }

        // get incoming bookmark:
        dsl_wstat.m_get_name ( &achl_name,  &inl_len_name  );
        dsl_wstat.m_get_ineta( &achl_ineta, &inl_len_ineta );

        // copy data:
        adsl_ws_cma->inc_port = dsl_wstat.m_get_port();
        adsl_ws_cma->inc_wait = dsl_wstat.m_get_wait();
        dsl_wstat.m_get_mac( adsl_ws_cma->chrc_mac );

        // copy string length:
        adsl_ws_cma->inc_len_name  = inl_len_name;
        adsl_ws_cma->inc_len_ineta = inl_len_ineta;

        // copy strings itself:
        memcpy( (char*)adsl_ws_cma + sizeof(dsd_cma_workstation),
                achl_name, inl_len_name );
        memcpy( (char*)adsl_ws_cma + sizeof(dsd_cma_workstation) + inl_len_name,
                achl_ineta, inl_len_ineta );
    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_portlets );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_workstations


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_cma_portlets
 * get porlets from cma
 *
 * @param[in]   ds_hvector<ds_porlet>* ads_portlets     protlets to be saved
 * @return      bool                                    true = success
*/
bool ds_usercma::m_get_cma_portlets( ds_hvector<ds_portlet> *adsp_portlets )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    int                  inl_pos;               // loop variable
    ds_portlet           dsl_portlet;           // current portlet
    dsd_cma_portlet*     adsl_ptl_cma;          // current portlet in cma
    char*                achl_name;             // name

    // init incoming vector:
    adsp_portlets->m_init( adsc_wsp_helper );
    dsl_portlet.m_init   ( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // loop through all portlets:
    for ( inl_pos = 0; inl_pos < adsc_settings->inc_portlets; inl_pos++ ) {
        adsl_ptl_cma = m_get_portlet( inl_pos );
        if ( adsl_ptl_cma == NULL ) {
            m_close_settings();
            return false;
        }

        // get name:
        achl_name  = (char*)adsl_ptl_cma + sizeof(dsd_cma_portlet);

        // set values:
        dsl_portlet.m_set_name ( achl_name, adsl_ptl_cma->inc_len_name  );
        dsl_portlet.m_set_open ( adsl_ptl_cma->boc_open );

        // add to vector:
        adsp_portlets->m_add( dsl_portlet );
    }

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_cma_portlets


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_portlets
 * save portlets in cma
 *
 * @param[in]   ds_hvector<ds_porlet>* adsp_portlets    portlets to be saved
 * @return      bool                                    true = success
*/
bool ds_usercma::m_set_portlets( ds_hvector<ds_portlet> *adsp_portlets )
{
    // initialize some variables:
    bool                 bol_ret;               // return for some func calls
    int                  inl_size;              // new size of cma
    int                  inl_pos;               // loop variable
    const char*          achl_name;             // name
    int                  inl_len_name;          // length of name
    dsd_cma_portlet*     adsl_ptl_cma;          // current protlet in cma

    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }

    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_jwtsa_conf );
	if ( bol_ret == false )
	{
		m_close_settings();
		return false;
    }
	
    // evaluate new needed length:
    inl_size = m_eval_size( ied_portlets, false, NULL );

    // loop through incoming portlets:
    for ( HVECTOR_FOREACH(ds_portlet, adsl_cur, *adsp_portlets) ) {
        const ds_portlet& dsl_portlet = HVECTOR_GET(adsl_cur);
        dsl_portlet.m_get_name ( &achl_name, &inl_len_name );
        
        if ( inl_len_name  > 0 ) {
            inl_size =   ALIGN_INT(inl_size)
                       + (int)sizeof(dsd_cma_portlet)
                       + inl_len_name;
        }
    }

    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new portlets:
    adsc_settings->inc_portlets = (int)adsp_portlets->m_size();
    inl_pos = 0;
    for ( HVECTOR_FOREACH(ds_portlet, adsl_cur, *adsp_portlets) ) {
        // get current settings portlet:
        const ds_portlet& dsl_portlet = HVECTOR_GET(adsl_cur);
        // get buffer in cma:
        adsl_ptl_cma = m_get_portlet( inl_pos++ );
        if ( adsl_ptl_cma == NULL ) {
            continue;
        }

        // get incoming portlet:
        dsl_portlet.m_get_name( &achl_name,  &inl_len_name  );

        // copy data:
        adsl_ptl_cma->boc_open     = dsl_portlet.m_is_open();
        adsl_ptl_cma->inc_len_name = inl_len_name;
        memcpy( (char*)adsl_ptl_cma + sizeof(dsd_cma_portlet),
                achl_name, inl_len_name );
    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_jwtsa_conf );

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_set_portlets


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_show_flyer
 * is flyer active
 *
 * @return      bool                                        true = show flyer
*/
bool ds_usercma::m_show_flyer()
{
    bool bol_ret;
    if ( m_open_settings(false) ) {
        bol_ret = adsc_settings->boc_flyer;
        m_close_settings();
        return bol_ret;
    }
    return true;
} // end of ds_usercma::m_show_flyer


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_flyer
 * set flyer
 *
 * @return      bool
*/
bool ds_usercma::m_set_flyer( bool bop_show )
{
    if ( m_open_settings(true) ) {
        adsc_settings->boc_flyer = bop_show;
        m_close_settings();
        return true;
    }
    return false;
} // end of ds_usercma::m_set_flyer


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_lastws
 * get last webserver from wsg cma
 *
 * @param[in]   int*        ain_protocol    fill with protocol
 * @param[in]   int*        ain_port        fill with port
 * @return      ds_hstring                  last webserver
*/
ds_hstring ds_usercma::m_get_lastws( int *ainp_protocol, int *ainp_port )
{
    // initialize some variables:
    char       *achl_lastws;
    ds_hstring dsl_lastws( adsc_wsp_helper );

    if ( m_open_wsg(false) ) {
        achl_lastws = (char*)(adsc_wsg + 1);
        dsl_lastws.m_write( achl_lastws, adsc_wsg->inc_len_lastws );
        if ( ainp_protocol != NULL ) {
            *ainp_protocol = adsc_wsg->inc_proto_lastws;
        }
        if ( ainp_port != NULL ) {
            *ainp_port = adsc_wsg->inc_port_lastws;
        }
        m_close_wsg();
    }
    return dsl_lastws;
} // end of ds_usercma::m_get_lastws


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_lastws
 * set last webserver from wsg cma
 *
 * @param[in]   int         in_protocol     protocol
 * @param[in]   const char* ach_lws         last webserver
 * @param[in]   int         in_len          length of last webserver
 * @param[in]   int         in_port         port
 * @return      bool                        true = success
*/
bool ds_usercma::m_set_lastws( int inp_protocol, const char *achp_lws,
                               int inp_len, int inp_port )
{
    // initialize some variables:
    bool bol_ret;
    char *achl_lastws;

    if ( inp_len < 0 ) {
        return false;
    }
    if ( achp_lws == NULL ) {
        inp_len = 0;
    }

    // open cma for writing:
    bol_ret = m_open_wsg( true );
    if ( bol_ret == false ) {
        return false;
    }

    // check length:
    if ( inp_len != adsc_wsg->inc_len_lastws ) {
        // resize cma:
        bol_ret = m_resize_wsg(   (int)sizeof(dsd_usercma_wsg)
                                + inp_len );
        if ( bol_ret == false ) {
            m_close_wsg();
            return false;
        }

        adsc_wsg->inc_len_lastws = inp_len;
    }
    
    // save data:
    adsc_wsg->inc_proto_lastws = inp_protocol;
    adsc_wsg->inc_port_lastws  = inp_port;

    // save new webserver:
    achl_lastws = (char*)(adsc_wsg + 1);
    if ( inp_len > 0 && achp_lws != NULL ) {
        memcpy( achl_lastws, achp_lws, inp_len );
    }

    // close cma:
    m_close_wsg();
    return true;
} // end of ds_usercma::m_set_lastws


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_sso_time
 * get single sign on time in wsg cma
 *
 * @param[in]   int     in_index
 * @return      hl_time_t
*/
hl_time_t ds_usercma::m_get_sso_time( int inp_index )
{
    hl_time_t tm_ret = 0;

    if ( inp_index < 0 || inp_index > LEN_SUPR_SSO ) {
        return 0;
    }

    if ( m_open_wsg(false) ) {
        tm_ret = adsc_wsg->tmrc_supress_sso[inp_index];
        m_close_wsg();
    }
    return tm_ret;
} // end of ds_usercma::m_get_sso_time


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_sso_time
 * set single sign on time in wsg cma
 *
 * @param[in]   int     in_index
 * @param[in]   hl_time_t  il_time
 * @return      bool                true = success
*/
bool ds_usercma::m_set_sso_time( int inp_index, hl_time_t ilp_time )
{
    if ( inp_index < 0 || inp_index > LEN_SUPR_SSO ) {
        return false;
    }

    if ( m_open_wsg(true) ) {
        adsc_wsg->tmrc_supress_sso[inp_index] = ilp_time;
        m_close_wsg();
        return true;
    }
    return false;
} // end of ds_usercma::m_set_sso_time


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_get_ica_port
 *  get ica port from wsg cma
 *
 * @return      int
*/
int ds_usercma::m_get_ica_port()
{
    int inl_port = -1;
    if ( m_open_wsg(false) ) {
        inl_port = adsc_wsg->inc_ica_port;
        m_close_wsg();
    }
    return inl_port;
} // end of ds_usercma::m_get_ica_port


/**
 * \ingroup authlib
 *
 * function ds_usercma::m_set_ica_port
 *  set ica port in wsg cma
 *
 * @return      int
*/
bool ds_usercma::m_set_ica_port( int inp_port )
{
    if ( m_open_wsg(true) ) {
        adsc_wsg->inc_ica_port = inp_port;
        m_close_wsg();
        return true;
    }
    return false;
} // end of ds_usercma::m_get_ica_port


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_reset_ica_counter
 *  reset ica session counter
 *
 * @return  bool
*/
bool ds_usercma::m_reset_ica_count()
{
    if ( m_open_wsg(true) ) {
        adsc_wsg->inc_ica_visits = 0;
        adsc_wsg->unc_ica_active_last = 0;
        m_close_wsg();
        return true;
    }
    return false;
} /* end of ds_usercma::m_reset_ica_count */


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_decrease_ica_count
 *  decrease ica session counter
 *
 * @return  bool
*/
bool ds_usercma::m_decrease_ica_count()
{
    if ( m_open_wsg(true) ) {
        adsc_wsg->inc_ica_visits--;
        adsc_wsg->unc_ica_active_last = this->adsc_wsp_helper->m_cb_get_time();
        if ( adsc_wsg->inc_ica_visits < 0 ) {
            adsc_wsg->inc_ica_visits = 0;
        }
        m_close_wsg();
        return true;
    }
    return false;
} /* end of ds_usercma::m_decrease_ica_count */


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_increase_ica_count
 *  increase ica session counter
 *
 * @return  bool
*/
bool ds_usercma::m_increase_ica_count()
{
    if ( m_open_wsg(true) ) {
        adsc_wsg->inc_ica_visits++;
        m_close_wsg();
        return true;
    }
    return false;
} /* end of ds_usercma::m_increase_ica_count */


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_is_ica_active
 *  check if still ica sessions active while comparing session counter
 *
 * @return  bool
*/
bool ds_usercma::m_is_ica_active()
{
    bool bol_ret;
    if ( m_open_wsg(false) ) {
        bol_ret = (adsc_wsg->inc_ica_visits > 0);
        if(!bol_ret) {
            hl_time_t unl_time_now = this->adsc_wsp_helper->m_cb_get_time();
            hl_time_t unl_time_delta = unl_time_now-adsc_wsg->unc_ica_active_last;
            if(unl_time_delta >= 0 && unl_time_delta <= 5)
                bol_ret = true;
        }
		if(adsc_wsg->inc_ica_port <= 0)
			bol_ret = false;
        m_close_wsg();
        return bol_ret;
    }
    return false;
} /* end of ds_usercma::m_is_ica_active */


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_export_inetas
 * get all saved INETAs from cma
 *
 * @param[in]   ds_hvector_btype<dsd_ineta_temp>*   ads_ppp_inetas
 * @param[in]   ds_hvector_btype<dsd_ineta_temp>*   ads_htcp_inetas
 * @return      bool                                true = success
*/
bool ds_usercma::m_export_inetas( ds_hvector_btype<dsd_ineta_temp> *adsp_ppp_inetas,
                                  ds_hvector_btype<dsd_ineta_temp> *adsp_htcp_inetas )
{
    // initialize some variables:
    bool                bol_ret;                    // return for several function calls
    int                 inl_pos;                    // loop variable
    dsd_ineta_temp      dsl_ineta;                  // current ineta for vector
    dsd_ineta_single_1* adsl_ineta_cma;             // current ineta in cma
    dsd_config_ineta_1* adsl_ineta_group;           // current ineta group in cma

    // check if cma is existing:
    bol_ret = adsc_wsp_helper->m_cb_exist_cma( chrc_ineta, inc_ineta );
    if ( bol_ret == false ) {
        return true; // not existing -> nothing to export (NO error)
    }

    // open cma for reading
    bol_ret = m_open_ineta( false );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // get PPP INETAs:
    //-------------------------------------------
    adsl_ineta_group = m_get_config_struct( DEF_INETA_GROUP_PPP );
    if ( adsl_ineta_group != NULL ) {
        for ( inl_pos = 0; inl_pos < adsl_ineta_group->imc_no_ineta; inl_pos++ ) {
            adsl_ineta_cma = m_get_ineta( inl_pos, DEF_INETA_GROUP_PPP );
            if ( adsl_ineta_cma != NULL ) {
                dsl_ineta.usc_family = adsl_ineta_cma->usc_family;
                dsl_ineta.usc_length = adsl_ineta_cma->usc_length;
                memcpy( dsl_ineta.chrc_ineta, (adsl_ineta_cma + 1),
                        adsl_ineta_cma->usc_length );
                adsp_ppp_inetas->m_add( dsl_ineta );
            }
        }
    }

    //-------------------------------------------
    // get HTCP INETAs:
    //-------------------------------------------
    adsl_ineta_group = m_get_config_struct( DEF_INETA_GROUP_HTCP );
    if ( adsl_ineta_group != NULL ) {
        for ( inl_pos = 0; inl_pos < adsl_ineta_group->imc_no_ineta; inl_pos++ ) {
            adsl_ineta_cma = m_get_ineta( inl_pos, DEF_INETA_GROUP_HTCP );
            if ( adsl_ineta_cma != NULL ) {
                dsl_ineta.usc_family = adsl_ineta_cma->usc_family;
                dsl_ineta.usc_length = adsl_ineta_cma->usc_length;
                memcpy( dsl_ineta.chrc_ineta, (adsl_ineta_cma + 1),
                        adsl_ineta_cma->usc_length );
                adsp_htcp_inetas->m_add( dsl_ineta );
            }
        }
    }

    // close cma again:
    m_close_ineta();
    return true;
} // end of ds_usercma::m_export_inetas


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_import_inetas
 * save INETAs in cma
 *
 * @param[in]   ds_hvector_btype<dsd_ineta_temp>*   ads_ppp_inetas
 * @param[in]   ds_hvector_btype<dsd_ineta_temp>*   ads_htcp_inetas
 * @return      bool                                true = success
*/
bool ds_usercma::m_import_inetas( ds_hvector_btype<dsd_ineta_temp> *adsp_ppp_inetas,
                                  ds_hvector_btype<dsd_ineta_temp> *adsp_htcp_inetas )
{
    // initialize some variables:
    bool                bol_ret;                    // return for several function calls
    int                 inl_needed_ppp  = 0;        // needed memory size for ppp inetas
    int                 inl_needed_htcp = 0;        // needed memory size for htcp inetas
    int                 inl_total;                  // total needed memory
    int                 inl_offset_ppp;             // offset of ppp inetas in cma
    int                 inl_offset_htcp;            // offset of htcp inetas in cma
    dsd_ineta_single_1* adsl_ineta_cma;             // current ineta in cma
    
    //-------------------------------------------
    // check incoming sizes:
    //-------------------------------------------
    if (    adsp_ppp_inetas->m_empty()
         && adsp_htcp_inetas->m_empty() ) {
        return true; // this is NO error (cause everything that should be saved is saved)!
    }

    //-------------------------------------------
    // evaluate needed memory for ppp:
    //-------------------------------------------
    if ( !adsp_ppp_inetas->m_empty() ) {
        inl_needed_ppp = (int)sizeof(struct dsd_config_ineta_1);
    }
    for ( HVECTOR_FOREACH(dsd_ineta_temp, adsl_cur, *adsp_ppp_inetas) ) {
        const dsd_ineta_temp& dsl_ineta = HVECTOR_GET(adsl_cur);

#ifndef DEF_DONT_ALIGN_SINGLE
        inl_needed_ppp =   ALIGN_INT(inl_needed_ppp)
                         + (int)sizeof( dsd_ineta_single_1 )
                         + dsl_ineta.usc_length;
#else
        inl_needed_ppp +=   (int)sizeof( dsd_ineta_single_1 )
                          + dsl_ineta.usc_length;
#endif
    }

    //-------------------------------------------
    // evaluate needed memory for htcp:
    //-------------------------------------------
    if ( !adsp_htcp_inetas->m_empty() ) {
        inl_needed_htcp = (int)sizeof(struct dsd_config_ineta_1);
    }
    for ( HVECTOR_FOREACH(dsd_ineta_temp, adsl_cur, *adsp_htcp_inetas) ) {
        const dsd_ineta_temp& dsl_ineta = HVECTOR_GET(adsl_cur);

#ifndef DEF_DONT_ALIGN_SINGLE
        inl_needed_htcp =   ALIGN_INT(inl_needed_htcp)
                          + (int)sizeof( dsd_ineta_single_1 )
                          + dsl_ineta.usc_length;
#else
        inl_needed_htcp +=   (int)sizeof( dsd_ineta_single_1 )
                           + dsl_ineta.usc_length;
#endif
    }

    //-------------------------------------------
    // evaluate total needed memory:
    //-------------------------------------------
    inl_total  = (int)sizeof(dsd_ineta_cma_data);
    if ( inl_needed_ppp > (int)sizeof(struct dsd_config_ineta_1) ) {
        inl_total       = ALIGN_INT( inl_total );
        inl_offset_ppp  = inl_total;
        inl_total      += inl_needed_ppp;
    } else {
        inl_offset_ppp  = 0;
    }
    if ( inl_needed_htcp > (int)sizeof(struct dsd_config_ineta_1) ) {
        inl_total        = ALIGN_INT( inl_total );
        inl_offset_htcp  = inl_total;
        inl_total       += inl_needed_htcp;
    } else {
        inl_offset_htcp  = 0;
    }

    if (    inl_offset_ppp  == 0
         && inl_offset_htcp == 0 ) {
        return false;
    }

    //-------------------------------------------
    // create cma:
    //-------------------------------------------
    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_ineta, inc_ineta,
                                                NULL, inl_total, inc_idle_timeout );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // open cma for writing:
    //-------------------------------------------
    bol_ret = m_open_ineta( true );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // save offsets:
    //-------------------------------------------
    adsc_ineta->inc_off_ppp  = inl_offset_ppp;
    adsc_ineta->inc_off_htcp = inl_offset_htcp;

    //-------------------------------------------
    // copy ppp inetas to cma:
    //-------------------------------------------
    if ( adsc_ineta->inc_off_ppp > 0 ) {
        bol_ret = m_fill_config_struct( (int)adsp_ppp_inetas->m_size(),
                                        inl_needed_ppp,
                                        DEF_INETA_GROUP_PPP );
        if ( bol_ret == false ) {
            m_close_ineta();
            return false;
        }
        int uinl_pos = 0;
        for ( HVECTOR_FOREACH(dsd_ineta_temp, adsl_cur, *adsp_ppp_inetas) ) {
            // get ineta from vector:
            const dsd_ineta_temp& dsl_ineta = HVECTOR_GET(adsl_cur);

            // get ineta from cma:
            adsl_ineta_cma = m_get_ineta( uinl_pos, DEF_INETA_GROUP_PPP );
            if ( adsl_ineta_cma == NULL ) {
                m_close_ineta();
                return false;
            }

            // copy the data to cma:
            adsl_ineta_cma->usc_family = dsl_ineta.usc_family;
            adsl_ineta_cma->usc_length = dsl_ineta.usc_length;
            memcpy( (adsl_ineta_cma + 1), dsl_ineta.chrc_ineta,
                    dsl_ineta.usc_length );
            uinl_pos++;
        }
    }

    //-------------------------------------------
    // copy htcp inetas to cma:
    //-------------------------------------------
    if ( adsc_ineta->inc_off_htcp > 0 ) {
        bol_ret = m_fill_config_struct( (int)adsp_htcp_inetas->m_size(),
                                        inl_needed_htcp,
                                        DEF_INETA_GROUP_HTCP );
        if ( bol_ret == false ) {
            m_close_ineta();
            return false;
        }
        int uinl_pos = 0;
        for ( HVECTOR_FOREACH(dsd_ineta_temp, adsl_cur, *adsp_htcp_inetas) ) {
            // get ineta from vector:
            const dsd_ineta_temp& dsl_ineta = HVECTOR_GET(adsl_cur);

            // get ineta from cma:
            adsl_ineta_cma = m_get_ineta( (int)uinl_pos, DEF_INETA_GROUP_HTCP );
            if ( adsl_ineta_cma == NULL ) {
                m_close_ineta();
                return false;
            }

            // copy the data to cma:
            adsl_ineta_cma->usc_family = dsl_ineta.usc_family;
            adsl_ineta_cma->usc_length = dsl_ineta.usc_length;
            memcpy( (adsl_ineta_cma + 1), dsl_ineta.chrc_ineta,
                    dsl_ineta.usc_length );
            uinl_pos++;
        }
    }

    // close cma again:
    m_close_ineta();
    return true;
} // end of ds_usercma::m_import_inetas


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_open_inetas
 * open cma and return PPP and HTCP inetas
 * ATTENTION:   this function call will keep cma open!!!
 *              a call to m_close_inetas is needed
 *
 * @param[out]     dsd_config_ineta_1** aads_ppp_inetas
 * @param[out]     dsd_config_ineta_1** aads_htcp_inetas
 * @return         bool                                     true = success
*/
bool ds_usercma::m_open_inetas( dsd_config_ineta_1 **aadsp_ppp_inetas,
                                dsd_config_ineta_1 **aadsp_htcp_inetas )
{
    // initialize some variables:
    bool bol_ret;

    // open cma for reading:
    bol_ret = m_open_ineta( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get ppp inetas:
    if ( adsc_ineta->inc_off_ppp > 0 ) {
        *aadsp_ppp_inetas = (dsd_config_ineta_1*)((char*)adsc_ineta + adsc_ineta->inc_off_ppp);
    } else {
        *aadsp_ppp_inetas = NULL;
    }

    // get htcp inetas:
    if ( adsc_ineta->inc_off_htcp > 0 ) {
        *aadsp_htcp_inetas = (dsd_config_ineta_1*)((char*)adsc_ineta + adsc_ineta->inc_off_htcp);
    } else {
        *aadsp_htcp_inetas = NULL;
    }

    return true;
} // end of ds_usercma::m_open_inetas


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_close_inetas
 * close cma (from call m_open_inetas)
 *
 * @param[in/out]  dsd_config_ineta_1 **aadsp_ppp_inetas
 * @param[in/out]  dsd_config_ineta_1 **aadsp_htcp_inetas
 * @return         bool                                     true = success
*/
bool ds_usercma::m_close_inetas( dsd_config_ineta_1 **aadsp_ppp_inetas,
                                 dsd_config_ineta_1 **aadsp_htcp_inetas )
{
    *aadsp_ppp_inetas = NULL;
    *aadsp_htcp_inetas = NULL;
    return m_close_ineta();
} // end of ds_usercma::m_close_inetas


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_add_roles
 * add possibles roles for user to cma
 * this function can only be called once
 *
 * @param[in]   ds_hvectpr_btype<dsd_role*> *adsp_vroles
 * @return      bool
*/
bool ds_usercma::m_add_roles( ds_hvector_btype<dsd_role*> *adsp_vroles )
{
    // initialize some variables:
    bool        bol_ret;                    // return value
    int         inl_needed;                 // needed length
    int         inl_offset;                 // working offset

    // check if cma exists already:
    bol_ret = adsc_wsp_helper->m_cb_exist_cma( chrc_roles, inc_roles );
    if ( bol_ret == true ) {
        /*
            cma exists already
            -> possible roles are already saved
            -> do nothing
        */
        return false;
    }

    // evaluate needed length:
    inl_needed = 0;
    for ( HVECTOR_FOREACH(dsd_role*, adsl_cur, *adsp_vroles) ) {
        const dsd_role* adsl_cur_role = HVECTOR_GET(adsl_cur);
        inl_needed += adsl_cur_role->inc_len_name + 1;
    }

    // create cma:
    bol_ret = m_create_roles( inl_needed );
    if ( bol_ret == false ) {
        return false;
    }

    // open cma for writing:
    bol_ret = m_open_roles( true );
    if (    bol_ret   == false
         || inc_rclen != inl_needed ) {
        return false;
    }

    // copy the data:
    inl_offset = 0;
    for ( HVECTOR_FOREACH(dsd_role*, adsl_cur, *adsp_vroles) ) {
        const dsd_role* adsl_cur_role = HVECTOR_GET(adsl_cur);
        memcpy( (achc_roles + inl_offset),
                adsl_cur_role->achc_name,
                adsl_cur_role->inc_len_name );
        inl_offset += adsl_cur_role->inc_len_name + 1;
        if ( inl_offset > inc_rclen ) {
            return false;
        }
    }

    // close cma again:
    m_close_roles();
    return true;
} // end of ds_usercma::m_add_roles


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_roles
 *
 * @param[in]   ds_hvectpr_btype<dsd_role*> *adsp_vroles
 * @return      bool
*/
bool ds_usercma::m_get_roles( ds_hvector_btype<dsd_role*> *adsp_vroles )
{
    // initialize some variables:
    bool                bol_ret;            // return value
    dsd_role*           adsl_cur_role;      // current role
    int                 inl_offset;         // working offset
    char*               achl_name;          // found name
    int                 inl_len_name;       // lenght of found name
    dsd_wspat_pconf_t*  adsl_wspat_config;  // config from hobwspat

    // get config from wspat:
    adsl_wspat_config = adsc_wsp_helper->m_get_wspat_config();
    if ( adsl_wspat_config == NULL ) {
        return false;
    }

    // open cma for reading:
    bol_ret = m_open_roles( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get roles:
    inl_offset    = 0;
    adsl_cur_role = adsl_wspat_config->adsc_roles;
    while ( inl_offset < inc_rclen ) {
        achl_name    = achc_roles + inl_offset;
        inl_len_name = (int)strlen(achl_name);

        if ( inl_len_name > 0 ) {
            while ( adsl_cur_role != NULL ) {
                if (    inl_len_name == adsl_cur_role->inc_len_name
                     && memcmp( achl_name, adsl_cur_role->achc_name, inl_len_name ) == 0 ) {
                    adsp_vroles->m_add( adsl_cur_role );
                    adsl_cur_role = adsl_cur_role->adsc_next;
                    break;
                }
                // get next element:
                adsl_cur_role = adsl_cur_role->adsc_next;
            }
        }

        inl_offset += inl_len_name + 1;
    }

    // close cma again:
    m_close_roles();
    return true;
} // end of ds_usercma::m_get_roles


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_is_in_list
 *
 * @param[in]   const char  *achp_role
 * @param[in]   int         inp_len
 * @return      bool
*/
bool ds_usercma::m_is_in_list( const char *achp_role, int inp_len )
{
    // initialize some variables:
    bool    bol_ret;                        // return value
    int     inl_offset;                     // working offset
    char*   achl_name;                      // found name
    int     inl_len_name;                   // lenght of found name

    // open cma for reading:
    bol_ret = m_open_roles( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get roles:
    inl_offset = 0;
    bol_ret    = false;
    while ( inl_offset < inc_rclen ) {
        achl_name    = achc_roles + inl_offset;
        inl_len_name = (int)strlen(achl_name);

        if (    inl_len_name == inp_len
             && memcmp( achl_name, achp_role, inp_len ) == 0 ) {
            bol_ret = true;
            break;
        }

        inl_offset += inl_len_name + 1;
    }

    // close cma again:
    m_close_roles();
    return bol_ret;
} // end of ds_usercma::m_is_in_list


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_select_role
 *
 * @param[in]   dsd_role *adsp_role
*/
void ds_usercma::m_select_role( dsd_role* adsp_role )
{
    adsc_srole = adsp_role;
	if(adsp_role != NULL)
		inc_idle_timeout = adsp_role->dsc_time_limits.in_max_period;
	else
		inc_idle_timeout = AT_DEF_MAX_PERIOD;
#if 0
    if ( inc_idle_timeout != adsc_srole->dsc_time_limits.in_max_period ) {
        inc_idle_timeout = adsp_role->dsc_time_limits.in_max_period;
        m_update_retention();
    }
#endif
} // end of ds_usercma::m_select_role


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_role
 *
 * @return   dsd_role*
*/
dsd_role* ds_usercma::m_get_role()
{
    return adsc_srole;
} // end of ds_usercma::m_get_role


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_select_domain
 * save selected domain configuration for faster access
 *
 * @param[in]   dsd_domain   *adsp_domain
*/
void ds_usercma::m_select_domain( struct dsd_domain *adsp_domain )
{
    adsc_domain = adsp_domain;
} // end of ds_usercma::m_select_domain


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_domain
 * get selected domain configuration
 *
 * @return  dsd_domain*
*/
struct dsd_domain* ds_usercma::m_get_domain()
{
    return adsc_domain;
} // end of ds_usercma::m_get_domain


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_domain_admin
 *
 * @param[out]  char    **aachp_dn          ptr to admin dn
 * @param[out]  int     *ainp_len_dn        length of admin dn
 * @param[out]  char    **aachp_pwd         ptr to admin password
 * @param[out]  int     *ainp_len_pwd       length of admin password
*/
void ds_usercma::m_get_domain_admin( char **aachp_dn, int *ainp_len_dn,
                                     char **aachp_pwd, int *ainp_len_pwd  )
{
    if ( !adsc_domain ) {
        *ainp_len_dn  = 0;
        *ainp_len_pwd = 0;
        return;
    }

    *aachp_dn     = adsc_domain->achc_dn_admin;
    *ainp_len_dn  = adsc_domain->inc_len_dn_admin;
    *aachp_pwd    = adsc_domain->achc_pwd_admin;
    *ainp_len_pwd = adsc_domain->inc_len_pwd_admin;
} // end of ds_usercma::m_get_domain_admin


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_auth_equals_config_ldap
 * check if authentication ldap (if any) equals configuration ldap
 *
 * @return  bool        true = equals
 *                      false otherwise
*/
bool ds_usercma::m_auth_equals_config_ldap()
{
    // initialize some variables:
    int  inl_auth_method;

    if ( !adsc_domain ) {
        return false;
    }

    enum ied_usercma_login_flags iel_auth_flags;
    inl_auth_method = m_get_authmethod(iel_auth_flags);
    switch ( inl_auth_method ) {
        case DEF_CLIB1_CONF_LDAP:
        case DEF_CLIB1_CONF_DYN_LDAP:
#if SM_USE_CERT_AUTH
            if((iel_auth_flags & ied_usercma_login_cert_auth) != 0)
                return false;
#endif
            return adsc_domain->boc_ldap_eq_name;
        default:
            return false;
    }
} // end of ds_usercma::m_auth_equals_config_ldap


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_select_config_ldap
 * get selected domain configuration
 *
 * @return  dsd_domain*
*/
bool ds_usercma::m_select_config_ldap()
{
    // initialize some variables:
    int  inl_auth_method;
    bool bol_ret;

    if ( !adsc_domain ) {
        return false;
    }

    enum ied_usercma_login_flags iel_auth_flags;
    inl_auth_method = m_get_authmethod(iel_auth_flags);

    /*
        reset already set ldap server
    */
    if ( inl_auth_method == DEF_CLIB1_CONF_DYN_LDAP ) {
        adsc_wsp_helper->m_reset_ldap_srv();
    }

    if (    adsc_domain->inc_len_ldap  > 0
         && adsc_domain->achc_ldap    != NULL ) {
        /*
            we have a corresponding ldap configured in domain
               -> select this one
                  if this is successful we are ready
                  if not configuration is wrong
        */
        bol_ret = adsc_wsp_helper->m_set_ldap_srv( adsc_domain->achc_ldap,
                                                   adsc_domain->inc_len_ldap );
        if ( bol_ret == true ) {
            return true;
        }
    }

    /*
        we have no corrensponding ldap configured
        or select failed
    */
    switch ( inl_auth_method ) {
        case DEF_CLIB1_CONF_RADIUS:
        case DEF_CLIB1_CONF_USERLI:
            /*
                if there are one ldap server configured
                we select the one and only ldap server
                otherwise we cannot go on
            */
            if ( (adsc_wsp_helper->m_get_wsp_auth() & DEF_CLIB1_CONF_DYN_LDAP) != DEF_CLIB1_CONF_DYN_LDAP ) {
                return adsc_wsp_helper->m_cb_set_ldap_srv( 0 );
            }
            return false;

        case DEF_CLIB1_CONF_KRB5:
        case DEF_CLIB1_CONF_DYN_KRB5:
            /*
                we use the wsp configuration "corresponding-LDAP-service"
                WSP should select LDAP by itself
            */
            return true;

        case DEF_CLIB1_CONF_LDAP:
        case DEF_CLIB1_CONF_DYN_LDAP:
            /*
                we use the same ldap server we have used for authentication
            */
            return adsc_wsp_helper->m_set_ldap_srv( adsc_domain->achc_name,
                                                    adsc_domain->inc_len_name );
    }
    return false;
} // end of ds_usercma::m_select_config_ldap


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_check
 * get name of successful compliance check
 *
 * @param[out]  char**  aach_name       name of successful check
 * @param[out]  int*    ain_len         length of name
 * @return      bool                    true = success
*/
bool ds_usercma::m_get_check( const char **aachp_name, int *ainp_len )
{
    //-------------------------------------------
    // is already a role selected?
    //-------------------------------------------
    if ( adsc_srole == NULL ) {
        return false;
    }

    *aachp_name = adsc_srole->achc_check;
    *ainp_len   = adsc_srole->inc_len_check;
    return true;
} // end of ds_usercma::m_get_check


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_role_name
 * get name of selected role
 *
 * @param[out]  char**  aach_name       name of selected role
 * @param[out]  int*    ain_len         length of name
 * @return      bool                    true = success
*/
bool ds_usercma::m_get_role_name( const char **aachp_name, int *ainp_len )
{
    //-------------------------------------------
    // is already a role selected?
    //-------------------------------------------
    if ( adsc_srole == NULL ) {
        return false;
    }

    *aachp_name = adsc_srole->achc_name;
    *ainp_len   = adsc_srole->inc_len_name;
    return true;
} // end of ds_usercma::m_get_role_name


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_welcomepage
 *
 * @param[out]  char**  aach_wpage
 * @param[out]  int*    ain_len_wpage
 * @return      bool
*/
bool ds_usercma::m_get_welcomepage( const char **aachp_wpage, int *ainp_len )
{
    if ( adsc_srole == NULL ) {
        return false;
    }

    if ( adsc_srole->inc_len_wpage > 0 ) {
        *aachp_wpage = adsc_srole->achc_wpage;
        *ainp_len    = adsc_srole->inc_len_wpage;
        return true;
    }
    return false;
} // end of ds_usercma::m_get_welcomepage


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_gui_skin
 *
 * @param[out]  char**  aach_skin
 * @param[out]  int*    ain_len
 * @return      bool
*/
bool ds_usercma::m_get_gui_skin( const char **aachp_skin, int *ainp_len )
{
    if ( adsc_srole == NULL ) {
        return false;
    }

    if ( adsc_srole->inc_len_skin > 0 ) {
        *aachp_skin = adsc_srole->achc_skin;
        *ainp_len   = adsc_srole->inc_len_skin;
        return true;
    }
    return false;
} // end of ds_usercma::m_get_gui_skin


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_portlets
 * portlets can be saved in
 *  - user settings
 *  - user role
 * compare this two lists and return a merged version
 *
 * @param[in/out]   ds_hvector<ds_portlet>* adsv_portlets   output portlets
 * @return          bool                                    true = success
*/
bool ds_usercma::m_get_portlets( ds_hvector<ds_portlet> *adsvp_portlets )
{
    //-------------------------------------------
    // is already a role selected?
    //-------------------------------------------
    if ( adsc_srole == NULL ) {
        return false;
    }

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    adsvp_portlets->m_init( adsc_wsp_helper );

    //-------------------------------------------
    // merge portlets from role and settings:
    //-------------------------------------------
    return m_merge_portlets( adsvp_portlets );
} // end of ds_usercma::m_get_portlets


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_portlet
 * get portlet by index
 *
 * @param[in]       int         in_index        position index
 * @param[in/out]   ds_portlet* ads_portlet     output portlet
 * @return          bool                        true = success
*/
bool ds_usercma::m_get_portlet( int inp_index, ds_portlet *adsp_portlet )
{
    // initialize some variables:
    bool                   bol_ret;
    ds_hvector<ds_portlet> dsv_portlets;

    if ( inp_index < 0 ) {
        return false;
    }

    bol_ret = m_merge_portlets( &dsv_portlets );
    if ( bol_ret == false ) {
        return false;
    }

    if ( inp_index >= (int)dsv_portlets.m_size() ) {
        return false;
    }

    *adsp_portlet = dsv_portlets.m_get( inp_index );
    return true;
} // end of ds_usercma::m_get_portlet


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_count_portlets
 * count allowed portlets for current user
 *
 * @return  int
*/
int ds_usercma::m_count_portlets()
{
    /*
        there can't be more portlets than are allowed in role
        so, for counting it is unnecessary which and how many
        portlets are saved in user settings
    */
    dsd_role_portlet* adsl_cur;
    int               inl_count;
    
    //-------------------------------------------
    // is already a role selected?
    //-------------------------------------------
    if ( adsc_srole == NULL ) {
        return 0;
    }

    //-------------------------------------------
    // loop through portlets:
    //-------------------------------------------
    adsl_cur  = adsc_srole->adsc_portlets;
    inl_count = 0;
    while ( adsl_cur != NULL ) {
        inl_count++;
        adsl_cur = adsl_cur->adsc_next;
    }

    return inl_count;
} // end of ds_usercma::m_count_portlets


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_is_portlet_allowed
 *
 * @param[in]   const char* ach_name        portlet name
 * @param[in]   int         in_len          length of portlet name
 * @return      bool
*/
bool ds_usercma::m_is_portlet_allowed( const char *achp_name, int inp_len )
{
    // initialize some variables:
    dsd_role_portlet* adsl_portlet;

    //-------------------------------------------
    // check input:
    //-------------------------------------------
    if (    achp_name  == NULL
         || inp_len     < 1    
         || adsc_srole == NULL ) {
        return false;
    }

    //-------------------------------------------
    // get all role portlets:
    //-------------------------------------------
    adsl_portlet = adsc_srole->adsc_portlets;

    //-------------------------------------------
    // loop through portlets:
    //-------------------------------------------
    while ( adsl_portlet != NULL ) {
        if (    adsl_portlet->achc_name                                != NULL
             && adsl_portlet->inc_len_name                             == inp_len
             && memcmp( adsl_portlet->achc_name, achp_name, inp_len ) == 0      ) {
            return true;
        }

        //---------------------------------------
        // get next portlet:
        //---------------------------------------
        adsl_portlet = adsl_portlet->adsc_next;
    }
    return false;
} // end of ds_usercma::m_is_portlet_allowed


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_is_caching_allowed
 *
 * @return      bool
*/
bool ds_usercma::m_is_caching_allowed()
{
    // is already a role selected?
    if ( adsc_srole == NULL ) {
        return false;
    }

    return adsc_srole->boc_enable_bcache;
} // end of ds_usercma::m_is_caching_allowed


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_is_config_allowed
 *
 * @return  bool
*/
bool ds_usercma::m_is_config_allowed( int inp_config )
{
    if ( adsc_srole == NULL ) {
        return false;
    }
    return ((adsc_srole->inc_allowed_conf & inp_config) == inp_config);
} // end of ds_user_cma::m_is_config_allowed


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_get_axss_time
 *
 * @return  hl_time_t                          expiration time
*/
hl_time_t ds_usercma::m_get_axss_time()
{
    hl_time_t tml_ret = 0;
    if ( m_open_axss(false) ) {
        tml_ret = adsc_axss->tmc_expire;
        m_close_axss();
    }
    return tml_ret;
} // end of ds_usercma::m_get_axss_time


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_set_axss_time
 *
 * @param[in]   hl_time_t                      expiration time
 * @return      bool                        true = success
*/
bool ds_usercma::m_set_axss_time( hl_time_t tmp_expires )
{
    if ( m_open_axss(true) ) {
        adsc_axss->tmc_expire = tmp_expires;
        m_close_axss();
        return true;
    }
    return false;
} // end of ds_usercma::m_set_axss_time


/*+---------------------------------------------------------------------+*/
/*| static public functions:                                            |*/
/*+---------------------------------------------------------------------+*/
/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_create_name
 * create name of base cma
 *
 * @param[in]   const char   *achp_user     username
 * @param[in]   int          inp_ulen       length username
 * @param[in]   const char   *achp_group    user group
 * @param[in]   int          inp_glen       length group
 * @param[in]   char         chrp_session   session number
 * @return      int                         filled output buffer
*/
int ds_usercma::m_create_name( const char *achp_user,  int inp_ulen,
                               const char *achp_group, int inp_glen,
                               const dsd_cma_session_no& rdsp_cma_session_no,
                               char *achp_buffer, int inp_blen )
{
    // initialize some variables:
    int inl_pos;

    /*
        base cma name will look like this:

        +-----+---+------...-+---+---------...-+---+----------------+
        | usr | / | group    | / | username    | / | session number |
        +-----+---+------...-+---+---------...-+---+----------------+
        |  3  | 1 | variable | 1 | variable    | 1 |        1       |
    */

	 // check minimal length
    inl_pos = (int)strlen(USERCMA_NAME_PREFIX);
    if ( inp_blen <   inl_pos  + 1  /* prefix / */
                    + inp_glen + 1  /* group  / */
                    + inp_ulen + 1  /* user   / */
                    + 3             /* session  */ ) {
        return -1;
    }

    memcpy( achp_buffer, USERCMA_NAME_PREFIX, inl_pos );
    achp_buffer[inl_pos] = '/';
    inl_pos++;

#if SM_AUTHENTICATE_CASE_SENSITIVE
    int inl_ret = m_cpy_vx_vx( &achp_buffer[inl_pos], inp_blen - inl_pos, ied_chs_utf_8, (void*)achp_group, inp_glen, ied_chs_utf_8 );
#else
    int inl_ret = m_cpy_uc_vx_vx( &achp_buffer[inl_pos], inp_blen - inl_pos, ied_chs_utf_8, (void*)achp_group, inp_glen, ied_chs_utf_8 );
#endif
	if(inl_ret < 0)
		return -1;
	inl_pos += inl_ret;

    achp_buffer[inl_pos] = '/';
    inl_pos++;

#if SM_AUTHENTICATE_CASE_SENSITIVE2
    inl_ret = m_cpy_vx_vx( &achp_buffer[inl_pos], inp_blen - inl_pos, ied_chs_utf_8, (void*)achp_user, inp_ulen, ied_chs_utf_8 );
#else
    inl_ret = m_cpy_uc_vx_vx( &achp_buffer[inl_pos], inp_blen - inl_pos, ied_chs_utf_8, (void*)achp_user, inp_ulen, ied_chs_utf_8 );
#endif
	if(inl_ret < 0)
		return -1;
	inl_pos += inl_ret;
    //memcpy( &achp_buffer[inl_pos], achp_user, inp_ulen );
    //inl_pos += inp_ulen;
    achp_buffer[inl_pos] = '/';
    inl_pos++;

	 char* x = &achp_buffer[inl_pos];
    int inl_len = sprintf_s(x, inp_blen-inl_pos, "%03u", (unsigned int)rdsp_cma_session_no.ucc_session_no);
	 if(inl_len <= 0)
		 return -1;
	 inl_pos += inl_len;
	 //achp_buffer[inl_pos] = chp_session;
    //inl_pos++;

    return inl_pos;
} // end of ds_usercma::m_create_name

int ds_usercma::m_create_cma_name(const dsd_login_info& rdsp_login_info,
	char* chrl_buffer, int inp_maxlen, const dsd_const_string& rdsp_suffix)
{
	//-------------------------------------------
	 // create name:
	 //-------------------------------------------
	int inl_main_len = m_create_name(rdsp_login_info.dsc_user.m_get_ptr(), rdsp_login_info.dsc_user.m_get_len(),
		rdsp_login_info.dsc_domain.m_get_ptr(), rdsp_login_info.dsc_domain.m_get_len(),
		rdsp_login_info.dsc_session_no, chrl_buffer, inp_maxlen );
	 if ( inl_main_len < 1 ) {
		  return -1;
	 }

	 //-------------------------------------------
	 // add login suffix:
	 //-------------------------------------------
	 int inl_blen = m_get_name( chrl_buffer, inl_main_len, chrl_buffer,
									inp_maxlen, rdsp_suffix );
	 if ( inl_blen < 1 ) {
		  return -1;
	 }
	 return inl_blen;
}

#if SM_USE_NEW_CMA_NAMES
int ds_usercma::m_exists_user(ds_wsp_helper *adsp_wsp_helper, const dsd_login_info& rdsp_login_info) {
    char chrl_buffer[D_MAXCMA_NAME];
	int inl_name_len = m_create_cma_name(rdsp_login_info, chrl_buffer, D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX);
	if(inl_name_len < 0)
		return -1;
    return adsp_wsp_helper->m_cb_exist_cma2(chrl_buffer, inl_name_len);
}
#else
/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_exists_user
 * is user with given cma base name logged in?
 *
 * @apram[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @param[in]   const char      *achp_cma           cma base name
 * @param[in]   int             inp_len             length of cma base name
 * @return      bool
*/
int ds_usercma::m_exists_user( ds_wsp_helper *adsp_wsp_helper,
                                const char *achp_cma, int inp_len )
{
#if SM_USE_MAIN_CMA_ONLY
    return adsp_wsp_helper->m_cb_exist_cma2( achp_cma, inp_len );
#else
    // initialize some variables:
    char chrl_buffer[D_MAXCMA_NAME];
    int  inl_blen;

    inl_blen = m_get_name( achp_cma, inp_len, chrl_buffer,
                           D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
    if ( inl_blen < 1 ) {
        return -1;
    }

    return adsp_wsp_helper->m_cb_exist_cma2( chrl_buffer, inl_blen );
#endif
} // end of ds_usercma::m_exists_user
#endif

#if SM_USE_CMA_ITERATOR
struct dsd_exists_same_user {
	bool boc_result;

	ied_pred_result m_handle(ds_wsp_helper *adsp_wsp_helper, const dsd_const_string& rdsp_name, const dsd_login_info& rdsp_info) {
		int inl_ret = adsp_wsp_helper->m_cb_exist_cma2(rdsp_name.m_get_ptr(), rdsp_name.m_get_len());
		if(inl_ret < 0)
			return iec_abort;
		if(inl_ret == 0)
			return iec_continue;

		char chrl_buffer[D_MAXCMA_NAME]; /* buf cma name */
		//-------------------------------------------
		// create name:
		//-------------------------------------------
		int inl_main_len = ds_usercma::m_create_name(
			rdsp_info.dsc_user.m_get_ptr(), rdsp_info.dsc_user.m_get_len(),
			rdsp_info.dsc_domain.m_get_ptr(), rdsp_info.dsc_domain.m_get_len(),
			rdsp_info.dsc_session_no, chrl_buffer, D_MAXCMA_NAME );
		if ( inl_main_len < 1 ) {
			return iec_abort;
		}

		struct dsd_hl_aux_c_cma_1 dsl_cma;
		if(!adsp_wsp_helper->m_cb_open_cma2(chrl_buffer, inl_main_len, &dsl_cma, false))
			return iec_continue;
		if ( dsl_cma.inc_len_cma_area < (int)sizeof(struct dsd_usercma_main) ) {
			adsp_wsp_helper->m_cb_close_cma2(&dsl_cma);
			return iec_continue;
		}
		struct dsd_usercma_main* adsl_main = (struct dsd_usercma_main*)dsl_cma.achc_cma_area;
		int inl_port  = adsl_main->inc_port;
		adsp_wsp_helper->m_cb_close_cma2(&dsl_cma);

		if ( inl_port != adsp_wsp_helper->m_get_listen_port() ) {
			 return iec_continue;
		} 
		this->boc_result = true;
		return iec_done;
	}
};
#endif

/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_exists_same_user
 * check if user with same username is already logged in
 *
 * @apram[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @param[in]   const char      *achp_user          username
 * @param[in]   int             inp_ulen            length username
 * @param[in]   const char      *achp_group         user group
 * @param[in]   int             inp_glen            length group
 * @return      bool
*/
bool ds_usercma::m_exists_same_user( ds_wsp_helper *adsp_wsp_helper,
                                     const char *achp_user, int inp_ulen,
                                     const char *achp_group, int inp_glen )
{
#if SM_USE_CMA_ITERATOR
	dsd_exists_same_user dsl_pred;
	dsl_pred.boc_result = false;
	if(!m_iterate_sessions(adsp_wsp_helper, achp_user, inp_ulen, achp_group, inp_glen, dsl_pred))
		return false;
	return dsl_pred.boc_result;
#else
	int                     inl_session;        /* loop counter         */
		 
	// TODO: CMA-List
    for ( inl_session = 1; inl_session <= D_MAXCMA_SESSION_NO; inl_session++ ) {
       void                    *avl_handle;        /* main cma handle      */
		 void                    *avl_cma;           /* main cma data        */
		 int                     inl_cma;            /* length of main cma   */
		 struct dsd_usercma_main *adsl_main;         /* main cma structure   */
		 int                     inl_port;           /* port of connection   */
		 char                    chrl_buffer[D_MAXCMA_NAME]; /* buf cma name */
		//-------------------------------------------
		 // create name:
		 //-------------------------------------------
		 int inl_main_len = m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
												 dsd_cma_session_no((unsigned char)inl_session), chrl_buffer, D_MAXCMA_NAME );
		 if ( inl_main_len < 1 ) {
			  return false;
		 }

		 //-------------------------------------------
		 // add login suffix:
		 //-------------------------------------------
		 int inl_blen = m_get_name( chrl_buffer, inl_main_len, chrl_buffer,
										D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
		 if ( inl_blen < 1 ) {
			  return false;
		 }

        bool bol_ret = adsp_wsp_helper->m_cb_exist_cma( chrl_buffer, inl_blen );
        if ( bol_ret == true ) {
            avl_handle = adsp_wsp_helper->m_cb_open_cma( chrl_buffer, inl_main_len,
                                                         &avl_cma, &inl_cma, false );
            if ( avl_handle == NULL ) {
                continue;
            }
            if ( inl_cma < (int)sizeof(struct dsd_usercma_main) ) {
                adsp_wsp_helper->m_cb_close_cma( &avl_handle );
                continue;
            }
            adsl_main = (struct dsd_usercma_main*)avl_cma;
            inl_port  = adsl_main->inc_port;
            adsp_wsp_helper->m_cb_close_cma( &avl_handle );

            if ( inl_port != adsp_wsp_helper->m_get_listen_port() ) {
                continue;
            } 
            return true;
        }
    }
    return false;
#endif /*SM_USE_CMA_ITERATOR*/
} // end of ds_usercma::m_exists_same_user

#if SM_USE_CMA_ITERATOR
	struct dsd_get_free_user {
		dsd_cma_session_no dsc_last_used;
		dsd_cma_session_no* adsp_out;

		ied_pred_result m_handle(ds_wsp_helper *adsp_wsp_helper, const dsd_const_string& rdsp_name, const dsd_login_info& rdsp_info) {
        	int inl_ret = adsp_wsp_helper->m_cb_exist_cma2(rdsp_name.m_get_ptr(), rdsp_name.m_get_len());
			if(inl_ret < 0)
				return iec_abort;
			// Does not exist?
			if(inl_ret == 0) {
				*adsp_out = rdsp_info.dsc_session_no;
				adsp_out = NULL;
				return iec_done;
			}
			return m_find_free(adsp_wsp_helper, rdsp_info);
		}

		ied_pred_result m_find_free(ds_wsp_helper *adsp_wsp_helper, const dsd_login_info& rdsp_info) {
			int inl_max_no = rdsp_info.dsc_session_no.ucc_session_no;
			for(int inl_no=dsc_last_used.ucc_session_no+1; inl_no<=inl_max_no; inl_no++) {
				char chrl_buffer[D_MAXCMA_NAME];
				//-------------------------------------------
				// create name:
				//-------------------------------------------
				int inl_blen = ds_usercma::m_create_name( rdsp_info.dsc_user.m_get_ptr(), rdsp_info.dsc_user.m_get_len(),
					rdsp_info.dsc_domain.m_get_ptr(), rdsp_info.dsc_domain.m_get_len(),
					dsd_cma_session_no((unsigned char)inl_no), chrl_buffer, D_MAXCMA_NAME );
				if ( inl_blen < 1 ) {
				   return iec_abort;
				}
				
				//-------------------------------------------
				// add login suffix:
				//-------------------------------------------
				int inl_ret = ds_usercma::m_exists_user(adsp_wsp_helper, chrl_buffer, inl_blen);
				if(inl_ret < 0) {
					return iec_abort;
				}
				if ( inl_ret == 0 ) {
					*adsp_out = dsd_cma_session_no((unsigned char)inl_no);
					adsp_out = NULL;
					return iec_done;
				}
			}
			dsc_last_used = rdsp_info.dsc_session_no;
			return iec_continue; 
		}
	};
#endif

/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_get_free_user
 * find first free session index for given user
 *
 * @apram[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @param[in]   const char      *achp_user          username
 * @param[in]   int             inp_ulen            length username
 * @param[in]   const char      *achp_group         user group
 * @param[in]   int             inp_glen            length group
 * @return      char                                session number
 *                                                  0 in error cases
*/
 bool ds_usercma::m_get_free_user( ds_wsp_helper *adsp_wsp_helper,
                                  const char *achp_user, int inp_ulen,
                                  const char *achp_group, int inp_glen,
											 dsd_cma_session_no* adsp_out )
{
#if SM_USE_CMA_ITERATOR
	dsd_get_free_user dsl_pred;
	dsl_pred.dsc_last_used.ucc_session_no = 0;
	dsl_pred.adsp_out = adsp_out;
	if(!m_iterate_sessions(adsp_wsp_helper, achp_user, inp_ulen, achp_group, inp_glen, dsl_pred))
		return false;
	if(dsl_pred.adsp_out == NULL)
		return true;
	dsd_login_info dsl_info;
	dsl_info.dsc_user = dsd_const_string(achp_user, inp_ulen);
	dsl_info.dsc_domain = dsd_const_string(achp_group, inp_glen);
	dsl_info.dsc_session_no.ucc_session_no = D_MAXCMA_SESSION_NO;
	if(dsl_pred.m_find_free(adsp_wsp_helper, dsl_info) == iec_done)
		return true;
	return false;
#else
	// initialize some variables:
    for ( int inl_session = 1; inl_session <= D_MAXCMA_SESSION_NO; inl_session++ ) {
	    char chrl_buffer[D_MAXCMA_NAME];
       //-------------------------------------------
		 // create name:
		 //-------------------------------------------
		 int inl_blen = m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
											dsd_cma_session_no((unsigned char)inl_session), chrl_buffer, D_MAXCMA_NAME );
		 if ( inl_blen < 1 ) {
			  return false;
		 }

		 //-------------------------------------------
		 // add login suffix:
		 //-------------------------------------------
		 inl_blen = m_get_name( chrl_buffer, inl_blen, chrl_buffer,
										D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
		 if ( inl_blen < 1 ) {
			  return false;
		 }
     
		 bool bol_ret = adsp_wsp_helper->m_cb_exist_cma( chrl_buffer, inl_blen );
        if ( bol_ret == false ) {
				*adsp_out = dsd_cma_session_no((unsigned char)inl_session);
            return true;
        }
    }
    return false;
#endif /*SM_USE_CMA_ITERATOR*/
} // end of ds_usercma::m_get_free_user

#if SM_USE_CMA_ITERATOR
template<typename PRED> bool ds_usercma::m_iterate_sessions(
	ds_wsp_helper *adsp_wsp_helper,
	const char *achp_user, int inp_ulen,
	const char *achp_group, int inp_glen,
	PRED& rdsp_pred)
 {
	// initialize some variables:
	char chrl_buffer_cur[D_MAXCMA_NAME];
	char chrl_buffer_cur2[D_MAXCMA_NAME];
	char chrl_buffer_e[D_MAXCMA_NAME];

	dsd_const_string dsl_user(achp_user, inp_ulen);
	dsd_const_string dsl_domain(achp_group, inp_glen);

	//-------------------------------------------
	// create name:
	//-------------------------------------------
	 int inl_blen_s = ds_usercma::m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
										dsd_cma_session_no((unsigned char)0), chrl_buffer_cur, D_MAXCMA_NAME );
	 if ( inl_blen_s < 1 ) {
		  return false;
	 }
#if !SM_USE_MAIN_CMA_ONLY
	 //-------------------------------------------
	 // add login suffix:
	 //-------------------------------------------
	 inl_blen_s = ds_usercma::m_get_name( chrl_buffer_cur, inl_blen_s, chrl_buffer_cur,
									D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
	 if ( inl_blen_s < 1 ) {
		  return false;
	 }
#endif

	 int inl_blen_e = ds_usercma::m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
										dsd_cma_session_no((unsigned char)D_MAXCMA_SESSION_NO), chrl_buffer_e, D_MAXCMA_NAME );
	 if ( inl_blen_e < 1 ) {
		  return false;
	 }
#if !SM_USE_MAIN_CMA_ONLY
	 //-------------------------------------------
	 // add login suffix:
	 //-------------------------------------------
	 inl_blen_e = ds_usercma::m_get_name( chrl_buffer_e, inl_blen_e, chrl_buffer_e,
									D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
	 if ( inl_blen_e < 1 ) {
		  return false;
	 }
#endif

	 char* achl_last = chrl_buffer_cur;
	 int inl_last_len = inl_blen_s;

	 //printf("m_get_all_users: len=%d start=%.*s\n", inl_blen_s, inl_blen_s, chrl_buffer_cur);
	 while(true) {
		 char* achl_next = (achl_last == chrl_buffer_cur) ? chrl_buffer_cur2 : chrl_buffer_cur;
		 int iml_next_len = adsp_wsp_helper->m_cb_get_next_cma(achl_last, inl_last_len, achl_next, D_MAXCMA_NAME);
		 if(iml_next_len < 0)
			 return false;
		 if(iml_next_len == 0)
			 break;
		 if(iml_next_len != inl_blen_s)
			 break;
		 if(memcmp(achl_next, chrl_buffer_e, iml_next_len) > 0)
			 break;
		 //printf("m_get_all_users: iml_next_len=%d next=%.*s\n", iml_next_len, iml_next_len, achl_next);
		 achl_last = achl_next;
		 inl_last_len = iml_next_len;

		 dsd_const_string dsl_tmp(achl_next, iml_next_len);
		 dsd_login_info dsl_info;
		 if(!m_parse_cma_name(dsl_tmp, dsl_info))
			 continue;
#if SM_USE_MAIN_CMA_ONLY
		 // Is not the main CMA?
		 if(!dsl_info.dsc_suffix.m_equals(""))
			 continue;
#else
		 // Is not the login CMA?
		 if(!dsl_info.dsc_suffix.m_equals(USERCMA_LOGIN_SUFFIX))
			 continue;
#endif
		 if(!dsl_info.dsc_domain.m_equals(dsl_domain))
			 break;
		 if(!dsl_info.dsc_user.m_equals(dsl_user))
			 break;
		 switch(rdsp_pred.m_handle(adsp_wsp_helper, dsl_tmp, dsl_info)) {
		 case iec_continue:
			continue;
		 case iec_done:
			 return true;
		 case iec_abort:
		 default:
			 return false;
		 }
	 }
	 return true; 
 }
#endif

#if SM_USE_CMA_ITERATOR
	struct dsd_get_all_users {
		dsd_cma_session_no* achp_sessions;
		int inp_max_sessions;
		int inl_count;

		ied_pred_result m_handle(ds_wsp_helper *adsp_wsp_helper, const dsd_const_string& rdsp_name, const dsd_login_info& rdsp_info) {
			int inl_ret = adsp_wsp_helper->m_cb_exist_cma2(rdsp_name.m_get_ptr(), rdsp_name.m_get_len());
			 if ( inl_ret < 0 )
				 return iec_abort;
			 // Does not exist?
			 if ( inl_ret == 0 )
				 return iec_continue;
			 achp_sessions[inl_count] = rdsp_info.dsc_session_no;
			 inl_count++;
			 if(inl_count >= inp_max_sessions)
				 return iec_done;
			 return iec_continue;
		}
	};
#endif

/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_get_all_users
 *
 * @apram[in]   ds_wsp_helper   *adsp_wsp_helper    wsp helper class
 * @param[in]   const char      *achp_user          username
 * @param[in]   int             inp_ulen            length username
 * @param[in]   const char      *achp_group         user group
 * @param[in]   int             inp_glen            length group
 * @param[out]  char            *achp_sessions      buffer to hold found sessions
 * @param[int]  int             inp_max_sessions    max length of buffer
 * @return      int                                 number of found sessions
*/
int ds_usercma::m_get_all_users( ds_wsp_helper *adsp_wsp_helper,
                                 const char *achp_user, int inp_ulen,
                                 const char *achp_group, int inp_glen,
                                 dsd_cma_session_no* achp_sessions, int inp_max_sessions )
{
#if SM_USE_CMA_ITERATOR
	dsd_get_all_users dsl_pred;
	dsl_pred.achp_sessions = achp_sessions;
	dsl_pred.inp_max_sessions = inp_max_sessions;
	dsl_pred.inl_count = 0;
	if(!m_iterate_sessions(adsp_wsp_helper, achp_user, inp_ulen, achp_group, inp_glen, dsl_pred))
		return -1;
	return dsl_pred.inl_count;
#else
	int inl_count = 0;
	for ( int inl_session = 1; inl_session <= D_MAXCMA_SESSION_NO; inl_session++ ) {
		 char            chrl_buffer[D_MAXCMA_NAME]; // cma name
		 //-------------------------------------------
		 // create name:
		 //-------------------------------------------
		 int inl_blen = m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
											dsd_cma_session_no((unsigned char)inl_session), chrl_buffer, D_MAXCMA_NAME );
		 if ( inl_blen < 1 ) {
			  return -1;
		 }
		 
		 //-------------------------------------------
		 // add login suffix:
		 //-------------------------------------------
		 inl_blen = m_get_name( chrl_buffer, inl_blen, chrl_buffer,
										D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
		 if ( inl_blen < 1 ) {
			  return -1;
		 }

        bool bol_ret = adsp_wsp_helper->m_cb_exist_cma( chrl_buffer, inl_blen );
        if ( bol_ret == true ) {
            if ( inl_count >= inp_max_sessions )
					return -1;
            achp_sessions[inl_count] = dsd_cma_session_no((unsigned char)inl_session);
            inl_count++;
        }
    }
    return inl_count;
#endif /*SM_USE_CMA_ITERATOR*/
} // end of ds_usercma::m_get_all_users


/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_is_sticket
 * check if given buffer is a session ticket
 *
 * @param[out]  char    *achp_session       session number
 * @param[in]   char*   achp_buffer         pointer to output buffer
 * @param[in]   int     inp_len_buffer      length of output buffer
 * @return      bool                        true = success
*/
bool ds_usercma::m_is_sticket( dsd_cma_session_no *achp_session,
                               const char *achp_buffer, int inp_blen )
{
    /*
        We will build a 4 byte checksum over the following 
        session number + random string.

        Random string is given in base64
        We will transform checksum + session number to bas64.

        So, our session ticket will look like this:

        +--------------------------------+------- ... -------+
        | b64(checksum + session number) | random string     |
        +--------------------------------+------- ... -------+
                       8                 inp_len_buffer - 8
    */

    // initialize some variables:
    struct dsd_sticket_cs dsl_decoded;
    int                   inl_ret;
    char                  chrl_buf[LEN_SESSTICKET - DEF_LEN_B64CS + 1];
    unsigned int          uinl_compare;

    if ( inp_blen != LEN_SESSTICKET ) {
        return false;
    }

    //-------------------------------------------
    // decode(checksum + session num):
    //-------------------------------------------
    inl_ret = ds_hstring::m_from_b64( achp_buffer, DEF_LEN_B64CS,
                          (char*)&dsl_decoded,
								  (int)(sizeof(dsl_decoded.uinc_checksum) + sizeof(dsl_decoded.chc_session)) );
    if ( inl_ret != (int)(sizeof(dsl_decoded.uinc_checksum) + sizeof(dsl_decoded.chc_session)) ) {
        return false;
    }

    //-------------------------------------------
    // checksum(session num + random):
    //-------------------------------------------
    chrl_buf[0] = dsl_decoded.chc_session;
    memcpy( &chrl_buf[1], &achp_buffer[DEF_LEN_B64CS],
            LEN_SESSTICKET - DEF_LEN_B64CS             );
    uinl_compare = m_build_cs( chrl_buf,
                               LEN_SESSTICKET - DEF_LEN_B64CS + 1 );

    //-------------------------------------------
    // compare checksums:
    //-------------------------------------------
    if ( uinl_compare != dsl_decoded.uinc_checksum ) {
        return false;
    }

    if ( achp_session ) {
        *achp_session = dsd_cma_session_no((unsigned char)dsl_decoded.chc_session);
    }
    return true;
} // end of ds_usercma::m_is_sticket


/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_get_usercma
 * get user cma from ident settings (saved in wsp)
 *
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper    wsp callback class
 * @param[out]  ds_usercma      *adsp_ucma          user cma output
 * @return      bool
*/
bool ds_usercma::m_get_usercma( ds_wsp_helper *adsp_wsp_helper, ds_usercma *adsp_ucma )
{
    // initialize some variables:
    bool                       bol_ret;         // return for some funcs
    struct dsd_sdh_ident_set_1 dsl_ident;       // wsp ident settings
    char            chrl_buffer[D_MAXCMA_NAME]; // cma name
    int                        inl_len;         // length cma name
    dsd_wspat_pconf_t          *adsl_wspat_conf;// wspat config
    struct dsd_role            *adsl_role;      // current role
    struct dsd_domain          *adsl_domain;    // current domain
    ds_hstring                 dsl_temp;        // role name

    //-------------------------------------------
    // get ident settings from wsp:
    //-------------------------------------------
#define DSL_USER    (dsl_ident.dsc_userid)
#define DSL_GROUP   (dsl_ident.dsc_user_group)

    memset( &DSL_USER,  0, sizeof(struct dsd_unicode_string) );
    memset( &DSL_GROUP, 0, sizeof(struct dsd_unicode_string) );
    dsl_ident.achc_userfld    = NULL;
    dsl_ident.imc_len_userfld = 0;

    bol_ret = adsp_wsp_helper->m_cb_get_ident( &dsl_ident );
    if (    bol_ret                    == false           /* error while call */
         || DSL_USER.imc_len_str        < 1               /* no user name     */
         || DSL_USER.iec_chs_str       != ied_chs_utf_8   /* invalid encoding */
         || (    DSL_GROUP.imc_len_str  > 0
              && DSL_GROUP.iec_chs_str != ied_chs_utf_8 ) /* invalid encoding */
         || dsl_ident.imc_len_userfld  != sizeof(dsd_aux_ident_session_info) ) {           /* wrong session    */
        return false;
    }
	 
	 dsd_aux_ident_session_info* adsl_aux_ident_session_info = (dsd_aux_ident_session_info*)dsl_ident.achc_userfld;
	 dsd_cma_session_no dsd_cma_session_no(adsl_aux_ident_session_info->ucc_session_no);
    //-------------------------------------------
    // create main cma name:
    //-------------------------------------------
    inl_len = m_create_name( (char*)DSL_USER.ac_str, DSL_USER.imc_len_str,
                             (char*)DSL_GROUP.ac_str, DSL_GROUP.imc_len_str,
									  dsd_cma_session_no, chrl_buffer, D_MAXCMA_NAME );
#undef DSL_USER
#undef DSL_GROUP

    if ( inl_len < 1 ) {
        return false;
    }

    //-------------------------------------------
    // check if user is logged in:
    //-------------------------------------------
    int inl_ret = ds_usercma::m_exists_user( adsp_wsp_helper,
                                         chrl_buffer, inl_len );
    if ( inl_ret != 1 ) {
        return false;
    }

    //-------------------------------------------
    // init usercma:
    //-------------------------------------------
    adsp_ucma->m_init( adsp_wsp_helper );
    
    //-------------------------------------------
    // select role:
    //-------------------------------------------
    adsl_wspat_conf = adsp_wsp_helper->m_get_wspat_config();
    if ( adsl_wspat_conf == NULL ) {
        return true;
    }

    bol_ret = adsp_ucma->m_set_name( chrl_buffer, inl_len );
    if ( bol_ret == false ) {
        return false;
    }
    dsl_temp  = adsp_ucma->m_get_userrole();
    adsl_role = adsl_wspat_conf->adsc_roles;
    while ( adsl_role != NULL ) {
        if ( dsl_temp.m_equals(adsl_role->achc_name, adsl_role->inc_len_name) ) {
            break;
        }
        adsl_role = adsl_role->adsc_next;
    }
	adsp_ucma->m_select_role( adsl_role );

    //-------------------------------------------
    // select domain config:
    //-------------------------------------------
    dsl_temp    = adsp_ucma->m_get_userdomain();
    adsl_domain = adsl_wspat_conf->dsc_domains.adsc_domain;
    if ( dsl_temp.m_get_len() > 0 ) {
        while ( adsl_domain != NULL ) {
            if ( dsl_temp.m_equals(adsl_domain->achc_disp_name, adsl_domain->inc_len_disp_name) ) {
                break;
            }
            adsl_domain = adsl_domain->adsc_next;
        }
    }
    if ( adsl_domain != NULL ) {
        adsp_ucma->m_select_domain( adsl_domain );
    }

    return true;
} // end of ds_usercma::m_get_usercma

bool ds_usercma::m_parse_cma_name(const dsd_const_string& rdsp_name, dsd_login_info& rdsp_out) {
    /*
        base cma name will look like this:

        +-----+---+------...-+---+---------...-+---+----------------+--------------------+
        | usr | / | group    | / | username    | / | session number | (optional) /suffix |
        +-----+---+------...-+---+---------...-+---+----------------+--------------------+
        |  3  | 1 | variable | 1 | variable    | 1 |        1       |   variable         |

        group can have zero lenth, than following "/" is also missing
        username must exist
    */
	int inl_pos = 0;
	dsd_const_string dsl_word;
	// read first word (could be group or username):
	if(m_get_word(rdsp_name, &inl_pos, dsl_word))
		return false;
	inl_pos++;
	if(!dsl_word.m_equals(USERCMA_NAME_PREFIX))
		return false;
	if(m_get_word(rdsp_name, &inl_pos, rdsp_out.dsc_domain))
		return false;
	inl_pos++;
	if(m_get_word(rdsp_name, &inl_pos, rdsp_out.dsc_user))
		return false;
	inl_pos++;
	m_get_word(rdsp_name, &inl_pos, dsl_word);
	rdsp_out.dsc_suffix = rdsp_name.m_substring(inl_pos);
	int inl_session_no;
	if(dsl_word.inc_length > 3 || !m_parse_int(dsl_word, inl_session_no))
		return false;
	if(inl_session_no < 1 && inl_session_no > D_MAXCMA_SESSION_NO)
		return false;
	rdsp_out.dsc_session_no.ucc_session_no = (unsigned char)inl_session_no;
	return true;
}

/**
 * \ingroup authlib
 *
 * public static function ds_usercma::m_is_user
 * decide if given string contains to a user login cma
 *
 * @param[in]   const char  *achp_cma       cma name
 * @param[in]   int         inp_len         length of cma name
 * @return      bool
*/
bool ds_usercma::m_is_user( const char *achp_cma, int inp_len )
{
	dsd_const_string dsl_cma_name(achp_cma, inp_len);
	dsd_login_info dsl_info;
	if(!m_parse_cma_name(dsl_cma_name, dsl_info))
		return false;
	if(!dsl_info.dsc_suffix.m_equals(USERCMA_LOGIN_SUFFIX))
		return false;
	return true;
} // end of ds_usercma::m_is_user

/**
 * \ingroup authlib
 *
 * public static function ds_usercma::m_get_user
 * get user information from given login cma name
 *
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper    wsp callback class
 * @param[in]   const char      *achp_cma           cma name
 * @param[in]   int             inp_len             length of cma name
 * @param[out]  dsd_getuser     *adsp_user          user information
 * @return      bool
*/
bool ds_usercma::m_get_user( ds_wsp_helper *adsp_wsp_helper,
                             const char *achp_cma, int inp_len,
                             struct dsd_getuser *adsp_user )
{
    // initialize some variables:
    struct dsd_usercma_login *adsl_login;   // cma structure
    char                     *achl_user;    // user name
    char                     *achl_domain;  // user domain
    char                     *achl_dn;      // ldap dn
    char                     *achl_wspgroup;// wsp user group
    char                     *achl_role;    // selected role

    // open cma:
	struct dsd_hl_aux_c_cma_1 dsl_cma;
    if(!adsp_wsp_helper->m_cb_open_cma2(achp_cma, inp_len, &dsl_cma, false))
        return false;

    // check cma data:
	if (dsl_cma.inc_len_cma_area <  (int)sizeof(dsd_usercma_login) ) {
        adsp_wsp_helper->m_cb_close_cma2(&dsl_cma);
        return false;
    }
	adsl_login = (dsd_usercma_login*)dsl_cma.achc_cma_area;
    if ( dsl_cma.inc_len_cma_area != (int)sizeof(dsd_usercma_login)
                   + adsl_login->inc_len_username
                   + adsl_login->inc_len_userdomain
                   + adsl_login->inc_len_password
                   + adsl_login->inc_len_userdn
                   + adsl_login->inc_len_wspgroup
                   + adsl_login->inc_len_role ) {
        adsp_wsp_helper->m_cb_close_cma2(&dsl_cma);
        return false;
    }

    // get the requested data:
    achl_user     = (char*)(adsl_login + 1);
    achl_domain   = achl_user + adsl_login->inc_len_username;
    achl_dn       =   achl_domain
                    + adsl_login->inc_len_userdomain
                    + adsl_login->inc_len_password;
    achl_wspgroup = achl_dn + adsl_login->inc_len_userdn;
    achl_role     = achl_wspgroup + adsl_login->inc_len_wspgroup;
        
    adsp_user->dsc_username.m_setup  ( adsp_wsp_helper );
    adsp_user->dsc_userdomain.m_setup( adsp_wsp_helper );
    adsp_user->dsc_wspgroup.m_setup  ( adsp_wsp_helper );
    adsp_user->dsc_role.m_setup      ( adsp_wsp_helper );
    adsp_user->dsc_userdn.m_setup    ( adsp_wsp_helper );

    adsp_user->tmc_login       = adsl_login->tmc_login;
    adsp_user->iec_auth_flags   = adsl_login->iec_auth_flags;
    adsp_user->inc_auth_method = adsl_login->inc_auth_method;
    adsp_user->chc_session     = adsl_login->chc_session;

    adsp_user->dsc_username.m_write  ( achl_user, adsl_login->inc_len_username );
    adsp_user->dsc_userdomain.m_write( achl_domain, adsl_login->inc_len_userdomain );
    adsp_user->dsc_wspgroup.m_write  ( achl_wspgroup, adsl_login->inc_len_wspgroup );
    adsp_user->dsc_role.m_write      ( achl_role, adsl_login->inc_len_role );
    adsp_user->dsc_userdn.m_write    ( achl_dn, adsl_login->inc_len_userdn );

    memcpy( &adsp_user->dsc_client, &adsl_login->dsc_client,
            sizeof(dsd_aux_query_client) );

    adsp_wsp_helper->m_cb_close_cma2(&dsl_cma);
    return true;
} // end of ds_usercma::m_get_user


/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_check_timeouts
 * check timeouts for given user, delete cmas if not active anymore
 *
 * @param[in]   ds_wsp_helper   *adsp_wsp_helper    wsp_helper class
 * @param[in]   dsd_getuser     *adsp_user          user inforamtion
 * @return      bool                                true = still valid
*/
bool ds_usercma::m_check_timeouts( ds_wsp_helper *adsp_wsp_helper,
                                   struct dsd_getuser *adsp_user )
{
    // initialize some variables:
    hl_time_t           ill_now;               // current time
    char             chrl_main[D_MAXCMA_NAME]; // main cma name
    int              inl_mlen;              // length of main cma name
    char             chrl_buffer[D_MAXCMA_NAME]; // cma name
    int              inl_blen;              // length of cma name
    void             *avl_handle;           // cma handle
    void             *avl_data;             // pointer to cma content
    int              inl_dlen;              // length of cma content
    dsd_wspat_pconf_t *adsl_wspat_conf;      // wspat config
    dsd_role         *adsl_role;            // current role
    dsd_usercma_main *adsl_main;            // main cma
    hl_time_t           ill_lastaction;        // last action

    // get wspat configuration:
    adsl_wspat_conf = adsp_wsp_helper->m_get_wspat_config();
    if ( adsl_wspat_conf == NULL ) {
        return true;
    }

    // get users roles:
    adsl_role = adsl_wspat_conf->adsc_roles;
    while ( adsl_role != NULL ) {
        if ( adsp_user->dsc_role.m_equals(adsl_role->achc_name,
                                          adsl_role->inc_len_name) == true ) {
            break;
        }
        adsl_role = adsl_role->adsc_next;
    }
    if ( adsl_role == NULL ) {
        return true;
    }

    //-------------------------------------------
    // get last action timestamp:
    //-------------------------------------------
    inl_mlen = m_create_name( adsp_user->dsc_username.m_get_ptr(),
                              adsp_user->dsc_username.m_get_len(),
                              adsp_user->dsc_userdomain.m_get_ptr(),
                              adsp_user->dsc_userdomain.m_get_len(),
                              adsp_user->chc_session, chrl_main,
                              D_MAXCMA_NAME );
    if ( inl_mlen < 1 ) {
        return false;
    }
    avl_handle = adsp_wsp_helper->m_cb_open_cma( chrl_main, inl_mlen,
                                                 &avl_data, &inl_dlen, false );
    if ( avl_handle == NULL ) {
        return false;
    }
    if (    avl_data == NULL
         || inl_dlen  < (int)sizeof(dsd_usercma_main) ) {
        adsp_wsp_helper->m_cb_close_cma( &avl_handle );
        return false;
    }
    adsl_main = (dsd_usercma_main*)avl_data;
    if ( inl_dlen !=   (int)sizeof(dsd_usercma_main)
                     + adsl_main->inc_len_message
                     + adsl_main->inc_len_bpage ) {
        adsp_wsp_helper->m_cb_close_cma( &avl_handle );
        return false;
    }
    ill_lastaction = adsl_main->tmc_laction;
    adsp_wsp_helper->m_cb_close_cma( &avl_handle );

    //-------------------------------------------
    // compare timestamps
    //-------------------------------------------
    ill_now = adsp_wsp_helper->m_cb_get_time();
    if (    /* check idle period */ 
            (    adsl_role->dsc_time_limits.in_idle_period > 0
              &&   ill_lastaction
                 + adsl_role->dsc_time_limits.in_idle_period  <= ill_now )
         || /* check max session lifetime */
            (    adsl_role->dsc_time_limits.in_max_period  > 0
              &&   adsp_user->tmc_login
                 + adsl_role->dsc_time_limits.in_max_period   <= ill_now ) ) {

        //---------------------------------------
        // delete all cmas:
        //---------------------------------------
        // main cma:
        adsp_wsp_helper->m_cb_delete_cma( chrl_main, inl_mlen );

        // login cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }

        // settings cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_SETTING_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }

        // wsg cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_WSG_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }

        // ineta cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_INETA_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }

        // roles cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_ROLES_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }

        // axss cma:
        inl_blen = m_get_name( chrl_main, inl_mlen, chrl_buffer,
                               D_MAXCMA_NAME, USERCMA_AXSS_SUFFIX );
        if ( inl_blen > 0 ) {
            adsp_wsp_helper->m_cb_delete_cma( chrl_buffer, inl_blen );
        }
        return false;
    }
    return true;
} // end of ds_usercma::m_check_timeouts                                   


/**
 * \ingroup authlib
 *
 * static public function ds_usercma::m_get_login_info
 * get login time and client ip for given user session
 *
 * @param[in]   ds_wsp_helper        *adsp_wsp_helper    wsp helper class
 * @param[in]   const char           *achp_user          username
 * @param[in]   int                  inp_ulen            length username
 * @param[in]   const char           *achp_group         user group
 * @param[in]   int                  inp_glen            length group
 * @param[in]   char                 chp_session         session number
 * @param[out]  hl_time_t               *ilp_login          login time
 * @param[out]  dsd_aux_query_client *adsp_ineta         client ip
 * @return      int                                      number of found sessions
*/
bool ds_usercma::m_get_login_info( ds_wsp_helper *adsp_wsp_helper,
                                   const char *achp_user, int inp_ulen,
                                   const char *achp_group, int inp_glen,
                                   const dsd_cma_session_no& chp_session, hl_time_t *ilp_login,
                                   dsd_aux_query_client* adsp_ineta )
{
    // initialize some variables:
    char                     chrl_buffer[D_MAXCMA_NAME];    // cma name
    int                      inl_blen;                      // length of cma name
    void                     *avl_handle;                   // cma handle
    void                     *avl_data;                     // pointer to cma content
    int                      inl_dlen;                      // length of cma content
    struct dsd_usercma_login *adsl_login;                   // cma structure

    // create name:
    inl_blen = m_create_name( achp_user, inp_ulen, achp_group, inp_glen,
                              chp_session, chrl_buffer, D_MAXCMA_NAME );
    if ( inl_blen < 1 ) {
        return false;
    }
    inl_blen = m_get_name( chrl_buffer, inl_blen, chrl_buffer,
                           D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
    if ( inl_blen < 1 ) {
        return false;
    }

    // open cma:
    avl_handle = adsp_wsp_helper->m_cb_open_cma( chrl_buffer, inl_blen,
                                                 &avl_data,  &inl_dlen,
                                                 false );
    if ( avl_handle == NULL ) {
        return false;
    }

    // check cma data:
    if (    avl_data == NULL
         || inl_dlen  < (int)sizeof(dsd_usercma_login) ) {
        adsp_wsp_helper->m_cb_close_cma( &avl_handle );
        return false;
    }
    adsl_login = (dsd_usercma_login*)avl_data;
    if ( inl_dlen !=   (int)sizeof(dsd_usercma_login)
                     + adsl_login->inc_len_username
                     + adsl_login->inc_len_userdomain
                     + adsl_login->inc_len_password
                     + adsl_login->inc_len_userdn
                     + adsl_login->inc_len_wspgroup
                     + adsl_login->inc_len_role ) {
        adsp_wsp_helper->m_cb_close_cma( &avl_handle );
        return false;
    }

    // get the requested data:
    *ilp_login = adsl_login->tmc_login;
    memcpy( adsp_ineta, &adsl_login->dsc_client, sizeof(dsd_aux_query_client) );

    adsp_wsp_helper->m_cb_close_cma( &avl_handle );
    return true;
} // end of ds_usercma::m_get_login_info


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function ds_usercma::m_create_sticket
 * create session ticket
 *
 * @param[in]   char            chp_session         session number
 * @param[in]   char            *achp_buffer        pointer to output buffer
 * @param[in]   int             inp_blen            length of output buffer
 * @return      bool                                true = success
*/
int ds_usercma::m_create_sticket( const dsd_cma_session_no& chp_session,
                                  char *achp_buffer, int inp_blen )
{
    /*
        We will build a 4 byte checksum over the following 
        session number + random string.

        Random string is given in base64
        We will transform checksum + session number to bas64.

        So, our session ticket will look like this:

        +--------------------------------+------- ... -------+
        | b64(checksum + session number) | random string     |
        +--------------------------------+------- ... -------+
                       8                 inp_len_buffer - 8
    */

    // initialize some variables:
    struct dsd_sticket_cs dsl_decoded;
    size_t                uinl_pos;
    bool                  bol_ret;
    bool                  bol_repeat;

    if ( inp_blen != LEN_SESSTICKET ) {
        return false;
    }

    //-------------------------------------------
    // insert session number:
    //-------------------------------------------
    achp_buffer[DEF_LEN_B64CS - 1] = chp_session.ucc_session_no; // for checksum
    dsl_decoded.chc_session        = chp_session.ucc_session_no; // for b64
        
    do {
        //---------------------------------------
        // get random string
        //---------------------------------------
        bol_ret = adsc_wsp_helper->m_cb_get_random_cookie(
                                          &achp_buffer[DEF_LEN_B64CS],
                                          inp_blen - DEF_LEN_B64CS );
		
		if ( bol_ret == false ) {
            return false;
        }

        //---------------------------------------
        // checksum(over session num + random)
        //---------------------------------------
        dsl_decoded.uinc_checksum = m_build_cs( &achp_buffer[DEF_LEN_B64CS-1],
                                                inp_blen - DEF_LEN_B64CS + 1 );

        //---------------------------------------
        // check checksum for '0' characters
        //---------------------------------------
        bol_repeat = false;
        for ( uinl_pos = 0; uinl_pos < sizeof(unsigned int); uinl_pos++ ) {
            if ( dsl_decoded.chrc_checksum[uinl_pos] == 0 ) {
                bol_repeat = true;
                break;
            }
        }
    } while ( bol_repeat == true );

    //-------------------------------------------
    // b64(checksum + session num)
    //-------------------------------------------
    int inl_ret = ds_hstring::m_to_b64( (char*)&dsl_decoded,
                        sizeof(dsl_decoded.uinc_checksum) + sizeof(dsl_decoded.chc_session),
                        achp_buffer, DEF_LEN_B64CS       );
    if(inl_ret != DEF_LEN_B64CS)
        return false;
    return true;
} // end of ds_usercma::m_create_sticket


/**
 * private function ds_usercma::m_set_names
 * set names of all (not main) cmas
 *
 * @return bool
*/
bool ds_usercma::m_set_names()
{
    inc_login = m_get_name( chrc_main, inc_main, chrc_login,
                            D_MAXCMA_NAME, USERCMA_LOGIN_SUFFIX );
    if ( inc_login < 1 ) {
        return false;
    }

    inc_settings = m_get_name( chrc_main, inc_main, chrc_settings,
                               D_MAXCMA_NAME, USERCMA_SETTING_SUFFIX );
    if ( inc_settings < 1 ) {
        return false;
    }

    inc_wsg = m_get_name( chrc_main, inc_main, chrc_wsg,
                          D_MAXCMA_NAME, USERCMA_WSG_SUFFIX );
    if ( inc_wsg < 1 ) {
        return false;
    }

    inc_ineta = m_get_name( chrc_main, inc_main, chrc_ineta,
                            D_MAXCMA_NAME, USERCMA_INETA_SUFFIX );
    if ( inc_ineta < 1 ) {
        return false;
    }

    inc_roles = m_get_name( chrc_main, inc_main, chrc_roles,
                            D_MAXCMA_NAME, USERCMA_ROLES_SUFFIX );
    if ( inc_roles < 1 ) {
        return false;
    }

    inc_axss = m_get_name( chrc_main, inc_main, chrc_axss,
                           D_MAXCMA_NAME, USERCMA_AXSS_SUFFIX );
    if ( inc_axss < 1 ) {
        return false;
    }
    return true;
} // end of ds_usercma::m_set_names

#if 0
/**
 * private function ds_usercma::m_update_retention
 * update retention time for all existing cmas
 *
 * @return      bool
*/
bool ds_usercma::m_update_retention()
{
    // initialize some variables:
    bool bol_ret = true;

#define M_CMA_EXISTS(x,y) adsc_wsp_helper->m_cb_exist_cma(x,y)
#define M_SET_RETENTION(x,y,z) adsc_wsp_helper->m_cb_set_retention_cma(x,y,z)

    // main cma:
    if ( M_CMA_EXISTS(chrc_main, inc_main) ) {
        bol_ret &= M_SET_RETENTION( chrc_main, inc_main, inc_idle_timeout );
    }

    // login cma:
    if ( M_CMA_EXISTS(chrc_login, inc_login) ) {
        bol_ret &= M_SET_RETENTION( chrc_login, inc_login, inc_idle_timeout );
    }

    // settings cma:
    if ( M_CMA_EXISTS(chrc_settings, inc_settings) ) {
        bol_ret &= M_SET_RETENTION( chrc_settings, inc_settings, inc_idle_timeout );
    }

    // wsg cma:
    if ( M_CMA_EXISTS(chrc_wsg, inc_wsg) ) {
        bol_ret &= M_SET_RETENTION( chrc_wsg, inc_wsg, inc_idle_timeout );
    }

    // ineta cma:
    if ( M_CMA_EXISTS(chrc_ineta, inc_ineta) ) {
        bol_ret &= M_SET_RETENTION( chrc_ineta, inc_ineta, inc_idle_timeout );
    }

    // roles cma:
    if ( M_CMA_EXISTS(chrc_roles, inc_roles) ) {
        bol_ret &= M_SET_RETENTION( chrc_roles, inc_roles, inc_idle_timeout );
    }

    // axss cma:
    if ( M_CMA_EXISTS(chrc_axss, inc_axss) ) {
        bol_ret &= M_SET_RETENTION( chrc_axss, inc_axss, inc_idle_timeout );
    }

#undef M_CMA_EXISTS
#undef M_SET_RETENTION
    return bol_ret;
} // end of ds_usercma::m_update_retention
#endif

/**
 * private function ds_usercma::m_merge_portlets
 * portlets can be saved in
 *  - user settings
 *  - user role
 * compare this two lists and return a merged version
 *
 * @param[out]  ds_hvector<ds_portlet>*     adsv_out
 * @return      bool
*/
bool ds_usercma::m_merge_portlets( ds_hvector<ds_portlet> *adsvp_out )
{
    // initialize some variables:
    ds_hvector<ds_portlet> dslv_set_portlets;               // portlet list from settings
    dsd_role_portlet*      adsl_portlet;                    // current portlet (role format)
    bool                   bol_ret;                         // return for several func calls
    int                    inl_pos;                         // position in vector
    const char*            achl_name;                       // name of current portlet
    int                    inl_len_name;                    // length of name

    //-------------------------------------------
    // is already a role selected?
    //-------------------------------------------
    if ( adsc_srole == NULL ) {
        return false;
    }

    //-------------------------------------------
    // init output vector:
    //-------------------------------------------
    adsvp_out->m_init( adsc_wsp_helper );

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dslv_set_portlets.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // get portlets from settings:
    //-------------------------------------------
    bol_ret = m_get_cma_portlets( &dslv_set_portlets );
    if (    bol_ret == false
         || dslv_set_portlets.m_empty() ) {

        ds_portlet dsl_portlet;
        dsl_portlet.m_init(adsc_wsp_helper);
        /*
            no portlets in user settings found
            -> just take the role ones
        */
        adsl_portlet = adsc_srole->adsc_portlets;
        while ( adsl_portlet != NULL ) {
            // fill current portlet:
            dsl_portlet.m_set_name ( adsl_portlet->achc_name,
                                     adsl_portlet->inc_len_name );
            dsl_portlet.m_set_open ( adsl_portlet->bo_open );

            // add to output vector:
            if ( dsl_portlet.m_is_complete() ) {
                adsvp_out->m_add( dsl_portlet );
                dsl_portlet.m_reset();
            }

            // get next role portlet:
            adsl_portlet = adsl_portlet->adsc_next;
        }

    } else {
        /*
            portlets in user settings found
            -> add allowed settings portlets to merged list
            -> add new role portlets to merged list
        */

        //---------------------------------------
        // add portlets from user settings:
        //---------------------------------------
        for ( HVECTOR_FOREACH(ds_portlet, adsl_cur, dslv_set_portlets) ) {
            // get current settings portlet:
            const ds_portlet& dsl_portlet = HVECTOR_GET(adsl_cur);

            // check if this portlet is allowed:
            dsl_portlet.m_get_name( &achl_name, &inl_len_name );
            bol_ret = m_is_portlet_allowed( achl_name, inl_len_name );

            // add to list if allowed:
            if ( bol_ret == true ) {
                adsvp_out->m_add( dsl_portlet );
            }
        }

        //---------------------------------------
        // check for newer portlets in role:
        //---------------------------------------
        ds_portlet dsl_portlet;
        dsl_portlet.m_init(adsc_wsp_helper);

        adsl_portlet = adsc_srole->adsc_portlets;
        while ( adsl_portlet != NULL ) {
            // check if portlet is in list:
            inl_pos = m_is_portlet_in_list( adsvp_out,
                                            adsl_portlet->achc_name,
                                            adsl_portlet->inc_len_name );
            if ( inl_pos == -1 ) {
                // entry not found -> add it to list
                dsl_portlet.m_set_name ( adsl_portlet->achc_name,
                                         adsl_portlet->inc_len_name );
                dsl_portlet.m_set_open ( adsl_portlet->bo_open );

                // add to output vector:
                if ( dsl_portlet.m_is_complete() ) {
                    adsvp_out->m_add( dsl_portlet );
                    dsl_portlet.m_reset();
                }               
            }

            // get next role portlet:
            adsl_portlet = adsl_portlet->adsc_next;
        }
    }
    
    return ( !adsvp_out->m_empty() );
} // end of ds_usercma::m_merge_portlets


/**
 * private function ds_usercma::m_is_portlet_in_list
 * check if given portlet name is in list
 *
 * @param[in]   ds_hevtor<ds_portlet>*  adsv_list   list to search in
 * @param[in]   const char*             ach_name    name to search for
 * @param[in]   int                     in_len      length of name
 * @return      int                                 found at position
 *                                                  -1 if not found
*/
int ds_usercma::m_is_portlet_in_list( ds_hvector<ds_portlet> *adsvp_list,
                                      const char *achp_name, int inp_len )
{
    // initialize some variables:
    const char*      achl_current;            // name of current portlet
    int        inl_len_cur;             // length of current portlet name

    size_t uinl_pos = 0;                // position in list
    for ( HVECTOR_FOREACH(ds_portlet, adsl_cur, *adsvp_list) ) {
        // get current settings portlet:
        const ds_portlet& dsl_current = HVECTOR_GET(adsl_cur);
        dsl_current.m_get_name( &achl_current, &inl_len_cur );
        if (    inl_len_cur == inp_len
             && memcmp( achl_current, achp_name, inp_len ) == 0 ) {
            return (int)uinl_pos;
        }
        uinl_pos++;
    }
    return -1;
} // end of ds_usercma::m_is_portlet_in_list

/**
 * private function ds_usercma::m_create_pwcma
 *
 * creates the encrypted pw and stores it in a CMA
 * CMA name: USER-PWD[0]DOMAIN[0]USERID
 * Content is encrypted via DEF_AUX_SECURE_XOR
 * Key is DOMAIN[0]USERID
*/
bool ds_usercma::m_create_pwcma( const char *achp_username, int inp_unlen, const char *achp_userdomain, int inp_udlen, const char *achp_password, int inp_pwlen )
{
#define PWCMA_LEN_PREFIX sizeof(chrs_prefix)

	int								inl_ret;
	static const char				chrs_prefix[] = "USER-PWD";
	char							chrl_data[D_MAXCMA_NAME];
	struct dsd_aux_secure_xor_1		dsl_secure_xor;

	/********************************************************************************************/
	/* Create Name of CMA																		*/
	/********************************************************************************************/
	// Prefix
	memcpy( chrc_pwcma_name, chrs_prefix, PWCMA_LEN_PREFIX );
	inc_pwcma_namelen = PWCMA_LEN_PREFIX;
	
	// userdomain
#if SM_AUTHENTICATE_CASE_SENSITIVE
    inl_ret = m_cpy_vx_vx( chrc_pwcma_name + inc_pwcma_namelen, D_MAXCMA_NAME - inc_pwcma_namelen, ied_chs_utf_8, (void*)achp_userdomain, inp_udlen, ied_chs_utf_8 );
#else
    inl_ret = m_cpy_uc_vx_vx( chrc_pwcma_name + inc_pwcma_namelen, D_MAXCMA_NAME - inc_pwcma_namelen, ied_chs_utf_8, (void*)achp_userdomain, inp_udlen, ied_chs_utf_8 );
#endif
    if( inl_ret < 0 ){ return false; }
	inc_pwcma_namelen += inl_ret + 1;

	// username
#if SM_AUTHENTICATE_CASE_SENSITIVE
	inl_ret = m_cpy_vx_vx( chrc_pwcma_name + inc_pwcma_namelen, D_MAXCMA_NAME - inc_pwcma_namelen, ied_chs_utf_8, (void*)achp_username, inp_unlen, ied_chs_utf_8 );
#else
	inl_ret = m_cpy_uc_vx_vx( chrc_pwcma_name + inc_pwcma_namelen, D_MAXCMA_NAME - inc_pwcma_namelen, ied_chs_utf_8, (void*)achp_username, inp_unlen, ied_chs_utf_8 );
#endif
    if( inl_ret < 0 ){ return false; }
	inc_pwcma_namelen += inl_ret;

    if(inp_pwlen > 0) {
	    /********************************************************************************************/
	    /* Create Data of CMA																		*/
	    /********************************************************************************************/
	    dsl_secure_xor.achc_destination	= chrl_data;
	    dsl_secure_xor.achc_post_key	= chrc_pwcma_name + PWCMA_LEN_PREFIX;
	    dsl_secure_xor.imc_len_post_key	= inc_pwcma_namelen - PWCMA_LEN_PREFIX;
	    dsl_secure_xor.achc_source		= (char*)achp_password;
	    dsl_secure_xor.imc_len_xor		= inp_pwlen;

	    bool bol_ret = adsc_wsp_helper->m_cb_secure_aux( &dsl_secure_xor );
	    if(!bol_ret)
		    return false;
    }

	/********************************************************************************************/
	/* Create CMA																				*/
	/********************************************************************************************/
	bool bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_pwcma_name, inc_pwcma_namelen, chrl_data, inp_pwlen, inc_idle_timeout );
	if(!bol_ret)
		return false;
	return true;

#undef PWCMA_LEN_PREFIX
}

/**
 * private function ds_usercma::m_open_pwcma
 *
 * @param[in]   bool    bop_write
 * @return      bool
*/
bool ds_usercma::m_open_pwcma( bool bop_write )
{
    // initialize some variables:
    void *avl_data;                         // pointer to cma content

    // open cma:
    avc_pwcma_handle = adsc_wsp_helper->m_cb_open_cma( chrc_pwcma_name, inc_pwcma_namelen, &avl_data, &inc_pwcma_datalen, bop_write );

    if ( avc_pwcma_handle == NULL ){ return false; } // cma doesnt exist. i dont try to create it, this is done via m_create_pwcma!
	
    // check return data:
    if ( avl_data == NULL )
	{
        m_close_pwcma();
        return false;
    }

    // initialize content pointer:
    avc_pwcma_data = avl_data;

    return true;
} // end of ds_usercma::m_open_pwcma

/**
 * private function ds_usercma::m_resize_pwcma
 *
 * @param[in]   int     inp_size
 * @return      bool                        true = success
*/
bool ds_usercma::m_resize_pwcma( int inp_size )
{
    // initialize some variables:
    bool  bol_ret;                                   // return from resize
    void* avl_data;                                  // pointer to cma content

    // check if cma is opened already:
    if ( avc_pwcma_handle == NULL ){ return false; }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_pwcma_handle, &avl_data, inp_size );
    if ( bol_ret == false )
	{
        avc_pwcma_data = NULL;
        return false;
    }

    // init return pointer:
    avc_pwcma_data = avl_data;
    return true;
} // end of ds_usercma::m_resize_pwcma

/**
 * private function ds_usercma::m_close_pwcma
 *
 * @return      bool
*/
bool ds_usercma::m_close_pwcma()
{
	avc_pwcma_data		= NULL;
	inc_pwcma_datalen	= 0;
    return adsc_wsp_helper->m_cb_close_cma( &avc_pwcma_handle );
} // end of ds_usercma::m_close_pwcma

/**
 * private function ds_usercma::m_create_main
 *
 * @return      bool                        true = success
*/
ds_wsp_helper::ied_cma_result ds_usercma::m_create_main()
{
    // initialize some variables:
    dsd_usercma_main dsl_main;

    memset( &dsl_main, 0, sizeof(dsd_usercma_main) );
    dsl_main.inc_version = USERCMA_VERSION;
    dsl_main.inc_port    = adsc_wsp_helper->m_get_listen_port();
    ds_wsp_helper::ied_cma_result inl_ret = adsc_wsp_helper->m_cb_create_cma_excl( chrc_main, inc_main,
                                                &dsl_main,
                                                sizeof(dsd_usercma_main),
												inc_idle_timeout );
	 if(inl_ret != ds_wsp_helper::iec_cma_success)
		 return inl_ret;
    return ds_wsp_helper::iec_cma_success;
} // end of ds_usercma::m_create_main

/**
 * private function ds_usercma::m_open_main
 *
 * @param[in]   bool    bop_write
 * @return      bool                        true = success
*/
bool ds_usercma::m_open_main( bool bop_write )
{
    // initialize some variables:
    void* avl_data;                         // pointer to cma content
    int   inl_len;                          // length of cma content

    // open cma:
    avc_main = adsc_wsp_helper->m_cb_open_cma( chrc_main, inc_main,
                                               &avl_data, &inl_len,
                                               bop_write            );
    if ( avc_main == NULL ) {
        return false;
    }

    // check return data:
    if (    avl_data == NULL
         || inl_len  <  (int)sizeof(dsd_usercma_main) ) {
        m_close_main();
        return false;
    }

    // initialize content pointer:
    adsc_main = (dsd_usercma_main*)avl_data;

    // compare version number:
    if ( adsc_main->inc_version != USERCMA_VERSION ) {
        m_close_main();
        return false;
    }

    // compare total length with our length pointers:
    if ( inl_len !=   (int)sizeof(dsd_usercma_main)
                    + adsc_main->inc_len_message
                    + adsc_main->inc_len_bpage ) {
        m_close_main();
        return false;
    }
    return true;
} // end of ds_basecma::m_open_cma


/**
 * private function ds_usercma::m_resize_main
 *
 * @param[in]   int     inp_size
 * @return      bool                        true = success
*/
bool ds_usercma::m_resize_main( int inp_size )
{
    // initialize some variables:
    bool  bol_ret;                                   // return from resize
    void* avl_data;                                  // pointer to cma content

    // check if cma is opened already:
    if ( avc_main == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_main, &avl_data, inp_size );
    if ( bol_ret == false ) {
        adsc_main = NULL;
        return false;
    }

    // init return pointer:
    adsc_main = (dsd_usercma_main*)avl_data;
    return true;
} // end of ds_usercma::m_resize_main


/**
 * private function ds_usercma::m_close_main
 *
 * @return      bool
*/
bool ds_usercma::m_close_main()
{
    adsc_main = NULL;
    return adsc_wsp_helper->m_cb_close_cma( &avc_main );
} // end of ds_usercma::m_close_main


/**
 * private function ds_usercma::m_create_login
 * create login cma
 *
 * @return      bool
*/
bool ds_usercma::m_create_login()
{
    bool bol_ret;
    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_login, inc_login,
                                                NULL, sizeof(dsd_usercma_login),
												inc_idle_timeout );
    return bol_ret;
} // end of ds_usercma::m_create_login


/**
 * private function ds_usercma::m_open_login
 *
 * @param[in]   bool    bop_write
 * @return      bool
*/
bool ds_usercma::m_open_login( bool bop_write )
{
    // initialize some variables:
    void *avl_data;                         // pointer to cma content
    int  inl_len;                           // length of cma content
    bool bol_ret;                           // return value

    // open cma:
    avc_login = adsc_wsp_helper->m_cb_open_cma( chrc_login, inc_login,
                                                &avl_data,  &inl_len,
                                                bop_write              );
    if ( avc_login == NULL ) {
        if ( bop_write == false ) {
            return false;
        }

        // cma does not exist, create it:
        bol_ret = m_create_login();
        if ( bol_ret == false ) {
            return false;
        }

        // try to open is again:
        avc_login = adsc_wsp_helper->m_cb_open_cma( chrc_login, inc_login,
                                                    &avl_data,  &inl_len,
                                                    bop_write              );
        if ( avc_login == NULL ) {
            return false;
        }
    }

    // check return data:
    if (    avl_data == NULL
         || inl_len  <  (int)sizeof(dsd_usercma_login) ) {
        m_close_login();
        return false;
    }

    //-----------------------------------------------
    // initialize content pointer:
    //-----------------------------------------------
    adsc_login = (dsd_usercma_login*)avl_data;

    //-----------------------------------------------
    // compare total length with our length pointers:
    //-----------------------------------------------
    if ( inl_len !=   (int)sizeof(dsd_usercma_login)
                   + adsc_login->inc_len_username
                   + adsc_login->inc_len_userdomain
                   + adsc_login->inc_len_password
                   + adsc_login->inc_len_userdn
                   + adsc_login->inc_len_wspgroup
                   + adsc_login->inc_len_role ) {
        m_close_login();
        return false;
    }
    return true;
} // end of ds_usercma::m_open_login


/**
 * private function ds_usercma::m_resize_login
 *
 * @param[in]   int inp_size
 * @return      bool
*/
bool ds_usercma::m_resize_login( int inp_size )
{
    // initialize some variables:
    bool  bol_ret;                          // return from resize
    void  *avl_data;                        // pointer to cma content

    // check if cma is opened already:
    if ( avc_login == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_login, &avl_data, inp_size );
    if ( bol_ret == false ) {
        return false;
    }

    // init return pointer:
    adsc_login = (dsd_usercma_login*)avl_data;
    return true;
} // end of ds_usercma::m_resize_login


/**
 * private function ds_usercma::m_close_login
 *
 * @return      bool
*/
bool ds_usercma::m_close_login()
{
    adsc_login = NULL;
    return adsc_wsp_helper->m_cb_close_cma( &avc_login );
} // end of ds_usercma::m_close_login


/**
 * private function ds_usercma::m_set_user
 *
 * @param[in]   const char  *achp_username
 * @param[in]   int         inp_unlen
 * @param[in]   const char  *achp_userdomain
 * @param[in]   int         inp_urlen
 * @param[in]   char        chp_session
 * @param[in]   const char  *achp_password
 * @param[in]   int         inp_pwlen
 * @param[in]   const char  *achp_wspgroup
 * @param[in]   int         inp_wglen
 * @param[in]   int         inp_auth_method
 * @param[in]   bool        bop_anonymous
 * @return      bool
*/
bool ds_usercma::m_set_user( const char *achp_username,   int inp_unlen,
                             const char *achp_userdomain, int inp_urlen,
                             const struct dsd_aux_ident_session_info* adsp_aux_ident_session_info,
                             const char *achp_password,  int inp_pwlen,
                             const char *achp_userdn,    int inp_dnlen,
                             const char *achp_wspgroup,  int inp_wglen,
                             int        inp_auth_method, enum ied_usercma_login_flags iep_auth_flags )
{
    // initialize some variables:
    bool bol_ret;
    char *achl_save;

    if (    inp_unlen < 0
         || inp_urlen < 0 
         || inp_pwlen < 0
         || inp_dnlen < 0
         || inp_wglen < 0 ) {
        return false;
    }

    // open cma for writing:
    bol_ret = m_open_login( true );
    if ( bol_ret == false ) {
        return false;
    }

    // resize cma:
    bol_ret = m_resize_login(   (int)sizeof(dsd_usercma_login)
                              + inp_unlen
                              + inp_urlen
                              + inp_pwlen
                              + inp_dnlen
                              + inp_wglen                       );
    if ( bol_ret == false ) {
        m_close_login();
        return false;
    }

    // reset older values:
    adsc_login->inc_len_role    = 0;
    adsc_login->inc_pwd_expires = -1;

    // save authentication method:
    adsc_login->inc_auth_method = inp_auth_method;

    // save timestamp:
    adsc_login->tmc_login     = adsc_wsp_helper->m_cb_get_time();
    adsc_login->iec_auth_flags = iep_auth_flags;
	 adsc_login->chc_session   = dsd_cma_session_no(adsp_aux_ident_session_info->ucc_session_no);

    // save username:
    adsc_login->inc_len_username  = inp_unlen;
    achl_save = (char*)(adsc_login + 1);
    if ( inp_unlen > 0 && achp_username != NULL ) {
        memcpy( achl_save, achp_username, inp_unlen );
    }
    achl_save += inp_unlen;

    // save userdomain:
    adsc_login->inc_len_userdomain = inp_urlen;
    if ( inp_urlen > 0 && achp_userdomain != NULL ) {
        memcpy( achl_save, achp_userdomain, inp_urlen );
    }
    achl_save += inp_urlen;

    // save password:
    adsc_login->inc_len_password = inp_pwlen;
    if ( inp_pwlen > 0 && achp_password != NULL ) {
        memcpy( achl_save, achp_password, inp_pwlen );
    }
    achl_save += inp_pwlen;

    // save userdn:
    adsc_login->inc_len_userdn = inp_dnlen;
    if ( inp_dnlen > 0 && achp_userdn != NULL ) {
        memcpy( achl_save, achp_userdn, inp_dnlen );
    }
    achl_save += inp_dnlen;

    // save wspgroup:
    adsc_login->inc_len_wspgroup = inp_wglen;
    if ( inp_wglen > 0 && achp_wspgroup != NULL ) {
        memcpy( achl_save, achp_wspgroup, inp_wglen );
    }

	 // copy session ticket
	 memcpy(adsc_login->chr_sticket, adsp_aux_ident_session_info->chrc_session_ticket, sizeof(adsp_aux_ident_session_info->chrc_session_ticket));

	 // save client ineta:
    adsc_wsp_helper->m_cb_get_clientip( &adsc_login->dsc_client );

    // close cma:
    m_close_login();
    return true;
} // end of ds_usercma::m_set_user


/**
 * private function ds_usercma::m_create_settings
 *
 * @return      bool
*/
bool ds_usercma::m_create_settings()
{
    bool bol_ret;
    dsd_usercma_settings dsl_settings;

    memset( &dsl_settings, 0, sizeof(dsd_usercma_settings) );
    dsl_settings.boc_flyer = true;
    dsl_settings.inc_lang  = -1;
    

    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_settings,
                                                inc_settings,
                                                &dsl_settings,
                                                sizeof(dsd_usercma_settings),
												inc_idle_timeout );
    return bol_ret;
} // end of ds_usercma::m_create_settings



/**
 * private function ds_usercma::m_open_settings
 *
 * @param[in]   bool    bop_write
 * @return      true if successful
*/
bool ds_usercma::m_open_settings( bool bop_write )
{
    // initialize some variables:
    void *avl_data;                         // pointer to cma content
    bool bol_ret;                           // return value
    int  inl_req_len;                       // required length of cma

    // open cma:
    avc_settings = adsc_wsp_helper->m_cb_open_cma( chrc_settings, inc_settings,
                                                   &avl_data, &inc_sclen,
                                                   bop_write );
    if ( avc_settings == NULL ) {
        if ( bop_write == false ) {
            return false;
        }

        // cma does not exist, create it:
        bol_ret = m_create_settings();
        if ( bol_ret == false ) {
            return false;
        }

        // try to open is again:
        avc_settings = adsc_wsp_helper->m_cb_open_cma( chrc_settings, inc_settings,
                                                       &avl_data, &inc_sclen,
                                                       bop_write );
        if ( avc_settings == NULL ) {
            return false;
        }
    }

    // check return data:
    if (    avl_data    == NULL
         || inc_sclen <  (int)sizeof(dsd_usercma_settings) ) {
        m_close_settings();
        return false;
    }

    // initialize content pointer:
    adsc_settings = (dsd_usercma_settings*)avl_data;

	// compare total length with our length pointers:
	inl_req_len = m_eval_size( ied_max_setting, false, NULL );
    if ( inc_sclen != inl_req_len ) {
        m_close_settings();
        return false;
    }

    return true;
} // end of ds_usercma::m_open_settings


/**
 * private function ds_usercma::m_resize_settings
 *
 * @param[in]   int inp_size
 * @return      bool
*/
bool ds_usercma::m_resize_settings( int inp_size )
{    
    // initialize some variables:
    bool  bol_ret;                          // return from resize
    void *avl_data;                         // pointer to cma content

    // check if cma is opened already:
    if ( avc_settings == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_settings, &avl_data, inp_size );
    if ( bol_ret == false ) {
        return false;
    }

    // init return pointer:
    adsc_settings = (dsd_usercma_settings*)avl_data;
    inc_sclen     = inp_size;
    return true;
} // end of d_usercma::m_resize_settings


/**
 * private function ds_usercma::m_close_settings
 *
 * @return      bool
*/
bool ds_usercma::m_close_settings()
{
#if 0
	// Assertion code
	if(avc_settings == NULL)
		return true;
	int inl_req_len = m_eval_size( ied_max_setting, false, NULL );
	if(inl_req_len != inc_sclen) {
		return false;
	}
#endif
    adsc_settings = NULL;
    inc_sclen     = 0;
    return adsc_wsp_helper->m_cb_close_cma( &avc_settings );
} // end of ds_usercma::m_close_settings


/**
 * private function ds_usercma::m_get_wsg_bmark
 *  get wsg bookmark structure from cma by index
 *
 * @param[in]   int                 inp_index   index number of bookmark
 * @return      dsd_cma_wsg_bmark*              pointer to found structure
*/
dsd_cma_wsg_bmark* ds_usercma::m_get_ws_bmark( int inp_index )
{
    // initialize some variables:
    int                 inl_offset;             // offset in memory
    int                 inl_counter;            // loop variable
    dsd_cma_wsg_bmark   *adsl_bmark = NULL;     // bookmark structure

    //-------------------------------------------
    // check total number of bookmarks:
    //-------------------------------------------
    if ( inp_index >= adsc_settings->inc_ws_bookmarks) {
        return NULL;
    }

    //-------------------------------------------
    // get offset:
    //-------------------------------------------
    inl_offset =   (int)sizeof(dsd_usercma_settings)
						+ adsc_settings->inc_len_umsg
                        + adsc_settings->inc_len_default_portlet;

    //-------------------------------------------
    // loop through bookmarks:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current bookmark struct
        adsl_bmark = (dsd_cma_wsg_bmark*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_wsg_bmark)
                          + adsl_bmark->inc_len_name
                          + adsl_bmark->inc_len_url;
        }
    }

    return adsl_bmark;
} // end of ds_usercma::m_get_wsg_bmark

/**
 * private function ds_usercma::m_get_wfa_bmark
 *  get wfa bookmark structure from cma by index
 *
 * @param[in]   int                 inp_index   index number of bookmark
 * @return      dsd_cma_wfa_bmark*              pointer to found structure
*/
dsd_cma_wfa_bmark* ds_usercma::m_get_wfa_bmark( int inp_index )
{
    // initialize some variables:
    int                 inl_offset;             // offset in memory
    int                 inl_counter;            // loop variable
    dsd_cma_wsg_bmark   *adsl_wsg_bmark;        // last wsg bookmark
    dsd_cma_wfa_bmark   *adsl_wfa_bmark = NULL; // wfa bookmark

    //-------------------------------------------
    // check total number of bookmarks:
    //-------------------------------------------
    if ( inp_index >= adsc_settings->inc_wfa_bookmarks ) {
        return NULL;
    }

    //-------------------------------------------
    // get offset:
    //-------------------------------------------
    adsl_wsg_bmark = m_get_ws_bmark( adsc_settings->inc_ws_bookmarks - 1 );
    if ( adsl_wsg_bmark == NULL ) {
        // no bookmark yet:
        inl_offset =   (int)sizeof(dsd_usercma_settings)
							+ adsc_settings->inc_len_umsg
                            + adsc_settings->inc_len_default_portlet;
    } else {
        // go to end of bookmark:
        inl_offset =   (int)((char*)adsl_wsg_bmark - (char*)adsc_settings)
                     + (int)sizeof(dsd_cma_wsg_bmark)
                     + adsl_wsg_bmark->inc_len_name
                     + adsl_wsg_bmark->inc_len_url;
    }

    //-------------------------------------------
    // loop through bookmarks:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current bookmark struct
        adsl_wfa_bmark = (dsd_cma_wfa_bmark*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_wfa_bmark)
                          + adsl_wfa_bmark->inc_len_name
                          + adsl_wfa_bmark->inc_len_url
                          + adsl_wfa_bmark->inc_len_user
                          + adsl_wfa_bmark->inc_len_pwd
                          + adsl_wfa_bmark->inc_len_domain;
        }
    }

    return adsl_wfa_bmark;
} // end of ds_usercma::m_get_wfa_bmark


/**
 * private function ds_usercma::m_get_workstation
 * get workstation structure from cma by index
 *
 * @param[in]   int                 inp_index   index number of workstation
 * @return      dsd_cma_workstation*            pointer to found structure
*/
dsd_cma_workstation* ds_usercma::m_get_workstation( int inp_index )
{
    // initialize some variables:
    int                  inl_offset;            // offset in memory
    int                  inl_counter;           // loop variable
    dsd_cma_workstation  *adsl_wstat = NULL;    // workstation structure
    dsd_cma_wsg_bmark    *adsl_wsg_bmark;       // last wsg bookmark structure
    dsd_cma_wfa_bmark    *adsl_wfa_bmark;       // last wfa bookmark structure

    //-------------------------------------------
    // check total workstations:
    //-------------------------------------------
    if ( inp_index >= adsc_settings->inc_workstations ) {
        return NULL;
    }

    //-------------------------------------------
    // get last bookmark:
    //-------------------------------------------
    adsl_wfa_bmark = m_get_wfa_bmark( adsc_settings->inc_wfa_bookmarks - 1 );
    if ( adsl_wfa_bmark == NULL ) {
        adsl_wsg_bmark = m_get_ws_bmark( adsc_settings->inc_ws_bookmarks - 1 );
        if ( adsl_wsg_bmark == NULL ) {
            // no bookmark yet:
            inl_offset =   (int)sizeof(dsd_usercma_settings)
								+ adsc_settings->inc_len_umsg
                                + adsc_settings->inc_len_default_portlet;
        } else {
            // go to end of bookmark:
            inl_offset =   (int)((char*)adsl_wsg_bmark - (char*)adsc_settings)
                         + (int)sizeof(dsd_cma_wsg_bmark)
                         + adsl_wsg_bmark->inc_len_name
                         + adsl_wsg_bmark->inc_len_url;
        }
    } else {
        // go to end of bookmark:
        inl_offset =   (int)((char*)adsl_wfa_bmark - (char*)adsc_settings)
                     + (int)sizeof(dsd_cma_wfa_bmark)
                     + adsl_wfa_bmark->inc_len_name
                     + adsl_wfa_bmark->inc_len_url
                     + adsl_wfa_bmark->inc_len_user
                     + adsl_wfa_bmark->inc_len_pwd
                     + adsl_wfa_bmark->inc_len_domain;
    }

    //-------------------------------------------
    // loop through bookmarks:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current workstation struct:
        adsl_wstat = (dsd_cma_workstation*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_workstation)
                          + adsl_wstat->inc_len_ineta
                          + adsl_wstat->inc_len_name;
        }
    }

    return adsl_wstat;
} // end of ds_usercma::m_get_workstation


/**
 * private function ds_usercma::m_get_portlet
 * get portlet structure from cma by index
 *
 * @param[in]   int                 inp_index   index number of workstation
 * @return      dsd_cma_portlet*                pointer to found structure
*/
dsd_cma_portlet* ds_usercma::m_get_portlet( int inp_index )
{
    // initialize some variables:
    int                  inl_offset;            // offset in memory
    int                  inl_counter;           // loop variable
    dsd_cma_workstation  *adsl_wstat;           // workstation structure
    dsd_cma_wfa_bmark    *adsl_wfa_bmark;       // last wfa bookmark structure
    dsd_cma_wsg_bmark    *adsl_wsg_bmark;       // last wsg bookmark structure
    dsd_cma_portlet      *adsl_portlet = NULL;  // portlet structure

    //-------------------------------------------
    // check total porlets:
    //-------------------------------------------
    if ( inp_index >= adsc_settings->inc_portlets ) {
        return NULL;
    }

    //-------------------------------------------
    // get last workstation:
    //-------------------------------------------
    adsl_wstat = m_get_workstation( adsc_settings->inc_workstations - 1 );
    if ( adsl_wstat == NULL ) {
        // no workstation yet -> get last bookmark
        adsl_wfa_bmark = m_get_wfa_bmark( adsc_settings->inc_wfa_bookmarks - 1 );
        if ( adsl_wfa_bmark == NULL ) {
            adsl_wsg_bmark = m_get_ws_bmark( adsc_settings->inc_ws_bookmarks - 1 );
            if ( adsl_wsg_bmark == NULL ) {
                // no bookmark yet:
                inl_offset =   (int)sizeof(dsd_usercma_settings)
								    + adsc_settings->inc_len_umsg
                                    + adsc_settings->inc_len_default_portlet;
            } else {
                // go to end of bookmark:
                inl_offset =   (int)((char*)adsl_wsg_bmark - (char*)adsc_settings)
                             + (int)sizeof(dsd_cma_wsg_bmark)
                             + adsl_wsg_bmark->inc_len_name
                             + adsl_wsg_bmark->inc_len_url;
            }
        } else {
            // go to end of bookmark:
            inl_offset =   (int)((char*)adsl_wfa_bmark - (char*)adsc_settings)
                         + (int)sizeof(dsd_cma_wfa_bmark)
                         + adsl_wfa_bmark->inc_len_name
                         + adsl_wfa_bmark->inc_len_url
                         + adsl_wfa_bmark->inc_len_user
                         + adsl_wfa_bmark->inc_len_pwd
                         + adsl_wfa_bmark->inc_len_domain;
        }
    } else {
        // go to end of workstation:
        inl_offset =   (int)((char*)adsl_wstat - (char*)adsc_settings)
                     + (int)sizeof(dsd_cma_workstation)
                     + adsl_wstat->inc_len_ineta
                     + adsl_wstat->inc_len_name;
    }

    //-------------------------------------------
    // loop through porlets:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current portlet struct:
        adsl_portlet = (dsd_cma_portlet*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_portlet)
                          + adsl_portlet->inc_len_name;
        }
    }

    return adsl_portlet;
} // end of ds_usercma::m_get_portlet



/*! \brief Count the amount of configs in the settings CMA
 *
 * @return		Amount of configs
 *
 */
int ds_usercma::m_jwtsa_count_configs()
{
    int inl_ret = 0;
    if ( m_open_settings(false) )
	{
		inl_ret = adsc_settings->inc_jwtsa_confs;
        m_close_settings();
    }
    return inl_ret;
}

/**
 * private function ds_usercma::m_jwtsa_get_config
 *  get jwtsa conf structure from cma by index
 *
 * @param[in]   int                 inp_index   index number of jwtsa configuration
 * @return      dsd_cma_wfa_bmark*              pointer to found structure
*/
dsd_cma_jwtsaconf*	ds_usercma::m_jwtsa_get_config ( int inp_index )
{
    // initialize some variables:
    int                  inl_offset;				// offset in memory
    int                  inl_counter;				// loop variable
    dsd_cma_workstation  *adsl_wstat;				// workstation structure
    dsd_cma_wfa_bmark    *adsl_wfa_bmark;			// last wfa bookmark structure
    dsd_cma_wsg_bmark    *adsl_wsg_bmark;			// last wsg bookmark structure
    dsd_cma_portlet      *adsl_portlet;				// portlet structure
	dsd_cma_jwtsaconf	 *adsl_jwtsaconf = NULL;	// jwtsa configurations

    //-------------------------------------------
    // check total porlets:
    //-------------------------------------------
	if ( inp_index >= adsc_settings->inc_jwtsa_confs ){ return NULL; }

    //-------------------------------------------
    // get last workstation:
    //-------------------------------------------
	adsl_portlet = m_get_portlet( adsc_settings->inc_portlets -1 );
	if( adsl_portlet == NULL ) // no portlet yet -> get last workstation
	{
		adsl_wstat = m_get_workstation( adsc_settings->inc_workstations - 1 );
		if( adsl_wstat == NULL ) // no workstation yet -> get last bookmark
		{        
			adsl_wfa_bmark = m_get_wfa_bmark( adsc_settings->inc_wfa_bookmarks - 1 );
			if( adsl_wfa_bmark == NULL )
			{
				adsl_wsg_bmark = m_get_ws_bmark( adsc_settings->inc_ws_bookmarks - 1 );
				if( adsl_wsg_bmark == NULL ) // no bookmark yet
				{
					inl_offset =   (int)sizeof(dsd_usercma_settings)
								     + adsc_settings->inc_len_umsg
                                     + adsc_settings->inc_len_default_portlet;
				}
				else // go to end of bookmark:
				{
					inl_offset =   (int)((char*)adsl_wsg_bmark - (char*)adsc_settings)
								 + (int)sizeof(dsd_cma_wsg_bmark)
								 + adsl_wsg_bmark->inc_len_name
								 + adsl_wsg_bmark->inc_len_url;
				}
			}
			else // go to end of bookmark:
			{
				inl_offset =   (int)((char*)adsl_wfa_bmark - (char*)adsc_settings)
							 + (int)sizeof(dsd_cma_wfa_bmark)
							 + adsl_wfa_bmark->inc_len_name
							 + adsl_wfa_bmark->inc_len_url
							 + adsl_wfa_bmark->inc_len_user
							 + adsl_wfa_bmark->inc_len_pwd
							 + adsl_wfa_bmark->inc_len_domain;
			}
		}
		else // go to end of workstation:
		{
			inl_offset =   (int)((char*)adsl_wstat - (char*)adsc_settings)
						 + (int)sizeof(dsd_cma_workstation)
						 + adsl_wstat->inc_len_ineta
						 + adsl_wstat->inc_len_name;
		}
	}
	else
	{
		inl_offset =	(int)( (char*)adsl_portlet - (char*)adsc_settings )
					+	(int) sizeof( dsd_cma_portlet )
					+	adsl_portlet->inc_len_name;
	}

    //-------------------------------------------
    // loop through configs:
    //-------------------------------------------
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
        if ( inl_offset > inc_sclen ) {
            return NULL;
        }

        // get current portlet struct:
        adsl_jwtsaconf = (dsd_cma_jwtsaconf*)((char*)adsc_settings + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and string lengths:
            inl_offset +=   (int)sizeof(dsd_cma_jwtsaconf)
                          + adsl_jwtsaconf->inc_len_name;
        }
    }

    return adsl_jwtsaconf;
}


/**
 * \ingroup authlib
 *
 * public function ds_usercma::m_jwtsa_get_config
 * get users jwt sa configuration from index number
 *
 * @param[in]   int				inp_index				index number
 * @param[out]  ds_jwtsa_conf*	adsp_jwtsa_config		output bmark
 * @return      bool									true = success
*/
bool ds_usercma::m_jwtsa_get_config( int inp_index, ds_jwtsa_conf* adsp_jwtsa_config )
{
    // initialize some variables:
    bool               bol_ret;                 // return for some func calls
    dsd_cma_jwtsaconf *adsl_cma_config;         // current config in cma
    char*              achl_name;               // name

    // init variable:
    adsp_jwtsa_config->m_init( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }

    // get config at index:
    adsl_cma_config = m_jwtsa_get_config( inp_index );
    if ( adsl_cma_config == NULL ) {
        m_close_settings();
        return false;
    }

    // get name:
    achl_name = (char*)adsl_cma_config + sizeof(dsd_cma_jwtsaconf);

    // set name:
    adsp_jwtsa_config->m_set_name( achl_name, adsl_cma_config->inc_len_name );

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_jwtsa_get_config



/**
 * private function ds_usercma::m_get_wsg_bookmark
 * get users webservergate bookmark from index number
 *
 * @param[in]   enum ied_bookmark_type   ienp_type  which bookmark to get (wsg or rdvpn)
 * @param[in]   int             inp_index           index number
 * @param[out]  ds_bookmark*    adsp_bmark          output bmark
 * @return      bool                                true = success
*/
bool ds_usercma::m_get_ws_bookmark( enum ied_bookmark_type ienp_type, int inp_index, ds_bookmark* adsp_bmark )
{
    // initialize some variables:
    bool               bol_ret;                 // return for some func calls
    dsd_cma_wsg_bmark *adsl_bm_cma;             // current bookmark in cma
    char*              achl_url;                // url
    char*              achl_name;               // name

    // init variable:
    adsp_bmark->m_init( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }
    
    switch (ienp_type) {
        case ied_bookmark_rdvpn:
            inp_index += adsc_settings->inc_wsg_bookmarks;
        case ied_bookmark_wsg:
            break;
        default:
            return false; //unimplemented type
    }
    
    // get bookmark at index:
    adsl_bm_cma = m_get_ws_bmark( inp_index );
    if ( adsl_bm_cma == NULL ) {
        m_close_settings();
        return false;
    }

    // get name and url:
    achl_name = (char*)adsl_bm_cma + sizeof(dsd_cma_wsg_bmark);
    achl_url  = achl_name + adsl_bm_cma->inc_len_name;

    // set name and url:
    adsp_bmark->m_set_name( achl_name, adsl_bm_cma->inc_len_name );
    adsp_bmark->m_set_url ( achl_url,  adsl_bm_cma->inc_len_url  );

    // set ownership:
    adsp_bmark->m_set_own( adsl_bm_cma->boc_is_own );

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_ws_bookmark


/**
 * private function ds_usercma::m_get_wsg_bookmarks
 * get users webservergate bookmarks
 *
 * @param[in]   enum ied_bookmark_type      ienp_type        which bookmarks to get (wsg or rdvpn)
 * @param[in]   ds_hvector<ds_bookmark>*    adsp_bmarks      output buffer
 * @return      bool
*/
bool ds_usercma::m_get_ws_bookmarks( enum ied_bookmark_type ienp_type, ds_hvector<ds_bookmark> *adsp_bmarks )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_pos;                  // loop variable
    ds_bookmark       dsl_bmark;                // current bookmark
    dsd_cma_wsg_bmark *adsl_bm_cma;             // current bookmark in cma
    char*             achl_url;                 // url
    char*             achl_name;                // name
    int               inl_first;                // index of first bookmark in ws array
    int               inl_count;                // count of bookmarks to copy
    
    // init incoming vector:
    adsp_bmarks->m_init( adsc_wsp_helper );
    dsl_bmark.m_init   ( adsc_wsp_helper );

    // open cma for reading:
    bol_ret = m_open_settings( false );
    if ( bol_ret == false ) {
        return false;
    }
    
    switch (ienp_type) {
        case ied_bookmark_wsg:
            inl_first = 0;
            inl_count = adsc_settings->inc_wsg_bookmarks;
            break;
        case ied_bookmark_rdvpn:
            inl_first = adsc_settings->inc_wsg_bookmarks;
            inl_count = adsc_settings->inc_rdvpn_bookmarks;
            break;
        default:
            return false; //unimplemented type
    }


    // loop through all wsg bookmarks:
    for ( inl_pos = inl_first; inl_pos < inl_first+inl_count; inl_pos++ ) {
        adsl_bm_cma = m_get_ws_bmark( inl_pos );
        if ( adsl_bm_cma == NULL ) {
            m_close_settings();
            return false;
        }

        // get name and url:
        achl_name = (char*)adsl_bm_cma + sizeof(dsd_cma_wsg_bmark);
        achl_url  = achl_name + adsl_bm_cma->inc_len_name;

        // set name and url:
        dsl_bmark.m_set_name( achl_name, adsl_bm_cma->inc_len_name );
        dsl_bmark.m_set_url ( achl_url,  adsl_bm_cma->inc_len_url  );

        // set ownership:
        dsl_bmark.m_set_own( adsl_bm_cma->boc_is_own );

        // add to vector:
        adsp_bmarks->m_add( dsl_bmark );
    }

    // close cma:
    m_close_settings();
    return true;
} // end of ds_usercma::m_get_ws_bookmarks


/**
 * private function ds_usercma::m_set_wsg_bookmarks
 * save webservergate/proxy bookmarks in cma 
 * ATTENTION: this call will overwrite existing bookmarks (of same type)
 * 
 * @param[in]   enum ied_bookmark_type       ienp_type      which bookmarks to set (wsg or rdvpn)
 * @param[in]   ds_hvector<ds_bookmark>*    ads_bmarks      bookmarks to be saved
 * @param[in]   bool                bop_keep_inherited      wether to keep or override inherited bookmarks of selected type
 * @return      bool                                        true = success
*/
bool ds_usercma::m_set_ws_bookmarks( enum ied_bookmark_type ienp_type, ds_hvector<ds_bookmark> *adsp_bmarks, bool bop_keep_inherited )
{
    // initialize some variables:
    bool              bol_ret;                  // return for some func calls
    int               inl_size;                 // new size of cma
    int               inl_offset;               // offset in cma
    int               inl_pos;                  // loop variable
    const char*             achl_url;                 // url
    int               inl_len_url;              // length of url
    const char*             achl_name;                // name
    int               inl_len_name;             // length of name
    dsd_cma_wsg_bmark *adsl_bm_cma;             // current bookmark in cma
    ds_hvector<ds_bookmark> dsl_bmarks_temp;    // all bookmarks (new and old of other types)
    int               inl_first;                // index of first bookmark in ws array
    int               inl_count;                // count of bookmarks to copy
    ds_bookmark       dsl_bmark;                // current bookmark copy
    int               inl_inherited;            // number of inherited bms copied
    
    dsl_bmarks_temp.m_init(adsc_wsp_helper);
	dsl_bmark.m_init(adsc_wsp_helper);
    inl_inherited = 0;
    
    // open cma for writing:
    bol_ret = m_open_settings( true );
    if ( bol_ret == false ) {
        return false;
    }
    
    switch (ienp_type) {
        case ied_bookmark_wsg:
            inl_first = 0;
            inl_count = adsc_settings->inc_wsg_bookmarks;
            break;
        case ied_bookmark_rdvpn:
            inl_first = adsc_settings->inc_wsg_bookmarks;
            inl_count = adsc_settings->inc_rdvpn_bookmarks;
            break;
        default:
            return false; //unimplemented type
    }


    // save data behind our insert pointer:
    bol_ret = m_create_backup( ied_wfa_bmarks );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // evaluate new needed length:
    inl_size = m_eval_size( ied_wsg_bmarks, false, NULL );
    inl_offset = inl_size;
    
    //run the loop at least once, even when there are no bookmarks to copy the new bm's
    for(inl_pos = 0; inl_pos <= adsc_settings->inc_ws_bookmarks; inl_pos++) {
        inl_offset = ALIGN_INT(inl_offset);
        adsl_bm_cma = (dsd_cma_wsg_bmark*)((char*)adsc_settings + inl_offset);
        //position after the last bookmark of type to replace (==first of next type or element after list end): insert new bookmarks
        if (inl_pos == inl_first+inl_count) {
            for (HVECTOR_FOREACH(ds_bookmark, adsl_cur, *adsp_bmarks)) {
                const ds_bookmark& dsl_bmark_orig = HVECTOR_GET(adsl_cur);
                dsl_bmark_orig.m_get_url ( &achl_url,  &inl_len_url );
                dsl_bmark_orig.m_get_name( &achl_name, &inl_len_name );

                if (    inl_len_url > 0 && inl_len_name > 0 ) {
                    inl_size =   ALIGN_INT(inl_size)
                               + (int)sizeof(dsd_cma_wsg_bmark)
                               + inl_len_url
                               + inl_len_name;
                    
                    // set name and url:
                    dsl_bmark.m_set_name( achl_name, inl_len_name );
                    dsl_bmark.m_set_url ( achl_url,  inl_len_url  );

                    // set ownership:
					dsl_bmark.m_set_own( dsl_bmark_orig.m_is_own() );

                    // add to temp vector:
                    dsl_bmarks_temp.m_add( dsl_bmark );
                }
            }
        }
        //bookmarks of other type than the one to replace, or inherited (when keep_inherited): copy to tmp
        if(   inl_pos < adsc_settings->inc_ws_bookmarks 
            && (inl_pos < inl_first
                || (inl_pos >= inl_first+inl_count)
                || (bop_keep_inherited && !adsl_bm_cma->boc_is_own))) {
            
            if(   inl_pos >= inl_first && inl_pos < inl_first+inl_count) {
                inl_inherited++;
            }
            
            inl_size = ALIGN_INT(inl_size);
            // get current bookmark struct

            // add structure and string lengths to new size:
            inl_size +=   (int)sizeof(dsd_cma_wsg_bmark)
                      + adsl_bm_cma->inc_len_name
                      + adsl_bm_cma->inc_len_url;
            
            
            // get name and url:
            achl_name = (char*)adsl_bm_cma + sizeof(dsd_cma_wsg_bmark);
            achl_url  = achl_name + adsl_bm_cma->inc_len_name;

            // set name and url:
            dsl_bmark.m_set_name( achl_name, adsl_bm_cma->inc_len_name );
            dsl_bmark.m_set_url ( achl_url,  adsl_bm_cma->inc_len_url  );

            // set ownership:
            dsl_bmark.m_set_own( adsl_bm_cma->boc_is_own );

            // add to temp vector:
            dsl_bmarks_temp.m_add( dsl_bmark );
        }

        // add structure and string lengths to offset (read pos):
        inl_offset +=   (int)sizeof(dsd_cma_wsg_bmark)
                      + adsl_bm_cma->inc_len_name
                      + adsl_bm_cma->inc_len_url;
    }
    
    if ( inc_scbc_len > 0 ) {
        inl_size =   ALIGN_INT(inl_size)
                   + inc_scbc_len;
    }

    // resize cma:
    bol_ret = m_resize_settings( inl_size );
    if ( bol_ret == false ) {
        m_close_settings();
        return false;
    }

    // insert new bookmarks:
    switch (ienp_type) {
        case ied_bookmark_wsg:
            adsc_settings->inc_wsg_bookmarks = (int)adsp_bmarks->m_size() + inl_inherited;
            break;
        case ied_bookmark_rdvpn:
            adsc_settings->inc_rdvpn_bookmarks = (int)adsp_bmarks->m_size() + inl_inherited;
            break;
        default:
            return false; //unimplemented type
    }

    adsc_settings->inc_ws_bookmarks = adsc_settings->inc_wsg_bookmarks + adsc_settings->inc_rdvpn_bookmarks;
    inl_pos = 0;
    inl_offset = m_eval_size( ied_wsg_bmarks, false, NULL );
    
    for (HVECTOR_FOREACH(ds_bookmark, adsl_cur, dsl_bmarks_temp)) {
        const ds_bookmark& dsl_bmark_ref = HVECTOR_GET(adsl_cur);
        // get buffer in cma:
        inl_offset = ALIGN_INT(inl_offset);
        adsl_bm_cma = (dsd_cma_wsg_bmark*)((char*)adsc_settings + inl_offset);
        
        if ( inl_offset > inc_sclen ) {
            continue;
        }

        // get incoming bookmark:
        dsl_bmark_ref.m_get_name( &achl_name, &inl_len_name );
        dsl_bmark_ref.m_get_url ( &achl_url,  &inl_len_url );

        // copy ownership
        adsl_bm_cma->boc_is_own = dsl_bmark_ref.m_is_own();

        // copy length:
        adsl_bm_cma->inc_len_name = inl_len_name;
        adsl_bm_cma->inc_len_url  = inl_len_url;

        // copy data itself:
        memcpy( (char*)adsl_bm_cma + sizeof(dsd_cma_wsg_bmark),
                achl_name, inl_len_name );
        memcpy( (char*)adsl_bm_cma + sizeof(dsd_cma_wsg_bmark) + inl_len_name,
                achl_url, inl_len_url );
        // add structure and string lengths to offset (write pos):
        inl_offset +=   (int)sizeof(dsd_cma_wsg_bmark)
                      + adsl_bm_cma->inc_len_name
                      + adsl_bm_cma->inc_len_url;

    }

    // copy saved data back:
    bol_ret = m_free_backup( ied_wfa_bmarks );

    // close cma:
    m_close_settings();
    return bol_ret;
} // end of ds_usercma::m_set_ws_bookmarks


/**
 * private function ds_usercma::m_create_backup
 * save data from given point til end of cma 
 * 
 * @param[in]   enum ied_usercma_settings   ienp_type
 * @return      bool
*/
bool ds_usercma::m_create_backup( enum ied_usercma_settings ienp_type )
{
    // initialize some variables:
    void *avl_temp;

    avl_temp = m_get_first_of( ienp_type );
    if ( avl_temp != NULL ) {
        inc_scbc_len = inc_sclen - (int)((char*)avl_temp - (char*)adsc_settings);
        if ( inc_scbc_len > 0 ) {
            achc_sc_bac = adsc_wsp_helper->m_cb_get_memory( inc_scbc_len, false );
            if ( achc_sc_bac == NULL ) {
                return false;
            }
            memcpy( achc_sc_bac, avl_temp, inc_scbc_len );
        }
    } else {
        inc_scbc_len = 0;
    }
    return true;
} // end of ds_usercma::m_create_backup


/**
 * private function ds_usercma::m_free_backup
 * free backuped data
 * 
 * @param[in]   enum ied_usercma_settings   ienp_type
 * @return      bool
*/
bool ds_usercma::m_free_backup( enum ied_usercma_settings ienp_type )
{
    // initialize some variables:
    void *avl_temp;

    if ( inc_scbc_len > 0 ) {
        avl_temp = m_get_first_of( ienp_type );
        if ( avl_temp == NULL ) {
            return false;
        }
        memcpy( avl_temp, achc_sc_bac, inc_scbc_len );
        adsc_wsp_helper->m_cb_free_memory( achc_sc_bac );
        inc_scbc_len = 0;
    }
    return true;
} // end of ds_usercma::m_free_backup


/**
 * private function ds_usercma::m_get_first_of
 * get first pointer of following data (needed to backup data)
 * 
 * @param[in]   enum ied_usercma_settings   ienp_type
 * @return      void*                       pointer to first found element
*/
void* ds_usercma::m_get_first_of( enum ied_usercma_settings ienp_type )
{
    // initialize some variables:
    void *avl_ret = NULL;

    switch ( ienp_type ) {
		case ied_default_portlet:
			avl_ret = ((char*) adsc_settings) + 
					ALIGN_INT((int)sizeof(dsd_usercma_settings)+ adsc_settings->inc_len_umsg);
			break;
        case ied_wsg_bmarks:
            avl_ret = (void*)m_get_ws_bmark( 0 );
            // break missing on purpose!

        case ied_wfa_bmarks:
            if ( avl_ret == NULL ){ avl_ret = (void*)m_get_wfa_bmark( 0 ); }
			else{ break; }
            // break missing on purpose!

        case ied_workstats:
            if ( avl_ret == NULL ){ avl_ret = (void*)m_get_workstation( 0 ); } 
			else{ break; }
            // break missing on purpose!

        case ied_portlets:
            if ( avl_ret == NULL ){ avl_ret = m_get_portlet( 0 ); }
			else{ break; }
            // break missing on purpose!

		case ied_jwtsa_conf:
			if( avl_ret == NULL){ avl_ret = m_jwtsa_get_config( 0 ); }
			break;
#if BO_HOBTE_CONFIG
        case ied_hobte_conf:
            if( avl_ret == NULL){ avl_ret = m_hobte_get_config( 0 ); }
            break;
#endif
    }
    return avl_ret;
} // end of ds_usercma::m_get_first_of


/**
 * private function ds_usercma::m_eval_size
 * evaluate size until given type
 * 
 * @param[in]   enum ied_usercma_settings   ienp_type
 * @param[in]   bool                        bop_only_inherited
 * @param[in]   int*                        ainp_inherited
 * @return      int                         size
*/
int ds_usercma::m_eval_size( enum ied_usercma_settings ienp_type,
                             bool bop_only_inherited, int *ainp_inherited )
{    // initialize some variables:
    int                         inl_ret;
    int                         inl_pos;
    int                         inl_type;
    struct dsd_cma_wsg_bmark    *adsl_wsg_bmark;
    struct dsd_cma_wfa_bmark    *adsl_wfa_bmark;
    struct dsd_cma_workstation  *adsl_wstat;
    struct dsd_cma_portlet      *adsl_portlet;
	struct dsd_cma_jwtsaconf	*adsl_jwtsaconf;
#if BO_HOBTE_CONFIG
    struct dsd_cma_hobteconf	*adsl_hobteconf;
#endif

    inl_ret = 0;
    if ( ainp_inherited != NULL ) {
        *ainp_inherited = 0;
    }
	int inl_type_incl = ienp_type-1;
    for ( inl_type = (int)ied_struct_only; inl_type <= inl_type_incl; inl_type++ ) {
        switch( inl_type ) {
            case ied_struct_only:
                inl_ret += (int)sizeof( dsd_usercma_settings );
                break;

            case ied_usr_msg:
                inl_ret += adsc_settings->inc_len_umsg;
                break;

            case ied_default_portlet:
                inl_ret += adsc_settings->inc_len_default_portlet;
                break;

            case ied_wsg_bmarks:
                // loop trough wsg bookmarks:
                for ( inl_pos = 0; inl_pos < adsc_settings->inc_ws_bookmarks; inl_pos++ ) {
                    adsl_wsg_bmark = m_get_ws_bmark( inl_pos );
                    if ( adsl_wsg_bmark == NULL ) {
                        continue;
                    }

                    if (    inl_type                   == inl_type_incl
                         && bop_only_inherited         == true
                         && adsl_wsg_bmark->boc_is_own == true      ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof(dsd_cma_wsg_bmark)
                              + adsl_wsg_bmark->inc_len_name
                              + adsl_wsg_bmark->inc_len_url;

                    if (    inl_type           == inl_type_incl
                         && bop_only_inherited == true
                         && ainp_inherited     != NULL ) {
                        (*ainp_inherited)++;
                    }
                }
                break;
                
            case ied_wfa_bmarks:
                // loop through wfa bookmarks:
                for ( inl_pos = 0; inl_pos < adsc_settings->inc_wfa_bookmarks; inl_pos++ ) {
                    adsl_wfa_bmark = m_get_wfa_bmark( inl_pos );
                    if ( adsl_wfa_bmark == NULL ) {
                        continue;
                    }

                    if (    inl_type                   == inl_type_incl
                         && bop_only_inherited         == true
                         && adsl_wfa_bmark->boc_is_own == true      ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof(dsd_cma_wfa_bmark)
                              + adsl_wfa_bmark->inc_len_name
                              + adsl_wfa_bmark->inc_len_url
                              + adsl_wfa_bmark->inc_len_user
                              + adsl_wfa_bmark->inc_len_pwd
                              + adsl_wfa_bmark->inc_len_domain;

                    if (    inl_type           == inl_type_incl
                         && bop_only_inherited == true
                         && ainp_inherited     != NULL ) {
                        (*ainp_inherited)++;
                    }
                }
                break;

            case ied_workstats:
                // loop through workstations:
                for ( inl_pos = 0; inl_pos < adsc_settings->inc_workstations; inl_pos++ ) {
                    adsl_wstat = m_get_workstation( inl_pos );
                    if ( adsl_wstat == NULL ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof(dsd_cma_workstation)
                              + adsl_wstat->inc_len_name
                              + adsl_wstat->inc_len_ineta;
                }
                break;

            case ied_portlets:
                // loop trough portlets:
                for ( inl_pos = 0; inl_pos < adsc_settings->inc_portlets; inl_pos++ ) {
                    adsl_portlet = m_get_portlet( inl_pos );
                    if ( adsl_portlet == NULL ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof(dsd_cma_portlet)
                              + adsl_portlet->inc_len_name;
                }
                break;
			case ied_jwtsa_conf:
				for ( inl_pos = 0; inl_pos < adsc_settings->inc_jwtsa_confs; inl_pos++ )
				{
                    adsl_jwtsaconf = m_jwtsa_get_config( inl_pos );
                    if ( adsl_jwtsaconf == NULL ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof( dsd_cma_jwtsaconf )
                              + adsl_jwtsaconf->inc_len_name;
                }
				break;
#if BO_HOBTE_CONFIG
            case ied_hobte_conf:
				for ( inl_pos = 0; inl_pos < adsc_settings->inc_hobte_confs; inl_pos++ )
				{
                    adsl_hobteconf = m_hobte_get_config( inl_pos );
                    if ( adsl_hobteconf == NULL ) {
                        continue;
                    }

                    inl_ret =   ALIGN_INT(inl_ret)
                              + (int)sizeof( dsd_cma_hobteconf )
                              + adsl_hobteconf->inc_len_name;
                }
				break;
#endif        
        }
    }
    return inl_ret;
} // end of ds_usercma::m_eval_size


/**
 * private function ds_usercma::m_create_wsg
 *
 * @return  bool
*/
bool ds_usercma::m_create_wsg()
{
    bool bol_ret;

    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_wsg, inc_wsg,
                                                NULL, sizeof(dsd_usercma_wsg),
												inc_idle_timeout );
    return bol_ret;
} // end of ds_usercma::m_create_wsg


/**
 * private function ds_usercma::m_open_wsg
 *
 * @param[in]   bool    bop_write
 * @return      bool
*/
bool ds_usercma::m_open_wsg( bool bop_write )
{
    // initialize some variables:
    void *avl_data;                         // pointer to cma content
    int  inl_len;                           // length of cma content
    bool bol_ret;                           // return value

    // open cma:
    avc_wsg = adsc_wsp_helper->m_cb_open_cma( chrc_wsg, inc_wsg,
                                              &avl_data, &inl_len, bop_write );
    if ( avc_wsg == NULL ) {
        if ( bop_write == false ) {
            return false;
        }

        // cma does not exist, create it:
        bol_ret = m_create_wsg();
        if ( bol_ret == false ) {
            return false;
        }

        // try to open is again:
        avc_wsg = adsc_wsp_helper->m_cb_open_cma( chrc_wsg, inc_wsg,
                                                  &avl_data, &inl_len, bop_write );
        if ( avc_wsg == NULL ) {
            return false;
        }
    }

    // check return data:
    if (    avl_data == NULL
         || inl_len  <  (int)sizeof(dsd_usercma_wsg) ) {
        m_close_wsg();
        return false;
    }

    // initialize content pointer:
    adsc_wsg = (dsd_usercma_wsg*)avl_data;

    // compare total length with our length pointers:
    if ( inl_len !=   (int)sizeof(dsd_usercma_wsg)
                    + adsc_wsg->inc_len_lastws     ) {
        m_close_wsg();
        return false;
    }    
    return true;
} // end of ds_usercma::m_open_wsg


/**
 * private function ds_usercma::m_resize_wsg
 *
 * @param[in]   int     inp_size
 * @return      bool
*/
bool ds_usercma::m_resize_wsg( int inp_size )
{
    // initialize some variables:
    bool bol_ret;                           // return from resize
    void *avl_data;                         // pointer to cma content

    // check if cma is opened already:
    if ( avc_wsg == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_wsg, &avl_data, inp_size );
    if ( bol_ret == false ) {
        return false;
    }

    // init return pointer:
    adsc_wsg = (dsd_usercma_wsg*)avl_data;
    return true;
} // end of ds_usercma::m_resize_wsg


/**
 * private function ds_usercma::m_close_wsg
 *
 * @return      bool
*/
bool ds_usercma::m_close_wsg()
{
    adsc_wsg = NULL;
    return adsc_wsp_helper->m_cb_close_cma( &avc_wsg );
} // end of ds_usercma::m_close_wsg


/**
 * private function ds_usercma::m_open_ineta
 *
 * @param[in]   bool bop_write
 * @return      bool
*/
bool ds_usercma::m_open_ineta( bool bop_write )
{
    // initialize some variables:
    void *avl_data;
    int  inl_len;

    // open cma:
    avc_ineta = adsc_wsp_helper->m_cb_open_cma( chrc_ineta, inc_ineta,
                                                &avl_data, &inl_len,
                                                bop_write );
    if ( avc_ineta == NULL ) {
        return false;
    }

    // check return data:
    if (    avl_data    == NULL
         || inl_len  < (int)sizeof(dsd_ineta_cma_data) ) {
        m_close_ineta();
        return false;
    }

    // initialize content pointer:
    adsc_ineta = (dsd_ineta_cma_data*)avl_data;
    return true;
} // end of ds_usercma::m_open_ineta


/**
 * private function ds_usercma::m_close_ineta
 *
 * @return      bool
*/
bool ds_usercma::m_close_ineta()
{
    adsc_ineta = NULL;
    return adsc_wsp_helper->m_cb_close_cma( &avc_ineta );
} // end of ds_usercma::m_close_ineta


/**
 * private function ds_usercma::m_fill_config_struct
 * fill dsd_config_ineta structure
 *
 * @param[in]   int     in_inetas           number of inetas
 * @param[in]   int     in_memory           required memory
 * @param[in]   int     in_group            ineta group 
 * @return      bool                        true = success
*/
bool ds_usercma::m_fill_config_struct( int inp_inetas, int inp_memory, int inp_group )
{
    // initialize some variables:
    struct dsd_config_ineta_1* adsl_ineta_group;

    adsl_ineta_group = m_get_config_struct( inp_group );
    if ( adsl_ineta_group == NULL ) {
        return false;
    }

    adsl_ineta_group->imc_no_ineta = inp_inetas;
    adsl_ineta_group->imc_len_mem  = inp_memory;
    return true;
} // end of ds_ineta::m_fill_config_struct

/**
 * private function ds_usercma::m_get_config_struct
 * get config struct from cma by group
 *
 * @param[in]   int                 in_group    ineta group
 * @return      dsd_config_ineta_1*             pointer to found structure
*/
dsd_config_ineta_1* ds_usercma::m_get_config_struct( int inp_group )
{
    switch ( inp_group ) {
        case DEF_INETA_GROUP_PPP:
            if ( adsc_ineta->inc_off_ppp == 0 ) {
                return NULL;
            }
            return (dsd_config_ineta_1*)((char*)adsc_ineta + adsc_ineta->inc_off_ppp);

        case DEF_INETA_GROUP_HTCP:
            if ( adsc_ineta->inc_off_htcp == 0 ) {
                return NULL;
            }
            return (dsd_config_ineta_1*)((char*)adsc_ineta + adsc_ineta->inc_off_htcp);

        default:
            return NULL;
    }
} // end of ds_usercma::m_get_config_struct



/**
 * private function ds_usercma::m_get_ineta
 * get ineta structure from cma by index
 *
 * @param[in]   int                 in_index    index number of ineta
 * @param[in]   int                 in_group    ineta group
 * @return      dsd_ineta_single_1*             pointer to found structure
*/
dsd_ineta_single_1* ds_usercma::m_get_ineta( int inp_index, int inp_group )
{
    // initialize some variables:
    struct dsd_config_ineta_1* adsl_ineta_group;
    struct dsd_ineta_single_1* adsl_ineta_single = NULL;
    int                        inl_counter;
    int                        inl_offset;

    //-------------------------------------------
    // select INETA group:
    //-------------------------------------------
    adsl_ineta_group = m_get_config_struct( inp_group );
    if ( adsl_ineta_group == NULL ) {
        return NULL;
    }

    //-------------------------------------------
    // check total INETAs:
    //-------------------------------------------
    if ( inp_index >= adsl_ineta_group->imc_no_ineta ) {
        return NULL;
    }

    //-------------------------------------------
    // loop through INETAs:
    //-------------------------------------------
    inl_offset = sizeof(dsd_config_ineta_1);
    for ( inl_counter = 0; inl_counter <= inp_index; inl_counter++ ) {
#ifndef DEF_DONT_ALIGN_SINGLE
        // alignment:
        inl_offset = ALIGN_INT(inl_offset);
#endif
        if ( inl_offset > adsl_ineta_group->imc_len_mem ) {
            return NULL;
        }

        // get current INETA:
        adsl_ineta_single = (dsd_ineta_single_1*)((char*)adsl_ineta_group + inl_offset);

        if ( inl_counter < inp_index ) {
            // add structure and address length:
            inl_offset +=   (int)sizeof(dsd_ineta_single_1)
                          + adsl_ineta_single->usc_length;
        }
    }
    return adsl_ineta_single;
} // end of ds_usercma::m_get_ineta


/**
 * private function ds_usercma::m_create_roles
 *
 * @return      bool
*/
bool ds_usercma::m_create_roles( int inp_len )
{
    bool bol_ret;

    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_roles, inc_roles,
                                                NULL, inp_len, inc_idle_timeout );
    return bol_ret;
} // end of ds_usercma::m_create_roles


/**
 * function ds_usercma::m_open_roles
 *
 * @param[in]   bool    bop_write
 * @return      bool
*/
bool ds_usercma::m_open_roles( bool bop_write )
{
    avc_roles = adsc_wsp_helper->m_cb_open_cma( chrc_roles, inc_roles,
                                                (void**)&achc_roles,
                                                &inc_rclen,
                                                bop_write );
    if ( avc_roles == NULL ) {
        return false;
    }

    // check return data:
    if (    achc_roles == NULL
         || inc_rclen   < 0    ) {
        m_close_roles();
        return false;
    }
    return true;
} // end of ds_usercma::m_open_roles


/**
 * private function ds_usercma::m_resize_roles
 *
 * @param[in]   int inp_size
 * @return      bool
*/
bool ds_usercma::m_resize_roles( int inp_size )
{
    // initialize some variables:
    bool bol_ret;

    // check if cma is opened already:
    if ( avc_roles == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_roles,
                                                (void**)&achc_roles,
                                                inp_size );
    if ( bol_ret == false ) {
        return false;
    }
    inc_rclen = inp_size;
    return true;
} // end of ds_usercma::m_resize_roles


/**
 * private function ds_usercma::m_close_roles
 *
 * @return      bool
*/
bool ds_usercma::m_close_roles()
{
    achc_roles = NULL;
    inc_rclen  = 0;
    return adsc_wsp_helper->m_cb_close_cma( &avc_roles );
} // end of ds_usercma::m_close_roles


/**
 * private function ds_usercma::m_create_axss
 *
 * @return      bool
*/
bool ds_usercma::m_create_axss()
{
    bool bol_ret;
    bol_ret = adsc_wsp_helper->m_cb_create_cma( chrc_axss, inc_axss,
                                                NULL, sizeof(dsd_usercma_axss),
												inc_idle_timeout );
    return bol_ret;
} // end of ds_usercma::m_create_axss


/**
 * function ds_usercma::m_open_axss
 *
 * @param[in]   bool    bop_write
 * @return      bool
*/
bool ds_usercma::m_open_axss( bool bop_write )
{
    // initialize some variables:
    void *avl_data;                         // pointer to cma content
    int  inl_len;                           // length of cma content
    bool bol_ret;                           // return value

    // open cma:
    avc_axss = adsc_wsp_helper->m_cb_open_cma( chrc_axss, inc_axss,
                                               &avl_data, &inl_len,
                                               bop_write );
    if ( avc_axss == NULL ) {
        if ( bop_write == false ) {
            return false;
        }

        // cma does not exist, create it:
        bol_ret = m_create_axss();
        if ( bol_ret == false ) {
            return false;
        }

        // try to open is again:
        avc_axss = adsc_wsp_helper->m_cb_open_cma( chrc_axss, inc_axss,
                                                   &avl_data, &inl_len,
                                                   bop_write );
        if ( avc_axss == NULL ) {
            return false;
        }
    }

    // check return data:
    if (    avl_data == NULL
         || inl_len  <  (int)sizeof(dsd_usercma_axss) ) {
        m_close_axss();
        return false;
    }

    // initialize content pointer:
    adsc_axss = (dsd_usercma_axss*)avl_data;
    return true;
} // end of ds_usercma::m_open_axss


/**
 * private function ds_usercma::m_resize_axss
 *
 * @param[in]   int inp_size
 * @return      bool
*/
bool ds_usercma::m_resize_axss( int inp_size )
{
    // initialize some variables:
    bool bol_ret;                           // return from resize
    void *avl_data;                         // pointer to cma content

    // check if cma is opened already:
    if ( avc_axss == NULL ) {
        return false;
    }

    // do the resize:
    bol_ret = adsc_wsp_helper->m_cb_resize_cma( avc_axss, &avl_data, inp_size );
    if ( bol_ret == false ) {
        return false;
    }

    // init return pointer:
    adsc_axss = (dsd_usercma_axss*)avl_data;
    return true;
} // end of ds_usercma::m_resize_axss


/**
 * private function ds_usercma::m_close_axss
 *
 * @return      bool
*/
bool ds_usercma::m_close_axss()
{
    adsc_axss = NULL;
    return adsc_wsp_helper->m_cb_close_cma( &avc_axss );
} // end of ds_usercma::m_close_axss


/*+---------------------------------------------------------------------+*/
/*| static private functions:                                           |*/
/*+---------------------------------------------------------------------+*/
/**
 * static private function ds_usercma::m_build_cs
 * this algorithm is taken from 
 * http://www.cl.cam.ac.uk/research/srg/bluebook/21/crc/node6.html#SECTION00060000000000000000
 *
 * @param[in]   const char      *achp_buf   data to build checksum from
 * @param[in]   int             inp_blen    length of data
 * @return      unsigned int                checksum
*/
unsigned int ds_usercma::m_build_cs( const char *achp_buf, int inp_blen )
{
    // initialize some variables:
    unsigned int        uin_result;
    int                 in_pos;
    int                 in_bit;
    unsigned char       rch_octet;
    unsigned char*      auch_data = (unsigned char*)achp_buf;
    
    if ( inp_blen < 4 ) {
        return 0;
    }

    uin_result  = *auch_data++ << 24;
    uin_result |= *auch_data++ << 16;
    uin_result |= *auch_data++ << 8;
    uin_result |= *auch_data++;
    uin_result  = ~ uin_result;
    inp_blen -=4;
    
    for ( in_pos = 0; in_pos < inp_blen; in_pos++ ) {
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
} // end of ds_usercma::m_build_cs

/**
 * static private function ds_usercma::m_get_name
 * create name for subcmas
 *
 * @param[in]   const char      *achp_main      main cma name
 * @param[in]   int             inp_mlen        length of main cma name
 * @param[in]   char            *achp_out       pointer to output buffer
 * @param[in]   int             inp_max_out     length of output buffer
 * @param[in]   const char*     achp_suffix     append to output (zero terminated)
 * @return      int                             written length
*/
int ds_usercma::m_get_name( const char *achp_main, int inp_mlen,
                            char *achp_out, int inp_max_out,
                            const dsd_const_string& rdsp_suffix )
{
    // initialize some variables:
	int inl_slen = rdsp_suffix.m_get_len();

    if ( inp_mlen < 1 ) {
        return 0;
    }

    if ( inp_mlen + inl_slen < inp_max_out ) {
        if ( achp_out != achp_main ) {
            memcpy ( achp_out, achp_main, inp_mlen );
        }
		memcpy( &achp_out[inp_mlen], rdsp_suffix.m_get_ptr(), inl_slen );
        return inp_mlen + inl_slen;
    }
    return 0;
} // end of ds_usercma::m_get_name


/**
 * static private function ds_usercma::m_get_word
 * get word ("/" is delimiter)
 *
 * @param[in]       const char  *achp_data      data
 * @param[in]       int         inp_dlen        length of data
 * @param[in/out]   int         *ainp_offset    offset in data
 * @param[out]      char        **aachp_word    found word
 * @param[out]      int         *ainp_wlen      length of found word
*/
bool ds_usercma::m_get_word( const char *achp_data, int inp_dlen,
                             int *ainp_offset,
                             const char **aachp_word, int *ainp_wlen )
{
    *aachp_word = (char*)&achp_data[*ainp_offset];
    *ainp_wlen  = 0;
    for ( ; *ainp_offset < inp_dlen; (*ainp_offset)++ ) {
        if ( achp_data[*ainp_offset] == '/' ) {
			 return false;
        }
        (*ainp_wlen)++;
    }
	 return true;
} // end of ds_usercma::m_get_word

bool ds_usercma::m_get_word( const dsd_const_string& rdsp_in, int *ainp_offset, dsd_const_string& rdsp_out )
{
	int inl_len;
	bool bol_ret = m_get_word(rdsp_in.m_get_ptr(), rdsp_in.m_get_len(), ainp_offset, &rdsp_out.strc_ptr, &inl_len);
	rdsp_out.inc_length = inl_len;
	return bol_ret;
} // end of ds_usercma::m_get_word


static const char chrs_cma_pwd_prefix[] = {
  'U', 'S', 'E', 'R', '-', 'P', 'W', 'D', 0
};

BOOL ds_usercma::m_read_single_signon_credentials(struct dsd_sso_info& rdsp_sso_info) {
   BOOL bol_rc;
   int iml1, iml2, iml3;
   char chrl_work1[8192];
   char chrl_work2[8192];
   char chrl_work3[8192];
   char *achl_w1, *achl_w2;
   struct dsd_sdh_ident_set_1 dsl_g_idset1;
   struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR    */
   struct dsd_hl_aux_c_cma_1 dsl_accma1;  /* command common memory area */

   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );  /* settings for given ident */
   bol_rc = this->adsc_wsp_helper->m_call_aux(
                                       DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                       &dsl_g_idset1,
                                       sizeof(struct dsd_sdh_ident_set_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_GET_IDENT_SETTINGS returned %d iec_ret_g_idset1 %d.",
                 __LINE__, bol_rc, dsl_g_idset1.iec_ret_g_idset1 );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     return TRUE;                      /* parameters have been set */
   }
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_user_group )  /* unicode string user-group */
            * sizeof(HL_WCHAR);
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_userid )  /* unicode string userid */
            * sizeof(HL_WCHAR);
   iml3 = 0;                                /* length password         */
#if 0
   if (!bop_credential_cache) {             /* SSO - single-sign-on configuration */
     goto p_cl_sta_48;                      /* end of password         */
   }
#endif
   memcpy( chrl_work1, chrs_cma_pwd_prefix, sizeof(chrs_cma_pwd_prefix) );
   iml3 = m_cpy_vx_ucs( chrl_work1 + sizeof(chrs_cma_pwd_prefix),
                        sizeof(chrl_work1) - sizeof(chrs_cma_pwd_prefix),
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
   if (iml3 < 0) {
     adsc_wsp_helper->m_logf(ied_sdh_log_error, "ds_authenticate-l%05d-W m_cpy_vx_ucs() user-group returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 = chrl_work1 + sizeof(chrs_cma_pwd_prefix) + iml3 + 1;
   iml3 = m_cpy_vx_ucs( achl_w1,
                        (chrl_work1 + sizeof(chrl_work1)) - achl_w1,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_userid );  /* unicode string userid */
   if (iml3 < 0) {
     adsc_wsp_helper->m_logf(ied_sdh_log_error, "ds_authenticate-l%05d-W m_cpy_vx_ucs() userid returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 += iml3;
   memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
   dsl_accma1.ac_cma_name = chrl_work1;     /* cma name                */
   dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
   dsl_accma1.inc_len_cma_name = achl_w1 - chrl_work1;  /* length cma name in elements */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   bol_rc = this->adsc_wsp_helper->m_call_aux(
                                       DEF_AUX_COM_CMA,  /* command common memory area */
                                       &dsl_accma1,
                                       sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   adsc_wsp_helper->m_logf(ied_sdh_log_error, "ds_authenticate-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured - not found */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   if (dsl_accma1.inc_len_cma_area == 0) {  /* length of cma area      */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = achl_w1 - (chrl_work1 + sizeof(chrs_cma_pwd_prefix));  /* length of post key string */
   dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
   dsl_asxor1.achc_post_key = chrl_work1 + sizeof(chrs_cma_pwd_prefix);  /* address of post key string */
   dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
   dsl_asxor1.achc_destination = chrl_work2;  /* address of destination */
   bol_rc = this->adsc_wsp_helper->m_call_aux(
                                          DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                          &dsl_asxor1,
                                          sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   iml3 = m_cpy_vx_vx( chrl_work3, sizeof(chrl_work3), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                       chrl_work2, dsl_accma1.inc_len_cma_area, ied_chs_utf_8 )  /* Unicode UTF-8 */
            * sizeof(HL_WCHAR);

   p_cl_sta_44:                             /* unlock CMA              */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
   bol_rc = this->adsc_wsp_helper->m_call_aux(
                                          DEF_AUX_COM_CMA,  /* command common memory area */
                                          &dsl_accma1,
                                          sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_output_area_1, "xl-webterm-rdp-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }

   p_cl_sta_48:                             /* end of password         */
//#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
#if 0
   if (ADSL_CC1->boc_so_without_domain) {   /* <sign-on-without-domain> */
     iml1 = 0;                              /* do not use domain       */
   }
#endif
//#undef ADSL_CC1
// to-do 16.04.15 KB
//   "sign-on-use-domain",
//   dsl_g_idset1.dsc_user_group - replace by local
   //struct dsd_clib1_contr_1* adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
   rdsp_sso_info.inc_rdp_cred_size = iml1 + iml2 + iml3 + sizeof(HL_WCHAR);
   bol_rc = this->adsc_wsp_helper->m_call_aux(
                                       DEF_AUX_MEMGET,
                                       &rdsp_sso_info.achc_rdp_cred,  /* RDP credentials */
                                       rdsp_sso_info.inc_rdp_cred_size );  /* length area */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   achl_w1 = (char*)rdsp_sso_info.achc_rdp_cred;   /* RDP credentials         */
   achl_w2 = achl_w1 + rdsp_sso_info.inc_rdp_cred_size;

   if (iml1 > 0) {                          /* with domain             */
	  int iml4 = m_cpy_vx_ucs( achl_w1, (achl_w2-achl_w1)/sizeof(HL_WCHAR), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
	 if (iml4 < 0) {
		 adsc_wsp_helper->m_logf(ied_sdh_log_error, "ds_authenticate-l%05d-W m_cpy_vx_ucs() returned error",
					   __LINE__ );
		 return FALSE;
     }
	 rdsp_sso_info.dsc_client_domain.iec_chs_str = ied_chs_utf_16;
	 rdsp_sso_info.dsc_client_domain.imc_len_str = iml4; /* Domain Name Length */
	 rdsp_sso_info.dsc_client_domain.ac_str = achl_w1; /* Domain Name */
	 achl_w1 += iml4 * sizeof(HL_WCHAR);
   }
   if (iml2 > 0) {                          /* with userid             */
     int iml4 = m_cpy_vx_ucs( achl_w1, (achl_w2-achl_w1)/sizeof(HL_WCHAR), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &dsl_g_idset1.dsc_userid );  /* unicode string userid */
	 if (iml4 < 0) {
		 adsc_wsp_helper->m_logf(ied_sdh_log_error, "ds_authenticate-l%05d-W m_cpy_vx_ucs() returned error",
					   __LINE__ );
		 return FALSE;
     }
	 rdsp_sso_info.dsc_client_userid.iec_chs_str = ied_chs_utf_16;
	 rdsp_sso_info.dsc_client_userid.imc_len_str = iml4; /* User Name Length */
	 rdsp_sso_info.dsc_client_userid.ac_str = achl_w1; /* User Name */
     achl_w1 += iml4 * sizeof(HL_WCHAR);
   }
   if (iml3 > 0) {                          /* with password           */
     memcpy( achl_w1, chrl_work3, iml3 );
	 rdsp_sso_info.dsc_client_password.iec_chs_str = ied_chs_utf_16;
	 rdsp_sso_info.dsc_client_password.imc_len_str = iml3 / sizeof(HL_WCHAR); /* Password Name Length */
	 rdsp_sso_info.dsc_client_password.ac_str = achl_w1; /* Password Name */
   }
#undef ADSL_CC1
   return TRUE;
} /* end m_read_single_signon_credentials()                                          */

void ds_usercma::m_clear_single_signon_credentials(struct dsd_sso_info& rdsp_sso_info) {
	memset(rdsp_sso_info.achc_rdp_cred, 0, rdsp_sso_info.inc_rdp_cred_size);
	this->adsc_wsp_helper->m_call_aux(DEF_AUX_MEMFREE, &rdsp_sso_info.achc_rdp_cred, rdsp_sso_info.inc_rdp_cred_size);
}
