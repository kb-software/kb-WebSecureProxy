#ifndef DS_PRE_CMA_H
#define DS_PRE_CMA_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_pre_cma                                                            |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   Aug 2009                                                              |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define LEN_WSP_ID         8
#define LEN_RANDOM         24
#define LEN_NOAUTH_COOKIE  LEN_WSP_ID + LEN_RANDOM

#define SM_USE_PRECMA_CACHE	1

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

/*+-------------------------------------------------------------------------+*/
/*| some definitions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class  ds_hstring;          // forward definition
class  ds_wsp_helper;       // forward definition
struct dsd_usercma_pre;     // forward definition

/*! \brief Holds information about a kickout
 *
 * @ingroup authentication
 *
 * Client IP and login time
 */
typedef struct dsd_auth_kicked_out {
    dsd_aux_query_client  ds_client;  // clients ip
    hl_time_t                tm_login;   // clients login time
} dsd_kicked_out_t;
/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Common Memory Area Class
 *
 * @ingroup authentication
 *
 * Class which stores information about a user
 */
class ds_pre_cma
{
public:
    // constructor:
    ds_pre_cma();

    // functions:
    void m_init( ds_wsp_helper* ads_wsp_helper );

    // new interface functions:
    bool m_create_cookie();
    bool m_delete_cookie();
	bool m_commit();

    // old interface functions:
    bool m_set_name( const char* ach_cookie, int in_len_cookie );
    bool m_create  ();

    // cookie function
    bool m_has_cookie_format( const char *achp_cookie, int inp_length );
    void m_get_cookie( const char** aach_cookie, int* ain_len );

    // state functions:
    void m_init_state ( int in_state );
    void m_set_state  ( int in_state );
    void m_unset_state( int in_state );
    bool m_check_state( int in_state );
    int  m_get_state  ();

    // language functions:
    int  m_get_lang();
    bool m_set_lang( int in_lang );

    // user functions:
    ds_hstring m_get_user    ();
	ds_hstring m_get_userdn  ();
    ds_hstring m_get_password();
    ds_hstring m_get_domain  ();
    bool       m_set_user( const char* ach_username, int in_len_username );
    bool       m_set_user( const char* ach_domain,   int in_len_domain,
                           const char* ach_username, int in_len_username,
                           const char* ach_password, int in_len_password, 
						   const char* ach_userdn,   int in_len_userdn);
    
    // booked page functions:
    ds_hstring m_get_bpage  ();
    bool       m_set_bpage  ( const char* ach_page, int in_len );
    bool       m_clear_bpage();

    // message functions:
    ds_hstring m_get_message  ( const char* ach_url, int in_len_url,
                                int* ain_type, int *ain_code         );
    bool       m_set_message  ( int in_msg_type,     int in_msg_code,
                                const dsd_const_string& ach_msg,
                                const dsd_const_string& ach_url );
    
    // radius state functions:
    ds_hstring m_get_radius  ();
    bool       m_set_radius  ( const char* ach_rad, int in_len );
    bool       m_clear_radius();

    // kicked out:
    bool m_save_kicked_out( dsd_kicked_out_t* ads_kicked_out );
    bool m_get_kicked_out ( dsd_kicked_out_t* ads_kicked_out );

private:
    // variables:
    ds_wsp_helper*   adsc_wsp_helper;                   // wsp helper class
		
    dsd_usercma_pre* ads_pre_cma;                       // cma content structure
#if SM_USE_PRECMA_CACHE
	int              inc_len_pre_cma;
	bool             boc_cma_changed;
#else
	dsd_hl_aux_c_cma_1 dsc_cma;                         // cma handle
#endif
	char             chr_cmaname[LEN_NOAUTH_COOKIE];    // cma name

    char*            achc_username;                     // username
    char*            achc_password;                     // password
    char*            achc_domain;                       // domain
	char*            achc_userdn;						// userdn
    char*            achc_bpage;                        // requested page
    char*            achc_msg;                          // message
    char*            achc_radius_state;                 // radius state
    
    // functions:
    bool m_create_cma_name( bool bo_force_new = false );
    bool m_create_cma     ();
    bool m_open_cma       ( bool bo_write );
    bool m_resize_cma     ( int in_size );
    bool m_close_cma      ();
    void m_setup_strings  ();

    unsigned int m_build_checksum( const char* ach_data, int in_len );
};
#endif // DS_PRE_CMA_H
