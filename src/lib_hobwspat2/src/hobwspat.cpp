/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*| ========                                                            |*/
/*|   hobwspat                                                          |*/
/*|                                                                     |*/
/*| DESCRIPTION:                                                        |*/
/*| ============                                                        |*/
/*|   this is a complete rewrite of KBs authentication library          |*/
/*|                                                                     |*/
/*| DATE:                                                               |*/
/*| =====                                                               |*/
/*|   June 2009                                                         |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs                                                    |*/
/*|   Tobias Hofmann                                                    |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define AT_STORAGE_SIZE 1*1024
/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#endif
#include <ds_wsp_helper.h>
#include <hob-libwspat.h>
#include "./hobwspat.h"
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include "./ds_wspat.h"
#include "./config/ds_at_config.h"
#include "hob-http-header-1.h"
#include <rdvpn_globals.h>
#include <ds_workstation.h>
#ifndef HOB_XSLUNIC1_H
#define HOB_XSLUNIC1_H
#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
static const char byrs_out_conn_ok_loadbalance[] = {
	(unsigned char) 0X05,
	(unsigned char) 0X84,
	(unsigned char) 0X20
};

static const char byrs_out_conn_ok[] = {
	(unsigned char) 0X05,
	(unsigned char) 0X84,
	(unsigned char) 0X80
};

#define WEBTERM_MODE "webterm_mode="
#define WEBTERM_NAME "webterm_name="
//#define WEBTERM_PROT "webterm_prot="
#define WEBTERM_SID  "webterm_sid="
#define LEN_SESSTICKET HL_RDVPN_LEN_SESSTICKET

/*+---------------------------------------------------------------------+*/
/*| structures:                                                         |*/
/*+---------------------------------------------------------------------+*/
struct dsd_webterm_info // also used in sdh_gwt_rdp header by KB!
{
	int imc_len_sid;
};

/*+---------------------------------------------------------------------+*/
/*| structures:                                                         |*/
/*+---------------------------------------------------------------------+*/
struct dsd_webterm_dod_info // also used in sdh_gwt_rdp header by KB!
{
	int             imc_len_str; // length string elements
	int             imc_port;
	BOOL            boc_with_macaddr;  /* macaddr is included */
	unsigned char   chrc_macaddr[6];
	int             imc_waitconn;
};
/* KB: target string in idna has to be in memory behind the structure! */

/*+---------------------------------------------------------------------+*/
/*| config function:                                                    |*/
/*+---------------------------------------------------------------------+*/
BOOL m_wspat3_config_in( struct dsd_hl_clib_dom_conf *adsp_conf )
{
#ifdef _DEBUG
	// check incoming parameter:
	if ( adsp_conf == NULL ) {
		printf( "HWSPATE0025E ads_conf == NULL\n" );
		return FALSE;
	}
#endif

	// initialize some variables:
	bool          bo_ret = false;                   // return value
	ds_wsp_helper dsc_wsp_helper;                   // wsp helper class
	ds_at_config  dsc_config( &dsc_wsp_helper );    // config class

	dsc_wsp_helper.m_init_conf( adsp_conf );

	//-----------------------------------------
	// print startup message:
	//-----------------------------------------
	dsc_wsp_helper.m_cb_printf_out( "HWSPATI001I %s V%s initialized",
		AT_LONGNAME, AT_VERSION );

	//-----------------------------------------
	// read and save configuration section:
	//-----------------------------------------
	bo_ret = dsc_config.m_read_config();
	if ( bo_ret == false ) {
		dsc_wsp_helper.m_cb_printf_out( "HWSPATE026E error while reading config - fallback to default" );
	}
	dsc_config.m_check_config();
	bo_ret = dsc_config.m_save_config();

	return (bo_ret == true) ? TRUE : FALSE;
} // end of m_wspat3_config_in


/*+---------------------------------------------------------------------+*/
/*| working function:                                                   |*/
/*+---------------------------------------------------------------------+*/
void m_wspat3_proc_in( struct dsd_wspat3_1 *adsp_auth )
{
	// initialize some variables:
	ds_wsp_helper     dsl_wsp_helper;
	bool              bol_clear       = false;
	ds_wspat          *adsl_wspat     = (ds_wspat*)adsp_auth->ac_ext;
	ds_hstring						dsc_response( &dsl_wsp_helper );
	struct dsd_aux_get_workarea		dsl_wa;
	BOOL							bol_ret;

	dsl_wsp_helper.m_init_auth( adsp_auth );

	/**************************************\
	| Variables for detection of websocket |
	\**************************************/

	// hofmants: Initializing stuff for KBs HTTP Parser
	struct dsd_http_header_server_1			dsl_hhs;
	struct dsd_stor_sdh_1					dsl_stor_sdh_1;
	struct dsd_call_http_header_server_1	dsl_chhs;  // call HTTP processing at server 
	// Prepare options structure
	struct dsd_proc_http_header_server_1 dsl_phhs =
	{
		(amd_store_alloc)m_aux_stor_alloc,		/* amd_store_alloc */
		(amd_store_free)m_aux_stor_free,		/* amd_store_free */
		FALSE,									/* boc_consume_input - consume input */
		TRUE,									/* boc_store_cookies - store cookies */
		FALSE									/* output fields for other side */
	};

	struct dsd_wspat3_conn			*adsl_wspat3_conn;
	// END Initializing stuff for KBs HTTP Parser

	struct dsd_webterm_dod_info*	adsl_dod_info;
	int								inl_function;
	int								inl_len_out = 1024;
	char							chrl_buffer[1024];
	struct dsd_get_servent_1		dsl_srv;           // WSP call structure
	class ds_workstation			dsl_workstation;
	bool							bol_is_websocket = false;
	ds_hstring						dsl_sessionticket( &dsl_wsp_helper );
	ds_hstring						dsl_webterm_mode( &dsl_wsp_helper );
	ds_hstring						dsl_webterm_name( &dsl_wsp_helper );
#if SM_USE_QUICK_LINK
	ds_hstring						dsl_webterm_sid( &dsl_wsp_helper );
#endif
	ds_hstring						dsl_temp( &dsl_wsp_helper );
	int								index;
	int								length;
	HL_UINT							uinc_auth = 0;
	ds_authenticate					dsl_ident( &dsl_wsp_helper );// authentication class
	dsd_auth_t						dsl_auth;                   // authentication structure
	ds_usercma						dsl_usercma;
	const char* 					achl_temp;
	void*							avl_srv_handle = NULL;
	dsl_usercma.m_init( &dsl_wsp_helper );

	switch (adsp_auth->iec_at_function) {
		/*
		normal processing:
		*/
	case ied_atf_normal:
		//---------------------------------
		// check for input data:
		//---------------------------------
		if (	( adsp_auth->adsc_gai1_in_from_client == NULL )
			||	( adsl_wspat && adsl_wspat->done )				)
		{
			adsp_auth->iec_at_return = ied_atr_input;
			return;
		}

		//---------------------------------
		// do a fast check for protocol:
		//---------------------------------
		/* WEBSOCKET HANDLING */
		if (    adsl_wspat == NULL
			&& adsp_auth->adsc_gai1_in_from_client->achc_ginp_cur  != NULL
			&& adsp_auth->adsc_gai1_in_from_client->achc_ginp_cur  < adsp_auth->adsc_gai1_in_from_client->achc_ginp_end 
			&& *adsp_auth->adsc_gai1_in_from_client->achc_ginp_cur != (char)0x05                                         ) {

				/* Get a storage container */			
				dsl_stor_sdh_1.amc_aux			= adsp_auth->amc_aux;
				dsl_stor_sdh_1.vpc_userfld		= adsp_auth->vpc_userfld;
				dsl_stor_sdh_1.imc_stor_size	= 8192;
				m_aux_stor_start( &dsl_stor_sdh_1 );

				// Prepare input structure
				memset(&dsl_chhs, 0, sizeof(dsd_call_http_header_server_1));
				memset( chrl_buffer, 0, 1024 );

				/* set the storage container */
				dsl_chhs.adsc_stor_sdh_1 = &dsl_stor_sdh_1;

				dsl_chhs.adsc_gai1_in               = adsp_auth->adsc_gai1_in_from_client;   
				dsl_chhs.achc_url_path              = chrl_buffer;
				dsl_chhs.imc_length_url_path_buffer = sizeof(chrl_buffer);

				// Now call http-parser
				bol_ret = m_proc_http_header_server( &dsl_phhs,  /* HTTP processing at server */
					&dsl_chhs,  /* call HTTP processing at server */
					&dsl_hhs);  /* HTTP processing at server */

				if( !bol_ret )
				{
					adsp_auth->iec_at_return = ied_atr_failed;
					return;
				}

				if ( dsl_hhs.imc_length_http_header == 0 )
				{
					adsp_auth->iec_at_return = ied_atr_input; /* wait for more input data */
					return;
				}

				dsd_const_string hstr_url(dsl_hhs.achc_url_path, dsl_hhs.imc_length_url_path);
				if( ( dsl_hhs.iec_hcon == ied_hcon_upgrade ) && ( dsl_hhs.iec_hupg == ied_hupg_websocket )
					&& !hstr_url.m_starts_with("/wsg/") )
				{
					bol_is_websocket = true;

#if 0
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_hhs.imc_length_url_path=%d", dsl_hhs.imc_length_url_path );
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_hhs.achc_url_path=%p", dsl_hhs.achc_url_path );
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_hhs.adsc_ht_cookie_ch=%p", dsl_hhs.adsc_ht_cookie_ch );
#endif					
#if SM_USE_QUICK_LINK
					dsd_const_string hstr_url(dsl_hhs.achc_url_path, dsl_hhs.imc_length_url_path);
					//dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM hstr_url=%.*s", hstr_url.m_get_len(), hstr_url.m_get_ptr() );
					if ( hstr_url.m_starts_with("/(HOB") ) {
						int in_pos = hstr_url.m_index_of(")");
						if( in_pos < 0 )
						{
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}
						dsd_const_string dsl_cookie = hstr_url.m_substring(5, in_pos);
						hstr_url = hstr_url.m_substring(in_pos + 1);
						if(!dsl_sessionticket.m_from_rfc3548(dsl_cookie.m_get_ptr(), dsl_cookie.m_get_len())) {
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}
					}
					else
#endif
						if(dsl_hhs.adsc_ht_cookie_ch != NULL) {
							/* TODO: make it work for browsers with cookies disabled! */

							/* Get data from cookie */
							const dsd_const_string dsl_ident_hobwsp_cookie(IDENT_HOBWSP_COOKIE);
							/* KB writes the cookie itself directly in the memory after the dsd_http_cookie struct in dsl_hhs */
							dsl_temp.m_write( (char*)((( struct dsd_http_cookie* )dsl_hhs.adsc_ht_cookie_ch ) + 1 ), dsl_hhs.adsc_ht_cookie_ch->imc_length_cookie );
							index = dsl_temp.m_search( dsl_ident_hobwsp_cookie );
							if( index == -1 )
							{
								dsl_wsp_helper.m_log( ied_sdh_log_error, "HWSPATE029E HOB cookie missing" );
								adsp_auth->iec_at_return = ied_atr_failed;
								return;
							}
							const char* achl_begin = dsl_temp.m_get_ptr();
							int inl_index_end = dsl_temp.m_find_first_of("; ", false, index + dsl_ident_hobwsp_cookie.m_get_len());
							const char* achl_end = (inl_index_end > index) ? achl_begin + inl_index_end : achl_begin + dsl_hhs.adsc_ht_cookie_ch->imc_length_cookie;
							const char* achl_ticket = dsl_temp.m_get_from( index + dsl_ident_hobwsp_cookie.m_get_len() + 1 );
							if(!dsl_sessionticket.m_from_rfc3548(achl_ticket, achl_end-achl_ticket)) {
								adsp_auth->iec_at_return = ied_atr_failed;
								return;
							}
						}
						else {
							dsl_wsp_helper.m_log( ied_sdh_log_error, "HWSPATE029E no cookie available" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}
						//dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_sessionticket=%.*s", dsl_sessionticket.m_get_len(), dsl_sessionticket.m_get_ptr() );
						/* Get configuration name from URL parameter */
						dsl_temp.m_reset();
						dsl_temp.m_write( dsl_hhs.achc_url_path, dsl_hhs.imc_length_url_path );

						/* webterm_mode */
						dsd_const_string dsl_webterm_mode_key(WEBTERM_MODE);
						index = dsl_temp.m_search( dsl_webterm_mode_key );
						if( index >= 0 )
						{
							index += dsl_webterm_mode_key.m_get_len();
							length = dsl_temp.m_search( index, "&" );
							if( length < 0 ) // in case the query is at the end of the url, then there is no "&"
							{
								length = dsl_temp.m_get_len();
							}
							dsl_webterm_mode.m_write( dsl_temp.m_substring(index, length) );
						}

						/* webterm_name */
						dsd_const_string dsl_webterm_name_key(WEBTERM_NAME);
						index = dsl_temp.m_search( dsl_webterm_name_key );
						if( index == -1 )
						{
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}
						index += dsl_webterm_name_key.m_get_len();
						length = dsl_temp.m_search( index, "&" );
						if( length < 0 ) // in case the query is at the end of the url, then there is no "&"
						{
							length = dsl_temp.m_get_len();
						}
						dsl_webterm_name.m_write( dsl_temp.m_substring(index, length) );

#if SM_USE_QUICK_LINK
						/* webterm_sid */
						dsd_const_string dsl_webterm_sid_key(WEBTERM_SID);
						index = dsl_temp.m_search( dsl_webterm_sid_key );
						if( index >= 0 ) {
							index += dsl_webterm_sid_key.m_get_len();
							length = dsl_temp.m_search( index, "&" );
							if( length < 0 ) // in case the query is at the end of the url, then there is no "&"
							{
								length = dsl_temp.m_get_len();
							}
							dsl_webterm_sid.m_write( dsl_temp.m_substring(index, length) );
							dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_webterm_sid=%.*s", dsl_webterm_sid.m_get_len(), dsl_webterm_sid.m_get_ptr() );
						}
#endif
				}

				/* release memory */
				m_aux_stor_end( &dsl_stor_sdh_1 );

				if( bol_is_websocket )
				{
					if ( adsp_auth->ac_ext == NULL )
					{
						// get memory for our working class
						// and put in ac_ext pointer -> we will get it again on every call
						adsp_auth->ac_ext = dsl_wsp_helper.m_cb_get_memory( sizeof(ds_wspat), true );
						if ( adsp_auth->ac_ext == NULL )
						{
							dsl_wsp_helper.m_log( ied_sdh_log_error, "HWSPATE029E cannot get session memory" );
							adsp_auth->iec_at_return = ied_atr_err_aux;
							return;
						}

						// setup our main working class:
						adsl_wspat = new(adsp_auth->ac_ext) ds_wspat();
						adsl_wspat->done = true;
					}

					/* Authenticate User: Prepare auth structure */
					memset( &dsl_auth, 0, sizeof(dsd_auth_t) );

					/* Parse data from sessionticket */
					// password
					dsl_auth.achc_password    = dsl_sessionticket.m_get_ptr();
					dsl_auth.inc_len_password = LEN_SESSTICKET;

					// user
					dsd_const_string dsl_user_domain = dsl_sessionticket.m_substring(LEN_SESSTICKET);
					index = dsl_user_domain.m_index_of( "/" );
					if( index == -1 )
					{
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE030E cannot get session ticket" );
						adsp_auth->iec_at_return = ied_atr_failed;
						return;
					}
					dsl_auth.achc_user = dsl_user_domain.m_get_ptr();
					dsl_auth.inc_len_user = index;

					// domain
					index++; // because of the slash
					dsd_const_string dsl_domain = dsl_user_domain.m_substring(index);
					dsl_auth.achc_domain    = dsl_domain.m_get_ptr();
					dsl_auth.inc_len_domain = dsl_domain.m_get_len();

					dsl_auth.adsc_out_usr			= &dsl_usercma;
					dsl_auth.boc_avoid_compl_check	= true;

					/* Check if the cookie is still valid */
					uinc_auth = dsl_ident.m_authenticate( &dsl_auth );
					if( ( uinc_auth & AUTH_SUCCESS ) != AUTH_SUCCESS )
					{
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE031E authentication failed" );
						adsp_auth->iec_at_return = ied_atr_failed;
						return;
					}

					/*************************************/
					/* USER is authenticated from now on */
					/*************************************/

					/* Prepare connection structure */
					if (adsp_auth->imc_len_work_area < sizeof( struct dsd_wspat3_conn )) {
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE040E Webterm WA overflow" );
						adsp_auth->iec_at_return = ied_atr_failed;
						return;
					}

					adsl_wspat3_conn = ( struct dsd_wspat3_conn* )adsp_auth->achc_work_area;
					memset( adsl_wspat3_conn, 0, sizeof( struct dsd_wspat3_conn ) );

					adsp_auth->achc_work_area		+= sizeof( struct dsd_wspat3_conn );
					adsp_auth->imc_len_work_area	-= sizeof( struct dsd_wspat3_conn );

					if( dsl_webterm_mode.m_equals( "DOD" ) )
					{					
						/* Get DOD Settings from CMA */
						dsl_workstation.m_init( &dsl_wsp_helper );
						bol_ret = dsl_auth.adsc_out_usr->m_get_workstation( dsl_webterm_name.m_get_ptr(), dsl_webterm_name.m_get_len(), &dsl_workstation );
						if( !bol_ret )
						{
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE032E Webterm DoD - cannot get workstation" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}

						/* Count number of server entries with websocket */
						memset( &dsl_srv, 0, sizeof(struct dsd_get_servent_1 ) );
						dsl_srv.vpc_usent       = dsl_auth.avc_userentry;
						dsl_srv.vpc_usgro       = dsl_auth.avc_usergroup;
						dsl_srv.ainc_no_servent = &index;

						dsl_srv.iec_scp_def = ied_scp_websocket;
						bol_ret = adsp_auth->amc_aux( adsp_auth->vpc_userfld, DEF_AUX_COUNT_SERVENT, &dsl_srv, sizeof(struct dsd_get_servent_1) );

						//inl_len_out = adsp_auth->imc_len_work_area;

						if( !bol_ret || index == 0 )
						{
							/* error */
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE033E Webterm DoD - count server entries failed" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}

						while(true)
						{
							inl_len_out = adsp_auth->imc_len_work_area;
							avl_srv_handle = dsl_wsp_helper.m_cb_get_server_entry(	dsl_auth.avc_userentry,
								dsl_auth.avc_usergroup,
								ied_scp_websocket,
								NULL,
								0,
								adsp_auth->achc_work_area, &inl_len_out,
								avl_srv_handle,
								&inl_function );

							if( avl_srv_handle == NULL )
							{
								dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE034E Webterm DoD - no server entry found" );
								adsp_auth->iec_at_return = ied_atr_failed;
								return;
							}
							if( inl_function == DEF_FUNC_PTTD ){ break; }
						}

						/* set pointers in connection structure */
						if (adsp_auth->imc_len_work_area < inl_len_out ) {
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE041E Webterm WA overflow" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}

						adsl_wspat3_conn->dsc_ucs_server_entry.ac_str		= adsp_auth->achc_work_area;
						adsl_wspat3_conn->dsc_ucs_server_entry.imc_len_str	= inl_len_out;

						adsp_auth->achc_work_area		+= inl_len_out;
						adsp_auth->imc_len_work_area	-= inl_len_out;

						/* get dod data and put it in a workarea ( data has to be contiguous )
						struct dsd_webterm_dod_info:
						- int	imc_len_str;		// length string in elements
						- int	imc_port;			// port to connect to
						- BOOL	boc_with_macaddr;
						- char	chrc_macaddr[6];	// macaddr switch on
						- int	imc_waitconn;		// wait for connect
						=> Target Address IPv4 / IPv6 / DNS name is in memory behind the structure
						*/

						/* initialize dod data area */
						if (adsp_auth->imc_len_work_area < sizeof( struct dsd_webterm_dod_info )) {
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE042E Webterm WA overflow" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}

						adsl_dod_info = (struct dsd_webterm_dod_info*)( adsp_auth->achc_work_area );
						memset( adsl_dod_info, 0, sizeof( struct dsd_webterm_dod_info ) );

						adsp_auth->achc_work_area		+= sizeof( struct dsd_webterm_dod_info );
						adsp_auth->imc_len_work_area	-= sizeof( struct dsd_webterm_dod_info );

						dsl_workstation.m_get_ineta( &achl_temp, &index );
						adsl_dod_info->imc_len_str = m_cpy_vx_vx(	adsp_auth->achc_work_area,	adsp_auth->imc_len_work_area,	ied_chs_idna_1,
							(char*)achl_temp,					index,							ied_chs_utf_8 );

						if( adsl_dod_info->imc_len_str == -1 )
						{
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE034E Webterm DoD - error converting ip address" );
							adsp_auth->iec_at_return = ied_atr_failed;
							return;
						}

						adsl_dod_info->imc_port = dsl_workstation.m_get_port();
						dsl_workstation.m_get_mac( (unsigned char*)adsl_dod_info->chrc_macaddr );
						if(	   adsl_dod_info->chrc_macaddr[0] != 204
							|| adsl_dod_info->chrc_macaddr[1] != 204
							|| adsl_dod_info->chrc_macaddr[2] != 204
							|| adsl_dod_info->chrc_macaddr[3] != 204
							|| adsl_dod_info->chrc_macaddr[4] != 204
							|| adsl_dod_info->chrc_macaddr[5] != 204 )
						{
							adsl_dod_info->boc_with_macaddr = TRUE;
						}
						adsl_dod_info->imc_waitconn = dsl_workstation.m_get_wait();

						/* give it to KB */
						bol_ret = adsp_auth->amc_aux(	adsp_auth->vpc_userfld,
							DEF_AUX_PUT_SESS_STOR,
							(void*)adsl_dod_info,
							sizeof( struct dsd_webterm_dod_info ) + adsl_dod_info->imc_len_str );
						if( !bol_ret )
						{
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE035E Webterm DoD - error storing DoD information" );
							adsp_auth->iec_at_return = ied_atr_err_aux;
							return;
						}

					}
					else /* if( dsl_webterm_mode.m_equals( "DIRECT" ) )*/
					{
						/* In case of DIRECT, the webterm_name contains the base64 encoded server entry name */
						dsl_temp.m_reset();
						if(!dsl_temp.m_from_b64( dsl_webterm_name.m_get_ptr(), dsl_webterm_name.m_get_len() )) {
							dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE038E Webterm Direct - could not decode server entry" );
							adsp_auth->iec_at_return = ied_atr_err_aux;
							return;
						}

						/* Copy name of SDH in workarea, otherwise its lost */
						memcpy( adsp_auth->achc_work_area, dsl_temp.m_get_ptr(), dsl_temp.m_get_len() );

						/* set pointers */
						adsl_wspat3_conn->dsc_ucs_server_entry.ac_str		= adsp_auth->achc_work_area;
						adsl_wspat3_conn->dsc_ucs_server_entry.imc_len_str	= dsl_temp.m_get_len();
					}
					/*else
					{
					// unknown mode! 
					dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE036E Webterm unknown mode" );
					adsp_auth->iec_at_return = ied_atr_failed;
					return;
					} */

					adsl_wspat3_conn->iec_hconn							= ied_hconn_sel_servent;
					adsl_wspat3_conn->iec_scp_def						= ied_scp_websocket;
					adsl_wspat3_conn->dsc_ucs_server_entry.iec_chs_str	= ied_chs_utf_8;

					bol_ret = adsp_auth->amc_aux(	adsp_auth->vpc_userfld,
						DEF_AUX_CONN_PREPARE,
						adsl_wspat3_conn,
						sizeof(struct dsd_wspat3_conn) );

					if( bol_ret == FALSE )
					{
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE037E webterm: error while preparing connection" );
						adsp_auth->iec_at_return = ied_atr_err_aux;  /* error in aux subroutine */
						return;
					}

					adsp_auth->ac_exc_aux = (void*) adsl_wspat3_conn;
					adsp_auth->imc_exc_aux = sizeof( struct dsd_wspat3_conn );

					adsp_auth->iec_at_return = ied_atr_connect;

#if SM_USE_QUICK_LINK && 0
					// Not used anymore - code is handled by SDH itself
					if(dsl_webterm_sid.m_get_len() <= 0)
						return;

					dsd_const_string dsl_sid("SID");
					// Prefix
					char chrl_pwcma_name[128];
					memcpy( chrl_pwcma_name, dsl_sid.m_get_ptr(), dsl_sid.m_get_len()+1 );
					int inl_pwcma_namelen = dsl_sid.m_get_len()+1;
					// SID
					int inl_ret = m_cpy_vx_vx( chrl_pwcma_name + inl_pwcma_namelen,
						sizeof(chrl_pwcma_name) - inl_pwcma_namelen, ied_chs_utf_8,
						(void*)dsl_webterm_sid.m_get_ptr(), dsl_webterm_sid.m_get_len(), ied_chs_utf_8 );
					if( inl_ret < 0 ){ 
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE037E webterm: unknown SID" );
						adsp_auth->iec_at_return = ied_atr_err_aux;  /* error in aux subroutine */
						return;
					}
					inl_pwcma_namelen += inl_ret;
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM CMA-name=%.*s", inl_pwcma_namelen, chrl_pwcma_name );

					char chrl_data_copy[1024];
					char* achl_cma_data;
					int inl_cma_len;
					void* avol_cma_handle = dsl_wsp_helper.m_cb_open_cma(chrl_pwcma_name, inl_pwcma_namelen, 
						(void**)&achl_cma_data, &inl_cma_len, false);
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM avol_cma_handle=%p", avol_cma_handle );
					if(avol_cma_handle == NULL)
					{
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE037E webterm: unknown SID" );
						adsp_auth->iec_at_return = ied_atr_err_aux;  /* error in aux subroutine */
						return;
					}
					memcpy(chrl_data_copy, achl_cma_data, inl_cma_len);
					dsl_wsp_helper.m_cb_close_cma(&avol_cma_handle);

					dsd_const_string dsl_cma_data(chrl_data_copy, inl_cma_len);
					dsl_wsp_helper.m_logf( ied_sdh_log_error, "#WEBTERM dsl_cma_data=%.*s", dsl_cma_data.m_get_len(), dsl_cma_data.m_get_ptr() );
					int inl_user_end = dsl_cma_data.m_index_of("\0");
					if(inl_cma_len > sizeof(chrl_data_copy)) {
						dsl_wsp_helper.m_cb_close_cma(&avol_cma_handle);
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE037E webterm: unknown SID" );
						adsp_auth->iec_at_return = ied_atr_err_aux;  /* error in aux subroutine */
						return;
					}
					dsd_const_string dsl_rdp_user(dsl_cma_data.m_substring(0, inl_user_end));
					dsd_const_string dsl_rdp_domain(dsl_cma_data.m_substring(inl_user_end+1));
#if 0
					//dsd_const_string dsl_rdp_user("test");
					//dsd_const_string dsl_rdp_domain("HOB01");
					if(!dsl_wsp_helper.m_cb_set_ident(
						dsl_rdp_user.m_get_ptr(), dsl_rdp_user.m_get_len(),
						dsl_rdp_domain.m_get_ptr(), dsl_rdp_domain.m_get_len(),
						NULL, 0))
					{
						dsl_wsp_helper.m_log( ied_sdh_log_error,"HWSPATE037E webterm: set ident failed" );
						adsp_auth->iec_at_return = ied_atr_err_aux;  /* error in aux subroutine */
						return;
					}
#endif
#endif
					return;
				}

				dsl_wsp_helper.m_log( ied_sdh_log_warning,"HWSPATE038W webterm: other protocol" );
				adsp_auth->iec_at_return = ied_atr_other_prot; // is this correct?
				return;
		}
		/* END WEBSOCKET HANDLING */


		//---------------------------------
		// create our working class:
		//---------------------------------
		if ( adsp_auth->ac_ext == NULL ) {
			// get memory for our working class
			// and put in ac_ext pointer -> we will get it again on every call
			adsp_auth->ac_ext = dsl_wsp_helper.m_cb_get_memory( sizeof(ds_wspat), true );
			if ( adsp_auth->ac_ext == NULL ) {
				dsl_wsp_helper.m_log( ied_sdh_log_error,
					"HWSPATE029E cannot get session memory" );
				adsp_auth->iec_at_return = ied_atr_err_aux;
				return;
			}

			// setup our main working class:
			adsl_wspat = new(adsp_auth->ac_ext) ds_wspat();
		}

		//---------------------------------
		// setup storage container:
		//---------------------------------
		dsl_wsp_helper.m_use_storage( &(adsl_wspat->av_storage), AT_STORAGE_SIZE );

		//---------------------------------
		// init working class:
		//---------------------------------
		adsl_wspat->m_init( &dsl_wsp_helper );

		//---------------------------------
		// process data:
		//---------------------------------
		adsl_wspat->m_run();
		break;

		/*
		connection established:
		*/
	case ied_atf_connect_ok:
		// check our class pointer
		if ( adsl_wspat == NULL ) {
			dsl_wsp_helper.m_log( ied_sdh_log_warning,
				"HWSPATW010W session pointer is null" );
			return;
		}

		if( adsl_wspat->done )
		{
			adsp_auth->iec_at_return = ied_atr_end;
			break;
		}

		dsl_wsp_helper.m_send_data( byrs_out_conn_ok,
			sizeof(byrs_out_conn_ok) );

		adsp_auth->iec_at_return = ied_atr_end;
		dsl_wsp_helper.m_log_output();
		break;

	case ied_atf_do_lbal:
		// check our class pointer
		if ( adsl_wspat == NULL ) {
			dsl_wsp_helper.m_log( ied_sdh_log_warning,
				"HWSPATW010W session pointer is null" );
			return;
		}
		dsl_wsp_helper.m_send_data( byrs_out_conn_ok_loadbalance,
			sizeof(byrs_out_conn_ok_loadbalance) );
		adsp_auth->iec_at_return = ied_atr_end;
		dsl_wsp_helper.m_log_output();
		break;

		/*
		connection failed:
		abnormal end;
		Return error message
		*/
	case ied_atf_connect_failed:
		if ( adsl_wspat != NULL ){ bol_clear = true; }

		/* get a workarea because we dont get one from KB */
		bol_ret = adsp_auth->amc_aux( adsp_auth->vpc_userfld, DEF_AUX_GET_WORKAREA, (void*)&dsl_wa, sizeof( dsd_aux_get_workarea ) );
		if( bol_ret )
		{
			/* Protocol stuff */
			dsc_response.m_writef( "%c", (char)0x05 );
			dsc_response.m_writef( "%c", (char)0x84 );
			if( adsp_auth->iec_at_function == ied_atf_connect_failed )
			{
				dsc_response.m_writef( "%c", (unsigned char) ( 0X40 | 0X08 | 0X02 ) ); /* connect failed, error message, input server entry */
			}
			else
			{
				dsc_response.m_writef( "%c", (unsigned char) ( 0X40 | 0X08 | 0X01 ) ); /* connect failed, error message, abend */
			}

			/*	should be taken from resources file in the correct language, but its ok for now.
			maybe it has to be done in multiple languages in future */
			dsc_response.m_write_nhasn( strlen( "Could not connect to the server!" ) );
			dsc_response.m_write( "Could not connect to the server!" );

			/* init the structure to give data to client */
			adsp_auth->adsc_gai1_out_to_client	= ( struct dsd_gather_i_1* )dsl_wa.achc_work_area;
			dsl_wa.achc_work_area				+= sizeof( struct dsd_gather_i_1 );
			dsl_wa.imc_len_work_area			-= sizeof( struct dsd_gather_i_1 );

			/* get actual data in the workarea */
			adsp_auth->adsc_gai1_out_to_client->achc_ginp_cur = dsl_wa.achc_work_area;
			memcpy( dsl_wa.achc_work_area, dsc_response.m_get_ptr(), dsc_response.m_get_len() );

			/* set the end pointers */
			dsl_wa.achc_work_area								+= dsc_response.m_get_len();
			dsl_wa.imc_len_work_area							-= dsc_response.m_get_len();
			adsp_auth->adsc_gai1_out_to_client->achc_ginp_end	= dsl_wa.achc_work_area;

			adsp_auth->adsc_gai1_out_to_client->adsc_next = NULL;
		}

		adsp_auth->iec_at_return = ied_atr_failed;
		break;

		/*
		(abnormal) end:
		*/
	case ied_atf_abend:
		if ( adsl_wspat != NULL ){ bol_clear = true; }
		adsp_auth->iec_at_return = ied_atr_end;
		break;

	default:
		bol_clear = true;
		adsp_auth->iec_at_return = ied_atr_failed;
		dsl_wsp_helper.m_log( ied_sdh_log_warning,
			"HWSPATW011W unknown at function" );
		break;
	} // end of switch

	//-----------------------------------------
	// clear session class if selected:
	//-----------------------------------------
	if ( bol_clear == true ) {
		// check our class pointer
		if ( adsl_wspat == NULL ) {
			dsl_wsp_helper.m_log( ied_sdh_log_warning,
				"HWSPATW012W session pointer is null" );
			return;
		}
		void *avl_storage = adsl_wspat->av_storage;
		// init storage container:
		dsl_wsp_helper.m_use_storage( &(avl_storage), AT_STORAGE_SIZE );

		// call destructor for our working class (must be inited!):
		adsl_wspat->m_init( &dsl_wsp_helper );
		adsl_wspat->ds_wspat::~ds_wspat();

		// clear storage container:
		dsl_wsp_helper.m_no_storage( &(avl_storage) );

		// free working class memory:
		dsl_wsp_helper.m_cb_free_memory( adsp_auth->ac_ext, sizeof(ds_wspat) );
		adsp_auth->ac_ext = NULL;
	}

	return;
} // end of m_wspat3_proc_in
