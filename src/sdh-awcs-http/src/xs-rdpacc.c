/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-rdpacc                                                         |*/
/*|   RDP Accelerator Handling and Parsing                              |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Tobias Hofmann, January 2012                                      |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| global includes:                                                    |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #include <windows.h>
#endif //HL_UNIX
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#include <hob-xsclib01.h>
#include <hob-xslunic1.h>

// RDP Client Header Files
#include "hob-encry-1.h"
#define HCOMPR2 // stupid stuff for hob-rdpclient1.h
#include "hob-cd-record-1.h"
#include "hob-rdpclient1.h"

#include <hob-xs-rdpacc.h>

/*+---------------------------------------------------------------------+*/
/*| local structs:                                                      |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_client_order {
	struct dsd_cc_co1				dsl_cc_co1;
	union
	{
		struct dsd_cc_start_rdp_client	dsc_start_client;
		struct dsd_cc_pass_license      dsc_pass_license;
		struct dsd_cc_events_mouse_keyb ds_input_event;
	};
} dsd_client_order;


/*+---------------------------------------------------------------------+*/
/*| local function prototypes:                                          |*/
/*+---------------------------------------------------------------------+*/
static BOOL m_init_rdpacc( struct dsd_call_rdpacc *, struct dsd_rdp_user_event * );
static BOOL m_set_connection_details( struct dsd_rdpacc_settings* );
static unsigned short hl_wchar_len( HL_WCHAR* );
static BOOL m_command_from_server( struct dsd_rdpacc_settings*, struct dsd_se_co1* );
static BOOL m_handle_license( struct dsd_rdpacc_settings* );
static HANDLE m_create_file( int, HL_WCHAR*, HL_WCHAR*, char*, BOOL );
static BOOL m_confirm_active_pdu( struct dsd_rdpacc_settings* );


/********************************************************************************/
/*   Alles neu macht der Mai! Start implementing new RDPACC Client interface	*/
/********************************************************************************/
extern BOOL m_rdpacc_start( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_user_event *adsp_user_event )
{
	dsd_rdpacc_settings		*adsl_rdpacc_settings;

	/* init and connect! */
	m_init_rdpacc( adsp_call_rdpacc, adsp_user_event );
	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;

	adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_gather_i_1_in = adsp_call_rdpacc->adsc_gather_i_1_in;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.achc_work_area = adsp_call_rdpacc->achc_work_area;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_len_work_area = adsp_call_rdpacc->inc_len_work_area;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.amc_aux = adsp_call_rdpacc->amc_aux;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.vpc_userfld = adsp_call_rdpacc->avc_userfield;
	
	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_func = DEF_IFUNC_START;
	m_rdpclient_1( &(adsl_rdpacc_settings->dsc_call_rdpclient_1) );

	m_set_connection_details( adsl_rdpacc_settings );
	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_func = DEF_IFUNC_REFLECT;
	m_rdpclient_1( &(adsl_rdpacc_settings->dsc_call_rdpclient_1) );
	adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_gai1_out_to_server;

	// release memory because i allocated it in m_set_connection_details, remove it when storage container works
	adsp_call_rdpacc->amc_aux( adsp_call_rdpacc->avc_userfield, DEF_AUX_MEMFREE, adsl_rdpacc_settings->adsc_client_order, 0 );

	return TRUE;
}


extern BOOL m_rdpacc_end( struct dsd_call_rdpacc *adsp_call_rdpacc )
{
	/* todo: end it! */
	return TRUE;
}

extern BOOL m_rdpacc_get_event( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_draw_command **adsp_command_out )
{
	BOOL					bol_ret;
	struct dsd_se_co1		*adsl_servercommand;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;

	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;
	adsl_rdpacc_settings->adsc_call_rdpacc = adsp_call_rdpacc;

	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_func				= DEF_IFUNC_REFLECT;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_gather_i_1_in	= adsp_call_rdpacc->adsc_gather_i_1_in;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.achc_work_area		= adsp_call_rdpacc->achc_work_area;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_len_work_area	= adsp_call_rdpacc->inc_len_work_area;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.amc_aux				= adsp_call_rdpacc->amc_aux;
	adsl_rdpacc_settings->dsc_call_rdpclient_1.vpc_userfld			= adsp_call_rdpacc->avc_userfield;	
	m_rdpclient_1( &(adsl_rdpacc_settings->dsc_call_rdpclient_1) );

	while( adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_se_co1_ch != NULL )
	{
		adsl_servercommand = adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_se_co1_ch;
		adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_se_co1_ch = adsl_servercommand->adsc_next;
		
		// m_command_from_server really needed ???
		bol_ret = m_command_from_server( adsl_rdpacc_settings, adsl_servercommand );

		if( adsl_rdpacc_settings->dsc_call_rdpclient_1.boc_callrevdir == TRUE )
		{
			adsl_rdpacc_settings->dsc_call_rdpclient_1.boc_callrevdir = FALSE;
			adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_func	   = DEF_IFUNC_TOSERVER;
			
			// create informations for the answer back to the server
			if( adsl_rdpacc_settings->boc_request_license == TRUE )
			{
				m_handle_license( adsl_rdpacc_settings );
			}
			else if( adsl_rdpacc_settings->boc_send_confirm_active_pdu == TRUE )
			{
				m_confirm_active_pdu( adsl_rdpacc_settings );
			}

			// todo!
			m_rdpclient_1( &adsl_rdpacc_settings->dsc_call_rdpclient_1 );
			adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_gai1_out_to_server;
			adsp_call_rdpacc->boc_data_to_server = TRUE;
		}

		if( bol_ret == TRUE ){ m_aux_stor_free( adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, adsl_servercommand ); }
	}

	*adsp_command_out = adsl_rdpacc_settings->dsc_command_out;
}


extern BOOL m_rdpacc_send_event( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_user_event *adsp_user_event )
{
	BOOL					bol_ret;
	dsd_client_order		*ads_order;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;

	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;
	adsl_rdpacc_settings->adsc_call_rdpacc = adsp_call_rdpacc;

	/* browser events */
	switch( adsp_user_event->iec_event_type )
	{
		case ied_mouse:
			// storage container is not available right now!
			// ads_order = (dsd_client_order*) m_aux_stor_alloc( adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, sizeof(dsd_client_order));
			
			// order memory manually, because storage container is not initialised
			bol_ret = adsp_call_rdpacc->amc_aux(	adsp_call_rdpacc->avc_userfield,
													DEF_AUX_MEMGET,
													(void*)&ads_order,
													sizeof( dsd_client_order ) );
			
			memset(ads_order, 0, sizeof(dsd_client_order));
			ads_order->dsl_cc_co1.iec_cc_command		= ied_ccc_events_mouse_keyb;
			ads_order->ds_input_event.achc_event_buf	= adsp_user_event->dsc_user_mouse.chrc_order;
			ads_order->ds_input_event.imc_no_order		= 1;
			ads_order->ds_input_event.imc_events_len	= adsp_user_event->dsc_user_mouse.ic_len;
			break;
		case ied_keyboard:
			// storage container is not available right now!
			// ads_order = (dsd_client_order*) m_aux_stor_alloc( adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, sizeof(dsd_client_order));
			
			// order memory manually, because storage container is not initialised
			bol_ret = adsp_call_rdpacc->amc_aux(	adsp_call_rdpacc->avc_userfield,
													DEF_AUX_MEMGET,
													(void*)&ads_order,
													sizeof( dsd_client_order ) );

			memset(ads_order, 0, sizeof(dsd_client_order));
			ads_order->dsl_cc_co1.iec_cc_command		= ied_ccc_events_mouse_keyb;
			ads_order->ds_input_event.achc_event_buf	= adsp_user_event->dsc_user_keyboard.chrc_order;
			ads_order->ds_input_event.imc_no_order		= 1;
			ads_order->ds_input_event.imc_events_len	= adsp_user_event->dsc_user_keyboard.ic_len;
			break;
		default:
			return FALSE;
	}

	// call RDP-Accelerator and send orders
	adsl_rdpacc_settings->adsc_events_to_server = &(ads_order->dsl_cc_co1);
	adsl_rdpacc_settings->dsc_call_rdpclient_1.inc_func = DEF_IFUNC_REFLECT;

	m_rdpclient_1( &adsl_rdpacc_settings->dsc_call_rdpclient_1 );
	adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_call_rdpclient_1.adsc_gai1_out_to_server;

	return TRUE;
}





/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/

/**
 * private function m_init_rdpacc
 *  save settings struct and connect to windows terminal server
 *
 * @return      nothing
*/
static BOOL m_init_rdpacc( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_user_event *adsp_user_event )
{
	dsd_rdpacc_settings		*adsl_rdpacc_settings;
	BOOL					bol_ret;

	bol_ret = adsp_call_rdpacc->amc_aux(	adsp_call_rdpacc->avc_userfield,
											DEF_AUX_MEMGET,
											&adsp_call_rdpacc->avc_ext,
											sizeof(dsd_rdpacc_settings) );

	if (    bol_ret                   == FALSE
         || adsp_call_rdpacc->avc_ext == NULL  ) {
        return FALSE;
    }

	adsl_rdpacc_settings = (dsd_rdpacc_settings*) adsp_call_rdpacc->avc_ext;
	memset(adsl_rdpacc_settings, 0, sizeof(dsd_rdpacc_settings) );
	adsl_rdpacc_settings->adsc_call_rdpacc = adsp_call_rdpacc;
	memcpy( &adsl_rdpacc_settings->dsc_connection_info, &adsp_user_event->dsc_user_connect, sizeof( struct dsd_rdp_user_connect ) );

	bol_ret = adsl_rdpacc_settings->adsc_call_rdpacc->amc_aux(	adsl_rdpacc_settings->adsc_call_rdpacc->avc_userfield,
																DEF_AUX_TCP_CONN,
																(void*) &( adsl_rdpacc_settings->dsc_connection_info.dsc_connection ),
																sizeof(struct dsd_aux_tcp_conn_1) );

	return bol_ret;
}



/**
 * private function m_set_connection_details
 *  start rdpacc with special settings
 *
 * @return      nothing
*/
static BOOL m_set_connection_details( struct dsd_rdpacc_settings* adsp_rdpacc_settings )
{
	HL_WCHAR*			awcs_domain	= (HL_WCHAR*) L"";
	BOOL				bol_ret;
	dsd_client_order	*adsl_client_order = NULL;

	//const wchar_t wst_computer_name[]	= L"Hallo Harald"; /* yep, dont ask */
	char chr_hardware_information[16];
	memcpy( chr_hardware_information, "comp_01", 7 );

	/* no storage container initialized!
	adsp_rdpacc_settings->adsc_client_order	= (dsd_client_order*) m_aux_stor_alloc( adsp_call_rdpclient_1->adsc_stor_sdh_1, sizeof(dsd_client_order) );
	*/

	// try to do it that way, because storage container is not available at this stage
	// attention: memory is released in calling function! if u remove this func again, u have to take care of that, too
	bol_ret = adsp_rdpacc_settings->adsc_call_rdpacc->amc_aux(	adsp_rdpacc_settings->adsc_call_rdpacc->avc_userfield,
																DEF_AUX_MEMGET,
																(void*)&adsl_client_order,
																sizeof( dsd_client_order ) );
	
	memset( (void*)adsl_client_order, 0, sizeof(dsd_client_order) );
	
	adsp_rdpacc_settings->adsc_client_order = adsl_client_order;
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.adsc_next = NULL;
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.iec_cc_command = ied_ccc_start_rdp_client;
	adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_cc_co1_ch = &(adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1);

	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.boc_compression		= FALSE;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.imc_dim_x				= 1024;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.imc_dim_y				= 768;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.imc_coldep			= 16;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_ineta_a	= (HL_WCHAR *) ucrs_loinf_ineta;   // INETA
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_ineta_len	= sizeof(ucrs_loinf_ineta);       // INETA Length 
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_path_a		= (HL_WCHAR *) ucrs_loinf_path;     // Client Path 
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_path_len	= sizeof(ucrs_loinf_path);         // Client Path Length 
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_extra_a	= (void *) ucrs_loinf_extra;       // Extra Parameters 
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_extra_len	= sizeof(ucrs_loinf_extra);       // Extra Parameters Length 
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_domna_a	= awcs_domain;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_domna_len	= hl_wchar_len(awcs_domain) * sizeof(HL_WCHAR);
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_userna_a	= adsp_rdpacc_settings->dsc_connection_info.chrc_user;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_userna_len	= adsp_rdpacc_settings->dsc_connection_info.inc_user_len * sizeof(HL_WCHAR);
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.awcc_loinf_pwd_a		= adsp_rdpacc_settings->dsc_connection_info.chrc_password;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.usc_loinf_pwd_len		= adsp_rdpacc_settings->dsc_connection_info.inc_password_len * sizeof(HL_WCHAR);
	//adsp_rdpacc_settings->adsc_client_order->dsc_start_client.umc_loinf_options	= 0x30733; // no auto-logon
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.umc_loinf_options		= 0x3073B; // auto-logon
	//memset(adsp_rdpacc_settings->adsc_client_order->dsc_start_client.wcrc_computer_name, 0, sizeof(adsp_rdpacc_settings->adsc_client_order->dsc_start_client.wcrc_computer_name));
	//memcpy(adsp_rdpacc_settings->adsc_client_order->dsc_start_client.wcrc_computer_name, wst_computer_name, sizeof(wst_computer_name));
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.imc_platform_id		= 0x04010000;
	adsp_rdpacc_settings->adsc_client_order->dsc_start_client.achc_machine_name		= chr_hardware_information;
	memcpy(adsp_rdpacc_settings->adsc_client_order->dsc_start_client.chrc_client_hardware_data, chr_hardware_information, sizeof( chr_hardware_information ));
	
	adsp_rdpacc_settings->boc_started = TRUE;
	return TRUE;
}

static unsigned short hl_wchar_len(HL_WCHAR* us_wchar)
{
	unsigned short us_ret = 0;
	while(TRUE)
	{
		if(us_wchar[us_ret] == 0){ return us_ret; }
		us_ret++;
	}
}

static BOOL m_command_from_server( dsd_rdpacc_settings *adsp_rdpacc_settings, struct dsd_se_co1 *adsp_servercommand )
{
	BOOL					bol_ret;
	struct dsd_sc_draw_sc	*adsl_draw;
	dsd_rdp_draw_command	*adsl_command_out;
	dsd_rdp_draw_command	*adsl_tmp = NULL;

	switch( adsp_servercommand->iec_se_command )
	{
		case ied_sec_request_license:
			adsp_rdpacc_settings->boc_request_license = TRUE;
			adsp_rdpacc_settings->adsc_license_order = adsp_servercommand; // store it to release memory later. why? rdpacc design...
			adsp_rdpacc_settings->dsc_call_rdpclient_1.boc_callrevdir = TRUE;
			return FALSE;
		case ied_sec_recv_demand_active_pdu:
			adsp_rdpacc_settings->boc_send_confirm_active_pdu = TRUE;
			adsp_rdpacc_settings->dsc_call_rdpclient_1.boc_callrevdir = TRUE;
			break;
		case ied_sec_update_screen:
			adsl_draw = ( struct dsd_sc_draw_sc* ) (adsp_servercommand + 1);
			adsl_command_out = adsp_rdpacc_settings->dsc_command_out; // get pointer to first element in command chain
			while( adsl_command_out != NULL )
			{
				adsl_tmp = adsl_command_out;
				adsl_command_out = adsl_command_out->adsc_next;
			}

			bol_ret = adsp_rdpacc_settings->adsc_call_rdpacc->amc_aux(	adsp_rdpacc_settings->dsc_call_rdpclient_1.vpc_userfld,
																		DEF_AUX_MEMGET,
																		&(adsl_command_out),
																		sizeof(dsd_rdp_draw_command) );

			memset( (void*)adsl_command_out, 0, sizeof(dsd_rdp_draw_command) );

			if( adsl_tmp == NULL ){ adsp_rdpacc_settings->dsc_command_out = adsl_command_out; } // first call, create 1st element of chain
			else{ adsl_tmp->adsc_next = adsl_command_out; } // chain
			
			adsl_command_out->ied_command_type						= ied_rectangle;
			adsl_command_out->dsc_rectangle_data.imc_left_x			= adsl_draw->imc_left;
			adsl_command_out->dsc_rectangle_data.imc_top_y			= adsl_draw->imc_top;
			adsl_command_out->dsc_rectangle_data.imc_bottom_y		= adsl_draw->imc_bottom;
			adsl_command_out->dsc_rectangle_data.imc_width			= adsl_draw->imc_right - adsl_draw->imc_left;
			adsl_command_out->dsc_rectangle_data.imc_height			= adsl_draw->imc_bottom - adsl_draw->imc_top;
			adsl_command_out->dsc_rectangle_data.avc_screenbuffer	= adsp_rdpacc_settings->dsc_call_rdpclient_1.ac_screen_buffer;
			adsl_command_out->dsc_rectangle_data.imc_resolution_x	= adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_rdp_co->imc_dim_x;
			
			break;
		default:
			return FALSE;
	}
	return TRUE;
}


static BOOL m_handle_license( struct dsd_rdpacc_settings *adsp_rdpacc_settings )
{
	struct dsd_sc_request_license*	adsl_request_license;	
	int								im_size_license;
	int								i;
	HANDLE							dsl_hfi;
	DWORD							im_read = 0;

	adsp_rdpacc_settings->boc_request_license = FALSE;

	// the license request is stored directly in the memory behind the server command!
	// Nothing points at it, you have to know it by heart :-/
	adsl_request_license = (struct dsd_sc_request_license*)(adsp_rdpacc_settings->adsc_license_order + 1);
	
	/*
	printf("\nRequest license\n");
    printf("---------------\n");
    wprintf(L"Version:      0X%x\n", adsl_request_license->imc_version);
    wprintf(L"Company name: %s\n", adsl_request_license->awsc_companyname);
    wprintf(L"Product ID:   %s\n", adsl_request_license->awsc_productid);
	*/

	for( i = 0; i < adsl_request_license->im_num_scopes; i++ )
	{
		printf("Scope[%i]: %s\n", i, adsl_request_license->ach_scope[i]);
		dsl_hfi = m_create_file( adsl_request_license->imc_version,
								 adsl_request_license->awsc_companyname,
								 adsl_request_license->awsc_productid,
								 adsl_request_license->ach_scope[0], // hofmants: scope[0] just used from testprog, not sure if this is ok
								 FALSE );
		if(dsl_hfi == INVALID_HANDLE_VALUE)
		{
			//printf( "Data Read Error reading license-file: %d\n", GetLastError());
			continue;
		}

		if(    (ReadFile(dsl_hfi, &im_size_license, sizeof(int), &im_read, 0) == FALSE)
			|| (im_read != sizeof(int) ) )
		{
			CloseHandle(dsl_hfi);
            continue;
		}

		adsp_rdpacc_settings->adsc_client_order	= (dsd_client_order*) m_aux_stor_alloc( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, sizeof(dsd_client_order) + im_size_license );
		memset( (void*)adsp_rdpacc_settings->adsc_client_order, 0, sizeof(dsd_client_order) + im_size_license );
		adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.iec_cc_command = ied_ccc_pass_license;
		// put the content behind the structure...
		adsp_rdpacc_settings->adsc_client_order->dsc_pass_license.achc_content = (char*)(adsp_rdpacc_settings->adsc_client_order + 1);
		adsp_rdpacc_settings->adsc_client_order->dsc_pass_license.imc_len_content = im_size_license;

		// Read License
		if(	   (ReadFile(dsl_hfi, adsp_rdpacc_settings->adsc_client_order->dsc_pass_license.achc_content, im_size_license, &im_read, 0) == FALSE) 
            || (im_read != im_size_license))
		{
			// printf( "Data Read Error reading license-file: %d\n", GetLastError());
			m_aux_stor_free( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, adsp_rdpacc_settings->adsc_client_order );
			CloseHandle(dsl_hfi);
			continue;
		}

		CloseHandle(dsl_hfi);
        // printf("License found!\n");
		m_aux_stor_free( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, adsp_rdpacc_settings->adsc_client_order );
		adsp_rdpacc_settings->adsc_license_order = NULL;
		adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_cc_co1_ch  = &(adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1);
        return TRUE;
	}
	
	adsp_rdpacc_settings->adsc_client_order	= (dsd_client_order*) m_aux_stor_alloc( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, sizeof(dsd_client_order) );
	memset( (void*)adsp_rdpacc_settings->adsc_client_order, 0, sizeof(dsd_client_order) );
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.adsc_next = NULL;
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.iec_cc_command = ied_ccc_pass_license;
	adsp_rdpacc_settings->adsc_client_order->dsc_pass_license.achc_content = NULL;
	adsp_rdpacc_settings->adsc_client_order->dsc_pass_license.imc_len_content = 0;

	adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_cc_co1_ch = &(adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1);
	m_aux_stor_free( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, adsp_rdpacc_settings->adsc_client_order );
	return TRUE;
}


static HANDLE m_create_file( int imp_version, HL_WCHAR* achp_companyname, HL_WCHAR* achp_productid, char* achp_scope, BOOL bop_write)
{
	static const int	ims_maxsize = 0x1000;
    char				chr_filename[0x1000];
    int					iml_pos = 0;

    iml_pos += sprintf_s(chr_filename, ims_maxsize, "%04X_", imp_version);
    iml_pos += m_sbc_from_u16z(chr_filename + iml_pos, ims_maxsize - iml_pos, achp_companyname, ied_chs_ascii_850);
    iml_pos += sprintf_s(chr_filename + iml_pos, ims_maxsize - iml_pos, "_");
    iml_pos += m_sbc_from_u16z(chr_filename + iml_pos, ims_maxsize - iml_pos, achp_productid, ied_chs_ascii_850);
    iml_pos += sprintf_s(chr_filename + iml_pos, ims_maxsize - iml_pos, "_%s.dat", achp_scope);
   
    iml_pos -= 5;
    while(iml_pos >= 0)
	{
		if( (chr_filename[iml_pos] == ' ') || (chr_filename[iml_pos] == '.') )
		{
			chr_filename[iml_pos] = '_';
		}
		iml_pos--;
	}

	if(bop_write)
	{
		return CreateFileA(chr_filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
	}
	
	return CreateFileA(chr_filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
}


static BOOL m_confirm_active_pdu( struct dsd_rdpacc_settings *adsp_rdpacc_settings )
{
	adsp_rdpacc_settings->boc_send_confirm_active_pdu = FALSE;
	adsp_rdpacc_settings->adsc_client_order	= (dsd_client_order*) m_aux_stor_alloc( adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_stor_sdh_1, sizeof(dsd_client_order) );
	memset( (void*)adsp_rdpacc_settings->adsc_client_order, 0, sizeof(dsd_client_order) );
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.adsc_next = NULL;
	adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1.iec_cc_command = ied_ccc_send_confirm_active_pdu;
	adsp_rdpacc_settings->dsc_call_rdpclient_1.adsc_cc_co1_ch  = &(adsp_rdpacc_settings->adsc_client_order->dsl_cc_co1);
	return TRUE;
}
/*#############################################################################
### CONSTRUCTION AREA CONSTRUCTION AREA CONSTRUCTION AREA CONSTRUCTION AREA ###
###############################################################################
                             ___          _/                      \
                     /======/            /                         \
            ____    //      \___       ,/                           ´\.
             | \\  //           :,   ./                                \
     |_______|__|_//            ;:; /                                   \
    _L_____________\o           ;;;/                                     \.
____(CCCCCCCCCCCCCC)____________-/_________________________________________\___
###############################################################################
### CONSTRUCTION AREA CONSTRUCTION AREA CONSTRUCTION AREA CONSTRUCTION AREA ###
#############################################################################*/









/*+---------------------------------------------------------------------+*/
/*| local function prototypes:                                          |*/
/*+---------------------------------------------------------------------+*/


#if 0
static BOOL m_sub_aux_helper( void *, int, void *, int );
#endif


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/

#if 0
extern BOOL m_rdpacc_start_old( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_user_event *adsp_user_event )
{
//	BOOL					bol_ret;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;

	m_init_rdpacc( adsp_call_rdpacc, adsp_user_event );
	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;

	// initialise the rdp accelerator client
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_func			= DEF_IFUNC_START;
	adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gather_i_1_in	= adsp_call_rdpacc->adsc_gather_i_1_in;
	adsl_rdpacc_settings->dsc_hl_clib_1.achc_work_area		= adsp_call_rdpacc->achc_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_len_work_area	= adsp_call_rdpacc->inc_len_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.amc_aux				= &m_sub_aux_helper;
	adsl_rdpacc_settings->dsc_hl_clib_1.vpc_userfld			= (void*)adsp_call_rdpacc->avc_ext;

	m_rdpclient_1( &adsl_rdpacc_settings->dsc_hl_clib_1 ); // this calls m_rdp_client_sub_1()
	
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_func			= DEF_IFUNC_TOSERVER;
	m_rdpclient_1( &adsl_rdpacc_settings->dsc_hl_clib_1 ); // this calls m_rdp_client_sub_1()
	adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gai1_out_to_server;
}
#endif

#if 0
/* todo: end connection properly */
extern BOOL m_rdpacc_end_old( struct dsd_call_rdpacc *adsp_call_rdpacc )
{
	//BOOL					bol_ret;
	//dsd_rdpacc_settings		*adsl_rdpacc_settings;
	return FALSE;
}
#endif

#if 0
extern BOOL m_rdpacc_get_event_old( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_draw_command **adsp_command_out )
{
	BOOL					bol_ret;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;
	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;
	adsl_rdpacc_settings->adsc_call_rdpacc = adsp_call_rdpacc;

	adsl_rdpacc_settings->dsc_hl_clib_1.inc_func			= DEF_IFUNC_FROMSERVER;
	adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gather_i_1_in	= adsp_call_rdpacc->adsc_gather_i_1_in;
	adsl_rdpacc_settings->dsc_hl_clib_1.achc_work_area		= adsp_call_rdpacc->achc_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_len_work_area	= adsp_call_rdpacc->inc_len_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.amc_aux				= &m_sub_aux_helper;
	adsl_rdpacc_settings->dsc_hl_clib_1.vpc_userfld			= (void*)adsp_call_rdpacc->avc_ext;
	m_rdpclient_1( &adsl_rdpacc_settings->dsc_hl_clib_1 ); // this calls m_rdp_client_sub_1(), see below
	
	if( adsl_rdpacc_settings->dsc_hl_clib_1.boc_callrevdir == TRUE )
	{
		adsl_rdpacc_settings->dsc_hl_clib_1.boc_callrevdir = FALSE;
		adsl_rdpacc_settings->dsc_hl_clib_1.inc_func	   = DEF_IFUNC_TOSERVER;
		m_rdpclient_1( &adsl_rdpacc_settings->dsc_hl_clib_1 ); // this calls m_rdp_client_sub_1(), see below
		adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gai1_out_to_server;
		adsp_call_rdpacc->boc_data_to_server = TRUE;
	}
	*adsp_command_out = adsl_rdpacc_settings->dsc_command_out;

}
#endif

#if 0
extern BOOL m_rdpacc_send_event_old( struct dsd_call_rdpacc *adsp_call_rdpacc, struct dsd_rdp_user_event *adsp_user_event )
{
	BOOL					bol_ret;
	dsd_client_order		*ads_order;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;

	adsl_rdpacc_settings = (dsd_rdpacc_settings*)adsp_call_rdpacc->avc_ext;
	adsl_rdpacc_settings->adsc_call_rdpacc = adsp_call_rdpacc;

	/* browser events */
	switch(adsp_user_event->iec_event_type)
	{
		case ied_mouse:
			//-- prepare to send to server
			ads_order = (dsd_client_order*) m_aux_stor_alloc( adsl_rdpacc_settings->adsc_stor_sdh_1, sizeof(dsd_client_order));
			memset(ads_order, 0, sizeof(dsd_client_order));
			ads_order->dsl_cc_co1.iec_cc_command		= ied_ccc_events_mouse_keyb;
			ads_order->ds_input_event.achc_event_buf	= adsp_user_event->dsc_user_mouse.chrc_order;
			ads_order->ds_input_event.imc_no_order		= 1;
			ads_order->ds_input_event.imc_events_len	= adsp_user_event->dsc_user_mouse.ic_len;
			break;
		case ied_keyboard:
			ads_order = (dsd_client_order*) m_aux_stor_alloc( adsl_rdpacc_settings->adsc_stor_sdh_1, sizeof(dsd_client_order));
			memset(ads_order, 0, sizeof(dsd_client_order));
			ads_order->dsl_cc_co1.iec_cc_command		= ied_ccc_events_mouse_keyb;
			ads_order->ds_input_event.achc_event_buf	= adsp_user_event->dsc_user_keyboard.chrc_order;
			ads_order->ds_input_event.imc_no_order		= 1;
			ads_order->ds_input_event.imc_events_len	= adsp_user_event->dsc_user_keyboard.ic_len;
			break;
		default:
			return FALSE;
	}

	// call RDP-Accelerator and send orders
	adsl_rdpacc_settings->adsc_events_to_server = &(ads_order->dsl_cc_co1);
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_func = DEF_IFUNC_TOSERVER;
	adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gather_i_1_in	= adsl_rdpacc_settings->adsc_call_rdpacc->adsc_gather_i_1_in;
	adsl_rdpacc_settings->dsc_hl_clib_1.achc_work_area		= adsl_rdpacc_settings->adsc_call_rdpacc->achc_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.inc_len_work_area	= adsl_rdpacc_settings->adsc_call_rdpacc->inc_len_work_area;
	adsl_rdpacc_settings->dsc_hl_clib_1.amc_aux				= &m_sub_aux_helper;
	adsl_rdpacc_settings->dsc_hl_clib_1.vpc_userfld			= (void*)adsl_rdpacc_settings;

	m_rdpclient_1( &adsl_rdpacc_settings->dsc_hl_clib_1 ); // this calls m_rdp_client_sub_1()
	adsp_call_rdpacc->adsc_gather_i_1_out = adsl_rdpacc_settings->dsc_hl_clib_1.adsc_gai1_out_to_server;

	return TRUE;
}
#endif

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
#if 0
static BOOL m_sub_aux_helper( void *avp_userfld, int inp_type, void *avp_param, int inp_length )
{
    struct dsd_rdpacc_settings *adsl_rdpacc_settings;

    adsl_rdpacc_settings = (struct dsd_rdpacc_settings*)avp_userfld;
    if ( !adsl_rdpacc_settings ) {
        return FALSE;
    }

	return adsl_rdpacc_settings->adsc_call_rdpacc->amc_aux( adsl_rdpacc_settings->adsc_call_rdpacc->avc_userfield,
                                                inp_type, avp_param, inp_length );
} // end of m_sub_aux_helper


// this function is called by m_rdpclient_1, see above
void m_rdp_client_sub_1( struct dsd_hl_clib_1		 *adsp_hl_clib_1,
						 struct dsd_rdp_client_sub_1 *adsp_rcs_1,
						 char						 *acp_ka )
{
	BOOL					bol_ret;
	dsd_rdpacc_settings		*adsl_rdpacc_settings;
	struct dsd_se_co1		*adsl_servercommand;
	
	adsl_rdpacc_settings = (dsd_rdpacc_settings*) adsp_hl_clib_1->vpc_userfld;
	
	switch( adsp_hl_clib_1->inc_func )
	{
		case DEF_IFUNC_START:
			// store the pointer to the internal storage container
			// its necessary to allocate/release memory for the rdp client
			adsl_rdpacc_settings->adsc_stor_sdh_1 = adsp_rcs_1->adsc_stor_sdh_1;
			break;

		case DEF_IFUNC_FROMSERVER:
			/* process data from server */
			while(adsp_rcs_1->adsc_se_co1_ch != NULL)
			{
				adsl_servercommand = adsp_rcs_1->adsc_se_co1_ch;
				adsp_rcs_1->adsc_se_co1_ch = adsl_servercommand->adsc_next;
				bol_ret = m_command_from_server( adsl_rdpacc_settings, adsl_servercommand, adsp_rcs_1 ); 
				if( bol_ret == TRUE ){ m_aux_stor_free( adsl_rdpacc_settings->adsc_stor_sdh_1, adsl_servercommand ); }
			}
			break;
		case DEF_IFUNC_TOSERVER:
			if( adsl_rdpacc_settings->boc_started == FALSE )
			{
				m_set_connection_details( adsl_rdpacc_settings, adsp_rcs_1 );
			}
			else if( adsl_rdpacc_settings->adsc_events_to_server != NULL )
			{
				adsp_rcs_1->adsc_cc_co1_ch = adsl_rdpacc_settings->adsc_events_to_server;
				adsl_rdpacc_settings->adsc_events_to_server = NULL;
			}
			// TODO: mouse and keyboard events
			break;
		default:
			break;
	}
}
#endif







