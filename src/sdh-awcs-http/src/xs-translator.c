/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-translator                                                     |*/
/*|   HTML5 <-> RDP Event Translation                                   |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Tobias Hofmann, March 2012                                        |*/
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

#include <hob-xs-html5.h>
#include <hob-xs-rdpacc.h>
#include <hob-xs-translator.h>
#include <hob-xs-draw.h>
/*+---------------------------------------------------------------------+*/
/*| local structs:                                                      |*/
/*+---------------------------------------------------------------------+*/

// translation table for german key codes
static const unsigned char chr_rdp_keys_de[] =
{
	/* 0    1    2    3     4    5    6    7     8    9    A    B     C    D    E    F */
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x0e,0x0f,0x00,0x00, 0x00,0x1c,0x00,0x00, /* 00 - 0F*/
	0x2a,0x1d,0x38,0x00, 0x00,0x02,0x00,0x00, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, /* 10 - 1F*/
	0x39,0x02,0x03,0x2b, 0x06,0x05,0x07,0x2b, 0x09,0x0a,0x1b,0x1b, 0x33,0x35,0x34,0x08, /* 20 - 2F*/
	0x0b,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x34,0x33, 0x56,0x0b,0x56,0x0c, /* 30 - 3F*/
	0x10,0x1e,0x30,0x2e, 0x20,0x12,0x21,0x22, 0x23,0x17,0x24,0x25, 0x26,0x32,0x31,0x18, /* 40 - 4F*/
	0x19,0x10,0x13,0x1f, 0x14,0x16,0x2f,0x11, 0x2d,0x2c,0x15,0x09, 0x0c,0x0a,0x00,0x35, /* 50 - 5F*/
	0x00,0x1e,0x30,0x2e, 0x20,0x12,0x21,0x22, 0x23,0x17,0x24,0x25, 0x26,0x32,0x31,0x18, /* 60 - 6F*/
	0x19,0x10,0x13,0x1f, 0x14,0x16,0x2f,0x11, 0x2d,0x2c,0x15,0x08, 0x56,0x0b,0x1b,0x00, /* 70 - 7F*/
	/* ASCII ends here */
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 80 - 8F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 90 - 9F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* A0 - AF*/
	0x00,0x00,0x03,0x04, 0x00,0x32,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* B0 - BF*/
	0x00,0x00,0x00,0x00, 0x28,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* C0 - CF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x27,0x00, 0x00,0x00,0x00,0x00, 0x1a,0x00,0x00,0x0c, /* D0 - DF*/
	0x00,0x00,0x00,0x00, 0x28,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* E0 - EF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x27,0x00, 0x00,0x00,0x00,0x00, 0x1a,0x00,0x00,0x00  /* F0 - FF*/
};

static const unsigned char chr_rdp_keys_function[] =
{
	/* 0    1    2    3     4    5    6    7     8    9    A    B     C    D    E    F */
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x0e,0x0f,0x00,0x00, 0x00,0x1c,0x00,0x00, /* 00 - 0F*/
	0x2a,0x1d,0x38,0x00, 0x3a,0x00,0x00,0x00, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, /* 10 - 1F*/
	0x39,0x49,0x51,0x4f, 0x47,0x4b,0x48,0x4d, 0x50,0x00,0x00,0x00, 0x00,0x52,0x53,0x00, /* 20 - 2F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 30 - 3F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 40 - 4F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x5b, 0x00,0x00,0x00,0x00, /* 50 - 5F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 60 - 6F*/
	0x3b,0x3c,0x3d,0x3e, 0x3f,0x40,0x41,0x42, 0x43,0x44,0x57,0x58, 0x00,0x00,0x00,0x00, /* 70 - 7F*/

	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 80 - 8F*/
	0x45,0x46,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* 90 - 9F*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* A0 - AF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* B0 - BF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* C0 - CF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* D0 - DF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* E0 - EF*/
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, /* F0 - FF*/
};


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
static int			m_create_mouse_event	( struct dsd_browser_event*, char*, WORD );
static int			m_create_charkey_event	( struct dsd_browser_event*, char*, int );
static int			m_create_funckey_event	( struct dsd_browser_event*, char*, int );
static BOOL			m_putImageData			( struct dsd_rdp_draw_command*, struct dsd_html5_answer* );


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
extern BOOL m_html5_to_rdp( struct dsd_browser_event *adsp_browser_event, struct dsd_rdp_user_event *adsp_user_event )
{
	switch( adsp_browser_event->iec_type )
	{
		case ied_be_connect:
			/* connect event */
			
			adsp_user_event->iec_event_type													= ied_connect;
			adsp_user_event->dsc_user_connect.dsc_connection.dsc_target_ineta.ac_str		= adsp_browser_event->dsc_rdp_srv_infos.chrc_rdp_srv;
			adsp_user_event->dsc_user_connect.dsc_connection.dsc_target_ineta.imc_len_str	= adsp_browser_event->dsc_rdp_srv_infos.inc_srv_len;
			adsp_user_event->dsc_user_connect.dsc_connection.dsc_target_ineta.iec_chs_str	= ied_chs_utf_8;
			adsp_user_event->dsc_user_connect.dsc_connection.imc_server_port				= adsp_browser_event->dsc_rdp_srv_infos.inc_port;
			adsp_user_event->dsc_user_connect.dsc_connection.dsc_aux_tcp_def.ibc_ssl_client	= 0;

			memcpy( adsp_user_event->dsc_user_connect.chrc_user, adsp_browser_event->dsc_rdp_srv_infos.chrc_user, adsp_browser_event->dsc_rdp_srv_infos.inc_user_len * sizeof(HL_WCHAR));
			adsp_user_event->dsc_user_connect.inc_user_len = adsp_browser_event->dsc_rdp_srv_infos.inc_user_len;

			memcpy( adsp_user_event->dsc_user_connect.chrc_password, adsp_browser_event->dsc_rdp_srv_infos.chrc_password, adsp_browser_event->dsc_rdp_srv_infos.inc_password_len * sizeof(HL_WCHAR));
			adsp_user_event->dsc_user_connect.inc_password_len = adsp_browser_event->dsc_rdp_srv_infos.inc_password_len;

			break;
		case ied_be_charkey_pressed:
		    adsp_user_event->iec_event_type				= ied_keyboard;
			adsp_user_event->dsc_user_keyboard.ic_len	= m_create_charkey_event(adsp_browser_event, adsp_user_event->dsc_user_keyboard.chrc_order, 0 );
			break;
		
		case ied_be_funckey_press:
			adsp_user_event->iec_event_type				= ied_keyboard;
			adsp_user_event->dsc_user_keyboard.ic_len	= m_create_funckey_event(adsp_browser_event, adsp_user_event->dsc_user_keyboard.chrc_order, 0 );
			break;
		case ied_be_funckey_release:
			adsp_user_event->iec_event_type				= ied_keyboard;
			adsp_user_event->dsc_user_keyboard.ic_len	= m_create_funckey_event(adsp_browser_event, adsp_user_event->dsc_user_keyboard.chrc_order, 1 );
			break;

		case ied_be_mouse_release:
			adsp_user_event->iec_event_type			= ied_mouse;
			adsp_user_event->dsc_user_mouse.ic_len = m_create_mouse_event( adsp_browser_event, adsp_user_event->dsc_user_mouse.chrc_order, 0x1000 );
			break;
		case ied_be_mouse_press:
			adsp_user_event->iec_event_type			= ied_mouse;
			adsp_user_event->dsc_user_mouse.ic_len = m_create_mouse_event( adsp_browser_event, adsp_user_event->dsc_user_mouse.chrc_order, (0x1000 | 0x8000) );
			break;
		case ied_be_mouse_move:
			adsp_user_event->iec_event_type			= ied_mouse;
			adsp_user_event->dsc_user_mouse.ic_len = m_create_mouse_event( adsp_browser_event, adsp_user_event->dsc_user_mouse.chrc_order, 0x0800 );
			break;
		default:
			break;
	}
	return TRUE;
}


extern BOOL m_rdp_to_html5( struct dsd_rdp_draw_command* adsp_rdp_draw_command, struct dsd_rdp_event **aadsp_rdp_event )
{
	/* DUMMY */
	/* only purpose is to seperate rdpacc and html5 part, events are the same size and so on */
	*aadsp_rdp_event = (struct dsd_rdp_event*) adsp_rdp_draw_command;
	/*
	adsp_rdp_event->iec_type		= adsp_rdp_draw_command->ied_command_type;
	adsp_rdp_event->dsc_rectangle	= adsp_rdp_draw_command->dsc_rectangle_data;
	adsp_rdp_event->adsc_next		= (dsd_rdp_event*) adsp_rdp_draw_command->adsc_next;
	*/
	return TRUE;
}

static int m_create_mouse_event( struct dsd_browser_event *adsp_browser_event, char * achp_buffer, WORD imp_flags ) 
{
	unsigned short		*aus_pos;

	*achp_buffer++	= 0x20; // Mouse Event
	aus_pos		= (unsigned short*) achp_buffer;

	*aus_pos++ = imp_flags;
	*aus_pos++ = 0xFFFF & ((unsigned short) adsp_browser_event->uinc_x );
	*aus_pos   = 0xFFFF & ((unsigned short) adsp_browser_event->uinc_y );
	
	return(7); // todo: calculate dynamically
}

static int m_create_charkey_event( struct dsd_browser_event *adsp_browser_event, char *achp_buffer, int ip_up )
{
	*achp_buffer++ = ( ip_up ? 1 : 0 );
	*achp_buffer = chr_rdp_keys_de[ (unsigned char)adsp_browser_event->rchc_key[0] ];

	return(2);
}

static int m_create_funckey_event( struct dsd_browser_event *adsp_browser_event, char *achp_buffer, int ip_up )
{
	*achp_buffer++ = ( ip_up ? 1 : 0 );
	*achp_buffer = chr_rdp_keys_function[ (unsigned char)adsp_browser_event->uchc_function ];

	return(2);
}