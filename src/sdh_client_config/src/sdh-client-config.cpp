/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: sdh-client-config                                   |*/
/*| -------------                                                     |*/
/*|  DLL / Library for HOB WebSecureProxy                             |*/
/*|  Sending JWT/IWT config to client via HTTP                        |*/
/*|    using KB's HTTP parser                                         |*/
/*|  Tobias Hofmann 09.10.12                                          |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC                                                 |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Design Documentation			                                  |*/
/*+-------------------------------------------------------------------+*/
/*! \mainpage HOB Client Configuration Provider ( CCP )
 *
 * Introduction
 * ============
 *
 * This module handles incoming requests for a certain JWT Standalone configuration ( JWT SA ).
 * It checks, if the JWT was started with the configured settings and searches for the requested configuration in the LDAP.
 * If the configuration is found, it returns it as XML, otherwise an HTTP Error Code is returned.
 *
 *  Use Case
 *   ========
 *  1) A user logs in to RDVPN. There he has a list of targets for the JWT SA.
 *
 *  2) He clicks on a target. The webserver prepares a Java Web Start File (jnlp), with following parameters
 *      - hlsecentropy: use user input to create a high entropy for the random number generator
 *      - configuration name
 *      - destination of the java sources
 *      - session cookie
 *
 *  3) The jnlp is started on the client side. JWT SA uses the parameters and forges a HOB SOCKS request
 *
 *  4) The WSP recognizes the HOB SOCKS and forwards it to the Client Configuration Provider
 *
 *  5) The Client Configuration Provider receives an HTTP header, and checks, if the JWT SA was started with the correct parameters
 *     This is to prevent user manipulation.
 *
 *  6) If everything is ok, the module searches for the configuration in the LDAP.
 *
 *  7) If the configuration is found, its returned as XML, otherwise the client receives an error.
 *
 * <b> Picture is not correctly formatted in Doxygen, please see it in the sourcecode </b>
<PRE>
            CLIENT
      ._________________.                                         RDVPN WebServer
      |.---------------.|                                          /----------\
      ||               ||      1) LOGIN ===================>       | Target 1 |
      ||   HOB RDVPN   ||                                          | Target 2 |
      ||               ||		<==================== JNLP 2)      | Target 3 |
      ||               ||                                          \----------/
      ||               ||
      ||_______________||
      /.-.-.-.-.-.-.-.-.\                                          /-----\
     /.-.-.-.-.-.-.-.-.-.\     3) HOB SOCKS================>       | WSP |
    /.-.-.-.-.-.-.-.-.-.-.\                                        \-----/
   /______/__________\___o_\                                          |
   \_______________________/                                  4) FORWARD to CCP
                                                                      |
                                                                      v
           /--------\                                              /-----------\
           | JWT SA |          <================== CONFIG 7)       | 5) and 6) |
           \--------/                                              \-----------/
</PRE>
*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#define SM_USE_SSO_CREDENTIALS	1

// Normal system-depended includes
// -------------------------------
#ifndef HL_UNIX
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/sem.h>
#include <errno.h>
#include <arpa/inet.h>
#include <hob-unix01.h>
#include <ctype.h>
#endif

#include <sdh-version.h>
#include <stdio.h>

// Include HOB-librarys, which are used
// ------------------------------------

/* for linux compilation */
#ifndef BOOL
	#define BOOL int
#endif

#include <hob-http-header-1.h>
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

#include <hob-stor-sdh.h>
#include <ds_hstring.h>
#include <ds_usercma.h>
#include <ds_xml.h>
#include <hob-libwspat.h>

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET

#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
	#include <hob-xsclib01.h>
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used structures and classes.                             |*/
/*+-------------------------------------------------------------------+*/
struct dsd_userinfo
{
	ds_hstring					dsc_username;
	ds_hstring					dsc_userdn;
	ds_hstring					dsc_password;
	ds_hstring					dsc_userdomain;
};

/*+-------------------------------------------------------------------+*/
/*| DEFINES                                                           |*/
/*+-------------------------------------------------------------------+*/
#define JWTSA_LDAP_ENTRY			"hobjwtsa"			// field name in LDAP
#define JWTSA_SESSION_LIST			"session-list"
#define JWTSA_SESSION_ENTRY			"session-entry"
#define JWTSA_SESSION_YES			"yes"
#define JWTSA_SESSION_ACTIVE		"activate"
#define JWTSA_SESSION_NAME			"name"

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

enum ied_parameters
{
	ied_wsp_userid,
	ied_hlsecentropy,
	ied_wsp_password
};

struct dsd_parameter_string
{
	const char	*achc_value;
	int		inc_len;
};

struct dsd_parameter_string dsr_parameter_strings[] =
{
	{ "WSP_USERID", 10 },
	{ "HLSECENTROPY", 12 },
	{ "WSP_PASSWORD", 12 }
};


static const char achrs_http_0[] =
{
   0x48, 0x54, 0x54, 0x50,  0x2f, 0x31, 0x2e, 0x31,  0x20, 0x32, 0x30, 0x30,  0x20, 0x4f, 0x4b, 0x0d, // |HTTP/1.1 200 OK.|
   0x0a, 0x43, 0x6f, 0x6e,  0x74, 0x65, 0x6e, 0x74,  0x2d, 0x4c, 0x65, 0x6e,  0x67, 0x74, 0x68, 0x3a, // |.Content-Length:|
   0x20,                                                                                              // |.               |
};

static const char achrs_http_1[] =
{
   0x0d, 0x0a, 0x43, 0x6f,  0x6e, 0x74, 0x65, 0x6e,  0x74, 0x2d, 0x54, 0x79,  0x70, 0x65, 0x3a, 0x20, // |..Content-Type: |
   0x74, 0x65, 0x78, 0x74,  0x2f, 0x78, 0x6d, 0x6c,  0x0d, 0x0a,                                      // |text/xml..      |
   0x43, 0x6f, 0x6e, 0x6e,  0x65, 0x63, 0x74, 0x69,  0x6f, 0x6e, 0x3a, 0x20,  0x4b, 0x65, 0x65, 0x70, // |Connection: Keep|
   0x2d, 0x41, 0x6c, 0x69,  0x76, 0x65, 0x0d, 0x0a,                                                   // |-Alive..        |   
   0x0d, 0x0a
};

static const char achrg_http_error_0[] =
{
	/* H     T     T     P     /     1     .     1            4     0     3           F     o     r     b     i     d     d     e     n             */
	0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20,  0x34, 0x30, 0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x0d, 0x0a,
	0x0d, 0x0a
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/
/* Main working function */
bool		m_sdh_client_config_fromclient( dsd_hl_clib_1* );

/* HTTP creating functions */
bool		send_http_response( dsd_hl_clib_1 *, int );
static void	send_http_error( dsd_hl_clib_1* );

/* LDAP access */
static bool	m_get_client_config( struct dsd_http_header_server_1*, dsd_hl_clib_1*, int* );
struct		dsd_ldap_val* m_get_attribute( const dsd_const_string&, const char *, int, ds_wsp_helper*, enum ied_scope_ldap_def );
void		m_close_ldap( ds_wsp_helper* );
struct		dsd_ldap_val* m_jwtsa_save_groups( dsd_co_ldap_1*, struct dsd_stor_sdh_1* );

/* configuration parsing and saving */
static bool	m_is_correct_config( struct dsd_ldap_val*, ds_wsp_helper*, const dsd_const_string& rdsp_name );
bool		m_jwtsa_config_active( dsd_xml_tag*, ds_wsp_helper* );
static bool	m_save_data_in_wa( struct dsd_ldap_val*, dsd_hl_clib_1* );

/* Helper functions */
static bool	m_high_entropy( dsd_hl_clib_1* );
static int	m_read_hasn1_length( char** );
bool		m_set_ptr_to_par_value( enum ied_parameters, char*, char** );
char*		aligne_pointer( char* );

/*+-------------------------------------------------------------------+*/
/*| Entrys for the Server-Data-Hook.                                  |*/
/*+-------------------------------------------------------------------+*/
#pragma warning(disable:4273)

/**
 * public function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf *adsp_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_conf )
{
	char chrl_buffer[512];
	int iml_length;
	const char *achl_error = "Failure reading Client Configuration Provider Details";

	iml_length = sprintf( chrl_buffer, "%s Version %s - %s", SDH_LONGNAME, SDH_VERSION_STRING, __DATE__ );

	if( iml_length > 0){ adsp_conf->amc_aux( adsp_conf->vpc_userfld, DEF_AUX_CONSOLE_OUT, (void*)chrl_buffer, iml_length ); }
	else{ adsp_conf->amc_aux( adsp_conf->vpc_userfld, DEF_AUX_CONSOLE_OUT, (void*)achl_error, strlen( achl_error ) ); }

    return TRUE;
} // end of m_hlclib_conf



extern "C" HL_DLL_PUBLIC void m_hlclib01(dsd_hl_clib_1 *adsp_hl_clib)
{
#pragma warning(default:4273)

	switch(adsp_hl_clib->inc_func)
	{
		case DEF_IFUNC_START:
		case DEF_IFUNC_CLOSE:
		{
			return;
		}
        
		// working session modes
		// ---------------------
		case DEF_IFUNC_FROMSERVER:
		case DEF_IFUNC_REFLECT: 
		case DEF_IFUNC_TOSERVER:
		{
			if( !m_sdh_client_config_fromclient( adsp_hl_clib ))
			{
				adsp_hl_clib->inc_return = DEF_IRET_ERRAU;
			}
			return;
		}
		default:
		{
			adsp_hl_clib->inc_return = DEF_IRET_ERRAU;
			return; 
		}
	} // end of switch(adsp_hl_clib->inc_func)
}

/*+-------------------------------------------------------------------+*/
/*| Main functions of working structure                               |*/
/*+-------------------------------------------------------------------+*/

/**
 * @param[in]   const char					*achp_dn			dn to read attribute from
 * @param[in]   int							inp_len_dn			length of dn
 * @param[in]   const char					*achp_attr			attribute to read
 * @param[in]   int							inp_len_attr		length of attribute
 * @param[in]   ds_wsp_helper				*adsp_wsp_helper	needed for several function calls
 * @param[in]	enum ied_scope_ldap_def		iep_scope			searchscope
 * @return      dsd_ldap_val*									values
 *																NULL if nothing found
*/
struct dsd_ldap_val* m_get_attribute( const dsd_const_string& rdsp_userdn,
                                      const char *achp_attr, int inp_len_attr,
									  ds_wsp_helper *adsp_wsp_helper,
									  enum ied_scope_ldap_def iep_scope )
{
    struct dsd_co_ldap_1    dsl_ldap;           /* ldap command struct   */
    bool                    bol_ret;            /* return from ldap call */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap      = ied_co_ldap_search;
    dsl_ldap.iec_sear_scope   = iep_scope;
    dsl_ldap.ac_dn            = const_cast<char*>(rdsp_userdn.m_get_start());
	dsl_ldap.imc_len_dn       = rdsp_userdn.m_get_len();
    dsl_ldap.iec_chs_dn       = ied_chs_utf_8;
    dsl_ldap.ac_attrlist      = (char*)achp_attr;
    dsl_ldap.imc_len_attrlist = inp_len_attr;
    dsl_ldap.iec_chs_attrlist = ied_chs_utf_8;
    memset( &dsl_ldap.dsc_add_dn, 0, sizeof(struct dsd_unicode_string) );

	bol_ret = adsp_wsp_helper->m_cb_ldap_request( &dsl_ldap );

    if (    bol_ret                     == false
         || (    dsl_ldap.iec_ldap_resp != ied_ldap_success
              && dsl_ldap.iec_ldap_resp != ied_ldap_no_results )
         || dsl_ldap.adsc_attr_desc            == NULL
         || dsl_ldap.adsc_attr_desc->adsc_attr == NULL   ) {
        if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL) && (dsl_ldap.iec_ldap_resp != ied_ldap_no_results)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: dsl_ldap.ac_errmsg is zero-terminated
				adsp_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsp_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return NULL;
    }
    return &dsl_ldap.adsc_attr_desc->adsc_attr->dsc_val;
} // end of m_get_attribute



/** \brief Close LDAP
 *
 *	self explanatory
 *
*/
void m_close_ldap( ds_wsp_helper *adsp_wsp_helper )
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap    = ied_co_ldap_close;
	bool bol_ret;
	bol_ret = adsp_wsp_helper->m_cb_ldap_request( &dsl_ldap );
	if ( dsl_ldap.iec_ldap_resp != ied_ldap_success) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: dsl_ldap.ac_errmsg is zero-terminated
				adsp_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsp_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
	}
    adsp_wsp_helper->m_reset_ldap_srv();
}

/*! \brief checks if the configuration is active
 *
 * private function m_jwtsa_config_active
 *
 * @param[in]	dsd_xml_tag* adsp_pnode		xml string with the configuration
 * @return      bool						active?
*/
bool m_jwtsa_config_active( dsd_xml_tag* adsp_pnode, ds_wsp_helper *adsp_wsp_helper )
{
	ds_xml          dsl_xml;							/* XML parsing									*/
	const char			*achl_name;							/* the config name								*/
	int             inl_len_name;						/* len of the config name						*/
	dsd_xml_tag		*adsl_temp_tag;						/* check return value of the xml parser			*/

	dsl_xml.m_init( adsp_wsp_helper );

	adsl_temp_tag = dsl_xml.m_get_value(	adsp_pnode,
											JWTSA_SESSION_ACTIVE,
											&achl_name,
											&inl_len_name );

	if( adsl_temp_tag == NULL || achl_name == NULL ){ return false; }

#if 1
    int imp_result;
    if(!m_cmpi_u8l_u8l(&imp_result, JWTSA_SESSION_YES, sizeof(JWTSA_SESSION_YES)-1, (char*)achl_name, inl_len_name))
        return false;
    return imp_result == 0;
#else
    /* convert every letter to lowercase */
	for( int i = 0; i < inl_len_name; i++ ){ achl_name[i] = (char)tolower( achl_name[i] ); }

	/* check if value is YES */
	if( memcmp( achl_name, JWTSA_SESSION_YES, inl_len_name ) == 0 ){ return true; }
	return false;
#endif
}



static bool m_is_correct_config( struct dsd_ldap_val *adsp_value, ds_wsp_helper *adsp_wsp_helper, const dsd_const_string& rdsp_name )
{
	int							inl_own_len;
	ds_xml						dsl_xml_parser;			/* get a XML parser class */
	dsd_xml_tag					*adsl_node;
	dsd_xml_tag					*adsl_temp_tag;
	const char						*achl_name;				/* the config name								*/
	int							inl_len_name;			/* len of the config name						*/

	if( rdsp_name.m_get_len() <= 0 ){ return false; }

	inl_own_len = adsp_value->imc_len_val;

	dsl_xml_parser.m_init( adsp_wsp_helper ); // wsp helper provides memory management
	
	adsl_node = dsl_xml_parser.m_from_xml( adsp_value->ac_val, inl_own_len );
	if( adsl_node == NULL || adsl_node->ads_child == NULL ){ return false; }

	/* search for <session-list> */
	adsl_node = dsl_xml_parser.m_get_value( adsl_node, JWTSA_SESSION_LIST, &achl_name, &inl_len_name );
	if( adsl_node == NULL || adsl_node->ads_child == NULL ){ return false; }

	/* from <session-list> to <session-entry> */
	adsl_node = adsl_node->ads_child;

	/* loop through all available nodes*/	
	while( adsl_node != NULL )
	{
		/* check if data is still a session entry */
		if( memcmp( adsl_node->ach_data, JWTSA_SESSION_ENTRY, adsl_node->in_len_data ) != 0 )
		{
			return false;
		}
		
		adsl_temp_tag = dsl_xml_parser.m_get_value( adsl_node,
													JWTSA_SESSION_NAME,
													&achl_name,
													&inl_len_name );
		if( adsl_temp_tag == NULL ){ return false; }

		/* compare the name */
		if(!rdsp_name.m_equals(dsd_const_string(achl_name, inl_len_name)))
		{
			/* get next node if the name doesnt match */
			adsl_node = adsl_node ->ads_next;
			continue;
		}

		/* now we found the configuration we wanted, check if it is active */
		if( m_jwtsa_config_active( adsl_node, adsp_wsp_helper ) ){ return true; }
		
		adsl_node = adsl_node ->ads_next;
	}
	return false;
}



/** \brief Stores the groups in our JWTSA container
 *
 *	Takes a dsd_co_ldap_1* pointer and checks the groups. then it stores
 *  all the groups in a storage container, which is member of the class
 *
*/
struct dsd_ldap_val* m_jwtsa_save_groups( dsd_co_ldap_1 *adsp_co_ldap, struct dsd_stor_sdh_1 *adsp_stor_sdh_1 )
{
	char					*achl_own;
	struct dsd_ldap_val		*adsl_attr_start = 0;
	struct dsd_ldap_val		*adsl_attr_current = 0;
	struct dsd_ldap_val		*adsl_attr_old = 0;

	adsl_attr_current = adsp_co_ldap->adsc_memship_desc;

	while( adsl_attr_current != NULL )
	{
		/* get some memory from our container */
		achl_own = (char*)m_aux_stor_alloc( adsp_stor_sdh_1, sizeof( struct dsd_ldap_val ) + adsl_attr_current->imc_len_val );
		if( achl_own == NULL ){ return NULL; }
		
		/* save our data, otherwise it will be lost with the next LDAP call */
		memcpy( achl_own, adsl_attr_current, sizeof ( struct dsd_ldap_val ) );
		memcpy( achl_own + sizeof( struct dsd_ldap_val ), adsl_attr_current->ac_val , adsl_attr_current->imc_len_val );

		/* create linked list */
		if( adsl_attr_start == NULL )
		{
			adsl_attr_start	= ( struct dsd_ldap_val* )achl_own;
			adsl_attr_start->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */
		}
		else{ adsl_attr_old->adsc_next_val = ( struct dsd_ldap_val* )achl_own; }
		
		adsl_attr_old = ( struct dsd_ldap_val* )achl_own;
		adsl_attr_old->ac_val = (char*)( achl_own + sizeof( struct dsd_ldap_val ) ); /* data is stored in the memory behind the structure */

		adsl_attr_current = adsl_attr_current->adsc_next_val;
	}

	return adsl_attr_start;
}

/**	\brief stores a value ( dsd_ldap_val ) in the workarea
*
* @param[in]		struct dsd_ldap_val *adsp_value
* @param[in/out]	dsd_hl_clib_1 *adsp_hl_clib
*/
static bool m_save_data_in_wa(  struct dsd_ldap_val *adsp_value, dsd_hl_clib_1 *adsp_hl_clib )
{
	struct dsd_aux_get_workarea		adsl_wa;
	struct dsd_gather_i_1			*adsl_gather_out = NULL;
	int							bol_ret;
	bool							bol_first = true;

	adsl_wa.achc_work_area		= adsp_hl_clib->achc_work_area;
	adsl_wa.imc_len_work_area	= adsp_hl_clib->inc_len_work_area;

	adsp_hl_clib->adsc_gai1_out_to_client = (struct dsd_gather_i_1 *) adsl_wa.achc_work_area;

	while( adsp_value->imc_len_val > 0 )
	{
		if( adsl_wa.imc_len_work_area < sizeof( struct dsd_gather_i_1 ) ){ return false; }
		
		adsl_gather_out					 = (struct dsd_gather_i_1 *) adsl_wa.achc_work_area;
		adsl_wa.achc_work_area			+= sizeof( dsd_gather_i_1 );
		adsl_wa.imc_len_work_area		-= sizeof( dsd_gather_i_1 );
		adsl_gather_out->achc_ginp_cur	 = adsl_wa.achc_work_area;
		
		if( adsl_wa.imc_len_work_area < adsp_value->imc_len_val )
		{
			memcpy( (void*)adsl_wa.achc_work_area, adsp_value->ac_val, adsl_wa.imc_len_work_area );
			adsl_gather_out->achc_ginp_end		 = adsl_wa.achc_work_area + adsl_wa.imc_len_work_area;
			adsp_value->ac_val					+= adsl_wa.imc_len_work_area;	
			adsp_value->imc_len_val				-= adsl_wa.imc_len_work_area;

			if( bol_first )
			{
				adsp_hl_clib->achc_work_area += adsp_hl_clib->inc_len_work_area;
				adsp_hl_clib->inc_len_work_area = 0;
				bol_first = false;
			}

			bol_ret = adsp_hl_clib->amc_aux( adsp_hl_clib->vpc_userfld, DEF_AUX_GET_WORKAREA, (void*)&adsl_wa, sizeof( dsd_aux_get_workarea ) );
			if( !bol_ret ){ return false; }
			adsl_gather_out->adsc_next = ( struct dsd_gather_i_1 * )adsl_wa.achc_work_area;
			continue;
		}

		memcpy( (void*)adsl_wa.achc_work_area, adsp_value->ac_val, adsp_value->imc_len_val );
		if( bol_first )
		{
			adsp_hl_clib->achc_work_area	+= adsp_value->imc_len_val + sizeof( struct dsd_gather_i_1 );
			adsp_hl_clib->inc_len_work_area -= ( adsp_value->imc_len_val + sizeof( struct dsd_gather_i_1 ) );
		}
		adsl_wa.achc_work_area					+= adsp_value->imc_len_val;
		adsl_wa.imc_len_work_area				-= adsp_value->imc_len_val;
		adsl_gather_out->achc_ginp_end			 = adsl_wa.achc_work_area;
		adsl_gather_out->adsc_next				 = NULL;
		return true;
	}
	return false;
}

/** \brief Get the desired config out of LDAP
 *
 *	Searches the configuration for JWT SA in the LDAP and returns it in the workarea.
 *	At the start of the workarea is a gather structure
 *
 * \param[in]		struct dsd_http_header_server_1		*adsp_http_header
 * \param[in/out]	dsd_hl_clib_1						*adsp_hl_clib
*/
static bool m_get_client_config( struct dsd_http_header_server_1 *adsp_http_header, dsd_hl_clib_1 *adsp_hl_clib, int *inp_len )
{
	class ds_usercma			dsl_usercma;
	ds_wsp_helper				dsl_wsp_helper;
	bool						bol_ret;
	struct dsd_ldap_val			*adsl_value;            /* attribute value        */
	//struct dsd_userinfo			dsl_userinfo;
	bool						bol_found = false;
	dsd_co_ldap_1				dsl_co_ldap;
	dsd_ldap_val				*adsl_attr_current = NULL;
	struct dsd_stor_sdh_1		dsl_stor_groups;
	dsd_domain					*adsl_domain;
	
	/* initialize our helper class */
	dsl_wsp_helper.m_init_trans( adsp_hl_clib );
	
	/* get the information about the user */
    bol_ret = ds_usercma::m_get_usercma( &dsl_wsp_helper, &dsl_usercma );
    if ( !bol_ret ){ 
        dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE001E get user-cma failed" );
        return false;
    }
	adsl_domain = dsl_usercma.m_get_domain();

	dsd_const_string dsl_url_path(adsp_http_header->achc_url_path, adsp_http_header->imc_length_url_path);
	if(!dsl_url_path.m_starts_with("/")) {
		dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE002E invalid path" );
        return false;
	}
	dsl_url_path = dsl_url_path.m_substring(1);
	int inl_version = 0;
#if SM_USE_SSO_CREDENTIALS
	if(dsl_url_path.m_starts_with("client-config/")) {
		dsl_url_path = dsl_url_path.m_substring(14);
		if(dsl_url_path.m_starts_with("v1/")) {
			dsl_url_path = dsl_url_path.m_substring(3);
			inl_version = 1;
		}
		else {
			dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE002E unsupported version" );
			return false;
		}
	}
#endif

	/***********************************************************************************************************\
	* The following scenarios can happen:																		*
	*		AUTH			CONFIG STORE																		*
	*		====			============																		*
	* 1)	intern LDAP		intern LDAP																			*
	*		extern LDAP		extern LDAP => in both cases we have to bind with the userdn to search the config	*
	*																											*
	* 2)	extern LDAP		intern LDAP																			*
	*		KERBEROS		intern LDAP																			*
	*		RADIUS			intern LDAP = in all three cases we have to use the search admin to bind			*
	\***********************************************************************************************************/

	enum ied_usercma_login_flags iel_auth_flags;
    int inl_authmethod = dsl_usercma.m_get_authmethod(iel_auth_flags);

	switch( inl_authmethod )
	{
		/* we use the same ldap server we have used for authentication */
		case DEF_CLIB1_CONF_DYN_LDAP:		// 0X00000100
		case DEF_CLIB1_CONF_LDAP:			// 0X00000080

			dsl_wsp_helper.m_reset_ldap_srv();
			bol_ret = dsl_usercma.m_auth_equals_config_ldap();
			
			/* check if it is case 1) in upper explanation -> bol_ret = true */
			if( bol_ret )
			{
				bol_ret = dsl_wsp_helper.m_set_ldap_srv(adsl_domain->achc_ldap,
                    adsl_domain->inc_len_ldap );
				if ( !bol_ret ){ 
                    dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE002E failed to select LDAP server" );
                    return false;
                }

				/* get the needed information out of the CMA */
				ds_hstring dsl_userdn(dsl_usercma.m_get_userdn());
				ds_hstring dsl_password(dsl_usercma.m_get_password());

				struct dsd_co_ldap_1 dsl_ldap;           /* ldap command struct   */

                memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
                dsl_ldap.iec_co_ldap		= ied_co_ldap_bind;
                dsl_ldap.iec_ldap_auth		= ied_auth_dn;
                dsl_ldap.ac_userid			= const_cast<char*>(dsl_userdn.m_get_ptr());
                dsl_ldap.imc_len_userid		= dsl_userdn.m_get_len();
                dsl_ldap.iec_chs_userid		= ied_chs_utf_8;
                dsl_ldap.ac_passwd			= const_cast<char*>(dsl_password.m_get_ptr());
                dsl_ldap.imc_len_passwd		= dsl_password.m_get_len();
                dsl_ldap.iec_chs_passwd		= ied_chs_utf_8;
                bol_ret = dsl_wsp_helper.m_cb_ldap_request( &dsl_ldap );
                if ( (bol_ret == false) || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
					if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
						if (dsl_ldap.imc_len_errmsg == -1) { // means: dsl_ldap.ac_errmsg is zero-terminated
							dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
						}
						else {
							dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
						}
					}
                    dsl_wsp_helper.m_logf( ied_sdh_log_error, "HCLCFGE003E LDAP bind failed with error %d",
                        dsl_ldap.iec_ldap_resp );
                    m_close_ldap( &dsl_wsp_helper );
                    return false;
                }
				break;
			}
		
			// BREAK missing on purpose! we have to use search admin!
		
		default: /* we have different authentication, use search admin */
			//DEF_CLIB1_CONF_SERVLI			0X00000001
			//DEF_CLIB1_CONF_HOBWSAT3		0X00000002
			//DEF_CLIB1_CONF_USERLI			0X00000004
			//DEF_CLIB1_CONF_RADIUS			0X00000008
			//DEF_CLIB1_CONF_DYN_RADIUS		0X00000010
			//DEF_CLIB1_CONF_KRB5			0X00000020
			//DEF_CLIB1_CONF_DYN_KRB5		0X00000040

			if ( adsl_domain->inc_len_ldap > 0 && adsl_domain->achc_ldap != NULL )
			{
				/*
					we have a corresponding ldap configured in domain
					   -> select this one
						  if this is successful we are ready
						  if not configuration is wrong
				*/
				bol_ret = dsl_wsp_helper.m_set_ldap_srv( adsl_domain->achc_ldap, adsl_domain->inc_len_ldap );
				if ( !bol_ret ){ 
                    dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE004E failed to select LDAP server" );
                    return false;
                }
			}
			
            struct dsd_co_ldap_1 dsl_ldap;           /* ldap command struct   */

            memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
            dsl_ldap.iec_co_ldap		= ied_co_ldap_bind;
            /* do an administration bind to config ldap */
            if ( adsl_domain->inc_len_dn_admin > 0 ) {
                dsl_ldap.iec_ldap_auth  = ied_auth_dn;
                dsl_ldap.ac_userid      = adsl_domain->achc_dn_admin;
                dsl_ldap.imc_len_userid = adsl_domain->inc_len_dn_admin;
                dsl_ldap.iec_chs_userid = ied_chs_utf_8;
                dsl_ldap.ac_passwd      = adsl_domain->achc_pwd_admin;
                dsl_ldap.imc_len_passwd = adsl_domain->inc_len_pwd_admin;
                dsl_ldap.iec_chs_passwd = ied_chs_utf_8;
            } else {
                dsl_ldap.iec_ldap_auth = ied_auth_admin;
            }
            bol_ret = dsl_wsp_helper.m_cb_ldap_request( &dsl_ldap );
            if ( (bol_ret == false) || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
				if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
					if (dsl_ldap.imc_len_errmsg == -1) { // means: dsl_ldap.ac_errmsg is zero-terminated
						dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
					}
					else {
						dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
					}
				}
                dsl_wsp_helper.m_logf( ied_sdh_log_error, "HCLCFGE005E LDAP bind failed with error %d",
                    dsl_ldap.iec_ldap_resp );
                m_close_ldap( &dsl_wsp_helper );
                return false;
            }
			break;
	}

	/* Now check every available LDAP entry */

	/*----------*/
	/* OWN 		*/
	/*----------*/
	/* needs userdn */
    ds_hstring dsl_userdn(dsl_usercma.m_get_userdn());

    adsl_value = m_get_attribute(	dsl_userdn.m_const_str(),
									JWTSA_LDAP_ENTRY,
									(int)sizeof(JWTSA_LDAP_ENTRY) - 1,
									&dsl_wsp_helper,
									ied_sear_baseobject );
	if( adsl_value != NULL )
	{
		/* Check if configuration is in this file! */
		bol_ret = m_is_correct_config( adsl_value, &dsl_wsp_helper, dsl_url_path );
		if( bol_ret )
		{
			bol_found = true;
		}
	}

	/*----------*/
	/* TREE		*/
	/*----------*/
	if( !bol_found ) /* search in the groups */
	{
		int inl_last_pos = 0;
		while( true )
		{
			/* check if there is a comma */
            int inl_pos = dsl_userdn.m_search(inl_last_pos, ",");
            if(inl_pos == -1)
                break;
            inl_last_pos = inl_pos + 1;
            dsd_const_string dsl_userdn_part(dsl_userdn.m_substring(inl_last_pos));
			//dsl_userinfo.dsc_userdn.m_set(dsl_userinfo.dsc_userdn.m_substring(i + 1));
			//i = 0; /* dsc_userdn is now changed to the new value, so we have to start parsing at the beginning of the string!*/

			adsl_value = m_get_attribute(	dsl_userdn_part,
											JWTSA_LDAP_ENTRY,
											(int)sizeof(JWTSA_LDAP_ENTRY) - 1,
											&dsl_wsp_helper,
											ied_sear_baseobject );
			if( adsl_value != NULL )
			{
				/* Check if configuration is in this file! */
				bol_ret = m_is_correct_config( adsl_value, &dsl_wsp_helper, dsl_url_path );
				if( bol_ret )
				{
					bol_found = true;
					//dsl_userinfo.dsc_userdn.m_set(dsl_userdn_part);
			        break;
				}
			}
		}
	}

	/*----------*/
	/* GROUP	*/
	/*----------*/
	dsl_stor_groups.imc_stor_size = 2048;
	dsl_stor_groups.amc_aux = adsp_hl_clib->amc_aux;
	dsl_stor_groups.vpc_userfld = adsp_hl_clib->vpc_userfld;

	m_aux_stor_start( &dsl_stor_groups );

	if( !bol_found ) /* search in the groups */
	{
		/* prepare LDAP access */
		memset( &dsl_co_ldap, 0, sizeof( dsd_co_ldap_1 ) );
#ifdef OLD_LDAP_CALL_FOR_GROUP_MEMBERSHIP
		dsl_co_ldap.ac_dn = NULL;
		dsl_co_ldap.imc_len_dn = 0;
		dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership;   
		dsl_co_ldap.iec_sear_scope = ied_sear_basedn;
#else
		dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership_nested;
		dsl_co_ldap.iec_chs_dn  = ied_chs_utf_8;
		dsl_co_ldap.ac_dn       = const_cast<char*>(dsl_userdn.m_get_ptr());
		dsl_co_ldap.imc_len_dn  = dsl_userdn.m_get_len();
		dsl_co_ldap.iec_sear_scope = ied_sear_basedn;
#endif
		bol_ret = dsl_wsp_helper.m_cb_ldap_request( &dsl_co_ldap );
		if( (bol_ret == false) || (dsl_co_ldap.iec_ldap_resp != ied_ldap_success) ){ 
			if ((bol_ret != false) && (dsl_co_ldap.iec_ldap_resp != ied_ldap_no_results) && (dsl_co_ldap.ac_errmsg != NULL)) {
				if (dsl_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
					dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_co_ldap.ac_errmsg);
				}
				else {
					dsl_wsp_helper.m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_co_ldap.imc_len_errmsg, dsl_co_ldap.ac_errmsg);
				}
			}
            dsl_wsp_helper.m_logf( ied_sdh_log_error, "HCLCFGE006E failed to get LDAP membership (error %d)",
                dsl_co_ldap.iec_ldap_resp );
            return false;
        }

		/* save the results, otherwise they are lost with the next LDAP call! */
		adsl_attr_current = m_jwtsa_save_groups( &dsl_co_ldap, &dsl_stor_groups );
		
		/* loop through all group memberships and get the configs out of LDAP */
		while( adsl_attr_current != NULL )
		{
			dsd_const_string dsl_userdn(adsl_attr_current->ac_val, adsl_attr_current->imc_len_val);
			adsl_value = m_get_attribute(	dsl_userdn,
											JWTSA_LDAP_ENTRY,
											(int)sizeof(JWTSA_LDAP_ENTRY) - 1,
											&dsl_wsp_helper,
											ied_sear_baseobject );
			if( adsl_value != NULL )
			{
				/* Check if configuration is in this file! */
				bol_ret = m_is_correct_config( adsl_value, &dsl_wsp_helper, dsl_url_path );
				if( bol_ret )
				{
					bol_found = true;
                    //dsl_userinfo.dsc_userdn.m_set( dsl_userdn );
					break;
				}
			}	
			adsl_attr_current = adsl_attr_current->adsc_next_val;
		}
	}

	/* cleanup */
	m_aux_stor_end( &dsl_stor_groups );

	if( !bol_found )
	{
		m_close_ldap( &dsl_wsp_helper );
        dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE007E requested configuration not found" );
		return false;
	}

#if SM_USE_SSO_CREDENTIALS
	if(inl_version >= 1) {
		dsd_const_string dsl_xml_config(adsl_value->ac_val, adsl_value->imc_len_val);
		dsd_const_string dsl_xml_prefix;
		int inl_prefix1 = dsl_xml_config.m_index_of("<?");
		if(inl_prefix1 >= 0) {
			int inl_prefix2 = dsl_xml_config.m_index_of(inl_prefix1, "?>");
			if(inl_prefix2 >= 0) {
				dsl_xml_prefix = dsl_xml_config.m_substring(0, inl_prefix2+2);
				dsl_xml_config = dsl_xml_config.m_substring(inl_prefix2+2);
			}
		}
		int inl_output_len = 0;
		bol_ret = dsl_wsp_helper.m_send_data(dsl_xml_prefix.m_get_ptr(), dsl_xml_prefix.m_get_len(), ied_sdh_dd_toclient);
		if(!bol_ret)
			goto LBL_CLOSE;
		inl_output_len += dsl_xml_prefix.m_get_len();
		dsd_const_string dsl_client_config1 = "<client-config>";
		bol_ret = dsl_wsp_helper.m_send_data(dsl_client_config1.m_get_ptr(), dsl_client_config1.m_get_len(), ied_sdh_dd_toclient);
		if(!bol_ret)
			goto LBL_CLOSE;
		inl_output_len += dsl_client_config1.m_get_len();
		ds_usercma::dsd_sso_info dsl_sso_info;
		if(dsl_usercma.m_read_single_signon_credentials(dsl_sso_info)) {
			ds_hstring dsl_sso_data(&dsl_wsp_helper);
			dsl_sso_data.m_write("<sso-credentials><userid>");
			dsl_sso_data.m_write_xml_text(dsl_sso_info.dsc_client_userid);
			dsl_sso_data.m_write("</userid><domain>");
			dsl_sso_data.m_write_xml_text(dsl_sso_info.dsc_client_domain);
			dsl_sso_data.m_write("</domain><password>");
			dsl_sso_data.m_write_xml_text(dsl_sso_info.dsc_client_password);
			dsl_sso_data.m_write("</password></sso-credentials>");
			dsl_usercma.m_clear_single_signon_credentials(dsl_sso_info);
			bol_ret = dsl_wsp_helper.m_send_data(dsl_sso_data.m_get_ptr(), dsl_sso_data.m_get_len(), ied_sdh_dd_toclient);
			if(!bol_ret)
				goto LBL_CLOSE;
			inl_output_len += dsl_sso_data.m_get_len();
		}
		bol_ret = dsl_wsp_helper.m_send_data(dsl_xml_config.m_get_ptr(), dsl_xml_config.m_get_len(), ied_sdh_dd_toclient);
		if(!bol_ret)
			goto LBL_CLOSE;
		inl_output_len += dsl_xml_config.m_get_len();
		dsd_const_string dsl_client_config2 = "</client-config>";
		bol_ret = dsl_wsp_helper.m_send_data(dsl_client_config2.m_get_ptr(), dsl_client_config2.m_get_len(), ied_sdh_dd_toclient);
		if(!bol_ret)
			goto LBL_CLOSE;
		inl_output_len += dsl_client_config2.m_get_len();

		*inp_len = inl_output_len;
		goto LBL_CLOSE;
	}
#endif

	*inp_len = adsl_value->imc_len_val;
	bol_ret = m_save_data_in_wa( adsl_value, adsp_hl_clib );
    if( !bol_ret ) {
        dsl_wsp_helper.m_log( ied_sdh_log_error, "HCLCFGE008E failed to save configuration data" );
    }
	
LBL_CLOSE:
	m_close_ldap( &dsl_wsp_helper );
	return bol_ret;
}

static bool m_high_entropy( dsd_hl_clib_1 *adsp_hl_clib )
{
	class ds_usercma			dsl_usercma;
	ds_wsp_helper				dsl_wsp_helper;
	struct dsd_role				*adsl_role;
	bool						bol_ret;
	
	/* initialize our helper class */
	dsl_wsp_helper.m_init_trans( adsp_hl_clib );
	
	/* get the information about the user */
    bol_ret = ds_usercma::m_get_usercma( &dsl_wsp_helper, &dsl_usercma );
    if ( !bol_ret ){ return false; }

	adsl_role = dsl_usercma.m_get_role();
	
	return( adsl_role->boc_high_entropy );
}

static void send_http_error( dsd_hl_clib_1 *adsp_hl_clib )
{
	dsd_gather_i_1* adsl_gather_1;
	
	if( adsp_hl_clib->inc_len_work_area < sizeof( struct dsd_gather_i_1 ) ){ return; }

	adsl_gather_1 = ( dsd_gather_i_1* ) adsp_hl_clib->achc_work_area;
	
	adsl_gather_1->achc_ginp_cur = (char*) achrg_http_error_0;
	adsl_gather_1->achc_ginp_end = (char*) achrg_http_error_0 + sizeof( achrg_http_error_0 );
	adsl_gather_1->adsc_next = NULL;
	adsp_hl_clib->adsc_gai1_out_to_client = adsl_gather_1;
}

static int m_read_hasn1_length( char **aachp_data )
{
	int inl_result	= 0;
	int inl_shift	= 0;
	int inl_byte	= 0;

	while(true)
	{
		inl_byte = **aachp_data;
		(*aachp_data)++;

		inl_result |= (inl_byte & 0x7F) << inl_shift;
		if((inl_byte & 0x80) == 0)
		{
			return inl_result;
		}
		inl_shift += 7;
	}
}

bool m_set_ptr_to_par_value( enum ied_parameters iep_par, char *achp_data, char **aachp_par_value )
{
	int			inl_length_key = 0;
	int			bol_ret;
	int			inl_result;
	int			inl_len_bytes;

	if( achp_data == NULL ){ return false; }

	while( *achp_data != 0 )
	{
		inl_length_key = m_read_hasn1_length( &achp_data ); // calculate the length of the following utf8 string
		inl_len_bytes = m_len_bytes_vx( (void*)achp_data, inl_length_key, ied_chs_utf_8 ); // byte size can differ from string length

		if( inl_length_key == dsr_parameter_strings[iep_par].inc_len )
		{
			// if the length is the same, test if it is the searched parameter
			bol_ret = m_cmpi_vx_vx( &inl_result,
									dsr_parameter_strings[iep_par].achc_value, dsr_parameter_strings[iep_par].inc_len, ied_chs_utf_8,
									achp_data, inl_length_key, ied_chs_utf_8 );

			// if the comparison was successful
			if( bol_ret && inl_result == 0 )
			{
				achp_data += inl_len_bytes;
				*aachp_par_value = achp_data;
				return true;
			}
		}
		achp_data += inl_len_bytes;
	}

	return false;
}


bool m_sdh_client_config_fromclient( dsd_hl_clib_1 *adsp_hl_clib )
{
	int										il_len;
	int										il_result;
	dsd_gather_i_1							*adsl_input = adsp_hl_clib->adsc_gather_i_1_in;
	char									*achl_par_value;
	char									chrl_http_url_path[ 1024 ];   /* HTTP URL path           */
	struct dsd_stor_sdh_1					dsl_stor_sdh_1;
#ifdef B150602
	static dsd_proc_http_header_server_1	dsl_phhs;
#endif
static const struct dsd_proc_http_header_server_1 dss_phhs1 = {
   (amd_store_alloc) &m_aux_stor_alloc,     /* amc_store_alloc - storage container allocate memory */
   (amd_store_free) &m_aux_stor_free,       /* amc_store_free - storage container free memory */
   TRUE,                                    /* boc_consume_input - consume input */
   TRUE,                                    /* boc_store_cookies - store cookies */
   TRUE                                     /* boc_out_os - output fields for other side */
};
	dsd_call_http_header_server_1			dsl_chhs;  // call HTTP processing at server
	dsd_http_header_server_1				dsl_hhs;

	if(adsl_input == NULL){ return true; }

	/* Get a storage container */
	dsl_stor_sdh_1.amc_aux			= adsp_hl_clib->amc_aux;
	dsl_stor_sdh_1.vpc_userfld		= adsp_hl_clib->vpc_userfld;
	dsl_stor_sdh_1.imc_stor_size	= 8192;
	m_aux_stor_start( &dsl_stor_sdh_1 );

	// Prepare input structure
	memset(&dsl_chhs, 0, sizeof( dsd_call_http_header_server_1 ));

	/* set the storage container */
	dsl_chhs.adsc_stor_sdh_1			= &dsl_stor_sdh_1;
	dsl_chhs.adsc_gai1_in               = adsl_input;   
	dsl_chhs.achc_url_path              = chrl_http_url_path;
	dsl_chhs.imc_length_url_path_buffer = sizeof( chrl_http_url_path );

#ifdef B150206
	// Prepare options structure
	dsl_phhs.boc_consume_input = TRUE;
	dsl_phhs.boc_store_cookies = TRUE;
#endif

	// Now call http-parser
#ifdef B150206
	BOOL bol_ret = m_proc_http_header_server(	&dsl_phhs,  /* HTTP processing at server */
												&dsl_chhs,  /* call HTTP processing at server */
												&dsl_hhs);  /* HTTP processing at server */
#endif
	BOOL bol_ret = m_proc_http_header_server(	&dss_phhs1,  /* HTTP processing at server */
												&dsl_chhs,  /* call HTTP processing at server */
												&dsl_hhs);  /* HTTP processing at server */
	if( !bol_ret )
	{
		m_aux_stor_end( &dsl_stor_sdh_1 );
		return false;
	}

	// Check header length
	if( dsl_hhs.imc_length_http_header == 0 )
	{
		m_aux_stor_end( &dsl_stor_sdh_1 );
		return true;
	}

	// Encode URI to UTF8
	char chrl_buffer[1024];
	int iml_len;

	memset( chrl_buffer, 0, sizeof( chrl_buffer ) );
	iml_len = m_cpy_vx_vx(	chrl_buffer,			sizeof(chrl_buffer),			ied_chs_utf_8,
							dsl_hhs.achc_url_path,	dsl_hhs.imc_length_url_path,	ied_chs_uri_1 );
	
	if( iml_len == -1 )
	{
		m_aux_stor_end( &dsl_stor_sdh_1 );
		send_http_error( adsp_hl_clib );
		return false;
	}

	dsl_hhs.achc_url_path		= chrl_buffer;
	dsl_hhs.imc_length_url_path	= iml_len;

	if( m_high_entropy( adsp_hl_clib ) )
	{
		bol_ret = m_set_ptr_to_par_value( ied_hlsecentropy, dsl_hhs.achc_hob_cookie, &achl_par_value );
		if( !bol_ret )
		{
			m_aux_stor_end( &dsl_stor_sdh_1 );
			send_http_error( adsp_hl_clib );
			return false;
		}
		il_len = m_read_hasn1_length( &achl_par_value );
		// now compare the value
		bol_ret = m_cmpi_vx_vx( &il_result,
								achl_par_value, il_len, ied_chs_utf_8,
								(void*)"YES", 3, ied_chs_utf_8 );

		// if the comparison wasn't successful
		if( !bol_ret || il_result != 0 )
		{
			m_aux_stor_end( &dsl_stor_sdh_1 );
			send_http_error( adsp_hl_clib );
			return false;
		}
	}

	bol_ret = m_get_client_config( &dsl_hhs, adsp_hl_clib, &il_len );

	m_aux_stor_end( &dsl_stor_sdh_1 );

	if( bol_ret == false )
	{
		send_http_error( adsp_hl_clib );
		return false;
	}

   // Send answer
   return send_http_response( adsp_hl_clib, il_len );
}

bool send_http_response( dsd_hl_clib_1 *adsp_hl_clib, int inp_len )
{
	struct dsd_aux_get_workarea		dsl_wa;
	struct dsd_gather_i_1			*adsl_gather_1 = NULL;
	struct dsd_gather_i_1			*adsl_gather_2 = NULL;
	int								bol_ret;
	char							chrl_payload_string[10];
	int								i = 9; /* length of chrl_len_string - 1 */
	int								iml_len_string = 0;
	int								iml_total = 0;
	
	bol_ret = adsp_hl_clib->amc_aux( adsp_hl_clib->vpc_userfld, DEF_AUX_GET_WORKAREA, (void*)&dsl_wa, sizeof( dsd_aux_get_workarea ) );
	if( !bol_ret ){ return false; }

	/*--- calculate whole size we need ---*/
	iml_total += sizeof( struct dsd_gather_i_1 );						/* one gather */
	iml_total += sizeof( achrs_http_0 );								/* HTTP STATUS Header */
	
	/* convert to a string */
	while( inp_len > 0 )
	{
		chrl_payload_string[i--] = (char)(0x30 + (inp_len % 10));
		inp_len /= 10;
	}
	iml_len_string = 9 - i;
	iml_total += iml_len_string;										/* length of the payload, converted to a string */
	iml_total += sizeof(achrs_http_1);									/* Content type HTTP Header */
	/*--- size calculation done ---*/
	if( dsl_wa.imc_len_work_area < iml_total ){ return false; }

	/* set a gather at the start of the workarea */
	adsl_gather_1 = ( struct dsd_gather_i_1* ) dsl_wa.achc_work_area;
	dsl_wa.achc_work_area		+= sizeof( struct dsd_gather_i_1 );
	dsl_wa.imc_len_work_area	-= sizeof( struct dsd_gather_i_1 );
	adsl_gather_1->achc_ginp_cur = dsl_wa.achc_work_area;
	
	/* copy HTTP status headers, because global static variables are unloaded when the DLL is gone */
	memcpy( dsl_wa.achc_work_area, achrs_http_0, sizeof( achrs_http_0 ) );
	dsl_wa.achc_work_area		+= sizeof( achrs_http_0 );
	dsl_wa.imc_len_work_area	-= sizeof( achrs_http_0 );

	/* copy the length as string */
	memcpy( dsl_wa.achc_work_area, &(chrl_payload_string[i+1]), iml_len_string );
	dsl_wa.achc_work_area		+= iml_len_string;
	dsl_wa.imc_len_work_area	-= iml_len_string;

	/* copy the content type http header*/
	memcpy( dsl_wa.achc_work_area, achrs_http_1, sizeof( achrs_http_1 ) );
	dsl_wa.achc_work_area		+= sizeof( achrs_http_1 );
	dsl_wa.imc_len_work_area	-= sizeof( achrs_http_1 );

	/* set the end */
	adsl_gather_1->achc_ginp_end = dsl_wa.achc_work_area;
	
	/* change the gathers to the right order ( adsc_gai1_out_to_client was set by m_save_data_in_wa ) */
	adsl_gather_2 = adsp_hl_clib->adsc_gai1_out_to_client;
	adsl_gather_1->adsc_next = adsl_gather_2;
	adsp_hl_clib->adsc_gai1_out_to_client = adsl_gather_1;

	return TRUE;
}

/*+-------------------------------------------------------------------+*/
/*| Other functions of working structure                              |*/
/*+-------------------------------------------------------------------+*/

char* aligne_pointer(char* achp_pointer)
{
	return (char*)(((long long int) achp_pointer) & (0 - sizeof(void *)));
}
