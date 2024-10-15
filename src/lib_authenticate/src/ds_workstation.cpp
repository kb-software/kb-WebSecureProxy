/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_workstation.h>
#include <ds_xml.h>
#ifdef HL_UNIX
    #include <ctype.h>
#endif

static const dsd_const_string achg_ws_tags[] = {
    "workstation",
    "name",
    "inetaddr",
    "mac-address",
    "port",
    "wait-connect"
};

enum ied_ws_tags {
    ied_ws_tag_wstat,
    ied_ws_tag_name,
    ied_ws_tag_ineta,
    ied_ws_tag_mac,
    ied_ws_tag_port,
    ied_ws_tag_wait
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_init
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper
*/
void ds_workstation::m_init( ds_wsp_helper* ads_wsp_helper )
{    
    adsc_wsp_helper = ads_wsp_helper;
    dsc_name.m_init ( ads_wsp_helper );
    dsc_ineta.m_init( ads_wsp_helper );
} // end of ds_workstation::m_init


/**
 * \ingroup authlib
 *
 * public ds_workstation::m_is_complete
 * check if all values are filled
 *
 * @return bool
*/
bool ds_workstation::m_is_complete()
{
    // initialize some variables:
    int  inl_pos;
    bool bol_non_zero = false;

    if ( dsc_name.m_get_len() < 1 ) {
        return false;
    }

    if ( dsc_ineta.m_get_len() < 1 ) {
        return false;
    }

    if ( uisc_port < 1 ) {
        return false;
    }

    if ( inc_wait < 1 ) {
        return false;
    }
    // [41239]: removed check - a MAC of 0 is now accepted (for case of unspecified MAC)
    /*for ( inl_pos = 0; inl_pos < (int)sizeof(chrc_mac); inl_pos++ ) {
        if ( chrc_mac[inl_pos] != 0 ) {
            bol_non_zero = true;
            break;
        }
    }
    
    return bol_non_zero;
    */

    return true;
} // end of ds_workstation::m_is_complete


/**
 * \ingroup authlib
 *
 * public function ds_workstation.m_reset
*/
void ds_workstation::m_reset()
{
    dsc_name.m_reset();
    dsc_ineta.m_reset();
    memset( chrc_mac, 0, sizeof(chrc_mac) );
    uisc_port = 0;
    inc_wait  = 0;
} // end of ds_workstation::m_reset


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_from_xml
 * fill this class from xml data
 *
 * @param[in]   const char* ach_xml         pointer to xml
 * @param[in]   int         in_len          length of xml data
 * @return      bool                        true = success
*/
bool ds_workstation::m_from_xml( const char* ach_xml, int in_len )
{
    // initialize some variables:
    ds_xml          dsl_parser;             // xml parser class
    dsd_xml_tag*    adsl_pnode;             // first tag

    //-------------------------------------------
    // init xml parser:
    //-------------------------------------------
    dsl_parser.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // parse the data and check name of tag:
    //-------------------------------------------
    adsl_pnode = dsl_parser.m_from_xml( (char*)ach_xml, in_len );
    if ( adsl_pnode == NULL ) {
        return false;
    }
    return m_from_xml( adsl_pnode );
} // end of ds_workstation::m_from_xml


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_from_xml
 * fill this class from xml node
 *
 * @param[in]   dsd_xml_tag* ads_pnode      xml parent node
 * @return      bool                        true = success
*/
bool ds_workstation::m_from_xml( dsd_xml_tag* ads_pnode )
{
    // initialize some variables:
    ds_xml          dsl_xml;                // xml class
    const char*     achl_ineta;             // ineta
    int             inl_len_ineta;          // length of ineta
    dsd_unicode_string dsl_name;            // name
    const char*     achl_mac;               // mac address
    int             inl_len_mac;            // length of mac
    int             inl_port;               // port
    int             inl_wait;               // wait

    //-------------------------------------------
    // init xml class:
    //-------------------------------------------
    dsl_xml.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // check name of tag:
    //-------------------------------------------
    dsl_xml.m_get_node_name( ads_pnode, (const char**) &(dsl_name.ac_str), &(dsl_name.imc_len_str) );
    dsl_name.iec_chs_str = ied_chs_utf_8;
    if ( !achg_ws_tags[ied_ws_tag_wstat].m_equals(dsl_name) ) {
        return false;
    }

    //-------------------------------------------
    // get recommended values:
    //-------------------------------------------
    dsl_xml.m_get_value( ads_pnode,
                         achg_ws_tags[ied_ws_tag_name],
                         (const char**) &(dsl_name.ac_str), &(dsl_name.imc_len_str) );
    dsl_name.iec_chs_str = ied_chs_xml_utf_8;
    dsl_xml.m_get_value( ads_pnode,
                         achg_ws_tags[ied_ws_tag_ineta],
                         &achl_ineta, &inl_len_ineta );
    dsl_xml.m_get_value( ads_pnode,
                         achg_ws_tags[ied_ws_tag_mac],
                         &achl_mac, &inl_len_mac );    
    inl_port = dsl_xml.m_read_int( ads_pnode,
                                   achg_ws_tags[ied_ws_tag_port],
                                   3389 );
    inl_wait = dsl_xml.m_read_int( ads_pnode,
                                   achg_ws_tags[ied_ws_tag_wait],
                                   180 );
    if (    dsl_name.ac_str  == NULL || dsl_name.imc_len_str < 1
         || achl_ineta == NULL || inl_len_ineta < 1
         || achl_mac   == NULL || inl_len_mac   < 1
         || inl_port    < 0    || inl_port      > 65535
         || inl_wait    < 1                             ) {
        return false;
    }

    //-------------------------------------------
    // convert mac:
    //-------------------------------------------
    if ( m_string_to_mac( achl_mac, inl_len_mac, chrc_mac ) == false ) {
        return false;
    }

    //-------------------------------------------
    // save port:
    //-------------------------------------------
    uisc_port = (unsigned short)inl_port;

    //-------------------------------------------
    // save wait:
    //-------------------------------------------
    inc_wait = inl_wait;

    //-------------------------------------------
    // save name and ineta:
    //-------------------------------------------
    dsc_name.m_set ( dsl_name );
    dsc_ineta.m_set( achl_ineta, inl_len_ineta );
    return true;
} // end of ds_workstation::m_from_xml


/**
 * \ingroup authlib
 *
 * function ds_workstation::m_to_xml
 * create xml from class content
 *
 * @param[in/out]   ds_hstring* ads_xml     outbut buffer
 * @return          bool                    true = success
*/
bool ds_workstation::m_to_xml( ds_hstring* ads_xml ) const
{
    //-------------------------------------------
    // check saved data:
    //-------------------------------------------
    if (    dsc_name.m_get_len()  < 1
         || dsc_ineta.m_get_len() < 1 ) {
        return false;
    }

    //-------------------------------------------
    // write the data:
    //-------------------------------------------
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_wstat]);
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_name]);
    ads_xml->m_write_xml_text(dsc_name.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_name]);
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_ineta]);
    ads_xml->m_write_xml_text(dsc_ineta.m_const_str());
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_ineta]);
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_mac]);
    ads_xml->m_writef( "%02x:%02x:%02x:%02x:%02x:%02x", 
                       chrc_mac[0], chrc_mac[1], chrc_mac[2],
                       chrc_mac[3], chrc_mac[4], chrc_mac[5] );
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_mac]);
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_port]);
    ads_xml->m_write_int(uisc_port);
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_port]);
    ads_xml->m_write_xml_open_tag(achg_ws_tags[ied_ws_tag_wait]);
    ads_xml->m_write_int(inc_wait);
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_wait]);
    ads_xml->m_write_xml_close_tag(achg_ws_tags[ied_ws_tag_wstat]);
    return true;
} // end of ds_workstation::m_to_xml


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_name
 *
 * @param[in]   char**  aach_name
 * @param[in]   int*    ain_len
 * @return      bool
*/
bool ds_workstation::m_get_name( const char** aach_name,  int* ain_len ) const
{
    *aach_name = dsc_name.m_get_ptr();
    *ain_len   = dsc_name.m_get_len();
    return ( *ain_len > 0 );
} // end of ds_workstation::m_get_name


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_ineta
 *
 * @param[in]   char**  aach_ineta
 * @param[in]   int*    ain_len
 * @return      bool
*/
bool ds_workstation::m_get_ineta( const char** aach_ineta, int* ain_len ) const
{
    *aach_ineta = dsc_ineta.m_get_ptr();
    *ain_len    = dsc_ineta.m_get_len();
    return ( *ain_len > 0 );
} // end of ds_workstation::m_get_ineta


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_mac
 *
 * @return      unsigned char*
*/
const unsigned char* ds_workstation::m_get_mac() const
{
    return &chrc_mac[0];
} // end of ds_workstation::m_get_mac


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_mac
 *
 * @param[in]   unsigned char[6]
*/
void ds_workstation::m_get_mac( unsigned char chr_mac[6] ) const
{
    memcpy( chr_mac, chrc_mac, 6 );
} // end of ds_workstation::m_get_mac


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_write_mac
 *
 * @param[in/out]   ds_hstring* ads_out
*/
void ds_workstation::m_write_mac( ds_hstring* ads_out )
{
    ads_out->m_writef( "%02x:%02x:%02x:%02x:%02x:%02x",
                       chrc_mac[0], chrc_mac[1],
                       chrc_mac[2], chrc_mac[3],
                       chrc_mac[4], chrc_mac[5] );
} // end of ds_workstation::m_write_mac


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_port
 *
 * @return unsigned short
*/
unsigned short ds_workstation::m_get_port() const
{
    return uisc_port;
} // end of ds_workstation::m_get_port


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_get_wait
 *
 * @return int
*/
int ds_workstation::m_get_wait() const
{
    return inc_wait;
} // end of ds_workstation::m_get_wait


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_wait
 *
 * @param[in]   int in_wait
*/
void ds_workstation::m_set_wait( int in_wait )
{
    inc_wait = in_wait;
} // end of ds_workstation::m_set_wait


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_name
 *
 * @param[in]   const char* ach_name
 * @param[in]   int         in_len
*/
void ds_workstation::m_set_name( const char* ach_name, int in_len )
{
    dsc_name.m_set( ach_name, in_len );
} // end of ds_workstation::m_set_name


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_ineta
 *
 * @param[in]   const char* ach_ineta
 * @param[in]   int         in_len
*/
void ds_workstation::m_set_ineta( const char* ach_ineta, int in_len )
{
    dsc_ineta.m_set( ach_ineta, in_len );
} // end of ds_workstation::m_set_ineta


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_mac
 *
 * @param[in]   unsigned char chr_mac[6]
*/
void ds_workstation::m_set_mac( unsigned char chr_mac[6] )
{
    memcpy( chrc_mac, chr_mac, 6 );
} // end of ds_workstation::m_set_mac


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_mac
 *
 * @param[in]   const char* ach_mac
 * @param[in]   int         in_len
 * return       bool
*/
bool ds_workstation::m_set_mac( const char* ach_mac, int in_len )
{
    return m_string_to_mac( ach_mac, in_len, chrc_mac );
} // end of ds_workstation::m_set_mac


/**
 * \ingroup authlib
 *
 * public function ds_workstation::m_set_port
 *
 * @param[in]   int     in_port
 * @return      bool
*/
bool ds_workstation::m_set_port( int in_port )
{
    if ( in_port > -1 && in_port < 65535 ) {
        uisc_port = (unsigned short)in_port;
        return true;
    }
    return false;
} // end of ds_workstation::m_set_port

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * private function ds_workstation::m_string_to_mac
 * convert given string to mac address byte array
 *
 * @param[in]   const char*   ach_str           pointer to string
 * @param[in]   int           in_len            length of string
 * @param[out]  unsigned char chr_mac[6]        output mac address
 * @return      bool                            true = success
*/
bool ds_workstation::m_string_to_mac( const char* ach_str, int in_len,
                                      unsigned char chr_mac[6] )
{
    // initialize some variables:
    int           inl_count;
    int           inl_pos = 0;
    char          chl_sign;
    unsigned int  uinl_num;
    unsigned char chr_res[6];           // for holding unfinished result

    for ( inl_count = 0; inl_count < 6; inl_count++ )               // writing values into result for case there is something wrong with incoming data
        chr_mac[inl_count] = 0;

    if(in_len == 1 && ach_str[0] == '0')                            // one zero means no mac was submitted and all zero in chr_mac is a value that represents this
        return true;

    if(!(in_len == 17 || in_len == 14))                             // mac address should be 17 chars long (for cisco 14)
        return false;

    for (inl_count = 0; inl_count < in_len && inl_pos < 6 ; inl_count++)
    {
        chl_sign = (char)tolower( ach_str[inl_count] );

        if( chl_sign == ':' || chl_sign == '.' || chl_sign == '-' )                       // separator
            continue;

        if (    (chl_sign < '0' || chl_sign > '9')
             && (chl_sign < 'a' || chl_sign > 'f') )                                      // wrong char
            return false;

        uinl_num = isdigit(chl_sign) ? (chl_sign - '0') : (chl_sign - 'a' + 10);          // first convert

        inl_count++;                                                                      // next char

        if(inl_count >= in_len)
            return false;

        chl_sign = (char)tolower( ach_str[inl_count] );                                   

        if (    (chl_sign < '0' || chl_sign > '9')
             && (chl_sign < 'a' || chl_sign > 'f') )                                      // wrong char
            return false;

        uinl_num <<= 4;
        uinl_num += isdigit(chl_sign) ? (chl_sign - '0') : (chl_sign - 'a' + 10);        // second convert

        chr_res[inl_pos] = (unsigned char)uinl_num;
        inl_pos++;


    }

	if(inl_pos != 6)
		return false;

    // only if conversion successful, copy chr_res to output parameter chr_mac (otherwise it stays all 0)
    memcpy( chr_mac, chr_res, 6 );

    return true;
} // end of ds_wprkstation::m_string_to_mac
