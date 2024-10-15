#if 0
1. Client packets:
==================
    1.1 Start of Communication:
    ===========================

        +---+---+---- ... ----+---+---- ... ----+---+ ... +---- ... ----+---+---+---+---- .... ----+
        | 5 | 0 | protocol    | 0 | key = value | 0 |     | key = value | 0 | 0 |len| methods      |
        +---+---+---- ... ----+---+---- ... ----+---+ ... +---- ... ----+---+---+---+---- .... ----+
          1   1   variable      1   variable      1         variable      1   1   1   len

        0x05:
            socks5 protocol

        0x00:
            In org sock5, 0 means no authentication supported, KB: "this would make no sense".
            In the HOB solution, we want to send the protocol of the client, but this is not
            part of the socks protocol.
            So for the server to differentiate, the clients send a zero for the number of auth methods.

        protocol:
            The name of the protocol of the client, utf8.
            Zero terminated.

        key=value:
            There might be any number of zero-terminated strings.
            The sequence is ended by an additional byte zero.
            Right now, there are 4 strings supported:
                language=value
                userid=value
                password=value
                server=value

        len:
            The number of authentication methods (1 byte).

        methods:
            len number off methods.
            No Authentication:  0x00    MJ: "why does no auth make sense now?"
            Authentication:     0x83
            Display Servers:    0x84

    1.2. Do Authentication:
    =======================

        +---+----+---+-------------+---+--------------+---+-------------+
        | 5 | 83 | N | first input | M | second input | L | third input |
        +---+----+---+-------------+---+--------------+---+-------------+
          1    1   1       N         1        M         1        L

        0x05:
            socks5 protocol

        0x83:
            do authentication

        N:
            length of first input field (NHASN)

        first input:
            first input field (depending on requested INPUT and OUTPUT, see server) UTF8

        M:
            length of second input field (NHASN)

        second input:
            second input field (depending on requested INPUT and OUTPUT, see server) UTF8

        // new in version 2 (14 Feb 2011)
        L:
            length of third input field (NHASN)
                
        third input:
            third input field (depending on requested INPUT and OUTPUT, see server) UTF8

        If not input field is requested by the Status of Input and Output (see server),
        no input is possible and nothing can be send.
        The number of input fields, depends on the Status of Input and Output (see server).

    1.3. Select Server:
    ===================

        +---+----+----+-------- ...
        | 5 | 84 | XX | ...        
        +---+----+----+-------- ...
          1    1    1   variable

        0x05:
            socks5 protocol

        0x84:
            request display server

        XX:
            Status of Input and Output
                0x80:   input follows

        If input follows, is is given by
        length (NHASN)
        text (UTF8)



2. Server packets:
==================
    2.1 Request Authentication:
    ===========================

        +---+----+----+-------- ...
        | 5 | 83 | XX | ...        
        +---+----+----+-------- ...
          1    1    1   variable

        0x05:
            socks5 protocol

        0x83:
            request authentication

        XX:
            Status of Input and Output
                0x80:   Input of userid required
                0x40:   Input of password required
                0x08:   field with userid follows
                0x04:   field with text follows
                // new in version 2 (14 Feb 2011)
                0x02:   second state field follows
                0x01:   abnormal end
            The Status is bit-wise ored.
            Text field are added with length (NHASN) and text in UTF-8

        // new in version 2 (14 Feb 2011)
        XX: optional second state field (only if previous is 0x02!)
            --------
            Status of Input and Output
                0x80:   Password may be changed
                0x40:   Password needs to be changed
                


    2.1 Display Server/Connection state:
    ====================================

        +---+----+----+-------- ...
        | 5 | 84 | XX | ...        
        +---+----+----+-------- ...
          1    1    1   variable

        0x05:
            socks5 protocol

        0x84:
            display server

        XX:
            Status of Input and Output
                0x80:   connection successfull
                0x40:   connection failed
                0x20:   do loadbalancing
                0x10:   wait for server to connect, time in NHASN follows
                0x08:   message follows
                0x04:   server list follows; last server name has length 0;
                        each entry: length (NHASN), name (UTF8)
                0x02:   Input of server name required
                0x01:   abnormal end
            The Status is bit-wise ored.
#endif

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_ldap.h>
#include <types_defines.h>
#ifndef HL_UNIX
    #include <windows.h>
#endif
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <rdvpn_globals.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include "ds_wspat.h"
#include <hob-libwspat.h>
#include "hobwspat.h"
#include "at_resources.h"
#include <ds_workstation.h>
#include <ds_hvector.h>

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
// protocol socks5:
#define AT_PROTO               (char)0x05  // socks5 protocol

// server protocol:
#define AT_PROTO_REQ_AUTH      (char)0x83  // request authentication
#define AT_PROTO_SEL_SERVER    (char)0x84  // select server
#define AT_PROTO_REQ_USERID    (char)0x80  // input of userid required
#define AT_PROTO_REQ_PWD       (char)0x40  // input of password required
#define AT_PROTO_FLD_USERID    (char)0x08  // field with userid follows
#define AT_PROTO_FLD_TEXT      (char)0x04  // field with text follows
#define AT_PROTO_SECOND        (char)0x02  // second state field follows
#define AT_PROTO_ABEND         (char)0x01  // abnormal end
#define AT_PROTO_CON_SUC       (char)0x80  // connection sucessfull
#define AT_PROTO_CON_FAILED    (char)0x40  // connection failed
#define AT_PROTO_LOADBAL       (char)0x20  // do loadbalancing
#define AT_PROTO_WAIT          (char)0x10  // wait for server to connect
#define AT_PROTO_MESSAGE       (char)0x08  // message follows
#define AT_PROTO_SERVERLIST    (char)0x04  // server list follows
#define AT_PROTO_REQ_SERVER    (char)0x02  // input of server name required

// second state fields (server):
#define AT_PROTO_PWD_MAY_CHANGED  (char)0x80 // password may be changed
#define AT_PROTO_PWD_MUST_CHANGED (char)0x40 // password must be changed

// client protocol:
#define AT_PROTO_START         (char)0x00  // start sign for protocol
#define AT_PROTO_DO_AUTH       (char)0x83  // do authentication
#define AT_PROTO_DISP_SERVER   (char)0x84  // display server
#define AT_PROTO_INPUT_FOLLOW  (char)0x80  // input follows

// methods from client
#define AT_METHOD_NO_AUTH      (char)0x00  // method no authentication
#define AT_METHOD_AUTH         (char)0x83  // method authentication
#define AT_METHOD_DIS_SERVER   (char)0x84  // method display server

// returns for parsing methods
#define AT_PACKET_READY        0
#define AT_PACKET_NOT_READY    1
#define AT_PACKET_ERROR        2

// m_request_auth message types
#define AT_MSG_DEF             0
#define AT_MSG_AUTH_FAILED     1
#define AT_MSG_KICK_OUT        2
#define AT_MSG_NO_ROLE         3
#define AT_MSG_CHANGE_PWD      4
#define AT_MSG_SERVER_ENTRY_NOT_FOUND  5
#define AT_MSG_CONNECT_FAILED  6

// DesktopOnDemand delimiter:
#define AT_DOD_DELIMITER ": "
#define AT_PROTO_LOGOFF  "HOB-LOGOFF"

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
// allowed keywords: (compare to ied_wspat_keyword in header file)
static const dsd_const_string achr_wspat_keywords[] = {
    "language",
    "userid",
    "password",
    "server"
};

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_wspat::ds_wspat()
{
    adsc_wsp_helper   = NULL;
    av_storage        = NULL;
    adsc_config       = NULL;
    adsc_connect      = NULL;
    avc_usergroup     = NULL;
    avc_userentry     = NULL; 
    uinc_auth         = 0;
    boc_kick_out      = false;
    boc_expires       = false;
    inc_processed     = -1;
    inc_offset        =  0;
    ienc_gstate       = ied_wspat_firstbyte;
    ienc_language     = ied_wspat_lang_en;
    dsc_fpacket.ien_keyword       = ied_wspat_key_unknown;
    dsc_fpacket.in_meth_len       = 0;
    dsc_fpacket.bo_meth_no_auth   = false;
    dsc_fpacket.bo_meth_auth      = false;
    dsc_fpacket.bo_meth_disp_serv = false;
    dsc_apacket.in_length         = 0;
    dsc_spacket.in_length         = 0;

#if SM_USE_CERT_AUTH
	this->iec_certificate_auth = iec_cert_auth_result_not_checked;
	this->adsc_cert_auth_entry = NULL;
#endif
} // end of ds_wspat::ds_wspat


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_wspat::~ds_wspat()
{
    if ( adsc_connect != NULL ) {
        adsc_wsp_helper->m_cb_free_memory( adsc_connect );
        adsc_connect = NULL;
    }
} // end of ds_wspat::~ds_wspat


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_wspat::m_init
 * initialize helper class and other needed variables
 *
 * @param[in]   ds_wsp_helper*  adsp_wsp_helper
*/
void ds_wspat::m_init( ds_wsp_helper* adsp_wsp_helper )
{
    adsc_wsp_helper = adsp_wsp_helper;

    dsc_ucma.m_init    ( adsp_wsp_helper );
    dsc_userid.m_init  ( adsp_wsp_helper );
    dsc_password.m_init( adsp_wsp_helper );
    dsc_new_pwd.m_init ( adsp_wsp_helper );
    dsc_save_pwd.m_init( adsp_wsp_helper );
    dsc_server.m_init  ( adsp_wsp_helper );
    dsc_proto.m_init   ( adsp_wsp_helper );
    
    dsc_rad_state.m_init( adsp_wsp_helper );
    dsc_rad_mess.m_init ( adsp_wsp_helper );

    adsc_config = (dsd_wspat_config*)adsc_wsp_helper->m_get_config();
} // end of ds_wspat::m_init


/**
 * function ds_wspat::m_run
 * working function in normal state
*/
void ds_wspat::m_run()
{
    // initialize some variables:
    dsd_wspat3_1   *adsl_auth;              // calling structue from wsp
    dsd_gather_i_1 *adsl_input;             // input gather data

    //----------------------------------------------------
    // get incoming data and wsp class:
    //----------------------------------------------------
    adsl_auth = (dsd_wspat3_1*)adsc_wsp_helper->m_get_structure();

    //----------------------------------------------------
    // log incoming data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_input();

    //----------------------------------------------------
    // handle data:
    //----------------------------------------------------
    adsl_input = adsc_wsp_helper->m_get_input();
    if ( adsl_input != NULL ) {
        adsl_auth->iec_at_return = (ied_at_return)m_handle_data( adsl_input );
    } else {
        adsl_auth->iec_at_return = ied_atr_input; // waiting for more input
    }

    //----------------------------------------------------
    // log outgoing data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_output();
    
    return;
} // end of ds_wspat::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/

/**
 * function ds_wspat::m_handle_data
 * handle incoming data
 * we will return elements from ied_at_return
 *
 * @param[in]   dsd_gather_i_1* ads_input       input data
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_handle_data( dsd_gather_i_1* ads_input )
{
    // initialize some variables:
    int        in_length    =  0;               // length of data
    char*      ach_byte     =  NULL;            // current byte
    int        in_ret;                         // return value for some function calls

    //----------------------------------------------------
    // get total length of input data:
    //----------------------------------------------------
    in_length = adsc_wsp_helper->m_get_gather_len( ads_input );

    //----------------------------------------------------
    // loop through the data:
    //----------------------------------------------------
    for ( ; inc_offset < in_length; inc_offset++ ) {
        ach_byte = adsc_wsp_helper->m_get_end_ptr( ads_input, inc_offset );

        switch ( ienc_gstate ) {
            /*
                first byte must be 0x05 (otherwise it is wrong protocol)
            */
            case ied_wspat_firstbyte:
                if ( *ach_byte != AT_PROTO ) {
                    //ads_wsp_helper->m_logf( ied_sdh_log_info, AT_INFO(3),
                    //                        "wrong protocol found" );
                    return (int)ied_atr_other_prot;
                }
                ienc_gstate = ied_wspat_secondbyte;
                break;

            /*
               second byte will in which state of communication we are
                    0x00 start of communication
                    0x83 do authentication
                    0x84 select server
            */
            case ied_wspat_secondbyte:
                switch ( *ach_byte ) {
                    case AT_PROTO_START:
                        // we will parse first packet:
                        ienc_gstate = ied_wspat_proto_first;

                        // set start state for first packet:
                        dsc_fpacket.ien_state = ied_wspat_first_protocol;
                        break;

                    case AT_PROTO_DO_AUTH:
                        // we will parse authentication packet:
                        ienc_gstate = ied_wspat_proto_auth;

                        // set start state for authentication packet:
                        dsc_apacket.ien_state = ied_wspat_auth_len;
                        break;
                    case AT_PROTO_DISP_SERVER:
                        // we will parse display server packet:
                        ienc_gstate = ied_wspat_disp_server;

                        // set start state for server packet:
                        dsc_spacket.ien_state = ied_wspat_srv_state;
                        break;
                    default:
                        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                                "HWSPATW007W unknown second byte found" );
                        return (int)ied_atr_other_prot;
                }
                break;

            /*
                read first packet from client:
            */
            case ied_wspat_proto_first:
                in_ret = m_parse_fpacket( ads_input, in_length );
                if ( in_ret == AT_PACKET_ERROR ) {
                    return (int)ied_atr_failed;
                }
                if ( in_ret == AT_PACKET_READY ) {
                    ienc_gstate = ied_wspat_response;
                }
                break;

            /*
                read authentication request packet:
            */
            case ied_wspat_proto_auth:
                in_ret = m_parse_authpacket( ads_input, in_length );
                if ( in_ret == AT_PACKET_ERROR ) {
                    return (int)ied_atr_failed;
                }
                if ( in_ret == AT_PACKET_READY ) {
                    ienc_gstate = ied_wspat_response;
                }
                break;

            /*
                parse display server request packet:
            */
            case ied_wspat_disp_server:
                in_ret = m_parse_srvpacket( ads_input, in_length );
                if ( in_ret == AT_PACKET_ERROR ) {
                    return (int)ied_atr_failed;
                }
                if ( in_ret == AT_PACKET_READY ) {
                    ienc_gstate = ied_wspat_response;
                }
                break;

            /*
                a packet is completly read in, but there are still data in input:
            */
            case ied_wspat_response:
                adsc_wsp_helper->m_mark_processed( ads_input, &inc_offset, &in_length );
                ienc_gstate = ied_wspat_firstbyte;
                return m_create_response();

            /*
                unknown state:
            */
            default:
                adsc_wsp_helper->m_log( ied_sdh_log_error,
                                        "HWSPATE006E unknown internal state found" );
                return (int)ied_atr_failed;
        }
    } // end of while

    //----------------------------------------------------
    // mark data as processed:
    //----------------------------------------------------
    if ( inc_processed > -1 ) {
        /*
            we have started to read a packet, but not yet finished
            -> mark until this position, wsp will give us this data once again!
            -> save offset
        */
        adsc_wsp_helper->m_mark_processed( ads_input, &inc_processed, &in_length );
        inc_offset = in_length;
        
        // we are waiting for more input:
        return (int)ied_atr_input;
    } else {
        /*
            this block is completly finished
            -> mark complete block as processed!
            -> set state to firstbyte again
            -> create response
        */
        adsc_wsp_helper->m_mark_processed( ads_input, &inc_offset, &in_length );
        if (    ienc_gstate == ied_wspat_response
             || ienc_gstate == ied_wspat_dod      ) {
            ienc_gstate = ied_wspat_firstbyte;
            return m_create_response();
        } else {
            // we are waiting for more input:
            return (int)ied_atr_input;
        }
    }
} // end of ds_wspat::m_handle_data


/**
 * function ds_wspat::m_parse_fpacket
 * parse first packet from client
 *
 * @param[in]       dsd_gather_i_1* ads_input       incoming data
 * @param[in]       int             in_length       total length of input
 * @return          int                             code:
 *                                                  AT_PACKET_READY     = packet completly parsed
 *                                                  AT_PACKET_NOT_READY = packet not yet complete
 *                                                  AT_PACKET_ERROR     = error whil parsing
*/
int ds_wspat::m_parse_fpacket( dsd_gather_i_1* ads_input, int in_length )
{
    // initialize some variables:
    char*      ach_byte    =  NULL;             // current byte
    char*      ach_rec     =  NULL;             // read a hole string out of gather
    int        in_rec      =  0;                // length of ach_rec
    int        in_read     =  0;                // already read bytes
    bool       bo_ret      =  false;            // return value for some function calls

    //----------------------------------------------------
    // loop through the data:
    //----------------------------------------------------
    for ( ; inc_offset < in_length; inc_offset++ ) {
        ach_byte = adsc_wsp_helper->m_get_end_ptr( ads_input, inc_offset );

        switch ( dsc_fpacket.ien_state ) {
            /*
                read protocol (end sign is 0)
            */
            case ied_wspat_first_protocol:
                // save start position:
                if ( inc_processed == -1 ) {
                    inc_processed = inc_offset;
                    dsc_proto.m_setup( adsc_wsp_helper );
                }
                // search end
                if ( *ach_byte == 0 ) {
                    // check maximal length:
                    if ( adsc_config->in_maxlenproto > 0 ) {
                        if ( inc_offset - inc_processed > adsc_config->in_maxlenproto ) {
                            adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                    "HWSPATE037E protocol is too long" );
							do
							{
								ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
								ads_input = ads_input->adsc_next;
							}while( ads_input != NULL );

                            return AT_PACKET_ERROR;
                        }
                    }

                    // save data:
                    while ( in_read < inc_offset - inc_processed ) {
                        ach_rec = adsc_wsp_helper->m_get_buf( ads_input, inc_processed + in_read,
                                                              inc_offset - (inc_processed + in_read ),
                                                              &in_rec );
                        in_read += in_rec;
                        dsc_proto.m_write( ach_rec, in_rec );
                    }
                    in_read      =  0;         // reset read marker
                    inc_processed = -1;        // reset start position marker

                    // check if we got a known protocol:
                    ienc_proto = adsc_wsp_helper->m_cb_get_protocol_type( dsc_proto.m_get_ptr(),
                                                                          dsc_proto.m_get_len() );

#if hofmants
					// handle response:
					if( ienc_proto == ied_scp_spec )
					{
						// hofmants: get protocols
						//dsd_auth_t      dsl_auth;  // authentication structure
						//avc_userentry = dsl_auth.avc_userentry;
						//avc_usergroup = dsl_auth.avc_usergroup;
						//int inl1;

						//inl1 = adsc_wsp_helper->m_cb_count_servers( NULL, NULL, ienc_proto, dsc_proto.m_get_ptr(), dsc_proto.m_get_len() );
						bo_ret = true;
						if( !bo_ret )
						{
							adsc_wsp_helper->m_log( ied_sdh_log_warning, "HWSPATW008W unknown protocol found" );

							do
							{
								ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
								ads_input = ads_input->adsc_next;
							}
							while( ads_input != NULL );

							return AT_PACKET_ERROR;
						}
					}
#endif

                    // we are expecting keyword/value pairs now:
                    dsc_fpacket.ien_state = ied_wspat_first_keyword;
                }
                break;

            /*
                read keyword (end sign is =)
                hole list of keywords will be ending with an 0
            */
            case ied_wspat_first_keyword:
                // save start position:
                if ( inc_processed == -1 ) {
                    // check if there this is end of keyword/value pairs
                    if ( *ach_byte == 0 ) {
                        dsc_fpacket.ien_state = ied_wspat_first_method_length;
                        break;
                    }
                    inc_processed = inc_offset;
                }
                // search end
                if ( *ach_byte == '=' ) {
                    // compare keyword with our list and get type:
                    dsc_fpacket.ien_keyword = m_get_keytype( ads_input, inc_processed, inc_offset );
                    if ( dsc_fpacket.ien_keyword == ied_wspat_key_unknown ) {
                        adsc_wsp_helper->m_log( ied_sdh_log_warning,
                                                "HWSPATW009W invalid keyword found" );

						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    }
                    inc_processed = -1;              // reset start position marker
                    // we are expecting value now:
                    dsc_fpacket.ien_state = ied_wspat_first_keyvalue;
                }
                break;

            /*
                read keyvalue (end sign is 0)
            */
            case ied_wspat_first_keyvalue:
                // save start position:
                if ( inc_processed == -1 ) {
                    inc_processed = inc_offset;
                }
                // search end
                if ( *ach_byte == 0 ) {
                    bo_ret = m_save_keyvalue( ads_input, inc_processed, inc_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                "HWSPATE007E saving keyword failed" );
						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );
                        
						return AT_PACKET_ERROR;
                    }
                    inc_processed = -1;              // reset start position marker
                    // get next keyword/value pair:
                    dsc_fpacket.ien_state = ied_wspat_first_keyword;
                }
                break;

            /*
                get method length
            */
            case ied_wspat_first_method_length:
                dsc_fpacket.in_meth_len = (unsigned char) *ach_byte;
                if ( dsc_fpacket.in_meth_len < 1 ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE008E invalid method length '%d' found",
                                             dsc_fpacket.in_meth_len );

					do
					{
						ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
						ads_input = ads_input->adsc_next;
					}while( ads_input != NULL );

                    return AT_PACKET_ERROR;
                }
                // read methods:
                dsc_fpacket.ien_state = ied_wspat_first_methods;
                break;

            /*
                read methods itself
            */
            case ied_wspat_first_methods:
                switch ( *ach_byte ) {
                    case AT_METHOD_NO_AUTH:
                        dsc_fpacket.bo_meth_no_auth = true;
                        break;
                    case AT_METHOD_AUTH:
                        dsc_fpacket.bo_meth_auth = true;
                        break;
                    case AT_METHOD_DIS_SERVER:
                        dsc_fpacket.bo_meth_disp_serv = true;
                        break;
                    default:
                        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HWSPATE009E unknown method '0x%x' found",
                                                 *ach_byte );
                        break;
                }
                dsc_fpacket.in_meth_len--;
                if ( dsc_fpacket.in_meth_len < 1 ) {
                    if ( dsc_fpacket.bo_meth_auth == false ) {
                        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                "HWSPATE010E client does not support authentication" );

						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    }
                    return AT_PACKET_READY;
                }
                break;
        } // end of switch
    } // end of for loop

    return AT_PACKET_NOT_READY;
} // end of ds_wspat::m_parse_fpacket


/**
 * function ds_wspat::m_parse_authpacket
 * parse auth packet from client
 *
 * @param[in]       dsd_gather_i_1* ads_input       incoming data
 * @param[in]       int             in_length       total length of input
 * @param[in/out]   int*            ain_pos         position of processed data
 * @return          int                             code:
 *                                                  AT_PACKET_READY     = packet completly parsed
 *                                                  AT_PACKET_NOT_READY = packet not yet complete
 *                                                  AT_PACKET_ERROR     = error whil parsing
*/
int ds_wspat::m_parse_authpacket( dsd_gather_i_1* ads_input, int in_length )
{
    // initialize some variables:
    char*      ach_byte    =  NULL;             // current byte
    bool       bo_ret      =  false;            // return value for some function calls

    //----------------------------------------------------
    // loop through the data:
    //----------------------------------------------------
    for ( ; inc_offset < in_length; inc_offset++ ) {
        ach_byte = adsc_wsp_helper->m_get_end_ptr( ads_input, inc_offset );

        switch ( dsc_apacket.ien_state ) {
            /*
                read length of input field in NHASN
            */
            case ied_wspat_auth_len:
                dsc_apacket.in_length <<= 7;
                dsc_apacket.in_length |= (unsigned char)(*ach_byte & 0X7F);
                // check for buffer overflow:
                if ( dsc_apacket.in_length < 0 ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE103E invalid input length '%d' found",
                                             dsc_apacket.in_length );
					do
					{
						ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
						ads_input = ads_input->adsc_next;
					}while( ads_input != NULL );

                    return AT_PACKET_ERROR;
                }

                // check if "more" byte is set:
                if ( !(*ach_byte & 0X80) ) {
                    if ( dsc_apacket.in_length < 0 ) {
                        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HWSPATE011E invalid input length '%d' found",
                                                 dsc_apacket.in_length );

						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    } else if ( dsc_apacket.in_length == 0 ) {
                        /*
                            this might be an empty new password
                        */
                        return AT_PACKET_READY;
                    }
                    // read input field:
                    dsc_apacket.ien_state = ied_wspat_auth_input;
                }
                break;

            /*
                read input field
            */
            case ied_wspat_auth_input:
                // save start position:
                if ( inc_processed == -1 ) {
                    inc_processed = inc_offset;
                }
                // is end reached?
                if ( inc_offset - inc_processed == dsc_apacket.in_length ) {
                    bo_ret = m_save_auth_input( ads_input, inc_processed, inc_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                "HWSPATE012E saving input field failed" );
						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    }
                    // reset start position marker:
                    inc_processed = -1;             
                    // we must reduce in_offset, to read length in next loop run:
                    inc_offset--;
                    // reset field length:
                    dsc_apacket.in_length = 0;
                    // read next length field:
                    dsc_apacket.ien_state = ied_wspat_auth_len;
                }
                break;

        } // end of switch
    } // end of for loop

    // read also last packet:
    if ( inc_offset - inc_processed == dsc_apacket.in_length ) {
        bo_ret = m_save_auth_input( ads_input, inc_processed, inc_offset );
        if ( bo_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_error,
                                    "HWSPATE013E saving input field failed" );
			do
			{
				ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
				ads_input = ads_input->adsc_next;
			}while( ads_input != NULL );

            return AT_PACKET_ERROR;
        }
        // reset start position marker:
        inc_processed = -1;         
        // we must reduce in_offset:
        inc_offset--;
        // reset field length:
        dsc_apacket.in_length = 0;
        // read next length field:
        dsc_apacket.ien_state = ied_wspat_auth_len;
    }

    // are we ready:
    if ( dsc_userid.m_get_len() < 1 || dsc_password.m_get_len() < 1 ) {
        return AT_PACKET_NOT_READY;
    }
    return AT_PACKET_READY;
} // end of ds_wspat::m_parse_authpacket


/**
 * function ds_wspat::m_parse_srvpacket
 * parse auth packet from client
 *
 * @param[in]       dsd_gather_i_1* ads_input       incoming data
 * @param[in]       int             in_length       total length of input
 * @return          int                             code:
 *                                                  AT_PACKET_READY     = packet completly parsed
 *                                                  AT_PACKET_NOT_READY = packet not yet complete
 *                                                  AT_PACKET_ERROR     = error whil parsing
*/
int ds_wspat::m_parse_srvpacket( dsd_gather_i_1* ads_input, int in_length )
{
    // initialize some variables:
    char*      ach_byte    =  NULL;             // current byte
    bool       bo_ret      =  false;            // return value for some function calls

    //----------------------------------------------------
    // loop through the data:
    //----------------------------------------------------
    for ( ; inc_offset < in_length; inc_offset++ ) {
        ach_byte = adsc_wsp_helper->m_get_end_ptr( ads_input, inc_offset );

        switch ( dsc_spacket.ien_state ) {
            /*
                read state field:
            */
            case ied_wspat_srv_state:
                if ( *ach_byte != AT_PROTO_INPUT_FOLLOW ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE014E invalid server status '0x%x found",
                                             *ach_byte );
					do
					{
						ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
						ads_input = ads_input->adsc_next;
					}while( ads_input != NULL );

                    return AT_PACKET_ERROR;
                }
                dsc_spacket.ien_state = ied_wspat_srv_len;
                break;

            /*
                read length of input field in NHASN
            */
            case ied_wspat_srv_len:
                dsc_spacket.in_length <<= 7;
                dsc_spacket.in_length |= (unsigned char)(*ach_byte & 0X7F);
                // check if "more" byte is set:
                if ( !(*ach_byte & 0X80) ) {
                    if ( dsc_spacket.in_length < 1 ) {
                        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                                 "HWSPATE015E invalid server length '%d' found",
                                                 dsc_spacket.in_length );
						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    }

                    // check maximal length:
                    if ( adsc_config->in_maxlenserver > 0 ) {
                        if ( dsc_spacket.in_length > adsc_config->in_maxlenserver ) {
                            adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                    "HWSPATE031E protocol is too long" );
							do
							{
								ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
								ads_input = ads_input->adsc_next;
							}while( ads_input != NULL );

                            return AT_PACKET_ERROR;
                        }
                    }

                    // read input field:
                    dsc_spacket.ien_state = ied_wspat_srv_srv;
                }
                break;

            /*
                read input field
            */
            case ied_wspat_srv_srv:
                // save start position:
                if ( inc_processed == -1 ) {
                    inc_processed = inc_offset;
                }
                // is end reached?
                if ( inc_offset - inc_processed == dsc_spacket.in_length ) {
                    bo_ret = m_save_server( ads_input, inc_processed, inc_offset );
                    if ( bo_ret == false ) {
                        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                                "HWSPATE016E saving server field failed" );
						do
						{
							ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
							ads_input = ads_input->adsc_next;
						}while( ads_input != NULL );

                        return AT_PACKET_ERROR;
                    }
                    // reset start position marker:
                    inc_processed = -1;
                    // we must reduce in_offset:
                    inc_offset--;
                    // we are ready (only one input field is allowed)
                    return AT_PACKET_READY;
                }
                break;

        } // end of switch
    } // end of for loop

    // read also last packet:
    if ( inc_offset - inc_processed == dsc_spacket.in_length ) {
        bo_ret = m_save_server( ads_input, inc_processed, inc_offset );
        if ( bo_ret == false ) {
            adsc_wsp_helper->m_log( ied_sdh_log_error,
                                    "HWSPATE017E saving server field failed" );
			do
			{
				ads_input->achc_ginp_cur = ads_input->achc_ginp_end;
				ads_input = ads_input->adsc_next;
			}while( ads_input != NULL );

            return AT_PACKET_ERROR;
        }
        // reset start position marker:
        inc_processed = -1;
        // we must reduce in_offset:
        inc_offset--;
        // we are ready (only one input field is allowed)
        return AT_PACKET_READY;
    }

    return AT_PACKET_NOT_READY;
} // end of ds_wspat::m_parse_srvpacket


/**
 * function ds_wspat::m_create_response
 * create a response depending on the saved data
 *
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_create_response()
{
    // initialize some variables:
    int             inl_server     = 0;         // number of server entries
    char            chrl_buffer[512];           // temp buffer for server name    
    int             inl_len_out;                // length of server name
    ds_authenticate dsl_ident( adsc_wsp_helper );// authentication class
    dsd_auth_t      dsl_auth;                   // authentication structure
    ds_hstring      dsl_tmp_user;               // user name
    ds_hstring      dsl_tmp_domain;             // user domain
    const char*     achl_userid;                // userid working pointer
    int             inl_len_userid;             // length of userid
    int             inl_offset;                 // offset in userid
    bool            bol_ret;                    // return code for several func calls
    int             inl_function;               // function of server entry
    int             inl_wstats;                 // workstations for user
    char            chrl_cma[D_MAXCMA_NAME];    // buffer for cma name
    int             inl_clen;                   // length of cma nam

    dsc_ucma.m_init  ( adsc_wsp_helper );
    dsl_tmp_user.m_init  ( adsc_wsp_helper );
    dsl_tmp_domain.m_init( adsc_wsp_helper );

	//-------------------------------------------
    // check if protocol is defined:
    //-------------------------------------------
    if ( ienc_proto == ied_scp_undef ) {
        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                "HWSPATE030E no protocol defined" );
        return ied_atr_failed;
    }

#if SM_USE_CERT_AUTH
	if(this->iec_certificate_auth == iec_cert_auth_result_not_checked) {
		dsd_auth_t dsl_cert_auth;
		memset( &dsl_cert_auth, 0, sizeof(dsd_auth_t) );
		dsl_ident.m_check_certificate_auth(adsc_wsp_helper->m_get_wspat_config(), &dsl_cert_auth);
		this->adsc_cert_auth_entry = dsl_cert_auth.adsc_cert_auth_entry;
		this->iec_certificate_auth = dsl_cert_auth.iec_certificate_auth;
		this->dsc_cert_userid.m_init(adsc_wsp_helper);
		if(dsl_cert_auth.adsc_cert_auth_entry != NULL && dsl_cert_auth.adsc_cert_auth_entry->dsc_user.inc_len > 0) {
			const dsd_utf8_string& dsl_cert_domain = this->adsc_cert_auth_entry->dsc_domain;
			if(dsl_cert_domain.inc_len > 0) {
				this->dsc_cert_userid.m_write(dsd_const_string(dsl_cert_domain.achc_data, dsl_cert_domain.inc_len));
				this->dsc_cert_userid.m_write("\\");
			}
			const dsd_utf8_string& dsl_cert_user = this->adsc_cert_auth_entry->dsc_user;
			this->dsc_cert_userid.m_write(dsd_const_string(dsl_cert_user.achc_data, dsl_cert_user.inc_len));
		}
	}
#endif

	//---------------------------------------
    // get username and userdomain:
    //---------------------------------------
    achl_userid    = dsc_userid.m_get_ptr();
    inl_len_userid = dsc_userid.m_get_len();
    for ( inl_offset = 0; inl_offset < inl_len_userid - 1; inl_offset++ ) {
        if (    achl_userid[inl_offset]   == '\\'
                && achl_userid[inl_offset+1] != '\\' ) {
            dsl_tmp_domain.m_write( achl_userid, inl_offset );
            dsl_tmp_user.m_write ( &achl_userid[inl_offset + 1], 
                                inl_len_userid - inl_offset - 1 );
            break;
        }
    }
    if ( dsl_tmp_user.m_get_len() < 1 ) {
        dsl_tmp_user = dsc_userid;
    }
    dsl_tmp_domain.m_replace( "\\\\", "\\" );
    dsl_tmp_user.m_replace( "\\\\", "\\" );

	dsd_const_string dsl_user = dsl_tmp_user.m_const_str();
	dsd_const_string dsl_password = this->dsc_password.m_const_str();
	dsd_const_string dsl_domain = dsl_tmp_domain.m_const_str();
#if SM_USE_CERT_AUTH
	if(this->adsc_cert_auth_entry != NULL) {
		const dsd_utf8_string& dsl_cert_user = this->adsc_cert_auth_entry->dsc_user;
		dsl_user = dsd_const_string(dsl_cert_user.achc_data, dsl_cert_user.inc_len);
		const dsd_utf8_string& dsl_cert_domain = this->adsc_cert_auth_entry->dsc_domain;
		dsl_domain = dsd_const_string(dsl_cert_domain.achc_data, dsl_cert_domain.inc_len);
#if SM_USE_CERT_AUTH_V2
		// No password given by client?
		if(dsl_password.m_get_len() <= 0) {
			const dsd_utf8_string& dsl_cert_pwd = this->adsc_cert_auth_entry->dsc_password;
			dsl_password = dsd_const_string(dsl_cert_pwd.achc_data, dsl_cert_pwd.inc_len);
		}
#endif
	}
#endif

    //-------------------------------------------
    // check if authentication stuff is given:
    //-------------------------------------------
    if ( (dsl_user.m_get_len()   <= 0 
         || dsl_password.m_get_len() <= 0)
#if SM_USE_CERT_AUTH
		 && this->iec_certificate_auth != iec_cert_auth_result_authenticated
#endif
		 )
	{
		return m_request_auth( AT_MSG_DEF, dsd_const_string::m_null() );
    }

    if (   (uinc_auth & AUTH_SUCCESS) != AUTH_SUCCESS
         || boc_expires               == true         ) {
        
        //---------------------------------------
        // prepare auth structure:
        //---------------------------------------
        memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
        dsl_auth.achc_user             = dsl_user.m_get_ptr();
        dsl_auth.inc_len_user          = dsl_user.m_get_len();
        dsl_auth.achc_domain           = dsl_domain.m_get_ptr();
        dsl_auth.inc_len_domain        = dsl_domain.m_get_len();
        dsl_auth.adsc_state            = &dsc_rad_state;
        dsl_auth.adsc_out_msg          = &dsc_rad_mess;
        dsl_auth.adsc_out_usr          = &dsc_ucma;
        dsl_auth.boc_avoid_compl_check = true;
		dsl_auth.iec_certificate_auth  = this->iec_certificate_auth;
        if ( (uinc_auth & AUTH_CHANGE_PWD) == AUTH_CHANGE_PWD ) {
            /*
                previous call returned change password
                 -> check if client sent new password
                 -> check if old password matches
            */

            if (    dsc_new_pwd.m_get_len() < 1
                 || dsc_save_pwd.m_equals(dsl_password.m_get_ptr(), dsl_password.m_get_len()) == false ) {
                return m_request_auth( AT_MSG_AUTH_FAILED, dsd_const_string::m_null() );
            }
            
            dsl_auth.achc_password     = dsc_new_pwd.m_get_ptr();
            dsl_auth.inc_len_password  = dsc_new_pwd.m_get_len();
            
            dsl_auth.achc_old_pwd      = dsl_password.m_get_ptr();
            dsl_auth.inc_len_old_pwd   = dsl_password.m_get_len();
        } else {
            if ( dsc_new_pwd.m_get_len() > 0 ) {
                dsl_auth.achc_password     = dsc_new_pwd.m_get_ptr();
                dsl_auth.inc_len_password  = dsc_new_pwd.m_get_len();
                
                dsl_auth.achc_old_pwd      = dsl_password.m_get_ptr();
                dsl_auth.inc_len_old_pwd   = dsl_password.m_get_len();
            } else {
                dsl_auth.achc_password     = dsl_password.m_get_ptr();
                dsl_auth.inc_len_password  = dsl_password.m_get_len();
            }
        }

        //---------------------------------------
        // do authentication:
        //---------------------------------------
        if ( boc_expires == true ) {
            if ( dsc_new_pwd.m_get_len() > 0 ) {
                uinc_auth = dsl_ident.m_change_password( &dsl_auth );
            } else {
                // nothing todo
                uinc_auth = AUTH_SUCCESS;
            }
            boc_expires = false;
            dsc_userid.m_reset();
            dsc_password.m_reset();
            dsc_new_pwd.m_reset();
            dsc_save_pwd.m_reset();
        } else if ( adsc_config->ds_public.boc_multiple_login == true ) {
            /*
                user can login multiple times
            */
            uinc_auth = dsl_ident.m_authenticate( &dsl_auth );

            //-----------------------------------
            // password expires?
            //-----------------------------------
            if ( dsl_auth.inc_pw_expires != DEF_DONT_EXPIRE ) {
                // save current password:
                dsc_save_pwd.m_setup( adsc_wsp_helper, dsl_password.m_get_len() );
                dsc_save_pwd.m_write( dsl_password.m_get_ptr(), dsl_password.m_get_len() );
                dsc_password.m_reset();
                boc_expires = true;
                return m_pwd_expires( dsl_auth.inc_pw_expires );
            } else if ( uinc_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER) ) {
                // start a second session:
                uinc_auth = dsl_ident.m_create_user( &dsl_auth );
            }
        } else {
            /*
                user can just login once
            */
            if ( boc_kick_out == true ) {
                // kickout from previous call
                inl_clen = ds_usercma::m_create_name( dsl_auth.achc_user,
                                                      dsl_auth.inc_len_user,
                                                      dsl_auth.achc_domain,
                                                      dsl_auth.inc_len_domain,
                                                      dsd_cma_session_no((unsigned char)1), chrl_cma,
                                                      D_MAXCMA_NAME );
                if ( inl_clen < 1 ) {
                    return m_request_auth( AT_MSG_AUTH_FAILED, dsd_const_string::m_null() );
                }
                bol_ret = ds_usercma::m_exists_user( adsc_wsp_helper,
                                                     chrl_cma, inl_clen );
                if ( bol_ret == true ) {
                    dsl_ident.m_end_session( &dsl_auth );
                }
                boc_kick_out = false;

                // start a second session:
                uinc_auth = dsl_ident.m_create_user( &dsl_auth );
            } else {
                uinc_auth = dsl_ident.m_authenticate( &dsl_auth );

                //-------------------------------
                // password expires?
                //-------------------------------
                if (    (uinc_auth & AUTH_SUCCESS) == AUTH_SUCCESS
                     && dsl_auth.inc_pw_expires    != DEF_DONT_EXPIRE ) {
                    // save current password:
                    dsc_save_pwd.m_setup( adsc_wsp_helper, dsl_password.m_get_len() );
                    dsc_save_pwd.m_write( dsl_password.m_get_ptr(), dsl_password.m_get_len() );
                    dsc_password.m_reset();
                    boc_expires = true;
                    return m_pwd_expires( dsl_auth.inc_pw_expires );
                }
            }
        }
        if ( (uinc_auth & AUTH_FAILED) == AUTH_FAILED ) {
            // authentication failed:
            // -> check if we are in a challange mode:
            if (    (   (uinc_auth & AUTH_METH_RADIUS)     == AUTH_METH_RADIUS
                      ||(uinc_auth & AUTH_METH_DYN_RADIUS) == AUTH_METH_DYN_RADIUS )
                 && (uinc_auth & AUTH_METH_CHALLENGE) == AUTH_METH_CHALLENGE ) {
                dsc_password.m_reset();
                return m_request_challenge();
            }

            // -> check if reason is a second login
            else if ( uinc_auth == (AUTH_FAILED | AUTH_METH_CMA | AUTH_SAME_USER) ) {
                if ( adsc_config->ds_public.boc_multiple_login == false ) {
                    /* single user mode */
                    boc_kick_out = true;
                    return m_request_auth( AT_MSG_KICK_OUT, dsd_const_string::m_null() );
                }
            }

            // -> check if we have found no role
            else if ( (uinc_auth & AUTH_NO_ROLE_POSSIBLE) == AUTH_NO_ROLE_POSSIBLE ) {
                return m_request_auth( AT_MSG_NO_ROLE, dsd_const_string::m_null() );
            } 
            
            // -> check if we have to change password
            else if ( (uinc_auth & AUTH_CHANGE_PWD) == AUTH_CHANGE_PWD ) {
                // save current password:
                dsc_save_pwd.m_setup( adsc_wsp_helper, dsl_password.m_get_len() );
                dsc_save_pwd.m_write( dsl_password.m_get_ptr(), dsl_password.m_get_len() );
                dsc_password.m_reset();
                // ask again for new password:
                return m_request_auth( AT_MSG_CHANGE_PWD, dsd_const_string::m_null() );
            }

            // ask again for authentication:
            return m_request_auth( AT_MSG_AUTH_FAILED, dsd_const_string::m_null() );
        }

        //---------------------------------------
        // get userentry and usergroup, overwrite
        // our saved password with session ticket
        // and clear radius messages
        //---------------------------------------
        avc_userentry = dsl_auth.avc_userentry;
        avc_usergroup = dsl_auth.avc_usergroup;
        dsc_password  = dsc_ucma.m_get_sticket();
        dsc_rad_state.m_reset();
        dsc_rad_mess.m_reset();
    }

    if (    ienc_proto == ied_scp_spec
         && dsc_proto.m_equals(AT_PROTO_LOGOFF) ) {
        memset( &dsl_auth, 0, sizeof(dsd_auth_t) );
        dsl_auth.achc_user             = dsl_user.m_get_ptr();
        dsl_auth.inc_len_user          = dsl_user.m_get_len();
        dsl_auth.achc_domain           = dsl_domain.m_get_ptr();
        dsl_auth.inc_len_domain        = dsl_domain.m_get_len();
        dsl_auth.achc_password         = dsl_password.m_get_ptr();
        dsl_auth.inc_len_password      = dsl_password.m_get_len();
        dsl_auth.adsc_out_usr          = &dsc_ucma;
        dsl_ident.m_end_session( &dsl_auth );
        return (int)ied_atr_failed;
    }

    //-------------------------------------------
    // send server list:
    //-------------------------------------------
    if ( dsc_server.m_get_len() < 1 ) {
        // let's see how many server entries exist:
        inl_server = adsc_wsp_helper->m_cb_count_servers( avc_userentry, avc_usergroup,
                                                          ienc_proto,
                                                          dsc_proto.m_get_ptr(),
                                                          dsc_proto.m_get_len() );
        if ( inl_server < 1 ) {
            adsc_wsp_helper->m_log( ied_sdh_log_error,
                                    "HWSPATE018E no server entries defined" );
            return (int)ied_atr_failed;
        } 
#if 0
        else {
            // TODO!!!
            // check if protocol is allowed by role:
            switch ( ien_proto ) {
                case ied_scp_http:
                case ied_scp_rdp:
                case ied_scp_hrdpe1:
                case ied_scp_ica:
                case ied_scp_ldap:
                case ied_scp_hoby:
                case ied_scp_3270:
                case ied_scp_5250:
                case ied_scp_vt:
                case ied_scp_socks5:
                case ied_scp_ssh:
                case ied_scp_smb:
                    break;

                case ied_scp_hpppt1:
                    if ( dsc_ucma.m_role_allows(DEF_ROLE_ALLOW_PPP) == false ) {
                        ads_wsp_helper->m_logf( ied_sdh_log_warning, AT_WARN(50),
                                                "role forbids protocol 'ied_scp_hpppt1'" );
                        return (int)ied_atr_failed;
                    }
                    break;

                case ied_scp_hvoip1:
                case ied_scp_krb5ts1:
                case ied_scp_sstp:
                case ied_scp_spec:
                    break;
            }
        }
#endif
        
        // only one server is available -> we select this one
        if ( inl_server == 1 ) {
            // get the server:
            inl_len_out = 512;
            adsc_wsp_helper->m_cb_get_server_entry( avc_userentry, avc_usergroup,
                                                    ienc_proto,
                                                    dsc_proto.m_get_ptr(),
                                                    dsc_proto.m_get_len(),
                                                    chrl_buffer, &inl_len_out,
                                                    NULL, &inl_function );

            // check function of server:
            if (    inl_function == DEF_FUNC_PTTD   /* desktop on demand */
                 /* && (adsc_wsp_helper->m_get_wsp_auth() & DEF_CLIB1_CONF_LDAP) > 0
                    we might also have ldap when just krb5 is configured */ ) {
                // count workstations in cma:
                inl_wstats = dsc_ucma.m_count_workstations();
                if ( inl_wstats < 1 ) {
                    adsc_wsp_helper->m_log( ied_sdh_log_error,
                                            "HWSPATE049E no workstation defined" );
                    return (int)ied_atr_failed;
                } else if ( inl_wstats > 1 ) {
                    // more than one server -> send a list to client:
                    return m_send_server_list();
                }
            }

            // prepare connect to this server:
            dsc_server.m_write( chrl_buffer, inl_len_out );
            return m_prepare_connect();
        }

        // more than one server -> send a list to client:
        return m_send_server_list();
    }

    //-------------------------------------------
    // prepare connect to the selected server:
    //-------------------------------------------
    return m_prepare_connect();
} // end of ds_wspat::m_create_response


/**
 * function ds_wspat::m_request_auth
 * create a request authentication packet and send it.
 *
 * @param[in]   int     in_message              special message type
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_request_auth( int in_message, const dsd_const_string& rdsp_message )
{
    // initialize some variables:
	dsd_const_string ach_message = rdsp_message;                 // message to client
    ds_hstring dsc_response;
    int        inl_ret      = (int)ied_atr_input;   // we are accepting more data

    dsc_response.m_setup( adsc_wsp_helper );

    //-------------------------------------
    // create request auth packet:
    //-------------------------------------
	dsc_response.m_write_char(AT_PROTO);
    dsc_response.m_write_char(AT_PROTO_REQ_AUTH);

	int inl_req_credentials = AT_PROTO_REQ_USERID | AT_PROTO_REQ_PWD;
#if SM_USE_CERT_AUTH
	dsd_const_string dsl_fixed_user = this->dsc_cert_userid.m_const_str();
	if(dsl_fixed_user.m_get_len() > 0) {
		inl_req_credentials &= ~AT_PROTO_REQ_USERID;
		inl_req_credentials |= AT_PROTO_FLD_USERID;
	}
#else
	dsd_const_string dsl_fixed_user;
#endif

    //-------------------------------------
    // set status byte:
    //-------------------------------------
    switch ( in_message ) {
        case AT_MSG_AUTH_FAILED:
            dsc_userid = dsl_fixed_user;
            dsc_password.m_reset();
            dsc_response.m_write_char(inl_req_credentials
                                    | AT_PROTO_FLD_TEXT
                                    | AT_PROTO_SECOND);
            dsc_response.m_write_char(AT_PROTO_PWD_MAY_CHANGED);
#if SM_USE_CERT_AUTH
			if((inl_req_credentials & AT_PROTO_FLD_USERID) != 0) {
				dsc_response.m_write_nhasn( dsl_fixed_user.m_get_len() );
		        dsc_response.m_write(dsl_fixed_user);
			}
#endif
			ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_failed );
            break;

        case AT_MSG_KICK_OUT:
            dsc_password.m_reset();
            dsc_response.m_write_char(AT_PROTO_REQ_PWD | AT_PROTO_FLD_TEXT);
            ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_kickout );
            break;

        case AT_MSG_NO_ROLE:
            dsc_response.m_write_char(AT_PROTO_ABEND | AT_PROTO_FLD_TEXT);
            ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_no_role );
            inl_ret = (int)ied_atr_end;
            break;

        case AT_MSG_CHANGE_PWD:
            dsc_response.m_write_char(AT_PROTO_REQ_PWD | AT_PROTO_SECOND | AT_PROTO_FLD_TEXT);
            dsc_response.m_write_char(AT_PROTO_PWD_MUST_CHANGED );
            ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_change_pwd );
            break;

			case AT_MSG_SERVER_ENTRY_NOT_FOUND:
            dsc_response.m_write_char(AT_PROTO_ABEND | AT_PROTO_FLD_TEXT);
            ach_message = m_get_resource( ienc_language, ied_wspat_res_server_entry_not_found );
            inl_ret = (int)ied_atr_end;
            break;

			case AT_MSG_CONNECT_FAILED:
            dsc_response.m_write_char(AT_PROTO_ABEND | AT_PROTO_FLD_TEXT);
				if(rdsp_message.m_get_len() <= 0)
					ach_message = m_get_resource( ienc_language, ied_wspat_res_connect_failed );
            inl_ret = (int)ied_atr_end;
            break;

        default:
			if(dsc_userid.m_get_len() > 0) {
				inl_req_credentials &= ~AT_PROTO_REQ_USERID;
			}
#if SM_USE_CERT_AUTH
			if(dsl_fixed_user.m_get_len() > 0)
				dsc_userid = dsl_fixed_user;
#endif
			if((inl_req_credentials & AT_PROTO_REQ_USERID) != 0) {
				ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_user_pwd );
			}
			else {
                ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_pwd );
			}
            dsc_response.m_write_char(inl_req_credentials
                                      | AT_PROTO_FLD_TEXT
                                      | AT_PROTO_SECOND);
            dsc_response.m_write_char(AT_PROTO_PWD_MAY_CHANGED);
#if SM_USE_CERT_AUTH
			if((inl_req_credentials & AT_PROTO_FLD_USERID) != 0) {
				dsc_response.m_write_nhasn( dsl_fixed_user.m_get_len() );
		        dsc_response.m_write(dsl_fixed_user);
			}
#endif
            break;
    }

    //-------------------------------------
    // write message:
    //-------------------------------------
	if ( ach_message.m_get_len() > 0 ) {
		int inl_len = ach_message.m_get_len();
        dsc_response.m_write_nhasn( inl_len );
        dsc_response.m_write(ach_message);
    }

    //-------------------------------------
    // send message:
    //-------------------------------------
    adsc_wsp_helper->m_send_data( dsc_response.m_get_ptr(),
                                  dsc_response.m_get_len() );
    return inl_ret;
} // end of ds_wspat::m_request_auth


/**
 * function ds_wspat::m_pwd_expires
 * create a packet for client which informs about password exire date
 *
 * @param[in]   int     inp_expire_days         expires in x day
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_pwd_expires( int inp_expire_days )
{
    // initialize some variables:
	dsd_const_string achl_message;
    ds_hstring dsl_response;
    ds_hstring dsl_temp;

    dsl_response.m_setup( adsc_wsp_helper );

    //-------------------------------------------
    // create request auth packet:
    //-------------------------------------------
    dsl_response.m_write_char( AT_PROTO );
    dsl_response.m_write_char( AT_PROTO_REQ_AUTH );
    dsl_response.m_write_char(   AT_PROTO_REQ_PWD
                                 | AT_PROTO_FLD_TEXT
                                 | AT_PROTO_SECOND   );
    dsl_response.m_write_char( AT_PROTO_PWD_MAY_CHANGED );

    switch ( inp_expire_days ) {
        case 0:
            achl_message = m_get_resource( ienc_language, ied_wspat_res_auth_pwd_exp_today );
            break;
        case 1:
            achl_message = m_get_resource( ienc_language, ied_wspat_res_auth_pwd_exp_tomorrow );
            break;
        default:
            achl_message = m_get_resource( ienc_language, ied_wspat_res_auth_pwd_exp_days );
			if ( achl_message.m_get_len() > 0 ) {
                dsl_temp.m_setup( adsc_wsp_helper );
				dsl_temp.m_writef( achl_message.m_get_ptr(), inp_expire_days );
				achl_message = dsl_temp.m_const_str();
            }
            break;
    }

    if ( achl_message.m_get_len() > 0 ) {
		int inl_len = achl_message.m_get_len();
        dsl_response.m_write_nhasn( inl_len );
        dsl_response.m_write( achl_message );
    }

    //-------------------------------------------
    // send message:
    //-------------------------------------------
    adsc_wsp_helper->m_send_data( dsl_response.m_get_ptr(),
                                  dsl_response.m_get_len() );
    return ied_atr_input;
} // end of ds_wspat::m_pwd_expires


/**
 * function ds_wspat::m_request_challenge
 * create a request challenge packet and send it.
 *
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_request_challenge()
{
    // initialize some variables:
	dsd_const_string ach_message;                 // message to client
    ds_hstring   dsc_response;

    dsc_response.m_setup( adsc_wsp_helper );

    //-------------------------------------
    // create request auth packet:
    //-------------------------------------
    dsc_response.m_write_char( AT_PROTO );
    dsc_response.m_write_char( AT_PROTO_REQ_AUTH );
    
    //-------------------------------------
    // set status byte:
    //-------------------------------------
    dsc_response.m_write_char( AT_PROTO_REQ_PWD | AT_PROTO_FLD_TEXT );

    //-------------------------------------
    // get user cma:
    //-------------------------------------
	ach_message = dsc_rad_mess.m_const_str();

    if ( dsc_rad_mess.m_get_len() < 1 ) {
        ach_message = m_get_resource( ienc_language, ied_wspat_res_auth_challenge );
    }

    //-------------------------------------
    // write message:
    //-------------------------------------
	if ( ach_message.m_get_len() > 0 ) {
        dsc_response.m_write_nhasn( ach_message.m_get_len() );
        dsc_response.m_write( ach_message );
    }

    //-------------------------------------
    // send message:
    //-------------------------------------
    adsc_wsp_helper->m_send_data( dsc_response.m_get_ptr(),
                                  dsc_response.m_get_len() );

    //-------------------------------------
    // we are accepting more data:
    // -> set return value to more input
    //-------------------------------------
    return (int)ied_atr_input;
} // end of ds_wspat::m_request_challenge


/**
 * function ds_wspat::m_send_server_list
 * send server list
 *
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_send_server_list()
{
    // initialize some variables:
    void*                      avl_srv_handle    = NULL;    // server handle
    char                       chrl_buffer[512];            // temp buffer for server name    
    int                        inl_len_out;                 // length of server name
    ds_hstring                 dsl_response;                // response buffer
    const char*                achl_name;                   // name of current workstation
    int                        inl_len_name;                // length of name
    ds_hvector<ds_workstation> dsl_vwstats;                 // configured workstation from cma
    bool                       bol_ret;                     // return from several func calls
    int                        inl_function;                // function of server entry
    int                        inl_wsp_auth;                // configured authentication methods

    //-------------------------------------------
    // check if client supports server list
    //-------------------------------------------
    if ( dsc_fpacket.bo_meth_disp_serv == false ) {
        adsc_wsp_helper->m_log( ied_sdh_log_error,
                    "HWSPATE037E client doen't support server list, but more than one server is existing" );
        return (int)ied_atr_failed;
    }

    //-------------------------------------------
    // get configured auth methods:
    //-------------------------------------------
    inl_wsp_auth = adsc_wsp_helper->m_get_wsp_auth();

    dsl_response.m_setup( adsc_wsp_helper );

    //-------------------------------------------
    // create 'display server' packet:
    //-------------------------------------------
    dsl_response.m_write_char( AT_PROTO );
    dsl_response.m_write_char( AT_PROTO_SEL_SERVER );
    dsl_response.m_write_char( AT_PROTO_SERVERLIST | AT_PROTO_REQ_SERVER );

    //-------------------------------------------
    // write servers:
    //-------------------------------------------
    for ( ; ; ) {
        inl_function   = -1;
        inl_len_out    = 512;
        avl_srv_handle = adsc_wsp_helper->m_cb_get_server_entry( avc_userentry, avc_usergroup,
                                                                 ienc_proto,
                                                                 dsc_proto.m_get_ptr(),
                                                                 dsc_proto.m_get_len(),
                                                                 chrl_buffer,
                                                                 &inl_len_out,
                                                                 avl_srv_handle,
                                                                 &inl_function );
        if ( avl_srv_handle == NULL ) {
            break;
        }
        if ( inl_function == DEF_FUNC_PTTD ) {
            /*
                ldap is configured:
                 -> try to read configured workstations from cma

                otherwise:
                 -> use old method (means: display DOD entry and
                    after selection have a look if there is 
                    something configured in wsp.xml for this user)
            */
            //-----------------------------------
            // get workstations from cma:
            //-----------------------------------
            bol_ret = dsc_ucma.m_get_workstations( &dsl_vwstats );
            if ( bol_ret == true ) {
                for (HVECTOR_FOREACH(ds_workstation, adsl_cur, dsl_vwstats)) {
                    const ds_workstation& dsl_wstat = HVECTOR_GET(adsl_cur);
                    // add each single workstation
                    bol_ret = dsl_wstat.m_get_name( &achl_name, &inl_len_name );
                    if (    bol_ret == true
                         && inl_len_name > 0 ) {
                        // write new length:
                        dsl_response.m_write_nhasn(   inl_len_out
                                                    + (int)strlen(AT_DOD_DELIMITER)
                                                    + inl_len_name );
                        // write name:
                        dsl_response.m_write( chrl_buffer, inl_len_out );
                        dsl_response.m_write( AT_DOD_DELIMITER );
                        dsl_response.m_write( achl_name, inl_len_name );
                    }
                }
            } else {
                //-------------------------------
                // insert dod dummy entry:
                //-------------------------------
                dsl_response.m_write_nhasn( inl_len_out );
                dsl_response.m_write( chrl_buffer, inl_len_out );
            }
        } else {
            //-----------------------------------
            // insert this server entry:
            //-----------------------------------
            dsl_response.m_write_nhasn( inl_len_out );
            dsl_response.m_write( chrl_buffer, inl_len_out );
        }
    }
    
    //-------------------------------------------
    // server list ends with an zero:
    //-------------------------------------------
    dsl_response.m_write_nhasn( 0 );

    //-------------------------------------------
    // send message:
    //-------------------------------------------
    adsc_wsp_helper->m_send_data( dsl_response.m_get_ptr(),
                                  dsl_response.m_get_len() );

    //-------------------------------------------
    // we are accepting more data:
    // -> set return value to more input
    //-------------------------------------------
    return (int)ied_atr_input;
} // end of ds_wspat::m_send_server_list


/**
 * function ds_wspat::m_prepare_connect
 * prepare connect to a server
 *
 * @return      int         return value from ied_at_return
*/
int ds_wspat::m_prepare_connect()
{
    // initialize some variables:
    bool             bol_ret;                   // return from aux call
    int              inl_delimiter;             // delimiter position
    int              inl_pos;                   // loop variable
    int              inl_count;                 // number of workstations
    ds_workstation   dsl_wstat;                 // workstation
    ds_hstring       dsl_response;              // buffer for response
    const char       *achl_temp;                // helper variable
    int              inl_len_temp;              // length helper variable
    dsd_wspat3_1     *adsl_auth;                // calling structue from wsp

    //-------------------------------------------
    // check if we have been called already:
    //-------------------------------------------
    if ( adsc_connect != NULL ) {
        adsl_auth = (dsd_wspat3_1*)adsc_wsp_helper->m_get_structure();
        adsl_auth->ac_exc_aux  = adsc_connect;
        adsl_auth->imc_exc_aux = (int)sizeof(struct dsd_wspat3_conn);
        return (int)ied_atr_connect;
    }

    
    //-------------------------------------------
    // get memory for connection structure:
    //-------------------------------------------
    adsc_connect = (dsd_wspat3_conn*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_wspat3_conn), true );
    if ( adsc_connect == NULL ) {
        // NEW
        adsc_wsp_helper->m_log( ied_sdh_log_error, "HWSPATE038E cannot get connection memory" );
		return (int)ied_atr_err_aux;
    }

    //-------------------------------------------
    // set protocol:
    //-------------------------------------------
    adsc_connect->iec_scp_def = ienc_proto;

    //-------------------------------------------
    // select server (by name):
    //-------------------------------------------
    adsc_connect->iec_hconn         = ied_hconn_sel_servent;
    adsc_connect->dsc_ucs_server_entry.ac_str      = (void*)dsc_server.m_get_ptr();
    adsc_connect->dsc_ucs_server_entry.imc_len_str = dsc_server.m_get_len();
    adsc_connect->dsc_ucs_server_entry.iec_chs_str = ied_chs_utf_8;
    adsc_connect->vpc_usent         = avc_userentry;
    adsc_connect->vpc_usgro         = avc_usergroup;

    //-------------------------------------------
    // check if we have DoD-delimter in name:
    //-------------------------------------------
    inl_delimiter = dsc_server.m_search( AT_DOD_DELIMITER );
    if ( inl_delimiter > 0 ) {
        adsc_connect->dsc_ucs_server_entry.imc_len_str = inl_delimiter;
    }

    //-------------------------------------------
    // fill connect data:
    //-------------------------------------------
    do {
        adsc_connect->iec_conn_ret = ied_conn_invalid;
        bol_ret = adsc_wsp_helper->m_cb_prepare_connect( adsc_connect );
        if ( bol_ret == false ) {
			  adsc_wsp_helper->m_logf( ied_sdh_log_error,
                "HWSPATE044E prepare connect failed");
           adsc_wsp_helper->m_cb_free_memory( adsc_connect );
           adsc_connect = NULL;
		     return (int)ied_atr_err_aux;
		  }
		  if(adsc_connect->iec_conn_ret == ied_conn_ok)
			  break;
		  bool bol_try_full_name = false;
		  int inl_message = AT_MSG_CONNECT_FAILED;
		  dsd_const_string dsl_message = dsd_const_string::m_null();
		  switch(adsc_connect->iec_conn_ret) {
		  case ied_conn_se_p_no: /* no server entry with this protocol */
			  dsl_message = "no server entry with this protocol";
			  break;
		  case ied_conn_se_p_tm: /* too many server entries with this protocol */
			  dsl_message = "too many server entries with this protocol";
			  break;
		  case ied_conn_se_not_found: /* server entry not found */
			  bol_try_full_name = true;
			  inl_message = AT_MSG_SERVER_ENTRY_NOT_FOUND;
			  break;
		  case ied_conn_se_oth_p: /* server entry has other protocol */
			  dsl_message = "server entry has other protocol";
			  break;
		  case ied_conn_tcp_ref: /* ERROR_CONNECTION_REFUSED The remote system refused the network connection. */
			  dsl_message = "The remote system refused the network connection.";
			  break;
		  case ied_conn_tcp_to: /* WSAETIMEDOUT A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. */
			  dsl_message = "A connection attempt failed because the connected party did not properly respond after a period of time,"
				  "or established connection failed because connected host has failed to respond.";
			  break;
		  case ied_conn_tcp_act_ref: /* WSAECONNREFUSED No connection could be made because the target machine actively refused it. */
			  dsl_message = "No connection could be made because the target machine actively refused it.";
			  break;
		  case ied_conn_tcp_unr: /* WSAEHOSTUNREACH A socket operation was attempted to an unreachable host. */
			  dsl_message = "A socket operation was attempted to an unreachable host.";
			  break;
		  case ied_conn_tcp_ghbn: /* HL_ERROR_GETHOSTBYNAME */
			  break;
		  case ied_conn_xyz: /* pass thru to desktop */
			  break;
		  default:
			  break;
		  }
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
				"HWSPATE039E prepare connect failed (status %d)",
            adsc_connect->iec_conn_ret );

        adsc_wsp_helper->m_cb_free_memory( adsc_connect );
        adsc_connect = NULL;
        return m_request_auth( inl_message, dsl_message );
    } while ( true );

    adsc_wsp_helper->m_logf( ied_sdh_log_warning, "HWSPATI002I select-server %.*s %.*s",
                             dsc_proto.m_get_len(), dsc_proto.m_get_ptr(),
                             adsc_connect->dsc_ucs_server_entry.imc_len_str,
                             (char*)adsc_connect->dsc_ucs_server_entry.ac_str );

    //-------------------------------------------
    // check connection mode:
    //-------------------------------------------
    if ( adsc_connect->iec_hconn == ied_hconn_pttd ) {
        if ( inl_delimiter > 0 ) {
            /*
                get dod settings from ldap settings:
            */
            bol_ret = m_fill_dod( dsc_server.m_get_ptr() + inl_delimiter + (int)strlen(AT_DOD_DELIMITER),
                                  dsc_server.m_get_len() - inl_delimiter - (int)strlen(AT_DOD_DELIMITER)  );
        }
        if (    bol_ret       == false
             || inl_delimiter == -1    ) {
            /*
                given machine name does not exist
                or we have just received DoD prefix
                -> if just one machine is available, select this one
                -> otherwise send serverlist with available machines
            */
            dsl_wstat.m_init( adsc_wsp_helper );
            inl_count = dsc_ucma.m_count_workstations();
            if ( inl_count < 1 ) {
                /*
                    no workstation at all -> error
                */
                adsc_wsp_helper->m_cb_free_memory( adsc_connect );
                adsc_connect = NULL;
                // NEW
                adsc_wsp_helper->m_log( ied_sdh_log_error, "HWSPATE040E no workstations found" );
		        return (int)ied_atr_err_aux;
            } else if ( inl_count == 1 ) {
                /*
                    just one workstation -> select the one and only
                */
                bol_ret = dsc_ucma.m_get_workstation( 0, &dsl_wstat );
                if ( bol_ret == false ) {
                    adsc_wsp_helper->m_cb_free_memory( adsc_connect );
                    adsc_connect = NULL;
                    // NEW
                    adsc_wsp_helper->m_log( ied_sdh_log_error, "HWSPATE041E cannot get workstation information" );
		            return (int)ied_atr_err_aux;
                }
                dsl_wstat.m_get_ineta( &achl_temp, &inl_len_temp );
                if (    achl_temp == NULL
                     || inl_len_temp < 1 ) {
                    adsc_wsp_helper->m_cb_free_memory( adsc_connect );
                    adsc_connect = NULL;
                    // NEW
                    adsc_wsp_helper->m_log( ied_sdh_log_error, "HWSPATE042E cannot get workstation ineta" );
                    return (int)ied_atr_err_aux;
                }
                dsc_dod_ineta.m_setup( adsc_wsp_helper, inl_len_temp );
                dsc_dod_ineta.m_set( achl_temp, inl_len_temp );

                //-------------------------------------------
                // fill pttd data:
                //-------------------------------------------
                dsl_wstat.m_get_mac( (unsigned char*)adsc_connect->chrc_macaddr );
                adsc_connect->boc_with_macaddr = TRUE;
                adsc_connect->imc_waitconn               = dsl_wstat.m_get_wait();
                adsc_connect->imc_port                   = (int)dsl_wstat.m_get_port();
                adsc_connect->dsc_ucs_target.ac_str      = (void*)dsc_dod_ineta.m_get_ptr();
                adsc_connect->dsc_ucs_target.imc_len_str = dsc_dod_ineta.m_get_len();
                adsc_connect->dsc_ucs_target.iec_chs_str = ied_chs_utf_8;
            } else {
                /*
                    multiple workstations -> send serverlist
                */
                adsc_wsp_helper->m_cb_free_memory( adsc_connect );
                adsc_connect = NULL;

                if ( dsc_fpacket.bo_meth_disp_serv == false ) {
                    adsc_wsp_helper->m_log( ied_sdh_log_error,
                                "HWSPATE051E client doen't support server list, but more than one workstation is existing" );
                    adsc_wsp_helper->m_cb_free_memory( adsc_connect );
                    adsc_connect = NULL;
                    return (int)ied_atr_failed;
                }


                //-------------------------------
                // create 'display server' packet
                //-------------------------------
                dsl_response.m_setup( adsc_wsp_helper );
                dsl_response.m_write_char( AT_PROTO );
                dsl_response.m_write_char( AT_PROTO_SEL_SERVER );
                dsl_response.m_write_char( AT_PROTO_SERVERLIST | AT_PROTO_REQ_SERVER );

                for ( inl_pos = 0; inl_pos < inl_count; inl_pos++ ) {
                    bol_ret = dsc_ucma.m_get_workstation( inl_pos, &dsl_wstat );
                    if ( bol_ret == false ) {
                        continue;
                    }
                    bol_ret = dsl_wstat.m_get_name( &achl_temp, &inl_len_temp );
                    if (    bol_ret      == true
                         && inl_len_temp > 0     ) {
                        // write length:
                        dsl_response.m_write_nhasn( (inl_delimiter > 0 ? inl_delimiter : dsc_server.m_get_len())
                                                    + (int)strlen(AT_DOD_DELIMITER)
                                                    + inl_len_temp );
                        // write name:
                        dsl_response.m_write( dsc_server.m_get_ptr(), inl_delimiter > 0 ? inl_delimiter : dsc_server.m_get_len() );
                        dsl_response.m_write( AT_DOD_DELIMITER );
                        dsl_response.m_write( achl_temp, inl_len_temp );
                    }
                }

                // terminate server list:
                dsl_response.m_write_nhasn( 0 );
                dsc_server.m_reset();

                //-------------------------------
                // send message:
                //-------------------------------
                adsc_wsp_helper->m_send_data( dsl_response.m_get_ptr(),
                                              dsl_response.m_get_len() );
                return (int)ied_atr_input;
            }
        }

        // connect pass thru to desktop:
        adsl_auth = (dsd_wspat3_1*)adsc_wsp_helper->m_get_structure();
        adsl_auth->ac_exc_aux  = adsc_connect;
        adsl_auth->imc_exc_aux = (int)sizeof(struct dsd_wspat3_conn);
        return m_send_dod();
    }

    //-------------------------------------------
    // insert connection struct in wspat struct:
    //-------------------------------------------
    adsl_auth = (dsd_wspat3_1*)adsc_wsp_helper->m_get_structure();
    adsl_auth->ac_exc_aux  = adsc_connect;
    adsl_auth->imc_exc_aux = (int)sizeof(struct dsd_wspat3_conn);
    return (int)ied_atr_connect;
} // end of ds_wspat::m_prepare_connect


/**
 * private function m_fill_dod
 * fill given connection structure with dod settings
 *
 * @param[in]   const char* ach_wstat           name of workstation
 * @param[in]   int         in_len_wstat        length of workstation name
 * @return      bool                            true = success
*/
bool ds_wspat::m_fill_dod( const char* ach_wstat, int in_len_wstat )
{
    // initialize some variables:
    bool           bol_ret;                     // return for some function calls
    ds_workstation dsl_wstat;                   // workstation
    const char*    achl_ineta;                  // ineta of workstation
    int            inl_len_ineta;               // length of ineta

    if (    in_len_wstat <  1
         || ach_wstat    == NULL ) {
        return false;
    }

    //-------------------------------------------
    // init some classes:
    //-------------------------------------------
    dsl_wstat.m_init( adsc_wsp_helper );

    //-------------------------------------------
    // get workstation by its name:
    //-------------------------------------------
    bol_ret = dsc_ucma.m_get_workstation( ach_wstat, in_len_wstat, &dsl_wstat );
    if ( bol_ret == false ) {
        return false;
    }

    //-------------------------------------------
    // get ineta:
    //-------------------------------------------
    dsl_wstat.m_get_ineta( &achl_ineta, &inl_len_ineta );
    if (    achl_ineta == NULL
         || inl_len_ineta < 1 ) {
        return false;
    }
    dsc_dod_ineta.m_setup( adsc_wsp_helper, inl_len_ineta );
    dsc_dod_ineta.m_write( achl_ineta, inl_len_ineta );

    //-------------------------------------------
    // fill pttd data:
    //-------------------------------------------
    dsl_wstat.m_get_mac( (unsigned char*)adsc_connect->chrc_macaddr );
    adsc_connect->boc_with_macaddr = TRUE;
    adsc_connect->imc_waitconn               = dsl_wstat.m_get_wait();
    adsc_connect->imc_port                   = (int)dsl_wstat.m_get_port();
    adsc_connect->dsc_ucs_target.ac_str      = (void*)dsc_dod_ineta.m_get_ptr();
    adsc_connect->dsc_ucs_target.imc_len_str = dsc_dod_ineta.m_get_len();
    adsc_connect->dsc_ucs_target.iec_chs_str = ied_chs_utf_8;
    return true;
} // end of ds_wspat::m_fill_dod


/**
 * function ds_wspat::m_send_dod
 * send desktop on demand packet
 *
 * @return      int                             return value from ied_at_return
*/
int ds_wspat::m_send_dod()
{
    // initialize some variables:
    ds_hstring dsc_response;                    // response buffer

    dsc_response.m_setup( adsc_wsp_helper );

    //-------------------------------------
    // set desktop on demand state:
    //-------------------------------------
    ienc_gstate = ied_wspat_dod;

    //-------------------------------------
    // create display server packet:
    //-------------------------------------
    dsc_response.m_write_char( AT_PROTO );
    dsc_response.m_write_char( AT_PROTO_SEL_SERVER );
    dsc_response.m_write_char( AT_PROTO_WAIT );

    //-------------------------------------
    // write wait time (NHASN):
    //-------------------------------------
    dsc_response.m_write_nhasn( adsc_connect->imc_waitconn );

    //-------------------------------------
    // send message:
    //-------------------------------------
    adsc_wsp_helper->m_send_data( dsc_response.m_get_ptr(),
                                  dsc_response.m_get_len() );

    return (int)ied_atr_connect;
} // end of ds_wspat::m_send_dod


/**
 * function ds_wspat::m_get_keytype
 * get type for found keyword
 *
 * @param[in]   dsd_gather_i_1*     ads_input       incoming data
 * @param[in]   int                 in_start        start position of keyword
 * @param[in]   int                 in_end          end position of keyword
 * @return      ied_wspat_keyword                     type of keyword
*/
ied_wspat_keyword ds_wspat::m_get_keytype( dsd_gather_i_1* ads_input,
                                         int in_start, int in_end )
{
    // initialize some variables:
    int             in_read     = 0;                    // already read bytes
    char*           ach_rec     = NULL;                 // received bytes
    int             in_rec      = 0;                    // lenght of received bytes
    ds_hstring      dsc_keyword;                        // temporary buffer for keyword

    dsc_keyword.m_setup( adsc_wsp_helper, in_end - in_start + 1 );

    while ( in_read < in_end - in_start ) {
        ach_rec = adsc_wsp_helper->m_get_buf( ads_input, in_start + in_read,
                                              in_end - (in_start + in_read),
                                              &in_rec );
        if ( ach_rec == NULL ) {
            return ied_wspat_key_unknown;
        }
        in_read += in_rec;
        dsc_keyword.m_write( ach_rec, in_rec );
    }

    dsd_const_string dsl_key = dsc_keyword.m_const_str();
    ied_wspat_keyword ien_type = ds_wsp_helper::m_search_equals_ic2(
        achr_wspat_keywords, dsl_key, ied_wspat_key_unknown);
    return ien_type;
} // end of ds_wspat::m_get_keytype


/**
 * function ds_wspat::m_save_keyvalue
 *
 * @param[in]   dsd_gather_i_1*     ads_input       incoming data
 * @param[in]   int                 in_start        start position of keyword
 * @param[in]   int                 in_end          end position of keyword
*/
bool ds_wspat::m_save_keyvalue( dsd_gather_i_1* ads_input,
                                int in_start, int in_end )
{
    // initialize some variables:
    int         in_read  = 0;                   // already read bytes
    char*       ach_rec  = NULL;                // received bytes
    int         in_rec   = 0;                   // lenght of received bytes
    int         in_pos   = 0;                   // position in data
    ds_hstring* ads_temp = NULL;                // pointer to buffer that should be filled
    int         in_lang  = 0;                   // tempory lang 

    //---------------------------------
    // check data:
    //---------------------------------
    switch( dsc_fpacket.ien_keyword ) {
        case ied_wspat_key_language:
            if ( in_end - in_start > (int)sizeof(int) ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HWSPATE019E send language is too long (%d > %d)",
                                         in_end - in_start, (int)sizeof(int) );
                return false;
            }
            break;

        case ied_wspat_key_userid:
            if ( dsc_userid.m_get_len() > 0 ) {
                adsc_wsp_helper->m_log( ied_sdh_log_error,
                                        "HWSPATE020E userid already set" );
                return false;
            }
            // check maximal length:
            if ( adsc_config->in_maxlenuser > 0 ) {
                if ( in_end - in_start > adsc_config->in_maxlenuser ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE034E username is too long (%d > %d)",
                                             in_end - in_start,
                                             adsc_config->in_maxlenuser );
                    return false;
                }
            }
            dsc_userid.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
            ads_temp = &dsc_userid;
            break;

        case ied_wspat_key_password:
            if ( dsc_password.m_get_len() > 0 ) {
                adsc_wsp_helper->m_log( ied_sdh_log_error,
                                        "HWSPATE021E password already set" );
                return false;
            }
            // check maximal length:
            if ( adsc_config->in_maxlenpwd > 0 ) {
                if ( in_end - in_start > adsc_config->in_maxlenpwd ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE035E password is too long (%d > %d)",
                                             in_end - in_start,
                                             adsc_config->in_maxlenpwd );
                    return false;
                }
            }
            dsc_password.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
            ads_temp = &dsc_password;
            break;

        case ied_wspat_key_server:
            if ( dsc_server.m_get_len() > 0 ) {
                adsc_wsp_helper->m_log( ied_sdh_log_error,
                                        "HWSPATE022E server already set" );
                return false;
            }
            // check maximal length:
            if ( adsc_config->in_maxlenserver > 0 ) {
                if ( in_end - in_start > adsc_config->in_maxlenserver ) {
                    adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                             "HWSPATE036E server is too long (%d > %d)",
                                             in_end - in_start,
                                             adsc_config->in_maxlenserver );
                    return false;
                }
            }
            dsc_server.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
            ads_temp = &dsc_server;
            break;

		default:
			adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                        "HWSPATE043E keyword unknown");
            return false;
    }

    //---------------------------------
    // read the date and save it:
    //---------------------------------
    while ( in_read < in_end - in_start ) {
        ach_rec = adsc_wsp_helper->m_get_buf( ads_input, in_start + in_read,
                                              in_end - (in_start + in_read),
                                              &in_rec );
        if ( ach_rec == NULL ) {
            return false;
        }
        in_read += in_rec;

        switch( dsc_fpacket.ien_keyword ) {
            case ied_wspat_key_language:
                for ( in_pos = 0; in_pos < in_rec; in_pos++ ) {
                    in_lang <<= 8;
                    in_lang |= *((unsigned char *) &ach_rec[in_pos]);
                }
                break;
            
            default:
                ads_temp->m_write( ach_rec, in_rec );
                break;
        }
    }

    //---------------------------------
    // save temp lang in our class:
    //---------------------------------
    if ( dsc_fpacket.ien_keyword == ied_wspat_key_language ) {
        ienc_language = (ied_wspat_language)in_lang;
    }

    return true;
} // end of ds_wspat::m_save_keyvalue


/**
 * function ds_wspat::m_save_auth_input
 *
 * @param[in]   dsd_gather_i_1*     ads_input       incoming data
 * @param[in]   int                 in_start        start position of input
 * @param[in]   int                 in_end          end position of input
*/
bool ds_wspat::m_save_auth_input( dsd_gather_i_1* ads_input,
                                  int in_start, int in_end )
{
    // initialize some variables:
    int         in_read  = 0;                   // already read bytes
    char*       ach_rec  = NULL;                // received bytes
    int         in_rec   = 0;                   // lenght of received bytes
    ds_hstring* ads_temp = NULL;                // pointer to buffer that should be filled

    //---------------------------------
    // check data:
    //---------------------------------
    if ( dsc_userid.m_get_len() < 1 ) {
        // check maximal length:
        if ( adsc_config->in_maxlenuser > 0 ) {
            if ( in_end - in_start > adsc_config->in_maxlenuser ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HWSPATE032E username is too long (%d > %d)",
                                         in_end - in_start,
                                         adsc_config->in_maxlenuser );
                return false;
            }
        }
        dsc_userid.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
        ads_temp = &dsc_userid;
    } else if ( dsc_password.m_get_len() < 1 ) {
        // check maximal length:
        if ( adsc_config->in_maxlenpwd > 0 ) {
            if ( in_end - in_start > adsc_config->in_maxlenpwd ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HWSPATE033E password is too long (%d > %d)",
                                         in_end - in_start,
                                         adsc_config->in_maxlenpwd );
                return false;
            }
        }
        dsc_password.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
        ads_temp = &dsc_password;
    } else if ( dsc_new_pwd.m_get_len() < 1 ) {
        // check maximal length:
        if ( adsc_config->in_maxlenpwd > 0 ) {
            if ( in_end - in_start > adsc_config->in_maxlenpwd ) {
                adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                         "HWSPATE100E new password is too long (%d > %d)",
                                         in_end - in_start,
                                         adsc_config->in_maxlenpwd );
                return false;
            }
        }
        dsc_new_pwd.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
        ads_temp = &dsc_new_pwd;
    } else {
        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                "HWSPATE023E not requested input found" );
        return false;
    }

    //---------------------------------
    // read the date and save it:
    //---------------------------------
    while ( in_read < in_end - in_start ) {
        ach_rec = adsc_wsp_helper->m_get_buf( ads_input, in_start + in_read,
                                              in_end - (in_start + in_read),
                                              &in_rec );
        if ( ach_rec == NULL ) {
            return false;
        }
        in_read += in_rec;
        ads_temp->m_write( ach_rec, in_rec );
    }

    return true;
} // end of ds_wspat::m_save_auth_input


/**
 * function ds_wspat::m_save_server
 *
 * @param[in]   dsd_gather_i_1*     ads_input       incoming data
 * @param[in]   int                 in_start        start position of input
 * @param[in]   int                 in_end          end position of input
*/
bool ds_wspat::m_save_server( dsd_gather_i_1* ads_input, int in_start, int in_end )
{
    // initialize some variables:
    int         in_read  = 0;                   // already read bytes
    char*       ach_rec  = NULL;                // received bytes
    int         in_rec   = 0;                   // lenght of received bytes

    //---------------------------------
    // check data:
    //---------------------------------
    if ( dsc_server.m_get_len() < 1 ) {
        dsc_server.m_setup( adsc_wsp_helper, in_end - in_start + 1 );
    } else {
        adsc_wsp_helper->m_log( ied_sdh_log_error,
                                "HWSPATE024E server already selected" );
        return false;
    }

    //---------------------------------
    // read the data and save it:
    //---------------------------------
    while ( in_read < in_end - in_start ) {
        ach_rec = adsc_wsp_helper->m_get_buf( ads_input, in_start + in_read,
                                              in_end - (in_start + in_read),
                                              &in_rec );
        if ( ach_rec == NULL ) {
            return false;
        }
        in_read += in_rec;
        dsc_server.m_write( ach_rec, in_rec );
    }
    return true;
} // end of ds_wspat::m_save_server
