#define DEF_HL_INCL_INET

#if defined WIN32 || defined WIN64
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <string.h>
#endif

#ifdef HL_UNIX
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef HL_FREEBSD
#include <netinet/in.h>
#endif
#endif

#include <ds_wsp_helper.h>
#include "socks5_entry.h"
#include "socks5.h"

#if defined WIN32 || WIN64
#pragma warning(disable:4996)
#pragma warning(disable:4127) // conditional expression is constant
#endif

// without the following code a compilation error occurs under UNIX (Linux04):
// "/home/frankjm/sdh_socks5/include/hob-xsclib01.h:574: error: expected constructor, destructor, or type conversion before ?(? token"
#ifdef HL_UNIX
#define __declspec(dllexport)
#endif

#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

// TODO-search for: we must 1) mark all data as processed; 2) close the connection



/* RFC 1928: SOCKS Protocol Version 5 states:
The client connects to the server, and sends a version identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+

   The VER field is set to X'05' for this version of the protocol.  The
   NMETHODS field contains the number of method identifier octets that
   appear in the METHODS field.

   The server selects from one of the methods given in METHODS, and
   sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+

   If the selected METHOD is X'FF', none of the methods listed by the
   client are acceptable, and the client MUST close the connection.

   The values currently defined for METHOD are:

          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS

   The client and server then enter a method-specific sub-negotiation.


   RFC 1929 - Username/Password Authentication for SOCKS V5 states:
   Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

   The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.
*/

void socks5::m_setup(ds_wsp_helper* adsl_wsp_helper, struct dsd_hl_clib_1 * ads_trans_in) {
    ads_wsp_helper = adsl_wsp_helper;
    ads_trans      = ads_trans_in;
}


void socks5::Handle() {

    struct ds_manage_buf* ads_conn_memory = (struct ds_manage_buf *) ads_trans->ac_ext;

    //---------------------------------------//
    // negotiation for authentication method //
    //---------------------------------------//
    // data packet from the client is at least 3 bytes (at most 257 !)
    // we collect data, until the minimum of 3 bytes is received
    
    // determine length of the received data
    int in_len_received = 0;
    int in_count_gather = 0;
    struct dsd_gather_i_1 * adsl_gather_tmp = ads_trans->adsc_gather_i_1_in;
    while (adsl_gather_tmp) {
        in_len_received += (int)(adsl_gather_tmp->achc_ginp_end - adsl_gather_tmp->achc_ginp_cur);
        adsl_gather_tmp = adsl_gather_tmp->adsc_next;  // get next in chain
        in_count_gather++;
    }

    // set starting states according to the current phase
    int in_current_state = 0;
    switch (ads_conn_memory->in_phase) {
        case PHASE_NEGO_AUTH_METH: {
            if (in_len_received < 3) { // length of data is lower than minimum expected data for this phase in SOCKS5
                ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE100E: negotiation for authentication method: received data are too short (less than 3): %d", in_len_received);
                return;
            }

            in_current_state = ien_st_first_byte;

            // we must distinguish between Socks4A and Socks5 (signalled by first byte)
            if (*(ads_trans->adsc_gather_i_1_in->achc_ginp_cur) == 0x04) { 
                bo_socks4 = true;
                
                // minimum length of Socks4 is 9 bytes (Socks4A is longer) -> we will collect at least this portion
                if (in_len_received < 9) {
                    ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE101E: received data are too short for Socks4 (less than 9): %d", in_len_received);
                    return;
                }

                in_current_state = ien_st_4_first_byte;
            }

            break;
        }
        case PHASE_AUTH_USERNAME_PASSWORD: {
            if (in_len_received < 5) { // length of data is lower than minimum expected data for this phase
                ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE102E: subnegotiation (username/password): received data are too short (less than 5): %d", in_len_received);
                return;
            }
            in_current_state = ien_st_first_byte_userpw;
            break;
        }
        case PHASE_REQUEST: {
            if (in_len_received < 6) { // length of data is lower than minimum expected data for this phase
                ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE103E: request from client: received data are too short (less than 6): %d", in_len_received);
                return;
            }
            in_current_state = ien_st_first_byte_request;
            break;
        }
        case PHASE_WORK_PROXY: {
            in_current_state = ien_st_copy_in_to_out;

            break;
        }
        default: {
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE104E: invalid phase %d", ads_conn_memory->in_phase);
            return;
        }
   }


    // loop over input data
    struct dsd_gather_i_1 * adsl_curr_in_gath = ads_trans->adsc_gather_i_1_in;

    if (adsl_curr_in_gath == NULL) {
        ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE105E: no input data");
        return;        
    }


    char * ach_current; // current reading position
    bool bo_data_complete = false;
    int in_count_methods = 0;
    int in_len_username = 0;
    int in_len_password = 0;
    int in_len_address_ipv4_4octets  =  4;
    int in_len_address_ipv6_16octets = 16;
    int in_len_rest_of_domain = 0;
    int in_len_port = 2;

    int in_len_domain_received = 0;

    char ch_username[in_maxlen_username_password];
    memset(&ch_username[0], 0, in_maxlen_username_password);
    char ch_password[in_maxlen_username_password];
    memset(&ch_password[0], 0, in_maxlen_username_password);
    memset(&auch_address_ipv4[0], 0, 5);
    memset(&auch_address_domain[0], 0, in_maxlen_domain);
    memset(&auch_port_to_connect_to[0], 0, 2);

    char ch_addr[in_maxlen_domain];
    memset(&ch_addr[0], 0, in_maxlen_domain);

    char* ach_connect_to = NULL; // address of the server to which we want connect

    int in_pos = 0; // current writing position to ch_username or ch_password or auch_address_ipv4
    do {
        if (adsl_curr_in_gath->achc_ginp_cur < adsl_curr_in_gath->achc_ginp_end) {
            ach_current = adsl_curr_in_gath->achc_ginp_cur;
            while (ach_current < adsl_curr_in_gath->achc_ginp_end) {
                switch (in_current_state) {
                    //-------------------------------------
                    // PHASE_NEGO_AUTH_METH
                    // ------------------------------------

                    //-------------------------------------
                    // SOCKS4 + SOCKS4A
                    // ------------------------------------
                    // Socks4/4A-protocol states: first byte of communication must be 0x04
                    case ien_st_4_first_byte: {
                        if (*ach_current != 0x04) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE106E: data are not of protocol-type SOCKS4/4A");

                            // TODO we must 1) mark all data as processed; 2) close the connection
                            return;
                        }
                        ach_current++;
                        in_current_state = ien_st_4_second_byte;  // increase state
                        break;
                    }

                    // second byte: command code must be 0x01 for CONNECT
                    case ien_st_4_second_byte: {
                        if (*ach_current != 0x01) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE107E: invalid command code (must be 1)");

                            // TODO we must 1) mark all data as processed; 2) close the connection
                            return;
                        }
                        ach_current++;
                        in_current_state = ien_st_4_read_dest_port;  // increase state
                        in_pos = 0; // prepare for next state
                        break;
                    }

                    // 2 bytes port number
                    case ien_st_4_read_dest_port: {
                        if (in_pos < 2) { // collect the port; the port is in network byte order, meaning BIG Endian
                            auch_port_to_connect_to[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_port -> check for completness
                        in_len_port--;
                        if (in_len_port > 0) { // port is not complete
                            break;
                        }
                        in_current_state = ien_st_4_read_address;  // increase state
                        in_pos = 0; // prepare for next state
                        break;
                    }

                    case ien_st_4_read_address: {
                        if (in_pos < 5-1) { // collect the address
                            auch_address_ipv4[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_address_ipv4_4octets -> check for completness
                        in_len_address_ipv4_4octets--;
                        if (in_len_address_ipv4_4octets > 0) { // address is not complete
                            break;
                        }

                        // 4 bytes were read in -> distinguish between Socks4 (123.123.123.123) and Socks4A (0.0.0.123)
                        if ( (auch_address_ipv4[0] == 0) && (auch_address_ipv4[1] == 0) && (auch_address_ipv4[2] == 0) && (auch_address_ipv4[3] != 0) ) {
                            bo_socks_4a = true;
                        }

                        // address is complete (in case of Socks4a ach_connect_to will be set to a correct value later on)
                        sprintf(&ch_addr[0], "%u.%u.%u.%u", auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]);
                        ach_connect_to = &ch_addr[0];

                        in_current_state = ien_st_4_read_user_id;  // increase state
                        in_pos = 0; // reset writing position
                        break;
                    }

                    case ien_st_4_read_user_id: { // userId is terminated by 0x00
                        // we don't need the userID -> read until a 0x00 is found
                        if (in_pos < in_maxlen_username_password-1) { // collect the userid
                            if (*ach_current == 0x00) { // we must read until the first 0x00
                                if (bo_socks_4a) { // // JF 19.12.06 to support Socks4A we must read in domain name (NULL-terminated!!)
                                    ach_current++;
                                    in_current_state = ien_st_4_read_domain;
                                    in_pos = 0; // reset writing position
                                }
                                else {
                                    // JF 19.12.06 do the connect in a seperate state
                                    // ach_current++; // this must be done in next state; otherwise the while loop will be left!!
                                    in_current_state = ien_st_4_do_connect;
                                }
                                break;
                            }
                            auch_user_id[in_pos] = (*ach_current);
                            in_pos++;
                            ach_current++;
                            break; // read next character
                        }
                        else { // userid is too long
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE108E: userid is longer than %d bytes", (in_maxlen_username_password-1));

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);                            
                            // send 'failure' and close connection
                            char ch_output[] = {0x00, 0x5B, auch_port_to_connect_to[0], auch_port_to_connect_to[1], auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]};
                            m_send(&ch_output[0], 8, true, ied_sdh_dd_toclient);
                            return;
                        }

                        break;
                    }

                    // JF 19.12.06
                    case ien_st_4_read_domain: { // domain is terminated by 0x00
                        // we don't need the userID -> read until a 0x00 is found
                        if (in_pos < in_maxlen_domain-1) { // collect the domain nmae
                            if (*ach_current == 0x00) { // we must read until the first 0x00
                                // this must be done in next state; otherwise the while loop will be left!!     ach_current++;
                                ach_connect_to = (char*)&auch_4_domain[0];
                                in_current_state = ien_st_4_do_connect;
                                break;
                            }
                            auch_4_domain[in_pos] = (*ach_current);
                            in_pos++;
                            ach_current++;
                            break; // read next character
                        }
                        else { // domain is too long
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE109E: domain name is longer than %d bytes", (in_maxlen_username_password-1));

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);                            
                            // send 'failure' and close connection
                            char ch_output[] = {0x00, 0x5B, auch_port_to_connect_to[0], auch_port_to_connect_to[1], auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]};
                            m_send(&ch_output[0], 8, true, ied_sdh_dd_toclient);
                            return;
                        }

                        break;
                    }

                    // JF 19.12.06 do connect in a seperate state
                    case ien_st_4_do_connect: {
                        ach_current++;

                        //-------------------------
                        // if we get here: all required data were read in
                        //-------------------------
                        bo_data_complete = true;

                        // mark gathers as processed (until the current position)
                        m_mark_as_processed(ach_current, adsl_curr_in_gath);

                        //-------------------
                        // connect to server (Socks4)
                        //-------------------
                        bool bo_connect_ok = m_connect_to_server(ach_connect_to, NULL); // JF 07.05.07 Tickte[12542]: in case of Socks4 the detailled error number is of no interest -> therefore 0
                        if (!bo_connect_ok) { // connect failed
                            // send 'failure' and close connection
                            // this response goes to client, because connection to server could not be established
                            char ch_output[] = {0x00, 0x5B, auch_port_to_connect_to[0], auch_port_to_connect_to[1], auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]};
                            m_send(&ch_output[0], 8, true, ied_sdh_dd_toclient);
                            return;
                        }


                        // We connected to server and had data for the client.

                        if (bo_socks4) { // send reply 'success' in Socks4 (Socks4 only supports IPv4!).
                            char ch_output[] = {0x00, 0x5A, auch_port_to_connect_to[0], auch_port_to_connect_to[1], auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]};
                            m_send(&ch_output[0], 8, false, ied_sdh_dd_toclient);                
                        }
                        else { // send reply 'success' Socks5
                            // Connect was successful. Retrieve informations about the established connection. These information must be sent to client.
                            dsd_aux_get_session_info dsl_sessinfo;
                            BOOL bo = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_GET_SESSION_INFO, &dsl_sessinfo, sizeof(struct dsd_aux_get_session_info));
                            if ( (bo == FALSE) || (dsl_sessinfo.iec_ass != ied_ass_connected) ) {
                                ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE184E: DEF_AUX_GET_SESSION_INFO failed %d %d. ", bo, dsl_sessinfo.iec_ass);

                                // For simpleness we ALWAYS send ATYP_IPv4, even if there was another ATYP in request.
                                char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                                m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);
                                return;
                            }

                            // Response, when connection is established with a IPv4 adapter.
                            char ch_output_ipv4[] = {0x05, 0x00, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00,  //  4 bytes for IPv6
                                                                                  0x00, 0x00};             //  2 bytes for port
                            
                            // Response, when connection is established with a IPv6 adapter.
                            char ch_output_ipv6[] = {0x05, 0x00, 0x00, ATYP_IPv6, 0x00, 0x00, 0x00, 0x00,  // 16 bytes for IPv6
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00};             //  2 bytes for port

                            switch (dsl_sessinfo.dsc_soa_server_this.ss_family) {
                                case AF_INET: { // IPv4
                                    struct sockaddr_in* adsl_so = (struct sockaddr_in*) &dsl_sessinfo.dsc_soa_server_this;
                                    memmove((void*)&ch_output_ipv4[  4], &adsl_so->sin_addr, 4);
                                    memmove((void*)&ch_output_ipv4[4+4], &adsl_so->sin_port, 2);
                                    m_send(&ch_output_ipv4[0], sizeof(ch_output_ipv4), false, ied_sdh_dd_toclient);
                                    break;
                                }
                                case AF_INET6: { // IPv6
                                    struct sockaddr_in6* adsl_so_ipv6 = (struct sockaddr_in6*) &dsl_sessinfo.dsc_soa_server_this;
                                    memmove((void*)&ch_output_ipv6[   4], &adsl_so_ipv6->sin6_addr, 16);
                                    memmove((void*)&ch_output_ipv6[4+16], &adsl_so_ipv6->sin6_port,  2);
                                    m_send(&ch_output_ipv6[0], sizeof(ch_output_ipv6), false, ied_sdh_dd_toclient);
                                    break;
                                }
                                default: {// family not found
                                    ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE185E: DEF_AUX_GET_SESSION_INFO returns invalid address family %d.", (int)dsl_sessinfo.dsc_soa_server_this.ss_family);
                                    // For simpleness we ALWAYS send ATYP_IPv4, even if there was another ATYP in request.
                                    char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                                    m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);
                                    return;
                                }
                            }
                        }
                        
                        ads_conn_memory->in_phase = PHASE_WORK_PROXY;
                    }


                    //-------------------------------------
                    // SOCKS5
                    // ------------------------------------
                    // Socks5-protocol states: first byte of communication must be 0x05
                    case ien_st_first_byte: {
                        if (*ach_current != 0x05) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE110E: data are not of protocol-type SOCKS5");

                            // TODO we must 1) mark all data as processed; 2) close the connection
                            return;
                        }
                        ach_current++;
                        in_current_state = ien_st_second_byte;  // increase state
                        break;
                    }
                    // second byte: number of authentication methods, which the client supports (allowed: 1-255)
                    case ien_st_second_byte: {
                        in_count_methods = *((unsigned char *)ach_current);
                        if (in_count_methods == 0) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE111E: invalid number of authentication methods (must not be 0)");

                            // TODO we must 1) mark all data as processed; 2) close the connection
                            return;
                        }
                        ach_current++;
                        in_current_state = ien_st_read_client_meth;  // increase state
                        break;
                   }
                   // get authentication methods (supported by the client)
                   case ien_st_read_client_meth: {
                        if ((*ach_current) == in_meth_no_auth) {
                            in_client_suggest_methods |= (1<<in_meth_no_auth);
                        }
                        else if ((*ach_current) == in_meth_gssapi) {
                            in_client_suggest_methods |= (1<<in_meth_gssapi);
                        }
                        else if ((*ach_current) == in_meth_user_pwd) {
                            in_client_suggest_methods |= (1<<in_meth_user_pwd);
                        }

                        ach_current++;

                        // we must read in in_count_methods of methods -> check for completness
                        in_count_methods--;
                        if (in_count_methods > 0) { // not all methods are read in
                            break;
                        }
                        

                        //-------------------------
                        // if we get here: all required data of PHASE_NEGO_AUTH_METH were read in
                        //-------------------------
                        bo_data_complete = true;

                        // mark gathers as processed (until the current position)
                        m_mark_as_processed(ach_current, adsl_curr_in_gath);

                        // select authentication method (if no authentication method can be selected -> client MUST close the connection)
                        int in_sel_auth_meth = m_select_auth_method(in_client_suggest_methods);
                        if (in_sel_auth_meth != in_meth_no_accept) { // an authentication method was selected -> refresh the state to "Authentication in progress /method>"
                            if (in_sel_auth_meth == in_meth_user_pwd) {
                                ads_conn_memory->in_phase = PHASE_AUTH_USERNAME_PASSWORD;
                            }
                            else if (in_sel_auth_meth == in_meth_gssapi) {
                                ads_conn_memory->in_phase = PHASE_AUTH_GSSAPI;
                            }
                            else if (in_sel_auth_meth == in_meth_no_auth) {
                                ads_conn_memory->in_phase = PHASE_REQUEST;
                            }
                        }
                        else {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE112E: unable to negotiate authentication model");

                            // RFC1928 states, that the client must close the connection after it received our response
                            // to be sure against faking, we reset the phase to the beginning phase PHASE_NEGO_AUTH_METH
                            ads_conn_memory->in_phase = PHASE_NEGO_AUTH_METH;
                        }

                        // send response (means: write to workarea and return)
                        // we will write a gather-structure and 2 bytes (response by socks server)
                        char ch_output[] = {0x05, (char)in_sel_auth_meth};
                        m_send(&ch_output[0], 2, false, ied_sdh_dd_toclient);

                        return; // end of case STATE_NEGO_AUTH_METH
                   }

                    //-------------------------------------
                    // PHASE_AUTH_USERNAME_PASSWORD
                    // ------------------------------------
                    // Socks5-protocol states: first byte of username/password-authentication must be 0x01
                    case ien_st_first_byte_userpw: {
                        int in_first_byte = *ach_current;
                        ach_current++;
                        if (in_first_byte != 0X01) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE113E: version of subnegotiation must be 1 instead of %d", in_first_byte);

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);                            
                            // send 'failure' and close connection
                            char ch_output[] = {0x01, 0x01}; // second byte is 0x00 in case of success
                            m_send(&ch_output[0], 2, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_len_username;  // increase state
                        break;
                    }
                    // second byte holds length of the username (allowed: 1-255)
                    case ien_st_len_username: {
                        in_len_username = *((unsigned char *)ach_current);
                        ach_current++;
                        if (in_len_username == 0) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE114E: invalid length info for username (must not be 0)");

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x01, 0x02}; // second byte is 0x00 in case of success
                            m_send(&ch_output[0], 2, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_read_username;  // increase state
                        break;
                    }
                   case ien_st_read_username: {
                        if (in_pos < in_maxlen_username_password-1) { // collect the username
                            ch_username[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_username -> check for completness
                        in_len_username--;
                        if (in_len_username > 0) { // username is not complete
                            break;
                        }

                        // username is complete
                        in_current_state = ien_st_len_password;  // increase state
                        break;
                    }
                    case ien_st_len_password: {
                        in_len_password = *((unsigned char *)ach_current);
                        ach_current++;
                        if (in_len_password == 0) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE115E: invalid length info for password (must not be 0)");

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x01, 0x03}; // second byte is 0x00 in case of success
                            m_send(&ch_output[0], 2, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_read_password;  // increase state
                        in_pos = 0; // reset position for reading the password
                        break;
                    }
                   case ien_st_read_password: {
                        if (in_pos < in_maxlen_username_password-1) { // collect the password
                            ch_password[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_password -> check for completness
                        in_len_password--;
                        if (in_len_password > 0) { // password is not complete
                            break;
                        }

                        //-------------------------
                        // if we get here: all required data of PHASE_AUTH_USERNAME_PASSWORD were read in
                        //-------------------------
                        bo_data_complete = true;

                        // mark gathers as processed (until the current position)
                        m_mark_as_processed(ach_current, adsl_curr_in_gath);

                        //----------------------------
                        // do checking username/password
                        //----------------------------
                        bool bo_authenticated = m_authenticate(&ch_username[0], &ch_password[0]);
                        if (!bo_authenticated) {
                            // send 'failure' and close connection
                            char ch_output[] = {0x01, 0x04}; // second byte is 0x00 in case of success
                            m_send(&ch_output[0], 2, true, ied_sdh_dd_toclient);    
                            return;
                        }

                        // send 'success' and DON'T CLOSE connection
                        char ch_output[] = {0x01, 0x00}; // second byte is 0x00 in case of success
                        m_send(&ch_output[0], 2, false, ied_sdh_dd_toclient);

                        ads_conn_memory->in_phase = PHASE_REQUEST;

                        return;
                    } // end of PHASE_AUTH_USERNAME_PASSWORD


                    //-------------------------------------
                    // PHASE_REQUEST
                    // ------------------------------------
                    // Socks5-protocol states: first byte of PHASE_REQUEST must be the protocol version -> 0x05
                    case ien_st_first_byte_request: {
                        int in_first_byte_request = *ach_current;
                        ach_current++;
                        if (in_first_byte_request != 0X05) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE116E: version of socks request must be 5 not %d.", in_first_byte_request);

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                            m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_command_request;  // increase state
                        break;
                    }
                    // second byte holds the requested command (allowed: 1=CONNECT; 2=BIND; 3=UDP); we support only 0x01
                    case ien_st_command_request: {
                        int in_command = *((unsigned char *)ach_current);
                        ach_current++;
                        if (in_command != 0x01) { // we only support command 0x01 (CONNECT)
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE117E: command not supported: %d (must be 1)", in_command);

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x05, 0x07, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                            m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_reserved_request;  // increase state
                        break;
                    }
                    // third byte must be 0x00 (reserved)
                    case ien_st_reserved_request: {
                        int in_reserved = *((unsigned char *)ach_current);
                        ach_current++;
                        if (in_reserved != 0x00) {
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE118E: reserved byte is invalid: %d (must be 0)", in_reserved);

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                            m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        in_current_state = ien_st_address_type;  // increase state
                        break;
                    }
                    // Adress type (1=IPv4; 3=domainname; 4=IPv6)
                    case ien_st_address_type: {
                        in_atyp_request = *((unsigned char *)ach_current);
                        ach_current++;

                        if (in_atyp_request == ATYP_IPv4) { // the address is a IPv4 address with a length of 4 octets
                            in_current_state = ien_st_read_address_ipv4;  // increase state
                        }
                        else if (in_atyp_request == ATYP_IPv6) { // the address is a IPv6 address with a length of 16 octets
                            in_current_state = ien_st_read_address_ipv6;  // increase state
                        }
                        else if (in_atyp_request == ATYP_DOMAINNAME) { // the address field contains a fully qualified domain name; 
                                                            // the first octet of the address field contains the number of octets
                                                            // of name that follows (no NULL-termination)
                            // read in len-info
                            in_len_rest_of_domain = (*ach_current);
                            in_len_domain_received = in_len_rest_of_domain;
                            ach_current++;
                            in_pos = 0;
                            in_current_state = ien_st_read_address_domain;
                        }
                        else { // requested address type is not supported
                            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE119E: address type is invalid/not supported: %d.", in_atyp_request);

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current, adsl_curr_in_gath);
                            // send 'failure' and close connection
                            char ch_output[] = {0x05, 0x08, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                            m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);    
                            return;
                        }
                        break;
                    }
                    case ien_st_read_address_domain: {
                        if (in_pos < in_len_domain_received) { // collect the address
                            auch_address_domain[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_rest_of_domain -> check for completness
                        in_len_rest_of_domain--;
                        if (in_len_rest_of_domain > 0) { // address is not complete
                            break;
                        }

                        // address is complete
                        ach_connect_to = (char*)&auch_address_domain[0];

                        in_current_state = ien_st_read_port;  // increase state
                        in_pos = 0; // reset writing position
                        break;
                    }
                    case ien_st_read_address_ipv4: {
                        if (in_pos < 5-1) { // collect the address (4 octets)
                            auch_address_ipv4[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_address_ipv4_4octets -> check for completness
                        in_len_address_ipv4_4octets--;
                        if (in_len_address_ipv4_4octets > 0) { // address is not complete
                            break;
                        }

                        // address is complete
                        // we will give address as zero-terminated string "xxx.xxx.xxx.xxx"
                        sprintf(&ch_addr[0], "%u.%u.%u.%u", auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]);
                        ach_connect_to = &ch_addr[0];

                        in_current_state = ien_st_read_port;  // increase state
                        in_pos = 0; // reset writing position
                        break;
                    }
                    case ien_st_read_address_ipv6: {
                        if (in_pos < 17-1) { // collect the address (16 octets)
                            auch_address_ipv6[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_address_ipv6_16octets -> check for completness
                        in_len_address_ipv6_16octets--;
                        if (in_len_address_ipv6_16octets > 0) { // address is not complete
                            break;
                        }

                        // address is complete
                        // we will give address as zero-terminated string "2001:0db8:85a3:08d3:1319:8a2e:0370:7344"
                        sprintf(&ch_addr[0], "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                                           , auch_address_ipv6[ 0], auch_address_ipv6[ 1], auch_address_ipv6[ 2], auch_address_ipv6[ 3]
                                           , auch_address_ipv6[ 4], auch_address_ipv6[ 5], auch_address_ipv6[ 6], auch_address_ipv6[ 7]
                                           , auch_address_ipv6[ 8], auch_address_ipv6[ 9], auch_address_ipv6[10], auch_address_ipv6[11]
                                           , auch_address_ipv6[12], auch_address_ipv6[13], auch_address_ipv6[14], auch_address_ipv6[15]);
                        ach_connect_to = &ch_addr[0];

                        in_current_state = ien_st_read_port;  // increase state
                        in_pos = 0; // reset writing position
                        break;
                    }
                    case ien_st_read_port: {
                        if (in_pos < 2) { // collect the port; the port is in network byte order, meaning BIG Endian
                            auch_port_to_connect_to[in_pos] = (*ach_current);
                            in_pos++;
                        }
                        ach_current++;

                        // we must read in in_len_port -> check for completness
                        in_len_port--;
                        if (in_len_port > 0) { // port is not complete
                            break;
                        }

                        //-------------------------
                        // if we get here: all required data of PHASE_REQUEST were read in
                        //-------------------------
                        bo_data_complete = true;

                        // mark gathers as processed (until the current position)
                        m_mark_as_processed(ach_current, adsl_curr_in_gath);

                        //-------------------
                        // connect to server (Socks5)
                        //-------------------
                        int in_detailled_error = -1; // JF 07.05.07 Tickte[12542]: in case of Socks5 return a detailled error number
                        bool bo_connect_ok = m_connect_to_server(ach_connect_to, &in_detailled_error);
                        if (!bo_connect_ok) { // connect failed
                            // Send 'failure' and close connection.
                            // This response goes to client, because connection to server could not be established.
                            // For simpleness we ALWAYS send ATYP_IPv4, even if there was another ATYP in request.
                            char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                            // Detailled error code, if available.
                            if (in_detailled_error == ied_tcr_denied_tf) { // target filter blocked connection
                                ch_output[1] = 0x02; // 'Connection  not allowed by ruleset'
                            }
                            if (in_detailled_error == ied_tcr_no_route) {
                                ch_output[1] = 0x04; // 'Host unreachable'
                            }
                            if (in_detailled_error == ied_tcr_refused) {
                                ch_output[1] = 0x05; // 'Connection  refused'
                            }

                            m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);
                            return;
                        }


                        // We connected to server and had data for the client.

                        if (bo_socks4) { // send reply 'success' in Socks4 (Socks4 only supports IPv4!).
                            char ch_output[] = {0x00, 0x5A, auch_port_to_connect_to[0], auch_port_to_connect_to[1], auch_address_ipv4[0], auch_address_ipv4[1], auch_address_ipv4[2], auch_address_ipv4[3]};
                            m_send(&ch_output[0], 8, false, ied_sdh_dd_toclient);                
                        }
                        else { // send reply 'success' Socks5
                            // Connect was successful. Retrieve informations about the established connection. These information must be sent to client.
                            dsd_aux_get_session_info dsl_sessinfo;
                            BOOL bo = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_GET_SESSION_INFO, &dsl_sessinfo, sizeof(struct dsd_aux_get_session_info));
                            if ( (bo == FALSE) || (dsl_sessinfo.iec_ass != ied_ass_connected) ) {
                                ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE184E: DEF_AUX_GET_SESSION_INFO failed %d %d. ", bo, dsl_sessinfo.iec_ass);

                                // For simpleness we ALWAYS send ATYP_IPv4, even if there was another ATYP in request.
                                char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                                m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);
                                return;
                            }

                            // Response, when connection is established with a IPv4 adapter.
                            char ch_output_ipv4[] = {0x05, 0x00, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00,  //  4 bytes for IPv6
                                                                                  0x00, 0x00};             //  2 bytes for port
                            
                            // Response, when connection is established with a IPv6 adapter.
                            char ch_output_ipv6[] = {0x05, 0x00, 0x00, ATYP_IPv6, 0x00, 0x00, 0x00, 0x00,  // 16 bytes for IPv6
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00, 0x00, 0x00,
                                                                                  0x00, 0x00};             //  2 bytes for port

                            switch (dsl_sessinfo.dsc_soa_server_this.ss_family) {
                                case AF_INET: { // IPv4
                                    struct sockaddr_in* adsl_so = (struct sockaddr_in*) &dsl_sessinfo.dsc_soa_server_this;
                                    memmove((void*)&ch_output_ipv4[  4], &adsl_so->sin_addr, 4);
                                    memmove((void*)&ch_output_ipv4[4+4], &adsl_so->sin_port, 2);
                                    m_send(&ch_output_ipv4[0], sizeof(ch_output_ipv4), false, ied_sdh_dd_toclient);
                                    break;
                                }
                                case AF_INET6: { // IPv6
                                    struct sockaddr_in6* adsl_so_ipv6 = (struct sockaddr_in6*) &dsl_sessinfo.dsc_soa_server_this;
                                    memmove((void*)&ch_output_ipv6[   4], &adsl_so_ipv6->sin6_addr, 16);
                                    memmove((void*)&ch_output_ipv6[4+16], &adsl_so_ipv6->sin6_port,  2);
                                    m_send(&ch_output_ipv6[0], sizeof(ch_output_ipv6), false, ied_sdh_dd_toclient);
                                    break;
                                }
                                default: {// family not found
                                    ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE185E: DEF_AUX_GET_SESSION_INFO returns invalid address family %d.", (int)dsl_sessinfo.dsc_soa_server_this.ss_family);
                                    // For simpleness we ALWAYS send ATYP_IPv4, even if there was another ATYP in request.
                                    char ch_output[] = {0x05, 0x01, 0x00, ATYP_IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                                    m_send(&ch_output[0], 10, true, ied_sdh_dd_toclient);
                                    return;
                                }
                            }
                        }
                        
                        ads_conn_memory->in_phase = PHASE_WORK_PROXY;
                    } // end of PHASE_REQUEST

                    //-------------------------------------
                    // PHASE_WORK_PROXY
                    // ------------------------------------
                    case ien_st_copy_in_to_out: {
                        if (ads_trans->adsc_gather_i_1_in == NULL) {  // no input data
                            return;
                        }

                        m_send(adsl_curr_in_gath->achc_ginp_cur, adsl_curr_in_gath->achc_ginp_end - adsl_curr_in_gath->achc_ginp_cur,
                            false, ied_sdh_dd_auto);

                        ach_current = adsl_curr_in_gath->achc_ginp_end; // to get next input
                        adsl_curr_in_gath->achc_ginp_cur = adsl_curr_in_gath->achc_ginp_end; // mark input gather as 'processed'

                        bo_data_complete = true; // to avoid printout, that data were not complete

                        break;
                    } // end of PHASE_WORK_PROXY
                                                 
                } // switch
           } // while
     } // if
     adsl_curr_in_gath = adsl_curr_in_gath->adsc_next;
   } while (adsl_curr_in_gath);

   if (!bo_data_complete) {
       ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE121E: data are not complete in state %d", in_current_state);
       return;
   }
}
//  mark how far the received blocks are processed
// adsl_current_gather can be omitted; I hope in this way, it is more performant
void socks5::m_mark_as_processed(char* ach_processed_til_here, struct dsd_gather_i_1 * adsl_current_gather) {
   struct dsd_gather_i_1 * adsl_gather_tmp = ads_trans->adsc_gather_i_1_in;
   while (adsl_gather_tmp) {                // loop over all gathers
     if (adsl_gather_tmp == adsl_current_gather) {  // current block found
        if ( (ach_processed_til_here >= adsl_gather_tmp->achc_ginp_cur) &&
             (ach_processed_til_here <= adsl_gather_tmp->achc_ginp_end) ) { // JF 05.01.07 ensure, that we are at correct position
                   adsl_gather_tmp->achc_ginp_cur = ach_processed_til_here;  // processed till here
        }
        else {
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE122E: m_mark_as_processed cannot find position");
        }
        break;
     }
     adsl_gather_tmp->achc_ginp_cur = adsl_gather_tmp->achc_ginp_end;
     adsl_gather_tmp = adsl_gather_tmp->adsc_next;  // get next
   }
}

// socks server must select one of the authentication methods, which the client suggested
int socks5::m_select_auth_method(int in_suggested_by_client)
{
#ifdef AUTH_USER_PWD  // JF 02.01.07  without this define we will respond to a request for authentication with ONLY username/password 0x05 0x01 0x02 with 0x01 0x00 instead of 0x01 0xFF
    if ((in_suggested_by_client & (1<<in_meth_user_pwd)) == (1<<in_meth_user_pwd)) {
        return in_meth_user_pwd;
    }
#endif // AUTH_USER_PWD
    
    if (bo_no_auth_allowed) {
        if ((in_suggested_by_client & (1<<in_meth_no_auth)) == (1<<in_meth_no_auth)) {
            return in_meth_no_auth;
        }
    }

    return in_meth_no_accept;
}


bool socks5::m_connect_to_server(char* ach_server_address, int* in_detailled_error)
{
    if (ach_server_address == NULL) {
        return false;
    }

    // get an int from auch_port
    int in_port = (auch_port_to_connect_to[0] << 8);
    in_port += auch_port_to_connect_to[1];

    // Write info to log.
    switch (in_atyp_request) {
        case ATYP_IPv4: {
            ads_wsp_helper->m_logf(ied_sdh_log_info, "HSOCI123I: connect to %s:%d (IPv4)", ach_server_address, in_port);
            break;
        }
        case ATYP_IPv6: {
            ads_wsp_helper->m_logf(ied_sdh_log_info, "HSOCI223I: connect to server=%s port=%d (IPv6)", ach_server_address, in_port);
            break;
        }
        case ATYP_DOMAINNAME: {
            ads_wsp_helper->m_logf(ied_sdh_log_info, "HSOCI323I: connect to server=%s port=%d (Domain name)", ach_server_address, in_port);
            break;
        }
    }

    struct dsd_aux_tcp_conn_1 ds_tcp;
    memset(&ds_tcp, 0, sizeof(dsd_aux_tcp_conn_1));
    ds_tcp.dsc_target_ineta.ac_str      = ach_server_address;
    ds_tcp.dsc_target_ineta.imc_len_str = -1;
    ds_tcp.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;
    ds_tcp.imc_server_port = in_port;

    bool bo = ads_wsp_helper->m_cb_tcp_connect(&ds_tcp);
    if (bo == false) {
        ds_hstring hstr_err(ads_wsp_helper);
        hstr_err.m_writef("HSOCE124E: Connect to server %s:%d failed %d %d. ", ach_server_address, in_port, bo, ds_tcp.iec_tcpconn_ret);
        // Detailed error message.
        if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_ocos) { // no option connect-other-server configured
            hstr_err.m_write("No option connect-other-server configured.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_cs_ssl) {
            hstr_err.m_write("No Client-Side SSL configured.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_denied_tf) { 
            hstr_err.m_write("Access denied by target filter.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_hostname) { 
            hstr_err.m_write("Host name not in DNS.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_route) {
            hstr_err.m_write("No route to host.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_refused) {
            hstr_err.m_write("Connection refused.");
        }
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_timeout) {
            hstr_err.m_write("Connection timed out.");
        }
        // this error can also be returned, when target filter denied the access! comment of KB: 'other error';
        else if (ds_tcp.iec_tcpconn_ret == ied_tcr_error) {
            hstr_err.m_write("Connection failed with 'other error'.");
        }
		ads_wsp_helper->m_log(ied_sdh_log_error, hstr_err.m_const_str());

        if (ds_tcp.iec_tcpconn_ret != ied_tcr_ok) {
            if (in_detailled_error != NULL) {
                *in_detailled_error = ds_tcp.iec_tcpconn_ret;
            }
        }

        return false;
    }

    // Connect was successful.
    ads_wsp_helper->m_log(ied_sdh_log_info, "HSOCI328I: Connect was successful.");

    return true; // connect succeeded
}


// Send data to client or server.
int socks5::m_send(char* ach_output, int in_len_output, bool bo_terminate_connection, enum ied_sdh_data_direction ienp_direction)
{
    bool bol_ret = ads_wsp_helper->m_send_data(ach_output, in_len_output, ienp_direction);
    if (bol_ret == false) {
        ads_wsp_helper->m_log(ied_sdh_log_error, "HSOCE428E: Sending data failed.");
    }

    // force WSP to terminate this connection
    if (bo_terminate_connection) {
        ads_trans->inc_return = DEF_IRET_END;
    }

    return 0;
}

// authenticate the delivered username and password
bool socks5::m_authenticate(char* ach_username, char* ach_password)
{
    if (bo_radius_on) {
        return m_auth_radius(ach_username, ach_password);
    }
    else {
        return true;
    }
}


bool socks5::m_auth_radius(char* ach_username, char* ach_password) {

    struct dsd_hl_aux_radius_1 ds_auth_radius;
    memset( &ds_auth_radius, 0, sizeof(struct dsd_hl_aux_radius_1) );
    
    ds_auth_radius.dsc_ucs_userid.ac_str        = (void*)ach_username;
    ds_auth_radius.dsc_ucs_userid.imc_len_str   = static_cast<int>(strlen(ach_username));
    ds_auth_radius.dsc_ucs_userid.iec_chs_str   = ied_chs_utf_8;
    ds_auth_radius.dsc_ucs_password.ac_str      = (void*)ach_password;
    ds_auth_radius.dsc_ucs_password.imc_len_str = static_cast<int>(strlen(ach_password));
    ds_auth_radius.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;

    ds_auth_radius.boc_send_nas_ineta = true; // force WSP to send NAS IP Address

    BOOL bol1 = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_RADIUS_QUERY, &ds_auth_radius, sizeof(struct dsd_hl_aux_radius_1));
    //-------------------------------
    // RADIUS: query failed
    //-------------------------------
    if ( (bol1 == false) || (ds_auth_radius.iec_radius_resp == ied_rar_invalid) || (ds_auth_radius.iec_radius_resp == ied_rar_error) ) { // 0: invalid parameter; 4: error                          
        if (bol1 == false) {
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE127E: RADIUS-query failed: method returned false");
        }
        if (ds_auth_radius.iec_radius_resp == ied_rar_invalid) {
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE128E: RADIUS-query failed: parameter is invalid");           
        }
        if (ds_auth_radius.iec_radius_resp == ied_rar_error) {
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE129E: RADIUS-query failed: no valid response.");
        }
        return false;
    }

    //-------------------------------
    // RADIUS: REJECT
    //-------------------------------
    if (ds_auth_radius.iec_radius_resp == ied_rar_access_reject) {
        ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE130E: RADIUS server rejected the login.");
        return false;
    }
    //-------------------------------
    // RADIUS: CHALLENGE
    //-------------------------------
    else if (ds_auth_radius.iec_radius_resp == ied_rar_challenge) { // challenge is not supported
        ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE131E: RADIUS server made a challenge. Challenge is not supported.");
        return false;
    }
    //-------------------------------
    // RADIUS: ACCEPTED
    //-------------------------------
    else if (ds_auth_radius.iec_radius_resp == ied_rar_access_accept) { // accepted
        return true;
    }
    //-------------------------------
    // RADIUS: unknown response
    //-------------------------------
    else { // unknown
        ads_wsp_helper->m_logf(ied_sdh_log_error, "HSOCE132E: Unknown RADIUS response in DEF_AUX_RADIUS_QUERY.");
        return false;
    }
}

