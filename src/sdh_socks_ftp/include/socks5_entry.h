/*+-----------------------------------------------------------------------------------------+*/
/*|                                                                                         |*/
/*| FILE NAME:                                                                              |*/
/*| -------------                                                                           |*/
/*|  Server-Data-Hook for WebSecureProxy, which acts as a SOCKS4/SOCKS5 server (RFC 1928    |*/
/*|  and 1929); SOCKS4A is not supported (because we cannot resolve the domain name via WSP)|*/
/*|  Implementation: State machine; see original by KB ilt_sdh_socks5_1.cpp                 |*/
/*|  (KB's programm has some disadvantages:                                                 |*/
/*|        1) no authentication mechanism was implemented;                                  |*/
/*|        2) if the received data are split to more gather structures, e.g.                |*/
/*|      {0x05, 0x4, 0x08 |-| 0x02, 0x00, 0x09}, only the first structure was processed !! )|*/
/*|  Supported Authentication Methods: username/password; (NO AUTH -> configurable by       |*/
/*|     socks5::bo_no_auth_allowed) (not supported: GSSAPI)                                 |*/
/*|  Supported Client Commands: CONNECT; (not supported: BIND; UDP)                         |*/
/*|  Supported Address Types: IPv4 (4 octets); IPv6 (16 octets); domain name                |*/
/*|                                                                                         |*/
/*|    RADIUS authentication implemented (flag bo_radius_on), but never tested              |*/
/*|                                                                                         |*/
/*| PROJECT NAME:    SocksServer                                                            |*/
/*| -------------                                                                           |*/
/*|  Joachim FRANK        April 2006                                                        |*/
/*|                                                                                         |*/
/*| COPYRIGHT:                                                                              |*/
/*| ----------                                                                              |*/
/*|  Copyright (C) HOB 2011                                                                 |*/
/*+-----------------------------------------------------------------------------------------+*/

//------------------------------------------------------------------------------------------------------------
// version
// 2.3.0.21  11.03.11  Ticket[21668]: If the server closed the connection, we close the connection to the client, too. Otherwise the client will send
//                     data on this connection to us, but we have no more a server connection -> the data will get lost.
//                     The new SDH-interface (with sending direction) is implemented.
// 2.3.0.20  25.01.11  If there is no configuration section, do not treat this as an error.
// 2.3.0.19  12.01.11  Ticket[21346]: RFC 1928 states, that the IP of the adapter, over which the connection is established to the target server, and the
//                     according local port must be sent back to client.
//                     Support for IPv6 implemented.
//                     Logging is now done with ds_wsp_helper.
//                     ds_hstrings implemented.
// 1.0.0.18  25.10.10  Ticket[20013]: You can configure an IPv4 address as <out-adapter-ipv4> in the <configuration-section> of Socks5Dll. This address
//                     will be returned to the Socks5-client. Additionally a port can be specified as <out-port>. If <out-adapter-ipv4> is specified
//                     but no port, then the fixed port number 64664 will be returned to client.
// 1.0.0.17  16.03.09  Built for CD.
//                     All printf are done via WSP.  
// 1.0.0.16  19.09.07  Ticket[12810]: read WSP's version number;
// 1.0.0.15  14.06.07  SOCKS_dll used wrong format of message identifiers ('sdh_socks5' or 'HIWSE001E') -> changed to HSOCE001E;
// 1.0.0.14  23.05.07  avoid NULLPointer !!
// 1.0.0.13  07.05.07  Ticket[12542]: detailled error numbers are returned to client, if no connection could be established to a server
// 1.0.0.12  12.03.07  built for CD
// 1.0.0.11  30.01.07  built for shipment (was not shipped; only inhouse); displayed incorrect name under Windows (e.g. "x86", although it was 'x64')
// 1.0.0.10  11.01.07  m_select_auth_method() improved: without this define we will respond to
//                       a request for authentication with ONLY username/password 0x05 0x01 0x02 with 0x01 0x00 instead of 0x01 0xFF 
// 1.0.0.9   19.12.06  support of fully-qualified domain names as server address
//                       checking for NULL-pointer (fTrace)
// 1.0.0.8   07.12.06  
// 1.0.0.7   15.11.06  ported to Linux32;
//                       it must be allowed, that <configuration-section> does not exist
// 1.0.0.6   16.10.06  xerces_2_7_0 is used from now on; version for shipment (Win32,Itanium, x64)
// 1.0.0.5   21.08.06  unnecessary items deleted; version for shipment
// 1.0.0.4   24.07.06  support for Socks4; Socks4A is not supported!
// 1.0.0.3   13.07.06  compilation with new headers is now possible
// 1.0.0.2   30.06.06  we reported the address/port of the server, to which we connected, as 0x00s to the client
// 1.01      28.03.06  new project

#ifndef SDH_SOCKS5_ENTRY_H
#define SDH_SOCKS5_ENTRY_H

#include "rdvpn_globals.h"
#include "socks5.h"
#include <sdh_version.h>
#include <ds_wsp_helper.h>


#ifdef HL_UNIX
    #define LOGFILE_PATH          "../log/" 
#else
    #define LOGFILE_PATH          "..\\log\\" 
#endif

// <flags>
#define FLAG_DO_TRACE                       1  // set this flag to write received and returned data into a file

//#define SOCKS_CNF_NODE_OUT_PORT          "out-port"
//#define SOCKS_CNF_NODE_OUT_ADAPTER_IPV4  "out-adapter-ipv4"

// states of a session
#define PHASE_NEGO_AUTH_METH                1  // negotiation for authentication method is in progress  
#define PHASE_AUTH_USERNAME_PASSWORD        2  // authentication is in progress (username/password)
#define PHASE_AUTH_GSSAPI                   3  // authentication is in progress (GSSAPI)
#define PHASE_REQUEST                       4  // request by client is in progress
#define PHASE_WORK_PROXY                    5  // data processing as proxy

// Address types; specified in RFC 1928.
#define ATYP_IPv4        0x01 
#define ATYP_DOMAINNAME  0x03
#define ATYP_IPv6        0x04

struct ds_manage_buf { // manages the session buffer
    int            in_id;
    int            in_phase; // phase of SOCKS5:  
    socks5*        cla_socks5;
    char           ch_socks5[sizeof(socks5)];
};

struct ds_my_conf { // parameters of the configuration
    dsd_sdh_log_t ds_logfile;
    int           in_flags;  // e.g. whether to write a trace file
    //char          rch_out_adapter_ipv4[5]; // zero-terminated
    //char          rch_out_port[3];         // zero-terminated
};


void m_print_out_conf(struct dsd_hl_clib_dom_conf *ads_conf, char* ach_to_print);

void m_read_config_from_file_section(struct dsd_read_config* ads_read_config, ds_wsp_helper* ads_wsp_helper);
int m_write_config_to_memory(struct dsd_read_config * ads_read_cfg, char* ach_cnf_buf);

#endif  // SDH_SOCKS5_ENTRY_H
