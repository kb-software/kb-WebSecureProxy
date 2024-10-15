/*+-----------------------------------------------------------------------------------------+*/
/*|                                                                                         |*/
/*| FILE NAME:                                                                              |*/
/*| -------------                                                                           |*/
/*|  Server-Data-Hook for WebSecureProxy, which guards user authentication and then         |*/
/*|  supports download of e.g. HOB-applets and/or connects to another WebServer             |*/
/*|                                                                                         |*/
/*| PROJECT NAME:    WebServer/-Gate                                                        |*/
/*| -------------                                                                           |*/
/*|  see FILE NAME decription                                                               |*/
/*|  Joachim FRANK   June 2007                                                              |*/
/*|  Michael Jakobs 2009                                                                    |*/
/*|                                                                                         |*/
/*| COPYRIGHT:                                                                              |*/
/*| ----------                                                                              |*/
/*|  Copyright (C) HOB 2008 - 2012                                                          |*/
/*+-----------------------------------------------------------------------------------------+*/

/* Annotation to compression (from homepage of zlib:  http://www.gzip.org/zlib/zlib_faq.html#faq20)
What's the difference between the "gzip" and "deflate" HTTP 1.1 encodings? 
"gzip" is the gzip format, and "deflate" is the zlib format. They should probably have called the second one "zlib"
instead to avoid confusion with the raw deflate compressed data format. While the HTTP 1.1 RFC 2616 correctly points
to the zlib specification in RFC 1950 for the "deflate" transfer encoding, there have been reports of servers and browsers
that incorrectly produce or expect raw deflate data per the deflate specficiation in RFC 1951, most notably Microsoft.
So even though the "deflate" transfer encoding using the zlib format would be the more efficient approach (and in fact exactly
what the zlib format was designed for), using the "gzip" transfer encoding is probably more reliable due to an unfortunate
choice of name on the part of the HTTP 1.1 authors.
Bottom line: use the gzip format for HTTP 1.1 encoding.
*/

// TODO
//Ticket[6847]: if HTTP/1.0, then the server side must close the connection

/*
	Following lines are part of the documentation for the BSI.
	They descripe our modules and how they are related to the high level design.
	The documentation is done via DoxyGen, so special comments are used.
*/

/*! \mainpage HOB WebServer and WebServer Gate
 *
 * Introduction
 * ============
 *
 * This module handles incoming HTTP requests, reads requested files from the disk
 * and delievers them to the client. It manages also the virtual links and the portlets
 * a user can access.
 *
 * Components
 * ========== 
 *
 * ### WebServer ###
 * + Landing Page
 * + File Reader
 * + HTTP Creator and Responder
 * + Authentication
 *
 * ### WebServer Gate ###
 * + Data Processor
 *
 * ### WSP Callback ###
 *
 * ### Session Handler ###
 *
 * ### Working Interface ( Server Data Hook ) ###
 *
 * ### Configuration Reader ###
 *
 * ### Configuration Interface ###
 */

/*! @defgroup authlib Authentication Library
 *
 * \brief Handles Authentication to RDVPN
 *
 * The Authentication Library is responsible for every authentication to RDVPN.
 * It is used to authenticate users against LDAP, Kerberos or Radius.
 * It can also handle session tickets.
 */


/*! @defgroup webserver Integrated WebServer
 *
 * \brief Handles HTTP Requests to RDVPN
 *
 *  Accepts HTTP requests and delievers the start pages
 */

/*! @defgroup webservergate WebServer Gate
 *
 *  \brief Manipulates requested WebPages
 *
 *  Transforms HTML, CSS and Javascript data, so that it can be accessed secure
 */

/*! @defgroup filereader File Reader
 *  @ingroup webserver
 *
 *  \brief Reads requested files from the disk
 *
 *  Reads requested files from the disk and gives it to the webserver.
 */

/*! @defgroup landingpage Landing Page
 *  @ingroup webserver
 *
 *  \brief Start Page for RDVPN
 *
 *  This module includes the functions, which create the landing page with all the functionalities
 */

/*! @defgroup dataprocessor Data Processor
 *  @ingroup webservergate
 *
 *  \brief Deals with HTML, CSS and Javascript
 *
 *  Parses data and transforms it
 */

/*! @defgroup creator HTTP Creator and Responder
 *  @ingroup webserver
 *
 *  \brief Creates and responds to HTTP requests
 *
 *  Parses HTTP and assembles appropriate answers
 */

/*! @defgroup authentication CMA Authentication
 *  @ingroup webserver
 *
 *  \brief Authenticates a user to the CMA
 *
 *  Authentication and data handling in the CMA
 */

/*! @defgroup wspcallback WSP Callback
 *
 *  \brief Callback method which is called by the WSP
 *
 *  Functions which interact with the WSP
 */

/*! @defgroup sessionhandler Session Handler
 *
 *  \brief Session Handler
 *
 *  This module decides, to where the data is given and which handler is called
 */

/*! @defgroup winterface Working Interface
 *
 *  \brief Server Data Hook
 *
 *  This is the entry point where the WSP handles the control to this Server Data Hook.
 *  Additionally, there is a component which is a wrapper for the WSP auxiliary function interface
 */

/*! @defgroup cinterface Configuration Interface
 *
 *  \brief Callback method which is called by the WSP
 *
 *  The WSP calls this function to give the webserver its configuration
 */

/*! @defgroup configuration Configuration Reader
 *
 *  \brief Reads parts of the configuration XML
 *
 *  Here the configuration is parsed and stored
 */

//------------------------------------------------------------------------------------------------------------
// version
// 2.3.0.37 26.06.12  Ticket[23699]: script interpreter could loose white spaces after replacing some data
// 2.3.0.36 05.06.12  Ticket[24234]: virtual path should not be checked by "HOBnet"
// 2.3.0.35 05.06.12  Ticket[24235]: extended port for jnlp files
// 2.3.0.34 24.05.12  fixed a bug while switching from preauth cookies to postauth cookies
// 2.3.0.33 10.05.12  fixed a bug in processing of ica files
// 2.3.0.32 08.05.12  modified ica integration
//                    we are now supporting mutliple sessions over wsp-passthrough
// 2.3.0.31 26.04.12  fix for: webserver could crash while going through the list of virtual links
// 2.3.0.30 10.04.12  Ticket[23724], fixed problems with radius authentication and configuration ldap
//                    if cn is different than sAMAccountName
// 2.3.0.29 05.04.12  merged fixes for Ticket[23556] from wsg 5
//          05.04.12  enlarged random in preauth cookie
// 2.3.0.28 04.04.12  fixed Ticket[23613] (HTML injection in login page)
//                    fixed Ticket[23747] (HTML injection in wsplog page)
// 2.3.0.27 20.02.12  fixed a bug in wfa startup
// 2.3.0.26 19.02.12  bookmark support for wfa
// 2.3.0.25 16.02.12  random port support for ica integration
//                    use dn for forced LDAP password change (due to some modifications in LDAP modul)
// 2.3.0.24 12.02.12  Added checks for globaladmin extentsions to be only accessable
//                    if globaladmin portlet is enabled
// 2.3.0.23 12.02.12  Fixed storing the content body for POST requests on virutal links
// 2.3.0.22 09.02.12  Added Content-MD5 for HEAD requests
// 2.3.0.21 29.01.12  Removed some unused and old stuff (like ignore interpreter configuration)
//                    all virtual links will now be ignored by wsg
//                    moved wsg enabled/disabled to visibilty of portlet
//                    RDVPNUpdater is accessibel if admin portlet is allowed
// 2.3.0.20 23.01.12  Fixed a bug in chunked-length handling
//                    first version with new hobwspat3
// 2.3.0.17 21.10.11  Citrix Java ICA Client Integration (JICA) for webservergate
//                    some bugfixes merged from ws5
// 2.3.0.16 15.04.11  we are now support kickout of multiple sessions at one time
// 2.3.0.15 04.04.11  'realm' replaced with 'domain' in source files and configuration files. 
//          31.03.11  Ticket[21758]: Problems with chunked data, which are split to several gather-items.
//          24.03.11  Superfluous calls to ds_transaction.m_close_connection() were removed.
//                    ds_transaction.m_mark_as_processed(NULL) must be called before we close a connection with ds_transaction.m_close_connection().
//                    If the delivered http header 'Host' does not match the configured one, we forward to the configured host name. When we received
//                    payload data in this case (e.g. a POST was received), we must read the whole data, before we do the redirection.
//          22.03.11  Ticket[21567]: Scenario: The URL to an external webserver contains an IPv6 address; example:
//                    GET /http://%5B2003:100:1000:e40:f171:9052:9abd:b142%5D HTTP/1.1 (%5B=[;%5D=]). When WebserverGate (TCP-)connects to external
//                    webserver, we must pass '2003:100:1000:e40:f171:9052:9abd:b142' to WSP. The http-header-field 'Host' must have the
//                    value '[2003:100:1000:e40:f171:9052:9abd:b142]'.
//          22.03.11  MJ password change on request and warning if password will expire
// 2.3.0.14 16.03.11  Usage of flag dsd_hl_clib_1.boc_callrevdir was reduced (especially in case of SPNEGO). Some items could not be
//                    removed, but KB stated that this is no problem, "the flag will remain in his code".
// 2.3.0.13 15.03.11  MJ PPPTunnel to hsl (version for beta CD04)
//          07.03.11  JF Ticket[21611]: The placeholders in system-parametrs were changed from %TEXT:username; %TEXT:password to %TEXT:wsp_userid; %TEXT:wsp_password.
//          03.03.11  JF Ticket[21611]: On client side another Precomp runs, so we must twice duplicate '%' inside username/password of system-parameters.
// 2.3.0.12 08.02.11  Ticket[21462]: GET '/' is back to the two possibilities:
//                                   1.) user is not authenticated -> to login page
//                                   2.) user is authenticated     -> forward site after auth
// 2.3.0.11 02.02.11  Ticket[21458] Find and replace placeholder for language in jnlp files.
// 2.3.0.10 24.01.11  Ticket[21382] Find and replace placeholder for SystemParameters in jnlp files.
// 2.3.0.9  21.01.11  Parsing of http header improved: Only look for 0x0a as line separators; ignore 0x0d.
//          20.12.10  Pipelining for WSG improved.
//          10.12.10  Ticket[21184]: Support of pipelining: When there is a GET/HEAD (pipelined POST is not supported!) and there
//                    are outstanding input data, we assume that the client sent a pipelined request. Then we will tell WSP to call us again.
//          06.08.10  More readable error messages, when connect to external web server fails.
//                    Ticket[20401]: Virtual links implemented.
//          06.07.10  Ticket[20231]: Support of multiple PPP-Tunnels added.
//          22.06.10  Ticket[20167]: ALWAYS check the header 'Content-Encoding'. If there is an encoding, the data must be decoded.
//          17.05.10  Ticket[19966]: ds_control: Do not return to WSP. Instead go on with parsing.
// 2.3.0.8  07.05.10  First version with Xerces 3.1
//          26.04.10  Ticket[19810]: Solution for SSO with 'Basic Authentication': 
//                       1) Trying a SingleSignOn to an external web server (which requests 'Basic Authentication') with the RDVPN-Login-credentials
//                          can be disabled by ORing the settings value with SETTING_DISABLE_SSO_AUTH_BASIC (=64). 
//                       2) The SSO is done for each TCP connection: When the web server responds with 'Unauthorized', we try the authorization with
//                          RDVPN-credentials. If this succeeds, the credentials will always be inserted into all requests on THIS TCP CONNECTION. If SSO fails,
//                          the 'Unauthorized' is passed to the browser, where the user can insert his credentials. 
//                       ATTENTION: A more sophisticated solution
//                       a) would consider the hostname and path to determine, whether the credentials shall be inserted. 
//                       b) would store the hostname, path and the according credentials in a CMA for using them on each connection. 
//                          This would avoid, that we try SSO on each new connection (there might be scenarios were the web server would block, when
//                          too many invalid logins are performed)! 
//          07.10.09  Ticket[18618]: HDR_MODE_CONTENT_LENGTH added, to prevent chunking and compression
//          02.10.09  Ticket[18603]: If there is for example in_len_ppp_address=0, we must use the value 1 for the calculation of the
//                    required memory, because the char* in the configuration-structure points to a ZERO-TERMINATED memory.
//          21.09.09  Reject URLs like /abc/file%00name.txt -> the URL would be cut by zero-termination!
// 2.3.0.2  22.07.09  using authentication from wspat/ds_wsp_helper class
//                    including wspat project (linked as a library from lib_hobwspat project)
// 2.3.0.1  22.06.09  new project merged from ws5 and ws6
//------------------------------------------------------------------------------------------------------------

//-----------------------------------
//    format of message identifier: HIWSE000E
//    example of KB: HWSPS061I
//    HIWS = HobIntegratedWebServer
//    E    = similar to S (I don't know, what this character is good for; I made it equal to type, to allow easier searching for nextfree number)
//    000  = 3-digit-number
//    I    = Type (I=Information, W=Warning, E=Error)
//-----------------------------------


#ifndef SDH_WEB_SERVER_H
#define SDH_WEB_SERVER_H

#include <ds_wsp_helper.h>
#include "ds_page.h"
#include "wsg_res.h"
#include "ds_url.h"
#include <ds_hashtable.h>
#include "./wsg/interpreter/ds_attributes.h"
#include <ws_version.h>


#if defined WIN32 || defined WIN64
    #if defined WIN64
        #ifdef _IA64_
            #define HL_CPUTYPE       "IPF"
        #else
            #define HL_CPUTYPE       "EM64T"
        #endif
    #else // WIN32
        #define HL_CPUTYPE           "x86"
    #endif
#else // UNIX
// under UNIX the string will be passed as pre-processor-flag HL_CPUTYPE
#endif
#ifndef HL_CPUTYPE
    #define HL_CPUTYPE           "unknown"   // default
#endif

// MJ 10.06.09:
#ifdef HL_UNIX
    #define LOGFILE_PATH          "../log/"
    #define WEBSERVER_PATH        "plugins/web_server/"  
#else
    #define LOGFILE_PATH          "..\\log\\"
    #define WEBSERVER_PATH        "plugins\\web_server\\"  
#endif

#define SHORT_HF_SERVER              "HOB WSP"
#define STRING_HOB                   "HOB"
#define PLACEHOLDER_CONTENT_LENGTH   "HOB0123456789HOB"

#define USERNAME        "username"
#define PASSWORD        "password"
#define HL_WS_DOMAIN    "domain"
#define KICKOUT         "kick-out"
#define DEF_CREATE_NEW  "create-new"
#define CANCEL          "cancel"
#define SESSION         "session"
#define SHOW_HOMEPAGE   "force-site-after-auth"
#define OLD_PASSWORD    "old-pwd"
#define NEW_PASSWORD    "new-pwd"
#define CONF_PASSWORD   "conf-pwd"
#define STATE           "state"
#define LOGOFF          "logoff"
#define DESTINATION     "destination"
#define CHECK_CLIENT    "check_client"  // Ticket[13661]
#define QUARANTINE      "quarantine"    // MJ 13.02.09, Ticket[16992]

// <settings>
// SETTING 1 is now free
#define SETTING_ENABLE_DECOMPRESSION             1  // set this flag to enable decompression with gzip (deflate is not supported)
#define SETTING_CACHE_XSL                        2  // MJ 11.02.2010: set this flag to cache parsed xsl data in cma
#define SETTING_SEND_NO_SERVER_HF                4  // set this flag to suppress sending the htpp-header field 'Server' to browser
#define SETTING_DO_SYSTEM_CHECK                  8  // print out machines properties (e.g. endiness)
#define SETTING_DISABLE_HTTPS                   16  // set this flag to disable https; means that e.g. "location moved" will use "http://" instead of "https://"
#define SETTING_HOB_NET_OFF                     32  // if this flag is set, the HOB_net is de-activated
#define SETTING_DISABLE_SSO_AUTH_BASIC          64  // Ticket[19810]: set this flag, if you do not want, that WSG will try to process a SSO with 'Basic Authentication' to external webserver
#define SETTING_ENABLE_COMPRESSION             128  // Ticket[14237]: set this flag to enable compression with gzip (deflate is not supported)
#define SETTING_DISABLE_SSO_AUTH_NEGOTIATE     256  // Ticket[19810]: set this flag, if you do not want, that WSG will try to process a SSO with 'Negotiate Authentication' (SPNEGO) to external webserver
#define SETTING_ACT_AS_MOZILLA                 512  // when this flag is set, WSG always sends 'Mozilla' in header field user agent
#define SETTING_DONT_INSERT_FAVICON           1024  // Ticket[18274]: set this flag to disable inserting a favicon if not found in html page
#define SETTING_AUTH_NEGO_NO_OPTIMI_TOKEN     2048  // Ticket[19810]: set this flag, if you want to negotiate the mechanism type (No optimistic token will be included in first request to server)
#define SETTING_AUTH_NEGO_USE_MS_KERB         4096  // Ticket[19810]: set this flag, if you want to use Microsoft's Kerberos OID (1.2.840.48018.1.2.2) instead of MIT Kerberos v5 (1.2.840.113554.1.2.2).
// SETTING  8192 is now free!
#define SETTING_KERB5_NO_MUTUAL              16384  // Ticket[19810]: set this flag, if Kerberos_v5 shall NOT DO mutual authentication
#define SETTING_DISABLE_COOKIE_STORAGE       32768  // Ticket[14905]: set this flag to disable our own cookie storage
#define SETTING_AUTH_NEGO_ONLY_ONCE        0x10000  // Ticket[19810]: set this flag, if the 'Negotiate' header shall be sent only during the establishing of the connection to web server (the first request)
#define SETTING_DISABLE_SUPPORT_PIPELINING 0x20000  // Ticket[21184]: set this flag, to disable the support of pipelining
#define SETTING_ALLOW_EMBEDDED_USE         0x40000  // Ticket[54135]: set this flag, to disable iframe usage suppression

// <flags>
// FLAG  1 is now free!
#define FLAG_WRITE_COMPLETE_FILENAME         2  // write the complete file path into gather.txt
// FLAG  4 is now free!
// FLAG  8 is now free!
// FLAG 16 is now free!
// FLAG 32 is now free!
// FLAG 64 is now free!
#define FLAG_TRACE_COOKIES                 128  // Ticket[14905]: set this flag to activate a cookie trace

#define INVALID   -1
#define LANGUAGE_NOT_SET -1

// JF 25.06.08 Ticket[15237]
#define HDR_MODE_DEFAULT                  0
#define HDR_MODE_CONTENT_LENGTH           0x1
#define HDR_MODE_NO_X_FRAME_OPTION        0x2
#define HDR_MODE_NO_X_FRAME_OPTION        0x2

// HTTP header-field-names
#define HF_ACCEPT_ENCODING    "Accept-Encoding"
#define HF_ACCEPT_LANGUAGE    "Accept-Language"
#define HF_AUTHORIZATION      "Authorization"
#define HF_CACHE_CONTROL      "Cache-Control"
#define HF_CONNECTION         "Connection"
#define HF_CONTENT_ENCODING   "Content-Encoding"
#define HF_CONTENT_LENGTH     "Content-Length"
#define HF_CONTENT_TYPE       "Content-Type"
#define HF_CONTENT_MD5        "Content-MD5"
#define HF_COOKIE             "Cookie"
#define HF_DATE               "Date"
#define HF_HOST               "Host"
#define HF_IF_MODIFIED_SINCE  "If-Modified-Since"
#define HF_LAST_MODIFIED      "Last-Modified"
#define HF_EXPIRES            "Expires"
#define HF_LOCATION           "Location"
#define HF_PRAGMA             "Pragma"
#define HF_REFERER            "Referer"
#define HF_SERVER_VERSION     "Server"
#define HF_SET_COOKIE         "Set-Cookie"
#define HF_TRANSFER_ENCODING  "Transfer-Encoding"
#define HF_USER_AGENT         "User-Agent"
#define HF_WWW_AUTHENTICATE   "WWW-Authenticate"
#define HF_CONTENT_SECURITY_POLICY   "Content-Security-Policy"	// TODO
#define HF_CONTENT_SECURITY_POLICY_REPORT_ONLY  "Content-Security-Policy-Report-Only" // TODO
#define HF_REFERRER_POLICY    "Referrer-Policy"	// TODO
#define HF_UPGRADE            "Upgrade"
#define HF_ORIGIN             "Origin"
#define HF_X_FRAME_OPTIONS    "X-Frame-Options" // TODO
#define HF_STRICT_TRANSPORT_SECURITY    "Strict-Transport-Security"
#define HF_X_XSS_PROTECTION   "X-XSS-Protection"
#define HF_X_CONTENT_TYPE_OPTIONS   "X-Content-Type-Options"
#define HF_X_UA_COMPATIBLE    "X-UA-Compatible" // TODO

// HTTP-header-field-values
#define HFV_CHUNKED   "chunked"
#define HFV_CLOSE     "close"
#define HFV_IDENTITY  "identity"        // for content-encoding
#define HFV_GZIP      "gzip"            // for content-encoding
#define HFV_DEFLATE   "deflate"         // for content-encoding
#define HFV_COMPRESS  "compress"        // for content-encoding
#define HFV_PACK200   "pack200-gzip"    // for content-encoding
#define HFV_WWWAUTH_BASIC     "Basic"     // for WWW-Authenticate
#define HFV_WWWAUTH_DIGEST    "Digest"    // for WWW-Authenticate
#define HFV_WWWAUTH_NEGOTIATE "Negotiate" // for WWW-Authenticate
#define HFV_WWWAUTH_NTLM      "NTLM"      // for WWW-Authenticate

#define HF_HTTP_0_9         "HTTP/0.9"
#define HF_HTTP_1_0         "HTTP/1.0"
#define HF_HTTP_1_1         "HTTP/1.1"
#define BLANK_HF_HTTP_1_0   " HTTP/1.0"
#define BLANK_HF_HTTP_1_1   " HTTP/1.1"

#define CRLF "\r\n"

#define TAG_SITE_AFTER_AUTH         "<site-after-auth>"
#define END_TAG_SITE_AFTER_AUTH     "</site-after-auth>"
#define TAG_USER_PROFILE            "<user_profile>"
#define END_TAG_USER_PROFILE        "</user_profile>"
#define TAG_CLIENT_CHECK            "<client_check>"
#define END_TAG_CLIENT_CHECK        "</client_check>"

#define REPLACE_LANGUAGE                "<%=language%>"                 // Ticket[21458]
#define REPLACE_SYSTEMPARAMS            "<%=systemparams%>"             // Ticket[21382]
#define REPLACE_USERNAME                "<%=user%>"                     // Ticket[15866]
#define REPLACE_PASSWORD                "<%=password%>"                 // Ticket[15866]
#define REPLACE_CONTEXT                 "<%=context%>"                  // Ticket[15866]
#define REPLACE_SERVER_ENTRY_NAME       "<%=server-entry-name%>"        // Java Web Start PPP Tunnel
#define REPLACE_HSOCKS_STICKET          "<%=hsocks-sticket%>"           // hobphone
#define REPLACE_HTTP_COOKIE             "<%=httpcookie%>"               // hobphone
#define REPLACE_HOME_PRE                "%TEXT:home;"
#define REPLACE_HOME                    "<%=home%>"                     // Ticket[6654]
#define REPLACE_URL_JNLP                "<%=url_jnlp%>"                 // Ticket[14129]
#define REPLACE_JWTSA_CONFIG_URL		"<%=jwtsa_config_url%>"
#define REPLACE_JWTSA_CONFIG			"<%=jwtsa_config%>"
#define REPLACE_WEBTERM_MODE			"<%=webterm_mode%>"
#define REPLACE_WEBTERM_NAME			"<%=webterm_name%>"
//#define REPLACE_WEBTERM_PROT			"<%=webterm_prot%>"
#define REPLACE_WEBTERM_URL			    "<%=webterm_url%>"
#define REPLACE_WEBTERM_SESS			"<%=webterm_session%>"
#define REPLACE_HCLIENT_CFG             "<%=client-cfg%>"
#define REPLACE_HCLIENT_CDB             "<%=client-cdb%>"
#define REPLACE_HCLIENT_PWD             "<%=client-pwd%>"
#define REPLACE_HIGH_ENTROPY            "<%=high-entropy%>"
#define REPLACE_HSOCKS_USER             "<%=hsocks-user%>"
#define REPLACE_SESSIONTICKET           "<%=sessionticket%>"
#define REPLACE_WSP_URL                 "<%=wsp-url%>"
#define REPLACE_WSP_PORT                "<%=wsp-port%>"
#define REPLACE_PROPS_FILE              "<%=props_file%>"
#define REPLACE_NAME_JWS                "<%=name_jws%>"
#define REPLACE_WSP_INETA               "%TEXT:wsp_ineta;"              // Ticket[14262]
#define REPLACE_WSP_L2TP_ARG            "%TEXT:wsp_l2tp_arg;"           // Ticket[14262]
#define REPLACE_WSP_SOCKS_MODE          "%TEXT:wsp_socks_mode;"         // Ticket[14262]
#define REPLACE_WSP_LOCALHOST           "%TEXT:wsp_localhost;"          // Ticket[14262]
#define REPLACE_WSP_UNIX_PARAMETER      "%TEXT:wsp_unix_parameter;"     // Ticket[16598]
#define REPLACE_PPP_SYSTEM_PARAMETERS   "%TEXT:wsp_system_parameters;"  // Ticket[17719]

#define  COOKIE_PATH      "path=" 
#define  COOKIE_DOMAIN    "domain="


#define PATH_FORCE_LOGOUT_PAGE              -10
// #define PATH_LOGOUT_PRE_PAGE_REQUESTED    -9
#define PATH_LOGOUT_PAGE_REQUESTED           -8
#define PATH_ACCESS_DENIED                   -7
#define PATH_GET_FAVICON                     -6
#define PATH_GET_SLASH_IS_NOT_LOGOFF         -5
#define PATH_URL_IS_SLASH                    -4
#define PATH_LOGIN_PAGE_REQUESTED            -3
#define PATH_FORCE_LOGIN_PAGE                -2
#define PATH_ERROR                           -1
#define PATH_AUTHENICATION_REQUIRED           0    // Authentication is required to get this page  
#define PATH_PUBLIC                           1    // A file underneeth folder "/public" was requested


#define LEN_COOKIE_STRING   256  // max len of a string placed to HTTP-header "Set-Cookie"
#define LEN_PATH           2000  // Ticket[11522]:  512 // len of file path for the file to return
#define MAX_AGE_LOGIN_COOKIE "604800" // maximal age of the cookie which sets username / domain at login site
#define HOBWSP_USER "HOBWSP_USER="
#define HOBWSP_DOMAIN "HOBWSP_DOMAIN="

#define CRLF_CRLF  "\r\n\r\n"

#define CNF_NODE_ROOT_DIR               "root-dir"
#define CNF_NODE_DLL_PATH               "dll-path"          // path to folder containing res.xml (if unset, [wsp_working_dir]/plugins/web_server/ is used; see also WEBSERVER_PATH)
#define CNF_NODE_HTTP_HOST              "http-hostname"
#define CNF_NODE_BOOKMARK_HOST          "bookmark-hostname"
#define CNF_NODE_SITE_AFTER_AUTH        "site-after-auth"
#define CNF_NODE_SHOW_SAA_CHECKBOX      "show-site-after-auth-checkbox"
#define CNF_NODE_GUI_SKIN               "gui-skin"
#define CNF_NODE_COMPRESSION            "compression"       // Ticket[14903]
#define CNF_NODE_CLUSTER_URL            "cluster-url"       // cluster URL (for node-independent bookmarks)
#define CNF_NODE_RES_XML_PATH           "res-xml-full-path" // full path to res.xml (if unset, [wsp_working_dir]/plugins/web_server/res.xml is used; see also WEBSERVER_PATH)
                                                            // overwrites (and replaces) the badly chosen old <dll-path>
// [16125]
#define CNF_NODE_MAX_LEN_HEADER_LINE        "max_len_header_line"
#define CNF_NODE_MAX_COUNT_HEADER_LINES     "max_count_header_lines"
#define HOB_MAX_LEN_HEADER_LINE_DEFAULT     8192
#define HOB_MAX_COUNT_HEADER_LINES_DEFAULT  100

//// log
//#define CNF_NODE_LOG                    "log"
//#define CNF_NODE_LOG_FILE               "file"
//#define CNF_NODE_LOG_ENABLE             "enable"
//#define CNF_NODE_LOG_LEVEL              "level// Webterm Server Entries

// Webterm Configuration in XML
#define CNF_NODE_WEBTERM_SERVER_LIST	"webterm-server-list"
#define CNF_NODE_WEBTERM_SERVER_ENTRY	"server-entry"
#define CNF_NODE_WEBTERM_SERVER_NAME	"name"
#define CNF_NODE_WEBTERM_SUBPROTOCOL	"subprotocol"
#define CNF_NODE_WEBTERM_SESSION        "session"

// HOB-PPP-Tunnel
#define CNF_NODE_PPP_TUNNEL             "HOB-PPP-Tunnel"
#define CNF_NODE_PPP_ADDRESS            "address"
#define CNF_NODE_PPP_SERVER_ENTRY_NAME  "server-entry-name"
#define CNF_NODE_PPP_COMMAND_LINE       "command-line"
#define CNF_NODE_PPP_LOCALHOST          "localhost"
#define CNF_NODE_PPP_ENABLED            "enabled" // Ticket[18118]
#define CNF_NODE_PPP_UNIX_PARAMETER     "unix_parameter" // Ticket[16598]
#define CNF_NODE_PPP_UNIX_PARAMETER_DASH "unix-parameter"
#define CNF_NODE_PPP_SYSTEM_PARAMETERS  "system-parameters" // Ticket[17719]
// SSO
#define CNF_NODE_SSO                    "SSO"
#define CNF_NODE_SSO_PAGE               "page"
#define CNF_NODE_SSO_PAGE_IDLIST        "ID-list"
#define CNF_NODE_SSO_PAGE_IDLIST_ACTION L"action"
#define CNF_NODE_SSO_PAGE_IDLIST_FORM   L"form"
#define CNF_NODE_SSO_PAGE_IDLIST_ID     "ID"
#define CNF_NODE_TYPE                   "type"
#define CNF_NODE_NAME                   "name"
#define CNF_NODE_VALUE                  "value"
// SettPrecomp
#define CNF_NODE_SETTPRECOMP             "SettPrecomp"
#define CNF_NODE_SETTPRECOMP_EXTENSIONS  "extensions"
#define CNF_NODE_SETTPRECOMP_EXT         "ext"
#define CNF_NODE_SETTPRECOMP_FILES       "files"
#define CNF_NODE_SETTPRECOMP_FILE        "file"

#define CNF_NODE_VIRTUAL_LINK           "virtual-link" // JF 06.08.10 Ticket[20401]
#define CNF_NODE_VIRTUAL_DIR            "virtual-dir"
#define CNF_NODE_ALIAS                  "alias"
#define CNF_NODE_PATH                   "path"
#define CNF_NODE_URL                    "url"

// webserver server-list
#define CNF_NODE_WS_SRV_LST             "ws-server-list"
#define CNF_NODE_WS_SRV_LST_NAME        "name"
#define CNF_NODE_WS_SRV_LST_SRV_ETR     "server-entry"
#define CNF_NODE_WS_SRV_LST_SRV_ETR_FNC "function"
#define CNF_NODE_WS_SRV_LST_SRV_ETR_URL "url"

// ica url ending:
#define CNF_NODE_ICA_LOGIN              "ica-login"
#define CNF_NODE_ICA_SESSION            "ica-session"

#define FOLDER_PUBLIC               "/public/"
#define VIRTUAL_DIRECTORY           "/public/lib/hob-virtual/"
#define USERDATA_APPLET_PAGE        "/public/lib/hob-virtual/userdata_applet.html"
#define USERDATA_PASSWORD_PAGE      "/public/lib/hob-virtual/pwd.html"

#define SETTINGS_PAGE               "/protected/portlets/settings/settings.hsl"
#define CHANGE_PWD_PAGE             "/protected/change-password.hsl"

#define ICA_PORT_PAGE              "/protected/wsg/ica-port"
#define ICA_CLOSE_PAGE             "/protected/wsg/ica-close"
#define ICA_ALIVE_PAGE             "/protected/wsg/ica-stillalive"
#define QUARANTINE_HSL             "/protected/quarantine/quarantine.hsl"
#define INSTALL_AST_HTML           "/protected/quarantine/install/ast/install.htm"

#define GLOBAL_START_SITE           "/public/login.hsl"
#define GLOBAL_LOGOUT_PAGE          "/public/logout.hsl"

#define HOBWEBFILEACCESS            "/WebFileAccess"
#define HOBWFA_LOGIN                "/WebFileAccess/start"
#define HOBWFA_SAVE_BMARKS          "/WebFileAccess/edit_bookmark"
#define RDVPNUpdater                "/RDVPNUpdater"
#define RDVPNDirectoryServices      "/RDVPNDirectoryServices"
#define RDVPNCertificateManager     "/RDVPNCertificateManager"
#define RDVPNPluginManager          "/RDVPNPluginManager"
#define JWTSAREQUEST				"/protected/portlets/jwtsa/JWT.jnlp"
#define WEBTERMRDPPAGE				"/protected/portlets/webtermrdp/webtermrdp.hsl"

#define FILE_HOBSCRIPT_JS        "HOBwsg.js"
#define FILE_HOBHOME_JS          "HOBHome.js"
#define FILE_EXT_HTML            ".html"
#define FILE_EXT_HTM             ".htm"
#define FILE_EXT_JNLP            ".jnlp"
#define FILE_EXT_JAR             ".jar"
#define FILE_EXT_PACK_GZ         ".pack.gz"
#define FILE_EXT_TEMPLATE        ".hsl"
#define FILE_ERROR_TEMPLATE      "/public/error.hsl"

#define PORTLETS_DIRECTORY      "/protected/portlets/"

/* TODO! insert new portlets! jwtsa and webtermrdp */
static const dsd_const_string achg_known_portlets[] = {
    "wsg",
    "jterm",
    "wfa",
    "ppptunnel",
    "globaladmin",
    "settings"
};
enum ied_known_portlets {
    ied_unknown_portlet = -1,
    ied_wsg_portlet       =  0,
    ied_jterm_portlet     =  1,
    ied_wfa_portlet       =  2,
    ied_ppp_portlet       =  3,
    ied_globaladm_portlet =  4,
    ied_settings_portlet  =  5
};

// MJ 30.07.08, Ticket[15446]:

// for avoiding problems with opera (whose first GET will be "/favicon.ico")
#define PATH_FAVICON       "/favicon.ico"

#define DEFAULT_DELAY_TIME    90

// MJ 08.06.09: use storage container:
#define SDH_STORAGE_SIZE    64 * 1024


//-----------
// Virtual Link(s)
//-----------
/*! \brief Virtual Link
 *
 * @ingroup webserver
 *
 *  This data structure represents a virtual link target
 */
struct dsd_virtual_link {
    int               in_len_alias;     //!< length of alias
    char*             ach_alias;        //!< alias
    int               in_len_url;       //!< length of url
    char*             ach_url;          //!< url
    int               in_protocol;      //!< protocol of url; 0=http; 1=https
    int               in_port;          //!< port of url
    int               in_len_authority; //!< length of authority of url
    char*             ach_authority;    //!< authority of url
    int               in_len_path;      //!< length of path of url
    char*             ach_path;         //!< path of url
    dsd_virtual_link* adsc_next;        //!< pointer to next dsd_virtual_link
};


//-----------
// PPP-Tunnel
//-----------
/*! \brief PPP Tunnel
 *
 * @ingroup webserver
 *
 *  This data structure represents a ppp tunnel target
 */
struct dsd_pppt {
    int              in_id;                    //!< ID of this configuration
    int              in_len_address;           //!< length of address
    char*            ach_address;              //!< address
    int              in_len_localhost;         //!< length of localhost
    char*            ach_localhost;            //!< localhost
    int              in_len_server_entry_name; //!< length of server-entry-name
    char*            ach_server_entry_name;    //!< server-entry-name
    int              in_len_system_parameters; //!< length of system_parameters
    char*            ach_system_parameters;    //!< system_parameters
    dsd_pppt*        adsc_next;                //!< pointer to next dsd_pppt
};

//-----------
// SSO
//-----------
/*! \brief Single Sign On
 *
 * @ingroup webserver
 *
 *  Structure which is used for single sign on
 */
struct dsd_id {
    char*            achc_name;             //!< name of this ID
    int              inc_len_name;          //!< length of ID name
    char*            achc_value;            //!< value of this ID (e.g.: "#{username}")
    int              inc_len_value;         //!< length of value
    char*            achc_type;             //!< type of this ID (e.g.: "input")
    int              inc_len_type;          //!< length of type
    dsd_id*          adsc_next;             //!< next ID
};

/*! \brief Web Page
 *
 *  Linked structures for a Web Page
 */
struct dsd_page {
    char*            achc_name;             //!< page name
    int              inc_len_name;          //!< length of page name
    char*            achc_url;              //!< url
    int              inc_len_url;           //!< length of url
	 ds_url::dsd_base_url dsc_url;			  //!< URL information
    dsd_id*          adsc_ids;              //!< IDs
    dsd_page*        adsc_next;             //!< next page
};

/*! \brief Linked Page List
 *
 * @ingroup webserver
 *
 *  Holds reference to the first page in the linked list
 */
struct dsd_sso {
    dsd_page*        adsc_page;             //!< 1st page in chain
};

/*! \brief List of Names
 *
 * @ingroup webserver
 *
 *  Linked List of Names
 */
typedef struct dsd_named_list {
    char                  *achc_name;       /*!< current name              */
    int                   inc_len_name;     /*!< length of name            */
    struct dsd_named_list *adsc_next;       /*!< next list                 */
} dsd_named_list;

//-----------
// Precomp settings
//-----------
/*! \brief Project Internal Precompiler
 *
 * @ingroup webserver
 *
 *  The Precompiler is used to customize sourcecode to special needs
 */
struct dsd_precomp {
    dsd_named_list*  adsc_ext;              //!< 1st extension in chain
    dsd_named_list*  adsc_file;             //!< 1st file in chain
};

/*
    webserver server lists
*/
enum ied_ws_srv_entry_func {
    ied_ws_srv_func_invalid = -1,           /*!< invalid function          */
    ied_ws_srv_func_ica     =  0            /*!< citrix ica integration    */
};

/*! \brief Server Entry
 *
 * @ingroup webserver
 *
 *  Linked List of Server Entries
 */
typedef struct dsd_ws_srv_entry {
    char                       *achc_name;  /*!< server entry name (utf8)  */
    int                        inc_len_name;/*!< length of name            */
    enum ied_ws_srv_entry_func iec_func;    /*!< selected function         */
    char                       *achc_url;   /*!< server url (utf8)         */
    int                        inc_len_url; /*!< length of url             */
	 ds_url::dsd_base_url       dsc_url;
    struct dsd_ws_srv_entry    *adsc_next;  /*!< next websrv server entry  */
} dsd_ws_srv_entry;

/*! \brief Server List
 *
 * @ingroup webserver
 *
 *  Linked Server Lists
 */
typedef struct dsd_ws_srv_lst {
    char                    *achc_name;     /*!< server list name (utf8)   */
    int                     inc_len_name;   /*!< length of name            */
    struct dsd_ws_srv_entry *adsc_entries;  /*!< list of server entries    */
    struct dsd_ws_srv_lst   *adsc_next;     /*!< next server list          */
} dsd_ws_srv_lst;

#ifndef _IED_WEBTERM_SUBPROTOCOL
#define _IED_WEBTERM_SUBPROTOCOL
/*also defined in ds_hobte_conf.h*/
enum ied_webterm_subprotocol {
    ied_webterm_subprotocol_unknown,
    ied_webterm_subprotocol_rdp,
    ied_webterm_subprotocol_ssh,
    ied_webterm_subprotocol_vt525,
    ied_webterm_subprotocol_tn3270,
    ied_webterm_subprotocol_tn5250,
    ied_webterm_subprotocol_tedefault
};
#endif

/*
*	Webterm server with "server entry" name and protocol name
*	see configuration section of the webserver in the wsp.xml
*/
typedef struct dsd_webterm_server
{
	char						*achc_server_name;
	int							inc_len_server_name;
	char						*achc_protocol_name;
	int							inc_len_protocol_name;
    char						*achc_session_name;
	int							inc_len_session_name;
    ied_webterm_subprotocol     iec_subprotocol;
    ied_webterm_protogroup      iec_protogroup;
	struct dsd_webterm_server	*adsc_next;
} dsd_webterm_server;

class ds_resource;

/*! \brief Configuration Parameters
 *
 * @ingroup webserver
 *
 *  Holds the configuration for a user which is logged in
 */
struct ds_my_conf {
    dsd_sdh_log_t ds_logfile;   // MJ 02.11.09 (Must be first element)
	struct dsd_stor_sdh_1 dsc_storage;
	ds_wsp_helper dsc_wsp_helper;
    // MJ 08.03.10, removed (SDH could be called from different connections) int         in_http_port;
    int         in_max_len_header_line; //!< Ticket[16125]: determines the maximum line length limit. If set to a positive value, any HTTP line exceeding this limit will cause an "400 Bad Request". A negative or zero value will effectively disable the check.
    int         in_max_count_header_lines; //!< Ticket[16125]: determines the maximum HTTP header count allowed. If set to a positive value, the number of HTTP headers received from the data stream exceeding this limit will cause an "400 Bad Request". A negative or zero value will effectively disable the check.
	 int         in_max_request_payload; //!< determines the maximum length limit of posted data
    int         in_settings;
    int         in_flags;
    int         in_count_alias_path;
    dsd_const_string        ach_hostname;
    dsd_const_string        ach_bookmark_host;
    dsd_const_string        ach_hf_server;
    dsd_const_string        ach_login_site;
    dsd_const_string        ach_site_after_auth;
    dsd_const_string        ach_gui_skin;
    dsd_const_string        ach_dll_path;
    dsd_const_string        ach_root_dir;
    dsd_const_string        ach_cluster_url;
    dsd_const_string        ach_res_xml_path;
    
    const char*       ach_alias;
    const char*       ach_path;

    dsd_pppt			*adsl_pppt;   //!< JF 06.07.10 Ticket[20231]: Anchor of the chain of PPP-Tunnel-structures. NULL, if no PPP-Tunnel is configured.
    dsd_virtual_link	*adsl_vi_lnk; //!< JF 06.08.10 Ticket[20401]: Anchor of the chain of VirtualLinks-structures. NULL, if no virtual link is configured.
	dsd_webterm_server	*adsc_webterm_list;

    // Ticket[16715]:
    dsd_sso             dsl_sso;
    dsd_precomp         dsl_precomp;

    // MJ 21.09.09, resources
    ds_resource* av_resource;

    // MJ 09.11.09: wsg attributes:
    ds_attributes ds_wsg_attr;
    bool bo_show_ssa_checkbox; //!< MJ 07.07.2010: show site-after-auth checkbox on login page

    struct dsd_ws_srv_lst *adsc_ws_srv_lst;
    struct dsd_named_list *adsc_ica_login_pages;
    struct dsd_named_list *adsc_ica_session_pages;
};

class ds_session; // forward definition

int m_write_config_to_memory(struct dsd_read_config * ads_read_cfg, ds_wsp_helper* ads_helper, char* ach_cnf_buf, int in_len_cnf_buf);
int m_calc_len_lists(struct dsd_read_config* ads_read_cfg);

void m_system_check(ds_wsp_helper* ads_helper);

#endif  // SDH_WEB_SERVER_H
