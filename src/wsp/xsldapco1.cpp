/*! @mainpage HOB LDAP-client description
 *
 **************************************************************************************************
 * PROJECT:  HOB LDAP CPP-interface.
 *
 * This project implements a complete LDAP interface to any LDAPv3 server.
 *
 * Comment:
 * A LDAP-request is initiated via a call of the function 'm_ldap_request()' or
 * via a call of the function 'm_ldap_auth()'.
 * The functions 'm_ldap_init()' and 'm_ldap_free()' are called as constructor
 * an destructor of the class dsd_ldap.
 * - WIN32 has to be set for 32-Bit version for windows.
 * - WIN64 creates a 64-Bit windows library.
 * - UNIX  is the switch for a Linux Library.
 *
 * Required programs:
 * - MS Visual Studio .NET 2005, 2010 or 2012
 * - MS Linker
 *
 * Copyright (C) HOB Germany 2005-2018
 *
 * @version 1.01.0710

 * @author  Juergen-Lorenz Lauenstein
 * @date    2005/08/16   (creation)
 * @date    2012/07/25   (svn 516)
 * @date    2012/09/18   (svn 531)
 * @date    2012/09/25   (svn 532)
 * @date    2012/10/10   (svn 534)
 * @date    2012/10/11   (svn 536)
 * @date    2012/10/18   (svn 538)
 * @date    2012/11/06   (svn 542)
 * @date    2012/11/21   (svn 547)
 * @date    2012/11/27   (svn 549)
 * @date    2013/01/23   (svn 552)
 * @date    2013/07/04   (svn 590)
 * @date    2013/07/24   (svn 592)
 * @date    2013/11/18   (svn 596)  (ticket 31023)
 * @date    2013/11/28   (svn 599)  (ticket 31180)
 * @date    2014/02/18   (svn 601)
 * @date    2014/03/13   (svn 602)
 * @date    2014/03/27   (svn 603)
 * @date    2014/04/08   (svn 604)
 * @date    2014/04/23   (svn 605)  (ticket 29235)
 * @date    2014/06/24   (svn 609)  (GSS-SPNEGO support)
 * @date    2015/04/14   (svn 642)  (LDS support)
 * @date    2015/04/30   (svn 648)  (OpenDJ with PagedResultsControl)
 * @date    2015/05/04   (svn 652)  (PagedResultsControl not critical)
 * @date    2015/06/02   (svn 657)  (nested group search)
 * @date    2015/07/22   (svn 658)  (LDS password management, group management)
 * @date    2015/07/27   (svn 660)  
 * @date    2015/09/04   (svn 663)  (heap corruption)
 * @date    2017/05/11   (svn 685)  (m_ldap_get_sysinfo(), ticket 48497)
 * @date    2017/06/01   (svn 686)  (ticket 49335)
 * @date    2017/07/02   (svn 688)  (ticket 49335)
 * @date    2017/10/04   (svn 690)  (ticket 30984, 49098)
 * @date    2017/10/12   (svn 691)  (DEBUG messages removed)
 * @date    2017/11/06   (svn 692)  (delete groups after execution of m_ldap_modify_dn())
 * @date    2017/12/07   (svn 710)  (ticket 52901, EA-Admin cannot log in when trying to connect to LDAP database)
 *
 * @todo  save session number, do not use the current number
 * @todo  m_ldap_connect() - wait for a cleanup-event after an error retry
 * @todo  enable support of 'search referral'
 *
 * Defines:
 * - WIN32                  program for windows 32-bit
 * - WIN64                  program for windows 64-bit
 * - HL_UNIX                program for Linux or Unix
 * - HL_DEBUG               hob debug controls
 * - HOB_SSL_BUFFER_CHECK   log output of ssl buffers
 * - DEF_HCU2               set by the HCU2 project
 * - SM_USE_LDAP_AUX_CALL   use DEF_AUX_MEMGET for external storage management
 *
 * - HOB_LDAP_REFERRAL      support of LDAP referrals
 * - HOB_SPNEGO_SUPPORT     support of SPNEGO (KRB5, NTLMv2, NTLM)
 *
 **************************************************************************************************
 *
 * The HOB LDAP-client interface supports a full-functional interface to the following server list:
 * - Microsoft Active Directory
 * - OpenDJ (OpenDS)
 * - Siemens DirX LDAP
 * - IBM Directory Server
 * - iPlanet Directory Server
 * - Novell Directory Server
 * - OpenLDAP
 *
 * The LDAP-configuration is part of the WebSecureProxy-configuration and defines the parameters for
 * the connection like ip-address and port (nonSSL and SSL), the server type (e.g. MSAD), the administrator
 * bind for searching users without a distinguished name-paths and some other parameters. The document
 * [SOFTWARE.HLSEC.DOC-LDAP](@ref page1) contains detailed paragraphs for every parameter. It's recommended
 * to use SSL for a server connection. Some operations like password change in a MSAD-environment require a
 * SSL connection. The HOB-LDAP supports a client-side SSL using the HOB implementation. The document
 * [SOFTWARE.HLSEC.CSSSL01](@ref page2) describes this scenario.
 * Programmers find a detailed tutorial how to use the interface either at
 * [HOB-Wiki](http://wiki.hob.de/wiki/attach/SoftwareDocumentation_Development/LDAP-Tutorial.pdf "LDAP-Tutorial.pdf") or
 * [LDAP-Tutorial](LDAP-Tutorial.rtf "LDAP-Tutorial.rtf"), if you are using the doxygen generated documentation.
 *
 * The LDAP interface uses two classes (dsd_ldap, dsd_ldap_control) for managing the LDAP- and the TCP-
 * protocol (tcpcomp01) and 5 helper classes, e.g. for the ASN.1-, the trace-management or others (dsd_bufm,
 * dsd_ldap_schema, dsd_asn1, dsd_error, dsd_trace). This module is loaded provides the following global functions:
 * m_ldap_init(), m_ldap_free(), m_ldap_request() and m_ldap_auth().
 * LDAP is loaded by a main program, e.g. the WebSecureProxy and acts as a 'pseudo' class, since the main program
 * has to call a 'pseudo'-constructor and -destructor to initialize or free the class. This is done by m_ldap_init()
 * and m_ldap_free(). All LDAP-client requests are handled by m_ldap_request(). The function m_ldap_auth() supports
 * the authentication with a given user-id and password only. All global functions (except m_ldap_auth) have the
 * class pointer as the parameter to address the class instance.  
 *
 * The following specifications are fulfilled, missing topics are marked:
 * - RFC 2696 (LDAP Control Extension for Simple Paged Results Manipulation)
 * - RFC 3045 (Storing Vendor Information in the LDAP rootDSE)
 * - RFC 3062 (LDAP Password Modify Extended Operation)
 * - RFC 4178 (The Simple and Protected Generic Security Service Application Program Interface Negotiation Mechanism (GSSAPI))
 * - RFC 4510 (Technical Specification Road Map) covers the following specifications:
 * - RFC 4511 (The protocol) except the topics:
 *          + 4.1.10 Referral
 *          + 4.4    Unsolicited Notification
 *          + 4.5.3  Continuation References in the Search Result
 *          + 4.13   IntermediateResponse Message
 *          + 4.14   StartTLS Operation
 * - RFC 4512 (Directory Information Models)
 * - RFC 4513 (Authentication Methods and Security Mech.) except the following:
 *          + 3.  StartTLS Operation
 *          + 6.2 StartTLS Security Considerations
 * - RFC 4514 (String Representation of Distinguished Names)
 * - RFC 4515 (String Representation of Search Filters)
 * - RFC 4516 (Uniform Resource Locater) is not implemented
 * - RFC 4517 (Syntaxes and Matching Rules) except the topics:
 *          + 3.3.4  Country String
 *          + 3.3.5  Delivery Method
 *          + 3.3.7  DIT Content Rule Description
 *          + 3.3.8  DIT Structure Rule Description
 *          + 3.3.10 - 3.3.14 Enhanced Guide, ...
 *          + 3.3.17 JPEG
 *          + 3.3.27 - 3.3.28 Other Mailbox, ...
 *          + 3.3.31 - 3.3.34 Telephone Number, ...
 * - RFC 4518 (Internationalized String Preparation)
 * - RFC 4519 (Schema for User Applications)
 */

/*+----------------------------------------------------------------------------------------------+*/
/*| System and library header files...                                                           |*/
/*+----------------------------------------------------------------------------------------------+*/
#define CLIENT_VERSION  "1.01.0710"
#undef  HOB_LDAP_REFERRAL
#undef  HOB_SSL_BUFFER_CHECK
#undef  HOB_SPNEGO_SUPPORT


#define SM_USE_SSL_AUX_STORE	1

#if defined WIN32 || defined WIN64
#include <cstdlib>
#include <cstring>
#include <iostream>
  #ifdef HL_DEBUG
  #define _CRTDBG_MAP_ALLOC
  #include <crtdbg.h>
  #endif /* HL_DEBUG */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#elif defined HL_UNIX
#define _ASSERTE(expr)
#define _atoi64(a)       strtoll(a, NULL, 10)
#define _ultoa(a,b,c)    ultoa(a, c, b, 20)

#include <string>
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "hob-unix01.h"
#endif /* WIN32, WIN64, UNIX */

#define DEF_HL_INCL_DOM
#define DOMNode void
#include "hob-netw-01.h"
#include "hob-xslunic1.h"
#include "hob-xslhcla1.hpp"
#ifndef HOB_CONTR_TIMER
#define HOB_CONTR_TIMER
#endif
#include "hob-xslcontr.h"
#include "hob-ssl-01.h"
#include "hob-ntlm-01.h"
#include "hob-xsclib01.h"
#include "hob-avl03.h"
#include "hob-wsppriv.h"
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-tcp-sync-01.h"
#include "hob-tcpco1.hpp"

#ifdef DEF_TC_OWN_NS
using namespace ns_tcpcomp_mh;
#endif /* DEF_TC_OWN_NS */
using namespace std;
#include "hob-ldap01.hpp"


#define D_LDAP_SSL_RECV_BUFFER_LEN	D_LDAP_SSL_BUFFER_LEN

/*+----------------------------------------------------------------------------------------------+*/
/*| global function prototypes...                                                                |*/
/*+----------------------------------------------------------------------------------------------+*/
#ifdef HOB_RD_VPN_2_1_10
void mg_cb_connect    ( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int );
#else
void mg_cb_connect    ( class dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *, socklen_t, int );
#endif
void mg_cb_connect_err( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int );
void mg_cb_send       ( class dsd_tcpcomp *, void * );
int  mg_cb_getrecvbuf ( class dsd_tcpcomp *, void *, void **, char **, int ** );
int  mg_cb_recv       ( class dsd_tcpcomp *, void *, void * );
void mg_cb_error      ( class dsd_tcpcomp *, void *, char *, int, int );
void mg_cb_cleanup    ( class dsd_tcpcomp *, void * );

#if HOB_LDAP_TRACE_TRAFFIC
extern "C" void m_console_out( char *achp_buff, int implength );
#endif

/*+----------------------------------------------------------------------------------------------+*/
/*| Initialize static global static variables...                                                 |*/
/*+----------------------------------------------------------------------------------------------+*/
volatile int        dsd_ldap::im_init_cs (0);          // synchronization object init flag
volatile int        dsd_ldap::im_utc_update (1);       // utc time must be updated

#if !SM_BUGFIX_20140804
int                 dsd_ldap::im_sess_cnt (0);         // ldap session counter
#endif
int                 dsd_ldap::im_init_cnt (0);         // ldap instance counter
HL_LONGLONG         dsd_ldap::il_utc_time (0);         // utc time
dsd_timer_ele       dsd_ldap::ds_timer_1;
dsd_ldap_schema    *dsd_ldap::ads_schema_anc (NULL);   // ldap schema object chain for non MSAD servers
void               *dsd_ldap::ads_hl_stor_glob (NULL); // global storage handler
dsd_hcla_critsect_1 dsd_ldap::ds_cs_ldap;              // synchronization object
dsd_tcpcallback_t   dsd_ldap::ds_tcpcb = { mg_cb_connect_err, // tcpcomp callback structure
                                           mg_cb_connect,
                                           mg_cb_send,
                                           mg_cb_getrecvbuf,
                                           mg_cb_recv,
                                           mg_cb_error,
                                           mg_cb_cleanup,
                                           &m_get_random_number
                                         };

#define namingContexts          "namingContexts"
#define defaultNamingContext    "defaultNamingContext"
#define schemaNamingContext     "schemaNamingContext"
#define subschemaSubentry       "subschemaSubentry"
#define supportedSASLMechanisms "supportedSASLMechanisms"
#define supportedExtension      "supportedExtension"
#define vendorName              "vendorName"
#define vendorVersion           "vendorVersion"
#define dnsHostName             "dnsHostName"
#define supportedLDAPVersion    "supportedLDAPVersion"
#define supportedControl        "supportedControl"

const char *dsd_ldap::achs_RootDSE[] = { namingContexts,          // ied_nctx
                                         defaultNamingContext,    // ied_def_nctx
                                         schemaNamingContext,     // ied_sch_nctx
                                         subschemaSubentry,       // ied_subsch_nctx
                                         supportedSASLMechanisms, // ied_sasl_mech
                                         supportedExtension,      // ied_extent
                                         vendorName,              // ied_vname
                                         vendorVersion,           // ied_vver
                                         dnsHostName,             // ied_dns_namee
                                         supportedLDAPVersion,    // ied_ldap_ver
                                         supportedControl,        // ied_control
                                         NULL };

const char *dsd_trace::achs_t_bind_auth[] = { "user",        // 0 [S_BIND_AUTH][ied_auth_user]
                                              "pwd-change",  // 1 [S_BIND_AUTH][ied_auth_user_pwd_change]
                                              "dn",          // 2 [S_BIND_AUTH][ied_auth_dn]
                                              "admin",       // 3 [S_BIND_AUTH][ied_auth_admin]
                                              "ntlm",        // 4 [S_BIND_AUTH][ied_auth_ntlm]
                                              "krb5",        // 5 [S_BIND_AUTH][ied_auth_krb5]
                                              "sid"          // 7 [S_BIND_AUTH][ied_auth_sid]
                                            };

const char *dsd_trace::achs_t_sear_scope[] = { "baseobject",  // 0 [S_SEARCH_SCOPE][ied_sear_baseobject]
                                               "onelevel",    // 1 [S_SEARCH_SCOPE][ied_sear_onelevel]
                                               "sublevel",    // 2 [S_SEARCH_SCOPE][ied_sear_sublevel]
                                               "children",    // 3 [S_SEARCH_SCOPE][ied_sear_children]
                                               "superlevel",  // 4 [S_SEARCH_SCOPE][ied_sear_superlevel]
                                               "root",        // 5 [S_SEARCH_SCOPE][ied_sear_root]
                                               "basedn",      // 6 [S_SEARCH_SCOPE][ied_sear_basedn]
                                               "attronly"     // 7 [S_SEARCH_SCOPE][ied_sear_attronly]
                                             };

// class dsd_error - LDAP error messages
static struct dsd_error ds_ldap_errlist[] =
{
    { 'I', ied_ldap_success,              "Success" },
    { 'W', ied_ldap_op_err,               "Operations error" },
    { 'W', ied_ldap_prot_err,             "Protocol error" },
    { 'W', ied_ldap_tlimit_exceeded,      "Time limit exceeded" },
    { 'W', ied_ldap_slimit_exceeded,      "Size limit exceeded" },
    { 'I', ied_ldap_cmp_false,            "Compare False" },
    { 'I', ied_ldap_cmp_true,             "Compare True" },
    { 'W', ied_ldap_auth_notsupp,         "Authentication method not supported" },
    { 'W', ied_ldap_strong_auth_req,      "Strong(er) authentication required" },
    { 'I', ied_ldap_referral,             "Referral" },
    { 'W', ied_ldap_admin_lim_exceeded,   "Administrative limit exceeded" },
    { 'W', ied_ldap_unavail_critext,      "Critical extension is unavailable" },
    { 'W', ied_ldap_confid_req,           "Confidentiality required" },
    { 'I', ied_ldap_sasl_bind,            "SASL bind in progress" },
    // LDAP attribute errors...
    { 'I', ied_ldap_no_such_attr,         "No such attribute" },
    { 'I', ied_ldap_undef_attr_type,      "Undefined attribute type" },
    { 'I', ied_ldap_inappr_matching,      "Inappropriate matching" },
    { 'I', ied_ldap_constraint_violation, "Constraint violation" },
    { 'I', ied_ldap_attr_or_val_exist,    "Type or value exists" },
    { 'W', ied_ldap_inv_attr_syntax,      "Invalid syntax" },
    // LDAP name errors...
    { 'I', ied_ldap_no_such_obj,          "No such object" },
    { 'I', ied_ldap_alias_problem,        "Alias problem" },
    { 'I', ied_ldap_inv_dn_syntax,        "Invalid DN syntax" },
    { 'I', ied_ldap_alias_deref_problem,  "Alias dereferencing problem" },
    // LDAP security errors..
    { 'I', ied_ldap_password_change,      "Password must change" },
    { 'I', ied_ldap_no_logon_this_time,   "Logon not permitted at this time" },
    { 'I', ied_ldap_account_disabled,     "Account disabled" },
    { 'I', ied_ldap_account_expired,      "Account expired" },
    { 'I', ied_ldap_account_locked,       "Account locked" },
    { 'I', ied_ldap_need_ssl,             "SSL needed" },
    { 'I', ied_ldap_password_expired,            "Password has been expired" },
    { 'I', ied_ldap_password_do_not_expire,      "Password do not expire" },
    { 'I', ied_ldap_password_not_a_user_account, "Not a normal user account" },
    { 'I', ied_ldap_password_not_required,       "No password is required" },
    { 'I', ied_ldap_inappr_auth,          "Inappropriate authentication" },
    { 'I', ied_ldap_inv_cred,             "Invalid credentials" },
    { 'W', ied_ldap_insuff_access_rights, "Insufficient access" },
    // LDAP service errors...
    { 'I', ied_ldap_busy,                 "Server is busy" },
    { 'W', ied_ldap_unavail,              "Server is unavailable" },
    { 'I', ied_ldap_unwill_to_perform,    "Server is unwilling to perform" },
    { 'I', ied_ldap_loop_detect,          "Loop detected" },
    { 'I', ied_ldap_would_block,          "Request would block" },
    // LDAP update errors...
    { 'I', ied_ldap_name_violation,       "Name violation" },
    { 'I', ied_ldap_objcls_violation,     "Objectclass violation" },
    { 'I', ied_ldap_not_allowed_on_nleaf, "Operation not allowed on non-leaf" },
    { 'I', ied_ldap_not_allowed_on_rdn,   "Operation not allowed on RDN" },
    { 'I', ied_ldap_entr_already_exists,  "Already exists" },
    { 'I', ied_ldap_objcls_mode_prohib,   "Cannot modify objectclass" },
    { 'I', ied_ldap_other,                "Internal error" },
    // API result codes...
    { 'W', ied_ldap_param_inv,            "Bad parameter to a ldap routine" },
    { 'W', ied_ldap_server_down,          "Can't contact LDAP server" },
    { 'E', ied_ldap_connect_err,          "Connect error" },
    { 'E', ied_ldap_send_err,             "Send error" },
    { 'I', ied_ldap_send_blocked,         "Send blocked" },
    { 'W', ied_ldap_connection_closed,    "Connection closed" },
    { 'W', ied_ldap_connection_active,    "Connection already active" },
    { 'W', ied_ldap_session_limit,        "Session limit reached" },
    { 'I', ied_ldap_auth_unknown,         "Unknown authentication method" },
    { 'W', ied_ldap_filter_err,           "Bad search filter" },
    { 'E', ied_ldap_no_memory,            "Out of memory" },
    { 'E', ied_ldap_tcpcomp_err,          "TCPCOMP error" },
    { 'E', ied_ldap_wsa_err,              "WSA error" },
    { 'E', ied_ldap_socket_err,           "Socket error" },
    { 'I', ied_ldap_no_bind,              "No bind initiated" },
    { 'E', ied_ldap_not_supp,             "Not supported" },
    { 'W', ied_ldap_no_config,            "No configuration found" },
    { 'I', ied_ldap_timeout,              "Timed out" },
    { 'I', ied_ldap_no_results,           "No results returned" },
    { 'I', ied_ldap_more_results,         "More results to return" },
    // ASN.1 error codes...
    { 'W', ied_ldap_encoding_err,         "ASN.1 encoding error" },
    { 'W', ied_ldap_decoding_err,         "ASN.1 decoding error" },
    { 'W', ied_ldap_inv_result_type,      "ASN.1 invalid result type" },
    // LDAP failure codes..
    { 'W', ied_ldap_bind_err,             "Bind failed" },
    { 'W', ied_ldap_search_err,           "Search failed" },
    { 'W', ied_ldap_lookup_err,           "Lookup failed" },
    { 'W', ied_ldap_unbind_err,           "Unbind failed" },
    { 'W', ied_ldap_abandon_err,          "Abandon failed" },
    { 'W', ied_ldap_compare_err,          "Compare failed" },
    { 'W', ied_ldap_modify_err,           "Modify failed" },
    { 'W', ied_ldap_modify_dn_err,        "Modify(DN) failed" },
    { 'W', ied_ldap_add_err,              "Add failed" },
    { 'W', ied_ldap_delete_err,           "Delete failed" },
    { 'W', ied_ldap_check_pwd_err,        "Check password failed" },
    { 'W', ied_ldap_explode_dn_err,       "Explode DN failed" },
    { 'W', ied_ldap_clone_dn_err,         "Clone DN failed" },
    { 'W', ied_ldap_change_pwd_err,       "Change password failed" },
    { 'W', ied_ldap_failure,              "Function error" },
    { '?', 0, "" }
}; // ds_ldap_errlist{}

struct dsd_error *dsd_error::ads_etab (&ds_ldap_errlist[0]);


#if SM_USE_RECV_GATHERS
static void m_gatherlist_init(dsd_gatherlist* adsp_list) 
{
	adsp_list->adsc_first = NULL;
	adsp_list->adsc_last = NULL;

} // m_gatherlist_init()


static void m_gatherlist_push_back(dsd_gatherlist* adsp_list, dsd_gather_i_1* adsp_c) 
{
	adsp_c->adsc_next = NULL;

	if (adsp_list->adsc_first == NULL) 
    {
	  adsp_list->adsc_first = adsp_c;
	  adsp_list->adsc_last = adsp_c;
	  return;
	}

	adsp_list->adsc_last->adsc_next = adsp_c;
	adsp_list->adsc_last = adsp_c;

}  // m_gatherlist_push_back()


static dsd_gather_i_1* m_gatherlist_remove_first(dsd_gatherlist* adsp_list) 
{
	dsd_gather_i_1* ads_cur = adsp_list->adsc_first;

	if (ads_cur == NULL)
	  return NULL;

	adsp_list->adsc_first = ads_cur->adsc_next;
	ads_cur->adsc_next = NULL;
	return ads_cur;

}  // m_gatherlist_remove_first()


static void m_gatherlist_release(dsd_gatherlist* adsp_list) 
{
	adsp_list->adsc_first = NULL;
	adsp_list->adsc_last = NULL;

} // m_gatherlist_release()


static void m_gatherlist_push_back(dsd_gatherlist* adsp_list, dsd_gatherlist* adsp_list_add) 
{
	dsd_gather_i_1* ads_src_first = adsp_list_add->adsc_first;

	if (ads_src_first == NULL)
	  return;

	dsd_gather_i_1* ads_src_last = adsp_list_add->adsc_last;
	m_gatherlist_release(adsp_list_add);
	
    if (adsp_list->adsc_first == NULL) 
    {
		adsp_list->adsc_first = ads_src_first;
		adsp_list->adsc_last = ads_src_last;
		return;
	}
	
    adsp_list->adsc_last->adsc_next = ads_src_first;
	adsp_list->adsc_last = ads_src_last;

} // m_gatherlist_push_back() 


static void m_gatherlist_push_front(dsd_gatherlist* adsp_list, dsd_gatherlist* adsp_list_add) 
{
	dsd_gather_i_1* ads_src_first = adsp_list_add->adsc_first;

	if (ads_src_first == NULL)
		return;

	dsd_gather_i_1* ads_src_last = adsp_list_add->adsc_last;
	m_gatherlist_release(adsp_list_add);

	if (adsp_list->adsc_first == NULL)
    {
		adsp_list->adsc_first = ads_src_first;
		adsp_list->adsc_last = ads_src_last;
		return;
	}
	
    adsp_list->adsc_first->adsc_next = ads_src_last;
	adsp_list->adsc_first = ads_src_first;

} // m_gatherlist_push_front()


static dsd_gather_i_1* m_skip_consumed_gathers(dsd_gatherlist* adsp_list)
{
	while(adsp_list->adsc_first != NULL) 
    {
		if (adsp_list->adsc_first->achc_ginp_cur < adsp_list->adsc_first->achc_ginp_end)
		  break;

		dsd_gather_i_1* adsl_tmp = m_gatherlist_remove_first(adsp_list);
		::free(adsl_tmp);
	}
	return adsp_list->adsc_first;
}

static void m_gatherlist_free(dsd_gatherlist* adsp_list)
{
   while(true) 
   {
	   dsd_gather_i_1* adsl_gather = m_gatherlist_remove_first(adsp_list);

	   if (adsl_gather == NULL)
		 break;

	   ::free(adsl_gather);
   }

} // m_gatherlist_free()


static dsd_gather_i_1* m_skip_consumed_gathers(dsd_gather_i_1* adsp_start)
{
	dsd_gather_i_1* adsl_tmp = adsp_start;

	while(adsl_tmp != NULL) 
    {
		if (adsl_tmp->achc_ginp_cur < adsl_tmp->achc_ginp_end)
		  break;

		adsl_tmp = adsl_tmp->adsc_next;
	}

	return adsl_tmp;

} // m_skip_consumed_gathers()
#endif /*SM_USE_RECV_GATHERS*/


/*+---------------------------------------------------------------------------------------------+*/
/*| Global functions...                                                                         |*/
/*+---------------------------------------------------------------------------------------------+*/
/**
 * static function:  m_bswap32()
 *
 * Swaps a 32-bit integer (le -> be and vice versa).
 *
 * @return   swapped integer
 *
 */
static unsigned int  m_bswap32( unsigned int ump_val )
{
   return (ump_val << 24 | (ump_val << 8) & 0xff0000UL | (ump_val >> 8) & 0xff00UL | ump_val >> 24);
}

/**
 * LDAP global function:  m_ldap_get_version()
 *
 * Returns the current version of this LDAP client.
 *
 * @return   LDAP client version (e.g. "1.01.0606")
 *
 */
char *m_ldap_get_version()
{
   return CLIENT_VERSION;
}

#ifdef _DEBUG
/**
 * Static permanent storage function:  ms_aux_per_mem()
 *
 * Get permanent storage function. Allocates storage for any purposes.
 *
 * @param[in]       vpp_userfld    user context address (e.g. 'this'-pointer)
 * @param[in]       imp_func       DEF_AUX_xxx function code
 * @param[in, out]  avop_mem       pointer to the memory address
 * @param[in]       imp_size       requested memory size
 *
 * @return     \b TRUE if success, else \b FALSE
 *
 * @todo  WSP error management
 */
static BOOL  ms_aux_per_mem( void *vpp_userfld, int imp_func, void *avop_mem, int imp_size )
{
	class dsd_ldap* adsl_ldap = (class dsd_ldap*)vpp_userfld;
	// what to do?
	switch (imp_func)
    {
		case DEF_AUX_MEMGET:  { // allocate storage...
			                    void* avol_ptr = m_aux_stor_alloc(&adsl_ldap->ads_hl_stor_per, imp_size);
			                    if (avol_ptr == NULL)
				                  return FALSE;
			              
                                *(void **)avop_mem = avol_ptr;
			                    return TRUE;
		                      }

		case DEF_AUX_MEMFREE: { // free storage...
			                    void* avol_ptr = *(void **)avop_mem;
                                if (avol_ptr == NULL)
				                  return TRUE;
			
                                 m_aux_stor_free(&adsl_ldap->ads_hl_stor_per, avol_ptr);
			                     *(void **)avop_mem = NULL;
                                 return TRUE;
		                      }
		default:    		  return FALSE;
	} 
} // static function 'ms_aux_per_mem( void *, int, void *, int )'
#endif // _DEBUG


/**
 * SSL static storage function:  ms_aux_ssl_mem()
 *
 * Get storage ssl-function. Allocates storage for any ssl-purposes.
 *
 * @param[in]       vpp_userfld    user context address (e.g. 'this'-pointer)
 * @param[in]       imp_func       DEF_AUX_xxx function code
 * @param[in, out]  avop_mem       pointer to the memory address
 * @param[in]       imp_size       requested memory size
 *
 * @return     \b TRUE if success, else \b FALSE
 *
 * @todo  WSP error management
 */
static BOOL  ms_aux_ssl_mem( void *vpp_userfld, int imp_func, void *avop_mem, int imp_size )
{
#if SM_USE_SSL_AUX_STORE
	class dsd_ldap* adsl_ldap = (class dsd_ldap*)vpp_userfld;
	// what to do?
	switch (imp_func)
    {
		case DEF_AUX_MEMGET:  { // allocate storage...
			                    void* avol_ptr = m_aux_stor_alloc(&adsl_ldap->ads_hl_stor_ssl, imp_size);
			                    if (avol_ptr == NULL)
				                  return FALSE;
			              
                                *(void **)avop_mem = avol_ptr;
			                    return TRUE;
		                      }

		case DEF_AUX_MEMFREE: { // free storage...
			                    void* avol_ptr = *(void **)avop_mem;
                                if (avol_ptr == NULL)
				                  return TRUE;
			
                                 m_aux_stor_free(&adsl_ldap->ads_hl_stor_ssl, avol_ptr);
			                     *(void **)avop_mem = NULL;
                                 return TRUE;
		                      }
		default:    		  return FALSE;
	} 
#else
   // test for valid parameters?
   if (vpp_userfld && avop_mem)
   {
     // what to do?
     switch (imp_func)
     {
        case DEF_AUX_MEMGET:   // allocate storage...
                               if (imp_size > 0)
                               {
								 void* avol_tmp = malloc(imp_size);
								 if (avol_tmp == NULL)
                                   return FALSE;
#ifdef HL_DEBUG
                                 _ASSERTE(_CrtIsValidPointer(avol_tmp, imp_size, TRUE ));
#endif
								 *(void **)avop_mem = avol_tmp;
								 return TRUE;
                               }
                               break;

        case DEF_AUX_MEMFREE:  // free storage...
                               if (*(void **)avop_mem != NULL)
                               {
#ifdef HL_DEBUG
                                 _ASSERTE(_CrtIsValidPointer( *(void **)avop_mem, sizeof(char), TRUE ));
#endif
 								 free(*(void **)avop_mem);
								 *(void **)avop_mem = NULL;

                                 return TRUE;
                               }
        default:               break;
     } // switch()
   } // end of valid parameters

   return FALSE;
#endif
} // static function 'ms_aux_ssl_mem( void *, int, void *, int )'


/**
 * static storage function:  ms_aux_mem()
 *
 * Get client storage. Allocates memory using the internal storage container or the given one.
 *
 * @param[in]  adsp_ldap         ldap request structure
 * @param[in]  avop_stor_handle  alternate internal storage handler
 * @param[in]  inp_size          requested memory size
 *
 * @return     void *            allocated storage pointer
 */
static void  *ms_aux_mem(struct dsd_co_ldap_1 *adsp_ldap_req, void **avop_stor_handle, int inp_size) 
{
#if SM_USE_LDAP_AUX_CALL
	if (adsp_ldap_req->amc_aux != NULL) 
    {
		void* avol_ret (NULL);

		if (!adsp_ldap_req->amc_aux(adsp_ldap_req->vpc_userfld, DEF_AUX_MEMGET, &avol_ret, inp_size))
		  return NULL;
		
        return avol_ret;
	}
#else
	if (adsp_ldap_req->avoc_stor_handle != NULL) {
		return m_aux_stor_alloc( adsp_ldap_req->avoc_stor_handle, inp_size);
	}
#endif
    // use internal class storage handler...
	return m_aux_stor_alloc(avop_stor_handle, inp_size);

}; // static function 'ms_aux_mem( struct dsd_ldap *, void **, int)'


/**
 * LDAP global function:  m_ldap_auth()
 *
 * Function for the authentication of a given user-id and password.
 *
 * @param[in]  adsp_cfg_ldap     LDAP configuration parameters
 * @param[in]  adsp_uc_userid    user-id (unicode)
 * @param[in]  adsp_uc_password  password (unicode)
 *
 * @return     \b enum ied_ret_ldap_def   a enumeration of possible return values
 *
 * Comment:
 * LDAP-, TCP/IP- or other errors are send back as 'ied_ret_ldap_not_avail'
 */
enum ied_ret_ldap_def  m_ldap_auth( struct dsd_ldap_group     *adsp_cfg_ldap,
                                    struct dsd_unicode_string *adsp_uc_userid,
                                    struct dsd_unicode_string *adsp_uc_password )
{
   enum ied_ret_ldap_def  iel_ret;

   // valid parameters???
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_cfg_ldap, sizeof(struct dsd_ldap_group), FALSE ));
   _ASSERTE(_CrtIsValidPointer( adsp_uc_userid, sizeof(struct dsd_unicode_string), FALSE ));
   _ASSERTE(_CrtIsValidPointer( adsp_uc_password, sizeof(struct dsd_unicode_string), FALSE ));
#endif

   if (!adsp_cfg_ldap || !adsp_uc_userid || !adsp_uc_password)
     return ied_ret_ldap_failure;

   // call class constructor
   class  dsd_ldap  dsl_ldap;
                    dsl_ldap.m_ldap_init();

   // set ldap request object...
   LDAP_REQ_STRUC(dsl_co_ldap)

   dsl_co_ldap.iec_co_ldap    = ied_co_ldap_bind;  // do ldap bind...
   dsl_co_ldap.iec_ldap_auth  = ied_auth_user;     // authentication with the given user-id
   dsl_co_ldap.ac_userid      = (char *)adsp_uc_userid->ac_str;
   dsl_co_ldap.imc_len_userid = adsp_uc_userid->imc_len_str;
   dsl_co_ldap.iec_chs_userid = adsp_uc_userid->iec_chs_str;
   dsl_co_ldap.ac_passwd      = (char *)adsp_uc_password->ac_str;
   dsl_co_ldap.imc_len_passwd = adsp_uc_password->imc_len_str;
   dsl_co_ldap.iec_chs_passwd = adsp_uc_password->iec_chs_str;
   
   // send bind request...
   dsl_ldap.m_ldap_request( (struct dsd_ldap_group *)adsp_cfg_ldap, (struct dsd_co_ldap_1 *)&dsl_co_ldap );

   // translate return code...
   switch (dsl_co_ldap.iec_ldap_resp)
   {
      case ied_ldap_success:
          // everything ok...
          iel_ret = ied_ret_ldap_ok;
          break;
      case ied_ldap_no_results:
          // user-id not found...
          iel_ret = ied_ret_ldap_inv_userid;
          break;
      case ied_ldap_bind_err:
          // user-id not found...
          iel_ret = ied_ret_ldap_inv_password;
          break;
      default:
          iel_ret = ied_ret_ldap_not_avail;
          break;
   } // switch()

   // call destructor
   dsl_ldap.m_ldap_free();
   // return to caller...
   return iel_ret;

} // global function 'm_ldap_auth( dsd_ldap_group *, dsd_unicode_string *, dsd_unicode_string * )


/**
 * SSL global callback function:  mg_cb_ssl_compl()
 *
 * SSL 'hello'-protocol completed.
 *
 * @param[in]  adsp_ssl_ccb    ssl object
 *
 * @return     none
 */
void mg_cb_ssl_compl( struct dsd_hl_ssl_ccb_1 *adsp_ssl_ccb )
{
   // set ssl completion object...
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ssl_ccb, sizeof(struct dsd_hl_ssl_ccb_1), FALSE ));
#endif
   ((class dsd_ldap *)adsp_ssl_ccb->vpc_userfld)->bo_ssl_completed = TRUE;

} // global function 'm_cb_ssl_compl( struct dsd_hl_ssl_ccb_1 * )'


/**
 * Timer global callback function:  mg_cb_utc_timer()
 *
 * LDAP utc-timer update interval completed.
 *
 * @param[in]  adsp_utc_timer   utc-timer structure
 *
 * @return     none
 */
void mg_cb_utc_timer( dsd_timer_ele *adsp_utc_timer )
{
   // set update flag...
#if defined WIN32 || defined WIN64
   InterlockedExchange( (LONG volatile *)&dsd_ldap::im_utc_update, 1 );
#elif defined HL_UNIX
   __sync_lock_test_and_set( &dsd_ldap::im_utc_update, 1 );
#endif

} // global function 'm_cb_utc_timer()'


/**
 * TCPCOMP global callback function:  mg_cb_connect()
 *
 * Connect callback function. Close connections if an error occurred.
 *
 * #ifdef HOB_RD_VPN_2_1_10
 *   @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 *   @param[in]  adsp_ldap_control  ldap control object
 *   @param[in]  adsp_soa           sockaddr structure (ipv4 oripv6)
 *   @param[in]  imp_len_soa        length of the sockaddr structure
 *   @param[in]  imp_error          error code
 * #else
 *   @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 *   @param[in]  adsp_ldap_control  ldap control object
 *   @param[in]  adsp_target_ineta  todo: missing description (currently used as dummy)
 *   @param[in]  avop_free_til      todo: missing description (currently used as dummy)
 *   @param[in]  adsp_soa           sockaddr structure (ipv4 oripv6)
 *   @param[in]  imp_len_soa        length of the sockaddr structure
 *   @param[in]  imp_error          error code
 * #endif
 *
 * @return     none
 *
 */
void mg_cb_connect( class dsd_tcpcomp  *adsp_tcp,
                    void               *adsp_ldap_control,
#ifndef HOB_RD_VPN_2_1_10
                    struct dsd_target_ineta_1 *adsp_target_ineta,
                    void                      *avop_free_til,
#endif
                    struct sockaddr    *adsp_soa,
                    socklen_t           imp_len_soa,
                    int                 imp_error )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
   _ASSERTE(_CrtIsValidPointer( adsp_soa, sizeof(struct sockaddr), FALSE ));
#endif

   // was the connect successful ?
   if (!imp_error)
   { // yes, ...
     if (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap)
       // call callback function of the current ldap object...
       ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap->m_cb_connect( adsp_soa, imp_len_soa );
   }

} // global function 'mg_cb_connect_1( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int )'


/**
 * TCPCOMP global callback function:  mg_cb_connect_err()
 *
 * Connect error callback function. Close connections if called.
 *
 * @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 * @param[in]  adsp_soa           sockaddr structure (ipv4 or ipv6)
 * @param[in]  imp_len_soa        length of the sockaddr structure
 * @param[in]  imp_current_index  index number of the entry failed
 * @param[in]  imp_total_index    number of all entries
 * @param[in]  imp_errno          error code
 *
 * @return     none
 */
void mg_cb_connect_err( class dsd_tcpcomp *adsp_tcp,
                        void              *adsp_ldap_control,
                        struct sockaddr   *adsp_soa,
                        socklen_t          imp_len_soa,
                        int                imp_current_index,
                        int                imp_total_index,
                        int                imp_errno )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
#endif
#if !SM_BUGFIX_20140804
   dsd_ldap::ds_cs_ldap.m_enter();
   dsd_ldap* adsl_ldap = ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap;
   dsd_ldap::ds_cs_ldap.m_leave();
#endif
	if (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap != NULL) 
    {
      // call callback function of the current ldap object...
      ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap->m_cb_connect_err( adsp_soa, imp_len_soa, imp_current_index, imp_total_index, imp_errno );
	}
} // global function 'mg_cb_connect_err( class dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int )'


/**
 * TCPCOMP global callback function:  mg_cb_send()
 *
 * Send callback function. Resend buffers.
 *
 * @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 *
 * @return     none
 */
void mg_cb_send( class dsd_tcpcomp *adsp_tcp, void *adsp_ldap_control )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
#endif
   if (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap)
     // call callback function of the current ldap object...
     ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap->m_cb_send();

} // global function 'mg_cb_send( class dsd_tcpcomp *, void * )'


/**
 * TCPCOMP global callback function:  mg_cb_getrecvbuf()
 *
 * Get receive buffer callback function.
 *
 * @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 * @param[out] aavop_handle       pointer to the buffer handle variable (internally used)
 * @param[out] aachp_buffer       pointer to the buffer pointer variable (where to write)
 * @param[out] aaimp_len          pointer to the buffer length variable (bytes written)
 *
 * @return     maximum buffer length (0 = receive not allowed)
 */
int mg_cb_getrecvbuf( class dsd_tcpcomp *adsp_tcp,
                      void              *adsp_ldap_control,
                      void             **aavop_handle,
                      char             **aachp_buffer,
                      int              **aaimp_len )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
#endif

   if (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap != NULL)
     // call callback function of the current ldap object...
     return ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap->m_cb_getrecvbuf( aavop_handle, aachp_buffer, aaimp_len );

   return 0;

} // global function 'mg_cb_getrecvbuf( class dsd_tcpcomp *, void *, void **, char **, int ** )'


/**
 * TCPCOMP global callback function:  mg_cb_recv()
 *
 * Receive callback function.
 *
 * @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 * @param[in]  avop_handle        handle of buffer (internally used)
 *
 * @return     \b TRUE,  if more data should be received or
 *             \b FALSE, otherwise
 */
int mg_cb_recv( class dsd_tcpcomp *adsp_tcp, void *adsp_ldap_control, void* avop_handle )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
#endif

   if (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap)
     // call callback function of the current ldap object...
     return ((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap->m_cb_recv( avop_handle );
   
   return FALSE;

} // global function 'mg_cb_recv( class dsd_tcpcomp *, void *, void * )'


/**
 * TCPCOMP global callback function:  mg_cb_cleanup()
 *
 * Cleanup callback function.
 *
 * @param[in]  adsp_tcpcomp       tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 *
 * @return     none
 */
void mg_cb_cleanup( class dsd_tcpcomp *adsp_tcpcomp, void *adsp_ldap_control )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
   _ASSERTE(_CrtIsValidPointer( adsp_tcpcomp, sizeof(class dsd_tcpcomp), FALSE ));
#endif
#if !SM_BUGFIX_20140804
   // decrement session count...
   dsd_ldap::ds_cs_ldap.m_enter();
   if (dsd_ldap::im_sess_cnt > 0)  --dsd_ldap::im_sess_cnt;
   dsd_ldap::ds_cs_ldap.m_leave();
#endif

   // the cleanup() is the very last call of tcpcomp, so we are sure to free the control class...
	class dsd_ldap *adsl_ldap (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap);
	if (adsl_ldap != NULL)
	{ // server-side cleanup call because of an TCP error or server connect close
		// call callback function of the current ldap object...
		adsl_ldap->m_cb_cleanup_serverside( adsp_tcpcomp, (class dsd_ldap_control *)adsp_ldap_control );
	}

	if (((class dsd_ldap_control *)adsp_ldap_control)->m_ref_dec())
	  delete (class dsd_ldap_control *)adsp_ldap_control;

} // global function 'mg_cb_cleanup( class dsd_tcpcomp *, void * )'


/**
 * TCPCOMP global callback function:  mg_cb_error()
 *
 * Error callback function.
 *
 * @param[in]  adsp_tcp           tcpcomp object for nonblocking IO
 * @param[in]  adsp_ldap_control  ldap control object
 * @param[in]  strp_err           short error message
 * @param[in]  imp_errno          API error number
 * @param[in]  imp_errloc         tcpcomp error location. (See tcpcomp::ERRORAT_XXXX flags)
 *
 * @return     none
 */
void mg_cb_error( class dsd_tcpcomp *adsp_tcp,
                  void              *adsp_ldap_control,
                  char              *strp_err,
                  int                imp_errno,
                  int                imp_errloc )
{
#ifdef HL_DEBUG
  _ASSERTE(_CrtIsValidPointer( adsp_tcp, sizeof(class dsd_tcpcomp), FALSE ));
  _ASSERTE(_CrtIsValidPointer( adsp_ldap_control, sizeof(class dsd_ldap_control), FALSE ));
#endif

  class dsd_ldap  *adsl_ldap_cl (((class dsd_ldap_control *)adsp_ldap_control)->ads_ldap);
  if (adsl_ldap_cl != NULL) 
  {
    // call callback function of the current ldap object...
    adsl_ldap_cl->m_cb_error( strp_err, imp_errno, imp_errloc );
    
    int inl_err;
	((class dsd_ldap_control *)adsp_ldap_control)->ds_ev_response.m_post(&inl_err);
  }

} // global function 'mg_cb_error( class dsd_tcpcomp *, void *, char *, int, int )'



/**
 * LDAP global work thread function:  mg_wt_ldap_request()
 *
 * Work thread function for different LDAP commands, which would block.
 *
 * @param[in]  adsp_wt   work thread object
 * @param[in]  avop_p0   1.parameter: class  dsd_ldap   * (LDAP class instance)
 * @param[in]  avop_p1   2.parameter: struct dsd_co_ldap_1 * (LDAP command structure)
 * @param[in]  avop_p2   3.parameter: not used
 *
 * @return     none
 */
void mg_wt_ldap_request( struct dsd_hco_wothr *adsp_wt,
                         void *avop_p0,
                         void *avop_p1,
                         void *avop_p2 )
{
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_wt, sizeof(struct dsd_hco_wothr), FALSE ));
#endif
   if (adsp_wt && avop_p0 && avop_p1)
     ((class dsd_ldap *)avop_p0)->m_wt_ldap_request( adsp_wt, (struct dsd_co_ldap_1 *)avop_p1 );

} // global work thread function 'mg_wt_ldap_request( struct dsd_hco_wothr *, void *, void *, void * )'


/**
 * LDAP global function:  m_ldap_request()
 *
 * Function for different LDAP commands. A list of possible commands can be
 * found at 'ied_co_ldap_def'.
 *
 * @param[in]  adsp_ldap         ldap class instance
 * @param[in]  adsp_cfg_ldap     LDAP configuration parameters
 * @param[in]  adsp_co_ldap      LDAP command structure
 * @param[in]  vpp_userfld       user field for callback-function
 * @param[in]  (*m_cb_func)()    callback function
 *
 * @return     \b FALSE  if the class instance was requested to be freed or
 *             \b TRUE   otherwise
 *
 * Comment:
 * LDAP-, TCP/IP- or other errors are send back in the 'dsd_co_ldap_1'-structure
 */
int m_ldap_request( class  dsd_ldap        *adsp_ldap,
                    struct dsd_ldap_group  *adsp_cfg_ldap,
                    struct dsd_co_ldap_1   *adsp_co_ldap,
                    void                   *vpp_userfld,
                    int (*m_cb_func)(void *, class dsd_ldap *, struct dsd_co_ldap_1 *) )
{
   // call the entry function of the current ldap object...
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap, sizeof(class dsd_ldap), FALSE ));
#endif
   if (adsp_ldap)
     return adsp_ldap->m_ldap_request( adsp_cfg_ldap, adsp_co_ldap, vpp_userfld, m_cb_func );

   return TRUE;

} // global function 'm_ldap_request( class dsd_ldap*, struct dsd_ldap_group*, struct dsd_co_ldap_1*, void *, (*m_cb_func)() )'

/**
 * LDAP global function:  m_ldap_init()
 *
 * The constructor-function of the current class instance.
 *
 * @param[in]  adsp_ldap    ldap class instance
 *
 * @return     none
 */
void m_ldap_init( class dsd_ldap *adsp_ldap )
{
   // call entry function of the current ldap object...
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap, sizeof(class dsd_ldap), FALSE ));
#endif
   if (adsp_ldap)
     adsp_ldap->m_ldap_init();

} // global function 'm_ldap_init( class dsd_ldap * )'


/**
 * LDAP global function:  m_ldap_free()
 *
 * The destructor-function of the current class instance.
 *
 * @param[in]  adsp_ldap    ldap class instance
 *
 * @return     none
 */
void m_ldap_free( class dsd_ldap *adsp_ldap )
{
   // call entry function of the current ldap object...
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_ldap, sizeof(class dsd_ldap), FALSE ));
#endif
   if (adsp_ldap) 
   {
     adsp_ldap->m_ldap_free();
#if SM_BUGFIX_20140804
	 adsp_ldap->~dsd_ldap();
#endif
   }

} // global function 'm_ldap_free( class dsd_ldap * )'

#if SM_BUGFIX_20140804
void dsd_ldap_control::m_ref_inc() 
{
#if defined WIN32 || defined WIN64
   InterlockedIncrement(&this->inc_ref_count);
#elif defined HL_UNIX
   __sync_add_and_fetch(&this->inc_ref_count, 1);
#endif

} // class dsd_ldap_control

bool dsd_ldap_control::m_ref_dec() 
{
#if defined WIN32 || defined WIN64
   if (InterlockedDecrement(&this->inc_ref_count) <= 0)
	 return true;
	
   return false;

#elif defined HL_UNIX
   int inl_res = __sync_sub_and_fetch(&this->inc_ref_count, 1);
	
   if (inl_res <= 0)
	 return true;
	
   return false;
#endif

} // class dsd_ldap_control

int dsd_ldap_control::m_wait(int imp_waitmsec, int *aimp_ext_error) 
{
  if (imp_waitmsec < 0)
	return this->ds_ev_response.m_wait(aimp_ext_error);

  return this->ds_ev_response.m_wait_msec(imp_waitmsec, aimp_ext_error);

}
#endif /*SM_BUGFIX_20140804*/


/*+---------------------------------------------------------------------------------------------+*/
/*| class 'dsd_ldap' ...                                                                        |*/
/*+---------------------------------------------------------------------------------------------+*/
/**
 * Public class function:  dsd_ldap::m_ldap_request()
 *
 * Function for different LDAP commands. A list of possible commands can be
 * found at 'ied_co_ldap_def'. This is the main entry function. Every request has
 * to be send with the initiated structure 'dsd_co_ldap_1'.
 *
 * @param[in]  adsp_cfg_ldap    LDAP configuration parameters
 * @param[in]  adsp_co_ldap     LDAP command structure
 * @param[in]  vpp_userfld      user field for callback-function
 * @param[in]  m_cb_func()      callback function (used in nonblocking mode)
 *
 * @return     \b FALSE  if the class instance was requested to be freed or
 *             \b TRUE   otherwise
 *
 * Comment:
 *     The following parameters have to be set for all requests (ied_co_ldap_...):
 *     [in]  'iec_co_ldap'       - LDAP command code
 *
 *     [out] 'iec_ldap_resp'     - response code (ied_ldap_success if successful or any error code(ied_ldap_...)
 *                               note:  ied_ldap_sasl_bind flags a type2-message (ntlm-challenge) returned
 *                                      by the server
 *     [out] 'dsc_err_msg'       - error message
 *
 *  The requests ied_co_ldap_abandon, ied_co_ldap_close, ied_co_ldap_get_last_err don't use any
 *  further input parameters.
 *
 * The following requests need additional parameters:
 **************************************************************************************************
 * ied_co_ldap_add:
 *
 *     [in]  'adsc_attr_desc'        - attribute description(s) (single- or multi-valued)
 *            ->adsc_next_attr_desc  - next attribute description list
 *            ->iec_chs_dn           - dn name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - dn name length
 *            ->ac_dn                - dn name (of the following attribute(s)
 *            ->adsc_attr            - attribute description(s)
 *              ->adsc_next_attr     - next attribute description
 *              ->iec_chs_attr       - attribute name character set (ied_chs_utf_8)
 *              ->imc_len_attr       - attribute name length
 *              ->ac_attr            - attribute name (which values are added)
 *                ->dsc_val;         - attribute value description
 *                 .adsc_next_val    - next value description (if multivalued)
 *                 .iec_chs_val;     - value character set (ied_chs_utf_8)
 *                 .imc_len_val;     - value length
 *                 .ac_val;          - value (to add)
 *
 **************************************************************************************************
 * ied_co_ldap_bind:
 *
 * there are two different kinds of bind():  simple and sasl (3-way handshake for ntlm)
 *
 *     [in]  'iec_ldap_auth'      - bind with dn, user name, administrator or sasl
 *     [in]  'iec_chs_userid'     - simple: user name character set (e.g. ied_chs_ascii_850)
 *                                  sasl:   ignored
 *     [in]  'imc_len_userid'     - simple: user name length
 *                                  sasl:   ignored
 *     [in]  'ac_userid'          - simple: user name
 *                                  sasl:   ignored
 *     [in]  'iec_chs_passwd'     - simple: password character set (e.g. ied_chs_ascii_850)
 *                                  sasl:   ignored
 *     [in]  'imc_len_passwd'     - simple: password length
 *                                  sasl:   credentials length
 *     [in]  'ac_passwd'          - simple: password
 *                                  sasl:   credentials
 * simple authentication:
 *
 *     [out] 'iec_chs_dn'        - DN name character set (ied_chs_utf_8)
 *     [out] 'imc_len_dn'        - DN name length
 *     [out] 'ac_dn'             - DN name of the user
 *
 *
 * These parameters overwrites the <dn>- and <password>-entries of the xml-configuration
 **************************************************************************************************
 * ied_co_ldap_compare:
 *
 *     [in]  'adsc_attr_desc'        - partial attribute description (single- or multi-valued)
 *            ->adsc_next_attr_desc  - NULL
 *            ->iec_chs_dn           - dn name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - dn name length
 *            ->ac_dn                - dn name (of the following attribute(s)
 *            ->adsc_attr            - attribute description(s)
 *              ->adsc_next_attr     - NULL
 *              ->iec_chs_attr       - attribute name character set (ied_chs_utf_8)
 *              ->imc_len_attr       - attribute name length
 *              ->ac_attr            - attribute name (which value is compared)
 *                ->dsc_val;         - attribute value description
 *                 .adsc_next_val    - NULL
 *                 .iec_chs_val;     - value character set (ied_chs_utf_8)
 *                 .imc_len_val;     - value length
 *                 .ac_val;          - value (new)
 *
 **************************************************************************************************
 * ied_co_ldap_delete:
 *
 *     [in]  'iec_chs_dn'        - character set of the DN entry name
 *     [in]  'imc_len_dn'        - DN entry name length (in bytes)
 *     [in]  'ac_dn'             - DN entry name to delete
 *
 **************************************************************************************************
 * ied_co_ldap_explode_dn:
 *
 *     [in]  'avoc_stor_handle'      - NULL: LDAP storage handle, else use this client handle
 *
 *     [out] 'adsc_attr_desc'        - RDN-attribute description list
 *            ->adsc_next_attr_desc  - next RDN-attribute description list
 *            ->iec_chs_dn           - RDN name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - RDN name length
 *            ->ac_dn                - RDN name
 *            ->adsc_attr            - NULL: no further attribute description(s)
 *
 **************************************************************************************************
 * ied_co_ldap_clone_dn:
 *
 *     [in]  'avoc_stor_handle'      - NULL: LDAP storage handle, else use this client handle
 *
 *     [in]  'iec_chs_dn'            - (optional) RDN name character set
 *     [in]  'imc_len_dn'            - (optional) RDN name length (in bytes)
 *     [in]  'ac_dn'                 - (optional) RDN name
 *     [in]  'adsc_attr_desc'        - RDN-attribute description list
 *            ->adsc_next_attr_desc  - next RDN-attribute description list
 *            ->iec_chs_dn           - RDN name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - RDN name length
 *            ->ac_dn                - RDN name
 *            ->adsc_attr            - NULL: no further attribute description(s)
 *
 *     [out] 'iec_chs_dn'            - created DN name character set
 *     [out] 'imc_len_dn'            - created DN name length (in bytes)
 *     [out] 'ac_dn'                 - created DN name
 *
 **************************************************************************************************
 * ied_co_ldap_get_membership (groups):
 *
 *     [out] 'adsc_attr_desc'        - attribute description list (personal- or group-membership)
 *            ->adsc_next_attr_desc  - next attribute description list
 *            ->iec_chs_dn           - dn name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - dn name length
 *            ->ac_dn                - dn name (of the following attribute(s)
 *            ->adsc_attr            - attribute description(s)
 *              ->adsc_next_attr     - next attribute description
 *              ->iec_chs_attr       - attribute name character set (ied_chs_utf_8)
 *              ->imc_len_attr       - attribute name length
 *              ->ac_attr            - attribute name
 *                ->dsc_val;         - attribute value description
 *                 .adsc_next_val    - next value description (if multivalued)
 *                 .iec_chs_val;     - value character set (ied_chs_utf_8)
 *                 .imc_len_val;     - value length
 *                 .ac_val;          - value
 *
 **************************************************************************************************
 * ied_co_ldap_get_sysinfo:
 *
 *     [out] 'adsc_sys_info'         - ldap server system information list
 *            ->adsc_target_ineta    - server ip-address structure
 *            ->imc_port             - server ip-port
 *            ->iec_type             - server ldap type (e.g. OpenLDAP)
 *            ->dsc_base_dn          - list of base-dn description(s)
 *              .adsc_next_val       - next base-dn description (if more than one is defined)
 *              .iec_chs_val;        - base-dn character set (ied_chs_utf_8)
 *              .imc_len_val;        - base-dn length
 *              .ac_val;             - base-dn
 *
 **************************************************************************************************
 * ied_co_ldap_check_pwd_age:
 *
 *     [in]  'iec_chs_dn'            - character set of the DN entry name
 *     [in]  'imc_len_dn'            - DN entry name length (in bytes)
 *     [in]  'ac_dn'                 - DN entry name (to check the password for)
 *
 *     [out] 'adsc_pwd_info'         - ldap server password expire time list
 *            ->iec_account_control  - ldap user account control
 *            ->ilc_exp_minutes;     - password expire time in minutes
 *            ->ilc_exp_hours;       - password expire time in hours
 *            ->ilc_exp_days;        - password expire time in days
 *
 **************************************************************************************************
 * ied_co_ldap_modify:
 *
 *     [in]  'adsc_attr_desc'        - partial attribute description (single- or multi-valued)
 *            ->adsc_next_attr_desc  - next attribute description list
 *            ->iec_chs_dn           - dn name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - dn name length
 *            ->ac_dn                - dn name (of the following attribute(s)
 *            ->adsc_attr            - attribute description(s)
 *              ->adsc_next_attr     - next attribute description
 *              ->iec_chs_attr       - attribute name character set (ied_chs_utf_8)
 *              ->imc_len_attr       - attribute name length
 *              ->ac_attr            - attribute name (which values are changed)
 *                ->dsc_val;         - attribute value description
 *                 .adsc_next_val    - next value description (if multivalued)
 *                 .iec_chs_val;     - value character set (ied_chs_utf_8)
 *                 .imc_len_val;     - value length
 *                 .ac_val;          - value (new)
 *
 **************************************************************************************************
 * ied_co_ldap_modify_dn:
 *
 *     [in]  'iec_chs_dn'        - character set of the (R)DN entry name
 *     [in]  'imc_len_dn'        - (R)DN entry name length (in bytes)
 *     [in]  'ac_dn'             - (R)DN entry name to change
 *     [in]  'iec_chs_newrdn'    - character set of the modifyRDN (e.g. UTF-8)
 *     [in]  'imc_len_newrdn'    - new modifyRDN-name length (in bytes)
 *     [in]  'ac_newrdn'         - new modifyRDN-name (e.g. UTF-8 coded)
 *
 **************************************************************************************************
 * ied_co_ldap_msad_change_password:
 *
 *     [in]  'iec_chs_passwd_new' - simple: new password character set (e.g. ied_chs_ascii_850)
 *     [in]  'imc_len_passwd_new' - simple: new password length
 *     [in]  'ac_passwd_new'      - simple: new password
 *
 **************************************************************************************************
 * ied_co_ldap_search:
 *
 *     [in]  'iec_chs_dn'        - DN baseObject character set
 *     [in]  'imc_len_dn'        - DN baseObject length
 *     [in]  'ac_dn'             - DN baseObject
 *                                 if NULL, the last 'dn' and if not set, the 'namingcontexts' is used
 *                                 as baseObject
 *     [in]  'dsc_add_dn'        - additional relative (user-)base dn
 *     [in]  'iec_sear_scope'    - search at the baseObject or backwards to the root
 *
 *     [in]  'iec_chs_filter'    - filter expression character set (e.g. ied_chs_ascii_850)
 *     [in]  'imc_len_filter'    - filter expression name length
 *     [in]  'ac_filter'         - filter expression (e.g. '(&(ou=hob)(o=malta))' )
 *
 *     [in]  'iec_chs_attrlist'  - attribute list character set (e.g. ied_chs_ascii_850)
 *     [in]  'imc_len_attrlist'  - attribute list length
 *     [in]  'ac_attrlist'       - list of attributes to return, comma separated (CSV)
 *                                 (e.g. 'hcName,hcNo,hcKey')
 *
 *     [out] 'adsc_attr_desc'        - attribute description list (personal- or group-membership)
 *            ->adsc_next_attr_desc  - next attribute description list
 *            ->iec_chs_dn           - dn name character set (ied_chs_utf_8)
 *            ->imc_len_dn           - dn name length
 *            ->ac_dn                - dn name (of the following attribute(s)
 *            ->adsc_attr            - attribute description(s)
 *              ->adsc_next_attr     - next attribute description
 *              ->iec_chs_attr       - attribute name character set (ied_chs_utf_8)
 *              ->imc_len_attr       - attribute name length
 *              ->ac_attr            - attribute name
 *                ->dsc_val;         - attribute value description
 *                 .adsc_next_val    - next value description (if multivalued)
 *                 .iec_chs_val;     - value character set (ied_chs_utf_8)
 *                 .imc_len_val;     - value length
 *                 .ac_val;          - value
 *
 *     [out] 'iec_chs_dn'        - DN baseObject character set (ied_chs_utf_8)
 *     [out] 'imc_len_dn'        - DN baseObject length
 *     [out] 'ac_dn'             - DN baseObject
 *
 */
int dsd_ldap::m_ldap_request( struct dsd_ldap_group *adsp_cfg_ldap,
                              struct dsd_co_ldap_1  *adsp_co_ldap,
                              void                  *vpp_userfld,
                              int (*m_cb_func)(void *, class dsd_ldap *, struct dsd_co_ldap_1 *) )
{                                                                                                   
   int  iml_rc (ied_ldap_success);

   // (re)start temporary storage management
   this->ds_buf_ldap.m_free(&this->ads_hl_stor_tmp);
   START_MEM( this->ads_hl_stor_tmp )

#ifdef DEBUG_AVL
   // DEBUG AVL integrity-check
   dsd_ldap_schema *adsl_schema (dsd_ldap::ads_schema_anc);

   if (adsl_schema && adsl_schema->m_htree_avl_check() == FALSE)
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 10, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "AVL-Tree corrupted!" );
#endif

   // valid parameters?
   if (!adsp_cfg_ldap || !adsp_co_ldap)
   { // set error 'ied_ldap_param_inv'...
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
     adsp_co_ldap->iec_ldap_resp = ied_ldap_failure;
     return TRUE;
   }

   // save configuration pointer...
   this->ads_ldap_group = adsp_cfg_ldap;
   this->il_start_time = 0;

   // set trace level
   this->ds_ldap_trace.m_set_level( this->ads_ldap_group->imc_trace_level );

   // save and set non-blocking callback-parameters
   this->m_cb_func = m_cb_func;
   this->vp_userfld = vpp_userfld;
   this->ds_call_para.ac_param_2 = adsp_co_ldap;

#if SM_BUGFIX_20140724
	this->m_set_request_active(true);
#endif
    // check LDAP command byte...
    switch (adsp_co_ldap->iec_co_ldap)
    {
       case ied_co_ldap_invalid:
       default:                    // invalid command request -> error: invalid parameter
                                   this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
                                   adsp_co_ldap->iec_ldap_resp = ied_ldap_failure;
                                   break;
       case ied_co_ldap_bind:      // bind (connect) to the LDAP - server
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                   { // use blocking call...
                                     iml_rc = this->m_ldap_bind( adsp_co_ldap );
                                     if (iml_rc == ied_ldap_success)
                                     { // set return parameters
                                       adsp_co_ldap->iec_chs_dn = ied_chs_utf_8;   // set distinguished name
                                       adsp_co_ldap->imc_len_dn = this->im_len_dn;
                                       adsp_co_ldap->ac_dn      = this->achr_dn;
                                     }
                                   }
                                   break;
       case ied_co_ldap_get_bind:  // get current bind-context
                                   iml_rc = this->m_ldap_get_bind( adsp_co_ldap );
                                   break;
       case ied_co_ldap_search:    // search entry...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call..
                                     iml_rc = this->m_ldap_search( adsp_co_ldap );

                                   break;
       case ied_co_ldap_lookup:    // test the validity of a DN...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call..
                                     iml_rc = this->m_ldap_lookup( adsp_co_ldap );

                                   break;
       case ied_co_ldap_compare:   // compare entry...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_compare( adsp_co_ldap );

                                   break;
       case ied_co_ldap_modify:    // modify entry...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_modify( adsp_co_ldap );

                                   break;
       case ied_co_ldap_modify_dn: // modify distinguished name...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_modify_dn( adsp_co_ldap );

                                   break;
       case ied_co_ldap_add:       // add entry...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_add( adsp_co_ldap );

                                   break;
       case ied_co_ldap_delete:    // delete entry...
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_delete( adsp_co_ldap );

                                   break;
       case ied_co_ldap_get_attrlist:
                                   // get attribute list of the user
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_get_attrlist( adsp_co_ldap );

                                   break;
       case ied_co_ldap_get_membership:
                                   // get 'memberOf'-membership of an entry (group / user)
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_get_membership( adsp_co_ldap );

                                   break;
       case ied_co_ldap_get_membership_nested:
                                   // get nested 'membership' of an entry (group / user)
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_get_membership_nested( adsp_co_ldap );

                                   break;
      case ied_co_ldap_get_members:
                                   // get 'member'-values of an entry (group / user)
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                    iml_rc = this->m_ldap_get_members( adsp_co_ldap );

                                   break;
      case ied_co_ldap_get_members_nested:
                                   // get 'member'-values of an entry (group / user)
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_get_members_nested( adsp_co_ldap );

                                  break;
       case ied_co_ldap_get_sysinfo:
                                   // get ldap server system informations
                                   iml_rc = this->m_ldap_get_sysinfo( adsp_co_ldap );
                                   break;
       case ied_co_ldap_explode_dn:
                                   // get the RDNs of a given DN
                                   iml_rc = this->m_ldap_explode_dn( adsp_co_ldap );
                                   break;
       case ied_co_ldap_clone_dn:  // create these RDNs and the user in the current LDAP
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_clone_dn( adsp_co_ldap );

                                   break;
       case ied_co_ldap_check_pwd_age:
								   // check the user's password age
                                   if (this->m_cb_func)
                                   { // use nonblocking call mechanism...
                                     m_hco_run_thread( &this->ds_call_para );
                                     iml_rc = ied_ldap_would_block;
                                   }
                                   else
                                     // use blocking call...
                                     iml_rc = this->m_ldap_check_pwd_age( adsp_co_ldap );

                                   break;
       case ied_co_ldap_abandon:   // cancel request...
                                   iml_rc = this->m_ldap_abandon();
                                   break;
       case ied_co_ldap_get_last_err:
                                   // get the last error
                                   iml_rc = this->m_ldap_get_last_error();
                                   break;
       case ied_co_ldap_close:     // close server connection...
                                   iml_rc = this->m_ldap_close(NULL);
                                   break;
    } // switch(ldap-cmd)
#if SM_BUGFIX_20140724
	this->m_set_request_active(false);
#endif

   // check the return code...
   switch (iml_rc)
   {
      default:        // error...
                      adsp_co_ldap->iec_ldap_resp  = ied_resp_ldap_def(this->ds_ldap_error.m_get_error());
REQ_ERROR:
                      adsp_co_ldap->iec_chs_errmsg = ied_chs_utf_8;
                      adsp_co_ldap->ac_errmsg      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, HL_ERRMSG_LEN );
                      adsp_co_ldap->imc_len_errmsg = (int)this->ds_ldap_error.m_format_msg( (char *)adsp_co_ldap->ac_errmsg, HL_ERRMSG_LEN,
                                                                                            &this->ds_conn,
                                                                                            this->ads_ldap_entry ? this->ads_ldap_entry->imc_port : 0 );
                      // trace message LDAP0091T
                      if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR ))
                        this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 91, this->im_sess_no, m_get_epoch_ms(),
                                                     &this->ds_conn, this->ads_ldap_entry,
                                                     "LdapResp=%i RC=%i Message=\"%.*(.*)s\"",
                                                     adsp_co_ldap->iec_ldap_resp, iml_rc,
                                                     adsp_co_ldap->imc_len_errmsg, adsp_co_ldap->iec_chs_errmsg, adsp_co_ldap->ac_errmsg );

                      // ticket 49335 (map 'no error' to 'success')
                      if (adsp_co_ldap->iec_ldap_resp == 0)
                        adsp_co_ldap->iec_ldap_resp = ied_ldap_success; 

                      break;
      case ied_ldap_no_bind:
                      // no valid bind context...
      case ied_ldap_not_allowed_on_nleaf:
                      // non-empty node is not deleted...
      case ied_ldap_attr_or_val_exist:
                      // modify value already set...
      case ied_ldap_password_change:
      case ied_ldap_password_expired:
                      // password expired...
                      adsp_co_ldap->iec_ldap_resp = (ied_resp_ldap_def)iml_rc;
                      goto REQ_ERROR;

      case ied_ldap_would_block:
                      // function would block...
      case ied_ldap_sasl_bind:
                      // bind in progress...
      case ied_ldap_cmp_true:
      case ied_ldap_cmp_false:
                      // m_ldap_compare return values...
      case ied_ldap_success:
                      // clear error handling
                      this->ds_ldap_error.m_free();
                      adsp_co_ldap->iec_ldap_resp  = (ied_resp_ldap_def)iml_rc;
                      adsp_co_ldap->imc_len_errmsg = 0;
                      adsp_co_ldap->ac_errmsg      = NULL;
                      break;
   } // switch (iml_rc)

   // close TCP connection?
   class dsd_ldap_control  *adsl_ldap_control (this->ads_ldap_control);
   if (adsl_ldap_control && adsl_ldap_control->bo_tcperr)
     this->m_ldap_close(NULL);

#if SM_BUGFIX_20140724
	if (this->im_c_status != dsd_ldap::DISCONNECTED) 
    {
      this->ds_buf_ldap.m_free(&this->ads_hl_stor_tmp);

      if (this->ads_ldap_control)
	    this->ads_ldap_control->ds_tcpcomp.m_recv();
	}
#endif

#ifdef DEBUG_AVL
   // DEBUG AVL integrity-check
   adsl_schema = dsd_ldap::ads_schema_anc;

   if (adsl_schema && adsl_schema->m_htree_avl_check() == FALSE)
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 11, this->im_sess_no, m_get_epoch_ms(),
		&this->ds_conn, this->ads_ldap_entry,
                                  "AVL-Tree corrupted!" );
#endif
   return TRUE;

} // dsd_ldap::m_ldap_request( dsd_ldap_group*, dsd_co_ldap_1*, void *, (*m_cb_func)() )

/**
 * Constructor of the class dsd_ldap
 *
 * Initializes and creates all the needed members. The static members and
 * methods are initialized only once.
 */
void dsd_ldap::m_ldap_init()
{

   // initialize member variables...
   this->im_ldap_msgid  = 0;        // set start message ID
   this->ads_ldap_group = NULL;     // no configuration group set
   this->ads_ldap_entry = NULL;     // no configuration entry set
   this->im_ldap_templ  = ied_sys_ldap_generic;
   this->im_ldap_type   = ied_sys_ldap_generic;

#ifdef _DEBUG
   this->imc_req_counter = 0;
#endif
	// don't create the ldap-control-class here. we have changed the logic, so
   // create it at tcpcomp-'connect()'!
   this->ads_ldap_control = NULL;
#if SM_BUGFIX_20140724
	this->dsc_cs_ldap2.m_create();
	this->boc_pending_request = false;
#endif

	this->ds_ev_connect.m_create( &this->ds_ldap_error.im_apicode );

   this->im_c_status = dsd_ldap::DISCONNECTED;
   this->achr_dn     = NULL;       // no bind-DN set
   this->achr_pwd    = NULL;       // no bind-password
   this->im_len_dn = this->im_len_pwd = 0;

   // initialize all 'RootDSE'-members and the LDAP request structure...
   memset( (void *)&this->ds_RootDSE, 0, sizeof(struct dsd_RootDSE) );
   memset( (void *)&this->ds_ldapreq, 0, sizeof(struct dsd_ldap::dsd_ldapreq) );
   this->bo_RootDSE      = FALSE;
   this->bo_page_results = FALSE;

   // rfc 2696 ('pagedResultsControl')
   this->avo_cookie    = NULL;
   this->im_cookie_len = 0;

   this->ads_domainSID   = NULL;
   this->ads_ldap_schema = NULL;
   this->ads_referral    = NULL;

   // initialize ssl...
   this->ach_ssltoappl_buf = NULL; // ssl translate buffers
   this->ach_ssltosock_buf = NULL;
   this->ads_hl_stor_ssl   = NULL;

#if SM_USE_RECV_GATHERS
   m_gatherlist_init(&this->dsc_recv_data);
#endif

   // initialize permanent and temporary storage handle
   // la; this comment avoids memory leaks, if the class is closed
   // this->ads_hl_stor_tmp = this->ads_hl_stor_per = NULL;
   START_MEM( this->ads_hl_stor_tmp )
   START_MEM( this->ads_hl_stor_per )

   // initialize error/trace handling
   this->ds_ldap_error.m_init( this->ads_hl_stor_per );
   this->ds_ldap_trace.m_init( "LDAP", sizeof "LDAP" - 1 );

   // initialize static members only once...
#if defined WIN32 || defined WIN64
   if (InterlockedCompareExchange( (LONG volatile *)&dsd_ldap::im_init_cs, 1, 0 ) == 0)
     dsd_ldap::ds_cs_ldap.m_create();          // critical section overall instances
#elif defined HL_UNIX
   if (__sync_val_compare_and_swap( &dsd_ldap::im_init_cs, 0, 1) == 0)
     dsd_ldap::ds_cs_ldap.m_create();          // critical section overall instances
#endif

   // next instance...
   dsd_ldap::ds_cs_ldap.m_enter();
   {
     if (!dsd_ldap::im_init_cnt)
       START_MEM( dsd_ldap::ads_hl_stor_glob )  // initialize storage handler

     ++dsd_ldap::im_init_cnt;       // increment instance count...
   }
   dsd_ldap::ds_cs_ldap.m_leave();

   // statistics (session number)
   this->im_sess_no = im_init_cnt;

   // socket initialization
   memset( (void *)&this->ds_conn, 0, sizeof(struct sockaddr_storage) );

   // initialize nonblocking environment
   this->ds_call_para.amc_function = &mg_wt_ldap_request;
   this->ds_call_para.ac_param_1 = this;
   this->ds_call_para.ac_param_2 = NULL;
   this->ds_call_para.ac_param_3 = NULL;

   // check the machine endianess...
   { int   iml_1 = 1;
     char *achl_1 = (char *)&iml_1;
     if (achl_1[0] == 1) // lowest address contains the least significant byte
       // little endian
       this->bo_le = TRUE;
     else
       this->bo_le = FALSE;
   }

#ifdef DEBUG_AVL
   // DEBUG AVL integrity-check
   dsd_ldap_schema *adsl_schema (dsd_ldap::ads_schema_anc);

   if (adsl_schema && adsl_schema->m_htree_avl_check() == FALSE)
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 12, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "AVL-Tree corrupted!" );
#endif

   return;

} // dsd_ldap::m_ldap_init()


/**
 * Destructor of the class dsd_ldap
 *
 * Frees all the used resources and decrements the session counter
 */
void dsd_ldap::m_ldap_free()
{
   // close TCP connection...
   this->m_ldap_close(NULL);
   this->ds_ev_connect.m_close( &this->ds_ldap_error.im_apicode );

#ifdef DEBUG_AVL
   // DEBUG AVL integrity-check
   dsd_ldap_schema *adsl_schema (dsd_ldap::ads_schema_anc);

   if (adsl_schema && adsl_schema->m_htree_avl_check() == FALSE)
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 14, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "AVL-Tree corrupted!" );
#endif
#if SM_BUGFIX_20140804
   if (this->ads_ldap_control != NULL) {
	   if (this->ads_ldap_control->m_ref_dec()) {
		  delete this->ads_ldap_control;
	   }
	   this->ads_ldap_control = NULL;
   }
#endif

   // adjust session counter...
   dsd_ldap::ds_cs_ldap.m_enter();
   {
     if (dsd_ldap::im_init_cnt > 0)
       --dsd_ldap::im_init_cnt;

     //cleanup resources, if this is the last running session!
     if (!dsd_ldap::im_init_cnt)
     { // free the AVL trees and reset schema anchor
       dsd_ldap::ads_schema_anc = NULL;
       END_MEM(dsd_ldap::ads_hl_stor_glob);
     }
   } // last running session
   dsd_ldap::ds_cs_ldap.m_leave();


   // reset receive buffer management
   this->ds_buf_ldap.m_free(&this->ads_hl_stor_tmp);
#if SM_USE_RECV_GATHERS
   m_gatherlist_free(&this->dsc_recv_data);
#else
   this->ds_buf_ssl.m_free(&this->ads_hl_stor_ssl);
#endif

   // reset error/trace structure
   this->ds_ldap_error.m_free();
   this->ds_ldap_trace.m_free();

   // free permanent and ssl storage page
   END_MEM(this->ads_hl_stor_tmp);
   END_MEM(this->ads_hl_stor_per);
   END_MEM(this->ads_hl_stor_ssl);
#ifdef HL_DEBUG
  #ifdef _CRTDBG_MAP_ALLOC
   _CrtSetDbgFlag( _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF );
   _CrtDumpMemoryLeaks();
  #endif
#endif
   this->achr_dn  = NULL;
   this->achr_pwd = NULL;
   this->im_len_dn = this->im_len_pwd = 0;

   this->ads_referral = NULL;
   // reset 'pagedResultsControl'-Cookie
   this->avo_cookie    = NULL;
   this->im_cookie_len = 0;

   return;

} // dsd_ldap::m_ldap_free()


/**
 * LDAP instance work thread function:  m_wt_ldap_request()
 *
 * Work thread function for different LDAP commands, which would block.
 *
 * @param[in]  adsp_wt       work thread object
 * @param[in]  adsp_co_ldap  LDAP command structure
 *
 * @return     none
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
void dsd_ldap::m_wt_ldap_request( struct dsd_hco_wothr *adsp_wt, struct dsd_co_ldap_1 *adsp_co_ldap )
{
   int iml_rc;

   // check LDAP command byte...
   //::m_hco_wothr_blocking( adsp_wt ); ???
#ifdef HL_DEBUG
   _ASSERTE(_CrtIsValidPointer( adsp_co_ldap, sizeof(struct dsd_co_ldap_1), FALSE ));
#endif

   switch (adsp_co_ldap->iec_co_ldap)
   {
      default:                    // invalid command request -> error: invalid parameter
                                  this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
                                  adsp_co_ldap->iec_ldap_resp = ied_ldap_failure;
                                  iml_rc = ied_ldap_failure;
                                  break;
      case ied_co_ldap_bind:      // bind (connect) to the LDAP - server
                                  iml_rc = this->m_ldap_bind( adsp_co_ldap );
                                  if (iml_rc == ied_ldap_success)
                                  { // set return parameters
                                    adsp_co_ldap->iec_chs_dn = ied_chs_utf_8;   // set distinguished name
                                    adsp_co_ldap->imc_len_dn = this->im_len_dn;
                                    adsp_co_ldap->ac_dn      = this->achr_dn;
                                  }
                                  break;
      case ied_co_ldap_search:    // search entry...
                                  iml_rc = this->m_ldap_search( adsp_co_ldap );
                                  break;
      case ied_co_ldap_lookup:    // test the validity of a DN...
                                  iml_rc = this->m_ldap_lookup( adsp_co_ldap );
                                  break;
      case ied_co_ldap_compare:   // compare entry...
                                  iml_rc = this->m_ldap_compare( adsp_co_ldap );
                                  break;
      case ied_co_ldap_modify:    // modify entry...
                                  iml_rc = this->m_ldap_modify( adsp_co_ldap );
                                  break;
      case ied_co_ldap_modify_dn: // modify distinguished name...
                                  iml_rc = this->m_ldap_modify_dn( adsp_co_ldap );
                                   break;
      case ied_co_ldap_add:       // add entry...
                                  iml_rc = this->m_ldap_add( adsp_co_ldap );
                                  break;
      case ied_co_ldap_clone_dn:  // clone the given RDNs...
                                  iml_rc = this->m_ldap_clone_dn( adsp_co_ldap );
                                  break;
      case ied_co_ldap_delete:    // delete entry...
                                  iml_rc = this->m_ldap_delete( adsp_co_ldap );
                                  break;
      case ied_co_ldap_get_attrlist:
                                  // get attribute list of the user
                                  iml_rc = this->m_ldap_get_attrlist( adsp_co_ldap );
                                  break;
      case ied_co_ldap_get_membership:
                                  // get 'memberOf'-membership of an entry (group / user)
                                  iml_rc = this->m_ldap_get_membership( adsp_co_ldap );
                                  break;
      case ied_co_ldap_get_membership_nested:
                                  // get nested 'membership' of an entry (group / user)
                                  iml_rc = this->m_ldap_get_membership_nested( adsp_co_ldap );
                                  break;
      case ied_co_ldap_get_members:
                                  // get 'member'-values of an entry (group / user)
                                  iml_rc = this->m_ldap_get_members( adsp_co_ldap );
                                  break;
      case ied_co_ldap_get_members_nested:
                                  // get 'member'-values of an entry (group / user)
                                  iml_rc = this->m_ldap_get_members_nested( adsp_co_ldap );
                                  break;
      case ied_co_ldap_check_pwd_age:
                                  // check the user's password age
                                  iml_rc = this->m_ldap_check_pwd_age( adsp_co_ldap );
                                  break;
   } // switch(ldap-cmd)

   // @todo: m_hco_wothr_active( adsp_wt );  ???

   // check the return code...
   switch (iml_rc)
   {
        default:        // error...
                        adsp_co_ldap->iec_ldap_resp  = ied_resp_ldap_def( this->ds_ldap_error.m_get_error() );
WT_REQ_ERROR:
                        adsp_co_ldap->iec_chs_errmsg = ied_chs_utf_8;
                        adsp_co_ldap->ac_errmsg      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, HL_ERRMSG_LEN );
                        adsp_co_ldap->imc_len_errmsg = (int)this->ds_ldap_error.m_format_msg( (char *)adsp_co_ldap->ac_errmsg, HL_ERRMSG_LEN,
                                                                                              &this->ds_conn, this->ads_ldap_entry->imc_port );
                        // trace message LDAP0092T
                        if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR ))
                          this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 92, this->im_sess_no, m_get_epoch_ms(),
                                                       &this->ds_conn, this->ads_ldap_entry,
                                                       "WT-Error=%i Message=\"%.*(.*)s\"",
                                                       adsp_co_ldap->iec_ldap_resp,
                                                       adsp_co_ldap->imc_len_errmsg, adsp_co_ldap->iec_chs_errmsg, adsp_co_ldap->ac_errmsg );
                        break;

        case ied_ldap_password_change:
                        // password expired...
                        adsp_co_ldap->iec_ldap_resp = (ied_resp_ldap_def)iml_rc;
                        goto WT_REQ_ERROR;

        case ied_ldap_attr_or_val_exist:
                        // modify value already set...
                        adsp_co_ldap->iec_ldap_resp = (ied_resp_ldap_def)iml_rc;
                        goto WT_REQ_ERROR;

        case ied_ldap_would_block:
                        // function would block...
        case ied_ldap_sasl_bind:
                        // bind in progress...
        case ied_ldap_not_allowed_on_nleaf:
                        // non-empty node is not deleted...
        case ied_ldap_cmp_true:
        case ied_ldap_cmp_false:
                        // m_ldap_compare() return values...
        case ied_ldap_success:
                        // clear error handling
                        this->ds_ldap_error.m_free();
                        adsp_co_ldap->iec_ldap_resp  = (ied_resp_ldap_def)iml_rc;
                        adsp_co_ldap->imc_len_errmsg = 0;
                        adsp_co_ldap->ac_errmsg      = NULL;
                        break;
   } // switch()

   // close TCP connection...
   class dsd_ldap_control  *adsl_ldap_control (this->ads_ldap_control);
   if (adsl_ldap_control && adsl_ldap_control->bo_tcperr)
     this->m_ldap_close(NULL);

   // inform caller...
   // only test
   if (this->m_cb_func)
     this->m_cb_func( this->vp_userfld, this, adsp_co_ldap );

} // dsd_ldap::m_wt_ldap_request( struct dsd_hco_wothr *, struct dsd_co_ldap_1 * )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_connect()
 *
 * Connect callback function. In the case of an error the callback-function
 * 'm_cb_connect_err()' is called.
 *
 * @param[in]  adsp_soa      sockaddr structure (ipv4 or ipv6)
 * @param[in]  imp_len_soa   length of the sockaddr structure
 *
 * @return     none
 */
void dsd_ldap::m_cb_connect( struct sockaddr *adsp_soa, socklen_t imp_len_soa )
{
#if !SM_BUGFIX_20140804
	// increment session count...
#if defined WIN32 || defined WIN64
   InterlockedIncrement((LONG volatile *)&dsd_ldap::im_sess_cnt);
#elif defined HL_UNIX
   __sync_add_and_fetch(&dsd_ldap::im_sess_cnt, 1);
#endif
#endif

   // -> statistics
#if !SM_BUGFIX_20140724
	this->ads_ldap_entry->imc_cur_session = dsd_ldap::im_sess_cnt;
#endif
	++this->ads_ldap_entry->imc_no_conn_suc;

#if !SM_BUGFIX_20140724
   if (dsd_ldap::im_sess_cnt > this->ads_ldap_entry->imc_max_session)
   { // we have a new maximum
     this->ads_ldap_entry->imc_max_session = dsd_ldap::im_sess_cnt;
     this->ads_ldap_entry->imc_l_epoch_max_session = (int)m_get_epoch_ms();
   }
#endif
	// <- statistics

   // save ip-address...
   if (adsp_soa && imp_len_soa)
     memcpy((void *)&this->ds_conn, (const void *)adsp_soa, imp_len_soa );

   this->im_c_status = dsd_ldap::CONNECTED;
   this->ads_ldap_control->bo_tcperr        = FALSE;
   this->ads_ldap_control->bo_recv_complete = FALSE;
   this->ads_ldap_control->bo_connected     = TRUE;

   // >>> trace message LDAP0022T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 22, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry, "Connected" );

   // set event (connect succesful or error)
   this->ds_ev_connect.m_post( &this->ds_ldap_error.im_apicode );

   return;

} // dsd_ldap::m_cb_connect( struct sockaddr *, socklen_t )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_connect_err()
 *
 * Connect error callback function.
 *
 * @param[in]  adsp_soa           sockaddr structure (ipv4 or ipv6)
 * @param[in]  imp_len_soa        length of the sockaddr structure
 * @param[in]  imp_current_index  index number of the entry failed
 * @param[in]  imp_total_index    number of all entries
 * @param[in]  imp_errno          error code
 *
 * @return     none
 */
void dsd_ldap::m_cb_connect_err( struct sockaddr *adsp_soa, socklen_t imp_len_soa,
                                 int imp_current_index, int imp_total_index, int imp_errno )
{
   // connection was not successful!
   // save error code 'imp_err' and ip-address...
   if (adsp_soa && imp_len_soa)
     memcpy((void *)&this->ds_conn, (const void *)adsp_soa, imp_len_soa );
   this->ds_ldap_error.m_set_error( ied_ldap_connect_err/*LDAP result code*/, imp_errno/*API error*/ );

   // >>> trace message LDAP0021T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 21, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "TCPIP-Connect Error=%i", imp_errno );

   this->im_c_status = dsd_ldap::DISCONNECTED;

   // set tcpcomp error location flag...
   this->ads_ldap_control->bo_tcperr    = TRUE;
   this->ads_ldap_control->bo_connected = FALSE;
   // @todo: try next server configuration address...

   // statistics...
   ++this->ads_ldap_entry->imc_no_conn_fail;

   // set connect-event(error);
   this->ds_ev_connect.m_post( &this->ds_ldap_error.im_apicode );
   return;

} // dsd_ldap::m_cb_connect_err( struct sockaddr *, socklen_t )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_send()
 *
 * Send callback function. Resend buffers.
 */
void dsd_ldap::m_cb_send()
{
   dsd_gather_i_1 *adsl_gath  (NULL);

   // are there any data to send?
   if (this->ads_ldap_control &&
       this->ds_gather_send.achc_ginp_end - this->ds_gather_send.achc_ginp_cur)
   { // yes, set statistics and send rest of data...
     ++this->ads_ldap_entry->imc_send_packet;

     if (this->ads_ldap_control->ds_tcpcomp.m_send_gather( &this->ds_gather_send, &adsl_gath ) == 0)
     { // send error
       // @todo: set error structure and close TCP-connection...
       return;
     }

     // no send error...
     if (adsl_gath)
     { // send blocked, calculate new send address...
       memcpy((void *)&this->ds_gather_send, (const void *)adsl_gath, sizeof(struct dsd_gather_i_1) );
       this->ads_ldap_control->ds_tcpcomp.m_sendnotify();
     }
   }

   return;

} // dsd_ldap::m_cb_send()

/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_getrecvbuf()
 *
 * Get receive buffer callback function (SSL and nonSSL).
 *
 * @param[out]  aavop_handle  pointer to the buffer handle variable (internally used)
 * @param[out]  aachp_buffer  pointer to the buffer pointer variable (where to write)
 * @param[out]  aaimp_len     pointer to the buffer length variable (bytes written)
 *
 * @return      maximum buffer length. 0 = receive not allowed
 */
int dsd_ldap::m_cb_getrecvbuf( void **aavop_handle, char **aachp_buffer, int **aaimp_len )
{

#if SM_BUGFIX_20140724
	bool bol_pending_request = false;
	this->dsc_cs_ldap2.m_enter();
	bol_pending_request = this->boc_pending_request;
	this->dsc_cs_ldap2.m_leave();
#endif
	if (!bol_pending_request) 
    {
		return 0;
	}

#if SM_USE_RECV_GATHERS
	//this->dsc_cs_ldap2.m_enter();
	struct dsd_gather_i_1* adsl_tmp = (struct dsd_gather_i_1*)malloc(sizeof(struct dsd_gather_i_1) + D_LDAP_RBUF_SIZE);
	if (adsl_tmp == NULL)
		return 0;
	//this->dsc_cs_ldap2.m_leave();
	adsl_tmp->achc_ginp_cur = (char*)(adsl_tmp + 1);
	adsl_tmp->achc_ginp_end = adsl_tmp->achc_ginp_cur + D_LDAP_RBUF_SIZE;
    *aavop_handle = adsl_tmp;
    *aachp_buffer = adsl_tmp->achc_ginp_cur;
    *aaimp_len    = &this->inc_recv_data_len;
	this->inc_recv_data_len = 0;

   //return min(adsl_buf->imc_buflen - adsl_buf->imc_pos, 1);
   return D_LDAP_RBUF_SIZE;
#else
   int  iml_len  (0);
   class dsd_bufm *adsl_buf (&this->ds_buf_ldap);

	if (!this->ads_ldap_control->bo_recv) 
    {
		return 0;
	}

	// SSL or nonSSL?
   if (this->ads_ldap_entry->boc_csssl_conf)
   { // yes, SSL...
     adsl_buf = &this->ds_buf_ssl;

#ifdef HOB_SSL_BUFFER_CHECK
   // trace message LDAP0081T
   if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_DATA, 81, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "m_cb_getrecvbuf (SSL) (len=%i, data-len=%i, data-len_s = %i, pos=%i, next-pos=%i)",
                                  adsl_buf->imc_buflen, adsl_buf->imc_datalen, adsl_buf->imc_datalen_s, adsl_buf->imc_pos, adsl_buf->imc_nextpos );
#endif
     // initiate internal storage, if needed...
#if 1
	if (!adsl_buf->m_ensure_capacity(&this->ads_hl_stor_ssl, D_LDAP_SSL_RECV_BUFFER_LEN))
		return 0;
#else
   if (adsl_buf->imc_buflen == 0)
       adsl_buf->m_alloc( &this->ads_hl_stor_ssl, D_LDAP_SSL_RECV_BUFFER_LEN );
     else
     { // do we need more storage?
       if (adsl_buf->imc_buflen - adsl_buf->imc_pos == 0 /*the whole buffer is in use*/)
       { // yes, we need more storage...
         adsl_buf->imc_buflen += D_LDAP_SSL_RECV_BUFFER_LEN;
#if D_LDAP_RBUF_MAXSIZE > 0
         if (adsl_buf->imc_buflen < D_LDAP_RBUF_MAXSIZE)
           // reallocate a new storage (internal or external)
           adsl_buf->m_realloc( adsl_buf->imc_buflen );
         else
           // set exception (no more memory)
           goto GETBUF_ERROR;
#else
           // no receive buffer limitation!
		   // reallocate a new storage (internal or external)
           adsl_buf->m_realloc( &this->ads_hl_stor_ssl, adsl_buf->imc_buflen );
#endif
	     }
     }
#endif
   }
   else
   { // nonSSL work flow...
     // initiate internal storage, if needed...
	 if (!adsl_buf->m_ensure_capacity(&this->ads_hl_stor_tmp, D_LDAP_TL_SIZE))
		return 0;
	 switch (this->ds_asn1.m_test_resp( adsl_buf, &iml_len ))
       {
         default:
         case LASN1_ERROR:     // ASN.1 decoding error...
                               this->ds_ldap_error.m_set_error( ied_ldap_decoding_err );
         case LASN1_SUCCESS:   // TLV complete!
                               this->ads_ldap_control->bo_recv = FALSE;
                               return 0;
         case LASN1_WAIT_MORE: // is the remaining length sufficient?
                               // we need more storage
							   int iml_valid_len = adsl_buf->imc_pos - adsl_buf->imc_nextpos;
							   if (!adsl_buf->m_ensure_capacity(&this->ads_hl_stor_tmp, iml_valid_len + iml_len))
								  return 0;
                               break;
       } // switch (m_test_resp)
   } // end of nonSSL

#ifdef HOB_SSL_BUFFER_CHECK
   // trace message LDAP0099T
   if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
     this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 99, this->im_sess_no, m_get_epoch_ms(),
                                 &this->ds_conn, this->ads_ldap_entry,
                                 "m_cb_getrecvbuf (SSL-ret) (len=%i, pos=%i, data-len_s= %i)",
                                 adsl_buf->imc_buflen, adsl_buf->imc_pos, adsl_buf->imc_datalen_s);
#endif

   // set receive buffer parameters...
   *aavop_handle = adsl_buf;
   *aachp_buffer = (char *)adsl_buf->m_getaddr() + adsl_buf->imc_pos;
   *aaimp_len    = &adsl_buf->imc_datalen;

   //return min(adsl_buf->imc_buflen - adsl_buf->imc_pos, 1);
   return adsl_buf->imc_buflen - adsl_buf->imc_pos;
#endif
} // dsd_ldap::m_cb_getrecvbuf( void**, char**, int** )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_recv()
 *
 * Receive callback function.
 *
 * @param[in]  avop_handle   pointer to the buffer handle (dsd_ldap::ach_buf)
 *
 * @return     \b TRUE   if more data should be received,
 *             \b FALSE  otherwise
 */
int dsd_ldap::m_cb_recv( void* avop_handle )
{
#if SM_BUGFIX_20140724
	bool bol_pending_request = false;
	this->dsc_cs_ldap2.m_enter();
	bol_pending_request = this->boc_pending_request;
	this->dsc_cs_ldap2.m_leave();
	
#endif
#if SM_USE_RECV_GATHERS
	if (!bol_pending_request)
	{ // @todo: generate error message or something else...
		this->ads_ldap_control->ds_tcpcomp.m_end_session();
		this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err );
		return FALSE;
	}
	struct dsd_gather_i_1* adsl_tmp = (struct dsd_gather_i_1*)avop_handle;
	// are there data available ?
   if (this->inc_recv_data_len <= 0)
   { // @todo: generate error message or something else...
		::free(adsl_tmp);
		this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err );
		return FALSE;
   }
	adsl_tmp->achc_ginp_end = adsl_tmp->achc_ginp_cur + this->inc_recv_data_len;
	this->inc_recv_data_len = 0;
	this->dsc_cs_ldap2.m_enter();
	m_gatherlist_push_back(&this->dsc_recv_data, adsl_tmp);
	this->dsc_cs_ldap2.m_leave();
	
	this->ads_ldap_control->ds_ev_response.m_post( &this->ds_ldap_error.im_apicode );
	return FALSE;
#else
	class dsd_bufm *adsl_buf ((class dsd_bufm *)avop_handle);

   // don't receive any data (so far)
   this->ads_ldap_control->bo_recv = FALSE;


	// do we get a valid parameter or do we receive an error or is the connection closed?
   if (adsl_buf == NULL || adsl_buf->imc_datalen < 0)
   { // connection closed or error received
     this->im_c_status = dsd_ldap::DISCONNECTED;

     this->ads_ldap_control->bo_tcperr    = TRUE;
     this->ads_ldap_control->bo_connected = FALSE;

     goto RECV_READY;
   }

#if SM_BUGFIX_20140724
   if (!bol_pending_request)
   { // @todo: generate error message or something else...
		this->ads_ldap_control->ds_tcpcomp.m_end_session();
		this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err );
		return FALSE;
   }
#endif

	// are there data available ?
   if (adsl_buf->imc_datalen == 0)
   { // @todo: generate error message or something else...
     this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err );
     return FALSE;
   }

   // save data received so far...
#ifdef HOB_SSL_BUFFER_CHECK
   int  iml_pos_s  (adsl_buf->imc_pos);
#endif
   adsl_buf->imc_pos += adsl_buf->imc_datalen;
   // save overall data length
   adsl_buf->imc_datalen_s += adsl_buf->imc_datalen;

   // statistics...
   this->ads_ldap_entry->ilc_recv_data += adsl_buf->imc_datalen;
   ++this->ads_ldap_entry->imc_recv_packet;
#ifdef HOB_SSL_BUFFER_CHECK
   // trace message LDAP0080T
   if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_DATA, 80, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "m_cb_recv (packet=%i, data-len=%i, data-len-s= %i, pos-s=%i, pos=%i, next-pos=%i, buf_len=%i)",
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_recv_packet : 0, 
                                  adsl_buf->imc_datalen, adsl_buf->imc_datalen_s,
                                  iml_pos_s, adsl_buf->imc_pos, adsl_buf->imc_nextpos, adsl_buf->imc_buflen );
#endif

#if HOB_LDAP_TRACE_TRAFFIC
   m_hl1_printf("#CBRECV: len=%d", adsl_buf->imc_pos-adsl_buf->imc_nextpos);
   m_console_out((char*)adsl_buf->m_getaddr()+adsl_buf->imc_nextpos, adsl_buf->imc_pos-adsl_buf->imc_nextpos);
#endif
   // only nonSSL processing (we cannot check the ASN.1 in SSL)
   if (this->ads_ldap_entry->boc_csssl_conf == FALSE)
   { // LDAP result --> test for all data received
     // Look for a complete TLV-message...
     int iml_len (0);

     switch (this->ds_asn1.m_test_resp( adsl_buf, &iml_len ))
     {
       case LASN1_ERROR:     // ASN.1 decoding error...
	   default:
                             this->ds_ldap_error.m_set_error( ied_ldap_decoding_err );
                             return FALSE;
       case LASN1_WAIT_MORE: // wait for more data...
                             this->ads_ldap_control->bo_recv = TRUE;  // wait for more data...
                             return TRUE;
       case LASN1_SUCCESS:   // TLV complete!
                             this->ads_ldap_control->bo_recv_complete = TRUE; // we have received a complete response
							 break;
     } // switch (m_test_resp)
   } // end of nonSSL work flow

RECV_READY:
   // set 'response ready for parsing'-event...
   this->ads_ldap_control->ds_ev_response.m_post( &this->ds_ldap_error.im_apicode );
   return FALSE;
#endif
} // dsd_ldap::m_cb_recv( void* )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_error()
 *
 * Error callback function (to the specific instance of dsd_ldap).
 *
 * @param[in]  strp_err     short error message
 * @param[in]  imp_errno    API error number
 * @param[in]  imp_errloc   tcpcomp error location (See tcpcomp::ERRORAT_XXXX flags)
 *
 * @return     none
 */
void dsd_ldap::m_cb_error( char *strp_err, int imp_errno, int imp_errloc )
{

   // set tcpcomp error location flag...
   this->ads_ldap_control->bo_tcperr = TRUE;

   switch (imp_errloc)
   {
      case ERRORAT_RECV:
      case ERRORAT_STOPCONN:
      case ERRORAT_STARTCONN:
      case ERRORAT_TCPTHREAD: this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err, // LDAP result code
                                                               imp_errno,            // API error
                                                               NULL, 0,              // (R)DN, Length
                                                               strp_err, (int)strnlen( strp_err, D_LDAP_MAX_STRLEN ) );
                              break;
      case ERRORAT_CLOSE:     this->ds_ldap_error.m_set_error( ied_ldap_connection_closed, // LDAP result code
                                                               imp_errno,                  // API error
                                                               NULL, 0,                    // (R)DN, Length
                                                               strp_err, (int)strnlen( strp_err, D_LDAP_MAX_STRLEN ) );
                              // statistics...
                              if (this->ads_ldap_entry)
                                ++this->ads_ldap_entry->imc_error_sess;

                              break;
      case ERRORAT_CONNECT:   this->ds_ldap_error.m_set_error( ied_ldap_connect_err, // LDAP result code
                                                               imp_errno,            // API error
                                                               NULL, 0,              // (R)DN, Length
                                                               strp_err, (int)strnlen( strp_err, D_LDAP_MAX_STRLEN ) );
                              break;
      case ERRORAT_SEND:      this->ds_ldap_error.m_set_error( ied_ldap_send_err, // LDAP result code
                                                               imp_errno,         // API error
                                                               NULL, 0,           // (R)DN, Length
                                                               strp_err, (int)strnlen( strp_err, D_LDAP_MAX_STRLEN ) );
      default:                break;
   }

   // trace message LDAP0093T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 93, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "TCPIP-Error=%i Function=%i Message=%s",
                                  imp_errno, imp_errloc, strp_err ? strp_err : "none" );
   return;

} // dsd_ldap::m_cb_error( char*, int, int )


/**
 * TCPCOMP instance callback function: dsd_ldap::m_cb_cleanup_serverside()
 *
 * Cleanup callback function for server-side close (to the specific instance
 * of dsd_ldap).
 *
 * @param[in]  adsp_tcpcomp  class dsd_tcpcomp object
 *
 * @return     none
 *
 * Remarks: If this instance of cleanup is called, we have a valid ldap object
 */
void dsd_ldap::m_cb_cleanup_serverside( class dsd_tcpcomp *adsp_tcpcomp, class dsd_ldap_control* adsp_req )
{
   // trace message LDAP0097T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 97, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, (struct dsd_ldap_entry *)this->ads_ldap_entry,
                                  "TCPIP-Cleanup (server-side, tcpcomp=%i, ldap=%i)", adsp_tcpcomp, this );

   // asynchronous cleanup (server-side)
   this->m_ldap_close(adsp_req);
	int inl_err;
   adsp_req->ds_ev_response.m_post(&inl_err);
   return;

} // dsd_ldap::m_cb_cleanup_serverside()


/**
 * Public class function:  dsd_ldap::m_ldap_connect()
 *
 * Initiates the connection to a ldap server.
 *
 * @param[in]  adsp_ldap_group  grouped list of ldap-configurations
 *
 * @return     error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Remarks:\n
 * We have a chain of configuration entries inside a ldap configuration group.
 * Starting with the first entry we try to connect to a ldap server. If the connection
 * fails, we wait a time (<retry-after-error>) before we start a retry using the current
 * parameters. Then we step to the next configuration entry and do the same.
 */
int  dsd_ldap::m_ldap_connect( struct dsd_ldap_group *adsp_ldap_group )
{
#define SESS_LIMIT  this->ads_ldap_entry->imc_conf_max_session
#define CONNECT_TO  this->ads_ldap_entry->imc_timeout_conn

   int  iml_rc;            // connect return code
   socklen_t  dsl_socklen; // work variable for sockaddr

#if SM_BUGFIX_20140724
   // do we have already an opened session?
   if (this->ads_ldap_control != NULL)
   { // error: a second connect without a former close!!!
	   if (this->ads_ldap_control->bo_connected) 
       {
		 this->ds_ldap_error.m_set_error( ied_ldap_connection_active, ied_ldap_connect_err );
		 return ied_ldap_failure;
	   }

	   if (this->ads_ldap_control->m_ref_dec())
       {
		  delete this->ads_ldap_control;
	   }
   	   this->ads_ldap_control = NULL;
   }

	// save ldap configuration lists...
   this->ads_ldap_group = adsp_ldap_group;
   this->ads_ldap_entry = adsp_ldap_group->adsc_ldap_entry;
	while(this->ads_ldap_entry != NULL) {
	   // non SSL! Test for a valid ip-address...
		if (this->ads_ldap_entry->adsc_server_ineta == NULL || this->ads_ldap_entry->adsc_server_ineta->imc_no_ineta == 0) {
			this->ads_ldap_entry = this->ads_ldap_entry->adsc_next;
			continue;
		}
		// calculate template index...
		switch (this->ads_ldap_entry->adsc_ldap_template->imc_len_name)
		{
			case sizeof DEF_LDAP_MSAD-1:      if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
																 (void *)DEF_LDAP_MSAD,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_msad;     // Microsoft active directory
											  break;

			case sizeof DEF_LDAP_IBM-1:       if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
															     (void *)DEF_LDAP_IBM,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_ibm;      // IBM directory  server
											  break;

			case sizeof DEF_LDAP_IPLANET-1:   if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
																 (void *)DEF_LDAP_IPLANET,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_iplanet;  // iPlanet directory  server
											  break;

			case sizeof DEF_LDAP_NOVELL-1:    if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
																 (void *)DEF_LDAP_NOVELL,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_novell;   // NOVELL directory  server
											  break;

			case sizeof DEF_LDAP_OPENLDAP-1:  if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
																 (void *)DEF_LDAP_OPENLDAP,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_openldap; // OpenLDAP
											  break;

			case sizeof DEF_LDAP_OPENDS-1:
		 /*case sizeof DEF_LDAP_OPENDJ-1:*/   if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
												 				 (void *)DEF_LDAP_OPENDS,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_opends;   // OpenDS
											  else
											  {
												if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
													 			   (void *)DEF_LDAP_OPENDJ,
																   this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												  this->im_ldap_templ = ied_sys_ldap_opendj; // OpenDJ
											  }
											  break;

			case sizeof DEF_LDAP_SIEMENS-1:   if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
																 (void *)DEF_LDAP_SIEMENS,
																 this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
												this->im_ldap_templ = ied_sys_ldap_siemens;  // Siemens
											  break;

			default:                          this->im_ldap_templ = ied_sys_ldap_generic;    // generic
											  break;
		} //switch()


		// save LDAP server type (pay attention to the generic type!
		this->im_ldap_type = this->im_ldap_templ;

		int iml_max_session = this->ads_ldap_entry->imc_conf_max_session != 0
			? this->ads_ldap_entry->imc_conf_max_session : D_LDAP_MAX_SESSION;
		const int inl_timeout = CONNECT_TO != 0 ? CONNECT_TO*1000 : D_LDAP_WAIT;
		const int INC_NUM_RETRIES = 2;
		for(int iml_retry=0; iml_retry<INC_NUM_RETRIES; iml_retry++) {
			// SSL?
			if (this->ads_ldap_entry->boc_csssl_conf)
			{ // process ssl in a little bit different way...
			  if (this->m_ssl_init( this->ads_ldap_entry ) != ied_ldap_success) {
					break;	
			  }
			}

			dsd_ldap::ds_cs_ldap.m_enter();
			{
				int iml_cur_session = this->ads_ldap_entry->imc_cur_session;
				if (iml_cur_session >= iml_max_session) {
					dsd_ldap::ds_cs_ldap.m_leave();
					if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO )) {
						this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 20, this->im_sess_no, m_get_epoch_ms(),
							&this->ds_conn, this->ads_ldap_entry,
							"Maximum Session Limit reached Template=\"%.*(.*)s\" Current-Sessions=%i Max-Sessions=%i",
							this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                            ied_chs_utf_8, 
                            this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL,
							iml_cur_session, 
                            this->ads_ldap_entry ? this->ads_ldap_entry->imc_conf_max_session : 0);
					}
					break;
				}
				this->ads_ldap_entry->imc_cur_session++;
				if (this->ads_ldap_entry->imc_max_session < this->ads_ldap_entry->imc_cur_session) {
					this->ads_ldap_entry->imc_max_session = this->ads_ldap_entry->imc_cur_session;
					this->ads_ldap_entry->imc_l_epoch_max_session = (int)m_get_epoch_ms();
				}
				this->ads_ldap_control = new dsd_ldap_control( this );
#if SM_BUGFIX_20140804
				this->ads_ldap_control->m_ref_inc();
#endif
			}
			dsd_ldap::ds_cs_ldap.m_leave();

			// start TCPCOMP connection...
			m_set_connect_p1( &this->ds_conn, (socklen_t *)&dsl_socklen, this->ads_ldap_entry->adsc_server_ineta, 0 );

			// trace message LDAP0020T
			if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO )) {
				this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 21, this->im_sess_no, m_get_epoch_ms(),
											 &this->ds_conn, this->ads_ldap_entry,
											 "Connect Template=\"%.*(.*)s\" tcpcomp=%i, Max-Session=%i, Version=%s",
											 this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                                             ied_chs_utf_8, 
                                             this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL,
											 &this->ads_ldap_control->ds_tcpcomp,
											 this->ads_ldap_entry ? this->ads_ldap_entry->imc_conf_max_session : 0, 
                                             CLIENT_VERSION );
			}

#if SM_BUGFIX_20140804
			this->ads_ldap_control->m_ref_inc();
#endif
			if (this->ads_ldap_control->ds_tcpcomp.m_startco_mh( (dsd_tcpcallback_p)&dsd_ldap::ds_tcpcb,
																			 (void *)this->ads_ldap_control,
																			 (struct dsd_bind_ineta_1 *)&this->ads_ldap_entry->dsc_bind_multih,
																			 (struct dsd_target_ineta_1 *)this->ads_ldap_entry->adsc_server_ineta,
#ifndef HOB_RD_VPN_2_1_10
																			 (void *)NULL,
#endif
																			 (unsigned short)this->ads_ldap_entry->imc_port,
																			 TRUE /*do connect round-robin*/ ) != 0)
			{ // @todo: error message to event viewer or something else...
#if SM_BUGFIX_20140804
				this->ads_ldap_control->m_ref_dec();
#endif
				if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR )) {
					this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 21, this->im_sess_no, m_get_epoch_ms(),
						                         &this->ds_conn, this->ads_ldap_entry,
						                         "Connect failed Template=\"%.*(.*)s\"",
						                         this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                                                 ied_chs_utf_8, 
                                                 this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL);
				}
				//this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err, ERRORAT_STARTCONN );
				goto LBL_CLEANUP1;
			}

			// wait for a successful completion...
			iml_rc = (inl_timeout < 0)
				? this->ds_ev_connect.m_wait(&this->ds_ldap_error.im_apicode)
				: this->ds_ev_connect.m_wait_msec(inl_timeout, &this->ds_ldap_error.im_apicode);
			// test return code and error conditions...
			if (iml_rc != 0 /*timeout -2, error -1*/ || this->im_c_status == dsd_ldap::DISCONNECTED /*connect error */)
			{ // @todo: error message to event viewer or something else...
				if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR )) {
					this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 22, this->im_sess_no, m_get_epoch_ms(),
						                         &this->ds_conn, this->ads_ldap_entry,
						                         "Connect failed Template=\"%.*(.*)s\" because of timeout iml_rc=%d",
						                         this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                                                 ied_chs_utf_8, 
                                                 this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL,
						                         iml_rc);
				}
				
				//this->ds_ldap_error.m_set_error( (iml_rc == -2) ? ied_ldap_timeout : ied_ldap_connect_err, ERRORAT_CONNECT );
				
				goto LBL_CLEANUP2;
			}

			// connection successful (but SSL requires a 'hello'-protocol!!!)...
			if (this->ads_ldap_entry->boc_csssl_conf)
			{ // SSL 'hello'-protocol
				if (this->m_ssl_hello( this->ads_ldap_entry ) != ied_ldap_success) {
					// TODO: Leave inner loop
					goto LBL_CLEANUP2;
				}
			}

			// nonSSL and SSL are ready now...
			return ied_ldap_success;
LBL_CLEANUP2:
			this->im_c_status = dsd_ldap::DISCONNECTED;
			this->ads_ldap_control->ads_ldap = NULL;
			if (this->ads_ldap_entry->boc_csssl_conf)
			{
				this->m_ssl_close();
			}
			this->ads_ldap_control->ds_tcpcomp.m_end_session();
LBL_CLEANUP1:
			dsd_ldap::ds_cs_ldap.m_enter();
			this->ads_ldap_entry->imc_cur_session--;
			this->ads_ldap_control->ads_ldap = NULL;
			if (this->ads_ldap_control->m_ref_dec()) 
            {
				delete this->ads_ldap_control;
			}
			this->ads_ldap_control = NULL;
			dsd_ldap::ds_cs_ldap.m_leave();

			// is it the second time ?
			if (iml_retry+1 < INC_NUM_RETRIES && this->ads_ldap_entry->imc_retry_after_error > 0)
			{ // wait <retry-after-error> seconds and retry the current configuration...
				this->ds_ev_connect.m_wait_msec( this->ads_ldap_entry->imc_retry_after_error * 1000,
														&iml_rc );
			}
		}
		this->ads_ldap_entry = this->ads_ldap_entry->adsc_next;
	}
	// no valid configuration found!!!
	this->ds_ldap_error.m_set_error( ied_ldap_no_config, ied_ldap_connect_err );
	return ied_ldap_failure;
#else
	// valid parameter?
   if (adsp_ldap_group == NULL || adsp_ldap_group->adsc_ldap_entry == NULL)
   { // @todo: error message to event viewer or something else
CONNECT_CONFIG_ERROR:
     // no valid configuration found!!!
     this->ds_ldap_error.m_set_error( ied_ldap_no_config, ied_ldap_connect_err );
     return ied_ldap_failure;
   }

   // save ldap configuration lists...
   this->ads_ldap_group = adsp_ldap_group;
   this->ads_ldap_entry = adsp_ldap_group->adsc_ldap_entry;

   // calculate template index...
   switch (this->ads_ldap_entry->adsc_ldap_template->imc_len_name)
   {
      case sizeof DEF_LDAP_MSAD-1:      if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_MSAD,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_msad;     // Microsoft active directory
                                        break;
      case sizeof DEF_LDAP_IBM-1:       if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_IBM,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_ibm;      // IBM directory  server
                                        break;
      case sizeof DEF_LDAP_IPLANET-1:   if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_IPLANET,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_iplanet;  // iPlanet directory  server
                                        break;
      case sizeof DEF_LDAP_NOVELL-1:    if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_NOVELL,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_novell;   // NOVELL directory  server
                                        break;
      case sizeof DEF_LDAP_OPENLDAP-1:  if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_OPENLDAP,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_openldap; // OpenLDAP
                                        break;
      case sizeof DEF_LDAP_OPENDS-1:
    /*case sizeof DEF_LDAP_OPENDJ-1:*/  if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_OPENDS,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_opends;   // OpenDS
                                        else
                                        {
                                          if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                             (void *)DEF_LDAP_OPENDJ,
                                                         this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                            this->im_ldap_templ = ied_sys_ldap_opendj; // OpenDJ
                                        }
                                        break;
      case sizeof DEF_LDAP_SIEMENS-1:   if (!m_hl_memicmp( (void *)(this->ads_ldap_entry->adsc_ldap_template + 1),
                                                           (void *)DEF_LDAP_SIEMENS,
                                                       this->ads_ldap_entry->adsc_ldap_template->imc_len_name ))
                                          this->im_ldap_templ = ied_sys_ldap_siemens;  // Siemens
                                        break;
      default:                          this->im_ldap_templ = ied_sys_ldap_generic;    // generic
                                        break;
   } //switch()


   // save LDAP server type (pay attention to the generic type!
   this->im_ldap_type = this->im_ldap_templ;

#if !SM_BUGFIX_20140724
   // test session limit!!!
   if ((SESS_LIMIT ? SESS_LIMIT : D_LDAP_MAX_SESSION) <= dsd_ldap::im_sess_cnt)
   { // @todo: error message to event viewer or something else
     this->ds_ldap_error.m_set_error( ied_ldap_session_limit, ied_ldap_connect_err );
     return ied_ldap_failure;
   }
#endif

   // do we have already an opened session?
   if (this->ads_ldap_control && this->ads_ldap_control->bo_connected)
   { // error: a second connect without a former close!!!
     this->ds_ldap_error.m_set_error( ied_ldap_connection_active, ied_ldap_connect_err );
     return ied_ldap_failure;
   }


   // loop to connect, try all configuration entries until we have success or not...
   do
   {
#if SM_BUGFIX_20140724
		int iml_max_session = this->ads_ldap_entry->imc_conf_max_session != 0
			? this->ads_ldap_entry->imc_conf_max_session : D_LDAP_MAX_SESSION;
#endif
     // non SSL! Test for a valid ip-address...
     if (this->ads_ldap_entry->adsc_server_ineta == NULL || this->ads_ldap_entry->adsc_server_ineta->imc_no_ineta == 0)
       // configuration error -> try the next configuration...
       goto CONNECT_TRY_NEXT;

     // SSL?
     if (this->ads_ldap_entry->boc_csssl_conf)
     { // process ssl in a little bit different way...
       if (this->m_ssl_init( this->ads_ldap_entry ) != ied_ldap_success)
         // ssl-init error --> try the next configuration (without any retry!!!)
         goto CONNECT_TRY_NEXT;
     }

	  dsd_ldap::ds_cs_ldap.m_enter();
		{
#if SM_BUGFIX_20140724
			int iml_cur_session = this->ads_ldap_entry->imc_cur_session;
			if (iml_cur_session >= this->ads_ldap_entry->imc_conf_max_session) {
				dsd_ldap::ds_cs_ldap.m_leave();
				if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO )) {
					 this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 20, this->im_sess_no, m_get_epoch_ms(),
							                      &this->ds_conn, this->ads_ldap_entry,
							                      "Maximum Session Limit reached Template=\"%.*(.*)s\" Current-Sessions=%i Max-Sessions=%i",
						       	                  this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                                                  ied_chs_utf_8, 
                                                  this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL,
							                      iml_cur_session, 
                                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_conf_max_session : 0);
				}
				goto CONNECT_TRY_NEXT;
			}
			this->ads_ldap_entry->imc_cur_session++;
#endif
			if (this->ads_ldap_control != NULL) {
				this->ads_ldap_control->ads_ldap = NULL;
				if (this->ads_ldap_control->m_ref_dec()) 
                {
					delete this->ads_ldap_control;
				}
			}

			this->ads_ldap_control = new class dsd_ldap_control( this );
#if SM_BUGFIX_20140804
			this->ads_ldap_control->m_ref_inc();
#endif
		}
		dsd_ldap::ds_cs_ldap.m_leave();


     // start TCPCOMP connection...
     m_set_connect_p1( &this->ds_conn, (socklen_t *)&dsl_socklen, this->ads_ldap_entry->adsc_server_ineta, 0 );

     // trace message LDAP0020T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 20, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "Connect Template=\"%.*(.*)s\" tcpcomp=%i, Max-Session=%i, Version=%s",
                                    this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template->imc_len_name : 0, 
                                    ied_chs_utf_8, 
                                    this->ads_ldap_entry ? this->ads_ldap_entry->adsc_ldap_template + 1 : NULL,
                                    &this->ads_ldap_control->ds_tcpcomp,
                                    this->ads_ldap_entry ? this->ads_ldap_entry->imc_conf_max_session : 0, 
                                    CLIENT_VERSION );

#if SM_BUGFIX_20140804
	 this->ads_ldap_control->m_ref_inc();
#endif
     if (this->ads_ldap_control->ds_tcpcomp.m_startco_mh( (dsd_tcpcallback_p)&dsd_ldap::ds_tcpcb,
                                                          (void *)this->ads_ldap_control,
                                                          (struct dsd_bind_ineta_1 *)&this->ads_ldap_entry->dsc_bind_multih,
                                                          (struct dsd_target_ineta_1 *)this->ads_ldap_entry->adsc_server_ineta,
#ifndef HOB_RD_VPN_2_1_10
                                                          (void *)NULL,
#endif
                                                          (unsigned short)this->ads_ldap_entry->imc_port,
                                                          TRUE /*do connect round-robin*/ ) != 0)
     { // @todo: error message to event viewer or something else...
#if SM_BUGFIX_20140804
	   this->ads_ldap_control->m_ref_dec();
#endif
       this->ds_ldap_error.m_set_error( ied_ldap_tcpcomp_err, ERRORAT_STARTCONN );
       this->im_c_status = dsd_ldap::DISCONNECTED;
       goto CONNECT_RETRY;
     }

     //m_hl1_printf("#m_ldap_connect: adsp_tcpcomp=%p\n", &this->ads_ldap_control->ds_tcpcomp);
	  // wait for a successful completion...
     iml_rc = this->ds_ev_connect.m_wait_msec( CONNECT_TO ? CONNECT_TO*1000 : D_LDAP_WAIT,
                                               &this->ds_ldap_error.im_apicode );

     // test return code and error conditions...
     if (iml_rc != 0 /*timeout -2, error -1*/ || this->im_c_status == dsd_ldap::DISCONNECTED /*connect error */)
     { // @todo: error message to event viewer or something else...
       this->ds_ldap_error.m_set_error( (iml_rc == -2) ? ied_ldap_timeout : ied_ldap_connect_err, ERRORAT_CONNECT );
CONNECT_RETRY:
#if SM_BUGFIX_20140724
		 dsd_ldap::ds_cs_ldap.m_enter();
		 this->ads_ldap_entry->imc_cur_session--;
		 dsd_ldap::ds_cs_ldap.m_leave();
#endif
		 // is it the second time ?
       if (iml_retry == 0 && this->ads_ldap_entry->imc_retry_after_error)
       { // wait <retry-after-error> seconds and retry the current configuration...
         this->ds_ev_connect.m_wait_msec( this->ads_ldap_entry->imc_retry_after_error * 1000,
                                          &iml_rc );
         ++iml_retry;
         continue;
       }
       else
       { // try next configuration...
CONNECT_TRY_NEXT:
         if (this->ads_ldap_entry->adsc_next)
         { // set next configuration
           iml_retry = 0;      // reset <retry-after-error> - counter
           this->ads_ldap_entry = this->ads_ldap_entry->adsc_next;
           continue;
         }
         else
           // configuration error -> no more entries available!
           goto CONNECT_CONFIG_ERROR;
       }
     }
     else
	    // connection successful (but SSL requires a 'hello'-protocol!!!)...
       if (this->ads_ldap_entry->boc_csssl_conf)
       { // SSL 'hello'-protocol
			 if (this->m_ssl_hello( this->ads_ldap_entry ) != ied_ldap_success) {
#if SM_BUGFIX_20140724
				 dsd_ldap::ds_cs_ldap.m_enter();
				 this->ads_ldap_entry->imc_cur_session--;
				 dsd_ldap::ds_cs_ldap.m_leave();
#endif
				// ssl-'hello' error -> try the next configuration
				goto CONNECT_TRY_NEXT;
			 }
       }
#if SM_BUGFIX_20140724
		 dsd_ldap::ds_cs_ldap.m_enter();
		 if (this->ads_ldap_entry->imc_max_session < this->ads_ldap_entry->imc_cur_session) {
			 this->ads_ldap_entry->imc_max_session = this->ads_ldap_entry->imc_cur_session;
			 this->ads_ldap_entry->imc_l_epoch_max_session = (int)m_get_epoch_ms();
		 }
		 dsd_ldap::ds_cs_ldap.m_leave();
#endif
       // nonSSL and SSL are ready now...
       return ied_ldap_success;

   } while(1);

   return ied_ldap_failure;
#endif
} // dsd_ldap::m_ldap_connect( struct dsd_ldap_group* )

#if SM_BUGFIX_20140724
void dsd_ldap::m_set_request_active(bool bop_active) {
	this->dsc_cs_ldap2.m_enter();
	this->boc_pending_request = bop_active;
	this->dsc_cs_ldap2.m_leave();
}
#endif

/**
 * Public class function:  dsd_ldap::m_ssl_init()
 *
 * Initiates the ssl-connection to a ldap server.
 *
 * @param[in]  adsp_ldap_entry   entry list of ldap-configurations
 *
 * @return     error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 */
int  dsd_ldap::m_ssl_init( struct dsd_ldap_entry *adsp_ldap_entry )
{
#if !SM_USE_RECV_GATHERS
   // initialize ssl storage handle
	this->ds_buf_ssl.m_free(&this->ads_hl_stor_ssl);
#endif
   START_MEM(this->ads_hl_stor_ssl)
#if !SM_USE_RECV_GATHERS
   // initialize receive buffer storage management
   this->ds_buf_ssl.m_init( &this->ads_hl_stor_ssl );
#endif
   // initialize ssl...
   memset( (void *)&this->ds_sslstruct, int(0), sizeof(struct dsd_hl_ssl_c_1) );
   //memset( (void *)&this->ds_appltossl, int(0), sizeof(struct dsd_gather_i_1) );
   memset( (void *)&this->ds_socktossl, int(0), sizeof(struct dsd_gather_i_1) );

   this->ds_sslstruct.amc_aux           = &ms_aux_ssl_mem;     // storage subroutine
   this->ds_sslstruct.amc_conn_callback = &mg_cb_ssl_compl;    // ssl callback complete routine
   this->ds_sslstruct.vpc_userfld       = this;                // user field
   this->ds_sslstruct.adsc_gai1_in_cl   = NULL; // input from client
   this->ds_sslstruct.adsc_gai1_in_se   = &this->ds_socktossl; // input from server

   // set ssl structure...
   this->ach_ssltoappl_buf = (char *)m_aux_stor_alloc( &this->ads_hl_stor_ssl, int(D_LDAP_SSL_BUFFER_LEN) );
   this->ach_ssltosock_buf = (char *)m_aux_stor_alloc( &this->ads_hl_stor_ssl, int(D_LDAP_SSL_BUFFER_LEN) );

   this->ds_sslstruct.achc_out_cl_cur = this->ach_ssltoappl_buf;
   this->ds_sslstruct.achc_out_cl_end = this->ach_ssltoappl_buf + D_LDAP_SSL_BUFFER_LEN;
   this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
   this->ds_sslstruct.achc_out_se_end = this->ach_ssltosock_buf + D_LDAP_SSL_BUFFER_LEN;
   this->ds_sslstruct.vpc_config_id = adsp_ldap_entry->vpc_csssl_config_id; // address config id

   // call ssl...
   m_hlcl01( &this->ds_sslstruct );
   if (this->ds_sslstruct.inc_return != 0)
     return ied_ldap_failure;

     return ied_ldap_success;

} // dsd_ldap::m_ssl_init( struct dsd_ldap_entry * )

int dsd_ldap::m_ssl_close() {
	if (this->ds_sslstruct.inc_func == DEF_IFUNC_CLOSE)
		return ied_ldap_success;
	if (this->ads_hl_stor_ssl == NULL)
		return ied_ldap_success;
   this->ds_sslstruct.boc_eof_server = this->ds_sslstruct.boc_eof_client = TRUE;
   this->ds_sslstruct.inc_func       = DEF_IFUNC_CLOSE;
   this->ds_sslstruct.adsc_gai1_in_cl = NULL;

   do
   { // call ssl...
     m_hlcl01( &this->ds_sslstruct );
   } while (this->ds_sslstruct.inc_return != DEF_IRET_END && this->ds_sslstruct.inc_return >= 0);

#if SM_USE_RECV_GATHERS
	m_gatherlist_free(&this->dsc_recv_data);
#else
	this->ds_buf_ssl.m_free(&this->ads_hl_stor_ssl);
#endif
	END_MEM(this->ads_hl_stor_ssl);
	this->ach_ssltoappl_buf = NULL;
	this->ach_ssltosock_buf = NULL;

   if (this->ds_sslstruct.inc_return != DEF_IRET_END) {
       // ssl close error
       return ied_ldap_failure;
   }
	
	return ied_ldap_success;
}

/**
 * Public class function:  dsd_ldap::m_ssl_hello()
 *
 * Performs the ssl-handshake protocol (send 'hello'...) to the SSL LDAP server.
 *
 * @param[in]  adsp_ldap_entry   entry list of ldap-configurations
 *
 * @return     error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 */
int  dsd_ldap::m_ssl_hello( struct dsd_ldap_entry *adsp_ldap_entry )
{
	int inl_timeout_conn = this->ads_ldap_entry->imc_timeout_conn;
	if (inl_timeout_conn != 0) {
		inl_timeout_conn = inl_timeout_conn*1000;
	}
	else {
		inl_timeout_conn = D_LDAP_WAIT;
	}

   // do ssl-handshake (send 'hello'...)
   this->bo_ssl_completed = FALSE;

   // wait for ssl-response...
	if (this->ads_ldap_control == NULL)
		return ied_ldap_failure;
#if SM_USE_RECV_GATHERS
	dsd_gatherlist dsl_data_in_se;
   
   m_gatherlist_init(&dsl_data_in_se);
   while (true)
   {
		if (!this->ads_ldap_control->bo_connected)
			goto CONNECT_SSL_ERROR;
		if (this->ads_ldap_control->bo_tcperr)
			goto CONNECT_SSL_ERROR;

		this->dsc_cs_ldap2.m_enter();
		m_gatherlist_push_back(&dsl_data_in_se, &this->dsc_recv_data);
		this->dsc_cs_ldap2.m_leave();
		this->ds_sslstruct.adsc_gai1_in_se = dsl_data_in_se.adsc_first;

		while(true) {
			// are there any data to send?
			while (this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
			{  // process ssl generated send data (like alerts, ...)
			  int iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf,
																 int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf));
			  // SSL send() - error ?
			  if (iml_rc < 0)
				goto CONNECT_SSL_ERROR;

			  this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
			} // while(send)
			m_hlcl01( &this->ds_sslstruct );
			if (this->ds_sslstruct.inc_return != 0)
				 goto CONNECT_SSL_ERROR;
			this->ds_sslstruct.adsc_gai1_in_se = m_skip_consumed_gathers(&dsl_data_in_se);
			if (this->bo_ssl_completed) {
				// ssl-handshake completed!
				goto LBL_COMPLETE;
			}
			if (this->ds_sslstruct.adsc_gai1_in_se == NULL && this->ds_sslstruct.achc_out_se_cur == this->ach_ssltosock_buf)
				break;
		}	
		this->ads_ldap_control->bo_recv = TRUE;
		this->ads_ldap_control->bo_recv_complete = FALSE;
		this->ads_ldap_control->ds_tcpcomp.m_recv();

		// wait for a successful completion...
		if (this->ads_ldap_control == NULL ||
			this->ads_ldap_control->m_wait(inl_timeout_conn, &this->ds_ldap_error.im_apicode ) != 0 )
		{
			goto CONNECT_SSL_ERROR;
		}
   }
CONNECT_SSL_ERROR:
   m_gatherlist_free(&dsl_data_in_se);
   return ied_ldap_failure;
LBL_COMPLETE:
	if (dsl_data_in_se.adsc_first != NULL) {
		this->dsc_cs_ldap2.m_enter();
		m_gatherlist_push_front(&this->dsc_recv_data, &dsl_data_in_se);
		this->dsc_cs_ldap2.m_leave();
	}

	return ied_ldap_success;
#else
   if (this->ads_ldap_control &&
       this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
   { // send ssl-data...
     int iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf,
                                                        int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf));
     // SSL send() - error?
     if (iml_rc < 0)
       goto CONNECT_SSL_ERROR;
	 if (iml_rc != int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf)) {
		 goto CONNECT_SSL_ERROR;
	  }

     this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
   }
   // wait for ssl-response...
#if 0
LBL_WAIT_FOR_MORE:
#endif
	while (this->ads_ldap_control)
   {
      if (!this->ads_ldap_control->bo_connected)
         return ied_ldap_failure;
      if (this->ads_ldap_control->bo_tcperr)
         return ied_ldap_failure;
		this->ads_ldap_control->bo_recv          = TRUE;
      this->ads_ldap_control->bo_recv_complete = FALSE;
      this->ads_ldap_control->ds_tcpcomp.m_recv();

     // wait for a successful completion...
     if (this->ads_ldap_control == NULL ||
         this->ads_ldap_control->m_wait( CONNECT_TO ? CONNECT_TO*1000 : D_LDAP_WAIT,
                                                             &this->ds_ldap_error.im_apicode ) != 0 )
     {
       return ied_ldap_failure;
     }

     // process received send data...
	 this->ds_socktossl.achc_ginp_cur = (char *)this->ds_buf_ssl.m_getaddr() + this->ds_buf_ssl.imc_nextpos;
     this->ds_socktossl.achc_ginp_end = (char *)this->ds_buf_ssl.m_getaddr() + this->ds_buf_ssl.imc_pos;
     this->ds_socktossl.adsc_next     = NULL;
	 this->ds_sslstruct.adsc_gai1_in_se = &this->ds_socktossl;

     // call ssl...
     m_hlcl01( &this->ds_sslstruct );
	 this->ds_sslstruct.adsc_gai1_in_se = m_skip_consumed_gathers(this->ds_sslstruct.adsc_gai1_in_se);
	 if (this->ds_sslstruct.inc_return != 0)
       goto CONNECT_SSL_ERROR;
	 this->ds_buf_ssl.imc_nextpos = int(this->ds_socktossl.achc_ginp_cur - (char *)this->ds_buf_ssl.m_getaddr());

     // are there any data to send?
     while (this->ads_ldap_control &&
            this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
     {  // process ssl generated send data (like alerts, ...)
        iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf,
                                                           int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf));
        // SSL send() - error ?
        if (iml_rc < 0)
          goto CONNECT_SSL_ERROR;

        this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
        // call ssl...
        m_hlcl01( &this->ds_sslstruct );
        if (this->ds_sslstruct.inc_return != 0)
          goto CONNECT_SSL_ERROR;
     } // while(send)

     // call ssl...
     m_hlcl01( &this->ds_sslstruct );
     if (this->ds_sslstruct.inc_return != 0)
       goto CONNECT_SSL_ERROR;

     if (this->bo_ssl_completed)
       // ssl-handshake completed!
       break;

     // receive more data and wait for completed handshake
     //this->ds_buf_ssl.m_clear();
     }
   } // while(receive)

   return ied_ldap_success;
CONNECT_SSL_ERROR:
#if 0
	if (this->ds_sslstruct.inc_return == -113)
		goto LBL_WAIT_FOR_MORE;
#endif
	return ied_ldap_failure;
#endif /*SM_USE_RECV_GATHERS*/
} // dsd_ldap::m_ssl_hello( struct dsd_ldap_group * )


/**
 * Private class function:  dsd_ldap::m_ldap_close()
 *
 * Disconnect to a ldap server by sending an 'unbind'-request.
 *
 * @param[in]  bop_serverside  (\b TRUE) for server-side initiated close
 *
 * @return     error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_close(class dsd_ldap_control* adsp_req)
{

   int  iml_rc (ied_ldap_success);

	bool bol_serverside = adsp_req != NULL;
   // trace message LDAP0019
   if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_INFO))
     this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_INFO, 19, this->im_sess_no, m_get_epoch_ms(),
                                 &this->ds_conn, (struct dsd_ldap_entry *)this->ads_ldap_entry,
                                 "Close (%s-side)", bol_serverside ? "server" : "client");
   this->im_c_status = dsd_ldap::DISCONNECTED;

   class dsd_tcpcomp *adsl_tcpcomp (NULL);
   BOOL  bol_error (FALSE);

   dsd_ldap::ds_cs_ldap.m_enter();
   {
		if (this->ads_ldap_control != NULL) {
			if (adsp_req != NULL && adsp_req != this->ads_ldap_control) {
			   goto LBL_DONE;
			}
			if (this->ads_ldap_control->ads_ldap != NULL)
			{ // call either from client, sdh, ... or call from m_ldap_free()
				this->ads_ldap_control->bo_recv_complete = FALSE;
				this->ads_ldap_control->bo_recv          = FALSE;   // no receive active
				this->ads_ldap_control->bo_connected     = FALSE;

				// clean tcpcomp object...
				adsl_tcpcomp = &this->ads_ldap_control->ds_tcpcomp;
				bol_error    = this->ads_ldap_control->bo_tcperr;

				this->ads_ldap_control->bo_tcperr = FALSE;
				this->ads_ldap_control->ads_ldap  = NULL;
				//this->ads_ldap_control = NULL;

#if SM_BUGFIX_20140724
				if (this->ads_ldap_entry != NULL) {
					this->ads_ldap_entry->imc_cur_session--;
				}
#endif
			} // ads_ldap_control
		}
   }
LBL_DONE:
   dsd_ldap::ds_cs_ldap.m_leave();

#if SM_BUGFIX_20140724
	// stop TCP session only, if no TCP error
	if (bol_serverside)
		return ied_ldap_success;
   if (adsl_tcpcomp && !bol_error)
	  adsl_tcpcomp->m_end_session();
#else
	// stop TCP session only, if no TCP error
   if (adsl_tcpcomp && bop_serverside && !bol_error)
     adsl_tcpcomp->m_end_session();
#endif
   // invalidate the RootDSE
   this->bo_RootDSE = false;

   if (this->ads_ldap_entry != NULL)
   {
#if !SM_BUGFIX_20140724
     // statistics...
     this->ads_ldap_entry->imc_cur_session = dsd_ldap::im_sess_cnt;
#endif
     // SSL?
     if (this->ads_ldap_entry->boc_csssl_conf)
     { // test ssl structure..
		  iml_rc = this->m_ssl_close();
     } // SSL?
   } // ads_ldap_entry


   // free ssl storage...
   this->ach_ssltoappl_buf = NULL;
   this->ach_ssltosock_buf = NULL;

   // reset bind-dn and password
   if (this->im_len_dn)
     FREE_MEM( this->ads_hl_stor_per, this->achr_dn )
   if (this->im_len_pwd)
     FREE_MEM( this->ads_hl_stor_per, this->achr_pwd )

   this->im_len_dn = this->im_len_pwd = 0;
   // reset ldap schema
   this->ads_ldap_schema = NULL;

   return iml_rc;

} // dsd_ldap::m_ldap_close()


/**
 * Private class function:  dsd_ldap::m_ldap_bind()
 *
 * Binds and authenticates to a ldap server.
 *
 *     ASN.1:
 *     BindRequest ::= [APPLICATION 0] SEQUENCE { version         INTEGER (1 ... 127),
 *                                                name            LDAPDN,
 *                                                authentication  AuthenticaionChoice
 *                                              }
 *
 *                      AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
 *                                                        sasl [3]   SaslCredentials
 *                                                      }
 *
 *                      SaslCredentials ::= SEQUENCE { mechanism   LDAPString,
 *                                                     credentials OCTET STRING OPTIONAL
 *                                                   }
 *
 *
 * @param[in,out]   adsp_co_ldap  request structure
 *
 * @return   error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_bind( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   int    iml_len_userid (adsp_co_ldap->imc_len_userid);
   char  *achl_userid    (adsp_co_ldap->ac_userid);
   int    iml_rc (ied_ldap_success);
   void  *avol_1;

   LDAP_REQ_STRUC(dsl_co_ldap)

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       iml_rc = this->m_ldap_connect( this->ads_ldap_group );
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
      default:                     break;
   } // end of switch

   // trace message LDAP0030T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 30, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Bind Authentication=%s Realm=\"%.*(.*)s\" User-ID=\"%.*(.*)s\" Administrator=\"%.*(.*)s\"",
                                  this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_ldap_auth, dsd_trace::S_BIND_AUTH ),
                                  adsp_co_ldap->dsc_add_dn.ac_str ? adsp_co_ldap->dsc_add_dn.imc_len_str : sizeof "none" -1,
                                  adsp_co_ldap->dsc_add_dn.ac_str ? adsp_co_ldap->dsc_add_dn.iec_chs_str : ied_chs_ascii_850,
                                  adsp_co_ldap->dsc_add_dn.ac_str ? adsp_co_ldap->dsc_add_dn.ac_str : "none",
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->imc_len_userid : sizeof "none" - 1,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->iec_chs_userid : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->ac_userid : "none",
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_len_userid : 0, 
                                  ied_chs_utf_8, 
                                  this->ads_ldap_entry ? this->ads_ldap_entry->achc_userid : NULL);


   if (iml_rc == ied_ldap_success && (this->im_c_status == dsd_ldap::CONNECTED ||
                                      (this->im_c_status == dsd_ldap::BIND_SASL || this->im_c_status == dsd_ldap::BIND)))
   { // perform ldap bind...

     // initiate ASN.1 class...
     this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
     // initialize receive buffer storage management
     this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

     // select special binds...
     switch (adsp_co_ldap->iec_ldap_auth)
     {
#ifdef HOB_SPNEGO_SUPPORT
        case ied_auth_ntlm:            // sasl management (SPNEGO)...
        case ied_auth_krb5:            {
                                         struct dsd_unicode_string  ds_unicode_usr = { adsp_co_ldap->ac_userid, 
                                                                                       adsp_co_ldap->imc_len_userid, 
                                                                                       adsp_co_ldap->iec_chs_userid };
                                         struct dsd_unicode_string  ds_unicode_pwd = { adsp_co_ldap->ac_passwd, 
                                                                                       adsp_co_ldap->imc_len_passwd, 
                                                                                       adsp_co_ldap->iec_chs_passwd };
                                         return this->m_aux_bind_sasl(&ds_unicode_usr, &ds_unicode_pwd,
                                                                      adsp_co_ldap->iec_ldap_auth /*mechanism type*/,
                                                                      NULL);
                                       }
#endif // HOB_SPNEGO_SUPPORT

        case ied_auth_user_pwd_change: // password change...
                                       return this->m_ldap_password( adsp_co_ldap );
        case ied_auth_admin:           // administration bind
                                       { struct dsd_unicode_string  ds_unicode_usr = { this->ads_ldap_entry->achc_userid, 
                                                                                       this->ads_ldap_entry->imc_len_userid,
                                                                                       ied_chs_utf_8 };
                                         struct dsd_unicode_string  ds_unicode_pwd = { this->ads_ldap_entry->achc_password, 
                                                                                       this->ads_ldap_entry->imc_len_password,
                                                                                       ied_chs_utf_8 };

                                         iml_rc = this->m_aux_bind_simple( &ds_unicode_usr, &ds_unicode_pwd );
                                         if (iml_rc == ied_ldap_success)
                                         { // set scope to admin...
                                           if (this->im_len_pwd)
                                             FREE_MEM( this->ads_hl_stor_per, this->achr_pwd )
                                           if (this->im_len_dn)
                                             FREE_MEM( this->ads_hl_stor_per, this->achr_dn )

                                           this->im_len_pwd = this->im_len_dn = 0;
                                         }
                                         return iml_rc;
                                       } // case ied_auth_admin
                                       break;

        case ied_auth_user:            { // check for valid input parameters...    
                                         if (!adsp_co_ldap->imc_len_userid)
                                         { // error, anonymous bind not allowed...
                                           this->ds_ldap_error.m_set_error( ied_ldap_auth_notsupp, ied_ldap_bind_err );
                                           return ied_ldap_failure;
                                         }

                                         if (!adsp_co_ldap->imc_len_passwd)
                                         { // error, stronger authentication required (no bind without password!)...
                                           this->ds_ldap_error.m_set_error( ied_ldap_strong_auth_req, ied_ldap_bind_err );
                                           return ied_ldap_failure;
                                         }

                                         // now we have to search for '*' and '?' --> these user-ids are not valid!
                                         // it doesn't matter whether the characters are masked by '\' or utf-8 sequences
                                         char *achl_1 = adsp_co_ldap->ac_userid,
                                              *achl_2 = adsp_co_ldap->ac_userid + adsp_co_ldap->imc_len_userid;

                                         do { if (*achl_1 == '*' || *achl_1 == '?')
                                              { // error, user name contains invalid and forbidden characters...
                                                this->ds_ldap_error.m_set_error( ied_ldap_inv_cred, ied_ldap_bind_err );
                                                return ied_ldap_failure;
                                              }
                                              achl_1++;
                                            } while (achl_1 < achl_2);
                                       
                                         // use the search administrator
                                         struct dsd_unicode_string  ds_unicode_usr = { this->ads_ldap_entry->achc_userid, 
                                                                                       this->ads_ldap_entry->imc_len_userid,
                                                                                       ied_chs_utf_8 };
                                         struct dsd_unicode_string  ds_unicode_pwd = { this->ads_ldap_entry->achc_password, 
                                                                                       this->ads_ldap_entry->imc_len_password,
                                                                                       ied_chs_utf_8 };
                                       
                                         iml_rc = this->m_aux_bind_simple( &ds_unicode_usr, &ds_unicode_pwd );
                                         if (iml_rc != ied_ldap_success)
                                           // error, return to caller
                                           return iml_rc;
                                       
                                       } // case ied_auth_user
                                       break;
        case ied_auth_dn:
        case ied_auth_sid:             { struct dsd_unicode_string  ds_unicode_usr = { adsp_co_ldap->ac_userid, 
                                                                                       adsp_co_ldap->imc_len_userid,
                                                                                       adsp_co_ldap->iec_chs_userid };
                                         struct dsd_unicode_string  ds_unicode_pwd = { adsp_co_ldap->ac_passwd, 
                                                                                       adsp_co_ldap->imc_len_passwd,
                                                                                       adsp_co_ldap->iec_chs_passwd };

                                         iml_rc = this->m_aux_bind_simple( &ds_unicode_usr, &ds_unicode_pwd);
                                         if (iml_rc != ied_ldap_success)
                                           // error, return to caller
                                           return iml_rc;
                                       
                                       } // case ied_auth_sid, ied_auth_dn
                                       break;

        default:                       // authentication type not (yet) supported
                                       this->ds_ldap_error.m_set_error( ied_ldap_auth_notsupp, ied_ldap_bind_err );
                                       return ied_ldap_failure;
     }; // switch(iec_ldap_auth)


     // now we have to process the user management:
     // 1. ied_auth_sid:  the sid-bind was successful, but we have to search for the user-DN and the attributes
     // 2. ied_auth_dn:   the DN-bind was successful, the only thing we have to do, is the attribute-search
     // 3. ied_auth_user: the search-admin-bind was successful, but we have to do the same search as ied_auth_sid,
     //                   furthermore we do a bind with the found user-DN in the last step.

     // search user- and group-entries (LDAP-templates)...
     // convert user-id, in not utf-8
     if (adsp_co_ldap->imc_len_userid && adsp_co_ldap->iec_chs_userid != ied_chs_utf_8)
     {
       iml_len_userid = m_len_vx_vx( ied_chs_utf_8,
                                     (void *)adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, adsp_co_ldap->iec_chs_userid );
       if (iml_len_userid == -1)
       { // error, invalid string format...
         this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
         return ied_ldap_failure;
       }
       // allocate storage for the translation
       achl_userid = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, iml_len_userid );
       // translation to UTF-8...
       if (m_cpy_vx_vx_fl( (void *)achl_userid, iml_len_userid, ied_chs_utf_8,
                           (void *)adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, adsp_co_ldap->iec_chs_userid,
                           D_CPYVXVX_FL_NOTAIL0 ) == -1)
       { // error, invalid string format...
         this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
         return ied_ldap_failure;
       } 
     }


     // initialize search request structure...
     dsl_co_ldap.iec_co_ldap = ied_co_ldap_search;

     // used by referral (subdomain controller)
     dsl_co_ldap.ac_userid      = adsp_co_ldap->ac_userid;
     dsl_co_ldap.imc_len_userid = adsp_co_ldap->imc_len_userid;
     dsl_co_ldap.iec_chs_userid = adsp_co_ldap->iec_chs_userid;
     dsl_co_ldap.ac_passwd      = adsp_co_ldap->ac_passwd;
     dsl_co_ldap.imc_len_passwd = adsp_co_ldap->imc_len_passwd;
     dsl_co_ldap.iec_chs_passwd = adsp_co_ldap->iec_chs_passwd;


     // set search scope
     if (adsp_co_ldap->iec_ldap_auth == ied_auth_user || adsp_co_ldap->iec_ldap_auth == ied_auth_sid)
       dsl_co_ldap.iec_sear_scope = ied_sear_sublevel;   // 'baseObject and all sub-levels'
     else
     { // search <base-dn>
       dsl_co_ldap.iec_sear_scope = ied_sear_baseobject; // 'baseObject only'
       // set base-dn
       dsl_co_ldap.ac_dn      = achl_userid;
       dsl_co_ldap.imc_len_dn = iml_len_userid;
       dsl_co_ldap.iec_chs_dn = ied_chs_utf_8;
     }

     // set search filter (using templates)...
     struct dsd_ldap_template *adsl_templ = this->ads_ldap_entry->adsc_ldap_template;

     // all filter contain "(objectClass=...)"
     dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
     dsl_co_ldap.imc_len_filter = sizeof "(objectClass=)" - 1 + (adsl_templ->imc_len_user_attr ? adsl_templ->imc_len_user_attr // e.g. objectClass='person'
                                                                                               : 1);                           // objectClass='*'
     // we have different filter for each authentication type
     switch (adsp_co_ldap->iec_ldap_auth)
     {
        case ied_auth_sid: // filter: "(&(objectClass=...)(objectSid=...))"
                           dsl_co_ldap.imc_len_filter += sizeof "(objectSid=)" - 1 + iml_len_userid + sizeof "(&)" - 1;
                           avol_1 = dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per, dsl_co_ldap.imc_len_filter );
                           // build filter
                           memcpy( avol_1, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
                           avol_1 = (char *)avol_1 + sizeof "(&(objectClass=" - 1;

                           if (adsl_templ->imc_len_user_attr /*person*/)
                           { // objectClass=person
                             memcpy( avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
                             avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
                           }
                           else
                           { // objectClass=*
                             *(char *)avol_1 = '*';
                             avol_1 = (char *)avol_1 + 1;
                           }

                           memcpy( avol_1, (const void *)")(objectSid=)", sizeof ")(objectSid=)" - 1 );
                           avol_1 = (char *)avol_1 + sizeof ")(objectSid=)" - 1;
                           memcpy( avol_1, (const void *)achl_userid, iml_len_userid );
                           avol_1 = (char *)avol_1 + iml_len_userid;
                           memcpy( avol_1, (const void *)"))", sizeof "))" - 1 );
                           break;

        case ied_auth_dn:  // filter: "(objectClass=...)"
                           avol_1 = dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per, dsl_co_ldap.imc_len_filter );
                           // build filter
                           memcpy( (void *)dsl_co_ldap.ac_filter, (const void *)"(objectClass=", sizeof "(objectClass=" - 1 );
                           avol_1 = (char *)avol_1 + sizeof "(objectClass=" - 1;

                           if (adsl_templ->imc_len_user_attr /*person*/)
                           { // objectClass=person
                             memcpy( avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
                             avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
                           }
                           else
                           { // objectClass=*
                             *(char *)avol_1 = '*';
                             avol_1 = (char *)avol_1 + 1;
                           }

                           *(char *)avol_1 = ')';
                           break;

        case ied_auth_user:
        default:           // filter: "(&(objectClass=person)(|(sAMAccoundName=...)(cn=...)))"
                           dsl_co_ldap.imc_len_filter += (adsl_templ->imc_len_search_d_a ? adsl_templ->imc_len_search_d_a  // e.g. "userPrincipalName"
                                                                                         : sizeof "sAMAccountName" - 1) +  // default
                                                         sizeof "(=)" - 1;
                           dsl_co_ldap.imc_len_filter += (adsl_templ->imc_len_upref ? adsl_templ->imc_len_upref            // e.g. "uid"
                                                                                    : sizeof "cn" - 1) +                   // default
                                                         sizeof "(=)" - 1;
                           dsl_co_ldap.imc_len_filter += iml_len_userid * 2 + sizeof "(&(|))" - 1;

                           // check 'sAMAccountType'...
                           // Note: If the MSAD database contains entries with the same name for computer and user, both have the objectclass 'person'.
                           //       Thus we need the attribute 'sAMAccountType to distinguish which entry is the right one.
                           if (this->im_ldap_type == ied_sys_ldap_msad)
                           { // MS LDS doesn't support 'sAMAccountType', so we use the following filter condition:
                             // "(&(objectCategory=person)(objectclass=user))"
                             dsl_co_ldap.imc_len_filter += sizeof("(objectCategory=)user") - 1;
                           }

                           // get storage for the filter string
                           avol_1 = dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per, dsl_co_ldap.imc_len_filter );

                           // build filter...
                           if (this->im_ldap_type == ied_sys_ldap_msad)
                           { // MS LDS doesn't support 'sAMAccountType', so modify the normal filter syntax
                             memcpy( avol_1, (const void *)"(&(objectClass=user)(objectCategory=", sizeof "(&(objectClass=user)(objectCategory=" - 1 );
                             avol_1 = (char *)avol_1 + sizeof "(&(objectClass=user)(objectCategory=" - 1;
                           }
                           else
                           { 
                             memcpy( avol_1, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
                             avol_1 = (char *)avol_1 + sizeof "(&(objectClass=" - 1;
                           }


                           if (adsl_templ->imc_len_user_attr /*person*/)
                           { // objectClass=person
                             memcpy( avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
                             avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
                           }
                           else
                           { // objectClass=*
                             *(char *)avol_1 = '*';
                             avol_1 = (char *)avol_1 + 1;
                           }

                           memcpy( avol_1, (const void *)")(|(", sizeof ")(|(" - 1 );
                           avol_1 = (char *)avol_1 + sizeof ")(|(" - 1;

                           // "searchDefaultAttribute"
                           if (adsl_templ->imc_len_search_d_a)
                           { // e.g. userPrincipalName=...
                             memcpy( avol_1, (const void *)adsl_templ->achc_search_d_a, adsl_templ->imc_len_search_d_a );
                             avol_1 = (char *)avol_1 + adsl_templ->imc_len_search_d_a;
                           }
                           else
                           { // sAMAccountName=...
                             memcpy( avol_1, (const void *)"sAMAccountName", sizeof "sAMAccountName" - 1 );
                             avol_1 = (char *)avol_1 + sizeof "sAMAccountName" - 1;
                           }

                           *(char *)avol_1 = '=';
                           avol_1 = (char *)avol_1 + 1;
                           memcpy( avol_1, (const void *)achl_userid, iml_len_userid );
                           avol_1 = (char *)avol_1 + iml_len_userid;
                           memcpy( avol_1, (const void *)")(", sizeof ")(" - 1 );
                           avol_1 = (char *)avol_1 + sizeof ")(" - 1;

                           // "userPrefix"
                           if (adsl_templ->imc_len_upref)
                           { // e.g. uid=...
                             memcpy( avol_1, (const void *)adsl_templ->achc_upref, adsl_templ->imc_len_upref );
                             avol_1 = (char *)avol_1 + adsl_templ->imc_len_upref;
                           }
                           else
                           { // cn=...
                             memcpy( avol_1, (const void *)"cn", sizeof "cn" - 1 );
                             avol_1 = (char *)avol_1 + sizeof "cn" - 1;
                           }

                           *(char *)avol_1 = '=';
                           avol_1 = (char *)avol_1 + 1;
                           memcpy( avol_1, (const void *)achl_userid, iml_len_userid );
                           avol_1 = (char *)avol_1 + iml_len_userid;
                           memcpy( avol_1, (const void *)")))", sizeof ")))" - 1 );
                           break;
     } // switch()


     // set attribute-list to return (e.g. <user-prefix>, <membership-attribute> and
     // optional (MSAD): "objectSid", "primaryGroupID" and "sAMAccountType")
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_upref + adsl_templ->imc_len_mship_attr;
     dsl_co_ldap.ac_attrlist      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per, dsl_co_ldap.imc_len_attrlist + 2/*'\,'*/ +
                                    sizeof "objectSid,primaryGroupID,sAMAccountType," - 1/*'\0'*/ );
     avol_1 = (void *)dsl_co_ldap.ac_attrlist;

     // add "objectSid", "primaryGroupID" and "sAMAccountType" only, if we have a MSAD-type!
     if (this->im_ldap_type == ied_sys_ldap_msad)
     {
       memcpy( avol_1, (void *)"objectSid,primaryGroupID,sAMAccountType,", sizeof "objectSid,primaryGroupID,sAMAccountType," - 1 );
       avol_1 = (char *)avol_1 + sizeof "objectSid,primaryGroupID,sAMAccountType," - 1;
       dsl_co_ldap.imc_len_attrlist += sizeof "objectSid,primaryGroupID,sAMAccountType," - 1;
     } // MSAD environment only

     // <user-prefix>, e.g. "cn"?
     if (adsl_templ->imc_len_upref)
     {
       memcpy( avol_1, (const void *)adsl_templ->achc_upref, adsl_templ->imc_len_upref );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_upref;

       if (adsl_templ->imc_len_mship_attr)
       {
         *(char *)avol_1 = ',';
         avol_1 = (char *)avol_1 + 1;
         ++dsl_co_ldap.imc_len_attrlist;
       }
     }

     // <membership-attribute>, e.g. "memberOf"?
     if (adsl_templ->imc_len_mship_attr)
       memcpy( avol_1, (const void *)adsl_templ->achc_mship_attr, adsl_templ->imc_len_mship_attr );

     // do we use a realm?
     dsl_co_ldap.dsc_add_dn.ac_str      = adsp_co_ldap->dsc_add_dn.ac_str;
     dsl_co_ldap.dsc_add_dn.iec_chs_str = adsp_co_ldap->dsc_add_dn.iec_chs_str;
     dsl_co_ldap.dsc_add_dn.imc_len_str = adsp_co_ldap->dsc_add_dn.imc_len_str;


     // perform the search-request...
     iml_rc = this->m_ldap_search( &dsl_co_ldap, FALSE/*attributes and values*/,
                                   &dsl_co_ldap.ac_dn, &dsl_co_ldap.imc_len_dn, &dsl_co_ldap.iec_chs_dn );
     FREE_MEM( this->ads_hl_stor_per, dsl_co_ldap.ac_filter )
     FREE_MEM( this->ads_hl_stor_per, dsl_co_ldap.ac_attrlist )
     dsl_co_ldap.imc_len_filter = dsl_co_ldap.imc_len_attrlist = 0;

     // search error!
     if (iml_rc != ied_ldap_success)
     { // if ied_auth_dn was set, we should save the bind-parameters (for reconnect)
       if (adsp_co_ldap->iec_ldap_auth == ied_auth_dn)
       {
         if (this->im_len_pwd)
           FREE_MEM( this->ads_hl_stor_per, this->achr_pwd )
         if (this->im_len_dn)
           FREE_MEM( this->ads_hl_stor_per, this->achr_dn )

         this->im_len_pwd = this->im_len_dn = 0;

         iml_rc = ied_ldap_success;
         goto BIND_DN;
       }
       return iml_rc;
     }

     // before we bind with the found dn (ied_auth_user only!), we should save the results...
     if (/* this->im_ldap_type == ied_sys_ldap_msad && */ dsl_co_ldap.adsc_attr_desc != NULL)
     { // MSAD only: check and convert the 'objectSID'
       struct dsd_ldap_attr *adsl_attr_1 = dsl_co_ldap.adsc_attr_desc->adsc_attr;
       struct dsd_ldap_attr *adsl_attr_2 = adsl_attr_1;
       struct dsd_ldap_attr *adsl_attr_mship = NULL;
       struct dsd_sid        dsl_sid_1;
       struct dsd_ldap_val  *adsl_val_pg (NULL), dsl_val_1;
       int  iml_pg;

       LDAP_REQ_STRUC(dsl_co_ldap_pg)


       while (adsl_attr_1)
       { // check the returned partial attributes...
         if (adsl_attr_1->imc_len_attr == this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr &&
             !m_hl_memicmp( adsl_attr_1->ac_attr, this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr, adsl_attr_1->imc_len_attr ))
           // save attribute address of <memberOf>
           adsl_attr_mship = adsl_attr_1;
         else
         {
           if (adsl_attr_1->imc_len_attr == sizeof "objectSid" - 1 &&
               !m_hl_memicmp( adsl_attr_1->ac_attr, (void *)"objectSid", adsl_attr_1->imc_len_attr ))
           { // 'objectSid'...
             memcpy( (void *)&dsl_sid_1,
                     (const void *)adsl_attr_1->dsc_val.ac_val,
                     adsl_attr_1->dsc_val.imc_len_val );
             this->m_aux_hex_to_sid( &dsl_sid_1, &adsl_attr_1->dsc_val, this->ads_hl_stor_tmp );
           }
           else
           { // 'primaryGroupID'...
             if (adsl_attr_1->imc_len_attr == sizeof "primaryGroupID" - 1 &&
                 !m_hl_memicmp( adsl_attr_1->ac_attr, (void *)"primaryGroupID", adsl_attr_1->imc_len_attr ))
             { // search group associated with the 'primaryGroupID' found!
               string str_pg( adsl_attr_1->dsc_val.ac_val, adsl_attr_1->dsc_val.imc_len_val );
               iml_pg = atoi( str_pg.c_str() );
               // endianess?
               if (this->bo_le == FALSE)
               { // convert from le to be
                 iml_pg = m_bswap32(iml_pg);
               }

               if (this->bo_RootDSE == TRUE || this->m_aux_search_RootDSE() == ied_ldap_success)
               {
                 if (this->ads_domainSID)
                 { 
                   struct dsd_ldap_val  dsl_context;

                   // MS LDS doesn't support 'defaultNamingContext'
                   if (this->ds_RootDSE.ads_defaultcontext)
                   { // MSAD with default context
                     dsl_context.ac_val      = this->ds_RootDSE.ads_defaultcontext->ac_val;
                     dsl_context.imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
                     dsl_context.iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
                   }
                   else
                   { // MS LDS
                     dsl_context.ac_val      = this->ads_ldap_entry->achc_base_dn;
                     dsl_context.imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
                     dsl_context.iec_chs_val = ied_chs_utf_8;
                   }

                   // build 'objectSid' for the primary group
                   memcpy( (void *)&dsl_sid_1, (const void *)this->ads_domainSID, sizeof(struct dsd_sid) );
                   *(int *)dsl_sid_1.uchcr_subID[dsl_sid_1.uchc_count_subIDs] = iml_pg;
                   dsl_sid_1.uchc_count_subIDs++;
                   this->m_aux_hex_to_sid( &dsl_sid_1, &dsl_val_1, this->ads_hl_stor_tmp );

                   // perform a search request for the 'primary group'-dn...
                   string str_filter( "(&(objectClass=" );
                          str_filter += string( this->ads_ldap_entry->adsc_ldap_template->achc_group_attr,
                                                this->ads_ldap_entry->adsc_ldap_template->imc_len_group_attr );
                          str_filter += ")(objectSid=";
                          str_filter += string( dsl_val_1.ac_val, dsl_val_1.imc_len_val );
                          str_filter += "))";

                   dsl_co_ldap_pg.iec_co_ldap      = ied_co_ldap_search;
                   dsl_co_ldap_pg.iec_sear_scope   = ied_sear_sublevel;
                   dsl_co_ldap_pg.ac_filter        = (char *)str_filter.c_str();
                   dsl_co_ldap_pg.imc_len_filter   = (int)str_filter.length();
                   dsl_co_ldap_pg.iec_chs_filter   = ied_chs_utf_8;
                   dsl_co_ldap_pg.ac_attrlist      = (char*)"objectSid";
                   dsl_co_ldap_pg.imc_len_attrlist = sizeof "objectSid" - 1;
                   dsl_co_ldap_pg.iec_chs_attrlist = ied_chs_utf_8;
                   dsl_co_ldap_pg.ac_dn            = dsl_context.ac_val;
                   dsl_co_ldap_pg.imc_len_dn       = dsl_context.imc_len_val;
                   dsl_co_ldap_pg.iec_chs_dn       = dsl_context.iec_chs_val;

                   if (this->m_ldap_search( &dsl_co_ldap_pg ) == ied_ldap_success &&
                       dsl_co_ldap_pg.adsc_attr_desc)
                   { // add 'primary group'-dn...
                     // find next free structure in the chain...
                     adsl_val_pg  = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                             sizeof(struct dsd_ldap_val) );
                     memset( (void *)adsl_val_pg, 0, sizeof(struct dsd_ldap_val) );

                     adsl_val_pg->imc_len_val = dsl_co_ldap_pg.adsc_attr_desc->imc_len_dn;
                     adsl_val_pg->iec_chs_val = dsl_co_ldap_pg.adsc_attr_desc->iec_chs_dn;
                     adsl_val_pg->ac_val      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                          adsl_val_pg->imc_len_val );
                     memcpy( (void *)adsl_val_pg->ac_val,
                             (const void *)dsl_co_ldap_pg.adsc_attr_desc->ac_dn,
                             adsl_val_pg->imc_len_val );
                   } // search(successful)
                 } // domainSID set
               } // namingcontexts
             } // primaryGroupID found
           } // 'primaryGroupID'
         }

         // step to the next
         adsl_attr_2 = adsl_attr_1;  // save old address
         adsl_attr_1 = adsl_attr_1->adsc_next_attr;
       } // while (partial attributes)


       if (adsl_attr_mship)
       { // add 'primary group'-dn to the list of 'memberOf'-values
         struct dsd_ldap_val *adsl_val_2 = &adsl_attr_mship->dsc_val;

         while (adsl_val_2->adsc_next_val)  // search end of list...
              adsl_val_2 = adsl_val_2->adsc_next_val;

         adsl_val_2->adsc_next_val = adsl_val_pg;
       }
       else
       { // we don't have any membership entries, but do we have the 'primaryGroupId'?
         if (adsl_val_pg)
         { // yes, we have a 'primaryGroupId'
           adsl_attr_2->adsc_next_attr = (struct dsd_ldap_attr *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                                   sizeof( struct dsd_ldap_attr) );
           adsl_attr_1 = adsl_attr_2->adsc_next_attr;
           adsl_attr_1->ac_attr        = this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr;
           adsl_attr_1->imc_len_attr   = this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr;
           adsl_attr_1->iec_chs_attr   = ied_chs_utf_8;
           adsl_attr_1->adsc_next_attr = NULL;
           adsl_attr_1->dsc_val.ac_val        = adsl_val_pg->ac_val;
           adsl_attr_1->dsc_val.imc_len_val   = adsl_val_pg->imc_len_val;
           adsl_attr_1->dsc_val.iec_chs_val   = adsl_val_pg->iec_chs_val;
           adsl_attr_1->dsc_val.adsc_next_val = NULL;
           adsl_attr_1->dsc_val.ac_val_old    = NULL;
           adsl_attr_1->dsc_val.imc_len_val_old = 0;
         }
         else
           adsl_attr_1 = NULL;
       }
     } // MSAD only!

     // set return search results (member, objectSID and others...)
     adsp_co_ldap->adsc_attr_desc = dsl_co_ldap.adsc_attr_desc;


     if (adsp_co_ldap->iec_ldap_auth == ied_auth_user)
     {  // do the final user's bind with the found dn...
        struct dsd_unicode_string  ds_unicode_usr = { dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn,  dsl_co_ldap.iec_chs_dn, };
        struct dsd_unicode_string  ds_unicode_pwd = { adsp_co_ldap->ac_passwd, 
                                                      adsp_co_ldap->imc_len_passwd, 
                                                      adsp_co_ldap->iec_chs_passwd };
        
        iml_rc = this->m_aux_bind_simple( &ds_unicode_usr, &ds_unicode_pwd );
     }

     // save the bind result credentials...
BIND_DN:
     if (iml_rc == ied_ldap_success)
     { // save bind-parameter (for reconnect!!!)
       GET_MEM_CHAR(this->ads_hl_stor_per, this->achr_dn, dsl_co_ldap.imc_len_dn)
       this->im_len_dn = dsl_co_ldap.imc_len_dn;
       memcpy( (void *)this->achr_dn, (const void *)dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn );


       if (adsp_co_ldap->imc_len_passwd && adsp_co_ldap->iec_chs_passwd != ied_chs_utf_8)
       { this->im_len_pwd = m_len_vx_vx( ied_chs_utf_8,
                                         (void *)adsp_co_ldap->ac_passwd, int(adsp_co_ldap->imc_len_passwd), adsp_co_ldap->iec_chs_passwd );
         if (this->im_len_pwd == -1)
         { // error, invalid string format...
           this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
           return ied_ldap_failure;
         }
         // translation to UTF-8...
         GET_MEM_CHAR( this->ads_hl_stor_per, this->achr_pwd, this->im_len_pwd )
         if (m_cpy_vx_vx_fl( (void *)this->achr_pwd, this->im_len_pwd, ied_chs_utf_8,
                             (void *)adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, adsp_co_ldap->iec_chs_passwd,
                             D_CPYVXVX_FL_NOTAIL0 ) == -1)
         { // error, invalid string format...
           this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
           return ied_ldap_failure;
         }
       }
       else
       { // save password
         GET_MEM_CHAR( this->ads_hl_stor_per, this->achr_pwd, adsp_co_ldap->imc_len_passwd )
         this->im_len_pwd = adsp_co_ldap->imc_len_passwd;
         memcpy( (void *)this->achr_pwd, (const void *)adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd );
       }
     } // ied_ldap_success
     else
     { // ied_ldap_password_change?
       if (iml_rc == ied_ldap_password_change || iml_rc == ied_ldap_password_expired)
       { // save the dn (for password change!)...
         GET_MEM_CHAR( this->ads_hl_stor_tmp, adsp_co_ldap->ac_dn, dsl_co_ldap.imc_len_dn )
         adsp_co_ldap->imc_len_dn = dsl_co_ldap.imc_len_dn;
         adsp_co_ldap->iec_chs_dn = ied_chs_utf_8;
         memcpy( (void *)adsp_co_ldap->ac_dn, (const void *)dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn );
       }
     }
   } // connected

   return iml_rc;

}; // dsd_ldap::m_ldap_bind()


/**
 * Private class function:  dsd_ldap::m_aux_bind_admin()
 *
 * Binds and authenticates as the administrator to a ldap server. Look for a further
 * description at m_ldap_bind().
 *
 * @return   error        (\b ied_ldap_failure),
 *           successful   (\b ied_ldap_success) or
 *           send blocked (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_bind_admin()
{
   // now we process the administrator bind...
   struct dsd_unicode_string  ds_userid = { this->ads_ldap_entry->achc_userid,   
                                            this->ads_ldap_entry->imc_len_userid, 
                                            ied_chs_utf_8 };
   struct dsd_unicode_string  ds_passwd = { this->ads_ldap_entry->achc_password, 
                                            this->ads_ldap_entry->imc_len_password, 
                                            ied_chs_utf_8 };

   return this->m_aux_bind_simple( &ds_userid, &ds_passwd );

} // dsd_ldap::m_aux_bind_admin()


/**
 * Private class function:  dsd_ldap::m_aux_bind_simple()
 *
 * Binds and authenticates to a ldap server. Look for a further
 * description at m_ldap_bind().
 *
 * @param[in]  struct dsd_unicode_string *   user-id, user-dn (required!)
 * @param[in]  struct dsd_unicode_string *   password (utf-8, required)
 *
 * @return     error                   (\b ied_ldap_failure),
 *             successful              (\b ied_ldap_success),
 *             send blocked            (\b ied_ldap_send_blocked),
 *             password expired        (\b ied_ldap_password_expired),
 *             invalid credentials     (\b ied_ldap_inv_cred),
 *             anonymous not supported (\b ied_ldap_auth_notsupp) or
 *             password required       (\b ied_ldap_strong_auth_req)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_bind_simple( struct dsd_unicode_string *adsp_userid, 
                                 struct dsd_unicode_string *adsp_passwd )
{
   // initiate ASN.1 class...
   this->ds_asn1.m_init(&this->ads_hl_stor_tmp );

   // check for valid input parameters...
   if (!adsp_userid->imc_len_str)
   { // error, anonymous bind not allowed...
     this->ds_ldap_error.m_set_error( ied_ldap_auth_notsupp, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   if (!adsp_passwd->imc_len_str)
     { // error, stronger authentication required (no bind without password!)...
       this->ds_ldap_error.m_set_error( ied_ldap_strong_auth_req, ied_ldap_bind_err );
       return ied_ldap_failure;
     }

   // now we have to search for '*' and '?' --> these user-ids are not valid!
       // it doesn't matter whether the characters are masked by '\' or utf-8 sequences
   char *achl_1 = (char *)adsp_userid->ac_str, 
        *achl_2 = (char *)adsp_userid->ac_str + adsp_userid->imc_len_str;

       do { if (*achl_1 == '*' || *achl_1 == '?')
            { // error, user name contains invalid and forbidden characters...
              this->ds_ldap_error.m_set_error( ied_ldap_inv_cred, ied_ldap_bind_err );
              return ied_ldap_failure;
            }
            achl_1++;
          } while (achl_1 < achl_2);

   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init(&this->ads_hl_stor_tmp);
   // build bind-request...
   LDAPREQ_BIND(this->ds_ldapreq)

   if (this->ds_asn1.m_printf( "{it{ists}}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               LDAP_VERSION_3 /*i*/,
                               adsp_userid->ac_str, adsp_userid->imc_len_str, int(adsp_userid->iec_chs_str) /*s*/,
                               LDAP_AUTH_SIMPLE /*t*/,
                               adsp_passwd->ac_str, adsp_passwd->imc_len_str, int(adsp_passwd->iec_chs_str) /*s*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for bind response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (BIND-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc == ied_ldap_success)
   { // BIND was successful
     this->im_c_status = dsd_ldap::BIND;
     return iml_rc;
   }

   // @todo: error message to event viewer or something else...
   this->ds_ldap_error.m_set_apicode( ied_ldap_bind_err );
   if (iml_rc == ied_ldap_password_change || iml_rc == ied_ldap_password_expired)
     return iml_rc;

   return ied_ldap_failure;

}; // dsd_ldap::m_aux_bind_simple()


#ifdef HOB_LDAP_REFERRAL
/**
 * Private class function:  dsd_ldap::m_ref_bind_subdomain()
 *
 * Do a simple Bind and authenticates to a ldap server. Look for a further
 * description at m_ldap_bind().
 *
 * @param[in]  adsp_tcpsync   synchronous TCP
 * @param[in]  adsp_co_ldap   request structure
 *
 * @return     error                   (\b ied_ldap_failure),
 *             successful              (\b ied_ldap_success),
 *             send blocked            (\b ied_ldap_send_blocked),
 *             password expired        (\b ied_ldap_password_expired),
 *             invalid credentials     (\b ied_ldap_inv_cred),
 *             anonymous not supported (\b ied_ldap_auth_notsupp) or
 *             password required       (\b ied_ldap_strong_auth_req)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ref_bind_subdomain( struct dsd_tcpsync_1  *adsp_tcpsync,
                                    struct dsd_co_ldap_1  *adsp_co_ldap )
{
   // initialize asn.1-storage manager...
   class dsd_asn1  dsl_asn1;
                   dsl_asn1.m_init( this->ads_hl_stor_tmp );

   // check for valid input parameters...
   if (!adsp_co_ldap->imc_len_userid || adsp_co_ldap->ac_userid == NULL)
   { // error, anonymous bind not allowed...
     this->ds_ldap_error.m_set_error( ied_ldap_auth_notsupp, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   if (!adsp_co_ldap->imc_len_passwd || adsp_co_ldap->ac_passwd == NULL)
     { // error, stronger authentication required (no bind without password!)...
       this->ds_ldap_error.m_set_error( ied_ldap_strong_auth_req, ied_ldap_bind_err );
       return ied_ldap_failure;
     }

   // now we have to search for '*' and '?' --> these userids are not valid!
       // it doesn't matter whether the characters are masked by '\' or utf-8 sequences
       char *achl_1 = (char *)adsp_co_ldap->ac_userid, *achl_2 = (char *)adsp_co_ldap->ac_userid + adsp_co_ldap->imc_len_userid;

       do { if (*achl_1 == '*' || *achl_1 == '?')
            { // error, user name contains invalid and forbidden characters...
              this->ds_ldap_error.m_set_error( ied_ldap_inv_cred, ied_ldap_bind_err );
              return ied_ldap_failure;
            }
            achl_1++;
          } while (achl_1 < achl_2);

   // initialize receive buffer storage management
   dsd_bufm  dsl_buf_ldap;
             dsl_buf_ldap.m_init( this->ads_hl_stor_tmp, 1024 );
   // build bind-request...
   struct dsd_ldapreq  dsl_ldapreq;
   LDAPREQ_BIND( dsl_ldapreq )

   if (dsl_asn1.m_printf( "{it{ists}}",
                          dsl_ldapreq.imc_msgid /*i*/,
                          dsl_ldapreq.imc_req /*t*/,
                          LDAP_VERSION_3 /*i*/,
                          adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, adsp_co_ldap->iec_chs_userid /*s*/,
                          LDAP_AUTH_SIMPLE /*t*/,
                          adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, adsp_co_ldap->iec_chs_passwd /*sS*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // send the message...
   dsl_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   dsl_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send

   int iml_error;
   struct dsd_gather_i_1 *adsl_gather_out (NULL);

   if (m_tcpsync_send_gather( &iml_error,
                              adsp_tcpsync,
                              dsl_asn1.ads_gather,
                              &adsl_gather_out,
                              5000 /* time out */ ) == FALSE)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_send_err, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // wait for bind response...
   int iml_len (m_tcpsync_recv( &iml_error,
                                adsp_tcpsync,
                                (char *)dsl_buf_ldap.m_getaddr(),
                                1024 /* buffer size for bind response */,
                                5000 /* time out */ ));
   if (iml_len < 1)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_connection_closed, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // parse LDAP result (BIND-response)...
   dsl_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;
   dsl_buf_ldap.imc_datalen = iml_len;
   dsl_buf_ldap.imc_nextpos = iml_len;

   iml_error = this->m_aux_parse_resp( &dsl_buf_ldap, &dsl_asn1, &dsl_ldapreq );
   if (iml_error != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_bind_err );
     if (iml_error == ied_ldap_password_change)
       return iml_error;

     return ied_ldap_failure;
   }


   // BIND was successful
   // search filter: "(&(objectClass=...)(|(sAMAccoundName=...)(cn=...)))"
   void *avol_1;
   struct dsd_ldap_template *adsl_templ  (this->ads_ldap_entry->adsc_ldap_template);

   LDAP_REQ_STRUC(dsl_co_ldap)

   dsl_co_ldap.iec_sear_scope = ied_sear_sublevel;   // 'baseObject and all sub-levels'
   dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
   dsl_co_ldap.imc_len_filter = sizeof "(objectClass=)" - 1 + (adsl_templ->imc_len_user_attr ? adsl_templ->imc_len_user_attr // e.g. objectClass='person'
                                                                                             : 1);                           // objectClass='*'
   dsl_co_ldap.imc_len_filter += (adsl_templ->imc_len_search_d_a ? adsl_templ->imc_len_search_d_a  // e.g. "userPrincipalName"
                                                                 : sizeof "sAMAccountName" - 1) +  // default
                                 sizeof "(=)" - 1;
   dsl_co_ldap.imc_len_filter += (adsl_templ->imc_len_upref ? adsl_templ->imc_len_upref            // e.g. "uid"
                                                            : sizeof "cn" - 1) +                   // default
                                 sizeof "(=)" - 1;
   dsl_co_ldap.imc_len_filter += adsp_co_ldap->imc_len_userid * 2 + sizeof "(&(|))" - 1;

   avol_1 = dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_filter );
   
   // build filter
   memcpy( avol_1, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
   avol_1 = (char *)avol_1 + sizeof "(&(objectClass=" - 1;

   if (adsl_templ->imc_len_user_attr /*person*/)
   { // objectClass=person
     memcpy( avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
   }
   else
   { // objectClass=*
     *(char *)avol_1 = '*';
     avol_1 = (char *)avol_1 + 1;
   }

   memcpy( avol_1, (const void *)")(|(", sizeof ")(|(" - 1 );
   avol_1 = (char *)avol_1 + sizeof ")(|(" - 1;

   // "searchDefaultAttribute"
   if (adsl_templ->imc_len_search_d_a)
   { // e.g. userPrincipalName=...
     memcpy( avol_1, (const void *)adsl_templ->achc_search_d_a, adsl_templ->imc_len_search_d_a );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_search_d_a;
   }
   else
   { // sAMAccountName=...
     memcpy( avol_1, (const void *)"sAMAccountName", sizeof "sAMAccountName" - 1 );
     avol_1 = (char *)avol_1 + sizeof "sAMAccountName" - 1;
   }

   *(char *)avol_1 = '=';
   avol_1 = (char *)avol_1 + 1;
   memcpy( avol_1, (const void *)adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid );
   avol_1 = (char *)avol_1 + adsp_co_ldap->imc_len_userid;
   memcpy( avol_1, (const void *)")(", sizeof ")(" - 1 );
   avol_1 = (char *)avol_1 + sizeof ")(" - 1;

   // "userPrefix"
   if (adsl_templ->imc_len_upref)
   { // e.g. uid=...
     memcpy( avol_1, (const void *)adsl_templ->achc_upref, adsl_templ->imc_len_upref );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_upref;
   }
   else
   { // cn=...
     memcpy( avol_1, (const void *)"cn", sizeof "cn" - 1 );
     avol_1 = (char *)avol_1 + sizeof "cn" - 1;
   }

   *(char *)avol_1 = '=';
   avol_1 = (char *)avol_1 + 1;
   memcpy( avol_1, (const void *)adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid );
   avol_1 = (char *)avol_1 + adsp_co_ldap->imc_len_userid;
   memcpy( avol_1, (const void *)")))", sizeof ")))" - 1 );


   // set attribute-list to return (e.g. <user-prefix>, <membership-attribute> and
   // optional (MSAD): "objectSid" and "primaryGroupID")
   dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
   dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_upref + adsl_templ->imc_len_mship_attr;
   dsl_co_ldap.ac_attrlist      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_attrlist + 2/*'\,'*/ +
                                  sizeof "objectSid,primaryGroupID," - 1/*'\0'*/ );
   avol_1 = (void *)dsl_co_ldap.ac_attrlist;
   // add "objectSid" and "primaryGroupID" only, if we have a MSAD-type!
   if (this->im_ldap_type == ied_sys_ldap_msad)
   {
     memcpy( avol_1, (const void *)"objectSid,primaryGroupID,", sizeof "objectSid,primaryGroupID," - 1 );
     avol_1 = (char *)avol_1 + sizeof "objectSid,primaryGroupID," - 1;
     dsl_co_ldap.imc_len_attrlist += sizeof "objectSid,primaryGroupID," - 1;
   } // MSAD environment only

   // <user-prefix>, e.g. "cn"?
   if (adsl_templ->imc_len_upref)
   {
     memcpy( avol_1, (const void *)adsl_templ->achc_upref, adsl_templ->imc_len_upref );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_upref;

     if (adsl_templ->imc_len_mship_attr)
     {
       *(char *)avol_1 = ',';
       avol_1 = (char *)avol_1 + 1;
       ++dsl_co_ldap.imc_len_attrlist;
     }
   }
   
   // <membership-attribute>, e.g. "memberOf"?
   if (adsl_templ->imc_len_mship_attr)
     memcpy( avol_1, (const void *)adsl_templ->achc_mship_attr, adsl_templ->imc_len_mship_attr );


   // do we use a realm?
   dsl_co_ldap.dsc_add_dn.ac_str      = adsp_co_ldap->dsc_add_dn.ac_str;
   dsl_co_ldap.dsc_add_dn.iec_chs_str = adsp_co_ldap->dsc_add_dn.iec_chs_str;
   dsl_co_ldap.dsc_add_dn.imc_len_str = adsp_co_ldap->dsc_add_dn.imc_len_str;

   // perform the search-request...
   int  iml_rc  (this->m_ldap_search( &dsl_co_ldap, FALSE/*attr and vals*/,
                                      &dsl_co_ldap.ac_dn, &dsl_co_ldap.imc_len_dn, &dsl_co_ldap.iec_chs_dn ));
   FREE_MEM( this->ads_hl_stor_tmp, dsl_co_ldap.ac_filter )
   FREE_MEM( this->ads_hl_stor_tmp, dsl_co_ldap.ac_attrlist )
   dsl_co_ldap.imc_len_filter = dsl_co_ldap.imc_len_attrlist = 0;

     // search error!
     if (iml_rc != ied_ldap_success)
     { // if ied_auth_dn was set, we should save the bind-parameters (for reconnect)
       // error...
       return iml_rc;
     }

     // before we bind with the found dn (ied_auth_user only!), we should save the results...
     if (this->im_ldap_type == ied_sys_ldap_msad)
     { // MSAD only: check and convert the 'objectSID'
       struct dsd_ldap_attr *adsl_attr_1 (dsl_co_ldap.adsc_attr_desc->adsc_attr);
       struct dsd_ldap_attr *adsl_attr_2 (adsl_attr_1);
       struct dsd_ldap_attr *adsl_attr_mship (NULL);
       struct dsd_sid        dsl_sid_1;
       struct dsd_ldap_val  *adsl_val_pg = NULL, dsl_val_1;
       int  iml_pg;

       LDAP_REQ_STRUC(dsl_co_ldap_pg)


       while (adsl_attr_1)
       { // check the returned partial attributes...
         if (adsl_attr_1->imc_len_attr == this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr &&
             !m_hl_memicmp( adsl_attr_1->ac_attr, this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr, adsl_attr_1->imc_len_attr ))
           // save attribute address of <memberOf>
           adsl_attr_mship = adsl_attr_1;
         else
         {
           if (adsl_attr_1->imc_len_attr == sizeof "objectSid" - 1 &&
               !m_hl_memicmp( adsl_attr_1->ac_attr, (void *)"objectSid", adsl_attr_1->imc_len_attr ))
           { // 'objectSid'...
             memcpy( (void *)&dsl_sid_1,
                     (const void *)adsl_attr_1->dsc_val.ac_val,
                     adsl_attr_1->dsc_val.imc_len_val );
             this->m_aux_hex_to_sid( &dsl_sid_1, &adsl_attr_1->dsc_val, this->ads_hl_stor_tmp );
           }
           else
           { // 'primaryGroupID'...
             if (adsl_attr_1->imc_len_attr == sizeof "primaryGroupID" - 1 &&
                 !m_hl_memicmp( adsl_attr_1->ac_attr, (void *)"primaryGroupID", adsl_attr_1->imc_len_attr ))
             { // search group associated with the 'primaryGroupID' found!
               string str_pg( adsl_attr_1->dsc_val.ac_val, adsl_attr_1->dsc_val.imc_len_val );
               iml_pg = atoi( str_pg.c_str() );
               // endianess?
               if (this->bo_le == FALSE)
               { // convert from le to be
                 iml_pg = m_bswap32(iml_pg);
               }

               if (this->bo_RootDSE == TRUE || this->m_aux_search_RootDSE() == ied_ldap_success)
               {
                 if (this->ads_domainSID)
                 { 
                   struct dsd_ldap_val  dsl_context;

                   // MS LDS doesn't support 'defaultNamingContext'
                   if (this->ds_RootDSE.ads_defaultcontext)
                   { // MSAD with default context
                     dsl_context.ac_val      = this->ds_RootDSE.ads_defaultcontext->ac_val;
                     dsl_context.imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
                     dsl_context.iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
                   }
                   else
                   { // MS LDS
                     dsl_context.ac_val      = this->ads_ldap_entry->achc_base_dn;
                     dsl_context.imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
                     dsl_context.iec_chs_val = ied_chs_utf_8;
                   }
                 
                   // build 'objectSid' for the primary group
                   memcpy( (void *)&dsl_sid_1, (const void *)this->ads_domainSID, sizeof(struct dsd_sid) );
                   *(int *)dsl_sid_1.uchcr_subID[dsl_sid_1.uchc_count_subIDs] = iml_pg;
                   dsl_sid_1.uchc_count_subIDs++;
                   this->m_aux_hex_to_sid( &dsl_sid_1, &dsl_val_1, this->ads_hl_stor_tmp );

                   // perform a search request for the primary group dn...
                   string str_filter( "(&(objectClass=" );
                          str_filter += string( this->ads_ldap_entry->adsc_ldap_template->achc_group_attr,
                                                this->ads_ldap_entry->adsc_ldap_template->imc_len_group_attr );
                          str_filter += ")(objectSid=";
                          str_filter += string( dsl_val_1.ac_val, dsl_val_1.imc_len_val );
                          str_filter += "))";


                   dsl_co_ldap_pg.iec_co_ldap      = ied_co_ldap_search;
                   dsl_co_ldap_pg.iec_sear_scope   = ied_sear_sublevel;
                   dsl_co_ldap_pg.ac_filter        = (char *)str_filter.c_str();
                   dsl_co_ldap_pg.imc_len_filter   = str_filter.length();
                   dsl_co_ldap_pg.iec_chs_filter   = ied_chs_utf_8;
                   dsl_co_ldap_pg.ac_attrlist      = (char*)"objectSid";
                   dsl_co_ldap_pg.imc_len_attrlist = sizeof "objectSid" - 1;
                   dsl_co_ldap_pg.iec_chs_attrlist = ied_chs_utf_8;
                   dsl_co_ldap_pg.ac_dn            = dsl_context->ac_val;
                   dsl_co_ldap_pg.imc_len_dn       = dsl_context->imc_len_val;
                   dsl_co_ldap_pg.iec_chs_dn       = dsl_context->iec_chs_val;

                   if (this->m_ldap_search( &dsl_co_ldap_pg ) == ied_ldap_success &&
                       dsl_co_ldap_pg.adsc_attr_desc)
                   { // add 'primarygroup'-dn...
                     // find next free structure in the chain...
                     adsl_val_pg  = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                             sizeof(struct dsd_ldap_val) );
                     memset( (void *)adsl_val_pg, 0, sizeof(struct dsd_ldap_val) );

                     adsl_val_pg->imc_len_val = dsl_co_ldap_pg.adsc_attr_desc->imc_len_dn;
                     adsl_val_pg->iec_chs_val = dsl_co_ldap_pg.adsc_attr_desc->iec_chs_dn;
                     adsl_val_pg->ac_val      = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                          adsl_val_pg->imc_len_val );
                     memcpy( (void *)adsl_val_pg->ac_val,
                             (const void *)dsl_co_ldap_pg.adsc_attr_desc->ac_dn,
                             adsl_val_pg->imc_len_val );
                   } // search(successful)
                 } // domainSID set
               } // namingcontexts
             } // primaryGroupID found
           } // 'primaryGroupID'
         }

         // step to the next
         adsl_attr_2 = adsl_attr_1;  // save old address
         adsl_attr_1 = adsl_attr_1->adsc_next_attr;
       } // while (partial attributes)


       if (adsl_attr_mship)
       { // add 'memberOf'-value
         struct dsd_ldap_val *adsl_val_2 = &adsl_attr_mship->dsc_val;

         while (adsl_val_2->adsc_next_val)
              adsl_val_2 = adsl_val_2->adsc_next_val;

         adsl_val_2->adsc_next_val = adsl_val_pg;
       }
       else
       { // we don't have any membership entries, but do we have the 'primaryGroupId'?
         if (adsl_val_pg)
         { // yes, we have a 'primaryGroupId'
           adsl_attr_2->adsc_next_attr = (struct dsd_ldap_attr *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                                   sizeof( struct dsd_ldap_attr) );
           adsl_attr_1 = adsl_attr_2->adsc_next_attr;
           adsl_attr_1->ac_attr        = this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr;
           adsl_attr_1->imc_len_attr   = this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr;
           adsl_attr_1->iec_chs_attr   = ied_chs_utf_8;
           adsl_attr_1->adsc_next_attr = NULL;
           adsl_attr_1->dsc_val.ac_val        = adsl_val_pg->ac_val;
           adsl_attr_1->dsc_val.imc_len_val   = adsl_val_pg->imc_len_val;
           adsl_attr_1->dsc_val.iec_chs_val   = adsl_val_pg->iec_chs_val;
           adsl_attr_1->dsc_val.adsc_next_val = NULL;
           adsl_attr_1->dsc_val.ac_val_old    = NULL;
           adsl_attr_1->dsc_val.imc_len_val_old = 0;
         }
         else
           adsl_attr_1 = NULL;
       }
     } // MSAD only!

     // set return search results (member, objectSID and others...)
     adsp_co_ldap->adsc_attr_desc = dsl_co_ldap.adsc_attr_desc;


     if (adsp_co_ldap->iec_ldap_auth == ied_auth_user)
       // do the final user's bind with the found dn...
       iml_rc = this->m_aux_bind_simple( dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn,  dsl_co_ldap.iec_chs_dn,
                                         adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, adsp_co_ldap->iec_chs_passwd );

     // save the bind result credentials...
//BIND_DN:
     if (iml_rc == ied_ldap_success)
     { // save bind-parameter (for reconnect!!!)
       GET_MEM_CHAR( this->ads_hl_stor_per, this->achr_dn, dsl_co_ldap.imc_len_dn )
       this->im_len_dn = dsl_co_ldap.imc_len_dn;
       memcpy( (void *)this->achr_dn, (const void *)dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn );


       if (adsp_co_ldap->imc_len_passwd && adsp_co_ldap->iec_chs_passwd != ied_chs_utf_8)
       { this->im_len_pwd = m_len_vx_vx( ied_chs_utf_8,
                                         (void *)adsp_co_ldap->ac_passwd, int(adsp_co_ldap->imc_len_passwd), adsp_co_ldap->iec_chs_passwd );
         if (this->im_len_pwd == -1)
         { // error, invalid string format...
           this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
           return ied_ldap_failure;
         }
         // translation to UTF-8...
         GET_MEM_CHAR( this->ads_hl_stor_per, this->achr_pwd, this->im_len_pwd + 1 /*'\0'*/ )
         if (m_cpy_vx_vx_fl( (void *)this->achr_pwd, this->im_len_pwd, ied_chs_utf_8,
                             (void *)adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, adsp_co_ldap->iec_chs_passwd,
                             D_CPYVXVX_FL_NOTAIL0 ) == -1)
         { // error, invalid string format...
           this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_bind_err );
           return ied_ldap_failure;
         }
       }
       else
       { // save password
         GET_MEM_CHAR( this->ads_hl_stor_per, this->achr_pwd, adsp_co_ldap->imc_len_passwd )
         this->im_len_pwd = adsp_co_ldap->imc_len_passwd;
         memcpy( (void *)this->achr_pwd, (const void *)adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd );
       }
     } // ied_ldap_success
     else
     { // ied_ldap_password_change?
       if (iml_rc == ied_ldap_password_change)
       { // save the dn (for password change!)...
         GET_MEM_CHAR( this->ads_hl_stor_tmp, adsp_co_ldap->ac_dn, dsl_co_ldap.imc_len_dn )
         adsp_co_ldap->imc_len_dn = dsl_co_ldap.imc_len_dn;
         adsp_co_ldap->iec_chs_dn = ied_chs_utf_8;
         memcpy( (void *)adsp_co_ldap->ac_dn, (const void *)dsl_co_ldap.ac_dn, dsl_co_ldap.imc_len_dn );
       }
     }

   return iml_error;

}; // dsd_ldap::m_ref_bind_subdomain()
#endif // HOB_LDAP_REFERRAL


#ifdef HOB_SPNEGO_SUPPORT
/**
 * Private class function:  dsd_ldap::m_aux_bind_sasl()
 *
 * Binds and authenticates to a ldap server, using SASL credentials. The GSS-SPNEGO authentication
 * mechanism (RFC4178) is actually the GSSAPI authentication mechanism but with a client-server
 * negotiation mechanism that provides for selection of the preferred security mechanism that both
 * client and server support. In this case, the server will prefer Kerberos then NTLMv2 then NTLM.
 * Look for a further description at m_ldap_bind().
 *
 * @param[in]  dsd_unicode_string *   user-id (utf-8) 
 * @param[in]  dsd_unicode_string *   password (utf-8)
 * @param[in]  iep_ldap_auth   sasl mechanism (e.g. NTLMv2)
 *
 * @return     error          (\b ied_ldap_failure),
 *             successful     (\b ied_ldap_success),
 *             send blocked   (\b ied_ldap_send_blocked) or
 *             saslInProgress (\b ied_ldap_sasl_bind)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */

/** callback routines for NTLM component                                */
static BOOL m_cb_get_random( void *vpp_userfld, char *achp_random, int imp_len_random )
{
   if (m_secdrbg_randbytes(achp_random, imp_len_random) == 0)
     return TRUE;

   return FALSE;

} // m_ntlm_get_random()


static BOOL m_cb_get_epoch( void *vpp_userfld, HL_LONGLONG *ailp_epoch )
{
   *ailp_epoch = m_get_epoch_ms();
   return TRUE;

} // m_ntlm_get_epoch()


int dsd_ldap::m_aux_bind_sasl( struct dsd_unicode_string *adsp_usr, struct dsd_unicode_string *adsp_pwd,
                               enum ied_auth_ldap_def iep_ldap_auth,
                               struct dsd_aux_get_domain_info_1 *adsp_domain_info )
{
#define HL_MECHANISM_LEN     2048   
#define HL_CHANNEL_BINDINGS  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";


   char *achr_token, *achl_mech;
   int   im_token_len;

   
   struct dsd_ntlm_req  dsl_ntlm_req;
   memset((void *)&dsl_ntlm_req, int(0), sizeof(struct dsd_ntlm_req));


   switch (iep_ldap_auth)
   {
      case ied_auth_krb5:   // set kerberos token
                            achr_token   = dsl_ntlm_req.achc_negotiate;
                            im_token_len = dsl_ntlm_req.imc_len_negotiate;
                            // set mechanism
                            achl_mech = "GSSAPI";
                            break;

      case ied_auth_ntlm:   // set up ntlm-request (type 1 message)
                            dsl_ntlm_req.vpc_userfld    = (void *)this;
                            dsl_ntlm_req.amc_get_epoch  = &m_cb_get_epoch;     // callback get_epoch
                            dsl_ntlm_req.amc_get_random = &m_cb_get_random;    // callback get_random
                            dsl_ntlm_req.boc_gssapi     = TRUE;
                            dsl_ntlm_req.iec_ntlmf      = ied_ntlmf_neg_gen;   // generate type 1 message
                                                                               // allocate packet NTLMSSP_NEGOTIATE
                            dsl_ntlm_req.achc_negotiate    = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, HL_MECHANISM_LEN );
                            dsl_ntlm_req.imc_len_negotiate = HL_MECHANISM_LEN;
                            memset((void *)dsl_ntlm_req.achc_negotiate, int(0), dsl_ntlm_req.imc_len_negotiate);

                            dsl_ntlm_req.dsc_ucs_prot_target.ac_str      = "NTLMSSP";
                            dsl_ntlm_req.dsc_ucs_prot_target.imc_len_str = sizeof("NTLMSSP") - 1;
                            dsl_ntlm_req.dsc_ucs_prot_target.iec_chs_str = ied_chs_utf_8;

                            if (!m_proc_ntlm_req( &dsl_ntlm_req ))
                            { // @todo: error message to event viewer or something else...
                              this->ds_ldap_error.m_set_error(ied_ldap_sasl_bind, ied_ldap_bind_err);
                              return ied_ldap_failure;
                            }
                            
                            // set token
                            achr_token   = dsl_ntlm_req.achc_negotiate;
                            im_token_len = dsl_ntlm_req.imc_len_negotiate;
                            // set mechanism
                            achl_mech = "GSS-SPNEGO";
                            break;
                         
      default:              // unknown mechanism!
                            this->ds_ldap_error.m_set_error(ied_ldap_auth_unknown, ied_ldap_bind_err);
                            return ied_ldap_failure;
   }; // switch (mechanism)


   // build bind-request (NTLM: type 1 message, KRB5: service ticket)...
   LDAPREQ_BIND(this->ds_ldapreq)

   if (this->ds_asn1.m_printf( "{it{ist{so}}}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               LDAP_VERSION_3 /*i*/,
                               NULL, 0, int(ied_chs_invalid) /*s*/,
                               LDAP_AUTH_SASL /*t*/,
                               achl_mech, strnlen(achl_mech, D_LDAP_MAX_STRLEN), int(ied_chs_utf_8) /*s*/,
                               achr_token, im_token_len /*o*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for bind response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (BIND-response, saslBindInProgress, NTLM: type 2 message)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc != ied_ldap_success && iml_rc != ied_ldap_sasl_bind)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // BIND was successful or in progress...
   if (iml_rc == ied_ldap_sasl_bind)
   { 
     this->im_c_status = dsd_ldap::BIND_SASL;
     
     if (iep_ldap_auth == ied_auth_ntlm)
     { // save type 2-message (challenge)...
       if (this->ds_asn1.m_scanf( "O", &dsl_ntlm_req.achc_challenge, &dsl_ntlm_req.imc_len_challenge, &this->ads_hl_stor_tmp ) != LASN1_SUCCESS)
       { // protocol error!
         this->ds_ldap_error.m_set_error( ied_ldap_decoding_err, ied_ldap_bind_err );
         return ied_ldap_failure;
       }
     }
   }


   // initialize token...
   achr_token   = NULL;
   im_token_len = 0;

   if (iep_ldap_auth == ied_auth_ntlm)
   { // set up ntlm-request (NTLM: type 3 message)
     dsl_ntlm_req.iec_ntlmf    = ied_ntlmf_auth_gen;   // generate type 3 message
                                                       // allocate packet NTLMSSP_AUTHENTICATE
     dsl_ntlm_req.boc_gssapi   = FALSE;
     dsl_ntlm_req.achc_auth    = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, HL_MECHANISM_LEN );
     dsl_ntlm_req.imc_len_auth = HL_MECHANISM_LEN;
     memset((void *)dsl_ntlm_req.achc_auth, int(0), dsl_ntlm_req.imc_len_auth);

     dsl_ntlm_req.dsc_ucs_userid.ac_str      = adsp_usr->ac_str;      // user-id 
     dsl_ntlm_req.dsc_ucs_userid.imc_len_str = adsp_usr->imc_len_str;
     dsl_ntlm_req.dsc_ucs_userid.iec_chs_str = adsp_usr->iec_chs_str;
     dsl_ntlm_req.dsc_ucs_password.ac_str      = adsp_pwd->ac_str;    // password
     dsl_ntlm_req.dsc_ucs_password.imc_len_str = adsp_pwd->imc_len_str;
     dsl_ntlm_req.dsc_ucs_password.iec_chs_str = adsp_pwd->iec_chs_str;
     dsl_ntlm_req.achc_msv_channel_bindings    = HL_CHANNEL_BINDINGS;
     // set target name
     char *achr_prot_target ((char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, 128));
     int   im_prot_target_len (128);

     memcpy((void *)achr_prot_target, (const void *)"ldap/", sizeof("ldap/")-1);
     m_hl_inet_ntop(&this->ds_conn, achr_prot_target + sizeof("ldap/") - 1, im_prot_target_len - sizeof("ldap/") - 1);

     dsl_ntlm_req.dsc_ucs_prot_target.ac_str      = achr_prot_target;  // target like "ldap/172.22.0.1"
     dsl_ntlm_req.dsc_ucs_prot_target.imc_len_str = -1;                // '\0' terminated
     dsl_ntlm_req.dsc_ucs_prot_target.iec_chs_str = ied_chs_ascii_850;

     // get computer name...
     char *achr_computername ((char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, 256));
     int   im_computername_len (256);
#if defined WIN32 || defined WIN64
     if (GetComputerNameExA(ComputerNameNetBIOS, achr_computername, (LPDWORD)&im_computername_len))
     { // set workstation name
       dsl_ntlm_req.dsc_ucs_workstation.ac_str      = achr_computername;
       dsl_ntlm_req.dsc_ucs_workstation.imc_len_str = im_computername_len;
       dsl_ntlm_req.dsc_ucs_workstation.iec_chs_str = ied_chs_ascii_850;
     }
#elif define HL_UNIX
     if (!gethostname(achr_computername, im_computername_len))
     { // set workstation name
       dsl_ntlm_req.dsc_ucs_workstation.ac_str      = achr_computername;
       dsl_ntlm_req.dsc_ucs_workstation.imc_len_str = strnlen(achr_computername, im_computer_name_len);
       dsl_ntlm_req.dsc_ucs_workstation.iec_chs_str = ied_chs_ascii_850;
     }
#endif

     if (!m_proc_ntlm_req( &dsl_ntlm_req ))
     { // @todo: error message to event viewer or something else...
       this->ds_ldap_error.m_set_error(ied_ldap_sasl_bind, ied_ldap_bind_err);
       return ied_ldap_failure;
     }

     // set token...
     achr_token   = dsl_ntlm_req.achc_auth;
     im_token_len = dsl_ntlm_req.imc_len_auth;

   } // NTLMv2


   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // build bind-request (type 3 message)...
   LDAPREQ_BIND(this->ds_ldapreq)

   if (this->ds_asn1.m_printf( "{it{ist{so}}}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               LDAP_VERSION_3 /*i*/,
                               NULL, 0, int(ied_chs_invalid) /*s*/,
                               LDAP_AUTH_SASL /*t*/,
                               achl_mech, strnlen(achl_mech, D_LDAP_MAX_STRLEN), int(ied_chs_utf_8) /*s*/,
                               achr_token, im_token_len /*o*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-bind!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for bind response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_bind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // @todo: This response is the final response for NTLM, but for Kerberos we get another krb5_blob (KRB_TOKEN_CFX_WRAP)
   //        So we have to take this blob, set any krb5_sgn_chksum and to send it again to LDAP, before we get the same
   //        final message
   //        This response seems to be a message built by GSS_Wrap(), thus we have to call GSS_Unwrap()
   //        Who is responsible for the ticket and how is it requested?

   // parse LDAP result (BIND-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc != ied_ldap_success && iml_rc != ied_ldap_sasl_bind)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // Bind(SPNEGO) was successful
   this->im_c_status = dsd_ldap::BIND;
   return iml_rc;

} // dsd_ldap::m_aux_bind_sasl()
#endif // HOB_SPNEGO_SUPPORT


/**
 * Private class function:  dsd_ldap::m_ldap_password()
 *
 * Only MSAD:
 * Changes the user's password in an active directory environment.
 * This is done by an authentication using the old password, then the result
 * is parsed for the password expired message. Last the password is changed
 * under the administrator's control.
 *
 * Only 'Password Modify Extended Operation'-support:
 * Set up an extended LDAP request [APPLICATION 23] with OID of 1.3.6.1.4.1.4203.1.11.1
 *
 * @param[in]  adsp_co_ldap   LDAP command structure
 *
 * @return     error         (\b ied_ldap_failure),
 *             successful    (\b ied_ldap_success) or
 *             send blocked  (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ldap_password( struct dsd_co_ldap_1 *adsp_co_ldap )
{

   if (this->im_ldap_type != ied_sys_ldap_msad)
     // use 'modify-password'-extended operation...
     return m_aux_password_ex( adsp_co_ldap );

   // from now we are in the MSAD-world...
   // MSAD says: we need a ssl-connection!!!
   if (this->ads_ldap_entry->boc_csssl_conf == FALSE)
   { // error, no ssl
     this->ds_ldap_error.m_set_error( ied_ldap_need_ssl, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   // 1. take the user account for the password change scenerio!
   // verify the old password (bind with the old password)...
   struct dsd_ldap_attr  dsl_attr_new, dsl_attr_old;

   dsl_attr_new.adsc_next_attr = NULL;
   dsl_attr_new.ac_attr        = (char *)"unicodePwd";
   dsl_attr_new.imc_len_attr   = sizeof "unicodePwd" - 1;
   dsl_attr_new.iec_chs_attr   = ied_chs_utf_8;
   dsl_attr_new.dsc_val.adsc_next_val = NULL;
   memcpy( (void *)&dsl_attr_old, (const void *)&dsl_attr_new, sizeof(struct dsd_ldap_attr) );

   //  convert the 'unicodePwd'-attribute values to utf-16 (le)
   if (adsp_co_ldap->imc_len_passwd_new)
     this->m_aux_msad_val( adsp_co_ldap->ac_passwd_new, adsp_co_ldap->imc_len_passwd_new, adsp_co_ldap->iec_chs_passwd_new,
                           &dsl_attr_new.dsc_val.ac_val, &dsl_attr_new.dsc_val.imc_len_val, &dsl_attr_new.dsc_val.iec_chs_val );
   else
   { // error, no new password defined (inappropriateAuthentication)
     this->ds_ldap_error.m_set_error( ied_ldap_inappr_auth, ied_ldap_bind_err );
     return ied_ldap_failure;
   }

   this->m_aux_msad_val( adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, adsp_co_ldap->iec_chs_passwd,
                         &dsl_attr_old.dsc_val.ac_val, &dsl_attr_old.dsc_val.imc_len_val, &dsl_attr_old.dsc_val.iec_chs_val );

   struct dsd_unicode_string  ds_unicode_usr = { adsp_co_ldap->ac_userid, 
                                                 adsp_co_ldap->imc_len_userid,
                                                 adsp_co_ldap->iec_chs_userid };
   struct dsd_unicode_string  ds_unicode_pwd = { adsp_co_ldap->ac_passwd, 
                                                 adsp_co_ldap->imc_len_passwd, 
                                                 adsp_co_ldap->iec_chs_passwd };

   int iml_rc = this->m_aux_bind_simple( &ds_unicode_usr, &ds_unicode_pwd);

   if (iml_rc != ied_ldap_success && iml_rc != ied_ldap_password_change)
     // bind (with old password) error! --> go to step 2 (admin-bind)
     goto ADMIN_PWD;

   // trace message LDAP0048T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))                                                                                   
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 48, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Modify password (MSAD) Userid=\"%.*(.*)s\"",
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->imc_len_userid : sizeof "none" - 1, 
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->iec_chs_userid : ied_chs_ascii_850, 
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->ac_userid : "none" );  

   // perform the modify-request with the new password...
   // this is done by a special modify (delete the old password and add the new one)
   if (this->m_aux_msad_modify_pw( adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, adsp_co_ldap->iec_chs_userid,
                                   &dsl_attr_old, &dsl_attr_new ) == ied_ldap_success)
      // the user's password has changed
      return ied_ldap_success;

ADMIN_PWD:
   // trace message LDAP0049T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))                                                                                   
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 49, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Modify password (MSAD) Administrator=\"%.*(.*)s\", Userid=\"%.*(.*)s\"",
                                  this->ads_ldap_entry ? (this->ads_ldap_entry->achc_userid ? this->ads_ldap_entry->imc_len_userid : sizeof "none" - 1) : 0,
                                  ied_chs_utf_8,
                                  this->ads_ldap_entry ? (this->ads_ldap_entry->achc_userid ? this->ads_ldap_entry->achc_userid : "none") : NULL,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->imc_len_userid : sizeof "none" - 1, 
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->iec_chs_userid : ied_chs_ascii_850, 
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->ac_userid : "none" );  

   // prepare the new password now (but we need an administrator bind)...
   struct dsd_unicode_string  ds_unicode_adm_2 = { this->ads_ldap_entry->achc_userid, 
                                                   this->ads_ldap_entry->imc_len_userid,
                                                   ied_chs_utf_8 };
   struct dsd_unicode_string  ds_unicode_pwd_2 = { this->ads_ldap_entry->achc_password, 
                                                   this->ads_ldap_entry->imc_len_password, 
                                                   ied_chs_utf_8 };

   if (this->m_aux_bind_simple(&ds_unicode_adm_2, &ds_unicode_pwd_2) != ied_ldap_success)
     // bind error!
     return iml_rc;

   if (this->m_aux_modify( adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, adsp_co_ldap->iec_chs_userid,
                           &dsl_attr_new, ied_ldap_mod_replace ) != ied_ldap_success)
   { // error, couldn't change the user's password...
     this->ds_ldap_error.m_set_error( ied_ldap_op_err, ied_ldap_change_pwd_err );
     return ied_ldap_failure;
   }

   return ied_ldap_success;

}; // dsd_ldap::m_ldap_password()


/**
 * Private class function:  dsd_ldap::m_aux_password_ex()
 *
 * Set up an extended LDAP request [APPLICATION 23] with OID of 1.3.6.1.4.1.4203.1.11.1
 *
 * ASN.1:
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE { requestName    LDAPOID,
 *                                                 requestValue   OCTET STRING OPTIONAL,
 *                                               }
 *
 *
 * @param[in]  adsp_co_ldap   LDAP command structure
 *
 * @return     error         (\b ied_ldap_failure),
 *             successful    (\b ied_ldap_success) or
 *             send blocked  (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
 int dsd_ldap::m_aux_password_ex( struct dsd_co_ldap_1 *adsp_co_ldap )
 {
   int iml_rc;


   // Support of the OID 1.3.6.1.4.1.4203.1.11.1 ?
   if (this->bo_RootDSE == FALSE && this->m_aux_search_RootDSE() != ied_ldap_success)
     // error, we can't execute the extended password change
     return ied_ldap_failure;

   struct dsd_ldap_val *adsl_OID = this->ds_RootDSE.ads_extendedOIDs;
   while (adsl_OID)
   { // search OID...
     if (adsl_OID->imc_len_val == sizeof OID_PW_MODIFY_EX - 1 &&
         !m_hl_memicmp( adsl_OID->ac_val, (void *)OID_PW_MODIFY_EX, sizeof OID_PW_MODIFY_EX - 1))
       break;
     else
       adsl_OID = adsl_OID->adsc_next_val;
   }

   if (!adsl_OID)
   { // error, no OID support found!
     this->ds_ldap_error.m_set_error( ied_ldap_op_err, ied_ldap_change_pwd_err );
     return ied_ldap_failure;
   }

   // trace message LDAP0045T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 45, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Modify password (OID=%s) Userid=\"%.*(.*)s\"",
                                  OID_PW_MODIFY_EX,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->imc_len_userid : sizeof "none" - 1,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->iec_chs_userid : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_userid ? adsp_co_ldap->ac_userid : "none" );

   // OID-support found, now we can do the following...
   // 1. new_password only --> password change (administrator bind)
   // 2. old/new-password  --> password change (user bind)
   //    first try to bind with the user-id and use the administrator-bind only if this step fails!
   if (adsp_co_ldap->ac_passwd)
   { // case 2 (password change)
     LDAP_REQ_STRUC(dsl_co_ldap);
     memcpy( (void *)&dsl_co_ldap, (const void *)adsp_co_ldap, sizeof(struct dsd_co_ldap_1) );
     
     dsl_co_ldap.iec_ldap_auth = ied_auth_dn;

     if (this->m_ldap_bind( &dsl_co_ldap ) != ied_ldap_success)
     { // now try to bind with the administrator-credentials...
       if (this->m_aux_bind_admin() != ied_ldap_success)
         // bind error!
         return ied_ldap_failure;
     }
   }

   // perform ldap request...
   LDAPREQ_PWMOD_EX(this->ds_ldapreq)
   // initialize asn.1-storage manager...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // build the asn.1-formatted extended operation request...
   if (adsp_co_ldap->ac_passwd)
     // case 2 (password change)
     iml_rc = this->ds_asn1.m_printf( "{it{tst{{tststs}}}}",
                                      this->ds_ldapreq.imc_msgid /*i*/,
                                      this->ds_ldapreq.imc_req /*t*/,
                                      LDAP_TAG_EXOP_REQ_OID /*t*/,
                                      OID_PW_MODIFY_EX, sizeof OID_PW_MODIFY_EX - 1, ied_chs_utf_8 /*s*/,
                                      LDAP_TAG_EXOP_REQ_VALUE /*t*/,
                                      LDAP_TAG_EXOP_MOD_USER /*t*/,
                                      adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, int(adsp_co_ldap->iec_chs_userid) /*s*/,
                                      LDAP_TAG_EXOP_MOD_PWD_O /*t*/,
                                      adsp_co_ldap->ac_passwd, adsp_co_ldap->imc_len_passwd, int(adsp_co_ldap->iec_chs_passwd) /*s*/,
                                      LDAP_TAG_EXOP_MOD_PWD_N /*t*/,
                                      adsp_co_ldap->ac_passwd_new, adsp_co_ldap->imc_len_passwd_new, int(adsp_co_ldap->iec_chs_passwd_new) /*s*/ );
   else
     // case 1 (password reset)
     iml_rc = this->ds_asn1.m_printf( "{it{tst{{tsts}}}}",
                                      this->ds_ldapreq.imc_msgid /*i*/,
                                      this->ds_ldapreq.imc_req /*t*/,
                                      LDAP_TAG_EXOP_REQ_OID /*t*/,
                                      OID_PW_MODIFY_EX, sizeof OID_PW_MODIFY_EX - 1, int(ied_chs_utf_8) /*s*/,
                                      LDAP_TAG_EXOP_REQ_VALUE /*t*/,
                                      LDAP_TAG_EXOP_MOD_USER /*t*/,
                                      adsp_co_ldap->ac_userid, adsp_co_ldap->imc_len_userid, int(adsp_co_ldap->iec_chs_userid) /*s*/,
                                      LDAP_TAG_EXOP_MOD_PWD_N /*t*/,
                                      adsp_co_ldap->ac_passwd_new, adsp_co_ldap->imc_len_passwd_new, int(adsp_co_ldap->iec_chs_passwd_new) /*s*/ );
   // do we get any errors?
   if (iml_rc == LASN1_ERROR)
   { // error; we can't execute the ldap-password change
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_change_pwd_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL???
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_change_pwd_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for extented response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_change_pwd_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (extendedOperation-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_change_pwd_err );
     return ied_ldap_failure;
   }

   return ied_ldap_success;

}; // dsd_ldap::m_aux_password_ex( struct dsd_co_ldap_1 * )


/**
 * Private class function:  dsd_ldap::m_aux_is_singlevalued()
 *
 * Look for the single- or multi-valued property of an given attribute.
 *
 * @param[in]     adsp_ldap_attr   structure, that contains the attribute to look for
 * @param[in,out] aiep_attrtype    the result of the single /multivalued test is stored there
 *
 * @return        error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_is_singlevalued( struct dsd_ldap_attr *adsp_ldap_attr, enum ied_ldap_attr_def *aiep_attrtype )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   int   iml_rc;
   int   iml_len_dn, iml_len_attr (adsp_ldap_attr->imc_len_attr);
   char *achl_dn, *achl_1;
   BOOL  bol_found (FALSE);
   struct dsd_ldap_attr_desc **aadsl_attr_desc;
   struct dsd_ldap_attr_desc  *adsl_attr_desc (NULL);


   *aiep_attrtype  = ied_ldap_attr_undef;
   aadsl_attr_desc = &adsl_attr_desc;

   // @todo: should we support formats other than utf-8 ?
   if (iml_len_attr == -1)
     iml_len_attr = (int)strnlen( (const char *)adsp_ldap_attr->ac_attr, D_LDAP_MAX_STRLEN );

   // have we requested the contexts yet?
   if (this->bo_RootDSE == FALSE)
   { // no, get contexts...
     this->m_aux_search_RootDSE();
     
     // reinitialize receive buffer storage management
     this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );
   }

   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );

   // MSAD schema context?
   if (this->ds_RootDSE.ads_schemacontext)
   { // build search-request...
     LDAPREQ_SEARCH(this->ds_ldapreq)

     struct dsd_ldap_template *adsl_templ = this->ads_ldap_entry->adsc_ldap_template;

     iml_len_dn = this->ds_RootDSE.ads_schemacontext->imc_len_val + iml_len_attr + 2 /*"=,*/ + (adsl_templ->imc_len_upref ? adsl_templ->imc_len_upref : sizeof "cn" - 1);
     achl_1 = achl_dn = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, iml_len_dn );
     if (adsl_templ->imc_len_upref)
     { // send this only if not set yet!
       memcpy( (void *)achl_1, (const void *)adsl_templ->achc_upref, adsl_templ->imc_len_upref );
       *(achl_1 + adsl_templ->imc_len_upref) = '=';
       achl_1 = achl_1 + adsl_templ->imc_len_upref + 1;
     }
     else
     { // default-attribute: "cn="
       memcpy( (void *)achl_1, (const void *)"cn=", sizeof "cn=" - 1 );
       achl_1 = achl_1 + sizeof "cn=" - 1;
     }
     memcpy( (void *)achl_1, (const void *)adsp_ldap_attr->ac_attr, iml_len_attr );
     achl_1 += iml_len_attr;
     *achl_1 = ',';
     memcpy( (void *)(achl_1 + 1), (const void *)this->ds_RootDSE.ads_schemacontext->ac_val, this->ds_RootDSE.ads_schemacontext->imc_len_val );

     // trace message LDAP0074T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 74, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "IsSinglevalued Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\" Max-Size=%i Max-Time=%i",
                                    this->ds_ldap_trace.m_translate( (int)ied_sear_baseobject, dsd_trace::S_SEARCH_SCOPE ),
                                    achl_dn ? iml_len_dn : sizeof "none" - 1,
                                    achl_dn ? this->ds_RootDSE.ads_schemacontext->iec_chs_val : ied_chs_ascii_850,
                                    achl_dn ? achl_dn : "none",
                                    sizeof "(objectClass=*)" - 1, ied_chs_ascii_850, "(objectClass=*)",
                                    sizeof "isSingleValued" - 1, ied_chs_ascii_850, "IsSingleValued",
                                    this->ads_ldap_entry ? this->ads_ldap_entry->imc_search_buf_size : 0, 
                                    this->ads_ldap_entry ? this->ads_ldap_entry->imc_timeout_search : 0);

     // build the asn.1-formatted search request...
     if (this->ds_asn1.m_printf( "{it{seeiib",
                                 this->ds_ldapreq.imc_msgid /*i*/,
                                 this->ds_ldapreq.imc_req /*t*/,
                                 achl_dn, iml_len_dn, int(this->ds_RootDSE.ads_schemacontext->iec_chs_val) /*s*/,
                                 int(ied_sear_baseobject) /*e*/,
                                 LDAP_DEREF_NEVER /*e*/,
                                 this->ads_ldap_entry->imc_search_buf_size /*i*/,
                                 this->ads_ldap_entry->imc_timeout_search /*i*/,
                                 FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
     { // error; we can't execute the ldap-search!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
       return ied_ldap_failure;
     }

     // now we set the filter(s) in asn.1-format...
     if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) != LASN1_SUCCESS)
     { // error, we can't set a valid filter combination!
       this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_lookup_err );
       return ied_ldap_failure;
     }
     // now we set the asn1-attributelist...
     if (this->ds_asn1.m_printf( "{C}}}", "isSingleValued", sizeof "isSingleValued" - 1, int(ied_chs_utf_8) /*C*/) == LASN1_ERROR)
     { // error, we can't set a valid attribute combination!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
       return ied_ldap_failure;
     }

     // send the message...
     this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
     this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
     // statistics...
     ++this->ads_ldap_entry->imc_send_packet;

     // SSL or non SSL???
     iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_send_err /* apicode */ );
     if (iml_rc != ied_ldap_success)
       return iml_rc;

     // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
     do
     {  // enable receiving...
        this->ads_ldap_control->bo_recv_complete = FALSE;
        iml_rc = this->m_recv( ied_ldap_search_err /* apicode */ );
        if (iml_rc != ied_ldap_success)
          return iml_rc;
        // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
        this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

        if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
        { // @todo: error message to event viewer or something else...
          this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
          return ied_ldap_failure;
        }

        switch (ds_asn1.im_op)
        {
          case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
              bol_found = TRUE;
              iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc );

              if (iml_rc == ied_ldap_success)
              { // test for 'single-valued'...
                if ((*aadsl_attr_desc)->adsc_attr->dsc_val.imc_len_val)
                { if (!m_hl_memicmp( (char *)(*aadsl_attr_desc)->adsc_attr->dsc_val.ac_val, (void *)"TRUE", sizeof "TRUE" - 1))
                    *aiep_attrtype = ied_ldap_attr_single;
                  else
                  { if (!m_hl_memicmp( (char *)(*aadsl_attr_desc)->adsc_attr->dsc_val.ac_val, (void *)"FALSE", sizeof "FALSE" - 1))
                      *aiep_attrtype = ied_ldap_attr_multi;
                  }
                }
              }
              break;
          case LDAP_RESP_SEARCH_DONE:
              if (bol_found == FALSE)
              { // nothing found!!!
                this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
                return ied_ldap_failure;
              }
              break;
         case LDAP_RESP_SEARCH_REF:
         default:
              break;
        } // end of switch()
     } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   } // end of 'schemaNamingcontext' (MSAD)
   else
   { // nonMSAD: use the common context 'subschemaSubentry'...
     if (this->ds_RootDSE.ads_subschemaentry)
     { // context is set, look for an already saved LDAP-schema with the same configuration data...
       dsd_ldap_schema *adsl_schema (dsd_ldap::ads_schema_anc);
       while (adsl_schema)
       { // compare configuration addresses
         if (this->ads_ldap_group == adsl_schema->ads_ldap_group &&
             this->ads_ldap_entry == adsl_schema->ads_ldap_entry)
         { // save schema for later use
           this->ads_ldap_schema = adsl_schema;
           break;
         }
         // next in chain
         adsl_schema = adsl_schema->ads_next;
       } // while()

       // did we found a schema?
       if (this->ads_ldap_schema == NULL)
       { // no, we have ask the ldap server...
         LDAPREQ_SEARCH(this->ds_ldapreq)

         // trace message LDAP0075T
         if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
           this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 75, this->im_sess_no, m_get_epoch_ms(),
                                        &this->ds_conn, this->ads_ldap_entry,
                                        "IsSingleValued Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\" Max-Size=%i Max-Time=%i",
                                        this->ds_ldap_trace.m_translate( (int)ied_sear_baseobject, dsd_trace::S_SEARCH_SCOPE ),
                                        this->ds_RootDSE.ads_subschemaentry->ac_val ? this->ds_RootDSE.ads_subschemaentry->imc_len_val : sizeof "none" - 1,
                                        this->ds_RootDSE.ads_subschemaentry->ac_val ? this->ds_RootDSE.ads_subschemaentry->iec_chs_val : ied_chs_ascii_850,
                                        this->ds_RootDSE.ads_subschemaentry->ac_val ? this->ds_RootDSE.ads_subschemaentry->ac_val : "none",
                                        sizeof "(objectClass=*)" - 1, ied_chs_ascii_850, "(objectClass=*)",
                                        sizeof "attributeTypes" - 1, ied_chs_ascii_850, "attributeTypes",
                                        0, 
                                        this->ads_ldap_entry ? this->ads_ldap_entry->imc_timeout_search : 0);


         // build the asn.1-formatted search request...
         if (this->ds_asn1.m_printf( "{it{seeiib",
                                     this->ds_ldapreq.imc_msgid /*i*/,
                                     this->ds_ldapreq.imc_req /*t*/,
                                     this->ds_RootDSE.ads_subschemaentry->ac_val,
                                     this->ds_RootDSE.ads_subschemaentry->imc_len_val,
                                     int(this->ds_RootDSE.ads_subschemaentry->iec_chs_val) /*s*/,
                                     int(ied_sear_baseobject) /*e*/,
                                     LDAP_DEREF_NEVER /*e*/,
                                     0 /*i*/,  // no buffer limitation, don't use 'this->ads_ldap_entry->imc_search_buf_size'!!!
                                     this->ads_ldap_entry->imc_timeout_search /*i*/,
                                     FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
         { // error; we can't execute the ldap-search!
           this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
           return ied_ldap_failure;
         }

         // now we set the filter(s) in asn.1-format...
         if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) != LASN1_SUCCESS)
         { // error, we can't set a valid filter combination!
           this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_lookup_err );
           return ied_ldap_failure;
         }
         // now we set the asn1-attributelist...
         if (this->ds_asn1.m_printf( "{C}}}", "attributeTypes", sizeof "attributeTypes" - 1, int(ied_chs_utf_8) /*C*/) == LASN1_ERROR)
         { // error, we can't set a valid attribute combination!
           this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
           return ied_ldap_failure;
         }

         // send the message...
         this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
         this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
         // statistics...
         ++this->ads_ldap_entry->imc_send_packet;

         // SSL or non SSL???
         iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_send_err /* apicode */ );
         if (iml_rc != ied_ldap_success)
           return iml_rc;

         // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
         do
         {  // enable receiving...
            this->ads_ldap_control->bo_recv_complete = FALSE;
            iml_rc = this->m_recv( ied_ldap_search_err /* apicode */ );
            if (iml_rc != ied_ldap_success)
              return iml_rc;
            // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
            this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

            if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
            { // @todo: error message to event viewer or something else...
              this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
              return ied_ldap_failure;
            }

            switch (ds_asn1.im_op)
            {
              case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
                  bol_found = TRUE;
                  iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc );

                  if (iml_rc == ied_ldap_success && (*aadsl_attr_desc)->adsc_attr)
                  { // 'partialAttribute'-list found, search for 'single-valued' attributes...
                    // example:
                    // "( 1.3.6.1.4.1.6275.3 NAME 'hobte' DESC 'HOB EA Terminal Emulation Settings' SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 SINGLE-VALUE ... )"
#if SM_BUGFIX_20140804
                    dsd_ldap::ds_cs_ldap.m_enter();
#endif
				    this->ads_ldap_schema = (class dsd_ldap_schema *)m_aux_stor_alloc( &dsd_ldap::ads_hl_stor_glob, sizeof(class dsd_ldap_schema) );
#if SM_BUGFIX_20140804
                    dsd_ldap::ds_cs_ldap.m_leave();
#endif
				    this->ads_ldap_schema->m_init( this->ads_ldap_group, this->ads_ldap_entry );


                    char *achl_1, *achl_2, *achl_3, *achl_end;
                    BOOL  bol_next;

                    // start with the first value
                    struct dsd_ldap_val *adsl_val_1 = &(*aadsl_attr_desc)->adsc_attr->dsc_val;

                    do // step through the value list...
                    {  if (adsl_val_1->imc_len_val)
                       { // the values are utf-8 formatted
                         achl_1   = adsl_val_1->ac_val;               // string begin address
                         achl_end = achl_1 + adsl_val_1->imc_len_val; // string end address
                         bol_next = FALSE;                            // TRUE: the current string is tested, take the next one

                         do // step through the value string...
                         {  // 1. search for "NAME '"...
                            achl_1 = (char *)memchr( (void *)achl_1, int('N'), size_t(achl_end - achl_1) );
                            if (achl_1)
                            { // 'N' found, now check the rest...
                              if (sizeof "NAME" - 1 <= achl_end - achl_1 &&
                                  !m_hl_memicmp( (void *)achl_1, (void *)"NAME ", sizeof "NAME " - 1 ))
                              { // "NAME '" found!
                                achl_1 += sizeof "NAME " - 1;  // this marks the begin of the attribute name

                                // do we have the attribute-name itself or a alias list?
                                if (*achl_1 == '\'')
                                  achl_1++;                      // begin address of the name
                                else
                                { if (*achl_1 == '(')
                                  { if (*(achl_1 + 1) == ' ')    // begin address of the primary name
                                      achl_1 += sizeof "( \'" - 1;
                                    else
                                      achl_1 += sizeof "(\'" - 1;
                                  }
                                }

                                // search the end of the attribute name...
                                achl_2  = (char *)memchr( (void *)achl_1, int('\''), size_t(achl_end - achl_1) );
                                if (achl_2 && *(achl_2 + 1) == ' ')
                                { // achl_1 and achl_2 are the begin and end address of the attribute name
                                  achl_3 = achl_2 + 2;   // the rest is done from here (single- or multivalued-test)

                                  do // search for "single-value" (if not found the attribute is multi valued!)
                                  {  achl_3 = (char *)memchr( (void *)achl_3, int('S'), size_t(achl_end - achl_3) );
                                     if (achl_3)
                                     { // test for "SINGLE-VALUE"...
                                       if (sizeof "SINGLE-VALUE" - 1 <= achl_end - achl_3 &&
                                           !m_hl_memicmp( (void *)achl_3, (void *)"SINGLE-VALUE", sizeof "SINGLE-VALUE" - 1 ))
                                       { // insert!
                                         if (this->ads_ldap_schema->m_htree_avl_insert( achl_1, int(achl_2 - achl_1),
                                                                                        ied_ldap_attr_single ) == FALSE &&
                                             this->ads_ldap_schema->im_avl_status != dsd_ldap_schema::ALREADY_INSERTED)
                                         { // error; we can't use any schema!
                                           this->ds_ldap_error.m_set_error( ied_ldap_undef_attr_type, ied_ldap_lookup_err );
                                           return ied_ldap_failure;
                                         }
                                         bol_next = TRUE;   // attribute inserted, test next...
                                       } // 'single-value'-property found!
                                       else
                                         // continue search...
                                         achl_3++;
                                     } // 'S' found
                                     else
                                     { // string end reached, insert attribute with 'multi-valued'-property
                                       if (this->ads_ldap_schema->m_htree_avl_insert( achl_1, int(achl_2 - achl_1),
                                                                                      ied_ldap_attr_multi ) == FALSE &&
                                           this->ads_ldap_schema->im_avl_status != dsd_ldap_schema::ALREADY_INSERTED)
                                       { // error; we can't use any schema!
                                         this->ds_ldap_error.m_set_error( ied_ldap_undef_attr_type, ied_ldap_lookup_err );
                                         return ied_ldap_failure;
                                       }
                                       bol_next = TRUE;     // test next...
                                     }
                                  } while (bol_next == FALSE); // test for "single- or multivalued"
                                }
                              }
                            }
                            else
                              bol_next = TRUE;

                         } while (bol_next == FALSE);  // test for the 'singlevalued'-property of the current attribute
                       } // valid value

                       // step to the next value...
                       adsl_val_1 = adsl_val_1->adsc_next_val;

                    } while (adsl_val_1); // step through the value list...
                  } // entry found

                  break;
              case LDAP_RESP_SEARCH_DONE:
                  if (bol_found == FALSE)
                  { // nothing found!!!
                    this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
                    return ied_ldap_failure;
                  }
                  break;
              case LDAP_RESP_SEARCH_REF:
              default:
                  break;
            } // end of switch()
         } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

       } // end of schema allocation
     } // end of 'subschema attribute list'


     // now try to find out, if our atribute is 'single-valued'...
     if (this->ads_ldap_schema)
     {
       if (this->ads_ldap_schema->m_htree_avl_search( adsp_ldap_attr->ac_attr, iml_len_attr, aiep_attrtype ) == FALSE &&
           this->ads_ldap_schema->im_avl_status == dsd_ldap_schema::NOT_FOUND)
       { // error; we can't use any schema!
         this->ds_ldap_error.m_set_error( ied_ldap_undef_attr_type, ied_ldap_lookup_err );
         return ied_ldap_failure;
       }
     }
     else
     { // error; we can't use any schema!
       this->ds_ldap_error.m_set_error( ied_ldap_undef_attr_type, ied_ldap_lookup_err );
       return ied_ldap_failure;
     }
   } // end 'subschemaSubentry' (others)

   return ied_ldap_success;

} // dsd_ldap::m_aux_is_singlevalued()


/**
 * Private class function:  dsd_ldap::m_aux_add()
 *
 * Initiates a ldap add operation. Look for a further description at m_ldap_add().
 *
 * @param[in]  strp_dn      dn of the attribute(s) to add (utf-8)
 * @param[in]  imp_len_dn   dn length
 * @param[in]  iep_chs_dn   dn character set
 * @param[in]  adsp_attr    list of all attribute(s) to add
 *
 * @return     error        (\b ied_ldap_failure),
 *             successful   (\b ied_ldap_success) or
 *             send blocked (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_add( char *strp_dn, int imp_len_dn, enum ied_charset iep_chs_dn, struct dsd_ldap_attr *adsp_attr )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   struct dsd_ldap_val  *adsl_val;
   struct dsd_ldap_val  *adsl_attr_vals_t (NULL), *adsl_attr_vals (NULL);
   struct dsd_ldap_attr *adsl_attr (adsp_attr);

   // build add-request...
   LDAPREQ_ADD(this->ds_ldapreq)

   // build the asn.1-formatted add request...
   if (this->ds_asn1.m_printf( "{it{s{",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               LDAP_REQ_ADD /*t*/,
                               strp_dn, imp_len_dn, int(iep_chs_dn) /*s*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_add_err );
     return ied_ldap_failure;
   }

   // set a sequence of attributes and the values to change
   while (adsl_attr)
   { // set the value(s)...
     adsl_attr_vals = NULL;
     adsl_val = &adsl_attr->dsc_val;
     while (adsl_val)
     { // set a value...
       // build 'v'-structure for 'm_printf()'
       if (adsl_attr_vals == NULL)
       {
         adsl_attr_vals = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_val) );
         memset((void *)adsl_attr_vals, int(0), sizeof(struct dsd_ldap_val));

         adsl_attr_vals_t = adsl_attr_vals;
       }
       else
       {
         adsl_attr_vals_t->adsc_next_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_val) );
         memset((void *)adsl_attr_vals_t->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

         adsl_attr_vals_t = adsl_attr_vals_t->adsc_next_val;
       }

       adsl_attr_vals_t->imc_len_val   = adsl_val->imc_len_val;
       adsl_attr_vals_t->ac_val        = adsl_val->ac_val;
       adsl_attr_vals_t->iec_chs_val   = adsl_val->iec_chs_val;
       // @todo  adsl_attr_vals_t->adsc_next_val = NULL;

       // step to the next value...
       adsl_val = adsl_val->adsc_next_val;
     } // while (value(s))

     if (this->ds_asn1.m_printf( "{s[v]}",
                                 adsl_attr->ac_attr, adsl_attr->imc_len_attr, int(adsl_attr->iec_chs_attr) /*s*/,
                                 adsl_attr_vals /*v*/ ) == LASN1_ERROR)
     { // error; we can't execute this ldap-add!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_add_err );
       return ied_ldap_failure;
     }
     adsl_attr = adsl_attr->adsc_next_attr;
   } // while (attributes)

   // end the asn.1-request structure...
   if (this->ds_asn1.m_printf( "}}}" ) == LASN1_ERROR)
   { // error; we can't execute this ldap-add!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_add_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_write;
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_add_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for add response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_add_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (ADD-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_add_err );
     return ied_ldap_failure;
   }

   return ied_ldap_success;

} // dsd_ldap_aux::m_aux_add()


/**
 * Private class function:  dsd_ldap::m_aux_deletetree()
 *
 * Initiates a ldap delete operation on non leaf nodes. Look for a further description at m_ldap_delete().
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error        (\b ied_ldap_failure),
 *                 successful   (\b ied_ldap_success) or
 *                 send blocked (\b ied_ldap_send_blocked)...
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 *
 *
 * Example "Delete of T22 and all sub-nodes":

             T1
             |
     -----------------
     |               |
    T21             T22 (x)
                     |
     ---------------------------------
     |               |               |
    T31 (x)         T32 (x)         T33 (x)
                     |               |
               -------------         |
               |           |         |
              T41 (x)     T42 (x)   T43 (x)
                           |         |
                          T51 (x)   T52 (x)


1. Search child-entries (single level, T22)

   T22->adsc_parent = NULL (starting point of delete)
   T22->adsc_next   = NULL (the parent node has no neighbor nodes)
   T22->adsc_child  = T31
                      T31->adsc_parent = T22
                      T31->adsc_child  = ???
                      T31->adsc_next   = T32
                      |                  T32->adsc_parent = T22
                      |                  T32->adsc_child  = ???
                      |                  T32->adsc_next   = T33
                      |                  |                  T33->adsc_parent = T22
                      |                  |                  T33->adsc_child  = ???
                      |                  |                  T33->adsc_next   = NULL
                      |                  |                  |
2.1. Search child-entries (single level, T31)               |
                      |                  |                  |
                      T31->adsc_child = NULL  (can be deleted now) --> T22->adsc_child = T31->adsc_next = T32
                                         |                  |
2.2. Search child-entries (single level, T32)               |
                                         |                  |
                                         T32->adsc_child = T41
                                                           T41->adsc_parent = T32
                                                           T41->adsc_child  = ???
                                                           T41->adsc_next   = T42
                                                            |                 T42->adsc_parent = T32
                                                            |                 T42->adsc_child  = ???
                                                            |                 T42->adsc_next   = NULL
                                                            |
2.3. Search child-entries (single level, T33)               |
                                                            |
                                                            T33->adsc_child = T43
                                                                              T43->adsc_parent = T33
                                                                              T43->adsc_child  = ???
                                                                              T43->adsc_next   = NULL

3. In the following steps we have to search for childes and we can delete each node without ones...

 */
int dsd_ldap::m_aux_deletetree( struct dsd_co_ldap_1 *adsp_co_ldap )
{

   // trace message LDAP0057T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 57, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Delete Tree (nonLeaf) DN=\"%.*(.*)s\" ",
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn? adsp_co_ldap->ac_dn : "none" );

   // is the deletetree-control supported?
#ifdef HL_DEBUG
   this->bo_deltree = FALSE;  //  ignore the delete-control OID for debugging purposes
#endif

   if (this->bo_deltree)
   { // 'deltree'-control is supported!
     // build delete-request...
     LDAPREQ_DELETE(this->ds_ldapreq)
     // initiate ASN.1 class...
     this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
     // initialize receive buffer storage management
     this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

     // build the asn.1-formatted delete request (draft-armijo-ldap-treedelete-03.txt)...
     if (this->ds_asn1.m_printf( "{itst{{o}}}",
                                 this->ds_ldapreq.imc_msgid /*i*/,
                                 LDAP_REQ_DELETE /*t*/,
                                 adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/,
                                 LASN1_CONTROLS /*t*/,
                                 OID_DELTREE, sizeof OID_DELTREE - 1 /*o*/ ) == LASN1_ERROR)
     { // error; we can't execute the ldap-delete!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_delete_err );
       return ied_ldap_failure;
     }

     // send the message...
     this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
     this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
     // statistics...
     ++this->ads_ldap_entry->imc_count_write;
     ++this->ads_ldap_entry->imc_send_packet;

     // SSL or non SSL???
     int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_delete_err /* apicode */ );
     if (iml_rc != ied_ldap_success)
       return iml_rc;

     // wait for delete response...
     this->ads_ldap_control->bo_recv_complete = FALSE;

     iml_rc = this->m_recv( ied_ldap_delete_err /* apicode */ );
     if (iml_rc != ied_ldap_success)
       return iml_rc;

     // parse LDAP result (DELETE-response)...
     this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

     if (this->m_aux_parse_resp(&this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq) != ied_ldap_success)
     { // @todo: error message to event viewer or something else...
       this->ds_ldap_error.m_set_apicode( ied_ldap_delete_err );
       return ied_ldap_failure;
     }

   } // 'deltree'-control
   else
   {
     // if the control-oid of 'deltree' isn't supported, we have to count all subnodes...
     struct dsd_node  *adsl_node_anc ((struct dsd_node *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, sizeof(struct dsd_node)));
                       adsl_node_anc->adsc_parent = NULL;   // starting point of delete
                       adsl_node_anc->adsc_next   = NULL;   // the parent node has no neighbour nodes
                       adsl_node_anc->ac_dn       = adsp_co_ldap->ac_dn;
                       adsl_node_anc->imc_len_dn  = adsp_co_ldap->imc_len_dn;
                       adsl_node_anc->adsc_child  = NULL;

     struct dsd_node  *adsl_node_1  (adsl_node_anc);
     struct dsd_node  *adsl_node_p  (NULL/*adsl_node_1*/);
     struct dsd_node **aadsl_child_1;
                       aadsl_child_1 = &adsl_node_anc->adsc_child;

     // set ldap-search or ldap-delete request
     LDAP_REQ_STRUC(dsl_co_ldap_sear)
     dsl_co_ldap_sear.iec_co_ldap      = ied_co_ldap_search;
     dsl_co_ldap_sear.iec_chs_dn       = ied_chs_utf_8;
     dsl_co_ldap_sear.iec_sear_scope   = ied_sear_onelevel;
     dsl_co_ldap_sear.ac_filter        = "(objectClass=*)";
     dsl_co_ldap_sear.imc_len_filter   = sizeof "(objectClass=*)" - 1;
     dsl_co_ldap_sear.iec_chs_filter   = ied_chs_utf_8;
     dsl_co_ldap_sear.ac_attrlist      = "objectClass";
     dsl_co_ldap_sear.imc_len_attrlist = sizeof "objectClass" - 1;
     dsl_co_ldap_sear.iec_chs_attrlist = ied_chs_utf_8;

     LDAP_REQ_STRUC(dsl_co_ldap_del)
     dsl_co_ldap_del.iec_co_ldap = ied_co_ldap_delete;
     dsl_co_ldap_del.iec_chs_dn  = ied_chs_utf_8;

     struct dsd_ldap_attr_desc *adsl_attr_desc  (NULL);
DELTREE_SEARCH:
     dsl_co_ldap_sear.ac_dn          = adsl_node_1->ac_dn;
     dsl_co_ldap_sear.imc_len_dn     = adsl_node_1->imc_len_dn;
     dsl_co_ldap_sear.adsc_attr_desc = NULL;


     if (this->m_ldap_search(&dsl_co_ldap_sear, TRUE/*attr only*/) != ied_ldap_success)
     { // error; we can't execute the ldap-search! The reason code was set by m_ldap_search()
       // if we get the result code "ied_ldap_no_results", there are no more child-nodes existing.
       if (this->ds_ldap_error.m_get_error() == ied_ldap_no_results)
       { // delete this node
         dsl_co_ldap_del.ac_dn      = dsl_co_ldap_sear.ac_dn;
         dsl_co_ldap_del.imc_len_dn = dsl_co_ldap_sear.imc_len_dn;

         if (m_ldap_delete(&dsl_co_ldap_del) != ied_ldap_success)
         { // error; we can't execute the ldap-delete! The reason code was set by m_ldap_delete()
           // cannot delete node, so we should not continue deleting!
           return ied_ldap_failure;
         }

         // remove entry...
         struct dsd_node  *adsl_node_3 (adsl_node_1->adsc_parent->adsc_child);
         struct dsd_node  *adsl_node_4 (adsl_node_1->adsc_parent->adsc_child->adsc_next);
         struct dsd_node **aadsl_node_1;
                           aadsl_node_1 = &adsl_node_1->adsc_parent->adsc_child;

         // search child entry...
         while (adsl_node_3)
         {  // deleted child entry found?
            if (adsl_node_3 == adsl_node_1)
            { // remove it from chain...
              *aadsl_node_1 = adsl_node_4;
              break;
            }
            // try next child
            aadsl_node_1 = &adsl_node_3;
            adsl_node_4 = adsl_node_3;
            adsl_node_3 = adsl_node_3->adsc_next;
         } // while()

         // next child in chain
         adsl_node_1 = adsl_node_1->adsc_next;
         goto DELTREE_CONTINUE;
       }
       else
         // we have get another error, return to caller
         return ied_ldap_failure;
     }
     else
     { // save dn of the child-nodes
       adsl_attr_desc = dsl_co_ldap_sear.adsc_attr_desc;

       if (adsl_attr_desc)
       { // save child entries...
         while (adsl_attr_desc)
         {  // save dn of the sub-node...
            *aadsl_child_1 = ((struct dsd_node *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, sizeof(struct dsd_node)));
            (*aadsl_child_1)->ac_dn       = adsl_attr_desc->ac_dn;
            (*aadsl_child_1)->imc_len_dn  = adsl_attr_desc->imc_len_dn;
            (*aadsl_child_1)->adsc_parent = adsl_node_1;  // set parent node of this child node
            (*aadsl_child_1)->adsc_child  = NULL;
            (*aadsl_child_1)->adsc_next   = NULL;

            aadsl_child_1  = &(*aadsl_child_1)->adsc_next;
            adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;
         } // while ldap-entries...


         adsl_node_p = adsl_node_1;              // save old parent
         adsl_node_1 = adsl_node_p->adsc_child;  // set child-chain

         // test each child entry...
DELTREE_CONTINUE:
         if (adsl_node_1)
         { // set child as the new parent
           aadsl_child_1 = &adsl_node_1->adsc_child;
         }
         else
         { // no more child entries, we have to step back one level...
           adsl_node_1 = adsl_node_p;
           adsl_node_p = adsl_node_p->adsc_parent;

           // if we have no more parents, we reached the 'root'-element of
           // the delete-tree
           if (adsl_node_p)
             aadsl_child_1 = &adsl_node_1->adsc_child;
           else
           { // delete the 'root'-node
             dsl_co_ldap_del.ac_dn      = adsl_node_1->ac_dn;
             dsl_co_ldap_del.imc_len_dn = adsl_node_1->imc_len_dn;

             return m_ldap_delete(&dsl_co_ldap_del);
           }
         }

         goto DELTREE_SEARCH;
       } // child entries found
     } // search success
   } // subnode counting

   return ied_ldap_success;

} // dsd_ldap_aux::m_aux_deletetree()


/**
 * Private class function:  dsd_ldap::m_aux_modify()
 *
 * Initiates a ldap modify operation. Look for a further
 * description at m_ldap_modify().
 *
 * @param[in]  strp_dn      dn of the attribute(s) to modify (utf-8)
 * @param[in]  imp_len_dn   dn length
 * @param[in]  iep_chs_dn   dn character set
 * @param[in]  adsp_attr    list of all attribute(s) to modify
 * @param[in]  iep_mod      ldap modify mode (ADD, REPLACE or DELETE)
 *
 * @return     error        (\b ied_ldap_failure),
 *             successful   (\b ied_ldap_success) or
 *             send blocked (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_modify( char *strp_dn, int imp_len_dn, enum ied_charset iep_chs_dn,
                            struct dsd_ldap_attr    *adsp_attr,
                            enum   ied_ldap_mod_def  iep_mod )
{
   // build modify-request...
   LDAPREQ_MODIFY(this->ds_ldapreq)
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // build the asn.1-formatted modify request...
   if (this->ds_asn1.m_printf( "{it{s{",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               strp_dn, imp_len_dn, int(iep_chs_dn) /*s*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_err );
     return ied_ldap_failure;
   }

   // add, replace or delete the specified value(s) in the list
   if (this->ds_asn1.m_printf( "{e{s[v]}}",
                               iep_mod, /*e*/
                               adsp_attr->ac_attr, adsp_attr->imc_len_attr, int(adsp_attr->iec_chs_attr) /*s*/,
                               &adsp_attr->dsc_val /*v*/ ) == LASN1_ERROR)
   { // error; we can't execute this ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_err );
     return ied_ldap_failure;
   }

   // end the asn.1-request structure...
   if (this->ds_asn1.m_printf( "}}}" ) == LASN1_ERROR)
   { // error; we can't execute this ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_write;
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_modify_err /* apicode */ );
   if (iml_rc != ied_ldap_success && iml_rc != ied_ldap_send_blocked)
     return iml_rc;

   // wait for modify response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_modify_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (MODIFY-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_modify_err );

     if (iml_rc == ied_ldap_attr_or_val_exist)
       return iml_rc;

       return ied_ldap_failure;
   }

   return ied_ldap_success;

} // dsd_ldap_aux::m_aux_modify()


/**
 * Private class function:  dsd_ldap::m_aux_msad_modify_pw()
 *
 * Initiates a special msad ldap modify operation. Look for a further
 * description at m_ldap_modify().
 *
 * @param[in]  strp_userdn      user-dn
 * @param[in]  imp_len_userdn   user-dn length
 * @param[in]  iep_chs_userdn   user-dn character set
 * @param[in]  adsp_pw_old      old password to delete
 * @param[in]  adsp_pw_new      new password to add
 *
 * @return     error        (\b ied_ldap_failure),
 *             successful   (\b ied_ldap_success) or
 *             send blocked (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_aux_msad_modify_pw( char *strp_userdn, int imp_len_userdn, enum ied_charset iep_chs_userdn,
                                    struct dsd_ldap_attr    *adsp_pw_old,
                                    struct dsd_ldap_attr    *adsp_pw_new )
{
   // build modify-request...
   LDAPREQ_MODIFY(this->ds_ldapreq)
   // initialize asn.1-storage manager...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // build the asn.1-formatted modify request...
   if (this->ds_asn1.m_printf( "{it{s{",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               strp_userdn, imp_len_userdn, int(iep_chs_userdn) /*s*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_err );
     return ied_ldap_failure;
   }


   // delete the attribute value of 'unicodePwd' and add the new one...
   if (this->ds_asn1.m_printf( "{e{s[v]}}{e{s[v]}}}}}",
                               ied_ldap_mod_delete, /*e*/
                               adsp_pw_old->ac_attr, adsp_pw_old->imc_len_attr, int(adsp_pw_old->iec_chs_attr) /*s*/,
                               &adsp_pw_old->dsc_val, /*v*/
                               ied_ldap_mod_add, /*e*/
                               adsp_pw_new->ac_attr, adsp_pw_new->imc_len_attr, int(adsp_pw_new->iec_chs_attr) /*s*/,
                               &adsp_pw_new->dsc_val /*v*/ ) == LASN1_ERROR)
   { // error; we can't execute this ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_write;
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_modify_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for modify response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_modify_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (MODIFY-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_modify_err );

     if (iml_rc == ied_ldap_attr_or_val_exist)
       return iml_rc;

     return ied_ldap_failure;
   }

   return ied_ldap_success;

} // dsd_ldap_aux::m_aux_modify_msad_pw()


/**
 * Private class function:  dsd_ldap::m_ldap_search()
 *
 * Initiates a ldap search operation. We use the 'pageResults'-control, if supported.
 *
 *      ASN.1:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   LDAPDN,
 *                                                   scope        ENUMERATED { baseObject   (0),
 *                                                                             singleLevel  (1),
 *                                                                             wholeSubtree (2) },
 *                                                   derefAliases ENUMERATED { neverDerefAliases   (0),
 *                                                                             derefInSearching    (1),
 *                                                                             derefFindingBaseObj (2),
 *                                                                             derefAlways         (3) },
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    BOOLEAN,
 *                                                   filter       Filter,
 *                                                   attributes   AttributeSelection }
 *
 *                              Filter ::= CHOICE { and             [0]  SET SIZE (1..MAX) OF filter Filter,
 *                                                  or              [1]  SET SIZE (1..MAX) OF filter Filter,
 *                                                  not             [2]  Filter,
 *                                                  equalityMatch   [3]  AttributeValueAssertion,
 *                                                  substrings      [4]  SubstringFilter,
 *                                                  greaterOrEqual  [5]  AttributeValueAssertion,
 *                                                  lessOrEqual     [6]  AttributeValueAssertion,
 *                                                  present         [7]  AttributeDescription,
 *                                                  approxMatch     [8]  AttributeValueAssertion,
 *                                                  extensibleMatch [9]  MatchingRuleAssertion }
 *
 *                              AttributeSelection ::= SEQUENCE OF selector LDAPString
 *
 *                              AttributeValueAssertion ::= SEQUENCE { attributeDesc  AttributeDescription (LDAPString),
 *                                                                     assertionValue AssertionValue       (OCTET STRING) }
 *
 *                              SubstringFilter ::= SEQUENCE { type       AttributeDescription,
 *                                                             substrings SEQUENCE SIZE OF substring CHOICE { initial [0] AssertionValue,
 *                                                                                                            any     [1] AssertionValue,
 *                                                                                                            final   [2] AssertionValue }
 *                                                           }
 *
 *                              MatchingRuleAssertion ::= SEQUENCE { matchingRule [1]  MatchingRuleId (LDAPString) OPTIONAL,
 *                                                                   type         [2]  AttributeDescription        OPTIONAL,
 *                                                                   matchValue   [3]  AssertionValue,
 *                                                                   dnAttributes [4]  BOOLEAN
 *                                                                 }
 *
 *
 *                              pagedResultsControl ::= SEQUENCE { controlType     1.2.840.113556.1.4.319,
 *                                                                 criticality     BOOLEAN DEFAULT FALSE,
 *                                                                 controlValue    searchControlValue
 *                                                               }
 *
 * optional:                    searchControlValue ::= SEQUENCE { size            INTEGER (0..maxInt),
 *                                                                                -- requested page size from client
 *                                                                                -- result set size estimate from server
 *                                                                cookie          OCTET STRING
 *                                                              }
 *
 *
 * @param[in,out]  adsp_co_ldap    request structure
 * @param[in]      bop_attr_only   return attributes only, if TRUE
 * @param[in,out]  aachp_dn        pointer to the dn-string address
 * @param[in,out]  aimp_len_dn     pointer to the dn-string length address
 * @param[in,out]  aiep_chs_dn     pointer to the dn-string character set
 *
 * @return    error        (\b ied_ldap_failure),
 *            successful   (\b ied_ldap_success) or
 *            send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ldap_search( struct dsd_co_ldap_1 *adsp_co_ldap, BOOL bop_attr_only,
                             char **aachp_dn, int *aimp_len_dn, enum ied_charset *aiep_chs_dn )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search
#define REALM      adsp_co_ldap->dsc_add_dn

   BOOL   bol_found;
   int    iml_rc, iml_rc2;
   int    iml_1, iml_2;
   struct dsd_ldap_attr_desc **aadsl_attr_desc;
   struct dsd_unicode_string  dsl_dn = {NULL, 0, ied_chs_utf_8};
   struct dsd_ldap_val *adsl_namingcontexts (NULL);


   // clear references...
   if (this->ads_referral)
   {
     struct dsd_referral *adsl_ref (this->ads_referral);
     struct dsd_referral *adsl_ref_next;

     while (adsl_ref)
     {
        adsl_ref_next = adsl_ref->adsc_next;
        FREE_MEM( this->ads_hl_stor_per, adsl_ref )
        adsl_ref = adsl_ref_next;
     }
     this->ads_referral = NULL;
   }


   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-search!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_search_err );
                                     return ied_ldap_no_bind;
                                   }

                                     BIND_WITH_DN()

      default:                     break;
   } // end of switch

   // trace message LDAP0040T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 40, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Search Scope=%s DN=\"%.*(.*)s\" Realm=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\" attr-only=%s Max-Size=%i Max-Time=%i",
                                  this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none",
                                  REALM.ac_str ? REALM.imc_len_str : sizeof "none" - 1,
                                  REALM.ac_str ? REALM.iec_chs_str : ied_chs_ascii_850,
                                  REALM.ac_str ? REALM.ac_str : "none",
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->imc_len_filter : sizeof "(objectClass=*)" - 1,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->iec_chs_filter : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->ac_filter : "(objectClass=*)",
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->imc_len_attrlist : sizeof "none" - 1,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->iec_chs_attrlist : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->ac_attrlist : "none",
                                  bop_attr_only ? "true" : "false",
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_search_buf_size : 0, 
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_timeout_search : 0);

   // normal LDAP search or search along the tree?
   if (adsp_co_ldap->iec_sear_scope == ied_sear_superlevel)
     return this->m_aux_search_tree( adsp_co_ldap );
   // normal LDAP search or search starting at namingcontexts?
   if (adsp_co_ldap->iec_sear_scope == ied_sear_root)
     return this->m_aux_search_root( adsp_co_ldap );

   // do we need the 'namingcontexts'?
   if (this->bo_RootDSE == FALSE && this->m_aux_search_RootDSE() != ied_ldap_success)
   {
     if (adsp_co_ldap->imc_len_dn == 0)
       // error; we can't execute the ldap-search!
       return ied_ldap_failure;
   }

   // ok, perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)

   // do we have any distinguished name as 'baseObject' ?
   if (adsp_co_ldap->iec_sear_scope == ied_sear_basedn)
   { // use <base-dn> (utf-8 format)...
     dsl_dn.imc_len_str = this->ads_ldap_entry->imc_len_base_dn;
     dsl_dn.ac_str      = this->ads_ldap_entry->achc_base_dn;
   }
   else
   { // use the internal dn or scan over the namingcontexts...
     if (REALM.ac_str && REALM.imc_len_str)
     { // calculate the realm length...
       iml_2 = 0;

       // should we convert the character set?
       if (REALM.iec_chs_str != ied_chs_utf_8)
       {
         iml_1 = m_len_vx_ucs( ied_chs_utf_8, &REALM );
         if (iml_1 == -1)
         { // error, invalid string format...
           this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
           return ied_ldap_failure;
         }
       }
       else
         iml_1 = (REALM.imc_len_str != -1) ? REALM.imc_len_str : (int)strnlen( (const char *)REALM.ac_str, D_LDAP_MAX_STRLEN );


       // use <base-dn> or parameter-dn
       if (adsp_co_ldap->ac_dn && adsp_co_ldap->imc_len_dn)
       { // use parameter-dn...
         // should we convert the character set?
         if (adsp_co_ldap->iec_chs_dn != ied_chs_utf_8)
         {
           iml_2 = m_len_vx_vx( ied_chs_utf_8, adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn );
           if (iml_2 == -1)
           { // error, invalid string format...
             this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
             return ied_ldap_failure;
           }
         }
         else
           iml_2 = (adsp_co_ldap->imc_len_dn != -1) ? adsp_co_ldap->imc_len_dn
                                                    : (int)strnlen( adsp_co_ldap->ac_dn, D_LDAP_MAX_STRLEN );
       }

       // add realms...
       dsl_dn.imc_len_str = iml_1 + 1/*','*/ + ((iml_2) ? iml_2 : this->ads_ldap_entry->imc_len_base_dn);
       dsl_dn.ac_str      = m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_dn.imc_len_str );

       (REALM.iec_chs_str != ied_chs_utf_8) ? (void *)m_cpy_vx_ucs( dsl_dn.ac_str, iml_1, ied_chs_utf_8, &REALM )
                                            : memcpy( dsl_dn.ac_str, (const void *)REALM.ac_str, iml_1 );
       *((char *)dsl_dn.ac_str + iml_1) = ',';

       if (iml_2)
         (adsp_co_ldap->iec_chs_dn != ied_chs_utf_8) ? (void *)m_cpy_vx_vx_fl( (char *)dsl_dn.ac_str + iml_1 + 1, iml_2, ied_chs_utf_8,
                                                                               (void *)adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn,
                                                                               D_CPYVXVX_FL_NOTAIL0 )
                                                     : memcpy( (char *)dsl_dn.ac_str + iml_1 + 1, (const void *)adsp_co_ldap->ac_dn, iml_2 );
       else
        memcpy( (char *)dsl_dn.ac_str + iml_1 + 1, (const void *)this->ads_ldap_entry->achc_base_dn, this->ads_ldap_entry->imc_len_base_dn );
     }
     else
     { if (adsp_co_ldap->imc_len_dn)
       { // yes, use the parameter dn...
         dsl_dn.iec_chs_str = adsp_co_ldap->iec_chs_dn;
         dsl_dn.imc_len_str = adsp_co_ldap->imc_len_dn;
         dsl_dn.ac_str      = adsp_co_ldap->ac_dn;
       }
       else
       { if (this->im_len_dn)
         { // use the last known dn!
           dsl_dn.imc_len_str = this->im_len_dn;
           dsl_dn.ac_str      = this->achr_dn;
         }
         else
         { // ok, last change -> take the 'namingcontexts'
           if (this->ds_RootDSE.ads_namingcontexts != NULL && this->ds_RootDSE.ads_namingcontexts->imc_len_val)
           { adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts; // set flag for later use
             dsl_dn.iec_chs_str = adsl_namingcontexts->iec_chs_val;     // always set to utf-8
             dsl_dn.imc_len_str = adsl_namingcontexts->imc_len_val;
             dsl_dn.ac_str      = adsl_namingcontexts->ac_val;
           }
           else
           { // in the environment of LDS and eDirectory (ticket 48497) we have to take <ROOT>
             dsl_dn.iec_chs_str = ied_chs_utf_8;
             dsl_dn.imc_len_str = 0;
             dsl_dn.ac_str      = (void *)"";

             // ignore the error so far!
             // error; we can't execute the ldap-search!
             // this->ds_ldap_error.m_set_error( ied_ldap_inv_dn_syntax, ied_ldap_search_err );
             // return ied_ldap_failure;
           }
         }
       }
     }
   }


   // initialize attribute description structure of the requester
   adsp_co_ldap->adsc_attr_desc = NULL;
   aadsl_attr_desc = &adsp_co_ldap->adsc_attr_desc;

SEARCH_REQUEST:
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // create valid LDAP message ID...
   this->ds_ldapreq.imc_msgid = this->m_get_msgid();
   // build the asn.1-formatted search request...
   if (this->ds_asn1.m_printf( "{it{Seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               &dsl_dn /*S*/,
                               int( (adsp_co_ldap->iec_sear_scope < ied_sear_superlevel)
                                    ? adsp_co_ldap->iec_sear_scope
                                    : ((adsp_co_ldap->iec_sear_scope == ied_sear_basedn) ? ied_sear_sublevel : ied_sear_baseobject)) /*e*/,
                               LDAP_DEREF_NEVER /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               bop_attr_only /*true: attributes only*//*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) in asn.1-format...
   if (adsp_co_ldap->imc_len_filter == 0)
     // default: IBM secure way LDAP and other implementations use this as default
     iml_rc = this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 );
   else
     // set filter parameter...
     iml_rc = this->ds_asn1.m_put_filter( (const char *)adsp_co_ldap->ac_filter, adsp_co_ldap->imc_len_filter, adsp_co_ldap->iec_chs_filter );

   // everything ok?
   if (iml_rc != LASN1_SUCCESS)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set asn1-attribute(s)...
   if (this->ds_asn1.m_printf( "{C}}",
                               adsp_co_ldap->ac_attrlist, adsp_co_ldap->imc_len_attrlist, int(adsp_co_ldap->iec_chs_attrlist) /*C*/) == LASN1_ERROR)
   { // error, we can't set a valid attribute combination!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // does the server support the 'pagedResultControl'-control?
   if (this->bo_page_results == TRUE)
   { // construct control
     int iml_rc ( this->ds_asn1.m_printf( "t{{obt{{is}}}}",
                                          LASN1_CONTROLS, /*t*/
                                          OID_PAGE_RESULTS, sizeof OID_PAGE_RESULTS - 1, /*o*/
                                          FALSE /*TRUE*/, /*b*/
                                          LASN1_OCTETSTRING, /*t*/
                                          D_LDAP_PAGE_SIZE, /*searchControlValue: i*/
                                          this->avo_cookie, this->im_cookie_len, ied_chs_utf_8 /*searchControlValue: s*/ ));
     // free cookie...
     if (this->avo_cookie)
       FREE_MEM( this->ads_hl_stor_per, this->avo_cookie )

     this->im_cookie_len = 0;
     this->avo_cookie = NULL;

     if (iml_rc == LASN1_ERROR)
     { // error; we can't build ldap-search with controls!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
       return ied_ldap_failure;
     }
   } // 'pagedResultControl'


   // finish the search request
   this->ds_asn1.m_printf( "}" );

   // send the message...
   bol_found = FALSE;
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL???
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc2 = this->m_recv( ied_ldap_search_err /* apicode */ );
      if (iml_rc2 != ied_ldap_success)
        return iml_rc2;
	  // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
        return ied_ldap_failure;
      }
      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             bol_found = TRUE;
             // find next free structure in the chain...
             while (*aadsl_attr_desc)
                  aadsl_attr_desc = &(*aadsl_attr_desc)->adsc_next_attr_desc;

             iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc, aachp_dn, aimp_len_dn, aiep_chs_dn );
             break;
        case LDAP_RESP_SEARCH_DONE:
             if (bol_found == FALSE)
             { if (adsl_namingcontexts == NULL)
               { // nothing found!!!
                 this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
                 return ied_ldap_failure;
               }

               // next 'namingcontext'...
               adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;

               if (adsl_namingcontexts && adsl_namingcontexts->imc_len_val)
               { dsl_dn.ac_str      = adsl_namingcontexts->ac_val;
                 dsl_dn.imc_len_str = adsl_namingcontexts->imc_len_val;
                 dsl_dn.iec_chs_str = adsl_namingcontexts->iec_chs_val;  // always set to utf-8

                 goto SEARCH_REQUEST;
               }
               else
               { // nothing found so far!
                 // new feature: try referrals...
                 if (this->ads_referral == NULL)
                 { // error, we don't have referrals
                   this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
                   return ied_ldap_failure;
                 }
#ifdef HOB_LDAP_REFERRAL
                 // use subdomains...
                 // trace message LDAP0031T
                 if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
                   this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 31, this->im_sess_no, m_get_epoch_ms(),
                                                &this->ds_conn, this->ads_ldap_entry,
                                                "Bind (Subdomain) Authentication=%s Userid=\"%.*(.*)s\"",
                                                this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_ldap_auth, dsd_trace::S_BIND_AUTH ),
                                                adsp_co_ldap->ac_userid ? adsp_co_ldap->imc_len_userid : sizeof "none" - 1,
                                                adsp_co_ldap->ac_userid ? adsp_co_ldap->iec_chs_userid : ied_chs_ascii_850,
                                                adsp_co_ldap->ac_userid ? adsp_co_ldap->ac_userid : "none" );

                 struct dsd_referral  *adsl_referral (this->ads_referral);

                 while (adsl_referral)
                 {
                    LDAP_REQ_STRUC(dsl_co_ldap);
                    memcpy( (void *)&dsl_co_ldap, (const void *)adsp_co_ldap, sizeof(struct dsd_co_ldap_1) );
                    
                    dsl_co_ldap.iec_co_ldap   = ied_co_ldap_bind;
                    dsl_co_ldap.iec_ldap_auth = ied_auth_user;


                    if (this->m_ref_check_subdomain( adsp_co_ldap, adsl_referral, this->ads_ldap_entry ) != ied_ldap_success)
                    { // create error messages for some error conditions!!!
                      // e.g. cannot connect -> try next
                      //      authentication error (wrong password) -> final error
                      iml_rc = ied_ldap_failure;
                    }
                    else
                    { // we have results!!!
                      iml_rc = ied_ldap_success;
                      break;
                    }

                    // check next...
                    adsl_referral = adsl_referral->adsc_next;
                 } // while()
                 // search subdomains
#endif // HOB_LP_REFERRAL
               } // test referrals
               // namingcontexts and referrals
             } // no entries found so far (bol_found == FALSE)
             else
             { // do we have more entries (rfc 2696, 'pagedResultsControl')?
               if (this->im_cookie_len && this->avo_cookie)
               { // next search...
                 goto SEARCH_REQUEST;
               }

             }

             break;

        case LDAP_RESP_SEARCH_REF:
             // save references, if not found any entry...
             // @under discussion
             // if (bol_found == FALSE)
             //   iml_rc = this->m_aux_search_result_ref();
             break;

        default:
             break;
      } // end of switch()

   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   return iml_rc;

#undef REALM
}; // dsd_ldap::m_ldap_search( dsd_co_ldap_1* )


#ifdef HOB_LDAP_REFERRAL
/**
 * Private class function:  dsd_ldap::m_ref_check_subdomain()
 *
 * Try to connect to the given subdomain.
 *
 * @param[in,out]  adsp_co_ldap     request structure
 * @param[in]      adsp_referral    referral
 * @param[in]      adsp_ldap_entry  ldap configuration
 *
 * @return    error        (\b ied_ldap_failure),
 *            successful   (\b ied_ldap_success) or
 *
 * Comment:
 * If the function returns any status other than 'ied_ldap_success', the error cannot be retrieved by 'ied_co_ldap_get_last_err'.
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ref_check_subdomain( struct dsd_co_ldap_1  *adsp_co_ldap,
                                     struct dsd_referral   *adsp_referral,
                                     struct dsd_ldap_entry *adsp_ldap_entry )
{
   int iml_errno (0);
   struct dsd_tcpsync_1  dsl_tcpsync_1;


   // valid parameters?
   if (adsp_referral == NULL || adsp_referral->dsc_ldap_url.imc_len_str == 0)
     return ied_ldap_param_inv;


   // try to connect to the subdomain-controller
   struct dsd_target_ineta_1 *adsl_server_ineta ( m_get_target_ineta( adsp_referral->dsc_ldap_url.ac_str,
                                                                      adsp_referral->dsc_ldap_url.imc_len_str,
                                                                      adsp_referral->dsc_ldap_url.iec_chs_str,
                                                                      &adsp_ldap_entry->dsc_bind_multih ) );
   if (adsl_server_ineta)
   { // we have a valid ldap ip-address
     if (m_tcpsync_connect( &iml_errno,
                            &dsl_tcpsync_1,
                            &adsp_ldap_entry->dsc_bind_multih,
                            adsl_server_ineta,
                            adsp_referral->imc_port ) == TRUE)
     { // connected, search subdomain...
       // 1. do authentication (bind)
       this->m_ref_bind_subdomain( &dsl_tcpsync_1, adsp_co_ldap );

       //this->m_aux_search_ref( &dsl_tcpsync );

       // close connection
       m_tcpsync_close( &iml_errno, &dsl_tcpsync_1 );

     } // connected

     // avoid memory leaks!
     free( adsl_server_ineta );

     // did we have success? --> return ied_ldap_success

   } // adsl_server_ineta



   return ied_ldap_success;

}; // dsd_ldap::m_ref_check_subdomain( struct dsd_co_ldap_1 *, struct dsd_referral  * )
#endif // HOB_LDAP_REFERRAL

/**
 * Private class function:  dsd_ldap::m_ldap_lookup()
 *
 * Test the validity of a given DN and returns the attributes requested by the caller. If no attribute
 * list is requested, only the DN is tested.
 *
 * @param[in,out]  adsp_co_ldap    request structure
 * @param[in]      bop_attr_only   returns the attribute only (without values)
 *
 * @return    error        (\b ied_ldap_failure),
 *            successful   (\b ied_ldap_success) or
 *            send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ldap_lookup(struct dsd_co_ldap_1 *adsp_co_ldap, BOOL bop_attr_only)
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   BOOL   bol_found (FALSE), bol_attrlist (TRUE);
   int    iml_rc;
   struct dsd_ldap_attr_desc **aadsl_attr_desc;

   struct dsd_unicode_string  dsl_attrlist;
                              dsl_attrlist.ac_str      = (void *)adsp_co_ldap->ac_attrlist;
                              dsl_attrlist.imc_len_str = adsp_co_ldap->imc_len_attrlist;
                              dsl_attrlist.iec_chs_str = adsp_co_ldap->iec_chs_attrlist;


   // do we have a distinguished name as 'baseObject' ?
   if (adsp_co_ldap->imc_len_dn == 0 || adsp_co_ldap->ac_dn == NULL)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_lookup_err );
     return ied_ldap_failure;
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // initialize attribute description structure of the requester
   adsp_co_ldap->adsc_attr_desc = NULL;
   aadsl_attr_desc = &adsp_co_ldap->adsc_attr_desc;

   // use either "objectClass" as the default value or the attrlist-parameter
   if (dsl_attrlist.ac_str == NULL || dsl_attrlist.imc_len_str == 0)
   { // use default attribute list (objectClass)
     dsl_attrlist.ac_str      = (void *)"objectClass";
     dsl_attrlist.imc_len_str = sizeof "objectClass" - 1;
     dsl_attrlist.iec_chs_str = ied_chs_utf_8;
     bol_attrlist = FALSE;
   }

   // create valid LDAP message ID...
   this->ds_ldapreq.imc_msgid = this->m_get_msgid();
   // build the asn.1-formatted search request...
   if (this->ds_asn1.m_printf( "{it{seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/,
                               int(ied_sear_baseobject) /*e*/,
                               LDAP_DEREF_ALWAYS /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               (bol_attrlist == FALSE || bop_attr_only == TRUE) ? TRUE/*attr only*/ : FALSE/*attr and value*/ /*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) and the attribute list in asn.1-format...
   if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) != LASN1_SUCCESS)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_lookup_err );
     return ied_ldap_failure;
   }

   // now we set the asn1-attributelist...
   if (this->ds_asn1.m_printf( "{C}}}",
                               dsl_attrlist.ac_str, dsl_attrlist.imc_len_str, int(dsl_attrlist.iec_chs_str) /*C*/) == LASN1_ERROR)
   { // error, we can't set a valid attribute combination!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_lookup_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL???
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_lookup_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   char       *achl_dn    (NULL);
   int         iml_len_dn (0);
   ied_charset iel_chs_dn;

   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc = this->m_recv( ied_ldap_lookup_err /* apicode */ );
      if (iml_rc != ied_ldap_success)
        return iml_rc;
      // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_lookup_err );
        return ied_ldap_failure;
      }

      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             bol_found = TRUE;
             // find next free structure in the chain...
             while (*aadsl_attr_desc)
                  aadsl_attr_desc = &(*aadsl_attr_desc)->adsc_next_attr_desc;

            iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc, &achl_dn, &iml_len_dn, &iel_chs_dn );

             if (iml_rc == ied_ldap_success)
             { // default attribute value found?
               if (bol_attrlist ==  FALSE)
                 // return the dn only...
                 (*aadsl_attr_desc)->adsc_attr = NULL;
             }
             else
             { // no attribute values found, but the entry ?
               if (iml_len_dn && achl_dn)
               { // return the dn only...
                  *aadsl_attr_desc = (struct dsd_ldap_attr_desc *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_attr_desc) );

                  (*aadsl_attr_desc)->ac_dn      = achl_dn;
                  (*aadsl_attr_desc)->imc_len_dn = iml_len_dn;
                  (*aadsl_attr_desc)->iec_chs_dn = iel_chs_dn;

                  (*aadsl_attr_desc)->adsc_next_attr_desc = NULL;
                  (*aadsl_attr_desc)->adsc_attr           = NULL;
               }
             }

              break;
        case LDAP_RESP_SEARCH_DONE:
             if (bol_found == FALSE)
             { // nothing found!!!
               this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_lookup_err*/ );
               return ied_ldap_failure;
             }
             break;
        case LDAP_RESP_SEARCH_REF:
        default:
             break;
      } // end of switch()

   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   return iml_rc;

} // dsd_ldap::m_ldap_lookup( dsd_co_ldap_1 * )


/**
 * Private class function:  dsd_ldap::m_ldap_unbind()
 *
 * Unbinds to a ldap server (the connection is closed!!!).
 *
 *     ASN.1:
 *     UnbindRequest ::= [APPLICATION 2] NULL
 *
 *
 * @return   error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_unbind()
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   // trace message LDAP0035T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 35, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Unbind" );

   // valid connection?
   if (this->im_c_status != dsd_ldap::BIND)
   { // error; we can't execute the ldap-unbind!
     this->ds_ldap_error.m_set_error( ied_ldap_op_err, ied_ldap_unbind_err );
     return ied_ldap_failure;
   }

   // create valid LDAP message ID...
   LDAPREQ_UNBIND(this->ds_ldapreq)

   // build unbind-request...
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   if (this->ds_asn1.m_printf( "{itn}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-unbind!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_unbind_err );
     return ied_ldap_failure;
   }

   /* send the message */
   if (this->im_len_dn)
     FREE_MEM( this->ads_hl_stor_per, this->achr_dn )
   if (this->im_len_pwd)
     FREE_MEM( this->ads_hl_stor_per, this->achr_pwd )

   this->im_len_dn = this->im_len_pwd = 0;

   this->im_c_status = dsd_ldap::UNBIND;
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_unbind_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // there is no LDAP result...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;
   this->im_c_status = dsd_ldap::DISCONNECTED;
   return ied_ldap_success;

} // dsd_ldap::m_ldap_unbind()


/**
 * Private class function:  dsd_ldap::m_ldap_abandon()
 *
 * Cancel of a current LDAP operation (e.g. 'search').
 *
 *     ASN.1:
 *     AbandonRequest ::= [APPLICATION 16] MessageID
 *
 *
 * @return   error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_abandon()
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   // trace message LDAP0036T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 36, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Abandon" );

   // valid connection?
   if (this->im_c_status != dsd_ldap::BIND)
   { // error; we can't execute the ldap-abandon!
     this->ds_ldap_error.m_set_error( ied_ldap_op_err, ied_ldap_abandon_err );
     return ied_ldap_failure;
   }

   // attention: Don't overwrite the last messageID (this->ds_ldapreq.imc_msgid)!!!
   LDAPREQ_ABANDON(this->ds_ldapreq)

   // build abandon-request...
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   if (this->ds_asn1.m_printf( "{iti}",
                               this->m_get_msgid() /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               this->ds_ldapreq.imc_msgid /*i*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-abandon!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_abandon_err );
     return ied_ldap_failure;
   }

   /* send the message */
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL???
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_abandon_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // there is no LDAP result...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;
   return ied_ldap_success;

} // dsd_ldap::m_ldap_abandon()


/**
 * Private class function:  dsd_ldap::m_ldap_get_last_error()
 *
 * Returns the last erro condition.
 *
 * @return   return code (\b ied_ldap_failure, \b ied_ldap_success or any other)
 *
 */
int dsd_ldap::m_ldap_get_last_error()
{
   int iml_rc (this->ds_ldap_error.m_get_error());

   // trace message LDAP0032T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 32, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "GetLastError(): %i (%s)", 
                                  iml_rc, this->ds_ldap_error.m_get_errormsg(iml_rc) );

   // @todo: LDAP distinguished name (ac_dn, ...)
   return iml_rc;
   
} // dsd_ldap::m_ldap_get_last_error()


/**
 * Private class function:  dsd_ldap::m_ldap_get_attrlist()
 *
 * Searches and returns the whole attribute list (with/without values ) of a given dn.
 *
 *      ASN.1:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   LDAPDN,
 *                                                   scope        ENUMERATED { baseObject   (0) },
 *                                                   derefAliases ENUMERATED { derefAlways  (3) },
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    True/False,
 *                                                   filter       Filter '(objectClass=*)'
 *                                                   attributes   NULL }
 *
 *
 * @param[in,out]  adsp_co_ldap   request structure
 *
 * @return    error        (\b ied_ldap_failure),
 *            successful   (\b ied_ldap_success) or
 *            send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_ldap_get_attrlist( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   BOOL   bol_found;
   int    iml_rc, iml_rc2;
   struct dsd_ldap_attr_desc **aadsl_attr_desc;


   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)

   // do we have any distinguished name as 'baseObject' ?
   if (adsp_co_ldap->imc_len_dn == 0 || adsp_co_ldap->ac_dn == NULL)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // trace message LDAP0046T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 46, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Attributelist Scope=%s DN=\"%.*(.*)s\"",
                                  this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none" );

   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // initialize attribute description structure of the requester
   adsp_co_ldap->adsc_attr_desc = NULL;
   aadsl_attr_desc = &adsp_co_ldap->adsc_attr_desc;
   // create valid LDAP message ID...
   this->ds_ldapreq.imc_msgid = this->m_get_msgid();
   // build the asn.1-formatted search request...
   if (this->ds_asn1.m_printf( "{it{seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/,
                               int(ied_sear_baseobject) /*e*/,
                               LDAP_DEREF_NEVER /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               (adsp_co_ldap->iec_sear_scope == ied_sear_attronly) ? TRUE : FALSE /*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) in asn.1-format...
   if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) != LASN1_SUCCESS)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set asn1-attribute(s)...
   if (this->ds_asn1.m_printf( "{}}}", NULL /* or "" */, 0, int(ied_chs_utf_8) ) == LASN1_ERROR)
   { // error, we can't set a valid attribute combination!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // send the message...
   bol_found = FALSE;
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL???
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc2 = this->m_recv( ied_ldap_search_err /* apicode */ );
      if (iml_rc2 != ied_ldap_success)
        return iml_rc2;
      // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
        return ied_ldap_failure;
      }

      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             bol_found = TRUE;
             // find next free structure in the chain...
             while (*aadsl_attr_desc)
                  aadsl_attr_desc = &(*aadsl_attr_desc)->adsc_next_attr_desc;

             iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc );
             break;
        case LDAP_RESP_SEARCH_DONE:
             if (bol_found == FALSE)
             { // nothing found!!!
               this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
               return ied_ldap_failure;
             }
        case LDAP_RESP_SEARCH_REF:
        default:
             break;
      } // end of switch()

   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   return iml_rc;

} // dsd_ldap::m_ldap_get_attrlist( dsd_co_ldap_1* )


/**
 * Private class function:  dsd_ldap::m_ldap_get_membership()
 *
 * Searches the group-membership (MSAD 'memberOf'-attribute) of an entry (group or user). 
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_get_membership(struct dsd_co_ldap_1 *adsp_co_ldap)
{
   void  *avol_1;
   struct dsd_ldap_val  *adsl_namingcontexts (NULL);

   LDAP_REQ_STRUC(dsl_co_ldap_bind)
   
   int    iml_rc (ied_ldap_success), 
          iml_rc_bind (m_ldap_get_bind(&dsl_co_ldap_bind, TRUE /*internal use of the password*/));

   BOOL   bol_param_dn (TRUE);
   void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;

#ifdef _DEBUG   
//   adsp_co_ldap->amc_aux     = &ms_aux_per_mem;     // storage subroutine 
//   adsp_co_ldap->vpc_userfld = this;
#endif
   if (!adsp_co_ldap->imc_len_dn || adsp_co_ldap->ac_dn == NULL)
   { // we have to use the actual bound user's DN...
     bol_param_dn = FALSE;      
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect(this->ads_ldap_group) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND'...
                                   if (!bol_param_dn)
                                     BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // set bind to search administrator account
   if (m_aux_bind_admin() != ied_ldap_success)
     // error; we can't execute the ldap-search!
     return ied_ldap_failure;

   // set membership-value to return
   adsp_co_ldap->adsc_memship_desc = NULL;
   adsp_co_ldap->adsc_attr_desc    = NULL;

   struct dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);

   // search user-member-entry (use of LDAP-templates)...
   // do this, if either we use a MSAD or <membership-attribute> is supported!
   if (this->im_ldap_type == ied_sys_ldap_msad || adsl_templ->imc_len_mship_attr)
   {
     LDAP_REQ_STRUC(dsl_co_ldap)

     dsl_co_ldap.iec_co_ldap    = ied_co_ldap_search;
     dsl_co_ldap.iec_sear_scope = ied_sear_baseobject;  // search at the base object only
     dsl_co_ldap.dsc_add_dn.ac_str      = NULL;
     dsl_co_ldap.dsc_add_dn.imc_len_str = 0;

     if (bol_param_dn)
     { // use the parameter DN
       dsl_co_ldap.ac_dn      = adsp_co_ldap->ac_dn;
       dsl_co_ldap.imc_len_dn = adsp_co_ldap->imc_len_dn;
       dsl_co_ldap.iec_chs_dn = adsp_co_ldap->iec_chs_dn;
     }
     else
     {
       dsl_co_ldap.ac_dn      = this->achr_dn;
       dsl_co_ldap.imc_len_dn = this->im_len_dn;
       dsl_co_ldap.iec_chs_dn = ied_chs_utf_8;
     }

     // set search filter (using templates)...
     dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
     dsl_co_ldap.imc_len_filter = sizeof "(|(objectClass=)(objectClass=))" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_user_attr  ? adsl_templ->imc_len_user_attr  : sizeof "*" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_filter );

     memcpy((void *)dsl_co_ldap.ac_filter, (const void *)"(|(objectClass=", sizeof "(|(objectClass=" - 1 );
     avol_1 = dsl_co_ldap.ac_filter + sizeof "(|(objectClass=" - 1;
     
     if (adsl_templ->imc_len_user_attr)
     { memcpy((void *)avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     
     memcpy((void *)avol_1, (const void *)")(objectClass=", sizeof ")(objectClass=" - 1);
     avol_1 = (char *)avol_1 + sizeof ")(objectClass=" - 1;

     if (adsl_templ->imc_len_group_attr)
     { memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1);

     
     // set attribute-list to return (valid for person-requests!)
     // e.g. attrlist="memberOf,primaryGroupID"
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_mship_attr;
     dsl_co_ldap.ac_attrlist      = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_attrlist + 1/*"\,"*/ +
                                                             sizeof "primaryGroupID" - 1 /*'\0'*/);
     avol_1 = (void *)dsl_co_ldap.ac_attrlist;

     // add "primaryGroupID" only, if we have a MSAD-type!
     if (this->im_ldap_type == ied_sys_ldap_msad)
     {
       memcpy((void *)avol_1, (const void *)"primaryGroupID", sizeof "primaryGroupID" - 1);
       avol_1 = (char *)avol_1 + sizeof "primaryGroupID" - 1;
       dsl_co_ldap.imc_len_attrlist += sizeof "primaryGroupID" - 1;

       if (adsl_templ->imc_len_mship_attr)
       {
         *(char *)avol_1 = ',';
         avol_1 = (char *)avol_1 + 1;
         ++dsl_co_ldap.imc_len_attrlist;
       }
     } // MSAD environment only

     // <membership-attribute>, e.g. "memberOf"?
     if (adsl_templ->imc_len_mship_attr)
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_mship_attr, adsl_templ->imc_len_mship_attr );
     
     
     // trace message LDAP0042T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 42, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "Membership Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\"",
                                    this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.imc_len_dn : sizeof "none" - 1,
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.iec_chs_dn : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.ac_dn      : "none",
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.imc_len_filter : sizeof "none" - 1,
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.iec_chs_filter : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.ac_filter      : "none",
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.imc_len_attrlist : sizeof "none" - 1,
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.iec_chs_attrlist : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.ac_attrlist      : "none" );     
     
     // perform the search-request(person)...
     if (this->m_ldap_search( &dsl_co_ldap ) == ied_ldap_success && 
         dsl_co_ldap.adsc_attr_desc)
     { 
       // search successful, transfer membership to the structure of the requester!
       struct dsd_ldap_attr *adsl_attr_1 = dsl_co_ldap.adsc_attr_desc->adsc_attr;
       struct dsd_ldap_attr *adsl_attr_memberof (NULL);
       struct dsd_sid        dsl_sid_1;
       struct dsd_ldap_val  *adsl_val_pg (NULL), dsl_val_1;
       int  iml_pg;

       LDAP_REQ_STRUC(dsl_co_ldap_pg)

     
       while (adsl_attr_1)
       {  // check the returned partial attributes...
          if (adsl_attr_1->imc_len_attr == this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr &&
              !m_hl_memicmp( adsl_attr_1->ac_attr, this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr, adsl_attr_1->imc_len_attr ))
            // save attribute address of <memberOf>
            adsl_attr_memberof = adsl_attr_1;
          else
          { // check for 'primaryGroupID'...
            if (adsl_attr_1->imc_len_attr == sizeof "primaryGroupID" - 1 &&
                !m_hl_memicmp( adsl_attr_1->ac_attr, (void *)"primaryGroupID", adsl_attr_1->imc_len_attr ))
            { // search group associated with the 'primaryGroupID' found!
              string str_pg( adsl_attr_1->dsc_val.ac_val, adsl_attr_1->dsc_val.imc_len_val );
              iml_pg = atoi( str_pg.c_str() );
              // endianess?
              if (this->bo_le == FALSE)
              { // convert from le to be
                iml_pg = m_bswap32(iml_pg);
              }

              if (this->bo_RootDSE == TRUE || this->m_aux_search_RootDSE() == ied_ldap_success)
              {
                if (this->ads_domainSID)
                { 
                  struct dsd_ldap_val  dsl_context;

     
                  // MS LDS doesn't support 'defaultNamingContext'
                  if (this->ds_RootDSE.ads_defaultcontext)
                  { // MSAD with default context
                    dsl_context.ac_val      = this->ds_RootDSE.ads_defaultcontext->ac_val;
                    dsl_context.imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
                    dsl_context.iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
                  }
                  else
                  { // MS LDS
                    dsl_context.ac_val      = this->ads_ldap_entry->achc_base_dn;
                    dsl_context.imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
                    dsl_context.iec_chs_val = ied_chs_utf_8;
                  }
     
                  // build 'objectSid' for the primary group
                  memcpy((void *)&dsl_sid_1, (const void *)this->ads_domainSID, sizeof(struct dsd_sid) );
                  *(int *)dsl_sid_1.uchcr_subID[dsl_sid_1.uchc_count_subIDs] = iml_pg;
                  dsl_sid_1.uchc_count_subIDs++;
                  this->m_aux_hex_to_sid( &dsl_sid_1, &dsl_val_1, this->ads_hl_stor_tmp );
     
                  // perform a search request for the 'primary group'-dn...
                  string str_filter( "(&(objectClass=" );
                         str_filter += string( this->ads_ldap_entry->adsc_ldap_template->achc_group_attr,
                                               this->ads_ldap_entry->adsc_ldap_template->imc_len_group_attr );
                         str_filter += ")(objectSid=";
                         str_filter += string( dsl_val_1.ac_val, dsl_val_1.imc_len_val );
                         str_filter += "))";
     

                  dsl_co_ldap_pg.iec_co_ldap      = ied_co_ldap_search;
                  dsl_co_ldap_pg.iec_sear_scope   = ied_sear_sublevel;
                  dsl_co_ldap_pg.ac_filter        = (char *)str_filter.c_str();
                  dsl_co_ldap_pg.imc_len_filter   = (int)str_filter.length();
                  dsl_co_ldap_pg.iec_chs_filter   = ied_chs_utf_8;
                  dsl_co_ldap_pg.ac_attrlist      = (char*)"objectSid";
                  dsl_co_ldap_pg.imc_len_attrlist = sizeof "objectSid" - 1;
                  dsl_co_ldap_pg.iec_chs_attrlist = ied_chs_utf_8;
                  dsl_co_ldap_pg.ac_dn            = dsl_context.ac_val;
                  dsl_co_ldap_pg.imc_len_dn       = dsl_context.imc_len_val;
                  dsl_co_ldap_pg.iec_chs_dn       = dsl_context.iec_chs_val;
     
                  if (this->m_ldap_search( &dsl_co_ldap_pg ) == ied_ldap_success &&
                      dsl_co_ldap_pg.adsc_attr_desc)
                  { // add 'primary group'-dn...
                    // find next free structure in the chain...
                    adsl_val_pg  = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                     sizeof(struct dsd_ldap_val));
                    memset( (void *)adsl_val_pg, 0, sizeof(struct dsd_ldap_val) );
     
                    adsl_val_pg->imc_len_val = dsl_co_ldap_pg.adsc_attr_desc->imc_len_dn;
                    adsl_val_pg->iec_chs_val = dsl_co_ldap_pg.adsc_attr_desc->iec_chs_dn;
                    adsl_val_pg->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                  adsl_val_pg->imc_len_val );
                    memcpy((void *)adsl_val_pg->ac_val,
                           (const void *)dsl_co_ldap_pg.adsc_attr_desc->ac_dn,
                           adsl_val_pg->imc_len_val );
                  } // search(successful)
                } // domainSID set
              } // namingcontexts
            } // primaryGroupID found
          }
     
          // step to the next
          adsl_attr_1 = adsl_attr_1->adsc_next_attr;
       } // while (partial attributes)
         
         
        if (adsl_attr_memberof)
        { // add 'primarygroup'-DN to the list of 'memberOf'-value(s)
          struct dsd_ldap_val *adsl_val_1 = &adsl_attr_memberof->dsc_val;
         

          while (adsl_val_1->adsc_next_val)           // search the end of the <memberOf>-list..
               adsl_val_1 = adsl_val_1->adsc_next_val;

          adsl_val_1->adsc_next_val = adsl_val_pg;    // add 'primarygroup'-DN
          adsl_attr_memberof->adsc_next_attr = NULL;  // cut the chain of attributes
        }
        else
        { // we don't have any membership entries, so create one if we have the 'primaryGroupId'?
          if (adsl_val_pg)
          { // yes, we have a 'primaryGroupId'
            adsl_attr_memberof = (dsd_ldap_attr *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_attr));
            memset((void *)adsl_attr_memberof, int(0), sizeof(struct dsd_ldap_attr));

            adsl_attr_memberof->ac_attr        = this->ads_ldap_entry->adsc_ldap_template->achc_mship_attr;
            adsl_attr_memberof->imc_len_attr   = this->ads_ldap_entry->adsc_ldap_template->imc_len_mship_attr;
            adsl_attr_memberof->iec_chs_attr   = ied_chs_utf_8;
            adsl_attr_memberof->dsc_val.ac_val      = adsl_val_pg->ac_val;
            adsl_attr_memberof->dsc_val.imc_len_val = adsl_val_pg->imc_len_val;
            adsl_attr_memberof->dsc_val.iec_chs_val = adsl_val_pg->iec_chs_val;
          }
        }
       
       
        // move value(s) to the membership-structure...
        if (adsl_attr_memberof)
        {
          adsp_co_ldap->adsc_memship_desc = (dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
          memset((void *)adsp_co_ldap->adsc_memship_desc, int(0), sizeof(struct dsd_ldap_val));
       
          struct dsd_ldap_val  *adsl_memship_desc (adsp_co_ldap->adsc_memship_desc);   // destination (returned structure)
          struct dsd_ldap_val  *adsl_memberof_val (&adsl_attr_memberof->dsc_val);      // source


          while (adsl_memberof_val->imc_len_val)
          {
               adsl_memship_desc->iec_chs_val   = adsl_memberof_val->iec_chs_val;
               adsl_memship_desc->imc_len_val   = adsl_memberof_val->imc_len_val;
               adsl_memship_desc->ac_val        = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, adsl_memberof_val->imc_len_val);
               memcpy((void *)adsl_memship_desc->ac_val, (void *)adsl_memberof_val->ac_val, adsl_memberof_val->imc_len_val);

               // next entry
               adsl_memberof_val = adsl_memberof_val->adsc_next_val;
               
               if (adsl_memberof_val)
               {
                 adsl_memship_desc->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                 memset((void *)adsl_memship_desc->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                 adsl_memship_desc = adsl_memship_desc->adsc_next_val;
               }
               else
                 break;

          } // while (transfer)
          
        } // 'memberOf'-transfer
     } // search was successful
   } // support of <membership-attribute> (e.g. by MSAD)


   // search group-memberships ("member"-attribute)...
   LDAP_REQ_STRUC(dsl_co_ldap_member)

   char *achl_dn ("none");
   int   iml_len_dn (sizeof "none" - 1);

   if (adsp_co_ldap->ac_dn && adsp_co_ldap->imc_len_dn != 0)
   { // convert 'dn'-parameter if necessary
     iml_len_dn = m_len_vx_vx(ied_chs_utf_8, (void *)adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn);
     
     if (iml_len_dn == -1)
     { // error, invalid string format...
       this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
       return ied_ldap_failure;
     }

     achl_dn = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, iml_len_dn);
     if (m_cpy_vx_vx_fl((void *)achl_dn, iml_len_dn, ied_chs_utf_8,
                        (void *)adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn,
                        D_CPYVXVX_FL_NOTAIL0) == -1)
     { // error, invalid string format...
       this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
       return ied_ldap_failure;
     } 
   }

   // @todo: use group-dn, if set (for the moment use the namingcontexts!)
   dsl_co_ldap_member.iec_co_ldap      = ied_co_ldap_search;
   dsl_co_ldap_member.iec_sear_scope   = ied_sear_sublevel;  // search at the baseObject and all sub-levels
   dsl_co_ldap_member.ac_attrlist      = (char *)"objectclass";
   dsl_co_ldap_member.imc_len_attrlist = sizeof "objectclass" - 1;
   dsl_co_ldap_member.iec_chs_attrlist = ied_chs_utf_8;

   // set search filter (using templates)...
   dsl_co_ldap_member.iec_chs_filter  = ied_chs_utf_8;
   dsl_co_ldap_member.imc_len_filter  = sizeof "(&(objectClass=)())" - 1 + iml_len_dn + 1/*"="*/;
   dsl_co_ldap_member.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
   dsl_co_ldap_member.imc_len_filter += adsl_templ->imc_len_member_attr ? adsl_templ->imc_len_member_attr : sizeof "member" - 1/*default*/;
   dsl_co_ldap_member.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap_member.imc_len_filter );

   memcpy((void *)dsl_co_ldap_member.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
   avol_1 = dsl_co_ldap_member.ac_filter + sizeof "(&(objectClass=" - 1;

   if (adsl_templ->imc_len_group_attr)
   { 
     memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
   }
   else
   { // default-value: "*"
     *(char *)avol_1 = '*';
     avol_1 = (char *)avol_1 + 1;
   }
   
   memcpy((void *)avol_1, (const void *)")(", sizeof ")(" - 1 );
   avol_1 = (char *)avol_1 + sizeof ")(" - 1;

   if (adsl_templ->imc_len_member_attr)
   { 
     memcpy((void *)avol_1, (const void *)adsl_templ->achc_member_attr, adsl_templ->imc_len_member_attr );
     *((char *)avol_1 + adsl_templ->imc_len_member_attr) = '=';
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_member_attr + 1;
   }
   else
   { // default-attribute: "member="
     memcpy((void *)avol_1, (const void *)"member=", sizeof "member=" - 1 );
     avol_1 = (char *)avol_1 + sizeof "member=" - 1;
   }

   memcpy((void *)avol_1, (const void *)achl_dn, iml_len_dn);
   avol_1 = (char *)avol_1 + iml_len_dn;
   memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1 );

   // perform the search-request...
   BOOL bol_add (FALSE);
   struct dsd_ldap_val **aadsl_memship_desc = NULL;
   struct dsd_ldap_val  *adsl_memship_desc_prev (NULL);

   adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;


   while (adsl_namingcontexts)
   {    // use this 'namingcontext' for searching entries...
        dsl_co_ldap_member.ac_dn      = adsl_namingcontexts->ac_val;
        dsl_co_ldap_member.imc_len_dn = adsl_namingcontexts->imc_len_val;
        dsl_co_ldap_member.iec_chs_dn = adsl_namingcontexts->iec_chs_val;  // always set to utf-8

        if (this->m_ldap_search(&dsl_co_ldap_member, TRUE/*attr only*/) == ied_ldap_success)
        { // entries found, add membership at the end of the structure returned to caller.
          // Note: Add only, if this entry isn't added yet!
          while (dsl_co_ldap_member.adsc_attr_desc)
          {
              bol_add = TRUE;
              aadsl_memship_desc     = &adsp_co_ldap->adsc_memship_desc;
              adsl_memship_desc_prev = *aadsl_memship_desc;
    
              while (*aadsl_memship_desc)
              { 
                  // compare all entries inserted so far...
                  if ((*aadsl_memship_desc)->imc_len_val == dsl_co_ldap_member.adsc_attr_desc->imc_len_dn &&
                      !m_hl_memicmp((const void *)(*aadsl_memship_desc)->ac_val, 
                                    (const void *)dsl_co_ldap_member.adsc_attr_desc->ac_dn,
                                    dsl_co_ldap_member.adsc_attr_desc->imc_len_dn))
                  { // value already added!
                    bol_add = FALSE;
                    break;
                  }

                  adsl_memship_desc_prev = *aadsl_memship_desc;
                  aadsl_memship_desc     = &(*aadsl_memship_desc)->adsc_next_val;
              } // while (aadsl_memship_desc)

              if (bol_add == TRUE)
              { // insert the new element...
                // is it the first insert?
                if (adsp_co_ldap->adsc_memship_desc == NULL)
                { // yes, prepare structure...
                  adsp_co_ldap->adsc_memship_desc = (dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                  memset((void *)adsp_co_ldap->adsc_memship_desc, int(0), sizeof(struct dsd_ldap_val));

                  aadsl_memship_desc = &adsp_co_ldap->adsc_memship_desc;
                  adsl_memship_desc_prev = *aadsl_memship_desc;

                  adsl_memship_desc_prev->iec_chs_val = dsl_co_ldap_member.adsc_attr_desc->iec_chs_dn;
                  adsl_memship_desc_prev->imc_len_val = dsl_co_ldap_member.adsc_attr_desc->imc_len_dn;
                  adsl_memship_desc_prev->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                           dsl_co_ldap_member.adsc_attr_desc->imc_len_dn);         
                  memcpy((void *)adsl_memship_desc_prev->ac_val, 
                         (void *)dsl_co_ldap_member.adsc_attr_desc->ac_dn, 
                         dsl_co_ldap_member.adsc_attr_desc->imc_len_dn);
                }
                else
                { // no...
                  adsl_memship_desc_prev->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                  memset((void *)adsl_memship_desc_prev->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));
       
                  adsl_memship_desc_prev->adsc_next_val->iec_chs_val = dsl_co_ldap_member.adsc_attr_desc->iec_chs_dn;
                  adsl_memship_desc_prev->adsc_next_val->imc_len_val = dsl_co_ldap_member.adsc_attr_desc->imc_len_dn;
                  adsl_memship_desc_prev->adsc_next_val->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                          dsl_co_ldap_member.adsc_attr_desc->imc_len_dn);         
                  memcpy((void *)adsl_memship_desc_prev->adsc_next_val->ac_val, 
                         (void *)dsl_co_ldap_member.adsc_attr_desc->ac_dn, 
                         dsl_co_ldap_member.adsc_attr_desc->imc_len_dn);
                }
              } // add (true)

              // test next entry 
              dsl_co_ldap_member.adsc_attr_desc = dsl_co_ldap_member.adsc_attr_desc->adsc_next_attr_desc;
          } // while (dsl_co_ldap.adsc_attr_desc)
        } // success (search groups)

        // step to the next 'namingcontext'
        adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
   } // end of while('namingcontexts')


   // have we anything to set up in the membership-structure?
   if (adsp_co_ldap->adsc_memship_desc == NULL)
   { // nothing found, set error!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
     iml_rc = ied_ldap_failure;
   }

   // restore bind context
   if (iml_rc_bind == ied_ldap_success)
   {
     struct dsd_unicode_string dsl_userid = {dsl_co_ldap_bind.ac_userid, 
                                             dsl_co_ldap_bind.imc_len_userid, 
                                             dsl_co_ldap_bind.iec_chs_userid};
     struct dsd_unicode_string dsl_passwd = {dsl_co_ldap_bind.ac_passwd, 
                                             dsl_co_ldap_bind.imc_len_passwd, 
                                             dsl_co_ldap_bind.iec_chs_passwd};

     m_aux_bind_simple(&dsl_userid, &dsl_passwd);
   }  

   return iml_rc;

} //dsd_ldap::m_ldap_get_membership()


/**
 * Private class function:  dsd_ldap::m_ldap_get_membership_nested()
 *
 * Returns a list of all group memberships of an entry (user or group). In contrast to m_ldap_get_membership()
 * the function returns the membership of groups to other groups. The maximum depth of scanning is
 * controlled by <search-nested-groups-level>.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_get_membership_nested( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   LDAP_REQ_STRUC(dsl_co_ldap)
   LDAP_REQ_STRUC(dsl_co_ldap_sear)
   LDAP_REQ_STRUC(dsl_co_ldap_bind)

   int  iml_rc (ied_ldap_success), 
        iml_rc_bind (m_ldap_get_bind(&dsl_co_ldap_bind, TRUE /*internal use of the password*/));

   BOOL  bol_param_dn (TRUE);
   void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;

#ifdef _DEBUG   
//   adsp_co_ldap->amc_aux     = &ms_aux_per_mem;     // storage subroutine 
//   adsp_co_ldap->vpc_userfld = this;
#endif

   if (!adsp_co_ldap->imc_len_dn || adsp_co_ldap->ac_dn == NULL)
   { // we have to use the actual bound user's DN
     bol_param_dn = FALSE;
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect(this->ads_ldap_group) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   if (!bol_param_dn)
                                     BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // set membership-value to return
   adsp_co_ldap->adsc_memship_desc = NULL;
   adsp_co_ldap->adsc_attr_desc    = NULL;
   
   // set request structure for ied_co_ldap_get_membership()
   dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership;
   dsl_co_ldap.amc_aux     = adsp_co_ldap->amc_aux;     
   dsl_co_ldap.vpc_userfld = adsp_co_ldap->vpc_userfld;

   if (bol_param_dn)
   { // use the parameter DN
     dsl_co_ldap.ac_dn      = adsp_co_ldap->ac_dn;
     dsl_co_ldap.imc_len_dn = adsp_co_ldap->imc_len_dn;
     dsl_co_ldap.iec_chs_dn = adsp_co_ldap->iec_chs_dn;
   }
   else
   { // use the already bound user
     dsl_co_ldap.ac_dn      = this->achr_dn;
     dsl_co_ldap.imc_len_dn = this->im_len_dn;
     dsl_co_ldap.iec_chs_dn = ied_chs_utf_8;
   }


   // trace message LDAP0044T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 44, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Membership(nested) Scope=%s DN=\"%.*(.*)s\" ",
                                  this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none" );

   iml_rc = m_ldap_get_membership(&dsl_co_ldap);  

   if (iml_rc == ied_ldap_success && dsl_co_ldap.adsc_memship_desc)
   { 
     // set bind to search administrator account and scan group dependencies...
     if (m_aux_bind_admin() != ied_ldap_success)
       // error; we can't execute the ldap-search!
       return ied_ldap_failure;


     void *avol_1;

     struct dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);
     struct dsd_ldap_val      *adsl_memship (dsl_co_ldap.adsc_memship_desc),
                              *adsl_namingcontexts;

     dsl_co_ldap_sear.iec_co_ldap      = ied_co_ldap_search;
     dsl_co_ldap_sear.iec_sear_scope   = ied_sear_sublevel;  // search at the baseObject and all sub-levels
     dsl_co_ldap_sear.ac_attrlist      = (char *)"objectclass";
     dsl_co_ldap_sear.imc_len_attrlist = sizeof "objectclass" - 1;
     dsl_co_ldap_sear.iec_chs_attrlist = ied_chs_utf_8;

GROUPLIST_NEXT:
     // set search filter (using templates)...
     dsl_co_ldap_sear.iec_chs_filter  = ied_chs_utf_8;
     dsl_co_ldap_sear.imc_len_filter  = sizeof "(&(objectClass=)())" - 1 + adsl_memship->imc_len_val + 1/*"="*/;
     dsl_co_ldap_sear.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap_sear.imc_len_filter += adsl_templ->imc_len_member_attr ? adsl_templ->imc_len_member_attr : sizeof "member" - 1/*default*/;
     dsl_co_ldap_sear.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap_sear.imc_len_filter );

     memcpy((void *)dsl_co_ldap_sear.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
     avol_1 = dsl_co_ldap_sear.ac_filter + sizeof "(&(objectClass=" - 1;

     if (adsl_templ->imc_len_group_attr)
     { 
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     
     memcpy((void *)avol_1, (const void *)")(", sizeof ")(" - 1 );
     avol_1 = (char *)avol_1 + sizeof ")(" - 1;

     if (adsl_templ->imc_len_member_attr)
     { 
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_member_attr, adsl_templ->imc_len_member_attr );
       *((char *)avol_1 + adsl_templ->imc_len_member_attr) = '=';
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_member_attr + 1;
     }
     else
     { // default-attribute: "member="
       memcpy((void *)avol_1, (const void *)"member=", sizeof "member=" - 1 );
       avol_1 = (char *)avol_1 + sizeof "member=" - 1;
     }

     memcpy((void *)avol_1, (const void *)adsl_memship->ac_val, adsl_memship->imc_len_val);
     avol_1 = (char *)avol_1 + adsl_memship->imc_len_val;
     memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1 );

     // perform the search-request...
     adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;

     while (adsl_namingcontexts)
     {    // use this 'namingcontext' for searching entries...
          dsl_co_ldap_sear.ac_dn      = adsl_namingcontexts->ac_val;
          dsl_co_ldap_sear.imc_len_dn = adsl_namingcontexts->imc_len_val;
          dsl_co_ldap_sear.iec_chs_dn = adsl_namingcontexts->iec_chs_val;  // always set to utf-8

          if (m_ldap_search(&dsl_co_ldap_sear, TRUE/*attr only*/) == ied_ldap_success)
          { 
            // we have found nested groups, include them if not yet added
            BOOL  bol_add (FALSE);
            struct dsd_ldap_val **aadsl_memship_desc = NULL;
            struct dsd_ldap_val  *adsl_memship_desc_prev (NULL);

            while (dsl_co_ldap_sear.adsc_attr_desc)
            {
                 bol_add = TRUE;
                 aadsl_memship_desc     = &dsl_co_ldap.adsc_memship_desc; 
                 adsl_memship_desc_prev = *aadsl_memship_desc;           
            
                 while (*aadsl_memship_desc)
                 { 
                     // compare all entries inserted so far...
                     if ((*aadsl_memship_desc)->imc_len_val == dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn &&
                         !m_hl_memicmp((const void *)(*aadsl_memship_desc)->ac_val, 
                                       (const void *)dsl_co_ldap_sear.adsc_attr_desc->ac_dn,
                                       dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn))
                     { // value already added!
                       bol_add = FALSE;
                       break;
                     }

                     adsl_memship_desc_prev = *aadsl_memship_desc;
                     aadsl_memship_desc     = &(*aadsl_memship_desc)->adsc_next_val;
                 } // while (aadsl_memship_desc)

                 if (bol_add == TRUE)
                 { // insert the new element...
                   adsl_memship_desc_prev->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                             sizeof(struct dsd_ldap_val));
                   memset((void *)adsl_memship_desc_prev->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));
          
                   adsl_memship_desc_prev->adsc_next_val->iec_chs_val = dsl_co_ldap_sear.adsc_attr_desc->iec_chs_dn;
                   adsl_memship_desc_prev->adsc_next_val->imc_len_val = dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn;
                   adsl_memship_desc_prev->adsc_next_val->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                           dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn);
                   memcpy((void *)adsl_memship_desc_prev->adsc_next_val->ac_val, 
                          (void *)dsl_co_ldap_sear.adsc_attr_desc->ac_dn, 
                          dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn);
                 } // add (true)

                 // test next entry 
                 dsl_co_ldap_sear.adsc_attr_desc = dsl_co_ldap_sear.adsc_attr_desc->adsc_next_attr_desc;
            } // while (dsl_co_ldap.adsc_memship_desc)           
          } // success (search groups)

          // step to the next 'namingcontext'
          adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
     } // end of while('namingcontexts')


     // step to the next entry in the membership list
     adsl_memship = adsl_memship->adsc_next_val;
     if (adsl_memship)
       goto GROUPLIST_NEXT;

      
   } // success(m_ldap_get_membership())


   // have we anything to set up in the membership-structure?
   adsp_co_ldap->adsc_memship_desc = dsl_co_ldap.adsc_memship_desc;

   if (adsp_co_ldap->adsc_memship_desc == NULL)
   { // nothing found, set error!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
     iml_rc = ied_ldap_failure;
   }

   // restore bind context
   if (iml_rc_bind == ied_ldap_success)
   {
     struct dsd_unicode_string dsl_userid = {dsl_co_ldap_bind.ac_userid, 
                                             dsl_co_ldap_bind.imc_len_userid, 
                                             dsl_co_ldap_bind.iec_chs_userid};
     struct dsd_unicode_string dsl_passwd = {dsl_co_ldap_bind.ac_passwd, 
                                             dsl_co_ldap_bind.imc_len_passwd, 
                                             dsl_co_ldap_bind.iec_chs_passwd};

     m_aux_bind_simple(&dsl_userid, &dsl_passwd);
   }  

   return iml_rc;

} //dsd_ldap::m_ldap_get_membership_nested()


/**
 * Private class function:  dsd_ldap::m_ldap_get_members()
 *
 * Searches the list of members (MSAD 'member'-attribute) of an entry (group or user). 
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_get_members(struct dsd_co_ldap_1 *adsp_co_ldap)
{
   void  *avol_1;
   struct dsd_ldap_val  *adsl_namingcontexts (NULL);

   LDAP_REQ_STRUC(dsl_co_ldap_bind)

   int   iml_rc (ied_ldap_success), 
         iml_rc_bind (m_ldap_get_bind(&dsl_co_ldap_bind, TRUE /*internal use of the password*/));

   BOOL  bol_param_dn (TRUE);
   void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;

#ifdef _DEBUG   
//   adsp_co_ldap->amc_aux     = &ms_aux_per_mem;     // storage subroutine 
//   adsp_co_ldap->vpc_userfld = this;
#endif

   if (!adsp_co_ldap->imc_len_dn || adsp_co_ldap->ac_dn == NULL)
   { // we have to use the actual bound user's DN...
     bol_param_dn = FALSE;      
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect(this->ads_ldap_group) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND'...
                                   if (!bol_param_dn)
                                     BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // set bind to search administrator account
   if (m_aux_bind_admin() != ied_ldap_success)
     // error; we can't execute the ldap-search!
     return ied_ldap_failure;

   // set membership-value to return
   adsp_co_ldap->adsc_memship_desc = NULL;
   adsp_co_ldap->adsc_attr_desc    = NULL;

   struct dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);

   // search user-member-entry (use of LDAP-templates)...
   // do this, if either we use a MSAD or <membership-attribute> is supported!
   if (this->im_ldap_type == ied_sys_ldap_msad || adsl_templ->imc_len_mship_attr)
   {
     LDAP_REQ_STRUC(dsl_co_ldap)
  
     dsl_co_ldap.iec_co_ldap    = ied_co_ldap_search;
     dsl_co_ldap.iec_sear_scope = ied_sear_baseobject;  // search at the base object only
     dsl_co_ldap.dsc_add_dn.ac_str      = NULL;
     dsl_co_ldap.dsc_add_dn.imc_len_str = 0;

     if (bol_param_dn)
     { // use the parameter DN
       dsl_co_ldap.ac_dn      = adsp_co_ldap->ac_dn;
       dsl_co_ldap.imc_len_dn = adsp_co_ldap->imc_len_dn;
       dsl_co_ldap.iec_chs_dn = adsp_co_ldap->iec_chs_dn;
     }
     else
     {
       dsl_co_ldap.ac_dn      = this->achr_dn;
       dsl_co_ldap.imc_len_dn = this->im_len_dn;
       dsl_co_ldap.iec_chs_dn = ied_chs_utf_8;
     }

     // set search filter (using templates)...
     dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
     dsl_co_ldap.imc_len_filter = sizeof "(|(objectClass=)(objectClass=))" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_user_attr  ? adsl_templ->imc_len_user_attr  : sizeof "*" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_filter );

     memcpy((void *)dsl_co_ldap.ac_filter, (const void *)"(|(objectClass=", sizeof "(|(objectClass=" - 1 );
     avol_1 = dsl_co_ldap.ac_filter + sizeof "(|(objectClass=" - 1;
     
     if (adsl_templ->imc_len_user_attr)
     { memcpy((void *)avol_1, (const void *)adsl_templ->achc_user_attr, adsl_templ->imc_len_user_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_user_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     
     memcpy((void *)avol_1, (const void *)")(objectClass=", sizeof ")(objectClass=" - 1);
     avol_1 = (char *)avol_1 + sizeof ")(objectClass=" - 1;

     if (adsl_templ->imc_len_group_attr)
     { memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1);

     
     // set attribute-list to return (valid for person-requests!)
     // e.g. attrlist="member"
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_member_attr;
     dsl_co_ldap.ac_attrlist      = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_attrlist + 1);
     avol_1 = (void *)dsl_co_ldap.ac_attrlist;

     // <member-attribute>, e.g. "member"?
     if (adsl_templ->imc_len_member_attr)
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_member_attr, adsl_templ->imc_len_member_attr );
     
     
     // trace message LDAP0043T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 43, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "Members Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\"",
                                    this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.imc_len_dn : sizeof "none" - 1,
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.iec_chs_dn : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_dn ? dsl_co_ldap.ac_dn : "none",
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.imc_len_filter : sizeof "none" - 1,
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.iec_chs_filter : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_filter ? dsl_co_ldap.ac_filter : "none",
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.imc_len_attrlist : sizeof "none" - 1,
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.iec_chs_attrlist : ied_chs_ascii_850,
                                    dsl_co_ldap.ac_attrlist ? dsl_co_ldap.ac_attrlist : "none" );
     
     // perform the search-request(person)...
     if (this->m_ldap_search(&dsl_co_ldap ) == ied_ldap_success && 
         dsl_co_ldap.adsc_attr_desc)
     { 
       // search successful, transfer membership to the structure of the requester!
       struct dsd_ldap_attr *adsl_attr_1 = dsl_co_ldap.adsc_attr_desc->adsc_attr;
       struct dsd_ldap_attr *adsl_attr_member (NULL);

       while (adsl_attr_1)
       {  // check the returned partial attributes...
          if (adsl_attr_1->imc_len_attr == this->ads_ldap_entry->adsc_ldap_template->imc_len_member_attr &&
              !m_hl_memicmp( adsl_attr_1->ac_attr, this->ads_ldap_entry->adsc_ldap_template->achc_member_attr, adsl_attr_1->imc_len_attr ))
            // save attribute address of <member>
            adsl_attr_member = adsl_attr_1;
     
          // step to the next
          adsl_attr_1 = adsl_attr_1->adsc_next_attr;
       } // while (partial attributes)
         
         
       // move value(s) to the member-structure...
       if (adsl_attr_member)
       {
         adsp_co_ldap->adsc_memship_desc = (dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
         memset((void *)adsp_co_ldap->adsc_memship_desc, int(0), sizeof(struct dsd_ldap_val));
       
         struct dsd_ldap_val  *adsl_memship_desc (adsp_co_ldap->adsc_memship_desc);   // destination (returned structure)
         struct dsd_ldap_val  *adsl_member_val (&adsl_attr_member->dsc_val);          // source


         while (adsl_member_val->imc_len_val)
         {
              adsl_memship_desc->iec_chs_val   = adsl_member_val->iec_chs_val;
              adsl_memship_desc->imc_len_val   = adsl_member_val->imc_len_val;
              adsl_memship_desc->ac_val        = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, adsl_member_val->imc_len_val);
              memcpy((void *)adsl_memship_desc->ac_val, (void *)adsl_member_val->ac_val, adsl_member_val->imc_len_val);

              // next entry
              adsl_member_val = adsl_member_val->adsc_next_val;
              
              if (adsl_member_val)
              {
                adsl_memship_desc->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                memset((void *)adsl_memship_desc->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                adsl_memship_desc = adsl_memship_desc->adsc_next_val;
              }
              else
                break;

         } // while (transfer)
         
       } // 'member'-transfer
     } // search was successful
   } // support of <member-attribute> (e.g. by MSAD)


   // search group-members ("memberOf"-attribute)...
   char *achl_dn ("none");
   int   iml_len_dn (sizeof "none" - 1);

   if (adsp_co_ldap->ac_dn && adsp_co_ldap->imc_len_dn != 0)
   { // convert 'dn'-parameter if necessary
     iml_len_dn = m_len_vx_vx(ied_chs_utf_8, (void *)adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn);
     
     if (iml_len_dn == -1)
     { // error, invalid string format...
       this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
       return ied_ldap_failure;
     }

     achl_dn = (char *)m_aux_stor_alloc(&this->ads_hl_stor_tmp, iml_len_dn);
     if (m_cpy_vx_vx_fl((void *)achl_dn, iml_len_dn, ied_chs_utf_8,
                        (void *)adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn,
                        D_CPYVXVX_FL_NOTAIL0) == -1)
     { // error, invalid string format...
       this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_search_err );
       return ied_ldap_failure;
     } 
   }

   // @todo: use group-dn, if set (for the moment use all the namingcontexts!)
   LDAP_REQ_STRUC(dsl_co_ldap_memof)

   dsl_co_ldap_memof.iec_co_ldap      = ied_co_ldap_search;
   dsl_co_ldap_memof.iec_sear_scope   = ied_sear_sublevel;  // search at the baseObject and all sub-levels
   dsl_co_ldap_memof.ac_attrlist      = (char *)"objectclass";
   dsl_co_ldap_memof.imc_len_attrlist = sizeof "objectclass" - 1;
   dsl_co_ldap_memof.iec_chs_attrlist = ied_chs_utf_8;

   // set search filter (using templates)...
   dsl_co_ldap_memof.iec_chs_filter  = ied_chs_utf_8;
   dsl_co_ldap_memof.imc_len_filter  = sizeof "(&(objectClass=)())" - 1 + iml_len_dn + 1/*"="*/;
   dsl_co_ldap_memof.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
   dsl_co_ldap_memof.imc_len_filter += adsl_templ->imc_len_mship_attr ? adsl_templ->imc_len_mship_attr : sizeof "memberOf" - 1/*default*/;
   dsl_co_ldap_memof.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap_memof.imc_len_filter );

   memcpy((void *)dsl_co_ldap_memof.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
   avol_1 = dsl_co_ldap_memof.ac_filter + sizeof "(&(objectClass=" - 1;

   if (adsl_templ->imc_len_group_attr)
   { 
     memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
   }
   else
   { // default-value: "*"
     *(char *)avol_1 = '*';
     avol_1 = (char *)avol_1 + 1;
   }
   
   memcpy((void *)avol_1, (const void *)")(", sizeof ")(" - 1 );
   avol_1 = (char *)avol_1 + sizeof ")(" - 1;

   if (adsl_templ->imc_len_mship_attr)
   { 
     memcpy((void *)avol_1, (const void *)adsl_templ->achc_mship_attr, adsl_templ->imc_len_mship_attr );
     *((char *)avol_1 + adsl_templ->imc_len_mship_attr) = '=';
     avol_1 = (char *)avol_1 + adsl_templ->imc_len_mship_attr + 1;
   }
   else
   { // default-attribute: "memberOf="
     memcpy((void *)avol_1, (const void *)"memberOf=", sizeof "memberOf=" - 1 );
     avol_1 = (char *)avol_1 + sizeof "memberOf=" - 1;
   }

   memcpy((void *)avol_1, (const void *)achl_dn, iml_len_dn);
   avol_1 = (char *)avol_1 + iml_len_dn;
   memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1 );

   // perform the search-request...
   BOOL bol_add (FALSE);
   struct dsd_ldap_val **aadsl_memship_desc = NULL;
   struct dsd_ldap_val  *adsl_memship_desc_prev (NULL);

   adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;


   while (adsl_namingcontexts)
   {    // use this 'namingcontext' for searching entries...
        dsl_co_ldap_memof.ac_dn      = adsl_namingcontexts->ac_val;
        dsl_co_ldap_memof.imc_len_dn = adsl_namingcontexts->imc_len_val;
        dsl_co_ldap_memof.iec_chs_dn = adsl_namingcontexts->iec_chs_val;  // always set to utf-8

        if (this->m_ldap_search( &dsl_co_ldap_memof, TRUE/*attr only*/) == ied_ldap_success)
        { // entries found, add membership at the end of the structure returned to caller.
          // Note: Add only, if this entry isn't added yet!
          while (dsl_co_ldap_memof.adsc_attr_desc)
          {
              bol_add = TRUE;
              aadsl_memship_desc     = &adsp_co_ldap->adsc_memship_desc;
              adsl_memship_desc_prev = *aadsl_memship_desc;
    
              while (*aadsl_memship_desc)
              { 
                  // compare all entries inserted so far...
                  if ((*aadsl_memship_desc)->imc_len_val == dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn &&
                      !m_hl_memicmp((const void *)(*aadsl_memship_desc)->ac_val, 
                                    (const void *)dsl_co_ldap_memof.adsc_attr_desc->ac_dn,
                                    dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn))
                  { // value already added!
                    bol_add = FALSE;
                    break;
                  }

                  adsl_memship_desc_prev = *aadsl_memship_desc;
                  aadsl_memship_desc     = &(*aadsl_memship_desc)->adsc_next_val;
              } // while (aadsl_memship_desc)

              if (bol_add == TRUE)
              { // insert the new element...
                // is it the first insert?
                if (adsp_co_ldap->adsc_memship_desc == NULL)
                { // yes, prepare structure...
                  adsp_co_ldap->adsc_memship_desc = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                  memset((void *)adsp_co_ldap->adsc_memship_desc, int(0), sizeof(struct dsd_ldap_val));

                  aadsl_memship_desc     = &adsp_co_ldap->adsc_memship_desc;
                  adsl_memship_desc_prev = *aadsl_memship_desc;

                  adsl_memship_desc_prev->iec_chs_val = dsl_co_ldap_memof.adsc_attr_desc->iec_chs_dn;
                  adsl_memship_desc_prev->imc_len_val = dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn;
                  adsl_memship_desc_prev->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                           dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn);         
                  memcpy((void *)adsl_memship_desc_prev->ac_val, 
                         (void *)dsl_co_ldap_memof.adsc_attr_desc->ac_dn, 
                         dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn);
                }
                else
                { // no...
                  adsl_memship_desc_prev->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof( struct dsd_ldap_val));
                  memset((void *)adsl_memship_desc_prev->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));
       
                  adsl_memship_desc_prev->adsc_next_val->iec_chs_val = dsl_co_ldap_memof.adsc_attr_desc->iec_chs_dn;
                  adsl_memship_desc_prev->adsc_next_val->imc_len_val = dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn;
                  adsl_memship_desc_prev->adsc_next_val->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                          dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn);         
                  memcpy((void *)adsl_memship_desc_prev->adsc_next_val->ac_val, 
                         (void *)dsl_co_ldap_memof.adsc_attr_desc->ac_dn, 
                         dsl_co_ldap_memof.adsc_attr_desc->imc_len_dn);
                }
              } // add (true)

              // test next entry 
              dsl_co_ldap_memof.adsc_attr_desc = dsl_co_ldap_memof.adsc_attr_desc->adsc_next_attr_desc;
          } // while (dsl_co_ldap.adsc_attr_desc)
        } // success (search groups)

        // step to the next 'namingcontext'
        adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
   } // end of while('namingcontexts')


   // have we anything to set up in the membership-structure?
   if (adsp_co_ldap->adsc_memship_desc == NULL)
   { // nothing found, set error!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
     iml_rc = ied_ldap_failure;
   }


   // restore bind context
   if (iml_rc_bind == ied_ldap_success)
   {
     struct dsd_unicode_string dsl_userid = {dsl_co_ldap_bind.ac_userid, 
                                             dsl_co_ldap_bind.imc_len_userid, 
                                             dsl_co_ldap_bind.iec_chs_userid};
     struct dsd_unicode_string dsl_passwd = {dsl_co_ldap_bind.ac_passwd, 
                                             dsl_co_ldap_bind.imc_len_passwd, 
                                             dsl_co_ldap_bind.iec_chs_passwd};

     m_aux_bind_simple(&dsl_userid, &dsl_passwd);
   }  

   return iml_rc;

} //dsd_ldap::m_ldap_get_members()


/**
 * Private class function:  dsd_ldap::m_ldap_get_members_nested()
 *
 * Returns a list of all group memberships of an entry (user or group). In contrast to m_ldap_get_members()
 * the function returns the membership of groups to other groups. The maximum depth of scanning is
 * controlled by <search-nested-groups-level>.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_get_members_nested( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   LDAP_REQ_STRUC(dsl_co_ldap)
   LDAP_REQ_STRUC(dsl_co_ldap_sear)
   LDAP_REQ_STRUC(dsl_co_ldap_bind)

   int   iml_rc (ied_ldap_success), 
         iml_rc_bind (m_ldap_get_bind(&dsl_co_ldap_bind, TRUE /*internal use of the password*/));

   BOOL  bol_param_dn (TRUE);
   void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;

#ifdef _DEBUG   
//   adsp_co_ldap->amc_aux     = &ms_aux_per_mem;     // storage subroutine 
//   adsp_co_ldap->vpc_userfld = this;
#endif

   if (!adsp_co_ldap->imc_len_dn || adsp_co_ldap->ac_dn == NULL)
   { // we have to use the actual bound user's DN
     bol_param_dn = FALSE;
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect(this->ads_ldap_group) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   if (!bol_param_dn)
                                     BIND_WITH_DN()
      default:                     break;
   } // end of switch


   // set membership-value to return
   adsp_co_ldap->adsc_memship_desc = NULL;
   adsp_co_ldap->adsc_attr_desc    = NULL;
   
   // set request structure for ied_co_ldap_get_membership()
   dsl_co_ldap.iec_co_ldap = ied_co_ldap_get_membership;
   dsl_co_ldap.amc_aux     = adsp_co_ldap->amc_aux;     
   dsl_co_ldap.vpc_userfld = adsp_co_ldap->vpc_userfld;

   if (bol_param_dn)
   { // use the parameter DN
     dsl_co_ldap.ac_dn      = adsp_co_ldap->ac_dn;
     dsl_co_ldap.imc_len_dn = adsp_co_ldap->imc_len_dn;
     dsl_co_ldap.iec_chs_dn = adsp_co_ldap->iec_chs_dn;
   }
   else
   { // use the already bound user
     dsl_co_ldap.ac_dn      = this->achr_dn;
     dsl_co_ldap.imc_len_dn = this->im_len_dn;
     dsl_co_ldap.iec_chs_dn = ied_chs_utf_8;
   }


   // trace message LDAP0041T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 41, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Members(nested) Scope=%s DN=\"%.*(.*)s\" ",
                                  this->ds_ldap_trace.m_translate( (int)adsp_co_ldap->iec_sear_scope, dsd_trace::S_SEARCH_SCOPE ),
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none" );

   iml_rc = m_ldap_get_members(&dsl_co_ldap);  

   if (iml_rc == ied_ldap_success && dsl_co_ldap.adsc_memship_desc)
   { 
     // set bind to search administrator account and scan group dependencies...
     if (m_aux_bind_admin() != ied_ldap_success)
       // error; we can't execute the ldap-search!
       return ied_ldap_failure;


     void *avol_1;

     struct dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);
     struct dsd_ldap_val      *adsl_memship (dsl_co_ldap.adsc_memship_desc),
                              *adsl_namingcontexts;

     dsl_co_ldap_sear.iec_co_ldap      = ied_co_ldap_search;
     dsl_co_ldap_sear.iec_sear_scope   = ied_sear_sublevel;  // search at the baseObject and all sub-levels
     dsl_co_ldap_sear.ac_attrlist      = (char *)"objectclass";
     dsl_co_ldap_sear.imc_len_attrlist = sizeof "objectclass" - 1;
     dsl_co_ldap_sear.iec_chs_attrlist = ied_chs_utf_8;

GROUPLIST_NEXT:
     // set search filter (using templates)...
     dsl_co_ldap_sear.iec_chs_filter  = ied_chs_utf_8;
     dsl_co_ldap_sear.imc_len_filter  = sizeof "(&(objectClass=)())" - 1 + adsl_memship->imc_len_val + 1/*"="*/;
     dsl_co_ldap_sear.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap_sear.imc_len_filter += adsl_templ->imc_len_mship_attr ? adsl_templ->imc_len_mship_attr : sizeof "memberOf" - 1/*default*/;
     dsl_co_ldap_sear.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap_sear.imc_len_filter );

     memcpy((void *)dsl_co_ldap_sear.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
     avol_1 = dsl_co_ldap_sear.ac_filter + sizeof "(&(objectClass=" - 1;

     if (adsl_templ->imc_len_group_attr)
     { 
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *(char *)avol_1 = '*';
       avol_1 = (char *)avol_1 + 1;
     }
     
     memcpy((void *)avol_1, (const void *)")(", sizeof ")(" - 1 );
     avol_1 = (char *)avol_1 + sizeof ")(" - 1;

     if (adsl_templ->imc_len_mship_attr)
     { 
       memcpy((void *)avol_1, (const void *)adsl_templ->achc_mship_attr, adsl_templ->imc_len_mship_attr );
       *((char *)avol_1 + adsl_templ->imc_len_mship_attr) = '=';
       avol_1 = (char *)avol_1 + adsl_templ->imc_len_mship_attr + 1;
     }
     else
     { // default-attribute: "memberOf="
       memcpy((void *)avol_1, (const void *)"memberOf=", sizeof "memberOf=" - 1 );
       avol_1 = (char *)avol_1 + sizeof "memberOf=" - 1;
     }

     memcpy((void *)avol_1, (const void *)adsl_memship->ac_val, adsl_memship->imc_len_val);
     avol_1 = (char *)avol_1 + adsl_memship->imc_len_val;
     memcpy((void *)avol_1, (const void *)"))", sizeof "))" - 1 );

     // perform the search-request...
     adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;

     while (adsl_namingcontexts)
     {    // use this 'namingcontext' for searching entries...
          dsl_co_ldap_sear.ac_dn      = adsl_namingcontexts->ac_val;
          dsl_co_ldap_sear.imc_len_dn = adsl_namingcontexts->imc_len_val;
          dsl_co_ldap_sear.iec_chs_dn = adsl_namingcontexts->iec_chs_val;  // always set to utf-8

          if (m_ldap_search( &dsl_co_ldap_sear, TRUE/*attr only*/) == ied_ldap_success)
          { 
            // we have found nested groups, include them if not yet added
            BOOL  bol_add (FALSE);
            struct dsd_ldap_val **aadsl_memship_desc = NULL;
            struct dsd_ldap_val  *adsl_memship_desc_prev (NULL);

            while (dsl_co_ldap_sear.adsc_attr_desc)
            {
                 bol_add = TRUE;
                 aadsl_memship_desc     = &dsl_co_ldap.adsc_memship_desc; 
                 adsl_memship_desc_prev = *aadsl_memship_desc;           
            
                 while (*aadsl_memship_desc)
                 { 
                     // compare all entries inserted so far...
                     if ((*aadsl_memship_desc)->imc_len_val == dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn &&
                         !m_hl_memicmp((const void *)(*aadsl_memship_desc)->ac_val, 
                                       (const void *)dsl_co_ldap_sear.adsc_attr_desc->ac_dn,
                                       dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn))
                     { // value already added!
                       bol_add = FALSE;
                       break;
                     }

                     adsl_memship_desc_prev = *aadsl_memship_desc;
                     aadsl_memship_desc     = &(*aadsl_memship_desc)->adsc_next_val;
                 } // while (aadsl_memship_desc)

                 if (bol_add == TRUE)
                 { // insert the new element...
                   adsl_memship_desc_prev->adsc_next_val = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                             sizeof(struct dsd_ldap_val));
                   memset((void *)adsl_memship_desc_prev->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));
          
                   adsl_memship_desc_prev->adsc_next_val->iec_chs_val = dsl_co_ldap_sear.adsc_attr_desc->iec_chs_dn;
                   adsl_memship_desc_prev->adsc_next_val->imc_len_val = dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn;
                   adsl_memship_desc_prev->adsc_next_val->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, 
                                                                                           dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn);
                   memcpy((void *)adsl_memship_desc_prev->adsc_next_val->ac_val, 
                          (void *)dsl_co_ldap_sear.adsc_attr_desc->ac_dn, 
                          dsl_co_ldap_sear.adsc_attr_desc->imc_len_dn);
                 } // add (true)

                 // test next entry 
                 dsl_co_ldap_sear.adsc_attr_desc = dsl_co_ldap_sear.adsc_attr_desc->adsc_next_attr_desc;
            } // while (dsl_co_ldap.adsc_memship_desc)           
          } // success (search groups)

          // step to the next 'namingcontext'
          adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
     } // end of while('namingcontexts')


     // step to the next entry in the membership list
     adsl_memship = adsl_memship->adsc_next_val;
     if (adsl_memship)
       goto GROUPLIST_NEXT;

      
   } // success(m_ldap_get_membership())


   // have we anything to set up in the membership-structure?
   adsp_co_ldap->adsc_memship_desc = dsl_co_ldap.adsc_memship_desc;

   if (adsp_co_ldap->adsc_memship_desc == NULL)
   { // nothing found, set error!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
     iml_rc = ied_ldap_failure;
   }

   // restore bind context
   if (iml_rc_bind == ied_ldap_success)
   {
     struct dsd_unicode_string dsl_userid = {dsl_co_ldap_bind.ac_userid, 
                                             dsl_co_ldap_bind.imc_len_userid, 
                                             dsl_co_ldap_bind.iec_chs_userid};
     struct dsd_unicode_string dsl_passwd = {dsl_co_ldap_bind.ac_passwd, 
                                             dsl_co_ldap_bind.imc_len_passwd, 
                                             dsl_co_ldap_bind.iec_chs_passwd};

     m_aux_bind_simple(&dsl_userid, &dsl_passwd);
   }  

   return iml_rc;

} //dsd_ldap::m_ldap_get_members_nested()


/**
 * Private class function:  dsd_ldap::m_get_msgid()
 *
 * Returns a new LDAP message id.
 *
 * @return   int  LDAP message id
 */
int dsd_ldap::m_get_msgid()
{
   return ++this->im_ldap_msgid;

} // dsd_ldap::m_get_msgid()


/**
 * Private class function:  dsd_ldap::m_ldap_add()
 *
 * Initiates a ldap extended add operation.
 *
 *      ASN.1:
 *      AddRequest ::= [APPLICATION 8] SEQUENCE { entry       LDAPDN,
 *                                                attributes  AttributeList
 *                                              }
 *
 *                     AttributeList ::= SEQUENCE of attribute Attribute
 *
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Remarks:\n
 * We only use the 'replace'-operation, because it includes the 'add'. The use of 'delete' to delete
 * partial values is not recommended, instead of the attribute with all its values should be read and
 * replaced over this 'modify'-request.\n\n
 *
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_add( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search
#define ATTR_DESC  adsp_co_ldap->adsc_attr_desc


   int  iml_rc = ied_ldap_success;

   struct dsd_ldap_attr_desc *adsl_attr_desc = adsp_co_ldap->adsc_attr_desc;

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-search!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_add_err );
                                     return ied_ldap_no_bind;
                                   }

                                     BIND_WITH_DN()

      default:                     break;
   } // end of switch

   // trace message LDAP0050T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 50, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Add DN=\"%.*(.*)s\" Attribute(s)=\"%.*(.*)s\" Value(s)=\"%.*(.*)s\"",
                                  ATTR_DESC->ac_dn ? ATTR_DESC->imc_len_dn : sizeof "none" - 1,
                                  ATTR_DESC->ac_dn ? ATTR_DESC->iec_chs_dn : ied_chs_ascii_850,
                                  ATTR_DESC->ac_dn ? ATTR_DESC->ac_dn : "none",
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->imc_len_attr : sizeof "none" - 1,
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->iec_chs_attr : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->ac_attr : "none",
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->dsc_val.imc_len_val : sizeof "none" - 1,
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->dsc_val.iec_chs_val : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr ? ATTR_DESC->adsc_attr->dsc_val.ac_val : "none" );

   // build add request...
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // set a sequence of attributes to add
   while (adsl_attr_desc)
   {
      // set the dn for adding attributes...
      iml_rc = this->m_aux_add( adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn, adsl_attr_desc->adsc_attr );
      if (iml_rc != ied_ldap_success)
        return iml_rc;

      // step to the next attribute description...
      adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;
   } // while (attributes)

   return ied_ldap_success;

#undef ATTR_DESC
} // dsd_ldap::m_ldap_add()


/**
 * Private class function:  dsd_ldap::m_ldap_compare()
 *
 * Initiates a ldap compare operation.
 *
 *      ASN.1:
 *      CompareRequest ::= [APPLICATION 14] SEQUENCE { entry   LDAPDN,
 *                                                     ava     AttributeValueAssertion
 *                                                   }
 *
 *                          AttributeValueAssertion ::= SEQUENCE { attributeDesc   AttributeDescription (LDAPString)
 *                                                                 assertionValue  AssertionValue (OCTET STRING)
 *                                                               }
 *
 *      Fields of the CompareRequest are:
 *
 * entry:  the name of the entry to be compared.
 * ava:    holds the attribute value assertion to be compared.
 *
 *
 * The resultCode is set to \b compareTrue, \b compareFalse, or an appropriate error.
 * 'compareTrue' indicates that the assertion value in the ava field matches a value
 * of the attribute or subtype according to the attribute's EQUALITY matching rule.
 * 'compareFalse' indicates that the assertion value in the ava field and the values
 * of the attribute or subtype did not match. Other result codes indicate either that
 * the result of the comparison was undefined or that some error occurred.
 *
 * @param[in,out]  adsp_co_ldap   request structure
 *
 * @return         error         (\b ied_ldap_failure) ,
 *                 compare true  (\b ied_ldap_cmp_true),
 *                 compare false (\b ied_ldap_cmp_false) or
 *                 send blocked  (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_compare( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define ATTR_DESC  adsp_co_ldap->adsc_attr_desc

   int  iml_rc;

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-compare!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-compare!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_compare_err );
                                     return ied_ldap_no_bind;
                                   }

                                     BIND_WITH_DN()

      default:                     break;
   } // end of switch

   // trace message LDAP0061T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 61, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Compare DN=\"%.*(.*)s\" Attribute=\"%.*(.*)s\" Value=\"%.*(.*)s\"",
                                  ATTR_DESC->ac_dn ? ATTR_DESC->imc_len_dn : sizeof "none" - 1,
                                  ATTR_DESC->ac_dn ? ATTR_DESC->iec_chs_dn : ied_chs_ascii_850,
                                  ATTR_DESC->ac_dn ? ATTR_DESC->ac_dn : "none",
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->imc_len_attr : sizeof "none" - 1,
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->iec_chs_attr : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->ac_attr : "none",
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.imc_len_val : sizeof "none" - 1,
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.iec_chs_val : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.ac_val : "none" );

   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // build the compare request...
   LDAPREQ_COMPARE(this->ds_ldapreq)

   if (this->ds_asn1.m_printf( "{it{s{ss}}}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               ATTR_DESC->ac_dn, ATTR_DESC->imc_len_dn, int(ATTR_DESC->iec_chs_dn) /*s*/,
                               ATTR_DESC->adsc_attr->ac_attr,
                               ATTR_DESC->adsc_attr->imc_len_attr,
                               int(ATTR_DESC->adsc_attr->iec_chs_attr) /*s*/,
                               ATTR_DESC->adsc_attr->dsc_val.ac_val,
                               ATTR_DESC->adsc_attr->dsc_val.imc_len_val,
                               int(ATTR_DESC->adsc_attr->dsc_val.iec_chs_val) /*s*/) == LASN1_ERROR)
   { // error; we can't execute the ldap-compare!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_compare_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL?
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_compare_err /*apicode*/ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for compare response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_compare_err /*apicode*/ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (COMPARE-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq );
   if (iml_rc != ied_ldap_success)
   {
     if (iml_rc == ied_ldap_cmp_true || iml_rc == ied_ldap_cmp_false)
       return iml_rc;

     // @todo: error message to event viewer or something else...
       this->ds_ldap_error.m_set_apicode( ied_ldap_compare_err );
       return ied_ldap_failure;
     }

   return ied_ldap_success;

#undef COMP_ATTR
} // dsd_ldap::m_ldap_compare()


/**
 * Private class function:  dsd_ldap::m_ldap_modify()
 *
 * Initiates a ldap modify operation.
 *
 *     ASN.1:
 *     ModfiyRequest ::= [APPLICATION 6] SEQUENCE { object   LDAPDN,
 *                                                  changes  SEQUENCE OF change SEQUENCE
 *                                                                              { operation     ENUMERATED
 *                                                                                              { add     (0),
 *                                                                                                delete  (1),
 *                                                                                                replace (2),
 *                                                                                                ...
 *                                                                                              },
 *                                                                                modification  PartialAttribute
 *                                                                              }
 *                                               }
 *
 *                   PartialAttribute ::= SEQUENCE { type   AttributeDescription (LDAPString),
 *                                                   vals   SET OF value  AttributeValue (OCTETString)
 *                                                 }
 *
 *
 * @param[in,out]  adsp_co_ldap   request structure
 *
 * @return         error        (\b ied_ldap_failure),
 *                 successful   (\b ied_ldap_success) or
 *                 send blocked (\b ied_ldap_send_blocked)
 *
 * Remarks:\n
 * We only use the 'replace'-operation, because it includes the 'add'. The use of 'delete' to delete
 * partial values is not recommended, instead of the attribute with all its values should be read and
 * replaced over this 'modify'-request.\n\n
 *
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_modify( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search
#define ATTR_DESC  adsp_co_ldap->adsc_attr_desc


   int  iml_rc = ied_ldap_success;
   int  iml_cmp;

   struct dsd_ldap_attr_desc *adsl_attr_desc (adsp_co_ldap->adsc_attr_desc);
   struct dsd_ldap_attr      *adsl_attr;
   struct dsd_ldap_val       *adsl_val_1, *adsl_val_2;

   LDAP_REQ_STRUC(dsl_co_ldap)


   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-search!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_modify_err );
                                     return ied_ldap_no_bind;
                                   }

                                   BIND_WITH_DN()

      default:                     break;
   } // end of switch


   enum ied_ldap_attr_def  iel_attr (ied_ldap_attr_undef);

   // trace message LDAP0060T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
   {
     this->m_aux_is_singlevalued(ATTR_DESC->adsc_attr, &iel_attr);
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 60, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Modify DN=\"%.*(.*)s\" Attribute(s)=\"%.*(.*)s\" %s nextAttrDesc=%u nextAttr=%u Old-Value(s)=\"%.*(.*)s\" New-Value(s)=\"%.*(.*)s\"",
                                  ATTR_DESC->ac_dn ? ATTR_DESC->imc_len_dn : sizeof "none" - 1,                            /* DN=.. .*/
                                  ATTR_DESC->ac_dn ? ATTR_DESC->iec_chs_dn : ied_chs_ascii_850,
                                  ATTR_DESC->ac_dn ? ATTR_DESC->ac_dn : "none",
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->imc_len_attr : sizeof "none" - 1,  /* Attribute(s)=... */
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->iec_chs_attr : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr->ac_attr ? ATTR_DESC->adsc_attr->ac_attr : "none",
                                  iel_attr == ied_ldap_attr_single ? "Singlevalued" : (iel_attr == ied_ldap_attr_multi ? "Multivalued" : "undefined"),  
                                  ATTR_DESC->adsc_next_attr_desc, ATTR_DESC->adsc_attr->adsc_next_attr,
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val_old ? ATTR_DESC->adsc_attr->dsc_val.imc_len_val_old : sizeof "none" - 1,  /* Old-Value(s)=... */
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val_old ? ATTR_DESC->adsc_attr->dsc_val.iec_chs_val_old : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val_old ? ATTR_DESC->adsc_attr->dsc_val.ac_val_old : "none",
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.imc_len_val : sizeof "none" - 1,          /* New-Value(s)=... */
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.iec_chs_val : ied_chs_ascii_850,
                                  ATTR_DESC->adsc_attr->dsc_val.ac_val ? ATTR_DESC->adsc_attr->dsc_val.ac_val : "none" );
   } // end of trace message

   // build modify request...
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // valid input parameters?
   if (adsl_attr_desc == NULL)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_modify_err );
     return ied_ldap_failure;
   }


   // step through the attribute list...
   do
   {  // ask for the attribute type (single- or multivalued)...
      iel_attr = ied_ldap_attr_undef;

      adsl_attr = adsl_attr_desc->adsc_attr;
      if (this->m_aux_is_singlevalued( adsl_attr, &iel_attr ) != ied_ldap_success)
      { // error; we didn't find this attribute! The error code is set by m_aux_is_singlevalued()
        // this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_modify_err );
        return ied_ldap_failure;
      }

      // now, we have different processing for single- and multivalued attributes...
      switch (iel_attr)
      {
        case ied_ldap_attr_single:
            {
              ied_ldap_mod_def  iel_mod (ied_ldap_mod_add);

              // test for DELETE...
              if (adsl_attr_desc->adsc_attr->dsc_val.imc_len_val == 0)
              { // DELETE...
                   iel_mod = ied_ldap_mod_delete;
              }
              else
              { // test for ADD or REPLACE...
                dsl_co_ldap.iec_co_ldap = ied_co_ldap_lookup;
                dsl_co_ldap.ac_dn       = adsl_attr_desc->ac_dn;
                dsl_co_ldap.imc_len_dn  = adsl_attr_desc->imc_len_dn;
                dsl_co_ldap.iec_chs_dn  = adsl_attr_desc->iec_chs_dn;
                dsl_co_ldap.ac_attrlist      = adsl_attr->ac_attr;
                dsl_co_ldap.iec_chs_attrlist = adsl_attr->iec_chs_attr;
                dsl_co_ldap.imc_len_attrlist = adsl_attr->imc_len_attr;
                dsl_co_ldap.adsc_attr_desc   = NULL;

                // lookup for the modify-mode...
   	            if (this->m_ldap_lookup(&dsl_co_ldap, TRUE /*check attribute only*/) == ied_ldap_success && 
                    dsl_co_ldap.adsc_attr_desc                                                           &&
                    dsl_co_ldap.adsc_attr_desc->adsc_attr                                                && 
                    dsl_co_ldap.adsc_attr_desc->adsc_attr->imc_len_attr)
                { // attribute found -> REPLACE
                  iel_mod = ied_ldap_mod_replace;
                }

                // the MSAD-'unicodePwd'-attribute needs some special operation...
                if (this->im_ldap_type == ied_sys_ldap_msad &&
                    m_cmpi_vx_vx( &iml_cmp, (void *)adsl_attr_desc->adsc_attr->ac_attr, adsl_attr_desc->adsc_attr->imc_len_attr, adsl_attr_desc->adsc_attr->iec_chs_attr,
                                  (void *)"unicodePwd", sizeof "unicodePwd" - 1, ied_chs_utf_8 ) == TRUE)
                { // did we anything found?
                  if (!iml_cmp)
                  { // yes, convert the attribute value to utf-16 (le)
                    this->m_aux_msad_val( adsl_attr->dsc_val.ac_val, adsl_attr->dsc_val.imc_len_val, adsl_attr->dsc_val.iec_chs_val,
                                          &adsl_attr->dsc_val.ac_val, &adsl_attr->dsc_val.imc_len_val, &adsl_attr->dsc_val.iec_chs_val );
                    // MSAD password change works with replace only (or 'del' followed by 'add' in a single request only!)
                    iel_mod = ied_ldap_mod_replace;
                  }
                } // end ('unicodePwd')
              } // end (ADD or REPLACE)

              // set the dn for modifying attributes...
              adsl_attr = adsl_attr_desc->adsc_attr;

              iml_rc = this->m_aux_modify( adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn, adsl_attr, iel_mod );
              if (iml_rc != ied_ldap_success)
                return iml_rc; // replaced: ied_ldap_failure;
            } // end of 'single-valued'-processing
            break;

        case ied_ldap_attr_multi:
            {
              ied_ldap_mod_def  iel_mod (ied_ldap_mod_add);

              // test for DELETE...
              adsl_attr = adsl_attr_desc->adsc_attr;
              if (adsl_attr_desc->adsc_attr->dsc_val.imc_len_val == 0)
              { // DELETE...
                iel_mod = ied_ldap_mod_delete;

                // should we delete the whole 'multivalued'-entry?
                if (adsl_attr_desc->adsc_attr->dsc_val.imc_len_val_old)
                { // no, delete the selected value only...
                  adsl_attr = (struct dsd_ldap_attr *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_attr) );
                  adsl_attr->ac_attr        = adsl_attr_desc->adsc_attr->ac_attr;
                  adsl_attr->imc_len_attr   = adsl_attr_desc->adsc_attr->imc_len_attr;
                  adsl_attr->iec_chs_attr   = adsl_attr_desc->adsc_attr->iec_chs_attr;
                  adsl_attr->adsc_next_attr = NULL;
                  adsl_attr->dsc_val.ac_val        = adsl_attr_desc->adsc_attr->dsc_val.ac_val_old;
                  adsl_attr->dsc_val.imc_len_val   = adsl_attr_desc->adsc_attr->dsc_val.imc_len_val_old;
                  adsl_attr->dsc_val.iec_chs_val   = adsl_attr_desc->adsc_attr->dsc_val.iec_chs_val_old;
                  adsl_attr->dsc_val.adsc_next_val = NULL;

                  // have we more than one entry to delete?
                  adsl_val_1 = adsl_attr_desc->adsc_attr->dsc_val.adsc_next_val;
                  adsl_val_2 = &adsl_attr->dsc_val;
                  while (adsl_val_1)
                  {  // yes, allocate a next structure...
                     adsl_val_2->adsc_next_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_val) );
                     memset((void *)adsl_val_2->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                     adsl_val_2 = adsl_val_2->adsc_next_val;
                     adsl_val_2->ac_val        = adsl_val_1->ac_val_old;
                     adsl_val_2->imc_len_val   = adsl_val_1->imc_len_val_old;
                     adsl_val_2->iec_chs_val   = adsl_val_1->iec_chs_val_old;
                     // do we have more to delete?
                     adsl_val_1 = adsl_val_1->adsc_next_val;
                  } // while (val)
                }
                else
                  // yes, delete the whole entry...
                  adsl_attr = adsl_attr_desc->adsc_attr;
              }
              else
              { // 'dsc_val' is set, test for ADD or REPLACE...
                dsl_co_ldap.iec_co_ldap = ied_co_ldap_lookup;
                dsl_co_ldap.ac_dn       = adsl_attr_desc->ac_dn;
                dsl_co_ldap.imc_len_dn  = adsl_attr_desc->imc_len_dn;
                dsl_co_ldap.iec_chs_dn  = adsl_attr_desc->iec_chs_dn;
                dsl_co_ldap.ac_attrlist      = adsl_attr->ac_attr;
                dsl_co_ldap.iec_chs_attrlist = adsl_attr->iec_chs_attr;
                dsl_co_ldap.imc_len_attrlist = adsl_attr->imc_len_attr;
                dsl_co_ldap.adsc_attr_desc   = NULL;

                // lookup for the modify-mode...
     	        if (this->m_ldap_lookup( &dsl_co_ldap ) == ied_ldap_success && dsl_co_ldap.adsc_attr_desc &&
                    dsl_co_ldap.adsc_attr_desc->adsc_attr && dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val)
                { // attribute found -> should the value be added or replaced ?
                  // a replace must be done in a combination of delete followed by an add!
                  if (adsl_attr_desc->adsc_attr->dsc_val.imc_len_val_old)
                  { // replace...
                    adsl_attr = (struct dsd_ldap_attr *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_attr) );
                    adsl_attr->ac_attr        = adsl_attr_desc->adsc_attr->ac_attr;
                    adsl_attr->imc_len_attr   = adsl_attr_desc->adsc_attr->imc_len_attr;
                    adsl_attr->iec_chs_attr   = adsl_attr_desc->adsc_attr->iec_chs_attr;
                    adsl_attr->adsc_next_attr = NULL;
                    adsl_attr->dsc_val.ac_val        = adsl_attr_desc->adsc_attr->dsc_val.ac_val_old;
                    adsl_attr->dsc_val.imc_len_val   = adsl_attr_desc->adsc_attr->dsc_val.imc_len_val_old;
                    adsl_attr->dsc_val.iec_chs_val   = adsl_attr_desc->adsc_attr->dsc_val.iec_chs_val_old;
                    adsl_attr->dsc_val.adsc_next_val = NULL;

                    // have we more than one entry to replace?
                    adsl_val_1 = adsl_attr_desc->adsc_attr->dsc_val.adsc_next_val;
                    adsl_val_2 = &adsl_attr->dsc_val;
                    while (adsl_val_1)
                    {  // yes, allocate a next structure...
                       adsl_val_2->adsc_next_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_val));
                       memset((void *)adsl_val_2->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                       adsl_val_2 = adsl_val_2->adsc_next_val;
                       adsl_val_2->ac_val        = adsl_val_1->ac_val_old;
                       adsl_val_2->imc_len_val   = adsl_val_1->imc_len_val_old;
                       adsl_val_2->iec_chs_val   = adsl_val_1->iec_chs_val_old;
                       // do we have more to delete?
                       adsl_val_1 = adsl_val_1->adsc_next_val;
                    } // while (val)

                    iml_rc = this->m_aux_modify( adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn, adsl_attr, ied_ldap_mod_delete );
                    if (iml_rc != ied_ldap_success)
                      return iml_rc; // replaced: ied_ldap_failure;

                    // set list of values to add...
                    adsl_attr = adsl_attr_desc->adsc_attr;
                  }
                }
              } // end (ADD or REPLACE)

              // set the dn for modifying attributes...
              iml_rc = this->m_aux_modify( adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn, adsl_attr, iel_mod );
              if (iml_rc != ied_ldap_success)
                return iml_rc; // replaced: ied_ldap_failure;

            } // end of 'multivalued'-processing
            break;

        default:
            // error; we didn't find the attribute type!
            this->ds_ldap_error.m_set_error( ied_ldap_undef_attr_type, ied_ldap_modify_err );
            return ied_ldap_failure;
      } // end of switch()

      // step to the next attribute description...
      adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;

   } while (adsl_attr_desc);

   return ied_ldap_success;

#undef ATTR_DESC
} // dsd_ldap::m_ldap_modify()


/**
 * Private class function:  dsd_ldap::m_ldap_modify_dn()
 *
 * The Modify DN operation allows to change the relative distinguished name (RDN) of an entry in the directory 
 * and/or to move a subtree of entries to a new location in the directory. After this operation it checks for 
 * membership in groups at the old dn and deletes them.
 *
 *      ASN.1:
 *      ModfiyDNRequest ::= [APPLICATION 12] SEQUENCE { entry         LDAPDN,
 *                                                      newrdn        RelativeLDAPDN,
 *                                                      deleteoldrdn  BOOLEAN (default: TRUE)
 *                                                      newSuperior   [0] LDAPDN optional
 *                                                    }
 *
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error        (\b ied_ldap_failure),
 *                 successful   (\b ied_ldap_success) or
 *                 send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_modify_dn( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   char  *achl_newrdn, *achl_superior;
   int    iml_len_newrdn, iml_len_superior;
   int    iml_rc = ied_ldap_success;

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-search!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_modify_dn_err );
                                     return ied_ldap_no_bind;
                                   }

                                     BIND_WITH_DN()

      default:                     break;
   } // end of switch

   // trace message LDAP0070T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 70, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "ModifyDN DN=\"%.*(.*)s\" DN-new=\"%.*(.*)s\"",
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none",
                                  adsp_co_ldap->ac_newrdn ? adsp_co_ldap->imc_len_newrdn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_newrdn ? adsp_co_ldap->iec_chs_newrdn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_newrdn ? adsp_co_ldap->ac_newrdn : "none" );

   // build modifyDN-request...
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // build modifydn-request...
   LDAPREQ_MODIFYDN(this->ds_ldapreq)

   // do we need a 'newSuperior' ?
   iml_len_superior = (adsp_co_ldap->imc_len_newrdn < 0) ? (int)strnlen( (const char *)adsp_co_ldap->imc_len_newrdn, D_LDAP_MAX_STRLEN )
                                                         : adsp_co_ldap->imc_len_newrdn;
   achl_superior    = adsp_co_ldap->ac_newrdn;

   while (isspace((unsigned char)*achl_superior) && iml_len_superior)
   {  // ignore spaces at the beginning...
      ++achl_superior;
      --iml_len_superior;
   }
   // set start address for scan
   achl_newrdn    = achl_superior;
   iml_len_newrdn = iml_len_superior;

   while (iml_len_superior)
   {  // search for ','-delimiter
      if (_iscomma(*achl_superior))
      { // delimiter found
        iml_len_newrdn = int(achl_superior - achl_newrdn);  // points before ','
        ++achl_superior;
        --iml_len_superior;
        while (isspace((unsigned char)*achl_superior) && iml_len_superior)
        { // ignore spaces after the ','...
          ++achl_superior;
          --iml_len_superior;
        }
        while (isspace((unsigned char)*(achl_newrdn + iml_len_newrdn - 1)) && iml_len_newrdn)
          // ignore spaces before the ','...
          --iml_len_newrdn;

        break;
      }
      ++achl_superior;
      --iml_len_superior;
   } // end of while()

   // build the asn.1-formatted modifydn request...
   if (iml_len_superior)
     iml_rc = this->ds_asn1.m_printf( "{it{ssbts}}",
                                      this->ds_ldapreq.imc_msgid /*i*/,
                                      this->ds_ldapreq.imc_req /*t*/,
                                      adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/,
                                      achl_newrdn, iml_len_newrdn, int(adsp_co_ldap->iec_chs_newrdn) /*s*/,
                                      TRUE /*b*/, LDAP_TAG_NEWSUPERIOR /*t*/,
                                      achl_superior, iml_len_superior, int(adsp_co_ldap->iec_chs_newrdn) /*s*/);
   else
     iml_rc = this->ds_asn1.m_printf( "{it{ssb}}",
                                      this->ds_ldapreq.imc_msgid /*i*/,
                                      this->ds_ldapreq.imc_req /*t*/,
                                      adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/,
                                      achl_newrdn, iml_len_newrdn, int(adsp_co_ldap->iec_chs_newrdn) /*s*/,
                                      TRUE /*b*/ );

   if (iml_rc == LASN1_ERROR)
   { // error; we can't execute the ldap-modify!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_modify_dn_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_write;
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL?
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_modify_dn_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for modify response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_modify_dn_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (MODIFY-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_modify_dn_err );
     return ied_ldap_failure;
   }


   // look for group members and delete them...
   dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);

   if (adsl_templ->achc_member_attr && adsl_templ->imc_len_member_attr)
   { // to do the search we need a 'member'-attribute!
     LDAP_REQ_STRUC(dsl_co_ldap)
     dsl_co_ldap.iec_co_ldap    = ied_co_ldap_search;
     dsl_co_ldap.iec_sear_scope = ied_sear_sublevel;  
     dsl_co_ldap.ac_dn          = this->ads_ldap_entry->achc_base_dn;
     dsl_co_ldap.imc_len_dn     = this->ads_ldap_entry->imc_len_base_dn;
     dsl_co_ldap.iec_chs_dn     = ied_chs_utf_8;  
     
     // set search filter (using templates)...
     int iml_len_dn = (adsp_co_ldap->imc_len_dn < 0) ? (int)strnlen((const char *)adsp_co_ldap->ac_dn, D_LDAP_MAX_STRLEN)
                                                     : adsp_co_ldap->imc_len_dn;
     dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
     dsl_co_ldap.imc_len_filter = sizeof "(&(objectClass=)(=))" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_member_attr;
     dsl_co_ldap.imc_len_filter += iml_len_dn;
     dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_filter );

     memcpy((void *)dsl_co_ldap.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
     char *achl_1 = dsl_co_ldap.ac_filter + sizeof "(&(objectClass=" - 1;
       
     if (adsl_templ->imc_len_group_attr)
     { memcpy((void *)achl_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       achl_1 += adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *achl_1 = '*';
       achl_1++;
     }
     
     memcpy((void *)achl_1, (const void *)")(", sizeof ")(" - 1);
     achl_1 += sizeof ")(" - 1;
     memcpy((void *)achl_1, (const void *)adsl_templ->achc_member_attr, adsl_templ->imc_len_member_attr );
     achl_1 += adsl_templ->imc_len_member_attr;
     *achl_1 = '=';
     achl_1++;
     memcpy((void *)achl_1, (const void *)adsp_co_ldap->ac_dn, iml_len_dn);
     memcpy((void *)(achl_1 + iml_len_dn), (const void *)"))", sizeof "))" - 1);
       
     // set attribute-list ('member') 
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_member_attr;
     dsl_co_ldap.ac_attrlist      = adsl_templ->achc_member_attr;
       
     // perform the search-request('member')...
     if (this->m_ldap_search(&dsl_co_ldap) == ied_ldap_success && dsl_co_ldap.adsc_attr_desc)
     { // groups with the specified member' found
       // step through these groups and delete each member...
       struct dsd_ldap_attr_desc *adsl_attr_desc (dsl_co_ldap.adsc_attr_desc);
       struct dsd_ldap_attr  dsl_ldap_attr;
                             dsl_ldap_attr.ac_attr        = adsl_templ->achc_member_attr;
                             dsl_ldap_attr.imc_len_attr   = adsl_templ->imc_len_member_attr;
                             dsl_ldap_attr.iec_chs_attr   = ied_chs_utf_8;
                             dsl_ldap_attr.adsc_next_attr = NULL;
                             dsl_ldap_attr.dsc_val.adsc_next_val   = NULL;
                             dsl_ldap_attr.dsc_val.ac_val          = adsp_co_ldap->ac_dn;
                             dsl_ldap_attr.dsc_val.imc_len_val     = adsp_co_ldap->imc_len_dn;
                             dsl_ldap_attr.dsc_val.iec_chs_val     = adsp_co_ldap->iec_chs_dn;
                             dsl_ldap_attr.dsc_val.ac_val_old      = NULL;
                             dsl_ldap_attr.dsc_val.imc_len_val_old = 0;
                             dsl_ldap_attr.dsc_val.iec_chs_val_old = ied_chs_invalid;
       do
       { // delete this value
         if (adsl_attr_desc->adsc_attr)
           this->m_aux_modify(adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn,
                              &dsl_ldap_attr, ied_ldap_mod_delete /*ied_ldap_mod_def::*/);       

         // step to the next entry
         adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;
       } while (adsl_attr_desc);
     }
   } // template <member>

   return ied_ldap_success;

} // dsd_ldap::m_ldap_modify_dn()


/**
 * Private class function:  dsd_ldap::m_ldap_get_sysinfo()
 *
 * Returns informations about the used ldap server.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 * The member 'iec_type' of the structure 'dsd_ldap_sysinfo' returns the real server type in the case
 * of a generic-type (if already connected!).
 */
int dsd_ldap::m_ldap_get_sysinfo( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SYSINFO  adsp_co_ldap->adsc_sysinfo

   int iml_rc (ied_ldap_success);


   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       iml_rc = this->m_ldap_connect( this->ads_ldap_group );
                                   if (iml_rc == ied_ldap_success)
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   iml_rc = this->m_aux_bind_admin();
      default:                     break;
   } // end of switch


   if (iml_rc == ied_ldap_success)
   { // collect system informations...
	 void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;
     
	 SYSINFO = (struct dsd_ldap_sysinfo *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof(struct dsd_ldap_sysinfo));
     memset((void *)SYSINFO, int(0), sizeof(struct dsd_ldap_sysinfo));

     // set ip-address and port
     SYSINFO->imc_port           = this->ads_ldap_entry->imc_port;
     SYSINFO->adsc_target_ineta  = this->ads_ldap_entry->adsc_server_ineta;

     // set administrator name
     SYSINFO->imc_len_admin = this->ads_ldap_entry->imc_len_userid;
     SYSINFO->ac_admin      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, SYSINFO->imc_len_admin);
     memcpy((void *)SYSINFO->ac_admin, (const void *)this->ads_ldap_entry->achc_userid, SYSINFO->imc_len_admin);

     // set configured <base-dn>
     SYSINFO->adsc_base_dn_conf = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof(struct dsd_ldap_val) );
     memset((void *)SYSINFO->adsc_base_dn_conf, int(0), sizeof(struct dsd_ldap_val));

     if (this->ads_ldap_entry->imc_len_base_dn)
     {
       SYSINFO->adsc_base_dn_conf->ac_val      = this->ads_ldap_entry->achc_base_dn;
       SYSINFO->adsc_base_dn_conf->imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
       SYSINFO->adsc_base_dn_conf->iec_chs_val = ied_chs_utf_8;
     }

     // ask for the RootDSE, if not yet happened
     SYSINFO->adsc_base_dn = SYSINFO->adsc_base_dn_def = NULL;

     if (this->bo_RootDSE == FALSE)
       this->m_aux_search_RootDSE();  // don't check for any error(s) returned. That's bad luck!


     if (this->bo_RootDSE == TRUE)
     {
       if (this->ds_RootDSE.ads_namingcontexts)
       {
         struct dsd_ldap_val  *adsl_namingcontext (this->ds_RootDSE.ads_namingcontexts);
         struct dsd_ldap_val **aadsl_sysinfo_dn = &(SYSINFO->adsc_base_dn);
         struct dsd_ldap_val  *adsl_sysinfo_dn2 (NULL);


         while (adsl_namingcontext)
         {
           *aadsl_sysinfo_dn = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof(struct dsd_ldap_val));
           memset((void *)*aadsl_sysinfo_dn, int(0), sizeof(struct dsd_ldap_val));

           if (adsl_sysinfo_dn2)
             ((struct dsd_ldap_val *)(*aadsl_sysinfo_dn))->adsc_next_val = adsl_sysinfo_dn2;

           ((struct dsd_ldap_val *)(*aadsl_sysinfo_dn))->imc_len_val = adsl_namingcontext->imc_len_val;
           ((struct dsd_ldap_val *)(*aadsl_sysinfo_dn))->iec_chs_val = adsl_namingcontext->iec_chs_val;
           ((struct dsd_ldap_val *)(*aadsl_sysinfo_dn))->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, (*aadsl_sysinfo_dn)->imc_len_val);
           memcpy( (void *)(*aadsl_sysinfo_dn)->ac_val, (const void *)adsl_namingcontext->ac_val, (size_t)(*aadsl_sysinfo_dn)->imc_len_val );

           adsl_sysinfo_dn2 = *aadsl_sysinfo_dn;
           adsl_namingcontext = adsl_namingcontext->adsc_next_val;
         } // while()
       }

       if (this->ds_RootDSE.ads_defaultcontext)
       { 
         SYSINFO->adsc_base_dn_def = (struct dsd_ldap_val *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, sizeof(struct dsd_ldap_val));
         memset((void *)SYSINFO->adsc_base_dn_def, int(0), sizeof(struct dsd_ldap_val));

         SYSINFO->adsc_base_dn_def->imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
         SYSINFO->adsc_base_dn_def->iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
         SYSINFO->adsc_base_dn_def->ac_val      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, SYSINFO->adsc_base_dn_def->imc_len_val);
         memcpy( (void *)SYSINFO->adsc_base_dn_def->ac_val,
                 (const void *)this->ds_RootDSE.ads_defaultcontext->ac_val,
                 (size_t)SYSINFO->adsc_base_dn_def->imc_len_val );
       }  // 'defaultNamingContext'
     } // bo_RootDSE == TRUE


     // set the template configured in the xml-configuration
     SYSINFO->adsc_ldap_template = this->ads_ldap_entry->adsc_ldap_template;
     // set directory server type (if we have selected the generic template, we should try to
     // set the real server type !
     if (this->im_ldap_templ == ied_type_ldap_def(ied_sys_ldap_generic))
       // return the real server type...
       SYSINFO->iec_type = ied_type_ldap_def(this->im_ldap_type);
     else
       SYSINFO->iec_type = ied_type_ldap_def(this->im_ldap_templ);

   } // connect and bind ok!

   return iml_rc;

#undef SYSINFO
} // dsd_ldap::m_ldap_get_sysinfo()


/**
 * Private class function:  dsd_ldap::m_ldap_check_pwd_age()
 *
 * Returns informations about the user's password expire date.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
#define  HL_MSAD_UAC   "userAccountControl"                    

#define  HL_LDS_UAdis  "msDS-UserAccountDisabled"
#define  HL_LDS_PWDexp "msDS-UserPasswordExpired"
#define  HL_LDS_PWDreq "ms-DS-UserPasswordNotRequired"
#define  HL_LDS_PWDnot "msDS-UserDontExpirePassword"
//#define  HL_LDS_UACcom "msDS-User-Account-Control-Computed"    // reflected by the flags above

#define  HL_ATTRLIST   HL_MSAD_UAC","   \
                       HL_LDS_UAdis","  \
                       HL_LDS_PWDexp"," \
                       HL_LDS_PWDreq"," \
                       HL_LDS_PWDnot


int dsd_ldap::m_ldap_check_pwd_age( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   HL_LONGLONG   ill_max_pwd_age;        // maximum password age (minutes)
   HL_LONGLONG   ill_last_pwd_set;       // last password set (minutes)
   unsigned int  uml_user_control (0);   // user account control


   // trace message LDAP0033T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 33, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Check password  DN=\"%.*(.*)s\"",
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none" );

   // initialize return values...
   if (adsp_co_ldap->adsc_pwd_info == NULL)
     adsp_co_ldap->adsc_pwd_info = (dsd_ldap_pwd *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(struct dsd_ldap_pwd) );

   memset( (void *)adsp_co_ldap->adsc_pwd_info, int(0), sizeof(struct dsd_ldap_pwd) );


   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-check!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   if (this->m_aux_bind_admin() != ied_ldap_success)
                                     // error; we can't execute the ldap-check!
                                     return ied_ldap_failure;

      default:                     break;
   } // end of switch


   // we need the 'defaultNamingContext' as the RootDSE
   // Note: MS LDS doesn't support it, thus we take the configured 'base_dn'
   if (this->bo_RootDSE == FALSE && this->m_aux_search_RootDSE() != ied_ldap_success)
   { // error; we can't execute the ldap-check_pwd!
     return ied_ldap_failure;
   }

   // 1. perform ldap search (User-DN, 'userAccountControl')...
   // Note: MSAD LDS doesn't support 'userAcccountControl', instead of we use the following attributes:
   //       'msDS-UserAccountDisabled', 'msDS-UserPasswordExpired', ...
   LDAP_REQ_STRUC(dsl_co_ldap)

   dsl_co_ldap.iec_co_ldap      = ied_co_ldap_search;
   dsl_co_ldap.iec_sear_scope   = ied_sear_baseobject;
   dsl_co_ldap.ac_dn            = adsp_co_ldap->ac_dn;
   dsl_co_ldap.imc_len_dn       = adsp_co_ldap->imc_len_dn;
   dsl_co_ldap.iec_chs_dn       = adsp_co_ldap->iec_chs_dn;
   dsl_co_ldap.ac_filter        = (char *)"(objectClass=*)";
   dsl_co_ldap.imc_len_filter   = sizeof "(objectClass=*)" - 1;
   dsl_co_ldap.iec_chs_filter   = ied_chs_utf_8;
   dsl_co_ldap.ac_attrlist      = (char *)HL_ATTRLIST;
   dsl_co_ldap.imc_len_attrlist = sizeof HL_ATTRLIST - 1;
   dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;

   if (this->m_ldap_search( &dsl_co_ldap ) != ied_ldap_success)
   { // error; we can't execute the ldap-search! The error was set by m_ldap_search().
     this->ds_ldap_error.m_set_apicode(ied_ldap_check_pwd_err);
     return ied_ldap_failure;
   }

   // test for NORMAL_ACCOUNT and DONT_EXPIRE_PASSWORD or PASSWORD_EXPIRED
#define HL_MSAD_ACCOUNT_DISABLED      0x00000002    // msDS-UserAccountDisabled
#define HL_MSAD_LOCKOUT	              0x00000010    // msDS-UserAccountAutoLocked
#define HL_MSAD_PASSWORD_NOTREQD      0x00000020    // ms-DS-UserPasswordNotRequired
#define HL_MSAD_PASSWORD_CANT_CHANGE  0x00000040    // not supported
#define HL_MSAD_ENCR_PASSWD_ALLOWED	  0x00000080    // msDS-UserEncryptedTextPasswordAllowed
#define HL_MSAD_NORMAL_ACCOUNT        0x00000200    // msDS-User-Account-Control-Computed
#define HL_MSAD_PASSWORD_DONT_EXPIRE  0x00010000    // msDS-UserDontExpirePassword
#define HL_MSAD_PASSWORD_EXPIRED      0x00800000    // msDS-UserPasswordExpired

#define HL_MSAD_SAMTYPE_DOMAIN        0x00000000    // SAM_DOMAIN_OBJECT
#define HL_MSAD_SAMTYPE_GROUP         0x10000000    // SAM_GROUP_OBJECT
#define HL_MSAD_SAMTYPE_NONSEC_GROUP  0x10000001    // SAM_NON_SECURITY_GROUP_OBJECT
#define HL_MSAD_SAMTYPE_ALIAS         0x20000000    // SAM_ALIAS_OBJECT
#define HL_MSAD_SAMTYPE_NONSEC_ALIAS  0x20000001    // SAM_NON_SECURITY_ALIAS_OBJECT
#define HL_MSAD_SAMTYPE_USER          0x30000000    // SAM_USER_OBJECT
#define HL_MSAD_SAMTYPE_USER_ACCOUNT  0x30000000    // SAM_NORMAL_USER_ACCOUNT
#define HL_MSAD_SAMTYPE_MACH_ACCOUNT  0x30000001    // SAM_MACHINE_ACCOUNT
#define HL_MSAD_SAMTYPE_TRUST_ACCOUNT 0x30000002    // SAM_TRUST_ACCOUNT
#define HL_MSAD_SAMTYPE_APPBASIC_GRP  0x40000000    // SAM_APP_BASIC_GROUP
#define HL_MSAD_SAMTYPE_APPQUERY_GRP  0x40000001    // SAM_APP_QUERY_GROUP
#define HL_MSAD_SAMTYPE_ACCTYPE_MAX   0x7FFFFFFF    // SAM_ACCOUNT_TYPE_MAX

   // Notes for MS AD and MS LDS:
   // 1. The msDS-User-Account-Control-Computed attribute has different behavior on AD DS and AD LDS
   // 2. userAccountControl isn't supported on MS LDS
   // 3. Use of the msDS-... attributes for MS LDS
   // Look either for 'userAccountControl' or MS LS flags...
   struct dsd_ldap_attr  *adsl_attr (dsl_co_ldap.adsc_attr_desc->adsc_attr);

   while (adsl_attr)
   {
     // MSAD: userAccountControl?
     if (adsl_attr->imc_len_attr == sizeof HL_MSAD_UAC-1 &&
         !m_hl_memicmp((const void *)adsl_attr->ac_attr, (const void *)HL_MSAD_UAC, sizeof HL_MSAD_UAC-1))
     {
       char *achl_1 = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(unsigned int) * 2 + 1/*'\0'*/ );
       memcpy( (void *)achl_1,
               (const void *)(dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.ac_val),
               dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val );
       achl_1[dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val] = '\0';
       uml_user_control = (unsigned int)atoi( achl_1 );

       // we got all information (MSAD)
       break;
     }
     else
     { // check MS LDS flags...
       // MS LDS: msDS-UserAccountDisabled (TRUE / FALSE)?
       if (adsl_attr->imc_len_attr == sizeof HL_LDS_UAdis-1 &&
           !m_hl_memicmp((const void *)adsl_attr->ac_attr, (const void *)HL_LDS_UAdis, sizeof HL_LDS_UAdis-1))
       { // test for 'TRUE'...
         if (!m_hl_memicmp((const void *)adsl_attr->dsc_val.ac_val, (const void *)"TRUE", sizeof "TRUE"-1))
           // account is disabled
           uml_user_control |= HL_MSAD_ACCOUNT_DISABLED;
       }
       else
       { // MS LDS: msDS-UserPasswordExpired (TRUE / FALSE)?
         if (adsl_attr->imc_len_attr == sizeof HL_LDS_PWDexp-1 &&
             !m_hl_memicmp((const void *)adsl_attr->ac_attr, (const void *)HL_LDS_PWDexp, sizeof HL_LDS_PWDexp-1))
         { // test for 'TRUE'...
           if (!m_hl_memicmp((const void *)adsl_attr->dsc_val.ac_val, (const void *)"TRUE", sizeof "TRUE"-1))
             // the user's password is expired
             uml_user_control |= HL_MSAD_PASSWORD_EXPIRED;
         }
         else
         { // MS LDS: ms-DS-UserPasswordNotRequired (TRUE / FALSE)?
           if (adsl_attr->imc_len_attr == sizeof HL_LDS_PWDreq-1 &&
               !m_hl_memicmp((const void *)adsl_attr->ac_attr, (const void *)HL_LDS_PWDreq, sizeof HL_LDS_PWDreq-1))
           { // test for 'TRUE'...
             if (!m_hl_memicmp((const void *)adsl_attr->dsc_val.ac_val, (const void *)"TRUE", sizeof "TRUE"-1))
               // the user's password is expired
               uml_user_control |= HL_MSAD_PASSWORD_NOTREQD;
           }
           else
           { // MS LDS: msDS-UserDontExpirePassword (TRUE / FALSE)?
             if (adsl_attr->imc_len_attr == sizeof HL_LDS_PWDnot-1 &&
                 !m_hl_memicmp((const void *)adsl_attr->ac_attr, (const void *)HL_LDS_PWDnot, sizeof HL_LDS_PWDnot-1))
             { // test for 'TRUE'...
               if (!m_hl_memicmp((const void *)adsl_attr->dsc_val.ac_val, (const void *)"TRUE", sizeof "TRUE"-1))
                 // the user's password is expired
                 uml_user_control |= HL_MSAD_PASSWORD_DONT_EXPIRE;
             }
           }
         }
       }
     }

     adsl_attr = adsl_attr->adsc_next_attr;
   } // while (adsl_attr)


   // check user control flags if set
   if (uml_user_control)   
   {
     // we can check the password expire time for users only!
     if ((uml_user_control & HL_MSAD_NORMAL_ACCOUNT) == 0)
       // not a user account, return
       adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_password_not_a_user_account;
     else
     { // now check for disabled account
       if (uml_user_control & HL_MSAD_ACCOUNT_DISABLED)
         // account disabled, return
         adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_account_disabled;
       else
       { // is the password already expired?
         if (uml_user_control & HL_MSAD_PASSWORD_EXPIRED)
           // password expired, return
           adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_password_expired;
         else
         { // is any password required?
           if (uml_user_control & HL_MSAD_PASSWORD_NOTREQD)
             // no password required, return
             adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_password_not_required;
           else
           { // do the password expire?
             if (uml_user_control & HL_MSAD_PASSWORD_DONT_EXPIRE)
               // password do not expire, return
               adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_password_do_not_expire;
           }
         }
       }
     }
   } // uml_user_control


   // is there any status set?
   if (adsp_co_ldap->adsc_pwd_info->iec_account_control)
     // yes, return (password is expired for several reasons or account is disabled!)
     return ied_ldap_success;
   else
   { // 2. perform ldap search (User-DN, 'pwdLastSet')...
     dsl_co_ldap.ac_attrlist      = (char *)"pwdLastSet";
     dsl_co_ldap.imc_len_attrlist = sizeof "pwdLastSet" - 1;
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;

     if (this->m_ldap_search( &dsl_co_ldap ) != ied_ldap_success)
     { // error; we can't execute the ldap-search! The error was set by m_ldap_search().
       this->ds_ldap_error.m_set_apicode(ied_ldap_check_pwd_err);
       return ied_ldap_failure;
     }

     // save the value (Microsoft special format (LARGE_INTEGER))
     char *achl_1 = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(HL_LONGLONG) * 2 + 1/*'\0'*/ );
     memcpy( (void *)achl_1,
             (const void *)(dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.ac_val),
             dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val );
     achl_1[dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val] = '\0';
     ill_last_pwd_set  =_atoi64( achl_1 );   // last password set in 100ns since 1.1.1601 12a.m.

     // 3. perform ldap search (RootDSE, 'maxPwdAge')...
     struct dsd_ldap_val  dsl_context;

     // MS LDS doesn't support 'defaultNamingContext'
     if (this->ds_RootDSE.ads_defaultcontext)
     { // MSAD with default context
       dsl_context.ac_val      = this->ds_RootDSE.ads_defaultcontext->ac_val;
       dsl_context.imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
       dsl_context.iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
     }
     else
     { // MS LDS
       dsl_context.ac_val      = this->ads_ldap_entry->achc_base_dn;
       dsl_context.imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
       dsl_context.iec_chs_val = ied_chs_utf_8;
     }

     dsl_co_ldap.ac_dn            = dsl_context.ac_val;
     dsl_co_ldap.imc_len_dn       = dsl_context.imc_len_val;
     dsl_co_ldap.iec_chs_dn       = dsl_context.iec_chs_val;
     dsl_co_ldap.ac_attrlist      = (char *)"maxPwdAge";
     dsl_co_ldap.imc_len_attrlist = sizeof "maxPwdAge" - 1;

     if (this->m_ldap_search( &dsl_co_ldap ) != ied_ldap_success)
     { // do not report any error; we use the maximum value for this attribute!
       achl_1 = "-8639999990000000"; // 9999:23:59:59
     }
     else
     { // save the value ('-.....', Microsoft special format (LARGE_INTEGER))
       achl_1 = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, sizeof(HL_LONGLONG) * 2 + 1/*'-'*/ + 1/*'\0'*/ );
       memcpy( (void *)achl_1,
               (const void *)(dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.ac_val),
               dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val );
       achl_1[dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val] = '\0';
     }

     ill_max_pwd_age  =_atoi64( achl_1 ) * (-1); // remove the '-'  (value in 100ns)

     // get current utc-time (in 100ns since 1.1.1601 12a.m.)
     if (dsd_ldap::im_utc_update)
     { // get time and restart timer...
#if defined WIN32 || defined WIN64
       InterlockedExchange( (LONG *)&dsd_ldap::im_utc_update, 0 );
#elif defined HL_UNIX
       __sync_lock_test_and_set( &dsd_ldap::im_utc_update, 0 );
#endif

#if defined WIN32 || defined WIN64
       GetSystemTimeAsFileTime( (LPFILETIME)&dsd_ldap::il_utc_time );
#endif
       dsd_ldap::ds_timer_1.ilcwaitmsec = 1000 * 60;  // wait at least 1 minute
       dsd_ldap::ds_timer_1.amc_compl   = mg_cb_utc_timer;
       m_time_set( &dsd_ldap::ds_timer_1, FALSE );
     } // system time

     // now calculate how many days are remain
     ill_max_pwd_age -= dsd_ldap::il_utc_time - ill_last_pwd_set;
     ill_max_pwd_age /= 10 * 1000 * 1000;    // result in seconds
     // does the password expire?
     if (ill_max_pwd_age < 0)
       adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_password_expired;
     else
       adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_success;

     adsp_co_ldap->adsc_pwd_info->ilc_exp_minutes = ill_max_pwd_age / 60;
     adsp_co_ldap->adsc_pwd_info->ilc_exp_hours   = adsp_co_ldap->adsc_pwd_info->ilc_exp_minutes / 60;
     adsp_co_ldap->adsc_pwd_info->ilc_exp_days    = adsp_co_ldap->adsc_pwd_info->ilc_exp_hours / 24;
   } // end of ldap('pwdLastSet' and 'maxPwdAge')


   // no account information set
   if (adsp_co_ldap->adsc_pwd_info->iec_account_control == ied_ldap_invalid)
     adsp_co_ldap->adsc_pwd_info->iec_account_control = ied_ldap_success;

   return ied_ldap_success;

} // dsd_ldap::m_ldap_check_pwd_age()


/**
 * Private class function:  dsd_ldap::m_ldap_get_bind()
 *
 * Returns informations about the current bind-context.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_get_bind( struct dsd_co_ldap_1 *adsp_co_ldap, 
                               BOOL bop_pwd /*for internal use only,  callers cannot set this value!*/ )
{
   // valid connection?
   if (this->im_c_status == dsd_ldap::BIND && this->achr_dn && this->im_len_dn)
   { // set current context...
     adsp_co_ldap->ac_userid      = this->achr_dn;
     adsp_co_ldap->imc_len_userid = this->im_len_dn;
     adsp_co_ldap->iec_chs_userid = ied_chs_utf_8;

     if (bop_pwd == TRUE)
     {
       adsp_co_ldap->ac_passwd      = this->achr_pwd;
       adsp_co_ldap->imc_len_passwd = this->im_len_pwd;
       adsp_co_ldap->iec_chs_passwd = ied_chs_utf_8;
     }
     return ied_ldap_success;
   }
   else
   { // no valid context found!
     adsp_co_ldap->ac_userid      = adsp_co_ldap->ac_passwd      = NULL;
     adsp_co_ldap->imc_len_userid = adsp_co_ldap->imc_len_passwd = 0;

     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_bind_err );
     return ied_ldap_no_bind;
   }

} // dsd_ldap::m_ldap_get_bind()


/**
 * Private class function:  dsd_ldap::m_aux_parse_resp()
 *
 * Scans the LDAPResult messages.
 *
 *      BindResponse     ::= [APPLICATION 1]  SEQUENCE { COMPONENTS OF LDAPResult,
 *                                                       serverSaslCreds  [7] OCTET STRING OPTIONAL
 *                                                     }
 *      SearchResultDone ::= [APPLICATION 5]  LDAPResult
 *      ModifyResponse   ::= [APPLICATION 7]  LDAPResult
 *      AddResponse      ::= [APPLICATION 9]  LDAPResult
 *      DeleteResponse   ::= [APPLICATION 11] LDAPResult
 *      ModifyDNResponse ::= [APPLICATION 13] LDAPResult
 *      CompareResponse  ::= [APPLICATION 15] LDAPResult
 *
 *      LDAPResult ::= SEQUENCE { resultCode      ENUMERATED {...},
 *                                matchedDN       LDAPDN,
 *                                errorMessage    LDAPString,
 *                                referral        [3] Referral OPTIONAL
 *                              }
 * optional:
 *
 *      pagedResultsControl ::= SEQUENCE { controlType     1.2.840.113556.1.4.319,
 *                                         criticality     BOOLEAN DEFAULT FALSE,
 *                                         controlValue    searchControlValue
 *                                       }
 *
 *      The searchControlValue is an OCTET STRING wrapping the BER-encoded
 *      version of the following SEQUENCE:
 *
 *      searchControlValue ::= SEQUENCE { size    INTEGER (0..maxInt),
 *                                                -- requested page size from client
 *                                                -- result set size estimate from server
 *                                        cookie   OCTET STRING
 *                                      }
 *
 *
 * @param[in]   adsp_buf      LDAPMessage structure to parse
 * @param[in]   adsp_asn1     ASN.1 buffer to parse
 * @param[in]   adsp_ldapreq  ldap request structure
 *
 * @return      resultCode(Error)
 *
 * Remarks:\n
 * All other LDAP responses have be parsed by other routines.
 */
int dsd_ldap::m_aux_parse_resp( class dsd_bufm *adsp_buf, class dsd_asn1 *adsp_asn1, struct dsd_ldapreq *adsp_ldapreq )
{
    int    iml_result_code (ied_ldap_failure);
    char  *achl_matched_dn, *achl_diagnostic_msg;
    int    iml_len_msg, iml_len_dn;

    // do we have got valid parameters?
    if (adsp_buf == NULL || adsp_asn1 == NULL || adsp_ldapreq == NULL)
    { // error, nothing to parse...
      this->ds_ldap_error.m_set_error( ied_ldap_no_results );
      return ied_ldap_failure;
    }

	char* achl_temp = (char *)adsp_buf->m_get_bufaddr();
    // set pointer for parsing...
   adsp_asn1->asn1_beg = achl_temp + adsp_buf->imc_nextpos;
   adsp_asn1->asn1_end = achl_temp + adsp_buf->imc_pos;
 
    // trace message LDAP0095T
    if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_DATA ))
      this->ds_ldap_trace.m_trace_data( dsd_trace::LEVEL_DATA, 95, this->im_sess_no, adsp_ldapreq->imc_msgid, adsp_ldapreq->ac_req,
                                        m_get_epoch_ms(), &this->ds_conn, this->ads_ldap_entry,
                                        (const unsigned char *)adsp_asn1->asn1_beg, (unsigned int)(adsp_asn1->asn1_end - adsp_asn1->asn1_beg));

    // test for the right messageID and the right response type...
    adsp_asn1->m_get_tag( &adsp_asn1->im_tag );
    adsp_asn1->m_get_len( &adsp_asn1->im_len );
	char* achl_end = adsp_asn1->asn1_beg + adsp_asn1->im_len;
    adsp_asn1->m_get_msgid( &adsp_asn1->im_msgid );
    adsp_asn1->m_get_op( &adsp_asn1->im_op );    // get the expected protocol operation (e.g. LDAP_RESP_BIND, ...)

    if ((adsp_asn1->im_msgid && (adsp_asn1->im_msgid != adsp_ldapreq->imc_msgid)) ||
        (adsp_asn1->im_op != adsp_ldapreq->imc_resp[0] &&
         adsp_asn1->im_op != adsp_ldapreq->imc_resp[1] &&
         adsp_asn1->im_op != adsp_ldapreq->imc_resp[2] &&
         adsp_asn1->im_op != adsp_ldapreq->imc_resp[3]))
    { // ldap protocol error, nothing to parse...
      this->ds_ldap_error.m_set_error( ied_ldap_prot_err );
      return ied_ldap_failure;
    }

    // LDAPResult::= SEQUENCE { resultCode         ENUMERATED {...}
    //                          matchedDN          LDAPDN,     --> LDAPString ::= OCTET STRING
    //                          diagnosticMessage  LDAPString, --> LDAPString ::= OCTET STRING
    //                        }
    int   iml_oid_len (0), iml_size (0);
    char *achl_oid (NULL);

    switch (adsp_asn1->im_op)
    {
       case LDAP_RESP_SEARCH_DONE:
                               // statistics...
                               if (this->il_start_time)
                               { HL_LONGLONG ill_time = m_get_epoch_ms() - this->il_start_time;
                                 this->ads_ldap_entry->ilc_sum_search_t_msec += ill_time;

                                 if (ill_time > this->ads_ldap_entry->imc_max_search_t_msec)
                                   this->ads_ldap_entry->imc_max_search_t_msec = int(ill_time);
                               }
       case LDAP_RESP_ADD:
       case LDAP_RESP_BIND:
       case LDAP_RESP_COMPARE:
       case LDAP_RESP_DELETE:
       case LDAP_RESP_MODDN:
       case LDAP_RESP_MODIFY:
       case LDAP_RESP_EXTENDED:
                               // LDAPResult...
                               adsp_asn1->m_scanf( "{eoo",
                                                   &iml_result_code /*e*/,
                                                   &achl_matched_dn, &iml_len_dn /*o*/,
                                                   &achl_diagnostic_msg, &iml_len_msg /*o*/ );

							   // do mapping from asn.1(0) to ied_ldap_success...
							   if (!iml_result_code)
								 iml_result_code = ied_ldap_success;

                               // optional: check for OID '1.2.840.113556.1.4.319' (pagedResultsControl)...
                               if (this->bo_page_results == TRUE                                              &&
                                   adsp_asn1->m_scanf( "{{o", &achl_oid, &iml_oid_len /*o*/) == LASN1_SUCCESS &&
                                   iml_oid_len == sizeof OID_PAGE_RESULTS - 1                                 &&
                                   !m_hl_memicmp((const void *)achl_oid, (const void *)OID_PAGE_RESULTS, iml_oid_len))
                               {
                                 // free the last (old) cookie and save the new one...
                                 if (this->im_cookie_len && this->avo_cookie)
                                   FREE_MEM( this->ads_hl_stor_per, this->avo_cookie )

                                 adsp_asn1->m_scanf( "{{iO", &iml_size /*i*/, &this->avo_cookie, &this->im_cookie_len, &this->ads_hl_stor_per /*O*/);
                               } // 'pagedResultsControl'

                               // check result code
                               switch (iml_result_code)
                               {
                                  case ied_ldap_success:
                                  case ied_ldap_sasl_bind:      // saslBindInProgress...
                                      break;

                                  case ied_ldap_cmp_true:
                                  case ied_ldap_cmp_false:
                                      // trace message LDAP0094T
                                      if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
                                        this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 94, this->im_sess_no, m_get_epoch_ms(),
                                                                     &this->ds_conn, this->ads_ldap_entry,
                                                                     "Compare Result=%s",
                                                                     (iml_result_code == ied_ldap_cmp_true) ? "true" : "false" );
                                      break;

                                  case ied_ldap_referral:
                                      // trace message LDAP0098T
                                      if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
                                        this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 98, this->im_sess_no, m_get_epoch_ms(),
                                                                     &this->ds_conn, this->ads_ldap_entry,
                                                                     "Search result referral (\"%.*(.*)s\")",
                                                                     achl_diagnostic_msg ? iml_len_msg : sizeof "none" - 1,
                                                                     ied_chs_utf_8,
                                                                     achl_diagnostic_msg ? achl_diagnostic_msg : "none" );
                                      // for the user's information only! Don't stop execution
                                      iml_result_code = ied_ldap_success;
                                      break;

                                  case ied_ldap_inv_cred:
                                      // check for 'password expired'...
                                      if (iml_len_msg)
                                      { // MSAD uses messages like "80090308: LdapErr: DSID-0C0903AA, comment: AcceptSecurityContext error, data 773, v1771"
                                        string        str_diagmsg( achl_diagnostic_msg, iml_len_msg );
                                        unsigned int  uml_found = (unsigned int)str_diagmsg.find( ", data " );

                                        if (str_diagmsg.find( "80090308" ) != string::npos &&
                                            uml_found != string::npos)
                                        { // check the different subclasses of "invalid credentials"...
                                          switch (atoi( str_diagmsg.substr( uml_found + sizeof ", data " - 1, 3 ).c_str() ))
                                          {
                                            case 532:  // password expired
                                                       iml_result_code = ied_ldap_password_expired;
                                                       break;
                                            case 773:  // user must reset password
                                                       iml_result_code = ied_ldap_password_change;
                                                       break;
                                            case 530:  // not permitted to logon at this time
                                                       iml_result_code = ied_ldap_no_logon_this_time;
                                                       break;
                                            case 533:  // account disabled
                                                       iml_result_code = ied_ldap_account_disabled;
                                                       break;
                                            case 701:  // account expired
                                                       iml_result_code = ied_ldap_account_expired;
                                                       break;
                                            case 775:  // account locked
                                                       iml_result_code = ied_ldap_account_locked;
                                            default:   // user name invalid (data 525)
                                                       // invalid credentials (data 52e)
                                                       // no rights for signon (data 531)
                                                       break;
                                          } // switch()
                                        }
                                      } // iml_len_msg

                                  default:
                                      // save error...
                                      this->ds_ldap_error.m_set_error( iml_result_code,
                                                                       ied_ldap_failure,
                                                                       achl_matched_dn, iml_len_dn,
                                                                       achl_diagnostic_msg, iml_len_msg );

                                      // trace message LDAP0090T
                                      if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_ERROR ))
                                        this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_ERROR, 90, this->im_sess_no, m_get_epoch_ms(),
                                                                     &this->ds_conn, this->ads_ldap_entry,
                                                                     "LDAP-Error=%i (%s) DN=\"%.*(.*)s\" Message=\"%.*(.*)s\"",
                                                                     iml_result_code, this->ds_ldap_error.m_get_errormsg(iml_result_code),
                                                                     achl_matched_dn ? iml_len_dn : sizeof "none" - 1,
                                                                     ied_chs_utf_8,
                                                                     achl_matched_dn ? achl_matched_dn : "none",
                                                                     achl_diagnostic_msg ? iml_len_msg : sizeof "none" - 1,
                                                                     ied_chs_utf_8,
                                                                     achl_diagnostic_msg ? achl_diagnostic_msg : "none" );
                                      break;
                               } // switch(iml_result_code)

                               break;

       case LDAP_RESP_SEARCH_ENTRY:
       case LDAP_RESP_SEARCH_REF:
                               // parse 'SearchResultEntry [APPLICATION 4]' or 'SearchResultReference [APPLICATION 19]'...
                               iml_result_code = ied_ldap_success;
                               break;

       default:                // invalid LDAP response!!!
                               iml_result_code = ied_ldap_prot_err;
                               break;
    } // switch(im_op)

	if (adsp_asn1->asn1_end < achl_end)
		return ied_ldap_failure;

    adsp_buf->imc_nextpos = (int)(achl_end - achl_temp);
	adsp_asn1->asn1_end = achl_end;

    return iml_result_code;

} // dsd_ldap::m_aux_parse_resp( dsd_bufm *, dsd_asn1 *, dsd_ldapreq * )


/**
 * Private class function:  dsd_ldap::m_ldap_delete()
 *
 * Initiates a ldap delete operation. Only leaf entries without any sub-nodes can be
 * deleted with this function. There are two ways to delete non-leaf entries:
 * If the LDAP server supports the following control OID (1.2.840.113556.1.4.805),
 * the entry and all its sub-entries are deleted by one LDAP request only or, and
 * this the normal way, we have to build a list of all sub-entries first. Then we can
 * delete all entries beginning at the lowest level and ending with the entry at the
 * highest level (in other words: the entry pointed by the DN of the function's call
 * parameter list).
 * There is a safety check against unwanted delete of non-leaf entries. The caller
 * of the function can set a confirmation flag to control the processing. If the flag
 * is set to 'yes' or 'skip', the function continues and deletes all sub-entries. The
 * 'no' (default) forces the function to return with an error 'ied_ldap_not_allowed_on_nleaf'.
 * So the function has to be called a second time with 'yes' or 'skip' for continue
 * the delete.
 * After deleting the entry check for membership in groups and delete these member entries too.
 *
 *
 *     ASN.1:
 *     DeleteRequest ::= [APPLICATION 10] LDAPDN
 *
 *     Controls ::= SEQUENCE OF control Control
 *
 *     Control ::= SEQUENCE { controlType   LDAPOID,
 *                            criticality   BOOLEAN DEFAULT FALSE,
 *                            controlValue  OCTET STRING OPTIONAL
 *                          }
 *
 *
 * @param[in,out]  adsp_co_ldap   request structure
 *
 * @return         error        (\b ied_ldap_failure),
 *                 successful   (\b ied_ldap_success) or
 *                 send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_ldap_delete(struct dsd_co_ldap_1 *adsp_co_ldap)
{
   int   iml_rc (ied_ldap_success);

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       if (this->m_ldap_connect( this->ads_ldap_group ) != ied_ldap_success)
                                     // error; we can't execute the ldap-search!
                                     return ied_ldap_failure;
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   // do we have valid informations for a bind?
                                   if (this->achr_dn == NULL || this->im_len_dn == 0)
                                   { // error; we can't execute the ldap-search!
                                     this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_delete_err );
                                     return ied_ldap_no_bind;
                                   }

                                   BIND_WITH_DN()
      default:                     break;
   } // end of switch

   // trace message LDAP0055T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 55, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Delete DN=\"%.*(.*)s\" ",
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn? adsp_co_ldap->iec_chs_dn  : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn? adsp_co_ldap->ac_dn       : "none" );

   // perform ldap delete/modify...
   LDAPREQ_DELETE(this->ds_ldapreq)
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // do we have any distinguished name as 'baseObject' ?
   if (adsp_co_ldap->imc_len_dn == 0 || adsp_co_ldap->ac_dn == NULL)
   { // what should we do? --> return with error
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_delete_err );
     return ied_ldap_failure;
   }

   // build the asn.1-formatted delete request...
   if (this->ds_asn1.m_printf( "{its}",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, int(adsp_co_ldap->iec_chs_dn) /*s*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-delete!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_delete_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_write;
   ++this->ads_ldap_entry->imc_send_packet;

   // SSL or non SSL?
   iml_rc = this->m_send(this->ds_asn1.ads_gather, ied_ldap_delete_err /*apicode*/);
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for delete response...
   this->ads_ldap_control->bo_recv_complete = FALSE;

   iml_rc = this->m_recv( ied_ldap_delete_err /*apicode*/);
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // parse LDAP result (DELETE-response)...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

   iml_rc = this->m_aux_parse_resp(&this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq);
   if (iml_rc != ied_ldap_success)
   { // @todo: error message to event viewer or something else...
     this->ds_ldap_error.m_set_apicode( ied_ldap_delete_err );

     if (iml_rc == ied_ldap_not_allowed_on_nleaf)
     { // test the 'confirmation'-flag
       if (adsp_co_ldap->iec_ldap_confirm == ied_confirm_yes ||
           adsp_co_ldap->iec_ldap_confirm == ied_confirm_skip)
         // delete it anyway
         if (this->m_aux_deletetree(adsp_co_ldap) == ied_ldap_success)
           goto delete_groups;
     }

     return ied_ldap_failure;
   }

delete_groups:
   // look for group members and delete them too
   dsd_ldap_template *adsl_templ (this->ads_ldap_entry->adsc_ldap_template);

   if (adsl_templ->achc_member_attr && adsl_templ->imc_len_member_attr)
   { // to do the search we need a 'member'-attribute!
     LDAP_REQ_STRUC(dsl_co_ldap)
     dsl_co_ldap.iec_co_ldap    = ied_co_ldap_search;
     dsl_co_ldap.iec_sear_scope = ied_sear_sublevel;  
     dsl_co_ldap.ac_dn          = this->ads_ldap_entry->achc_base_dn;
     dsl_co_ldap.imc_len_dn     = this->ads_ldap_entry->imc_len_base_dn;
     dsl_co_ldap.iec_chs_dn     = ied_chs_utf_8;  
     
     // set search filter (using templates)...
     int iml_len_dn = (adsp_co_ldap->imc_len_dn < 0) ? (int)strnlen((const char *)adsp_co_ldap->ac_dn, D_LDAP_MAX_STRLEN)
                                                     : adsp_co_ldap->imc_len_dn;
     dsl_co_ldap.iec_chs_filter = ied_chs_utf_8;
     dsl_co_ldap.imc_len_filter = sizeof "(&(objectClass=)(=))" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_group_attr ? adsl_templ->imc_len_group_attr : sizeof "*" - 1;
     dsl_co_ldap.imc_len_filter += adsl_templ->imc_len_member_attr;
     dsl_co_ldap.imc_len_filter += iml_len_dn;
     dsl_co_ldap.ac_filter = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, dsl_co_ldap.imc_len_filter );

     memcpy((void *)dsl_co_ldap.ac_filter, (const void *)"(&(objectClass=", sizeof "(&(objectClass=" - 1 );
     char *achl_1 = dsl_co_ldap.ac_filter + sizeof "(&(objectClass=" - 1;
       
     if (adsl_templ->imc_len_group_attr)
     { memcpy((void *)achl_1, (const void *)adsl_templ->achc_group_attr, adsl_templ->imc_len_group_attr );
       achl_1 += adsl_templ->imc_len_group_attr;
     }
     else
     { // default-value: "*"
       *achl_1 = '*';
       achl_1++;
     }
     
     memcpy((void *)achl_1, (const void *)")(", sizeof ")(" - 1);
     achl_1 += sizeof ")(" - 1;
     memcpy((void *)achl_1, (const void *)adsl_templ->achc_member_attr, adsl_templ->imc_len_member_attr );
     achl_1 += adsl_templ->imc_len_member_attr;
     *achl_1 = '=';
     achl_1++;
     memcpy((void *)achl_1, (const void *)adsp_co_ldap->ac_dn, iml_len_dn);
     memcpy((void *)(achl_1 + iml_len_dn), (const void *)"))", sizeof "))" - 1);
       
     // set attribute-list ('member') 
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.imc_len_attrlist = adsl_templ->imc_len_member_attr;
     dsl_co_ldap.ac_attrlist      = adsl_templ->achc_member_attr;
       
     // perform the search-request('member')...
     if (this->m_ldap_search(&dsl_co_ldap) == ied_ldap_success && dsl_co_ldap.adsc_attr_desc)
     { // groups with the specified member' found
       // step through these groups and delete each member...
       struct dsd_ldap_attr_desc *adsl_attr_desc (dsl_co_ldap.adsc_attr_desc);
       struct dsd_ldap_attr  dsl_ldap_attr;
                             dsl_ldap_attr.ac_attr        = adsl_templ->achc_member_attr;
                             dsl_ldap_attr.imc_len_attr   = adsl_templ->imc_len_member_attr;
                             dsl_ldap_attr.iec_chs_attr   = ied_chs_utf_8;
                             dsl_ldap_attr.adsc_next_attr = NULL;
                             dsl_ldap_attr.dsc_val.adsc_next_val   = NULL;
                             dsl_ldap_attr.dsc_val.ac_val          = adsp_co_ldap->ac_dn;
                             dsl_ldap_attr.dsc_val.imc_len_val     = adsp_co_ldap->imc_len_dn;
                             dsl_ldap_attr.dsc_val.iec_chs_val     = adsp_co_ldap->iec_chs_dn;
                             dsl_ldap_attr.dsc_val.ac_val_old      = NULL;
                             dsl_ldap_attr.dsc_val.imc_len_val_old = 0;
                             dsl_ldap_attr.dsc_val.iec_chs_val_old = ied_chs_invalid;
       do
       { // delete this value
         if (adsl_attr_desc->adsc_attr)
           this->m_aux_modify(adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn,
                              &dsl_ldap_attr, ied_ldap_mod_delete /*ied_ldap_mod_def::*/);       

         // step to the next entry
         adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;
       } while (adsl_attr_desc);
     }
   } // template <member>

   return ied_ldap_success;

}; // dsd_ldap::m_ldap_delete()


/**
 * Private class function:  dsd_ldap::m_ldap_explode_dn()
 *
 * Parts a given DN into the RDNs. If the caller of this function has set his own storage
 * handler, the output fields are allocated from there. So the caller is responsible for
 * the right memory handling!
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 *
 * @todo 2012/02/21  save the objectclasses of every RDN!
 */
int dsd_ldap::m_ldap_explode_dn( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   int   iml_1, iml_2, iml_esc_1;
   char *achl_1, *achl_2, *achl_3, *achl_esc_1;
   BOOL  bol_basedn;

   struct dsd_ldap_attr_desc  **aadsl_attr_desc_1 = &adsp_co_ldap->adsc_attr_desc;

   // trace message LDAP0056T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 56, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "ExplodeDN DN=\"%.*(.*)s\"",
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->imc_len_dn : sizeof "none" - 1,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->iec_chs_dn : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_dn ? adsp_co_ldap->ac_dn : "none" );

   // check the input parameter...
   if (adsp_co_ldap->imc_len_dn == 0 || adsp_co_ldap->ac_dn == NULL)
   { // error, wrong parameter!
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_explode_dn_err );
     return ied_ldap_failure;
   }

   struct dsd_ldap_val       *adsl_namingcontext;
   struct dsd_unicode_string  dsl_uc_dn;

   void** avol_stor_handle_per = &this->ads_hl_stor_per;
	// do we use the same encoding?
   if (this->ds_RootDSE.ads_namingcontexts &&
       this->ds_RootDSE.ads_namingcontexts->iec_chs_val != adsp_co_ldap->iec_chs_dn)
   { // no, create a copy with the same encoding...
     dsl_uc_dn.iec_chs_str = this->ds_RootDSE.ads_namingcontexts->iec_chs_val;
     dsl_uc_dn.imc_len_str = m_len_vx_vx( this->ds_RootDSE.ads_namingcontexts->iec_chs_val,
                                          adsp_co_ldap->ac_dn,
                                          adsp_co_ldap->imc_len_dn,
                                          adsp_co_ldap->iec_chs_dn );
     // check for conversion errors...
     if (dsl_uc_dn.imc_len_str == -1)
     { // error, invalid DN syntax!
       this->ds_ldap_error.m_set_error( ied_ldap_inv_dn_syntax, ied_ldap_explode_dn_err );
       return ied_ldap_failure;
     }

     void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;
	 dsl_uc_dn.ac_str = ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, dsl_uc_dn.imc_len_str );
     if (m_cpy_vx_vx_fl( dsl_uc_dn.ac_str, dsl_uc_dn.imc_len_str, dsl_uc_dn.iec_chs_str,
                         adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn,
                         D_CPYVXVX_FL_NOTAIL0 ) == -1)
     { // error, invalid string format...
       this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_explode_dn_err );
       return ied_ldap_failure;
     } 
   }
   else
   { // yes, no further actions are necessary!
     dsl_uc_dn.iec_chs_str = adsp_co_ldap->iec_chs_dn;
     dsl_uc_dn.imc_len_str = adsp_co_ldap->imc_len_dn;
     dsl_uc_dn.ac_str      = ms_aux_mem(adsp_co_ldap, avol_stor_handle_per, dsl_uc_dn.imc_len_str );
     memcpy( (void *)dsl_uc_dn.ac_str, (const void *)adsp_co_ldap->ac_dn, dsl_uc_dn.imc_len_str );
   }


   // part the RDNs from the given DN...
   iml_1           = dsl_uc_dn.imc_len_str;
   achl_1 = achl_3 = (char *)dsl_uc_dn.ac_str;

   // look for the delimiters ('comma' and 'semicolon')...
   bol_basedn = FALSE;

   while (iml_1 && bol_basedn == FALSE)
   {  // search an unmasked delimiter...
      if ((achl_2 = (char *)memchr( (const void *)achl_1, int(','), iml_1 )) ||
          (achl_2 = (char *)memchr( (const void *)achl_1, int(';'), iml_1 )))
      { // 'comma' or 'semicolon' found, is it unmasked?
        achl_2++;                       // after the 'comma' or the 'semicolon'
        iml_1 -= int(achl_2 - achl_1);  // length of the remaining length
        achl_1 = achl_2;
        // set copy length
        iml_2 = (int)(achl_2 - achl_3 - 1/*','*/);

        if (*(achl_2 - 2) != 0x5c /*'\'-escape character*/)
        { // unmasked delimiter found, check the base-DN...
          adsl_namingcontext = this->ds_RootDSE.ads_namingcontexts;
          while (adsl_namingcontext)
          {  // have we reached the base-dn?
             if (iml_1 == adsl_namingcontext->imc_len_val &&
                 !m_hl_memicmp( (void *)achl_2,
                                (void *)adsl_namingcontext->ac_val,
                                (int)adsl_namingcontext->imc_len_val ))
             { // trace message LDAP0052T
               if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_DATA ))
                 this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_DATA, 52, this->im_sess_no, m_get_epoch_ms(),
                                              &this->ds_conn, this->ads_ldap_entry,
                                              "ExplodeDN RootDSE=\"%.*(.*)s\"",
                                              adsl_namingcontext->ac_val ? adsl_namingcontext->imc_len_val : sizeof "none" - 1,
                                              adsl_namingcontext->ac_val ? adsl_namingcontext->iec_chs_val : ied_chs_ascii_850,
                                              adsl_namingcontext->ac_val ? adsl_namingcontext->ac_val : "none" );
               // base-dn found!
               bol_basedn = TRUE;
               break;
             }
             else
              adsl_namingcontext = adsl_namingcontext->adsc_next_val;
          }; // while(contexts)

          // set response...
          *aadsl_attr_desc_1 = (struct dsd_ldap_attr_desc *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_per, sizeof(struct dsd_ldap_attr_desc) );
          ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->adsc_next_attr_desc = NULL;
          ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->adsc_attr           = NULL;
          ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->iec_chs_dn          = dsl_uc_dn.iec_chs_str;

          // remove blanks at the begin of this RDN
          while (iml_2 && isspace((unsigned char)*achl_3))
          {
            achl_3++; iml_2--;
          } // while()

          ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->ac_dn = achl_3;

          // remove blanks at the end of this RDN
          achl_3 += iml_2 - 1;

          while (iml_2 && isspace((unsigned char)*achl_3))
          {
            achl_3--; iml_2--;
          } // while()

          ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->imc_len_dn = iml_2;

          // unmask the RDN (e.g. change '\,' to ',')
          achl_esc_1 = ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->ac_dn;
          iml_esc_1  = ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->imc_len_dn;

          while (iml_esc_1 > 1)
          {
             if (*achl_esc_1 == '\\' && *(achl_esc_1 + 1) != '\\')
             { // escape character found!
               // correct length...
               iml_esc_1--;
               ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->imc_len_dn--;

               memcpy(achl_esc_1, (const void *)(achl_esc_1 + 1), iml_esc_1);
             } // escape character found

             iml_esc_1--;
             achl_esc_1++;
          }; // while(scan for '\')


          // trace message LDAP0053T
          if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_DATA ))
            this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_DATA, 53, this->im_sess_no, m_get_epoch_ms(),
                                         &this->ds_conn, this->ads_ldap_entry,
                                         "ExplodeDN RDN=\"%.*(.*)s\"",
                                         ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->imc_len_dn,
                                         dsl_uc_dn.iec_chs_str,
                                         ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->ac_dn );

          // address for the next insert...
          aadsl_attr_desc_1 = &((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->adsc_next_attr_desc;
          // save last delimiter position!
          achl_3 = achl_2;
        } // unmasked delimiter found!
      }
      else
        // we have reached the end!
        break;
   }; // while ('comma' or 'semicolon')


   // insert the base-dn
   if (iml_1)
   { // the last RDN
     *aadsl_attr_desc_1 = (struct dsd_ldap_attr_desc *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_per, sizeof(struct dsd_ldap_attr_desc) );
     ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->adsc_next_attr_desc = NULL;
     ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->adsc_attr  = NULL;
     ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->iec_chs_dn = dsl_uc_dn.iec_chs_str;
     ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->imc_len_dn = iml_1;
     ((struct dsd_ldap_attr_desc *)*aadsl_attr_desc_1)->ac_dn      = achl_3;

     // trace message LDAP0054T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_DATA ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_DATA, 54, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "ExplodeDN RDN=\"%.*(.*)s\"",
                                    iml_1, dsl_uc_dn.iec_chs_str, achl_3 );
   }

   return ied_ldap_success;

}; // dsd_ldap::m_ldap_explode_dn()


/**
 * Private class function:  dsd_ldap::m_ldap_clone_dn()
 *
 * Clones given RDNs to the actual connected LDAP server.
 * The system looks for the different RDNs and creates it they don't exist.
 *
 * @param[in,out]  adsp_co_ldap  request structure
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 *
 * @todo 2012/02/21  clone the objectclasses of every RDN!
 */
int dsd_ldap::m_ldap_clone_dn( struct dsd_co_ldap_1 *adsp_co_ldap )
{
   int   iml_rc;
   BOOL  bol_added = FALSE;
   int   iml_cn;


   // check the input parameter...
   if (!adsp_co_ldap->adsc_attr_desc)
   { // error, wrong parameter!
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_clone_dn_err );
     return ied_ldap_failure;
   }

   // valid connection?
   switch (this->im_c_status)
   {
      case dsd_ldap::DISCONNECTED: // --> try to connect to the ldap server
      case dsd_ldap::UNBIND:       iml_rc = this->m_ldap_connect( this->ads_ldap_group );
                                   if (iml_rc == ied_ldap_success)
      case dsd_ldap::CONNECTED:    // --> send 'BIND' ...
                                   { if (this->m_aux_bind_admin() != ied_ldap_success)
                                     { this->ds_ldap_error.m_set_error( ied_ldap_no_bind, ied_ldap_clone_dn_err );
                                       return ied_ldap_no_bind;
                                     }
                                   }
      default:                     break;
   } // end of switch


   // create a linked chain of all RDNs except the base-dn...
   struct dsd_ldap_attr_desc *adsl_attr_desc = adsp_co_ldap->adsc_attr_desc;

   struct dsd_list
   {
     struct dsd_list *adsc_next;   // next dsd_list
     int              imc_len_rdn; // rdn-attribute length
                                   // rdn-attribute (utf-8)...
   };

   struct dsd_list *adsl_list_1, *adsl_list_anc = NULL;
   int   iml_len_rdn,     // length of the current RDN (utf-8)
         iml_len_dn (0);  // length over all RDNs (+ '\,'s)

   // 1. check the input list of all RDNs (except the last one == old base-dn)
   while (adsl_attr_desc && adsl_attr_desc->adsc_next_attr_desc)
   {  // check the character format of the RDN (we need utf-8)
      if (adsl_attr_desc->iec_chs_dn != ied_chs_utf_8)
      { // we have to convert to utf-8...
        iml_len_rdn = m_len_vx_vx( ied_chs_utf_8,
                                   adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn );
        if (iml_len_rdn == -1)
        { // error, invalid string format...
          this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_clone_dn_err );
          return ied_ldap_failure;
        }
      }
      else
        // we have already utf-8
       iml_len_rdn = (adsl_attr_desc->imc_len_dn != -1) ? adsl_attr_desc->imc_len_dn 
                                                        : (int)strnlen( (const char *)adsl_attr_desc->ac_dn, D_LDAP_MAX_STRLEN );


      // calculate  the length overall
      iml_len_dn += iml_len_rdn + 1 /*'\,'*/;
      // generate list element...
      adsl_list_1 = (struct dsd_list *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                                         sizeof(struct dsd_list) + iml_len_rdn );
      adsl_list_1->imc_len_rdn = iml_len_rdn;
      // copy rdn-string...
      if (adsl_attr_desc->iec_chs_dn != ied_chs_utf_8)
      {
        if (m_cpy_vx_vx_fl( adsl_list_1 + 1, iml_len_rdn, ied_chs_utf_8,
                            adsl_attr_desc->ac_dn, adsl_attr_desc->imc_len_dn, adsl_attr_desc->iec_chs_dn,
                            D_CPYVXVX_FL_NOTAIL0 ) == -1)
        { // error, invalid string format...
          this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_clone_dn_err );
          return ied_ldap_failure;
        } 
      }
      else
        memcpy( adsl_list_1 + 1, (const void *)adsl_attr_desc->ac_dn, iml_len_rdn );

      // set new anchor and step to the next attribute description
      adsl_list_1->adsc_next = adsl_list_anc;
      adsl_list_anc = adsl_list_1;

      adsl_attr_desc = adsl_attr_desc->adsc_next_attr_desc;
   }; // while(RDNs)


   // 2. check the optional dn-extension...
   if (adsp_co_ldap->imc_len_dn)
   { // check the optional dn-extension format (we need utf-8)
     if (adsp_co_ldap->iec_chs_dn != ied_chs_utf_8)
     { // we have to convert to utf-8...
       iml_len_rdn = m_len_vx_vx( ied_chs_utf_8,
                                  adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn );
       if (iml_len_rdn == -1)
       { // error, invalid string format...
         this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_clone_dn_err );
         return ied_ldap_failure;
       }
     }
     else
       // we have already utf-8
       iml_len_rdn = (adsp_co_ldap->imc_len_dn != -1) ? adsp_co_ldap->imc_len_dn 
                                                      : (int)strnlen( (const char *)adsp_co_ldap->ac_dn, D_LDAP_MAX_STRLEN );


     // calculate  the length overall
     iml_len_dn += iml_len_rdn + 1 /*'\,'*/;
     // generate list element...
     adsl_list_1 = (struct dsd_list *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                                        sizeof(struct dsd_list) + iml_len_rdn );
     adsl_list_1->imc_len_rdn = iml_len_rdn;
     // copy the optional dn-extension string...
     if (adsp_co_ldap->iec_chs_dn != ied_chs_utf_8)
     {
       if (m_cpy_vx_vx_fl( adsl_list_1 + 1, iml_len_rdn, ied_chs_utf_8,
                           adsp_co_ldap->ac_dn, adsp_co_ldap->imc_len_dn, adsp_co_ldap->iec_chs_dn,
                           D_CPYVXVX_FL_NOTAIL0 ) == -1)
       { // error, invalid string format...
         this->ds_ldap_error.m_set_error( ied_ldap_param_inv, ied_ldap_clone_dn_err );
         return ied_ldap_failure;
       } 
     }
     else
       memcpy( adsl_list_1 + 1, (const void *)adsp_co_ldap->ac_dn, iml_len_rdn );

     // set new anchor
     adsl_list_1->adsc_next = adsl_list_anc;
     adsl_list_anc = adsl_list_1;
   } // optional dn-extension



   // loop over all RDNs, beginning with the base-dn
   adsl_list_1 = adsl_list_anc;

   char *achl_dn = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                             iml_len_dn + this->ads_ldap_entry->imc_len_base_dn /*<base-dn>*/ + 1 /*'\,'*/ );
   // LDAP lookup request (check the existence of the RDN)
   LDAP_REQ_STRUC(dsl_co_ldap)
   
   dsl_co_ldap.iec_co_ldap      = ied_co_ldap_lookup;
   dsl_co_ldap.ac_dn            = achl_dn;
   dsl_co_ldap.iec_chs_dn       = ied_chs_utf_8;

   // add the following values if a new RDN is created...
   struct dsd_ldap_val  dsl_val_domain;      // additional objectclass for a domain
                        dsl_val_domain.adsc_next_val = NULL;
                        dsl_val_domain.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_domain.imc_len_val   = sizeof "domain" - 1;
                        dsl_val_domain.ac_val        = (char *)"domain";

   struct dsd_ldap_attr  dsl_attr_dc;        // domain-attribute
                         dsl_attr_dc.adsc_next_attr = NULL;
                         dsl_attr_dc.iec_chs_attr   = ied_chs_utf_8;
                         dsl_attr_dc.imc_len_attr   = sizeof "dc" - 1;
                         dsl_attr_dc.ac_attr        = (char *)"dc";
                         dsl_attr_dc.dsc_val.iec_chs_val   = ied_chs_utf_8;
                         dsl_attr_dc.dsc_val.adsc_next_val = NULL;
   // -----------------------------------------------------------------------------------------------------------------
   struct dsd_ldap_val  dsl_val_orgunit;     // additional objectclass for a organizationalUnit (ou=)
                        dsl_val_orgunit.adsc_next_val = NULL;
                        dsl_val_orgunit.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_orgunit.imc_len_val   = sizeof "organizationalUnit" -1;
                        dsl_val_orgunit.ac_val        = (char *)"organizationalUnit";

   struct dsd_ldap_val  dsl_val_container;   // additional objectclass for a container (cn=)
                        dsl_val_container.adsc_next_val = NULL;
                        dsl_val_container.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_container.imc_len_val   = sizeof "container" -1;
                        dsl_val_container.ac_val        = (char *)"container";
   // -----------------------------------------------------------------------------------------------------------------
   struct dsd_ldap_val  dsl_val_group;       // additional objectclasses for a group entry
                        dsl_val_group.adsc_next_val = NULL;
                        dsl_val_group.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_group.imc_len_val   = this->ads_ldap_entry->adsc_ldap_template->imc_len_group_attr;
                        dsl_val_group.ac_val        = this->ads_ldap_entry->adsc_ldap_template->achc_group_attr;
   // -----------------------------------------------------------------------------------------------------------------
   struct dsd_ldap_val  dsl_val_pers;        // additional objectclasses for a user entry
                        dsl_val_pers.adsc_next_val = NULL;
                        dsl_val_pers.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_pers.imc_len_val   = this->ads_ldap_entry->adsc_ldap_template->imc_len_user_attr;
                        dsl_val_pers.ac_val        = this->ads_ldap_entry->adsc_ldap_template->achc_user_attr;
   struct dsd_ldap_val  dsl_val_orgpers;
                        dsl_val_orgpers.adsc_next_val = &dsl_val_pers;
                        dsl_val_orgpers.iec_chs_val   = ied_chs_utf_8;
                        dsl_val_orgpers.imc_len_val   = sizeof "organizationalPerson" -1;
                        dsl_val_orgpers.ac_val        = (char *)"organizationalPerson";

   struct dsd_ldap_attr  dsl_attr_sn;   // user entry-attributes
                         dsl_attr_sn.adsc_next_attr = NULL;
                         dsl_attr_sn.iec_chs_attr = ied_chs_utf_8;
                         dsl_attr_sn.imc_len_attr = sizeof "sn" - 1;
                         dsl_attr_sn.ac_attr      = (char *)"sn";
                         dsl_attr_sn.dsc_val.iec_chs_val   = ied_chs_utf_8;
                         dsl_attr_sn.dsc_val.adsc_next_val = NULL;
   struct dsd_ldap_attr  dsl_attr_cn;
                         dsl_attr_cn.adsc_next_attr = NULL;
                         dsl_attr_cn.iec_chs_attr = ied_chs_utf_8;
                         dsl_attr_cn.imc_len_attr = this->ads_ldap_entry->adsc_ldap_template->imc_len_upref;
                         dsl_attr_cn.ac_attr      = this->ads_ldap_entry->adsc_ldap_template->achc_upref;
                         dsl_attr_cn.dsc_val.iec_chs_val   = ied_chs_utf_8;
                         dsl_attr_cn.dsc_val.adsc_next_val = NULL;
   // -----------------------------------------------------------------------------------------------------------------
   struct dsd_ldap_attr  dsl_attr_ou;   // container-attribute
                         dsl_attr_ou.adsc_next_attr = NULL;
                         dsl_attr_ou.iec_chs_attr = ied_chs_utf_8;
                         dsl_attr_ou.imc_len_attr = sizeof "ou" - 1;
                         dsl_attr_ou.ac_attr      = (char *)"ou";
                         dsl_attr_ou.dsc_val.iec_chs_val   = ied_chs_utf_8;
                         dsl_attr_ou.dsc_val.adsc_next_val = NULL;

   struct dsd_ldap_attr  dsl_oc;      // standard objectclasses for containers or user/group-entries
                         dsl_oc.iec_chs_attr = ied_chs_utf_8;
                         dsl_oc.imc_len_attr = sizeof "objectClass" - 1;
                         dsl_oc.ac_attr      = (char *)"objectClass";
                         dsl_oc.dsc_val.iec_chs_val   = ied_chs_utf_8;
                         dsl_oc.dsc_val.imc_len_val   = sizeof "top" -1;
                         dsl_oc.dsc_val.ac_val        = (char *)"top";

   struct dsd_ldap_attr_desc  dsl_new_entry;   // RDN of the new container or user entry
                              dsl_new_entry.adsc_next_attr_desc = NULL;
                              dsl_new_entry.ac_dn               = achl_dn;
                              dsl_new_entry.iec_chs_dn          = ied_chs_utf_8;
                              dsl_new_entry.adsc_attr           = &dsl_oc;

   // LDAP add reuest (add a new RDN)
   LDAP_REQ_STRUC(dsl_co_ldap_add)

   dsl_co_ldap_add.iec_co_ldap      = ied_co_ldap_add;
   dsl_co_ldap_add.adsc_attr_desc   = &dsl_new_entry;

   // build sub-DN...
   memcpy( (void *)achl_dn, (const void *)this->ads_ldap_entry->achc_base_dn, this->ads_ldap_entry->imc_len_base_dn );
   iml_len_dn = this->ads_ldap_entry->imc_len_base_dn;

   struct dsd_ldap_val *adsl_val_ext, *adsl_val_ext_2;


   while (adsl_list_1)
   {
      // insert new RDN at first
      memmove( achl_dn + adsl_list_1->imc_len_rdn + 1/*,*/, achl_dn, iml_len_dn + 1 );
      memcpy( (void *)achl_dn, (const void *)(adsl_list_1 + 1), adsl_list_1->imc_len_rdn );
      *(achl_dn + adsl_list_1->imc_len_rdn) = ',';
      // set length used so far
      iml_len_dn += adsl_list_1->imc_len_rdn + 1;

      // complete the ldap request...
      dsl_co_ldap.imc_len_dn = iml_len_dn;
      dsl_co_ldap_add.adsc_attr_desc->imc_len_dn = iml_len_dn;

      // lookup for the sub DN path...
      if (bol_added == TRUE || (this->m_ldap_lookup( &dsl_co_ldap ) != ied_ldap_success &&
                                this->ds_ldap_error.im_result_code  == ied_ldap_no_such_obj))
      { // it seems that the requested path doesn't exist
        // set the dn for adding attributes...
        // set 'ou=...' or 'cn=...'
        char *achl_1 = (char *)memchr( (void *)(adsl_list_1 + 1), int('='), adsl_list_1->imc_len_rdn );

        if (achl_1)
        { // take value...
          achl_1++;
          // container or user/group-entry?
          iml_cn = m_hl_memicmp( (void *)(adsl_list_1 + 1),
                                 (void *)this->ads_ldap_entry->adsc_ldap_template->achc_upref,
                                 this->ads_ldap_entry->adsc_ldap_template->imc_len_upref );

          if (!iml_cn)
          { // note: only the last entry in the chain can be a user/group entry!
            if (adsl_list_1->adsc_next)
              // we have found an user/group-like entry, but it should be handled as a container!
              goto SET_CONTAINER;
            else
            { // user/group-entry...
              if (adsp_co_ldap->iec_objectclass == ied_objectclass_group)
              { // group...
                dsl_oc.dsc_val.adsc_next_val = &dsl_val_group;
                dsl_attr_cn.adsc_next_attr   = NULL;
                // save where to add the user specific objectclasses
                adsl_val_ext = &dsl_val_group;
              }
              else
              { // this is a real user entry!
                dsl_oc.dsc_val.adsc_next_val = &dsl_val_orgpers;
                dsl_attr_cn.adsc_next_attr   = &dsl_attr_sn;
                // save where to add the user specific objectclasses
                adsl_val_ext = &dsl_val_pers;
              }
            }

            dsl_oc.adsc_next_attr = &dsl_attr_cn;
            dsl_attr_cn.dsc_val.ac_val      = dsl_attr_sn.dsc_val.ac_val      = achl_1;
            dsl_attr_cn.dsc_val.imc_len_val = dsl_attr_sn.dsc_val.imc_len_val = adsl_list_1->imc_len_rdn - (int)(achl_1 - (char *)(adsl_list_1 + 1));

            // add additional objectclasses (CSV format)...
            if (adsp_co_ldap->imc_len_attrlist && adsp_co_ldap->ac_attrlist)
            {
              char *achl_csv, *achl_csv_2, *achl_csv_3;
              int   iml_csv;

              // translate string to utf-8, if necessary...
              if (adsp_co_ldap->iec_chs_attrlist != ied_chs_utf_8)
              { // translate to utf_8
                iml_csv = m_len_vx_vx( ied_chs_utf_8,
                                       (void *)adsp_co_ldap->ac_attrlist, adsp_co_ldap->imc_len_attrlist, adsp_co_ldap->iec_chs_attrlist );
                if (iml_csv == -1)
                { // error, invalid string format...
                  goto ADD_CONTAINER;
                }
                // allocate storage for the translation
                achl_csv = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, iml_csv );
                // translation to UTF-8...
                if (m_cpy_vx_vx_fl( (void *)achl_csv, iml_csv, ied_chs_utf_8,
                                    (void *)adsp_co_ldap->ac_attrlist, adsp_co_ldap->imc_len_attrlist, adsp_co_ldap->iec_chs_attrlist,
                                    D_CPYVXVX_FL_NOTAIL0 ) == -1)
                { // error, invalid string format...
                  goto ADD_CONTAINER;
                } 
              }
              else
              { // format was ok
                achl_csv = adsp_co_ldap->ac_attrlist;
                iml_csv  = adsp_co_ldap->imc_len_attrlist;
              }

              // step through this array of strings...
              // check for the string length -1 (zero terminated string)
              if (iml_csv < 0)  iml_csv = (int)strnlen( (const char *)achl_csv, D_LDAP_MAX_STRLEN );
              achl_csv_2 = achl_csv;
              while (iml_csv)
              {  // search for ','-delimiter
                 if (_iscomma(*achl_csv))
                 { // delimiter found
                   achl_csv_3 = achl_csv;
                   while (isspace((unsigned char)*achl_csv_2))      ++achl_csv_2;   // ignore spaces...
                   while (isspace((unsigned char)*(achl_csv - 1)))  --achl_csv;
                   // set objectclass-attribute value...
                   adsl_val_ext->adsc_next_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                                                                          sizeof(struct dsd_ldap_val));
                   memset((void *)adsl_val_ext->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                   adsl_val_ext = adsl_val_ext->adsc_next_val;
                   adsl_val_ext->ac_val      = achl_csv_2;
                   adsl_val_ext->imc_len_val = int(achl_csv - achl_csv_2);
                   adsl_val_ext->iec_chs_val = ied_chs_utf_8;
                   // step to the next element...
                   achl_csv_2 = achl_csv_3 + 1;
                   achl_csv   = achl_csv_3;
                 }
                 ++achl_csv;
                 --iml_csv;
              } // end of while()

              if (achl_csv_2)
              {  // set objectclass-attribute value...
                 adsl_val_ext->adsc_next_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                                                                        sizeof(struct dsd_ldap_val));
                 memset((void *)adsl_val_ext->adsc_next_val, int(0), sizeof(struct dsd_ldap_val));

                 adsl_val_ext = adsl_val_ext->adsc_next_val;
                 adsl_val_ext->ac_val      = achl_csv_2;
                 adsl_val_ext->imc_len_val = int(achl_csv - achl_csv_2);
                 adsl_val_ext->iec_chs_val = ied_chs_utf_8;
              }
            } // user specific objectclasses
          } // user/group-entry
          else
          { // domain or container?
            if (!m_hl_memicmp( (void *)(adsl_list_1 + 1), (void *)"dc", 2 ))
            { // domain...
              dsl_oc.dsc_val.adsc_next_val = &dsl_val_domain;
              dsl_oc.adsc_next_attr = &dsl_attr_dc;

              dsl_attr_dc.dsc_val.ac_val      = achl_1;
              dsl_attr_dc.dsc_val.imc_len_val = adsl_list_1->imc_len_rdn - (int)(achl_1 - (char *)(adsl_list_1 + 1));
            }
            else
            { // container...
SET_CONTAINER:
              if (iml_cn != 0)
              { // ou=...
                dsl_oc.dsc_val.adsc_next_val = &dsl_val_orgunit;
                dsl_oc.adsc_next_attr = &dsl_attr_ou;
                dsl_attr_ou.dsc_val.ac_val      = achl_1;
                dsl_attr_ou.dsc_val.imc_len_val = adsl_list_1->imc_len_rdn - (int)(achl_1 - (char *)(adsl_list_1 + 1));
              }
              else
              { // cn=...
                dsl_oc.dsc_val.adsc_next_val = &dsl_val_container;
                dsl_oc.adsc_next_attr = &dsl_attr_cn;
                dsl_attr_cn.dsc_val.ac_val      = achl_1;
                dsl_attr_cn.dsc_val.imc_len_val = adsl_list_1->imc_len_rdn - (int)(achl_1 - (char *)(adsl_list_1 + 1));
              }
            }
          }

ADD_CONTAINER:
          iml_rc = this->m_ldap_add( &dsl_co_ldap_add );
          if (iml_rc != ied_ldap_success)
            return iml_rc;
          else
            bol_added = TRUE;  // from now we can omit 'm_ldap_lookup()'!!!
        }
      }

     // path exists or is created now!
     adsl_list_1 = adsl_list_1->adsc_next;
   } // while(adsl_list_1)

	void** avol_stor_handle_tmp = &this->ads_hl_stor_tmp;
     
   // set return value (new DN)
   adsp_co_ldap->iec_chs_dn = ied_chs_utf_8;
   adsp_co_ldap->imc_len_dn = iml_len_dn;
   adsp_co_ldap->ac_dn      = (char *)ms_aux_mem(adsp_co_ldap, avol_stor_handle_tmp, iml_len_dn );
   memcpy( (void *)adsp_co_ldap->ac_dn, (const void *)achl_dn, iml_len_dn );
   FREE_MEM(this->ads_hl_stor_per, achl_dn)

   // do we have extra objectclasses?
   if (adsp_co_ldap->imc_len_attrlist && adsp_co_ldap->ac_attrlist)
   { // yes, step through the chain...
     adsl_val_ext_2 = adsl_val_ext = dsl_val_pers.adsc_next_val;
     while (adsl_val_ext)
     {
       adsl_val_ext_2 = adsl_val_ext->adsc_next_val;
       FREE_MEM( this->ads_hl_stor_per, adsl_val_ext )
       adsl_val_ext = adsl_val_ext_2;
     }

     adsl_val_ext_2 = adsl_val_ext = dsl_val_group.adsc_next_val;
     while (adsl_val_ext)
     {
       adsl_val_ext_2 = adsl_val_ext->adsc_next_val;
       FREE_MEM( this->ads_hl_stor_per, adsl_val_ext )
       adsl_val_ext = adsl_val_ext_2;
     }
   }

   return ied_ldap_success;

}; // dsd_ldap::m_ldap_clone_dn()


/**
 * class function:  dsd_ldap::m_hex2value()
 *
 * returns the value of a hex-character (e.g. 'A' -> 0x0A).
 *
 * @param[in]  imp_ch   hex character (ASCII)
 *
 * @return     int   hex value or
 *          \b -1    error, if not a valid hex character
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_ldap::m_hex2value( int imp_ch )
{
    if (imp_ch >= '0' && imp_ch <= '9' )  return imp_ch - '0';
    if (imp_ch >= 'A' && imp_ch <= 'F' )  return imp_ch + (10 - int('A'));
    if (imp_ch >= 'a' && imp_ch <= 'f' )  return imp_ch + (10 - int('a'));
    return -1;

}; // dsd_ldap::m_hex2value()


/**
 * Private class function:  dsd_ldap::m_aux_search_RootDSE()
 *
 * Searches for the 'namingcontexts'-entries of the LDAP directory and
 *
 *      ASN.1:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   none,
 *                                                   scope        baseObject (0),
 *                                                   derefAliases neverDerefAliases (0),
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    False,
 *                                                   filter       present('objectClass'),
 *                                                   attributes   'namingContexts' 'subschemSubentry' 'defaultNamingContext'
 *                                                                'schemaNamingContext' 'supportedSASLMechanisms'
 *                                                                'supportedExtension' 'supportedControl' 'dnsHostName'
 *                                                                'supportedLdapVersion' 'vendorname' 'vendorversion'
 *                                                 }
 *
 *      MSAD only:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   none,
 *                                                   scope        wholeSubtree (0),
 *                                                   derefAliases neverDerefAliases (0),
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    False,
 *                                                   filter       present('objectClass=domainDNS'),
 *                                                   attributes   'objectSID'
 *                                                 }
 *
 *
 * @return    error        (\b ied_ldap_failure),
 *            successful   (\b ied_ldap_success) or
 *            send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_search_RootDSE()
{
   void  *avol_1;
   BOOL   bol_found (FALSE);
   struct dsd_ldap_attr_desc *adsl_attr_desc (NULL);
   struct dsd_ldap_attr      *adsl_attr_1;
   struct dsd_ldap_val       *adsl_val_1, **aadsl_val_1;


   this->bo_RootDSE = FALSE;

   // trace message LDAP0051T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 51, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Search-RootDSE Max-Size=%i Max-Time=%i",
                                  this->ads_ldap_entry->imc_search_buf_size, this->ads_ldap_entry->imc_timeout_search );

   // perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   if (this->ds_asn1.m_printf( "{it{seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               NULL, 0, int(ied_chs_invalid) /*baseObject: s*/,
                               int(ied_sear_baseobject) /*e*/,
                               LDAP_DEREF_NEVER /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) in asn.1-format...
   if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) == LASN1_ERROR)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }
   // we end with the attributes items to return...
   if (this->ds_asn1.m_printf( "{a}}}", achs_RootDSE, int(ied_chs_utf_8) ) == LASN1_ERROR)
   { // error; we can't execute this ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL?
   int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc = this->m_recv( ied_ldap_search_err /* apicode */ );
      if (iml_rc != ied_ldap_success)
        return iml_rc;

      // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
        return ied_ldap_failure;
      }

      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             bol_found = TRUE;
             // find next free structure in the chain...
             iml_rc = this->m_aux_search_result_entry( &adsl_attr_desc );
             if (iml_rc != ied_ldap_success)
               return iml_rc;

             // free already allocated structures (e.g 'namingcontexts','subschemaSubentry',...)
             while (this->ds_RootDSE.ads_namingcontexts)
             {  // save 'next'-pointer
                avol_1 = (void *)this->ds_RootDSE.ads_namingcontexts->adsc_next_val;
                FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_namingcontexts )
                this->ds_RootDSE.ads_namingcontexts = (struct dsd_ldap_val *)avol_1;
             }

             while (this->ds_RootDSE.ads_SASLmechanisms)
             {  // save 'next'-pointer
                avol_1 = (void *)this->ds_RootDSE.ads_SASLmechanisms->adsc_next_val;
                FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_SASLmechanisms )
                this->ds_RootDSE.ads_SASLmechanisms = (struct dsd_ldap_val *)avol_1;
             }

             while (this->ds_RootDSE.ads_extendedOIDs)
             {  // save 'next'-pointer
                avol_1 = (void *)this->ds_RootDSE.ads_extendedOIDs->adsc_next_val;
                FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_extendedOIDs )
                this->ds_RootDSE.ads_extendedOIDs = (struct dsd_ldap_val *)avol_1;
             }

             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_subschemaentry )
             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_schemacontext )
             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_defaultcontext )
             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_vendorname )
             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_vendorversion )
             FREE_MEM( this->ads_hl_stor_per, this->ds_RootDSE.ads_dnshostname )
             // reset page control option
             this->bo_page_results = FALSE;


             // get the array(vector) of attribute values...
             adsl_attr_1 = adsl_attr_desc->adsc_attr;
             while (adsl_attr_1)
             {  // check the returned partial attributes...
                adsl_val_1 = &adsl_attr_1->dsc_val;


                switch (adsl_attr_1->imc_len_attr)
                {
                    case sizeof namingContexts - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_nctx], adsl_attr_1->imc_len_attr ))
                        { // save 'namingContext'...
                          // please pay attention, that some ldap servers send empty strings (e.g. Novell eDirectory)
                          aadsl_val_1 = &this->ds_RootDSE.ads_namingcontexts;
                          while (adsl_val_1 && adsl_val_1->imc_len_val)
                          {
                            *aadsl_val_1 = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                            memset((void *)*aadsl_val_1, int(0), sizeof(struct dsd_ldap_val));

                            ((struct dsd_ldap_val *)*aadsl_val_1)->ac_val      = (char *)*aadsl_val_1 + sizeof(struct dsd_ldap_val);
                            ((struct dsd_ldap_val *)*aadsl_val_1)->imc_len_val = adsl_val_1->imc_len_val;
                            ((struct dsd_ldap_val *)*aadsl_val_1)->iec_chs_val = adsl_val_1->iec_chs_val;
                            memcpy( (void *)((struct dsd_ldap_val *)*aadsl_val_1)->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );

                            adsl_val_1  = adsl_val_1->adsc_next_val;
                            aadsl_val_1 = &((struct dsd_ldap_val *)*aadsl_val_1)->adsc_next_val;
                          } // while()
                        }
                        break;

                    case sizeof defaultNamingContext - 1:
                 /* case sizeof supportedLDAPVersion - 1: */
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_def_nctx], adsl_attr_1->imc_len_attr ))
                        { // save 'defaultNamingContext'...
                          this->ds_RootDSE.ads_defaultcontext = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_defaultcontext, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_defaultcontext->ac_val      = (char *)this->ds_RootDSE.ads_defaultcontext + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_defaultcontext->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_defaultcontext->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_defaultcontext->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );
                        }
                        else
                        {
                          if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_ldap_ver], adsl_attr_1->imc_len_attr ))
                          { // test 'supportedLDAPVersion'...
                            BOOL bol_ver_supported (FALSE);
                            while (adsl_val_1)
                            {
                               if (!m_hl_memicmp( adsl_val_1->ac_val, (void *)LDAP_VERSION_3_S, adsl_val_1->imc_len_val))
                               {
                                 bol_ver_supported = TRUE;
                                 break;
                               }
                               adsl_val_1  = adsl_val_1->adsc_next_val;
                            } // while()

                            if (!bol_ver_supported)
                            { // error; we need LDAP v3
                              this->ds_ldap_error.m_set_error( ied_ldap_not_supp, ied_ldap_search_err );
                              return ied_ldap_failure;
                            }
                          }
                        }
                        break;

                    case sizeof schemaNamingContext - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_sch_nctx], adsl_attr_1->imc_len_attr ))
                        { // save 'schemaNamingContext' (MSAD only)
                          this->ds_RootDSE.ads_schemacontext = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_schemacontext, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_schemacontext->ac_val      = (char *)this->ds_RootDSE.ads_schemacontext + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_schemacontext->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_schemacontext->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_schemacontext->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );

                          // change the server type if we have a generic template
                          if (this->im_ldap_templ == ied_sys_ldap_generic)
                            this->im_ldap_type = ied_sys_ldap_msad;
                        }
                        break;

                    case sizeof dnsHostName - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_dns_name], adsl_attr_1->imc_len_attr ))
                        { // save 'dnsHostName'
                          this->ds_RootDSE.ads_dnshostname = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_dnshostname, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_dnshostname->ac_val      = (char *)this->ds_RootDSE.ads_dnshostname + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_dnshostname->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_dnshostname->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_dnshostname->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );
                        }
                        break;

                    case sizeof subschemaSubentry - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_sub_schema], adsl_attr_1->imc_len_attr ))
                        { // save 'subschemaSubentry'...
                          this->ds_RootDSE.ads_subschemaentry = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_subschemaentry, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_subschemaentry->ac_val      = (char *)this->ds_RootDSE.ads_subschemaentry + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_subschemaentry->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_subschemaentry->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_subschemaentry->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );
                        }
                        break;

                    case sizeof supportedSASLMechanisms - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_sasl_mech], adsl_attr_1->imc_len_attr ))
                        { // save 'supportedSASLMechanisms'...
                          aadsl_val_1 = &this->ds_RootDSE.ads_SASLmechanisms;
                          while (adsl_val_1)
                          {
                            *aadsl_val_1 = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                            memset((void *)*aadsl_val_1, int(0), sizeof(struct dsd_ldap_val));

                            ((struct dsd_ldap_val *)*aadsl_val_1)->ac_val      = (char *)*aadsl_val_1 + sizeof(struct dsd_ldap_val);
                            ((struct dsd_ldap_val *)*aadsl_val_1)->imc_len_val = adsl_val_1->imc_len_val;
                            ((struct dsd_ldap_val *)*aadsl_val_1)->iec_chs_val = adsl_val_1->iec_chs_val;
                            memcpy( (void *)((struct dsd_ldap_val *)*aadsl_val_1)->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );

                            adsl_val_1  = adsl_val_1->adsc_next_val;
                            aadsl_val_1 = &((struct dsd_ldap_val *)*aadsl_val_1)->adsc_next_val;
                          } // while()
                        }
                        break;

                    case sizeof supportedExtension - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_extent], adsl_attr_1->imc_len_attr ))
                        { // save 'supportedExtension'...
                          aadsl_val_1 = &this->ds_RootDSE.ads_extendedOIDs;
                          while (adsl_val_1)
                          {
                            *aadsl_val_1 = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                            memset((void *)*aadsl_val_1, int(0), sizeof(struct dsd_ldap_val));

                            ((struct dsd_ldap_val *)*aadsl_val_1)->ac_val      = (char *)*aadsl_val_1 + sizeof(struct dsd_ldap_val);
                            ((struct dsd_ldap_val *)*aadsl_val_1)->imc_len_val = adsl_val_1->imc_len_val;
                            ((struct dsd_ldap_val *)*aadsl_val_1)->iec_chs_val = adsl_val_1->iec_chs_val;
                            memcpy( (void *)((struct dsd_ldap_val *)*aadsl_val_1)->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );

                            adsl_val_1  = adsl_val_1->adsc_next_val;
                            aadsl_val_1 = &((struct dsd_ldap_val *)*aadsl_val_1)->adsc_next_val;
                          } // while()
                        }
                        break;

                    case sizeof supportedControl - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_control], adsl_attr_1->imc_len_attr))
                        { // check for 'pageResultsControl'-OID and 'LDAP_SERVER_TREE_DELETE'-OID
                          while (adsl_val_1 && (this->bo_page_results == FALSE || this->bo_deltree == FALSE))
                          {
                            if (!m_hl_memicmp( adsl_val_1->ac_val, (void *)OID_PAGE_RESULTS, adsl_val_1->imc_len_val))
                              this->bo_page_results = TRUE;
                            else
                              if (!m_hl_memicmp( adsl_val_1->ac_val, (void *)OID_DELTREE, adsl_val_1->imc_len_val))
                                this->bo_deltree = TRUE;

                            adsl_val_1  = adsl_val_1->adsc_next_val;
                          } // while()
                        }
                        break;

                    case sizeof vendorName - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_vname], adsl_attr_1->imc_len_attr ))
                        { // save 'vendorName'...
                          this->ds_RootDSE.ads_vendorname = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_vendorname, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_vendorname->ac_val      = (char *)this->ds_RootDSE.ads_vendorname + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_vendorname->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_vendorname->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_vendorname->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );
                        }
                        break;

                    case sizeof vendorVersion - 1:
                        if (!m_hl_memicmp( adsl_attr_1->ac_attr, (void *)achs_RootDSE[ied_vver], adsl_attr_1->imc_len_attr ))
                        { // save 'vendorVersion'...
                          this->ds_RootDSE.ads_vendorversion = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + adsl_val_1->imc_len_val );
                          memset((void *)this->ds_RootDSE.ads_vendorversion, int(0), sizeof(struct dsd_ldap_val));

                          this->ds_RootDSE.ads_vendorversion->ac_val      = (char *)this->ds_RootDSE.ads_vendorversion + sizeof(struct dsd_ldap_val);
                          this->ds_RootDSE.ads_vendorversion->imc_len_val = adsl_val_1->imc_len_val;
                          this->ds_RootDSE.ads_vendorversion->iec_chs_val = adsl_val_1->iec_chs_val;
                          memcpy( (void *)this->ds_RootDSE.ads_vendorversion->ac_val, (const void *)adsl_val_1->ac_val, adsl_val_1->imc_len_val );
                        }
                        break;

                    default:
                       break;

                } // switch (adsl_attr_1->imc_len_attr)

               // step to the next
               adsl_attr_1 = adsl_attr_1->adsc_next_attr;
             } // while (partial attributes)

             break;
        case LDAP_RESP_SEARCH_DONE:
        case LDAP_RESP_SEARCH_REF:
        default:
             break;
      } // end of switch()

   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);


   // handle empty namingContexts values safely
   if (this->ds_RootDSE.ads_namingcontexts == NULL)
   { // try to change to get the namingContects (strategy of Apache Directory Studio)
     // trace message LDAP0047T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
       this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 47, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "Search-RootDSE (namingContexts)  Max-Size=%i Max-Time=%i",
                                    this->ads_ldap_entry->imc_search_buf_size, this->ads_ldap_entry->imc_timeout_search );

     // perform ldap search...
     LDAPREQ_SEARCH(this->ds_ldapreq)
     // initiate ASN.1 class...
     this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
     // initialize receive buffer storage management
     this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

     if (this->ds_asn1.m_printf( "{it{seeiib",
                                 this->ds_ldapreq.imc_msgid /*i*/,
                                 this->ds_ldapreq.imc_req /*t*/,
                                 NULL, 0, int(ied_chs_invalid) /*baseObject: s*/,
                                 int(ied_sear_baseobject) /*e*/,
                                 LDAP_DEREF_NEVER /*e*/,
                                 this->ads_ldap_entry->imc_search_buf_size /*i*/,
                                 this->ads_ldap_entry->imc_timeout_search /*i*/,
                                 FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
     { // error; we can't execute the ldap-search!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
       return ied_ldap_failure;
     }

     // now we set the filter(s) in asn.1-format...
     if (this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 ) == LASN1_ERROR)
     { // error, we can't set a valid filter combination!
       this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
       return ied_ldap_failure;
     }
     // we end with the attributes items to return...
     if (this->ds_asn1.m_printf( "{C}}}", "objectClass", sizeof "objectClass" - 1, int(ied_chs_utf_8) ) == LASN1_ERROR)
     { // error; we can't execute this ldap-search!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
       return ied_ldap_failure;
     }

     // send the message...
     this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
     this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
     // statistics...
     ++this->ads_ldap_entry->imc_count_search;
     ++this->ads_ldap_entry->imc_send_packet;
     this->il_start_time = m_get_epoch_ms();

     // SSL or non SSL?
     int iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
     if (iml_rc != ied_ldap_success)
       return iml_rc;


     // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
     char       *achl_dn;
     int         iml_len_dn;
     ied_charset iel_chs_dn;

     do
     {  // enable receiving...
        this->ads_ldap_control->bo_recv_complete = FALSE;
        iml_rc = this->m_recv( ied_ldap_search_err /* apicode */ );
        if (iml_rc != ied_ldap_success)
          return iml_rc;

        // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
        this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

        if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
        { // @todo: error message to event viewer or something else...
          this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
          return ied_ldap_failure;
        }

        switch (ds_asn1.im_op)
        {
          case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
               achl_dn    = NULL;
               iml_len_dn = 0;
               adsl_attr_desc = NULL;

               // search end of chain....
               aadsl_val_1 = &this->ds_RootDSE.ads_namingcontexts;
               while (*aadsl_val_1)
                  aadsl_val_1 = &((struct dsd_ldap_val *)*aadsl_val_1)->adsc_next_val;

               // save 'namingContext'...
               while (this->m_aux_search_result_entry( &adsl_attr_desc,
                                                       &achl_dn, &iml_len_dn, &iel_chs_dn ) == ied_ldap_success &&
                      achl_dn && iml_len_dn > 0)
               {
                  *aadsl_val_1 = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_ldap_val) + iml_len_dn );
                  memset((void *)*aadsl_val_1, int(0), sizeof(struct dsd_ldap_val));

                  ((struct dsd_ldap_val *)*aadsl_val_1)->ac_val        = (char *)*aadsl_val_1 + sizeof(struct dsd_ldap_val);
                  ((struct dsd_ldap_val *)*aadsl_val_1)->imc_len_val   = iml_len_dn;
                  ((struct dsd_ldap_val *)*aadsl_val_1)->iec_chs_val   = iel_chs_dn;
                  memcpy( (void *)((struct dsd_ldap_val *)*aadsl_val_1)->ac_val, (const void *)achl_dn, iml_len_dn );

                  aadsl_val_1 = &((struct dsd_ldap_val *)*aadsl_val_1)->adsc_next_val;
               } // while(dn)

          case LDAP_RESP_SEARCH_DONE:
          case LDAP_RESP_SEARCH_REF:
          default:
               break;
        } // end of switch()

     } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   } // namingContexts were null

   // RootDSE search was successful so far!
   this->bo_RootDSE = TRUE;

   // ----------------------------------------------------------------------------------------------------
   // only MSAD (domainDNS - objectSID)...
   if (this->im_ldap_type == ied_sys_ldap_msad)
   {
     struct dsd_ldap_val  dsl_context;

     // MS LDS doesn't support 'defaultNamingContext'
     if (this->ds_RootDSE.ads_defaultcontext)
     { // MSAD with default context
       dsl_context.ac_val      = this->ds_RootDSE.ads_defaultcontext->ac_val;
       dsl_context.imc_len_val = this->ds_RootDSE.ads_defaultcontext->imc_len_val;
       dsl_context.iec_chs_val = this->ds_RootDSE.ads_defaultcontext->iec_chs_val;
     }
     else
     { // MS LDS
       dsl_context.ac_val      = this->ads_ldap_entry->achc_base_dn;
       dsl_context.imc_len_val = this->ads_ldap_entry->imc_len_base_dn;
       dsl_context.iec_chs_val = ied_chs_utf_8;
     }
    
     LDAP_REQ_STRUC(dsl_co_ldap)
     
     dsl_co_ldap.iec_sear_scope   = ied_sear_sublevel;
     dsl_co_ldap.ac_filter        = (char *)"(objectClass=domainDNS)";
     dsl_co_ldap.imc_len_filter   = sizeof "(objectClass=domainDNS)" - 1;
     dsl_co_ldap.iec_chs_filter   = ied_chs_utf_8;
     dsl_co_ldap.ac_attrlist      = (char *)"objectSid";
     dsl_co_ldap.imc_len_attrlist = sizeof "objectSid" - 1;
     dsl_co_ldap.iec_chs_attrlist = ied_chs_utf_8;
     dsl_co_ldap.ac_dn            = dsl_context.ac_val;
     dsl_co_ldap.imc_len_dn       = dsl_context.imc_len_val;
     dsl_co_ldap.iec_chs_dn       = dsl_context.iec_chs_val;


     // the object clas 'domainDNS' is optional, ignore the search 'no result'-error
     if (this->m_ldap_search( &dsl_co_ldap ) == ied_ldap_success)
     { // save domain SID
       FREE_MEM( this->ads_hl_stor_per, this->ads_domainSID )

       if (dsl_co_ldap.adsc_attr_desc)
       {
         this->ads_domainSID = (struct dsd_sid *)m_aux_stor_alloc( &this->ads_hl_stor_per, sizeof(struct dsd_sid) );
         memset( (void *)this->ads_domainSID, 0, sizeof(struct dsd_sid) );
         memcpy( (void *)this->ads_domainSID,
                 (const void *)dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.ac_val,
                 dsl_co_ldap.adsc_attr_desc->adsc_attr->dsc_val.imc_len_val );
       }
     }

   } // MSAD only

   return ied_ldap_success;

}; // dsd_ldap::m_aux_search_RootDSE()


/**
 * Private class function:  dsd_ldap::m_aux_search_result_entry()
 *
 * Parses the 'SearchResultEntry'-operation. 
 *
 * Note that the PartialAttributeList may hold zero (!) elements. This may happen when none of the attributes of 
 * an entry were requested or could be returned. Note also that the PartialAttribute vals set may hold zero (!)
 * elements. This may happen when typesOnly is requested.
 *
 *      ASN.1:
 *      SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName   LDAPDN,
 *                                                       attributes   PartialAttributeList }
 *
 *                        PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
 *
 *                        PartialAttribute ::= SEQUENCE { type   AttributeDescription (LDAPString),
 *                                                        vals   SET OF value  AttributeValue (OCTETString)
 *                                                      }
 *
 *
 * @param[in,out]  aadsp_ldap_attr_desc  request structure
 * @param[in,out]  aachp_dn              pointer to the dn string address, if at least one attribute was returned
 * @param[in,out]  aimp_len_dn           pointer to the dn string length address
 * @param[in,out]  aiep_chs_dn           pointer to the dn string character-set address
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_search_result_entry( struct dsd_ldap_attr_desc **aadsp_ldap_attr_desc,
                                         char **aachp_dn, int *aimp_len_dn, enum ied_charset *aiep_chs_dn )
{
   struct dsd_ldap_attr_desc **aadsl_ldap_attr_desc;
   struct dsd_ldap_val       **aadsl_ldap_val, *adsl_val;
   struct dsd_ldap_attr      **aadsl_ldap_attr = NULL;

   char  *achl_dn = NULL, *achl_attr;
   int    iml_len_dn = 0, iml_len_attr;


   // initialize return parameter
   if (aachp_dn)
   {
     *aachp_dn    = NULL;
     *aimp_len_dn = 0;
     *aiep_chs_dn = ied_chs_invalid;
   }

   // get the 'objectName (DN)'...
   // it's valid only if at least one attribute was returned.
   if (this->ds_asn1.m_scanf( "{O{", &achl_dn, &iml_len_dn, &this->ads_hl_stor_per ) != LASN1_SUCCESS)
   { // protocol error!
     this->ds_ldap_error.m_set_error( ied_ldap_decoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // shorten the DN (without superfluous blanks)
   int   iml_1;
   char *achl_1, *achl_2;

   if (iml_len_dn && achl_dn)
   { // remove following blanks...
     achl_1 = achl_dn + iml_len_dn - 1;
     while (iml_len_dn && isspace((unsigned char)*achl_1))
     {  achl_1--, iml_len_dn--;  }

     // remove leading blanks...
     achl_1 = achl_dn;
     while (iml_len_dn && isspace((unsigned char)*achl_1))
     {  achl_1++, iml_len_dn--;  }

     // did we found leading blanks?
     if (achl_1 != achl_dn)
 	  memcpy( (void *)achl_dn, (const void *)achl_1, iml_len_dn );


     iml_1  = iml_len_dn;
     achl_1 = achl_dn;

     while (iml_1)
     { // remove blanks between a 'comma' and the first character of the next dn-part...
       achl_2 = (char *)memchr( (const void *)achl_1, int(','), iml_1 );
       if (achl_2 /*comma found, is it unmasked?*/)
       {
	     achl_2++;                         // after the 'comma'
         iml_1 -= (int)(achl_2 - achl_1);  // length of the remaining rest
         achl_1 = achl_2;

         if (*(achl_2 - 2) != 0x5c /*'\'-escape character*/)
         { // unmasked comma found!
           // remove space(s) after the 'comma'
           while (iml_1 && isspace((unsigned char)*achl_1))
  	       {  achl_1++, iml_1--, iml_len_dn--;  }

           // did we found any blanks?
           if (achl_1 != achl_2)
           { // yes, move the rest of the string
	        memcpy( (void *)achl_2, (const void *)achl_1, iml_1 );
	         achl_1 = achl_2;
	       }
	     } // unmasked comma found!
       }
       else
         // no more characters found, now search the blanks before a 'comma'
         break;
     } // while (iml_1)


     iml_1  = iml_len_dn;
     achl_1 = achl_dn;

     while (iml_1)
     { // remove blanks before a 'comma' and the first character of the previous dn-part...
       achl_2 = (char *)memchr( (const void *)achl_1, int(','), iml_1 );
       if (achl_2 /*comma found, is it unmasked?*/)
       {
         iml_1 -= (int)(achl_2 - achl_1);  // length of the remaining rest
   	     achl_1 = achl_2;

         if (*(achl_2 - 1) != 0x5c /*'\'-escape character*/)
         { // unmasked comma found!
           // remove space(s) before the 'comma'
           while (iml_len_dn && isspace((unsigned char)*(achl_1 - 1)))
	       {  achl_1--, iml_len_dn--;  }

           // did we found any blanks?
           if (achl_1 != achl_2)
             // yes, move the rest of the string
 	         memcpy( (void *)achl_1, (const void *)achl_2, iml_1 );
         }
         achl_1++, iml_1--;
       }
       else
         // no more characters found!
         break;
     } // while (iml_1)
   } // end of valid 'objectName'


   aadsl_ldap_attr_desc = aadsp_ldap_attr_desc;
   do
   { // scan for all returned attribute(s) and their value(s)...
     iml_len_attr = 0;
     achl_attr = NULL;
     adsl_val  = NULL;

     switch (this->ds_asn1.m_scanf( "{o[v]}", &achl_attr, &iml_len_attr, &adsl_val ))
     {
       case LASN1_ERROR:     // protocol error!
                             this->ds_ldap_error.m_set_error( ied_ldap_decoding_err, ied_ldap_search_err );
                             return ied_ldap_failure;

       case LASN1_WAIT_MORE: // no more attributes found!
                             if (*aadsl_ldap_attr_desc == NULL)
                             { 
                               this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results );
                               return ied_ldap_failure;
                             }
                             return ied_ldap_success;

       case LASN1_SUCCESS:   // save return values...
                             if (*aadsl_ldap_attr_desc == NULL)
                             { // save DN of the following attribute(s)
                               if (aachp_dn)
                               { // save baseobject DN
                                 *aachp_dn    = achl_dn;
                                 *aimp_len_dn = iml_len_dn;
                                 *aiep_chs_dn = ied_chs_utf_8;
                               }

                               *aadsl_ldap_attr_desc = (struct dsd_ldap_attr_desc *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                                                      sizeof(struct dsd_ldap_attr_desc) );
                               (*aadsl_ldap_attr_desc)->ac_dn      = achl_dn;
                               (*aadsl_ldap_attr_desc)->imc_len_dn = iml_len_dn;
                               (*aadsl_ldap_attr_desc)->iec_chs_dn = ied_chs_utf_8;

                               (*aadsl_ldap_attr_desc)->adsc_next_attr_desc = NULL;
                               (*aadsl_ldap_attr_desc)->adsc_attr           = NULL;
                               aadsl_ldap_attr = &(*aadsl_ldap_attr_desc)->adsc_attr;
                             }

                             *aadsl_ldap_attr = (struct dsd_ldap_attr *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                                          sizeof(struct dsd_ldap_attr) );
                             // set attribute description
                             (*aadsl_ldap_attr)->iec_chs_attr   = ied_chs_utf_8;
                             (*aadsl_ldap_attr)->imc_len_attr   = iml_len_attr;
                             (*aadsl_ldap_attr)->ac_attr        = achl_attr;
                             (*aadsl_ldap_attr)->adsc_next_attr = NULL;
                             // set value description of the attribute saved above
                             memset((void *)&(*aadsl_ldap_attr)->dsc_val, int(0), sizeof(struct dsd_ldap_val));

                             (*aadsl_ldap_attr)->dsc_val.iec_chs_val = ied_chs_utf_8;
                             (*aadsl_ldap_attr)->dsc_val.imc_len_val = adsl_val ? adsl_val->imc_len_val : 0;
                             (*aadsl_ldap_attr)->dsc_val.ac_val      = adsl_val ? adsl_val->ac_val : NULL;

                             // test for multivalued...
                             aadsl_ldap_val = adsl_val ? &(*aadsl_ldap_attr)->dsc_val.adsc_next_val : NULL;
                             while (adsl_val && adsl_val->adsc_next_val)
                             { // multivalued!
                               *aadsl_ldap_val = (struct dsd_ldap_val *)m_aux_stor_alloc( &this->ads_hl_stor_tmp,
                                                                                          sizeof(struct dsd_ldap_val) );
                               memset((void *)*aadsl_ldap_val, int(0), sizeof(struct dsd_ldap_val));

                               adsl_val = adsl_val->adsc_next_val;

                               (*aadsl_ldap_val)->iec_chs_val = ied_chs_utf_8;
                               (*aadsl_ldap_val)->imc_len_val = adsl_val->imc_len_val;
                               (*aadsl_ldap_val)->ac_val      = adsl_val->ac_val;

                                aadsl_ldap_val = &(*aadsl_ldap_val)->adsc_next_val;
                             } // while(multivalued)

                             // set address to the next structure...
                             aadsl_ldap_attr = &(*aadsl_ldap_attr)->adsc_next_attr;
                             break;

       default:              break;
     } // end of switch()
   } while (1);

   return ied_ldap_success;

} // dsd_ldap::m_aux_search_result_entry()


#ifdef HOB_LDAP_REFERRAL
/**
 * Private class function:  dsd_ldap::m_aux_search_result_ref()
 *
 * Parses the 'SearchResultReference'-operation.
 *
 *      ASN.1:
 *      SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI
 *
 *                            uri ::= LDAPString
 *
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_search_result_ref()
{
   char  *achl_ref, *achl_ref_2, *achl_ref_3;
   int    iml_len_ref;


   // get the 'uri'...
   if (this->ds_asn1.m_scanf( "{o", &achl_ref, &iml_len_ref ) != LASN1_SUCCESS)
   { // protocol error!
     this->ds_ldap_error.m_set_error( ied_ldap_decoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // the ldap url (rfc 4516 describes the format, e.g. "ldap://ldap01.example.com/ou=users,dc=example,dc=com")
   // set address after "scheme COLON SLASH SLASH", look at rfc 4516 2ff.
   achl_ref    += sizeof "ldap://" - 1;
   iml_len_ref -= sizeof "ldap://" - 1;

   // allocate referral
   struct dsd_referral  *adsl_ref ((struct dsd_referral *)m_aux_stor_alloc( &this->ads_hl_stor_per,
                                                                            sizeof(struct dsd_referral) + iml_len_ref ));
   memset( (void *)adsl_ref, int(0), sizeof(struct dsd_referral) );

   // now we search the host part "[host [COLON port]]", terminated by SLASH
   achl_ref_2 = (char *)memchr( (const void *)achl_ref, int('/'), iml_len_ref );
   achl_ref_3 = (char *)memchr( (const void *)achl_ref, int(':'), iml_len_ref );

   if (achl_ref_2 > achl_ref)
   { // save host part
     adsl_ref->dsc_ldap_url.iec_chs_str = ied_chs_utf_8;
     adsl_ref->dsc_ldap_url.imc_len_str = (achl_ref_3 != NULL && achl_ref_3 < achl_ref_2)
                                          ? (achl_ref_3 - achl_ref)   // have port
                                          : (achl_ref_2 - achl_ref);  // no port, use ldap default 389

     if (achl_ref_3 != NULL && achl_ref_3 < achl_ref_2)
     { // read port number
       *achl_ref_2 = '\0';
       adsl_ref->imc_port = atoi( achl_ref_3 + 1 );
     }
     else
       // use default port
       adsl_ref->imc_port = D_LDAP_PORT;


     adsl_ref->dsc_ldap_url.ac_str = adsl_ref + 1;

     memcpy( (void *)adsl_ref->dsc_ldap_url.ac_str, (const void *)achl_ref, adsl_ref->dsc_ldap_url.imc_len_str );
     iml_len_ref -= adsl_ref->dsc_ldap_url.imc_len_str;
   } // host part

   // step after the SLASH
   achl_ref_2++;
   iml_len_ref--;

   // we finish with the dn part
   adsl_ref->dsc_devicecontext.iec_chs_str = ied_chs_utf_8;
   adsl_ref->dsc_devicecontext.imc_len_str = iml_len_ref;
   adsl_ref->dsc_devicecontext.ac_str      = adsl_ref + 1;
   adsl_ref->dsc_devicecontext.ac_str      = (char *)adsl_ref->dsc_devicecontext.ac_str + adsl_ref->dsc_ldap_url.imc_len_str;

   memcpy( (void *)adsl_ref->dsc_devicecontext.ac_str, (const void *)achl_ref_2, adsl_ref->dsc_devicecontext.imc_len_str );

   // chain the referral...
   // add the new entry at the end of chain, because this fastens the search later
   // the very first reference contains the information we are looking for (very often!)
   struct dsd_referral *adsl_ref_1 (this->ads_referral);

   if (adsl_ref_1)
   {
      while (adsl_ref_1->adsc_next)
         adsl_ref_1 = adsl_ref_1->adsc_next;

     adsl_ref_1->adsc_next = adsl_ref;
   }
   else
     this->ads_referral = adsl_ref;


   return ied_ldap_success;

} // dsd_ldap::m_aux_search_result_ref()
#endif // HOB_LDAP_REFERRAL


/**
 * Private class function:  dsd_ldap::m_aux_search_tree()
 *
 * Initiates a ldap search operation, beginning at the baseObject and then along the tree back to
 * the root-entry (one of the namingcontexts).
 *
 *      ASN.1:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   LDAPDN,
 *                                                   scope        ENUMERATED { baseObject   (0),
 *                                                                             singleLevel  (1),
 *                                                                             wholeSubtree (2) },
 *                                                   derefAliases ENUMERATED { neverDerefAliases   (0),
 *                                                                             derefInSearching    (1),
 *                                                                             derefFindingBaseObj (2),
 *                                                                             derefAlways         (3) },
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    BOOLEAN,
 *                                                   filter       Filter,
 *                                                   attributes   AttributeSelection }
 *
 *                         Filter ::= CHOICE { and             [0]  SET SIZE (1..MAX) OF filter Filter,
 *                                             or              [1]  SET SIZE (1..MAX) OF filter Filter,
 *                                             not             [2]  Filter,
 *                                             equalityMatch   [3]  AttributeValueAssertion,
 *                                             substrings      [4]  SubstringFilter,
 *                                             greaterOrEqual  [5]  AttributeValueAssertion,
 *                                             lessOrEqual     [6]  AttributeValueAssertion,
 *                                             present         [7]  AttributeDescription,
 *                                             approxMatch     [8]  AttributeValueAssertion,
 *                                             extensibleMatch [9]  MatchingRuleAssertion }
 *
 *                         AttributeSelection ::= SEQUENCE OF selector LDAPString
 *
 *                         AttributeValueAssertion ::= SEQUENCE { attributeDesc  AttributeDescription (LDAPString),
 *                                                                assertionValue AssertionValue       (OCTET STRING) }
 *
 *                         SubstringFilter ::= SEQUENCE { type       AttributeDescription,
 *                                                        substrings SEQUENCE SIZE OF substring CHOICE { initial [0] AssertionValue,
 *                                                                                                       any     [1] AssertionValue,
 *                                                                                                       final   [2] AssertionValue }
 *                                                      }
 *
 *                         MatchingRuleAssertion ::= SEQUENCE { matchingRule [1]  MatchingRuleId (LDAPString) OPTIONAL,
 *                                                              type         [2]  AttributeDescription        OPTIONAL,
 *                                                              matchValue   [3]  AssertionValue,
 *                                                              dnAttributes [4]  BOOLEAN
 *                                                            }
 *
 *
 * @param[in,out]  adsp_co_ldap   request structure
 *
 * @return         error        (\b ied_ldap_failure),
 *                 successful   (\b ied_ldap_success) or
 +                 send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_search_tree( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   int    iml_rc, iml_cmp, iml_1;
   char  *achl_1;
   char  *achl_dn (NULL);
   int    iml_len_dn (0);
   ied_charset iel_chs_dn (ied_chs_utf_8);

   struct dsd_ldap_val        *adsl_namingcontexts = NULL;
   struct dsd_ldap_attr_desc **aadsl_attr_desc;


   // allocate 'namingcontexts' as the base dn to compare
   if (this->bo_RootDSE == FALSE && this->m_aux_search_RootDSE() != ied_ldap_success)
   { // error; we can't execute the ldap-search!
     return ied_ldap_failure;
   }

   // ok, perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)

   // do we have any distinguished name as 'baseObject' ?
   if (adsp_co_ldap->imc_len_dn)
   { // yes, use the parameter dn
     iel_chs_dn = adsp_co_ldap->iec_chs_dn;
     iml_len_dn = adsp_co_ldap->imc_len_dn;
     achl_dn    = adsp_co_ldap->ac_dn;
   }
   else
   { // use the internal dn or scan over the namingcontexts...
     if (this->im_len_dn)
     { // use the last known dn!
       iel_chs_dn = ied_chs_utf_8;
       iml_len_dn = this->im_len_dn;
       achl_dn    = this->achr_dn;
     }
     else
     { // error; we can't execute the ldap-search!
       this->ds_ldap_error.m_set_error( ied_ldap_inv_dn_syntax, ied_ldap_search_err );
       return ied_ldap_failure;
     }
   }

   // search the corresponding context...
   adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;
   while (adsl_namingcontexts)
   {  // use this 'namingcontext' for searching entries...
      iml_1  = iml_len_dn - adsl_namingcontexts->imc_len_val;  // compare the context length only
      achl_1 = NULL;
      if (iml_1 >= 0)
      { // possible context root (dn >= namingcontext)
        achl_1 = achl_dn + iml_1;    // set start address
        if (m_cmpi_vx_vx( &iml_cmp,
                          (void *)adsl_namingcontexts->ac_val, adsl_namingcontexts->imc_len_val, adsl_namingcontexts->iec_chs_val,
                          (void *)achl_1, iml_len_dn - iml_1, iel_chs_dn ))
        { // baseObject found?
          if (!iml_cmp)
          // yes, ready to start
            break;

          // test next entry...
          adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
        }
      }
   } // while()

   // root-entry found ?
   if (adsl_namingcontexts == NULL)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_inv_dn_syntax, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   adsp_co_ldap->adsc_attr_desc = NULL;
   // initialize attribute description structure of the requester
   aadsl_attr_desc = &adsp_co_ldap->adsc_attr_desc;

SEARCH_TREE_REQUEST:
   // initiate ASN.1 class...
   this->ds_asn1.m_init( &this->ads_hl_stor_tmp );
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init( &this->ads_hl_stor_tmp );

   // create valid LDAP message ID...
   this->ds_ldapreq.imc_msgid = this->m_get_msgid();

   // trace message LDAP0073T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 73, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Search-Tree Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\" Max-Size=%i Max-Time=%i",
                                  this->ds_ldap_trace.m_translate( (int)ied_sear_baseobject, dsd_trace::S_SEARCH_SCOPE ),
                                  achl_dn ? iml_len_dn : sizeof "none" - 1,
                                  achl_dn ? iel_chs_dn : ied_chs_ascii_850,
                                  achl_dn ? achl_dn : "none",
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->imc_len_filter : sizeof "(objectClass=*)" - 1,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->iec_chs_filter : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->ac_filter : "(objectClass=*)",
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->imc_len_attrlist : sizeof "none" - 1,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->iec_chs_attrlist : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->ac_attrlist : "none",
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_search_buf_size : 0, 
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_timeout_search : 0);

   // build the asn.1-formatted search request...
   if (this->ds_asn1.m_printf( "{it{seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               achl_dn, iml_len_dn, int(iel_chs_dn) /*s*/,
                               int(ied_sear_baseobject) /*e*/,
                               LDAP_DEREF_NEVER /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) in asn.1-format...
   if (adsp_co_ldap->imc_len_filter == 0)
     // default: IBM secure way LDAP use this as default
     iml_rc = this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 );
   else
     // set filter parameter...
     iml_rc = this->ds_asn1.m_put_filter( (const char *)adsp_co_ldap->ac_filter, adsp_co_ldap->imc_len_filter, adsp_co_ldap->iec_chs_filter );

   // everything ok?
   if (iml_rc != LASN1_SUCCESS)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set asn1-attribute(s)...
   if (this->ds_asn1.m_printf( "{C}}}",
                               adsp_co_ldap->ac_attrlist, adsp_co_ldap->imc_len_attrlist, int(adsp_co_ldap->iec_chs_attrlist) /*C*/) == LASN1_ERROR)
   { // error, we can't set a valid attribute combination!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL?
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc = this->m_recv( ied_ldap_search_err /* apicode */ );
      if (iml_rc != ied_ldap_success)
        return iml_rc;

      // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
        return ied_ldap_failure;
      }

      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             // find next free structure in the chain...
             while (*aadsl_attr_desc)
                  aadsl_attr_desc = &(*aadsl_attr_desc)->adsc_next_attr_desc;

             this->m_aux_search_result_entry( aadsl_attr_desc );
             break;
        case LDAP_RESP_SEARCH_DONE:
             // have we reached the base-root?
             if (m_cmpi_vx_vx( &iml_cmp,
                                 (void *)adsl_namingcontexts->ac_val, adsl_namingcontexts->imc_len_val, adsl_namingcontexts->iec_chs_val,
                                 (void *)achl_dn, iml_len_dn, iel_chs_dn ))
             { // baseObject found?
               if (!iml_cmp)
                 // yes, return...
                 break;
             }
             else
             { // error, we can't compare the baseObjects
               this->ds_ldap_error.m_set_error( ied_ldap_op_err, ied_ldap_search_err );
               return ied_ldap_failure;
             }
             // step along the 'dn'-tree...
             achl_1 = (char *)memchr( (const void *)achl_dn, int(','), iml_len_dn );
             if (achl_1)
             { // shorten the string...
               iml_len_dn = --iml_len_dn - (int)(achl_1 - achl_dn);
               achl_dn    = ++achl_1;
             }

             goto SEARCH_TREE_REQUEST;

        case LDAP_RESP_SEARCH_REF:
        default:
             break;
      } // end of switch()
   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   // have we found anything?
   if (adsp_co_ldap->adsc_attr_desc == NULL)
   { // nothing found!!!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results );
     return ied_ldap_failure;
   }

   return ied_ldap_success;

} // dsd_ldap::m_aux_search_tree( dsd_co_ldap_1* )


/**
 * Private class function:  dsd_ldap::m_aux_search_root()
 *
 * Initiates a ldap search operation, beginning at the namingcontexts (as baseObject) and then all
 * sub-levels.
 *
 *      ASN.1:
 *      SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject   LDAPDN,
 *                                                   scope        ENUMERATED { baseObject   (0),
 *                                                                             singleLevel  (1),
 *                                                                             wholeSubtree (2) },
 *                                                   derefAliases ENUMERATED { neverDerefAliases   (0),
 *                                                                             derefInSearching    (1),
 *                                                                             derefFindingBaseObj (2),
 *                                                                             derefAlways         (3) },
 *                                                   sizeLimit    INTEGER (0 .. maxInt),
 *                                                   timeLimit    INTEGER (0 .. maxInt),
 *                                                   typesOnly    BOOLEAN,
 *                                                   filter       Filter,
 *                                                   attributes   AttributeSelection }
 *
 *                         Filter ::= CHOICE { and             [0]  SET SIZE (1..MAX) OF filter Filter,
 *                                             or              [1]  SET SIZE (1..MAX) OF filter Filter,
 *                                             not             [2]  Filter,
 *                                             equalityMatch   [3]  AttributeValueAssertion,
 *                                             substrings      [4]  SubstringFilter,
 *                                             greaterOrEqual  [5]  AttributeValueAssertion,
 *                                             lessOrEqual     [6]  AttributeValueAssertion,
 *                                             present         [7]  AttributeDescription,
 *                                             approxMatch     [8]  AttributeValueAssertion,
 *                                             extensibleMatch [9]  MatchingRuleAssertion }
 *
 *                         AttributeSelection ::= SEQUENCE OF selector LDAPString
 *
 *                         AttributeValueAssertion ::= SEQUENCE { attributeDesc  AttributeDescription (LDAPString),
 *                                                                assertionValue AssertionValue       (OCTET STRING) }
 *
 *                         SubstringFilter ::= SEQUENCE { type       AttributeDescription,
 *                                                        substrings SEQUENCE SIZE OF substring CHOICE { initial [0] AssertionValue,
 *                                                                                                       any     [1] AssertionValue,
 *                                                                                                       final   [2] AssertionValue }
 *                                                      }
 *
 *                         MatchingRuleAssertion ::= SEQUENCE { matchingRule [1]  MatchingRuleId (LDAPString) OPTIONAL,
 *                                                              type         [2]  AttributeDescription        OPTIONAL,
 *                                                              matchValue   [3]  AssertionValue,
 *                                                              dnAttributes [4]  BOOLEAN
 *                                                            }
 *
 *
 * @param[in,out]   adsp_co_ldap   request structure
 *
 * @return          error        (\b ied_ldap_failure),
 *                  successful   (\b ied_ldap_success) or
 *                  send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_search_root( struct dsd_co_ldap_1 *adsp_co_ldap )
{
#define SEARCH_TO  this->ads_ldap_entry->imc_timeout_search

   int   iml_rc, iml_rc2;
   BOOL  bol_found;

   struct dsd_ldap_val        *adsl_namingcontexts = NULL;
   struct dsd_ldap_attr_desc **aadsl_attr_desc;


   // allocate 'namingcontexts' as the base dn to compare
   if (this->bo_RootDSE == FALSE && this->m_aux_search_RootDSE() != ied_ldap_success)
   { // error; we can't execute the ldap-search!
     return ied_ldap_failure;
   }

   // ok, perform ldap search...
   LDAPREQ_SEARCH(this->ds_ldapreq)

   // search the corresponding context...
   adsl_namingcontexts = this->ds_RootDSE.ads_namingcontexts;
   // root-entry found ?
   if (adsl_namingcontexts == NULL)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_inv_dn_syntax, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   bol_found = FALSE;
   adsp_co_ldap->adsc_attr_desc = NULL;
   // initialize attribute description structure of the requester
   aadsl_attr_desc = &adsp_co_ldap->adsc_attr_desc;

SEARCH_ROOT_REQUEST:
   // initiate ASN.1 class...
   this->ds_asn1.m_init(&this->ads_hl_stor_tmp);
   // initialize receive buffer storage management
   this->ds_buf_ldap.m_init(&this->ads_hl_stor_tmp);

   // create valid LDAP message ID...
   this->ds_ldapreq.imc_msgid = this->m_get_msgid();

   // trace message LDAP0072T
   if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_INFO ))
     this->ds_ldap_trace.m_trace( dsd_trace::LEVEL_INFO, 72, this->im_sess_no, m_get_epoch_ms(),
                                  &this->ds_conn, this->ads_ldap_entry,
                                  "Search-Root Scope=%s DN=\"%.*(.*)s\" Filter=\"%.*(.*)s\" Attributelist=\"%.*(.*)s\" Max-Size=%i Max-Time=%i",
                                  this->ds_ldap_trace.m_translate( (int)ied_sear_sublevel, dsd_trace::S_SEARCH_SCOPE ),
                                  adsl_namingcontexts->ac_val ? adsl_namingcontexts->imc_len_val : sizeof "none" - 1,
                                  adsl_namingcontexts->ac_val ? adsl_namingcontexts->iec_chs_val : ied_chs_ascii_850,
                                  adsl_namingcontexts->ac_val ? adsl_namingcontexts->ac_val : "none",
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->imc_len_filter : sizeof "(objectClass=*)" - 1,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->iec_chs_filter : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_filter ? adsp_co_ldap->ac_filter : "(objectClass=*)",
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->imc_len_attrlist : sizeof "none" - 1,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->iec_chs_attrlist : ied_chs_ascii_850,
                                  adsp_co_ldap->ac_attrlist ? adsp_co_ldap->ac_attrlist : "none",
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_search_buf_size : 0, 
                                  this->ads_ldap_entry ? this->ads_ldap_entry->imc_timeout_search : 0);

   // build the asn.1-formatted search request...
   if (this->ds_asn1.m_printf( "{it{seeiib",
                               this->ds_ldapreq.imc_msgid /*i*/,
                               this->ds_ldapreq.imc_req /*t*/,
                               adsl_namingcontexts->ac_val, adsl_namingcontexts->imc_len_val, int(adsl_namingcontexts->iec_chs_val) /*s*/,
                               int(ied_sear_sublevel) /*e*/,
                               LDAP_DEREF_NEVER /*e*/,
                               this->ads_ldap_entry->imc_search_buf_size /*i*/,
                               this->ads_ldap_entry->imc_timeout_search /*i*/,
                               FALSE /*attr and val*//*b*/ ) == LASN1_ERROR)
   { // error; we can't execute the ldap-search!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set the filter(s) in asn.1-format...
   if (adsp_co_ldap->imc_len_filter == 0)
     // default: IBM secure way LDAP use this as default
     iml_rc = this->ds_asn1.m_put_filter( "(objectClass=*)", sizeof "(objectClass=*)" - 1, ied_chs_utf_8 );
   else
     // set filter parameter...
     iml_rc = this->ds_asn1.m_put_filter( (const char *)adsp_co_ldap->ac_filter, adsp_co_ldap->imc_len_filter, adsp_co_ldap->iec_chs_filter );

   // everything ok?
   if (iml_rc != LASN1_SUCCESS)
   { // error, we can't set a valid filter combination!
     this->ds_ldap_error.m_set_error( ied_ldap_filter_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // now we set asn1-attribute(s)...
   if (this->ds_asn1.m_printf( "{C}}",
                               adsp_co_ldap->ac_attrlist, adsp_co_ldap->imc_len_attrlist, int(adsp_co_ldap->iec_chs_attrlist) /*C*/) == LASN1_ERROR)
   { // error, we can't set a valid attribute combination!
     this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
     return ied_ldap_failure;
   }

   // does the server support the 'pagedResultControl'-control?
   if (this->bo_page_results == TRUE)
   { // construct control
     int iml_rc ( this->ds_asn1.m_printf( "t{{obt{{is}}}}", 
                                          LASN1_CONTROLS, /*t*/  
                                          OID_PAGE_RESULTS, sizeof OID_PAGE_RESULTS - 1, /*o*/
                                          FALSE /*TRUE*/, /*b*/
                                          LASN1_OCTETSTRING, /*t*/
                                          D_LDAP_PAGE_SIZE, /*searchControlValue: i*/
                                          this->avo_cookie, this->im_cookie_len, ied_chs_utf_8 /*searchControlValue: s*/ ));
     // free cookie...
     if (this->avo_cookie)
       FREE_MEM( this->ads_hl_stor_per, this->avo_cookie )
     
     this->im_cookie_len = 0;
     this->avo_cookie = NULL;

     if (iml_rc == LASN1_ERROR)
     { // error; we can't build ldap-search with controls!
       this->ds_ldap_error.m_set_error( ied_ldap_encoding_err, ied_ldap_search_err );
       return ied_ldap_failure;
     }
   } // 'pagedResultControl'

   // finish the search request
   this->ds_asn1.m_printf( "}" );

   // send the message...
   this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_INPROGRESS;
   this->ds_asn1.m_set_gather( &this->ads_ldap_entry->ilc_send_data/*statistics*/ );  // build gather chain for send
   // statistics...
   ++this->ads_ldap_entry->imc_count_search;
   ++this->ads_ldap_entry->imc_send_packet;
   this->il_start_time = m_get_epoch_ms();

   // SSL or non SSL?
   iml_rc = this->m_send( this->ds_asn1.ads_gather, ied_ldap_search_err /* apicode */ );
   if (iml_rc != ied_ldap_success)
     return iml_rc;

   // wait for a search response (SearchResultEntry, SearchResultReference or SearchResultDone)
   do
   {  // enable receiving...
      this->ads_ldap_control->bo_recv_complete = FALSE;
      iml_rc2 = this->m_recv( ied_ldap_search_err /* apicode */ );
      if (iml_rc2 != ied_ldap_success)
        return iml_rc2;

      // event posted, now parse the LDAP result (one of the SEARCH-responses set above)...
      this->ds_ldapreq.imc_l_status = dsd_ldap::dsd_ldapreq::REQ_COMPLETED;

      if (this->m_aux_parse_resp( &this->ds_buf_ldap, &this->ds_asn1, &this->ds_ldapreq ) != ied_ldap_success)
      { // @todo: error message to event viewer or something else...
        this->ds_ldap_error.m_set_apicode( ied_ldap_search_err );
        return ied_ldap_failure;
      }

      switch (ds_asn1.im_op)
      {
        case LDAP_RESP_SEARCH_ENTRY:     // parse SearchResultEntry...
             // find next free structure in the chain...
             bol_found = TRUE;
             while (*aadsl_attr_desc)
                  aadsl_attr_desc = &(*aadsl_attr_desc)->adsc_next_attr_desc;

             iml_rc = this->m_aux_search_result_entry( aadsl_attr_desc );
             break;
        case LDAP_RESP_SEARCH_DONE:
             // anything found?
               if (bol_found == FALSE)
             { 
               if (adsl_namingcontexts == NULL)
               { // error, nothing found!!!
                 this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results/*ied_ldap_search_err*/ );
                 return ied_ldap_failure;
               }
               else
               { // next 'namingcontext'...
                 adsl_namingcontexts = adsl_namingcontexts->adsc_next_val;
                 if (adsl_namingcontexts)
                   goto SEARCH_ROOT_REQUEST;
             }
             }
             else
             { // do we have more entries (rfc 2696, 'pagedResultsControl')?
               if (this->im_cookie_len && this->avo_cookie)
               { // next search...
                 goto SEARCH_ROOT_REQUEST;
               }
             }
             
             break;
        case LDAP_RESP_SEARCH_REF:
        default:
             break;
      } // end of switch()
   } while (this->ds_asn1.im_op != LDAP_RESP_SEARCH_DONE);

   // have we found anything?
   if (adsp_co_ldap->adsc_attr_desc == NULL)
   { // nothing found!!!
     this->ds_ldap_error.m_set_error( ied_ldap_no_such_attr, ied_ldap_no_results );
     return ied_ldap_failure;
   }

   return ied_ldap_success;

} // dsd_ldap::m_aux_search_root( dsd_co_ldap_1* )


/**
 * Private class function:  dsd_ldap::m_aux_msad_val()
 *
 * Convert an attribute value in a MSAD compatible Unicode quoted version.
 * This must be done for the following attributes: 'unicodePwd, ...
 *
 * @param[in]   achp_in       input string
 * @param[in]   imp_len_in    input string length
 * @param[in]   iep_chs_in    input string character set
 * @param[out]  aachp_out     output string (quoted Unicode, little endian)
 * @param[out]  aimp_len_out  output string length
 * @param[out]  aiep_chs_out  output string character set
 *
 * @return      error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Remarks:\n
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int  dsd_ldap::m_aux_msad_val(  char *achp_in, int imp_len_in, enum ied_charset iep_chs_in,
                                char **aachp_out, int *aimp_len_out, enum ied_charset *aiep_chs_out )
{
   int   iml_len_passwd8 (0), iml_len_passwd16 (0);
   char *achl_passwd8 (NULL), *achl_passwd16 (NULL);

   // anything to be tested for ms specific attributes?
   if (imp_len_in)
   { // yes, perform the translation...
     iml_len_passwd8 = m_len_vx_vx( ied_chs_utf_8, (void *)achp_in, imp_len_in, iep_chs_in );
     if (iml_len_passwd8 == -1)
       goto MSAD_ERROR;  // error, invalid string format...

     achl_passwd8 = (char *)m_aux_stor_alloc( &this->ads_hl_stor_tmp, iml_len_passwd8 + 2/*quotes*/ );
     // translation to utf-8...
     if (m_cpy_vx_vx_fl( (void *)(achl_passwd8 + 1), iml_len_passwd8, ied_chs_utf_8,
                         (void *)achp_in, imp_len_in, iep_chs_in,
                         D_CPYVXVX_FL_NOTAIL0 ) == -1)
       goto MSAD_ERROR;  // error, invalid string format

     // insert quotes...
     *achl_passwd8 = '\"';
     *(achl_passwd8 + iml_len_passwd8 + 1) = '\"';

     // translate it now to utf-16 (little endian)...
     iml_len_passwd16 = m_len_vx_vx( ied_chs_le_utf_16, (void *)achl_passwd8, int(iml_len_passwd8 + 2), ied_chs_utf_8 );
     if (iml_len_passwd16 == -1)
       goto MSAD_ERROR;  // error, invalid string format...

     achl_passwd16 = (char *)m_aux_stor_alloc( &this->ads_hl_stor_per, iml_len_passwd16 * 2/*wchar*/ );
     // translation to UTF-16 (little endian)...
     if (m_cpy_vx_vx_fl( (void *)achl_passwd16, iml_len_passwd16, ied_chs_le_utf_16,
                         (void *)achl_passwd8, iml_len_passwd8 + 2, ied_chs_utf_8,
                         D_CPYVXVX_FL_NOTAIL0 ) == -1)
       goto MSAD_ERROR;  // error, invalid string format

     // set return values...
     *aachp_out    = achl_passwd16;
     *aimp_len_out = iml_len_passwd16 * 2; /* xslunic counts the unicode characters! */
     *aiep_chs_out = ied_chs_le_utf_16;
     return ied_ldap_success;
   }

MSAD_ERROR:
   // error, invalid string format...
   this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
   // set return parameters...
   *aachp_out    = NULL;
   *aimp_len_out = 0;
   return ied_ldap_failure;

} // dsd_ldap::m_aux_msad_val( dsd_val_in*, dsd_val_out* )

/**
 * Private class function:  dsd_ldap::m_send()
 *
 * Sends SSL- or nonSSL data to the LDAP server.
 *
 * @param[in]  adsp_gather_send  LDAP request data
 * @param[in]  imp_apicode       LDAP api function code using this routine
 *
 * @return     error        (\b ied_ldap_failure),
 *             successful   (\b ied_ldap_success) or
 *             send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_send( struct dsd_gather_i_1 *adsp_gather_send, int imp_apicode )
{
   struct dsd_gather_i_1 *adsl_gather (NULL);

#ifdef _DEBUG
	this->imc_req_counter++;
#endif
   // is there a valid connection?
   if (this->im_c_status != dsd_ldap::DISCONNECTED && this->im_c_status != dsd_ldap::UNBIND)
   {
     // trace message LDAP0096T
     if (this->ds_ldap_trace.m_is_enabled( dsd_trace::LEVEL_DATA ))
       this->ds_ldap_trace.m_trace_gather_data( dsd_trace::LEVEL_DATA, 96, this->im_sess_no,
                                                this->ds_ldapreq.imc_msgid, this->ds_ldapreq.ac_req,
                                                m_get_epoch_ms(), &this->ds_conn, this->ads_ldap_entry,
                                                adsp_gather_send );

     // SSL or nonSSl?
     if (this->ads_ldap_entry->boc_csssl_conf)
     { // use SSL...
	    // call ssl...
			this->ds_sslstruct.adsc_gai1_in_cl = adsp_gather_send;
			while(true) {
				// send all ssl data...
				while (this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
				{
					int iml_out_se_len = (int)(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf);
					int iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf, iml_out_se_len);
					// SSL send() - error?
					if (iml_rc < 0)
						goto SEND_SSL_ERROR;
					if (iml_rc != iml_out_se_len) {
						goto SEND_SSL_ERROR;
					}
					this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
				} // while(ssl-send)
				m_hlcl01( &this->ds_sslstruct );
				this->ds_sslstruct.adsc_gai1_in_cl = m_skip_consumed_gathers(this->ds_sslstruct.adsc_gai1_in_cl);
				if (this->ds_sslstruct.inc_return != 0)
				{ // ssl send error...
					goto SEND_SSL_ERROR;
				}
				int iml_out_se_len_new = (int)(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf);

				if (iml_out_se_len_new == 0 && this->ds_sslstruct.adsc_gai1_in_cl == NULL)
					break;
			}
     }
     else
     { 
       if (this->ads_ldap_control)
       { // send gather data...
         int iml_len = this->ads_ldap_control->ds_tcpcomp.m_send_gather(adsp_gather_send, &adsl_gather);

         // use nonSSL...
         if (iml_len == 0)
         { // send error, report it and close connection...
           this->ds_ldap_error.m_set_error( ied_ldap_send_err, imp_apicode );
           return ied_ldap_failure;
         }
         else
         { // no send errors ...
           if (adsl_gather)
           { // send blocked, calculate new send address...
             
             memcpy( (void *)&this->ds_gather_send, (const void *)adsl_gather, sizeof(struct dsd_gather_i_1) );
             this->ads_ldap_control->ds_tcpcomp.m_sendnotify();

             return ied_ldap_send_blocked;
           }
         }
       } // this->ads_ldap_control
     }
   } // end of ready to sent (bo_connected == TRUE)

   return ied_ldap_success;
SEND_SSL_ERROR:
   return ied_ldap_failure;
} // dsd_ldap::m_send( dsd_gather_i_1 *, int )

/**
 * Private class function:  dsd_ldap::m_recv()
 *
 * Receives SSL- or nonSSL data from the LDAP server.
 *
 * @param[in]  imp_apicode     LDAP api function code
 *
 * @return     error        (\b ied_ldap_failure),
 *             successful   (\b ied_ldap_success) or
 *             send blocked (\b ied_ldap_send_blocked)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_recv( int imp_apicode )
{
   if (this->ads_ldap_control == NULL)
		return ied_ldap_failure; 

#if SM_USE_RECV_GATHERS
   dsd_gatherlist dsl_data_in_se;
   
   m_gatherlist_init(&dsl_data_in_se);
   while (true)
   {
		if (!this->ads_ldap_control->bo_connected)
			goto RECV_SSL_ERROR;
		if (this->ads_ldap_control->bo_tcperr)
			goto RECV_SSL_ERROR;

		int iml_valid_len = this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos;

		if (iml_valid_len > 0) {
			int iml_len = 0;
			int iml_nextpos = 0;
			switch (this->ds_asn1.m_test_resp( &this->ds_buf_ldap, &iml_len, &iml_nextpos ))
			{
				default:
				case LASN1_ERROR:     // ASN.1 decoding error...
									 this->ads_ldap_control->bo_recv = FALSE;
									 this->ds_ldap_error.m_set_error( ied_ldap_decoding_err );
									 goto RECV_SSL_ERROR;
				case LASN1_SUCCESS:   // TLV complete!
									 goto LBL_COMPLETE;
				case LASN1_WAIT_MORE: // wait for more data...
									 break;
			} // switch()
		}

		this->dsc_cs_ldap2.m_enter();
		m_gatherlist_push_back(&dsl_data_in_se, &this->dsc_recv_data);
		this->dsc_cs_ldap2.m_leave();
		
		if (dsl_data_in_se.adsc_first == NULL) {
			this->ads_ldap_control->bo_recv = TRUE;
			this->ads_ldap_control->ds_tcpcomp.m_recv();

			// wait for a successful completion...
			if (this->ads_ldap_control == NULL ||
				this->ads_ldap_control->m_wait( CONNECT_TO ? CONNECT_TO*1000 : D_LDAP_WAIT,
																	&this->ds_ldap_error.im_apicode ) != 0)
			{
			   goto RECV_SSL_ERROR;
			}
			continue;
		}

		if (this->ads_ldap_entry->boc_csssl_conf) {
		   this->ds_sslstruct.adsc_gai1_in_se = dsl_data_in_se.adsc_first;
			this->ach_ssltoappl_buf = (char *)m_aux_stor_realloc(&this->ads_hl_stor_ssl,
					this->ach_ssltoappl_buf, D_LDAP_SSL_BUFFER_LEN);
			while(true) {
				this->ds_sslstruct.achc_out_cl_cur = this->ach_ssltoappl_buf;
				this->ds_sslstruct.achc_out_cl_end = this->ach_ssltoappl_buf + D_LDAP_SSL_BUFFER_LEN;

				// call ssl and translate received ssl-data...
				m_hlcl01( &this->ds_sslstruct );
				this->ds_sslstruct.adsc_gai1_in_se = m_skip_consumed_gathers(&dsl_data_in_se);

				if (this->ds_sslstruct.inc_return != 0)
				{ // ssl receive error...
	#ifdef HOB_SSL_BUFFER_CHECK
					// trace message LDAP0087T
					if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
					  this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 87, this->im_sess_no, m_get_epoch_ms(),
												  &this->ds_conn, this->ads_ldap_entry,
												  "m_recv (SSL) (receive-error=%i)", this->ds_sslstruct.inc_return);
	#endif
					goto RECV_SSL_ERROR;
				}
				int iml_out_se_len_new = (int)(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf);
				// are there any data to sent?
				while (this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
				{  // process SSL generated send-data (like alerts, ...)
					int iml_out_se_len = (int)(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf);
					int iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf, iml_out_se_len);

					// SSL send() - error ?
					if (iml_rc < 0) {
						goto RECV_SSL_ERROR;
					}
					if (iml_rc != iml_out_se_len) {
						goto RECV_SSL_ERROR;
					}

					this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
				} // while(send ssl-data)

				int iml_new_data = (int)(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf);
				int iml_valid_len = this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos;
				this->ds_buf_ldap.m_ensure_capacity(&this->ads_hl_stor_tmp, iml_valid_len + iml_new_data);
				memcpy((void *)((char *)this->ds_buf_ldap.m_get_bufaddr() + this->ds_buf_ldap.imc_pos),
					   (const void *)this->ach_ssltoappl_buf,
					   iml_new_data);
				this->ds_buf_ldap.imc_pos += iml_new_data;

				if (iml_out_se_len_new == 0 && iml_new_data == 0)
					break;
			}
		}
		else {
			dsd_gather_i_1* adsl_tmp = m_gatherlist_remove_first(&dsl_data_in_se); 
			int iml_new_data = (int)(adsl_tmp->achc_ginp_end - adsl_tmp->achc_ginp_cur);
			int iml_valid_len = this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos;
			this->ds_buf_ldap.m_ensure_capacity(&this->ads_hl_stor_tmp, iml_valid_len + iml_new_data);

			memcpy((void *)((char *)this->ds_buf_ldap.m_get_bufaddr() + this->ds_buf_ldap.imc_pos),
				   (const void *)adsl_tmp->achc_ginp_cur, 
                   iml_new_data);
			this->ds_buf_ldap.imc_pos += iml_new_data;
			::free(adsl_tmp);
		}
#if HOB_LDAP_TRACE_TRAFFIC
		m_hl1_printf("#LDAP-DATA-COMBINED: len=%d", this->ds_buf_ldap.imc_pos);
		m_console_out((char*)this->ds_buf_ldap.m_getaddr() + this->ds_buf_ldap.imc_nextpos,
			this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos);
#endif

#ifdef HOB_SSL_BUFFER_CHECK
      // trace message LDAP0085T
      if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
        this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 85, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "m_recv (SSL) (pos_s=%i, pos=%i, buf_len_s=%i, buf_len=%i)",
                                    iml_pos_s, this->ds_buf_ldap.imc_pos, iml_buflen_s, this->ds_buf_ldap.imc_buflen);
#endif

#ifdef HOB_SSL_BUFFER_CHECK
      // trace message LDAP0083T
      if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
        this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 83, this->im_sess_no, m_get_epoch_ms(),
                                    &this->ds_conn, this->ads_ldap_entry,
                                    "m_recv (data-len=%i, pos=%i, next-pos=%i, buf_len=%i)",
                                    this->ds_buf_ldap.imc_datalen, this->ds_buf_ldap.imc_pos, this->ds_buf_ldap.imc_nextpos,
                                    this->ds_buf_ldap.imc_buflen);
#endif
   }
RECV_SSL_ERROR:
   m_gatherlist_free(&dsl_data_in_se);

   return ied_ldap_failure;
LBL_COMPLETE:
	if (dsl_data_in_se.adsc_first != NULL) {
		this->dsc_cs_ldap2.m_enter();
		m_gatherlist_push_front(&this->dsc_recv_data, &dsl_data_in_se);
		this->dsc_cs_ldap2.m_leave();
	}

   return ied_ldap_success;

#else
   BOOL  bol_compl (FALSE);
   int   iml_len (0), iml_rc (0);
   int   iml_pos_s (0), iml_buflen_s (0);

	// SSL or nonSSl?
   if (this->ads_ldap_entry->boc_csssl_conf)
   { // use SSL...
     this->ds_buf_ssl.m_clear();
	 this->ds_sslstruct.achc_out_cl_cur = this->ach_ssltoappl_buf;

#ifdef HOB_SSL_BUFFER_CHECK
     // trace message LDAP0082T
     if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
       this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 82, this->im_sess_no, m_get_epoch_ms(),
                                   &this->ds_conn, this->ads_ldap_entry,
                                   "m_recv (data-len=%i, data-len_s= %i, pos=%i, next-pos=%i, buf_len=%i)",
                                   this->ds_buf_ldap.imc_datalen, this->ds_buf_ldap.imc_datalen_s, this->ds_buf_ldap.imc_pos,
                                   this->ds_buf_ldap.imc_nextpos, this->ds_buf_ldap.imc_buflen);
#endif
	// wait for ssl-response...
     while (this->ads_ldap_control && bol_compl == FALSE)
     {
		 if (!this->ads_ldap_control->bo_connected) {
           return ied_ldap_failure;
		 }
		 if (this->ads_ldap_control->bo_tcperr) {
           return ied_ldap_failure;
		 }
		  this->ads_ldap_control->bo_recv = TRUE;
        this->ads_ldap_control->ds_tcpcomp.m_recv();

        // wait for a successful completion...
        if (this->ads_ldap_control == NULL ||
            this->ads_ldap_control->m_wait( CONNECT_TO ? CONNECT_TO*1000 : D_LDAP_WAIT,
                                                                &this->ds_ldap_error.im_apicode ) != 0)
        {
#ifdef HOB_SSL_BUFFER_CHECK
          // trace message LDAP0086T
          if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
            this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 86, this->im_sess_no, m_get_epoch_ms(),
                                        &this->ds_conn, this->ads_ldap_entry,
                                        "m_recv (SSL) (wait-error=%i)", this->ds_ldap_error.im_apicode);
#endif
           return ied_ldap_failure;
        }
        else
        { // process received ssl-data...
LBL_PROC_SSL:
          this->ds_socktossl.achc_ginp_cur   = (char *)this->ds_buf_ssl.m_getaddr() + this->ds_buf_ssl.imc_nextpos;
          this->ds_socktossl.achc_ginp_end   = (char *)this->ds_buf_ssl.m_getaddr() + this->ds_buf_ssl.imc_pos;
          this->ds_socktossl.adsc_next       = NULL;
          this->ds_sslstruct.adsc_gai1_in_se = &this->ds_socktossl;
		  this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;

          this->ach_ssltoappl_buf = (char *)m_aux_stor_realloc(&this->ads_hl_stor_ssl,
			                                                   this->ach_ssltoappl_buf,
															   this->ds_buf_ssl.imc_buflen);
		  this->ds_sslstruct.achc_out_cl_cur = this->ach_ssltoappl_buf;
          this->ds_sslstruct.achc_out_cl_end = this->ach_ssltoappl_buf + this->ds_buf_ssl.imc_buflen;

          // call ssl and translate received ssl-data...
          m_hlcl01( &this->ds_sslstruct );
	      this->ds_sslstruct.adsc_gai1_in_se = m_skip_consumed_gathers(this->ds_sslstruct.adsc_gai1_in_se);

          if (this->ds_sslstruct.inc_return != 0)
          { // ssl receive error...
RECV_SSL_ERROR:
#ifdef HOB_SSL_BUFFER_CHECK
            // trace message LDAP0087T
            if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
              this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 87, this->im_sess_no, m_get_epoch_ms(),
                                          &this->ds_conn, this->ads_ldap_entry,
                                          "m_recv (SSL) (receive-error=%i)", this->ds_sslstruct.inc_return);
#endif
            return ied_ldap_failure;
          }
          // are there any data to sent?
          while (this->ads_ldap_control &&
                 this->ds_sslstruct.achc_out_se_cur != this->ach_ssltosock_buf)
          {  // process SSL generated send-data (like alerts, ...)
             iml_rc = this->ads_ldap_control->ds_tcpcomp.m_send(this->ach_ssltosock_buf,
                                                                int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf));

             // SSL send() - error ?
			 if (iml_rc < 0) {
               goto RECV_SSL_ERROR;
			 }
			 if (iml_rc != int(this->ds_sslstruct.achc_out_se_cur - this->ach_ssltosock_buf)) {
				 goto RECV_SSL_ERROR;
			  }

             this->ds_sslstruct.achc_out_se_cur = this->ach_ssltosock_buf;
             // call ssl...
             m_hlcl01( &this->ds_sslstruct );

             if (this->ds_sslstruct.inc_return != 0)
             { // ssl send error...
#ifdef HOB_SSL_BUFFER_CHECK
               // trace message LDAP0088T
               if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
                 this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 88, this->im_sess_no, m_get_epoch_ms(),
                                             &this->ds_conn, this->ads_ldap_entry,
                                             "m_recv (SSL) (send-error=%i)", this->ds_sslstruct.inc_return);
#endif
               return ied_ldap_failure;
             }
          } // while(send ssl-data)

          // call ssl (necessary after sent)...
          m_hlcl01( &this->ds_sslstruct );

          if (this->ds_sslstruct.inc_return < 0)
          { // ssl error...
#ifdef HOB_SSL_BUFFER_CHECK
            // trace message LDAP0089T
            if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
              this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 89, this->im_sess_no, m_get_epoch_ms(),
                                          &this->ds_conn, this->ads_ldap_entry,
                                          "m_recv (SSL) (error=%i)", this->ds_sslstruct.inc_return);
#endif
            return ied_ldap_failure;
          }

		  int iml_old_pos = this->ds_buf_ssl.imc_nextpos;
		  int iml_new_pos = int(this->ds_socktossl.achc_ginp_cur - (char *)this->ds_buf_ssl.m_getaddr());

		  this->ds_buf_ssl.imc_nextpos = iml_new_pos;
          if (this->ach_ssltoappl_buf != this->ds_sslstruct.achc_out_cl_cur)
          { // copy data to asn.1 buffer for parsing...
            iml_pos_s    = this->ds_buf_ldap.imc_pos;
            iml_buflen_s = this->ds_buf_ldap.imc_buflen;

#if HOB_LDAP_TRACE_TRAFFIC
			m_hl1_printf("#LDAP-DATA: len=%d", int(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf));
			m_console_out(this->ach_ssltoappl_buf, int(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf));
#endif
			int iml_new_data = (int)(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf);
			int iml_valid_len = this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos;
			this->ds_buf_ldap.m_ensure_capacity(&this->ads_hl_stor_tmp, iml_valid_len + iml_new_data);

            //this->ds_buf_ldap.m_alloc(&this->ads_hl_stor_tmp, int(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf) + iml_buflen_s /*data to work off*/);
            //this->ds_buf_ldap.imc_pos = int(this->ds_sslstruct.achc_out_cl_cur - this->ach_ssltoappl_buf) + iml_pos_s;
            memcpy((void *)((char *)this->ds_buf_ldap.m_getaddr() + this->ds_buf_ldap.imc_pos),
                   (const void *)this->ach_ssltoappl_buf,
                   iml_new_data);
			this->ds_buf_ldap.imc_pos += iml_new_data;
#if HOB_LDAP_TRACE_TRAFFIC
			m_hl1_printf("#LDAP-DATA-COMBINED: len=%d", this->ds_buf_ldap.imc_pos);
			m_console_out((char*)this->ds_buf_ldap.m_getaddr() + this->ds_buf_ldap.imc_nextpos,
				this->ds_buf_ldap.imc_pos - this->ds_buf_ldap.imc_nextpos);
#endif

#ifdef HOB_SSL_BUFFER_CHECK
            // trace message LDAP0085T
            if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
              this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 85, this->im_sess_no, m_get_epoch_ms(),
                                          &this->ds_conn, this->ads_ldap_entry,
                                          "m_recv (SSL) (pos_s=%i, pos=%i, buf_len_s=%i, buf_len=%i)",
                                          iml_pos_s, this->ds_buf_ldap.imc_pos, iml_buflen_s, this->ds_buf_ldap.imc_buflen);
#endif

#ifdef HOB_SSL_BUFFER_CHECK
            // trace message LDAP0083T
            if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
              this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 83, this->im_sess_no, m_get_epoch_ms(),
                                          &this->ds_conn, this->ads_ldap_entry,
                                          "m_recv (data-len=%i, pos=%i, next-pos=%i, buf_len=%i)",
                                          this->ds_buf_ldap.imc_datalen, this->ds_buf_ldap.imc_pos, this->ds_buf_ldap.imc_nextpos,
                                          this->ds_buf_ldap.imc_buflen);
#endif
			int iml_nextpos = 0;
            switch (this->ds_asn1.m_test_resp( &this->ds_buf_ldap, &iml_len, &iml_nextpos ))
            {
               case LASN1_ERROR:     // ASN.1 decoding error...
                                     this->ads_ldap_control->bo_recv = FALSE;
                                     this->ds_ldap_error.m_set_error( ied_ldap_decoding_err );
                                     return ied_ldap_failure;
               case LASN1_SUCCESS:   // TLV complete!
                                     this->ads_ldap_control->bo_recv = FALSE;
                                     bol_compl = TRUE;
                                     //// clear ssl buffer since the data have been decrypted
                                     //this->ds_buf_ssl.m_clear();
                                     goto LBL_COMPLETE;
               case LASN1_WAIT_MORE: // wait for more data...
                                     bol_compl = FALSE;
                                     //this->ds_buf_ssl.m_clear();
									 //if (this->ds_sslstruct.achc_out_cl_cur == this->ds_sslstruct.achc_out_cl_end)
									 this->ds_sslstruct.achc_out_cl_cur = this->ach_ssltoappl_buf;
                                     goto LBL_PROC_MORE;
                                     break;
            } // switch()

#ifdef HOB_SSL_BUFFER_CHECK
            // trace message LDAP0084T
            if (this->ds_ldap_trace.m_is_enabled(dsd_trace::LEVEL_DATA))
              this->ds_ldap_trace.m_trace(dsd_trace::LEVEL_DATA, 84, this->im_sess_no, m_get_epoch_ms(),
                                          &this->ds_conn, this->ads_ldap_entry,
                                          "m_recv (data-len=%i, pos=%i, next-pos=%i, buf_len=%i, exp-len=%i)",
                                          this->ds_buf_ldap.imc_datalen, this->ds_buf_ldap.imc_pos, this->ds_buf_ldap.imc_nextpos,
                                          this->ds_buf_ldap.imc_buflen, iml_len);
#endif
          }
		  if (iml_old_pos != iml_new_pos)
			  goto LBL_PROC_MORE;
		  continue;
LBL_PROC_MORE:
		  if (this->ds_sslstruct.inc_return == 1) {
			  return ied_ldap_failure;
		  }
		  goto LBL_PROC_SSL;
		} // process ssl-data ...
     } // while(receive)
   } // SSL
   else
   { // use nonSSL...
     // reset LDAP receive buffer...
     //this->ds_buf_ldap.m_free(&this->ads_hl_stor_tmp);
		this->ads_ldap_control->bo_recv = TRUE;
		this->ads_ldap_control->ds_tcpcomp.m_recv();

		if (this->ads_ldap_control == NULL ||
			this->ads_ldap_control->m_wait( SEARCH_TO ? SEARCH_TO*1000 : D_LDAP_WAIT,
															   &this->ds_ldap_error.im_apicode ) != 0)
		{ // @todo: error message to event viewer or something else...
			this->ds_ldap_error.m_set_error( ied_ldap_timeout, imp_apicode );
			return ied_ldap_failure;
		}
   } // nonSSL
   return ied_ldap_success;
#endif /*SM_USE_RECV_GATHERS*/

} // dsd_ldap::m_recv( int )


/**
 * Private class function:  dsd_ldap::m_aux_sid_to_hex()
 *
 * Converts a human-readable SID in a hexadecimal-coded SID format (x01,x00,x00,x00,x00,x00,x05,...).
 *
 * @param[in]      achp_sid    string-format of the SID
 * @param[in]      imp_len     string length
 * @param[in, out] adsp_sid    hexadecimal-coded SID
 *
 * @return         error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
int dsd_ldap::m_aux_sid_to_hex( char *achp_sid, int imp_len, struct dsd_sid *adsp_sid )
{

   unsigned int uml_off = 2; // "S-1"
   int   iml_subid, iml_1;
   unsigned int uml_next;


   // check the input parameters...
   if (!achp_sid || !imp_len || !adsp_sid)
   { // error, invalid parameters...
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
     return ied_ldap_failure;
   }

   // initialize SID structure
   string  strl_sid( achp_sid, imp_len);
   memset( (void *)achp_sid, 0, sizeof(struct dsd_sid) );

   if (strl_sid.find( "S-", 0 ) == string::npos)
   { // error, invalid parameters...
SID_ERROR:
     this->ds_ldap_error.m_set_error( ied_ldap_inv_attr_syntax );
     return ied_ldap_failure;
   }

   // get "S-1"
   adsp_sid->uchc_revision = strl_sid.at( uml_off ) & 0x0f;
   if (strl_sid.at( uml_off + 1 ) != '-')
     goto SID_ERROR;

   // get "S-1-5"
   uml_off += 2;
   adsp_sid->uchc_authority[5] = strl_sid.at( uml_off ) & 0xff;
   if (strl_sid.at( uml_off + 1 ) != '-')
     goto SID_ERROR;

   // get "S-1-5-nn" (sub-IDs...)
   uml_off  += 2;
   iml_subid = 0;

   do
   { // read sub_ID number... convert it to le-integer
     uml_next = (unsigned int)strl_sid.find( '-', uml_off );
     if (uml_next != string::npos)
     { // delimiter '-' found!
       iml_1 = atoi( strl_sid.substr( uml_off, uml_next - uml_off ).c_str() );
       // endianess?
       if (this->bo_le == FALSE)
       { // convert from le to be
         iml_1 = m_bswap32(iml_1);
       }

       *(int *)adsp_sid->uchcr_subID[iml_subid] = iml_1;
       // next sub-id
       iml_subid++;
       if (iml_subid > 15 /*max SubIDs are supported by MSAD!*/)
         // error, invalid attribute syntax
         goto SID_ERROR;

       uml_off = uml_next + 1;
     }
     else
     { // no delimiter found, add the last one
       if (uml_off < (int)strl_sid.length())
       {
         iml_1 = atoi( strl_sid.substr( uml_off, strl_sid.length() - uml_off ).c_str() );
         // endianess?
         if (this->bo_le == FALSE)
         { // convert from le to be
           iml_1 = m_bswap32(iml_1);
         }
         *(int *)adsp_sid->uchcr_subID[iml_subid] = iml_1;
       }
     }
   } while (uml_next != string::npos);

   return ied_ldap_success;

}; // dsd_ldap::m_aux_sid_to_hex( char *, int, struct dsd_sid * )


/**
 * Private class function:  dsd_ldap::m_aux_hex_to_sid()
 *
 * Converts a hexadecimal-coded SID to a human readable SID in the form of "S-1-5-...".
 *
 * @param[in]       adsp_sid      hexadecimal-coded SID
 * @param[in, out]  adsp_val      string-format of the SID
 * @param[in]       adsp_hl_stor  storage handler
 *
 * @return          error (\b ied_ldap_failure) or successful (\b ied_ldap_success)
 *
 * Comment:
 * If the function returns 'ied_ldap_failure', the error can be retrieved by 'ied_co_ldap_get_last_err'.
 */
#if defined WIN32 || defined WIN64
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

int dsd_ldap::m_aux_hex_to_sid( struct dsd_sid      *adsp_sid,
                                struct dsd_ldap_val *adsp_val,
                                void                *adsp_hl_stor )
{
#define SID_LEN  160

   int   iml_subid, iml_1, iml_len;
   char *achl_1;


   // check the input parameters...
   if (!adsp_sid || !adsp_val || !adsp_hl_stor)
   { // error, invalid parameters...
     this->ds_ldap_error.m_set_error( ied_ldap_param_inv );
     return ied_ldap_failure;
   }

   // initialize SID structure
   adsp_val->ac_val      = (char *)m_aux_stor_alloc( &adsp_hl_stor, SID_LEN );
   adsp_val->iec_chs_val = ied_chs_utf_8;

   achl_1 = adsp_val->ac_val;
   // set header "S-(revision)-(authority)-"
   memcpy( (void *)achl_1, (const void *)"S-r-a-", sizeof "S-r-a-"-1 );
   *(achl_1 + 2) = adsp_sid->uchc_revision + 0x30;
   *(achl_1 + 4) = adsp_sid->uchc_authority[5] + 0x30;
   achl_1 += sizeof "S-r-a-"-1;

   // test the sub-id count
   if (!adsp_sid->uchc_count_subIDs || adsp_sid->uchc_count_subIDs > 15 /*max SubIDs are supported by MSAD!*/)
   { // error, invalid attribute syntax
SID_ERROR:
     this->ds_ldap_error.m_set_error( ied_ldap_inv_attr_syntax );
     return ied_ldap_failure;
   }

   iml_subid = 0;
   do
   { // read le-format (4 byte) and convert it to ASCII
     memcpy( (void *)&iml_1, (const void *)&adsp_sid->uchcr_subID[iml_subid], sizeof(int) );;
     // endianess?
     if (this->bo_le == FALSE)
     { // convert from le to be
       iml_1 = m_bswap32(iml_1);
     }

     iml_len = sprintf( achl_1, "%u", (unsigned int)iml_1 );

     if (iml_len == -1)
       goto SID_ERROR;

     achl_1 += iml_len;
     *achl_1 = '-';
     achl_1++;
     // next sub-id
     iml_subid++;

   } while (iml_subid < adsp_sid->uchc_count_subIDs);

   // set return values
   adsp_val->imc_len_val = (int)(achl_1 - adsp_val->ac_val - 1);
   m_aux_stor_realloc( &adsp_hl_stor, adsp_val->ac_val, adsp_val->imc_len_val );

   return ied_ldap_success;

#undef SID_LEN
}; // dsd_ldap::m_aux_hex_to_sid( struct dsd_sid *, struct dsd_val_1 *, void * )
#if defined WIN32 || defined WIN64
#pragma warning(pop)
#endif



/*+-----------------------------------------------------------------------------+*/
/*| class 'dsd_asn1' ...                                                        |*/
/*+-----------------------------------------------------------------------------+*/
/**
 * \class dsd_asn1
 *
 * Implements a complete ASN.1 class interface to any LDAPv3 server.
 *
 * Comment:
 * The functions 'm_init()' is called as the class initializer. The class itself
 * is constructed by the class dsd_ldap.\n
 * The ASN.1-fields are built as gather structures. A detailed description is found
 * at [SOFTWARE.HLSEC.SERDAHO1](@ref page13) in the chapter 1.6 and 1.7.
 *
 * WIN32   has to be set for 32-Bit version for windows.
 * WIN64   creates a 64-Bit windows library.
 * HL_UNIX is the switch for a Linux Library.
 *
 * Required programs:
 * MS Visual Studio .NET 2005
 * MS Linker
 *
 * Copyright (C) HOB Germany 2005-2007
 *
 * @version 1.02
 * @author  Juergen-Lorenz Lauenstein
 * @date    2005/08/16   (creation)
 * @date    2008/03/10   (last changes)
 *
 * Defines:
 * WIN32        program for windows 32-bit
 * WIN64        program for windows 64-bit
 * HL_UNIX      program for Linux or UNIX
 */

/**
 * initialize the class: dsd_asn1::m_init()
 *
 * initializes the class dsd_asn1
 *
 * @param[in]  adsp_hl_stor  hob storage handler
 *
 * @return     none
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
void dsd_asn1::m_init( void **aavop_hl_stor/*ASN.1-request*/ )
{
    this->im_tag   = LASN1_UNKNOWN;
    this->im_len   = 0;
    this->ach_val  = NULL;
    this->im_msgid = 0;
    this->im_op    = 0;

    this->asn1_beg   = NULL;
    this->asn1_end   = NULL;
    this->bo_no_data = FALSE;  // no (more) data available (asn1_beg == asn1_end)

    this->aavo_hl_stor = aavop_hl_stor;   // hob internal storage handler for ASN.1-request

    // initiate sequenceOf structure...
    memset( (void *)&this->ds_seqof, int(0), sizeof(dsd_asn1::dsd_seqof_1) );
    this->ds_seqof.imc_tag = LASN1_UNKNOWN;
    // set actual sequence structure to use
    this->ads_seqof_act = &this->ds_seqof;

} // dsd_asn1::m_init()


/**
 * private class function:  dsd_asn1::m_get_int()
 *
 * get 'integer'-value after TLV-parsing
 *
 * @param[in,out] aimp_int   value bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_int( int *aimp_int )
{
   int      iml_int, iml_len, iml_lenlen;
   char    *achl_beg;

   unsigned int  uml_len;   // length of integer-value
   unsigned char ucrl_int[sizeof(int)];

   // initialize the return value
   *aimp_int = 0;

   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 2 /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // test for an 'integer'-type...
   achl_beg = this->asn1_beg;
   if (*achl_beg != LASN1_INTEGER)
     return LASN1_ERROR;

   // normal length or multibyte length (> 127)
   ++achl_beg;
   if ((*achl_beg & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     iml_lenlen = *(unsigned char *)achl_beg & 0x7f;   // get length of length
     // is the length count too big?
     if (iml_lenlen > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + iml_lenlen > this->asn1_end)
       // no, we have to wait for more data...
       return LASN1_WAIT_MORE;

     // construct multibyte length...
     for (uml_len = 0, ++achl_beg; iml_lenlen != 0; --iml_lenlen)
     { // get length (byte by byte)...
       uml_len <<= 8;
       uml_len |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   }
   else
   { // short length values (0...127)
     uml_len = *(unsigned char *)achl_beg;
     ++achl_beg;
   }

   // is the length of the 'integer'-value too big?
   if (uml_len > sizeof(unsigned int))
     // yes, ASN.1 decode error
     return LASN1_ERROR;
   // length calculated, do we have received enough bytes?
   if (achl_beg + uml_len > this->asn1_end)
   // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // copy bytes...
   if (uml_len)
   { // read into the low-order bytes of our buffer...
     memcpy( (void *)ucrl_int, (const void *)achl_beg, size_t(uml_len) );
     // sign extend if necessary
     iml_int = (0x80 & ucrl_int[0]) ? -1 : 0;
     // shift in the bytes
     for (iml_len = 0 ; iml_len < int(uml_len); ++iml_len )
        iml_int = (iml_int << 8) | ucrl_int[iml_len];

     *aimp_int = iml_int;
     achl_beg += uml_len;
   }
   // step asn1.-pointer
   this->asn1_beg = achl_beg;
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_int()


/**
 * private class function:  dsd_asn1::m_get_bool()
 *
 * gets the 'boolean'-value after TLV-parsing
 *
 * @param[in,out] aimp_bool  value bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_bool( BOOL *aimp_bool )
{
   int      iml_bool, iml_len, iml_lenlen;
   char    *achl_beg;

   unsigned int  uml_len;    // length of 'boolean'-value
   unsigned char ucrl_bool[sizeof(int)];

   // initialize the return value
   *aimp_bool = 0;
   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 2 /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // test for an 'boolean'-type...
   achl_beg = this->asn1_beg;
   if (*achl_beg != LASN1_BOOLEAN)
     return LASN1_ERROR;

   // normal length or multibyte length
   ++achl_beg;
   if ((*achl_beg & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     iml_lenlen = *(unsigned char *)achl_beg & 0x7f;   // get length of length
     // is the length count too big?
     if (iml_lenlen > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + iml_lenlen > this->asn1_end)
       // no, we have to wait for more data...
       return LASN1_WAIT_MORE;

     // construct multibyte length...
     for (uml_len = 0, ++achl_beg; iml_lenlen != 0; --iml_lenlen)
     { // get length (byte by byte)...
       uml_len <<= 8;
       uml_len |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   }
   else
   { // short length values (0...127)
     uml_len = *(unsigned char *)achl_beg;
     ++achl_beg;
   }

   // is the length of the 'boolean'-value too big?
   if (uml_len > sizeof(unsigned int))
     // yes, ASN.1 decode error
     return LASN1_ERROR;
   // length calculated, do we have received enough bytes?
   if (achl_beg + uml_len > this->asn1_end)
   // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // copy bytes...
   if (uml_len)
   { // read into the low-order bytes of our buffer...
     memcpy( (void *)ucrl_bool, (const void *)achl_beg, size_t(uml_len) );
     // sign extend if necessary
     iml_bool = (0x80 & ucrl_bool[0]) ? -1 : 0;
     // shift in the bytes
     for (iml_len = 0 ; iml_len < int(uml_len); ++iml_len )
        iml_bool = (iml_bool << 8) | ucrl_bool[iml_len];

     *(int *)aimp_bool = iml_bool;
     achl_beg += uml_len;
    }
   // step asn1.-pointer
   this->asn1_beg = achl_beg;
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_bool()


/**
 * private class function:  dsd_asn1::m_put_bool()
 *
 * sets an boolean in ASN.1-notation
 *
 * @param[in]  imp_bool   value bytes
 * @param[in]  imp_tag    tag byte (LASN1_BOOLEAN or user tag)
 *
 * @return  \b LASN1_SUCCESS    if everything is ok or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_bool( int imp_bool/*value*/, int imp_tag/*tag*/ )
{
    int    iml_taglen, iml_lenlen;
    struct dsd_elem_1 *adsl_elem_1 = this->m_get_element();

    // save tag value and the length of the value...
    adsl_elem_1->imc_tag = (imp_tag == LASN1_UNKNOWN) ? LASN1_BOOLEAN : imp_tag;
    adsl_elem_1->imc_len = 1;

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len) );

    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );
    // set (V)alue... (look at 'ASN.1 Complete', page 309)
    *(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen) = imp_bool ? (unsigned char)~0U : (unsigned char)0U;

    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_bool()


/**
 * private class function:  dsd_asn1::m_get_enum()
 *
 * get 'enumeration'-value after TLV-parsing
 *
 * @param[in,out] aimp_enum  value bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_enum( int *aimp_enum )
{
   int      iml_enum, iml_len, iml_lenlen;
   char    *achl_beg;

   unsigned int  uml_len;   // length of the 'enumeration'-value
   unsigned char ucrl_enum[sizeof(int)];

   // initialize the return value
   *aimp_enum = 0;
   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 2 /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // test for an 'enumerated'-type...
   achl_beg = this->asn1_beg;
   if (*achl_beg != LASN1_ENUMERATED)
     return LASN1_ERROR;

   // normal length or multibyte length
   ++achl_beg;
   if ((*achl_beg & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     iml_lenlen = *(unsigned char *)achl_beg & 0x7f;   // get length of length
     // is the length count too big?
     if (iml_lenlen > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + iml_lenlen > this->asn1_end)
       // no, we have to wait for more data...
       return LASN1_WAIT_MORE;

     // construct multibyte length...
     for (uml_len = 0, ++achl_beg; iml_lenlen != 0; --iml_lenlen)
     { // get length (byte by byte)...
       uml_len <<= 8;
       uml_len |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   }
   else
   { // short length values (0...127)
     uml_len = *(unsigned char *)achl_beg;
     ++achl_beg;
   }

   // is the length of the 'enumeration'-value too big?
   if (uml_len > sizeof(unsigned int))
     // yes, ASN.1 decode error
     return LASN1_ERROR;
   // length calculated, do we have received enough bytes?
   if (achl_beg + uml_len > this->asn1_end)
   // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // copy bytes...
   if (uml_len)
   { // read into the low-order bytes of our buffer...
     memcpy((void *)ucrl_enum, (const void *)achl_beg, size_t(uml_len) );
     // sign extend if necessary
     iml_enum = (0x80 & ucrl_enum[0]) ? -1 : 0;
     // shift in the bytes
     for (iml_len = 0 ; iml_len < int(uml_len); ++iml_len )
        iml_enum = (iml_enum << 8) | ucrl_enum[iml_len];

     *aimp_enum = iml_enum;
     achl_beg += uml_len;
    }
   // step asn1.-pointer
   this->asn1_beg = achl_beg;
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_enum()


/**
 * private class function:  dsd_asn1::m_get_string()
 *
 * gets an octet-string after TLV-parsing, allocates temporary or permanent storage as needed
 *
 * @param[in,out]  aachp_string  pointer to string address
 * @param[in,out]  aimp_len      pointer to the length of the string
 * @param[in]      aavop_handle  permanent storage handler
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_string( char **aachp_string, int *aimp_len, void **aavop_handle )
{
   int           iml_lenlen;
   char         *achl_beg;
   unsigned int  uml_len;

   // initialize the return value
   *aachp_string = NULL;
   *aimp_len     = 0;

   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 2 /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // test for an 'octet string'-type...
   achl_beg = this->asn1_beg;
   if (*(unsigned char *)achl_beg != LASN1_OCTETSTRING && *(unsigned char *)achl_beg != LASN1_SASL_CREDS)
     return LASN1_ERROR;

   // normal length or multibyte length
   ++achl_beg;
   if ((*achl_beg & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     iml_lenlen = *(unsigned char *)achl_beg & 0x7f;   // get length of length
     // is the length count too big?
     if (iml_lenlen > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + iml_lenlen > this->asn1_end)
       // no, we have to wait for more data...
       return LASN1_WAIT_MORE;

     // construct multibyte length...
     for (uml_len = 0, ++achl_beg; iml_lenlen != 0; --iml_lenlen)
     { // get length (byte by byte)...
       uml_len <<= 8;
       uml_len |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   }
   else
   { // short length values (0...127)
     uml_len = *(unsigned char *)achl_beg;
     ++achl_beg;
   }

   // length calculated, do we have received enough bytes?
   if (achl_beg + uml_len > this->asn1_end)
   // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // copy bytes...
   if (uml_len)
   { // allocate storage and read into the low-order bytes of our buffer...
     *aachp_string = (char *)m_aux_stor_alloc( aavop_handle ? aavop_handle : this->aavo_hl_stor, int(uml_len) );
     *aimp_len     = uml_len;
     memcpy((void *)*aachp_string, (const void *)achl_beg, size_t(uml_len) );

     achl_beg += uml_len;
    }
   // step asn1.-pointer
   this->asn1_beg = achl_beg;
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_string()


/**
 * private class function:  dsd_asn1::m_get_stringar()
 *
 * gets an array(vector) of octet-strings after TLV-parsing, allocates temporary storage as needed
 *
 * @param[in,out]  aadsp_attr_vals  pointer to the structure of values
 * @param[in]      aavop_handle     permanent storage handler
 *
 * @return  \b LASN1_SUCCESS    if everything is OK,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_stringar( dsd_ldap_val **aadsp_attr_vals, void **aavop_handle )
{
   int   iml_setof_tag, iml_setof_len;
   int   iml_rc, iml_lenlen;
   char *achl_beg, *achl_end;
   unsigned int  uml_len;
   struct dsd_ldap_val  **aadsl_attr_vals;

   // initialize the return value
   aadsl_attr_vals = aadsp_attr_vals;

   // skip over the SETOF-tag...
   if ((iml_rc = this->m_get_tag( &iml_setof_tag )) != LASN1_SUCCESS ||
       (iml_rc = this->m_get_len( &iml_setof_len )) != LASN1_SUCCESS)
     return iml_rc;
   if (iml_setof_tag != LASN1_SET)
     return LASN1_ERROR;

   // is the buffer size sufficient?
   if (iml_setof_len && this->asn1_end - this->asn1_beg < 2 /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   achl_beg = this->asn1_beg;
   achl_end = this->asn1_beg + iml_setof_len;

   // parse SETOF-sequence...
   while (achl_beg < achl_end)
   {  // test for an 'octet string'-type...
      if (*achl_beg != LASN1_OCTETSTRING)
        return LASN1_ERROR;

      // normal length or multibyte length
      ++achl_beg;
      if ((*achl_beg & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
      { // multibyte length values (> 127)
        iml_lenlen = *(unsigned char *)achl_beg & 0x7f;   // get length of length
        // is the length count too big?
        if (iml_lenlen > sizeof(unsigned int))
          // yes, ASN.1 decode error
          return LASN1_ERROR;

        // construct multibyte length...
        for (uml_len = 0, ++achl_beg; iml_lenlen != 0; --iml_lenlen)
        { // get length (byte by byte)...
          uml_len <<= 8;
          uml_len |= *(unsigned char *)achl_beg;
          ++achl_beg;
        }
      }
      else
      { // short length values (0...127)
        uml_len = *(unsigned char *)achl_beg;
        ++achl_beg;
      }

      // length calculated, copy bytes...
      if (uml_len)
      { // allocate storage and read into the low-order bytes of our buffer...
        *aadsl_attr_vals = (struct dsd_ldap_val *)m_aux_stor_alloc( aavop_handle ? aavop_handle : this->aavo_hl_stor, 
                                                                    sizeof(struct dsd_ldap_val) + uml_len );
        memset((void *)*aadsl_attr_vals, int(0), sizeof(struct dsd_ldap_val));

        ((struct dsd_ldap_val *)*aadsl_attr_vals)->ac_val      = (char *)*aadsl_attr_vals + sizeof(struct dsd_ldap_val);
        ((struct dsd_ldap_val *)*aadsl_attr_vals)->imc_len_val = uml_len;
        ((struct dsd_ldap_val *)*aadsl_attr_vals)->iec_chs_val = ied_chs_utf_8;

        memcpy((void *)((struct dsd_ldap_val *)*aadsl_attr_vals)->ac_val, (const void *)achl_beg, size_t(uml_len) );
        aadsl_attr_vals = (struct dsd_ldap_val **)&((struct dsd_ldap_val *)*aadsl_attr_vals)->adsc_next_val;

        achl_beg += uml_len;
      }
   } // end of while()

   // step asn1.-pointer
   this->asn1_beg = achl_beg;
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_stringar()


/**
 * public class function:  dsd_asn1::m_test_resp()
 *
 * tests the LDAP-response for a complete ASN.1-structure
 *
 * @param[in]    adsp_buf      received data in a dsd_bufm-structure
 * @param[out]   aimp_len      minimum number of bytes for a complete parsing,
 *                             if LASN1_WAIT_MORE is returned
 * @param[out]   aimp_nextpos  position of the next ldap response
 *                             if LASN1_SUCCESS is returned (only ssl)
 *
 * @return  \b LASN1_SUCCESS      if everything is ok,
 *          \b LASN1_WAIT_MORE    if there are not enough data for processing or
 *          \b LASN1_ERROR        if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_test_resp( class dsd_bufm *adsp_buf, int *aimp_len, int *aimp_nextpos )
{

   int    iml_byte,      // tag or length byte(s)
          iml_byte_t,    // temporary multibyte tag or length
          iml_len;       // temporary multibyte tag or value length
   BOOL   bo_compl;      // ready flag for multibyte processing
   char  *achl_beg,      // temporary buffer start address
         *achl_end_rcv,  // temporary buffer end address of received data
         *achl_end;      // temporary buffer end address;

   // reset length value to be returned
   if (aimp_nextpos)
     *aimp_nextpos = 0;

   *aimp_len = 0;
   // is the buffer size sufficient?
   if (adsp_buf->imc_buflen < D_LDAP_TL_SIZE /*TL==0, without V*/)
   { // no, we have to wait for more data...
     *aimp_len = D_LDAP_TL_SIZE - adsp_buf->imc_buflen;
     return LASN1_WAIT_MORE;
   }
   int iml_valid_len = adsp_buf->imc_pos - adsp_buf->imc_nextpos;
   // have we received a minimum of 'D_LDAP_TL_SIZE' bytes?
   if (iml_valid_len < D_LDAP_TL_SIZE /*TL==0, without V*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // set temporary pointer for parsing
   char* achl_temp = (char *)adsp_buf->m_get_bufaddr();
   achl_beg     = achl_temp + adsp_buf->imc_nextpos;
   achl_end_rcv = achl_temp + adsp_buf->imc_pos;    // end address of data received yet
   achl_end     = achl_temp + adsp_buf->imc_buflen; // end address of data
   ////////////////////////////////////////////////////////////////////////////
   // (T)LV: assume the first byte as the begin of the tag
   // save first tag byte and step pointer to the next position...
   iml_byte = *(unsigned char *)achl_beg;
   ++achl_beg;
   // normal tag or big mask tag (> 31) ?
   if ((iml_byte & LASN1_BIG_TAG_MASK) == LASN1_BIG_TAG_MASK)
   { // multibyte tag processing...
     for (iml_byte = 0, iml_len = 1, bo_compl = FALSE;
          achl_beg <= achl_end_rcv;
          ++iml_len )
     { // construct multibyte tag value...
       iml_byte_t = *(unsigned char *)achl_beg;
       ++achl_beg;
       iml_byte <<= 7;
       iml_byte |= (iml_byte_t & 0x7F);
       // more tag bytes?
       if (!(iml_byte_t & LASN1_MORE_TAG_MASK))
       { bo_compl = TRUE;
         break;  // no, we are ready!
       }
     } // for (spanning multibyte tags)

     // are all bytes processed?
     if (bo_compl == FALSE)
     { // no, we have to wait for more
       *aimp_len = 1;
       return LASN1_WAIT_MORE;
     }

     // tag too big?
       if (iml_len > sizeof(unsigned int))
         // yes, ASN.1 decode error
         return LASN1_ERROR;
   } // multibyte tag processing...

   ////////////////////////////////////////////////////////////////////////////
   // T(L)V: assume the next bytes as the length
   // save first length byte and step pointer to the next position...
   iml_byte = *(unsigned char *)achl_beg;
   ++achl_beg;
   // normal length or multibyte length ?
   if ((iml_byte & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     iml_len = iml_byte & 0x7f;        // get length of length
     // is the length count too big?
     if (iml_len > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + iml_len > achl_end_rcv)
     { // no, we have to wait for more data...
       *aimp_len = (int)(achl_beg + iml_len - achl_end);
       return LASN1_WAIT_MORE;
     }
     // construct multibyte length...
     for (iml_byte = 0; iml_len != 0; --iml_len)
     { // get length (byte by byte)...
       iml_byte <<= 8;
       iml_byte |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   } // multibyte length processing...
   iml_len = iml_byte;
   ////////////////////////////////////////////////////////////////////////////
   // TL(V): assume the next bytes as the values
   // is the buffer size sufficient?
   if (achl_beg + iml_len > achl_end_rcv)
   { // no, we have to wait for more data...
//   if (achl_beg + iml_len - achl_end_rcv > adsp_buf->imc_buflen)
     *aimp_len = (int)(achl_beg + iml_len - achl_end_rcv);
     return LASN1_WAIT_MORE;
   }

   // only ssl!
   if (aimp_nextpos)
     // a ssl packet can contain more than one response!!!
     *aimp_nextpos = (int)(achl_beg - (char *)adsp_buf->m_get_bufaddr() + iml_len);

   return LASN1_SUCCESS;

} // dsd_asn1::m_test_resp( dsd_bufm *, int *, int * )


/**
 * public class function:  dsd_asn1::m_get_tag()
 *
 * get the tag after TLV-parsing
 *
 * @param[in,out]  aimp_tag   tag bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is OK,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_tag( int *aimp_tag )
{
   unsigned int uml_tag;    // temporary multibyte tag byte
   int          inl_len;    // temporary mutlibyte tag length
   BOOL         bo_ready;   // ready flag for multibyte processing
   char        *achl_beg;   // temporary buffer pointer

   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 1 /*T, without LV*/)
   { // no, we have to wait for more data...
     *aimp_tag = LASN1_UNKNOWN;
     return LASN1_WAIT_MORE;
   }

   // returns the first byte as the tag or the saved one
   achl_beg = this->asn1_beg;  // set temporary pointer
   // save tag and step pointer to the next position...
   *aimp_tag = *(unsigned char *)achl_beg;
   ++achl_beg;

   // normal tag or big mask tag (> 31)
   if ((*aimp_tag & LASN1_BIG_TAG_MASK) == LASN1_BIG_TAG_MASK)
   { // multibyte tag processing...
     for (*aimp_tag = 0, inl_len = 1, bo_ready = FALSE;
          achl_beg <= this->asn1_end;
          ++inl_len )
     { // construct mutlibyte tag value...
       uml_tag = *(unsigned char *)achl_beg;
       ++achl_beg;
       *aimp_tag <<= 7;
       *aimp_tag |= (uml_tag & 0x7F);
       // more tag bytes?
       if (!(uml_tag & LASN1_MORE_TAG_MASK))
       { bo_ready = TRUE;
         break;   // no, we are ready!
       }
     } // for (spanning multibyte tags)

     // are all bytes processed?
     if (bo_ready == FALSE)
     { // no, we have to wait for more
       *aimp_tag = LASN1_UNKNOWN;
       return LASN1_WAIT_MORE;
     }

     // tag too big?
       if (inl_len > sizeof(unsigned int))
       { // yes, ASN.1 decode error
         *aimp_tag = LASN1_UNKNOWN;
         return LASN1_ERROR;
       }
   } // multibyte tag processing...

   // everthing is ok!
   this->im_tag   = *aimp_tag;  // save actual tag
   this->asn1_beg = achl_beg;   // save actual address
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_tag()


/**
 * public class function:  dsd_asn1::m_get_len()
 *
 * get the length after TLV-parsing
 *
 * @param[in,out]  aimp_len   length bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_len( int *aimp_len )
{
   int   inl_len;
   char *achl_beg;   // temporary buffer pointer

   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 1 /*L, without V*/)
   { // no, we have to wait for more data...
     *aimp_len = 0;
     return LASN1_WAIT_MORE;
   }

   // returns the first byte as the length or the saved one
   achl_beg = this->asn1_beg;  // set temporary pointer
   // save length and step pointer to the next position...
   *aimp_len = *(unsigned char *)this->asn1_beg;
   ++achl_beg;

   // normal length or multibyte length ?
   if ((*aimp_len & LASN1_MORE_TAG_MASK) == LASN1_MORE_TAG_MASK)
   { // multibyte length values (> 127)
     inl_len   = *aimp_len & 0x7f;    // get length of length
     *aimp_len = 0;
     // is the length count too big?
     if (inl_len > sizeof(unsigned int))
       // yes, ASN.1 decode error
       return LASN1_ERROR;

     // do we have received enough bytes?
     if (achl_beg + inl_len > this->asn1_end)
       // no, we have to wait for more data...
       return LASN1_WAIT_MORE;

     // construct multibyte length...
     for (; inl_len != 0; --inl_len)
     { // get length (byte by byte)...
       *aimp_len <<= 8;
       *aimp_len |= *(unsigned char *)achl_beg;
       ++achl_beg;
     }
   } // multibyte length processing...

   // everything is ok!
   this->im_len   = *aimp_len;  // save actual length
   this->asn1_beg = achl_beg;   // save actual address
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_len()


/**
 * public class function:  dsd_asn1::m_get_msgid()
 *
 * gets the ldap message id
 *
 * @param[in,out]  aimp_msgid   message id bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_msgid( int *aimp_msgid )
{
   // message-id: (T): LASN1_INTEGER, (L): n, (V): integer)
   return this->m_get_int( (int *)aimp_msgid );

} // dsd_asn1::m_get_msgid()


/**
 * public class function:  dsd_asn1::m_get_op()
 *
 * get ldap operation byte (we don't step the buffer pointer!!!)
 *
 * @param[in,out]  aimp_op      operation bytes to return
 *
 * @return  \b LASN1_SUCCESS    if everything is ok,
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_op( int *aimp_op )
{
   // initialize return value
   *aimp_op = 0;
   // is the buffer size sufficient?
   if (this->asn1_end - this->asn1_beg < 1 /*only T, without LV*/)
     // no, we have to wait for more data...
     return LASN1_WAIT_MORE;

   // save operation byte...
   if (*this->asn1_beg & LASN1_CLASS_APPLICATION)
   { *aimp_op = *(unsigned char *)this->asn1_beg;
     return LASN1_SUCCESS;
   }
   return LASN1_ERROR;

} // dsd_asn1::m_get_op()


/**
 * private class function:  dsd_asn1::m_get_val()
 *
 * return the pointer to the value stream (we don't step the buffer pointer!!!)
 *
 * @param[in,out]  achp_val     value address to return
 *
 * @return  \b LASN1_SUCCESS    if everything is OK or
 *          \b LASN1_WAIT_MORE  if there are not enough data for processing
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_get_val( char **achp_val )
{
   // is the buffer size sufficient?
   if (int(this->asn1_end - this->asn1_beg) < this->im_len)
   { // no, we have to wait for more data...
     *achp_val = NULL;
     return LASN1_WAIT_MORE;
   }
   *achp_val = this->asn1_beg;
   this->ach_val = *achp_val;  // save actual value address
   return LASN1_SUCCESS;

} // dsd_asn1::m_get_val()


/**
 * public class function:  dsd_asn1::m_printf()
 *
 * formats an ASN.1 message buffer.
 *
 * @param[in]   achp_fmt   operation format string
 *
 * @return     \b LASN1_SUCCESS     if everything is ok or
 *             \b LASN1_ERROR       if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_printf( const char *achp_fmt, ... )
{
    enum ied_charset  iel_chs;

    struct dsd_ldap_val       *adsl_attr_vals;
    struct dsd_unicode_string *adsl_unicode;

    char  *achl_1, *achl_2, *achl_3;
    char **aachl_1;
    int    iml_1, iml_2;
    int    iml_rc  (LASN1_SUCCESS);


    va_list  dsp_list;
    va_start(dsp_list, achp_fmt);

    for (iml_rc = LASN1_SUCCESS; *achp_fmt && iml_rc == LASN1_SUCCESS; ++achp_fmt)
    {
      switch (*achp_fmt)
      {
        case 'b':  // (b)oolean...
            // create structure with standard tag (LASN1_BOOLEAN), if no "usertag" was set with 't'
            iml_rc = this->m_put_bool( va_arg(dsp_list, int)/*value*/, this->im_tag/*tag*/ );
            break;
        case 'i':   // (i)nteger...
            // create structure with standard tag (LASN1_INTEGER), if no "usertag" was set with 't'
            iml_rc = this->m_put_int( int(va_arg(dsp_list, int))/*value*/, this->im_tag/*tag*/ );
            break;
        case 'e':   // (e)numeration...
            // create structure with standard tag (LASN1_ENUMERATION), if no "usertag" was set with 't'
            iml_rc = this->m_put_enum( int(va_arg(dsp_list, int))/*value*/, this->im_tag/*tag*/ );
            break;
        case 'n':   // (n)ull...
            // create structure with standard tag (LASN1_NULL), if no "usertag" was set with 't'
            iml_rc = this->m_put_null( this->im_tag/*tag*/ );
            break;
        case 'o':   // (o)ctet string...
            achl_1  = va_arg(dsp_list, char *);   // string pointer
            iml_1   = va_arg(dsp_list, int);      // string length
            iml_rc = this->m_put_octetstring( achl_1, iml_1, this->im_tag/*tag*/ );
            break;
        case 's':   // (s)tring...
            // create structure with standard tag (LASN1_OCTETSTRING), if no "usertag" was set with 't'
            achl_1  = va_arg(dsp_list, char *);            // string pointer
            iml_1   = va_arg(dsp_list, int);               // string length
            iel_chs = (ied_charset)va_arg(dsp_list, int);  // string character set
            iml_rc = this->m_put_string( achl_1, iml_1, iel_chs, this->im_tag/*tag*/ );
            break;
        case 'S':   // struct dsd_unicode_(S)tring...
            // create structure with standard tag (LASN1_OCTETSTRING), if no "usertag" was set with 't'
            adsl_unicode = va_arg(dsp_list, struct dsd_unicode_string *);    // pointer to a unicode string structure
            iml_rc = this->m_put_string_uc( adsl_unicode, this->im_tag/*tag*/ );
            break;
        case 't':   // (t)ag for the next element...
            this->im_tag = va_arg(dsp_list, unsigned int);
            this->im_usertag = 1;
            break;
        case 'v':   // (v)ector of strings...
            adsl_attr_vals = va_arg(dsp_list, struct dsd_ldap_val *);
            // step through this array of strings...
            while (adsl_attr_vals && adsl_attr_vals->imc_len_val)
            {
              iml_rc = this->m_put_string( (char *)adsl_attr_vals->ac_val, int(adsl_attr_vals->imc_len_val),
                                           ied_charset(adsl_attr_vals->iec_chs_val), this->im_tag );
              if (iml_rc != LASN1_SUCCESS)
                break;

                adsl_attr_vals = adsl_attr_vals->adsc_next_val;
            }
            break;
        case 'a':   // (a)rray of null terminated strings...
            aachl_1 = va_arg(dsp_list, char **);          // pointer to a string array
            iel_chs = (ied_charset)va_arg(dsp_list, int); // string character set
            // step through this array of strings...
            while (*aachl_1)
            {
              iml_rc = this->m_put_string( *aachl_1, (int)strnlen( *aachl_1, D_LDAP_MAX_STRLEN ), iel_chs, this->im_tag );
              if (iml_rc != LASN1_SUCCESS)
                break;

                aachl_1++;
            }
            break;
        case 'C':   // (C)SV-formatted strings...
            achl_1  = va_arg(dsp_list, char *);           // CSV-string
            iml_1   = va_arg(dsp_list, int);              // string length
            iel_chs = (ied_charset)va_arg(dsp_list, int); // string character set

            if (achl_1)
            { // translate string to utf-8, if necessary...
              if (iel_chs != ied_chs_utf_8)
              { iml_2 = m_len_vx_vx( ied_chs_utf_8, (void *)achl_1, int(iml_1), iel_chs );
                if (iml_2 == -1)
                { // error, invalid string format...
                  iml_rc = LASN1_ERROR;
                  break;
                }
                // allocate storage for the translation
                achl_2 = (char *)m_aux_stor_alloc( this->aavo_hl_stor, iml_2 + 1 /*'\0'*/ );
                // translation to UTF-8...
                if (m_cpy_vx_vx_fl( (void *)achl_2, iml_2, ied_chs_utf_8, 
                                    (void *)achl_1, iml_1, iel_chs,
                                    D_CPYVXVX_FL_NOTAIL0 ) == -1)
                {  // error, invalid string format
                   iml_rc = LASN1_ERROR;
                   break;
                }

                achl_1 = achl_2;
                iml_1 = iml_2;
              }

              // step through this array of strings...
              // check for the string length -1 (zero terminated string)
              if (iml_1 < 0)  iml_1 = (int)strnlen( (const char *)achl_1, D_LDAP_MAX_STRLEN );
              achl_2 = achl_1;
              while (iml_1)
              {  // search for ','-delimiter
                 if (_iscomma(*achl_1))
                 { // delimiter found
                   achl_3 = achl_1;
                   while (isspace((unsigned char)*achl_2))        ++achl_2;   // ignore spaces...
                   while (isspace((unsigned char)*(achl_1 - 1)))  --achl_1;
                   iml_rc = this->m_put_string( achl_2, (int)(achl_1 - achl_2), ied_chs_utf_8, this->im_tag/*tag*/ );
                   if (iml_rc != LASN1_SUCCESS)
                     break;
                   // step to the next element...
                   achl_2 = achl_3 + 1;
                   achl_1 = achl_3;
                 }
                 ++achl_1;
                 --iml_1;
              } // end of while()

              if (iml_rc == LASN1_SUCCESS && achl_2)
                iml_rc = this->m_put_string( achl_2, int(achl_1 - achl_2), ied_chs_utf_8, this->im_tag/*tag*/ );
            } // end of valid input string
            break;
        case '{':   // begin sequence...
            // create structure with standard tag (LASN1_SEQUENCE), if no "usertag" was set with 't'
            iml_rc = this->m_start_seq( this->im_tag );
            break;
        case '}':   // end sequence...
            // close structure and calculate length of all elements
            iml_rc = this->m_end_seq();
            break;
        case '[':   // begin set...
            iml_rc = this->m_start_set( this->im_tag );
            break;
        case ']':   // end set...
            iml_rc = this->m_end_set();
            break;

        default:   // no support for all other functions...
            iml_rc = LASN1_ERROR;
            break;
      } // switch()

      if ( this->im_usertag == 0 )
        this->im_tag = LASN1_ERROR;
      else
        this->im_usertag = 0;
    } // for-loop()

    va_end( dsp_list );
    return iml_rc;

} // dsd_asn1::m_printf()


/**
 * public class function:  dsd_asn1::m_scanf()
 *
 * parses the received ASN.1 message string.
 *
 * @param[in]   achp_fmt   operation format string
 *
 * @return     \b LASN1_SUCCESS     if everything is OK or
 *             \b LASN1_ERROR       if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_scanf( const char *achp_fmt, ... )
{
    int    iml_rc  (LASN1_SUCCESS);
    int   *aiml_1;
    char **aachl_1;
    void **aavol_1;
    struct dsd_ldap_val **aadsl_attr_vals;

    va_list   dsp_list;
    va_start( dsp_list, achp_fmt );

/*
    // no more data to parse?
    if (this->asn1_beg == this->asn1_end)
    { this->bo_no_data = TRUE;
      return LASN1_NO_DATA;
    }
    else
      this->bo_no_data = FALSE;
*/
    for (iml_rc = 0; *achp_fmt && iml_rc == LASN1_SUCCESS; ++achp_fmt)
    {
       switch (*achp_fmt)
       {
          case 'b':  // (b)oolean...
                     iml_rc = this->m_get_bool( (BOOL *)va_arg(dsp_list, int *) );
                     break;
          case 'e':  // (e)numeration...
                     iml_rc = this->m_get_enum( (int *)va_arg(dsp_list, int *) );
                     break;
          case 'i':  // (i)nteger...
                     iml_rc = this->m_get_int( (int *)va_arg(dsp_list, int *) );
                     break;
          case 'o':  // (o)ctet string... - allocate temporary storage as needed
                     aachl_1 = va_arg(dsp_list, char **);
                     aiml_1  = va_arg(dsp_list, int *);
                     iml_rc = this->m_get_string( aachl_1, aiml_1 );
                     break;
          case 'O':  // (o)ctet string... - allocate permanent storage as needed
                     aachl_1 = va_arg(dsp_list, char **);
                     aiml_1  = va_arg(dsp_list, int *);
                     aavol_1 = va_arg(dsp_list, void **);
                     iml_rc = this->m_get_string( aachl_1, aiml_1, aavol_1/*permanent storage handler*/ );
                     break;
          case 'v':  // (v)ector of strings (in other words: sequence of strings)...- allocate temporary storage
                     aadsl_attr_vals = va_arg(dsp_list, struct dsd_ldap_val **);
                     iml_rc = this->m_get_stringar( aadsl_attr_vals );
                     break;
          case 'V':  // (v)ector of strings (in other words: sequence of strings)...- allocate permanent storage
                     aadsl_attr_vals = va_arg(dsp_list, struct dsd_ldap_val **);
                     aavol_1         = va_arg(dsp_list, void **);
                     iml_rc = this->m_get_stringar( aadsl_attr_vals, aavol_1/*permanent storage handler*/ );
                     break;
          case 'x':  // skip the ne(x)t element... - whatever it is
                     if ((iml_rc = this->m_get_tag(&this->im_tag)) == LASN1_SUCCESS &&
                         (iml_rc = this->m_get_len(&this->im_len)) == LASN1_SUCCESS)
                     {
                       this->asn1_beg += this->im_len;                   // step address to the next tag
                       this->im_tag = *(unsigned char *)this->asn1_beg;  // and save it
                     }
                     break;
          case '{':  // begin sequence...
          case '[':  // begin set of...
                     if (*(achp_fmt + 1) != 'v' && *(achp_fmt + 1) != 'V')
                     { // save tag and length
                       iml_rc = this->m_get_tag( &this->im_tag );
                       if (iml_rc == LASN1_SUCCESS)
                       iml_rc = this->m_get_len( &this->im_len );
                     }
                     break;
          case '}':  // end sequence...
          case ']':  // end set...
                     break;

          default:  // all other format identifier are not supported (for the moment)
                    iml_rc = LASN1_ERROR;
                    break;
       } // end of switch()
    } // end of for()

    va_end( dsp_list );
    return iml_rc;

} // dsd_asn1::m_scanf()


/**
 * public class function:  dsd_asn1::m_set_gather()
 *
 * sets a gather chain for sending data and set statistic data
 *
 * @param[in,out]  ailp_datalen  add the length of gather data (statistics)
 *
 * @return   \b LASN1_SUCCESS   if everything is ok or
 *           \b LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_set_gather( HL_LONGLONG* ailp_datalen )
{
    struct dsd_gather_i_1  *adsl_gath_1;
    struct dsd_gather_i_1  *adsl_gath_2  (NULL);
    struct dsd_asn1::dsd_elem_1   *adsl_elem_1;
    struct dsd_asn1::dsd_seqof_1  *adsl_seqof_1;

    int  iml_sendlen = 0;
    // allocate storage for all samples asn.1-structures...
    this->ads_gather = (struct dsd_gather_i_1 *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                                  int(this->ds_seqof.imc_gath_cnt * sizeof(struct dsd_gather_i_1)) );
    memset( (void *)this->ads_gather, int(0), size_t(this->ds_seqof.imc_gath_cnt * sizeof(struct dsd_gather_i_1)) );
    adsl_gath_1 = this->ads_gather;

    // step over all sequences...
    adsl_seqof_1 = &this->ds_seqof;
    while (adsl_seqof_1)
    {  // set gather members...
       adsl_gath_1->achc_ginp_cur = adsl_seqof_1->achc_buf;
       adsl_gath_1->achc_ginp_end = adsl_gath_1->achc_ginp_cur + adsl_seqof_1->imc_len;
       // statistics...
       iml_sendlen += adsl_seqof_1->imc_len;
       // step to the next gather...
       // adsl_gath_1->adsc_next = (struct dsd_gather_i_1 *)(adsl_gath_1 + sizeof(struct dsd_gather_i_1));
       adsl_gath_1->adsc_next = adsl_gath_1 + 1;
       adsl_gath_2 = adsl_gath_1;
       adsl_gath_1 = adsl_gath_1->adsc_next;

       // step over all elements for this sequence...
       adsl_elem_1  = adsl_seqof_1->adsc_elem;
       while (adsl_elem_1)
       {  // set gather members...
          adsl_gath_1->achc_ginp_cur = adsl_elem_1->achc_buf;
          adsl_gath_1->achc_ginp_end = adsl_gath_1->achc_ginp_cur + adsl_elem_1->imc_len;
          // statistics...
          iml_sendlen += adsl_elem_1->imc_len;
          // step to the next gather...
          // adsl_gath_1->adsc_next = (struct dsd_gather_i_1 *)(adsl_gath_1 + sizeof(struct dsd_gather_i_1));
          adsl_gath_1->adsc_next = adsl_gath_1 + 1;
          adsl_gath_2 = adsl_gath_1;
          adsl_gath_1 = adsl_gath_1->adsc_next;
          // step to the next element...
          adsl_elem_1 = adsl_elem_1->adsc_next;
       } // while (elements)

       // next in chain...
       adsl_seqof_1 = adsl_seqof_1->adsc_next;
     } // while (sequences)

     // adjust end of chain
     adsl_gath_2->adsc_next = NULL;
     // statistics...
     if (ailp_datalen)
       *ailp_datalen += iml_sendlen;

     return LASN1_SUCCESS;

} // dsd_asn1::m_set_gather()


/**
 * private class function:  dsd_asn1::m_put_null()
 *
 * sets a null in ASN.1-notation
 *
 * @param[in]    imp_tag    tag byte (LASN1_NULL or user tag)
 *
 * @return  \b LASN1_SUCCESS    if everything is OK or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_null( int imp_tag )
{
    int  iml_taglen;
    int  iml_lenlen;
    struct dsd_asn1::dsd_elem_1 *adsl_elem_1 (this->m_get_element());

    // set tag value and null length of the value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_NULL : imp_tag;
    adsl_elem_1->imc_len = 0;

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len) );

    // write tlv...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );
    // set length of buffer bytes written...
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_null()


/**
 * private class function:  dsd_asn1::m_start_set()
 *
 * sets the SET_OF tag
 *
 * @param[in]   imp_tag    tag byte (LASN1_SET or usertag)
 *
 * @return  \b LASN1_SUCCESS   if everything is ok or
 *          \b LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_start_set( int imp_tag )
{
    return this->m_start_seq( (imp_tag == LASN1_ERROR) ? LASN1_SET : imp_tag );

} // dsd_asn1::m_start_set()


/**
 * private class function:  dsd_asn1::m_end_set()
 *
 * ends the SET_OF tag and calculate the length of all elements
 *
 * @return  \b LASN1_SUCCESS   if everything is ok or
 *          \b LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int  dsd_asn1::m_end_set()
{
    /*
     * If this is the toplevel sequence or set, we need to actually
     * write the stuff out.  Otherwise, it's already been put in
     * the appropriate buffer and will be written when the toplevel
     * one is written.  In this case all we need to do is update the
     * length and tag.
     */
    return this->m_end_seq();

} // dsd_asn1::m_end_set()


/**
 * private class function:  dsd_asn1::m_start_seq()
 *
 * sets the SEQUENCE_OF tag
 *
 * @param[in]  imp_tag    tag byte (LASN1_SEQUENCE or usertag)
 *
 * @return  \b LASN1_SUCCESS   if everything is ok or
 *          \b LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_start_seq( int imp_tag )
{
    // search last in chain...
    struct dsd_asn1::dsd_seqof_1  *adsl_seqof  (&this->ds_seqof);
    struct dsd_asn1::dsd_seqof_1  *adsl_seqof_p;

    while (adsl_seqof->adsc_next)
         adsl_seqof = adsl_seqof->adsc_next;

    // use the anchor or allocate a new one to set the tag...
    if (adsl_seqof->imc_tag != LASN1_ERROR)
    { // allocate a new one...
      adsl_seqof_p = adsl_seqof;
      adsl_seqof->adsc_next = (dsd_asn1::dsd_seqof_1 *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                                         int(sizeof(dsd_asn1::dsd_seqof_1)) );
      // initiate structure...
      adsl_seqof = adsl_seqof->adsc_next;
      memset( (void *)adsl_seqof, int(0), sizeof(dsd_asn1::dsd_seqof_1) );
      adsl_seqof->adsc_prev = adsl_seqof_p;
    }

    this->ads_seqof_act = adsl_seqof;
    this->ads_seqof_act->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_SEQUENCE : imp_tag;
    return LASN1_SUCCESS;

} // dsd_asn1::m_start_seq()


/**
 * private class function:  dsd_asn1::m_end_seq()
 *
 * ends the SEQUENCE_OF tag and calculate the length of all elements
 *
 * @return  \b LASN1_SUCCESS   if everything is ok or
 *          \b LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_end_seq()
{
   struct dsd_asn1::dsd_elem_1  *adsl_elem_1;
   struct dsd_asn1::dsd_seqof_1 *adsl_seqof_1;

   int  iml_len_all;
   int  iml_taglen, iml_lenlen;

   // valid sequenceOf-chain?
   if (this->ads_seqof_act)
   { // search all inserted elements...
     iml_len_all = 0;
     this->ads_seqof_act->imc_gath_cnt = 0;

     adsl_elem_1 = this->ads_seqof_act->adsc_elem;
     while (adsl_elem_1)
     {  // add length...
        iml_len_all += adsl_elem_1->imc_len;
        // next in chain...
        ++this->ads_seqof_act->imc_gath_cnt;
        adsl_elem_1 = adsl_elem_1->adsc_next;
     }

     // add length of all chained sequences...
     adsl_seqof_1 = this->ads_seqof_act->adsc_next;
     while (adsl_seqof_1)
     {  if (adsl_seqof_1->imc_gath_cnt != -1)
        { // not yet counted!
          iml_len_all += adsl_seqof_1->imc_len_all;
          this->ads_seqof_act->imc_gath_cnt += adsl_seqof_1->imc_gath_cnt;
          adsl_seqof_1->imc_gath_cnt = -1;   // registered!
        }
        // search next...
        adsl_seqof_1 = adsl_seqof_1->adsc_next;
     }

     // calculate the length of the tag and the length of the length...
     iml_taglen = this->m_calc_taglen( this->ads_seqof_act->imc_tag );
     iml_lenlen = this->m_calc_lenlen( iml_len_all );
     // allocate storage for the asn.1-TLV
     this->ads_seqof_act->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                               int(iml_taglen + iml_lenlen) );
     ++this->ads_seqof_act->imc_gath_cnt;
     // write TLV...
     this->m_put_tag( ads_seqof_act->imc_tag, iml_taglen, ads_seqof_act->achc_buf );
     this->m_put_len( iml_len_all, iml_lenlen, ads_seqof_act->achc_buf + iml_taglen );
     // set length of buffer bytes written (length overall)...
     this->ads_seqof_act->imc_len     = iml_lenlen + iml_taglen;
     this->ads_seqof_act->imc_len_all = iml_len_all + this->ads_seqof_act->imc_len;
     // sequenceOf-structure completed!
     this->ads_seqof_act->boc_set = TRUE;

     // step to the next active sequenceOf-structure...
     this->ads_seqof_act = this->ads_seqof_act->adsc_prev;
     while (this->ads_seqof_act && this->ads_seqof_act->boc_set == TRUE)
          this->ads_seqof_act = this->ads_seqof_act->adsc_prev;

     return LASN1_SUCCESS;
   }

     // no active sequenceOf-chain!
     return LASN1_ERROR;

} // dsd_asn1::m_end_seq()


/**
 * private class function:  dsd_asn1::m_calc_taglen()
 *
 * calculate the length of the tag bytes in the TLV
 *
 * @param[in]  imp_tag   tag value
 *
 * @return      number of bytes  if everything is OK or
 *           \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_calc_taglen( int imp_tag )
{
    int          iml_1;
    unsigned int uml_mask;

    // find the first non-all-zero byte in the tag..
    for (iml_1 = sizeof(unsigned int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_tag & uml_mask)
         break;
    }
    return iml_1 + 1;

} // dsd_asn1::m_calc_taglen()


/**
 * private class function:  dsd_asn1::m_calc_lenlen()
 *
 * calculate the length of the length bytes in the TLV
 *
 * @param[in]  imp_len    length value
 *
 * @return     number of bytes in asn.1-length notation
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_calc_lenlen( int imp_len )
{
    //  short length, if it's less than 128 - one byte giving the len, with bit 8=0
    if (imp_len <= (unsigned int)0x7FU)  return 1;

    // long length otherwise - one byte with bit 8 set, giving the length of the length,
    // followed by the length itself
    if (imp_len <= (unsigned int)0xffU)     return 2;
    if (imp_len <= (unsigned int)0xffffU)   return 3;
    if (imp_len <= (unsigned int)0xffffffU) return 4;
    return 5;

} // dsd_asn1::m_calc_lenlen()


/**
 * private class function:  dsd_asn1::m_put_tag()
 *
 * writes an ASN.1-tag in network byte order
 *
 * @param[in]  imp_tag     tag bytes
 * @param[in]  imp_taglen  number of tag bytes
 * @param[in]  achp_buf    destination buffer to write
 *
 * @return  \b LASN1_SUCCESS    if everything is ok or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_tag( int imp_tag, int imp_taglen, char *achp_buf )
{
    unsigned char  chrl_nettag[sizeof(int)];

    for (int inl_1 = 0; inl_1 < imp_taglen; ++inl_1)
    {  // build network byte order
        chrl_nettag[(sizeof(unsigned int) - 1) - inl_1] = (unsigned char)(imp_tag & 0xffU);
        imp_tag >>= 8;
    }

    memcpy((void *)achp_buf, (const void *)&chrl_nettag[sizeof(int) - imp_taglen], size_t(imp_taglen) );
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_tag()


/**
 * private class function:  dsd_asn1::m_put_len()
 *
 * writes an ASN.1-length in network byte order
 *
 * @param[in]  imp_len     length bytes
 * @param[in]  imp_lenlen  number of length bytes
 * @param[in]  achp_buf    destination buffer to write
 *
 * @return  \b LASN1_SUCCESS    if everything is ok or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_len( int imp_len, int imp_lenlen, char *achp_buf )
{
    unsigned char chrl_netlen[sizeof(int)] = { 0 };

    // short len if it's less than 128 - one byte giving the len, with bit 8=0
    if (imp_lenlen == 1)
      *achp_buf = char(imp_len);
    else
    { // long length otherwise - one byte with bit 8 set, giving the length of the
      // length, followed by the length itself.
      --imp_lenlen;
      *achp_buf = char(0x80 | imp_lenlen);
      // write length bytes in network byte order...
      for (int inl_1 = 0; inl_1 < imp_lenlen; ++inl_1)
      {  // build network byte order
         chrl_netlen[(sizeof(unsigned int) - 1) - inl_1] = (unsigned char)(imp_len & 0xffU);
         imp_len >>= 8;
      }
      memcpy((void *)(achp_buf + 1), (const void *)&chrl_netlen[sizeof(int) - imp_lenlen], size_t(imp_lenlen) );
    }
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_len()


/**
 * private class function:  dsd_asn1::m_put_int()
 *
 * sets an integer in ASN.1-notation
 *
 * @param[in]  imp_int    value bytes
 * @param[in]  imp_tag    tag byte (LASN1_INTEGER or usertag)
 *
 * @return  \b LASN1_SUCCESS    if everything is ok or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_int( int imp_int/*value*/, int imp_tag/*tag*/ )
{
    int            iml_1;               // work variable
    int            iml_taglen, iml_lenlen;
    unsigned int   uml_int, uml_mask;
    unsigned char  chrl_netval[sizeof(int)];

    struct dsd_elem_1  *adsl_elem_1  (this->m_get_element());

    // save tag value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_INTEGER : imp_tag;

    // calculate length of integer value...
    uml_int = imp_int;    // bit fiddling should be done with unsigned values
    // look for first non-all-one byte...
    for (iml_1 = sizeof(int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_int < 0 /*signed?*/)
       {  // not all ones
          if ((uml_int & uml_mask) != uml_mask)  break;
       }
       else
       { // not all zero
         if (uml_int & uml_mask)  break;
    }  }

    // we now have the "leading byte". if the high bit on this byte matches the sign bit,
    // we need to "back up" a byte.
    uml_mask = uml_int & ((unsigned int)0x80U << (iml_1 * 8));
    if ((uml_mask && !(imp_int < 0/*signed?*/)) || ((imp_int < 0/*signed?*/) && !uml_mask))
      ++iml_1;

    // calculate the length of the value
    adsl_elem_1->imc_len = iml_1 + 1;
    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len) );
    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );

    for (iml_1 = 0; iml_1 < adsl_elem_1->imc_len; ++iml_1)
    {  // build network byte order
       chrl_netval[(sizeof(unsigned int) - 1) - iml_1] = (unsigned char)(uml_int & 0xffU);
       uml_int >>= 8;
    }
    memcpy((void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen), (const void *)&chrl_netval[sizeof(int) - adsl_elem_1->imc_len], adsl_elem_1->imc_len );
    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_int()


/**
 * private class function:  dsd_asn1::m_put_enum()
 *
 * sets an enumeration in ASN.1-notation
 *
 * @param[in]  imp_enum    value bytes
 * @param[in]  imp_tag     tag byte (LASN1_ENUMERATED or usertag)
 *
 * @return  \b LASN1_SUCCESS    if everything is ok or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_enum( int imp_enum/*value*/, int imp_tag/*tag*/ )
{
    int  iml_1;               // work variable
    int  iml_taglen, iml_lenlen;
    unsigned int   uml_enum, uml_mask;
    unsigned char  chrl_netval[sizeof(int)];

    struct dsd_elem_1  *adsl_elem_1  (this->m_get_element());

    // save tag value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_ENUMERATED : imp_tag;

    // calculate length of enumeration value...
    uml_enum = imp_enum;      // bit fiddling should be done with unsigned values
    // look for first non-all-one byte...
    for (iml_1 = sizeof(int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_enum < 0 /*signed?*/)
       {  // not all ones
          if ((uml_enum & uml_mask) != uml_mask)  break;
       }
       else
       { // not all zero
         if (uml_enum & uml_mask)  break;
    }  }

    // we now have the "leading byte". if the high bit on this byte matches the sign bit,
    // we need to "back up" a byte.
    uml_mask = uml_enum & ((unsigned int)0x80U << (iml_1 * 8));
    if ((uml_mask && !(imp_enum < 0/*signed?*/)) || ((imp_enum < 0/*signed?*/) && !uml_mask))
      ++iml_1;

    // calculate the length of the value
    adsl_elem_1->imc_len = iml_1 + 1;
    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len) );
    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );

    for (iml_1 = 0; iml_1 < adsl_elem_1->imc_len; ++iml_1)
    {  // build network byte order
       chrl_netval[(sizeof(unsigned int)-1) - iml_1] = (unsigned char)(uml_enum & 0xffU);
       uml_enum >>= 8;
    }
    memcpy((void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen), (const void *)&chrl_netval[sizeof(int) - adsl_elem_1->imc_len], adsl_elem_1->imc_len );
    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_enum()


/**
 * private class function:  dsd_asn1::m_put_string()
 *
 * sets an octet string in ASN.1-notation, the string is translated in UTF-8.
 *
 * @param[in]  astrp_str    string bytes
 * @param[in]  imp_len      string length
 * @param[in]  iep_chs_src  character-set of the string
 * @param[in]  imp_tag      tag byte (LASN1_OCTETSTRING or user-tag)
 *
 * @return   \b LASN1_SUCCESS    if everything is ok or
 *           \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * MSAD uses a quoted unicode-16 little endian string for the password modification,
 * we must copy this without any changes!\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_string( char *astrp_str, int imp_len, enum ied_charset iep_chs_src, int imp_tag )
{
    int         iml_taglen, iml_lenlen;
    struct dsd_elem_1 *adsl_elem_1  (this->m_get_element());

    // save tag value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_OCTETSTRING : imp_tag;

    if (astrp_str && iep_chs_src != ied_chs_utf_8 && iep_chs_src != ied_chs_le_utf_16 /*MSAD: e.g 'unicodePwd'-values*/)
    {
      adsl_elem_1->imc_len = m_len_vx_vx( ied_chs_utf_8, (void *)astrp_str, int(imp_len), iep_chs_src );
      if (adsl_elem_1->imc_len == -1)
        // error, invalid string format...
        return LASN1_ERROR;
    }

    // check for the length value -1 (zero terminated)
    adsl_elem_1->imc_len = (imp_len < 0) ? (int)strnlen( (const char *)astrp_str, D_LDAP_MAX_STRLEN )
                                         : imp_len;

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len + 1 /*'\0'*/) );
    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );

    if (astrp_str)
    { // translation to UTF-8 (if necessary)...
      if (iep_chs_src != ied_chs_utf_8 && iep_chs_src != ied_chs_le_utf_16)
      { // translation to UTF-8...
        if (m_cpy_vx_vx_fl( (void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen), adsl_elem_1->imc_len, ied_chs_utf_8,
                            (void *)astrp_str, imp_len, iep_chs_src,
                            D_CPYVXVX_FL_NOTAIL0 ) == -1)
          // error, invalid string format
          return LASN1_ERROR;
      }
      else
        memcpy((void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen),
               (const void *)astrp_str, size_t(adsl_elem_1->imc_len) );
    }
    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_string()


/**
 * private class function:  dsd_asn1::m_put_string_uc()
 *
 * sets an octet string in ASN.1-notation, the string is translated in UTF-8.
 *
 * @param[in]  adsp_unicode  unicode string description
 * @param[in]  imp_tag       tag byte (LASN1_OCTETSTRING or user-tag)
 *
 * @return  \b LASN1_SUCCESS    if everything is OK or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * MSAD uses a quoted unicode-16 little endian string for the password modification,
 * we must copy this without any changes!\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_string_uc( dsd_unicode_string *adsp_unicode, int imp_tag )
{
    int  iml_taglen, iml_lenlen;
    struct dsd_elem_1 *adsl_elem_1  (this->m_get_element());

    // save tag value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_OCTETSTRING : imp_tag;

    if (adsp_unicode->ac_str && adsp_unicode->iec_chs_str != ied_chs_utf_8 &&
                                adsp_unicode->iec_chs_str != ied_chs_le_utf_16 /*MSAD: e.g 'unicodePwd'-values*/)
    {
      adsl_elem_1->imc_len = m_len_vx_ucs( ied_chs_utf_8, adsp_unicode );
      if (adsl_elem_1->imc_len == -1)
        // error, invalid string format...
        return LASN1_ERROR;
    }

      // check for the length value -1 (zero terminated)
      adsl_elem_1->imc_len = (adsp_unicode->imc_len_str < 0) ? (int)strnlen( (const char *)adsp_unicode->ac_str, D_LDAP_MAX_STRLEN )
                                                             : adsp_unicode->imc_len_str;

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len + 1 /*'\0'*/) );

    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );

    if (adsp_unicode->ac_str)
    { // translation to UTF-8 (if necessary)...
      if (adsp_unicode->iec_chs_str != ied_chs_utf_8 && adsp_unicode->iec_chs_str != ied_chs_le_utf_16)
        // translation to UTF-8...
        m_cpy_vx_ucs( (void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen), adsl_elem_1->imc_len, ied_chs_utf_8,
                      adsp_unicode );
      else
        memcpy((void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen),
               (const void *)adsp_unicode->ac_str, size_t(adsl_elem_1->imc_len) );
    }
    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

}; // dsd_asn1::m_put_string_uc()


/**
 * private class function:  dsd_asn1::m_put_octetstring()
 *
 * sets an octet string in ASN.1-notation w/o any translation.
 *
 * @param[in]  astrp_str    string bytes
 * @param[in]  imp_len      string length
 * @param[in]  imp_tag      tag byte (LASN1_OCTETSTRING or user-tag)
 *
 * @return  \b LASN1_SUCCESS    if everything is OK or
 *          \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_octetstring( char *astrp_str, int imp_len, int imp_tag )
{
    int  iml_taglen;
    int  iml_lenlen;
    struct dsd_elem_1 *adsl_elem_1  (this->m_get_element());

    // save tag value
    adsl_elem_1->imc_tag = (imp_tag == LASN1_ERROR) ? LASN1_OCTETSTRING : imp_tag;

    // we need a valid length of the string...
    if (imp_len < 0 /* || imp_len == 0 */)
      return LASN1_ERROR;

    adsl_elem_1->imc_len = imp_len;
    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( adsl_elem_1->imc_tag );
    iml_lenlen = this->m_calc_lenlen( adsl_elem_1->imc_len );
    // allocate storage for the asn.1-TLV
    adsl_elem_1->achc_buf = (char *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                      int(iml_taglen + iml_lenlen + adsl_elem_1->imc_len) );
    // write TLV...
    this->m_put_tag( adsl_elem_1->imc_tag, iml_taglen, adsl_elem_1->achc_buf );
    this->m_put_len( adsl_elem_1->imc_len, iml_lenlen, adsl_elem_1->achc_buf + iml_taglen );

    if (astrp_str != NULL && imp_len > 0)  // no values to copy for empty strings
      memcpy((void *)(adsl_elem_1->achc_buf + iml_taglen + iml_lenlen),
             (const void *)astrp_str, size_t(imp_len) );
    
    // set length of buffer bytes written (length overall)
    adsl_elem_1->imc_len += iml_taglen + iml_lenlen;
    return LASN1_SUCCESS;

} // dsd_asn1::m_put_octetstring()


/**
 * private class function:  dsd_asn1::m_put_complex_filter()
 *
 * constructs an ASN.1-coded filter with OR, AND or NOT.
 *
 * @param[in]  achp_filter  filter string to search in
 * @param[in]  imp_tag      explicit tag (AND, OR, NOT) to be set
 *
 * @return     char*   pointer to the next filter element, if everything is ok or
 *          \b NULL    if an error in the filter string is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
char * dsd_asn1::m_put_complex_filter(  char *achp_filter, int imp_tag )
{
    char  *achl_next;

    // we have (x(filter)...) with achp_filter as the address to the x.
    // we have to find the parent matching the one before the x and put
    // the intervening filters by calling m_put_filter_list().
    if (this->m_printf( "t{", imp_tag ) == LASN1_ERROR)
      return NULL;

    ++achp_filter;
    if ((achl_next = this->m_find_filter_right_parent( achp_filter )) == NULL)
      return NULL;

    *achl_next = '\0';
    if (this->m_put_filter_list( achp_filter, imp_tag ) == LASN1_ERROR)
      return NULL;

    // close the '('...
    *achl_next++ = ')';
    // flush explicit tagged thang
    if (this->m_printf( "}" ) == LASN1_ERROR)
      return NULL;

    return achl_next;

} // dsd_asn1::m_put_complex_filter()


/**
 * public class function:  dsd_asn1::m_put_filter()
 *
 * constructs an ASN.1-coded filter (OpenLDAP::ldap_pvt_put_filter()).
 *
 * A filter looks like this:
 *      Filter ::= CHOICE { and             [0]     SET OF Filter,
 *                          or              [1]     SET OF Filter,
 *                          not             [2]     Filter,
 *                          equalityMatch   [3]     AttributeValueAssertion,
 *                          substrings      [4]     SubstringFilter,
 *                          greaterOrEqual  [5]     AttributeValueAssertion,
 *                          lessOrEqual     [6]     AttributeValueAssertion,
 *                          present         [7]     AttributeType,
 *                          approxMatch     [8]     AttributeValueAssertion,
 *                          extensibleMatch [9]     MatchingRuleAssertion -- LDAPv3 }
 *
 *      SubstringFilter ::= SEQUENCE { type               AttributeType,
 *                                     SEQUENCE OF CHOICE { initial          [0] IA5String,
 *                                                          any              [1] IA5String,
 *                                                          final            [2] IA5String }
 *                                   }
 *
 *      MatchingRuleAssertion ::= SEQUENCE { -- LDAPv3
 *                                           matchingRule    [1] MatchingRuleId OPTIONAL,
 *                                           type            [2] AttributeDescription OPTIONAL,
 *                                           matchValue      [3] AssertionValue,
 *                                           dnAttributes    [4] BOOLEAN Default: FALSE }
 *
 * Note: tags in a choice are always explicit
 *
 *
 * @param[in]  achp_filter      filter string to search in
 * @param[in]  imp_len_filter   length of the filter string
 * @param[in]  iep_chs_filter   character set of the filter
 *
 * @return     \b LASN1_SUCCESS    if everything is ok or
 *             \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The filter string has to be UTF-8 formatted!
 */
int dsd_asn1::m_put_filter( const char *achp_filter, int imp_len_filter, enum ied_charset iep_chs_filter )
{
    int   iml_rc;
    char *achl_filter;   // local copy of the filter string parameter
    int   iml_filter;
    char *achl_next;
    int   iml_braces (0);


    // test the parameters for validity!!
    if (achp_filter == NULL || imp_len_filter == 0 || imp_len_filter > D_LDAP_MAX_STRLEN)
      return LASN1_ERROR;

    // unfortunately, we have to copy the string (because of the OpenLDAP-routines!)
    iml_filter = m_len_vx_vx( ied_chs_utf_8, (void *)achp_filter, imp_len_filter, iep_chs_filter );
    if (iml_filter == -1)
      // error, invalid string format...
      return LASN1_ERROR;

    achl_filter = (char *)m_aux_stor_alloc( this->aavo_hl_stor, iml_filter + 1 /*'\0'*/ );
    // translate filter string to UTF-8, if not yet...
    if (m_cpy_vx_vx_fl( (void *)achl_filter, iml_filter, ied_chs_utf_8,
                        (void *)achp_filter, imp_len_filter, iep_chs_filter,
                        D_CPYVXVX_FL_NOTAIL0 ) == -1)
      // error, invalid string format
      return LASN1_ERROR;

    *(achl_filter + iml_filter) = '\0';

    // the string is parsed...
    while (*achl_filter)
    {   // character parsing..
        switch (*achl_filter)
        {
          case '(':  // begin brace...
                     ++achl_filter;
                     ++iml_braces;
                     // skip spaces...
                     while (*achl_filter && isspace((unsigned char)*achl_filter))  ++achl_filter;
                     // parses the characters inside the braces...
                     switch (*achl_filter)
                     {
                       case '&':  // LASN1_FILTER_AND...
                                  achl_filter = this->m_put_complex_filter( achl_filter, LASN1_FILTER_AND );
                                  if (achl_filter == NULL)
                                  { // error!
                                    iml_rc = LASN1_ERROR;
                                    goto FILTER_DONE;
                                  }
                                  // after that the brace is closed
                                  --iml_braces;
                                  break;
                       case '|':  // LASN1_FILTER_OR...
                                  achl_filter = this->m_put_complex_filter( achl_filter, LASN1_FILTER_OR );
                                  if (achl_filter == NULL)
                                  { // error!
                                    iml_rc = LASN1_ERROR;
                                    goto FILTER_DONE;
                                  }
                                  // after that the brace is closed
                                  --iml_braces;
                                  break;
                       case '!':  // LASN1_FILTER_NOT...
                                  achl_filter = this->m_put_complex_filter( achl_filter, LASN1_FILTER_NOT );
                                  if (achl_filter == NULL)
                                  { // error!
                                    iml_rc = LASN1_ERROR;
                                    goto FILTER_DONE;
                                  }
                                  // after that the brace is closed
                                  --iml_braces;
                                  break;
                       case '(':  // two '(' without any link to AND, OR, ... is nor allowed!
                                  // error!
                                    iml_rc = LASN1_ERROR;
                                    goto FILTER_DONE;

                       default:   // all other characters...
                                  achl_next = this->m_find_filter_right_parent( achl_filter );
                                  // any errors found?
                                  if (achl_next == NULL)
                                  { // error!
                                    iml_rc = LASN1_ERROR;
                                    goto FILTER_DONE;
                                  }

                                  *achl_next = '\0';   // set temporary stop for the following routine
                                  iml_rc = this->m_put_simple_filter( achl_filter );
                                  if (iml_rc != LASN1_SUCCESS)
                                    // error!
                                    goto FILTER_DONE;

                                  // restore former character
                                  *achl_next = ')';
                                  ++achl_next;
                                  achl_filter = achl_next;
                                  --iml_braces;
                                  break;
                     } // end of inner switch()

                     break;  // end of case '('

          case ')':  // end brace...
                     iml_rc = this->m_printf( "]" );
                     if (iml_rc != LASN1_SUCCESS)
                       // error!
                       goto FILTER_DONE;

                     // step to the next character...
                       ++achl_filter;
                       --iml_braces;
                     
                     break;

          case ' ':  // ignore blank...
                     ++achl_filter;
                     break;

          default:  // assume it's a simple type=value filter...
                    achl_next = strchr( achl_filter, '\0' );
                    iml_rc = this->m_put_simple_filter( achl_filter );
                    if (iml_rc != LASN1_SUCCESS)
                      // error !
                      goto FILTER_DONE;

                      // step to the next filter substring
                      achl_filter = achl_next;
                    break;
        }

        if (!iml_braces)
          break;
    } // end of while()

    iml_rc = (iml_braces || *achl_filter) ? LASN1_ERROR : LASN1_SUCCESS;

FILTER_DONE:
    return iml_rc;

} // dsd_asn1::m_put_filter()


/**
 * private class function:  dsd_asn1::m_put_filter_list()
 *
 * puts a list of filters like this "(filter1)(filter2)...".
 *
 * @param[in]  achp_filter  filter string to search in
 * @param[in]  imp_tag      explicit tag to be set
 *
 * @return     \b LASN1_SUCCESS    if everything is OK or
 *             \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_filter_list( char *achp_filter, int imp_tag )
{
    char *achl_next  (NULL);
    char  chl_1;

    // parse filter string...
    while (*achp_filter)
    {   // skip spaces!
        while (*achp_filter && isspace((unsigned char)*achp_filter))  ++achp_filter;
        // end of string found?
        if (*achp_filter == '\0')
          break;
        // find next closing brace...
        achl_next = this->m_find_filter_right_parent( achp_filter + 1 );
        if (achl_next == NULL)
          return LASN1_ERROR;

        chl_1 = *++achl_next;
        // now we have "(filter)" with achp_filter pointing to it
        *achl_next = '\0';
        if (this->m_put_filter( achp_filter, -1 /*zero terminated*/, ied_chs_utf_8 ) == LASN1_ERROR)
          return LASN1_ERROR;
        // restore character replaced by '\0'
        *achl_next = chl_1;
        achp_filter = achl_next;

        if (imp_tag == LASN1_FILTER_NOT)
          break;
    } // end of while()

    if (imp_tag == LASN1_FILTER_NOT && (achl_next == NULL || *achp_filter))
      return LASN1_ERROR;

    return LASN1_SUCCESS;

} // dsd_asn1::m_put_filter_list()


/**
 * private class function:  dsd_asn1::m_put_simple_filter()
 *
 * constructs an ASN.1-coded filter.
 *
 * search filter format:   attribute operator value (e.g. cn=smith)
 *
 *     operator  description                            example
 *     -------------------------------------------------------------------------------
 *        =      returns entries whose attribute is     cn=John Smith finds the entry
 *               equal to the value                     with common name John Smith
 *
 *       >=      returns entries whose attribute is     sn>=smith finds all entries
 *               greater than or equal to the value     from smith to z*
 *
 *       <=      returns entries whose attribute is     sn<=smith finds all entries
 *               less than or equal to the value        from a* to smith
 *
 *       =*      returns entries that have a value      sn=* finds all entries that
 *               set for that attribute                 have the sn attribute
 *
 *       ~=      returns entries whose attribute value  sn~=smith might find the entry
 *               approximately matches the specified    "sn=smith"
 *               value. Typically, this is an algorithm
 *               that matches words that sound alike
 *
 *
 * @param[in]  achp_filter  filter string to search in (utf-8 format)
 *
 * @return     \b LASN1_SUCCESS    if everything is OK or
 *             \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_simple_filter( char *achp_filter )
{
    char  *achl_1;        // work variable
    char  *achl_value;    // points to the value of the filter attribute (after '=')
    char  *achl_wildcard; // points to a wild card character found (e.g. sn=*)
    char  *achl_filter;   // copy of the filter string (achp_filter)
    char  *achl_filter_rule (NULL);
    int    iml_ftype;
    int    iml_rc (LASN1_ERROR);


    // unfortunately, we have to copy the string (because of the OpenLDAP-routines!)
    int  iml_len_filter ((int)strnlen( (const char *)achp_filter, D_LDAP_MAX_STRLEN ));

    achl_filter = (char *)m_aux_stor_alloc( this->aavo_hl_stor, iml_len_filter + 1 );
    memcpy((void *)achl_filter, (const void *)achp_filter, iml_len_filter );
    *(achl_filter + iml_len_filter) = '\0';

    // search filter value (e.g. cn=hob)...
    achl_1 = strchr( achp_filter, '=' );
    if (achl_1 == NULL)
      goto SIMPLE_FILTER_DONE;

    achl_value = achl_1 + 1;  // points after the '='
    *achl_1  = '\0';          // separate the attribute
    --achl_1;                 // points before the '='

    // test for LE, GE, or something else...
    switch (*achl_1)
    {
       case '<':  // '<=' : lower or equal
                  iml_ftype = LASN1_FILTER_LE;      // save value and set end of string
                  *achl_1 = '\0';
                  break;
       case '>':  // '>=' : greater or equal
                  iml_ftype = LASN1_FILTER_GE;      // save value and set end of string
                  *achl_1 = '\0';
                  break;
       case '~':  // '~=' : approximately match
                  iml_ftype = LASN1_FILTER_APPROX;  // save value and set end of string
                  *achl_1 = '\0';
                  break;
       case ':':  // RFC2254 extensible filters are of the form:
                  // type [:dn][:rule] := value  or  [:dn]:rule := value
                  // e.g. "(uid:caseExactMatch:=HobUser)"
                  iml_ftype = LASN1_FILTER_EXT;     // save value and set end of string
                  *achl_1 = '\0';
                  // search filter 'type' and 'rule'...
                  achl_1 = strrchr( achp_filter, ':' );
                  if (achl_1)
                  { // 'matchingRule' found!
                    achl_filter_rule = achl_1 + 1;
                    *achl_1 = '\0';
                  }
                  break;
       default:   // simple filter processing
                  achl_wildcard = this->m_find_filter_wildcard( achl_value );
                  if (achl_wildcard == NULL )
                    // error
                    goto SIMPLE_FILTER_DONE;
                  else
                  { // have we reached the end?
                    if (*achl_wildcard == '\0')
                      // we assume, that's e.g. 'sn=hob'
                      iml_ftype = LASN1_FILTER_EQUALITY;
                    else
                    { // we assume, that's e.g. 'sn=*'
                      if (strncmp( achl_value, "*", D_LDAP_MAX_STRLEN ) == 0)
                        iml_ftype = LASN1_FILTER_PRESENT;
                      else
                      { // writes a filter string (e.g. sn=hob)...
                        iml_rc = this->m_put_substring_filter( achp_filter, achl_value );
                        goto SIMPLE_FILTER_DONE;
                      }
                    }
                  }
                  break;
    } // end of switch()

    if (iml_ftype == LASN1_FILTER_PRESENT)
      // writes the filter string (e.g. sn=*)
      iml_rc = this->m_printf( "ts",
                               iml_ftype /*t*/,
                               achp_filter, -1 /*zero terminated*/, int(ied_chs_utf_8) /*s*/ );
    else
    { // writes the filter string (e.g. sn=hob)
      int iml_len_value (this->m_put_filter_value_unescape( achl_value ));

      if (iml_len_value >= 0)
      {
        iml_rc = (iml_ftype == LASN1_FILTER_EXT) ? this->m_printf( "t{tststs}",
                                                                    iml_ftype /*t*/,
                                                                    LASN1_FILTER_EXT_MATCH /*t*/,
                                                                    achl_filter_rule, -1, int(ied_chs_utf_8),
                                                                    LASN1_FILTER_EXT_TYPE /*t*/,
                                                                    achp_filter, -1 /*zero terminated*/, int(ied_chs_utf_8) /*s*/,
                                                                    LASN1_FILTER_EXT_VALUE /*t*/,
                                                                    achl_value, iml_len_value, (int)ied_chs_utf_8 /*s*/ )
                                                 :  this->m_printf( "t{ss}",
                                                                    iml_ftype /*t*/,
                                                                    achp_filter, -1 /*zero terminated*/, int(ied_chs_utf_8) /*s*/,
                                                                    achl_value, iml_len_value, (int)ied_chs_utf_8 /*s*/ );
       }
    }

SIMPLE_FILTER_DONE:
    if (iml_rc != LASN1_ERROR)
      iml_rc = LASN1_SUCCESS;

    return iml_rc;

} // dsd_asn1::m_put_simple_filter()


/**
 * private class function:  dsd_asn1::m_put_substring_filter()
 *
 * puts a substring-filter like this "(cn=smith)...".
 *
 * @param[in]  achp_type  filter attribute string
 * @param[in]  achp_val   filter value string
 *
 * @return     \b LASN1_SUCCESS    if everything is OK or
 *             \b LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_substring_filter( char *achp_type, char *achp_val )
{
    char *achl_next;
    int   iml_len;
    int   iml_cnt   (0);    // wild card character count
    int   iml_ftype (LASN1_FILTER_SUBSTRINGS);

    // format a substring filter in ASN.1-syntax...
    if (this->m_printf( "t{s{",
                        iml_ftype /*t*/,
                        achp_type, -1 /*zero terminated*/, int(ied_chs_utf_8) /*s*/) == LASN1_ERROR)
      // asn.1 error
      return LASN1_ERROR;

    // step through the value string...
    for (; *achp_val; achp_val=achl_next)
    {  // search for a wild card character...
       achl_next = this->m_find_filter_wildcard( achp_val );
       // test the result pointer...
       if (achl_next == NULL)
         // nothing found, error
         return LASN1_ERROR;

       if  (*achl_next == '\0')
         // end of string reached
         iml_ftype = LASN1_SUBSTRING_FINAL;
        else
        { // further string processing ...
          *achl_next = '\0';   // set a temporary stop
          ++achl_next;
          if (!iml_cnt)
            iml_ftype = LASN1_SUBSTRING_INITIAL;
          else
            iml_ftype = LASN1_SUBSTRING_ANY;

          ++iml_cnt;  // counts all the wildcard characters
        }

        if (*achp_val != '\0' || iml_ftype == LASN1_SUBSTRING_ANY)
        {   iml_len = this->m_put_filter_value_unescape( achp_val );

            if (iml_len < 0)
              // error
              return LASN1_ERROR;

            if (this->m_printf( "ts",
                                iml_ftype /*t*/,
                                achp_val, iml_len, int(ied_chs_utf_8) /*s*/ ) == LASN1_ERROR)
              // asn.1 error
              return LASN1_ERROR;
        }
    } // end of for()

    // build ending sequence...
    if (this->m_printf( "}}" ) == LASN1_ERROR)
      // asn.1 error
      return LASN1_ERROR;

    return LASN1_SUCCESS;

} // dsd_asn1::m_put_substring_filter()


/**
 * private class function:  dsd_asn1::m_find_filter_right_parent()
 *
 * finds the ending ')' of the given filter string.
 *
 * @param[in]  achp_filter  filter string to search in
 *
 * @return     char*    pointer to position found or
 *          \b NULL     error, if not found before the string ends
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
char *dsd_asn1::m_find_filter_right_parent( char *achp_filter )
{
    int iml_bal  (1);  // we have found an open brace, before we have called this function
    int iml_esc  (0);  // no escape character found yet

    while (*achp_filter && iml_bal)
    {   // step over escape characters...
        if (!iml_esc)
        {
          if (*achp_filter == '(')
            ++iml_bal;     // another open brace found
          else
            if (*achp_filter == ')')
              --iml_bal;
        }
        // test for escape character...
        iml_esc = (*achp_filter == '\\' && !iml_esc);

        if (iml_bal)
          ++achp_filter;
    } // end of while()

    // 'open brace'-cnt != 'close brace'-count --> error
    return *achp_filter ? achp_filter : NULL;

} // dsd_asn1::m_find_filter_right_parent()


/**
 * private class function:  dsd_asn1::m_find_filter_wildcard()
 *
 * search for a wildcard ('*') in the value part of the filter string.
 *
 * @param[in]  achp_filter  filter string to search in
 *
 * @return     const char*   pointer to the value part of the filter or
 *          \b NULL          error, if not found before the string ends
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
char * dsd_asn1::m_find_filter_wildcard( const char *achp_filter )
{

    for (; *achp_filter != '\0'; ++achp_filter)
    {
       switch (*achp_filter)
       {
          case '*':  // found wildcard found!
                     return (char *)achp_filter;
          case '\\': // escape character handling...
                     if (achp_filter[1] == '\0')
                       return NULL;

                     // test for valid hex-values...
                       if (_ishex(achp_filter[1]) && _ishex(achp_filter[2]))
                         achp_filter += 2;   // step after the escape sequence
                       else
                       { switch (achp_filter[1])
                         {
                            case '*':  // allow RFC 1960 escapes
                            case '(':
                            case ')':
                            case '+':
                            case '/':
                            case ',':   // Ticket 29235
                                        break;
                            case '\\':  ++achp_filter;
                                        break;
                            default:    return NULL;
                         }
                       }
                     
          default:   break;
       } // end of switch()
    } // end of for()

    return (char *)achp_filter;

} // dsd_asn1::m_find_filter_wildcard()


/**
 * private class function:  dsd_asn1::m_put_filter_value_unescape()
 *
 * unescapes the value string if necessary. It supports both LDAPv2 and
 * LDAPv3 escapes.
 *
 * @param[in]  achp_val  filter value string
 *
 * @return     int             length of the filter value or
 *          \b LASN1_ERROR     if an error is detected
 *
 * Remarks:\n
 * The output can include null characters!\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
int dsd_asn1::m_put_filter_value_unescape( char *achp_val )
{
    int  iml_1, iml_2;         // working variables
    int  iml_val_1, iml_val_2;

    for (iml_1=iml_2=0; achp_val[iml_1] != '\0'; ++iml_1)
    {
        switch (achp_val[iml_1])
        {
          case '*':   // invalid character, error...
                      return LASN1_ERROR;
          case '\\':  // 'escape '-character
                      ++iml_1;
                      if (achp_val[iml_1] == '\0')
                        // escape at end of string
                        return LASN1_ERROR;

                      // determine the type of LDAP escape...
                        if ((iml_val_1 = dsd_ldap::m_hex2value(achp_val[iml_1])) >= 0)
                        { // LDAPv3 escape...
                          if ((iml_val_2 = dsd_ldap::m_hex2value(achp_val[iml_1+1])) < 0)
                            //error, must be two digit code
                            return LASN1_ERROR;

                          achp_val[iml_2++] = (char)(iml_val_1*16 + iml_val_2);
                          ++iml_1;
                        }
                        else
                        { // LDAPv2 escape (do not convert this!)...
                          switch (achp_val[iml_1])
                          {
                            case '(':
                            case ')':
                            case '*':
                            case '+':
                            case '/':
                            case ',':   // Ticket 29235
                                        achp_val[iml_2++] = '\\';
                                        achp_val[iml_2++] = achp_val[iml_1];
                                        break;
                            case '\\':  achp_val[iml_2++] = achp_val[iml_1];
                                        break;
                            default:    // illegal escape...
                                        return LASN1_ERROR;
                          }
                        }
                      
                      break;

          default:    // copy normal character...
                      achp_val[iml_2++] = achp_val[iml_1];
                      break;
        } // end of outer switch()
    } // end of for()

    achp_val[iml_2] = '\0';

    return iml_2;

} // dsd_asn1::m_put_filter_value_unescape()


/**
 * private class function:  dsd_asn1::m_get_element()
 *
 * gets a new initiated element to build an ASN.1-TLV.
 *
 * @return     struct dsd_elem_1 *   pointer to a fresh element
 *
 * Remarks:\n
 * The caller is responsible for the input parameters. They are not tested for validity.
 */
dsd_asn1::dsd_elem_1 *dsd_asn1::m_get_element()
{
    // search the last element in the chain of the actual sequence...
    struct dsd_asn1::dsd_elem_1  *adsl_elem_1 (this->ads_seqof_act->adsc_elem);

    // 1. elements are already chained, so look for the end...
    if (adsl_elem_1)
    { // search the end of the element chain...
      while (adsl_elem_1->adsc_next)
           adsl_elem_1 = adsl_elem_1->adsc_next;
      // allocate a new one...
      adsl_elem_1->adsc_next = (dsd_asn1::dsd_elem_1 *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                                         sizeof(dsd_asn1::dsd_elem_1) );
      // initiate the new element
      memset( (void *)adsl_elem_1->adsc_next, int(0), sizeof(dsd_asn1::dsd_elem_1) );
      adsl_elem_1->adsc_next->adsc_seqof = adsl_elem_1->adsc_seqof;      // set parent sequenceOf-structure address

      return adsl_elem_1->adsc_next;
    }

    // 2. no elements are allocated yet
    this->ads_seqof_act->adsc_elem = (dsd_asn1::dsd_elem_1 *)m_aux_stor_alloc( this->aavo_hl_stor, 
                                                                               sizeof(dsd_asn1::dsd_elem_1) );
      // initiate the new element
      memset( (void *)this->ads_seqof_act->adsc_elem, int(0), sizeof(dsd_asn1::dsd_elem_1) );
      this->ads_seqof_act->adsc_elem->adsc_seqof = this->ads_seqof_act;  // set parent sequenceOf-structure address

      return this->ads_seqof_act->adsc_elem;

} // dsd_asn1::m_get_element()



/*+---------------------------------------------------------------------------------------------+*/
/*| helper functions ...                                                                        |*/
/*+---------------------------------------------------------------------------------------------+*/
int m_hl_inet_ntop4( const unsigned char *, char *, int );
int m_hl_inet_ntop6( const unsigned char *, char *, int );

/**
 *  m_hl_inet_ntop() - Convert an ipv4/ipv6-address to presentation format.
 *
 *  The function converts an ipv4/ipv6 - network address into a ASCII string in
 *  internet standard format.
 *  AF_INET:    ddd.ddd.ddd.ddd
 *  AF_INET6:   xxxxxxxxxxxxx
 *
 *  @param[in]      adsp_soa        network address structure:
 *                                  struct in_addr  (AF_INET)
 *                                  struct in6_addr (AF_INET6)
 *  @param[in,out]  achrp_ipaddr    ip-address buffer
 *  @param[in,out]  inp_len_ipaddr  maximum length of ip-address buffer
 *
 *  @return   \b 0                  if successful, else an error is happened,
 *            \b EOPNOTSUPP         invalid address format,
 *            \b EAFNOSUPPORT       invalid address family or
 *            \b ENOBUFS            converted address or port would exceed 'inl_len_...'
 *
 *  comment:  This is based on the official BSD source of 'inet_ntop()'.
 */
int m_hl_inet_ntop( struct sockaddr_storage *adsp_soa, char *achrp_ipaddr, int inp_len_ipaddr )
{
   // valid parameter?
   if (adsp_soa && achrp_ipaddr)
   {
     // check address family
     switch (adsp_soa->ss_family)
     {
       case AF_INET:   /* format: ddd.ddd.ddd.ddd */
#if defined WIN32 || defined WIN64
                       return m_hl_inet_ntop4( (const unsigned char *)&((struct sockaddr_in *)adsp_soa)->sin_addr.S_un.S_un_b.s_b1,
                                               achrp_ipaddr, inp_len_ipaddr );
#elif defined HL_UNIX
                       return m_hl_inet_ntop4( (const unsigned char *)&((struct sockaddr_in *)adsp_soa)->sin_addr.s_addr,
                                               achrp_ipaddr, inp_len_ipaddr );
#endif
       case AF_INET6:  /* format: ffff:ffff:...:ddd.ddd.ddd.ddd */
#if defined WIN32 || defined WIN64
                       return m_hl_inet_ntop6( (const unsigned char *)((struct sockaddr_in6 *)adsp_soa)->sin6_addr.u.Byte,
                                               achrp_ipaddr, inp_len_ipaddr );
#elif defined HL_UNIX
                       return m_hl_inet_ntop6( (const unsigned char *)((struct sockaddr_in6 *)adsp_soa)->sin6_addr.s6_addr,
                                               achrp_ipaddr, inp_len_ipaddr );
#endif
                       /* format: unknown */
       default:        break;
     } // end of switch
   } // valid parameter

   return EAFNOSUPPORT;

} /* m_hl_inet_ntop() */


/**
 *  m_hl_inet_ntop4() - Convert an ipv4-address to presentation format.
 *
 *  The function converts an ipv4 - network address into a ASCII string in
 *  internet standard format.
 *  AF_INET:    ddd.ddd.ddd.ddd
 *
 *  @param[in]  achrp_src    ipv4 network address
 *  @param[out] achrp_dst    ASCII output buffer
 *  @param[in]  inp_len_dst  maximum ASCII output buffer length
 *
 *  @return   \b 0             if successful, else an error has happened,
 *            \b EOPNOTSUPP    invalid address format,
 *            \b EAFNOSUPPORT  invalid address family or
 *            \b ENOBUFS       converted address or port would exceed 'inl_len_...'
 *
 *  comment:  This is based on the official BSD source of 'inet_ntop()'.
 */
int m_hl_inet_ntop4( const unsigned char *achrp_src, char *achrp_dst, int inp_len_dst )
{
   char chrl_ineta[sizeof "255.255.255.255\0"];
   int  inl_1 = m_hlsnprintf( chrl_ineta, sizeof(chrl_ineta), ied_chs_utf_8, "%u.%u.%u.%u", achrp_src[0], achrp_src[1], achrp_src[2], achrp_src[3] );

   if (inl_1 <= 0 || inl_1 >= int(inp_len_dst))
     // buffer isn't sufficient
     return ENOBUFS;

   memcpy(achrp_dst, (const void *)chrl_ineta, inl_1 + 1/*'\0'*/ );
   return 0;

} /* m_hl_inet_ntop4() */


/**
 *  m_hl_inet_ntop6() - Convert an ipv6-address to presentation format.
 *
 *  The function converts an ipv4/ipv6 - network address into a ASCII string in
 *  internet standard format.
 *  AF_INET6:   xxxxxxxxxxxxx
 *
 *  @param[in]  achrp_src    ipv6 network address
 *  @param[out] achrp_dst    ASCII output buffer
 *  @param[out] inp_len_dst  maximum ASCII output buffer length
 *
 *  @return   \b 0             if successful, else an error is happened,
 *            \b EOPNOTSUPP    invalid address format,
 *            \b EAFNOSUPPORT  invalid address family or
 *            \b ENOBUFS       converted address or port would exceed 'inl_len_...'
 *
 *  comment:  This is based on the official BSD source of 'inet_ntop()'.
 */
int m_hl_inet_ntop6( const unsigned char *achrp_src, char *achrp_dst, int inp_len_dst )
{
   char  chrl_ineta[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255\0"];
   char *achrl_tp, *achrl_ep;
   int   inl_adv, inl_1;
   struct { int inc_base, inc_len; } dsl_best, dsl_cur;
   unsigned int uml_blocks[8];

   /* Preprocess:
    *   Copy the input (bytewise) array into a wordwise array.
    *   Find the longest run of 0x00's in src[] for :: shorthanding */
   memset( (void *)uml_blocks, int('\0'), sizeof(uml_blocks) );
   for (inl_1=0; inl_1 < 16; ++inl_1)
      uml_blocks[inl_1 / 2] |= (achrp_src[inl_1] << ((1 - (inl_1 % 2)) << 3));

   dsl_best.inc_base = dsl_cur.inc_base = -1;
   dsl_best.inc_len  = dsl_cur.inc_len  = 0;

   for (inl_1=0; inl_1 < 8; ++inl_1)
   {
      if (uml_blocks[inl_1] == 0)
      { if (dsl_cur.inc_base == -1)
          dsl_cur.inc_base = inl_1, dsl_cur.inc_len = 1;
        else
          ++dsl_cur.inc_len;
      }
      else
      { if (dsl_cur.inc_base != -1)
        { if (dsl_best.inc_base == -1 || dsl_cur.inc_len > dsl_best.inc_len)
            dsl_best = dsl_cur;

          dsl_cur.inc_base = -1;
      } }
    } // for()

    if (dsl_cur.inc_base != -1)
    { if (dsl_best.inc_base == -1 || dsl_cur.inc_len > dsl_best.inc_len)
        dsl_best = dsl_cur;
    }
    if (dsl_best.inc_base != -1 && dsl_best.inc_len < 2)
      dsl_best.inc_base = -1;

    /* format the result... */
    achrl_tp = chrl_ineta;
    achrl_ep = chrl_ineta + sizeof(chrl_ineta) - 1;
    for (inl_1=0; inl_1 < 8 && achrl_tp < achrl_ep; ++inl_1)
    {  /* are we inside the best run of 0x00's? */
       if (dsl_best.inc_base != -1 && inl_1 >= dsl_best.inc_base && inl_1 < (dsl_best.inc_base + dsl_best.inc_len))
       { if (inl_1 == dsl_best.inc_base)
         { if (achrl_tp + 1 >= achrl_ep)
             return EOPNOTSUPP;
           *achrl_tp++ = ':';
         }
         continue;
       }
       /* are we following an initial run of 0x00s or any real hex? */
       if (inl_1)
       { if (achrl_tp + 1 >= achrl_ep)
           return EOPNOTSUPP;
          *achrl_tp++ = ':';
       }
       /* is this address an encapsulated IPv4? */
       if (inl_1 == 6 && dsl_best.inc_base == 0 &&
           (dsl_best.inc_len == 6 || (dsl_best.inc_len == 5 && uml_blocks[5] == 0xffff)))
       { if (!m_hl_inet_ntop4( achrp_src+12, achrl_tp, int(achrl_ep - achrl_tp)))
           return EOPNOTSUPP;
         achrl_tp += (int)strnlen( achrl_tp, D_LDAP_MAX_STRLEN );
         break;
       }
       inl_adv = m_hlsnprintf( achrl_tp, int(achrl_ep - achrl_tp), ied_chs_utf_8, "%x", uml_blocks[inl_1] );
       if (inl_adv <= 0 || inl_adv >= achrl_ep - achrl_tp)
         return EOPNOTSUPP;
       achrl_tp += inl_adv;
    } // for()
    /* was it a trailing run of 0x00's? */
    if (dsl_best.inc_base != -1 && (dsl_best.inc_base + dsl_best.inc_len) == 8)
    { if (achrl_tp + 1 >= achrl_ep)
        return EOPNOTSUPP;
      *achrl_tp++ = ':';
    }
    if (achrl_tp + 1 >= achrl_ep)
      return EOPNOTSUPP;

    *achrl_tp++ = '\0';

    /* check for overflow, copy, and we're done. */
    if (size_t(achrl_tp - chrl_ineta) > size_t(inp_len_dst))
    { // not enough storage...
      return ENOBUFS;
    }

    memcpy(achrp_dst, (const void *)chrl_ineta, inp_len_dst );
    return 0;

} /* m_hl_inet_ntop6() */



/**
 *  dsd_ldap_schema::m_htree1_avl_compare() - Callback routine for comparing tree entries.
 *
 *  The function compares entries using different criteria.
 *
 *  @param[in]  avop_userfld       htree user field structure
 *  @param[in]  adsp_htree_elem_1  first element to compare
 *  @param[in]  adsp_htree_elem_2  second element to compare
 *
 *  @return   \b -1   the second element is longer,
 *            \b  1   the first element is longer or
 *            \b  0   the elements are equal
 */
int dsd_ldap_schema::m_htree1_avl_compare( void *avop_userfld,
                                           struct dsd_htree1_avl_entry *adsp_htree_elem_1,
                                           struct dsd_htree1_avl_entry *adsp_htree_elem_2 )
{
   struct dsd_avl_schema_attr *adsl_schema_attr_1 ((struct dsd_avl_schema_attr *)((char *)adsp_htree_elem_1 - offsetof(dsd_avl_schema_attr, dsc_htree1)));
   struct dsd_avl_schema_attr *adsl_schema_attr_2 ((struct dsd_avl_schema_attr *)((char *)adsp_htree_elem_2 - offsetof(dsd_avl_schema_attr, dsc_htree1)));

   // compare the attribute names only if both lengths are equal
   if (adsl_schema_attr_1->imc_len_val == adsl_schema_attr_2->imc_len_val)
   { return m_hl_memicmp( adsl_schema_attr_1->ac_val,
                          adsl_schema_attr_2->ac_val,
                          adsl_schema_attr_1->imc_len_val );
   }

   if (adsl_schema_attr_1->imc_len_val > adsl_schema_attr_2->imc_len_val)
     return 1;   // the first element is greater

     return -1;  // the second element is greater

} // dsd_ldap_schema::m_htree1_avl_compare()


/**
 *  m_hl_memicmp() - Replacement for _memicmp() in a Linux-environment.
 *
 *  The function compares entries ignoring their case.
 *
 *  @param[in]  avop_buf1   first buffer
 *  @param[in]  avop_buf2   second buffer
*   @param[in]  imp_count   number of characters to compare
 *
 *  @return   \b  -1  avop_buf1 less than avop_buf2
 *            \b   0  both buffers are equal
 *            \b   1  avop_buf1 greater than avop_buf2
 */
int m_hl_memicmp( const void *avop_buf1, const void *avop_buf2, int imp_count )
{
   int  imp_result (-1);

   m_cmpi_vx_vx( &imp_result,
                 avop_buf1, imp_count, ied_chs_utf_8,
                 avop_buf2, imp_count, ied_chs_utf_8 );
   return imp_result;

} // m_hl_memicmp()


// we need some functions in environments outside the WebSecureProxy
#if (defined WIN32 || defined WIN64) && !defined IBIPGW08 && !defined DEF_HCU2
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/* writes a string to the console
 *
 * Note: this is a copied from ibipgw08.cpp
 */
extern "C" int m_hl1_printf( char *aptext, ... )
{
  va_list    dsl_argptr;
  int        iml1;
  HL_WCHAR   wcrl_out1[512 * sizeof(HL_WCHAR)];

  va_start( dsl_argptr, aptext );
  iml1 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1), ied_chs_ansi_819, aptext, dsl_argptr );

  if (iml1 > 0)
  {
    *((char *)wcrl_out1 + iml1)     = '\n';
    *((char *)wcrl_out1 + iml1 + 1) = 0;
  }
  cout << (char *)wcrl_out1;

  va_end( dsl_argptr );
  return iml1;

} // end m_hl1_printf()


/* writes a string to the console
 *
 * Note: this is a copied from ibipgw08.cpp:
 */
extern "C" int m_hlnew_printf( int imp_type, char *aptext, ... )
{
  va_list    dsl_argptr;
  int        iml1;
  HL_WCHAR   wcrl_out1[512 * sizeof(HL_WCHAR)];

  va_start( dsl_argptr, aptext );
  iml1 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1) - 2, ied_chs_ansi_819, aptext, dsl_argptr );

  if (iml1 > 0)
  {
    *((char *) wcrl_out1 + iml1)     = '\n';
    *((char *) wcrl_out1 + iml1 + 1) = 0;
  }
  cout << (char *)wcrl_out1;

  va_end( dsl_argptr );
  return iml1;

} // end m_hlnew_printf()


/* returns a number between zero and impmax minus one
 *
 * Note: this is a copied from ibipgw08.cpp
 */
extern "C" int m_get_random_number( int impmax )
{
   HL_LONGLONG ill_1  = (HL_LONGLONG)rand() * impmax;
               ill_1 /= RAND_MAX + 1;
   return (int)ill_1;

} // m_get_random_number()

#endif // !IBIPGW08, !DEF_HCU2

/*************************************************************************************************
 * end of 'xsldap01.cpp'
 *************************************************************************************************/
