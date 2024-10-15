//-------------------------------------------------------------------------------
// settings which are used by more than one project inside the RD-VPN-solution //
//-------------------------------------------------------------------------------

#ifndef RDVPN_GLOBALS_H
#define RDVPN_GLOBALS_H

#define SM_USE_CERT_AUTH      1     // Enable certificate authentication
#define SM_USE_CERT_AUTH_V2   (SM_USE_CERT_AUTH && 1)
#define SM_USE_QUICK_LINK	  1
#define SM_USE_VIRTUAL_LINK	1
#define SM_USE_AUX_PIPE_STREAM	1
#define SM_USE_HOBLAUNCH_REDIRECT 1

#define START_ITEM_COUNT_CMA  100   // count of (cookie-)items, which will be stored in CMA
#define IDENT_HOBWSP_COOKIE   "HOBWSP_SID"   // HOB's cookie name; note: no trailing '='

#include <align.h>

// return values:
#define SUCCESS 0  // Return value, if all is ok

#define LDAP_USER_MUST_CHANGE_PW  773  // Speciqal return value, when LDAP server requests, that the user must change its password.

// Inherit modes. How sdh_ea_ldap will collect files.
enum ied_inherit_modes {
    ien_inh_mode_none    =  0x0,
    ien_inh_mode_tree    =  0x1,
    ien_inh_mode_group   =  0x2,
    ien_inh_mode_both    =  0x3   // default
};

enum ied_troolean {
	ied_undefined = 0,
	ied_false = -1,
	ied_true = 1,
};

#define HL_TROOLEAN_TO_BOOL(t, d) ((t != ied_undefined) ? (t != ied_false) : d)

// states of a session
#define ST_OCCUPIED                             1
#define ST_FREE_CMA                             2  
#define ST_CHALLENGE_IN_PROGRESS                4
#define ST_AUTHENTICATED                        8
#define ST_KICK_OUT                            16
#define ST_KICKED_OUT                          32
#define ST_SHORT_HF_SERVER                     64
#define ST_HTTP_COOKIE_SENT                   128
#define ST_HTTP_COOKIE_ENABLED                256
#define ST_ACCEPTED                           512
//#define ST_PURE_GET_SLASH                    1024   // Ticket[16829]
#define ST_COMPLCHECK_FORCE                  2048
#define ST_COMPLCHECK_ERROR                  4096
#define ST_COMPLCHECK_SUCCESS                8192
#define ST_COMPLCHECK_INSTALL               16384
#define ST_COMPLCHECK_INTEGRITY             32768
#define ST_COMPLCHECK_AST                   65536
#define ST_COMPLCHECK_RULE                 131072
#define ST_FORCE_SSA_PAGE                  262144 // MJ 07.07.2010: force site-after-auth page
#define ST_CHANGE_PASSWORD                 524288 // MH 08.07.2010: change password

#define INT_ERR_COOKIE_EXPIRED  -31  // JF 08.03.07 Ticket[12133]

#define PT_VERS_1    1
#define WSP_VERSION_PREFIX    "HOB WebSecureProxy V"

#define HOB_MIN(a,b) ((a)>(b)?(b):(a))

//JF 25.06.07 moved to rdvpn_globals.h   
#define CNF_NODE_SETTINGS               "settings"
#define CNF_NODE_FLAGS                  "flags"

// log
#define CNF_NODE_LOG                    "log"
#define CNF_NODE_LOG_FILE               "file"
#define CNF_NODE_LOG_ENABLE             "enable"
#define CNF_NODE_LOG_LEVEL              "level"

#define LEN_ATTR                    256  // len of an RADIUS attribute
#define MAX_STATE    250

#define PROTO_HTTP   0
#define PROTO_HTTPS  1

// Ticket[14903]
#define STRING_YES           "YES"
#define STRING_NO            "NO"
#define INT_YES              1
#define INT_NO               2 // NO is not 0, because we want to signal, that 'NO' was read in

#define HL_RDVPN_LEN_SESSTICKET	32

struct dsd_aux_ident_session_info {
	char chrc_session_ticket[HL_RDVPN_LEN_SESSTICKET];
	unsigned char ucc_session_no;
};

#endif  // RDVPN_GLOBALS_H
