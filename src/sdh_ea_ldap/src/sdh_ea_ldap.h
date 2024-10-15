#ifndef SDH_EA_LDAP_H
#define SDH_EA_LDAP_H

/*+---------------------------------------------------------------------+*/
/*| version:                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <sdh_version.h>

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

#define LEN_EA_HEADER   28  // Length in bytes of the EA protocol header
#define EA_VERSION    3600  // Gives the version of the (simulated) EA Server

#define SDH_STORAGE_SIZE   32 * 1024   // default storage container size

#ifdef HL_UNIX
    #define LOGFILE_PATH          "../log/"
#else
    #define LOGFILE_PATH          "..\\log\\"
#endif

/*+---------------------------------------------------------------------+*/
/*| default settings:                                                   |*/
/*+---------------------------------------------------------------------+*/
#define SDH_DEF_LOG_FILE    "SDH"SDH_SHORTCUT".log"

/*+---------------------------------------------------------------------+*/
/*| configuration structures:                                           |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_ea_config {
    dsd_sdh_log_t ds_log;           // log settings (must be first element!)
    int           in_inherit_mode;  // inheritance mode
    char          *achc_rpath;      // reload path
    int           inc_len_rpath;    // length of reload path
    char          *achc_dom_admin_rdn;      //rdn of the domainadministrator-group
    int           inc_len_dom_admin_rdn;    //length of rdn of the domainadministrator-group
    bool          boc_domadmin_create;      //auto-creation of the domainadministrator-group
} dsd_ea_config_t;

#endif // SDH_EA_LDAP_H


