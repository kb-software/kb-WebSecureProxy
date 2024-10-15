#ifndef HOBWSPAT_H
#define HOBWSPAT_H

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define AT_LONGNAME    "HOB Authentication Library"
#define AT_SHORTNAME   "HOBWSPAT"
#define AT_SHORTCUT    "AT3"
#define AT_VERSION     "2.3.3.0"

#ifdef HL_UNIX
    #define LOGFILE_PATH          "../log/"
#else
    #define LOGFILE_PATH          "..\\log\\"
#endif

/*+---------------------------------------------------------------------+*/
/*| default settings:                                                   |*/
/*+---------------------------------------------------------------------+*/
#define AT_DEF_LOG_FILE        AT_SHORTCUT".log"
#define AT_DEF_MAX_LEN_PROTO   64
#define AT_DEF_MAX_LEN_USER    256
#define AT_DEF_MAX_LEN_PWD     256
#define AT_DEF_MAX_LEN_SERVER  256

/*+---------------------------------------------------------------------+*/
/*| configuration structures:                                           |*/
/*+---------------------------------------------------------------------+*/

/*
    IMPORTANT: dsd_wspat_public_config must ALWAYS be 
    first element behind the key !!!
*/
struct dsd_wspat_config {
    dsd_sdh_log_t           ds_log;             // log settings (must be frist element!)
    dsd_wspat_public_config ds_public;          // public configuration for all datahooks
    int                     in_maxlenproto;     // max length of protocol string
    int                     in_maxlenuser;      // max length of user name
    int                     in_maxlenpwd;       // max length of password
    int                     in_maxlenserver;    // max length of server name
};
#endif  // HOBWSPAT_H
