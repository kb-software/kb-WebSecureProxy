#ifndef _SDH_EXAMPLE_H
#define _SDH_EXAMPLE_H

/*+---------------------------------------------------------------------+*/
/*| version:                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <sdh_version.h>

/*+---------------------------------------------------------------------+*/
/*| history:                                                            |*/
/*+---------------------------------------------------------------------+*/
/*
     V      | Date     | A. |   Description
    ========+==========+====+==============================================
    2.3.0.2 |          | MJ | moved to Xerces 3.1
    0.*     |          | MJ | First testing versions
*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SDH_INFO(x)     "H"SDH_SHORTCUT"I%03dI: %s", x
#define SDH_WARN(x)     "H"SDH_SHORTCUT"W%03dW: %s", x
#define SDH_ERROR(x)    "H"SDH_SHORTCUT"E%03dE: %s", x

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
typedef struct dsd_sdh_config {
    dsd_sdh_log_t ds_log;           // log settings (must be frist element!)
} dsd_sdh_config_t;

#endif // _SDH_EXAMPLE_H


