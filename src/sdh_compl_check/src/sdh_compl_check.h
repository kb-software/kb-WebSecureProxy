#ifndef _SDH_COMPL_CHECK_H
#define _SDH_COMPL_CHECK_H

/*+---------------------------------------------------------------------+*/
/*| history:                                                            |*/
/*+---------------------------------------------------------------------+*/
/*
     V      | Date     | A. | Description
    ========+==========+====+===============================================
    2.3.0.5 | 06.07.10 | MJ | changed configuration: we will read the checks
            |          |    | without knowledge of their content, cause they
            |          |    | are just forwarded to java client
    --------+----------+----+-----------------------------------------------
    2.3.0.4 |          | MJ | moved to Xerces 3.1
    --------+----------+----+-----------------------------------------------
    0.*     |          | MJ | First testing versions
*/

/*+---------------------------------------------------------------------+*/
/*| version:                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <sdh_version.h>

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define SDH_STORAGE_SIZE   16* 1024   // default storage container size

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
#define HL_COMP_CHECK_INTEGRITY     1
#define HL_COMP_CHECK_AST           2
#define HL_COMP_CHECK_RULE          4

struct dsd_compl_check {
    char*               achc_name;          // name
    int                 inc_len_name;       // length of name
    char*               achc_str_xml;       // compliance check as xml string
    int                 inc_len_xml;        // length of xml string
    int                 inc_checks;         // integrated checks
    dsd_compl_check*    adsc_next;          // next compliance check
};

typedef struct dsd_sdh_config {
    dsd_sdh_log_t       ds_log;             // log settings (must be frist element!)
    dsd_compl_check*    ads_check;          // compliance check list
} dsd_sdh_config_t;

#endif // _SDH_COMPL_CHECK_H


