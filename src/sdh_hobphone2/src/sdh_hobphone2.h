#ifndef _SDH_HOBPHONE2_H
#define _SDH_HOBPHONE2_H

/*+---------------------------------------------------------------------+*/
/*| version:                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <sdh_version.h>

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
/* the maximum length of a UDP gateway name */
const int im_max_udp_gatway_name_length = 255;
/* the maximum number of channels */
const int im_max_channel_count = 64;
/* the maximum number of sip accounts */
const int im_max_account_count = 5;
/* the size of a receive buffer */
const int im_max_buffer_size = 16384;

/*+---------------------------------------------------------------------+*/
/*| configuration structures:                                           |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_sdh_addressbook_config {
    /* the next config or NULL */
    dsd_sdh_addressbook_config *ads_next;
    /* the name of the configuration */
    char *ach_name;
    int im_name_len;
    /* the type fo the addressbook */
    char *ach_type;
    int im_type_len;
    /* the url to connect to */
    char *ach_url;
    int im_url_len;
    /* authentication mode */
    char *ach_authentication_mode;
    int im_authentication_mode_len;
    /* username */
    char *ach_username;
    int im_username_len;
    /* the connection mode */
    char *ach_connection_mode;
    int im_connection_mode_len;
    /* the gate url */
    char *ach_gate_url;
    int im_gate_url_len;
    /* the gate username */
    char *ach_gate_username;
    int im_gate_username_len;
    /*The associated domain*/
    char *ach_domain;
    int im_domain_len;
} dsd_sdh_addressbook_config_t;

typedef struct dsd_sdh_config {
    /* the log - must be first element */
    dsd_sdh_log_t ds_log;
    /* the name of the default UDP gw to use or NULL */
    char *ach_udp_gw_name;
    /* the length of the UDP gw name or 0 */
    int im_udp_gw_name_len;
    /* The maximum time (milliseconds) for a test packet before udp gate is disabled. */
    long il_udp_gate_timeout;
    /* The time between two keep-alive packets for the udp gate in seconds. */
    long im_udp_gate_keepalive;
    /* The time between two keep-alive packets for the TCP keepalive in millseconds. */
    long im_tcp_keepalive;
    bool bo_client_timeout_priority;
    bool bo_allowlocalpass;
    bool bo_qualifyreply;
    bool bo_notifyreply;
    bool bo_sipautoreply;
    int im_reload_timeout;
    /* the linked list of addressbook configs or NULL if none present */
    dsd_sdh_addressbook_config *ads_addressbook_config;
} dsd_sdh_config_t;

#endif // _SDH_HOBPHONE2_H


