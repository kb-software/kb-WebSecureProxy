#ifndef _HOB_POSTPARAMS_H
#define _HOB_POSTPARAMS_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| FILE:                                                                   |*/
/*| =====                                                                   |*/
/*|   hob-postparams.h                                                      |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this file holds all possible post params for our template pages       |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   July 2009                                                             |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define POST_LANG               "language"
#define POST_DEL_COOKIE         "rm-cookie"
#define POST_LOGOUT_USR         "logout-usr"
#define POST_CHANGE_PWD_NOW     "change-password-now"
#define POST_CHANGE_PWD_LATER   "change-password-later"

#define PARAM_SET_TASK      "task"
#define PARAM_WSG_BMARK     "wsg-bookmark"
#define PARAM_RDVPN_BMARK     "rdvpn-bookmark"
#define PARAM_WFA_BMARK     "wfa-bookmark"
#define PARAM_BMARK_NAME    "bmark-name"
#define PARAM_BMARK_URL     "bmark-url"
#define PARAM_SAVE_LANG     "save-lang"
#define PARAM_WSG_FLYER     "wsg-flyer"
#define PARAM_DEFAULT_PORTLET   "default-portlet"
#define PARAM_DOD_WSTAT     "workstation"
#define PARAM_WSTAT_NAME    "wstat-name"
#define PARAM_WSTAT_INETA   "wstat-ineta"
#define PARAM_WSTAT_PORT    "wstat-port"
#define PARAM_WSTAT_MAC     "wstat-mac"
#define PARAM_WSTAT_TOUT    "wstat-timeout"
#define PARAM_PORTLET       "portlet"
#define PARAM_PORTLET_STATE "portlet-state"
#define PARAM_PORTLET_POS   "portlet-position"

#define PARAM_EDIT_SETT     "edit"

/*
    post parameters:
*/
static const dsd_const_string ach_tmp_post_params[] = {
    POST_LANG,
    POST_LOGOUT_USR,
    POST_CHANGE_PWD_NOW,
    POST_CHANGE_PWD_LATER,
    "domain",
    "path",
    "name",
    POST_DEL_COOKIE,
};

enum ied_tmp_post_params {
    ied_post_language,
    ied_post_logout_usr,
    ied_post_change_pwd_now,
    ied_post_change_pwd_later,
	ied_post_cookie_domain,
	ied_post_cookie_path,
	ied_post_cookie_name,
    ied_post_rm_cookie,
};

/*
    settings parameter keys
*/
static const dsd_const_string ach_settings_params[] = {
    PARAM_SET_TASK,
    PARAM_WSG_BMARK,
    PARAM_RDVPN_BMARK,
    PARAM_WFA_BMARK,
    PARAM_BMARK_NAME,
    PARAM_BMARK_URL,
    PARAM_SAVE_LANG,
    PARAM_WSG_FLYER,
    PARAM_DOD_WSTAT,
    PARAM_WSTAT_NAME,
    PARAM_WSTAT_INETA,
    PARAM_WSTAT_PORT,
    PARAM_WSTAT_MAC,
    PARAM_WSTAT_TOUT,
    PARAM_PORTLET,
    PARAM_PORTLET_STATE,
    PARAM_PORTLET_POS,
    PARAM_DEFAULT_PORTLET
};

enum ied_settings_params {
    ied_set_task,
    ied_set_wsg_bmark,
    ied_set_rdvpn_bmark,
    ied_set_wfa_bmark,
    ied_set_bmark_name,
    ied_set_bmark_url,
    ied_set_save_lang,
    ied_set_wsg_flyer,
    ied_set_dod_wstat,
    ied_set_wstat_name,
    ied_set_wstat_ineta,
    ied_set_wstat_port,
    ied_set_wstat_mac,
    ied_set_wstat_tout,
    ied_set_portlet,
    ied_set_portlet_state,
    ied_set_portlet_pos,
    ied_set_default_portlet
};

/*
    settings task keys
*/
static const dsd_const_string ach_settings_tasks[] = {
    PARAM_EDIT_SETT
};

enum ied_settings_tasks {
    ied_set_task_unset = -1,
    ied_set_task_edit  =  0
};

#endif //_HOB_POSTPARAMS_H
