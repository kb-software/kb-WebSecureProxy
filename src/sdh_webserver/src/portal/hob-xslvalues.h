#ifndef DEF_HOB_XSLVALUES_V2_H
#define DEF_HOB_XSLVALUES_V2_H

/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| FILE:                                                                   |*/
/*| =====                                                                   |*/
/*|   hob-xslvalues.h                                                       |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this file holds all possible xsl values                               |*/
/*|   these values are organised in groups                                  |*/
/*|                                                                         |*/
/*|   we are supporting:                                                    |*/
/*|         a chain group/subgroup/subsubgroup                              |*/
/*|         up to 99 subgroups per group                                    |*/
/*|         and up to 99 values per group                                   |*/
/*|   for limitations, have a look at enum ied_xslvalue                     |*/
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
/*| ==========                                                              |*/
/*|                                                                         |*/
/*| Overhaul                                                                |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| ==========                                                              |*/
/*|    March 2017                                                           |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|    created direct connection between string value and enum value        |*/
/*|                                                                         |*/
/*|    removed limits for groups and subgroups                              |*/
/*|                                                                         |*/
/*|    reduced chance to introduce new bug                                  |*/
/*|    when inserting new values.                                           |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|     Stephan Martin                                                      |*/
/*|     Georg Beljajew                                                      |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/




enum ied_xslvalue {
    ied_xslval_unknown            = 0,

    /*
        language group:
    */
    ied_xslgrp_lang,
    /*
        query group:
    */
    ied_xslgrp_query,

    /*
        rdvpn group:
    */
    ied_xslgrp_rdvpn,
    /* wsp subgroup */
    ied_xslgrp_rdvpn_wsp,
    ied_xslval_rdvpn_wsp_name,
    /* wsp subgroup */
    ied_xslgrp_rdvpn_iws,
    ied_xslval_rdvpn_iws_ver,
    ied_xslval_rdvpn_iws_name,
    ied_xslval_rdvpn_iws_architecture,
    ied_xslval_rdvpn_iws_date,
    ied_xslval_rdvpn_iws_host,

    /*
        user group:
    */
    ied_xslgrp_usr,
    ied_xslval_usr_http_cookie,
    ied_xslval_usr_url_session_id,
    ied_xslval_usr_name,
    ied_xslval_usr_hsocks_id,
    ied_xslval_usr_password,
    ied_xslval_usr_hsocks_pwd,
    ied_xslval_usr_domain,
    ied_xslval_usr_role,
    ied_xslval_usr_sessionticket,
    ied_xslval_usr_hsocks_sticket,    
    ied_xslval_usr_logintime,
    ied_xslval_usr_welcomesite,
    ied_xslval_usr_lastwebserver,
    ied_xslval_usr_message,
    ied_xslval_usr_authenticated,
    ied_xslval_usr_end_ctrl_applet,
    ied_xslval_usr_wsg_flyer,
    ied_xslval_usr_default_portlet,
    ied_xslval_usr_skin,
    ied_xslval_usr_adm_msg,
    ied_xslval_usr_lang,
    ied_xslval_usr_pwd_expires,
    ied_xslval_usr_is_selected_lang,
    ied_xslval_usr_bookmarkhostname,
    /* cookie subgroup */
    ied_xslgrp_usr_cookie,
    ied_xslval_usr_cookie_name,
    ied_xslval_usr_cookie_value,
    ied_xslval_usr_cookie_version,
    ied_xslval_usr_cookie_expires,
    ied_xslval_usr_cookie_domain,
    ied_xslval_usr_cookie_path,
    ied_xslval_usr_cookie_port,
    ied_xslval_usr_cookie_comment,
    ied_xslval_usr_cookie_commenturl,
    ied_xslval_usr_cookie_secure,
    ied_xslval_usr_cookie_httponly,
    ied_xslval_usr_cookie_discard,
    ied_xslval_usr_cookie_handle,
    ied_xslval_usr_cookie_domain_changed,
    /* portlets subgroup */
    ied_xslgrp_usr_portlet,
    ied_xslval_usr_portlet_name,
    ied_xslval_usr_portlet_open,
    ied_xslval_usr_portlet_handle,
    ied_xslval_usr_portlet_hide,
    ied_xslval_usr_portlet_is_default,
    /* allowed subgroup */
    ied_xslgrp_usr_allowed,
    ied_xslval_usr_allowed_wsg,
    ied_xslval_usr_allowed_jterm,
    ied_xslval_usr_allowed_wfa,
    ied_xslval_usr_allowed_ppp,
    ied_xslval_usr_allowed_settings,
    ied_xslval_usr_allowed_conf_wsg_bmarks,
    ied_xslval_usr_allowed_conf_rdvpn_bmarks,
    ied_xslval_usr_allowed_conf_wfa_bmarks,
    ied_xslval_usr_allowed_conf_dod,
    ied_xslval_usr_allowed_conf_others,
    ied_xslval_usr_allowed_wsg_input,
    ied_xslval_usr_allowed_embedded_page,
    /* wsg-bookmarks subgroup */
    ied_xslgrp_usr_wsg_bmarks,
    ied_xslval_usr_wsg_bmark_name,
    ied_xslval_usr_wsg_bmark_url,
    ied_xslval_usr_wsg_bmark_is_own,
    ied_xslval_usr_wsg_bmark_handle,
    /* wsg-bookmarks subgroup */
    ied_xslgrp_usr_rdvpn_bmarks,
    ied_xslval_usr_rdvpn_bmark_name,
    ied_xslval_usr_rdvpn_bmark_url,
    ied_xslval_usr_rdvpn_bmark_is_own,
    ied_xslval_usr_rdvpn_bmark_handle,
    /* wfa-bookmarks subgroup */
    ied_xslgrp_usr_wfa_bmarks,
    ied_xslval_usr_wfa_bmark_name,
    ied_xslval_usr_wfa_bmark_url,
    ied_xslval_usr_wfa_bmark_is_own,
    ied_xslval_usr_wfa_bmark_handle,
    /* workstations subgroup */
    ied_xslgrp_usr_wstats,
    ied_xslval_usr_wstat_name,
    ied_xslval_usr_wstat_ineta,
    ied_xslval_usr_wstat_mac,
    ied_xslval_usr_wstat_port,
    ied_xslval_usr_wstat_timeout,
    ied_xslval_usr_wstat_handle,
    /* jwt standalone configuration */
    ied_xslgrp_usr_jwtsa_config,
    ied_xslval_usr_jwtsa_config_name,
    /* webterm subgroup */
    ied_xslgrp_usr_webterm,
    ied_xslgrp_usr_webterm_rdp,	
    ied_xslgrp_usr_webterm_ssh, //JTERM configs in XML (xl-webterm-uni-01)
    ied_xslgrp_usr_webterm_name,
    ied_xslgrp_usr_webterm_protocol_link,
    ied_xslgrp_usr_webterm_te, //Jterm configs from LDAP (xl-webterm-uni-01)
#if BO_HOBTE_CONFIG    
    ied_xslgrp_usr_webterm_te_name,
    ied_xslgrp_usr_webterm_te_protocol_link,
    ied_xslgrp_usr_webterm_te_session,
#endif
    /*
        login group:
    */
    ied_xslgrp_login,
    ied_xslval_login_challenge,
    ied_xslval_login_change_pwd,
    ied_xslval_login_show_ssa_cbox,
    ied_xslval_login_cookie_user,
    /* query subgroup */
    ied_xslgrp_login_query,
    ied_xslval_login_query_username,
    ied_xslval_login_query_userdomain,
    ied_xslval_login_query_password,
    ied_xslval_login_query_kick_out,
    ied_xslval_login_query_create_new,
    ied_xslval_login_query_cancel,
    ied_xslval_login_query_show_homepage,
    ied_xslval_login_query_old_pwd,
    ied_xslval_login_query_new_pwd,
    ied_xslval_login_query_conf_pwd,
    /* domain subgroup */
    ied_xslgrp_login_domain,
    ied_xslval_login_domain_disp_list,
    ied_xslval_login_domain_name,
    ied_xslval_login_domain_selected,
    /* kick-out subgroup */
    ied_xslgrp_login_kick_out,
    ied_xslval_login_kick_out_ineta,
    ied_xslval_login_kick_out_login_time,
    ied_xslval_login_kick_out_session,
    ied_xslval_login_kick_out_multiple,
    /* kicked-out subgroup */
    ied_xslgrp_login_kicked_out,
    ied_xslval_login_kicked_out_ineta,
    ied_xslval_login_kicked_out_login_time,

    /*
        lgout group:
    */
    ied_xslgrp_logout,
    /* session subgroup */
    ied_xslgrp_logout_session,
    ied_xslval_logout_session_gate_name,
    ied_xslval_logout_session_svr_entry,
    ied_xslval_logout_session_proto,
    ied_xslval_logout_session_srv_ip_port,
    ied_xslval_logout_session_number,
    ied_xslval_logout_session_clt_ip,
    ied_xslval_logout_session_time_started,
    ied_xslval_logout_session_no_rec_clt,
    ied_xslval_logout_session_no_snd_clt,
    ied_xslval_logout_session_no_rec_srv,
    ied_xslval_logout_session_no_snd_srv,
    ied_xslval_logout_session_no_rec_crypt,
    ied_xslval_logout_session_no_snd_crypt,
    ied_xslval_logout_session_dt_rec_clt,
    ied_xslval_logout_session_dt_snd_clt,
    ied_xslval_logout_session_dt_rec_srv,
    ied_xslval_logout_session_dt_snd_srv,
    ied_xslval_logout_session_dt_rec_crypt,
    ied_xslval_logout_session_dt_snd_crypt,
    ied_xslval_logout_session_cert_name,
    ied_xslval_logout_session_user_name,
    ied_xslval_logout_session_user_group,
    ied_xslval_logout_session_cur_handle,
    ied_xslval_logout_session_cur_srv_name,

    /*
        ppptunnel group:
    */
    ied_xslgrp_ppptnl,
    ied_xslval_ppptnl_name,
    ied_xslval_ppptnl_id,
    ied_xslval_ppptnl_ineta,
    ied_xslval_ppptnl_socks,
    ied_xslval_ppptnl_localhost,
    ied_xslval_ppptnl_server_name,

    /*
        postparam group:
    */
    ied_xslgrp_queryparam,
    ied_xslval_queryparam_set_lang,
    ied_xslval_queryparam_save_lang,
    ied_xslval_queryparam_rm_cookie,
    ied_xslval_queryparam_sett_task,
    ied_xslval_queryparam_wsg_bmark,
    ied_xslval_queryparam_rdvpn_bmark,
    ied_xslval_queryparam_wfa_bmark,
    ied_xslval_queryparam_bmark_name,
    ied_xslval_queryparam_bmark_url,
    ied_xslval_queryparam_wsg_flyer,
    ied_xslval_queryparam_wstat,
    ied_xslval_queryparam_wstat_name,
    ied_xslval_queryparam_wstat_ineta,
    ied_xslval_queryparam_wstat_port,
    ied_xslval_queryparam_wstat_mac,
    ied_xslval_queryparam_wstat_timeout,
    ied_xslval_queryparam_portlet,
    ied_xslval_queryparam_portlet_state,
    ied_xslval_queryparam_portlet_pos,
    ied_xslval_queryparam_edit_sett,
    ied_xslval_queryparam_default_portlet,

    /*
        wspadmin group:
    */
    ied_xslgrp_wspadmin,
    ied_xslval_wspadmin_return_code,
    /* query subgroup */
    ied_xslgrp_wspadmin_query,
    ied_xslval_wspadmin_query_sel_cluster,
    ied_xslval_wspadmin_query_disp_from,
    ied_xslval_wspadmin_query_disp_total,
    ied_xslval_wspadmin_query_count_filled,
    ied_xslval_wspadmin_query_get_backward,
    ied_xslval_wspadmin_query_search_usr,
    ied_xslval_wspadmin_query_search_usrgroup,
    ied_xslval_wspadmin_query_search_time,
    ied_xslval_wspadmin_query_search_word,
    ied_xslval_wspadmin_query_search_wildcard,
    ied_xslval_wspadmin_query_search_regexp,
    ied_xslval_wspadmin_query_disc_session,
    ied_xslval_wspadmin_query_logout_usr,
    ied_xslval_wspadmin_query_trace_ineta,
    ied_xslval_wspadmin_query_erase_inetas,
    ied_xslval_wspadmin_query_dump_cma,
    /* cluster subgroup */
    ied_xslgrp_wspadmin_cluster,
    ied_xslval_wspadmin_cluster_select_handle,
    ied_xslval_wspadmin_cluster_start_time,
    ied_xslval_wspadmin_cluster_server_name,
    ied_xslval_wspadmin_cluster_conf_name,
    ied_xslval_wspadmin_cluster_wsp_query,
    ied_xslval_wspadmin_cluster_server_group,
    ied_xslval_wspadmin_cluster_server_location,
    ied_xslval_wspadmin_cluster_process_id,
    ied_xslval_wspadmin_cluster_connect_time,
    ied_xslval_wspadmin_cluster_lb_load,
    ied_xslval_wspadmin_cluster_lb_time,
    ied_xslval_wspadmin_cluster_active,
    ied_xslval_wspadmin_cluster_number_rec,
    ied_xslval_wspadmin_cluster_length_rec,
    ied_xslval_wspadmin_cluster_number_snd,
    ied_xslval_wspadmin_cluster_length_snd,
    /* session subgroup */
    ied_xslgrp_wspadmin_session,
    ied_xslval_wspadmin_session_gate_name,
    ied_xslval_wspadmin_session_svr_entry,
    ied_xslval_wspadmin_session_proto,
    ied_xslval_wspadmin_session_srv_ip_port,
    ied_xslval_wspadmin_session_number,
    ied_xslval_wspadmin_session_clt_ip,
    ied_xslval_wspadmin_session_time_started,
    ied_xslval_wspadmin_session_no_rec_clt,
    ied_xslval_wspadmin_session_no_snd_clt,
    ied_xslval_wspadmin_session_no_rec_srv,
    ied_xslval_wspadmin_session_no_snd_srv,
    ied_xslval_wspadmin_session_no_rec_crypt,
    ied_xslval_wspadmin_session_no_snd_crypt,
    ied_xslval_wspadmin_session_dt_rec_clt,
    ied_xslval_wspadmin_session_dt_snd_clt,
    ied_xslval_wspadmin_session_dt_rec_srv,
    ied_xslval_wspadmin_session_dt_snd_srv,
    ied_xslval_wspadmin_session_dt_rec_crypt,
    ied_xslval_wspadmin_session_dt_snd_crypt,
    ied_xslval_wspadmin_session_cert_name,
    ied_xslval_wspadmin_session_user_name,
    ied_xslval_wspadmin_session_user_group,
    ied_xslval_wspadmin_session_cur_handle,
    ied_xslval_wspadmin_session_cur_srv_name,
    /* listen subgroup */
    ied_xslgrp_wspadmin_listen,
    ied_xslval_wspadmin_listen_gate_name,
    ied_xslval_wspadmin_listen_tm_conf_loaded,
    ied_xslval_wspadmin_listen_active_conf,
    ied_xslval_wspadmin_listen_use_listen_gateway,
    ied_xslval_wspadmin_listen_port,
    ied_xslval_wspadmin_listen_backlog,
    ied_xslval_wspadmin_listen_timeout,
    ied_xslval_wspadmin_listen_threshold,
    ied_xslval_wspadmin_listen_over_threshold,
    ied_xslval_wspadmin_listen_tm_last_threshold,
    ied_xslval_wspadmin_listen_max_sessions,
    ied_xslval_wspadmin_listen_start_session,
    ied_xslval_wspadmin_listen_current_sessions,
    ied_xslval_wspadmin_listen_max_sessions_reached,
    ied_xslval_wspadmin_listen_max_sessions_exceeded,
    ied_xslval_wspadmin_listen_cur_handle,
    /* listen ineta subsubgroup */
    ied_xslgrp_wspadmin_listen_ineta,
    ied_xslval_wspadmin_listen_ineta_active,
    ied_xslval_wspadmin_listen_ineta_ip_address,
    /* performance subrgoup */
    ied_xslgrp_wspadmin_perf,
    ied_xslval_wspadmin_perf_used_cpu_time,
    ied_xslval_wspadmin_perf_used_memory,
    ied_xslval_wspadmin_perf_network_data,
    ied_xslval_wspadmin_perf_loadbalancing,
    ied_xslval_wspadmin_perf_cur_handle,
    /* logifle subgroup */
    ied_xslgrp_wspadmin_log,
    ied_xslval_wspadmin_log_position,
    ied_xslval_wspadmin_log_filled,
    ied_xslval_wspadmin_log_timestamp,
    ied_xslval_wspadmin_log_message,
    ied_xslval_wspadmin_log_cur_handle,
    ied_xslval_wspadmin_log_cur_srv_name,
    ied_xslval_wspadmin_log_cur_conf_name,
    /* users subgroup */
    ied_xslgrp_wspadmin_user,
    ied_xslval_wspadmin_user_number,
    ied_xslval_wspadmin_user_name,
    ied_xslval_wspadmin_user_domain,
    ied_xslval_wspadmin_user_wspgroup,
    ied_xslval_wspadmin_user_role,
    ied_xslval_wspadmin_user_logged_in,
    ied_xslval_wspadmin_user_ineta,
    ied_xslval_wspadmin_user_session,
    /* wsp trace administration subgroup */
    ied_xslgrp_wspadmin_trace,
    ied_xslval_wspadmin_trace_enabled,
    ied_xslval_wspadmin_trace_active,
    ied_xslval_wspadmin_trace_all_sessions,
    ied_xslval_wspadmin_trace_output,
    ied_xslval_wspadmin_trace_no_single_ineta,
    ied_xslval_wspadmin_trace_session_allsettings,
    ied_xslval_wspadmin_trace_session_data_amount,
    ied_xslval_wspadmin_trace_session_netw,
    ied_xslval_wspadmin_trace_session_ssl_ext,
    ied_xslval_wspadmin_trace_session_ssl_int,
    ied_xslval_wspadmin_trace_session_ssl_ocsp,
    ied_xslval_wspadmin_trace_session_wspat3_ext,
    ied_xslval_wspadmin_trace_session_wspat3_int,
    ied_xslval_wspadmin_trace_session_sdh_ext,
    ied_xslval_wspadmin_trace_session_sdh_int,
    ied_xslval_wspadmin_trace_session_aux,
    ied_xslval_wspadmin_trace_session_misc,
    ied_xslval_wspadmin_trace_session_others,
    ied_xslval_wspadmin_trace_core_allsettings,
    ied_xslval_wspadmin_trace_core_data_amount,
    ied_xslval_wspadmin_trace_core_console,
    ied_xslval_wspadmin_trace_core_cluster,
    ied_xslval_wspadmin_trace_core_udp,
    ied_xslval_wspadmin_trace_core_dod,
    ied_xslval_wspadmin_trace_core_radius,
    ied_xslval_wspadmin_trace_core_virus_ch,
    ied_xslval_wspadmin_trace_core_hob_tun,
    ied_xslval_wspadmin_trace_core_ldap,
    ied_xslval_wspadmin_trace_core_krb5,
    ied_xslval_wspadmin_trace_core_ms_rpc,
    ied_xslval_wspadmin_trace_core_admin,
    ied_xslval_wspadmin_trace_core_ligw,
    ied_xslval_wspadmin_trace_core_others,
    ied_xslval_wspadmin_trace_individual_session,
    ied_xslval_wspadmin_trace_wsp_handle,				
    ied_xslval_wspadmin_trace_wsp_srv_name,					
    ied_xslval_wspadmin_trace_wsp_wsp_name,												
    ied_xslval_wspadmin_trace_wsp_srv_location,											
    ied_xslval_wspadmin_trace_wsp_srv_group,
    ied_xslval_wspadmin_trace_flag_sess_netw,											// read in xsl as "wspadmin/wsptrace/flag-sess-netw"
    ied_xslval_wspadmin_trace_flag_sess_ssl_ext,										// read in xsl as "wspadmin/wsptrace/flag-sess-ssl-ext"
    ied_xslval_wspadmin_trace_flag_sess_ssl_int,										// read in xsl as "wspadmin/wsptrace/flag-sess-ssl-int"
    ied_xslval_wspadmin_trace_flag_sess_ssl_ocsp,										// read in xsl as "wspadmin/wsptrace/flag-sess-ssl-ocsp"
    ied_xslval_wspadmin_trace_flag_sess_wspat3_ext,										// read in xsl as "wspadmin/wsptrace/flag-sess-wspat3-ext"
    ied_xslval_wspadmin_trace_flag_sess_wspat3_int,										// read in xsl as "wspadmin/wsptrace/flag-sess-wspat3-int"
    ied_xslval_wspadmin_trace_flag_sess_sdh_ext,										// read in xsl as "wspadmin/wsptrace/flag-sess-sdh-ext"
    ied_xslval_wspadmin_trace_flag_sess_sdh_int,										// read in xsl as "wspadmin/wsptrace/flag-sess-sdh-int"
    ied_xslval_wspadmin_trace_flag_sess_aux,											// read in xsl as "wspadmin/wsptrace/flag-sess-aux"
    ied_xslval_wspadmin_trace_flag_sess_misc,											// read in xsl as "wspadmin/wsptrace/flag-sess-misc"
    ied_xslval_wspadmin_trace_flag_sess_others,											// read in xsl as "wspadmin/wsptrace/flag-sess-others"
    ied_xslval_wspadmin_trace_flag_core_console,										// read in xsl as "wspadmin/wsptrace/flag-core-console"
    ied_xslval_wspadmin_trace_flag_core_cluster,										// read in xsl as "wspadmin/wsptrace/flag-core-cluster"
    ied_xslval_wspadmin_trace_flag_core_udp,										    // read in xsl as "wspadmin/wsptrace/flag-core-udp"
    ied_xslval_wspadmin_trace_flag_core_dod,    										// read in xsl as "wspadmin/wsptrace/flag-core-dod"
    ied_xslval_wspadmin_trace_flag_core_radius, 										// read in xsl as "wspadmin/wsptrace/flag-core-radius"
    ied_xslval_wspadmin_trace_flag_core_virus_ch,										// read in xsl as "wspadmin/wsptrace/flag-core-virus-ch"
    ied_xslval_wspadmin_trace_flag_core_hob_tun,										// read in xsl as "wspadmin/wsptrace/flag-core-hob-tun"
    ied_xslval_wspadmin_trace_flag_core_ldap,   										// read in xsl as "wspadmin/wsptrace/flag-core-ldap"
    ied_xslval_wspadmin_trace_flag_core_krb5,   										// read in xsl as "wspadmin/wsptrace/flag-core-krb5"
    ied_xslval_wspadmin_trace_flag_core_ms_rpc, 										// read in xsl as "wspadmin/wsptrace/flag-core-ms-rpc"
    ied_xslval_wspadmin_trace_flag_core_admin,  										// read in xsl as "wspadmin/wsptrace/flag-core-admin"
    ied_xslval_wspadmin_trace_flag_core_ligw,	    									// read in xsl as "wspadmin/wsptrace/flag-core-ligw"
    ied_xslval_wspadmin_trace_flag_core_others,	    									// read in xsl as "wspadmin/wsptrace/flag-core-others"

    /*
        error group:
    */
    ied_xslgrp_error,
    ied_xslval_error_show_back
};

struct dsd_xsl_name_entry {
    dsd_const_string      strc_name;   
    enum ied_xslvalue     iec_enum_value; 
};

struct dsd_xsl_group {
    dsd_xsl_name_entry dsc_group_name;                //!< group name
    const dsd_xsl_name_entry* adsc_childs;     //!< direct child elements
    int                   in_no_childs;         //!< number of childs
    const dsd_xsl_group*  ads_subgroup;         //!< subgroup list
    int                   in_no_groups;         //!< number of subgroups
};

#define CS(x) dsd_const_string(x)

/*+-------------------------------------------------------------------------+*/
/*| lang group:                                                             |*/
/*+-------------------------------------------------------------------------+*/
static const dsd_xsl_group ds_lang_grp = { 
    {CS("lang"), ied_xslgrp_lang },             // group name
    NULL,                                       // child elements
    0,                                          // number of childs
    NULL,                                       // subgroups
    0                                           // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| query group:                                                            |*/
/*+-------------------------------------------------------------------------+*/
static const dsd_xsl_group ds_query_grp = { 
    {CS("query"), ied_xslgrp_query },           // group name
    NULL,                                       // child elements
    0,                                          // number of childs
    NULL,                                       // subgroups
    0                                           // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| rdvpn group:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/*
    rdvpn/wsp subgroup:
*/
static const dsd_xsl_name_entry achr_rdvpn_wsp_sgrp_childs[] = {
    {CS("name"), ied_xslval_rdvpn_wsp_name }                    // read in xsl as "rdvpn/wsp/name"
};
static const dsd_xsl_group ds_rdvpn_wsp_sgrp = {
    {CS("wsp"), ied_xslgrp_rdvpn_wsp },                         // group name
    achr_rdvpn_wsp_sgrp_childs,                                 // child elements
    (int)(sizeof(achr_rdvpn_wsp_sgrp_childs)/sizeof(dsd_xsl_name_entry)),    // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    rdvpn/iws subgroup:
*/
static const dsd_xsl_name_entry achr_rdvpn_iws_sgrp_childs[] = {
    {CS("version"), ied_xslval_rdvpn_iws_ver },                         // read in xsl as "rdvpn/iws/version"
    {CS("name"), ied_xslval_rdvpn_iws_name },                           // read in xsl as "rdvpn/iws/name"
    {CS("architecture"), ied_xslval_rdvpn_iws_architecture },           // read in xsl as "rdvpn/iws/architecture"
    {CS("date"), ied_xslval_rdvpn_iws_date },                           // read in xsl as "rdvpn/iws/date"
    {CS("host"), ied_xslval_rdvpn_iws_host },                           // read in xsl as "rdvpn/iws/host"
                                             
};
static const dsd_xsl_group ds_rdvpn_iws_sgrp = {
    {CS("iws"), ied_xslgrp_rdvpn_iws },                         // group name
    achr_rdvpn_iws_sgrp_childs,                                 // child elements
    (int)(sizeof(achr_rdvpn_iws_sgrp_childs)/sizeof(dsd_xsl_name_entry)),    // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    rdvpn main group:
*/
static const dsd_xsl_group ds_rdvpn_sgrp[] = {
    ds_rdvpn_wsp_sgrp,                                          // rdvpn/wsp subgroup
    ds_rdvpn_iws_sgrp                                           // rdvpn/iws subgroup
};
static const dsd_xsl_group ds_rdvpn_grp = { 
    {CS("rdvpn"), ied_xslgrp_rdvpn },                           // group name
    NULL,                                                       // child elements
    0,                                                          // number of childs
    ds_rdvpn_sgrp,                                              // subgroups
    (int)(sizeof(ds_rdvpn_sgrp)/sizeof(dsd_xsl_group))          // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| user group:                                                             |*/
/*+-------------------------------------------------------------------------+*/
/*
    user/cookie subgroup:
*/
static const dsd_xsl_name_entry achr_user_cookie_sgrp_childs[] = {
    {CS("name"), ied_xslval_usr_cookie_name },                  // read in xsl as "user/cookie/name"
    {CS("value"), ied_xslval_usr_cookie_value },                // read in xsl as "user/cookie/value"
    {CS("version"), ied_xslval_usr_cookie_version },            // read in xsl as "user/cookie/version"
    {CS("expires"), ied_xslval_usr_cookie_expires },            // read in xsl as "user/cookie/expires"
    {CS("domain"), ied_xslval_usr_cookie_domain },              // read in xsl as "user/cookie/domain"
    {CS("path"), ied_xslval_usr_cookie_path },                  // read in xsl as "user/cookie/path"
    {CS("port"), ied_xslval_usr_cookie_port },                  // read in xsl as "user/cookie/port"
    {CS("comment"), ied_xslval_usr_cookie_comment },            // read in xsl as "user/cookie/comment"
    {CS("commenturl"), ied_xslval_usr_cookie_commenturl },      // read in xsl as "user/cookie/commenturl"
    {CS("secure"), ied_xslval_usr_cookie_secure },              // read in xsl as "user/cookie/secure"
    {CS("http-only"), ied_xslval_usr_cookie_httponly },         // read in xsl as "user/cookie/http-only"
    {CS("discard"), ied_xslval_usr_cookie_discard },            // read in xsl as "user/cookie/discard"
    {CS("handle"), ied_xslval_usr_cookie_handle },              // read in xsl as "user/cookie/handle"
    {CS("domain-changed"), ied_xslval_usr_cookie_domain_changed },// read in xsl as "user/cookie/domain-changed"
                     
};
static const dsd_xsl_group ds_user_cookie_sgrp = {
    {CS("cookie"), ied_xslgrp_usr_cookie },                     // group name
    achr_user_cookie_sgrp_childs,                               // child elements
    (int)(sizeof(achr_user_cookie_sgrp_childs)/sizeof(dsd_xsl_name_entry)),  // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/portlet subgroup:
*/
static const dsd_xsl_name_entry achr_user_portlet_sgrp_childs[] = {
    {CS("name"), ied_xslval_usr_portlet_name },                 // read in xsl as "user/portlet/name"
    {CS("open"), ied_xslval_usr_portlet_open },                 // read in xsl as "user/portlet/open"
    {CS("handle"), ied_xslval_usr_portlet_handle },             // read in xsl as "user/portlet/handle"
    {CS("hide"), ied_xslval_usr_portlet_hide },                 // for hiding portlets as "user/portlet/hide"
    {CS("is-default"), ied_xslval_usr_portlet_is_default },     // for hiding portlets as "user/portlet/is-default"
};
static const dsd_xsl_group ds_user_portlet_sgrp = {
    {CS("portlet"), ied_xslgrp_usr_portlet },                   // group name
    achr_user_portlet_sgrp_childs,                              // child elements
    (int)(sizeof(achr_user_portlet_sgrp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/allowed subgroup
*/
static const dsd_xsl_name_entry achr_user_allowed_sgrp_childs[] = {
    {CS("wsg"), ied_xslval_usr_allowed_wsg },                               // read in xsl as "user/allowed/wsg"
    {CS("jterm"), ied_xslval_usr_allowed_jterm },                           // read in xsl as "user/allowed/jterm"
    {CS("wfa"), ied_xslval_usr_allowed_wfa },                               // read in xsl as "user/allowed/wfa"
    {CS("ppptunnel"), ied_xslval_usr_allowed_ppp },                         // read in xsl as "user/allowed/ppptunnel"
    {CS("settings"), ied_xslval_usr_allowed_settings },                     // read in xsl as "user/allowed/settings"
    {CS("configure-wsg-bmarks"), ied_xslval_usr_allowed_conf_wsg_bmarks },  // read in xsl as "user/allowed/configure-wsg-bmarks"
    {CS("configure-rdvpn-bmarks"), ied_xslval_usr_allowed_conf_rdvpn_bmarks },// read in xsl as "user/allowed/configure-rdvpn-bmarks"
    {CS("configure-wfa-bmarks"), ied_xslval_usr_allowed_conf_wfa_bmarks },  // read in xsl as "user/allowed/configure-wfa-bmarks"
    {CS("configure-dod"), ied_xslval_usr_allowed_conf_dod },                // read in xsl as "user/allowed/configure-dod"
    {CS("configure-others"), ied_xslval_usr_allowed_conf_others },          // read in xsl as "user/allowed/configure-others"
    {CS("wsg-input"), ied_xslval_usr_allowed_wsg_input },                   // read in xsl as "user/allowed/wsg-input"
    {CS("use-embedded"), ied_xslval_usr_allowed_embedded_page },            // read in xsl as "user/allowed/use-embedded"
};
static const dsd_xsl_group ds_user_allowed_sgrp = {
    {CS("allowed"), ied_xslgrp_usr_allowed },                   // group name
    achr_user_allowed_sgrp_childs,                              // child elements
    (int)(sizeof(achr_user_allowed_sgrp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/wsg-bookmarks subgroup:
*/
static const dsd_xsl_name_entry achr_user_wsg_bmark_sgrp_childs[] = {
    {CS("name"), ied_xslval_usr_wsg_bmark_name },               // read in xsl as "user/wsg-bookmarks/name"
    {CS("url"), ied_xslval_usr_wsg_bmark_url },                 // read in xsl as "user/wsg-bookmarks/url"
    {CS("is-own"), ied_xslval_usr_wsg_bmark_is_own },           // read in xsl as "user/wsg-bookmarks/is-own"
    {CS("handle"), ied_xslval_usr_wsg_bmark_handle },           // read in xsl as "user/wsg-bookmarks/handle"
                   
};
static const dsd_xsl_group ds_user_wsg_bmark = {
    {CS("wsg-bookmarks"), ied_xslgrp_usr_wsg_bmarks },          // group name
    achr_user_wsg_bmark_sgrp_childs,                            // child elements
    (int)(sizeof(achr_user_wsg_bmark_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/rdvpn-bookmarks subgroup:
*/
static const dsd_xsl_name_entry achr_user_rdvpn_bmark_sgrp_childs[] = {
    {CS("name"), ied_xslval_usr_rdvpn_bmark_name },               // read in xsl as "user/rdvpn-bookmarks/name"
    {CS("url"), ied_xslval_usr_rdvpn_bmark_url },                 // read in xsl as "user/rdvpn-bookmarks/url"
    {CS("is-own"), ied_xslval_usr_rdvpn_bmark_is_own },           // read in xsl as "user/rdvpn-bookmarks/is-own"
    {CS("handle"), ied_xslval_usr_rdvpn_bmark_handle },           // read in xsl as "user/rdvpn-bookmarks/handle"
                   
};
static const dsd_xsl_group ds_user_rdvpn_bmark = {
    {CS("rdvpn-bookmarks"), ied_xslgrp_usr_rdvpn_bmarks },        // group name
    achr_user_rdvpn_bmark_sgrp_childs,                            // child elements
    (int)(sizeof(achr_user_rdvpn_bmark_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/jwtsa-config subgroup:
*/
static const dsd_xsl_name_entry achr_user_jwtsa_config_sgrp_childs[] =
{
    {CS("name"), ied_xslval_usr_jwtsa_config_name}              // read in xsl as "user/jwtsa-config/name"
};
static const dsd_xsl_group ds_user_jwtsa_config =
{
    {CS("jwtsa-config"), ied_xslgrp_usr_jwtsa_config },             // group name
    achr_user_jwtsa_config_sgrp_childs,								// child elements
    (int)(sizeof(achr_user_jwtsa_config_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,															// subgroups
    0																// number of subgroups
};

/*
    user/webterm subgroup:
*/
static const dsd_xsl_name_entry achr_user_webterm_sgrp_childs[] =
{
    {CS("rdp"), ied_xslgrp_usr_webterm_rdp },						        // read in xsl as "user/webterm/rdp"
    {CS("ssh"), ied_xslgrp_usr_webterm_ssh },					            // read in xsl as "user/webterm/ssh"
    {CS("name"), ied_xslgrp_usr_webterm_name },                             // read in xsl as "user/webterm/name"
    {CS("protocol-link"), ied_xslgrp_usr_webterm_protocol_link },           // read in xsl as "user/webterm/protocol-link"
    {CS("te"), ied_xslgrp_usr_webterm_te },                                 // read in xsl as "user/webterm/te
                    
#if BO_HOBTE_CONFIG  
    {CS("te-name"), ied_xslgrp_usr_webterm_te_name },                       // read in xsl as "user/webterm/te-name"
    {CS("te-protocol-link"), ied_xslgrp_usr_webterm_te_protocol_link },     // read in xsl as "user/webterm/te-protocol-link"
    {CS("te-session"), ied_xslgrp_usr_webterm_te_session },                 // read in xsl as "user/webterm/te-session"
    
#endif
};
static const dsd_xsl_group ds_user_webterm =
{
    {CS("webterm"),	ied_xslgrp_usr_webterm },                       // group name
    achr_user_webterm_sgrp_childs,									// child elements
    (int)(sizeof(achr_user_webterm_sgrp_childs)/sizeof(dsd_xsl_name_entry)),		// number of childs
    NULL,															// subgroups
    0																// number of subgroups
};

/*
    user/wfa-bookmarks subgroup:
*/
static const dsd_xsl_name_entry achr_user_wfa_bmark_sgrp_childs[] = {
    {CS("name"), ied_xslval_usr_wfa_bmark_name },                   // read in xsl as "user/wfa-bookmarks/name"
    {CS("url"), ied_xslval_usr_wfa_bmark_url },                     // read in xsl as "user/wfa-bookmarks/url"
    {CS("is-own"), ied_xslval_usr_wfa_bmark_is_own },               // read in xsl as "user/wfa-bookmarks/is-own"
    {CS("handle"), ied_xslval_usr_wfa_bmark_handle },               // read in xsl as "user/wfa-bookmarks/handle"
};
static const dsd_xsl_group ds_user_wfa_bmark = {
    {CS("wfa-bookmarks"), ied_xslgrp_usr_wfa_bmarks },          // group name
    achr_user_wfa_bmark_sgrp_childs,                            // child elements
    (int)(sizeof(achr_user_wfa_bmark_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    user/workstations subgroup:
*/
static const dsd_xsl_name_entry achr_user_wstat_sgrp_child[] = {
    {CS("name"), ied_xslval_usr_wstat_name },                       // read in xsl as "user/workstations/name"
    {CS("ineta"), ied_xslval_usr_wstat_ineta },                     // read in xsl as "user/workstations/ineta"
    {CS("mac"), ied_xslval_usr_wstat_mac },                         // read in xsl as "user/workstations/mac"
    {CS("port"), ied_xslval_usr_wstat_port },                       // read in xsl as "user/workstations/port"
    {CS("timeout"), ied_xslval_usr_wstat_timeout },                 // read in xsl as "user/workstations/timeout"
    {CS("handle"), ied_xslval_usr_wstat_handle },                   // read in xsl as "user/workstations/handle"
};
static const dsd_xsl_group ds_user_wstat = {
    {CS("workstations"), ied_xslgrp_usr_wstats },               // group name
    achr_user_wstat_sgrp_child,                                 // child elements
    (int)(sizeof(achr_user_wstat_sgrp_child)/sizeof(dsd_xsl_name_entry)),    // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

static const dsd_xsl_name_entry ach_user_grp_childs[] = { 
    {CS("httpcookie"), ied_xslval_usr_http_cookie },                // read in xsl as "user/httpcookie"
    {CS("url-session-id"), ied_xslval_usr_url_session_id },         // read in xsl as "user/url-session-id"
    {CS("name"), ied_xslval_usr_name },                             // read in xsl as "user/name"
    {CS("hsocks-id"), ied_xslval_usr_hsocks_id },                   // read in xsl as "user/hsocks-id"
    {CS("password"), ied_xslval_usr_password },                     // read in xsl as "user/password"
    {CS("hsocks-password"), ied_xslval_usr_hsocks_pwd },            // read in xsl as "user/hsocks-password"
    {CS("domain"), ied_xslval_usr_domain },                         // read in xsl as "user/domain"
    {CS("selected-role"), ied_xslval_usr_role },                    // read in xsl as "user/selected-role"
    {CS("sessionticket"), ied_xslval_usr_sessionticket },           // read in xsl as "user/sessionticket"
    {CS("hsocks-sticket"), ied_xslval_usr_hsocks_sticket },         // read in xsl as "user/hsocks-sticket"
    {CS("logintime"), ied_xslval_usr_logintime },                   // read in xsl as "user/logintime"
    {CS("welcomesite"), ied_xslval_usr_welcomesite },               // read in xsl as "user/welcomesite"
    {CS("lastwebserver"), ied_xslval_usr_lastwebserver },           // read in xsl as "user/lastwebserver"
    {CS("message"), ied_xslval_usr_message },                       // read in xsl as "user/message"
    {CS("authenticated"), ied_xslval_usr_authenticated },           // read in xsl as "user/authenticated"
    {CS("end-control-applet"), ied_xslval_usr_end_ctrl_applet },    // read in xsl as "user/end-control-applet"
    {CS("show-wsg-flyer"), ied_xslval_usr_wsg_flyer },              // read in xsl as "user/show-wsg-flyer"
    {CS("default-portlet"), ied_xslval_usr_default_portlet },       // read in xsl as "user/default-portlet"
    {CS("gui-skin"), ied_xslval_usr_skin },                         // read in xsl as "user/gui-skin"
    {CS("adm-message"), ied_xslval_usr_adm_msg },                   // read in xsl as "user/adm-message"
    {CS("language"), ied_xslval_usr_lang },                         // read in xsl as "user/language"
    {CS("pwd-expires"), ied_xslval_usr_pwd_expires },               // read in xsl as "user/pwd-expires"
    {CS("is-selected-lang"), ied_xslval_usr_is_selected_lang },     // read in xsl as "user/is-selected-lang"
    {CS("bookmarkhostname"), ied_xslval_usr_bookmarkhostname },     // read in xsl as "user/bookmarkhostname"
   
};

static const dsd_xsl_group ds_user_sgrp[] = {
    ds_user_cookie_sgrp,                                        // user/cookie subgroup
    ds_user_portlet_sgrp,                                       // user/portlet subgroup
    ds_user_allowed_sgrp,                                       // user/allowed subgroup
    ds_user_wsg_bmark,                                          // user/wsg-bookmarks subgroup
    ds_user_rdvpn_bmark,                                        // user/rdvpn-bookmarks subgroup
    ds_user_wfa_bmark,                                          // user/wfa-bookmarks subgroup
    ds_user_wstat,                                              // user/workstations subgroup
    ds_user_jwtsa_config,										// user/jwtsa-config subgroup
    ds_user_webterm
};

static const dsd_xsl_group ds_user_grp = { 
    {CS("user"), ied_xslgrp_usr },                              // group name
    ach_user_grp_childs,                                        // child elements
    (int)(sizeof(ach_user_grp_childs)/sizeof(dsd_xsl_name_entry)),           // number of childs
    ds_user_sgrp,                                               // subgroups
    (int)(sizeof(ds_user_sgrp)/sizeof(dsd_xsl_group))           // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| login group:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/*
    login/query subgroup:
*/
static const dsd_xsl_name_entry achr_login_query_sgrp_childs[] = {
    {CS("username"), ied_xslval_login_query_username },             // read in xsl as "login/query/username"
    {CS("userdomain"), ied_xslval_login_query_userdomain },         // read in xsl as "login/query/userdomain"
    {CS("password"), ied_xslval_login_query_password },             // read in xsl as "login/query/password"
    {CS("kick-out"), ied_xslval_login_query_kick_out },             // read in xsl as "login/query/kick-out"
    {CS("create-new"), ied_xslval_login_query_create_new },         // read in xsl as "login/query/create-new"
    {CS("cancel"), ied_xslval_login_query_cancel },                 // read in xsl as "login/query/cancel"
    {CS("show-homepage"), ied_xslval_login_query_show_homepage },   // read in xsl as "login/query/show-homepage"
    {CS("old-password"), ied_xslval_login_query_old_pwd },          // read in xsl as "login/query/old-password"
    {CS("new-password"), ied_xslval_login_query_new_pwd },          // read in xsl as "login/query/new-password"
    {CS("confirm-password"), ied_xslval_login_query_conf_pwd },     // read in xsl as "login/query/confirm-password"
    
};
static const dsd_xsl_group ds_login_query_sgrp = {
    {CS("query"), ied_xslgrp_login_query },                     // group name
    achr_login_query_sgrp_childs,                               // child elements
    (int)(sizeof(achr_login_query_sgrp_childs)/sizeof(dsd_xsl_name_entry)),  // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    login/domain subgroup:
*/
static const dsd_xsl_name_entry achr_login_domain_sgrp_childs[] = {
    {CS("display-list"), ied_xslval_login_domain_disp_list },       // read in xsl as "login/domain/display-list"
    {CS("name"), ied_xslval_login_domain_name },                    // read in xsl as "login/domain/name"
    {CS("is-selected"), ied_xslval_login_domain_selected },         // read in xsl as "login/domain/is-selected"
};
static const dsd_xsl_group ds_login_domain_sgrp = {
    {CS("domain"), ied_xslgrp_login_domain },                   // group name
    achr_login_domain_sgrp_childs,                              // child elements
    (int)(sizeof(achr_login_domain_sgrp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    login/kick-out subgroup:
*/
static const dsd_xsl_name_entry achr_login_kickout_sgrp_childs[] = {
    {CS("ineta"), ied_xslval_login_kick_out_ineta },                // read in xsl as "login/kick-out/ineta"
    {CS("login-time"), ied_xslval_login_kick_out_login_time },      // read in xsl as "login/kick-out/login-time"
    {CS("session"), ied_xslval_login_kick_out_session },            // read in xsl as "login/kick-out/session"
    {CS("multiple-allowed"), ied_xslval_login_kick_out_multiple },  // read in xsl as "login/kick-out/multiple-allowed"
    
};
static const dsd_xsl_group ds_login_kickout_sgrp = {
    {CS("kick-out"), ied_xslgrp_login_kick_out },               // group name
    achr_login_kickout_sgrp_childs,                             // child elements
    (int)(sizeof(achr_login_kickout_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    login/kicked-out subgroup:
*/
static const dsd_xsl_name_entry achr_login_kickedout_sgrp_childs[] = {
    {CS("ineta"), ied_xslval_login_kicked_out_ineta },              // read in xsl as "login/kicked-out/ineta"
    {CS("login-time"), ied_xslval_login_kicked_out_login_time },    // read in xsl as "login/kicked-out/login-time"
};
static const dsd_xsl_group ds_login_kickedout_sgrp = {
    {CS("kicked-out"), ied_xslgrp_login_kicked_out },           // group name
    achr_login_kickedout_sgrp_childs,                           // child elements
    (int)(sizeof(achr_login_kickedout_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    login main group:
*/
static const dsd_xsl_name_entry ach_login_grp_childs[] = { 
    {CS("challenge"), ied_xslval_login_challenge },                 // read in xsl as "login/challenge"
    {CS("change-password"), ied_xslval_login_change_pwd },          // read in xsl as "login/change-password"
    {CS("show-homepage-checkbox"), ied_xslval_login_show_ssa_cbox },// read in xsl as "login/show-homepage-checkbox"
    {CS("cookie-user"), ied_xslval_login_cookie_user },	         	// read in xsl as "login/cookie-user"
};
static const dsd_xsl_group ds_login_sgrp[] = {
    ds_login_query_sgrp,                                            // login/query subgroup
    ds_login_domain_sgrp,                                           // login/domain subgroup
    ds_login_kickout_sgrp,                                          // login/kick-out subgroup
    ds_login_kickedout_sgrp                                         // login/kicked-out subgroup
};
static const dsd_xsl_group ds_login_grp = { 
    {CS("login"), ied_xslgrp_login },                               // group name
    ach_login_grp_childs,                                           // child elements
    (int)(sizeof(ach_login_grp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    ds_login_sgrp,                                                  // subgroups
    (int)(sizeof(ds_login_sgrp)/sizeof(dsd_xsl_group))              // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| logout group:                                                           |*/
/*+-------------------------------------------------------------------------+*/
/*
    logout/session subgroup:
*/
static const dsd_xsl_name_entry achr_logout_sess_sgrp_childs[] = {
    {CS("gate-name"), ied_xslval_logout_session_gate_name },                // read in xsl as "logout/session/gate-name"
    {CS("server-entry"), ied_xslval_logout_session_svr_entry },             // read in xsl as "logout/session/server-entry"
    {CS("protocol"), ied_xslval_logout_session_proto },                     // read in xsl as "logout/session/protocol"
    {CS("server-ip:port"), ied_xslval_logout_session_srv_ip_port },         // read in xsl as "logout/session/server-ip:port"
    {CS("session-number"), ied_xslval_logout_session_number },              // read in xsl as "logout/session/session-number"
    {CS("client-ip"), ied_xslval_logout_session_clt_ip },                   // read in xsl as "logout/session/client-ip"
    {CS("time-started"), ied_xslval_logout_session_time_started },          // read in xsl as "logout/session/time-started"
    {CS("number-rec-client"), ied_xslval_logout_session_no_rec_clt },       // read in xsl as "logout/session/number-rec-client"
    {CS("number-snd-client"), ied_xslval_logout_session_no_snd_clt },       // read in xsl as "logout/session/number-snd-client"
    {CS("number-rec-server"), ied_xslval_logout_session_no_rec_srv },       // read in xsl as "logout/session/number-rec-server"
    {CS("number-snd-server"), ied_xslval_logout_session_no_snd_srv },       // read in xsl as "logout/session/number-snd-server"
    {CS("number-rec-encrypted"), ied_xslval_logout_session_no_rec_crypt },  // read in xsl as "logout/session/number-rec-encrypted"
    {CS("number-snd-encrypted"), ied_xslval_logout_session_no_snd_crypt },  // read in xsl as "logout/session/number-snd-encrypted"
    {CS("data-rec-client"), ied_xslval_logout_session_dt_rec_clt },         // read in xsl as "logout/session/data-rec-client"
    {CS("data-snd-client"), ied_xslval_logout_session_dt_snd_clt },         // read in xsl as "logout/session/data-snd-client"
    {CS("data-rec-server"), ied_xslval_logout_session_dt_rec_srv },         // read in xsl as "logout/session/data-rec-server"
    {CS("data-snd-server"), ied_xslval_logout_session_dt_snd_srv },         // read in xsl as "logout/session/data-snd-server"
    {CS("data-rec-encrypted"), ied_xslval_logout_session_dt_rec_crypt },    // read in xsl as "logout/session/data-rec-encrypted"
    {CS("data-snd-encrypted"), ied_xslval_logout_session_dt_snd_crypt },    // read in xsl as "logout/session/data-snd-encrypted"
    {CS("certificate-name"), ied_xslval_logout_session_cert_name },         // read in xsl as "logout/session/certificate-name"
    {CS("user-name"), ied_xslval_logout_session_user_name },                // read in xsl as "logout/session/user-name"
    {CS("user-group"), ied_xslval_logout_session_user_group },              // read in xsl as "logout/session/user-group"
    {CS("current-handle"), ied_xslval_logout_session_cur_handle },          // read in xsl as "logout/session/current-handle"
    {CS("current-server-name"), ied_xslval_logout_session_cur_srv_name },   // read in xsl as "logout/session/current-server-name"
    
};
static const dsd_xsl_group ds_logout_sess_sgrp = {
    {CS("session"), ied_xslgrp_logout_session },                // group name
    achr_logout_sess_sgrp_childs,                               // child elements
    (int)(sizeof(achr_logout_sess_sgrp_childs)/sizeof(dsd_xsl_name_entry)),  // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};


/*
    logout main group:
*/
static const dsd_xsl_group ds_logout_sgrp[] = {
    ds_logout_sess_sgrp                                          // logout/session subgroup
};
static const dsd_xsl_group ds_logout_grp = { 
    {CS("logout"), ied_xslgrp_logout },                          // group name
    NULL,                                                        // child elements
    0,                                                           // number of childs
    ds_logout_sgrp,                                              // subgroups
    (int)(sizeof(ds_logout_sgrp)/sizeof(dsd_xsl_group))          // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| ppptunnel group:                                                        |*/
/*+-------------------------------------------------------------------------+*/
/*
    ppptunnel childs:
*/
static const dsd_xsl_name_entry achr_ppptunnel_grp_childs[] = {
    {CS("name"), ied_xslval_ppptnl_name },                      // read in xsl as "ppptunnel/name"
    {CS("id"), ied_xslval_ppptnl_id },                          // read in xsl as "ppptunnel/id"
    {CS("wsp-ineta"), ied_xslval_ppptnl_ineta },                // read in xsl as "ppptunnel/wsp-ineta"
    {CS("wsp-socks-mode"), ied_xslval_ppptnl_socks },           // read in xsl as "ppptunnel/wsp-socks-mode"
    {CS("wsp-localhost"), ied_xslval_ppptnl_localhost },        // read in xsl as "ppptunnel/wsp-localhost"
    {CS("server-entry-name"), ied_xslval_ppptnl_server_name },  // read in xsl as "ppptunnel/server-entry-name"
                   
};
/*
    ppptunnel main group:
*/
static const dsd_xsl_group ds_ppptunnel_grp = { 
    {CS("ppptunnel"), ied_xslgrp_ppptnl },                      // group name
    achr_ppptunnel_grp_childs,                                  // child elements
    (int)(sizeof(achr_ppptunnel_grp_childs)/sizeof(dsd_xsl_name_entry)),     // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| postparam group:                                                        |*/
/*+-------------------------------------------------------------------------+*/
/*
    queryparam main group:
*/
static const dsd_xsl_name_entry ach_queryparam_grp_childs[] = {
    {CS("set-lang"), ied_xslval_queryparam_set_lang },              // read in xsl as "queryparam/set-lang"
    {CS("save-lang"), ied_xslval_queryparam_save_lang },            // read in xsl as "queryparam/save-lang"
    {CS("rm-cookie"), ied_xslval_queryparam_rm_cookie },            // read in xsl as "queryparam/rm-cookie"
    {CS("settings-task"), ied_xslval_queryparam_sett_task },        // read in xsl as "queryparam/settings-task"
    {CS("wsg-bookmark"), ied_xslval_queryparam_wsg_bmark },         // read in xsl as "queryparam/wsg-bookmark"
    {CS("rdvpn-bookmark"), ied_xslval_queryparam_rdvpn_bmark },     // read in xsl as "queryparam/rdvpn-bookmark"
    {CS("wfa-bookmark"), ied_xslval_queryparam_wfa_bmark },         // read in xsl as "queryparam/wfa-bookmark"
    {CS("bookmark-name"), ied_xslval_queryparam_bmark_name },       // read in xsl as "queryparam/bookmark-name"
    {CS("bookmark-url"), ied_xslval_queryparam_bmark_url },         // read in xsl as "queryparam/bookmark-url"
    {CS("wsg-flyer"), ied_xslval_queryparam_wsg_flyer },            // read in xsl as "queryparam/wsg-flyer"
    {CS("workstation"), ied_xslval_queryparam_wstat },              // read in xsl as "queryparam/workstation"
    {CS("wstat-name"), ied_xslval_queryparam_wstat_name },          // read in xsl as "queryparam/wstat-name"
    {CS("wstat-ineta"), ied_xslval_queryparam_wstat_ineta },        // read in xsl as "queryparam/wstat-ineta"
    {CS("wstat-port"), ied_xslval_queryparam_wstat_port },          // read in xsl as "queryparam/wstat-port"
    {CS("wstat-mac"), ied_xslval_queryparam_wstat_mac },            // read in xsl as "queryparam/wstat-mac"
    {CS("wstat-timeout"), ied_xslval_queryparam_wstat_timeout },    // read in xsl as "queryparam/wstat-timeout"
    {CS("portlet"), ied_xslval_queryparam_portlet },                // read in xsl as "queryparam/portlet"
    {CS("portlet-state"), ied_xslval_queryparam_portlet_state },    // read in xsl as "queryparam/portlet-state"
    {CS("portlet-position"), ied_xslval_queryparam_portlet_pos },   // read in xsl as "queryparam/portlet-position"
    {CS("edit-settings"), ied_xslval_queryparam_edit_sett },        // read in xsl as "queryparam/edit-settings"
    {CS("default-portlet"), ied_xslval_queryparam_default_portlet },// read in xsl as "queryparam/default-portlet"
    
};
static const dsd_xsl_group ds_queryparam_grp = { 
    {CS("queryparam"), ied_xslgrp_queryparam },                     // group name
    ach_queryparam_grp_childs,                                      // child elements
    (int)(sizeof(ach_queryparam_grp_childs)/sizeof(dsd_xsl_name_entry)),     // number of childs
    NULL,                                                           // subgroups
    0                                                               // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| wspadmin group:                                                         |*/
/*+-------------------------------------------------------------------------+*/
/*
    wspadmin/query subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_query_sgrp_childs[] = {
    {CS("select-cluster"), ied_xslval_wspadmin_query_sel_cluster },             // read in xsl as "wspadmin/query/select-cluster"
    {CS("display-from"), ied_xslval_wspadmin_query_disp_from },                 // read in xsl as "wspadmin/query/display-from"
    {CS("display-total"), ied_xslval_wspadmin_query_disp_total },               // read in xsl as "wspadmin/query/display-total"
    {CS("count-filled"), ied_xslval_wspadmin_query_count_filled },              // read in xsl as "wspadmin/query/count-filled"
    {CS("get-backward"), ied_xslval_wspadmin_query_get_backward },              // read in xsl as "wspadmin/query/get-backward"
    {CS("search-user"), ied_xslval_wspadmin_query_search_usr },                 // read in xsl as "wspadmin/query/search-user"
    {CS("search-usergroup"), ied_xslval_wspadmin_query_search_usrgroup },       // read in xsl as "wspadmin/query/search-usergroup"
    {CS("search-time"), ied_xslval_wspadmin_query_search_time },                // read in xsl as "wspadmin/query/search-time"
    {CS("search-word"), ied_xslval_wspadmin_query_search_word },                // read in xsl as "wspadmin/query/search-word"
    {CS("search-with-wildcard"), ied_xslval_wspadmin_query_search_wildcard },   // read in xsl as "wspadmin/query/search-with-wildcard"
    {CS("search-with-regexp"), ied_xslval_wspadmin_query_search_regexp },       // read in xsl as "wspadmin/query/search-with-regexp"
    {CS("disconnect-session"), ied_xslval_wspadmin_query_disc_session },        // read in xsl as "wspadmin/query/disconnect-session"
    {CS("logout-user"), ied_xslval_wspadmin_query_logout_usr },                 // read in xsl as "wspadmin/query/logout-user"
    {CS("trace-ineta"), ied_xslval_wspadmin_query_trace_ineta },				// read in xsl as "wspadmin/query/trace-ineta"
    {CS("erase-inetas"), ied_xslval_wspadmin_query_erase_inetas },              // read in xsl as "wspadmin/query/erase-inetas"
    {CS("dump-cma"), ied_xslval_wspadmin_query_dump_cma },                      // read in xsl as "wspadmin/query/dump-cma"
    
};
static const dsd_xsl_group ds_wspadmin_query_sgrp = {
    {CS("query"), ied_xslgrp_wspadmin_query },                                  // group name
    achr_wspadmin_query_sgrp_childs,                                            // child elements
    (int)(sizeof(achr_wspadmin_query_sgrp_childs)/sizeof(dsd_xsl_name_entry)),  // number of childs
    NULL,                                                                       // subgroups
    0                                                                           // number of subgroups
};

/*
    wspadmin/cluster subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_cluster_sgrp_childs[] = {
    {CS("select-handle"), ied_xslval_wspadmin_cluster_select_handle },      // read in xsl as "wspadmin/cluster/select-handle"
    {CS("start-time"), ied_xslval_wspadmin_cluster_start_time },            // read in xsl as "wspadmin/cluster/start-time"
    {CS("server-name"), ied_xslval_wspadmin_cluster_server_name },          // read in xsl as "wspadmin/cluster/server-name"
    {CS("conf-name"), ied_xslval_wspadmin_cluster_conf_name },              // read in xsl as "wspadmin/cluster/conf-name"
    {CS("wsp-query"), ied_xslval_wspadmin_cluster_wsp_query },              // read in xsl as "wspadmin/cluster/wsp-query"
    {CS("server-group"), ied_xslval_wspadmin_cluster_server_group },		// read in xsl as "wspadmin/cluster/server-group"
    {CS("server-location"), ied_xslval_wspadmin_cluster_server_location },	// read in xsl as "wspadmin/cluster/server-location"
    {CS("process-id"), ied_xslval_wspadmin_cluster_process_id },            // read in xsl as "wspadmin/cluster/process-id"
    {CS("connect-time"), ied_xslval_wspadmin_cluster_connect_time },        // read in xsl as "wspadmin/cluster/connect-time"
    {CS("lb-load"), ied_xslval_wspadmin_cluster_lb_load },                  // read in xsl as "wspadmin/cluster/lb-load"
    {CS("lb-time"), ied_xslval_wspadmin_cluster_lb_time },                  // read in xsl as "wspadmin/cluster/lb-time"
    {CS("active"), ied_xslval_wspadmin_cluster_active },                    // read in xsl as "wspadmin/cluster/active"
    {CS("number-receives"), ied_xslval_wspadmin_cluster_number_rec },       // read in xsl as "wspadmin/cluster/number-receives"
    {CS("length-receives"), ied_xslval_wspadmin_cluster_length_rec },       // read in xsl as "wspadmin/cluster/length-receives"
    {CS("number-send"), ied_xslval_wspadmin_cluster_number_snd },           // read in xsl as "wspadmin/cluster/number-send"
    {CS("length-send"), ied_xslval_wspadmin_cluster_length_snd },           // read in xsl as "wspadmin/cluster/length-send"
    
};
static const dsd_xsl_group ds_wspadmin_cluster_sgrp = {
    {CS("cluster"), ied_xslgrp_wspadmin_cluster },                          // group name
    achr_wspadmin_cluster_sgrp_childs,                                      // child elements
    (int)(sizeof(achr_wspadmin_cluster_sgrp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    NULL,                                                                   // subgroups
    0                                                                       // number of subgroups
};

/*
    wspadmin/session subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_session_sgrp_childs[] = {
    {CS("gate-name"), ied_xslval_wspadmin_session_gate_name },                  // read in xsl as "wspadmin/session/gate-name"
    {CS("server-entry"), ied_xslval_wspadmin_session_svr_entry },               // read in xsl as "wspadmin/session/server-entry"
    {CS("protocol"), ied_xslval_wspadmin_session_proto },                       // read in xsl as "wspadmin/session/protocol"
    {CS("server-ip:port"), ied_xslval_wspadmin_session_srv_ip_port },           // read in xsl as "wspadmin/session/server-ip:port"
    {CS("session-number"), ied_xslval_wspadmin_session_number },                // read in xsl as "wspadmin/session/session-number"
    {CS("client-ip"), ied_xslval_wspadmin_session_clt_ip },                     // read in xsl as "wspadmin/session/client-ip"
    {CS("time-started"), ied_xslval_wspadmin_session_time_started },            // read in xsl as "wspadmin/session/time-started"
    {CS("number-rec-client"), ied_xslval_wspadmin_session_no_rec_clt },         // read in xsl as "wspadmin/session/number-rec-client"
    {CS("number-snd-client"), ied_xslval_wspadmin_session_no_snd_clt },         // read in xsl as "wspadmin/session/number-snd-client"
    {CS("number-rec-server"), ied_xslval_wspadmin_session_no_rec_srv },         // read in xsl as "wspadmin/session/number-rec-server"
    {CS("number-snd-server"), ied_xslval_wspadmin_session_no_snd_srv },         // read in xsl as "wspadmin/session/number-snd-server"
    {CS("number-rec-encrypted"), ied_xslval_wspadmin_session_no_rec_crypt },    // read in xsl as "wspadmin/session/number-rec-encrypted"
    {CS("number-snd-encrypted"), ied_xslval_wspadmin_session_no_snd_crypt },    // read in xsl as "wspadmin/session/number-snd-encrypted"
    {CS("data-rec-client"), ied_xslval_wspadmin_session_dt_rec_clt },           // read in xsl as "wspadmin/session/data-rec-client"
    {CS("data-snd-client"), ied_xslval_wspadmin_session_dt_snd_clt },           // read in xsl as "wspadmin/session/data-snd-client"
    {CS("data-rec-server"), ied_xslval_wspadmin_session_dt_rec_srv },           // read in xsl as "wspadmin/session/data-rec-server"
    {CS("data-snd-server"), ied_xslval_wspadmin_session_dt_snd_srv },           // read in xsl as "wspadmin/session/data-snd-server"
    {CS("data-rec-encrypted"), ied_xslval_wspadmin_session_dt_rec_crypt },      // read in xsl as "wspadmin/session/data-rec-encrypted"
    {CS("data-snd-encrypted"), ied_xslval_wspadmin_session_dt_snd_crypt },      // read in xsl as "wspadmin/session/data-snd-encrypted"
    {CS("certificate-name"), ied_xslval_wspadmin_session_cert_name },           // read in xsl as "wspadmin/session/certificate-name"
    {CS("user-name"), ied_xslval_wspadmin_session_user_name },                  // read in xsl as "wspadmin/session/user-name"
    {CS("user-group"), ied_xslval_wspadmin_session_user_group },                // read in xsl as "wspadmin/session/user-group"
    {CS("current-handle"), ied_xslval_wspadmin_session_cur_handle },            // read in xsl as "wspadmin/session/current-handle"
    {CS("current-server-name"), ied_xslval_wspadmin_session_cur_srv_name },     // read in xsl as "wspadmin/session/current-server-name"
    
};
static const dsd_xsl_group ds_wspadmin_session_sgrp = {
    {CS("session"), ied_xslgrp_wspadmin_session },                              // group name
    achr_wspadmin_session_sgrp_childs,                                          // child elements
    (int)(sizeof(achr_wspadmin_session_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                                       // subgroups
    0                                                                           // number of subgroups
};

/*
    wspadmin/trace subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_trace_sgrp_childs[] = {
    {CS("trace-enabled"), ied_xslval_wspadmin_trace_enabled },                      // read in xsl as "wspadmin/wsptrace/trace-enabled"
    {CS("trace-active"), ied_xslval_wspadmin_trace_active },                        // read in xsl as "wspadmin/wsptrace/trace-active"
    {CS("trace-all-sessions"), ied_xslval_wspadmin_trace_all_sessions },            // read in xsl as "wspadmin/wsptrace/trace-all-sessions"
    {CS("trace-output"), ied_xslval_wspadmin_trace_output },                        // read in xsl as "wspadmin/wsptrace/trace-output"
    {CS("no-single-ineta"), ied_xslval_wspadmin_trace_no_single_ineta },            // read in xsl as "wspadmin/wsptrace/no-single-ineta"
    {CS("session-allsettings"), ied_xslval_wspadmin_trace_session_allsettings },    // read in xsl as "wspadmin/wsptrace/session-allsettings"
    {CS("session-data-amount"), ied_xslval_wspadmin_trace_session_data_amount },    // read in xsl as "wspadmin/wsptrace/session-data-amount"
    {CS("session-network"), ied_xslval_wspadmin_trace_session_netw },               // read in xsl as "wspadmin/wsptrace/session-network"
    {CS("session-sslext"), ied_xslval_wspadmin_trace_session_ssl_ext },             // read in xsl as "wspadmin/wsptrace/session-sslext"
    {CS("session-sslint"), ied_xslval_wspadmin_trace_session_ssl_int },             // read in xsl as "wspadmin/wsptrace/session-sslint"
    {CS("session-sslocsp"), ied_xslval_wspadmin_trace_session_ssl_ocsp },           // read in xsl as "wspadmin/wsptrace/session-sslocsp"
    {CS("session-wspat3ext"), ied_xslval_wspadmin_trace_session_wspat3_ext },       // read in xsl as "wspadmin/wsptrace/session-wspat3ext"
    {CS("session-wspat3int"), ied_xslval_wspadmin_trace_session_wspat3_int },       // read in xsl as "wspadmin/wsptrace/session-wspat3int"
    {CS("session-sdhext"), ied_xslval_wspadmin_trace_session_sdh_ext },             // read in xsl as "wspadmin/wsptrace/session-sdhext"
    {CS("session-sdhint"), ied_xslval_wspadmin_trace_session_sdh_int },             // read in xsl as "wspadmin/wsptrace/session-sdhint"
    {CS("session-aux"), ied_xslval_wspadmin_trace_session_aux },                    // read in xsl as "wspadmin/wsptrace/session-aux"
    {CS("session-miscell"), ied_xslval_wspadmin_trace_session_misc },               // read in xsl as "wspadmin/wsptrace/session-miscell"
    {CS("session-others"), ied_xslval_wspadmin_trace_session_others },              // read in xsl as "wspadmin/wsptrace/session-others"
    {CS("core-allsettings"), ied_xslval_wspadmin_trace_core_allsettings },          // read in xsl as "wspadmin/wsptrace/core-allsettings"
    {CS("core-data-amount"), ied_xslval_wspadmin_trace_core_data_amount },          // read in xsl as "wspadmin/wsptrace/core-data-amount"
    {CS("core-console"), ied_xslval_wspadmin_trace_core_console },                  // read in xsl as "wspadmin/wsptrace/core-console"
    {CS("core-cluster"), ied_xslval_wspadmin_trace_core_cluster },                  // read in xsl as "wspadmin/wsptrace/core-cluster"
    {CS("core-udp"), ied_xslval_wspadmin_trace_core_udp },                          // read in xsl as "wspadmin/wsptrace/core-udp"
    {CS("core-dod"), ied_xslval_wspadmin_trace_core_dod },                          // read in xsl as "wspadmin/wsptrace/core-dod"
    {CS("core-radius"), ied_xslval_wspadmin_trace_core_radius },                    // read in xsl as "wspadmin/wsptrace/core-radius"
    {CS("core-virus"), ied_xslval_wspadmin_trace_core_virus_ch },                   // read in xsl as "wspadmin/wsptrace/core-virus"
    {CS("core-hobtun"), ied_xslval_wspadmin_trace_core_hob_tun },                   // read in xsl as "wspadmin/wsptrace/core-hobtun"
    {CS("core-ldap"), ied_xslval_wspadmin_trace_core_ldap },                        // read in xsl as "wspadmin/wsptrace/core-ldap"
    {CS("core-krb5"), ied_xslval_wspadmin_trace_core_krb5 },                        // read in xsl as "wspadmin/wsptrace/core-krb5"
    {CS("core-msrpc"), ied_xslval_wspadmin_trace_core_ms_rpc },                     // read in xsl as "wspadmin/wsptrace/core-msrpc"
    {CS("core-admin"), ied_xslval_wspadmin_trace_core_admin },                      // read in xsl as "wspadmin/wsptrace/core-admin"
    {CS("core-ligw"), ied_xslval_wspadmin_trace_core_ligw },                        // read in xsl as "wspadmin/wsptrace/core-ligw"
    {CS("core-others"), ied_xslval_wspadmin_trace_core_others },                    // read in xsl as "wspadmin/wsptrace/core-others"
    {CS("individual-session"), ied_xslval_wspadmin_trace_individual_session },      // read in xsl as "wspadmin/wsptrace/individual-session"
    {CS("wsp-handle"), ied_xslval_wspadmin_trace_wsp_handle },                      // read in xsl as "wspadmin/wsptrace/wsp-handle"
    {CS("wsp-srv-name"), ied_xslval_wspadmin_trace_wsp_srv_name },                  // read in xsl as "wspadmin/wsptrace/wsp-srv-name"
    {CS("wsp-wsp-name"), ied_xslval_wspadmin_trace_wsp_wsp_name },                  // read in xsl as "wspadmin/wsptrace/wsp-wsp-name"
    {CS("wsp-srv-location"), ied_xslval_wspadmin_trace_wsp_srv_location },          // read in xsl as "wspadmin/wsptrace/wsp-srv-location"
    {CS("wsp-srv-group"), ied_xslval_wspadmin_trace_wsp_srv_group },                // read in xsl as "wspadmin/wsptrace/wsp-srv-group"
    {CS("flag-sess-netw"), ied_xslval_wspadmin_trace_flag_sess_netw },              // read in xsl as "wspadmin/wsptrace/flag-sess-netw"
    {CS("flag-sess-ssl-ext"), ied_xslval_wspadmin_trace_flag_sess_ssl_ext },        // read in xsl as "wspadmin/wsptrace/flag-sess-ssl-ext"
    {CS("flag-sess-ssl-int"), ied_xslval_wspadmin_trace_flag_sess_ssl_int },        // read in xsl as "wspadmin/wsptrace/flag-sess-ssl-int"
    {CS("flag-sess-ssl-ocsp"), ied_xslval_wspadmin_trace_flag_sess_ssl_ocsp },      // read in xsl as "wspadmin/wsptrace/flag-sess-ssl-ocsp"
    {CS("flag-sess-wspat3-ext"), ied_xslval_wspadmin_trace_flag_sess_wspat3_ext },  // read in xsl as "wspadmin/wsptrace/flag-sess-wspat3-ext"
    {CS("flag-sess-wspat3-int"), ied_xslval_wspadmin_trace_flag_sess_wspat3_int },  // read in xsl as "wspadmin/wsptrace/flag-sess-wspat3-int"
    {CS("flag-sess-sdh-ext"), ied_xslval_wspadmin_trace_flag_sess_sdh_ext },        // read in xsl as "wspadmin/wsptrace/flag-sess-sdh-ext"
    {CS("flag-sess-sdh-int"), ied_xslval_wspadmin_trace_flag_sess_sdh_int },        // read in xsl as "wspadmin/wsptrace/flag-sess-sdh-int"
    {CS("flag-sess-aux"), ied_xslval_wspadmin_trace_flag_sess_aux },                // read in xsl as "wspadmin/wsptrace/flag-sess-aux"
    {CS("flag-sess-misc"), ied_xslval_wspadmin_trace_flag_sess_misc },              // read in xsl as "wspadmin/wsptrace/flag-sess-misc"
    {CS("flag-sess-others"), ied_xslval_wspadmin_trace_flag_sess_others },          // read in xsl as "wspadmin/wsptrace/flag-sess-others"
    {CS("flag-core-console"), ied_xslval_wspadmin_trace_flag_core_console },        // read in xsl as "wspadmin/wsptrace/flag-core-console"
    {CS("flag-core-cluster"), ied_xslval_wspadmin_trace_flag_core_cluster },        // read in xsl as "wspadmin/wsptrace/flag-core-cluster"
    {CS("flag-core-udp"), ied_xslval_wspadmin_trace_flag_core_udp },                // read in xsl as "wspadmin/wsptrace/flag-core-udp"
    {CS("flag-core-dod"), ied_xslval_wspadmin_trace_flag_core_dod },                // read in xsl as "wspadmin/wsptrace/flag-core-dod"
    {CS("flag-core-radius"), ied_xslval_wspadmin_trace_flag_core_radius },          // read in xsl as "wspadmin/wsptrace/flag-core-radius"
    {CS("flag-core-virus-ch"), ied_xslval_wspadmin_trace_flag_core_virus_ch },      // read in xsl as "wspadmin/wsptrace/flag-core-virus-ch"
    {CS("flag-core-hob-tun"), ied_xslval_wspadmin_trace_flag_core_hob_tun },        // read in xsl as "wspadmin/wsptrace/flag-core-hob-tun"
    {CS("flag-core-ldap"), ied_xslval_wspadmin_trace_flag_core_ldap },              // read in xsl as "wspadmin/wsptrace/flag-core-ldap"
    {CS("flag-core-krb5"), ied_xslval_wspadmin_trace_flag_core_krb5 },              // read in xsl as "wspadmin/wsptrace/flag-core-krb5"
    {CS("flag-core-ms-rpc"), ied_xslval_wspadmin_trace_flag_core_ms_rpc },          // read in xsl as "wspadmin/wsptrace/flag-core-ms-rpc"
    {CS("flag-core-admin"), ied_xslval_wspadmin_trace_flag_core_admin },            // read in xsl as "wspadmin/wsptrace/flag-core-admin"
    {CS("flag-core-ligw"), ied_xslval_wspadmin_trace_flag_core_ligw },              // read in xsl as "wspadmin/wsptrace/flag-core-ligw"
    {CS("flag-core-others"), ied_xslval_wspadmin_trace_flag_core_others },          // read in xsl as "wspadmin/wsptrace/flag-core-others"


};
static const dsd_xsl_group ds_wspadmin_trace_sgrp = {
    {CS("wsptrace"), ied_xslgrp_wspadmin_trace },                   // group name
    achr_wspadmin_trace_sgrp_childs,								// child elements
    (int)(sizeof(achr_wspadmin_trace_sgrp_childs)/sizeof(dsd_xsl_name_entry)),	// number of childs
    NULL,                                                           // subgroups
    0                                                               // number of subgroups
};

/*
    wspadmin/listen/ineta subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_listen_ineta_ssgrp_childs[] = {
    {CS("active"), ied_xslval_wspadmin_listen_ineta_active },                       // read in xsl as "wspadmin/listen/ineta/active"
    {CS("ip-address"), ied_xslval_wspadmin_listen_ineta_ip_address },               // read in xsl as "wspadmin/listen/ineta/ip-address"
};
static const dsd_xsl_group ds_wspadmin_listen_ineta_ssgrp = {
    {CS("ineta"), ied_xslgrp_wspadmin_listen_ineta },                               // group name
    achr_wspadmin_listen_ineta_ssgrp_childs,                                        // child elements
    (int)(sizeof(achr_wspadmin_listen_ineta_ssgrp_childs)/sizeof(dsd_xsl_name_entry)),   // number of childs
    NULL,                                                                           // subgroups
    0                                                                               // number of subgroups
};

/*
    wspadmin/listen subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_listen_sgrp_childs[] = {
{CS("gate-name"), ied_xslval_wspadmin_listen_gate_name },                       // read in xsl as "wspadmin/listen/gate-name"
{CS("time-conf-loaded"), ied_xslval_wspadmin_listen_tm_conf_loaded },           // read in xsl as "wspadmin/listen/time-conf-loaded"
{CS("active-conf"), ied_xslval_wspadmin_listen_active_conf },                   // read in xsl as "wspadmin/listen/active-conf"
{CS("use-listen-gateway"), ied_xslval_wspadmin_listen_use_listen_gateway },     // read in xsl as "wspadmin/listen/use-listen-gateway"
{CS("port"), ied_xslval_wspadmin_listen_port },                                 // read in xsl as "wspadmin/listen/port"
{CS("backlog"), ied_xslval_wspadmin_listen_backlog },                           // read in xsl as "wspadmin/listen/backlog"
{CS("timeout"), ied_xslval_wspadmin_listen_timeout },                           // read in xsl as "wspadmin/listen/timeout"
{CS("threshold"), ied_xslval_wspadmin_listen_threshold },                       // read in xsl as "wspadmin/listen/threshold"
{CS("over-threshold"), ied_xslval_wspadmin_listen_over_threshold },             // read in xsl as "wspadmin/listen/over-threshold"
{CS("time-last-threshold"), ied_xslval_wspadmin_listen_tm_last_threshold },     // read in xsl as "wspadmin/listen/time-last-threshold"
{CS("max-sessions"), ied_xslval_wspadmin_listen_max_sessions },                 // read in xsl as "wspadmin/listen/max-sessions"
{CS("start-session"), ied_xslval_wspadmin_listen_start_session },               // read in xsl as "wspadmin/listen/start-session"
{CS("current-sessions"), ied_xslval_wspadmin_listen_current_sessions },         // read in xsl as "wspadmin/listen/current-sessions"
{CS("max-sessions-reached"), ied_xslval_wspadmin_listen_max_sessions_reached }, // read in xsl as "wspadmin/listen/max-sessions-reached"
{CS("max-sessions-exceeded"), ied_xslval_wspadmin_listen_max_sessions_exceeded },// read in xsl as "wspadmin/listen/max-sessions-exceeded"
{CS("current-handle"), ied_xslval_wspadmin_listen_cur_handle },                 // read in xsl as "wspadmin/listen/current-handle"
};
static const dsd_xsl_group ds_wspadmin_listen_ssgrp[] = {
    ds_wspadmin_listen_ineta_ssgrp                              // wspadmin/listen/ineta subsubgroup
};
static const dsd_xsl_group ds_wspadmin_listen_sgrp = {
    {CS("listen"), ied_xslgrp_wspadmin_listen },                // group name
    achr_wspadmin_listen_sgrp_childs,                           // child elements
    (int)(sizeof(achr_wspadmin_listen_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    ds_wspadmin_listen_ssgrp,                                   // subgroups
    (int)(sizeof(ds_wspadmin_listen_ssgrp)/sizeof(dsd_xsl_group))// number of subgroups
};

/*
    wspadmin/performance subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_perf_sgrp_childs[] = {
    {CS("used-cpu-time"), ied_xslval_wspadmin_perf_used_cpu_time },                 // read in xsl as "wspadmin/performance/used-cpu-time"
    {CS("used-memory"), ied_xslval_wspadmin_perf_used_memory },                     // read in xsl as "wspadmin/performance/used-memory"
    {CS("network-data"), ied_xslval_wspadmin_perf_network_data },                   // read in xsl as "wspadmin/performance/network-data"
    {CS("loadbalancing"), ied_xslval_wspadmin_perf_loadbalancing },                 // read in xsl as "wspadmin/performance/loadbalancing"
    {CS("current-handle"), ied_xslval_wspadmin_perf_cur_handle },                   // read in xsl as "wspadmin/performance/current-handle"
};
static const dsd_xsl_group ds_wspadmin_perf_sgrp = {
    {CS("performance"), ied_xslgrp_wspadmin_perf },             // group name
    achr_wspadmin_perf_sgrp_childs,                             // child elements
    (int)(sizeof(achr_wspadmin_perf_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    wspadmin/logfile subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_log_sgrp_childs[] = {
    {CS("position"), ied_xslval_wspadmin_log_position },                            // read in xsl as "wspadmin/logfile/position"
    {CS("filled"), ied_xslval_wspadmin_log_filled },                                // read in xsl as "wspadmin/logfile/filled"
    {CS("timestamp"), ied_xslval_wspadmin_log_timestamp },                          // read in xsl as "wspadmin/logfile/timestamp"
    {CS("message"), ied_xslval_wspadmin_log_message },                              // read in xsl as "wspadmin/logfile/message"
    {CS("current-handle"), ied_xslval_wspadmin_log_cur_handle },                    // read in xsl as "wspadmin/logfile/current-handle"
    {CS("current-server-name"), ied_xslval_wspadmin_log_cur_srv_name },             // read in xsl as "wspadmin/logfile/current-server-name"
    {CS("current-conf-name"), ied_xslval_wspadmin_log_cur_conf_name },              // read in xsl as "wspadmin/logfile/current-conf-name"
};
static const dsd_xsl_group ds_wspadmin_log_sgrp = {
    {CS("logfile"), ied_xslgrp_wspadmin_log },                  // group name
    achr_wspadmin_log_sgrp_childs,                              // child elements
    (int)(sizeof(achr_wspadmin_log_sgrp_childs)/sizeof(dsd_xsl_name_entry)), // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    wspadmin/users subgroup:
*/
static const dsd_xsl_name_entry achr_wspadmin_user_sgrp_childs[] = {
    {CS("number"), ied_xslval_wspadmin_user_number },                               // read in xsl as "wspadmin/users/number"
    {CS("name"), ied_xslval_wspadmin_user_name },                                   // read in xsl as "wspadmin/users/name"
    {CS("domain"), ied_xslval_wspadmin_user_domain },                               // read in xsl as "wspadmin/users/domain"
    {CS("wspgroup"), ied_xslval_wspadmin_user_wspgroup },                           // read in xsl as "wspadmin/users/wspgroup"
    {CS("role"), ied_xslval_wspadmin_user_role },                                   // read in xsl as "wspadmin/users/role"
    {CS("logged-in"), ied_xslval_wspadmin_user_logged_in },                         // read in xsl as "wspadmin/users/logged-in"
    {CS("ineta"), ied_xslval_wspadmin_user_ineta },                                 // read in xsl as "wspadmin/users/ineta"
    {CS("session"), ied_xslval_wspadmin_user_session },                             // read in xsl as "wspadmin/users/session"
};
static const dsd_xsl_group ds_wspadmin_user_sgrp = {
    {CS("users"), ied_xslgrp_wspadmin_user },                   // group name
    achr_wspadmin_user_sgrp_childs,                             // child elements
    (int)(sizeof(achr_wspadmin_user_sgrp_childs)/sizeof(dsd_xsl_name_entry)),// number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*
    wspadmin main group:
*/
static const dsd_xsl_group ds_wspadmin_sgrp[] = {
    ds_wspadmin_query_sgrp,                                     // wspadmin/query       subgroup
    ds_wspadmin_cluster_sgrp,                                   // wspadmin/cluster     subgroup
    ds_wspadmin_session_sgrp,                                   // wspadmin/session     subgroup
    ds_wspadmin_listen_sgrp,                                    // wspadmin/listen      subgroup
    ds_wspadmin_perf_sgrp,                                      // wspadmin/performance subgroup
    ds_wspadmin_log_sgrp,                                       // wspadmin/logfile     subgroup
    ds_wspadmin_user_sgrp,                                      // wspadmin/users       subgroup
    ds_wspadmin_trace_sgrp										// wspadmin/trace		subgroup	
};
static const dsd_xsl_name_entry achr_wspadmin_grp_childs[] = {
    {CS("return-code"), ied_xslval_wspadmin_return_code }       // read in xsl as "wspadmin/return-code"
};
static const dsd_xsl_group ds_wspadmin_grp = { 
    {CS("wspadmin"), ied_xslgrp_wspadmin },                     // group name
    achr_wspadmin_grp_childs,                                   // child elements
    (int)(sizeof(achr_wspadmin_grp_childs)/sizeof(dsd_xsl_name_entry)),      // number of childs
    ds_wspadmin_sgrp,                                           // subgroups
    (int)(sizeof(ds_wspadmin_sgrp)/sizeof(dsd_xsl_group))       // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| error group:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/*
    queryparam main group:
*/
static const dsd_xsl_name_entry ach_error_grp_childs[] = {
    {CS("show-back"), ied_xslval_error_show_back },             // read in xsl as "error/show-back"
};
static const dsd_xsl_group ds_error_grp = { 
    {CS("error"), ied_xslgrp_error },                           // group name
    ach_error_grp_childs,                                       // child elements
    (int)(sizeof(ach_error_grp_childs)/sizeof(dsd_xsl_name_entry)),          // number of childs
    NULL,                                                       // subgroups
    0                                                           // number of subgroups
};

/*+-------------------------------------------------------------------------+*/
/*| main xsl value structure:                                               |*/
/*+-------------------------------------------------------------------------+*/
static const dsd_xsl_group dsr_xslvalues[] = {
    ds_lang_grp,                // language group
    ds_query_grp,               // query group
    ds_rdvpn_grp,               // rdvpn group
    ds_user_grp,                // user group
    ds_login_grp,               // login group
    ds_logout_grp,              // logout group
    ds_ppptunnel_grp,           // ppptunnel group
    ds_queryparam_grp,          // queryparam group
    ds_wspadmin_grp,            // wspadmin group
    ds_error_grp                // error group
};

#undef CS

#endif