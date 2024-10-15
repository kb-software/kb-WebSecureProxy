/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-wsp-admin-1.h                                      |*/
/*| ----------                                                        |*/
/*|  IP-Gateway with SSL                                              |*/
/*|  WebSecureProxy                                                   |*/
/*|  Header File for the Admin Interface (Administration)             |*/
/*|  KB 04.04.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC or other Unix C-Compilers                                    |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_LONGLONG
#define HL_LONGLONG long long int
#endif
#ifndef DEF_LEN_FINGERPRINT
#define DEF_LEN_FINGERPRINT    20           /* length of hashes        */
#endif

#define EXT_WSP_ADM_SESSION_USERFLD

/**
   response for this WSP in the cluster
   name of query: cluster
   structure type: 0
   this structure is followed by up to six UTF-8 strings
     name of host
     WSP version etc.
     name in cluster, if configured
     group, if configured
     location, if configured
     URL, if configured
*/
struct dsd_wspadm1_cluster_main {           /* WSP Administration Cluster this WSP */
   HL_LONGLONG ilc_epoch_started;           /* time WSP started        */
   int        imc_len_server_name;          /* length server name      */
   int        imc_len_query_main;           /* length WSP version etc. UTF-8 */
   int        imc_len_wsp_name;             /* length cluster WSP name UTF-8 */
   int        imc_len_group;                /* length of group in bytes */
   int        imc_len_location;             /* length of location in bytes */
   int        imc_len_url;                  /* length of URL in bytes  */
   int        imc_pid;                      /* process id              */
   int        imc_lb_load;                  /* load reported in load-balancing */
   int        imc_lb_epoch;                 /* epoch last report load-balancing */
   BOOL       boc_listen_stopped;           /* listen has been stopped */
   BOOL       boc_deny_not_configured;      /* deny connect in from not configured WSP */
   char       chrc_wsp_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over WSP */
   char       chrc_conf_file_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over current configuration-file */
};

/**
   response for other WSPs in the cluster
   name of query: cluster
   structure type: 1
   this structure is followed by three UTF-8 strings
     name in cluster, in the configuration, or from remote side
     name of host
     WSP version etc.
*/
struct dsd_wspadm1_cluster_remote {         /* WSP Administration Cluster remote WSP */
   HL_LONGLONG ilc_handle_cluster;          /* select cluster          */
   HL_LONGLONG ilc_epoch_started;           /* time WSP started        */
// int        imc_len_wsp_name;             /* length WSP name UTF-8   */
   int        imc_len_config_name;          /* length configuration name */
   int        imc_len_server_name;          /* length server name      */
   int        imc_len_query_main;           /* length WSP version etc. UTF-8 */
   int        imc_len_group;                /* length of group in bytes */
   int        imc_len_location;             /* length of location in bytes */
   int        imc_len_url;                  /* length of URL in bytes  */
   int        imc_pid;                      /* process id              */
   int        imc_epoch_conn;               /* time/epoch connected    */
   int        imc_lb_load;                  /* load reported in load-balancing */
   int        imc_lb_epoch;                 /* epoch last report load-balancing */
   BOOL       boc_listen_stopped;           /* listen has been stopped */
   BOOL       boc_same_group;               /* is in same group as main */
   BOOL       boc_unix_socket;              /* is Unix domain socket   */
   BOOL       boc_redirect;                 /* is redirected           */
   int        imc_uds_pid;                  /* process id Unix domain socket */
   int        imc_time_start;               /* time connection started */
   int        imc_stat_no_recv;             /* statistic number of receives */
   int        imc_stat_no_send;             /* statistic number of sends */
   HL_LONGLONG ilc_stat_len_recv;           /* statistic length of receives */
   HL_LONGLONG ilc_stat_len_send;           /* statistic length of sends */
   char       chrc_wsp_fingerprint[ DEF_LEN_FINGERPRINT ];  /* hash over WSP */
};

#ifndef EXT_WSP_ADM_SESSION_USERFLD
/**
   query active sessions
   name of query: session
   structure type: 0
   this structure is followed by up to two UTF-8 strings
*/
#endif
#ifdef EXT_WSP_ADM_SESSION_USERFLD
/**
   query active sessions
   name of query: session
   structure type: 0
   this structure is followed by up to two UTF-8 strings and one binary field
*/
#endif
/**
   usage of imc_len_user_group - length name user group UTF-8
   < 0 (-1) means all groups
   == 0 means session where group has length 0 (zero)
   exception:
   query for imc_len_userid == 0 and imc_len_user_group == 0
     returns all sessions
     maybe this should be changed in the future,
     so that with this setting,
     all sessions where group has length 0 (zero)
     and any user should be returned.
   17.08.14  KB
*/
struct dsd_wspadm1_q_session {              /* WSP query Administration Session */
   int        imc_session_no;               /* session number last before */
   int        imc_no_session;               /* number of sessions to retrieve */
   int        imc_len_userid;               /* length userid UTF-8     */
   int        imc_len_user_group;           /* length name user group UTF-8 */
#ifdef EXT_WSP_ADM_SESSION_USERFLD
   int        imc_len_userfld;              /* length user field in bytes */
#endif
   BOOL       boc_use_wildcard;             /* use wildcard in search  */
};

#ifndef EXT_WSP_ADM_SESSION_USERFLD
/**
   response for each active session
   name of query: session
   structure type: 0
   this structure is followed by seven variables:
     UTF-8 string gate name
     UTF-8 string Server Entry
     UTF-8 string protocol
     binary INETA and port connection to server
     UTF-8 string DN from certificate
     UTF-8 string userid
     UTF-8 string user-group
*/
#endif
#ifdef EXT_WSP_ADM_SESSION_USERFLD
/**
   response for each active session
   name of query: session
   structure type: 0
   this structure is followed by eight variables:
     UTF-8 string gate name
     UTF-8 string Server Entry
     UTF-8 string protocol
     binary INETA and port connection to server
     UTF-8 string DN from certificate
     UTF-8 string userid
     UTF-8 string user-group
     binary field userfld
*/
#endif
struct dsd_wspadm1_session {                /* WSP Administration Session */
   int        imc_len_gate_name;            /* length gate name UTF-8  */
   int        imc_len_serv_ent;             /* length name Server Entry UTF-8 */
   int        imc_len_protocol;             /* length of protocol UTF-8 */
   int        imc_len_ineta_port;           /* INETA and Port connection to server */
   int        imc_session_no;               /* session number          */
   char       chrc_ineta[40];               /* internet-address client char */
   int        imc_time_start;               /* time session started    */
   int        imc_c_ns_rece_c;              /* count receive client    */
   int        imc_c_ns_send_c;              /* count send client       */
   int        imc_c_ns_rece_s;              /* count receive server    */
   int        imc_c_ns_send_s;              /* count send server       */
   int        imc_c_ns_rece_e;              /* count encrypted from cl */
   int        imc_c_ns_send_e;              /* count encrypted to clie */
   HL_LONGLONG ilc_d_ns_rece_c;             /* data received client    */
   HL_LONGLONG ilc_d_ns_send_c;             /* data sent client        */
   HL_LONGLONG ilc_d_ns_rece_s;             /* data received server    */
   HL_LONGLONG ilc_d_ns_send_s;             /* data sent server        */
   HL_LONGLONG ilc_d_ns_rece_e;             /* data received encyrpted */
   HL_LONGLONG ilc_d_ns_send_e;             /* data sent encrypted     */
   int        imc_len_name_cert;            /* length name from certificate UTF-8 */
   int        imc_len_userid;               /* length userid UTF-8     */
   int        imc_len_user_group;           /* length name user group UTF-8 */
#ifdef EXT_WSP_ADM_SESSION_USERFLD
   int        imc_len_userfld;              /* length user field in bytes */
#endif
};

/**
   response for each listen
   name of query: listen
   structure type: 0
   this structure is followed by one UTF-8 string
     and multiple structures type 1
*/
struct dsd_wspadm1_listen_main {            /* WSP Administration Listen */
   int        imc_len_gate_name;            /* length gate name UTF-8  */
   int        imc_epoch_conf_loaded;        /* time / epoch configuration loaded */
   BOOL       boc_active_conf;              /* listen is from active configuration */
   BOOL       boc_use_listen_gw;            /* listen over listen gateway */
   int        imc_gateport;                 /* TCP/IP port listen      */
   int        imc_backlog;                  /* TCP/IP backlog listen   */
   int        imc_timeout;                  /* timeout in seconds      */
   int        imc_thresh_session;           /* threshold-session       */
   BOOL       boc_cur_thresh_session;       /* currently over threshold-session */
   int        imc_epoch_thresh_se_notify;   /* last time of threshold-session notify */
   int        imc_session_max;              /* maximum number of sess  */
   int        imc_session_cos;              /* count start of session  */
   int        imc_session_cur;              /* current number of sess  */
   int        imc_session_mre;              /* maximum no sess reached */
   int        imc_session_exc;              /* number max session exce */
};

/**
   response for each listen
   name of query: listen
   structure type: 1
   this structure is followed by the INETA
*/
struct dsd_wspadm1_listen_ineta {           /* WSP Administration Listen */
   BOOL       boc_listen_active;            /* listen is active        */
   int        imc_len_ineta;                /* length of INETA in bytes */
};

/**
   response for performance data
   name of query: perfdata
   structure type: 0
*/
struct dsd_wspadm1_perfdata_appl {          /* WSP Administration performance data */
   int        imc_sum_cpu;                  /* CPU time used           */
   HL_LONGLONG ilc_memory_cur;              /* current memory used     */
   int        imc_sum_network;              /* networking data         */
   int        imc_loadbal_cur;              /* current loadbalancing value */
};

/**
   response for performance data
   name of query: perfdata
   structure type: 1
*/
struct dsd_wspadm1_perfdata_threads {       /* WSP Administration performance data */
   int        imc_max_poss_workthr;         /* max possible work thr   */
   int        imc_max_act_workthr;          /* max active work thr     */
   int        imc_workthr_alloc;            /* allocated work threads  */
   int        imc_workthr_sched;            /* scheduled work threads  */
   int        imc_workthr_active;           /* active work threads     */
   int        imc_workque_sched;            /* work queue scheduled    */
   int        imc_workque_max_no;           /* work queue maximum      */
   int        imc_workque_max_time;         /* for time of maximum     */
   int        imc_prio_thr;                 /* priority of one thread  */
};

enum ied_wspadm1_logreq1_def {              /* admin log request 1 definition */
   ied_wa1l_invalid = 0,                    /* invalid value           */
   ied_wa1l_cur = 1,                        /* return current / last records */
   ied_wa1l_pos = 2,                        /* read from position      */
   ied_wa1l_epoch = 3,                      /* read records with this epoch */
   ied_wa1l_upd_start = 4,                  /* start dynamic update    */
   ied_wa1l_upd_stop = 5                    /* stop dynamic update     */
};

/**
   query log messages
   name of query: log
   structure type: 0
   this structure may followed by one UTF-8 string
*/
struct dsd_wspadm1_q_log {                  /* WSP query log           */
   HL_LONGLONG ilc_position;                /* position where to read  */
   int        imc_count_filled;             /* count how often filled  */
#ifdef B100908
   int        imc_epoch;                    /* epoch / time of log record */
#endif
   HL_LONGLONG ilc_epoch;                   /* epoch / time of log record */
   int        imc_len_query;                /* length of following query string, UTF-8 */
   BOOL       boc_query_regex;              /* query is regular expression */
   BOOL       boc_backward;                 /* read backward           */
   int        imc_retr_no_rec;              /* retrieve number of records */
   ied_wspadm1_logreq1_def iec_wa1l;        /* admin log request 1 definition */
};

/**
   response for log messages
   name of query: log
   structure type: 0
   this structure is followed by one UTF-8 string
*/
struct dsd_wspadm1_log {                    /* WSP log record          */
   HL_LONGLONG ilc_position;                /* position where to read  */
   int        imc_count_filled;             /* count how often filled  */
#ifdef B100908
   int        imc_epoch;                    /* epoch / time of log record */
#endif
   HL_LONGLONG ilc_epoch;                   /* epoch / time of log record */
   int        imc_len_msg;                  /* length of following message, UTF-8 */
};

/**
   disconnect a SSL / TCP session
   name of query: cancel-session
   structure type: 0
*/
struct dsd_wspadm1_q_can_sess_1 {           /* WSP cancel session      */
   int        imc_session_no;               /* session number          */
};

/**
   response to disconnect a SSL / TCP session
   name of query: cancel-session
   structure type: 0
*/
struct dsd_wspadm1_r_can_sess_1 {           /* WSP cancel session      */
   BOOL       boc_ok;                       /* cancel session successful */
};


enum ied_wspadm1_wsp_trace_def {            /* admin WSP Trace definition */
   ied_wawt_invalid = 0,                    /* invalid value           */
   ied_wawt_target,                         /* define new target       */
   ied_wawt_trace_new_ineta_all,            /* trace all INETAs        */
   ied_wawt_trace_new_ineta_spec,           /* trace specific INETA    */
   ied_wawt_trace_del_ineta_all,            /* delete trace all INETAs */
   ied_wawt_trace_del_ineta_spec,           /* delete trace specific INETA */
   ied_wawt_trace_new_core,                 /* new parameters trace WSP core */
   ied_wawt_trace_cma_dump                  /* make a dump of the CMA  */
};

enum ied_wsp_trace_target {                 /* WSP Trace target        */
   ied_wtt_invalid = 0,                     /* invalid value           */
   ied_wtt_console,                         /* print on console        */
   ied_wtt_file_ascii,                      /* trace records to file ASCII */
   ied_wtt_file_bin,                        /* trace records to file binary */
   ied_wtt_xyz                              /* trace records to xyz    */
};

struct dsd_wspadm1_q_wsp_trace_1 {          /* WSP Trace               */
   enum ied_wspadm1_wsp_trace_def iec_wawt;  /* admin WSP Trace definition */
   union {
     int      imc_trace_level;              /* trace level             */
     enum ied_wsp_trace_target iec_wtt;     /* WSP Trace target        */
   };
};

struct dsd_wspadm1_r_wsp_tr_act_1 {         /* reply WSP Trace active settings */
   BOOL       boc_allow_wsp_trace;          /* configured <allow-wsp-trace> */
   enum ied_wsp_trace_target iec_wtt;       /* WSP Trace target        */
   int        imc_wsp_trace_core_flags1;    /* WSP trace core flags    */
   BOOL       boc_sess_trace_ineta_all;     /* trace all INETAS        */
   int        imc_sess_ia_trace_level;      /* trace all INETAS trace-level */
   int        imc_sess_no_single_ineta;     /* trace started for single INETAs */
};

#define DEF_WSPADM_RT_INV_PARAM   0XF0      /* invalid parameters      */
#define DEF_WSPADM_RT_EOF         0XF1      /* end-of-file             */
#define DEF_WSPADM_RT_INV_REQ     0XF2      /* invalid request         */
#define DEF_WSPADM_RT_RESOURCE_UA 0XF3      /* resource unavailable    */
#define DEF_WSPADM_RT_TIMEOUT     0XF4      /* timeout while processing command */
#define DEF_WSPADM_RT_CLUSTER     0XF5      /* error invalid cluster   */
#define DEF_WSPADM_RT_PROC_E      0XF6      /* processing error        */
#define DEF_WSPADM_RT_MISC        0XF7      /* miscellaneous           */
