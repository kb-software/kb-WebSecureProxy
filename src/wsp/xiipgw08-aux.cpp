//#define D_MAKE_ERROR_070727
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif

/** process first level aux callback routine                           */
extern "C" BOOL m_cdaux( void * vpp_userfld, int imp_func, void * apparam, int imp_length ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_text_1;                   /* length output text      */
   int        iml_dump_1;                   /* length output dump      */
   enum ied_wsp_trace_record_type iel_wtrt;  /* record type of WSP trace */
   char       *achl_func;                   /* text of function        */
   char       *achl_text_1;                 /* output text             */
   char       *achl_dump_1;                 /* output dump             */
   char   *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_record *adsl_wtr_in;  /* WSP trace record input */
   char       chrl_work1[ 512 ];

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

#ifdef PROBLEM_090225                       /* hangs at close          */
   if (vpp_userfld) {
     m_clconn1_last_action( ADSL_CONN1_G, 2000 + inp_func );  /* last action */
     ADSL_CONN1_G->achc_last_action = "xiipgw08-aux call l"PREPINT(__LINE__);  /* text last action */
   }
   bol1 = m_secondary_aux( vpp_userfld, imp_func, apparam, imp_length );
   if (vpp_userfld) {
     m_clconn1_last_action( ADSL_CONN1_G, 3000 + 100 * bol1 + inp_func );  /* last action */
     ADSL_CONN1_G->achc_last_action = "xiipgw08-aux return l"PREPINT(__LINE__);  /* text last action */
   }
   return bol1;
#endif
   if (imp_func == DEF_AUX_WSP_TRACE) {     /* write WSP trace         */
     goto p_wt_00;                          /* command WSP Trace       */
   }
   if (   (vpp_userfld == NULL)
       || (ADSL_CONN1_G == NULL)            /* no connection passed    */
       || ((ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) == 0)) {  /* do not generate WSP trace record */
     return m_secondary_aux( vpp_userfld, imp_func, apparam, imp_length );
   }
#define HL_MAX_AUX_TEXT sizeof(chrl_work1)
   iml_text_1 = 0;                          /* length output text      */
   iml_dump_1 = 0;                          /* length output dump      */
   achl_func = "** undefined **";           /* text of function        */
   switch (imp_func) {
     case DEF_AUX_MEMGET:
       achl_func = "DEF_AUX_MEMGET";        /* text of function        */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(void *);         /* length output dump      */
       break;
     case DEF_AUX_MEMFREE:                  // release a block of memory
       achl_func = "DEF_AUX_MEMFREE";       /* text of function        */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(void *);         /* length output dump      */
       break;
     case DEF_AUX_CONSOLE_OUT:
       achl_func = "DEF_AUX_CONSOLE_OUT";   /* text of function        */
       if (imp_length > HL_MAX_AUX_TEXT) break;
       achl_text_1 = (char *) apparam;      /* output text             */
       iml_text_1 = imp_length;             /* length output text      */
       break;
     case DEF_AUX_CO_UNICODE:
       achl_func = "DEF_AUX_CO_UNICODE";    /* text of function        */
       break;
#ifdef WORK051124
     case DEF_AUX_CHECK_USERID:             /* check userid            */
       achl_func = "DEF_AUX_CHECK_USERID";  /* text of function        */
       break;
#endif
     case DEF_AUX_RADIUS_QUERY:             /* do Radius query         */
       achl_func = "DEF_AUX_RADIUS_QUERY";  /* text of function        */
       break;
     case DEF_AUX_RADIUS_FREE:              /* free data received from radius */
       achl_func = "DEF_AUX_RADIUS_FREE";   /* text of function        */
       break;
     case DEF_AUX_DISKFILE_ACCESS:
       achl_func = "DEF_AUX_DISKFILE_ACCESS";  /* text of function     */
       if (imp_length != sizeof(struct dsd_hl_aux_diskfile_1)) break;  /* not correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = imp_length;             /* length output dump      */
       break;
     case DEF_AUX_DISKFILE_RELEASE:         // release a disk file
       achl_func = "DEF_AUX_DISKFILE_RELEASE";  /* text of function    */
       break;
     case DEF_AUX_DISKFILE_TIME_LM:         /* get time last modified  */
       achl_func = "DEF_AUX_DISKFILE_TIME_LM";  /* text of function    */
       break;
     case DEF_AUX_GET_TIME:
       achl_func = "DEF_AUX_GET_TIME";      /* text of function        */
       break;
     case DEF_AUX_GET_CERTIFICATE:          /* get address certificate */
       achl_func = "DEF_AUX_GET_CERTIFICATE";  /* text of function     */
       break;
     case DEF_AUX_STRING_FROM_EPOCH:
       achl_func = "DEF_AUX_STRING_FROM_EPOCH";  /* text of function   */
       break;
     case DEF_AUX_EPOCH_FROM_STRING:
       achl_func = "DEF_AUX_EPOCH_FROM_STRING";  /* text of function   */
       break;
     case DEF_AUX_GET_DN:                   /* get address Distinguished Name */
       achl_func = "DEF_AUX_GET_DN";        /* text of function        */
       break;
     case DEF_AUX_GET_AUTH:                 /* get authentication      */
       achl_func = "DEF_AUX_GET_AUTH";      /* text of function        */
       break;
     case DEF_AUX_TCP_CONN:                 /* new TCP connection server */
       achl_func = "DEF_AUX_TCP_CONN";      /* text of function        */
       break;
     case DEF_AUX_TCP_CLOSE:                /* close TCP to Server     */
       achl_func = "DEF_AUX_TCP_CLOSE";     /* text of function        */
       break;
     case DEF_AUX_QUERY_CLIENT:             /* query TCP client connection */
       achl_func = "DEF_AUX_QUERY_CLIENT";  /* text of function        */
       break;
     case DEF_AUX_QUERY_RECEIVE:            /* query TCP data          */
       achl_func = "DEF_AUX_QUERY_RECEIVE";  /* text of function       */
       break;
     case DEF_AUX_COM_CMA:                  /* command common memory area */
       achl_func = "DEF_AUX_COM_CMA";       /* text of function        */
//     if (imp_length != sizeof(struct dsd_get_servent_1)) break;  /* not correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = imp_length;             /* length output dump      */
       break;
     case DEF_AUX_RANDOM_RAW:
       achl_func = "DEF_AUX_RANDOM_RAW";    /* text of function        */
       break;
     case DEF_AUX_RANDOM_BASE64:
       achl_func = "DEF_AUX_RANDOM_BASE64";  /* text of function       */
       break;
     case DEF_AUX_CHECK_IDENT:              /* check ident - authenticate */
       achl_func = "DEF_AUX_CHECK_IDENT";   /* text of function        */
       break;
     case DEF_AUX_GET_SC_PROT:              /* get Server Entry Protocol */
       achl_func = "DEF_AUX_GET_SC_PROT";   /* text of function        */
       break;
     case DEF_AUX_COUNT_SERVENT:            /* count server entries    */
       achl_func = "DEF_AUX_COUNT_SERVENT";  /* text of function       */
//     if (imp_length != sizeof(struct dsd_get_servent_1)) break;  /* not correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = imp_length;             /* length output dump      */
       break;
     case DEF_AUX_GET_SERVENT:              /* get server entry        */
       achl_func = "DEF_AUX_GET_SERVENT";   /* text of function        */
//     if (imp_length != sizeof(struct dsd_get_servent_1)) break;  /* not correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = imp_length;             /* length output dump      */
       break;
     case DEF_AUX_CONN_PREPARE:             /* prepare for connect HOB-WSP-AT3 */
       achl_func = "DEF_AUX_CONN_PREPARE";  /* text of function        */
#ifndef B140724
       if (imp_length != sizeof(struct dsd_wspat3_conn)) break;  /* not correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(struct dsd_wspat3_conn);  /* length output dump */
#endif
       break;
     case DEF_AUX_QUERY_MAIN_STR:           /* query main program for string */
       achl_func = "DEF_AUX_QUERY_MAIN_STR";  /* text of function      */
       break;
     case DEF_AUX_TIMER1_SET:               /* set timer in milliseconds */
       achl_func = "DEF_AUX_TIMER1_SET";    /* text of function        */
       break;
     case DEF_AUX_TIMER1_REL:               /* release timer set before */
       achl_func = "DEF_AUX_TIMER1_REL";    /* text of function        */
       break;
     case DEF_AUX_TIMER1_QUERY:             /* return struct dsd_timer1_ret */
       achl_func = "DEF_AUX_TIMER1_QUERY";  /* text of function        */
       break;
     case DEF_AUX_QUERY_GATHER:             /* query Gather Structure, struct dsd_q_gather_1 */
       achl_func = "DEF_AUX_QUERY_GATHER";  /* text of function        */
       break;
     case DEF_AUX_GET_PRIV_SESSION:         /* return priviliges of session */
       achl_func = "DEF_AUX_GET_PRIV_SESSION";  /* text of function    */
       break;
     case DEF_AUX_PUT_SESS_STOR:            /* put Session Storage     */
       achl_func = "DEF_AUX_PUT_SESS_STOR";  /* text of function       */
       break;
     case DEF_AUX_GET_SESS_STOR:            /* get Session Storage     */
       achl_func = "DEF_AUX_GET_SESS_STOR";  /* text of function       */
       break;
     case DEF_AUX_DESCR_SESS_STOR:          /* get Session Storage Descriptor */
       achl_func = "DEF_AUX_DESCR_SESS_STOR";  /* text of function     */
       break;
     case DEF_AUX_QUERY_SYSADDR:            /* return array with system addresses */
       achl_func = "DEF_AUX_QUERY_SYSADDR";  /* text of function       */
       break;
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
       achl_func = "DEF_AUX_GET_WORKAREA";  /* text of function        */
       break;
     case DEF_AUX_GET_T_MSEC:               /* get time / epoch in milliseconds */
       achl_func = "DEF_AUX_GET_T_MSEC";    /* text of function        */
       break;
     case DEF_AUX_MARK_WORKAREA_INC:        /* increment usage count in work area */
       achl_func = "DEF_AUX_MARK_WORKAREA_INC";  /* text of function   */
       break;
     case DEF_AUX_MARK_WORKAREA_DEC:        /* decrement usage count in work area */
       achl_func = "DEF_AUX_MARK_WORKAREA_DEC";  /* text of function   */
       break;
     case DEF_AUX_SERVICE_REQUEST:          /* service request         */
       achl_func = "DEF_AUX_SERVICE_REQUEST";  /* text of function     */
       break;
     case DEF_AUX_LDAP_REQUEST:             /* LDAP service request    */
       achl_func = "DEF_AUX_LDAP_REQUEST";  /* text of function        */
       break;
     case DEF_AUX_SDH_OBJECT:               /* Server-Data-Hook object */
       achl_func = "DEF_AUX_SDH_OBJECT";    /* text of function        */
       break;
     case DEF_AUX_SIP_REQUEST:              /* SIP protocol request    */
       achl_func = "DEF_AUX_SIP_REQUEST";   /* text of function        */
       break;
     case DEF_AUX_UDP_REQUEST:              /* UDP request             */
       achl_func = "DEF_AUX_UDP_REQUEST";   /* text of function        */
       break;
     case DEF_AUX_GET_IDENT_SETTINGS:       /* return settings of this user */
       achl_func = "DEF_AUX_GET_IDENT_SETTINGS";  /* text of function  */
       break;
     case DEF_AUX_SESSION_CONF:             /* configure session parameters */
       achl_func = "DEF_AUX_SESSION_CONF";  /* text of function        */
       break;
     case DEF_AUX_ADMIN:                    /* administration command  */
       achl_func = "DEF_AUX_ADMIN";         /* text of function        */
       break;
     case DEF_AUX_SET_IDENT:                /* set ident - userid and user-group */
       achl_func = "DEF_AUX_SET_IDENT";     /* text of function        */
       break;
     case DEF_AUX_GET_CONN_SNO:             /* get connection SNO session number */
       achl_func = "DEF_AUX_GET_CONN_SNO";  /* text of function        */
       break;
     case DEF_AUX_GET_RADIUS_CONF:          /* get Radius group Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_get_radius_entry)) {};  /* correct size */
       achl_func = "DEF_AUX_GET_RADIUS_CONF";  /* text of function     */
       break;
     case DEF_AUX_SET_RADIUS_CONF:          /* set Radius group Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_set_radius_entry)) {};  /* correct size */
       achl_func = "DEF_AUX_SET_RADIUS_CONF";  /* text of function     */
       break;
     case DEF_AUX_REL_RADIUS_CONF:          /* release Radius group Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_rel_radius_entry)) {};  /* correct size */
       achl_func = "DEF_AUX_REL_RADIUS_CONF";  /* text of function     */
       break;
     case DEF_AUX_KRB5_SIGN_ON:             /* sign-on with Kerberos   */
       achl_func = "DEF_AUX_KRB5_SIGN_ON";  /* text of function        */
       break;
     case DEF_AUX_KRB5_SE_TI_GET:           /* Kerberos get Service Ticket */
       achl_func = "DEF_AUX_KRB5_SE_TI_GET";  /* text of function      */
       break;
     case DEF_AUX_KRB5_SE_TI_C_R:           /* Kerberos check Service Ticket Response */
       achl_func = "DEF_AUX_KRB5_SE_TI_C_R";  /* text of function      */
       break;
     case DEF_AUX_KRB5_GET_SESS_KEY:        /* Kerberos-5 retrieve session key */
       achl_func = "DEF_AUX_KRB5_GET_SESS_KEY";  /* text of function      */
       break;
     case DEF_AUX_KRB5_ENCRYPT:             /* Kerberos encrypt data   */
       achl_func = "DEF_AUX_KRB5_ENCRYPT";  /* text of function        */
       break;
     case DEF_AUX_KRB5_DECRYPT:             /* Kerberos decrypt data   */
       achl_func = "DEF_AUX_KRB5_DECRYPT";  /* text of function        */
       break;
     case DEF_AUX_KRB5_SE_TI_REL:           /* Kerberos release Service Ticket Resources */
       achl_func = "DEF_AUX_KRB5_SE_TI_REL";  /* text of function      */
       break;
     case DEF_AUX_KRB5_LOGOFF:              /* release Kerberos TGT    */
       achl_func = "DEF_AUX_KRB5_LOGOFF";   /* text of function        */
       break;
     case DEF_AUX_GET_KRB5_CONF:            /* get Kerberos Configuration Entry */
       achl_func = "DEF_AUX_GET_KRB5_CONF";  /* text of function       */
       break;
     case DEF_AUX_SET_KRB5_CONF:            /* set Kerberos Configuration Entry */
       achl_func = "DEF_AUX_SET_KRB5_CONF";  /* text of function       */
       break;
     case DEF_AUX_REL_KRB5_CONF:            /* release Kerberos Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_rel_krb5_entry)) {};  /* correct size */
       achl_func = "DEF_AUX_REL_KRB5_CONF";  /* text of function       */
       break;
     case DEF_AUX_SESSION_KRB5_CONF:        /* assign Kerberos Configuration Entry to session */
       if (imp_length == sizeof(struct dsd_aux_krb5_session_assign_conf)) {};  /* correct size */
       achl_func = "DEF_AUX_SESSION_KRB5_CONF";  /* text of function   */
       break;
     case DEF_AUX_GET_LDAP_CONF:            /* get LDAP Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_get_ldap_entry))  {};  /* correct size */
       achl_func = "DEF_AUX_GET_LDAP_CONF";  /* text of function        */
       break;
     case DEF_AUX_SET_LDAP_CONF:            /* set LDAP Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_set_ldap_entry))  {};  /* correct size */
       achl_func = "DEF_AUX_SET_LDAP_CONF";  /* text of function       */
       break;
     case DEF_AUX_REL_LDAP_CONF:            /* release LDAP Configuration Entry */
       if (imp_length == sizeof(struct dsd_aux_rel_ldap_entry))  {};  /* correct size */
       achl_func = "DEF_AUX_REL_LDAP_CONF";  /* text of function       */
       break;
     case DEF_AUX_GET_SESSION_INFO:         /* get information about the session */
       if (imp_length == sizeof(struct dsd_aux_get_session_info)) {};  /* correct size */
       achl_func = "DEF_AUX_GET_SESSION_INFO";  /* text of function    */
       break;
     case DEF_AUX_UDP_GATE:                 /* handle UDP-gate         */
       if (imp_length == sizeof(struct dsd_aux_cmd_udp_gate)) {};  /* correct size */
       achl_func = "DEF_AUX_UDP_GATE";      /* text of function        */
       break;
     case DEF_AUX_NOT_DROP_TCP_PACKET:      /* do not drop TCP packets */
       if (imp_length == sizeof(BOOL)) {};  /* correct size            */
       achl_func = "DEF_AUX_NOT_DROP_TCP_PACKET";  /* text of function */
       break;
     case DEF_AUX_GET_DUIA:                 /* get domain userid INETA */
       if (imp_length == sizeof(struct dsd_aux_get_duia_1)) {};  /* correct size */
       achl_func = "DEF_AUX_GET_DUIA";      /* text of function        */
       break;
     case DEF_AUX_SECURE_XOR:               /* apply secure XOR        */
       if (imp_length == sizeof(struct dsd_aux_secure_xor_1)) {};  /* correct size */
       achl_func = "DEF_AUX_SECURE_XOR";    /* text of function        */
       break;
     case DEF_AUX_WEBSO_CONN:               /* connect for WebSocket applications */
       if (imp_length == sizeof(struct dsd_aux_webso_conn_1)) {};  /* correct size */
       achl_func = "DEF_AUX_WEBSO_CONN";    /* text of function        */
       break;
     case DEF_AUX_SECURE_RANDOM:            /* get secure random       */
       achl_func = "DEF_AUX_SECURE_RANDOM";  /* text of function       */
       break;
     case DEF_AUX_GET_WSP_FINGERPRINT:      /* get WSP fingerprint     */
       achl_func = "DEF_AUX_GET_WSP_FINGERPRINT";  /* text of function */
       break;
     case DEF_AUX_PIPE:                     /* aux-pipe                */
       achl_func = "DEF_AUX_PIPE";          /* text of function        */
       break;
     case DEF_AUX_UTILITY_THREAD:           /* create unitliy thread   */
       achl_func = "DEF_AUX_UTILITY_THREAD";  /* text of function      */
       break;
     case DEF_AUX_SWAP_STOR:                /* manage swap storage     */
       achl_func = "DEF_AUX_SWAP_STOR";     /* text of function        */
       break;
     case DEF_AUX_DYN_LIB:                  /* manage dynamic library  */
       achl_func = "DEF_AUX_DYN_LIB";       /* text of function        */
       break;
     case DEF_AUX_SIG_GET_CLIENT:           /* signature - get client credentials */
       achl_func = "DEF_AUX_SIG_GET_CLIENT";  /* text of function      */
       break;
     case DEF_AUX_SIG_SIGN_NONCE:           /* signature - sign nonce  */
       achl_func = "DEF_AUX_SIG_SIGN_NONCE";  /* text of function      */
       break;
     case DEF_AUX_SET_SESSION_TIMEOUT:      /* set session timeout     */
       achl_func = "DEF_AUX_SET_SESSION_TIMEOUT";  /* text of function */
       break;
     case DEF_AUX_GET_DOMAIN_INFO:          /* retrieve domain-information of connection - gate */
       achl_func = "DEF_AUX_GET_DOMAIN_INFO";  /* text of function     */
       break;
     case DEF_AUX_GET_RPC_CONF:             /* get RPC Configuration Entry */
       achl_func = "DEF_AUX_GET_RPC_CONF";  /* text of function        */
       break;
     case DEF_AUX_SET_RPC_CONF:             /* set RPC Configuration Entry */
       achl_func = "DEF_AUX_SET_RPC_CONF";  /* text of function        */
       break;
     case DEF_AUX_REL_RPC_CONF:             /* release RPC Configuration Entry */
       achl_func = "DEF_AUX_REL_RPC_CONF";  /* text of function        */
       break;
#ifdef XYZ1
     case DEF_AUX_AUTH_RPC:                 /* authenticate over RPC   */
       achl_func = "DEF_AUX_AUTH_RPC";      /* text of function        */
       break;
#endif
#ifdef INCL_TEST_RPC
     case DEF_AUX_AUTH_RPC_NTLMV2:          /* authenticate NTLMv2 over RPC */
       if (imp_length == sizeof(struct dsd_aux_auth_rpc_ntlmv2_1)) {  /* correct size */
         achl_dump_1 = (char *) apparam;    /* output dump             */
         iml_dump_1 = sizeof(struct dsd_aux_auth_rpc_ntlmv2_1);  /* length output dump */
       }
       achl_func = "DEF_AUX_AUTH_RPC_NTLMV2";
       break;
#endif
     case DEF_AUX_FILE_IO:                  /* file input-output       */
       achl_func = "DEF_AUX_FILE_IO";       /* text of function        */
       break;
     case DEF_AUX_SET_LOCAL_USER:           /* set local user          */
       achl_func = "DEF_AUX_SET_LOCAL_USER";  /* text of function      */
       break;
     case DEF_AUX_CHECK_LOGOUT:             /* check logout at sign on */
       achl_func = "DEF_AUX_CHECK_LOGOUT";  /* text of function        */
       break;
     case DEF_AUX_GET_ADDR_SERVER_ERROR:    /* get address zero-terminated message server error */
       achl_func = "DEF_AUX_GET_ADDR_SERVER_ERROR";  /* text of function */
       if (imp_length != sizeof(void *)) break;  /* correct size       */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(void *);         /* length output dump      */
       break;
     case DEF_AUX_GET_SSL_SERVER_CERT:      /* get address SSL used server certificate */
       achl_func = "DEF_AUX_GET_SSL_SERVER_CERT";  /* text of function */
       if (imp_length != sizeof(struct dsd_hl_aux_ssl_get_server_cert)) break;  /* correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(struct dsd_hl_aux_ssl_get_server_cert);  /* length output dump */
       break;
     case DEF_AUX_SDH_RELOAD:               /* manage SDH reload       */
       achl_func = "DEF_AUX_SDH_RELOAD";    /* text of function        */
       if (imp_length != sizeof(struct dsd_hl_aux_manage_sdh_reload)) break;  /* correct size */
       achl_dump_1 = (char *) apparam;      /* output dump             */
       iml_dump_1 = sizeof(struct dsd_hl_aux_manage_sdh_reload);  /* length output dump */
       break;
     case DEF_AUX_DEBUG_CHECK:              /* debug check             */
       achl_func = "DEF_AUX_DEBUG_CHECK";   /* text of function        */
       break;
     case DEF_AUX_RANDOM_VISIBLE:           /* get visible secure random - nonce */
       achl_func = "DEF_AUX_RANDOM_VISIBLE";  /* text of function      */
       break;
     case DEF_AUX_RANDOM_HIDDEN:            /* get hidden secure random */
       achl_func = "DEF_AUX_RANDOM_HIDDEN";  /* text of function       */
       break;
     case DEF_AUX_GET_CS_SSL_ADDR:          /* get addresses of client-side SSL implementation */
       achl_func = "DEF_AUX_GET_CS_SSL_ADDR";  /* text of function     */
       break;
   }
#undef HL_MAX_AUX_TEXT
   bol1 = m_secondary_aux( vpp_userfld, imp_func, apparam, imp_length );
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
#ifdef B110504
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
   adsl_wt1_w1->imc_len_text                /* length of text this record */
     = sprintf( (char *) (adsl_wt1_w1 + 1),
                "SNO=%08d aux-call( %p , %d , %p , %d ) %s returned %d.",
                ADSL_CONN1_G->dsc_co_sort.imc_sno, vpp_userfld, imp_func, apparam, imp_length, achl_func, bol1 );
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return bol1;
#endif
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXCALL", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
   iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                   "aux-call( %p , %d , %p , %d ) %s returned %d.",
                   vpp_userfld, imp_func, apparam, imp_length, achl_func, bol1 );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
   ADSL_WTR_G1->imc_length = iml1;          /* length of text / data   */
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#ifdef NOT_YET_140804
#ifndef B140804
   struct dsd_wsp_trace_record *adsl_wtr_h1 = ADSL_WTR_G1;
// struct dsd_wsp_trace_1 *adsl_wt1_h1 = adsl_wt1_w1;
   adsl_wt1_w2 = adsl_wt1_w1;
#endif
#endif
   if (iml_text_1 > 0) {                    /* length output text      */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     memcpy( ADSL_WTR_G2 + 1, achl_text_1, iml_text_1 );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G2->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G2 + 1);
     ADSL_WTR_G2->imc_length = iml_text_1;  /* length of text / data   */
#ifdef NOT_YET_140804
#ifndef B140804
     adsl_wtr_h1 = ADSL_WTR_G2;
#endif
#endif
   } else if (iml_dump_1 > 0) {             /* length output dump      */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     memcpy( ADSL_WTR_G2 + 1, achl_dump_1, iml_dump_1 );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G2 + 1);
     ADSL_WTR_G2->imc_length = iml_dump_1;  /* length of text / data   */
#ifdef NOT_YET_140804
#ifndef B140804
     adsl_wtr_h1 = ADSL_WTR_G2;
#endif
#endif
   }
#ifdef NOT_YET_140804
#ifndef B140804
   if (imp_func == DEF_AUX_COM_CMA) {       /* command common memory area */
#define ADSL_AC1 ((struct dsd_hl_aux_c_cma_1 *) apparam)
     struct dsd_wsp_trace_record *adsl_wtr_h2 = adsl_wtr_h1;
     int imh1 = ADSL_AC1->inc_len_cma_name;             /* length cma name in elements */
     int imh2;
     if (   (ADSL_AC1->iec_chs_name == ied_chs_utf_16)
         || (ADSL_AC1->iec_chs_name == ied_chs_be_utf_16)
         || (ADSL_AC1->iec_chs_name == ied_chs_le_utf_16)) {
       imh1 <<= 1;
     }
     if (imh1 > 0) {
       adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
       adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
       adsl_wt1_w2 = adsl_wt1_w3;  /* this is current network */

       achl_w1 = (char *) (adsl_wt1_w2 + 1);
       achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G3 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G3, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G3->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       achl_w3 = (char *) (ADSL_WTR_G3 + 1);  /* here starts content */
       imh2 = achl_w2 - achl_w3;
       if (imh2 > imh1) imh2 = imh1;
       memcpy( achl_w3, ADSL_AC1->ac_cma_name, imh2 );
       ADSL_WTR_G3->achc_content              /* content of text / data  */
         = (char *) (ADSL_WTR_G3 + 1);
       ADSL_WTR_G3->imc_length = imh2;  /* length of text / data   */
       adsl_wtr_h1->adsc_next = ADSL_WTR_G3;
       adsl_wtr_h1 = ADSL_WTR_G3;
#undef ADSL_WTR_G3
     }
     imh1 = ADSL_AC1->inc_len_cma_area;             /* length of cma area      */
     if (ADSL_AC1->achc_cma_area == NULL) {
       imh1 = 0;
     }
     if (imh1 > 0) {
//----
       if (   (imh1 >= 0X94)
           && (!memcmp( (char *) ADSL_AC1->achc_cma_area + 0X8C, "56780000", 8 ))) {
         m_hlnew_printf( HLOG_TRACE1, "l%05d CMA",
                         __LINE__ );
       }

//----
       adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
       adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
       adsl_wt1_w2 = adsl_wt1_w3;  /* this is current network */

       achl_w1 = (char *) (adsl_wt1_w2 + 1);
       achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G3 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G3, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G3->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       achl_w3 = (char *) (ADSL_WTR_G3 + 1);  /* here starts content */
       imh2 = achl_w2 - achl_w3;
       if (imh2 > imh1) imh2 = imh1;
       memcpy( achl_w3, ADSL_AC1->achc_cma_area, imh2 );
       ADSL_WTR_G3->achc_content              /* content of text / data  */
         = (char *) (ADSL_WTR_G3 + 1);
       ADSL_WTR_G3->imc_length = imh2;  /* length of text / data   */
       adsl_wtr_h1->adsc_next = ADSL_WTR_G3;
       adsl_wtr_h1 = ADSL_WTR_G3;
#undef ADSL_WTR_G3
     }
#undef ADSL_AC1
   }
#endif
#endif
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return bol1;

   p_wt_00:                                 /* command WSP Trace       */
#define ADSL_WTRH_G ((struct dsd_wsp_trace_header *) apparam)
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, ADSL_WTRH_G->chrc_wtrt_id, sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = ADSL_WTRH_G->imc_wtrh_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
   achl_w1 = (char *) (adsl_wt1_w1 + 1);    /* here is area for trace records */
   achl_w2 = (char *) adsl_wt1_w1 + LEN_TCP_RECV;  /* end of this piece of memory */
   adsl_wt1_w1->adsc_wsp_trace_record = (struct dsd_wsp_trace_record *) achl_w1;  /* WSP trace records */
   adsl_wtr_in = ADSL_WTRH_G->adsc_wtrh_chain;  /* chain of WSP trace records */
   adsl_wt1_w2 = adsl_wt1_w1;               /* current trace area      */
   adsl_wtr_w1 = NULL;                      /* previous WSP trace record */
#undef ADSL_WTRH_G

   p_wt_20:                                 /* next input WSP Trace record */
   iel_wtrt = adsl_wtr_in->iec_wtrt;        /* record type of WSP trace */
   if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) > achl_w2) {
     adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );
#ifdef B130216
     achl_w1 = (char *) adsl_wt1_w3;        /* here is area for trace records */
#else
     achl_w1 = (char *) (adsl_wt1_w3 + 1);  /* here is area for trace records */
#endif
     achl_w2 = (char *) adsl_wt1_w3 + LEN_TCP_RECV;  /* end of this piece of memory */
     adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record    */
     adsl_wt1_w2 = adsl_wt1_w3;             /* this is current area    */
   }
   memset( achl_w1, 0, sizeof(struct dsd_wsp_trace_record) );
   if (adsl_wtr_w1) {                       /* previous WSP trace record */
     adsl_wtr_w1->adsc_next = (struct dsd_wsp_trace_record *) achl_w1;  /* WSP trace record */
   }
   adsl_wtr_w1 = (struct dsd_wsp_trace_record *) achl_w1;  /* WSP trace record */
   achl_w1 += sizeof(struct dsd_wsp_trace_record);
   achl_w4 = NULL;                          /* no start of record      */

   p_wt_40:                                 /* copy input WSP Trace record */
   achl_w3 = adsl_wtr_in->achc_content;     /* content of text / data  */
   iml1 = adsl_wtr_in->imc_length;          /* length of text / data   */
   while (TRUE) {                           /* loop for output of text / data */
     iml2 = achl_w2 - achl_w1;
     if (iml2 > iml1) iml2 = iml1;
     if (iml2 > 0) {
       if (achl_w4 == NULL) {               /* no start of record      */
         adsl_wtr_w1->iec_wtrt = iel_wtrt;  /* record type of WSP trace */
         adsl_wtr_w1->achc_content = achl_w4 = achl_w1;  /* content of text / data */
       }
       memcpy( achl_w1, achl_w3, iml2 );
       achl_w1 += iml2;
       achl_w3 += iml2;
       iml1 -= iml2;
       if (iml1 <= 0) break;                /* all copied              */
     }
     if (achl_w4) {                         /* with start of record    */
       adsl_wtr_w1->imc_length = achl_w1 - achl_w4;  /* length of text / data */
       adsl_wtr_w1->boc_more = TRUE;        /* more data to follow     */
     }
     adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
#ifndef B130312
     memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );
#endif
#ifdef B130216
     achl_w1 = (char *) adsl_wt1_w3;        /* here is area for trace records */
#else
     achl_w1 = (char *) (adsl_wt1_w3 + 1);  /* here is area for trace records */
#endif
     achl_w2 = (char *) adsl_wt1_w3 + LEN_TCP_RECV;  /* end of this piece of memory */
     adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record    */
     adsl_wt1_w2 = adsl_wt1_w3;             /* this is current area    */
     if (achl_w4) {                         /* with start of record    */
       memset( achl_w1, 0, sizeof(struct dsd_wsp_trace_record) );
       adsl_wtr_w1->adsc_next = (struct dsd_wsp_trace_record *) achl_w1;  /* WSP trace record */
       adsl_wtr_w1 = (struct dsd_wsp_trace_record *) achl_w1;  /* WSP trace record */
       adsl_wtr_w1->iec_wtrt = iel_wtrt;    /* record type of WSP trace */
       achl_w1 += sizeof(struct dsd_wsp_trace_record);
       adsl_wtr_w1->achc_content = achl_w4 = achl_w1;  /* content of text / data */
     }
   }
   adsl_wtr_w1->imc_length = achl_w1 - achl_w4;  /* length of text / data */
   if (adsl_wtr_in->boc_more) {             /* more data to follow     */
     adsl_wtr_in = adsl_wtr_in->adsc_next;  /* get next input record   */
     if (   (adsl_wtr_in == NULL)
         || (adsl_wtr_in->iec_wtrt != iel_wtrt)) {  /* record type of WSP trace */
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s aux() WSP Trace record invalid",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
       return FALSE;                        /* report error            */
     }
     goto p_wt_40;                          /* copy input WSP Trace record */
   }
   achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
   adsl_wtr_in = adsl_wtr_in->adsc_next;    /* get next input record   */
   if (adsl_wtr_in) {                       /* more data follows       */
     goto p_wt_20;                          /* next input WSP Trace record */
   }
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return TRUE;                             /* all done                */
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_cdaux()                                                     */

/** process secondary level aux callback routine                       */
static BOOL m_secondary_aux( void * vpp_userfld, int imp_func, void * apparam, int imp_length ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_rc;                       /* return code             */
   socklen_t  iml_so1;                      /* working variable        */
   HL_LONGLONG ill_w1;                      /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension field */
   struct dsd_auxf_1 **aadsl_auxf_1_cur;    /* current chain auxiliary extension fields */
#ifdef XYZ1
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */
#endif
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
   void       *vprl_message[DEF_MSG_PIPE_LEN];  /* message in pipe     */
#endif
#ifdef OLD01
   struct dsd_user_entry *adsl_usent_1;
   struct dsd_user_group *adsl_usgro_1;
#endif
#ifdef OLD_1112
#ifndef NOT_YET_UNIX_110808
   en_at_claddrtype iel_claddrtype;
#endif
   void * avol_client_netaddr;
#endif
#ifdef OLD_1112
   class dsd_radius_query *adsl_radqu_w1;   /* class Radius Query      */
#endif
#ifdef XYZ1
#ifndef OLD_1112
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
#endif
#endif
   struct dsd_auxf_1 *adsl_auxf_1_raq;      /* aux ext fi radius query */
#ifdef OLD_1112
   struct dsd_auxf_1 *adsl_auxf_1_dnc;      /* aux ext fi DN certificate */
#endif
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
#ifndef NO_LDAP_071116
   struct dsd_ldap_group *adsl_ldap_group_w1;  /* definition LDAP group */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifndef WSP_V24
   struct dsd_unicode_string dsl_us_userid;  /* for userid             */
#endif
   struct dsd_unicode_string dsl_us_password;  /* for password         */
   char       byrl_work1[ 256 ];            /* work area               */

#ifdef TRACEHL1
   ims_cdaux++;
   m_hlnew_printf( HLOG_XYZ1, "m_cdaux called 1 vpp_userfld=%p function=%d apparam=%p length=%d * count=%d",
                   vpp_userfld, imp_func, apparam, imp_length, ims_cdaux );
#endif
#define X_AUADDR  *((void **) apparam)
   if (vpp_userfld) goto pconn00;           /* with connection         */
   switch (imp_func) {
     case DEF_AUX_MEMGET:
       if (imp_length <= 0) return FALSE;
       X_AUADDR = malloc( imp_length );
       if (X_AUADDR) return TRUE;
#ifndef B170329
       m_hlnew_printf( HLOG_EMER1, "HWSPM025E out of memory - l%05d aux-call configuration",
                       __LINE__ );
#endif
       return FALSE;
     case DEF_AUX_MEMFREE:
       free( X_AUADDR );
       return TRUE;
     case DEF_AUX_CONSOLE_OUT:
       achl1 = "";
       iml1 = imp_length;
       if (iml1 > DEF_MAX_LEN_CO) {
         iml1 = DEF_MAX_LEN_CO;
         achl1 = "...";
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPM092I configuration display: %.*s%s",
                       iml1, apparam, achl1 );
       return TRUE;                         /* all done                */
     case DEF_AUX_CO_UNICODE:
       achl1 = "";
       iml1 = imp_length;
       if (iml1 > DEF_MAX_LEN_CO) {
         iml1 = DEF_MAX_LEN_CO;
         achl1 = "...";
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPM093I configuration display: %.*(ux)s%s",
                       iml1, apparam, achl1 );
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_TIME:
     case DEF_AUX_STRING_FROM_EPOCH:
     case DEF_AUX_EPOCH_FROM_STRING:
     case DEF_AUX_COM_CMA:                  /* command common memory area */
     case DEF_AUX_RANDOM_RAW:
     case DEF_AUX_RANDOM_BASE64:
     case DEF_AUX_QUERY_MAIN_STR:           /* query main program for string */
     case DEF_AUX_DEBUG_CHECK:              /* debug check             */
     case DEF_AUX_FILE_IO:                  /* file input-output       */
#ifdef HL_UNIX
#ifndef B160423
//   case DEF_AUX_SECURE_RANDOM:            /* get secure random       */
     case DEF_AUX_SECURE_RANDOM_SEED:       /* get secure random       */
//   case DEF_AUX_SECURE_SEED:              /* get secure seed         */
     case DEF_AUX_RANDOM_VISIBLE:           /* get visible secure random - nonce */
     case DEF_AUX_RANDOM_HIDDEN:            /* get hidden secure random */
#endif
#endif
     case DEF_AUX_GET_CS_SSL_ADDR:          /* get addresses of client-side SSL implementation */
       goto pconn00;                        /* process normal          */
   }
   return FALSE;

   pconn00:                                 /* with connection         */
#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (vpp_userfld) {
     ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
   }
#endif
#ifdef B080407
#ifdef TRACEHL1
#ifndef HL_UNIX
   {
     class clconn1 *adsh_clconn1_1;
     adsh_clconn1_1 = aconn1a;              /* get anchor              */
     while (adsh_clconn1_1) {               /* loop over all conn      */
       if (adsh_clconn1_1 == ADSL_CONN1_G) break;
       adsh_clconn1_1 = adsh_clconn1_1->getnext();  /* get next in chain */
     }
     if (adsh_clconn1_1 == NULL) {          /* connection not found    */
       m_hlnew_printf( HLOG_XYZ1, "m_cdaux called invalid connection - not in chain" );
     }
   }
#endif
#endif
#endif
   aadsl_auxf_1_cur = NULL;                 /* not current chain auxiliary extension fields */
   if (ADSL_AUX_CF1) {                      /* with connection         */
     if (ADSL_AUX_CF1->dsc_cid.iec_src_func != ied_src_fu_util_thread) {  /* not utility thread */
       aadsl_auxf_1_cur = &ADSL_CONN1_G->adsc_auxf_1;  /* current chain auxiliary extension fields */
     } else {                                 /* is utility thread       */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) ADSL_AUX_CF1->dsc_cid.ac_cid_addr)
       aadsl_auxf_1_cur = &ADSL_UTC_G->adsc_auxf_1;  /* current chain auxiliary extension fields */
#undef ADSL_UTC_G
     }
   }
   switch (imp_func) {
     case DEF_AUX_MEMGET:
       if (imp_length <= 0) return FALSE;
       adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + imp_length );
#ifdef B170329
       if (adsl_auxf_1_w1 == NULL) return FALSE;  /* out of memory     */
#endif
#ifndef B170329
       if (adsl_auxf_1_w1 == NULL) {        /* out of memory           */
         m_hlnew_printf( HLOG_EMER1, "HWSPM026E out of memory - l%05d aux-call session",
                         __LINE__ );
         return FALSE;
       }
#endif
       adsl_auxf_1_w1->iec_auxf_def = ied_auxf_normstor;  /* normal storage */
       memcpy( &adsl_auxf_1_w1->dsc_cid,
               &ADSL_AUX_CF1->dsc_cid,
               sizeof(struct dsd_cid) );    /* current Server-Data-Hook */
#ifdef TRACEHLP
       adsl_auxf_1_w1->inc_size_mem = imp_length;  /* size of memory      */
       ADSL_CONN1_G->inc_aux_mem_cur += adsl_auxf_1_w1->inc_size_mem;
       if (ADSL_CONN1_G->inc_aux_mem_max < ADSL_CONN1_G->inc_aux_mem_cur) {
         ADSL_CONN1_G->inc_aux_mem_max = ADSL_CONN1_G->inc_aux_mem_cur;
       }
#endif
#ifdef B130319
       adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
#else
       adsl_auxf_1_w1->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
       *aadsl_auxf_1_cur = adsl_auxf_1_w1;  /* set new current chain auxiliary extension fields */
#endif
       X_AUADDR = adsl_auxf_1_w1 + 1;
       return TRUE;                         /* all done                */
     case DEF_AUX_CONSOLE_OUT:
       achl1 = "";
       iml1 = imp_length;
       if (iml1 > DEF_MAX_LEN_CO) {
         iml1 = DEF_MAX_LEN_CO;
         achl1 = "...";
       }
#ifdef B130314
//     if (ADSL_AUX_CF1->iec_src_func == ied_src_fu_bgt_stat) {  /* background-task for statistic */
#endif
#ifndef B170224
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         m_hlnew_printf( HLOG_XYZ1, "HWSPM086I utility-thread display: %.*s%s",
                         iml1, apparam, achl1 );
         return TRUE;                       /* all done                */
       }
#endif
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_bgt_stat) {  /* background-task for statistic */
         m_hlnew_printf( HLOG_XYZ1, "HWSPR010I Report bgt display: %.*s%s",
                         iml1, apparam, achl1 );
         return TRUE;                       /* all done                */
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPS061I GATE=%(ux)s SNO=%08d INETA=%s display: %.*s%s",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       iml1, apparam, achl1 );
       return TRUE;                         /* all done                */
     case DEF_AUX_CO_UNICODE:
       achl1 = "";
       iml1 = imp_length;
       if (iml1 > DEF_MAX_LEN_CO) {
         iml1 = DEF_MAX_LEN_CO;
         achl1 = "...";
       }
#ifdef B130314
//     if (ADSL_AUX_CF1->iec_src_func == ied_src_fu_bgt_stat) {  /* background-task for statistic */
#endif
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_bgt_stat) {  /* background-task for statistic */
         m_hlnew_printf( HLOG_XYZ1, "HWSPR011I Report bgt display: %.*(ux)s%s",
                         iml1, apparam, achl1 );
         return TRUE;                       /* all done                */
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPS062I GATE=%(ux)s SNO=%08d INETA=%s display: %.*(ux)s%s",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       iml1, apparam, achl1 );
       return TRUE;                         /* all done                */
#ifdef WORK051124
     case DEF_AUX_CHECK_USERID:             /* check userid            */
#define ADSL_AUX_CHUSER ((struct dsd_hl_aux_chuser_1 *) apparam)
       dsl_us_userid.ac_str = ADSL_AUX_CHUSER->achc_name;  /* address of string */
       dsl_us_userid.imc_len_str = ADSL_AUX_CHUSER->inc_len_name;  /* length string in elements */
       dsl_us_userid.iec_chs_str = ied_chs_utf_8;  /* character set string */
       dsl_us_password.ac_str = ADSL_AUX_CHUSER->achc_password;  /* address of string */
       dsl_us_password.imc_len_str = ADSL_AUX_CHUSER->inc_len_password;  /* length string in elements */
       dsl_us_password.iec_chs_str = ied_chs_utf_8;  /* character set string */
       ADSL_AUX_CHUSER->iec_auth_def = m_auth_user(
                        &adsl_usent_1,
                        &adsl_usgro_1,
                        ADSL_CONN1_G,
                        &dsl_us_userid,
                        &dsl_us_password,
                        FALSE,
                        TRUE );
                      );
       return TRUE;                         /* all done                */
#undef ADSL_AUX_CHUSER
#endif
     case DEF_AUX_RADIUS_QUERY:             /* do Radius query         */
       /* check if radius server defined                               */
#ifdef OLD_1112
       if (ADSL_CONN1_G->adsc_gate1->inc_no_radius == 0) return FALSE;
#endif
#ifndef OLD_1112
       if (ADSL_CONN1_G->adsc_radius_group == NULL) return FALSE;  /* active Radius group */
#endif
       /* search radius query and dn from certificate                  */
       adsl_auxf_1_raq = NULL;              /* aux ext fi radius query */
#ifdef OLD_1112
// to-do 07.01.12 KB no need to search for certificate
       adsl_auxf_1_dnc = NULL;              /* aux ext fi DN certificate */
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get first element */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_radqu) {
           /* radius query found                                       */
           adsl_auxf_1_raq = adsl_auxf_1_w1;  /* aux ext fi radius query */
           if (adsl_auxf_1_dnc) break;
         } else if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
           /* name from certificate                                    */
           adsl_auxf_1_dnc = adsl_auxf_1_w1;  /* aux ext fi DN certificate */
           if (adsl_auxf_1_raq) break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
#endif
#ifndef OLD_1112
#ifdef B130319
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get first element */
#else
       adsl_auxf_1_w1 = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
#endif
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_radqu) {
           /* radius query found                                       */
           adsl_auxf_1_raq = adsl_auxf_1_w1;  /* aux ext fi radius query */
           break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
#endif
       if (adsl_auxf_1_raq == NULL) {       /* radius query not found  */
#ifdef B080407
#ifndef HL_UNIX
#ifndef HL_IPV6
         iel_claddrtype = en_atca_IPV4;
         avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1;
#else
         iel_claddrtype = en_atca_IPV6;
         avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1;
         if (bog_ipv6 == FALSE) {
           iel_claddrtype = en_atca_IPV4;
         }
#endif
#else
         iel_claddrtype = en_atca_IPV4;
         avol_client_netaddr = (void *) &ADSL_CONN1_G->dsc_un_sa_client;
#ifdef HL_IPV6
#ifndef HL_AIX_OLD
         if (ADSL_CONN1_G->dsc_un_sa_client.dsc_sost1.ss_family == AF_INET6) {
           iel_claddrtype = en_atca_IPV6;
         }
#else
         if (ADSL_CONN1_G->dsc_un_sa_client.dsc_sost1.__ss_family == AF_INET6) {
           iel_claddrtype = en_atca_IPV6;
         }
#endif
#endif
#endif
#endif
#ifdef OLD_1112
#ifndef B090701
#ifndef HL_UNIX
         iel_claddrtype = en_atca_IPV4;
         avol_client_netaddr = NULL;
         switch (ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa.ss_family) {
           case AF_INET:                    /* IPV4                    */
             avol_client_netaddr = &((struct sockaddr_in *) &ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa)->sin_addr;
//           iel_claddrtype = en_atca_IPV4;
             break;
           case AF_INET6:                   /* IPV6                    */
             avol_client_netaddr = &((struct sockaddr_in6 *) &ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa)->sin6_addr;
             iel_claddrtype = en_atca_IPV6;
             break;
         }
#else
// to-do 01.07.09 KB
#endif
#endif
#endif
#ifdef OLD_1112
         adsl_radqu_w1 = ADSL_CONN1_G->adsc_radqu;  /* get existing Radius class */
         if (adsl_radqu_w1 == NULL) {       /* does not exist          */
           iml1 = 0;
           if (adsl_auxf_1_dnc) {           /* certificate found       */
             iml1 = *((int *) (adsl_auxf_1_dnc + 1));
           }
           adsl_radqu_w1 = new dsd_radius_query( ADSL_CONN1_G,
                                                 ADSL_CONN1_G->adsc_gate1->inc_no_radius,
                                                 ADSL_CONN1_G->adsc_gate1->inc_no_usgro,
                                                 (HL_WCHAR *) (((int *) (adsl_auxf_1_dnc + 1)) + 1),
                                                 iml1,
                                                 &(ADSL_CONN1_G->adsc_gate1->dsc_radius_conf),
                                                 iel_claddrtype,
                                                 avol_client_netaddr );
           adsl_auxf_1_raq = &adsl_radqu_w1->dsc_auxf_1;
           adsl_auxf_1_raq->iec_auxf_def = ied_auxf_radqu;
#ifdef B130319
           adsl_auxf_1_raq->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_raq;
#else
           adsl_auxf_1_raq->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
           *aadsl_auxf_1_cur = adsl_auxf_1_raq;  /* set new current chain auxiliary extension fields */
#endif
         } else {
           adsl_auxf_1_raq = &adsl_radqu_w1->dsc_auxf_1;
         }
#endif
#ifndef OLD_1112
         adsl_auxf_1_raq = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                           + sizeof(struct dsd_radius_control_1)
                                                           + sizeof(void *)
                                                           + sizeof(BOOL) );
         memset( adsl_auxf_1_raq, 0, sizeof(struct dsd_auxf_1) );
         m_radius_init( (struct dsd_radius_control_1 *) (adsl_auxf_1_raq + 1),
                        ADSL_CONN1_G->adsc_radius_group,
                        ADSL_CONN1_G,       /* current connection      */
#ifndef HL_UNIX
                        (struct sockaddr *) &ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                        (struct sockaddr *) &ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                        &m_aux_radius_req_compl );
         adsl_auxf_1_raq->iec_auxf_def = ied_auxf_radqu;
#ifdef B130319
         adsl_auxf_1_raq->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_raq;
#else
         adsl_auxf_1_raq->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
         *aadsl_auxf_1_cur = adsl_auxf_1_raq;  /* set new current chain auxiliary extension fields */
#endif
#endif
       }
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
#ifdef OLD_1112
       bol1 = ((class dsd_radius_query *)
                 ((char *) adsl_auxf_1_raq - offsetof( dsd_radius_query, dsc_auxf_1 )))
                   ->m_proc_radius_query( (struct dsd_hl_aux_radius_1 *) apparam );
#endif
#ifndef OLD_1112
#define ADSL_RCTRL1_G ((struct dsd_radius_control_1 *) (adsl_auxf_1_raq + 1))
#define AADSL_HCO_WOTHR ((struct dsd_hco_wothr **) ((char *) (ADSL_RCTRL1_G + 1)))
#define ABOL_POSTED ((volatile BOOL *) ((char *) (ADSL_RCTRL1_G + 1) + sizeof(void *)))
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "xiipgw08-aux-l%05d-T m_secondary_aux() ADSL_RCTRL1_G=%p AADSL_HCO_WOTHR=%p ABOL_POSTED=%p ADSL_AUX_CF1->adsc_hco_wothr=%p.",
                       __LINE__, ADSL_RCTRL1_G, AADSL_HCO_WOTHR, ABOL_POSTED, ADSL_AUX_CF1->adsc_hco_wothr );
#endif
       *AADSL_HCO_WOTHR = ADSL_AUX_CF1->adsc_hco_wothr;
       *ABOL_POSTED = FALSE;
       bol1 = m_radius_request( ADSL_RCTRL1_G, (struct dsd_hl_aux_radius_1 *) apparam );
       if (bol1) {                          /* wait for completition   */
         while (*ABOL_POSTED == FALSE) {
           m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
         }
       }
#undef ADSL_RCTRL1_G
#undef AADSL_HCO_WOTHR
#undef ABOL_POSTED
#endif
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifdef OLD_1112
       return bol1;
#endif
#ifndef OLD_1112
       return TRUE;
#endif
     case DEF_AUX_RADIUS_FREE:              /* free data received from radius */
#ifdef B130319
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get first element */
#else
       adsl_auxf_1_w1 = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
#endif
       adsl_auxf_1_w2 = NULL;               /* no previous yet         */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_radqu) {
           /* radius query found                                       */
#ifndef HL_UNIX
           EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
           ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section  */
#endif
           if (adsl_auxf_1_w2 == NULL) {    /* is first in chain       */
#ifdef B130319
             ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
#else
             *aadsl_auxf_1_cur = adsl_auxf_1_w1->adsc_next;  /* remove from current chain auxiliary extension fields */
#endif
           } else {                         /* in middle of chain      */
             adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
           }
#ifndef HL_UNIX
           LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
           ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section  */
#endif
#ifdef OLD_1112
           if (ADSL_CONN1_G->adsc_radqu == NULL) {  /* did not exist before */
             ((class dsd_radius_query *)
               ((char *) adsl_auxf_1_w1 - offsetof( dsd_radius_query, dsc_auxf_1 )))
                 ->m_delete();              /* call routine            */
           }
#endif
#ifndef OLD_1112
#define ADSL_RCTRL1_G ((struct dsd_radius_control_1 *) (adsl_auxf_1_w1 + 1))
// 08.02.12 KB m_radius_cleanup() not needed
//         m_radius_cleanup( ADSL_RCTRL1_G );  /* do cleanup           */
#ifndef B141029
           m_radius_cleanup( ADSL_RCTRL1_G );  /* do cleanup           */
#endif
           free( adsl_auxf_1_w1 );          /* free memory             */
#undef ADSL_RCTRL1_G
#endif
           return TRUE;                     /* Radius entry removed    */
         }
         adsl_auxf_1_w2 = adsl_auxf_1_w1;   /* save previous           */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
       return FALSE;                        /* no Radius entry found   */
     case DEF_AUX_DISKFILE_ACCESS:
       iml1 = iml2 = 0;
       if (vpp_userfld) {
         iml1 = ADSL_CONN1_G->imc_trace_level;
         iml2 = ADSL_CONN1_G->dsc_co_sort.imc_sno;
       }
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
       m_read_diskfile( ADSL_AUX_CF1->adsc_hco_wothr, iml1, iml2,
                        DEF_AUX_DISKFILE_ACCESS,
                        (struct dsd_hl_aux_diskfile_1 *) apparam );
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
       if (   (((struct dsd_hl_aux_diskfile_1 *) apparam)->adsc_int_df1 == NULL)
           || (((struct dsd_hl_aux_diskfile_1 *) apparam)->iec_dfar_def != ied_dfar_ok)) {
         return TRUE;                       /* all done                */
       }
#ifdef TRACEHL_070505
       m_hlnew_printf( HLOG_TRACE1, "HWSPMTRAC070505C l%05d DEF_AUX_DISKFILE_ACCESS create entry",
                       __LINE__ );
#endif
       adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + sizeof(void *) );
       adsl_auxf_1_w1->iec_auxf_def = ied_auxf_diskfile;  /* diskfile */
       *((void **) (adsl_auxf_1_w1 + 1)) = (char *) ((struct dsd_hl_aux_diskfile_1 *) apparam)->adsc_int_df1
                                                     - offsetof( dsd_diskfile_1, dsc_int_df1 );
       ((struct dsd_hl_aux_diskfile_1 *) apparam)->ac_handle = adsl_auxf_1_w1 + 1;
#ifdef B130319
       adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
#else
       adsl_auxf_1_w1->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
       *aadsl_auxf_1_cur = adsl_auxf_1_w1;  /* set new current chain auxiliary extension fields */
#endif
       return TRUE;                         /* all done                */
     case DEF_AUX_DISKFILE_TIME_LM:         /* get time last modified  */
       iml1 = iml2 = 0;
       if (vpp_userfld) {
         iml1 = ADSL_CONN1_G->imc_trace_level;
         iml2 = ADSL_CONN1_G->dsc_co_sort.imc_sno;
       }
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
       m_read_diskfile( ADSL_AUX_CF1->adsc_hco_wothr, iml1, iml2,
                        DEF_AUX_DISKFILE_TIME_LM,
                        (struct dsd_hl_aux_diskfile_1 *) apparam );
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_TIME:
#ifdef B140826
       time( (time_t *) apparam );
#endif
       *((int *) apparam) = (int) time( NULL );
       if (*((int *) apparam) == 0) *((int *) apparam) = 1;  /* January 18th 2038 */
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_CERTIFICATE:          /* get address certificate */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certificate) {
           X_AUADDR = (adsl_auxf_1_w1 + 1);  /* return address of certificate */
           return TRUE;                     /* all done                */
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
       X_AUADDR = NULL;                     /* not defined             */
       return TRUE;                         /* all done                */
     case DEF_AUX_STRING_FROM_EPOCH:
       if (imp_length != sizeof(struct dsd_hl_aux_epoch_1)) return FALSE;
       return m_string_from_epoch( (struct dsd_hl_aux_epoch_1 *) apparam );
     case DEF_AUX_EPOCH_FROM_STRING:
       if (imp_length != sizeof(struct dsd_hl_aux_epoch_1)) return FALSE;
       return m_epoch_from_string( (struct dsd_hl_aux_epoch_1 *) apparam );
     case DEF_AUX_GET_DN:                   /* get address Distinguished Name */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
           X_AUADDR = (adsl_auxf_1_w1 + 1);  /* return address of DN   */
           return TRUE;                     /* all done                */
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
       X_AUADDR = NULL;                     /* not defined             */
       return TRUE;                         /* all done                */
#ifdef B130911
     case DEF_AUX_GET_AUTH:                 /* get authentication      */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_authname) {
           X_AUADDR = (adsl_auxf_1_w1 + 1);  /* return address of DN   */
           return TRUE;                     /* all done                */
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
       X_AUADDR = NULL;                     /* not defined             */
       return TRUE;                         /* all done                */
#endif
     case DEF_AUX_TCP_CONN:                 /* new TCP connection server */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       if (imp_length != sizeof(struct dsd_aux_tcp_conn_1)) return FALSE;
#ifndef HL_UNIX
#ifndef TRY_D_INCL_HTUN
       return m_tcp_conn( ADSL_AUX_CF1, (struct dsd_aux_tcp_conn_1 *) apparam );
#endif
#ifdef TRY_D_INCL_HTUN
       return m_tcp_dynamic_conn( ADSL_AUX_CF1, (struct dsd_aux_tcp_conn_1 *) apparam, NULL, NULL, TRUE );
#endif
#else
       return m_tcp_dynamic_conn( ADSL_AUX_CF1, (struct dsd_aux_tcp_conn_1 *) apparam, NULL, NULL, TRUE );
#endif
     case DEF_AUX_TCP_CLOSE:                /* close TCP to Server     */
#ifdef B140126
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) {
         return FALSE;
       }
#endif
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
#ifdef B130320
#ifndef TRY_D_INCL_HTUN
#ifdef NEW050421A
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous;
       free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free this server entry */
       ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1;
#else
       free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free this server entry */
       ADSL_CONN1_G->adsc_server_conf_1 = ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1;
#endif
#ifndef HL_UNIX
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
       ADSL_CONN1_G->dcl_tcp_r_s.close1();  /* close connection server */
       while (ADSL_CONN1_G->dcl_tcp_r_s.getrecthr()) {  /* status in receive thr */
         m_hlnew_printf( HLOG_WARN1, "HWSPMXXX6-%05d-W m_cdaux() Thread=%d SNO=%08d server-socket boc_recthr set",
                         __LINE__, GetCurrentThreadId(), ADSL_CONN1_G->dsc_co_sort.imc_sno );
         Sleep( 100 );
       }
// to-do 06.11.09 KB synchronzie with cleanup
       Sleep( 2000 );                       /* only temporary          */
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifndef B090703
#ifdef CSSSL_060620
// to-do 03.07.09 SSL subroutine has to free internal buffers
       if (ADSL_CONN1_G->adsc_csssl_oper_1) {  /* operation of client-side SSL */
         free( ADSL_CONN1_G->adsc_csssl_oper_1 );  /* free memory again */
         ADSL_CONN1_G->adsc_csssl_oper_1 = NULL;  /* no more client-side SSL */
       }
#endif
#endif
/* UUUU 18.01.05 KB missing free buffers if something received */
#else
#ifdef B110810
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
       /* give notice to thread with TCP poll() - connect thread, stop receive */
       *((ied_message *) &vprl_message[0]) = ied_me_no_recv_server;  /* stop receive server */
       vprl_message[1] = ADSL_CONN1_G;      /* pointer to class        */
       iml_rc = write( ADSL_CONN1_G->adsc_cothr->ifdpipe[1], vprl_message, sizeof(vprl_message) );
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d write pipe completed / returned iml_rc=%d errno=%d",
                       __LINE__, iml_rc, errno );
#endif
       sleep( 1 );                          /* wait some time          */
       iml1 = 5;                            /* number of passes        */
#ifdef OLD01
       while (   (ADSL_CONN1_G->adsc_sdhc1_ts_se)
              && (iml1)) {
         sleep( 1 );                        /* wait some time          */
         iml1--;                            /* count pass              */
       }
       if (ADSL_CONN1_G->adsc_sdhc1_ts_se) {  /* not yet all sent      */
         m_hlnew_printf( HLOG_WARN1, "HWSPMXXX6-%05d-W m_cdaux() GATE=%(ux)s SNO=%08d INETA=%s send data to server aborted",
                         __LINE__,
                         m_clconn1_gatename( ADSL_CONN1_G ),
                         m_clconn1_sno( ADSL_CONN1_G ),
                         m_clconn1_chrc_ineta( ADSL_CONN1_G ) );
       }
#endif
       while (   (ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1)
              && (iml1)) {
         sleep( 1 );                        /* wait some time          */
         iml1--;                            /* count pass              */
       }
       if (ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1) {  /* not yet all sent */
         m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX6-%05d-W m_cdaux() GATE=%(ux)s SNO=%08d INETA=%s send data to server aborted",
                         __LINE__,
                         m_clconn1_gatename( ADSL_CONN1_G ),
                         m_clconn1_sno( ADSL_CONN1_G ),
                         m_clconn1_chrc_ineta( ADSL_CONN1_G ) );
       }
       iml_rc = m_ip_snddis( ADSL_CONN1_G->ifd_s, NULL );
       if (iml_rc < 0) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX6-%05d-W m_cdaux() GATE=%(ux)s SNO=%08d INETA=%s t_snddis to server error %d %d",
                         __LINE__,
                         m_clconn1_gatename( ADSL_CONN1_G ),
                         m_clconn1_sno( ADSL_CONN1_G ),
                         m_clconn1_chrc_ineta( ADSL_CONN1_G ),
                         iml_rc, t_errno );
       }
       iml_rc = m_ip_unbind( ADSL_CONN1_G->ifd_s );
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
       if (ADSL_CONN1_G->adsc_sdhc1_s1) {   /* something received      */
         m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s1 );  /* free storage  */
         ADSL_CONN1_G->adsc_sdhc1_s1 = NULL;  /* no more reference     */
       }
       if (ADSL_CONN1_G->adsc_sdhc1_s2) {   /* something received      */
         m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s2 );  /* free storage  */
         ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* no more reference     */

       }
#ifdef OLD01
       while (ADSL_CONN1_G->adsc_sdhc1_ts_se) {  /* buffers not sent yet */
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->adsc_sdhc1_ts_se;  /* get buffer not sent yet */
         ADSL_CONN1_G->adsc_sdhc1_ts_se = ADSL_CONN1_G->adsc_sdhc1_ts_se->adsc_next;
         m_proc_free( adsl_sdhc1_w1 );      /* free storage            */
       }
#endif
       while (ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1) {  /* buffers not sent yet */
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* get buffer not sent yet */
         ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1 = ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1->adsc_next;
         m_proc_free( adsl_sdhc1_w1 );      /* free storage            */
       }
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifndef B090703
#ifdef CSSSL_060620
// to-do 03.07.09 SSL subroutine has to free internal buffers
       if (ADSL_CONN1_G->adsc_csssl_oper_1) {  /* operation of client-side SSL */
         free( ADSL_CONN1_G->adsc_csssl_oper_1 );  /* free memory again */
         ADSL_CONN1_G->adsc_csssl_oper_1 = NULL;  /* no more client-side SSL */
       }
#endif
#endif
#endif
#endif
//     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_prep_server;  /* stat server  */
       return TRUE;                         /* all done                */
#endif
#ifdef TRY_D_INCL_HTUN
       return m_tcp_close( ADSL_AUX_CF1 );
#endif
#else
       return m_tcp_close( ADSL_AUX_CF1 );
#endif
     case DEF_AUX_QUERY_CLIENT:             /* query TCP client connection */
       if (imp_length != sizeof(struct dsd_aux_query_client)) return FALSE;
       memset( apparam, 0, sizeof(struct dsd_aux_query_client) );
#define ADSL_AUX_QUERY_CLIENT ((struct dsd_aux_query_client *) apparam)
#ifndef HL_UNIX
#define ADSL_SOA_G &ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa
#else
#define ADSL_SOA_G &ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn
#endif
       ADSL_AUX_QUERY_CLIENT->inc_addr_family = (ADSL_SOA_G)->ss_family;
       if ((ADSL_SOA_G)->ss_family == AF_INET) {
         memcpy( ADSL_AUX_QUERY_CLIENT->chrc_multih_ineta,
                 &((struct sockaddr_in *) (&ADSL_CONN1_G->adsc_gate_listen_1->dsc_soa))->sin_addr,
                 4 );
         memcpy( ADSL_AUX_QUERY_CLIENT->chrc_client_ineta,
                 &((struct sockaddr_in *) (ADSL_SOA_G))->sin_addr,
                 4 );
       } else if ((ADSL_SOA_G)->ss_family == AF_INET6) {
         memcpy( ADSL_AUX_QUERY_CLIENT->chrc_multih_ineta,
                 &((struct sockaddr_in6 *) (&ADSL_CONN1_G->adsc_gate_listen_1->dsc_soa))->sin6_addr,
                 16 );
         memcpy( ADSL_AUX_QUERY_CLIENT->chrc_client_ineta,
                 &((struct sockaddr_in6 *) (ADSL_SOA_G))->sin6_addr,
                 16 );
       }
#undef ADSL_SOA_G
       ADSL_AUX_QUERY_CLIENT->inc_port = ADSL_CONN1_G->adsc_gate1->imc_gateport;
#ifndef B080407
       if (   (ADSL_CONN1_G->adsc_gate1->imc_permmov_from_port > 0)  /* <permanently-moved-from_port> */
           && (((struct sockaddr_in *) &ADSL_CONN1_G->adsc_gate_listen_1->dsc_soa)->sin_port == htons( ADSL_CONN1_G->adsc_gate1->imc_permmov_from_port))) {  /* <permanently-moved-from_port> */
         ADSL_AUX_QUERY_CLIENT->inc_port = ADSL_CONN1_G->adsc_gate1->imc_permmov_from_port;
       }
#endif
#undef ADSL_AUX_QUERY_CLIENT
       return TRUE;                         /* all done                */
     case DEF_AUX_QUERY_RECEIVE:            /* query TCP data          */
       if (imp_length != sizeof(struct dsd_aux_query_receive)) return FALSE;
       memset( apparam, 0, sizeof(struct dsd_aux_query_receive) );
#define ADSL_AUX_QUERY_RECEIVE ((struct dsd_aux_query_receive *) apparam)
       if (ADSL_CONN1_G->adsc_sdhc1_c1) {   /* data received from client */
         ADSL_AUX_QUERY_RECEIVE->boc_data_client = TRUE;  /* data from client available */
       }
       if (ADSL_CONN1_G->adsc_sdhc1_s1) {   /* data received from server */
         ADSL_AUX_QUERY_RECEIVE->boc_data_server = TRUE;  /* data from server available */
       }
#undef ADSL_AUX_QUERY_RECEIVE
       return TRUE;                         /* all done                */
     case DEF_AUX_COM_CMA:                  /* command common memory area */
       return m_cma1_proc( vpp_userfld, (struct dsd_hl_aux_c_cma_1 *) apparam );
     case DEF_AUX_RANDOM_RAW:
       if (imp_length <= 0) return FALSE;
       iml1 = imp_length;
       do {                                 /* fill all bytes          */
         iml1--;                            /* index one less          */
         *((char *) apparam + iml1) = (unsigned char) (m_get_random_number( 256 ) ^ ucs_random_01);
       } while (iml1);                      /* loop over all bytes     */
       return TRUE;                         /* all done                */
     case DEF_AUX_RANDOM_BASE64:
       if (imp_length <= 0) return FALSE;
       iml1 = imp_length;
       do {                                 /* fill all bytes          */
         iml1--;                            /* index one less          */
         *((char *) apparam + iml1)
           = (unsigned char) *(ucrs_base64
                                 + ((m_get_random_number( 64 ) ^ ucs_random_01) & 0X3F));
       } while (iml1);                      /* loop over all bytes     */
       return TRUE;                         /* all done                */
     case DEF_AUX_CHECK_IDENT:              /* check ident - authenticate */
#define ADSL_AUX_CHIDENT ((struct dsd_hl_aux_ch_ident *) apparam)
#ifndef WSP_V24
       dsl_us_userid.ac_str = ADSL_AUX_CHIDENT->ac_userid;  /* address of string */
       dsl_us_userid.imc_len_str = ADSL_AUX_CHIDENT->inc_len_userid;  /* length string in elements */
       dsl_us_userid.iec_chs_str = ADSL_AUX_CHIDENT->iec_chs_userid;  /* character set string */
#endif
#ifdef WSP_V24
#define ADSL_G_IDSET1_G ((struct dsd_aux_set_ident_1 *) byrl_work1)
       memset( ADSL_G_IDSET1_G, 0, sizeof(struct dsd_aux_set_ident_1) );
       ADSL_G_IDSET1_G->dsc_userid.ac_str = ADSL_AUX_CHIDENT->ac_userid;  /* address of string */
       ADSL_G_IDSET1_G->dsc_userid.imc_len_str = ADSL_AUX_CHIDENT->inc_len_userid;  /* length string in elements */
       ADSL_G_IDSET1_G->dsc_userid.iec_chs_str = ADSL_AUX_CHIDENT->iec_chs_userid;  /* character set string */
#endif
       dsl_us_password.ac_str = ADSL_AUX_CHIDENT->ac_password;  /* address of string */
       dsl_us_password.imc_len_str = ADSL_AUX_CHIDENT->inc_len_password;  /* length string in elements */
       dsl_us_password.iec_chs_str = ADSL_AUX_CHIDENT->iec_chs_password;  /* character set string */
       ADSL_AUX_CHIDENT->iec_chid_ret = m_auth_user(
                        &ADSL_CONN1_G->adsc_user_entry,
                        &ADSL_CONN1_G->adsc_user_group,
                        ADSL_CONN1_G,
#ifndef WSP_V24
                        &dsl_us_userid,
#endif
#ifdef WSP_V24
                        ADSL_G_IDSET1_G,
#endif
                        &dsl_us_password,
                        TRUE,
                        TRUE );
#ifdef WSP_V24
#undef ADSL_G_IDSET1_G
#endif
       if (ADSL_AUX_CHIDENT->avpc_usent) {
         *ADSL_AUX_CHIDENT->avpc_usent = ADSL_CONN1_G->adsc_user_entry;
       }
       if (ADSL_AUX_CHIDENT->avpc_usgro) {
         *ADSL_AUX_CHIDENT->avpc_usgro = ADSL_CONN1_G->adsc_user_group;
       }
       return TRUE;                         /* all done                */
#undef ADSL_AUX_CHIDENT
     case DEF_AUX_GET_SC_PROT:              /* get Server Entry Protocol */
#define ADSL_AUX_GETSCP1 ((struct dsd_get_sc_prot_1 *) apparam)
       *ADSL_AUX_GETSCP1->aiec_scp_def
         = m_decode_prot( ADSL_AUX_GETSCP1->iec_chs_scp,
                          ADSL_AUX_GETSCP1->ac_scp,
                          ADSL_AUX_GETSCP1->inc_len_scp );
       return TRUE;                         /* all done                */
#undef ADSL_AUX_GETSCP1
     case DEF_AUX_COUNT_SERVENT:            /* count server entries    */
     case DEF_AUX_GET_SERVENT:              /* get server entry        */
       m_get_servent_1( imp_func, ADSL_CONN1_G, (struct dsd_get_servent_1 *) apparam );
       return TRUE;                         /* all done                */
     case DEF_AUX_CONN_PREPARE:             /* prepare for connect HOB-WSP-AT3 */
#ifdef OLD_1112
       m_prep_conn_1( ADSL_CONN1_G, (struct dsd_hlwspat2_conn *) apparam );
#else
       m_prep_conn_1( ADSL_CONN1_G, (struct dsd_wspat3_conn *) apparam );
#endif
       return TRUE;                         /* all done                */
     case DEF_AUX_QUERY_MAIN_STR:           /* query main program for string */
       *((char **) apparam) = (char *) chrs_query_main;  /* return string */
       return TRUE;                         /* all done                */
     case DEF_AUX_TIMER1_SET:               /* set timer in milliseconds */
       /* if timer already set, release this timer                     */
#ifdef B130314
       m_aux_timer_del( ADSL_CONN1_G, ADSL_AUX_CF1->iec_src_func, ADSL_AUX_CF1->ac_sdh );
       m_aux_timer_new( ADSL_CONN1_G, ADSL_AUX_CF1->iec_src_func, ADSL_AUX_CF1->ac_sdh, imp_length );
#endif
       m_aux_timer_del( ADSL_CONN1_G, &ADSL_AUX_CF1->dsc_cid );
       m_aux_timer_new( ADSL_CONN1_G, &ADSL_AUX_CF1->dsc_cid, imp_length, ied_auxtu_normal );
       return TRUE;                         /* all done                */
     case DEF_AUX_TIMER1_REL:               /* release timer set before */
#ifdef B130314
       m_aux_timer_del( ADSL_CONN1_G, ADSL_AUX_CF1->iec_src_func, ADSL_AUX_CF1->ac_sdh );
#endif
       m_aux_timer_del( ADSL_CONN1_G, &ADSL_AUX_CF1->dsc_cid );
       return TRUE;                         /* all done                */
     case DEF_AUX_TIMER1_QUERY:             /* return struct dsd_timer1_ret */
       if (imp_length != sizeof(struct dsd_timer1_ret)) return FALSE;
#define ADSL_TIMER1_RET_G ((struct dsd_timer1_ret *) apparam)
       ADSL_TIMER1_RET_G->ilc_epoch = m_get_epoch_ms();  /* Epoch in milliseconds */
       /* search thru all timers                                       */
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;
       while (adsl_auxf_1_w1) {             /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
#ifdef B130314
         if (   (ADSL_AUX_T->iec_src_func == ADSL_AUX_CF1->iec_src_func)  /* type auxiliary timer */
             && (ADSL_AUX_T->ac_sdh == ADSL_AUX_CF1->ac_sdh)) {  /* address of SDH */
           ADSL_TIMER1_RET_G->boc_timer_set = TRUE;  /* a timer is set and active */
           ADSL_TIMER1_RET_G->ilc_timer = ADSL_AUX_T->ilc_endtime;  /* Epoch when timer elapses */
           return TRUE;                     /* all done                */
         }
#endif
         if (!memcmp( &ADSL_AUX_T->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) )) {  /* type auxiliary timer and component */
           ADSL_TIMER1_RET_G->boc_timer_set = TRUE;  /* a timer is set and active */
           ADSL_TIMER1_RET_G->ilc_timer = ADSL_AUX_T->ilc_endtime;  /* Epoch when timer elapses */
           return TRUE;                     /* all done                */
         }
#undef ADSL_AUX_T
         adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
       }
       ADSL_TIMER1_RET_G->boc_timer_set = FALSE;  /* a timer is not set */
       ADSL_TIMER1_RET_G->ilc_timer = 0;    /* Epoch when timer elapses */
       return TRUE;                         /* all done                */
#undef ADSL_TIMER1_RET_G
     case DEF_AUX_QUERY_GATHER:             /* query Gather Structure, struct dsd_q_gather_1 */
       if (imp_length != sizeof(struct dsd_q_gather_1)) return FALSE;
       if (   (((struct dsd_q_gather_1 *) apparam)->imc_set_signal != 0)
           && (((struct dsd_q_gather_1 *) apparam)->imc_set_signal != HL_AUX_SIGNAL_IO_1)
           && (((struct dsd_q_gather_1 *) apparam)->imc_set_signal != HL_AUX_SIGNAL_IO_2)
           && (((struct dsd_q_gather_1 *) apparam)->imc_set_signal != HL_AUX_SIGNAL_IO_3)
           && (((struct dsd_q_gather_1 *) apparam)->imc_set_signal != HL_AUX_SIGNAL_IO_4)) {
         return FALSE;                      /* invalid signal          */
       }
       ((struct dsd_q_gather_1 *) apparam)->boc_still_active = FALSE;
#define ADSL_GAI1_COMP ((struct dsd_gather_i_1 *) ((struct dsd_q_gather_1 *) apparam)->ac_gather)
       iml1 = 0;                            /* first funktion          */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
       while (TRUE) {                       /* loop over all functions */
         while (adsl_sdhc1_w1) {            /* loop over all buffers   */
           adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain input data */
           while (adsl_gai1_w1) {           /* loop over output        */
             if (adsl_gai1_w1 == ADSL_GAI1_COMP) {  /* gather found    */
               if (adsl_gai1_w1->achc_ginp_end > adsl_gai1_w1->achc_ginp_cur) {
                 ((struct dsd_q_gather_1 *) apparam)->boc_still_active = TRUE;
               }
               break;
             }
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           }
           if (adsl_gai1_w1) break;         /* gather found            */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         }
         if (adsl_sdhc1_w1) break;          /* gather found            */
         if (iml1 == 2) break;              /* all functions done      */
         if (iml1 == 0) {                   /* do send to client now   */
#ifndef HL_UNIX
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send;
#else
#ifdef B120502
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_cl.adsc_sdhc1;  /* chain to send to client */
#else
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* get chain to send to client */
#endif
#endif
         } else {                           /* do send to server now   */
#ifdef B120502
#ifndef HL_UNIX
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;
#else
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* chain to send to server */
#endif
#else
           switch (ADSL_CONN1_G->iec_servcotype) {
             case ied_servcotype_normal_tcp:  /* normal TCP            */
#ifndef HL_UNIX
               adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;  /* get start of chain */
#else
               adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send;  /* get chain to send to server */
#endif
               break;
#ifdef D_INCL_HTUN
             case ied_servcotype_htun:      /* HOB-TUN                 */
               adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get start of chain */
               break;
#endif
             case ied_servcotype_l2tp:      /* L2TP                    */
               adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_l2tp_sch;  /* send buffers */
               break;
           }
#endif
         }
         iml1++;                            /* next function           */
       }
       if (((struct dsd_q_gather_1 *) apparam)->imc_set_signal == 0) return TRUE;
       if (adsl_sdhc1_w1 == NULL) return TRUE;  /* gather not found    */
       if (((struct dsd_q_gather_1 *) apparam)->boc_still_active == FALSE) return TRUE;
       /* set Signal in chain, so that we get notified when the gather has been processed */
       adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                      + sizeof(struct dsd_aux_q_gather) );
       adsl_auxf_1_w1->iec_auxf_def = ied_auxf_q_gather;  /* query gather */
#define ADSL_Q_GATHER ((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))
       ADSL_Q_GATHER->adsc_gai1_q = ADSL_GAI1_COMP;  /* address gather queried  */
#ifdef B130314
       ADSL_Q_GATHER->iec_src_func = ADSL_AUX_CF1->iec_src_func;  /* set function */
       ADSL_Q_GATHER->ac_sdh = ADSL_AUX_CF1->ac_sdh;  /* current Server-Data-Hook */
#endif
       memcpy( &ADSL_Q_GATHER->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* set function and component */
       ADSL_Q_GATHER->imc_signal = ((struct dsd_q_gather_1 *) apparam)->imc_set_signal;  /* set signal when no more active */
#ifdef B130319
       adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
#else
       adsl_auxf_1_w1->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
       *aadsl_auxf_1_cur = adsl_auxf_1_w1;  /* set new current chain auxiliary extension fields */
#endif
       return TRUE;                         /* all done                */
#undef ADSL_Q_GATHER
#undef ADSL_GAI1_COMP
     case DEF_AUX_GET_PRIV_PERS:            /* return priviliges of user entry */
       return FALSE;                        /* not yet implemented     */
     case DEF_AUX_SET_PRIV_SESSION:         /* set priviliges of session */
       iml1 = imp_length;                   /* get length of area in calling program */
       if (iml1 > sizeof(ADSL_CONN1_G->chrc_priv)) {
         iml1 = sizeof(ADSL_CONN1_G->chrc_priv);
       }
       memcpy( ADSL_CONN1_G->chrc_priv, apparam, iml1 );
       if (iml1 < sizeof(ADSL_CONN1_G->chrc_priv)) {
         memset( ADSL_CONN1_G->chrc_priv + iml1, 0, sizeof(ADSL_CONN1_G->chrc_priv) - iml1 );
       }
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_PRIV_SESSION:         /* return priviliges of session */
       iml1 = imp_length;                   /* get length of area in calling program */
       if (iml1 > sizeof(ADSL_CONN1_G->chrc_priv)) {
         iml1 = sizeof(ADSL_CONN1_G->chrc_priv);
       }
       memcpy( apparam, ADSL_CONN1_G->chrc_priv, iml1 );
       if (iml1 < imp_length) {
         memset( apparam, 0, imp_length - iml1 );
       }
       return TRUE;                         /* all done                */
     case DEF_AUX_PUT_SESS_STOR:            /* put Session Storage     */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       adsl_auxf_1_w2 = NULL;               /* no previous yet         */
       while (adsl_auxf_1_w1) {             /* loop over all auxiliary entries */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sess_stor) break;  /* Session Storage */
         adsl_auxf_1_w2 = adsl_auxf_1_w1;   /* save previous           */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       if (   (adsl_auxf_1_w1 == NULL)
           || (*((int *) (adsl_auxf_1_w1 + 1)) != imp_length)) {
#ifdef XYZ1
         adsl_auxf_1_w3 = adsl_auxf_1_w1;   /* save old entry          */
#endif
#ifdef B140121
         if (adsl_auxf_1_w2 == NULL) {      /* old was at beginning of chain */
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
         } else {                           /* old was middle in chain */
           adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
         }
         free( adsl_auxf_1_w1 );            /* free old entry          */
#endif
         if (adsl_auxf_1_w1) {              /* we have old storage     */
           if (adsl_auxf_1_w2 == NULL) {    /* old was at beginning of chain */
             ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
           } else {                         /* old was middle in chain */
             adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
           }
           free( adsl_auxf_1_w1 );          /* free old entry          */
         }
         if (imp_length > 0) {              /* still entry             */
           adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                          + sizeof(int) + imp_length );
           adsl_auxf_1_w1->iec_auxf_def = ied_auxf_sess_stor;  /* set type of entry */
           adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
           memcpy( &adsl_auxf_1_w1->dsc_cid,
                   &ADSL_AUX_CF1->dsc_cid,
                   sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
           *((int *) (adsl_auxf_1_w1 + 1)) = imp_length;  /* set length  */
#ifdef XYZ1
           if (*((int *) (adsl_auxf_1_w3 + 1)) > imp_length) {
             memcpy( (char *) (adsl_auxf_1_w1 + 1) + sizeof(int) + imp_length,
                     (char *) (adsl_auxf_1_w3 + 1) + sizeof(int) + imp_length,
                     *((int *) (adsl_auxf_1_w3 + 1)) - imp_length );
           }
           free( adsl_auxf_1_w3 );          /* free old entry          */
#endif
         }
       }
       if (imp_length > 0) {                /* some new content        */
         memcpy( (char *) (adsl_auxf_1_w1 + 1) + sizeof(int),
                 apparam, imp_length );
       }
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_SESS_STOR:            /* get Session Storage     */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       while (adsl_auxf_1_w1) {             /* loop over all auxiliary entries */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sess_stor) break;  /* Session Storage */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       iml1 = 0;                            /* set area filled so far  */
       if (adsl_auxf_1_w1) {                /* entry found             */
         iml1 = *((int *) (adsl_auxf_1_w1 + 1));
         if (*((int *) (adsl_auxf_1_w1 + 1)) > imp_length) {
           iml1 = imp_length;               /* copy only this part     */
         }
         memcpy( apparam,
                 (char *) (adsl_auxf_1_w1 + 1) + sizeof(int),
                 iml1 );
       }
       if (iml1 < imp_length) {             /* fill remaining area     */
         memset( (char *) apparam + iml1, 0, imp_length - iml1 );
       }
       return TRUE;                         /* all done                */
     case DEF_AUX_DESCR_SESS_STOR:          /* get Session Storage Descriptor */
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
#define ADSL_DESCR_SS ((struct dsd_hl_descr_sess_stor *) apparam)
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get anchor of chain */
       while (adsl_auxf_1_w1) {             /* loop over all auxiliary entries */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sess_stor) {  /* Session Storage */
           ADSL_DESCR_SS->achc_sess_stor
             = (char *) (adsl_auxf_1_w1 + 1) + sizeof(int);  /* pointer to session storage */
           ADSL_DESCR_SS->inc_len_sess_stor
             = *((int *) (adsl_auxf_1_w1 + 1));  /* length of session storage */
           return TRUE;                         /* all done                */
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       ADSL_DESCR_SS->achc_sess_stor = NULL;  /* pointer to session storage */
       ADSL_DESCR_SS->inc_len_sess_stor = 0;  /* length of session storage */
       return TRUE;                         /* all done                */
#undef ADSL_DESCR_SS
     case DEF_AUX_QUERY_SYSADDR:            /* return array with system addresses */
       if (imp_length != sizeof(void *)) return FALSE;
       *((void **) apparam) = &dss_sysaddr;  /* return system addresses */
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
       if (imp_length != sizeof(struct dsd_aux_get_workarea)) return FALSE;
       if (ADSL_AUX_CF1->dsc_cid.iec_src_func == ied_src_fu_util_thread) {  /* utility thread */
         return FALSE;                      /* not allowed / not implemented */
       }
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifndef B100407
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#endif
       adsl_sdhc1_w1->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* get old chain */
#ifndef B140620
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier */
#endif
       ADSL_AUX_CF1->adsc_sdhc1_chain = adsl_sdhc1_w1;  /* set new chain */
#define ADSL_AUX_GET_WORKAREA ((struct dsd_aux_get_workarea *) apparam)
       ADSL_AUX_GET_WORKAREA->achc_work_area = (char *) (adsl_sdhc1_w1 + 1);
       ADSL_AUX_GET_WORKAREA->imc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
#ifdef TRACEHLP
       m_hlnew_printf( HLOG_XYZ1, "HWSPM-%05d-T m_cdaux() DEF_AUX_GET_WORKAREA mem=%p ADSL_AUX_CF1=%p adsc_conn=%p iec_src_func=%d",
                       __LINE__, adsl_sdhc1_w1, ADSL_AUX_CF1, ADSL_AUX_CF1->adsc_conn, ADSL_AUX_CF1->iec_src_func );
#endif
       return TRUE;                         /* all done                */
#undef ADSL_AUX_GET_WORKAREA
     case DEF_AUX_GET_T_MSEC:               /* get time / epoch in milliseconds */
       if (imp_length != sizeof(HL_LONGLONG)) return FALSE;  /* invalid size */
       if ((((HL_LONGLONG) apparam) & (sizeof(void *) - 1))) return FALSE;  /* misaligned */
       *((HL_LONGLONG *) apparam) = m_get_epoch_ms();
       return TRUE;                         /* all done                */
     case DEF_AUX_MARK_WORKAREA_INC:        /* increment usage count in work area */
       return m_mark_work_area( vpp_userfld, (char *) apparam, 1 );
     case DEF_AUX_MARK_WORKAREA_DEC:        /* decrement usage count in work area */
       return m_mark_work_area( vpp_userfld, (char *) apparam, -1 );
     case DEF_AUX_SERVICE_REQUEST:          /* service request         */
       if (imp_length != sizeof(struct dsd_aux_service_query_1)) return FALSE;  /* invalid size */
       return m_proc_service_query( vpp_userfld, (struct dsd_aux_service_query_1 *) apparam );
#ifndef NO_LDAP_071116
     case DEF_AUX_LDAP_REQUEST:             /* LDAP service request    */
       if (imp_length != sizeof(struct dsd_co_ldap_1)) return FALSE;  /* invalid size */
       if (ADSL_CONN1_G->adsc_aux_ldap == NULL) {  /* create LDAP structure */
         ADSL_CONN1_G->adsc_aux_ldap
           = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                             + sizeof(class dsd_ldap_cl) );
#ifdef B130319
         ADSL_CONN1_G->adsc_aux_ldap->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
         ADSL_CONN1_G->adsc_auxf_1 = ADSL_CONN1_G->adsc_aux_ldap;
#else
         ADSL_CONN1_G->adsc_aux_ldap->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
         *aadsl_auxf_1_cur = ADSL_CONN1_G->adsc_aux_ldap;  /* set new current chain auxiliary extension fields */
#endif
         ADSL_CONN1_G->adsc_aux_ldap->iec_auxf_def = ied_auxf_ldap;  /* LDAP service */
#ifndef B150219
         ADSL_CONN1_G->adsc_aux_ldap->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier */
#endif
#ifdef TRACEHLP
         ADSL_CONN1_G->adsc_aux_ldap->inc_size_mem = 0;  /* size of memory */
#endif
         memset( ADSL_CONN1_G->adsc_aux_ldap + 1, 0, sizeof(class dsd_ldap_cl) );
         m_ldap_init( (class dsd_ldap_cl *) (ADSL_CONN1_G->adsc_aux_ldap + 1) );
/**
   27.08.12 Jürgen Lauenstein + KB
   add three parameters
   - void *    connection
   - int       imc_sno session number
   - int       imc_trace_level    trace-level
   first parameter needed for warning and info messages
*/
       }
#ifdef B091129
       adsl_ldap_group_w1 = ADSL_CONN1_G->adsc_gate1->adsc_ldap_group;
       /* LDAP definition from server side half session has higher priority */
       if (   (ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1)
           && (ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1->adsc_ldap_group)) {
         adsl_ldap_group_w1 = ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1->adsc_ldap_group;
       }
#endif
       adsl_ldap_group_w1 = ADSL_CONN1_G->adsc_ldap_group;
#ifndef B090724_XYZ
       bol1 = m_ldap_request( (class dsd_ldap_cl *) (ADSL_CONN1_G->adsc_aux_ldap + 1),
                              adsl_ldap_group_w1,  /* LDAP group configured */
                              (struct dsd_co_ldap_1 *) apparam );
#else
       bol1 = ((class dsd_ldap_cl *) (ADSL_CONN1_G->adsc_aux_ldap + 1))->m_ldap_request(
                                        adsl_ldap_group_w1,  /* LDAP group configured */
                                        (struct dsd_co_ldap_1 *) apparam );
#endif
       if (bol1) return TRUE;               /* all valid               */
       /* remove LDAP element from chain                               */
       m_ldap_free( (class dsd_ldap_cl *) (ADSL_CONN1_G->adsc_aux_ldap + 1) );
#ifdef B130319
       adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;
#else
       adsl_auxf_1_w1 = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
#endif
       adsl_auxf_1_w2 = NULL;               /* no previous yet         */
       while (adsl_auxf_1_w1) {
         if ((adsl_auxf_1_w1 + 1) == ADSL_CONN1_G->adsc_aux_ldap) break;
         adsl_auxf_1_w2 = adsl_auxf_1_w1;   /* save previous           */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       }
       if (adsl_auxf_1_w1 == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "UUUU 13.11.07 m_cdaux() no field in chain found" );
         return FALSE;
       }
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_w2 == NULL) {        /* is first in chain       */
#ifdef B130319
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
#else
         *aadsl_auxf_1_cur = adsl_auxf_1_w1->adsc_next;  /* remove from current chain auxiliary extension fields */
#endif
       } else {                             /* in middle of chain      */
         adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       ADSL_CONN1_G->adsc_aux_ldap = NULL;
       return TRUE;                         /* all done                */
#endif
     case DEF_AUX_SDH_OBJECT:               /* Server-Data-Hook object */
       if (imp_length != sizeof(struct dsd_get_sdh_object_1)) return FALSE;  /* invalid size */
       return m_aux_sdh_obj_1( vpp_userfld, (struct dsd_get_sdh_object_1 *) apparam );
     case DEF_AUX_SIP_REQUEST:              /* SIP protocol request    */
       if (imp_length != sizeof(struct dsd_sdh_sip_requ_1)) return FALSE;  /* invalid size */
       return m_aux_sip_requ_1( vpp_userfld, (struct dsd_sdh_sip_requ_1 *) apparam );
     case DEF_AUX_UDP_REQUEST:              /* UDP request             */
       if (imp_length != sizeof(struct dsd_sdh_udp_requ_1)) return FALSE;  /* invalid size */
       return m_aux_udp_requ_1( vpp_userfld, (struct dsd_sdh_udp_requ_1 *) apparam );
     case DEF_AUX_GET_IDENT_SETTINGS:       /* return settings of this user */
       if (imp_length != sizeof(struct dsd_sdh_ident_set_1)) return FALSE;  /* invalid size */
       return m_aux_get_ident_set_1( vpp_userfld, (struct dsd_sdh_ident_set_1 *) apparam );
     case DEF_AUX_SESSION_CONF:             /* configure session parameters */
       if (imp_length != sizeof(struct dsd_aux_session_conf_1)) return FALSE;  /* invalid size */
       return m_aux_session_conf_1( vpp_userfld, (struct dsd_aux_session_conf_1 *) apparam );
     case DEF_AUX_ADMIN:                    /* administration command  */
       if (imp_length != sizeof(struct dsd_aux_admin_1)) return FALSE;  /* invalid size */
       return m_aux_admin_1( vpp_userfld, (struct dsd_aux_admin_1 *) apparam );
     case DEF_AUX_SET_IDENT:                /* set ident - userid and user-group */
       if (imp_length != sizeof(struct dsd_aux_set_ident_1)) return FALSE;  /* invalid size */
       return m_aux_set_ident_1( vpp_userfld, (struct dsd_aux_set_ident_1 *) apparam );
     case DEF_AUX_GET_CONN_SNO:             /* get connection SNO session number */
       if (imp_length != sizeof(int)) return FALSE;  /* invalid size   */
       *((int *) apparam) = ADSL_CONN1_G->dsc_co_sort.imc_sno;
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_RADIUS_CONF:          /* get Radius group Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_get_radius_entry)) return FALSE;  /* invalid size */
#define ADSL_AGRE ((struct dsd_aux_get_radius_entry *) apparam)
       ADSL_AGRE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       ADSL_AGRE->imc_ret_conf_entry = ADSL_CONN1_G->adsc_gate1->imc_no_radius;  /* return number of configured entries */
       ADSL_AGRE->boc_option_ms_chap_v2 = FALSE;  /* entry supports MS-CHAP-V2 */
       memset( &ADSL_AGRE->dsc_ret_name, 0, sizeof(struct dsd_unicode_string) );  /* return name of configured entry */
       memset( &ADSL_AGRE->dsc_ret_comment, 0, sizeof(struct dsd_unicode_string) );  /* return comment of configured entry */
       if (ADSL_AGRE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_AGRE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_radius) return TRUE;  /* input index of entry too high */
       ADSL_AGRE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_RADIUS_GROUP_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_radius_group + ADSL_AGRE->imc_no_entry))
       ADSL_AGRE->dsc_ret_name.ac_str = ADSL_RADIUS_GROUP_W1 + 1;  /* address of string */
       ADSL_AGRE->dsc_ret_name.imc_len_str = ADSL_RADIUS_GROUP_W1->imc_len_name;  /* length string in elements */
       ADSL_AGRE->dsc_ret_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
       ADSL_AGRE->dsc_ret_comment.ac_str = ADSL_RADIUS_GROUP_W1->achc_comment;  /* address comment */
       ADSL_AGRE->dsc_ret_comment.imc_len_str = ADSL_RADIUS_GROUP_W1->imc_len_comment;  /* length string in elements */
       ADSL_AGRE->dsc_ret_comment.iec_chs_str = ied_chs_utf_8;  /* character set string */
       if (ADSL_RADIUS_GROUP_W1->imc_options & DEF_RADIUS_GROUP_OPTION_MS_CHAP_V2) {  /* options */
         ADSL_AGRE->boc_option_ms_chap_v2 = TRUE;  /* entry supports MS-CHAP-V2 */
       }
       return TRUE;                         /* all done                */
#undef ADSL_RADIUS_GROUP_W1
#undef ADSL_AGRE
     case DEF_AUX_SET_RADIUS_CONF:          /* set Radius group Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_set_radius_entry)) return FALSE;  /* invalid size */
#define ADSL_ASRE ((struct dsd_aux_set_radius_entry *) apparam)
       ADSL_ASRE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       if (ADSL_ASRE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_ASRE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_radius) return TRUE;  /* input index of entry too high */
       ADSL_ASRE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_RADIUS_GROUP_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_radius_group + ADSL_ASRE->imc_no_entry))
       ADSL_CONN1_G->adsc_radius_group = ADSL_RADIUS_GROUP_W1;  /* set active Radius group */
       if (ADSL_CONN1_G->adsc_ldap_group == NULL) {  /* check active LDAP group */
         ADSL_CONN1_G->adsc_ldap_group = ADSL_CONN1_G->adsc_radius_group->adsc_ldap_group;  /* set corresponding LDAP group */
       }
       return TRUE;                         /* all done                */
#undef ADSL_RADIUS_GROUP_W1
#undef ADSL_ASRE
     case DEF_AUX_REL_RADIUS_CONF:          /* release Radius group Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_rel_radius_entry)) return FALSE;  /* invalid size */
#define ADSL_ARRE ((struct dsd_aux_rel_radius_entry *) apparam)
       if (ADSL_CONN1_G->adsc_radius_group == NULL) {
         ADSL_ARRE->iec_ret_rel_radius = ied_ret_rel_radius_not_set;  /* Radius group not set */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc <= 1) {
         ADSL_ARRE->iec_ret_rel_radius = ied_ret_rel_radius_not_mult_conf;  /* not multiple Radius groups configured */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_radius_group->adsc_ldap_group) {  /* set corresponding LDAP group */
         if (ADSL_CONN1_G->adsc_radius_group->adsc_ldap_group == ADSL_CONN1_G->adsc_ldap_group) {
           ADSL_CONN1_G->adsc_ldap_group = NULL;  /* clear LDAP entry  */
         }
       }
       ADSL_CONN1_G->adsc_radius_group = NULL;  /* clear entry         */
       ADSL_ARRE->iec_ret_rel_radius = ied_ret_rel_radius_ok;  /* release o.k. */
       return TRUE;                         /* all done                */
#undef ADSL_ARRE
     case DEF_AUX_KRB5_SIGN_ON:             /* sign-on with Kerberos   */
       if (imp_length != sizeof(struct dsd_aux_krb5_sign_on_1)) return FALSE;  /* invalid size */
#define ADSL_AKSO1 ((struct dsd_aux_krb5_sign_on_1 *) apparam)
       if (ADSL_CONN1_G->adsc_krb5_kdc_1 == NULL) {
         ADSL_AKSO1->iec_ret_krb5 = ied_ret_krb5_kdc_not_sel;  /* KDC not selected */
         if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc == 0) {
           ADSL_AKSO1->iec_ret_krb5 = ied_ret_krb5_kdc_not_conf;  /* KDC not configured */
         }
         return TRUE;
       }
       return m_krb5_sign_on( ADSL_AUX_CF1,
                              ADSL_CONN1_G->adsc_krb5_kdc_1,
                              ADSL_AKSO1 );
#undef ADSL_AKSO1
     case DEF_AUX_KRB5_SE_TI_GET:           /* Kerberos get Service Ticket */
       if (imp_length != sizeof(struct dsd_aux_krb5_se_ti_get_1)) return FALSE;  /* invalid size */
#define ADSL_AKSTG1 ((struct dsd_aux_krb5_se_ti_get_1 *) apparam)
       if (ADSL_CONN1_G->adsc_krb5_kdc_1 == NULL) {
         ADSL_AKSTG1->iec_ret_krb5 = ied_ret_krb5_kdc_not_sel;  /* KDC not selected */
         if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc == 0) {
           ADSL_AKSTG1->iec_ret_krb5 = ied_ret_krb5_kdc_not_conf;  /* KDC not configured */
         }
         return TRUE;
       }
       return m_krb5_se_ti_get( ADSL_AUX_CF1,
                                ADSL_CONN1_G->adsc_krb5_kdc_1,
                                ADSL_AKSTG1 );
#undef ADSL_AKSTG1
     case DEF_AUX_KRB5_SE_TI_C_R:           /* Kerberos check Service Ticket Response */
       if (imp_length != sizeof(struct dsd_aux_krb5_se_ti_c_r_1)) return FALSE;  /* invalid size */
       return m_krb5_se_ti_c_r( ADSL_AUX_CF1,
                                (struct dsd_aux_krb5_se_ti_c_r_1 *) apparam );
     case DEF_AUX_KRB5_GET_SESS_KEY:        /* Kerberos-5 retrieve session key */
       if (imp_length != sizeof(struct dsd_aux_krb5_get_session_key)) return FALSE;  /* invalid size */
       return m_krb5_get_session_key( (struct dsd_aux_krb5_get_session_key *) apparam );
     case DEF_AUX_KRB5_ENCRYPT:             /* Kerberos encrypt data   */
       if (imp_length != sizeof(struct dsd_aux_krb5_encrypt)) return FALSE;  /* invalid size */
       return m_krb5_encrypt( ADSL_AUX_CF1,
                              (struct dsd_aux_krb5_encrypt *) apparam );
     case DEF_AUX_KRB5_DECRYPT:             /* Kerberos decrypt data   */
       if (imp_length != sizeof(struct dsd_aux_krb5_decrypt)) return FALSE;  /* invalid size */
       return m_krb5_decrypt( ADSL_AUX_CF1,
                              (struct dsd_aux_krb5_decrypt *) apparam );
     case DEF_AUX_KRB5_SE_TI_REL:           /* Kerberos release Service Ticket Resources */
       if (imp_length != sizeof(struct dsd_aux_krb5_se_ti_rel_1)) return FALSE;  /* invalid size */
       return m_krb5_se_ti_rel( ADSL_AUX_CF1,
                                (struct dsd_aux_krb5_se_ti_rel_1 *) apparam );
     case DEF_AUX_KRB5_LOGOFF:              /* release Kerberos TGT    */
       if (imp_length != sizeof(struct dsd_aux_krb5_logoff)) return FALSE;  /* invalid size */
#define ADSL_AKLO ((struct dsd_aux_krb5_logoff *)  apparam)
       return m_krb5_logoff( ADSL_AUX_CF1, ADSL_AKLO );
#undef ADSL_AKLO
     case DEF_AUX_GET_KRB5_CONF:            /* get Kerberos Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_get_krb5_entry)) return FALSE;  /* invalid size */
#define ADSL_AGKE ((struct dsd_aux_get_krb5_entry *) apparam)
       ADSL_AGKE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       ADSL_AGKE->imc_ret_conf_entry = ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc;  /* return number of configured entries */
       memset( &ADSL_AGKE->dsc_ret_name, 0, sizeof(struct dsd_unicode_string) );  /* return name of configured entry */
       memset( &ADSL_AGKE->dsc_ret_comment, 0, sizeof(struct dsd_unicode_string) );  /* return comment of configured entry */
       if (ADSL_AGKE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_AGKE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) return TRUE;  /* input index of entry too high */
       ADSL_AGKE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_KRB5_KDC_1_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_krb5_kdc_1 + ADSL_AGKE->imc_no_entry))
       ADSL_AGKE->dsc_ret_name.ac_str = ADSL_KRB5_KDC_1_W1 + 1;  /* address of string */
       ADSL_AGKE->dsc_ret_name.imc_len_str = ADSL_KRB5_KDC_1_W1->imc_len_name;  /* length string in elements */
       ADSL_AGKE->dsc_ret_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
       ADSL_AGKE->dsc_ret_comment.ac_str = (char *) (ADSL_KRB5_KDC_1_W1 + 1) + ADSL_KRB5_KDC_1_W1->imc_len_name;  /* address of string */
       ADSL_AGKE->dsc_ret_comment.imc_len_str = ADSL_KRB5_KDC_1_W1->imc_len_comment;  /* length string in elements */
       ADSL_AGKE->dsc_ret_comment.iec_chs_str = ied_chs_utf_8;  /* character set string */
       return TRUE;                         /* all done                */
#undef ADSL_KRB5_KDC_1_W1
#undef ADSL_AGKE
     case DEF_AUX_SET_KRB5_CONF:            /* set Kerberos Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_set_krb5_entry)) return FALSE;  /* invalid size */
#define ADSL_ASKE ((struct dsd_aux_set_krb5_entry *) apparam)
       ADSL_ASKE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       if (ADSL_ASKE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_ASKE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) return TRUE;  /* input index of entry too high */
       ADSL_ASKE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_KRB5_KDC_1_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_krb5_kdc_1 + ADSL_ASKE->imc_no_entry))
       ADSL_CONN1_G->adsc_krb5_kdc_1 = ADSL_KRB5_KDC_1_W1;  /* set active Kerberos 5 KDC */
       if (ADSL_CONN1_G->adsc_ldap_group == NULL) {  /* check active LDAP group */
         ADSL_CONN1_G->adsc_ldap_group = ADSL_CONN1_G->adsc_krb5_kdc_1->adsc_ldap_group;  /* set corresponding LDAP group */
       }
       return TRUE;                         /* all done                */
#undef ADSL_KRB5_KDC_1_W1
#undef ADSL_ASKE
     case DEF_AUX_REL_KRB5_CONF:            /* release Kerberos Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_rel_krb5_entry)) return FALSE;  /* invalid size */
#define ADSL_ARKE ((struct dsd_aux_rel_krb5_entry *) apparam)
       if (ADSL_CONN1_G->adsc_krb5_kdc_1 == NULL) {
         ADSL_ARKE->iec_ret_rel_krb5 = ied_ret_rel_krb5_not_set;  /* KDC not set */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc <= 1) {
         ADSL_ARKE->iec_ret_rel_krb5 = ied_ret_rel_krb5_not_mult_conf;  /* not multiple KDC configured */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_krb5_kdc_1->adsc_ldap_group) {  /* set corresponding LDAP group */
         if (ADSL_CONN1_G->adsc_krb5_kdc_1->adsc_ldap_group == ADSL_CONN1_G->adsc_ldap_group) {
           ADSL_CONN1_G->adsc_ldap_group = NULL;  /* clear LDAP entry  */
         }
       }
       ADSL_CONN1_G->adsc_krb5_kdc_1 = NULL;  /* clear entry           */
       ADSL_ARKE->iec_ret_rel_krb5 = ied_ret_rel_krb5_ok;  /* release o.k. */
       return TRUE;                         /* all done                */
#undef ADSL_ARKE
     case DEF_AUX_SESSION_KRB5_CONF:        /* assign Kerberos Configuration Entry to session */
       if (imp_length != sizeof(struct dsd_aux_krb5_session_assign_conf)) return FALSE;  /* invalid size */
#define ADSL_AKSAC ((struct dsd_aux_krb5_session_assign_conf *)  apparam)
       if (ADSL_CONN1_G->adsc_krb5_kdc_1) {  /* KDC already set        */
         ADSL_AKSAC->iec_ret_krb5 = ied_ret_krb5_conf_already_set;  /* KDC already set */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc <= 1) {  /* check number of configured entries */
         ADSL_AKSAC->iec_ret_krb5 = ied_ret_krb5_not_mult_conf;  /* not multiple KDC configured */
         return TRUE;                       /* all done                */
       }
       ADSL_CONN1_G->adsc_krb5_kdc_1 = m_krb5_session_assign_conf( ADSL_AUX_CF1, ADSL_AKSAC );
       if (ADSL_CONN1_G->adsc_krb5_kdc_1 == NULL) return TRUE;
       if (ADSL_CONN1_G->adsc_ldap_group == NULL) {  /* check active LDAP group */
         ADSL_CONN1_G->adsc_ldap_group = ADSL_CONN1_G->adsc_krb5_kdc_1->adsc_ldap_group;  /* set corresponding LDAP group */
       }
       return TRUE;                         /* all done                */
#undef ADSL_AKSAC
     case DEF_AUX_GET_LDAP_CONF:            /* get LDAP Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_get_ldap_entry)) return FALSE;  /* invalid size */
#define ADSL_AGLE ((struct dsd_aux_get_ldap_entry *) apparam)
       ADSL_AGLE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       ADSL_AGLE->imc_ret_conf_entry = ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group;  /* return number of configured entries */
       memset( &ADSL_AGLE->dsc_ret_name, 0, sizeof(struct dsd_unicode_string) );  /* return name of configured entry */
       memset( &ADSL_AGLE->dsc_ret_comment, 0, sizeof(struct dsd_unicode_string) );  /* return comment of configured entry */
       if (ADSL_AGLE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_AGLE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) return TRUE;  /* input index of entry too high */
       ADSL_AGLE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_LDAP_GROUP_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_ldap_group + ADSL_AGLE->imc_no_entry))
       ADSL_AGLE->dsc_ret_name.ac_str = ADSL_LDAP_GROUP_W1 + 1;  /* address of string */
       ADSL_AGLE->dsc_ret_name.imc_len_str = ADSL_LDAP_GROUP_W1->imc_len_name;  /* length string in elements */
       ADSL_AGLE->dsc_ret_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
       ADSL_AGLE->dsc_ret_comment.ac_str = (char *) (ADSL_LDAP_GROUP_W1 + 1) + ADSL_LDAP_GROUP_W1->imc_len_name;  /* address of string */
       ADSL_AGLE->dsc_ret_comment.imc_len_str = ADSL_LDAP_GROUP_W1->imc_len_comment;  /* length string in elements */
       ADSL_AGLE->dsc_ret_comment.iec_chs_str = ied_chs_utf_8;  /* character set string */
       return TRUE;                         /* all done                */
#undef ADSL_LDAP_GROUP_W1
#undef ADSL_AGLE
     case DEF_AUX_SET_LDAP_CONF:            /* set LDAP Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_set_ldap_entry)) return FALSE;  /* invalid size */
#define ADSL_ASLE ((struct dsd_aux_set_ldap_entry *) apparam)
       ADSL_ASLE->boc_ret_ok = FALSE;       /* return TRUE if o.k.     */
       if (ADSL_ASLE->imc_no_entry < 0) return TRUE;  /* input index of entry invalid */
       if (ADSL_ASLE->imc_no_entry >= ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) return TRUE;  /* input index of entry too high */
       ADSL_ASLE->boc_ret_ok = TRUE;        /* return TRUE if o.k.     */
#define ADSL_LDAP_GROUP_W1 (*(ADSL_CONN1_G->adsc_gate1->adsrc_ldap_group + ADSL_ASLE->imc_no_entry))
       ADSL_CONN1_G->adsc_ldap_group = ADSL_LDAP_GROUP_W1;  /* set active LDAP group */
       return TRUE;                         /* all done                */
#undef ADSL_LDAP_GROUP_W1
#undef ADSL_ASLE
     case DEF_AUX_REL_LDAP_CONF:            /* release LDAP Configuration Entry */
       if (imp_length != sizeof(struct dsd_aux_rel_ldap_entry)) return FALSE;  /* invalid size */
#define ADSL_ARLE ((struct dsd_aux_rel_ldap_entry *) apparam)
       if (ADSL_CONN1_G->adsc_ldap_group == NULL) {
         ADSL_ARLE->iec_ret_rel_ldap = ied_ret_rel_ldap_not_set;  /* LDAP not set */
         return TRUE;                       /* all done                */
       }
       if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group <= 1) {
         ADSL_ARLE->iec_ret_rel_ldap = ied_ret_rel_ldap_not_mult_conf;  /* not multiple LDAP configured */
         return TRUE;                       /* all done                */
       }
       ADSL_CONN1_G->adsc_ldap_group = NULL;  /* clear entry           */
       ADSL_ARLE->iec_ret_rel_ldap = ied_ret_rel_ldap_ok;  /* release o.k. */
       return TRUE;                         /* all done                */
#undef ADSL_ARLE
     case DEF_AUX_GET_SESSION_INFO:         /* get information about the session */
       if (imp_length != sizeof(struct dsd_aux_get_session_info)) return FALSE;  /* invalid size */
#define ADSL_GSI ((struct dsd_aux_get_session_info *) apparam)
       memset( ADSL_GSI, 0, sizeof(struct dsd_aux_get_session_info) );
       ADSL_GSI->imc_session_no = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
//#ifdef NOT_YET_130704
       ADSL_GSI->iec_coty = ADSL_CONN1_G->adsc_gate1->iec_coty;  /* connection type */
//#endif
//     memset( &ADSL_GSI->dsc_scp_name, 0, sizeof(struct dsd_unicode_string) );
       ADSL_GSI->iec_scp_def = ied_scp_undef;  /* protocol undefined   */
       ADSL_GSI->iec_ass = ied_ass_not_conf;  /* server not configured */
// to-do 19.12.10 KB not connected
#ifndef HL_UNIX
       memcpy( &ADSL_GSI->dsc_soa_client,
               &ADSL_CONN1_G->dcl_tcp_r_c.dsc_soa,
               sizeof(struct sockaddr_storage) );
       switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
         case ied_servcotype_normal_tcp:    /* normal TCP              */
           ADSL_GSI->iec_ast = ied_ast_tcp_os;  /* TCP of OS           */
           memcpy( &ADSL_GSI->dsc_soa_server_other,  /* address information server on other side */
                   &ADSL_CONN1_G->dcl_tcp_r_s.dsc_soa,  /* sockaddr from class to receive server */
                   sizeof(struct sockaddr_storage) );
           iml_so1 = sizeof(struct sockaddr_storage);
#ifdef B110316

           iml1 = getsockname( ADSL_CONN1_G->dcl_tcp_r_s.dsc_tcpco1.mc_getsocket(),
                               (struct sockaddr *) &ADSL_GSI->dsc_soa_server_this,  /* address information server on this side */
                               &iml_so1 );
#else
           iml1 = getsockname( ADSL_CONN1_G->dcl_tcp_r_s.m_get_socket(),
                               (struct sockaddr *) &ADSL_GSI->dsc_soa_server_this,  /* address information server on this side */
                               &iml_so1 );
#endif
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
#ifdef D_INCL_HOB_TUN
         case ied_servcotype_htun:          /* HOB-TUN                 */
           if (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL) {  /* no INETA */
             ADSL_GSI->iec_ass = ied_ass_disco;  /* disconnected from server */
             break;
           }
// to do 20.04.13 KB - IPV4 and IPV6 both possible at the same time
           if (ADSL_CONN1_G->adsc_ineta_raws_1->boc_with_user) {  /* structure with user */
             ADSL_GSI->iec_ast = ied_ast_tcp_htun;  /* TCP of HOB-TUN, HOB-TCP */
             if (ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_family != 0) {
               ADSL_GSI->dsc_soa_server_this.ss_family = AF_INET;
               memcpy( &((struct sockaddr_in *) &ADSL_GSI->dsc_soa_server_this)->sin_addr,
                       &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                       sizeof(UNSIG_MED) );
               ((struct sockaddr_in *) &ADSL_GSI->dsc_soa_server_this)->sin_port
                 = htons( ADSL_CONN1_G->adsc_ineta_raws_1->usc_appl_port );  /* port in use */
             } else if (ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_family != 0) {
               ADSL_GSI->dsc_soa_server_this.ss_family = AF_INET6;
               memcpy( &((struct sockaddr_in6 *) &ADSL_GSI->dsc_soa_server_this)->sin6_addr,
                       &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr,
                       16 );
               ((struct sockaddr_in6 *) &ADSL_GSI->dsc_soa_server_this)->sin6_port
                 = htons( ADSL_CONN1_G->adsc_ineta_raws_1->usc_appl_port );  /* port in use */
             }
           }
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
#endif
         case ied_servcotype_l2tp:          /* L2TP                    */
           ADSL_GSI->iec_ast = ied_ast_l2tp;  /* L2TP over UDP         */
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
       }
#endif
#ifdef HL_UNIX
       memcpy( &ADSL_GSI->dsc_soa_client,
               &ADSL_CONN1_G->dsc_tc1_client.dsc_soa_conn,
               sizeof(struct sockaddr_storage) );
       switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
         case ied_servcotype_normal_tcp:    /* normal TCP              */
           ADSL_GSI->iec_ast = ied_ast_tcp_os;  /* TCP of OS           */
           memcpy( &ADSL_GSI->dsc_soa_server_other,  /* address information server on other side */
                   &ADSL_CONN1_G->dsc_tc1_server.dsc_soa_conn,  /* sockaddr from class to receive server */
                   sizeof(struct sockaddr_storage) );
           iml_so1 = sizeof(struct sockaddr_storage);
           iml1 = getsockname( ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.mc_getsocket(),
                               (struct sockaddr *) &ADSL_GSI->dsc_soa_server_this,  /* address information server on this side */
                               &iml_so1 );
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
#ifdef D_INCL_HOB_TUN
         case ied_servcotype_htun:          /* HOB-TUN                 */
           if (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL) {  /* no INETA */
             ADSL_GSI->iec_ass = ied_ass_disco;  /* disconnected from server */
             break;
           }
// to do 20.04.13 KB - IPV4 and IPV6 both possible at the same time
// to do 28.07.14 KB - fill ADSL_GSI->dsc_soa_server_other  /* address information server on other side */
           if (ADSL_CONN1_G->adsc_ineta_raws_1->boc_with_user) {  /* structure with user */
             ADSL_GSI->iec_ast = ied_ast_tcp_htun;  /* TCP of HOB-TUN, HOB-TCP */
#ifndef B140728
             memcpy( &ADSL_GSI->dsc_soa_server_other,  /* address information server on other side */
                     &ADSL_CONN1_G->dsc_soa_htcp_server,  /* address information for connected */
                     sizeof(struct sockaddr_storage) );
#endif
             if (ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_family != 0) {
               ADSL_GSI->dsc_soa_server_this.ss_family = AF_INET;
               memcpy( &((struct sockaddr_in *) &ADSL_GSI->dsc_soa_server_this)->sin_addr,
                       &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                       sizeof(UNSIG_MED) );
               ((struct sockaddr_in *) &ADSL_GSI->dsc_soa_server_this)->sin_port
                 = htons( ADSL_CONN1_G->adsc_ineta_raws_1->usc_appl_port );  /* port in use */
             } else if (ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_family != 0) {
               ADSL_GSI->dsc_soa_server_this.ss_family = AF_INET6;
               memcpy( &((struct sockaddr_in6 *) &ADSL_GSI->dsc_soa_server_this)->sin6_addr,
                       &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr,
                       16 );
               ((struct sockaddr_in6 *) &ADSL_GSI->dsc_soa_server_this)->sin6_port
                 = htons( ADSL_CONN1_G->adsc_ineta_raws_1->usc_appl_port );  /* port in use */
             }
           }
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
#endif
         case ied_servcotype_l2tp:          /* L2TP                    */
           ADSL_GSI->iec_ast = ied_ast_l2tp;  /* L2TP over UDP         */
           ADSL_GSI->iec_ass = ied_ass_connected;  /* connected to server */
           break;
       }
#endif
       if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) return TRUE;  /* configuration server */
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;
       ADSL_GSI->boc_csssl = adsl_server_conf_1_w1->boc_use_csssl;  /* with client-side SSL */
       if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {
         adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous;
       }
       ADSL_GSI->imc_server_port = adsl_server_conf_1_w1->inc_server_port;  /* port of the server */
       ADSL_GSI->adsc_bind_out = &adsl_server_conf_1_w1->dsc_bind_out;  /* IP address multihomed */
       ADSL_GSI->adsc_server_ineta = adsl_server_conf_1_w1->adsc_server_ineta;  /* INETAs of the server */
#ifndef B170213
// 26.01.17 KB - add dsc_ucs_server_dns_name
       ADSL_GSI->dsc_server_dns_name.ac_str = adsl_server_conf_1_w1->achc_dns_name;  /* address of DNS name */
       ADSL_GSI->dsc_server_dns_name.imc_len_str = adsl_server_conf_1_w1->imc_len_dns_name;  /* length of DNS name */
       ADSL_GSI->dsc_server_dns_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
#endif
       ADSL_GSI->iec_scp_def = ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def;
       if (ADSL_GSI->iec_scp_def != ied_scp_spec) return TRUE;  /* special protocol */
       ADSL_GSI->dsc_scp_name.ac_str = ADSL_CONN1_G->adsc_server_conf_1->awcc_protocol;  /* address of string */
       ADSL_GSI->dsc_scp_name.imc_len_str = ADSL_CONN1_G->adsc_server_conf_1->inc_len_protocol / sizeof(HL_WCHAR) - 1;  /* length string in elements */
       ADSL_GSI->dsc_scp_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
       return TRUE;                         /* all done                */
#undef ADSL_GSI
     case DEF_AUX_UDP_GATE:                 /* handle UDP-gate         */
       if (imp_length != sizeof(struct dsd_aux_cmd_udp_gate)) return FALSE;  /* invalid size */
#define ADSL_CMD_UG ((struct dsd_aux_cmd_udp_gate *) apparam)
       return m_aux_udp_gate_1( vpp_userfld, ADSL_CMD_UG );
#undef ADSL_CMD_UG
     case DEF_AUX_NOT_DROP_TCP_PACKET:      /* do not drop TCP packets */
       if (imp_length != sizeof(BOOL)) return FALSE;  /* invalid size  */
//#ifdef ERROR_1308
//#ifndef HL_UNIX
       switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
#ifdef D_INCL_HOB_TUN
         case ied_servcotype_htun:          /* HOB-TUN                 */
#ifdef B130808
           ADSL_CONN1_G->dsc_tun_contr1.boc_not_drop_tcp_packet = *((BOOL *) apparam);  /* do not drop TCP packets */
#else
           ADSL_CONN1_G->dsc_tun_contr_conn.boc_not_drop_tcp_packet = *((BOOL *) apparam);  /* do not drop TCP packets */
#endif
           break;
#endif
         case ied_servcotype_l2tp:          /* L2TP                    */
           ADSL_CONN1_G->dsc_l2tp_session.boc_not_drop_tcp_packet = *((BOOL *) apparam);  /* do not drop TCP packets */
           break;
       }
//#endif
//#endif
       return TRUE;
     case DEF_AUX_GET_DUIA:                 /* get domain userid INETA */
       if (imp_length != sizeof(struct dsd_aux_get_duia_1)) return FALSE;  /* invalid size  */
#define ADSL_GDUIA1_G ((struct dsd_aux_get_duia_1 *) apparam)
       m_aux_get_duia_1( ADSL_CONN1_G, ADSL_GDUIA1_G );
       return TRUE;
#undef ADSL_GDUIA1_G
     case DEF_AUX_SECURE_XOR:               /* apply secure XOR        */
       if (imp_length != sizeof(struct dsd_aux_secure_xor_1)) return FALSE;  /* invalid size  */
       return m_aux_secure_xor( (struct dsd_aux_secure_xor_1 *) apparam);
     case DEF_AUX_WEBSO_CONN:               /* connect for WebSocket applications */
       if (imp_length != sizeof(struct dsd_aux_webso_conn_1)) return FALSE;  /* invalid size  */
       return m_aux_webso_conn( vpp_userfld, (struct dsd_aux_webso_conn_1 *) apparam);
//   case DEF_AUX_SECURE_RANDOM:            /* get secure random       */
     case DEF_AUX_SECURE_RANDOM_SEED:       /* get secure random       */
#ifdef B130405
       iml1 = m_secdrbg_randbytes( (char *) apparam, imp_length );
       if (iml1 == imp_length) return TRUE;
       return FALSE;
#endif
#ifdef HL_UNIX
#ifndef B160423
       if (dss_loconf_1.achc_ext_random_g_domain_socket_name) {  /* external Random Generator */
         return m_get_secure_seed( vpp_userfld, apparam, imp_length );
       }
#endif
#endif
#ifdef B160706
       iml1 = m_secdrbg_randbytes( (char *) apparam, imp_length );
       if (iml1 == 0) return TRUE;
       if (vpp_userfld) {
         m_hlnew_printf( HLOG_WARN1, "HWSPS200W GATE=%(ux)s SNO=%08d INETA=%s create secure random returned error %d.",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                         iml1 );
       } else {
         m_hlnew_printf( HLOG_WARN1, "HWSPM300W create secure random returned error %d.",
                         iml1 );
       }
#endif
#ifndef B160706
       m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW called depreciated aux-call l%05d - no %d",
                       __LINE__, DEF_AUX_SECURE_RANDOM_SEED );
#endif
       return FALSE;
     case DEF_AUX_GET_WSP_FINGERPRINT:      /* get WSP fingerprint     */
       if (imp_length != DEF_LEN_FINGERPRINT) return FALSE;  /* invalid size  */
       memcpy( apparam, dsg_this_server.chrc_fingerprint, DEF_LEN_FINGERPRINT );
       return TRUE;
     case DEF_AUX_PIPE:                     /* aux-pipe                */
       if (imp_length != sizeof(struct dsd_aux_pipe_req_1)) return FALSE;  /* aux-pipe request - invalid size */
       return m_aux_pipe_manage( vpp_userfld, (struct dsd_aux_pipe_req_1 *) apparam );
     case DEF_AUX_UTILITY_THREAD:           /* create unitliy thread   */
       if (imp_length != sizeof(struct dsd_aux_util_thread_call_1)) return FALSE;  /* create utility thread - invalid size */
       return m_aux_util_thread_cmd( vpp_userfld, (struct dsd_aux_util_thread_call_1 *) apparam );
     case DEF_AUX_SWAP_STOR:                /* manage swap storage     */
       if (imp_length != sizeof(struct dsd_aux_swap_stor_req_1)) return FALSE;   /* swap storage request - invalid size */
       return m_aux_swap_stor_req_1( vpp_userfld, (struct dsd_aux_swap_stor_req_1 *) apparam );
     case DEF_AUX_DYN_LIB:                  /* manage dynamic library  */
       if (imp_length != sizeof(struct dsd_aux_dyn_lib_req_1)) return FALSE;  /* dynamic library request - invalid size */
       return m_aux_dyn_lib_req_1( vpp_userfld, (struct dsd_aux_dyn_lib_req_1 *) apparam );
     case DEF_AUX_SIG_GET_CLIENT:           /* signature - get client credentials */
//     achl_func = "DEF_AUX_SIG_GET_CLIENT";  /* text of function      */
//     break;
       return FALSE;
     case DEF_AUX_SIG_SIGN_NONCE:           /* signature - sign nonce  */
//     achl_func = "DEF_AUX_SIG_SIGN_NONCE";  /* text of function      */
//     break;
       return FALSE;
     case DEF_AUX_SET_SESSION_TIMEOUT:      /* set session timeout     */
       ADSL_CONN1_G->imc_timeout_set = imp_length;  /* timeout set in seconds */
       if (imp_length == 0) return TRUE;    /* no timeout set          */
       ill_w1 = m_get_epoch_ms() + imp_length * 1000;  /* get current end-time */
       if (ADSL_CONN1_G->dsc_timer.vpc_chain_2 != NULL) {  /* timer set */
         if (ill_w1 <= ADSL_CONN1_G->dsc_timer.ilcendtime) {  /* no need to set new timer */
           return TRUE;
         }
         m_time_rel( &ADSL_CONN1_G->dsc_timer );  /* release timer     */
       }
       ADSL_CONN1_G->dsc_timer.ilcendtime = ill_w1;  /* set new end-time */
       m_time_set( &ADSL_CONN1_G->dsc_timer, TRUE );  /* set new timer */
       return TRUE;
     case DEF_AUX_GET_DOMAIN_INFO:          /* retrieve domain-information of connection - gate */
       if (imp_length != sizeof(struct dsd_aux_get_domain_info_1)) return FALSE;  /* get domain-information - invalid size */
       return m_aux_get_domain_info_1( vpp_userfld, (struct dsd_aux_get_domain_info_1 *) apparam );
     case DEF_AUX_GET_RPC_CONF:             /* get RPC Configuration Entry */
       return FALSE;
     case DEF_AUX_SET_RPC_CONF:             /* set RPC Configuration Entry */
       return FALSE;
     case DEF_AUX_REL_RPC_CONF:             /* release RPC Configuration Entry */
       return FALSE;
#ifdef XYZ1
     case DEF_AUX_AUTH_RPC:                 /* authenticate over RPC   */
       return FALSE;
#endif
#ifdef INCL_TEST_RPC
     case DEF_AUX_AUTH_RPC_NTLMV2:          /* authenticate NTLMv2 over RPC */
       if (imp_length != sizeof(struct dsd_aux_auth_rpc_ntlmv2_1)) return FALSE;  /* not correct size */
       return m_rpc_ntlmv2_proc( ADSL_AUX_CF1->adsc_hco_wothr,
                                 ADSL_CONN1_G,
                                 ADSL_CONN1_G->adsc_rpc_group,  /* active RPC group */
                                 (struct dsd_aux_auth_rpc_ntlmv2_1 *) apparam );
#endif
     case DEF_AUX_FILE_IO:                  /* file input-output       */
       if (imp_length != sizeof(struct dsd_aux_file_io_req_1)) return FALSE;  /* file IO request - invalid size */
       iml1 = iml2 = 0;
       if (vpp_userfld) {
         iml1 = ADSL_CONN1_G->imc_trace_level;
         iml2 = ADSL_CONN1_G->dsc_co_sort.imc_sno;
       }
       return m_aux_file_io_req_1( vpp_userfld, (struct dsd_aux_file_io_req_1 *) apparam, iml1, iml2 );
     case DEF_AUX_SET_LOCAL_USER:           /* set local user          */
       if (imp_length != sizeof(struct dsd_hl_aux_set_local_user)) return FALSE;  /* set local user - invalid size */
#define ADSL_AUX_SETLOCUSER ((struct dsd_hl_aux_set_local_user *) apparam)
#ifdef XYZ1
       dsl_us_userid.ac_str = ADSL_AUX_SETLOCUSER->dsc_ucs_userid.ac_str;  /* address of string */
       dsl_us_userid.imc_len_str = ADSL_AUX_SETLOCUSER->dsc_ucs_userid.imc_len_str;  /* length string in elements */
       dsl_us_userid.iec_chs_str = ADSL_AUX_SETLOCUSER->dsc_ucs_userid.iec_chs_str;  /* character set string */
       dsl_us_password.imc_len_str = 0;     /* length password         */
       ADSL_AUX_SETLOCUSER->iec_chid_ret = m_auth_user(
                        &ADSL_CONN1_G->adsc_user_entry,
                        &ADSL_CONN1_G->adsc_user_group,
                        ADSL_CONN1_G,
                        &dsl_us_userid,
                        &dsl_us_password,
                        FALSE,              /* do not check password   */
                        TRUE );
#endif
#ifdef WSP_V24
#define ADSL_G_IDSET1_G ((struct dsd_aux_set_ident_1 *) byrl_work1)
       memset( ADSL_G_IDSET1_G, 0, sizeof(struct dsd_aux_set_ident_1) );
       ADSL_G_IDSET1_G->dsc_userid = ADSL_AUX_SETLOCUSER->dsc_ucs_userid;
#endif
       ADSL_AUX_SETLOCUSER->iec_chid_ret = m_auth_user(
                        &ADSL_CONN1_G->adsc_user_entry,
                        &ADSL_CONN1_G->adsc_user_group,
                        ADSL_CONN1_G,
#ifndef WSP_V24
                        &ADSL_AUX_SETLOCUSER->dsc_ucs_userid,
#endif
#ifdef WSP_V24
                        ADSL_G_IDSET1_G,
#endif
                        NULL,
                        FALSE,              /* do not check password   */
                        TRUE );
#ifdef WSP_V24
#undef ADSL_G_IDSET1_G
#endif
       if (ADSL_AUX_SETLOCUSER->avpc_usent) {
         *ADSL_AUX_SETLOCUSER->avpc_usent = ADSL_CONN1_G->adsc_user_entry;
       }
       if (ADSL_AUX_SETLOCUSER->avpc_usgro) {
         *ADSL_AUX_SETLOCUSER->avpc_usgro = ADSL_CONN1_G->adsc_user_group;
       }
       if (ADSL_AUX_SETLOCUSER->adsc_ucs_password) {  /* fill with password */
         ADSL_AUX_SETLOCUSER->adsc_ucs_password->imc_len_str = 0;  /* set length zero */
         if (   (ADSL_AUX_SETLOCUSER->iec_chid_ret == ied_chid_ok)  /* userid and password valid */
             && (ADSL_CONN1_G->adsc_user_entry)) {
#define ADSL_USER_ENTRY_G ((struct dsd_user_entry *) ADSL_CONN1_G->adsc_user_entry)
           ADSL_AUX_SETLOCUSER->adsc_ucs_password->ac_str = (char *) (ADSL_USER_ENTRY_G + 1) + ADSL_USER_ENTRY_G->inc_len_name_bytes;
           ADSL_AUX_SETLOCUSER->adsc_ucs_password->imc_len_str = ADSL_USER_ENTRY_G->inc_len_password_bytes;  /* len of password in bytes */
           ADSL_AUX_SETLOCUSER->adsc_ucs_password->iec_chs_str = ied_chs_utf_8;  /* character set string */
#undef ADSL_USER_ENTRY_G
         }
       }
       return TRUE;                         /* all done                */
#undef ADSL_AUX_SETLOCUSER
     case DEF_AUX_CHECK_LOGOUT:             /* check logout at sign on */
       return FALSE;                        /* not yet implemented - 13.03.14 KB */
     case DEF_AUX_GET_ADDR_SERVER_ERROR:    /* get address zero-terminated message server error */
       if (imp_length != sizeof(void *)) return FALSE;  /* correct size */
       *((char **) apparam) = ADSL_CONN1_G->chrc_server_error;  /* display server error */
       return TRUE;                         /* all done                */
     case DEF_AUX_GET_SSL_SERVER_CERT:      /* get address SSL used server certificate */
       if (imp_length != sizeof(struct dsd_hl_aux_ssl_get_server_cert)) return FALSE;  /* correct size */
#define ADSL_AFSSC_G ((struct dsd_hl_aux_ssl_get_server_cert *) apparam)
       ADSL_AFSSC_G->imc_error = 0;         /* zero = no error         */
       bol_rc = m_get_server_certificate( &ADSL_AFSSC_G->ac_addr_server_cert,  /* address of server certificate */
                                          &ADSL_AFSSC_G->imc_len_server_cert,  /* length of server certificate */
                                          ADSL_CONN1_G->dsc_hlse03s.ac_ext );
       if (bol_rc) return TRUE;
       ADSL_AFSSC_G->imc_error = 1;         /* zero = no error         */
       return TRUE;
#undef ADSL_AFSSC_G
     case DEF_AUX_SDH_RELOAD:               /* manage SDH reload       */
       if (imp_length != sizeof(struct dsd_hl_aux_manage_sdh_reload)) return FALSE;  /* correct size */
       return m_aux_sdh_reload_call( vpp_userfld, (struct dsd_hl_aux_manage_sdh_reload *) apparam );
     case DEF_AUX_DEBUG_CHECK:              /* debug check             */
       if (imp_length != 1) return FALSE;   /* not implemented         */
#ifndef HL_UNIX
#ifdef _DEBUG
       iml1 = _CrtCheckMemory();
       if (iml1 == 0) {
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d _CrtCheckMemory() returned zero - heap corrupted",
                         __LINE__ );
       }
       return iml1;
#endif
#endif
       return TRUE;
#ifndef B160423
     case DEF_AUX_RANDOM_VISIBLE:           /* get visible secure random - nonce */
     case DEF_AUX_RANDOM_HIDDEN:            /* get hidden secure random */
       iml1 = m_secdrbg_randbytes( (char *) apparam, imp_length );
       if (iml1 == 0) return TRUE;
       if (vpp_userfld) {
         m_hlnew_printf( HLOG_WARN1, "HWSPS200W GATE=%(ux)s SNO=%08d INETA=%s create secure random returned error %d.",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                         iml1 );
       } else {
         m_hlnew_printf( HLOG_WARN1, "HWSPM300W create secure random returned error %d.",
                         iml1 );
       }
       return FALSE;
#endif
     case DEF_AUX_GET_CS_SSL_ADDR:          /* get addresses of client-side SSL implementation */
       if (imp_length != sizeof(struct dsd_aux_get_cs_ssl_addr)) return FALSE;  /* get addresses of client-side SSL implementation */
#ifndef HL_UNIX
#define ADSL_LOCONF_1_G adsg_loconf_1_inuse
#else
#define ADSL_LOCONF_1_G (&dss_loconf_1)
#endif
#define ADSL_AGSSA_G ((struct dsd_aux_get_cs_ssl_addr *) apparam)
       ADSL_AGSSA_G->vpc_csssl_config_id = ADSL_LOCONF_1_G->vpc_csssl_config_id;  /* Client Side SSL Configuration to use */
       ADSL_AGSSA_G->amc_cl_registerconfig = &m_cl_registerconfig;
       ADSL_AGSSA_G->amc_release_config = &m_release_config;
       ADSL_AGSSA_G->amc_hlcl01 = &m_hlcl01;
       ADSL_AGSSA_G->amc_FromASN1_DNCommonNameToString = &FromASN1_DNCommonNameToString;
       ADSL_AGSSA_G->amc_FromASN1CertToCertStruc = &FromASN1CertToCertStruc;
       ADSL_AGSSA_G->amc_FreeCertStruc = &FreeCertStruc;
       return TRUE;
#undef ADSL_LOCONF_1_G
#undef ADSL_AGSSA_G
   }
   /* not new element                                                  */
#ifdef B130319
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;
#else
   adsl_auxf_1_w1 = *aadsl_auxf_1_cur;      /* get current chain auxiliary extension fields */
#endif
   adsl_auxf_1_w2 = NULL;                   /* no previous yet         */
   while (adsl_auxf_1_w1) {
     if ((adsl_auxf_1_w1 + 1) == X_AUADDR) break;
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save previous           */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() called 2 vpp_userfld=%p adsl_auxf_1_w1=%p",
                   vpp_userfld, adsl_auxf_1_w1 );
#endif
   if (adsl_auxf_1_w1 == NULL) {            /* not found in chain      */
     byrl_work1[ 0 ] = 0;                   /* no content              */
     if (vpp_userfld) {
       m_hlsnprintf( byrl_work1, sizeof(byrl_work1), ied_chs_utf_8,  /* Unicode UTF-8 */
                     " GATE=%(ux)s SNO=%08d INETA=%s",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS201W%(u8)s aux-call l%05d invalid addresses %p %p - not found in chain",
                     byrl_work1, __LINE__, apparam, X_AUADDR );
     return FALSE;
   }
   switch (imp_func) {
     case DEF_AUX_MEMFREE:                  // release a block of memory
#ifdef TRACEHLP
       ADSL_CONN1_G->inc_aux_mem_cur -= adsl_auxf_1_w1->inc_size_mem;
#endif
       if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_normstor) {  /* normal storage */
#ifdef B170224
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
#endif
#ifndef B170224
         if (ADSL_AUX_CF1->dsc_cid.iec_src_func != ied_src_fu_util_thread) {  /* not utility thread */
#ifndef HL_UNIX
           EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
           ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section  */
#endif
         }
#endif
         if (adsl_auxf_1_w2 == NULL) {      /* is first in chain       */
#ifdef B130319
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
#else
           *aadsl_auxf_1_cur = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
#endif
         } else {                           /* in middle of chain      */
           adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
         }
#ifdef B170224
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
#endif
#ifndef B170224
         if (ADSL_AUX_CF1->dsc_cid.iec_src_func != ied_src_fu_util_thread) {  /* not utility thread */
#ifndef HL_UNIX
           LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
           ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section  */
#endif
         }
#endif
         free( adsl_auxf_1_w1 );            /* give back to os         */
         return TRUE;                       /* all done                */
       }
       if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_defstor) {  /* predefined storage */
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
         if (adsl_auxf_1_w2 == NULL) {      /* is first in chain       */
#ifdef B130319
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
#else
           *aadsl_auxf_1_cur = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
#endif
         } else {                           /* in middle of chain      */
           adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
         }
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
         m_proc_free( adsl_auxf_1_w1 );     /* put in chain of unused  */
         return TRUE;                       /* all done                */
       }
       m_hlnew_printf( HLOG_XYZ1, "UUUU 18.09.04 m_cdaux() DEF_AUX_MEMFREE invalid iec_auxf_def found" );
       return FALSE;
     case DEF_AUX_DISKFILE_RELEASE:         // release a disk file
#ifdef TRACEHL_070505
       bol1 = TRUE;
       if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_diskfile) {  /* compare disk-file */
         bol1 = FALSE;
       }
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505D l%05d DEF_AUX_DISKFILE_RELEASE release entry adsl_auxf_1_w1=%p, iec_auxf_def=%d, bol1=%d",
                       __LINE__, adsl_auxf_1_w1, adsl_auxf_1_w1->iec_auxf_def, bol1 );
#endif
       if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_diskfile) {  /* compare disk-file */
         return FALSE;
       }
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_w2 == NULL) {        /* is first in chain       */
#ifdef B130319
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
#else
        *aadsl_auxf_1_cur = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
#endif
       } else {                             /* in middle of chain      */
         adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       time( (time_t *) &(*((struct dsd_diskfile_1 **) (adsl_auxf_1_w1 + 1)))->ipc_time_last_acc );  /* get current time */
       dss_critsect_aux.m_enter();
       (*((struct dsd_diskfile_1 **) (adsl_auxf_1_w1 + 1)))->inc_usage_count--;  /* usage-count */
       dss_critsect_aux.m_leave();
       free( adsl_auxf_1_w1 );              /* give back to os         */
       return TRUE;                         /* all done                */
   }
   m_hlnew_printf( HLOG_XYZ1, "UUUU 18.09.04 m_cdaux() invalid imp_func found" );
   return FALSE;
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
#undef X_AUADDR
} /* end m_secondary_aux()                                             */

/** add an entry to the session entry chain                            */
extern "C" char * m_wsp_s_ent_add( void *vpp_userfld, int imp_type,
                                   int imp_len_content ) {
   int        iml1;                         /* working variable        */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   iml1 = sizeof(struct dsd_auxf_ext_1);    /* set length extra memory */
   switch (imp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       iml1 = sizeof(struct dsd_hco_wacha_1);  /* size extra memory    */
       break;
     case DEF_WSP_TYPE_SIP:
       iel_auxf_def = ied_auxf_sip;         /* SIP request             */
       break;
     case DEF_WSP_TYPE_UDP:
       iel_auxf_def = ied_auxf_udp;         /* UDP request             */
       break;
     case DEF_WSP_TYPE_GATE_UDP:
       iel_auxf_def = ied_auxf_gate_udp;    /* UDP-gate entry          */
       break;
     case DEF_WSP_TYPE_SERVICE:
       iel_auxf_def = ied_auxf_service_query_1;  /* service query 1    */
       break;
     default:
       m_hl_abend1( "m_wsp_s_ent_add() invalid imp_type" );
       break;
   }
#ifdef B060709
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                 + sizeof(dsd_wsp_cma_lock_1)
                                                 + imp_len_content );
#endif
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + iml1 + imp_len_content );
   adsl_auxf_1_w1->iec_auxf_def = iel_auxf_def;  /* type of entry      */
#ifndef B131225
   memcpy( &adsl_auxf_1_w1->dsc_cid,
           &ADSL_AUX_CF1->dsc_cid,
           sizeof(struct dsd_cid) );        /* current Server-Data-Hook */
#endif
#ifdef TRACEHLP
   adsl_auxf_1_w1->inc_size_mem = imp_len_content;  /* size of memory  */
   ADSL_CONN1_G->inc_aux_mem_cur += adsl_auxf_1_w1->inc_size_mem;
   if (ADSL_CONN1_G->inc_aux_mem_max < ADSL_CONN1_G->inc_aux_mem_cur) {
     ADSL_CONN1_G->inc_aux_mem_max = ADSL_CONN1_G->inc_aux_mem_cur;
   }
#endif
   if (imp_type != DEF_WSP_TYPE_CMA) {
     ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal = 0;  /* clear signal */
#ifdef B130314
     ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->ac_sdh = ADSL_AUX_CF1->ac_sdh;  /* current Server-Data-Hook */
#endif
     memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid,
             &ADSL_AUX_CF1->dsc_cid,        /* current component / Server-Data-Hook */
             sizeof(dsd_cid) );
     adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
     return (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1);
   }
   m_hco_wothr_wacha_prep( ADSL_AUX_CF1->adsc_hco_wothr, (struct dsd_hco_wacha_1 *) (adsl_auxf_1_w1 + 1) );
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504131 m_wsp_s_ent_add() clconn1=%p adsl_auxf_1_w1=%p imp_len_content=%d ret_val=%p",
                   ADSL_CONN1_G, adsl_auxf_1_w1, imp_len_content,
                   (char *) (adsl_auxf_1_w1 + 1) + sizeof(dsd_hco_wacha_1) );
#endif
   return (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_hco_wacha_1);
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_wsp_s_ent_add()                                             */

/** delete an entry from the session entry chain                       */
extern "C" void m_wsp_s_ent_del( void *vpp_userfld, int imp_type, char *achp_entry ) {
#ifdef B060709
   BOOL       bol1;                         /* working variable        */
#endif
   int        iml1;                         /* working variable        */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_hco_wothr *adsc_hco_wothr;    /* working variable        */

#ifdef TRY_080211
   if (vpp_userfld == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSP-l%05d m_wsp_s_ent_del( vpp_userfld == NULL )", __LINE__ );
     return;
   }
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504132 m_wsp_s_ent_del() clconn1=%p achp_entry=%p",
               ADSL_CONN1_G, achp_entry );
#endif
   iml1 = sizeof(struct dsd_auxf_ext_1);    /* set length extra memory */
   switch (imp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       iml1 = sizeof(struct dsd_hco_wacha_1);  /* size extra memory    */
       break;
     case DEF_WSP_TYPE_SIP:
       iel_auxf_def = ied_auxf_sip;         /* SIP request             */
       break;
     case DEF_WSP_TYPE_UDP:
       iel_auxf_def = ied_auxf_udp;         /* UDP request             */
       break;
     case DEF_WSP_TYPE_SERVICE:
       iel_auxf_def = ied_auxf_service_query_1;  /* service query 1    */
       break;
     default:
       m_hl_abend1( "m_wsp_s_ent_del() invalid imp_type" );
       break;
   }
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of chain     */
   adsl_auxf_1_w2 = NULL;                   /* clear last element      */
   while (adsl_auxf_1_w1) {
#ifdef B060709
     if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(dsd_wsp_cma_lock_1)) == achp_entry) {
#ifdef FORKEDIT
     }
#endif
#else
     if (((char *) (adsl_auxf_1_w1 + 1) + iml1) == achp_entry) {
#endif
       if (adsl_auxf_1_w1->iec_auxf_def != iel_auxf_def) {  /* type of entry */
         m_hl_abend1( "m_wsp_s_ent_del() element has different type" );
       }
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_w2 == NULL) {        /* replace at anchor       */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
       } else {                             /* middle in chain         */
         adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       if (imp_type == DEF_WSP_TYPE_CMA) {
         /* activate all work threads that are waiting                 */
         m_hco_wothr_wacha_rel( ADSL_AUX_CF1->adsc_hco_wothr,
                                (struct dsd_hco_wacha_1 *) (adsl_auxf_1_w1 + 1) );
       }
#ifdef B060628
#ifndef HL_UNIX
       while (((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->adsc_workth) {
         adsl_workth_1 = ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->adsc_workth;
         ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->adsc_workth
           = (class clworkth *) adsl_workth_1->vpc_lock_1;
#ifdef TRACEHL_CMA_050413
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504133 m_wsp_s_ent_del() clconn1=%p adsl_auxf_1_w1=%p achp_entry=%p adsl_workth_1=%p adsl_workth_1->vpc_lock_1=%p",
                     ADSL_CONN1_G, adsl_auxf_1_w1, achp_entry, adsl_workth_1, adsl_workth_1->vpc_lock_1 );
#endif
         bol1 = SetEvent( adsl_workth_1->hevework );
         if (bol1 == FALSE) {
           m_hlnew_printf( HLOG_XYZ1, "HWSPM061W m_wsp_s_ent_del() SetEvent WORK Error %d",
                       GetLastError() );
         }
       }
#endif
#endif
#ifdef TRACEHLP
       ADSL_CONN1_G->inc_aux_mem_cur -= adsl_auxf_1_w1->inc_size_mem;
#endif
       free( adsl_auxf_1_w1 );              /* free memory again       */
       return;                              /* all done                */
     }
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save this element       */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   m_hl_abend1( "m_wsp_s_ent_del() element not found" );
   return;                                  /* for compiler only       */
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_wsp_s_ent_del()                                             */

/** retrieve an entry from the session entry chain                     */
extern "C" char * m_wsp_s_ent_get( void *vpp_userfld, int imp_type, char *achp_entry ) {
   BOOL       bol1;                         /* working variable        */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;        /* auxiliary extension fi  */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   switch (imp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       break;
     default:
       m_hl_abend1( "m_wsp_s_ent_get() invalid imp_type" );
       break;
   }
   bol1 = FALSE;                            /* not next element        */
   if (achp_entry == NULL) bol1 = TRUE;     /* return next element     */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of chain     */
   while (adsl_auxf_1_w1) {
     if (adsl_auxf_1_w1->iec_auxf_def == iel_auxf_def) {  /* type of entry */
       if (bol1) return (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_hco_wacha_1);
       if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_hco_wacha_1)) == achp_entry) {
         bol1 = TRUE;                       /* return next element     */
       }
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   if (bol1) return NULL;                   /* was last element        */
   m_hl_abend1( "m_wsp_s_ent_get() element not found" );
   return NULL;                             /* for compiler only       */
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_wsp_s_ent_get()                                             */

/** add an entry to the wait-chain                                     */
extern "C" void m_wsp_s_ent_wacha_add( void *vpp_userfld, int inp_type, char *achp_entry_this, char *achp_entry_lock ) {
   m_hco_wothr_wacha_append( ((struct dsd_aux_cf1 *) vpp_userfld)->adsc_hco_wothr,
                             (struct dsd_hco_wacha_1 *) (achp_entry_this - sizeof(struct dsd_hco_wacha_1)),
                             (struct dsd_hco_wacha_1 *) (achp_entry_lock - sizeof(struct dsd_hco_wacha_1)) );
} /* end m_wsp_s_ent_wacha_add()                                       */

#ifdef B090226
/* wait for event, depending on session entry chain                    */
extern "C" void m_wsp_s_wait( void *vpp_userfld_w, int imp_type, void *vpp_userfld_p, char *achp_entry ) {
   DWORD      dwl1;                         /* working variable        */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#ifdef B060709
#ifndef HL_UNIX
   class clworkth *adsl_workth_1;           /* working variable        */
#else
   struct dsd_hco_wothr *adsc_hco_wothr;    /* working variable        */
#endif
#endif

#ifdef B060530
#define ADSL_CONN1_G_W ((DSD_CONN_G *) vpp_userfld_w)
#define ADSL_CONN1_G_P ((DSD_CONN_G *) vpp_userfld_p)
#endif
#define ADSL_CONN1_G_W ((DSD_CONN_G *) ((struct dsd_aux_cf1 *) vpp_userfld_w)->adsc_conn)
#define ADSL_CONN1_G_P ((DSD_CONN_G *) ((struct dsd_aux_cf1 *) vpp_userfld_p)->adsc_conn)
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504134 m_wsp_s_wait() clconn1-w=%p clconn1-p=%p achp_entry=%p",
                   ADSL_CONN1_G_W, ADSL_CONN1_G_P, achp_entry );
#endif
   switch (imp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       break;
     default:
       m_hl_abend1( "m_wsp_s_wait() invalid imp_type" );
       break;
   }
   dss_critsect_aux.m_enter();
   adsl_auxf_1_w1 = ADSL_CONN1_G_P->adsc_auxf_1;  /* anchor of chain   */
   while (adsl_auxf_1_w1) {                 /* loop over all aux entries */
#ifdef B060709
     if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(dsd_wsp_cma_lock_1)) == achp_entry) {
#ifdef FORKEDIT
     }
#endif
#else
     if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_hco_lock_1)) == achp_entry) {
#endif
       if (adsl_auxf_1_w1->iec_auxf_def != iel_auxf_def) {  /* type of entry */
         m_hl_abend1( "m_wsp_s_wait() element has different type" );
       }
       /* chain of work threads waiting for this lock                  */
#ifdef B060628
#ifndef HL_UNIX
       ADSL_CONN1_G_W->adsc_workth->vpc_lock_1
         = ADSL_CONN1_G_P->adsc_workth->vpc_lock_1;
       ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->adsc_workth
         = ADSL_CONN1_G_W->adsc_workth;
#endif
#endif
       break;                               /* all done                */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   dss_critsect_aux.m_leave();
   if (adsl_auxf_1_w1 == NULL) {            /* nothing to wait for     */
     return;                                /* do not wait             */
   }
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504135 m_wsp_s_wait() has to wait clconn1-w=%p clconn1-p=%p achp_entry=%p",
                   ADSL_CONN1_G_W, ADSL_CONN1_G_P, achp_entry );
#endif
   m_hco_wothr_lock( ((struct dsd_aux_cf1 *) vpp_userfld_w)->adsc_hco_wothr,
                     (struct dsd_hco_lock_1 *) (adsl_auxf_1_w1 + 1) );
#ifdef B060628
#ifndef HL_UNIX
   ADSL_CONN1_G_W->adsc_workth->m_set_block();
   dwl1 = WaitForSingleObject( ADSL_CONN1_G_W->adsc_workth->hevework, INFINITE );
   if (dwl1 != WAIT_OBJECT_0) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPM065W m_wsp_s_wait() WaitForSingleObject() Return %d Error %d", dwl1, GetLastError() );
   }
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504136 m_wsp_s_wait() after wait clconn1-w=%p ADSL_CONN1_G_W->adsc_workth->vpc_lock_1=%p achp_entry=%p",
                   ADSL_CONN1_G_W, ADSL_CONN1_G_W->adsc_workth->vpc_lock_1, achp_entry );
// ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_w1 + 1))->adsc_workth = NULL;
#endif
   ADSL_CONN1_G_W->adsc_workth->m_set_active();
#endif
#endif
#undef ADSL_CONN1_G_W
#undef ADSL_CONN1_G_P
} /* end m_wsp_s_wait()                                                */
#endif

/** wait for event, depending on session entry chain                   */
extern "C" void m_wsp_s_wait( void *vpp_userfld_w, int inp_type, char *achp_entry ) {
   DWORD      dwl1;                         /* working variable        */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#ifdef B060709
#ifndef HL_UNIX
   class clworkth *adsl_workth_1;           /* working variable        */
#else
   struct dsd_hco_wothr *adsc_hco_wothr;    /* working variable        */
#endif
#endif

#define ADSL_CONN1_G_W ((DSD_CONN_G *) ((struct dsd_aux_cf1 *) vpp_userfld_w)->adsc_conn)
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504134 m_wsp_s_wait() clconn1-w=%p clconn1-p=%p achp_entry=%p",
                   ADSL_CONN1_G_W, ADSL_CONN1_G_P, achp_entry );
#endif
   switch (inp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       break;
     default:
       m_hl_abend1( "m_wsp_s_wait() invalid inp_type" );
       break;
   }
   dss_critsect_aux.m_enter();
   adsl_auxf_1_w1 = ADSL_CONN1_G_W->adsc_auxf_1;  /* anchor of chain   */
   while (adsl_auxf_1_w1) {                 /* loop over all aux entries */
     if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_hco_wacha_1)) == achp_entry) {
       if (adsl_auxf_1_w1->iec_auxf_def != iel_auxf_def) {  /* type of entry */
         m_hl_abend1( "m_wsp_s_wait() element has different type" );
       }
       /* chain of work threads waiting for this lock                  */
       break;                               /* all done                */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   dss_critsect_aux.m_leave();
   if (adsl_auxf_1_w1 == NULL) {            /* nothing to wait for     */
     m_hl_abend1( "m_wsp_s_wait() entry not found in chain" );
   }
#ifdef TRACEHL_CMA_050413
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504135 m_wsp_s_wait() has to wait clconn1-w=%p achp_entry=%p",
                   ADSL_CONN1_G_W, achp_entry );
#endif
#ifdef PROBLEM_090225                       /* hangs at close          */
   m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux-l%05d-T before m_hco_wothr_wacha_wait( %p )",
                   __LINE__, adsl_auxf_1_w1 + 1 );
#endif
   m_hco_wothr_wacha_wait( (struct dsd_hco_wacha_1 *) (adsl_auxf_1_w1 + 1) );
#ifdef PROBLEM_090225                       /* hangs at close          */
   m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux-l%05d-T after  m_hco_wothr_wacha_wait( %p )",
                   __LINE__, adsl_auxf_1_w1 + 1 );
#endif
#undef ADSL_CONN1_G_W
} /* end m_wsp_s_wait()                                                */

/** notify an entry with a signal                                      */
extern "C" void m_wsp_s_ent_notify( void * adsp_conn, char *achp_entry, int imp_signal ) {
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux-l%05d-T m_wsp_s_ent_notify( %p , %p , %08X )",
                   __LINE__, adsp_conn, achp_entry, imp_signal );
#endif
/**
   comment:
   this routine would be faster
   if the corresponding entry
   would be taken direct, not thru searching
   but this implementation is more save against programming errors
*/
#define ADSL_CONN1_G ((DSD_CONN_G *) adsp_conn)
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of chain     */
   while (adsl_auxf_1_w1) {                 /* loop over all aux entries */
     if (((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)) == achp_entry) {
       break;                               /* element found           */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_w1 == NULL) {            /* entry not found         */
     m_hlnew_printf( HLOG_WARN1, "xiipgw08-aux-l%05d-W m_wsp_s_ent_notify( %p , %p , %08X ) entry not found",
                     __LINE__, adsp_conn, achp_entry, imp_signal );
     return;                                /* ignore this call        */
   }
   ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal |= imp_signal;  /* set signal */
#ifndef B130314
   ADSL_CONN1_G->boc_signal_set = TRUE;     /* signal for component set */
#endif
   m_act_thread_1( ADSL_CONN1_G );
#undef ADSL_CONN1_G
} /* end m_wsp_s_ent_notify()                                          */

/** count entries from the session entry chain                         */
extern "C" int m_wsp_s_count( void *vpp_userfld, int imp_type ) {
   int        iml_count;                    /* count entries           */
   ied_auxf_def iel_auxf_def;               /* type of entry           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   switch (imp_type) {
     case DEF_WSP_TYPE_CMA:
       iel_auxf_def = ied_auxf_cma1;        /* common memory area      */
       break;
     default:
       m_hl_abend1( "m_wsp_s_count() invalid imp_type" );
       break;
   }
   iml_count = 0;                           /* reset count entries     */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of chain     */
   while (adsl_auxf_1_w1) {                 /* loop over all auxiliary entries */
     if (adsl_auxf_1_w1->iec_auxf_def == iel_auxf_def) {  /* type of entry */
       iml_count++;                         /* increment count entries */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   return iml_count;                        /* return count entries    */
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_wsp_s_count()                                               */

/** return the connection from a given userfield                       */
extern "C" DSD_CONN_G * m_get_conn1_from_userfld( void *vpp_userfld ) {
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
   return ADSL_AUX_CF1->adsc_conn;          /* pointer on connection */
#undef ADSL_AUX_CF1
} /* end m_get_conn1_from_userfld()                                    */

/** return address of field chain buffers extra                        */
extern "C" struct dsd_sdh_control_1 ** m_get_sdhc1_extra_from_conn1( DSD_CONN_G *adsp_conn1 ) {
   return &adsp_conn1->adsc_sdhc1_extra;
} /* end m_get_sdhc1_extra_from_conn1()                                */

/** activate the connection with a signal                              */
extern "C" void m_act_conn1_signal( DSD_CONN_G *adsp_conn1, char *achp_ext, int imp_signal ) {
   ((struct dsd_auxf_ext_1 *) achp_ext - 1)->imc_signal |= imp_signal;  /* set signal */
#ifndef B130314
   adsp_conn1->boc_signal_set = TRUE;       /* signal for component set */
#endif
#ifndef HL_UNIX
   m_act_conn( adsp_conn1 );                /* activate connection     */
#else
   m_act_thread_1( adsp_conn1 );            /* activate work-thread    */
#endif
} /* end m_act_conn1_signal()                                          */

/** radius request is complete                                         */
static void m_aux_radius_req_compl( struct dsd_radius_control_1 *adsp_rctrl1, int imp_error ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */

#define AADSL_HCO_WOTHR ((struct dsd_hco_wothr **) ((char *) adsp_rctrl1 + sizeof(struct dsd_radius_control_1)))
#define ABOL_POSTED ((BOOL *) ((char *) adsp_rctrl1 + sizeof(struct dsd_radius_control_1) + sizeof(void *)))
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux-l%05d-T m_aux_radius_req_compl( %p ) AADSL_HCO_WOTHR=%p ABOL_POSTED=%p.",
                   __LINE__, adsp_rctrl1, AADSL_HCO_WOTHR, ABOL_POSTED );
#endif
   *ABOL_POSTED = TRUE;                     /* radius request complete */
   iml_rc = (*AADSL_HCO_WOTHR)->dsc_event.m_post( &iml_error );
   if (iml_rc != 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnn001W error post event %d %d.",
                     iml_rc, iml_error );
   }
#undef AADSL_HCO_WOTHR
#undef ABOL_POSTED
} /* end m_aux_radius_req_compl()                                      */

#ifdef TRACEHL_070505
static int ims_trace_mem_c = 0;             /* count memory            */
#endif
#define DSD_WORKTHR struct dsd_hco_wothr

/** read a file into memory                                            */
static void m_read_diskfile( DSD_WORKTHR *adsp_workthr, int imp_trace_level, int imp_sno, int imp_func,
                             struct dsd_hl_aux_diskfile_1 *adsp_aux_df1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, inl2;                   /* working variables       */
   DWORD      dwl1;                         /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   int        iml_len_name;                 /* length of file-name     */
   HL_LONGLONG ill_file_storage;            /* all files together      */
#ifndef HL_UNIX
   HL_LONGLONG ill_file_size;               /* size of this file       */
#endif
   HL_LONGLONG ill_pos_file;                /* position in file        */
   char       *achl_buffer;                 /* buffer for read         */
   int        iml_read;                     /* so much to read         */
   BOOL       bolerror;                     /* save error              */
   BOOL       bol_read_file;                /* read the file           */
   BOOL       bol_wait;                     /* wait for access to file */
   time_t     dsl_time_1;                   /* for time                */
   time_t     dsl_time_2;                   /* for time                */
#ifdef B060628
#ifndef HL_UNIX
   class clworkth *adsl_workth_1;           /* working variable        */
   class clworkth *adsl_workth_2;           /* working variable        */
#endif
#endif
   DSD_WORKTHR *adsl_workthr_w1;            /* working variable        */
   DSD_WORKTHR *adsl_workthr_w2;            /* working variable        */
#ifndef HL_UNIX
   unsigned long int uml_returned_read;     /* how much read from disk */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_diskfile_1 *adsl_df1_1;       /* diskfile in memory      */
   struct dsd_diskfile_1 *adsl_df1_2;       /* diskfile in memory      */
   struct dsd_diskfile_1 *adsl_df1_3;       /* diskfile in memory      */
   struct dsd_diskfile_1 *adsl_df1_4;       /* diskfile in memory      */
   struct dsd_diskfile_1 *adsl_df1_5;       /* diskfile in memory      */
   struct dsd_diskfile_1 *adsl_df1_lock;    /* file to lock            */
   struct dsd_diskfile_1 dsl_df1_this;      /* temporary diskfile      */
   struct dsd_unicode_string dsl_ucs_l;     /* working variable        */
#ifndef D_NO_SNMP
   struct dsd_wsp_snmp_trap_file_access dsl_wsp_snmp_trap_file_access;  /* File Access failed */
#endif
#ifndef HL_UNIX
   HANDLE     dsl_hfi1;                     /* handle for file         */
   BY_HANDLE_FILE_INFORMATION dsl_fi1;
   WIN32_FILE_ATTRIBUTE_DATA dsl_fi2;       /* file not opened         */
   WCHAR      wcrl_file_name[ MAX_PATH ];   /* for file name           */
#else
#ifdef OLD01
   int        iml_lnam_u16;                 /* length name UTF-16      */
#endif
   int        iml_fd_f1;                    /* file-descriptor for file */
   int        iml_rc1;                      /* return code             */
   struct stat dsl_stat_1;                  /* for stat()              */
   char       chrl_file_name[ 1024 ];       /* for file name           */
#endif

   bos_disk_file = TRUE;                    /* did access disk file    */
   adsp_aux_df1->adsc_int_df1 = NULL;
   adsp_aux_df1->ac_handle = NULL;
   adsp_aux_df1->imc_time_last_mod = 0;
   adsp_aux_df1->iec_dfar_def = ied_dfar_ok;  /* clear return-code     */
   /* input file-name may not be zero-terminated                       */
   dsl_ucs_l.ac_str = adsp_aux_df1->ac_name;
   dsl_ucs_l.imc_len_str = adsp_aux_df1->inc_len_name;
   dsl_ucs_l.iec_chs_str = adsp_aux_df1->iec_chs_name;  /* character set  */
#ifndef HL_UNIX
   switch (adsp_aux_df1->iec_chs_name) {    /* character set           */
     case ied_chs_ascii_850:                /* ASCII 850               */
       iml_len_name = adsp_aux_df1->inc_len_name;
#ifndef HL_UNIX
       if (iml_len_name >= MAX_PATH) iml_len_name = MAX_PATH - 1;
#endif
       iml1 = 0;
       while (iml1 < iml_len_name) {
         wcrl_file_name[ iml1 ] = ucrg_tab_850_to_819[ *((unsigned char *) adsp_aux_df1->ac_name + iml1) ];
         iml1++;                            /* next character          */
       }
       break;
     case ied_chs_ansi_819:                 /* ANSI 819                */
       iml_len_name = adsp_aux_df1->inc_len_name;
#ifndef HL_UNIX
       if (iml_len_name >= MAX_PATH) iml_len_name = MAX_PATH - 1;
#endif
       iml1 = 0;
       while (iml1 < iml_len_name) {
         wcrl_file_name[ iml1 ] = *((unsigned char *) adsp_aux_df1->ac_name + iml1);
         iml1++;                            /* next character          */
       }
       break;
     case ied_chs_utf_8:                    /* Unicode UTF-8           */
       achl1 = (char *) adsp_aux_df1->ac_name;
       achl2 = achl1 + adsp_aux_df1->inc_len_name;
       iml_len_name = 0;                    /* clear length target name */
       bolerror = FALSE;
       while (achl1 < achl2) {              /* loop over input         */
#ifdef B111216
         if (iml_len_name >= MAX_PATH) {    /* output too long         */
           bolerror = TRUE;
           break;
         }
#else
         if (iml_len_name >= MAX_PATH) break;  /* output too long      */
#endif
         if (((signed char) *achl1) >= 0) {
           wcrl_file_name[ iml_len_name ] = *((unsigned char *) achl1);
           iml_len_name++;                  /* next WCHAR output       */
           achl1++;
         } else {
           wcrl_file_name[ iml_len_name ] = (WCHAR) *achl1++;
           if (achl1 >= achl2) {
             bolerror = TRUE;
             break;
           }
           if (((signed char) *achl1) >= 0) {
             bolerror = TRUE;
             break;
           }
           if ((*achl1 & 0X40) != 0) {
             bolerror = TRUE;
             break;
           }
           if ((wcrl_file_name[ iml_len_name ] & 0X20) == 0) {
             wcrl_file_name[ iml_len_name ] &= 0X1F;
             wcrl_file_name[ iml_len_name ] <<= 6;
             wcrl_file_name[ iml_len_name ] |= *achl1++ & 0X3F;
           } else {
             wcrl_file_name[ iml_len_name ] &= 0X0F;
             wcrl_file_name[ iml_len_name ] <<= 6;
             wcrl_file_name[ iml_len_name ] |= *achl1++ & 0X3F;
             if (((signed char) *achl1) >= 0) {
               bolerror = TRUE;
               break;
             }
             if ((*achl1 & 0X40) != 0) {
               bolerror = TRUE;
               break;
             }
             wcrl_file_name[ iml_len_name ] <<= 6;
             wcrl_file_name[ iml_len_name ] |= *achl1++ & 0X3F;
           }
           iml_len_name++;                  /* next WCHAR output       */
         }
       }
#ifndef B111219
       if (iml_len_name >= MAX_PATH) {      /* output too long         */
         bolerror = TRUE;
         iml_len_name = MAX_PATH - 1;
       }
#endif
       if (bolerror == FALSE) break;
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF001W error in UTF-8 file-name" );
       break;
     case ied_chs_utf_16:                   /* Unicode UTF-16 = WCHAR  */
       iml_len_name = adsp_aux_df1->inc_len_name;
#ifndef HL_UNIX
       if (iml_len_name >= MAX_PATH) iml_len_name = MAX_PATH - 1;
#endif
       memcpy( wcrl_file_name, adsp_aux_df1->ac_name, iml_len_name * sizeof(HL_WCHAR) );
       break;
     default:
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF002W error in character-set file-name" );
       return;                              /* invalid parameter       */
   }
   wcrl_file_name[ iml_len_name ] = 0;      /* zero-terminated now     */
#else
   switch (adsp_aux_df1->iec_chs_name) {    /* character set           */
     case ied_chs_ascii_850:                /* ASCII 850               */
       iml_len_name = m_u8l_from_a819l( chrl_file_name, sizeof(chrl_file_name) - 1,
                                        (char *) adsp_aux_df1->ac_name, adsp_aux_df1->inc_len_name );
       if (iml_len_name < 0) {              /* target too short        */
         iml_len_name = sizeof(chrl_file_name) - 1;
       }
       break;
     case ied_chs_ansi_819:                 /* ANSI 819                */
       iml_len_name = m_u8l_from_a819l( chrl_file_name, sizeof(chrl_file_name) - 1,
                                        (char *) adsp_aux_df1->ac_name, adsp_aux_df1->inc_len_name );
       if (iml_len_name < 0) {              /* target too short        */
         iml_len_name = sizeof(chrl_file_name) - 1;
       }
       break;
     case ied_chs_utf_8:                    /* Unicode UTF-8           */
       iml_len_name = adsp_aux_df1->inc_len_name;  /* length target name */
       if (iml_len_name > (sizeof(chrl_file_name) - 1)) {  /* name to long */
         iml_len_name = sizeof(chrl_file_name) - 1;
       }
       memcpy( chrl_file_name, adsp_aux_df1->ac_name, iml_len_name );
       break;
     case ied_chs_utf_16:                   /* Unicode UTF-16 = WCHAR  */
       iml_len_name = m_u8l_from_u16l( chrl_file_name, sizeof(chrl_file_name) - 1,
                                       (HL_WCHAR *) adsp_aux_df1->ac_name, adsp_aux_df1->inc_len_name );
       if (iml_len_name < 0) {              /* target too short        */
         iml_len_name = sizeof(chrl_file_name) - 1;
       }
       break;
     default:
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF002W error in character-set file-name" );
       return;                              /* invalid parameter       */
   }
   chrl_file_name[ iml_len_name ] = 0;      /* zero-terminated now     */
#ifdef OLD01
   bol1 = m_count_u16_from_u8l( &iml_lnam_u16, chrl_file_name, iml_len_name );  /* length name UTF-16 */
#endif
#endif
   memset( &dsl_df1_this, 0, sizeof(struct dsd_diskfile_1) );  /* temporary diskfile */
#ifndef HL_UNIX
   dsl_df1_this.dsc_int_df1.awcc_name = (HL_WCHAR *) wcrl_file_name;
#else
   dsl_df1_this.dsc_int_df1.achc_name = chrl_file_name;
#endif
   dsl_df1_this.iec_difi_def = ied_difi_locked;  /* is locked          */

   predif20:                                /* search the file         */
   time( &dsl_time_1 );                     /* get current time        */
#ifndef HL_UNIX
   iml1 = adsg_loconf_1_inuse->inc_time_cache_disk_file;  /* so long in cache */
#else
   iml1 = dss_loconf_1.inc_time_cache_disk_file;  /* so long in cache  */
#endif
   if (iml1 == 0) iml1 = DEF_TIME_CACHE_DISK_FILE;
   if (iml1 < DEF_TIME_CACHE_DF_MIN) {      /* time in seconds         */
     iml1 = DEF_TIME_CACHE_DF_MIN;          /* set minimum time        */
   }
   dsl_time_2 = dsl_time_1 - iml1;          /* latest time             */
#ifndef HL_UNIX
#ifdef TRACEHL_050419
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC050419A m_read_diskfile() Thread=%d predif20 dsl_time_1=%d dsl_time_2=%d name=%(ux)s",
                   GetCurrentThreadId(), (int) dsl_time_1, (int) dsl_time_2, wcrl_file_name );
#endif
#else
#ifdef TRACEHL_050419
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC050419A m_read_diskfile() name=%(u8)s",
                   chrl_file_name );
#endif
#endif
   ill_file_storage = 0;                    /* all files together      */
   adsl_df1_2 = NULL;                       /* no file found           */
   adsl_df1_4 = NULL;                       /* set previous element    */
   bol_wait = FALSE;                        /* wait for access to file */
   dss_critsect_aux.m_enter();
   adsl_df1_1 = adss_df1_anchor;            /* get anchor of files     */
   while (adsl_df1_1) {                     /* loop over all files in cache */
#ifdef TRACEHL_070505
#ifndef HL_UNIX
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505A l%05d m_read_diskfile() adsl_df1_1=%p boc_superseeded=%d inc_usage_count=%d",
                     __LINE__, adsl_df1_1, adsl_df1_1->boc_superseeded, adsl_df1_1->inc_usage_count );
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505A l%05d m_read_diskfile() awcc_name=%(ux)s",
                     __LINE__, adsl_df1_1->dsc_int_df1.awcc_name );
     if (adsl_df1_1->dsc_int_df1.achc_filecont_start) {  /* file in memory */
       char chrh_work[32];
       HL_LONGLONG ilh1 = adsl_df1_1->dsc_int_df1.achc_filecont_end
                            - adsl_df1_1->dsc_int_df1.achc_filecont_start;
       m_edit_sci_two( chrh_work, ilh1 );
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505A l%05d m_read_diskfile() size=%s",
                       __LINE__, chrh_work );
    }
#endif
#endif
     if (adsl_df1_1->boc_superseeded == FALSE) {
#ifndef HL_UNIX
       if (!_wcsicoll( (WCHAR *) adsl_df1_1->dsc_int_df1.awcc_name, wcrl_file_name )) {
         adsl_df1_2 = adsl_df1_1;           /* save file found         */
       }
#else
       if (!strcmp( (char *) adsl_df1_1->dsc_int_df1.achc_name, chrl_file_name )) {
         adsl_df1_2 = adsl_df1_1;           /* save file found         */
       }
#endif
     }
     adsl_df1_3 = adsl_df1_1;               /* save this file pointer  */
     adsl_df1_1 = adsl_df1_1->adsc_next;    /* get next in chain       */
     /* check if this entry has to be removed from cache               */
     if (   (adsl_df1_3->inc_usage_count == 0)
#ifdef B070504
         && (adsl_df1_3->ipc_time_last_acc <= dsl_time_2)
#else
         && (   (adsl_df1_3->ipc_time_last_acc <= dsl_time_2)
             || (adsl_df1_3->boc_superseeded))
#endif
         && (adsl_df1_3->iec_difi_def != ied_difi_locked)
         && (adsl_df1_3 != adsl_df1_2)) {   /* not file found          */
       if (adsl_df1_4 == NULL) {            /* was first element       */
         adss_df1_anchor = adsl_df1_1;      /* set new chain           */
       } else {                             /* not first element       */
         adsl_df1_4->adsc_next = adsl_df1_1;  /* set new element in chain */
       }
       free( adsl_df1_3 );                  /* free memory             */
#ifdef TRACEHL_070505
       ims_trace_mem_c--;                   /* count memory            */
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505M l%05d m_read_diskfile() free %p ims_trace_mem_c=%d",
                       __LINE__, adsl_df1_3, ims_trace_mem_c );
#endif
#ifdef TRACEHL_050419
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504191 m_read_diskfile() Thread=%d adsl_df1_3=%p freed",
                   GetCurrentThreadId(), adsl_df1_3 );
       adsl_df1_3 = NULL;                   /* make pointer invalid    */
#endif
     } else {                               /* file still valid        */
       adsl_df1_4 = adsl_df1_3;             /* set previous element    */
       ill_file_storage += adsl_df1_3->dsc_int_df1.achc_filecont_end
                           - adsl_df1_3->dsc_int_df1.achc_filecont_start;
     }
   }
#ifdef TRACEHL_050419
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504195 m_read_diskfile() Thread=%d adss_df1_anchor=%p",
                   GetCurrentThreadId(), adss_df1_anchor );
   adsl_df1_1 = adss_df1_anchor;            /* get anchor of files     */
   while (adsl_df1_1) {                     /* loop over all files in cache */
#ifdef OLD01
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504196 m_read_diskfile() chain adsl_df1_1=%p ilc_file_size=%I64d len=%d start=%p end=%p inc_len_name=%d iec_difi_def=%d name=%(ux)s",
                 adsl_df1_1, adsl_df1_1->ilc_file_size,
                 adsl_df1_1->dsc_int_df1.achc_filecont_end
                   - adsl_df1_1->dsc_int_df1.achc_filecont_start,
                 adsl_df1_1->dsc_int_df1.achc_filecont_start,
                 adsl_df1_1->dsc_int_df1.achc_filecont_end,
                 adsl_df1_1->dsc_int_df1.inc_len_name,
                 adsl_df1_1->iec_difi_def,
                 adsl_df1_1->dsc_int_df1.awcc_name );
#endif
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504196 m_read_diskfile() chain adsl_df1_1=%p ilc_file_size=%d len=%d start=%p end=%p inc_len_name=%d iec_difi_def=%d ipc_time_last_acc=%d inc_usage_count=%d name=%(ux)s",
                     adsl_df1_1, (int) adsl_df1_1->ilc_file_size,
                     (int) (adsl_df1_1->dsc_int_df1.achc_filecont_end
                              - adsl_df1_1->dsc_int_df1.achc_filecont_start),
                     adsl_df1_1->dsc_int_df1.achc_filecont_start,
                     adsl_df1_1->dsc_int_df1.achc_filecont_end,
                     adsl_df1_1->dsc_int_df1.inc_len_name,
                     adsl_df1_1->iec_difi_def,
                     (int) adsl_df1_1->ipc_time_last_acc,
                     adsl_df1_1->inc_usage_count,
                     adsl_df1_1->dsc_int_df1.awcc_name );
     adsl_df1_1 = adsl_df1_1->adsc_next;    /* get next in chain       */
   }
#endif
#endif
   if (adsl_df1_2) {                        /* file found              */
     if (adsl_df1_2->iec_difi_def == ied_difi_locked) {  /* file is locked */
       adsl_workthr_w1 = adsl_df1_2->dsc_lock_1.adsc_ch_lock;  /* get chain of locks */
       adsl_workthr_w2 = NULL;              /* no previous element     */
       adsp_workthr->adsc_ch_lock = NULL;   /* chain of locked threads */
       while (adsl_workthr_w1) {            /* loop to find last in chain */
         adsl_workthr_w2 = adsl_workthr_w1;  /* save last entry        */
         adsl_workthr_w1 = adsl_workthr_w1->adsc_ch_lock;
       }
       if (adsl_workthr_w2 == NULL) {       /* first element           */
         adsl_df1_2->dsc_lock_1.adsc_ch_lock = adsp_workthr;
       } else {                             /* middle in chain         */
         adsl_workthr_w2->adsc_ch_lock = adsp_workthr;
       }
       bol_wait = TRUE;                     /* wait for access to file */
     } else {                               /* can use this file       */
       if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
         adsl_df1_2->inc_usage_count++;     /* file is in use          */
#ifdef TRACEHL_070505
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505F l%05d m_read_diskfile() in-use adsl_df1_2=%p inc_usage_count=%d",
                         __LINE__, adsl_df1_2, adsl_df1_2->inc_usage_count );
#endif
       }
     }
   } else {                                 /* insert dummy entry      */
     dsl_df1_this.adsc_next = adss_df1_anchor;  /* get old chain       */
     adss_df1_anchor = &dsl_df1_this;       /* insert temporary entry  */
   }
   dss_critsect_aux.m_leave();
   if (adsl_df1_2) {                        /* file found              */
     adsl_df1_2->ipc_time_last_acc = dsl_time_1;  /* get current time  */
     if (bol_wait) goto predif60;           /* wait for access to file */
     /* check if already superseeded                                   */
#ifndef HL_UNIX
     iml1 = adsg_loconf_1_inuse->inc_time_reload_disk_file;  /* check on disk */
#else
     iml1 = dss_loconf_1.inc_time_reload_disk_file;  /* check on disk  */
#endif
     if (iml1 == 0) iml1 = DEF_TIME_RELOAD_DISK_FILE;
     dsl_time_2 = dsl_time_1 - iml1;        /* latest time             */
     while (adsl_df1_2->ipc_time_last_checked < dsl_time_2) {  /* check now */
       adsl_df1_2->ipc_time_last_checked = dsl_time_1;  /* set checked now */
#ifndef HL_UNIX
       bol1 = GetFileAttributesExW( wcrl_file_name, GetFileExInfoStandard, &dsl_fi2 );
       if (bol1 == FALSE) {                 /* error / file cannot be accessed */
#ifdef D_NO_SNMP
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF010W m_read_diskfile %(ux)s GetFileAttributesExW() returned Error %d",
                         wcrl_file_name, GetLastError() );
#else
         dwl1 = GetLastError();
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF010W m_read_diskfile %(ux)s GetFileAttributesExW() returned Error %d",
                         wcrl_file_name, dwl1 );
         memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
         dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
         m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
         adsp_aux_df1->iec_dfar_def = ied_dfar_file_att;
         if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) break;
         if (adsl_df1_2->dsc_int_df1.achc_filecont_start) {
           ill_file_size = 0;
           memset( &dsl_fi1, 0, sizeof(dsl_fi1) );
           dsl_hfi1 = INVALID_HANDLE_VALUE;
           goto predif44;                   /* make entry for file     */
         }
         if (adsl_df1_2->iec_difi_def == ied_difi_locked) break;  /* file is locked */
         dss_critsect_aux.m_enter();
         if (adsl_df1_2->iec_difi_def == ied_difi_valid) {
           adsl_df1_2->iec_difi_def = ied_difi_not_exists;
           adsl_df1_2->ilc_file_size = 0;
           adsl_df1_2->dsc_int_df1.imc_time_last_mod = 0;
         }
         dss_critsect_aux.m_leave();
         break;
       }
       ill_file_size = ((HL_LONGLONG) dsl_fi2.nFileSizeHigh << 32) | dsl_fi2.nFileSizeLow;
       bol1 = FALSE;                        /* do not check            */
       if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) {
         bol1 = TRUE;                       /* check if read new       */
       } else {
#ifdef D_MAKE_ERROR_070727
         *((unsigned char *) &dsl_fi2.ftLastWriteTime) = 0XFF;  /* make invalid */
#endif
         if (memcmp( &adsl_df1_2->dsc_filetime_last_mod, &dsl_fi2.ftLastWriteTime, sizeof(struct _FILETIME) )) {
           adsl_df1_2->boc_superseeded = TRUE;
           memcpy( &adsl_df1_2->dsc_filetime_last_mod, &dsl_fi2.ftLastWriteTime, sizeof(struct _FILETIME) );
           adsl_df1_2->dsc_int_df1.imc_time_last_mod = m_win_epoch_from_filetime( &dsl_fi2.ftLastWriteTime );
           bol1 = TRUE;                     /* check if read new       */
         }
       }
#else                                       /* HL_UNIX                 */
       iml_rc1 = stat( chrl_file_name, &dsl_stat_1 );
       if (iml_rc1 < 0) {                   /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF010W m_read_diskfile %(u8)s stat() returned Error %d",
                         chrl_file_name, errno );
         adsp_aux_df1->iec_dfar_def = ied_dfar_file_att;
         if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) break;
         if (adsl_df1_2->dsc_int_df1.achc_filecont_start) {
           memset( &dsl_stat_1, 0, sizeof(dsl_stat_1) );
           iml_fd_f1 = -1;                  /* file not opened         */
           goto predif44;                   /* make entry for file     */
         }
         if (adsl_df1_2->iec_difi_def == ied_difi_locked) break;  /* file is locked */
         dss_critsect_aux.m_enter();
         if (adsl_df1_2->iec_difi_def == ied_difi_valid) {
           adsl_df1_2->iec_difi_def = ied_difi_not_exists;
           adsl_df1_2->ilc_file_size = 0;
           adsl_df1_2->dsc_int_df1.imc_time_last_mod = 0;
         }
         dss_critsect_aux.m_leave();
         break;
       }
       bol1 = FALSE;                        /* do not check            */
       if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) {
         bol1 = TRUE;                       /* check if read new       */
       } else {
         if (adsl_df1_2->dsc_int_df1.imc_time_last_mod != dsl_stat_1.st_mtime) {
           adsl_df1_2->boc_superseeded = TRUE;
           adsl_df1_2->dsc_int_df1.imc_time_last_mod = dsl_stat_1.st_mtime;
           bol1 = TRUE;                     /* check if read new       */
         }
       }
#endif
       if (bol1) {                          /* check if read new       */
         while (TRUE) {
           if (imp_func != DEF_AUX_DISKFILE_ACCESS) break;
#ifndef HL_UNIX
           if (adsg_loconf_1_inuse->ilc_disk_file_size_max) {  /* length one file */
             if (ill_file_size > adsg_loconf_1_inuse->ilc_disk_file_size_max) break;
           }
           if (adsg_loconf_1_inuse->ilc_disk_file_storage) {  /* maximum storage */
             if ((ill_file_storage + ill_file_size) > adsg_loconf_1_inuse->ilc_disk_file_storage) break;
           }
#else
           if (dss_loconf_1.ilc_disk_file_size_max) {  /* length one file */
             if (dsl_stat_1.st_size > dss_loconf_1.ilc_disk_file_size_max) break;
           }
           if (dss_loconf_1.ilc_disk_file_storage) {  /* maximum storage */
             if ((ill_file_storage + dsl_stat_1.st_size) > dss_loconf_1.ilc_disk_file_storage) break;
           }
#endif
           bol_read_file = TRUE;            /* read the file           */
#ifdef B070808
           iml1 = adsl_df1_2->inc_usage_count;  /* compare usage count */
           if (imp_func == DEF_AUX_DISKFILE_ACCESS) iml1--;
#else
           iml1 = adsl_df1_2->inc_usage_count - 1;  /* compare usage count */
#endif
           if (iml1 && adsl_df1_2->dsc_int_df1.achc_filecont_start) {
#ifdef B070803
             if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
               adsl_df1_2->inc_usage_count--;  /* is not in use any more */
             }
#else
             adsl_df1_2->inc_usage_count = iml1;  /* decrement usage count, if necessary */
#endif
             adsl_df1_2 = NULL;             /* do not free this entry  */
           }
           goto predif40;                   /* read the file now       */
         }
       }
       break;
     }
#ifdef B091102
     if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
#else
#ifdef FORKEDIT
     }
#endif
     if (   (adsl_df1_2->iec_difi_def == ied_difi_not_exists)
         && (adsp_aux_df1->iec_dfar_def == ied_dfar_ok)) {
       adsp_aux_df1->iec_dfar_def = ied_dfar_rep_error;  /* repeated error */
     }
     if (   (imp_func == DEF_AUX_DISKFILE_ACCESS)
         && (adsp_aux_df1->iec_dfar_def == ied_dfar_ok)) {
#endif
       if (adsl_df1_2->dsc_int_df1.achc_filecont_start == NULL) {
         while (TRUE) {
           adsp_aux_df1->iec_dfar_def = ied_dfar_cache_inv;
           if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) break;
           adsp_aux_df1->iec_dfar_def = ied_dfar_mem_file;
#ifndef HL_UNIX
           if (adsg_loconf_1_inuse->ilc_disk_file_size_max) {  /* length one file */
             if (adsl_df1_2->ilc_file_size
                  > adsg_loconf_1_inuse->ilc_disk_file_size_max) break;
           }
           if (adsg_loconf_1_inuse->ilc_disk_file_storage) {  /* maximum storage */
             if ((ill_file_storage + adsl_df1_2->ilc_file_size)
                   > adsg_loconf_1_inuse->ilc_disk_file_storage) break;
           }
#else
           if (dss_loconf_1.ilc_disk_file_size_max) {  /* length one file */
#ifdef NOT_YET
             if (adsl_df1_2->ilc_file_size
                  > dss_loconf_1.ilc_disk_file_size_max) break;
#endif
           }
           if (dss_loconf_1.ilc_disk_file_storage) {  /* maximum storage */
#ifdef NOT_YET
             if ((ill_file_storage + adsl_df1_2->ilc_file_size)
                   > dss_loconf_1.ilc_disk_file_storage) break;
#endif
           }
#endif
           bol_read_file = TRUE;            /* read the file           */
           goto predif40;                   /* read the file now       */
         }
         adsp_aux_df1->adsc_int_df1 = &adsl_df1_2->dsc_int_df1;
         return;                            /* all done                */
       }
#ifdef B070510
       dss_critsect_aux.m_enter();
       adsl_df1_2->inc_usage_count++;       /* file is in use          */
       dss_critsect_aux.m_leave();
#ifdef TRACEHL_070505
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505E l%05d m_read_diskfile() in-use adsl_df1_2=%p inc_usage_count=%d",
                       __LINE__, adsl_df1_2, adsl_df1_2->inc_usage_count );
#endif
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_ok;  /* file is valid     */
       adsp_aux_df1->adsc_int_df1 = &adsl_df1_2->dsc_int_df1;
     }
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "m_read_diskfile() old file start=%p end=%p",
                 adsl_df1_2->dsc_int_df1.achc_filecont_start,
                 adsl_df1_2->dsc_int_df1.achc_filecont_end );
#endif
     adsp_aux_df1->imc_time_last_mod = adsl_df1_2->dsc_int_df1.imc_time_last_mod;
#ifdef OLD01
#ifndef B091102
     if (adsl_df1_2->iec_difi_def == ied_difi_not_exists) {
     }
#endif
#endif
     return;
   }
   bol_read_file = FALSE;                   /* do not read the file    */
   if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
     bol_read_file = TRUE;                  /* read the file           */
   }

   predif40:                                /* read this file          */
   adsp_aux_df1->iec_dfar_def = ied_dfar_ok;  /* clear return-code     */
#ifndef HL_UNIX
   ill_file_size = 0;
   memset( &dsl_fi1, 0, sizeof(dsl_fi1) );
   dsl_hfi1 = CreateFileW( wcrl_file_name, GENERIC_READ, FILE_SHARE_READ, 0,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_hfi1 == INVALID_HANDLE_VALUE) {  /* error occured           */
#ifdef D_NO_SNMP
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF011W m_read_diskfile %(ux)s open input returned Error %d.",
                     wcrl_file_name, GetLastError() );
#else
     dwl1 = GetLastError();
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF011W m_read_diskfile %(ux)s open input returned Error %d.",
                     wcrl_file_name, dwl1 );
     memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
     m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
     adsp_aux_df1->iec_dfar_def = ied_dfar_os_error;
//   bol_read_file = FALSE;                 /* do not read the file    */
   } else {
#ifdef NEW_VISUAL_C
     bol1 = GetFileSizeEx( dsl_hfi1, (PLARGE_INTEGER) &ill_file_size );
     if (bol1 == FALSE) {
#ifdef D_NO_SNMP
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF012W m_read_diskfile %(ux)s GetFileSizeEx() returned Error %d.",
                       wcrl_file_name, GetLastError() );
#else
       dwl1 = GetLastError();
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF012W m_read_diskfile %(ux)s GetFileSizeEx() returned Error %d.",
                       wcrl_file_name, dwl1 );
       memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
       dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
       m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_get_file_size;
     }
#else
     *((DWORD *) &ill_file_size + 0) = GetFileSize( dsl_hfi1, ((DWORD *) &ill_file_size + 1) );
     while (*((DWORD *) &ill_file_size + 0) == INVALID_FILE_SIZE) {
       dwl1 = GetLastError();
       if (dwl1 == NO_ERROR) break;
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF012W m_read_diskfile %(ux)s GetFileSize() returned Error %d.",
                       wcrl_file_name, dwl1 );
#ifndef D_NO_SNMP
       memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
       dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
       m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_get_file_size;
       break;
     }
#endif
     bol1 = GetFileInformationByHandle( dsl_hfi1, &dsl_fi1 );
     if (bol1 == FALSE) {
#ifdef D_NO_SNMP
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF013W m_read_diskfile %(ux)s GetFileInformationByHandle() returned Error %d.",
                       wcrl_file_name, GetLastError() );
#else
       dwl1 = GetLastError();
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF013W m_read_diskfile %(ux)s GetFileInformationByHandle() returned Error %d.",
                       wcrl_file_name, dwl1 );
       memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
       dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
       m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_get_file_inf;
     }
   }
#else
   memset( &dsl_stat_1, 0, sizeof(struct stat) );
   iml_fd_f1 = open( chrl_file_name, O_RDONLY );
   if (iml_fd_f1 < 0) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF011W m_read_diskfile %(u8)s open input returned Error %d.",
                     chrl_file_name, errno );
     adsp_aux_df1->iec_dfar_def = ied_dfar_os_error;
//   bol_read_file = FALSE;                 /* do not read the file    */
   } else {
     iml_rc1 = fstat( iml_fd_f1, &dsl_stat_1 );
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF013W m_read_diskfile %(u8)s fstat() returned Error %d.",
                       chrl_file_name, errno );
       adsp_aux_df1->iec_dfar_def = ied_dfar_get_file_inf;
     }
   }
#endif

   predif44:                                /* make entry for file     */
   do {
     /* storage for file contents should be aligned                    */
#ifndef HL_UNIX
     iml1 = (iml_len_name + 1) * sizeof(HL_WCHAR);  /* length of file-name */
#else
#ifdef OLD01
     iml1 = (iml_lnam_u16 + 1) * sizeof(HL_WCHAR);  /* length of file-name */
#endif
     iml1 = iml_len_name + 1;               /* length of file-name     */
#endif
     inl2 = 0;                              /* no contents of file     */
     while (bol_read_file) {                /* read the file           */
       if (adsp_aux_df1->iec_dfar_def != ied_dfar_ok) break;
       adsp_aux_df1->iec_dfar_def = ied_dfar_mem_file;
#ifndef HL_UNIX
       if (adsg_loconf_1_inuse->ilc_disk_file_size_max) {  /* length one file */
         if (ill_file_size > adsg_loconf_1_inuse->ilc_disk_file_size_max) break;
       }
       if (adsg_loconf_1_inuse->ilc_disk_file_storage) {  /* maximum storage */
         if ((ill_file_storage + ill_file_size) > adsg_loconf_1_inuse->ilc_disk_file_storage) break;
       }
#else
       if (dss_loconf_1.ilc_disk_file_size_max) {  /* length one file  */
         if (dsl_stat_1.st_size > dss_loconf_1.ilc_disk_file_size_max) break;
       }
       if (dss_loconf_1.ilc_disk_file_storage) {  /* maximum storage   */
         if ((ill_file_storage + dsl_stat_1.st_size) > dss_loconf_1.ilc_disk_file_storage) break;
       }
#endif
//     adsp_aux_df1->iec_dfar_def = ied_dfar_ok;  /* clear return-code */
#ifndef HL_UNIX
       if (ill_file_size) {                 /* something in file       */
         inl2 = ill_file_size;              /* with contents of file   */
         iml1 += sizeof(void *) - 1;
         iml1 &= 0 - sizeof(void *);
       }
#else
       if (dsl_stat_1.st_size) {            /* something in file       */
         inl2 = dsl_stat_1.st_size;         /* with contents of file   */
         iml1 += sizeof(void *) - 1;
         iml1 &= 0 - sizeof(void *);
       }
#endif
       break;
     }
     adsl_df1_5 = (struct dsd_diskfile_1 *) malloc( sizeof(struct dsd_diskfile_1)
                                                    + iml1 + inl2 );
#ifdef TRACEHL_050419
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504192 m_read_diskfile() Thread=%d malloc() adsl_df1_5=%p len=%d+%d+%d",
                     GetCurrentThreadId(), adsl_df1_5, sizeof(struct dsd_diskfile_1), iml1, inl2 );
#endif
     if (adsl_df1_5 == NULL) {
#ifndef HL_UNIX
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF020W m_read_file %(ux)s malloc returned zero",
                       wcrl_file_name );
#else
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF020W m_read_file %(u8)s malloc returned zero",
                       chrl_file_name );
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_mem_entry;
       break;
     }
#ifdef TRACEHL_070505
     dss_critsect_aux.m_enter();
     ims_trace_mem_c++;                     /* count memory            */
     dss_critsect_aux.m_leave();
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505L l%05d m_read_diskfile() malloc %p ims_trace_mem_c=%d",
                     __LINE__, adsl_df1_5, ims_trace_mem_c );
#endif
     memset( adsl_df1_5, 0, sizeof(struct dsd_diskfile_1) );
#ifndef HL_UNIX
     memcpy( adsl_df1_5 + 1, wcrl_file_name, (iml_len_name + 1) * sizeof(WCHAR) );
     adsl_df1_5->dsc_int_df1.awcc_name = (HL_WCHAR *) (adsl_df1_5 + 1);
     adsl_df1_5->dsc_int_df1.inc_len_name = iml_len_name;
#else
#ifdef OLD01
     m_u16z_from_u8l( (HL_WCHAR *) (adsl_df1_5 + 1), iml_lnam_u16 + 1, chrl_file_name, iml_len_name );
     adsl_df1_5->dsc_int_df1.awcc_name = (HL_WCHAR *) (adsl_df1_5 + 1);
     adsl_df1_5->dsc_int_df1.inc_len_name = iml_lnam_u16;
#endif
     memcpy( adsl_df1_5 + 1, chrl_file_name, iml_len_name + 1 );
     adsl_df1_5->dsc_int_df1.achc_name = (char *) (adsl_df1_5 + 1);
     adsl_df1_5->dsc_int_df1.inc_len_name = iml_len_name;
#endif
     adsl_df1_5->iec_difi_def = ied_difi_not_exists;  /* status of entry */
#ifndef B070510
     if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
       adsl_df1_5->inc_usage_count = 1;     /* file is in use          */
#ifdef TRACEHL_070505
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505J l%05d m_read_diskfile() new-in-use adsl_df1_5=%p inc_usage_count=%d",
                       __LINE__, adsl_df1_5, adsl_df1_5->inc_usage_count );
#endif
     }
#endif
#ifndef HL_UNIX
     if (dsl_hfi1 != INVALID_HANDLE_VALUE) {  /* file really opened    */
       adsl_df1_5->iec_difi_def = ied_difi_valid;  /* entry is valid   */
       if (inl2) {                          /* read file afterwards    */
         adsl_df1_5->iec_difi_def = ied_difi_locked;  /* file is locked */
       }
     }
#else
     if (iml_fd_f1 >= 0) {                  /* file really opened      */
       adsl_df1_5->iec_difi_def = ied_difi_valid;  /* entry is valid   */
       if (inl2) {                          /* read file afterwards    */
         adsl_df1_5->iec_difi_def = ied_difi_locked;  /* file is locked */
       }
     }
#endif
/* 19.04.05 KB Itanium ???? */
#ifndef HL_UNIX
     time( (time_t *) &adsl_df1_5->ipc_time_last_checked );  /* get current time */
     memcpy( &adsl_df1_5->dsc_filetime_last_mod, &dsl_fi1.ftLastWriteTime, sizeof(struct _FILETIME) );
     adsl_df1_5->dsc_int_df1.imc_time_last_mod = m_win_epoch_from_filetime( &dsl_fi1.ftLastWriteTime );
     adsl_df1_5->ilc_file_size = ill_file_size;  /* size of this file  */
#else
     time( (time_t *) &adsl_df1_5->ipc_time_last_checked );  /* get current time */
     adsl_df1_5->dsc_int_df1.imc_time_last_mod = dsl_stat_1.st_mtime;
     adsl_df1_5->ilc_file_size = dsl_stat_1.st_size;  /* size of this file */
#endif
#ifdef B070504
     adsl_df1_2 = NULL;                     /* no file found           */
#endif
     adsl_df1_4 = NULL;                     /* set previous element    */
     bol_wait = FALSE;                      /* wait for access to file */
     dss_critsect_aux.m_enter();
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       adsl_df1_3 = adsl_df1_1;             /* save this file pointer  */
       adsl_df1_1 = adsl_df1_1->adsc_next;  /* get next in chain       */
#ifdef OLD01
       if (adsl_df1_3->boc_superseeded == FALSE) {
#ifndef HL_UNIX
         if (!_wcsicoll( (WCHAR *) adsl_df1_3->dsc_int_df1.awcc_name, wcrl_file_name )) {
#ifdef FORKEDIT
         }
#endif
#else
#ifdef OLD01
         bol1 = m_cmp_u16z_u8z( &iml_rc1, adsl_df1_3->dsc_int_df1.awcc_name, chrl_file_name );
         if ((bol1) && (iml_rc1 == 0)) {    /* file-name equal         */
#ifdef FORKEDIT
         }
#endif
#endif
         if (!_wcsicoll( (WCHAR *) adsl_df1_3->dsc_int_df1.awcc_name, wcrl_file_name )) {
#endif
#ifdef TRACEHL_050419
           m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC05041CB m_read_diskfile() adsl_df1_5=%p adsl_df1_3=%p adsl_df1_4=%p adsl_df1_1=%p inl2=%d found file-name equal",
                       adsl_df1_5, adsl_df1_3, adsl_df1_4, adsl_df1_1, inl2 );
#endif
           do {
             if (adsl_df1_3->iec_difi_def == ied_difi_locked) {  /* file is locked */
#ifndef HL_UNIX
#ifdef B060628
#ifdef TRACEHL_050419
               m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504199 m_read_diskfile() Thread=%d adsl_df1_5=%p adsl_df1_3=%p inl2=%d found file locked",
                           GetCurrentThreadId(), adsl_df1_5, adsl_df1_3, inl2 );
#endif
               if (inl2) {                  /* must read contents      */
                 adsl_workth_1 = (class clworkth *) adsl_df1_3->vpc_lock_1;
                 adsl_workth_2 = NULL;
                 adsp_workthr->vpc_lock_1 = NULL;
                 while (adsl_workth_1) {
                   adsl_workth_2 = adsl_workth_1;  /* save last entry  */
                   adsl_workth_1 = (class clworkth *) adsl_workth_1->vpc_lock_1;
                 }
                 if (adsl_workth_2 == NULL) {  /* first element        */
                   adsl_df1_3->vpc_lock_1 = adsp_workthr;
                 } else {                   /* middle in chain         */
                   adsl_workth_2->vpc_lock_1 = adsp_workthr;
                 }
                 bol_wait = TRUE;           /* wait for access to file */
               }
#else
               if (inl2) {                  /* must read contents      */
                 adsl_df1_lock = adsl_df1_3;  /* set file to lock      */
                 bol_wait = TRUE;           /* wait for access to file */
               }
#endif
#endif
               free( adsl_df1_5 );          /* free memory again       */
               adsl_df1_5 = adsl_df1_3;     /* data from this entry    */
               inl2 = 0;                    /* do not read contents    */
               break;
             }
             if (adsl_df1_3->dsc_int_df1.achc_filecont_start) {
               /* file found which is valid, take this one             */
#ifdef TRACEHL_050419
               m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504194 m_read_diskfile() Thread=%d adsl_df1_5=%p adsl_df1_3=%p found old file",
                               GetCurrentThreadId(), adsl_df1_5, adsl_df1_3 );
#endif
               free( adsl_df1_5 );          /* free memory again       */
               adsl_df1_5 = adsl_df1_3;     /* data from this entry    */
               if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
                 adsl_df1_5->inc_usage_count++;  /* file is in use     */
                 inl2 = 0;                  /* do not read contents    */
               }
               break;
             }
#ifdef TRACEHL_050419
             m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC050419B m_read_diskfile() Thread=%d adsl_df1_5=%p adsl_df1_3=%p adsl_df1_4=%p adsl_df1_1=%p found file without content",
                             GetCurrentThreadId(), adsl_df1_5, adsl_df1_3, adsl_df1_4, adsl_df1_1 );
#endif
             /* old entry is without file contents - remove old entry  */
             if (adsl_df1_4 == NULL) {      /* was first element       */
               adss_df1_anchor = adsl_df1_1;  /* set new chain         */
             } else {                       /* not first element       */
               adsl_df1_4->adsc_next = adsl_df1_1;  /* set new element in chain */
             }
             free( adsl_df1_3 );            /* free memory             */
             adsl_df1_3 = NULL;             /* no more old entry       */
           } while (FALSE);
           if (adsl_df1_3) break;           /* stop searching          */
         }
       }
       if (adsl_df1_3) {                    /* element still valid     */
         adsl_df1_4 = adsl_df1_3;           /* save previous element   */
       }
#endif
       if (adsl_df1_3 == &dsl_df1_this) {   /* is this temporary entry ? */
         if (adsl_df1_4 == NULL) {          /* was first element       */
           adss_df1_anchor = adsl_df1_1;    /* set new chain           */
         } else {                           /* not first element       */
           adsl_df1_4->adsc_next = adsl_df1_1;  /* set new element in chain */
         }
         /* copy the locks                                             */
         memcpy( &adsl_df1_5->dsc_lock_1, &dsl_df1_this.dsc_lock_1, sizeof(struct dsd_hco_lock_1) );
         adsl_df1_3 = NULL;                 /* no previous entry       */
       } else if (adsl_df1_3 == adsl_df1_2) {  /* entry to be removed  */
#ifdef TRACEHL_070505
#ifndef HL_UNIX
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505B l%05d m_read_diskfile() file-to-delete-found adsl_df1_3=%p boc_superseeded=%d",
                         __LINE__, adsl_df1_3, adsl_df1_3->boc_superseeded );
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505B l%05d m_read_diskfile() awcc_name=%(ux)s",
                         __LINE__, adsl_df1_3->dsc_int_df1.awcc_name );
#endif
#endif
         if (adsl_df1_4 == NULL) {          /* was first element       */
           adss_df1_anchor = adsl_df1_1;    /* set new chain           */
         } else {                           /* not first element       */
           adsl_df1_4->adsc_next = adsl_df1_1;  /* set new element in chain */
         }
         /* copy the locks                                             */
         memcpy( &adsl_df1_5->dsc_lock_1, &adsl_df1_2->dsc_lock_1, sizeof(struct dsd_hco_lock_1) );
         adsl_df1_5->inc_usage_count = adsl_df1_2->inc_usage_count;  /* file is in use */
#ifdef XYZ1
#ifndef B070510
         if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
           adsl_df1_5->inc_usage_count++;   /* file is in use          */
#ifdef TRACEHL_070505
           m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505K l%05d m_read_diskfile() copy-in-use adsl_df1_5=%p inc_usage_count=%d",
                           __LINE__, adsl_df1_5, adsl_df1_5->inc_usage_count );
#endif
         }
#endif
#endif
         free( adsl_df1_2 );                /* free old entry          */
#ifdef TRACEHL_070505
         ims_trace_mem_c--;                 /* count memory            */
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505N l%05d m_read_diskfile() free %p ims_trace_mem_c=%d",
                         __LINE__, adsl_df1_2, ims_trace_mem_c );
#endif
         adsl_df1_2 = NULL;                 /* no more old entry       */
         adsl_df1_3 = NULL;                 /* no previous entry       */
       }
       if (adsl_df1_3) {                    /* element still valid     */
         adsl_df1_4 = adsl_df1_3;           /* save previous element   */
       }
     }
#ifndef B070504
     adsl_df1_5->adsc_next = adss_df1_anchor;  /* get anchor of files  */
     adss_df1_anchor = adsl_df1_5;          /* set new anchor of files */
#endif
#ifdef OLD01
     if (adsl_df1_1 == NULL) {              /* set new entry           */
       adsl_df1_5->adsc_next = adss_df1_anchor;  /* get anchor of files */
       adss_df1_anchor = adsl_df1_5;        /* set new anchor of files */
     }
#endif
     dss_critsect_aux.m_leave();
     if (inl2 == 0) break;                  /* do not read contents    */
     /* buffer for read                                                */
     achl_buffer = (char *) (adsl_df1_5 + 1) + iml1;
#ifdef TRACEHL_050419
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504193 m_read_diskfile() Thread=%d adsl_df1_5=%p achl_buffer=%p len=%lld",
                     GetCurrentThreadId(), adsl_df1_5, achl_buffer, ill_file_size );
#endif
     ill_pos_file = 0;                      /* position in file        */
     iml_read = 0X01000000;                 /* maximum length read     */
#ifndef HL_UNIX
     while (ill_pos_file < ill_file_size) {
       if (iml_read > (ill_file_size - ill_pos_file)) {
         iml_read = (ill_file_size - ill_pos_file);
       }
       bol1 = ReadFile( dsl_hfi1, achl_buffer, iml_read, &uml_returned_read, 0 );
       if (bol1 == FALSE) {                 /* error occured           */
#ifdef D_NO_SNMP
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF021W m_read_file %(ux)s ReadFile() returned Error %d",
                         wcrl_file_name, GetLastError() );
#else
         dwl1 = GetLastError();
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF021W m_read_file %(ux)s ReadFile() returned Error %d",
                         wcrl_file_name, dwl1 );
         memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
         dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
         dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
         m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
         break;
       }
       achl_buffer += uml_returned_read;
       ill_pos_file += uml_returned_read;
     }
#else
     while (ill_pos_file < dsl_stat_1.st_size) {
       if (iml_read > (dsl_stat_1.st_size - ill_pos_file)) {
         iml_read = (dsl_stat_1.st_size - ill_pos_file);
       }
       iml_rc1 = read( iml_fd_f1, achl_buffer, iml_read );
       if (iml_rc1 < 0) {                   /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF021W m_read_file %(u8)s read() returned Error %d",
                         chrl_file_name, errno );
         break;
       }
       achl_buffer += iml_rc1;
       ill_pos_file += iml_rc1;
     }
#endif
#ifndef HL_UNIX
     if (ill_pos_file < ill_file_size) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF022W m_read_file %(ux)s ReadFile() could not read entire file",
                       wcrl_file_name );
#ifdef FORKEDIT
     }
#endif
#else
     if (ill_pos_file < dsl_stat_1.st_size) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF022W m_read_file %(u8)s read() could not read entire file",
                       chrl_file_name );
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_file_read;
     } else {
#define COMP_ERR_050419
#ifdef COMP_ERR_050419
       adsl_df1_5->dsc_int_df1.achc_filecont_start = (char *) (adsl_df1_5 + 1) + iml1;
#ifndef HL_UNIX
       adsl_df1_5->dsc_int_df1.achc_filecont_end = (char *) (adsl_df1_5 + 1) + iml1 + (int) ill_file_size;
#else
       adsl_df1_5->dsc_int_df1.achc_filecont_end = (char *) (adsl_df1_5 + 1) + iml1 + dsl_stat_1.st_size;
#endif
#else
       adsl_df1_5->dsc_int_df1.achc_filecont_start = (char *) (adsl_df1_5 + 1) + iml1;
       adsl_df1_5->dsc_int_df1.achc_filecont_end = (char *) (adsl_df1_5 + 1) + iml1 + ill_file_size;
       iml_read = iml1;
#ifndef HL_UNIX
       iml_read += ill_file_size;
#else
       iml_read += dsl_stat_1.st_size;
#endif
       adsl_df1_5->dsc_int_df1.achc_filecont_end = (char *) (adsl_df1_5 + 1) + iml_read;
#endif
       adsp_aux_df1->iec_dfar_def = ied_dfar_ok;  /* clear return-code */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_read_diskfile() file new start=%p end=%p",
                   adsl_df1_5->dsc_int_df1.achc_filecont_start,
                   adsl_df1_5->dsc_int_df1.achc_filecont_end );
#endif
#ifdef TRACEHL_050419
#ifndef HL_UNIX
#ifdef OLD01
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504197 m_read_diskfile() Thread=%d set file size adsl_df1_5=%p iml1=%d ill_file_size=%I64d len=%d start=%p end=%p",
                   GetCurrentThreadId(),
                   adsl_df1_5, iml1, ill_file_size,
                   adsl_df1_5->dsc_int_df1.achc_filecont_end
                     - adsl_df1_5->dsc_int_df1.achc_filecont_start,
                   adsl_df1_5->dsc_int_df1.achc_filecont_start,
                   adsl_df1_5->dsc_int_df1.achc_filecont_end );
#endif
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504197 m_read_diskfile() Thread=%d set file size adsl_df1_5=%p iml1=%d ill_file_size=%d len=%d start=%p end=%p",
                   GetCurrentThreadId(),
                   adsl_df1_5, iml1, (int) ill_file_size,
                   (int) (adsl_df1_5->dsc_int_df1.achc_filecont_end
                            - adsl_df1_5->dsc_int_df1.achc_filecont_start),
                   adsl_df1_5->dsc_int_df1.achc_filecont_start,
                   adsl_df1_5->dsc_int_df1.achc_filecont_end );
       if (adsl_df1_5->dsc_int_df1.achc_filecont_start) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504198 m_read_diskfile() Thread=%d achc_filecont_start=%p *achc_filecont_start=%02X",
                         GetCurrentThreadId(),
                         adsl_df1_5->dsc_int_df1.achc_filecont_start,
                         *((unsigned char *) adsl_df1_5->dsc_int_df1.achc_filecont_start) );
       }
#endif
#endif
#ifdef B070510
       if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
         dss_critsect_aux.m_enter();
         adsl_df1_5->inc_usage_count++;     /* file is in use          */
         dss_critsect_aux.m_leave();
#ifdef TRACEHL_070505
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505G l%05d m_read_diskfile() in-use adsl_df1_5=%p inc_usage_count=%d",
                         __LINE__, adsl_df1_5, adsl_df1_5->inc_usage_count );
#endif
       }
#endif
#ifndef HL_UNIX
       time( (time_t *) &adsl_df1_5->ipc_time_last_acc );  /* get current time */
#endif
     }
     /* file is no more locked                                         */
#ifdef B060709
     dss_critsect_aux.m_enter();
     adsl_df1_5->iec_difi_def = ied_difi_valid;  /* entry is valid     */
#ifdef B060709
#ifndef HL_UNIX
     adsl_workth_1 = (class clworkth *) adsl_df1_5->vpc_lock_1;
#endif
#endif
     dss_critsect_aux.m_leave();
#endif
     adsl_df1_5->iec_difi_def = ied_difi_valid;  /* entry is valid     */
#ifdef OLD01
     m_hco_wothr_unlock( adsp_workthr, &adsl_df1_5->dsc_lock_1 );
#endif
     adsl_workthr_w1 = adsl_df1_5->dsc_lock_1.adsc_ch_lock;  /* get chain of locks */
     if (adsl_workthr_w1) {                 /* activate thread waiting */
       adsl_df1_5->dsc_lock_1.adsc_ch_lock = NULL;  /* no more chain of locks */
       m_hco_wothr_post( adsp_workthr, adsl_workthr_w1 );
     }
#ifdef TRACEHL_050419
     m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC050419B m_read_diskfile() Thread=%d after unlock adsl_df1_5=%p adsl_workth_1=%p",
                     GetCurrentThreadId(), adsl_df1_5, adsl_workthr_w1 );
#endif
#ifndef HL_UNIX
#ifdef B060628
     if (adsl_workth_1) {                   /* activate thread waiting */
#ifdef CHECK_THR_1
       if (adsl_workth_1->ad_clconn1 == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "--- m_read_diskfile() file is no more locked call m_proc_data( NULL ) - workthr=%p",
                     adsl_workth_1 );
       }
#endif
       bol1 = SetEvent( adsl_workth_1->hevework );
       if (bol1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPRDF030W m_read_diskfile %(ux)s SetEvent WORK other 1 Error %d",
                     wcrl_file_name, GetLastError() );
       }
     }
#endif
#endif
   } while (FALSE);
   if (imp_func == DEF_AUX_DISKFILE_ACCESS) {
     if (adsl_df1_5->dsc_int_df1.achc_filecont_start) {
       adsp_aux_df1->adsc_int_df1 = &adsl_df1_5->dsc_int_df1;
     }
#ifndef B070510
     if (   (adsp_aux_df1->adsc_int_df1 == NULL)
         || (adsp_aux_df1->iec_dfar_def != ied_dfar_ok)) {
       dss_critsect_aux.m_enter();
       adsl_df1_5->inc_usage_count--;       /* file is not in use      */
       dss_critsect_aux.m_leave();
#ifdef TRACEHL_070505
       m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC070505H l%05d m_read_diskfile() not-in-use adsl_df1_5=%p inc_usage_count=%d",
                       __LINE__, adsl_df1_5, adsl_df1_5->inc_usage_count );
#endif
     }
#endif
   }
   if (adsl_df1_5->iec_difi_def != ied_difi_not_exists) {  /* status of entry */
     adsp_aux_df1->imc_time_last_mod = adsl_df1_5->dsc_int_df1.imc_time_last_mod;
   }
#ifndef HL_UNIX
   if (dsl_hfi1 != INVALID_HANDLE_VALUE) {
     bol1 = CloseHandle( dsl_hfi1 );
     if (bol1 == FALSE) {
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ux)s CloseHandle() returned Error %d.",
                       wcrl_file_name, GetLastError() );
     }
   }
#else
   if (iml_fd_f1 >= 0) {                    /* file really opened      */
     iml_rc1 = close( iml_fd_f1 );          /* close file              */
     if (iml_rc1) {                         /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(u8)s close() returned Error %d.",
                       chrl_file_name, errno );
     }
   }
#endif
#ifdef B150120
   if (bol_wait == FALSE) return;           /* nothing more to do      */
#endif
   if (bol_wait) {                          /* wait for access         */
     goto predif60;                         /* wait for access to file */
   }
   /* nothing more to do                                               */
   if ((imp_trace_level & HL_WT_SESS_AUX) == 0) return;  /* do not generate WSP trace record */
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXDF01", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = imp_sno;     /* WSP session number      */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
   iml1 = m_hlsnprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                        LEN_TCP_RECV - sizeof(struct dsd_wsp_trace_1) - sizeof(struct dsd_wsp_trace_record),
                        ied_chs_utf_8,
                        "read disk-file function %d file-name \"%(ucs)s\"",
                        imp_func, &dsl_ucs_l );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
   ADSL_WTR_G1->imc_length = iml1;          /* length of text / data   */
// ADSL_WTR_G1->adsc_next = NULL;           /* end of chain            */
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return;                                  /* all done                */

   predif60:                                /* wait for access to file */
#ifdef OLD01
   m_hco_wothr_lock( adsp_workthr, &adsl_df1_lock->dsc_lock_1 );
#endif
   m_hco_wothr_wait( adsp_workthr );        /* wait for access to file */
#ifndef HL_UNIX
#ifdef B060628
   dwl1 = WaitForSingleObject( adsp_workthr->hevework, INFINITE );
   if (dwl1 != WAIT_OBJECT_0) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPRDF050W m_read_diskfile %(ux)s WaitForSingleObject() Returned %d Error %d",
                     wcrl_file_name, dwl1, GetLastError() );
   }
#ifdef B050427
   adsl_workth_1 = (class clworkth *) adsl_df1_5->vpc_lock_1;
#else
   adsl_workth_1 = (class clworkth *) adsp_workthr->vpc_lock_1;
#endif
   if (adsl_workth_1) {                     /* activate thread waiting */
#ifdef CHECK_THR_1
     if (adsl_workth_1->ad_clconn1 == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "--- m_read_diskfile() predif60 call m_proc_data( NULL ) - workthr=%p",
                   adsl_workth_1 );
     }
#endif
     bol1 = SetEvent( adsl_workth_1->hevework );
     if (bol1 == FALSE) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF051 m_read_diskfile %(ux)s SetEvent WORK other 2 Error %d",
                       wcrl_file_name, GetLastError() );
     }
   }
#endif
#endif
   goto predif20;                           /* search the file         */
} /* end m_read_diskfile()                                             */
#undef DSD_WORKTHR

/** subroutine to add an entry to the auxiliary timer chain            */
#ifdef B130314
//static void m_aux_timer_new( DSD_CONN_G *adsp_conn1, enum ied_src_func iep_src_func,
//                             void * ap_sdh, int inp_intv_msec )
#endif
static void m_aux_timer_new( DSD_CONN_G *adsp_conn1, struct dsd_cid *adsp_cid,
                             int inp_intv_msec, enum ied_auxt_usage iep_auxtu ) {
#ifndef B150330
   int        iml1;                         /* working variable        */
#endif
   BOOL       bol_set_timer;                /* do set timer            */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */
#ifdef HL_UNIX
   int        iml_rc;                       /* return-code API         */
   void       *dsrl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe   */
#endif
#ifndef B150330
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif

   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(struct dsd_aux_timer) );
#ifndef B150330
   if (adsp_conn1->imc_trace_level & HL_WT_SESS_AUX) {  /* do generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXTIMS", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = m_hlsnprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                          LEN_TCP_RECV - sizeof(struct dsd_wsp_trace_1) - sizeof(struct dsd_wsp_trace_record),
                          ied_chs_utf_8,
                          "m_aux_timer_new() sets timer auxf_1 %p CID iec_src_func=%d ac_cid_addr=%p.",
                          adsl_auxf_1_w1, adsp_cid->iec_src_func, adsp_cid->ac_cid_addr );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
//   ADSL_WTR_G1->adsc_next = NULL;         /* end of chain            */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   adsl_auxf_1_w1->iec_auxf_def = ied_auxf_timer;  /* entry type timer */
   adsl_auxf_1_w1->dsc_cid = *adsp_cid;     /* set component           */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
#ifdef B130314
   ADSL_AUX_T->iec_src_func = iep_src_func;  /* type auxiliary timer */
   ADSL_AUX_T->ilc_endtime = m_get_epoch_ms() + inp_intv_msec;  /* end-time in milli-seconds */
   ADSL_AUX_T->ac_sdh = ap_sdh;             /* address of SDH          */
#endif
   memcpy( &ADSL_AUX_T->dsc_cid, adsp_cid, sizeof(struct dsd_cid) );  /* set component */
   ADSL_AUX_T->ilc_endtime = m_get_epoch_ms() + inp_intv_msec;  /* end-time in milli-seconds */
   ADSL_AUX_T->iec_auxtu = iep_auxtu;       /* usage of the auxiliary timer */
   ADSL_AUX_T->boc_expired = FALSE;         /* timer has not yet expired */
   adsl_auxf_1_w1->adsc_next = adsp_conn1->adsc_auxf_1;  /* anchor of chain */
   adsp_conn1->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new entry         */
   if (adsp_conn1->adsc_aux_timer_ch == NULL) {  /* no element in chain yet */
     ADSL_AUX_T->adsc_auxf_next = NULL;     /* clear next in chain     */
     adsp_conn1->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is only element */
     goto pauxt_20;                         /* check if activate timer */
   }
   if (((struct dsd_aux_timer *) (adsp_conn1->adsc_aux_timer_ch + 1))->ilc_endtime
         > ADSL_AUX_T->ilc_endtime) {
     ADSL_AUX_T->adsc_auxf_next = adsp_conn1->adsc_aux_timer_ch;  /* get old chain */
     adsp_conn1->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is first element */
     goto pauxt_20;                         /* check if activate timer */
   }
   /* get correct position in chain                                    */
   adsl_auxf_1_w2 = adsp_conn1->adsc_aux_timer_ch;
   bol_set_timer = TRUE;                    /* do set timer            */
   while (TRUE) {
     adsl_auxf_1_w3 = adsl_auxf_1_w2;
     adsl_auxf_1_w2 = ((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->adsc_auxf_next;
     if (adsl_auxf_1_w2 == NULL) break;
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->ilc_endtime
           < ADSL_AUX_T->ilc_endtime) {
       break;
     }
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->boc_expired == FALSE) {  /* timer has not yet expired */
       bol_set_timer = FALSE;               /* timer already set to this value */
     }
   }
   ADSL_AUX_T->adsc_auxf_next = adsl_auxf_1_w2;
   ((struct dsd_aux_timer *) (adsl_auxf_1_w3 + 1))->adsc_auxf_next
     = adsl_auxf_1_w1;
   if (bol_set_timer == FALSE) return;      /* all done                */
   goto pauxt_40;                           /* set timer now           */

   pauxt_20:                                /* check if activate timer */
   if (   (adsp_conn1->ilc_timeout)
       && (adsp_conn1->ilc_timeout <= ADSL_AUX_T->ilc_endtime)) {
     return;                                /* is normal timeout       */
   }

   pauxt_40:                                /* set timer now           */
   if (adsp_conn1->dsc_timer.vpc_chain_2) {  /* timer already set      */
     m_time_rel( &adsp_conn1->dsc_timer );  /* release timer           */
   }
   adsp_conn1->dsc_timer.ilcendtime = ADSL_AUX_T->ilc_endtime;  /* set end-time */
   m_time_set( &adsp_conn1->dsc_timer, TRUE );  /* set new timer       */
   return;
#undef ADSL_AUX_T
} /* end m_aux_timer_new()                                             */

/** subroutine to delete an entry to the auxiliary timer chain         */
#ifdef B130314
//static void m_aux_timer_del( DSD_CONN_G *adsp_conn1, enum ied_src_func iep_src_func,
//                             void * ap_sdh )
#endif
static void m_aux_timer_del( DSD_CONN_G *adsp_conn1, struct dsd_cid *adsp_cid ) {
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */

   /* get correct position in chain of auxiliary timers                */
   adsl_auxf_1_w1 = adsp_conn1->adsc_aux_timer_ch;
   adsl_auxf_1_w2 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
#ifdef B130314
     if (   (ADSL_AUX_T->iec_src_func == iep_src_func)  /* type auxiliary timer */
         && (ADSL_AUX_T->ac_sdh == ap_sdh)) {  /* address of SDH       */
       break;                               /* entry found             */
     }
#endif
     if (!memcmp( &ADSL_AUX_T->dsc_cid, adsp_cid, sizeof(struct dsd_cid) )) {  /* check component */
       break;                               /* entry found             */
     }
#undef ADSL_AUX_T
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save previous entry     */
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (adsl_auxf_1_w1 == NULL) return;      /* entry not found         */
// to-do 20.01.15 KB - enter critical section
#ifndef B150121
#ifndef HL_UNIX
   EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
#endif
   if (adsl_auxf_1_w2 == NULL) {            /* was first entry         */
     adsp_conn1->adsc_aux_timer_ch = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   } else {                                 /* middle in chain         */
     ((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->adsc_auxf_next
       = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
#ifndef B150121
#ifndef HL_UNIX
   LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
#endif
   /* get correct position in chain of auxiliary fields                */
   adsl_auxf_1_w2 = adsp_conn1->adsc_auxf_1;  /* chain auxiliary ext fi */
   adsl_auxf_1_w3 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w2) {                 /* loop over all timer entries */
     if (adsl_auxf_1_w2 == adsl_auxf_1_w1) break;  /* entry found      */
     adsl_auxf_1_w3 = adsl_auxf_1_w2;       /* save previous entry     */
     adsl_auxf_1_w2 = adsl_auxf_1_w2->adsc_next;
   }
   if (adsl_auxf_1_w2 == NULL) return;      /* entry not found         */
   if (adsl_auxf_1_w3 == NULL) {            /* was first entry         */
     adsp_conn1->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
   } else {                                 /* middle in chain         */
     adsl_auxf_1_w3->adsc_next = adsl_auxf_1_w1->adsc_next;
   }
   free( adsl_auxf_1_w1 );                  /* free memory timer entry */
} /* end m_aux_timer_del()                                             */

/** subroutine to check an entry of the auxiliary timer chain          */
#ifdef B130314
//static BOOL m_aux_timer_check( DSD_CONN_G *adsp_conn1, enum ied_src_func iep_src_func,
//                               void * ap_sdh )
#endif
/**
   called in critical section of conn1
*/
static BOOL m_aux_timer_check( DSD_CONN_G *adsp_conn1, struct dsd_cid *adsp_cid ) {
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */

   /* get correct position in chain of auxiliary timers                */
   adsl_auxf_1_w1 = adsp_conn1->adsc_aux_timer_ch;
   adsl_auxf_1_w2 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
#ifdef B130314
     if (   (ADSL_AUX_T->iec_src_func == iep_src_func)  /* type auxiliary timer */
         && (ADSL_AUX_T->ac_sdh == ap_sdh)) {  /* address of SDH       */
       break;                               /* entry found             */
     }
#endif
     if (!memcmp( &ADSL_AUX_T->dsc_cid, adsp_cid, sizeof(struct dsd_cid) )) {  /* check component */
       break;                               /* entry found             */
     }
#undef ADSL_AUX_T
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save previous entry     */
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (adsl_auxf_1_w1 == NULL) return FALSE;  /* entry not found       */
#define ADSL_AUX_TIMER_G ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
   if (ADSL_AUX_TIMER_G->boc_expired == FALSE) return FALSE;  /* timer has not yet expired */
#undef ADSL_AUX_TIMER_G
// to-do 20.01.15 KB - enter critical section
#ifdef B150214
#ifndef B150121
#ifndef HL_UNIX
   EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
#endif
#endif
   if (adsl_auxf_1_w2 == NULL) {            /* was first entry         */
     adsp_conn1->adsc_aux_timer_ch = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   } else {                                 /* middle in chain         */
     ((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->adsc_auxf_next
       = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
#ifdef B150214
#ifndef B150121
#ifndef HL_UNIX
   LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
#endif
#endif
   /* get correct position in chain of auxiliary fields                */
   adsl_auxf_1_w2 = adsp_conn1->adsc_auxf_1;  /* chain auxiliary ext fi */
   adsl_auxf_1_w3 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w2) {                 /* loop over all timer entries */
     if (adsl_auxf_1_w2 == adsl_auxf_1_w1) break;  /* entry found      */
     adsl_auxf_1_w3 = adsl_auxf_1_w2;       /* save previous entry     */
     adsl_auxf_1_w2 = adsl_auxf_1_w2->adsc_next;
   }
   if (adsl_auxf_1_w2 == NULL) return FALSE;  /* entry not found       */
   if (adsl_auxf_1_w3 == NULL) {            /* was first entry         */
     adsp_conn1->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
   } else {                                 /* middle in chain         */
     adsl_auxf_1_w3->adsc_next = adsl_auxf_1_w1->adsc_next;
   }
   free( adsl_auxf_1_w1 );                  /* free memory timer entry */
   return TRUE;                             /* timer has expired       */
} /* end m_aux_timer_check()                                           */

/**
  subroutine to return Signals set for this function
*/
static int m_ret_signal( struct dsd_aux_cf1 *adsp_aux_cf1 ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   int        iml_signal;                   /* return Signal           */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w4;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w5;       /* auxiliary extension fi  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifndef B150330
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif

#ifdef TRACEHL_090912_01
   if (bog_trace_v1) {                      /* variable for debugging  */
     m_hlnew_printf( HLOG_XYZ1, "HWSP-l%05d-T m_ret_signal() bog_trace_v1 set",
                     __LINE__ );
   }
#endif
#define ADSL_CONN1_G (adsp_aux_cf1->adsc_conn)  /* pointer on connection */
#ifndef B130314
   ADSL_CONN1_G->boc_signal_set = FALSE;    /* signal for component set */
#endif
   iml_signal = 0;                          /* return Signal           */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* chain auxiliary ext fi */
   adsl_auxf_1_w2 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     switch (adsl_auxf_1_w1->iec_auxf_def) {  /* type of entry         */
       case ied_auxf_timer:                 /* timer                   */
#define ADSL_AUX_TIMER_G ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
         if (ADSL_AUX_TIMER_G->boc_expired == FALSE) break;  /* timer has not yet expired */
#ifdef B130314
         if (ADSL_AUX_TIMER_G->iec_src_func != adsp_aux_cf1->iec_src_func) break;  /* check type auxiliary timer */
         if (ADSL_AUX_TIMER_G->ac_sdh != adsp_aux_cf1->ac_sdh) break;  /* not current Server-Data-Hook */
#endif
#ifndef B130314
         ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
         if (memcmp( &ADSL_AUX_TIMER_G->dsc_cid, &adsp_aux_cf1->dsc_cid, sizeof(struct dsd_cid) )) break;  /* check component */
#endif
#undef ADSL_AUX_TIMER_G
         iml_signal |= HL_AUX_SIGNAL_TIMER;  /* set signal timer       */
         /* remove this entry from the chain                           */
         adsl_auxf_1_w3 = adsl_auxf_1_w1;   /* save this entry         */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
         if (adsl_auxf_1_w2 == NULL) {      /* at anchor of chain      */
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* remove from chain */
         } else {                           /* middle in chain         */
           adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1;  /* remove from chain */
         }
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
         /* remove also from timer chain                               */
         adsl_auxf_1_w4 = ADSL_CONN1_G->adsc_aux_timer_ch;
         adsl_auxf_1_w5 = NULL;             /* clear previous entry    */
         while (adsl_auxf_1_w4) {           /* loop over all timer entries */
           if (adsl_auxf_1_w4 == adsl_auxf_1_w3) {  /* entry found     */
// to-do 20.01.15 KB - enter critical section
#ifndef B150121
#ifndef HL_UNIX
             EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
             ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section */
#endif
#endif
             if (adsl_auxf_1_w5 == NULL) {  /* was first entry         */
               ADSL_CONN1_G->adsc_aux_timer_ch
                 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
             } else {                       /* middle in chain         */
               ((struct dsd_aux_timer *) (adsl_auxf_1_w5 + 1))->adsc_auxf_next
                 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
             }
#ifndef B150121
#ifndef HL_UNIX
             LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
             ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section */
#endif
#endif
             break;                         /* entry found             */
           }
           adsl_auxf_1_w5 = adsl_auxf_1_w4;  /* save previous entry    */
           adsl_auxf_1_w4 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
         }
         /* if adsl_auxf_1_w4 NULL, that timer not found, error        */
         free( adsl_auxf_1_w3 );            /* free storage of this element */
         continue;                          /* next path thru the loop */
       case ied_auxf_q_gather:              /* query gather            */
#ifdef B130314
         if (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->iec_src_func
               != adsp_aux_cf1->iec_src_func) break;  /* not this function */
         if (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->ac_sdh
               != adsp_aux_cf1->ac_sdh) break;  /* not current Server-Data-Hook */
#endif
#define ADSL_GAI1_COMP (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->adsc_gai1_q)
         iml1 = 0;                          /* first funktion          */
         bol1 = FALSE;                      /* gather not active       */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
         while (TRUE) {                     /* loop over all functions */
           while (adsl_sdhc1_w1) {          /* loop over all buffers   */
             adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain input data */
             while (adsl_gai1_w1) {         /* loop over output        */
               if (adsl_gai1_w1 == ADSL_GAI1_COMP) {  /* gather found  */
                 if (adsl_gai1_w1->achc_ginp_end > adsl_gai1_w1->achc_ginp_cur) {
                   bol1 = TRUE;             /* gather still active     */
                 }
                 break;
               }
               adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
             }
             if (adsl_gai1_w1) break;       /* gather found            */
             adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           }
           if (adsl_sdhc1_w1) break;        /* gather found            */
           if (iml1 == 2) break;            /* all functions done      */
           if (iml1 == 0) {                 /* do send to client now   */
#ifndef HL_UNIX
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send;
#else
#ifdef B120502
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_cl.adsc_sdhc1;  /* chain to send to client */
#else
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* get chain to send to client */
#endif
#endif
           } else {                         /* do send to server now   */
#ifdef B120502
#ifndef HL_UNIX
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;
#else
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* chain to send to server */
#endif
#else
             switch (ADSL_CONN1_G->iec_servcotype) {
               case ied_servcotype_normal_tcp:  /* normal TCP          */
#ifndef HL_UNIX
                 adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;  /* get start of chain */
#else
                 adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send;  /* get chain to send to server */
#endif
                 break;
#ifdef D_INCL_HTUN
               case ied_servcotype_htun:    /* HOB-TUN                 */
                 adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get start of chain */
                 break;
#endif
               case ied_servcotype_l2tp:    /* L2TP                    */
                 adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_l2tp_sch;  /* send buffers */
                 break;
             }
#endif
           }
           iml1++;                          /* next function           */
         }
#undef ADSL_GAI1_COMP
         if (bol1 == FALSE) break;          /* gather not active       */
#ifndef B130314
         ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
         if (memcmp( &((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->dsc_cid,
                     &adsp_aux_cf1->dsc_cid,
                     sizeof(struct dsd_cid) )) {
           break;
         }
#endif
         iml_signal |= ((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->imc_signal;
         /* remove this entry from the chain                           */
         adsl_auxf_1_w3 = adsl_auxf_1_w1;   /* save this entry         */
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
         if (adsl_auxf_1_w2 == NULL) {      /* at anchor of chain      */
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* remove from chain */
         } else {                           /* middle in chain         */
           adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1;  /* remove from chain */
         }
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
         free( adsl_auxf_1_w3 );            /* free storage of this element */
         continue;                          /* next path thru the loop */
       case ied_auxf_service_query_1:       /* service query 1         */
       case ied_auxf_sip:                   /* SIP request             */
       case ied_auxf_udp:                   /* UDP request             */
       case ied_auxf_admin:                 /* admin command           */
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
       case ied_auxf_pipe_conn:             /* aux-pipe established connection */
#ifndef B130314
         if (((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal == 0) break;
         ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
         if (memcmp( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid,
                     &adsp_aux_cf1->dsc_cid,
                     sizeof(struct dsd_cid) )) {
           break;
         }
#endif
         iml_signal |= ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal;
         ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal = 0;  /* interrupt has been passed */
         break;
       case ied_auxf_util_thread:           /* utility thread          */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_w1 + 1))
         if (ADSL_UTC_G->boc_thread_ended == FALSE) break;  /* thread has not yet ended */
         ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
         if (memcmp( &ADSL_UTC_G->dsc_cid,
                     &adsp_aux_cf1->dsc_cid,
                     sizeof(struct dsd_cid) )) {
           break;
         }
         iml_signal |= ADSL_UTC_G->imc_signal_parent;  /* signal for parent */
#undef ADSL_UTC_G
         break;
     }
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save previous entry     */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
   }
   while (   (ADSL_CONN1_G->adsc_int_webso_conn_1)  /* connect for WebSocket applications - internal */
          && (ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify)) {  /* notify SDH */
#ifndef B130314
     if (memcmp( &ADSL_CONN1_G->adsc_int_webso_conn_1->dsc_cid,
                 &adsp_aux_cf1->dsc_cid,
                 sizeof(struct dsd_cid) )) {
       ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
       break;
     }
#endif
     iml_signal |= ADSL_CONN1_G->adsc_int_webso_conn_1->imc_signal;
#ifndef B130314
     ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
     break;
   }
#ifndef B150330
   if (   (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX)  /* do generate WSP trace record */
       && (iml_signal != 0)) {
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXSIG1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = m_hlsnprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                          LEN_TCP_RECV - sizeof(struct dsd_wsp_trace_1) - sizeof(struct dsd_wsp_trace_record),
                          ied_chs_utf_8,
                          "m_ret_signal() returns signal 0X%08X CID iec_src_func=%d ac_cid_addr=%p.",
                          iml_signal, adsp_aux_cf1->dsc_cid.iec_src_func, adsp_aux_cf1->dsc_cid.ac_cid_addr );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
//   ADSL_WTR_G1->adsc_next = NULL;         /* end of chain            */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifdef TRACEHL_090912_01
   if (iml_signal == 0) return 0;
   m_hlnew_printf( HLOG_XYZ1, "HWSP-l%05d-T m_ret_signal() returns %08X.",
                   __LINE__, iml_signal );
#endif
   return iml_signal;                       /* return Signal           */
#undef ADSL_CONN1_G
} /* end m_ret_signal()                                                */

/**
  subroutine to check if Signals are set for any Server-Data-Hook
*/
//static void * m_check_sdh_signal( struct dsd_aux_cf1 *adsp_aux_cf1 )
static struct dsd_cid * m_check_sdh_signal( struct dsd_aux_cf1 *adsp_aux_cf1 ) {
   int        iml1;                         /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifndef B150330
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif

#define ADSL_CONN1_G (adsp_aux_cf1->adsc_conn)  /* pointer on connection */
#ifdef XYZ1
#ifndef B130314
   ADSL_CONN1_G->boc_signal_set = FALSE;    /* signal for component set */
#endif
#endif
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* chain auxiliary ext fi */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     switch (adsl_auxf_1_w1->iec_auxf_def) {  /* type of entry         */
       case ied_auxf_timer:                 /* timer                   */
#define ADSL_AUX_TIMER_G ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
         if (ADSL_AUX_TIMER_G->boc_expired == FALSE) break;  /* timer has not yet expired */
#ifdef B130314
         if (ADSL_AUX_TIMER_G->iec_src_func != ied_src_fu_sdh) break;  /* check type auxiliary timer */
         return (void *) ADSL_AUX_TIMER_G->ac_sdh;  /* return position Server-Data-Hook */
#endif
#ifndef B150330
         if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {  /* do generate WSP trace record */
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXTIMR", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
           iml1 = m_hlsnprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                                LEN_TCP_RECV - sizeof(struct dsd_wsp_trace_1) - sizeof(struct dsd_wsp_trace_record),
                                ied_chs_utf_8,
                                "m_check_sdh_signal() returns timer set auxf_1 %p CID iec_src_func=%d ac_cid_addr=%p.",
                                adsl_auxf_1_w1, ADSL_AUX_TIMER_G->dsc_cid.iec_src_func, ADSL_AUX_TIMER_G->dsc_cid.ac_cid_addr );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
           ADSL_WTR_G1->imc_length = iml1;  /* length of text / data   */
//         ADSL_WTR_G1->adsc_next = NULL;   /* end of chain            */
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
#endif
         return &ADSL_AUX_TIMER_G->dsc_cid;  /* return component id with position Server-Data-Hook */
#undef ADSL_AUX_TIMER_G
       case ied_auxf_q_gather:              /* query gather            */
#ifdef B130314
         if (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->iec_src_func
               != ied_src_fu_sdh) break;    /* not this function */
#endif
         if (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->dsc_cid.iec_src_func
               != ied_src_fu_sdh) break;    /* not this function */
#define ADSL_GAI1_COMP (((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->adsc_gai1_q)
         iml1 = 0;                          /* first funktion          */
         adsl_gai1_w1 = NULL;               /* gather not found        */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
         while (TRUE) {                     /* loop over all functions */
           while (adsl_sdhc1_w1) {          /* loop over all buffers   */
             adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain input data */
             while (adsl_gai1_w1) {         /* loop over output        */
               if (adsl_gai1_w1 == ADSL_GAI1_COMP) {  /* gather found  */
                 break;                     /* do not check more gather */
               }
               adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
             }
             if (adsl_gai1_w1) break;       /* gather found            */
             adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           }
           if (adsl_sdhc1_w1) break;        /* gather found            */
           if (iml1 == 2) break;            /* all functions done      */
           if (iml1 == 0) {                 /* do send to client now   */
#ifndef HL_UNIX
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send;
#else
#ifdef B120502
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_cl.adsc_sdhc1;  /* chain to send to client */
#else
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* get chain to send to client */
#endif
#endif
           } else {                         /* do send to server now   */
#ifdef B120502
#ifndef HL_UNIX
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;
#else
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* chain to send to server */
#endif
#else
             switch (ADSL_CONN1_G->iec_servcotype) {
               case ied_servcotype_normal_tcp:  /* normal TCP          */
#ifndef HL_UNIX
                 adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send;  /* get start of chain */
#else
                 adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send;  /* get chain to send to server */
#endif
                 break;
#ifdef D_INCL_HTUN
               case ied_servcotype_htun:    /* HOB-TUN                 */
                 adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get start of chain */
                 break;
#endif
               case ied_servcotype_l2tp:    /* L2TP                    */
                 adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_l2tp_sch;  /* send buffers */
                 break;
             }
#endif
           }
           iml1++;                          /* next function           */
         }
#undef ADSL_GAI1_COMP
         if (   (adsl_gai1_w1)
             && (adsl_gai1_w1->achc_ginp_end > adsl_gai1_w1->achc_ginp_cur)) {
           break;                           /* gather still active     */
         }
#ifdef B130314
         return (void *) ((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->ac_sdh;
#endif
         return &((struct dsd_aux_q_gather *) (adsl_auxf_1_w1 + 1))->dsc_cid;  /* return component id with position Server-Data-Hook */
       case ied_auxf_service_query_1:       /* service query 1         */
       case ied_auxf_sip:                   /* SIP request             */
       case ied_auxf_udp:                   /* UDP request             */
       case ied_auxf_admin:                 /* admin command           */
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
       case ied_auxf_pipe_conn:             /* aux-pipe established connection */
         if (((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->imc_signal == 0) break;  /* interrupt not set */
#ifdef XYZ1
#ifndef B130314
         ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
#endif
#ifdef B130314
         return ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->ac_sdh;
#endif
         return &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid;  /* return component id with position Server-Data-Hook */
       case ied_auxf_util_thread:           /* utility thread          */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_w1 + 1))
         if (ADSL_UTC_G->boc_thread_ended == FALSE) break;  /* thread has not yet ended */
         return &ADSL_UTC_G->dsc_cid;       /* return component id with position Server-Data-Hook */
#undef ADSL_UTC_G
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
   }
   if (   (ADSL_CONN1_G->adsc_int_webso_conn_1)  /* connect for WebSocket applications - internal */
       && (ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify)) {  /* notify SDH */
#ifdef XYZ1
#ifndef B130314
     ADSL_CONN1_G->boc_signal_set = TRUE;   /* signal for component set */
#endif
#endif
#ifdef B130314
     return ADSL_CONN1_G->adsc_int_webso_conn_1->ac_sdh;
#endif
     return &ADSL_CONN1_G->adsc_int_webso_conn_1->dsc_cid;
   }
   return NULL;                             /* no Server-Data-Hook found */
#undef ADSL_CONN1_G
} /* end m_check_sdh_signal()                                          */

/**
  Subroutine, which may be called from a Server-Data-Hook,
  to set the work-thread blocking
*/
static void m_set_wothr_blocking( void * vpp_userfld ) {
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
#undef ADSL_AUX_CF1
} /* end m_set_wothr_blocking()                                        */

/**
  Subroutine, which may be called from a Server-Data-Hook,
  to set the work-thread active
*/
static void m_set_wothr_active( void * vpp_userfld ) {
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#undef ADSL_AUX_CF1
} /* end m_set_wothr_active()                                          */

/**
  Subroutine to mark work area
*/
static BOOL m_mark_work_area( void *vpp_userfld, char * achp_pointer, int imp_incdec ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

#ifdef TRACEHL_WA_COUNT                     /* 17.09.09 KB count work area inc / dec */
   if (imp_incdec > 0) ims_count_wa_inc++;  /* work area increment     */
   else if (imp_incdec < 0) ims_count_wa_dec++;  /* work area decrement */
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* get chain of work-areas */
   while (adsl_sdhc1_w1) {                  /* loop over all temorary work areas */
     if (   (achp_pointer >= (char *) (adsl_sdhc1_w1 + 1))
         && (achp_pointer < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV))) {
       adsl_sdhc1_w1->imc_usage_count += imp_incdec;  /* set usage count */
#ifdef TRACEHL_SDH_01
       m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux.cpp l%05d m_mark_work_area( ... %p %d ) ADSL_AUX_CF1->adsc_sdhc1_chain adsl_sdhc1_w1=%p imc_usage_count=%d",
                       __LINE__, achp_pointer, imp_incdec, adsl_sdhc1_w1, adsl_sdhc1_w1->imc_usage_count );
#endif
#ifndef B140620
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier */
#endif
       return TRUE;                         /* work area marked        */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain input output work areas */
   while (adsl_sdhc1_w1) {                  /* loop over all input output work areas */
     if (   (achp_pointer >= (char *) (adsl_sdhc1_w1 + 1))
         && (achp_pointer < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV))) {
       adsl_sdhc1_w1->imc_usage_count += imp_incdec;  /* set usage count */
#ifdef TRACEHL_SDH_01
       m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux.cpp l%05d m_mark_work_area( ... %p %d ) ADSL_CONN1_G->adsc_sdhc1_chain adsl_sdhc1_w1=%p imc_usage_count=%d",
                       __LINE__, achp_pointer, imp_incdec, adsl_sdhc1_w1, adsl_sdhc1_w1->imc_usage_count );
#endif
#ifndef B140620
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier */
#endif
       return TRUE;                         /* work area marked        */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* get chain work areas in use */
   while (adsl_sdhc1_w1) {                  /* loop over all work areas in use */
     if (   (achp_pointer >= (char *) (adsl_sdhc1_w1 + 1))
         && (achp_pointer < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV))) {
       adsl_sdhc1_w1->imc_usage_count += imp_incdec;  /* set usage count */
#ifdef TRACEHL_SDH_01
       m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux.cpp l%05d m_mark_work_area( ... %p %d ) ADSL_CONN1_G->adsc_sdhc1_inuse adsl_sdhc1_w1=%p imc_usage_count=%d",
                       __LINE__, achp_pointer, imp_incdec, adsl_sdhc1_w1, adsl_sdhc1_w1->imc_usage_count );
#endif
#ifndef B140620
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier */
#endif
       return TRUE;                         /* work area marked        */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   return FALSE;                            /* area not found          */
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_mark_work_area()                                            */

/** process service query                                              */
static BOOL m_proc_service_query( void *vpp_userfld, struct dsd_aux_service_query_1 * adsp_sequ1 ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   struct dsd_service_conf_1 *adsl_service_conf_1;  /* chain of service configuration */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   if (adsp_sequ1->iec_co_service == ied_co_service_open) {  /* service open connection */
#ifndef HL_UNIX
     adsl_service_conf_1 = adsg_loconf_1_inuse->adsc_service_conf_1;
#else
     adsl_service_conf_1 = dss_loconf_1.adsc_service_conf_1;
#endif
     while (adsl_service_conf_1) {
       bol1 = m_cmp_vx_vx( &iml1,
                           adsp_sequ1->ac_service_name,  /* service name */
                           adsp_sequ1->imc_len_service_name,  /* length service name in elements */
                           adsp_sequ1->iec_chs_service_name,  /* character set service name */
                           adsl_service_conf_1->achc_name,  /* name of entry, UTF-8 */
                           adsl_service_conf_1->imc_len_name,  /* length of name bytes */
                           ied_chs_utf_8 );
       if ((bol1) && (iml1 == 0)) break;    /* service-name equal      */
       adsl_service_conf_1 = adsl_service_conf_1->adsc_next;  /* get next in chain */
     }
     if (adsl_service_conf_1 == NULL) {     /* service not found       */
       adsp_sequ1->iec_ret_service = ied_ret_service_inv_name;  /* invalid service name - not found */
       adsp_sequ1->vpc_sequ_handle = NULL;  /* clear handle of service query */
       return TRUE;                         /* all done                */
     }
     adsp_sequ1->vpc_sequ_handle
       = adsl_service_conf_1->amc_service_open( vpp_userfld,
                                                adsl_service_conf_1,
                                                adsp_sequ1 );
     if (adsp_sequ1->vpc_sequ_handle) {     /* opened successfully */
       adsp_sequ1->iec_ret_service = ied_ret_service_ok;  /* service command o.k. */
     } else {
       adsp_sequ1->iec_ret_service = ied_ret_service_open_failed;  /* service open failed */
     }
     return TRUE;                           /* all done                */
   }
   if (adsp_sequ1->vpc_sequ_handle == NULL) {  /* check handle of service query */
     adsp_sequ1->iec_ret_service = ied_ret_service_not_open;  /* service not open */
     return TRUE;
   }
   switch (adsp_sequ1->iec_co_service) {
     case ied_co_service_requ:              /* service request         */
       bol1 = ((struct dsd_service_aux_1 *) adsp_sequ1->vpc_sequ_handle)->amc_service_requ
                                            ( vpp_userfld,
                                              adsp_sequ1->vpc_sequ_handle,
                                              adsp_sequ1 );
       if (bol1) break;
       m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_SERVICE, (char *) adsp_sequ1->vpc_sequ_handle );
       adsp_sequ1->vpc_sequ_handle = NULL;  /* clear handle of service query */
       adsp_sequ1->iec_ret_service = ied_ret_service_req_failed;  /* request failed */
       return TRUE;
     case ied_co_service_close:             /* service close connection */
       ((struct dsd_service_aux_1 *) adsp_sequ1->vpc_sequ_handle)->amc_service_close
                                            ( vpp_userfld,
                                              adsp_sequ1->vpc_sequ_handle );
       m_wsp_s_ent_del( vpp_userfld, DEF_WSP_TYPE_SERVICE, (char *) adsp_sequ1->vpc_sequ_handle );
       adsp_sequ1->vpc_sequ_handle = NULL;  /* clear handle of service query */
       break;
     default:
       return FALSE;
   }
   adsp_sequ1->iec_ret_service = ied_ret_service_ok;  /* service command o.k. */
   return TRUE;
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_proc_service_query()                                        */

/** process SDH-object                                                 */
static BOOL m_aux_sdh_obj_1( void * vpp_userfld, struct dsd_get_sdh_object_1 *adsp_get_sdh_obj_1 ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   struct dsd_sdh_obj_1 *adsl_sdh_obj_1;    /* chain server-data-hook-object */

#ifndef HL_UNIX
   adsl_sdh_obj_1 = adsg_loconf_1_inuse->adsc_sdh_obj_1;
#else
   adsl_sdh_obj_1 = dss_loconf_1.adsc_sdh_obj_1;
#endif
   while (adsl_sdh_obj_1) {                 /* loop over all defined objects */
     bol1 = m_cmp_vx_vx( &iml1,
                         adsp_get_sdh_obj_1->ac_sdho_name,  /* Server-Data-Hook object name */
                         adsp_get_sdh_obj_1->imc_len_sdho_name,  /* length Server-Data-Hook object name in elements */
                         adsp_get_sdh_obj_1->iec_chs_sdho_name,  /* character set Server-Data-Hook object name */
                         adsl_sdh_obj_1 + 1,  /* name of entry, UTF-8 */
                         adsl_sdh_obj_1->imc_len_name,  /* length of name bytes */
                         ied_chs_utf_8 );
     if ((bol1) && (iml1 == 0)) {           /* requested SDH found     */
#ifdef B080609
       adsp_get_sdh_obj_1->adsc_sdh_stack_1->amc_hlclib01
         = adsl_sdh_obj_1->adsc_sdhl_1->amc_hlclib01;
#endif
       adsp_get_sdh_obj_1->adsc_sdh_stack_1->amc_hlclib01
         = adsl_sdh_obj_1->adsc_ext_lib1->amc_hlclib01;
       adsp_get_sdh_obj_1->adsc_sdh_stack_1->ac_conf = adsl_sdh_obj_1->ac_conf;
       adsp_get_sdh_obj_1->iec_ret_get_sdho = ied_ret_g_sdho_ok;  /* get sdh object command o.k. */
       return TRUE;                         /* all done                */
     }
     adsl_sdh_obj_1 = adsl_sdh_obj_1->adsc_next;  /* get next in chain */
   }
   adsp_get_sdh_obj_1->iec_ret_get_sdho = ied_ret_g_sdho_not_found;  /* Server-Data-Hook not found */
   return TRUE;                             /* all done                */
} /* end m_aux_sdh_obj_1()                                             */

/** retrieve session confiuration                                      */
static BOOL m_aux_session_conf_1( void *vpp_userfld, struct dsd_aux_session_conf_1 *adsp_sessco1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* compare values          */
   int        iml_count;                    /* count entries           */
   char       *achl1;                       /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_old_act;  /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_old_prev;  /* auxiliary extension fi */
   struct dsd_auxf_1 *adsl_auxf_1_new;      /* auxiliary extension fi  */
   struct dsd_aux_conf_servli_1 *adsl_servli_1_w1;  /* configure server list */
   struct dsd_server_list_1 *adsc_server_list_1_w1;  /* list of servers */
   struct dsd_targfi_1 *adsl_targfi_1_w1;   /* target-filter           */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#define ADSL_USENT_G (ADSL_CONN1_G->adsc_user_entry)
   /* search if element already exists                                 */
   adsl_auxf_1_old_act = ADSL_CONN1_G->adsc_auxf_1;  /* get first element */
   adsl_auxf_1_old_prev = NULL;             /* clear previous element  */
   while (adsl_auxf_1_old_act) {            /* loop over chain         */
     if (adsl_auxf_1_old_act->iec_auxf_def == ied_auxf_sessco1) break;  /* session configuration */
     adsl_auxf_1_old_prev = adsl_auxf_1_old_act;  /* set previous element */
     adsl_auxf_1_old_act = adsl_auxf_1_old_act->adsc_next;  /* get next in chain */
   }
   iml_count = 0;                           /* clear count entries     */
   adsl_servli_1_w1 = adsp_sessco1->adsc_servli_1;  /* get chain of configure server list */
   while (adsl_servli_1_w1) {               /* loop over configure server lists */
     iml_count++;                           /* count this entry        */
     adsl_servli_1_w1 = adsl_servli_1_w1->adsc_next;  /* get next in chain */
   }
   iml1 = 0;                                /* storage for INETAs      */
   if (adsp_sessco1->adsc_co_ineta_ppp) {   /* configured INETAs PPP */
     iml1 = (adsp_sessco1->adsc_co_ineta_ppp->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *));
   }
   if (adsp_sessco1->adsc_co_ineta_appl) {  /* configured INETAs application / HTCP */
     iml1 += (adsp_sessco1->adsc_co_ineta_appl->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *));
   }
   /* get storage for new entry                                        */
   adsl_auxf_1_new
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_sessco1)
                                       + iml_count * sizeof(void *)
                                       + iml1 );
   memset( adsl_auxf_1_new, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_sessco1) );
   adsl_auxf_1_new->iec_auxf_def = ied_auxf_sessco1;  /* session configuration */
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_new + 1))
   ADSL_AUXF_SESSCO1_W1->boc_use_default_servli = adsp_sessco1->boc_use_default_servli;  /* use default server list */
   if (adsp_sessco1->dsc_targfi_1_name.imc_len_str) {  /* length string in elements */
#ifndef HL_UNIX
     adsl_targfi_1_w1 = adsg_loconf_1_inuse->adsc_targfi_1;  /* chain of target-filters */
#else
     adsl_targfi_1_w1 = dss_loconf_1.adsc_targfi_1;  /* chain of target-filters */
#endif
     while (adsl_targfi_1_w1) {             /* loop over all configured target-filters */
#ifdef B110104
       bol1 = m_cmp_vx_vx( &iml_cmp,
                           adsp_sessco1->dsc_targfi_1_name.ac_str,
                           adsp_sessco1->dsc_targfi_1_name.imc_len_str,
                           adsp_sessco1->dsc_targfi_1_name.iec_chs_str,
                           adsl_targfi_1_w1->awcc_name,
                           -1,
                           ied_chs_utf_16 );
#endif
       bol1 = m_cmp_vx_vx( &iml_cmp,
                           adsp_sessco1->dsc_targfi_1_name.ac_str,
                           adsp_sessco1->dsc_targfi_1_name.imc_len_str,
                           adsp_sessco1->dsc_targfi_1_name.iec_chs_str,
                           (char *) adsl_targfi_1_w1 + adsl_targfi_1_w1->imc_off_name,
                           adsl_targfi_1_w1->imc_len_name,
                           ied_chs_utf_8 );
       if ((bol1) && (iml_cmp == 0)) break;  /* strings are equal      */
       adsl_targfi_1_w1 = adsl_targfi_1_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_targfi_1_w1 == NULL) {        /* target-filter not found */
       m_hlnew_printf( HLOG_WARN1, "HWSPM220W GATE=%(ux)s SNO=%08d INETA=%s set session parameters - target-filter \"%.*(.*)s\" not configured - ignored",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       adsp_sessco1->dsc_targfi_1_name.imc_len_str,
                       adsp_sessco1->dsc_targfi_1_name.iec_chs_str,
                       adsp_sessco1->dsc_targfi_1_name.ac_str );
     }
     ADSL_AUXF_SESSCO1_W1->adsc_targfi_1 = adsl_targfi_1_w1;  /* set target-filter */
   }
   adsl_servli_1_w1 = adsp_sessco1->adsc_servli_1;  /* get chain of configure server list */
   while (adsl_servli_1_w1) {               /* loop over configure server lists */
#ifndef HL_UNIX
     adsc_server_list_1_w1 = adsg_loconf_1_inuse->adsc_server_list_1;  /* chain of list of servers */
#else
     adsc_server_list_1_w1 = dss_loconf_1.adsc_server_list_1;  /* chain of list of servers */
#endif
     while (adsc_server_list_1_w1) {        /* loop over all configured server-lists */
       bol1 = m_cmp_vx_vx( &iml_cmp,
                           adsl_servli_1_w1->dsc_servli_name.ac_str,
                           adsl_servli_1_w1->dsc_servli_name.imc_len_str,
                           adsl_servli_1_w1->dsc_servli_name.iec_chs_str,
                           adsc_server_list_1_w1 + 1,
                           -1,
                           ied_chs_utf_16 );
       if ((bol1) && (iml_cmp == 0)) break;  /* strings are equal      */
       adsc_server_list_1_w1 = adsc_server_list_1_w1->adsc_next;  /* get next in chain */
     }
     if (adsc_server_list_1_w1 == NULL) {   /* server list not found   */
       m_hlnew_printf( HLOG_XYZ1, "HWSPM221W GATE=%(ux)s SNO=%08d INETA=%s set session parameters - server-list \"%.*(.*)s\" not configured - ignored",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       adsl_servli_1_w1->dsc_servli_name.imc_len_str,
                       adsl_servli_1_w1->dsc_servli_name.iec_chs_str,
                       adsl_servli_1_w1->dsc_servli_name.ac_str );
     } else {                               /* server list found       */
       iml_count = ADSL_AUXF_SESSCO1_W1->imc_no_seli;  /* get number of server lists already set */
       while (iml_count > 0) {              /* check all previous server lists */
         if (*((void **) ADSL_AUXF_SESSCO1_W1 + iml_count - 1) == (void *) adsc_server_list_1_w1) {
           m_hlnew_printf( HLOG_XYZ1, "HWSPM222W GATE=%(ux)s SNO=%08d INETA=%s set session parameters - server-list \"%.*(.*)s\" double set - ignored",
                           ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                           adsl_servli_1_w1->dsc_servli_name.imc_len_str,
                           adsl_servli_1_w1->dsc_servli_name.iec_chs_str,
                           adsl_servli_1_w1->dsc_servli_name.ac_str );
           break;
         }
         iml_count--;                       /* decrement index         */
       }
       if (iml_count <= 0) {                /* check was o.k.          */
         *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + ADSL_AUXF_SESSCO1_W1->imc_no_seli)
           = (void *) adsc_server_list_1_w1;
         ADSL_AUXF_SESSCO1_W1->imc_no_seli++;  /* increment count server-list */
       }
     }
     adsl_servli_1_w1 = adsl_servli_1_w1->adsc_next;  /* get next in chain */
   }
   achl1 = (char *) ((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + ADSL_AUXF_SESSCO1_W1->imc_no_seli);
   if (adsp_sessco1->adsc_co_ineta_ppp) {   /* configured INETAs PPP */
     iml1 = (adsp_sessco1->adsc_co_ineta_ppp->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *));
     memcpy( achl1, adsp_sessco1->adsc_co_ineta_ppp, iml1 );
     ADSL_AUXF_SESSCO1_W1->adsc_co_ineta_ppp = (struct dsd_config_ineta_1 *) achl1;
     achl1 += iml1;
   }
   if (adsp_sessco1->adsc_co_ineta_appl) {  /* configured INETAs application / HTCP */
     iml1 = (adsp_sessco1->adsc_co_ineta_appl->imc_len_mem + sizeof(void *) - 1) & (0 - sizeof(void *));
     memcpy( achl1, adsp_sessco1->adsc_co_ineta_appl, iml1 );
     ADSL_AUXF_SESSCO1_W1->adsc_co_ineta_appl = (struct dsd_config_ineta_1 *) achl1;
   }
#undef ADSL_AUXF_SESSCO1_W1
   if (adsl_auxf_1_old_act) {               /* replace old element     */
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
#endif
     if (adsl_auxf_1_old_prev == NULL) {    /* is first in chain       */
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_old_act->adsc_next;  /* set first element */
     } else {                               /* middle in chain         */
       adsl_auxf_1_old_prev->adsc_next = adsl_auxf_1_old_act->adsc_next;  /* remove from chain */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#endif
     free( adsl_auxf_1_old_act );           /* free storage            */
   }
   adsl_auxf_1_new->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_new;  /* set first element */
   return TRUE;
#undef ADSL_USENT_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_session_conf_1()                                        */

/** process admin request over aux callback routine                    */
static BOOL m_aux_admin_1( void *vpp_userfld, struct dsd_aux_admin_1 *adsp_admin1 ) {
// BOOL       bol1;                         /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   /* search if element already exists                                 */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get first element   */
   while (adsl_auxf_1_w1) {                 /* loop over chain         */
#ifdef B130314
     if (   (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_admin)  /* admin command */
         && (((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->ac_sdh == ADSL_AUX_CF1->ac_sdh)) {  /* current Server-Data-Hook */
       break;                               /* entry found             */
     }
#endif
     if (   (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_admin)  /* admin command */
         && (((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid.ac_cid_addr == ADSL_AUX_CF1->dsc_cid.ac_cid_addr)) {  /* current Server-Data-Hook */
       break;                               /* entry found             */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_w1 == NULL) {            /* admin element not found */
     /* get storage for new entry                                      */
     adsl_auxf_1_w1
       = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                         + sizeof(struct dsd_auxf_ext_1)
                                         + sizeof(struct dsd_auxf_admin1) );
     memset( adsl_auxf_1_w1, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1) + sizeof(struct dsd_auxf_admin1) );
     adsl_auxf_1_w1->iec_auxf_def = ied_auxf_admin;  /* admin command  */
#ifdef B130314
     ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->ac_sdh = ADSL_AUX_CF1->ac_sdh;  /* current Server-Data-Hook */
#endif
     memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
     adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain     */
   } else {                                 /* check if free old memory */
     if (adsp_admin1->boc_free_buffers) {   /* free old buffers        */
       while (((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1) {  /* buffers from previous calls */
         adsl_sdhc1_w1 = ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1;
         ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1
           = adsl_sdhc1_w1->adsc_next;      /* remove from chain       */
         m_proc_free( adsl_sdhc1_w1 );      /* free the buffer         */
       }
     }
   }
   return m_proc_admin_aux( adsp_admin1, adsl_auxf_1_w1, ADSL_AUX_CF1->adsc_hco_wothr );
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_admin_1()                                               */

/** set ident of a session over aux callback routine                   */
static BOOL m_aux_set_ident_1( void *vpp_userfld, struct dsd_aux_set_ident_1 *adsp_ident1 ) {
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_prev;     /* auxiliary extension fi  */
   struct dsd_auxf_ident_1 dsl_auxf_ident_1;  /* definition ident      */
   void *     al_free;                      /* memory to free          */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   memset( &dsl_auxf_ident_1, 0, sizeof(struct dsd_auxf_ident_1) );  /* definition ident */
#ifdef B101118
   dsl_auxf_ident_1.imc_len_userid = 0;     /* clear length userid UTF-8     */
#endif
   if (adsp_ident1->dsc_userid.imc_len_str) {  /* length string in elements not zero */
     if (adsp_ident1->dsc_userid.ac_str == NULL) return FALSE;  /* is not valid */
     if (adsp_ident1->dsc_userid.iec_chs_str == ied_chs_invalid) return FALSE;  /* is not valid */
     dsl_auxf_ident_1.imc_len_userid
       = m_len_vx_vx( ied_chs_utf_8,
                      adsp_ident1->dsc_userid.ac_str,
                      adsp_ident1->dsc_userid.imc_len_str,
                      adsp_ident1->dsc_userid.iec_chs_str );
     if (dsl_auxf_ident_1.imc_len_userid <= 0) return FALSE;  /* is not valid */
   }
#ifdef B101118
   dsl_auxf_ident_1.imc_len_user_group = 0;  /* clear length name user group UTF-8 */
#endif
   if (adsp_ident1->dsc_user_group.imc_len_str != 0) {  /* length string in elements not zero */
     if (adsp_ident1->dsc_user_group.ac_str == NULL) return FALSE;  /* is not valid */
     if (adsp_ident1->dsc_user_group.iec_chs_str == ied_chs_invalid) return FALSE;  /* is not valid */
     dsl_auxf_ident_1.imc_len_user_group
       = m_len_vx_vx( ied_chs_utf_8,
                      adsp_ident1->dsc_user_group.ac_str,
                      adsp_ident1->dsc_user_group.imc_len_str,
                      adsp_ident1->dsc_user_group.iec_chs_str );
     if (dsl_auxf_ident_1.imc_len_user_group <= 0) return FALSE;  /* is not valid */
   }
#ifdef WSP_V24
   if (adsp_ident1->dsc_cl_host.imc_len_str != 0) {  /* unicode string host sent by client */
     if (adsp_ident1->dsc_cl_host.ac_str == NULL) return FALSE;  /* is not valid */
     if (adsp_ident1->dsc_cl_host.iec_chs_str == ied_chs_invalid) return FALSE;  /* is not valid */
     dsl_auxf_ident_1.imc_len_cl_host       /* length UTF-8 string host sent by client */
       = m_len_vx_ucs( ied_chs_utf_8, &adsp_ident1->dsc_cl_host );
     if (dsl_auxf_ident_1.imc_len_cl_host <= 0) return FALSE;  /* is not valid */
   }
   if (adsp_ident1->dsc_cl_device.imc_len_str != 0) {  /* unicode string device sent by client */
     if (adsp_ident1->dsc_cl_device.ac_str == NULL) return FALSE;  /* is not valid */
     if (adsp_ident1->dsc_cl_device.iec_chs_str == ied_chs_invalid) return FALSE;  /* is not valid */
     dsl_auxf_ident_1.imc_len_cl_device     /* length UTF-8 string device sent by client */
       = m_len_vx_ucs( ied_chs_utf_8, &adsp_ident1->dsc_cl_device );
     if (dsl_auxf_ident_1.imc_len_cl_device <= 0) return FALSE;  /* is not valid */
   }
   if (adsp_ident1->dsc_cl_appl.imc_len_str != 0) {  /* unicode string appl sent by client */
     if (adsp_ident1->dsc_cl_appl.ac_str == NULL) return FALSE;  /* is not valid */
     if (adsp_ident1->dsc_cl_appl.iec_chs_str == ied_chs_invalid) return FALSE;  /* is not valid */
     dsl_auxf_ident_1.imc_len_cl_appl       /* length UTF-8 string appl sent by client */
       = m_len_vx_ucs( ied_chs_utf_8, &adsp_ident1->dsc_cl_appl );
     if (dsl_auxf_ident_1.imc_len_cl_appl <= 0) return FALSE;  /* is not valid */
   }
   dsl_auxf_ident_1.imc_auth_flags = adsp_ident1->imc_auth_flags;  /* flags from authentication - WSP-socks-mode */
#endif
   dsl_auxf_ident_1.imc_len_userfld = adsp_ident1->imc_len_userfld;  /* length user field any character set */
   /* search if element already exists                                 */
   adsl_auxf_1_prev = NULL;                 /* clear previous element  */
   adsl_auxf_1_cur = ADSL_CONN1_G->adsc_auxf_1;  /* get first element  */
   al_free = NULL;                          /* memory to free          */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_prev == NULL) {      /* no previous element     */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_cur->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_auxf_1_prev->adsc_next = adsl_auxf_1_cur->adsc_next;  /* remove from chain */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
//     free( adsl_auxf_1_cur );             /* free memory             */
       al_free = adsl_auxf_1_cur;           /* memory to free          */
       break;                               /* all done                */
     }
     adsl_auxf_1_prev = adsl_auxf_1_cur;    /* set previous element    */
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   if (   (dsl_auxf_ident_1.imc_len_userid == 0)  /* check length userid UTF-8     */
       && (dsl_auxf_ident_1.imc_len_user_group == 0)  /* check length name user group UTF-8 */
       && (dsl_auxf_ident_1.imc_len_userfld == 0)) {  /* check length user field any character set */
     if (al_free) {                         /* memory to free          */
       free( al_free );                     /* free memory now         */
     }
     return TRUE;                           /* all done                */
   }
   if (dsl_auxf_ident_1.imc_len_user_group == 0) {  /* check length name user group UTF-8 */
     m_hlnew_printf( HLOG_INFO1, "HWSPM223I GATE=%(ux)s SNO=%08d INETA=%s set session owner userid=%.*(.*)s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_ident1->dsc_userid.imc_len_str,
                     adsp_ident1->dsc_userid.iec_chs_str,
                     adsp_ident1->dsc_userid.ac_str );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPM224I GATE=%(ux)s SNO=%08d INETA=%s set session owner group=%.*(.*)s userid=%.*(.*)s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_ident1->dsc_user_group.imc_len_str,
                     adsp_ident1->dsc_user_group.iec_chs_str,
                     adsp_ident1->dsc_user_group.ac_str,
                     adsp_ident1->dsc_userid.imc_len_str,
                     adsp_ident1->dsc_userid.iec_chs_str,
                     adsp_ident1->dsc_userid.ac_str );
   }
   /* get storage for new entry                                        */
#ifndef WSP_V24
   adsl_auxf_1_cur
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_ident_1)
                                       + dsl_auxf_ident_1.imc_len_userid  /* length userid UTF-8 */
                                       + dsl_auxf_ident_1.imc_len_user_group  /* length name user group UTF-8 */
                                       + dsl_auxf_ident_1.imc_len_userfld );  /* length user field any character set */
#endif
#ifdef WSP_V24
   adsl_auxf_1_cur
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_ident_1)
                                       + dsl_auxf_ident_1.imc_len_userid  /* length userid UTF-8 */
                                       + dsl_auxf_ident_1.imc_len_user_group  /* length name user group UTF-8 */
                                       + dsl_auxf_ident_1.imc_len_cl_host  /* length UTF-8 string host sent by client */
                                       + dsl_auxf_ident_1.imc_len_cl_device  /* length UTF-8 string device sent by client */
                                       + dsl_auxf_ident_1.imc_len_cl_appl );  /* length UTF-8 string appl sent by client */
#endif
   memcpy( adsl_auxf_1_cur + 1, &dsl_auxf_ident_1, sizeof(struct dsd_auxf_ident_1) );
   if (dsl_auxf_ident_1.imc_len_userid) {   /* check length userid UTF-8 */
     m_cpy_vx_vx( (char *) (adsl_auxf_1_cur + 1) + sizeof(struct dsd_auxf_ident_1),
                  dsl_auxf_ident_1.imc_len_userid,
                  ied_chs_utf_8,
                  adsp_ident1->dsc_userid.ac_str,
                  adsp_ident1->dsc_userid.imc_len_str,
                  adsp_ident1->dsc_userid.iec_chs_str );
   }
   if (dsl_auxf_ident_1.imc_len_user_group) {  /* check length name user group UTF-8 */
     m_cpy_vx_vx( (char *) (adsl_auxf_1_cur + 1) + sizeof(struct dsd_auxf_ident_1) + dsl_auxf_ident_1.imc_len_userid,
                  dsl_auxf_ident_1.imc_len_user_group,
                  ied_chs_utf_8,
                  adsp_ident1->dsc_user_group.ac_str,
                  adsp_ident1->dsc_user_group.imc_len_str,
                  adsp_ident1->dsc_user_group.iec_chs_str );
   }
   if (dsl_auxf_ident_1.imc_len_userfld) {  /* check length user field any character set */
     memcpy( (char *) (adsl_auxf_1_cur + 1) + sizeof(struct dsd_auxf_ident_1)
                        + dsl_auxf_ident_1.imc_len_userid
                        + dsl_auxf_ident_1.imc_len_user_group,
             adsp_ident1->achc_userfld,
             dsl_auxf_ident_1.imc_len_userfld );
   }
#ifdef WSP_V24
   if (dsl_auxf_ident_1.imc_len_cl_host) {  /* length UTF-8 string host sent by client */
     m_cpy_vx_ucs( (char *) (adsl_auxf_1_cur + 1)
                     + sizeof(struct dsd_auxf_ident_1)
                     + dsl_auxf_ident_1.imc_len_userid
                     + dsl_auxf_ident_1.imc_len_user_group,
                   dsl_auxf_ident_1.imc_len_cl_host,
                   ied_chs_utf_8,
                   &adsp_ident1->dsc_cl_host );
   }
   if (dsl_auxf_ident_1.imc_len_cl_device) {  /* length UTF-8 string device sent by client */
     m_cpy_vx_ucs( (char *) (adsl_auxf_1_cur + 1)
                     + sizeof(struct dsd_auxf_ident_1)
                     + dsl_auxf_ident_1.imc_len_userid
                     + dsl_auxf_ident_1.imc_len_user_group
                     + dsl_auxf_ident_1.imc_len_cl_host,
                   dsl_auxf_ident_1.imc_len_cl_device,
                   ied_chs_utf_8,
                   &adsp_ident1->dsc_cl_device );
   }
   if (dsl_auxf_ident_1.imc_len_cl_appl) {  /* length UTF-8 string appl sent by client */
     m_cpy_vx_ucs( (char *) (adsl_auxf_1_cur + 1)
                     + sizeof(struct dsd_auxf_ident_1)
                     + dsl_auxf_ident_1.imc_len_userid
                     + dsl_auxf_ident_1.imc_len_user_group
                     + dsl_auxf_ident_1.imc_len_cl_host
                     + dsl_auxf_ident_1.imc_len_cl_device,
                   dsl_auxf_ident_1.imc_len_cl_appl,
                   ied_chs_utf_8,
                   &adsp_ident1->dsc_cl_appl );
   }
#endif
   memset( adsl_auxf_1_cur, 0, sizeof(struct dsd_auxf_1) );
   adsl_auxf_1_cur->iec_auxf_def = ied_auxf_ident;  /* ident - userid and user-group */
   adsl_auxf_1_cur->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_cur;  /* set new chain      */
   if (al_free) {                           /* memory to free          */
     free( al_free );                       /* free memory now         */
   }
   return TRUE;                             /* all done                */
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_set_ident_1()                                           */

/** retrieve ident of a session over aux callback routine              */
static BOOL m_aux_get_ident_1( DSD_CONN_G *adsp_conn, struct dsd_sdh_ident_set_1 *adsp_g_idset1 ) {
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */

   adsl_auxf_1_cur = adsp_conn->adsc_auxf_1;  /* get first element     */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
       goto p_found_00;                     /* entry found             */
     }
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   return FALSE;

   p_found_00:                              /* entry found             */
#define ADSL_AUXF_IDENT_1 ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_cur + 1))
   adsp_g_idset1->dsc_userid.ac_str = ADSL_AUXF_IDENT_1 + 1;
   adsp_g_idset1->dsc_userid.imc_len_str = ADSL_AUXF_IDENT_1->imc_len_userid;
   adsp_g_idset1->dsc_userid.iec_chs_str = ied_chs_utf_8;
   if (ADSL_AUXF_IDENT_1->imc_len_user_group) {  /* check length name user group UTF-8 */
     adsp_g_idset1->dsc_user_group.ac_str = (char *) (ADSL_AUXF_IDENT_1 + 1) + ADSL_AUXF_IDENT_1->imc_len_userid;
     adsp_g_idset1->dsc_user_group.imc_len_str = ADSL_AUXF_IDENT_1->imc_len_user_group;
     adsp_g_idset1->dsc_user_group.iec_chs_str = ied_chs_utf_8;
   }
#ifdef WSP_V24
   if (ADSL_AUXF_IDENT_1->imc_len_cl_host) {  /* length UTF-8 string host sent by client */
     adsp_g_idset1->dsc_cl_host.ac_str
       = (char *) (ADSL_AUXF_IDENT_1 + 1)
           + ADSL_AUXF_IDENT_1->imc_len_userid
           + ADSL_AUXF_IDENT_1->imc_len_user_group;
     adsp_g_idset1->dsc_cl_host.imc_len_str = ADSL_AUXF_IDENT_1->imc_len_cl_host;
     adsp_g_idset1->dsc_cl_host.iec_chs_str = ied_chs_utf_8;
   }
   if (ADSL_AUXF_IDENT_1->imc_len_cl_device) {  /* length UTF-8 string device sent by client */
     adsp_g_idset1->dsc_cl_device.ac_str
       = (char *) (ADSL_AUXF_IDENT_1 + 1)
           + ADSL_AUXF_IDENT_1->imc_len_userid
           + ADSL_AUXF_IDENT_1->imc_len_user_group
           + ADSL_AUXF_IDENT_1->imc_len_cl_host;
     adsp_g_idset1->dsc_cl_device.imc_len_str = ADSL_AUXF_IDENT_1->imc_len_cl_device;
     adsp_g_idset1->dsc_cl_device.iec_chs_str = ied_chs_utf_8;
   }
   if (ADSL_AUXF_IDENT_1->imc_len_cl_appl) {  /* length UTF-8 string appl sent by client */
     adsp_g_idset1->dsc_cl_appl.ac_str
       = (char *) (ADSL_AUXF_IDENT_1 + 1)
           + ADSL_AUXF_IDENT_1->imc_len_userid
           + ADSL_AUXF_IDENT_1->imc_len_user_group
           + ADSL_AUXF_IDENT_1->imc_len_cl_host
           + ADSL_AUXF_IDENT_1->imc_len_cl_device;
     adsp_g_idset1->dsc_cl_appl.imc_len_str = ADSL_AUXF_IDENT_1->imc_len_cl_appl;
     adsp_g_idset1->dsc_cl_appl.iec_chs_str = ied_chs_utf_8;
   }
   adsp_g_idset1->imc_auth_flags = ADSL_AUXF_IDENT_1->imc_auth_flags;  /* flags from authentication - WSP-socks-mode */
#endif
   if (ADSL_AUXF_IDENT_1->imc_len_userfld) {  /* check length user field any character set */
     adsp_g_idset1->achc_userfld            /* user field for session */
       = (char *) (ADSL_AUXF_IDENT_1 + 1)
                     + ADSL_AUXF_IDENT_1->imc_len_userid
                     + ADSL_AUXF_IDENT_1->imc_len_user_group;
     adsp_g_idset1->imc_len_userfld = ADSL_AUXF_IDENT_1->imc_len_userfld;  /* length user field for session */
   }
#undef ADSL_AUXF_IDENT_1
   return TRUE;                             /* structure has been filled */
} /* end m_aux_get_ident_1()                                           */

/** get domain userid INETA                                            */
static void m_aux_get_duia_1( DSD_CONN_G *adsp_conn, struct dsd_aux_get_duia_1 *adsp_g_duia_1 ) {
   int        iml1, iml2, iml3;             /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */

   achl1 = adsp_g_duia_1->achc_string;      /* address of string       */
   achl2 = achl1 + adsp_g_duia_1->imc_len_field;  /* plus length of field, input, end of output */
   iml1 = 0;                                /* no output till now      */
   adsl_auxf_1_cur = adsp_conn->adsc_auxf_1;  /* get first element     */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
       goto p_found_00;                     /* entry found             */
     }
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   if (achl1 < achl2) *achl1++ = '/';
   if (achl1 < achl2) *achl1++ = '/';
   iml1 = 2;                                /* filled till here        */
   goto p_ineta_00;                         /* fill in INETA           */

   p_found_00:                              /* entry found             */
#define ADSL_AUXF_IDENT_1 ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_cur + 1))
   iml2 = achl2 - achl1;                    /* space in output area    */
   if (iml2 > ADSL_AUXF_IDENT_1->imc_len_user_group) iml2 = ADSL_AUXF_IDENT_1->imc_len_user_group;
   if (iml2 > 0) {                          /* space to fill in domain */
     memcpy( achl1, (char *) (ADSL_AUXF_IDENT_1 + 1) + ADSL_AUXF_IDENT_1->imc_len_userid, iml2 );
     achl1 += iml2;
   }
   iml1 += ADSL_AUXF_IDENT_1->imc_len_user_group;
   if (achl1 < achl2) *achl1++ = '/';
   iml1++;
   iml2 = achl2 - achl1;                    /* space in output area    */
   if (iml2 > ADSL_AUXF_IDENT_1->imc_len_userid) iml2 = ADSL_AUXF_IDENT_1->imc_len_userid;
   if (iml2 > 0) {                          /* space to fill in userid */
     memcpy( achl1, ADSL_AUXF_IDENT_1 + 1, iml2 );
     achl1 += iml2;
   }
   iml1 += ADSL_AUXF_IDENT_1->imc_len_userid;
   if (achl1 < achl2) *achl1++ = '/';
   iml1++;
#ifdef XYZ1
   if (ADSL_AUXF_IDENT_1->imc_len_userfld) {  /* check length user field any character set */
     adsp_g_idset1->achc_userfld            /* user field for session */
       = (char *) (ADSL_AUXF_IDENT_1 + 1)
                     + ADSL_AUXF_IDENT_1->imc_len_userid
                     + ADSL_AUXF_IDENT_1->imc_len_user_group;
     adsp_g_idset1->imc_len_userfld = ADSL_AUXF_IDENT_1->imc_len_userfld;  /* length user field for session */
   }
#endif
#undef ADSL_AUXF_IDENT_1

   p_ineta_00:                              /* fill in INETA           */
   iml2 = strlen( adsp_conn->chrc_ineta );  /* internet-address char   */
   iml3 = achl2 - achl1;                    /* space in output area    */
   if (iml3 > iml2) iml3 = iml2;            /* set length of INETA     */
   if (iml3 > 0) {                          /* space to fill in userid */
     memcpy( achl1, adsp_conn->chrc_ineta, iml3 );
     achl1 += iml3;
   }
   iml1 += iml2;
   adsp_g_duia_1->imc_len_string = iml1;    /* length of string, output, maybe longer than imc_len_field */
   return;                                  /* structure has been filled */
} /* end m_aux_get_duia_1()                                            */

/**
  for secure XOR, there is an entry in the WSP-XML-configuration-file,
  <general>
    <security-token-plain>
      or
    <security-token-encrypted>
  a hash is taken from this UTF-8 string.
  When the function aux() DEF_AUX_SECURE_XOR is processed,
  the optionally passed post-key is also feed into this hash.
  AES encryption is done as described in RFC 3711 - Secure RTP (SRTP).
  The follwing input variables are needed for the AES encryption:
  - RSA key, 256 bit = 32 bytes
  - IV, 128 bit = 16 bytes
  - first block for AES CBC encryption, 16 bytes
    ??? 23.11.12 KB
  the output string is built by XOR of the input string
  with the result of the AES encryption.
*/
/** process secure XOR                                                 */
static BOOL m_aux_secure_xor( struct dsd_aux_secure_xor_1 *adsp_asx1 ) {
   char       *achl1, *achl2, *achl3, *achl4, *achl5;  /* working variables */
   HL_LONGLONG ilrl_sha384_temp[ SHA384_ARRAY_SIZE ];  /* for hash security-token */
   char       chrl_hash_both[ SHA384_DIGEST_LEN ];  /* output of hash  */
   char       chrl_encry1[ 16 ];            /* for encryption          */
   char       chrl_encry_in[ 16 ];          /* input for encryption    */
   struct ds_aes_key_t dsl_enckeybyte;      /* for AES encryption      */
   unsigned char ucrl_ivector[ HL_AES_LEN ];

   if (adsp_asx1->imc_len_xor <= 0) {       /* length of string        */
     return FALSE;                          /* signal error            */
   }
   memcpy( ilrl_sha384_temp, ilrs_sha384_security_token, sizeof(ilrs_sha384_security_token) );  /* for hash security-token */
   if (adsp_asx1->imc_len_post_key > 0) {   /* length of post key string */
     SHA384_512_Update( ilrl_sha384_temp, adsp_asx1->achc_post_key, 0, adsp_asx1->imc_len_post_key );
   }
   SHA384_Final( ilrl_sha384_temp, chrl_hash_both, 0 );
#ifndef B160919
   /* by Dr. Fink; included KB 11.02.17 */
   dsl_enckeybyte.im_flags = CHECK_CPU_AES_FLAG;
#endif
   m_aes_set_encrypt_key( (unsigned char *) chrl_hash_both, 8, &dsl_enckeybyte );
   memcpy( ucrl_ivector, (unsigned char *) chrl_hash_both + 32, sizeof(ucrl_ivector) );
   achl1 = adsp_asx1->achc_source;          /* address of source       */
   achl2 = achl1 + adsp_asx1->imc_len_xor;  /* add length of string, end */
   achl3 = adsp_asx1->achc_destination;     /* address of destination  */
   memset( chrl_encry_in, 0, sizeof(chrl_encry_in) );  /* input for encryption */
   while (TRUE) {                           /* loop to XOR data        */
     m_aes_cbc_encrypt( (unsigned char *) chrl_encry_in, (unsigned char *) chrl_encry1, &dsl_enckeybyte, 1, ucrl_ivector, 8 + 6 );
     achl4 = achl1 + sizeof(chrl_encry1);
     if (achl4 > achl2) achl4 = achl2;      /* end of input            */
     achl5 = chrl_encry1;                   /* here is content for XOR */
     do {
       *achl3 = *achl1 ^ *achl5;            /* one byte XOR            */
       achl1++;                             /* increment input         */
       achl3++;                             /* increment output        */
       achl5++;                             /* increment content for XOR */
     } while (achl1 < achl4);
     if (achl1 >= achl2) break;
     *((int *) chrl_encry1) += 1;
   }
   return TRUE;
} /* end m_aux_secure_xor()                                            */

/** connect for WebSocket applications                                 */
static BOOL m_aux_webso_conn( void *vpp_userfld, struct dsd_aux_webso_conn_1 *adsp_awc1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_lbal_send;  /* load-balancing send to client */
   struct dsd_conn_pttd_thr *adsl_cpttdt;   /* connect PTTD thread     */

#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (vpp_userfld) {
     ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
   }
#endif
#ifdef DEBUG_150509_01                      /* problem memory-leak webso_conn */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_aux_webso_conn() ADSL_CONN1_G=%p adsp_awc1->iec_cwc=%d.",
                   __LINE__, ADSL_CONN1_G, adsp_awc1->iec_cwc );
#endif

   adsp_awc1->imc_len_data_recv = 0;        /* clear length data received */
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     goto p_cont_00;                        /* continue processing     */
   }
   adsp_awc1->boc_internal_act = FALSE;     /* internal WebSocket component not active */
   adsp_awc1->iec_twc = ied_twc_invalid;    /* invalid                 */
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_websocket) {  /* check protocol WebSocket */
     adsp_awc1->iec_rwc = ied_rwc_no_webso_prot;  /* connection not WebSocket protocol */
     return TRUE;
   }
   if (adsp_awc1->iec_cwc != ied_cwc_open) {  /* open - connect to internal routine */
     adsp_awc1->iec_rwc = ied_rwc_inv_param;  /* invalid parameters in call */
     return TRUE;
   }
   adsp_awc1->iec_rwc = ied_rwc_ok;         /* processing o.k.         */
   bol1 = FALSE;                            /* internal structure not necessary */
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_DIR) {  /* normal connection */
     adsp_awc1->iec_twc = ied_twc_dynamic;  /* dynamic, nothing configured */
     if (   (ADSL_CONN1_G->adsc_server_conf_1->adsc_server_ineta)  /* server INETA */
         || (ADSL_CONN1_G->adsc_server_conf_1->boc_dns_lookup_before_connect)) {  /* needs to solve INETA before connect */
       adsp_awc1->iec_twc = ied_twc_static;  /* static, server configured */
       bol1 = TRUE;                         /* internal structure necessary */
     }
   } else if (ADSL_CONN1_G->adsc_server_conf_1->inc_function < 0) {  /* something with load-balancing */
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_WTS) {  /* set function WTSGATE */
       adsp_awc1->iec_twc = ied_twc_lbal;   /* WTS load-balancing      */
       bol1 = TRUE;                         /* internal structure necessary */
     } else if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_VDI_WSP) {  /* set function VDI-WSP-GATE */
       adsp_awc1->iec_twc = ied_twc_vdi;    /* VDI                     */
       bol1 = TRUE;                         /* internal structure necessary */
     }
   } else if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
     adsp_awc1->iec_twc = ied_twc_pttd;     /* pass thru to desktop - DOD desktop-on-demand */
     bol1 = TRUE;                           /* internal structure necessary */
   }
   if (bol1 == FALSE) {                     /* internal structure not necessary */
     return TRUE;
   }
   ADSL_CONN1_G->adsc_int_webso_conn_1 = (struct dsd_int_webso_conn_1 *) malloc( sizeof(struct dsd_int_webso_conn_1) );  /* connect for WebSocket applications - internal */
   memset( ADSL_CONN1_G->adsc_int_webso_conn_1, 0, sizeof(struct dsd_int_webso_conn_1) );  /* connect for WebSocket applications - internal */
   ADSL_CONN1_G->adsc_int_webso_conn_1->iec_twc = adsp_awc1->iec_twc;
   ADSL_CONN1_G->adsc_int_webso_conn_1->imc_signal = adsp_awc1->imc_signal;  /* signal to set */
#ifdef B130314
   ADSL_CONN1_G->adsc_int_webso_conn_1->ac_sdh = ADSL_AUX_CF1->ac_sdh;  /* current Server-Data-Hook */
#endif
   memcpy( &ADSL_CONN1_G->adsc_int_webso_conn_1->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
   adsp_awc1->boc_internal_act = TRUE;      /* internal WebSocket component active */
   return TRUE;

   p_cont_00:                               /* continue processing     */
#ifdef DEBUG_150509_01                      /* problem memory-leak webso_conn */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_aux_webso_conn() p_cont_00: ADSL_CONN1_G->adsc_int_webso_conn_1=%p ->adsc_sdhc1_recv=%p.",
                   __LINE__, ADSL_CONN1_G->adsc_int_webso_conn_1, ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv );
#endif
   if (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_gai1_pass) {  /* data passed to calling program */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* buffers received */
     if (adsl_sdhc1_w1->adsc_gather_i_1_i != ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_gai1_pass) {
// to-do 08.06.12 KB - error message
     }
     ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_gai1_pass = NULL;  /* no data passed to calling program */
     adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_sdhc1_w1->adsc_gather_i_1_i->adsc_next;  /* remove gather */
     if (adsl_sdhc1_w1->adsc_gather_i_1_i == NULL) {  /* no more data in this sdhc1 */
       ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_w1->adsc_next;  /* remove from chain buffers received */
       m_proc_free( adsl_sdhc1_w1 );        /* free memory again       */
     }
   }
   switch (adsp_awc1->iec_cwc) {            /* command WebSocket connect */
     case ied_cwc_open:                     /* open - connect to internal routine */
       adsp_awc1->iec_rwc = ied_rwc_inv_param;  /* invalid parameters in call */
       return TRUE;
     case ied_cwc_status:                   /* check status            */
       ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = FALSE;  /* reset notify SDH */
       while (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv) {  /* buffers received */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* buffers received */
         while (adsl_sdhc1_w1->adsc_gather_i_1_i) {  /* gather with data */
           if (adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur < adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_end) {
             break;
           }
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_sdhc1_w1->adsc_gather_i_1_i->adsc_next;  /* remove gather */
         }
         if (adsl_sdhc1_w1->adsc_gather_i_1_i) {  /* data found to pass */
           ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_gai1_pass  /* data passed to calling program */
             = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set data found    */
           adsp_awc1->achc_data_recv        /* address data received   */
             = adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur;
           adsp_awc1->imc_len_data_recv     /* length data received    */
             = adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_end - adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur;
           break;
         }
         ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_w1->adsc_next;  /* remove from chain buffers received */
         m_proc_free( adsl_sdhc1_w1 );      /* free memory again       */
       }
       adsp_awc1->boc_connected = ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect;  /* did connect */
       if (   (ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect)  /* did connect */
           && (ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error)) {  /* connect error */
         adsp_awc1->imc_connect_error = ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error;  /* connect error */
         adsp_awc1->boc_connected = FALSE;  /* is not connected        */
       }
       if (   (ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect)  /* did connect */
           && (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_gai1_pass == NULL)) {  /* no data passed to calling program */
         adsp_awc1->boc_internal_act = FALSE;  /* internal WebSocket component not active */
         m_close_webso_conn( vpp_userfld );
       }
       adsp_awc1->iec_rwc = ied_rwc_ok;     /* processing o.k.         */
       return TRUE;
     case ied_cwc_conn:                     /* connect to target       */
       if (ADSL_CONN1_G->adsc_int_webso_conn_1->iec_twc == ied_twc_static) {  /* static, server configured */
         ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = FALSE;  /* did connect */
         ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error = 0;  /* connect error */
         ADSL_CONN1_G->adsc_int_webso_conn_1->boc_connect_active = TRUE;  /* connect active now */
#ifndef HL_UNIX
         ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
         ADSL_CONN1_G->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
         adsp_awc1->iec_rwc = ied_rwc_ok;   /* processing o.k.         */
         return TRUE;
       }
       if (ADSL_CONN1_G->adsc_int_webso_conn_1->iec_twc == ied_twc_pttd) {  /* pass thru to desktop - DOD desktop-on-demand */
#ifdef B130429
         iml1 = m_len_vx_ucs( ied_chs_ascii_850, &adsp_awc1->dsc_ucs_target );  /* length INETA DNS / IPV4 / IPV6 */
         if (iml1 <= 0) {
// to-do 30.01.12 KB error message
         }
#endif
         iml1 = m_len_vx_ucs( ied_chs_idna_1, &adsp_awc1->dsc_ucs_target );  /* length INETA DNS / IPV4 / IPV6 */
         if (iml1 <= 0) {
           m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_aux_webso_conn() l%05d could not copy dsc_ucs_target",
                           ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                           __LINE__ );
           adsp_awc1->iec_rwc = ied_rwc_inv_param;  /* invalid parameters in call */
           return TRUE;
         }
         adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr) + iml1 + 1 );
         memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
         adsl_cpttdt->adsc_conn1 = ADSL_CONN1_G;  /* for this connection */
         adsl_cpttdt->imc_len_target_bytes = iml1;
         adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
#ifdef B130429
         m_cpy_vx_ucs( adsl_cpttdt + 1, iml1, ied_chs_ascii_850,
                       &adsp_awc1->dsc_ucs_target );  /* INETA DNS / IPV4 / IPV6 */
#endif
         m_cpy_vx_ucs( adsl_cpttdt + 1, iml1, ied_chs_idna_1,
                       &adsp_awc1->dsc_ucs_target );  /* INETA DNS / IPV4 / IPV6 */
         *((char *) (adsl_cpttdt + 1) + iml1) = 0;  /* make zero-terminated */
         adsl_cpttdt->imc_port_target = adsp_awc1->imc_port;
#ifdef NOT_YET_120130
         adsl_cpttdt->umc_out_ineta = adsp_awc1->umc_out_ineta;
#endif
         adsl_cpttdt->umc_out_ineta
           = *((UNSIG_MED *) &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.dsc_soai4.sin_addr);
         adsl_cpttdt->boc_with_macaddr = adsp_awc1->boc_with_macaddr;
         memcpy( adsl_cpttdt->chrc_macaddr, adsp_awc1->chrc_macaddr, sizeof(adsl_cpttdt->chrc_macaddr) );
         adsl_cpttdt->imc_waitconn = adsp_awc1->imc_waitconn;
         ADSL_CONN1_G->adsc_cpttdt = adsl_cpttdt;  /* connect active now */
         m_pd_auth_start_pttd( (struct dsd_pd_work *) ((char *) ADSL_AUX_CF1 - offsetof( struct dsd_pd_work , dsc_aux_cf1 )),
                               adsl_cpttdt );
         adsp_awc1->iec_rwc = ied_rwc_ok;   /* processing o.k.         */
         return TRUE;
       }
       adsp_awc1->iec_rwc = ied_rwc_inv_param;  /* invalid parameters in call */
       return TRUE;
     case ied_cwc_lbvdi_send:               /* send data WTS load-balancing or VDI */
       /* start load-balancing                                         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_lbal;  /* status do load-balancing */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
#endif
       if (   (ADSL_CONN1_G->adsc_lbal_gw_1 == NULL)  /* no load balancing yet */
           && (ADSL_CONN1_G->adsc_wtsudp1 == NULL)) {  /* no WTS UDP   */
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
         m_hlnew_printf( HLOG_TRACE1, "m_aux_webso_conn() new - l%05d ADSL_CONN1_G=%p ADSL_CONN1_G->adsc_wtsudp1=%p ADSL_CONN1_G->adsc_lbal_gw_1=%p.",
                         __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_wtsudp1, ADSL_CONN1_G->adsc_lbal_gw_1 );
#endif
#ifdef B140128
         /* area for UDP processing                                    */
         ADSL_CONN1_G->adsc_wtsudp1 = (struct dsd_wts_udp_1 *) malloc( sizeof(struct dsd_wts_udp_1) );
         memset( ADSL_CONN1_G->adsc_wtsudp1, 0, sizeof(struct dsd_wts_udp_1) );
#endif
#ifdef DEBUG_150509_01                      /* problem memory-leak webso_conn */
         m_hlnew_printf( HLOG_TRACE1, "l%05d m_aux_webso_conn() ->inc_wts_time1=%d ->inc_wts_time2=%d.",
                         __LINE__,
                         ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time1,
                         ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time2 );
#endif
         m_lbal_udp_start( ADSL_CONN1_G );
         /* class load balancing GW                                    */
         ADSL_CONN1_G->adsc_lbal_gw_1 = new dsd_lbal_gw_1( ADSL_CONN1_G,
             ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time1,
             ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time2,
             ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1,
             ADSL_CONN1_G->adsc_server_conf_1->boc_is_blade_server );
       }
       adsl_sdhc1_lbal_send = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* load-balancing send to client */
#ifndef B170329
       if (ADSL_CONN1_G->adsc_lbal_gw_1->ac_free_mem) {  /* free memory */
         m_proc_free( ADSL_CONN1_G->adsc_lbal_gw_1->ac_free_mem );  /* free memory */
       }
       ADSL_CONN1_G->adsc_lbal_gw_1->ac_free_mem = adsl_sdhc1_lbal_send;  /* free memory */
#endif
       iml1 = 0;                            /* nothing to send yet     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_cl_recv( adsp_awc1->achc_lbvdi_send,  /* address data send WTS load-balancing or VDI */
           adsp_awc1->imc_len_lbvdi_send,   /* length data send WTS load-balancing or VDI */
           (char *) adsl_sdhc1_lbal_send
                      + sizeof(struct dsd_sdh_control_1)
                      + sizeof(struct dsd_gather_i_1),
           LEN_TCP_RECV
             - sizeof(struct dsd_sdh_control_1)
             - sizeof(struct dsd_gather_i_1),
           &achl1, &iml1 );
       adsp_awc1->iec_rwc = ied_rwc_ok;     /* processing o.k.         */
       return TRUE;
     case ied_cwc_close:                    /* close connection to internal routine */
       adsp_awc1->boc_internal_act = FALSE;  /* internal WebSocket component not active */
       m_close_webso_conn( vpp_userfld );
       adsp_awc1->iec_rwc = ied_rwc_ok;     /* processing o.k.         */
       return TRUE;
   }
   adsp_awc1->iec_rwc = ied_rwc_inv_param;  /* invalid parameters in call */
   return TRUE;

#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_aux_webso_conn()                                            */

/** close connection for WebSocket applications                        */
static void m_close_webso_conn( void *vpp_userfld ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

#ifdef DEBUG_150509_01                      /* problem memory-leak webso_conn */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_close_webso_conn() p_cont_00: ADSL_CONN1_G->adsc_int_webso_conn_1=%p ->adsc_sdhc1_recv=%p.",
                   __LINE__, ADSL_CONN1_G->adsc_int_webso_conn_1, ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv );
#endif
   while (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv) {  /* buffers received */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* buffers received */
     ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_w1->adsc_next;  /* remove from chain buffers received */
     m_proc_free( adsl_sdhc1_w1 );          /* free memory again       */
   }
   free( ADSL_CONN1_G->adsc_int_webso_conn_1 );
   ADSL_CONN1_G->adsc_int_webso_conn_1 = NULL;

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1

} /* end m_close_webso_conn()                                          */

#ifdef HL_UNIX
#ifndef B160423
#define LEN_EXT_RANDOM_G_REQUEST_RANDOM  8
/** get secure seed from external random generator                     */
static BOOL m_get_secure_seed( void *vpp_userfld, void * apparam, int imp_length ) {
   BOOL       bol_ret;                      /* return code             */
   int        iml1, iml2;                   /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_unix_socket;              /* Unix socket             */
   int        iml_pos_input;                /* position input          */
   int        iml_timeout;                  /* timeout for poll()      */
   HL_LONGLONG ill_endtime;                 /* end time for request    */
   HL_LONGLONG ill_epoch_cur;               /* Epoch in milliseconds   */
   struct sockaddr_un dsl_unix_socket_server;  /* address of domain socket */
   struct pollfd dsrl_poll[ 1 ];            /* for poll()              */
   char       byrl_work1[ 4096 ];           /* work area               */

#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (vpp_userfld) {                       /* called from connection  */
     ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
   }
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_get_secure_seed( %p , %p , %d ) called ADSL_CONN1_G=%p.",
                   __LINE__, vpp_userfld, apparam, imp_length, ADSL_CONN1_G );
#endif
#ifdef XYZ1
#ifdef TRACEHL1
   m_hl1_printf( "nbt-random-generator-client-01-l%05d-T UDSNAME \"%s\"",
                 __LINE__, achl_domain_socket );
#endif
#endif
   if (vpp_userfld) {                       /* called from connection  */
     m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   }
   bol_ret = FALSE;                         /* return code             */
   ill_endtime = m_get_epoch_ms()           /* end-time in milli-seconds */
                   + dss_loconf_1.imc_ext_random_g_timeout_ms;  /* timeout external Random Generator */
   iml_unix_socket = socket( AF_LOCAL, SOCK_STREAM, 0 );
   if (iml_unix_socket < 0) {               /* error occured           */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM330W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d socket( AF_LOCAL ... ) returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_unix_socket, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM310W m_get_secure_seed() l%05d socket( AF_LOCAL ... ) returned %d %d.",
                       __LINE__, iml_unix_socket, errno );
     }
     goto p_ret_00;                         /* return                  */
   }
   memset( &dsl_unix_socket_server, 0, sizeof(struct sockaddr_un) );
   dsl_unix_socket_server.sun_family = AF_LOCAL;
   iml1 = strlen( dss_loconf_1.achc_ext_random_g_domain_socket_name );  /* external Random Generator */
   if (iml1 >= sizeof(dsl_unix_socket_server.sun_path)) {
     iml1 = sizeof(dsl_unix_socket_server.sun_path) - 1;
   }
   memcpy( dsl_unix_socket_server.sun_path,
           dss_loconf_1.achc_ext_random_g_domain_socket_name,  /* external Random Generator */
           iml1 );
   *(dsl_unix_socket_server.sun_path + iml1) = 0;  /* make zero-terminated */

   /* set to non-blocking I/O                                          */
   iml1 = fcntl( iml_unix_socket, F_GETFL, 0 );
   fcntl( iml_unix_socket, F_SETFL, iml1 | O_NONBLOCK );

   dsrl_poll[ 0 ].fd = iml_unix_socket;
   dsrl_poll[ 0 ].events = POLLIN;
   dsrl_poll[ 0 ].revents = 0;

   iml_rc = connect( iml_unix_socket,
                     (struct sockaddr *) &dsl_unix_socket_server,
                     sizeof(struct sockaddr_un) );
   if (iml_rc < 0) {                        /* error occured           */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM331W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d connect Unix socket domain name \"%s\" returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, dsl_unix_socket_server.sun_path, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM311W m_get_secure_seed() l%05d connect Unix socket domain name \"%s\" returned %d %d.",
                       __LINE__, dsl_unix_socket_server.sun_path, iml_rc, errno );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbt-random-generator-client-01-l%05d-T connect Unix socket succeeded",
                 __LINE__ );
#endif
   iml_rc = write( iml_unix_socket, chrs_ext_random_g_eyecatcher, sizeof(chrs_ext_random_g_eyecatcher) );
   if (iml_rc != sizeof(chrs_ext_random_g_eyecatcher)) {  /* error occured           */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM332W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS write() eyecatcher returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM312W m_get_secure_seed() l%05d UDS write() eyecatcher returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbt-random-generator-client-01-l%05d-T write() eyecatcher succeeded",
                 __LINE__ );
#endif
   iml_pos_input = 0;                       /* position input          */
   iml1 = iml2 = 0;                         /* clear position and state */

   p_read_00:                               /* read response to eyecatcher */
   ill_epoch_cur = m_get_epoch_ms();        /* Epoch in milliseconds   */
   iml_timeout = ill_endtime - ill_epoch_cur;  /* timeout for poll()   */
   if (iml_timeout <= 0) {                  /* function takes too long */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM333W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() eyecatcher timeout",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__ );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM313W m_get_secure_seed() l%05d UDS recv() eyecatcher timeout",
                       __LINE__ );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
   iml_rc = poll( dsrl_poll, 1, iml_timeout );
   if (iml_rc < 0) {                        /* was error               */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM334W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS poll() receive eyecatcher returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM314W m_get_secure_seed() l%05d UDS poll() receive eyecatcher returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T poll() returned %d.",
                   __LINE__, iml_rc );
#endif
   if ((dsrl_poll[ 0 ].revents & POLLIN) == 0) {  /* event not set     */
     goto p_read_00;                        /* read response to eyecatcher */
   }

   iml_rc = recv( iml_unix_socket,
                  byrl_work1 + iml_pos_input,
                  sizeof(byrl_work1) - iml_pos_input,
                  0 );
   if (iml_rc <= 0) {                       /* error or end            */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM335W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() eyecatcher returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM315W m_get_secure_seed() l%05d UDS recv() eyecatcher returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
#ifdef TRACEHL1
   m_console_out( byrl_work1 + iml_pos_input, iml_rc );
#endif

   iml_pos_input += iml_rc;                 /* position end read       */

   do {                                     /* loop to recognize CR LF */
     switch (*(byrl_work1 + iml1)) {        /* input character         */
       case CHAR_CR:                        /* carriage-return found   */
         iml2 = 1;                          /* set state CR            */
         break;
       case CHAR_LF:                        /* line-feed found         */
         if (iml2 != 0) goto p_read_04;
         break;
       default:
         iml2 = 0;                          /* state any character     */
         break;
     }
     iml1++;                                /* next character          */
   } while (iml1 < iml_pos_input);
   if (iml_pos_input < sizeof(byrl_work1)) {  /* buffer not full       */
     goto p_read_00;                        /* read next part response to eyecatcher */
   }
   if (vpp_userfld) {                       /* called from connection  */
     m_hlnew_printf( HLOG_WARN1, "HWSPM336W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() complete buffer eyecatcher length %d - not found <CR><LF>",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     __LINE__, sizeof(byrl_work1) );
   } else {
     m_hlnew_printf( HLOG_WARN1, "HWSPM316W m_get_secure_seed() l%05d UDS recv() complete buffer eyecatcher length %d - not found <CR><LF>",
                     __LINE__, sizeof(byrl_work1) );
   }
   goto p_close_00;                         /* close UDS socket        */

   p_read_04:                               /* read till CR LF         */
   iml1++;                                  /* after LF                */
   if (iml1 != iml_pos_input) {             /* not at end              */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM337W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() invalid character after eyecatcher pos %d end %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml1, iml_pos_input );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM317W m_get_secure_seed() l%05d UDS recv() invalid character after eyecatcher pos %d end %d.",
                       __LINE__, iml1, iml_pos_input );
     }
     goto p_close_00;                       /* close UDS socket        */
   }

#ifdef TRACEHL1
   m_hl1_printf( "nbt-random-generator-server-01-l%05d-I response from server \"%.*s\"",
                 __LINE__, iml1 - 2, byrl_work1 );
#endif

   /* send request for random                                          */
   memcpy( byrl_work1, "RANDOM", 6 );
   byrl_work1[ 6 ] = (unsigned char) (imp_length >> 8);
   byrl_work1[ 7 ] = (unsigned char) imp_length;
   iml_rc = write( iml_unix_socket, byrl_work1, LEN_EXT_RANDOM_G_REQUEST_RANDOM );
   if (iml_rc != LEN_EXT_RANDOM_G_REQUEST_RANDOM) {  /* error occured  */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM338W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS write() request random returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM318W m_get_secure_seed() l%05d UDS write() request random returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nbt-random-generator-client-01-l%05d-T write() request random succeeded",
                 __LINE__ );
#endif
   iml_pos_input = 0;                       /* position input          */

   p_read_40:                               /* read response to random request */
// 29.06.16 KB - poll()
   ill_epoch_cur = m_get_epoch_ms();        /* Epoch in milliseconds   */
   iml_timeout = ill_endtime - ill_epoch_cur;  /* timeout for poll()   */
   if (iml_timeout <= 0) {                  /* function takes too long */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM339W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() random timeout",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__ );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM319W m_get_secure_seed() l%05d UDS recv() random timeout",
                       __LINE__ );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
   iml_rc = poll( dsrl_poll, 1, iml_timeout );
   if (iml_rc < 0) {                        /* was error               */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM340W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS poll() receive random returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM320W m_get_secure_seed() l%05d UDS poll() receive random returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T poll() returned %d.",
                   __LINE__, iml_rc );
#endif
   if ((dsrl_poll[ 0 ].revents & POLLIN) == 0) {  /* event not set     */
     goto p_read_40;                        /* read response to random request */
   }

   iml_rc = recv( iml_unix_socket,
                  (char *) apparam + iml_pos_input,
                  imp_length - iml_pos_input,
                  0 );
   if (iml_rc <= 0) {                       /* error or end            */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM341W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS recv() random returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM321W m_get_secure_seed() l%05d UDS recv() random returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
     goto p_close_00;                       /* close UDS socket        */
   }
   iml_pos_input += iml_rc;                 /* position input          */
   if (iml_pos_input < imp_length) {        /* not complete received   */
     goto p_read_40;                        /* read response to random request */
   }
#ifdef TRACEHL1
   m_console_out( (char *) apparam, imp_length );
#endif
   bol_ret = TRUE;                          /* return code             */

   p_close_00:                              /* close UDS socket        */
   iml_rc = close( iml_unix_socket );
   if (   (iml_rc != 0)                     /* error occured           */
       && (bol_ret)) {                      /* no error before         */
     if (vpp_userfld) {                     /* called from connection  */
       m_hlnew_printf( HLOG_WARN1, "HWSPM342W GATE=%(ux)s SNO=%08d INETA=%s m_get_secure_seed() l%05d UDS close() returned %d %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       __LINE__, iml_rc, errno );
     } else {
       m_hlnew_printf( HLOG_WARN1, "HWSPM322W m_get_secure_seed() l%05d UDS close() returned %d %d.",
                       __LINE__, iml_rc, errno );
     }
   }

   p_ret_00:                                /* return                  */
   if (vpp_userfld) {                       /* called from connection  */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   return bol_ret;                          /* all done                */

#ifndef HELP_DEBUG
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
#endif
} /* end m_get_secure_seed()                                           */
#endif
#endif

/** manage aux-pipe for communication between different components     */
static BOOL m_aux_pipe_manage( void *vpp_userfld, struct dsd_aux_pipe_req_1 *adsp_apr1 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl_in_cur;                 /* current input           */
   char       *achl_out_cur, *achl_out_end;  /* output pointers        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_ap_listen;  /* auxiliary ext field aux-pipe listen */
   struct dsd_auxf_1 *adsl_auxf_1_apc_this;  /* address aux-pipe connection control structure of this side */
   struct dsd_auxf_1 *adsl_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   struct dsd_auxf_1 *adsl_auxf_1_last;     /* last entry in chain     */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* working variable        */
   DSD_CONN_G *adsl_conn1_partner;          /* connection of partner   */
   struct dsd_aux_pipe_read_buffer *adsl_aprb_first;  /* aux-pipe read buffer */
   struct dsd_aux_pipe_read_buffer *adsl_aprb_last;  /* aux-pipe read buffer */
   struct dsd_aux_pipe_read_buffer *adsl_aprb_w1;  /* aux-pipe read buffer */
   char       *achl_avl_error;              /* error code AVL tree     */
   union {
     struct dsd_aux_pipe_listen dsl_ap_listen;  /* aux-pipe listen control structure */
     struct dsd_aux_pipe_conn dsl_ap_conn;  /* aux-pipe connection control structure */
   };
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   switch (adsp_apr1->iec_apc) {            /* aux-pipe command        */
     case ied_apc_create:                   /* create, server side open */
       goto p_ap_create_00;                 /* listen for aux-pipe     */
     case ied_apc_open:                     /* open, client side open  */
       goto p_ap_open_00;                   /* open connection aux-pipe */
     case ied_apc_close_listen:             /* close listen, created by create */
       goto p_ap_close_listen_00;           /* close listen            */
     case ied_apc_close_conn:               /* close single connection */
       goto p_ap_close_conn_00;             /* close connection        */
     case ied_apc_close_all:                /* close all               */
       goto p_ap_close_all_00;              /* close all               */
     case ied_apc_state:                    /* check state session     */
       goto p_ap_state_00;                  /* check state session     */
     case ied_apc_free_read_buffer:         /* free passed read buffers */
       goto p_ap_frb_00;                    /* free passed read buffers */
     case ied_apc_write:                    /* write to session        */
       goto p_ap_write_00;                  /* write to session        */
   }
   adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
   return TRUE;

   p_ap_create_00:                          /* listen for aux-pipe     */
   if (adsp_apr1->imc_len_aux_pipe_name <= 0) {  /* length of name of aux-pipe */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (   (adsp_apr1->iec_aps != ied_aps_session)  /* for current session */
       && (adsp_apr1->iec_aps != ied_aps_process)) {  /* for current process */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (adsp_apr1->imc_signal == 0) {        /* signal to set           */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (adsp_apr1->iec_aps != ied_aps_session) {  /* for current session */
     goto p_ap_create_20;                   /* create new aux-pipe listen */
   }
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain           */
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     if (   (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_pipe_listen)  /* aux-pipe create with name */
         && (ADSL_APL_G->iec_aps == ied_aps_process)  /* for current process */
         && (ADSL_APL_G->imc_len_aux_pipe_name == adsp_apr1->imc_len_aux_pipe_name)  /* length of name of aux-pipe */
         && (!memcmp( ADSL_APL_G + 1,
                      adsp_apr1->achc_aux_pipe_name,   /* address name of aux-pipe */
                      adsp_apr1->imc_len_aux_pipe_name ))) {  /* length of name of aux-pipe */
       adsp_apr1->iec_aprc = ied_aprc_listen_double;  /* aux-pipe-name already defined */
       return TRUE;                         /* all done                */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
#undef ADSL_APL_G

   p_ap_create_20:                          /* create new aux-pipe listen */
   /* auxiliary ext field aux-pipe listen                              */
   adsl_auxf_1_ap_listen = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                           + sizeof(struct dsd_auxf_ext_1)  /* definition auxiliary field extension */
                                                           + sizeof(struct dsd_aux_pipe_listen)  /* aux-pipe listen control structure */
                                                           + adsp_apr1->imc_len_aux_pipe_name );  /* length of name of aux-pipe */
#ifndef NOT_YET_131017
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_ap_listen + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   m_hlnew_printf( HLOG_TRACE1, "m_aux_pipe_manage() l%05d adsl_auxf_1_ap_listen=%p &ADSL_APL_G->dsc_sort_pipe=%p.",
                   __LINE__, adsl_auxf_1_ap_listen, &ADSL_APL_G->dsc_sort_pipe );
#undef ADSL_APL_G
#endif
   memset( adsl_auxf_1_ap_listen, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1) + sizeof(struct dsd_aux_pipe_listen) );
   memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_ap_listen + 1))->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
   memcpy( &adsl_auxf_1_ap_listen->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_ap_listen + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   ADSL_APL_G->achc_aux_pipe_name = (char *) (ADSL_APL_G + 1);  /* address name of aux-pipe */
   memcpy( ADSL_APL_G + 1,
           adsp_apr1->achc_aux_pipe_name,   /* address name of aux-pipe */
           adsp_apr1->imc_len_aux_pipe_name );  /* length of name of aux-pipe */
   ADSL_APL_G->imc_len_aux_pipe_name = adsp_apr1->imc_len_aux_pipe_name;  /* length of name of aux-pipe */
   ADSL_APL_G->iec_aps = adsp_apr1->iec_aps;
   ADSL_APL_G->ac_conn1 = ADSL_CONN1_G;     /* for this connection     */
   ADSL_APL_G->imc_signal = adsp_apr1->imc_signal;  /* signal to set   */
   if (adsp_apr1->iec_aps == ied_aps_session) {  /* for current session */
     goto p_ap_create_40;                   /* continue start listen   */
   }

   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_aux.m_enter();              /* critical section        */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                                 &dsl_htree1_work, &ADSL_APL_G->dsc_sort_pipe );
   if (bol_rc == FALSE) {                   /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   }
   if (   (dsl_htree1_work.adsc_found == NULL)  /* not found in tree   */
       && (achl_avl_error == NULL)) {       /* no error before         */
     bol_rc = m_htree1_avl_insert( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                                   &dsl_htree1_work, &ADSL_APL_G->dsc_sort_pipe );
     if (bol_rc == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_insert() failed";  /* error code AVL tree */
     }
   }
   dss_critsect_aux.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* error code AVL tree     */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s aux-pipe AVL-tree error %s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     achl_avl_error );
     free( adsl_auxf_1_ap_listen );
     adsp_apr1->iec_aprc = ied_aprc_misc;   /* miscellaneous error     */
     return TRUE;                           /* all done                */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     free( adsl_auxf_1_ap_listen );
     adsp_apr1->iec_aprc = ied_aprc_listen_double;  /* aux-pipe-name already defined */
     return TRUE;                           /* all done                */
   }
#ifdef XYZ1
   ied_aprc_ok,                             /* command returns o.k.    */
   ied_aprc_listen_double,                  /* aux-pipe-name already defined */
   ied_aprc_listen_undef,                   /* aux-pipe-name not defined */
// to-do 14.04.13 KB
   ied_aprc_misc                            /* miscellaneous error     */
#endif
#undef ADSL_APL_G

   p_ap_create_40:                          /* continue start listen   */
   adsl_auxf_1_ap_listen->iec_auxf_def = ied_auxf_pipe_listen;  /* aux-pipe create with name */
   adsl_auxf_1_ap_listen->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ap_listen;  /* set new chain */
   adsp_apr1->vpc_aux_pipe_handle = adsl_auxf_1_ap_listen;  /* handle of aux-pipe */
   adsp_apr1->iec_aprc = ied_aprc_ok;       /* command returns o.k.    */
   return TRUE;                             /* all done                */

   p_ap_open_00:                            /* open connection aux-pipe */
   if (adsp_apr1->imc_len_aux_pipe_name <= 0) {  /* length of name of aux-pipe */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (adsp_apr1->imc_signal == 0) {        /* signal to set           */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (adsp_apr1->iec_aps != ied_aps_session) {  /* for current session */
     goto p_ap_open_20;                     /* ready to open connection aux-pipe */
   }
   adsl_auxf_1_ap_listen = ADSL_CONN1_G->adsc_auxf_1;  /* get chain    */
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_ap_listen + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   while (adsl_auxf_1_ap_listen) {          /* loop over all entries   */
     if (   (adsl_auxf_1_ap_listen->iec_auxf_def == ied_auxf_pipe_listen)  /* aux-pipe create with name */
         && (ADSL_APL_G->iec_aps == ied_aps_process)  /* for current process */
         && (ADSL_APL_G->imc_len_aux_pipe_name == adsp_apr1->imc_len_aux_pipe_name)  /* length of name of aux-pipe */
         && (!memcmp( ADSL_APL_G + 1,
                      adsp_apr1->achc_aux_pipe_name,  /* address name of aux-pipe */
                      adsp_apr1->imc_len_aux_pipe_name ))) {  /* length of name of aux-pipe */
       goto p_ap_open_20;                   /* ready to open connection aux-pipe */
     }
     adsl_auxf_1_ap_listen = adsl_auxf_1_ap_listen->adsc_next;  /* get next in chain */
   }
   adsp_apr1->iec_aprc = ied_aprc_listen_undef;  /* aux-pipe-name not defined */
   return TRUE;                             /* all done                */

#undef ADSL_APL_G

   p_ap_open_20:                            /* ready to open connection aux-pipe */
   adsl_auxf_1_apc_this                     /* address aux-pipe connection control structure of this side */
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_ext_1)  /* definition auxiliary field extension */
                                       + sizeof(struct dsd_aux_pipe_conn) );  /* aux-pipe connection control structure */
   memset( adsl_auxf_1_apc_this, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1)+ sizeof(struct dsd_aux_pipe_conn) );
   adsl_auxf_1_apc_this->iec_auxf_def = ied_auxf_pipe_conn;  /* aux-pipe established connection */
   memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_apc_this + 1))->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
   memcpy( &adsl_auxf_1_apc_this->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* current Server-Data-Hook */
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   ADSL_APC_THIS_G->ac_conn1 = ADSL_CONN1_G;  /* for this connection   */
   ADSL_APC_THIS_G->imc_signal = adsp_apr1->imc_signal;  /* signal to set */
   adsl_auxf_1_apc_partner                  /* address aux-pipe connection control structure of partner */
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_ext_1)  /* definition auxiliary field extension */
                                       + sizeof(struct dsd_aux_pipe_conn) );  /* aux-pipe connection control structure */
   memset( adsl_auxf_1_apc_partner, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1)+ sizeof(struct dsd_aux_pipe_conn) );
   adsl_auxf_1_apc_partner->iec_auxf_def = ied_auxf_pipe_conn;  /* aux-pipe established connection */
   adsl_auxf_1_apc_partner->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* current Server-Data-Hook */
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   ADSL_APC_THIS_G->adsc_auxf_1_apc_partner = adsl_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   ADSL_APC_PARTNER_G->adsc_auxf_1_apc_partner = adsl_auxf_1_apc_this;  /* address aux-pipe connection control structure of partner */
   memset( &dsl_ap_listen, 0, sizeof(struct dsd_aux_pipe_listen) );  /* aux-pipe listen control structure */
   dsl_ap_listen.achc_aux_pipe_name = adsp_apr1->achc_aux_pipe_name;  /* address name of aux-pipe */
   dsl_ap_listen.imc_len_aux_pipe_name = adsp_apr1->imc_len_aux_pipe_name;  /* length of name of aux-pipe */
   if (adsp_apr1->iec_aps != ied_aps_session) {  /* for current session */
     goto p_ap_open_40;                     /* search not for current session, search AVL tree */
   }

#define ADSL_APL_PARTNER ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_ap_listen + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_apc_partner + 1))->dsc_cid,
           &((struct dsd_auxf_ext_1 *) ((char *) ADSL_APL_PARTNER - sizeof(struct dsd_auxf_ext_1)))->dsc_cid,
           sizeof(struct dsd_cid) );        /* current Server-Data-Hook */
   memcpy( &adsl_auxf_1_apc_partner->dsc_cid,
           &adsl_auxf_1_ap_listen->dsc_cid,
           sizeof(struct dsd_cid) );        /* current Server-Data-Hook */
   if (ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn == NULL) {  /* chain aux-pipe connection control structures new connections */
     ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn = adsl_auxf_1_apc_partner;  /* set new chain aux-pipe connection control structures new connections */
   } else {
     adsl_auxf_1_w1 = ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn;  /* get old chain aux-pipe connection control structures new connections */
     while (adsl_auxf_1_w1->adsc_next) adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
     adsl_auxf_1_w1->adsc_next = adsl_auxf_1_apc_partner;  /* append to chain */
   }
   ((struct dsd_auxf_ext_1 *) ((char *) ADSL_APL_PARTNER - sizeof(struct dsd_auxf_ext_1)))->imc_signal
     = ADSL_APL_PARTNER->imc_signal;
   ADSL_APC_PARTNER_G->imc_signal = ADSL_APL_PARTNER->imc_signal;
   adsl_conn1_partner = (DSD_CONN_G *) ADSL_APL_PARTNER->ac_conn1;  /* connection of partner */
   ADSL_APC_PARTNER_G->ac_conn1 = adsl_conn1_partner;  /* for this connection */
   adsl_conn1_partner->boc_signal_set = TRUE;  /* signal for component set */
   goto p_ap_open_80;                       /* last part open connection */

#undef ADSL_APL_PARTNER

   p_ap_open_40:                            /* search not for current session, search AVL tree */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_aux.m_enter();              /* critical section        */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                                 &dsl_htree1_work, &dsl_ap_listen.dsc_sort_pipe );
   if (bol_rc == FALSE) {                   /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   } else if (dsl_htree1_work.adsc_found) {  /* found in tree          */
#ifdef B131017
#define ADSL_APL_PARTNER ((struct dsd_aux_pipe_listen *) (dsl_htree1_work.adsc_found - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))  /* aux-pipe listen control structure */
#endif
#define ADSL_APL_PARTNER ((struct dsd_aux_pipe_listen *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))  /* aux-pipe listen control structure */
     memcpy( &((struct dsd_auxf_ext_1 *) (adsl_auxf_1_apc_partner + 1))->dsc_cid,
             &((struct dsd_auxf_ext_1 *) ((char *) ADSL_APL_PARTNER - sizeof(struct dsd_auxf_ext_1)))->dsc_cid,
             sizeof(struct dsd_cid) );      /* current Server-Data-Hook */
#ifdef B131017
#define ADSL_AF1_APL_PARTNER ((struct dsd_auxf_1 *) (dsl_htree1_work.adsc_found - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe ) - sizeof(struct dsd_auxf_ext_1) - sizeof(struct dsd_auxf_1)))  /* aux-pipe listen control structure */
#endif
#define ADSL_AF1_APL_PARTNER ((struct dsd_auxf_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe ) - sizeof(struct dsd_auxf_ext_1) - sizeof(struct dsd_auxf_1)))  /* aux-pipe listen control structure */
#ifndef NOT_YET_131017
     m_hlnew_printf( HLOG_TRACE1, "m_aux_pipe_manage() l%05d dsl_htree1_work.adsc_found=%p ADSL_AF1_APL_PARTNER=%p.",
                     __LINE__, dsl_htree1_work.adsc_found, ADSL_AF1_APL_PARTNER );
     m_hlnew_printf( HLOG_TRACE1, "m_aux_pipe_manage() l%05d offsetof=0X%X sizeof(struct dsd_auxf_ext_1)=0X%X sizeof(struct dsd_auxf_1)=0X%0X.",
                     __LINE__,
                     offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe ),
                     sizeof(struct dsd_auxf_ext_1),
                     sizeof(struct dsd_auxf_1) );
#endif
     memcpy( &adsl_auxf_1_apc_partner->dsc_cid,
             &ADSL_AF1_APL_PARTNER->dsc_cid,
             sizeof(struct dsd_cid) );      /* current Server-Data-Hook */
#undef ADSL_AF1_APL_PARTNER
     if (ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn == NULL) {  /* chain aux-pipe connection control structures new connections */
       ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn = adsl_auxf_1_apc_partner;  /* set new chain aux-pipe connection control structures new connections */
     } else {
       adsl_auxf_1_w1 = ADSL_APL_PARTNER->adsc_auxf_1_apc_ch_new_conn;  /* get old chain aux-pipe connection control structures new connections */
       while (adsl_auxf_1_w1->adsc_next) adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
       adsl_auxf_1_w1->adsc_next = adsl_auxf_1_apc_partner;  /* append to chain */
     }
     ((struct dsd_auxf_ext_1 *) ((char *) ADSL_APL_PARTNER - sizeof(struct dsd_auxf_ext_1)))->imc_signal
       = ADSL_APL_PARTNER->imc_signal;
     ADSL_APC_PARTNER_G->imc_signal = ADSL_APL_PARTNER->imc_signal;
     adsl_conn1_partner = (DSD_CONN_G *) ADSL_APL_PARTNER->ac_conn1;  /* connection of partner */
     ADSL_APC_PARTNER_G->ac_conn1 = adsl_conn1_partner;  /* for this connection */
     adsl_conn1_partner->boc_signal_set = TRUE;  /* signal for component set */
#undef ADSL_APL_PARTNER
   }
   dss_critsect_aux.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* error code AVL tree     */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s aux-pipe AVL-tree error %s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     achl_avl_error );
     free( adsl_auxf_1_apc_this );          /* address aux-pipe connection control structure of this side */
     free( adsl_auxf_1_apc_partner );       /* address aux-pipe connection control structure of partner */
     adsp_apr1->iec_aprc = ied_aprc_misc;   /* miscellaneous error     */
     return TRUE;                           /* all done                */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     free( adsl_auxf_1_apc_this );          /* address aux-pipe connection control structure of this side */
     free( adsl_auxf_1_apc_partner );       /* address aux-pipe connection control structure of partner */
     adsp_apr1->iec_aprc = ied_aprc_listen_undef;  /* aux-pipe-name not defined */
     return TRUE;                           /* all done                */
   }

   p_ap_open_80:                            /* last part open connection */
   adsl_auxf_1_apc_this->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_apc_this;  /* set new chain */
   adsp_apr1->vpc_aux_pipe_handle = adsl_auxf_1_apc_this;  /* handle of aux-pipe */
   adsp_apr1->imc_sno = adsl_conn1_partner->dsc_co_sort.imc_sno;  /* session number */
   adsp_apr1->iec_aprc = ied_aprc_ok;       /* command returns o.k.    */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_open_00: ADSL_CONN1_G=%p adsl_conn1_partner=%p.",
                   __LINE__, ADSL_CONN1_G, adsl_conn1_partner );
#endif
   if (adsl_conn1_partner == ADSL_CONN1_G) return TRUE;
#ifndef HL_UNIX
   m_act_conn( adsl_conn1_partner );        /* activate connection     */
#else
   m_act_thread_1( adsl_conn1_partner );    /* activate work-thread    */
#endif
   return TRUE;                             /* all done                */

#undef ADSL_APC_THIS_G
#undef ADSL_APC_PARTNER_G

   p_ap_close_listen_00:                    /* close listen            */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain           */
   adsl_auxf_1_last = NULL;                 /* no last element yet     */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     if (((void *) adsl_auxf_1_w1) == adsp_apr1->vpc_aux_pipe_handle) {
       if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_pipe_listen) {  /* aux-pipe create with name */
         adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
         return TRUE;                       /* all done                */
       }
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_last == NULL) {      /* at anchor of chain      */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
       } else {
         adsl_auxf_1_last->adsc_next = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       m_aux_pipe_listen_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
       free( adsl_auxf_1_w1 );              /* free memory             */
       adsp_apr1->iec_aprc = ied_aprc_ok;   /* command returns o.k.    */
       return TRUE;                         /* all done                */
     }
     adsl_auxf_1_last = adsl_auxf_1_w1;     /* set last element        */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
   return TRUE;                             /* all done                */

   p_ap_close_conn_00:                      /* close connection        */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain           */
   adsl_auxf_1_last = NULL;                 /* no last element yet     */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     if (((void *) adsl_auxf_1_w1) == adsp_apr1->vpc_aux_pipe_handle) {
       if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_pipe_conn) {  /* aux-pipe established connection */
         adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
         return TRUE;                       /* all done                */
       }
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_last == NULL) {      /* at anchor of chain      */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;
       } else {
         adsl_auxf_1_last->adsc_next = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       m_aux_pipe_conn_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
       free( adsl_auxf_1_w1 );              /* free memory             */
       adsp_apr1->iec_aprc = ied_aprc_ok;   /* command returns o.k.    */
       return TRUE;                         /* all done                */
     }
     adsl_auxf_1_last = adsl_auxf_1_w1;     /* set last element        */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
   return TRUE;                             /* all done                */

   p_ap_close_all_00:                       /* close all               */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain           */
   adsl_auxf_1_last = NULL;                 /* no last element yet     */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save entry              */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     switch (adsl_auxf_1_w2->iec_auxf_def) {  /* type of entry         */
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
         m_aux_pipe_listen_cleanup( ADSL_CONN1_G, adsl_auxf_1_w2 );
         free( adsl_auxf_1_w2 );            /* free entry              */
         break;
       case ied_auxf_pipe_conn:             /* aux-pipe established connection */
         m_aux_pipe_conn_cleanup( ADSL_CONN1_G, adsl_auxf_1_w2 );
         free( adsl_auxf_1_w2 );            /* free entry              */
         break;
       default:
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
         if (adsl_auxf_1_last == NULL) {    /* at anchor of chain      */
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w2;
         } else {
           adsl_auxf_1_last->adsc_next = adsl_auxf_1_w2;  /* append to last element */
         }
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
         adsl_auxf_1_last = adsl_auxf_1_w2;  /* set last element       */
         adsl_auxf_1_last->adsc_next = NULL;  /* set end of chain      */
     }
   }
   adsp_apr1->iec_aprc = ied_aprc_ok;       /* command returns o.k.    */
   return TRUE;                             /* all done                */

   p_ap_state_00:                           /* check state session     */
   if (adsp_apr1->vpc_aux_pipe_handle == NULL) {  /* handle of aux-pipe */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   adsl_auxf_1_apc_this = (struct dsd_auxf_1 *) adsp_apr1->vpc_aux_pipe_handle;  /* address aux-pipe connection control structure of this side */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_state_00: adsl_auxf_1_apc_this=%p ...->iec_auxf_def=%d.",
                   __LINE__, adsl_auxf_1_apc_this, adsl_auxf_1_apc_this->iec_auxf_def );
#endif
   if (adsl_auxf_1_apc_this->iec_auxf_def == ied_auxf_pipe_conn) {  /* aux-pipe established connection */
     goto p_ap_state_40;                    /* check state connection  */
   }
   if (adsl_auxf_1_apc_this->iec_auxf_def != ied_auxf_pipe_listen) {  /* aux-pipe create with name */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   adsp_apr1->vpc_aux_pipe_handle = NULL;   /* handle of aux-pipe      */
   adsp_apr1->adsc_gai1_data = NULL;        /* input and output data   */
   adsp_apr1->boc_session_active = FALSE;   /* session is active       */
   adsp_apr1->imc_sno = 0;                  /* session number          */
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
   if (ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn == NULL) {  /* chain aux-pipe connection control structures new connections */
     adsp_apr1->iec_aprc = ied_aprc_idle;   /* command returns nothing */
     return TRUE;                           /* all done                */
   }
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_auxf_1_w1 = ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn;  /* get old chain aux-pipe connection control structures new connections */
   ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn = adsl_auxf_1_w1->adsc_next;  /* remove from chain aux-pipe connection control structures new connections */
   dss_critsect_aux.m_leave();              /* critical section        */
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain       */
   adsp_apr1->vpc_aux_pipe_handle = adsl_auxf_1_w1;  /* handle of aux-pipe      */
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   adsl_auxf_1_apc_partner = ADSL_APC_THIS_G->adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   if (adsl_auxf_1_apc_partner) {           /* connection still active */
     adsl_conn1_partner = (DSD_CONN_G *) ADSL_APC_PARTNER_G->ac_conn1;  /* connection of partner */
     adsp_apr1->boc_session_active = TRUE;  /* session is active       */
     adsp_apr1->imc_sno = adsl_conn1_partner->dsc_co_sort.imc_sno;  /* session number */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_state_00: adsl_auxf_1_w1=%p adsl_auxf_1_apc_partner=%p partner-sno=%08d.",
                   __LINE__, adsl_auxf_1_w1, adsl_auxf_1_apc_partner, adsp_apr1->imc_sno );
#endif
   adsp_apr1->iec_aprc = ied_aprc_new_conn;  /* command returns new incomming connection */
   return TRUE;                             /* all done                */

#undef ADSL_APL_G
#undef ADSL_APC_THIS_G
#undef ADSL_APC_PARTNER_G

   p_ap_state_40:                           /* check state connection  */
   adsp_apr1->adsc_gai1_data = NULL;        /* input and output data   */
   adsp_apr1->boc_session_active = FALSE;   /* session is active       */
   adsp_apr1->imc_sno = 0;                  /* session number          */
   adsp_apr1->iec_aprc = ied_aprc_conn_ended;  /* connection has ended */
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_state_40: adsl_auxf_1_apc_this=%p &ADSL_APC_THIS_G->adsc_aprb_ch=%p cont=%p.",
                   __LINE__, adsl_auxf_1_apc_this, &ADSL_APC_THIS_G->adsc_aprb_ch, ADSL_APC_THIS_G->adsc_aprb_ch );
#endif
   adsl_aprb_w1 = ADSL_APC_THIS_G->adsc_aprb_ch;  /* get old chain of aux-pipe read buffers */
   while (   (adsl_aprb_w1)
          && (adsl_aprb_w1->boc_passed)) {  /* already passed to calling component */
     adsl_aprb_w1 = adsl_aprb_w1->adsc_next;
   }
   if (adsl_aprb_w1) {                      /* found data to pass to component */
     adsp_apr1->adsc_gai1_data              /* input and output data   */
       = adsl_gai1_w1
         = &adsl_aprb_w1->dsc_gai1_data;    /* gather data             */
     while (adsl_aprb_w1->adsc_next) {      /* more data follow        */
       adsl_aprb_w1->boc_passed = TRUE;     /* already passed to calling component */
       adsl_aprb_w1 = adsl_aprb_w1->adsc_next;
       adsl_gai1_w1->adsc_next = &adsl_aprb_w1->dsc_gai1_data;  /* gather data */
       adsl_gai1_w1 = &adsl_aprb_w1->dsc_gai1_data;  /* set last gather data in chain */
     }
     adsl_aprb_w1->boc_passed = TRUE;       /* already passed to calling component */
     adsp_apr1->iec_aprc = ied_aprc_read_buf;  /* command returns read buffers */
   }
   adsl_auxf_1_apc_partner = ADSL_APC_THIS_G->adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_state_40: adsl_auxf_1_apc_this=%p adsl_auxf_1_apc_partner=%p partner-sno=%08d.",
                   __LINE__, adsl_auxf_1_apc_this, adsl_auxf_1_apc_partner, adsp_apr1->imc_sno );
#endif
   if (adsl_auxf_1_apc_partner == NULL) {   /* no more connected to partner */
     return TRUE;                           /* all done                */
   }
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   adsl_conn1_partner = (DSD_CONN_G *) ADSL_APC_PARTNER_G->ac_conn1;  /* connection of partner */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_state_40: adsl_auxf_1_apc_this=%p adsl_auxf_1_apc_partner=%p partner-sno=%08d.",
                   __LINE__, adsl_auxf_1_apc_this, adsl_auxf_1_apc_partner, adsl_conn1_partner->dsc_co_sort.imc_sno );
#endif
   adsp_apr1->boc_session_active = TRUE;    /* session is active       */
   adsp_apr1->imc_sno = adsl_conn1_partner->dsc_co_sort.imc_sno;  /* session number */
   if (adsl_aprb_w1) {                      /* found data to pass to component */
     return TRUE;                           /* all done                */
   }
   adsp_apr1->iec_aprc = ied_aprc_idle;     /* command returns nothing */
   return TRUE;                             /* all done                */

#undef ADSL_APC_THIS_G
#undef ADSL_APC_PARTNER_G

   p_ap_frb_00:                             /* free passed read buffers */
   if (adsp_apr1->vpc_aux_pipe_handle == NULL) {  /* handle of aux-pipe */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   adsl_auxf_1_apc_this = (struct dsd_auxf_1 *) adsp_apr1->vpc_aux_pipe_handle;  /* address aux-pipe connection control structure of this side */
   if (adsl_auxf_1_apc_this->iec_auxf_def != ied_auxf_pipe_conn) {  /* aux-pipe established connection */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
#ifdef XYZ1
   while (   (ADSL_APC_THIS_G->adsc_aprb_ch)
          && (ADSL_APC_THIS_G->adsc_aprb_ch->boc_passed)) {  /* already passed to calling component */
     dss_critsect_aux.m_enter();            /* critical section        */
     adsl_aprb_w1 = ADSL_APC_THIS_G->adsc_aprb_ch;
     ADSL_APC_THIS_G->adsc_aprb_ch = adsl_aprb_w1->adsc_next;  /* remove from chain */
     dss_critsect_aux.m_leave();            /* critical section        */
     m_proc_free( adsl_aprb_w1 );           /* free memory again       */
   }
#endif
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_aprb_first = ADSL_APC_THIS_G->adsc_aprb_ch;
   if (   (adsl_aprb_first)                 /* buffer found            */
       && (adsl_aprb_first->boc_passed == FALSE)) {  /* already passed to calling component */
     adsl_aprb_first = NULL;                /* do not process          */
   }
   if (adsl_aprb_first) {                   /* buffer found            */
     adsl_aprb_w1 = adsl_aprb_first;        /* get first buffer        */
     while (   (adsl_aprb_w1->adsc_next)
            && (adsl_aprb_w1->adsc_next->boc_passed)) {  /* already passed to calling component */
       adsl_aprb_w1 = adsl_aprb_w1->adsc_next;  /* get next in chain   */
     }
     ADSL_APC_THIS_G->adsc_aprb_ch = adsl_aprb_w1->adsc_next;  /* set new chain */
     adsl_aprb_w1->adsc_next = NULL;        /* end of buffers to free  */
   }
   dss_critsect_aux.m_leave();              /* critical section        */
   while (adsl_aprb_first) {                /* buffer found            */
     adsl_aprb_w1 = adsl_aprb_first;        /* get first buffer        */
     adsl_aprb_first = adsl_aprb_first->adsc_next;
     m_proc_free( adsl_aprb_w1 );           /* free memory again       */
   }
   adsp_apr1->iec_aprc = ied_aprc_ok;       /* command returns o.k.    */
   return TRUE;                             /* all done                */

#undef ADSL_APC_THIS_G

   p_ap_write_00:                           /* write to session        */
   if (adsp_apr1->vpc_aux_pipe_handle == NULL) {  /* handle of aux-pipe */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   adsl_auxf_1_apc_this = (struct dsd_auxf_1 *) adsp_apr1->vpc_aux_pipe_handle;  /* address aux-pipe connection control structure of this side */
   if (adsl_auxf_1_apc_this->iec_auxf_def != ied_auxf_pipe_conn) {  /* aux-pipe established connection */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
   if (adsp_apr1->adsc_gai1_data == NULL) {  /* input and output data  */
     adsp_apr1->iec_aprc = ied_aprc_parm_error;  /* aux-pipe command parameter invalid */
     return TRUE;                           /* all done                */
   }
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   adsl_auxf_1_apc_partner = ADSL_APC_THIS_G->adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   if (adsl_auxf_1_apc_partner == NULL) {   /* no more connected to partner */
     adsp_apr1->boc_session_active = FALSE;  /* session is active      */
     adsp_apr1->imc_sno = 0;                /* session number          */
     adsp_apr1->iec_aprc = ied_aprc_conn_ended;  /* connection has ended */
     return TRUE;                           /* all done                */
   }
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   adsl_conn1_partner = (DSD_CONN_G *) ADSL_APC_PARTNER_G->ac_conn1;  /* connection of partner */
   adsp_apr1->boc_session_active = TRUE;    /* session is active       */
   adsp_apr1->imc_sno = adsl_conn1_partner->dsc_co_sort.imc_sno;  /* session number */
   adsl_gai1_w1 = adsp_apr1->adsc_gai1_data;  /* input and output data  */
   achl_in_cur = adsl_gai1_w1->achc_ginp_cur;
   adsl_aprb_first = adsl_aprb_last = adsl_aprb_w1
     = (struct dsd_aux_pipe_read_buffer *) m_proc_alloc();  /* aux-pipe read buffer */

   p_ap_write_20:                           /* fill output buffer      */
   memset( adsl_aprb_w1, 0, sizeof(struct dsd_aux_pipe_read_buffer) );
   achl_out_cur = (char *) (adsl_aprb_w1 + 1);
   achl_out_end = (char *) adsl_aprb_w1 + LEN_TCP_RECV;
   adsl_aprb_w1->dsc_gai1_data.achc_ginp_cur = achl_out_cur;

   p_ap_write_24:                           /* continue fill output buffer */
   while (achl_in_cur >= adsl_gai1_w1->achc_ginp_end) {
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     if (adsl_gai1_w1 == NULL) {
       goto p_ap_write_40;                  /* output buffers filled   */
     }
     achl_in_cur = adsl_gai1_w1->achc_ginp_cur;
   }
   iml1 = adsl_gai1_w1->achc_ginp_end - achl_in_cur;
   iml2 = achl_out_end - achl_out_cur;
   if (iml2 == 0) {                         /* output buffer full      */
     adsl_aprb_w1->dsc_gai1_data.achc_ginp_end = achl_out_cur;
     adsl_aprb_w1 = (struct dsd_aux_pipe_read_buffer *) m_proc_alloc();  /* aux-pipe read buffer */
     adsl_aprb_last->adsc_next = adsl_aprb_w1;
     adsl_aprb_last = adsl_aprb_w1;
     goto p_ap_write_20;                    /* fill output buffer      */
   }
   if (iml1 > iml2) iml1 = iml2;
   memcpy( achl_out_cur, achl_in_cur, iml1 );
   achl_out_cur += iml1;                    /* increment output        */
   achl_in_cur += iml1;                     /* increment input         */
   goto p_ap_write_24;                      /* continue fill output buffer */

   p_ap_write_40:                           /* output buffers filled   */
   adsl_aprb_w1->dsc_gai1_data.achc_ginp_end = achl_out_cur;
   dss_critsect_aux.m_enter();              /* critical section        */
   if (ADSL_APC_THIS_G->adsc_auxf_1_apc_partner) {  /* address aux-pipe connection control structure of partner */
     if (ADSL_APC_PARTNER_G->adsc_aprb_ch == NULL) {  /* chain of aux-pipe read buffers */
       ADSL_APC_PARTNER_G->adsc_aprb_ch = adsl_aprb_first;  /* new chain of aux-pipe read buffers */
     } else {                               /* append to chain         */
       adsl_aprb_w1 = ADSL_APC_PARTNER_G->adsc_aprb_ch;  /* get old chain of aux-pipe read buffers */
       while (adsl_aprb_w1->adsc_next) adsl_aprb_w1 = adsl_aprb_w1->adsc_next;
       adsl_aprb_w1->adsc_next = adsl_aprb_first;  /* append to chain of aux-pipe read buffers */
     }
     adsl_aprb_first = NULL;                /* data passed to partner  */
     ((struct dsd_auxf_ext_1 *) ((char *) ADSL_APC_PARTNER_G - sizeof(struct dsd_auxf_ext_1)))->imc_signal
       = ADSL_APC_PARTNER_G->imc_signal;
   }
   dss_critsect_aux.m_leave();              /* critical section        */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_write_40: adsl_auxf_1_apc_partner=%p &ADSL_APC_PARTNER_G->adsc_aprb_ch=%p cont=%p.",
                   __LINE__, adsl_auxf_1_apc_partner, &ADSL_APC_PARTNER_G->adsc_aprb_ch, ADSL_APC_PARTNER_G->adsc_aprb_ch );
#endif
   if (adsl_aprb_first) {                   /* data not passed to partner */
     do {                                   /* loop to free buffers again */
       adsl_aprb_w1 = adsl_aprb_first;      /* get chain of aux-pipe read buffers */
       adsl_aprb_first = adsl_aprb_w1->adsc_next;  /* remove from chain of aux-pipe read buffers */
       m_proc_free( adsl_aprb_w1 );         /* free buffer             */
     } while (adsl_aprb_first);
     adsp_apr1->boc_session_active = FALSE;  /* session is active      */
     adsp_apr1->imc_sno = 0;                /* session number          */
     adsp_apr1->iec_aprc = ied_aprc_conn_ended;  /* connection has ended */
     return TRUE;                           /* all done                */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_write_40: adsl_auxf_1_apc_this=%p adsl_auxf_1_apc_partner=%p partner-sno=%08d.",
                   __LINE__, adsl_auxf_1_apc_this, adsl_auxf_1_apc_partner, adsp_apr1->imc_sno );
#endif
   adsl_conn1_partner->boc_signal_set = TRUE;  /* signal for component set */
   adsp_apr1->iec_aprc = ied_aprc_ok;       /* command returns o.k.    */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_cdaux() l%05d p_ap_write_40: ADSL_CONN1_G=%p adsl_conn1_partner=%p.",
                   __LINE__, ADSL_CONN1_G, adsl_conn1_partner );
#endif
   if (adsl_conn1_partner == ADSL_CONN1_G) return TRUE;
#ifndef HL_UNIX
   m_act_conn( adsl_conn1_partner );        /* activate connection     */
#else
   m_act_thread_1( adsl_conn1_partner );    /* activate work-thread    */
#endif
   return TRUE;                             /* all done                */

#undef ADSL_APC_THIS_G
#undef ADSL_APC_PARTNER_G

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_pipe_manage()                                           */

/** cleanup for aux-pipe listen                                        */
static void m_aux_pipe_listen_cleanup( DSD_CONN_G *adsp_conn1, struct dsd_auxf_1 *adsp_auxf_1_ap_listen ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_auxf_1 *adsl_auxf_1_apc_this;  /* address aux-pipe connection control structure of this side */
   struct dsd_auxf_1 *adsl_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   DSD_CONN_G *adsl_conn1_partner;          /* connection of partner   */
   struct dsd_aux_pipe_read_buffer *adsl_aprb_w1;  /* aux-pipe read buffer */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsp_auxf_1_ap_listen + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */

   if (ADSL_APL_G->iec_aps != ied_aps_process) {  /* for current process */
     goto p_apl_cu_40;                      /* free new connections    */
   }
   achl_avl_error = NULL;                   /* error code AVL tree     */
   dss_critsect_aux.m_enter();              /* critical section        */
   do {                                     /* pseudo-loop             */
     bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                                   &dsl_htree1_work, &ADSL_APL_G->dsc_sort_pipe );
     if (bol_rc == FALSE) {                 /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree   */
       break;
     }
     bol_rc = m_htree1_avl_delete( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                                   &dsl_htree1_work );
     if (bol_rc == FALSE) {                 /* error occured           */
       achl_avl_error = "m_htree1_avl_delete() failed";  /* error code AVL tree */
     }
#ifndef B171026
     dsl_htree1_work.adsc_found = (struct dsd_htree1_avl_entry *) &m_aux_pipe_listen_cleanup;  /* avoid error message */
#endif
   } while (FALSE);
   dss_critsect_aux.m_leave();              /* critical section        */
   if (achl_avl_error) {                    /* error code AVL tree     */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_aux_pipe_listen_cleanup() l%05d aux-pipe AVL-tree error %s.",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta,
                     __LINE__,
                     achl_avl_error );
     goto p_apl_cu_40;                      /* free new connections    */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_aux_pipe_listen_cleanup() l%05d aux-pipe AVL-tree entry not found",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta,
                     __LINE__ );
   }

   p_apl_cu_40:                             /* free new connections    */
   while (ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn) {  /* chain aux-pipe connection control structures new connections */
     adsl_auxf_1_apc_this = ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn;  /* get old chain aux-pipe connection control structures new connections */
     ADSL_APL_G->adsc_auxf_1_apc_ch_new_conn = adsl_auxf_1_apc_this->adsc_next;  /* remove from chain aux-pipe connection control structures new connections */
#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_this + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
     adsl_auxf_1_apc_partner = ADSL_APC_THIS_G->adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
     if (adsl_auxf_1_apc_partner) {         /* connection still active */
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
       ADSL_APC_PARTNER_G->adsc_auxf_1_apc_partner = NULL;  /* clear address aux-pipe connection control structure of partner */
       adsl_conn1_partner = (DSD_CONN_G *) ADSL_APC_PARTNER_G->ac_conn1;  /* connection of partner */
       ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_apc_partner + 1))->imc_signal
         = ADSL_APC_PARTNER_G->imc_signal;
       adsl_conn1_partner->boc_signal_set = TRUE;  /* signal for component set */
       if (adsl_conn1_partner != adsp_conn1) {  /* is other session / connection */
#ifndef HL_UNIX
         m_act_conn( adsl_conn1_partner );  /* activate connection     */
#else
         m_act_thread_1( adsl_conn1_partner );  /* activate work-thread */
#endif
       }
#undef ADSL_APC_PARTNER_G
     }
     while (ADSL_APC_THIS_G->adsc_aprb_ch) {  /* check chain of aux-pipe read buffers */
       dss_critsect_aux.m_enter();          /* critical section        */
       adsl_aprb_w1 = ADSL_APC_THIS_G->adsc_aprb_ch;  /* get old chain of aux-pipe read buffers */
       ADSL_APC_THIS_G->adsc_aprb_ch = adsl_aprb_w1->adsc_next;  /* remove from chain of aux-pipe read buffers */
       dss_critsect_aux.m_leave();          /* critical section        */
       m_proc_free( adsl_aprb_w1 );         /* free buffer             */
     }
#undef ADSL_APC_THIS_G
     free( adsl_auxf_1_apc_this );          /* free memory             */
   }
#undef ADSL_APL_G
} /* end m_aux_pipe_listen_cleanup()                                   */

/** cleanup for aux-pipe connection                                    */
static void m_aux_pipe_conn_cleanup( DSD_CONN_G *adsp_conn1, struct dsd_auxf_1 *adsp_auxf_1_ap_conn ) {
   struct dsd_auxf_1 *adsl_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   DSD_CONN_G *adsl_conn1_partner;          /* connection of partner   */
   struct dsd_aux_pipe_read_buffer *adsl_aprb_w1;  /* aux-pipe read buffer */

#define ADSL_APC_THIS_G ((struct dsd_aux_pipe_conn *) ((char *) (adsp_auxf_1_ap_conn + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
   adsl_auxf_1_apc_partner = ADSL_APC_THIS_G->adsc_auxf_1_apc_partner;  /* address aux-pipe connection control structure of partner */
   if (adsl_auxf_1_apc_partner) {           /* connection still active */
#define ADSL_APC_PARTNER_G ((struct dsd_aux_pipe_conn *) ((char *) (adsl_auxf_1_apc_partner + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe connection control structure */
     ADSL_APC_PARTNER_G->adsc_auxf_1_apc_partner = NULL;  /* clear address aux-pipe connection control structure of partner */
     adsl_conn1_partner = (DSD_CONN_G *) ADSL_APC_PARTNER_G->ac_conn1;  /* connection of partner */
     ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_apc_partner + 1))->imc_signal
       = ADSL_APC_PARTNER_G->imc_signal;
     adsl_conn1_partner->boc_signal_set = TRUE;  /* signal for component set */
     if (adsl_conn1_partner != adsp_conn1) {  /* is other session / connection */
#ifndef HL_UNIX
       m_act_conn( adsl_conn1_partner );    /* activate connection     */
#else
       m_act_thread_1( adsl_conn1_partner );  /* activate work-thread */
#endif
     }
#undef ADSL_APC_PARTNER_G
   }
   while (ADSL_APC_THIS_G->adsc_aprb_ch) {  /* check chain of aux-pipe read buffers */
     dss_critsect_aux.m_enter();            /* critical section        */
     adsl_aprb_w1 = ADSL_APC_THIS_G->adsc_aprb_ch;  /* get old chain of aux-pipe read buffers */
     ADSL_APC_THIS_G->adsc_aprb_ch = adsl_aprb_w1->adsc_next;  /* remove from chain of aux-pipe read buffers */
     dss_critsect_aux.m_leave();            /* critical section        */
     m_proc_free( adsl_aprb_w1 );           /* free buffer             */
   }

#undef ADSL_APC_THIS_G
} /* end m_aux_pipe_conn_cleanup()                                     */

/** compare entries in AVL tree of aux-pipe-listen                     */
static int m_cmp_aux_pipe_listen( void *,
                                  struct dsd_htree1_avl_entry *adsp_entry_1,
                                  struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml1;                         /* working variable        */
#define ADSL_APL_P1 ((struct dsd_aux_pipe_listen *) ((char *) adsp_entry_1 - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))
#define ADSL_APL_P2 ((struct dsd_aux_pipe_listen *) ((char *) adsp_entry_2 - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))
   iml1 = ADSL_APL_P1->imc_len_aux_pipe_name;  /* length of name of aux-pipe */
   if (iml1 > ADSL_APL_P2->imc_len_aux_pipe_name) iml1 = ADSL_APL_P2->imc_len_aux_pipe_name;
#ifdef XYZ1
   iml1 = memcmp( ADSL_APL_P1 + 1, ADSL_APL_P2 + 1, iml1 );
#endif
   iml1 = memcmp( ADSL_APL_P1->achc_aux_pipe_name, ADSL_APL_P2->achc_aux_pipe_name, iml1 );
   if (iml1 != 0) return iml1;
   return ADSL_APL_P1->imc_len_aux_pipe_name - ADSL_APL_P2->imc_len_aux_pipe_name;
#undef ADSL_APL_P1
#undef ADSL_APL_P2
} /* end m_cmp_aux_pipe_listen()                                       */

/** command to start and manage utility threads                        */
static BOOL m_aux_util_thread_cmd( void *vpp_userfld, struct dsd_aux_util_thread_call_1 *adsp_autc1 ) {
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   BOOL       bol_ut_denied;                /* start utiltity thread denied */
   struct dsd_auxf_1 *adsl_auxf_1_ut;       /* auxiliary ext field utility thread */
   struct dsd_auxf_1 *adsl_auxf_1_last;     /* last auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_extra_thread_entry *adsl_ete_cur;  /* current extra thread entry */
   struct dsd_extra_thread_entry *adsl_ete_last;  /* last extra thread entry */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   switch (adsp_autc1->iec_autc) {          /* util-thread command     */
     case ied_autc_start:                   /* start utility thread    */
       goto p_utc_20;                       /* start utility thread    */
     case ied_autc_signal:                  /* send signal to utility thread */
     case ied_autc_check:                   /* check if running and get return values */
       goto p_utc_40;                       /* utility thread already started */
   }
   goto p_utc_80;                           /* invalid parameters      */

   p_utc_20:                                /* start utility thread    */
   if (adsp_autc1->amc_util_thread == NULL) {  /* entry of utility thread */
     goto p_utc_80;                         /* invalid parameters      */
   }
   if (adsp_autc1->imc_signal_parent == 0) {  /* signal for parent     */
     goto p_utc_80;                         /* invalid parameters      */
   }
   if (adsp_autc1->imc_no_xchg_mem_area > MAX_UTIL_THR_MEM_AREA) {  /* number of entries arc_xchg_mem_area */
     goto p_utc_80;                         /* invalid parameters      */
   }
   if (adsp_autc1->imc_no_xchg_mem_area < 0) {  /* number of entries arc_xchg_mem_area */
     goto p_utc_80;                         /* invalid parameters      */
   }
#ifdef NOT_YET_130414
   dss_critsect_aux.m_enter();              /* critical section        */
   dss_critsect_aux.m_leave();              /* critical section        */
#endif
   adsl_auxf_1_ut = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + sizeof(struct dsd_util_thread_ctrl) );  /* auxiliary ext field utility thread */
   memset( adsl_auxf_1_ut, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_util_thread_ctrl) );  /* auxiliary ext field utility thread */

#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_ut + 1))

#ifdef TRYOUT
// L.S. 04.02.1015:
   ((struct dsd_aux_cf1 *)(&ADSL_UTC_G->dsc_pd_work))->adsc_hco_wothr = (ADSL_AUX_CF1->adsc_hco_wothr);
#endif

   ADSL_UTC_G->dsc_ete.ac_conn1 = ADSL_CONN1_G;  /* for this connection */
   ADSL_UTC_G->dsc_ete.ilc_time_started_ms = m_get_epoch_ms();  /* time / epoch started in milliseconds */
   ADSL_UTC_G->amc_util_thread = adsp_autc1->amc_util_thread;  /* entry of utility thread */
   memcpy( &ADSL_UTC_G->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* component identifier */
   ADSL_UTC_G->imc_thread_priority = adsp_autc1->imc_thread_priority;  /* priority of utility thread to be created */
   if (adsp_autc1->boc_thread_priority_relative) {  /* priority of utility thread to be created is relative */
#ifndef HL_UNIX
     ADSL_UTC_G->imc_thread_priority = adsg_loconf_1_inuse->inc_prio_work_thread + adsp_autc1->imc_thread_priority;  /* priority of utility thread to be created */
#else
     ADSL_UTC_G->imc_thread_priority = dss_loconf_1.inc_prio_work_thread + adsp_autc1->imc_thread_priority;  /* priority of utility thread to be created */
#endif
   }
   if (ADSL_UTC_G->imc_thread_priority < DEF_PRIO_MINIMUM) {
     ADSL_UTC_G->imc_thread_priority = DEF_PRIO_MINIMUM;
   }
   if (ADSL_UTC_G->imc_thread_priority > DEF_PRIO_MAXIMUM) {
     ADSL_UTC_G->imc_thread_priority = DEF_PRIO_MAXIMUM;
   }
   ADSL_UTC_G->imc_signal_parent = adsp_autc1->imc_signal_parent;  /* signal for parent */
   adsp_autc1->adsc_aux_util_thread_param_1 = &ADSL_UTC_G->dsc_utp1;  /* paramter call utility thread */
#ifdef B170224
   ADSL_UTC_G->dsc_pd_work.dsc_aux_cf1.adsc_conn = ADSL_CONN1_G;  /* set connection */
#endif
#ifdef B130314
   ADSL_UTC_G->dsc_pd_work.dsc_aux_cf1.iec_src_func = ied_src_fu_util_thread;  /* utility thread */
#endif
   ADSL_UTC_G->dsc_pd_work.dsc_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_util_thread;  /* utility thread */
   ADSL_UTC_G->dsc_pd_work.dsc_aux_cf1.dsc_cid.ac_cid_addr = ADSL_UTC_G;
#ifndef B170224
   ADSL_UTC_G->dsc_pd_work.dsc_aux_cf1.adsc_conn = NULL;
#endif
   ADSL_UTC_G->dsc_utp1.amc_aux = &m_cdaux;  /* auxiliary callback routine */
   ADSL_UTC_G->dsc_utp1.vpc_userfld = &ADSL_UTC_G->dsc_pd_work;  /* User Field Subroutine */
   ADSL_UTC_G->dsc_utp1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;
   /* move memory resources from connection to utility thread          */
   iml1 = 0;                                /* clear index             */
   while (iml1 < adsp_autc1->imc_no_xchg_mem_area) {  /* number of entries arc_xchg_mem_area */
     adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain of auxiliary extension fields connection */
     adsl_auxf_1_last = NULL;               /* start of chain          */
     while (adsl_auxf_1_w1) {               /* loop over chain of auxiliary extension fields */
       if (   (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_normstor)  /* normal storage */
           && (((void *) (adsl_auxf_1_w1 + 1)) == adsp_autc1->arc_xchg_mem_area[ iml1 ])) {
         break;
       }
       adsl_auxf_1_last = adsl_auxf_1_w1;   /* save last in chain      */
       adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_auxf_1_w1) {                  /* found in chain of auxiliary extension fields */
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_last == NULL) {      /* at start of chain       */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;  /* remove at start of chain auxiliary extension fields */
       } else {                             /* middle in chain         */
         adsl_auxf_1_last->adsc_next = adsl_auxf_1_w1->adsc_next;  /* remove from chain auxiliary extension fields */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
       adsl_auxf_1_w1->adsc_next = ADSL_UTC_G->adsc_auxf_1;  /* get chain auxiliary extension fields */
       ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain auxiliary extension fields */
     } else {                               /* not found in chain      */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d amc_util_thread returned invalid field arc_xchg_mem_area index %d address %p.",
                       __LINE__, iml1, adsp_autc1->arc_xchg_mem_area[ iml1 ] );
     }
     iml1++;                                /* increment index         */
   }
   adsl_auxf_1_ut->iec_auxf_def = ied_auxf_util_thread;  /* utility thread */
   adsl_auxf_1_ut->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* current Server-Data-Hook */
   adsl_auxf_1_ut->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ut;  /* set new chain       */
   ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area = adsp_autc1->imc_no_xchg_mem_area;  /* number of entries arc_xchg_mem_area */
   memcpy( ADSL_UTC_G->dsc_utp1.arc_xchg_mem_area,
           adsp_autc1->arc_xchg_mem_area,
           sizeof( ADSL_UTC_G->dsc_utp1.arc_xchg_mem_area ) );
   ADSL_UTC_G->dsc_utp1.adsc_gai1_xchg = adsp_autc1->adsc_gai1_xchg;  /* input and output data */
   bol_ut_denied = FALSE;                   /* start utiltity thread denied */
   dss_critsect_aux.m_enter();              /* critical section        */
   dss_ets_ut.imc_no_started++;             /* number of instances started */
   dss_ets_ut.imc_no_current++;             /* number of instances currently executing */
   ADSL_UTC_G->dsc_ete.adsc_next = dss_ets_ut.adsc_ete_ch;  /* get old chain extra thread entries */
   dss_ets_ut.adsc_ete_ch = &ADSL_UTC_G->dsc_ete;  /* set new chain extra thread entries */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (bol_ut_denied == FALSE) {            /* not start utiltity thread denied */
     iml_rc = ADSL_UTC_G->dsc_thread.mc_create( &m_aux_util_thread_execute, ADSL_UTC_G );
     if (iml_rc >= 0) {                     /* no error occured        */
       adsp_autc1->iec_autrc = ied_autrc_ok;  /* command processed o.k. */
       return TRUE;
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d CreateThread utility thread Error", __LINE__ );
   }
   dss_critsect_aux.m_enter();              /* critical section        */
   if (bol_ut_denied == FALSE) {            /* not start utiltity thread denied */
     adsl_ete_cur = dss_ets_ut.adsc_ete_ch;  /* get old chain extra thread entries */
     adsl_ete_last = NULL;                  /* clear last extra thread entry */
     while (adsl_ete_cur) {                 /* loop over extra thread entries */
       if (adsl_ete_cur == &ADSL_UTC_G->dsc_ete) {  /* found in chain extra thread entries */
         break;
       }
       adsl_ete_last = adsl_ete_cur;        /* set last extra thread entry */
       adsl_ete_cur = adsl_ete_cur->adsc_next;  /* get next in chain   */
     }
     if (adsl_ete_cur) {                    /* extra thread entry found */
       if (adsl_ete_last == NULL) {         /* at anchor of chain extra thread entries */
         dss_ets_ut.adsc_ete_ch = adsl_ete_cur->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain extra thread entries */
         adsl_ete_last->adsc_next = adsl_ete_cur->adsc_next;  /* remove from chain */
       }
     }
     dss_ets_ut.imc_no_current--;           /* number of instances currently executing */
   }
   dss_ets_ut.imc_no_denied++;              /* number of start requests denied / failed */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (bol_ut_denied == FALSE) {            /* not start utiltity thread denied */
     if (adsl_ete_cur == NULL) {            /* extra thread entry not found */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d did not find entry in chain of extra thread entries %p.",
                       __LINE__, &ADSL_UTC_G->dsc_ete );
     }
   }
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ut->adsc_next;  /* remove from chain */
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   free( adsl_auxf_1_ut );                  /* free memory again       */
   return TRUE;

#undef ADSL_UTC_G

   p_utc_40:                                /* utility thread already started */
   adsl_auxf_1_ut = ADSL_CONN1_G->adsc_auxf_1;  /* get chain           */
   adsl_auxf_1_last = NULL;                 /* last auxiliary extension field */
   while (adsl_auxf_1_ut) {                 /* loop over all auxiliary extension fields */
     if (&((struct dsd_util_thread_ctrl *) (adsl_auxf_1_ut + 1))->dsc_utp1 == adsp_autc1->adsc_aux_util_thread_param_1) break;
     adsl_auxf_1_last = adsl_auxf_1_ut;     /* last auxiliary extension field */
     adsl_auxf_1_ut = adsl_auxf_1_ut->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_ut == NULL) {            /* utility thread not found */
     goto p_utc_80;                         /* invalid parameters      */
   }

#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_ut + 1))

   if (ADSL_UTC_G->boc_thread_ended) {      /* thread has already ended */
     goto p_utc_60;                         /* utility thread has ended */
   }
   adsp_autc1->imc_no_xchg_mem_area = 0;
   adsp_autc1->adsc_gai1_xchg = NULL;       /* input and output data   */
   return TRUE;

   p_utc_60:                                /* utility thread has ended */
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
   if (adsl_auxf_1_last == NULL) {          /* first in chain          */
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ut->adsc_next;  /* remove from chain */
   } else {                                 /* was middle in chain     */
     adsl_auxf_1_last->adsc_next = adsl_auxf_1_ut->adsc_next;  /* remove from chain */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   adsp_autc1->imc_no_xchg_mem_area = ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area;  /* number of entries arc_xchg_mem_area */
   memcpy( adsp_autc1->arc_xchg_mem_area,
           ADSL_UTC_G->dsc_utp1.arc_xchg_mem_area,
           sizeof( adsp_autc1->arc_xchg_mem_area ) );
   adsp_autc1->adsc_gai1_xchg = ADSL_UTC_G->dsc_utp1.adsc_gai1_xchg;  /* input and output data */
   if (ADSL_UTC_G->adsc_auxf_1) {           /* chain auxiliary extension fields */
     adsl_auxf_1_last = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
     while (adsl_auxf_1_last->adsc_next) adsl_auxf_1_last = adsl_auxf_1_last->adsc_next;
     adsl_auxf_1_last->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary extension fields connection */
     ADSL_CONN1_G->adsc_auxf_1 = ADSL_UTC_G->adsc_auxf_1;  /* set new chain auxiliary extension fields connection */
   }
   free( adsl_auxf_1_ut );                  /* free memory again       */
   adsp_autc1->iec_autrc = ied_autrc_ended;  /* util-thread has ended  */
   return TRUE;

#undef ADSL_UTC_G

   p_utc_80:                                /* invalid parameters      */
   adsp_autc1->iec_autrc = ied_autrc_inv_param;  /* invalid parameters passed */
   return TRUE;

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1

} /* end m_aux_util_thread_cmd()                                       */

/**
   the utility thread cannot access the field adsc_auxf_1 in DSD_CONN_G (the connection).
   so, for cleanup, the connection sets dsc_ete.ac_conn1 to NULL when ending;
   this means the utility thread needs to free its resources itself.
   when resources are passed from the utility thread to the connection
   (running on a work thread), the utility thread sets boc_thread_ended to TRUE;
   this means, the connections needs to free the resources.
   the connection, running on a work thread, can access adsc_auxf_1 in struct dsd_util_thread_ctrl
   only before the utility thread was started or after boc_thread_ended is set.
*/

/** utility thread, execution                                          */
static htfunc1_t m_aux_util_thread_execute( void * vp_param ) {
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* return code             */
#endif
   int        iml1;                         /* working variable        */
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension field */
   struct dsd_extra_thread_entry *adsl_ete_cur;  /* current extra thread entry */
   struct dsd_extra_thread_entry *adsl_ete_last;  /* last extra thread entry */
   HL_LONGLONG ill_time_ended;              /* time / epoch ended in milliseconds */

#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) vp_param)

#ifndef HL_UNIX
   bol_rc = SetThreadPriority( GetCurrentThread(), ADSL_UTC_G->imc_thread_priority );
   if (bol_rc == FALSE) {
     m_hl1_printf( "m_aux_util_thread_execute-%l05d-W utility thread SetThreadPriority Error:%d.",
                   __LINE__, GetLastError() );
   }
#else
   ADSL_UTC_G->dsc_thread.mc_setpriority( ADSL_UTC_G->imc_thread_priority );
#endif

   ADSL_UTC_G->amc_util_thread( &ADSL_UTC_G->dsc_utp1 );

   ill_time_ended = m_get_epoch_ms();       /* time / epoch ended in milliseconds */
   ill_time_ended -= ADSL_UTC_G->dsc_ete.ilc_time_started_ms;
   /* pass memory areas to connection, free other resources            */
   adsl_auxf_1_w1 = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
   ADSL_UTC_G->adsc_auxf_1 = NULL;          /* chain is empty          */
   if (   (ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area > MAX_UTIL_THR_MEM_AREA)  /* number of entries arc_xchg_mem_area */
       || (ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area < 0)) {  /* number of entries arc_xchg_mem_area */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d amc_util_thread returned invalid imc_no_xchg_mem_area %d.",
                     __LINE__, ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area );  /* number of entries arc_xchg_mem_area */
     ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area = 0;  /* clear number of entries arc_xchg_mem_area */
   }
   iml1 = 0;                                /* clear index             */
   while (iml1 < ADSL_UTC_G->dsc_utp1.imc_no_xchg_mem_area) {  /* number of entries arc_xchg_mem_area */
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* get chain of auxiliary extension fields */
     adsl_auxf_1_w3 = NULL;                 /* start of chain          */
     while (adsl_auxf_1_w2) {               /* loop over chain of auxiliary extension fields */
       if (   (adsl_auxf_1_w2->iec_auxf_def == ied_auxf_normstor)  /* normal storage */
           && (((void *) (adsl_auxf_1_w2 + 1)) == ADSL_UTC_G->dsc_utp1.arc_xchg_mem_area[ iml1 ])) {
         break;
       }
       adsl_auxf_1_w3 = adsl_auxf_1_w2;     /* save last in chain      */
       adsl_auxf_1_w2 = adsl_auxf_1_w2->adsc_next;  /* get next in chain */
     }
     if (adsl_auxf_1_w2) {                  /* found in chain of auxiliary extension fields */
       if (adsl_auxf_1_w3 == NULL) {        /* at start of chain       */
         adsl_auxf_1_w1 = adsl_auxf_1_w2->adsc_next;  /* remove at start of chain auxiliary extension fields */
       } else {                             /* middle in chain         */
         adsl_auxf_1_w3->adsc_next = adsl_auxf_1_w2->adsc_next;  /* remove from chain auxiliary extension fields */
       }
       adsl_auxf_1_w2->adsc_next = ADSL_UTC_G->adsc_auxf_1;  /* get chain auxiliary extension fields */
       ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w2;  /* set new chain auxiliary extension fields */
     } else {                               /* not found in chain      */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d amc_util_thread returned invalid field arc_xchg_mem_area index %d address %p.",
                       __LINE__, iml1, ADSL_UTC_G->dsc_utp1.arc_xchg_mem_area[ iml1 ] );
     }
     iml1++;                                /* increment index         */
   }
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* get chain of auxiliary extension fields */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
     switch (adsl_auxf_1_w2->iec_auxf_def) {
       case ied_auxf_normstor:              /* normal storage          */
         break;                             /* free total memory       */
       case ied_auxf_defstor:               /* predefined storage      */
         m_proc_free( adsl_auxf_1_w2 );     /* put in chain of unused  */
         adsl_auxf_1_w2 = NULL;             /* no memory to free       */
         break;
//     case ied_auxf_ocsp:                  /* OCSP entry              */
#ifdef TRACEHL_P_DISP
//       m_hlnew_printf( HLOG_XYZ1, "chain auxiliary ext field OCSP found" );
#endif
//       m_ocsp_cleanup( this, adsl_auxf_1_1 );
//       break;
//     case ied_auxf_radqu:                 /* Radius query            */
//       break;
       case ied_auxf_diskfile:              /* link to disk file       */
         time( (time_t *) &(*((struct dsd_diskfile_1 **) (adsl_auxf_1_w2 + 1)))->ipc_time_last_acc );  /* get current time */
         dss_critsect_aux.m_enter();
         (*((struct dsd_diskfile_1 **) (adsl_auxf_1_w2 + 1)))->inc_usage_count--;  /* usage-count */
         dss_critsect_aux.m_leave();
         break;
//     case ied_auxf_cma1:                  /* common memory area      */
//           /* activate all work threads that are waiting             */
//           m_hco_wothr_unlock( ADSL_AUX_CF1->adsc_hco_wothr,
//                               (struct dsd_hco_lock_1 *) (adsl_auxf_1_1 + 1) );
//           break;
//     case ied_auxf_service_query_1:       /* service query 1         */
//       ((struct dsd_service_aux_1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w2 + 1)) + 1)->amc_service_close
//                                      ( ADSL_AUX_CF1, (char *) (adsl_auxf_1_w2 + 1) + sizeof(struct dsd_auxf_ext_1) );
//       break;
       case ied_auxf_ldap:                  /* LDAP service            */
         m_ldap_free( (class dsd_ldap_cl *) (adsl_auxf_1_w2 + 1) );
         break;
//     case ied_auxf_sip:               /* SIP request             */
//       m_aux_sip_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
//       break;
//     case ied_auxf_udp:               /* UDP request             */
//       m_aux_udp_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
//       break;
//     case ied_auxf_gate_udp:          /* UDP-gate entry          */
//       m_aux_gate_udp_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
//       break;
//         case ied_auxf_sessco1:           /* session configuration   */
//           break;
       case ied_auxf_admin:                 /* admin command           */
       case ied_auxf_ident:                 /* ident - userid and user-group */
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
       case ied_auxf_pipe_conn:             /* aux-pipe established connection */
       case ied_auxf_util_thread:           /* utility thread          */
       case ied_auxf_swap_stor:             /* swap storage            */
       case ied_auxf_dyn_lib:               /* dynamic library         */
       default:
         m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d cannot free resource %p iec_auxf_def %d.",
                         __LINE__, adsl_auxf_1_w2, adsl_auxf_1_w2->iec_auxf_def );
         adsl_auxf_1_w2 = NULL;             /* no memory to free       */
         break;
     }
     if (adsl_auxf_1_w2) free( adsl_auxf_1_w2 );  /* free memory       */
   }
   dss_critsect_aux.m_enter();              /* critical section        */
#ifndef HL_UNIX
   adsl_conn1_l = (class clconn1 *) ADSL_UTC_G->dsc_ete.ac_conn1;  /* current connection */
#else
   adsl_conn1_l = (struct dsd_conn1 *) ADSL_UTC_G->dsc_ete.ac_conn1;  /* current connection */
#endif
   if (adsl_conn1_l) {                      /* still connected to parent */
     ADSL_UTC_G->boc_thread_ended = TRUE;   /* thread has ended        */
   }
// free from tree of utility thread struct dsd_extra_thread_entry in struct dsd_extra_thread_stat
   adsl_ete_cur = dss_ets_ut.adsc_ete_ch;   /* get old chain extra thread entries */
   adsl_ete_last = NULL;                    /* clear last extra thread entry */
   while (adsl_ete_cur) {                   /* loop over extra thread entries */
     if (adsl_ete_cur == &ADSL_UTC_G->dsc_ete) {  /* found in chain extra thread entries */
       break;
     }
     adsl_ete_last = adsl_ete_cur;          /* set last extra thread entry */
     adsl_ete_cur = adsl_ete_cur->adsc_next;  /* get next in chain     */
   }
   if (adsl_ete_cur) {                      /* extra thread entry found */
     if (adsl_ete_last == NULL) {           /* at anchor of chain extra thread entries */
       dss_ets_ut.adsc_ete_ch = adsl_ete_cur->adsc_next;  /* remove from chain */
     } else {                               /* middle in chain extra thread entries */
       adsl_ete_last->adsc_next = adsl_ete_cur->adsc_next;  /* remove from chain */
     }
   }
   dss_ets_ut.imc_no_current--;             /* number of instances currently executing */
   dss_ets_ut.ilc_sum_time_ms += ill_time_ended;  /* summary time executed in milliseconds */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (adsl_ete_cur == NULL) {              /* extra thread entry not found */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d did not find entry in chain of extra thread entries %p.",
                     __LINE__, &ADSL_UTC_G->dsc_ete );
   }
   if (adsl_conn1_l) {                      /* still connected to parent */
     adsl_conn1_l->boc_signal_set = TRUE;   /* signal for component set */
#ifndef HL_UNIX
     m_act_conn( adsl_conn1_l );            /* activate connection     */
#else
     m_act_thread_1( adsl_conn1_l );        /* activate work-thread    */
#endif
     return 0;
   }
   /* free all resources                                               */
   /* no more connected to parent                                      */
   while (ADSL_UTC_G->adsc_auxf_1) {        /* chain auxiliary extension fields */
     adsl_auxf_1_w1 = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
     ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w2->adsc_next;  /* remove from chain */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_normstor) {  /* normal storage */
       free( adsl_auxf_1_w1 );              /* free memory             */
     } else {                               /* other type              */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW utility thread l%05d cannot free resource %p iec_auxf_def %d.",
                       __LINE__, adsl_auxf_1_w1, adsl_auxf_1_w1->iec_auxf_def );
     }
   }
   free( (char *) vp_param - sizeof(struct dsd_auxf_1) );
   return 0;

#undef ADSL_UTC_G

} /* end m_aux_util_thread_execute()                                   */

#ifdef WAS_BEFORE_1501
#ifndef D_INCL_SWAP_STOR
/** request for usage for swap storage                                 */
static BOOL m_aux_swap_stor_req_1( void *vpp_userfld, struct dsd_aux_swap_stor_req_1 *adsp_assr1 ) {
   return FALSE;
} /* end m_aux_swap_stor_req_1()                                       */
#endif
#endif
#ifdef B131227
/** request for usage for swap storage                                 */
static BOOL m_aux_swap_stor_req_1( void *vpp_userfld, struct dsd_aux_swap_stor_req_1 *adsp_assr1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_swap_stor_chunk *adsl_swstch_w1;  /* swap storage chunk  */
   struct dsd_swap_stor_chunk *adsl_swstch_w2;  /* swap storage chunk  */
   struct dsd_swap_stor_chunk *adsl_swstch_w3;  /* swap storage chunk  */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   switch (adsp_assr1->iec_swsc) {          /* swap storage command    */
     case ied_swsc_open:                    /* open swap storage       */
       goto p_sw_st_open_00;                /* open swap storage       */
     case ied_swsc_close:                   /* close swap storage      */
       goto p_sw_st_close_40;               /* close swap storage      */
     case ied_swsc_clear_and_close:         /* clear content and close swap storage */
       goto p_sw_st_close_00;               /* clear and close swap storage */
     case ied_swsc_get_buf:                 /* acquire swap storage buffer */
       goto p_sw_st_get_buf_00;             /* acquire swap storage buffer */
     case ied_swsc_read:                    /* read swap storage buffer */
     case ied_swsc_write:                   /* write swap storage buffer */
     case ied_swsc_release:                 /* release swap storage chunk */
       break;
   }
   return FALSE;

   p_sw_st_open_00:                         /* open swap storage       */
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) );  /* auxiliary extension field */
   memset( adsl_auxf_1_w1, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1) + sizeof(struct dsd_auxf_admin1) );
   adsl_auxf_1_w1->iec_auxf_def = ied_auxf_swap_stor;  /* swap storage */
   adsl_auxf_1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* current Server-Data-Hook */
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain       */
   adsp_assr1->vpc_aux_swap_stor_handle = adsl_auxf_1_w1;  /* handle of swap storage */
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   return TRUE;                             /* all done                */

   p_sw_st_close_00:                        /* clear and close swap storage */
   p_sw_st_close_40:                        /* close swap storage      */
   return FALSE;

   p_sw_st_get_buf_00:                      /* acquire swap storage buffer */
   achl_avl_error = NULL;                   /* error code AVL tree     */
   if (dss_swap_stor_ctrl.adsc_swstch_ch_free) {  /* chain free swap storage chunks */
     goto p_sw_st_get_buf_40;               /* should have storage for chunk */
   }

   p_sw_st_get_buf_20:                      /* acquire storage for multiple chunks */
   adsl_swstch_w1 = (struct dsd_swap_stor_chunk *) malloc( NO_SWAP_STOR_FREE * sizeof(struct dsd_swap_stor_chunk) );
   iml1 = NO_SWAP_STOR_FREE - 2;            /* acquire number of free swap storage chunks */
   adsl_swstch_w2 = adsl_swstch_w3 = adsl_swstch_w1 + 1;  /* first free chunk */
   do {
     adsl_swstch_w3->adsc_next = adsl_swstch_w3 + 1;
     adsl_swstch_w3++;
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_swstch_w3->adsc_next = dss_swap_stor_ctrl.adsc_swstch_ch_free;  /* get old chain free swap storage chunks */
   dss_swap_stor_ctrl.adsc_swstch_ch_free = adsl_swstch_w2;  /* set new chain free swap storage chunks */
   goto p_sw_st_get_buf_60;                 /* put swap storage chunk in AVL tree */

   p_sw_st_get_buf_40:                      /* should have storage for chunk */
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_swstch_w1 = dss_swap_stor_ctrl.adsc_swstch_ch_free;  /* chain free swap storage chunks */
   if (adsl_swstch_w1 == NULL) {            /* did not find free swap storage chunks */
     dss_critsect_aux.m_leave();            /* critical section        */
     goto p_sw_st_get_buf_20;               /* acquire storage for multiple chunks */
   }
   dss_swap_stor_ctrl.adsc_swstch_ch_free = adsl_swstch_w1->adsc_next;  /* remove from chain free swap storage chunks */

   p_sw_st_get_buf_60:                      /* put swap storage chunk in AVL tree */
   adsl_swstch_w1->iec_swsst = ied_swsst_acq;  /* acquired by component */
   adsl_swstch_w1->imc_index = adsp_assr1->imc_index;  /* index of dataset / chunk */
   adsl_swstch_w1->vpc_aux_swap_stor_handle = adsp_assr1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
// struct dsd_htree1_avl_entry dsc_sort_comp;  /* entry for sorting for component */
// struct dsd_htree1_avl_entry dsc_sort_file;  /* entry for sorting on file */
   bol_rc = m_htree1_avl_search( NULL, &dss_swap_stor_ctrl.dsc_htree1_avl_swap_stor_comp,
                                 &dsl_htree1_work, &adsl_swstch_w1->dsc_sort_comp );  /* entry for sorting for component */
   if (bol_rc == FALSE) {                   /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   }
   if (   (dsl_htree1_work.adsc_found == NULL)  /* not found in tree   */
       && (achl_avl_error == NULL)) {       /* no error before         */
     bol_rc = m_htree1_avl_insert( NULL, &dss_swap_stor_ctrl.dsc_htree1_avl_swap_stor_comp,
                                   &dsl_htree1_work, &adsl_swstch_w1->dsc_sort_comp );  /* entry for sorting for component */
     if (bol_rc == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_insert() failed";  /* error code AVL tree */
     }
   }
   dss_critsect_aux.m_leave();              /* critical section        */
#ifdef XYZ1
   if (achl_avl_error) {                    /* error code AVL tree     */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s aux-pipe AVL-tree error %s.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     achl_avl_error );
     free( adsl_auxf_1_ap_listen );
     adsp_apr1->iec_aprc = ied_aprc_misc;   /* miscellaneous error     */
     return TRUE;                           /* all done                */
   }
#endif

   dss_critsect_aux.m_leave();              /* critical section        */
   adsl_swstch_w1->achc_stor_addr           /* storage address or RBA on file */
     = adsp_assr1->achc_stor_addr           /* storage address         */
       = (char *) malloc( LEN_BLOCK_SWAP );  /* length block of swap area */
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   return TRUE;                             /* all done                */

   p_sw_st_get_buf_80:                      /* swap storage chunk double */
   return TRUE;                             /* all done                */

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1

} /* end m_aux_swap_stor_req_1()                                       */

/** compare entries in AVL tree of swap storage components             */
static int m_cmp_aux_swap_stor_comp( void *,
                                     struct dsd_htree1_avl_entry *adsp_entry_1,
                                     struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml1;                         /* working variable        */
#define ADSL_APL_P1 ((struct dsd_aux_pipe_listen *) ((char *) adsp_entry_1 - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))
#define ADSL_APL_P2 ((struct dsd_aux_pipe_listen *) ((char *) adsp_entry_2 - offsetof( struct dsd_aux_pipe_listen, dsc_sort_pipe )))
   iml1 = ADSL_APL_P1->imc_len_aux_pipe_name;  /* length of name of aux-pipe */
   if (iml1 > ADSL_APL_P2->imc_len_aux_pipe_name) iml1 = ADSL_APL_P2->imc_len_aux_pipe_name;
#ifdef XYZ1
   iml1 = memcmp( ADSL_APL_P1 + 1, ADSL_APL_P2 + 1, iml1 );
#endif
   iml1 = memcmp( ADSL_APL_P1->achc_aux_pipe_name, ADSL_APL_P2->achc_aux_pipe_name, iml1 );
   if (iml1 != 0) return iml1;
   return ADSL_APL_P1->imc_len_aux_pipe_name - ADSL_APL_P2->imc_len_aux_pipe_name;
#undef ADSL_APL_P1
#undef ADSL_APL_P2
} /* end m_cmp_aux_swap_stor_comp()                                    */
#endif
static void m_swap_stor_open( void ) {
   int        iml_rc;                       /* return code             */
#ifdef HL_UNIX
   int        iml_fd;                       /* file-descriptor         */
   int        iml_error;                    /* error number / errno    */
   struct dsd_filename_1 *adsl_fn_w1;       /* filename for swap file  */
//#ifdef XYZ1
#ifndef D_NO_STAT64
   struct flock64 dsl_flock;
#else
   struct flock dsl_flock;
#endif
//#endif
#endif

#ifndef HL_UNIX
#define ADSL_LOCONF_1_G adsg_loconf_1_inuse
#else
#define ADSL_LOCONF_1_G (&dss_loconf_1)
#endif
   if (ADSL_LOCONF_1_G->imc_max_swap_size == 0) {  /* <max-swap-size> in 64 KB units */
     return;
   }
#ifndef HL_UNIX
   if (dss_swap_stor_ctrl.boc_init) {       /* swap storage has been initialized */
     m_swap_stor_update();
     return;
   }
   dss_swap_stor_ctrl.boc_init = TRUE;      /* swap storage has been initialized */
#endif

   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_create return code %d.",
                     __LINE__, iml_rc );
   }

#ifndef HL_UNIX
   dss_swap_stor_ctrl.dsl_h_file = INVALID_HANDLE_VALUE;  /* handle of open swap file */
#endif
#ifdef HL_UNIX
// dss_swap_stor_ctrl.imc_fd_file = -1;     /* file-descriptor of open swap file */
#endif

   if (ADSL_LOCONF_1_G->adsc_swap_fn_chain == NULL) {  /* chain of filenames for swap file */
     return;
   }
#ifndef HL_UNIX
   dss_swap_stor_ctrl.dsc_ucs_file_name     /* file name               */
     = ADSL_LOCONF_1_G->adsc_swap_fn_chain->dsc_ucs_file_name;
   dss_swap_stor_ctrl.dsl_h_file            /* handle of open swap file */
     = CreateFileW( (WCHAR *) dss_swap_stor_ctrl.dsc_ucs_file_name.ac_str,
                    GENERIC_READ | GENERIC_WRITE, 0, 0,
                    CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0 );
//FILE_ATTRIBUTE_TEMPORARY
//FILE_FLAG_DELETE_ON_CLOSE
   if (dss_swap_stor_ctrl.dsl_h_file == INVALID_HANDLE_VALUE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR CreateFileW( %(ucs)s , ... ) returned error %d.",
                     __LINE__,
                     &dss_swap_stor_ctrl.dsc_ucs_file_name,
                     GetLastError() );
   }
#endif
#ifdef HL_UNIX
// to-do 31.12.14 KB - open file if not locked
   adsl_fn_w1 = ADSL_LOCONF_1_G->adsc_swap_fn_chain;

   p_open_20:                               /* open this file          */
#ifdef B160805
   iml_fd = open( (char *) adsl_fn_w1->dsc_ucs_file_name.ac_str,
#ifdef HL_LINUX
//                O_DIRECT |
#endif
                    O_RDWR | O_CREAT,
                  S_IRUSR | S_IWUSR );
#endif
#ifndef B160805
   iml_fd = open( (char *) adsl_fn_w1->dsc_ucs_file_name.ac_str,
#ifndef HL_LINUX
//                O_DIRECT |
#endif
                    O_RDWR | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR );
#endif
   if (iml_fd < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR open( %(ucs)s , ... ) returned error %d %d.",
                     __LINE__,
                     &adsl_fn_w1->dsc_ucs_file_name,
                     iml_fd, errno );
     goto p_open_80;                        /* try next configured file */
   }
//#define NO_SWAP_LOCK
#ifndef NO_SWAP_LOCK
#ifndef D_NO_STAT64
   memset( &dsl_flock, 0, sizeof(struct flock64) );
#else
   memset( &dsl_flock, 0, sizeof(struct flock) );
#endif
   dsl_flock.l_type = F_WRLCK;
   dsl_flock.l_whence = SEEK_SET;
   dsl_flock.l_len = 1;
// iml_rc = fcntl64( iml_fd, F_SETLK, &dsl_flock );
// to-do 24.01.15 KB - fcntl64() should be used, does not work
   iml_rc = fcntl( iml_fd, F_SETLK, &dsl_flock );
#ifdef TRACEHL1
   iml_error = errno;                       /* error number / errno    */
   m_hlnew_printf( HLOG_TRACE1, "m_swap_stor_open() l%05d fcntl() returned %d %d.",
                   __LINE__, iml_rc, iml_error );
   m_console_out( (char *) &dsl_flock, sizeof(struct flock) );
#endif
   if (iml_rc < 0) {                        /* error occured           */
#ifndef TRACEHL1
     iml_error = errno;                     /* error number / errno    */
#endif
     if (iml_error != EAGAIN) {
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR fcntl( %(ucs)s , ... ) returned error %d %d.",
                       __LINE__,
                       &adsl_fn_w1->dsc_ucs_file_name,
                       iml_rc, iml_error );
     }
     close( iml_fd );
     goto p_open_80;                        /* try next configured file */
   }
#endif
#ifdef XYZ1
   iml_rc = flock( iml_fd, LOCK_EX );
#ifdef TRACEHL1
   iml_error = errno;                       /* error number / errno    */
   m_hlnew_printf( HLOG_TRACE1, "m_swap_stor_open() l%05d flock() returned %d %d.",
                   __LINE__, iml_rc, iml_error );
#endif
   if (iml_rc < 0) {                        /* error occured           */
#ifndef TRACEHL1
     iml_error = errno;                     /* error number / errno    */
#endif
     if (iml_error != EAGAIN) {
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR flock( %(ucs)s , ... ) returned error %d %d.",
                       __LINE__,
                       &adsl_fn_w1->dsc_ucs_file_name,
                       iml_rc, iml_error );
     }
     close( iml_fd );
     goto p_open_80;                        /* try next configured file */
   }
#endif
   dss_swap_stor_ctrl.imc_fd_file = iml_fd;  /* file-descriptor of open swap file */
   dss_swap_stor_ctrl.achc_file_name = (char *) adsl_fn_w1->dsc_ucs_file_name.ac_str;  /* filename for multiple open */
   m_hlnew_printf( HLOG_INFO1, "HWSPM0xxI l%05d SWAP-STOR using swap-file \"%(ucs)s\"",
                   __LINE__,
                   &adsl_fn_w1->dsc_ucs_file_name );
   return;

   p_open_80:                               /* try next configured file */
   adsl_fn_w1 = adsl_fn_w1->adsc_next;      /* get next in chain       */
   if (adsl_fn_w1) {                        /* more files configured   */
     goto p_open_20;                        /* open this file          */
   }
// dss_swap_stor_ctrl.imc_fd_file = -1;     /* file-descriptor of open swap file */
   m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR no valid swap-file found",
                   __LINE__ );
   return;
#endif
#undef ADSL_LOCONF_1_G
} /* end m_swap_stor_open()                                            */

#ifndef HL_UNIX
static void m_swap_stor_update( void ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_cmp;                      /* compare values          */

   if (adsg_loconf_1_inuse->adsc_swap_fn_chain == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR reload configuration - no <swap-file> configured",
                     __LINE__ );
     if (dss_swap_stor_ctrl.dsl_h_file == INVALID_HANDLE_VALUE) return;
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR continue to use file %(ucs)s.",
                     __LINE__,
                     &dss_swap_stor_ctrl.dsc_ucs_file_name );
     return;
   }
   if (dss_swap_stor_ctrl.dsl_h_file == INVALID_HANDLE_VALUE) {
     goto p_upd_20;                         /* open file now           */
   }
   bol_rc = m_cmpi_ucs_ucs( &iml_cmp,
                            &adsg_loconf_1_inuse->adsc_swap_fn_chain->dsc_ucs_file_name,
                            &dss_swap_stor_ctrl.dsc_ucs_file_name );
   if ((bol_rc) && (iml_cmp == 0)) return;  /* filename did not change */
   m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR continue to use file %(ucs)s.",
                   __LINE__,
                   &dss_swap_stor_ctrl.dsc_ucs_file_name );
   return;                                  /* all done                */

   p_upd_20:                                /* open file now           */
   dss_swap_stor_ctrl.dsc_ucs_file_name     /* file name               */
     = adsg_loconf_1_inuse->adsc_swap_fn_chain->dsc_ucs_file_name;
   dss_swap_stor_ctrl.dsl_h_file            /* handle of open swap file */
     = CreateFileW( (WCHAR *) dss_swap_stor_ctrl.dsc_ucs_file_name.ac_str,
                    GENERIC_READ | GENERIC_WRITE, 0, 0,
                    CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, 0 );
//FILE_ATTRIBUTE_TEMPORARY
//FILE_FLAG_DELETE_ON_CLOSE
   if (dss_swap_stor_ctrl.dsl_h_file == INVALID_HANDLE_VALUE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR CreateFileW( %(ucs)s , ... ) returned error %d.",
                     __LINE__,
                     &dss_swap_stor_ctrl.dsc_ucs_file_name,
                     GetLastError() );
   }
} /* end m_swap_stor_update()                                          */
#endif

/** request for usage for swap storage                                 */
static BOOL m_aux_swap_stor_req_1( void *vpp_userfld, struct dsd_aux_swap_stor_req_1 *adsp_assr1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_index_file;               /* index of dataset / access file */
   char       chl_l;                        /* working variable        */
#ifdef B141229
#ifndef HL_UNIX
   DWORD      uml_write;                    /* return bytes written    */
   DWORD      uml_error;                    /* error code returned     */
#endif
#endif
// long long int ill_rba;                   /* RBA for access to disk  */
// void       *vpl_w1, *vpl_w2;             /* working variables       */
   char       *achl_w1, *achl_w2;           /* working variables       */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension field */
   struct dsd_swap_stor_chain *adsl_ss_ch_w1;  /* chain of swap storage chunks */
   struct dsd_swap_stor_chain *adsl_ss_ch_w2;  /* chain of swap storage chunks */
   struct dsd_swap_stor_chain **aadsl_ss_ch_ch;  /* chain of swap storage chunks */
#ifdef B131227
   struct dsd_swap_stor_chunk *adsl_swstch_w1;  /* swap storage chunk  */
   struct dsd_swap_stor_chunk *adsl_swstch_w1;  /* swap storage chunk  */
   struct dsd_swap_stor_chunk *adsl_swstch_w2;  /* swap storage chunk  */
   struct dsd_swap_stor_chunk *adsl_swstch_w3;  /* swap storage chunk  */
#endif
   struct dsd_swap_occupied *adsl_swoc_w1;  /* swap file occupied bits */
   struct dsd_swap_occupied **aadsl_swoc_ce;  /* end of chain swap file occupied bits */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#ifdef B141229
#ifndef HL_UNIX
   OVERLAPPED dsl_olstruct;                 /* structure for overlapped IO */
#endif
#endif

#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (vpp_userfld) {
     ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
   }
   struct dsd_swap_stor_aux *ADSL_SS_AUX = NULL;
#endif

   if (adsp_assr1->iec_swsc != ied_swsc_open) {  /* open swap storage  */
     goto p_sw_st_cont;                     /* continue swap storage   */
   }

   /* request open                                                     */
#ifndef HL_UNIX
#define ADSL_LOCONF_1_G adsg_loconf_1_inuse
#else
#define ADSL_LOCONF_1_G (&dss_loconf_1)
#endif
   if (ADSL_LOCONF_1_G->imc_max_swap_size == 0) {  /* <max-swap-size> in 64 KB units */
     adsp_assr1->iec_swsr = ied_swsr_not_conf;  /* swap storage not configured */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;
   }
#undef ADSL_LOCONF_1_G

   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + sizeof(struct dsd_swap_stor_aux) );  /* auxiliary field */
   memset( adsl_auxf_1_w1, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_swap_stor_aux) );
   adsl_auxf_1_w1->iec_auxf_def = ied_auxf_swap_stor;  /* swap storage */
   adsl_auxf_1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* current Server-Data-Hook */
#ifdef HL_UNIX
#ifdef HELP_DEBUG
   ADSL_SS_AUX = (struct dsd_swap_stor_aux *) (adsl_auxf_1_w1 + 1);
#endif
#ifndef HELP_DEBUG
#define ADSL_SS_AUX ((struct dsd_swap_stor_aux *) (adsl_auxf_1_w1 + 1))
#endif
   ADSL_SS_AUX->imc_fd_file = -1;           /* file-descriptor of open swap file */
#ifndef HELP_DEBUG
#undef ADSL_SS_AUX
#endif
#endif
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain       */
   adsp_assr1->vpc_aux_swap_stor_handle = adsl_auxf_1_w1;  /* handle of swap storage */
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_sw_st_cont:                            /* continue swap storage   */
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) adsp_assr1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   if (adsl_auxf_1_w1 == NULL) {            /* handle not passed       */
     adsp_assr1->iec_swsr = ied_swsr_param_error;  /* parameter error  */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_swap_stor) {  /* swap storage */
     adsp_assr1->iec_swsr = ied_swsr_param_error;  /* parameter error  */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#ifdef HELP_DEBUG
   ADSL_SS_AUX = (struct dsd_swap_stor_aux *) (adsl_auxf_1_w1 + 1);
#endif
   switch (adsp_assr1->iec_swsc) {          /* swap storage command    */
     case ied_swsc_close:                   /* close swap storage      */
#ifdef B141229
       goto p_sw_st_close_40;               /* close swap storage      */
#endif
     case ied_swsc_clear_and_close:         /* clear content and close swap storage */
       goto p_sw_st_close_00;               /* clear and close swap storage */
     case ied_swsc_get_buf:                 /* acquire swap storage buffer */
       goto p_sw_st_get_buf_00;             /* acquire swap storage buffer */
     case ied_swsc_read:                    /* read swap storage buffer */
     case ied_swsc_write:                   /* write swap storage buffer */
     case ied_swsc_release:                 /* release swap storage chunk */
       goto p_sw_st_access_00;              /* access swap storage buffer */
   }

   adsp_assr1->iec_swsr = ied_swsr_param_error;  /* parameter error    */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

#ifndef HELP_DEBUG
#define ADSL_SS_AUX ((struct dsd_swap_stor_aux *) (adsl_auxf_1_w1 + 1))
#endif

#ifdef B141229
   p_sw_st_close_00:                        /* clear and close swap storage */
   adsl_ss_ch_w1 = ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   while (adsl_ss_ch_w1) {                  /* loop over chain of swap storage chunks */
     iml1 = D_SWAP_STOR_CHAIN_CHUNKS;
     do {                                   /* loop to free all chain elements */
       iml1--;                              /* decrement index         */
       if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr) {  /* storage address when in memory */
         memset( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr, 0, LEN_BLOCK_SWAP );  /* erase memory */
       }
     } while (iml1 > 0);
     adsl_ss_ch_w1 = adsl_ss_ch_w1->adsc_next;  /* get next in chain   */
   }

   p_sw_st_close_40:                        /* close swap storage      */
#endif

   p_sw_st_close_00:                        /* close swap storage      */
   adsl_auxf_1_w1->iec_auxf_def = (enum ied_auxf_def) 0;  /* to prevent invalid access */
   adsl_ss_ch_w1 = ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   achl_w1 = NULL;                          /* no clear buffer for write */
   while (adsl_ss_ch_w1) {                  /* loop over chain of swap storage chunks */
     iml1 = D_SWAP_STOR_CHAIN_CHUNKS;
     do {                                   /* loop to free all chain elements */
       iml1--;                              /* decrement index         */
       if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr) {  /* storage address when in memory */
#ifdef B141228
         free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr );  /* free storage */
#endif
         bol1 = FALSE;                      /* not buffer saved        */
         if (adsp_assr1->iec_swsc == ied_swsc_clear_and_close) {  /* clear content and close swap storage */
           memset( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr, 0, LEN_BLOCK_SWAP );  /* clear memory */
           if (achl_w1 == NULL) {           /* no clear buffer for write */
             achl_w1 = adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr;  /* save this block */
             bol1 = TRUE;                   /* buffer saved            */
           }
         }
         if (bol1 == FALSE) {               /* not buffer saved        */
           iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
           if (iml_rc < 0) {                /* error occured           */
             m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                             __LINE__, iml_rc );
           }
#define AC_STOR_G (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)
           *((void **) AC_STOR_G) = dss_swap_stor_ctrl.ac_free;  /* chain of free storage pieces */
           dss_swap_stor_ctrl.ac_free = AC_STOR_G;  /* new chain of free storage pieces */
#undef AC_STOR_G
           dss_swap_stor_ctrl.imc_mem_free++;  /* number of chunks in memory free */
           iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
           if (iml_rc < 0) {                /* error occured           */
             m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                             __LINE__, iml_rc );
           }
         }
       }
       if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file >= 0) {  /* index on file (RBA), -1 when not in file */
         iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                           __LINE__, iml_rc );
         }
         if (adsp_assr1->iec_swsc == ied_swsc_clear_and_close) {  /* clear content and close swap storage */
           if (achl_w1 == NULL) {           /* not yet free buffer saved */
             achl_w1 = m_swap_stor_acq_mem( TRUE );
             memset( achl_w1, 0, LEN_BLOCK_SWAP );  /* clear memory    */
           }
         } else {
           bol_rc = m_swap_stor_file_mark_free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file, TRUE );
         }
         iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                        /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                           __LINE__, iml_rc );
         }
         if (adsp_assr1->iec_swsc == ied_swsc_clear_and_close) {  /* clear content and close swap storage */
           bol_rc = m_swap_stor_file_write( ADSL_AUX_CF1->adsc_hco_wothr,
#ifdef HL_UNIX
                                            &ADSL_SS_AUX->imc_fd_file,  /* file-descriptor of open swap file */
#endif
                                            adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file,
                                            achl_w1 );
           bol_rc = m_swap_stor_file_mark_free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file, FALSE );
         }
       }
     } while (iml1 > 0);
     adsl_ss_ch_w2 = adsl_ss_ch_w1;         /* save this element       */
     adsl_ss_ch_w1 = adsl_ss_ch_w1->adsc_next;  /* get next in chain   */
#ifdef B141228
     free( adsl_ss_ch_w2);                  /* free this element       */
#endif
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
     *((void **) adsl_ss_ch_w2) = dss_swap_stor_ctrl.adsc_ss_ch_free;  /* chain of free swap storage chunks */
     dss_swap_stor_ctrl.adsc_ss_ch_free = adsl_ss_ch_w2;  /* new chain of free swap storage chunks */
     if (achl_w1) {                         /* free buffer saved       */
       *((void **) achl_w1) = dss_swap_stor_ctrl.ac_free;  /* chain of free storage pieces */
       dss_swap_stor_ctrl.ac_free = achl_w1;  /* new chain of free storage pieces */
       dss_swap_stor_ctrl.imc_mem_free++;  /* number of chunks in memory free */
     }
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                        /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
   }
#ifdef HL_UNIX
   if (ADSL_SS_AUX->imc_fd_file >= 0) {     /* file-descriptor of open swap file */
     close( ADSL_SS_AUX->imc_fd_file );
   }
#endif
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
   if (adsl_auxf_1_w1 == ADSL_CONN1_G->adsc_auxf_1) {  /* check chain  */
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
   } else {
     adsl_auxf_1_w2 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain         */
     if (adsl_auxf_1_w2 == NULL) {
       goto p_sw_st_close_80;               /* return error            */
     }
     while (adsl_auxf_1_w1 != adsl_auxf_1_w2->adsc_next) {
       adsl_auxf_1_w2 = adsl_auxf_1_w2->adsc_next;
       if (adsl_auxf_1_w2 == NULL) {
         goto p_sw_st_close_80;             /* return error            */
       }
     }
     adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1->adsc_next;
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   free( adsl_auxf_1_w1 );                  /* free auxiliary field    */
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_sw_st_close_80:                        /* return error            */
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d illogic",
                   __LINE__ );
   adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error       */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_sw_st_get_buf_00:                      /* acquire swap storage buffer */
#ifndef HL_UNIX
#define ADSL_LOCONF_1_G adsg_loconf_1_inuse
#else
#define ADSL_LOCONF_1_G (&dss_loconf_1)
#endif
   if (((dss_swap_stor_ctrl.imc_mem_max - dss_swap_stor_ctrl.imc_mem_free)
           + dss_swap_stor_ctrl.imc_file_cur)  /* number of chunks on file currently */
         >= ADSL_LOCONF_1_G->imc_max_swap_size) {
     adsp_assr1->iec_swsr = ied_swsr_full;  /* swap storage is full    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#undef ADSL_LOCONF_1_G
   iml1 = adsp_assr1->imc_index;            /* index of dataset / chunk */
   if (iml1 != ADSL_SS_AUX->imc_index_filled) {  /* index of dataset / chunks filled */
     adsp_assr1->iec_swsr = ied_swsr_access_out_of_order;  /* access out of order */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
   dss_swap_stor_ctrl.ilc_no_acq++;         /* number of chunks acquired */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   adsl_ss_ch_w1 = ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   aadsl_ss_ch_ch = &ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   while (iml1 >= D_SWAP_STOR_CHAIN_CHUNKS) {  /* not in this chunk    */
     if (adsl_ss_ch_w1 == NULL) {           /* not contiguous          */
       adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error     */
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
         goto p_trace_00;                   /* output WSP-trace        */
       }
       return TRUE;                         /* all done                */
     }
     aadsl_ss_ch_ch = &adsl_ss_ch_w1->adsc_next;  /* chain of swap storage chunks */
     adsl_ss_ch_w1 = adsl_ss_ch_w1->adsc_next;  /* get next in chain   */
     iml1 -= D_SWAP_STOR_CHAIN_CHUNKS;      /* number in next chunk    */
   }
   if (adsl_ss_ch_w1 == NULL) {             /* not yet memory for chain */
#ifdef B141228
     adsl_ss_ch_w1 = (dsd_swap_stor_chain *) malloc( sizeof(dsd_swap_stor_chain) );
#endif
     if (iml1 != 0) {                       /* not first piece in this chunk */
       adsp_assr1->iec_swsr = ied_swsr_access_out_of_order;  /* access out of order */
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
         goto p_trace_00;                   /* output WSP-trace        */
       }
       return TRUE;                         /* all done                */
     }
     adsl_ss_ch_w1 = m_swap_stor_acq_ss_ch();
     if (adsl_ss_ch_w1 == NULL) {           /* out of memory           */
       adsp_assr1->iec_swsr = ied_swsr_nomem;  /* out of memory        */
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
         goto p_trace_00;                   /* output WSP-trace        */
       }
       return TRUE;                         /* all done                */
     }
     iml2 = D_SWAP_STOR_CHAIN_CHUNKS;
     do {                                   /* loop to initialize chain element */
       iml2--;                              /* decrement index         */
       adsl_ss_ch_w1->dsrc_ss_c[ iml2 ].achc_stor_addr = NULL;  /* storage address when in memory */
       adsl_ss_ch_w1->dsrc_ss_c[ iml2 ].imc_index_on_file = -1;  /* index on file (RBA), -1 when not in file */
     } while (iml2 > 0);
     adsl_ss_ch_w1->adsc_next = NULL;       /* clear chain             */
     *aadsl_ss_ch_ch = adsl_ss_ch_w1;       /* append to chain of swap storage chunks */
   }
   if (   (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)  /* storage address when in memory */
       || (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file >= 0)) {  /* index on file (RBA), -1 when not in file */
     adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error     */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr
     = adsp_assr1->achc_stor_addr           /* storage address         */
#ifdef B141228
       = (char *) malloc( LEN_BLOCK_SWAP );  /* length block of swap area */
#endif
       = m_swap_stor_acq_mem( FALSE );
   if (adsp_assr1->achc_stor_addr == NULL) {  /* out of memory         */
     adsp_assr1->iec_swsr = ied_swsr_nomem;  /* out of memory          */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   ADSL_SS_AUX->imc_index_filled++;         /* index of dataset / chunks filled */
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_sw_st_access_00:                       /* access swap storage buffer */
   adsl_ss_ch_w1 = ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   iml1 = adsp_assr1->imc_index;            /* index of dataset / chunk */
   while (TRUE) {
     if (adsl_ss_ch_w1 == NULL) {           /* not contiguous          */
       adsp_assr1->iec_swsr = ied_swsr_access_out_of_order;  /* access out of order */
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
         goto p_trace_00;                   /* output WSP-trace        */
       }
       return TRUE;                         /* all done                */
     }
     if (iml1 < D_SWAP_STOR_CHAIN_CHUNKS) {  /* in this chunk          */
       break;
     }
     adsl_ss_ch_w1 = adsl_ss_ch_w1->adsc_next;
     iml1 -= D_SWAP_STOR_CHAIN_CHUNKS;      /* number in next chunk    */
   }
   if (   (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr == NULL)  /* storage address when in memory */
       && (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file < 0)) {  /* index on file (RBA), -1 when not in file */
     adsp_assr1->iec_swsr = ied_swsr_inv_access;  /* invalid access    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   if (adsp_assr1->iec_swsc == ied_swsc_write) {  /* write swap storage buffer */
     goto p_sw_st_write_00;                 /* write chunk swap storage */
   } else if (adsp_assr1->iec_swsc == ied_swsc_read) {  /* read swap storage buffer */
#ifdef B141229
     adsp_assr1->achc_stor_addr             /* storage address         */
       = adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr;  /* storage address when in memory */
#endif
#define AC_STOR_G (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)
     if (AC_STOR_G == NULL) {               /* memory not in storage   */
       iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                         __LINE__, iml_rc );
       }
       AC_STOR_G = m_swap_stor_acq_mem( TRUE );
       dss_swap_stor_ctrl.ilc_no_file_read++;  /* number of reads from swap storage file */
       iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                         __LINE__, iml_rc );
       }
       bol_rc = m_swap_stor_file_read( ADSL_AUX_CF1->adsc_hco_wothr,
#ifdef HL_UNIX
                                       ADSL_SS_AUX->imc_fd_file,  /* file-descriptor of open swap file */
#endif
                                       adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file,
                                       AC_STOR_G );
       if (bol_rc == FALSE) {               /* error occured           */
         adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error */
       }
     }
     adsp_assr1->achc_stor_addr = AC_STOR_G;  /* storage address       */
#undef AC_STOR_G
   } else if (adsp_assr1->iec_swsc == ied_swsc_release) {  /* release swap storage chunk */
#ifdef B141228
     free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr );  /* storage address when in memory */
#endif
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                        /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
     if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file >= 0) {  /* index on file (RBA), -1 when not in file */
       bol_rc = m_swap_stor_file_mark_free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file, TRUE );
       if (bol_rc == FALSE) {               /* error occured           */
         adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error */
       }
       adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file = -1;  /* index on file (RBA), -1 when not in file */
     }
#define AC_STOR_G (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)
     if (AC_STOR_G) {                       /* memory in storage       */
       *((void **) AC_STOR_G) = dss_swap_stor_ctrl.ac_free;  /* chain of free storage pieces */
       dss_swap_stor_ctrl.ac_free = AC_STOR_G;  /* new chain of free storage pieces */
       dss_swap_stor_ctrl.imc_mem_free++;   /* number of chunks in memory free */
       AC_STOR_G = NULL;                    /* no more memory associated */
     }
#undef AC_STOR_G
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                        /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
#ifdef B141229
     adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr = NULL;  /* storage address when in memory */
#endif
   }
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_sw_st_write_00:                        /* write chunk swap storage */
   if (adsp_assr1->achc_stor_addr != adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr) {
     adsp_assr1->iec_swsr = ied_swsr_param_error;  /* parameter error  */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#ifndef HL_UNIX
#define ADSL_LOCONF_1_G adsg_loconf_1_inuse
#else
#define ADSL_LOCONF_1_G (&dss_loconf_1)
#endif
   if ((dss_swap_stor_ctrl.imc_mem_max - dss_swap_stor_ctrl.imc_mem_free + NO_SWAP_STOR_OVERHEAD)
         <= ADSL_LOCONF_1_G->imc_swap_mem_size) {  /* <size-swap-in-memory> in 64 KB units */
     adsp_assr1->iec_swsr = ied_swsr_ok;    /* o.k.                    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   if (dss_swap_stor_ctrl.imc_file_cur      /* number of chunks on file currently */
         >= (ADSL_LOCONF_1_G->imc_max_swap_size - ADSL_LOCONF_1_G->imc_swap_mem_size)) {
     adsp_assr1->iec_swsr = ied_swsr_full;  /* swap storage is full    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#ifndef HL_UNIX
   if (dss_swap_stor_ctrl.dsl_h_file == INVALID_HANDLE_VALUE) {
     adsp_assr1->iec_swsr = ied_swsr_full;  /* swap storage is full    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#endif
#ifdef HL_UNIX
   if (dss_swap_stor_ctrl.imc_fd_file < 0) {
     adsp_assr1->iec_swsr = ied_swsr_full;  /* swap storage is full    */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
#endif
#undef ADSL_LOCONF_1_G

   /* search free hole in swap file                                    */
// ill_rba = 0;                             /* RBA for access to disk  */
   iml_index_file = 0;                      /* index of dataset / access file */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }

//struct dsd_swap_occupied {                  /* swap file occupied bits */
   adsl_swoc_w1 = dss_swap_stor_ctrl.adsc_swap_occupied;  /* chain swap file occupied bits */
   aadsl_swoc_ce = &dss_swap_stor_ctrl.adsc_swap_occupied;  /* end of chain swap file occupied bits */
   if (adsl_swoc_w1 == NULL) {              /* need to create first element */
     goto p_sw_st_write_40;                 /* make new element swap file occupied bits */
   }
#ifdef XYZ1
   while (((long long int) adsl_swoc_w1->avpc_occupied)
            >= ((long long int) ((char *) (adsl_swoc_w1 + 1) + LEN_SWAP_OCCUPIED))) {
     *aadsl_swoc_ce = adsl_swoc_w1;         /* end of chain swap file occupied bits */
//   ill_rba += (LEN_SWAP_OCCUPIED << 3) << SHIFT_BLOCK_SWAP;  /* RBA for access to disk */
     iml_index_file += LEN_SWAP_OCCUPIED << 3;  /* index of dataset / access file */
     adsl_swoc_w1 = adsl_swoc_w1->adsc_next;  /* get next in chain     */
     if (adsl_swoc_w1 == NULL) {            /* need to create next element */
       goto p_sw_st_write_40;               /* make new element swap file occupied bits */
     }
   }
#endif
   p_sw_st_write_20:                        /* search in swap file occupied bits */
   aadsl_swoc_ce = &adsl_swoc_w1->adsc_next;  /* end of chain swap file occupied bits */
   if (((long long int) adsl_swoc_w1->avpc_occupied)
         < ((long long int) ((char *) (adsl_swoc_w1 + 1) + LEN_SWAP_OCCUPIED))) {
     goto p_sw_st_write_28;                 /* entry swap file occupied bits not totally filled */
   }

   p_sw_st_write_24:                        /* all entries occupied    */
// ill_rba += (LEN_SWAP_OCCUPIED << 3) << SHIFT_BLOCK_SWAP;  /* RBA for access to disk */
   iml_index_file += LEN_SWAP_OCCUPIED << 3;  /* index of dataset / access file */
   adsl_swoc_w1 = adsl_swoc_w1->adsc_next;  /* get next in chain       */
   if (adsl_swoc_w1) {                      /* found next element      */
     goto p_sw_st_write_20;                 /* search in swap file occupied bits */
   }
   goto p_sw_st_write_40;                   /* make new element swap file occupied bits */

   p_sw_st_write_28:                        /* entry swap file occupied bits not totally filled */
   /* check here if we have entry with one bit NULL                    */
#ifdef XYZ1
   vpl_w1 = (void *) adsl_swoc_w1->avpc_occupied;
   vpl_w2 = (void *) ((char *) (adsl_swoc_w1 + 1) + LEN_SWAP_OCCUPIED);
   while (   ((long long int) vpl_w1) < ((long long int) vpl_w2)) {
   }
#endif
   achl_w1 = (char *) adsl_swoc_w1->avpc_occupied;
   achl_w2 = (char *) ((char *) (adsl_swoc_w1 + 1) + LEN_SWAP_OCCUPIED);
   while (   (achl_w1 < achl_w2)
          && (*((void **) achl_w1) == vps_ones)) {
     achl_w1 += sizeof(void *);
   }
   adsl_swoc_w1->avpc_occupied = (void **) achl_w1;
   if (achl_w1 >= achl_w2) {                /* all entries occupied    */
     goto p_sw_st_write_24;                 /* all entries occupied    */
   }
   iml_index_file += (achl_w1 - ((char *) (adsl_swoc_w1 + 1))) << 3;  /* index of dataset / access file */
   while (*((unsigned char *) achl_w1) == 0XFF) {
     achl_w1++;
     iml_index_file += 8;                   /* index of dataset / access file */
   }
   chl_l = *achl_w1;                        /* get byte with one bit NULL */
   iml2 = 0;
   while (((signed char) chl_l) < 0) {      /* most significant bit set */
     iml2++;                                /* count bit               */
     chl_l <<= 1;                           /* shift one bit           */
   }
   iml_index_file += iml2;                  /* index of dataset / access file */
   *achl_w1 |= 1 << (8 - 1 - iml2);         /* this entry occupied now */
   goto p_sw_st_write_48;                   /* position swap file calculated */

   p_sw_st_write_40:                        /* make new element swap file occupied bits */
   adsl_swoc_w1 = (struct dsd_swap_occupied *) malloc( sizeof(struct dsd_swap_occupied) + LEN_SWAP_OCCUPIED );
   if (adsl_swoc_w1 == NULL) {              /* out of memory           */
     dss_swap_stor_ctrl.ilc_out_of_memory++;  /* count times out of memory */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
     adsp_assr1->iec_swsr = ied_swsr_nomem;  /* out of memory          */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   memset( adsl_swoc_w1, 0, sizeof(struct dsd_swap_occupied) + LEN_SWAP_OCCUPIED );
   *(unsigned char *) (adsl_swoc_w1 + 1) = 0X80;  /* first entry occupied */
   adsl_swoc_w1->avpc_occupied = (void **) (adsl_swoc_w1 + 1);  /* occupied till here */
   *aadsl_swoc_ce = adsl_swoc_w1;           /* end of chain swap file occupied bits */
// dss_swap_stor_ctrl.ilc_no_acq++;         /* number of chunks acquired */

   p_sw_st_write_48:                        /* position swap file calculated */
   dss_swap_stor_ctrl.imc_file_cur++;       /* number of chunks on file currently */
   if (dss_swap_stor_ctrl.imc_file_cur > dss_swap_stor_ctrl.imc_file_max) {  /* number of chunks on file maximum */
     dss_swap_stor_ctrl.imc_file_max = dss_swap_stor_ctrl.imc_file_cur;  /* number of chunks on file maximum */
   }
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }

   adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file = iml_index_file;  /* index on file (RBA), -1 when not in file */
#ifdef B141229
   memset( &dsl_olstruct, 0, sizeof(OVERLAPPED) );  /* structure for overlapped IO */
   dsl_olstruct.Offset = (DWORD) (iml_index_file << SHIFT_BLOCK_SWAP);
   dsl_olstruct.OffsetHigh = (DWORD) (iml_index_file >> (32 - SHIFT_BLOCK_SWAP));
   dsl_olstruct.hEvent = ADSL_AUX_CF1->adsc_hco_wothr->dsc_event.dsc_heve_1;
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   bol_rc = WriteFile( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                       adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr,  /* storage address when in memory */
                       LEN_BLOCK_SWAP,
                       NULL,
                       &dsl_olstruct );
   uml_error = GetLastError();
   if (   (bol_rc != FALSE)                 /* error occured           */
       || (uml_error != ERROR_IO_PENDING)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR WriteFile() returned %d error %d.",
                     __LINE__,
                     bol_rc, uml_error );
   }
   bol_rc = GetOverlappedResult( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                                 &dsl_olstruct,
                                 &uml_write,
                                 TRUE );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR GetOverlappedResult() returned error %d.",
                     __LINE__,
                     GetLastError() );
   }
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#endif
#define AC_STOR_G (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)
   bol_rc = m_swap_stor_file_write( ADSL_AUX_CF1->adsc_hco_wothr,
#ifdef HL_UNIX
                                    &ADSL_SS_AUX->imc_fd_file,  /* file-descriptor of open swap file */
#endif
                                    iml_index_file,
                                    AC_STOR_G );
//#ifdef XYZ1
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
   *((void **) AC_STOR_G) = dss_swap_stor_ctrl.ac_free;  /* chain of free storage pieces */
   dss_swap_stor_ctrl.ac_free = AC_STOR_G;  /* new chain of free storage pieces */
#undef AC_STOR_G
   dss_swap_stor_ctrl.imc_mem_free++;       /* number of chunks in memory free */
   if (bol_rc) {                            /* write succeeded         */
     dss_swap_stor_ctrl.ilc_no_file_write++;  /* number of writes to swap storage file */
   }
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr = NULL;  /* storage address when in memory */
//#endif
   adsp_assr1->iec_swsr = ied_swsr_ok;      /* o.k.                    */
   if (bol_rc) {                            /* write succeeded         */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
       goto p_trace_00;                     /* output WSP-trace        */
     }
     return TRUE;                           /* all done                */
   }
   adsp_assr1->iec_swsr = ied_swsr_int_error;  /* internal error       */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_AUX) {
     goto p_trace_00;                       /* output WSP-trace        */
   }
   return TRUE;                             /* all done                */

   p_trace_00:                              /* output WSP-trace        */
   switch (adsp_assr1->iec_swsc) {          /* swap storage command    */
     case ied_swsc_open:                    /* open swap storage       */
       achl_w1 = "ied_swsc_open";
       break;
     case ied_swsc_close:                   /* close swap storage      */
       achl_w1 = "ied_swsc_close";
       break;
     case ied_swsc_clear_and_close:         /* clear content and close swap storage */
       achl_w1 = "ied_swsc_clear_and_close";
       break;
     case ied_swsc_get_buf:                 /* acquire swap storage buffer */
       achl_w1 = "ied_swsc_get_buf";
       break;
     case ied_swsc_read:                    /* read swap storage buffer */
       achl_w1 = "ied_swsc_read";
       break;
     case ied_swsc_write:                   /* write swap storage buffer */
       achl_w1 = "ied_swsc_write";
       break;
     case ied_swsc_release:                 /* release swap storage chunk */
       achl_w1 = "ied_swsc_release";
       break;
     default:
       achl_w1 = "* unknown *";
       break;
   }
   switch (adsp_assr1->iec_swsr) {          /* return code swap storage command */
     case ied_swsr_ok:                      /* o.k.                    */
       achl_w2 = "ied_swsr_ok";
       break;
     case ied_swsr_not_conf:                /* swap storage not configured */
       achl_w2 = "ied_swsr_not_conf";
       break;
     case ied_swsr_full:                    /* swap storage is full    */
       achl_w2 = "ied_swsr_full";
       break;
     case ied_swsr_param_error:             /* parameter error         */
       achl_w2 = "ied_swsr_param_error";
       break;
     case ied_swsr_chunk_not_found:         /* chunk not found         */
       achl_w2 = "ied_swsr_chunk_not_found";               /* chunk not found         */
       break;
     case ied_swsr_nomem:                   /* out of memory           */
       achl_w2 = "ied_swsr_nomem";
       break;
     case ied_swsr_inv_access:              /* invalid access          */
       achl_w2 = "ied_swsr_inv_access";
       break;
     case ied_swsr_int_error:               /* internal error          */
       achl_w2 = "ied_swsr_int_error";
       break;
     case ied_swsr_access_out_of_order:     /* access out of order     */
       achl_w2 = "ied_swsr_access_out_of_order";
       break;
     default:
       achl_w2 = "* unknown *";
       break;
   }
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXSWS1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
   iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                   "SWAP-STOR com=%s ret=%s achc_stor_addr=%p imc_index=%d/0X%X.",
                   achl_w1, achl_w2,
                   adsp_assr1->achc_stor_addr,
                   adsp_assr1->imc_index, adsp_assr1->imc_index );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
   ADSL_WTR_G1->imc_length = iml1;          /* length of text / data   */
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
   /* output parameter area                                            */
   achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   memcpy( ADSL_WTR_G2 + 1, adsp_assr1, sizeof(struct dsd_aux_swap_stor_req_1) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;   /* binary data passed      */
   ADSL_WTR_G2->achc_content                /* content of text / data  */
     = (char *) (ADSL_WTR_G2 + 1);
   ADSL_WTR_G2->imc_length = sizeof(struct dsd_aux_swap_stor_req_1);  /* length of text / data */
   ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;    /* append to chain         */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return TRUE;                             /* all done                */
#ifndef HELP_DEBUG
#undef ADSL_SS_AUX
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_aux_swap_stor_req_1()                                       */

#ifndef HL_UNIX
/** write a chunk to the SWAP-STOR file                                */
static BOOL m_swap_stor_file_write( struct dsd_hco_wothr *adsp_hco_wothr,
                                    int imp_index, void * ap_buffer ) {
   BOOL       bol_rc;                       /* return code             */
   DWORD      uml_write;                    /* return bytes written    */
   DWORD      uml_error;                    /* error code returned     */
   OVERLAPPED dsl_olstruct;                 /* structure for overlapped IO */

   memset( &dsl_olstruct, 0, sizeof(OVERLAPPED) );  /* structure for overlapped IO */
   dsl_olstruct.Offset = (DWORD) (imp_index << SHIFT_BLOCK_SWAP);
   dsl_olstruct.OffsetHigh = (DWORD) (imp_index >> (32 - SHIFT_BLOCK_SWAP));
   dsl_olstruct.hEvent = adsp_hco_wothr->dsc_event.dsc_heve_1;
   m_hco_wothr_blocking( adsp_hco_wothr );  /* mark thread blocking    */
   bol_rc = WriteFile( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                       ap_buffer,           /* storage address when in memory */
                       LEN_BLOCK_SWAP,
                       NULL,
                       &dsl_olstruct );
   uml_error = GetLastError();
   if (   (bol_rc != FALSE)                 /* error occured           */
       || (uml_error != ERROR_IO_PENDING)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR WriteFile() returned %d error %d.",
                     __LINE__,
                     bol_rc, uml_error );
   }
   bol_rc = GetOverlappedResult( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                                 &dsl_olstruct,
                                 &uml_write,
                                 TRUE );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR GetOverlappedResult() returned error %d.",
                     __LINE__,
                     GetLastError() );
   }
   m_hco_wothr_active( adsp_hco_wothr, FALSE );  /* mark thread active */
   return TRUE;                             /* all done                */
} /* end m_swap_stor_file_write()                                      */

/** read a chunk from the SWAP-STOR file                               */
static BOOL m_swap_stor_file_read( struct dsd_hco_wothr *adsp_hco_wothr,
                                   int imp_index, void * ap_buffer ) {
   BOOL       bol_rc;                       /* return code             */
   DWORD      uml_write;                    /* return bytes written    */
   DWORD      uml_error;                    /* error code returned     */
   OVERLAPPED dsl_olstruct;                 /* structure for overlapped IO */

   memset( &dsl_olstruct, 0, sizeof(OVERLAPPED) );  /* structure for overlapped IO */
   dsl_olstruct.Offset = (DWORD) (imp_index << SHIFT_BLOCK_SWAP);
   dsl_olstruct.OffsetHigh = (DWORD) (imp_index >> (32 - SHIFT_BLOCK_SWAP));
   dsl_olstruct.hEvent = adsp_hco_wothr->dsc_event.dsc_heve_1;
   m_hco_wothr_blocking( adsp_hco_wothr );  /* mark thread blocking    */
   bol_rc = ReadFile( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                      ap_buffer,            /* storage address when in memory */
                      LEN_BLOCK_SWAP,
                      NULL,
                      &dsl_olstruct );
   uml_error = GetLastError();
   if (   (bol_rc != FALSE)                 /* error occured           */
       || (uml_error != ERROR_IO_PENDING)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR ReadFile() returned %d error %d.",
                     __LINE__,
                     bol_rc, uml_error );
   }
   bol_rc = GetOverlappedResult( dss_swap_stor_ctrl.dsl_h_file,  /* handle of open swap file */
                                 &dsl_olstruct,
                                 &uml_write,
                                 TRUE );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR GetOverlappedResult() returned error %d.",
                     __LINE__,
                     GetLastError() );
   }
   m_hco_wothr_active( adsp_hco_wothr, FALSE );  /* mark thread active */
   return TRUE;                             /* all done                */
} /* end m_swap_stor_file_read()                                       */
#endif
#ifdef HL_UNIX
/** write a chunk to the SWAP-STOR file                                */
static BOOL m_swap_stor_file_write( struct dsd_hco_wothr *adsp_hco_wothr,
                                    int *aimp_fd_file,  /* file-descriptor of open swap file */
                                    int imp_index, void * ap_buffer ) {
   int        iml_rc;                       /* return code             */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "HWSPM0xxW l%05d m_swap_stor_file_write() *aimp_fd_file=%d imp_index=%d ap_buffer=%p.",
                   __LINE__, *aimp_fd_file, imp_index, ap_buffer );
//#endif
   if (*aimp_fd_file >= 0) {                /* file-descriptor of open swap file */
     goto p_wr_20;                          /* continue write          */
   }
   if (dss_swap_stor_ctrl.achc_file_name == NULL) {
     return FALSE;                          /* return error            */
   }
   *aimp_fd_file = open( dss_swap_stor_ctrl.achc_file_name,
#ifdef HL_LINUX
//                       O_RDWR | O_DIRECT,
                         O_RDWR,
#endif
#ifndef HL_LINUX
                         O_RDWR,
#endif
                         S_IRUSR | S_IWUSR );
   if (*aimp_fd_file < 0) {                 /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR open( %s , ... ) returned error %d %d.",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name,
                     *aimp_fd_file, errno );
     return FALSE;                          /* return error            */
   }

   p_wr_20:                                 /* continue write          */
#ifndef D_NO_STAT64
   iml_rc = lseek64( *aimp_fd_file,
                     (HL_LONGLONG) (imp_index << SHIFT_BLOCK_SWAP),
                     SEEK_SET );
#else
   iml_rc = lseek( *aimp_fd_file,
                   (HL_LONGLONG) (imp_index << SHIFT_BLOCK_SWAP),
                   SEEK_SET );
#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR lseek64( %s , ... ) returned error %d %d.",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name,
                     iml_rc, errno );
     return FALSE;                          /* return error            */
   }
   iml_rc = write( *aimp_fd_file,
                   ap_buffer,               /* storage address when in memory */
                   LEN_BLOCK_SWAP );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR write( %s , ... ) returned error %d %d.",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name,
                     iml_rc, errno );
     return FALSE;                          /* return error            */
   }
   return TRUE;                             /* all done                */
} /* end m_swap_stor_file_write()                                      */

/** read a chunk from the SWAP-STOR file                               */
static BOOL m_swap_stor_file_read( struct dsd_hco_wothr *adsp_hco_wothr,
                                   int imp_fd_file,  /* file-descriptor of open swap file */
                                   int imp_index, void * ap_buffer ) {
   int        iml_rc;                       /* return code             */

   if (imp_fd_file < 0) {                   /* file-descriptor of open swap file */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR file %s not opened",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name );
     return FALSE;                          /* return error            */
   }
#ifndef D_NO_STAT64
   iml_rc = lseek64( imp_fd_file,
                     (HL_LONGLONG) (imp_index << SHIFT_BLOCK_SWAP),
                     SEEK_SET );
#else
   iml_rc = lseek( imp_fd_file,
                   (HL_LONGLONG) (imp_index << SHIFT_BLOCK_SWAP),
                   SEEK_SET );
#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR lseek64( %s , ... ) returned error %d %d.",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name,
                     iml_rc, errno );
     return FALSE;                          /* return error            */
   }
   iml_rc = read( imp_fd_file,
                  ap_buffer,                /* storage address when in memory */
                  LEN_BLOCK_SWAP );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR read( %s , ... ) returned error %d %d.",
                     __LINE__,
                     dss_swap_stor_ctrl.achc_file_name,
                     iml_rc, errno );
     return FALSE;                          /* return error            */
   }
   return TRUE;                             /* all done                */
} /* end m_swap_stor_file_read()                                       */
#endif

/** mark a chunk from the SWAP-STOR file as free                       */
static BOOL m_swap_stor_file_mark_free( int imp_index, BOOL bop_locked ) {
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_swap_occupied *adsl_swoc_w1;  /* swap file occupied bits */

   if (bop_locked == FALSE) {               /* not in Critical Section */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
   }
   adsl_swoc_w1 = dss_swap_stor_ctrl.adsc_swap_occupied;  /* chain swap file occupied bits */
   if (adsl_swoc_w1 == NULL) {              /* no element found        */
     goto p_error_00;                       /* error occured           */
   }
   iml1 = imp_index;                        /* get the index           */
   while (iml1 > (LEN_SWAP_OCCUPIED * 8)) {  /* get next block occupied */
     adsl_swoc_w1 = adsl_swoc_w1->adsc_next;  /* get next in chain     */
     if (adsl_swoc_w1 == NULL) {            /* no element found        */
       goto p_error_00;                     /* error occured           */
     }
     iml1 -= LEN_SWAP_OCCUPIED * 8;         /* index in next part      */
   }
   achl_w1 = (char *) (adsl_swoc_w1 + 1) + (iml1 >> 3);
   *achl_w1 &= -1 - (1 << (8 - 1 - (iml1 & 0X07)));
   achl_w1 = (char *) (adsl_swoc_w1 + 1) + ((iml1 >> 3) & (0 - sizeof(void *)));
   if (achl_w1 < ((char *) adsl_swoc_w1->avpc_occupied)) {
     adsl_swoc_w1->avpc_occupied = (void **) achl_w1;  /* occupied till here */
   }
   dss_swap_stor_ctrl.imc_file_cur--;       /* number of chunks on file currently */
   if (bop_locked == FALSE) {               /* not in Critical Section */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
   }
   return TRUE;                             /* all done                */

   p_error_00:                              /* error occured           */
   if (bop_locked == FALSE) {               /* not in Critical Section */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
   }
   return FALSE;                            /* return error            */
} /* end m_swap_stor_file_mark_free()                                  */

/** acquire a piece of memory for swap storage, size LEN_BLOCK_SWAP    */
static char * m_swap_stor_acq_mem( BOOL bop_locked ) {
   int        iml_rc;                       /* return code             */
   void *     al_stor;                      /* storage found           */

   if (bop_locked == FALSE) {               /* not in Critical Section */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
   }
   if (dss_swap_stor_ctrl.ac_free == NULL) {  /* chain of free storage pieces */
     goto p_acq_20;                         /* acquire new piece of storage */
   }
   al_stor = dss_swap_stor_ctrl.ac_free;    /* get element of chain of free storage pieces */
   dss_swap_stor_ctrl.ac_free = *((void **) al_stor);  /* remove from chain of free storage pieces */
   dss_swap_stor_ctrl.imc_mem_free--;       /* number of chunks in memory free */
   if (bop_locked == FALSE) {               /* not in Critical Section */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
   }
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "HWSPM0xxW l%05d m_swap_stor_acq_mem() return %p.",
                   __LINE__, al_stor );
//#endif
   return (char *) al_stor;

   p_acq_20:                                /* acquire new piece of storage */
#ifdef B141229
// HL_LONGLONG ilc_no_acq;                  /* number of chunks acquired */
   dss_swap_stor_ctrl.ilc_no_current++;     /* number of chunks currently */
   if (dss_swap_stor_ctrl.ilc_no_current > dss_swap_stor_ctrl.ilc_no_mem_max) {  /* number of chunks maximum in memory */
     dss_swap_stor_ctrl.ilc_no_mem_max = dss_swap_stor_ctrl.ilc_no_current;  /* number of chunks maximum in memory */
   }
#endif
   dss_swap_stor_ctrl.imc_mem_max++;        /* number of chunks in memory maximum */

   /* access to memory subsystem should not be in critical section     */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
#ifdef XYZ1
   al_stor = malloc( LEN_BLOCK_SWAP );
#endif
#ifndef HL_UNIX
   al_stor = VirtualAlloc( NULL, LEN_BLOCK_SWAP, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
#endif
#ifdef HL_UNIX
   al_stor = mmap( NULL, LEN_BLOCK_SWAP, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
#endif
   if (al_stor) {                           /* got memory              */
     if (bop_locked == FALSE) {             /* not in Critical Section */
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "HWSPM0xxW l%05d m_swap_stor_acq_mem() return %p.",
                       __LINE__, al_stor );
//#endif
       return (char *) al_stor;
     }
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "HWSPM0xxW l%05d m_swap_stor_acq_mem() return %p.",
                     __LINE__, al_stor );
//#endif
     return (char *) al_stor;
   }

   /* out of memory                                                    */
   m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR out of memory",
                   __LINE__ );
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
#ifdef B141229
   dss_swap_stor_ctrl.ilc_no_current--;     /* number of chunks currently */
#endif
   dss_swap_stor_ctrl.imc_mem_max--;        /* number of chunks in memory maximum */
   dss_swap_stor_ctrl.ilc_out_of_memory++;  /* count times out of memory */
   return NULL;
} /* end m_swap_stor_acq_mem()                                         */

/** acquire a piece of memory for swap storage chain                   */
static struct dsd_swap_stor_chain * m_swap_stor_acq_ss_ch( void ) {
   int        iml_rc;                       /* return code             */
   struct dsd_swap_stor_chain *adsl_ss_ch_w1;  /* chain of swap storage chunks */
   struct dsd_swap_stor_chain *adsl_ss_ch_w2;  /* chain of swap storage chunks */
   struct dsd_swap_stor_chain *adsl_ss_ch_w3;  /* chain of swap storage chunks */

   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
   if (dss_swap_stor_ctrl.adsc_ss_ch_free == NULL) {  /* chain of free swap storage chunks */
     goto p_acq_20;                         /* acquire new piece of storage */
   }
   adsl_ss_ch_w1 = dss_swap_stor_ctrl.adsc_ss_ch_free;  /* get element of chain of free swap storage chunks */
   dss_swap_stor_ctrl.adsc_ss_ch_free = *((struct dsd_swap_stor_chain **) adsl_ss_ch_w1);  /* remove from chain of free swap storage chunks */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   return adsl_ss_ch_w1;

   p_acq_20:                                /* acquire new piece of storage */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   /* acquire multiple elements to optimize usage of the memory subsystem */
   adsl_ss_ch_w1 = (struct dsd_swap_stor_chain *) malloc( NO_SWAP_STOR_FREE * sizeof(struct dsd_swap_stor_chain) );
   if (adsl_ss_ch_w1 == NULL) {
     goto p_acq_40;                         /* out of memory           */
   }
   adsl_ss_ch_w2 = adsl_ss_ch_w3 = adsl_ss_ch_w1 + 1;  /* new free elements */
   do {
     *((struct dsd_swap_stor_chain **) adsl_ss_ch_w3) = adsl_ss_ch_w3 + 1;
     adsl_ss_ch_w3++;                       /* next element            */
   } while (adsl_ss_ch_w3 < (adsl_ss_ch_w1 + NO_SWAP_STOR_FREE - 1));
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
   *((struct dsd_swap_stor_chain **) adsl_ss_ch_w3) = dss_swap_stor_ctrl.adsc_ss_ch_free;  /* append old elements of chain of free swap storage chunks */
   dss_swap_stor_ctrl.adsc_ss_ch_free = *((struct dsd_swap_stor_chain **) adsl_ss_ch_w2);  /* new elements chain of free swap storage chunks */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   return adsl_ss_ch_w1;

   /* out of memory                                                    */
   p_acq_40:                                /* out of memory           */
   m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d SWAP-STOR out of memory",
                   __LINE__ );
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                     __LINE__, iml_rc );
   }
   dss_swap_stor_ctrl.ilc_out_of_memory++;  /* count times out of memory */
   iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                     __LINE__, iml_rc );
   }
   return NULL;
} /* end m_swap_stor_acq_ss_ch()                                       */

/** cleanup for SWAP-STOR                                              */
static void m_aux_swap_stor_cleanup( struct dsd_hco_wothr *adsp_hco_wothr,
                                     DSD_CONN_G *adsp_conn1, struct dsd_auxf_1 *adsp_auxf_1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   struct dsd_swap_stor_chain *adsl_ss_ch_w1;  /* chain of swap storage chunks */
   struct dsd_swap_stor_chain *adsl_ss_ch_w2;  /* chain of swap storage chunks */

#ifndef HELP_DEBUG
#define ADSL_SS_AUX ((struct dsd_swap_stor_aux *) (adsp_auxf_1 + 1))
#endif
#ifdef HELP_DEBUG
   struct dsd_swap_stor_aux *ADSL_SS_AUX = (struct dsd_swap_stor_aux *) (adsp_auxf_1 + 1);
#endif
   adsl_ss_ch_w1 = ADSL_SS_AUX->adsc_ss_ch;  /* chain of swap storage chunks */
   while (adsl_ss_ch_w1) {                  /* loop over chain of swap storage chunks */
     iml1 = D_SWAP_STOR_CHAIN_CHUNKS;
     do {                                   /* loop to free all chain elements */
       iml1--;                              /* decrement index         */
       if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr) {  /* storage address when in memory */
         iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                           __LINE__, iml_rc );
         }
#define AC_STOR_G (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].achc_stor_addr)
         *((void **) AC_STOR_G) = dss_swap_stor_ctrl.ac_free;  /* chain of free storage pieces */
         dss_swap_stor_ctrl.ac_free = AC_STOR_G;  /* new chain of free storage pieces */
#undef AC_STOR_G
         dss_swap_stor_ctrl.imc_mem_free++;  /* number of chunks in memory free */
         iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
         if (iml_rc < 0) {                  /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                           __LINE__, iml_rc );
         }
       }
       if (adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file >= 0) {  /* index on file (RBA), -1 when not in file */
         bol_rc = m_swap_stor_file_mark_free( adsl_ss_ch_w1->dsrc_ss_c[ iml1 ].imc_index_on_file, FALSE );
       }
     } while (iml1 > 0);
     adsl_ss_ch_w2 = adsl_ss_ch_w1;         /* save this element       */
     adsl_ss_ch_w1 = adsl_ss_ch_w1->adsc_next;  /* get next in chain   */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_enter() return code %d.",
                       __LINE__, iml_rc );
     }
     *((void **) adsl_ss_ch_w2) = dss_swap_stor_ctrl.adsc_ss_ch_free;  /* chain of free swap storage chunks */
     dss_swap_stor_ctrl.adsc_ss_ch_free = adsl_ss_ch_w2;  /* new chain of free swap storage chunks */
     iml_rc = dss_swap_stor_ctrl.dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                        /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_swap_stor_ctrl.dsc_critsect m_leave() return code %d.",
                       __LINE__, iml_rc );
     }
   }
#ifdef HL_UNIX
   if (ADSL_SS_AUX->imc_fd_file >= 0) {     /* file-descriptor of open swap file */
     close( ADSL_SS_AUX->imc_fd_file );
   }
#endif
#ifndef HELP_DEBUG
#undef ADSL_SS_AUX
#endif
} /* end m_aux_swap_stor_cleanup()                                     */

#ifndef HL_UNIX
/** request to load or handle dynamic libraries                        */
static BOOL m_aux_dyn_lib_req_1( void *vpp_userfld, struct dsd_aux_dyn_lib_req_1 *adsp_adlr1 ) {
   int        iml1;                         /* working variable        */
   DWORD      dwl_rc;                       /* return code             */
   HMODULE    dsl_h_module;                 /* handle of module        */
   struct dsd_dyn_lib_ctrl *adsl_dyn_lib_ctrl;  /* dynamic library control */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_last;     /* auxiliary extension field */
   HL_WCHAR   wcrl_fn_1[ LEN_FILE_NAME ];   /* file name 1             */
   HL_WCHAR   wcrl_fn_2[ LEN_FILE_NAME ];   /* file name 2             */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   adsp_adlr1->imc_error = 0;               /* reset error code        */
   switch (adsp_adlr1->iec_adlc) {          /* dynamic library command */
     case ied_adlc_load:                    /* load dynamic library    */
       goto p_load_00;                      /* load dynamic library    */
     case ied_adlc_unload:                  /* unload dynamic library  */
     case ied_adlc_entry:                   /* return entry of dynamic library */
       goto p_check_00;                     /* check passed handle     */
   }
   adsp_adlr1->iec_ret_dl = ied_ret_dl_inv_param;  /* invalid parameters passed */
   return TRUE;

   p_load_00:                               /* load dynamic library    */
   iml1 = m_cpy_vx_ucs( wcrl_fn_1, sizeof(wcrl_fn_1) / sizeof(wcrl_fn_1[0]), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_adlr1->dsc_dyn_lib_name );  /* name and path dynamic library */
   if (iml1 <= 0) {                         /* file name not valid     */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_inv_param;  /* invalid parameters passed */
     return TRUE;
   }
   dwl_rc = GetFullPathNameW( (WCHAR *) wcrl_fn_1, sizeof(wcrl_fn_2) / sizeof(wcrl_fn_2[0]), (WCHAR *) wcrl_fn_2, NULL );
   if (dwl_rc == 0) {                       /* error occured           */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_fn_inv;  /* file name invalid */
     adsp_adlr1->imc_error = GetLastError();  /* error code            */
     return TRUE;
   }
   if (dwl_rc >= sizeof(wcrl_fn_2) / sizeof(wcrl_fn_2[0])) {  /* buffer overflow */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_fn_too_long;  /* file name too long */
     return TRUE;
   }
   dss_critsect_slow.m_enter();             /* critical section        */
   adsl_dyn_lib_ctrl = adss_dyn_lib_ctrl_ch;  /* chain dynamic library control */
   while (adsl_dyn_lib_ctrl) {              /* loop over chain dynamic library control */
     if (   (adsl_dyn_lib_ctrl->imc_len_fn == dwl_rc)  /* length file-name in elements */
         && (!memcmp( adsl_dyn_lib_ctrl + 1, wcrl_fn_2, dwl_rc * sizeof(wcrl_fn_2[0]) ))) {
       adsl_dyn_lib_ctrl->imc_references++;  /* count references       */
       goto p_load_60;                      /* dynamic library already loaded */
     }
     adsl_dyn_lib_ctrl = adsl_dyn_lib_ctrl->adsc_next;  /* get next in chain */
   }
   dsl_h_module = LoadLibraryW( (WCHAR *) wcrl_fn_2 );
   if (dsl_h_module == NULL) {
     adsp_adlr1->imc_error = GetLastError();  /* error code            */
     goto p_load_60;                        /* dynamic library already loaded */
   }
   adsl_dyn_lib_ctrl = (struct dsd_dyn_lib_ctrl *) malloc( sizeof(struct dsd_dyn_lib_ctrl) + (dwl_rc + 1) * sizeof(wcrl_fn_2[0]) );  /* dynamic library control */
   adsl_dyn_lib_ctrl->imc_references = 1;   /* count references        */
   adsl_dyn_lib_ctrl->imc_len_fn = dwl_rc;  /* length file-name in elements */
   adsl_dyn_lib_ctrl->dsc_h_module = dsl_h_module;  /* handle of module */
   memcpy( adsl_dyn_lib_ctrl + 1, wcrl_fn_2, (dwl_rc + 1) * sizeof(wcrl_fn_2[0]) );  /* copy file-name */
   adsl_dyn_lib_ctrl->adsc_next = adss_dyn_lib_ctrl_ch;  /* get old chain dynamic library control */
   adss_dyn_lib_ctrl_ch = adsl_dyn_lib_ctrl;  /* set new chain dynamic library control */

   p_load_60:                               /* dynamic library already loaded */
   dss_critsect_slow.m_leave();             /* critical section        */
   if (adsl_dyn_lib_ctrl == NULL) {         /* no dynamic library loaded */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_fn_not_found;  /* file name not found */
     return TRUE;
   }
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + sizeof(struct dsd_aux_dyn_lib_conn) );  /* auxiliary extension field */
   memset( adsl_auxf_1_w1, 0, sizeof(struct dsd_auxf_1) + sizeof(struct dsd_auxf_ext_1) + sizeof(struct dsd_auxf_admin1) );
   adsl_auxf_1_w1->iec_auxf_def = ied_auxf_dyn_lib;  /* dynamic library */
   ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1))->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* current Server-Data-Hook */
#define ADSL_ADLC_G ((struct dsd_aux_dyn_lib_conn *) (adsl_auxf_1_w1 + 1))
   ADSL_ADLC_G->adsc_dyn_lib_ctrl = adsl_dyn_lib_ctrl;  /* dynamic library control */
#undef ADSL_ADLC_G
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set new chain       */
   adsp_adlr1->vpc_aux_dyn_lib_handle = adsl_auxf_1_w1;  /* handle of dynamic library */
   adsp_adlr1->iec_ret_dl = ied_ret_dl_ok;  /* command returned o.k.   */
   return TRUE;

   p_check_00:                              /* check passed handle     */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary extension fields */
   adsl_auxf_1_last = NULL;                 /* last auxiliary extension field */
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
     if (adsl_auxf_1_w1 == ((struct dsd_auxf_1 *) adsp_adlr1->vpc_aux_dyn_lib_handle)) {  /* handle of dynamic library */
       goto p_check_20;                     /* auxiliary extension field found */
     }
     adsl_auxf_1_last = adsl_auxf_1_w1;     /* last auxiliary extension field */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   adsp_adlr1->iec_ret_dl = ied_ret_dl_inv_handle;  /* invalid handle of dynamic library passed */
   return TRUE;

   p_check_20:                              /* auxiliary extension field found */
   if (adsl_auxf_1_w1->iec_auxf_def != ied_auxf_dyn_lib) {  /* dynamic library */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_inv_handle;  /* invalid handle of dynamic library passed */
     return TRUE;
   }
   if (adsp_adlr1->iec_adlc == ied_adlc_unload) {  /* unload dynamic library */
     m_aux_dyn_lib_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
#endif
     if (adsl_auxf_1_last == NULL) {        /* last auxiliary extension field */
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;  /* remove from chain auxiliary extension fields */
     } else {                               /* middle in chain         */
       adsl_auxf_1_last->adsc_next = adsl_auxf_1_w1->adsc_next;  /* remove from chain auxiliary extension fields */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#endif
     free( adsl_auxf_1_w1 );                /* free memory auxiliary extension field */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_ok;  /* command returned o.k. */
     return TRUE;
   }
   iml1 = m_cpy_vx_ucs( wcrl_fn_1, sizeof(wcrl_fn_1), ied_chs_ansi_819,  /* ANSI 819 */
                        &adsp_adlr1->dsc_dyn_lib_entry );  /* name of entry of dynamic library */
   if (iml1 <= 0) {                         /* entry name not valid    */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_inv_param;  /* invalid parameters passed */
     return TRUE;
   }
#define ADSL_ADLC_G ((struct dsd_aux_dyn_lib_conn *) (adsl_auxf_1_w1 + 1))
   ADSL_ADLC_G->adsc_dyn_lib_ctrl = adsl_dyn_lib_ctrl;  /* dynamic library control */
   adsp_adlr1->vpc_aux_dyn_lib_entry        /* entry in dynamic library */
     = GetProcAddress( ADSL_ADLC_G->adsc_dyn_lib_ctrl->dsc_h_module,  /* handle of module */
                       (char *) wcrl_fn_1 );
#undef ADSL_ADLC_G
   if (adsp_adlr1->vpc_aux_dyn_lib_entry != NULL) {  /* entry in dynamic library */
     adsp_adlr1->iec_ret_dl = ied_ret_dl_ok;  /* command returned o.k. */
     return TRUE;
   }
   adsp_adlr1->imc_error = GetLastError();  /* error code              */
   adsp_adlr1->iec_ret_dl = ied_ret_dl_entry_not_found;  /* entry not found in dynamic library */
   return TRUE;

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_dyn_lib_req_1()                                         */

/** cleanup for dynamic library                                        */
static void m_aux_dyn_lib_cleanup( DSD_CONN_G *adsp_conn1, struct dsd_auxf_1 *adsp_auxf_1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_dyn_lib_ctrl *adsl_dyn_lib_ctrl_cur;  /* dynamic library control */

   dss_critsect_slow.m_enter();             /* critical section        */
#define ADSL_ADLC_G ((struct dsd_aux_dyn_lib_conn *) (adsp_auxf_1 + 1))
   ADSL_ADLC_G->adsc_dyn_lib_ctrl->imc_references--;  /* count references */
   if (ADSL_ADLC_G->adsc_dyn_lib_ctrl->imc_references > 0) {  /* check references */
     goto p_unload_60;                      /* all done                */
   }
   if (ADSL_ADLC_G->adsc_dyn_lib_ctrl == adss_dyn_lib_ctrl_ch) {  /* chain dynamic library control */
     adss_dyn_lib_ctrl_ch = ADSL_ADLC_G->adsc_dyn_lib_ctrl->adsc_next;  /* remove from chain dynamic library control */
   } else {
     if (adss_dyn_lib_ctrl_ch == NULL) {    /* check chain dynamic library control */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW m_aux_dyn_lib_cleanup() l%05d cannot free dynamic library - auxf_1 %p adsc_dyn_lib_ctrl %p.",
                       __LINE__, adsp_auxf_1, ADSL_ADLC_G->adsc_dyn_lib_ctrl );
       goto p_unload_60;                    /* all done                */
     }
     adsl_dyn_lib_ctrl_cur = adss_dyn_lib_ctrl_ch;  /* chain dynamic library control */
     while (ADSL_ADLC_G->adsc_dyn_lib_ctrl != adsl_dyn_lib_ctrl_cur->adsc_next) {  /* chain dynamic library control */
       adsl_dyn_lib_ctrl_cur = adsl_dyn_lib_ctrl_cur->adsc_next;
       if (adsl_dyn_lib_ctrl_cur == NULL) {
         m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW m_aux_dyn_lib_cleanup() l%05d cannot free dynamic library - auxf_1 %p adsc_dyn_lib_ctrl %p.",
                         __LINE__, adsp_auxf_1, ADSL_ADLC_G->adsc_dyn_lib_ctrl );
         goto p_unload_60;                  /* all done                */
       }
     }
     adsl_dyn_lib_ctrl_cur->adsc_next = adsl_dyn_lib_ctrl_cur->adsc_next->adsc_next;  /* remove from chain */
   }
   bol_rc = FreeLibrary( ADSL_ADLC_G->adsc_dyn_lib_ctrl->dsc_h_module );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW m_aux_dyn_lib_cleanup() l%05d FreeLibrary() returned error %d - auxf_1 %p adsc_dyn_lib_ctrl %p.",
                     __LINE__, GetLastError(), adsp_auxf_1, ADSL_ADLC_G->adsc_dyn_lib_ctrl );
   }
   free( ADSL_ADLC_G->adsc_dyn_lib_ctrl );  /* free memory             */
#undef ADSL_ADLC_G

   p_unload_60:                             /* all done                */
   dss_critsect_slow.m_leave();             /* critical section        */
} /* end m_aux_dyn_lib_cleanup()                                       */
#endif
#ifdef HL_UNIX
/** request to load or handle dynamic libraries                        */
static BOOL m_aux_dyn_lib_req_1( void *vpp_userfld, struct dsd_aux_dyn_lib_req_1 *adsp_adlr1 ) {
   return FALSE;
} /* end m_aux_dyn_lib_req_1()                                         */
#endif

/** retrieve domain-information of connection - gate                   */
static BOOL m_aux_get_domain_info_1( void *vpp_userfld, struct dsd_aux_get_domain_info_1 *adsp_gdi1 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_dotted;                   /* dotted INETAs already checked */
   int        iml_cmp;                      /* compare values          */
   int        iml1, iml2, iml3;             /* working variables       */
   struct dsd_domain_info_1 *adsl_domain_info_w1;  /* domain information */
   struct dsd_domain_info_1 *adsl_domain_info_default;  /* domain information default */
   struct dsd_unicode_string *adsl_ucs_w1;  /* working variable        */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

#ifndef HL_UNIX
   adsp_gdi1->dsc_ucs_netbios_computer_name.ac_str = dsg_this_server.chrc_server_name;
   adsp_gdi1->dsc_ucs_netbios_computer_name.imc_len_str = dsg_this_server.imc_len_server_name;
   adsp_gdi1->dsc_ucs_netbios_computer_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
#endif
// to-do 04.07.13 KB - 2 fields for NTLM client
//#ifdef NOT_YET_130704
   adsp_gdi1->iec_coty = ADSL_CONN1_G->adsc_gate1->iec_coty;  /* connection type */
//#endif
// to-do 04.07.13 KB - search default
   if (adsp_gdi1->dsc_ucs_hostname.imc_len_str == 0) {  /* no HTTP Host: */
     adsp_gdi1->iec_dir = ied_dir_param_inv;  /* input paramater invalid */
     return TRUE;
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_domain_info == 0) {  /* number of domain informations */
     adsp_gdi1->iec_dir = ied_dir_notfound;  /* domain information not found */
     return TRUE;
   }
   iml1 = 0;                                /* clear index domain information in gate */
   adsl_domain_info_default = NULL;         /* domain information default */

   p_gdi_20:                                /* check domain information */
   adsl_domain_info_w1 = ADSL_CONN1_G->adsc_gate1->adsrc_domain_info[ iml1 ];  /* domain information */
   if (   (adsl_domain_info_w1->boc_use_as_default)  /* use-as-default */
       && (adsl_domain_info_default == NULL)) {  /* domain information default */
     adsl_domain_info_default = adsl_domain_info_w1;  /* domain information default */
   }
   adsl_ucs_w1 = adsl_domain_info_w1->adsc_ucs_dns_ineta;  /* array of server-DNS-ineta */
   bol_dotted = FALSE;                      /* dotted INETAs already checked */
   if (adsl_domain_info_w1->imc_no_dns_ineta == 0) {  /* number of server-DNS-ineta */
     goto p_gdi_60;                         /* end of check Unicode strings of host */
   }
   iml2 = adsl_domain_info_w1->imc_no_dns_ineta;  /* number of server-DNS-ineta */
   iml3 = 0;                                /* clear index of Unicode strings */

   p_gdi_40:                                /* check Unicode string of host */
   bol_rc = m_cmp_ucs_ucs( &iml_cmp, adsl_ucs_w1 + iml3, &adsp_gdi1->dsc_ucs_hostname );
   if ((bol_rc) && (iml_cmp == 0)) {        /* strings are equal       */
     adsp_gdi1->iec_dir = ied_dir_found;    /* domain information found */
     goto p_gdi_found;                      /* domain information entry found */
   }
   iml3++;                                  /* increment index of Unicode strings */
   if (iml3 < iml2) {                       /* not yet at end of array */
     goto p_gdi_40;                         /* check Unicode string of host */
   }

   p_gdi_60:                                /* end of check Unicode strings of host */
   if (   (bol_dotted == FALSE)             /* dotted INETAs already checked */
       && (adsl_ucs_w1 == adsl_domain_info_w1->adsc_ucs_dns_ineta)  /* array of server-DNS-ineta */
       && (adsl_domain_info_w1->imc_no_dotted_ineta > 0)) {  /* number of server-dotted-ineta */
     adsl_ucs_w1 = adsl_domain_info_w1->adsc_ucs_dotted_ineta;  /* array of server-dotted-ineta */
     iml2 = adsl_domain_info_w1->imc_no_dotted_ineta;  /* number of server-dotted-ineta */
     iml3 = 0;                              /* clear index of Unicode strings */
     bol_dotted = TRUE;                     /* dotted INETAs already checked */
     goto p_gdi_40;                         /* check Unicode string of host */
   }

   iml1++;                                  /* increment index domain information in gate */
   if (iml1 < ADSL_CONN1_G->adsc_gate1->imc_no_domain_info) {  /* number of domain informations */
     goto p_gdi_20;                         /* check domain information */
   }
   if (adsl_domain_info_default == NULL) {  /* domain information default */
     adsp_gdi1->iec_dir = ied_dir_notfound;  /* domain information not found */
     return TRUE;
   }
   adsl_domain_info_w1 = adsl_domain_info_default;  /* domain information default */
   adsp_gdi1->iec_dir = ied_dir_default;    /* returned domain information default values */

   p_gdi_found:                             /* domain information entry found */
   adsp_gdi1->dsc_ucs_dns_domain_name = adsl_domain_info_w1->dsc_ucs_dns_domain_name;  /* server-DNS-domain-name */
   adsp_gdi1->dsc_ucs_dns_computer_name = adsl_domain_info_w1->dsc_ucs_dns_computer_name;  /* server-DNS-computer-name */
   adsp_gdi1->dsc_ucs_dns_tree_name = adsl_domain_info_w1->dsc_ucs_dns_tree_name;  /* server-DNS-tree-name */
   adsp_gdi1->dsc_ucs_netbios_domain_name = adsl_domain_info_w1->dsc_ucs_netbios_domain_name;  /* NetBIOS-domain-name */
   adsp_gdi1->dsc_ucs_permmov_url = adsl_domain_info_w1->dsc_ucs_permmov_url;  /* permanently-moved-URL */
#ifndef B160423
   adsp_gdi1->dsc_ucs_group_id = adsl_domain_info_w1->dsc_ucs_group_id;  /* group Id */
   adsp_gdi1->dsc_ucs_auth_token = adsl_domain_info_w1->dsc_ucs_auth_token;  /* authentication token */
#endif
   adsp_gdi1->dsc_ucs_comment = adsl_domain_info_w1->dsc_ucs_comment;  /* comment */
   adsp_gdi1->iec_diat = adsl_domain_info_w1->iec_diat;  /* domain information authentication-type */
   adsp_gdi1->boc_use_full_pm_url = adsl_domain_info_w1->boc_use_full_pm_url;  /* use-full-permanently-moved-URL */
   return TRUE;
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_get_domain_info_1()                                     */

/** file IO requests                                                   */
static BOOL m_aux_file_io_req_1( void * vpp_userfld, struct dsd_aux_file_io_req_1 *adsp_fior1, int imp_trace_level, int imp_sno ) {
   BOOL       bol_rc;                       /* return code             */
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_fd;                       /* file-descriptor         */
#endif
   int        iml1;                         /* working variable        */
#ifndef HL_UNIX
   unsigned long int uml_returned_read;     /* how much read from disk */
   DWORD      dwl_error;                    /* error returned          */
   DWORD      dwl_write;                    /* NumberOfBytesWritten    */
#endif
   char       *achl_w1, *achl_w2, *achl_w3;  /* working variables      */
#ifdef HL_UNIX
   char       *achl_file;                   /* name of file            */
#endif
#ifndef HL_UNIX
   WCHAR      *awcl_w1;                     /* working variable        */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 **aadsl_auxf_1_cur;    /* current chain auxiliary extension fields */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   HL_LONGLONG ill_file_size;               /* size of this file       */
#ifndef HL_UNIX
   HANDLE     dsl_hfi1;                     /* handle for file         */
#endif
#ifdef XYZ1
   BY_HANDLE_FILE_INFORMATION dsl_fi1;
   WIN32_FILE_ATTRIBUTE_DATA dsl_fi2;       /* file not opened         */
#endif
#ifndef HL_UNIX
   WCHAR      wcrl_file_name[ MAX_PATH ];   /* for file name           */
#endif
#ifdef HL_UNIX
#ifndef D_NO_STAT64
   struct stat64 dsl_stat_1;                /* for stat()              */
#else
   struct stat dsl_stat_1;                  /* for stat()              */
#endif
   char       chrl_file_name[ 1024 ];       /* for file name           */
#endif

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   aadsl_auxf_1_cur = NULL;                 /* not current chain auxiliary extension fields */
   if (ADSL_AUX_CF1) {                      /* with connection         */
     if (ADSL_AUX_CF1->dsc_cid.iec_src_func != ied_src_fu_util_thread) {  /* not utility thread */
       aadsl_auxf_1_cur = &ADSL_CONN1_G->adsc_auxf_1;  /* current chain auxiliary extension fields */
     } else {                                 /* is utility thread       */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) ADSL_AUX_CF1->dsc_cid.ac_cid_addr)
       aadsl_auxf_1_cur = &ADSL_UTC_G->adsc_auxf_1;  /* current chain auxiliary extension fields */
#undef ADSL_UTC_G
     }
   }
   switch (adsp_fior1->iec_fioc) {          /* command for file IO     */
     case ied_fioc_compl_file_read:         /* read complete file      */
       goto p_cf_re_00;                     /* read complete file      */
     case ied_fioc_compl_file_write:        /* write complete file     */
       goto p_cf_wr_00;                     /* write complete file     */
     case ied_fioc_file_delete:             /* delete the file         */
       goto p_dele_00;                      /* delete the file         */
   }
   goto p_param_error;                      /* input paramater invalid */

   p_cf_re_00:                              /* read complete file      */
#ifndef HL_UNIX
   awcl_w1 = (WCHAR *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (   (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_utf_16)  /* Unicode UTF-16 = WCHAR */
           && (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_le_utf_16))  /* Unicode UTF-16 little endian */
       || (adsp_fior1->boc_unix_style_fn)) {  /* filename Unix style   */
     iml1 = m_cpy_vx_ucs( wcrl_file_name,
                          sizeof(wcrl_file_name),
                          ied_chs_utf_16,   /* Unicode UTF-16          */
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     awcl_w1 = wcrl_file_name;
     if (adsp_fior1->boc_unix_style_fn) {   /* filename Unix style     */
       achl_w1 = (char *) wcrl_file_name;
       achl_w2 = (char *) wcrl_file_name + iml1 * sizeof(HL_WCHAR);
       do {                                 /* loop to find Unix slash */
         iml1 = achl_w2 - achl_w1;
         achl_w3 = (char *) memchr( achl_w1, '/', iml1 );
         if (achl_w3 == NULL) break;        /* not found               */
         if (  ((((int) achl_w3) & 1) == 0)
             & (*(achl_w3 + 1) == 0)) {
           *achl_w3++ = '\\';
         }
         achl_w1 = achl_w3 + 1;
       } while (achl_w1 < achl_w2);
     }
   }
#endif
#ifdef HL_UNIX
   achl_file = (char *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ieg_charset_system)) {
     iml1 = m_cpy_vx_ucs( chrl_file_name,
                          sizeof(chrl_file_name),
                          ieg_charset_system,
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     achl_file = chrl_file_name;
   }
#endif
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   }
#ifndef HL_UNIX
   dsl_hfi1 = CreateFileW( awcl_w1, GENERIC_READ, FILE_SHARE_READ, 0,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_hfi1 == INVALID_HANDLE_VALUE) {  /* error occured           */
#ifdef D_NO_SNMP
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_WARN1, "HWSPRDFnnnW m_read_diskfile %(ucs)s open input returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
#endif
#else
//   dwl1 = GetLastError();
//   m_hlnew_printf( HLOG_WARN1, "HWSPRDFnnnW m_read_diskfile %(ux)s open input returned Error %d.",
//                   wcrl_file_name, dwl1 );
#endif
     dwl_error = GetLastError();
     if (dwl_error == ERROR_FILE_NOT_FOUND) {
       adsp_fior1->iec_fior = ied_fior_file_not_found;  /* The system cannot find the file specified. ERROR_FILE_NOT_FOUND */
       goto p_error_20;                     /* continue error          */
     }
     adsp_fior1->iec_fior = ied_fior_open_error;  /* error from open   */
     adsp_fior1->imc_error = dwl_error;
     goto p_error_20;                       /* continue error          */
   }
   bol_rc = GetFileSizeEx( dsl_hfi1, (PLARGE_INTEGER) &ill_file_size );
   if (bol_rc == FALSE) {                   /* returned error          */
#ifdef D_NO_SNMP
     m_hlnew_printf( HLOG_XYZ1, "HWSPRDF012W m_read_diskfile %(ucs)s GetFileSizeEx() returned Error %d",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
#else
#ifdef XYZ1
     dwl1 = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPRDF012W m_read_diskfile %(ux)s GetFileSizeEx() returned Error %d",
                     awcl_w1, dwl1 );
     memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
     dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
     m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
#endif
//   adsp_aux_df1->iec_dfar_def = ied_dfar_get_file_size;
   }
#endif
#ifdef HL_UNIX
   iml_fd = open( chrl_file_name, O_RDONLY );
   if (iml_fd < 0) {                        /* error occured           */
     iml_error = errno;
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF011W m_read_diskfile %(ucs)s open input returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, iml_error );
#endif
     if (iml_error == ENOENT) {
       adsp_fior1->iec_fior = ied_fior_file_not_found;  /* No such file or directory. ENOENT */
       goto p_error_20;                     /* continue error          */
     }
     adsp_fior1->iec_fior = ied_fior_open_error;  /* error from open   */
     adsp_fior1->imc_error = iml_error;
     goto p_error_20;                       /* continue error          */
   }
#ifndef D_NO_STAT64
   memset( &dsl_stat_1, 0, sizeof(struct stat64) );
   iml_rc = fstat64( iml_fd, &dsl_stat_1 );
#else
   memset( &dsl_stat_1, 0, sizeof(struct stat) );
   iml_rc = fstat( iml_fd, &dsl_stat_1 );
#endif
   if (iml_rc < 0) {                        /* error occured           */
     iml_error = errno;
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF013W xxxxxxxxxxxxxxx %(ucs)s fstat64() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, iml_error );
     adsp_fior1->iec_fior = ied_fior_open_error;  /* error from open   */
     adsp_fior1->imc_error = iml_error;
     goto p_error_20;                       /* continue error          */
   }
   ill_file_size = dsl_stat_1.st_size;      /* size of this file       */
#endif
   if (ADSL_AUX_CF1 == NULL) {              /* without connection      */
     achl_w1 = (char *) malloc( ill_file_size );
   } else {                                 /* with connection         */
     adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + ill_file_size );
     adsl_auxf_1_w1->iec_auxf_def = ied_auxf_normstor;  /* normal storage */
     memcpy( &adsl_auxf_1_w1->dsc_cid,
             &ADSL_AUX_CF1->dsc_cid,
             sizeof(struct dsd_cid) );      /* current Server-Data-Hook */
#ifdef TRACEHLP
   adsl_auxf_1_w1->inc_size_mem = ill_file_size;  /* size of memory    */
   ADSL_CONN1_G->inc_aux_mem_cur += adsl_auxf_1_w1->inc_size_mem;
   if (ADSL_CONN1_G->inc_aux_mem_max < ADSL_CONN1_G->inc_aux_mem_cur) {
     ADSL_CONN1_G->inc_aux_mem_max = ADSL_CONN1_G->inc_aux_mem_cur;
   }
#endif
     adsl_auxf_1_w1->adsc_next = *aadsl_auxf_1_cur;  /* get current chain auxiliary extension fields */
     *aadsl_auxf_1_cur = adsl_auxf_1_w1;    /* set new current chain auxiliary extension fields */
     achl_w1 = (char *) (adsl_auxf_1_w1 + 1);
   }
   achl_w2 = achl_w1 + ill_file_size;
   adsp_fior1->achc_data = achl_w1;         /* address of data         */
   do {
     iml1 = 0X01000000;                     /* maximum length read     */
     if ((achl_w1 + iml1) > achl_w2) iml1 = achl_w2 - achl_w1;
#ifndef HL_UNIX
     bol_rc = ReadFile( dsl_hfi1, achl_w1, iml1, &uml_returned_read, 0 );
     if (bol_rc == FALSE) {                 /* error occured           */
#ifdef XYZ1
#ifdef D_NO_SNMP
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF021W m_read_file %(ucs)s ReadFile() returned Error %d",
                       &adsp_fior1->dsc_ucs_file_name, GetLastError() );
#else
       dwl1 = GetLastError();
       m_hlnew_printf( HLOG_XYZ1, "HWSPRDF021W m_read_file %(ux)s ReadFile() returned Error %d",
                       awcl_w1, dwl1 );
       memset( &dsl_wsp_snmp_trap_file_access, 0, sizeof(struct dsd_wsp_snmp_trap_file_access) );  /* File Access failed */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.ac_str = wcrl_file_name;  /* address of string */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.imc_len_str = iml_len_name;  /* length string in elements */
       dsl_wsp_snmp_trap_file_access.dsc_file_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
       dsl_wsp_snmp_trap_file_access.imc_errno = dwl1;  /* error number */
       m_snmp_trap_1( ied_wsp_snmp_trap_file_access, &dsl_wsp_snmp_trap_file_access );
#endif
#endif
       break;
     }
     if (uml_returned_read == 0) break;
     achl_w1 += uml_returned_read;
#endif
#ifdef HL_UNIX
     iml_rc = read( iml_fd, achl_w1, iml1 );
     if (iml_rc < 0) {                      /* error occured           */
       break;
     }
     if (iml_rc == 0) break;
     achl_w1 += iml_rc;
#endif
   } while (achl_w1 < achl_w2);
#ifndef HL_UNIX
   bol_rc = CloseHandle( dsl_hfi1 );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s CloseHandle() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
   }
#endif
#ifdef HL_UNIX
   iml_rc = close( iml_fd );
   if (iml_rc != 0) {                       /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s CloseHandle() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, errno );
   }
#endif
   adsp_fior1->ilc_len_data = achl_w1 - adsp_fior1->achc_data;  /* length of data */
   adsp_fior1->iec_fior = ied_fior_ok;      /* o.k.                    */
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   /* nothing more to do                                               */
   if ((imp_trace_level & HL_WT_SESS_AUX) == 0) return TRUE;  /* do not generate WSP trace record */
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SAUXIOR1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = imp_sno;     /* WSP session number      */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
   iml1 = m_hlsnprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                        LEN_TCP_RECV - sizeof(struct dsd_wsp_trace_1) - sizeof(struct dsd_wsp_trace_record),
                        ied_chs_utf_8,
                        "l%05d file IO request read complete file \"%(ucs)s\" size %lld/0X%llX.",
                        __LINE__,
                        &adsp_fior1->dsc_ucs_file_name,
                        adsp_fior1->ilc_len_data,
                        adsp_fior1->ilc_len_data );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
   ADSL_WTR_G1->imc_length = iml1;          /* length of text / data   */
// ADSL_WTR_G1->adsc_next = NULL;           /* end of chain            */
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return TRUE;                             /* all done                */

   p_cf_wr_00:                              /* write complete file     */
   if (   (adsp_fior1->ilc_len_data == 0)
       && (adsp_fior1->adsc_gai1_data == NULL)) {  /* input and output data */
     goto p_param_error;                    /* input paramater invalid */
   }
#ifndef HL_UNIX
   awcl_w1 = (WCHAR *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (   (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_utf_16)  /* Unicode UTF-16 = WCHAR */
           && (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_le_utf_16))) {  /* Unicode UTF-16 little endian */
     iml1 = m_cpy_vx_ucs( wcrl_file_name,
                          sizeof(wcrl_file_name),
                          ied_chs_utf_16,   /* Unicode UTF-16          */
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     awcl_w1 = wcrl_file_name;
   }
#endif
#ifdef HL_UNIX
   achl_file = (char *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ieg_charset_system)) {
     iml1 = m_cpy_vx_ucs( chrl_file_name,
                          sizeof(chrl_file_name),
                          ieg_charset_system,
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     achl_file = chrl_file_name;
   }
#endif
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   }
#ifndef HL_UNIX
   dsl_hfi1 = CreateFileW( awcl_w1, GENERIC_WRITE, 0, 0,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_hfi1 == INVALID_HANDLE_VALUE) {  /* error occured           */
     dwl_error = GetLastError();
#ifdef D_NO_SNMP
     m_hlnew_printf( HLOG_WARN1, "HWSPRDFnnnW m_read_diskfile %(ucs)s open input returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
#else
//   dwl1 = GetLastError();
//   m_hlnew_printf( HLOG_WARN1, "HWSPRDFnnnW m_read_diskfile %(ux)s open input returned Error %d.",
//                   wcrl_file_name, dwl1 );
#endif
     adsp_fior1->iec_fior = ied_fior_open_error;  /* error from open   */
     adsp_fior1->imc_error = dwl_error;
     goto p_error_20;                       /* continue error          */
   }
#endif
#ifdef HL_UNIX
/* to-do 05.08.16 KB - set O_DIRECT */
   iml_fd = open( achl_file,
                  O_WRONLY | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
   if (iml_fd < 0) {                        /* error occured           */
     iml_error = errno,
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W xxxxxxxxx open() returned error %d.",
                     __LINE__, iml_error );
     adsp_fior1->iec_fior = ied_fior_open_error;  /* error from open   */
     adsp_fior1->imc_error = iml_error;
     goto p_error_20;                       /* continue error          */
   }
#endif
   if (adsp_fior1->adsc_gai1_data) {        /* input and output data   */
     goto p_cf_wr_40;                       /* write data from gather  */
   }
   achl_w1 = adsp_fior1->achc_data;         /* address of data         */
   achl_w2 = achl_w1 + adsp_fior1->ilc_len_data;  /* add length of data */

   p_cf_wr_28:                              /* write a piece           */
   iml1 = 0X01000000;                       /* maximum length write    */
   if ((achl_w1 + iml1) > achl_w2) iml1 = achl_w2 - achl_w1;
   if (iml1 == 0) {                         /* no data to write        */
     goto p_cf_wr_60;                       /* all written             */
   }
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_hfi1, achl_w1, iml1, &dwl_write, NULL );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s WriteFile() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
   }
#endif
#ifdef HL_UNIX
   iml_rc = write( iml_fd, achl_w1, iml1 );
   if (iml_rc != iml1) {                    /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s write() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, errno );
   }
#endif
   achl_w1 += iml1;                         /* count bytes written     */
   if (achl_w1 < achl_w2) {                 /* more data to write      */
     goto p_cf_wr_28;                       /* write a piece           */
   }
   goto p_cf_wr_60;                         /* all written             */

   p_cf_wr_40:                              /* write data from gather  */
   adsl_gai1_w1 = adsp_fior1->adsc_gai1_data;  /* input and output data */

   p_cf_wr_44:                              /* write single gather     */
   achl_w1 = adsl_gai1_w1->achc_ginp_cur;
   achl_w2 = adsl_gai1_w1->achc_ginp_end;

   p_cf_wr_48:                              /* write a piece           */
   iml1 = 0X01000000;                       /* maximum length write    */
   if ((achl_w1 + iml1) > achl_w2) iml1 = achl_w2 - achl_w1;
   if (iml1 == 0) {                         /* no data to write        */
     goto p_cf_wr_52;                       /* gather written          */
   }
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_hfi1, achl_w1, iml1, &dwl_write, NULL );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s WriteFile() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
   }
#endif
#ifdef HL_UNIX
   iml_rc = write( iml_fd, achl_w1, iml1 );
   if (iml_rc != iml1) {                    /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s write() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, errno );
   }
#endif
   achl_w1 += iml1;                         /* count bytes written     */
   if (achl_w1 < achl_w2) {                 /* more data to write      */
     goto p_cf_wr_48;                       /* write a piece           */
   }

   p_cf_wr_52:                              /* gather written          */
   adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain       */
   if (adsl_gai1_w1) {                      /* more data               */
     goto p_cf_wr_44;                       /* write single gather     */
   }

   p_cf_wr_60:                              /* all written             */
#ifndef HL_UNIX
   bol_rc = CloseHandle( dsl_hfi1 );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s CloseHandle() returned Error %d.",
                     &adsp_fior1->dsc_ucs_file_name, GetLastError() );
   }
#endif
#ifdef HL_UNIX
   iml_rc = close( iml_fd );
   if (iml_rc != 0) {                       /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPRDF040W m_read_diskfile %(ucs)s close() returned Error %d %d.",
                     &adsp_fior1->dsc_ucs_file_name, iml_rc, errno );
   }
#endif
   adsp_fior1->iec_fior = ied_fior_ok;      /* o.k.                    */
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   return TRUE;                             /* all done                */

   p_dele_00:                               /* delete the file         */
#ifndef HL_UNIX
   awcl_w1 = (WCHAR *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (   (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_utf_16)  /* Unicode UTF-16 = WCHAR */
           && (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ied_chs_le_utf_16))) {  /* Unicode UTF-16 little endian */
     iml1 = m_cpy_vx_ucs( wcrl_file_name,
                          sizeof(wcrl_file_name),
                          ied_chs_utf_16,   /* Unicode UTF-16          */
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     awcl_w1 = wcrl_file_name;
   }
#endif
#ifdef HL_UNIX
   achl_file = (char *) adsp_fior1->dsc_ucs_file_name.ac_str;  /* address of string */
   if (   (adsp_fior1->dsc_ucs_file_name.imc_len_str >= 0)
       || (adsp_fior1->dsc_ucs_file_name.iec_chs_str != ieg_charset_system)) {
     iml1 = m_cpy_vx_ucs( chrl_file_name,
                          sizeof(chrl_file_name),
                          ieg_charset_system,
                          &adsp_fior1->dsc_ucs_file_name );
     if (iml1 <= 0) {                       /* returned error          */
       goto p_param_error;                  /* input paramater invalid */
     }
     achl_file = chrl_file_name;
   }
#endif
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   }
   adsp_fior1->iec_fior = ied_fior_ok;      /* o.k.                    */
   adsp_fior1->imc_error = 0;               /* error code              */
#ifndef HL_UNIX
   bol_rc = DeleteFileW( (WCHAR *) awcl_w1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_fior1->imc_error = GetLastError();  /* error code              */
//   adsp_adlr1->iec_ret_dl = ied_ret_dl_entry_not_found;  /* entry not found in dynamic library */
   }
#endif
#ifdef HL_UNIX
   iml_rc = unlink( achl_file );
   if (iml_rc != 0) {                       /* error occured           */
     adsp_fior1->imc_error = errno;
//   adsp_adlr1->iec_ret_dl = ied_ret_dl_entry_not_found;  /* entry not found in dynamic library */
   }
#endif
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   return TRUE;                             /* all done                */


   p_error_00:                              /* error occured           */
   p_error_20:                              /* continue error          */
   if (ADSL_AUX_CF1) {                      /* with connection         */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   }
   return TRUE;                             /* all done                */

   p_param_error:                           /* input paramater invalid */
   adsp_fior1->iec_fior = ied_fior_param_inv;  /* input parameters invalid */
   return TRUE;                             /* all done                */
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* m_aux_file_io_req_1()                                             */

/** aux function manage SDH reload                                     */
static BOOL m_aux_sdh_reload_call( void *vpp_userfld, struct dsd_hl_aux_manage_sdh_reload *adsp_amsr ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_last;     /* last entry in chain     */
#ifdef WAS_BEFORE_1501
   struct dsd_sdh_reload_saved *adsl_srs_w1;  /* SDHs, saved for reload */
   struct dsd_sdh_reload_saved *adsl_srs_last;  /* last SDH, saved for reload */
#endif
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct {
     struct dsd_sdh_reload_auxf dsc_sra_l;
     char     byrc_sdh_rn[ MAX_LEN_SDH_RELOAD_NAME ];  /* maximum length name SDH reload */
   } dsl_sr_sort;
//#define MAX_LEN_SDH_RELOAD_NAME 256         /* maximum length name SDH reload */

#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (vpp_userfld) {
     ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
   }
#endif

   switch (adsp_amsr->iec_asrc) {           /* command for SDH reload  */
     case ied_asrc_define:                  /* define this SDH for reload */
       goto p_asr_def_00;                   /* define this SDH for reload */
#ifdef WAS_BEFORE_1501
     case ied_asrc_undefine:                /* undefine this SDH for reload */
       goto p_asr_und_00;                   /* undefine this SDH for reload */
#endif
     case ied_asrc_reload:                  /* reload saved SDH        */
       goto p_asr_rel_00;                   /* reload saved SDH        */
   }
   adsp_amsr->iec_asrr = ied_asrr_param_error;  /* parameter error     */
   return TRUE;

   p_asr_def_00:                            /* define this SDH for reload */
/**
   question 21.06.14 KB
   should only one SDH reload for each SDH or connection be allowed ???
*/
   if (adsp_amsr->imc_wait_seconds <= 0) {  /* wait seconds for destroy */
     adsp_amsr->iec_asrr = ied_asrr_param_error;  /* parameter error   */
     return TRUE;
   }
   adsl_auxf_1_w1 = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                    + sizeof(struct dsd_sdh_reload_auxf)
                                                    + adsp_amsr->imc_len_sdh_name );  /* length of SDH name */
   adsl_auxf_1_w1->iec_auxf_def = ied_auxf_sdh_reload;  /* SDH reload  */
   adsl_auxf_1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;
#ifdef TRACEHLP
#define IML_TEMP_LEN (sizeof(struct dsd_sdh_reload_auxf) + adsp_amsr->imc_len_sdh_name)
   adsl_auxf_1_w1->inc_size_mem = IML_TEMP_LEN;  /* size of memory     */
   ADSL_CONN1_G->inc_aux_mem_cur += adsl_auxf_1_w1->inc_size_mem;
   if (ADSL_CONN1_G->inc_aux_mem_max < ADSL_CONN1_G->inc_aux_mem_cur) {
     ADSL_CONN1_G->inc_aux_mem_max = ADSL_CONN1_G->inc_aux_mem_cur;
   }
#undef IML_TEMP_LEN
#endif
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsl_auxf_1_w1 + 1))
#ifdef XYZ1
//   ADSL_SRA_G->adsc_sdh_work_1;  /* work area server data hook */
   ADSL_SRA_G->achc_addr_pass_data = adsp_amsr->achc_addr_pass_data;  /* address of data to pass */
   ADSL_SRA_G->imc_len_pass_data = adsp_amsr->imc_len_pass_data;  /* length of data to pass */
#endif
   ADSL_SRA_G->imc_len_sdh_name = adsp_amsr->imc_len_sdh_name;  /* length of SDH name */
   ADSL_SRA_G->imc_wait_seconds = adsp_amsr->imc_wait_seconds;  /* wait seconds for destroy */
   ADSL_SRA_G->ac_conn1 = ADSL_CONN1_G;     /* for this connection     */
   memcpy( ADSL_SRA_G + 1, adsp_amsr->achc_addr_sdh_name, adsp_amsr->imc_len_sdh_name );
#ifdef XYZ1
   ADSL_SRA_G->imc_hookc
     = ((struct dsd_pd_work *) ((char *) ADSL_AUX_CF1 - offsetof( struct dsd_pd_work, dsc_aux_cf1 )))->imc_hookc;
#endif
   /* insert in AVL-tree SDH-reload                                    */
   dss_critsect_aux.m_enter();              /* critical section        */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                                 &dsl_htree1_work, &ADSL_SRA_G->dsc_sort_sdh_reload );  /* entry for sorting SDH-reload identifiers */
   if (bol_rc == FALSE) {                   /* error occured           */
     dss_critsect_aux.m_leave();            /* critical section        */
     free( adsl_auxf_1_w1 );
     adsp_amsr->iec_asrr = ied_asrr_internal_error;  /* internal error while processing */
     return TRUE;
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
     dss_critsect_aux.m_leave();            /* critical section        */
     free( adsl_auxf_1_w1 );
     adsp_amsr->iec_asrr = ied_asrr_double;  /* SDH name double        */
     return TRUE;
   }
   bol_rc = m_htree1_avl_insert( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                                 &dsl_htree1_work, &ADSL_SRA_G->dsc_sort_sdh_reload );  /* entry for sorting SDH-reload identifiers */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (bol_rc == FALSE) {                   /* error occured           */
     free( adsl_auxf_1_w1 );
     adsp_amsr->iec_asrr = ied_asrr_internal_error;  /* internal error while processing */
     return TRUE;
   }
#undef ADSL_SRA_G
   /* insert at anchor of chain                                        */
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
   adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   ADSL_CONN1_G->boc_survive = TRUE;        /* survive E-O-F client    */
   adsp_amsr->iec_asrr = ied_asrr_ok;       /* o.k.                    */
   return TRUE;

#ifdef WAS_BEFORE_1501
   p_asr_und_00:                            /* undefine this SDH for reload */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary extension fields */
   adsl_auxf_1_last = NULL;                 /* last auxiliary extension field */
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsl_auxf_1_w1 + 1))
     if (   (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sdh_reload)  /* SDH reload */
         && (!memcmp( &adsl_auxf_1_w1->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid)))
         && (ADSL_SRA_G->imc_len_sdh_name == adsp_amsr->imc_len_sdh_name)  /* length of SDH name */
         && (!memcmp( ADSL_SRA_G + 1, adsp_amsr->achc_addr_sdh_name, adsp_amsr->imc_len_sdh_name ))) {
       break;
     }
#undef ADSL_SRA_G
     adsl_auxf_1_last = adsl_auxf_1_w1;     /* last auxiliary extension field */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_w1 == NULL) {            /* not found in chain      */
     adsp_amsr->iec_asrr = ied_asrr_not_found;  /* saved SDH not found */
     return TRUE;
   }
#ifdef TRACEHLP
   ADSL_CONN1_G->inc_aux_mem_cur -= adsl_auxf_1_w1->inc_size_mem;
#endif
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
   if (adsl_auxf_1_last == NULL) {          /* last auxiliary extension field */
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1->adsc_next;  /* remove from chain auxiliary extension fields */
   } else {                                 /* middle in chain         */
     adsl_auxf_1_last->adsc_next = adsl_auxf_1_w1->adsc_next;  /* remove from chain auxiliary extension fields */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
   free( adsl_auxf_1_w1 );                  /* free memory auxiliary extension field */
   adsp_amsr->iec_asrr = ied_asrr_ok;       /* o.k.                    */
   return TRUE;
#endif

   p_asr_rel_00:                            /* reload saved SDH        */
#ifdef WAS_BEFORE_1501
   adsl_srs_last = NULL;                    /* last SDH, saved for reload */
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_srs_w1 = adss_sdh_reload_saved_ch;  /* chain SDHs, saved for reload */
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsl_srs_w1->adsc_auxf_1_sdh_reload + 1))
   while (adsl_srs_w1) {                    /* loop over chain SDHs, saved for reload */
     if (   (adsl_srs_w1->ac_cid_addr == ADSL_AUX_CF1->dsc_cid.ac_cid_addr)  /* address of component / SDH / PHL */
         && (ADSL_SRA_G->imc_len_sdh_name == adsp_amsr->imc_len_sdh_name)  /* length of SDH name */
         && (!memcmp( ADSL_SRA_G + 1, adsp_amsr->achc_addr_sdh_name, adsp_amsr->imc_len_sdh_name ))) {
       adsl_srs_w1->boc_reload_active = TRUE;  /* reload is active     */
       if (adsl_srs_last == NULL) {         /* last SDH, saved for reload */
         adss_sdh_reload_saved_ch = adsl_srs_w1->adsc_next;  /* remove from chain SDHs, saved for reload */
       } else {                             /* middle in chain         */
         adsl_srs_last->adsc_next = adsl_srs_w1->adsc_next;  /* remove from chain SDHs, saved for reload */
       }
       break;
     }
     adsl_srs_last = adsl_srs_w1;           /* last SDH, saved for reload */
     adsl_srs_w1 = adsl_srs_w1->adsc_next;  /* get next in chain       */
   }
   dss_critsect_aux.m_leave();              /* critical section        */
   if (adsl_srs_w1 == NULL) {               /* not found in chain      */
     adsp_amsr->iec_asrr = ied_asrr_not_found;  /* saved SDH not found */
     return TRUE;
   }
   m_time_rel( &adsl_srs_w1->dsc_timer_ele );   /* release timer       */
#undef ADSL_SRA_G
   ADSL_AUX_CF1->adsc_sdh_reload_saved = adsl_srs_w1;  /* SDH, saved for reload */
#endif
   if (adsp_amsr->imc_len_sdh_name > MAX_LEN_SDH_RELOAD_NAME) {  /* maximum length name SDH reload */
     adsp_amsr->iec_asrr = ied_asrr_param_error;  /* parameter error   */
     return TRUE;
   }
   memset( &dsl_sr_sort.dsc_sra_l, 0, sizeof(struct dsd_sdh_reload_auxf) );
   dsl_sr_sort.dsc_sra_l.imc_len_sdh_name = adsp_amsr->imc_len_sdh_name;  /* length of SDH name */
   memcpy( dsl_sr_sort.byrc_sdh_rn, adsp_amsr->achc_addr_sdh_name, adsp_amsr->imc_len_sdh_name );

   /* search entry in AVL-tree                                         */
   dss_critsect_aux.m_enter();              /* critical section        */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                                 &dsl_htree1_work, &dsl_sr_sort.dsc_sra_l.dsc_sort_sdh_reload );  /* entry for sorting SDH-reload identifiers */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_amsr->iec_asrr = ied_asrr_internal_error;  /* internal error while processing */
     return TRUE;
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     adsp_amsr->iec_asrr = ied_asrr_not_found;  /* saved SDH not found */
     return TRUE;
   }
#ifndef HELP_DEBUG
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_sdh_reload_auxf, dsc_sort_sdh_reload )))
#define ADSL_AUXF_SDHR_G ((struct dsd_auxf_1 *) ADSL_SRA_G - 1)
#else
   struct dsd_sdh_reload_auxf *ADSL_SRA_G = (struct dsd_sdh_reload_auxf *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_sdh_reload_auxf, dsc_sort_sdh_reload ));
   struct dsd_auxf_1 *ADSL_AUXF_SDHR_G = (struct dsd_auxf_1 *) ADSL_SRA_G - 1;
#endif
   ADSL_AUX_CF1->ac_sdhr_conn1 = ADSL_SRA_G->ac_conn1;  /* reload SDH from this connection */
   ADSL_AUX_CF1->dsc_sdhr_cid = ADSL_AUXF_SDHR_G->dsc_cid;  /* component identifier */
// ADSL_CONN1_G->boc_survive = TRUE;        /* survive E-O-F client    */
   adsp_amsr->iec_asrr = ied_asrr_ok;       /* o.k.                    */
   return TRUE;
#ifndef HELP_DEBUG
#undef ADSL_SRA_G
#undef ADSL_AUXF_SDHR_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* m_aux_sdh_reload_call()                                           */

#ifdef WAS_BEFORE_1501
/** SDH reload - old connection / session ends                         */
static void m_sdh_reload_old_end( struct dsd_aux_cf1 *adsp_aux_cf1, struct dsd_auxf_1 *adsp_auxf_1 ) {
   struct dsd_sdh_reload_saved *adsl_srs_w1;  /* SDHs, saved for reload */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w4;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w5;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* current entry in chain  */
   struct dsd_auxf_1 *adsl_auxf_1_last;     /* last entry in chain     */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* control area server data hook */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current control area server data hook */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last control area server data hook */
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */

#define ADSL_CONN1_G (adsp_aux_cf1->adsc_conn)  /* pointer on connection */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_old_end( adsp_aux_cf1=%p , adsp_auxf_1=%p ) called ADSL_CONN1_G=%p.",
                   __LINE__, adsp_aux_cf1, adsp_auxf_1, ADSL_CONN1_G );
//#endif

   adsl_srs_w1 = (struct dsd_sdh_reload_saved *) malloc( sizeof(struct dsd_sdh_reload_saved) );  /* SDH, saved for reload */
   memset( adsl_srs_w1, 0, sizeof(struct dsd_sdh_reload_saved) );
   adsl_srs_w1->adsc_auxf_1_sdh_reload = adsp_auxf_1;  /* auxiliary extension field for reload */
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary extension fields */
   adsl_auxf_1_last = NULL;                 /* last auxiliary extension field */
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
     adsl_auxf_1_cur = adsl_auxf_1_w1;      /* current auxiliary extension field */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     switch (adsl_auxf_1_w1->iec_auxf_def) {
       case ied_auxf_timer:                 /* timer                   */
         do {                               /* pseudo-loop             */
           /* remove this from timer chain                             */
           adsl_auxf_1_w4 = ADSL_CONN1_G->adsc_aux_timer_ch;
           adsl_auxf_1_w5 = NULL;           /* clear previous entry    */
           while (adsl_auxf_1_w4) {         /* loop over all timer entries */
             if (adsl_auxf_1_w4 == adsl_auxf_1_w1) {  /* entry found   */
// to-do 20.01.15 KB - enter critical section
#ifndef B150121
#ifndef HL_UNIX
               EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
               ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section */
#endif
#endif
               if (adsl_auxf_1_w5 == NULL) {  /* was first entry       */
                 ADSL_CONN1_G->adsc_aux_timer_ch
                   = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
               } else {                     /* middle in chain         */
                 ((struct dsd_aux_timer *) (adsl_auxf_1_w5 + 1))->adsc_auxf_next
                   = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
               }
#ifndef B150121
#ifndef HL_UNIX
               LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
               ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section */
#endif
#endif
               break;                       /* entry found             */
             }
             adsl_auxf_1_w5 = adsl_auxf_1_w4;  /* save previous entry  */
             adsl_auxf_1_w4 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
           }
           /* if adsl_auxf_1_w4 NULL, that timer not found, error      */
         } while (FALSE);
         /* fall thru                                                  */
       case ied_auxf_normstor:              /* normal storage          */
       case ied_auxf_defstor:               /* predefined storage      */
       case ied_auxf_sdh_reload:            /* SDH reload              */
         adsl_auxf_1_w1->adsc_next = adsl_srs_w1->adsc_auxf_1_ch;  /* chain auxiliary ext fields */
         adsl_srs_w1->adsc_auxf_1_ch = adsl_auxf_1_w1;  /* new chain auxiliary ext fields */
         break;                             /* free total memory       */
       default:
#ifndef HL_UNIX
         EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#endif
         if (adsl_auxf_1_last == NULL) {    /* at beginning of chain   */
           ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_cur;  /* set chain auxiliary extension fields */
         } else {                           /* middle in chain         */
           adsl_auxf_1_last->adsc_next = adsl_auxf_1_cur;  /* append to chain auxiliary extension fields */
         }
#ifndef HL_UNIX
         LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
         adsl_auxf_1_last = adsl_auxf_1_cur;  /* last auxiliary extension field */
         break;
     }
   }
   if (adsl_auxf_1_last) {                  /* last auxiliary extension field */
     adsl_auxf_1_last->adsc_next = NULL;    /* set end of chain        */
   }
   m_sdh_cleanup( adsp_aux_cf1, &adsp_auxf_1->dsc_cid );  /* cleanup other resources of old Server-Data-Hook */

   adsl_sdhc1_last = NULL;                  /* last control area server data hook */
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_enter();    /* critical section        */
#endif
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-aux.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* chain of buffers input output */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, &adsp_auxf_1->dsc_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsl_srs_w1->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsl_srs_w1->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave of old list       */
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
     }
   }
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }

   adsl_sdhc1_last = NULL;                  /* last control area server data hook */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* chain of buffers in use */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, &adsp_auxf_1->dsc_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsl_srs_w1->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsl_srs_w1->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave of old list       */
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         ADSL_CONN1_G->adsc_sdhc1_inuse = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
     }
   }
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }

   adsl_sdhc1_last = NULL;                  /* last control area server data hook */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_extra;  /* chain of buffers extra */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, &adsp_auxf_1->dsc_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsl_srs_w1->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsl_srs_w1->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave of old list       */
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         ADSL_CONN1_G->adsc_sdhc1_extra = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
     }
   }
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }

#ifndef HL_UNIX
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_G->dsc_critsect.m_leave();    /* critical section        */
#endif
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsp_auxf_1 + 1))
   if (ADSL_SRA_G->imc_hookc >= 0) {        /* is Server-Data-Hook     */
     adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       memcpy( &adsl_srs_w1->dsc_sdh_s_1, &ADSL_CONN1_G->dsc_sdh_s_1, sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       memcpy( &adsl_srs_w1->dsc_sdh_s_1,
               &ADSL_CONN1_G->adsrc_sdh_s_1[ ADSL_SRA_G->imc_hookc ],
               sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
       ADSL_CONN1_G->adsrc_sdh_s_1[ ADSL_SRA_G->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
   }
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_srs_w1->adsc_next = adss_sdh_reload_saved_ch;  /* chain SDHs, saved for reload */
   adss_sdh_reload_saved_ch = adsl_srs_w1;  /* chain SDHs, saved for reload */
   dss_critsect_aux.m_leave();              /* critical section        */
   adsl_srs_w1->dsc_timer_ele.amc_compl = &m_sdh_reload_timeout;  /* set routine for free after timer */
   adsl_srs_w1->dsc_timer_ele.ilcwaitmsec = ADSL_SRA_G->imc_wait_seconds * 1000;  /* wait seconds for destroy */
   m_time_set( &adsl_srs_w1->dsc_timer_ele, FALSE );  /* set timer     */
#undef ADSL_SRA_G
#undef ADSL_CONN1_G
} /* m_sdh_reload_old_end()                                            */
#endif

/** SDH reload - old connection / get resources                        */
/**
   called in critical section of conn1
*/
static void m_sdh_reload_old_resources( DSD_CONN_G *adsp_conn1,
                                        struct dsd_cid *adsp_cid,
                                        struct dsd_sdh_reload_saved *adsp_srs ) {
   int        iml_hookc;                    /* number of the hook      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w4;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w5;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* current entry in chain  */
// struct dsd_auxf_1 *adsl_auxf_1_last;     /* last entry in chain     */
   struct dsd_auxf_1 **aadsl_auxf_1_ch;     /* last entry in chain     */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* control area server data hook */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur;  /* current control area server data hook */
// struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last control area server data hook */
   struct dsd_sdh_control_1 **aadsl_sdhc1_ch;  /* last control area server data hook */
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_old_resources( adsp_conn1=%p , adsp_cid=%p , adsp_srs=%p ) called",
                   __LINE__, adsp_conn1, adsp_cid, adsp_srs );
#endif

   memset( adsp_srs, 0, sizeof(struct dsd_sdh_reload_saved) );
   adsl_auxf_1_w1 = adsp_conn1->adsc_auxf_1;  /* get chain auxiliary extension fields */
// adsl_auxf_1_last = NULL;                 /* last auxiliary extension field */
   aadsl_auxf_1_ch = &adsp_conn1->adsc_auxf_1;  /* last entry in chain */
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
     adsl_auxf_1_cur = adsl_auxf_1_w1;      /* current auxiliary extension field */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
     if (!memcmp( &adsl_auxf_1_cur->dsc_cid, adsp_cid, sizeof(struct dsd_cid) )) {
       switch (adsl_auxf_1_cur->iec_auxf_def) {
         case ied_auxf_timer:               /* timer                   */
           do {                             /* pseudo-loop             */
             /* remove this from timer chain                             */
             adsl_auxf_1_w4 = adsp_conn1->adsc_aux_timer_ch;
             adsl_auxf_1_w5 = NULL;         /* clear previous entry    */
             while (adsl_auxf_1_w4) {       /* loop over all timer entries */
               if (adsl_auxf_1_w4 == adsl_auxf_1_cur) {  /* entry found   */
  #ifdef B150330
  // to-do 20.01.15 KB - enter critical section
  #ifndef B150121
  #ifndef HL_UNIX
                 EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
  #else
                 adsp_conn1->dsc_critsect.m_enter();  /* critical section */
  #endif
  #endif
  #endif
                 if (adsl_auxf_1_w5 == NULL) {  /* was first entry       */
                   adsp_conn1->adsc_aux_timer_ch
                     = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
                 } else {                     /* middle in chain         */
                   ((struct dsd_aux_timer *) (adsl_auxf_1_w5 + 1))->adsc_auxf_next
                     = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
                 }
  #ifdef B150330
  #ifndef B150121
  #ifndef HL_UNIX
                 LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
  #else
                 adsp_conn1->dsc_critsect.m_leave();  /* critical section */
  #endif
  #endif
  #endif
                 break;                       /* entry found             */
               }
               adsl_auxf_1_w5 = adsl_auxf_1_w4;  /* save previous entry  */
               adsl_auxf_1_w4 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
             }
             /* if adsl_auxf_1_w4 NULL, that timer not found, error      */
           } while (FALSE);
           /* fall thru                                                  */
         case ied_auxf_normstor:            /* normal storage          */
         case ied_auxf_defstor:             /* predefined storage      */
         case ied_auxf_sdh_reload:          /* SDH reload              */
         case ied_auxf_sip:                 /* SIP request             */
         case ied_auxf_udp:                 /* UDP request             */
           adsl_auxf_1_cur->adsc_next = adsp_srs->adsc_auxf_1_ch;  /* chain auxiliary ext fields */
           adsp_srs->adsc_auxf_1_ch = adsl_auxf_1_cur;  /* new chain auxiliary ext fields */
           adsl_auxf_1_cur = NULL;          /* this memory moved       */
           break;                           /* resource transfered     */
       }
     }
     if (adsl_auxf_1_cur) {                 /* current auxiliary extension field */
       *aadsl_auxf_1_ch = adsl_auxf_1_cur;  /* last entry in chain     */
       aadsl_auxf_1_ch = &adsl_auxf_1_cur->adsc_next;  /* last entry in chain     */
     }
   }
   *aadsl_auxf_1_ch = NULL;                 /* last entry in chain     */
#ifdef OLD01
   if (adsl_auxf_1_last) {                  /* last auxiliary extension field */
     adsl_auxf_1_last->adsc_next = NULL;    /* set end of chain        */
   }
#endif

// adsl_sdhc1_last = NULL;                  /* last control area server data hook */
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* chain of buffers input output */
   aadsl_sdhc1_ch = &adsp_conn1->adsc_sdhc1_chain;  /* last control area server data hook */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, adsp_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsp_srs->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsp_srs->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave of old list       */
#ifdef OLD01
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         adsp_conn1->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
#endif
       *aadsl_sdhc1_ch = adsl_sdhc1_cur;    /* last control area server data hook */
       aadsl_sdhc1_ch = &adsl_sdhc1_cur->adsc_next;  /* last control area server data hook */
     }
   }
#ifdef OLD01
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }
#endif
   *aadsl_sdhc1_ch = NULL;                  /* last control area server data hook */

// adsl_sdhc1_last = NULL;                  /* last control area server data hook */
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
   aadsl_sdhc1_ch = &adsp_conn1->adsc_sdhc1_inuse;  /* last control area server data hook */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, adsp_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsp_srs->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsp_srs->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave in old list       */
#ifdef OLD01
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
#endif
       *aadsl_sdhc1_ch = adsl_sdhc1_cur;    /* last control area server data hook */
       aadsl_sdhc1_ch = &adsl_sdhc1_cur->adsc_next;  /* last control area server data hook */
     }
   }
#ifdef OLD01
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }
#endif
   *aadsl_sdhc1_ch = NULL;                  /* last control area server data hook */

// adsl_sdhc1_last = NULL;                  /* last control area server data hook */
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_extra;  /* chain of buffers extra */
   aadsl_sdhc1_ch = &adsp_conn1->adsc_sdhc1_extra;  /* last control area server data hook */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers in use */
     adsl_sdhc1_cur = adsl_sdhc1_w1;        /* current control area server data hook */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     if (   (adsl_sdhc1_cur->imc_usage_count != 0)  /* usage count     */
         && (!memcmp( &adsl_sdhc1_cur->dsc_cid, adsp_cid, sizeof(struct dsd_cid) ))) {
       adsl_sdhc1_cur->adsc_next = adsp_srs->adsc_sdhc1_chain;  /* chain of buffers input output */
       adsp_srs->adsc_sdhc1_chain = adsl_sdhc1_cur;  /* new chain of buffers input output */
     } else {                               /* leave in old list       */
#ifdef OLD01
       if (adsl_sdhc1_last == NULL) {       /* at beginning of chain   */
         adsp_conn1->adsc_sdhc1_extra = adsl_sdhc1_cur;  /* set chain buffers */
       } else {                             /* middle in chain         */
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_cur;  /* append to chain buffers */
       }
       adsl_sdhc1_last = adsl_sdhc1_cur;    /* last control area server data hook */
#endif
       *aadsl_sdhc1_ch = adsl_sdhc1_cur;    /* last control area server data hook */
       aadsl_sdhc1_ch = &adsl_sdhc1_cur->adsc_next;  /* last control area server data hook */
     }
   }
#ifdef OLD01
   if (adsl_sdhc1_last) {                   /* we have chain with last control area server data hook */
     adsl_sdhc1_last->adsc_next = NULL;     /* set end of chain        */
   }
#endif
   *aadsl_sdhc1_ch = NULL;                  /* last control area server data hook */

   adsl_server_conf_1_used = adsp_conn1->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     memcpy( &adsp_srs->dsc_sdh_s_1, &adsp_conn1->dsc_sdh_s_1, sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
     adsp_conn1->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
   } else {
     iml_hookc                              /* number of the hook      */
       = ((struct dsd_sdh_session_1 *) adsp_cid->ac_cid_addr)
           - ((struct dsd_sdh_session_1 *) (adsl_server_conf_1_used + 1));
     memcpy( &adsp_srs->dsc_sdh_s_1,
             &adsp_conn1->adsrc_sdh_s_1[ iml_hookc ],
             sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
     adsp_conn1->adsrc_sdh_s_1[ iml_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
   }
} /* end m_sdh_reload_old_resources()                                  */

/** SDH reload - new connection / insert resources                     */
static void m_sdh_reload_new_resources( void *vpp_userfld,
                                        struct dsd_sdh_reload_saved *adsp_srs ) {
   int        iml_hookc;                    /* number of the hook      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension field */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_new_resources( vpp_userfld=%p , adsp_srs=%p ) called ADSL_CONN1_G=%p.",
                   __LINE__, vpp_userfld, adsp_srs, ADSL_CONN1_G );
//#endif

   m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of old Server-Data-Hook */

   while (adsp_srs->adsc_auxf_1_ch) {       /* chain auxiliary ext fields */
     adsl_auxf_1_w1 = adsp_srs->adsc_auxf_1_ch;  /* get first entry chain auxiliary ext fields */
     adsp_srs->adsc_auxf_1_ch = adsl_auxf_1_w1->adsc_next;  /* new chain auxiliary ext fields */
     switch (adsl_auxf_1_w1->iec_auxf_def) {
#ifdef XYZ1
       case ied_auxf_sdh_reload:            /* SDH reload              */
         free( adsl_auxf_1_w1 );            /* free memory             */
         adsl_auxf_1_w1 = NULL;             /* not for new SDH         */
         break;                             /* free total memory       */
#endif
#ifdef NOT_YET_150108
       case ied_auxf_sip:                   /* SIP request             */
#define ADSL_SIP_ENTRY_1_G ((struct dsd_sip_entry_1 *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))
         ADSL_SIP_ENTRY_1_G->adsc_conn1 = ADSL_CONN1_G;  /* for this connection */
#undef ADSL_SIP_ENTRY_1_G
         break;
       case ied_auxf_udp:                   /* UDP request             */
#define ADSL_UDP_MULTIW_1_G ((struct dsd_udp_multiw_1 *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))
#define ADSL_UDP_GW_1_G ((struct dsd_udp_gw_1 *) (ADSL_UDP_MULTIW_1_G + 1))
        ADSL_UDP_GW_1_G->adsc_conn1 = ADSL_CONN1_G;  /* for this connection */
#undef ADSL_UDP_MULTIW_1_G
#undef ADSL_UDP_GW_1_G
         break;                             /* pass to new SDH         */
#endif
       case ied_auxf_sip:                   /* SIP request             */
         m_sip_set_conn1( (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1), ADSL_CONN1_G );
         break;
       case ied_auxf_udp:                   /* UDP request             */
         m_udp_set_conn1( (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1), ADSL_CONN1_G );
         break;                             /* pass to new SDH         */
       case ied_auxf_sdh_reload:            /* SDH reload              */
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsl_auxf_1_w1 + 1))
         ADSL_SRA_G->ac_conn1 = ADSL_CONN1_G;  /* for this connection  */
#undef ADSL_SRA_G
         break;                             /* pass to new SDH         */
       case ied_auxf_util_thread:           /* utility thread */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_w1 + 1))
         ADSL_UTC_G->dsc_ete.ac_conn1 = ADSL_CONN1_G;  /* for this connection */
#undef ADSL_UTC_G
         break;                             /* pass to new SDH         */
       case ied_auxf_pipe_listen:           /* aux-pipe create with name */
#define ADSL_APL_G ((struct dsd_aux_pipe_listen *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))  /* aux-pipe listen control structure */
         ADSL_APL_G->ac_conn1 = ADSL_CONN1_G;  /* for this connection  */
#undef ADSL_APL_G
         break;                             /* pass to new SDH         */
       case ied_auxf_timer:                 /* timer                   */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
// to-do 21.06.14 KB - dsc_cid need only once, in first header
         memcpy( &ADSL_AUX_T->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* set component */
         if (ADSL_CONN1_G->adsc_aux_timer_ch == NULL) {  /* no element in chain yet */
           ADSL_AUX_T->adsc_auxf_next = NULL;  /* clear next in chain  */
           ADSL_CONN1_G->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is only element */
           break;                           /* all done                */
         }
         if (((struct dsd_aux_timer *) (ADSL_CONN1_G->adsc_aux_timer_ch + 1))->ilc_endtime
               > ADSL_AUX_T->ilc_endtime) {
           ADSL_AUX_T->adsc_auxf_next = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get old chain */
           ADSL_CONN1_G->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is first element */
           break;                           /* all done                */
         }
         /* get correct position in chain                              */
         adsl_auxf_1_w2 = ADSL_CONN1_G->adsc_aux_timer_ch;
         while (TRUE) {
           adsl_auxf_1_w3 = adsl_auxf_1_w2;
           adsl_auxf_1_w2 = ((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->adsc_auxf_next;
           if (adsl_auxf_1_w2 == NULL) break;
           if (((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->ilc_endtime
                 < ADSL_AUX_T->ilc_endtime) {
             break;
           }
         }
         ADSL_AUX_T->adsc_auxf_next = adsl_auxf_1_w2;
         ((struct dsd_aux_timer *) (adsl_auxf_1_w3 + 1))->adsc_auxf_next
           = adsl_auxf_1_w1;
         break;                             /* free total memory       */
#undef ADSL_AUX_T
     }
     if (adsl_auxf_1_w1) {                  /* pass to new SDH         */
       adsl_auxf_1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;
       adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain auxiliary extension fields */
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set chain auxiliary extension fields */
     }
   }

   if (adsp_srs->adsc_sdhc1_chain) {        /* chain of buffers input output */
     adsl_sdhc1_w1 = adsp_srs->adsc_sdhc1_chain;  /* get chain of buffers input output */
     while (TRUE) {                         /* loop to set session identifier */
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;
       if (adsl_sdhc1_w1->adsc_next == NULL) break;  /* is last in chain */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
     }
     adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* append old chain */
     ADSL_CONN1_G->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* set new anchor */
   }

   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     memcpy( &ADSL_CONN1_G->dsc_sdh_s_1, &adsp_srs->dsc_sdh_s_1, sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
     ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = FALSE;  /* processing of this SDH has not ended */
   } else {
     iml_hookc                              /* number of the hook      */
       = ((struct dsd_sdh_session_1 *) ADSL_AUX_CF1->dsc_cid.ac_cid_addr)
           - ((struct dsd_sdh_session_1 *) (adsl_server_conf_1_used + 1));
     memcpy( &ADSL_CONN1_G->adsrc_sdh_s_1[ iml_hookc ],
             &adsp_srs->dsc_sdh_s_1,
             sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
     ADSL_CONN1_G->adsrc_sdh_s_1[ iml_hookc ].boc_ended = FALSE;  /* processing of this SDH has not ended */
   }
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_sdh_reload_new_resources()                                  */

/** SDH reload - old connection / session ends                         */
static void m_sdh_reload_old_end( struct dsd_aux_cf1 *adsp_aux_cf1, struct dsd_auxf_1 *adsp_auxf_1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#define ADSL_CONN1_G (adsp_aux_cf1->adsc_conn)  /* pointer on connection */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_old_end( adsp_aux_cf1=%p , adsp_auxf_1=%p ) called ADSL_CONN1_G=%p.",
                   __LINE__, adsp_aux_cf1, adsp_auxf_1, ADSL_CONN1_G );
//#endif

#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsp_auxf_1 + 1))
   /* the routine may be called mulitple times                         */
   if (ADSL_SRA_G->ac_conn1 == NULL) return;  /* for this connection   */
   ADSL_SRA_G->ac_conn1 = NULL;             /* set all destroyed       */

   /* delete entry in AVL-tree SDH-reload                              */
   dss_critsect_aux.m_enter();              /* critical section        */
   bol_rc = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                                 &dsl_htree1_work, &ADSL_SRA_G->dsc_sort_sdh_reload );  /* entry for sorting SDH-reload identifiers */
   if (bol_rc == FALSE) {                   /* error occured           */
     dss_critsect_aux.m_leave();            /* critical section        */
     m_hlnew_printf( HLOG_WARN1, "HWSPMXXXX-%05d-W m_sdh_reload_old_end() m_htree1_avl_search() returned FALSE",
                     __LINE__ );
     return;
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     dss_critsect_aux.m_leave();            /* critical section        */
     m_hlnew_printf( HLOG_WARN1, "HWSPMXXXX-%05d-W m_sdh_reload_old_end() m_htree1_avl_search() entry \"%.*s\" returned FALSE",
                     __LINE__, ADSL_SRA_G->imc_len_sdh_name, ADSL_SRA_G + 1 );
     return;
   }
   bol_rc = m_htree1_avl_delete( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                                 &dsl_htree1_work );
   dss_critsect_aux.m_leave();              /* critical section        */
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMXXXX-%05d-W m_sdh_reload_old_end() m_htree1_avl_delete() returned FALSE",
                     __LINE__ );
   }
#undef ADSL_SRA_G
#undef ADSL_CONN1_G
} /* m_sdh_reload_old_end()                                            */

#ifdef WAS_BEFORE_1501
/** SDH reload - replace SDH now                                       */
static void m_sdh_reload_do( void *vpp_userfld, int imp_hookc ) {
   struct dsd_sdh_reload_saved *adsl_srs_w1;  /* SDH, saved for reload */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension field */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension field */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_do( vpp_userfld=%p , imp_hookc=%d ) called ADSL_CONN1_G=%p.",
                   __LINE__, vpp_userfld, imp_hookc, ADSL_CONN1_G );
//#endif

   m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of old Server-Data-Hook */

#ifdef WAS_BEFORE_1501
   adsl_srs_w1 = ADSL_AUX_CF1->adsc_sdh_reload_saved;  /* SDH, saved for reload */
#endif

#ifdef WAS_BEFORE_1501
   while (adsl_srs_w1->adsc_auxf_1_ch) {    /* chain auxiliary ext fields */
     adsl_auxf_1_w1 = adsl_srs_w1->adsc_auxf_1_ch;  /* get first entry chain auxiliary ext fields */
     adsl_srs_w1->adsc_auxf_1_ch = adsl_auxf_1_w1->adsc_next;  /* new chain auxiliary ext fields */
     switch (adsl_auxf_1_w1->iec_auxf_def) {
       case ied_auxf_sdh_reload:            /* SDH reload              */
         free( adsl_auxf_1_w1 );            /* free memory             */
         adsl_auxf_1_w1 = NULL;             /* not for new SDH         */
         break;                             /* free total memory       */
       case ied_auxf_timer:                 /* timer                   */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
// to-do 21.06.14 KB - dsc_cid need only once, in first header
         memcpy( &ADSL_AUX_T->dsc_cid, &ADSL_AUX_CF1->dsc_cid, sizeof(struct dsd_cid) );  /* set component */
         if (ADSL_CONN1_G->adsc_aux_timer_ch == NULL) {  /* no element in chain yet */
           ADSL_AUX_T->adsc_auxf_next = NULL;  /* clear next in chain  */
           ADSL_CONN1_G->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is only element */
           break;                           /* all done                */
         }
         if (((struct dsd_aux_timer *) (ADSL_CONN1_G->adsc_aux_timer_ch + 1))->ilc_endtime
               > ADSL_AUX_T->ilc_endtime) {
           ADSL_AUX_T->adsc_auxf_next = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get old chain */
           ADSL_CONN1_G->adsc_aux_timer_ch = adsl_auxf_1_w1;  /* this is first element */
           break;                           /* all done                */
         }
         /* get correct position in chain                              */
         adsl_auxf_1_w2 = ADSL_CONN1_G->adsc_aux_timer_ch;
         while (TRUE) {
           adsl_auxf_1_w3 = adsl_auxf_1_w2;
           adsl_auxf_1_w2 = ((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->adsc_auxf_next;
           if (adsl_auxf_1_w2 == NULL) break;
           if (((struct dsd_aux_timer *) (adsl_auxf_1_w2 + 1))->ilc_endtime
                 < ADSL_AUX_T->ilc_endtime) {
             break;
           }
         }
         ADSL_AUX_T->adsc_auxf_next = adsl_auxf_1_w2;
         ((struct dsd_aux_timer *) (adsl_auxf_1_w3 + 1))->adsc_auxf_next
           = adsl_auxf_1_w1;
         break;                             /* free total memory       */
#undef ADSL_AUX_T
     }
     if (adsl_auxf_1_w1) {                  /* pass to new SDH         */
       adsl_auxf_1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;
       adsl_auxf_1_w1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain auxiliary extension fields */
       ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* set chain auxiliary extension fields */
     }
   }

   if (adsl_srs_w1->adsc_sdhc1_chain) {     /* chain of buffers input output */
     adsl_sdhc1_w1 = adsl_srs_w1->adsc_sdhc1_chain;  /* get chain of buffers input output */
     while (TRUE) {                         /* loop to set session identifier */
       adsl_sdhc1_w1->dsc_cid = ADSL_AUX_CF1->dsc_cid;
       if (adsl_sdhc1_w1->adsc_next == NULL) break;  /* is last in chain */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
     }
     adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* append old chain */
     ADSL_CONN1_G->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* set new anchor */
   }

   if (imp_hookc >= 0) {                    /* is Server-Data-Hook     */
     adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       memcpy( &ADSL_CONN1_G->dsc_sdh_s_1, &adsl_srs_w1->dsc_sdh_s_1, sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = FALSE;  /* processing of this SDH has not ended */
     } else {
       memcpy( &ADSL_CONN1_G->adsrc_sdh_s_1[ imp_hookc ],
               &adsl_srs_w1->dsc_sdh_s_1,
               sizeof(struct dsd_sdh_session_1) );  /* copy work area server data hook per session */
       ADSL_CONN1_G->adsrc_sdh_s_1[ imp_hookc ].boc_ended = FALSE;  /* processing of this SDH has not ended */
     }
   }

   free( adsl_srs_w1 );                     /* free memory SDH, saved for reload */
#endif
#ifdef WAS_BEFORE_1501
   ADSL_AUX_CF1->adsc_sdh_reload_saved = NULL;  /* no more SDH, saved for reload */
#endif

#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* m_sdh_reload_do()                                                 */

/** SDH reload timeout                                                 */
static void m_sdh_reload_timeout( struct dsd_timer_ele *adsp_timer_ele ) {
   struct dsd_sdh_reload_saved *adsl_srs_w1;  /* SDHs, saved for reload */
   struct dsd_sdh_reload_saved *adsl_srs_last;  /* last SDH, saved for reload */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */

#define ADSL_SRS_G ((struct dsd_sdh_reload_saved *) ((char *) adsp_timer_ele - offsetof( struct dsd_sdh_reload_saved, dsc_timer_ele )))
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_reload_timeout( adsp_timer_ele=%p ) called ADSL_SRA_G=%p.",
                   __LINE__, adsp_timer_ele, ADSL_SRS_G );
//#endif
   if (ADSL_SRS_G->boc_reload_active) return;  /* reload is active     */

#ifdef WAS_BEFORE_1501
   adsl_srs_last = NULL;                    /* last SDH, saved for reload */
   dss_critsect_aux.m_enter();              /* critical section        */
   if (ADSL_SRS_G->boc_reload_active == FALSE) {  /* reload is not active */
     adsl_srs_w1 = adss_sdh_reload_saved_ch;  /* chain SDHs, saved for reload */
     while (adsl_srs_w1) {                  /* loop over chain SDHs, saved for reload */
       if (adsl_srs_w1 = ADSL_SRS_G) {      /* entry found             */
         if (adsl_srs_last == NULL) {         /* last SDH, saved for reload */
           adss_sdh_reload_saved_ch = adsl_srs_w1->adsc_next;  /* remove from chain SDHs, saved for reload */
         } else {                             /* middle in chain         */
           adsl_srs_last->adsc_next = adsl_srs_w1->adsc_next;  /* remove from chain SDHs, saved for reload */
         }
         break;
       }
       adsl_srs_last = adsl_srs_w1;         /* last SDH, saved for reload */
       adsl_srs_w1 = adsl_srs_w1->adsc_next;  /* get next in chain     */
     }
   }
   dss_critsect_aux.m_leave();              /* critical section        */
   if (adsl_srs_w1 == NULL) {               /* not found in chain      */
// to-do 21.06.14 KB - error message
     return;
   }
   while (adsl_srs_w1->adsc_auxf_1_ch) {    /* loop over chain auxiliary extension fields */
     adsl_auxf_1_w1 = adsl_srs_w1->adsc_auxf_1_ch;  /* chain auxiliary extension fields */
     adsl_srs_w1->adsc_auxf_1_ch = adsl_auxf_1_w1->adsc_next;  /* remove from chain */
     switch (adsl_auxf_1_w1->iec_auxf_def) {
       case ied_auxf_normstor:              /* normal storage          */
         break;                             /* free total memory       */
       case ied_auxf_defstor:               /* predefined storage      */
         m_proc_free( adsl_auxf_1_w1 );     /* put in chain of unused  */
         adsl_auxf_1_w1 = NULL;             /* no memory to free       */
         break;
       case ied_auxf_sdh_reload:            /* SDH reload              */
         break;                             /* free total memory       */
       case ied_auxf_timer:                 /* timer                   */
         break;                             /* free total memory       */
       default:
         m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW m_sdh_reload_timeout() l%05d cannot free resource %p iec_auxf_def %d.",
                         __LINE__, adsl_auxf_1_w1, adsl_auxf_1_w1->iec_auxf_def );
         adsl_auxf_1_w1 = NULL;             /* no memory to free       */
         break;
     }
     if (adsl_auxf_1_w1) free( adsl_auxf_1_w1 );  /* free memory       */
   }
   while (adsl_srs_w1->adsc_sdhc1_chain) {  /* loop over chain of buffers input output */
     adsl_sdhc1_w1 = adsl_srs_w1->adsc_sdhc1_chain;  /* chain of buffers input output */
     adsl_srs_w1->adsc_sdhc1_chain = adsl_sdhc1_w1->adsc_next;  /* remove from chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free memory             */
   }
   free( adsl_srs_w1 );                     /* free memory again       */
#endif
#undef ADSL_SRS_G
} /* m_sdh_reload_timeout()                                            */
#endif

/** SDH reload client ended                                            */
static void m_sdh_reload_client_ended( DSD_CONN_G *adsp_conn1 ) {
   int        iml_timeout;                  /* timeout in seconds      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_cid dsl_cid;                  /* component identifier    */

   iml_timeout = 0;                         /* timeout in seconds      */
   adsl_auxf_1_w1 = adsp_conn1->adsc_auxf_1;  /* get chain auxiliary extension fields */
   while (adsl_auxf_1_w1) {                 /* loop over chain auxiliary extension fields */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sdh_reload) {  /* SDH reload */
#define ADSL_SRA_G ((struct dsd_sdh_reload_auxf *) (adsl_auxf_1_w1 + 1))
       if (   (iml_timeout == 0)            /* not yet set             */
           || (ADSL_SRA_G->imc_wait_seconds < iml_timeout)) {  /* wait seconds for destroy */
         iml_timeout = ADSL_SRA_G->imc_wait_seconds;  /* wait seconds for destroy */
       }
#undef ADSL_SRA_G
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   if (iml_timeout == 0) {                  /* timeout in seconds      */
// to-do 04.01.15 KB - error message
     return;
   }
// 05.01.15 KB - only for testing
// iml_timeout = 30;                        /* timeout in seconds      */
   memset( &dsl_cid, 0, sizeof(struct dsd_cid) );  /* component identifier */
   dsl_cid.iec_src_func = ied_src_fu_to_sdh_relo;  /* timeout SDH reload */
   m_aux_timer_new( adsp_conn1, &dsl_cid, iml_timeout * 1000, ied_auxtu_sdh_reload );  /* wait for SDH-reload */
} /* end m_sdh_reload_client_ended()                                   */

/** compare entries in AVL tree of SDH-reload                          */
static int m_cmp_aux_sdh_reload( void *,
                                 struct dsd_htree1_avl_entry *adsp_entry_1,
                                 struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml1;                         /* working variable        */
#define ADSL_SRA_P1 ((struct dsd_sdh_reload_auxf *) ((char *) adsp_entry_1 - offsetof( struct dsd_sdh_reload_auxf, dsc_sort_sdh_reload )))
#define ADSL_SRA_P2 ((struct dsd_sdh_reload_auxf *) ((char *) adsp_entry_2 - offsetof( struct dsd_sdh_reload_auxf, dsc_sort_sdh_reload )))
   iml1 = ADSL_SRA_P1->imc_len_sdh_name;    /* length of SDH name      */
   if (iml1 > ADSL_SRA_P2->imc_len_sdh_name) iml1 = ADSL_SRA_P2->imc_len_sdh_name;
   iml1 = memcmp( ADSL_SRA_P1 + 1, ADSL_SRA_P2 + 1, iml1 );
   if (iml1 != 0) return iml1;
   return ADSL_SRA_P1->imc_len_sdh_name - ADSL_SRA_P2->imc_len_sdh_name;
#undef ADSL_SRA_P1
#undef ADSL_SRA_P2
} /* end m_cmp_aux_sdh_reload()                                        */

/** get string with user identity for L2TP session                     */
extern "C" int m_l2tp_pass_session_owner( struct dsd_l2tp_session *adsp_l2tp_session, char *achp_area, int imp_len_area ) {
   int        iml1, iml2, iml3;             /* working variables       */
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */

#ifndef HL_UNIX
   adsl_conn1_l = ((class clconn1 *)
                     ((char *) adsp_l2tp_session
                        - offsetof( class clconn1, dsc_l2tp_session )));
#endif
#ifdef HL_UNIX
   adsl_conn1_l = ((struct dsd_conn1 *)
                     ((char *) adsp_l2tp_session
                        - offsetof( struct dsd_conn1, dsc_l2tp_session )));
#endif
   adsl_auxf_1_cur = adsl_conn1_l->adsc_auxf_1;  /* get first element  */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
       break;
     }
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_cur == NULL) return 0;   /* no ident found          */
#define ADSL_AUXF_IDENT_1 ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_cur + 1))
   iml1 = iml2 = 0;
   if (ADSL_AUXF_IDENT_1->imc_len_user_group < 0X0080) {  /* check length name user group UTF-8 */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ADSL_AUXF_IDENT_1->imc_len_user_group;
     }
     iml2++;
   } else {                                 /* length in two bytes     */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ((ADSL_AUXF_IDENT_1->imc_len_user_group >> 7) | 0X80);
     }
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) (ADSL_AUXF_IDENT_1->imc_len_user_group & 0X7F);
     }
     iml2 += 2;
   }
   iml3 = imp_len_area - iml1;
   if (iml3 > ADSL_AUXF_IDENT_1->imc_len_user_group) {  /* check length name user group UTF-8 */
     iml3 = ADSL_AUXF_IDENT_1->imc_len_user_group;  /* get length name user group UTF-8 */
   }
   if (iml3 > 0) {
     memcpy( achp_area + iml1,
             (char *) (ADSL_AUXF_IDENT_1 + 1) + ADSL_AUXF_IDENT_1->imc_len_userid,
             iml3 );
     iml1 += iml3;
   }
   iml2 += ADSL_AUXF_IDENT_1->imc_len_user_group;  /* add length name user group UTF-8 */
   if (ADSL_AUXF_IDENT_1->imc_len_userid < 0X0080) {  /* check length userid UTF-8 */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ADSL_AUXF_IDENT_1->imc_len_userid;
     }
     iml2++;
   } else {                                 /* length in two bytes     */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ((ADSL_AUXF_IDENT_1->imc_len_userid >> 7) | 0X80);
     }
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) (ADSL_AUXF_IDENT_1->imc_len_userid & 0X7F);
     }
     iml2 += 2;
   }
   iml3 = imp_len_area - iml1;
   if (iml3 > ADSL_AUXF_IDENT_1->imc_len_userid) {  /* check length userid UTF-8 */
     iml3 = ADSL_AUXF_IDENT_1->imc_len_userid;  /* get length userid UTF-8 */
   }
   if (iml3 > 0) {
     memcpy( achp_area + iml1,
             ADSL_AUXF_IDENT_1 + 1,
             iml3 );
     iml1 += iml3;
   }
   iml2 += ADSL_AUXF_IDENT_1->imc_len_userid;  /* add length userid UTF-8 */
   return iml2;                             /* return length total     */
#undef ADSL_AUXF_IDENT_1
} /* end m_l2tp_pass_session_owner()                                   */

#ifdef D_INCL_HOB_TUN
/** get string with user identity for HOB-TUN session                  */
extern "C" int m_tun_pass_session_owner( struct dsd_tun_contr_conn *adsp_tun_contr_conn, char *achp_area, int imp_len_area ) {
   int        iml1, iml2, iml3;             /* working variables       */
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */

#ifndef HL_UNIX
   adsl_conn1_l = ((class clconn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( class clconn1, dsc_tun_contr_conn )));
#endif
#ifdef HL_UNIX
   adsl_conn1_l = ((struct dsd_conn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
   adsl_auxf_1_cur = adsl_conn1_l->adsc_auxf_1;  /* get first element  */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
       break;
     }
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   if (adsl_auxf_1_cur == NULL) return 0;   /* no ident found          */
#define ADSL_AUXF_IDENT_1 ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_cur + 1))
   iml1 = iml2 = 0;
   if (ADSL_AUXF_IDENT_1->imc_len_user_group < 0X0080) {  /* check length name user group UTF-8 */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ADSL_AUXF_IDENT_1->imc_len_user_group;
     }
     iml2++;
   } else {                                 /* length in two bytes     */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ((ADSL_AUXF_IDENT_1->imc_len_user_group >> 7) | 0X80);
     }
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) (ADSL_AUXF_IDENT_1->imc_len_user_group & 0X7F);
     }
     iml2 += 2;
   }
   iml3 = imp_len_area - iml1;
   if (iml3 > ADSL_AUXF_IDENT_1->imc_len_user_group) {  /* check length name user group UTF-8 */
     iml3 = ADSL_AUXF_IDENT_1->imc_len_user_group;  /* get length name user group UTF-8 */
   }
   if (iml3 > 0) {
     memcpy( achp_area + iml1,
             (char *) (ADSL_AUXF_IDENT_1 + 1) + ADSL_AUXF_IDENT_1->imc_len_userid,
             iml3 );
     iml1 += iml3;
   }
   iml2 += ADSL_AUXF_IDENT_1->imc_len_user_group;  /* add length name user group UTF-8 */
   if (ADSL_AUXF_IDENT_1->imc_len_userid < 0X0080) {  /* check length userid UTF-8 */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ADSL_AUXF_IDENT_1->imc_len_userid;
     }
     iml2++;
   } else {                                 /* length in two bytes     */
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) ((ADSL_AUXF_IDENT_1->imc_len_userid >> 7) | 0X80);
     }
     if (iml1 < imp_len_area) {
       *(achp_area + iml1++) = (unsigned char) (ADSL_AUXF_IDENT_1->imc_len_userid & 0X7F);
     }
     iml2 += 2;
   }
   iml3 = imp_len_area - iml1;
   if (iml3 > ADSL_AUXF_IDENT_1->imc_len_userid) {  /* check length userid UTF-8 */
     iml3 = ADSL_AUXF_IDENT_1->imc_len_userid;  /* get length userid UTF-8 */
   }
   if (iml3 > 0) {
     memcpy( achp_area + iml1,
             ADSL_AUXF_IDENT_1 + 1,
             iml3 );
     iml1 += iml3;
   }
   iml2 += ADSL_AUXF_IDENT_1->imc_len_userid;  /* add length userid UTF-8 */
   return iml2;                             /* return length total     */
#undef ADSL_AUXF_IDENT_1
} /* end m_tun_pass_session_owner()                                    */
#endif

#ifndef B140620
/** cleanup resources of Server-Data-Hook                              */
static void m_sdh_cleanup( struct dsd_aux_cf1 *adsp_aux_cf1, struct dsd_cid *adsp_cid ) {
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w3;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w4;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w5;       /* auxiliary extension fi  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

#ifndef HELP_DEBUG
#define ADSL_CONN1_G (adsp_aux_cf1->adsc_conn)  /* pointer on connection */
#else
   DSD_CONN_G *ADSL_CONN1_G = NULL;         /* pointer on connection   */
   if (adsp_aux_cf1) {
     ADSL_CONN1_G = adsp_aux_cf1->adsc_conn;  /* pointer on connection */
   }
#endif

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_sdh_cleanup( adsp_aux_cf1=%p , adsp_cid=%p ) called ADSL_CONN1_G=%p sno=%08d.",
                   __LINE__, adsp_aux_cf1, adsp_cid, ADSL_CONN1_G, ADSL_CONN1_G->dsc_co_sort.imc_sno );
//#endif
// to-do 20.01.15 KB - stop timer first
#ifndef B150121
   if (ADSL_CONN1_G->dsc_timer.vpc_chain_2) {  /* timer still set      */
     m_time_rel( &ADSL_CONN1_G->dsc_timer );  /* release timer         */
   }
#endif

   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* chain auxiliary ext fields */
   adsl_auxf_1_w2 = NULL;                   /* clear previous entry    */
   while (adsl_auxf_1_w1) {                 /* loop over all entries   */
     if (   (adsp_cid == NULL)              /* all fields              */
         || (!memcmp( &adsl_auxf_1_w1->dsc_cid,  /* component identifier */
                      adsp_cid,
                      sizeof(struct dsd_cid) ))) {
       switch (adsl_auxf_1_w1->iec_auxf_def) {  /* type of entry       */
         case ied_auxf_defstor:             /* predefined storage      */
           adsl_auxf_1_w3 = adsl_auxf_1_w1;  /* save this entry        */
           adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
           m_proc_free( adsl_auxf_1_w3 );   /* put in chain of unused  */
           continue;                        /* next path thru the loop */
         case ied_auxf_timer:               /* timer                   */
           if (adsp_cid == NULL) break;     /* all fields              */
           /* remove this from timer chain                             */
           adsl_auxf_1_w4 = ADSL_CONN1_G->adsc_aux_timer_ch;
           adsl_auxf_1_w5 = NULL;           /* clear previous entry    */
           while (adsl_auxf_1_w4) {         /* loop over all timer entries */
             if (adsl_auxf_1_w4 == adsl_auxf_1_w1) {  /* entry found   */
               if (adsl_auxf_1_w5 == NULL) {  /* was first entry       */
                 ADSL_CONN1_G->adsc_aux_timer_ch
                   = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
               } else {                     /* middle in chain         */
                 ((struct dsd_aux_timer *) (adsl_auxf_1_w5 + 1))->adsc_auxf_next
                   = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
               }
               break;                       /* entry found             */
             }
             adsl_auxf_1_w5 = adsl_auxf_1_w4;  /* save previous entry  */
             adsl_auxf_1_w4 = ((struct dsd_aux_timer *) (adsl_auxf_1_w4 + 1))->adsc_auxf_next;
           }
           /* if adsl_auxf_1_w4 NULL, that timer not found, error      */
           break;
         case ied_auxf_service_query_1:     /* service query 1         */
           ((struct dsd_service_aux_1 *) ((char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1)))->amc_service_close
                                          ( adsp_aux_cf1, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
           break;
         case ied_auxf_ldap:                /* LDAP service            */
           m_ldap_free( (class dsd_ldap_cl *) (adsl_auxf_1_w1 + 1) );
           break;
         case ied_auxf_sip:                 /* SIP request             */
           m_aux_sip_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
           break;
         case ied_auxf_udp:                 /* UDP request             */
           m_aux_udp_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
           break;
         case ied_auxf_gate_udp:            /* UDP-gate entry          */
           m_aux_gate_udp_cleanup( ADSL_CONN1_G, (char *) (adsl_auxf_1_w1 + 1) + sizeof(struct dsd_auxf_ext_1) );
           break;
         case ied_auxf_admin:               /* admin command           */
           while (((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1) {  /* buffers from previous calls */
             adsl_sdhc1_w1 = ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1;
             ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_w1 + 1) + 1))->adsc_sdhc1_1
               = adsl_sdhc1_w1->adsc_next;  /* remove from chain       */
             m_proc_free( adsl_sdhc1_w1 );  /* free the buffer         */
           }
           break;
         case ied_auxf_pipe_listen:         /* aux-pipe create with name */
           m_aux_pipe_listen_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
           break;
         case ied_auxf_pipe_conn:           /* aux-pipe established connection */
           m_aux_pipe_conn_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
           break;
         case ied_auxf_util_thread:         /* utility thread          */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_w1 + 1))
           /* set signal to terminate the utility thread               */
           ADSL_UTC_G->dsc_utp1.imc_signal |= HL_AUX_SIGNAL_CANCEL;
           dss_critsect_aux.m_enter();      /* critical section        */
           /* connection to session has ended                          */
           ADSL_UTC_G->dsc_ete.ac_conn1 = NULL;  /* clear connection   */
           adsl_auxf_1_w3 = adsl_auxf_1_w1;  /* do free memory now     */
           /* check if utility thread is still running                 */
           if (ADSL_UTC_G->boc_thread_ended) {  /* thread has already ended */
             /* utility thread will free all resources                 */
             adsl_auxf_1_w3 = NULL;         /* nothing to free         */
           }
           dss_critsect_aux.m_leave();      /* critical section        */
           if (adsl_auxf_1_w3) {            /* memory to free          */
             while (ADSL_UTC_G->adsc_auxf_1) {  /* chain auxiliary extension fields */
               adsl_auxf_1_w3 = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
               ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w3->adsc_next;  /* remove from chain */
               if (adsl_auxf_1_w3->iec_auxf_def == ied_auxf_normstor) {  /* normal storage */
                 free( adsl_auxf_1_w3 );    /* free memory             */
               } else {                     /* other type              */
                 m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s ied_auxf_util_thread l%05d cannot free resource %p iec_auxf_def %d.",
                                 ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                                 __LINE__, adsl_auxf_1_w3, adsl_auxf_1_w3->iec_auxf_def );
               }
             }
           }
           break;
#undef ADSL_UTC_G
         case ied_auxf_swap_stor:           /* swap storage            */
           m_aux_swap_stor_cleanup( adsp_aux_cf1->adsc_hco_wothr, ADSL_CONN1_G, adsl_auxf_1_w1 );
           break;
#ifndef HL_UNIX
// to-do 23.06.14 KB
         case ied_auxf_dyn_lib:             /* dynamic library         */
           m_aux_dyn_lib_cleanup( ADSL_CONN1_G, adsl_auxf_1_w1 );
           break;
#endif
         case ied_auxf_sdh_reload:          /* SDH reload              */
           m_sdh_reload_old_end( adsp_aux_cf1, adsl_auxf_1_w1 );
           break;
       }
       /* remove this entry from the chain                             */
       adsl_auxf_1_w3 = adsl_auxf_1_w1;     /* save this entry         */
       adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
#ifndef HL_UNIX
       EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section      */
#endif
       if (adsl_auxf_1_w2 == NULL) {        /* at anchor of chain      */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_w1;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_auxf_1_w2->adsc_next = adsl_auxf_1_w1;  /* remove from chain */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section      */
#endif
// do-to 05.01.15 KB - heap corrupted
       free( adsl_auxf_1_w3 );              /* free storage of this element */
       continue;                            /* next path thru the loop */
     }
     adsl_auxf_1_w2 = adsl_auxf_1_w1;       /* save previous entry     */
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;
   }
// to-do 20.01.15 KB - start session timer again
#ifndef B150121
   m_conn1_set_timer_1( ADSL_CONN1_G );
#endif
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_sdh_cleanup()                                               */
#endif

#ifdef CHECK_PROB_070113
/** check if the chain did not get corrupted                           */
static void m_check_chain_aux( void * vpp_userfld ) {
   int        iml_count;                    /* count entries           */
   BOOL       bol_nonsense;                 /* nonsense - do not opt   */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */

//#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
//#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_userfld)

   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_auxf_1;  /* get first element   */
   iml_count = 0;                           /* reset count entries     */
   bol_nonsense = FALSE;                    /* nonsense - do not opt   */
   while (adsl_auxf_1_w1) {                 /* loop over chain         */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_radqu) {
       m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux l%05d m_check_chain_aux() ied_auxf_radqu adsl_auxf_1_w1=%p",
                       __LINE__, adsl_auxf_1_w1 );
     }
     iml_count++;                           /* increment count entries */
     if (*((char *) adsl_auxf_1_w1)) {
       bol_nonsense = TRUE;                 /* nonsense - do not opt   */
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   m_hlnew_printf( HLOG_XYZ1, "xiipgw08-aux l%05d m_check_chain_aux() count-aux=%d bol_nonsense=%d",
                   __LINE__, iml_count, bol_nonsense );
   return;

#undef ADSL_CONN1_G
//#undef ADSL_AUX_CF1
} /* end m_check_chain_aux()                                           */
#endif

#undef DSD_CONN_G

