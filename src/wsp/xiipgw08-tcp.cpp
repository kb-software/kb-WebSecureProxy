/**
   xiipgw08-tcp.cpp
   include file for HOB WebSecureProxy (WSP)
   IBIPGW08.cpp and nbipgw20.cpp
   doing all TCP staff like:
   - connect for Load-Balancing
   - connect and disconnect for Server-Data-Hooks (SDH)
   - callback routines for server-side and client-side SSL
   - OCSP
*/

#define SM_BUGFIX_20170807	1

#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif

/** connect to server                                                  */
#ifndef HL_UNIX
inline int clconn1::mc_conn_server( struct dsd_aux_cf1 *adsp_aux_cf1_cur,
                                    struct sockaddr *adsp_soa )
#else
inline int m_tcp_sa_conn_server( struct dsd_aux_cf1 *adsp_aux_cf1_cur,
                                 struct sockaddr *adsp_soa )
#endif
{
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_len_soa_dest;             /* length of sockaddr      */
   int        iml_len_soa_bind;             /* length of sockaddr      */
   int        iml_server_socket;            /* socket of server        */
#ifdef HL_UNIX
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   struct sockaddr *adsl_soa_w1;
   char       *achl_w1;                     /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   char       chrl_ineta_target[ LEN_DISP_INETA ];  /* for INETA target */
#ifdef NEW_070924
   int     iml_no_ineta;                    /* number of INETA         */
#endif
#ifdef D_INCL_HOB_TUN
   socklen_t  iml_local_namelen;            /* length of name local    */
   struct dsd_target_ineta_1 *adsl_server_ineta_w1;  /* server INETA   */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
   struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
#endif

#ifndef HL_UNIX
#define ADSL_CONN1_G this                   /* pointer on connection   */
#else
#define ADSL_CONN1_G adsl_conn1             /* pointer on connection   */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "mc_clconn1::conn_server adsp_soa=%p.", adsp_soa );
#endif
#ifdef HL_UNIX
   adsl_conn1 = adsp_aux_cf1_cur->adsc_conn;  /* for this connection   */
#endif
   iml_len_soa_dest = sizeof(struct sockaddr_in);  /* length of sockaddr IPV4 */
   if (adsp_soa->sa_family != AF_INET) {    /* not IPV4                */
     iml_len_soa_dest = sizeof(struct sockaddr_in6);  /* length of sockaddr IPV6 */
   }
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNECOSE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d connect (LB-GW) struct sockaddr %p.",
                  __LINE__, adsp_soa );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + ADSL_WTR_G1->imc_length + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
#define ACHL_WSP_T_DATA ((char *) (ADSL_WTR_G2 + 1))  /* here starts content */
     ADSL_WTR_G2->achc_content = ACHL_WSP_T_DATA;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml_len_soa_dest;  /* length of text / data */
     memcpy( ACHL_WSP_T_DATA, adsp_soa, iml_len_soa_dest );
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
#undef ACHL_WSP_T_DATA
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef D_INCL_HOB_TUN
// to-do 05.01.12 KB HOB-TUN HTCP
   if (adsp_soa->sa_family != AF_INET) {    /* not IPV4                */
     goto p_norm_c_00;                      /* connect normal          */
   }
   if (adsg_loconf_1_inuse->adsc_raw_packet_if_conf == NULL) {  /* HOB-TUN not configured */
     goto p_norm_c_00;                      /* connect normal          */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->boc_use_ineta_appl == FALSE) {  /* not use HTCP */
     goto p_norm_c_00;                      /* connect normal          */
   }
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) {   /* no configuration raw-packet-interface */
     goto p_norm_c_00;                      /* connect normal          */
   }
   ADSL_CONN1_G->adsc_ineta_raws_1 = m_prepare_htun_ineta_htcp( ADSL_CONN1_G,
                                                                adsp_aux_cf1_cur->adsc_hco_wothr,
                                                                ied_ineta_raws_user_ipv4 );
   if (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL) {  /* INETA not found  */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     goto p_norm_c_00;                      /* connect normal          */
   }
   adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, D_TCP_ERROR );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, chrl_ineta_local, ADSL_CONN1_G->adsc_ineta_raws_1->usc_appl_port );
   }
   memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );
   ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type HTCP */
   ADSL_CONN1_G->adsc_ineta_raws_1->ac_conn1 = ADSL_CONN1_G;  /* set connection        */
   adsl_server_ineta_w1 = (struct dsd_target_ineta_1 *) malloc( sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 4 );
   memset( adsl_server_ineta_w1, 0, sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) );
   adsl_server_ineta_w1->imc_no_ineta = 1;  /* number of INETA         */
   adsl_server_ineta_w1->imc_len_mem        /* length of memory including ADSL_CONN1_G structure */
     = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 4;
#define ADSL_INETA_S1_G ((struct dsd_ineta_single_1 *) (adsl_server_ineta_w1 + 1))
   ADSL_INETA_S1_G->usc_family = AF_INET;   /* family IPV4 / IPV6      */
   ADSL_INETA_S1_G->usc_length = 4;         /* length of following address */
   *((UNSIG_MED *) (ADSL_INETA_S1_G + 1)) = *((UNSIG_MED *) &((struct sockaddr_in *) adsp_soa)->sin_addr);
#undef ADSL_INETA_S1_G
   memset( &dsl_tun_start_htcp, 0, sizeof(struct dsd_tun_start_htcp) );  /* HOB-TUN start interface HTCP */
   dsl_tun_start_htcp.adsc_server_ineta = adsl_server_ineta_w1;  /* server INETA */
// dsl_tun_start_htcp.ac_free_ti1 = al_free_ti1;  /* INETA to free     */
   dsl_tun_start_htcp.imc_server_port = ntohs( ((struct sockaddr_in *) adsp_soa)->sin_port );  /* TCP/IP port connect */
   dsl_tun_start_htcp.boc_connect_round_robin = FALSE;  /* do not connect round-robin */
   dsl_tun_start_htcp.imc_tcpc_to_msec = adsl_raw_packet_if_conf->imc_tcpc_to_msec;  /* TCP connect timeout milliseconds */
   if (dsl_tun_start_htcp.imc_tcpc_to_msec == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_to_msec = DEF_HTCP_TCPC_TO_MSEC;  /* TCP connect timeout milliseconds */
   }
   dsl_tun_start_htcp.imc_tcpc_try_no = adsl_raw_packet_if_conf->imc_tcpc_try_no;  /* TCP connect number of try */
   if (dsl_tun_start_htcp.imc_tcpc_try_no == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_try_no = DEF_HTCP_TCPC_TRY_NO;  /* TCP connect number of try */
   }
   dsl_tun_start_htcp.boc_tcp_keepalive = adsg_loconf_1_inuse->boc_tcp_keepalive;  /* TCP KEEPALIVE */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* chain of buffers to send over HOB-TUN */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type */
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) adsp_aux_cf1_cur->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &adsp_aux_cf1_cur->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select
     = DEF_NETW_POST_1_HTUN_CONN_OK | DEF_NETW_POST_1_HTUN_FREE_R;  /* select the events */
   ADSL_CONN1_G->adsc_ineta_raws_1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
#ifdef TRACEHL1
#ifndef HL_UNIX
#ifdef B120206
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T clconn1::mc_conn_server() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h, &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr1 );
#else
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T clconn1::mc_conn_server() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, ADSL_CONN1_G->dsc_htun_h, &ADSL_CONN1_G->dsc_tun_contr1 );
#endif
#endif
#endif
   dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h;  /* where to put the handle created */
   m_hl_lock_inc_1( &ADSL_CONN1_G->imc_references );  /* references to this session */
   m_htun_new_sess_htcp( &dsl_tun_start_htcp,
                         &ADSL_CONN1_G->dsc_tun_contr_conn,  /* HOB-TUN control area connection */
                         &ADSL_CONN1_G->adsc_ineta_raws_1->dsc_tun_contr_ineta );  /* HOB-TUN control interface for INETA */
   ADSL_CONN1_G->dsc_htun_h = ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h;  /* handle created */
   m_hco_wothr_blocking( adsp_aux_cf1_cur->adsc_hco_wothr );  /* mark thread blocking */
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( adsp_aux_cf1_cur->adsc_hco_wothr );  /* wait for an event */
   }
   m_hco_wothr_active( adsp_aux_cf1_cur->adsc_hco_wothr, FALSE );  /* mark thread active */
   if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_CONN_OK) {  /* done HTUN connect ok */
     m_clconn1_naeg1( ADSL_CONN1_G );
     return 0;
   }
   /* we need to free the local INETA created                          */
   m_cleanup_htun_ineta( ADSL_CONN1_G->adsc_ineta_raws_1 );
   free( ADSL_CONN1_G->adsc_ineta_raws_1 );  /* free the memory        */
   ADSL_CONN1_G->adsc_ineta_raws_1 = NULL;  /* auxiliary field for HOB-TUN */
   return HL_ERROR_HTCP_CONN;

#undef ADSL_NETW_POST_1

   p_norm_c_00:                             /* connect normal          */
#endif
   iml_server_socket = socket( adsp_soa->sa_family, SOCK_STREAM, 0 );
   if (iml_server_socket < 0) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s socket for connect (LB-GW) failed with code %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     iml_server_socket, D_TCP_ERROR );
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server  */
     return D_TCP_ERROR;
   }
   bol1 = FALSE;                            /* no error message        */
   while (TRUE) {
     if (ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.boc_bind_needed == FALSE) break;
// to-do 10.08.10 KB - check bind and family
     switch (adsp_soa->sa_family) {
       case AF_INET:                        /* IPV4                    */
         if (ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.boc_ipv4 == FALSE) {  /* IPV4 not supported */
           bol1 = TRUE;                     /* display error message   */
           break;
         }
         adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.dsc_soai4;  /* address information IPV4 */
         iml_len_soa_bind = sizeof(struct sockaddr_in);  /* length of sockaddr */
         break;
       case AF_INET6:                       /* IPV6                    */
         if (ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.boc_ipv4 == FALSE) {  /* IPV4 not supported */
           bol1 = TRUE;                     /* display error message   */
           break;
         }
         adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out.dsc_soai6;  /* address information IPV6 */
         iml_len_soa_bind = sizeof(struct sockaddr_in6);  /* length of sockaddr */
         break;
       default:                             /* should never occur      */
         bol1 = TRUE;                       /* display error message   */
         break;
     }
     if (bol1) break;                       /* display error message   */
     iml_rc = bind( iml_server_socket, adsl_soa_w1, iml_len_soa_bind );
     if (iml_rc == 0) break;                /* no error                */
     m_hlnew_printf( HLOG_WARN1, "HWSPS012W GATE=%(ux)s SNO=%08d INETA=%s bind for connect (LB-GW) failed with code %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( iml_server_socket );
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server           */
     return D_TCP_ERROR;
   }
   if (bol1) {                              /* display error message   */
     m_hlnew_printf( HLOG_WARN1, "HWSPS180W GATE=%(ux)s SNO=%08d INETA=%s could not do bind for connect (LB-GW)",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
   }

   m_hco_wothr_blocking( adsp_aux_cf1_cur->adsc_hco_wothr );  /* mark thread blocking */
   iml_rc = connect( iml_server_socket, adsp_soa, iml_len_soa_dest );
   if (iml_rc != 0) {                       /* connect returned error  */
     iml_error = D_TCP_ERROR;               /* error code              */
   }
   m_hco_wothr_active( adsp_aux_cf1_cur->adsc_hco_wothr, FALSE );  /* mark thread active */
   if (iml_rc != 0) {                       /* connect returned error  */
     m_hlnew_printf( HLOG_WARN1, "HWSPS013W GATE=%(ux)s SNO=%08d INETA=%s connect (LB-GW) to server failed with code %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, iml_rc, iml_error );
     D_TCP_CLOSE( iml_server_socket );
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;       /* status server           */
     if (iml_error) return iml_error;
     return iml_rc;
   }
   iml_rc = getnameinfo( adsp_soa, iml_len_soa_dest,
                         chrl_ineta_target, sizeof(chrl_ineta_target),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPS181W GATE=%(ux)s SNO=%08d INETA=%s clconn1::mc_conn_server l%05d getnameinfo() returned %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     __LINE__,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta_target, "???" );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPS182I GATE=%(ux)s SNO=%08d INETA=%s connect (LB-GW) to server %s successful",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   chrl_ineta_target );
#ifdef NEW_070924
   iml_no_ineta = 0;                        /* clear number of INETA   */
   p_conn_00:                               /* start connect           */
#endif
#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "clconn1::mc_conn_server() connect succeeded" );
#endif
   /* start connection server                                          */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifndef HL_UNIX
   dcl_tcp_r_s.start1( ADSL_CONN1_G,
                       adsp_soa, iml_len_soa_dest,
                       iml_server_socket );
#ifdef TRY_110523_01
   dcl_tcp_r_s.start2();                    /* start TCPCOMP           */
#endif
#else
#ifndef B130312
   memset( &ADSL_CONN1_G->dsc_tc1_server, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure server */
#endif
   ADSL_CONN1_G->dsc_tc1_server.boc_connected = TRUE;  /* TCP session is connected */
   iml_rc = ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_startco_fb(
                  iml_server_socket,
                  &dss_tcpcomp_cb1,
                  ADSL_CONN1_G );
   if (iml_rc != 0) {                       /* error occured           */
     ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
     m_hlnew_printf( HLOG_WARN1, "HWSPS183W GATE=%(ux)s SNO=%08d INETA=%s nbipgw20 l%05d m_startco_mh() failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     __LINE__, iml_rc );
     return iml_rc;                         /* all done                */
   }
#endif
#ifdef HL_UNIX
#ifndef TJ_B170809
   memcpy( &ADSL_CONN1_G->dsc_tc1_server.dsc_soa_conn, adsp_soa, iml_len_soa_dest );
#endif
#endif
   ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* status server */
#ifdef NOT_NEEDED_120105
   bol1 = FALSE;
   EnterCriticalSection( &d_act_critsect );  /* critical section act   */
   if (boc_st_act == FALSE) {               /* util-thread not active  */
     boc_st_act = TRUE;                     /* util-thread active now  */
     bol1 = TRUE;                           /* activate thread         */
   }
   LeaveCriticalSection( &d_act_critsect );  /* critical section act   */
   if (bol1) {
#ifdef B060628
     clworkth::act_thread( ADSL_CONN1_G );
#else
     m_act_thread_2( ADSL_CONN1_G );                /* activate m_proc_data()  */
#endif
   }
#endif
   m_clconn1_naeg1( ADSL_CONN1_G );
   return 0;
#undef ADSL_CONN1_G
} /* end clconn1::mc_conn_server()                                        */

/**
   do dynamic connect for Server-Data-Hooks (SDHs)
*/
extern "C" BOOL m_tcp_dynamic_conn( void * vpp_userfld, struct dsd_aux_tcp_conn_1 *adsp_tcp_conn,
                                    struct dsd_target_ineta_1 *adsp_target_ineta_1, void * ap_free_ti1,
                                    BOOL bop_extended ) {
   int        iml1;                         /* working variable        */
   int        dwl1;                         /* working variable        */
   BOOL       bol_csssl;                    /* with client-side SSL    */
   char       *achl1;                       /* working variable        */
   char       *achl_stf;                    /* source target-filter    */
// new 14.08.10 KB
   int        iml_server_port;              /* port of server          */
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   socklen_t  iml_local_namelen;            /* length of name local    */
#ifndef HL_UNIX
   LARGE_INTEGER ill_entropy;               /* time now                */
#else
   long long int ill_entropy;               /* time now                */
#endif
   struct dsd_target_ineta_1 *adsl_target_ineta_1;  /* INETAs of target */
#ifndef B121120
   void *     al_free_ti1;                  /* INETA to free           */
#endif
#ifdef D_INCL_HOB_TUN
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_old;  /* auxiliary extension field HTUN */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_new;  /* auxiliary extension field HTUN */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct sockaddr *adsl_soa_w1;            /* working variable        */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
   struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
#endif
// end new
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
#ifndef B140707
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */
#ifndef B140311
   struct dsd_unicode_string dsl_ucs_target;  /* target INETA          */
   struct sockaddr_storage dsl_soa;         /* filled with INETA       */
   char       chrl_disp_ineta[ LEN_DISP_INETA ];  /* internet-address char */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_tcp_dynamic_conn() started - TCP connect" );
#endif
#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#endif
#ifdef HELP_DEBUG
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) vpp_userfld;  /* auxiliary control structure */
   DSD_CONN_G *ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#endif
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d m_tcp_dynamic_conn() called ADSL_CONN1_G->iec_st_ses=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses );
#endif
   /* check if server already selected                                 */
#ifdef B140707
// check if already connected 15.08.10 KB
// ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B101208
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)
       || (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)  /* with server connection */
       || (   (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == TRUE)
           || (   (ADSL_CONN1_G->adsc_server_conf_1->inc_function != DEF_FUNC_DIR)
               && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_http)
               && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_hrdpe1)  /* protocol HOB MS RDP Extension 1 */
               && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_socks5))  /* protocol Socks-5 */
           || (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE))) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS050W GATE=%(ux)s SNO=%08d INETA=%s TCP connect - server invalid or already connected",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1), ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_invalid;  /* parameter is invalid */
     return TRUE;
   }
#else
#ifdef D_FOR_VC
   class clconn1 *adsh_conn1 = ADSL_CONN1_G;
   struct dsd_server_conf_1 *adsh_server_conf_1 = ADSL_CONN1_G->adsc_server_conf_1;  /* server configuration */
#endif
#define DEBUG_131116_01
#ifdef DEBUG_131116_01
   DSD_CONN_G *adsl_clconn1 = ADSL_CONN1_G;
   m_hlnew_printf( HLOG_TRACE1, "DEBUG_131116_01 l%05d adsl_clconn1=%p.",
                   __LINE__, adsl_clconn1 );
#endif
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)
       || (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)  /* with server connection */
       || (   (ADSL_CONN1_G->adsc_server_conf_1->inc_function != DEF_FUNC_DIR)
           && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_http)
           && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_hrdpe1)  /* protocol HOB MS RDP Extension 1 */
           && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_socks5)  /* protocol Socks-5 */
           && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_websocket))) {  /* protocol WebSocket */
     m_hlnew_printf( HLOG_WARN1, "HWSPS050W GATE=%(ux)s SNO=%08d INETA=%s TCP connect - server invalid or already connected",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1), ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
#ifndef B121120
     if (ap_free_ti1) free( ap_free_ti1 );  /* INETA to free           */
#endif
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_invalid;  /* parameter is invalid */
     return TRUE;
   }
#endif
   if (ADSL_CONN1_G->adsc_server_conf_1->boc_conn_other_se == FALSE) {  /* option-connect-other-server */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s TCP connect - option-connect-other-server not configured, connect not allowed",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1), ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
#ifndef B121120
     if (ap_free_ti1) free( ap_free_ti1 );  /* INETA to free           */
#endif
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_no_ocos;  /* option-connect-other-server not configured */
     return TRUE;
   }
#endif
#ifndef B140707
   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (   (adsl_server_conf_1_used)
       && (adsl_server_conf_1_used->adsc_seco1_previous)) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
   if (   (adsl_server_conf_1_used == NULL)
       || (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)  /* with server connection */
       || (   (adsl_server_conf_1_used->inc_function != DEF_FUNC_DIR)
           && (adsl_server_conf_1_used->iec_scp_def != ied_scp_http)
           && (adsl_server_conf_1_used->iec_scp_def != ied_scp_hrdpe1)  /* protocol HOB MS RDP Extension 1 */
           && (adsl_server_conf_1_used->iec_scp_def != ied_scp_socks5)  /* protocol Socks-5 */
           && (adsl_server_conf_1_used->iec_scp_def != ied_scp_websocket))) {  /* protocol WebSocket */
     m_hlnew_printf( HLOG_WARN1, "HWSPS050W GATE=%(ux)s SNO=%08d INETA=%s TCP connect - server invalid or already connected",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
     if (ap_free_ti1) free( ap_free_ti1 );  /* INETA to free           */
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_invalid;  /* parameter is invalid */
     return TRUE;
   }
   if (adsl_server_conf_1_used->boc_conn_other_se == FALSE) {  /* option-connect-other-server */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s TCP connect - option-connect-other-server not configured, connect not allowed",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
     if (ap_free_ti1) free( ap_free_ti1 );  /* INETA to free           */
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_no_ocos;  /* option-connect-other-server not configured */
     return TRUE;
   }
#endif
   bol_csssl = FALSE;                       /* with client-side SSL    */
   if (adsp_tcp_conn->dsc_aux_tcp_def.ibc_ssl_client) {  /* use client-side SSL */
     bol_csssl = TRUE;                      /* with client-side SSL    */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->boc_use_csssl) {  /* do use client-side-SSL */
     bol_csssl = TRUE;                      /* with client-side SSL    */
   }
#ifdef CSSSL_060620
#ifdef B120211
   if (   (bol_csssl)                       /* use client-side SSL     */
       && (adsg_loconf_1_inuse->boc_csssl_conf == FALSE)) {  /* Client Side SSL not configured */
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_no_cs_ssl;  /* no Client-Side SSL configured */
     return TRUE;
   }
#else
   if (bol_csssl) {                         /* use client-side SSL     */
     if (adsg_loconf_1_inuse->boc_csssl_conf == FALSE) {  /* Client Side SSL not configured */
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_no_cs_ssl;  /* no Client-Side SSL configured */
#ifndef B121120
       if (ap_free_ti1) free( ap_free_ti1 );  /* INETA to free           */
#endif
       return TRUE;
     }
#ifndef HL_UNIX
     bol1 = QueryPerformanceCounter( &ill_entropy );
#else
     ill_entropy = m_get_epoch_nanoseconds();
#endif
   }
#endif
#endif
   adsl_targfi_w1 = m_get_session_targfi( &achl_stf, ADSL_CONN1_G );
// new 14.08.10 KB
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
#ifdef B140311
   if (adsp_target_ineta_1) {               /* INETA passed as parameter */
     adsl_target_ineta_1 = adsp_target_ineta_1;  /* use INETA passed as parameter */
#ifndef B121120
     al_free_ti1 = ap_free_ti1;             /* INETA to free           */
#endif
     goto p_ineta_20;                       /* target INETA is valid   */
   }
#endif
#ifndef B140311
   if (adsp_target_ineta_1 == NULL) {       /* INETA passed as parameter */
     goto p_ineta_08;                       /* get INETA from DNS-name or string */
   }
   adsl_target_ineta_1 = adsp_target_ineta_1;  /* use INETA passed as parameter */
   al_free_ti1 = ap_free_ti1;               /* INETA to free           */
   dsl_ucs_target.ac_str = (void *) "dynamic-dotted-INETA";  /* target INETA */
   dsl_ucs_target.imc_len_str = -1;
   dsl_ucs_target.iec_chs_str = ied_chs_utf_8;
   if (adsl_target_ineta_1->imc_no_ineta != 1) {  /* number of INETA   */
     goto p_ineta_20;                       /* target INETA is valid   */
   }
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );  /* filled with INETA */
#define ADSL_INETA_S_G ((struct dsd_ineta_single_1 *) (adsl_target_ineta_1 + 1))
   dsl_soa.ss_family = ADSL_INETA_S_G->usc_family;
   switch (dsl_soa.ss_family) {
     case AF_INET:                          /* IPV4                    */
       memcpy( &((struct sockaddr_in *) &dsl_soa)->sin_addr,
               ADSL_INETA_S_G + 1,
               4 );
       break;
     case AF_INET6:                         /* IPV6                    */
       memcpy( &((struct sockaddr_in6 *) &dsl_soa)->sin6_addr,
               ADSL_INETA_S_G + 1,
               16 );
       break;
   }
#undef ADSL_INETA_S_G
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa, sizeof(struct sockaddr_storage),
                         chrl_disp_ineta, sizeof(chrl_disp_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPS212W GATE=%(ux)s SNO=%08d INETA=%s TCP connect l%05d getnameinfo() returned %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( chrl_disp_ineta, "???" );
   }
   dsl_ucs_target.ac_str = chrl_disp_ineta;  /* target INETA           */
   goto p_ineta_20;                         /* target INETA is valid   */

   p_ineta_08:                              /* get INETA from DNS-name or string */
#endif
   adsl_target_ineta_1 = m_get_target_ineta( adsp_tcp_conn->dsc_target_ineta.ac_str,
                                             adsp_tcp_conn->dsc_target_ineta.imc_len_str,
                                             adsp_tcp_conn->dsc_target_ineta.iec_chs_str,
                                             &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out );  /* IP address multihomed */
   if (adsl_target_ineta_1 == NULL) {       /* could not get INETA     */
//#ifdef NOT_YET
// 14.08.10 KB - wait for Mr. Sommer
     m_hlnew_printf( HLOG_WARN1, "HWSPS052W GATE=%(ux)s SNO=%08d INETA=%s TCP connect INETA target %(ucs)s cannot be resolved",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta, &adsp_tcp_conn->dsc_target_ineta );
//#endif
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
     adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_hostname;  /* host-name not in DNS */
     return TRUE;
   }
#ifndef B121120
   al_free_ti1 = ap_free_ti1;               /* INETA to free           */
#endif
#ifndef B140311
   dsl_ucs_target = adsp_tcp_conn->dsc_target_ineta;  /* target INETA  */
#endif
#ifndef B121120

   p_ineta_20:                              /* target INETA is valid   */
#endif
   if (adsl_targfi_w1) {                    /* with target-filter      */
     if (adsg_loconf_1_inuse->inc_network_stat >= 4) {
#ifdef B140311
       m_hlnew_printf( HLOG_INFO1, "HWSPS0xxI GATE=%(ux)s SNO=%08d INETA=%s m_tcp_dynamic_conn apply target-filter %(u8)s from %s to %(ucs)s.",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta,
                       (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name,
                       achl_stf,
                       &adsp_tcp_conn->dsc_target_ineta );
#endif
#ifndef B140311
       m_hlnew_printf( HLOG_INFO1, "HWSPS210I GATE=%(ux)s SNO=%08d INETA=%s m_tcp_dynamic_conn apply target-filter %(u8)s from %s to %(ucs)s.",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta,
                       (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name,
                       achl_stf,
                       &dsl_ucs_target );
#endif
     }
     bol1 = m_check_target_multiconn( ADSL_CONN1_G,
                                      adsl_targfi_w1,
                                      &adsp_tcp_conn->dsc_target_ineta,
                                      adsl_target_ineta_1,
                                      adsp_tcp_conn->imc_server_port );
     if (bol1 == FALSE) {                   /* target-filter blocks access */
#ifdef B140311
       m_hlnew_printf( HLOG_WARN1, "HWSPS0xxW GATE=%(ux)s SNO=%08d INETA=%s m_tcp_dynamic_conn target-filter %(u8)s from %s blocks access to %(ucs)s.",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta,
                       (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name,
                       achl_stf,
                       &adsp_tcp_conn->dsc_target_ineta );
#endif
#ifndef B140311
       m_hlnew_printf( HLOG_WARN1, "HWSPS211W GATE=%(ux)s SNO=%08d INETA=%s m_tcp_dynamic_conn target-filter %(u8)s from %s blocks access to %(ucs)s.",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta,
                       (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name,
                       achl_stf,
                       &dsl_ucs_target );
#endif
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifndef B121120
       if (al_free_ti1) free( al_free_ti1 );  /* INETA to free         */
#endif
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_denied_tf;  /* access denied because of target-filter */
       return TRUE;
     }
   }

#ifdef D_INCL_HOB_TUN
   adsl_ineta_raws_1_old = ADSL_CONN1_G->adsc_ineta_raws_1;  /* get old auxiliary field for HOB-TUN */
   adsl_ineta_raws_1_new = NULL;             /* auxiliary extension field HTUN */
   if (ADSL_CONN1_G->adsc_server_conf_1->boc_use_ineta_appl == FALSE) {  /* do not use HTCP */
     goto p_tcpcomp_00;                     /* connect over TCPCOMP    */
   }
#ifndef B150127
/**
  HOB-TUN with driver
  maybe does not run over localhost
  22.06.12  KB
*/
#define ADSL_INETA_SINGLE_1_G ((struct dsd_ineta_single_1 *) (adsl_target_ineta_1 + 1))
   if (   (adsl_target_ineta_1->imc_no_ineta == 1)
       && (ADSL_INETA_SINGLE_1_G->usc_family == AF_INET)
       && (*((unsigned char *) (ADSL_INETA_SINGLE_1_G + 1)) == 0X7F)) {
     goto p_tcpcomp_00;                     /* connect over TCPCOMP    */
   }
#undef ADSL_INETA_SINGLE_1_G
#endif
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) {   /* no configuration raw-packet-interface */
     goto p_tcpcomp_00;                     /* connect over TCPCOMP    */
   }
   /* 14.08.10 KB only IPV4 supported by HOB-TUN                       */
   adsl_ineta_raws_1_new = m_prepare_htun_ineta_htcp( ADSL_CONN1_G,
                                                      ADSL_AUX_CF1->adsc_hco_wothr,
                                                      ied_ineta_raws_user_ipv4 );
   if (adsl_ineta_raws_1_new == NULL) {      /* auxiliary extension field HTUN */
     m_hlnew_printf( HLOG_XYZ1, "HWSPCnnnW GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta );
     goto p_tcpcomp_00;                     /* connect over TCPCOMP    */
   }
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (adsl_ineta_raws_1_new + 1))
   adsl_soa_w1 = (struct sockaddr *) &adsl_ineta_raws_1_new->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                  /* error occured           */
#ifndef HL_UNIX
     if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
       iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code   */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     iml_rc );
#else
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     errno );
#endif
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     chrl_ineta_local, adsl_ineta_raws_1_new->usc_appl_port );
   }
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* chain of buffers to send over HOB-TUN */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );
   ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type */
   memset( &dsl_tun_start_htcp, 0, sizeof(struct dsd_tun_start_htcp) );  /* HOB-TUN start interface HTCP */
   dsl_tun_start_htcp.adsc_server_ineta = adsl_target_ineta_1;  /* server INETA */
   dsl_tun_start_htcp.ac_free_ti1 = al_free_ti1;  /* INETA to free     */
   dsl_tun_start_htcp.imc_server_port = adsp_tcp_conn->imc_server_port;  /* TCP/IP port connect */
   dsl_tun_start_htcp.boc_connect_round_robin = ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin;  /* do connect round-robin */
   dsl_tun_start_htcp.imc_tcpc_to_msec = adsl_raw_packet_if_conf->imc_tcpc_to_msec;  /* TCP connect timeout milliseconds */
   if (dsl_tun_start_htcp.imc_tcpc_to_msec == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_to_msec = DEF_HTCP_TCPC_TO_MSEC;  /* TCP connect timeout milliseconds */
   }
   dsl_tun_start_htcp.imc_tcpc_try_no = adsl_raw_packet_if_conf->imc_tcpc_try_no;  /* TCP connect number of try */
   if (dsl_tun_start_htcp.imc_tcpc_try_no == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_try_no = DEF_HTCP_TCPC_TRY_NO;  /* TCP connect number of try */
   }
   dsl_tun_start_htcp.boc_tcp_keepalive = adsg_loconf_1_inuse->boc_tcp_keepalive;  /* TCP KEEPALIVE */
   adsl_ineta_raws_1_new->ac_conn1 = ADSL_CONN1_G;  /* set connection  */
// dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &ADSL_CONN1_G->dsc_htun_h;  /* where to put the handle created */
   dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &adsl_ineta_raws_1_new->dsc_htun_h;  /* where to put the handle created */
#ifndef B130116
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN       */
#endif
#ifndef B130124
   ADSL_CONN1_G->adsc_ineta_raws_1 = adsl_ineta_raws_1_new;  /* auxiliary extension field HOB-TUN */
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select
     = DEF_NETW_POST_1_HTUN_CONN_OK | DEF_NETW_POST_1_HTUN_FREE_R;  /* select the events */
   adsl_ineta_raws_1_new->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   m_hl_lock_inc_1( &ADSL_CONN1_G->imc_references );  /* references to this session */
   m_htun_new_sess_htcp( &dsl_tun_start_htcp,
                         &ADSL_CONN1_G->dsc_tun_contr_conn,  /* HOB-TUN control area connection */
                         &adsl_ineta_raws_1_new->dsc_tun_contr_ineta );  /* HOB-TUN control interface for INETA */
   ADSL_CONN1_G->dsc_htun_h = adsl_ineta_raws_1_new->dsc_htun_h;  /* handle created */
// ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#ifdef B130116
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN       */
#endif
#ifdef TRACEHL1
#ifndef HL_UNIX
#ifndef NEW_HOB_TUN_1103
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_tcp_dynamic_conn() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, adsl_ineta_raws_1_new->dsc_htun_h, &adsl_ineta_raws_1_new->dsc_tun_contr1 );
#else
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_tcp_dynamic_conn() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, ADSL_CONN1_G->dsc_htun_h, &ADSL_CONN1_G->dsc_tun_contr1 );
#endif
#endif
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#ifdef DEBUG_130722_01                      /* HTCP connect fails      */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp-l%05d-T m_tcp_dynamic_conn() adsl_ineta_raws_1_new=%p ->imc_state=0X%08X ADSL_CONN1_G->adsc_ineta_raws_1=%p.",
                   __LINE__, adsl_ineta_raws_1_new, adsl_ineta_raws_1_new->imc_state, ADSL_CONN1_G->adsc_ineta_raws_1 );
#endif
#ifndef B130719
#ifdef B130722
   if ((adsl_ineta_raws_1_new->imc_state & (DEF_STATE_HTUN_FREE_R_1 | DEF_STATE_HTUN_FREE_R_2)) == 0) {  /* done HTUN free resources */
     goto p_conn_20;                        /* after connect           */
   }
#endif
#ifndef B130722
// to-do 22.07.13 KB - should we also check DEF_STATE_HTUN_SESS_END ???
   if ((adsl_ineta_raws_1_new->imc_state & DEF_STATE_HTUN_ERR_SESS_END) == 0) {  /* done HOB-TUN free resources */
     goto p_conn_20;                        /* after connect           */
   }
#endif
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B130722
   ADSL_CONN1_G->adsc_ineta_raws_1 = NULL;
#endif
#ifdef B131213
// 15.08.10 KB - where to get error number from ???
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_timeout;  /* connection timed out */
#endif
#ifndef B131213
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_error;  /* other error     */
#ifdef NOT_YET_131213
xiipgw08-tun.cpp
connect error
hob-tun01.h
#define HTCP_ERR_CONN_REFUSED         (HTCP_ERR_BASE + 1)
#endif
#endif
#ifndef HL_UNIX
#ifndef B110419
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
#endif
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected    */
#endif
#ifndef B131118
#endif
   return TRUE;
#endif

#undef ADSL_NETW_POST_1

#endif
//---
   p_tcpcomp_00:                            /* connect over TCPCOMP    */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifdef B120213
   memset( &ADSL_CONN1_G->dsc_netw_post_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_CONN1_G->dsc_netw_post_1.adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_CONN1_G->dsc_netw_post_1.imc_select = DEF_NETW_POST_1_TCPCOMP_CONN_OK | DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */

   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_wait_conn_s_dynamic;  /* wait for dynamic connect to server */
   bol1 = ADSL_CONN1_G->dcl_tcp_r_s.m_connect_1( ADSL_CONN1_G,
                                                 &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,  /* IP address multihomed */
                                                 adsl_target_ineta_1,
                                                 adsp_tcp_conn->imc_server_port,
                                                 ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin,  /* do connect round-robin */
                                                 &ADSL_CONN1_G->dsc_netw_post_1 );  /* structure to post from network callback */
   if (bol1 == FALSE) {                     /* error occured           */
// to-do 14.12.10 KB
   }
   while (ADSL_CONN1_G->dsc_netw_post_1.boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CONN_OK | DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_wait_conn_s_dynamic;  /* wait for dynamic connect to server */
   bol1 = ADSL_CONN1_G->dcl_tcp_r_s.m_connect_1( ADSL_CONN1_G,
                                                 &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,  /* IP address multihomed */
                                                 adsl_target_ineta_1,
                                                 al_free_ti1,
                                                 adsp_tcp_conn->imc_server_port,
                                                 ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin,  /* do connect round-robin */
                                                 ADSL_NETW_POST_1 );  /* structure to post from network callback */
   if (bol1 == FALSE) {                     /* error occured           */
// to-do 14.12.10 KB
   }
#else
// to-do 13.02.12 KB
   ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_dynamic;  /* wait for dynamic connect to server */
   memset( &ADSL_CONN1_G->dsc_tc1_server, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure server */
   ADSL_CONN1_G->dsc_tc1_server.adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   ADSL_CONN1_G->dsc_tc1_server.boc_connected = TRUE;  /* TCP session is connected */
   iml_rc = ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_startco_mh(
                  &dss_tcpcomp_cb1,
//                this,
                  ADSL_CONN1_G,
                  &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,  /* IP address multihomed */
                  adsl_target_ineta_1,
                  al_free_ti1,
                  adsp_tcp_conn->imc_server_port,
                  ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin );  /* do connect round-robin */
   if (iml_rc != 0) {                       /* error occured           */
     ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d m_startco_mh() failed %d.",
                     __LINE__, iml_rc );
   }
#endif
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d before wait ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype );
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#undef ADSL_NETW_POST_1
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d after  wait ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype );
#endif
   if (adsl_target_ineta_1 != adsp_target_ineta_1) {  /* INETA not passed as parameter */
     free( adsl_target_ineta_1 );           /* free the target INETAs  */
   }
#ifndef HL_UNIX
#ifndef X101214_XX
   if (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_start_server_1) {  /* start connection to server part one */
     goto p_conn_20;                        /* after connect           */
   }
#else
   if (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_start_dyn_serv_1) {  /* start connection to server part one dynamic */
     goto p_conn_20;                        /* after connect           */
   }
#endif
#else
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_1) {  /* start connection to server part one */
     goto p_conn_20;                        /* after connect           */
   }
#endif
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d ADSL_CONN1_G->iec_st_ses=%d - set iec_servcotype to ied_servcotype_none",
                   __LINE__, ADSL_CONN1_G->iec_st_ses );
#endif
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B131213
// 15.08.10 KB - where to get error number from ???
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_timeout;  /* connection timed out */
#endif
#ifndef B131213
#ifndef HL_UNIX
   iml1 = ADSL_CONN1_G->dcl_tcp_r_s.m_get_conn_error();
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_error;  /* other error     */
   switch (iml1) {                          /* check error from TCPCOMP */
     case TCPCOMP_ERR_CONN_ALL_REFUSED:
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_refused;  /* connect refused */
       break;
     case TCPCOMP_ERR_CONN_ALL_TIMEOUT:
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_timeout;  /* connect timed out */
       break;
// 13.12.13 KB - no route to host
   }
#endif
#ifdef HL_UNIX
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_error;  /* other error     */
   switch (ADSL_CONN1_G->imc_connect_error) {  /* check error from TCPCOMP */
     case TCPCOMP_ERR_CONN_ALL_REFUSED:
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_refused;  /* connect refused */
       break;
     case TCPCOMP_ERR_CONN_ALL_TIMEOUT:
       adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_timeout;  /* connect timed out */
       break;
// 13.12.13 KB - no route to host
   }
#endif
#endif
#ifndef HL_UNIX
#ifndef B110419
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
#endif
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected    */
#endif
   return TRUE;

   p_conn_20:                               /* after connect           */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_tcp_dynamic_conn() l%05d - TCP connect successfull", __LINE__ );
#endif
#ifdef D_INCL_HOB_TUN
#ifdef B130124
#ifdef HL_UNIX
   ADSL_CONN1_G->adsc_ineta_raws_1 = adsl_ineta_raws_1_new;  /* auxiliary extension field HTUN */
#endif
#endif
#endif
#ifndef B140525
   if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old entry */
     ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
#ifdef B140704
     free( adsl_server_conf_1_w1 );         /* free old server entry   */
#endif
#ifndef B140704
     /* free delayed because of race conditions                        */
#define ADSL_TIMER_ELE_G ((struct dsd_timer_ele *) ((char *) adsl_server_conf_1_w1 + IMD_SERVER_CONF_1))
     memset( ADSL_TIMER_ELE_G, 0, sizeof(struct dsd_timer_ele) );
     ADSL_TIMER_ELE_G->amc_compl = &m_free_seco1;  /* set routine for free after timer */
     ADSL_TIMER_ELE_G->ilcwaitmsec = DEF_TIMER_FREE_SERVER_CONF_1;  /* delay in milliseconds before freeing the temporary server configuration */
     m_time_set( ADSL_TIMER_ELE_G, FALSE );  /* set timer now          */
#undef ADSL_TIMER_ELE_G
#endif
   }
#endif
   if (bop_extended == FALSE) {             /* we are not extended     */
     goto p_conn_40;                        /* do remaining things after connect */
   }
   adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old value */
#ifdef DEBUG_131129_01                      /* adsc_seco1_previous - configuration server previous */
   if (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp-l%05d-W DEBUG_131129_01 m_tcp_dynamic_conn() adsc_seco1_previous not NULL - memory leak",
                     __LINE__ );
   }
#endif
#ifdef B170208
#ifdef B140525
#ifndef X101215_XX
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
   ADSL_CONN1_G->adsc_server_conf_1 = (struct dsd_server_conf_1 *)
                                         malloc( sizeof(struct dsd_server_conf_1)
                                                 + adsl_server_conf_1_w1->inc_no_sdh
                                                   * sizeof(struct dsd_sdh_work_1) );
#else
   ADSL_CONN1_G->adsc_server_conf_1 = (struct dsd_server_conf_1 *)
                                         malloc( sizeof(struct dsd_server_conf_1) );
#endif
#endif
#ifndef B140525
// to-do 25.05.14 - memory for DNS name as needed for SSL certificated check
   ADSL_CONN1_G->adsc_server_conf_1 = (struct dsd_server_conf_1 *)
                                         malloc( sizeof(struct dsd_server_conf_1) );
#endif
#endif
#ifndef B170208
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &adsp_tcp_conn->dsc_target_ineta );  /* INETA of target / server */
   if (iml1 < 0) {
     m_hlnew_printf( HLOG_WARN1, "xiipgw08-tcp-l%05d-W m_tcp_dynamic_conn() character-set invalid",
                     __LINE__ );
     return FALSE;
   }
   ADSL_CONN1_G->adsc_server_conf_1 = (struct dsd_server_conf_1 *)
                                         malloc( sizeof(struct dsd_server_conf_1) + iml1 );
#endif
   memset( ADSL_CONN1_G->adsc_server_conf_1, 0, sizeof(struct dsd_server_conf_1) );
#ifndef B170208
   m_cpy_uc_vx_ucs( ADSL_CONN1_G->adsc_server_conf_1 + 1, iml1, ied_chs_utf_8,  /* Unicode UTF-8 */
                    &adsp_tcp_conn->dsc_target_ineta );  /* INETA of target / server */
   ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name  /* address of DNS name */
     = (char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1);
   ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name = iml1;  /* length of DNS name */
#endif
   ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous = adsl_server_conf_1_w1;  /* configuration server previous */
   ADSL_CONN1_G->adsc_server_conf_1->boc_use_csssl = bol_csssl;  /* client-side SSL */
#ifdef B140525
   if (adsl_server_conf_1_w1->inc_no_sdh) {
     ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh = adsl_server_conf_1_w1->inc_no_sdh;
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
     memcpy( ADSL_CONN1_G->adsc_server_conf_1 + 1,
             adsl_server_conf_1_w1 + 1,
             adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1) );
#ifdef B101215
     if (adsl_server_conf_1_w1->inc_no_sdh >= 2) {
       ADSL_CONN1_G->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
       memset( ADSL_CONN1_G->adsrc_sdh_s_1, 0, adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
     }
#endif
#ifdef TRACEHL1
     {
       char *achh1, *achh2, *achh3;
       char chrh_work_1[128];
       int inh1, inh2;

       m_hlnew_printf( HLOG_XYZ1, "m_tcp_dynamic_conn() l%05d - ADSL_CONN1_G->adsc_server_conf_1=%p",
                       __LINE__, ADSL_CONN1_G->adsc_server_conf_1 );
       m_hlnew_printf( HLOG_XYZ1, "m_tcp_dynamic_conn() copy to=%p from=%p len=%d",
                       ADSL_CONN1_G->adsc_server_conf_1 + 1,
                       adsl_server_conf_1_w1 + 1,
                       adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1) );
       achh1 = (char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1);
       achh2 = achh1 + adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1);
       while (achh1 < achh2) {
         inh1 = sprintf( chrh_work_1, "<%p> ", achh1 );
         achh3 = achh1 + 16;
         if (achh3 > achh2) achh3 = achh2;
         inh2 = 4;
         do {
           if (inh2 == 0) {
            chrh_work_1[ inh1++ ] = ' ';
            inh2 = 4;
           }
           inh1 += sprintf( chrh_work_1 + inh1, " %02X", (unsigned char) *achh1++ );
           inh2--;
         } while (achh1 < achh3);
         m_hlnew_printf( HLOG_XYZ1, "%s", chrh_work_1 );
       }
     }
#endif
   }
#endif
   ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic = TRUE;
#ifdef XYZ1
#ifndef B080407
   ADSL_CONN1_G->dcl_tcp_r_s.start1( ADSL_CONN1_G,
                                     (struct sockaddr *) &dsl_soa_target,
                                     sizeof(dsl_soa_target),
                                     iml_conn_socket );
#endif
#endif
   p_conn_40:                               /* do remaining things after connect */
#ifdef B060718
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server */
#else
   if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifdef XYZ1
     ADSL_CONN1_G->dcl_tcp_r_s.start2();      /* start TCPCOMP           */
#endif
// 14.08.10 KB where to do this ???
#ifndef HL_UNIX
     ADSL_CONN1_G->dcl_tcp_r_s.start3();    /* receive data now        */
#else
     ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_recv();  /* receive data now */
#endif
   }
#endif
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected    */
#endif
   iml1 = 0;                                /* clear timeout           */
#ifdef CSSSL_060620
   if (bol_csssl) {                         /* use client-side SSL     */
     iml1 = m_cl_get_conf_timeout( adsg_loconf_1_inuse->vpc_csssl_config_id );
   }
#endif
   /* from GATE                                                        */
   if (   (iml1 == 0)
       || (ADSL_CONN1_G->adsc_gate1->itimeout < iml1)) {
     iml1 = ADSL_CONN1_G->adsc_gate1->itimeout;
   }
   if (ADSL_CONN1_G->adsc_server_conf_1) {  /* server connected        */
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout) {
       if (   (iml1 == 0)
           || (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout < iml1)) {
         iml1 = ADSL_CONN1_G->adsc_server_conf_1->inc_timeout;
       }
     }
   }
#ifndef B130323
   if (ADSL_CONN1_G->imc_timeout_set) {     /* timeout set in seconds  */
     iml1 = ADSL_CONN1_G->imc_timeout_set;  /* timeout set in seconds  */
   }
#endif
   if (iml1 > 0) {                          /* set timeout             */
     ADSL_CONN1_G->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time */
   } else {                                 /* no timeout              */
     ADSL_CONN1_G->ilc_timeout = 0;         /* no end-time             */
   }
/* IPV6 - attention UUUU */
#ifdef B100816
// to-do 16.08.10 - do we need a message or is this done in TCPCOMP callback ???
   m_hlnew_printf( HLOG_XYZ1, "HWSPS060I GATE=%(ux)s SNO=%08d INETA=%s connect to server (dynamic) INETA %d.%d.%d.%d successful",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                   *((unsigned char *) &dsl_soa_target.sin_addr),
                   *((unsigned char *) &dsl_soa_target.sin_addr + 1),
                   *((unsigned char *) &dsl_soa_target.sin_addr + 2),
                   *((unsigned char *) &dsl_soa_target.sin_addr + 3) );
#endif
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifdef CSSSL_060620
   if (bol_csssl == FALSE) return TRUE;     /* do not start SSL        */
   /* use client-side SSL                                              */
#ifdef B170208
   iml1 = m_len_vx_ucs( ied_chs_utf_8, &adsp_tcp_conn->dsc_target_ineta );
   ADSL_CONN1_G->adsc_csssl_oper_1 = (struct dsd_csssl_oper_1 *) malloc( sizeof(struct dsd_csssl_oper_1) + iml1 + 1 );
   memset( ADSL_CONN1_G->adsc_csssl_oper_1, 0, sizeof(struct dsd_csssl_oper_1) );
   m_cpy_vx_ucs( ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                 iml1,
                 ied_chs_utf_8,
                 &adsp_tcp_conn->dsc_target_ineta );
   *((char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) + iml1) = 0;  /* make zero-terminated */
#endif
#ifndef B170208
   ADSL_CONN1_G->adsc_csssl_oper_1 = (struct dsd_csssl_oper_1 *) malloc( sizeof(struct dsd_csssl_oper_1) + iml1 + 1 );
   memset( ADSL_CONN1_G->adsc_csssl_oper_1, 0, sizeof(struct dsd_csssl_oper_1) );
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.dsc_ucs_target_host.ac_str  /* address of string */
     = ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name;  /* address of DNS name */
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.dsc_ucs_target_host.imc_len_str  /* length of string in elements */
     = ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.dsc_ucs_target_host.iec_chs_str  /* character set of string */
     = ied_chs_utf_8;                       /* Unicode UTF-8           */
#endif
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_aux = &m_cdaux;  /* subroutine */
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_conn_callback = &m_ssl_conn_cl_compl_cl;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_start = &m_ocsp_start;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_send = &m_ocsp_send;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_recv = &m_ocsp_recv;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_stop = &m_ocsp_stop;
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.vpc_config_id = adsg_loconf_1_inuse->vpc_csssl_config_id;
#ifndef HL_UNIX
   bol1 = QueryPerformanceCounter( (LARGE_INTEGER *) &ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.ilc_entropy );
#else
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.ilc_entropy = m_get_epoch_nanoseconds();
#endif
   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.ilc_entropy -= *((HL_LONGLONG *) &ill_entropy);  /* time needed for connect */
#ifdef XYZ1
   m_hlcl01( &ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d m_tcp_dynamic_conn() - m_hlcl01( %p ) returned inc_return=%d",
                   __LINE__,
                   &ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s,
                   ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s.inc_return );
#endif
#endif
   adsp_tcp_conn->iec_tcpconn_ret = ied_tcr_ok;  /* connect successful */
   return TRUE;                             /* all done                */
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_tcp_dynamic_conn()                                          */

/**
   do static connect to configured server
*/
extern "C" int m_tcp_static_conn( void * vpp_userfld, BOOL bop_wait_compl ) {
   int        iml_rc;                       /* return code             */
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* return code             */
#endif
   struct dsd_target_ineta_1 *adsl_server_ineta_w1;  /* server INETA   */
#ifndef B130826
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
#endif
   void *     al_free_ti1;                  /* INETA to be freed       */
#ifdef D_INCL_HOB_TUN
   socklen_t  iml_local_namelen;            /* length of name local    */
   enum ied_ineta_raws_def iel_irs_def;     /* type of INETA raw socket */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* extension field HOB-TUN */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
   struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_tcp_static_conn() started - TCP connect" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d m_tcp_static_conn() called ADSL_CONN1_G->iec_st_ses=%d bop_wait_compl=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, bop_wait_compl );
#endif
   adsl_server_ineta_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_server_ineta;  /* server INETA */
   al_free_ti1 = NULL;                      /* INETA to be freed       */
   if (ADSL_CONN1_G->adsc_server_conf_1->boc_dns_lookup_before_connect) {  /* needs to solve INETA before connect */
     adsl_server_ineta_w1 = m_get_target_ineta( ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name,  /* address of DNS name */
                                                ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                                                ied_chs_ansi_819,
                                                &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out );
     if (adsl_server_ineta_w1 == NULL) {    /* could not resolve INETA */
       m_hlnew_printf( HLOG_WARN1, "HWSPS170W GATE=%(ux)s SNO=%08d INETA=%s configured INETA %.*s could not by resolved by DNS",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                       ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name );  /* address of DNS name */
#define DEF_ERR_NO_DNS 124
       if (bop_wait_compl) return DEF_ERR_NO_DNS;
       if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active */
         ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = DEF_ERR_NO_DNS;
         ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
         ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
         return DEF_ERR_NO_DNS;
       }
// to-do 03.07.10 KB we return now, we do not need to start the SDHs
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error */
#endif
       if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) return DEF_ERR_NO_DNS;  /* not dynamicly allocated */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_error_co_dyn;  /* status server error */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
#endif
       return DEF_ERR_NO_DNS;
     }
     al_free_ti1 = adsl_server_ineta_w1;    /* INETA to be freed       */
   }
#ifdef HL_UNIX
   ADSL_CONN1_G->imc_connect_error = 0;     /* save connect error      */
#endif
#ifdef D_INCL_HOB_TUN
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
   if (   (ADSL_CONN1_G->adsc_server_conf_1->boc_use_ineta_appl)  /* use HTCP */
       && (adsl_raw_packet_if_conf)) {
     iel_irs_def = ied_ineta_raws_user_ipv4;  /* INETA user IPV4       */
     adsl_ineta_raws_1_w1 = m_prepare_htun_ineta_htcp( ADSL_CONN1_G,
                                                       ADSL_AUX_CF1->adsc_hco_wothr,
                                                       iel_irs_def );
     if (adsl_ineta_raws_1_w1) {            /* INETA found             */
       goto p_start_tun_00;                 /* start HOB-TUN           */
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS173W GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
   }
#endif
#ifndef B130826
   adsl_netw_post_1 = NULL;                 /* structure to post from network callback */
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   if (bop_wait_compl) {
#ifdef B130826
     memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
     ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
     ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CONN_OK | DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
#else
     adsl_netw_post_1 = ADSL_NETW_POST_1;   /* structure to post from network callback */
     memset( adsl_netw_post_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
     adsl_netw_post_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
     adsl_netw_post_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CONN_OK | DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
#endif
   }
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifdef B121122
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_wait_conn_s_dynamic;  /* wait for dynamic connect to server */
#else
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#endif
#ifdef B130826
   bol_rc = ADSL_CONN1_G->dcl_tcp_r_s.m_connect_1( ADSL_CONN1_G,
                                                   &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,  /* IP address multihomed */
                                                   adsl_server_ineta_w1,
#ifndef B121120
                                                   al_free_ti1,  /* INETA to free */
#endif
                                                   ADSL_CONN1_G->adsc_server_conf_1->inc_server_port,  /* TCP/IP port connect */
                                                   ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin,  /* do connect round-robin */
                                                   ADSL_NETW_POST_1 );  /* structure to post from network callback */
#endif
#ifndef B130826
   bol_rc = ADSL_CONN1_G->dcl_tcp_r_s.m_connect_1( ADSL_CONN1_G,
                                                   &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,  /* IP address multihomed */
                                                   adsl_server_ineta_w1,
                                                   al_free_ti1,  /* INETA to free */
                                                   ADSL_CONN1_G->adsc_server_conf_1->inc_server_port,  /* TCP/IP port connect */
                                                   ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin,  /* do connect round-robin */
                                                   adsl_netw_post_1 );  /* structure to post from network callback */
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
// to-do 14.12.10 KB
   }
#else
   memset( &ADSL_CONN1_G->dsc_tc1_server, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure server */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifdef TRY100514X01
#include "xiipgw08-test-ineta-1.cpp"
#endif
// iec_st_ses = ied_ses_wait_conn_s_pttd;  /* wait for connect to server, pass-thru-to-desktop */
// if (bop_wait_compl == FALSE) {
     ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
// }
   ADSL_CONN1_G->dsc_tc1_server.boc_connected = TRUE;  /* TCP session is connected */
#ifndef B140530
   ADSL_CONN1_G->dsc_tc1_server.adsc_netw_post_1 = adsl_netw_post_1;  /* structure to post from network callback */
#endif
   iml_rc = ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_startco_mh(
              &dss_tcpcomp_cb1,
              ADSL_CONN1_G,
              &ADSL_CONN1_G->adsc_server_conf_1->dsc_bind_out,
              adsl_server_ineta_w1,         /* server INETA            */
#ifndef B121121
              al_free_ti1,                  /* INETA to free           */
#endif
              ADSL_CONN1_G->adsc_server_conf_1->inc_server_port,  /* TCP/IP port connect */
              ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin );  /* do connect round-robin */
   if (iml_rc) {                            /* error occured          */
     ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
#ifndef B140530
     ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#endif
// boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
     m_hlnew_printf( HLOG_WARN1, "HWSPS175W GATE=%(ux)s SNO=%08d INETA=%s nbipgw20 l%05d m_startco_mh() failed %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
// to-do 13.08.10 KB what to do ???
// to-do 17.11.12 KB set ADSL_CONN1_G->iec_st_ses
     if (al_free_ti1) free( al_free_ti1 );  /* INETA to be freed       */
     return iml_rc;
   }
#endif
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d m_tcp_static_conn() after TCPCOMP ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d adsl_netw_post_1=%p.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype, adsl_netw_post_1 );
#endif
   if (bop_wait_compl == FALSE) return 0;   /* connect active          */
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp.cpp l%05d m_tcp_static_conn() after wait ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype );
#endif
   if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifndef HL_UNIX
     ADSL_CONN1_G->dcl_tcp_r_s.start3();    /* receive data now        */
#else
     ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_recv();  /* receive data now */
#endif
   }
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
   return ADSL_CONN1_G->dcl_tcp_r_s.m_get_conn_error();
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected    */
   return ADSL_CONN1_G->imc_connect_error;
#endif
#undef ADSL_NETW_POST_1
#ifdef D_INCL_HOB_TUN
   p_start_tun_00:                          /* start HOB-TUN           */
   adsl_soa_w1 = (struct sockaddr *) &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                  /* error occured           */
#ifndef HL_UNIX
     if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
       iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code   */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     iml_rc );
#else
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     errno );
#endif
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     chrl_ineta_local, adsl_ineta_raws_1_w1->usc_appl_port );
   }
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* chain of buffers to send over HOB-TUN */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );
   ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type */
   memset( &dsl_tun_start_htcp, 0, sizeof(struct dsd_tun_start_htcp) );  /* HOB-TUN start interface HTCP */
   dsl_tun_start_htcp.adsc_server_ineta = adsl_server_ineta_w1;  /* server INETA */
   dsl_tun_start_htcp.ac_free_ti1 = al_free_ti1;  /* INETA to free     */
   dsl_tun_start_htcp.imc_server_port = ADSL_CONN1_G->adsc_server_conf_1->inc_server_port;  /* TCP/IP port connect */
   dsl_tun_start_htcp.boc_connect_round_robin = ADSL_CONN1_G->adsc_server_conf_1->boc_connect_round_robin;  /* do connect round-robin */
   dsl_tun_start_htcp.imc_tcpc_to_msec = adsl_raw_packet_if_conf->imc_tcpc_to_msec;  /* TCP connect timeout milliseconds */
   if (dsl_tun_start_htcp.imc_tcpc_to_msec == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_to_msec = DEF_HTCP_TCPC_TO_MSEC;  /* TCP connect timeout milliseconds */
   }
   dsl_tun_start_htcp.imc_tcpc_try_no = adsl_raw_packet_if_conf->imc_tcpc_try_no;  /* TCP connect number of try */
   if (dsl_tun_start_htcp.imc_tcpc_try_no == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_try_no = DEF_HTCP_TCPC_TRY_NO;  /* TCP connect number of try */
   }
   dsl_tun_start_htcp.boc_tcp_keepalive = adsg_loconf_1_inuse->boc_tcp_keepalive;  /* TCP KEEPALIVE */
   adsl_ineta_raws_1_w1->ac_conn1 = ADSL_CONN1_G;  /* set connection   */
// dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &ADSL_CONN1_G->dsc_htun_h;  /* where to put the handle created */
   dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &adsl_ineta_raws_1_w1->dsc_htun_h;  /* where to put the handle created */
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#endif
   ADSL_CONN1_G->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
   m_hl_lock_inc_1( &ADSL_CONN1_G->imc_references );  /* references to this session */
   m_htun_new_sess_htcp( &dsl_tun_start_htcp,
                         &ADSL_CONN1_G->dsc_tun_contr_conn,  /* HOB-TUN control area connection */
                         &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta );  /* HOB-TUN control interface for INETA */
   ADSL_CONN1_G->dsc_htun_h = adsl_ineta_raws_1_w1->dsc_htun_h;  /* handle created */
#ifdef B130116
#ifdef B121211
// ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#endif
#ifndef B121211
   ADSL_CONN1_G->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;
#endif
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
#endif
   if (bop_wait_compl == FALSE) return 0;   /* connect active          */
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select
     = DEF_NETW_POST_1_HTUN_CONN_OK | DEF_NETW_POST_1_HTUN_FREE_R;  /* select the events */
   adsl_ineta_raws_1_w1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#ifndef B121211
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* server is connected    */
#endif
#endif
// to-do 21.11.12 KB - connect error
   return 0;
#undef ADSL_NETW_POST_1
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_tcp_static_conn()                                           */

/**
   close connection to server for Server-Data-Hooks (SDHs)
*/
extern "C" BOOL m_tcp_close( void * vpp_userfld ) {
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
#endif
   BOOL       bol1;                         /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#ifndef B140611
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifndef B101213
#ifdef D_INCL_HOB_TUN
   dsd_htun_h dsl_htun_h;                   /* handle for HTUN         */
#endif
#endif
#ifdef D_INCL_HOB_TUN
#ifdef B120913
   struct dsd_netw_post_1 dsl_netw_post_1;  /* structure to post from network callback */
#endif
#ifndef B141205
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* extension field HOB-TUN */
#endif
#endif
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_tcp_close() started - TCP close existing connection" );
#endif
#ifdef DEBUG_100830_01
   m_hlnew_printf( HLOG_XYZ1, "m_tcp_close() started - TCP close existing connection" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
#define ADSL_PD_WORK_G ((struct dsd_pd_work *) ((char *) vpp_userfld - offsetof( struct dsd_pd_work, dsc_aux_cf1 )))
#ifndef B140611
   bol1 = FALSE;                            /* no client-side SSL      */
#endif
   if (ADSL_CONN1_G->adsc_csssl_oper_1) {   /* with client-side SSL    */
#ifndef B140611
//   ADSL_PD_WORK_G->boc_eof_server = TRUE;  /* set End-of-File Server */
     ADSL_PD_WORK_G->boc_eof_client = TRUE;  /* set End-of-File Client */
#endif
     m_pd_close_cs_ssl( ADSL_PD_WORK_G );
#ifndef B140611
//   ADSL_PD_WORK_G->boc_eof_server = FALSE;  /* reset End-of-File Server */
     ADSL_PD_WORK_G->boc_eof_client = FALSE;  /* reset End-of-File Client */
     bol1 = TRUE;                           /* with client-side SSL    */
#endif
   }
#ifndef B140611
   /* check if we still need to send data to the server                */
   if (bol1) {                              /* needs to change data from client-side SSL */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     adsl_sdhc1_w2 = NULL;                  /* nothing to append data to */
     while (adsl_sdhc1_w1) {                /* loop over all buffers   */
       if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) {
         if (adsl_sdhc1_w1->inc_position == -1) {  /* to client-side SSL */
           adsl_sdhc1_w1->adsc_gather_i_1_i = NULL;  /* no more gather input data */
           if (adsl_sdhc1_w2 == NULL) {     /* nothing to append data to */
             adsl_sdhc1_w2 = adsl_sdhc1_w1;  /* append data from here  */
           }
         } else if (adsl_sdhc1_w1->inc_position == -2) {  /* was data to server after client-side SSL */
           adsl_sdhc1_w1->inc_position = -1;  /* send to server now    */
           if (adsl_sdhc1_w2) {             /* something to append data to */
             do {                           /* loop all old structures */
               adsl_sdhc1_w2->adsc_gather_i_1_i = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set gather input data */
               adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
             } while (adsl_sdhc1_w2 != adsl_sdhc1_w1);
             adsl_sdhc1_w2 = NULL;          /* nothing to append data to */
           }
         }
       }
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
   }
   bol1 = m_do_send_server( ADSL_AUX_CF1->adsc_hco_wothr, ADSL_CONN1_G );
#endif
#undef ADSL_PD_WORK_G
   switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
       goto p_tcpcomp_00;                   /* end session TCPCOMP     */
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HOB-TUN                 */
       goto p_htun_00;                      /* HOB-TUN                 */
#endif
   }
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   return TRUE;                             /* all done                */

   p_tcpcomp_00:                            /* end session TCPCOMP     */
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_SEND_COMPL;  /* posted for TCPCOMP send complete */
#ifndef HL_UNIX
   ADSL_CONN1_G->dcl_tcp_r_s.m_set_netw_post_1( ADSL_NETW_POST_1 );
   bol1 = ADSL_CONN1_G->dcl_tcp_r_s.m_check_send_act();
   if (bol1) {                              /* we need to wait for send complete */
     while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
       m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
     }
     ADSL_NETW_POST_1->boc_posted = FALSE;  /* reset again */
   }
   bol1 = m_do_send_server( ADSL_AUX_CF1->adsc_hco_wothr, ADSL_CONN1_G );
   if (bol1) goto p_tcpcomp_00;             /* wait again till data sent */
#else
// to-do 13.02.12 KB
   if (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send) {  /* chain to send */
     while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
       m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
     }
     goto p_tcpcomp_00;                     /* wait again till data sent */
   }
#endif
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_TCPCOMP_CLEANUP;  /* select the events */
#ifndef HL_UNIX
   ADSL_CONN1_G->dcl_tcp_r_s.m_set_netw_post_1( ADSL_NETW_POST_1 );
   if (ADSL_CONN1_G->dcl_tcp_r_s.getstc() == FALSE) {  /* session to server is not active */
     ADSL_NETW_POST_1->boc_posted = TRUE;   /* as if event has been posted */
   }
   ADSL_CONN1_G->dcl_tcp_r_s.close1();      /* close the TCP session   */
#else
   ADSL_CONN1_G->dsc_tc1_server.adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_end_session();  /* close TCP session */
// to-do 13.02.12 KB
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#undef ADSL_NETW_POST_1
#ifdef B171004
   /* remove blocks received from server                               */
   while (TRUE) {                           /* loop till no more data  */
     adsl_sdhc1_w1 = NULL;                  /* no data received yet    */
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {     /* data received from server */
       ADSL_CONN1_G->inc_c_ns_rece_s++;     /* count receive server    */
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (ADSL_CONN1_G->adsc_sdhc1_s1 + 1))
       ADSL_CONN1_G->ilc_d_ns_rece_s += ADSL_GATHER_I_1_W->achc_ginp_end - ADSL_GATHER_I_1_W->achc_ginp_cur;
#undef ADSL_GATHER_I_1_W
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_s1;  /* get data received from server */
       ADSL_CONN1_G->adsc_sdhc1_s1 = ADSL_CONN1_G->adsc_sdhc1_s2;  /* second buffer in front  */
       ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer     */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (adsl_sdhc1_w1 == NULL) break;      /* no data received        */
     m_proc_free( adsl_sdhc1_w1 );          /* free data again         */
   }
#endif
#ifdef B130724
#ifndef B130712
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#endif
#endif
#ifdef D_INCL_HOB_TUN
   goto p_close_20;                         /* continue close          */

   p_htun_00:                               /* HOB-TUN                 */
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (ADSL_CONN1_G->adsc_ineta_raws_1 + 1))
   m_do_send_server( ADSL_AUX_CF1->adsc_hco_wothr, ADSL_CONN1_G );

   p_htun_20:                               /* loop to wait till all data sent */
#ifdef B141205
   ADSL_CONN1_G->adsc_ineta_raws_1->imc_state &= -1 - DEF_STATE_HTUN_SEND_COMPL;  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
#endif
#ifndef B141205
   adsl_ineta_raws_1_w1 = ADSL_CONN1_G->adsc_ineta_raws_1;
   if (adsl_ineta_raws_1_w1 == NULL) {
     goto p_htun_40;                        /* all data sent           */
   }
   adsl_ineta_raws_1_w1->imc_state &= -1 - DEF_STATE_HTUN_SEND_COMPL;  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
#endif
   /* do garbage-collection and count how many bytes there are still to be sent */
#ifdef B141126
   while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     while (adsl_gai1_w1) {                 /* loop over chain gai1    */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     if (adsl_gai1_w1) break;               /* not all data sent       */
     ADSL_CONN1_G->adsc_sdhc1_htun_sch = ADSL_CONN1_G->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
#ifdef B110315
     if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use         */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     } else {                               /* work area still in use  */
       m_clconn1_mark_work_area( ADSL_CONN1_G, adsl_sdhc1_w1 );
     }
#else
     m_clconn1_mark_work_area( ADSL_CONN1_G, adsl_sdhc1_w1 );
#endif
   }
#endif
#ifndef B141126
   if (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
#endif
     while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       while (adsl_gai1_w1) {               /* loop over chain gai1    */
         if (   (adsl_sdhc1_w1->adsc_next)
             && (adsl_gai1_w1 == adsl_sdhc1_w1->adsc_next->adsc_gather_i_1_i)) {
           adsl_gai1_w1 = NULL;             /* all data in next block  */
           break;
         }
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       if (adsl_gai1_w1) break;             /* not all data sent       */
       ADSL_CONN1_G->adsc_sdhc1_htun_sch = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       /* block may still have usage count                             */
       adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* chain of buffers in use */
       ADSL_CONN1_G->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#endif
   }
#endif
   if (ADSL_CONN1_G->adsc_sdhc1_htun_sch == NULL) {  /* all data sent  */
     goto p_htun_40;                        /* all data sent           */
   }
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_HTUN_SEND_COMPL;  /* posted for HOB-TUN HTCP send complete */
   ADSL_CONN1_G->adsc_ineta_raws_1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SEND_COMPL) {  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
     ADSL_NETW_POST_1->boc_posted = TRUE;   /* as if event has been posted */
   }
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
   goto p_htun_20;                          /* loop to wait till all data sent */
#undef ADSL_NETW_POST_1

   p_htun_40:                               /* all data sent           */
#ifndef B101213
#ifndef NEW_HOB_TUN_1103
   dsl_htun_h = ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h;  /* handle for HOB-TUN */
#else
   dsl_htun_h = ADSL_CONN1_G->dsc_htun_h;   /* handle for HOB-TUN      */
#endif
   if (dsl_htun_h == NULL) {                /* already closed          */
     goto p_htun_60;                        /* HOB-TUN session closed  */
   }
#endif
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_AUX_CF1->adsc_hco_wothr->vprc_aux_area)
   memset( ADSL_NETW_POST_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
   ADSL_NETW_POST_1->adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
#ifndef TRY_120126_01
#ifdef HL_UNIX
#ifndef B130114
#define NEW_CLOSE_HTCP
#endif
#endif
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_HTUN_SESS_END;  /* posted for HOB-TUN HTCP session end */
#ifdef B141205
   ADSL_CONN1_G->adsc_ineta_raws_1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state
         & (DEF_STATE_HTUN_SESS_END         /* done HOB-TUN HTCP session end */
              | DEF_STATE_HTUN_ERR_SESS_END)) {  /* done HOB-TUN HTCP session end was with error */
#ifdef B101213
     dsl_netw_post_1.boc_posted = TRUE;     /* as if event has been posted */
#else
     goto p_htun_60;                        /* HOB-TUN session closed  */
#endif
   }
#endif
#ifndef B141205
   adsl_ineta_raws_1_w1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   if (adsl_ineta_raws_1_w1->imc_state
         & (DEF_STATE_HTUN_SESS_END         /* done HOB-TUN HTCP session end */
              | DEF_STATE_HTUN_ERR_SESS_END)) {  /* done HOB-TUN HTCP session end was with error */
     goto p_htun_60;                        /* HOB-TUN session closed  */
   }
#endif
#ifndef B120705
   if (   (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN)  /* HOB-TUN */
       || (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW)) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNCSC2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_tcp_close() call m_htun_sess_close() adsc_ineta_raws_1=%p.",
                  __LINE__, ADSL_CONN1_G->adsc_ineta_raws_1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifndef B101213
#endif
#ifdef B101213
   m_htun_sess_close( ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h );
#else
   m_htun_sess_close( dsl_htun_h );
#endif
#endif
#ifdef TRY_120126_01
   ADSL_NETW_POST_1->imc_select = DEF_NETW_POST_1_HTUN_FREE_R;  /* posted for HTUN free resources */
   ADSL_CONN1_G->adsc_ineta_raws_1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_FREE_R_1) {  /* done HTUN free resources */
     goto p_htun_60;                        /* HOB-TUN session closed  */
   }
   m_htun_sess_close( dsl_htun_h );
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
   }
#undef ADSL_NETW_POST_1
#ifndef B101213

   p_htun_60:                               /* HOB-TUN session closed  */
#endif
#ifdef B130924
#ifdef B120716
#ifndef B101005
   ADSL_CONN1_G->adsc_ineta_raws_1->ac_conn1 = NULL;  /* no more connected to session */
#endif
#else
   if (ADSL_CONN1_G->adsc_ineta_raws_1) {
     ADSL_CONN1_G->adsc_ineta_raws_1->ac_conn1 = NULL;  /* no more connected to session */
   }
#endif
#endif

   /* remove blocks received from server                               */
   while (TRUE) {                           /* loop till no more data  */
     adsl_sdhc1_w1 = NULL;                  /* no data received yet    */
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {     /* data received from server */
       ADSL_CONN1_G->inc_c_ns_rece_s++;     /* count receive server    */
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (ADSL_CONN1_G->adsc_sdhc1_s1 + 1))
       ADSL_CONN1_G->ilc_d_ns_rece_s += ADSL_GATHER_I_1_W->achc_ginp_end - ADSL_GATHER_I_1_W->achc_ginp_cur;
#undef ADSL_GATHER_I_1_W
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_s1;  /* get data received from server */
       ADSL_CONN1_G->adsc_sdhc1_s1 = ADSL_CONN1_G->adsc_sdhc1_s2;  /* second buffer in front  */
       ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer     */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (adsl_sdhc1_w1 == NULL) break;      /* no data received        */
     m_proc_free( adsl_sdhc1_w1 );          /* free data again         */
   }
   while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
     ADSL_CONN1_G->adsc_sdhc1_htun_sch = ADSL_CONN1_G->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
#ifdef DEBUG_130722_01                      /* HTCP connect fails      */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tcp-l%05d-T m_tcp_close() ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->adsc_ineta_raws_1=%p.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->adsc_ineta_raws_1 );
#endif
#ifndef B130724
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_conn;  /* is connected to server */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server */
#endif
#endif

   p_close_20:                              /* continue close          */
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef B130712
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#endif
#ifndef B130724
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
#endif
#ifndef B170620
// Stefan Martin SM170609_TCPCONNERR
#define ADSL_PD_WORK_G ((struct dsd_pd_work *) ((char *) vpp_userfld - offsetof( struct dsd_pd_work, dsc_aux_cf1 )))
   ADSL_PD_WORK_G->boc_eof_server = FALSE;              /* Reset EOF server flag in workthread. */
#undef ADSL_PD_WORK_G
#endif
#ifndef B171004
   /* remove blocks received from server                               */
   while (TRUE) {                           /* loop till no more data  */
     adsl_sdhc1_w1 = NULL;                  /* no data received yet    */
#ifndef HL_UNIX
     EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_enter();  /* enter CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {     /* data received from server */
       ADSL_CONN1_G->inc_c_ns_rece_s++;     /* count receive server    */
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (ADSL_CONN1_G->adsc_sdhc1_s1 + 1))
       ADSL_CONN1_G->ilc_d_ns_rece_s += ADSL_GATHER_I_1_W->achc_ginp_end - ADSL_GATHER_I_1_W->achc_ginp_cur;
#undef ADSL_GATHER_I_1_W
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_s1;  /* get data received from server */
       ADSL_CONN1_G->adsc_sdhc1_s1 = ADSL_CONN1_G->adsc_sdhc1_s2;  /* second buffer in front  */
       ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer     */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#else
     iml_rc = ADSL_CONN1_G->dsc_critsect.m_leave();  /* leave CriticalSection */
     if (iml_rc < 0) {                      /* error occured           */
// to-do 09.08.11 KB error number
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
     }
#endif
     if (adsl_sdhc1_w1 == NULL) break;      /* no data received        */
     m_proc_free( adsl_sdhc1_w1 );          /* free data again         */
   }
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* chain of buffers input output */
   while (adsl_sdhc1_w1) {                  /* loop over chain of buffers input output */
     if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
     if (adsl_sdhc1_w1->inc_position > 0) break;  /* position send to client */
     if (adsl_sdhc1_w1->inc_position == 0) {  /* position send to client */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       while (adsl_gai1_w1) {               /* loop over chain gai1    */
         adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
#endif
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous == NULL) return TRUE;  /* configuration server previous */
#ifdef B140704
   adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous;
   free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free this server entry */
   ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1;
   return TRUE;                             /* all done                */
#endif
#ifndef B140704
   adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;
   ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;
   /* free delayed because of race conditions                          */
#define ADSL_TIMER_ELE_G ((struct dsd_timer_ele *) ((char *) adsl_server_conf_1_w1 + IMD_SERVER_CONF_1))
   memset( ADSL_TIMER_ELE_G, 0, sizeof(struct dsd_timer_ele) );
   ADSL_TIMER_ELE_G->amc_compl = &m_free_seco1;  /* set routine for free after timer */
   ADSL_TIMER_ELE_G->ilcwaitmsec = DEF_TIMER_FREE_SERVER_CONF_1;  /* delay in milliseconds before freeing the temporary server configuration */
   m_time_set( ADSL_TIMER_ELE_G, FALSE );   /* set timer now           */
   return TRUE;                             /* all done                */
#undef ADSL_TIMER_ELE_G
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_tcp_close()                                                 */

#ifndef B140810
// 07.02.14 KB - move to xiipgw08-tcp.cpp
/** Connect Callback Server-Side SSL                                   */
static void m_ssl_conn_cl_compl_se( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
   int        inl1, inl2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
   int        inl_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
#ifdef OLD_1112
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
   char       *achl_pfs;                    /* pfs = YES / NO          */
   char       *achl_ssl_tls;                /* SSL / TLS version       */
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork2[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 256 ];          /* for text cipher         */
   char       byrl_ssl_tls[ 32 ];           /* SSL / TLS version       */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_se called" );
#endif
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#ifndef HELP_DEBUG                           /* 04.04.06 KB - help in tracing */
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld;  /* auxiliary control structure */
#ifndef HL_UNIX
   class clconn1 *ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#else
   struct dsd_conn1 *ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#endif
   struct dsd_ssl_query_info *ADSL_SSL_QUERY_INFO = (struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata;
   unsigned char *AUCL_CONNDATA = (unsigned char *) adsp_ccb_1->ac_conndata;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_se called adsp_ccb_1=%p", adsp_ccb_1 );
   m_hlnew_printf( HLOG_TRACE1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
//       for (i = 0; i < (ADSL_SSL_QUERY_INFO->hssl_byPartnerNameLength*2); i= i+2)
         for (i = 0; i < (ADSL_SSL_QUERY_INFO->ucc_partner_name_length*2); i= i+2)
         {
//     szString[j++] = ADSL_SSL_QUERY_INFO->hssl_byPartnerName[i+1];
       szString[j++] = ADSL_SSL_QUERY_INFO->ucrc_partner_name[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_TRACE1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->boc_st_sslc) {         /* ssl handshake complete  */
     m_hlnew_printf( HLOG_WARN1, "HWSPS00nW SSL handshake complete double" );
   }
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of extensions   */
   adsl_auxf_1_3 = NULL;                    /* no previous yet         */
   while (adsl_auxf_1_1) {                  /* loop over chain         */
     adsl_auxf_1_2 = adsl_auxf_1_1;         /* save this entry         */
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain   */
     bol1 = FALSE;                          /* is not double           */
     if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certname) {
       m_hlnew_printf( HLOG_WARN1, "HWSPS071W GATE=%(ux)s SNO=%08d INETA=%s Certificate Name (dn) came double",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     } else if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certificate) {
       m_hlnew_printf( HLOG_WARN1, "HWSPS072W GATE=%(ux)s SNO=%08d INETA=%s Certificate came double",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     }
     if (bol1) {                            /* remove this entry       */
       if (adsl_auxf_1_3 == NULL) {         /* is first in chain       */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_1;
       } else {                             /* in middle of chain      */
         adsl_auxf_1_3->adsc_next = adsl_auxf_1_1;
       }
       free( adsl_auxf_1_2 );               /* free this entry         */
     } else {
       adsl_auxf_1_3 = adsl_auxf_1_2;       /* save previous           */
     }
   }
#ifdef B121009
   inl_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   inl_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (inl_len_cert < 0)
       || (inl_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS073W GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     inl_len_cert );
     inl_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
     achl_pfs = "NO";                       /* pfs = YES / NO          */
     if (adsp_ccb_1->boc_pfs_used) {        /* Was a key exchange with PFS used? */
       achl_pfs = "YES";                    /* pfs = YES / NO          */
     }
     iml_ns_prot = ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 16;  /* SSL / TLS protocol version */
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     achl_ssl_tls = (char *) achrs_ssl_prot[ iml_ns_prot ];  /* SSL / TLS version */
     if (   (iml_ns_prot == 1)
         || (iml_ns_prot == 2)) {
       sprintf( byrl_ssl_tls,
                "%s-V%d.%d",
                achrs_ssl_prot[ iml_ns_prot ],
                (ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 8) & 0XFF,
                ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers & 0XFF );
       achl_ssl_tls = byrl_ssl_tls;         /* SSL / TLS version       */
     }
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_mac) / sizeof(achrs_ssl_mac[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
     sprintf( byrlwork_ssl, " - pfs:%s protocol:%s cipher-suite:%s key-exchange-mode:%s"
              " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
              achl_pfs,                     /* pfs = YES / NO          */
              achl_ssl_tls,                 /* SSL / TLS version       */
              achrs_ssl_ci_prot[ iml_ns_ci_sui ],
              achrs_ssl_keyexch[ iml_ns_keyexch ],
              achrs_ssl_ci_alg[ iml_ns_ci_alg ],
              achrs_ssl_ci_type[ iml_ns_ci_type ],
              achrs_ssl_mac[ iml_ns_mac ],
              achrs_ssl_auth[ iml_ns_auth ],
              achrs_ssl_compr[ iml_ns_compr ] );
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
   adsl_auxf_1_dn = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + (inl_len_cert + 1) * sizeof(HL_WCHAR) );
   adsl_auxf_1_dn->iec_auxf_def = ied_auxf_certname;  /* name from certificate */
   *((int *) (adsl_auxf_1_dn + 1)) = inl_len_cert;  /* set length name  */
   inl1 = sprintf( byrlwork1, "SSL logon - " );
   if (adsp_ccb_1->achc_fingerprint) {
     inl1 += sprintf( &byrlwork1[inl1], "fingerprint: " );
     inl2 = 0;
     do {
       inl1 += sprintf( &byrlwork1[inl1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + inl2) );

       if (inl2 % 2) byrlwork1[ inl1++ ] = ' ';
       inl2++;                              /* next character          */
     } while (inl2 < DEF_SSL_LEN_FINGERPRINT);
     inl1 += sprintf( &byrlwork1[inl1], "- " );  /* separate following text */
   }
   inl1 += sprintf( &byrlwork1[inl1], "DN (name from certificate): " );
   achl1 = &byrlwork1[inl1];                /* name comes here         */
   memcpy( byrlwork2, byrlwork1, inl1 );
   achl2 = &byrlwork2[inl1];                /* name comes here         */
   for (inl1 = 0; inl1 < inl_len_cert; inl1++ ) {
#ifdef B121009
     inl2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ inl1 * 2 ]) );
#endif
     inl2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ inl1 * 2 ]) );
     *((HL_WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl1) = inl2;
     if (inl2 < 0X0100) {
       *achl1++ = ucrg_tab_819_to_850[ inl2 ];
       *achl2++ = (char) inl2;
     } else {
       *achl1++ = '?';
       *achl2++ = '?';
     }
   }
   *((HL_WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl_len_cert) = 0;
   adsl_auxf_1_dn->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_dn;  /* set new chain       */
   *achl1 = 0;                              /* make zero-terminated    */
   achl1 = byrlwork1;
   *achl2 = 0;                              /* make zero-terminated    */
   achl2 = byrlwork2;
   if (adsp_ccb_1->inc_len_certificate == 0) goto psussl80;  /* write message */
   /* store certificate                                                */
   adsl_auxf_1_ce = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->iec_auxf_def = ied_auxf_certificate;  /* certificate */
   *((int *) (adsl_auxf_1_ce + 1)) = adsp_ccb_1->inc_len_certificate;  /* set length certificate */
   memcpy( (int *) (adsl_auxf_1_ce + 1) + 1,
           adsp_ccb_1->achc_certificate,
           adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ce;  /* set new chain       */

   psussl80:                                /* write message           */
#ifdef B060506
   /* 04.08.04 KB + Joachim Frank */
// printf( "%S INETA=%s %s\n",
//         (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->chrc_ineta, au1 );
   _snprintf( byrl_cout, sizeof(byrl_cout), "HWSPS080I GATE=%S SNO=%08d INETA=%s %s%s\n",
              (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
              ADSL_CONN1_G->dsc_co_sort.imc_sno,
              ADSL_CONN1_G->chrc_ineta, achl1, byrlwork_ssl );
#ifndef TRACE_PRINTF
   cout << byrl_cout;
#else
   EnterCriticalSection( &dss_critsect_printf );
   printf( "%s", (char *) byrl_cout );
   LeaveCriticalSection( &dss_critsect_printf );
#endif
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPS080I GATE=%(ux)s SNO=%08d INETA=%s %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta, achl2, byrlwork_ssl );
#ifdef WORK051119
   /* start authentication                                             */
   if (ADSL_CONN1_G->adsc_gate1->ad_auth_startup) {  /* must do authentication */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 before" );
#endif
#ifdef NOTYET050819
     ADSL_CONN1_G->dcl_wsat1_1 = (*ADSL_CONN1_G->adsc_gate1->ad_authlib1->am_constr)
       ( ADSL_CONN1_G->adsc_gate1->ad_auth_startup,
         (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
         inl_len_cert,
         ADSL_CONN1_G->adsc_gate1->ienatfa,
#ifndef HL_IPV6
         en_atca_IPV4,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1
#else
         en_atca_IPV6,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1
#endif
       );
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 after" );
#endif
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)
       && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_http)
       && (   (ADSL_CONN1_G->adsc_gate1->inc_no_radius)  /* authenticate Radius */
           || (ADSL_CONN1_G->adsc_gate1->inc_no_usgro))) {  /* authenticate usgr */
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
     ADSL_CONN1_G->adsc_radqu = new dsd_radius_query( ADSL_CONN1_G,
                                                      ADSL_CONN1_G->adsc_gate1->inc_no_radius,
                                                      ADSL_CONN1_G->adsc_gate1->inc_no_usgro,
                                                      (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
                                                      inl_len_cert,
                                                      &(ADSL_CONN1_G->adsc_gate1->dsc_radius_conf),
                                                      iel_claddrtype,
                                                      avol_client_netaddr );
   }
#endif
   ADSL_CONN1_G->boc_st_sslc = TRUE;        /* ssl handshake complete  */
#ifndef HELP_DEBUG
#undef AUCL_CONNDATA
//#undef hssl_QueryInfo
#undef ADSL_SSL_QUERY_INFO
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_ssl_conn_cl_compl_se()                                      */

#ifdef CSSSL_060620
/* Connect Callback Client-Side SSL                                    */
static void m_ssl_conn_cl_compl_cl( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
   int        iml1, iml2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_not_valid_dn;             /* check DN                */
   int        iml_len_msg_ssl;              /* length of SSL message   */
   int        iml_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
#ifdef XYZ1
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
#endif
#ifndef B140728
   char       *achl_pfs;                    /* pfs = YES / NO          */
   char       *achl_ssl_tls;                /* SSL / TLS version       */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
#endif
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 512 ];          /* for text cipher         */
#ifndef B140728
   char       byrl_ssl_tls[ 32 ];           /* SSL / TLS version       */
   char       byrl_ineta_server[ LEN_DISP_INETA ];  /* for INETA server */
#endif
#ifdef XYZ1
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_cl called" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p.", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_TRACE1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d.",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
//       for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         for (i = 0; i < (ADSL_SSL_QUERY_INFO->ucc_partner_name_length*2); i= i+2)
         {
//     szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
           szString[j++] = ADSL_SSL_QUERY_INFO->ucrc_partner_name[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
#ifdef DEBUG_100809
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_XYZ1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->adsc_csssl_oper_1 == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS085W Client-Side SSL handshake, but SSL not active" );
     return;
   }
   bol_not_valid_dn = adsg_loconf_1_inuse->boc_csssl_usage_dn;  /* check DN - TRUE if check necessary */
   if (ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc) {  /* ssl handshake complete */
     m_hlnew_printf( HLOG_WARN1, "HWSPS086W Client-Side SSL handshake complete double" );
   }
#ifdef B121009
   iml_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   iml_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (iml_len_cert < 0)
       || (iml_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     iml_len_cert );
     iml_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   iml_len_msg_ssl = 0;                     /* length of SSL message   */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
#ifndef B140728
     achl_pfs = "NO";                       /* pfs = YES / NO          */
     if (adsp_ccb_1->boc_pfs_used) {        /* Was a key exchange with PFS used? */
       achl_pfs = "YES";                    /* pfs = YES / NO          */
     }
     iml_ns_prot = ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 16;  /* SSL / TLS protocol version */
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     achl_ssl_tls = (char *) achrs_ssl_prot[ iml_ns_prot ];  /* SSL / TLS version */
     if (   (iml_ns_prot == 1)
         || (iml_ns_prot == 2)) {
       sprintf( byrl_ssl_tls,
                "%s-V%d.%d",
                achrs_ssl_prot[ iml_ns_prot ],
                (ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 8) & 0XFF,
                ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers & 0XFF );
       achl_ssl_tls = byrl_ssl_tls;         /* SSL / TLS version       */
     }
#endif
#ifdef B140728
     iml_ns_prot = *(AUCL_CONNDATA + 48);
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
#endif
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_mac) / sizeof(achrs_ssl_mac[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
#ifdef B140728
     iml_len_msg_ssl = sprintf( byrlwork_ssl, " - protocol:%s cipher-suite:%s key-exchange-mode:%s"
                                " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
                                achrs_ssl_prot[ iml_ns_prot ],
                                achrs_ssl_ci_prot[ iml_ns_ci_sui ],
                                achrs_ssl_keyexch[ iml_ns_keyexch ],
                                achrs_ssl_ci_alg[ iml_ns_ci_alg ],
                                achrs_ssl_ci_type[ iml_ns_ci_type ],
                                achrs_ssl_mac[ iml_ns_mac ],
                                achrs_ssl_auth[ iml_ns_auth ],
                                achrs_ssl_compr[ iml_ns_compr ] );
#endif
#ifndef B140728
     iml_len_msg_ssl = sprintf( byrlwork_ssl, " - pfs:%s protocol:%s cipher-suite:%s key-exchange-mode:%s"
                                " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
                                achl_pfs,   /* pfs = YES / NO          */
                                achl_ssl_tls,  /* SSL / TLS version    */
                                achrs_ssl_ci_prot[ iml_ns_ci_sui ],
                                achrs_ssl_keyexch[ iml_ns_keyexch ],
                                achrs_ssl_ci_alg[ iml_ns_ci_alg ],
                                achrs_ssl_ci_type[ iml_ns_ci_type ],
                                achrs_ssl_mac[ iml_ns_mac ],
                                achrs_ssl_auth[ iml_ns_auth ],
                                achrs_ssl_compr[ iml_ns_compr ] );
#endif
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
   iml1 = 0;
   if (adsp_ccb_1->achc_fingerprint) {
     iml1 += sprintf( &byrlwork1[iml1], "fingerprint: " );
     iml2 = 0;
     do {
       iml1 += sprintf( &byrlwork1[iml1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + iml2) );

       if (iml2 % 2) byrlwork1[ iml1++ ] = ' ';
       iml2++;                              /* next character          */
     } while (iml2 < DEF_SSL_LEN_FINGERPRINT);
     iml1 += sprintf( &byrlwork1[iml1], "- " );  /* separate following text */
   }
   iml1 += sprintf( &byrlwork1[iml1], "DN (name from certificate): " );
   achl1 = achl2 = &byrlwork1[iml1];        /* name comes here         */
   for (iml1 = 0; iml1 < iml_len_cert; iml1++ ) {
#ifdef B121009
     iml2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ iml1 * 2 ]) );
#endif
     iml2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ iml1 * 2 ]) );
     if (iml2 < 0X0100) {
       *achl1++ = (char) iml2;
     } else {
       *achl1++ = '?';
     }
   }
   *achl1 = 0;                              /* make zero-terminated    */
#if SM_BUGFIX_20170807
#ifndef HL_UNIX
   bol1 = m_cmpi_vx_vx( &iml1, achl2, -1, ied_chs_ascii_850,
          ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name, ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name, ied_chs_ascii_850);

#endif
#ifdef HL_UNIX
   bol1 = m_cmp_vx_vx( &iml1, achl2, -1, ied_chs_ascii_850,
          ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name, ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name, ied_chs_ascii_850);
#endif
#else
   bol1 = TRUE;
#ifndef HL_UNIX
   iml1 = _stricmp( achl2, (char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) );
#endif
#ifdef HL_UNIX
   iml1 = strcasecmp( achl2, (char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) );
#endif
#endif
   if (bol1 == FALSE || iml1) {                              /* strings not equal       */
     strcpy( &byrlwork_ssl[ iml_len_msg_ssl ], " Certificate does not contain valid DNS-name" );
   } else {                                 /* all valid               */
     bol_not_valid_dn = FALSE;              /* check DN successful     */
   }
   achl1 = byrlwork1;

   psussl80:                                /* write message           */
#ifdef B140728
// to-do 30.04.09 KB IPV6 and HTCP
   m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxI GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%s INETA-host=%d.%d.%d.%d - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr)),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 1),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 2),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 3),
                   achl1, byrlwork_ssl );
#endif
#ifndef B140728
   byrl_ineta_server[ 0 ] = 0;              /* for INETA server        */
   adsl_soa_w1 = NULL;                      /* sockaddr temporary value */
   switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
#ifndef HL_UNIX
       adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->dcl_tcp_r_s.dsc_soa;  /* sockaddr from class to receive server */
#endif
#ifdef HL_UNIX
       adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->dsc_tc1_server.dsc_soa_conn;  /* sockaddr from class to receive server */
#endif
       break;
#ifdef D_INCL_HOB_TUN
      case ied_servcotype_htun:             /* HOB-TUN                 */
        if (ADSL_CONN1_G->adsc_ineta_raws_1->boc_with_user) {  /* structure with user */
          adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->dsc_soa_htcp_server;  /* address information for connected */
        }
        break;
#endif
   }
   if (adsl_soa_w1) {                       /* sockaddr temporary value */
     getnameinfo( adsl_soa_w1, sizeof(struct sockaddr_storage),
                  byrl_ineta_server, sizeof(byrl_ineta_server),
                  0, 0, NI_NUMERICHOST );
   }
   if (byrl_ineta_server[ 0 ] == 0) {       /* for INETA server        */
     strcpy( byrl_ineta_server, "???" );
   }
#if SM_BUGFIX_20170807
   m_hlnew_printf( HLOG_INFO1, "HWSPS084I GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%.*s INETA-host=%s - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_server_conf_1->imc_len_dns_name,
                   ADSL_CONN1_G->adsc_server_conf_1->achc_dns_name,
                   byrl_ineta_server,
                   achl1, byrlwork_ssl );
#else
   m_hlnew_printf( HLOG_INFO1, "HWSPS084I GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%s INETA-host=%s - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                   byrl_ineta_server,
                   achl1, byrlwork_ssl );
#endif // SM_BUGFIX_20170807
#endif
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc = TRUE;  /* ssl handshake complete */
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_error = bol_not_valid_dn;  /* if DNS name wrong, error occured */
#ifndef B100731
#ifndef HL_UNIX
   if (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_wait_csssl) {  /* wait for client-side SSL */
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_start_server_2;  /* start connection to server part two */
   }
#endif
#ifdef HL_UNIX
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_wait_csssl) {  /* wait for client-side SSL */
     ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_2;  /* start connection to server part two */
   }
#endif
#endif
#undef AUCL_CONNDATA
#undef hssl_QueryInfo
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_ssl_conn_cl_compl_cl()                                      */
#endif
#endif

/** OCSP start                                                         */
static int m_ocsp_start( void * vpp_userfld, struct dsd_hl_ocsp_d_1 *adsp_hlocspd1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_errno;                    /* error returned          */
   int        iml1;                         /* working variable        */
   time_t     dsl_time_1;                   /* for time                */
#ifdef XYZ1
//--- old ---
   int        iml_rc;                       /* return code             */
   int        iml_ind_connect;              /* index of connect        */
   char       *achl1;                       /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   socklen_t  iml_namelen;                  /* length of name          */
   socklen_t  iml_bindlen;                  /* length for bind         */
//--- new ---
#endif
   struct dsd_ocspint_1 *adsl_ocspint_1_1;  /* internal OCSP structure */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
#ifdef XYZ1
//--- old ---
   struct sockaddr *adsl_soa_bind;          /* address information for bind */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */
   char       chrl_ineta_server[ LEN_DISP_INETA ];  /* for INETA server */
#endif

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#define ADSL_OCSPEXT_1 ((struct dsd_ocspext_1 *) (adsp_hlocspd1 + 1))

//#ifdef TRACEHL1
#ifdef TRACEHL_OCSP_01
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_start() called vpp_userfld=%p adsp_hlocspd1=%p",
                   vpp_userfld, adsp_hlocspd1 );
#ifdef B120212
   {
     DSD_CONN_G *adsh_clconn1_1;
     adsh_clconn1_1 = aconn1a;              /* get anchor              */
     while (adsh_clconn1_1) {               /* loop over all conn      */
       if (adsh_clconn1_1 == ADSL_CONN1_G) break;
       adsh_clconn1_1 = adsh_clconn1_1->getnext();  /* get next in chain */
     }
     if (adsh_clconn1_1 == NULL) {          /* connection not found    */
       m_hlnew_printf( HLOG_TRACE1, "m_ocsp_start() called invalid connection - not in chain" );
     }
   }
#endif
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;
   while (adsl_auxf_1_1) {
     if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_ocsp) {
       m_hlnew_printf( HLOG_TRACE1, "m_ocsp_start() called and struct dsd_ocspint_1 already defined" );
     }
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
   }
#endif
#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_TRACE1, "m_ocsp_start l%05d adsp_hlocspd1=%p <ADSL_OCSPEXT_1->inc_time_retry=%p>-->%d/0X%08X",
                   __LINE__, adsp_hlocspd1, &ADSL_OCSPEXT_1->inc_time_retry, ADSL_OCSPEXT_1->inc_time_retry, ADSL_OCSPEXT_1->inc_time_retry );
#endif
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPST1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_start() vpp_userfld=%p adsp_hlocspd1=%p ADSL_OCSPEXT_1->inc_time_retry=%d.",
                  __LINE__, vpp_userfld, adsp_hlocspd1, ADSL_OCSPEXT_1->inc_time_retry );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (ADSL_OCSPEXT_1->inc_time_retry) {    /* time when to retry      */
     time( &dsl_time_1 );                   /* get current time        */
     if (ADSL_OCSPEXT_1->inc_time_retry > dsl_time_1) {
       if ((ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) == 0) {  /* do not generate WSP trace record */
         return -1;                         /* return error            */
       }
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPST2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_start() return because time retry set and not elapsed",
                    __LINE__ );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
       return -1;                           /* return error            */
     }
     ADSL_OCSPEXT_1->inc_time_retry = 0;    /* time elapsed - try again */
   }
   adsl_ocspint_1_1 = (struct dsd_ocspint_1 *) malloc( sizeof(struct dsd_ocspint_1) );
#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_TRACE1, "m_ocsp_start l%05d adsp_hlocspd1=%p MALLOC->adsl_ocspint_1_1=%p.",
                   __LINE__, adsp_hlocspd1, adsl_ocspint_1_1 );
#endif
   adsl_ocspint_1_1->dsc_auxf_1.iec_auxf_def = ied_auxf_ocsp;
   adsl_ocspint_1_1->adsc_ocsp_def_1 = adsp_hlocspd1;  /* save addr definition */
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   bol_rc = m_tcpsync_connect( &iml_errno,
                               &adsl_ocspint_1_1->dsc_tcpsync_1,
                               &ADSL_OCSPEXT_1->dsc_bind_multih,
                               ADSL_OCSPEXT_1->adsc_server_ineta,
                               ADSL_OCSPEXT_1->imc_port );
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     if (bol_rc) {                          /* connect succeeded       */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPST3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_start() connect succeeded adsl_ocspint_1_1=%p.",
                    __LINE__, adsl_ocspint_1_1 );
     } else {                               /* connect failed          */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPST4", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_start() connect failed %d.",
                    __LINE__, iml_errno );
     }
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bol_rc) {                            /* connect succeeded       */
     adsl_ocspint_1_1->dsc_auxf_1.adsc_next = ADSL_CONN1_G->adsc_auxf_1;
     ADSL_CONN1_G->adsc_auxf_1 = &adsl_ocspint_1_1->dsc_auxf_1;
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
     return 0;                              /* return success          */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPOCSP001W GATE=%(ux)s SNO=%08d INETA=%s OCSP connect returned error %d.",
                   m_clconn1_gatename( ADSL_CONN1_G ),
                   m_clconn1_sno( ADSL_CONN1_G ),
                   m_clconn1_chrc_ineta( ADSL_CONN1_G ),
                   iml_errno );
   free( adsl_ocspint_1_1 );                /* free memory again       */
   if (ADSL_OCSPEXT_1->inc_time_retry) {    /* error already set       */
     m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
     return -1;                             /* return error            */
   }
   time( &dsl_time_1 );                     /* get current time        */
   iml1 = ADSL_OCSPEXT_1->inc_wait_retry;
   if (iml1 == 0) iml1 = DEF_OCSP_RETRY;
   ADSL_OCSPEXT_1->inc_time_retry = dsl_time_1 + iml1;
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   return -1;
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#undef ADSL_OCSPEXT_1
} /* end m_ocsp_start()                                                */

/** OCSP send                                                          */
static int m_ocsp_send( void * vpp_userfld, char *achp_buf, int imp_len ) {
   int        iml1;                         /* working variable        */
   int        iml_errno;                    /* error returned          */
#ifdef XYZ1
   int        iml_offset;                   /* offset data to send     */
#endif
   int        iml_rc;                       /* return code             */
#ifdef XYZ1
   time_t     dsl_time_1;                   /* for time                */
#endif
   char       *achl_w1;                     /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

#ifdef B080407
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_send() called 1 vpp_userfld=%p", vpp_userfld );
   {
     class clconn1 *adsh_clconn1_1;
     adsh_clconn1_1 = aconn1a;              /* get anchor              */
     while (adsh_clconn1_1) {               /* loop over all conn      */
       if (adsh_clconn1_1 == ADSL_CONN1_G) break;
       adsh_clconn1_1 = adsh_clconn1_1->getnext();  /* get next in chain */
     }
     if (adsh_clconn1_1 == NULL) {          /* connection not found    */
       m_hlnew_printf( HLOG_XYZ1, "m_ocsp_send() called invalid connection - not in chain" );
     }
   }
#endif
#endif
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;
   while (adsl_auxf_1_1) {
     if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_ocsp) break;
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_send() called 2 vpp_userfld=%p adsl_auxf_1_1=%p",
                   vpp_userfld, adsl_auxf_1_1 );
#endif
   if (adsl_auxf_1_1 == NULL) {
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPSE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_send( vpp_userfld=%p , ... ) failed because OCSP not started",
                    __LINE__, vpp_userfld );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPOCSP010W GATE=%(ux)s SNO=%08d INETA=%s m_ocsp_send() OCSP not started",
                     m_clconn1_gatename( ADSL_CONN1_G ),
                     m_clconn1_sno( ADSL_CONN1_G ),
                     m_clconn1_chrc_ineta( ADSL_CONN1_G ) );
     return -1;
   }
#define ADSL_OCSPINT_1 ((struct dsd_ocspint_1 *) ((char *) adsl_auxf_1_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) ))
#define ADSL_OCSPEXT_1 ((struct dsd_ocspext_1 *) (ADSL_OCSPINT_1->adsc_ocsp_def_1 + 1))
   iml1 = ADSL_OCSPEXT_1->inc_wait_retry;
   if (iml1 == 0) iml1 = DEF_OCSP_RETRY;
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   iml_rc = m_tcpsync_send_single( &iml_errno,
                                   &ADSL_OCSPINT_1->dsc_tcpsync_1,
                                   achp_buf,
                                   imp_len,
                                   iml1 );
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPSE2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_send( vpp_userfld=%p , ... ) send length %d/0X%X returned %d.",
                  __LINE__, vpp_userfld, imp_len, imp_len, iml_rc );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + ADSL_WTR_G1->imc_length + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
#define ACHL_WSP_T_DATA ((char *) (ADSL_WTR_G2 + 1))  /* here starts content */
     ADSL_WTR_G2->achc_content = ACHL_WSP_T_DATA;  /* content of text / data */
     ADSL_WTR_G2->imc_length = imp_len;     /* length of text / data   */
     memcpy( ACHL_WSP_T_DATA, achp_buf, imp_len );
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
#undef ACHL_WSP_T_DATA
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   if (iml_rc == imp_len) return iml_rc;    /* returned length sent    */
   m_hlnew_printf( HLOG_WARN1, "HWSPOCSP002W GATE=%(ux)s SNO=%08d INETA=%s OCSP send returned error %d %d.",
                   m_clconn1_gatename( ADSL_CONN1_G ),
                   m_clconn1_sno( ADSL_CONN1_G ),
                   m_clconn1_chrc_ineta( ADSL_CONN1_G ),
                   iml_rc, iml_errno );
   return -1;
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#undef ADSL_OCSPINT_1
#undef ADSL_OCSPEXT_1
} /* end m_ocsp_send()                                                 */

/** OCSP receive                                                       */
static struct dsd_hl_ocsp_rec * m_ocsp_recv( void * vpp_userfld ) {
   int        iml_rc;                       /* return code             */
   int        iml_errno;                    /* error returned          */
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_r;        /* for receive             */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

#ifdef B080407
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_rec() called 1 vpp_userfld=%p", vpp_userfld );
   {
     class clconn1 *adsh_clconn1_1;
     adsh_clconn1_1 = aconn1a;              /* get anchor              */
     while (adsh_clconn1_1) {               /* loop over all conn      */
       if (adsh_clconn1_1 == ADSL_CONN1_G) break;
       adsh_clconn1_1 = adsh_clconn1_1->getnext();  /* get next in chain */
     }
     if (adsh_clconn1_1 == NULL) {          /* connection not found    */
       m_hlnew_printf( HLOG_XYZ1, "m_ocsp_rec() called invalid connection - not in chain" );
     }
   }
#endif
#endif
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;
   while (adsl_auxf_1_1) {
     if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_ocsp) break;
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
   }
//#ifdef TRACEHL1
#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_rec() called 2 vpp_userfld=%p adsl_auxf_1_1=%p.",
                   vpp_userfld, adsl_auxf_1_1 );
#endif
   if (adsl_auxf_1_1 == NULL) {
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPRE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_recv( vpp_userfld=%p ) failed because OCSP not started",
                    __LINE__, vpp_userfld );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPOCSP020W GATE=%(ux)s SNO=%08d INETA=%s m_ocsp_recv() OCSP not started",
                     m_clconn1_gatename( ADSL_CONN1_G ),
                     m_clconn1_sno( ADSL_CONN1_G ),
                     m_clconn1_chrc_ineta( ADSL_CONN1_G ) );
     return NULL;
   }
#define ADSL_OCSPINT_1 ((struct dsd_ocspint_1 *) ((char *) adsl_auxf_1_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) ))
#ifndef B050630
#define ADSL_OCSPEXT_1 ((struct dsd_ocspext_1 *) (ADSL_OCSPINT_1->adsc_ocsp_def_1 + 1))
#else
#define ADSL_OCSPEXT_1 ((struct dsd_ocspext_1 *) (ADSL_OCSPINT_1 + 1))
#endif
#ifdef TRACEHL_050630
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_recv l%05d adsl_auxf_1_1=%p ADSL_OCSPEXT_1=%p",
                   __LINE__, adsl_auxf_1_1, ADSL_OCSPEXT_1 );
#endif
   adsl_auxf_1_r = (struct dsd_auxf_1 *) m_proc_alloc();
   adsl_auxf_1_r->iec_auxf_def = ied_auxf_defstor;  /* predefined storage */
   iml1 = ADSL_OCSPEXT_1->inc_wait_retry;
   if (iml1 == 0) iml1 = DEF_OCSP_RETRY;
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPRE2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_recv( vpp_userfld=%p ) start receiving",
                  __LINE__, vpp_userfld );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#define ADSL_REC_1 ((struct dsd_hl_ocsp_rec *) (adsl_auxf_1_r + 1))
   ADSL_REC_1->inp_data_len = m_tcpsync_recv( &iml_errno,
                                              &ADSL_OCSPINT_1->dsc_tcpsync_1,
                                              (char *) (ADSL_REC_1 + 1),
                                              LEN_TCP_RECV
                                                - sizeof(struct dsd_auxf_1)
                                                - sizeof(struct dsd_hl_ocsp_rec),
                                              iml1 );
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPRE3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_recv( vpp_userfld=%p ) receive returned %d/0X%X iml_errno=%d.",
                  __LINE__, vpp_userfld, ADSL_REC_1->inp_data_len, ADSL_REC_1->inp_data_len, iml_errno );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (ADSL_REC_1->inp_data_len > 0) {    /* data received           */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + ADSL_WTR_G1->imc_length + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
#define ACHL_WSP_T_DATA ((char *) (ADSL_WTR_G2 + 1))  /* here starts content */
       ADSL_WTR_G2->achc_content = ACHL_WSP_T_DATA;  /* content of text / data */
       /* attention - data received may to too long for trace buffer   */
       iml1 = ((char *) adsl_wt1_w1 + LEN_TCP_RECV) - achl_w1;
       if (iml1 > ADSL_REC_1->inp_data_len) iml1 = ADSL_REC_1->inp_data_len;
       ADSL_WTR_G2->imc_length = iml1;      /* length of text / data   */
       memcpy( ACHL_WSP_T_DATA, ADSL_REC_1 + 1, iml1 );
       ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain       */
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
#undef ACHL_WSP_T_DATA
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (ADSL_REC_1->inp_data_len > 0) {
     adsl_auxf_1_r->adsc_next = ADSL_CONN1_G->adsc_auxf_1;
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_r;
   }
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   if (ADSL_REC_1->inp_data_len > 0) return ADSL_REC_1;
   m_hlnew_printf( HLOG_WARN1, "HWSPOCSP003W GATE=%(ux)s SNO=%08d INETA=%s OCSP receive returned error %d %d.",
                   m_clconn1_gatename( ADSL_CONN1_G ),
                   m_clconn1_sno( ADSL_CONN1_G ),
                   m_clconn1_chrc_ineta( ADSL_CONN1_G ),
                   ADSL_REC_1->inp_data_len, iml_errno );
   m_proc_free( adsl_auxf_1_r );            /* free data again         */
   return NULL;
#undef ADSL_REC_1
#undef ADSL_OCSPINT_1
#undef ADSL_OCSPEXT_1
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_ocsp_recv()                                                 */

/** OCSP stop                                                          */
static void m_ocsp_stop( void * vpp_userfld ) {
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */

#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_TRACE1, "m_ocsp_stop l%05d called m_ocsp_stop( %p )",
                   __LINE__, vpp_userfld );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef B080407
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_stop() called 1 vpp_userfld=%p", vpp_userfld );
   {
     class clconn1 *adsh_clconn1_1;
     adsh_clconn1_1 = aconn1a;              /* get anchor              */
     while (adsh_clconn1_1) {               /* loop over all conn      */
       if (adsh_clconn1_1 == ADSL_CONN1_G) break;
       adsh_clconn1_1 = adsh_clconn1_1->getnext();  /* get next in chain */
     }
     if (adsh_clconn1_1 == NULL) {          /* connection not found    */
       m_hlnew_printf( HLOG_XYZ1, "m_ocsp_stop() called invalid connection - not in chain" );
     }
   }
#endif
#endif
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;
   adsl_auxf_1_2 = NULL;                    /* no previous yet         */
   while (adsl_auxf_1_1) {
     if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_ocsp) break;
     adsl_auxf_1_2 = adsl_auxf_1_1;         /* save previous           */
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
   }
//#ifdef TRACEHL1
#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_XYZ1, "m_ocsp_stop() called 2 vpp_userfld=%p adsl_auxf_1_1=%p",
                   vpp_userfld, adsl_auxf_1_1 );
#endif
   if (adsl_auxf_1_1 == NULL) {
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPST1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length              /* length of text / data   */
         = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_stop( vpp_userfld=%p ) failed because OCSP not started",
                    __LINE__, vpp_userfld );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPOCSP030W GATE=%(ux)s SNO=%08d INETA=%s m_ocsp_stop() OCSP not started",
                     m_clconn1_gatename( ADSL_CONN1_G ),
                     m_clconn1_sno( ADSL_CONN1_G ),
                     m_clconn1_chrc_ineta( ADSL_CONN1_G ) );
     return;
   }
#define ADSL_OCSPINT_1 ((struct dsd_ocspint_1 *) ((char *) adsl_auxf_1_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) ))
#define ADSL_OCSPEXT_1 ((struct dsd_ocspext_1 *) (ADSL_OCSPINT_1->adsc_ocsp_def_1 + 1))
   if (adsl_auxf_1_2 == NULL) {             /* is first in chain       */
     ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_1->adsc_next;
   } else {                                 /* in middle of chain      */
     adsl_auxf_1_2->adsc_next = adsl_auxf_1_1->adsc_next;
   }
   m_ocsp_cleanup( ADSL_CONN1_G, adsl_auxf_1_1 );
#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_TRACE1, "m_ocsp_stop l%05d call free( %p ) offset %d.",
                   __LINE__,
                   (char *) adsl_auxf_1_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ),
                   offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) );
#endif
   free( (char *) adsl_auxf_1_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) );
   if ((ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_OCSP) == 0) return;  /* do not generate WSP trace record */
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPSTO", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->imc_length                  /* length of text / data   */
     = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_stop( vpp_userfld=%p ) returns",
                __LINE__, vpp_userfld );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) (ADSL_WTR_G1 + 1);
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return;
#undef ADSL_OCSPEXT_1
#undef ADSL_OCSPINT_1
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_ocsp_stop()                                                 */

/**
  cleanup OCSP when no more needed, or when there was an error
*/
static void m_ocsp_cleanup( DSD_CONN_G *adsp_clconn1, struct dsd_auxf_1 *adsp_auxf_1 ) {
   int        iml_rc;                       /* return code             */
   int        iml_errno;                    /* error returned          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */

#ifdef TRACEHL_OCSP_01
   m_hlnew_printf( HLOG_TRACE1, "m_ocsp_cleanup l%05d called m_ocsp_cleanup( %p , %p )",
                   __LINE__, adsp_clconn1, adsp_auxf_1 );
#endif
#define ADSL_OCSPINT_1 ((struct dsd_ocspint_1 *) ((char *) adsp_auxf_1 - offsetof( struct dsd_ocspint_1, dsc_auxf_1 ) ))
   iml_rc = m_tcpsync_close( &iml_errno,
                             &ADSL_OCSPINT_1->dsc_tcpsync_1 );
   if (adsp_clconn1->imc_trace_level & HL_WT_SESS_SSL_OCSP) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SOCSPCUP", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_clconn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length                /* length of text / data   */
       = sprintf( (char *) (ADSL_WTR_G1 + 1), "l%05d m_ocsp_cleanup( adsp_clconn1=%p , adsp_auxf_1=%p ) m_tcpsync_close() returned %d iml_errno=%d.",
                  __LINE__, adsp_clconn1, adsp_auxf_1, iml_rc, iml_errno );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (iml_rc == 0) return;
   m_hlnew_printf( HLOG_WARN1, "HWSPOCSP004W GATE=%(ux)s SNO=%08d INETA=%s OCSP cleanup returned error %d %d.",
                   m_clconn1_gatename( adsp_clconn1 ),
                   m_clconn1_sno( adsp_clconn1 ),
                   m_clconn1_chrc_ineta( adsp_clconn1 ),
                   iml_rc, iml_errno );
#undef ADSL_OCSPINT_1
} /* end m_ocsp_cleanup()                                              */

static inline void m_conn1_set_timer_1( DSD_CONN_G *adsp_clconn1 ) {
   HL_LONGLONG ill_w1;                      /* working variables       */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */

   adsl_auxf_1_w1 = adsp_clconn1->adsc_aux_timer_ch;  /* get chain auxiliary timer */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
     if (ADSL_AUX_T->boc_expired == FALSE) break;  /* timer has not yet expired */
#undef ADSL_AUX_T
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (   (adsl_auxf_1_w1 == NULL)          /* no auxiliary timer entry not found */
       && (adsp_clconn1->ilc_timeout == 0)) {  /* no timeout           */
     if (adsp_clconn1->dsc_timer.vpc_chain_2) {  /* timer still set    */
       m_time_rel( &adsp_clconn1->dsc_timer );  /* release timer       */
     }
   } else {                                 /* needs timer             */
     ill_w1 = adsp_clconn1->ilc_timeout;    /* get timeout             */
     if (   (adsl_auxf_1_w1)                /* auxiliary timer set     */
         && (   (ill_w1 == 0)               /* timer not yet set       */
             || (ill_w1 > ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime))) {
       ill_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     if (   (ill_w1 != adsp_clconn1->dsc_timer.ilcendtime)  /* different end-time */
         || (adsp_clconn1->dsc_timer.vpc_chain_2 == NULL)) {  /* timer not set */
       if (adsp_clconn1->dsc_timer.vpc_chain_2) {  /* timer still set  */
         m_time_rel( &adsp_clconn1->dsc_timer );  /* release timer     */
       }
       adsp_clconn1->dsc_timer.ilcendtime = ill_w1;  /* set new end-time */
       m_time_set( &adsp_clconn1->dsc_timer, TRUE );  /* set new timer */
     }
   }
} /* end m_conn1_set_timer_1()                                         */

#undef DSD_CONN_G

