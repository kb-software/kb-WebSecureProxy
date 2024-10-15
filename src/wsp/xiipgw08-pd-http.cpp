/**
  xiipgw08-pd-http.cpp
  Subroutine to process plain HTTP data from client - without SSL

  26.02.13 KB
*/
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif
/**
*  see HOBTEXT SOFTWARE.HLJWT.RADIUS01
*/

/** process plain HTTP input from client                               */
static void m_pd_plain_http( struct dsd_pd_work *adsp_pd_work ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1;                     /* working variable        */
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_pd_http_ctrl *adsl_pd_http_ctrl;  /* process data HTTP control */
   struct dsd_phl_conf_1 *adsl_phl_conf_1;  /* plain-HTTP-library configuration */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working variable       */
#ifdef XYZ1
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7, iml8;  /* working variables */
   int        iml_w1, iml_w2;               /* working variables       */
   int        iml_save_2;                   /* so many characters after last checkpoint */
   int        iml_save_max;                 /* maximum number of characters after last checkpoint */
   int        iml_no_servent;               /* number of server entries */
   int        iml_user_servent;             /* no server entries user  */
   int        iml_ind_servent;              /* index of server entries */
   int        iml_serv_no_sdh;              /* number of server-data-hooks - for position send data to server */
#ifdef OLD_1112
   int        iml1, iml2;                   /* working variables       */
   int        iml_rc;                       /* return code             */
   int        iml_len_cert;                 /* length of certificate n */
#endif
   BOOL       bol1;                         /* working variable        */
#ifdef OLD_1112
   BOOL       bol_http;                     /* try HTTP                */
#endif
   char       chl1;                         /* working variable        */
   enum ied_scp_def iel_scp_def;            /* server-conf protocol    */
#ifdef OLD_1112
   ied_at_function iel_function;            /* authentication function */
   ied_at_return iel_return;                /* return authentication   */
   ied_scp_def iel_scp_def;                 /* server-conf protocol    */
   char       *achl_w1;                     /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   void *     avol_client_netaddr;          /* address net-addr        */
   void *     alout;                        /* address output subroutine */
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   struct dsd_hl_wspat2_1 dsl_hlwspat2;     /* WSPAT2 call parameters  */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_func;                   /* function alpha          */
   struct dsd_wsp_auth_1 *adsl_wa1;         /* structure for authentication */
   struct dsd_wsp_auth_normal *adsl_wan;    /* normal authentication   */
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
   struct dsd_gather_i_1 *adsl_gai1_client_input;  /* gather start input from client */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_client;  /* output data to client */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_server;  /* output data to server */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working variable       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_save_2;                 /* save pointer on characters */
   unsigned short int *awcl1;               /* working variable        */
#ifdef OLD_1112
   struct dsd_sdh_control_1 *adsl_sdhc1_work_frse;  /* current work area */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
#ifndef B100831
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working variable       */
#endif
   struct dsd_hl_wspat2_1 dsl_wspat3_1;     /* parameters HOBWSPAT3    */
#endif
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */
   struct dsd_conn_pttd_thr *adsl_cpttdt;   /* connect PTTD thread     */
#ifdef OLD_1112
   char       chrl_work1[8];                /* work area               */
#endif
   struct dsd_wspat3_1 dsl_wspat3_1;        /* HOB Authentication Library V3 - 1 */
   enum ied_chid_ret iel_chid_ret;          /* returned authenticated  */
   enum ied_set_def iel_set_def;            /* server entry type       */
   struct dsd_unicode_string dsl_ucs_userid;  /* for userid            */
   struct dsd_unicode_string dsl_ucs_password;  /* for password        */
   struct dsd_unicode_string dsl_ucs_w1;    /* temporary field         */
   char       chrl_work1[ 256 ];            /* work area               */
#endif
   struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
   struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
   struct dsd_hl_aux_epoch_1 dsl_epoch;     /* parameters for subroutine */
   char       chrl_http_url_path[ LEN_HTTP_PATH_CHECK ];  /* HTTP path to check */
#ifndef OLD_1305
   char       chrl_hostname[ 512 ];         /* HTTP Host:              */
   struct dsd_aux_get_domain_info_1 dsl_gdi1;  /* retrieve domain-information of connection - gate */
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   adsl_conn1_l = ADSL_CONN1_G;             /* current connection      */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_plain_http() l%05d started adsl_conn1_l=0X%p adsp_pd_work=0X%p",
                   __LINE__, adsl_conn1_l, adsp_pd_work );
#endif
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_phl;  /* plain-HTTP-library */
   ADSL_AUX_CF1->ac_sdh = NULL;             /* current Server-Data-Hook */
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_phl;  /* plain-HTTP-library */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr = NULL;  /* no component          */
   adsp_pd_work->iec_pdwr = ied_pdwr_cont;  /* continue receiving      */
   if (adsl_conn1_l->adsc_pd_http_ctrl) {   /* process data HTTP control */
     adsl_pd_http_ctrl = adsl_conn1_l->adsc_pd_http_ctrl;  /* process data HTTP control */
     if (adsl_pd_http_ctrl->adsc_phl_conf_1) {  /* plain-HTTP-library configuration */
       adsl_phl_conf_1 = adsl_pd_http_ctrl->adsc_phl_conf_1;  /* plain-HTTP-library configuration */
       goto p_phl_60;                       /* next call plain-HTTP-library */
     }
   }

   /* check if SSL input                                               */
   iml1 = sizeof(ucrs_http_ssl_01);         /* length compare SSL input data */
   achl_w1 = (char *) ucrs_http_ssl_01;     /* area to compare with    */
   adsl_gai1_w1 = adsl_conn1_l->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* get input from client */
   while (adsl_gai1_w1) {                   /* loop over input data    */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml2 > 0) {                        /* data found to compare   */
       if (iml2 > iml1) iml2 = iml1;        /* only part to compare    */
       if (memcmp( adsl_gai1_w1->achc_ginp_cur, achl_w1, iml2 )) {
         goto p_start_20;                   /* in not SSL              */
       }
       achl_w1 += iml2;                     /* this part compared      */
       iml1 -= iml2;                        /* compare remaining to compare */
       if (iml1 <= 0) {                     /* found SSL               */
         adsp_pd_work->iec_pdwr = ied_pdwr_ssl;  /* found continue SSL */
         return;
       }
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   return;                                  /* not enough data         */

   p_start_20:                              /* is not SSL              */
   memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */
#ifdef XYZ1
#ifdef DEF_STORAGE_CONTAINER
   dsl_chhs1.ac_stor_1 = al_stor_1;
#endif
#endif
   dsl_chhs1.adsc_gai1_in = adsl_conn1_l->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* get input from client */
   dsl_chhs1.achc_url_path = chrl_http_url_path;  /* memory for URL path */
   dsl_chhs1.imc_length_url_path_buffer = sizeof(chrl_http_url_path);  /* length memory for URL path */
#ifndef OLD_1305
   dsl_chhs1.achc_hostname = chrl_hostname;  /* memory for hostname    */
   dsl_chhs1.imc_length_hostname_buffer = sizeof(chrl_hostname);  /* length memory for hostname */
#endif
   bol_rc = m_proc_http_header_server( &dss_phhs1_check_01,  /* HTTP processing at server */
                                       &dsl_chhs1,  /* call HTTP processing at server */
                                       &dsl_hhs1 );  /* HTTP processing at server */
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPH000W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP check HTTP header returned error",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   if (dsl_hhs1.imc_length_http_header == 0) {  /* length of HTTP header */
     return;                                /* wait for more data      */
   }
   adsl_pd_http_ctrl = NULL;             ;  /* process data HTTP control */
   if (adsl_conn1_l->adsc_gate1->imc_no_phl == 0) {  /* number of plain-HTTP-libraries */
     goto p_redir_00;                       /* check redirect          */
   }
   iml1 = adsl_conn1_l->adsc_gate1->imc_no_phl;  /* number of plain-HTTP-libraries */
   adsl_pd_http_ctrl = (struct dsd_pd_http_ctrl *) malloc( sizeof(struct dsd_pd_http_ctrl) );  /* process data HTTP control */
   iml2 = 0;                                /* index of plain-HTTP-libraries */
   adsl_phl_conf_1 = adsl_conn1_l->adsc_gate1->adsc_phl_conf_1;  /* first plain-HTTP-library configuration */

   p_phl_20:                                /* check plain-HTTP-library */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr = adsl_pd_http_ctrl;  /* component plain-HTTP-library */
   memset( &adsl_pd_http_ctrl->dsc_phl_call_1, 0, sizeof(struct dsd_phl_call_1) );  /* plain-HTTP-library Call */
   adsl_pd_http_ctrl->dsc_phl_call_1.adsc_gather_i_1_in = adsl_conn1_l->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* input data */
   adsl_pd_http_ctrl->dsc_phl_call_1.achc_url_path = chrl_http_url_path;  /* address memory of URL path */
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_length_url_path = dsl_hhs1.imc_length_url_path;  /* length of URL path */
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_stored_url_path = dsl_hhs1.imc_stored_url_path;  /* stored part of URL path */
   adsl_pd_http_ctrl->dsc_phl_call_1.amc_aux = &m_cdaux;  /* subroutine */
   adsl_pd_http_ctrl->dsc_phl_call_1.vpc_userfld = ADSL_AUX_CF1;  /* auxiliary control structure */
   adsl_pd_http_ctrl->dsc_phl_call_1.ac_conf = adsl_phl_conf_1->ac_conf;  /* data from configuration */
   adsl_phl_conf_1->adsc_ext_lib1->amc_phl_entry( &adsl_pd_http_ctrl->dsc_phl_call_1 );  /* entry for plain-HTTP-library */
   if (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_NORMAL) {  /* o.k. returned */
     goto p_phl_40;                         /* valid plain-HTTP-library found */
   }
   if (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return != DEF_IRET_OTHER_TARGET) {  /* not return because of other target */
// to-do 20.03.13 KB
     m_hlnew_printf( HLOG_WARN1, "HWSPH010W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP call plain-HTTP-library returned error %d.",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta,
                     adsl_pd_http_ctrl->dsc_phl_call_1.imc_return );
   }
   iml2++;                                  /* index of plain-HTTP-libraries */
   adsl_phl_conf_1++;                       /* next plain-HTTP-library configuration */
   if (iml2 < iml1) {                       /* more plain-HTTP-library to check */
     goto p_phl_20;                         /* check plain-HTTP-library */
   }
   free( adsl_pd_http_ctrl );               /* free memory             */
   goto p_redir_00;                         /* check redirect          */

   p_phl_40:                                /* valid plain-HTTP-library found */
#ifndef HL_UNIX
   adsl_conn1_l->iec_st_cls = clconn1::ied_cls_normal_http;  /* process normal HTTP */
#else
   adsl_conn1_l->iec_st_cls = ied_cls_normal_http;  /* process normal HTTP */
#endif
   adsl_conn1_l->adsc_pd_http_ctrl = adsl_pd_http_ctrl;  /* process data HTTP control */
   adsl_pd_http_ctrl->adsc_phl_conf_1 = adsl_phl_conf_1;  /* plain-HTTP-library configuration */
   adsl_pd_http_ctrl->dsc_phl_call_1.achc_url_path = NULL;  /* address memory of URL path */
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_length_url_path = 0;  /* length of URL path */
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_stored_url_path = 0;  /* stored part of URL path */

   p_phl_60:                                /* next call plain-HTTP-library */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr = adsl_pd_http_ctrl;  /* component plain-HTTP-library */
   adsl_pd_http_ctrl->dsc_phl_call_1.vpc_userfld = ADSL_AUX_CF1;  /* auxiliary control structure */
   ADSL_AUX_CF1->adsc_sdhc1_chain = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_01
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_next = NULL;  /* is only element */
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_usage_count = 0;  /* clear usage count */
   adsl_pd_http_ctrl->dsc_phl_call_1.achc_work_area = (char *) (ADSL_AUX_CF1->adsc_sdhc1_chain + 1);
   adsl_pd_http_ctrl->dsc_phl_call_1.inc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
   adsl_pd_http_ctrl->dsc_phl_call_1.adsc_gather_i_1_in = adsl_conn1_l->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* input data */
   adsl_pd_http_ctrl->dsc_phl_call_1.adsc_gather_i_1_out = NULL;  /* no output data */
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_signal = 0;  /* clear signal  */
   if (adsl_conn1_l->boc_signal_set) {      /* signal for component set */
     adsl_pd_http_ctrl->dsc_phl_call_1.imc_signal = m_ret_signal( ADSL_AUX_CF1 );  /* search signal */
   }
   adsl_pd_http_ctrl->dsc_phl_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
   adsl_phl_conf_1->adsc_ext_lib1->amc_phl_entry( &adsl_pd_http_ctrl->dsc_phl_call_1 );  /* entry for plain-HTTP-library */
#ifdef B130315
   if (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_NORMAL) {  /* o.k. returned */
//   goto p_phl_40;                         /* valid plain-HTTP-library found */
   }
#endif
   if (adsl_pd_http_ctrl->dsc_phl_call_1.adsc_gather_i_1_out == NULL) {  /* no output data */
     do {                                   /* loop to free work areas */
      adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
      ADSL_AUX_CF1->adsc_sdhc1_chain = adsl_sdhc1_w1->adsc_next;
      free( adsl_sdhc1_w1 );                /* free memory - previous work area */
     } while (ADSL_AUX_CF1->adsc_sdhc1_chain);
#ifdef B130602
     if (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_NORMAL) {  /* o.k. returned */
       return;                              /* nothing more to do      */
     }
#endif
// to-do 15.03.13 KB
     goto p_phl_80;                         /* return from plain-HTTP-library */
   }
   adsl_gai1_w1 = adsl_pd_http_ctrl->dsc_phl_call_1.adsc_gather_i_1_out;  /* get chain to send */
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;
   adsl_conn1_l->inc_c_ns_send_c++;         /* count send client       */
   do {                                     /* loop over data to send to client */
     adsl_conn1_l->ilc_d_ns_send_c += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
#ifndef HL_UNIX
   adsl_conn1_l->dcl_tcp_r_c.m_send_gather( adsl_sdhc1_w1, FALSE );
#else
   m_send_clse_tcp_1( adsl_conn1_l, &adsl_conn1_l->dsc_tc1_client, adsl_sdhc1_w1, FALSE );
#endif

   p_phl_80:                                /* return from plain-HTTP-library */
   if (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_NORMAL) {  /* o.k. returned */
     return;                                /* nothing more to do      */
   }
// to-do 15.03.13 KB
#ifdef XYZ1
   if (   (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_NORMAL)  /* o.k. returned */
       || (adsl_pd_http_ctrl->dsc_phl_call_1.imc_return == DEF_IRET_END)) {  /* connection should be ended */
     return;                                /* nothing more to do      */
   }
#endif
   adsp_pd_work->boc_abend = TRUE;          /* abend of session        */
   adsp_pd_work->iec_pdwr = ied_pdwr_end_session;  /* end session      */
#ifndef B170321
   adsp_pd_work->inc_count_proc_end = 2;    /* process end of connection */
// to-do 21.03.17 KB - better set -1 ???
#endif
   iml1 = adsl_pd_http_ctrl->dsc_phl_call_1.imc_return;  /* save return code */
   free( adsl_pd_http_ctrl );               /* free memory             */
   adsl_conn1_l->adsc_pd_http_ctrl = NULL;  /* clear process data HTTP control */
   if (iml1 == DEF_IRET_END) {              /* connection should be ended */
     if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn1_l->achc_reason_end = "plain-HTTP-library ended normal";
     }
     return;                                /* nothing more to do      */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPH012W GATE=%(ux)s SNO=%08d INETA=%s l%05d plain-HTTP-library returned %d.",
                   adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                   adsl_conn1_l->chrc_ineta,
                   __LINE__,
                   iml1 );
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "plain-HTTP-library server ended with error";
   }
   return;

   p_redir_00:                              /* check redirect          */
#ifndef OLD_1305
   if (dsl_hhs1.imc_length_hostname > dsl_hhs1.imc_stored_hostname) {
     m_hlnew_printf( HLOG_WARN1, "HWSPH020W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP HTTP Host: too long",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   memset( &dsl_gdi1, 0, sizeof(struct dsd_aux_get_domain_info_1) );  /* retrieve domain-information of connection - gate */
   dsl_gdi1.dsc_ucs_hostname.ac_str = dsl_hhs1.achc_hostname;  /* memory for hostname */
   dsl_gdi1.dsc_ucs_hostname.imc_len_str = dsl_hhs1.imc_stored_hostname;  /* stored part of hostname */
// to-do 01.06.13 KB - to be changed later
   dsl_gdi1.dsc_ucs_hostname.iec_chs_str = ied_chs_idna_1;  /* IDNA RFC 3492 etc; Punycode */
#ifdef TEMPORARY_1306
   dsl_gdi1.dsc_ucs_hostname.iec_chs_str = ied_chs_utf_8;  /* character set string */
#endif
   bol_rc = m_aux_get_domain_info_1( &adsp_pd_work->dsc_aux_cf1, &dsl_gdi1 );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPH021W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP get domain information returned error",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   if (   (   (dsl_gdi1.iec_dir == ied_dir_found)  /* domain information found */
           || (dsl_gdi1.iec_dir == ied_dir_default))  /* returned domain information default values */
       && (dsl_gdi1.dsc_ucs_permmov_url.imc_len_str != 0)) {  /* permanently-moved-URL */
     dsl_gdi1.dsc_ucs_hostname = dsl_gdi1.dsc_ucs_permmov_url;  /* permanently-moved-URL */
   }
   if (dsl_gdi1.dsc_ucs_hostname.imc_len_str == 0) {  /* length used hostname */
     m_hlnew_printf( HLOG_WARN1, "HWSPH022W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP no Host: from domain information",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
#endif
   /* get a block of memory for send data                              */
   adsl_sdhc1_w1 = adsl_conn1_l->adsc_sdhc1_chain;  /* get first in chain */
   if (adsl_sdhc1_w1) {                     /* something received      */
     adsl_conn1_l->adsc_sdhc1_chain = NULL;  /* no blocks in chain     */
     adsl_sdhc1_w2 = adsl_sdhc1_w1->adsc_next;  /* get chain to free   */
     while (adsl_sdhc1_w2) {                /* loop over all buffers   */
       adsl_sdhc1_w3 = adsl_sdhc1_w2;       /* save this block         */
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w3 );        /* free this block         */
     }
   } else {
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_w1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   }
   adsl_sdhc1_w1->adsc_next = NULL;         /* this is last block now  */
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - 1;
   adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* first part to send */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_01;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_01 + sizeof(ucrs_http_perm_mov_01);
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   memset( &dsl_epoch, 0, sizeof(struct dsd_hl_aux_epoch_1) );  /* parameters for subroutine */
   dsl_epoch.ac_epoch_str = (char *) (adsl_sdhc1_w1 + 1);
   dsl_epoch.inc_len_epoch = 64;
   dsl_epoch.iec_chs_epoch = ied_chs_ansi_819;
   dsl_epoch.imc_epoch_val = (int) time( NULL );  /* get current time  */
   m_string_from_epoch( &dsl_epoch );
   achl_w1 = (char *) (adsl_sdhc1_w1 + 1) + dsl_epoch.inc_len_epoch;
   adsl_gai1_w1->achc_ginp_cur = (char *) (adsl_sdhc1_w1 + 1);
   adsl_gai1_w1->achc_ginp_end = achl_w1;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_02;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_02 + sizeof(ucrs_http_perm_mov_02);
#ifndef OLD_1305
   if (dsl_gdi1.boc_use_full_pm_url) {      /* use-full-permanently-moved-URL */
     adsl_gai1_w1->achc_ginp_end -= 8;
   }
#endif
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
#ifdef OLD_1305
   adsl_gai1_w1->achc_ginp_cur = ADSL_CONN1_G->adsc_gate1->achc_permmov_url;  /* address of URL */
   adsl_gai1_w1->achc_ginp_end
     = ADSL_CONN1_G->adsc_gate1->achc_permmov_url + ADSL_CONN1_G->adsc_gate1->imc_len_permmov_url;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w2 = adsl_gai1_w1;             /* save this gather        */
   iml1 = ADSL_CONN1_G->adsc_gate1->imc_gateport;
   if (ADSL_CONN1_G->adsc_gate1->imc_permmov_to_port >= 0) {  /* <permanently-moved-to-port> */
     iml1 = ADSL_CONN1_G->adsc_gate1->imc_permmov_to_port;  /* <permanently-moved-to-port> */
   }
   achl_w1 += 16;
   adsl_gai1_w1->achc_ginp_end = achl_w1;
   do {                                     /* loop for output of digits */
     *(--achl_w1) = (iml1 % 10) + '0';      /* output one digit        */
     iml1 /= 10;                            /* divide number           */
   } while (iml1 > 0);
   *(--achl_w1) = ':';                      /* output separator        */
   adsl_gai1_w1->achc_ginp_cur = achl_w1;
#endif
#ifndef OLD_1305
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_plain_http() l%05d before m_cpy_vx_ucs() adsl_conn1_l=0X%p length buffer=%d.",
                   __LINE__, adsl_conn1_l, ((char *) (adsl_gai1_w1 - 7)) - achl_w1 );
#endif
   iml1 = m_cpy_vx_ucs( achl_w1, ((char *) (adsl_gai1_w1 - 7)) - achl_w1, ied_chs_idna_1,  /* IDNA RFC 3492 etc; Punycode */
                        &dsl_gdi1.dsc_ucs_hostname );
   if (iml1 <= 0) {                         /* nothing copied          */
     m_hlnew_printf( HLOG_WARN1, "HWSPH023W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP could not copy HTTP Host:",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     m_proc_free( adsl_sdhc1_w1 );          /* free the send block     */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   adsl_gai1_w1->achc_ginp_cur = achl_w1;
   achl_w1 += iml1;                         /* after ths string        */
   adsl_gai1_w1->achc_ginp_end = achl_w1;
   if (dsl_gdi1.boc_use_full_pm_url == FALSE) {  /* use-full-permanently-moved-URL */
     achl_w1++;                             /* space for output separator */
     iml1 = adsl_conn1_l->adsc_gate1->imc_gateport;
     if (adsl_conn1_l->adsc_gate1->imc_permmov_to_port >= 0) {  /* <permanently-moved-to-port> */
       iml1 = adsl_conn1_l->adsc_gate1->imc_permmov_to_port;  /* <permanently-moved-to-port> */
     }
     iml2 = iml1;                           /* get the number          */
     do {                                   /* loop to find digits of the number */
       achl_w1++;                           /* needs one character     */
       iml2 /= 10;                          /* divide number           */
     } while (iml2 > 0);
     if (achl_w1 > ((char *) adsl_gai1_w1 - 7)) {  /* not enough space */
       m_hlnew_printf( HLOG_WARN1, "HWSPH024W GATE=%(ux)s SNO=%08d INETA=%s plain-HTTP HTTP Host: port number too long",
                       adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                       adsl_conn1_l->chrc_ineta );
       m_proc_free( adsl_sdhc1_w1 );        /* free the send block     */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       return;                              /* nothing more to do      */
     }
     adsl_gai1_w1->achc_ginp_end = achl_w1;
     do {                                   /* loop for output of digits */
       *(--achl_w1) = (iml1 % 10) + '0';    /* output one digit        */
       iml1 /= 10;                          /* divide number           */
     } while (iml1 > 0);
     *(--achl_w1) = ':';                    /* output separator        */
   }
   adsl_gai1_w2 = adsl_gai1_w1;             /* save this gather        */
#endif
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_03;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_03 + sizeof(ucrs_http_perm_mov_03);
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
#ifdef OLD01
   adsl_gai1_w1->achc_ginp_cur = dsg_this_server.chrc_server_name;
   adsl_gai1_w1->achc_ginp_end
     = dsg_this_server.chrc_server_name + dsg_this_server.imc_len_server_name;
#endif
   adsl_gai1_w1->achc_ginp_cur = (char *) m_get_query_main();
   adsl_gai1_w1->achc_ginp_end
     = adsl_gai1_w1->achc_ginp_cur + strlen( adsl_gai1_w1->achc_ginp_cur );
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_04;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_04 + sizeof(ucrs_http_perm_mov_04);
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   /* output of Content-Length                                         */
   iml1 = (sizeof(ucrs_http_perm_mov_05) - 4) + adsl_conn1_l->adsc_gate1->imc_len_permmov_url
            + (adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur)
            + sizeof(ucrs_http_perm_mov_06);
   achl_w1 += 16 + 16;
   adsl_gai1_w1->achc_ginp_end = achl_w1;
   do {                                     /* loop for output of digits */
     *(--achl_w1) = (iml1 % 10) + '0';      /* output one digit        */
     iml1 /= 10;                            /* divide number           */
   } while (iml1 > 0);
   adsl_gai1_w1->achc_ginp_cur = achl_w1;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_05;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_05 + sizeof(ucrs_http_perm_mov_05);
#ifndef OLD_1305
   if (dsl_gdi1.boc_use_full_pm_url) {      /* use-full-permanently-moved-URL */
     adsl_gai1_w1->achc_ginp_end -= 8;
   }
#endif
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
#ifdef OLD_1305
   adsl_gai1_w1->achc_ginp_cur = ADSL_CONN1_G->adsc_gate1->achc_permmov_url;  /* address of URL */
   adsl_gai1_w1->achc_ginp_end
     = ADSL_CONN1_G->adsc_gate1->achc_permmov_url + ADSL_CONN1_G->adsc_gate1->imc_len_permmov_url;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
#endif
   adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w2->achc_ginp_cur;
   adsl_gai1_w1->achc_ginp_end = adsl_gai1_w2->achc_ginp_end;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_06;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_06 + sizeof(ucrs_http_perm_mov_06);
   adsl_gai1_w1->adsc_next = NULL;          /* set end of chain        */
#ifdef XYZ1
   adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;
   adsl_sdhc1_w1->inc_position = 0;
#endif
   adsl_conn1_l->inc_c_ns_send_c++;         /* count send client       */
   adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
   do {                                     /* loop over data to send to client */
     adsl_conn1_l->ilc_d_ns_send_c += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
#ifndef HL_UNIX
#ifdef XYZ1
#ifdef TRY_120306_01                        /* flow-control send       */
   if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
     ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = FALSE;  /* activate connection after send */
   }
#endif
#endif
   adsl_conn1_l->dcl_tcp_r_c.m_send_gather( adsl_sdhc1_w1, FALSE );
#else
#ifdef B110810
   m_tcp_send_1( ADSL_CONN1_G, FALSE, adsl_sdhc1_w1 );
#endif
   m_send_clse_tcp_1( adsl_conn1_l, &ADSL_CONN1_G->dsc_tc1_client, adsl_sdhc1_w1, FALSE );
#endif
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef XYZ1
   ADSL_CONN1_G->adsc_sdhc1_chain = NULL;   /* no blocks in chain      */
#endif
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "session moved";
   }
   adsp_pd_work->boc_abend = TRUE;          /* abend of session        */
   return;

#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_pd_plain_http()                                             */

#undef DSD_CONN_G
