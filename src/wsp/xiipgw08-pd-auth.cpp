#define DEBUG_140327_01
#define DEBUG_140328_01 256
//#define B140305
#define B130919
#ifndef HL_UNIX
//#define TEMP_KRB5
#endif
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif
/**
*  see HOBTEXT SOFTWARE.HLJWT.RADIUS01
*/

#ifdef TEMP_KRB5
#include "hob-krb5-kb-wsp-01-keytab.h"
#define MAX_LEN_KEYTAB (16 * 1024)
#define VAL_PWD_KEYTAB "p123p123"
#define VAL_REALM_KEYTAB "HOBTEST01.LOCAL"

extern "C" BOOL m_krb5_keytab_mit_to_heim(struct dsd_aux_krb5_mit_to_heim* adsp_keytab_data);

struct dsd_aux_krb5_mit_to_heim {               /* Kerberos Keytab conversion */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
   char       *achc_mit_data;               /* input data */
   int        imc_mit_data_len;             /* length of input data */
   char       *achc_heim_data_buffer;         /* output buffer for Heimdal kt data */
   int        imc_heim_buffer_len;           /* length output buffer for kt data */
   int        imc_heim_len_ret;              /* returned length of kt data */
   struct dsd_unicode_string dsc_password;  /* Password for keydump*/
   struct dsd_unicode_string dsc_realm;  /* Keytab realm */
};
#endif

/** process authentication                                             */
static void m_pd_auth1( struct dsd_pd_work *adsp_pd_work ) {
   BOOL       bol_rc;                       /* return code             */
#ifndef B140305
   BOOL       bol_proc_servli;              /* needs to process server-list */
#endif
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7, iml8;  /* working variables */
   int        iml_w1, iml_w2;               /* working variables       */
   int        iml_index;                    /* index of table / array  */
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
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_wsp_auth_1 *adsl_wa1;         /* structure for authentication */
   struct dsd_wsp_auth_normal *adsl_wan;    /* normal authentication   */
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
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
   struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
   struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
   char       chrl_work1[ 256 ];            /* work area               */
#ifdef WSP_V24
   struct dsd_aux_set_ident_1 dsl_g_idset1;  /* set ident - userid and user-group */
#endif
#ifdef TEMP_KRB5
   struct dsd_unicode_string dsl_ucs_l;     /* unicode string          */
   struct dsd_aux_krb5_mit_to_heim dsl_akm2h;  /* Kerberos Keytab conversion */
   struct dsd_aux_krb5_se_ti_check_1 dsl_akstc1;  /* Kerberos check Service Ticket */
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   adsl_conn1_l = ADSL_CONN1_G;             /* current connection      */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d started ADSL_CONN1_G=0X%p adsp_pd_work=0X%p",
                   __LINE__, adsl_conn1_l, adsp_pd_work );
#endif
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_auth;  /* Authentication active */
   ADSL_AUX_CF1->ac_sdh = NULL;             /* current Server-Data-Hook */
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_auth;  /* Authentication active */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr = NULL;
#ifdef OLD_1112
   bol_http = FALSE;                        /* do not try HTTP         */
#endif
#ifdef OLD_1112
   adsl_sdhc1_work_frse = NULL;             /* no storage yet          */
#endif
#ifndef B140305
   bol_proc_servli = FALSE;                 /* needs to process server-list */
#endif
// new 26.12.11 KB
   /* search input data to authentication                              */
   adsl_gai1_w1 = NULL;                     /* no input data found     */
   adsl_sdhc1_cur_1 = adsl_conn1_l->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) {
       if (adsl_sdhc1_cur_1->inc_position < MAX_SERVER_DATA_HOOK) break;  /* not position from client to authentication */
       adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1) {               /* loop over output        */
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* get this buffer         */
       do {                                 /* loop over remaining buffers */
         adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       } while (   (adsl_sdhc1_w1)
                && (adsl_sdhc1_w1->inc_position >= MAX_SERVER_DATA_HOOK));  /* position from client to authentication */
       break;
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   adsl_gai1_client_input = adsl_gai1_w1;   /* gather start input from client */
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_radqu) goto pauth20;  /* storage for variables acquired */
#else
   if (adsl_conn1_l->adsc_gate1->adsc_hobwspat3_ext_lib1) {  /* external library loaded for HOB-WSP-AT3 */
     goto p_atlib_00;                       /* process authentication-library */
   }
   if (adsl_conn1_l->adsc_wsp_auth_1) goto pauth20;  /* structure for authentication */
#endif

   /* start subroutines                                                */
   iml1 = 0;
#ifdef B120107
   if (adsl_conn1_l->adsc_gate1->imc_no_radius) {  /* number of radius groups */
     iml1 = sizeof(struct dsd_radius_control_1) + sizeof(struct dsd_hl_aux_radius_1);  /* radius control + radius request */
   }
#else
#ifndef NO_AUTH_RADIUS                      /* 09.05.12 KB - for test password change */
   if (adsl_conn1_l->adsc_radius_group) {   /* active Radius group     */
     iml1 = sizeof(struct dsd_radius_control_1) + sizeof(struct dsd_hl_aux_radius_1);  /* radius control + radius request */
   }
#endif
#endif
   adsl_conn1_l->adsc_wsp_auth_1 = (struct dsd_wsp_auth_1 *) malloc( sizeof(struct dsd_wsp_auth_1) + sizeof(struct dsd_wsp_auth_normal) + iml1 );  /* structure for authentication normal */
#ifdef B120107
   memset ( adsl_conn1_l->adsc_wsp_auth_1, 0, sizeof(struct dsd_wsp_auth_1) + sizeof(struct dsd_wsp_auth_normal) );  /* normal authentication */
#endif
   memset ( adsl_conn1_l->adsc_wsp_auth_1, 0, sizeof(struct dsd_wsp_auth_1) + sizeof(struct dsd_wsp_auth_normal) + iml1 );  /* normal authentication */
   adsl_wan = (struct dsd_wsp_auth_normal * ) (adsl_conn1_l->adsc_wsp_auth_1 + 1);  /* normal authentication */
// memset ( adsl_wan, 0, sizeof(struct dsd_wsp_auth_normal) );  /* normal authentication */
   adsl_wan->imc_language = adsl_conn1_l->adsc_gate1->imc_language;  /* get language configured */
   adsl_wan->aadsc_usent = m_get_addr_user_entry( adsl_conn1_l );
   adsl_wan->aadsc_usgro = m_get_addr_user_group( adsl_conn1_l );
   if (iml1) {                              /* with radius             */
     m_radius_init( (struct dsd_radius_control_1 *) (adsl_wan + 1),
#ifdef B120107
                    adsl_conn1_l->adsc_gate1->adsrc_radius_group[ 0 ],  /* Radius groups */
#else
                    adsl_conn1_l->adsc_radius_group,  /* active Radius group */
#endif
                    adsl_conn1_l,           /* current connection      */
#ifndef HL_UNIX
                    (struct sockaddr *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                    (struct sockaddr *) &adsl_conn1_l->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                    &m_auth_radius_req_compl );
   }

   pauth20:                                 /* storage for variables acquired */
   adsl_wa1 = adsl_conn1_l->adsc_wsp_auth_1;  /* structure for authentication */
#ifdef DEBUG_130502_01                      /* loop connection failed PTTD */
   m_hlnew_printf( HLOG_TRACE1, "HWSPAnnnT authentication l%05d adsl_conn1_l=%p iec_st_ses=%d adsc_server_conf_1=%p adsl_gai1_w1=%p boc_notify=%d boc_timed_out=%d boc_connect_active=%d boc_did_connect=%d imc_connect_error=%d boc_rec_from_server=%d boc_http=%d.",
                   __LINE__,
                   adsl_conn1_l, adsl_conn1_l->iec_st_ses, adsl_conn1_l->adsc_server_conf_1,
                   adsl_gai1_w1,
                   adsl_wa1->boc_notify,    /* notify authentication routine */
                   adsl_wa1->boc_timed_out,  /* received timed out     */
                   adsl_wa1->boc_connect_active,  /* connect active now */
                   adsl_wa1->boc_did_connect,  /* did connect          */
                   adsl_wa1->imc_connect_error,  /* connect error      */
                   adsl_wa1->boc_rec_from_server,  /* receive from server */
                   adsl_wa1->boc_http );    /* check HTTP              */
#endif  /* DEBUG_130502_01                     loop connection failed PTTD */
   if (adsl_wa1->boc_http) {                /* check HTTP              */
     goto p_http_00;                        /* other protocol received - HTTP */
   }
   adsl_wa1->boc_notify = FALSE;            /* reset notify authentication routine */
// adsl_wan = &adsl_conn1_l->adsc_wsp_auth_1->dsc_wan;  /* normal authentication */
   adsl_wan = (struct dsd_wsp_auth_normal * ) (adsl_wa1 + 1);  /* normal authentication */
   adsl_rctrl1 = NULL;                      /* radius control          */
#ifndef NO_AUTH_RADIUS                      /* 09.05.12 KB - for test password change */
// to-do 07.01.12 KB use other flag
   if (adsl_conn1_l->adsc_radius_group) {   /* active Radius group     */
     adsl_rctrl1 = (struct dsd_radius_control_1 *) (adsl_wan + 1);  /* radius control */
     if (   (adsl_rctrl1->adsc_rreq)        /* active radius request   */
         && (adsl_rctrl1->adsc_rreq->iec_radius_resp != ied_rar_invalid)) {  /* parameter is invalid */
       goto p_radius_00;                    /* radius request response received */
     }
   }
#endif
   if (adsl_wa1->boc_did_connect) goto p_conn_00;  /* did connect      */
   if (adsl_gai1_w1 == NULL) return;        /* no input data found     */
   iml1 = 0;                                /* count input data        */
   iml_save_2 = 0;                          /* so many characters after last checkpoint */
   while (TRUE) {                           /* loop over input data    */
     if (adsl_gai1_w1 == NULL) return;      /* no input data           */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     iml1 += iml2;                          /* length up to here       */
     if (iml1 > adsl_wan->imc_inp_proc) break;  /* new data in this block */
     iml_save_2 += iml2;                    /* so many characters after last checkpoint */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   achl_rp = adsl_gai1_w1->achc_ginp_cur + (adsl_wan->imc_inp_proc - iml1 + iml2);
   iml_save_2 += achl_rp - adsl_gai1_w1->achc_ginp_cur;  /* so many characters after last checkpoint */
   achl_save_2 = NULL;                      /* not yet processed something */
   iml_save_max = MAX_AUTH_IN;              /* maximum length input authentication */
   if (adsl_wan->iec_wani == ied_wani_kw_value) {  /* value for keyword */
     if (adsl_wan->iec_wanhkw == ied_wanhkw_language) {  /* value is language */
       iml_save_max = sizeof(int);          /* maximum number of characters after last checkpoint */
     } else if (adsl_wan->iec_wanhkw == ied_wanhkw_krb5_ticket) {  /* value is krb5-ticket */
       iml_save_max = MAX_AUTH_KRB5_TI;     /* maximum length authentication Kerberos ticket */
     }
// } else if (adsl_wan->iec_wani == ied_wani_prot_utf8) {  /* protocol in UTF-8 */
   }
   while (TRUE) {                           /* loop over input data    */
     iml1 = adsl_gai1_w1->achc_ginp_end - achl_rp;  /* data in this block */
     switch (adsl_wan->iec_wani) {          /* check which state       */
       case ied_wani_start:                 /* first data from client  */
         if (*achl_rp != 0X05) {            /* first byte not Socks 5  */
#ifdef XYZ1
#ifdef B060507
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e001 first data from input not Socks / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           return ied_atr_other_prot;       /* other protocol selected */
#endif
#ifdef B130405
           m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
           adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
#endif
           adsl_wa1->boc_http = TRUE;       /* check HTTP              */
           goto p_http_00;                  /* other protocol received - HTTP */
         }
         adsl_wan->iec_wani = ied_wani_prot_cs;  /* protocol const start */
         achl_rp++;                         /* this character processed */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         break;
       case ied_wani_prot_cs:               /* protocol const start    */
         if (*achl_rp != 0) {               /* pseudo length must be zero */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e033 first data from input do not contain protocol (zero / %02X)",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d first data from input do not contain protocol (zero / %02X)",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 01";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wani = ied_wani_prot_utf8;  /* protocol in UTF-8 */
         achl_rp++;                         /* this character processed */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         iml_save_max = MAX_AUTH_IN;        /* maximum length input authentication */
         break;
       case ied_wani_prot_utf8:             /* protocol in UTF-8       */
         achl_w1 = (char *) memchr( achl_rp, 0, iml1 );
         if (achl_w1 == NULL) {
           achl_rp += iml1;                 /* this character processed */
           iml_save_2 += iml1;              /* so many characters after last checkpoint */
           if (iml_save_2 <= iml_save_max) break;  /* maximum number of characters after last checkpoint */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s double",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 02";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         /* end of protocol found                                      */
         adsl_wan->imc_len_protocol = iml_save_2 + (achl_w1 - achl_rp);
#ifdef WORK_060624
         if (adsl_wan->imc_len_protocol == 0) goto p_err_len_00;  /* invalid length field */
#endif
         adsl_wan->achc_protocol = (char *) malloc( adsl_wan->imc_len_protocol );
         m_auth_get_input( adsl_gai1_client_input, adsl_wan->achc_protocol, achl_save_2, achl_w1 );
         adsl_wan->iec_scp_def = m_decode_prot( ied_chs_utf_8, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
         if (adsl_wan->iec_scp_def == ied_scp_http) {  /* protocol HTTP */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e036 protocol HTTP requested - not allowed" );
           *aapout = achp_work_area;    /* output work area        */
           iec_rqc = ied_rqc_abend;     /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;      /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d protocol HTTP requested - not allowed",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__ );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 03";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         /* check what received next                                   */
         achl_rp = achl_w1 + 1;             /* continue from here      */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         adsl_wan->iec_wani = ied_wani_keyword;  /* search keyword     */
         break;
       case ied_wani_keyword:               /* search keyword          */
         achl_w1 = (char *) memchr( achl_rp, 0, iml1 );
         if (achl_w1) {                     /* ending zero found       */
           iml2 = iml_save_2 + (achl_w1 - achl_rp);
           if (iml2 == 0) {                 /* no more keyword         */
             achl_rp = achl_w1 + 1;         /* continue from here      */
             achl_save_2 = achl_rp;         /* save how far processed  */
             iml_save_2 = 0;                /* so many characters after last checkpoint */
             adsl_wan->iec_wani = ied_wani_lenmeth;  /* length of methods */
             break;
           }
         }
         achl_w2 = (char *) memchr( achl_rp, '=', iml1 );
         if (achl_w2 == NULL) {             /* not end of keyword      */
           if (achl_w1) {                   /* zero for end found      */
             goto p_prog_illogic_00;        /* program illogic         */
           }
           achl_rp += iml1;                 /* this character processed */
           iml_save_2 += iml1;              /* so many characters after last checkpoint */
           break;
         }
         iml2 = iml_save_2 + (achl_w2 - achl_rp);  /* length of keyword */
         if (iml2 > (sizeof(chrl_work1) - 1)) {  /* keyword too long   */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword too long %d.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, iml2 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 04";
           }
           goto p_ret_err_00;               /* return after error      */
         }
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_XYZ1, "xsradiq1-%05d-T dsd_radius_query::m_proc_rad_data() call dsd_radius_query::m_auth_get_input( %p, %p, %p, %p )",
                         __LINE__, adsl_gai1_client_input, chrl_work1, achl_save_2, achl_w2  );
#endif
         m_auth_get_input( adsl_gai1_client_input, chrl_work1, achl_save_2, achl_w2 );
         *(chrl_work1 + iml2) = 0;          /* make zero-terminated    */
#ifdef B150511
         adsl_wan->iec_wanhkw = ied_wanhkw_invalid;  /* value is invalid */
         bol1 = FALSE;                      /* is not double           */
         iml_save_max = MAX_AUTH_IN;        /* maximum length input authentication */
         if (!strcmp( chrl_work1, "language" )) {
           adsl_wan->iec_wanhkw = ied_wanhkw_language;  /* value is language */
           bol1 = adsl_wan->boc_hkw_language;  /* language set in header */
           iml_save_max = sizeof(int);      /* maximum number of characters after last checkpoint */
         } else if (!strcmp( chrl_work1, "userid" )) {
           adsl_wan->iec_wanhkw = ied_wanhkw_userid;  /* value is userid */
           bol1 = adsl_wan->boc_hkw_userid;  /* userid set in header   */
         } else if (!strcmp( chrl_work1, "password" )) {
           adsl_wan->iec_wanhkw = ied_wanhkw_password;  /* value is password */
           bol1 = adsl_wan->boc_hkw_password;  /* value is password    */
         } else if (!strcmp( chrl_work1, "server" )) {
           adsl_wan->iec_wanhkw = ied_wanhkw_server;  /* value is server */
           bol1 = adsl_wan->boc_hkw_server;  /* server set in header   */
#ifdef TEMP_KRB5
         } else if (!strcmp( chrl_work1, "krb5-ticket" )) {
#ifdef XYZ1
         } else if (!strcmp( chrl_work1, "KRB5-TICKET" )) {
#endif
           adsl_wan->iec_wanhkw = ied_wanhkw_krb5_ticket;  /* value is krb5-ticket */
           bol1 = adsl_wan->boc_hkw_krb5_ticket;  /* kerberos-5 ticket in header */
           iml_save_max = MAX_AUTH_KRB5_TI;  /* maximum length authentication Kerberos ticket */
#endif
         }
         if (adsl_wan->iec_wanhkw == ied_wanhkw_invalid) {  /* value is invalid  */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s undefined",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 05";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         if (bol1) {                        /* keyword double          */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s double",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 06";
           }
           goto p_ret_err_00;               /* return after error      */
         }
#endif
         iml_index = sizeof(dsrs_const_auth_kw) / sizeof(dsrs_const_auth_kw[0]) - 1;
         do {
           if (!strcmp( chrl_work1, dsrs_const_auth_kw[ iml_index ].achc_name )) break;
           iml_index--;                     /* decrement index         */
         } while (iml_index >= 0);
         if (iml_index < 0) {               /* keyword not found in table */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s undefined",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 05";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         if (*((BOOL *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].imc_displ_defined))) {
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s double",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 06";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wanhkw
           = *((enum ied_wanhkw_value *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].iec_wanhkw));
         iml_save_max = dsrs_const_auth_kw[ iml_index ].imc_max_len;  /* maximum length of value ticket */
         achl_rp = achl_w2 + 1;             /* continue from here      */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         adsl_wan->iec_wani = ied_wani_kw_value;  /* value for keyword */
         break;
       case ied_wani_kw_value:              /* value for keyword       */
         achl_w1 = (char *) memchr( achl_rp, 0, iml1 );
         if (achl_w1 == NULL) {
           achl_rp += iml1;                 /* this character processed */
           iml_save_2 += iml1;              /* so many characters after last checkpoint */
           if (iml_save_2 <= iml_save_max) break;  /* maximum number of characters after last checkpoint */
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data keyword %s double",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, chrl_work1 );
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 07";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         /* end of keyword value found                                 */
         iml2 = iml_save_2 + (achl_w1 - achl_rp);
         if (iml2 == 0) {                   /* length zero - invalid   */
           goto p_err_len_00;               /* invalid length field    */
         }
#ifdef B150511
         if (adsl_wan->iec_wanhkw != ied_wanhkw_language) {
           achl_w2 = (char *) malloc( iml2 );
         } else {                           /* keyword language        */
           if (iml2 > (sizeof(chrl_work1) - 1)) {  /* keyword too long */
             goto p_err_len_00;             /* invalid length field    */
           }
           achl_w2 = chrl_work1;            /* parameter in stack      */
         }
         m_auth_get_input( adsl_gai1_client_input, achl_w2, achl_save_2, achl_w1 );
         switch (adsl_wan->iec_wanhkw) {
           case ied_wanhkw_language:        /* value is language       */
             if (iml2 > sizeof(int)) {      /* language too long       */
               m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data language %.*(u8)s too long - ignored",
                               adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                               adsl_conn1_l->chrc_ineta,
                               __LINE__, iml2, achl_w2 );
               adsl_wan->boc_hkw_language = TRUE;  /* language set in header */
               break;
             }
             achl_w3 = achl_w2;             /* save address input      */
             iml3 = iml2;                   /* save length input       */
             iml4 = 0;                      /* clear value first       */
             do {                           /* loop over all characters */
               iml4 <<= 8;                  /* shift previous value    */
               iml4 |= *((unsigned char *) achl_w2);
               achl_w2++;                   /* next input              */
               iml2--;                      /* decrement length        */
             } while (iml2);
             iml2 = sizeof(inrs_language) / sizeof(inrs_language[0]);
             while (TRUE) {                 /* search language         */
               iml2--;
               if (iml2 < 0) break;
               if (iml4 == inrs_language[iml2]) break;
             }
             adsl_wan->boc_hkw_language = TRUE;  /* language set in header */
             if (iml2 < 0) {                /* language not found in table */
               m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data language %.*(u8)s not defined - ignored",
                               adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                               adsl_conn1_l->chrc_ineta,
                               __LINE__, iml3, achl_w3 );
               break;
             }
             adsl_wan->imc_language = iml4;  /* set the language       */
             break;
           case ied_wanhkw_userid:          /* value is userid         */
             adsl_wan->boc_hkw_userid = TRUE;  /* userid set in header */
             adsl_wan->achc_userid = achl_w2;  /* save userid here     */
             adsl_wan->boc_varstor_name = TRUE;  /* name for variable storage */
             adsl_wan->imc_len_userid = iml2;  /* set length received userid */
             break;
           case ied_wanhkw_password:        /* value is password       */
             adsl_wan->boc_hkw_password = TRUE;  /* password set in header */
             adsl_wan->achc_password = achl_w2;  /* save password here */
             adsl_wan->boc_varstor_password = TRUE;  /* password for variable storage */
             adsl_wan->imc_len_password = iml2;  /* set length received password */
             break;
           case ied_wanhkw_server:          /* value is server         */
             adsl_wan->boc_hkw_server = TRUE;  /* server set in header */
             adsl_wan->achc_stor_servent = achl_w2;  /* save server here */
             adsl_wan->imc_len_servent = iml2;  /* set length received server */
             break;
           case ied_wanhkw_krb5_ticket:     /* value is krb5-ticket    */
             adsl_wan->boc_hkw_krb5_ticket = TRUE;  /* kerberos-5 ticket set in header */
             adsl_wan->achc_stor_krb5_ticket = achl_w2;  /* storage kerberos-5 ticket */
             adsl_wan->imc_len_krb5_ticket = iml2;  /* set length received kerberos-5 ticket */
             break;
           default:
             free( achl_w2 );               /* free storage again      */
             goto p_prog_illogic_00;        /* program illogic         */
         }
#endif
         if (dsrs_const_auth_kw[ iml_index ].imc_displ_addr >= 0) {  /* displacement where address in structure */
           achl_w2 = (char *) malloc( iml2 );
         } else {                           /* special case            */
           if (iml2 > (sizeof(chrl_work1) - 1)) {  /* value too long   */
             goto p_err_len_00;             /* invalid length field    */
           }
           achl_w2 = chrl_work1;            /* parameter in stack      */
         }
         m_auth_get_input( adsl_gai1_client_input, achl_w2, achl_save_2, achl_w1 );
         *((BOOL *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].imc_displ_defined)) = TRUE;
         if (dsrs_const_auth_kw[ iml_index ].imc_displ_addr >= 0) {  /* displacement where address in structure */
           *((char **) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].imc_displ_addr))
             = achl_w2;                     /* set storage             */
           *((int *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].imc_displ_len))
             = iml2;
           if (*((enum ied_wanhkw_value *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].iec_wanhkw))
                 == ied_wanhkw_userid) {    /* value is userid         */
             adsl_wan->boc_varstor_name = TRUE;  /* name for variable storage */
           } else if (*((enum ied_wanhkw_value *) ((char *) adsl_wan + dsrs_const_auth_kw[ iml_index ].iec_wanhkw))
                        == ied_wanhkw_password) {  /* value is password */
             adsl_wan->boc_varstor_password = TRUE;  /* password for variable storage */
           }
         } else {                           /* special case            */
           if (dsrs_const_auth_kw[ iml_index ].imc_displ_addr == -1) {  /* language */
             do {                           /* pseudo-loop             */
               if (iml2 > sizeof(int)) {      /* language too long       */
                 m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data language %.*(u8)s too long - ignored",
                                 adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                                 adsl_conn1_l->chrc_ineta,
                                 __LINE__, iml2, achl_w2 );
                 break;
               }
               achl_w3 = achl_w2;           /* save address input      */
               iml3 = iml2;                 /* save length input       */
               iml4 = 0;                    /* clear value first       */
               do {                         /* loop over all characters */
                 iml4 <<= 8;                /* shift previous value    */
                 iml4 |= *((unsigned char *) achl_w2);
                 achl_w2++;                 /* next input              */
                 iml2--;                    /* decrement length        */
               } while (iml2);
               iml2 = sizeof(inrs_language) / sizeof(inrs_language[0]);
               while (TRUE) {               /* search language         */
                 iml2--;
                 if (iml2 < 0) break;
                 if (iml4 == inrs_language[iml2]) break;
               }
               if (iml2 < 0) {              /* language not found in table */
                 m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data language %.*(u8)s not defined - ignored",
                                 adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                                 adsl_conn1_l->chrc_ineta,
                                 __LINE__, iml3, achl_w3 );
                 break;
               }
               adsl_wan->imc_language = iml4;  /* set the language     */
             } while (FALSE);
           } else {                         /* flags                   */
             iml3 = 0;                      /* start with last digit   */
             iml4 = 0;                      /* clear value first       */
             do {                           /* loop over all characters */
               if ((*((unsigned char *) achl_w2 + iml3) < '0')
                     || (*((unsigned char *) achl_w2 + iml3) > '9')) {
                 m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data flags %.*(u8)s not numeric - ignored",
                                 adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                                 adsl_conn1_l->chrc_ineta,
                                 __LINE__, iml2, achl_w2 );
                 iml4 = 0;                  /* clear flags             */
                 break;
               }
               iml4 *= 10;                  /* multiply previous value */
               iml4 += *((unsigned char *) achl_w2 + iml3) - '0';
               iml3++;                      /* increment index input   */
             } while (iml3 < iml2);
             adsl_wan->imc_value_flags = iml4;  /* value of flags      */
           }
         }
         /* after this parameter, search for new keyword               */
         achl_rp = achl_w1 + 1;             /* continue from here      */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         adsl_wan->iec_wani = ied_wani_keyword;  /* search keyword     */
         break;
       case ied_wani_lenmeth:               /* length of methods       */
         adsl_wan->iec_wani = ied_wani_methchoice;      /* choice of methods       */
         adsl_wan->imc_inpds_v1 = (unsigned char) *achl_rp;  /* value 1 input data stream */
         if (adsl_wan->imc_inpds_v1 == 0) goto p_err_len_00;  /* invalid length field */
         adsl_wan->imc_inpds_v2 = 0;        /* method radius not found */
         adsl_wan->imc_inpds_v3 = 0;        /* method no authentication not found */
         adsl_wan->imc_inpds_v4 = 0;        /* display server not found */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         break;
       case ied_wani_methchoice:             /* choice of methods       */
         achl_w1 = achl_rp + iml1;          /* end of input            */
         do {
           if (achl_rp >= achl_w1) break;
           if (((unsigned char) *achl_rp) == 0X00) {  /* method no auth f */
             adsl_wan->imc_inpds_v3++;      /* method no auth found    */
           }
           if (((unsigned char) *achl_rp) == 0X83) {  /* method radius f */
             adsl_wan->imc_inpds_v2++;      /* method radius found     */
           }
           if (((unsigned char) *achl_rp) == 0X84) {  /* display server */
             adsl_wan->imc_inpds_v4++;      /* display server found    */
           }
           achl_rp++;                       /* this byte processed     */
           adsl_wan->imc_inpds_v1--;        /* count length            */
         } while (adsl_wan->imc_inpds_v1 > 0);
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         if (adsl_wan->imc_inpds_v1) break;  /* more characters to follow */
         /* end of this record                                         */
         while (TRUE) {
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifdef XYZ1
             *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e003 first block received from client too long / %d",
                                        adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
             *aapout = achp_work_area;      /* output work area        */
             iec_rqc = ied_rqc_abend;       /* abend requested         */
#ifdef PROB_NEDAP_050620
             inrc_prob_trace[3] = __LINE__;
             inrc_prob_trace[4] = ied_atr_display;
#endif
             return ied_atr_display;        /* do display now          */
#endif
             m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d first block received from client too long / %d.",
                             adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                             adsl_conn1_l->chrc_ineta,
                             __LINE__,
                             adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
// to-do 16.01.12 KB error text
             if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
               adsl_conn1_l->achc_reason_end = "error authentication UUUU";
             }
             goto p_ret_err_00;             /* return after error      */
           }
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           if (adsl_gai1_w1 == NULL) break;  /* at end of chain input data */
         }
         adsl_wan->imc_inp_proc = 0;        /* no data processed       */
#ifdef NOT_YET_111226
         bol1 = FALSE;                      /* not valid yet           */
         if (   (imc_no_radius)             /* number of radius server */
             || (imc_no_usgro)) {           /* number of user groups   */
           if (adsl_wan->imc_inpds_v2) {    /* method radius found     */
             bol1 = TRUE;                   /* is valid                */
           }
         } else {                           /* no authentication defined */
           if (adsl_wan->imc_inpds_v3) {    /* method no auth found    */
             bol1 = TRUE;                   /* is valid                */
           }
         }
         if (bol1 == FALSE) {               /* no valid method found   */
           adsl_gai1_w1->achc_ginp_cur = achl_rp + 1;  /* data processed */
           *(achp_work_area + 0) = 0XFF;    /* radius response error   */
           *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
           memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
           ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_cur = achp_work_area;
           ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_end = achp_work_area + 1;
           iec_rqc = ied_rqc_errsocks;      /* error socks protocol    */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_input;
#endif
           return ied_atr_input;            /* wait for more input     */
         }
#ifdef B060624
         iml1 = adsl_gai1_w1->achc_ginp_end - (achl_rp + 1);
         if (iml1) {                        /* more characters receive */
           adsl_gai1_w1->achc_ginp_cur = achl_rp + 1;  /* data processed */
         }
         adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
#endif
         if (   (imc_no_radius == 0)        /* number of radius server */
             && (imc_no_usgro == 0)) {      /* number of user groups   */
           if (adsl_wan->imc_inpds_v3) {    /* method no auth found    */
             goto paute00;                  /* authentification ended  */
           }
           m_hlnew_printf( HLOG_XYZ1, "xsradq1 without authentication" );
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_input;
#endif
           return ied_atr_input;            /* wait for more input     */
         }
#endif
#ifdef TEMP_KRB5
         if (adsl_wan->boc_hkw_krb5_ticket) {  /* with kerberos-5 ticket in header */
           goto p_krb5_in_00;               /* input Kerberos ticket   */
         }
#endif
         if (adsl_wan->boc_hkw_userid) {    /* userid set in header    */
           adsl_wan->iec_wani = ied_wani_proc_data;  /* process the data now */
           goto precdat40;                  /* end of received data    */
         }
#ifdef NOT_YET_111226
         *(achp_work_area + 0) = 0X05;      /* radius response         */
         *(achp_work_area + 1) = 0X83;      /* method radius selected  */
         *(achp_work_area + 2) = 0XC4;      /* input userid + password */
#endif
         adsl_wan->chc_type_input = 0XC4;   /* input userid + password */
         achl_w1 = "HOB WebSecureProxy authentication\r\nenter userid and password\r\n";
         switch (adsl_wan->imc_language) {
           case HL_LANG_FR:
             achl_w1 = "Authentification HOB WebSecureProxy\r\nentrez code d\302\264utilisateur et mot de passe\r\n";
             break;
           case HL_LANG_DE:
             achl_w1 = "HOB WebSecureProxy Anmeldung\r\nGeben Sie User-Id und Passwort ein\r\n";
             break;
           case HL_LANG_NL:
             achl_w1 = "HOB WebSecureProxy Aanmelding\r\nVul Userid en paswoord in\r\n";
             break;
         }
         iml1 = strlen( achl_w1 );
         adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
         memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
         adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
         ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
         ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
         *(ADSL_DATA_G1 + 0) = 0X05;        /* radius response         */
         *(ADSL_DATA_G1 + 1) = 0X83;        /* method radius selected  */
         *(ADSL_DATA_G1 + 2) = 0XC4;        /* input userid + password */
         ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
         ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
         if (iml1 < 0X80) {                 /* only one length byte    */
           *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte */
           ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
         } else {                           /* length in two bytes     */
           *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
           *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
           ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
         }
         adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
         adsl_wan->iec_wani = ied_wani_recr1;  /* start of record from here */
         goto p_send_cl_00;                 /* send encrypted to client */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
#ifdef XYZ1
         if (iml1 < 0X80) {                 /* only one length byte    */
           memcpy( achp_work_area + 4, achl1, iml1 );
           *(achp_work_area + 3) = (unsigned char) iml1;  /* length of text */
           *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
           memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
           ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_cur = achp_work_area;
           ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_end = achp_work_area + 4 + iml1;
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_input;
#endif
           return ied_atr_input;            /* wait for more input     */
         }
         memcpy( achp_work_area + 5, achl1, iml1 );
         *(achp_work_area + 3) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
         *(achp_work_area + 4) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
         *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
         memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
         ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_cur = achp_work_area;
         ((struct dsd_gather_i_1 *) *aapout)->adsl_wan->achc_ginp_end = achp_work_area + 5 + iml1;
#ifdef PROB_NEDAP_050620
         inrc_prob_trace[3] = __LINE__;
         inrc_prob_trace[4] = ied_atr_input;
#endif
         return ied_atr_input;              /* wait for more input     */
#endif
       case ied_wani_recr1:                 /* start radius record     */
         if (*achl_rp != 0X05) {
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e004 first byte from input record not Socks / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode first byte from input record not Socks / %02X.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 08";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         if ((adsl_wan->chc_type_input & 0XC0) == 0) {  /* no input requested */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e010 input from client, but not requested" );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode input from client, but not requested",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__ );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 09";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wani = ied_wani_meth_f;  /* method field        */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         if (adsl_wan->boc_varstor_password) {  /* password from variable storage */
           free( adsl_wan->achc_password );  /* storage password entry */
           adsl_wan->boc_varstor_password = FALSE;  /* nothing from variable storage */
           adsl_wan->imc_len_password = 0;  /* clear length password entry */
         }
         break;
       case ied_wani_meth_f:                /* method field            */
         if (((unsigned char) *achl_rp) != 0X83) {  /* method radius f */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e005 second byte from input record not type radius / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode second byte from input record not type radius / %02X.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 10";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->imc_inpds_v1 = 0;        /* clear length value      */
         adsl_wan->iec_wani = ied_wani_len_password;  /* length of password */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         if ((adsl_wan->chc_type_input & 0X80) == 0) break;  /* password requested */
         adsl_wan->iec_wani = ied_wani_len_userid;  /* length of userid */
         if (adsl_wan->boc_varstor_name) {  /* name for variable storage */
           free( adsl_wan->achc_userid );   /* storage name entry      */
           adsl_wan->boc_varstor_name = FALSE;  /* nothing in variable storage */
           adsl_wan->imc_len_userid = 0;    /* clear length name entry */
         }
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         break;
       case ied_wani_len_userid:            /* length of userid        */
         adsl_wan->imc_inpds_v1 <<= 7;      /* shift old value         */
         adsl_wan->imc_inpds_v1 |= *achl_rp & 0X7F;  /* apply new bits */
         achl_w1 = achl_rp;                 /* save position           */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         if (*achl_w1 & 0X80) break;        /* more bit set            */
         if (adsl_wan->imc_inpds_v1 == 0) goto p_err_len_00;  /* invalid length field */
         if (adsl_wan->imc_inpds_v1 > MAX_LEN_AUTH_LEN_U_PW) goto p_err_len_00;  /* maximum length authentication userid or password */
         adsl_wan->imc_len_userid = adsl_wan->imc_inpds_v1;     /* get length              */
         adsl_wan->achc_userid = (char *) malloc( adsl_wan->imc_len_userid );
         adsl_wan->boc_varstor_name = TRUE;  /* name for variable storage */
         adsl_wan->imc_inpds_v1 = 0;        /* value 1 input data stre */
         adsl_wan->iec_wani = ied_wani_data_userid;  /* data follows   */
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         break;
       case ied_wani_data_userid:           /* content of userid       */
         if (iml1 < (adsl_wan->imc_len_userid - iml_save_2)) {  /* not till end of userid */
           achl_rp += iml1;                 /* this character processed */
           iml_save_2 += iml1;              /* so many characters after last checkpoint */
           break;
         }
         /* end of userid found                                        */
         achl_w1 = achl_rp + adsl_wan->imc_len_userid - iml_save_2;  /* copy till here */
         m_auth_get_input( adsl_gai1_client_input, adsl_wan->achc_userid, achl_save_2, achl_w1 );
         achl_rp = achl_w1;                 /* continue from here      */
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         adsl_wan->iec_wani = ied_wani_len_password;  /* length of password */
         adsl_wan->imc_inpds_v1 = 0;        /* clear length value      */
         continue;                          /* do not update achl_rp   */
       case ied_wani_len_password:          /* length of password      */
         adsl_wan->imc_inpds_v1 <<= 7;      /* shift old value         */
         adsl_wan->imc_inpds_v1 |= *achl_rp & 0X7F;  /* apply new bits */
         achl_w1 = achl_rp;                 /* save position           */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         if (*achl_w1 & 0X80) break;        /* more bit set            */
         if (adsl_wan->imc_inpds_v1 > MAX_LEN_AUTH_LEN_U_PW) goto p_err_len_00;  /* maximum length authentication userid or password */
         adsl_wan->imc_len_password = adsl_wan->imc_inpds_v1;   /* get length */
         if (adsl_wan->imc_len_password == 0) {  /* no password set    */
//         achl_rp = achl_w1;               /* continue from here      */
           adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far */
           achl_save_2 = NULL;              /* nothing to process      */
           /* end of this record                                       */
           while (TRUE) {
             if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifdef XYZ1
               *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e043 WSP-Socks-mode record received from client too long" );
               *aapout = achp_work_area;    /* output work area        */
               iec_rqc = ied_rqc_abend;     /* abend requested         */
#ifdef PROB_NEDAP_050620
               inrc_prob_trace[3] = __LINE__;
               inrc_prob_trace[4] = ied_atr_display;
#endif
               return ied_atr_display;      /* do display now          */
#endif
               m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode record received from client too long",
                               adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                               adsl_conn1_l->chrc_ineta,
                               __LINE__ );
// to-do 16.01.12 KB error number
               if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
                 adsl_conn1_l->achc_reason_end = "error input data to authentication 11";
               }
               goto p_ret_err_00;           /* return after error      */
             }
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
             if (adsl_gai1_w1 == NULL) break;  /* at end of chain input data */
           }
           adsl_wan->imc_inp_proc = 0;      /* no data processed       */
           adsl_wan->iec_wani = ied_wani_proc_data;  /* process the data now */
           goto precdat40;                  /* do authentication now   */
         }
         adsl_wan->achc_password = (char *) malloc( adsl_wan->imc_len_password );
         adsl_wan->boc_varstor_password = TRUE;  /* password for variable storage */
         adsl_wan->imc_inpds_v1 = 0;        /* value 1 input data stre */
         adsl_wan->iec_wani = ied_wani_data_password;  /* data follows */
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         break;
       case ied_wani_data_password:         /* content of password     */
         if (iml1 < (adsl_wan->imc_len_password - iml_save_2)) {  /* not till end of password */
           achl_rp += iml1;                 /* this character processed */
           iml_save_2 += iml1;              /* so many characters after last checkpoint */
           break;
         }
         /* end of password found                                      */
         achl_w1 = achl_rp + adsl_wan->imc_len_password - iml_save_2;  /* copy till here */
         m_auth_get_input( adsl_gai1_client_input, adsl_wan->achc_password, achl_save_2, achl_w1 );
         achl_rp = achl_w1;                 /* continue from here      */
         adsl_gai1_w1->achc_ginp_cur = achl_rp;  /* processed so far   */
         achl_save_2 = NULL;                /* nothing to process      */
         /* end of this record                                         */
         while (TRUE) {
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifdef XYZ1
             *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e043 WSP-Socks-mode record received from client too long" );
             *aapout = achp_work_area;      /* output work area        */
             iec_rqc = ied_rqc_abend;       /* abend requested         */
#ifdef PROB_NEDAP_050620
             inrc_prob_trace[3] = __LINE__;
             inrc_prob_trace[4] = ied_atr_display;
#endif
             return ied_atr_display;          /* do display now          */
#endif
             m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode record received from client too long",
                             adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                             adsl_conn1_l->chrc_ineta,
                             __LINE__ );
// to-do 16.01.12 KB error number
             if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
               adsl_conn1_l->achc_reason_end = "error input data to authentication 12";
             }
             goto p_ret_err_00;             /* return after error      */
           }
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           if (adsl_gai1_w1 == NULL) break;  /* at end of chain input data */
         }
         adsl_wan->imc_inp_proc = 0;        /* no data processed       */
         adsl_wan->iec_wani = ied_wani_proc_data;  /* process the data now */
         goto precdat40;                    /* do authentication now   */
       case ied_wani_seen_st:               /* start server entry      */
         if (*achl_rp != 0X05) {
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e024 WSP-Socks-mode record received from client first byte record not Socks / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode record received from client first byte record not Socks / %02X.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 13";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wani = ied_wani_seen_method;     /* method follows          */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         break;
       case ied_wani_seen_method:           /* method received         */
         if (((unsigned char) *achl_rp) != 0X84) {  /* method sel serv */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e025 second byte from input record not type select server / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode second byte from input record not type select server / %02X.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 14";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wani = ied_wani_seen_stio;  /* status input output follows */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         break;
       case ied_wani_seen_stio:             /* status input output     */
         if (((unsigned char) *achl_rp) != 0X80) {  /* status inp outp */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e026 third byte from input record not status input output / %02X",
                                      (unsigned char) *achl_rp );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode third byte from input record not status input output / %02X.",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, (unsigned char) *achl_rp );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 15";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->imc_inpds_v1 = adsl_wan->imc_inpds_v2 = 0;   /* clear all values        */
         adsl_wan->iec_wani = ied_wani_seen_len;        /* length field follows    */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         break;
       case ied_wani_seen_len:              /* length field server entry */
         adsl_wan->imc_inpds_v1 <<= 7;      /* shift old value         */
         adsl_wan->imc_inpds_v1 |= *achl_rp & 0X7F;  /* apply new bits */
         achl_w1 = achl_rp;                 /* save position           */
         achl_rp++;                         /* this byte processed     */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         if (*achl_w1 & 0X80) break;        /* more bit set            */
         if (adsl_wan->imc_inpds_v1 == 0) {  /* invalid value received */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e027 WSP-Socks-mode select server length zero received" );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode select server length zero received",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__ );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 16";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         if (adsl_wan->imc_inpds_v1 > MAX_LEN_AUTH_LEN_SERVER) {  /* maximum length authentication length server */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e028 WSP-Socks-mode select server length %d received - too high",
                                      adsl_wan->imc_inpds_v1 );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode select server length %d received - too high",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__, adsl_wan->imc_inpds_v1 );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 17";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         if (adsl_wan->achc_stor_servent) {           /* storage server entry    */
           free( adsl_wan->achc_stor_servent );       /* free the storage        */
         }
         adsl_wan->achc_stor_servent = (char *) malloc( adsl_wan->imc_inpds_v1 );
         if (adsl_wan->achc_stor_servent == NULL) {   /* no storage allocated    */
#ifdef XYZ1
           *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e029 WSP-Socks-mode select server error malloc()" );
           *aapout = achp_work_area;        /* output work area        */
           iec_rqc = ied_rqc_abend;         /* abend requested         */
#ifdef PROB_NEDAP_050620
           inrc_prob_trace[3] = __LINE__;
           inrc_prob_trace[4] = ied_atr_display;
#endif
           return ied_atr_display;          /* do display now          */
#endif
           m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode select server error malloc()",
                           adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                           adsl_conn1_l->chrc_ineta,
                           __LINE__ );
// to-do 16.01.12 KB error number
           if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
             adsl_conn1_l->achc_reason_end = "error input data to authentication 18";
           }
           goto p_ret_err_00;               /* return after error      */
         }
         adsl_wan->iec_wani = ied_wani_seen_data;  /* field UTF-8 follows */
         break;
       case ied_wani_seen_data:             /* data UTF-8 server-entry */
         iml1 = adsl_gai1_w1->achc_ginp_end - achl_rp;  /* length data input */
         if (iml1 > (adsl_wan->imc_inpds_v1 - adsl_wan->imc_inpds_v2)) {
           iml1 = adsl_wan->imc_inpds_v1 - adsl_wan->imc_inpds_v2;
         }
         memcpy( adsl_wan->achc_stor_servent + adsl_wan->imc_inpds_v2, achl_rp, iml1 );
         adsl_wan->imc_inpds_v2 += iml1;    /* increment output        */
         achl_rp += iml1;                   /* increment input         */
         achl_save_2 = achl_rp;             /* save how far processed  */
         iml_save_2 = 0;                    /* so many characters after last checkpoint */
         if (adsl_wan->imc_inpds_v2 < adsl_wan->imc_inpds_v1) break;
         /* all input received for this record                         */
         adsl_wan->imc_len_servent = adsl_wan->imc_inpds_v1;  /* set length received server */
         adsl_wan->iec_wani = ied_wani_proc_data;  /* process the data now */
         break;                             /* now check if end of input */
       case ied_wani_proc_data:             /* process the data        */
#ifdef XYZ1
         *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e006 WSP-Socks-mode record received from client too long / %d",
                                    iml1 );
         *aapout = achp_work_area;          /* output work area        */
         iec_rqc = ied_rqc_abend;           /* abend requested         */
#ifdef PROB_NEDAP_050620
         inrc_prob_trace[3] = __LINE__;
         inrc_prob_trace[4] = ied_atr_display;
#endif
         return ied_atr_display;            /* do display now          */
#endif
         m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode record received from client too long / %d.",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                         adsl_conn1_l->chrc_ineta,
                         __LINE__, iml1 );
// to-do 16.01.12 KB error number
         if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
           adsl_conn1_l->achc_reason_end = "error input data to authentication 19";
         }
         goto p_ret_err_00;                 /* return after error      */
       default:
#ifdef XYZ1
         *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e041 WSP-Socks-mode record received from client program illogic adsl_wan->iec_wani=%d",
                                    adsl_wan->iec_wani );
         *aapout = achp_work_area;          /* output work area        */
         iec_rqc = ied_rqc_abend;           /* abend requested         */
#ifdef PROB_NEDAP_050620
         inrc_prob_trace[3] = __LINE__;
         inrc_prob_trace[4] = ied_atr_display;
#endif
         return ied_atr_display;            /* do display now          */
#endif
         m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d WSP-Socks-mode record received from client program illogic adsl_wan->iec_wani=%d.",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                         adsl_conn1_l->chrc_ineta,
                         __LINE__, adsl_wan->iec_wani );
// to-do 16.01.12 KB error number
         if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
           adsl_conn1_l->achc_reason_end = "error input data to authentication 20";
         }
         goto p_ret_err_00;                 /* return after error      */
     }
     /* check if more data in this block                               */
     if (achl_rp < adsl_gai1_w1->achc_ginp_end) continue;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) break;       /* needs more data         */
     achl_rp = adsl_gai1_w1->achc_ginp_cur;  /* here are more data     */
   }
   adsl_gai1_w1 = adsl_gai1_client_input;   /* get input data from client */
   if (achl_save_2) {                       /* some data processed     */
     while (TRUE) {                         /* loop over input data    */
       if (adsl_gai1_w1 == NULL) {          /* needs more data         */
         m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d input data end reached, illogic",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                         adsl_conn1_l->chrc_ineta,
                         __LINE__ );
         if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
           adsl_conn1_l->achc_reason_end = "error input data to authentication 21";
         }
         goto p_ret_err_00;                 /* return after error      */
       }
       if ((achl_save_2 >= adsl_gai1_w1->achc_ginp_cur) && (achl_save_2 <= adsl_gai1_w1->achc_ginp_end)) {
         break;
       }
       /* this gather block has been processed                         */
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1->achc_ginp_cur = achl_save_2;  /* start from here    */
   }
   adsl_wan->imc_inp_proc = 0;              /* no data processed       */
   while (TRUE) {                           /* loop over input data    */
     if (adsl_gai1_w1 == NULL) {            /* needs more data         */
       if (adsl_wan->iec_wani != ied_wani_proc_data) {  /* not end of authentication */
         return;                            /* wait for more input     */
       }
       goto psese00;                        /* select server done      */
     }
     adsl_wan->imc_inp_proc += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   /* this point never reached                                         */

   precdat40:                               /* end of received data    */
   dsl_ucs_userid.ac_str = adsl_wan->achc_userid;  /* address of string */
   dsl_ucs_userid.imc_len_str = adsl_wan->imc_len_userid;  /* length string in elements */
   dsl_ucs_userid.iec_chs_str = ied_chs_utf_8;  /* character set string */
   dsl_ucs_password.ac_str = adsl_wan->achc_password;  /* address of string */
   dsl_ucs_password.imc_len_str = adsl_wan->imc_len_password;  /* length string in elements */
   dsl_ucs_password.iec_chs_str = ied_chs_utf_8;  /* character set string */
   if (adsl_rctrl1 == NULL) {               /* no radius control       */
     goto precdat60;                        /* authenticate against internal users */
   }
#define ASDL_RREQ ((struct dsd_hl_aux_radius_1 *) (adsl_rctrl1 + 1))  /* radius request */
   memset( ASDL_RREQ, 0, sizeof(struct dsd_hl_aux_radius_1) );  /* clear radius request */
   memcpy( &ASDL_RREQ->dsc_ucs_userid, &dsl_ucs_userid, sizeof(struct dsd_unicode_string) );  /* userid */
   memcpy( &ASDL_RREQ->dsc_ucs_password, &dsl_ucs_password, sizeof(struct dsd_unicode_string) );  /* password */
   ASDL_RREQ->boc_send_nas_ineta = TRUE;    /* send NAS IP Address     */
   bol1 = m_radius_request( adsl_rctrl1, ASDL_RREQ );
#ifdef DEBUG_140327_01
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d m_radius_request() returned %d.",
                   __LINE__, bol1 );
#endif
#undef ASDL_RREQ
   if (bol1) return;                        /* wait for radius response */
   achl_w1 = "radius server not operational";
   chl1 = (unsigned char) (0X04 | 0X01);    /* text and abend          */
   adsp_pd_work->boc_abend = TRUE;          /* abend of session        */
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
   m_auth_delete( adsp_pd_work, adsl_conn1_l->adsc_wsp_auth_1 );  /* free all fields of authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
   adsl_wa1 = NULL;                     /* no more structure for authentication */
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "radius server not operational";
   }
   /* give message to client                                         */
   iml1 = strlen( achl_w1 );
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
   ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
   ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
   *(ADSL_DATA_G1 + 0) = 0X05;              /* radius response         */
   *(ADSL_DATA_G1 + 1) = 0X83;              /* method radius selected  */
   *(ADSL_DATA_G1 + 2) = chl1;              /* input as set            */
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
   if (iml1 < 0X80) {                       /* only one length byte    */
     *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte   */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
   } else {                                 /* length in two bytes     */
     *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
     *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
   }
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
   goto p_send_cl_00;                       /* send encrypted to client */

   precdat60:                               /* authenticate against internal users */
#ifdef WSP_V24
   memset( &dsl_g_idset1, 0, sizeof(struct dsd_aux_set_ident_1) );  /* set ident - userid and user-group */
   dsl_g_idset1.dsc_userid.ac_str = adsl_wan->achc_userid;  /* address of string */
   dsl_g_idset1.dsc_userid.imc_len_str = adsl_wan->imc_len_userid;  /* length string in elements */
   dsl_g_idset1.dsc_userid.iec_chs_str = ied_chs_utf_8;  /* character set string */
   if (adsl_wan->boc_hkw_host) {            /* host set in header      */
     dsl_g_idset1.dsc_cl_host.ac_str = adsl_wan->achc_host;  /* address of string */
     dsl_g_idset1.dsc_cl_host.imc_len_str = adsl_wan->imc_len_host;  /* length string in elements */
     dsl_g_idset1.dsc_cl_host.iec_chs_str = ied_chs_utf_8;  /* character set string */
   }
   if (adsl_wan->boc_hkw_device) {          /* device set in header    */
     dsl_g_idset1.dsc_cl_device.ac_str = adsl_wan->achc_device;  /* address of string */
     dsl_g_idset1.dsc_cl_device.imc_len_str = adsl_wan->imc_len_device;  /* length string in elements */
     dsl_g_idset1.dsc_cl_device.iec_chs_str = ied_chs_utf_8;  /* character set string */
   }
   if (adsl_wan->boc_hkw_appl) {            /* appl set in header      */
     dsl_g_idset1.dsc_cl_appl.ac_str = adsl_wan->achc_appl;  /* address of string */
     dsl_g_idset1.dsc_cl_appl.imc_len_str = adsl_wan->imc_len_appl;  /* length string in elements */
     dsl_g_idset1.dsc_cl_appl.iec_chs_str = ied_chs_utf_8;  /* character set string */
   }
   dsl_g_idset1.imc_auth_flags = adsl_wan->imc_value_flags;  /* value of flags */
#endif
   iel_chid_ret = m_auth_user( adsl_wan->aadsc_usent, adsl_wan->aadsc_usgro,
                               adsl_conn1_l,
#ifndef WSP_V24
                               &dsl_ucs_userid, &dsl_ucs_password,
#endif
#ifdef WSP_V24
                               &dsl_g_idset1,  /* set ident - userid and user-group */
                               &dsl_ucs_password,
#endif
                               TRUE, TRUE );
   achl_w1 = "error illogic";
   adsl_wan->chc_type_input = 0XC4;         /* input userid + password */
   bol1 = FALSE;                            /* not authentication failed */
   switch (iel_chid_ret) {
#ifdef B140328
     case ied_ad_ok:                        /* userid and password fit */
#endif
     case ied_chid_ok:                      /* userid and password valid */
       if (adsl_wan->achc_stor_servent) {   /* storage server entry    */
         goto psese00;                      /* select server done      */
       }
//     achl_w1 = "authentication done - wait for connect";
       achl_w1 = "authenticated - connection is being established";
       switch (adsl_wan->imc_language) {
         case HL_LANG_FR:
           achl_w1 = "Succ\303\250s d\302\264authentification - veuillez patienter";
           break;
         case HL_LANG_DE:
           achl_w1 = "Anmeldung erfolgreich - warten auf Connect";
           break;
         case HL_LANG_NL:
           achl_w1 = "Aanmelding succesvol - wachten op verbinding";
           break;
       }
       adsl_wan->chc_type_input = 0X04;     /* output text             */
       break;
#ifdef B140328
     case ied_ad_inv_user:                  /* userid invalid - not found */
#endif
     case ied_chid_inv_userid:              /* userid invalid - not known in system */
       achl_w1 = "userid not defined";
       switch (adsl_wan->imc_language) {
         case HL_LANG_DE:
           achl_w1 = "User-Id falsch";
           break;
       }
       bol1 = TRUE;                         /* authentication failed   */
       break;
#ifdef B140328
     case ied_ad_inv_password:              /* password invalid        */
#endif
     case ied_chid_inv_password:            /* password invalid - does not match */
       achl_w1 = "password invalid";
       switch (adsl_wan->imc_language) {
         case HL_LANG_DE:
           achl_w1 = "Passwort falsch";
           break;
       }
       bol1 = TRUE;                         /* authentication failed   */
       break;
   }
   if (   (bol1)                            /* authentication failed   */
       && (adsg_loconf_1_inuse->boc_auth_hide_msg)) {  /* hide authentication error message */
     achl_w1 = "the user name or password is incorrect";
     switch (adsl_wan->imc_language) {
       case HL_LANG_DE:
         achl_w1 = "Userid oder Passwort falsch";
         break;
     }
   }
   /* give message to client                                         */
   iml1 = strlen( achl_w1 );
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
   ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
   ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
   *(ADSL_DATA_G1 + 0) = 0X05;              /* radius response         */
   *(ADSL_DATA_G1 + 1) = 0X83;              /* method radius selected  */
   *(ADSL_DATA_G1 + 2) = adsl_wan->chc_type_input;  /* input as set    */
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
   if (iml1 < 0X80) {                       /* only one length byte    */
     *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte   */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
   } else {                                 /* length in two bytes     */
     *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
     *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
   }
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
   if (iel_chid_ret != ied_chid_ok) {       /* authentication failed   */
     adsl_wan->iec_wani = ied_wani_recr1;   /* start of record from here */
     goto p_send_cl_00;                     /* send encrypted to client */
   }
#ifdef B140305
   goto p_servli_00;                        /* process server-list     */
#endif
#ifndef B140305
   bol_proc_servli = TRUE;                  /* needs to process server-list */
   goto p_send_cl_00;                       /* send encrypted to client */
#endif

#ifdef TEMP_KRB5
   p_krb5_in_00:                            /* input Kerberos ticket   */
#ifdef XYZ1
   memset( &dsl_akm2h, 0, sizeof(struct dsd_aux_krb5_mit_to_heim) );  /* Kerberos Keytab conversion */
   dsl_akm2h.achc_mit_data = (char *) kb_wsp_01_keytab;  /* input data */
   dsl_akm2h.imc_mit_data_len = sizeof(kb_wsp_01_keytab);  /* length of input data */
   dsl_akm2h.achc_heim_data_buffer = (char *) malloc( MAX_LEN_KEYTAB );  /* output buffer for Heimdal kt data */
   dsl_akm2h.imc_heim_buffer_len = MAX_LEN_KEYTAB;  /* length output buffer for kt data */
   /* Password for keydump */
   dsl_akm2h.dsc_password.ac_str = VAL_PWD_KEYTAB;
   dsl_akm2h.dsc_password.imc_len_str = strlen(VAL_PWD_KEYTAB);
   dsl_akm2h.dsc_password.iec_chs_str = ied_chs_utf_8;   /* character set string */
   /* Keytab realm */
   dsl_akm2h.dsc_password.ac_str = VAL_REALM_KEYTAB;
   dsl_akm2h.dsc_password.imc_len_str = strlen(VAL_REALM_KEYTAB);
   dsl_akm2h.dsc_password.iec_chs_str = ied_chs_utf_8;   /* character set string */
   bol1 = m_krb5_keytab_mit_to_heim( &dsl_akm2h );
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-auth-l%05d m_krb5_keytab_mit_to_heim() returned %d iec_ret_krb5=%d.",
                   __LINE__, bol1, dsl_akm2h.iec_ret_krb5 );
   dsl_ucs_l.ac_str = adsl_wan->achc_stor_krb5_ticket;  /* address of string */
   dsl_ucs_l.imc_len_str = adsl_wan->imc_len_krb5_ticket;  /* length string in elements */
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* character set string */
   iml1 = (adsl_wan->imc_len_krb5_ticket + 4 - 1) / 4 * 3;
   achl_w2 = (char *) malloc( MAX_KRB5_SE_TI + iml1 );
   iml4 = m_get_ucs_base64( &iml2, &iml3,
                            achl_w2 + MAX_KRB5_SE_TI, iml1,
                            &dsl_ucs_l );
   if (iml4 <= 0) {                         /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d UUUU base64 error %d position %d.",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta,
                     __LINE__,
                     iml2, iml3 );
     if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn1_l->achc_reason_end = "error input data to authentication TEMP_KRB5 01";
     }
     free( dsl_akm2h.achc_heim_data_buffer );
     free( achl_w2 );
     goto p_ret_err_00;                     /* return after error      */
   }
   memset( &dsl_akstc1, 0, sizeof(struct dsd_aux_krb5_se_ti_check_1) );  /* Kerberos check Service Ticket */
   dsl_akstc1.achc_ticket_in = achl_w2 + MAX_KRB5_SE_TI;  /* address buffer for service ticket input */
   dsl_akstc1.imc_ticket_length = iml4;     /* length of input service ticket */
   dsl_akstc1.achc_mutual_resp_buffer = achl_w2;  /* address buffer for mutual response */
   dsl_akstc1.imc_mutual_resp_buffer_len = MAX_KRB5_SE_TI;  /* length buffer for mutual response */
   dsl_akstc1.achc_keytab = dsl_akm2h.achc_heim_data_buffer;  /* address of keytab */
   dsl_akstc1.imc_len_keytab = dsl_akm2h.imc_heim_len_ret;  /* length of keytab */
   dsl_akstc1.dsc_aux_krb5_opt_1.ibc_no_ret_handle = 1;
   bol1 = m_krb5_se_ti_check_request( NULL, &dsl_akstc1 );
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-auth-l%05d m_krb5_se_ti_check_request() returned %d iec_ret_krb5=%d.",
                   __LINE__, bol1, dsl_akstc1.iec_ret_krb5 );
   free( dsl_akm2h.achc_heim_data_buffer );
   free( achl_w2 );
   return;
#endif
   dsl_ucs_l.ac_str = adsl_wan->achc_stor_krb5_ticket;  /* address of string */
   dsl_ucs_l.imc_len_str = adsl_wan->imc_len_krb5_ticket;  /* length string in elements */
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* character set string */
   iml1 = (adsl_wan->imc_len_krb5_ticket + 4 - 1) / 4 * 3;
   achl_w2 = (char *) malloc( MAX_KRB5_SE_TI + iml1 );
   iml4 = m_get_ucs_base64( &iml2, &iml3,
                            achl_w2 + MAX_KRB5_SE_TI, iml1,
                            &dsl_ucs_l );
   if (iml4 <= 0) {                         /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d UUUU base64 error %d position %d.",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta,
                     __LINE__,
                     iml2, iml3 );
     if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn1_l->achc_reason_end = "error input data to authentication TEMP_KRB5 01";
     }
     free( dsl_akm2h.achc_heim_data_buffer );
     free( achl_w2 );
     goto p_ret_err_00;                     /* return after error      */
   }
   memset( &dsl_akstc1, 0, sizeof(struct dsd_aux_krb5_se_ti_check_1) );  /* Kerberos check Service Ticket */
   dsl_akstc1.achc_ticket_in = achl_w2 + MAX_KRB5_SE_TI;  /* address buffer for service ticket input */
   dsl_akstc1.imc_ticket_length = iml4;     /* length of input service ticket */
   dsl_akstc1.achc_mutual_resp_buffer = achl_w2;  /* address buffer for mutual response */
   dsl_akstc1.imc_mutual_resp_buffer_len = MAX_KRB5_SE_TI;  /* length buffer for mutual response */
   dsl_akstc1.achc_keytab = (char *) kb_wsp_01_keytab;  /* address of keytab */
   dsl_akstc1.imc_len_keytab = sizeof(kb_wsp_01_keytab);  /* length of keytab */
   dsl_akstc1.dsc_aux_krb5_opt_1.ibc_no_ret_handle = 1;
   bol1 = m_krb5_se_ti_check_request( NULL, &dsl_akstc1 );
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-auth-l%05d m_krb5_se_ti_check_request() returned %d iec_ret_krb5=%d.",
                   __LINE__, bol1, dsl_akstc1.iec_ret_krb5 );
   free( achl_w2 );
   return;
#endif

   p_radius_00:                             /* radius request response received */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d p_radius_00 iec_radius_resp=%d adsl_gai1_w1=%p.",
                   __LINE__, adsl_rctrl1->adsc_rreq->iec_radius_resp, adsl_gai1_w1 );
#endif
#define ASDL_RREQ ((struct dsd_hl_aux_radius_1 *) (adsl_rctrl1 + 1))  /* radius request */
   switch (ASDL_RREQ->iec_radius_resp) {    /* response from radius server */
     case ied_rar_access_accept:            /* accept sign on          */
       goto p_radius_80;                    /* radius sign-on complete */
     case ied_rar_access_reject:            /* reject access           */
       achl_w1 = "authentication failed - try again";
       switch (adsl_wan->imc_language) {
         case HL_LANG_DE:
           achl_w1 = "Anmeldung fehlgeschlagen - neuer Versuch";
           break;
         case HL_LANG_NL:
           achl_w1 = "Fout bij aanmelden - probeer opnieuw";
           break;
       }
#ifdef B140327
       adsl_wan->chc_type_input = 0XC4;     /* input userid + password */
#endif
       chl1 = 0XC4;                         /* input userid + password */
       break;
     case ied_rar_challenge:                /* request challenge       */
       achl_w1 = "enter challenge:";
       switch (adsl_wan->imc_language) {
         case HL_LANG_DE:
           achl_w1 = "verlangte Eingabe:";
           break;
         case HL_LANG_NL:
           achl_w1 = "invoer gewenst:";
           break;
       }
#ifdef B140327
       adsl_wan->chc_type_input = 0X44;     /* input passw, output text */
#endif
       chl1 = 0X44;                         /* input passw, output text */
       break;
     case ied_rar_need_new_password:        /* needs new password      */
       achl_w1 = "change password required";
       adsl_wan->chc_type_input = 0X05;     /* input new password and text */
       break;
     default:
       achl_w1 = "radius server not operational";
#ifdef B140327
       adsl_wan->chc_type_input = (unsigned char) (0X04 | 0X01);  /* text and abend */
#endif
       chl1 = (unsigned char) (0X04 | 0X01);  /* text and abend        */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
       m_auth_delete( adsp_pd_work, adsl_conn1_l->adsc_wsp_auth_1 );  /* free all fields of authentication */
       adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
       adsl_wa1 = NULL;                     /* no more structure for authentication */
       if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
         adsl_conn1_l->achc_reason_end = "radius server not operational";
       }
       break;
   }
   /* give message to client                                         */
   iml1 = strlen( achl_w1 );
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
   ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
   ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
   *(ADSL_DATA_G1 + 0) = 0X05;              /* radius response         */
   *(ADSL_DATA_G1 + 1) = 0X83;              /* method radius selected  */
#ifdef B140327
   *(ADSL_DATA_G1 + 2) = adsl_wan->chc_type_input;  /* input as set    */
#endif
   *(ADSL_DATA_G1 + 2) = chl1;              /* input as set            */
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
#ifdef B140372
   if (ASDL_RREQ->iec_radius_resp == ied_rar_challenge) {  /* request challenge */
#ifdef FORKEDIT
   }
#endif
#endif
   if (   (adsl_wa1)                        /* structure for authentication */
       && (ASDL_RREQ->iec_radius_resp == ied_rar_challenge)) {  /* request challenge */
     achl_w1 = ASDL_RREQ->achc_attr_in;     /* attributes input        */
     achl_w2 = ASDL_RREQ->achc_attr_in + ASDL_RREQ->imc_attr_in;  /* add length attributes input */
     adsl_gai1_w1 = NULL;                   /* no output yet           */
     while (achl_w1 < achl_w2) {            /* loop over attributes input */
       if ((achl_w1 + 2) > achl_w2) break;  /* remaining data too short */
       iml2 = *((unsigned char *) achl_w1 + 1);  /* get length attribute */
       if (iml2 < 3) break;                 /* length too short        */
       if ((achl_w1 + iml2) > achl_w2) break;  /* too long             */
       if (*((unsigned char *) achl_w1 + 0) == 0X12) {  /* Reply-Message */
         /* first charriage-return line-feed                           */
         if (adsl_gai1_w1 == NULL) {        /* first output            */
           adsl_gai1_w1 = (struct dsd_gather_i_1 *) (ADSL_DATA_G1 + 8);
           ADSL_GAI1_G2->adsc_next = adsl_gai1_w1;
         } else {                           /* next gather             */
           adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
           adsl_gai1_w1++;
         }
         adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_cr_lf;
         adsl_gai1_w1->achc_ginp_end = (char *) ucrs_cr_lf + sizeof(ucrs_cr_lf);
         adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
         adsl_gai1_w1++;
         adsl_gai1_w1->achc_ginp_cur = achl_w1 + 2;
         adsl_gai1_w1->achc_ginp_end = achl_w1 + iml2;
         iml1 += 2 + iml2 - 2;
       }
       achl_w1 += iml2;                     /* add length attribute    */
     }
     /* at end carriage-return line-feed                               */
     if (adsl_gai1_w1 == NULL) {            /* first output            */
       adsl_gai1_w1 = (struct dsd_gather_i_1 *) (ADSL_DATA_G1 + 8);
       ADSL_GAI1_G2->adsc_next = adsl_gai1_w1;
     } else {                               /* next gather             */
       adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
       adsl_gai1_w1++;
     }
     adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_cr_lf;
     adsl_gai1_w1->achc_ginp_end = (char *) ucrs_cr_lf + sizeof(ucrs_cr_lf);
     adsl_gai1_w1->adsc_next = NULL;
     iml1 += 2;
   }
   if (iml1 < 0X80) {                       /* only one length byte    */
     *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte   */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
   } else {                                 /* length in two bytes     */
     *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
     *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
   }
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
#ifdef B140327
   ASDL_RREQ->iec_radius_resp = ied_rar_invalid;  /* parameter is invalid - no radius-request active */
   adsl_wan->iec_wani = ied_wani_recr1;     /* start of record from here */
#endif
   if (adsl_wa1) {                          /* still structure for authentication */
     ASDL_RREQ->iec_radius_resp = ied_rar_invalid;  /* parameter is invalid - no radius-request active */
     adsl_wan->chc_type_input = chl1;       /* input as set            */
     adsl_wan->iec_wani = ied_wani_recr1;   /* start of record from here */
   }
   goto p_send_cl_00;                       /* send encrypted to client */

   p_radius_80:                             /* radius sign-on complete */
   ASDL_RREQ->iec_radius_resp = ied_rar_invalid;  /* parameter is invalid - no radius-request active */
   if (adsl_wan->achc_stor_servent) {       /* storage server entry    */
     goto psese00;                          /* select server done      */
   }
   adsl_wan->chc_type_input = 0X04;         /* output text             */
// achl_w1 = "authentication done - wait for connect";
   achl_w1 = "authenticated - connection is being established";
   switch (adsl_wan->imc_language) {
     case HL_LANG_FR:
       achl_w1 = "Succ\303\250s d\302\264authentification - veuillez patienter";
       break;
     case HL_LANG_DE:
       achl_w1 = "Anmeldung erfolgreich - warten auf Connect";
       break;
     case HL_LANG_NL:
       achl_w1 = "Aanmelding succesvol - wachten op verbinding";
       break;
   }
   /* give message to client                                         */
   iml1 = strlen( achl_w1 );
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
   ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
   ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
   *(ADSL_DATA_G1 + 0) = 0X05;              /* radius response         */
   *(ADSL_DATA_G1 + 1) = 0X83;              /* method radius selected  */
   *(ADSL_DATA_G1 + 2) = adsl_wan->chc_type_input;  /* input as set    */
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
   if (iml1 < 0X80) {                       /* only one length byte    */
     *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte   */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
   } else {                                 /* length in two bytes     */
     *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
     *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
   }
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
   ASDL_RREQ->iec_radius_resp = ied_rar_invalid;  /* parameter is invalid - no radius-request active */
#undef ASDL_RREQ
#ifndef B140305
   bol_proc_servli = TRUE;                  /* needs to process server-list */
   goto p_send_cl_00;                       /* send encrypted to client */
#endif

   p_servli_00:                             /* process server-list     */
#ifndef B140305
   bol_proc_servli = FALSE;                 /* needs to process server-list */
#endif
// to-do 27.12.11 KB display authentication
   /* check what is configured                                         */
// imc_no_servent = 0;
// imc_user_servent = 0;
   iel_set_def = m_conn_get_set( adsl_conn1_l, FALSE );
// if (iel_set_def != ied_set_ss5h) goto paute60;  /* is not server list */
   iml_no_servent = m_conn_get_no_servent( adsl_conn1_l,
                                           adsl_wan->iec_scp_def, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
   iml_user_servent = 0;                    /* no user-group server-list */
   while (adsl_wan->imc_len_userid) {       /* user signed on          */
     if (adsl_rctrl1) {                     /* with radius             */
#ifndef WSP_V24
       dsl_ucs_userid.ac_str = adsl_wan->achc_userid;  /* address of string */
       dsl_ucs_userid.imc_len_str = adsl_wan->imc_len_userid;  /* length string in elements */
       dsl_ucs_userid.iec_chs_str = ied_chs_utf_8;  /* character set string */
#endif
#ifdef WSP_V24
       memset( &dsl_g_idset1, 0, sizeof(struct dsd_aux_set_ident_1) );  /* set ident - userid and user-group */
       dsl_g_idset1.dsc_userid.ac_str = adsl_wan->achc_userid;  /* address of string */
       dsl_g_idset1.dsc_userid.imc_len_str = adsl_wan->imc_len_userid;  /* length string in elements */
       dsl_g_idset1.dsc_userid.iec_chs_str = ied_chs_utf_8;  /* character set string */
       if (adsl_wan->boc_hkw_host) {        /* host set in header      */
         dsl_g_idset1.dsc_cl_host.ac_str = adsl_wan->achc_host;  /* address of string */
         dsl_g_idset1.dsc_cl_host.imc_len_str = adsl_wan->imc_len_host;  /* length string in elements */
         dsl_g_idset1.dsc_cl_host.iec_chs_str = ied_chs_utf_8;  /* character set string */
       }
       if (adsl_wan->boc_hkw_device) {      /* device set in header    */
         dsl_g_idset1.dsc_cl_device.ac_str = adsl_wan->achc_device;  /* address of string */
         dsl_g_idset1.dsc_cl_device.imc_len_str = adsl_wan->imc_len_device;  /* length string in elements */
         dsl_g_idset1.dsc_cl_device.iec_chs_str = ied_chs_utf_8;  /* character set string */
       }
       if (adsl_wan->boc_hkw_appl) {        /* appl set in header      */
         dsl_g_idset1.dsc_cl_appl.ac_str = adsl_wan->achc_appl;  /* address of string */
         dsl_g_idset1.dsc_cl_appl.imc_len_str = adsl_wan->imc_len_appl;  /* length string in elements */
         dsl_g_idset1.dsc_cl_appl.iec_chs_str = ied_chs_utf_8;  /* character set string */
       }
       dsl_g_idset1.imc_auth_flags = adsl_wan->imc_value_flags;  /* value of flags */
#endif
       m_auth_user( adsl_wan->aadsc_usent, adsl_wan->aadsc_usgro,
                    adsl_conn1_l,
#ifndef WSP_V24
                    &dsl_ucs_userid, NULL,
#endif
#ifdef WSP_V24
                    &dsl_g_idset1,          /* set ident - userid and user-group */
                    NULL,                   /* no password             */
#endif
                    FALSE, TRUE );
     }
     if (*adsl_wan->aadsc_usent == NULL) break;
     iml_user_servent = m_conn_get_no_user_servent( adsl_conn1_l, *adsl_wan->aadsc_usent, *adsl_wan->aadsc_usgro,
                                                    adsl_wan->iec_scp_def, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
     break;
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d iml_no_servent=%d iml_user_servent=%d.",
                   __LINE__, iml_no_servent, iml_user_servent );
#endif
   if ((iml_no_servent == 0) && (iml_user_servent == 0)) {
// to-do 27.12.11 KB
     achl_w1 = "no server-entry configured for protocol passed\r\n";
#ifdef XYZ1
     switch (adsl_wan->imc_language) {
       case HL_LANG_FR:
         achl_w1 = "Authentification HOB WebSecureProxy\r\nentrez code d\302\264utilisateur et mot de passe\r\n";
         break;
       case HL_LANG_DE:
         achl_w1 = "HOB WebSecureProxy Anmeldung\r\nGeben Sie User-Id und Passwort ein\r\n";
         break;
       case HL_LANG_NL:
         achl_w1 = "HOB WebSecureProxy Aanmelding\r\nVul Userid en paswoord in\r\n";
         break;
     }
#endif
     iml1 = strlen( achl_w1 );
     adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
     memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
     ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
     ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
     *(ADSL_DATA_G1 + 0) = (unsigned char) 0X05;  /* socks 5 response  */
     *(ADSL_DATA_G1 + 1) = (unsigned char) 0X83;  /* method radius selected */
     *(ADSL_DATA_G1 + 2) = (unsigned char) (0X04 | 0X01);  /* text follows and abend */
     ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
     ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
     if (iml1 < 0X80) {                     /* only one length byte    */
       *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte */
       ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
     } else {                               /* length in two bytes     */
       *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
       *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
       ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
     }
     adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
     goto p_send_cl_00;                     /* send encrypted to client */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
   }
   if (adsl_wan->achc_stor_servent) {       /* storage server entry    */
     goto psese00;                          /* select server done      */
   }
   if ((iml_no_servent + iml_user_servent) == 1) {  /* only one server */
     adsl_wan->imc_inpds_v1 = 0;            /* no input from client    */
     goto psese00;                          /* select server done      */
   }
   adsl_wan->iec_wani = ied_wani_seen_st;   /* start server entry      */
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
   adsl_sdhc1_out_to_client = adsl_sdhc1_w1;  /* first block to send to client */
// iec_rqi = ied_rqi_seen_st;               /* input start server entry */
// *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
// memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   *(ADSL_DATA_G1 + 0) = 0X05;              /* socks 5 response        */
   *(ADSL_DATA_G1 + 1) = 0X84;              /* select server           */
   if (adsl_wan->imc_inpds_v4 == 0) {       /* do not display server found */
     *(ADSL_DATA_G1 + 2) = 0X02;            /* input server entry      */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 3;
#ifdef PROB_NEDAP_050620
     inrc_prob_trace[3] = __LINE__;
     inrc_prob_trace[4] = ied_atr_input;
#endif
#ifdef B140328
     if (adsl_sdhc1_out_to_client->adsc_next == NULL) {  /* no chain yet     */
       adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set new chain */
     } else {                               /* append to chain         */
       adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain    */
       while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain   */
     }
     adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
     while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
     adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
#endif
     goto p_send_cl_00;                     /* send encrypted to client */
//   return ied_atr_input;                  /* wait for more input     */
   }
   *(ADSL_DATA_G1 + 2) = 0X06;              /* input and display server entry */
   achl_w1 = ADSL_DATA_G1 + 3;              /* output from here        */
   achl_w2 = (char *) adsl_sdhc1_w1 + LEN_TCP_RECV;  /* end of output area */
#ifdef DEBUG_140328_01
   achl_w2 = (char *) adsl_sdhc1_w1 + DEBUG_140328_01;  /* end of output area */
#endif
   iml_ind_servent = 0;                     /* index of server entries */

   paute08:                                 /* send next server entry  */
   if (iml_ind_servent == (iml_no_servent + iml_user_servent)) {  /* last entry reached */
     if (achl_w1 >= achl_w2) {              /* no space in output area */
       ADSL_GAI1_G1->achc_ginp_end = achl_w1;
#ifdef B140328
       if (adsl_sdhc1_out_to_client->adsc_next == NULL) {  /* no chain yet   */
         adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set new chain */
       } else {                             /* append to chain         */
         adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain  */
         while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       }
       adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
#endif
       if (adsl_sdhc1_w1 != adsl_sdhc1_out_to_client) {  /* not first block to send to client */
         adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain */
         if (adsl_sdhc1_w2 == NULL) {       /* no chain yet            */
           adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set chain */
         } else {                           /* append to chain         */
           while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
           adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain */
         }
         adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
         while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
         adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
       }
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
       ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
       achl_w1 = ADSL_DATA_G1;              /* output from here        */
       achl_w2 = (char *) adsl_sdhc1_w1 + LEN_TCP_RECV;  /* end of output area */
     }
     *achl_w1++ = 0;                        /* set length zero = e-o-f */
     ADSL_GAI1_G1->achc_ginp_end = achl_w1;
#ifdef B140328
     if (adsl_sdhc1_out_to_client->adsc_next == NULL) {  /* no chain yet     */
       adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set new chain */
     } else {                               /* append to chain         */
       adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain    */
       while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain   */
     }
     adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
     while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
     adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
#endif
     if (adsl_sdhc1_w1 != adsl_sdhc1_out_to_client) {  /* not first block to send to client */
       adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain */
       if (adsl_sdhc1_w2 == NULL) {         /* no chain yet            */
         adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set chain */
       } else {                             /* append to chain         */
         while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       }
       adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
     }
     goto p_send_cl_00;                     /* send encrypted to client */
   }
   if (iml_ind_servent < iml_no_servent) {  /* is normal entry         */
     awcl1 = m_conn_get_servent_by_no( adsl_conn1_l,
                                       iml_ind_servent,
                                       adsl_wan->iec_scp_def, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
   } else {                                 /* is in area of user      */
     awcl1 = m_conn_get_user_servent_by_no( adsl_conn1_l,
                                            *adsl_wan->aadsc_usent, *adsl_wan->aadsc_usgro,
                                            iml_ind_servent - iml_no_servent,
                                            adsl_wan->iec_scp_def, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
   }
   if (awcl1 == NULL) {
// to-do 27.12.11 KB
#ifdef XYZ1
     *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e019 server entries not found - logic error" );
     *aapout = achp_work_area;              /* output work area        */
     iec_rqc = ied_rqc_abend;               /* abend requested         */
#ifdef PROB_NEDAP_050620
     inrc_prob_trace[3] = __LINE__;
     inrc_prob_trace[4] = ied_atr_display;
#endif
     return ied_atr_display;                /* do display now          */
#endif
   }
   iml1 = m_len_vx_vx( ied_chs_utf_8,       /* Unicode UTF-8           */
                       awcl1, -1, ied_chs_utf_16 );  /* Unicode UTF-16 = WCHAR */
   iml2 = 0;                                /* reset counter           */
   iml3 = iml1;                             /* get original value      */
   do {                                     /* loop over digits        */
     iml2++;                                /* count digit             */
     iml3 >>= 7;                            /* remove 7 bits           */
   } while (iml3 != 0);
   if ((achl_w1 + iml1 + iml2) > achl_w2) {  /* not enough space       */
     ADSL_GAI1_G1->achc_ginp_end = achl_w1;
#ifdef B140328
     if (adsl_sdhc1_out_to_client->adsc_next == NULL) {  /* no chain yet     */
       adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set new chain */
     } else {                               /* append to chain         */
       adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain    */
       while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain   */
     }
     adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
     while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
     adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
#endif
     if (adsl_sdhc1_w1 != adsl_sdhc1_out_to_client) {  /* not first block to send to client */
       adsl_sdhc1_w2 = adsl_sdhc1_out_to_client->adsc_next;  /* get chain */
       if (adsl_sdhc1_w2 == NULL) {         /* no chain yet            */
         adsl_sdhc1_out_to_client->adsc_next = adsl_sdhc1_w1;  /* set chain */
       } else {                             /* append to chain         */
         while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_w1;  /* append to chain */
       }
       adsl_gai1_w1 = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
     }
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
     ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
     achl_w1 = ADSL_DATA_G1;                /* output from here        */
     achl_w2 = (char *) adsl_sdhc1_w1 + LEN_TCP_RECV;  /* end of output area */
   }
   achl_w1 += iml2;                         /* after length NHASN      */
   achl_w3 = achl_w1;                       /* save this position      */
   m_cpy_vx_vx( achl_w1, iml1, ied_chs_utf_8,  /* Unicode UTF-8        */
                awcl1, -1, ied_chs_utf_16 );  /* Unicode UTF-16 = WCHAR */
   achl_w1 += iml1;                         /* end of this string      */
   chl1 = 0;                                /* no more bit             */
   do {                                     /* loop over number        */
     *(--achl_w3) = (char) ((iml1 & 0X7F) | chl1);
     iml1 >>= 7;                            /* remove these bits       */
     chl1 = 0X80;                           /* set more bit            */
   } while (iml1 != 0);
   iml_ind_servent++;                       /* end of this entry       */
   goto paute08;                            /* send next server entry  */

#undef ADSL_GAI1_G1
#undef ADSL_DATA_G1

   psese00:                                 /* select server done      */
   dsl_ucs_w1.ac_str = adsl_wan->achc_stor_servent;  /* address of string */
   dsl_ucs_w1.imc_len_str = adsl_wan->imc_len_servent;  /* length string in elements */
   dsl_ucs_w1.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8           */
   bol1 = m_sel_server_socks5_1( adsl_conn1_l, *adsl_wan->aadsc_usent, *adsl_wan->aadsc_usgro,
                                 &dsl_ucs_w1,
                                 adsl_wan->iec_scp_def, adsl_wan->achc_protocol, adsl_wan->imc_len_protocol );
   if (   (bol1 == FALSE)                   /* server not selected     */
       && (adsl_wan->boc_hkw_server)) {     /* server set in header    */
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d client sent <server-entry>%(ucs)s not configured",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta,
                     __LINE__,
                     &dsl_ucs_w1 );
     if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn1_l->achc_reason_end = "error input data to authentication <server-entry> not configured";
     }
     achl_w1 = "abend because of <server-entry>";
     iml1 = strlen( achl_w1 );
     achl_w2 = " not configured";
     iml2 = strlen( achl_w2 );
     iml3 = iml1 + adsl_wan->imc_len_servent + iml2;
     adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
     memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 4 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_GAI1_G3 (ADSL_GAI1_G2 + 1)
#define ADSL_GAI1_G4 (ADSL_GAI1_G3 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 4 * sizeof(struct dsd_gather_i_1))
     ADSL_GAI1_G2->achc_ginp_cur = achl_w1;
     ADSL_GAI1_G2->achc_ginp_end = achl_w1 + iml1;
     ADSL_GAI1_G2->adsc_next = ADSL_GAI1_G3;
     ADSL_GAI1_G3->achc_ginp_cur = adsl_wan->achc_stor_servent;
     ADSL_GAI1_G3->achc_ginp_end = adsl_wan->achc_stor_servent + adsl_wan->imc_len_servent;
     ADSL_GAI1_G3->adsc_next = ADSL_GAI1_G4;
     ADSL_GAI1_G4->achc_ginp_cur = achl_w2;
     ADSL_GAI1_G4->achc_ginp_end = achl_w2 + iml2;
     *(ADSL_DATA_G1 + 0) = (unsigned char) 0X05;  /* socks 5 response  */
     *(ADSL_DATA_G1 + 1) = (unsigned char) 0X83;  /* method radius selected */
     *(ADSL_DATA_G1 + 2) = (unsigned char) (0X04 | 0X01);  /* text follows and abend */
     ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
     ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
     if (iml3 < 0X80) {                     /* only one length byte    */
       *(ADSL_DATA_G1 + 3) = (unsigned char) iml3;  /* set length byte */
       ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
     } else {                               /* length in two bytes     */
       *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml3 >> 7) | 0X80);  /* length first byte */
       *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml3 & 0X7F);  /* length second byte */
       ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
     }
     adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     goto p_send_cl_00;                     /* send encrypted to client */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_GAI1_G3
#undef ADSL_GAI1_G4
#undef ADSL_DATA_G1
   }
   if (adsl_wan->achc_stor_servent) {       /* storage with input field */
     free( adsl_wan->achc_stor_servent );   /* free the storage        */
     adsl_wan->achc_stor_servent = NULL;    /* clear address           */
   }
   if (bol1 == FALSE) {                     /* server not selected     */
#ifdef XYZ1
     iec_rqi = ied_rqi_seen_st;             /* input start server entry */
     *(achp_work_area + 0) = 0X05;          /* socks 5 response        */
     *(achp_work_area + 1) = 0X84;          /* select server           */
     *(achp_work_area + 2) = 0X0A;          /* message and input se en */
     achl1 = "error server not selected - input not in server-list";
     switch (adsc_radius_conf->inc_language) {
       case HL_LANG_DE:
         achl1 = "Server nicht ausgew\303\244hlt - error";
         break;
//     case HL_LANG_NL:
//       achl1 = "Probleem met Radius server\r\nopnieuw aanmelden\r\nVul Userid en paswoord in";
//       break;
     }
     iml1 = strlen( achl1 );
     memcpy( achp_work_area + 4, achl1, iml1 );
     *(achp_work_area + 3) = (unsigned char) iml1;  /* length of text  */
     *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
     memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
     ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_cur = achp_work_area;
     ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_end = achp_work_area + 4 + iml1;
#ifdef PROB_NEDAP_050620
     inrc_prob_trace[3] = __LINE__;
     inrc_prob_trace[4] = ied_atr_input;
#endif
     return ied_atr_input;                  /* wait for more input     */
#endif
// to-do 21.01.12 KB error message
   }
   /* continue what to do now                                          */
   iel_set_def = m_conn_get_set( adsl_conn1_l, FALSE );
#ifdef XYZ1
// goto paute60;                            /* connect to type of server */

   paute60:                                 /* is not server list      */
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d paute60 iel_set_def=%d.",
                   __LINE__, iel_set_def );
#endif
#ifndef B130502
   adsl_wa1->imc_connect_error = 0;         /* reset connect error     */
#endif
   if (   (iel_set_def == ied_set_direct)   /* connect direct          */
       || (iel_set_def == ied_set_casc_wsp)  /* CASCADED-WSP           */
       || (iel_set_def == ied_set_l2tp)) {  /* L2TP UDP connection     */
#ifdef XYZ1
     boc_connect_active = TRUE;             /* connect active now      */
     iec_rqc = ied_rqc_illogic;             /* set invalid call        */
#ifdef PROB_NEDAP_050620
     inrc_prob_trace[3] = __LINE__;
     inrc_prob_trace[4] = ied_atr_connect;
#endif
     return ied_atr_connect;                /* do connect              */
#endif
     adsl_wa1->boc_connect_active = TRUE;   /* connect active now      */
#ifndef HL_UNIX
     adsl_conn1_l->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
     adsl_conn1_l->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
     return;
   }
   if (iel_set_def == ied_set_loadbal) {    /* load balancing          */
#ifdef XYZ1
     *(achp_work_area + 0) = 0X05;          /* socks 5 response        */
     *(achp_work_area + 1) = 0X84;          /* select server           */
     *(achp_work_area + 2) = 0X20;          /* continue load balancing */
     *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
     memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
     ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_cur = achp_work_area;
     ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_end = achp_work_area + 3;
     m_delete();                            /* delete this class       */
     return ied_atr_end;                    /* authorisation completed */
#endif
//#ifdef B140131
     adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
     /* already buffer in adsl_sdhc1_out_to_client                     */
//#endif
     memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
     *(ADSL_DATA_G1 + 0) = 0X05;            /* socks 5 response        */
     *(ADSL_DATA_G1 + 1) = 0X84;            /* select server           */
     *(ADSL_DATA_G1 + 2) = 0X20;            /* continue load balancing */
     ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 3;
     adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_DATA_G1
     m_auth_delete( adsp_pd_work, adsl_conn1_l->adsc_wsp_auth_1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsl_wa1 = NULL;                       /* no more structure for authentication */
     /* start load-balancing                                           */
#ifndef HL_UNIX
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_lbal;  /* status do load-balancing */
#else
     ADSL_CONN1_G->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
#endif
     goto p_send_cl_00;                     /* send encrypted to client */
   }
   if (iel_set_def != ied_set_pttd) {       /* not PASS THRU TO DESKTOP */
#ifdef XYZ1
     *ainplenout = 1 + sprintf( achp_work_area, "xsradiq1-e030 WSP-Socks-mode select server invalid type %d.",
                                iel_set_def );
     *aapout = achp_work_area;              /* output work area        */
     iec_rqc = ied_rqc_abend;               /* abend requested         */
#ifdef PROB_NEDAP_050620
     inrc_prob_trace[3] = __LINE__;
     inrc_prob_trace[4] = ied_atr_display;
#endif
     return ied_atr_display;                /* do display now          */
#endif
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d select server invalid type %d.",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta,
                     __LINE__, iel_set_def );
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   adsl_wan->imc_inpds_v1 = 1;              /* set get only parameters */
   if (adsl_rctrl1 == NULL) {               /* no radius control       */
     goto p_pttd_db_00;                     /* PASS THRU TO DESKTOP from database */
   }
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d Desktop-on-Demand not implemented with Radius",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta,
                     __LINE__ );
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
#ifdef XYZ1
   goto pdoco00;                            /* do connect              */

   paute68:                                 /* parameters have been checked */
#endif

   p_pttd_db_00:                            /* PASS THRU TO DESKTOP from database */
#define ADSL_USENT_G (*adsl_wan->aadsc_usent)
   if (ADSL_USENT_G->boc_with_target == FALSE) {  /* target is not included */
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d Desktop-on-Demand not configured in XML-DB",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta,
                     __LINE__ );
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr) );
   memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
   adsl_cpttdt->umc_out_ineta = ADSL_USENT_G->umc_out_ineta;  /* IP address multihomed */
   adsl_cpttdt->achc_target = ADSL_USENT_G->achc_target;  /* INETA target ied_chs_idna_1 */
   adsl_cpttdt->imc_len_target_bytes = ADSL_USENT_G->inc_len_target_bytes;  /* length of target in bytes */
   adsl_cpttdt->imc_port_target = ADSL_USENT_G->inc_port_target;  /* target port */
   adsl_cpttdt->boc_with_macaddr = ADSL_USENT_G->boc_with_macaddr;  /* macaddr is included */
   memcpy( adsl_cpttdt->chrc_macaddr,       /* macaddr switch on       */
           ADSL_USENT_G->chrc_macaddr,
           sizeof(adsl_cpttdt->chrc_macaddr) );
   iml1 = adsl_cpttdt->imc_waitconn = ADSL_USENT_G->inc_waitconn;  /* wait for connect compl */
#undef ADSL_USENT_G

   p_pttd_sta_00:                           /* start PASS THRU TO DESKTOP */
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
   *(ADSL_DATA_G1 + 0) = 0X05;              /* socks 5 response        */
   *(ADSL_DATA_G1 + 1) = 0X84;              /* select server           */
   *(ADSL_DATA_G1 + 2) = 0X10;              /* wait for server to connect + sec */
   iml2 = 0;                                /* number of digits        */
   while (TRUE) {                           /* loop output NHASN       */
     iml2++;                                /* one digit more          */
     iml3 = iml1;                           /* get number              */
     achl_w1 = ADSL_DATA_G1 + 3 + iml2;       /* end output              */
     chl1 = 0;                              /* reset more bit          */
     while (TRUE) {                         /* loop over digits        */
       *(--achl_w1) = (char) ((iml3 & 0X7F) | chl1);  /* output digits */
       iml3 >>= 7;                          /* remove 7 bits           */
       if (iml3 == 0) break;                /* all done                */
       if (achl_w1 == (ADSL_DATA_G1 + 3)) break;   /* not enough space */
       chl1 = (char) 0X80;                  /* set more bit            */
     }
     if (iml3 == 0) break;                  /* was enough space        */
   }
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 3 + iml2;
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_DATA_G1
   adsl_cpttdt->adsc_conn1 = adsl_conn1_l;  /* for this connection     */
   adsl_conn1_l->adsc_cpttdt = adsl_cpttdt;  /* connect active now     */
   m_pd_auth_start_pttd( adsp_pd_work, adsl_cpttdt );
   goto p_send_cl_00;                       /* send encrypted to client */

#ifdef XYZ1
#define ADSL_RQCONN ((struct dsd_radqu_connect *) achp_work_area)
   if (ADSL_RQCONN->boc_with_target == FALSE) {
     goto pssfa00;                          /* select server failed    */
   }
   iml1 = ADSL_RQCONN->imc_waitconn;        /* time in seconds         */
#undef ADSL_RQCONN
   *((unsigned char *) achp_work_area + 0) = 0X05;  /* socks 5 response */
   *((unsigned char *) achp_work_area + 1) = 0X84;  /* select server   */
   *((unsigned char *) achp_work_area + 2) = 0X10;  /* wait for server to connect + sec */
   iml2 = 0;                                /* number of digits        */
   while (TRUE) {                           /* loop output NHASN       */
     iml2++;                                /* one digit more          */
     iml3 = iml1;                           /* get number              */
     achl1 = achp_work_area + 3 + iml2;     /* end output              */
     chl1 = 0;                              /* reset more bit          */
     while (TRUE) {                         /* loop over digits        */
       *(--achl1) = (char) ((iml3 & 0X7F) | chl1);  /* output digits   */
       iml3 >>= 7;                          /* remove 7 bits           */
       if (iml3 == 0) break;                /* all done                */
       if (achl1 == (achp_work_area + 3)) break;   /* not enough space */
       chl1 = (char) 0X80;                  /* set more bit            */
     }
     if (iml3 == 0) break;                  /* was enough space        */
   }
   *aapout = achp_work_area + inp_len_work_area - sizeof(struct dsd_gather_i_1);  /* output work area */
   memset( *aapout, 0, sizeof(struct dsd_gather_i_1) );
   ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_cur = achp_work_area;
   ((struct dsd_gather_i_1 *) *aapout)->achc_ginp_end = achp_work_area + 3 + iml2;
   iec_rqc = ied_rqc_connect;               /* do connect              */
#ifdef PROB_NEDAP_050620
   inrc_prob_trace[3] = __LINE__;
   inrc_prob_trace[4] = ied_atr_input;
#endif
   return ied_atr_input;                    /* wait for more input     */
#endif
#ifdef NOT_YET_120220
#define ADSL_S_CONN ((struct dsd_wspat3_conn *) dsl_wspat3_1.ac_exc_aux)
   iml1 = m_len_vx_ucs( ied_chs_idna_1, &ADSL_S_CONN->dsc_ucs_target );  /* length INETA DNS / IPV4 / IPV6 */
   if (iml1 <= 0) {
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d could not copy INETA",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta,
                     __LINE__ );
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
// to-do 30.01.12 KB error message
   }
   adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr) + iml1 + 1 );
   memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
   adsl_cpttdt->adsc_conn1 = adsl_conn1_l;  /* for this connection     */
   adsl_cpttdt->imc_len_target_bytes = iml1;
   adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
   m_cpy_vx_ucs( adsl_cpttdt + 1, iml1, ied_chs_idna_1,
                 &ADSL_S_CONN->dsc_ucs_target );  /* INETA DNS / IPV4 / IPV6 */
   *((char *) (adsl_cpttdt + 1) + iml1) = 0;  /* make zero-terminated  */
   adsl_cpttdt->imc_port_target = ADSL_S_CONN->imc_port;
#ifdef NOT_YET_120130
   adsl_cpttdt->umc_out_ineta = ADSL_RADQUCO->umc_out_ineta;
#endif
   adsl_cpttdt->umc_out_ineta
     = *((UNSIG_MED *) &adsl_conn1_l->adsc_server_conf_1->dsc_bind_out.dsc_soai4.sin_addr);
   adsl_cpttdt->boc_with_macaddr = ADSL_S_CONN->boc_with_macaddr;
   memcpy( adsl_cpttdt->chrc_macaddr, ADSL_S_CONN->chrc_macaddr, sizeof(adsl_cpttdt->chrc_macaddr) );
   adsl_cpttdt->imc_waitconn = ADSL_S_CONN->imc_waitconn;
   adsl_conn1_l->adsc_cpttdt = adsl_cpttdt;  /* connect active now */
   m_pd_auth_start_pttd( adsp_pd_work, adsl_cpttdt );
#undef ADSL_S_CONN
#endif
   return;

   p_err_len_00:                            /* invalid length field    */
   m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d processing input data length of field invalid",
                   adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                   adsl_conn1_l->chrc_ineta,
                   __LINE__ );
// to-do 16.01.12 KB error text
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "error authentication UUUU";
   }
   goto p_ret_err_00;                       /* return after error      */

   p_prog_illogic_00:                       /* program illogic         */
   m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d processing input data program illogic",
                   adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                   adsl_conn1_l->chrc_ineta,
                   __LINE__ );
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "error authentication illogic";
   }
// goto p_ret_err_00;                       /* return after error      */

   p_ret_err_00:                            /* return after error      */
   adsp_pd_work->boc_eof_server = TRUE;     /* End-of-File Server      */
   if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
     adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
   }
   adsp_pd_work->boc_abend = TRUE;          /* abend of session        */
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
   m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = NULL;    /* no more structure for authentication */
   return;                                  /* nothing more to do      */
#ifdef OLD_1112
// end new 26.12.11 KB
   iel_function = ied_atf_normal;           /* normal processing       */
   if (ADSL_CONN1_G->adsc_radqu->boc_connect_active) {  /* has to do connect */
     if (ADSL_CONN1_G->adsc_radqu->boc_did_connect == FALSE) return;  /* did not yet connect */
     ADSL_CONN1_G->adsc_radqu->boc_connect_active = FALSE;  /* no more do connect */
     iel_function = ied_atf_connect_ok;     /* connect succeeded       */
     if (ADSL_CONN1_G->adsc_radqu->imc_connect_error) {   /* connect with error */
       iel_function = ied_atf_connect_failed;  /* connect failed       */
     }
   }
   if (   (ADSL_CONN1_G->adsc_radqu->imc_len_received)  /* length radius received */
       || (ADSL_CONN1_G->adsc_radqu->boc_timed_out)) {  /* received timed out */
     m_aux_timer_del( ADSL_CONN1_G, ied_src_fu_radius, NULL );  /* delete timer */
   }
#ifdef B080609
   if (ADSL_CONN1_G->adsc_gate1->adsc_hlwspat2_lib1) {  /* authentication library */
     goto pauth40;                          /* call HOBWSPAT2          */
   }
#endif
   if (ADSL_CONN1_G->adsc_gate1->adsc_hobwspat2_ext_lib1) {  /* authentication library */
     goto pauth40;                          /* call HOBWSPAT2          */
   }
// adsl_gai1_w1 = NULL;
   adsl_sdhc1_work_frse = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_work_frse, 0, sizeof(struct dsd_sdh_control_1) );

   pauth24:                                 /* call radius function    */
   alout = NULL;                            /* no output yet           */
   iml1 = 0;                                /* clear length output     */
   iel_return = ADSL_CONN1_G->adsc_radqu->m_proc_rad_data( iel_function,
                  adsp_pd_work->adsc_gai1_i,
                  &alout, &iml1,
                  (char *) (adsl_sdhc1_work_frse + 1),
                  LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) );  /* length work-area */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d m_proc_rad_data returned=%d alout=%p iml1=%d",
                   __LINE__, iel_return, alout, iml1 );
#endif
   adsl_gai1_w1 = adsp_pd_work->adsc_gai1_i;  /* get data for later processing */
#ifndef B060507
/* 14.11.05 KB - input used as output, not freed */
   adsp_pd_work->adsc_gai1_i = NULL;
#endif
   switch (iel_return) {
     case ied_atr_end:                      /* end of authentication   */
#ifdef TRACEHL_USER_080202
       m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d ied_atr_end=%d adsc_user_entry=%p &aue=%p.",
                       __LINE__, ied_atr_end, ADSL_CONN1_G->adsc_user_entry, &ADSL_CONN1_G->adsc_user_entry );
#endif
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       if (alout == NULL) {                 /* no output returned      */
         m_proc_free( adsl_sdhc1_work_frse );  /* free memory area     */
         adsl_sdhc1_work_frse = NULL;       /* no more storage         */
         break;
       }
       adsl_sdhc1_work_frse->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) alout;
#ifdef B090731
       adsp_pd_work->adsc_sdhc1_client = adsl_sdhc1_work_frse;  /* send data to client */
#endif
       /* send data to client after SSL encryption                     */
       adsl_sdhc1_work_frse->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_work_frse->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
       adsl_sdhc1_work_frse->boc_ready_t_p = TRUE;  /* ready to process */
#endif
       adsl_sdhc1_work_frse->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
       adsl_sdhc1_w2 = NULL;                /* clear previous in chain */
#ifndef B100831
       adsl_sdhc1_w3 = NULL;                /* clear first entry       */
#endif
       while (adsl_sdhc1_w1) {              /* loop over all buffers   */
         if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifndef B100831
         if (   (adsl_sdhc1_w1->inc_position == MAX_SERVER_DATA_HOOK)  /* position send to client */
             && (adsl_sdhc1_w1->adsc_gather_i_1_i)  /* data appended   */
             && (adsl_sdhc1_w3 == NULL)) {
           adsl_sdhc1_w3 = adsl_sdhc1_w1;   /* save first entry        */
         }
#endif
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save previous in chain  */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       adsl_sdhc1_work_frse->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
       if (adsl_sdhc1_w2 == NULL) {         /* is start of chain now   */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_work_frse;  /* set new chain */
       } else {                             /* middle in chain         */
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_work_frse;  /* set in chain */
       }
#ifndef B100831
       if (adsl_sdhc1_w3) {                 /* we need to append to gather */
         adsl_gai1_w1 = adsl_sdhc1_w3->adsc_gather_i_1_i;  /* get first gather */
         while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* search end of chain */
         adsl_gai1_w1->adsc_next = adsl_sdhc1_work_frse->adsc_gather_i_1_i;  /* append new data */
       }
#endif
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
       if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) break;
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_function >= 0) break;
       /* start load-balancing                                         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_lbal;  /* status do load-balancing */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
#endif
       break;
     case ied_atr_other_prot:               /* other protocol selected */
       bol_http = TRUE;                     /* do try HTTP             */
       goto pauth80;                        /* protocol is HTTP        */
     case ied_atr_connect:                  /* do connect now          */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d m_proc_rad_data returned connect",
                       __LINE__ );
#endif
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_function < 0) {
         /* has to do load-balancing                                   */
         iel_function = ied_atf_connect_ok;  /* connect succeeded      */
         goto pauth24;                      /* call radius function    */
       }
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
       if (alout == NULL) {                 /* no output returned      */
         m_proc_free( adsl_sdhc1_work_frse );  /* free memory area     */
         adsl_sdhc1_work_frse = NULL;       /* no more storage         */
         break;
       }
#define ADSL_RADQUCO ((struct dsd_radqu_connect *) alout)
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_PTTD) {
         adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr)
                           + ADSL_RADQUCO->imc_len_target_bytes );
         memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
         if (ADSL_RADQUCO->imc_len_target_bytes) {
           memcpy( adsl_cpttdt + 1,
                   (char *) (ADSL_RADQUCO + 1) + ADSL_RADQUCO->imc_len_name_bytes,
                   ADSL_RADQUCO->imc_len_target_bytes );
           adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
         } else {
           adsl_cpttdt->achc_target = ADSL_RADQUCO->achc_target;
         }
         adsl_cpttdt->adsc_conn1 = ADSL_CONN1_G;  /* for this connection */
         adsl_cpttdt->inc_len_target_bytes = ADSL_RADQUCO->imc_len_target_bytes;
         adsl_cpttdt->inc_port_target = ADSL_RADQUCO->imc_port_target;
         adsl_cpttdt->umc_out_ineta = ADSL_RADQUCO->umc_out_ineta;
#ifdef B070917
         if (adsl_cpttdt->umc_out_ineta == INADDR_ANY) {
           adsl_cpttdt->umc_out_ineta = ADSL_CONN1_G->adsc_server_conf_1->umc_out_ineta;
         }
#endif
// 24.09.07 to-do KB
         adsl_cpttdt->boc_with_macaddr = ADSL_RADQUCO->boc_with_macaddr;
         memcpy( adsl_cpttdt->chrc_macaddr, ADSL_RADQUCO->chrc_macaddr, sizeof(adsl_cpttdt->chrc_macaddr) );
         adsl_cpttdt->inc_waitconn = ADSL_RADQUCO->imc_waitconn;
         ADSL_CONN1_G->adsc_cpttdt = adsl_cpttdt;  /* connect active now */
#ifdef B100810
         iml_rc = adsl_cpttdt->dsc_event_thr.m_create( &iml1 );
         if (iml_rc) {                      /* error occured           */
           m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d Event Create conn_pttd Error %d/%d.",
                           __LINE__, iml_rc, iml1 );
         }
#ifndef HL_UNIX
         ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#else
         ADSL_CONN1_G->iec_st_ses = ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#endif
         iml_rc = adsl_cpttdt->dsc_thread.mc_create( &m_conn_pttd_thread, adsl_cpttdt );
         if (iml_rc == -1) {
           m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d CreateThread conn_pttd Error",
                           __LINE__ );
         }
         iml_rc = adsl_cpttdt->dsc_event_thr.m_post( &iml1 );
         if (iml_rc) {                      /* error occured           */
           m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d Event Post conn_pttd Error %d/%d.",
                           __LINE__, iml_rc, iml1 );
         }
#endif
         m_pd_auth_start_pttd( adsp_pd_work, adsl_cpttdt );
#undef ADSL_RADQUCO
       }
       m_proc_free( adsl_sdhc1_work_frse );  /* free memory area       */
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
       break;
     case ied_atr_failed:                   /* authentication failed   */
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication failed";
       }
       m_proc_free( adsl_sdhc1_work_frse );  /* free memory area       */
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
       break;
     case ied_atr_err_aux:                  /* error in aux subroutine */
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s radius-authentication err-aux",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication err-aux";
       }
       m_proc_free( adsl_sdhc1_work_frse );  /* free memory area       */
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
       break;
     case ied_atr_input:                    /* wait for more input     */
       if (alout == NULL) {                 /* no output returned      */
         m_proc_free( adsl_sdhc1_work_frse );  /* free memory area     */
         adsl_sdhc1_work_frse = NULL;       /* no more storage         */
         break;
       }
       adsl_sdhc1_work_frse->adsc_gather_i_1_i  = (struct dsd_gather_i_1 *) alout;
#ifdef B090731
       adsp_pd_work->adsc_sdhc1_client = adsl_sdhc1_work_frse;  /* send data to client */
#endif
       /* send data to client after SSL encryption                     */
       adsl_sdhc1_work_frse->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_work_frse->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
       adsl_sdhc1_work_frse->boc_ready_t_p = TRUE;  /* ready to process */
#endif
       adsl_sdhc1_work_frse->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
       adsl_sdhc1_w2 = NULL;                /* clear previous in chain */
#ifndef B100831
       adsl_sdhc1_w3 = NULL;                /* clear first entry       */
#endif
       while (adsl_sdhc1_w1) {              /* loop over all buffers   */
         if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifndef B100831
         if (   (adsl_sdhc1_w1->inc_position == MAX_SERVER_DATA_HOOK)  /* position send to client */
             && (adsl_sdhc1_w1->adsc_gather_i_1_i)  /* data appended   */
             && (adsl_sdhc1_w3 == NULL)) {
           adsl_sdhc1_w3 = adsl_sdhc1_w1;   /* save first entry        */
         }
#endif
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save previous in chain  */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       adsl_sdhc1_work_frse->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
       if (adsl_sdhc1_w2 == NULL) {         /* is start of chain now   */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_work_frse;  /* set new chain */
       } else {                             /* middle in chain         */
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_work_frse;  /* set in chain */
       }
#ifndef B100831
       if (adsl_sdhc1_w3) {                 /* we need to append to gather */
         adsl_gai1_w1 = adsl_sdhc1_w3->adsc_gather_i_1_i;  /* get first gather */
         while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* search end of chain */
         adsl_gai1_w1->adsc_next = adsl_sdhc1_work_frse->adsc_gather_i_1_i;  /* append new data */
       }
#endif
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
       break;
     case ied_atr_display:                  /* display data            */
       if ((iml1 > 0) && (((char *) alout + iml1 - 1) == 0)) iml1--;  /* was zero-terminated */
       m_hlnew_printf( HLOG_XYZ1, "HWSPS026I GATE=%(ux)s SNO=%08d INETA=%s radius-authentication: %.*s",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, iml1, alout );
       iel_function = ied_atf_normal;       /* normal processing       */
       goto pauth24;                        /* call radius function    */
     case ied_atr_auth:                     /* user has authenticated  */
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s radius-authentication Userid: %.*(u8)s",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, iml1, alout );
       iel_function = ied_atf_normal;       /* normal processing       */
       goto pauth24;                        /* call radius function    */
     default:
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s radius-authentication logic-error - returned=%d",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, iel_return );
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication logic-error";
       }
       m_proc_free( adsl_sdhc1_work_frse );  /* free memory area       */
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
       break;
   }
   return;

   pauth40:                                 /* call HOBWSPAT2          */
   adsl_sdhc1_work_frse = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_work_frse, 0, sizeof(struct dsd_sdh_control_1) );
   memset( &dsl_wspat3_1, 0, sizeof(struct dsd_hl_wspat2_1) );
   dsl_wspat3_1.iec_at_function = iel_function;  /* processing as set before */
   dsl_wspat3_1.achc_work_area = (char *) (adsl_sdhc1_work_frse + 1);
   dsl_wspat3_1.inc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
   dsl_wspat3_1.adsc_gather_i_1_in = adsp_pd_work->adsc_gai1_i;
#ifdef OLD01
   dsl_wspat3_1.inc_func = DEF_IFUNC_REFLECT;  /* send output back to client */
#endif
#ifdef B060415B
   dsl_wspat3_1.vpc_userfld = ADSL_CONN1_G;      /* pointer to connection   */
#endif
   dsl_wspat3_1.vpc_userfld = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structure */
   dsl_wspat3_1.amc_aux = &m_cdaux;         /* subroutine              */
   dsl_wspat3_1.ac_ext = ADSL_CONN1_G->adsc_radqu->ac_hlwspat2_ext;
   dsl_wspat3_1.ac_conf = ADSL_CONN1_G->adsc_gate1->vpc_hlwspat2_conf;  /* configuration authentication library */
#ifndef NO_WSP_SOCKS_MODE_01
   /* flags of configuration                                           */
   if (ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
   if (ADSL_CONN1_G->adsc_gate1->inc_no_radius) {  /* radius server defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
#endif

   pauth44:                                 /* call HOBWSPAT2 direct   */
#ifdef B080609
   ADSL_CONN1_G->adsc_gate1->adsc_hlwspat2_lib1->amc_entry( &dsl_wspat3_1 );
#endif
   ADSL_CONN1_G->adsc_gate1->adsc_hobwspat2_ext_lib1->amc_at2_entry( &dsl_wspat3_1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d HOBWSPAT2 amc_at2_entry returned iec_at_return=%d ac_ext=%p adsc_gather_i_1_out=%p",
                   __LINE__,  dsl_wspat3_1.iec_at_return, dsl_wspat3_1.ac_ext, dsl_wspat3_1.adsc_gather_i_1_out );
#endif
   ADSL_CONN1_G->adsc_radqu->ac_hlwspat2_ext = dsl_wspat3_1.ac_ext;
   if (dsl_wspat3_1.adsc_gather_i_1_out) {  /* output from authentication library */
     adsl_sdhc1_work_frse->adsc_gather_i_1_i = dsl_wspat3_1.adsc_gather_i_1_out;
#ifdef B090731
     /* append to output chain                                         */
     if (adsp_pd_work->adsc_sdhc1_client == NULL) {  /* data to send to client returned */
       adsp_pd_work->adsc_sdhc1_client = adsl_sdhc1_work_frse;  /* set new data */
     } else {
       adsl_sdhc1_w1 = adsp_pd_work->adsc_sdhc1_client;  /* data to send to client returned */
       do {                                 /* loop over old entries   */
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save last entry         */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w1);
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_work_frse;  /* set new data */
#ifdef B080327
       adsl_sdhc1_work_frse = NULL;         /* no more storage         */
#endif
     }
#endif
     /* send data to client after SSL encryption                       */
     adsl_sdhc1_work_frse->inc_function = DEF_IFUNC_FROMSERVER;
     adsl_sdhc1_work_frse->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
     adsl_sdhc1_work_frse->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
     adsl_sdhc1_work_frse->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     adsl_sdhc1_w2 = NULL;                  /* clear previous in chain */
#ifndef B100831
     adsl_sdhc1_w3 = NULL;                  /* clear first entry       */
#endif
     while (adsl_sdhc1_w1) {                /* loop over all buffers   */
       if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifndef B100831
       if (   (adsl_sdhc1_w1->inc_position == MAX_SERVER_DATA_HOOK)  /* position send to client */
           && (adsl_sdhc1_w1->adsc_gather_i_1_i)  /* data appended     */
           && (adsl_sdhc1_w3 == NULL)) {
         adsl_sdhc1_w3 = adsl_sdhc1_w1;     /* save first entry        */
       }
#endif
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save previous in chain  */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_work_frse->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
     if (adsl_sdhc1_w2 == NULL) {           /* is start of chain now   */
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_work_frse;  /* set new chain */
     } else {                               /* middle in chain         */
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_work_frse;  /* set in chain */
     }
#ifndef B100831
     if (adsl_sdhc1_w3) {                   /* we need to append to gather */
       adsl_gai1_w1 = adsl_sdhc1_w3->adsc_gather_i_1_i;  /* get first gather */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* search end of chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_work_frse->adsc_gather_i_1_i;  /* append new data */
     }
#endif
#ifndef B080327
     adsl_sdhc1_work_frse = NULL;           /* no more storage         */
#endif
#ifdef B060430
   } else if (dsl_wspat3_1.iec_at_return != ied_atr_connect) {  /* no output */
#endif
   } else {
     m_proc_free( adsl_sdhc1_work_frse );   /* free memory area        */
     adsl_sdhc1_work_frse = NULL;           /* no more storage         */
   }
#ifdef XYZ1
#ifndef B090629
   adsl_gai1_w1 = NULL;                     /* clear data in use later */
#endif
#endif
   switch (dsl_wspat3_1.iec_at_return) {    /* check what returned     */
     case ied_atr_input:                    /* wait for more input     */
       return;                              /* all done                */
     case ied_atr_end:                      /* end of authentication   */
#ifdef TRACEHL_USER_080202
       m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d ied_atr_end=%d adsc_user_entry=%p &aue=%p.",
                       __LINE__, ied_atr_end, ADSL_CONN1_G->adsc_user_entry, &ADSL_CONN1_G->adsc_user_entry );
#endif
       goto pauth80;                        /* call radius function end */
     case ied_atr_other_prot:               /* other protocol selected */
       bol_http = TRUE;                     /* do try HTTP             */
#ifndef B090629
       adsl_gai1_w1 = adsp_pd_work->adsc_gai1_i;  /* get data for later processing */
       adsp_pd_work->adsc_gai1_i = NULL;    /* data processed so far   */
#endif
       goto pauth80;                        /* protocol is HTTP        */
     case ied_atr_connect:                  /* do connect now          */
       goto pauth48;                        /* process connect         */
     case ied_atr_failed:                   /* authentication failed   */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication Library HOBWSPAT2 failed";
       }
       goto pauth80;                        /* call radius function end */
     case ied_atr_err_aux:                  /* error in aux subroutine */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication Library HOBWSPAT2 err-aux";
       }
       goto pauth80;                        /* call radius function end */
     case ied_atr_send_client:              /* only data to send to the client */
       adsl_sdhc1_work_frse = (struct dsd_sdh_control_1 *) m_proc_alloc();
       memset( adsl_sdhc1_work_frse, 0, sizeof(struct dsd_sdh_control_1) );
       dsl_wspat3_1.achc_work_area = (char *) (adsl_sdhc1_work_frse + 1);
       dsl_wspat3_1.inc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
       dsl_wspat3_1.adsc_gather_i_1_out = NULL;  /* no output from authentication library yet */
       goto pauth44;                        /* call HOBWSPAT2 direct   */
     default:
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s Authentication Library HOBWSPAT2 returned invalid value %d",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, dsl_wspat3_1.iec_at_return );
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication Library HOBWSPAT2 inv-ret";
       }
       goto pauth80;                        /* call radius function end */
   }
   return;

   pauth48:                                 /* connect for HOBWSPAT2   */
#define ADSL_S_CONN ((struct dsd_hlwspat2_conn *) dsl_wspat3_1.ac_exc_aux)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d ADSL_S_CONN=%p iec_hconn=%d",
                   __LINE__, ADSL_S_CONN, ADSL_S_CONN->iec_hconn );
#endif
   if (ADSL_S_CONN->vpc_servent) {          /* handle to server entry  */
     ADSL_CONN1_G->adsc_server_conf_1
       = (struct dsd_server_conf_1 *) ADSL_S_CONN->vpc_servent;
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh >= 2) {
       ADSL_CONN1_G->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
       memset( ADSL_CONN1_G->adsrc_sdh_s_1, 0, ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
     }
   }
   switch (ADSL_S_CONN->iec_hconn) {
     case ied_hconn_def_servent:
       break;
     case ied_hconn_pttd:                   /* pass thru to desktop    */
       iml1 = 0;                            /* clear length INETA      */
       if (ADSL_S_CONN->achc_ineta) {       /* INETA given as parameter */
         iml1 = strlen( ADSL_S_CONN->achc_ineta ) + 1;
       }
       adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr)
                         + iml1 );
       memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
       if (iml1) {                          /* with INETA              */
         memcpy( adsl_cpttdt + 1, ADSL_S_CONN->achc_ineta, iml1 );
         adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
         adsl_cpttdt->inc_len_target_bytes = iml1 - 1;
       }
       adsl_cpttdt->adsc_conn1 = ADSL_CONN1_G;  /* for this connection */
       adsl_cpttdt->inc_port_target = ADSL_S_CONN->inc_port;
       adsl_cpttdt->umc_out_ineta = ADSL_S_CONN->umc_out_ineta;
#ifdef B070917
       if (adsl_cpttdt->umc_out_ineta == INADDR_ANY) {
         adsl_cpttdt->umc_out_ineta = ADSL_CONN1_G->adsc_server_conf_1->umc_out_ineta;
       }
#endif
// 24.09.07 to-do KB
       adsl_cpttdt->boc_with_macaddr = ADSL_S_CONN->boc_with_macaddr;
       memcpy( adsl_cpttdt->chrc_macaddr, ADSL_S_CONN->chrc_macaddr, sizeof(adsl_cpttdt->chrc_macaddr) );
       adsl_cpttdt->inc_waitconn = ADSL_S_CONN->inc_waitconn;
       ADSL_CONN1_G->adsc_cpttdt = adsl_cpttdt;  /* connect active now */
#ifdef B100810
       iml_rc = adsl_cpttdt->dsc_event_thr.m_create( &iml1 );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d Event Create conn_pttd Error %d/%d.",
                         __LINE__, iml_rc, iml1 );
       }
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#endif
       iml_rc = adsl_cpttdt->dsc_thread.mc_create( &m_conn_pttd_thread, adsl_cpttdt );
       if (iml_rc == -1) {
         m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d CreateThread conn_pttd Error",
                         __LINE__ );
       }
       iml_rc = adsl_cpttdt->dsc_event_thr.m_post( &iml1 );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "m_pd_auth1() l%05d Event Post conn_pttd Error %d/%d.",
                         __LINE__, iml_rc, iml1 );
       }
#endif
       m_pd_auth_start_pttd( adsp_pd_work, adsl_cpttdt );
#ifdef B090716
       break;
#else
       ADSL_CONN1_G->adsc_radqu->boc_did_connect = FALSE;  /* did not yet connect */
       ADSL_CONN1_G->adsc_radqu->boc_connect_active = TRUE;  /* has to do connect */
       return;
#endif
     default:
       break;
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)
       && (ADSL_CONN1_G->adsc_server_conf_1->inc_function < 0)) {
     /* has to do load-balancing                                       */
     iel_function = ied_atf_connect_ok;     /* connect succeeded       */
     goto pauth40;                          /* call HOBWSPAT2          */
   }
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
   ADSL_CONN1_G->adsc_radqu->boc_did_connect = FALSE;  /* did not yet connect */
   ADSL_CONN1_G->adsc_radqu->boc_connect_active = TRUE;  /* has to do connect */
   return;
#undef ADSL_S_CONN

   pauth80:                                 /* call radius function end */
   if (adsl_sdhc1_work_frse == NULL) {      /* no storage in stock     */
     adsl_sdhc1_work_frse = (struct dsd_sdh_control_1 *) m_proc_alloc();
   }
   alout = NULL;                            /* no output yet           */
   iml1 = 0;                                /* clear length output     */
   iel_return = ADSL_CONN1_G->adsc_radqu->m_proc_rad_data( ied_atf_abend,
                  adsp_pd_work->adsc_gai1_i,
                  &alout, &iml1,
                  (char *) (adsl_sdhc1_work_frse + 1),
                  LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) );  /* length work-area */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d m_proc_rad_data ied_atf_abend returned=%d alout=%p iml1=%d",
                   __LINE__, iel_return, alout, iml1 );
#endif
   switch (iel_return) {
     case ied_atr_end:                      /* end of authentication   */
#ifdef TRACEHL_USER_080202
       m_hlnew_printf( HLOG_XYZ1, "m_pd_auth1() l%05d ied_atr_end=%d adsc_user_entry=%p &aue=%p.",
                       __LINE__, ied_atr_end, ADSL_CONN1_G->adsc_user_entry, &ADSL_CONN1_G->adsc_user_entry );
#endif
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) break;
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_function >= 0) break;
       /* start load-balancing                                         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_lbal;  /* status do load-balancing */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
#endif
       break;
     case ied_atr_failed:                   /* authentication failed   */
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication failed";
       }
       bol_http = FALSE;                    /* do not try HTTP         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
       break;
     case ied_atr_err_aux:                  /* error in aux subroutine */
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s radius-authentication err-aux",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication err-aux";
       }
       bol_http = FALSE;                    /* do not try HTTP         */
#ifndef HL_UNIX
       ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
       ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
       break;
     case ied_atr_display:                  /* display data            */
       if ((iml1 > 0) && (((char *) alout + iml1 - 1) == 0)) iml1--;  /* was zero-terminated */
       m_hlnew_printf( HLOG_XYZ1, "HWSPS026I GATE=%(ux)s SNO=%08d INETA=%s radius-authentication: %.*s",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, iml1, alout );
       goto pauth80;                        /* call radius function    */
     default:                               /* return code invalid     */
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s radius-authentication logic-error - returned=%d",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta, iel_return );
       ADSL_CONN1_G->adsc_radqu = NULL;     /* class no more active    */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "Authentication logic-error";
       }
       bol_http = FALSE;                    /* do not try HTTP         */
       break;
   }
   m_proc_free( adsl_sdhc1_work_frse );     /* free memory area        */
   adsl_sdhc1_work_frse = NULL;             /* no more storage         */
   if (bol_http == FALSE) return;           /* do not try HTTP         */

   pa_http_00:                              /* protocol is HTTP, SSTP, MS-RPC or RDG */
   achl_w1 = chrl_work1;                    /* area to put request in  */
   iml1 = sizeof(chrl_work1);               /* size of area area       */
   while (adsl_gai1_w1) {                   /* loop over input data    */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;          /* only as much as needed  */
     memcpy( achl_w1, adsl_gai1_w1->achc_ginp_cur, iml2 );
     achl_w1 += iml2;                       /* increment output pointer */
     iml1 -= iml2;                          /* decrement length remaining */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (achl_w1 < (chrl_work1 + 4 + 1)) return;  /* wait for more data  */
   achl_w1 = "HTTP";                        /* default protocol        */
   iel_scp_def = ied_scp_http;              /* protocol HTTP           */
   if (!memcmp( chrl_work1, "SSTP_", 5 )) {
     achl_w1 = "SSTP";                      /* SSTP protocol           */
     iel_scp_def = ied_scp_sstp;            /* protocol SSTP           */
   }
   if (!memcmp( chrl_work1, "RPC_", 4 )) {
     achl_w1 = "MS-RPC";                    /* MS-RPC protocol         */
     iel_scp_def = ied_scp_ms_rpc;          /* protocol MS-RPC         */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d before check HTTP/SSTP/MS-RPC iel_scp_def=%d",
                   __LINE__, iel_scp_def );
#endif

#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + iml1) * sizeof(void *))))
   iml1 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* start in reverse order */
   while (TRUE) {                           /* loop over all server-entries */
     iml1--;                                /* check next entry        */
     if (iml1 < 0) break;                   /* was last server-entry   */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data check l%05d %s ADSL_CONN1_G->adsc_gate1->inc_no_seli=%d iml1=%d ADSL_SELSERV_1=%p *=%p",
                       __LINE__, achl_w1,
                       ADSL_CONN1_G->adsc_gate1->inc_no_seli, iml1,
                       ADSL_SELSERV_1, *((void **) ADSL_SELSERV_1) );
#endif
     /* get anchor of chain server conf                                */
     adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d check HTTP/SSTP adsl_server_conf_1_w1=%p ...->iec_scp_def=%d",
                       __LINE__, adsl_server_conf_1_w1, adsl_server_conf_1_w1->iec_scp_def );
#endif
       /* protocol HTTP, SSTP or MS-RPC                                */
       if (adsl_server_conf_1_w1->iec_scp_def == iel_scp_def) {
         ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1;  /* set this server */
         if (adsl_server_conf_1_w1->inc_no_sdh >= 2) {
           ADSL_CONN1_G->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
           memset( ADSL_CONN1_G->adsrc_sdh_s_1, 0, adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
         }
         m_hlnew_printf( HLOG_XYZ1, "HWSPS020I GATE=%(ux)s SNO=%08d INETA=%s select-server %s %(ux)s",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                         ADSL_CONN1_G->chrc_ineta,
                         achl_w1,
                         (char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1)
                           + ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh
                             * sizeof(struct dsd_sdh_work_1) );
#ifndef HL_UNIX
         ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
         ADSL_CONN1_G->m_start_rec_server( adsp_pd_work );  /* open connection server */
         if (   (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_error_conn)  /* status server error */
             && (ADSL_CONN1_G->achc_reason_end == NULL)) {  /* reason end session */
           switch (iel_scp_def) {           /* check protocol          */
             case ied_scp_http:             /* protocol HTTP           */
               ADSL_CONN1_G->achc_reason_end = "connect to HTTP-Server failed";
               break;
             case ied_scp_sstp:             /* protocol SSTP           */
               ADSL_CONN1_G->achc_reason_end = "connect SSTP failed";
               break;
             case ied_scp_ms_rpc:           /* protocol MS-RPC         */
               ADSL_CONN1_G->achc_reason_end = "connect to MS-RPC-Server failed";
               break;
           }
         }
#else
         ADSL_CONN1_G->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
         m_start_rec_server( adsp_pd_work );  /* open connection server */
         if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_error_conn)  /* status server error */
             && (ADSL_CONN1_G->achc_reason_end == NULL)) {  /* reason end session */
           switch (iel_scp_def) {           /* check protocol          */
             case ied_scp_http:             /* protocol HTTP           */
               ADSL_CONN1_G->achc_reason_end = "connect to HTTP-Server failed";
               break;
             case ied_scp_sstp:             /* protocol SSTP           */
               ADSL_CONN1_G->achc_reason_end = "connect SSTP failed";
               break;
             case ied_scp_ms_rpc:           /* protocol MS-RPC         */
               ADSL_CONN1_G->achc_reason_end = "connect to MS-RPC-Server failed";
               break;
           }
         }
#endif
         break;
       }
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
     if (adsl_server_conf_1_w1) break;      /* server conf found       */
   }
   if (iml1 < 0) {                          /* no HTTP / SSTP / MS-RPC entry found */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS020I GATE=%(ux)s SNO=%08d INETA=%s select-server %s - no server (protocol %s) defined in server-list",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     achl_w1, achl_w1,
                     (char *) (ADSL_CONN1_G->adsc_server_conf_1 + 1) );
   }
#ifdef DEBUG_100810
#endif
#undef ADSL_SELSERV_1
   return;
#endif
   p_conn_00:                               /* did connect             */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d p_conn_00",
                   __LINE__ );
#endif
   adsl_wa1->boc_did_connect = FALSE;       /* reset did connect       */
   adsl_wa1->boc_connect_active = FALSE;    /* reset has to do connect */
   if (adsl_wa1->imc_connect_error == 0) {  /* check connect error     */
     goto p_conn_40;                        /* connect successful      */
   }
#ifndef B130503
   if (ADSL_CONN1_G->adsc_server_conf_1) {  /* configuration server    */
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh >= 2) {
       free( ADSL_CONN1_G->adsrc_sdh_s_1 );
     }
     ADSL_CONN1_G->adsc_server_conf_1 = NULL;  /* configuration server */
   }
#endif
   bol1 = FALSE;                            /* not abend               */
   if (adsl_wan->boc_hkw_server) {          /* server set in header    */
     bol1 = TRUE;                           /* abend now               */
   }
   if (adsl_wan->imc_inpds_v1 == 0) {       /* no input from client    */
     bol1 = TRUE;                           /* abend now               */
   }
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_GAI1_G2 (ADSL_GAI1_G1 + 1)
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + 2 * sizeof(struct dsd_gather_i_1))
#define ADSL_DATA_G2 (ADSL_DATA_G1 + 8)
   *(ADSL_DATA_G1 + 0) = (unsigned char) 0X05;  /* WSP-socks-mode response */
   *(ADSL_DATA_G1 + 1) = (unsigned char) 0X84;  /* method select server */
   if (bol1 == FALSE) {                     /* not abend               */
     *(ADSL_DATA_G1 + 2) = (unsigned char) (0X40 | 0X08 | 0X02);  /* connect failed, error message, input server entry */
     iml1 = sprintf( ADSL_DATA_G2, "server connect error %d - select other server-entry",
                     adsl_wa1->imc_connect_error );
     adsl_wan->iec_wani = ied_wani_seen_st;  /* start server entry     */
   } else {
     *(ADSL_DATA_G1 + 2) = (unsigned char) (0X40 | 0X08 | 0X01);  /* connect failed, error message, abend */
     iml1 = sprintf( ADSL_DATA_G2, "server connect error %d - session ended",
                     adsl_wa1->imc_connect_error );
     adsp_pd_work->boc_eof_server = TRUE;   /* End-of-File Server      */
     if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
       adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
     }
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
#ifndef HL_UNIX
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
#else
     ADSL_CONN1_G->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
#endif
     m_auth_delete( adsp_pd_work, adsl_conn1_l->adsc_wsp_auth_1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsl_wa1 = NULL;                       /* no more structure for authentication */
     if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn1_l->achc_reason_end = "connect to server failed";
     }
   }
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   ADSL_GAI1_G1->adsc_next = ADSL_GAI1_G2;
   ADSL_GAI1_G2->achc_ginp_cur = ADSL_DATA_G2;
   ADSL_GAI1_G2->achc_ginp_end = ADSL_DATA_G2 + iml1;
   if (iml1 < 0X80) {                       /* only one length byte    */
     *(ADSL_DATA_G1 + 3) = (unsigned char) iml1;  /* set length byte   */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 4;
   } else {                                 /* length in two bytes     */
     *(ADSL_DATA_G1 + 3 + 0) = (unsigned char) ((iml1 >> 7) | 0X80);  /* length first byte */
     *(ADSL_DATA_G1 + 3 + 1) = (unsigned char) (iml1 & 0X7F);  /* length second byte */
     ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 5;
   }
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_GAI1_G2
#undef ADSL_DATA_G1
#undef ADSL_DATA_G2
   goto p_send_cl_00;                       /* send encrypted to client */

   p_conn_40:                               /* connect successful      */
   adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
#ifdef DEBUG_130919_01                      /* problem DoD             */
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d p_conn_04 adsl_sdhc1_out_to_client=%p.",
                   __LINE__, adsl_sdhc1_out_to_client );
#endif
   memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_out_to_client + 1))
#define ADSL_DATA_G1 ((char *) adsl_sdhc1_out_to_client + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1))
   ADSL_GAI1_G1->achc_ginp_cur = ADSL_DATA_G1;
   *(ADSL_DATA_G1 + 0) = (unsigned char) 0X05;  /* WSP-socks-mode response */
   *(ADSL_DATA_G1 + 1) = (unsigned char) 0X84;  /* method select server */
   *(ADSL_DATA_G1 + 2) = (unsigned char) 0X80;  /* connect successful  */
   ADSL_GAI1_G1->achc_ginp_end = ADSL_DATA_G1 + 3;
   adsl_sdhc1_out_to_client->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* set chain data */
#undef ADSL_GAI1_G1
#undef ADSL_DATA_G1
// to-do 27.12.11 KB free storage
   m_auth_delete( adsp_pd_work, adsl_conn1_l->adsc_wsp_auth_1 );  /* free all fields of authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = NULL;    /* no more structure for authentication */
   adsl_wa1 = NULL;                         /* no more structure for authentication */
/**
//ifdef B130919
for cascaded WSPs, output of SDHs, which is normally sent to the client,
needs to go thru the authentication library.
so the authentication library sends its output on stage MAX_SERVER_DATA_HOOK + 1
but when the authentication library is ended,
this output needs to go to MAX_SERVER_DATA_HOOK.
*/

// new 26.12.11 KB
   p_send_cl_00:                            /* send encrypted to client */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d p_send_cl_00 adsl_wa1=%p adsl_sdhc1_out_to_client=%p.",
                   __LINE__, adsl_wa1, adsl_sdhc1_out_to_client );
#endif
   adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* get chain of blocks to send */
   while (TRUE) {                           /* loop over all blocks to send */
     adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;
#ifdef B130919
     adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK + 1;  /* position send to client */
#else
     adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#endif
#ifndef B140328
     adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
#endif
     if (adsl_sdhc1_w1->adsc_next == NULL) break;  /* was last in chain */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_w2 = NULL;                    /* clear last in chain     */
   adsl_gai1_w1 = NULL;                     /* no gather to append to  */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifdef B130919
     if (adsl_sdhc1_cur_1->inc_position == (MAX_SERVER_DATA_HOOK + 1)) {  /* position send to client */
       if (adsl_gai1_w1 == NULL) {          /* no gather to append to  */
         adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
       }
     }
#else
     if (adsl_sdhc1_cur_1->inc_position == MAX_SERVER_DATA_HOOK) {  /* position send to client */
       if (adsl_gai1_w1 == NULL) {          /* no gather to append to  */
         adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
       }
     }
#endif
     adsl_sdhc1_w2 = adsl_sdhc1_cur_1;      /* set last in chain       */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_w2 == NULL) {             /* insert at beginning of chain */
     adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get old chain */
     ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_out_to_client;  /* set new chain */
#ifdef B140328
     if (adsl_wa1) return;                  /* send data to client     */
     goto p_cha_blo_00;                     /* change block when authentication has ended */
#endif
     goto p_send_cl_20;                     /* buffers have been inserted in session-wide chain */
   }
   adsl_sdhc1_w1->adsc_next = adsl_sdhc1_w2->adsc_next;  /* get remaining chain */
   adsl_sdhc1_w2->adsc_next = adsl_sdhc1_out_to_client;  /* set remaining chain */
   if (adsl_gai1_w1) {                      /* gather to append to     */
     while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
     adsl_gai1_w1->adsc_next = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* last in chain this shdc1 */
   }

   p_send_cl_20:                            /* buffers have been inserted in session-wide chain */
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( adsl_conn1_l, "m_pd_auth1() output to client", __LINE__ );
#endif
#ifndef B140305
   if (bol_proc_servli) {                   /* needs to process server-list */
     goto p_servli_00;                      /* process server-list     */
   }
#endif
   if (adsl_wa1) return;                    /* send data to client     */
   goto p_cha_blo_00;                       /* change block when authentication has ended */

   p_atlib_00:                              /* process authentication-library */
   if (adsl_conn1_l->adsc_wsp_auth_1) goto p_atlib_20;  /* structure for authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = (struct dsd_wsp_auth_1 *) malloc( sizeof(struct dsd_wsp_auth_1) + sizeof(void *) );  /* structure for authentication radius */
   memset ( adsl_conn1_l->adsc_wsp_auth_1, 0, sizeof(struct dsd_wsp_auth_1) + sizeof(void *) );  /* authentication over library */

   p_atlib_20:                              /* process authentication-library */
   adsl_wa1 = adsl_conn1_l->adsc_wsp_auth_1;  /* structure for authentication */
   adsl_wa1->boc_notify = FALSE;            /* reset notify authentication routine */

   p_atlib_40:                              /* call authentication-library */
#define AADSL_AC_EXT ((void **) (adsl_wa1 + 1))
   memset( &dsl_wspat3_1, 0, sizeof(struct dsd_wspat3_1) );  /* HOB Authentication Library V3 - 1 */
// dsl_wspat3_1.iec_at_function = iel_function;  /* processing as set before */
// dsl_wspat3_1.achc_work_area = (char *) (adsl_sdhc1_work_frse + 1);
   ADSL_AUX_CF1->adsc_sdhc1_chain = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_01
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_next = NULL;  /* is only element */
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_usage_count = NULL;  /* clear usage count */
   dsl_wspat3_1.achc_work_area = (char *) (ADSL_AUX_CF1->adsc_sdhc1_chain + 1);
   dsl_wspat3_1.imc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
// dsl_wspat3_1.adsc_gather_i_1_in = adsp_pd_work->adsc_gai1_i;
   dsl_wspat3_1.adsc_gai1_in_from_client = adsl_gai1_w1;  /* input data from client */
   dsl_wspat3_1.vpc_userfld = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structure */
   dsl_wspat3_1.amc_aux = &m_cdaux;         /* subroutine              */
   dsl_wspat3_1.ac_ext = *AADSL_AC_EXT;     /* get attached buffer     */
   dsl_wspat3_1.ac_conf = adsl_conn1_l->adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
   /* flags of configuration                                           */
   if (adsl_conn1_l->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (adsl_conn1_l->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (adsl_conn1_l->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (adsl_conn1_l->adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
   dsl_wspat3_1.imc_sno = adsl_conn1_l->dsc_co_sort.imc_sno;  /* session number */
   if (adsl_conn1_l->imc_trace_level & HL_WT_SESS_WSPAT3_INT) {  /* WSP trace HOB WSP-AT-3 intern */
     dsl_wspat3_1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP trace HOB WSP-AT-3 all */
           | (adsl_conn1_l->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
   dsl_wspat3_1.imc_language = adsl_conn1_l->adsc_gate1->imc_language;  /* language configured */
   dsl_wspat3_1.iec_at_function = ied_atf_normal;  /* normal processing */
#ifndef HL_UNIX
   if (   (adsl_conn1_l->iec_servcotype != ied_servcotype_none)  /* with server connection */
       && (adsl_conn1_l->iec_st_ses == clconn1::ied_ses_conn)) {  /* status server */
     dsl_wspat3_1.boc_server_connected = TRUE;  /* connected to server */
   }
#else
   if (   (adsl_conn1_l->iec_servcotype != ied_servcotype_none)  /* with server connection */
       && (adsl_conn1_l->iec_st_ses == ied_ses_conn)) {  /* status server */
     dsl_wspat3_1.boc_server_connected = TRUE;  /* connected to server */
   }
#endif
// dsl_wspat3_1.imc_signal = 0;             /* clear signals occured   */
   if (adsl_conn1_l->boc_signal_set) {      /* signal for component set */
     dsl_wspat3_1.imc_signal = m_ret_signal( &adsp_pd_work->dsc_aux_cf1 );  /* search signal */
   }
   dsl_wspat3_1.boc_eof_client = adsp_pd_work->boc_eof_client;  /* End-of-File Client */
   dsl_wspat3_1.boc_eof_server = adsp_pd_work->boc_eof_server;  /* End-of-File Server */
   if (adsl_wa1->boc_did_connect) {         /* did connect             */
     adsl_wa1->boc_did_connect = FALSE;     /* reset did connect       */
     adsl_wa1->boc_connect_active = FALSE;  /* reset has to do connect */
     if (adsl_wa1->imc_connect_error == 0) {  /* check connect error   */
       dsl_wspat3_1.iec_at_function = ied_atf_connect_ok;  /* connect succeeded */
     } else {                               /* connect returned error  */
// to-do 13.01.12 KB reset server-conf and free memory ???
//   if (adsl_wa1->imc_connect_error == 0)   /* connect error           */
       dsl_wspat3_1.iec_at_function = ied_atf_connect_failed;  /* connect failed */
       dsl_wspat3_1.imc_connect_error = adsl_wa1->imc_connect_error;  /* connect error */
       if (adsl_conn1_l->adsc_server_conf_1) {  /* configuration server */
         if (adsl_conn1_l->adsc_server_conf_1->inc_no_sdh >= 2) {
           free( adsl_conn1_l->adsrc_sdh_s_1 );  /* array work area server data hook per session */
         }
         adsl_conn1_l->adsc_server_conf_1 = NULL;  /* reset configuration server */
       }
     }
   } else {
#ifndef HL_UNIX
     if (adsl_conn1_l->iec_st_ses == clconn1::ied_ses_do_lbal) {  /* status do load-balancing */
#ifdef FORKEDIT
     }
#endif
#else
     if (adsl_conn1_l->iec_st_ses == ied_ses_do_lbal) {  /* status do load-balancing */
#endif
       dsl_wspat3_1.iec_at_function = ied_atf_do_lbal;  /* status doing load-balancing */
     }
   }
   if (adsp_pd_work->boc_abend) {           /* abend of session        */
     dsl_wspat3_1.iec_at_function = ied_atf_abend;  /* function abend  */
   }
   if (adsl_conn1_l->imc_trace_level & HL_WT_SESS_WSPAT3_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SATLCAL1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsl_conn1_l->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = iml3 = iml4 = 0;         /* clear counters          */
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_client;  /* input data from client */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1++;                              /* count gather            */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_server;  /* input data from server */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml3++;                              /* count gather            */
       iml4 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     achl_func = "* undefined *";
     chrl_work1[0] = 0;
     switch (dsl_wspat3_1.iec_at_function) {  /* input function of HOB-WSP-AT3 */
       case ied_atf_normal:                 /* normal processing       */
         achl_func = "ied_atf_normal";
         break;
       case ied_atf_connect_ok:             /* connect succeeded       */
         achl_func = "ied_atf_connect_ok";
         break;
       case ied_atf_connect_failed:         /* connect failed          */
         achl_func = "ied_atf_connect_failed";
         sprintf( chrl_work1, " imc_connect_error=%d", dsl_wspat3_1.imc_connect_error );
         break;
       case ied_atf_do_lbal:                /* status doing load-balancing */
         achl_func = "ied_atf_do_lbal";
         break;
       case ied_atf_abend:                  /* function abend          */
         achl_func = "ied_atf_abend";
         break;
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml7 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "call authentication library %d %s%s - input-data-from-client:g=%d l=%d/0X%X. input-data-from-server:g=%d l=%d/0X%X.",
                     dsl_wspat3_1.iec_at_function, achl_func, chrl_work1,
                     iml1, iml2, iml2, iml3, iml4, iml4 );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml7;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content     */
     ADSL_WTR_G2->achc_content = achl_w4;   /* content of text / data  */
     ADSL_WTR_G2->imc_length = sizeof(struct dsd_wspat3_1);  /* length of text / data */
     adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     adsl_wtr_w1 = ADSL_WTR_G2;             /* this is last in chain now */
     memcpy( achl_w4, &dsl_wspat3_1, sizeof(struct dsd_wspat3_1) );
     achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + sizeof(struct dsd_wspat3_1) + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     if (   (iml1)
         && (adsl_conn1_l->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_client;  /* input data from client */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml7 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml7 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml8 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ call authentication-library in-from-client gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml7, iml7 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml8;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml7;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml8 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml8 > iml7) iml8 = iml7;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml8 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml7 -= iml8;
           } while (iml7 > 0);
// to-do 10.01.12 KB iml7 == 0
//         iml_w2 += iml7;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
     if (   (iml3)
         && (adsl_conn1_l->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_server;  /* input data from server */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml7 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml7 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml8 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ call authentication-library in-from-server gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml7, iml7 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml8;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml7;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml8 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml8 > iml7) iml8 = iml7;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml8 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml7 -= iml8;
           } while (iml7 > 0);
// to-do 10.01.12 KB iml7 == 0
//         iml_w2 += iml7;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_conn1_l->adsc_gate1->adsc_hobwspat3_ext_lib1->amc_at3_entry( &dsl_wspat3_1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d HOB-WSP-AT3 amc_at3_entry returned iec_at_return=%d ac_ext=%p adsc_gai1_out_to_client=%p.",
                   __LINE__,  dsl_wspat3_1.iec_at_return, dsl_wspat3_1.ac_ext, dsl_wspat3_1.adsc_gai1_out_to_client );
#endif
   *AADSL_AC_EXT = dsl_wspat3_1.ac_ext;     /* save attached buffer    */
#undef AADSL_AC_EXT
   if (adsl_conn1_l->imc_trace_level & HL_WT_SESS_WSPAT3_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SATLRET1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsl_conn1_l->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = iml3 = iml4 = iml5 = iml6 = 0;  /* clear counters   */
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_client;  /* input data from client */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_in_from_server;  /* input data from server */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_out_to_client;  /* get chain output data to client */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml3++;                              /* count gather            */
       iml4 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_out_to_server;  /* get chain output data to server */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml5++;                              /* count gather            */
       iml6 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     achl_func = "* undefined *";
     switch (dsl_wspat3_1.iec_at_return) {
       case ied_atr_end:                    /* end of authentication   */
         achl_func = "ied_atr_end";
         break;
       case ied_atr_other_prot:             /* other protocol selected */
         achl_func = "ied_atr_other_prot";
         break;
       case ied_atr_input:                  /* wait for more input     */
         achl_func = "ied_atr_input";
         break;
       case ied_atr_connect:                /* do connect now          */
         achl_func = "ied_atr_connect";
         break;
       case ied_atr_failed:                 /* authentication failed   */
         achl_func = "ied_atr_failed";
         break;
       case ied_atr_start_rec_server:       /* start receiving from the server */
         achl_func = "ied_atr_start_rec_server";
         break;
       case ied_atr_err_aux:                /* error in aux subroutine */
         achl_func = "ied_atr_err_aux";
         break;
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml7 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "returned authentication library %d %s ac_exc_aux=%p - remaining-length-data-input-from-client=%d/0X%X remaining-length-data-input-from-server=%d/0X%X out_to_client:g=%d l=%d/0X%X out_to_server:g=%d l=%d/0X%X.",
                     dsl_wspat3_1.iec_at_return, achl_func, dsl_wspat3_1.ac_exc_aux,
                     iml1, iml1, iml2, iml2, iml3, iml4, iml4, iml5, iml6, iml6 );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml7;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content     */
     ADSL_WTR_G2->achc_content = achl_w4;   /* content of text / data  */
     ADSL_WTR_G2->imc_length = sizeof(struct dsd_wspat3_1);  /* length of text / data */
     adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     adsl_wtr_w1 = ADSL_WTR_G2;             /* this is last in chain now */
     memcpy( achl_w4, &dsl_wspat3_1, sizeof(struct dsd_wspat3_1) );
     achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + sizeof(struct dsd_wspat3_1) + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     if (   (iml4)
         && (adsl_conn1_l->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_out_to_client;  /* get chain output data to client */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml7 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml7 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml8 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ authentication-library returned out-to-client gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml7, iml7 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml8;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml7;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml8 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml8 > iml7) iml8 = iml7;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml8 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml7 -= iml8;
           } while (iml7 > 0);
// to-do 10.01.12 KB iml7 == 0
//         iml_w2 += iml7;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
     if (   (iml6)
         && (adsl_conn1_l->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_wspat3_1.adsc_gai1_out_to_server;  /* get chain output data to server */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml7 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml7 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 80) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml8 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ authentication-library returned out-to-server gather-no=%d disp=0X%X addr=0X%X length=%d/0X%X.",
                           iml_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml7, iml7 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml8;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml7;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml8 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml8 > iml7) iml8 = iml7;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml8 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml7 -= iml8;
           } while (iml7 > 0);
// to-do 10.01.12 KB iml7 == 0
//         iml_w2 += iml7;                  /* increment displacement  */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   adsl_sdhc1_out_to_client = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* output data to client */
   adsl_sdhc1_out_to_server = NULL;         /* output data to server   */
   while (dsl_wspat3_1.adsc_gai1_out_to_server) {  /* check start of chain output data to server */
     if (adsl_conn1_l->iec_servcotype == ied_servcotype_none) {  /* no server connection */
// to-do 07.03.11 KB error message
       m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication-library returned data to send to server - illogic",
                       adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta );
       if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
         adsl_conn1_l->achc_reason_end = "error from authentication-library";
       }
       adsp_pd_work->boc_eof_server = TRUE;  /* End-of-File Server     */
       if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
         adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
       }
       dsl_wspat3_1.boc_callagain = FALSE;  /* do not process last server-data-hook again */
       dsl_wspat3_1.adsc_gai1_out_to_server = NULL;  /* clear start of chain output data to server */
       break;
     }
     if (dsl_wspat3_1.adsc_gai1_out_to_client) {  /* check start of chain output data to client */
       adsl_sdhc1_out_to_server = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_out_to_server, 0, sizeof(struct dsd_sdh_control_1) );
#else
       {
         int imh1 = adsl_sdhc1_out_to_server->imc_line_no[ 0 ];
         memset( adsl_sdhc1_out_to_server, 0, sizeof(struct dsd_sdh_control_1) );
         adsl_sdhc1_out_to_server->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_out_to_server->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
     } else {                               /* only data to server     */
       adsl_sdhc1_out_to_server = adsl_sdhc1_out_to_client;  /* output data to server */
       adsl_sdhc1_out_to_client = NULL;     /* output data to client   */
     }
     iml_serv_no_sdh = -1;                  /* number of server-data-hooks - for position send data to server */
     if (adsl_conn1_l->adsc_server_conf_1) {  /* with server configured  */
       iml_serv_no_sdh = adsl_conn1_l->adsc_server_conf_1->inc_no_sdh - 1;
     }
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* get chain to be sent to server */
     while (adsl_sdhc1_w1) {                /* loop over all new buffers */
       adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_wspat3_1.adsc_gai1_out_to_server;  /* set start of chain output data to server */
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = iml_serv_no_sdh;
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
#ifdef XYZ1
     adsl_sdhc1_out_to_server->adsc_gather_i_1_i = dsl_wspat3_1.adsc_gai1_out_to_server;  /* set start of chain output data to server */
#endif
     adsl_sdhc1_cur_1 = adsl_conn1_l->adsc_sdhc1_chain;  /* get start of chain */
     adsl_sdhc1_w1 = adsl_sdhc1_w2 = NULL;  /* no end of chain         */
     while (adsl_sdhc1_cur_1) {             /* loop over remaining buffers */
       if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_cur_1->inc_position < iml_serv_no_sdh)) {
         break;
       }
       if (   (adsl_sdhc1_w2 == NULL)       /* no buffer to start      */
           && (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_cur_1->inc_position == iml_serv_no_sdh)) {
         adsl_sdhc1_w2 = adsl_sdhc1_cur_1;  /* set buffer to start     */
       }
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* save last buffer        */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w3 = adsl_sdhc1_out_to_server;  /* get chain to insert */
     while (adsl_sdhc1_w3->adsc_next) adsl_sdhc1_w3 = adsl_sdhc1_w3->adsc_next;  /* search last in chain */
     if (adsl_sdhc1_w1) {                   /* append to chain         */
       adsl_sdhc1_w3->adsc_next = adsl_sdhc1_w1->adsc_next;  /* get old end of chain */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_out_to_server;  /* set start of chain */
       if (adsl_sdhc1_w2) {                 /* buffer to start found   */
         /* chain of gather input                                      */
         if (adsl_sdhc1_w2->adsc_gather_i_1_i == NULL) {  /* insert at start of chain */
           adsl_sdhc1_w2->adsc_gather_i_1_i = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
         } else {                           /* insert middle in chain  */
           adsl_gai1_cur = adsl_sdhc1_w2->adsc_gather_i_1_i;
           while (adsl_gai1_cur->adsc_next) adsl_gai1_cur = adsl_gai1_cur->adsc_next;
           adsl_gai1_cur->adsc_next = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
         }
       }
     } else {                               /* set at start of chain   */
       adsl_sdhc1_w3->adsc_next = adsl_conn1_l->adsc_sdhc1_chain;  /* append old chain to new entries */
       adsl_conn1_l->adsc_sdhc1_chain = adsl_sdhc1_out_to_server;  /* set start of chain */
     }
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( adsl_conn1_l, "m_pd_auth1() after insert out_to_server", __LINE__ );
#endif
     break;
   }
   if (adsl_sdhc1_out_to_client) {          /* insert chain of output data to client */
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* get chain of blocks to send */
     while (TRUE) {                         /* loop over all blocks to send */
       adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_wspat3_1.adsc_gai1_out_to_client;  /* set start of chain output data to client */
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;
#ifdef B130919
       adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK + 1;  /* position send to client */
#else
       adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       if (adsl_sdhc1_w1->adsc_next == NULL) break;  /* was last in chain */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_w2 = NULL;                  /* clear last in chain     */
     adsl_gai1_w1 = NULL;                   /* no gather to append to  */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
       if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifdef B130919
       if (adsl_sdhc1_cur_1->inc_position == (MAX_SERVER_DATA_HOOK + 1)) {  /* position send to client */
         if (adsl_gai1_w1 == NULL) {        /* no gather to append to  */
           adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
         }
       }
#else
       if (adsl_sdhc1_cur_1->inc_position == MAX_SERVER_DATA_HOOK) {  /* position send to client */
         if (adsl_gai1_w1 == NULL) {        /* no gather to append to  */
           adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
         }
       }
#endif
       adsl_sdhc1_w2 = adsl_sdhc1_cur_1;    /* set last in chain       */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     if (adsl_sdhc1_w2 == NULL) {           /* insert at beginning of chain */
       adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get old chain */
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_out_to_client;  /* set new chain */
       return;                              /* send data to client     */
     }
     adsl_sdhc1_w1->adsc_next = adsl_sdhc1_w2->adsc_next;  /* get remaining chain */
     adsl_sdhc1_w2->adsc_next = adsl_sdhc1_out_to_client;  /* set remaining chain */
     if (adsl_gai1_w1) {                    /* gather to append to     */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* last in chain */
       adsl_gai1_w1->adsc_next = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;  /* last in chain this shdc1 */
     }
   }
   switch (dsl_wspat3_1.iec_at_return) {
     case ied_atr_end:                      /* end of authentication   */
#ifdef B130515
// to-do 13.01.12 KB ??? only free() needed
       m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
       adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
//     break;
#ifndef B130515
       adsl_wa1 = NULL;                     /* no more structure for authentication */
#endif
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1 l%05d ied_atr_end adsl_wa1=%p.",
                       __LINE__, adsl_wa1 );
#endif
#ifndef B140717
       adsl_wa1->boc_auth_ended = TRUE;     /* authentication has ended */
#endif
       goto p_cha_blo_00;                   /* change block when authentication has ended */
     case ied_atr_other_prot:               /* other protocol selected */
#ifdef B130405
       m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
       adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
#endif
       adsl_wa1->boc_http = TRUE;           /* check HTTP              */
       goto p_http_00;                      /* other protocol received - HTTP */
     case ied_atr_input:                    /* wait for more input     */
       break;                               /* nothing more to do      */
     case ied_atr_connect:                  /* do connect now          */
#ifndef B130502
       adsl_wa1->imc_connect_error = 0;     /* reset connect error     */
#endif
#define ADSL_S_CONN ((struct dsd_wspat3_conn *) dsl_wspat3_1.ac_exc_aux)
       if (ADSL_S_CONN) {
// to-do 07.06.12 KB
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d amc_at3_entry() returned connect ADSL_S_CONN=%p iec_hconn=%d.",
                         __LINE__, ADSL_S_CONN, ADSL_S_CONN->iec_hconn );
#endif
         if (adsl_conn1_l->imc_trace_level & HL_WT_SESS_WSPAT3_EXT) {  /* generate WSP trace record */
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "SATLCON1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_sno = adsl_conn1_l->dsc_co_sort.imc_sno;  /* WSP session number */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
           achl_func = "* undefined *";
           chrl_work1[0] = 0;
           switch (ADSL_S_CONN->iec_hconn) {  /* Hook Connect          */
             case ied_hconn_ineta:          /* by INETA                */
               achl_func = "ied_hconn_ineta";
               break;
             case ied_hconn_ipv4:           /* INETA IPV4              */
               achl_func = "ied_hconn_ipv4";
               break;
             case ied_hconn_ipv6:           /* INETA IPV6              */
               achl_func = "ied_hconn_ipv6";
               break;
             case ied_hconn_def_servent:    /* connect default server entry */
               achl_func = "ied_hconn_def_servent";
               m_hlsnprintf( chrl_work1, sizeof(chrl_work1), ied_chs_utf_8,  /* Unicode UTF-8 */
                             " server-entry=\"%(ucs)s\"",
                             &ADSL_S_CONN->dsc_ucs_server_entry );  /* Server Entry */
               break;
             case ied_hconn_sel_servent:    /* select server entry by name */
               achl_func = "ied_hconn_sel_servent";
               break;
             case ied_hconn_pttd:           /* pass thru to desktop    */
               achl_func = "ied_hconn_pttd";
               break;
           }
// to-do 28.01.14 KB - decode protocol
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
           iml7 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                           "connect from authentication library %d %s%s vpc_servent=%p.",
                           ADSL_S_CONN->iec_hconn, achl_func, chrl_work1, ADSL_S_CONN->vpc_servent );
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
           ADSL_WTR_G1->imc_length = iml7;  /* length of text / data   */
           adsl_wt1_w2 = adsl_wt1_w1;       /* last WSP Trace area     */
           adsl_wtr_w1 = ADSL_WTR_G1;       /* set last in chain       */
           achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
           achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
           ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
           memcpy( achl_w4, ADSL_S_CONN, sizeof(struct dsd_wspat3_conn) );
           ADSL_WTR_G2->imc_length = sizeof(struct dsd_wspat3_conn);  /* length of text / data */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
         /* check WebSocket                                            */
         if (   (ADSL_S_CONN->iec_scp_def == ied_scp_websocket)  /* protocol WebSocket */
             && (ADSL_S_CONN->vpc_servent == NULL)) {  /* handle to server entry */
           bol1 = m_sel_server_socks5_1( adsl_conn1_l,
                                         (struct dsd_user_entry *) ADSL_S_CONN->vpc_usent,  /* user entry */
                                         (struct dsd_user_group *) ADSL_S_CONN->vpc_usgro,  /* user-group entry */
                                         &ADSL_S_CONN->dsc_ucs_server_entry,
                                         ied_scp_websocket, NULL, 0 );
// to-do 07.06.12 KB check bol1 - error message and abend session
         } else if (ADSL_S_CONN->vpc_servent) {  /* handle to server entry */
           adsl_conn1_l->adsc_server_conf_1
             = (struct dsd_server_conf_1 *) ADSL_S_CONN->vpc_servent;
           if (adsl_conn1_l->adsc_server_conf_1->inc_no_sdh >= 2) {
             adsl_conn1_l->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_conn1_l->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
             memset( adsl_conn1_l->adsrc_sdh_s_1, 0, adsl_conn1_l->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
           }
#ifndef B120121
#ifndef WSP_V24
           m_clconn1_naeg1( adsl_conn1_l );
#endif
#ifdef WSP_V24
           m_clconn1_nagl1( adsl_conn1_l );
#endif
#endif
         }
       }
       if (adsl_conn1_l->adsc_server_conf_1 == NULL) {  /* no server selected */
// to-do 13.01.12 KB error message and abend session
         m_hlnew_printf( HLOG_XYZ1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication-library returned ied_atr_connect and server-entry not found",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta );
         m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
         adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
         adsp_pd_work->boc_abend = TRUE;    /* abend of session        */
         return;                            /* nothing more to do      */
       }
#ifdef TRY_130920_01
// to-do 20.09.13 KB - what to do?
/**
check if direct connection, with server, no reflection,
then connect to server.
this was missing here.
*/
#endif
       if (   (adsl_conn1_l->adsc_server_conf_1->iec_scp_def == ied_scp_websocket)  /* protocol WebSocket */
           && (   (adsl_conn1_l->adsc_server_conf_1->boc_sdh_reflect)  /* only Server-Data-Hook */
               || (   (adsl_conn1_l->adsc_server_conf_1->inc_function != DEF_FUNC_DIR)  /* set function direct */
                   && (adsl_conn1_l->adsc_server_conf_1->inc_function != DEF_FUNC_RDP)  /* set function RDP */
                   && (adsl_conn1_l->adsc_server_conf_1->inc_function != DEF_FUNC_ICA)))) {  /* set function ICA */

#ifndef HL_UNIX
         adsl_conn1_l->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
         adsl_conn1_l->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
         adsl_wa1->boc_did_connect = TRUE;  /* did connect             */
         adsl_wa1->imc_connect_error = 0;   /* no connect error        */
         goto p_atlib_40;                   /* call authentication-library */
       }
#ifdef NOT_YET_120113
       if (adsl_conn1_l->adsc_server_conf_1->inc_function < 0) {
         /* has to do load-balancing                                   */
         iel_function = ied_atf_connect_ok;  /* connect succeeded      */
         goto pauth24;                      /* call radius function    */
       }
#endif
#ifndef B120122
       if (adsl_conn1_l->adsc_server_conf_1->inc_function < 0) {
#ifndef HL_UNIX
         adsl_conn1_l->iec_st_ses = clconn1::ied_ses_do_lbal;  /* status do load-balancing */
#else
         adsl_conn1_l->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
#endif
         goto p_atlib_40;                   /* call authentication-library */
       }
#endif
       adsl_wa1->boc_did_connect = FALSE;   /* did not yet connect     */
       adsl_wa1->boc_connect_active = TRUE;  /* has to do connect      */
       if (adsl_conn1_l->adsc_server_conf_1->inc_function != DEF_FUNC_PTTD) {
#ifndef HL_UNIX
         adsl_conn1_l->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
#else
         adsl_conn1_l->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
#endif
         break;
       }
#ifdef B120130
       adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr)
                         + ADSL_RADQUCO->imc_len_target_bytes );
       memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
       if (ADSL_RADQUCO->imc_len_target_bytes) {
         memcpy( adsl_cpttdt + 1,
                 (char *) (ADSL_RADQUCO + 1) + ADSL_RADQUCO->imc_len_name_bytes,
                 ADSL_RADQUCO->imc_len_target_bytes );
         adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
       } else {
         adsl_cpttdt->achc_target = ADSL_RADQUCO->achc_target;
       }
       adsl_cpttdt->adsc_conn1 = adsl_conn1_l;  /* for this connection */
       adsl_cpttdt->inc_len_target_bytes = ADSL_RADQUCO->imc_len_target_bytes;
#endif
#ifdef B130429
       iml1 = m_len_vx_ucs( ied_chs_ascii_850, &ADSL_S_CONN->dsc_ucs_target );  /* length INETA DNS / IPV4 / IPV6 */
#endif
       iml1 = m_len_vx_ucs( ied_chs_idna_1, &ADSL_S_CONN->dsc_ucs_target );  /* length INETA DNS / IPV4 / IPV6 */
       if (iml1 <= 0) {
         m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication l%05d could not copy INETA",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno, adsl_conn1_l->chrc_ineta,
                         __LINE__ );
         m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
         adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
         adsp_pd_work->boc_abend = TRUE;    /* abend of session        */
         return;                            /* nothing more to do      */
       }
       adsl_cpttdt = (struct dsd_conn_pttd_thr *) malloc( sizeof(struct dsd_conn_pttd_thr) + iml1 + 1 );
       memset( adsl_cpttdt, 0, sizeof(struct dsd_conn_pttd_thr) );
       adsl_cpttdt->adsc_conn1 = adsl_conn1_l;  /* for this connection */
       adsl_cpttdt->imc_len_target_bytes = iml1;
       adsl_cpttdt->achc_target = (char *) (adsl_cpttdt + 1);
#ifdef B130429
       m_cpy_vx_ucs( adsl_cpttdt + 1, iml1, ied_chs_ascii_850,
                     &ADSL_S_CONN->dsc_ucs_target );  /* INETA DNS / IPV4 / IPV6 */
#endif
       m_cpy_vx_ucs( adsl_cpttdt + 1, iml1, ied_chs_idna_1,
                     &ADSL_S_CONN->dsc_ucs_target );  /* INETA DNS / IPV4 / IPV6 */
       *((char *) (adsl_cpttdt + 1) + iml1) = 0;  /* make zero-terminated */
       adsl_cpttdt->imc_port_target = ADSL_S_CONN->imc_port;
#ifdef NOT_YET_120130
       adsl_cpttdt->umc_out_ineta = ADSL_RADQUCO->umc_out_ineta;
#endif
       adsl_cpttdt->umc_out_ineta
         = *((UNSIG_MED *) &adsl_conn1_l->adsc_server_conf_1->dsc_bind_out.dsc_soai4.sin_addr);
       adsl_cpttdt->boc_with_macaddr = ADSL_S_CONN->boc_with_macaddr;
       memcpy( adsl_cpttdt->chrc_macaddr, ADSL_S_CONN->chrc_macaddr, sizeof(adsl_cpttdt->chrc_macaddr) );
       adsl_cpttdt->imc_waitconn = ADSL_S_CONN->imc_waitconn;
       adsl_conn1_l->adsc_cpttdt = adsl_cpttdt;  /* connect active now */
       m_pd_auth_start_pttd( adsp_pd_work, adsl_cpttdt );
       break;
#undef ADSL_S_CONN
     case ied_atr_failed:                   /* authentication failed   */
       m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication-library returned: authentication failed",
                       adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                       adsl_conn1_l->chrc_ineta );
       m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
       adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       return;                              /* nothing more to do      */
     case ied_atr_start_rec_server:         /* start receiving from the server */
       adsl_wa1->boc_rec_from_server = TRUE;  /* receive from server   */
       break;
     case ied_atr_err_aux:                  /* error in aux subroutine */
       m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication-library returned: ied_atr_err_aux / error in aux subroutine",
                       adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                       adsl_conn1_l->chrc_ineta );
       m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
       adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
       adsp_pd_work->boc_abend = TRUE;      /* abend of session        */
       return;                              /* nothing more to do      */
   }
   if (dsl_wspat3_1.boc_callagain) {        /* call again              */
     goto p_atlib_40;                       /* call authentication-library */
   }
   return;                                  /* nothing more to do      */

   p_http_00:                               /* other protocol received - HTTP */
   /* protocol is HTTP, SSTP, MS-RPC or RDG                            */
#ifdef XYZ1
   adsl_gai1_w1 = adsl_gai1_client_input;   /* gather start input from client */
   achl_w1 = chrl_work1;                    /* area to put request in  */
// iml1 = sizeof(chrl_work1);               /* size of area area       */
   iml1 = 8;                                /* size of area area       */
   while (adsl_gai1_w1) {                   /* loop over input data    */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;          /* only as much as needed  */
     memcpy( achl_w1, adsl_gai1_w1->achc_ginp_cur, iml2 );
     achl_w1 += iml2;                       /* increment output pointer */
     iml1 -= iml2;                          /* decrement length remaining */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (achl_w1 < (chrl_work1 + 4 + 1)) return;  /* wait for more data  */
   achl_w1 = "HTTP";                        /* default protocol        */
   iel_scp_def = ied_scp_http;              /* protocol HTTP           */
   if (!memcmp( chrl_work1, "SSTP_", 5 )) {
     achl_w1 = "SSTP";                      /* SSTP protocol           */
     iel_scp_def = ied_scp_sstp;            /* protocol SSTP           */
   }
   if (!memcmp( chrl_work1, "RPC_", 4 )) {
     achl_w1 = "MS-RPC";                    /* MS-RPC protocol         */
     iel_scp_def = ied_scp_ms_rpc;          /* protocol MS-RPC         */
   }
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d call m_proc_http_header_server().",
                   __LINE__ );
#endif
   memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */
#ifdef XYZ1
#ifdef DEF_STORAGE_CONTAINER
   dsl_chhs1.ac_stor_1 = al_stor_1;
#endif
#endif
   dsl_chhs1.adsc_gai1_in = adsl_gai1_client_input;   /* gather start input from client */
   bol_rc = m_proc_http_header_server( &dss_phhs1_check_01,  /* HTTP processing at server */
                                       &dsl_chhs1,  /* call HTTP processing at server */
                                       &dsl_hhs1 );  /* HTTP processing at server */
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hlnew_printf( HLOG_WARN1, "HWSPAnnnW GATE=%(ux)s SNO=%08d INETA=%s authentication check HTTP header returned error",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta );
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
   if (dsl_hhs1.imc_length_http_header == 0) {  /* length of HTTP header */
     return;                                /* wait for more data      */
   }
   switch (dsl_hhs1.iec_hme) {              /* HTTP method             */
     case ied_hme_sstp:                     /* SSTP_DUPLEX_POST        */
       achl_w1 = "SSTP";                    /* SSTP protocol           */
       iel_scp_def = ied_scp_sstp;          /* protocol SSTP           */
       break;
     case ied_hme_ms_rpc:                   /* RPC_IN_DATA / RPC_OUT_DATA */
       achl_w1 = "MS-RPC";                  /* MS-RPC protocol         */
       iel_scp_def = ied_scp_ms_rpc;        /* protocol MS-RPC         */
       break;
     case ied_hme_rdg_out_data:             /* RDG_OUT_DATA            */
       achl_w1 = "RDG-OUT";
       iel_scp_def = ied_scp_rdg_out_d;     /* protocol MS RDG_OUT_DATA */
       break;
     case ied_hme_rdg_in_data:              /* RDG_IN_DATA             */
       achl_w1 = "RDG-IN";
       iel_scp_def = ied_scp_rdg_in_d;      /* protocol MS RDG_IN_DATA */
       break;
     default:
       achl_w1 = "HTTP";                    /* default protocol        */
       iel_scp_def = ied_scp_http;          /* protocol HTTP           */
       break;
   }

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d before check HTTP/SSTP/MS-RPC/RDG iel_scp_def=%d",
                   __LINE__, iel_scp_def );
#endif

#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + iml1) * sizeof(void *))))
#endif
   iml1 = adsl_conn1_l->adsc_gate1->inc_no_seli;  /* start in reverse order */
   while (TRUE) {                           /* loop over all server-entries */
     iml1--;                                /* check next entry        */
     if (iml1 < 0) break;                   /* was last server-entry   */
#ifdef OLD_1112
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data check l%05d %s adsl_conn1_l->adsc_gate1->inc_no_seli=%d iml1=%d ADSL_SELSERV_1=%p *=%p",
                       __LINE__, achl_w1,
                       adsl_conn1_l->adsc_gate1->inc_no_seli, iml1,
                       ADSL_SELSERV_1, *((void **) ADSL_SELSERV_1) );
#endif
#endif
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#else
     adsl_server_conf_1_w1 = adsl_conn1_l->adsc_gate1->adsrc_server_list_1[ iml1 ]->adsc_server_conf_1;  /* list of servers */
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1 l%05d check HTTP/SSTP adsl_server_conf_1_w1=%p ...->iec_scp_def=%d",
                       __LINE__, adsl_server_conf_1_w1, adsl_server_conf_1_w1->iec_scp_def );
#endif
       /* protocol HTTP, SSTP or MS-RPC                                */
       if (adsl_server_conf_1_w1->iec_scp_def == iel_scp_def) {
         adsl_conn1_l->adsc_server_conf_1 = adsl_server_conf_1_w1;  /* set this server */
         if (adsl_server_conf_1_w1->inc_no_sdh >= 2) {
           adsl_conn1_l->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
           memset( adsl_conn1_l->adsrc_sdh_s_1, 0, adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
         }
#ifndef B120121
#ifndef WSP_V24
         m_clconn1_naeg1( adsl_conn1_l );
#endif
#ifdef WSP_V24
         m_clconn1_nagl1( adsl_conn1_l );
#endif
#endif
         m_hlnew_printf( HLOG_INFO1, "HWSPS020I GATE=%(ux)s SNO=%08d INETA=%s select-server %s %(ux)s",
                         adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                         adsl_conn1_l->chrc_ineta,
                         achl_w1,
                         adsl_conn1_l->adsc_server_conf_1->awcc_name );
#ifndef HL_UNIX
         adsl_conn1_l->iec_st_ses = clconn1::ied_ses_prep_server;  /* prepare connect to server */
         adsl_conn1_l->m_start_rec_server( adsp_pd_work );  /* open connection server */
         if (   (adsl_conn1_l->iec_st_ses == clconn1::ied_ses_error_conn)  /* status server error */
             && (adsl_conn1_l->achc_reason_end == NULL)) {  /* reason end session */
           switch (iel_scp_def) {           /* check protocol          */
             case ied_scp_http:             /* protocol HTTP           */
               adsl_conn1_l->achc_reason_end = "connect to HTTP-Server failed";
               break;
             case ied_scp_sstp:             /* protocol SSTP           */
               adsl_conn1_l->achc_reason_end = "connect SSTP failed";
               break;
             case ied_scp_ms_rpc:           /* protocol MS-RPC         */
               adsl_conn1_l->achc_reason_end = "connect to MS-RPC-Server failed";
               break;
           }
         }
#else
         adsl_conn1_l->iec_st_ses = ied_ses_prep_server;  /* prepare connect to server */
         m_start_rec_server( adsp_pd_work );  /* open connection server */
         if (   (adsl_conn1_l->iec_st_ses == ied_ses_error_conn)  /* status server error */
             && (adsl_conn1_l->achc_reason_end == NULL)) {  /* reason end session */
           switch (iel_scp_def) {           /* check protocol          */
             case ied_scp_http:             /* protocol HTTP           */
               adsl_conn1_l->achc_reason_end = "connect to HTTP-Server failed";
               break;
             case ied_scp_sstp:             /* protocol SSTP           */
               adsl_conn1_l->achc_reason_end = "connect SSTP failed";
               break;
             case ied_scp_ms_rpc:           /* protocol MS-RPC         */
               adsl_conn1_l->achc_reason_end = "connect to MS-RPC-Server failed";
               break;
           }
         }
#endif
         break;
       }
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
     if (adsl_server_conf_1_w1) break;      /* server conf found       */
   }
#ifdef B120909
   if (iml1 < 0) {                          /* no HTTP / SSTP / MS-RPC entry found */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s select-server %s - no server (protocol %s) defined in server-list",
                     adsl_conn1_l->adsc_gate1 + 1, adsl_conn1_l->dsc_co_sort.imc_sno,
                     adsl_conn1_l->chrc_ineta,
                     achl_w1, achl_w1 );
     adsp_pd_work->boc_abend = TRUE;        /* abend of session        */
     return;                                /* nothing more to do      */
   }
#endif
#ifndef B120909
   if (iml1 >= 0) {                         /* HTTP / SSTP / MS-RPC / RDG entry found */
     goto p_cha_blo_00;                     /* change block when authentication has ended */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPS021W GATE=%(ux)s SNO=%08d INETA=%s select-server %s - no server (protocol %s) defined in server-list",
                   adsl_conn1_l->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   adsl_conn1_l->chrc_ineta,
                   achl_w1, achl_w1 );
   if (adsl_conn1_l->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1_l->achc_reason_end = "type of protocol not configured";
   }
   m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = NULL;    /* no more structure for authentication */
   /* consume input                                                    */
   adsl_gai1_w1 = adsl_gai1_client_input;   /* gather start input from client */
   while (adsl_gai1_w1) {                   /* loop over input data    */
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#ifndef HL_UNIX
   adsl_conn1_l->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
#else
   adsl_conn1_l->iec_st_ses = ied_ses_error_conn;  /* status server error */
#endif
   adsp_pd_work->boc_abend = TRUE;          /* abend of session        */
   return;                                  /* process end of session  */
#endif
#ifdef DEBUG_100810
#endif
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif

   p_cha_blo_00:                            /* change block when authentication has ended */
#ifdef B130406
   m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
   adsl_conn1_l->adsc_wsp_auth_1 = NULL;    /* no more structure for authentication */
#else
   if (adsl_wa1) {                          /* authentication still active */
     m_auth_delete( adsp_pd_work, adsl_wa1 );  /* free all fields of authentication */
     adsl_conn1_l->adsc_wsp_auth_1 = NULL;  /* no more structure for authentication */
   }
#endif
   /* old input to authentication is now output to server or input to server-data-hook */
   iml_serv_no_sdh = -1;                    /* number of server-data-hooks - for position send data to server */
   if (adsl_conn1_l->adsc_server_conf_1) {  /* with server configured  */
     iml_serv_no_sdh = adsl_conn1_l->adsc_server_conf_1->inc_no_sdh - 1;
   }
   adsl_sdhc1_cur_1 = adsl_conn1_l->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_last_1 = NULL;                /* last location 1         */
   adsl_sdhc1_w1 = NULL;                    /* no buffers to change position */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) {
       if (adsl_sdhc1_cur_1->inc_position < MAX_SERVER_DATA_HOOK) break;  /* not position from client to authentication */
       adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1) {               /* loop over output        */
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* get this buffer         */
       do {                                 /* loop over remaining buffers */
         adsl_sdhc1_cur_1->inc_position = iml_serv_no_sdh;  /* position send to server */
         adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
         adsl_sdhc1_w2 = adsl_sdhc1_cur_1;  /* save last to change     */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       } while (   (adsl_sdhc1_cur_1)
                && (adsl_sdhc1_cur_1->inc_position >= MAX_SERVER_DATA_HOOK));  /* position from client to authentication */
       if (adsl_sdhc1_last_1 == NULL) {     /* was at start of chain   */
         adsl_conn1_l->adsc_sdhc1_chain = adsl_sdhc1_cur_1;  /* remove these blocks from chain */
         break;
       }
       /* was middle in chain                                          */
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_cur_1;  /* remove these blocks from chain */
       break;
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save last location 1    */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_w1 == NULL) return;       /* no buffers to change position */
   adsl_sdhc1_w3 = NULL;                    /* position to insert to   */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_position < iml_serv_no_sdh) break;  /* not position from client to insert to */
     if (adsl_sdhc1_cur_1->inc_position == iml_serv_no_sdh) {  /* position from client to insert to */
       adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       if (adsl_sdhc1_w3 == NULL) {         /* position to insert to   */
         adsl_sdhc1_w3 = adsl_sdhc1_cur_1;  /* save position to insert to */
       }
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save last location 1    */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   adsl_sdhc1_w2->adsc_next = adsl_sdhc1_cur_1;  /* insert input from client blocks into chain */
   if (adsl_sdhc1_last_1 == NULL) {         /* was at start of chain   */
     adsl_conn1_l->adsc_sdhc1_chain = adsl_sdhc1_w1;  /* insert input from client blocks into chain */
   } else {
     adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;  /* insert input from client blocks into chain */
   }
   if (adsl_sdhc1_w3 == NULL) return;       /* no need to append gather */
   adsl_gai1_w1 = adsl_sdhc1_w3->adsc_gather_i_1_i;  /* get chain input data */
   if (adsl_gai1_w1 == NULL) {              /* no chain input data     */
     do {                                   /* loop to set chain input data */
       adsl_sdhc1_w3->adsc_gather_i_1_i = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
       adsl_sdhc1_w3 = adsl_sdhc1_w3->adsc_next;  /* get next in chain */
     } while (   (adsl_sdhc1_w3)
              && (adsl_sdhc1_w3->inc_position == iml_serv_no_sdh));  /* position from client to insert to */
     return;                                /* nothing more to do      */
   }
   while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   adsl_gai1_w1->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set chain input data */
   return;                                  /* all done                */
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_pd_auth1()                                                  */

/** callback routine, Radius request completed                         */
static void m_auth_radius_req_compl( struct dsd_radius_control_1 *adsp_rctrl1, int imp_error ) {
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */

   adsl_conn1_l = (DSD_CONN_G *) adsp_rctrl1->ac_conn1;  /* current connection */
   if (adsl_conn1_l == NULL) return;        /* do not activate         */
   if (imp_error) {                         /* error reported          */
     if (imp_error < 0) {                   /* timed out               */
       adsl_conn1_l->adsc_wsp_auth_1->boc_timed_out = TRUE;  /* received timed out */
     } else {
       adsl_conn1_l->adsc_wsp_auth_1->imc_connect_error = imp_error;  /* connect error */
     }
   }
   adsl_conn1_l->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   m_act_thread_1( adsl_conn1_l );          /* activate thread for session */
} /* end m_auth_radius_req_compl()                                     */

//#ifndef D_INCL_HTUN
//#ifdef TRY_D_INCL_HTUN
/** start pass-thru-to-desktop, also called desktop-on-demand          */
static void m_pd_auth_start_pttd( struct dsd_pd_work *adsp_pd_work,
                                  struct dsd_conn_pttd_thr *adsp_cpttdt ) {  /* connect PTTD thread */
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */

   iml_rc = adsp_cpttdt->dsc_hco_wothr.dsc_event.m_create( &iml1 );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "m_pd_auth_start_pttd() l%05d Event Create conn_pttd Error %d/%d.",
                     __LINE__, iml_rc, iml1 );
   }
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_do_cpttdt;  /* connect pass thru to desktop */
#endif
//#ifndef HL_UNIX
   adsp_cpttdt->dsc_ete.ac_conn1 = ADSL_CONN1_G;  /* for this connection */
   adsp_cpttdt->dsc_ete.ilc_time_started_ms = m_get_epoch_ms();  /* time / epoch started in milliseconds */
   dss_critsect_aux.m_enter();              /* critical section        */
   dss_ets_pttd.imc_no_started++;           /* number of instances started */
   dss_ets_pttd.imc_no_current++;           /* number of instances currently executing */
   adsp_cpttdt->dsc_ete.adsc_next = dss_ets_pttd.adsc_ete_ch;  /* get old chain extra thread entries */
   dss_ets_pttd.adsc_ete_ch = &adsp_cpttdt->dsc_ete;  /* set new chain extra thread entries */
   dss_critsect_aux.m_leave();              /* critical section        */
//#endif
   iml_rc = adsp_cpttdt->dsc_hco_wothr.dsc_hcthread.mc_create( &m_conn_pttd_thread, adsp_cpttdt );
   if (iml_rc == -1) {
     m_hlnew_printf( HLOG_WARN1, "m_pd_auth_start_pttd() l%05d CreateThread conn_pttd Error",
                     __LINE__ );
   }
   iml_rc = adsp_cpttdt->dsc_hco_wothr.dsc_event.m_post( &iml1 );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "m_pd_auth_start_pttd() l%05d Event Post conn_pttd Error %d/%d.",
                     __LINE__, iml_rc, iml1 );
   }
} /* end m_pd_auth_start_pttd()                                        */
//#endif
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
// new 26.12.11 KB

/** get the input characters since the last sync-point                 */
static inline void m_auth_get_input(
       struct dsd_gather_i_1 *adsp_gather_i_1_in,  /* input data       */
       char * achp_out, char * achp_start_inp, char * achp_end_inp ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   char       *achl_out;                    /* output area             */
   char       *achl_w1;                     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather data - working variable */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-auth-%05d-T m_auth_get_input( %p, %p, %p, %p ) called",
                   __LINE__, adsp_gather_i_1_in, achp_out, achp_start_inp, achp_end_inp );
#endif
   achl_out = achp_out;                     /* output area             */
   adsl_gai1_w1 = adsp_gather_i_1_in;       /* get input data          */
   if (achp_start_inp) {                    /* data processed before   */
     while (TRUE) {                         /* loop over input data    */
       if (   (achp_start_inp >= adsl_gai1_w1->achc_ginp_cur)
           && (achp_start_inp <= adsl_gai1_w1->achc_ginp_end)) {
         adsl_gai1_w1->achc_ginp_cur = achp_start_inp;
         break;
       }
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) return;    /* illogic                 */
     }
   }
   bol1 = FALSE;                            /* not yet end data        */
   while (TRUE) {                           /* loop over input data    */
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* save start data        */
     if (   (achp_end_inp >= adsl_gai1_w1->achc_ginp_cur)
         && (achp_end_inp <= adsl_gai1_w1->achc_ginp_end)) {
       adsl_gai1_w1->achc_ginp_cur = achp_end_inp;
       bol1 = TRUE;                         /* is last element         */
     } else {
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     }
     iml1 = adsl_gai1_w1->achc_ginp_cur - achl_w1;  /* length to copy  */
     memcpy( achl_out, achl_w1, iml1 );
     achl_out += iml1;
     if (bol1) {                            /* all processed           */
//     *achl_out = 0;                       /* make zero-terminated    */
       return;                              /* all done                */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) return;      /* needs more data         */
   }
} /* end m_auth_get_input()                                            */

/** free all fields of authentication                                  */
static void m_auth_delete( struct dsd_pd_work *adsp_pd_work, struct dsd_wsp_auth_1 *adsp_wa1 ) {
   DSD_CONN_G *adsl_conn1_l;                /* current connection      */
   struct dsd_wspat3_1 dsl_wspat3_1;        /* HOB Authentication Library V3 - 1 */

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   adsl_conn1_l = ADSL_CONN1_G;             /* current connection      */
   if (adsl_conn1_l->adsc_gate1->adsc_hobwspat3_ext_lib1 == NULL) {  /* external library loaded for HOB-WSP-AT3 */
     goto p_no_atl_00;                      /* no authentication library */
   }
#ifndef B140717
   if (adsp_wa1->boc_auth_ended) {          /* authentication has ended */
     goto p_free_00;                        /* free all memory         */
   }
#endif
#define AADSL_AC_EXT ((void **) (adsp_wa1 + 1))
   memset( &dsl_wspat3_1, 0, sizeof(struct dsd_wspat3_1) );  /* HOB Authentication Library V3 - 1 */
   dsl_wspat3_1.amc_aux = &m_cdaux;         /* subroutine              */
   dsl_wspat3_1.vpc_userfld = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structure */
   dsl_wspat3_1.ac_ext = *AADSL_AC_EXT;     /* get attached buffer     */
   dsl_wspat3_1.ac_conf = adsl_conn1_l->adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
   /* flags of configuration                                           */
   if (adsl_conn1_l->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (adsl_conn1_l->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (adsl_conn1_l->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (adsl_conn1_l->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups */
     dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (adsl_conn1_l->adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_wspat3_1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
   dsl_wspat3_1.imc_language = adsl_conn1_l->adsc_gate1->imc_language;  /* language configured */
   dsl_wspat3_1.iec_at_function = ied_atf_abend;  /* function abend    */
   adsl_conn1_l->adsc_gate1->adsc_hobwspat3_ext_lib1->amc_at3_entry( &dsl_wspat3_1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_auth_delete() l%05d HOB-WSP-AT3 amc_at3_entry returned iec_at_return=%d ac_ext=%p.",
                   __LINE__,  dsl_wspat3_1.iec_at_return, dsl_wspat3_1.ac_ext );
#endif
#undef AADSL_AC_EXT
   goto p_free_00;                          /* free all memory         */

   p_no_atl_00:                             /* no authentication library */
#define ADSL_WAN_G ((struct dsd_wsp_auth_normal *) (adsp_wa1 + 1))  /* normal authentication   */
#ifndef NO_AUTH_RADIUS                      /* 09.05.12 KB - for test password change */
   if (adsl_conn1_l->adsc_radius_group) {   /* active Radius group     */
     m_radius_cleanup( (struct dsd_radius_control_1 *) ((char *) adsp_wa1 + sizeof(struct dsd_wsp_auth_1) + sizeof(struct dsd_wsp_auth_normal)) );
   }
#endif
   if (ADSL_WAN_G->achc_protocol) {         /* storage for protocol    */
     free( ADSL_WAN_G->achc_protocol );     /* free the storage for protocol */
   }
   if (ADSL_WAN_G->achc_stor_servent) {     /* storage with input field */
     free( ADSL_WAN_G->achc_stor_servent );  /* free the storage       */
   }
   if (ADSL_WAN_G->boc_varstor_name) {      /* name for variable storage */
     free( ADSL_WAN_G->achc_userid );       /* storage name entry      */
   }
   if (ADSL_WAN_G->boc_varstor_password) {  /* password from variable storage */
     free( ADSL_WAN_G->achc_password );     /* storage password entry */
   }
   if (ADSL_WAN_G->boc_hkw_host) {          /* host set in header      */
     free( ADSL_WAN_G->achc_host );         /* storage host            */
   }
   if (ADSL_WAN_G->boc_hkw_device) {        /* device set in header    */
     free( ADSL_WAN_G->achc_device );       /* storage device          */
   }
   if (ADSL_WAN_G->boc_hkw_appl) {          /* appl set in header      */
     free( ADSL_WAN_G->achc_appl );         /* storage appl            */
   }
   if (ADSL_WAN_G->boc_hkw_krb5_ticket) {   /* kerberos-5 ticket set in header */
     free( ADSL_WAN_G->achc_stor_krb5_ticket );  /* storage kerberos-5 ticket */
   }
#undef ADSL_WAN_G

   p_free_00:                               /* free all memory         */
#ifdef XYZ1
// 09.05.14 KB - fields for radius may not exist
#ifdef DEBUG_140327_01
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
   adsl_rctrl1 = (struct dsd_radius_control_1 *) ((char *) adsp_wa1 + sizeof(struct dsd_wsp_auth_1) + sizeof(struct dsd_wsp_auth_normal));
   m_hlnew_printf( HLOG_TRACE1, "m_pd_auth1() l%05d p_free_00: vpc_chain_2 = %p.",
                   __LINE__, adsl_rctrl1->dsc_timer.vpc_chain_2 );
#endif
#endif
   free( adsp_wa1 );                        /* free memory of authentication */
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_auth_delete()                                               */
#undef DSD_CONN_G
