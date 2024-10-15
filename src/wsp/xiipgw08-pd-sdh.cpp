#ifdef TO_DO_140926
boc_callagain;                /* call again this direction */
should first send output to server or client
#endif
#ifdef WSP_TRACE_TRY01_XXX
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSDHCAL1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
// to-do 13.03.14 KB - signal
#endif
#define DEBUG_111213_01 16                  /* save chain in stack     */
#define HELP_DEBUG
#define DEBUG_111205_01                     /* because of insure++     */
#define TRY_091014_01
#define DEBUG_111116_01 8                   /* block is lost           */
#define TRY_111117_01
#define TRY_111124_01
//#define DEBUG_150218_01                     /* problem gather          */
#ifdef DEBUG_150218_01                      /* problem gather          */
#define DEF_DEB_GA1_GATHER 4
#define DEF_DEB_GA1_TOTAL  16
struct dsd_deb_ga1_1 {
   void *     ac_gai1;
   void *     ac_cur;
   int        imc_len;
   int        imc_filler;
};

struct dsd_deb_ga1_2 {
   void *     ac_eyecatcher;
   void *     ac_sdhc1;
   int        inc_function;                 /* function of SDH         */
   int        inc_position;                 /* position of SDH         */
   enum ied_sdhc_state iec_sdhcs;           /* state of control area server data hook */
   int        imc_usage_count;              /* usage count             */
   int        imc_filler_1;
   int        imc_filler_2;
   struct dsd_deb_ga1_1 dsrc_deb_ga1_1[ DEF_DEB_GA1_GATHER ];
};

static struct dsd_deb_ga1_2 dsrs_deb_ga1_2_1[ DEF_DEB_GA1_TOTAL ];
static struct dsd_deb_ga1_2 dsrs_deb_ga1_2_2[ DEF_DEB_GA1_TOTAL ];
static struct dsd_gather_i_1 *adss_gai1_break_1 = NULL;

static void m_fill_ga1_1( struct dsd_deb_ga1_2 *adsp_deb_ga1_2, struct dsd_sdh_control_1 *adsp_sdhc1 );
#endif
//#define DEBUG_060513                        /* do not process Server-Data-Hooks */
/**
  Subroutine to process Server-Data-Hook with data from Server

  The routine m_pd_do_sdh_frse() creates the data
  which will be sent encrypted to the client.
  The sdhc1-buffer is included in the session-wide chain
  ADSL_CONN1_G->adsc_sdhc1_chain and will be freed by the garbage
  collector.
*/
#ifdef DEBUG_111213_01                      /* save chain in stack     */
static int    ims_debug_count_frse = 0;
static int    ims_debug_count_tose = 0;
#endif
static void m_pd_do_sdh_frse( struct dsd_pd_work *adsp_pd_work ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7;  /* working variables */
   int        iml_w1, iml_w2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
#ifndef B140621
   BOOL       bol_after_sdh_reload;         /* after SDH reload        */
#endif
   enum ied_sdhc_state iel_sdhcs;           /* state of control area server data hook */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_func;                   /* function called         */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_2;  /* current location 2  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_2;  /* last location 2    */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_1;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_1;  /* currently processed end */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_2;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_2;  /* currently processed end */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_client;  /* output data to client */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_server;  /* output data to server */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
#endif
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
// struct dsd_gather_i_1 dsl_gather_i_1_i;  /* gather input data       */
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_check1;  /* for checks             */
#endif
#ifdef B140525
#ifndef B131225
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server */
#endif
#endif
#ifndef B140525
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
#ifdef TRACEHL_SDH_COUNT_1
   int        iml_sdh_count_1_1;            /* count entries           */
   int        iml_sdh_count_1_2;            /* count entries           */
   int        iml_sdh_count_1_3;            /* count entries           */
#endif
#ifdef HELP_DEBUG
   struct dsd_aux_cf1 *ADSL_AUX_CF1;        /* auxiliary control structure */
#ifndef HL_UNIX
#ifdef __cplusplus
   class clconn1 *ADSL_CONN1_G;             /* pointer on connection   */
#else
   void *     ADSL_CONN1_G;                 /* pointer on connection   */
#endif
#else
   struct dsd_conn1 *ADSL_CONN1_G;          /* pointer on connection   */
#endif
   struct dsd_server_conf_1 *ADSL_SERVER_G;  /* server configuration   */
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   void *     vprl_debug_1[ DEBUG_111213_01 ];  /* save chain in stack */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_1;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_2;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_3;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_4;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_5;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_6;  /* save structure for debugging */
   int        iml_save_line_d1;             /* save the line           */
   int        iml_save_line_d2;             /* save the line           */
#endif

#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   ADSL_AUX_CF1 = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structur */
   ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   ims_debug_count_frse++;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_frse() l%05d started ADSL_CONN1_G=0X%p adsp_pd_work=0X%p",
                   __LINE__, ADSL_CONN1_G, adsp_pd_work );
#endif
#ifdef TRACEHL_SDH_COUNT_1
   iml_sdh_count_1_1 = m_sdh_count_1( ADSL_CONN1_G, -1, "m_pd_do_sdh_frse() started", __LINE__ );
   iml_sdh_count_1_2 = iml_sdh_count_1_1;   /* count entries           */
#endif
#ifndef HELP_DEBUG
#define ADSL_SERVER_G ADSL_CONN1_G->adsc_server_conf_1
#else
   ADSL_SERVER_G = ADSL_CONN1_G->adsc_server_conf_1;
#endif
#ifndef B140525
   adsl_server_conf_1_used = ADSL_SERVER_G;  /* configuration server   */
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   iml1 = 0;                                /* clear index             */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain       */
   while (adsl_sdhc1_w1) {                  /* loop over all buffers   */
     vprl_debug_1[ iml1 ] = adsl_sdhc1_w1;
     iml1++;
     if (iml1 >= DEBUG_111213_01) break;    /* save area is full       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   while (iml1 < DEBUG_111213_01) {         /* fill remaining save area */
     vprl_debug_1[ iml1 ] = NULL;           /* clear entry             */
     iml1++;
   }
   adsl_sdhc1_save_1 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_2 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_3 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_4 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_5 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_6 = NULL;                /* save structure for debugging */
   iml_save_line_d1 = 0;                    /* save the line           */
   iml_save_line_d2 = 0;                    /* save the line           */
#endif
#ifdef OLD_1112
   adsp_pd_work->adsc_gai1_i = NULL;        /* no output data yet      */
#endif
   /* call server-data-hook with data from server                      */
   if (adsp_pd_work->imc_hookc < 0) {       /* hook-count not yet set  */
     adsp_pd_work->imc_hookc = 0;           /* count the hooks         */
#ifdef B140629
#ifdef B101215
     if (ADSL_SERVER_G->boc_sdh_reflect) {  /* only Server-Data-Hook   */
#ifdef FORKEDIT
     }
#endif
#else
     if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook */
         && (adsp_pd_work->inc_count_proc_end == 0)) {  /* do not process start or end of connection */
#endif
#ifdef FORKEDIT
     }
#endif
#endif
#ifndef B140629
     if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook */
         && (adsp_pd_work->inc_count_proc_end == 0)  /* do not process start or end of connection */
         && (adsp_pd_work->boc_eof_server == FALSE)) {  /* not End-of-File Server */
#endif
       adsp_pd_work->imc_hookc = 1;         /* do not reflection       */
#ifdef B140525
       if (adsp_pd_work->imc_hookc >= ADSL_SERVER_G->inc_no_sdh) {  /* do only reflection */
         return;                            /* do not process from server */
       }
#endif
#ifndef B140525
       if (adsp_pd_work->imc_hookc >= adsl_server_conf_1_used->inc_no_sdh) {  /* do only reflection */
         return;                            /* do not process from server */
       }
#endif
     }
   }
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_last_1 = NULL;                /* clear last in chain found */
   adsl_sdhc1_ps_1 = NULL;                  /* no first buffer to process */
   adsl_sdhc1_pe_1 = NULL;                  /* currently processed end */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
         || (adsl_sdhc1_cur_1->inc_position > adsp_pd_work->imc_hookc)) {
       break;
     }
     if (adsl_sdhc1_cur_1->inc_position == adsp_pd_work->imc_hookc) {  /* search for this one */
       if (adsl_sdhc1_ps_1 == NULL) {       /* no first buffer set     */
         adsl_sdhc1_ps_1 = adsl_sdhc1_cur_1;  /* this is first one     */
       }
       adsl_sdhc1_pe_1 = adsl_sdhc1_cur_1;  /* save last buffer to process */
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain  */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifdef B140525
#ifdef B080609
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_SERVER_G + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_SERVER_G + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pprda_frse_20 l%05d adsc_gate1->adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p ADSL_SERVER_G=%p",
                   __LINE__,
                   ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1,
                   ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1, ADSL_SERVER_G );
#endif
#endif
#ifndef B140525
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsl_server_conf_1_used + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pprda_frse_20 l%05d adsc_gate1->adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p ADSL_SERVER_G=%p",
                   __LINE__,
                   ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1,
                   ((char *) (adsl_server_conf_1_used + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1, adsl_server_conf_1_used );
#endif
#endif

   pprda_frse_20:                           /* next server-data-hook   */
#ifndef B140621
   bol_after_sdh_reload = FALSE;            /* after SDH reload        */
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none) {  /* with server connection */
     m_fill_ga1_1( dsrs_deb_ga1_2_1, ADSL_CONN1_G->adsc_sdhc1_chain );
   }
#endif
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
#ifdef B140525
   if (ADSL_SERVER_G->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
   if (bol1) {                              /* do not call SDH         */
     if (adsl_sdhc1_ps_1) {                 /* first buffer set        */
#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[64];
         sprintf( chrh_msg, "sdh-l%05d not-call-sdh", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_ps_1, chrh_msg );
       }
#endif
       iml1 = 0;                            /* clear count             */
       adsl_gai1_w1 = adsl_sdhc1_ps_1->adsc_gather_i_1_i;  /* get start of chain */
       while (adsl_gai1_w1) {               /* loop over all gather input */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;  /* ignore data */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       if (iml1) {                          /* data ignored            */
         m_hlnew_printf( HLOG_WARN1, "HWSPS151W GATE=%(ux)s SNO=%08d INETA=%s SDH no %d already ended - FROMSERVER data ignored %d.",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                         adsp_pd_work->imc_hookc, iml1 );
       }
#ifdef B110904
       adsl_sdhc1_ps_1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
       adsl_sdhc1_ps_1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
       adsl_sdhc1_w1 = adsl_sdhc1_ps_1->adsc_next;  /* get chain remaining blocks */
       while (adsl_sdhc1_w1) {                /* loop over all new buffers */
         if (adsl_sdhc1_w1->inc_function != adsl_sdhc1_ps_1->inc_function) break;
         if (adsl_sdhc1_w1->inc_position != adsl_sdhc1_ps_1->inc_position) break;
#ifdef B110904
         adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
         adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
     }
     adsp_pd_work->imc_hookc++;             /* increment no se-da-hook */
     if (adsp_pd_work->imc_hookc >= ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {
       goto pprda_frse_80;                  /* all Server-Data-Hook processed */
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_pe_1;    /* get last buffer processed */
     adsl_sdhc1_ps_1 = NULL;                /* no buffer to start      */
     while (adsl_sdhc1_cur_1) {             /* loop over buffers processed */
       if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           || (adsl_sdhc1_cur_1->inc_position > adsp_pd_work->imc_hookc)) {
         break;
       }
       if (adsl_sdhc1_cur_1->inc_position == adsp_pd_work->imc_hookc) {
#ifdef B110904
         adsl_sdhc1_cur_1->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
         adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
         if (adsl_sdhc1_ps_1 == NULL) {     /* no buffer to start      */
           adsl_sdhc1_ps_1 = adsl_sdhc1_cur_1;  /* this is first to process */
         }
         adsl_sdhc1_pe_1 = adsl_sdhc1_cur_1;  /* save last buffer to process */
       }
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save last buffer in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     goto pprda_frse_20;                    /* next server-data-hook   */
   }
   ADSL_AUX_CF1->adsc_sdhc1_chain = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   if (adsp_pd_work->imc_hookc > 0) {       /* hook-count 1            */
     adsl_sdhc1_save_1 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* save structure for debugging */
   } else {
     adsl_sdhc1_save_2 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* save structure for debugging */
   }
#endif
#ifdef TRACEHL_SDH_01
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_next = NULL;  /* is only element */
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_usage_count = 0;  /* clear usage count */
#ifndef B140620
   ADSL_AUX_CF1->adsc_sdhc1_chain->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier    */
#endif
   dsl_sdh_l1.achc_work_area = (char *) (ADSL_AUX_CF1->adsc_sdhc1_chain + 1);
   dsl_sdh_l1.inc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
   dsl_sdh_l1.adsc_gather_i_1_in = NULL;    /* no buffer yet           */
   if (adsl_sdhc1_ps_1) {                   /* first buffer set        */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       sprintf( chrh_msg, "sdh-l%05d input-sdh", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_ps_1, chrh_msg );
     }
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
     if (   (adsl_sdhc1_ps_1->adsc_gather_i_1_i)
         && (   (((char *) adsl_sdhc1_ps_1->adsc_gather_i_1_i) < ((char *) adsl_sdhc1_ps_1))
             || (((char *) adsl_sdhc1_ps_1->adsc_gather_i_1_i) > ((char *) adsl_sdhc1_ps_1 + 64)))) {
       m_hlnew_printf( HLOG_TRACE1, "DEBUG_150218_01 l%05d adsl_sdhc1_ps_1=%p adsl_sdhc1_ps_1->adsc_gather_i_1_i=%p.",
                       __LINE__, adsl_sdhc1_ps_1, adsl_sdhc1_ps_1->adsc_gather_i_1_i );
     }
#endif
     dsl_sdh_l1.adsc_gather_i_1_in = adsl_sdhc1_ps_1->adsc_gather_i_1_i;  /* get start of chain */
     while (dsl_sdh_l1.adsc_gather_i_1_in) {  /* loop to find valid gather */
       if (dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_cur
             < dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_end) {
         break;
       }
       dsl_sdh_l1.adsc_gather_i_1_in = dsl_sdh_l1.adsc_gather_i_1_in->adsc_next;
     }
   }
#ifdef CHECK_SDH_01
   adsl_gai1_h1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* save input        */
#endif
   dsl_sdh_l1.inc_func = DEF_IFUNC_FROMSERVER;
   achl_func = "DEF_IFUNC_FROMSERVER";      /* function called         */
#ifndef B101214
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
#ifndef B120116
       && (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* no server connection */
#endif
       && (adsp_pd_work->imc_hookc == 0)) {  /* count the hooks        */
     dsl_sdh_l1.inc_func = DEF_IFUNC_REFLECT;
     achl_func = "DEF_IFUNC_REFLECT";       /* function called         */
   }
#endif
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* auxiliary control structur */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.imc_signal = m_ret_signal( ADSL_AUX_CF1 );  /* search signal */
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
#ifdef B131225
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
#ifdef B140525
#ifndef B131225
   adsl_server_conf_1_w1 = ADSL_SERVER_G;   /* configuration server    */
   while (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
   }
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_w1 + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
#endif
#ifndef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_used + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
   dsl_sdh_l1.imc_signal = 0;               /* clear signal            */
   if (ADSL_CONN1_G->boc_signal_set) {      /* signal for component set */
     dsl_sdh_l1.imc_signal = m_ret_signal( ADSL_AUX_CF1 );  /* search signal */
   }
   dsl_sdh_l1.boc_eof_client = adsp_pd_work->boc_eof_client;  /* End-of-File Client */
   dsl_sdh_l1.boc_eof_server = adsp_pd_work->boc_eof_server;  /* End-of-File Server */
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
#ifdef B140525
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                           ((char *) (ADSL_SERVER_G + 1) \
                             + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifndef B140525
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                           ((char *) (adsl_server_conf_1_used + 1) \
                             + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifdef OLD_1112
   dsl_sdh_l1.ac_hobwspat2_conf = ADSL_CONN1_G->adsc_gate1->vpc_hlwspat2_conf;  /* data from HOB-WSP-AT2 configuration */
#else
   dsl_sdh_l1.ac_hobwspat3_conf = ADSL_CONN1_G->adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
#endif
   /* flags of configuration                                           */
   if (ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_gate1->inc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
   }
#endif
#ifndef OLD_1112
   if (ADSL_CONN1_G->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (ADSL_CONN1_G->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
#endif
   if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   iml1 = 0;
   if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups */
     iml1 = ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group;  /* number of LDAP groups */
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server configured     */
       && (ADSL_CONN1_G->adsc_server_conf_1->imc_no_ldap_group)) {  /* number of LDAP groups */
     iml1 = ADSL_CONN1_G->adsc_server_conf_1->imc_no_ldap_group;  /* number of LDAP groups */
   }
   if (iml1) {                              /* number of LDAP groups   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (iml1 > 1) {                        /* number of LDAP groups   */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
#ifndef HL_UNIX
// if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act()) {  /* still data to send to client */
   if (   (ADSL_CONN1_G->iec_st_cls == clconn1::ied_cls_closed)  /* client connection closed */
       || (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act())) {  /* still data to send to client */
     dsl_sdh_l1.boc_send_client_blocked = TRUE;  /* sending to the client is blocked */
   }
#else
// if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* still data to send to client */
   if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_closed)  /* client connection closed */
       || (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send)) {  /* still data to send to client */
     dsl_sdh_l1.boc_send_client_blocked = TRUE;  /* sending to the client is blocked */
   }
#endif
   dsl_sdh_l1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_INT) {  /* WSP Trace SDH intern */
     dsl_sdh_l1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
#ifdef CHECK_SDH_01
   adsl_gai1_check1 = NULL;                 /* clear for checks        */
   adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain */
   while (adsl_gai1_w1) {                   /* loop over all input gather */
     adsl_gai1_check1 = adsl_gai1_w1;       /* save for checks         */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#endif
#ifdef TRACEHL1
   {
     void *vph1, *vph2;
     vph1 = ADSL_SDH_LIB1;
     vph2 = (void *) ADSL_SDH_LIB1->amc_hlclib01;
     m_hlnew_printf( HLOG_TRACE1, "pprda_frse_20 addr method1 adsp_pd_work->imc_hookc=%d amc_hlclib01<%p>=%p",
                     adsp_pd_work->imc_hookc, &ADSL_SDH_LIB1->amc_hlclib01, vph2 );
   }
#endif
#ifndef B140621

   pprda_frse_28:                           /* call SDH                */
#endif
#ifdef WSP_TRACE_TRY01
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSDHCAL1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = 0;                       /* clear counters          */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1++;                              /* count gather            */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
// to-do 13.03.14 KB - signal
     iml3 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SNO=%08d call SDH %s hookc=%d no-gather-input=%d length-data-input=%d/0X%X imc_flags_1=0X%08X imc_signal=0X%08X eof-client=%d eof-server=%d",
                     ADSL_CONN1_G->dsc_co_sort.imc_sno, achl_func, adsp_pd_work->imc_hookc, iml1, iml2, iml2,
                     dsl_sdh_l1.imc_flags_1, dsl_sdh_l1.imc_signal, dsl_sdh_l1.boc_eof_client, dsl_sdh_l1.boc_eof_server );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml3;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml3 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (   (iml2)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH input gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
           iml_w2 += iml6;                  /* increment displacement  */
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           bol1 = FALSE;                    /* reset more flag         */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             adsl_wtr_w1->boc_more = bol1;  /* more data to follow     */
             bol1 = TRUE;                   /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   if (   (adss_gai1_break_1 != NULL)
       && (adss_gai1_break_1 != dsl_sdh_l1.adsc_gather_i_1_in)) {
     m_hlnew_printf( HLOG_TRACE1, "DEBUG_150218_01 l%05d adss_gai1_break_1=%p dsl_sdh_l1.adsc_gather_i_1_in=%p.",
                     __LINE__, adss_gai1_break_1, dsl_sdh_l1.adsc_gather_i_1_in );
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#ifdef DEBUG_150218_01                      /* problem gather          */
   adss_gai1_break_1 = NULL;
   if (   (dsl_sdh_l1.adsc_gather_i_1_in != NULL)
       && ((dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_end - dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_cur) > 0)) {
     adss_gai1_break_1 = dsl_sdh_l1.adsc_gather_i_1_in;
   }
#endif
#ifdef HELP_DEBUG
   ADSL_SERVER_G = ADSL_CONN1_G->adsc_server_conf_1;
#endif
#ifdef B140525
   if (ADSL_SERVER_G->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSDHRET1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = iml3 = iml4 = iml5 = 0;  /* clear counters          */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get chain output data to client */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml2++;                              /* count gather            */
       iml3 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_server;  /* get chain output data to server */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml4++;                              /* count gather            */
       iml5 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml6 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "returned SDH %s hookc=%d inc_return=%d remaining-length-data-input=%d/0X%X out_to_client:g=%d l=%d/0X%X out_to_server:g=%d l=%d/0X%X.",
                     achl_func, adsp_pd_work->imc_hookc, dsl_sdh_l1.inc_return,
                     iml1, iml1, iml2, iml3, iml3, iml4, iml5, iml5 );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml6;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml6 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (   (iml3)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get chain output data to client */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH returned out-to-client gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           bol1 = FALSE;                    /* reset more flag         */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             adsl_wtr_w1->boc_more = bol1;  /* more data to follow     */
             bol1 = TRUE;                   /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
#ifdef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
     if (   (iml5)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_server;  /* get chain output data to server */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH returned out-to-server gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           bol1 = FALSE;                    /* reset more flag         */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             adsl_wtr_w1->boc_more = bol1;  /* more data to follow     */
             bol1 = TRUE;                   /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
#ifdef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef DEBUG_120530_01                      /* warning SDHs too many work-areas */
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   iml1 = 0;                                /* count entries           */
   do {                                     /* loop over work areas    */
     iml1++;                                /* count entries           */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   } while (adsl_sdhc1_w1);
   if (iml1 >= DEBUG_120530_01) {           /* too many entries        */
     m_hlnew_printf( HLOG_TRACE1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SDH no %d FROMSERVER warning - %d = too many work areas.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_pd_work->imc_hookc, iml1 );
   }
#endif
#ifdef TRACEHL_SDH_COUNT_1
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   iml_sdh_count_1_3 = 0;                   /* count entries           */
   while (adsl_sdhc1_w1) {                  /* loop over work areas    */
     iml_sdh_count_1_3++;                   /* count entries           */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   iml_sdh_count_1_1 += iml_sdh_count_1_3;  /* add to count over all   */
#endif
#ifndef HL_UNIX
   if (   (ADSL_CONN1_G->iec_st_cls == clconn1::ied_cls_closed)  /* client connection closed */
#ifdef FORKEDIT
      )
#endif
#endif
#ifdef HL_UNIX
   if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_closed)  /* client connection closed */
#endif
       && (dsl_sdh_l1.adsc_gai1_out_to_client)) {  /* chain output data to client */
     iml1 = 0;                              /* clear count             */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get start of chain */
     while (adsl_gai1_w1) {                 /* loop over all gather input */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;  /* ignore data */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if (iml1) {                            /* data ignored            */
       m_hlnew_printf( HLOG_WARN1, "HWSPS153W GATE=%(ux)s SNO=%08d INETA=%s client ended and SDH no %d sends data to client - data ignored %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       adsp_pd_work->imc_hookc, iml1 );
     }
     dsl_sdh_l1.adsc_gai1_out_to_client = NULL;  /* clear chain output data to client */
   }
   if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
#ifdef DEBUG_150218_01                      /* problem gather          */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SDUMP001", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "l%05d DEBUG_150218_01 dsrs_deb_ga1_2_1.",
                       __LINE__ );
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
       adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
       adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
       ADSL_WTR_G2->imc_length = DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2);  /* length of text / data */
       memcpy( ADSL_WTR_G2 + 1, dsrs_deb_ga1_2_1, DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2) );
       adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
       /* second buffer */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SDUMP002", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "l%05d DEBUG_150218_01 dsrs_deb_ga1_2_2.",
                       __LINE__ );
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
       adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
       adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
       ADSL_WTR_G2->imc_length = DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2);  /* length of text / data */
       memcpy( ADSL_WTR_G2 + 1, dsrs_deb_ga1_2_2, DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2) );
       adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     }
#endif
#ifdef B140525
     if (ADSL_SERVER_G->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140525
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140620
     m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of Server-Data-Hook */
#endif
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
   }
#ifdef CHECK_SDH_01
   if (dsl_sdh_l1.adsc_gather_i_1_in != adsl_gai1_h1) {
     m_hlnew_printf( HLOG_WARN1, "m_pd_do_sdh_frse() l%05d returned gater_i_1_in corrupted",
                     __LINE__ );
#ifndef HL_UNIX
     ExitProcess( 1 );
#else
     exit( 1 );
#endif
   }
#ifdef NO_NEW_WSP_1102
   adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_out;  /* get start of chain */
#else
   adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get start of chain output data to client */
#endif
   while (adsl_gai1_w1) {                   /* loop over all input gather */
     if (adsl_gai1_check1 == adsl_gai1_w1) {  /* checks if last of input */
       m_hlnew_printf( HLOG_WARN1, "m_pd_do_sdh_frse() l%05d returned gater_i_1_out contains part of input",
                       __LINE__ );
#ifndef HL_UNIX
       ExitProcess( 1 );
#else
       exit( 1 );
#endif
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#endif
#ifdef TRACE_P_060922                       /* problem received data   */
   if (dsl_sdh_l1.adsc_gather_i_1_out) {
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_out;  /* get start of chain */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_frse l%05d time-sec=%lld\
 achc_ginp_cur=%p achc_ginp_end=%p data=0X%02X",
                       __LINE__, m_get_time(),
                       adsl_gai1_w1->achc_ginp_cur, adsl_gai1_w1->achc_ginp_end,
                       *((unsigned char *) adsl_gai1_w1->achc_ginp_cur) );
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
   }
#endif /* TRACE_P_060922                       problem received data   */
   /* mark buffers                                                     */
#ifdef OLD01
   adsl_sdhc1_cur_1 = adsl_sdhc1_ps_1;      /* get first buffer processed */
   while (adsl_sdhc1_cur_1) {               /* loop over buffers processed */
     adsl_sdhc1_cur_1->boc_ready_t_p = dsl_sdh_l1.boc_callagain;  /* ready to process */
     if (adsl_sdhc1_cur_1 == adsl_sdhc1_pe_1) break;
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
   }
#endif
#ifndef WA_150216_01
#ifdef B120107
#ifdef B110310
   if (   (dsl_sdh_l1.inc_func == DEF_IFUNC_REFLECT)
#ifdef FORKEDIT
      )
#endif
#else
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
       && (adsp_pd_work->imc_hookc == 0)    /* does reflection         */
#endif
#ifdef FORKEDIT
      )
#endif
#else
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
       && (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* no server connection */
       && (adsp_pd_work->imc_hookc == 0)    /* does reflection         */
#endif
       && (dsl_sdh_l1.adsc_gai1_out_to_server)) {  /* check start of chain output data to server */
// to-do 07.03.11 KB error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SDH imc_hookc=%d DEF_IFUNC_REFLECT returned data to send to server - illogic",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_pd_work->imc_hookc );
#ifdef B140525
     if (ADSL_SERVER_G->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140525
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140620
     m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of Server-Data-Hook */
#endif
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "error from Server-Data-Hook";
     }
     adsp_pd_work->boc_eof_server = TRUE;   /* End-of-File Server      */
     if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
       adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
     }
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
     dsl_sdh_l1.adsc_gai1_out_to_server = NULL;  /* clear start of chain output data to server */
   }
#endif
   iel_sdhcs = ied_sdhcs_idle;              /* idle, has been processed */
   if (dsl_sdh_l1.boc_callagain) {          /* process input again     */
     iel_sdhcs = ied_sdhcs_activate;        /* activate SDH when possible */
   } else if (dsl_sdh_l1.boc_notify_send_client_possible) {  /* notify SDH when sending to the client is possible */
     iel_sdhcs = ied_sdhcs_wait_send_client;  /* wait to send to client is possible */
   }
   if (adsl_sdhc1_ps_1) {                   /* buffers have been given */
     adsl_sdhc1_cur_1 = adsl_sdhc1_ps_1;    /* get first buffer processed */
     while (TRUE) {                         /* loop over buffers processed */
#ifdef B110904
       adsl_sdhc1_cur_1->boc_ready_t_p = dsl_sdh_l1.boc_callagain;  /* ready to process */
#endif
       adsl_sdhc1_cur_1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
       if (adsl_sdhc1_cur_1 == adsl_sdhc1_pe_1) break;
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
     }
   } else if (iel_sdhcs != ied_sdhcs_idle) {  /* not idle, has not been processed */
     adsl_sdhc1_ps_1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
     iml_sdh_count_1_1++;                   /* add to count over all   */
#endif
#ifndef TRACEHL_SDH_01
     memset( adsl_sdhc1_ps_1, 0, sizeof(struct dsd_sdh_control_1) );
#else
     {
       int imh1 = adsl_sdhc1_ps_1->imc_line_no[ 0 ];
       memset( adsl_sdhc1_ps_1, 0, sizeof(struct dsd_sdh_control_1) );
       adsl_sdhc1_ps_1->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
       adsl_sdhc1_ps_1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
     }
#endif
     adsl_sdhc1_ps_1->inc_function = DEF_IFUNC_FROMSERVER;
     adsl_sdhc1_ps_1->inc_position = adsp_pd_work->imc_hookc;
     adsl_sdhc1_ps_1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
     if (adsl_sdhc1_last_1 == NULL) {       /* not previous control area set */
       adsl_sdhc1_ps_1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
#ifndef TRY_111117_01
// to-do 17.11.11 KB the following instruction makes no sense since adsl_sdhc1_last_1 == NULL
// should it be adsl_sdhc1_ps_1 instead of adsl_sdhc1_last_1 ???
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_last_1;  /* set new chain */
#else
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_ps_1;  /* set new chain */
#endif
     } else {                               /* middle in chain         */
       adsl_sdhc1_ps_1->adsc_next = adsl_sdhc1_last_1->adsc_next;  /* get control areas behind */
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_ps_1;  /* insert this one */
     }
     adsl_sdhc1_pe_1 = adsl_sdhc1_ps_1;     /* currently processed end */
   }
   adsl_sdhc1_out_to_client = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* output data to client */
#ifdef DEBUG_120530_01                      /* warning SDHs too many work-areas */
   adsl_sdhc1_out_to_client = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* output data to client */
#endif
   adsl_sdhc1_out_to_server = NULL;         /* output data to server   */
   if (dsl_sdh_l1.adsc_gai1_out_to_server) {  /* check start of chain output data to server */
     if (dsl_sdh_l1.adsc_gai1_out_to_client) {  /* check start of chain output data to client */
       adsl_sdhc1_out_to_server = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
       iml_sdh_count_1_1++;                 /* add to count over all   */
#endif
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
     iml1 = adsp_pd_work->imc_hookc - 1;    /* get hook count minus one - next step or SSL server direct */
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* get chain to be sent to server */
     while (adsl_sdhc1_w1) {                /* loop over all new buffers */
       adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gai1_out_to_server;  /* set start of chain output data to server */
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = iml1;
#ifdef B110904
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_out_to_server->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gai1_out_to_server;  /* set start of chain output data to server */
     adsl_sdhc1_w1 = adsl_sdhc1_last_1;     /* get last gather found   */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save start              */
     if (adsl_sdhc1_w1 == NULL) adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
//   adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save start              */
     adsl_sdhc1_ps_2 = NULL;                /* no buffer to start      */
     while (adsl_sdhc1_w1) {                /* loop over remaining buffers */
#ifdef B110315
       if (   (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position < adsp_pd_work->imc_hookc)) {
         break;
       }
       if (   (adsl_sdhc1_ps_2 == NULL)     /* no buffer to start      */
           && (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position == adsp_pd_work->imc_hookc)) {
         adsl_sdhc1_ps_2 = adsl_sdhc1_w1;   /* set buffer to start     */
       }
#endif
#ifndef B110315
       if (   (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position < iml1)) {
         break;
       }
       if (   (adsl_sdhc1_ps_2 == NULL)     /* no buffer to start      */
           && (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position == iml1)) {
         adsl_sdhc1_ps_2 = adsl_sdhc1_w1;   /* set buffer to start     */
       }
#endif
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save last buffer        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* get chain to insert */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
     if (adsl_sdhc1_w2) {                   /* append to chain         */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_w2->adsc_next;  /* get old end of chain */
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_out_to_server;  /* set start of chain */
// to-do 07.03.11 KB append gather
       if (adsl_sdhc1_ps_2) {               /* buffer to start found   */
         /* chain of gather input                                      */
         adsl_gai1_cur = adsl_sdhc1_ps_2->adsc_gather_i_1_i;
         adsl_gai1_last = NULL;             /* clear last element      */
         while (adsl_gai1_cur) {
           adsl_gai1_last = adsl_gai1_cur;
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         }
         if (adsl_gai1_last == NULL) {      /* insert at start of chain */
           adsl_sdhc1_ps_2->adsc_gather_i_1_i = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
         } else {                           /* insert middle in chain  */
           adsl_gai1_last->adsc_next = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
         }
       }
     } else {                               /* set at start of chain   */
       adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* append old chain to new entries */
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_out_to_server;  /* set start of chain */
     }
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_frse() after insert out_to_server", __LINE__ );
#endif
   }
   if (dsl_sdh_l1.boc_callrevdir) {         /* requested to call again in reverse direction */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "pprda_frse_20 boc_callrevdir adsp_pd_work->imc_hookc=%d", adsp_pd_work->imc_hookc );
#endif
#ifdef B11213
     adsl_sdhc1_cur_2 = adsl_sdhc1_pe_1;    /* get last buffer processed */
     adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element        */
#else
     adsl_sdhc1_cur_2 = adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element */
#endif
     while (adsl_sdhc1_cur_2) {             /* loop over buffers processed */
       if (   (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_TOSERVER)
           && (adsl_sdhc1_cur_2->inc_position <= adsp_pd_work->imc_hookc)) {
         break;
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save last buffer in chain */
       adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
     }
     if (   (adsl_sdhc1_cur_2)              /* still buffer            */
         && (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_TOSERVER)
         && (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc)) {
       do {                                 /* loop over all for this sdh */
#ifdef B110904
         adsl_sdhc1_cur_2->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
         adsl_sdhc1_cur_2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
         adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
       } while (   (adsl_sdhc1_cur_2)       /* still buffer            */
                && (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_TOSERVER)
                && (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc));
     } else {                               /* insert new buffer       */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
       iml_sdh_count_1_1++;                 /* add to count over all   */
#endif
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#else
       {
         int imh1 = adsl_sdhc1_w1->imc_line_no[ 0 ];
         memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
         adsl_sdhc1_w1->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_w1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = adsp_pd_work->imc_hookc;
#ifdef B110904
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_cur_2;
       if (adsl_sdhc1_last_2 == NULL) {     /* insert at start of chain */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_2->adsc_next = adsl_sdhc1_w1;
       }
#ifdef TRACEHL_SDH_01
       m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_frse() revdir", __LINE__ );
#endif
     }
   }
#ifdef DEBUG_150218_01                      /* problem gather          */
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none) {  /* with server connection */
     m_fill_ga1_1( dsrs_deb_ga1_2_2, ADSL_CONN1_G->adsc_sdhc1_chain );
   }
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "sdh-l%05d after-sdh-1", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifndef HL_UNIX
   if (   (ADSL_CONN1_G->iec_st_cls == clconn1::ied_cls_closed)  /* client connection closed */
#ifdef FORKEDIT
      )
#endif
#endif
#ifdef HL_UNIX
   if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_closed)  /* client connection closed */
#endif
       && (dsl_sdh_l1.adsc_gai1_out_to_client)) {  /* chain output data to client */
     iml1 = 0;                              /* clear count             */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get start of chain */
     while (adsl_gai1_w1) {                 /* loop over all gather input */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;  /* ignore data */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if (iml1) {                            /* data ignored            */
       m_hlnew_printf( HLOG_WARN1, "HWSPS154W GATE=%(ux)s SNO=%08d INETA=%s client ended and SDH no %d sends data to client - data ignored %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       adsp_pd_work->imc_hookc, iml1 );
     }
     dsl_sdh_l1.adsc_gai1_out_to_client = NULL;  /* clear chain output data to client */
   }
   if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
     if (adsp_pd_work->boc_end_sdh == FALSE) {  /* first time end      */
       if (dsl_sdh_l1.inc_return == DEF_IRET_END) {
         ADSL_CONN1_G->achc_reason_end = "end from Server-Data-Hook";
       } else {
         ADSL_CONN1_G->achc_reason_end = "error from Server-Data-Hook";
       }
       adsp_pd_work->boc_end_sdh = TRUE;    /* close in progress       */
     }
     adsp_pd_work->boc_eof_server = TRUE;   /* End-of-File Server      */
     if (dsl_sdh_l1.inc_return == DEF_IRET_END) {
       achl_w1 = "end";
     } else {
       achl_w1 = "abend";
     }
     sprintf( ADSL_CONN1_G->chrc_server_error,  /* display server error */
              "Server-Data-Hook stage %d returned %s %d",
              adsp_pd_work->imc_hookc, achl_w1, dsl_sdh_l1.inc_return );
     if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
       adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
#ifndef B140716
// 17.07.14 KB - ohne Wirkung
       adsp_pd_work->boc_abend = TRUE;      /* do not process more     */
#endif
     }
   }
   /* insert this buffer into the session-wide chain                   */
   adsp_pd_work->imc_hookc++;               /* increment no se-da-hook */
#ifdef B090731
   if (   (adsp_pd_work->imc_hookc == ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)
       && (adsp_pd_work->adsc_gai1_i == NULL)) {  /* no output data yet */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_out;  /* get output data */
     while (adsl_gai1_w1) {                 /* loop over output        */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     adsp_pd_work->adsc_gai1_i = adsl_gai1_w1;  /* set output data     */
   }
#endif
#ifdef B110307
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   do {
     adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gather_i_1_out;
     adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;  /* function of SDH */
     adsl_sdhc1_w1->inc_position = adsp_pd_work->imc_hookc;  /* position of SDH */
#ifndef B090731
     if (adsp_pd_work->imc_hookc >= ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {
       adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK;  /* maximum number server-data-hook configured */
     }
#endif
     adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* not ready to process    */
     if (dsl_sdh_l1.adsc_gather_i_1_out) {  /* output data set         */
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
     }
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save last element       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   } while (adsl_sdhc1_w1);
#else
   if (adsl_sdhc1_out_to_client == NULL) {  /* no output data to client */
#ifndef B111213
// question 13.12.11 KB: do we need to set adsl_sdhc1_ps_2, adsl_sdhc1_pe_2 and adsl_sdhc1_last_2 ???
     adsl_sdhc1_cur_2 = adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element */
     adsl_sdhc1_ps_2 = adsl_sdhc1_pe_2 = NULL;  /* no buffers to pass  */
     while (adsl_sdhc1_cur_2) {             /* loop over buffers processed */
       if (   (adsl_sdhc1_cur_2->inc_function != DEF_IFUNC_FROMSERVER)
           || (adsl_sdhc1_cur_2->inc_position > adsp_pd_work->imc_hookc)) {
         break;
       }
       if (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc) {
         if (adsl_sdhc1_ps_2 == NULL) {     /* no buffer to start      */
           adsl_sdhc1_ps_2 = adsl_sdhc1_cur_2;  /* this is first to process */
         }
         adsl_sdhc1_pe_2 = adsl_sdhc1_cur_2;  /* save last buffer to process */
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save last buffer in chain */
       adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
     }
#endif
     goto pprda_frse_40;                    /* after output to client processed */
   }
#ifdef B110904
   bol1 = FALSE;                            /* reset flag ready to process */
   if (dsl_sdh_l1.adsc_gai1_out_to_client) bol1 = TRUE;  /* set flag ready to process */
#endif
   iel_sdhcs = ied_sdhcs_idle;              /* idle, has been processed */
   if (dsl_sdh_l1.adsc_gai1_out_to_client) {  /* output to client returned */
     iel_sdhcs = ied_sdhcs_activate;        /* activate SDH when possible */
   }
   iml1 = adsp_pd_work->imc_hookc;          /* position of SDH         */
   if (iml1 >= ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {
     iml1 = MAX_SERVER_DATA_HOOK;           /* maximum number server-data-hook configured */
   }
   adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* output data to client */
   do {
     adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get start of chain output data to client */
     adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;  /* function of SDH */
     adsl_sdhc1_w1->inc_position = iml1;    /* position of SDH         */
#ifdef B110904
     adsl_sdhc1_w1->boc_ready_t_p = bol1;   /* set flag ready to process */
#endif
     adsl_sdhc1_w1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save last element       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   } while (adsl_sdhc1_w1);
#endif

   /* now insert all new blocks into session-wide chain                */
#ifdef B111213
   adsl_sdhc1_cur_2 = adsl_sdhc1_pe_1;      /* get last buffer processed */
#ifndef B110211
   if (adsl_sdhc1_cur_2 == NULL) {          /* no current position     */
     adsl_sdhc1_cur_2 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get total old chain */
   }
#endif
   adsl_sdhc1_last_2 = adsl_sdhc1_last_1;   /* get last element        */
   adsl_sdhc1_ps_2 = NULL;                  /* no buffer to start      */
   adsl_sdhc1_pe_2 = adsl_sdhc1_pe_1;       /* get last buffer processed */
#else
   adsl_sdhc1_cur_2 = adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element */
   adsl_sdhc1_ps_2 = adsl_sdhc1_pe_2 = NULL;  /* no buffers to pass    */
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   if (adsp_pd_work->imc_hookc > 1) {       /* hook-count 1            */
     iml_save_line_d1 = __LINE__;           /* save the line           */
     adsl_sdhc1_save_3 = adsl_sdhc1_last_2;  /* save structure for debugging */
   } else {
     adsl_sdhc1_save_4 = adsl_sdhc1_last_2;  /* save structure for debugging */
   }
#endif
   while (adsl_sdhc1_cur_2) {               /* loop over buffers processed */
     if (   (adsl_sdhc1_cur_2->inc_function != DEF_IFUNC_FROMSERVER)
#ifndef TRY_091014_01
         || (adsl_sdhc1_cur_2->inc_position > adsp_pd_work->imc_hookc)) {
#else
#ifdef FORKEDIT
     }
        (
#endif
         || (adsl_sdhc1_cur_2->inc_position > adsl_sdhc1_w2->inc_position)) {
#endif
       break;
     }
#ifndef TRY_091014_01
     if (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc) {
#else
#ifdef FORKEDIT
     }
#endif
     if (adsl_sdhc1_cur_2->inc_position == adsl_sdhc1_w2->inc_position) {
#endif
#ifdef B110904
       adsl_sdhc1_cur_2->boc_ready_t_p = TRUE;  /* ready to process    */
#endif
       adsl_sdhc1_cur_2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
#ifdef B110307
       adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
#else
       adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* output data to client */
#endif
       do {
#ifdef B110904
         adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
         adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
       } while (adsl_sdhc1_w1);
       if (adsl_sdhc1_ps_2 == NULL) {       /* no buffer to start      */
         adsl_sdhc1_ps_2 = adsl_sdhc1_cur_2;  /* this is first to process */
       }
       adsl_sdhc1_pe_2 = adsl_sdhc1_cur_2;  /* save last buffer to process */
     }
     adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save last buffer in chain */
     adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "sdh-l%05d after-sdh-2", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef NEW_110211_XXX
   if (adsl_sdhc1_cur_2 == NULL) {          /* no current position     */
     adsl_sdhc1_cur_2 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get total old chain */
   }
#endif
#ifdef B111213
   adsl_sdhc1_w2->adsc_next = adsl_sdhc1_cur_2;
#endif
   if (adsl_sdhc1_last_2 == NULL) {         /* insert at start of chain */
#ifndef B111213
     adsl_sdhc1_w2->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get old chain */
#endif
     ADSL_CONN1_G->adsc_sdhc1_chain = ADSL_AUX_CF1->adsc_sdhc1_chain;
   } else {                                 /* insert middle in chain  */
#ifdef DEBUG_100810
#ifdef B100815
// 15.08.10 KB adsl_sdhc1_last_2->adsc_next should be adsl_sdhc1_cur_2
// so there is no need to do this routine
     if (adsl_sdhc1_last_2->adsc_next) {
       adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
       while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_last_2->adsc_next;
     }
#endif
#endif
#ifndef B111213
     adsl_sdhc1_w2->adsc_next = adsl_sdhc1_last_2->adsc_next;  /* get old chain end */
#endif
     adsl_sdhc1_last_2->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain;
   }
   if (adsl_sdhc1_ps_2 == NULL) {           /* no buffer to start      */
#ifdef B110307
     adsl_sdhc1_ps_2 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* this is first to process */
#else
     adsl_sdhc1_ps_2 = adsl_sdhc1_out_to_client;  /* output data to client */
#endif
#ifdef B111213
     adsl_sdhc1_pe_2 = adsl_sdhc1_w2;       /* this is last to process */
#endif
   } else {
     /* chain of gather input                                          */
     adsl_gai1_cur = adsl_sdhc1_ps_2->adsc_gather_i_1_i;
     adsl_gai1_last = NULL;                 /* clear last element      */
     while (adsl_gai1_cur) {
       adsl_gai1_last = adsl_gai1_cur;
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;
     }
#ifdef B110307
     if (adsl_gai1_last == NULL) {          /* insert at start of chain */
       adsl_sdhc1_ps_2->adsc_gather_i_1_i = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
     } else {                               /* insert middle in chain  */
       adsl_gai1_last->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
     }
#else
     if (adsl_gai1_last == NULL) {          /* insert at start of chain */
       adsl_sdhc1_ps_2->adsc_gather_i_1_i = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;
     } else {                               /* insert middle in chain  */
       adsl_gai1_last->adsc_next = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;
     }
#endif
   }
#ifndef B111213
   adsl_sdhc1_last_2 = adsl_sdhc1_pe_2 = adsl_sdhc1_w2;  /* this is last to process */
#endif
#ifdef TRACEHL_SDH_COUNT_1
   m_sdh_count_1( ADSL_CONN1_G, iml_sdh_count_1_1, "m_pd_do_sdh_frse() before pprda_frse_40", __LINE__ );
#endif
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_frse() after insert out_to_client", __LINE__ );
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   if (adsp_pd_work->imc_hookc > 1) {       /* hook-count 1            */
     iml_save_line_d2 = __LINE__;           /* save the line           */
     adsl_sdhc1_save_3 = adsl_sdhc1_last_2;  /* save structure for debugging */
   } else {
     adsl_sdhc1_save_4 = adsl_sdhc1_last_2;  /* save structure for debugging */
   }
#endif

   pprda_frse_40:                           /* after output to client processed */
#ifdef WAS_BEFORE_1501
#ifndef B140621
   if (ADSL_AUX_CF1->adsc_sdh_reload_saved) {  /* SDH, saved for reload */
     adsp_pd_work->imc_hookc--;             /* decrement no se-da-hook */
     m_sdh_reload_do( ADSL_AUX_CF1, adsp_pd_work->imc_hookc );
     dsl_sdh_l1.inc_func = DEF_IFUNC_RELOAD;  /* SDH reload            */
     achl_func = "DEF_IFUNC_RELOAD";        /* function called         */
     dsl_sdh_l1.adsc_gather_i_1_in = NULL;  /* set start of chain input */
     dsl_sdh_l1.adsc_gai1_out_to_client = NULL;  /* set chain output data to client */
     dsl_sdh_l1.adsc_gai1_out_to_server = NULL;  /* set chain output data to server */
     dsl_sdh_l1.imc_signal = 0;             /* clear signal            */
     bol_after_sdh_reload = TRUE;           /* after SDH reload        */
     goto pprda_frse_28;                    /* call SDH                */
   }
   if (bol_after_sdh_reload) {              /* after SDH reload        */
     adsp_pd_work->imc_hookc--;             /* decrement no se-da-hook */
     goto pprda_frse_20;                    /* same server-data-hook again */
   }
#endif
#endif
#ifdef WAS_BEFORE_1501
   if (dsl_sdh_l1.boc_callagain) {          /* process last server-data-hook again */
#ifdef WAS_BEFORE_1501
     adsp_pd_work->imc_hookc--;             /* decrement no se-da-hook */
     goto pprda_frse_20;                    /* same server-data-hook again */
#endif
     /* first send output data to client,
        then process this SDH again                                    */
   }
#endif
   /* check if more Server-Data-Hooks to process                       */
   if (adsp_pd_work->imc_hookc < ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {
     adsl_sdhc1_ps_1 = adsl_sdhc1_ps_2;     /* get next element start  */
     adsl_sdhc1_pe_1 = adsl_sdhc1_pe_2;     /* get next element end    */
     adsl_sdhc1_last_1 = adsl_sdhc1_last_2;  /* get new last element   */
     goto pprda_frse_20;                    /* next server-data-hook   */
   }

#undef ADSL_SDH_LIB1

   pprda_frse_80:                           /* all Server-Data-Hook processed */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "sdh-l%05d end m_pd_do_sdh_frse", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACEHL_SDH_COUNT_1
   m_sdh_count_1( ADSL_CONN1_G, iml_sdh_count_1_1, "m_pd_do_sdh_frse() return", __LINE__ );
#endif
   return;
#ifndef HELP_DEBUG
#undef ADSL_SERVER_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_pd_do_sdh_frse()                                            */

/**
  Subroutine to process Server-Data-Hook with data to Server

  The routine m_pd_do_sdh_tose() reads and returns data
  only on the session-wide chain ADSL_CONN1_G->adsc_sdhc1_chain

*/
static void m_pd_do_sdh_tose( struct dsd_pd_work *adsp_pd_work ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7;  /* working variables */
   int        iml_w1, iml_w2;               /* working variables       */
   int        iml_special_func;             /* call with special function */
   BOOL       bol1;                         /* working variable        */
#ifndef B140621
   BOOL       bol_after_sdh_reload;         /* after SDH reload        */
#endif
   enum ied_sdhc_state iel_sdhcs;           /* state of control area server data hook */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   char       *achl_func;                   /* function called         */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_2;  /* current location 2  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_2;  /* last location 2    */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_1;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_1;  /* currently processed end */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_2;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_2;  /* currently processed end */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_client;  /* output data to client */
   struct dsd_sdh_control_1 *adsl_sdhc1_out_to_server;  /* output data to server */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gather_i_1_i;  /* gather input data     */
#endif
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_check1;  /* for checks             */
#endif
#ifdef B140525
#ifndef B131225
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server */
#endif
#endif
#ifndef B140525
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
#ifdef DEBUG_111116_01                      /* block is lost           */
   BOOL       bol_lost_block_01;            /* block acquired          */
   BOOL       bol_lost_block_02;            /* block inserted          */
   BOOL       bol_lost_block_03;            /* block at beginning      */
   struct dsd_sdh_control_1 *adsl_sdhc1_inserted_at_1;  /* position inserted */
   int        imrl_lines[ DEBUG_111116_01 ];
#endif
#ifdef TRACEHL_SDH_COUNT_1
   int        iml_sdh_count_1_1;            /* count entries           */
   int        iml_sdh_count_1_2;            /* count entries           */
   int        iml_sdh_count_1_3;            /* count entries           */
#endif
#ifdef HELP_DEBUG
   struct dsd_aux_cf1 *ADSL_AUX_CF1;        /* auxiliary control structure */
#ifndef HL_UNIX
#ifdef __cplusplus
   class clconn1 *ADSL_CONN1_G;             /* pointer on connection   */
#else
   void *     ADSL_CONN1_G;                 /* pointer on connection   */
#endif
#else
   struct dsd_conn1 *ADSL_CONN1_G;          /* pointer on connection   */
#endif
   struct dsd_server_conf_1 *ADSL_SERVER_G;  /* server configuration   */
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   void *     vprl_debug_1[ DEBUG_111213_01 ];  /* save chain in stack */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_1;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_2;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_3;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_4;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_5;  /* save structure for debugging */
   struct dsd_sdh_control_1 *adsl_sdhc1_save_6;  /* save structure for debugging */
   int        iml_save_line_d1;             /* save the line           */
#endif

#ifdef DEBUG_111116_01                      /* block is lost           */
   bol_lost_block_01 = FALSE;               /* block acquired          */
   bol_lost_block_02 = FALSE;               /* block inserted          */
   bol_lost_block_03 = FALSE;               /* block at beginning      */
   adsl_sdhc1_inserted_at_1 = NULL;         /* position inserted */
   memset( imrl_lines, 0, sizeof(imrl_lines) );
#endif
#ifndef HELP_DEBUG
#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#else
   ADSL_AUX_CF1 = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structur */
   ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   ims_debug_count_tose++;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d started ADSL_CONN1_G=0X%p adsp_pd_work=0X%p adsp_pd_work->boc_eof_server=%d.",
                   __LINE__, ADSL_CONN1_G, adsp_pd_work, adsp_pd_work->boc_eof_server );
#endif
#ifdef TRACEHL_SDH_COUNT_1
   iml_sdh_count_1_1 = m_sdh_count_1( ADSL_CONN1_G, -1, "m_pd_do_sdh_tose() started", __LINE__ );
   iml_sdh_count_1_2 = iml_sdh_count_1_1;   /* count entries           */
#endif
#ifndef HELP_DEBUG
#define ADSL_SERVER_G ADSL_CONN1_G->adsc_server_conf_1
#else
   ADSL_SERVER_G = ADSL_CONN1_G->adsc_server_conf_1;
#endif
#ifndef B140525
   adsl_server_conf_1_used = ADSL_SERVER_G;  /* configuration server   */
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   iml1 = 0;                                /* clear index             */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain       */
   while (adsl_sdhc1_w1) {                  /* loop over all buffers   */
     vprl_debug_1[ iml1 ] = adsl_sdhc1_w1;
     iml1++;
     if (iml1 >= DEBUG_111213_01) break;    /* save area is full       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   while (iml1 < DEBUG_111213_01) {         /* fill remaining save area */
     vprl_debug_1[ iml1 ] = NULL;           /* clear entry             */
     iml1++;
   }
   adsl_sdhc1_save_1 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_2 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_3 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_4 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_5 = NULL;                /* save structure for debugging */
   adsl_sdhc1_save_6 = NULL;                /* save structure for debugging */
   iml_save_line_d1 = 0;                    /* save the line           */
#endif
#ifdef DEBUG_060513                         /* do not process Server-Data-Hooks */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain       */
   while (adsl_sdhc1_w1) {                  /* loop over all buffers   */
     if (   (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_w1->inc_position == (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh - 1))) {
       adsl_sdhc1_w1->inc_position = -1;    /* send direct to server   */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   return;
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "sdh-l%05d m_pd_do_sdh_tose start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   iml_special_func = adsp_pd_work->imc_special_func;  /* call with special function */

   pprda_tose_12:                           /* start processing server-data-hook */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_last_1 = NULL;                /* clear last in chain found */
   adsl_sdhc1_ps_1 = NULL;                  /* no first buffer to process */
   adsl_sdhc1_pe_1 = NULL;                  /* currently processed end */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function == DEF_IFUNC_TOSERVER) {
       if (adsl_sdhc1_cur_1->inc_position < adsp_pd_work->imc_hookc) {
         break;                             /* is already too far      */
       }
       if (adsl_sdhc1_cur_1->inc_position == adsp_pd_work->imc_hookc) {  /* search for this one */
         if (adsl_sdhc1_ps_1 == NULL) {     /* no first buffer set     */
           adsl_sdhc1_ps_1 = adsl_sdhc1_cur_1;  /* this is first one   */
         }
         adsl_sdhc1_pe_1 = adsl_sdhc1_cur_1;  /* save last buffer to process */
       }
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain  */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_cur_1 = NULL;
#endif
#ifdef B140525
#ifdef B080609
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_SERVER_G + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
#ifndef HELP_DEBUG
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_SERVER_G + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#else
   struct dsd_ext_lib1 *ADSL_SDH_LIB1 = ((struct dsd_sdh_work_1 *) \
                        ((char *) (ADSL_SERVER_G + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pprda_tose_20 l%05d adsc_gate1->adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p ADSL_SERVER_G=%p",
                   ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1,
                   ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1, ADSL_SERVER_G );
#endif
#endif

   pprda_tose_20:                           /* next server-data-hook   */
#ifndef B140525
#ifndef HELP_DEBUG
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsl_server_conf_1_used + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#else
   struct dsd_ext_lib1 *ADSL_SDH_LIB1 = ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsl_server_conf_1_used + 1) \
                          + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pprda_tose_20 l%05d adsc_gate1->adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p adsl_server_conf_1_used=%p",
                   ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1,
                   ((char *) (adsl_server_conf_1_used + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1, adsl_server_conf_1_used );
#endif
#endif
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() pprda_tose_20 before call SDH", __LINE__ );
   m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d pprda_tose_20 before call SDH boc_sdh_reflect=%d.",
                   __LINE__, ADSL_SERVER_G->boc_sdh_reflect );
#endif
#ifndef B140621
   bol_after_sdh_reload = FALSE;            /* after SDH reload        */
#endif
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
#ifdef B140525
   if (ADSL_SERVER_G->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
     bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
   if (bol1) {                              /* do not call SDH         */
     if (adsl_sdhc1_ps_1) {                 /* first buffer set        */
       iml1 = 0;                            /* clear count             */
       adsl_gai1_w1 = adsl_sdhc1_ps_1->adsc_gather_i_1_i;  /* get start of chain */
       while (adsl_gai1_w1) {               /* loop over all gather input */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;  /* ignore data */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       if (iml1) {                          /* data ignored            */
         m_hlnew_printf( HLOG_WARN1, "HWSPS152W GATE=%(ux)s SNO=%08d INETA=%s SDH no %d already ended - TOSERVER data ignored %d.",
                         ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                         adsp_pd_work->imc_hookc, iml1 );
       }
#ifdef B110904
       adsl_sdhc1_ps_1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
       adsl_sdhc1_ps_1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
       adsl_sdhc1_w1 = adsl_sdhc1_ps_1->adsc_next;  /* get chain remaining blocks */
       while (adsl_sdhc1_w1) {                /* loop over all new buffers */
         if (adsl_sdhc1_w1->inc_function != adsl_sdhc1_ps_1->inc_function) break;
         if (adsl_sdhc1_w1->inc_position != adsl_sdhc1_ps_1->inc_position) break;
#ifdef B110904
         adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
         adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
     }
     adsp_pd_work->imc_hookc--;             /* decrement no se-da-hook */
     if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook */
         && (adsp_pd_work->imc_hookc < 0)) {  /* does reflection       */
       goto pprda_tose_80;                  /* all server-data-hook processed */
     }
#ifndef B110329
     adsl_sdhc1_ps_2 = adsl_sdhc1_ps_1;     /* get next element start  */
     adsl_sdhc1_pe_2 = adsl_sdhc1_pe_1;     /* get next element end    */
     adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get new last element   */
#endif
     goto pprda_tose_60;                    /* process next stage SDH  */
   }
   ADSL_AUX_CF1->adsc_sdhc1_chain = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef DEBUG_101216_01
   m_hlnew_printf( HLOG_TRACE1, "T$D1 m_pd_do_sdh_tose() l%05d ADSL_AUX_CF1->adsc_sdhc1_chain=%p.",
                   __LINE__, ADSL_AUX_CF1->adsc_sdhc1_chain );
#endif
#ifdef TRACEHL_SDH_01
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_next = NULL;  /* is only element */
   ADSL_AUX_CF1->adsc_sdhc1_chain->imc_usage_count = 0;  /* clear usage count */
#ifndef B140620
   ADSL_AUX_CF1->adsc_sdhc1_chain->dsc_cid = ADSL_AUX_CF1->dsc_cid;  /* component identifier    */
#endif
   dsl_sdh_l1.achc_work_area = (char *) (ADSL_AUX_CF1->adsc_sdhc1_chain + 1);
   dsl_sdh_l1.inc_len_work_area = LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1);
   dsl_sdh_l1.adsc_gather_i_1_in = NULL;    /* no buffer yet           */
   if (adsl_sdhc1_ps_1) {                   /* first buffer set        */
#ifdef DEBUG_100830_01
     {
       void * ah_addr;
       int    imh_function;
       ah_addr = NULL;
       imh_function = 0;
       if (adsl_sdhc1_ps_1) {
         ah_addr = adsl_sdhc1_ps_1;
         imh_function = adsl_sdhc1_ps_1->inc_function;
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d before SDH adsl_sdhc1_ps_1=%p inc_function=%d.",
                       __LINE__, ah_addr, imh_function );
     }
#endif
     dsl_sdh_l1.adsc_gather_i_1_in = adsl_sdhc1_ps_1->adsc_gather_i_1_i;  /* get start of chain */
     while (dsl_sdh_l1.adsc_gather_i_1_in) {  /* loop to find valid gather */
       if (dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_cur
             < dsl_sdh_l1.adsc_gather_i_1_in->achc_ginp_end) {
         break;
       }
       dsl_sdh_l1.adsc_gather_i_1_in = dsl_sdh_l1.adsc_gather_i_1_in->adsc_next;
     }
   }
#ifdef CHECK_SDH_01
   adsl_gai1_h1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* save input        */
#endif
   dsl_sdh_l1.inc_func = DEF_IFUNC_TOSERVER;
   achl_func = "DEF_IFUNC_TOSERVER";        /* function called         */
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
       && (adsp_pd_work->imc_hookc == 0)) {  /* does reflection        */
     dsl_sdh_l1.inc_func = DEF_IFUNC_REFLECT;
     achl_func = "DEF_IFUNC_REFLECT";       /* function called         */
   }
   if (iml_special_func) {                  /* call with special function */
     dsl_sdh_l1.inc_func = iml_special_func;
     if (dsl_sdh_l1.inc_func == DEF_IFUNC_CLIENT_DISCO) {  /* client is disconnected */
       achl_func = "DEF_IFUNC_CLIENT_DISCO";  /* function called       */
     } else if (dsl_sdh_l1.inc_func == DEF_IFUNC_RELOAD) {  /* SDH reload */
       achl_func = "DEF_IFUNC_RELOAD";      /* function called         */
     } else if (dsl_sdh_l1.inc_func == DEF_IFUNC_PREP_CLOSE) {  /* prepare close */
       achl_func = "DEF_IFUNC_PREP_CLOSE";  /* function called         */
     } else {
       achl_func = "*unknown*";             /* function called         */
     }
   }
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* auxiliary control structur */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.imc_signal = m_ret_signal( ADSL_AUX_CF1 );  /* search signal */
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
#ifdef B140525
#ifdef B131225
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (ADSL_SERVER_G + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
#ifndef B131225
   adsl_server_conf_1_w1 = ADSL_SERVER_G;   /* configuration server    */
   while (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
   }
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_w1 + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
#endif
#ifndef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_used + 1) + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1));
#endif
   dsl_sdh_l1.imc_signal = 0;               /* clear signal            */
   if (ADSL_CONN1_G->boc_signal_set) {      /* signal for component set */
     dsl_sdh_l1.imc_signal = m_ret_signal( ADSL_AUX_CF1 );  /* search signal */
   }
   dsl_sdh_l1.boc_eof_client = adsp_pd_work->boc_eof_client;  /* End-of-File Client  */
   dsl_sdh_l1.boc_eof_server = adsp_pd_work->boc_eof_server;  /* End-of-File Server  */
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
#ifdef B140525
// to-do 25.12.13 KB - use SDHs of adsc_seco1_previous
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (ADSL_SERVER_G + 1) \
                            + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifndef B140525
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (adsl_server_conf_1_used + 1) \
                            + adsp_pd_work->imc_hookc * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifdef OLD_1112
   dsl_sdh_l1.ac_hobwspat2_conf = ADSL_CONN1_G->adsc_gate1->vpc_hlwspat2_conf;  /* data from HOB-WSP-AT2 configuration */
#else
   dsl_sdh_l1.ac_hobwspat3_conf = ADSL_CONN1_G->adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
#endif
   /* flags of configuration                                           */
   if (ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {  /* user group defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_gate1->inc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
   }
#endif
#ifndef OLD_1112
   if (ADSL_CONN1_G->adsc_gate1->imc_no_radius) {  /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (ADSL_CONN1_G->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
#endif
   if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc) {  /* number of Kerberos 5 KDCs */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (ADSL_CONN1_G->adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   iml1 = 0;
   if (ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group) {  /* number of LDAP groups */
     iml1 = ADSL_CONN1_G->adsc_gate1->imc_no_ldap_group;  /* number of LDAP groups */
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server configured */
       && (ADSL_CONN1_G->adsc_server_conf_1->imc_no_ldap_group)) {  /* number of LDAP groups */
     iml1 = ADSL_CONN1_G->adsc_server_conf_1->imc_no_ldap_group;  /* number of LDAP groups */
   }
   if (iml1) {                              /* number of LDAP groups   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (iml1 > 1) {                        /* number of LDAP groups   */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
#ifndef HL_UNIX
// if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act()) {  /* still data to send to client */
   if (   (ADSL_CONN1_G->iec_st_cls == clconn1::ied_cls_closed)  /* client connection closed */
       || (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act())) {  /* still data to send to client */
     dsl_sdh_l1.boc_send_client_blocked = TRUE;  /* sending to the client is blocked */
   }
#else
// if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* still data to send to client */
   if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_closed)  /* client connection closed */
       || (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send)) {  /* still data to send to client */
     dsl_sdh_l1.boc_send_client_blocked = TRUE;  /* sending to the client is blocked */
   }
#endif
   dsl_sdh_l1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_INT) {  /* WSP Trace SDH intern */
     dsl_sdh_l1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
#ifdef CHECK_SDH_01
   adsl_gai1_check1 = NULL;                 /* clear for checks        */
   adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain */
   while (adsl_gai1_w1) {                   /* loop over all input gather */
     adsl_gai1_check1 = adsl_gai1_w1;       /* save for checks         */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#endif
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
#ifndef B140621

   pprda_tose_28:                           /* call SDH                */
#endif
#ifdef WSP_TRACE_TRY01
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSDHCAL2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = 0;                       /* clear counters          */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1++;                              /* count gather            */
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml3 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SNO=%08d call SDH %s hookc=%d no-gather-input=%d length-data-input=%d/0X%X imc_flags_1=0X%08X imc_signal=0X%08X eof-client=%d eof-server=%d",
                     ADSL_CONN1_G->dsc_co_sort.imc_sno, achl_func, adsp_pd_work->imc_hookc, iml1, iml2, iml2,
                     dsl_sdh_l1.imc_flags_1, dsl_sdh_l1.imc_signal, dsl_sdh_l1.boc_eof_client, dsl_sdh_l1.boc_eof_server );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml3;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml3 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (   (iml2)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH input gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
           iml_w2 += iml6;                  /* increment displacement  */
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           bol1 = FALSE;                    /* reset more flag         */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             adsl_wtr_w1->boc_more = bol1;  /* more data to follow     */
             bol1 = TRUE;                   /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#ifdef HELP_DEBUG
   ADSL_SERVER_G = ADSL_CONN1_G->adsc_server_conf_1;
#endif
#undef ADSL_SDH_LIB1
#ifdef CHECK_SDH_01
   if (dsl_sdh_l1.adsc_gather_i_1_in != adsl_gai1_h1) {
     m_hlnew_printf( HLOG_WARN1, "m_pd_do_sdh_tose() l%05d returned gater_i_1_in corrupted",
                     __LINE__ );
#ifndef HL_UNIX
     ExitProcess( 1 );
#else
     exit( 1 );
#endif
   }
#ifdef XYZ1
   adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_out;  /* get start of chain */
   while (adsl_gai1_w1) {                   /* loop over all input gather */
     if (adsl_gai1_check1 == adsl_gai1_w1) {  /* checks if last of input */
       m_hlnew_printf( HLOG_WARN1, "m_pd_do_sdh_tose() l%05d returned gater_i_1_out contains part of input",
                       __LINE__ );
#ifndef HL_UNIX
       ExitProcess( 1 );
#else
       exit( 1 );
#endif
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#endif
#endif
#ifdef DEBUG_100830_01
#ifdef XYZ1
   if (   (dsl_sdh_l1.boc_callagain)
       && (dsl_sdh_l1.adsc_gather_i_1_out)) {
       void * ah_addr;
       int    imh_function;
       int    imh_count;
       adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
       imh_count = 0;
       do {
         m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d callagain <adsc_sdhc1_chain[%d]>=%p.",
                         __LINE__, imh_count, adsl_sdhc1_w1 );
         imh_count++;
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
       } while (adsl_sdhc1_w1);
       ah_addr = NULL;
       imh_function = 0;
       if (adsl_sdhc1_ps_1) {
         ah_addr = adsl_sdhc1_ps_1;
         imh_function = adsl_sdhc1_ps_1->inc_function;
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d adsl_sdhc1_ps_1=%p inc_function=%d.",
                       __LINE__, ah_addr, imh_function );
   }
#endif
#endif
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
#ifdef B140525
   if (ADSL_SERVER_G->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     ADSL_CONN1_G->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSDHRET1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = iml2 = iml3 = iml4 = iml5 = 0;  /* clear counters          */
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gather_i_1_in;  /* get start of chain input */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get chain output data to client */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml2++;                              /* count gather            */
       iml3 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_server;  /* get chain output data to server */
     while (adsl_gai1_w1) {                 /* loop over all input gather */
       iml4++;                              /* count gather            */
       iml5 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml6 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "returned SDH %s hookc=%d inc_return=%d remaining-length-data-input=%d/0X%X out_to_client:g=%d l=%d/0X%X out_to_server:g=%d l=%d/0X%X.",
                     achl_func, adsp_pd_work->imc_hookc, dsl_sdh_l1.inc_return,
                     iml1, iml1, iml2, iml3, iml3, iml4, iml5, iml5 );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml6;        /* length of text / data   */
     adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
     adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml6 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     if (   (iml3)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_client;  /* get chain output data to client */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH returned out-to-client gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
#ifdef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
     if (   (iml5)
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       iml_w1 = iml_w2 = 0;                 /* clear counters          */
       adsl_gai1_w1 = dsl_sdh_l1.adsc_gai1_out_to_server;  /* get chain output data to server */
       do {                                 /* loop over all input gather */
         iml_w1++;                          /* count gather            */
         iml6 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
         if (iml6 > 0) {                    /* data in this gather     */
           if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
             adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
             memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
             adsl_wt1_w2 = adsl_wt1_w3;     /* this is current area    */
             achl_w1 = (char *) (adsl_wt1_w2 + 1);
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
           }
           memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
           iml7 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                           "+ SDH returned out-to-server gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                           iml_w1, adsl_gai1_w1, iml_w2, adsl_gai1_w1->achc_ginp_cur, iml6, iml6 );
           ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed      */
           ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
           ADSL_WTR_G2->imc_length = iml7;  /* length of text / data   */
           adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain   */
           adsl_wtr_w1 = ADSL_WTR_G2;       /* this is last in chain now */
#ifndef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
           achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
           achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
           do {                             /* loop for output of data */
             iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             if (iml7 <= 0) {               /* we need another area    */
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;   /* this is current area    */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               iml7 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
             }
             if (iml7 > iml6) iml7 = iml6;
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
               adsl_wtr_w1->boc_more = TRUE;  /* more data to follow   */
             }
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             memcpy( achl_w4, achl_w3, iml7 );
             achl_w3 += iml7;
             ADSL_WTR_G2->imc_length = iml7;  /* length of text / data */
             achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml7 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
             iml6 -= iml7;
           } while (iml6 > 0);
#ifdef B120114
           iml_w2 += iml6;                  /* increment displacement  */
#endif
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef DEBUG_120530_01                      /* warning SDHs too many work-areas */
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   iml1 = 0;                                /* count entries           */
   do {                                     /* loop over work areas    */
     iml1++;                                /* count entries           */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   } while (adsl_sdhc1_w1);
   if (iml1 >= DEBUG_120530_01) {           /* too many entries        */
     m_hlnew_printf( HLOG_TRACE1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SDH no %d TOSERVER warning - %d = too many work areas.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_pd_work->imc_hookc, iml1 );
   }
#endif
#ifdef TRACEHL_SDH_COUNT_1
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   iml_sdh_count_1_3 = 0;                   /* count entries           */
   while (adsl_sdhc1_w1) {                  /* loop over work areas    */
     iml_sdh_count_1_3++;                   /* count entries           */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   iml_sdh_count_1_1 += iml_sdh_count_1_3;  /* add to count over all   */
#endif
   if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
#ifdef B140525
     if (ADSL_SERVER_G->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140525
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_EXT) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SDUMP001", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "l%05d DEBUG_150218_01 dsrs_deb_ga1_2_1.",
                       __LINE__ );
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
       adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
       adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
       ADSL_WTR_G2->imc_length = DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2);  /* length of text / data */
       memcpy( ADSL_WTR_G2 + 1, dsrs_deb_ga1_2_1, DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2) );
       adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
       /* second buffer */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SDUMP002", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "l%05d DEBUG_150218_01 dsrs_deb_ga1_2_2.",
                       __LINE__ );
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
       adsl_wt1_w2 = adsl_wt1_w1;             /* last WSP Trace area     */
       adsl_wtr_w1 = ADSL_WTR_G1;             /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
       ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
       ADSL_WTR_G2->imc_length = DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2);  /* length of text / data */
       memcpy( ADSL_WTR_G2 + 1, dsrs_deb_ga1_2_2, DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2) );
       adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     }
#endif
#ifndef B140620
     m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of Server-Data-Hook */
#endif
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
   }
#ifndef WA_150216_01
#ifdef B120107
#ifdef B110310
   if (   (dsl_sdh_l1.inc_func == DEF_IFUNC_REFLECT)
#ifdef FORKEDIT
      )
#endif
#else
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
       && (adsp_pd_work->imc_hookc == 0)    /* does reflection         */
#endif
#ifdef FORKEDIT
      )
#endif
#else
   if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* no server connection */
       && (adsp_pd_work->imc_hookc == 0)    /* does reflection         */
#endif
       && (dsl_sdh_l1.adsc_gai1_out_to_server)) {  /* check start of chain output data to server */
// to-do 07.03.11 KB error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SDH imc_hookc=%d DEF_IFUNC_REFLECT returned data to send to server - illogic",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     adsp_pd_work->imc_hookc );
#ifdef B140525
     if (ADSL_SERVER_G->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140525
     if (adsl_server_conf_1_used->inc_no_sdh < 2) {
       ADSL_CONN1_G->dsc_sdh_s_1.boc_ended = TRUE;  /* processing of this SDH has ended */
     } else {
       ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#endif
#ifndef B140620
     m_sdh_cleanup( ADSL_AUX_CF1, &ADSL_AUX_CF1->dsc_cid );  /* cleanup resources of Server-Data-Hook */
#endif
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "error from Server-Data-Hook";
     }
     adsp_pd_work->boc_eof_server = TRUE;   /* End-of-File Server      */
     if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
       adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
     }
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
     dsl_sdh_l1.adsc_gai1_out_to_server = NULL;  /* clear start of chain output data to server */
   }
#endif
   adsl_sdhc1_out_to_server = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* output data to server */
   adsl_sdhc1_out_to_client = NULL;         /* output data to client   */
   if (dsl_sdh_l1.adsc_gai1_out_to_client) {  /* check start of chain output data to client */
     if (dsl_sdh_l1.adsc_gai1_out_to_server) {  /* check start of chain output data to server */
       adsl_sdhc1_out_to_client = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
       iml_sdh_count_1_1++;                 /* add to count over all   */
#endif
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) );
#else
       {
         int imh1 = adsl_sdhc1_out_to_client->imc_line_no[ 0 ];
         memset( adsl_sdhc1_out_to_client, 0, sizeof(struct dsd_sdh_control_1) );
         adsl_sdhc1_out_to_client->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_out_to_client->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
#ifdef DEBUG_111116_01                      /* block is lost           */
       bol_lost_block_01 = TRUE;            /* block acquired          */
       memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
       imrl_lines[ 0 ] = __LINE__;
#endif
#ifdef DEBUG_110315_01
       m_hlnew_printf( HLOG_TRACE1, "*S* adsl_sdhc1_out_to_client=%p / DEBUG_110315_01", adsl_sdhc1_out_to_client );
       bos_debug_110315_01 = TRUE;
       adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* get chain of new buffers */
       as_debug_110315_01 = adsl_sdhc1_w1;  /* check where this block is freed */
       while (adsl_sdhc1_w1) {              /* loop over all new buffers */
         m_hlnew_printf( HLOG_TRACE1, "*S* adsl_sdhc1_w1=%p / DEBUG_110315_01", adsl_sdhc1_w1 );
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
#endif
     } else {                               /* only data to server     */
       adsl_sdhc1_out_to_client = adsl_sdhc1_out_to_server;  /* output data to client */
       adsl_sdhc1_out_to_server = NULL;     /* output data to server   */
     }
     iml1 = adsp_pd_work->imc_hookc + 1;    /* get hook count plus one - next step or client direct */
     if (iml1 >= ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {
       iml1 = MAX_SERVER_DATA_HOOK;         /* maximum number server-data-hook configured */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* get chain to be sent to client */
     while (adsl_sdhc1_w1) {                /* loop over all new buffers */
       adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gai1_out_to_client;  /* set start of chain output data to client */
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_w1->inc_position = iml1;
#ifdef B110904
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
//   adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save start              */
     adsl_sdhc1_w2 = NULL;                  /* not yet buffers before  */
     adsl_sdhc1_ps_2 = NULL;                /* no buffer to start      */
     while (adsl_sdhc1_w1) {                /* loop over remaining buffers */
       if (   (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER)
           || (adsl_sdhc1_w1->inc_position > iml1)) {
         break;
       }
       if (   (adsl_sdhc1_ps_2 == NULL)     /* no buffer to start      */
           && (adsl_sdhc1_w1->inc_function == DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position == iml1)) {
         adsl_sdhc1_ps_2 = adsl_sdhc1_w1;   /* set buffer to start     */
       }
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save last buffer        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_out_to_client;  /* get chain to insert */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
     if (adsl_sdhc1_w2) {                   /* append to chain         */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_w2->adsc_next;  /* get old end of chain */
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_out_to_client;  /* set start of chain */
#ifdef DEBUG_111116_01                      /* block is lost           */
       bol_lost_block_02 = TRUE;            /* block inserted          */
       adsl_sdhc1_inserted_at_1 = adsl_sdhc1_w2;  /* position inserted */
       memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
       imrl_lines[ 0 ] = __LINE__;
#endif
// to-do 07.03.11 KB append gather
#ifdef TRY_110719_01                        /* SDH append gather       */
#endif
       if (adsl_sdhc1_ps_2) {               /* buffer to start found   */
         /* chain of gather input                                      */
         adsl_gai1_cur = adsl_sdhc1_ps_2->adsc_gather_i_1_i;
         adsl_gai1_last = NULL;             /* clear last element      */
         while (adsl_gai1_cur) {
           adsl_gai1_last = adsl_gai1_cur;
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         }
         if (adsl_gai1_last == NULL) {      /* insert at start of chain */
           adsl_sdhc1_ps_2->adsc_gather_i_1_i = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;
         } else {                           /* insert middle in chain  */
           adsl_gai1_last->adsc_next = adsl_sdhc1_out_to_client->adsc_gather_i_1_i;
         }
       }
     } else {                               /* set at start of chain   */
       adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* append old chain to new entries */
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_out_to_client;  /* set start of chain */
#ifdef DEBUG_111116_01                      /* block is lost           */
       bol_lost_block_02 = TRUE;            /* block inserted          */
       bol_lost_block_03 = TRUE;            /* block at beginning      */
       memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
       imrl_lines[ 0 ] = __LINE__;
#endif
#ifdef TRY_111124_01
#endif
     }
#ifndef B111213
     if (adsl_sdhc1_last_1 == NULL) {       /* no last element         */
       adsl_sdhc1_last_1 = adsl_sdhc1_w1;   /* get new last element    */
     }
#endif
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() after insert out_to_client", __LINE__ );
#endif
   }
   /* mark buffers                                                     */
   iel_sdhcs = ied_sdhcs_idle;              /* idle, has been processed */
   if (dsl_sdh_l1.boc_callagain) {          /* process input again     */
     iel_sdhcs = ied_sdhcs_activate;        /* activate SDH when possible */
#ifdef DEBUG_111116_01                      /* block is lost           */
     memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
     imrl_lines[ 0 ] = __LINE__;
#endif
   } else if (dsl_sdh_l1.boc_notify_send_client_possible) {  /* notify SDH when sending to the client is possible */
     iel_sdhcs = ied_sdhcs_wait_send_client;  /* wait to send to client is possible */
   }
   if (adsl_sdhc1_ps_1) {                   /* buffers have been given */
     adsl_sdhc1_cur_1 = adsl_sdhc1_ps_1;    /* get first buffer processed */
     while (TRUE) {                         /* loop over buffers processed */
#ifdef B110904
       adsl_sdhc1_cur_1->boc_ready_t_p = dsl_sdh_l1.boc_callagain;  /* ready to process */
#endif
       adsl_sdhc1_cur_1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
       if (adsl_sdhc1_cur_1 == adsl_sdhc1_pe_1) break;
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
     }
   } else if (iel_sdhcs != ied_sdhcs_idle) {  /* not idle, has not been processed */
     adsl_sdhc1_ps_1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
     iml_sdh_count_1_1++;                   /* add to count over all   */
#endif
#ifndef TRACEHL_SDH_01
     memset( adsl_sdhc1_ps_1, 0, sizeof(struct dsd_sdh_control_1) );
#else
     {
       int imh1 = adsl_sdhc1_ps_1->imc_line_no[ 0 ];
       memset( adsl_sdhc1_ps_1, 0, sizeof(struct dsd_sdh_control_1) );
       adsl_sdhc1_ps_1->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
       adsl_sdhc1_ps_1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
     }
#endif
     adsl_sdhc1_ps_1->inc_function = DEF_IFUNC_TOSERVER;
     adsl_sdhc1_ps_1->inc_position = adsp_pd_work->imc_hookc;
     adsl_sdhc1_ps_1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
#ifdef DEBUG_111116_01                      /* block is lost           */
     memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
     imrl_lines[ 0 ] = __LINE__;
#endif
     if (adsl_sdhc1_last_1 == NULL) {       /* not previous control area set */
       adsl_sdhc1_ps_1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
#ifndef TRY_111117_01
// to-do 17.11.11 KB the following instruction makes no sense since adsl_sdhc1_last_1 == NULL
// should it be adsl_sdhc1_ps_1 instead of adsl_sdhc1_last_1 ???
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_last_1;  /* set new chain */
#else
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_ps_1;  /* set new chain */
#endif
     } else {                               /* middle in chain         */
       adsl_sdhc1_ps_1->adsc_next = adsl_sdhc1_last_1->adsc_next;  /* get control areas behind */
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_ps_1;  /* insert this one */
     }
     adsl_sdhc1_pe_1 = adsl_sdhc1_ps_1;     /* currently processed end */
#ifdef TRY_111124_01
     adsl_sdhc1_last_1 = adsl_sdhc1_ps_1;   /* set new end blocks of this stage */
#endif
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "pprda_tose_20 l%05d boc_callrevdir=%d adsp_pd_work->imc_hookc=%d ADSL_SERVER_G=%p",
                   __LINE__, dsl_sdh_l1.boc_callrevdir, adsp_pd_work->imc_hookc, ADSL_SERVER_G );
#endif
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() check next SDH", __LINE__ );
#endif
#ifdef DEBUG_111116_01                      /* block is lost           */
   while (bol_lost_block_01) {              /* block acquired          */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
     iml1 = 0;                              /* clear number of blocks  */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       if (adsl_sdhc1_w1 == adsl_sdhc1_out_to_client) break;  /* block found */
       iml1++;                              /* increment number of blocks */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
#ifdef B111205
     if (adsl_sdhc1_w1) break;              /* block found in chain    */
#else
     if (adsl_sdhc1_w1) {                   /* block found in chain    */
       bol_lost_block_01 = FALSE;           /* block acquired          */
       bol_lost_block_02 = FALSE;           /* block inserted          */
       bol_lost_block_03 = FALSE;           /* block at beginning      */
       adsl_sdhc1_inserted_at_1 = NULL;     /* position inserted */
       memmove( (char *) imrl_lines + sizeof(imrl_lines[0]), imrl_lines, sizeof(imrl_lines) - sizeof(imrl_lines[0]) );
       imrl_lines[ 0 ] = __LINE__;
       break;
     }
#endif
     m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 bol_lost_block_01-set bol_lost_block_02=%d adsl_sdhc1_out_to_client=%p elements-in-chain=%d.",
                     __LINE__, bol_lost_block_02, adsl_sdhc1_out_to_client, iml1 );
     m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 bol_lost_block_03=%d adsl_sdhc1_inserted_at_1=%p.",
                     __LINE__, bol_lost_block_03, adsl_sdhc1_inserted_at_1 );
     if (adsl_sdhc1_inserted_at_1) {        /* with inserted at        */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
       iml1 = 0;                            /* clear number of blocks  */
       while (adsl_sdhc1_w1) {              /* loop over all blocks    */
         if (adsl_sdhc1_w1 == adsl_sdhc1_inserted_at_1) break;  /* block found */
         iml1++;                            /* increment number of blocks */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 after check inserted at - adsl_sdhc1_w1=%p elements-in-chain=%d.",
                       __LINE__, adsl_sdhc1_w1, iml1 );
     }
     iml1 = sizeof(imrl_lines) / sizeof(imrl_lines[0]);
     do {
       iml1--;
       if (imrl_lines[ iml1 ]) {
         m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 iml1=%d line=%d.",
                         __LINE__, iml1, imrl_lines[ iml1 ] );
       }
     } while (iml1 > 0);
     break;
   }
#endif
   if (dsl_sdh_l1.boc_callrevdir) {
     adsl_sdhc1_cur_2 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     adsl_sdhc1_last_2 = NULL;              /* clear last in chain found */
     while (adsl_sdhc1_cur_2) {             /* loop over all buffers   */
// to-do 22.07.11 KB - should second line be > only, not >= ???
       if (   (adsl_sdhc1_cur_2->inc_function != DEF_IFUNC_FROMSERVER)
           || (adsl_sdhc1_cur_2->inc_position >= adsp_pd_work->imc_hookc)) {
         break;
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save previous in chain */
       adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
     }
     if (   (adsl_sdhc1_cur_2)              /* still buffer            */
         && (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc)) {
       do {                                 /* loop over all for this sdh */
#ifdef B110904
         adsl_sdhc1_cur_2->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
         adsl_sdhc1_cur_2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
         adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
       } while (   (adsl_sdhc1_cur_2)       /* still buffer            */
                && (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_FROMSERVER)
                && (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc));
     } else {                               /* insert new buffer       */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_COUNT_1
       iml_sdh_count_1_1++;                 /* add to count over all   */
#endif
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#else
       {
         int imh1 = adsl_sdhc1_w1->imc_line_no[ 0 ];
         memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
         adsl_sdhc1_w1->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_w1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_w1->inc_position = adsp_pd_work->imc_hookc;
#ifdef B110904
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_cur_2;
       if (adsl_sdhc1_last_2 == NULL) {     /* insert at start of chain */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1;
#ifndef B100216
         adsl_sdhc1_ps_1 = adsl_sdhc1_w1;
         adsl_sdhc1_pe_1 = adsl_sdhc1_w1;
#endif
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_2->adsc_next = adsl_sdhc1_w1;
       }
#ifndef TRY_111124_01
#ifndef B100216
       adsl_sdhc1_last_1 = adsl_sdhc1_w1;
#endif
#else
       if (adsl_sdhc1_last_1 == NULL) {     /* no start of chain       */
         adsl_sdhc1_last_1 = adsl_sdhc1_w1;  /* set new start of chain */
       }
#endif
#ifdef TRACEHL_SDH_01
       m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() insert revdir", __LINE__ );
#endif
     }
   }
// if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
   if (   (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL)
       && (adsp_pd_work->dsc_aux_cf1.ac_sdhr_conn1 == NULL)) {  /* reload SDH from this connection */
     if (adsp_pd_work->boc_end_sdh == FALSE) {  /* first time end      */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         if (dsl_sdh_l1.inc_return == DEF_IRET_END) {
           ADSL_CONN1_G->achc_reason_end = "end from Server-Data-Hook";
         } else {
           ADSL_CONN1_G->achc_reason_end = "error from Server-Data-Hook";
         }
       }
       adsp_pd_work->boc_end_sdh = TRUE;    /* close in progress       */
     }
     adsp_pd_work->boc_eof_server = TRUE;   /* End-of-File Server      */
     if (dsl_sdh_l1.inc_return == DEF_IRET_END) {
       achl_w1 = "end";
     } else {
       achl_w1 = "abend";
     }
     sprintf( ADSL_CONN1_G->chrc_server_error,  /* display server error */
              "Server-Data-Hook stage %d returned %s %d",
              adsp_pd_work->imc_hookc, achl_w1, dsl_sdh_l1.inc_return );
     if (adsp_pd_work->inc_count_proc_end == 0) {  /* process end of connection */
       adsp_pd_work->inc_count_proc_end = -1;  /* start process end of connection */
#ifndef B140716
// 17.07.14 KB - ohne Wirkung
       adsp_pd_work->boc_abend = TRUE;      /* do not process more     */
#endif
     }
   }
   /* insert this buffer into the session-wide chain                   */
   adsp_pd_work->imc_hookc--;               /* decrement no se-da-hook */
#ifdef B110307
   adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
   do {
     adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gather_i_1_out;
     adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;  /* function of SDH */
     adsl_sdhc1_w1->inc_position = adsp_pd_work->imc_hookc;  /* position of SDH */
     adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* not ready to process    */
     if (dsl_sdh_l1.adsc_gather_i_1_out) {  /* output data set         */
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
     }
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save last element       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   } while (adsl_sdhc1_w1);
#else
   if (adsl_sdhc1_out_to_server == NULL) {  /* no output data to server */
#ifdef B111213_X
     adsl_sdhc1_ps_2 = adsl_sdhc1_ps_1;     /* get next element start  */
     adsl_sdhc1_pe_2 = adsl_sdhc1_pe_1;     /* get next element end    */
     adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get new last element   */
#endif
#ifndef B111213
// question 13.12.11 KB: do we need to set adsl_sdhc1_ps_2, adsl_sdhc1_pe_2 and adsl_sdhc1_last_2 ???
     adsl_sdhc1_cur_2 = adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element */
     adsl_sdhc1_ps_2 = adsl_sdhc1_pe_2 = NULL;  /* no buffers to pass  */
     while (adsl_sdhc1_cur_2) {             /* loop over buffers processed */
       if (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_TOSERVER) {
         if (adsl_sdhc1_cur_2->inc_position < adsp_pd_work->imc_hookc) {
           break;
         }
         if (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc) {
           if (adsl_sdhc1_ps_2 == NULL) {   /* no buffer to start      */
             adsl_sdhc1_ps_2 = adsl_sdhc1_cur_2;  /* this is first to process */
           }
           adsl_sdhc1_pe_2 = adsl_sdhc1_cur_2;  /* save last buffer to process */
         }
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save last buffer in chain */
       adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
     }
#endif
     goto pprda_tose_40;                    /* after output to server processed */
   }
#ifdef B110904
   bol1 = FALSE;                            /* reset flag ready to process */
   if (dsl_sdh_l1.adsc_gai1_out_to_server) bol1 = TRUE;  /* set flag ready to process */
#endif
   iel_sdhcs = ied_sdhcs_idle;              /* idle, has been processed */
   if (dsl_sdh_l1.adsc_gai1_out_to_server) {  /* output to server returned */
     iel_sdhcs = ied_sdhcs_activate;        /* activate SDH when possible */
   }
   adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* output data to server */
   do {
     adsl_sdhc1_w1->adsc_gather_i_1_i = dsl_sdh_l1.adsc_gai1_out_to_server;  /* get start of chain output data to server */
     adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;  /* function of SDH */
     adsl_sdhc1_w1->inc_position = adsp_pd_work->imc_hookc;  /* position of SDH */
#ifdef B110904
     adsl_sdhc1_w1->boc_ready_t_p = bol1;   /* set flag ready to process */
#endif
     adsl_sdhc1_w1->iec_sdhcs = iel_sdhcs;  /* state of control area server data hook */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save last element       */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   } while (adsl_sdhc1_w1);
#endif
   /* now insert this block into session-wide chain                    */
#ifdef B110307
   /* check if this was reflection entry                               */
   if (   (ADSL_SERVER_G->boc_sdh_reflect)  /* only Server-Data-Hook   */
       && (adsp_pd_work->imc_hookc < 0)) {  /* does reflection         */
     adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
     do {
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_FROMSERVER;  /* function of SDH */
#ifdef B090731
       adsl_sdhc1_w1->inc_position = ADSL_SERVER_G->inc_no_sdh;  /* position of SDH */
#endif
       adsl_sdhc1_w1->inc_position = MAX_SERVER_DATA_HOOK;  /* maximum number server-data-hook configured */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     } while (adsl_sdhc1_w1);
     adsl_sdhc1_cur_2 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_last_2 = NULL;              /* clear last in chain found */
     adsl_sdhc1_ps_2 = NULL;                /* no buffer to start      */
     while (adsl_sdhc1_cur_2) {             /* loop over all buffers   */
       if (adsl_sdhc1_cur_2->inc_function != DEF_IFUNC_FROMSERVER) {
         break;
       }
#ifdef B090731
       if (adsl_sdhc1_cur_2->inc_position == ADSL_SERVER_G->inc_no_sdh) {
#ifdef FORKEDIT
       }
#endif
#endif
       if (adsl_sdhc1_cur_2->inc_position >= MAX_SERVER_DATA_HOOK) {  /* maximum number server-data-hook configured */
         if (adsl_sdhc1_ps_2 == NULL) {     /* no buffer to start      */
           adsl_sdhc1_ps_2 = adsl_sdhc1_cur_2;  /* this is first to process */
#ifdef B110904
           adsl_sdhc1_cur_2->boc_ready_t_p = TRUE;  /* ready to process */
#endif
           adsl_sdhc1_cur_2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
           adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
           do {
#ifdef B110904
             adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* this is not first buffer */
#endif
             adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
             adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
           } while (adsl_sdhc1_w1);
         }
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save previous in chain */
       adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w2->adsc_next = adsl_sdhc1_cur_2;
     if (adsl_sdhc1_last_2 == NULL) {       /* was at anchor of chain  */
       ADSL_CONN1_G->adsc_sdhc1_chain = ADSL_AUX_CF1->adsc_sdhc1_chain;
     } else {                               /* insert middle in chain  */
       adsl_sdhc1_last_2->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain;
       if (adsl_sdhc1_ps_2) {               /* buffer to start found   */
         /* set chain of first gather                                  */
         adsl_gai1_cur = adsl_sdhc1_ps_2->adsc_gather_i_1_i;
         adsl_gai1_last = NULL;             /* clear last element      */
         while (adsl_gai1_cur) {
           adsl_gai1_last = adsl_gai1_cur;
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         }
         if (adsl_gai1_last == NULL) {      /* insert at start of chain */
#ifdef B100831
           ADSL_CONN1_G->adsc_sdhc1_chain->adsc_gather_i_1_i = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
#else
           adsl_sdhc1_ps_2->adsc_gather_i_1_i = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
#endif
         } else {                           /* insert middle in chain  */
           adsl_gai1_last->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
         }
       }
     }
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() insert reflection", __LINE__ );
#endif
     if (dsl_sdh_l1.boc_callagain) {        /* process last server-data-hook again */
       adsp_pd_work->imc_hookc++;           /* increment no se-da-hook */
       goto pprda_tose_20;                  /* same server-data-hook again */
     }
     goto pprda_tose_80;                    /* all server-data-hook processed */
   }
#endif
   /* this was normal entry for next stage                             */
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() before loop", __LINE__ );
#endif
#ifdef DEBUG_101216_01
   {
     struct dsd_sdh_control_1 *adsh_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get anchor */
     while (adsh_sdhc1_w1) {
       if (   (adsh_sdhc1_w1->adsc_gather_i_1_i == NULL)
           && (adsh_sdhc1_w1->inc_function == DEF_IFUNC_TOSERVER)  /* function of SDH */
           && (adsh_sdhc1_w1->inc_position == 0)) {
         m_hlnew_printf( HLOG_TRACE1, "T$D1 m_pd_do_sdh_tose() l%05d found to loose adsh_sdhc1_w1=%p.",
                         __LINE__, adsh_sdhc1_w1 );
       }
       adsh_sdhc1_w1 = adsh_sdhc1_w1->adsc_next;
     }
   }
#endif
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   if (adsp_pd_work->imc_hookc == 0) {      /* hook-count 1            */
     adsl_sdhc1_save_1 = adsl_sdhc1_pe_1;   /* save structure for debugging */
     adsl_sdhc1_save_6 = adsl_sdhc1_last_1;  /* save structure for debugging */
   }
#endif
#ifdef B111213
   adsl_sdhc1_cur_2 = adsl_sdhc1_pe_1;      /* get last buffer processed */
   adsl_sdhc1_last_2 = adsl_sdhc1_last_1;   /* get last element        */
   adsl_sdhc1_ps_2 = NULL;                  /* no buffer to start      */
   adsl_sdhc1_pe_2 = adsl_sdhc1_pe_1;       /* get last buffer processed */
#else
   adsl_sdhc1_cur_2 = adsl_sdhc1_last_2 = adsl_sdhc1_last_1;  /* get last element */
   adsl_sdhc1_ps_2 = adsl_sdhc1_pe_2 = NULL;  /* no buffers to pass    */
#endif
   while (adsl_sdhc1_cur_2) {               /* loop over buffers processed */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d adsl_sdhc1_cur_2=%p inc_function=%d",
                     __LINE__, adsl_sdhc1_cur_2, adsl_sdhc1_cur_2->inc_function );
#endif
     if (adsl_sdhc1_cur_2->inc_function == DEF_IFUNC_TOSERVER) {
       if (adsl_sdhc1_cur_2->inc_position < adsp_pd_work->imc_hookc) {
         break;
       }
       if (adsl_sdhc1_cur_2->inc_position == adsp_pd_work->imc_hookc) {
#ifdef DEBUG_101216_01
         m_hlnew_printf( HLOG_TRACE1, "T$D1 m_pd_do_sdh_tose() l%05d adsl_sdhc1_cur_2=%p.",
                         __LINE__, adsl_sdhc1_cur_2 );
#endif
#ifdef B110904
         adsl_sdhc1_cur_2->boc_ready_t_p = TRUE;  /* ready to process    */
#endif
         adsl_sdhc1_cur_2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
#ifdef B110307
         adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
#else
         adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* output data to server */
#endif
         do {
#ifdef B110904
           adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* this is not first buffer */
#endif
           adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
         } while (adsl_sdhc1_w1);
         if (adsl_sdhc1_ps_2 == NULL) {     /* no buffer to start      */
           adsl_sdhc1_ps_2 = adsl_sdhc1_cur_2;  /* this is first to process */
         }
         adsl_sdhc1_pe_2 = adsl_sdhc1_cur_2;  /* save last buffer to process */
#ifdef TRACEHL_SDH_01
         m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() append to same block", __LINE__ );
#endif
       }
       adsl_sdhc1_last_2 = adsl_sdhc1_cur_2;  /* save last buffer in chain */
     }
     adsl_sdhc1_cur_2 = adsl_sdhc1_cur_2->adsc_next;  /* get next in chain */
   }
// question 14.12.11 KB should other variable be appended to adsl_sdhc1_w2
   adsl_sdhc1_w2->adsc_next = adsl_sdhc1_cur_2;
#ifdef DEBUG_111213_01                      /* save chain in stack     */
   if (adsp_pd_work->imc_hookc == 0) {      /* hook-count 1            */
     iml_save_line_d1 = __LINE__;           /* save the line           */
     adsl_sdhc1_save_2 = adsl_sdhc1_cur_2;  /* save structure for debugging */
     adsl_sdhc1_save_3 = adsl_sdhc1_last_2;  /* save structure for debugging */
     adsl_sdhc1_save_4 = adsl_sdhc1_ps_2;   /* save structure for debugging */
     adsl_sdhc1_save_5 = adsl_sdhc1_pe_2;   /* save structure for debugging */
   }
#endif
   if (adsl_sdhc1_last_2 == NULL) {         /* insert at start of chain */
#ifdef B110307
     ADSL_CONN1_G->adsc_sdhc1_chain = ADSL_AUX_CF1->adsc_sdhc1_chain;
#else
     ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_out_to_server;  /* output data to server */
#endif
   } else {                                 /* insert middle in chain  */
#ifdef B110315
#ifndef B101216
     if (adsl_sdhc1_last_2->adsc_next) {    /* we need to save the remaining chain */
#ifdef B110307
       adsl_sdhc1_w1 = ADSL_AUX_CF1->adsc_sdhc1_chain;
#else
       adsl_sdhc1_w1 = adsl_sdhc1_out_to_server;  /* output data to server */
#endif
       while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_last_2->adsc_next;  /* append remaining entries */
     }
#endif
#endif
#ifdef B110307
     adsl_sdhc1_last_2->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain;
#else
     adsl_sdhc1_last_2->adsc_next = adsl_sdhc1_out_to_server;  /* output data to server */
#endif
   }
   if (adsl_sdhc1_ps_2 == NULL) {           /* no buffer to start      */
#ifdef B110307
     adsl_sdhc1_ps_2 = ADSL_AUX_CF1->adsc_sdhc1_chain;  /* this is first to process */
#else
     adsl_sdhc1_ps_2 = adsl_sdhc1_out_to_server;  /* output data to server */
#endif
#ifdef B111213
     adsl_sdhc1_pe_2 = adsl_sdhc1_w2;       /* this is last to process */
#endif
   } else {
     /* chain of gather input                                          */
     adsl_gai1_cur = adsl_sdhc1_ps_2->adsc_gather_i_1_i;
     adsl_gai1_last = NULL;                 /* clear last element      */
     while (adsl_gai1_cur) {
       adsl_gai1_last = adsl_gai1_cur;
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;
     }
#ifdef B110307
     if (adsl_gai1_last == NULL) {          /* insert at start of chain */
       adsl_sdhc1_ps_2->adsc_gather_i_1_i = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
     } else {                               /* insert middle in chain  */
       adsl_gai1_last->adsc_next = ADSL_AUX_CF1->adsc_sdhc1_chain->adsc_gather_i_1_i;
     }
#else
     if (adsl_gai1_last == NULL) {          /* insert at start of chain */
       adsl_sdhc1_ps_2->adsc_gather_i_1_i = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
     } else {                               /* insert middle in chain  */
       adsl_gai1_last->adsc_next = adsl_sdhc1_out_to_server->adsc_gather_i_1_i;
     }
#endif
   }
#ifndef B111213
   adsl_sdhc1_last_2 = adsl_sdhc1_pe_2 = adsl_sdhc1_w2;  /* this is last to process */
#endif
#ifdef TRACEHL_SDH_COUNT_1
   m_sdh_count_1( ADSL_CONN1_G, iml_sdh_count_1_1, "m_pd_do_sdh_tose() before pprda_tose_40", __LINE__ );
#endif
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_sdh_tose() insert out_to_server", __LINE__ );
#endif

   pprda_tose_40:                           /* after output to server processed */
#ifdef WAS_BEFORE_1501
#ifndef B140621
   if (ADSL_AUX_CF1->adsc_sdh_reload_saved) {  /* SDH, saved for reload */
     adsp_pd_work->imc_hookc++;             /* increment no se-da-hook */
     m_sdh_reload_do( ADSL_AUX_CF1, adsp_pd_work->imc_hookc );
     dsl_sdh_l1.inc_func = DEF_IFUNC_RELOAD;  /* SDH reload            */
     achl_func = "DEF_IFUNC_RELOAD";        /* function called         */
     dsl_sdh_l1.adsc_gather_i_1_in = NULL;  /* set start of chain input */
     dsl_sdh_l1.adsc_gai1_out_to_client = NULL;  /* set chain output data to client */
     dsl_sdh_l1.adsc_gai1_out_to_server = NULL;  /* set chain output data to server */
     dsl_sdh_l1.imc_signal = 0;             /* clear signal            */
     bol_after_sdh_reload = TRUE;           /* after SDH reload        */
     goto pprda_tose_28;                    /* call SDH                */
   }
   if (bol_after_sdh_reload) {              /* after SDH reload        */
     adsp_pd_work->imc_hookc++;             /* increment no se-da-hook */
     goto pprda_tose_20;                    /* same server-data-hook again */
   }
#endif
#endif
#ifdef WAS_BEFORE_1501
   if (dsl_sdh_l1.boc_callagain) {          /* process last server-data-hook again */
#ifdef DEBUG_100830_01
     {
       void * ah_addr;
       int    imh_function;
       ah_addr = NULL;
       imh_function = 0;
       if (adsl_sdhc1_cur_1) {
         ah_addr = adsl_sdhc1_ps_1;
         imh_function = adsl_sdhc1_ps_1->inc_function;
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d adsl_sdhc1_ps_1=%p inc_function=%d.",
                       __LINE__, ah_addr, imh_function );
       ah_addr = NULL;
       imh_function = 0;
       if (adsl_sdhc1_ps_2) {
         ah_addr = adsl_sdhc1_ps_2;
         imh_function = adsl_sdhc1_ps_2->inc_function;
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d adsl_sdhc1_ps_2=%p inc_function=%d.",
                       __LINE__, ah_addr, imh_function );
     }
#endif
#ifdef WAS_BEFORE_1501
     adsp_pd_work->imc_hookc++;             /* increment no se-da-hook */
     goto pprda_tose_20;                    /* same server-data-hook again */
#endif
     /* first send output data to server,
        then process this SDH again                                    */
   }
#endif

   if (adsp_pd_work->dsc_aux_cf1.ac_sdhr_conn1 == NULL) {  /* reload SDH from this connection */
     goto pprda_tose_60;                    /* process next stage SDH  */
   }
#ifdef XYZ1
   if (iml_special_func != adsp_pd_work->imc_special_func) {  /* check call with special function */
     goto pprda_tose_60;                    /* process next stage SDH  */
   }
#endif
   /* process reload SDH now                                           */
   adsp_pd_work->imc_hookc++;               /* increment no se-da-hook */

#ifndef HL_UNIX
#define ADSL_CONN1_RECO ((class clconn1 *) adsp_pd_work->dsc_aux_cf1.ac_sdhr_conn1)
#else
#define ADSL_CONN1_RECO ((struct dsd_conn1 *) adsp_pd_work->dsc_aux_cf1.ac_sdhr_conn1)
#endif

   pprda_tose_44:                           /* check connection not active */
   if (ADSL_CONN1_RECO->boc_st_act) {       /* connection processing work-thread */
     goto pprda_tose_56;                    /* wait for connection no more active */
   }
#ifndef HL_UNIX
   EnterCriticalSection( &ADSL_CONN1_RECO->d_act_critsect );  /* critical section act */
#else
   ADSL_CONN1_RECO->dsc_critsect.m_enter();  /* critical section       */
#endif
   if (ADSL_CONN1_RECO->boc_st_act) {       /* connection processed on work-thread */
#ifndef HL_UNIX
     LeaveCriticalSection( &ADSL_CONN1_RECO->d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_RECO->dsc_critsect.m_leave();  /* critical section     */
#endif
     goto pprda_tose_56;                    /* wait for connection no more active */
   }
   m_sdh_reload_old_resources( ADSL_CONN1_RECO,
                               &adsp_pd_work->dsc_aux_cf1.dsc_sdhr_cid,
                               &adsp_pd_work->dsc_sdh_reload_saved );
   if (ADSL_CONN1_RECO->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_RECO->achc_reason_end = "reconnect new session got resources";
   }
#ifndef HL_UNIX
   ADSL_CONN1_RECO->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
   LeaveCriticalSection( &ADSL_CONN1_RECO->d_act_critsect );  /* critical section act */
   m_act_conn( ADSL_CONN1_RECO );           /* session needs to process end */
#else
   ADSL_CONN1_RECO->iec_st_ses = ied_ses_abend;  /* abnormal end of session */
   ADSL_CONN1_RECO->dsc_critsect.m_leave();  /* critical section       */
   m_act_thread_1( ADSL_CONN1_RECO );       /* session needs to process end */
#endif

   /* load old resources to new session                                */
   m_sdh_reload_new_resources( ADSL_AUX_CF1,
                               &adsp_pd_work->dsc_sdh_reload_saved );
   adsp_pd_work->dsc_aux_cf1.ac_sdhr_conn1 = NULL;  /* reload SDH from this connection */
   iml_special_func                         /* call with special function */
     = DEF_IFUNC_RELOAD;                    /* SDH reload              */
   ADSL_CONN1_G->boc_survive = TRUE;        /* survive E-O-F client    */
   goto pprda_tose_12;                      /* start processing server-data-hook */

   pprda_tose_56:                           /* wait for connection no more active */
   m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
#ifndef HL_UNIX
   Sleep( 200 );
#else
   sleep( 1 );
#endif
   m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
   goto pprda_tose_44;                      /* check connection not active */

#undef ADSL_CONN1_RECO

   pprda_tose_60:                           /* process next stage SDH  */
   iml_special_func = adsp_pd_work->imc_special_func;  /* reset call with special function */
   /* check if more Server-Data-Hooks to process                       */
   if (adsp_pd_work->imc_hookc >= 0) {
     adsl_sdhc1_ps_1 = adsl_sdhc1_ps_2;     /* get next element start  */
     adsl_sdhc1_pe_1 = adsl_sdhc1_pe_2;     /* get next element end    */
     adsl_sdhc1_last_1 = adsl_sdhc1_last_2;  /* get new last element   */
     goto pprda_tose_20;                    /* next server-data-hook   */
   }

#undef ADSL_SDH_LIB1

   pprda_tose_80:                           /* all Server-Data-Hook processed */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "sdh-l%05d m_pd_do_sdh_tose end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef DEBUG_111116_01                      /* block is lost           */
   while (bol_lost_block_01) {              /* block acquired          */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
     iml1 = 0;                              /* clear number of blocks  */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       if (adsl_sdhc1_w1 == adsl_sdhc1_out_to_client) break;  /* block found */
       iml1++;                              /* increment number of blocks */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_sdhc1_w1) break;              /* block found in chain    */
     m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 bol_lost_block_01-set bol_lost_block_02=%d adsl_sdhc1_out_to_client=%p elements-in-chain=%d.",
                     __LINE__, bol_lost_block_02, adsl_sdhc1_out_to_client, iml1 );
     m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 bol_lost_block_03=%d adsl_sdhc1_inserted_at_1=%p.",
                     __LINE__, bol_lost_block_03, adsl_sdhc1_inserted_at_1 );
     if (adsl_sdhc1_inserted_at_1) {        /* with inserted at        */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get start of chain */
       iml1 = 0;                            /* clear number of blocks  */
       while (adsl_sdhc1_w1) {              /* loop over all blocks    */
         if (adsl_sdhc1_w1 == adsl_sdhc1_inserted_at_1) break;  /* block found */
         iml1++;                            /* increment number of blocks */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 after check inserted at - adsl_sdhc1_w1=%p elements-in-chain=%d.",
                       __LINE__, adsl_sdhc1_w1, iml1 );
     }
     iml1 = sizeof(imrl_lines) / sizeof(imrl_lines[0]);
     do {
       iml1--;
       if (imrl_lines[ iml1 ]) {
         m_hlnew_printf( HLOG_TRACE1, "m_pd_do_sdh_tose() l%05d DEBUG_111116_01 iml1=%d line=%d.",
                         __LINE__, iml1, imrl_lines[ iml1 ] );
       }
     } while (iml1 > 0);
     break;
   }
#endif
#ifdef TRACEHL_SDH_COUNT_1
   m_sdh_count_1( ADSL_CONN1_G, iml_sdh_count_1_1, "m_pd_do_sdh_tose() return", __LINE__ );
#endif
   return;
#ifndef HELP_DEBUG
#undef ADSL_SERVER_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_pd_do_sdh_tose()                                            */

#ifdef CSSSL_060620
/**
  Subroutine to process Client-Side SSL

  The routine m_pd_do_cs_ssl() reads and returns data
  only on the session-wide chain ADSL_CONN1_G->adsc_sdhc1_chain

*/
static void m_pd_do_cs_ssl( struct dsd_pd_work *adsp_pd_work ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7, iml8, iml9;  /* working variables */
   char       *achl1;                       /* working variable        */
   BOOL       bol1;                         /* working varibale        */
   BOOL       bol_cont;                     /* continue calling Client-Side SSL */
#ifndef B140610
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
#ifdef XYZ1
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_2;  /* current location 2  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_2;  /* last location 2    */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_1;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_1;  /* currently processed end */
   struct dsd_sdh_control_1 *adsl_sdhc1_ps_2;  /* currently processed start */
   struct dsd_sdh_control_1 *adsl_sdhc1_pe_2;  /* currently processed end */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_work_frse;  /* current work area */
   struct dsd_sdh_control_1 *adsl_sdhc1_work_tose;  /* current work area */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gather_i_1_i;  /* gather input data     */
#endif
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_check1;  /* for checks             */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_do_cs_ssl() l%05d started ADSL_CONN1_G=0X%p adsp_pd_work=0X%p adsp_pd_work->boc_eof_server=%d.",
                   __LINE__, ADSL_CONN1_G, adsp_pd_work, adsp_pd_work->boc_eof_server );
#endif
//#define ADSL_SERVER_G ADSL_CONN1_G->adsc_server_conf_1
#define DSL_HLCL01S ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s
#ifdef XYZ1
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_last_1 = NULL;                /* clear last in chain found */
   adsl_sdhc1_ps_1 = NULL;                  /* no first buffer to process */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function == DEF_IFUNC_TOSERVER) {
       if (adsl_sdhc1_cur_1->inc_position < adsp_pd_work->imc_hookc) {
         break;                             /* is already too far      */
       }
     }
     if (adsl_sdhc1_cur_1->inc_position == adsp_pd_work->imc_hookc) {  /* search for this one */
       if (adsl_sdhc1_ps_1 == NULL) {       /* no first buffer set     */
         adsl_sdhc1_ps_1 = adsl_sdhc1_cur_1;  /* this is first one     */
       }
       adsl_sdhc1_pe_1 = adsl_sdhc1_cur_1;  /* save last buffer to process */
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain  */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#endif
#ifdef DEBUG_100809
   p_cs_ssl_20:                             /* call subroutine now     */
#endif
   /* get input data                                                   */
   DSL_HLCL01S.adsc_gai1_in_cl = NULL;      /* clear input from client */
   DSL_HLCL01S.adsc_gai1_in_se = NULL;      /* clear input from server */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_position == -1) {  /* input to Client-Side SSL */
       if (adsl_sdhc1_cur_1->inc_function == DEF_IFUNC_FROMSERVER) {
         if (DSL_HLCL01S.adsc_gai1_in_se == NULL) {
           DSL_HLCL01S.adsc_gai1_in_se = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain gather structures */
         }
       } else {
#ifndef DEBUG_100809
         if (DSL_HLCL01S.adsc_gai1_in_cl == NULL) {
           DSL_HLCL01S.adsc_gai1_in_cl = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain gather structures */
         }
#endif
#ifdef DEBUG_100809
         if (ADSL_CONN1_G->iec_st_ses != clconn1::ied_ses_wait_csssl) {  /* no more wait for client-side SSL */
           if (DSL_HLCL01S.adsc_gai1_in_cl == NULL) {
             DSL_HLCL01S.adsc_gai1_in_cl = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain gather structures */
           }
           if (adsl_sdhc1_cur_1 == as_debug_100809_01) {
             m_hlnew_printf( HLOG_TRACE1, "l%05d input to client-side SSL == %p / as_debug_100809_01",
                             __LINE__, adsl_sdhc1_cur_1 );
           }
         }
#endif
       }
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_cs_ssl;  /* SSL subroutine active */
   ADSL_AUX_CF1->ac_sdh = NULL;             /* current Server-Data-Hook */
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_cs_ssl;  /* SSL subroutine active */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr = NULL;
   DSL_HLCL01S.boc_eof_client = adsp_pd_work->boc_eof_client;  /* End-of-File Client */
   DSL_HLCL01S.boc_eof_server = adsp_pd_work->boc_eof_server;  /* End-of-File Server */
   if (ADSL_CONN1_G->adsc_csssl_oper_1->boc_error) {  /* error occured */
     DSL_HLCL01S.boc_eof_server = TRUE;     /* always End-of-File Server */
   }
   DSL_HLCL01S.vpc_userfld = ADSL_AUX_CF1;  /* auxiliary control structur */

#ifndef DEBUG_100809
   p_cs_ssl_20:                             /* call subroutine now     */
#endif
   bol_cont = FALSE;                        /* clear continue calling Client-Side SSL */
#ifndef B100802
   if (DSL_HLCL01S.inc_func == DEF_IFUNC_START) bol_cont = TRUE;  /* at start call twice */
#endif
   adsl_sdhc1_work_frse = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_work_frse->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ACHL_OUT_CL_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1)) + 1))
   DSL_HLCL01S.achc_out_cl_cur = ACHL_OUT_CL_START;
   DSL_HLCL01S.achc_out_cl_end
     = ACHL_OUT_CL_START
         + LEN_TCP_RECV
         - sizeof(struct dsd_sdh_control_1)
         - sizeof(struct dsd_gather_i_1);
#undef ACHL_OUT_CL_START
   adsl_sdhc1_work_tose = (struct dsd_sdh_control_1 *) m_proc_alloc();
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_work_tose->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#define ACHL_OUT_SE_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1)) + 1))
   DSL_HLCL01S.achc_out_se_cur = ACHL_OUT_SE_START;
   DSL_HLCL01S.achc_out_se_end
     = ACHL_OUT_SE_START
         + LEN_TCP_RECV
         - sizeof(struct dsd_sdh_control_1)
         - sizeof(struct dsd_gather_i_1);
#undef ACHL_OUT_SE_START
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_pd_do_cs_ssl() before m_hlcl01() inc_func=%d",
                   __LINE__, DSL_HLCL01S.inc_func );
#endif
#ifdef DEBUG_100809
   bol1 = ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc;  /* ssl handshake complete */
#endif
   adsl_wt1_w1 = NULL;                      /* no WSP trace record     */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_EXT) {  /* generate WSP trace record */
     /* count input from client                                        */
     iml1 = iml2 = iml3 = iml4 = 0;
     adsl_gai1_w1 = DSL_HLCL01S.adsc_gai1_in_cl;  /* input from client */
     while (adsl_gai1_w1) {                 /* loop over input         */
       iml1++;
       iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     adsl_gai1_w1 = DSL_HLCL01S.adsc_gai1_in_se;  /* input from server */
     while (adsl_gai1_w1) {                 /* loop over input         */
       iml3++;
       iml4 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SCLSSL01", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
   }


   m_hlcl01( &DSL_HLCL01S );

   if (adsl_wt1_w1) {                       /* WSP trace record        */
     /* count input data again                                         */
     /* count input from client                                        */
     iml5 = iml6 = 0;
     adsl_gai1_w1 = DSL_HLCL01S.adsc_gai1_in_cl;  /* input from client */
     while (adsl_gai1_w1) {                 /* loop over input         */
       iml5 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     adsl_gai1_w1 = DSL_HLCL01S.adsc_gai1_in_se;  /* input from server */
     while (adsl_gai1_w1) {                 /* loop over input         */
       iml6 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
#define ACHL_OUT_CL_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1)) + 1))
     iml7 = DSL_HLCL01S.achc_out_cl_cur - ACHL_OUT_CL_START;
#define ACHL_OUT_SE_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1)) + 1))
     iml8 = DSL_HLCL01S.achc_out_se_cur - ACHL_OUT_SE_START;
#ifdef B110504
     adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
     adsl_wt1_w1->imc_len_text              /* length of text this record */
       = sprintf( (char *) (adsl_wt1_w1 + 1),
                  "SNO=%08d CS-SSL in-from-client:g=%d l=%d/0X%X rem=%d/0X%X in-from-server:g=%d l=%d/0X%X rem=%d/0X%X out-to-client=%d/0X%X out-to-server=%d/0X%X eof-client=%d eof-server=%d returned=%d.",
                  ADSL_CONN1_G->dsc_co_sort.imc_sno, iml1, iml2, iml2, iml5, iml5, iml3, iml4, iml4, iml6, iml6,
                  iml7, iml7, iml8, iml8,
                  DSL_HLCL01S.boc_eof_client, DSL_HLCL01S.boc_eof_server,
                  DSL_HLCL01S.inc_return );
#endif
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml9 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "CS-SSL in-from-client:g=%d l=%d/0X%X rem=%d/0X%X in-from-server:g=%d l=%d/0X%X rem=%d/0X%X out-to-client=%d/0X%X out-to-server=%d/0X%X eof-client=%d eof-server=%d returned=%d.",
                     iml1, iml2, iml2, iml5, iml5, iml3, iml4, iml4, iml6, iml6,
                     iml7, iml7, iml8, iml8,
                     DSL_HLCL01S.boc_eof_client, DSL_HLCL01S.boc_eof_server,
                     DSL_HLCL01S.inc_return );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml9;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#ifndef B140611
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml9 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#endif
     if (   (iml7)                          /* data decrypted          */
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
#ifdef B140611
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml9 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#endif
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       achl_w3 = ACHL_OUT_CL_START;         /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current area    */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml2 = achl_w2 - achl_w4;
         if (iml2 > iml7) iml2 = iml7;
         memcpy( achl_w4, achl_w3, iml2 );
         achl_w4 += iml2;
         achl_w3 += iml2;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml7 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml7 > 0);
     }
#undef ADSL_WTR_G2
#ifndef B140611
     if (   (iml8)                          /* data encrypted          */
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       achl_w3 = ACHL_OUT_SE_START;         /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current area    */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml2 = achl_w2 - achl_w4;
         if (iml2 > iml8) iml2 = iml8;
         memcpy( achl_w4, achl_w3, iml2 );
         achl_w4 += iml2;
         achl_w3 += iml2;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml8 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml8 > 0);
     }
#undef ADSL_WTR_G2
#endif
#undef ADSL_WTR_G1
#undef ACHL_OUT_CL_START
#undef ACHL_OUT_SE_START
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_pd_do_cs_ssl() - m_hlcl01( %p ) returned inc_return=%d",
                   __LINE__,
                   &DSL_HLCL01S,
                   DSL_HLCL01S.inc_return );
#endif
#ifdef DEBUG_100809
   if (bol1 != ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc) {  /* ssl handshake complete */
     bol_cont = TRUE;                       /* continue calling Client-Side SSL */
   }
#endif
#define ACHL_OUT_SE_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1)) + 1))
#ifndef B140611
   /* temporary - may be SSL error */
   if (   (adsp_pd_work->boc_eof_server)    /* End-of-File Server      */
       && (DSL_HLCL01S.achc_out_se_cur != ACHL_OUT_SE_START)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL returned data to server but boc_eof_server set",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     DSL_HLCL01S.achc_out_se_cur = ACHL_OUT_SE_START;
   }
#endif
   if (DSL_HLCL01S.achc_out_se_cur == ACHL_OUT_SE_START) {
     m_proc_free( adsl_sdhc1_work_tose );   /* free buffer again       */
   } else {
     memset( adsl_sdhc1_work_tose, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_work_tose->adsc_gather_i_1_i
       = (struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1))->achc_ginp_cur
       = ACHL_OUT_SE_START;
#undef ACHL_OUT_SE_START
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_work_tose + 1))->achc_ginp_end
       = DSL_HLCL01S.achc_out_se_cur;
     /* data to server with SDH position -2                            */
     adsl_sdhc1_work_tose->inc_position = -2;   /* send to server      */
     adsl_sdhc1_work_tose->inc_function = DEF_IFUNC_TOSERVER;
#ifdef B110904
     adsl_sdhc1_work_tose->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
     adsl_sdhc1_work_tose->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_last_1 = NULL;              /* clear last in chain found */
     adsl_sdhc1_w1 = NULL;                  /* clear first entry       */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
#ifdef B110315
       if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) {
         if (   (adsl_sdhc1_cur_1->inc_position == adsl_sdhc1_work_tose->inc_position)
             && (adsl_sdhc1_w1 == NULL)) {  /* not yet first entry     */
           adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save this as first entry */
         }
       }
#else
       if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_cur_1->inc_position == -2)
           && (adsl_sdhc1_w1 == NULL)) {    /* not yet first entry     */
         adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save this as first entry */
       }
#endif
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     if (adsl_sdhc1_last_1 == NULL) {       /* new one is first in chain */
#ifdef B110315
       adsl_sdhc1_work_tose->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;
#endif
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_work_tose;
     } else {                               /* middle in chain         */
#ifdef B110315
       adsl_sdhc1_work_tose->adsc_next = adsl_sdhc1_cur_1;
#endif
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_work_tose;
#ifdef B130711
       /* set chain field of first struct dsd_sdh_control_1            */
       if (adsl_sdhc1_w1) {                 /* append to first struct dsd_sdh_control_1 */
         adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain gather structures */
         adsl_gai1_last = NULL;             /* no preceeder            */
         while (adsl_gai1_cur) {            /* loop over gather structures */
           adsl_gai1_last = adsl_gai1_cur;  /* save this as last one   */
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_last == NULL) {      /* no preceeder            */
           adsl_sdhc1_cur_1->adsc_gather_i_1_i = adsl_sdhc1_work_tose->adsc_gather_i_1_i;
         } else {                           /* middle of chain         */
           adsl_gai1_last->adsc_next = adsl_sdhc1_work_tose->adsc_gather_i_1_i;
         }
       }
#endif
#ifndef B130711
       /* set chain field of first struct dsd_sdh_control_1            */
       while (adsl_sdhc1_w1) {              /* append to first struct dsd_sdh_control_1 */
         while (TRUE) {                     /* loop to find first gather in old chain */
           adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain gather structures */
           if (adsl_gai1_cur) break;
           if (adsl_sdhc1_w1 == adsl_sdhc1_last_1) break;
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_cur == NULL) break;  /* no data before          */
         while (adsl_gai1_cur->adsc_next) adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         adsl_gai1_cur->adsc_next = adsl_sdhc1_work_tose->adsc_gather_i_1_i;
         break;
       }
#endif
     }
     bol_cont = TRUE;                       /* continue calling Client-Side SSL */
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_cs_ssl() insert to server", __LINE__ );
#endif
   }
#define ACHL_OUT_CL_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1)) + 1))
#ifndef B140611
   /* temporary - may be SSL error */
   if (   (adsp_pd_work->boc_eof_client)    /* End-of-File Client      */
       && (DSL_HLCL01S.achc_out_cl_cur != ACHL_OUT_CL_START)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL returned data to client but boc_eof_client set",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     DSL_HLCL01S.achc_out_cl_cur = ACHL_OUT_CL_START;
   }
#endif
   if (DSL_HLCL01S.achc_out_cl_cur == ACHL_OUT_CL_START) {
     m_proc_free( adsl_sdhc1_work_frse );   /* free buffer again       */
   } else {
     memset( adsl_sdhc1_work_frse, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
     adsl_sdhc1_work_frse->adsc_gather_i_1_i
       = (struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1))->achc_ginp_cur
       = ACHL_OUT_CL_START;
#undef ACHL_OUT_CL_START
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_work_frse + 1))->achc_ginp_end
       = DSL_HLCL01S.achc_out_cl_cur;
     /* data to client with SDH position 0                             */
     adsl_sdhc1_work_frse->inc_function = DEF_IFUNC_FROMSERVER;
#ifdef B110316
#ifndef B100802
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0) {
       adsl_sdhc1_work_frse->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
     }
#endif
#else
     iml1 = 0;                              /* set hook count of packet we search for */
#ifdef B140610
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0) {
       adsl_sdhc1_work_frse->inc_position = iml1 = MAX_SERVER_DATA_HOOK;  /* position send to client */
     }
#endif
#ifndef B140610
     adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     if (adsl_server_conf_1_used->inc_no_sdh == 0) {
       adsl_sdhc1_work_frse->inc_position = iml1 = MAX_SERVER_DATA_HOOK;  /* position send to client */
     }
#endif
#endif
#ifdef B110904
     adsl_sdhc1_work_frse->boc_ready_t_p = TRUE;  /* ready to process  */
#endif
     adsl_sdhc1_work_frse->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_last_1 = NULL;              /* clear last in chain found */
     adsl_sdhc1_w1 = NULL;                  /* clear first entry       */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
       if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) break;
#ifdef B110316
       if (adsl_sdhc1_cur_1->inc_position > 0) break;
       if (   (adsl_sdhc1_cur_1->inc_position == 0)
           && (adsl_sdhc1_w1 == NULL)) {    /* not yet first entry     */
         adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save this as first entry */
       }
#else
       if (adsl_sdhc1_cur_1->inc_position > iml1) break;
       if (   (adsl_sdhc1_cur_1->inc_position == iml1)  /* we append to these packets */
           && (adsl_sdhc1_w1 == NULL)) {    /* not yet first entry     */
         adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save this as first entry */
       }
#endif
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     if (adsl_sdhc1_last_1 == NULL) {       /* new one is first in chain */
       adsl_sdhc1_work_frse->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_work_frse;
     } else {                               /* middle in chain         */
       adsl_sdhc1_work_frse->adsc_next = adsl_sdhc1_cur_1;
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_work_frse;
#ifdef B130711
       /* set chain field of first struct dsd_sdh_control_1            */
       if (adsl_sdhc1_w1) {                 /* append to first struct dsd_sdh_control_1 */
         adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain gather structures */
         adsl_gai1_last = NULL;             /* no preceeder            */
         while (adsl_gai1_cur) {            /* loop over gather structures */
           adsl_gai1_last = adsl_gai1_cur;  /* save this as last one   */
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_last == NULL) {      /* no preceeder            */
           adsl_sdhc1_cur_1->adsc_gather_i_1_i = adsl_sdhc1_work_frse->adsc_gather_i_1_i;
         } else {                           /* middle of chain         */
           adsl_gai1_last->adsc_next = adsl_sdhc1_work_frse->adsc_gather_i_1_i;
         }
       }
#endif
#ifndef B130711
       /* set chain field of first struct dsd_sdh_control_1            */
       while (adsl_sdhc1_w1) {              /* append to first struct dsd_sdh_control_1 */
         while (TRUE) {                     /* loop to find first gather in old chain */
           adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain gather structures */
           if (adsl_gai1_cur) break;
           if (adsl_sdhc1_w1 == adsl_sdhc1_last_1) break;
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_cur == NULL) break;  /* no data before          */
         while (adsl_gai1_cur->adsc_next) adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         adsl_gai1_cur->adsc_next = adsl_sdhc1_work_frse->adsc_gather_i_1_i;
         break;
       }
#endif
     }
     bol_cont = TRUE;                       /* continue calling Client-Side SSL */
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_pd_do_cs_ssl() insert to client", __LINE__ );
#endif
   }
   if ((bol_cont) && (DSL_HLCL01S.inc_return == DEF_IRET_NORMAL)) {
     goto p_cs_ssl_20;                      /* call subroutine again   */
   }
   /* mark input buffers, cannot be processed now                      */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_position == -1) {  /* input to Client-Side SSL */
#ifdef B110904
       adsl_sdhc1_cur_1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
       adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
       if (DSL_HLCL01S.inc_return != DEF_IRET_NORMAL) {
         /* mark all buffers as processed                              */
         adsl_gai1_cur = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain gather structures */
         while (adsl_gai1_cur) {            /* loop over gather structures */
           adsl_gai1_cur->achc_ginp_cur = adsl_gai1_cur->achc_ginp_end;
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
         }
       }
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   if (DSL_HLCL01S.inc_return == DEF_IRET_NORMAL) return;
   if (DSL_HLCL01S.inc_return != DEF_IRET_END) {
     bol1 = m_rerrm1( DSL_HLCL01S.inc_return, &achl1, &iml1, chrg_ssl_error );
     if (bol1 == FALSE) {                   /* subroutine failed       */
       achl1 = "error-message not available";
       iml1 = strlen( achl1 );
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS150W GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL abend SSL-return-code=%d %.*s",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     DSL_HLCL01S.inc_return, iml1, achl1 );
     if (iml1 > (sizeof(ADSL_CONN1_G->chrc_server_error) - 35)) {
       iml1 = sizeof(ADSL_CONN1_G->chrc_server_error) - 35;
     }
     sprintf( ADSL_CONN1_G->chrc_server_error,  /* display server error */
              "client-side-SSL error %d %.*s",
              DSL_HLCL01S.inc_return, iml1, achl1 );
#ifndef B170127
/* Stefan Martin SM161111_SSLERR */
     adsp_pd_work->boc_eof_server = TRUE;
#endif
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_pd_do_cs_ssl() - free( ADSL_CONN1_G->adsc_csssl_oper_1=%p )",
                   __LINE__, ADSL_CONN1_G->adsc_csssl_oper_1 );
#endif
   free( ADSL_CONN1_G->adsc_csssl_oper_1 );  /* free memory            */
   ADSL_CONN1_G->adsc_csssl_oper_1 = NULL;  /* no more Client-Side SSL */
#ifdef B150127
   adsp_pd_work->boc_eof_server = TRUE;     /* End-of-File Server      */
#endif
// 23.06.06 KB UUUU close TCP server, otherwise security risk
#ifndef B150127
#ifdef D_INCL_HOB_TUN
   if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun) {  /* HOB-TUN HTCP */
     if (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL) return;
     m_htun_sess_close( ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h );
     return;
   }
#endif
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_normal_tcp) return;  /* not normal TCP */
#ifndef HL_UNIX
   ADSL_CONN1_G->dcl_tcp_r_s.close1();      /* class to receive server */
#endif
#ifdef HL_UNIX
   ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_end_session();  /* close TCP session */
#endif
#endif
   return;
#undef DSL_HLCL01S
//#undef ADSL_SERVER_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_pd_do_cs_ssl()                                              */

/**
  Subroutine to close Client-Side SSL
*/
static void m_pd_close_cs_ssl( struct dsd_pd_work *adsp_pd_work ) {
   int        iml1;                         /* working variable        */
#ifdef CLOSE_SSL_V1
   char       *achl1;                       /* working variable        */
   BOOL       bol1;                         /* working varibale        */
#endif
#ifdef XYZ1
   BOOL       bol_cont;                     /* continue calling Client-Side SSL */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
   struct dsd_sdh_control_1 *adsl_sdhc1_work_frse;  /* current work area */
   struct dsd_sdh_control_1 *adsl_sdhc1_work_tose;  /* current work area */
#ifdef OLD01
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#endif
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gather_i_1_i;  /* gather input data     */
#endif
#ifdef CHECK_SDH_01
   struct dsd_gather_i_1 *adsl_gai1_check1;  /* for checks             */
#endif
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structur */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_pd_close_cs_ssl() l%05d started ADSL_CONN1_G=%p adsp_pd_work=%p.",
                   __LINE__, ADSL_CONN1_G, adsp_pd_work );
#endif
#ifdef CLOSE_SSL_V1
#define DSL_HLCL01S ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s
   DSL_HLCL01S.adsc_gai1_in_cl = NULL;      /* clear input from client */
   DSL_HLCL01S.adsc_gai1_in_se = NULL;      /* clear input from server */
   DSL_HLCL01S.inc_func = DEF_IFUNC_CLOSE;  /* release buffers, do house-keeping */
   m_hlcl01( &DSL_HLCL01S );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_pd_close_cs_ssl() - m_hlcl01( %p ) returned inc_return=%d",
                   __LINE__,
                   &DSL_HLCL01S,
                   DSL_HLCL01S.inc_return );
#endif
   if (DSL_HLCL01S.inc_return != DEF_IRET_END) {
     bol1 = m_rerrm1( DSL_HLCL01S.inc_return, &achl1, &iml1, chrg_ssl_error );
     if (bol1 == FALSE) {                   /* subroutine failed       */
       achl1 = "error-message not available";
       iml1 = strlen( achl1 );
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS150W GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL abend SSL-return-code=%d %.*s",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     DSL_HLCL01S.inc_return, iml1, achl1 );
   }
   free( ADSL_CONN1_G->adsc_csssl_oper_1 );  /* free memory            */
   ADSL_CONN1_G->adsc_csssl_oper_1 = NULL;  /* no more Client-Side SSL */
#undef DSL_HLCL01S
#endif
#define DSL_HLCL01S ADSL_CONN1_G->adsc_csssl_oper_1->dsc_hlcl01s
   DSL_HLCL01S.inc_func = DEF_IFUNC_CLOSE;  /* release buffers, do house-keeping */
   do {
     m_pd_do_cs_ssl( adsp_pd_work );
   } while (ADSL_CONN1_G->adsc_csssl_oper_1);
// to-do 24.08.10 KB - tested by Mr. Jakobs, server-side SSL did also close
   adsp_pd_work->boc_eof_server = FALSE;    /* not End-of-File Server  */
// to-do 24.08.10 KB - adsc_csssl_oper_1 should be volatile - or not needed as same thread
#undef DSL_HLCL01S
// to-do 24.08.10 KB - send blocks to server
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_pd_close_cs_ssl()                                           */
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
static void m_fill_ga1_1( struct dsd_deb_ga1_2 *adsp_deb_ga1_2, struct dsd_sdh_control_1 *adsp_sdhc1 ) {
   int        iml1;
// int        iml_c_sdhc1;
   int        iml_c_gai1;
   struct dsd_deb_ga1_2 *adsl_deb_ga1_2_w1;
   struct dsd_deb_ga1_2 *adsl_deb_ga1_2_end;
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */

   memset( adsp_deb_ga1_2, 0, DEF_DEB_GA1_TOTAL * sizeof(struct dsd_deb_ga1_2) );
   adsl_deb_ga1_2_w1 = adsp_deb_ga1_2;
   adsl_deb_ga1_2_end = adsl_deb_ga1_2_w1 + DEF_DEB_GA1_TOTAL;
// iml_c_sdhc1 = 0;
   adsl_sdhc1_w1 = adsp_sdhc1;
   if (adsl_sdhc1_w1 == NULL) return;

   p_sdhc1_20:                              /* next sdhc1              */
   memcpy( &adsl_deb_ga1_2_w1->ac_eyecatcher, "SDHCxxxx", sizeof(void *) );
   adsl_deb_ga1_2_w1->ac_sdhc1 = adsl_sdhc1_w1;
   adsl_deb_ga1_2_w1->inc_function = adsl_sdhc1_w1->inc_function;  /* function of SDH */
   adsl_deb_ga1_2_w1->inc_position = adsl_sdhc1_w1->inc_position;  /* position of SDH */
   adsl_deb_ga1_2_w1->iec_sdhcs = adsl_sdhc1_w1->iec_sdhcs;  /* state of control area server data hook */
   adsl_deb_ga1_2_w1->imc_usage_count = adsl_sdhc1_w1->imc_usage_count;  /* usage count */
   iml_c_gai1 = 0;
   adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get start of chain */
   while (adsl_gai1_w1) {
     if (iml_c_gai1 < DEF_DEB_GA1_GATHER) {
       adsl_deb_ga1_2_w1->dsrc_deb_ga1_1[ iml_c_gai1 ].ac_gai1 = adsl_gai1_w1;
       adsl_deb_ga1_2_w1->dsrc_deb_ga1_1[ iml_c_gai1 ].ac_cur = adsl_gai1_w1->achc_ginp_cur;
       adsl_deb_ga1_2_w1->dsrc_deb_ga1_1[ iml_c_gai1 ].imc_len
         = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_c_gai1++;
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   }
   adsl_deb_ga1_2_w1++;
   if (adsl_deb_ga1_2_w1 >= adsl_deb_ga1_2_end) return;
   adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   if (adsl_sdhc1_w1) {
     goto p_sdhc1_20;                       /* next sdhc1              */
   }
   return;

// p_sdhc1_80:                              /* end sdhc1               */
} /* end m_fill_ga1_1()                                                */

static void m_check_gai_recv_server_1( struct dsd_sdh_control_1 *adsp_sdhc1, char *achp_msg, int imp_line ) {
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */

   adsl_sdhc1_w1 = adsp_sdhc1;
   while (adsl_sdhc1_w1) {
     if (   (adsl_sdhc1_w1->inc_function == DEF_IFUNC_FROMSERVER)  /* function of SDH */
         && (adsl_sdhc1_w1->inc_position == 0)  /* position of SDH */
         && (adsl_sdhc1_w1->adsc_gather_i_1_i)
         && (   (((char *) adsl_sdhc1_w1->adsc_gather_i_1_i) < ((char *) adsl_sdhc1_w1))
             || (((char *) adsl_sdhc1_w1->adsc_gather_i_1_i) > ((char *) adsl_sdhc1_w1 + 64)))) {
       adsl_sdhc1_w2 = adsl_sdhc1_w1;
       do {
         if (adsl_sdhc1_w2->inc_function != DEF_IFUNC_FROMSERVER) break;  /* function of SDH */
         if (adsl_sdhc1_w2->inc_position != 0) break;  /* position of SDH */
         if (adsl_sdhc1_w2->adsc_gather_i_1_i == NULL) break;
         adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;
         while (adsl_gai1_w1) {
           if (adsl_gai1_w1 == adsl_sdhc1_w1->adsc_gather_i_1_i) {
             adsl_sdhc1_w2 = NULL;
             break;
           }
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         }
         if (adsl_sdhc1_w2 == NULL) break;
         adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
       } while (adsl_sdhc1_w2);
       if (adsl_sdhc1_w2) {
         m_hlnew_printf( HLOG_TRACE1, "DEBUG_150218_01 l%05d %s l%05d adsl_sdhc1_w1=%p adsl_sdhc1_w1->adsc_gather_i_1_i=%p.",
                         __LINE__, achp_msg, imp_line, adsl_sdhc1_w1, adsl_sdhc1_w1->adsc_gather_i_1_i );
       }
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   }
} /* end m_check_gai_recv_server_1()                                   */
#endif
