#define TRY_150217_01                       /* problem garbage-collector */
#define TRY_150221_01                       /* problem gather lost     */
#define TRY_150226_01                       /* problem loop gather     */
//#define TRY_160113_01                       /* leave thread after less rounds */
#ifdef TRY_160113_01                        /* leave thread after less rounds */
#define CHECK_050301
#define DEF_WOTHR_LOOP         16           /* compare loop counter    */
#endif
#define WA_SSL_1501_01 (1 * 16 * 1024)      /* workaround SSL problem  */
#ifdef WA_SSL_1501_01                       /* workaround SSL problem  */
#define WA_SSL_1501_02 16                   /* number of gather structures */
#endif
#define B130919
#ifdef TO_DO_13119
     bol_end_conn_s_2 = TRUE;               /* now stage 2 close server */
     no more used
---
01.07.14 KB
bol_proc_sdh - no if
#endif
//#define WORKAROUND_SSL_PROB_120706
#define DEBUG_111205_01                     /* because of insure++     */
//#define TRACEHL_090427_01
#define TRY_090427_01
#define TRY_090729_01
#define TRY_090801_01
#define TRY_090801_02
#define TRY_120214_01                       /* stopps when connect successful */
//#define TRY_120924_01                       /* problem in garbage-collector */
// TRY_120924_01 is useless, maybe - 24.09.12 KB
//#define TRY_120924_02                       /* problem in garbage-collector */
//#define TRACEHL_090801_01
/**
  Handling of buffers
  Sometimes, buffers have to be kept over multiple calls to m_proc_data().
  So, all buffers are kept in the chain ADSL_CONN1_G->adsc_sdhc1_chain.
  First in this chain, there are the buffers with
  inc_function DEF_IFUNC_FROMSERVER, sorted in ascending order of inc_position.
  Buffers which have to be sent to the client direct after SSL encryption have
  inc_function DEF_IFUNC_FROMSERVER and inc_position MAX_SERVER_DATA_HOOK.
  After this, there are the buffers with inc_function DEF_IFUNC_TOSERVER,
  sorted in descending order of inc_position.
  Buffers which have to be sent to the server direct have
  inc_function DEF_IFUNC_TOSERVER and inc_position -1.
  When Client-Side SSL is used, the buffers used for Client-Side SSL have inc_position -1.
  Buffers which have to be sent to the server get inc_position -2 then.
  So the buffers are ordered in a way as they are processed logically.
  When there are multiple buffers struct dsd_sdh_control_1 with the same
  inc_function and inc_position, these are chained together, so that
  the field adsc_gather_i_1_i of the first struct dsd_sdh_control_1
  contains the total chain of data corresponding to this function.
  These is Garbage-Collection for the chain ADSL_CONN1_G->adsc_sdhc1_chain.
*/

#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif
#ifdef TRACEHL_SDH_COUNT_1
static int m_sdh_count_1( DSD_CONN_G *, int, char *, int );  /* count entries sdhc1 */
#endif

#ifdef TRACEHL_SDH_01
static void m_check_sdhc1( DSD_CONN_G *, char *, int );
#endif

/** process data of TCP SSL connection on work thread                  */
#ifndef HL_UNIX
#ifdef B060628
#ifndef TRACEHLD
inline void clconn1::m_proc_data( class clworkth *adsp_workth )  /* process data */
#else
inline void clconn1::m_proc_data( class clworkth *adsp_workth, int *iptrace_act, int *iptrace_time )  /* process data */
#endif
#else
inline void clconn1::m_proc_data( struct dsd_hco_wothr *adsp_hco_wothr )  /* process data */
#endif
#else
static void m_proc_data( struct dsd_hco_wothr *adsp_hco_wothr,
                         void *ap_param_1, void *ap_param_2, void *ap_param_3 )
#endif
{
#ifdef TRACEHL7
   char testbeg[] = " BEGIN LOCALS PROC_DATA";
#endif
#ifdef TRACEHL7
   char test22[] = " BEGIN2 LOCALS PROC_DATA";
#endif
#ifdef TRACE_SL1
   int        inl_loop;
#endif
#ifdef SSL_DEBUG_100710                     /* check loop in SSL       */
   int        iml_ssl_debug = 0;
#endif
   int iu1;                                 /* working variable        */
   int iu2;                                 /* working variable        */
   int        iml1, iml2, iml3, iml4, iml5, iml6, iml7, iml8, iml9;  /* working variables */
   char       *achl1;                       /* working variable        */
#ifndef B090420
   char       *achl_to;                     /* address of target area  */
#endif
#ifdef B130314
   void *     vpl_w1;                       /* working variable        */
#endif
   struct dsd_cid *adsl_cid_signal;         /* return signal           */
   int        inl_encry_cl;                 /* encrypted from client   */
   int        iml_recv;                     /* length data received from client */
#ifndef B140525
   int        iml_no_sdh;                   /* number of SDHs          */
#endif
   int        iml_fromcl_data;              /* count data from client  */
   int        iml_fromcl_rem;               /* count remaining from client */
   int        iml_fromse_rem;               /* count remaining from server */
#ifdef DEBUG_LOOP_PROC_DATA_01
   int        iml_cont_line;                /* line where bol_cont is set */
#endif
#ifdef DEBUG_100903_01
   enum ied_state_server iel_st_ses;        /* status server           */
#endif
#ifdef TRY_120214_01                        /* stopps when connect successful */
   enum ied_state_server iel_st_ses;        /* status server           */
#endif
#ifdef DEBUG_120705_01                      /* loop SSL                */
   int        iml_count_ssl;
#endif
   BOOL       bol1;                         /* working varibale        */
// BOOL       bol2;                         /* working varibale        */
   BOOL       bol_cont;                     /* continue processing     */
   BOOL       bol_c_act;                    /* client activate         */
   BOOL       bol_s_act;                    /* server activate         */
   BOOL       bol_end_conn_s_1;             /* process end server stage 1 */
   BOOL       bol_end_conn_s_2;             /* process end server stage 2 */
#ifndef B140703
   BOOL       bol_end_server;               /* process end server      */
#endif
   BOOL       bol_proc_sdh;                 /* process server-data-hook */
   BOOL       bol_sdh_tose;                 /* process SDH with data to server */
   BOOL       bol_save_st_sslc;             /* save status SSL         */
   BOOL       bol_suspend_do;               /* do suspend work thread  */
   BOOL       bol_suspend_act;              /* do activate work thread after suspend */
   BOOL       bol_lb_timed_out;             /* LB timed out            */
   BOOL       bol_lb_proc_cl;               /* LB process client       */
   BOOL       bol_lb_proc_se;               /* LB process server       */
   BOOL       bol_block_send_client;        /* send to client blocked  */
   BOOL       bol_block_send_server;        /* send to server blocked  */
#ifdef OLD_1112
   struct dsd_recudp1 *adsl_recudp1_w1;     /* chain of data received  */
#endif
   int        iml_count_loop;               /* loop counter for suspend */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server */
   struct dsd_sdh_control_1 *adsl_sdhc1_se_cl;  /* send to client      */
   struct dsd_sdh_control_1 *adsl_sdhc1_se_se;  /* send to server      */
   struct dsd_sdh_control_1 *adsl_sdhc1_client;  /* received from client */
   struct dsd_sdh_control_1 *adsl_sdhc1_lbal_send;  /* load-balancing send to client */
#ifndef OLD_1112
   struct dsd_sdh_control_1 *adsl_sdhc1_lbal_rec;  /* received from WTS load-balancing */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working variable       */
#ifdef TRY_150221_01                        /* problem gather lost     */
   struct dsd_sdh_control_1 *adsl_sdhc1_w4;  /* working variable       */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
// struct dsd_sdh_control_1 *adsl_sdhc1_ps_1;  /* currently processed start */
// struct dsd_sdh_control_1 *adsl_sdhc1_pe_1;  /* currently processed end */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
#ifdef B090731
   struct dsd_gather_i_1 dsl_gather_i_1_i;  /* gather input data       */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_w2;       /* auxiliary extension fi  */
#ifndef B140525
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif
   char   *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace area          */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace area          */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
#ifdef D_INCL_HOB_TUN
#ifdef TRY_130624_01
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* used INETA       */
#endif
#endif
// char       *achl1;                       /* working variable        */
   struct dsd_pd_work dsl_pd_work;          /* work in progress        */
#ifndef B090420
   struct dsd_hl_aux_epoch_1 dsl_epoch;     /* parameters for subroutine */
#endif
#ifdef WA_SSL_1501_01                       /* workaround SSL problem  */
   struct dsd_gather_i_1 *adsl_gai1_fromse;  /* save input data SSL    */
   struct dsd_gather_i_1 **aadsl_gai1_chain;  /* address of next chain */
   struct dsd_gather_i_1 dsrl_gai1_work[ WA_SSL_1501_02 ];  /* input data SSL */
#endif
#ifdef B120708
#ifdef HL_UNIX
   void       *dsrl_message[ DEF_MSG_PIPE_LEN ];  /* message in pipe   */
#endif
#endif
   char       chrl_work1[ LEN_TCP_SEND ];   /* working area            */
#ifdef TRACEHL7
   char *amemtest;
   char testend[]= " END LOCFLS PROC_DATA";
   BOOL bou_retaddr = FALSE;                /* check if returned o.k.  */
#endif
#ifndef HL_UNIX
#ifndef HELP_DEBUG
#define ADSL_CONN1_G this
#else
   class clconn1 *ADSL_CONN1_G = this;
#endif
#else
#define ADSL_CONN1_G ((struct dsd_conn1 *) ap_param_1)
#endif

#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() called ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype );
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d clconn1::m_proc_data start", __LINE__ );
   if (ADSL_CONN1_G->boc_st_act == FALSE) {
     while (TRUE) {
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data() called - boc_st_act == FALSE" );
#ifdef OLD01
#ifndef HL_UNIX
       Sleep( 2000 );
#else
       sleep( 2 );
#endif
#endif
#ifndef HL_UNIX
       ExitProcess( 2 );
#else
       exit( 2 );
#endif
     }
   }
#endif
#ifdef TRACEHLD
   *iptrace_act = 0;
   *iptrace_time = 0;
#endif

#ifdef TRACEHL7
   strcpy(testbeg, " BEGIN LOCALS PROC_DATA");
   strcpy(test22, " BEGIN2 LOCALS PROC_DATA");
   strcpy(testend, " END LOCALS PROC_DATA");
#endif

#ifdef TRACEHLA
   while (bos_error) { Sleep( 10000 ); }
#endif
#ifdef TRACE_HL_SESS_01
   m_clconn1_last_action( this, 10 );       /* last action             */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHLC
   m_check_aclconn1( this, 100 );
#endif
#ifdef TRACE_SL1
   inl_loop = 0;
#endif
#ifdef CHECK_PROB_070113
   m_check_chain_aux( ADSL_CONN1_G );
#endif
#ifdef DEBUG_101216_01
   adsl_sdhc1_w1 = NULL;                    /* nothing received from server yet */
#endif
#ifdef DEBUG_120705_01                      /* loop SSL                */
   iml_count_ssl = 0;
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main start", __LINE__ );
#endif
#ifndef B150710
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNEPDENT", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "SNO=%08d entering m_proc_data() iec_st_cls=%d iec_st_ses=%d iec_servcotype=%d.",
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->iec_st_cls,
                     ADSL_CONN1_G->iec_st_ses,
                     ADSL_CONN1_G->iec_servcotype );
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef B150714
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_abend) {  /* abnormal end of session */
     if (ADSL_CONN1_G->iec_st_cls != ied_cls_closed) {  /* client connection not closed */
#ifndef HL_UNIX
       ADSL_CONN1_G->dcl_tcp_r_c.close1();  /* close connection client */
#endif
#ifdef HL_UNIX
       m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_client, adsp_hco_wothr );  /* close connection client */
#endif
       ADSL_CONN1_G->iec_st_cls = ied_cls_closed;  /* client connection now closed */
     }
#ifndef B150714
     ADSL_CONN1_G->boc_survive = FALSE;     /* survive E-O-F client    */
     dsl_pd_work.boc_abend = TRUE;          /* do not process more     */
#endif
   }
#endif
#endif
// dsl_pd_work.dsc_aux_cf1.ac_sdhr_conn1 = NULL;  /* reload SDH from this connection */
   ADSL_CONN1_G->adsc_aux_cf1_cur = &dsl_pd_work.dsc_aux_cf1;  /* current auxiliary control structure */
   bol_lb_proc_cl = FALSE;                  /* LB process client       */
   bol_lb_proc_se = FALSE;                  /* LB process server       */
#ifdef B090731
   ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = NULL;  /* no input yet  */
#endif
   ADSL_CONN1_G->dsc_hlse03s.vpc_userfld = &dsl_pd_work.dsc_aux_cf1;  /* set user field */
   bol_proc_sdh = FALSE;                    /* process server-data-hook */
#ifndef B120405
   bol_sdh_tose = FALSE;                    /* nothing to server yet   */
#endif
   bol_block_send_client = bol_block_send_server = FALSE;
#ifndef B140525
   iml_no_sdh = 0;                          /* number of SDHs          */
   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used) {           /* with configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     iml_no_sdh = adsl_server_conf_1_used->inc_no_sdh;  /* number of SDHs */
   }
#endif
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (adsl_sdhc1_cur_1->inc_function == DEF_IFUNC_FROMSERVER) {
       if (adsl_sdhc1_cur_1->inc_position == MAX_SERVER_DATA_HOOK) {  /* position send to client */
         bol_block_send_client = TRUE;      /* send to client blocked  */
       }
     } else {
       if (adsl_sdhc1_cur_1->inc_position < 0) {  /* send direct or SSL */
         bol_block_send_server = TRUE;      /* send to server blocked  */
#ifdef TRACE_TCP_FLOW_01
         m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() bol_block_send_server set to TRUE",
                         __LINE__ );
#endif
       }
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   memset( &dsl_pd_work, 0, sizeof(struct dsd_pd_work) );
   dsl_pd_work.dsc_aux_cf1.adsc_conn = ADSL_CONN1_G;  /* set connection */
   dsl_pd_work.dsc_aux_cf1.adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
   if (ADSL_CONN1_G->iec_st_cls == ied_cls_closed) {  /* client connection closed */
     dsl_pd_work.boc_eof_client = TRUE;     /* End-of-File Client      */
   }
   iml_count_loop = 0;                      /* reset loop counter      */
   adsl_sdhc1_se_se = NULL;                 /* send to server          */
   bol_end_conn_s_1 = FALSE;                /* process end server      */
#ifndef B130316
   iel_st_ses = ADSL_CONN1_G->iec_st_ses;   /* save status server      */
#endif
#ifdef OLD_090731
   iml_serv_no_sdh = 0;                     /* number of server-data-hooks - for position send data to client */
   if (ADSL_CONN1_G->adsc_server_conf_1) {  /* with server configured  */
     iml_serv_no_sdh = ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh;
   }
#endif
#ifdef DEBUG_LOOP_PROC_DATA_01
   iml_cont_line = 0;                       /* line where bol_cont is set */
#endif

   pcopd20:                                 /* loop to process data    */
#ifdef TRACEHL_T_050131
   m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data() pcopd20 start" );
   m_chain_sdhc1();                         /* display chain           */
#endif
#ifndef B150714
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_abend) {  /* abnormal end of session */
     if (ADSL_CONN1_G->iec_st_cls != ied_cls_closed) {  /* client connection not closed */
#ifndef HL_UNIX
       ADSL_CONN1_G->dcl_tcp_r_c.close1();  /* close connection client */
#endif
#ifdef HL_UNIX
       m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_client, adsp_hco_wothr );  /* close connection client */
#endif
     }
     ADSL_CONN1_G->iec_st_cls = ied_cls_closed;  /* client connection now closed */
     dsl_pd_work.boc_eof_client = TRUE;     /* End-of-File Client      */
     ADSL_CONN1_G->boc_survive = FALSE;     /* survive E-O-F client    */
     dsl_pd_work.boc_abend = TRUE;          /* do not process more     */
#ifndef B150716
     if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
       dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
     }
#endif
   }
#endif
#ifndef B130710
#ifdef DEBUG_LOOP_PROC_DATA_01
//   iml_cont_line = 0;                       /* line where bol_cont is set */
#endif
   bol_cont = dsl_pd_work.boc_abend;        /* do not process more     */
#ifdef DEBUG_LOOP_PROC_DATA_01
   if (bol_cont) {                          /* do not process more     */
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
   }
#endif
#endif
#ifdef D_INCL_HOB_TUN
#ifndef TRY_130624_01
#ifdef B120203
#ifndef TRY_110523_03                       /* changes Mr. Jakob HOB-TUN / HTCP */
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (ADSL_CONN1_G->adsc_auxf_1_htun + 1))
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_htun) {  /* not HTUN */
     goto pcopd24;                          /* end of processing HTUN  */
   }
#else
   if (   (ADSL_CONN1_G->iec_servcotype != ied_servcotype_htun)  /* not HTUN */
       || (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL)) {
     goto pcopd24;                          /* end of processing HTUN  */
   }
#endif
#else
   if (   (ADSL_CONN1_G->iec_servcotype != ied_servcotype_htun)  /* not HOB-TUN */
       || (ADSL_CONN1_G->adsc_ineta_raws_1 == NULL)) {
     goto pcopd24;                          /* end of processing HOB-TUN */
   }
#endif
#ifdef B101125
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_compl_cpttdt) {  /* connect pass thru to desktop completed */
     ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* start connection to server part one */
#ifdef B100826
     ADSL_CONN1_G->adsc_ineta_raws_1->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get chain auxiliary ext field */
     ADSL_CONN1_G->adsc_auxf_1 = ADSL_CONN1_G->adsc_ineta_raws_1;  /* set new chain auxiliary ext field */
#endif
   }
#endif
   if (ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SESS_END) {  /* done HTUN HTCP session end */
     ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
     while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
       ADSL_CONN1_G->adsc_sdhc1_htun_sch = ADSL_CONN1_G->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     }
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       /* do not set when dynamic server                               */
       if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)
           || (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
         if ((ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_ERR_SESS_END) == 0) {  /* check done HTUN HTCP session end was with error */
           ADSL_CONN1_G->achc_reason_end = "server normal end";
         } else {                           /* abnormal end            */
           ADSL_CONN1_G->achc_reason_end = "server ended with error";
         }
       }
     }
     goto pcopd24;                          /* end of processing HOB-TUN */
   }
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd20 -1- imc_state=%08X DEF_STATE_HTUN_SEND_COMPL=%d adsc_sdhc1_htun_sch=%p imc_send_window=0X%08X.",
                       __LINE__, ADSL_CONN1_G->adsc_ineta_raws_1->imc_state,
                       ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SEND_COMPL,
                       ADSL_CONN1_G->adsc_sdhc1_htun_sch,
                       ADSL_CONN1_G->imc_send_window );
#endif
   if ((ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SEND_COMPL) == 0) {  /* done HTUN send complete - m_htun_htcp_send_complete() */
     goto pcopd24;                          /* end of processing HTUN  */
   }
   ADSL_CONN1_G->adsc_ineta_raws_1->imc_state &= -1 - DEF_STATE_HTUN_SEND_COMPL;  /* done HTUN send complete - m_htun_htcp_send_complete() */
#else
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_htun) {  /* not HTUN */
     goto pcopd24;                          /* end of processing HTUN  */
   }
   adsl_ineta_raws_1_w1 = ADSL_CONN1_G->adsc_ineta_raws_1;  /* used INETA */
   if (adsl_ineta_raws_1_w1 == NULL) {      /* already disconnected    */
     goto p_copd_tun_00;                    /* check end session HOB-TUN */
   }
   if (adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_SESS_END) {  /* done HOB-TUN HTCP session end */
     goto p_copd_tun_20;                    /* reached end session HOB-TUN */
   }
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd20 -1- imc_state=%08X DEF_STATE_HTUN_SEND_COMPL=%d adsc_sdhc1_htun_sch=%p imc_send_window=0X%08X.",
                       __LINE__, adsl_ineta_raws_1_w1->imc_state,
                       adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_SEND_COMPL,
                       ADSL_CONN1_G->adsc_sdhc1_htun_sch,
                       ADSL_CONN1_G->imc_send_window );
#endif
   if ((adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_SEND_COMPL) == 0) {  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
     goto pcopd24;                          /* end of processing HOB-TUN */
   }
   adsl_ineta_raws_1_w1->imc_state &= -1 - DEF_STATE_HTUN_SEND_COMPL;  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
#endif

   /* do garbage-collection and count how many bytes there are still to be sent */
   while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
#ifndef TRY_130511_01
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     while (adsl_gai1_w1) {                 /* loop over chain gai1    */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     if (adsl_gai1_w1) break;               /* not all data sent       */
#endif
#ifdef TRY_130511_01
     while (adsl_sdhc1_w1->adsc_gather_i_1_i) {  /* loop over chain gai1 */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1->adsc_next;  /* set chain to send */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     if (adsl_sdhc1_w1->adsc_gather_i_1_i) break;  /* not all data sent */
#endif
     ADSL_CONN1_G->adsc_sdhc1_htun_sch = ADSL_CONN1_G->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use         */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     } else {                               /* work area still in use  */
       m_clconn1_mark_work_area( ADSL_CONN1_G, adsl_sdhc1_w1 );
     }
   }
#ifdef TRACEHL_T_050131
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data() pcopd20 after freeing blocks sdhc1" );
   m_chain_sdhc1();                         /* display chain           */
#endif
   ADSL_CONN1_G->imc_send_window = 0;       /* clear send window       */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get chain not yet sent */
   if (adsl_sdhc1_w1 == NULL) {
     goto pcopd24;                          /* end of processing HOB-TUN */
   }
   do {                                     /* loop over chain sdhc1   */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     while (adsl_gai1_w1) {                 /* loop over chain gai1    */
       /* check if not already sent before                             */
       adsl_sdhc1_w2 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get chain to send */
       adsl_gai1_w2 = NULL;                 /* not found till now      */
       while (TRUE) {                       /* loop till this element found */
         if (adsl_sdhc1_w2 == adsl_sdhc1_w1) break;  /* this element found */
         adsl_gai1_w2 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain to send */
         while (adsl_gai1_w2) {             /* loop over all gather structures */
           if (adsl_gai1_w2 == adsl_gai1_w1) break;  /* same element sent before */
           adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_w2) break;           /* element sent before     */
         adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
         if (adsl_sdhc1_w2 == NULL) {
           m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_proc_data() l%05d logic error or chain corrupted",
                           m_clconn1_gatename( ADSL_CONN1_G ),
                           m_clconn1_sno( ADSL_CONN1_G ),
                           m_clconn1_chrc_ineta( ADSL_CONN1_G ),
                           __LINE__ );
           break;
         }
       }
       if (adsl_gai1_w2 == NULL) {          /* this gather structure not sent before */
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
           ADSL_CONN1_G->imc_send_window += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         }
       }
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   } while (adsl_sdhc1_w1);
#ifndef TRY_130624_01
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd20 -2- imc_state=%08X DEF_STATE_HTUN_SEND_COMPL=%d adsc_sdhc1_htun_sch=%p imc_send_window=0X%08X.",
                   __LINE__, ADSL_CONN1_G->adsc_ineta_raws_1->imc_state,
                   ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SEND_COMPL,
                   ADSL_CONN1_G->adsc_sdhc1_htun_sch,
                   ADSL_CONN1_G->imc_send_window );
#endif
#else
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd20 -2- imc_state=%08X DEF_STATE_HTUN_SEND_COMPL=%d adsc_sdhc1_htun_sch=%p imc_send_window=0X%08X.",
                   __LINE__, adsl_ineta_raws_1_w1->imc_state,
                   adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_SEND_COMPL,
                   ADSL_CONN1_G->adsc_sdhc1_htun_sch,
                   ADSL_CONN1_G->imc_send_window );
#endif
   goto pcopd24;                            /* end of processing HOB-TUN */

   p_copd_tun_00:                           /* check end session HOB-TUN */
   if (ADSL_CONN1_G->iec_st_ses != ied_ses_rec_close) {  /* received close */
     goto pcopd24;                          /* end of processing HOB-TUN */
   }

   p_copd_tun_20:                           /* reached end session HOB-TUN */
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
   while (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* loop over all buffers */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* save this buffer */
     ADSL_CONN1_G->adsc_sdhc1_htun_sch = ADSL_CONN1_G->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     /* do not set when dynamic server                                 */
     if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)
         || (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (   (adsl_ineta_raws_1_w1)
           && ((adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_ERR_SESS_END) == 0)) {  /* check done HTUN HTCP session end was with error */
         ADSL_CONN1_G->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         ADSL_CONN1_G->achc_reason_end = "server ended with error";
       }
     }
   }
#endif
//#undef ADSL_INETA_RAWS_1_G
#ifndef B130709
   if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server exists */
       && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect)) {  /* only Server-Data-Hook */
     ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server */
   }
#endif
#ifndef B130710
   bol_cont = TRUE;                         /* continue because of HOB-TUN */
#ifdef DEBUG_LOOP_PROC_DATA_01
   iml_cont_line = __LINE__;                /* line where bol_cont is set */
#endif
#endif

   pcopd24:                                 /* end of processing HOB-TUN */
#endif
   bol_suspend_do = FALSE;                  /* check suspend work thread */
   bol_suspend_act = FALSE;                 /* check activate work thread after suspend */
   if (iml_count_loop >= DEF_WOTHR_LOOP) {  /* check loop counter      */
#ifndef CHECK_050301
     if (dsg_hco_main.imc_workque_sched) {  /* work queue scheduled    */
#endif
       bol_suspend_do = TRUE;               /* do suspend work thread  */
#ifndef CHECK_050301
     }
#endif
//     bol_suspend_act = TRUE;              /* do activate work thread after suspend */
   }
   iml_count_loop++;                        /* increment loop counter  */
#ifdef DEBUG_LOOP_PROC_DATA_01
   if (iml_count_loop > DEBUG_LOOP_PROC_DATA_01) {
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd24 iml_count_loop=%d iml_cont_line=%d C->iec_st_ses=%d C->iec_servcotype=%d C->adsc_sdhc1_s1=%p.",
                     __LINE__, iml_count_loop, iml_cont_line, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype, ADSL_CONN1_G->adsc_sdhc1_s1 );
     m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d pcopd24 ...inc_count_proc_end=%d ...boc_abend=%d ...boc_eof_server=%d bol_end_conn_s_1=%d bol_end_conn_s_2=%d.",
                     __LINE__, dsl_pd_work.inc_count_proc_end, dsl_pd_work.boc_abend, dsl_pd_work.boc_eof_server, bol_end_conn_s_1, bol_end_conn_s_2 );
#ifndef HL_UNIX
     Sleep( 1000 );
#else
     sleep( 1 );
#endif
   }
   iml_cont_line = 0;                       /* line where bol_cont is set */
#endif
#ifdef DEBUG_LOOP_PROC_DATA_01
   iml1 = 0;
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain       */
   while (adsl_sdhc1_w1) {
     iml1++;
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   }
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d iml_count_loop=%d iec_st_ses=%d bol_cont=%d ADSL_CONN1_G->adsc_sdhc1_chain %d entries / adsc_ineta_raws_1=%p.",
                   __LINE__, iml_count_loop, ADSL_CONN1_G->iec_st_ses, bol_cont, iml1, ADSL_CONN1_G->adsc_ineta_raws_1 );
#endif
   bol_save_st_sslc = ADSL_CONN1_G->boc_st_sslc;  /* save status SSL   */
   if (   (ADSL_CONN1_G->adsc_aux_timer_ch)
       && (((struct dsd_aux_timer *) (ADSL_CONN1_G->adsc_aux_timer_ch + 1))->boc_expired)) {
#ifdef TRACEHL1
#ifdef B130314
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d timer expired - element=%p type=%d",
                     __LINE__, ADSL_CONN1_G->adsc_aux_timer_ch,
                     ((struct dsd_aux_timer *) (ADSL_CONN1_G->adsc_aux_timer_ch + 1))->iec_src_func );
#else
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d timer expired - element=%p type=%d",
                     __LINE__, ADSL_CONN1_G->adsc_aux_timer_ch,
                     ((struct dsd_aux_timer *) (ADSL_CONN1_G->adsc_aux_timer_ch + 1))->dsc_cid.iec_src_func );
#endif
#endif
     adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get chain of timers */
     while (adsl_auxf_1_w1) {               /* loop over auxiliary timer */
       if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->boc_expired == FALSE) break;
#ifdef B130314
//     switch (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->iec_src_func) {
#endif
       switch (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->dsc_cid.iec_src_func) {
         case ied_src_fu_radius:            /* Radius Entry            */
           if (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL) break;  /* no structure for authentication */
           ADSL_CONN1_G->adsc_wsp_auth_1->boc_timed_out = TRUE;  /* received timed out */
           break;
         case ied_src_fu_to_sdh_relo:       /* timeout SDH reload      */
           /* check if SDH reload active                               */
           adsl_auxf_1_w2 = ADSL_CONN1_G->adsc_auxf_1;   /* get chain auxiliary ext fields */
           while (adsl_auxf_1_w2) {         /* loop over all entries   */
             if (adsl_auxf_1_w2->iec_auxf_def == ied_auxf_sdh_reload) {  /* SDH reload */
               m_sdh_reload_old_end( &dsl_pd_work.dsc_aux_cf1, adsl_auxf_1_w2 );
             }
             adsl_auxf_1_w2 = adsl_auxf_1_w2->adsc_next;  /* get next in chain */
           }
           dsl_pd_work.imc_special_func     /* call with special function */
             = DEF_IFUNC_PREP_CLOSE;        /* prepare close           */
           dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
           if (ADSL_CONN1_G->achc_reason_end) break;  /* reason end session */
           ADSL_CONN1_G->achc_reason_end = "wait for reconnect from client timed out";
           break;
       }
       adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
     }
   }
   if (ADSL_CONN1_G->adsc_lbal_gw_1 == NULL) {  /* no load balancing   */
     bol_lb_proc_cl = FALSE;                /* LB process client       */
     bol_lb_proc_se = FALSE;                /* LB process server       */
     if (ADSL_CONN1_G->adsc_wtsudp1) {      /* still WTS UDP active    */
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data() free l%05d ADSL_CONN1_G=%p ADSL_CONN1_G->adsc_wtsudp1=%p &dsc_wln_ipv4.dsc_udp_multiw_1=%p dsc_wln_ipv6.dsc_udp_multiw_1=%p.",
                       __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_wtsudp1,
                       &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1, &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );
#endif
       if (ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
#ifdef B120213
         m_aux_udp_cleanup( ADSL_CONN1_G,
                            (char *) &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1 );  /* structure for multiple wait */
#else
         m_close_udp_multiw_1( &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1 );  /* structure for multiple wait */
#endif
       }
       if (ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
#ifdef B120213
         m_aux_udp_cleanup( ADSL_CONN1_G,
                            (char *) &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );  /* structure for multiple wait */
#else
         m_close_udp_multiw_1( &ADSL_CONN1_G->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );  /* structure for multiple wait */
#endif
       }
       m_hco_wothr_blocking( dsl_pd_work.dsc_aux_cf1.adsc_hco_wothr );  /* mark thread blocking */
#ifndef HL_UNIX
       Sleep( 200 );
#else
       usleep( 200 );
#endif
       m_hco_wothr_active( dsl_pd_work.dsc_aux_cf1.adsc_hco_wothr, FALSE );  /* mark thread active */
       while (ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec) {  /* received UDP packets */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec;  /* get first in chain */
         ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec = adsl_sdhc1_w1->adsc_next;  /* set new chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free memory             */
       }
       free( ADSL_CONN1_G->adsc_wtsudp1 );
       ADSL_CONN1_G->adsc_wtsudp1 = NULL;   /* no more WTS UDP         */
     }
   }
#ifndef B100323
   if (ADSL_CONN1_G->iec_st_cls == ied_cls_proc_ssl) {  /* process data as SSL input */
     if (ADSL_CONN1_G->adsc_sdhc1_frcl) {   /* chain of buffers from client (SSL encrypted) */
       goto pcopd40;                        /* process data now        */
     }
     ADSL_CONN1_G->iec_st_cls = ied_cls_normal;  /* status client normal processing */
   }
#endif
   adsl_sdhc1_client = NULL;                /* no data received from client */
#ifdef B090731
   memset( &dsl_gather_i_1_i, 0, sizeof(dsl_gather_i_1_i) );  /* gather input data */
#endif
#ifdef OLD_1112
   adsl_recudp1_w1 = NULL;                  /* chain of data received  */
#endif
#ifndef OLD_1112
   adsl_sdhc1_lbal_rec = NULL;              /* received from WTS load-balancing */
#endif
   bol_lb_timed_out = FALSE;                /* LB timed out            */
#ifdef B130716
#ifndef B130710
   bol_cont = dsl_pd_work.boc_abend;        /* do not process more     */
#ifdef DEBUG_LOOP_PROC_DATA_01
   if (bol_cont) {                          /* do not process more     */
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
   }
#endif
#endif
#endif
#ifdef B120820
   if (ADSL_CONN1_G->iec_st_cls != ied_cls_normal) {  /* status client not normal processing */
     goto pcopd28;                          /* check if data received  */
   }
#else
#ifndef HL_UNIX
   if (ADSL_CONN1_G->iec_st_cls != ied_cls_normal) {  /* status client not normal processing */
     goto pcopd28;                          /* check if data received  */
   }
#else
#ifdef B121121
   if (   (ADSL_CONN1_G->iec_st_cls != ied_cls_normal)  /* status client normal processing */
       && (ADSL_CONN1_G->iec_st_cls != ied_cls_rec_close)) {   /* received close */
     goto pcopd28;                          /* check if data received  */
   }
#else
   if (   (ADSL_CONN1_G->iec_st_cls != ied_cls_normal)  /* status client normal processing */
       && (ADSL_CONN1_G->iec_st_cls != ied_cls_rec_close)  /* received close */
       && (ADSL_CONN1_G->iec_st_cls != ied_cls_set_entropy)) {  /* set entropy */
     goto pcopd28;                          /* check if data received  */
   }
#endif
#endif
#endif
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_radqu) {          /* radius active           */
     if (   (ADSL_CONN1_G->adsc_radqu->imc_len_received)  /* length radius received */
         || (ADSL_CONN1_G->adsc_radqu->boc_timed_out)  /* received timed out */
         || (ADSL_CONN1_G->adsc_radqu->boc_did_connect)) {  /* did connect */
       goto pcopd52;                        /* process radius request  */
     }
   }
#endif
#ifndef OLD_1112
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* authentication active   */
     if (ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify) {  /* notify authentication routine */
       goto pcopd52;                        /* process radius request  */
     }
   }
#endif
   if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_do_lbal)  /* status do load-balancing */
       && (ADSL_CONN1_G->boc_st_sslc)       /* ssl handshake complete  */
       && (ADSL_CONN1_G->adsc_lbal_gw_1 == NULL)  /* no load balancing yet */
       && (ADSL_CONN1_G->adsc_wtsudp1 == NULL)) {  /* no WTS UDP       */
#ifdef B140118
     /* area for UDP processing                                        */
     ADSL_CONN1_G->adsc_wtsudp1 = (struct dsd_wts_udp_1 *) malloc( sizeof(struct dsd_wts_udp_1) );
     memset( ADSL_CONN1_G->adsc_wtsudp1, 0, sizeof(struct dsd_wts_udp_1) );
#endif
     m_lbal_udp_start( ADSL_CONN1_G );
     /* class load balancing GW                                        */
     ADSL_CONN1_G->adsc_lbal_gw_1 = new dsd_lbal_gw_1( ADSL_CONN1_G,
         ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time1,
         ADSL_CONN1_G->adsc_server_conf_1->inc_wts_time2,
         ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1,
         ADSL_CONN1_G->adsc_server_conf_1->boc_is_blade_server );
     bol_cont = TRUE;                       /* more to do              */
   }
#ifdef B140214
   if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_1)  /* start connection to server part one */
       || (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2)) {  /* start connection to server part two */
     bol_cont = TRUE;                       /* more to do              */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d iec_st_ses == ied_ses_start_server / adsc_sdhc1_chain=%p",
                     __LINE__, ADSL_CONN1_G->adsc_sdhc1_chain );
#endif
   }
#endif
#ifndef B140214
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2) {  /* start connection to server part two */
     bol_cont = TRUE;                       /* more to do              */
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d iec_st_ses == ied_ses_start_server_2 / adsc_sdhc1_chain=%p",
                     __LINE__, ADSL_CONN1_G->adsc_sdhc1_chain );
//#endif
   }
#endif
#ifdef DEBUG_100903_01
   iel_st_ses = ADSL_CONN1_G->iec_st_ses;   /* save status server      */
#endif
#ifdef TRY_120214_01                        /* stopps when connect successful */
   iel_st_ses = ADSL_CONN1_G->iec_st_ses;   /* save status server      */
#endif
   m_start_rec_server( &dsl_pd_work );
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d pcopd24 - after m_start_rec_server() iec_st_ses=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses );
#endif
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() after m_start_rec_server() ADSL_CONN1_G->iec_st_ses=%d.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses );
#endif
#ifdef B140527
#ifndef B140525
   iml_no_sdh = 0;                          /* number of SDHs          */
   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used) {           /* with configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     iml_no_sdh = adsl_server_conf_1_used->inc_no_sdh;  /* number of SDHs */
   }
#endif
#endif
#ifdef DEBUG_100903_01
   if (ADSL_CONN1_G->iec_st_ses != iel_st_ses) {  /* status server has changed */
     bol_cont = TRUE;                       /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
   }
#endif
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_error_conn) {  /* status server error */
     dsl_pd_work.boc_abend = TRUE;          /* process end session     */
#ifndef B14117
     if (   (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL)  /* authentication not active */
         && (ADSL_CONN1_G->boc_sdh_started == FALSE)) {  /* Server-Data-Hooks have been started */
       dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
     }
#endif
#ifndef B090909
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
#endif
#ifdef OLD_1112
     if (   (ADSL_CONN1_G->adsc_radqu == NULL)  /* radius no more active */
         && (ADSL_CONN1_G->achc_reason_end == NULL)) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "connect to Server failed";
     }
#endif
#ifndef OLD_1112
     if (   (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL)  /* authentication not active */
         && (ADSL_CONN1_G->achc_reason_end == NULL)) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "connect to Server failed";
     }
#endif
#ifndef DEBUG_100903_01
     bol_cont = TRUE;                       /* more to do              */
#endif
   }
#ifdef OLD_1112
   if (   (ADSL_CONN1_G->adsc_radqu)        /* radius active           */
       && (ADSL_CONN1_G->adsc_radqu->boc_did_connect)) {  /* did connect */
     goto pcopd52;                          /* process radius request  */
   }
#endif
#ifndef OLD_1112
   if (   (ADSL_CONN1_G->adsc_wsp_auth_1)   /* authentication active   */
       && (ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify)) {  /* notify authentication routine */
     goto pcopd52;                          /* process authentication / radius request */
   }
#endif
#ifdef B140701_XXX
   if (   (ADSL_CONN1_G->iec_st_ses != iel_st_ses)  /* status server has changed */
       && (ADSL_CONN1_G->adsc_int_webso_conn_1)) {  /* connect for WebSocket applications - internal */
     bol_sdh_tose = TRUE;                   /* call Server-Data-Hook anyway */
   }
#endif
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_sdh) {  /* start Server-Data-Hooks */
     ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
#ifdef B140525
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {  /* with server-data-hook */
       dsl_pd_work.inc_count_proc_end = 1;  /* process start of connection */
#ifndef X101214_XX
       dsl_pd_work.imc_hookc = -1;          /* hook-count              */
#else
       dsl_pd_work.imc_hookc = 0;           /* hook-count              */
#endif
       goto pcall_sdh_frse;                 /* call SDH from server    */
     }
#endif
#ifndef B140525
     if (iml_no_sdh > 0) {                  /* with server-data-hook   */
       dsl_pd_work.inc_count_proc_end = 1;  /* process start of connection */
       dsl_pd_work.imc_hookc = -1;          /* hook-count              */
       goto pcall_sdh_frse;                 /* call SDH from server    */
     }
#endif
   }

   pcopd28:                                 /* check if data received  */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd28-1", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   if (ADSL_CONN1_G->dsc_hlse03s.inc_func != DEF_IFUNC_CONT) {
     bol_cont = TRUE;                       /* more to process         */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
#ifndef HL_UNIX
     if (ADSL_CONN1_G->dsc_hlse03s.inc_func == DEF_IFUNC_START) {  /* check start mode */
       /* start receiving client                                       */
#ifdef B090626
       dcl_tcp_r_c.start2();                /* receive data now        */
#else
       dcl_tcp_r_c.start2();                /* start TCPCOMP           */
       iml1 = m_se_get_conf_timeout( adsc_gate1->vpc_configid );
       if (iml1 <= 0) iml1 = DEF_SSL_TIMEOUT;
       if (   (adsc_gate1->itimeout > 0)    /* set timeout             */
           && (adsc_gate1->itimeout < iml1)) {
         iml1 = adsc_gate1->itimeout;       /* get number of seconds   */
       }
       if (ADSL_CONN1_G->imc_timeout_set) {   /* timeout set in seconds */
         iml1 = ADSL_CONN1_G->imc_timeout_set;  /* timeout set in seconds */
       }
       if (iml1) {                          /* time specified          */
         dsc_timer.ilcwaitmsec = iml1 * 1000;  /* wait in milliseconds */
         m_time_set( &dsc_timer, FALSE );   /* set timeout now         */
         ilc_timeout = dsc_timer.ilcendtime;  /* save end-time         */
       }
       dcl_tcp_r_c.start3();                /* receive data now        */
       if (ADSL_CONN1_G->iec_st_cls == ied_cls_wait_start) {  /* wait for start message */
         ADSL_CONN1_G->iec_st_cls = ied_cls_start_02;  /* process start messages  */
       }
#endif
#ifndef B130316_XXX
       goto pcopd40;                        /* process data now        */
#else
       if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal) {  /* status client normal processing */
         goto pcopd40;                      /* process data now        */
       }
#endif
     }
#else
     if (ADSL_CONN1_G->dsc_hlse03s.inc_func == DEF_IFUNC_START) {  /* check start mode */
       /* start receiving client                                       */
// to-do 09.08.11 KB
//     dcl_tcp_r_c.start2();                /* start TCPCOMP           */
       iml1 = m_se_get_conf_timeout( ADSL_CONN1_G->adsc_gate1->vpc_configid );
       if (iml1 <= 0) iml1 = DEF_SSL_TIMEOUT;
       if (   (ADSL_CONN1_G->adsc_gate1->itimeout > 0)  /* set timeout */
           && (ADSL_CONN1_G->adsc_gate1->itimeout < iml1)) {
         iml1 = ADSL_CONN1_G->adsc_gate1->itimeout;  /* get number of seconds */
       }
       if (ADSL_CONN1_G->imc_timeout_set) {   /* timeout set in seconds */
         iml1 = ADSL_CONN1_G->imc_timeout_set;  /* timeout set in seconds */
       }
       if (iml1) {                          /* time specified          */
         ADSL_CONN1_G->dsc_timer.ilcwaitmsec = iml1 * 1000;  /* wait in milliseconds */
         m_time_set( &ADSL_CONN1_G->dsc_timer, FALSE );  /* set timeout now */
         ADSL_CONN1_G->ilc_timeout = ADSL_CONN1_G->dsc_timer.ilcendtime;  /* save end-time */
       }
// to-do 09.08.11 KB
//     dcl_tcp_r_c.start3();                /* receive data now        */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d clconn1::m_proc_data before ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1.m_recv()",
                       __LINE__ );
#endif
       ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1.m_recv();  /* start receiving from client */
       if (ADSL_CONN1_G->iec_st_cls == ied_cls_wait_start) {  /* wait for start message */
         ADSL_CONN1_G->iec_st_cls = ied_cls_start_02;  /* process start messages  */
       }
#ifndef B130316_XXX
       goto pcopd40;                        /* process data now        */
#else
       if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal) {  /* status client normal processing */
         goto pcopd40;                      /* process data now        */
       }
#endif
     }
#endif
   }
// if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) bou_conn_end = TRUE;
#ifdef TRACEHLD
   *iptrace_act = 0X11;
#endif
#ifndef B090420

// pcopd28:                                 /* check if data received  */
#endif
#ifdef DEBUG_101216_01
   m_hlnew_printf( HLOG_XYZ1, "T$D1 m_proc_data() l%05d overwrite adsl_sdhc1_w1=%p.",
                   __LINE__, adsl_sdhc1_w1 );
#endif
   adsl_sdhc1_w1 = NULL;                    /* nothing received from server yet */
   bol_c_act = FALSE;                       /* client activate         */
   bol_s_act = FALSE;                       /* server activate         */
   bol_end_conn_s_2 = FALSE;                /* do not process end server */
#ifndef B141124
   bol_end_server = FALSE;                  /* process end server      */
#endif
   if (bol_end_conn_s_1) {                  /* close server stage 1    */
     bol_cont = TRUE;                       /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
#ifdef B131119
     bol_end_conn_s_2 = TRUE;               /* now stage 2 close server */
#endif
#ifndef B131119
     dsl_pd_work.boc_eof_server = FALSE;    /* no more End-of-File Server */
#ifndef TJ_B171006
     ADSL_CONN1_G->chrc_server_error[0] = 0; /* reset server error */
#endif
#ifdef XYZ1
     dsl_pd_work.inc_count_proc_end = 0;    /* process start or end connection */
#endif
#endif
     bol_end_conn_s_1 = FALSE;              /* do not process end server */
   }
   if (dsl_pd_work.inc_count_proc_end > 0) {  /* process start or end connection */
/**
   to-do 07.09.10 KB
   should we test here if sending to the client or to the server
   is currently not possible because of flow-control?
   If we check for flow-control we need to check first if the
   TCP connection is still alive
   --- later ---
   no, this is not possible since dsl_pd_work.inc_count_proc_end
   has to be processed immediately, without returning from the work-thread.
   So maybe at other positions dsl_pd_work.inc_count_proc_end needs to be
   checked so that it can be processed immediately.
*/
     bol_cont = TRUE;                       /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
     bol_proc_sdh = TRUE;                   /* process server-data-hook */
//?? if (dsl_pd_work.inc_count_proc_end >= 2) {  /* process end of connection */
//?? }
   } else {
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd28-ret", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
#ifdef B141124
#ifndef B140703
     bol_end_server = FALSE;                /* process end server      */
#endif
#endif
#ifndef HL_UNIX
     EnterCriticalSection( &d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                     __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
#endif
#ifdef TRACE_TCP_FLOW_01
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() ADSL_CONN1_G->adsc_sdhc1_c1=%p.",
                     __LINE__, ADSL_CONN1_G->adsc_sdhc1_c1 );
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_c1) {     /* data received from client */
       do {
#ifndef HL_UNIX
         if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_conn)  /* status server */
             && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE)) {  /* not only Server-Data-Hook */
           /* wait because of flow control                             */
           if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
               && (dcl_tcp_r_s.m_check_send_act())) {  /* check server */
#ifdef TRY_120306_01                        /* flow-control send       */
             this->dcl_tcp_r_s.boc_act_conn_send = TRUE;  /* activate connection after send */
#endif
#ifdef TRACE_TCP_FLOW_01
             m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() dcl_tcp_r_s.boc_act_conn_send set to TRUE",
                             __LINE__ );
#endif
             break;
           }
#ifdef D_INCL_HOB_TUN
           if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun)  /* HTUN */
               && (ADSL_CONN1_G->imc_send_window > DEF_HTCP_SEND_WINDOW)) {  /* number of bytes to be sent */
             break;
           }
#endif
         }
#ifdef B120113
         /* flow-control, we stop receiving from the client while SSL-handshake is done with the server */
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_wait_csssl) break;  /* wait for client-side SSL */
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_1) break;  /* start connection to server part one */
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2) break;  /* start connection to server part two */
#else
         /* flow-control, we stop receiving from the client while we cannot send to the server */
         if (   (ADSL_CONN1_G->iec_st_ses != ied_ses_conn)  /* status server */
             && (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)) {  /* with server connection */
           break;
         }
#endif
#else
         if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_conn)  /* status server */
             && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE)) {  /* not only Server-Data-Hook */
           /* wait because of flow control                             */
           if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
               && (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send)) {  /* still data to send */
#ifdef TRY_120306_01                        /* flow-control send       */
             ADSL_CONN1_G->dsc_tc1_server.boc_act_conn_send = TRUE;  /* activate connection after send */
#endif
             break;
           }
#ifdef D_INCL_HOB_TUN
           if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun)  /* HTUN */
               && (ADSL_CONN1_G->imc_send_window > DEF_HTCP_SEND_WINDOW)) {  /* number of bytes to be sent */
             break;
           }
#endif
         }
         /* flow-control, we stop receiving from the client while we cannot send to the server */
         if (   (ADSL_CONN1_G->iec_st_ses != ied_ses_conn)  /* status server */
#ifdef TRY_131018_01                        /* problem test Mr. Jira, not receiving from client */
             && (ADSL_CONN1_G->iec_st_ses != ied_ses_rec_close)  /* received close */
#endif
             && (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)) {  /* with server connection */
           break;
         }
#endif
         if (bol_suspend_do) {              /* do suspend work thread  */
#ifdef TRACEHL1
           m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d bol_suspend_do set",
                           __LINE__ );
#endif
           bol_suspend_act = TRUE;          /* activate work thread after suspend */
           break;                           /* do not retrieve received data */
         }
         adsl_sdhc1_client = ADSL_CONN1_G->adsc_sdhc1_c1;  /* get data received */
         ADSL_CONN1_G->adsc_sdhc1_c1 = ADSL_CONN1_G->adsc_sdhc1_c2;  /* second buffer in front */
         ADSL_CONN1_G->adsc_sdhc1_c2 = NULL;  /* clear second buffer   */
         ADSL_CONN1_G->inc_c_ns_rece_c++;   /* count receive client    */
#ifdef B081003
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsl_sdhc1_client + 1))
         ADSL_CONN1_G->ilc_d_ns_rece_c += ADSL_GATHER_I_1_W->achc_ginp_end - ADSL_GATHER_I_1_W->achc_ginp_cur;
#undef ADSL_GATHER_I_1_W
#endif
         ADSL_CONN1_G->ilc_d_ns_rece_c
           += adsl_sdhc1_client->adsc_gather_i_1_i->achc_ginp_end
                - adsl_sdhc1_client->adsc_gather_i_1_i->achc_ginp_cur;
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         if (ADSL_CONN1_G->adsc_sdhc1_c1) {  /* client was stopped     */
           bol_c_act = TRUE;                /* client activate         */
         }
       } while (FALSE);
     } else {
#ifndef HL_UNIX
#ifdef WAS_BEFORE_1501
       if (dcl_tcp_r_c.getstc() == FALSE) {  /* get status connection  */
#ifdef FORKEDIT
       }
#endif
#endif
       if (   (dcl_tcp_r_c.getstc() == FALSE)  /* get status connection */
           && (ADSL_CONN1_G->iec_st_cls != ied_cls_closed)) {  /* client connection closed */
#ifdef FORKEDIT
       }
#endif
#else
#ifdef B120214
       if (ADSL_CONN1_G->iec_st_cls != ied_cls_normal) {  /* received close */
#ifdef FORKEDIT
       }
#endif
#else
       if (ADSL_CONN1_G->iec_st_cls == ied_cls_rec_close) {  /* received close */
#endif
#endif
         dsl_pd_work.boc_eof_client = TRUE;  /* End-of-File Client     */
#ifdef WAS_BEFORE_1501
#ifndef HL_UNIX
#ifndef B100408
         ADSL_CONN1_G->iec_st_cls = ied_cls_normal;  /* status client normal processing */
#endif
#endif
         if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
           dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
         }
#endif
         ADSL_CONN1_G->iec_st_cls = ied_cls_closed;  /* client connection closed */
         if (ADSL_CONN1_G->boc_survive == FALSE) {  /* survive E-O-F client */
           if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
             dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
           }
         } else {
           m_hlnew_printf( HLOG_INFO1, "HWSPS035I GATE=%(ux)s SNO=%08d INETA=%s connection ended from client - waiting for reconnect",
                           ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
           m_sdh_reload_client_ended( ADSL_CONN1_G );
           dsl_pd_work.imc_special_func     /* call with special function */
             = DEF_IFUNC_CLIENT_DISCO;      /* client is disconnected  */
         }
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
     }
#ifdef TRACEHL1
#ifndef HL_UNIX
     m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data entered Critical Section data from server adsc_sdhc1_s1=%p adsc_sdhc1_s2=%p dcl_tcp_r_s.getstc()=%d",
                     ADSL_CONN1_G->adsc_sdhc1_s1, ADSL_CONN1_G->adsc_sdhc1_s2, dcl_tcp_r_s.getstc() );
#endif
#ifdef B081003
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (ADSL_CONN1_G->adsc_sdhc1_s1 + 1))
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {
       m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data adsc_sdhc1_s1=%p achc_ginp_cur=%p achc_ginp_end=%p",
                       ADSL_CONN1_G->adsc_sdhc1_s1, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
     }
#undef ADSL_GATHER_I_1_W
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (ADSL_CONN1_G->adsc_sdhc1_s2 + 1))
     if (ADSL_CONN1_G->adsc_sdhc1_s2) {
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data adsc_sdhc1_s2=%p achc_ginp_cur=%p achc_ginp_end=%p",
                       ADSL_CONN1_G->adsc_sdhc1_s2, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
     }
#undef ADSL_GATHER_I_1_W
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {
       m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data adsc_sdhc1_s1=%p achc_ginp_cur=%p achc_ginp_end=%p",
                       ADSL_CONN1_G->adsc_sdhc1_s1,
                       ADSL_CONN1_G->adsc_sdhc1_s1->adsc_gather_i_1_i->achc_ginp_cur,
                       ADSL_CONN1_G->adsc_sdhc1_s1->adsc_gather_i_1_i->achc_ginp_end );
     }
     if (ADSL_CONN1_G->adsc_sdhc1_s2) {
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data adsc_sdhc1_s2=%p achc_ginp_cur=%p achc_ginp_end=%p",
                       ADSL_CONN1_G->adsc_sdhc1_s2,
                       ADSL_CONN1_G->adsc_sdhc1_s2->adsc_gather_i_1_i->achc_ginp_cur,
                       ADSL_CONN1_G->adsc_sdhc1_s2->adsc_gather_i_1_i->achc_ginp_end );
     }
#endif
     if (   (   (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL)  /* authentication not active */
             || (ADSL_CONN1_G->adsc_wsp_auth_1->boc_rec_from_server))  /* receive from server */
#ifndef TRY_120306_01                       /* flow-control send       */
#ifndef HL_UNIX
         && (dcl_tcp_r_c.m_check_send_act() == FALSE)  /* check flow client */
#else
         && (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL)  /* check flow client */
#endif
#endif
         && (dsl_pd_work.boc_eof_client == FALSE)) {  /* when client has ended, stop receiving from server */
       if (ADSL_CONN1_G->adsc_sdhc1_s1) {   /* data received from server */
#ifndef TRY_120306_01                       /* flow-control send       */
         if (bol_suspend_do) {              /* do suspend work thread  */
#ifdef FORKEDIT
         }
#endif
#else
#ifndef HL_UNIX
         if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act()) {  /* check flow client */
           ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = TRUE;  /* activate connection after send */
         } else if (bol_suspend_do) {       /* do suspend work thread  */
#else
         if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* check flow client */
           ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send = TRUE;  /* activate connection after send */
         } else if (bol_suspend_do) {       /* do suspend work thread  */
#endif
#endif
           bol_suspend_act = TRUE;          /* activate work thread after suspend */
         } else {
#ifndef B090731_XX
           adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_s1;  /* get data received from server */
           ADSL_CONN1_G->adsc_sdhc1_s1 = ADSL_CONN1_G->adsc_sdhc1_s2;  /* second buffer in front */
           ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer */
#ifdef TRACEHL_STOR_USAGE
           {
             char chrh_msg[16];
             sprintf( chrh_msg, "main-l%05d", __LINE__ );
             m_proc_trac_1( adsl_sdhc1_w1, chrh_msg );
           }
#endif
           bol_cont = TRUE;                 /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
           iml_cont_line = __LINE__;        /* line where bol_cont is set */
#endif
           if (ADSL_CONN1_G->adsc_sdhc1_s1) {  /* server was stopped   */
             bol_s_act = TRUE;              /* server activate         */
           }
#ifdef TRACEHL_101209
           m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_proc_data() bol_s_act=%d.",
                           __LINE__, bol_s_act );
#endif
#ifdef TRACEHL1
#ifndef HL_UNIX
           m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data entered Critical Section -2- data from server adsc_sdhc1_s1=%p adsc_sdhc1_s2=%p dcl_tcp_r_s.getstc()=%d",
                           ADSL_CONN1_G->adsc_sdhc1_s1, ADSL_CONN1_G->adsc_sdhc1_s2, dcl_tcp_r_s.getstc() );
#endif
#endif
#else
/*
   Server-Data-Hooks cannot be processed since they wait for more input
*/
           do {                             /* pseudo-loop             */
             /* check if not too many data to send to client           */
             iml1 = MAX_TCP_RECV * LEN_TCP_RECV;  /* maximum of send-buffers in memory */
             adsl_sdhc1_w2 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
             while (adsl_sdhc1_w2) {        /* loop over all buffers   */
               if (adsl_sdhc1_w2->inc_function != DEF_IFUNC_FROMSERVER) break;
               adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain of gather */
               while (adsl_gai1_w1) {       /* loop over all gather input */
                 iml1 -= adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
                 if (iml1 < 0) break;
                 adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
               }
#ifdef TRACEHL_090801_01
               iml2 = 0;
               adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain of gather */
               while (adsl_gai1_w1) {       /* loop over all gather input */
                 iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
                 adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
               }
               m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d - adsl_sdhc1_w2=%p length=%d inc_position=%d boc_ready_t_p=%d.",
                               __LINE__, adsl_sdhc1_w2, iml2, adsl_sdhc1_w2->inc_position, adsl_sdhc1_w2->boc_ready_t_p );
#endif
               if (iml1 < 0) break;
               adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
             }
#ifdef TRACEHL_090801_01
             if (iml1 < 0) {
               m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d - too many data in buffers", __LINE__ );
             }
#endif
#ifdef TRACEHL_101209
             if (iml1 < 0) {
               m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_proc_data() too many data in buffers",
                           __LINE__ );
             }
#endif
             if (iml1 < 0) break;
             adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_s1;  /* get data received from server */
             ADSL_CONN1_G->adsc_sdhc1_s1 = ADSL_CONN1_G->adsc_sdhc1_s2;  /* second buffer in front */
             ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer */
             bol_cont = TRUE;               /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
             iml_cont_line = __LINE__;      /* line where bol_cont is set */
#endif
             if (ADSL_CONN1_G->adsc_sdhc1_s1) {  /* server was stopped */
               bol_s_act = TRUE;            /* server activate         */
             }
#ifdef TRACEHL_101209
             m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_proc_data() bol_s_act=%d.",
                             __LINE__, bol_s_act );
#endif
#ifdef TRACEHL1
#ifndef HL_UNIX
             m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data entered Critical Section -2- data from server adsc_sdhc1_s1=%p adsc_sdhc1_s2=%p dcl_tcp_r_s.getstc()=%d",
                             ADSL_CONN1_G->adsc_sdhc1_s1, ADSL_CONN1_G->adsc_sdhc1_s2, dcl_tcp_r_s.getstc() );
#endif
#endif
           } while (FALSE);
#endif
         }
       } else {                             /* no data received        */
#ifdef B130909
//#ifndef HL_UNIX
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) {  /* status server */
           if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server exists */
               && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE)) {  /* not only Server-Data-Hook */
             if (   (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
                     && (dcl_tcp_r_s.getstc() == FALSE))  /* get status connection */
                 || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)) {  /* server connection ended */
#ifdef B071113
               if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
                 bol_end_conn_s_1 = TRUE;   /* process end server      */
               }
               dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server */
               if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
                 dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
               }
#else
               dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server */
               if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
                 bol_end_conn_s_1 = TRUE;   /* process end server      */
               } else if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
                 dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
               }
#endif
               bol_cont = TRUE;             /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
               iml_cont_line = __LINE__;    /* line where bol_cont is set */
#endif
             }
           }
         }
//#else
#endif
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_rec_close) {  /* received close */
#ifdef B140703
#ifndef TRY_130624_01
           if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server exists */
               && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE)  /* not only Server-Data-Hook */
               && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
#ifdef B071113
             if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
               bol_end_conn_s_1 = TRUE;     /* process end server      */
             }
             dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server */
             if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
               dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
             }
#else
             dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server */
             if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
               bol_end_conn_s_1 = TRUE;     /* process end server      */
             } else if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
               dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
             }
#endif
             bol_cont = TRUE;               /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
             iml_cont_line = __LINE__;      /* line where bol_cont is set */
#endif
           }
#else
#ifndef TRY_130716_01                        /* problem loop Web Server Gate */
           if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none) {  /* without server connection */
#ifdef FORKEDIT
           }
#endif
#endif
#ifdef TRY_130716_01                        /* problem loop Web Server Gate */
           if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* without server connection */
               || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
               || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)) {  /* server connection ended */
#endif
#ifdef B140629
             if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server exists */
                 && (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect == FALSE)  /* not only Server-Data-Hook */
                 && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
#ifdef FORKEDIT
             }
#endif
#endif
#ifndef B140629
             if (   (iml_no_sdh > 0)        /* number of SDHs          */
                 && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
#endif
               dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server */
#ifdef B131116
               if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
                 bol_end_conn_s_1 = TRUE;   /* process end server      */
               } else if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
                 dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
               }
#endif
#ifndef B131116
#ifdef B140525
#ifdef B131129
               if (   (ADSL_CONN1_G->adsc_server_conf_1->boc_conn_other_se)  /* option-connect-other-server */
                   && (   (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic)
                       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh))) {  /* with server-data-hook */
#ifdef FORKEDIT
               }
#endif
#endif
#ifndef B131129
               if (   (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic)
                   || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)) {  /* with server-data-hook */
#ifdef FORKEDIT
               }
#endif
#endif
#endif
#ifndef B140525
               if (   (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic)
                   || (iml_no_sdh > 0)) {   /* with SDH                */
#endif
                 bol_end_conn_s_1 = TRUE;   /* process end server      */
#ifndef HL_UNIX
                 if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
// to-do 17.11.13 KB - better solution with post like in Unix
                   dcl_tcp_r_s.close1();    /* close connection server */
#ifndef B131117
                   dcl_tcp_r_s.m_wait_cleanup();  /* wait for cleanup server */
#endif
                   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
                 }
#else
                 if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifdef B131117
                   ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_shutdown();  /* close connection server */
//                 ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not more connected */
#endif
#ifndef B131117
                   m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_server, adsp_hco_wothr );  /* close connection server */
#endif
                   ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
                 }
#endif
                 ADSL_CONN1_G->achc_reason_end = NULL;  /* reason end session */
               } else if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
                 dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
               }
#endif
               bol_cont = TRUE;             /* more to do              */
#ifndef B13119
               bol_proc_sdh = TRUE;         /* process server-data-hook */
#endif
#ifdef DEBUG_LOOP_PROC_DATA_01
               iml_cont_line = __LINE__;    /* line where bol_cont is set */
#endif
             }
#ifdef TRY_130716_01                        /* problem loop Web Server Gate */
             ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
#endif
           } else {                         /* wait till end server    */
             bol_cont = TRUE;               /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
             iml_cont_line = __LINE__;      /* line where bol_cont is set */
#endif
           }
#endif
#ifdef XYZ1
#ifndef B140525
           if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
             adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old entry */
             ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
             free( adsl_server_conf_1_w1 );  /* free old server entry  */
           }
#endif
#endif
#endif
#ifndef B140703
           bol_end_server = TRUE;           /* process end server      */
#endif
#ifndef B140727
           if (iml_no_sdh == 0) {           /* no SDH                  */
             if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
               dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
               bol_cont = TRUE;             /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
               iml_cont_line = __LINE__;    /* line where bol_cont is set */
#endif
             }
           }
#endif
         }
//#endif
       }
     }
     while (   (ADSL_CONN1_G->adsc_lbal_gw_1)
            && (ADSL_CONN1_G->adsc_wtsudp1)
            && (ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec)) {  /* received UDP packets */
       if (bol_suspend_do) {                /* do suspend work thread  */
         bol_suspend_act = TRUE;            /* activate work thread after suspend */
         break;
       }
       adsl_sdhc1_lbal_rec = ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec;  /* received from WTS load-balancing */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d m_proc_data() adsl_sdhc1_lbal_rec=%p.",
                       __LINE__, adsl_sdhc1_lbal_rec );
#endif
       ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec = adsl_sdhc1_lbal_rec->adsc_next;  /* remove from chain */
       bol_cont = TRUE;                     /* more to do              */
       break;
     }
     if (bol_block_send_client) {           /* send to client blocked  */
       bol_block_send_client = FALSE;       /* send to client no more blocked */
#ifndef HL_UNIX
       if (dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
#else
// to-do 09.08.11 KB flow client
       if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL) {  /* check flow client */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
#endif
     }
     if (bol_block_send_server) {           /* send to server blocked  */
       bol_block_send_server = FALSE;       /* send to server no more blocked */
#ifndef HL_UNIX
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           && (dcl_tcp_r_s.m_check_send_act() == FALSE)) {  /* check flow server */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
#else
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           && (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send == NULL)) {  /* check flow server */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
#endif
#ifdef D_INCL_HOB_TUN
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun)  /* HTUN */
           && (ADSL_CONN1_G->imc_send_window <= DEF_HTCP_SEND_WINDOW)) {  /* number of bytes to be sent */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
#endif
     }
     if (   (ADSL_CONN1_G->adsc_lbal_gw_1)
         && (ADSL_CONN1_G->adsc_wtsudp1)
         && (ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set)) {
#ifdef B130314
       bol_lb_timed_out = m_aux_timer_check( ADSL_CONN1_G, ied_src_fu_lbal, NULL );
#endif
       memset( &dsl_pd_work.dsc_aux_cf1.dsc_cid, 0, sizeof(struct dsd_cid) );
       dsl_pd_work.dsc_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_lbal;
       bol_lb_timed_out = m_aux_timer_check( ADSL_CONN1_G, &dsl_pd_work.dsc_aux_cf1.dsc_cid );
       if (bol_lb_timed_out) {
         ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set = FALSE;
         bol_cont = TRUE;                   /* more to do              */
       }
     }
//   if ((bol_cont == FALSE) || (bou_conn_end))   /* nothing more to do      */
//     boc_st_act = FALSE;                  /* util-thread not active  */
     /* check if data to send to server                                */
#ifdef B090909
     if (ADSL_CONN1_G->iec_st_ses == ied_ses_error_conn) {  /* status server error */
       if (   (ADSL_CONN1_G->adsc_radqu == NULL)  /* no more radius processing */
           && (ADSL_CONN1_G->achc_reason_end == NULL)) {    /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "error connect to Server";
       }
       bol_cont = TRUE;                     /* more to do              */
     }
#endif
#ifdef B130314
     /* check if a signal is set, which can be processed                 */
     if (   (bol_cont == FALSE)             /* nothing more to do      */
         && (ADSL_CONN1_G->adsc_server_conf_1)  /* with server           */
         && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)) {  /* with server-data-hook */
// to-do 21.02.12 KB check also signal of HOB-WSP-AT3
       vpl_w1 = m_check_sdh_signal( &dsl_pd_work.dsc_aux_cf1 );
       if (vpl_w1) bol_cont = TRUE;         /* signal found            */
#ifdef DEBUG_LOOP_PROC_DATA_01
       if (vpl_w1) {
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
       }
#endif
     }
#endif
     if (   (bol_cont == FALSE)             /* nothing more to do      */
         && (ADSL_CONN1_G->boc_signal_set)) {  /* signal for component set */
       adsl_cid_signal = m_check_sdh_signal( &dsl_pd_work.dsc_aux_cf1 );
       if (adsl_cid_signal) {               /* need to process signal  */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
     }
#ifndef TRY_120306_01                       /* flow-control send       */
#ifdef TRY_120214_01                        /* stopps when connect successful */
     if (ADSL_CONN1_G->iec_st_ses != iel_st_ses) {  /* status server has changed */
       bol_cont = TRUE;                     /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
       iml_cont_line = __LINE__;            /* line where bol_cont is set */
#endif
     }
#endif
     if (   (bol_cont == FALSE)             /* nothing more to do      */
         && (bol_suspend_act == FALSE)) {   /* do not suspend now      */
       ADSL_CONN1_G->boc_st_act = FALSE;    /* util-thread not active  */
     }
#else
     while (bol_cont == FALSE) {            /* nothing to do           */
       if (ADSL_CONN1_G->iec_st_ses != iel_st_ses) {  /* status server has changed */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;
       }
#ifndef HL_UNIX
       if (   (ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send)  /* activate connection after send */
           && (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act() == FALSE)) {  /* check flow client */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;                             /* continue                */
       }
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           && (ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send)  /* activate connection after send */
           && (ADSL_CONN1_G->dcl_tcp_r_s.m_check_send_act() == FALSE)) {  /* check flow server */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;                             /* continue                */
       }
#else
       if (   (ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send)  /* activate connection after send */
           && (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL)) {  /* check flow client */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;                             /* continue                */
       }
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           && (ADSL_CONN1_G->dsc_tc1_server.boc_act_conn_send)  /* activate connection after send */
           && (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send == NULL)) {  /* check flow client */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;                             /* continue                */
       }
#endif
#ifdef B141124
#ifndef B140819
/**
   possible other solution:
   do in critical section,
   but call subroutines with parameter; already in critical section.
   03.07.14  KB
*/
     if (bol_end_server) {                  /* process end server      */
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* without server connection */
           || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)) {  /* server connection ended */
         if (   (iml_no_sdh > 0)            /* number of SDHs          */
             && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
           dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server   */
           bol_end_conn_s_1 = TRUE;         /* process end server      */
#ifndef HL_UNIX
           if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
// to-do 17.11.13 KB - better solution with post like in Unix
             dcl_tcp_r_s.close1();          /* close connection server */
             dcl_tcp_r_s.m_wait_cleanup();  /* wait for cleanup server */
             ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
           }
#else
           if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
             m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_server, adsp_hco_wothr );  /* close connection server */
             ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
           }
#endif
           ADSL_CONN1_G->achc_reason_end = NULL;  /* reason end session */
           ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
           bol_cont = TRUE;                 /* more to do              */
           bol_proc_sdh = TRUE;             /* process server-data-hook */
#ifdef DEBUG_LOOP_PROC_DATA_01
           iml_cont_line = __LINE__;        /* line where bol_cont is set */
#endif
           break;
         }
         ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
       } else {                             /* wait till end server    */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;
       }
     }
#endif
#endif
#ifndef B141124
     if (bol_end_server) {                  /* process end server      */
       bol_cont = TRUE;                     /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
       iml_cont_line = __LINE__;            /* line where bol_cont is set */
#endif
       break;
     }
#endif
#ifdef XYZ1
       if (bol_block_send_client) {         /* send to client blocked  */
         if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
           bol_cont = TRUE;                 /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
           iml_cont_line = __LINE__;        /* line where bol_cont is set */
#endif
           break;                           /* continue                */
         }
         ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = TRUE;  /* activate connection after send */
       }
       if (bol_block_send_server) {         /* send to server blocked  */
         if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
           if (ADSL_CONN1_G->dcl_tcp_r_s.m_check_send_act() == FALSE) {  /* check flow server */
             bol_cont = TRUE;               /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
             iml_cont_line = __LINE__;      /* line where bol_cont is set */
#endif
             break;                         /* continue                */
           }
           ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send = TRUE;  /* activate connection after send */
         }
       }
#endif
       if (bol_suspend_act) break;          /* do suspend now          */
       ADSL_CONN1_G->boc_st_act = FALSE;    /* util-thread not active  */
       break;
     }
#endif
#ifndef HL_UNIX
     LeaveCriticalSection( &d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_leave()",
                     __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
#endif
#ifdef TRACEHLD
     *iptrace_act = 0;
#endif
#ifdef TRACE_TCP_FLOW_01
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() called ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_servcotype=%d dsl_pd_work.boc_eof_server=%d.",
                     __LINE__, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_servcotype, dsl_pd_work.boc_eof_server );
#endif
#ifdef B140819
#ifndef B140703
/**
   possible other solution:
   do in critical section,
   but call subroutines with parameter; already in critical section.
   03.07.14  KB
*/
     if (bol_end_server) {                  /* process end server      */
       if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* without server connection */
           || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
           || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)) {  /* server connection ended */
         if (   (iml_no_sdh > 0)            /* number of SDHs          */
             && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
           dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server   */
           bol_end_conn_s_1 = TRUE;         /* process end server      */
#ifndef HL_UNIX
           if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
// to-do 17.11.13 KB - better solution with post like in Unix
             dcl_tcp_r_s.close1();          /* close connection server */
             dcl_tcp_r_s.m_wait_cleanup();  /* wait for cleanup server */
             ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
           }
#else
           if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
             m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_server, adsp_hco_wothr );  /* close connection server */
             ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
           }
#endif
           ADSL_CONN1_G->achc_reason_end = NULL;  /* reason end session */
           bol_cont = TRUE;                 /* more to do              */
           bol_proc_sdh = TRUE;             /* process server-data-hook */
#ifdef DEBUG_LOOP_PROC_DATA_01
           iml_cont_line = __LINE__;        /* line where bol_cont is set */
#endif
         }
         ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
       } else {                             /* wait till end server    */
         bol_cont = TRUE;                   /* more to do              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
     }
#endif
#endif
//   if (bou_conn_end) this->close1();
#ifdef TRACEHL1
#ifdef B080407
     if (bol_cont == FALSE) {
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d end time-sec=%d",
                       __LINE__, m_get_time() );
     }
#endif
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d time-sec=%d bol_cont=%d ->boc_st_act=%d adsl_sdhc1_client=%p ADSL_CONN1_G->iec_st_ses=%d ADSL_CONN1_G->iec_st_cls=%d ADSL_CONN1_G->adsc_sdhc1_c1=%p.",
                     __LINE__, m_get_time(), bol_cont, ADSL_CONN1_G->boc_st_act, adsl_sdhc1_client, ADSL_CONN1_G->iec_st_ses, ADSL_CONN1_G->iec_st_cls, ADSL_CONN1_G->adsc_sdhc1_c1 );
#endif
#ifdef TRACEHLD
     *iptrace_act = 0X18;
#endif
#ifdef TRACEHLA
     m_clconn1_last_action( this, 11 );     /* last action             */
     if (bol_cont == FALSE) {               /* nothing to do           */
       m_clconn1_last_action( this, 102 );  /* last action             */
       if (bol_suspend_act == FALSE) return;  /* do not activate work thread after suspend */
       clworkth::act_thread( this );        /* activate same connection again */
       return;
     }
     if (adsl_sdhc1_client) {                 /* data received from client */
       m_clconn1_last_action( this, 110 );    /* last action             */
     }
     if (dcl_tcp_r_c.getstr()) {
       m_clconn1_last_action( this, 111 );    /* last action             */
     }
     if (dcl_tcp_r_c.get_error_rec()) {
       m_clconn1_last_action( this, 112 );    /* last action             */
     }
     if (il_recbuf_c2) {
       m_clconn1_last_action( this, 113 );    /* last action             */
     }
     if (il_recbuf_c1) {
       m_clconn1_last_action( this, 114 );    /* last action             */
     }
#endif
#ifdef FORKEDIT
     }
#endif
#ifdef TRACE_HL_SESS_01
     m_clconn1_last_action( this, 11 );     /* last action             */
#endif  /* TRACE_HL_SESS_01 */
     if (bol_cont == FALSE) {               /* nothing to do           */
#ifdef DEBUG_150218_01                      /* problem gather          */
       m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main return 01", __LINE__ );
#endif
//#ifdef WSP_TRACE_TRY02                    /* WSP-Trace               */
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNEPDLEA", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         achl_w1 = achl_w2 = "";
#ifndef HL_UNIX
         if (ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send) {  /* activate connection after send */
           achl_w1 = " + act conn after send to client";
         }
         if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
             && (ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send)) {  /* do activate connection after send */
           achl_w2 = " + act conn after send to server";
         }
#else
         if (ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send) {  /* activate connection after send */
           achl_w1 = " + act conn after send to client";
         }
         if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
             && (ADSL_CONN1_G->dsc_tc1_server.boc_act_conn_send)) {  /* do activate connection after send */
           achl_w2 = " + act conn after send to server";
         }
#endif
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "SNO=%08d leaving m_proc_data()%s%s",
                         ADSL_CONN1_G->dsc_co_sort.imc_sno, achl_w1, achl_w2 );
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
//#endif
#ifdef TRACE_HL_SESS_01
       m_clconn1_last_action( this, 102 );  /* last action             */
#endif  /* TRACE_HL_SESS_01 */
#ifdef B050224
       m_garb_coll_1( ADSL_CONN1_G );       /* do garbage collect      */
#endif
#ifdef DEBUG_100903_01
       {
         int imh3, imh4;
     int        imh_gather;                   /* count gather            */
     int        imh_data;                     /* count data              */
         char *achh1;
         struct dsd_sdh_control_1 *adsl_sdhc1_h1;
         struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
         adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
         while (adsl_sdhc1_h1) {
           if (adsl_sdhc1_h1->inc_function == DEF_IFUNC_FROMSERVER) {
             achh1 = "invalid";
             switch (adsl_sdhc1_h1->inc_function) {
               case DEF_IFUNC_FROMSERVER:
                 achl1 = "FROMSERVER";
                 break;
               case DEF_IFUNC_TOSERVER:
                 achl1 = "TOSERVER";
                 break;
             }
             adsl_gai1_h1 = adsl_sdhc1_h1->adsc_gather_i_1_i;  /* get chain to send */
             imh_gather = 0;                        /* clear count gather      */
             imh_data = 0;                          /* clear count data        */
             while (adsl_gai1_h1) {                 /* loop over data to send  */
               imh_gather++;                        /* increment count gather  */
               imh3 = adsl_gai1_h1->achc_ginp_end - adsl_gai1_h1->achc_ginp_cur;
        //     if (   (iml3 < 0)
        //         || (iml3 > + LEN_TCP_RECV)) {
        //     }
               imh4 = 0X01000000;
               if (   (adsl_gai1_h1->achc_ginp_cur > (char *) adsl_sdhc1_h1)
                   && (adsl_gai1_h1->achc_ginp_cur < ((char *) adsl_sdhc1_h1 + LEN_TCP_RECV))) {
                 imh4 = ((char *) adsl_sdhc1_h1 + LEN_TCP_RECV) - adsl_gai1_h1->achc_ginp_cur;
               }
               if (   (imh3 < 0)
                   || (imh3 > imh4)) {
                 while (TRUE) {
                   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd28 entry Gather of sdhc1=%p invalid length=%d/0X%X",
                                   __LINE__, adsl_sdhc1_h1, imh3, imh3 );
#ifndef HL_UNIX
                   Sleep( 2000 );
#else
                   sleep( 2 );
#endif
                 }
               }
               imh_data += imh3;
               adsl_gai1_h1 = adsl_gai1_h1->adsc_next;  /* get next in chain     */
             }
             m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd28 sdhc1=%p function=%d/%s position=%d imc_usage_count=%d gather=%d data=%d",
                             __LINE__,
                             adsl_sdhc1_h1, adsl_sdhc1_h1->inc_function, achl1, adsl_sdhc1_h1->inc_position, adsl_sdhc1_h1->imc_usage_count,
                             imh_gather, imh_data );
           }
           adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
         }
       }
#endif
#ifdef DEBUG_111206_01                      /* 06.12.11 KB check how ofter in main loop */
       if (iml_count_loop >= DEBUG_111206_01) {
         m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d before return iml_count_loop=%d.",
                         __LINE__, iml_count_loop );
       }
#endif
#ifdef TRY_160113_01                        /* leave thread after less rounds */
       m_garb_coll_1( ADSL_CONN1_G );       /* do garbage collect      */
#endif
       if (bol_suspend_act == FALSE) return;  /* do not activate work thread after suspend */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data nothing to do - return - act_thread()" );
#endif
       m_act_thread_2( ADSL_CONN1_G );      /* activate work-thread    */
       return;
     }
   }
#ifndef B141124
   while (bol_end_server) {                 /* process end server      */
     if (dsl_pd_work.inc_count_proc_end < 0) break;  /* process end of connection */
     if (dsl_pd_work.inc_count_proc_end == 2) break;  /* process end of connection */
     if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* without server connection */
         || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
         || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)) {  /* server connection ended */
       if (   (iml_no_sdh > 0)              /* number of SDHs          */
           && (ADSL_CONN1_G->adsc_sdhc1_s1 == NULL)) {  /* no data received from server */
         dsl_pd_work.boc_eof_server = TRUE;  /* End-of-File Server   */
         bol_end_conn_s_1 = TRUE;           /* process end server      */
#ifndef HL_UNIX
         if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
// to-do 17.11.13 KB - better solution with post like in Unix
           dcl_tcp_r_s.close1();            /* close connection server */
           dcl_tcp_r_s.m_wait_cleanup();    /* wait for cleanup server */
           ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
         }
#else
         if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
           m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_server, adsp_hco_wothr );  /* close connection server */
           ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
         }
#endif
         ADSL_CONN1_G->achc_reason_end = NULL;  /* reason end session  */
         bol_proc_sdh = TRUE;               /* process server-data-hook */
       }
       ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
     }
     break;
   }
#endif
   if (bol_end_conn_s_2) {                  /* process end server      */
#ifdef B100824
     free( ADSL_CONN1_G->adsc_server_conf_1 );  /* free this server entry */
     ADSL_CONN1_G->adsc_server_conf_1 = ADSL_CONN1_G->adsc_gate1->adsc_server_conf_1;
#endif
#ifdef B101208
#ifndef B100824
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old entry */
       ADSL_CONN1_G->adsc_server_conf_1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous;  /* configuration server previous */
       free( adsl_server_conf_1_w1 );       /* free old server entry   */
     }
#endif
#else
     if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old entry */
#ifdef B140525
       ADSL_CONN1_G->adsc_server_conf_1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous;  /* configuration server previous */
#endif
#ifndef B140525
       ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
#endif
       free( adsl_server_conf_1_w1 );       /* free old server entry   */
     }
#endif
#ifdef B120704
#ifndef HL_UNIX
     dcl_tcp_r_s.close1();                  /* close connection server */
#else
#endif
#endif
#ifndef B120704
#ifndef HL_UNIX
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
// to-do 17.11.13 KB - better solution with post like in Unix
       dcl_tcp_r_s.close1();                /* close connection server */
#ifndef B131117
       dcl_tcp_r_s.m_wait_cleanup();        /* wait for cleanup server */
#endif
       ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
     }
#else
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifdef B131117
       ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_shutdown();  /* close connection server */
//     ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not more connected */
#endif
#ifndef B131117
       m_tc1_close_1( &ADSL_CONN1_G->dsc_tc1_server, adsp_hco_wothr );  /* close connection server */
#endif
       ADSL_CONN1_G->iec_servcotype = ied_servcotype_none;  /* no server connection */
     }
#endif
#endif
     if (ADSL_CONN1_G->adsc_sdhc1_s1) {     /* data received from server */
       m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s1 );  /* free storage    */
       ADSL_CONN1_G->adsc_sdhc1_s1 = NULL;  /* clear data received from server */
     }
     if (ADSL_CONN1_G->adsc_sdhc1_s2) {     /* second buffer from server */
       m_proc_free( ADSL_CONN1_G->adsc_sdhc1_s2 );  /* free storage    */
       ADSL_CONN1_G->adsc_sdhc1_s2 = NULL;  /* clear second buffer from server */
     }
//   ADSL_CONN1_G->iec_st_ses = ied_ses_prep_server;        /* stat server             */
#ifndef B071113
//   if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic) {
     dsl_pd_work.boc_eof_server = FALSE;    /* no more End-of-File Server */
#ifndef TJ_B171006
     ADSL_CONN1_G->chrc_server_error[0] = 0; /* reset server error */
#endif
//   }
#endif
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd28-2", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   if (adsl_sdhc1_w1) {                     /* data received from server */
/**
     the blocks sdhc1 are chained together,
     but the gather structures are not yet chained together
*/
#ifdef WSP_TRACE_TRY01
     if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNERECS2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
       iml1 = iml2 = 0;                     /* clear counters          */
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* get chain of input      */
       do {                                 /* loop over chain received from server */
         iml1++;                            /* count sdhc1             */
         adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain of gather */
         do {                               /* loop over all gather input */
           iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         } while (adsl_gai1_w1);
         adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w2);
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       iml3 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                       "SNO=%08d processing received from server sdhc1=%p gai1=%p cur=%p + no-sdhc1=%d length-data=%d/0X%X.",
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       adsl_sdhc1_w1, adsl_sdhc1_w1->adsc_gather_i_1_i,
                       adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur,
                       iml1, iml2, iml2 );
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml3;      /* length of text / data   */
       adsl_wt1_w2 = adsl_wt1_w1;           /* last WSP Trace area     */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml3 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       if (   (iml2)
           && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
         iml4 = iml5 = 0;                   /* clear counters          */
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* get chain of input      */
         do {                               /* loop over all input gather */
           iml4++;                          /* count sdhc1             */
           adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain of gather */
           iml6 = 0;                        /* reset count gather      */
           do {                             /* output gather           */
             iml6++;                        /* increment count gather  */
             iml7 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* count length input */
             if (iml7 > 0) {                /* data in this gather     */
               if ((achl_w1 + sizeof(struct dsd_wsp_trace_record) + 128) >= achl_w2) {
                 adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
                 memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
                 adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
                 adsl_wt1_w2 = adsl_wt1_w3;  /* this is current area   */
                 achl_w1 = (char *) (adsl_wt1_w2 + 1);
                 achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
               }
               memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
               iml8 = sprintf( (char *) (ADSL_WTR_G2 + 1),
                               "+ sdhc1-no=%d gather-no=%d gai1=%p disp=0X%X addr=%p length=%d/0X%X.",
                               iml4, iml6, adsl_gai1_w1, iml5, adsl_gai1_w1->achc_ginp_cur, iml7, iml7 );
               ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed  */
               ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
               ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
               adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
               adsl_wtr_w1 = ADSL_WTR_G2;   /* this is last in chain now */
               iml5 += iml7;                /* increment displacement  */
               achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
               achl_w3 = adsl_gai1_w1->achc_ginp_cur;  /* here start binary data */
               bol1 = FALSE;                /* reset more flag         */
               do {                         /* loop for output of data */
                 iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
                 if (iml8 <= 0) {           /* we need another area    */
                   adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
                   memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
                   adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
                   adsl_wt1_w2 = adsl_wt1_w3;  /* this is current area */
                   achl_w1 = (char *) (adsl_wt1_w2 + 1);
                   achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
                   iml8 = achl_w2 - (achl_w1 + sizeof(struct dsd_wsp_trace_record));
                 }
                 if (iml8 > iml7) iml8 = iml7;
                 memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
                 ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
                 achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
                 ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
                 adsl_wtr_w1->boc_more = bol1;  /* more data to follow */
                 bol1 = TRUE;               /* set more flag           */
                 adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
                 adsl_wtr_w1 = ADSL_WTR_G2;  /* this is last in chain now */
                 memcpy( achl_w4, achl_w3, iml8 );
                 achl_w3 += iml8;
                 ADSL_WTR_G2->imc_length = iml8;  /* length of text / data */
                 achl_w1 = (char *) (((long long int) (achl_w1 + sizeof(struct dsd_wsp_trace_record) + iml8 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
                 iml7 -= iml8;
               } while (iml7 > 0);
             }
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           } while (adsl_gai1_w1);
           adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next sdhc1 */
         } while (adsl_sdhc1_w2);
       }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#endif
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[16];
       sprintf( chrh_msg, "main-l%05d", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_w1, chrh_msg );
     }
#endif
#ifdef TRACEHL_T_050130
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d if (adsl_sdhc1_w1) 1 - adsc_sdhc1_chain=%p",
                     __LINE__, adsc_sdhc1_chain );
#endif
#ifdef TRACEHL1
#ifdef B081003
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d input server data len=%d first-char=%02X",
                     __LINE__,
                     ADSL_GATHER_I_1_W->achc_ginp_end - ADSL_GATHER_I_1_W->achc_ginp_cur,
                     (unsigned char) *ADSL_GATHER_I_1_W->achc_ginp_cur );
#undef ADSL_GATHER_I_1_W
#endif
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d input server data len=%d++ first-char=%02X",
                     __LINE__,
                     adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_end - adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur,
                     (unsigned char) *adsl_sdhc1_w1->adsc_gather_i_1_i->achc_ginp_cur );
#endif
     ADSL_CONN1_G->inc_c_ns_rece_s++;       /* count receive server    */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get chain of input      */
#ifndef B120328
     iml1 = 0;                              /* data from server        */
     if (ADSL_CONN1_G->adsc_csssl_oper_1) {  /* process Client-Side-SSL */
       iml1 = -1;                           /* thru SSL first          */
#ifdef B140525
     } else if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server */
                || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
       iml1 = MAX_SERVER_DATA_HOOK;         /* position send to client */
#ifdef FORKEDIT
//   }
#endif
#endif
#ifndef B140525
     } else if (iml_no_sdh == 0) {          /* no server-data-hook     */
       iml1 = MAX_SERVER_DATA_HOOK;         /* position send to client */
#endif
#ifdef TRACEHL_STOR_USAGE
     } else {
       char chrh_msg[64];
       sprintf( chrh_msg, "main-l%05d else", __LINE__ );
       do {
         m_proc_trac_1( adsl_sdhc1_w2, chrh_msg );
         adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w2);
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* get chain of input      */
#endif
     }
     adsl_gai1_last = NULL;                 /* we have no chain of gather yet */
#endif
     do {                                   /* loop over chain received from server */
#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[16];
         sprintf( chrh_msg, "main-l%05d", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_w2, chrh_msg );
       }
#endif
       adsl_sdhc1_w3 = adsl_sdhc1_w2;       /* save last in chain      */
       adsl_sdhc1_w2->inc_function = DEF_IFUNC_FROMSERVER;  /* function of SDH */
#ifdef B110904
       adsl_sdhc1_w2->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
       adsl_sdhc1_w2->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
#ifdef NOT_YET_100903
       adsl_sdhc1_w2->inc_position = 0;     /* give to first server-data-hook */
#endif
#ifdef B120328
       if (ADSL_CONN1_G->adsc_csssl_oper_1) {  /* process Client-Side-SSL */
         adsl_sdhc1_w2->inc_position = -1;  /* thru SSL first          */
       } else if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server */
                  || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
         adsl_sdhc1_w2->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef TRACEHL_STOR_USAGE
       } else {
         char chrh_msg[64];
         sprintf( chrh_msg, "main-l%05d else", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_w2, chrh_msg );
#endif
       }
#else
       adsl_sdhc1_w2->inc_position = iml1;  /* set position            */
#endif
       adsl_gai1_w1 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain of gather */
#ifndef B120328
       if (adsl_gai1_last) {                /* we have already chain   */
         adsl_gai1_last->adsc_next = adsl_gai1_w1;  /* append new gather to chain */
       }
#endif
       do {                                 /* loop over all gather input */
         ADSL_CONN1_G->ilc_d_ns_rece_s += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
#ifndef B120328
         adsl_gai1_last = adsl_gai1_w1;     /* save last in chain      */
#endif
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       } while (adsl_gai1_w1);
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w2);
     /* input from server first in chain                               */
#ifdef B120328
     if (   (ADSL_CONN1_G->adsc_sdhc1_chain)
         && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_function == DEF_IFUNC_FROMSERVER)
         && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_position == adsl_sdhc1_w1->inc_position)) {
#ifdef FORKEDIT
     }
#endif
#else
     if (   (ADSL_CONN1_G->adsc_sdhc1_chain)
         && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_function == DEF_IFUNC_FROMSERVER)
         && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_position == iml1)) {
#endif
#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[64];
         sprintf( chrh_msg, "main-l%05d put-chain-start", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_w1, chrh_msg );
       }
#endif
/**
   question:
   are there sdhc1 in the chain
   where adsc_gather_i_1_i == NULL ???
   if YES, this logic needs to get changed.
   ---
   other possible improvement:
   where adsc_gather_i_1_i == NULL in the sdhc1 chain before,
   set to new gather
   21.02.15  KB
*/
       /* search where to put in chain                                 */
       adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;
       adsl_sdhc1_last_1 = NULL;            /* last element this kind  */
#ifdef TRY_150221_01                        /* problem gather lost     */
       adsl_gai1_cur = NULL;
#endif
       while (adsl_sdhc1_cur_1) {
#ifdef B120328
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             || (adsl_sdhc1_cur_1->inc_position != adsl_sdhc1_w1->inc_position)) {
           break;
         }
#else
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             || (adsl_sdhc1_cur_1->inc_position != iml1)) {
           break;
         }
#endif
#ifdef B110904
         adsl_sdhc1_cur_1->boc_ready_t_p = TRUE;  /* ready to process now */
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i == NULL) {
           m_hlnew_printf( HLOG_TRACE1, "l%05d m_proc_data() DEBUG_150218_01 adsc_gather_i_1_i == NULL ADSL_CONN1_G->adsc_sdhc1_chain=%p adsl_sdhc1_cur_1=%p.",
                           __LINE__, ADSL_CONN1_G->adsc_sdhc1_chain, adsl_sdhc1_cur_1 );
         }
#endif
#ifdef TRY_150221_01                        /* problem gather lost     */
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) {
           adsl_gai1_cur = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* save last gather */
         }
#endif
         adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
         adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
       }
       adsl_sdhc1_w3->adsc_next = adsl_sdhc1_cur_1;  /* insert at this point */
       if (adsl_sdhc1_last_1 == NULL) {     /* insert at start of chain */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
       }
       /* chain of gather input                                        */
#ifndef TRY_150221_01                       /* problem gather lost     */
       adsl_gai1_cur = ADSL_CONN1_G->adsc_sdhc1_chain->adsc_gather_i_1_i;
#endif
       adsl_gai1_last = NULL;               /* clear last element      */
       while (adsl_gai1_cur) {
         adsl_gai1_last = adsl_gai1_cur;
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
       }
       if (adsl_gai1_last == NULL) {        /* insert at start of chain */
         ADSL_CONN1_G->adsc_sdhc1_chain->adsc_gather_i_1_i = adsl_sdhc1_w1->adsc_gather_i_1_i;
       } else {                             /* insert middle in chain  */
         adsl_gai1_last->adsc_next = adsl_sdhc1_w1->adsc_gather_i_1_i;
       }
#ifdef TRY_150221_01                        /* problem gather lost     */
#ifdef TRY_150226_01                        /* problem loop gather     */
       if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#endif
       /* check if adsc_gather_i_1_i == NULL in the middle             */
       while (TRUE) {
         adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;
         adsl_sdhc1_w2 = NULL;              /* last element with gather */
         adsl_sdhc1_w3 = NULL;              /* last element no gather */
         while (TRUE) {
           if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) {
             if (adsl_sdhc1_w3) {           /* last element no gather */
               do {
                 adsl_sdhc1_w3->adsc_gather_i_1_i = adsl_sdhc1_cur_1->adsc_gather_i_1_i;
                 adsl_sdhc1_w3 = adsl_sdhc1_w3->adsc_next;  /* get next in chain */
               } while (adsl_sdhc1_w3 != adsl_sdhc1_cur_1);
               if (adsl_sdhc1_w2) {         /* last element with gather */
                 adsl_gai1_cur = adsl_sdhc1_w2->adsc_gather_i_1_i;
                 if (adsl_gai1_cur->adsc_next == NULL) {
/* to-do 21.02.15 KB - why gather in loop ??? */
                   if (adsl_gai1_cur == adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;
                   adsl_sdhc1_w2->adsc_gather_i_1_i->adsc_next = adsl_sdhc1_cur_1->adsc_gather_i_1_i;
                 } else {
                   do {
/* to-do 21.02.15 KB - why gather in loop ??? */
                     if (adsl_gai1_cur == adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;
                     adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
/* to-do 21.02.15 KB - why gather in loop ??? */
                     if (adsl_gai1_cur == adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;
                   } while (adsl_gai1_cur->adsc_next);
                   adsl_gai1_cur->adsc_next = adsl_sdhc1_cur_1->adsc_gather_i_1_i;
                 }
               }
               break;
             }
             adsl_sdhc1_w2 = adsl_sdhc1_cur_1;  /* last element with gather */
           } else {                         /* no gather in this sdhc1 */
//           if (adsl_sdhc1_w2) {           /* element with gather before */
               if (adsl_sdhc1_w3 == NULL) {         /* last element no gather */
                 adsl_sdhc1_w3 = adsl_sdhc1_cur_1;  /* last element no gather */
               }
//           }
           }
           if (adsl_sdhc1_cur_1 == adsl_sdhc1_w1) break;  /* last element reached */
           adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
         }
         if (adsl_sdhc1_cur_1 == adsl_sdhc1_w1) break;  /* last element reached */
       }
#ifdef TRY_150226_01                        /* problem loop gather     */
       }
#endif
#endif
     } else {                               /* insert at start of chain */
#ifdef B080426
       adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;
#endif
#ifndef B080426
       adsl_sdhc1_w3->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;
#endif
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_w1;
#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[64];
         sprintf( chrh_msg, "main-l%05d put-chain-middle", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_w1, chrh_msg );
       }
#endif
     }
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_proc_data() input from server", __LINE__ );
#endif
     bol_proc_sdh = TRUE;                   /* process server-data-hook */
#ifdef TRACEHL_T_050130
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data() if (adsl_sdhc1_w1) 2 - adsc_sdhc1_chain=%p",
                     adsc_sdhc1_chain );
#endif
   }
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd28-3", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACEHLD
   *iptrace_act = 0;
#endif
   /* all connections active                                           */
#ifdef B140525
#ifdef B131119
   if (   (dsl_pd_work.boc_eof_client == FALSE)
       && (dsl_pd_work.boc_eof_server == FALSE)) {
#ifdef FORKEDIT
   }
#endif
#else
#ifdef B140120
   if (   (dsl_pd_work.boc_eof_client == FALSE)
       && (   (dsl_pd_work.boc_eof_server == FALSE))
           || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh != 0)) {  /* with server-data-hook */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (dsl_pd_work.boc_eof_client == FALSE)
       && (   (dsl_pd_work.boc_eof_server == FALSE))
           || (   (ADSL_CONN1_G->adsc_server_conf_1)  /* with server configuration */
               && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh != 0))) {  /* with server-data-hook */
#ifdef FORKEDIT
   }
#endif
#endif
#endif
#endif
#ifndef B140525
#ifdef WAS_BEFORE_1501
   if (   (dsl_pd_work.boc_eof_client == FALSE)
       && (   (dsl_pd_work.boc_eof_server == FALSE))
           || (iml_no_sdh > 0)) {           /* with SDH                */
#ifdef FORKEDIT
   }
#endif
#endif
   if (   (dsl_pd_work.boc_eof_client == FALSE)
       && (   (dsl_pd_work.boc_eof_server == FALSE)
           || (iml_no_sdh > 0))) {          /* with SDH                */
#endif
#ifdef TRACEHL1
#ifdef B100813
     if (bol_s_act) {                       /* server activate         */
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data check server data (bol_s_act TRUE) dsl_gather_i_1_i.achc_ginp_cur=%p dsl_gather_i_1_i.achc_ginp_end=%p",
                       dsl_gather_i_1_i.achc_ginp_cur, dsl_gather_i_1_i.achc_ginp_end );
     }
#endif
#endif
     if (bol_s_act) {                       /* server activate         */
#ifdef TRACEHL_101209
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_proc_data() bol_s_act set ADSL_CONN1_G->iec_servcotype=%d.",
                       __LINE__, ADSL_CONN1_G->iec_servcotype );
#endif
       if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNWCORSE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed       */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length            /* length of text / data   */
           = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                      "continue receive from server" );
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       switch (ADSL_CONN1_G->iec_servcotype) {
         case ied_servcotype_normal_tcp:    /* normal TCP              */
#ifndef HL_UNIX
           if (dcl_tcp_r_s.get_error_rec()) break;
#ifdef TRACEHL_101209
           m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_proc_data() before dcl_tcp_r_s.newreceive().",
                           __LINE__ );
#endif
           dcl_tcp_r_s.newreceive();
#else
           if (ADSL_CONN1_G->dsc_tc1_server.boc_connected == FALSE) break;  /* TCP session is not connected */
           ADSL_CONN1_G->dsc_tc1_server.dsc_tcpco1_1.m_recv();  /* start receiving from server again */
#endif
           break;
#ifdef D_INCL_HOB_TUN
         case ied_servcotype_htun:          /* HOB-TUN                 */
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (ADSL_CONN1_G->adsc_auxf_1_htun + 1))
#ifndef NEW_HOB_TUN_1103
           m_htun_sess_canrecv( ADSL_CONN1_G->adsc_ineta_raws_1->dsc_htun_h );
#else
           m_htun_sess_canrecv( ADSL_CONN1_G->dsc_htun_h );
#endif
//#undef ADSL_INETA_RAWS_1_G
           break;
#endif
#ifdef B110904
         case ied_servcotype_l2tp:          /* L2TP                    */
           m_l2tp_canrecv( &ADSL_CONN1_G->dsc_l2tp_session );
           break;
#endif
       }
     }
     if (adsl_sdhc1_client) {               /* data received from client */
#ifndef HL_UNIX
       if (   (bol_c_act)                   /* client activate         */
           && (dcl_tcp_r_c.get_error_rec() == FALSE)) {
#ifdef FORKEDIT
       }
#endif
#else
       if (   (bol_c_act)                   /* client activate         */
           && (ADSL_CONN1_G->dsc_tc1_client.boc_connected)) {  /* TCP session is connected */
#endif
         if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
           adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
           adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
           adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
           memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNWCORCL", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
           adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
           adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id         */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
           ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed     */
           ADSL_WTR_G1->achc_content        /* content of text / data  */
             = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
           ADSL_WTR_G1->imc_length          /* length of text / data   */
             = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                        "continue receive from client" );
           adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
           m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
         }
#ifdef TRACEHLD
         *iptrace_act = 0X22;
#endif
#ifndef HL_UNIX
         dcl_tcp_r_c.newreceive();
#else
         ADSL_CONN1_G->dsc_tc1_client.dsc_tcpco1_1.m_recv();  /* start receiving from client again */
#endif
#ifdef TRACEHLD
         *iptrace_act = 0;
#endif
       }
     }
   } else {                                 /* connection closed       */
     if (adsl_sdhc1_client) {               /* data received from client */
#ifdef TRACEHL_T_050131
       m_hlnew_printf( HLOG_XYZ1, "proc_free 4 if (adsl_sdhc1_client)" );
       m_chain_sdhc1();                     /* display chain           */
#endif
       m_proc_free( adsl_sdhc1_client );    /* free memory area        */
       adsl_sdhc1_client = NULL;            /* no more buffer available */
     }
   }
   if (adsl_sdhc1_client == NULL) {
#ifdef WAS_BEFORE_1501
     if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal) {  /* status client normal processing */
       goto pcopd32;                        /* process SSL data        */
     }
#endif
     if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_normal)  /* status client normal processing */
         || (ADSL_CONN1_G->iec_st_cls == ied_cls_closed)) {  /* client connection closed */
       goto pcopd32;                        /* process SSL data        */
     }
#ifdef HL_UNIX
     if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_rec_close)  /* received close */
         && (ADSL_CONN1_G->dsc_hlse03s.inc_func != DEF_IFUNC_START)) {  /* not start mode */
       goto pcopd32;                        /* process SSL data        */
     }
#ifndef B121121
     if (ADSL_CONN1_G->iec_st_cls == ied_cls_set_entropy) {  /* set entropy */
       goto pcopd32;                        /* process SSL data        */
     }
#endif
#endif
#ifdef B100408X
     if (iec_st_cls == ied_cls_normal) {    /* status client normal processing */
       goto pcopd32;                        /* process SSL data        */
     }
#endif
     if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal_http) {  /* process normal HTTP */
       goto p_http_00;                      /* process HTTP            */
     }
#ifndef B130602
     if (dsl_pd_work.boc_abend) {           /* process end session     */
       dsl_pd_work.inc_count_proc_end = 2;  /* process end of connection */
       goto pcopd80;                        /* data processed          */
     }
#endif
     goto pcopd20;                          /* loop to process data    */
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd28-4", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   if (ADSL_CONN1_G->adsc_sdhc1_frcl == NULL) {  /* chain of buffers from client (SSL encrypted) */
     ADSL_CONN1_G->adsc_sdhc1_frcl = adsl_sdhc1_client;  /* this is new chain */
   } else {                                 /* append to chain         */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_frcl;  /* get chain      */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get first gather */
     while (adsl_sdhc1_w1->adsc_next) {     /* loop over all buffers   */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1->adsc_next = adsl_sdhc1_client;  /* append to chain */
#ifdef DEBUG_111205_01                      /* because of insure++     */
     adsl_sdhc1_w1 = NULL;
#endif
     while (adsl_gai1_w1->adsc_next) {      /* loop over all buffers   */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     adsl_gai1_w1->adsc_next = adsl_sdhc1_client->adsc_gather_i_1_i;  /* append new gather structures */
   }
// inserted 04.10.09 KB
   adsl_sdhc1_client = NULL;                /* no more buffer available */
#ifdef B120820
   if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal) {  /* status client normal processing */
     goto pcopd32;                          /* process SSL data        */
   }
#else
#ifndef HL_UNIX
   if (ADSL_CONN1_G->iec_st_cls == ied_cls_normal) {  /* status client normal processing */
     goto pcopd32;                          /* process SSL data        */
   }
#else
   if (   (ADSL_CONN1_G->iec_st_cls == ied_cls_normal)  /* status client normal processing */
       || (ADSL_CONN1_G->iec_st_cls == ied_cls_rec_close)) {   /* received close */
     goto pcopd32;                          /* process SSL data        */
   }
#endif
#endif
#ifdef B130226
   achl_to = chrl_work1;                    /* address of target area  */
   iml1 = 0;                                /* state of CR / LF        */
   bol1 = FALSE;                            /* no CR LF CR LF found    */
   adsl_gai1_w1 = ADSL_CONN1_G->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* get first gather */

   p_http_00:                               /* check if HTTP           */
   achl1 = adsl_gai1_w1->achc_ginp_cur;     /* get start of data       */

   p_http_20:                               /* check HTTP data         */
   if (achl1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of this gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_http_00;      /* check if HTTP           */
     goto p_http_40;                        /* end of HTTP data        */
   }
   switch (*achl1) {                        /* check which character   */
     case CHAR_CR:                          /* carriage-return         */
       if ((iml1 & 1) == 0) {               /* no CR before            */
         iml1++;
         break;
       }
       iml1 = 1;                            /* one CR found            */
       break;
     case CHAR_LF:                          /* line-feed               */
       if ((iml1 & 1) == 0) {               /* no CR before            */
         iml1 = 0;                          /* set normal character before */
         break;
       }
       iml1++;                              /* count LF                */
       if (iml1 < 4) break;                 /* not end of HTTP header  */
       bol1 = TRUE;                         /* end of HTTP header found */
       iml1 = 0;                            /* set normal character before */
       break;
     default:                               /* other character         */
       iml1 = 0;                            /* set normal character before */
       break;
   }
   if (achl_to < (chrl_work1 + D_HTTP_MAX_DATA)) {
     *achl_to++ = *achl1;                   /* get this character      */
   }
   achl1++;                                 /* this character processed */
   goto p_http_20;                          /* check HTTP data         */

   p_http_40:                               /* end of HTTP data        */
   if (   (achl_to >= (chrl_work1 + sizeof(ucrs_http_ssl_01)))
       && (!memcmp( chrl_work1, ucrs_http_ssl_01, sizeof(ucrs_http_ssl_01) ))) {
     goto p_http_80;                        /* SSL input found         */
   }
   if (   (bol1)                            /* end HTTP found          */
       && (achl_to >= (chrl_work1 + sizeof(ucrs_http_get_01)))
       && (!memcmp( chrl_work1, ucrs_http_get_01, sizeof(ucrs_http_get_01) ))) {
     goto p_http_44;                        /* do moved permanently    */
   }
   if (   (achl_to >= (chrl_work1 + sizeof(ucrs_http_ssl_01)))
       && (bol1)) {                         /* end HTTP found          */
     m_hlnew_printf( HLOG_WARN1, "HWSPS140W GATE=%(ux)s SNO=%08d INETA=%s input <permanently-moved-port> invalid data",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "input <permanently-moved-port> invalid data";
     }
#ifndef HL_UNIX
     this->close1( &dsl_pd_work );          /* close session           */
#else
     m_conn_close( &dsl_pd_work );          /* close session           */
#endif
     return;                                /* all done                */
   }
   if (achl_to < (chrl_work1 + D_HTTP_MAX_DATA)) goto pcopd20;  /* loop to process data */
   /* input is too long                                                */
   m_hlnew_printf( HLOG_WARN1, "HWSPS141W GATE=%(ux)s SNO=%08d INETA=%s input <permanently-moved-port> too long",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "input <permanently-moved-port> too long";
   }
#ifndef HL_UNIX
   this->close1( &dsl_pd_work );            /* close session           */
#else
   m_conn_close( &dsl_pd_work );            /* close session           */
#endif
   return;                                  /* all done                */

   p_http_44:                               /* do moved permanently    */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d p_http_44", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   /* get a block of memory for send data                              */
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get first in chain */
#ifndef B100318
   if (adsl_sdhc1_w1) {                     /* something received      */
#endif
   ADSL_CONN1_G->adsc_sdhc1_chain = NULL;   /* no blocks in chain      */
   adsl_sdhc1_cur_1 = adsl_sdhc1_w1->adsc_next;  /* get chain to free  */
#ifdef B100318
   adsl_sdhc1_w1->adsc_next = NULL;         /* this is last block now  */
#endif
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     adsl_sdhc1_w2 = adsl_sdhc1_cur_1;      /* save this block         */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w2 );          /* free this block         */
   }
#ifndef B100318
   } else {
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* needs a block for send data */
#ifndef B120210
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
#endif
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_w1->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   }
   adsl_sdhc1_w1->adsc_next = NULL;         /* this is last block now  */
#endif
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
   achl1 = (char *) (adsl_sdhc1_w1 + 1) + dsl_epoch.inc_len_epoch;
   adsl_gai1_w1->achc_ginp_cur = (char *) (adsl_sdhc1_w1 + 1);
   adsl_gai1_w1->achc_ginp_end = achl1;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_02;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_02 + sizeof(ucrs_http_perm_mov_02);
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
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
   achl1 += 16;
   adsl_gai1_w1->achc_ginp_end = achl1;
   do {                                     /* loop for output of digits */
     *(--achl1) = (iml1 % 10) + '0';        /* output one digit        */
     iml1 /= 10;                            /* divide number           */
   } while (iml1 > 0);
   *(--achl1) = ':';                        /* output separator        */
   adsl_gai1_w1->achc_ginp_cur = achl1;
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
   iml1 = (sizeof(ucrs_http_perm_mov_05) - 4) + ADSL_CONN1_G->adsc_gate1->imc_len_permmov_url
            + (adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur)
            + sizeof(ucrs_http_perm_mov_06);
   achl1 += 16 + 16;
   adsl_gai1_w1->achc_ginp_end = achl1;
   do {                                     /* loop for output of digits */
     *(--achl1) = (iml1 % 10) + '0';        /* output one digit        */
     iml1 /= 10;                            /* divide number           */
   } while (iml1 > 0);
   adsl_gai1_w1->achc_ginp_cur = achl1;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = (char *) ucrs_http_perm_mov_05;
   adsl_gai1_w1->achc_ginp_end = (char *) ucrs_http_perm_mov_05 + sizeof(ucrs_http_perm_mov_05);
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
   adsl_gai1_w1->achc_ginp_cur = ADSL_CONN1_G->adsc_gate1->achc_permmov_url;  /* address of URL */
   adsl_gai1_w1->achc_ginp_end
     = ADSL_CONN1_G->adsc_gate1->achc_permmov_url + ADSL_CONN1_G->adsc_gate1->imc_len_permmov_url;
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 - 1;  /* set chain           */
   adsl_gai1_w1--;                          /* next gather structure   */
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
   ADSL_CONN1_G->inc_c_ns_send_c++;         /* count send client       */
   adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
   do {                                     /* loop over data to send to client */
     ADSL_CONN1_G->ilc_d_ns_send_c += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
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
   dcl_tcp_r_c.m_send_gather( adsl_sdhc1_w1, FALSE );
#else
#ifdef B110810
   m_tcp_send_1( ADSL_CONN1_G, FALSE, adsl_sdhc1_w1 );
#endif
   m_send_clse_tcp_1( ADSL_CONN1_G, &ADSL_CONN1_G->dsc_tc1_client, adsl_sdhc1_w1, FALSE );
#endif
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef XYZ1
   ADSL_CONN1_G->adsc_sdhc1_chain = NULL;   /* no blocks in chain      */
#endif
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "session permanently moved";
   }
#ifndef HL_UNIX
   this->close1( &dsl_pd_work );            /* close session           */
#else
   m_conn_close( &dsl_pd_work );            /* close session           */
#endif
   return;                                  /* all done                */

   p_http_80:                               /* SSL input found         */
   ADSL_CONN1_G->iec_st_cls = ied_cls_proc_ssl;  /* process data as SSL input */
#ifdef B100324
   adsl_sdhc1_client = NULL;                /* process no input from client */
#endif
   goto pcopd40;                            /* call SSL subroutine     */
#endif
   p_http_00:                               /* process HTTP            */
   m_pd_plain_http( &dsl_pd_work );
   if (dsl_pd_work.iec_pdwr == ied_pdwr_cont) {  /* continue receiving */
     goto pcopd20;                          /* loop to process data    */
   }
   if (dsl_pd_work.iec_pdwr == ied_pdwr_ssl) {  /* found continue SSL */
     ADSL_CONN1_G->iec_st_cls = ied_cls_proc_ssl;  /* process data as SSL input */
     goto pcopd40;                          /* call SSL subroutine     */
   }
   if (dsl_pd_work.iec_pdwr == ied_pdwr_end_session) {  /* end session */
     ADSL_CONN1_G->iec_st_cls = ied_cls_normal;  /* status client normal processing */
     goto pcopd60;                          /* continue process output */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s error 26.02.13 KB",
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );

   pcopd32:                                 /* process SSL data        */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd32-1", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef B090731
   iml1 = 0;                                /* nothing to send yet     */
   if (adsl_recudp1_w1) {                   /* chain of data received  */
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( adsl_recudp1_w1->umc_ineta,
                               (char *) (adsl_recudp1_w1 + 1), adsl_recudp1_w1->imc_reclen,
                               bol_lb_timed_out,  /* LB timed out      */
                               chrl_work1, sizeof(chrl_work1),
                               &achl1, &iml1 );
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
#ifdef TRACEHLC
       m_check_aclconn1( this, 101 );
#endif
     }
     m_proc_free( adsl_recudp1_w1 );        /* free memory             */
   } else if (   (bol_lb_timed_out)         /* LB timed out            */
              || (bol_lb_proc_se)) {        /* LB process server       */
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( 0, NULL, 0,
                               bol_lb_timed_out,  /* LB timed out      */
                               chrl_work1, sizeof(chrl_work1),
                               &achl1, &iml1 );
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
     }
#ifdef TRACEHLC
     m_check_aclconn1( this, 102 );
#endif
   }
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {
/* UUUU 24.02.05 KB - do not process here - bug */
     ADSL_CONN1_G->boc_st_act = FALSE;      /* util-thread not active  */
#ifdef TRACEHLD
     *iptrace_act = 0X17;
#endif
#ifdef TRACE_HL_SESS_01
     m_clconn1_last_action( this, 12 );     /* last action             */
#endif  /* TRACE_HL_SESS_01 */
     return;
   }
   if (iml1) {                              /* something returned from load-balancing */
/* 10.02.05 KB */
//   ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur = achl1;
//   ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end = achl1 + iu1;
     dsl_gather_i_1_i.achc_ginp_cur = achl1;  /* send data to client   */
     dsl_gather_i_1_i.achc_ginp_end = achl1 + iml1;  /* end of data    */
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = &dsl_gather_i_1_i;
     bol_lb_proc_se = TRUE;                 /* LB process server       */
     goto pcopd40;                          /* call SSL subroutine     */
   }
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd32-2", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   adsl_sdhc1_lbal_send = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* load-balancing send to client */
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
   iml1 = 0;                                /* nothing to send yet     */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd32-3", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef OLD_1112
   if (adsl_recudp1_w1) {                   /* chain of data received  */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-recudp1", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
#ifdef B110810
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( adsl_recudp1_w1->umc_ineta,
                               (char *) (adsl_recudp1_w1 + 1), adsl_recudp1_w1->imc_reclen,
                               bol_lb_timed_out,  /* LB timed out      */
                               (char *) adsl_sdhc1_lbal_send
                                          + sizeof(struct dsd_sdh_control_1)
                                          + sizeof(struct dsd_gather_i_1),
                               LEN_TCP_RECV
                                 - sizeof(struct dsd_sdh_control_1)
                                 - sizeof(struct dsd_gather_i_1),
                               &achl1, &iml1 );
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
#ifdef TRACEHLC
       m_check_aclconn1( this, 101 );
#endif
     }
#endif
     m_proc_free( adsl_recudp1_w1 );        /* free memory             */
   } else if (   (bol_lb_timed_out)         /* LB timed out            */
              || (bol_lb_proc_se)) {        /* LB process server       */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-bol_lb", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( 0, NULL, 0,
                               bol_lb_timed_out,  /* LB timed out      */
                               chrl_work1, sizeof(chrl_work1),
                               &achl1, &iml1 );
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
     }
#ifdef TRACEHLC
     m_check_aclconn1( this, 102 );
#endif
   }
#endif
#ifndef OLD_1112
   if (adsl_sdhc1_lbal_rec) {               /* received from WTS load-balancing */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-recudp1", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsl_sdhc1_lbal_rec + 1))
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "l%05d m_proc_data() adsl_sdhc1_lbal_rec=%p ADSL_RECB_1_G=%p.",
                       __LINE__, adsl_sdhc1_lbal_rec, ADSL_RECB_1_G );
#endif
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( (struct sockaddr *) ADSL_RECB_1_G->achc_sockaddr,
                               ADSL_RECB_1_G->achc_data,  /* pointer to data */
                               ADSL_RECB_1_G->imc_len_data,  /* length of data */
                               bol_lb_timed_out,  /* LB timed out      */
                               (char *) adsl_sdhc1_lbal_send
                                          + sizeof(struct dsd_sdh_control_1)
                                          + sizeof(struct dsd_gather_i_1),
                               LEN_TCP_RECV
                                 - sizeof(struct dsd_sdh_control_1)
                                 - sizeof(struct dsd_gather_i_1),
                               &achl1, &iml1 );
#undef ADSL_RECB_1_G
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
#ifdef TRACEHLC
       m_check_aclconn1( this, 101 );
#endif
     }
     m_proc_free( adsl_sdhc1_lbal_rec );    /* free memory receive buffer */
   } else if (   (bol_lb_timed_out)         /* LB timed out            */
              || (bol_lb_proc_se)) {        /* LB process server       */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-bol_lb", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     if (ADSL_CONN1_G->adsc_lbal_gw_1) {    /* class still present     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_se_recv( NULL, NULL, 0,
                               bol_lb_timed_out,  /* LB timed out      */
#ifdef OLD_1112
                               chrl_work1, sizeof(chrl_work1),
#endif
#ifndef OLD_1112
                               (char *) adsl_sdhc1_lbal_send
                                          + sizeof(struct dsd_sdh_control_1)
                                          + sizeof(struct dsd_gather_i_1),
                               LEN_TCP_RECV
                                 - sizeof(struct dsd_sdh_control_1)
                                 - sizeof(struct dsd_gather_i_1),
#endif
                               &achl1, &iml1 );
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
     }
#ifdef TRACEHLC
     m_check_aclconn1( this, 102 );
#endif
   }
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd32-4", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef B120903
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {
/* UUUU 24.02.05 KB - do not process here - bug */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-inc_return", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     m_proc_free( adsl_sdhc1_lbal_send );   /* free memory area        */
     ADSL_CONN1_G->boc_st_act = FALSE;      /* util-thread not active  */
#ifdef TRACEHLD
     *iptrace_act = 0X17;
#endif
#ifdef TRACE_HL_SESS_01
     m_clconn1_last_action( this, 12 );     /* last action             */
#endif  /* TRACE_HL_SESS_01 */
     return;
   }
#endif
   if (iml1) {                              /* something returned from load-balancing */
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd32-lb-iml1", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     /* send data to client after SSL encryption                       */
     /*   or pass the WebSocket Server-Data-Hook                       */
#ifndef TRACEHL_SDH_01
     memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#else
     {
       int imh1 = adsl_sdhc1_lbal_send->imc_line_no[ 0 ];
       memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_lbal_send->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
       adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
     }
#endif
     adsl_sdhc1_lbal_send->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_cur = achl1;
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_end = achl1 + iml1;
     if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
       if (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv == NULL) {  /* no buffers received */
#ifdef DEBUG_150220_01                      /* Dod connect too earl    */
         m_hlnew_printf( HLOG_TRACE1, "DEBUG_150220_01 l%05d m_proc_data()", __LINE__ );
#endif
         ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_lbal_send;  /* set chain buffers received */
         ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* set notify SDH */
       } else {                             /* append to chain of buffers */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* get chain buffers received */
         while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
         adsl_sdhc1_w1->adsc_next = adsl_sdhc1_lbal_send;  /* append to chain buffers received */
       }
       goto pcopd20;                        /* loop to process data    */
     }
     adsl_sdhc1_lbal_send->inc_function = DEF_IFUNC_FROMSERVER;
     adsl_sdhc1_lbal_send->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
     adsl_sdhc1_lbal_send->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
     adsl_sdhc1_lbal_send->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     adsl_sdhc1_w2 = NULL;                  /* clear previous in chain */
     while (adsl_sdhc1_w1) {                /* loop over all buffers   */
       if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save previous in chain  */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_lbal_send->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
#ifdef DEBUG_111205_01                      /* because of insure++     */
     adsl_sdhc1_w1 = NULL;
#endif
     if (adsl_sdhc1_w2 == NULL) {           /* is start of chain now   */
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_lbal_send;  /* set new chain */
     } else {                               /* middle in chain         */
       adsl_sdhc1_w2->adsc_next = adsl_sdhc1_lbal_send;  /* set in chain    */
     }
     bol_lb_proc_se = TRUE;                 /* LB process server       */
     goto pcopd40;                          /* call SSL subroutine     */
   }
   m_proc_free( adsl_sdhc1_lbal_send );     /* free memory area        */
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd32-5", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef NOTYET050817
   ADSL_CONN1_G->dsc_hlse03s.boc_socket_alive = bou_conn_act;
#endif
   bol1 = FALSE;                            /* flag no input           */
   if (    (ADSL_CONN1_G->adsc_sdhc1_chain)
        && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_function == DEF_IFUNC_FROMSERVER)
        && (ADSL_CONN1_G->adsc_sdhc1_chain->inc_position <= 0)) {
     bol1 = TRUE;                           /* input found             */
   }
#ifndef B131119
   if (bol_end_conn_s_1) {                  /* process end server      */
     dsl_pd_work.imc_hookc = -1;            /* hook-count              */
     goto pcall_sdh_frse;                   /* call SDH from server    */
   }
#endif
#ifdef B071113
   if (dsl_pd_work.inc_count_proc_end <= 0) {  /* normal processing    */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (dsl_pd_work.inc_count_proc_end <= 0)  /* normal processing    */
       && (   (dsl_pd_work.boc_eof_server == FALSE)  /* is not End-of-File Server */
#ifdef B131119
           || (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE))) {
#ifdef FORKEDIT
   }
              ((
#endif
#else
#ifdef B140525
           || (   (ADSL_CONN1_G->adsc_server_conf_1)
               && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh != 0)))) {  /* with server-data-hook */
#ifdef FORKEDIT
   }
              ((
#endif
#endif
#ifndef B140525
           || (iml_no_sdh > 0))) {          /* with server-data-hook   */
#endif
#endif
//     && (bol_end_conn_s_1 == FALSE)
#endif
     if (bol1 == FALSE) goto pcopd40;       /* no input from server    */
#ifdef OLD_1112
     if (dsl_pd_work.adsc_gai1_i == NULL) {  /* no more data           */
#endif
       goto pcopd36;                        /* get input data          */
#ifdef OLD_1112
     }
#endif
   }
#ifdef B120116
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server     */
       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
#ifdef FORKEDIT
   }
#endif
#else
#ifdef B140525
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server     */
       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)  /* no server-data-hook */
       || (ADSL_CONN1_G->boc_sdh_started == FALSE)) {  /* Server-Data-Hooks have not been started */
#ifdef FORKEDIT
   }
#endif
#endif
#ifndef B140525
   if (   (iml1 == 0)                       /* no server-data-hook     */
       || (ADSL_CONN1_G->boc_sdh_started == FALSE)) {  /* Server-Data-Hooks have not been started */
#endif
#endif
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
#ifdef B110904
       adsl_sdhc1_cur_1->boc_ready_t_p = FALSE;  /* not ready to process */
#endif
       adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     goto pcopd36;                          /* get input data          */
   }
   dsl_pd_work.imc_hookc = -1;              /* hook-count              */
// amc_pd_proc = &m_pd_auth1;
// dsl_pd_work.amc_pd_proc( this, &dsl_pd_work );

   pcall_sdh_frse:                          /* call SDH from server    */
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main pcall_sdh_frse: 01", __LINE__ );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcall_sdh_frse", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   m_pd_do_sdh_frse( &dsl_pd_work );
#ifdef TRACE_070630
   m_hlnew_printf( HLOG_TRACE1, "l%05d clconn1::m_proc_data pcall_sdh_frse dsl_pd_work.adsc_gai1_i=%p",
                   __LINE__, dsl_pd_work.adsc_gai1_i );
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main pcall_sdh_frse: 02", __LINE__ );
#endif
#ifdef B101215
#ifndef B101214
   if (dsl_pd_work.inc_count_proc_end == 1) {  /* process start of connection */
     goto pcopd80;                          /* data to server processed */
   }
#endif
#else
   if (dsl_pd_work.inc_count_proc_end) {    /* process start or end of connection */
     goto pcopd80;                          /* data to server processed */
   }
#endif
#ifndef B140525
   if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none) {  /* no server connection */
     if (ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* save old entry */
       ADSL_CONN1_G->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
       free( adsl_server_conf_1_w1 );       /* free old server entry   */
     }
   }
#endif

   pcopd36:                                 /* get input data          */
#ifdef B090731
   ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = dsl_pd_work.adsc_gai1_i;  /* get input */
   dsl_pd_work.adsc_gai1_i = NULL;          /* input processed         */
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd36", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACEHL1
   {
     char chh1 = 0;
     int inh1 = 0;
     int inh2 = 0;
     int inh3;
     struct dsd_gather_i_1 *adsh_gather_i_1;  /* gather input data     */
     adsh_gather_i_1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;
     while (adsh_gather_i_1) {
       inh2++;
       inh3 = adsh_gather_i_1->achc_ginp_end - adsh_gather_i_1->achc_ginp_cur;
       if (inh3) {
         if (inh1 == 0) chh1 = *adsh_gather_i_1->achc_ginp_cur;
         inh1 += inh3;
       }
       adsh_gather_i_1 = adsh_gather_i_1->adsc_next;
     }
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data pcopd36 gather=%d len-inp=%d first-char=%02X",
                     inh2, inh1, (unsigned char) chh1 );
   }
#endif

   pcopd40:                                 /* call SSL subroutine     */
#ifdef WAS_BEFORE_1501
#ifdef DEBUG_140819_01                      /* SSL called after close  */
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {
     m_hlnew_printf( HLOG_TRACE1, "l%05d clconn1::m_proc_data pcopd40: SSL return=%d - should not be called again.",
                     __LINE__, ADSL_CONN1_G->dsc_hlse03s.inc_return );
   }
#endif
#endif
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {
     goto pcopd60;                          /* SSL has already ended   */
   }
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pcopd40: 01", __LINE__ );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd40-1", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACE_HL_SESS_01
   m_clconn1_last_action( this, 13 );       /* last action             */
#endif  /* TRACE_HL_SESS_01 */
#ifdef HL_UNIX
#ifdef TRACEHL1
   if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) {
     m_hlnew_printf( HLOG_XYZ1, "NBIPGW08 l%05d m_proc_data ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse=%p achc_ginp_cur=%p achc_ginp_end=%p",
                     __LINE__, ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse,
                     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur,
                     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_end );
     m_console_out( ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur,
                    ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_end
                      - ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur );
   }
#endif
#endif
#ifdef TRACE_SL1
   inl_loop++;
   if (inl_loop > 10) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd40 inl_loop=%d",
                     __LINE__, inl_loop );
     Sleep( 2000 );
   }
#endif
#ifdef B090615
   adsl_sdhc1_se_cl = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* send to client */
   ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
     = (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1);
   ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end
     = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
         + LEN_TCP_RECV
         - sizeof(struct dsd_sdh_control_1)
         - sizeof(struct dsd_gather_i_1);
#endif
   adsl_sdhc1_se_cl = NULL;                 /* no buffer for send to client */
   ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end = NULL;
   ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = NULL;  /* no input yet  */
   bol_block_send_client = TRUE;            /* send to client blocked  */
#ifdef B141117
#ifndef HL_UNIX
   if (dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
#else
#ifdef FORKEDIT
   }
#endif
// to-do 09.08.11 KB flow client
   if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL) {  /* check flow client */
#endif
#ifdef FORKEDIT
   }
#endif
#endif
#ifndef HL_UNIX
   if (   (dcl_tcp_r_c.m_check_send_act() == FALSE)  /* check flow client  */
#else
#ifdef FORKEDIT
      )
#endif
   if (   (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send == NULL)  /* check flow client */
#endif
       || (dsl_pd_work.inc_count_proc_end < 0)  /* process end connection */
       || (dsl_pd_work.inc_count_proc_end == 2)) {  /* process end connection */
     bol_block_send_client = FALSE;         /* send to client no more blocked */
     adsl_sdhc1_se_cl = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* send to client */
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_se_cl->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
     iml1 = MAX_SERVER_DATA_HOOK;           /* position send to client */
#ifdef B130919
     if (ADSL_CONN1_G->adsc_wsp_auth_1) {   /* structure for authentication */
       iml1 = MAX_SERVER_DATA_HOOK + 1;     /* position send to client */
     }
#endif
     ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
       = (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1);
     ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end
       = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
           + LEN_TCP_RECV
           - sizeof(struct dsd_sdh_control_1)
           - sizeof(struct dsd_gather_i_1);
     /* data from server with SDH position equals number of SDHs       */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     adsl_sdhc1_w2 = NULL;                  /* clear last found block  */
     while (adsl_sdhc1_w1) {                /* loop over all buffers   */
       if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
       if (adsl_sdhc1_w1->inc_position >= iml1) {  /* position send to client */
         adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
         while (adsl_gai1_w1) {
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
             ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = adsl_gai1_w1;  /* set input now */
             break;
           }
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         }
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save last found block   */
         if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) break;  /* has input now */
       }
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     /* check if we first need to send data from authentication        */
     while (adsl_sdhc1_w2) {                /* last block found        */
       if (adsl_sdhc1_w2->inc_position >= (MAX_SERVER_DATA_HOOK + 1)) {  /* position send to client */
         break;                             /* already from authentication */
       }
       adsl_sdhc1_w1 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
       while (adsl_sdhc1_w1) {              /* loop over remaining buffers */
         if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
         if (adsl_sdhc1_w1->inc_position >= (MAX_SERVER_DATA_HOOK + 1)) {  /* position send to client */
           adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
           while (adsl_gai1_w1) {
             if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
               break;
             }
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           }
           if (adsl_gai1_w1) {              /* found something to send */
             ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = adsl_gai1_w1;  /* set input now */
             break;                         /* send this first         */
           }
         }
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       break;
     }
   }
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef TRACEHL_060710
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data() l%05d pcopd40 before SSL adsl_sdhc1_se_cl=0X%p achc_send_cur=0X%p achc_send_end=0X%p",
                   __LINE__, adsl_sdhc1_se_cl, ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur, ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end );
#endif
#ifdef TRACEHL_T_050131
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d proc_alloc 2 pcopd40", __LINE__ );
   m_chain_sdhc1();                       /* display chain           */
#endif
   adsl_sdhc1_se_se = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* send to server first */
#ifdef TRACEHL_SDH_01
   adsl_sdhc1_se_se->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
#ifdef TRACEHL_070716
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d proc_alloc adsl_sdhc1_se_se=%p", __LINE__, adsl_sdhc1_se_se );
#endif
#define ACHL_OUT_S_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1)) + 1))
   ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur = ACHL_OUT_S_START;
   ADSL_CONN1_G->dsc_hlse03s.achc_tose_end
     = ACHL_OUT_S_START
         + LEN_TCP_RECV
         - sizeof(struct dsd_sdh_control_1)
         - sizeof(struct dsd_gather_i_1);
#undef ACHL_OUT_S_START
#ifdef TRACEHL_060710
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data() l%05d pcopd40 before SSL achc_out_cur=0X%p achc_out_end=0X%p",
                   __LINE__, ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur, ADSL_CONN1_G->dsc_hlse03s.achc_tose_end );
#endif
   ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromcl = NULL;  /* TX-Data from Socket / Client */
   if (ADSL_CONN1_G->adsc_sdhc1_frcl) {     /* chain of buffers from client (SSL encrypted) */
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromcl
       = ADSL_CONN1_G->adsc_sdhc1_frcl->adsc_gather_i_1_i;  /* get first gather */
   }
#ifdef TRACEHL1
#ifdef NOTYET050817
   m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d pcopd40 process SSL / subr ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse=%p alive=%d",
                   __LINE__, ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse, ADSL_CONN1_G->dsc_hlse03s.boc_socket_alive );
#endif
#endif
#ifdef TRACEHLD
   *iptrace_act = 0X12;
   *iptrace_time = time( 0 );
#endif
#ifdef TRACEHL7
   amemtest = (char *)malloc(5);
   bou_retaddr = TRUE;                      /* check if returned o.k.  */
#endif
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
   /* count input data                                                 */
   iml_recv = 0;                            /* clear length input data */
   adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get input data */
   while (adsl_gai1_w1) {                    /* loop over output        */
     iml_recv += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   }
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_EXT) {  /* generate WSP trace record */
     iml_fromcl_data = 0;                   /* count data from client  */
     adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromcl;  /* TX-Data from Socket / Client */
     while (adsl_gai1_w1) {                 /* loop over input data    */
       iml_fromcl_data += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
   }
#ifdef WA_SSL_1501_01                       /* workaround SSL problem  */
   adsl_gai1_fromse = NULL;                 /* save input data SSL     */
   iml1 = 0;                                /* clear length input data */
   if (adsl_sdhc1_se_cl) {                  /* with buffer for send to client */
     adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get input data */
     while (adsl_gai1_w1) {                 /* loop over input to SSL  */
       iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if (iml1 > WA_SSL_1501_01) break;    /* too much input data     */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
   }
   if (iml1 > WA_SSL_1501_01) {             /* too much input data     */
     adsl_gai1_fromse = adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get input data */
     aadsl_gai1_chain = &ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* address of next chain */
     iml1 = 0;                              /* clear index gather      */
     iml2 = WA_SSL_1501_01;                 /* maximum data            */
     while (adsl_gai1_w1) {                 /* loop over output        */
       iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if (iml3 > 0) {                      /* put in gather           */
         if (iml3 > iml2) iml3 = iml2;
         dsrl_gai1_work[ iml1 ].achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
         dsrl_gai1_work[ iml1 ].achc_ginp_end = adsl_gai1_w1->achc_ginp_cur + iml3;
         *aadsl_gai1_chain = &dsrl_gai1_work[ iml1 ];
         aadsl_gai1_chain = &dsrl_gai1_work[ iml1 ].adsc_next;
         iml2 -= iml3;
         if (iml2 <= 0) break;
         iml1++;
         if (iml1 >= WA_SSL_1501_02) break;
       }
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     *aadsl_gai1_chain = NULL;              /* end of chain            */
   }
#endif
#ifdef TRACEHL_050412
   if (achl_out_start != ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur) {  /* start output here    */
     m_hlnew_printf( HLOG_TRACE1, "+++ clconn1::m_proc_data pcopd40 SSL error 050412 achl_out_start != ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur" );
   }
#endif
#ifdef B130314
   dsl_pd_work.dsc_aux_cf1.iec_src_func = ied_src_fu_ssl;  /* SSL subroutine active */
   dsl_pd_work.dsc_aux_cf1.ac_sdh = NULL;   /* current Server-Data-Hook */
#endif
   dsl_pd_work.dsc_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_ssl;  /* SSL subroutine active */
   dsl_pd_work.dsc_aux_cf1.dsc_cid.ac_cid_addr = NULL;   /* current Server-Data-Hook */
   ADSL_CONN1_G->dsc_hlse03s.boc_eof_client = dsl_pd_work.boc_eof_client;  /* End-of-File Client */
#ifndef TRY_090801_01
#ifdef B080507
   ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = dsl_pd_work.boc_eof_server;  /* End-of-File Server */
#else
#ifndef TRY_090427_01
   ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = FALSE;
   if ((dsl_pd_work.boc_eof_server) && (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
     ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = TRUE;  /* End-of-File Server */
   }
#else
#ifdef XYZ1
   if (dsl_pd_work.inc_count_proc_end < 2) {  /* do not process end of connection */
     ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = FALSE;
     if ((dsl_pd_work.boc_eof_server) && (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
       ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = TRUE;  /* End-of-File Server */
     }
   } else {
     ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = TRUE;  /* End-of-File Server */
   }
#endif
   ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = TRUE;  /* End-of-File Server */
   do {                                     /* pseudo-loop             */
     if (dsl_pd_work.inc_count_proc_end >= 2) break;  /* do process end of connection */
     if (   (dsl_pd_work.boc_eof_server)
         && (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE)) {
       break;
     }
     ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = FALSE;  /* continue processing */
   } while (FALSE);
#endif
#endif
#else
   ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = FALSE;  /* continue processing */
   do {                                     /* pseudo-loop             */
#ifdef B141124
     if (dsl_pd_work.inc_count_proc_end < 2) {  /* do not process end of connection */
// 24.11.14 KB can be -1 - no problem
       if (dsl_pd_work.boc_eof_server == FALSE) break;
#ifdef B140525
#ifndef B131119
       if (   (ADSL_CONN1_G->adsc_server_conf_1)
           && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh != 0)) {  /* with server-data-hook */
         break;
       }
#endif
#endif
#ifndef B140525
       if (iml_no_sdh > 0) break;           /* with server-data-hook   */
#endif
       if (   (ADSL_CONN1_G->adsc_server_conf_1)
           && (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic)) {
         break;
       }
     }
#endif
#ifndef B141124
     if (dsl_pd_work.inc_count_proc_end != 2) {  /* do not process end of connection stage two */
       if (dsl_pd_work.boc_eof_server == FALSE) break;
       /* still, SDHs may continue after EOF server has been received  */
       if (dsl_pd_work.inc_count_proc_end == 0) break;  /* normal processing */
     }
#endif
     /* check if more data from server                                 */
     adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     while (adsl_sdhc1_w1) {                /* loop over all buffers   */
       if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) {
         adsl_sdhc1_w1 = NULL;              /* reached end of data     */
         break;
       }
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       while (adsl_gai1_w1) {               /* loop over gather structures */
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_gai1_w1) break;             /* more data to send found */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_sdhc1_w1) break;              /* more data to process    */
     ADSL_CONN1_G->dsc_hlse03s.boc_eof_server = TRUE;  /* End-of-File Server */
   } while (FALSE);
#endif
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d clconn1::m_proc_data before m_hlse03() inc_func=%d",
                   __LINE__, ADSL_CONN1_G->dsc_hlse03s.inc_func );
#endif
#ifdef TRACE_P_060922                       /* problem received data   */
   if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) {
#define ADSL_GATHER_I_1_W ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d time-sec=%lld\
 achc_ginp_cur=%p achc_ginp_end=%p data=0X%02X",
                     __LINE__, m_get_time(),
                     ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end,
                     *((unsigned char *) ADSL_GATHER_I_1_W->achc_ginp_cur) );
#undef ADSL_GATHER_I_1_W
   }
#endif /* TRACE_P_060922                       problem received data   */
#ifdef TRACEHL_090427_01
   if (dsl_pd_work.inc_count_proc_end == 2) {  /* process end of connection */
     m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d pcopd40 dsc_hlse03s.inc_return=%d dsc_hlse03s.boc_eof_server=%d.",
                     __LINE__, ADSL_CONN1_G->dsc_hlse03s.inc_return, ADSL_CONN1_G->dsc_hlse03s.boc_eof_server );
     Sleep( 1000 );
   }
#endif
#ifdef SSL_DEBUG_100710                     /* check loop in SSL       */
   if (iml_ssl_debug) {
     m_hlnew_printf( HLOG_TRACE1, "HWSPSxxxT l%05d before m_hlse03() dsc_hlse03s.achc_tose_cur=%p dsc_hlse03s.achc_tose_end=%p.",
                     __LINE__,
                     ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur,
                     ADSL_CONN1_G->dsc_hlse03s.achc_tose_end );
   }
#endif

   m_hlse03( &ADSL_CONN1_G->dsc_hlse03s );  /* call SSL subroutine     */

#ifdef TRACE_HL_SESS_01
   m_clconn1_last_action( this, 14 );       /* last action             */
#endif  /* TRACE_HL_SESS_01 */

#ifdef TRACEHL7
   free(amemtest);
   bou_retaddr = FALSE;                     /* check if returned o.k.  */
#endif
#ifdef TRACEHLD
   *iptrace_act = 0;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd40 returned SSL / inc_return = %d",
                   __LINE__, ADSL_CONN1_G->dsc_hlse03s.inc_return );
#endif
#ifdef SSL_DEBUG_100710                     /* check loop in SSL       */
   if (   (ADSL_CONN1_G->dsc_hlse03s.boc_eof_client)
       && (ADSL_CONN1_G->dsc_hlse03s.inc_return == DEF_IRET_NORMAL)) {
     m_hlnew_printf( HLOG_TRACE1, "HWSPSxxxT l%05d GATE=%(ux)s SNO=%08d INETA=%s iml_ssl_debug=%d.",
                     __LINE__, ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     iml_ssl_debug );
     m_hlnew_printf( HLOG_TRACE1, "HWSPSxxxT l%05d dsc_hlse03s.achc_tose_cur=%p dsc_hlse03s.achc_tose_end=%p.",
                     ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur,
                     ADSL_CONN1_G->dsc_hlse03s.achc_tose_end );
     iml_ssl_debug++;
     if (iml_ssl_debug >= SSL_DEBUG_100710) {
       ADSL_CONN1_G->dsc_hlse03s.inc_return = DEF_IRET_END;
     }
   }
#endif
#define SSL_DEBUG_100710                    /* check loop in SSL       */
#ifdef TRACEHL_060710
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data() l%05d pcopd40 after SSL achc_out_cur=0X%p achc_out_end=0X%p",
                   __LINE__, ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur, ADSL_CONN1_G->dsc_hlse03s.achc_tose_end );
#endif
#ifdef B060507
   if (   (dsl_pd_work.boc_eof_client || dsl_pd_work.boc_eof_server)
       && (dsl_pd_work.achc_out_start != ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur)) {  /* start output here    */
     m_hlnew_printf( HLOG_XYZ1, "+++ clconn1::m_proc_data l%05d pcopd40 SSL error 050405 inp-client=%d out-server=%d ret=%d",
                     __LINE__, iml_recv, ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur - dsl_pd_work.achc_out_start, ADSL_CONN1_G->dsc_hlse03s.inc_return );
   }
#endif
#ifdef TRACEHL_050412
   if (   (achl_out_start != ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur)  /* start output here    */
       && (!memcmp( achl_out_start, chrs_trace_050412, sizeof(chrs_trace_050412) ))) {
     m_hlnew_printf( HLOG_TRACE1, "+++ clconn1::m_proc_data pcopd40 SSL error 050412 achl_out_start contains pattern" );
   }
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pcopd40: 02", __LINE__ );
#endif
   while (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = NULL;  /* all input processed */
     if (ADSL_CONN1_G->boc_survive) break;  /* survive E-O-F client    */
     dsl_pd_work.boc_eof_client = TRUE;     /* End-of-File Client      */
     if (dsl_pd_work.inc_count_proc_end == 0) {  /* process end of connection */
       dsl_pd_work.inc_count_proc_end = -1;  /* start process end of connection */
     }
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       if (ADSL_CONN1_G->dsc_hlse03s.inc_return == DEF_IRET_END) {
         ADSL_CONN1_G->achc_reason_end = "SSL normal end";
       } else {
         ADSL_CONN1_G->achc_reason_end = "SSL abend";
       }
     }
     break;
   }
   if (   (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL)
       && (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_END)) {
     bol1 = m_rerrm1( ADSL_CONN1_G->dsc_hlse03s.inc_return, &achl1, &iml1, chrg_ssl_error );
     if (bol1 == FALSE) {                   /* subroutine failed       */
       achl1 = "error-message not available";
       iml1 = strlen( achl1 );
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS014W GATE=%(ux)s SNO=%08d INETA=%s connection abend SSL-return-code=%d %.*s",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     ADSL_CONN1_G->dsc_hlse03s.inc_return, iml1, achl1 );
   }
#ifdef WA_SSL_1501_01                       /* workaround SSL problem  */
   if (adsl_gai1_fromse) {                  /* save input data SSL    */
     adsl_gai1_w1 = dsrl_gai1_work;         /* get pseudo input gather */
     adsl_gai1_w2 = adsl_gai1_fromse;       /* get normal input gather */
     do {                                   /* loop over input to SSL  */
       adsl_gai1_w2->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       adsl_gai1_w2 = adsl_gai1_w2->adsc_next;
     } while (adsl_gai1_w1);
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = adsl_gai1_fromse;  /* original state */
   }
#endif
   while (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) {
     if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur
           < ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_end) break;
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->adsc_next;
   }
   /* count input data again                                           */
   adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get input data */
   iml_fromse_rem = 0;                       /* count remaining from server */
   while (adsl_gai1_w1) {                    /* loop over output        */
     iml_recv -= adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     iml_fromse_rem += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   }
   if (iml_recv) {                          /* some data processed     */
     ADSL_CONN1_G->inc_c_ns_send_e++;       /* count encrypted to client */
     ADSL_CONN1_G->ilc_d_ns_send_e += iml_recv;  /* count length of data */
   }
   bol_cont = FALSE;                        /* nothing more to do      */
   bol_sdh_tose = FALSE;                    /* nothing to server yet   */
#ifdef B140701
#ifdef B120903
   if (dsl_pd_work.inc_count_proc_end == 1) {  /* process start of connection */
     bol_sdh_tose = TRUE;                   /* call Server-Data-Hook anyway */
   }
#else
   if (dsl_pd_work.inc_count_proc_end > 0) {  /* process start or end of connection */
     bol_sdh_tose = TRUE;                   /* call Server-Data-Hook anyway */
   }
#endif
#endif
#ifndef B140701
   if (   (iml_no_sdh > 0)                  /* with server-data-hook   */
#ifdef TJ_B171006
       && (dsl_pd_work.inc_count_proc_end > 0)) {  /* process start or end of connection */
#else
       && ( (dsl_pd_work.inc_count_proc_end > 0)   /* process start or end of connection */
          || ( ADSL_CONN1_G->chrc_server_error[0] != 0 ) ) ) {  /* server error */
#endif 
     bol_sdh_tose = TRUE;                   /* call Server-Data-Hook anyway */
   }
#endif
#ifdef XYZ1
#ifndef B140701
   if (   (ADSL_CONN1_G->adsc_int_webso_conn_1)  /* connect for WebSocket applications - internal */
       && (ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify)) {  /* notify SDH */
     bol_sdh_tose = TRUE;                   /* call Server-Data-Hook anyway */
   }
#endif
#endif
#define ACHL_OUT_S_START ((char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1)) + 1))
   inl_encry_cl = ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur - ACHL_OUT_S_START;  /* decrypted from client */
#ifdef TRACEHL_060710
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data() l%05d pcopd40 after SSL adsl_sdhc1_se_se=0X%p ACHL_OUT_S_START=0X%p inl_encry_cl=%d",
                   __LINE__, adsl_sdhc1_se_se, ACHL_OUT_S_START, inl_encry_cl );
#endif
#ifdef DEBUG_120705_01                      /* loop SSL                */
   iml_count_ssl++;
   if (iml_count_ssl >= DEBUG_120705_01) {
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data() l%05d pcopd40 after SSL iml_count_ssl=%d.",
                     __LINE__, iml_count_ssl );
   }
#endif
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SSL_EXT) {  /* generate WSP trace record */
#ifdef B140604
     iml2 = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
              - (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1);
#endif
     iml2 = 0;                              /* clear length            */
     if (adsl_sdhc1_se_cl) {                /* buffer created          */
       iml2 = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
                - (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1);
     }
     adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromcl;  /* TX-Data from Socket / Client */
     iml_fromcl_rem = 0;                    /* count remaining from client */
     while (adsl_gai1_w1) {                 /* loop over input from client */
       iml_fromcl_data -= adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_fromcl_rem += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSSLRET1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                     "SSL returned %d encrypted-to-client=%d/0X%X decrypted-from-client=%d/0X%X.",
                     ADSL_CONN1_G->dsc_hlse03s.inc_return,
                     iml2,
                     iml2,
                     inl_encry_cl,
                     inl_encry_cl );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
     iml1 = sprintf( achl_w1 + sizeof(struct dsd_wsp_trace_record),
                     "- consumed-from-server=%d/0X%X remaining-from-server=%d/0X%X consumed-from-client=%d/0X%X remaining-from-client=%d/0X%X.",
                     iml_recv,
                     iml_recv,
                     iml_fromse_rem,
                     iml_fromse_rem,
                     iml_fromcl_data,
                     iml_fromcl_data,
                     iml_fromcl_rem,
                     iml_fromcl_rem );
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G2->achc_content = achl_w1 + sizeof(struct dsd_wsp_trace_record);  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;        /* length of text / data   */
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     if (   (inl_encry_cl > 0)              /* data to be displayed    */
         && (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       adsl_wtr_w1 = ADSL_WTR_G2;           /* set last in chain       */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G2 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
       iml1 = inl_encry_cl;                 /* length of data to be copied */
       achl_w3 = ACHL_OUT_S_START;          /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       bol1 = FALSE;                        /* reset more flag         */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml2 = achl_w2 - achl_w4;
         if (iml2 > iml1) iml2 = iml1;
         memcpy( achl_w4, achl_w3, iml2 );
         achl_w4 += iml2;
         achl_w3 += iml2;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (inl_encry_cl) {                      /* some data processed     */
#ifdef TRACEHL_060710
     m_console_out( ACHL_OUT_S_START, inl_encry_cl );
#endif
#ifdef DEBUG_100824_01
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun) {  /* is HTUN */
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (ADSL_CONN1_G->adsc_auxf_1_htun + 1))
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd40 inl_encry_cl=%d imc_state=%08X DEF_STATE_HTUN_SEND_COMPL=%d adsc_sdhc1_htun_sch=%p imc_send_window=0X%08X.",
                       __LINE__,
                       inl_encry_cl,
                       ADSL_CONN1_G->adsc_ineta_raws_1->imc_state,
                       ADSL_CONN1_G->adsc_ineta_raws_1->imc_state & DEF_STATE_HTUN_SEND_COMPL,
                       ADSL_CONN1_G->adsc_sdhc1_htun_sch,
                       ADSL_CONN1_G->imc_send_window );
//#undef ADSL_INETA_RAWS_1_G
     }
#endif
     ADSL_CONN1_G->inc_c_ns_rece_e++;       /* count decrypted from client */
     ADSL_CONN1_G->ilc_d_ns_rece_e += inl_encry_cl;  /* count length of data */
#ifndef TRACEHL_SDH_01
     memset( adsl_sdhc1_se_se, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#else
     {
       int imh1 = adsl_sdhc1_se_se->imc_line_no[ 0 ];
       memset( adsl_sdhc1_se_se, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_se_se->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
       adsl_sdhc1_se_se->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
     }
#endif
#ifdef HL_UNIX
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "NBIPGW08 l%05d m_proc_data adsl_sdhc1_se_se=%p ACHL_OUT_S_START=%p inl_encry_cl=%d",
                     __LINE__, adsl_sdhc1_se_se, ACHL_OUT_S_START, inl_encry_cl );
     m_console_out( ACHL_OUT_S_START, inl_encry_cl );
#endif
#endif
     adsl_sdhc1_se_se->adsc_gather_i_1_i
       = (struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1))->achc_ginp_cur
       = ACHL_OUT_S_START;
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1))->achc_ginp_end
       = ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur;
#ifdef TRACEHL_060710
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data() l%05d pcopd40 fill send client achc_ginp_cur=0X%p achc_ginp_end=0X%p",
                     __LINE__,
                     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1))->achc_ginp_cur,
                     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_se + 1))->achc_ginp_end );
#endif
#ifdef TRACEHL_STOR_USAGE
     {
       char chrh_msg[64];
       struct dsd_sdh_control_1 *adsl_sdhc1_h1;
       adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
       while (adsl_sdhc1_h1) {
         sprintf( chrh_msg, "main-l%05d pcopd40-2", __LINE__ );
         m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
         adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
       }
     }
#endif
     /* data to server with SDH position -1                            */
     adsl_sdhc1_se_se->inc_position = -1;   /* send to server          */
#ifdef OLD_1112
     if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server configured   */
         && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)  /* with server-data-hook */
         && (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal)) {  /* status do load-balancing */
       adsl_sdhc1_se_se->inc_position = ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh - 1;
#ifdef B101231
       bol_sdh_tose = TRUE;                 /* something to server     */
#else
       if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) {  /* is connected to server */
         bol_sdh_tose = TRUE;               /* something to server     */
       }
#endif
     }
#endif
#ifndef OLD_1112
     if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* not status do load-balancing */
       if (   (ADSL_CONN1_G->adsc_wsp_auth_1)  /* in authentication */
           || (ADSL_CONN1_G->iec_st_ses == ied_ses_auth)) {  /* status authentication */
         adsl_sdhc1_se_se->inc_position = MAX_SERVER_DATA_HOOK;  /* position from client to authentication */
#ifdef B140525
       } else if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* server configured */
                  && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)) {  /* with server-data-hook */
         adsl_sdhc1_se_se->inc_position = ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh - 1;
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) {  /* is connected to server */
           bol_sdh_tose = TRUE;             /* something to server     */
         }
#endif
#ifndef B140525
       } else if (iml_no_sdh > 0) {         /* with server-data-hook   */
         adsl_sdhc1_se_se->inc_position = iml_no_sdh - 1;
         if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) {  /* is connected to server */
           bol_sdh_tose = TRUE;             /* something to server     */
         }
#endif
       }
     }
#endif
     adsl_sdhc1_se_se->inc_function = DEF_IFUNC_TOSERVER;
#ifdef B110904
     adsl_sdhc1_se_se->boc_ready_t_p = TRUE;  /* ready to process      */
#endif
     adsl_sdhc1_se_se->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_last_1 = NULL;              /* clear last in chain found */
#ifdef B111124
     adsl_sdhc1_w1 = NULL;                  /* clear first entry       */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
       if (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER) {
         if (   (adsl_sdhc1_cur_1->inc_position == adsl_sdhc1_se_se->inc_position)
             && (adsl_sdhc1_w1 == NULL)) {  /* not yet first entry     */
           adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save this as first entry */
         } else if (adsl_sdhc1_cur_1->inc_position < adsl_sdhc1_se_se->inc_position) {
           break;                           /* insert here             */
         }
       }
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
#else
     adsl_sdhc1_w1 = NULL;                  /* clear first entry       */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
       if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_cur_1->inc_position <= adsl_sdhc1_se_se->inc_position)) {
#ifdef TRACEHL_SDH_01
         adsl_sdhc1_se_se->imc_line_no[ 2 ] = __LINE__;  /* line numbers for debugging */
#endif
         if (adsl_sdhc1_cur_1->inc_position != adsl_sdhc1_se_se->inc_position) break;
         if (adsl_sdhc1_w1 == NULL) {       /* not yet first entry     */
           adsl_sdhc1_w1 = adsl_sdhc1_cur_1;  /* save first entry      */
#ifdef TRACEHL_SDH_01
           adsl_sdhc1_se_se->imc_line_no[ 2 ] = __LINE__;  /* line numbers for debugging */
#endif
         }
       }
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
#endif
     if (adsl_sdhc1_last_1 == NULL) {       /* new one is first in chain */
       adsl_sdhc1_se_se->adsc_next = ADSL_CONN1_G->adsc_sdhc1_chain;
       ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_se_se;
#ifdef TRACEHL_SDH_01
       adsl_sdhc1_se_se->imc_line_no[ 3 ] = __LINE__;  /* line numbers for debugging */
#endif
     } else {                               /* middle in chain         */
       adsl_sdhc1_se_se->adsc_next = adsl_sdhc1_cur_1;
       adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_se_se;
#ifdef TRACEHL_SDH_01
       adsl_sdhc1_se_se->imc_line_no[ 3 ] = __LINE__;  /* line numbers for debugging */
#endif
       /* set chain field of first struct dsd_sdh_control_1            */
       if (adsl_sdhc1_w1) {                 /* append to first struct dsd_sdh_control_1 */
         adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain gather structures */
         adsl_gai1_w2 = NULL;               /* no preceeder            */
         while (adsl_gai1_w1) {             /* loop over gather structures */
           adsl_gai1_w2 = adsl_gai1_w1;     /* save this as last one   */
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_w2 == NULL) {        /* no preceeder            */
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_sdhc1_se_se->adsc_gather_i_1_i;
         } else {                           /* middle of chain         */
           adsl_gai1_w2->adsc_next = adsl_sdhc1_se_se->adsc_gather_i_1_i;
         }
       }
     }
#ifdef DEBUG_111205_01                      /* because of insure++     */
     adsl_sdhc1_w1 = NULL;
#endif
#ifdef TRACEHL_SDH_01
     m_check_sdhc1( ADSL_CONN1_G, "m_proc_data() data to server", __LINE__ );
#endif
     bol_cont = TRUE;                       /* call again              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
   } else {                                 /* no data decrypted       */
     m_proc_free( adsl_sdhc1_se_se );       /* free memory area        */
   }
   adsl_sdhc1_se_se = NULL;                 /* no data to server       */
#undef ACHL_OUT_S_START
#ifdef WORKAROUND_SSL_PROB_120706
   do {                                     /* pseudo-loop             */
     if (bol_cont) break;
     if (ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end != ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur) {
       adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get input data */
       while (adsl_gai1_w1) {               /* loop over input data    */
         if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       if (adsl_gai1_w1) {                  /* still input data        */
         bol_cont = TRUE;                   /* call again              */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
         break;
       }
     }
     if (ADSL_CONN1_G->dsc_hlse03s.achc_tose_end == ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur) break;
     adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromcl;  /* TX-Data from Socket / Client */
     while (adsl_gai1_w1) {                 /* loop over input data    */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     if (adsl_gai1_w1 == NULL) break;       /* no more input data      */
     bol_cont = TRUE;                       /* call again              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
   } while (FALSE);
#endif
#ifdef B090731
   if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse == NULL) {  /* all input processed  */
     while (dsl_pd_work.adsc_sdhc1_client) {  /* data to send to client returned */
       adsl_sdhc1_w1 = dsl_pd_work.adsc_sdhc1_client;  /* get this buffer */
       dsl_pd_work.adsc_sdhc1_client = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free memory area        */
     }
   }
#endif
#ifdef B140327
   if (dsl_pd_work.boc_abend) {             /* abend of session        */
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
#ifdef XYZ1
#ifndef B120909
     if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* configuration server */
       dsl_pd_work.boc_eof_client = TRUE;   /* End-of-File Client      */
     }
#endif
#endif
     bol_cont = TRUE;                       /* call again              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
     dsl_pd_work.boc_abend = FALSE;         /* stop processing abend   */
   }
#endif
   if (   (dsl_pd_work.boc_abend)           /* abend of session        */
       && (dsl_pd_work.inc_count_proc_end == 0)) {  /* process end of connection */
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
     bol_cont = TRUE;                       /* call again              */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
     dsl_pd_work.boc_abend = FALSE;         /* stop processing abend   */
   }
   /* garbage-collection data received from client                     */
   while (ADSL_CONN1_G->adsc_sdhc1_frcl) {  /* chain of buffers from client (SSL encrypted) */
     adsl_sdhc1_w1 = adsl_sdhc1_w2 = ADSL_CONN1_G->adsc_sdhc1_frcl;  /* get chain */
     do {                                   /* loop over buffers       */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get first gather */
#ifdef B110810
       while (adsl_gai1_w1) {               /* loop over gather input  */
         if (   (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end)
             && (adsl_gai1_w1->achc_ginp_cur >= ((char *) ADSL_CONN1_G->adsc_sdhc1_frcl))
             && (adsl_gai1_w1->achc_ginp_end <= ((char *) ADSL_CONN1_G->adsc_sdhc1_frcl + LEN_TCP_RECV))) {
           break;                           /* buffer is in use        */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
#else
       while (adsl_gai1_w1) {               /* loop over gather input  */
         if (   (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end)
             && (adsl_gai1_w1->achc_ginp_cur >= ((char *) adsl_sdhc1_w2))
             && (adsl_gai1_w1->achc_ginp_end <= ((char *) adsl_sdhc1_w2 + LEN_TCP_RECV))) {
           break;                           /* buffer is in use        */
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
#endif
       if (adsl_gai1_w1) break;             /* buffer is in use        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
#ifdef DEBUG_111205_01                      /* because of insure++     */
     adsl_sdhc1_w1 = NULL;
#endif
     if (adsl_gai1_w1) break;               /* buffer is in use        */
     ADSL_CONN1_G->adsc_sdhc1_frcl = adsl_sdhc1_w2->adsc_next;  /* remove from chain */
     m_proc_free( adsl_sdhc1_w2 );          /* free this buffer        */
   }
#ifdef B090814
   if (adsl_sdhc1_client) {                 /* data received from client */
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsl_sdhc1_client + 1))
     if (ADSL_CONN1_G->dsc_hlse03s.achc_inp_cur == ADSL_GATHER_I_1_W->achc_ginp_end) {
#ifdef TRACEHL_T_050131
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d proc_free 6 adsl_sdhc1_client after SSL",
                       __LINE__ );
       m_chain_sdhc1();                     /* display chain           */
#endif
       m_proc_free( adsl_sdhc1_client );    /* free memory area        */
       adsl_sdhc1_client = NULL;            /* no more buffer available */
     }
#undef ADSL_GATHER_I_1_W
   }
#endif
#ifndef B090615
   if (adsl_sdhc1_se_cl == NULL) {          /* no buffer for send to client */
     goto pcopd60;                          /* no authentication in this moment */
   }
#endif
#ifdef TO_DO_150312
   problem HOB RD VPN 2.1.10
   send routine says illogic, because still buffer to be sent in TCPCOMP thread
#ifndef TRY_150310                          /* send to client blocked  */
     dcl_tcp_r_c.m_send_gather( adsl_sdhc1_se_cl, FALSE );
#else
     EnterCriticalSection( &d_act_critsect );  /* critical section act */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send;  /* chain to send */
     if (adsl_sdhc1_w1) {                   /* chain to send           */
       /* append to chain send by TCPCOMP                              */
       while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
       adsl_sdhc1_w1->adsc_next = adsl_sdhc1_se_cl;
       /* gather also need to be in chain                              */
       adsl_gai1_w1 = ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send->adsc_gather_i_1_i;
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       adsl_gai1_w1->adsc_next = adsl_sdhc1_se_cl->adsc_gather_i_1_i;
       adsl_sdhc1_se_cl = NULL;             /* do not send now         */
     }
     LeaveCriticalSection( &d_act_critsect );  /* critical section act */
     if (adsl_sdhc1_se_cl) {                /* can send now            */
       dcl_tcp_r_c.m_send_gather( adsl_sdhc1_se_cl, FALSE );
     }
#endif
#endif
   if (ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
         != (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1)) {
#ifdef DEBUG_140123_01                      /* SSL close problem       */
     if (ADSL_CONN1_G->dsc_hlse03s.boc_eof_client) {  /* End-of-File Client */
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd40 DEBUG_140123_01 SSL boc_eof_client TRUE but returned data to send to client - illogic",
                       __LINE__ );
     }
#endif
     iml1 = ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur
              - (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1);
#ifdef TRACEHL1
#ifndef HL_UNIX
#else
#ifdef B110810
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd40 send client length = %d socket = %d",
                     __LINE__, iml1, ADSL_CONN1_G->ifd_c );
#endif
#endif
     if (iml1 > 8192) {
       m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd40 length data %d - too big / start=%p cur=%p",
                       __LINE__, iml1,
                       ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1,
                       ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur );
     }
#endif
#ifdef TRACEHL_060710
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data() l%05d pcopd40 after SSL adsl_sdhc1_se_cl=0X%p achc_out_cur=0X%p achc_out_end=0X%p",
                     __LINE__, adsl_sdhc1_se_cl, ADSL_CONN1_G->dsc_hlse03s.achc_tocl_cur, ADSL_CONN1_G->dsc_hlse03s.achc_tocl_end );
     m_console_out( (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1)) + 1), iml1 );
#endif
     ADSL_CONN1_G->inc_c_ns_send_c++;       /* count send client       */
     ADSL_CONN1_G->ilc_d_ns_send_c += iml1;  /* data send client       */
#ifdef TRACE_091013_01
     m_hlnew_printf( HLOG_TRACE1, "HWSPSxxxx GATE=%(ux)s SNO=%08d INETA=%s l%05d send to client %d/0X%08X sum=%lld.",
                     ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                     __LINE__, iml1, iml1, ADSL_CONN1_G->ilc_d_ns_send_c );
#endif
     /* buffer was not prepared                                        */
#ifndef TRACEHL_SDH_01
     memset( adsl_sdhc1_se_cl, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#else
     {
       int imh1 = adsl_sdhc1_se_cl->imc_line_no[ 0 ];
       memset( adsl_sdhc1_se_cl, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_se_cl->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
       adsl_sdhc1_se_cl->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
     }
#endif
     adsl_sdhc1_se_cl->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1))->achc_ginp_cur
       = (char *) adsl_sdhc1_se_cl + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
     ((struct dsd_gather_i_1 *) (adsl_sdhc1_se_cl + 1))->achc_ginp_end
       = (char *) adsl_sdhc1_se_cl + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)
         + iml1;
#ifdef DEBUG_150218_01                      /* problem gather          */
     m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main send-to-client 01", __LINE__ );
#endif


#ifdef TJ_B171005
#ifndef HL_UNIX
#ifdef XYZ1
#ifdef TRY_120306_01                        /* flow-control send       */
     if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
       ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = FALSE;  /* activate connection after send */
     }
#endif
#endif
     dcl_tcp_r_c.m_send_gather( adsl_sdhc1_se_cl, FALSE );
#else
     m_send_clse_tcp_1( ADSL_CONN1_G, &ADSL_CONN1_G->dsc_tc1_client, adsl_sdhc1_se_cl, FALSE );
#endif
#endif //TJ_B171005

#ifndef TJ_B171005
     if ( ( dsl_pd_work.inc_count_proc_end < 0 ) || ( dsl_pd_work.inc_count_proc_end == 2 ) ) {
#ifndef HL_UNIX
       EnterCriticalSection( &d_act_critsect );  /* critical section act */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send;  /* chain to send */
#else 
       ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send;  /* chain to send */
#endif
       if (adsl_sdhc1_w1) {                   /* chain to send           */
         /* append to chain send by TCPCOMP                              */
         while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
         adsl_sdhc1_w1->adsc_next = adsl_sdhc1_se_cl;
         adsl_sdhc1_se_cl = NULL;             /* do not send now         */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &d_act_critsect );  /* critical section act */
#else
       ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#endif
     }
     if (adsl_sdhc1_se_cl) {                /* can send now            */
#ifndef HL_UNIX
       dcl_tcp_r_c.m_send_gather( adsl_sdhc1_se_cl, FALSE );
#else
       m_send_clse_tcp_1( ADSL_CONN1_G, &ADSL_CONN1_G->dsc_tc1_client, adsl_sdhc1_se_cl, FALSE );
#endif
     }
#endif // not TJ_B171005


#ifdef DEBUG_150218_01                      /* problem gather          */
     m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main send-to-client 02", __LINE__ );
#endif
     bol_cont = TRUE;                       /* process more            */
#ifdef DEBUG_LOOP_PROC_DATA_01
     iml_cont_line = __LINE__;              /* line where bol_cont is set */
#endif
   } else {
     m_proc_free( adsl_sdhc1_se_cl );       /* free send to client again */
   }
#ifndef B130316
   if (ADSL_CONN1_G->iec_st_cls != ied_cls_normal) {  /* status client not normal processing */
     goto pcopd60;                          /* no authentication in this moment */
   }
#endif
#ifdef OLD_1112
#ifndef NOT_YET_UNIX_110808
   if (   (   (ADSL_CONN1_G->adsc_radqu == NULL)   /* no class authentication */
           && (ADSL_CONN1_G->iec_st_ses != ied_ses_auth))  /* status authentication */
       || (ADSL_CONN1_G->boc_st_sslc == FALSE)) {  /* ssl handshake not complete */
     goto pcopd60;                          /* no authentication in this moment */
   }
#else
     goto pcopd60;                          /* no authentication in this moment */
#endif
#else
   if (   (   (ADSL_CONN1_G->adsc_wsp_auth_1 == NULL)  /* not in authentication */
           && (ADSL_CONN1_G->iec_st_ses != ied_ses_auth))  /* status authentication */
       || (ADSL_CONN1_G->boc_st_sslc == FALSE)) {  /* ssl handshake not complete */
     goto pcopd60;                          /* no authentication in this moment */
   }
#endif

#ifdef OLD_1112
   pcopd52:                                 /* process radius query    */
#else
   pcopd52:                                 /* process authentication  */
   if (   (ADSL_CONN1_G->adsc_wsp_auth_1)
       && (ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify)) {  /* notify authentication routine */
     bol_cont = TRUE;                       /* more to do              */
   }
#endif
#ifndef HL_UNIX
#ifndef B090615
   if (dcl_tcp_r_c.m_check_send_act()) {    /* check flow client       */
     goto pcopd60;                          /* no authentication in this moment */
   }
#endif
#else
// to do 09.08.11 KB flow client
   if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* check flow client */
     goto pcopd60;                          /* no authentication in this moment */
   }
#endif
#ifdef OLD_1112
   /* search input data to authentication                              */
   adsl_gai1_w1 = NULL;                     /* no input data found     */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_cur_1->inc_position < 0)) {
       adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain input data */
       while (adsl_gai1_w1) {                    /* loop over output        */
         if (adsl_gai1_w1->achc_ginp_end > adsl_gai1_w1->achc_ginp_cur) break;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
#ifndef B110207_XXX
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* get this buffer         */
       do {                                 /* loop over remaining buffers */
#ifdef B110904
         adsl_sdhc1_w1->boc_ready_t_p = FALSE;  /* already processed   */
#endif
         adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_idle;  /* idle, has been processed */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w1);
#endif
       break;
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   dsl_pd_work.adsc_gai1_i = adsl_gai1_w1;  /* this is input data      */
#endif
#ifdef B060507
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d before m_pd_auth1() dsl_pd_work.achc_out_start=%p ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur=%p",
                   __LINE__, dsl_pd_work.achc_out_start, ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur );
#endif
   memset( &dsl_gai1_out1, 0, sizeof(dsl_gai1_out1) );  /* gather output data */
   dsl_gai1_out1.achc_ginp_cur = dsl_pd_work.achc_out_start;
   dsl_gai1_out1.achc_ginp_end = ADSL_CONN1_G->dsc_hlse03s.achc_tose_cur;
   dsl_pd_work.adsc_gai1_i = &dsl_gai1_out1;  /* this is input         */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d before call m_pd_auth1",
                   __LINE__ );
#endif
#endif
#ifdef CHECK_PROB_070113
   m_check_chain_aux( ADSL_CONN1_G );
#endif
   m_pd_auth1( &dsl_pd_work );
#ifdef DEBUG_100809
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d after  call m_pd_auth1 adsl_sdhc1_cur_1=%p.",
                   __LINE__, adsl_sdhc1_cur_1 );
   as_debug_100809_01 = adsl_sdhc1_cur_1;
#endif
#ifdef CHECK_PROB_070113
   m_check_chain_aux( ADSL_CONN1_G );
#endif
#ifdef B090731
/* 14.11.05 KB - input used as output, not freed */
   if (dsl_pd_work.adsc_sdhc1_client) {     /* data to send to client returned */
     /* make chain of all buffers                                      */
     adsl_sdhc1_w1 = dsl_pd_work.adsc_sdhc1_client;  /* get this buffer */
     adsl_gai1_w2 = NULL;                   /* no last buffer          */
     do {                                   /* loop over all control areas */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get input data */
       if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse == NULL) {
         ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = adsl_gai1_w1;
         bol_cont = TRUE;                   /* process more            */
#ifdef DEBUG_LOOP_PROC_DATA_01
         iml_cont_line = __LINE__;          /* line where bol_cont is set */
#endif
       }
       if (adsl_gai1_w2) {                  /* last buffer set         */
         adsl_gai1_w2->adsc_next = adsl_gai1_w1;  /* append to chain   */
       }
       do {                                 /* loop over output        */
         adsl_gai1_w2 = adsl_gai1_w1;       /* save as last buffer     */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       } while (adsl_gai1_w1);              /* for all buffers         */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     } while (adsl_sdhc1_w1);
   }
#endif
#ifndef B140527
   iml_no_sdh = 0;                          /* number of SDHs          */
   adsl_server_conf_1_used = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used) {           /* with configuration server */
     if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
       adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
     }
     iml_no_sdh = adsl_server_conf_1_used->inc_no_sdh;  /* number of SDHs */
   }
#endif
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_radqu) goto pcopd80;  /* Radius processing still active */
#endif
#ifndef B140220
   if (dsl_pd_work.boc_abend) {             /* process end session     */
     if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
       ADSL_CONN1_G->achc_reason_end = "abend of authentication";
     }
#ifdef B140326
     dsl_pd_work.inc_count_proc_end = 2;    /* process end of connection */
     goto pcopd80;                          /* data processed          */
#endif
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
#ifdef B150517
     dsl_pd_work.inc_count_proc_end = 1;    /* process end of connection */
#endif
#ifndef B150517
     dsl_pd_work.inc_count_proc_end = -1;   /* process end of connection */
#endif
#ifndef B140701
     ADSL_CONN1_G->iec_st_ses = ied_ses_abend;
#endif
     goto pcopd40;                          /* call SSL subroutine     */
   }
#endif
#ifndef OLD_1112
   if (ADSL_CONN1_G->adsc_wsp_auth_1) goto pcopd60;  /* authentication active */
#endif
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_do_lbal) {  /* status do load-balancing */
     bol_cont = TRUE;                       /* process more            */
#ifdef OLD_1112
     goto pcopd80;                          /* data to server processed */
#endif
   }
#ifdef OLD_1112
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) goto pcopd80;  /* no configured server */
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0) goto pcopd80;  /* no server-data-hook */
   /* now change remaining output as input to Server-Data-Hook         */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_cur_1->inc_position < 0)) {
       adsl_sdhc1_cur_1->inc_position = ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh - 1;
#ifdef B110904
#ifndef B101216
       adsl_sdhc1_cur_1->boc_ready_t_p = TRUE;  /* can be processed now */
#endif
#endif
       adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_proc_data() changed after auth", __LINE__ );
#endif
#endif
// to-do 14.01.12 KB - should go to pcopd60 ???
   goto pcopd80;                            /* data to server processed */

   pcopd60:                                 /* continue process output */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd60 check send-to-server time-sec=%d",
                   __LINE__, m_get_time() );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd60", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef B140525
   if (   (bol_sdh_tose == FALSE)           /* no data to server       */
       || (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server defined */
       || (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
     goto pcopd64;                          /* send output to server   */
   }
   /* set hook-count                                                   */
   dsl_pd_work.imc_hookc = ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh - 1;
#endif
#ifdef WAS_BEFORE_1501
#ifndef B140525
   if (   (bol_sdh_tose == FALSE)           /* no data to server       */
       || (iml_no_sdh == 0)) {              /* no server-data-hook     */
     goto pcopd64;                          /* send output to server   */
   }
   /* set hook-count                                                   */
   dsl_pd_work.imc_hookc = iml_no_sdh - 1;
#endif
#endif
   if (   (iml_no_sdh == 0)                 /* no server-data-hook     */
       || (   (bol_sdh_tose == FALSE)           /* no data to server       */
           && (dsl_pd_work.imc_special_func == 0))) {  /* call with special function */
     goto pcopd64;                          /* send output to server   */
   }
   /* set hook-count                                                   */
   dsl_pd_work.imc_hookc = iml_no_sdh - 1;

   pcall_sdh_tose:                          /* call SDH to server      */
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main pcall_sdh_tose: 01", __LINE__ );
#endif
   m_pd_do_sdh_tose( &dsl_pd_work );
#ifdef DEBUG_101216_01
   m_hlnew_printf( HLOG_TRACE1, "T$D1 m_proc_data() l%05d pcall_sdh_tose ADSL_CONN1_G->adsc_sdhc1_chain.",
                   __LINE__, ADSL_CONN1_G->adsc_sdhc1_chain );
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main pcall_sdh_tose: 02", __LINE__ );
#endif
   dsl_pd_work.imc_special_func = 0;        /* call with special function */

   pcopd64:                                 /* Client-Side SSL         */
   if (ADSL_CONN1_G->adsc_csssl_oper_1) {   /* process Client-Side-SSL */
     bol1 = dsl_pd_work.boc_eof_server;     /* save End-of-File Server */
     m_pd_do_cs_ssl( &dsl_pd_work );
#ifdef DEBUG_100809
     m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d after  call m_pd_do_cs_ssl() iec_st_ses=%d.",
                     __LINE__, ADSL_CONN1_G->iec_st_ses );
     if (ADSL_CONN1_G->iec_st_ses != ied_ses_wait_csssl) {  /* no more wait for client-side SSL */
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d after  call m_pd_do_cs_ssl() != ied_ses_wait_csssl",
                       __LINE__ );
     }
#endif
     if (dsl_pd_work.boc_eof_server != bol1) {  /* check End-of-File Server */
       bol_cont = TRUE;                     /* has more to process     */
#ifdef DEBUG_LOOP_PROC_DATA_01
       iml_cont_line = __LINE__;            /* line where bol_cont is set */
#endif
     }
#ifdef B110316
#ifndef NOT_YET_100809
     if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2) {  /* start connection to server part two */
       bol_cont = TRUE;                     /* has more to process     */
     }
#endif
#endif
   }

   pcopd80:                                 /* data to server processed */
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_proc_data() pcopd80", __LINE__ );
#endif
#ifdef TRACEHL_090801_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 start", __LINE__ );
#endif
#ifdef DEBUG_120206_01                      /* 06.02.12 KB check storage in use - sdhc1 */
   ims_debug_sdhc1_c--;                     /* counter display sdhc1 per session */
   if (ims_debug_sdhc1_c <= 0) {            /* counter display sdhc1 per session */
     int      imh1, imh2, imh3, imh4;
     struct dsd_sdh_control_1 *adsh_sdhc1_w1;  /* working variable     */

     ims_debug_sdhc1_c = DEBUG_120206_01;   /* reset counter display sdhc1 per session */
     imh1 = imh2 = imh3 = imh4 = 0;
#ifndef HL_UNIX
     EnterCriticalSection( &d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                     __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
#endif
     adsh_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain     */
     while (adsh_sdhc1_w1) {                /* loop over chain         */
       imh1++;                              /* count entry             */
       if (adsh_sdhc1_w1->imc_usage_count != 0) {  /* in use           */
         imh2++;                            /* count entry             */
       }
       adsh_sdhc1_w1 = adsh_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsh_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* chain of buffers in use */
     while (adsh_sdhc1_w1) {                /* loop over chain         */
       imh3++;                              /* count entry             */
       if (adsh_sdhc1_w1->imc_usage_count != 0) {  /* in use           */
         imh4++;                            /* count entry             */
       }
       adsh_sdhc1_w1 = adsh_sdhc1_w1->adsc_next;  /* get next in chain */
     }
#ifndef HL_UNIX
     LeaveCriticalSection( &d_act_critsect );  /* critical section act */
#else
     ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section        */
#endif
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d DEBUG_120206_01 sno=%08d iml_count_loop=%d blocks-n=%d bn-marked=%d blocks-in-use=%d biu-marked=%d.",
                     __LINE__, ADSL_CONN1_G->dsc_co_sort.imc_sno, iml_count_loop,
                     imh1, imh2, imh3, imh4 );
   }
#endif
#ifdef DEBUG_100824_01
   bol1 = FALSE;
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_conn) bol1 = TRUE;
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 start - iec_st_ses=%d ied_ses_conn=%d.",
                   __LINE__, ADSL_CONN1_G->ied_ses_conn, bol1 );
#endif
#ifdef TRY_120306_01                        /* flow-control send       */
#ifndef HL_UNIX
   ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = FALSE;  /* do not activate connection after send */
#else
   ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send = FALSE;  /* do not activate connection after send */
#endif
   if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifndef HL_UNIX
     ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send = FALSE;  /* do not activate connection after send */
#else
     ADSL_CONN1_G->dsc_tc1_server.boc_act_conn_send = FALSE;  /* do not activate connection after send */
#endif
   }
#ifdef TRACE_TCP_FLOW_01
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d m_proc_data() all boc_act_conn_send set to FALSE",
                   __LINE__ );
#endif
#endif
#ifdef DEBUG_130711_01                      /* 11.07.13 KB hangs after HTCP session end */
   iml1 = 0;
   adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain       */
   while (adsl_sdhc1_w1) {
     iml1++;
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
   }
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d iml_count_loop=%d iec_st_ses=%d bol_cont=%d ADSL_CONN1_G->adsc_sdhc1_chain %d entries / adsc_ineta_raws_1=%p.",
                   __LINE__, iml_count_loop, ADSL_CONN1_G->iec_st_ses, bol_cont, iml1, ADSL_CONN1_G->adsc_ineta_raws_1 );
#endif
   /* check if entry to process now                                    */
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
/**
   04.07.10 KB
   it is useless to use iml2 and iml3 in this routine
*/
#ifdef B100704
   iml2 = iml3 = 0;                         /* clear variables for compare */
#endif
#ifndef B140806
   iml1 = -1;                               /* check send to server    */
   if (ADSL_CONN1_G->adsc_csssl_oper_1) {   /* process Client-Side-SSL */
     iml1 = -2;                             /* only send direct        */
   }
#endif
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
#ifdef DEBUG_101216_01
     m_hlnew_printf( HLOG_XYZ1, "T$D1 m_proc_data() l%05d loop to process adsl_sdhc1_cur_1=%p.",
                     __LINE__, adsl_sdhc1_cur_1 );
     if (adsl_sdhc1_cur_1->adsc_gather_i_1_i == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "T$D1 m_proc_data() l%05d adsc_gather_i_1_i == NULL adsl_sdhc1_cur_1=%p.",
                       __LINE__, adsl_sdhc1_cur_1 );
     }
#endif
#ifdef B100704
     if (   (adsl_sdhc1_cur_1->inc_function != iml2)
         || (adsl_sdhc1_cur_1->inc_position != iml3)) {
#endif
       iml2 = adsl_sdhc1_cur_1->inc_function;
       iml3 = adsl_sdhc1_cur_1->inc_position;
#ifdef B100704
     }
#endif
#ifdef B110904
     while (adsl_sdhc1_cur_1->boc_ready_t_p) {  /* entry to be processed */
#endif
#ifdef FORKEDIT
     }
#endif
     while (adsl_sdhc1_cur_1->iec_sdhcs != ied_sdhcs_idle) {  /* idle, has been processed */
#ifndef B100704
       if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) break;
#endif
#ifndef TRY_120306_01                       /* flow-control send       */
#ifndef HL_UNIX
       if (   (adsl_sdhc1_cur_1->iec_sdhcs == ied_sdhcs_wait_send_client)  /* wait to send to client is possible */
           && (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act())) {  /* still data to send */
         break;                             /* do not process now      */
       }
#else
       if (   (adsl_sdhc1_cur_1->iec_sdhcs == ied_sdhcs_wait_send_client)  /* wait to send to client is possible */
           && (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send)) {  /* still data to send */
         break;                             /* do not process now      */
       }
#endif
#else
       if (adsl_sdhc1_cur_1->iec_sdhcs == ied_sdhcs_wait_send_client) {  /* wait to send to client is possible */
#ifndef HL_UNIX
         if (ADSL_CONN1_G->dcl_tcp_r_c.m_check_send_act()) {  /* still data to send */
           ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = TRUE;  /* activate connection after send */
           break;                           /* wait till data sent     */
         }
#else
         if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* still data to send */
           ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send = TRUE;  /* activate connection after send */
           break;                           /* wait till data sent     */
         }
#endif
       }
#endif
       if (iml3 >= MAX_SERVER_DATA_HOOK) {  /* maximum number server-data-hook configured */
         /* is buffer sent to client before encryption                 */
// to-do 28.03.14 KB - may be buffer which is input to authentication library
#ifdef B090731
         adsl_sdhc1_cur_1->boc_ready_t_p = FALSE;  /* not to be processed */
         if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) break;
         ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = adsl_sdhc1_cur_1->adsc_gather_i_1_i;
         break;
#endif
#ifndef HL_UNIX
#ifdef B120420
         if (dcl_tcp_r_c.m_check_send_act()) break;  /* check flow client */
#else
#ifdef B141124
         if (dcl_tcp_r_c.m_check_send_act()) {  /* check flow client   */
//        && (dsl_pd_work.inc_count_proc_end == 0)  /* process end connection */
#ifdef FORKEDIT
         }
#endif
#endif
#ifndef B141124
         if (   (dcl_tcp_r_c.m_check_send_act())   /* check flow client   */
             && (   (dsl_pd_work.inc_count_proc_end == 0)  /* do not process end connection */
                 || (dsl_pd_work.inc_count_proc_end == 1))) {  /* process start connection */
#endif
#ifdef B120704
           if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none) break;  /* with server connection */
#endif
           ADSL_CONN1_G->dcl_tcp_r_c.boc_act_conn_send = TRUE;  /* do activate connection after send */
           break;
         }
#endif
#else
#ifndef B140710
         if (ADSL_CONN1_G->iec_st_cls == ied_cls_rec_close) break;  /* received close */
#endif
#ifdef B141124
// to-do 09.08.11 KB check flow client
         if (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send) {  /* check flow client */
#ifdef FORKEDIT
         }
#endif
#endif
#ifndef B141124
         if (   (ADSL_CONN1_G->dsc_tc1_client.adsc_sdhc1_send)  /* check flow client */
             && (   (dsl_pd_work.inc_count_proc_end == 0)  /* do not process end connection */
                 || (dsl_pd_work.inc_count_proc_end == 1))) {  /* process start connection */
#endif
           ADSL_CONN1_G->dsc_tc1_client.boc_act_conn_send = TRUE;  /* do activate connection after send */
           break;
         }
#endif
         adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get input data */
         while (adsl_gai1_w1) {             /* loop over gather input  */
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
             goto pcopd40;                  /* input from server, send over SSL to client */
           }
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         }
         break;                             /* nothing found to send   */
       }
#ifdef XYZ1
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 call-SDH-again adsl_sdhc1_ps_1=%p pos=%d dir=%d",
                       __LINE__, adsl_sdhc1_ps_1, iml2, iml3 );
#endif
#endif
#ifdef B100704
#ifndef B091125
       if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) break;
#endif
#endif
       dsl_pd_work.imc_hookc = iml3;        /* hook-count              */
       if (iml2 == DEF_IFUNC_FROMSERVER) goto pcall_sdh_frse;  /* call SDH from server */
       if (iml3 < 0) {                      /* set direct to server    */
#ifdef B070716
         goto pcopd92;                      /* all processed           */
#else
#ifndef B140806
         if (iml3 <= iml1) iml1 = -3;       /* check send to server    */
#endif
         break;                             /* send after loop         */
#endif
       }
#ifndef B101231
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_conn) break;  /* is not connected to server */
#endif
       goto pcall_sdh_tose;                 /* call SDH to server      */
     }
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_090801_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 after loop thru ADSL_CONN1_G->adsc_sdhc1_chain",
                   __LINE__ );
#endif

   /* send output to server                                            */
#ifndef B140806
   if (iml1 > -3) {                         /* check send to server    */
     goto pcopd84;                          /* do not send data        */
   }
#endif
#ifdef B100809
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server defined */
       || (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect)  /* only Server-Data-Hook */
       || (ADSL_CONN1_G->iec_st_ses != ied_ses_conn)) {  /* status server not connected */
#ifdef TRACEHL1
     {
       BOOL boh1 = FALSE;
       if (ADSL_CONN1_G->adsc_server_conf_1) {  /* server defined */
         boh1 = ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect;  /* only Server-Data-Hook */
       }
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 ADSL_CONN1_G->adsc_server_conf_1=%p boc_sdh_reflect=%d iec_st_ses=%d",
                       __LINE__, ADSL_CONN1_G->adsc_server_conf_1, boh1, ADSL_CONN1_G->iec_st_ses );
     }
#endif
     goto pcopd84;                          /* do not send data        */
   }
#else
   /* do not check ied_ses_start_server_1 because of TCPCOMP           */
   if (   (ADSL_CONN1_G->adsc_server_conf_1 == NULL)  /* no server defined */
#ifdef B130421
       || (ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect)  /* only Server-Data-Hook */
#else
       || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_none)  /* no server connection */
       || (ADSL_CONN1_G->iec_servcotype == ied_servcotype_ended)  /* server connection ended */
#endif
       || (   (ADSL_CONN1_G->iec_st_ses != ied_ses_conn)  /* status server not connected */
           && (ADSL_CONN1_G->iec_st_ses != ied_ses_wait_csssl)  /* wait for client-side SSL */

           && (ADSL_CONN1_G->iec_st_ses != ied_ses_start_server_2))) {  /* start connection to server part two */
#ifdef TRACEHL1
     {
       BOOL boh1 = FALSE;
       if (ADSL_CONN1_G->adsc_server_conf_1) {  /* server defined      */
         boh1 = ADSL_CONN1_G->adsc_server_conf_1->boc_sdh_reflect;  /* only Server-Data-Hook */
       }
       m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 ADSL_CONN1_G->adsc_server_conf_1=%p boc_sdh_reflect=%d iec_st_ses=%d",
                       __LINE__, ADSL_CONN1_G->adsc_server_conf_1, boh1, ADSL_CONN1_G->iec_st_ses );
     }
#endif
     goto pcopd84;                          /* do not send data        */
   }
#endif
#ifndef HL_UNIX
   if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
       && (dcl_tcp_r_s.m_check_send_act())) {  /* check server         */
     bol_block_send_server = TRUE;          /* send to server blocked  */
//#ifdef TRY_140803_01                        /* problems boc_act_conn_send */
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
       ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send = TRUE;  /* do activate connection after send */
     }
//#endif
     goto pcopd84;                          /* do not send data        */
   }
#else
// to-do 09.08.11 check server
   if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
       && (ADSL_CONN1_G->dsc_tc1_server.adsc_sdhc1_send)) {  /* check flow server */
     bol_block_send_server = TRUE;          /* send to server blocked  */
//#ifdef TRY_140803_01                        /* problems boc_act_conn_send */
     if (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
       ADSL_CONN1_G->dsc_tc1_server.boc_act_conn_send = TRUE;  /* do activate connection after send */
     }
//#endif
     goto pcopd84;                          /* do not send data        */
   }
#endif
#ifdef D_INCL_HOB_TUN
   if (   (ADSL_CONN1_G->iec_servcotype == ied_servcotype_htun)  /* HTUN */
       && (ADSL_CONN1_G->imc_send_window > DEF_HTCP_SEND_WINDOW)) {  /* number of bytes to be sent */
     bol_block_send_server = TRUE;          /* send to server blocked  */
     goto pcopd84;                          /* do not send data        */
   }
#endif
#ifdef B100830
   iml1 = 0;
   if (ADSL_CONN1_G->adsc_csssl_oper_1) {   /* process Client-Side-SSL */
     iml1 = -1;                             /* only send direct        */
   }
   adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
   adsl_sdhc1_last_1 = NULL;                /* clear last element      */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_cur_1->inc_position < iml1)) {
       break;
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain  */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_cur_1 == NULL) goto pcopd84;  /* no data to send     */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_proc_data l%05d pcopd80 send-to-server adsl_sdhc1_cur_1=%p",
                   __LINE__, adsl_sdhc1_cur_1 );
#endif
   /* remove data to send from chain                                   */
   if (adsl_sdhc1_last_1 == NULL) {         /* at start of chain       */
     ADSL_CONN1_G->adsc_sdhc1_chain = NULL;  /* no more data in chain  */
   } else {                                 /* middle in chain         */
     adsl_sdhc1_last_1->adsc_next = NULL;   /* clear end of chain      */
   }
   /* count data sent to server                                        */
   bol1 = FALSE;                            /* no data found yet       */
   adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
   while (adsl_gai1_w1) {                   /* loop over data to send  */
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml1) {                            /* data to send found      */
       ADSL_CONN1_G->ilc_d_ns_send_s += iml1;  /* data send server     */
       bol1 = TRUE;                         /* data found              */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (bol1 == FALSE) {                     /* no data found           */
     /* free all buffers                                               */
     do {
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* get first buffer        */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* remove block from chain */
#ifdef B110315
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use       */
         m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
       } else {                             /* work area still in use  */
#endif
#ifndef HL_UNIX
         EnterCriticalSection( &d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_enter();  /* critical section    */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &ADSL_CONN1_G->dsc_critsect );
#endif
#endif
         adsl_sdhc1_w1->adsc_next = ADSL_CONN1_G->adsc_sdhc1_inuse;  /* chain of buffers in use */
         ADSL_CONN1_G->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
#ifndef HL_UNIX
         LeaveCriticalSection( &d_act_critsect );  /* critical section act */
#else
         ADSL_CONN1_G->dsc_critsect.m_leave();  /* critical section    */
#endif
#ifdef B110315
       }
#endif
     } while (adsl_sdhc1_cur_1);
#ifdef DEBUG_111205_01                      /* because of insure++     */
     adsl_sdhc1_w1 = NULL;
#endif
     goto pcopd88;                          /* all done                */
   }
   ADSL_CONN1_G->inc_c_ns_send_s++;         /* count send server       */
#ifdef PROB070717
   if (adsl_sdhc1_cur_1->adsc_gather_i_1_i == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 send-to-server adsl_sdhc1_cur_1=%p ->adsc_gather_i_1_i == NULL",
                     __LINE__, adsl_sdhc1_cur_1 );
   }
#endif
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d pcopd80 - iec_st_ses=%d adsl_sdhc1_cur_1=%p.",
                   __LINE__, ADSL_CONN1_G->iec_st_ses, adsl_sdhc1_cur_1 );
#endif
   switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
#ifndef HL_UNIX
#ifdef XYZ1
#ifdef TRY_120306_01                        /* flow-control send       */
       if (ADSL_CONN1_G->dcl_tcp_r_s.m_check_send_act() == FALSE) {  /* check flow client */
         ADSL_CONN1_G->dcl_tcp_r_s.boc_act_conn_send = FALSE;  /* activate connection after send */
       }
#endif
#endif
       dcl_tcp_r_s.m_send_gather( adsl_sdhc1_cur_1, FALSE );
#else
#ifdef B110810
       m_tcp_send_1( ADSL_CONN1_G, TRUE, adsl_sdhc1_cur_1 );
#endif
       m_send_clse_tcp_1( ADSL_CONN1_G, &ADSL_CONN1_G->dsc_tc1_server, adsl_sdhc1_cur_1, FALSE );
#endif
       break;
     case ied_servcotype_htun:              /* HOB-TUN                 */
       if (ADSL_CONN1_G->adsc_sdhc1_htun_sch) {  /* check start of chain */
         adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get start of chain */
         while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
         adsl_sdhc1_w1->adsc_next = adsl_sdhc1_cur_1;  /* append new blocks to the chain */
       } else {                             /* we build the chain now  */
         ADSL_CONN1_G->adsc_sdhc1_htun_sch = adsl_sdhc1_cur_1;  /* set start of chain */
       }
       /* all gather structure need to be chained together             */
       adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_htun_sch;  /* get start of chain */
       do {                                 /* loop to find first gather */
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;  /* gather found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_cur_1);
       if (adsl_sdhc1_cur_1 == NULL) break;
#ifdef XYZ1
       adsl_gai1_w1 = adsl_gai1_cur = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get first gather */
       while (adsl_gai1_cur->adsc_next) adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* last gather */
#endif
       adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get first gather */
       while (TRUE) {                       /* loop to append sdhc1 blocks */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
         if (adsl_sdhc1_cur_1 == NULL) break;
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) {  /* gather in this block */
           adsl_gai1_cur = adsl_gai1_w1;    /* get first gather        */
           do {
             if (adsl_gai1_cur == adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;  /* gather found */
             adsl_gai1_last = adsl_gai1_cur;  /* save last location    */
             adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
           } while (adsl_gai1_cur);
           if (adsl_gai1_cur == NULL) {     /* we need to append to the chain of gather */
             adsl_gai1_last->adsc_next = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* append new gather */
           }
         }
       }
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (ADSL_CONN1_G->adsc_auxf_1_htun + 1))
       ADSL_INETA_RAWS_1_G->imc_state |= DEF_STATE_HTUN_SEND_COMPL;  /* done HTUN send complete - m_htun_htcp_send_complete() */
#ifdef DEBUG_100824_01
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 before m_htun_sess_send() - adsl_gai1_w1=%p adsc_sdhc1_htun_sch=%p.",
                       __LINE__, adsl_gai1_w1, ADSL_CONN1_G->adsc_sdhc1_htun_sch );
#endif
#IFDEF B110502
       m_htun_sess_send( ADSL_INETA_RAWS_1_G->dsc_htun_h,
                         adsl_gai1_w1 );
#ELSE
       m_htun_sess_send( adsp_hco_wothr,
                         ADSL_INETA_RAWS_1_G->dsc_htun_h,
                         adsl_gai1_w1 );
#ENDIF
#undef ADSL_INETA_RAWS_1_G
       break;
     case ied_servcotype_l2tp:              /* L2TP                    */
       m_ext_send_server( adsp_hco_wothr, ADSL_CONN1_G, adsl_sdhc1_cur_1 );
       break;
   }
   goto pcopd88;
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd80-1", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifndef B100830
   bol1 = m_do_send_server( adsp_hco_wothr, ADSL_CONN1_G );
#ifdef TRACEHL_SDH_01
   m_check_sdhc1( ADSL_CONN1_G, "m_proc_data() after m_do_send_server()", __LINE__ );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd80-2", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   if (bol1) goto pcopd88;                  /* data have been sent     */
#endif
#ifdef B140709
#ifndef B140706
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_abend) {
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
     dsl_pd_work.inc_count_proc_end = 1;    /* process end of connection */
     goto pcopd40;                          /* call SSL subroutine     */
   }
#endif
#endif
#ifndef B140709
   if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_abend)
       && (dsl_pd_work.inc_count_proc_end == 0)) {  /* process end of connection */
     dsl_pd_work.boc_eof_server = TRUE;     /* End-of-File Server      */
#ifdef B150517
     dsl_pd_work.inc_count_proc_end = 1;    /* process end of connection */
#endif
#ifndef B150517
     dsl_pd_work.inc_count_proc_end = -1;   /* process end of connection */
#endif
     goto pcopd40;                          /* call SSL subroutine     */
   }
#endif

   pcopd84:                                 /* nothing to server       */
   if (ADSL_CONN1_G->adsc_lbal_gw_1) {      /* load-balancing active   */
     adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
     adsl_sdhc1_last_1 = NULL;              /* clear last element      */
     adsl_gai1_w1 = NULL;                   /* no data to send         */
     while (adsl_sdhc1_cur_1) {             /* loop over all buffers   */
       if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_cur_1->inc_position < 0)) {
         adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
         while (adsl_gai1_w1) {             /* loop over data to send  */
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
         }
         if (adsl_gai1_w1) break;           /* found data to send      */
       }
       adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
     }
     if (adsl_gai1_w1 == NULL) goto pcopd86;  /* no data to send       */
#ifdef B090731
     iml1 = 0;                              /* clear length to send    */
     ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_cl_recv( adsl_gai1_w1->achc_ginp_cur,
         adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
         chrl_work1, sizeof(chrl_work1),
         &achl1, &iml1 );
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     if (iml1) {                            /* something to send       */
       dsl_gather_i_1_i.achc_ginp_cur = achl1;  /* send to client      */
       dsl_gather_i_1_i.achc_ginp_end = achl1 + iml1;  /* end data     */
       ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = &dsl_gather_i_1_i;
       bol_lb_proc_cl = TRUE;               /* LB process client       */
       bol_cont = TRUE;                     /* process more            */
     }
#endif
     adsl_sdhc1_lbal_send = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* load-balancing send to client */
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
     iml1 = 0;                              /* nothing to send yet     */
     ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_cl_recv( adsl_gai1_w1->achc_ginp_cur,
         adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
         (char *) adsl_sdhc1_lbal_send
                    + sizeof(struct dsd_sdh_control_1)
                    + sizeof(struct dsd_gather_i_1),
         LEN_TCP_RECV
           - sizeof(struct dsd_sdh_control_1)
           - sizeof(struct dsd_gather_i_1),
         &achl1, &iml1 );
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     if (iml1) {                            /* something returned from load-balancing */
       /* send data to client after SSL encryption                     */
       /*   or pass the WebSocket Server-Data-Hook                     */
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#else
       {
         int imh1 = adsl_sdhc1_lbal_send->imc_line_no[ 0 ];
         memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
         adsl_sdhc1_lbal_send->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
       adsl_sdhc1_lbal_send->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1);
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_cur = achl1;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_end = achl1 + iml1;
       if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
         if (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv == NULL) {  /* no buffers received */
           ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_lbal_send;  /* set chain buffers received */
           ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* set notify SDH */
         } else {                           /* append to chain of buffers */
           adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* get chain buffers received */
           while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
           adsl_sdhc1_w1->adsc_next = adsl_sdhc1_lbal_send;  /* append to chain buffers received */
         }
         goto pcopd20;                      /* loop to process data */
       }
       adsl_sdhc1_lbal_send->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_lbal_send->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
       adsl_sdhc1_lbal_send->boc_ready_t_p = TRUE;  /* ready to process     */
#endif
       adsl_sdhc1_lbal_send->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
       adsl_sdhc1_w2 = NULL;                /* clear previous in chain */
       while (adsl_sdhc1_w1) {              /* loop over all buffers   */
         if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save previous in chain  */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       adsl_sdhc1_lbal_send->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
       if (adsl_sdhc1_w2 == NULL) {         /* is start of chain now   */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_lbal_send;  /* set new chain */
       } else {                             /* middle in chain         */
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_lbal_send;  /* set in chain  */
       }
       bol_lb_proc_cl = TRUE;               /* LB process client       */
       bol_cont = TRUE;                     /* process more            */
     } else {
       m_proc_free( adsl_sdhc1_lbal_send );  /* free memory area       */
     }
   } else if (   (ADSL_CONN1_G->boc_st_sslc)  /* ssl handshake complete */
              && (   (ADSL_CONN1_G->iec_st_ses == ied_ses_prep_server)
                  || (   (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_1)  /* start connection to server part one */
                  || (ADSL_CONN1_G->iec_st_ses == ied_ses_start_server_2)))) {  /* start connection to server part two */
#ifdef TRY_WITHOUT_100830  /* should be ifndef */
     bol_cont = TRUE;                       /* process more            */
#endif
#ifdef TRY_WITHOUT_100830
/**
   this part should be removed again because it is also done at pcopd24:
   12.08.10 KB
*/
     m_start_rec_server( &dsl_pd_work );    /* open connection server  */
#ifdef DEBUG_100824_01
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd84 - after m_start_rec_server() iec_st_ses=%d.",
                     __LINE__, ADSL_CONN1_G->iec_st_ses );
#endif
     if (   (ADSL_CONN1_G->iec_st_ses == ied_ses_error_conn)  /* status server error   */
         && (ADSL_CONN1_G->achc_reason_end == NULL)) {    /* reason end session      */
       ADSL_CONN1_G->achc_reason_end = "error connect to Server";
     }
#ifdef DEBUG_100810
     if (ADSL_CONN1_G->iec_st_ses == ied_ses_start_sdh) {  /* start Server-Data-Hooks */
       ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* is connected to server now */
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh) {  /* with server-data-hook */
         dsl_pd_work.inc_count_proc_end = 1;  /* process start of connection */
         dsl_pd_work.imc_hookc = -1;          /* hook-count              */
/* 10.08.10 KB set input ready to process */
         adsl_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain  */
         while (adsl_sdhc1_cur_1) {         /* loop over all buffers   */
           if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
               && (adsl_sdhc1_cur_1->inc_position == 0)) {
#ifdef B110904
             adsl_sdhc1_cur_1->boc_ready_t_p = TRUE;  /* ready to process */
#endif
             adsl_sdhc1_cur_1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
           }
           adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
         }
         goto pcall_sdh_frse;               /* call SDH from server    */
       }
     }
#endif
#endif
   }
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif
#ifdef TRACEHLX
   if (bohx) m_hlnew_printf( HLOG_XYZ1, "achc_out_cur not processed %p", this );
#endif
   goto pcopd88;                            /* data to server processed */

   pcopd86:                                 /* no data to server       */
   if (   (bol_lb_proc_cl)                  /* process client          */
       && (ADSL_CONN1_G->adsc_lbal_gw_1)) {  /* class gateway active   */
#ifdef B090731
     /* check if still input data not processed                        */
     adsl_gai1_w1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* get buffer send to client */
     while (adsl_gai1_w1) {                 /* loop over all gather    */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_w1 == NULL) {            /* no buffer found         */
       bol_lb_proc_cl = FALSE;              /* LB process client       */
       iml1 = 0;                            /* nothing to send yet     */
       ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_cl_recv( NULL, 0,
                               chrl_work1, sizeof(chrl_work1),
                               &achl1, &iml1 );
       if (iml1) {                          /* something to send       */
         dsl_gather_i_1_i.achc_ginp_cur = achl1;  /* send to client    */
         dsl_gather_i_1_i.achc_ginp_end = achl1 + iml1;  /* end data   */
         ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = &dsl_gather_i_1_i;
         bol_lb_proc_cl = TRUE;             /* LB process client       */
         bol_cont = TRUE;                   /* process more            */
       }
       if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
         delete ADSL_CONN1_G->adsc_lbal_gw_1;
         ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
       }
     } else {                               /* still input to process  */
       bol_cont = TRUE;                     /* process more            */
     }
#endif
     adsl_sdhc1_lbal_send = (struct dsd_sdh_control_1 *) m_proc_alloc();  /* load-balancing send to client */
#ifdef TRACEHL_SDH_01
     adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
#endif
     iml1 = 0;                              /* nothing to send yet     */
     ADSL_CONN1_G->adsc_lbal_gw_1->m_proc_cl_recv( NULL, 0,
         (char *) adsl_sdhc1_lbal_send
                    + sizeof(struct dsd_sdh_control_1)
                    + sizeof(struct dsd_gather_i_1),
         LEN_TCP_RECV
           - sizeof(struct dsd_sdh_control_1)
           - sizeof(struct dsd_gather_i_1),
         &achl1, &iml1 );
     if (iml1) {                            /* something returned from load-balancing */
       /* send data to client after SSL encryption                   */
       /*   or pass the WebSocket Server-Data-Hook                     */
#ifndef TRACEHL_SDH_01
       memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#else
       {
         int imh1 = adsl_sdhc1_lbal_send->imc_line_no[ 0 ];
         memset( adsl_sdhc1_lbal_send, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
         adsl_sdhc1_lbal_send->imc_line_no[ 0 ] = imh1;  /* line numbers for debugging */
         adsl_sdhc1_lbal_send->imc_line_no[ 1 ] = __LINE__;  /* line numbers for debugging */
       }
#endif
       adsl_sdhc1_lbal_send->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1);
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_cur = achl1;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_lbal_send + 1))->achc_ginp_end = achl1 + iml1;
       if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
         if (ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv == NULL) {  /* no buffers received */
           ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv = adsl_sdhc1_lbal_send;  /* set chain buffers received */
           ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* set notify SDH */
         } else {                           /* append to chain of buffers */
           adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_int_webso_conn_1->adsc_sdhc1_recv;  /* get chain buffers received */
           while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* search last in chain */
           adsl_sdhc1_w1->adsc_next = adsl_sdhc1_lbal_send;  /* append to chain buffers received */
         }
         goto pcopd20;                      /* loop to process data */
       }
       adsl_sdhc1_lbal_send->inc_function = DEF_IFUNC_FROMSERVER;
       adsl_sdhc1_lbal_send->inc_position = MAX_SERVER_DATA_HOOK;  /* position send to client */
#ifdef B110904
       adsl_sdhc1_lbal_send->boc_ready_t_p = TRUE;  /* ready to process     */
#endif
       adsl_sdhc1_lbal_send->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain   */
       adsl_sdhc1_w2 = NULL;                /* clear previous in chain */
       while (adsl_sdhc1_w1) {              /* loop over all buffers   */
         if (adsl_sdhc1_w1->inc_function != DEF_IFUNC_FROMSERVER) break;
         adsl_sdhc1_w2 = adsl_sdhc1_w1;     /* save previous in chain  */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       adsl_sdhc1_lbal_send->adsc_next = adsl_sdhc1_w1;  /* get remaining part of chain */
       if (adsl_sdhc1_w2 == NULL) {         /* is start of chain now   */
         ADSL_CONN1_G->adsc_sdhc1_chain = adsl_sdhc1_lbal_send;  /* set new chain */
       } else {                             /* middle in chain         */
         adsl_sdhc1_w2->adsc_next = adsl_sdhc1_lbal_send;  /* set in chain  */
       }
       bol_lb_proc_cl = TRUE;               /* LB process client       */
       bol_cont = TRUE;                     /* process more            */
     } else {
       m_proc_free( adsl_sdhc1_lbal_send );      /* free memory area        */
     }
     if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_lbal) {  /* status server */
       delete ADSL_CONN1_G->adsc_lbal_gw_1;
       ADSL_CONN1_G->adsc_lbal_gw_1 = NULL;
     }
   }
#ifdef DEBUG_111205_01                      /* because of insure++     */
   adsl_sdhc1_w1 = NULL;
#endif

   pcopd88:                                 /* data to server processed */
#ifdef TRACEHL_090427_01
   if (dsl_pd_work.inc_count_proc_end == 2) {  /* process end of connection */
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd88 dsc_hlse03s.inc_return=%d.",
                     __LINE__, ADSL_CONN1_G->dsc_hlse03s.inc_return );
     Sleep( 1000 );
   }
#endif
#ifdef B130314
   /* check if a signal is set which can be processed                  */
   if (   (ADSL_CONN1_G->adsc_server_conf_1)  /* with server           */
       && (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh)) {  /* with server-data-hook */
     vpl_w1 = m_check_sdh_signal( &dsl_pd_work.dsc_aux_cf1 );
     if (vpl_w1) {                          /* signal found            */
       /* set hook-count                                               */
       dsl_pd_work.imc_hookc
         = ((struct dsd_sdh_work_1 *) vpl_w1)
           - ((struct dsd_sdh_work_1 *) (ADSL_CONN1_G->adsc_server_conf_1 + 1));
       goto pcall_sdh_tose;                 /* call SDH to server      */
     }
   }
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main pcopd88: 01", __LINE__ );
#endif
   /* check if a signal is set which can be processed                  */
   while (ADSL_CONN1_G->boc_signal_set) {   /* signal for component set */
     adsl_cid_signal = m_check_sdh_signal( &dsl_pd_work.dsc_aux_cf1 );
     if (adsl_cid_signal == NULL) break;    /* no signal to get processed */
     switch (adsl_cid_signal->iec_src_func) {  /* function             */
       case ied_src_fu_auth:                /* Authentication active   */
         break;
       case ied_src_fu_sdh:                 /* Server-Data-Hook        */
#ifdef B140525
         if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) break;  /* no server */
         if (ADSL_CONN1_G->adsc_server_conf_1->inc_no_sdh == 0) break;  /* no server-data-hook */
#endif
#ifndef B140525
         if (iml_no_sdh == 0) break;        /* no server-data-hook     */
#endif
         /* set hook-count                                             */
#ifdef B131225
         dsl_pd_work.imc_hookc
           = ((struct dsd_sdh_work_1 *) adsl_cid_signal->ac_cid_addr)
               - ((struct dsd_sdh_work_1 *) (ADSL_CONN1_G->adsc_server_conf_1 + 1));
#endif
#ifdef DEBUG_131225_01                      /* signal - dsl_pd_work.imc_hookc */
         m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d <%p> dsl_pd_work.imc_hookc=%d.",
                         __LINE__, ADSL_CONN1_G, dsl_pd_work.imc_hookc );
         m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d <%p> adsl_cid_signal->ac_cid_addr=%p.",
                         __LINE__, ADSL_CONN1_G, adsl_cid_signal->ac_cid_addr );
         m_hlnew_printf( HLOG_TRACE1, "clconn1::m_proc_data l%05d <%p> (ADSL_CONN1_G->adsc_server_conf_1 + 1)=%p ADSL_CONN1_G->adsc_server_conf_1=%p ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous=%p.",
                         __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_server_conf_1 + 1, ADSL_CONN1_G->adsc_server_conf_1, ADSL_CONN1_G->adsc_server_conf_1->adsc_seco1_previous );
#endif
#ifndef B131225
         adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_server_conf_1;  /* configuration server */
         while (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* configuration server previous */
           adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
         }
         dsl_pd_work.imc_hookc
           = ((struct dsd_sdh_work_1 *) adsl_cid_signal->ac_cid_addr)
               - ((struct dsd_sdh_work_1 *) (adsl_server_conf_1_w1 + 1));
#endif
         goto pcall_sdh_tose;               /* call SDH to server      */
       case ied_src_fu_phl:                 /* plain-HTTP-library      */
         goto p_http_00;                    /* process HTTP            */
     }
     break;
   }
#ifdef B120903
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {  /* error occured */
#ifdef FORKEDIT
   }
#endif
#else
   if (dsl_pd_work.inc_count_proc_end == 2) {  /* process end of connection */
#endif
#ifdef B100324
     if (adsl_sdhc1_client) {               /* data received from client */
#ifdef TRACEHL_T_050131
       m_hlnew_printf( HLOG_XYZ1, "proc_free 10 adsl_sdhc1_client before close" );
       m_chain_sdhc1();                     /* display chain           */
#endif
       m_proc_free( adsl_sdhc1_client );    /* free memory area        */
     }
#endif
#ifdef TRACEHL5
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data <%p> before close1", ADSL_CONN1_G );
#endif
#ifdef TRACEHLD
     *iptrace_act = 0X15;
#endif
#ifdef TRACEHL7
     if (bou_retaddr)                       /* check if returned o.k.  */
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data <%p> bou_retaddr before close1", this );
#endif
#ifndef B090907
#ifdef TRACE_HL_SESS_01
     m_clconn1_last_action( ADSL_CONN1_G, 101 );  /* last action       */
#endif  /* TRACE_HL_SESS_01 */
#endif
#ifndef HL_UNIX
     this->close1( &dsl_pd_work );          /* close session           */
#else
     m_conn_close( &dsl_pd_work );          /* close session           */
#endif
#ifdef TRACEHL5
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data <%p> after  close1", ADSL_CONN1_G );
#endif
#ifdef TRACEHL7
     if (bou_retaddr)                       /* check if returned o.k.  */
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data <%p> bou_retaddr after close1", ADSL_CONN1_G );
#endif
#ifdef TRACEHLD
     *iptrace_act = 0X16;
#endif
#ifdef B090907
#ifdef TRACE_HL_SESS_01
     m_clconn1_last_action( ADSL_CONN1_G, 101 );  /* last action       */
#endif  /* TRACE_HL_SESS_01 */
#endif
     return;                                /* nothing more to do      */
   }

   pcopd92:                                 /* all processed           */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd92", __LINE__ );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d pcopd92", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACEHL_P_050118
   if (bol_cont) {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
#ifndef TEMP_140926_01
   /* work-around
   real solution: check where bol_cont has been set,
     should not have been set
   */
   if (ADSL_CONN1_G->dsc_hlse03s.inc_return != DEF_IRET_NORMAL) {  /* error occured */
     bol_cont = FALSE;
   }
#endif
   if (bol_cont) goto pcopd40;              /* more to do              */
#ifdef B090814
   if (ADSL_CONN1_G->adsc_sdhc1_frcl) {     /* chain of buffers from client (SSL encrypted) */
     goto pcopd40;                          /* more to do              */
   }
#endif
#ifdef B090731
#ifdef B070629
   dsl_pd_work.adsc_gai1_i = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* input from se  */
   while (dsl_pd_work.adsc_gai1_i) {
     if (dsl_pd_work.adsc_gai1_i->achc_ginp_cur < dsl_pd_work.adsc_gai1_i->achc_ginp_end) {
//     adsl_gather_i_1_i = NULL;            /* nothing to process      */
       goto pcopd40;                        /* more to do              */
     }
     dsl_pd_work.adsc_gai1_i = dsl_pd_work.adsc_gai1_i->adsc_next;
   }
#else
#ifndef TRY_090729_01
   dsl_pd_work.adsc_gai1_i = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* input from server */
   while (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) {
     if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur
           < ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_end) {
       goto pcopd40;                        /* more to do              */
     }
     ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->adsc_next;
     dsl_pd_work.adsc_gai1_i = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* input from se  */
   }
#else
   if (dcl_tcp_r_c.m_check_send_act() == FALSE) {  /* check flow client */
     dsl_pd_work.adsc_gai1_i = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* input from server */
     while (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse) {
       if (ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_cur
             < ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->achc_ginp_end) {
         goto pcopd40;                      /* more to do              */
       }
       ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse->adsc_next;
       dsl_pd_work.adsc_gai1_i = ADSL_CONN1_G->dsc_hlse03s.adsc_gai1_fromse;  /* input from server */
     }
   }
#endif
#endif
#endif
#ifndef B050224
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main m_garb_coll_1() 01 before", __LINE__ );
#endif
#ifndef TRY_160113_01                       /* leave thread after less rounds */
   m_garb_coll_1( ADSL_CONN1_G );           /* do garbage collect      */
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( ADSL_CONN1_G->adsc_sdhc1_chain, "pd_main m_garb_coll_1() 02 after", __LINE__ );
#endif
#ifdef TRACEHL_SDH_COUNT_1
   iml1 = m_sdh_count_1( ADSL_CONN1_G, -1, "after m_garb_coll_1()", __LINE__ );
#ifdef DEBUG_111202_01                      /* 02.12.11 KB check too many sdhc1 */
   if (iml1 >= DEBUG_111202_01) {
     m_hlnew_printf( HLOG_XYZ1, "after m_garb_coll_1() l%05d entries=%d - too many",
                     __LINE__, iml1 );
   }
#endif
#endif
#ifdef DEBUG_100903_01
   {
     int imh3, imh4;
     int        imh_gather;                   /* count gather            */
     int        imh_data;                     /* count data              */
     char *achh1;
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     struct dsd_gather_i_1 *adsl_gai1_h1;     /* working variable        */
     adsl_sdhc1_h1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       if (adsl_sdhc1_h1->inc_function == DEF_IFUNC_FROMSERVER) {
         achh1 = "invalid";
         switch (adsl_sdhc1_h1->inc_function) {
           case DEF_IFUNC_FROMSERVER:
             achl1 = "FROMSERVER";
             break;
           case DEF_IFUNC_TOSERVER:
             achl1 = "TOSERVER";
             break;
         }
         adsl_gai1_h1 = adsl_sdhc1_h1->adsc_gather_i_1_i;  /* get chain to send */
         imh_gather = 0;                        /* clear count gather      */
         imh_data = 0;                          /* clear count data        */
         while (adsl_gai1_h1) {                 /* loop over data to send  */
           imh_gather++;                        /* increment count gather  */
           imh3 = adsl_gai1_h1->achc_ginp_end - adsl_gai1_h1->achc_ginp_cur;
    //     if (   (iml3 < 0)
    //         || (iml3 > + LEN_TCP_RECV)) {
    //     }
           imh4 = 0X01000000;
           if (   (adsl_gai1_h1->achc_ginp_cur > (char *) adsl_sdhc1_h1)
               && (adsl_gai1_h1->achc_ginp_cur < ((char *) adsl_sdhc1_h1 + LEN_TCP_RECV))) {
             imh4 = ((char *) adsl_sdhc1_h1 + LEN_TCP_RECV) - adsl_gai1_h1->achc_ginp_cur;
           }
           if (   (imh3 < 0)
               || (imh3 > imh4)) {
             while (TRUE) {
               m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd92 entry Gather of sdhc1=%p invalid length=%d/0X%X",
                               __LINE__, adsl_sdhc1_h1, imh3, imh3 );
#ifndef HL_UNIX
               Sleep( 2000 );
#else
               sleep( 2 );
#endif
             }
           }
           imh_data += imh3;
           adsl_gai1_h1 = adsl_gai1_h1->adsc_next;  /* get next in chain     */
         }
         m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd92 sdhc1=%p function=%d/%s position=%d imc_usage_count=%d gather=%d data=%d",
                         __LINE__,
                         adsl_sdhc1_h1, adsl_sdhc1_h1->inc_function, achl1, adsl_sdhc1_h1->inc_position, adsl_sdhc1_h1->imc_usage_count,
                         imh_gather, imh_data );
       }
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#endif
   if (bol_save_st_sslc != ADSL_CONN1_G->boc_st_sslc) {  /* check status SSL */
     iml1 = 0;                              /* no timer yet            */
     if (ADSL_CONN1_G->adsc_gate1->itimeout > 0) {  /* timeout set     */
       iml1 = ADSL_CONN1_G->adsc_gate1->itimeout;  /* get number of seconds */
     }
     if (ADSL_CONN1_G->imc_timeout_set) {   /* timeout set in seconds  */
       iml1 = ADSL_CONN1_G->imc_timeout_set;  /* timeout set in seconds */
     }
     if (   (ADSL_CONN1_G->adsc_server_conf_1)
         && (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout)) {
       if (iml1 == 0) {                     /* no timer set yet        */
         iml1 = ADSL_CONN1_G->adsc_server_conf_1->inc_timeout;
       }
       if (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout < iml1) {
         iml1 = ADSL_CONN1_G->adsc_server_conf_1->inc_timeout;
       }
     }
     if (iml1) {                            /* timer set               */
       ADSL_CONN1_G->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time timeout  */
     } else {
       ADSL_CONN1_G->ilc_timeout = 0;       /* clear end-time timeout  */
     }
     if (ADSL_CONN1_G->adsc_gate1->ifunction < 0) {  /* load-balancing required */
       ADSL_CONN1_G->iec_st_ses = ied_ses_do_lbal;  /* status do load-balancing */
     }
   }
   if (dsl_pd_work.inc_count_proc_end == 0) goto pcopd20;  /* normal processing */
   if (   (dsl_pd_work.inc_count_proc_end == 1)  /* process start of connection */
       && (bol_save_st_sslc == ADSL_CONN1_G->boc_st_sslc)) {  /* check status SSL */
     dsl_pd_work.inc_count_proc_end = 0;    /* process data normal     */
   }
#ifdef TRACEHL_090427_01
   if (dsl_pd_work.inc_count_proc_end == 2) {  /* process end of connection */
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd92", __LINE__ );
     Sleep( 1000 );
   }
#endif
#ifdef B120903
   if (dsl_pd_work.inc_count_proc_end < 0) {  /* start process end of connection */
     dsl_pd_work.inc_count_proc_end = 2;    /* process end of connection */
   }
   goto pcopd20;                            /* proceed                 */
#else
   if (dsl_pd_work.inc_count_proc_end >= 0) {  /* not process end of connection */
     goto pcopd20;                          /* proceed                 */
   }
   dsl_pd_work.inc_count_proc_end = 2;      /* process end of connection */
#ifndef B120916
   if (ADSL_CONN1_G->boc_sdh_started == FALSE) {  /* Server-Data-Hooks have not been started */
     goto pcopd60;                          /* continue process output */
   }
#endif
   bol_sdh_tose = TRUE;                     /* something to server     */
   goto pcopd60;                            /* continue process output */
#endif
} /* end m_proc_data()                                                 */
#undef ADSL_CONN1_G

/** primary routine garbage collection                                 */
static inline void m_garb_coll_1( DSD_CONN_G *adsp_conn1 ) {  /* do garbage collect */
#ifndef B150217
   int        iml1;                         /* working variable        */
#endif
#ifdef TRY_120405_01                        /* optimize sdhc1 garbage collector */
   int        iml_cmp_function;             /* function of SDH         */
   int        iml_cmp_position;             /* position of SDH         */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location    */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location      */
#ifdef TRY_120924_01                        /* problem in garbage-collector */
   struct dsd_sdh_control_1 *adsl_sdhc1_free;  /* entries to be freed  */
#endif
   struct dsd_send_server_1 *adsl_send_server_1_w1;  /* for send to server */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
#ifndef B150217
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace area          */
#endif

   if (adsp_conn1->adsc_sdhc1_chain == NULL) {  /* no input output buffers */
     goto pgaco60;                          /* check work areas in use */
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = adsp_conn1->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d m_garb_coll_1 start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRY_120924_01                        /* problem in garbage-collector */
   adsl_sdhc1_free = NULL;                  /* clear chain entries to be freed */
#endif
   adsl_sdhc1_cur_1 = adsp_conn1->adsc_sdhc1_chain;
   adsl_sdhc1_last_1 = NULL;                /* no previous entry       */
#ifdef TRY_120405_01                        /* optimize sdhc1 garbage collector */
   iml_cmp_function = 0;                    /* function of SDH         */
#endif

   pgaco20:                                 /* process this entry      */
#ifdef TRY_120405_01                        /* optimize sdhc1 garbage collector */
   if (   (adsl_sdhc1_cur_1->inc_function == iml_cmp_function)  /* function of SDH */
       && (adsl_sdhc1_cur_1->inc_position == iml_cmp_position)) {  /* position of SDH */
     goto pgaco40;                          /* reference found         */
   }
#endif
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor        */
   while (adsl_sdhc1_w1) {                  /* loop over all entries   */
     adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
     adsl_gai1_last = NULL;
     while (TRUE) {                         /* loop over all entries   */
       if (adsl_gai1_cur == NULL) break;    /* no more element         */
#ifndef TRY_150218_01                       /* problem gather          */
       /* check if still data                                          */
       if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
         if (adsl_gai1_last == NULL) {      /* first element now       */
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_cur->adsc_next;
         } else {                           /* middle in chain         */
           adsl_gai1_last->adsc_next = adsl_gai1_cur->adsc_next;
         }
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         continue;
       }
#endif
#ifdef TRY_150218_01                       /* problem gather          */
       if (adsl_gai1_cur->achc_ginp_cur < adsl_gai1_cur->achc_ginp_end) {
#endif
       /* check if gather structure in this block                      */
       if (   (((char *) adsl_gai1_cur) >= ((char *) adsl_sdhc1_cur_1))
           && (((char *) adsl_gai1_cur) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
       /* check if any data in this block                              */
       if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsl_sdhc1_cur_1))
           && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
#ifdef TRY_150218_01                       /* problem gather          */
       }
#endif
       adsl_gai1_last = adsl_gai1_cur;      /* this is last element now */
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   /* check extra send server                                          */
   adsl_sdhc1_w1 = NULL;                    /* nothing to be checked   */
   switch (adsp_conn1->iec_servcotype) {
     case ied_servcotype_normal_tcp:        /* normal TCP              */
#ifndef HL_UNIX
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dcl_tcp_r_s.adsc_sdhc1_send;  /* get start of chain */
#else
#ifdef B120502
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* get chain to send to server */
#else
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dsc_tc1_server.adsc_sdhc1_send;  /* get chain to send to server */
#endif
#endif
       break;
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HOB-TUN                 */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_htun_sch;  /* get start of chain */
       break;
#endif
     case ied_servcotype_l2tp:              /* L2TP                    */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_l2tp_sch;  /* send buffers */
       break;
   }
#ifdef DEBUG_130509_01                      /* 09.05.13 KB check queue send buffers */
   {
     int imh1;
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;  /* working variable     */

     imh1 = 0;
     adsl_sdhc1_h1 = adsl_sdhc1_w1;
     while (adsl_sdhc1_h1) {
       imh1++;
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
     if (imh1 > DEBUG_130509_01) {
       m_hlnew_printf( HLOG_TRACE1, "m_garb_coll_1() l%05d SDH control send buffers count %d.",
                       __LINE__, imh1 );
     }
   }
#endif  /* DEBUG_130509_01                     09.05.13 KB check queue send buffers */
#ifndef NOT_TRY_130509_01
   while (adsl_sdhc1_w1) {                  /* loop over all entries   */
     adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
#ifndef TRY_120924_02                       /* problem in garbage-collector */
     while (TRUE) {                         /* loop over all entries   */
       if (adsl_gai1_cur == NULL) break;    /* no more element         */
#ifdef TRY_150217_01                        /* problem garbage-collector */
       if (adsl_gai1_cur->achc_ginp_cur < adsl_gai1_cur->achc_ginp_end) {
         goto pgaco40;                      /* reference found         */
       }
#endif
       /* check if gather structure in this block                      */
       if (   (((char *) adsl_gai1_cur) >= ((char *) adsl_sdhc1_cur_1))
           && (((char *) adsl_gai1_cur) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
       /* check if still data                                          */
       if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         continue;
       }
       /* check if any data in this block                              */
       if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsl_sdhc1_cur_1))
           && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
     }
#endif
#ifdef TRY_120924_02                        /* problem in garbage-collector */
     adsl_gai1_last = NULL;
     while (TRUE) {                         /* loop over all entries   */
       if (adsl_gai1_cur == NULL) break;    /* no more element         */
       /* check if still data                                          */
#ifndef TRY_150218_01                       /* problem gather          */
       if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
         if (adsl_gai1_last == NULL) {      /* first element now       */
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_cur->adsc_next;
         } else {                           /* middle in chain         */
           adsl_gai1_last->adsc_next = adsl_gai1_cur->adsc_next;
         }
#ifdef XYZ1
#ifdef TRY_150218_01                        /* problem gather          */
/* 18.02.15 KB - set adsl_gai1_last */
         adsl_gai1_last = adsl_gai1_cur;    /* is last now             */
#endif
#endif
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         continue;
       }
#endif
#ifdef TRY_150218_01                       /* problem gather          */
       if (adsl_gai1_cur->achc_ginp_cur < adsl_gai1_cur->achc_ginp_end) {
#endif
       /* check if gather structure in this block                      */
       if (   (((char *) adsl_gai1_cur) >= ((char *) adsl_sdhc1_cur_1))
           && (((char *) adsl_gai1_cur) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
       /* check if any data in this block                              */
       if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsl_sdhc1_cur_1))
           && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
         goto pgaco40;                      /* reference found         */
       }
#ifdef TRY_150218_01                       /* problem gather          */
       }
#endif
       adsl_gai1_last = adsl_gai1_cur;      /* this is last element now */
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
     }
#endif
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
#endif
#ifdef NOT_TRY_130509_01
   if (adsl_sdhc1_w1 == NULL) {             /* no SDH control found    */
     goto pgaco32;                          /* end of check SDH control */
   }

   pgaco24:                                 /* check SDH control       */
   adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
   if (adsl_gai1_cur == NULL) {             /* no more gather          */
     goto pgaco28;                          /* end of gather in SDH control */
   }
   if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
//#ifndef TRY_150218_01                       /* problem gather          */
     adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_cur->adsc_next;  /* gather no more in use */
//#endif
     goto pgaco24;                          /* check SDH control       */
   }
   do {                                     /* loop over all entries   */
     /* check if gather structure in this block                        */
     if (   (((char *) adsl_gai1_cur) >= ((char *) adsl_sdhc1_cur_1))
         && (((char *) adsl_gai1_cur) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
       goto pgaco40;                        /* reference found         */
     }
     /* check if still data                                            */
     if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;
       continue;
     }
     /* check if any data in this block                                */
     if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsl_sdhc1_cur_1))
         && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
       goto pgaco40;                        /* reference found         */
     }
     adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain   */
   } while (adsl_gai1_cur);

   pgaco28:                                 /* end of gather in SDH control */
   adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in SDH control in chain */
   if (adsl_sdhc1_w1) {                     /* continue processing     */
     goto pgaco24;                          /* check SDH control       */
   }

   pgaco32:                                 /* end of check SDH control */
#endif
   adsl_sdhc1_w1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain  */
   /* we need one entry in the chain to activate the SDHs              */
   while (adsl_sdhc1_cur_1->iec_sdhcs != ied_sdhcs_idle) {  /* not idle, has not been processed */
     if (   (adsl_sdhc1_w1)
         && (adsl_sdhc1_w1->inc_function == adsl_sdhc1_cur_1->inc_function)
         && (adsl_sdhc1_w1->inc_position == adsl_sdhc1_cur_1->inc_position)) {  /* position send to client */
       break;                               /* same one follows        */
     }
     if (   (adsl_sdhc1_last_1)
         && (adsl_sdhc1_last_1->inc_function == adsl_sdhc1_cur_1->inc_function)
         && (adsl_sdhc1_last_1->inc_position == adsl_sdhc1_cur_1->inc_position)) {  /* position send to client */
       break;                               /* already one in chain    */
     }
     goto pgaco40;                          /* needs to be processed later */
   }
#ifdef DEBUG_150218_01                      /* problem gather          */
   if (   (adsl_sdhc1_cur_1->adsc_gather_i_1_i)
       && (((char *) adsl_sdhc1_cur_1->adsc_gather_i_1_i) >= ((char *) adsl_sdhc1_cur_1))
       && (((char *) adsl_sdhc1_cur_1->adsc_gather_i_1_i) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))
       && (adsl_sdhc1_cur_1->adsc_gather_i_1_i->achc_ginp_cur
             < adsl_sdhc1_cur_1->adsc_gather_i_1_i->achc_ginp_end)) {
     m_hlnew_printf( HLOG_TRACE1, "DEBUG_150218_01 l%05d free invalid !!! adsl_sdhc1_cur_1=%p adsl_sdhc1_cur_1->adsc_gather_i_1_i=%p.",
                     __LINE__, adsl_sdhc1_cur_1, adsl_sdhc1_cur_1->adsc_gather_i_1_i );
   }
#endif
#ifndef B150217
   if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SGARBC01", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                     "garbage-collector l%05d free sdhc1 %p adsc_next=%p function=%d position=%d adsc_gather_i_1_i=%p adsl_sdhc1_last_1=%p.",
                     __LINE__, adsl_sdhc1_cur_1,
                     adsl_sdhc1_cur_1->adsc_next,
                     adsl_sdhc1_cur_1->inc_function, adsl_sdhc1_cur_1->inc_position,
                     adsl_sdhc1_cur_1->adsc_gather_i_1_i,
                     adsl_sdhc1_last_1 );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
#ifdef DEBUG_150218_01                      /* problem gather          */
     if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) {
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "SGARBCX1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
       iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                       "ga-co l%05d free sdhc1 %p adsc_gather_i_1_i=%p achc_ginp_cur=%p achc_ginp_end=%p.",
                       __LINE__, adsl_sdhc1_cur_1,
                       adsl_sdhc1_cur_1->adsc_gather_i_1_i,
                       adsl_sdhc1_cur_1->adsc_gather_i_1_i->achc_ginp_cur,
                       adsl_sdhc1_cur_1->adsc_gather_i_1_i->achc_ginp_end );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
       ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     }
#endif
   }
#endif
   /* this block is not needed any longer                              */
   if (adsl_sdhc1_last_1 == NULL) {         /* first element now       */
     adsp_conn1->adsc_sdhc1_chain = adsl_sdhc1_w1;
   } else {                                 /* middle in chain         */
     adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
   }
   adsl_sdhc1_w1 = adsl_sdhc1_cur_1;        /* save this element       */
   adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
#ifdef TRACEHL_T_050131
   m_hlnew_printf( HLOG_XYZ1, "proc_free x m_garb_coll_1()" );
#endif
   if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use           */
#ifndef TRY_120924_01                       /* problem in garbage-collector */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
#else
     adsl_sdhc1_w1->adsc_next = adsl_sdhc1_free;  /* get entries to be freed */
     adsl_sdhc1_free = adsl_sdhc1_w1;       /* set new chain entries to be freed */
#endif
   } else {                                 /* work area still in use  */
#ifndef HL_UNIX
     EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
     adsp_conn1->dsc_critsect.m_enter();    /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
     m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                     __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#endif
     adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* get old chain in use */
     adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* set new anchor  */
#ifndef HL_UNIX
     LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
     adsp_conn1->dsc_critsect.m_leave();    /* critical section        */
#endif
   }
   if (adsl_sdhc1_cur_1) goto pgaco20;      /* process this entry      */
#ifndef TRY_120924_01                       /* problem in garbage-collector */
   goto pgaco60;                            /* check work areas in use */
#else
   goto pgaco56;                            /* free entries            */
#endif

   pgaco40:                                 /* reference found         */
#ifdef TRY_120405_01                        /* optimize sdhc1 garbage collector */
   iml_cmp_function = adsl_sdhc1_cur_1->inc_function;  /* function of SDH */
   iml_cmp_position = adsl_sdhc1_cur_1->inc_position;  /* position of SDH */
#endif
   adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;    /* save previous entry     */
   adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;
   if (adsl_sdhc1_cur_1) goto pgaco20;      /* process this entry      */

#ifdef TRY_120924_01                        /* problem in garbage-collector */
   pgaco56:                                 /* free entries            */
   while (adsl_sdhc1_free) {                /* entries to be freed     */
     adsl_sdhc1_w1 = adsl_sdhc1_free;       /* get entry to be freed   */
     adsl_sdhc1_free = adsl_sdhc1_free->adsc_next;  /* remove from chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
#endif

   pgaco60:                                 /* check work areas in use */
   if (   (adsp_conn1->adsc_sdhc1_inuse == NULL)  /* no work areas in use */
       && (adsp_conn1->adsc_sdhc1_extra == NULL)) {  /* no buffers extra */
     goto pgaco80;                          /* all checked             */
   }
   adsl_sdhc1_last_1 = NULL;                /* no previous entry       */
#ifndef HL_UNIX
   EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_enter();      /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#endif
   adsl_sdhc1_cur_1 = adsp_conn1->adsc_sdhc1_inuse;
   while (TRUE) {                           /* loop over all entries   */
     if (adsl_sdhc1_cur_1 == NULL) break;   /* end of chain reached    */
#ifdef D_ALERT_01                           /* 07.04.10 KB - check if illogic */
     if (   (adsl_sdhc1_cur_1->imc_usage_count < 0)
         || (adsl_sdhc1_cur_1->imc_usage_count > 512)) {
       m_hlnew_printf( HLOG_XYZ1, "m_garb_coll_1() l%05d adsl_sdhc1_cur_1=%p imc_usage_count illogic",
                       adsl_sdhc1_cur_1, __LINE__ );
       char *achh1 = NULL;
       *achh1 = 'E';
     }
#endif
     if (adsl_sdhc1_cur_1->imc_usage_count == 0) {  /* not in use      */
#ifndef B110315
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor    */
       while (adsl_sdhc1_w1) {              /* loop over all entries   */
         adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
         while (TRUE) {                     /* loop over all entries   */
           if (adsl_gai1_cur == NULL) break;  /* no more element       */
           /* check if gather structure in this block                  */
           if (   (((char *) adsl_gai1_cur) >= ((char *) adsl_sdhc1_cur_1))
               && (((char *) adsl_gai1_cur) < ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
             break;                         /* reference found         */
           }
           /* check if still data                                      */
           if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
             adsl_gai1_cur = adsl_gai1_cur->adsc_next;
             continue;
           }
           /* check if any data in this block                          */
           if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsl_sdhc1_cur_1))
               && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsl_sdhc1_cur_1 + LEN_TCP_RECV))) {
             break;                         /* reference found         */
           }
           adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
         }
         if (adsl_gai1_cur) break;          /* reference found         */
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_w1) break;            /* reference found         */
#endif
#ifndef B150217
       if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "SGARBC02", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
         iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                         "garbage-collector l%05d free sdhc1 %p adsc_next=%p function=%d position=%d adsc_gather_i_1_i=%p adsl_sdhc1_last_1=%p.",
                         __LINE__, adsl_sdhc1_cur_1,
                         adsl_sdhc1_cur_1->adsc_next,
                         adsl_sdhc1_cur_1->inc_function, adsl_sdhc1_cur_1->inc_position,
                         adsl_sdhc1_cur_1->adsc_gather_i_1_i,
                         adsl_sdhc1_last_1 );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
         ADSL_WTR_G1->achc_content              /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
       }
#endif
       /* this block is not needed any longer                          */
       if (adsl_sdhc1_last_1 == NULL) {     /* first element now       */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_cur_1->adsc_next;
       } else {                             /* middle in chain         */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_cur_1->adsc_next;
       }
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* save this element       */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
       continue;
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set previous entry      */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   adsl_sdhc1_last_1 = NULL;                /* no previous entry       */
   adsl_sdhc1_cur_1 = adsp_conn1->adsc_sdhc1_extra;
   while (TRUE) {                           /* loop over all entries   */
     if (adsl_sdhc1_cur_1 == NULL) break;   /* end of chain reached    */
#ifdef D_ALERT_01                           /* 07.04.10 KB - check if illogic */
     if (   (adsl_sdhc1_cur_1->imc_usage_count < 0)
         || (adsl_sdhc1_cur_1->imc_usage_count > 512)) {
       m_hlnew_printf( HLOG_XYZ1, "m_garb_coll_1() l%05d adsl_sdhc1_cur_1=%p imc_usage_count illogic",
                       adsl_sdhc1_cur_1, __LINE__ );
       char *achh1 = NULL;
       *achh1 = 'E';
     }
#endif
     if (   (adsl_sdhc1_cur_1->imc_usage_count == 0)  /* not in use    */
         && (m_garb_coll_2( adsp_conn1, adsl_sdhc1_cur_1 ) == FALSE)) {
       /* this block is not needed any longer                          */
       if (adsl_sdhc1_last_1 == NULL) {     /* first element now       */
         adsp_conn1->adsc_sdhc1_extra = adsl_sdhc1_cur_1->adsc_next;
       } else {                             /* middle in chain         */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_cur_1->adsc_next;
       }
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* save this element       */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
       continue;
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set previous entry      */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif

   pgaco80:                                 /* all checked             */
#ifdef TRACEHL_T_050130
   m_hlnew_printf( HLOG_XYZ1, "m_garb_coll_1() returns - adsc_sdhc1_chain=%p adsc_sdhc1_inuse=%p",
                   adsp_conn1->adsc_sdhc1_chain, adsp_conn1->adsc_sdhc1_inuse );
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = adsp_conn1->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d m_garb_coll_1 end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   return;                                  /* all done                */
} /* end m_garb_coll_1()                                               */

/** seconary routine garbage collection                                */
static inline BOOL m_garb_coll_2( DSD_CONN_G *adsp_conn1, struct dsd_sdh_control_1 *adsp_sdhc1 ) {  /* do garbage collect */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */

#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = adsp_conn1->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d m_garb_coll_2 start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor        */
   while (adsl_sdhc1_w1) {                  /* loop over all entries   */
     adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
     while (TRUE) {                         /* loop over all entries   */
       if (adsl_gai1_cur == NULL) break;    /* no more element         */
       /* check if still data                                          */
       if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         continue;
       }
       /* check if gather structure in this block                      */
       if (   (((char *) adsl_gai1_cur) >= ((char *) adsp_sdhc1))
           && (((char *) adsl_gai1_cur) < ((char *) adsp_sdhc1 + LEN_TCP_RECV))) {
         return TRUE;                       /* reference found         */
       }
       /* check if any data in this block                              */
       if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsp_sdhc1))
           && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsp_sdhc1 + LEN_TCP_RECV))) {
         return TRUE;                       /* reference found         */
       }
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = adsp_conn1->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "main-l%05d m_garb_coll_2 end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifndef B070629
   /* process entries that are already scheduled for sending           */
   adsl_sdhc1_w1 = NULL;                    /* nothing to be checked   */
   switch (adsp_conn1->iec_servcotype) {
     case ied_servcotype_normal_tcp:        /* normal TCP              */
#ifndef HL_UNIX
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dcl_tcp_r_s.adsc_sdhc1_send;  /* get start of chain */
#else
#ifdef B120502
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dsc_vol_a_sdhc1_ts_se.adsc_sdhc1;  /* get chain to send to server */
#else
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) adsp_conn1->dsc_tc1_server.adsc_sdhc1_send;  /* get chain to send to server */
#endif
#endif
       break;
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HTUN                    */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_htun_sch;  /* get start of chain */
       break;
#endif
     case ied_servcotype_l2tp:              /* L2TP                    */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_l2tp_sch;  /* send buffers */
       break;
   }
   while (adsl_sdhc1_w1) {                  /* loop over all entries   */
     adsl_gai1_cur = adsl_sdhc1_w1->adsc_gather_i_1_i;
     while (TRUE) {                         /* loop over all entries   */
       if (adsl_gai1_cur == NULL) break;    /* no more element         */
       /* check if gather structure in this block                      */
       if (   (((char *) adsl_gai1_cur) >= ((char *) adsp_sdhc1))
           && (((char *) adsl_gai1_cur) < ((char *) adsp_sdhc1 + LEN_TCP_RECV))) {
         return TRUE;                       /* reference found         */
       }
       /* check if still data                                          */
       if (adsl_gai1_cur->achc_ginp_cur >= adsl_gai1_cur->achc_ginp_end) {
         adsl_gai1_cur = adsl_gai1_cur->adsc_next;
         continue;
       }
       /* check if any data in this block                              */
       if (   (adsl_gai1_cur->achc_ginp_cur >= ((char *) adsp_sdhc1))
           && (adsl_gai1_cur->achc_ginp_end <= ((char *) adsp_sdhc1 + LEN_TCP_RECV))) {
         return TRUE;                       /* reference found         */
       }
       adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
#endif
   return FALSE;                            /* no reference found      */
} /* end m_garb_coll_2()                                               */

/** send data to server                                                */
static BOOL m_do_send_server( struct dsd_hco_wothr *adsp_hco_wothr, DSD_CONN_G *adsp_conn1 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol1;                         /* working varibale        */
   int        iml1;                         /* working variable        */
#ifdef D_INCL_HOB_TUN
#ifndef B121212
   dsd_htun_h dsl_htun_h;                   /* handle for HOB-TUN      */
#endif
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_cur;    /* current location        */
   struct dsd_gather_i_1 *adsl_gai1_last;   /* last location           */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef D_INCL_HOB_TUN
#ifndef B130710
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
#endif
#ifndef B140828
   struct dsd_gather_i_1 *adsl_gai1_w3;     /* working variable        */
#endif
#endif

   iml1 = 0;
   if (adsp_conn1->adsc_csssl_oper_1) {     /* process Client-Side-SSL */
     iml1 = -1;                             /* only send direct        */
   }
   adsl_sdhc1_cur_1 = adsp_conn1->adsc_sdhc1_chain;  /* get chain      */
   adsl_sdhc1_last_1 = NULL;                /* clear last element      */
   while (adsl_sdhc1_cur_1) {               /* loop over all buffers   */
     if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
         && (adsl_sdhc1_cur_1->inc_position < iml1)) {
       break;
     }
     adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* save previous in chain  */
     adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
   }
   if (adsl_sdhc1_cur_1 == NULL) return FALSE;  /* no data to send     */
#ifdef TRY_110523_03                        /* changes Mr. Jakob HOB-TUN / HTCP */
   if (   (adsp_conn1->iec_servcotype == ied_servcotype_htun)  /* HOB-TUN */
       && (adsp_conn1->adsc_ineta_raws_1 == NULL)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxxW GATE=%(ux)s SNO=%08d INETA=%s m_proc_data l%05d pcopd80 send-to-server but no ineta_raws",
                     adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 send-to-server adsl_sdhc1_cur_1=%p.",
                   __LINE__, adsl_sdhc1_cur_1 );
#endif
   /* remove data to send from chain                                   */
   if (adsl_sdhc1_last_1 == NULL) {         /* at start of chain       */
     adsp_conn1->adsc_sdhc1_chain = NULL;   /* no more data in chain   */
   } else {                                 /* middle in chain         */
     adsl_sdhc1_last_1->adsc_next = NULL;   /* clear end of chain      */
   }
   /* count data sent to server                                        */
   bol1 = FALSE;                            /* no data found yet       */
   adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
   while (adsl_gai1_w1) {                   /* loop over data to send  */
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml1) {                            /* data to send found      */
       adsp_conn1->ilc_d_ns_send_s += iml1;  /* data send server       */
       bol1 = TRUE;                         /* data found              */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (bol1 == FALSE) {                     /* no data found           */
     /* free all buffers                                               */
     do {
       adsl_sdhc1_w1 = adsl_sdhc1_cur_1;    /* get first buffer        */
       adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* remove block from chain */
       if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use       */
         m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
       } else {                             /* work area still in use  */
#ifndef HL_UNIX
         EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
         adsp_conn1->dsc_critsect.m_enter();  /* critical section      */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
         m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                         __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#endif
         adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
         adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
#ifndef HL_UNIX
         LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
         adsp_conn1->dsc_critsect.m_leave();  /* critical section      */
#endif
       }
     } while (adsl_sdhc1_cur_1);
     return TRUE;                           /* all done                */
   }
   adsp_conn1->inc_c_ns_send_s++;           /* count send server       */
#ifdef PROB070717
   if (adsl_sdhc1_cur_1->adsc_gather_i_1_i == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "m_proc_data l%05d pcopd80 send-to-server adsl_sdhc1_cur_1=%p ->adsc_gather_i_1_i == NULL",
                     __LINE__, adsl_sdhc1_cur_1 );
   }
#endif
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 - iec_st_ses=%d adsl_sdhc1_cur_1=%p.",
                   __LINE__, adsp_conn1->iec_st_ses, adsl_sdhc1_cur_1 );
#endif
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( adsp_conn1->adsc_sdhc1_chain, "pd_main m_do_send_server: 01", __LINE__ );
#endif
   switch (adsp_conn1->iec_servcotype) {    /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
#ifndef HL_UNIX
       adsp_conn1->dcl_tcp_r_s.m_send_gather( adsl_sdhc1_cur_1, FALSE );
#else
#ifdef B110810
       m_tcp_send_1( adsp_conn1, TRUE, adsl_sdhc1_cur_1 );
#endif
       m_send_clse_tcp_1( adsp_conn1, &adsp_conn1->dsc_tc1_server, adsl_sdhc1_cur_1, FALSE );
#endif
       break;
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HOB-TUN                 */
#ifndef B130710
       adsl_gai1_w2 = NULL;
#endif
       if (adsp_conn1->adsc_sdhc1_htun_sch) {  /* check start of chain */
         adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_htun_sch;  /* get start of chain */
#ifdef B130710
         while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
#endif
#ifndef B130710
         while (TRUE) {                     /* loop over all old SDHC1 */
           if (   (adsl_gai1_w2 == NULL)    /* gather not yet set      */
               && (adsl_sdhc1_w1->adsc_gather_i_1_i)) {  /* gather found */
             adsl_gai1_w2 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* set first gather */
#ifndef B140828
             adsl_gai1_w3 = adsl_gai1_w2;   /* save first gather for send routine */
#endif
             while (adsl_gai1_w2->adsc_next) adsl_gai1_w2 = adsl_gai1_w2->adsc_next;
           }
           if (adsl_sdhc1_w1->adsc_next == NULL) break;  /* end of chain */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next SDHC1 in chain */
         }
#endif
         adsl_sdhc1_w1->adsc_next = adsl_sdhc1_cur_1;  /* append new blocks to the chain */
       } else {                             /* we build the chain now  */
         adsp_conn1->adsc_sdhc1_htun_sch = adsl_sdhc1_cur_1;  /* set start of chain */
       }
#ifdef B130710
       /* all gather structure need to be chained together             */
       adsl_sdhc1_cur_1 = adsp_conn1->adsc_sdhc1_htun_sch;  /* get start of chain */
       do {                                 /* loop to find first gather */
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;  /* gather found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_cur_1);
       if (adsl_sdhc1_cur_1 == NULL) break;
#ifdef XYZ1
       adsl_gai1_w1 = adsl_gai1_cur = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get first gather */
       while (adsl_gai1_cur->adsc_next) adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* last gather */
#endif
       adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get first gather */
       while (TRUE) {                       /* loop to append sdhc1 blocks */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
         if (adsl_sdhc1_cur_1 == NULL) break;
         if (adsl_sdhc1_cur_1->adsc_gather_i_1_i) {  /* gather in this block */
           adsl_gai1_cur = adsl_gai1_w1;    /* get first gather        */
           do {
             if (adsl_gai1_cur == adsl_sdhc1_cur_1->adsc_gather_i_1_i) break;  /* gather found */
             adsl_gai1_last = adsl_gai1_cur;  /* save last location    */
             adsl_gai1_cur = adsl_gai1_cur->adsc_next;  /* get next in chain */
           } while (adsl_gai1_cur);
           if (adsl_gai1_cur == NULL) {     /* we need to append to the chain of gather */
             adsl_gai1_last->adsc_next = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* append new gather */
           }
         }
       }
#endif
#ifndef B130710
       while (adsl_sdhc1_cur_1) {           /* check new chain         */
         adsl_gai1_w1 = adsl_sdhc1_cur_1->adsc_gather_i_1_i;  /* get first gather */
         if (adsl_gai1_w1) break;           /* check first gather      */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_cur_1 == NULL) break;  /* no data in new chain   */
       if (adsl_gai1_w2) {                  /* found old chain         */
         adsl_gai1_w2->adsc_next = adsl_gai1_w1;  /* append new chain to old chain */
#ifndef B140828
         adsl_gai1_w1 = adsl_gai1_w3;       /* pass first gather to send routine */
#endif
       }
#endif
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (adsp_conn1->adsc_auxf_1_htun + 1))
#ifdef B120208
       adsp_conn1->adsc_ineta_raws_1->imc_state |= DEF_STATE_HTUN_SEND_COMPL;  /* done HTUN send complete - m_htun_htcp_send_complete() */
#else
       if (adsp_conn1->adsc_ineta_raws_1) {  /* INETA still valid      */
         adsp_conn1->adsc_ineta_raws_1->imc_state |= DEF_STATE_HTUN_SEND_COMPL;  /* done HTUN send complete - m_htun_htcp_send_complete() */
       }
#endif
#ifdef DEBUG_100824_01
       m_hlnew_printf( HLOG_XYZ1, "clconn1::m_proc_data l%05d pcopd80 before m_htun_sess_send() - adsl_gai1_w1=%p adsc_sdhc1_htun_sch=%p.",
                       __LINE__, adsl_gai1_w1, adsp_conn1->adsc_sdhc1_htun_sch );
#endif
#ifdef B110502
#ifndef NEW_HOB_TUN_1103
       m_htun_sess_send( adsp_conn1->adsc_ineta_raws_1->dsc_htun_h,
                         adsl_gai1_w1 );
#else
       m_htun_sess_send( adsp_conn1->dsc_htun_h,
                         adsl_gai1_w1 );
#endif
#else
#ifndef NEW_HOB_TUN_1103
#ifdef B121212
       m_htun_sess_send( adsp_hco_wothr,
                         adsp_conn1->adsc_ineta_raws_1->dsc_htun_h,
                         adsl_gai1_w1 );
#else
       dsl_htun_h = adsp_conn1->dsc_htun_h;  /* handle for HOB-TUN     */
       if (adsp_conn1->adsc_ineta_raws_1) {  /* with INETA             */
         dsl_htun_h = adsp_conn1->adsc_ineta_raws_1->dsc_htun_h;  /* handle for HOB-TUN */
       }
       m_htun_sess_send( adsp_hco_wothr,
                         dsl_htun_h,
                         adsl_gai1_w1 );
#endif
#else
       m_htun_sess_send( adsp_hco_wothr,
                         adsp_conn1->dsc_htun_h,
                         adsl_gai1_w1 );
#endif
#endif
//#undef ADSL_INETA_RAWS_1_G
       break;
#endif
     case ied_servcotype_l2tp:              /* L2TP                    */
       bol_rc = m_ext_send_server( adsp_hco_wothr, adsp_conn1, adsl_sdhc1_cur_1 );
       if (bol_rc) break;
       if (adsp_conn1->achc_reason_end == NULL) {  /* reason end session */
         adsp_conn1->achc_reason_end = "abend while sending data";
       }
#ifndef HL_UNIX
       adsp_conn1->iec_st_ses = clconn1::ied_ses_abend;
#else
       adsp_conn1->iec_st_ses = ied_ses_abend;
#endif
       return FALSE;
   }
#ifdef DEBUG_150218_01                      /* problem gather          */
   m_check_gai_recv_server_1( adsp_conn1->adsc_sdhc1_chain, "pd_main m_do_send_server: 02", __LINE__ );
#endif
   return TRUE;
} /* end m_do_send_server()                                            */

/** extended send to server                                            */
static BOOL m_ext_send_server( struct dsd_hco_wothr *adsp_hco_wothr, DSD_CONN_G *adsp_conn1, struct dsd_sdh_control_1 *adsp_sdhc1_send ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_gai1;                     /* count send buffers      */
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_cont;                     /* continue sending        */
#ifdef B100818
   BOOL       bol_crsect;                   /* critical section        */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_send;  /* buffers to send      */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
#ifndef HL_UNIX
   struct dsd_send_gai1_1 dsrl_send_gai1_1[ DEF_SEND_WSASEND ];  /* block passed to send function */
#else
   struct dsd_send_gai1_1 dsrl_send_gai1_1[ DEF_SEND_IOVEC ];  /* block passed to send function */
#endif

// to-do 17.01.09 KB - if no work-thread (adsp_hco_wothr == NULL) schedule work-thread
//   needed because target-filter is blocking
#ifdef B100818
   bol_crsect = FALSE;                      /* critical section        */
#endif
   adsl_sdhc1_send = adsp_sdhc1_send;       /* get buffers to send     */
   adsl_sdhc1_w1 = NULL;                    /* no buffers in stock     */
#ifdef B100818
   switch (adsp_conn1->iec_servcotype) {    /* type of server connection */
     case ied_servcotype_htun:              /* HTUN                    */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_htun_sch;  /* get start of chain */
       break;
     case ied_servcotype_l2tp:              /* L2TP                    */
#ifndef HL_UNIX
       EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
       adsp_conn1->dsc_critsect.m_enter();  /* critical section        */
#endif
       bol_crsect = TRUE;                   /* critical section        */
       adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_l2tp_sch;  /* get start of chain */
       adsp_conn1->adsc_sdhc1_l2tp_sch = NULL;  /* chain is empty - maybe subroutine reads this field */
       break;
   }
#endif
#ifndef B100818
#ifndef HL_UNIX
   EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_enter();      /* critical section        */
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-pd-main.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsp_conn1->dsc_critsect );
#endif
#endif
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_l2tp_sch;  /* get start of chain */
   adsp_conn1->adsc_sdhc1_l2tp_sch = NULL;  /* chain is empty - maybe subroutine reads this field */
#endif
   if (adsl_sdhc1_w1) {                     /* already buffers in stock */
     adsl_sdhc1_send = adsl_sdhc1_w1;       /* get start of chain      */
     do {                                   /* loop over all old buffers */
       adsl_sdhc1_w2 = adsl_sdhc1_w1;       /* save last entry         */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
     adsl_sdhc1_w2->adsc_next = adsp_sdhc1_send;  /* append new buffers to chain */
   }
   if (adsl_sdhc1_send == NULL) goto p_send_end;  /* end of sending    */
   /* try to send all buffers now                                      */
   do {                                     /* loop till all sent      */
     iml_gai1 = 0;                          /* number of buffers       */
     bol_cont = FALSE;                      /* reset continue sending  */
     adsl_sdhc1_w1 = adsl_sdhc1_send;       /* get chain to send       */
     do {                                   /* loop over chain sdhc1   */
       adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
       while (adsl_gai1_w1) {               /* loop over chain gai1    */
         /* check if not already sent before                           */
         adsl_sdhc1_w2 = adsl_sdhc1_send;   /* get chain to send       */
         adsl_gai1_w2 = NULL;               /* not found till now      */
         while (TRUE) {                     /* loop till this element found */
           if (adsl_sdhc1_w2 == adsl_sdhc1_w1) break;  /* this element found */
           adsl_gai1_w2 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain to send */
           while (adsl_gai1_w2) {           /* loop over all gather structures */
             if (adsl_gai1_w2 == adsl_gai1_w1) break;  /* same element sent before */
             adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
           }
           if (adsl_gai1_w2) break;         /* element sent before     */
           adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
           if (adsl_sdhc1_w2 == NULL) {
#ifdef B110810
             m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_ext_send_server() l%05d logic error or chain corrupted",
                             m_clconn1_gatename( adsp_conn1 ),
                             m_clconn1_sno( adsp_conn1 ),
                             m_clconn1_chrc_ineta( adsp_conn1 ),
                             __LINE__ );
#else
             m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_ext_send_server() l%05d logic error or chain corrupted",
                             adsp_conn1->adsc_gate1 + 1, adsp_conn1->dsc_co_sort.imc_sno, adsp_conn1->chrc_ineta,
                             __LINE__ );
#endif
             break;
           }
         }
         if (adsl_gai1_w2 == NULL) {        /* this gather structure not sent before */
           if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifndef HL_UNIX
             if (iml_gai1 >= DEF_SEND_WSASEND) {
               bol_cont = TRUE;             /* continue sending        */
               break;                       /* nothing more to buffers */
             }
#else
             if (iml_gai1 >= DEF_SEND_IOVEC) {
               bol_cont = TRUE;             /* continue sending        */
               break;                       /* nothing more to buffers */
             }
#endif
             /* data to send found                                     */
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_cur
               = adsl_gai1_w1->achc_ginp_cur;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_end
               = adsl_gai1_w1->achc_ginp_end;
             dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.adsc_next
               = &dsrl_send_gai1_1[ iml_gai1 + 1 ].dsc_gai1_send;
             dsrl_send_gai1_1[ iml_gai1 ].adsc_gai1_org = adsl_gai1_w1;  /* gather input data origin */
             iml_gai1++;                    /* next gather input       */
           }
         }
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_gai1_w1) break;             /* has to send immediately */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     } while (adsl_sdhc1_w1);
     if (iml_gai1 == 0) break;              /* no data to send         */
     dsrl_send_gai1_1[ iml_gai1 - 1 ].dsc_gai1_send.adsc_next = NULL;
#ifndef B100818
     bol_rc = m_l2tp_send( adsp_hco_wothr,
                           &adsp_conn1->dsc_l2tp_session,
                           &dsrl_send_gai1_1[ 0 ].dsc_gai1_send );
#endif
#ifndef B140706
     if (bol_rc == FALSE) {                 /* abend session           */
#ifndef HL_UNIX
       LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
       adsp_conn1->dsc_critsect.m_leave();  /* critical section        */
#endif
       return FALSE;
     }
#endif
     /* mark buffers sent                                              */
     iml1 = iml2 = 0;
     do {                                   /* loop over all buffers sent */
       iml2 += dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_cur
                 - dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur;
       dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur
         = dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_cur;
       if (dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_cur
             < dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_end) {
         break;                             /* not all data sent       */
       }
       bol_cont = TRUE;                     /* continue sending        */
       iml1++;                              /* take next buffer        */
     } while (iml1 < iml_gai1);
     if (iml2 == 0) break;                  /* no data sent            */
   } while (bol_cont);
   /* free buffers                                                     */
   while (adsl_sdhc1_send) {                /* loop over all buffers   */
     adsl_sdhc1_w1 = adsl_sdhc1_send;       /* save this buffer        */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     while (adsl_gai1_w1) {                 /* loop over chain gai1    */
       if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
     if (adsl_gai1_w1) break;               /* not all data sent       */
     adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
#ifdef B120211
#ifdef B111124
#ifdef B110707
     if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use         */
       m_proc_free( adsl_sdhc1_w1 );        /* free this buffer        */
     } else {                               /* work area still in use  */
       m_clconn1_mark_work_area( adsp_conn1, adsl_sdhc1_w1 );
     }
#else
     adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_chain;  /* get anchor old data */
     adsp_conn1->adsc_sdhc1_chain = adsl_sdhc1_w1;  /* set new anchor  */
#endif
#else
     m_clconn1_mark_work_area( adsp_conn1, adsl_sdhc1_w1 );  /* block might contain other data */
#endif
#else
     adsl_sdhc1_w1->adsc_next = adsp_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     adsp_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
#endif
   }

   p_send_end:                              /* end of sending          */
#ifndef B100818
   adsp_conn1->adsc_sdhc1_l2tp_sch = adsl_sdhc1_send;  /* buffers in chain */
#endif
#ifndef HL_UNIX
   LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
   return TRUE;
} /* end m_ext_send_server()                                           */

#ifdef TRACEHL_SDH_01
#ifdef TRACEHL_SDH_02
static DSD_CONN_G *adss_conn1_trace_last = NULL;
static char * achs_msg_trace_last = "";
static int    ims_line_trace_last = 0;
#endif

/** check chains sdhc1 structures of a TCP SSL session                 */
static void m_check_sdhc1( DSD_CONN_G *adsp_conn1, char *achp_msg, int imp_line ) {  /* check order of structures */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_gather;                   /* count gather            */
   int        iml_data;                     /* count data              */
   char       *achl1;                       /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w3;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w4;  /* working variable       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
#ifdef TRACEHL_SDH_02
   DSD_CONN_G *adsl_conn1_trace_cur;
   char *     achl_msg_trace_cur;
   int        iml_line_trace_cur;
   char       *achl_avl_error;              /* error code AVL tree     */
   class clconn1 *adsl_conn_w1;             /* connection              */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_co_sort dsl_co_sort_w1;       /* for connection sort     */
#endif

#ifndef TRACEHL_CHECK_SDH                   /* 22.01.07 KB             */
   return;
#endif
   m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() %s l%05d adsc_sdhc1_chain=%p",
                   achp_msg, imp_line, adsp_conn1->adsc_sdhc1_chain );
   if (adsp_conn1->adsc_sdhc1_chain == NULL) return;
   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor        */
   iml1 = iml1 = -2;                        /* clear variables for compare */
   while (TRUE) {
     if (adsl_sdhc1_w1 == NULL) return;
     achl1 = "invalid";
     switch (adsl_sdhc1_w1->inc_function) {
       case DEF_IFUNC_FROMSERVER:
         achl1 = "FROMSERVER";
         break;
       case DEF_IFUNC_TOSERVER:
         achl1 = "TOSERVER";
         break;
     }
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     iml_gather = 0;                        /* clear count gather      */
     iml_data = 0;                          /* clear count data        */
     while (adsl_gai1_w1) {                 /* loop over data to send  */
       iml_gather++;                        /* increment count gather  */
       iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
//     if (   (iml3 < 0)
//         || (iml3 > + LEN_TCP_RECV)) {
//     }
       iml4 = 0X01000000;
       if (   (adsl_gai1_w1->achc_ginp_cur > (char *) adsl_sdhc1_w1)
           && (adsl_gai1_w1->achc_ginp_cur < ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV))) {
         iml4 = ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - adsl_gai1_w1->achc_ginp_cur;
       }
       if (   (iml3 < 0)
           || (iml3 > iml4)) {
         while (TRUE) {
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d entry Gather of sdhc1=%p invalid length=%d/0X%X",
                           __LINE__, adsl_sdhc1_w1, iml3, iml3 );
#ifndef HL_UNIX
           Sleep( 2000 );
#else
           sleep( 2 );
#endif
         }
       }
       iml_data += iml3;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     }
     m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() sdhc1=%p function=%d/%s position=%d imc_usage_count=%d gather=%d data=%d lines:%d/%d/%d/%d.",
                     adsl_sdhc1_w1, adsl_sdhc1_w1->inc_function, achl1, adsl_sdhc1_w1->inc_position, adsl_sdhc1_w1->imc_usage_count,
                     iml_gather, iml_data,
                     adsl_sdhc1_w1->imc_line_no[0], adsl_sdhc1_w1->imc_line_no[1], adsl_sdhc1_w1->imc_line_no[2], adsl_sdhc1_w1->imc_line_no[3] );
     /* check if Gather is in other SDHC1 entry                        */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     while (adsl_gai1_w1) {                 /* loop over data to send  */
       adsl_sdhc1_w3 = adsl_sdhc1_w4 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor */
       while (TRUE) {                       /* loop over two chains    */
         while (adsl_sdhc1_w3) {            /* loop over all SDHC1     */
           if (   (adsl_sdhc1_w3->inc_function != adsl_sdhc1_w1->inc_function)
               || (adsl_sdhc1_w3->inc_position != adsl_sdhc1_w1->inc_position)) {
             if (   ((char *) adsl_gai1_w1 >= (char *) adsl_sdhc1_w3)
                 && ((char *) adsl_gai1_w1 < (char *) (adsl_sdhc1_w3 + 1))) {
               m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d entry Gather of sdhc1=%p is in sdhc1=%p.",
                               __LINE__, adsl_sdhc1_w1, adsl_sdhc1_w3 );
#ifndef OLD01
               while (TRUE) {
#ifndef HL_UNIX
                 Sleep( 2000 );
#else
                 sleep( 2 );
#endif
                 m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d entry Gather of sdhc1=%p is in sdhc1=%p.",
                                 __LINE__, adsl_sdhc1_w1, adsl_sdhc1_w3 );
               }
#else
#ifndef HL_UNIX
               ExitProcess( 3 );
#else
               exit( 3 );
#endif
#endif
             }
           }
           adsl_sdhc1_w3 = adsl_sdhc1_w3->adsc_next;  /* get next in chain */
         }
         if (adsl_sdhc1_w4 != adsp_conn1->adsc_sdhc1_chain) break;  /* not first chain */
         adsl_sdhc1_w3 = adsl_sdhc1_w4 = adsp_conn1->adsc_sdhc1_inuse;  /* get anchor second chain */
       }
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
     }
#ifdef B111125
     /* check if all GATHER are chained together                       */
     adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get this entry SDHC1    */
#ifdef B101213
     while (TRUE) {                         /* loop over SDHC1         */
#ifdef FORKEDIT
     }
#endif
#else
     while (adsl_sdhc1_w1->adsc_gather_i_1_i) {  /* loop over SDHC1    */
#endif
#ifdef DEBUG_100831_01
       if (   (adsl_sdhc1_w1->inc_function == DEF_IFUNC_FROMSERVER)
           && (adsl_sdhc1_w1->inc_position == MAX_SERVER_DATA_HOOK)) {  /* position send to client */
         break;
       }
#endif
       adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next SDHC1 in chain */
       if (adsl_sdhc1_w2 == NULL) break;    /* was last one            */
       if (adsl_sdhc1_w2->inc_function != adsl_sdhc1_w1->inc_function) break;
       if (adsl_sdhc1_w2->inc_position != adsl_sdhc1_w1->inc_position) break;
       if (adsl_sdhc1_w2->adsc_gather_i_1_i == NULL) continue;  /* no chain to send */
       while (TRUE) {                       /* loop over Gather        */
         if (adsl_gai1_w1 == NULL) {        /* this Gather not found in chain */
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d entry Gather of sdhc1=%p not found in chain from sdhc1=%p.",
                           __LINE__, adsl_sdhc1_w2, adsl_sdhc1_w1 );
#ifndef B101213
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d adsl_sdhc1_w1->adsc_gather_i_1_i=%p.",
                           __LINE__, adsl_sdhc1_w1->adsc_gather_i_1_i );
#endif
#ifndef OLD01
           while (TRUE) {
#ifndef HL_UNIX
             Sleep( 2000 );
#else
             sleep( 2 );
#endif
             m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d entry Gather of sdhc1=%p not found in chain from sdhc1=%p.",
                             __LINE__, adsl_sdhc1_w2, adsl_sdhc1_w1 );
           }
#else
#ifndef HL_UNIX
           ExitProcess( 3 );
#else
           exit( 3 );
#endif
#endif
         }
         if (adsl_gai1_w1 == adsl_sdhc1_w2->adsc_gather_i_1_i) break;  /* check chain to send */
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
     }
#endif
     /* check whatever                                                 */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* save entry              */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w3 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor      */
     while (TRUE) {
       if (adsl_sdhc1_w3 == adsl_sdhc1_w2) break;
       if (adsl_sdhc1_w3 == adsl_sdhc1_w1) {
         m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d ring-chain sdhc1=%p",
                         __LINE__, adsl_sdhc1_w1 );
#ifndef OLD01
         while (TRUE) {
#ifndef HL_UNIX
           Sleep( 2000 );
#else
           sleep( 2 );
#endif
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d ring-chain sdhc1=%p",
                           __LINE__, adsl_sdhc1_w1 );
         }
#else
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
#endif
       }
       adsl_sdhc1_w3 = adsl_sdhc1_w3->adsc_next;  /* get next in chain */
     }
     if (   (adsl_sdhc1_w2->inc_function == iml1)
         && (adsl_sdhc1_w2->inc_position == iml2)) {
       continue;
     }
     if (adsl_sdhc1_w2->inc_function != iml1) {
       if (adsl_sdhc1_w2->inc_function < iml1) {
         m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d function not ascending", __LINE__ );
#ifndef OLD01
         while (TRUE) {
#ifndef HL_UNIX
           Sleep( 2000 );
#else
           sleep( 2 );
#endif
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d function not ascending", __LINE__ );
         }
#else
#ifndef HL_UNIX
         ExitProcess( 3 );
#else
         exit( 3 );
#endif
#endif
       }
       switch (adsl_sdhc1_w2->inc_function) {
         case DEF_IFUNC_FROMSERVER:
           break;
         case DEF_IFUNC_TOSERVER:
           break;
         default:
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d function invalid value", __LINE__ );
#ifndef OLD01
         while (TRUE) {
#ifndef HL_UNIX
           Sleep( 2000 );
#else
           sleep( 2 );
#endif
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d function invalid value", __LINE__ );
         }
#else
#ifndef HL_UNIX
           ExitProcess( 3 );
#else
           exit( 3 );
#endif
#endif
       }
       iml1 = adsl_sdhc1_w2->inc_function;
       iml2 = adsl_sdhc1_w2->inc_position;
       continue;
     }
     iml3 = DEF_IFUNC_FROMSERVER;
     if (adsl_sdhc1_w2->inc_position < iml2) {
       iml3 = DEF_IFUNC_TOSERVER;
     }
     if (iml3 != iml1) {
       m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d ascending / descending invalid", __LINE__ );
#ifndef OLD01
         while (TRUE) {
#ifndef HL_UNIX
           Sleep( 2000 );
#else
           sleep( 2 );
#endif
           m_hlnew_printf( HLOG_XYZ1, "m_check_sdhc1() l%05d ascending / descending invalid", __LINE__ );
         }
#else
#ifndef HL_UNIX
       ExitProcess( 3 );
#else
       exit( 3 );
#endif
#endif
     }
     iml2 = adsl_sdhc1_w2->inc_position;
   }
#ifdef TRACEHL_SDH_02
#ifdef TRACEHL_P_COUNT
   memset( &dsl_co_sort_w1, 0, sizeof(struct dsd_co_sort) );
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   bol_search_first = TRUE;                 /* search first entry      */
   EnterCriticalSection( &dsalloc_dcritsect );
   iml1 = ins_count_buf_in_use;
   EnterCriticalSection( &d_clconn_critsect );
   /* save last position                                               */
   adsl_conn1_trace_cur = adss_conn1_trace_last;
   achl_msg_trace_cur = achs_msg_trace_last;
   iml_line_trace_cur = ims_line_trace_last;
   while (TRUE) {                           /* loop over all sessions  */
     bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                  &dsl_htree1_work, bol_search_first );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
     bol_search_first = FALSE;              /* do not search first entry */
     adsl_conn_w1 = (class clconn1 *)
                      ((char *) dsl_htree1_work.adsc_found
                         - offsetof( struct dsd_co_sort, dsc_sort_1 )
                         - offsetof( class clconn1, dsc_co_sort ));
     if (adsl_conn_w1->adsc_sdhc1_c1) iml1--;  /* receive buffer client 1 */
     if (adsl_conn_w1->adsc_sdhc1_c2) iml1--;  /* receive buffer client 2 */
     if (adsl_conn_w1->adsc_sdhc1_s1) iml1--;  /* receive buffer server 1 */
     if (adsl_conn_w1->adsc_sdhc1_s2) iml1--;  /* receive buffer server 2 */
     adsl_sdhc1_w1 = NULL;
     switch (adsl_conn_w1->iec_servcotype) {  /* type of server connection */
       case ied_servcotype_htun:            /* HTUN                    */
         adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_htun_sch;  /* get start of chain */
         break;
       case ied_servcotype_l2tp:            /* L2TP                    */
         adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_l2tp_sch;  /* get start of chain */
         break;
     }
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       iml1--;                              /* count this block        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_frcl;  /* chain of buffers from client (SSL encrypted) */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       iml1--;                              /* count this block        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_chain;  /* chain of buffers input output */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       iml1--;                              /* count this block        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       iml1--;                              /* count this block        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
     adsl_sdhc1_w1 = adsl_conn_w1->adsc_sdhc1_extra;  /* chain of buffers extra */
     while (adsl_sdhc1_w1) {                /* loop over all blocks    */
       iml1--;                              /* count this block        */
       adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
     }
   }
   adss_conn1_trace_last = adsp_conn1;
   achs_msg_trace_last = achp_msg;
   ims_line_trace_last = imp_line;
   LeaveCriticalSection( &d_clconn_critsect );
   LeaveCriticalSection( &dsalloc_dcritsect );
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "l%05d m_check_sdhc1() achl_avl_error=%s.",
                     __LINE__, achl_avl_error );
   }
   if (iml1) {                              /* difference found        */
     m_hlnew_printf( HLOG_XYZ1, "l%05d m_check_sdhc1() diff=%d last    %s l%05d adsl_conn1_trace_cur=%p.",
                     __LINE__, iml1, achl_msg_trace_cur, iml_line_trace_cur, adsl_conn1_trace_cur );
     m_hlnew_printf( HLOG_XYZ1, "l%05d m_check_sdhc1() diff=%d current %s l%05d adsp_conn1=%p.",
                     __LINE__, iml1, achp_msg, imp_line, adsp_conn1 );
   }
#endif
#endif
} /* end m_check_sdhc1()                                               */
#endif
#ifdef TRACEHL_SDH_COUNT_1
/*
   counting the sdhc1 structures has a problem:
   when the aux-call DEF_AUX_TCP_CLOSE is called,
   blocks to get sent to the server may be removed from the chain.
*/
/** count sdhc1 structures of session                                  */
static int m_sdh_count_1( DSD_CONN_G *adsp_conn1, int imp_cmp, char *achp_msg, int imp_line ) {  /* count entries sdhc1 */
   int        iml_count;                    /* count entries           */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

   adsl_sdhc1_w1 = adsp_conn1->adsc_sdhc1_chain;  /* get anchor        */
   iml_count = 0;                           /* count entries           */
   while (adsl_sdhc1_w1) {                  /* loop over all entries   */
     iml_count++;                           /* count entries           */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
#ifdef DEBUG_111202_01                      /* 02.12.11 KB check too many sdhc1 */
   if (iml_count >= DEBUG_111202_01) {
     m_hlnew_printf( HLOG_XYZ1, "m_sdh_count_1() %s l%05d entries=%d - too many",
                     achp_msg, imp_line, iml_count );
   }
#endif
   if (imp_cmp < 0) return iml_count;       /* return entries          */
   if (imp_cmp == iml_count) return iml_count;  /* return entries      */
   m_hlnew_printf( HLOG_XYZ1, "m_sdh_count_1() %s l%05d entries=%d cmp=%d.",
                   achp_msg, imp_line, iml_count, imp_cmp );
#if 0
   while (imp_cmp > 0) Sleep( 1000 );
#endif
   return -1;
} /* end m_sdh_count_1()                                               */
#endif
#undef DSD_CONN_G
