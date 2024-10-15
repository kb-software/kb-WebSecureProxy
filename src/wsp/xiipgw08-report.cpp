   iml_diff_report = dsl_time_1 - dsl_time_last_report;  /* time difference report */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d start report time cur=%lld fingerprint=%lld dsl_time_last_report=%lld iml_diff_report=%d.",
                   __LINE__,
                   (HL_LONGLONG) dsl_time_1, (HL_LONGLONG) dsl_time_fingerprint,
                   (HL_LONGLONG) dsl_time_last_report,
                   iml_diff_report );
#endif
   dsl_time_last_report = dsl_time_1;       /* set time of last report */

   /* exchange buffer for bandwidth clients                            */
   adsl_bc1_report = dss_bc_ctrl.adsrc_bc1[ 0 ];
#ifndef HL_UNIX
   adsl_bc1_free = NULL;                    /* memory to get freed     */
   if (adsg_loconf_1_inuse->inc_report_intv == dss_bc_ctrl.imc_report_intv) {  /* saved interval in seconds */
     goto p_report_28;                      /* report reload configuration done */
   }
   dss_bc_ctrl.imc_report_intv = adsg_loconf_1_inuse->inc_report_intv;  /* saved interval in seconds */
   adsl_bc1_free = dss_bc_ctrl.adsc_bc1_mem;
   adsl_bc1_w1 = adsl_bc1_w2 = NULL;
   dss_bc_ctrl.adsc_bc1_mem = NULL;
   if (dss_bc_ctrl.imc_report_intv == 0) {  /* no more statistic       */
     goto p_report_24;                      /* pointers have been set  */
   }
   if (dss_bc_ctrl.boc_critsect_init == FALSE) {  /* critical section has been initialized */
     iml_rc = dss_bc_ctrl.dsc_critsect.m_create();
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_bc_ctrl.dsc_critsect m_create Return Code %d",
                       __LINE__, iml_rc );
     }
     dss_bc_ctrl.boc_critsect_init = TRUE;  /* critical section has been initialized */
   }
   iml1 = (dss_bc_ctrl.imc_report_intv + DEF_BANDWIDTH_CLIENT_SECS - 1) / DEF_BANDWIDTH_CLIENT_SECS;
   dss_bc_ctrl.adsc_bc1_mem
     = adsl_bc1_w1
       = (struct dsd_bandwidth_client_1 *) malloc( 2 * (sizeof(struct dsd_bandwidth_client_1)
                                                          + 2 * iml1 * sizeof(int)
                                                          + 2 * iml1 * sizeof(HL_LONGLONG)) );
   adsl_bc1_w1->dsc_time_start = dsl_time_1;  /* current time          */
   adsl_bc1_w1->imc_no_entries = iml1;      /* number of entries       */
   adsl_bc1_w1->aimc_p_sent                 /* number of packets sent  */
     = (int *) (adsl_bc1_w1 + 1);
   adsl_bc1_w1->aimc_p_recv                 /* number of packets received */
     = (int *) (adsl_bc1_w1 + 1) + iml1;
   adsl_bc1_w1->ailc_d_sent                 /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) adsl_bc1_w1
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml1 * sizeof(int));
   adsl_bc1_w1->ailc_d_recv                 /* count bytes data received */
     = (HL_LONGLONG *) ((char *) adsl_bc1_w1
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml1 * sizeof(int)
                          + iml1 * sizeof(HL_LONGLONG));
   memset( adsl_bc1_w1 + 1,
           0,
           2 * iml1 * sizeof(int)
             + 2 * iml1 * sizeof(HL_LONGLONG) );
   adsl_bc1_w2
     = (struct dsd_bandwidth_client_1 *) ((char *) adsl_bc1_w1
                                            + sizeof(struct dsd_bandwidth_client_1)
                                            + 2 * iml1 * sizeof(int)
                                            + 2 * iml1 * sizeof(HL_LONGLONG));
   adsl_bc1_w2->imc_no_entries = iml1;      /* number of entries       */
   adsl_bc1_w2->aimc_p_sent                 /* number of packets sent  */
     = (int *) (adsl_bc1_w2 + 1);
   adsl_bc1_w2->aimc_p_recv                 /* number of packets received */
     = (int *) (adsl_bc1_w2 + 1) + iml1;
   adsl_bc1_w2->ailc_d_sent                 /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) adsl_bc1_w2
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml1 * sizeof(int));
   adsl_bc1_w2->ailc_d_recv                 /* count bytes data received */
     = (HL_LONGLONG *) ((char *) adsl_bc1_w2
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml1 * sizeof(int)
                          + iml1 * sizeof(HL_LONGLONG));

   p_report_24:                             /* pointers have been set  */
   dss_bc_ctrl.dsc_critsect.m_enter();      /* critical section        */
   dss_bc_ctrl.adsrc_bc1[ 0 ] = adsl_bc1_w1;
   dss_bc_ctrl.adsrc_bc1[ 1 ] = adsl_bc1_w2;
   dss_bc_ctrl.dsc_critsect.m_leave();      /* critical section        */
   goto p_report_32;                        /* report exchange buffers */

   p_report_28:                             /* report reload configuration done */
#endif
   if (adsl_bc1_report) {                   /* with report bandwidth   */
     memset( dss_bc_ctrl.adsrc_bc1[ 1 ] + 1,
             0,
             2 * dss_bc_ctrl.adsrc_bc1[ 1 ]->imc_no_entries * sizeof(int)
               + 2 * dss_bc_ctrl.adsrc_bc1[ 1 ]->imc_no_entries * sizeof(HL_LONGLONG) );
     dss_bc_ctrl.adsrc_bc1[ 1 ]->dsc_time_start = dsl_time_1;  /* current time */
     dss_bc_ctrl.dsc_critsect.m_enter();    /* critical section        */
     dss_bc_ctrl.adsrc_bc1[ 0 ] = dss_bc_ctrl.adsrc_bc1[ 1 ];
     dss_bc_ctrl.adsrc_bc1[ 1 ] = adsl_bc1_report;
     dss_bc_ctrl.dsc_critsect.m_leave();    /* critical section        */
   }

#ifndef HL_UNIX
   p_report_32:                             /* report exchange buffers */
#endif
   strftime( chrl_work1, sizeof(chrl_work1),
             "%a %B %d %Y %H:%M:%S %Z",
             localtime( &dsl_time_1 ) );
   chrl_work2[0] = 0;                       /* no text queue           */
   if (dsg_hco_main.imc_workque_max_no) {   /* work queue maximum      */
     memcpy( chrl_work2, " at time: ", 10 );
     strftime( chrl_work2 + 10, sizeof(chrl_work2) - 10,
               "%a %B %d %Y %H:%M:%S %Z",
               localtime( &dsg_hco_main.dsc_workque_max_time ) );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPR001I Report %s / number of Work Threads %(dec1,)d - scheduled %(dec1,)d - busy %(dec1,)d - current queue %(dec1,)d - longest queue %(dec1,)d%s",
                   chrl_work1,
                   dsg_hco_main.imc_workthr_alloc, dsg_hco_main.imc_workthr_sched,
                   dsg_hco_main.imc_workthr_active,
                   dsg_hco_main.imc_workque_sched,
                   dsg_hco_main.imc_workque_max_no, chrl_work2 );
   bol_fingerprint = adsg_loconf_1_inuse->boc_print_fingerprint_in_report;  /* <print-fingerprint-in-report> */
#ifdef XYZ1
   if (adsg_loconf_1_inuse->imc_tod_mark_log == 0) {  /* <time-of-day-mark-log> seconds from midnight, +1 */
     dsl_time_fingerprint = 0;              /* time to print fingerprint in report */
     goto p_report_36;                      /* print fingerprint set   */
   }
#endif
   if (   (dsl_time_fingerprint != 0)       /* time to print fingerprint in report */
       && (dsl_time_fingerprint <= dsl_time_last_report)) {
     bol_fingerprint = TRUE;                /* print fingerprint now   */
   }
#ifdef XYZ1
   /* compute time next print fingerprint                              */
   adsl_tm_w1 = localtime( &dsl_time_1 );
   dsl_tm_l1 = *adsl_tm_w1;
   iml1 = (dsl_tm_l1.tm_hour * 60 + dsl_tm_l1.tm_min) * 60 + dsl_tm_l1.tm_sec;
   dsl_time_fingerprint = dsl_time_1 - iml1 + adsg_loconf_1_inuse->imc_tod_mark_log - 1 - 3600;
   bol1 = FALSE;                            /* needs to be today       */
   while (TRUE) {                           /* loop to compute time    */
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d p_report_32: time cur=%lld fingerprint=%lld.",
                     __LINE__, (HL_LONGLONG) dsl_time_1, (HL_LONGLONG) dsl_time_fingerprint );
//#endif
     adsl_tm_w1 = localtime( &dsl_time_fingerprint );
     dsl_tm_l2 = *adsl_tm_w1;
     /* check if today                                                 */
     if (   (bol1 == FALSE)
         && (dsl_tm_l2.tm_mday != dsl_tm_l1.tm_mday)) {
       dsl_time_fingerprint += 3600 / 2;    /* add halve an hour       */
       continue;                            /* try again               */
     }
     iml2 = (dsl_tm_l2.tm_hour * 60 + dsl_tm_l2.tm_min) * 60;
     if (adsg_loconf_1_inuse->imc_tod_mark_log != (iml2 + 1)) {
       dsl_time_fingerprint += 3600 / 2;    /* add halve an hour       */
       continue;                            /* try again               */
     }
     if (bol1) break;                       /* is tomorrow             */
     if (iml2 > iml1) break;                /* later this day          */
     dsl_time_fingerprint += (24 - 1) * 60 * 60;  /* time next day - daylight saving */
     bol1 = TRUE;                           /* is tomorrow             */
   }
#endif
#ifdef XYZ1

   p_report_36:                             /* print fingerprint set   */
#endif
   if (bol_fingerprint) {                   /* print fingerprint in report */
     m_edit_fingerprint( chrl_disp_fp, dsg_this_server.chrc_fingerprint );
     m_hlnew_printf( HLOG_INFO1, "HWSPR013I fingerprint of this HOB WebSecureProxy %.*s.",
                     sizeof(chrl_disp_fp), chrl_disp_fp );
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d p_report_36: time cur=%lld fingerprint=%lld.",
                   __LINE__, (HL_LONGLONG) dsl_time_1, (HL_LONGLONG) dsl_time_fingerprint );
#endif

#ifdef TRACEHLD
   {
     int ih1 = 0;                           /* count threads           */
     audclworkth1 = adss_workth_1_anchor;   /* get anchor of chain     */
     while (audclworkth1) {                 /* loop over all threads   */
       m_hlnew_printf( HLOG_XYZ1, "+++ check thread thrid=%d no=%d / %08X clconn1=%p act=%p time=%08X",
                         audclworkth1->getthrid(),
                         ih1 + 1, audclworkth1,
                         audclworkth1->ad_clconn1,
                         audclworkth1->trace_act, audclworkth1->trace_time );
       ih1++;
       audclworkth1 = audclworkth1->getnext();  /* get next in chain   */
     }
   }
#endif
#ifdef TRACEHLX
   cl_tcp_r::report_thread_mrecv();         /* display receive thr     */
#endif
   m_get_perf_data( &dss_perf_data );
#ifdef XYZ1
   m_edit_sci_two( byarruwork1, dss_perf_data.ulc_memory );
   m_edit_sci_dec( byarruwork2, dss_perf_data.ulc_io_total_ops );
   m_edit_sci_two( byarruwork3, dss_perf_data.ulc_io_total_bytes );
   m_hlnew_printf( HLOG_INFO1, "HWSPR002I Report Performance / elapsed CPU time %d sec / virt-stor %sB / I-O %s %sB.",
                   (int) ((dss_perf_data.ulc_cpu_total_time + 500) / 1000), byarruwork1, byarruwork2, byarruwork3 );
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPR002I Report Performance / elapsed CPU time %(dec1,)d sec / virt-stor %(sci-data)lldB / I-O %(dec1,)lld %(sci-data)lldB.",
                   (int) ((dss_perf_data.ulc_cpu_total_time + 500) / 1000),
                   dss_perf_data.ulc_memory,
                   dss_perf_data.ulc_io_total_ops,
                   dss_perf_data.ulc_io_total_bytes );
   /* report bandwidth used                                            */
   if (adsl_bc1_report == NULL) {           /* no report bandwidth     */
     goto p_report_40;                      /* after report bandwidth  */
   }
   iml1 = iml2 = iml3 = iml4 = iml5 = ill_w1 = ill_w2 = ill_w3 = ill_w4 = 0;  /* clear variables */
   do {
     iml2 += *(adsl_bc1_report->aimc_p_sent + iml1);  /* number of packets sent */
     if (iml3 < *(adsl_bc1_report->aimc_p_sent + iml1)) {  /* number of packets sent */
       iml3 = *(adsl_bc1_report->aimc_p_sent + iml1);  /* number of packets sent */
     }
     iml4 += *(adsl_bc1_report->aimc_p_recv + iml1);  /* number of packets received */
     if (iml5 < *(adsl_bc1_report->aimc_p_recv + iml1)) {  /* number of packets received */
       iml5 = *(adsl_bc1_report->aimc_p_recv + iml1);  /* number of packets received */
     }
     ill_w1 += *(adsl_bc1_report->ailc_d_sent + iml1);  /* count bytes data sent */
     if (ill_w2 < *(adsl_bc1_report->ailc_d_sent + iml1)) {  /* count bytes data sent */
       ill_w2 = *(adsl_bc1_report->ailc_d_sent + iml1);  /* count bytes data sent */
     }
     ill_w3 += *(adsl_bc1_report->ailc_d_recv + iml1);  /* count bytes data received */
     if (ill_w4 < *(adsl_bc1_report->ailc_d_recv + iml1)) {  /* count bytes data received */
       ill_w4 = *(adsl_bc1_report->ailc_d_recv + iml1);  /* count bytes data received */
     }
     iml1++;                                /* increment index         */
   } while (iml1 < adsl_bc1_report->imc_no_entries);  /* number of entries */
#ifndef TJ_B171019
   ils_d_sent += ill_w1;
   ils_d_recv += ill_w3;
#endif
   iml_diff_report += DEF_BANDWIDTH_CLIENT_SECS - 1;  /* time difference report - rounding */
   iml_diff_report /= DEF_BANDWIDTH_CLIENT_SECS;  /* time difference report - pieces */
   if (iml1 > iml_diff_report) {            /* compare time difference report - pieces */
     iml1 = iml_diff_report;                /* set time difference report - pieces */
   }
   if (iml1 <= 0) iml1 = 1;                 /* do not divide by zero   */
   iml2 += iml1 * (DEF_BANDWIDTH_CLIENT_SECS / 2);  /* rounding        */
   iml2 /= iml1 * DEF_BANDWIDTH_CLIENT_SECS;
   iml3 += DEF_BANDWIDTH_CLIENT_SECS / 2;   /* rounding                */
   iml3 /= DEF_BANDWIDTH_CLIENT_SECS;
   iml4 += iml1 * (DEF_BANDWIDTH_CLIENT_SECS / 2);  /* rounding        */
   iml4 /= iml1 * DEF_BANDWIDTH_CLIENT_SECS;
   iml5 += DEF_BANDWIDTH_CLIENT_SECS / 2;   /* rounding                */
   iml5 /= DEF_BANDWIDTH_CLIENT_SECS;
   ill_w1 <<= 3;                            /* from bytes to bits      */
   ill_w1 += iml1 * (DEF_BANDWIDTH_CLIENT_SECS / 2);  /* rounding      */
   ill_w1 /= iml1 * DEF_BANDWIDTH_CLIENT_SECS;
   ill_w2 <<= 3;                            /* from bytes to bits      */
   ill_w2 += DEF_BANDWIDTH_CLIENT_SECS / 2;  /* rounding               */
   ill_w2 /= DEF_BANDWIDTH_CLIENT_SECS;
   ill_w3 <<= 3;                            /* from bytes to bits      */
   ill_w3 += iml1 * (DEF_BANDWIDTH_CLIENT_SECS / 2);  /* rounding      */
   ill_w3 /= iml1 * DEF_BANDWIDTH_CLIENT_SECS;
   ill_w4 <<= 3;                            /* from bytes to bits      */
   ill_w4 += DEF_BANDWIDTH_CLIENT_SECS / 2;  /* rounding               */
   ill_w4 /= DEF_BANDWIDTH_CLIENT_SECS;
#ifndef TJ_B171019
   m_hlnew_printf( HLOG_INFO1, "HWSPRUUUI data received from client network: %(sci-data)lldB (%lld) - data sent to client network: %(sci-data)lldB (%lld)",
                   ils_d_recv,ils_d_recv, ils_d_sent,ils_d_sent );
   m_hlnew_printf( HLOG_INFO1, "HWSPR009I bandwidth client network output average packets / sec %(dec1,)d thruput %(sci-data)lldbps - peak packets / sec %(dec1,)d thruput %(sci-data)lldbps",
                   iml2, ill_w1, iml3, ill_w2 );
   m_hlnew_printf( HLOG_INFO1, "HWSPR010I bandwidth client network input  average packets / sec %(dec1,)d thruput %(sci-data)lldbps - peak packets / sec %(dec1,)d thruput %(sci-data)lldbps",
                   iml4, ill_w3, iml5, ill_w4 );
#else
   m_hlnew_printf( HLOG_INFO1, "HWSPR009I bandwidth client network output average packets / sec %(dec1,)d thruput %(sci-dec)lldbps - peak packets / sec %(dec1,)d thruput %(sci-dec)lldbps",
                   iml2, ill_w1, iml3, ill_w2 );
   m_hlnew_printf( HLOG_INFO1, "HWSPR010I bandwidth client network input  average packets / sec %(dec1,)d thruput %(sci-dec)lldbps - peak packets / sec %(dec1,)d thruput %(sci-dec)lldbps",
                   iml4, ill_w3, iml5, ill_w4 );
#endif
#ifndef HL_UNIX
   if (adsl_bc1_free) free( adsl_bc1_free );  /* memory to get freed   */
#endif

   p_report_40:                             /* after report bandwidth  */
   /* report disk-file                                                 */
   if (bos_disk_file) {                     /* did access disk file    */
     iml1 = iml2 = ill_w1 = 0;              /* reset counters          */
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       iml1++;                              /* count the files         */
       if (adsl_df1_1->dsc_int_df1.achc_filecont_start) {  /* file in memory */
         iml2++;                            /* count the files         */
         /* add size of this file  */
         ill_w1 += adsl_df1_1->dsc_int_df1.achc_filecont_end
                     - adsl_df1_1->dsc_int_df1.achc_filecont_start;
       }
       adsl_df1_1 = adsl_df1_1->adsc_next;  /* get next in chain       */
     }
#ifdef XYZ1
     m_edit_sci_two( byarruwork1, ill_w1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR005I Report cached disk files number %d / %d with data - size in memory: %sB.",
                     iml1, iml2, byarruwork1 );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPR005I Report cached disk files number %(dec1,)d / %(dec1,)d with data - size in memory: %(sci-data)lldB.",
                     iml1, iml2, ill_w1 );
   }
   m_cma1_statistics( &iml1, &ill_w1 );     /* get statistics          */
   if (iml1) {                              /* entries in CMA          */
#ifdef XYZ1
     m_edit_sci_two( byarruwork1, ill_w1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR006I Report CMA common memory area %d entries - size in memory: %sB.",
                     iml1, byarruwork1 );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPR006I Report CMA common memory area %(dec1,)d entries - size in memory: %(sci-data)lldB.",
                     iml1, ill_w1 );
   }
   /* SWAP-STOR                                                        */
   if (dss_swap_stor_ctrl.ilc_no_acq) {     /* number of chunks acquired */
     m_hlnew_printf( HLOG_INFO1, "HWSPR011I Report SWAP-STOR no-acquired %(dec1,)lld file-write %(dec1,)lld file-read %(dec1,)lld out-of-memory %(dec1,)lld.",
                     dss_swap_stor_ctrl.ilc_no_acq,  /* number of chunks acquired */
                     dss_swap_stor_ctrl.ilc_no_file_write, /* number of writes to swap storage file */
                     dss_swap_stor_ctrl.ilc_no_file_read,  /* number of reads from swap storage file */
                     dss_swap_stor_ctrl.ilc_out_of_memory );  /* count times out of memory */
     m_hlnew_printf( HLOG_INFO1, "HWSPR012I Report SWAP-STOR cur-in-memory %(sci-data)lldB max-in-memory %(sci-data)lldB cur-in-file %(sci-data)lldB max-in-file %(sci-data)lldB.",
                     (HL_LONGLONG) (dss_swap_stor_ctrl.imc_mem_max  /* number of chunks in memory maximum */
                                      - dss_swap_stor_ctrl.imc_mem_free)  /* number of chunks in memory free */
                                     << SHIFT_BLOCK_SWAP,
                     (HL_LONGLONG) dss_swap_stor_ctrl.imc_mem_max  /* number of chunks in memory maximum */
                                     << SHIFT_BLOCK_SWAP,
                     (HL_LONGLONG) dss_swap_stor_ctrl.imc_file_cur /* number of chunks on file currently */
                                     << SHIFT_BLOCK_SWAP,
                     (HL_LONGLONG) dss_swap_stor_ctrl.imc_file_max  /* number of chunks on file maximum */
                                     << SHIFT_BLOCK_SWAP );
   }

   m_cluster_report( &dsl_cluster_report );  /* cluster report structure */
   if (dsl_cluster_report.boc_cluster_active) {  /* cluster is active  */
     achl1 = "active";
     if (dsg_sys_state_1.boc_listen_active == FALSE) {
       achl1 = "closed";
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPR008I Report Cluster active connections %(dec1,)d - this group %(dec1,)d - listen %s.",
                     dsl_cluster_report.imc_no_cluster_active,  /* number of active cluster connections */
                     dsl_cluster_report.imc_no_same_group,  /* number of active cluster connections same group */
                     achl1 );
   }
   if (dss_ets_pttd.imc_no_started > 0) {   /* pass-thru-to-desktop - number of instances started */
     ill_w1 = dss_ets_pttd.ilc_sum_time_ms;  /* summary time executed in milliseconds */
     if (dss_ets_pttd.adsc_ete_ch) {        /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_pttd.adsc_ete_ch;  /* chain extra thread entries */
       ill_w2 = m_get_epoch_ms();           /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill_w1 += ill_w2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
#ifdef XYZ1
     achl1 = m_edit_dec_long( chrl_ns_num, ill_w1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR010I Report extra threads - desktop-on-demand - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_pttd.imc_no_current,  /* number of instances currently executing */
                     dss_ets_pttd.imc_no_started,  /* number of instances started */
                     dss_ets_pttd.imc_no_denied,   /* number of start requests denied */
                     achl1 );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPR010I Report extra threads - desktop-on-demand - currently-running=%(dec1,)d started=%(dec1,)d start-denied=%(dec1,)d time-running-milliseconds=%lld.",
                     dss_ets_pttd.imc_no_current,  /* number of instances currently executing */
                     dss_ets_pttd.imc_no_started,  /* number of instances started */
                     dss_ets_pttd.imc_no_denied,   /* number of start requests denied */
                     ill_w1 );
   }
   if (dss_ets_ut.imc_no_started > 0) {     /* utility threads - number of instances started */
     ill_w1 = dss_ets_ut.ilc_sum_time_ms;   /* summary time executed in milliseconds */
     if (dss_ets_ut.adsc_ete_ch) {          /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_ut.adsc_ete_ch;  /* chain extra thread entries */
       ill_w2 = m_get_epoch_ms();           /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill_w1 += ill_w2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
#ifdef XYZ1
     achl1 = m_edit_dec_long( chrl_ns_num, ill_w1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR011I Report extra threads - utility threads   - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_ut.imc_no_current,  /* number of instances currently executing */
                     dss_ets_ut.imc_no_started,  /* number of instances started */
                     dss_ets_ut.imc_no_denied,   /* number of start requests denied */
                     achl1 );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPR011I Report extra threads - utility threads   - currently-running=%(dec1,)d started=%(dec1,)d start-denied=%(dec1,)d time-running-milliseconds=%lld.",
                     dss_ets_ut.imc_no_current,  /* number of instances currently executing */
                     dss_ets_ut.imc_no_started,  /* number of instances started */
                     dss_ets_ut.imc_no_denied,   /* number of start requests denied */
                     ill_w1 );
   }
#ifndef HL_UNIX
   adsl_loconf_1_1 = adss_loconf_1_anchor;  /* get anchor loaded conf  */
   do {
     m_hlnew_printf( HLOG_INFO1, "HWSPR003I configuration loaded %s", adsl_loconf_1_1->byrc_time );
     audgate1 = adsl_loconf_1_1->adsc_gate_anchor;  /* get anchor gate */
     while (audgate1) {
       chrl_work1[0] = 0;                   /* make zero string        */
       if (audgate1->i_session_max) {
         m_hlsnprintf( chrl_work1, sizeof(chrl_work1), ied_chs_utf_8,
                       " max-session-conf=%(dec1,)d max-session-exceeded=%(dec1,)d",
                       audgate1->i_session_max, audgate1->i_session_exc );
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPR004I GATE=%(ux)s report - current sessions=%(dec1,)d start session requests=%(dec1,)d number of session maximum reached=%(dec1,)d%s.",
                       audgate1 + 1,
                       audgate1->i_session_cur, audgate1->i_session_cos, audgate1->i_session_mre,
                       chrl_work1 );
       audgate1 = audgate1->adsc_next;
     }
     adsl_loconf_1_1 = adsl_loconf_1_1->adsc_next;  /* get next in chain */
   } while (adsl_loconf_1_1);               /* over all configurations */
#endif
#ifdef HL_UNIX
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {
     chrl_work1[0] = 0;                     /* make zero string        */
     if (adsl_gate_1_w1->i_session_max) {
       m_hlsnprintf( chrl_work1, sizeof(chrl_work1), ied_chs_utf_8,
                     " max-session-conf=%(dec1,)d max-session-exceeded=%(dec1,)d",
                     adsl_gate_1_w1->i_session_max, adsl_gate_1_w1->i_session_exc );
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPR004I GATE=%(ux)s report - current sessions=%(dec1,)d start session requests=%(dec1,)d number of session maximum reached=%(dec1,)d%s.",
                     adsl_gate_1_w1 + 1,
                     adsl_gate_1_w1->i_session_cur, adsl_gate_1_w1->i_session_cos, adsl_gate_1_w1->i_session_mre,
                     chrl_work1 );
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;  /* get next in chain */
   }
#endif
   /* background-task statistics                                       */
   adsl_bgt_contr_1 = adsg_loconf_1_inuse->adsc_bgt_contr_1;  /* chain background-task control */
   while (adsl_bgt_contr_1) {               /* loop over background-tasks */
     adsl_bgt_function_1 = adsl_bgt_contr_1->adsc_bgt_function_1;  /* chain background-task functions */
     do {                                   /* loop over background-task functions */
       if (adsl_bgt_function_1->iec_bgtf == ied_bgtf_stat) {  /* called for statistic */
         memset( &dsl_aux_cf1, 0, sizeof(struct dsd_aux_cf1) );  /* auxiliary control structure */
         dsl_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_bgt_stat;  /* background-task for statistic */
         memset( &dsl_bgt_call_1, 0, sizeof(struct dsd_bgt_call_1) );  /* Background-Task Call */
         dsl_bgt_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
         dsl_bgt_call_1.ac_conf = adsl_bgt_contr_1->ac_conf;  /* data from configuration */
         dsl_bgt_call_1.vpc_userfld = &dsl_aux_cf1;  /* auxiliary control structure */
         dsl_bgt_call_1.amc_aux = &m_cdaux;  /* subroutine             */
         dsl_bgt_call_1.adsc_bgt_function_1 = adsl_bgt_function_1;  /* called for background-task function */
         adsl_bgt_contr_1->adsc_ext_lib1->amc_bgt_entry( &dsl_bgt_call_1 );
       }
       adsl_bgt_function_1 = adsl_bgt_function_1->adsc_next;  /* get next in chain */
     } while (adsl_bgt_function_1);
     adsl_bgt_contr_1 = adsl_bgt_contr_1->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_P_COUNT
   {
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       m_hlnew_printf( HLOG_TRACE1, "disk-file adsl_df1_1=%p inc_usage_count=%d boc_superseeded=%d"
                   " iec_difi_def=%d ipc_time_last_acc=%d/%08X ipc_time_last_checked=%d/%08X"
                   " achc_filecont_start=%p name=%S",
                   adsl_df1_1,
                   adsl_df1_1->inc_usage_count,
                   adsl_df1_1->boc_superseeded,
                   adsl_df1_1->iec_difi_def,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->dsc_int_df1.achc_filecont_start,
                   adsl_df1_1->dsc_int_df1.awcc_name );
       adsl_df1_1 = adsl_df1_1->adsc_next;    /* get next in chain       */
     }
   }
#endif
//ifdef TRACEHL_P_DISP
#ifdef TRACEHL_P_COUNT
   m_hlnew_printf( HLOG_TRACE1, "ins_count_buf_in_use=%d ins_count_buf_max=%d ins_count_memory=%d.",
                   ins_count_buf_in_use, ins_count_buf_max, ins_count_memory );
#endif
#ifdef TRACEHL_P_050118
   m_hlnew_printf( HLOG_TRACE1, "ims_p_050118 = %d.", ims_p_050118 );
#endif
#ifdef TRACEHL_WA_COUNT                     /* 17.09.09 KB count work area inc / dec */
   m_hlnew_printf( HLOG_TRACE1, "l%05d work area inc=%d dec=%d diff=%d.",
                   __LINE__, ims_count_wa_inc, ims_count_wa_dec, ims_count_wa_inc - ims_count_wa_dec );
#endif
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
   m_hlnew_printf( HLOG_TRACE1, "Report l%05d ims_trace_block_send=%d ims_trace_block_may=%d ims_trace_block_retry=%d.",
                   __LINE__,
                   ims_trace_block_send, ims_trace_block_may, ims_trace_block_retry );
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
#ifdef TRACEHL_STOR_USAGE
   {
     int imh1, imh2;
     struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_h1;
     EnterCriticalSection( &dsalloc_dcritsect );
     adsl_tr_stor_usage_01_h1 = adss_tr_stor_usage_01_anchor;
     while (adsl_tr_stor_usage_01_h1) {
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) (adsl_tr_stor_usage_01_h1 + 1))
       m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p stack=%p chrc_pos=%s adsc_next=%p adsc_gather_i_1_i=%p inc_function=%p inc_position=%p boc_ready_t_p=%p imc_usage_count=%p.",
                       __LINE__, adsl_tr_stor_usage_01_h1, adsl_tr_stor_usage_01_h1->ac_stack, adsl_tr_stor_usage_01_h1->chrc_pos,
                       ADSL_SDHC1_G->adsc_next,  /* field for chaining */
                       ADSL_SDHC1_G->adsc_gather_i_1_i,  /* gather input data */
                       ADSL_SDHC1_G->inc_function,  /* function of SDH */
                       ADSL_SDHC1_G->inc_position,  /* position of SDH */
                       ADSL_SDHC1_G->boc_ready_t_p,  /* ready to process */
                       ADSL_SDHC1_G->imc_usage_count );  /* usage count */
#undef ADSL_SDHC1_G
       imh1 = adsl_tr_stor_usage_01_h1->imc_ind_trac;
       imh2 = 0;
       do {
         imh2++;
         m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p no=%d trac=%s.",
                         __LINE__, adsl_tr_stor_usage_01_h1, imh2,
                         &adsl_tr_stor_usage_01_h1->chrc_trac[ imh1 * (sizeof(adsl_tr_stor_usage_01_h1->chrc_trac) / D_NO_TSU_NO) ] );
         imh1++;
         if (imh1 == D_NO_TSU_NO) imh1 = 0;
       } while (imh1 != adsl_tr_stor_usage_01_h1->imc_ind_trac);
       adsl_tr_stor_usage_01_h1 = adsl_tr_stor_usage_01_h1->adsc_next;
     }
     LeaveCriticalSection( &dsalloc_dcritsect );
   }
#endif
#ifdef TRACE_HL_SESS_01
   {
     BOOL     boh_first = TRUE;
     int      imh1, imh2, imh3, imh4, imh5;
     int      imh_gather;                   /* count gather            */
     int      imh_data;                     /* count data              */
     char     *achh2;
     char     *achh_avl_error = NULL;       /* clear error code AVL tree */
     struct dsd_sdh_control_1 *adsh_sdhc1_cur_1;  /* current location 1 */
     struct dsd_gather_i_1 *adsh_gai1_w1;   /* working variable        */
     struct dsd_htree1_avl_work dsh_htree1_work;  /* work-area for AVL-Tree */
     char     chrl_ns_1[320];               /* for network-statistic   */
     char     chrl_ns_num[16];              /* for number              */
     EnterCriticalSection( &d_clconn_critsect );
     while (TRUE) {                         /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                    &dsh_htree1_work, boh_first );
       if (bol1 == FALSE) {                 /* error occured           */
         achh_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsh_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#define ADSL_CONN1_G ((class clconn1 *) (dsh_htree1_work.adsc_found))
       boh_first = FALSE;
       m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-l%05d GATE=%(ux)s SNO=%08d INETA=%s adsc_server_conf_1=%p.",
                       __LINE__,
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       ADSL_CONN1_G->adsc_server_conf_1 );
#ifdef XYZ1
       chrl_ns_1[0] = 0;                    /* for network-statistic   */
       imh2 = m_get_time() - ADSL_CONN1_G->imc_time_start;
       imh3 = imh2 / 3600;
       imh5 = imh2 - imh3 * 3600;
       imh4 = imh5 / 60;
       imh5 -= imh4 * 60;
       imh1 = sprintf( chrl_ns_1, "duration: %d h %d min %d sec", imh3, imh4, imh5 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " / client: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " / server: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " / encrypted: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
#endif
       chrl_ns_1[0] = 0;                    /* for network-statistic   */
       imh2 = m_get_time() - ADSL_CONN1_G->imc_time_start;
       imh3 = imh2 / 3600;
       imh5 = imh2 - imh3 * 3600;
       imh4 = imh5 / 60;
       imh5 -= imh4 * 60;
       imh1 = sprintf( chrl_ns_1, "duration: %d h %d min %d sec", imh3, imh4, imh5 );
       imh1 += sprintf( chrl_ns_1 + imh1, " / client: rec %d", ADSL_CONN1_G->inc_c_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %d", ADSL_CONN1_G->inc_c_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " / server: rec %d", ADSL_CONN1_G->inc_c_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %d", ADSL_CONN1_G->inc_c_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " / encrypted: rec %d", ADSL_CONN1_G->inc_c_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %d", ADSL_CONN1_G->inc_c_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %lld bytes", ADSL_CONN1_G->ilc_d_ns_send_e );
       m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-l%05d %s.",
                       __LINE__, chrl_ns_1 );
       imh1 = 0;
       adsh_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
       while (adsh_sdhc1_cur_1) {           /* loop over all buffers   */
         adsh_gai1_w1 = adsh_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
         imh_gather = 0;                    /* clear count gather      */
         imh_data = 0;                      /* clear count data        */
         while (adsh_gai1_w1) {             /* loop over data to send  */
           imh_gather++;                    /* increment count gather  */
           imh2 = adsh_gai1_w1->achc_ginp_end - adsh_gai1_w1->achc_ginp_cur;
           imh_data += imh2;
           adsh_gai1_w1 = adsh_gai1_w1->adsc_next;  /* get next in chain */
         }
         m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-l%05d adsh_sdhc1_cur_1=%p function=%d position=%d imc_usage_count=%d gather=%d data=%d",
                         __LINE__, adsh_sdhc1_cur_1,
                         adsh_sdhc1_cur_1->inc_function, adsh_sdhc1_cur_1->inc_position, adsh_sdhc1_cur_1->imc_usage_count,
                         imh_gather, imh_data );
         imh1++;
         adsh_sdhc1_cur_1 = adsh_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-l%05d i_last_action=%05d i_prev_action=%05d adsc_sdhc1_chain=%p no-e=%d dcl_tcp_r_c.adsc_sdhc1_send=%p dcl_tcp_r_s.adsc_sdhc1_send=%p.",
                       __LINE__,
                       ADSL_CONN1_G->i_last_action, ADSL_CONN1_G->i_prev_action,
                       ADSL_CONN1_G->adsc_sdhc1_chain, imh1,
                       ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send,
                       ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send );
       imh1 = 0;
       do {
         m_hlnew_printf( HLOG_TRACE1, "HWSP-TRACE-l%05d ir_last_action[ %d ... ] = %05d %05d %05d %05d %05d %05d %05d %05d.",
                         __LINE__, imh1,
                         ADSL_CONN1_G->ir_last_action[ imh1 + 0 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 1 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 2 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 3 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 4 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 5 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 6 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 7 ] );
         imh1 += 8;
       } while (imh1 < DEF_LEN_LAST_ACTION);
#undef ADSL_CONN1_G
     }
     LeaveCriticalSection( &d_clconn_critsect );
     if (achh_avl_error) {                    /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSP-TRACE-l%05d AVL error %s.",
                       __LINE__, achh_avl_error );
     }
   }
#endif  /* TRACE_HL_SESS_01 */
