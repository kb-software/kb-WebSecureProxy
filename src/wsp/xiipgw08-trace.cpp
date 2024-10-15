#define INCL_CMA_DUMP

struct dsd_wsp_tr_intern_1 {                /* internal WSP trace      */
#ifndef HL_UNIX
   HANDLE     dsc_hfi1;                     /* handle for file         */
#else
   int        imc_fdfi1;                    /* file-descriptor for output file */
#endif
#ifdef INCL_CMA_DUMP
   int        imc_count;                    /* count entries           */
#endif
};

/** routine to pass WSP trace output                                   */
extern "C" void m_wsp_trace_out( struct dsd_wsp_trace_1 *adsp_wt1 ) {
   BOOL       bol1, bol2;                   /* working variable        */
   int        iml_rc, iml_error;            /* return codes            */

   bol1 = FALSE;                            /* do not start trace thread */
   bol2 = FALSE;                            /* do not set event        */
   if (adsp_wt1) {                          /* not pseudo parameters   */
     adsp_wt1->adsc_next = NULL;            /* only one set of records */
   }
   dss_trace_lock.m_enter();                /* enter critical section  */
   if (adsp_wt1) {                          /* not pseudo parameters   */
     if (dss_wsp_trace_thr_ctrl.adsc_wt1_last == NULL) {  /* WSP trace record last in chain */
       dss_wsp_trace_thr_ctrl.adsc_wt1_anchor = adsp_wt1;  /* WSP trace record anchor */
       bol2 = TRUE;                         /* do set event            */
     } else {                               /* append to chain         */
       dss_wsp_trace_thr_ctrl.adsc_wt1_last->adsc_next = adsp_wt1;  /* append to chain */
     }
     dss_wsp_trace_thr_ctrl.adsc_wt1_last = adsp_wt1;  /* WSP trace record last in chain */
   } else {                                 /* maybe start trace thread */
     bol2 = TRUE;                           /* do set event            */
   }
   if (dss_wsp_trace_thr_ctrl.boc_tread_running == FALSE) {  /* WSP trace thread is not running */
     dss_wsp_trace_thr_ctrl.boc_tread_running = TRUE;  /* WSP trace thread is running now */
     bol1 = TRUE;                           /* do start trace thread   */
   }
   dss_trace_lock.m_leave();                /* leave critical section  */
   if (bol1 == FALSE) goto p_out_20;        /* do not start trace thread */
   iml_rc = dss_wsp_trace_thr_ctrl.dsc_event_thr.m_create( &iml_error );  /* event for WSP trace thread */
   if (iml_rc < 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d event WSP trace m_create Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   iml_rc = dss_wsp_trace_thr_ctrl.dsc_thread.mc_create( &m_wsp_trace_thread, NULL );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d CreateThread WSP trace Error", __LINE__ );
   }

   p_out_20:                                /* thread has been started */
#ifndef WSP_TRACE_SLEEP
   if (bol2 == FALSE) return;               /* do not set event        */
#else
   if (bol2 == FALSE) {                     /* do not set event        */
#ifndef HL_UNIX
     Sleep( WSP_TRACE_SLEEP );
#else
     usleep( WSP_TRACE_SLEEP );
#endif
     return;
   }
#endif
   iml_rc = dss_wsp_trace_thr_ctrl.dsc_event_thr.m_post( &iml_error );  /* event for WSP trace thread */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMxxxW l%05d event WSP trace m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
#ifdef WSP_TRACE_SLEEP
#ifndef HL_UNIX
   Sleep( WSP_TRACE_SLEEP );
#else
   usleep( WSP_TRACE_SLEEP );
#endif
#endif
} /* end m_wsp_trace_out()                                             */

/** thread for WSP trace                                               */
static htfunc1_t m_wsp_trace_thread( void * ) {
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* working variable        */
#endif
#ifdef HL_UNIX
#ifdef INCL_CMA_DUMP
   BOOL       bol_rc;                       /* working variable        */
#endif
#endif
#ifdef INCL_CMA_DUMP
   BOOL       bol_cma_dump;                 /* make CMA dump           */
#endif
   int        iml_rc, iml_error;            /* return codes            */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_trace_record;             /* record number of trace  */
#ifdef B150118
   int        iml_trace_date;               /* current date of trace   */
#endif
   char       chl_w1, chl_w2;               /* working variable        */
#ifdef B150118
   time_t     dsl_time;                     /* time calculation        */
#endif
   time_t     dsl_time_1;                   /* for time                */
#ifndef HL_UNIX
   DWORD      dwl_write;                    /* for WriteFile()         */
#endif
#ifdef B150118
   HL_LONGLONG ill1;                        /* working variable        */
#endif
   HL_LONGLONG ill_w1;                      /* working variable        */
   HL_LONGLONG ill_epoch;                   /* time in microseconds    */
   HL_LONGLONG ill_start_of_day;            /* microseconds at start of day */
   char       *achl_inp_1, *achl_inp_2, *achl_inp_3, *achl_inp_4;  /* input data passed */
   char       *achl_out_1, *achl_out_2;     /* output data             */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace record        */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace record        */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_record *adsl_wtr_w2;  /* WSP trace record      */
   struct tm  *adsl_tm_w1;                  /* working variable        */
   struct tm  dsl_tm_l1;                    /* working variable        */
   struct tm  dsl_tm_l2;                    /* working variable        */
   struct tm  dsl_tm_trace_date;            /* date of trace records   */
   struct dsd_wsp_tr_intern_1 dsl_wti1;     /* internal WSP trace      */
#ifdef INCL_CMA_DUMP
   struct dsd_wsp_trace_1 dsl_wt1_l;        /* WSP trace record        */
#endif
#ifdef B150125
#ifndef HL_UNIX
   HANDLE     dsl_hfi1;                     /* handle for file         */
#else
   int        iml_fdfi1;                    /* file-descriptor for output file */
#endif
#endif
   char       byrlwork1[ 2048 ];            /* work area               */
   char       byrlwork2[ 256 ];             /* work area               */
   char       byrlwork3[ 256 ];             /* work area               */
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];

#ifndef B170211
   /* Dr. Fink says, is needed; no reason found why.
      change by Dr. Fink B161013
   */
   adsl_wtr_w1 = adsl_wtr_w2 = NULL;
#endif
   iml_trace_record = 0;                    /* record number of trace  */
#ifdef B150118
   iml_trace_date = 0;                      /* current date of trace   */
#endif
   memset( &dsl_tm_trace_date, 0, sizeof(struct tm) );  /* current date of trace records */
   dss_wsp_trace_thr_ctrl.iec_wtt = ied_wtt_console;  /* print on console */
#ifndef HL_UNIX
   /* set to highest priority                                          */
   bol_rc = SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W SetThreadPriority WSP Trace returned error %d.",
                     __LINE__, GetLastError() );
   }
#endif

   p_wtt_00:                                /* WSP trace start         */
#ifdef INCL_CMA_DUMP
   bol_cma_dump = FALSE;                    /* make CMA dump           */
   if (dss_wsp_trace_thr_ctrl.boc_cma_dump) {  /* make CMA dump        */
     bol_cma_dump = TRUE;                   /* make CMA dump           */
     dss_wsp_trace_thr_ctrl.boc_cma_dump = FALSE;  /* reset make CMA dump */
     ill_epoch = m_get_epoch_microsec();    /* time in microseconds    */
     memset( &dsl_wt1_l, 0, sizeof(struct dsd_wsp_trace_1) );  /* WSP trace record */
     memcpy( dsl_wt1_l.chrc_wtrt_id, "DCMA0000", sizeof(dsl_wt1_l.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wt1_l.ilc_epoch = ill_epoch;       /* time trace record recorded */
     dsl_wt1_l.imc_wtrt_tid = HL_THRID;     /* thread-id               */
     adsl_wt1_w1 = &dsl_wt1_l;              /* WSP trace record        */
     if (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_bin) {  /* trace records to file binary */
       goto p_wtt_22;                       /* output ASCII trace      */
     }
     goto p_wtt_bin_00;                     /* binary trace output     */
   }
#endif
   if (dss_wsp_trace_thr_ctrl.adsc_wt1_anchor) {  /* work for WSP trace */
     goto p_wtt_20;                         /* found work to do        */
   }
   iml_rc = dss_wsp_trace_thr_ctrl.dsc_event_thr.m_wait( &iml_error );
   if (iml_rc == 0) goto p_wtt_00;          /* WSP trace start         */
// to-do 02.07.10 KB error message
   m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W m_wsp_trace_thread thread m_wait Return Code %d Error %d.",
                 __LINE__, iml_rc, iml_error );
#ifndef HL_UNIX
   Sleep( 2000 );                           /* wait some time          */
#else
   sleep( 2 );                              /* wait some time          */
#endif
   goto p_wtt_00;                           /* WSP trace start         */

   p_wtt_20:                                /* found work to do        */
   dss_trace_lock.m_enter();                /* enter critical section  */
   adsl_wt1_w1 = dss_wsp_trace_thr_ctrl.adsc_wt1_anchor;  /* WSP trace record anchor */
   dss_wsp_trace_thr_ctrl.adsc_wt1_anchor = adsl_wt1_w1->adsc_next;  /* remove new WSP trace record from chain */
   if (dss_wsp_trace_thr_ctrl.adsc_wt1_anchor == NULL) {  /* no more chain */
     dss_wsp_trace_thr_ctrl.adsc_wt1_last = NULL;  /* no more WSP trace record last in chain */
   }
   dss_trace_lock.m_leave();                /* leave critical section  */
   if (adsl_wt1_w1->iec_wtrt != ied_wtrt_trace_data) {  /* not trace data */
     goto p_wtt_ctrl_00;                    /* control command received */
   }
   adsl_wtr_w1 = adsl_wt1_w1->adsc_wsp_trace_record;  /* WSP trace records */
// to-do 01.06.11 KB - erase lines
   if (adsl_wtr_w1 == NULL) {               /* no more trace records   */
     goto p_wtt_80;                         /* free memory passed      */
   }
   if (dss_wsp_trace_thr_ctrl.iec_wtt == ied_wtt_file_bin) {  /* trace records to file binary */
     goto p_wtt_bin_00;                     /* binary trace output     */
   }
   ill_epoch = adsl_wt1_w1->ilc_epoch;      /* time in microseconds    */

   p_wtt_22:                                /* output ASCII trace      */
   dsl_time_1 = ill_epoch / (1000 * 1000);  /* epoch in seconds        */
   adsl_tm_w1 = localtime( &dsl_time_1 );
   dsl_tm_l1 = dsl_tm_l2 = *adsl_tm_w1;
   dsl_tm_l1.tm_hour = 0;
   dsl_tm_l1.tm_min = 0;
   dsl_tm_l1.tm_sec = 0;
   if (!memcmp( &dsl_tm_l1, &dsl_tm_trace_date, sizeof(struct tm) )) {
     goto p_wtt_24;                         /* day of trace set        */
   }
   dsl_tm_trace_date = dsl_tm_l1;           /* set day of trace        */
   ill_start_of_day
     = ((HL_LONGLONG) ill_epoch
            - ((HL_LONGLONG) (dsl_tm_l2.tm_hour * 60 * 60 + dsl_tm_l2.tm_min * 60 + dsl_tm_l2.tm_sec) * 1000 * 1000))
          / (1000 * 1000) * (1000 * 1000);
   iml1 = sprintf( byrlwork1, "+++ WSP-Trace date " );
   iml1 += (int) strftime( byrlwork1 + iml1, sizeof(byrlwork1) - iml1,
                           "%b %d %Y", &dsl_tm_trace_date );
#ifndef HL_UNIX
   iml2                                     /* deviation               */
     = m_get_epoch_ms()                     /* exact time in milliseconds */
         - (m_get_epoch_microsec() + 500) / 1000;
   iml1 += m_hlsnprintf( byrlwork1 + iml1, sizeof(byrlwork1) - iml1, ied_chs_utf_8,
                         " / deviation %d milliseconds", iml2 );
#endif

   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_console:                  /* print on console        */
#ifndef HL_UNIX
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                       __LINE__, iml1, byrlwork1 );
#else
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T %.*s",
                       __LINE__, iml1, byrlwork1 );
#endif
       break;
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
       memcpy( byrlwork1 + iml1, chrs_crlf, sizeof(chrs_crlf) );
#ifndef HL_UNIX
       bol_rc = WriteFile( dsl_wti1.dsc_hfi1, byrlwork1, iml1 + 2, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
         goto p_wtt_80;                     /* free memory passed      */
       }
#else
       iml_rc = write( dsl_wti1.imc_fdfi1, byrlwork1, iml1 + 2 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         goto p_wtt_80;                     /* free memory passed      */
       }
#endif
       break;
   }

   p_wtt_24:                                /* day of trace set        */
   iml_trace_record++;                      /* increment record number of trace */
   ill_w1 = (HL_LONGLONG) ill_epoch - ill_start_of_day;  /* microseconds relative to start of day */
   iml2 = sprintf( byrlwork1, "+++ WSP-Trace record-no %08d %.*s SNO=%08d TID=%08d time %02d:%02d:%02d.%03d.%03d.",
                   iml_trace_record,
                   sizeof(adsl_wt1_w1->chrc_wtrt_id), adsl_wt1_w1->chrc_wtrt_id,  /* Id of trace record */
                   adsl_wt1_w1->imc_wtrt_sno,  /* WSP session number   */
                   adsl_wt1_w1->imc_wtrt_tid,  /* thread-id            */
                   (int) ((HL_LONGLONG) ill_w1 / ((HL_LONGLONG) 60 * 60 * 1000 * 1000)),
                   (int) ((HL_LONGLONG) (ill_w1 - ((HL_LONGLONG) ill_w1 / ((HL_LONGLONG) 60 * 60 * 1000 * 1000) * ((HL_LONGLONG) 60 * 60 * 1000 * 1000))) / (60 * 1000 * 1000)),
                   (int) (((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / (60 * 1000 * 1000) * (60 * 1000 * 1000))) / (1000 * 1000)),
                   (int) (((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / (1000 * 1000) * (1000 * 1000))) / 1000 ),
                   (int) ((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / 1000 * 1000)) );
   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_console:                  /* print on console        */
#ifndef HL_UNIX
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                       __LINE__, iml2, byrlwork1 );
#else
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T %.*s",
                       __LINE__, iml2, byrlwork1 );
#endif
       break;
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
       memcpy( byrlwork1 + iml2, chrs_crlf, sizeof(chrs_crlf) );
#ifndef HL_UNIX
       bol_rc = WriteFile( dsl_wti1.dsc_hfi1, byrlwork1, iml2 + 2, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );

         goto p_wtt_80;                     /* free memory passed      */
       }
#else
       iml_rc = write( dsl_wti1.imc_fdfi1, byrlwork1, iml2 + 2 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         goto p_wtt_80;                     /* free memory passed      */
       }
#endif
       break;
   }
#ifdef INCL_CMA_DUMP
   if (bol_cma_dump) {                      /* make CMA dump           */
     goto p_wtt_cma_00;                     /* dump CMA                */
   }
#endif

   p_wtt_40:                                /* next trace record       */
   if (adsl_wtr_w1 == NULL) {               /* no more trace records   */
     goto p_wtt_80;                         /* free memory passed      */
   }
   if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
     goto p_wtt_data_00;                    /* binary data passed      */
   }
   achl_out_1 = adsl_wtr_w1->achc_content;  /* content of text / data  */
   iml1 = adsl_wtr_w1->imc_length;          /* length of text / data   */
   if (adsl_wtr_w1->boc_more == FALSE) {    /* not more data to follow */
     goto p_wtt_text_40;                    /* text has been prepared  */
   }
   achl_out_2 = byrlwork1;                  /* output area is here     */

   p_wtt_text_20:                           /* copy part of text       */
// to-do 27.04.11 KB check after copy area
   memcpy( achl_out_2, achl_out_1, iml1 );
   achl_out_2 += iml1;
   if (adsl_wtr_w1->boc_more) {             /* more data to follow     */
     adsl_wtr_w1 = adsl_wtr_w1->adsc_next;  /* get next record in chain */
// to-do 27.04.11 KB check NULL and text
     achl_out_1 = adsl_wtr_w1->achc_content;  /* content of text / data */
     iml1 = adsl_wtr_w1->imc_length;        /* length of text / data   */
     goto p_wtt_text_20;                    /* copy part of text       */
   }
   iml1 = achl_out_2 - byrlwork1;           /* length of text          */
   achl_out_1 = byrlwork1;                  /* output area is here     */

   p_wtt_text_40:                           /* text has been prepared  */
   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_console:                  /* print on console        */
#ifndef HL_UNIX
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                       __LINE__, iml1, achl_out_1 );
#else
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T %.*s",
                       __LINE__, iml1, achl_out_1 );
#endif
       break;
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
#ifndef HL_UNIX
       bol_rc = WriteFile( dsl_wti1.dsc_hfi1, achl_out_1, iml1, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
         goto p_wtt_80;                     /* free memory passed      */
       }
       bol_rc = WriteFile( dsl_wti1.dsc_hfi1, chrs_crlf, sizeof(chrs_crlf), &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
         goto p_wtt_80;                     /* free memory passed      */
       }
#else
       iml_rc = write( dsl_wti1.imc_fdfi1, achl_out_1, iml1 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         goto p_wtt_80;                     /* free memory passed      */
       }
       iml_rc = write( dsl_wti1.imc_fdfi1, chrs_crlf, sizeof(chrs_crlf) );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         goto p_wtt_80;                     /* free memory passed      */
       }
#endif
       break;
   }
   adsl_wtr_w1 = adsl_wtr_w1->adsc_next;    /* get next record in chain */
   goto p_wtt_40;                           /* next trace record       */

   p_wtt_data_00:                           /* binary data passed      */
   m_wsp_trace_bin_1( &dsl_wti1,            /* internal WSP trace      */
                      adsl_wtr_w1 );        /* WSP trace record        */

   adsl_wtr_w1 = adsl_wtr_w1->adsc_next;    /* get next record in chain */
   if (adsl_wtr_w1) {                       /* more trace data follow  */
     goto p_wtt_40;                         /* next trace record       */
   }
   goto p_wtt_80;                           /* free memory passed      */

   p_wtt_bin_00:                            /* binary trace output     */
   iml_trace_record++;                      /* increment record number of trace */
#define ADSL_WTBH1 ((struct dsd_wsp_tr_bin_header_1 *) byrlwork1)
   memset( ADSL_WTBH1, 0, sizeof(struct dsd_wsp_tr_bin_header_1) );
   memcpy( ADSL_WTBH1->chrc_wtrt_id, adsl_wt1_w1->chrc_wtrt_id, sizeof(ADSL_WTBH1->chrc_wtrt_id) );  /* Id of trace record */
   ADSL_WTBH1->chrc_wtrt_epoch[ 0 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 56);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 1 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 48);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 2 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 40);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 3 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 32);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 4 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 24);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 5 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 16);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 6 ] = (unsigned char) (adsl_wt1_w1->ilc_epoch >> 8);  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_epoch[ 7 ] = (unsigned char) adsl_wt1_w1->ilc_epoch;  /* time trace record recorded */
   ADSL_WTBH1->chrc_wtrt_sno[ 0 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_sno >> 24);  /* WSP session number */
   ADSL_WTBH1->chrc_wtrt_sno[ 1 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_sno >> 16);  /* WSP session number */
   ADSL_WTBH1->chrc_wtrt_sno[ 2 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_sno >> 8);  /* WSP session number */
   ADSL_WTBH1->chrc_wtrt_sno[ 3 ] = (unsigned char) adsl_wt1_w1->imc_wtrt_sno;  /* WSP session number */
   ADSL_WTBH1->chrc_wtrt_tid[ 0 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_tid >> 24);  /* thread-id */
   ADSL_WTBH1->chrc_wtrt_tid[ 1 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_tid >> 16);  /* thread-id */
   ADSL_WTBH1->chrc_wtrt_tid[ 2 ] = (unsigned char) (adsl_wt1_w1->imc_wtrt_tid >> 8);  /* thread-id */
   ADSL_WTBH1->chrc_wtrt_tid[ 3 ] = (unsigned char) adsl_wt1_w1->imc_wtrt_tid;  /* thread-id */
   ADSL_WTBH1->chrc_wtrt_record_no[ 0 ] = (unsigned char) (iml_trace_record >> 24);  /* WSP trace record number */
   ADSL_WTBH1->chrc_wtrt_record_no[ 1 ] = (unsigned char) (iml_trace_record >> 16);  /* WSP trace record number */
   ADSL_WTBH1->chrc_wtrt_record_no[ 2 ] = (unsigned char) (iml_trace_record >> 8);  /* WSP trace record number */
   ADSL_WTBH1->chrc_wtrt_record_no[ 3 ] = (unsigned char) iml_trace_record;  /* WSP trace record number */
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, (char *) ADSL_WTBH1, sizeof(struct dsd_wsp_tr_bin_header_1), &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     goto p_wtt_80;                         /* free memory passed      */
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, (char *) ADSL_WTBH1, sizeof(struct dsd_wsp_tr_bin_header_1) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     goto p_wtt_80;                         /* free memory passed      */
   }
#endif
#ifdef INCL_CMA_DUMP
   if (bol_cma_dump) {                      /* make CMA dump           */
     goto p_wtt_cma_00;                     /* dump CMA                */
   }
#endif
   adsl_wtr_w1 = adsl_wt1_w1->adsc_wsp_trace_record;  /* WSP trace records */
   if (adsl_wtr_w1 == NULL) {               /* no more trace records   */
     goto p_wtt_bin_80;                     /* write end of record binary trace output */
   }

   p_wtt_bin_20:                            /* next part of binary trace output */
   adsl_wtr_w2 = adsl_wtr_w1;               /* get first part          */
   iml1 = 1;                                /* length of record        */

   p_wtt_bin_24:                            /* next in chain of binary trace output */
   iml1 += adsl_wtr_w2->imc_length;         /* length of text / data   */
   if (adsl_wtr_w2->boc_more == FALSE) {    /* no more data to follow  */
     goto p_wtt_bin_28;                     /* end of chain of binary trace output */
   }
   adsl_wtr_w2 = adsl_wtr_w2->adsc_next;    /* get next record in chain */
   if (adsl_wtr_w2 == NULL) {               /* end of chain reached    */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace binary output chain ended but more set before",
                     __LINE__ );
     goto p_wtt_bin_28;                     /* end of chain of binary trace output */
   }
   if (adsl_wtr_w2->iec_wtrt != adsl_wtr_w1->iec_wtrt) {  /* type of record WSP trace text / binary */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace in chain with more mixed text / binary",
                     __LINE__ );
   }
   goto p_wtt_bin_24;                       /* next in chain of binary trace output */

   p_wtt_bin_28:                            /* end of chain of binary trace output */
   achl_out_1 = byrlwork1 + 8;
   *achl_out_1 = 'A';                       /* output text / ASCII     */
   if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
     *achl_out_1 = 'B';                     /* output binary data      */
   }
   iml2 = 0;                                /* clear more flag         */
   while (TRUE) {                           /* output length NHASN     */
     *(--achl_out_1) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output digit */
     iml1 >>= 7;                            /* shift bits              */
     if (iml1 <= 0) break;                  /* end of number           */
     iml2 = 0X80;                           /* set more flag           */
   }
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, achl_out_1, (byrlwork1 + 8 + 1) - achl_out_1, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     goto p_wtt_80;                         /* free memory passed      */
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, achl_out_1, (byrlwork1 + 8 + 1) - achl_out_1 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     goto p_wtt_80;                         /* free memory passed      */
   }
#endif
   adsl_wtr_w2 = adsl_wtr_w1;               /* get first part          */

   p_wtt_bin_32:                            /* write content of chain of binary trace output */
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, adsl_wtr_w2->achc_content, adsl_wtr_w2->imc_length, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     goto p_wtt_80;                         /* free memory passed      */
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, adsl_wtr_w2->achc_content, adsl_wtr_w2->imc_length );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     goto p_wtt_80;                         /* free memory passed      */
   }
#endif
   if (adsl_wtr_w2->boc_more == FALSE) {    /* no more data to follow  */
     goto p_wtt_bin_40;                     /* next chain of binary trace output */
   }
   adsl_wtr_w2 = adsl_wtr_w2->adsc_next;    /* get next record in chain */
   if (adsl_wtr_w2 == NULL) {               /* end of chain reached    */
     goto p_wtt_bin_80;                     /* write end of record binary trace output */
   }
   goto p_wtt_bin_32;                       /* write content of chain of binary trace output */

   p_wtt_bin_40:                            /* next chain of binary trace output */
   adsl_wtr_w1 = adsl_wtr_w2->adsc_next;    /* get next record in chain */
   if (adsl_wtr_w1) {                       /* more records to follow  */
     goto p_wtt_bin_20;                     /* next part of binary trace output */
   }

   p_wtt_bin_80:                            /* write end of record binary trace output */
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, &chs_zero, sizeof(chs_zero), &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, &chs_zero, sizeof(chs_zero) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
   }
#endif

   p_wtt_80:                                /* free memory passed      */
#ifdef INCL_CMA_DUMP
   if (bol_cma_dump) {                      /* make CMA dump           */
     goto p_wtt_00;                         /* WSP trace start         */
   }
#endif
   adsl_wt1_w2 = adsl_wt1_w1->adsc_cont;    /* continue this record    */
   while (adsl_wt1_w2) {                    /* loop over all records   */
     adsl_wt1_w3 = adsl_wt1_w2;             /* save this memory address */
     adsl_wt1_w2 = adsl_wt1_w2->adsc_cont;  /* continue this record    */
     m_proc_free( adsl_wt1_w3 );            /* free memory trace record */
   }
   m_proc_free( adsl_wt1_w1 );              /* free memory trace record */
   goto p_wtt_00;                           /* WSP trace start         */

   p_wtt_ctrl_00:                           /* control command received */
   if (   (dss_wsp_trace_thr_ctrl.iec_wtt == ied_wtt_file_ascii)   /* trace records to file ASCII */
       || (dss_wsp_trace_thr_ctrl.iec_wtt == ied_wtt_file_bin)) {  /* trace records to file binary */
// 26.04.11 KB to-do write record file closed at
#ifndef HL_UNIX
     bol_rc = CloseHandle( dsl_wti1.dsc_hfi1 );
     if (bol_rc == FALSE) {
       m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W CloseHandle WSP Trace file returned error %d.",
                       __LINE__, GetLastError() );
     }
#else
     iml_rc = close( dsl_wti1.imc_fdfi1 );
     if (iml_rc != 0) {
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W close WSP Trace file returned error %d.",
                       __LINE__, errno );
     }
#endif
   }
   dss_wsp_trace_thr_ctrl.iec_wtt = (enum ied_wsp_trace_target) adsl_wt1_w1->imc_wsp_trace_target;  /* enum ied_wsp_trace_target / Trace target */
   if (   (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_ascii)   /* not trace records to file ASCII */
       && (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_bin)) {  /* not trace records to file binary */
     goto p_wtt_ctrl_80;                    /* control command processed */
   }
#ifndef HL_UNIX
#define D_CHARSET_WSP_TRACE ied_chs_utf_16
#else
#define D_CHARSET_WSP_TRACE ieg_charset_system
#endif
   iml_rc = m_cpy_vx_vx( byrlwork1, sizeof(byrlwork1), D_CHARSET_WSP_TRACE,
                         adsl_wt1_w1 + 1, adsl_wt1_w1->imc_len_filename, ied_chs_utf_8 );  /* Unicode UTF-8 */
#undef D_CHARSET_WSP_TRACE
   if (iml_rc <= 0) {
// 26.04.11 KB to-do error message
     dss_wsp_trace_thr_ctrl.iec_wtt = ied_wtt_console;  /* print on console */
     goto p_wtt_ctrl_80;                    /* control command processed */
   }
#ifndef HL_UNIX
   dsl_wti1.dsc_hfi1 = CreateFileW( (WCHAR *) byrlwork1, GENERIC_WRITE, 0, 0,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_wti1.dsc_hfi1 == INVALID_HANDLE_VALUE) {  /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace CreateFile() returned error %d.",
                     __LINE__, GetLastError() );
     dss_wsp_trace_thr_ctrl.iec_wtt = ied_wtt_console;  /* print on console */
     goto p_wtt_ctrl_80;                    /* control command processed */
   }
#else
   dsl_wti1.imc_fdfi1 = open( byrlwork1,
                              O_WRONLY | O_CREAT | O_TRUNC,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
   if (dsl_wti1.imc_fdfi1 < 0) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace open() returned error %d.",
                     __LINE__, errno );
     dss_wsp_trace_thr_ctrl.iec_wtt = ied_wtt_console;  /* print on console */
     goto p_wtt_ctrl_80;                    /* control command processed */
   }
#endif
   if (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_ascii) {  /* not trace records to file ASCII */
     goto p_wtt_ctrl_40;                    /* trace records to file binary */
   }
// 26.04.11 KB to-do write WSP version and when opened
   iml1 = sprintf( byrlwork1, "+ WSP-Trace V01 to file / %s.",
                   chrs_query_main );
   memcpy( byrlwork1 + iml1, chrs_crlf, sizeof(chrs_crlf) );
   iml1 += sizeof(chrs_crlf);
#ifdef B150118
   dsl_time = dsg_this_server.ilc_epoch_started / 1000;  /* time in seconds */
   strftime( byrlwork2, sizeof(byrlwork2), "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
#endif
   dsl_time_1 = dsg_this_server.ilc_epoch_started / 1000;  /* time in seconds */
   strftime( byrlwork2, sizeof(byrlwork2), "%d.%m.%y %H:%M:%S", localtime( &dsl_time_1 ) );
   iml1 += m_hlsnprintf( byrlwork1 + iml1, sizeof(byrlwork1) - iml1 - 2 - 128, ied_chs_ansi_819,
                         "+ server %.*(u8)s PID %d started time %s.",
                         dsg_this_server.imc_len_server_name, dsg_this_server.chrc_server_name,
                         dsg_this_server.imc_pid,
                         byrlwork2 );
   memcpy( byrlwork1 + iml1, chrs_crlf, sizeof(chrs_crlf) );
   iml1 += sizeof(chrs_crlf);
#ifdef B120219
   m_edit_fingerprint( chrl_disp_fp, adss_loconf_1_fill->chrc_fingerprint );
#else
   m_edit_fingerprint( chrl_disp_fp, adsg_loconf_1_inuse->chrc_fingerprint );
#endif
   iml1 += sprintf( byrlwork1 + iml1, "+ fingerprint (SHA1) of configuration file %.*s.",
                    sizeof(chrl_disp_fp), chrl_disp_fp );
   memcpy( byrlwork1 + iml1, chrs_crlf, sizeof(chrs_crlf) );
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, byrlwork1, iml1 + 2, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     goto p_wtt_80;                         /* free memory passed      */
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, byrlwork1, iml1 + 2 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     goto p_wtt_80;                         /* free memory passed      */
   }
#endif
#ifdef B150118
   iml_trace_date = 0;                      /* current date of trace   */
#endif
   memset( &dsl_tm_trace_date, 0, sizeof(struct tm) );  /* current date of trace records */
   goto p_wtt_ctrl_80;                      /* control command processed */

   p_wtt_ctrl_40:                           /* trace records to file binary */
   ill_epoch = adsl_wt1_w1->ilc_epoch;      /* time in microseconds    */
   dsl_time_1 = ill_epoch / (1000 * 1000);  /* epoch in seconds        */
   adsl_tm_w1 = localtime( &dsl_time_1 );
   dsl_tm_l1 = dsl_tm_l2 = *adsl_tm_w1;
   dsl_tm_l1.tm_hour = 0;
   dsl_tm_l1.tm_min = 0;
   dsl_tm_l1.tm_sec = 0;
   if (!memcmp( &dsl_tm_l1, &dsl_tm_trace_date, sizeof(struct tm) )) {
     goto p_wtt_24;                         /* day of trace set        */
   }
   dsl_tm_trace_date = dsl_tm_l1;           /* set day of trace        */
   ill_start_of_day
     = ((HL_LONGLONG) ill_epoch
            - ((HL_LONGLONG) (dsl_tm_l2.tm_hour * 60 * 60 + dsl_tm_l2.tm_min * 60 + dsl_tm_l2.tm_sec) * 1000 * 1000))
          / (1000 * 1000) * (1000 * 1000);
   strftime( byrlwork3, sizeof(byrlwork3),
             "%b %d %Y", &dsl_tm_l2 );
   ill_w1 = ill_epoch - ill_start_of_day;   /* microseconds relative to start of day */
#ifndef HL_UNIX
   iml1                                     /* deviation               */
     = m_get_epoch_ms()                     /* exact time in milliseconds */
         - (m_get_epoch_microsec() + 500) / 1000;
#else
   iml1 = 0;                                /* deviation               */
#endif
   dsl_time_1 = dsg_this_server.ilc_epoch_started / 1000;  /* time in seconds */
   strftime( byrlwork2, sizeof(byrlwork2), "%d.%m.%y %H:%M:%S", localtime( &dsl_time_1 ) );
#ifdef B120219
   m_edit_fingerprint( chrl_disp_fp, adss_loconf_1_fill->chrc_fingerprint );
#else
   m_edit_fingerprint( chrl_disp_fp, adsg_loconf_1_inuse->chrc_fingerprint );
#endif
   iml1 = m_hlsnprintf( byrlwork1, sizeof(byrlwork1), ied_chs_ansi_819,
                        "HOB WSP-Trace V01 to file date %s time %02d:%02d:%02d.%03d.%03d / %s "
                        "+ deviation %d milliseconds "
                        "+ server %.*(u8)s PID %d started time %s."
                        "+ fingerprint (SHA1) of configuration file %.*s.",
                        byrlwork3,
                        (int) ((HL_LONGLONG) ill_w1 / ((HL_LONGLONG) 60 * 60 * 1000 * 1000)),
                        (int) ((HL_LONGLONG) (ill_w1 - ((HL_LONGLONG) ill_w1 / ((HL_LONGLONG) 60 * 60 * 1000 * 1000) * ((HL_LONGLONG) 60 * 60 * 1000 * 1000))) / (60 * 1000 * 1000)),
                        (int) (((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / (60 * 1000 * 1000) * (60 * 1000 * 1000))) / (1000 * 1000)),
                        (int) (((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / (1000 * 1000) * (1000 * 1000))) / 1000 ),
                        (int) ((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / 1000 * 1000)),
                        chrs_query_main,
                        iml1,               /* deviation               */
                        dsg_this_server.imc_len_server_name, dsg_this_server.chrc_server_name,
                        dsg_this_server.imc_pid,
                        byrlwork2,
                        sizeof(chrl_disp_fp), chrl_disp_fp );
   memcpy( byrlwork1 + iml1, chrs_crlf, sizeof(chrs_crlf) );
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, byrlwork1, iml1 + 2, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     goto p_wtt_80;                         /* free memory passed      */
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, byrlwork1, iml1 + 2 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     goto p_wtt_80;                         /* free memory passed      */
   }
#endif

   p_wtt_ctrl_80:                           /* control command processed */
   m_proc_free( adsl_wt1_w1 );              /* free memory trace record */
   goto p_wtt_00;                           /* WSP trace start         */

#ifdef INCL_CMA_DUMP
   p_wtt_cma_00:                            /* dump CMA                */
   dsl_wti1.imc_count = 0;                  /* count entries           */
   bol_rc = m_cma1_gen_dump_01( &dsl_wti1, &m_dump_cma_01 );
#define IML_HEADER 8
   iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                        "- CMA-entries printed: %d.",
                        dsl_wti1.imc_count );  /* count entries        */
   m_wsp_trace_ascii_1( &dsl_wti1, byrlwork1 + IML_HEADER, iml1 );
   if (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_bin) {  /* trace records to file binary */
     goto p_wtt_00;                         /* WSP trace start         */
   }
#ifndef HL_UNIX
   bol_rc = WriteFile( dsl_wti1.dsc_hfi1, &chs_zero, sizeof(chs_zero), &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
   }
#else
   iml_rc = write( dsl_wti1.imc_fdfi1, &chs_zero, sizeof(chs_zero) );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
   }
#endif
   goto p_wtt_00;                           /* WSP trace start         */
#undef IML_HEADER
#endif
} /* end m_wsp_trace_thread()                                          */

static void m_wsp_trace_bin_1( struct dsd_wsp_tr_intern_1 *adsp_wti1,  /* internal WSP trace */
                               struct dsd_wsp_trace_record *adsp_wtr ) {  /* WSP trace record */
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* working variable        */
#endif
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2, iml3, iml4;       /* working variables       */
#ifndef HL_UNIX
   DWORD      dwl_write;                    /* for WriteFile()         */
#endif
   char       chl_w1, chl_w2;               /* working variable        */
   char       *achl_inp_1, *achl_inp_2, *achl_inp_3, *achl_inp_4;  /* input data passed */
   char       *achl_out_1, *achl_out_2;     /* output data             */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_record *adsl_wtr_w2;  /* WSP trace record      */
   char       byrlwork1[ 2048 ];            /* work area               */

   adsl_wtr_w1 = adsp_wtr;                  /* WSP trace record        */
   iml1 = 0;                                /* start displacement zero */
   achl_out_1 = byrlwork1;                  /* output area is here     */
   iml2 = 0;                                /* no output till now      */

   p_wti_data_20:                           /* get binary input data   */
   achl_inp_1 = adsl_wtr_w1->achc_content;  /* content of text / data  */
   achl_inp_2 = achl_inp_1 + adsl_wtr_w1->imc_length;  /* length of text / data */
   if (iml2 != 0) {                         /* not start of new line   */
     goto p_wti_data_44;                    /* output next character   */
   }

   p_wti_data_24:                           /* check if repeated character */
   achl_inp_3 = achl_inp_1;
   achl_inp_4 = achl_inp_2;
   chl_w1 = *achl_inp_3++;
   iml3 = 1;                                /* number of same characters */
   iml4 = 0;                                /* same data till the end  */
   adsl_wtr_w2 = adsl_wtr_w1;               /* get trace data record   */
   while (TRUE) {                           /* loop to search equal characters */
     while (   (achl_inp_3 < achl_inp_4)
            && (*achl_inp_3 == chl_w1)) {
       iml3++;                              /* increment number of same characters */
       achl_inp_3++;                        /* increment input         */
     }
     if (achl_inp_3 < achl_inp_4) break;
     if (adsl_wtr_w2->boc_more == FALSE) {  /* not more data to follow */
       iml4 = 1;                            /* same data till the end  */
       break;
     }
     adsl_wtr_w2 = adsl_wtr_w2->adsc_next;  /* get next record in chain */
// to-do 27.04.11 KB check NULL and binary
     if (adsl_wtr_w2 == NULL) break;        /* end of input data       */
     achl_inp_3 = adsl_wtr_w2->achc_content;  /* content of text / data  */
     achl_inp_4 = achl_inp_3 + adsl_wtr_w2->imc_length;  /* length of text / data */
   }
   if (iml4 == 0) {                         /* not end of input data   */
     iml3 &= 0 - 0X10;                      /* only full lines         */
   }
   if (iml3 < 0X10) {                       /* not full line           */
     goto p_wti_data_40;                    /* start of new line with binary input data */
   }
   chl_w2 = '.';                            /* translate character     */
   if (((signed char) chl_w1) >= 0X20) chl_w2 = chl_w1;
   iml4 = 4;
   do {
     iml4--;
     *(achl_out_1 + iml4) = chrstrans[ (iml1 >> ((4 - 1 - iml4) << 2)) & 0X0F ];
   } while (iml4 > 0);
   iml1 += iml3;                            /* compute next displacement */
   iml4 = sprintf( achl_out_1 + 4, "  repeated character %02X \"%c\" times %d/0X%04X.",
                   (unsigned char) chl_w1, chl_w2, iml3, iml3 );
   achl_out_2 = achl_out_1;                 /* save output area        */
   achl_out_1 += 4 + iml4;                  /* end of this output      */
   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_console:                  /* print on console        */
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                       __LINE__, achl_out_1 - achl_out_2, achl_out_2 );
       achl_out_1 = byrlwork1;              /* output area is here     */
       break;
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
       memcpy( achl_out_1, chrs_crlf, sizeof(chrs_crlf) );
       achl_out_1 += sizeof(chrs_crlf);
       if (achl_out_1 < (byrlwork1 + sizeof(byrlwork1) - 80)) {  /* output area is not full */
         break;
       }
#ifndef HL_UNIX
       bol_rc = WriteFile( adsp_wti1->dsc_hfi1, byrlwork1, achl_out_1 - byrlwork1, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
         return;                            /* all done                */
       }
#else
       iml_rc = write( adsp_wti1->imc_fdfi1, byrlwork1, achl_out_1 - byrlwork1 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         return;                            /* all done                */
       }
#endif
       achl_out_1 = byrlwork1;              /* output area is here     */
       break;
   }
   while (TRUE) {
     iml4 = achl_inp_2 - achl_inp_1;        /* length in this gather   */
     if (iml4 > iml3) iml4 = iml3;
     achl_inp_1 += iml4;
     iml3 -= iml4;
     if (iml3 <= 0) break;
     if (   (adsl_wtr_w1->boc_more == FALSE)  /* not more data to follow */
         || (adsl_wtr_w1->adsc_next == NULL)) {  /* more data to follow */
// 06.05.11 KB illogic
     }
     adsl_wtr_w1 = adsl_wtr_w1->adsc_next;  /* get next record in chain */
     achl_inp_1 = adsl_wtr_w1->achc_content;  /* content of text / data  */
     achl_inp_2 = achl_inp_1 + adsl_wtr_w1->imc_length;  /* length of text / data */
   }
   if (achl_inp_1 < achl_inp_2) {           /* more data in this record */
     goto p_wti_data_24;                    /* check if repeated character */
   }
   if (adsl_wtr_w1->boc_more) {             /* more data to follow     */
     adsl_wtr_w1 = adsl_wtr_w1->adsc_next;  /* get next record in chain */
     goto p_wti_data_20;                    /* get binary input data   */
   }
   goto p_wti_data_80;                      /* end of write binary input data */

   p_wti_data_40:                           /* start of new line with binary input data */
   iml4 = 4;
   do {
     iml4--;
     *(achl_out_1 + iml4) = chrstrans[ (iml1 >> ((4 - 1 - iml4) << 2)) & 0X0F ];
   } while (iml4 > 0);
   memset( achl_out_1 + 4, ' ', 2 + 4 * (12 + 1) + 1 + 1 + 0X10 );
   *(achl_out_1 + 4 + 2 + 4 * (12 + 1) + 1) = '*';
   *(achl_out_1 + 4 + 2 + 4 * (12 + 1) + 1 + 1 + 0X10) = '*';
   achl_out_2 = achl_out_1 + 4 + 2 - 1;     /* here first digit minus one */

   p_wti_data_44:                           /* output next character   */
   if ((iml2 & 3) == 0) achl_out_2++;       /* leave space             */
   chl_w1 = *achl_inp_1++;                  /* get next character      */
   *achl_out_2++ = chrstrans[ (((unsigned char) chl_w1) >> 4) & 0X0F ];
   *achl_out_2++ = chrstrans[ chl_w1 & 0X0F ];
   achl_out_2++;
   chl_w2 = '.';                            /* translate character     */
   if (((signed char) chl_w1) >= 0X20) chl_w2 = chl_w1;
   *(achl_out_1 + 4 + 2 + 4 * (12 + 1) + 1 + 1 + iml2) = chl_w2;
   iml2++;                                  /* one character written   */
   if (iml2 < 0X10) {                       /* line is not full        */
     if (achl_inp_1 < achl_inp_2) {         /* more data in this record */
       goto p_wti_data_44;                  /* output next character   */
     }
     if (adsl_wtr_w1->boc_more) {           /* more data to follow     */
       adsl_wtr_w1 = adsl_wtr_w1->adsc_next;  /* get next record in chain */
       goto p_wti_data_20;                  /* get binary input data   */
     }
   }
   iml1 += 0X10;                            /* compute next displacement */
   iml2 = 0;                                /* no output till now      */
   achl_out_2 = achl_out_1;                 /* save output area        */
   achl_out_1 += 4 + 2 + 4 * (12 + 1) + 1 + 1 + 0X10 + 1;  /* end of this output */
   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_console:                  /* print on console        */
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                       __LINE__, achl_out_1 - achl_out_2, achl_out_2 );
       achl_out_1 = byrlwork1;              /* output area is here     */
       break;
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
       memcpy( achl_out_1, chrs_crlf, sizeof(chrs_crlf) );
       achl_out_1 += sizeof(chrs_crlf);
       if (achl_out_1 < (byrlwork1 + sizeof(byrlwork1) - 80)) {  /* output area is not full */
         break;
       }
#ifndef HL_UNIX
       bol_rc = WriteFile( adsp_wti1->dsc_hfi1, byrlwork1, achl_out_1 - byrlwork1, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
         return;                            /* all done                */
       }
#else
       iml_rc = write( adsp_wti1->imc_fdfi1, byrlwork1, achl_out_1 - byrlwork1 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
         return;                            /* all done                */
       }
#endif
       achl_out_1 = byrlwork1;              /* output area is here     */
       break;
   }
   if (achl_inp_1 < achl_inp_2) {           /* more data in this record */
     goto p_wti_data_24;                    /* check if repeated character */
   }
   if (adsl_wtr_w1->boc_more) {             /* more data to follow     */
     adsl_wtr_w1 = adsl_wtr_w1->adsc_next;  /* get next record in chain */
     goto p_wti_data_20;                    /* get binary input data   */
   }

   p_wti_data_80:                           /* end of write binary input data */
   while (dss_wsp_trace_thr_ctrl.iec_wtt == ied_wtt_file_ascii) {  /* trace records to file ASCII */
     if (achl_out_1 <= byrlwork1) break;    /* output area is empty    */
#ifndef HL_UNIX
     bol_rc = WriteFile( adsp_wti1->dsc_hfi1, byrlwork1, achl_out_1 - byrlwork1, &dwl_write, 0 );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                       __LINE__, GetLastError() );
       return;                              /* all done                */
     }
#else
     iml_rc = write( adsp_wti1->imc_fdfi1, byrlwork1, achl_out_1 - byrlwork1 );
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                       __LINE__, errno );
       return;                              /* all done                */
     }
#endif
     break;
   }
   return;                                  /* all done                */
} /* end m_wsp_trace_bin_1()                                           */

#ifdef INCL_CMA_DUMP
static void m_dump_cma_01( void * vpp_userfld, struct dsd_cma_dump_01 *adsp_cm01 ) {
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* working variable        */
#endif
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2;                   /* working variables       */
#ifndef HL_UNIX
   DWORD      dwl_write;                    /* for WriteFile()         */
#endif
   HL_LONGLONG ill_w1;                      /* working variable        */
   HL_LONGLONG ill_start_of_day;            /* microseconds at start of day */
   time_t     dsl_time_1;                   /* for time                */
   char       *achl_w1, *achl_w2;           /* working vraiables       */
   struct tm  *adsl_tm_w1;                  /* working variable        */
   struct tm  dsl_tm_l1;                    /* working variable        */
   struct tm  dsl_tm_trace_date;            /* date of trace records   */
   struct dsd_wsp_trace_record dsl_wtr_l;   /* WSP trace record        */
   char       byrlwork1[ 2048 ];            /* work area               */
   char       byrlwork2[ 64 ];              /* work area               */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T CMA entry \"%(ucs)s\"",
                   __LINE__, &adsp_cm01->dsc_ucs_name );
//#endif
#define ADSL_WTI1_G ((struct dsd_wsp_tr_intern_1 *) vpp_userfld)  /* internal WSP trace */
#define IML_HEADER 8
   ADSL_WTI1_G->imc_count++;                /* count entries           */
   iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                        "+ CMA-entry no=%08d name \"%(ucs)s\"",
                        ADSL_WTI1_G->imc_count,  /* count entries      */
                        &adsp_cm01->dsc_ucs_name );
   m_wsp_trace_ascii_1( ADSL_WTI1_G, byrlwork1 + IML_HEADER, iml1 );
   iml1 = m_len_bytes_ucs( &adsp_cm01->dsc_ucs_name );
   if (iml1 > 0) {                          /* length valid            */
     if (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_bin) {  /* trace records to file binary */
       memset( &dsl_wtr_l, 0, sizeof(struct dsd_wsp_trace_record) );  /* WSP trace record */
       dsl_wtr_l.achc_content = (char *) adsp_cm01->dsc_ucs_name.ac_str;  /* content of text / data  */
       dsl_wtr_l.imc_length = iml1;         /* length of text / data */
       m_wsp_trace_bin_1( ADSL_WTI1_G, &dsl_wtr_l );
     } else {                               /* binary output           */
       /* first header for binary file                                 */
       memcpy( byrlwork1 + IML_HEADER, adsp_cm01->dsc_ucs_name.ac_str, iml1 );
       achl_w2 = byrlwork1 + IML_HEADER + iml1;
       achl_w1 = byrlwork1 + IML_HEADER - 1;
       *achl_w1 = (unsigned char) 'B';      /* type binary             */
       iml2 = 0;                            /* clear more flag         */
       while (TRUE) {                       /* output length NHASN     */
         *(--achl_w1) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output digit */
         iml1 >>= 7;                        /* shift bits              */
         if (iml1 <= 0) break;              /* end of number           */
         iml2 = 0X80;                       /* set more flag           */
       }
#ifndef HL_UNIX
       bol_rc = WriteFile( ADSL_WTI1_G->dsc_hfi1, achl_w1, achl_w2 - achl_w1, &dwl_write, 0 );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                         __LINE__, GetLastError() );
       }
#else
       iml_rc = write( ADSL_WTI1_G->imc_fdfi1, achl_w1, achl_w2 - achl_w1 );
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                         __LINE__, errno );
       }
#endif
     }
   }
   dsl_time_1 = adsp_cm01->ilc_epoch_last_used / 1000;  /* epoch in seconds */
   adsl_tm_w1 = localtime( &dsl_time_1 );
   dsl_tm_trace_date = dsl_tm_l1 = *adsl_tm_w1;
   ill_start_of_day
     = ((HL_LONGLONG) adsp_cm01->ilc_epoch_last_used
            - ((HL_LONGLONG) (dsl_tm_l1.tm_hour * 60 * 60 + dsl_tm_l1.tm_min * 60 + dsl_tm_l1.tm_sec) * 1000))
          / 1000 * 1000;
   dsl_tm_trace_date.tm_hour = 0;
   dsl_tm_trace_date.tm_min = 0;
   dsl_tm_trace_date.tm_sec = 0;
   iml2 = (int) strftime( byrlwork2, sizeof(byrlwork2),
                          "%b %d %Y", &dsl_tm_trace_date );
   ill_w1 = (HL_LONGLONG) adsp_cm01->ilc_epoch_last_used - ill_start_of_day;  /* milliseconds relative to start of day */
   iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                        "  last used %.*s time %02d:%02d:%02d.%03d.",
                        iml2, byrlwork2,    /* date                    */
                        (int) (ill_w1 / (60 * 60 * 1000)),
                        (int) ((HL_LONGLONG) (ill_w1 - ((HL_LONGLONG) ill_w1 / ((HL_LONGLONG) 60 * 60 * 1000) * ((HL_LONGLONG) 60 * 60 * 1000))) / (60 * 1000)),
                        (int) (((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / (60 * 1000) * (60 * 1000))) / 1000),
                        (int) ((HL_LONGLONG) ill_w1 - ((HL_LONGLONG) ill_w1 / 1000 * 1000)) );
   m_wsp_trace_ascii_1( ADSL_WTI1_G, byrlwork1 + IML_HEADER, iml1 );
   if (adsp_cm01->imc_retention_time) {     /* retention time in seconds */
     iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                          "  retention time in seconds: %d.",
                          adsp_cm01->imc_retention_time );  /* retention time in seconds */
     m_wsp_trace_ascii_1( ADSL_WTI1_G, byrlwork1 + IML_HEADER, iml1 );
   }
   if (adsp_cm01->imc_no_locks) {           /* number of locks         */
     iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                          "  number of current locks: %d.",
                          adsp_cm01->imc_no_locks );  /* number of locks */
     m_wsp_trace_ascii_1( ADSL_WTI1_G, byrlwork1 + IML_HEADER, iml1 );
   }
   iml1 = m_hlsnprintf( byrlwork1 + IML_HEADER, sizeof(byrlwork1) - IML_HEADER - sizeof(chrs_crlf), ied_chs_ansi_819,
                        "  area %p length %d/0X%X.",
                        adsp_cm01->achc_area, adsp_cm01->imc_size_area, adsp_cm01->imc_size_area );
   m_wsp_trace_ascii_1( ADSL_WTI1_G, byrlwork1 + IML_HEADER, iml1 );
   if (adsp_cm01->imc_size_area <= 0) return;
   if (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_file_bin) {  /* trace records to file binary */
     memset( &dsl_wtr_l, 0, sizeof(struct dsd_wsp_trace_record) );  /* WSP trace record */
     dsl_wtr_l.achc_content = adsp_cm01->achc_area;  /* content of text / data  */
     dsl_wtr_l.imc_length = adsp_cm01->imc_size_area;  /* length of text / data */
     m_wsp_trace_bin_1( ADSL_WTI1_G, &dsl_wtr_l );
     return;
   }
   /* first header for binary file                                     */
   achl_w1 = byrlwork1 + IML_HEADER - 1;
   *achl_w1 = (unsigned char) 'B';          /* type binary             */
   iml1 = adsp_cm01->imc_size_area;         /* get length net          */
   iml2 = 0;                                /* clear more flag         */
   while (TRUE) {                           /* output length NHASN     */
     *(--achl_w1) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output digit */
     iml1 >>= 7;                            /* shift bits              */
     if (iml1 <= 0) break;                  /* end of number           */
     iml2 = 0X80;                           /* set more flag           */
   }
#ifndef HL_UNIX
   bol_rc = WriteFile( ADSL_WTI1_G->dsc_hfi1, achl_w1, (byrlwork1 + IML_HEADER) - achl_w1, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     return;                                /* all done                */
   }
#else
   iml_rc = write( ADSL_WTI1_G->imc_fdfi1, achl_w1, (byrlwork1 + IML_HEADER) - achl_w1 );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     return;                                /* all done                */
   }
#endif
#ifndef HL_UNIX
   bol_rc = WriteFile( ADSL_WTI1_G->dsc_hfi1, adsp_cm01->achc_area, adsp_cm01->imc_size_area, &dwl_write, 0 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                     __LINE__, GetLastError() );
     return;                                /* all done                */
   }
#else
   iml_rc = write( ADSL_WTI1_G->imc_fdfi1, adsp_cm01->achc_area, adsp_cm01->imc_size_area );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                     __LINE__, errno );
     return;                                /* all done                */
   }
#endif
#undef IML_HEADER
#undef ADSL_WTI1_G
} /* end m_dump_cma_01()                                               */

/** write trace record ASCII                                           */
/* before and after the content there needs to be space for additional data */
static void m_wsp_trace_ascii_1( struct dsd_wsp_tr_intern_1 *adsp_wti1,  /* internal WSP trace */
                                 char *achp_out, int imp_len_out ) {
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* working variable        */
#endif
#ifdef HL_UNIX
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2;                   /* working variables       */
#ifndef HL_UNIX
   DWORD      dwl_write;                    /* for WriteFile()         */
#endif

   switch (dss_wsp_trace_thr_ctrl.iec_wtt) {  /* WSP Trace target      */
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
       memcpy( achp_out + imp_len_out, chrs_crlf, sizeof(chrs_crlf) );
       imp_len_out += sizeof(chrs_crlf);
       break;
     case ied_wtt_file_bin:                 /* trace records to file binary */
       *(--achp_out) = (unsigned char) 'A';  /* type ASCII             */
       imp_len_out++;                       /* length net              */
       iml1 = imp_len_out;                  /* get length net          */
       iml2 = 0;                            /* clear more flag         */
       while (TRUE) {                       /* output length NHASN     */
         *(--achp_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output digit */
         imp_len_out++;                     /* length net              */
         iml1 >>= 7;                        /* shift bits              */
         if (iml1 <= 0) break;              /* end of number           */
         iml2 = 0X80;                       /* set more flag           */
       }
       break;
   }
   if (dss_wsp_trace_thr_ctrl.iec_wtt == ied_wtt_console) {  /* print on console */
     m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T %.*s",
                     __LINE__, imp_len_out, achp_out );
   } else {
#ifndef HL_UNIX
     bol_rc = WriteFile( adsp_wti1->dsc_hfi1, achp_out, imp_len_out, &dwl_write, 0 );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W WSP-Trace WriteFile() returned error %d.",
                       __LINE__, GetLastError() );
       return;                              /* all done                */
     }
#else
     iml_rc = write( adsp_wti1->imc_fdfi1, achp_out, imp_len_out );
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W WSP-Trace write() returned error %d.",
                       __LINE__, errno );
       return;                              /* all done                */
     }
#endif
   }
} /* end m_wsp_trace_ascii_1()                                         */
#endif
