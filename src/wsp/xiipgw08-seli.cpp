//#define DEBUG_130708                        /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
// 15.04.06 KB UUUU vpp_user_fld_conn invalid
// 15.09.12 KB move parts from -seli.cpp to -tun.cpp
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif

static int m_check_servent( void **aap_handle, BOOL *abop_found_last,
                            struct dsd_server_list_1 *adsp_selserv,
                            struct dsd_get_servent_1 *adsp_gse1 );

/** select server from SOCKS5 input
    if inp_len_server is zero, take first server                       */
static inline BOOL m_sel_server_socks5_1( void *vpp_user_fld_conn,
                 struct dsd_user_entry *adsp_usent,
                 struct dsd_user_group *adsp_usgro,
                 struct dsd_unicode_string *adsp_ucs_server,
                 enum ied_scp_def iep_scp_def, char *chrp_prot, int inp_len_prot ) {
   BOOL       bol1;                         /* working variable        */
   int        inl1, inl2;                   /* working variables       */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_sel_server_socks5_1() called vpp_user_fld_conn=%p",
                   vpp_user_fld_conn );
#endif
#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + inl1) * sizeof(void *))))
#endif
   /* check if server already selected - to be sure                    */
   if (ADSL_CONN1_G->adsc_server_conf_1) return FALSE;
   if (ADSL_CONN1_G->adsc_gate1->inc_no_seli) {
     inl1 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* start in reverse order */
     do {
       inl1--;                              /* check next entry        */
       /* get anchor of chain server conf                                */
#ifdef OLD_1112
       adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#endif
#ifndef OLD_1112
       adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_gate1->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;  /* list of servers */
#endif
       while (adsl_server_conf_1_w1) {      /* loop over chain server entry */
         /* check protocol                                             */
         do {
           /* protocol HTTP                                            */
           if (adsl_server_conf_1_w1->iec_scp_def == ied_scp_http) break;
           if (adsl_server_conf_1_w1->inc_function != DEF_FUNC_CASC_WSP) {
             if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
             if (iep_scp_def == ied_scp_spec) {
               if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
               if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                             + adsl_server_conf_1_w1->inc_no_sdh
                               * sizeof(struct dsd_sdh_work_1)
                             + adsl_server_conf_1_w1->inc_len_name,
                           chrp_prot,
                           inp_len_prot )) {
                 break;
               }
             }
           }
           bol1 = TRUE;                     /* set this selected       */
           inl2 = 0;                        /* set this selected       */
#ifdef B120607
           if (inp_len_server) {            /* with field from client  */
#ifdef OLD_1112
             bol1 = m_cmpi_u16z_u8l( &inl2,
                                     (HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)
                                                    + adsl_server_conf_1_w1->inc_no_sdh
                                                      * sizeof(struct dsd_sdh_work_1) ),
                                     achp_server, inp_len_server );
#endif
#ifndef OLD_1112
             bol1 = m_cmpi_u16z_u8l( &inl2,
                                     adsl_server_conf_1_w1->awcc_name,
                                     achp_server, inp_len_server );
#endif
           }
#endif
#ifndef B120607
           if ((adsp_ucs_server) && (adsp_ucs_server->imc_len_str != 0)) {  /* with field from client */
             bol1 = m_cmpi_vx_vx( &inl2,
                                  adsl_server_conf_1_w1->awcc_name,
                                  -1,
                                  ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                                  adsp_ucs_server->ac_str,  /* address of string */
                                  adsp_ucs_server->imc_len_str,  /* length string in elements */
                                  adsp_ucs_server->iec_chs_str );  /* character set string */
           }
#endif
           if (bol1 && (inl2 == 0)) {
             /* server has been selected                               */
             ADSL_CONN1_G->adsc_server_conf_1
               = adsl_server_conf_1_w1;
             if (adsl_server_conf_1_w1->inc_no_sdh >= 2) {
               ADSL_CONN1_G->adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
               memset( ADSL_CONN1_G->adsrc_sdh_s_1, 0, adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
             }
#ifndef B120121
#ifndef HL_UNIX
             m_clconn1_naeg1( ADSL_CONN1_G );
#endif
#endif
#ifdef OLD_1112
             m_hlnew_printf( HLOG_XYZ1, "HWSPS063I GATE=%(ux)s SNO=%08d INETA=%s select-server from server-list %(ux)s",
                             ADSL_CONN1_G->adsc_gate1 + 1,
                             ADSL_CONN1_G->dsc_co_sort.imc_sno,
                             ADSL_CONN1_G->chrc_ineta,
                             (char *) (adsl_server_conf_1_w1 + 1)
                               + adsl_server_conf_1_w1->inc_no_sdh
                                 * sizeof(struct dsd_sdh_work_1) );
#endif
#ifndef OLD_1112
             m_hlnew_printf( HLOG_XYZ1, "HWSPS063I GATE=%(ux)s SNO=%08d INETA=%s select-server from server-list %(ux)s",
                             ADSL_CONN1_G->adsc_gate1 + 1,
                             ADSL_CONN1_G->dsc_co_sort.imc_sno,
                             ADSL_CONN1_G->chrc_ineta,
                             adsl_server_conf_1_w1->awcc_name );
#endif
             return TRUE;
           }
         } while (FALSE);
         adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
       }
     } while (inl1 > 0);                    /* for all server lists    */
   }
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif
   if (adsp_usgro == NULL) return FALSE;
   if (adsp_usgro->inc_no_seli == 0) return FALSE;
#ifdef OLD_1112
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_usgro + 1) \
                         + ((adsp_usgro->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + inl1 * sizeof(void *))))
#endif
   inl1 = adsp_usgro->inc_no_seli;          /* start in reverse order  */
   do {
     inl1--;                                /* check next entry        */
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_2->adsc_server_conf_1;
#endif
#ifndef OLD_1112
     adsl_server_conf_1_w1 = adsp_usgro->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
       /* check protocol                                               */
       do {
         /* protocol HTTP                                              */
         if (adsl_server_conf_1_w1->iec_scp_def == ied_scp_http) break;
         if (adsl_server_conf_1_w1->inc_function != DEF_FUNC_CASC_WSP) {
           if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
           if (iep_scp_def == ied_scp_spec) {
             if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
#ifdef OLD_1112
             if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                           + adsl_server_conf_1_w1->inc_no_sdh
                             * sizeof(struct dsd_sdh_work_1)
                           + adsl_server_conf_1_w1->inc_len_name,
                         chrp_prot,
                         inp_len_prot )) {
               break;
             }
#endif
#ifndef OLD_1112
             if (memcmp( adsl_server_conf_1_w1->awcc_protocol,
                         chrp_prot,
                         inp_len_prot )) {
               break;
             }
#endif
           }
         }
         bol1 = TRUE;                       /* set this selected       */
         inl2 = 0;                          /* set this selected       */
#ifdef B120607
         if (inp_len_server) {              /* with field from client  */
#ifdef OLD_1112
           bol1 = m_cmpi_u16z_u8l( &inl2,
                                   (HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)
                                                  + adsl_server_conf_1_w1->inc_no_sdh
                                                    * sizeof(struct dsd_sdh_work_1) ),
                                   achp_server, inp_len_server );
#endif
#ifndef OLD_1112
           bol1 = m_cmpi_u16z_u8l( &inl2,
                                   adsl_server_conf_1_w1->awcc_name,
                                   achp_server, inp_len_server );
#endif
         }
#endif
#ifndef B120607
         if ((adsp_ucs_server) && (adsp_ucs_server->imc_len_str != 0)) {  /* with field from client */
           bol1 = m_cmpi_vx_vx( &inl2,
                                adsl_server_conf_1_w1->awcc_name,
                                -1,
                                ied_chs_utf_16,  /* Unicode UTF-16 = WCHAR */
                                adsp_ucs_server->ac_str,  /* address of string */
                                adsp_ucs_server->imc_len_str,  /* length string in elements */
                                adsp_ucs_server->iec_chs_str );  /* character set string */
         }
#endif
         if (bol1 && (inl2 == 0)) {
           /* server has been selected                                 */
           ADSL_CONN1_G->adsc_server_conf_1
             = adsl_server_conf_1_w1;
#ifdef OLD_1112
           m_hlnew_printf( HLOG_XYZ1, "HWSPS064I GATE=%(ux)s SNO=%08d INETA=%s select-server from user-group server-list %(ux)s",
                           ADSL_CONN1_G->adsc_gate1 + 1,
                           ADSL_CONN1_G->dsc_co_sort.imc_sno,
                           ADSL_CONN1_G->chrc_ineta,
                           (char *) (adsl_server_conf_1_w1 + 1)
                             + adsl_server_conf_1_w1->inc_no_sdh
                               * sizeof(struct dsd_sdh_work_1) );
#endif
#ifndef OLD_1112
           m_hlnew_printf( HLOG_XYZ1, "HWSPS064I GATE=%(ux)s SNO=%08d INETA=%s select-server from user-group server-list %(ux)s",
                           ADSL_CONN1_G->adsc_gate1 + 1,
                           ADSL_CONN1_G->dsc_co_sort.imc_sno,
                           ADSL_CONN1_G->chrc_ineta,
                           adsl_server_conf_1_w1->awcc_name );
#endif
           return TRUE;
         }
       } while (FALSE);
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
   } while (inl1 > 0);                      /* for all server lists    */
#ifdef OLD_1112
#undef ADSL_SELSERV_2
#endif
   return FALSE;
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_sel_server_socks5_1()                                       */

/** return how many server entries                                     */
static inline int m_conn_get_no_servent( void *vpp_user_fld_conn,
                 enum ied_scp_def iep_scp_def, char *chrp_prot, int inp_len_prot ) {
   int        inl1, inl2;                   /* working variables       */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
   if (ADSL_CONN1_G->adsc_gate1->inc_no_seli == 0) return 0;
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + inl1) * sizeof(void *))))
#endif
   inl2 = 0;                                /* count servers           */
   inl1 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* start in reverse order */
   do {
     inl1--;                                /* check next entry        */
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#endif
#ifndef OLD_1112
     adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_gate1->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;  /* list of servers */
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
       /* check protocol                                               */
       do {
         if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
         if (iep_scp_def == ied_scp_spec) {
           if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
           if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                         + adsl_server_conf_1_w1->inc_no_sdh
                           * sizeof(struct dsd_sdh_work_1)
                         + adsl_server_conf_1_w1->inc_len_name,
                       chrp_prot,
                       inp_len_prot )) {
             break;
           }
         }
         inl2++;                            /* count the server        */
       } while (FALSE);
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
   } while (inl1 > 0);                      /* for all server lists    */
   return inl2;                             /* return the number       */
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* m_conn_get_no_servent()                                           */

/** return name of server entry                                        */
static HL_WCHAR * m_conn_get_servent_by_no( void *vpp_user_fld_conn, int inp1,
                 ied_scp_def iep_scp_def, char *chrp_prot, int inp_len_prot ) {
   int        inl1, inl2;                   /* working variables       */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + inl1) * sizeof(void *))))
#endif
   inl2 = 0;                                /* count servers           */
   inl1 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* start in reverse order */
   do {
     inl1--;                                /* check next entry        */
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#endif
#ifndef OLD_1112
     adsl_server_conf_1_w1 = ADSL_CONN1_G->adsc_gate1->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;  /* list of servers */
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
       /* check protocol                                               */
       do {
         if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
         if (iep_scp_def == ied_scp_spec) {
           if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
           if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                         + adsl_server_conf_1_w1->inc_no_sdh
                           * sizeof(struct dsd_sdh_work_1)
                         + adsl_server_conf_1_w1->inc_len_name,
                       chrp_prot,
                       inp_len_prot )) {
             break;
           }
         }
         if (inl2 == inp1) {                /* server found            */
           return (HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)
                                  + adsl_server_conf_1_w1->inc_no_sdh
                                    * sizeof(struct dsd_sdh_work_1) );
         }
         inl2++;                            /* count the server        */
       } while (FALSE);
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
   } while (inl1 > 0);                      /* for all server lists    */
   m_hlnew_printf( HLOG_XYZ1, "HWSPS070W GATE=%(ux)s SNO=%08d INETA=%s m_conn_get_servent_by_no() failed %d %d",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta, inp1, inl2 );
   return NULL;                             /* server not found        */
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* m_conn_get_servent_by_no()                                        */

/** return how many server entries of this user                        */
static inline int m_conn_get_no_user_servent( void *vpp_user_fld_conn,
                 struct dsd_user_entry *adsp_usent,
                 struct dsd_user_group *adsp_usgro,
                 ied_scp_def iep_scp_def, char *chrp_prot, int inp_len_prot ) {
   int        inl1, inl2, inl3;             /* working variables       */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
   if (adsp_usgro == NULL) return 0;
   if (adsp_usgro->inc_no_seli == 0) return 0;
#ifdef OLD_1112
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_usgro + 1) \
                         + ((adsp_usgro->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + inl1 * sizeof(void *))))
#endif
   inl2 = 0;                                /* count servers           */
   inl1 = adsp_usgro->inc_no_seli;          /* start in reverse order  */
   while (TRUE) {
     if (inl1 == 0) break;                  /* was last entry          */
     inl1--;                                /* check next entry        */
     /* check if server-list already counted from normal               */
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + inl3) * sizeof(void *))))
#endif
     inl3 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* get number of se-l */
     while (TRUE) {
       inl3--;
       if (inl3 < 0) break;
#ifdef OLD_1112
       if (ADSL_SELSERV_1 == ADSL_SELSERV_2) break;
#endif
#ifndef OLD_1112
       if (ADSL_CONN1_G->adsc_gate1->adsrc_server_list_1[ inl3 ] == adsp_usgro->adsrc_server_list_1[ inl1 ]) break;
#endif
     }
     if (inl3 >= 0) break;                  /* this one already counted */
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_2->adsc_server_conf_1;
#endif
#ifndef OLD_1112
     adsl_server_conf_1_w1 = adsp_usgro->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
       /* check protocol                                               */
       do {
         if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
         if (iep_scp_def == ied_scp_spec) {
           if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
           if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                         + adsl_server_conf_1_w1->inc_no_sdh
                           * sizeof(struct dsd_sdh_work_1)
                         + adsl_server_conf_1_w1->inc_len_name,
                       chrp_prot,
                       inp_len_prot )) {
             break;
           }
         }
         inl2++;                            /* count the server        */
       } while (FALSE);
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
   }
#ifdef OLD_1112
#undef ADSL_SELSERV_2
#endif
   return inl2;                             /* return number found     */
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_conn_get_no_user_servent()                                  */

/** retrieve name of server-entry of specific user                     */
static HL_WCHAR * m_conn_get_user_servent_by_no( void *vpp_user_fld_conn,
                   struct dsd_user_entry *adsp_usent,
                   struct dsd_user_group *adsp_usgro,
                   int inp1,
                   ied_scp_def iep_scp_def, char *chrp_prot, int inp_len_prot ) {
   int        inl1, inl2, inl3;             /* working variables       */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
   if (adsp_usgro == NULL) return NULL;
   if (adsp_usgro->inc_no_seli == 0) return NULL;
#ifdef OLD_1112
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_usgro + 1) \
                         + ((adsp_usgro->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + inl1 * sizeof(void *))))
#endif
   inl2 = 0;                                /* count servers           */
   inl1 = adsp_usgro->inc_no_seli;          /* start in reverse order  */
   while (TRUE) {
     if (inl1 == 0) break;                  /* was last entry          */
     inl1--;                                /* check next entry        */
     /* check if server-list already counted from normal               */
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1) \
                         + ((ADSL_CONN1_G->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + ADSL_CONN1_G->adsc_gate1->inc_no_usgro + inl3) * sizeof(void *))))
#endif
     inl3 = ADSL_CONN1_G->adsc_gate1->inc_no_seli;  /* get number of se-l */
     while (TRUE) {
       inl3--;
       if (inl3 < 0) break;
#ifdef OLD_1112
       if (ADSL_SELSERV_1 == ADSL_SELSERV_2) break;
#endif
#ifndef OLD_1112
       if (ADSL_CONN1_G->adsc_gate1->adsrc_server_list_1[ inl3 ] == adsp_usgro->adsrc_server_list_1[ inl1 ]) break;
#endif
     }
     if (inl3 >= 0) break;                  /* this one already counted */
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#endif
     /* get anchor of chain server conf                                */
#ifdef OLD_1112
     adsl_server_conf_1_w1 = ADSL_SELSERV_2->adsc_server_conf_1;
#endif
#ifndef OLD_1112
     adsl_server_conf_1_w1 = adsp_usgro->adsrc_server_list_1[ inl1 ]->adsc_server_conf_1;
#endif
     while (adsl_server_conf_1_w1) {        /* loop over chain server entry */
       /* check protocol                                               */
       do {
         if (adsl_server_conf_1_w1->iec_scp_def != iep_scp_def) break;
         if (iep_scp_def == ied_scp_spec) {
           if (inp_len_prot != adsl_server_conf_1_w1->inc_len_protocol) break;
           if (memcmp( (char *) (adsl_server_conf_1_w1 + 1)
                         + adsl_server_conf_1_w1->inc_no_sdh
                           * sizeof(struct dsd_sdh_work_1)
                         + adsl_server_conf_1_w1->inc_len_name,
                       chrp_prot,
                       inp_len_prot )) {
             break;
           }
         }
         if (inl2 == inp1) {                /* server found            */
           return (HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)
                                  + adsl_server_conf_1_w1->inc_no_sdh
                                    * sizeof(struct dsd_sdh_work_1) );
         }
         inl2++;                            /* count the server        */
       } while (FALSE);
       adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
     }
   }
#ifdef OLD_1112
#undef ADSL_SELSERV_2
#endif
   return NULL;                             /* entry not found         */
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_conn_get_user_servent_by_no()                               */

/** return server-type                                                 */
static inline ied_set_def m_conn_get_set( void * vpp_user_fld_conn,
                                          BOOL bop_reset ) {
#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_user_fld_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_user_fld_conn)
#endif
   if (bop_reset) {                         /* reset selected server   */
     if (ADSL_CONN1_G->adsc_gate1->ifunction == DEF_FUNC_SS5H) {
       ADSL_CONN1_G->adsc_server_conf_1 = NULL;
     }
   }
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {
     if (ADSL_CONN1_G->adsc_gate1->ifunction == DEF_FUNC_SS5H) {
       return ied_set_ss5h;                 /* SELECT-SOCKS5-HTTP      */
     }
     return ied_set_invalid;
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_function < 0) {  /* function WTSGATE or VDI-WSP */
     return ied_set_loadbal;                /* load balancing          */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_PTTD) {
     return ied_set_pttd;                   /* pass-thru-to-desktop    */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_CASC_WSP) {  /* function CASCADED-WSP */
     return ied_set_casc_wsp;               /* CASCADED-WSP            */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->inc_function == DEF_FUNC_L2TP) {  /* function L2TP UDP connection */
     return ied_set_l2tp;                   /* L2TP UDP connection     */
   }
   return ied_set_direct;                   /* connect direct          */
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_conn_get_set()                                              */

/** return address of user                                             */
inline dsd_user_entry ** m_get_addr_user_entry( void * vpp_conn ) {
#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_conn)
#endif
   return &ADSL_CONN1_G->adsc_user_entry;
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_get_addr_user_entry()                                       */

/** return address of user-group                                       */
inline dsd_user_group ** m_get_addr_user_group( void * vpp_conn ) {
#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_conn)
#endif
   return &ADSL_CONN1_G->adsc_user_group;
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_get_addr_user_group()                                       */

/** authenticate an user against WSP internal List of Users            */
static ied_chid_ret m_auth_user( struct dsd_user_entry **aadsp_usent,
                                 struct dsd_user_group **aadsp_usgro,
                                 void * vpp_conn,
                                 struct dsd_unicode_string *adsp_us_userid,
                                 struct dsd_unicode_string *adsp_us_password,
                                 BOOL bop_check_pw, BOOL bop_first_auth ) {
   BOOL       bol1;                         /* working-variable        */
   int        inl1;                         /* working-variable        */
   int        iml_result;                   /* for compare             */
   struct dsd_user_group *adsl_usgro_1;
   struct dsd_user_entry *adsl_usent_1;
   struct dsd_auxf_1 *adsl_auxf_1_cur;      /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_prev;     /* auxiliary extension fi  */
   struct dsd_auxf_ident_1 dsl_auxf_ident_1;  /* definition ident      */

#ifdef HELP_DEBUG
   DSD_CONN_G *ADSL_CONN1_G = (DSD_CONN_G *) vpp_conn;
#else
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_conn)
#endif
#ifdef TRACEHL_USER_080202
   m_hlnew_printf( HLOG_XYZ1, "m_auth_user() l%05d aadsp_usent=%p.",
                   __LINE__, aadsp_usent );
#endif

#ifdef TRACEHL_061220                       /* problems target-filter person */
   m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX1-%05d-T-1 m_auth_user() SNO=%08d adsc_user_group=%p adsc_user_entry=%p",
                   __LINE__,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->adsc_user_group,  /* structure user group  */
                   ADSL_CONN1_G->adsc_user_entry );  /* structure user entry  */
#endif /* TRACEHL_061220                    /* problems target-filter person */
   if (aadsp_usent) *aadsp_usent = NULL;    /* return no user          */
   if (aadsp_usgro) *aadsp_usgro = NULL;    /* return no group         */
   inl1 = 0;
   while (inl1 < ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {
#ifdef OLD_1112
     adsl_usgro_1 = (struct dsd_user_group *)
                      *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1)
                          + ((ADSL_CONN1_G->adsc_gate1->inc_len_name
                                + sizeof(void *) - 1) & (0 - sizeof(void *)))
                          + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + inl1) * sizeof(void *)));
#endif
#ifndef OLD_1112
     adsl_usgro_1 = ADSL_CONN1_G->adsc_gate1->adsrc_user_group[ inl1 ];  /* user group entries */
#endif
     adsl_usent_1 = adsl_usgro_1->adsc_usere;
     while (adsl_usent_1) {
#ifdef WORK051112
       if (!_wcsicmp( (WCHAR *) (adsl_usent_1 + 1), (WCHAR *) wcrluser )) {
         *aadsp_usent = adsl_usent_1;       /* return user found       */
         *aadsp_usgro = adsl_usgro_1;       /* return group found      */
         if (   (imp_len_password == adsl_usent_1->inc_len_password_bytes)
             && (adsl_usent_1->inc_len_password_bytes > 0)
             && !memcmp( achp_password,
                         (char *) (adsl_usent_1 + 1) + adsl_usent_1->inc_len_name_bytes,
                         imp_len_password )) {
           return ied_ad_ok;                /* user is authenticated   */
         }
         return ied_ad_inv_password;        /* password invalid        */
       }
#endif
       bol1 = m_cmpi_vx_vx( &iml_result,
                            (adsl_usent_1 + 1), -1, ied_chs_utf_16,
                            adsp_us_userid->ac_str, adsp_us_userid->imc_len_str, adsp_us_userid->iec_chs_str );
       if (bol1 && (iml_result == 0)) {     /* entry found             */
         if (bop_check_pw == FALSE) goto p_auth_ok_00;  /* authentication succeeded */
#ifdef B071219
         if (aadsp_usent) {                 /* user entry requested    */
           *aadsp_usent = adsl_usent_1;     /* return user found       */
         }
         if (aadsp_usgro) {                 /* user group requested    */
           *aadsp_usgro = adsl_usgro_1;     /* return group found      */
         }
#endif
#ifdef TRACEHL_061220                       /* problems target-filter person */
         m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX1-%05d-T-2 m_auth_user() SNO=%08d adsc_user_group=%p adsc_user_entry=%p",
                         __LINE__,
                         ADSL_CONN1_G->dsc_co_sort.imc_sno,
                         ADSL_CONN1_G->adsc_user_group,  /* structure user group  */
                         ADSL_CONN1_G->adsc_user_entry );  /* structure user entry  */
#endif /* TRACEHL_061220                    /* problems target-filter person */
#ifdef B071119
         if (imp_len_password == 0) return ied_chid_inv_password;  /* password invalid */
#else
#ifdef TRACEHL_USER_080202
         m_hlnew_printf( HLOG_XYZ1, "m_auth_user() l%05d len-password=%d.",
                           __LINE__, adsp_us_password->imc_len_str );
#endif
         if (adsp_us_password->imc_len_str == 0) {  /* no password passed */
           if (adsl_usent_1->inc_len_password_bytes == 0) {
#ifdef B100514
#ifndef B071219
             if (aadsp_usent) {             /* user entry requested    */
               *aadsp_usent = adsl_usent_1;  /* return user found      */
             }
             if (aadsp_usgro) {             /* user group requested    */
               *aadsp_usgro = adsl_usgro_1;  /* return group found     */
             }
#endif
#endif
             goto p_auth_ok_00;             /* authentication succeeded */
           }
           return ied_chid_inv_password;    /* password invalid        */
         }
#endif
         bol1 = m_cmp_vx_vx( &iml_result,
                             (char *) (adsl_usent_1 + 1) + adsl_usent_1->inc_len_name_bytes,
                             adsl_usent_1->inc_len_password_bytes, ied_chs_utf_8,
                             adsp_us_password->ac_str, adsp_us_password->imc_len_str, adsp_us_password->iec_chs_str );
         if (bol1 && (iml_result == 0)) {   /* entry found             */
#ifdef B100514
           if (aadsp_usent) {               /* user entry requested    */
             *aadsp_usent = adsl_usent_1;   /* return user found       */
           }
#endif
#ifdef TRACEHL_USER_080202
           {
             struct dsd_user_entry *adsh_usent = NULL;
             if (aadsp_usent) adsh_usent = *aadsp_usent;
             m_hlnew_printf( HLOG_XYZ1, "m_auth_user() l%05d password o.k. aadsp_usent=%p *aadsp_usent=%p.",
                             __LINE__, aadsp_usent, adsh_usent );
           }
#endif
#ifdef B100514
           if (aadsp_usgro) {               /* user group requested    */
             *aadsp_usgro = adsl_usgro_1;   /* return group found      */
           }
#endif
           goto p_auth_ok_00;               /* authentication succeeded */
         }
         return ied_chid_inv_password;      /* password invalid        */
       }
       adsl_usent_1 = adsl_usent_1->adsc_next;  /* next user in group  */
     }
     inl1++;                                /* next user-group         */
   }
   return ied_chid_inv_userid;              /* userid invalid - not found */

   p_auth_ok_00:                            /* authentication succeeded */
#ifndef B100514
   if (aadsp_usent) {                       /* user entry requested    */
     *aadsp_usent = adsl_usent_1;           /* return user found       */
   }
   if (aadsp_usgro) {                       /* user group requested    */
     *aadsp_usgro = adsl_usgro_1;           /* return group found      */
   }
#endif
   dsl_auxf_ident_1.imc_len_userid
     = m_len_vx_vx( ied_chs_utf_8, adsl_usent_1 + 1, -1, ied_chs_utf_16 );
   dsl_auxf_ident_1.imc_len_user_group
     = m_len_vx_vx( ied_chs_utf_8, adsl_usgro_1 + 1, -1, ied_chs_utf_16 );
   /* search if element already exists                                 */
   adsl_auxf_1_prev = NULL;                 /* clear previous element  */
   adsl_auxf_1_cur = ADSL_CONN1_G->adsc_auxf_1;  /* get first element  */
   while (adsl_auxf_1_cur) {                /* loop over chain         */
     if (adsl_auxf_1_cur->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
#ifdef TRACEHL_081125
       m_hlnew_printf( HLOG_XYZ1, "TRACEHL_081125 m_auth_user() l%05d adsl_auxf_1_cur=%p free",
                       __LINE__, adsl_auxf_1_cur );
#endif
       if (bop_first_auth == FALSE) return ied_chid_ok;  /* user is authenticated */
       if (adsl_auxf_1_prev == NULL) {      /* no previous element     */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_cur->adsc_next;  /* remove from chain */
       } else {                             /* middle in chain         */
         adsl_auxf_1_prev->adsc_next = adsl_auxf_1_cur->adsc_next;  /* remove from chain */
       }
       free( adsl_auxf_1_cur );             /* free memory             */
       break;                               /* all done                */
     }
     adsl_auxf_1_prev = adsl_auxf_1_cur;    /* set previous element    */
     adsl_auxf_1_cur = adsl_auxf_1_cur->adsc_next;  /* get next in chain */
   }
   /* get storage for new entry                                        */
   adsl_auxf_1_cur
     = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                       + sizeof(struct dsd_auxf_ident_1)
                                       + dsl_auxf_ident_1.imc_len_userid  /* length userid UTF-8 */
                                       + dsl_auxf_ident_1.imc_len_user_group );  /* length name user group UTF-8 */
#ifdef TRACEHL_081125
   m_hlnew_printf( HLOG_XYZ1, "TRACEHL_081125 m_auth_user() l%05d adsl_auxf_1_cur=%p new",
                   __LINE__, adsl_auxf_1_cur );
#endif
   memcpy( adsl_auxf_1_cur + 1, &dsl_auxf_ident_1, sizeof(struct dsd_auxf_ident_1) );
   if (dsl_auxf_ident_1.imc_len_userid) {   /* check length userid UTF-8     */
     m_cpy_vx_vx( (char *) (adsl_auxf_1_cur + 1) + sizeof(struct dsd_auxf_ident_1),
                  dsl_auxf_ident_1.imc_len_userid,
                  ied_chs_utf_8,
                  adsl_usent_1 + 1, -1, ied_chs_utf_16 );
   }
   if (dsl_auxf_ident_1.imc_len_user_group) {  /* check length name user group UTF-8 */
     m_cpy_vx_vx( (char *) (adsl_auxf_1_cur + 1) + sizeof(struct dsd_auxf_ident_1) + dsl_auxf_ident_1.imc_len_userid,
                  dsl_auxf_ident_1.imc_len_user_group,
                  ied_chs_utf_8,
                  adsl_usgro_1 + 1, -1, ied_chs_utf_16 );
   }
   memset( adsl_auxf_1_cur, 0, sizeof(struct dsd_auxf_1) );
   adsl_auxf_1_cur->iec_auxf_def = ied_auxf_ident;  /* ident - userid and user-group */
   adsl_auxf_1_cur->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_cur;  /* set new chain      */
#ifdef B100702
   ADSL_CONN1_G->umc_ineta_ppp_ipv4 = 0;    /* clear INETA PPP IPV4    */
   ADSL_CONN1_G->umc_ineta_appl_ipv4 = 0;   /* clear INETA appl IPV4   */
#endif
#ifdef B100403
   if (adsl_usent_1->imc_len_ineta_ppp) {   /* length INETA PPP        */
     memcpy( &ADSL_CONN1_G->umc_ineta_ppp_ipv4,
             (char *) (adsl_usent_1 + 1)
               + adsl_usent_1->inc_len_name_bytes
               + adsl_usent_1->inc_len_password_bytes
               + adsl_usent_1->inc_len_target_bytes,
             sizeof(UNSIG_MED) );
   }
   if (adsl_usent_1->imc_len_ineta_appl) {  /* length INETA HTCP       */
     memcpy( &ADSL_CONN1_G->umc_ineta_appl_ipv4,
             (char *) (adsl_usent_1 + 1)
               + adsl_usent_1->inc_len_name_bytes
               + adsl_usent_1->inc_len_password_bytes
               + adsl_usent_1->inc_len_target_bytes
               + adsl_usent_1->imc_len_ineta_ppp,
             sizeof(UNSIG_MED) );
   }
#endif
#ifdef B120915
#ifdef D_INCL_HOB_TUN
   m_session_new_params( ADSL_CONN1_G );    /* notify HOB-TUN and main of new INETA */
#endif
#endif
   return ied_chid_ok;                      /* user is authenticated   */
#ifndef HELP_DEBUG
#undef ADSL_CONN1_G
#endif
} /* end m_auth_user()                                                 */

/** retrieve certificate of SSL session with client                    */
static void * m_get_certificate( void * adsp_conn1 ) {
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */

   adsl_auxf_1_w1 = ((DSD_CONN_G *) adsp_conn1)->adsc_auxf_1;
   while (adsl_auxf_1_w1) {                 /* loop over all aux fields */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certificate) {
       return (void *) (adsl_auxf_1_w1 + 1);
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
   return NULL;                             /* not found               */
} /* end m_get_certificate()                                           */

/** get user settings                                                  */
extern "C" BOOL m_aux_get_ident_set_1( void *vpp_userfld, struct dsd_sdh_ident_set_1 *adsp_g_idset1 ) {
   int        iml1;                         /* working variable        */
   int        iml_result;                   /* for compare             */
   BOOL       bol1;                         /* working variable        */
   struct dsd_user_group *adsl_usgro_1;
   struct dsd_user_entry *adsl_usent_1;

#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) vpp_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   memset( adsp_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );
   bol1 = m_aux_get_ident_1( ADSL_CONN1_G, adsp_g_idset1 );
   if (bol1 == FALSE) goto p_get_20;        /* not found, search in internal database */
   if (adsp_g_idset1->dsc_user_group.imc_len_str == 0) goto p_get_80;  /* return success */
   iml1 = 0;
   while (iml1 < ADSL_CONN1_G->adsc_gate1->inc_no_usgro) {
#ifdef OLD_1112
     adsl_usgro_1 = (struct dsd_user_group *)
                      *((void **) ((char *) (ADSL_CONN1_G->adsc_gate1 + 1)
                          + ((ADSL_CONN1_G->adsc_gate1->inc_len_name
                                + sizeof(void *) - 1) & (0 - sizeof(void *)))
                          + (ADSL_CONN1_G->adsc_gate1->inc_no_radius + iml1) * sizeof(void *)));
#endif
#ifndef OLD_1112
     adsl_usgro_1 = ADSL_CONN1_G->adsc_gate1->adsrc_user_group[ iml1 ];  /* user group entries */
#endif
     bol1 = m_cmpi_vx_vx( &iml_result,
                          adsl_usgro_1 + 1, -1, ied_chs_utf_16,
                          adsp_g_idset1->dsc_user_group.ac_str,
                          adsp_g_idset1->dsc_user_group.imc_len_str,
                          adsp_g_idset1->dsc_user_group.iec_chs_str );
     if (bol1 && (iml_result == 0)) {       /* entry found             */
       goto p_user_20;                      /* search user             */
     }
     iml1++;                                /* next user-group         */
   }
   /* user-group not found                                             */
   goto p_get_80;                           /* return success          */

   p_user_20:                               /* search user             */
   adsl_usent_1 = adsl_usgro_1->adsc_usere;
   while (adsl_usent_1) {
     bol1 = m_cmpi_vx_vx( &iml_result,
                          adsl_usent_1 + 1, -1, ied_chs_utf_16,
                          adsp_g_idset1->dsc_userid.ac_str,
                          adsp_g_idset1->dsc_userid.imc_len_str,
                          adsp_g_idset1->dsc_userid.iec_chs_str );
     if (bol1 && (iml_result == 0)) {       /* entry found             */
       goto p_get_40;                       /* fill parameters from internal database */
     }
     adsl_usent_1 = adsl_usent_1->adsc_next;  /* next user in group    */
   }
   /* user not found                                                   */
   goto p_get_80;                           /* return success          */

   p_get_20:                                /* not found, search in internal database */
   if (ADSL_CONN1_G->adsc_user_entry == NULL) {  /* structure user entry */
     adsp_g_idset1->iec_ret_g_idset1 = ied_ret_g_idset1_not_found;  /* ident not found */
     return TRUE;
   }
   adsl_usent_1 = ADSL_CONN1_G->adsc_user_entry;  /* structure user entry */
#ifdef B090802
   adsp_g_idset1->ac_userid = ADSL_USENT_G + 1;  /* userid             */
   adsp_g_idset1->imc_len_userid = ADSL_USENT_G->inc_len_name_bytes / sizeof(HL_WCHAR) - 1;  /* length userid in elements */
   adsp_g_idset1->iec_chs_userid = ied_chs_utf_16;  /* character set userid */
#endif
   adsp_g_idset1->dsc_userid.ac_str = adsl_usent_1 + 1;  /* userid     */
   adsp_g_idset1->dsc_userid.imc_len_str = adsl_usent_1->inc_len_name_bytes / sizeof(HL_WCHAR) - 1;  /* length userid in elements */
   adsp_g_idset1->dsc_userid.iec_chs_str = ied_chs_utf_16;  /* character set userid */
   if (ADSL_CONN1_G->adsc_user_group) {     /* structure user group    */
     adsp_g_idset1->dsc_user_group.ac_str = ADSL_CONN1_G->adsc_user_group + 1;  /* user-group */
     adsp_g_idset1->dsc_user_group.imc_len_str = ADSL_CONN1_G->adsc_user_group->inc_len_name / sizeof(HL_WCHAR) - 1;  /* length user-group in elements */
     adsp_g_idset1->dsc_user_group.iec_chs_str = ied_chs_utf_16;  /* character set user-group */
   }

   p_get_40:                                /* fill parameters from internal database */
#define ADSL_USENT_G adsl_usent_1
#ifdef B100403
   if (ADSL_USENT_G->imc_len_ineta_ppp) {
     adsp_g_idset1->achc_ineta_ppp          /* INETA PPP Tunnel        */
       = (char *) (ADSL_USENT_G + 1)
           + ADSL_USENT_G->inc_len_name_bytes
           + ADSL_USENT_G->inc_len_password_bytes
           + ADSL_USENT_G->inc_len_target_bytes;
     adsp_g_idset1->imc_len_ineta_ppp = ADSL_USENT_G->imc_len_ineta_ppp;  /* length INETA PPP Tunnel */
   }
   if (ADSL_USENT_G->imc_len_ineta_appl) {
     adsp_g_idset1->achc_ineta_appl         /* INETA HTCP personal     */
       = (char *) (ADSL_USENT_G + 1)
           + ADSL_USENT_G->inc_len_name_bytes
           + ADSL_USENT_G->inc_len_password_bytes
           + ADSL_USENT_G->inc_len_target_bytes
           + ADSL_USENT_G->imc_len_ineta_ppp;
     adsp_g_idset1->imc_len_ineta_appl = ADSL_USENT_G->imc_len_ineta_appl;  /* length INETA HTCP */
   }
   if (ADSL_USENT_G->imc_len_sip_ident) {
     adsp_g_idset1->ac_sip_ident            /* SIP ident               */
       = (char *) (ADSL_USENT_G + 1)
           + ADSL_USENT_G->inc_len_name_bytes
           + ADSL_USENT_G->inc_len_password_bytes
           + ADSL_USENT_G->inc_len_target_bytes
           + ADSL_USENT_G->imc_len_ineta_ppp
           + ADSL_USENT_G->imc_len_ineta_appl
           + ADSL_USENT_G->imc_len_ineta_sip_gw;
     adsp_g_idset1->imc_len_sip_ident = ADSL_USENT_G->imc_len_sip_ident;  /* length SIP ident in elements */
     adsp_g_idset1->iec_chs_sip_ident = ied_chs_utf_8;  /* character set SIP ident */
   }
   if (ADSL_USENT_G->imc_len_sip_shase) {   /* length SIP shared secret */
     adsp_g_idset1->ac_sip_shase            /* SIP shared secret       */
       = (char *) (ADSL_USENT_G + 1)
           + ADSL_USENT_G->inc_len_name_bytes
           + ADSL_USENT_G->inc_len_password_bytes
           + ADSL_USENT_G->inc_len_target_bytes
           + ADSL_USENT_G->imc_len_ineta_ppp
           + ADSL_USENT_G->imc_len_ineta_appl
           + ADSL_USENT_G->imc_len_ineta_sip_gw
           + ADSL_USENT_G->imc_len_sip_ident;
     adsp_g_idset1->imc_len_sip_shase = ADSL_USENT_G->imc_len_sip_shase;  /* length SIP shared secret in elements */
     adsp_g_idset1->iec_chs_sip_shase = ied_chs_utf_8;  /* character set SIP shared secret */
   }
   if (ADSL_USENT_G->imc_len_ineta_sip_gw) {
     adsp_g_idset1->achc_ineta_sip_gw       /* INETA SIP gateway       */
       = (char *) (ADSL_USENT_G + 1)
           + ADSL_USENT_G->inc_len_name_bytes
           + ADSL_USENT_G->inc_len_password_bytes
           + ADSL_USENT_G->inc_len_target_bytes
           + ADSL_USENT_G->imc_len_ineta_ppp
           + ADSL_USENT_G->imc_len_ineta_appl;
     adsp_g_idset1->imc_len_ineta_sip_gw = ADSL_USENT_G->imc_len_ineta_sip_gw;  /* length INETA SIP gateway */
   }
#endif
   if (ADSL_USENT_G->imc_len_sip_fullname) {  /* length SIP fullname   */
     adsp_g_idset1->dsc_sip_fullname.ac_str = ADSL_USENT_G->achc_sip_fullname;  /* address of SIP fullname */
     adsp_g_idset1->dsc_sip_fullname.imc_len_str = ADSL_USENT_G->imc_len_sip_fullname;  /* length SIP fullname */
     adsp_g_idset1->dsc_sip_fullname.iec_chs_str = ied_chs_utf_8;  /* character set SIP fullname */
   }
   if (ADSL_USENT_G->imc_len_sip_ident) {   /* length SIP ident        */
     adsp_g_idset1->dsc_sip_ident.ac_str = ADSL_USENT_G->achc_sip_ident;  /* address of SIP ident */
     adsp_g_idset1->dsc_sip_ident.imc_len_str = ADSL_USENT_G->imc_len_sip_ident;  /* length SIP ident */
     adsp_g_idset1->dsc_sip_ident.iec_chs_str = ied_chs_utf_8;  /* character set SIP ident */
   }
   if (ADSL_USENT_G->imc_len_sip_display_number) {  /* length SIP display-number */
     adsp_g_idset1->dsc_sip_display_number.ac_str = ADSL_USENT_G->achc_sip_display_number;  /* address of SIP display-number */
     adsp_g_idset1->dsc_sip_display_number.imc_len_str = ADSL_USENT_G->imc_len_sip_display_number;  /* length SIP display-number */
     adsp_g_idset1->dsc_sip_display_number.iec_chs_str = ied_chs_utf_8;  /* character set SIP display-number */
   }
   if (ADSL_USENT_G->imc_len_sip_shase) {   /* length SIP shared secret */
     adsp_g_idset1->dsc_sip_shase.ac_str = ADSL_USENT_G->achc_sip_shase;  /* address of SIP shared secret */
     adsp_g_idset1->dsc_sip_shase.imc_len_str = ADSL_USENT_G->imc_len_sip_shase;  /* length SIP shared secret */
     adsp_g_idset1->dsc_sip_shase.iec_chs_str = ied_chs_utf_8;  /* character set SIP shared secret */
   }
   if (ADSL_USENT_G->imc_len_ineta_sip_gw) {
     adsp_g_idset1->achc_ineta_sip_gw       /* INETA SIP gateway       */
       = ADSL_USENT_G->achc_ineta_sip_gw;   /* address of INETA SIP Gateway */
     adsp_g_idset1->imc_len_ineta_sip_gw = ADSL_USENT_G->imc_len_ineta_sip_gw;  /* length INETA SIP gateway */
   }

   p_get_80:                                /* return success          */
   adsp_g_idset1->iec_ret_g_idset1 = ied_ret_g_idset1_ok;  /* ident known, parameters returned, o.k. */
   return TRUE;
#undef ADSL_USENT_G
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_aux_get_ident_set_1()                                       */

/** decode the Protocol specified                                      */
extern "C" enum ied_scp_def m_decode_prot( ied_charset iep_charset, void *ap_prot, int imp_len_prot ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   int        iml_i;                        /* working variable        */

   iml_i = sizeof(dsrs_protdef_e) / sizeof(dsrs_protdef_e[0]);
   do {
     iml_i--;
     bol1 = m_cmp_vx_vx( &iml1,
                         ap_prot, imp_len_prot, iep_charset,
                         dsrs_protdef_e[iml_i].achc_keyword, -1, ied_chs_utf_8 );
     if (bol1 && (iml1 == 0)) {             /* protocol found          */
       return dsrs_protdef_e[iml_i].iec_scp_def;
     }
   } while (iml_i > 0);
   return ied_scp_spec;                     /* special protocol        */
} /* end m_decode_prot()                                               */

/** subroutine to retrieve the server-entries with the given protocol  */
static void m_get_servent_1( int inp_param, DSD_CONN_G *adsp_conn,
                             struct dsd_get_servent_1 *adsp_gse1 ) {
   int        inl1, inl2;                   /* working variables       */
   BOOL       bol_found_last;               /* last entry already found */
   void **    aal_handle;                   /* address of handle       */
   struct dsd_auxf_1 *adsl_auxf_1_sessco1;  /* auxiliary session configuration */

   if (inp_param == DEF_AUX_COUNT_SERVENT) {
     *adsp_gse1->ainc_no_servent = 0;       /* only for DEF_AUX_COUNT_SERVENT */
     aal_handle = NULL;                     /* address of handle       */
   } else {                                 /* is DEF_AUX_GET_SERVENT  */
     bol_found_last = FALSE;                /* last entry not yet found */
     aal_handle = &adsp_gse1->vpc_handle;   /* address of handle       */
     if (*aal_handle == NULL) {             /* get first entry         */
       bol_found_last = TRUE;               /* last entry already found */
     }
   }
   /* check if session configuration set                               */
   adsl_auxf_1_sessco1 = adsp_conn->adsc_auxf_1;  /* get first element */
   while (adsl_auxf_1_sessco1) {            /* loop over chain         */
     if (adsl_auxf_1_sessco1->iec_auxf_def == ied_auxf_sessco1) break;  /* session configuration */
     adsl_auxf_1_sessco1 = adsl_auxf_1_sessco1->adsc_next;  /* get next in chain */
   }
   while (   (adsp_gse1->vpc_usgro)         /* user group valid        */
          && (adsl_auxf_1_sessco1 == NULL)) {  /* no session configuration */
#define ADSL_USGRO_G ((struct dsd_user_group *) adsp_gse1->vpc_usgro)
     if (ADSL_USGRO_G->inc_no_seli == 0) break;
     inl1 = ADSL_USGRO_G->inc_no_seli;
#ifdef OLD_1112
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_USGRO_G + 1) \
                         + ((ADSL_USGRO_G->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + inl1 * sizeof(void *))))
#endif
#ifndef OLD_1112
#ifdef XYZ1
#define ADSL_SELSERV_2 (ADSL_USGRO_G->adsrc_server_list_1[ inl1 ])
#endif
#endif
     inl1 = ADSL_USGRO_G->inc_no_seli;      /* start in reverse order  */
     while (TRUE) {
       if (inl1 == 0) break;                /* was last entry          */
       inl1--;                              /* check next entry        */
#ifdef OLD_1112
       inl2 = m_check_servent( aal_handle, &bol_found_last, ADSL_SELSERV_2, adsp_gse1 );
#endif
#ifndef OLD_1112
       inl2 = m_check_servent( aal_handle, &bol_found_last, ADSL_USGRO_G->adsrc_server_list_1[ inl1 ], adsp_gse1 );
#endif
       if (inl2) {
         if (inp_param != DEF_AUX_COUNT_SERVENT) return;
         *adsp_gse1->ainc_no_servent += inl2;  /* count server entries */
       }
     }
     break;
   }
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_sessco1 + 1))
   if (   (adsl_auxf_1_sessco1 == NULL)     /* no session configuration */
       || (ADSL_AUXF_SESSCO1_W1->imc_no_seli == 0)) {  /* number of server lists zero */
     goto p_default;                        /* check default entry     */
   }
#ifdef OLD_1112
#define ADSL_SELSERV_3 ((struct dsd_server_list_1 *) *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + inl1))
#endif
#ifndef OLD_1112
#define ADSL_SELSERV_3 ((struct dsd_server_list_1 *) *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + inl1))
#endif
   inl1 = 0;                                /* clear index of server lists */
   do {                                     /* loop over all server lists */
     inl2 = m_check_servent( aal_handle, &bol_found_last, ADSL_SELSERV_3, adsp_gse1 );
     if (inl2) {
       if (inp_param != DEF_AUX_COUNT_SERVENT) return;
       *adsp_gse1->ainc_no_servent += inl2;  /* count server entries   */
     }
     inl1++;                                /* increment index of server lists */
   } while (inl1 < ADSL_AUXF_SESSCO1_W1->imc_no_seli);  /* check number of server lists */

   p_default:                               /* check default entry     */
   if (   (adsl_auxf_1_sessco1)             /* with session configuration */
       && (ADSL_AUXF_SESSCO1_W1->boc_use_default_servli == FALSE)) {  /* do not use default server list */
     goto p_end;                            /* end of subroutine       */
   }
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_conn->adsc_gate1 + 1) \
                         + ((adsp_conn->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (adsp_conn->adsc_gate1->inc_no_radius + adsp_conn->adsc_gate1->inc_no_usgro + inl2) * sizeof(void *))))
#endif
   inl2 = adsp_conn->adsc_gate1->inc_no_seli;  /* start in reverse order */
   do {
     inl2--;                                /* check next entry        */
     /* check if not already processed in user-group                   */
     inl1 = -1;                             /* pseudo-value            */
     if (   (adsp_gse1->vpc_usgro)          /* user group valid        */
         && (adsl_auxf_1_sessco1 == NULL)) {  /* no session configuration */
       inl1 = ADSL_USGRO_G->inc_no_seli;    /* start in reverse order  */
       while (TRUE) {
         inl1--;                            /* check next entry        */
         if (inl1 < 0) break;               /* was last entry          */
#ifdef OLD_1112
         if (ADSL_SELSERV_2 == ADSL_SELSERV_1) break;  /* same entry   */
#endif
#ifndef OLD_1112
       if (ADSL_USGRO_G->adsrc_server_list_1[ inl1 ] == adsp_conn->adsc_gate1->adsrc_server_list_1[ inl2 ]) break;
#endif
       }
     }
     if (inl1 < 0) {                        /* entry not found         */
#ifdef OLD_1112
       inl1 = m_check_servent( aal_handle, &bol_found_last, ADSL_SELSERV_1, adsp_gse1 );
#endif
#ifndef OLD_1112
       inl1 = m_check_servent( aal_handle, &bol_found_last, adsp_conn->adsc_gate1->adsrc_server_list_1[ inl2 ], adsp_gse1 );
#endif
       if (inl1) {
         if (inp_param != DEF_AUX_COUNT_SERVENT) return;
         *adsp_gse1->ainc_no_servent += inl1;  /* count server entries */
       }
     }
   } while (inl2 > 0);                      /* for all server lists    */
#undef ADSL_USGRO_G
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#undef ADSL_SELSERV_2
#endif
#undef ADSL_SELSERV_3
#undef ADSL_AUXF_SESSCO1_W1

   p_end:                                   /* end of subroutine       */
   if (inp_param != DEF_AUX_COUNT_SERVENT) {
     *aal_handle = NULL;                    /* was last entry          */
   }
   return;
} /* end m_get_servent_1()                                             */

/** return server-entry in server-list                                 */
static int m_check_servent( void **aap_handle, BOOL *abop_found_last,
                            struct dsd_server_list_1 *adsp_selserv,
                            struct dsd_get_servent_1 *adsp_gse1 ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */

#ifdef OLD_1112
#define ACHL_SERVER_NAME_UTF16 ((HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)\
                                  + adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1)))
#endif
#ifndef OLD_1112
#define ACHL_SERVER_NAME_UTF16 (adsl_server_conf_1_w1->awcc_name)
#endif
#define ACHL_SERVER_PROT_UTF8 ((char *) (adsl_server_conf_1_w1 + 1) \
                                + adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1) \
                                + adsl_server_conf_1_w1->inc_len_name)
   iml1 = 0;                                /* no server found yet     */
   /* get anchor of chain server conf                                  */
   adsl_server_conf_1_w1 = adsp_selserv->adsc_server_conf_1;
   while (adsl_server_conf_1_w1) {          /* loop over chain server entry */
     /* check protocol                                                 */
     do {
       if (adsl_server_conf_1_w1->iec_scp_def != adsp_gse1->iec_scp_def) break;
       if (adsp_gse1->iec_scp_def == ied_scp_spec) {
#ifdef OLD_1112
         bol1 = m_cmp_vx_vx( &iml2,
                             ACHL_SERVER_PROT_UTF8, adsl_server_conf_1_w1->inc_len_protocol, ied_chs_utf_8,
                             adsp_gse1->ac_scp, adsp_gse1->inc_len_scp, adsp_gse1->iec_chs_scp );
#endif
#ifndef OLD_1112
         bol1 = m_cmp_vx_vx( &iml2,
                             ACHL_SERVER_PROT_UTF8,
                             adsl_server_conf_1_w1->inc_len_protocol,
                             ied_chs_utf_8,
                             adsp_gse1->dsc_ucs_protocol.ac_str,  /* address of string */
                             adsp_gse1->dsc_ucs_protocol.imc_len_str,  /* length string in elements */
                             adsp_gse1->dsc_ucs_protocol.iec_chs_str );  /* character set string */
#endif
         if (bol1 == FALSE) break;          /* not this protocol       */
         if (iml2) break;                   /* not this protocol       */
       }
       if (aap_handle) {                    /* search specific server  */
         if (*abop_found_last) {            /* return this server      */
           *aap_handle = adsl_server_conf_1_w1;  /* this is current server */
           iml1 = *adsp_gse1->ainc_len_target_bytes;  /* length of target area in bytes */
           iml2 = m_len_vx_vx( adsp_gse1->iec_chs_target,
                               ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16 );
           *adsp_gse1->ainc_len_target_bytes = iml2;
           m_cpy_vx_vx( adsp_gse1->ac_servent_target, iml1, adsp_gse1->iec_chs_target,
                        ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16 );
           if (adsp_gse1->aimc_function) {  /* store function of this server entry */
             *adsp_gse1->aimc_function = adsl_server_conf_1_w1->inc_function;  /* function to process */
           }
           return 1;                        /* server found            */
         }
         if (*aap_handle == (void *) adsl_server_conf_1_w1) {  /* is this the current server */
           *abop_found_last = TRUE;         /* set flag last server found */
         }
       } else {                             /* only count the servers  */
         iml1++;                            /* count the server        */
       }
     } while (FALSE);
     adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
   }
   return iml1;                             /* entries found           */
#undef ACHL_SERVER_NAME_UTF16
#undef ACHL_SERVER_PROT_UTF8
} /* end m_check_servent()                                             */

/** a packet has been received from the server                         */
extern "C" void m_count_recv_server( DSD_CONN_G *adsp_conn, int imp_length ) {
   adsp_conn->inc_c_ns_rece_s++;            /* count receive server    */
   adsp_conn->ilc_d_ns_rece_s += imp_length;  /* data receive server   */
} /* end m_count_recv_server()                                         */

/** a packet has been sent to the server                               */
extern "C" void m_count_sent_server( DSD_CONN_G *adsp_conn, int imp_length ) {
   adsp_conn->inc_c_ns_send_s++;            /* count send server       */
   adsp_conn->ilc_d_ns_send_s += imp_length;  /* data send server      */
} /* end m_count_sent_server()                                         */

#ifndef NOT_YET_UNIX_110808
#ifdef OLD_1112
/* prepare for connect with area from HLWSPAT2                         */
static void m_prep_conn_1( DSD_CONN_G *adsp_conn, struct dsd_hlwspat2_conn *adsp_param_conn ) {
   int        inl1;                         /* working-variable        */
   BOOL       bol1;                         /* working-variable        */
   int        iml_result;                   /* for compare             */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */
   struct dsd_auxf_1 *adsl_auxf_1_sessco1;  /* auxiliary session configuration */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_prep_conn_1() l%05d adsp_param_conn=%p iec_hconn=%d",
                   __LINE__, adsp_param_conn, adsp_param_conn->iec_hconn );
#endif
   adsp_param_conn->vpc_servent = NULL;     /* handle to server entry  */
   switch (adsp_param_conn->iec_hconn) {
     case ied_hconn_def_servent:
       break;
     case ied_hconn_sel_servent:            /* select server entry by name */
       /* check if session configuration set                           */
       adsl_auxf_1_sessco1 = adsp_conn->adsc_auxf_1;  /* get first element */
       while (adsl_auxf_1_sessco1) {        /* loop over chain         */
         if (adsl_auxf_1_sessco1->iec_auxf_def == ied_auxf_sessco1) break;  /* session configuration */
         adsl_auxf_1_sessco1 = adsl_auxf_1_sessco1->adsc_next;  /* get next in chain */
       }
#define ACHL_SERVER_NAME_UTF16 ((HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)\
                                  + adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1)))
       while (   (adsp_param_conn->vpc_usgro)  /* user group valid     */
              && (adsl_auxf_1_sessco1 == NULL)) {  /* no session configuration */
#define ADSL_USGRO_G ((struct dsd_user_group *) adsp_param_conn->vpc_usgro)
         if (ADSL_USGRO_G->inc_no_seli == 0) break;
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_USGRO_G + 1) \
                         + ((ADSL_USGRO_G->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + inl1 * sizeof(void *))))
         inl1 = ADSL_USGRO_G->inc_no_seli;  /* start in reverse order  */
         while (TRUE) {
           if (inl1 == 0) break;            /* was last entry          */
           inl1--;                          /* check next entry        */
           adsl_server_conf_1_w1 = ADSL_SELSERV_2->adsc_server_conf_1;
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
             /* compare the name of the entry                          */
             bol1 = m_cmpi_vx_vx( &iml_result,
                                  ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                  adsp_param_conn->ac_servent_target,
                                  adsp_param_conn->inc_len_target,
                                  adsp_param_conn->iec_chs_servent_t );
             if ((bol1) && (iml_result == 0)) {  /* entry found        */
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
#ifdef OLD_1112
               adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
#endif
#ifndef OLD_1112
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
#endif
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#ifdef OLD_1112
               } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
                 adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
#endif
               }
               return;                  /* all done                */
             }
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
         }
         break;
       }
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_sessco1 + 1))
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->imc_no_seli)) {  /* number of server lists not zero */
#define ADSL_SELSERV_3 ((struct dsd_server_list_1 *) *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + inl1))
         inl1 = 0;                          /* clear index of server lists */
         do {                                     /* loop over all server lists */
           adsl_server_conf_1_w1 = ADSL_SELSERV_3->adsc_server_conf_1;
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
             /* compare the name of the entry                          */
             bol1 = m_cmpi_vx_vx( &iml_result,
                                  ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                  adsp_param_conn->ac_servent_target,
                                  adsp_param_conn->inc_len_target,
                                  adsp_param_conn->iec_chs_servent_t );
             if ((bol1) && (iml_result == 0)) {  /* entry found        */
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
#ifdef OLD_1112
               adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
#endif
#ifndef OLD_1112
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
#endif
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#ifdef OLD_1112
               } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
                 adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
#endif
               }
               return;                  /* all done                */
             }
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
           inl1++;                                /* increment index of server lists */
         } while (inl1 < ADSL_AUXF_SESSCO1_W1->imc_no_seli);  /* check number of server lists */
       }
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->boc_use_default_servli == FALSE)) {  /* do not use default server list */
         break;
       }
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_conn->adsc_gate1 + 1) \
                         + ((adsp_conn->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (adsp_conn->adsc_gate1->inc_no_radius + adsp_conn->adsc_gate1->inc_no_usgro + inl1) * sizeof(void *))))
       inl1 = adsp_conn->adsc_gate1->inc_no_seli;  /* start in reverse order */
       do {
         inl1--;                            /* check next entry        */
#ifdef OLD_1112
         adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#endif
         while (adsl_server_conf_1_w1) {    /* loop over chain server entry */
           /* compare the name of the entry                            */
           bol1 = m_cmpi_vx_vx( &iml_result,
                                ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                adsp_param_conn->ac_servent_target,
                                adsp_param_conn->inc_len_target,
                                adsp_param_conn->iec_chs_servent_t );
           if ((bol1) && (iml_result == 0)) {  /* entry found          */
             adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
             adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
             adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
             if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
               m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
             } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
               adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
             }
             return;                        /* all done                */
           }
           adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
         }
       } while (inl1 > 0);                  /* for all server lists    */
#undef ACHL_SERVER_NAME_UTF16
#undef ADSL_USGRO_G
#undef ADSL_SELSERV_1
#undef ADSL_SELSERV_2
#undef ADSL_SELSERV_3
#undef ADSL_AUXF_SESSCO1_W1
       break;
     default:
       break;
   }
   adsp_param_conn->iec_conn_ret = ied_conn_se_not_found;  /* server entry not found */
   return;
} /* end m_prep_conn_1()                                               */
#endif
#ifndef OLD_1112
/** prepare for connect with area from HOB-WSP-AT3                     */
static void m_prep_conn_1( DSD_CONN_G *adsp_conn, struct dsd_wspat3_conn *adsp_param_conn ) {
   int        iml1;                         /* working-variable        */
   BOOL       bol1;                         /* working-variable        */
   int        iml_result;                   /* for compare             */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable server-entry */
   struct dsd_auxf_1 *adsl_auxf_1_sessco1;  /* auxiliary session configuration */
   struct dsd_unicode_string dsl_ucs_w1;    /* unicode string          */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_prep_conn_1() l%05d adsp_param_conn=%p iec_hconn=%d",
                   __LINE__, adsp_param_conn, adsp_param_conn->iec_hconn );
#endif
   adsp_param_conn->vpc_servent = NULL;     /* handle to server entry  */
   switch (adsp_param_conn->iec_hconn) {
     case ied_hconn_def_servent:
       /* check if session configuration set                           */
       adsl_auxf_1_sessco1 = adsp_conn->adsc_auxf_1;  /* get first element */
       while (adsl_auxf_1_sessco1) {        /* loop over chain         */
         if (adsl_auxf_1_sessco1->iec_auxf_def == ied_auxf_sessco1) break;  /* session configuration */
         adsl_auxf_1_sessco1 = adsl_auxf_1_sessco1->adsc_next;  /* get next in chain */
       }
       while (   (adsp_param_conn->vpc_usgro)  /* user group valid     */
              && (adsl_auxf_1_sessco1 == NULL)) {  /* no session configuration */
#define ADSL_USGRO_G ((struct dsd_user_group *) adsp_param_conn->vpc_usgro)
         if (ADSL_USGRO_G->inc_no_seli == 0) break;
         iml1 = ADSL_USGRO_G->inc_no_seli;  /* start in reverse order  */
         while (TRUE) {
           if (iml1 == 0) break;            /* was last entry          */
           iml1--;                          /* check next entry        */
           adsl_server_conf_1_w1 = ADSL_USGRO_G->adsrc_server_list_1[ iml1 ]->adsc_server_conf_1;
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
//-----
             /* check protocol                                         */
             while (adsl_server_conf_1_w1->iec_scp_def == adsp_param_conn->iec_scp_def) {
               if (adsp_param_conn->iec_scp_def == ied_scp_spec) {
                 bol1 = m_cmp_vx_vx( &iml_result,
                                     adsl_server_conf_1_w1->awcc_name,
                                     adsl_server_conf_1_w1->inc_len_protocol,
                                     ied_chs_utf_8,
                                     adsp_param_conn->dsc_ucs_protocol.ac_str,  /* address of string */
                                     adsp_param_conn->dsc_ucs_protocol.imc_len_str,  /* length string in elements */
                                     adsp_param_conn->dsc_ucs_protocol.iec_chs_str );  /* character set string */
                 if (bol1 == FALSE) break;  /* not this protocol       */
                 if (iml_result) break;     /* not this protocol       */
               }
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
#ifdef OLD_1112
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#else
// to-do 12.01.12 KB
#endif
               }
               return;                  /* all done                */
             }
//-----
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
         }
         break;
       }
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_sessco1 + 1))
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->imc_no_seli)) {  /* number of server lists not zero */
#define ADSL_SELSERV_3 ((struct dsd_server_list_1 *) *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + iml1))
         iml1 = 0;                          /* clear index of server lists */
         do {                               /* loop over all server lists */
           adsl_server_conf_1_w1 = ADSL_SELSERV_3->adsc_server_conf_1;
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
             /* check protocol                                         */
             while (adsl_server_conf_1_w1->iec_scp_def == adsp_param_conn->iec_scp_def) {
               if (adsp_param_conn->iec_scp_def == ied_scp_spec) {
                 bol1 = m_cmp_vx_vx( &iml_result,
                                     adsl_server_conf_1_w1->awcc_name,
                                     adsl_server_conf_1_w1->inc_len_protocol,
                                     ied_chs_utf_8,
                                     adsp_param_conn->dsc_ucs_protocol.ac_str,  /* address of string */
                                     adsp_param_conn->dsc_ucs_protocol.imc_len_str,  /* length string in elements */
                                     adsp_param_conn->dsc_ucs_protocol.iec_chs_str );  /* character set string */
                 if (bol1 == FALSE) break;  /* not this protocol       */
                 if (iml_result) break;     /* not this protocol       */
               }
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
               }
               return;                  /* all done                */
             }
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
           iml1++;                                /* increment index of server lists */
         } while (iml1 < ADSL_AUXF_SESSCO1_W1->imc_no_seli);  /* check number of server lists */
       }
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->boc_use_default_servli == FALSE)) {  /* do not use default server list */
         break;
       }
       iml1 = adsp_conn->adsc_gate1->inc_no_seli;  /* start in reverse order */
       do {
         iml1--;                            /* check next entry        */
         adsl_server_conf_1_w1 = adsp_conn->adsc_gate1->adsrc_server_list_1[ iml1 ]->adsc_server_conf_1;  /* list of servers */
         while (adsl_server_conf_1_w1) {    /* loop over chain server entry */
//-------------------
           /* check protocol                                         */
           while (adsl_server_conf_1_w1->iec_scp_def == adsp_param_conn->iec_scp_def) {
             if (adsp_param_conn->iec_scp_def == ied_scp_spec) {
               bol1 = m_cmp_vx_vx( &iml_result,
                                   adsl_server_conf_1_w1->awcc_name,
                                   adsl_server_conf_1_w1->inc_len_protocol,
                                   ied_chs_utf_8,
                                   adsp_param_conn->dsc_ucs_protocol.ac_str,  /* address of string */
                                   adsp_param_conn->dsc_ucs_protocol.imc_len_str,  /* length string in elements */
                                   adsp_param_conn->dsc_ucs_protocol.iec_chs_str );  /* character set string */
               if (bol1 == FALSE) break;    /* not this protocol       */
               if (iml_result) break;       /* not this protocol       */
             }
             adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
             adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
             adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
             if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
               m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
             }
             return;                  /* all done                */
           }
//-------------------
           adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
         }
       } while (iml1 > 0);                  /* for all server lists    */
#undef ADSL_USGRO_G
#undef ADSL_SELSERV_3
#undef ADSL_AUXF_SESSCO1_W1
       break;
     case ied_hconn_sel_servent:            /* select server entry by name */
#ifndef OLD_1112
       dsl_ucs_w1.imc_len_str = -1;         /* length string in elements */
       dsl_ucs_w1.iec_chs_str = ied_chs_utf_16;  /* character set string */
#endif
       /* check if session configuration set                           */
       adsl_auxf_1_sessco1 = adsp_conn->adsc_auxf_1;  /* get first element */
       while (adsl_auxf_1_sessco1) {        /* loop over chain         */
         if (adsl_auxf_1_sessco1->iec_auxf_def == ied_auxf_sessco1) break;  /* session configuration */
         adsl_auxf_1_sessco1 = adsl_auxf_1_sessco1->adsc_next;  /* get next in chain */
       }
#ifdef OLD_1112
#define ACHL_SERVER_NAME_UTF16 ((HL_WCHAR *) ((char *) (adsl_server_conf_1_w1 + 1)\
                                  + adsl_server_conf_1_w1->inc_no_sdh * sizeof(struct dsd_sdh_work_1)))
#endif
       while (   (adsp_param_conn->vpc_usgro)  /* user group valid     */
              && (adsl_auxf_1_sessco1 == NULL)) {  /* no session configuration */
#define ADSL_USGRO_G ((struct dsd_user_group *) adsp_param_conn->vpc_usgro)
         if (ADSL_USGRO_G->inc_no_seli == 0) break;
#ifdef OLD_1112
#define ADSL_SELSERV_2 ((struct dsd_server_list_1 *) *((void **) ((char *) (ADSL_USGRO_G + 1) \
                         + ((ADSL_USGRO_G->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + iml1 * sizeof(void *))))
#endif
         iml1 = ADSL_USGRO_G->inc_no_seli;  /* start in reverse order  */
         while (TRUE) {
           if (iml1 == 0) break;            /* was last entry          */
           iml1--;                          /* check next entry        */
#ifdef OLD_1112
           adsl_server_conf_1_w1 = ADSL_SELSERV_2->adsc_server_conf_1;
#else
           adsl_server_conf_1_w1 = ADSL_USGRO_G->adsrc_server_list_1[ iml1 ]->adsc_server_conf_1;
#endif
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
             /* compare the name of the entry                          */
#ifdef OLD_1112
             bol1 = m_cmpi_vx_vx( &iml_result,
                                  ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                  adsp_param_conn->ac_servent_target,
                                  adsp_param_conn->inc_len_target,
                                  adsp_param_conn->iec_chs_servent_t );
#else
             dsl_ucs_w1.ac_str = adsl_server_conf_1_w1->awcc_name;  /* address of name */
             bol1 = m_cmpi_ucs_ucs( &iml_result, &dsl_ucs_w1, &adsp_param_conn->dsc_ucs_server_entry );  /* compare Server Entry */
#endif
             if ((bol1) && (iml_result == 0)) {  /* entry found        */
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
#ifdef OLD_1112
               adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
#endif
#ifndef OLD_1112
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
#endif
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#ifdef OLD_1112
               } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
                 adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
#endif
               }
               return;                  /* all done                */
             }
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
         }
         break;
       }
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_sessco1 + 1))
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->imc_no_seli)) {  /* number of server lists not zero */
#define ADSL_SELSERV_3 ((struct dsd_server_list_1 *) *((void **) (ADSL_AUXF_SESSCO1_W1 + 1) + iml1))
         iml1 = 0;                          /* clear index of server lists */
         do {                               /* loop over all server lists */
           adsl_server_conf_1_w1 = ADSL_SELSERV_3->adsc_server_conf_1;
           while (adsl_server_conf_1_w1) {  /* loop over chain server entry */
             /* compare the name of the entry                          */
#ifdef OLD_1112
             bol1 = m_cmpi_vx_vx( &iml_result,
                                  ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                  adsp_param_conn->ac_servent_target,
                                  adsp_param_conn->inc_len_target,
                                  adsp_param_conn->iec_chs_servent_t );
#else
             dsl_ucs_w1.ac_str = adsl_server_conf_1_w1->awcc_name;  /* address of name */
             bol1 = m_cmpi_ucs_ucs( &iml_result, &dsl_ucs_w1, &adsp_param_conn->dsc_ucs_server_entry );  /* compare Server Entry */
#endif
             if ((bol1) && (iml_result == 0)) {  /* entry found        */
               adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
#ifdef OLD_1112
               adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
#endif
#ifndef OLD_1112
               adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
#endif
               adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
               if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
                 m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#ifdef OLD_1112
               } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
                 adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
#endif
               }
               return;                  /* all done                */
             }
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
           }
           iml1++;                                /* increment index of server lists */
         } while (iml1 < ADSL_AUXF_SESSCO1_W1->imc_no_seli);  /* check number of server lists */
       }
       if (   (adsl_auxf_1_sessco1)         /* with session configuration */
           && (ADSL_AUXF_SESSCO1_W1->boc_use_default_servli == FALSE)) {  /* do not use default server list */
         break;
       }
#ifdef OLD_1112
#define ADSL_SELSERV_1 ((struct dsd_server_list_1 *) *((void **) ((char *) (adsp_conn->adsc_gate1 + 1) \
                         + ((adsp_conn->adsc_gate1->inc_len_name + sizeof(void *) - 1) & (0 - sizeof(void *))) \
                         + (adsp_conn->adsc_gate1->inc_no_radius + adsp_conn->adsc_gate1->inc_no_usgro + iml1) * sizeof(void *))))
#endif
       iml1 = adsp_conn->adsc_gate1->inc_no_seli;  /* start in reverse order */
       do {
         iml1--;                            /* check next entry        */
#ifdef OLD_1112
         adsl_server_conf_1_w1 = ADSL_SELSERV_1->adsc_server_conf_1;
#else
         adsl_server_conf_1_w1 = adsp_conn->adsc_gate1->adsrc_server_list_1[ iml1 ]->adsc_server_conf_1;  /* list of servers */
#endif
         while (adsl_server_conf_1_w1) {    /* loop over chain server entry */
           /* compare the name of the entry                            */
#ifdef OLD_1112
           bol1 = m_cmpi_vx_vx( &iml_result,
                                ACHL_SERVER_NAME_UTF16, -1, ied_chs_utf_16,
                                adsp_param_conn->ac_servent_target,
                                adsp_param_conn->inc_len_target,
                                adsp_param_conn->iec_chs_servent_t );
#else
             dsl_ucs_w1.ac_str = adsl_server_conf_1_w1->awcc_name;  /* address of name */
           bol1 = m_cmpi_ucs_ucs( &iml_result, &dsl_ucs_w1, &adsp_param_conn->dsc_ucs_server_entry );  /* compare Server Entry */
#endif
           if ((bol1) && (iml_result == 0)) {  /* entry found          */
             adsp_param_conn->vpc_servent = adsl_server_conf_1_w1;  /* handle to server entry */
#ifdef OLD_1112
             adsp_param_conn->boc_load_balancing = FALSE;  /* do not load-balancing first */
#endif
#ifndef OLD_1112
             adsp_param_conn->iec_set = m_conn_get_set( adsp_conn, FALSE );  /* server entry type */
#endif
             adsp_param_conn->iec_conn_ret = ied_conn_ok;  /* return prepare + connect */
             if (adsl_server_conf_1_w1->inc_function == DEF_FUNC_PTTD) {  /* PASS-THRU-TO-DESKTOP */
               m_prep_pttd_1( adsp_param_conn, adsl_server_conf_1_w1 );
#ifdef OLD_1112
             } else if (adsl_server_conf_1_w1->inc_function < 0) {  /* has to do load-balancing */
               adsp_param_conn->boc_load_balancing = TRUE;  /* do load-balancing first */
#endif
             }
             return;                        /* all done                */
           }
           adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_next;
         }
       } while (iml1 > 0);                  /* for all server lists    */
#ifdef OLD_1112
#undef ACHL_SERVER_NAME_UTF16
#endif
#undef ADSL_USGRO_G
#ifdef OLD_1112
#undef ADSL_SELSERV_1
#undef ADSL_SELSERV_2
#endif
#undef ADSL_SELSERV_3
#undef ADSL_AUXF_SESSCO1_W1
       break;
     default:
       break;
   }
   adsp_param_conn->iec_conn_ret = ied_conn_se_not_found;  /* server entry not found */
   return;
} /* end m_prep_conn_1()                                               */
#endif
#endif

/** retrieve target-filter associated with TCP SSL session with the client */
static struct dsd_targfi_1 * m_get_session_targfi( char **aachp_msg, DSD_CONN_G *adsp_conn ) {
   struct dsd_auxf_1 *adsl_auxf_1_sessco1;  /* auxiliary session configuration */

   adsl_auxf_1_sessco1 = adsp_conn->adsc_auxf_1;  /* get first element */
   while (adsl_auxf_1_sessco1) {            /* loop over chain         */
     if (adsl_auxf_1_sessco1->iec_auxf_def == ied_auxf_sessco1) {  /* session configuration */
#define ADSL_AUXF_SESSCO1_W1 ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_sessco1 + 1))
       if (ADSL_AUXF_SESSCO1_W1->adsc_targfi_1 == NULL) break;  /* no target-filter defined */
       *aachp_msg = "dynamic";
       return ADSL_AUXF_SESSCO1_W1->adsc_targfi_1;  /* return target-filter */
#undef ADSL_AUXF_SESSCO1_W1
     }
     adsl_auxf_1_sessco1 = adsl_auxf_1_sessco1->adsc_next;  /* get next in chain */
   }
   if (   (adsp_conn->adsc_user_group)      /* user-group set          */
       && (adsp_conn->adsc_user_group->adsc_targfi_1)) {
     *aachp_msg = "user-group";
     return adsp_conn->adsc_user_group->adsc_targfi_1;
   }
   if (adsp_conn->adsc_server_conf_1->adsc_targfi_1) {
     *aachp_msg = "server-entry";
     return adsp_conn->adsc_server_conf_1->adsc_targfi_1;
   }
   if (adsp_conn->adsc_gate1->adsc_targfi_1) {
     *aachp_msg = "connection";
     return adsp_conn->adsc_gate1->adsc_targfi_1;
   }
   return NULL;                             /* no target-filter        */
} /* end m_get_session_targfi()                                        */

#ifdef D_HPPPT1_1
#ifdef XYZ1
extern "C" struct dsd_ppp_targfi_act_1 * m_get_l2tp_targfi( struct dsd_l2tp_session *adsp_l2tp_session ) {
   int        iml1;                         /* working-variable        */
   DSD_CONN_G *adsl_conn1;                  /* connection              */
   char       *achl_stf;                    /* source target-filter    */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */
   struct dsd_ppp_targfi_act_1 *adsl_ptfa1;  /* active target filter   */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   adsl_targfi_w1 = m_get_session_targfi( &achl_stf, adsl_conn1 );
   if (adsl_targfi_w1 == NULL) return NULL;
   if (adsg_loconf_1_inuse->inc_network_stat >= 4) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS0xxI GATE=%(ux)s SNO=%08d INETA=%s L2TP apply target-filter %(ux)s from %s.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, adsl_targfi_w1->awcc_name, achl_stf );
   }
   adsl_ptfa1 = (struct dsd_ppp_targfi_act_1 *) malloc( sizeof(struct dsd_ppp_targfi_act_1) );  /* active target filter */
   adsl_ptfa1->adsc_targfi_1 = adsl_targfi_w1;  /* used target filter  */
   adsl_ptfa1->adsc_ce_act = NULL;          /* chain active cache entries PPP target filter */
   adsl_ptfa1->adsc_ce_empty = adsl_ptfa1->dsrc_ce;  /* chain empty cache entries PPP target filter */
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop over all cache entries */
     adsl_ptfa1->dsrc_ce[ iml1 ].adsc_next = &adsl_ptfa1->dsrc_ce[ iml1 + 1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < (D_CACHE_TF_IPV4_NO_ENTRY - 1));
   adsl_ptfa1->dsrc_ce[ D_CACHE_TF_IPV4_NO_ENTRY - 1 ].adsc_next = NULL;
   return adsl_ptfa1;
} /* end m_get_l2tp_targfi()                                           */
#endif

/** retrieve target-filter for L2TP                                    */
//extern "C" struct dsd_targfi_1 * m_get_l2tp_targfi( struct dsd_l2tp_session *adsp_l2tp_session ) {
extern "C" struct dsd_targfi_1 * m_get_l2tp_targfi( struct dsd_l2tp_session *adsp_l2tp_session,
                                                    int *aimp_trace_level,  /* trace_level */
                                                    int *aimp_sno ) {  /* WSP session number */
   DSD_CONN_G *adsl_conn1;                  /* connection              */
   char       *achl_stf;                    /* source target-filter    */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_l2tp_session
                      - offsetof( DSD_CONN_G, dsc_l2tp_session )));
#ifndef B160503
   if (aimp_trace_level) *aimp_trace_level = adsl_conn1->imc_trace_level;  /* trace level set */
   if (aimp_sno) *aimp_sno = adsl_conn1->dsc_co_sort.imc_sno;  /* session number */
#endif
   adsl_targfi_w1 = m_get_session_targfi( &achl_stf, adsl_conn1 );
   if (adsl_targfi_w1 == NULL) return NULL;
   if (adsg_loconf_1_inuse->inc_network_stat >= 4) {
#ifdef B110104
     m_hlnew_printf( HLOG_XYZ1, "HWSPS082I GATE=%(ux)s SNO=%08d INETA=%s L2TP apply target-filter %(ux)s from %s.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, adsl_targfi_w1->awcc_name, achl_stf );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPS082I GATE=%(ux)s SNO=%08d INETA=%s L2TP apply target-filter %(u8)s from %s.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name, achl_stf );
   }
   return adsl_targfi_w1;
} /* end m_get_l2tp_targfi()                                           */

extern "C" BOOL m_get_l2tp_sstp_flag_channel_binding( struct dsd_l2tp_session *adsp_l2tp_session ) {
   DSD_CONN_G *adsl_conn1;                  /* connection              */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_l2tp_session
                      - offsetof( DSD_CONN_G, dsc_l2tp_session )));
   if (adsl_conn1->adsc_server_conf_1 == NULL) return FALSE;  /* no configuration server */
   return adsl_conn1->adsc_server_conf_1->boc_sstc_not_check_channel_bindings;  /* do not check channel binding for SSTP */
} /* end m_get_l2tp_sstp_flag_channel_binding()                        */

/** get configured if SSTP channel binding should be checked           */
extern "C" BOOL m_get_tun_sstp_flag_channel_binding( struct dsd_tun_contr_conn *adsp_tun_conn ) {
   DSD_CONN_G *adsl_conn1;                  /* connection              */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_tun_conn
                      - offsetof( DSD_CONN_G, dsc_tun_contr_conn )));
   return adsl_conn1->adsc_server_conf_1->boc_sstc_not_check_channel_bindings;  /* do not check channel binding for SSTP */
} /* m_get_tun_sstp_flag_channel_binding()                             */


#ifdef B150310
extern "C" BOOL m_check_l2tp_sstp_channel_binding( struct dsd_l2tp_session *adsp_l2tp_session,
                                                   unsigned char ucp_hash,
                                                   char *achp_cert_hash,
                                                   int imp_len_cert_hash,
                                                   char *achp_hlak ) {
   DSD_CONN_G *adsl_conn1;                  /* connection              */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_l2tp_session
                      - offsetof( DSD_CONN_G, dsc_l2tp_session )));
   return m_check_conn_sstp_channel_binding( adsl_conn1, ucp_hash, achp_cert_hash, imp_len_cert_hash, achp_hlak );
} /* m_check_l2tp_sstp_channel_binding()                               */

static BOOL m_check_conn_sstp_channel_binding( DSD_CONN_G *adsp_conn,
                                               unsigned char ucp_hash,
                                               char *achp_cert_hash,
                                               int imp_len_cert_hash,
                                               char *achp_hlak ) {
#define SSTP_HASH_LEN     32
#define SSTP_DIGEST_LEN   32
#define SSTP_HLAK_LEN     32

   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   char       *achl_cert;                   /* address of server certificate */
   int        iml_len_cert;                 /* length of server certificate */
   union {
     int      imrl_sha1[ SHA_ARRAY_SIZE ];    /* for SHA-1 hash        */
     int      imrl_sha256_array[ SHA256_ARRAY_SIZE ];  /* for SHA-256  */
   };
   char       byrl_digest_1[ SSTP_DIGEST_LEN ];
   char       byrl_digest_2[ SSTP_DIGEST_LEN ];
   char       byrl_hmac_1[ 64 ];            /* for HMAC                */
   char       byrl_hmac_2[ 64 ];            /* for HMAC                */

// to-do 03.07.14 KB - temporary
   return TRUE;

   if (achp_hlak != NULL) {                 /* MPPE not yet implemented */
// to-do 03.07.14 KB - error message
     return FALSE;
   }
   if (imp_len_cert_hash != (SSTP_HASH_LEN + 2 * SSTP_DIGEST_LEN)) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }
   bol_rc = m_get_server_certificate( (void **) &achl_cert, &iml_len_cert, adsp_conn->dsc_hlse03s.ac_ext );
   if (bol_rc == FALSE) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }
   if (iml_len_cert <= 0) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }
   switch (ucp_hash) {                      /* type of hash            */
     case 1:                                /* SHA-1                   */
       goto p_sha1_00;
     case 2:                                /* SHA-256                 */
       goto p_sha2_00;
   }
// to-do 03.07.14 KB - error message
   return FALSE;

   p_sha1_00:                               /* process SHA-1           */
   return FALSE;

   p_sha2_00:                               /* process SHA-256         */
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array, achl_cert, 0, iml_len_cert );
   SHA256_Final( imrl_sha256_array, byrl_digest_1, 0 );
   if (memcmp( achp_cert_hash + SSTP_HASH_LEN, byrl_digest_1, SHA256_DIGEST_LEN )) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }

   /* generate HMAC                                                    */
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml1 = 0;
   do {
     byrl_hmac_1[ iml1 ] ^= *((unsigned char *) achp_cert_hash + iml1);
     byrl_hmac_2[ iml1 ] ^= *((unsigned char *) achp_cert_hash + iml1);
     iml1++;                                /* increment index         */
   } while (iml1 < SSTP_HASH_LEN);          /* length of string to apply */
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   SHA256_Update( imrl_sha256_array, (char *) byrs_zeroes, 0, SSTP_HLAK_LEN );
   SHA256_Update( imrl_sha256_array, (char *) ucrs_sstp_mac_seed, 0, sizeof(ucrs_sstp_mac_seed) );
   SHA256_Update( imrl_sha256_array, (char *) ucrs_sstp_hmac_len_const, 0, sizeof(ucrs_sstp_hmac_len_const) );
   SHA256_Final( imrl_sha256_array, byrl_digest_1, 0 );
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   SHA256_Update( imrl_sha256_array, byrl_digest_1, 0, SHA256_DIGEST_LEN );
   SHA256_Final( imrl_sha256_array, byrl_digest_2, 0 );
   if (memcmp( achp_cert_hash + SSTP_HASH_LEN + SSTP_DIGEST_LEN, byrl_digest_2, SHA256_DIGEST_LEN )) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }
   return TRUE;
#undef SSTP_HASH_LEN
} /* end m_check_conn_sstp_channel_binding()                           */
#endif
/** check SSTP channel bindings for L2TP                               */
extern "C" BOOL m_check_l2tp_sstp_channel_binding( struct dsd_l2tp_session *adsp_l2tp_session,
                                                   char *achp_pkt, int imp_len_pkt ) {
   DSD_CONN_G *adsl_conn1;                  /* connection              */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_l2tp_session
                      - offsetof( DSD_CONN_G, dsc_l2tp_session )));
   return m_check_conn_sstp_channel_binding( adsl_conn1, achp_pkt, imp_len_pkt );
} /* m_check_l2tp_sstp_channel_binding()                               */

/** check SSTP channel bindings for HOB-TUN                            */
extern "C" BOOL m_check_tun_sstp_channel_binding( struct dsd_tun_contr_conn *adsp_tun_conn,
                                                  char *achp_pkt, int imp_len_pkt ) {
   DSD_CONN_G *adsl_conn1;                  /* connection              */

   adsl_conn1 = ((DSD_CONN_G *)
                   ((char *) adsp_tun_conn
                      - offsetof( DSD_CONN_G, dsc_tun_contr_conn )));
   return m_check_conn_sstp_channel_binding( adsl_conn1, achp_pkt, imp_len_pkt );
} /* m_check_tun_sstp_channel_binding()                                */

/** check SSTP channel bindings                                        */
static BOOL m_check_conn_sstp_channel_binding( DSD_CONN_G *adsp_conn,
                                               char *achp_pkt, int imp_len_pkt ) {
#define SSTP_LEN_HEADER        4
#define SSTP_FILLER_01    12
#define SSTP_NONCE_LEN    32
#define SSTP_HASH_LEN     32
#define SSTP_DIGEST_LEN   32
#define SSTP_HLAK_LEN     32
#define SSTP_MSG_CALL_CONNECTED_LENGTH 112
#define SSTP_CMAC_LENGTH 32
#define SSTP_CMAC_OFFSET 80

   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   char       *achl_hlak;                   /* address of HLAK - MPPE keys */
   char       *achl_cert;                   /* address of server certificate */
   int        iml_len_cert;                 /* length of server certificate */
   struct dsd_auxf_1 *adsl_auxf_1_hlak;     /* auxiliary extension field - HLAK */
   union {
     int      imrl_sha1[ SHA_ARRAY_SIZE ];    /* for SHA-1 hash        */
     int      imrl_sha256_array[ SHA256_ARRAY_SIZE ];  /* for SHA-256  */
   };
   char       byrl_digest_1[ SSTP_DIGEST_LEN ];
   char       byrl_digest_2[ SSTP_DIGEST_LEN ];
   char       byrl_pkt_hmac[ SSTP_MSG_CALL_CONNECTED_LENGTH ];


#ifdef XYZ1
   if (   (adsp_conn->adsc_server_conf_1)
       && (adsp_conn->adsc_server_conf_1->boc_check_cert)) {  /* do-not-check-certificate */
     return TRUE;
   }
#endif
   if ((imp_len_pkt - SSTP_LEN_HEADER - SSTP_FILLER_01) != (SSTP_HASH_LEN + 2 * SSTP_DIGEST_LEN)) {
// to-do 03.07.14 KB - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }
#ifdef XYZ1
   if (imp_len_cert_hash != (SSTP_HASH_LEN)) {
// to-do 03.07.14 KB - error message
     return FALSE;
   }
#endif
   bol_rc = m_get_server_certificate( (void **) &achl_cert, &iml_len_cert, adsp_conn->dsc_hlse03s.ac_ext );
   if (bol_rc == FALSE) {
// to-do 03.07.14 KB - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }
   if (iml_len_cert <= 0) {
// to-do 03.07.14 KB - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }
   /* get HLAK - MPPE keys saved before                                */
   achl_hlak = (char *) byrs_zeroes;        /* address of HLAK - MPPE keys */
   adsl_auxf_1_hlak = adsp_conn->adsc_auxf_1;  /* get chain auxiliary ext fields */
   while (adsl_auxf_1_hlak) {               /* loop over auxiliary extension fields */
     if (adsl_auxf_1_hlak->iec_auxf_def == ied_auxf_mppe_keys) {  /* SSTP - HLAK */
       achl_hlak = (char *) (adsl_auxf_1_hlak + 1);  /* address of HLAK - MPPE keys */
       break;
     }
     adsl_auxf_1_hlak = adsl_auxf_1_hlak->adsc_next;  /* get next in chain */
   }

   switch (*(achp_pkt + SSTP_LEN_HEADER + (SSTP_FILLER_01 - 1))) {  /* type of hash */
     case 1:                                /* SHA-1                   */
       goto p_sha1_00;
     case 2:                                /* SHA-256                 */
       goto p_sha2_00;
   }
// to-do 03.07.14 KB - error message
   m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                   adsp_conn->adsc_gate1 + 1,
                   adsp_conn->dsc_co_sort.imc_sno,
                   adsp_conn->chrc_ineta,
                   __LINE__ );
   return FALSE;

   p_sha1_00:                               /* process SHA-1           */
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, achl_cert, 0, iml_len_cert );
   SHA1_Final( imrl_sha1, byrl_digest_1, 0 );
   if (memcmp( achp_pkt + SSTP_LEN_HEADER + SSTP_FILLER_01 + SSTP_NONCE_LEN,
               byrl_digest_1, SHA_DIGEST_LEN )) {
// to-do 03.07.14 KB - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }

   // Now we generate the Key, T1 = HMAC(HLAK, S | LEN | 0x01)
   iml1 = SHA_DIGEST_LEN;

   // We use byrl_pkt_hmac in order to avoid using more memory
   memset( byrl_digest_1, 0, SHA_DIGEST_LEN );
   memcpy( byrl_pkt_hmac, (char *) ucrs_sstp_mac_seed, sizeof(ucrs_sstp_mac_seed) );
   static const unsigned char ucrs_sstp_hmac_len_const_SHA1[ 3 ] = {  /* SSTP HMAC constant */
       0X14, 0, 1
   };
   memcpy( byrl_pkt_hmac + sizeof(ucrs_sstp_mac_seed), (char *) ucrs_sstp_hmac_len_const_SHA1, sizeof(ucrs_sstp_hmac_len_const_SHA1) );


   // First 3 parameters refer to key - must be changed
// if (GenHMAC( (char *) byrs_zeroes,
   if (GenHMAC( achl_hlak,
                0, SHA_DIGEST_LEN, byrl_pkt_hmac, 0, sizeof(ucrs_sstp_mac_seed) + sizeof(ucrs_sstp_hmac_len_const), HMAC_SHA1_ID, byrl_digest_1, 0, &iml1 )){
            // to-do - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
            return FALSE;
   }

   // Now we calculate the CMAC
   memset( byrl_digest_2, 0, SHA_DIGEST_LEN );
   // Now we copy the pkt
   // and zero out the CMAC field
   memcpy( byrl_pkt_hmac, achp_pkt, SSTP_CMAC_OFFSET );
   memset( byrl_pkt_hmac + SSTP_CMAC_OFFSET, 0, SSTP_CMAC_LENGTH );
   if (GenHMAC( byrl_digest_1, 0, SHA_DIGEST_LEN, byrl_pkt_hmac, 0, SSTP_MSG_CALL_CONNECTED_LENGTH, HMAC_SHA1_ID, byrl_digest_2, 0, &iml1 )){
            // to-do - error message
            return FALSE;
   }
   // Now we compare the CMAC field
   if (memcmp( achp_pkt + SSTP_CMAC_OFFSET, byrl_digest_2, SHA_DIGEST_LEN )) {
            // to-do - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
            return FALSE;
   }


   return TRUE;

   p_sha2_00:                               /* process SHA-256         */
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array, achl_cert, 0, iml_len_cert );
   SHA256_Final( imrl_sha256_array, byrl_digest_1, 0 );
   if (memcmp( achp_pkt + SSTP_LEN_HEADER + SSTP_FILLER_01 + SSTP_NONCE_LEN,
               byrl_digest_1, SHA256_DIGEST_LEN )) {
// to-do 03.07.14 KB - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
     return FALSE;
   }

   // Now we generate the Key, T1 = HMAC(HLAK, S | LEN | 0x01)
   iml1 = SSTP_DIGEST_LEN;

   // We use byrl_pkt_hmac in order to avoid using more memory
   memset( byrl_digest_1, 0, SSTP_DIGEST_LEN );
   memcpy( byrl_pkt_hmac, (char *) ucrs_sstp_mac_seed, sizeof(ucrs_sstp_mac_seed) );
   memcpy( byrl_pkt_hmac + sizeof(ucrs_sstp_mac_seed), (char *) ucrs_sstp_hmac_len_const, sizeof(ucrs_sstp_hmac_len_const) );

   // First 3 parameters refer to key - must be changed
// if (GenHMAC( (char *) byrs_zeroes,
   if (GenHMAC( achl_hlak,
                0, SSTP_DIGEST_LEN, byrl_pkt_hmac, 0, sizeof(ucrs_sstp_mac_seed) + sizeof(ucrs_sstp_hmac_len_const), HMAC_SHA256_ID, byrl_digest_1, 0, &iml1 )){
            // to-do - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
            return FALSE;
   }

   // Now we calculate the CMAC
   memset( byrl_digest_2, 0, SSTP_DIGEST_LEN );
   // Now we copy the pkt
   // and zero out the CMAC field
   memcpy( byrl_pkt_hmac, achp_pkt, SSTP_CMAC_OFFSET );
   memset( byrl_pkt_hmac + SSTP_CMAC_OFFSET, 0, SSTP_CMAC_LENGTH );
   if (GenHMAC( byrl_digest_1, 0, SSTP_DIGEST_LEN, byrl_pkt_hmac, 0, SSTP_MSG_CALL_CONNECTED_LENGTH, HMAC_SHA256_ID, byrl_digest_2, 0, &iml1 )){
            // to-do - error message
            return FALSE;
   }
   // Now we compare the CMAC field
   if (memcmp( achp_pkt + SSTP_CMAC_OFFSET, byrl_digest_2, SSTP_CMAC_LENGTH )) {
            // to-do - error message
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s SSTP m_check_conn_sstp_channel_binding() l%05d error",
                     adsp_conn->adsc_gate1 + 1,
                     adsp_conn->dsc_co_sort.imc_sno,
                     adsp_conn->chrc_ineta,
                     __LINE__ );
            return FALSE;
   }


   return TRUE;

#undef SSTP_MSG_CALL_CONNECTED_LENGTH
#undef SSTP_CMAC_LENGTH
#undef SSTP_CMAC_OFFSET
#undef SSTP_HASH_LEN
} /* end m_check_conn_sstp_channel_binding()                           */

#define D_AVSMS_CHCH           11           /* attribute vendor-specific MS MS-CHAP-Challenge */
#define D_AVSMS_CHRE           25           /* attribute vendor-specific MS MS-CHAP-Response */
#define D_AVSMS_CHSU           26           /* attribute vendor-specific MS MS-CHAP-Success */
#define D_AVSMS_CHFA           2            /* attribute vendor-specific MS MS-CHAP-Failure */
#define LEN_AVSMS_NEW_PWD      512          /* attribute vendor-specific MS password UTF-16 bytes */

// to-do 01.09.12 KB - rename to m_ppp_se_auth()
/** do authentication for PPP server                                   */
extern "C" void m_ppp_auth_1( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_id;                       /* count array identifier  */
   HL_LONGLONG ill1;                        /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
#ifdef XYZ1
   char       *achl_rp;                     /* read pointer            */
#endif
   DSD_CONN_G *adsl_conn1_l;                /* the connection / session */
   void *     vpl_handle;                   /* handle for L2TP or HOB-TUN */
   int        inl_len_cert;                 /* length of certificate n */
   enum ied_chid_ret iel_chid_ret;          /* check ident return code */
#define TRY_140509_01                       /* try character set authentication */
#ifdef TRY_140509_01
   enum ied_charset iel_chs_auth;           /* character set authentication */
#endif
// BOOL       bol_http;                     /* try HTTP                */
// ied_at_function iel_function;            /* authentication function */
// ied_at_return iel_return;                /* return authentication   */
// ied_scp_def iel_scp_def;                 /* server-conf protocol    */
// char       *achl_w1;                     /* working variable        */
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_last;  /* last record in storage for authentication */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_ppp_auth_record *adsl_par_userid;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_recv_new;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_mscv2_challenge;  /* record in storage for authentication */
   struct dsd_auxf_1 *adsl_auxf_1_hlak;     /* auxiliary extension field - HLAK */
#ifndef B150703
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif
#ifndef HL_UNIX
   union {
     /* for MS-CHAP-V2                                                 */
     struct {
#endif
       struct dsd_ppp_auth_record *adsl_par_mscv2_response;  /* record in storage for authentication */
       struct dsd_ppp_auth_record *adsl_par_mscv2_change_pwd;  /* record in storage for authentication */
       struct dsd_user_entry *adsl_usent;   /* user entry              */
       int    imrl_sha1_array[ SHA_ARRAY_SIZE ];  /* for hash          */
       int    imrl_md4_array[ MD4_ARRAY_SIZE ];  /* for MD4            */
       unsigned int umrl_des_subkeytab[ DES_SUBKEY_ARRAY_SIZE ];  /* for DES */
#ifndef HL_UNIX
     };
     /* for PAP                                                        */
     struct {
#endif
       struct dsd_ppp_auth_record *adsl_par_pap_password;  /* record in storage for authentication */
#ifndef HL_UNIX
     };
     /* for EAP                                                        */
     struct {
#endif
       struct dsd_ppp_auth_record *adsl_par_eap_send;  /* record in storage for authentication */
       struct dsd_ppp_auth_record *adsl_par_radius_1;  /* record in storage for authentication */
#ifndef HL_UNIX
     };
   };
#endif
// struct dsd_hl_wspat2_1 dsl_hlwspat2;     /* WSPAT2 call parameters  */
// struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_unicode_string dsl_us_userid;  /* for userid             */
   struct dsd_unicode_string dsl_us_password;  /* for password         */
   char       chrl_work1[ 256 * 2 ];        /* working area            */
   char       chrl_work2[ 256 ];            /* working area            */
   char       chrl_work3[ 24 ];             /* working area            */
   char       chrl_work4[ SHA_DIGEST_LEN ];  /* working area           */
   unsigned char ucrl_work5[ 8 ];           /* work area DES           */
   char       chrl_pwd_hashhash[ SHA_DIGEST_LEN ];  /* PasswordHashHash       */
   char       chrl_masterkey[ SHA_DIGEST_LEN ];  /* MPPE master key    */

#define DEF_EAP_SUCCESS 1
#define DEF_EAP_FAILURE 2

   vpl_handle = adsp_ppp_se_1->vpc_handle;  /* handle for L2TP or HOB-TUN */
   if (vpl_handle == NULL) return;          /* is not valid            */
   if (adsp_ppp_se_1->adsc_ppp_cl_1) {      /* is L2TP                 */
     adsl_conn1_l = (DSD_CONN_G *) ((char *) vpl_handle
                                             - offsetof( DSD_CONN_G, dsc_l2tp_session ));
#ifdef D_INCL_HOB_TUN
   } else {                                 /* TRUE is HOB-TUN         */
// to-do 15.09.12 KB - where to get connection?
//   adsl_conn1_l = (DSD_CONN_G *) (((char *) vpl_handle - offsetof( DSD_CONN_G, dsc_tun_contr1 )));
     adsl_conn1_l = (DSD_CONN_G *) (((char *) vpl_handle - offsetof( DSD_CONN_G, dsc_tun_contr_conn )));
#endif
   }
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_1( %p ) adsp_ppp_se_1->imc_options=0X%08X adsp_ppp_se_1->adsc_ppp_auth_header=%p.",
                   __LINE__, adsp_ppp_se_1, adsp_ppp_se_1->imc_options, adsp_ppp_se_1->adsc_ppp_auth_header );
#endif
#ifndef B150703
   if (adsl_conn1_l->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNEAUTH1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsl_conn1_l->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                          "l%05d m_ppp_auth_1( %p ) imc_options=0X%08X adsc_ppp_auth_header=%p.",
                          __LINE__, adsp_ppp_se_1, adsp_ppp_se_1->imc_options, adsp_ppp_se_1->adsc_ppp_auth_header );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   if (adsp_ppp_se_1->imc_options & (D_PPP_OPT_AUTH_OK | D_PPP_OPT_ENDED)) {  /* authentication succeeded or PPP module has ended */
     if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) return;  /* no storage for authentication */
     adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_server_1 = NULL;  /* no more PPP server */
//   if (adsp_ppp_se_1->adsc_ppp_auth_header->boc_async_active == FALSE) {  /* asynchronous request is not active */
#ifdef B140325
     if (adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius == NULL) {  /* no Radius authentication */
// to-do 25.03.14 KB - end Radius
       m_proc_free( adsp_ppp_se_1->adsc_ppp_auth_header );  /* free storage for authentication */
     }
#endif
// to-do 25.03.14 KB - is this thread safe ???
     m_ppp_auth_free( adsp_ppp_se_1 );
     m_proc_free( adsp_ppp_se_1->adsc_ppp_auth_header );  /* free storage for authentication */
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
     m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_1( %p ) adsc_ppp_auth_header %p freed",
                     __LINE__, adsp_ppp_se_1, adsp_ppp_se_1->adsc_ppp_auth_header );
#endif
     adsp_ppp_se_1->adsc_ppp_auth_header = NULL;  /* clear storage for authentication */
     return;                                /* all done                */
   }
   if (adsp_ppp_se_1->adsc_ppp_auth_header) {  /* with storage for authentication */
     goto p_init_end;                       /* end of initialization   */
   }
   adsp_ppp_se_1->adsc_ppp_auth_header = (struct dsd_ppp_auth_header *) m_proc_alloc();  /* storage for authentication */
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_1( %p ) acquired memory adsp_ppp_se_1->imc_options=0X%08X. adsp_ppp_se_1->adsc_ppp_auth_header=%p.",
                   __LINE__, adsp_ppp_se_1, adsp_ppp_se_1->imc_options, adsp_ppp_se_1->adsc_ppp_auth_header );
#endif
   adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_server_1 = adsp_ppp_se_1;  /* PPP server */
   adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end  /* end of this storage */
     = (char *) adsp_ppp_se_1->adsc_ppp_auth_header + LEN_TCP_RECV;
   adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = NULL;  /* chain of records in storage for authentication */
   adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
     = (enum ied_ppp_auth_def) adsp_ppp_se_1->chrc_ppp_auth[ adsp_ppp_se_1->imc_auth_no ];
   adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = NULL;  /* not yet Radius authentication */
   adsp_ppp_se_1->adsc_ppp_auth_header->imc_state = 0;  /* state of processing */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_ms_chap_v2) {  /* not MS-CHAP-V2 */
     return;
   }
   adsl_par_w1 = (struct dsd_ppp_auth_record *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* record in storage for authentication */
#ifdef OLD01
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_challenge;  /* type of authentication record - MS-CHAP-V2 challenge */
   adsl_par_w1->imc_len_data = 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident);  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_w1 + 1))
   AUCL_PAR_DATA[ 0 ] = LEN_MSCV2_CHALLENGE;  /* length MS-CHAP-V2 challenge */
// to-do 14.03.14 KB - use secure random
   iml1 = LEN_MSCV2_CHALLENGE;              /* length MS-CHAP-V2 challenge */
   do {                                     /* loop to fill challenge  */
     AUCL_PAR_DATA[ iml1 ] = (unsigned char) m_get_random_number( 0X0100 );
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   memcpy( AUCL_PAR_DATA + 1 + LEN_MSCV2_CHALLENGE, ucrs_wsp_ident, sizeof(ucrs_wsp_ident) );
#undef AUCL_PAR_DATA
   adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_w1;  /* chain of records in storage for authentication */
   return;                                  /* send challenge to client */
#endif
   adsl_par_last = NULL;                    /* is first in chain       */
   goto p_gen_chal_00;                      /* generate challenge for MS-CHAP-V2 */

   p_init_end:                              /* end of initialization   */
   switch (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth) {  /* authentication-method in use */
     case ied_pppa_pap:                     /* PAP                     */
       goto p_pap_00;                       /* check PAP               */
//   case ied_pppa_chap:                    /* CHAP                    */
     case ied_pppa_ms_chap_v2:              /* MS-CHAP-V2              */
       goto p_mscv2_00;                     /* check MS-CHAP-V2        */
     case ied_pppa_eap:                     /* EAP                     */
       goto p_eap_00;                       /* check EAP               */
   }
   /* program should never come here                                   */
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "authentication processing PPP response - illogic 01" );
   return;

   p_eap_00:                                /* check EAP               */
   adsl_par_userid = NULL;                  /* record in storage for authentication */
   adsl_par_recv_new = NULL;                /* record in storage for authentication */
   adsl_par_radius_1 = NULL;                /* record in storage for authentication */
   adsl_par_mscv2_challenge = NULL;         /* record in storage for authentication */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   achl1 = (char *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* end of storage used */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     bol1 = FALSE;                          /* remove record           */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_userid:                 /* userid                  */
         adsl_par_userid = adsl_par_w1;     /* record in storage for authentication */
         bol1 = TRUE;                       /* keep record             */
         break;
       case ied_par_radius_1:               /* used for Radius         */
         adsl_par_radius_1 = adsl_par_w1;   /* record in storage for authentication */
         bol1 = TRUE;                       /* keep record             */
         break;
       case ied_par_eap_recv_1:             /* EAP received and not yet processed */
         adsl_par_recv_new = adsl_par_w1;   /* record in storage for authentication */
         bol1 = TRUE;                       /* keep record             */
         break;
       case ied_par_mscv2_challenge:        /* MS-CHAP-V2 challenge    */
         adsl_par_mscv2_challenge = adsl_par_w1;  /* record in storage for authentication */
         bol1 = TRUE;                       /* keep record             */
         break;
     }
     if (bol1) {                            /* keep record             */
       achl2 = (char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data;  /* end of this record */
       if (achl2 > achl1) achl1 = achl2;    /* in use till here        */
       adsl_par_last = adsl_par_w1;         /* save last in chain      */
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_conn1_l->adsc_radius_group == NULL) {  /* no active Radius group */
     goto p_mscv2_60;                       /* EAP not Radius          */
   }
   /* prepare Radius request                                           */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl1 + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius) {  /* for Radius authentication */
     goto p_eap_20;                         /* Radius already started  */
   }
   adsl_par_radius_1 = adsl_par_w1;         /* record in storage for authentication - Radius */
#define ADSL_PAR_RC1 ((struct dsd_radius_control_1 *) (adsl_par_radius_1 + 1))
#define ADSL_PAR_APS1 ((void **) (ADSL_PAR_RC1 + 1))
#define ADSL_PAR_AR1 ((struct dsd_hl_aux_radius_1 *) (ADSL_PAR_APS1 + 1))
#define ADSL_PAR_IDENT ((struct dsd_ppp_auth_record *) ((char *) (ADSL_PAR_AR1 + 1)))
#define ACHL_PAR_RATTR_0 ((char *) (ADSL_PAR_IDENT + 1))  /* Radius attributes */
   if (((char *) adsl_par_radius_1 + sizeof(struct dsd_ppp_auth_record)
             + (((char *) (ADSL_PAR_AR1 + 1)) - ((char *) ADSL_PAR_RC1)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 20" );
     return;
   }
   adsl_par_radius_1->iec_par = ied_par_radius_1;  /* used for Radius        */
   adsl_par_radius_1->imc_len_data          /* length of the data      */
     = ((char *) (ADSL_PAR_AR1 + 1))
          - ((char *) ADSL_PAR_RC1);
   *ADSL_PAR_APS1 = adsp_ppp_se_1->adsc_ppp_auth_header;  /* save address of storage for authentication */
   memset( ADSL_PAR_AR1, 0, sizeof(struct dsd_hl_aux_radius_1) );
   ADSL_PAR_AR1->dsc_ucs_userid.ac_str = (adsl_par_userid + 1);  /* address of userid */
   ADSL_PAR_AR1->dsc_ucs_userid.imc_len_str = adsl_par_userid->imc_len_data;  /* length userid in elements / bytes */
   ADSL_PAR_AR1->dsc_ucs_userid.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   ADSL_PAR_AR1->boc_radius_eap = TRUE;     /* Radius EAP message      */
   ADSL_PAR_AR1->boc_radius_msg_auth = TRUE;  /* with Radius message authentication */
   adsl_par_radius_1->adsc_next = ADSL_PAR_IDENT;  /* set chain        */
   /* AVP packet with EAP                                              */
#define DEF_RADIUS_AVP_TYPE_EAP 0X4F
   *(ACHL_PAR_RATTR_0 + 0) = (unsigned char) DEF_RADIUS_AVP_TYPE_EAP;  /* set type EAP */
   *(ACHL_PAR_RATTR_0 + 1) = (unsigned char) (2 + 4 + 1 + adsl_par_userid->imc_len_data);
   *(ACHL_PAR_RATTR_0 + 2 + 0) = (unsigned char) 2;
   *(ACHL_PAR_RATTR_0 + 2 + 1) = (unsigned char) 0;
   *(ACHL_PAR_RATTR_0 + 2 + 2) = (unsigned char) 0;
   *(ACHL_PAR_RATTR_0 + 2 + 3) = (unsigned char) (4 + 1 + adsl_par_userid->imc_len_data);
   *(ACHL_PAR_RATTR_0 + 2 + 4) = (unsigned char) 1;
   memcpy( ACHL_PAR_RATTR_0 + 2 + 4 + 1,
           adsl_par_userid + 1,         /* address of userid       */
           adsl_par_userid->imc_len_data );  /* length userid in elements / bytes */
   ADSL_PAR_AR1->achc_attr_out = ACHL_PAR_RATTR_0;  /* attributes output */
   ADSL_PAR_AR1->imc_len_attr_out           /* length attributes outp  */
     = 2 + 4 + 1 + adsl_par_userid->imc_len_data;
   ADSL_PAR_AR1->boc_send_nas_ineta = TRUE;  /* send NAS IP Address    */
   ADSL_PAR_IDENT->imc_len_data             /* length of the data      */
     = 2 + 4 + 1 + adsl_par_userid->imc_len_data;
   ADSL_PAR_IDENT->adsc_next = NULL;        /* clear chain             */
   ADSL_PAR_IDENT->iec_par = ied_par_aux;   /* type of authentication record - auxiliary record */
   adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = ADSL_PAR_RC1;  /* for Radius authentication */
   m_radius_init( ADSL_PAR_RC1,
                  adsl_conn1_l->adsc_radius_group,  /* active Radius group */
                  adsl_conn1_l,             /* current connection      */
#ifndef HL_UNIX
                  (struct sockaddr *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                  (struct sockaddr *) &adsl_conn1_l->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                  &m_ppp_auth_radius_compl );
   goto p_eap_60;                           /* do Radius request       */

   p_eap_20:                                /* Radius already started  */
   if (adsl_par_recv_new == NULL) {         /* record in storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "authentication processing PPP EAP response - illogic 01" );
     return;
   }
   if (adsl_par_radius_1 == NULL) {         /* record in storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "authentication processing PPP EAP response - illogic 02" );
     return;
   }
   /* maybe we need multiple AVL entries for the information to pass to the Radius server */
   iml1 = adsl_par_recv_new->imc_len_data;  /* length of the data      */
#define TEMP_MAX_LEN (0X100 - 1 - 2)
   iml2 = (iml1 + TEMP_MAX_LEN - 1) / TEMP_MAX_LEN;  /* number of AVL entries */
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + (iml1 + iml2 * 2))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 21" );
     return;
   }
   adsl_par_w1->iec_par = ied_par_aux;      /* type of authentication record - auxiliary record */
   adsl_par_w1->imc_len_data                /* length of the data      */
     = iml1 + iml2 * 2;
   achl1 = (char *) (adsl_par_recv_new + 1);  /* start of input        */
   achl2 = (char *) (adsl_par_w1 + 1);      /* start of output         */
   ADSL_PAR_AR1->achc_attr_out = achl2;     /* attributes output       */
   ADSL_PAR_AR1->imc_len_attr_out           /* length attributes outp  */
     = iml1 + iml2 * 2;
   do {                                     /* loop to fill AVL output */
     iml2 = iml1;                           /* length remaining data   */
     if (iml2 > TEMP_MAX_LEN) iml2 = TEMP_MAX_LEN;
     memcpy( achl2 + 2, achl1, iml2 );
     achl1 += iml2;
     *(achl2)++ = (unsigned char) DEF_RADIUS_AVP_TYPE_EAP;
     *(achl2)++ = (unsigned char) (iml2 + 2);
     achl2 += iml2;
     iml1 -= iml2;                          /* length copied           */
   } while (iml1 > 0);
#undef TEMP_MAX_LEN
   adsl_par_recv_new->iec_par = ied_par_eap_recv_2;  /* EAP received and already processed */

   p_eap_60:                                /* do Radius request       */
   bol1 = m_radius_request( ADSL_PAR_RC1, ADSL_PAR_AR1 );
   if (bol1 == FALSE) {                     /* returned error          */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - m_radius_request() failed" );
   }
   return;                                  /* wait for Radius completition */

#undef ADSL_PAR_RC1
#undef ADSL_PAR_APS1
#undef ADSL_PAR_AR1
#undef ADSL_PAR_IDENT
#undef ACHL_PAR_RATTR_0

   p_mscv2_00:                              /* check MS-CHAP-V2        */
   adsl_par_mscv2_challenge = NULL;         /* record in storage for authentication */
   adsl_par_userid = NULL;                  /* record in storage for authentication */
   adsl_par_mscv2_response = NULL;          /* record in storage for authentication */
   adsl_par_mscv2_change_pwd = NULL;        /* record in storage for authentication */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   achl1 = (char *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* end of storage used */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_mscv2_challenge:        /* MS-CHAP-V2 challenge    */
         adsl_par_mscv2_challenge = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_userid:                 /* userid                  */
         adsl_par_userid = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_mscv2_response:         /* MS-CHAP-V2 response     */
         adsl_par_mscv2_response = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_mscv2_change_pwd:       /* MS-CHAP-V2 change password */
         adsl_par_mscv2_change_pwd = adsl_par_w1;  /* record in storage for authentication */
         break;
     }
     achl2 = (char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data;  /* end of this record */
     if (achl2 > achl1) achl1 = achl2;      /* in use till here        */
     adsl_par_last = adsl_par_w1;           /* save last in chain      */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
#ifdef OLD01
   if (   (adsl_par_mscv2_challenge == NULL)
       || (adsl_par_userid == NULL)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing CHAP response - illogic 01" );
     return;
   }
#endif
   if (   (adsl_par_userid == NULL)
       || (   (adsl_par_mscv2_challenge == NULL)
           && (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
                 == ied_pppa_ms_chap_v2))) {  /* MS-CHAP-V2            */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing MS-CHAP-V2 response - illogic 02" );
     return;
   }
   if (adsl_conn1_l->adsc_radius_group == NULL) {  /* no active Radius group */
     goto p_mscv2_60;                       /* MS-CHAP-V2 not Radius   */
   }
   if ((adsl_conn1_l->adsc_radius_group->imc_options & DEF_RADIUS_GROUP_OPTION_MS_CHAP_V2) == 0) {
     goto p_mscv2_60;                       /* MS-CHAP-V2 not Radius   */
   }
   /* prepare Radius request                                           */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl1 + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
#define ADSL_PAR_RC1 ((struct dsd_radius_control_1 *) (adsl_par_w1 + 1))
#define ADSL_PAR_APS1 ((void **) (ADSL_PAR_RC1 + 1))
#define ADSL_PAR_AR1 ((struct dsd_hl_aux_radius_1 *) (ADSL_PAR_APS1 + 1))
#define ACHL_PAR_RATTR_0 ((char *) (ADSL_PAR_AR1 + 1))  /* Radius attributes */
#define ACHL_PAR_AVSMS_CHRE (ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 2 + LEN_MSCV2_CHALLENGE)
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + (((char *) ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 2 + LEN_MSCV2_RESPONSE)
                  - ((char *) ADSL_PAR_RC1)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 22" );
     return;
   }
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_aux;      /* type of authentication record - auxiliary record */
#ifdef XYZ1
   *ADSL_PAR_APS1 = adsp_ppp_se_1;          /* save address of PPP server */
#endif
   *ADSL_PAR_APS1 = adsp_ppp_se_1->adsc_ppp_auth_header;  /* save address of storage for authentication */
   memset( ADSL_PAR_AR1, 0, sizeof(struct dsd_hl_aux_radius_1) );
   ADSL_PAR_AR1->dsc_ucs_userid.ac_str = (adsl_par_userid + 1);  /* address of userid */
   ADSL_PAR_AR1->dsc_ucs_userid.imc_len_str = adsl_par_userid->imc_len_data;  /* length userid in elements / bytes */
   ADSL_PAR_AR1->dsc_ucs_userid.iec_chs_str = ied_chs_ansi_819;  /* character set userid / ANSI 819 */
// achl1 = ACHL_PAR_RATTR_0;                  /* start attributes        */
   /* MS-CHAP-Challenge                                                */
// if ((ACHL_PAR_RATTR_0 + (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_AVSMS_CHCH)) > MAX_LEN_RADIUS_PACKET) goto p_inv_req_00;  /* invalid request */
   memcpy( ACHL_PAR_RATTR_0, ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   *(ACHL_PAR_RATTR_0 + 1) = (unsigned char) (sizeof(ucrs_send_avp_ms_01) + 2 + LEN_MSCV2_CHALLENGE);  /* set length attribute */
   *(ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 0) = (unsigned char) D_AVSMS_CHCH;  /* attribute vendor-specific MS MS-CHAP-Challenge */
   *(ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 1) = (unsigned char) (2 + LEN_MSCV2_CHALLENGE);  /* attribute vendor-specific MS MS-CHAP-Challenge */
   memcpy( ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 2, (char *) (adsl_par_mscv2_challenge + 1) + 1, LEN_MSCV2_CHALLENGE );
   if (adsl_par_mscv2_change_pwd) {         /* record in storage for authentication */
     goto p_mscv2_20;                       /* MS-CHAP-V2 change password */
   }
// achl1 = ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 2 + LEN_MSCV2_CHALLENGE;  /* here is next attribute */
   memcpy( ACHL_PAR_AVSMS_CHRE, ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   *(ACHL_PAR_AVSMS_CHRE + 1) = (unsigned char) (sizeof(ucrs_send_avp_ms_01) + 2 + 2 + LEN_MSCV2_RESPONSE);  /* set length attribute */
   *(ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 0) = (unsigned char) D_AVSMS_CHRE;  /* attribute vendor-specific MS MS-CHAP-Response */
   *(ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 1) = (unsigned char) (2 + 2 + LEN_MSCV2_RESPONSE);  /* attribute vendor-specific MS MS-CHAP-Response */
   *(ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 0) = 0;
   *(ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 1) = 0;
   memcpy( ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 2, adsl_par_mscv2_response + 1, LEN_MSCV2_RESPONSE );
   ADSL_PAR_AR1->achc_attr_out = ACHL_PAR_RATTR_0;  /* attributes output */
   ADSL_PAR_AR1->imc_len_attr_out           /* length attributes outp  */
     = ((char *) ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 2 + LEN_MSCV2_RESPONSE)
          - ACHL_PAR_RATTR_0;
   ADSL_PAR_AR1->boc_send_nas_ineta = TRUE;  /* send NAS IP Address    */
   adsl_par_w1->imc_len_data                /* length of the data      */
     = ((char *) ACHL_PAR_AVSMS_CHRE + sizeof(ucrs_send_avp_ms_01) + 2 + 2 + LEN_MSCV2_RESPONSE)
          - ((char *) ADSL_PAR_RC1);
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = ADSL_PAR_RC1;  /* for Radius authentication */
   m_radius_init( ADSL_PAR_RC1,
                  adsl_conn1_l->adsc_radius_group,  /* active Radius group */
                  adsl_conn1_l,             /* current connection      */
#ifndef HL_UNIX
                  (struct sockaddr *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                  (struct sockaddr *) &adsl_conn1_l->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                  &m_ppp_auth_radius_compl );
   bol1 = m_radius_request( ADSL_PAR_RC1, ADSL_PAR_AR1 );
   if (bol1 == FALSE) {                     /* returned error          */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing CHAP response - m_radius_request() failed" );
   }
   return;                                  /* wait for Radius completition */

   p_mscv2_20:                              /* MS-CHAP-V2 change password */
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + ((ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 2 + LEN_MSCV2_CHALLENGE)
                      + (sizeof(ucrs_send_avp_ms_01) + 2 + 2 + 0X42)
                      + (LEN_AVSMS_NEW_PWD + 4)
                  - ((char *) ADSL_PAR_RC1)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 23" );
     return;
   }
   /* first LEN_AVSMS_NEW_PWD + 4 new password                         */
   /* second 0X42 ???                                                  */
#define ACHL_PAR_RATTR_1 (ACHL_PAR_RATTR_0 + sizeof(ucrs_send_avp_ms_01) + 2 + LEN_MSCV2_CHALLENGE)
   memcpy( ACHL_PAR_RATTR_1, ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
   *(ACHL_PAR_RATTR_1 + 1) = (unsigned char) (sizeof(ucrs_send_avp_ms_01) + 2 + 2 + 0X42);  /* set length */
   *(ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 0) = (unsigned char) 0X1B;  /* 27 for MS-CHAP2-PW */
   *(ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 1)
      = (unsigned char) (2 + 2 + 0X42);     /* length this part        */
   *(ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 2 + 0) = (unsigned char) 7;  /* Code 7 */
// *(ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 2 + 1) = adsp_rctrl1->chc_identifier;  /* identifier used */
// ADSL_PAR_AR1->achc_identifier            /* set identifier here     */
//   = ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 2 + 1;
   ADSL_PAR_AR1->imrc_pos_identifier[ 0 ]
     = (ACHL_PAR_RATTR_1 - ACHL_PAR_RATTR_0) + sizeof(ucrs_send_avp_ms_01) + 2 + 1;
   iml_id = 1;                              /* count array identifier  */
   memcpy( ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 2 + 2,
           (char *) (adsl_par_mscv2_change_pwd + 1) + LEN_AVSMS_NEW_PWD + 4,
           0X42 );
#define ACHL_PAR_RATTR_2 (ACHL_PAR_RATTR_1 + sizeof(ucrs_send_avp_ms_01) + 2 + 2 + 0X42)  /* Radius attributes */
   achl1 = ACHL_PAR_RATTR_2;                /* start of Radius attributes */
   iml1 = 0;                                /* clear displacement      */
   iml2 = 0;                                /* clear sequence number   */
   do {                                     /* loop to copy array      */
     iml3 = (LEN_AVSMS_NEW_PWD + 4) - iml1;  /* length remaining       */
     if (iml3 > (0X00FF - sizeof(ucrs_send_avp_ms_01) - 2 - 4)) {
       iml3 = 0X00FF - sizeof(ucrs_send_avp_ms_01) - 2 - 4;
     }
     achl2 = achl1;                         /* save start of attribute */
     memcpy( achl1, ucrs_send_avp_ms_01, sizeof(ucrs_send_avp_ms_01) );
     achl1 += sizeof(ucrs_send_avp_ms_01);
     *achl1++ = (unsigned char) 6;          /* 6 for MS-CHAP-NT-Enc-PW */
     *achl1++ = (unsigned char) ((iml3 + 2 + 4) & 0XFF);  /* vendor-length */
     *achl1++ = (unsigned char) 6;          /* Code is the same as for the MS-CHAP-PW-2 attribute */
//   *achl1++ = adsp_rctrl1->chc_identifier;  /* identifier used */
     ADSL_PAR_AR1->imrc_pos_identifier[ iml_id ] = achl1 - ACHL_PAR_RATTR_0;
     iml_id++;                              /* count array identifier  */
     achl1++;                               /* space for identifier used */
     iml2++;                                /* increment sequence number */
     *achl1++ = (unsigned char) ((iml2 >> 8) & 0XFF);  /* sequence number big endian */
     *achl1++ = (unsigned char) (iml2 & 0XFF);  /* sequence number big endian */
     memcpy( achl1, (char *) (adsl_par_mscv2_change_pwd + 1) + iml1, iml3 );  /* copy part */
     achl1 += iml3;                         /* increment output        */
     iml1 += iml3;                          /* increment input         */
     *(achl2 + 1) = (unsigned char) (achl1 - achl2);  /* length attribute vendor-specific MS MS-CHAP-NT-Enc-PW */
   } while (iml1 < (LEN_AVSMS_NEW_PWD + 4));
   ADSL_PAR_AR1->achc_attr_out = ACHL_PAR_RATTR_0;  /* attributes output */
   ADSL_PAR_AR1->imc_len_attr_out           /* length attributes outp  */
     = achl1 - ACHL_PAR_RATTR_0;
   ADSL_PAR_AR1->boc_send_nas_ineta = TRUE;  /* send NAS IP Address    */
   adsl_par_w1->imc_len_data                /* length of the data      */
     = achl1 - ((char *) ADSL_PAR_RC1);
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = ADSL_PAR_RC1;  /* for Radius authentication */
   m_radius_init( ADSL_PAR_RC1,
                  adsl_conn1_l->adsc_radius_group,  /* active Radius group */
                  adsl_conn1_l,             /* current connection      */
#ifndef HL_UNIX
                  (struct sockaddr *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                  (struct sockaddr *) &adsl_conn1_l->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                  &m_ppp_auth_radius_compl );
   bol1 = m_radius_request( ADSL_PAR_RC1, ADSL_PAR_AR1 );
   if (bol1 == FALSE) {                     /* returned error          */
     adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = NULL;  /* no Radius authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing CHAP response - m_radius_request() failed" );
   }
   return;                                  /* wait for Radius completition */

#undef ADSL_PAR_RC1
#undef ADSL_PAR_APS1
#undef ADSL_PAR_AR1
#undef ACHL_PAR_RATTR_0
#undef ACHL_PAR_RATTR_1
#undef ACHL_PAR_RATTR_2

   p_mscv2_60:                              /* MS-CHAP-V2 not Radius   */
#ifdef TRY_140509_01
   iel_chs_auth = ied_chs_ansi_819;         /* character set string - ANSI 819 */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
         == ied_pppa_eap) {                 /* EAP                     */
     iel_chs_auth = ied_chs_utf_8;          /* Unicode UTF-8           */
   }
#endif
   dsl_us_userid.ac_str = adsl_par_userid + 1;  /* address of string   */
   dsl_us_userid.imc_len_str = adsl_par_userid->imc_len_data;  /* length string in elements */
#ifndef TRY_140509_01
   dsl_us_userid.iec_chs_str = ied_chs_ansi_819;  /* character set string - ANSI 819 */
#else
   dsl_us_userid.iec_chs_str = iel_chs_auth;  /* character set authentication */
#endif
   iel_chid_ret = m_auth_user( &adsl_usent, NULL, adsl_conn1_l,
                               &dsl_us_userid, NULL,
                               FALSE, FALSE );
   if (iel_chid_ret != ied_chid_ok) {       /* not userid and password valid */
     goto p_mscv2_80;                       /* MS-CHAP-V2 not Radius failure */
   }
   achl2 = (char *) (adsl_par_mscv2_response + 1);  /* here is MS-CHAP-V2 response */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
         == ied_pppa_eap) {                 /* EAP                     */
     if (adsl_par_mscv2_challenge == NULL) {
       adsl_par_w1 = (struct dsd_ppp_auth_record *)
                       ((long long int) (achl1 + sizeof(void *) - 1)
                          & (0 - sizeof(void *)));
       goto p_gen_chal_00;                  /* generate challenge for MS-CHAP-V2 */
     }
     if (adsl_par_recv_new == NULL) {       /* no new data received    */
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 01" );
       return;
     }
#define ACHL_PAR_EAP ((char *) (adsl_par_recv_new + 1))
     if (*(ACHL_PAR_EAP + 0) != 2) {        /* not Code: Response      */
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 02" );
       return;
     }
     if (adsp_ppp_se_1->adsc_ppp_auth_header->imc_state != 0) {  /* state of processing */
       goto p_eap_end_00;                   /* end of EAP processing   */
     }
     if (adsl_par_recv_new->imc_len_data != (59 + adsl_par_userid->imc_len_data)) {
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 03" );
       return;
     }
     if (*(ACHL_PAR_EAP + 4) != DEF_PPP_EAP_MS_AUTH) {
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 04" );
       return;
     }
     if (*(ACHL_PAR_EAP + 59 - 1) != 0) {
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - MS-CHAP-V2 response not zero" );
       return;
     }
     if (memcmp( ACHL_PAR_EAP + 59,
                 adsl_par_userid + 1,
                 adsl_par_userid->imc_len_data )) {
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - userid invalid" );
       return;
     }
     achl2 = ACHL_PAR_EAP + 10;             /* here is MS-CHAP-V2 response */
#undef ACHL_PAR_EAP
     iel_chid_ret = ied_chid_cont;          /* not yet complete, continue processing */
   }
   /* generate ChallengeHash                                           */
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, (char *) achl2, 0, 16 );
   SHA1_Update( imrl_sha1_array, (char *) (adsl_par_mscv2_challenge + 1) + 1, 0, LEN_MSCV2_CHALLENGE );
   SHA1_Update( imrl_sha1_array, (char *) (adsl_par_userid + 1), 0, adsl_par_userid->imc_len_data );
   SHA1_Final( imrl_sha1_array, chrl_work2, 0 );
   /* generate NtPasswordHash                                          */
#ifdef B140512
#ifndef TRY_140509_01
   iml1 = m_cpy_vx_vx( chrl_work1,
                       sizeof(chrl_work1) / sizeof(HL_WCHAR),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (char *) (adsl_usent + 1) + adsl_usent->inc_len_name_bytes,
                       adsl_usent->inc_len_password_bytes,
                       ied_chs_utf_8 )      /* Unicode UTF-8           */
            * sizeof(HL_WCHAR);
#else
   iml1 = m_cpy_vx_vx( chrl_work1,
                       sizeof(chrl_work1) / sizeof(HL_WCHAR),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (char *) (adsl_usent + 1) + adsl_usent->inc_len_name_bytes,
                       adsl_usent->inc_len_password_bytes,
                       iel_chs_auth )       /* character set authentication */
            * sizeof(HL_WCHAR);
#endif
#endif
   iml1 = m_cpy_vx_vx( chrl_work1,
                       sizeof(chrl_work1) / sizeof(HL_WCHAR),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (char *) (adsl_usent + 1) + adsl_usent->inc_len_name_bytes,
                       adsl_usent->inc_len_password_bytes,
                       ied_chs_utf_8 )      /* Unicode UTF-8           */
            * sizeof(HL_WCHAR);
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, chrl_work1, 0, iml1 );
   MD4_Final( imrl_md4_array, chrl_work1, 0 );
#ifdef TRACEHL1
// m_console_out( chrl_work1, MD4_DIGEST_LEN );
#endif
   memset( chrl_work1 + MD4_DIGEST_LEN, 0, 21 - MD4_DIGEST_LEN );
   /* do DesEncrypt                                                    */
   iml1 = 3;
// ill1 = 0;                                /* for compiler only       */
#ifdef _DEBUG
   ill1 = 0;                                /* for compiler only       */
#endif
   iml2 = 0;                                /* index in chrl_work1 = ZPasswordHash */
   do {
     iml3 = 7;
     do {
       ill1 <<= 8;
       ill1 |= (unsigned char) chrl_work1[ iml2++ ];
       iml3--;                              /* decrement index         */
     } while (iml3 > 0);
     iml3 = 8;
     ill1 <<= 1;                            /* we need also last bit   */
     do {
       iml3--;                              /* decrement index         */
       ucrl_work5[ iml3 ] = ill1 & 0XFE;
       ill1 >>= 7;
     } while (iml3 > 0);
     GenDESSubKeys( ucrl_work5, umrl_des_subkeytab );
     DES_ecb_encrypt_decrypt( (unsigned char *) chrl_work2,
                              (unsigned char *) chrl_work3 + (3 - iml1) * 8,
                              umrl_des_subkeytab,
                              1,
                              DES_ENCRYPT );
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   iml1 = memcmp( chrl_work3, achl2 + 16 + 8, 24 );
   if (iml1) {                              /* authentication failed   */
     goto p_mscv2_80;                       /* MS-CHAP-V2 not Radius failure */
   }
   adsp_ppp_se_1->adsc_ppp_auth_header->imc_state = DEF_EAP_SUCCESS;  /* state of processing - successfull */

   /* GenerateAuthenticatorResponse                            */
   /* HashNtPasswordHash( PasswordHash, giving PasswordHashHash) */
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, chrl_work1, 0, MD4_DIGEST_LEN );
   MD4_Final( imrl_md4_array, chrl_pwd_hashhash, 0 );
#ifdef TRACEHL1
// System.out.println( "after MD4" );
// m_console_out( chrl_work4, 0, %int:MD4_DIGEST_LEN; );  /* show on console */
#endif
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, chrl_pwd_hashhash, 0, MD4_DIGEST_LEN );
   SHA1_Update( imrl_sha1_array, chrl_work3, 0, 24 );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mscv2_magic1, 0, sizeof(ucrs_mscv2_magic1) );
   SHA1_Final( imrl_sha1_array, chrl_work4, 0 );
#ifdef TRACEHL1
// System.out.println( "after SHA1-1" );
// m_console_out( chrl_work4, 0, SHA_DIGEST_LEN );  /* show on console */
#endif
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, chrl_work4, 0, SHA_DIGEST_LEN );
   SHA1_Update( imrl_sha1_array, chrl_work2, 0, 8 );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mscv2_magic2, 0, sizeof(ucrs_mscv2_magic2) );
   SHA1_Final( imrl_sha1_array, chrl_work4, 0 );
#ifdef TRACEHL1
// m_console_out( chrl_work4, 0, SHA_DIGEST_LEN );  /* show on console */
#endif
   if (   (adsl_conn1_l->adsc_server_conf_1 == NULL)
       || (adsl_conn1_l->adsc_server_conf_1->iec_scp_def != ied_scp_sstp)) {  /* not protocol SSTP */
     goto p_mscv2_68;                       /* MS-CHAP-V2 channel binding done */
   }
/**
  we need to pass the MPPE keys for SSTP channel binding
  so that it can be checked later
*/
   adsl_auxf_1_hlak = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + LEN_HLAK );  /* auxiliary extension field - HLAK */
   memset( adsl_auxf_1_hlak, 0, sizeof(struct dsd_auxf_1) );
   adsl_auxf_1_hlak->iec_auxf_def = ied_auxf_mppe_keys;  /* SSTP - HLAK */
#ifndef HL_UNIX
   EnterCriticalSection( &adsl_conn1_l->d_act_critsect );  /* critical section act */
#else
   adsl_conn1_l->dsc_critsect.m_enter();    /* critical section        */
#endif
   adsl_auxf_1_hlak->adsc_next = adsl_conn1_l->adsc_auxf_1;  /* get old chain auxiliary ext fields */
   adsl_conn1_l->adsc_auxf_1 = adsl_auxf_1_hlak;  /* set new chain auxiliary ext fields */
#ifndef HL_UNIX
   LeaveCriticalSection( &adsl_conn1_l->d_act_critsect );  /* critical section act */
#else
   adsl_conn1_l->dsc_critsect.m_leave();    /* critical section        */
#endif
   /* Generate the master session key.                                 */
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, chrl_pwd_hashhash, 0, MD4_DIGEST_LEN );
   SHA1_Update( imrl_sha1_array, chrl_work3, 0, 24);
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_magic1, 0, sizeof(ucrs_mppe_magic1) );
   SHA1_Final( imrl_sha1_array, chrl_masterkey, 0 );

   /* Generate the master receive key.                                 */
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, chrl_masterkey, 0, 16 );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_shspad1, 0, sizeof(ucrs_mppe_shspad1) );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_magic2, 0, sizeof(ucrs_mppe_magic2) );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_shspad2, 0, sizeof(ucrs_mppe_shspad2) );
   SHA1_Final( imrl_sha1_array, (char *) (adsl_auxf_1_hlak + 1), 0 );

   /* Generate the master send key. */
   SHA1_Init( imrl_sha1_array );
   SHA1_Update( imrl_sha1_array, chrl_masterkey, 0, 16 );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_shspad1, 0, sizeof(ucrs_mppe_shspad1) );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_magic3, 0, sizeof(ucrs_mppe_magic3) );
   SHA1_Update( imrl_sha1_array, (char *) ucrs_mppe_shspad2, 0, sizeof(ucrs_mppe_shspad2) );
   /* chrl_masterkey can be overwritten here, no more needed           */
   SHA1_Final( imrl_sha1_array, chrl_masterkey, 0 );
   memcpy( (char *) (adsl_auxf_1_hlak + 1) + 16, chrl_masterkey, 16 );

   p_mscv2_68:                              /* MS-CHAP-V2 channel binding done */
   /* pass record with MS-CHAP-V2 success                              */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl1 + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + (9 + 2 + SHA_DIGEST_LEN * 2))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 24" );
     return;
   }
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_success;  /* type of authentication record - MS-CHAP-V2 success */
   adsl_par_w1->imc_len_data = 2 + SHA_DIGEST_LEN * 2;  /* length of the data */
   achl1 = (char *) (adsl_par_w1 + 1);      /* pass MS-CHAP-V2 success here */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
         == ied_pppa_eap) {                 /* EAP                     */
     adsl_par_w1->iec_par = ied_par_eap_send_1;  /* EAP to send        */
     adsl_par_w1->imc_len_data = 9 + 2 + SHA_DIGEST_LEN * 2;  /* length of the data */
#define ABYL_PAR_DATA ((char *) (adsl_par_w1 + 1))
     *(ABYL_PAR_DATA + 4 + 2) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent old identification LCP configure */
     *(ABYL_PAR_DATA + 0) = (unsigned char) 1;  /* Code: Request       */
     adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
     *(ABYL_PAR_DATA + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
     *(ABYL_PAR_DATA + 2 + 0) = 0;
     *(ABYL_PAR_DATA + 2 + 1) = (unsigned char) (9 + 2 + SHA_DIGEST_LEN * 2);
     *(ABYL_PAR_DATA + 4 + 0) = (unsigned char) DEF_PPP_EAP_MS_AUTH;
     *(ABYL_PAR_DATA + 4 + 1) = (unsigned char) 3;  /* opcode success  */
     *(ABYL_PAR_DATA + 4 + 3 + 0) = 0;
     *(ABYL_PAR_DATA + 4 + 3 + 1) = (unsigned char) (4 + 2 + SHA_DIGEST_LEN * 2);
#undef ABYL_PAR_DATA
     achl1 = (char *) (adsl_par_w1 + 1) + 9;  /* pass MS-CHAP-V2 success here */
   }
   *achl1++ = 'S';
   *achl1++ = '=';
   achl2 = chrl_work4;                      /* start input             */
   iml1 = SHA_DIGEST_LEN;                   /* set length              */
   do {                                     /* loop to translate to ASCII */
     iml2 = (unsigned char) *achl2++;       /* get input               */
     *achl1++ = chrstrans[ iml2 >> 4 ];
     *achl1++ = chrstrans[ iml2 & 0X0F ];
     iml1--;                                /* decrement length        */
   } while (iml1 > 0);
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   m_ppp_se_auth_ret( adsp_ppp_se_1, iel_chid_ret );  /* authentication is valid - or continue */
   return;

   p_mscv2_80:                              /* MS-CHAP-V2 not Radius failure */
   /* create new challenge                                             */
#ifdef XYZ1
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   if (   (adsl_par_w1 == NULL)
       || (adsl_par_w1->iec_par != ied_par_mscv2_challenge)) {  /* MS-CHAP-V2 challenge */
// to-do 09.05.12 KB va-list - add __LINE__
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 04" );
     return;
   }
#endif
   if (adsl_par_mscv2_challenge == NULL) {
     if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
           == ied_pppa_eap) {               /* EAP                     */
       m_ppp_se_auth_ret( adsp_ppp_se_1, ied_chid_inv_password );  /* authentication is not valid */
       return;
     }
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 04" );
     return;
   }
   achl2 = (char *) (adsl_par_mscv2_challenge + 1) + 1;  /* here starts challenge */
   iml1 = LEN_MSCV2_CHALLENGE - 1;          /* length of challenge minus one */
// to-do 14.03.14 KB - use secure random
   do {                                     /* loop to fill challenge  */
     *(achl2 + iml1) = (unsigned char) m_get_random_number( 0X0100 );
     iml1--;                                /* decrement index         */
   } while (iml1 >= 0);
   /* pass record with MS-CHAP-V2 failure                              */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl1 + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + (5 + sizeof(ucrs_mscv2_failed_p1) + LEN_MSCV2_CHALLENGE * 2 + sizeof(ucrs_mscv2_failed_p2)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 25" );
     return;
   }
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_failure;  /* MS-CHAP-V2 failure */
   adsl_par_w1->imc_len_data
     = sizeof(ucrs_mscv2_failed_p1) + LEN_MSCV2_CHALLENGE * 2 + sizeof(ucrs_mscv2_failed_p2);
   achl1 = (char *) (adsl_par_w1 + 1);      /* pass MS-CHAP-V2 failure here */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
         == ied_pppa_eap) {                 /* EAP                     */
#ifdef XYZ1
     adsp_ppp_se_1->adsc_ppp_auth_header->imc_state = DEF_EAP_FAILURE;  /* state of processing - failure */
#endif
     adsl_par_w1->iec_par = ied_par_eap_send_1;  /* EAP to send        */
     adsl_par_w1->imc_len_data = 5 + sizeof(ucrs_mscv2_failed_p1) + LEN_MSCV2_CHALLENGE * 2 + sizeof(ucrs_mscv2_failed_p2);  /* length of the data */
#define ABYL_PAR_DATA ((char *) (adsl_par_w1 + 1))
#ifdef XYZ1
     *(ABYL_PAR_DATA + 4 + 2) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent old identification LCP configure */
#endif
     *(ABYL_PAR_DATA + 0) = (unsigned char) 1;  /* Code: Request       */
     adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
     *(ABYL_PAR_DATA + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
     *(ABYL_PAR_DATA + 2 + 0) = 0;
     *(ABYL_PAR_DATA + 2 + 1) = (unsigned char) (5 + sizeof(ucrs_mscv2_failed_p1) + LEN_MSCV2_CHALLENGE * 2 + sizeof(ucrs_mscv2_failed_p2));
     *(ABYL_PAR_DATA + 4 + 0) = (unsigned char) DEF_PPP_EAP_MS_AUTH;
#undef ABYL_PAR_DATA
     achl1 = (char *) (adsl_par_w1 + 1) + 5;  /* pass MS-CHAP-V2 failure here */
   }
   memcpy( achl1, ucrs_mscv2_failed_p1, sizeof(ucrs_mscv2_failed_p1) );
   *(achl1 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf - 1;  /* sent identification LCP configure minus one */
   achl1 += sizeof(ucrs_mscv2_failed_p1);   /* start output            */
   /* achl2 already set                                                */
   iml1 = LEN_MSCV2_CHALLENGE;              /* length of challenge     */
   do {                                     /* loop to translate to ASCII */
     iml2 = (unsigned char) *achl2++;       /* get input               */
     *achl1++ = chrstrans[ iml2 >> 4 ];
     *achl1++ = chrstrans[ iml2 & 0X0F ];
     iml1--;                                /* decrement length        */
   } while (iml1 > 0);
   memcpy( achl1,
           ucrs_mscv2_failed_p2,
           sizeof(ucrs_mscv2_failed_p2) );
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
// to-do 09.05.12 KB - other enum value
   m_ppp_se_auth_ret( adsp_ppp_se_1, ied_chid_inv_password );  /* authentication is not valid */
   return;

   p_eap_end_00:                            /* end of EAP processing   */
   if (adsl_par_recv_new->imc_len_data != (4 + 2)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 05" );
     return;
   }
#define ACHL_PAR_EAP ((char *) (adsl_par_recv_new + 1))
   if (*(ACHL_PAR_EAP + 4) != DEF_PPP_EAP_MS_AUTH) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 06" );
     return;
   }
   if (*(ACHL_PAR_EAP + 4 + 1) != 3) {      /* not Opcode: Success     */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing EAP response - illogic 07" );
     return;
   }
#undef ACHL_PAR_EAP
   m_ppp_se_auth_ret( adsp_ppp_se_1, ied_chid_ok );  /* userid and password valid */
   return;                                  /* all done                */

   p_gen_chal_00:                           /* generate challenge for MS-CHAP-V2 */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_challenge;  /* type of authentication record - MS-CHAP-V2 challenge */
   adsl_par_w1->imc_len_data = 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident);  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_w1 + 1))
   AUCL_PAR_DATA[ 0 ] = LEN_MSCV2_CHALLENGE;  /* length MS-CHAP-V2 challenge */
// to-do 14.03.14 KB - use secure random
   iml1 = LEN_MSCV2_CHALLENGE;              /* length MS-CHAP-V2 challenge */
   do {                                     /* loop to fill challenge  */
     AUCL_PAR_DATA[ iml1 ] = (unsigned char) m_get_random_number( 0X0100 );
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   memcpy( AUCL_PAR_DATA + 1 + LEN_MSCV2_CHALLENGE, ucrs_wsp_ident, sizeof(ucrs_wsp_ident) );
#undef AUCL_PAR_DATA
   if (adsl_par_last == NULL) {             /* is first in chain       */
     adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_w1;  /* chain of records in storage for authentication */
   } else {                                 /* append to chain         */
     adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain       */
   }
//#ifdef XYZ1
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth  /* authentication-method in use */
         != ied_pppa_eap) {                 /* EAP                     */
     return;
   }
   /* build EAP message to be sent                                     */
#define ABYL_PAR_END_DATA ((char *) (adsl_par_w1 + 1) + 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident))
   adsl_par_eap_send = (struct dsd_ppp_auth_record *)
                         ((long long int) (ABYL_PAR_END_DATA + sizeof(void *) - 1)
                            & (0 - sizeof(void *)));
#undef ABYL_PAR_END_DATA
   if (((char *) adsl_par_eap_send + sizeof(struct dsd_ppp_auth_record)
             + (9 + 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 26" );
     return;
   }
   adsl_par_eap_send->adsc_next = NULL;     /* clear chain             */
   adsl_par_eap_send->iec_par = ied_par_eap_send_1;  /* EAP to send    */
   adsl_par_eap_send->imc_len_data
     = 9 + 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident);
#define ABYL_PAR_DATA ((char *) (adsl_par_eap_send + 1))
   *(ABYL_PAR_DATA + 0) = (unsigned char) 1;  /* Code: Request         */
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   *(ABYL_PAR_DATA + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   iml1 = 9 + 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident);
   *(ABYL_PAR_DATA + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(ABYL_PAR_DATA + 2 + 1) = (unsigned char) iml1;
   *(ABYL_PAR_DATA + 4 + 0) = (unsigned char) DEF_PPP_EAP_MS_AUTH;
   *(ABYL_PAR_DATA + 4 + 1) = (unsigned char) 1;  /* opcode challenge  */
   *(ABYL_PAR_DATA + 4 + 2) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   iml1 -= 5;
   *(ABYL_PAR_DATA + 4 + 3 + 0) = (unsigned char) (iml1 >> 8);
   *(ABYL_PAR_DATA + 4 + 3 + 1) = (unsigned char) iml1;
   memcpy( ABYL_PAR_DATA + 9, adsl_par_w1 + 1, 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident) );
#undef ABYL_PAR_DATA
   adsl_par_w1->adsc_next = adsl_par_eap_send;  /* append to chain     */
   m_ppp_se_auth_ret( adsp_ppp_se_1, ied_chid_cont );  /* not yet complete, continue processing */
//#endif
   return;                                  /* send challenge to client */

   p_pap_00:                                /* check PAP               */
#ifndef B131115
   adsl_par_userid = NULL;                  /* record in storage for authentication */
   adsl_par_pap_password = NULL;            /* record in storage for authentication */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   achl1 = (char *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* end of storage used */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_userid:                 /* userid                  */
         adsl_par_userid = adsl_par_w1;     /* record in storage for authentication */
         break;
       case ied_par_password:               /* password                */
         adsl_par_pap_password = adsl_par_w1;  /* record in storage for authentication */
         break;
     }
     achl2 = (char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data;  /* end of this record */
     if (achl2 > achl1) achl1 = achl2;      /* in use till here        */
     adsl_par_last = adsl_par_w1;           /* save last in chain      */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (   (adsl_par_userid == NULL)
       || (adsl_par_pap_password == NULL)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing PAP response - illogic 01" );
     return;
   }
#endif
#ifndef B101110
   /* for HOB-PPP-T1 no authentication is required, this is already done in the WSP-socks-mode */
   if (   (adsl_conn1_l->adsc_server_conf_1)  /* configuration server    */
       && (adsl_conn1_l->adsc_server_conf_1->iec_scp_def == ied_scp_hpppt1)) {  /* protocol HOB-PPP-T1 */
     m_ppp_se_auth_ret( adsp_ppp_se_1, ied_chid_ok );  /* userid and password valid */
     return;
   }
#endif
#ifdef OLD_1112
   if (adsl_conn1_l->adsc_gate1->inc_no_radius) {  /* Radius configured  */
     goto p_rad_00;                         /* process Radius          */
   }
#endif
   if (adsl_conn1_l->adsc_radius_group) {   /* active Radius group     */
     goto p_rad_00;                         /* process Radius          */
   }
   if (adsl_conn1_l->adsc_gate1->inc_no_usgro) {  /* User Groups configured */
     goto p_usgro_00;                       /* process User Groups     */
   }
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "no authentication parameters in WSP configuration" );
   return;

   p_rad_00:                                /* process Radius          */
   /* prepare Radius request                                           */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl1 + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   if (((char *) adsl_par_w1 + sizeof(struct dsd_ppp_auth_record)
             + (sizeof(struct dsd_hl_aux_radius_1) + sizeof(void *)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 27" );
     return;
   }
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_aux;      /* type of authentication record - auxiliary record */
#define ADSL_PAR_RC1 ((struct dsd_radius_control_1 *) (adsl_par_w1 + 1))
#define ADSL_PAR_APS1 ((void **) (ADSL_PAR_RC1 + 1))
#define ADSL_PAR_AR1 ((struct dsd_hl_aux_radius_1 *) (ADSL_PAR_APS1 + 1))
   *ADSL_PAR_APS1 = adsp_ppp_se_1->adsc_ppp_auth_header;  /* save address of storage for authentication */
   memset( ADSL_PAR_AR1, 0, sizeof(struct dsd_hl_aux_radius_1) );
   ADSL_PAR_AR1->dsc_ucs_userid.ac_str = (adsl_par_userid + 1);  /* address of userid */
   ADSL_PAR_AR1->dsc_ucs_userid.imc_len_str = adsl_par_userid->imc_len_data;  /* length userid in elements / bytes */
   ADSL_PAR_AR1->dsc_ucs_userid.iec_chs_str = ied_chs_ansi_819;  /* character set userid / ANSI 819 */
   ADSL_PAR_AR1->dsc_ucs_password.ac_str = (adsl_par_pap_password + 1);  /* address of password */
   ADSL_PAR_AR1->dsc_ucs_password.imc_len_str = adsl_par_pap_password->imc_len_data;  /* length password in elements / bytes */
   ADSL_PAR_AR1->dsc_ucs_password.iec_chs_str = ied_chs_ansi_819;  /* character set password / ANSI 819 */
   ADSL_PAR_AR1->boc_send_nas_ineta = TRUE;  /* send NAS IP Address    */
   adsl_par_w1->imc_len_data                /* length of the data      */
     = sizeof(struct dsd_hl_aux_radius_1) + sizeof(void *);
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain         */
   adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = ADSL_PAR_RC1;  /* for Radius authentication */
   m_radius_init( ADSL_PAR_RC1,
                  adsl_conn1_l->adsc_radius_group,  /* active Radius group */
                  adsl_conn1_l,             /* current connection      */
#ifndef HL_UNIX
                  (struct sockaddr *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa,  /* address information session with client */
#else
                  (struct sockaddr *) &adsl_conn1_l->dsc_tc1_client.dsc_soa_conn,  /* address information session with client */
#endif
                  &m_ppp_auth_radius_compl );
   bol1 = m_radius_request( ADSL_PAR_RC1, ADSL_PAR_AR1 );
   if (bol1 == FALSE) {                     /* returned error          */
     adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius = NULL;  /* no Radius authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "processing CHAP response - m_radius_request() failed" );
   }
   return;                                  /* wait for Radius completition */
#ifdef XYZ1
#ifdef B120505
#define ADSC_RADQU_G ((class dsd_radius_query *) adsp_ppp_se_1->vpc_radius)
   if (ADSC_RADQU_G) goto p_rad_20;         /* Radius class exists     */
   inl_len_cert = 0;                        /* no certificate yet      */
   adsl_auxf_1_w1 = adsl_conn1_l->adsc_auxf_1;  /* get anchor auxiliary fields */
   while (adsl_auxf_1_w1) {
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certificate) {
       inl_len_cert = *((int *) (adsl_auxf_1_w1 + 1));
       break;
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
#ifdef OLD_1112
#ifndef HL_UNIX
   avol_client_netaddr = (void *) &adsl_conn1_l->dcl_tcp_r_c.dsc_soa;
#else
   avol_client_netaddr = (void *) &adsl_conn1_l->dsc_un_sa_client;
#endif
   iel_claddrtype = en_atca_IPV4;
   if (((struct sockaddr_in *) avol_client_netaddr)->sin_family == AF_INET6) {
     iel_claddrtype = en_atca_IPV6;
   }
#endif
#ifdef XYZ1
   ADSC_RADQU_G = new dsd_radius_query( adsl_conn1_l,
                                        adsl_conn1_l->adsc_gate1->inc_no_radius,
                                        adsl_conn1_l->adsc_gate1->inc_no_usgro,
                                        (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                        inl_len_cert,
                                        &(adsl_conn1_l->adsc_gate1->dsc_radius_conf),
                                        iel_claddrtype,
                                        avol_client_netaddr );
#endif
#ifdef OLD_1112
   adsp_ppp_se_1->vpc_radius = new dsd_radius_query( adsl_conn1_l,
                                        adsl_conn1_l->adsc_gate1->inc_no_radius,
                                        adsl_conn1_l->adsc_gate1->inc_no_usgro,
                                        (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                        inl_len_cert,
                                        &(adsl_conn1_l->adsc_gate1->dsc_radius_conf),
                                        iel_claddrtype,
                                        avol_client_netaddr );
   ADSC_RADQU_G->mc_set_ret_cb( adsp_ppp_se_1, &m_radqu_ret_callback );
#endif
#endif

   p_rad_20:                                /* Radius class exists     */
#ifdef B120505
#define ADSC_AUTH_1 adsp_ppp_se_1->adsc_ppp_auth_1
   dsl_us_userid.ac_str = ADSC_AUTH_1 + 1;  /* address of string       */
   dsl_us_userid.imc_len_str = ADSC_AUTH_1->imc_len_userid;  /* length string in elements */
   dsl_us_userid.iec_chs_str = ADSC_AUTH_1->iec_chs_auth;  /* character set string */
   dsl_us_password.ac_str = (char *) (ADSC_AUTH_1 + 1) + ADSC_AUTH_1->imc_len_userid;  /* address of string */
   dsl_us_password.imc_len_str = ADSC_AUTH_1->imc_len_password;  /* length string in elements */
   dsl_us_password.iec_chs_str = ADSC_AUTH_1->iec_chs_auth;  /* character set string */
#ifdef OLD_1112
   ADSC_RADQU_G->m_set_credentials( &dsl_us_userid, &dsl_us_password );
   ADSC_RADQU_G->mc_send_timer();
#endif
   return;
#undef ADSC_RADQU_G
#undef ADSC_AUTH_1
#endif
#endif

   p_usgro_00:                              /* process User Groups     */
#ifdef B120505
#define ADSC_AUTH_1 adsp_ppp_se_1->adsc_ppp_auth_1
   dsl_us_userid.ac_str = ADSC_AUTH_1 + 1;  /* address of string       */
   dsl_us_userid.imc_len_str = ADSC_AUTH_1->imc_len_userid;  /* length string in elements */
   dsl_us_userid.iec_chs_str = ADSC_AUTH_1->iec_chs_auth;  /* character set string */
   dsl_us_password.ac_str = (char *) (ADSC_AUTH_1 + 1) + ADSC_AUTH_1->imc_len_userid;  /* address of string */
   dsl_us_password.imc_len_str = ADSC_AUTH_1->imc_len_password;  /* length string in elements */
   dsl_us_password.iec_chs_str = ADSC_AUTH_1->iec_chs_auth;  /* character set string */
#undef ADSC_AUTH_1
   iel_chid_ret = m_auth_user( NULL, NULL, adsl_conn1_l,
                               &dsl_us_userid, &dsl_us_password,
                               TRUE, FALSE );
   m_ppp_se_auth_ret( adsp_ppp_se_1, iel_chid_ret );
#endif
#ifndef B131115
   dsl_us_userid.ac_str = adsl_par_userid + 1;  /* address of string */
   dsl_us_userid.imc_len_str = adsl_par_userid->imc_len_data;  /* length string in elements */
   dsl_us_userid.iec_chs_str = ied_chs_ansi_819;  /* character set string - ANSI 819 */
   dsl_us_password.ac_str = adsl_par_pap_password + 1;  /* address of string */
   dsl_us_password.imc_len_str = adsl_par_pap_password->imc_len_data;  /* length string in elements */
   dsl_us_password.iec_chs_str = ied_chs_ansi_819;  /* character set string - ANSI 819 */
   iel_chid_ret = m_auth_user( NULL, NULL, adsl_conn1_l,
                               &dsl_us_userid, &dsl_us_password,
                               TRUE, FALSE );
   m_ppp_se_auth_ret( adsp_ppp_se_1, iel_chid_ret );
#endif
   return;
#undef DEF_EAP_SUCCESS
#undef DEF_EAP_FAILURE
} /* end m_ppp_auth_1()                                                */

/** do authentication for PPP client                                   */
extern "C" void m_ppp_auth_2( struct dsd_ppp_client_1 *adsp_ppp_cl_1,
                              enum ied_ppp_auth_def iep_pppa ) {
/**
  which strategie should we use?
  maybe in the WSP-XML-file <L2TP-gateway>
    <authenticate-use-userid>
  and optionally
    <authenticate-use-password>
  are configured, then these are used.
  when with the client PAP is used,
  the userid and password of the client may be used.
  when MS-CHAP-V2 is used against <user-entry>,
  then these credential are used.
  When MS-CHAP-V2 is done with the client
  and this is authenticated against Radius,
  no man-in-the-middle is possible,
  so we have no password.
  We could try to authenticate only with the userid.
  06.05.12  KB
*/
   int        iml1;                         /* working variable        */
#ifdef XYZ1
   int        iml1, iml2, iml3;             /* working variables       */
   HL_LONGLONG ill1;                        /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
#ifdef XYZ1
   char       *achl_rp;                     /* read pointer            */
#endif
#endif
   DSD_CONN_G *adsl_conn1;                  /* the connection / session */
   void *     vpl_handle;                   /* handle for L2TP or HOB-TUN */
   struct dsd_l2tp_conf *adsl_l2tp_conf;    /* L2TP connection configuration */
#ifdef XYZ1
   int        inl_len_cert;                 /* length of certificate n */
   enum ied_chid_ret iel_chid_ret;          /* check ident return code */
// BOOL       bol_http;                     /* try HTTP                */
// ied_at_function iel_function;            /* authentication function */
// ied_at_return iel_return;                /* return authentication   */
// ied_scp_def iel_scp_def;                 /* server-conf protocol    */
// char       *achl_w1;                     /* working variable        */
#endif
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_last;  /* last record in storage for authentication */
#ifdef XYZ1
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#ifdef OLD_1112
   void *     avol_client_netaddr;          /* address net-addr        */
// void *     alout;                        /* address output subroutine */
   en_at_claddrtype iel_claddrtype;         /* type of address         */
#endif
   union {
     /* for MS-CHAP-V2                                                 */
     struct {
       struct dsd_ppp_auth_record *adsl_par_mscv2_challenge;  /* record in storage for authentication */
       struct dsd_ppp_auth_record *adsl_par_userid;  /* record in storage for authentication */
       struct dsd_ppp_auth_record *adsl_par_mscv2_response;  /* record in storage for authentication */
       struct dsd_user_entry *adsl_usent;   /* user entry              */
       int    imrl_sha1_array[ SHA_ARRAY_SIZE ];  /* for hash          */
       int    imrl_md4_array[ MD4_ARRAY_SIZE ];  /* for MD4            */
       unsigned int umrl_des_subkeytab[ DES_SUBKEY_ARRAY_SIZE ];  /* for DES */
     };
   };
// struct dsd_hl_wspat2_1 dsl_hlwspat2;     /* WSPAT2 call parameters  */
// struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_unicode_string dsl_us_userid;  /* for userid             */
   struct dsd_unicode_string dsl_us_password;  /* for password         */
   char       chrl_work1[ 256 * 2 ];        /* working area            */
   char       chrl_work2[ 256 ];            /* working area            */
   char       chrl_work3[ 24 ];             /* working area            */
   char       chrl_work4[ SHA_DIGEST_LEN ];  /* working area           */
   unsigned char ucrl_work5[ 8 ];           /* work area DES           */
#endif

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-seli-l%05d-T m_ppp_auth_2( %p , %d ) called",
                   __LINE__, adsp_ppp_cl_1, iep_pppa );
//#endif
   vpl_handle = adsp_ppp_cl_1->adsc_ppp_se_1->vpc_handle;  /* handle for L2TP or HOB-TUN */
   if (vpl_handle == NULL) return;          /* is not valid            */
   /* only supported L2TP                                              */
   adsl_conn1 = (DSD_CONN_G *) ((char *) vpl_handle
                                           - offsetof( DSD_CONN_G, dsc_l2tp_session ));
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_2( %p , %d ) adsp_ppp_cl_1->adsc_ppp_auth_header=%p.",
                   __LINE__, adsp_ppp_cl_1, adsp_ppp_cl_1->adsc_ppp_auth_header );
#endif
#ifndef B140402
   if (iep_pppa == ied_pppa_invalid) {      /* free resources          */
     if (adsp_ppp_cl_1->adsc_ppp_auth_header) {  /* with storage for authentication */
       m_proc_free( adsp_ppp_cl_1->adsc_ppp_auth_header );  /* free storage for authentication */
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
       m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_2( %p , %d ) freed adsp_ppp_cl_1->adsc_ppp_auth_header=%p.",
                       __LINE__, adsp_ppp_cl_1, adsp_ppp_cl_1->adsc_ppp_auth_header );
#endif
       adsp_ppp_cl_1->adsc_ppp_auth_header = NULL;  /* no more storage for authentication */
     }
     return;
   }
#endif
   if (adsp_ppp_cl_1->adsc_ppp_auth_header) {  /* with storage for authentication */
     goto p_init_end;                       /* end of initialization   */
   }
   adsp_ppp_cl_1->adsc_ppp_auth_header = (struct dsd_ppp_auth_header *) m_proc_alloc();  /* storage for authentication */
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_ppp_auth_2( %p ) adsp_ppp_cl_1->adsc_ppp_auth_header=%p.",
                   __LINE__, adsp_ppp_cl_1, adsp_ppp_cl_1->adsc_ppp_auth_header );
#endif
   adsp_ppp_cl_1->adsc_ppp_auth_header->achc_stor_end  /* end of this storage */
     = (char *) adsp_ppp_cl_1->adsc_ppp_auth_header + LEN_TCP_RECV;
   adsp_ppp_cl_1->adsc_ppp_auth_header->adsc_ppp_auth_record = NULL;  /* chain of records in storage for authentication */
   adsp_ppp_cl_1->adsc_ppp_auth_header->iec_ppp_auth = iep_pppa;  /* authentication-method in use */
#ifdef XYZ1
   if (adsp_ppp_cl_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_ms_chap_v2) {  /* not MS-CHAP-V2 */
     return;
   }
   adsl_par_w1 = (struct dsd_ppp_auth_record *) (adsp_ppp_cl_1->adsc_ppp_auth_header + 1);  /* record in storage for authentication */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_challenge;  /* type of authentication record - MS-CHAP-V2 challenge */
   adsl_par_w1->imc_len_data = 1 + LEN_MSCV2_CHALLENGE + sizeof(ucrs_wsp_ident);  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_w1 + 1))
   AUCL_PAR_DATA[ 0 ] = LEN_MSCV2_CHALLENGE;  /* length MS-CHAP-V2 challenge */
   iml1 = LEN_MSCV2_CHALLENGE;              /* length MS-CHAP-V2 challenge */
   do {                                     /* loop to fill challenge  */
     AUCL_PAR_DATA[ iml1 ] = (unsigned char) m_get_random_number( 0X0100 );
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   memcpy( AUCL_PAR_DATA + 1 + LEN_MSCV2_CHALLENGE, ucrs_wsp_ident, sizeof(ucrs_wsp_ident) );
#undef AUCL_PAR_DATA
   adsp_ppp_cl_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_w1;  /* chain of records in storage for authentication */
#endif
// return;                                  /* send challenge to client */

   p_init_end:                              /* end of initialization   */
   /* get credential configured in WSP-XML-file <L2TP-gateway>         */
   if (adsl_conn1->iec_servcotype != ied_servcotype_l2tp) {  /* not L2TP */
     return;
   }
   adsl_l2tp_conf = adsl_conn1->adsc_server_conf_1->adsc_l2tp_conf;  /* L2TP connection configuration */
   if (adsl_l2tp_conf == NULL) {            /* no L2TP connection configuration */
     return;
   }
   if (adsl_l2tp_conf->imc_len_auth_userid == 0) {  /* length of authenticate-use-userid bytes */
     return;
   }
#ifdef XYZ1
   iml1 = m_len_vx_vx( ied_chs_ansi_819,    /* ANSI 819                */
                       adsl_l2tp_conf->achc_auth_userid,  /* authenticate-use-userid UTF-8 */
                       adsl_l2tp_conf->imc_len_auth_userid,  /* length of authenticate-use-userid bytes */
                       ied_chs_utf_8 );     /* Unicode UTF-8           */
#endif
   adsl_par_w1 = (struct dsd_ppp_auth_record *) (adsp_ppp_cl_1->adsc_ppp_auth_header + 1);  /* record in storage for authentication */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_userid;   /* userid                  */
#define ACHL_PAR_DATA ((char *) (adsl_par_w1 + 1))
   adsl_par_w1->imc_len_data = m_cpy_vx_vx( ACHL_PAR_DATA,
                                            adsp_ppp_cl_1->adsc_ppp_auth_header->achc_stor_end
                                              - ACHL_PAR_DATA,
                                            ied_chs_ansi_819,  /* ANSI 819 */
                                            adsl_l2tp_conf->achc_auth_userid,  /* authenticate-use-userid UTF-8 */
                                            adsl_l2tp_conf->imc_len_auth_userid,  /* length of authenticate-use-userid bytes */
                                            ied_chs_utf_8 );  /* Unicode UTF-8 */
#undef ACHL_PAR_DATA
   adsp_ppp_cl_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_w1;  /* chain of records in storage for authentication */
   if (adsl_l2tp_conf->imc_len_auth_pwd == 0) {  /* length of authenticate-use-password bytes */
     return;
   }
   adsl_par_last = adsl_par_w1;             /* last record in storage for authentication */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) ((char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_password;  /* password (PAP)         */
#define ACHL_PAR_DATA ((char *) (adsl_par_w1 + 1))
   adsl_par_w1->imc_len_data = m_cpy_vx_vx( ACHL_PAR_DATA,
                                            adsp_ppp_cl_1->adsc_ppp_auth_header->achc_stor_end
                                              - ACHL_PAR_DATA,
                                            ied_chs_ansi_819,  /* ANSI 819 */
                                            adsl_l2tp_conf->achc_auth_pwd,  /* authenticate-use-password UTF-8 */
                                            adsl_l2tp_conf->imc_len_auth_pwd,  /* length of authenticate-use-password bytes */
                                            ied_chs_utf_8 );  /* Unicode UTF-8 */
#undef ACHL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain of records in storage for authentication */
   return;
} /* end m_ppp_auth_2()                                                */

/** PPP authentication over Radius is complete                         */
static void m_ppp_auth_radius_compl( struct dsd_radius_control_1 *adsp_rctrl1, int imp_error ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_a1;                       /* working variable        */
   int        imrl_a[ 3 ];                  /* numbers attributes      */
   char       *achl1, *achl2, *achl3, *achl4;  /* working variables    */
   char       *achl_max_par;                /* address maximum record in storage for authentication */
   char       *achl_mscv2_success;          /* address attribute MS-CHAP-V2 success */
   char       *achl_mscv2_failure;          /* address attribute MS-CHAP-V2 failure */
   void *     vpl_handle;                   /* handle for L2TP or HOB-TUN */
   DSD_CONN_G *adsl_conn1_l;                /* the connection / session */
   struct dsd_ppp_server_1 *adsl_ppp_se_1;
   struct dsd_ppp_auth_header *adsl_ppp_auth_header;  /* storage for authentication */
   struct dsd_hl_aux_radius_1 *adsl_har1;
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_last;  /* last record in storage for authentication */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-seli-l%05d-T m_ppp_auth_radius_compl( %p ) called",
                   __LINE__, adsp_rctrl1 );
//#endif
#ifdef XYZ1
   adsl_ppp_se_1 = *((struct dsd_ppp_server_1 **) (adsp_rctrl1 + 1));
#endif
   adsl_ppp_auth_header = *((struct dsd_ppp_auth_header **) (adsp_rctrl1 + 1));
#ifdef XYZ1
   if (adsl_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* storage for authentication */
// to-do 08.05.12 KB message
     return;
   }
#endif
   if (adsl_ppp_auth_header->vpc_radius != adsp_rctrl1) {  /* for Radius authentication */
// to-do 08.05.12 KB message
     return;
   }
   adsl_ppp_se_1 = adsl_ppp_auth_header->adsc_ppp_server_1;  /* PPP server */
   if (adsl_ppp_se_1 == NULL) {             /* PPP server already ended */
     m_proc_free( adsl_ppp_auth_header );   /* free storage for authentication */
// to-do 23.03.14 KB - should m_radius_cleanup( adsp_rctrl1 ); be called ???
     return;                                /* all done                */
   }
   vpl_handle = adsl_ppp_se_1->vpc_handle;  /* handle for L2TP or HOB-TUN */
   if (vpl_handle == NULL) {                /* is not valid            */
     m_hlnew_printf( HLOG_WARN1, "xiipgw08-seli-l%05d-W m_ppp_auth_radius_compl( %p ) adsl_ppp_se_1 %p vpl_handle == NULL",
                     __LINE__, adsp_rctrl1, adsl_ppp_se_1 );
     return;                                /* all done                */
   }
   if (adsl_ppp_se_1->adsc_ppp_cl_1) {      /* is L2TP                 */
     adsl_conn1_l = (DSD_CONN_G *) ((char *) vpl_handle
                                             - offsetof( DSD_CONN_G, dsc_l2tp_session ));
#ifdef D_INCL_HOB_TUN
   } else {                                 /* TRUE is HOB-TUN         */
// to-do 15.09.12 KB - where to get connection?
//   adsl_conn1_l = (DSD_CONN_G *) (((char *) vpl_handle - offsetof( DSD_CONN_G, dsc_tun_contr1 )));
     adsl_conn1_l = (DSD_CONN_G *) (((char *) vpl_handle - offsetof( DSD_CONN_G, dsc_tun_contr_conn )));
#endif
   }
   adsl_har1 = (struct dsd_hl_aux_radius_1 *) ((void **) (adsp_rctrl1 + 1) + 1);
   if (adsl_ppp_auth_header->iec_ppp_auth   /* authentication-method in use */
         == ied_pppa_eap) {                 /* EAP                     */
     goto p_compl_eap_00;                   /* Radius request EAP complete */
   }
   adsl_ppp_auth_header->vpc_radius = NULL;  /* for Radius authentication */
#ifdef B130323
   adsl_har1 = (struct dsd_hl_aux_radius_1 *) ((void **) (adsp_rctrl1 + 1) + 1);
#endif
   m_radius_cleanup( adsp_rctrl1 );         /* Radius request no more needed */
   switch (adsl_ppp_auth_header->iec_ppp_auth) {  /* authentication-method in use */
     case ied_pppa_pap:                     /* PAP                     */
       if (adsl_har1->iec_radius_resp == ied_rar_access_accept) {  /* response from radius server */
         m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_ok );  /* userid and password valid */
         return;                            /* all done                */
       }
       m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_inv_password );  /* authentication is not valid */
       return;                              /* all done                */
//   case ied_pppa_chap:                    /* CHAP                    */
     case ied_pppa_ms_chap_v2:              /* MS-CHAP-V2              */
       goto p_compl_mscv2_00;               /* MS-CHAP-V2              */
//   case ied_pppa_eap:                     /* EAP                     */
   }
   /* program should never come here                                   */
// to-do 21.11.13 KB message
   return;

   p_compl_mscv2_00:                        /* MS-CHAP-V2              */
   adsl_par_w1 = adsl_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   achl_max_par = (char *) (adsl_ppp_auth_header + 1);  /* end of storage used */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     achl1 = (char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data;  /* end of this record */
     if (achl1 > achl_max_par) achl_max_par = achl1;  /* in use till here */
     adsl_par_last = adsl_par_w1;           /* save last in chain      */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_har1->imc_attr_in <= 0) {       /* length attributes input */
// to-do 08.05.12 KB message
     return;
   }
   achl1 = adsl_har1->achc_attr_in;         /* attributes input        */
   achl2 = achl1 + adsl_har1->imc_attr_in;  /* length attributes input */
   /* we need MPPE keys / HLAK for SSTP channel bindings               */
   if (   (adsl_conn1_l->adsc_server_conf_1)
       && (adsl_conn1_l->adsc_server_conf_1->iec_scp_def == ied_scp_sstp)) {  /* protocol SSTP */
     m_radius_mppe_calc_1( adsl_conn1_l, adsp_rctrl1, achl1, adsl_har1->imc_attr_in );
   }
   achl_mscv2_success = NULL;               /* address attribute MS-CHAP-V2 success */
   achl_mscv2_failure = NULL;               /* address attribute MS-CHAP-V2 failure */

   p_attr_00:                               /* check Radius attributes */
   if ((achl1 + 2) >= achl2) {              /* not space for attribute */
// to-do 08.05.12 KB message
     return;
   }
   iml1 = *((unsigned char *) achl1 + 1);   /* get length              */
   if ((achl1 + iml1) > achl2) {            /* not space for attribute */
// to-do 08.05.12 KB message
     return;
   }
   achl3 = achl1;                           /* save address attribute  */
   achl1 += iml1;                           /* address of next attribute */
   if (*achl3 != 0X1A) {                    /* is not vendor specific  */
     goto p_attr_60;                        /* end of Radius attribute */
   }
   if (iml1 <= sizeof(ucrs_send_avp_ms_01)) {  /* is not Microsoft     */
     goto p_attr_60;                        /* end of Radius attribute */
   }
   if (memcmp( achl3 + 2, ucrs_send_avp_ms_01 + 2, sizeof(ucrs_send_avp_ms_01) - 2 )) {
     goto p_attr_60;                        /* end of Radius attribute */
   }
   switch (*((unsigned char *) achl3 + 2 + sizeof(ucrs_send_avp_ms_01) - 2)) {
     case D_AVSMS_CHSU:                     /* attribute vendor-specific MS MS-CHAP-Success */
       if (achl_mscv2_success) {            /* address attribute MS-CHAP-V2 success */
// to-do 08.05.12 KB message
         return;
       }
       achl_mscv2_success = achl3;          /* address attribute MS-CHAP-V2 success */
       break;
     case D_AVSMS_CHFA:                     /* attribute vendor-specific MS MS-CHAP-Failure */
       if (achl_mscv2_failure) {            /* address attribute MS-CHAP-V2 failure */
// to-do 08.05.12 KB message
         return;
       }
       achl_mscv2_failure = achl3;          /* address attribute MS-CHAP-V2 failure */
       break;
   }


   p_attr_60:                               /* end of Radius attribute */
   if (achl1 < achl2) {                     /* not end of attributes   */
     goto p_attr_00;                        /* check Radius attributes */
   }
   if (achl_mscv2_success == NULL) {        /* address attribute MS-CHAP-V2 success */
     goto p_attr_80;                        /* no attribute success    */
   }
   if (achl_mscv2_failure) {                /* address attribute MS-CHAP-V2 failure */
// to-do 08.05.12 KB message
     return;
   }
   if (adsl_har1->iec_radius_resp != ied_rar_access_accept) {  /* accept sign on */
// to-do 08.05.12 KB message
     return;
   }
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl_max_par + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_success;  /* MS-CHAP-V2 success */
   adsl_par_w1->imc_len_data = 2 + SHA_DIGEST_LEN * 2;  /* length of the data */
#define ACHL_PAR_DATA ((char *) (adsl_par_w1 + 1))
   memcpy( ACHL_PAR_DATA,
           achl_mscv2_success + 2 + sizeof(ucrs_send_avp_ms_01) - 2 + 3,
           2 + SHA_DIGEST_LEN * 2 );        /* length of the data      */
#undef ACHL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain of records in storage for authentication */
   m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_ok );  /* authentication is valid */
   return;                                  /* all done                */

   p_attr_80:                               /* no attribute success    */
   if (achl_mscv2_failure == NULL) {        /* address attribute MS-CHAP-V2 failure */
// to-do 08.05.12 KB message
     return;
   }
   if (   (adsl_har1->iec_radius_resp != ied_rar_access_reject)  /* reject access */
       && (adsl_har1->iec_radius_resp != ied_rar_need_new_password)) {  /* needs new password */
// to-do 08.05.12 KB message
     return;
   }
// memset( imrl_a, 0XFF, sizeof(imrl_a) );  /* set numbers to -1       */
   iml_a1 = 0;                              /* clear index of number   */
   achl1 = achl_mscv2_failure + 2 + sizeof(ucrs_send_avp_ms_01) + 1;  /* address attribute MS-CHAP-V2 failure */
   achl2 = achl_mscv2_failure + *((unsigned char *) achl_mscv2_failure + 1);  /* end of numbers */

   p_attr_num_00:                           /* process numbers         */
   if ((achl1 + 3) > achl2) {               /* no space for numbers    */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA012W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error space for number too short",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   if (*(achl1 + 0) != ucrs_vendor_s_ms_numbers[ iml_a1 ]) {
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA013W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X out of sequence",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     *(achl1 + 0), (unsigned char) *(achl1 + 0) );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   if (*(achl1 + 1) != '=') {               /* no equals follows       */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA014W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X no equals follows",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     *(achl1 + 0), (unsigned char) *(achl1 + 0) );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   achl1 += 2;                              /* start ASCII number here */
   achl3 = achl1 + 4;                       /* maximum end of number   */
   achl4 = achl1;                           /* save beginning of number */
   imrl_a[ iml_a1 ] = 0;                    /* reset number            */

   p_attr_num_20:                           /* process digit of number */
   if (achl1 >= achl2) {                    /* end of number           */
     goto p_attr_num_40;                    /* end of number           */
   }
   if (*achl1 == ' ') {                     /* followed by space       */
     goto p_attr_num_40;                    /* end of number           */
   }
   if (achl1 >= achl3) {                    /* number too big          */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA015W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X too big",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ] );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   if ((*achl1 < '0') || (*achl1 > '9')) {  /* is not digit            */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA016W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X invalid digit 0X%02X.",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ],
                     (unsigned char) *achl1 );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   imrl_a[ iml_a1 ] *= 10;                  /* shift old number        */
   imrl_a[ iml_a1 ] += *achl1 - '0';        /* add new digit           */
   achl1++;                                 /* after this digit        */
   goto p_attr_num_20;                      /* process digit of number */

   p_attr_num_40:                           /* end of number           */
   if (achl1 <= achl4) {                    /* no digit found          */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA017W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error number %c / 0X%02X no digit found",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1,
                     ucrs_vendor_s_ms_numbers[ iml_a1 ], ucrs_vendor_s_ms_numbers[ iml_a1 ] );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   iml_a1++;                                /* this digit processed    */
   if (achl1 >= achl2) {                    /* end of numbers          */
//   goto p_attr_60;                        /* radius attribute has been processed */
     goto p_attr_num_80;                    /* numbers have been processed */
   }
   if (iml_a1 >= (sizeof(imrl_a)/sizeof(imrl_a[0]))) {  /* too many numbers */
#ifdef XYZ1
// to-do 09.05.12 KB error
     m_hlnew_printf( HLOG_WARN1, "HWSPRA018W l%05d radius-group %.*(u8)s radius-server %.*(u8)s attribute MS-CHAP-Error too many numbers",
                     __LINE__,
                     adsl_radius_group->imc_len_name, adsl_radius_group + 1,
                     adsl_re_w1->imc_len_name, adsl_re_w1 + 1 );
     goto p_attr_60;                        /* radius attribute has been processed */
#endif
// to-do 08.05.12 KB message
     return;
   }
   achl1++;                                 /* after space             */
   goto p_attr_num_00;                      /* process next number     */

   p_attr_num_80:                           /* numbers have been processed */
   /* create new challenge                                             */
   adsl_par_w1 = adsl_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   if (   (adsl_par_w1 == NULL)
       || (adsl_par_w1->iec_par != ied_par_mscv2_challenge)) {  /* MS-CHAP-V2 challenge */
// to-do 09.05.12 KB va-list - add __LINE__
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 04" );
     return;
   }
   achl2 = (char *) (adsl_par_w1 + 1) + 1;  /* here starts challenge */
   iml1 = LEN_MSCV2_CHALLENGE - 1;          /* length of challenge minus one */
   do {                                     /* loop to fill challenge  */
     *(achl2 + iml1) = (unsigned char) m_get_random_number( 0X0100 );
     iml1--;                                /* decrement index         */
   } while (iml1 > 0);
   /* pass record with MS-CHAP-V2 failure                              */
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl_max_par + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_mscv2_failure;  /* MS-CHAP-V2 failure */
// adsl_par_w1->imc_len_data = 2 + SHA_DIGEST_LEN * 2;  /* length of the data */
#define ACHL_PAR_DATA ((char *) (adsl_par_w1 + 1))
   iml1 = sprintf( ACHL_PAR_DATA + 2 + 1 + 1,
                   "E=%d R=1 C=",
                   imrl_a[ 0 ] );
   achl1 = ACHL_PAR_DATA + 2 + 1 + 1 + iml1;  /* here is target for new challenge */
   /* achl2 already set                                                */
   iml1 = LEN_MSCV2_CHALLENGE;              /* length of challenge     */
   do {                                     /* loop to translate to ASCII */
     iml2 = (unsigned char) *achl2++;       /* get input               */
     *achl1++ = chrstrans[ iml2 >> 4 ];
     *achl1++ = chrstrans[ iml2 & 0X0F ];
     iml1--;                                /* decrement length        */
   } while (iml1 > 0);
   iml1 = sprintf( achl1,
                   " V=%d",
                   imrl_a[ 2 ] );
   adsl_par_w1->imc_len_data = (achl1 + iml1) - ACHL_PAR_DATA;  /* length of the data */
   *ACHL_PAR_DATA = 4;                      /* code failure            */
   *(ACHL_PAR_DATA + 2 + 0) = (unsigned char) (adsl_par_w1->imc_len_data >> 8);
   *(ACHL_PAR_DATA + 2 + 1) = (unsigned char) adsl_par_w1->imc_len_data;
#undef ACHL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to chain of records in storage for authentication */
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-seli-l%05d-T m_ppp_auth_radius_compl( %p ) call m_ppp_se_auth_ret()",
                   __LINE__, adsp_rctrl1 );
//#endif
// to-do 09.05.12 KB - other enum value
   m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_inv_password );  /* authentication is not valid */
   return;                                  /* all done                */

   p_compl_eap_00:                          /* Radius request EAP complete */
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-seli-l%05d-T m_ppp_auth_radius_compl( %p ) p_compl_eap_00: length adsl_har1->imc_attr_in %d ->iec_radius_resp=%d.",
                   __LINE__, adsp_rctrl1, adsl_har1->imc_attr_in, adsl_har1->iec_radius_resp );
//#endif
   if (adsl_har1->iec_radius_resp == ied_rar_access_accept) {  /* response from radius server */
     /* we need MPPE keys / HLAK for SSTP channel bindings               */
     if (   (adsl_conn1_l->adsc_server_conf_1)
         && (adsl_conn1_l->adsc_server_conf_1->iec_scp_def == ied_scp_sstp)) {  /* protocol SSTP */
       m_radius_mppe_calc_1( adsl_conn1_l, adsp_rctrl1, adsl_har1->achc_attr_in, adsl_har1->imc_attr_in );
     }
     m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_ok );  /* userid and password valid */
     return;                                /* all done                */
   }
   /* auxiliary records and old Radius records need to get removed     */
#ifndef B140401
   if (adsl_ppp_se_1->adsc_ppp_auth_header == NULL) return;
#endif
   adsl_par_w1 = adsl_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   achl_max_par = (char *) (adsl_ppp_auth_header + 1);  /* end of storage used */
   adsl_par_last = NULL;                    /* save last in chain      */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     if (   (adsl_par_w1->iec_par == ied_par_userid)  /* userid - EAP identitiy  */
         || (adsl_par_w1->iec_par == ied_par_radius_1)) {  /* used for Radius */
       achl1 = (char *) (adsl_par_w1 + 1) + adsl_par_w1->imc_len_data;  /* end of this record */
       if (achl1 > achl_max_par) achl_max_par = achl1;  /* in use till here */
       adsl_par_last = adsl_par_w1;         /* save last in chain      */
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_last == NULL) {             /* save last in chain      */
// to-do 23.03.14 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - no records in authentication storage" );
     return;
   }
   if (adsl_har1->imc_attr_in <= 0) {       /* length attributes input */
// to-do 08.05.12 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - no attributes received from Radius" );
     return;
   }
   /* first pass - count length EAP data                               */
   iml2 = 0;                                /* clear length found      */
   achl4 = NULL;                            /* only count length       */

   p_eap_attr_00:                           /* start pass thru AVP pairs */
   achl1 = adsl_har1->achc_attr_in;         /* attributes input        */
   achl2 = achl1 + adsl_har1->imc_attr_in;  /* length attributes input */

   p_eap_attr_20:                           /* check Radius attributes */
   if ((achl1 + 2) >= achl2) {              /* not space for attribute */
// to-do 08.05.12 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - attributes received from Radius invalid 01" );
     return;
   }
   iml1 = *((unsigned char *) achl1 + 1);   /* get length              */
   if (iml1 < 3) {                          /* length too short        */
// to-do 08.05.12 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - attributes received from Radius invalid 02" );
     return;
   }
   if ((achl1 + iml1) > achl2) {            /* not space for attribute */
// to-do 08.05.12 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - attributes received from Radius invalid 03" );
     return;
   }
   achl3 = achl1;                           /* save address attribute  */
   achl1 += iml1;                           /* address of next attribute */
   if (*achl3 != DEF_RADIUS_AVP_TYPE_EAP) {  /* is not vendor specific  */
     goto p_eap_attr_40;                    /* end of Radius attribute */
   }
   if (achl4 == NULL) {                     /* only count length       */
     iml2 += iml1 - 2;
     goto p_eap_attr_40;                    /* end of Radius attribute */
   }
   memcpy( achl4, achl3 + 2, iml1 - 2 );
   achl4 += iml1 - 2;

   p_eap_attr_40:                           /* end of Radius attribute */
   if (achl1 < achl2) {                     /* not end of attributes   */
     goto p_eap_attr_20;                    /* check Radius attributes */
   }
   if (achl4) {                             /* was already second pass */
     goto p_eap_attr_60;                    /* attributes have been processed */
   }
   if (iml2 == 0) {                         /* no EAP attributes found */
// to-do 23.03.14 KB message
     adsl_ppp_se_1->amc_ppp_se_abend( adsl_ppp_se_1, "received EAP response - no EAP attributes received from Radius" );
     return;
   }
   adsl_par_w1 = (struct dsd_ppp_auth_record *)
                   ((long long int) (achl_max_par + sizeof(void *) - 1)
                      & (0 - sizeof(void *)));
   adsl_par_last->adsc_next = adsl_par_w1;  /* append to old chain     */
   adsl_par_w1->adsc_next = NULL;           /* clear chain             */
   adsl_par_w1->iec_par = ied_par_eap_send_1;  /* EAP to send          */
   adsl_par_w1->imc_len_data = iml2;        /* length of the data      */
   achl4 = (char *) (adsl_par_w1 + 1);
   goto p_eap_attr_00;                      /* start pass thru AVP pairs */

   p_eap_attr_60:                           /* attributes have been processed */
   m_ppp_se_auth_ret( adsl_ppp_se_1, ied_chid_cont );  /* not yet complete, continue processing */
   return;                                  /* all done                */
} /* end m_ppp_auth_radius_compl()                                     */

/** calculate the MPPE keys - HLAK fpr SSTP channel binding            */
static void m_radius_mppe_calc_1( DSD_CONN_G *adsp_conn1, struct dsd_radius_control_1 *adsp_rctrl1, char *achp_attr, int imp_len_attr ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_offset;                   /* offset of output        */
   char       *achl_attr_10;                /* attribute type 10       */
   char       *achl_attr_11;                /* attribute type 11       */
   char       *achl_rp;                     /* read pointer attribute  */
   char       *achl_next;                   /* next attribute          */
   char       *achl_cur;                    /* current attribute       */
   struct dsd_auxf_1 *adsl_auxf_1_hlak;     /* auxiliary extension field - HLAK */
   int        imrl_md5_array[ MD5_ARRAY_SIZE ];  /* for MD5            */
   char       chrl_md5_digest[ MD5_DIGEST_LEN ];  /* for MD5           */
   char       chrl_decrypted[ 33 ];

   achl_attr_10 = NULL;                     /* attribute type 10       */
   achl_attr_11 = NULL;                     /* attribute type 11       */
   achl_next = achp_attr;

   p_attr_00:                               /* search thru attributes  */
   if ((achl_next + 2) > (achp_attr + imp_len_attr)) {  /* too long    */
// to-do 10.04.15 KB - error message                                   */
     return;
   }
   iml1 = *((unsigned char *) achl_next + 1);  /* get length           */
   achl_rp = achl_next;                     /* read pointer attribute  */
   achl_next += iml1;                       /* address of next attribute */
   if (achl_next > (achp_attr + imp_len_attr)) {  /* too long    */
// to-do 10.04.15 KB - error message                                   */
     return;
   }
   if (*achl_rp != 0X1A) {                  /* is not vendor specific  */
     goto p_attr_60;                        /* end of Radius attribute */
   }
   if (iml1 <= sizeof(ucrs_send_avp_ms_01)) {  /* is not Microsoft     */
     goto p_attr_60;                        /* end of Radius attribute */
   }
   if (memcmp( achl_rp + 2, ucrs_send_avp_ms_01 + 2, sizeof(ucrs_send_avp_ms_01) - 2 )) {
     goto p_attr_60;                        /* end of Radius attribute */
   }
   switch (*((unsigned char *) achl_rp + 2 + sizeof(ucrs_send_avp_ms_01) - 2)) {
     case 0X10:
       if (achl_attr_10 != NULL) {          /* attribute type 10       */
// to-do 10.04.15 KB message
         m_hlnew_printf( HLOG_WARN1, "xiipgw08-seli-l%05d-W m_radius_mppe_calc_1() Microsoft attribute 0X10 double",
                         __LINE__ );
         return;
       }
       achl_attr_10 = achl_rp;              /* attribute type 10       */
       break;
     case 0X11:
       if (achl_attr_11 != NULL) {          /* attribute type 11       */
// to-do 10.04.15 KB message
         m_hlnew_printf( HLOG_WARN1, "xiipgw08-seli-l%05d-W m_radius_mppe_calc_1() Microsoft attribute 0X11 double",
                         __LINE__ );
         return;
       }
       achl_attr_11 = achl_rp;              /* attribute type 11       */
       break;
   }

   p_attr_60:                               /* end of Radius attribute */
   if (achl_next < (achp_attr + imp_len_attr)) {  /* not end of attributes */
     goto p_attr_00;                        /* check Radius attributes */
   }
   if (   (achl_attr_10 == NULL)            /* attribute type 10       */
       && (achl_attr_11 == NULL)) {         /* attribute type 11       */
     return;
   }
   if (   (achl_attr_10 == NULL)            /* attribute type 10       */
       || (achl_attr_11 == NULL)) {         /* attribute type 11       */
// to-do 10.04.15 KB message
     m_hlnew_printf( HLOG_WARN1, "xiipgw08-seli-l%05d-W m_radius_mppe_calc_1() Microsoft attributes 0X10 0X11 - one is missing",
                     __LINE__ );
     return;
   }


/**
  we need to pass the MPPE keys for SSTP channel binding
  so that it can be checked later

  0X10 = SendKey
  0X11 = ReceiveKey
  ReceiveKey||SendKey
*/
   adsl_auxf_1_hlak = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1) + LEN_HLAK );  /* auxiliary extension field - HLAK */
   memset( adsl_auxf_1_hlak, 0, sizeof(struct dsd_auxf_1) );
   adsl_auxf_1_hlak->iec_auxf_def = ied_auxf_mppe_keys;  /* SSTP - HLAK */
#ifndef HL_UNIX
   EnterCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
   adsl_auxf_1_hlak->adsc_next = adsp_conn1->adsc_auxf_1;  /* get old chain auxiliary ext fields */
   adsp_conn1->adsc_auxf_1 = adsl_auxf_1_hlak;  /* set new chain auxiliary ext fields */
#ifndef HL_UNIX
   LeaveCriticalSection( &adsp_conn1->d_act_critsect );  /* critical section act */
#else
   adsp_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
   achl_cur = achl_attr_10;                 /* current attribute       */
   iml_offset = 16;                         /* offset of output        */

   p_decry_00:                              /* decrypt data            */
#ifdef NOT_YET_150410
//if (*((unsigned char *) achl_packet_sta + iml3 + sizeof(ucrs_send_avp_ms_01)) == 0x10) {
       UINT8 len = *((unsigned char *) achl_packet_sta + iml3 + sizeof(ucrs_send_avp_ms_01) + 1);
       len -= 2 + 2;
       MD5_Init( imrl_md5_array );
       MD5_Update( imrl_md5_array, adsl_rctrl1->adsc_radius_group->adsc_radius_entry->achc_shasec, 0, adsl_rctrl1->adsc_radius_group->adsc_radius_entry->imc_len_shasec );
       MD5_Update( imrl_md5_array, adsl_rctrl1->chrc_req_auth, 0, DEF_RADIUS_LEN_REQ_AUTH );
       MD5_Update( imrl_md5_array, achp_attr + sizeof(ucrs_send_avp_ms_01) + 2, 0, 2);
       char digest[DEF_RADIUS_LEN_REQ_AUTH];
       MD5_Final( imrl_md5_array, digest, 0 );
       UINT8 ulen = digest[0];
       ulen ^= *(achp_attr + sizeof(ucrs_send_avp_ms_01) + 4);
       // We should check here whether the length is correct

       char decrypted[32];
       char *psswd = achp_attr + sizeof(ucrs_send_avp_ms_01) + 2;
       for (int iml5 = 0; iml5 < len; iml5 += ulen /*??*/){
           for (int iml6 = 0; iml6 < ulen; iml6++){
               decrypted[iml5+iml6] = ((unsigned char ) *(psswd + iml5 + iml6 + 2)) ^ digest[iml6];

               // ecnrypted psswd may not be aligned...
               if ((iml5 + iml6) == len) break;
           }

           MD5_Init( imrl_md5_array );
           MD5_Update( imrl_md5_array, adsl_rctrl1->adsc_radius_group->adsc_radius_entry->achc_shasec, 0, adsl_rctrl1->adsc_radius_group->adsc_radius_entry->imc_len_shasec );
           MD5_Update( imrl_md5_array, psswd + iml5 + 2, 0, ulen/*??*/);
           MD5_Final( imrl_md5_array, digest, 0 );
       }

       memcpy( chrg_hlak + 16, decrypted + 1, ulen );
#endif
   iml1 = *((unsigned char *) achl_cur + sizeof(ucrs_send_avp_ms_01) + 1) - 2 - 2;
   // if iml1=48 -> the MasterReceiveKey is already 32 bit. Then HLAK = MasterReceive Key
   if (iml1==48){
	   achl_cur = achl_attr_11;
	   iml_offset = 0;
	   iml1 = *((unsigned char *) achl_cur + sizeof(ucrs_send_avp_ms_01) + 1) - 2 - 2;
   }
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, adsp_rctrl1->adsc_radius_group->adsc_radius_entry->achc_shasec, 0, adsp_rctrl1->adsc_radius_group->adsc_radius_entry->imc_len_shasec );
   MD5_Update( imrl_md5_array, adsp_rctrl1->chrc_req_auth, 0, DEF_RADIUS_LEN_REQ_AUTH );
   MD5_Update( imrl_md5_array, achl_cur + sizeof(ucrs_send_avp_ms_01) + 2, 0, 2);
   MD5_Final( imrl_md5_array, chrl_md5_digest, 0 );
   iml2 = (unsigned char) chrl_md5_digest[0];
   iml2 ^= *((unsigned char *) achl_cur + sizeof(ucrs_send_avp_ms_01) + 2 + 2);
// to-do 11.04.15 KB - iml1 may be negative - iml1 and iml2 could be too big
   // todo - should we consider other lengths??
   if ((iml2!=16) && (iml2 != 32)){
       // todo - error
       return;
   }
   iml3 = 0;
   do {
     iml4 = 0;
     do {
       chrl_decrypted[ iml3 + iml4 ] = *((unsigned char *) achl_cur + sizeof(ucrs_send_avp_ms_01) + 2 + iml3 + iml4 + 2)
                                         ^ chrl_md5_digest[ iml4 ];

       iml4++;
	   if ((iml3 + iml4 == 17) && (iml2 == 16)){
		   goto p_return;
	   }
	   if (iml3 + iml4 == 33){ // We have already the 32 bits needed
		   goto p_return;
	   }
     } while (iml4 < MD5_DIGEST_LEN); // chrl_md5_digest length
     MD5_Init( imrl_md5_array );
     MD5_Update( imrl_md5_array, adsp_rctrl1->adsc_radius_group->adsc_radius_entry->achc_shasec, 0, adsp_rctrl1->adsc_radius_group->adsc_radius_entry->imc_len_shasec );
     MD5_Update( imrl_md5_array, achl_cur + sizeof(ucrs_send_avp_ms_01) + 2 + iml3 + 2, 0, MD5_DIGEST_LEN);
     MD5_Final( imrl_md5_array, chrl_md5_digest, 0 );
     iml3 += 16;
   } while (1);
p_return:
   memcpy( (char *) (adsl_auxf_1_hlak + 1) + iml_offset, chrl_decrypted + 1, iml2 );

   if (iml_offset == 0) return;             /* all done                */
   achl_cur = achl_attr_11;                 /* current attribute       */
   iml_offset = 0;                          /* offset of output        */
   goto p_decry_00;                         /* decrypt data            */
} /* end m_radius_mppe_calc_1()                                        */

/** free resources authentication for PPP                              */
extern "C" void m_ppp_auth_free( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
#ifdef OLD_1112
#ifndef NOT_YET_UNIX_110808
#define ADSC_RADQU_G ((class dsd_radius_query *) adsp_ppp_se_1->vpc_radius)
   if (ADSC_RADQU_G == NULL) return;        /* for Radius authentication */
   ADSC_RADQU_G->m_delete();                /* remove this entry       */
   adsp_ppp_se_1->vpc_radius = NULL;        /* class no more present   */
#undef ADSC_RADQU_G
#endif
#endif
#ifndef B140329
   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) return;
   if (adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius) {  /* with Radius authentication */
#define ADSL_RC1 ((struct dsd_radius_control_1 *) adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius)
#ifdef XYZ1
     if (ADSL_RC1->dsc_timer.vpc_chain_2) {  /* timer still set        */
       m_time_rel( &ADSL_RC1->dsc_timer );  /* release timer           */
     }
#endif
     m_radius_cleanup( ADSL_RC1 );          /* Radius request no more needed */
#undef ADSL_RC1
   }
#endif
} /* end m_ppp_auth_free()                                             */
#endif

/** retrieve gate of session / connection                              */
extern "C" struct dsd_gate_1 * m_conn2gate( void * vpp_conn ) {
#define ADSL_CONN1_G ((DSD_CONN_G *) vpp_conn)
   return ADSL_CONN1_G->adsc_gate1;
#undef ADSL_CONN1_G
} /* end m_conn2gate()                                                 */

#ifndef NOT_YET_UNIX_110808
#ifdef OLD_1112
/* prepare for connect pass thru to desktop with area from HLWSPAT2    */
static void m_prep_pttd_1( struct dsd_hlwspat2_conn *adsp_param_conn,
                           struct dsd_server_conf_1 *adsp_server_conf_1 ) {
#define ADSL_USENT_G ((struct dsd_user_entry *) adsp_param_conn->vpc_usent)
   adsp_param_conn->iec_hconn = ied_hconn_pttd;  /* pass thru to desktop */
   if (ADSL_USENT_G == NULL) return;        /* no user defined         */
   if (ADSL_USENT_G->boc_with_target == FALSE) return;  /* target not included */
   adsp_param_conn->achc_ineta              /* address INETA / IPV4 / IPV6 */
     = (char *) (ADSL_USENT_G + 1)
         + ADSL_USENT_G->inc_len_name_bytes  /* length of name in bytes */
         + ADSL_USENT_G->inc_len_password_bytes;  /* len of password in bytes */
   adsp_param_conn->inc_port = ADSL_USENT_G->inc_port_target;
   adsp_param_conn->umc_out_ineta = ADSL_USENT_G->umc_out_ineta;
   adsp_param_conn->boc_with_macaddr = ADSL_USENT_G->boc_with_macaddr;
   memcpy( adsp_param_conn->chrc_macaddr, ADSL_USENT_G->chrc_macaddr, sizeof(adsp_param_conn->chrc_macaddr) );
   adsp_param_conn->inc_waitconn = ADSL_USENT_G->inc_waitconn;
#undef ADSL_USENT_G
} /* end m_prep_pttd_1()                                               */
#endif
#ifndef OLD_1112
/** prepare for connect pass thru to desktop with area from HOB-WSP-AT3 */
static void m_prep_pttd_1( struct dsd_wspat3_conn *adsp_param_conn,
                           struct dsd_server_conf_1 *adsp_server_conf_1 ) {
#define ADSL_USENT_G ((struct dsd_user_entry *) adsp_param_conn->vpc_usent)
   adsp_param_conn->iec_hconn = ied_hconn_pttd;  /* pass thru to desktop */
#ifndef OLD_1112
   adsp_param_conn->umc_out_ineta
     = *((UNSIG_MED *) &adsp_server_conf_1->dsc_bind_out.dsc_soai4.sin_addr);
#endif
   if (ADSL_USENT_G == NULL) return;        /* no user defined         */
   if (ADSL_USENT_G->boc_with_target == FALSE) return;  /* target not included */
#ifdef OLD_1112
   adsp_param_conn->achc_ineta              /* address INETA / IPV4 / IPV6 */
     = (char *) (ADSL_USENT_G + 1)
         + ADSL_USENT_G->inc_len_name_bytes  /* length of name in bytes */
         + ADSL_USENT_G->inc_len_password_bytes;  /* len of password in bytes */
#endif
#ifndef OLD_1112
   /* INETA DNS / IPV4 / IPV6                                          */
   adsp_param_conn->dsc_ucs_target.ac_str   /* address of string       */
     = (char *) (ADSL_USENT_G + 1)
         + ADSL_USENT_G->inc_len_name_bytes  /* length of name in bytes */
         + ADSL_USENT_G->inc_len_password_bytes;  /* len of password in bytes */
   adsp_param_conn->dsc_ucs_target.imc_len_str = -1;  /* length string in elements */
   adsp_param_conn->dsc_ucs_target.iec_chs_str = ied_chs_utf_8;  /* character set string */
#endif
   adsp_param_conn->imc_port = ADSL_USENT_G->inc_port_target;
#ifdef OLD_1112
   adsp_param_conn->umc_out_ineta = ADSL_USENT_G->umc_out_ineta;
#endif
   adsp_param_conn->boc_with_macaddr = ADSL_USENT_G->boc_with_macaddr;
   memcpy( adsp_param_conn->chrc_macaddr, ADSL_USENT_G->chrc_macaddr, sizeof(adsp_param_conn->chrc_macaddr) );
   adsp_param_conn->imc_waitconn = ADSL_USENT_G->inc_waitconn;
#undef ADSL_USENT_G
} /* end m_prep_pttd_1()                                               */
#endif
#endif

#ifdef B110104
static BOOL m_check_target_dns( struct dsd_targfi_1 *adsp_targfi_1,
                                char *achp_dns, int imp_port ) {
   int        iml_no_targfi_ele_1;          /* number of elements      */
   int        iml_no_protocol;              /* number of protocols     */
   int        iml_no_port;                  /* number of ports         */
   int        iml_stack;                    /* position in stack       */
   char       *achl_mask;                   /* position in mask        */
   char       *achl_inp;                    /* position input          */
#define DEF_MASK_STACK 16
   char       *achrl_sm[ DEF_MASK_STACK ];
   char       *achrl_si[ DEF_MASK_STACK ];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_check_target_dns() l%05d adsp_targfi_1=%p DNS=%s Port=%d",
                   __LINE__, adsp_targfi_1, achp_dns, imp_port );
#endif
   imp_port |= ((unsigned char) IPPROTO_TCP) << 24;
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_dns_00:                            /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_dns_12;                     /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (((unsigned char) *(((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                              + iml_no_targfi_ele_1)->achrc_protocol + iml_no_protocol))
           == IPPROTO_TCP) {
       goto p_cht_dns_12;                   /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_dns_60;                       /* protocol not found in list */

   p_cht_dns_12:                            /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_dns_20;                     /* port is valid           */
   }
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (imp_port == *(((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                         + iml_no_targfi_ele_1)->aimrc_port + iml_no_port)) {
       goto p_cht_dns_20;                   /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_dns_60;                       /* port not found in list  */

   p_cht_dns_20:                            /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->achc_dns_name == NULL) {
/* extension 27.03.07 KB - start */
     /* check if neither INETA nor DNS                                 */
     if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_netw_mask < 0) {
       goto p_cht_dns_40;                   /* this element matches    */
     }
/* extension 27.03.07 KB - end */
//   goto p_cht_dns_40;                     /* this element matches    */
     goto p_cht_dns_60;                     /* ignore this element     */
   }
   iml_stack = 0;                           /* clear stack index       */
   achl_mask = ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                 + iml_no_targfi_ele_1)->achc_dns_name;
   achl_inp = achp_dns;                     /* start of input to compare */

   plook00:
   switch (*achl_mask) {
     case 0:
       goto plook60;
     case '*':
       goto plook40;
     case '?':
       goto plook20;
     default:
       if (tabaau[(unsigned char) *achl_mask] == tabaau[(unsigned char) *achl_inp]) {
         achl_mask++;
         achl_inp++;
         goto plook00;
       }
       goto plook62;
   }

   plook20:                                 /* single wildcard         */
   if (*achl_inp == 0) goto plook62;        /* character follows       */
   achl_inp++;                              /* next character input    */
   achl_mask++;
   if (*achl_mask == '?') goto plook20;
   if (*achl_mask == '*') goto plook40;     /* asterix found           */
   goto plook00;

   plook40:                                 /* asterix wildcard        */
   achl_mask++;
   if (*achl_mask == '*') goto plook40;
   if (*achl_mask == '?') {
     achl_inp++;                            /* next character input    */
     goto plook40;
   }
   if (iml_stack == DEF_MASK_STACK) {       /* stack overflow          */
     goto p_cht_dns_60;                     /* mask does not match     */
   }
   achrl_sm[iml_stack] = achl_mask;
   achrl_si[iml_stack] = achl_inp;
   iml_stack++;
   goto plook00;

   plook60:                                 /* end of DNS-name         */
   if (*achl_inp == 0) goto p_cht_dns_40;   /* no more characters      */

   plook62:                                 /* end of DNS-name         */
   if (iml_stack == 0) {                    /* no more in table        */
     goto p_cht_dns_60;                     /* mask does not match     */
   }
   achrl_si[iml_stack - 1]++;
   achl_mask = achrl_sm[iml_stack - 1];
   achl_inp = achrl_si[iml_stack - 1];
   if (*achl_inp) goto plook00;
   if (*achl_mask == 0) goto p_cht_dns_40;  /* end already found       */
   iml_stack--;
   goto plook62;

   p_cht_dns_40:                            /* this element matches    */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     return FALSE;                          /* allow, finished         */
   }
   return TRUE;                             /* deny, target not allowed */

   p_cht_dns_60:                            /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_dns_00;                     /* check next element      */
   }
   return TRUE;                             /* target not allowed      */
} /* end m_check_target_dns()                                          */

static BOOL m_check_target_ineta( struct dsd_targfi_1 *adsp_targfi_1,
                                  UNSIG_MED ump_ineta, int imp_port ) {
   int        iml_no_targfi_ele_1;          /* number of elements      */
   int        iml_no_protocol;              /* number of protocols     */
   int        iml_no_port;                  /* number of ports         */
   UNSIG_MED  uml_ineta_w1;                 /* temporary INETA         */
   UNSIG_MED  uml_ineta_w2;                 /* temporary INETA         */
   UNSIG_MED  uml_work;                     /* for shift INETA         */

#ifdef TRACEHL1
   uml_work = ump_ineta;
   m_hlnew_printf( HLOG_XYZ1, "m_check_target_ineta() l%05d adsp_targfi_1=%p INETA=%d.%d.%d.%d Port=%d",
                   __LINE__, adsp_targfi_1,
                   *((unsigned char *) &uml_work + 0),
                   *((unsigned char *) &uml_work + 1),
                   *((unsigned char *) &uml_work + 2),
                   *((unsigned char *) &uml_work + 3),
                   imp_port );
#endif
   imp_port |= ((unsigned char) IPPROTO_TCP) << 24;
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_in_00:                             /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_in_12;                      /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (((unsigned char) *(((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                              + iml_no_targfi_ele_1)->achrc_protocol + iml_no_protocol))
           == IPPROTO_TCP) {
       goto p_cht_in_12;                    /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_in_60;                        /* protocol not found in list */

   p_cht_in_12:                             /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_in_20;                      /* port is valid           */
   }
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (imp_port == *(((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                         + iml_no_targfi_ele_1)->aimrc_port + iml_no_port)) {
       goto p_cht_in_20;                    /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_in_60;                        /* port not found in list  */

   p_cht_in_20:                             /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_netw_mask < 0) {
/* extension 27.03.07 KB - start */
     /* check if neither INETA nor DNS                                 */
     if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
           + iml_no_targfi_ele_1)->achc_dns_name == NULL) {
       goto p_cht_in_40;                    /* this element matches    */
     }
/* extension 27.03.07 KB - end */
     goto p_cht_in_60;                      /* try next element        */
   }
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_netw_mask == 0) {
     goto p_cht_in_40;                      /* this element matches    */
   }
#ifndef __LITTLE_ENDIAN
   uml_work = 0XFFFFFFFF << (32 - ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                    + iml_no_targfi_ele_1)->imc_netw_mask);
#else
   uml_ineta_w1 = 0XFFFFFFFF << (32 - ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                    + iml_no_targfi_ele_1)->imc_netw_mask);
   uml_work = GHFW( uml_ineta_w1 );
#endif
   uml_ineta_w1 = ump_ineta & uml_work;
   uml_ineta_w2 = ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                    + iml_no_targfi_ele_1)->umc_ineta
                      & uml_work;
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_check_target_ineta() l%05d ump_ineta=%08X uml_work=%08X uml_ineta_w1=%08X uml_ineta_w2=%08X",
                   __LINE__, ump_ineta, uml_work, uml_ineta_w1, uml_ineta_w2 );
#endif
   if (uml_ineta_w1 != uml_ineta_w2) {      /* do not match            */
     goto p_cht_in_60;                      /* try next element        */
   }

   p_cht_in_40:                             /* this element matches    */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     return FALSE;                          /* allow, finished         */
   }
   return TRUE;                             /* deny, target not allowed */

   p_cht_in_60:                             /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_in_00;                      /* check next element      */
   }
   return TRUE;                             /* target not allowed      */
} /* end m_check_target_ineta()                                        */
#endif

/** check INETAs against target-filter for TCP connect                 */
static BOOL m_check_target_multiconn( DSD_CONN_G *adsp_conn1,
                                      struct dsd_targfi_1 *adsp_targfi_1,
                                      struct dsd_unicode_string *adsp_ucs_dns_name,
                                      struct dsd_target_ineta_1 *adsp_target_ineta_1,
                                      int imp_port ) {
#ifndef B121114
   BOOL       bol_rc;                       /* return code             */
#endif
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
//---
   int        iml2;                         /* working variable        */
   int        iml_no_dns;                   /* position in DNS response */
//---
   int        iml_port;                     /* port to check           */
   int        iml_no_targfi_ele_1;          /* number of elements      */
   int        iml_no_protocol;              /* number of protocols     */
   int        iml_no_port;                  /* number of ports         */
   int        iml_stack;                    /* position in stack       */
   int        iml_is1_cur;                  /* number current INETA    */
//---
   int        iml_len_soa;                  /* length struct sockaddr_xxx */
//---
   char       *achl_w1;                     /* working variable        */
#ifdef B121114
   char       *achl_mask_cur;               /* current position in mask */
   char       *achl_mask_end;               /* end of mask             */
   char       *achl_inp;                    /* position input          */
#define DEF_MASK_STACK 16
   char       *achrl_sm[ DEF_MASK_STACK ];
   char       *achrl_si[ DEF_MASK_STACK ];
#endif
//---
   char       *achl_inp;                    /* position input          */
//---
   struct dsd_ineta_single_1 *adsl_is1_cur;  /* current INETA          */
   struct hostent *adsl_hostentry;          /* for gethostbyname()     */
   struct addrinfo *adsl_addrinfo_w1;
   struct addrinfo dsl_addrinfo_l;
//---
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   struct dsd_wsp_trace_1 **aadsl_wt1_r1;   /* WSP trace control record */
   struct dsd_wsp_trace_record **aadsl_wtr_r1;  /* WSP trace record    */
   struct sockaddr_storage dsl_soa_l;       /* address information     */
   struct dsd_unicode_string dsl_ucs_l1;    /* Unicode string          */
   struct dsd_unicode_string dsl_ucs_l2;    /* Unicode string          */
   char       byrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
//---
   char       chrl_work1[ 512 ];            /* work area               */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_check_target_multiconn() l%05d adsp_targfi_1=%p adsp_ucs_dns_name=%p adsp_target_ineta_1=%p imp_port=%d - not yet tested (beta)",
                   __LINE__, adsp_targfi_1, adsp_ucs_dns_name, adsp_target_ineta_1, imp_port );
#endif

   iml_port = (((unsigned char) IPPROTO_TCP) << 24) | imp_port;
   if (adsp_targfi_1->boc_with_dns == FALSE) {  /* does not include DNS filter */
     goto p_dns_end;                        /* end of check DNS        */
   }
   if (   (adsp_ucs_dns_name == NULL)
       || (adsp_ucs_dns_name->imc_len_str == 0)) {
     goto p_get_dns_00;                     /* retrieve DNS names from INETAs */
   }
   adsl_hostentry = NULL;                   /* no gethostbyname()      */
   achl_w1 = (char *) adsp_ucs_dns_name->ac_str;
#ifdef B121114
   if (   (adsp_ucs_dns_name->iec_chs_str == D_CHARSET_IP)
       && (adsp_ucs_dns_name->imc_len_str == -1)) {
     goto p_dns_20;                         /* DNS name at achl_w1     */
   }
   iml_rc = m_cpy_vx_ucs( chrl_work1, sizeof(chrl_work1), D_CHARSET_IP,
                          adsp_ucs_dns_name );
#else
   if (   (adsp_ucs_dns_name->iec_chs_str == ied_chs_idna_1)
       && (adsp_ucs_dns_name->imc_len_str == -1)) {
     goto p_dns_20;                         /* DNS name at achl_w1     */
   }
   iml_rc = m_cpy_vx_ucs( chrl_work1, sizeof(chrl_work1), ied_chs_idna_1,
                          adsp_ucs_dns_name );
#endif
   if (iml_rc <= 0) {                       /* did not copy DNS name   */
     m_hlnew_printf( HLOG_INFO1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s check target-filter could not copy DNS name",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     iml_rc );
     return FALSE;
   }
   achl_w1 = chrl_work1;                    /* DNS name at achl_w1     */

   p_dns_20:                                /* DNS name at achl_w1     */
   memset( &dsl_addrinfo_l, 0, sizeof(struct addrinfo) );
   dsl_addrinfo_l.ai_family = AF_UNSPEC;
   dsl_addrinfo_l.ai_flags = AI_NUMERICHOST;
   adsl_addrinfo_w1 = NULL;
   iml_rc = getaddrinfo( achl_w1, NULL, &dsl_addrinfo_l, &adsl_addrinfo_w1 );
   if (iml_rc == 0) {                       /* no error, numeric INETA */
     freeaddrinfo( adsl_addrinfo_w1 );      /* free addresses again    */
     goto p_get_dns_00;                     /* retrieve DNS names from INETAs */
   }
#ifndef HL_UNIX
#define D_TEMP_ERROR WSAHOST_NOT_FOUND
#else
#ifdef B121115
// to-do 13.02.12 KB error number
#define D_TEMP_ERROR EPERM
#else
#define D_TEMP_ERROR EAI_NONAME
#endif
#endif
   if (iml_rc != D_TEMP_ERROR) {            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s check target-filter getaddrinfo() returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     iml_rc, D_TCP_ERROR );
     return FALSE;
   }
#undef D_TEMP_ERROR
   goto p_get_dns_80;                       /* has retrieved DNS name  */

   p_get_dns_00:                            /* retrieve DNS names from INETAs */
   adsl_is1_cur = (struct dsd_ineta_single_1 *) (adsp_target_ineta_1 + 1);  /* current INETA */
   iml_is1_cur = 0;                         /* number current INETA    */

   p_get_dns_20:                            /* get DNS names           */
   adsl_hostentry = gethostbyaddr( (const char *) (adsl_is1_cur + 1),
                                   adsl_is1_cur->usc_length,  /* length of following address */
                                   adsl_is1_cur->usc_family );  /* family IPV4 / IPV6 */
//---
   if ((adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) == 0) {  /* generate WSP trace record */
     goto p_get_dns_40;                     /* WSP-trace done          */
   }
   memset( &dsl_soa_l, 0, sizeof(struct sockaddr_storage) );
   dsl_soa_l.ss_family = adsl_is1_cur->usc_family;
   if (adsl_is1_cur->usc_family == AF_INET) {
     *((UNSIG_MED *) &((struct sockaddr_in *) &dsl_soa_l)->sin_addr) = *((UNSIG_MED *) (adsl_is1_cur + 1) );
     iml_len_soa = sizeof(struct sockaddr_in);
   } else if (adsl_is1_cur->usc_family == AF_INET6) {
     memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr, adsl_is1_cur + 1, 16 );
     iml_len_soa = sizeof(struct sockaddr_in6);
   } else {
     iml_len_soa = 0;
     m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d family %d for getnameinfo() undefined",
                     __LINE__, adsl_is1_cur->usc_family );
   }
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, iml_len_soa,
                         byrl_ineta, sizeof(byrl_ineta), 0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPxxxxW l%05d getnameinfo() returned %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( byrl_ineta, "???" );
   }
   iml1 = 0;                                /* no names found          */
   if (adsl_hostentry) {                    /* API returned entry      */
     if (adsl_hostentry->h_name) iml1 = 1;  /* entry found             */
     iml_no_dns = 0;                        /* position in DNS response */
     while (adsl_hostentry->h_aliases[ iml_no_dns ]) {
       iml_no_dns++;                        /* increment position in DNS response */
     }
     iml1 += iml_no_dns;                    /* number of entries       */
   }
   adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data         */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
   memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN5", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
   adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
   adsl_wt1_w1->imc_wtrt_tid = HL_THRID;    /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
   ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                      "l%05d gethostbyaddr( \"%s\" ) returned %d DNS-names",
                                      __LINE__, byrl_ineta, iml1 );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content                /* content of text / data  */
     = (char *) (ADSL_WTR_G1 + 1);
   adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
   while (adsl_hostentry) {                 /* API returned entry      */
//   aadsl_wt1_r1 = &adsl_wt1_w1->adsc_next;
     aadsl_wt1_r1 = &adsl_wt1_w1->adsc_cont;
     adsl_wtr_w1
       = (struct dsd_wsp_trace_record *) ((char *) (ADSL_WTR_G1 + 1)
                                                     + ADSL_WTR_G1->imc_length
                                                     + sizeof(void *) - 1);
     *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
     aadsl_wtr_r1 = &ADSL_WTR_G1->adsc_next;
     achl_inp = adsl_hostentry->h_name;
     iml_no_dns = -1;                       /* position in DNS response */
     iml1 = 0;                              /* set counter             */
     while (TRUE) {                         /* loop output DNS names   */
       if (achl_inp) {                      /* name found              */
         iml2 = strlen( achl_inp );         /* get length              */
         iml1++;                            /* increment counter       */
#define D_LEN_TEXT 48
         if (((char *) adsl_wtr_w1 + D_LEN_TEXT + iml2)
               > ((char *) adsl_wt1_w2 + LEN_TCP_RECV)) {
           adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w2, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           *aadsl_wt1_r1 = adsl_wt1_w2;
//         aadsl_wt1_r1 = &adsl_wt1_w2->adsc_next;
           aadsl_wt1_r1 = &adsl_wt1_w2->adsc_cont;
           adsl_wtr_w1 = (struct dsd_wsp_trace_record *) (adsl_wt1_w2 + 1);
         }
#undef D_LEN_TEXT
         memset( adsl_wtr_w1, 0, sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wtr_w1->imc_length
           = sprintf( (char *) (adsl_wtr_w1 + 1),
                      "l%05d found DNS-name %d. \"%.*s\"",
                      __LINE__, iml1, iml2, achl_inp );
         adsl_wtr_w1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         adsl_wtr_w1->achc_content          /* content of text / data  */
           = (char *) (adsl_wtr_w1 + 1);
         *aadsl_wtr_r1 = adsl_wtr_w1;
         aadsl_wtr_r1 = &adsl_wtr_w1->adsc_next;
         *((size_t *) &adsl_wtr_w1)
           += sizeof(struct dsd_wsp_trace_record)
                + adsl_wtr_w1->imc_length
                + sizeof(void *) - 1;
         *((size_t *) &adsl_wtr_w1) &= 0 - sizeof(void *);
       }
       iml_no_dns++;                        /* position in DNS response */
       achl_inp = adsl_hostentry->h_aliases[ iml_no_dns ];
       if (achl_inp == NULL) break;         /* end of DNS names        */
     }
     break;
   }
#undef ADSL_WTR_G1
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */

   p_get_dns_40:                            /* WSP-trace done          */
//---
   if (adsl_hostentry == NULL) goto p_next_dns_40;  /* try next element in target INETA */
   achl_w1 = adsl_hostentry->h_name;
   iml1 = 0;                                /* to check aliases        */

   p_get_dns_80:                            /* has retrieved DNS name  */
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_dns_00:                            /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_dns_12;                     /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (*((unsigned char *) adsp_targfi_1
            + (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                  + iml_no_targfi_ele_1)->imc_off_protocol + iml_no_protocol))
           == IPPROTO_TCP) {
       goto p_cht_dns_12;                   /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_dns_60;                       /* protocol not found in list */

   p_cht_dns_12:                            /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_dns_20;                     /* port is valid           */
   }
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (iml_port == *((int *) ((char *) adsp_targfi_1
                                  + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                       + iml_no_targfi_ele_1)->imc_off_port)
                                + iml_no_port)) {
       goto p_cht_dns_20;                   /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_dns_60;                       /* port not found in list  */

   p_cht_dns_20:                            /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_dns_name == 0) {
#ifdef B110205
     /* check if neither INETA nor DNS                                 */
// to-do 06.01.11 KB - == 0 or != 0
     if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_len_ineta == 0) {
       goto p_cht_dns_40;                   /* this element matches    */
     }
#endif
     goto p_cht_dns_60;                     /* ignore this element     */
   }
#ifdef B121114
   iml_stack = 0;                           /* clear stack index       */
   achl_mask_cur = (char *) adsp_targfi_1
                     + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                           + iml_no_targfi_ele_1)->imc_off_dns_name;
   achl_mask_end = achl_mask_cur
                     + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                           + iml_no_targfi_ele_1)->imc_len_dns_name;
   achl_inp = achl_w1;                      /* start of input to compare */

   plook00:
   if (achl_mask_cur >= achl_mask_end) goto plook60;
   switch (*achl_mask_cur) {
     case '*':
       goto plook40;
     case '?':
       goto plook20;
     default:
       if (tabaau[(unsigned char) *achl_mask_cur] == tabaau[(unsigned char) *achl_inp]) {
         achl_mask_cur++;
         achl_inp++;
         goto plook00;
       }
       goto plook62;
   }

   plook20:                                 /* single wildcard         */
   if (*achl_inp == 0) goto plook62;        /* character follows       */
   achl_inp++;                              /* next character input    */
   achl_mask_cur++;
   if (achl_mask_cur >= achl_mask_end) goto plook60;
   if (*achl_mask_cur == '?') goto plook20;
   if (*achl_mask_cur == '*') goto plook40;  /* asterix found          */
   goto plook00;

   plook40:                                 /* asterix wildcard        */
   achl_mask_cur++;
   if (achl_mask_cur >= achl_mask_end) goto plook44;  /* end found     */
   if (*achl_mask_cur == '*') goto plook40;
   if (*achl_mask_cur == '?') {
     achl_inp++;                            /* next character input    */
     goto plook40;
   }

   plook44:                                 /* characters do not match */
   if (iml_stack == DEF_MASK_STACK) {       /* stack overflow          */
     goto p_cht_dns_60;                     /* mask does not match     */
   }
   achrl_sm[iml_stack] = achl_mask_cur;
   achrl_si[iml_stack] = achl_inp;
   iml_stack++;
   goto plook00;

   plook60:                                 /* end of DNS-name         */
   if (*achl_inp == 0) goto p_cht_dns_40;   /* no more characters      */

   plook62:                                 /* end of DNS-name         */
   if (iml_stack == 0) {                    /* no more in table        */
     goto p_cht_dns_60;                     /* mask does not match     */
   }
   achrl_si[iml_stack - 1]++;
   achl_mask_cur = achrl_sm[iml_stack - 1];
   if (achl_mask_cur >= achl_mask_end) goto p_cht_dns_40;  /* end already found */
   achl_inp = achrl_si[iml_stack - 1];
   if (*achl_inp) goto plook00;
   iml_stack--;
   goto plook62;

   p_cht_dns_40:                            /* this element matches    */
#endif
#ifndef B121114
   bol_rc = m_cmp_wc_i_vx_vx( &iml_rc,
                              achl_w1, -1, ied_chs_idna_1,
                              (char *) adsp_targfi_1
                                + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                     + iml_no_targfi_ele_1)->imc_off_dns_name,
                              ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_len_dns_name,
                              ied_chs_utf_8 );
//---
//------
   if (adsp_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     dsl_ucs_l1.ac_str = achl_inp;          /* address of string       */
     dsl_ucs_l1.imc_len_str = -1;           /* length string in elements */
     dsl_ucs_l1.iec_chs_str = ied_chs_idna_1;  /* character set string */
     dsl_ucs_l2.ac_str                      /* address of string       */
       = (char *) adsp_targfi_1
            + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                 + iml_no_targfi_ele_1)->imc_off_dns_name;
     dsl_ucs_l2.imc_len_str                 /* length string in elements */
       = ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
            + iml_no_targfi_ele_1)->imc_len_dns_name,
     dsl_ucs_l2.iec_chs_str = ied_chs_utf_8;  /* character set string  */
     achl_w1 = "FALSE";
     if (   (bol_rc)
         && (iml_rc == 0)) {
       achl_w1 = "TRUE ";
     }

     adsl_wt1_w1 = adsl_wt1_w2 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNETFDN6", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length
       = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1),
                       ((char *) adsl_wt1_w1 + LEN_TCP_RECV)
                         - ((char *) (ADSL_WTR_G1 + 1)),
                       ied_chs_utf_8,
                       "-- l%05d compare %s %(ucs)s %(ucs)s.",
                       __LINE__, achl_w1, &dsl_ucs_l1, &dsl_ucs_l2 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
//---
   if (   (bol_rc == FALSE)
       || (iml_rc != 0)) {
     goto p_cht_dns_60;                     /* mask does not match     */
   }
#endif
#ifdef B110205
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     goto p_next_dns_00;                    /* allow, finished         */
   }
   return FALSE;                            /* deny, target not allowed */
#else
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow == FALSE) {
     return FALSE;                          /* deny, target not allowed */
   }
   /* check if neither INETA nor DNS                                   */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_ineta == 0) {
     return TRUE;                           /* this element matches    */
   }
   goto p_dns_end;                          /* end of check DNS        */
#endif

   p_cht_dns_60:                            /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_dns_00;                     /* check next element      */
   }
#ifdef B110203
   return FALSE;                            /* target not allowed      */
#endif

   p_next_dns_00:                           /* this DNS name is valid  */
   if (adsl_hostentry == NULL) {            /* DNS name explicitly given */
     goto p_dns_end;                        /* allow, finished         */
   }
   achl_w1 = adsl_hostentry->h_aliases[iml1];
   iml1++;                                  /* to check aliases        */
   if (achl_w1) goto p_get_dns_80;          /* has retrieved DNS name  */

   p_next_dns_40:                           /* try next element in target INETA */
   iml_is1_cur++;                           /* number current INETA    */
   if (iml_is1_cur < adsp_target_ineta_1->imc_no_ineta) {  /* check number of INETA */
     adsl_is1_cur = (struct dsd_ineta_single_1 *) ((char *) (adsl_is1_cur + 1) + adsl_is1_cur->usc_length);  /* next INETA */
     goto p_get_dns_20;                     /* get DNS names           */
   }

   p_dns_end:                               /* end of check DNS        */
   adsl_is1_cur = (struct dsd_ineta_single_1 *) (adsp_target_ineta_1 + 1);  /* current INETA */
   iml_is1_cur = 0;                         /* number current INETA    */

   p_check_tf:                              /* check target-filter     */
   iml_no_targfi_ele_1 = 0;                 /* clear index of elements */

   p_cht_in_00:                             /* check one element       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_protocol == 0) {
     goto p_cht_in_12;                      /* protocol is valid       */
   }
   iml_no_protocol = 0;                     /* clear index of protocols */
   do {
     if (*((unsigned char *) adsp_targfi_1
            + (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                  + iml_no_targfi_ele_1)->imc_off_protocol + iml_no_protocol))
           == IPPROTO_TCP) {
       goto p_cht_in_12;                    /* protocol is valid       */
     }
     iml_no_protocol++;                     /* increment index of protocols */
   } while (iml_no_protocol < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                 + iml_no_targfi_ele_1)->imc_no_protocol);
   goto p_cht_in_60;                        /* protocol not found in list */

   p_cht_in_12:                             /* protocol is valid       */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_no_port == 0) {
     goto p_cht_in_20;                      /* port is valid           */
   }
   iml_no_port = 0;                         /* clear index of ports    */
   do {
     if (iml_port == *((int *) ((char *) adsp_targfi_1
                                  + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                                      + iml_no_targfi_ele_1)->imc_off_port)
                                + iml_no_port)) {
       goto p_cht_in_20;                    /* port is valid           */
     }
     iml_no_port++;                         /* increment index of ports */
   } while (iml_no_port < ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                            + iml_no_targfi_ele_1)->imc_no_port);
   goto p_cht_in_60;                        /* port not found in list  */

   p_cht_in_20:                             /* port is valid           */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_ineta == 0) {
#ifdef B110131
     /* check if neither INETA nor DNS                                 */
     if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_len_dns_name == 0) {
       goto p_cht_in_40;                    /* this element matches    */
     }
     goto p_cht_in_60;                      /* try next element        */
#endif
#ifdef NONSENSE
     if (adsp_targfi_1->boc_with_dns) {     /* does include DNS filter */
       goto p_cht_in_40;                    /* this element matches    */
     }
     goto p_cht_in_60;                      /* try next element        */
#endif
#ifdef B110203
     goto p_cht_in_40;                      /* this element matches    */
#endif
     /* check if neither INETA nor DNS                                 */
     if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
           + iml_no_targfi_ele_1)->imc_len_dns_name == 0) {
       goto p_cht_in_40;                    /* this element matches    */
     }
     goto p_cht_in_60;                      /* try next element        */
   }
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_len_ineta != adsl_is1_cur->usc_length) {
     goto p_cht_in_60;                      /* try next element        */
   }
   achl_w1 = (char *) (adsl_is1_cur + 1);   /* here is INETA           */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->imc_prefix_ineta) {  /* prefix of INETA */

     memcpy( chrl_work1, achl_w1, adsl_is1_cur->usc_length );
     achl_w1 = chrl_work1 + adsl_is1_cur->usc_length;  /* end of INETA */
     iml1 = adsl_is1_cur->usc_length * 8
              - (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                  + iml_no_targfi_ele_1)->imc_prefix_ineta);  /* prefix of INETA */
     while (iml1 >= 8) {                    /* clear one byte          */
       *(--achl_w1) = 0;                    /* clear this byte         */
       iml1 -= 8;                           /* decrement number of bits */
     }
     achl_w1--;                             /* byte before             */
     *achl_w1 &= 0XFF << iml1;              /* clear remaining bits    */
     achl_w1 = chrl_work1;                  /* here is INETA           */
   }
   /* check if INETA matches                                           */
   if (memcmp( achl_w1,
               (char *) adsp_targfi_1
                 + ((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
                     + iml_no_targfi_ele_1)->imc_off_ineta,
               adsl_is1_cur->usc_length )) {
     goto p_cht_in_60;                      /* try next element        */
   }

   p_cht_in_40:                             /* this element matches    */
   if (((struct dsd_targfi_ele_1 *) (adsp_targfi_1 + 1)
         + iml_no_targfi_ele_1)->boc_allow) {
     goto p_tf_ok;                          /* allow, finished         */
   }
   return FALSE;                            /* deny, target not allowed */

   p_cht_in_60:                             /* next element            */
   iml_no_targfi_ele_1++;                   /* increment index of elements */
   if (iml_no_targfi_ele_1 < adsp_targfi_1->imc_no_targfi_ele_1) {
     goto p_cht_in_00;                      /* check next element      */
   }
#ifndef B160503
   if (adsp_targfi_1->boc_blacklist) {      /* use-as-blacklist        */
     return TRUE;                           /* no deny found           */
   }
#endif
   return FALSE;                            /* deny, target not allowed */

   p_tf_ok:                                 /* target-filter o.k.      */
   iml_is1_cur++;                           /* number current INETA    */
   if (iml_is1_cur >= adsp_target_ineta_1->imc_no_ineta) return TRUE;  /* check number of INETA */
   adsl_is1_cur = (struct dsd_ineta_single_1 *) ((char *) (adsl_is1_cur + 1) + adsl_is1_cur->usc_length);  /* next INETA */
   goto p_check_tf;                         /* check target-filter     */
} /* end m_check_target_multiconn()                                    */

/** start WTS loadbalancing over UDP                                   */
static void m_lbal_udp_start( DSD_CONN_G *adsp_conn1 ) {
   int        iml_rc;                       /* return code             */
#ifdef HL_UNIX
   int        iml1;                         /* working variable        */
#endif
   BOOL       bol_broadcast;
   struct dsd_wts_udp_1 *adsl_wtsudp1;      /* WTS UDP                 */
   struct dsd_wtsg_1 *adsl_wtsg1_w1;        /* for WTSGATE             */
   struct dsd_server_conf_1 *adsl_server_conf_1;  /* configuration server */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_lbal_udp_start() l%05d adsp_conn1=%p.",
                   __LINE__, adsp_conn1 );
#endif
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
   m_hlnew_printf( HLOG_TRACE1, "m_lbal_udp_start() l%05d adsp_conn1=%p adsp_conn1->adsc_wtsudp1=%p.",
                   __LINE__, adsp_conn1, adsp_conn1->adsc_wtsudp1 );
#endif
   adsl_server_conf_1 = adsp_conn1->adsc_server_conf_1;  /* configuration server */
   /* area for UDP processing                                        */
   adsl_wtsudp1 = (struct dsd_wts_udp_1 *) malloc( sizeof(struct dsd_wts_udp_1) );
   memset( adsl_wtsudp1, 0, sizeof(struct dsd_wts_udp_1) );
   adsl_wtsudp1->ac_conn1 = adsp_conn1;     /* address connection      */
   adsl_wtsg1_w1 = adsl_server_conf_1->adsc_wtsg1;
   if (adsl_wtsg1_w1 == NULL) {             /* do only broadcast IPV4  */
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = adsl_wtsudp1;  /* WTS UDP - also means in use */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
   do {                                     /* loop over configured servers */
     adsl_wtsudp1->imc_no_target++;         /* count number of targets */
     if (adsl_wtsg1_w1->dsc_soa.ss_family == AF_INET) {  /* IPV4       */
       adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = adsl_wtsudp1;  /* WTS UDP - also means in use */
     } else {                               /* IPV6                    */
       adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = adsl_wtsudp1;  /* WTS UDP - also means in use */
     }
     adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain   */
   } while (adsl_wtsg1_w1);
   if (adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 == NULL) {  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
   if (adsl_server_conf_1->dsc_bind_out.boc_ipv6 == FALSE) {  /* IPV6 is not supported */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d target IPV6 but bind not supported",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__ );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
#define ADSL_UM1_G (&adsl_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1)
   ADSL_UM1_G->imc_socket = socket( AF_INET6, SOCK_DGRAM, 0 );
   if (ADSL_UM1_G->imc_socket < 0) {        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d socket() IPV6 returned error %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, D_TCP_ERROR );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
   iml_rc = bind( ADSL_UM1_G->imc_socket,
                  (struct sockaddr *) &adsl_server_conf_1->dsc_bind_out.dsc_soai6, sizeof(struct sockaddr_in6) );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d bind() IPV6 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
#ifndef HL_UNIX
   ADSL_UM1_G->dsc_event = WSACreateEvent();  /* create event for recv */
   if (ADSL_UM1_G->dsc_event == WSA_INVALID_EVENT) {  /* error occured */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d WSACreateEvent() IPV6 returned error %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
   iml_rc = WSAEventSelect( ADSL_UM1_G->imc_socket,
                            ADSL_UM1_G->dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d WSAEventSelect() IPV6 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     WSACloseEvent( ADSL_UM1_G->dsc_event );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
#endif
#ifdef HL_UNIX
   /* set the UDP socket to non-blocking                               */
   iml1 = fcntl( ADSL_UM1_G->imc_socket, F_GETFL, 0 );
   iml_rc = fcntl( ADSL_UM1_G->imc_socket, F_SETFL, iml1 | O_NONBLOCK );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d fcntl() IPV6 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV6 */
     goto p_sta_ipv4_00;                    /* start IPV4              */
   }
#endif
   ADSL_UM1_G->amc_udp_recv_compl = &m_lbal_udp_cb_recv;  /* callback when receive complete */
   m_start_udp_recv( ADSL_UM1_G );
#undef ADSL_UM1_G

   p_sta_ipv4_00:                           /* start IPV4              */
   if (adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 == NULL) {  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
   if (adsl_server_conf_1->dsc_bind_out.boc_ipv4 == FALSE) {  /* IPV4 is not supported */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d target IPV4 but bind not supported",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__ );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
#define ADSL_UM1_G (&adsl_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1)
   ADSL_UM1_G->imc_socket = socket( AF_INET, SOCK_DGRAM, 0 );
   if (ADSL_UM1_G->imc_socket < 0) {        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d socket() IPV4 returned error %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, D_TCP_ERROR );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
   iml_rc = bind( ADSL_UM1_G->imc_socket,
                  (struct sockaddr *) &adsl_server_conf_1->dsc_bind_out.dsc_soai4, sizeof(struct sockaddr_in) );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d bind() IPV4 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
#ifndef HL_UNIX
   ADSL_UM1_G->dsc_event = WSACreateEvent();  /* create event for recv */
   if (ADSL_UM1_G->dsc_event == WSA_INVALID_EVENT) {  /* error occured */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d WSACreateEvent() IPV4 returned error %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
   iml_rc = WSAEventSelect( ADSL_UM1_G->imc_socket,
                            ADSL_UM1_G->dsc_event,
                            FD_WRITE | FD_READ | FD_CLOSE );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d WSAEventSelect() IPV4 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     WSACloseEvent( ADSL_UM1_G->dsc_event );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
#endif
#ifdef HL_UNIX
   /* set the UDP socket to non-blocking                               */
   iml1 = fcntl( ADSL_UM1_G->imc_socket, F_GETFL, 0 );
   iml_rc = fcntl( ADSL_UM1_G->imc_socket, F_SETFL, iml1 | O_NONBLOCK );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d fcntl() IPV4 returned %d %d.",
                     adsp_conn1->adsc_gate1 + 1,
                     adsp_conn1->dsc_co_sort.imc_sno,
                     adsp_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     D_TCP_CLOSE( ADSL_UM1_G->imc_socket );
     adsl_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1 = NULL;  /* no WTS UDP IPV4 */
     goto p_sta_ipv4_80;                    /* end of IPV4             */
   }
#endif
   if (adsl_wtsudp1->imc_no_target == 0) {  /* send broadcast          */
     bol_broadcast = TRUE;
     iml_rc = setsockopt( ADSL_UM1_G->imc_socket,
                          SOL_SOCKET, SO_BROADCAST,
                          (const char *) &bol_broadcast, sizeof(bol_broadcast) );
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s start UDP WTS load-balancing l%05d UDP setsockopt( ... SO_BROADCAST ... ) returned %d %d.",
                       adsp_conn1->adsc_gate1 + 1,
                       adsp_conn1->dsc_co_sort.imc_sno,
                       adsp_conn1->chrc_ineta,
                       __LINE__, iml_rc, D_TCP_ERROR );
     }
   }
   ADSL_UM1_G->amc_udp_recv_compl = &m_lbal_udp_cb_recv;  /* callback when receive complete */
   m_start_udp_recv( ADSL_UM1_G );
#undef ADSL_UM1_G

   p_sta_ipv4_80:                           /* end of IPV4             */
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
   m_hlnew_printf( HLOG_TRACE1, "m_lbal_udp_start() l%05d adsp_conn1=%p adsl_wtsudp1=%p.",
                   __LINE__, adsp_conn1, adsl_wtsudp1 );
   if (adsp_conn1->adsc_wtsudp1) {
     m_hlnew_printf( HLOG_TRACE1, "m_lbal_udp_start() l%05d adsp_conn1=%p adsp_conn1->adsc_wtsudp1=%p adsl_wtsudp1=%p DEBUG_140118_01 !!! error !!!.",
                     __LINE__, adsp_conn1, adsp_conn1->adsc_wtsudp1, adsl_wtsudp1 );
   }
#endif
   adsp_conn1->adsc_wtsudp1 = adsl_wtsudp1;
} /* end m_lbal_udp_start()                                            */

/** callback for receiving loadbalacing packets on a UDP socket        */
static void m_lbal_udp_cb_recv( struct dsd_udp_multiw_1 *adsp_udp_multiw_1,
                                struct dsd_sdh_control_1 *adsp_sdhc1_rb ) {
   BOOL       bol1;                         /* working-variable        */
   struct dsd_wts_lbal_netw *adsl_wln_w1;   /* loadbalancing networking */
   struct dsd_wts_udp_1 *adsl_wtsudp1;      /* WTS UDP                 */
   DSD_CONN_G *adsl_conn1_l;                /* connection              */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
#ifdef XYZ1
   BOOL       bol_overflow_attr;            /* overflow of attribute storage */
   BOOL       bol_overflow_server_state;    /* overflow of server state storage */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   char       *achl_packet_sta;             /* start of packet         */
   char       *achl_packet_end;             /* end of packet           */
   char       *achlttr;                   /* pass attributes         */
   char       *achl_server_state;           /* save server state       */
   struct dsd_radius_netw_1 *adsl_rn1;      /* radius networking       */
   struct dsd_radius_entry *adsl_re_w1;     /* radius-server           */
   struct dsd_radius_control_1 *adsl_rctrl1;  /* radius control        */
   struct dsd_hl_aux_radius_1 *adsl_rreq;   /* radius request          */
   int        imrl_md5_array[ 24 ];         /* for MD5                 */
   char       chrl_work1[ 16 ];             /* work area MD5           */
#endif

#define ADSL_RECB_1_G ((struct dsd_sdh_udp_recbuf_1 *) (adsp_sdhc1_rb + 1))

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d m_lbal_udp_cb_recv( %p , %p ) called ADSL_RECB_1_G=%p.",
                   __LINE__, adsp_udp_multiw_1, adsp_sdhc1_rb, ADSL_RECB_1_G );
#endif
   /* ignore records with error                                        */
   if (ADSL_RECB_1_G->imc_len_data <= 0) {  /* length of data          */
     m_proc_free( adsp_sdhc1_rb );          /* free memory             */
     return;                                /* all done                */
   }

   adsl_wln_w1 = (struct dsd_wts_lbal_netw *) ((char *) adsp_udp_multiw_1
                                                 - offsetof( struct dsd_wts_lbal_netw, dsc_udp_multiw_1 ));
   adsl_wtsudp1 = adsl_wln_w1->adsc_wsp_udp_1;  /* WTS UDP - also means in use */
   adsl_conn1_l = (DSD_CONN_G *) adsl_wtsudp1->ac_conn1;  /* address connection */

   bol1 = FALSE;                            /* do not activate thread  */

#ifndef HL_UNIX
   EnterCriticalSection( &adsl_conn1_l->d_act_critsect );  /* critical section act */
#else
   adsl_conn1_l->dsc_critsect.m_enter();    /* critical section        */
#endif
#ifdef DEBUG_140701_01                      /* deadlock - critical section */
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-seli.cpp l%05d %08d %p after adsp_conn1->dsc_critsect.m_enter()",
                   __LINE__, HL_THRID, &adsl_conn1_l->dsc_critsect );
#endif
   if (adsl_wtsudp1->adsc_sdhc1_rec == NULL) {  /* no received UDP packets */
     adsl_wtsudp1->adsc_sdhc1_rec = adsp_sdhc1_rb;  /* set received UDP packets */
   } else {                                 /* append to chain         */
     adsl_sdhc1_w1 = adsl_wtsudp1->adsc_sdhc1_rec;  /* get received UDP packets */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w1->adsc_next = adsp_sdhc1_rb;  /* set received UDP packets */
   }
#ifndef HL_UNIX
   if (   (adsl_conn1_l->boc_st_act == FALSE)  /* thread with connection not active */
       && (adsl_conn1_l->dcl_tcp_r_c.m_check_send_act() == FALSE)) {
     adsl_conn1_l->boc_st_act = TRUE;       /* connection has thread now */
     bol1 = TRUE;                           /* activate thread         */
   }
#else
   if (   (adsl_conn1_l->boc_st_act == FALSE)  /* thread with connection not active */
       && (adsl_conn1_l->dsc_tc1_client.adsc_sdhc1_send == NULL)) {  /* check flow client */
     adsl_conn1_l->boc_st_act = TRUE;       /* connection has thread now */
     bol1 = TRUE;                           /* activate thread         */
   }
#endif
#ifndef HL_UNIX
   LeaveCriticalSection( &adsl_conn1_l->d_act_critsect );  /* critical section act */
#else
   adsl_conn1_l->dsc_critsect.m_leave();    /* critical section        */
#endif

   if (bol1) {
     m_act_thread_2( adsl_conn1_l );        /* activate m_proc_data()  */
   }

#undef ADSL_RECB_1_G
} /* end m_lbal_udp_cb_recv()                                          */

/** set a timer for a session / connection                             */
static void HLGW_set_timer( void *apparam, int imp_time ) {
   struct dsd_cid dsl_cid;                  /* component identifier    */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HLGW_set_timer apparam=%p iptime=%d",
                   apparam, imp_time );
#endif
#define ADSL_CONN1_G ((DSD_CONN_G *) apparam)
#ifdef B130314
   m_aux_timer_new( ADSL_CONN1_G, ied_src_fu_lbal, NULL, imp_time * 1000 );
#endif
   memset( &dsl_cid, 0, sizeof(struct dsd_cid) );  /* component identifier */
   dsl_cid.iec_src_func = ied_src_fu_lbal;
   m_aux_timer_new( ADSL_CONN1_G, &dsl_cid, imp_time * 1000, ied_auxtu_normal );
   ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set = TRUE;
   return;
#undef ADSL_CONN1_G
} /* end HLGW_set_timer()                                              */

#define D_LOAD_BAL_R1                       /* random processing       */
/** send load-balancing UDP packets                                    */
static void HLGW_sendto_LB( void *apparam, char *achp_buf, int imp_sendlen ) {
   int        iml1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_wts_udp_1 *adsl_wtsudp1;      /* WTS UDP                 */
   struct dsd_wtsg_1 *adsl_wtsg1_w1;        /* for WTSGATE             */
   struct dsd_wts_lbal_netw *adsl_wln_w1;   /* loadbalancing networking */
   struct sockaddr *adsl_soa_w1;            /* working variable        */
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   char       *achl1;                       /* working-variable        */
   int        iml_lb_rand;                  /* random position         */
   char       *achl_lbal_tab;               /* address of array        */
   char       chrl_lbal_tab[ 256 ];         /* array load balanced sent */
#endif
   struct sockaddr_in dsl_soa_broadcast;    /* client address information */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "HLGW_sendto_LB apparam=%p achp_buf=%p imp_sendlen=%d",
                   apparam, achp_buf, imp_sendlen );
#endif
#define ADSL_CONN1_G ((DSD_CONN_G *) apparam)
   adsl_wtsudp1 = ADSL_CONN1_G->adsc_wtsudp1;  /* WTS UDP              */
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml_lb_rand = 0;                         /* clear random position   */
   achl_lbal_tab = chrl_lbal_tab;           /* pointer on array        */
#endif
   adsl_wtsg1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1;
   if (adsl_wtsg1_w1 == NULL) {             /* do broadcast            */
     memset( &dsl_soa_broadcast, 0, sizeof(struct sockaddr_in) );
     dsl_soa_broadcast.sin_family = AF_INET;
     dsl_soa_broadcast.sin_port
       = htons( ADSL_CONN1_G->adsc_server_conf_1->inc_wts_br_port );
     dsl_soa_broadcast.sin_addr.s_addr = 0XFFFFFFFF;  /* set broadcast */
     adsl_soa_w1 = (struct sockaddr *) &dsl_soa_broadcast;
     adsl_wln_w1 = &adsl_wtsudp1->dsc_wln_ipv4;  /* loadbalancing networking IPV4 */
     iml1 = sizeof(struct sockaddr_in);
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "HLGW_sendto_LB send broadcast port=%d",
                     ADSL_CONN1_G->adsc_server_conf_1->inc_wts_br_port );
#endif
     goto pstlb40;                          /* send to LB              */
   }
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml_lb_rand = adsl_wtsudp1->imc_no_target;  /* start with count     */
   if (iml_lb_rand > sizeof(chrl_lbal_tab)) {
     achl_lbal_tab = (char *) malloc( iml_lb_rand );
   }
   memset( achl_lbal_tab, 0, iml_lb_rand );
#endif

   pstlb20:                                 /* send to next LB         */
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml1 = m_get_random_number( iml_lb_rand );
   adsl_wtsg1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1;
   achl1 = achl_lbal_tab;                   /* start of table          */
   while (TRUE) {                           /* loop over array         */
     if (*achl1 == 0) {                     /* entry not yet used      */
       if (iml1 == 0) break;                /* target position reached */
       iml1--;                              /* count random position   */
     }
     achl1++;                               /* next entry in array     */
     adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain   */
   }
   *achl1 = 1;                              /* mark element used       */
   iml_lb_rand--;                           /* one entry less          */
#endif
   if (adsl_wtsg1_w1->dsc_soa.ss_family == AF_INET) {  /* IPV4         */
     adsl_wln_w1 = &adsl_wtsudp1->dsc_wln_ipv4;   /* loadbalancing networking IPV4 */
     iml1 = sizeof(struct sockaddr_in);
   } else {                                 /* IPV6                    */
     adsl_wln_w1 = &adsl_wtsudp1->dsc_wln_ipv6;   /* loadbalancing networking IPV6 */
     iml1 = sizeof(struct sockaddr_in6);
   }
   adsl_soa_w1 = (struct sockaddr *) &adsl_wtsg1_w1->dsc_soa;
#ifndef D_LOAD_BAL_R1                       /* random processing       */
   adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain     */
#endif

   pstlb40:                                 /* send to LB              */
   if (adsl_wln_w1->adsc_wsp_udp_1 == NULL) {  /* no WTS UDP IPV4 / IPV6 */
     goto pstlb60;                          /* after send to LB        */
   }
   iml_rc = m_udp_sendto( &adsl_wln_w1->dsc_udp_multiw_1,  /* structure for multiple wait */
                          achp_buf, imp_sendlen,
                          adsl_soa_w1, iml1,
                          &iml_error );
   if (iml_rc <= 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s send UDP WTS load-balancing l%05d returned %d %d.",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     __LINE__, iml_rc, iml_error );
   }

   pstlb60:                                 /* after send to LB        */
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   if (iml_lb_rand) goto pstlb20;           /* send to next LB         */
   if (achl_lbal_tab != chrl_lbal_tab) {    /* check pointer on array  */
     free( achl_lbal_tab );                 /* free array              */
   }
#else
   if (adsl_wtsg1_w1) goto pstlb20;         /* send to next LB         */
#endif
#undef ADSL_CONN1_G
} /* end HLGW_sendto_LB()                                              */

/** start connection to server for WTS load-balancing or VDI           */
static int HLGW_start_conn( void *apparam,
                            struct sockaddr *adsp_soa ) {
   int        iml1;                         /* working variable        */
   struct dsd_cid dsl_cid;                  /* component identifier    */

#define ADSL_CONN1_G ((DSD_CONN_G *) apparam)
#ifdef B120211
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HLGW_start_conn( apparam=%p, adsp_soa=%p )",
                   apparam,
                   ump_ineta & 0XFF, ((ump_ineta >> 8) & 0XFF),
                   ((ump_ineta >> 16) & 0XFF), ((ump_ineta >> 24) & 0XFF),
                   imp_port );
#endif
#endif
#ifdef TRYCONNE
   int iu1 = 1;
   if (iu1) {
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server */
     m_hlnew_printf( HLOG_XYZ1, "HLGW_start_conn TRYCONE" );
     return iu1;
   }
#endif
   /* connect was successfull                                          */
#ifdef B060616
   if (ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket >= 0) {  /* socket open     */
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_close_active = TRUE;
     IP_closesocket( ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket );
     ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket = -1;
   }
#endif
#ifdef XYZ1
   if (ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed == FALSE) {  /* UDP socket not closed */
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_close_active = TRUE;
     IP_closesocket( ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket );
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed = TRUE;  /* UDP socket closed  */
   }
   while (ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1) {
     adsl_recudp1_w1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1;
     ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1->adsc_next;
     free( adsl_recudp1_w1 );
   }
#endif
   if (ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set) {
#ifdef B130314
     m_aux_timer_del( ADSL_CONN1_G, ied_src_fu_lbal, NULL );
#endif
     memset( &dsl_cid, 0, sizeof(struct dsd_cid) );  /* component identifier */
     dsl_cid.iec_src_func = ied_src_fu_lbal;
     m_aux_timer_del( ADSL_CONN1_G, &dsl_cid );
     ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set = FALSE;
   }
   iml1 = ADSL_CONN1_G->adsc_gate1->itimeout;  /* from GATE              */
   if (ADSL_CONN1_G->adsc_server_conf_1) {    /* server connected        */
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
   }
#ifndef HL_UNIX
   return ((class clconn1 *) apparam)->mc_conn_server( ADSL_CONN1_G->adsc_aux_cf1_cur, adsp_soa );
#else
// to-do 11.02.12 KB
   return m_tcp_sa_conn_server( ADSL_CONN1_G->adsc_aux_cf1_cur, adsp_soa );
#endif
#undef ADSL_CONN1_G
} /* end HLGW_start_conn()                                             */

/** check name of WTS load-balancing / VDI against authentication to WSP */
static int HLGW_check_name( void *apparam,
                            char *apname, int iplenname,
                            char *apdomain, int iplendomain ) {
   int iu1;
#ifndef NO_NAME_UNICODE
   int        inl1, inl2, inl3;             /* working variables       */
#endif
   char *au1, *au2;
   char *al1;                               /* working variable        */
   char byarruwork1[512];                   /* working variable        */
   char byarruwork2[512];                   /* working variable        */
   HL_WCHAR   wcharruwork1[256];            /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[512];
#ifdef TRACEHL1
   char *ah1, *ah2;
   ah1 = ah2 = "--- not defined ---";
   if (iplenname) ah1 = apname;
   if (iplendomain) ah2 = apdomain;
   m_hlnew_printf( HLOG_XYZ1, "HLGW_check_name name=%s domain=%s", ah1, ah2 );
#endif
#define auclconn11 ((DSD_CONN_G *) apparam)
//#define NO_NAME_UNICODE
#ifdef NO_NAME_UNICODE
   if (iplenname) {
     iu1 = sprintf( byarruwork1, "user-name: " );
     memcpy( byarruwork2, byarruwork1, iu1 );
     au1 = &byarruwork1[iu1];
     au2 = &byarruwork2[iu1];
     for ( iu1 = 0; iu1 < iplenname; iu1++ ) {
       *au1++ = ucrg_tab_819_to_850[ *(apname + iu1) ];
       *au2++ = *(apname + iu1);
       wcharruwork1[iu1] = *(apname + iu1);
     }
     if (iplendomain) {
       sprintf( au1, " domain-name: " );
       iu1 = strlen( byarruwork1 );
       au1 = &byarruwork1[iu1];
       for ( iu1 = 0; iu1 < iplendomain; iu1++ ) {
         *au1++ = ucrg_tab_819_to_850[ *(apdomain + iu1) ];
         *au2++ = *(apdomain + iu1);
       }
     }
     *au1 = 0;                              /* make zero-terminated    */
     *au2 = 0;                              /* make zero-terminated    */
   } else {
     iu1 = sprintf( byarruwork1, "no user-name" );
     memcpy( byarruwork2, byarruwork1, iu1 + 1 );
   }
#else
   if (iplenname) {
     inl3 = m_u16l_from_u8l( wcharruwork1, sizeof(wcharruwork1) / sizeof(wcharruwork1[0]) - 1,
                             apname, iplenname );
     wcharruwork1[inl3] = 0;                /* make zero-terminated    */
     inl1 = inl2 = sprintf( byarruwork1, "user-name: " );
     memcpy( byarruwork2, byarruwork1, inl1 );
     inl1 += m_a850l_from_u8l( &byarruwork1[inl1], sizeof(byarruwork1) - inl1 - 32, apname, iplenname );
     inl2 += m_a819l_from_u8l( &byarruwork2[inl2], sizeof(byarruwork2) - inl2 - 32, apname, iplenname );
     if (iplendomain) {
       inl1 += sprintf( &byarruwork1[inl1], " domain-name: " );
       inl2 += sprintf( &byarruwork2[inl2], " domain-name: " );
       inl1 += m_a850l_from_u8l( &byarruwork1[inl1], sizeof(byarruwork1) - inl1 - 1, apdomain, iplendomain );
       inl2 += m_a819l_from_u8l( &byarruwork2[inl2], sizeof(byarruwork2) - inl2 - 1, apdomain, iplendomain );
     }
     byarruwork1[inl1] = 0;                 /* make zero-terminated    */
     byarruwork2[inl2] = 0;                 /* make zero-terminated    */
   } else {
     inl1 = inl2 = sprintf( byarruwork1, "no user-name" );
     memcpy( byarruwork2, byarruwork1, inl1 + 1 );
   }
#endif
   al1 = "WTS";
#ifdef OLD_1112
   if (auclconn11->adsc_server_conf_1->boc_is_blade_server) {  /* check BLADE */
     al1 = "BLADE";
   }
#endif
#ifndef OLD_1112
   if (auclconn11->adsc_server_conf_1->boc_is_blade_server) {  /* check BLADE */
     al1 = "VDI";
   }
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPS040I GATE=%(ux)s SNO=%08d INETA=%s %s query %s",
                   (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->dsc_co_sort.imc_sno,
                   auclconn11->chrc_ineta, al1, byarruwork2 );
   iu1 = 0;                                 /* set return value success */
   if (auclconn11->adsc_server_conf_1->boc_wts_check_name) {  /* check name WTS */
     adsl_auxf_1_1 = auclconn11->adsc_auxf_1;  /* anchor of extensions */
     while (adsl_auxf_1_1) {                /* loop over chain         */
       if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_certname) break;
       adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
     }
     if (   (adsl_auxf_1_1 == NULL)
         || (*((int *) (adsl_auxf_1_1 + 1)) != iplenname)
         || (memcmp( wcharruwork1,
                     (((int *) (adsl_auxf_1_1 + 1)) + 1),
                     iplenname * sizeof(WCHAR) ))) {
       iu1 = 2;
       m_hlnew_printf( HLOG_XYZ1, "HWSPS033W GATE=%(ux)s SNO=%08d INETA=%s names not equal - connection refused",
                       auclconn11->adsc_gate1 + 1, auclconn11->dsc_co_sort.imc_sno,
                       auclconn11->chrc_ineta );
     }
   }
   return iu1;
#undef auclconn11
} /* end HLGW_check_name()                                             */

/** process abnormal end of session WTS load-balancing / VDI           */
static void HLGW_set_abend( void *apparam ) {
#define ADSL_CONN1_G ((DSD_CONN_G *) apparam)
#ifndef B150117
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error = HL_ERROR_LB_NO_SERVER;  /* connect error */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     return;
   }
#endif
#ifndef HL_UNIX
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;
#else
   ADSL_CONN1_G->iec_st_ses = ied_ses_abend;
#endif
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "Abend Load-Balancing";
   }
#undef ADSL_CONN1_G
} /* end HLGW_set_abend()                                              */

#ifndef B140704
/* routine called by timer thread for delayed freeing of memory - server conf 1 */
static void m_free_seco1( struct dsd_timer_ele *adsp_timer_ele ) {
   free( (char *) adsp_timer_ele - IMD_SERVER_CONF_1 );  /* free the memory */
} /* end m_free_seco1()                                                */
#endif

//#ifdef INCL_GW_L2TP
#ifdef D_INCL_HOB_TUN
/**
   Select an INETA used in the internal network for HOB-TUN.
   The routine m_prepare_htun_ineta() is also called to select an
   INETA for L2TP if this is configured.
*/
static struct dsd_ineta_raws_1 * m_prepare_htun_ineta_htcp( DSD_CONN_G *adsp_conn1,
                                                            struct dsd_hco_wothr *adsp_hco_wothr,
                                                            enum ied_ineta_raws_def iep_irs_def ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_len_ident;                /* length of ident         */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_ident;    /* auxiliary extension fi  */
   struct dsd_config_ineta_1 *adsl_co_ineta_w1;  /* configured INETAs  */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_new;  /* new INETA       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

   adsl_auxf_1_ident = NULL;                /* auxiliary extension field */
   adsl_co_ineta_w1 = NULL;                 /* configured INETAs       */
   iml_len_ident = 0;                       /* length of ident         */
#define ADSL_SESSCO1_G ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_w1 + 1))
   adsl_auxf_1_w1 = adsp_conn1->adsc_auxf_1;  /* get first element     */
   while (adsl_auxf_1_w1) {                 /* loop over chain         */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sessco1) {  /* session configuration */
       adsl_co_ineta_w1 = ADSL_SESSCO1_G->adsc_co_ineta_appl;  /* configured INETAs application / HTCP */
       if (adsl_auxf_1_ident) break;
     } else if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_ident) {  /* ident - userid and user-group */
       adsl_auxf_1_ident = adsl_auxf_1_w1;  /* auxiliary extension fi  */
       if (adsl_co_ineta_w1) break;
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
#undef ADSL_SESSCO1_G
#define ADSL_AUXF_IDENT_1_G ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_ident + 1))
   if (adsl_auxf_1_ident) {                 /* ident found             */
     iml_len_ident                          /* length of ident         */
       = ADSL_AUXF_IDENT_1_G->imc_len_userid  /* length userid UTF-8   */
           + ADSL_AUXF_IDENT_1_G->imc_len_user_group;  /* length name user group UTF-8 */
   } else {                                 /* try user-group, user-entry */
     if (   (adsp_conn1->adsc_user_group == NULL)  /* structure user group */
         || (adsp_conn1->adsc_user_entry == NULL)) {  /* structure user entry */
       return NULL;                         /* no identification       */
     }
   }
   if (adsl_co_ineta_w1 == NULL) {          /* no configuration found  */
     if (adsp_conn1->adsc_user_entry) {     /* structure user entry    */
       adsl_co_ineta_w1 = adsp_conn1->adsc_user_entry->adsc_config_ineta_1_appl;  /* configured INETAs application / HTCP */
     }
   }
   adsl_ineta_raws_1_new = (struct dsd_ineta_raws_1 *) malloc( sizeof(struct dsd_ineta_raws_1)
                                                                 + iml_len_ident );  /* length of ident */
   memset( adsl_ineta_raws_1_new, 0, sizeof(struct dsd_ineta_raws_1 ) );
   adsl_ineta_raws_1_new->boc_with_user = TRUE;  /* structure with user */
   adsl_ineta_raws_1_new->ac_conn1 = adsp_conn1;  /* for this connection */
   if (adsl_auxf_1_ident) {                 /* ident found             */
     memcpy( adsl_ineta_raws_1_new + 1,
             ADSL_AUXF_IDENT_1_G + 1,
             ADSL_AUXF_IDENT_1_G->imc_len_userid
               + ADSL_AUXF_IDENT_1_G->imc_len_user_group );
     adsl_ineta_raws_1_new->dsc_user_name.ac_str = adsl_ineta_raws_1_new + 1;  /* address of string */
     adsl_ineta_raws_1_new->dsc_user_name.imc_len_str = ADSL_AUXF_IDENT_1_G->imc_len_userid;  /* length string in elements */
     adsl_ineta_raws_1_new->dsc_user_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
     adsl_ineta_raws_1_new->dsc_user_group.ac_str
        = (char *) (adsl_ineta_raws_1_new + 1) + ADSL_AUXF_IDENT_1_G->imc_len_userid;  /* address of string */
     adsl_ineta_raws_1_new->dsc_user_group.imc_len_str = ADSL_AUXF_IDENT_1_G->imc_len_user_group;  /* length string in elements */
     adsl_ineta_raws_1_new->dsc_user_group.iec_chs_str = ied_chs_utf_8;  /* character set string */
   } else {                                 /* try user-group, user-entry */
     adsl_ineta_raws_1_new->dsc_user_name.ac_str = adsp_conn1->adsc_user_entry + 1;  /* address of string */
     adsl_ineta_raws_1_new->dsc_user_name.imc_len_str
       = adsp_conn1->adsc_user_entry->inc_len_name_bytes / sizeof(HL_WCHAR) - 1;  /* length string in elements */
     adsl_ineta_raws_1_new->dsc_user_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     adsl_ineta_raws_1_new->dsc_user_group.ac_str = adsp_conn1->adsc_user_group + 1;  /* address of string */
     adsl_ineta_raws_1_new->dsc_user_group.imc_len_str
       = adsp_conn1->adsc_user_group->inc_len_name / sizeof(HL_WCHAR) - 1;  /* length string in elements */
     adsl_ineta_raws_1_new->dsc_user_group.iec_chs_str = ied_chs_utf_16;  /* character set string */
   }
#undef ADSL_AUXF_IDENT_1_G
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNINNU", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                          "l%05d m_prepare_htun_ineta_htcp( ... , %d ) ac_conn1 %p SNO=%08d group=%(ucs)s userid=%(ucs)s.",
                          __LINE__,
                          iep_irs_def,
                          adsp_conn1,
                          adsp_conn1->dsc_co_sort.imc_sno,
                          &adsl_ineta_raws_1_new->dsc_user_group,
                          &adsl_ineta_raws_1_new->dsc_user_name );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   bol1 = m_update_htun_ineta( adsl_ineta_raws_1_new,
                               adsp_conn1,
                               adsp_hco_wothr,
                               iep_irs_def,
                               adsl_co_ineta_w1 );
   if (bol1) return adsl_ineta_raws_1_new;
   free( adsl_ineta_raws_1_new );           /* free structure again    */
   return NULL;                             /* could not assign INETA  */
} /* end m_prepare_htun_ineta_htcp()                                   */

static BOOL m_update_htun_ineta( struct dsd_ineta_raws_1 *adsp_ineta_raws_1,
                                 DSD_CONN_G *adsp_conn1,
                                 struct dsd_hco_wothr *adsp_hco_wothr,
                                 enum ied_ineta_raws_def iep_irs_def,
                                 struct dsd_config_ineta_1 *adsp_co_ineta ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variables */
   int        iml_rc;                       /* return code 1           */
   int        iml_error;                    /* return code 2           */
   int        iml_cmp;                      /* for compare operations  */
   int        iml_rem_no_ineta;             /* remaining number of INETA */
   int        iml_count_cluster;            /* count the cluster members */
   int        iml_rejected;                 /* count times rejected by other cluster members */
   int        iml_ineta_family;             /* family IPV4 / IPV6      */
   int        iml_len_ineta;                /* length INETA            */
   int        iml_disp_ineta;               /* displacement INETA in struct dsd_ineta_raws_1 */
   int        iml_disp_sort_ineta;          /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
   unsigned int uml_cur_time;               /* current time            */
   BOOL       bol_no_tun;                   /* INETA not for TUN-adapter */
   BOOL       bol_random;                   /* <appl-use-random-tcp-source-port> */
   BOOL       bol_lock_set;                 /* lock is set             */
   BOOL       bol_err_savebl_full;          /* give error message later */
   BOOL       bol_err_illogic;              /* give error message illogic */
   BOOL       bol_err_resp_cluster;         /* give error message cluster responses */
   BOOL       bol_search_appl;              /* search appl             */
   BOOL       bol_route_add;                /* add a route             */
   BOOL       bol_ser_post;                 /* post serialize thread   */
   HL_LONGLONG ill_time_cur;                /* current time            */
   HL_LONGLONG ill_time_end;                /* end time wait           */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_ineta_raws_t;           /* target of INETA         */
   char       *achl_fill_ineta_1;           /* fill INETA              */
   char       *achl_fill_ineta_2;           /* fill INETA              */
   char       *achl_fill_ineta_3;           /* fill INETA              */
   char       *achl_pool_e1;                /* for pool extension      */
   void *     al_work1;                     /* work area buffer        */
   void *     al_free_1;                    /* buffer to be freed      */
   struct dsd_cluster_ineta_temp *adsl_cluster_ineta_temp_w1;  /* temporary INETAs received from other cluster member */
   struct dsd_ineta_single_1 *adsl_ineta_single_1_w1;  /* single INETA target / listen / configured */
   struct dsd_cluster_ineta_this *adsl_cluster_ineta_this_w1;  /* save INETA this cluster member */
   struct dsd_pool_ineta_1 *adsl_pool_ineta_1_w1;  /* chain of pools of INETAs */
   struct dsd_pool_ineta_1 *adsl_pool_ineta_1_w2;  /* chain of pools of INETAs */
   struct dsd_ser_thr_task *adsl_ser_thr_task_free;  /* task for serial thread */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w1;  /* task for serial thread */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w2;  /* task for serial thread */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
   struct dsd_tun_ineta_1 *adsl_tun_ineta_1_w1;  /* range of INETAs used by TUN */
   struct dsd_appl_port_conf *adsl_appl_port_conf_w1;  /* configured ports for appl */
   struct dsd_cluster_ineta_wait *adsl_cluster_ineta_wait_ch;  /* wait to process INETAs this cluster member */
   struct dsd_cluster_ineta_wait *adsl_cluster_ineta_wait_w1;  /* wait to process INETAs this cluster member */
   struct sockaddr *adsl_soa_l;             /* local sockaddr          */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_htree1_avl_cntl *adsl_hac_ineta;
   struct dsd_htree1_avl_cntl *adsl_hac_user_i;
   struct dsd_htree1_avl_entry *adsl_sort_ineta_w1;
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_htree1_avl_work dsl_htree1_save;  /* save work-area for AVL-Tree */
   char       chrl_work1[ 256 ];            /* work area               */

   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
   bol_lock_set = FALSE;                    /* lock not set            */
   bol_err_savebl_full = FALSE;             /* give error message later */
   bol_err_illogic = FALSE;                 /* give error message illogic */
   bol_err_resp_cluster = FALSE;            /* give error message cluster responses */
   bol_route_add = FALSE;                   /* add a route             */
   bol_ser_post = FALSE;                    /* post serialize thread   */
   bol_no_tun = FALSE;                      /* INETA not for TUN-adapter */
   iml_rejected = 0;                        /* count times rejected by other cluster members */
   adsl_ser_thr_task_free = NULL;           /* task for serial thread  */
   al_work1 = NULL;                         /* work area buffer        */
   al_free_1 = NULL;                        /* buffer to be freed      */
   adsl_cluster_ineta_temp_w1 = NULL;       /* temporary INETAs received from other cluster member */
   adsl_cluster_ineta_wait_ch = NULL;       /* wait to process INETAs this cluster member */
   switch (iep_irs_def) {                   /* type of INETA raw socket */
     case ied_ineta_raws_n_ipv4:            /* INETA IPV4              */
       iml_ineta_family = AF_INET;          /* family IPV4 / IPV6      */
       iml_len_ineta = 4;                   /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv4;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = FALSE;             /* search appl             */
       bol_route_add = TRUE;                /* add a route             */
       break;
     case ied_ineta_raws_n_ipv6:            /* INETA IPV6              */
       iml_ineta_family = AF_INET6;         /* family IPV4 / IPV6      */
       iml_len_ineta = 16;                  /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv6;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv6 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = FALSE;             /* search appl             */
       bol_route_add = TRUE;                /* add a route             */
       break;
     case ied_ineta_raws_user_ipv4:         /* INETA user IPV4         */
       iml_ineta_family = AF_INET;          /* family IPV4 / IPV6      */
       iml_len_ineta = 4;                   /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       adsl_hac_user_i = &dss_htree1_avl_cntl_user_i_ipv4;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv4;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = TRUE;              /* search appl             */
       bol_route_add = TRUE;                /* add a route             */
       break;
     case ied_ineta_raws_user_ipv6:         /* INETA user IPV6         */
       iml_ineta_family = AF_INET6;         /* family IPV4 / IPV6      */
       iml_len_ineta = 16;                  /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       adsl_hac_user_i = &dss_htree1_avl_cntl_user_i_ipv6;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv6;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv6 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = TRUE;              /* search appl             */
       bol_route_add = TRUE;                /* add a route             */
       break;
     case ied_ineta_raws_l2tp_ipv4:         /* INETA L2TP IPV4         */
       iml_ineta_family = AF_INET;          /* family IPV4 / IPV6      */
       iml_len_ineta = 4;                   /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv4;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = FALSE;             /* search appl             */
       bol_no_tun = TRUE;                   /* INETA not for TUN-adapter */
       break;
     case ied_ineta_raws_l2tp_ipv6:         /* INETA L2TP IPV6         */
       iml_ineta_family = AF_INET6;         /* family IPV4 / IPV6      */
       iml_len_ineta = 16;                  /* length INETA            */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr)
              - ((char *) adsp_ineta_raws_1);
       achl_ineta_raws_t = (char *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr;  /* target of INETA */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       adsl_sort_ineta_w1 = &adsp_ineta_raws_1->dsc_sort_ineta_ipv6;
       iml_disp_sort_ineta = offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv6 );  /* displacement struct dsd_htree1_avl_entry in struct dsd_ineta_raws_1 */
       bol_search_appl = FALSE;             /* search appl             */
       bol_no_tun = TRUE;                   /* INETA not for TUN-adapter */
       break;
   }
   iml_count_cluster = m_cluster_count_active();  /* count the cluster members */
   al_work1 = m_proc_alloc();               /* work area buffer        */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   achl_fill_ineta_1 = NULL;                /* fill INETA              */
   /* task for serial thread                                           */
   if (bol_route_add) {                     /* add a route             */
     adsl_ser_thr_task_free
       = (struct dsd_ser_thr_task *) malloc( DEF_SERIAL_FREE_POOL * sizeof(struct dsd_ser_thr_task) );
     adsl_ser_thr_task_free->adsc_next = adsl_ser_thr_task_free + DEF_SERIAL_FREE_POOL - 1;
     adsl_ser_thr_task_w1 = adsl_ser_thr_task_free + 1;
     adsl_ser_thr_task_w1->adsc_next = NULL;
     iml1 = DEF_SERIAL_FREE_POOL - 2;
     do {
       adsl_ser_thr_task_w1++;              /* next entry in pool      */
       adsl_ser_thr_task_w1->adsc_next = adsl_ser_thr_task_w1 - 1;
       iml1--;                              /* decrement index         */
     } while (iml1 > 0);
#ifdef B120917
     dsl_work_i.dsc_ineta_raws_1.umc_index_if_arp = dss_ser_thr_ctrl.umc_index_if_arp;  /* holds index of compatible IF for ARP */
     dsl_work_i.dsc_ineta_raws_1.umc_index_if_route = dss_ser_thr_ctrl.umc_index_if_route;  /* holds index of compatible IF for routes */
     if (adsl_raw_packet_if_conf) {         /* configuration raw-packet-interface */
#ifdef B100802
       dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_taif_ineta;  /* <TUN-adapter-use-interface-ineta> */
#endif
//     dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_ta_ineta_local;
//     dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_ta_ineta_remote;
#ifdef B101007
       dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_ta_ineta_local ^ 0X03;
#endif
#ifndef NEW_HOB_TUN_1103
       dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_ta_ineta_local;
       *((unsigned char *) &dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta + sizeof(int) - 1) ^= 0X03;
#else
       dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta = adsl_raw_packet_if_conf->umc_taif_ineta;
#endif
     }
#endif
#ifndef HL_UNIX
     if (iml_ineta_family == AF_INET) {     /* family IPV4 / IPV6      */
       adsp_ineta_raws_1->umc_index_if_arp_ipv4 = dss_ser_thr_ctrl.umc_index_if_arp;  /* holds index of compatible IF for ARP */
       adsp_ineta_raws_1->umc_index_if_route_ipv4 = dss_ser_thr_ctrl.umc_index_if_route;  /* holds index of compatible IF for routes */
#ifdef B130109
       adsp_ineta_raws_1->umc_taif_ineta_ipv4 = adsl_raw_packet_if_conf->umc_taif_ineta;  /* <TUN-adapter-use-interface-ineta> */
#else
       adsp_ineta_raws_1->umc_taif_ineta_ipv4 = adsl_raw_packet_if_conf->umc_taif_ineta_ipv4;  /* <TUN-adapter-use-interface-ineta> */
#endif
     }
#endif
   }
   if (bol_search_appl == FALSE) {          /* INETA PPP               */
     goto p_new_ineta_00;                   /* needs new INETA         */
   }

   /* for INETA appl search if already in use                          */
   p_appl_check:                            /* check appl              */
   bol_lock_set = TRUE;                     /* lock is set             */
   dsg_global_lock.m_enter();
   do {
     bol1 = m_htree1_avl_search( NULL, adsl_hac_user_i,
                                 &dsl_htree1_work, &adsp_ineta_raws_1->dsc_sort_user );
     if (bol1 == FALSE) {                   /* error occured           */
       sprintf( chrl_work1,
                "m_htree1_avl_search() failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       break;
     }
     if (dsl_htree1_work.adsc_found) break;  /* entry found            */
     /* normally INETA and port do not match, so retrieve next         */
     bol1 = m_htree1_avl_getnext( NULL, adsl_hac_user_i,
                                  &dsl_htree1_work, FALSE );
     if (bol1 == FALSE) {                   /* error occured           */
       sprintf( chrl_work1,
                "m_htree1_avl_getnext() failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) break;  /* entry not found */
     /* check if userid and group are still the same                   */
#ifdef B121212
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - iml_disp_sort_ineta))
#else
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_user )))
#endif
     bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                            &adsp_ineta_raws_1->dsc_user_name,
                            &ADSL_INETA_RAWS_1_G->dsc_user_name );
     if ((bol1 == FALSE) || (iml_cmp)) {    /* does not match          */
       dsl_htree1_work.adsc_found = NULL;   /* no entry found          */
       break;
     }
     bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                            &adsp_ineta_raws_1->dsc_user_group,
                            &ADSL_INETA_RAWS_1_G->dsc_user_group );
     if ((bol1 == FALSE) || (iml_cmp)) {    /* does not match          */
       dsl_htree1_work.adsc_found = NULL;   /* no entry found          */
       break;
     }
#undef ADSL_INETA_RAWS_1_G
   } while (FALSE);
   if (achl_avl_error) {                    /* error occured           */
     goto p_ret_err;                        /* no INETA found          */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found       */
     goto p_new_ineta_00;                   /* needs new INETA         */
   }
   bol_route_add = FALSE;                   /* add a route             */

   /* check which port can be used                                     */
#ifdef B121212
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - iml_disp_sort_ineta))
#else
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_user )))
#endif
   memcpy( achl_ineta_raws_t,
           (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
           iml_len_ineta );
   memcpy( &dsl_htree1_save, &dsl_htree1_work, sizeof(struct dsd_htree1_avl_work) );  /* save work-area for AVL-Tree */
   adsl_appl_port_conf_w1 = (struct dsd_appl_port_conf *) chrl_work1;  /* configured ports for appl in work area */
   adsl_appl_port_conf_w1->usc_port_start = DEF_APPL_USE_SOURCE_P_START;  /* port to start with */
   adsl_appl_port_conf_w1->usc_no_ports = DEF_APPL_USE_SOURCE_P_NO;  /* number of ports */
   iml1 = 1;                                /* number of port entries  */
   bol_random = FALSE;                      /* not random              */
   if (adsl_raw_packet_if_conf) {           /* configuration raw-packet-interface */
     bol_random = adsl_raw_packet_if_conf->boc_random_appl_port;  /* <appl-use-random-tcp-source-port> */
     if (adsl_raw_packet_if_conf->imc_no_ele_appl_port_conf) {  /* number of elements configured ports for appl */
       adsl_appl_port_conf_w1 = adsl_raw_packet_if_conf->adsc_appl_port_conf;  /* configured ports for appl */
       iml1 = adsl_raw_packet_if_conf->imc_no_ele_appl_port_conf;  /* get number of elements configured ports for appl */
     }
   }
   if (bol_random == FALSE) {               /* not random              */
     goto p_appl_port_60;                   /* select the port sequential for this INETA */
   }
   /* we select the port random                                        */
   /* the port numbers in the configuration are sorted in ascending order */
   iml2 = 0;                                /* count ports in use      */

   p_appl_port_20:                          /* loop to retrieve ports used for this INETA */
   iml2++;                                  /* count ports in use      */
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_user_i,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   /* check is still same INETA                                        */
   if (   (dsl_htree1_work.adsc_found)      /* entry found             */
       && (!memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                    achl_ineta_raws_t,
                    iml_len_ineta ))) {
     goto p_appl_port_20;                   /* loop to retrieve ports used for this INETA */
   }
   iml3 = 0 - iml2;                         /* start with number already is use */
   iml4 = 0;                                /* clear index             */
   do {
     iml3 += (adsl_appl_port_conf_w1 + iml4)->usc_no_ports;
     iml4++;                                /* increment index         */
   } while (iml4 < iml1);
   if (iml3 <= 0) {                         /* all ports in use        */
     goto p_ret_err;                        /* no INETA found          */
   }
   iml1--;                                  /* prepare highest entry in configuration */
   iml2 = m_get_random_number( iml3 );
   memcpy( &dsl_htree1_work, &dsl_htree1_save, sizeof(struct dsd_htree1_avl_work) );  /* restore work-area for AVL-Tree */
   iml3 = 0;                                /* index in configured INETAs */
   iml4 = adsl_appl_port_conf_w1->usc_port_start;  /* get first INETA  */
   iml5 = adsl_appl_port_conf_w1->usc_port_start
            + adsl_appl_port_conf_w1->usc_no_ports;  /* compute port-no after this entry */

   p_appl_port_28:                          /* check in which area of INETAs */
   while (   (ADSL_INETA_RAWS_1_G->usc_appl_port >= iml5)  /* is in next range of INETAs */
          && (iml3 < iml1)) {               /* still in range of configuration */
     iml6 = iml5 - iml4;                    /* this area is not used   */
     if (iml2 < iml6) {                     /* is before end INETA     */
       goto p_appl_port_32;                 /* port to use found       */
     }
     iml2 -= iml6;                          /* this area overread      */
     iml3++;                                /* try in next range       */
     iml4 = (adsl_appl_port_conf_w1 + iml3)->usc_port_start;  /* get first INETA  */
     iml5 = (adsl_appl_port_conf_w1 + iml3)->usc_port_start
              + (adsl_appl_port_conf_w1 + iml3)->usc_no_ports;  /* compute port-no after this entry */
   }
   if (iml2 < (iml5 - ADSL_INETA_RAWS_1_G->usc_appl_port)) {  /* is before this INETA */
     goto p_appl_port_32;                   /* port to use found       */
   }
   iml2 -= ADSL_INETA_RAWS_1_G->usc_appl_port - iml4;
   iml4 = ADSL_INETA_RAWS_1_G->usc_appl_port + 1;  /* compare to next INETA */
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_user_i,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   /* check is still same INETA                                        */
   if (   (dsl_htree1_work.adsc_found)      /* entry found             */
       && (!memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                    achl_ineta_raws_t,
                    iml_len_ineta ))) {
     goto p_appl_port_28;                   /* check in which area of INETAs */
   }

   p_appl_port_32:                          /* port to use found       */
   adsp_ineta_raws_1->usc_appl_port = iml4 + iml2;
   goto p_ret_ok_60;                        /* all complete            */

   p_appl_port_60:                          /* select the port sequentially for this INETA */
   iml1--;                                  /* prepare highest entry in configuration */
#ifdef B100514
   iml2 = m_get_random_number( iml3 );
#endif
   memcpy( &dsl_htree1_work, &dsl_htree1_save, sizeof(struct dsd_htree1_avl_work) );  /* restore work-area for AVL-Tree */
   iml3 = 0;                                /* index in configured INETAs */
   iml4 = adsl_appl_port_conf_w1->usc_port_start;  /* get first INETA  */
   iml5 = adsl_appl_port_conf_w1->usc_port_start
            + adsl_appl_port_conf_w1->usc_no_ports;  /* compute port-no after this entry */

   p_appl_port_64:                          /* check the port          */
   if (ADSL_INETA_RAWS_1_G->usc_appl_port >= iml4) {
     goto p_appl_port_72;                   /* port in AVL-tree in this range */
   }

   p_appl_port_68:                          /* read next entry in AVL-tree */
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_user_i,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   /* check is still same INETA                                        */
   if (   (dsl_htree1_work.adsc_found)      /* entry found             */
       && (!memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                    achl_ineta_raws_t,
                    iml_len_ineta ))) {
     goto p_appl_port_64;                   /* check the port          */
   }
   adsp_ineta_raws_1->usc_appl_port = iml4;  /* use this port */
   goto p_ret_ok_60;                        /* all complete            */

   p_appl_port_72:                          /* port in AVL-tree in this range */
   if (ADSL_INETA_RAWS_1_G->usc_appl_port != iml4) {  /* this port not in use */
     adsp_ineta_raws_1->usc_appl_port = iml4;  /* use this port */
     goto p_ret_ok_60;                      /* all complete            */
   }
   iml4++;                                  /* set next port number    */
   if (iml4 < iml5) {                       /* still in range          */
     goto p_appl_port_68;                   /* read next entry in AVL-tree */
   }
   if (iml3 >= iml1) {                      /* all entries checked     */
     goto p_ret_err;                        /* no INETA found          */
   }
   iml3++;                                  /* try in next range       */
   iml4 = (adsl_appl_port_conf_w1 + iml3)->usc_port_start;  /* get first INETA  */
   iml5 = (adsl_appl_port_conf_w1 + iml3)->usc_port_start
            + (adsl_appl_port_conf_w1 + iml3)->usc_no_ports;  /* compute port-no after this entry */
   memcpy( &dsl_htree1_work, &dsl_htree1_save, sizeof(struct dsd_htree1_avl_work) );  /* restore work-area for AVL-Tree */
   goto p_appl_port_64;                     /* check the port          */

#undef ADSL_INETA_RAWS_1_G

   p_new_ineta_00:                          /* needs new INETA         */
   if (adsp_co_ineta == NULL) {             /* no configuration found  */
     if (   (bol_search_appl)               /* INETA appl              */
         || (bol_no_tun)) {                 /* INETA not for TUN-adapter */
       goto p_ret_err;                      /* no INETA found          */
     }
     goto p_pool_00;                        /* search INETA in pool    */
   }
   adsl_ineta_single_1_w1 = (struct dsd_ineta_single_1 *) (adsp_co_ineta + 1);  /* single INETA target / listen / configured */
   iml_rem_no_ineta = adsp_co_ineta->imc_no_ineta;  /* remaining number of INETA */

   p_new_ineta_20:                          /* check entry in configuration */
   if (iml_rem_no_ineta <= 0) {             /* at end of table         */
     goto p_new_ineta_80;                   /* end of entries in configuration */
   }
   if (adsl_ineta_single_1_w1->usc_family != iml_ineta_family) {  /* family IPV4 / IPV6 */
     adsl_ineta_single_1_w1
       = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                   + sizeof(struct dsd_ineta_single_1)
                                                   + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
     iml_rem_no_ineta--;                    /* remaining number of INETA */
     goto p_new_ineta_20;                   /* check entry in configuration */
   }
   memcpy( achl_ineta_raws_t,
           adsl_ineta_single_1_w1 + 1,
           adsl_ineta_single_1_w1->usc_length );  /* length of following address */
   /* check if in range of TUN-use-ineta                               */
   do {                                     /* pseudo-loop             */
     if (adsl_raw_packet_if_conf == NULL) break;  /* raw-packet-interface not configured */
     if (adsl_raw_packet_if_conf->adsc_tun_ineta_1 == NULL) break;  /* chain range of INETAs used by TUN */
     if (bol_no_tun) break;                 /* INETA not for TUN-adapter */
     if (   (iml_ineta_family == AF_INET)
         && (adsl_raw_packet_if_conf->boc_c_tun_ipv4 == FALSE)) {  /* configured TUN IPV4 */
       break;                               /* no need to check        */
     }
     if (   (iml_ineta_family == AF_INET6)
         && (adsl_raw_packet_if_conf->boc_c_tun_ipv6 == FALSE)) {  /* configured TUN IPV6 */
       break;                               /* no need to check        */
     }
     adsl_tun_ineta_1_w1 = adsl_raw_packet_if_conf->adsc_tun_ineta_1;  /* chain range of INETAs used by TUN */
     do {                                   /* loop over configured INETAs */
       if (adsl_tun_ineta_1_w1->usc_ineta_family == iml_ineta_family) {  /* family IPV4 / IPV6 */
         iml_cmp = memcmp( adsl_tun_ineta_1_w1 + 1,
                           achl_ineta_raws_t,
                           iml_len_ineta );
         if (iml_cmp == 0) break;           /* INETA found             */
         if (iml_cmp > 0) {                 /* not in this range       */
           adsl_tun_ineta_1_w1 = NULL;      /* this INETA not in range of TUN-use-ineta */
           break;
         }
         iml_cmp = memcmp( (char *) (adsl_tun_ineta_1_w1 + 1) + adsl_tun_ineta_1_w1->usc_ineta_length,
                           achl_ineta_raws_t,
                           iml_len_ineta );
         if (iml_cmp >= 0) break;           /* found in this range     */
       }
       adsl_tun_ineta_1_w1 = adsl_tun_ineta_1_w1->adsc_next;  /* get next in chain */
     } while (adsl_tun_ineta_1_w1);
     if (adsl_tun_ineta_1_w1 == NULL) {     /* this INETA not in range of TUN-use-ineta */
       adsl_ineta_single_1_w1
         = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                     + sizeof(struct dsd_ineta_single_1)
                                                     + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
       iml_rem_no_ineta--;                  /* remaining number of INETA */
       goto p_new_ineta_20;                 /* check entry in configuration */
     }
   } while (FALSE);
   /* found INETA is in range of TUN-use-ineta                         */
   if (bol_lock_set == FALSE) {             /* lock not set            */
     bol_lock_set = TRUE;                   /* lock is set             */
     dsg_global_lock.m_enter();
   }
   bol1 = m_htree1_avl_search( (void *) "C", adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   /* this entry has been processed                                    */
   adsl_ineta_single_1_w1
     = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                 + sizeof(struct dsd_ineta_single_1)
                                                 + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
   iml_rem_no_ineta--;                      /* remaining number of INETA */
   if (dsl_htree1_work.adsc_found) {        /* entry already in use    */
     goto p_new_ineta_20;                   /* check entry in configuration */
   }
   if (adss_cluster_ineta_this) {           /* chain save INETA this cluster member */
     adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
     do {                                   /* loop over INETAs this cluster member */
       if (adsl_cluster_ineta_this_w1->usc_ineta_family == iml_ineta_family) {  /* family IPV4 / IPV6 */
         achl1 = (char *) (adsl_cluster_ineta_this_w1 + 1);  /* first INETA */
         do {                               /* loop over all pairs of INETAs */
           do {                             /* pseudo-loop             */
             iml_cmp = memcmp( achl1,       /* INETA start             */
                               achl_ineta_raws_t,
                               iml_len_ineta );
             if (iml_cmp > 0) break;
             if (iml_cmp < 0) {
               iml_cmp = memcmp( achl1 + adsl_cluster_ineta_this_w1->usc_ineta_length,  /* INETA end */
                                 achl_ineta_raws_t,
                                 iml_len_ineta );
               if (iml_cmp < 0) break;
             }
             /* new INETA is in range of these saved INETAs            */
             goto p_new_ineta_60;           /* wait for saved INETAs to complete */
           } while (FALSE);
           if (iml_cmp > 0) break;          /* break because elements are sorted */
           achl1 += 2 * adsl_cluster_ineta_this_w1->usc_ineta_length;  /* length of following address */
         } while (achl1 < adsl_cluster_ineta_this_w1->achc_end_used);  /* address use till here */
       }
       adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
     } while (adsl_cluster_ineta_this_w1);
   }
   if (iml_count_cluster == 0) {            /* no other cluster member */
     goto p_ret_ok_00;                      /* INETA was found         */
   }
#define ADSL_CLUSTER_INETA_THIS_G ((struct dsd_cluster_ineta_this *) al_work1)
   if (achl_fill_ineta_1 == NULL) {         /* fill INETA              */
     memcpy( ADSL_CLUSTER_INETA_THIS_G + 1,
             achl_ineta_raws_t,
             iml_len_ineta );
     memcpy( (char *) (ADSL_CLUSTER_INETA_THIS_G + 1)
               + iml_len_ineta,
             achl_ineta_raws_t,
             iml_len_ineta );
     achl_fill_ineta_1 = (char *) (ADSL_CLUSTER_INETA_THIS_G + 1)
                                    + 2 * iml_len_ineta;
     achl_fill_ineta_2 = (char *) al_work1 + LEN_TCP_RECV;
     goto p_new_ineta_20;                   /* check entry in configuration */
   }
   /* elements are sorted                                              */
   memcpy( chrl_work1,
           achl_ineta_raws_t,
           iml_len_ineta );
   /* decrement by one to compare with last entry                      */
   m_ineta_op_dec( chrl_work1, iml_len_ineta );
   achl_fill_ineta_3 = (char *) (ADSL_CLUSTER_INETA_THIS_G + 1);
   do {                                     /* loop over already saved INETAs */
     iml_cmp = memcmp( achl_fill_ineta_3 + iml_len_ineta,  /* INETA end */
                       achl_ineta_raws_t,
                       iml_len_ineta );
     if (iml_cmp >= 0) break;               /* position found          */
     /* check if this end is just before the new INETA                 */
     iml_cmp = memcmp( achl_fill_ineta_3 + iml_len_ineta,  /* INETA end */
                       chrl_work1,
                       iml_len_ineta );
     if (iml_cmp == 0) {                    /* can be appended to this entry */
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl_ineta_raws_t,
               iml_len_ineta );
       /* check if next entry follows immediately                      */
       if ((achl_fill_ineta_3 + 2 * iml_len_ineta)
             >= achl_fill_ineta_1) {
         goto p_new_ineta_20;               /* check entry in configuration */
       }
       memcpy( chrl_work1,
               achl_ineta_raws_t,
               iml_len_ineta );
       /* increment by one to compare with next                        */
       m_ineta_op_inc( chrl_work1, iml_len_ineta );
       iml_cmp = memcmp( achl_fill_ineta_3 + 2 * iml_len_ineta,  /* INETA start next */
                         chrl_work1,
                         iml_len_ineta );
       if (iml_cmp > 0) {                   /* gap is bigger           */
         goto p_new_ineta_20;               /* check entry in configuration */
       }
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl_fill_ineta_3 + 3 * iml_len_ineta,
               iml_len_ineta );
       achl_fill_ineta_1 -= 2 * iml_len_ineta;
       achl_fill_ineta_3 += 2 * iml_len_ineta;
       if (achl_fill_ineta_3 >= achl_fill_ineta_1) {  /* no need to move entries */
         goto p_new_ineta_20;               /* check entry in configuration */
       }
       memmove( achl_fill_ineta_3,
                achl_fill_ineta_3 + 2 * iml_len_ineta,
                achl_fill_ineta_1 - achl_fill_ineta_3 );
       goto p_new_ineta_20;                 /* check entry in configuration */
     }
     achl_fill_ineta_3 += 2 * iml_len_ineta;  /* length of following address */
   } while (achl_fill_ineta_3 < achl_fill_ineta_1);
   if (achl_fill_ineta_3 < achl_fill_ineta_1) {  /* found within saved INETAs */
     iml_cmp = memcmp( achl_fill_ineta_3,   /* INETA start             */
                       achl_ineta_raws_t,
                       iml_len_ineta );
     if (iml_cmp > 0) {                     /* fill in before this pair */
       /* check if the following entry is just after this INETA with no gap */
       memcpy( chrl_work1,
               achl_ineta_raws_t,
               iml_len_ineta );
       /* increment by one to compare with next                        */
       m_ineta_op_inc( chrl_work1, iml_len_ineta );
       iml_cmp = memcmp( achl_fill_ineta_3,  /* INETA start            */
                         chrl_work1,
                         iml_len_ineta );
       if (iml_cmp <= 0) {                  /* possible to combine entries */
         memcpy( achl_fill_ineta_3,
                 achl_ineta_raws_t,
                 iml_len_ineta );
         goto p_new_ineta_20;               /* check entry in configuration */
       }
       /* needed to insert a new entry                                 */
       if ((achl_fill_ineta_1 + 2 * iml_len_ineta)
             > achl_fill_ineta_2) {         /* does not fit in this block */
         bol_err_savebl_full = TRUE;        /* give error message later */
         goto p_new_ineta_20;               /* ignore this entry       */
       }
       memmove( achl_fill_ineta_3 + 2 * iml_len_ineta,  /* target next entry */
                achl_fill_ineta_3,
                achl_fill_ineta_1 - achl_fill_ineta_3 );
       memcpy( achl_fill_ineta_3,
               achl_ineta_raws_t,
               iml_len_ineta );
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl_ineta_raws_t,
               iml_len_ineta );
       achl_fill_ineta_1 += 2 * iml_len_ineta;
       goto p_new_ineta_20;                 /* check entry in configuration */
     }
   }
   /* make new entry after the old entries                             */
   if ((achl_fill_ineta_1 + 2 * iml_len_ineta)
         > achl_fill_ineta_2) {             /* does not fit in this block */
     bol_err_savebl_full = TRUE;            /* give error message later */
     goto p_new_ineta_20;                   /* ignore this entry       */
   }
   memcpy( achl_fill_ineta_1,
           achl_ineta_raws_t,
           iml_len_ineta );
   memcpy( achl_fill_ineta_1 + iml_len_ineta,
           achl_ineta_raws_t,
           iml_len_ineta );
   achl_fill_ineta_1 += 2 * iml_len_ineta;
   goto p_new_ineta_20;                     /* check entry in configuration */

   p_new_ineta_60:                          /* wait for saved INETAs to complete */
#define ADSL_CLUSTER_INETA_WAIT_G ((struct dsd_cluster_ineta_wait *) al_work1)
   memset( ADSL_CLUSTER_INETA_WAIT_G, 0, sizeof(struct dsd_cluster_ineta_wait) );
   ADSL_CLUSTER_INETA_WAIT_G->adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
   ADSL_CLUSTER_INETA_WAIT_G->adsc_next = adsl_cluster_ineta_this_w1->adsc_cluster_ineta_wait;  /* wait to process INETAs this cluster member */
   adsl_cluster_ineta_this_w1->adsc_cluster_ineta_wait = ADSL_CLUSTER_INETA_WAIT_G;  /* insert this entry */
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */
   if (adsl_cluster_ineta_temp_w1) {        /* temporary INETAs received from other cluster member */
     m_proc_free( adsl_cluster_ineta_temp_w1 );  /* free the buffer    */
     adsl_cluster_ineta_temp_w1 = NULL;     /* clear temporary INETAs received from other cluster member */
   }
   do {
     m_hco_wothr_wait( adsp_hco_wothr );
   } while (ADSL_CLUSTER_INETA_WAIT_G->boc_end_wait == FALSE);  /* check end of waiting */
#ifdef XYZ1
   bol_lock_set = TRUE;                     /* lock is set             */
   dsg_global_lock.m_enter();
#endif
   goto p_new_ineta_00;                     /* needs new INETA         */
#undef ADSL_CLUSTER_INETA_WAIT_G

   p_new_ineta_80:                          /* end of entries in configuration */
   if (achl_fill_ineta_1 == NULL) {         /* fill INETA not set      */
     goto p_new_ineta_88;                   /* no INETA found          */
   }
   memset( al_work1, 0, sizeof(struct dsd_cluster_ineta_this) );
   ADSL_CLUSTER_INETA_THIS_G->adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
   ADSL_CLUSTER_INETA_THIS_G->imc_sequ = ims_cluster_ineta_sequ;  /* sequence number */
   ADSL_CLUSTER_INETA_THIS_G->usc_ineta_family = iml_ineta_family;  /* family IPV4 / IPV6 */
   ADSL_CLUSTER_INETA_THIS_G->usc_ineta_length = iml_len_ineta;  /* length of following address */
   ADSL_CLUSTER_INETA_THIS_G->achc_end_used = achl_fill_ineta_1;  /* address used till here */
   ims_cluster_ineta_sequ++;                /* sequence number cluster queries */
   ADSL_CLUSTER_INETA_THIS_G->adsc_next = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
   adss_cluster_ineta_this = ADSL_CLUSTER_INETA_THIS_G;  /* set new chain save INETA this cluster member */
#undef ADSL_CLUSTER_INETA_THIS_G
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */
   goto p_cluster_00;                       /* send to cluster members and wait for response */

   p_new_ineta_88:                          /* no INETA found          */
   if (   (bol_search_appl)                 /* INETA appl              */
       || (bol_no_tun)) {                   /* INETA not for TUN-adapter */
     goto p_ret_err;                        /* no INETA found          */
   }
   /* use INETA from pool for PPP                                      */

   p_pool_00:                               /* search INETA in pool    */
   if (adsl_raw_packet_if_conf == NULL) {   /* no configuration raw-packet-interface */
     goto p_ret_err;                        /* no INETA found          */
   }
#ifndef B130710
   if (bol_lock_set == FALSE) {             /* lock not set            */
     bol_lock_set = TRUE;                   /* lock is set             */
     dsg_global_lock.m_enter();
   }
#endif
   uml_cur_time = (unsigned int) time( NULL );  /* current time        */

   p_pool_08:                               /* search pool entry       */
   adsl_pool_ineta_1_w1 = adsl_raw_packet_if_conf->adsc_pool_ineta_1;  /* chain of pools of INETAs */
   adsl_pool_ineta_1_w2 = NULL;             /* save old chain of pools of INETAs */
   while (adsl_pool_ineta_1_w1) {           /* loop over all pool entries */
     if (adsl_pool_ineta_1_w1->usc_ineta_family == iml_ineta_family) {  /* family IPV4 / IPV6 */
       if (adsl_pool_ineta_1_w1->umc_last_all_in_use == 0) break;  /* epoch when last found all INETAs in use */
       if ((adsl_pool_ineta_1_w1->umc_last_all_in_use + DEF_INETA_POOL_INUSE_MAX)
             < uml_cur_time) {
         adsl_pool_ineta_1_w1->umc_last_all_in_use = 0;  /* epoch when last found all INETAs in use */
         break;
       }
       if ((adsl_pool_ineta_1_w1->umc_last_all_in_use + DEF_INETA_POOL_INUSE_WAIT)
             < uml_cur_time) {
         do {                                 /* pseudo-loop             */
           if (   (adsl_pool_ineta_1_w2)      /* old entry set           */
               && (adsl_pool_ineta_1_w2->umc_last_all_in_use <= adsl_pool_ineta_1_w1->umc_last_all_in_use)) {
             break;                           /* do not overwrite this old entry */
           }
           adsl_pool_ineta_1_w2 = adsl_pool_ineta_1_w1;  /* save old entry */
         } while (FALSE);
       }
     }
     adsl_pool_ineta_1_w1 = adsl_pool_ineta_1_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_pool_ineta_1_w1 == NULL) {      /* did not find entry with not all in use */
     adsl_pool_ineta_1_w1 = adsl_pool_ineta_1_w2;  /* try old entry    */
   }
   if (adsl_pool_ineta_1_w1 == NULL) {      /* did not find entry with not all in use */
     goto p_ret_err;                        /* no INETA found          */
   }
   /* check all INETAs of this pool entry                              */
   achl_pool_e1 = (char *) (adsl_pool_ineta_1_w1 + 1);  /* address first extension */
   iml1 = adsl_pool_ineta_1_w1->imc_no_ext;  /* number of extensions   */

   p_pool_20:                               /* check this extension    */
   memcpy( achl_ineta_raws_t,
           achl_pool_e1 + sizeof(int),
           iml_len_ineta );
   memcpy( chrl_work1,
           achl_ineta_raws_t,
           iml_len_ineta );
   m_ineta_op_add( chrl_work1,
                   iml_len_ineta,
                   *((int *) achl_pool_e1) - 1 );
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA adsl_sort_ineta_w1=%p achl_ineta_raws_t=%p.",
                   __LINE__, adsl_sort_ineta_w1, achl_ineta_raws_t );
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA achl_ineta_raws_t INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) achl_ineta_raws_t + 0),
                   *((unsigned char *) achl_ineta_raws_t + 1),
                   *((unsigned char *) achl_ineta_raws_t + 2),
                   *((unsigned char *) achl_ineta_raws_t + 3) );
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA chrl_work1 INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) chrl_work1 + 0),
                   *((unsigned char *) chrl_work1 + 1),
                   *((unsigned char *) chrl_work1 + 2),
                   *((unsigned char *) chrl_work1 + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   if (adss_cluster_ineta_this) {           /* chain save INETA this cluster member */
     adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
     do {                                   /* loop over INETAs this cluster member */
       if (adsl_cluster_ineta_this_w1->usc_ineta_family == iml_ineta_family) {  /* family IPV4 / IPV6 */
         achl1 = (char *) (adsl_cluster_ineta_this_w1 + 1);  /* first INETA */
         do {                               /* loop over all pairs of INETAs */
           do {                             /* pseudo-loop             */
             iml_cmp = memcmp( achl1,       /* INETA start             */
                               achl_ineta_raws_t,
                               iml_len_ineta );
             if (iml_cmp > 0) break;
             if (iml_cmp < 0) {
               iml_cmp = memcmp( achl1 + adsl_cluster_ineta_this_w1->usc_ineta_length,  /* INETA end */
                                 chrl_work1,
                                 iml_len_ineta );
               if (iml_cmp < 0) break;
             }
             /* new INETAs are in range of these saved INETAs          */
             goto p_new_ineta_60;           /* wait for saved INETAs to complete */
           } while (FALSE);
           if (iml_cmp > 0) break;          /* break because elements are sorted */
           achl1 += 2 * adsl_cluster_ineta_this_w1->usc_ineta_length;  /* length of following address */
         } while (achl1 < adsl_cluster_ineta_this_w1->achc_end_used);  /* address used till here */
       }
       adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
     } while (adsl_cluster_ineta_this_w1);
   }
   bol1 = m_htree1_avl_search( NULL, adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA sort %p achl_ineta_raws_t %p INETA %d.%d.%d.%d.",
                   __LINE__,
                   dsl_htree1_work.adsc_found,
                   achl_ineta_raws_t,
                   *((unsigned char *) achl_ineta_raws_t + 0),
                   *((unsigned char *) achl_ineta_raws_t + 1),
                   *((unsigned char *) achl_ineta_raws_t + 2),
                   *((unsigned char *) achl_ineta_raws_t + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   if (dsl_htree1_work.adsc_found == NULL) {  /* entry currently not in use */
     if (iml_count_cluster == 0) {          /* no other cluster member */
       adsl_pool_ineta_1_w1->umc_last_all_in_use = 0;  /* not all elements in use */
       goto p_ret_ok_00;                    /* INETA was found         */
     }
   } else {                                 /* this entry in use       */
     if (*((int *) achl_pool_e1) <= 1) {    /* not sucessive entries   */
       goto p_pool_60;                      /* this entry has been processed */
     }
     m_ineta_op_inc( achl_ineta_raws_t, iml_len_ineta );
   }

   p_pool_28:                               /* read sequential in AVL-tree */
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_ineta,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   achl1 = chrl_work1;                      /* address INETA end       */
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file reached   */
     goto p_pool_40;                        /* range of INETAs is valid */
   }
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - iml_disp_sort_ineta))
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA in AVL tree INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 0),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 1),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 2),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   iml_cmp = memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                     chrl_work1,
                     iml_len_ineta );
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA compare end range iml_cmp=%d.",
                   __LINE__, iml_cmp );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   if (iml_cmp > 0) {                       /* after this range        */
     dsl_htree1_work.adsc_found = NULL;     /* same as end-of-file reached */
     goto p_pool_40;                        /* range of INETAs is valid */
   }
   iml_cmp = memcmp( achl_ineta_raws_t,
                     (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                     iml_len_ineta );
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA compare new with found iml_cmp=%d.",
                   __LINE__, iml_cmp );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   if (iml_cmp >= 0) {                      /* nothing inbetween       */
     iml_cmp = memcmp( achl_ineta_raws_t,
                       chrl_work1,
                       iml_len_ineta );
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
     m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA compare iml_cmp=%d achl_ineta_raws_t=%d.%d.%d.%d chrl_work1=%d.%d.%d.%d.",
                     __LINE__, iml_cmp,
                     *((unsigned char *) achl_ineta_raws_t + 0),
                     *((unsigned char *) achl_ineta_raws_t + 1),
                     *((unsigned char *) achl_ineta_raws_t + 2),
                     *((unsigned char *) achl_ineta_raws_t + 3),
                     *((unsigned char *) chrl_work1 + 0),
                     *((unsigned char *) chrl_work1 + 1),
                     *((unsigned char *) chrl_work1 + 2),
                     *((unsigned char *) chrl_work1 + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
     if (iml_cmp >= 0) {                    /* start INETA not less than end INETA */
       goto p_pool_60;                      /* this entry has been processed */
     }
     m_ineta_op_inc( achl_ineta_raws_t, iml_len_ineta );
     goto p_pool_28;                        /* read sequential in AVL-tree */
   }
#define ACHL_INETA_SAVE_G (chrl_work1 + 1 * 32)
   memcpy( ACHL_INETA_SAVE_G,
           (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
           iml_len_ineta );
   /* decrement by one because we need end INETA included              */
   m_ineta_op_dec( ACHL_INETA_SAVE_G, iml_len_ineta );
   achl1 = ACHL_INETA_SAVE_G;               /* address INETA end       */
#undef ACHL_INETA_SAVE_G
#undef ADSL_INETA_RAWS_1_G

   p_pool_40:                               /* range of INETAs is valid */
   if (iml_count_cluster == 0) {            /* no other cluster member */
     adsl_pool_ineta_1_w1->umc_last_all_in_use = 0;  /* not all elements in use */
     goto p_ret_ok_00;                      /* INETA was found         */
   }
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA p_pool_40: achl_fill_ineta_1=%p.",
                   __LINE__, achl_fill_ineta_1 );
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA achl_ineta_raws_t INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) achl_ineta_raws_t + 0),
                   *((unsigned char *) achl_ineta_raws_t + 1),
                   *((unsigned char *) achl_ineta_raws_t + 2),
                   *((unsigned char *) achl_ineta_raws_t + 3) );
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA achl1 INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) achl1 + 0),
                   *((unsigned char *) achl1 + 1),
                   *((unsigned char *) achl1 + 2),
                   *((unsigned char *) achl1 + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
#define ADSL_CLUSTER_INETA_THIS_G ((struct dsd_cluster_ineta_this *) al_work1)
   if (achl_fill_ineta_1 == NULL) {         /* fill INETA              */
     memcpy( ADSL_CLUSTER_INETA_THIS_G + 1,
             achl_ineta_raws_t,
             iml_len_ineta );
     memcpy( (char *) (ADSL_CLUSTER_INETA_THIS_G + 1)
               + iml_len_ineta,
             achl1,
             iml_len_ineta );
     achl_fill_ineta_1 = (char *) (ADSL_CLUSTER_INETA_THIS_G + 1)
                                    + 2 * iml_len_ineta;
     achl_fill_ineta_2 = (char *) al_work1 + LEN_TCP_RECV;
     goto p_pool_48;                        /* INETAs have been saved in table for cluster members */
   }
   /* elements are sorted                                              */
#define ACHL_INETA_SAVE_G (chrl_work1 + 2 * 32)
   memcpy( ACHL_INETA_SAVE_G,
           achl_ineta_raws_t,
           iml_len_ineta );
   /* decrement by one to compare with last entry                      */
   m_ineta_op_dec( ACHL_INETA_SAVE_G, iml_len_ineta );
   achl_fill_ineta_3 = (char *) (ADSL_CLUSTER_INETA_THIS_G + 1);
   do {                                     /* loop over already saved INETAs */
     iml_cmp = memcmp( achl_fill_ineta_3 + iml_len_ineta,  /* INETA end */
                       achl_ineta_raws_t,
                       iml_len_ineta );
     if (iml_cmp >= 0) break;               /* position found          */
     /* check if this end is just before the new INETA                 */
     iml_cmp = memcmp( achl_fill_ineta_3 + iml_len_ineta,  /* INETA end */
                       ACHL_INETA_SAVE_G,
                       iml_len_ineta );
     if (iml_cmp == 0) {                    /* can be appended to this entry */
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl1,
               iml_len_ineta );
       /* check if next entry follows immediately                      */
       if ((achl_fill_ineta_3 + 2 * iml_len_ineta)
             >= achl_fill_ineta_1) {
         goto p_pool_48;                    /* INETAs have been saved in table for cluster members */
       }
       memcpy( ACHL_INETA_SAVE_G,
               achl1,
               iml_len_ineta );
       /* increment by one to compare with next                        */
       m_ineta_op_inc( ACHL_INETA_SAVE_G, iml_len_ineta );
       iml_cmp = memcmp( achl_fill_ineta_3 + 2 * iml_len_ineta,  /* INETA start next */
                         ACHL_INETA_SAVE_G,
                         iml_len_ineta );
       if (iml_cmp > 0) {                   /* gap is bigger           */
         goto p_pool_48;                    /* INETAs have been saved in table for cluster members */
       }
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl_fill_ineta_3 + 3 * iml_len_ineta,
               iml_len_ineta );
       achl_fill_ineta_1 -= 2 * iml_len_ineta;
       achl_fill_ineta_3 += 2 * iml_len_ineta;
       if (achl_fill_ineta_3 >= achl_fill_ineta_1) {  /* no need to move entries */
         goto p_pool_48;                    /* INETAs have been saved in table for cluster members */
       }
       memmove( achl_fill_ineta_3,
                achl_fill_ineta_3 + 2 * iml_len_ineta,
                achl_fill_ineta_1 - achl_fill_ineta_3 );
       goto p_pool_48;                      /* INETAs have been saved in table for cluster members */
     }
     achl_fill_ineta_3 += 2 * iml_len_ineta;  /* length of following address */
   } while (achl_fill_ineta_3 < achl_fill_ineta_1);
   if (achl_fill_ineta_3 < achl_fill_ineta_1) {  /* found within saved INETAs */
     iml_cmp = memcmp( achl_fill_ineta_3,   /* INETA start             */
                       achl1,
                       iml_len_ineta );
     if (iml_cmp > 0) {                     /* fill in before this pair */
       /* check if the following entry is just after this INETA with no gap */
       memcpy( ACHL_INETA_SAVE_G,
               achl1,
               iml_len_ineta );
       /* increment by one to compare with next                        */
       m_ineta_op_inc( ACHL_INETA_SAVE_G, iml_len_ineta );
       iml_cmp = memcmp( achl_fill_ineta_3,  /* INETA start            */
                         ACHL_INETA_SAVE_G,
                         iml_len_ineta );
       if (iml_cmp <= 0) {                  /* possible to combine entries */
         memcpy( achl_fill_ineta_3,
                 achl_ineta_raws_t,
                 iml_len_ineta );
         goto p_pool_48;                    /* INETAs have been saved in table for cluster members */
       }
       /* needed to insert a new entry                                 */
       if ((achl_fill_ineta_1 + 2 * iml_len_ineta)
             > achl_fill_ineta_2) {         /* does not fit in this block */
         bol_err_savebl_full = TRUE;        /* give error message later */
         goto p_pool_48;                    /* INETAs have been saved in table for cluster members */
       }
       memmove( achl_fill_ineta_3 + 2 * iml_len_ineta,  /* target next entry */
                achl_fill_ineta_3,
                achl_fill_ineta_1 - achl_fill_ineta_3 );
       memcpy( achl_fill_ineta_3,
               achl_ineta_raws_t,
               iml_len_ineta );
       memcpy( achl_fill_ineta_3 + iml_len_ineta,
               achl1,
               iml_len_ineta );
       achl_fill_ineta_1 += 2 * iml_len_ineta;
       goto p_pool_48;                      /* INETAs have been saved in table for cluster members */
     }
   }
   /* make new entry after the old entries                             */
   if ((achl_fill_ineta_1 + 2 * iml_len_ineta)
         > achl_fill_ineta_2) {             /* does not fit in this block */
     bol_err_savebl_full = TRUE;            /* give error message later */
     goto p_pool_48;                        /* INETAs have been saved in table for cluster members */
   }
   memcpy( achl_fill_ineta_1,
           achl_ineta_raws_t,
           iml_len_ineta );
   memcpy( achl_fill_ineta_1 + iml_len_ineta,
           achl1,
           iml_len_ineta );
   achl_fill_ineta_1 += 2 * iml_len_ineta;

#undef ACHL_INETA_SAVE_G

   p_pool_48:                               /* INETAs have been saved in table for cluster members */
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file reached   */
     goto p_pool_60;                        /* this entry has been processed */
   }
#ifndef B140714
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - iml_disp_sort_ineta))
#endif
   memcpy( achl_ineta_raws_t,
#ifdef B140714
           ADSL_CLUSTER_INETA_THIS_G + 1,
#endif
#ifndef B140714
           (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
#endif
           iml_len_ineta );
#ifndef B140714
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN p_pool_48: INETA achl_ineta_raws_t %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) achl_ineta_raws_t + 0),
                   *((unsigned char *) achl_ineta_raws_t + 1),
                   *((unsigned char *) achl_ineta_raws_t + 2),
                   *((unsigned char *) achl_ineta_raws_t + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_ineta_op_inc( achl_ineta_raws_t, iml_len_ineta );
   iml_cmp = memcmp( achl_ineta_raws_t,
                     chrl_work1,
                     iml_len_ineta );
   if (iml_cmp <= 0) {                      /* start INETA not greater end INETA */
     goto p_pool_28;                        /* read sequential in AVL-tree */
   }

#undef ADSL_CLUSTER_INETA_THIS_G

   p_pool_60:                               /* this entry has been processed */
   achl_pool_e1 += sizeof(int) + adsl_pool_ineta_1_w1->usc_ineta_length;
   iml1--;                                  /* decrement remeining number of extensions */
   if (iml1 > 0) goto p_pool_20;            /* check this extension    */
   if (achl_fill_ineta_1 == NULL) {         /* fill INETA not filled   */
     adsl_pool_ineta_1_w1->umc_last_all_in_use = uml_cur_time;  /* all INETAs in use */
     goto p_pool_08;                        /* search pool entry       */
   }
   /* send INETAs to all the other cluster members                     */
#define ADSL_CLUSTER_INETA_THIS_G ((struct dsd_cluster_ineta_this *) al_work1)
   memset( al_work1, 0, sizeof(struct dsd_cluster_ineta_this) );
   ADSL_CLUSTER_INETA_THIS_G->adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
   ADSL_CLUSTER_INETA_THIS_G->adsc_pool_ineta_1 = adsl_pool_ineta_1_w1;  /* pool of INETAs */
   ADSL_CLUSTER_INETA_THIS_G->imc_sequ = ims_cluster_ineta_sequ;  /* sequence number */
   ADSL_CLUSTER_INETA_THIS_G->usc_ineta_family = iml_ineta_family;  /* family IPV4 / IPV6 */
   ADSL_CLUSTER_INETA_THIS_G->usc_ineta_length = iml_len_ineta;  /* length of following address */
   ADSL_CLUSTER_INETA_THIS_G->achc_end_used = achl_fill_ineta_1;  /* address used till here */
   ims_cluster_ineta_sequ++;                /* sequence number cluster queries */
   ADSL_CLUSTER_INETA_THIS_G->adsc_next = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
   adss_cluster_ineta_this = ADSL_CLUSTER_INETA_THIS_G;  /* set new chain save INETA this cluster member */
#undef ADSL_CLUSTER_INETA_THIS_G
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */

   p_cluster_00:                            /* send to cluster members and wait for response */
   if (adsl_cluster_ineta_temp_w1) {        /* temporary INETAs received from other cluster member */
     m_proc_free( adsl_cluster_ineta_temp_w1 );  /* free the buffer    */
     adsl_cluster_ineta_temp_w1 = NULL;     /* clear temporary INETAs received from other cluster member */
   }
#define ADSL_CLUSTER_INETA_THIS_G ((struct dsd_cluster_ineta_this *) al_work1)
   iml1 = m_send_cluster_ineta( ADSL_CLUSTER_INETA_THIS_G );
   /* ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec is set by m_send_cluster_ineta() */
   bol_lock_set = TRUE;                     /* lock is set             */
   dsg_global_lock.m_enter();
   ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding += iml1;  /* number of responses outstanding */
   if (ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding == 0) {  /* check number of responses outstanding */
     goto p_cluster_20;                     /* cluster members have responed */
   }
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */
   bol1 = FALSE;                            /* end time not yet set    */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d before wait ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec=%d m_get_epoch_ms()=%lld.",
                   __LINE__, ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec, m_get_epoch_ms() );
#endif
   do {
     ill_time_cur = m_get_epoch_ms();       /* current time            */
     if (bol1 == FALSE) {                   /* end time not yet set    */
       ill_time_end = ill_time_cur + ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec;  /* set end time wait */
       bol1 = TRUE;                         /* end time set now        */
     }
     if (ill_time_cur >= ill_time_end) break;
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
     {
       int imh1 = (ill_time_end - ill_time_cur + 1000 - 1) / 1000;
       int imh2 = imh1;
       if (   (imh2 <= 0)
           << (imh2 > 10)) {
         imh2 = 10;
       }
       m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d        wait for %d seconds - corrected to %d seconds",
                       __LINE__, imh1, imh2 );
       HL_LONGLONG ilh_time_1 = m_get_epoch_ms();  /* current time     */
       m_hco_wothr_wait_sec( adsp_hco_wothr, imh2 );
       HL_LONGLONG ilh_time_2 = m_get_epoch_ms();  /* current time     */
       int imh3 = ilh_time_2 - ilh_time_1;
       m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d m_hco_wothr_wait_sec() returned after %d milliseconds ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding=%d.",
                       __LINE__, imh3, ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding );
       if (ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding == 0) break;
#ifdef HL_UNIX
       sleep( 10 );
       break;
#endif
     }
#endif
     m_hco_wothr_wait_sec( adsp_hco_wothr, (ill_time_end - ill_time_cur + 1000 - 1) / 1000 );
   } while (ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding != 0);
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d %08d after  wait ill_time_cur=%lld.",
                   __LINE__, HL_THRID, ill_time_cur );
#endif
#ifdef TRY100514$02
   Sleep( 3000 );                           /* generate collision      */
#endif

   p_cluster_20:                            /* cluster members have responed */
   if (bol_lock_set == FALSE) {             /* lock not set            */
     bol_lock_set = TRUE;                   /* lock is set             */
     dsg_global_lock.m_enter();
   }
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d %08d m_update_htun_ineta() p_cluster_20: after m_enter()",
                   __LINE__, HL_THRID );
#endif
   adsl_cluster_ineta_wait_ch = ADSL_CLUSTER_INETA_THIS_G->adsc_cluster_ineta_wait;  /* get wait to process INETAs this cluster member */
   al_free_1 = ADSL_CLUSTER_INETA_THIS_G->ac_ineta_buffer;  /* buffer with INETAs sent */
   adsl_cluster_ineta_temp_w1 = ADSL_CLUSTER_INETA_THIS_G->adsc_cluster_ineta_temp;  /* temporary INETAs received from other cluster member */
   if (ADSL_CLUSTER_INETA_THIS_G->imc_resp_outstanding != 0) {
     bol_err_resp_cluster = TRUE;           /* give error message cluster responses */
   }
   /* remove from chain save INETA this cluster member                 */
   if (ADSL_CLUSTER_INETA_THIS_G == adss_cluster_ineta_this) {
     adss_cluster_ineta_this = ADSL_CLUSTER_INETA_THIS_G->adsc_next;  /* remove from chain save INETA this cluster member */
   } else {                                 /* remove from middle of chain */
     adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
     bol1 = TRUE;
     while ((adsl_cluster_ineta_this_w1) && (adsl_cluster_ineta_this_w1->adsc_next != ADSL_CLUSTER_INETA_THIS_G)) {
       adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
     }
     if (adsl_cluster_ineta_this_w1) {
       adsl_cluster_ineta_this_w1->adsc_next = ADSL_CLUSTER_INETA_THIS_G->adsc_next;  /* remove from chain save INETA this cluster member */
       bol1 = FALSE;
     }
     if (bol1) bol_err_illogic = TRUE;      /* give error message illogic */
   }
   if (ADSL_CLUSTER_INETA_THIS_G->boc_rejected == FALSE) {  /* request has been rejected by other cluster member */
     goto p_cluster_28;                     /* continue response from other cluster members */
   }
   /* request to cluster members has been rejected                     */
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */
   while (adsl_cluster_ineta_wait_ch) {     /* wait to process INETAs this cluster member */
     adsl_cluster_ineta_wait_w1 = adsl_cluster_ineta_wait_ch;  /* get this entry */
     adsl_cluster_ineta_wait_ch = adsl_cluster_ineta_wait_ch->adsc_next;  /* remove from chain */
     adsl_cluster_ineta_wait_w1->boc_end_wait = TRUE;  /* end of waiting */
     m_hco_wothr_post( adsp_hco_wothr, adsl_cluster_ineta_wait_w1->adsc_hco_wothr );
   }
   if (adsl_cluster_ineta_temp_w1) {        /* temporary INETAs received from other cluster member */
     m_proc_free( adsl_cluster_ineta_temp_w1 );  /* free the buffer    */
     adsl_cluster_ineta_temp_w1 = NULL;     /* clear temporary INETAs received from other cluster member */
   }
   iml_rejected++;                          /* count times rejected by other cluster members */
   iml1 = m_get_random_number( iml_rejected
                                 * RANDOM_INETA_CLUSTER_WAIT
                                 * ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec )
            + ADSL_CLUSTER_INETA_THIS_G->imc_timeout_msec;
#ifndef HL_UNIX
   Sleep( iml1 );
#else
   usleep( iml1 * 1000 );
#endif
   achl_fill_ineta_1 = NULL;                /* fill INETA              */
   iml_count_cluster = m_cluster_count_active();  /* count the cluster members */
   if (bol_search_appl == FALSE) {          /* INETA PPP               */
     goto p_new_ineta_00;                   /* needs new INETA         */
   }
   goto p_appl_check;                       /* check appl              */

   p_cluster_28:                            /* continue response from other cluster members */
   achl1 = (char *) (ADSL_CLUSTER_INETA_THIS_G + 1);
   achl2 = ADSL_CLUSTER_INETA_THIS_G->achc_end_used;  /* address used till here */
   if (adsl_cluster_ineta_temp_w1) {        /* temporary INETAs received from other cluster member */
     achl1 = (char *) (adsl_cluster_ineta_temp_w1 + 1);
     achl2 = adsl_cluster_ineta_temp_w1->achc_end_used;  /* address used till here */
   }
   if (achl1 >= achl2) {                    /* no entries              */
     goto p_cluster_80;                     /* did not find free INETA */
   }
   if (ADSL_CLUSTER_INETA_THIS_G->adsc_pool_ineta_1) {  /* pool of INETAs */
     goto p_cluster_40;                     /* search INETA in pool    */
   }
   adsl_ineta_single_1_w1 = (struct dsd_ineta_single_1 *) (adsp_co_ineta + 1);  /* single INETA target / listen / configured */
   iml_rem_no_ineta = adsp_co_ineta->imc_no_ineta;  /* remaining number of INETA */

   p_cluster_32:                            /* check entry in configuration */
   if (iml_rem_no_ineta <= 0) {             /* at end of table         */
     goto p_cluster_36;                     /* end of entries in configuration */
   }
   if (adsl_ineta_single_1_w1->usc_family != iml_ineta_family) {  /* family IPV4 / IPV6 */
     adsl_ineta_single_1_w1
       = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                   + sizeof(struct dsd_ineta_single_1)
                                                   + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
     iml_rem_no_ineta--;                    /* remaining number of INETA */
     goto p_cluster_32;                     /* check entry in configuration */
   }
   memcpy( achl_ineta_raws_t,
           adsl_ineta_single_1_w1 + 1,
           adsl_ineta_single_1_w1->usc_length );  /* length of following address */
   achl3 = achl1;                           /* start of array start and end INETA */
   bol1 = FALSE;                            /* INETA not found in array */
   do {
     iml_cmp = memcmp( achl_ineta_raws_t,
                       achl3,
                       iml_len_ineta );
     if (iml_cmp < 0) break;                /* elements are sorted     */
     if (iml_cmp == 0) {                    /* INETA found in array    */
       bol1 = TRUE;                         /* set flag                */
       break;
     }
     iml_cmp = memcmp( achl_ineta_raws_t,
                       achl3 + iml_len_ineta,
                       iml_len_ineta );
     if (iml_cmp <= 0) {                    /* INETA found in array    */
       bol1 = TRUE;                         /* set flag                */
       break;
     }
     achl3 += 2 * iml_len_ineta;
   } while (achl3 < achl2);
   if (bol1 == FALSE) {                     /* INETA not found in array */
     adsl_ineta_single_1_w1
       = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                   + sizeof(struct dsd_ineta_single_1)
                                                   + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
     iml_rem_no_ineta--;                    /* remaining number of INETA */
     goto p_cluster_32;                     /* check entry in configuration */
   }
#ifdef XYZ1
   if (bol_lock_set == FALSE) {             /* lock not set            */
     bol_lock_set = TRUE;                   /* lock is set             */
     dsg_global_lock.m_enter();
   }
#endif
   bol1 = m_htree1_avl_search( (void *) "C", adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   /* this entry has been processed                                    */
   if (dsl_htree1_work.adsc_found) {        /* entry already in use    */
     adsl_ineta_single_1_w1
       = (struct dsd_ineta_single_1 *) ((char *) adsl_ineta_single_1_w1
                                                   + sizeof(struct dsd_ineta_single_1)
                                                   + adsl_ineta_single_1_w1->usc_length );  /* length of following address */
     iml_rem_no_ineta--;                    /* remaining number of INETA */
     goto p_cluster_32;                     /* check entry in configuration */
   }
   goto p_ret_ok_00;                        /* INETA was found         */

   p_cluster_36:                            /* end of entries in configuration */
   if (bol_search_appl) {                   /* INETA appl              */
     goto p_ret_err;                        /* no INETA found          */
   }
   goto p_pool_00;                          /* search INETA in pool    */

   p_cluster_40:                            /* search INETA in pool    */
#define ADSL_POOL_INETA_1_G ADSL_CLUSTER_INETA_THIS_G->adsc_pool_ineta_1
   /* check all INETAs of this pool entry                              */
   achl_pool_e1 = (char *) (ADSL_POOL_INETA_1_G + 1);  /* address first extension */
   iml1 = ADSL_POOL_INETA_1_G->imc_no_ext;  /* number of extensions    */

   p_cluster_48:                            /* check this extension    */
   memcpy( achl_ineta_raws_t,
           achl_pool_e1 + sizeof(int),
           iml_len_ineta );
   memcpy( chrl_work1,
           achl_ineta_raws_t,
           iml_len_ineta );
   m_ineta_op_add( chrl_work1,
                   iml_len_ineta,
                   *((int *) achl_pool_e1) - 1 );
#define ACHL_INETA_SAVE_G (chrl_work1 + 1 * 32)
   memcpy( ACHL_INETA_SAVE_G,
           chrl_work1,
           iml_len_ineta );

   p_cluster_52:                            /* compare INETAs with those received from cluster members */
   achl3 = achl1;                           /* start of array start and end INETA */
   bol1 = FALSE;                            /* INETA not found in array */
   do {
     iml_cmp = memcmp( achl_ineta_raws_t,
                       achl3 + iml_len_ineta,
                       iml_len_ineta );
     if (iml_cmp > 0) break;
     iml_cmp = memcmp( chrl_work1,
                       achl3,
                       iml_len_ineta );
     if (iml_cmp >= 0) {                    /* INETA found in array    */
       iml_cmp = memcmp( achl_ineta_raws_t,
                         achl3,
                         iml_len_ineta );
       if (iml_cmp < 0) {
         memcpy( achl_ineta_raws_t,
                 achl3,
                 iml_len_ineta );
       }
       iml_cmp = memcmp( chrl_work1,
                         achl3 + iml_len_ineta,
                         iml_len_ineta );
       if (iml_cmp > 0) {
         memcpy( chrl_work1,
                 achl3 + iml_len_ineta,
                 iml_len_ineta );
       }
       bol1 = TRUE;                         /* set flag                */
       break;
     }
     achl3 += 2 * iml_len_ineta;
   } while (achl3 < achl2);
   if (bol1 == FALSE) {                     /* INETA not found in array */
     goto p_cluster_68;                     /* this entry has been processed */
   }
   bol1 = m_htree1_avl_search( NULL, adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* entry currently not in use */
     ADSL_POOL_INETA_1_G->umc_last_all_in_use = 0;  /* not all elements in use */
     goto p_ret_ok_00;                      /* INETA was found         */
   }

   p_cluster_56:                            /* read sequential in AVL-tree */
   iml_cmp = memcmp( achl_ineta_raws_t,
                     chrl_work1,
                     iml_len_ineta );
   if (iml_cmp >= 0) {                      /* end of this range       */
     goto p_cluster_60;                     /* no free INETA in this range found */
   }
   m_ineta_op_inc( achl_ineta_raws_t, iml_len_ineta );
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_ineta,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file reached   */
     ADSL_POOL_INETA_1_G->umc_last_all_in_use = 0;  /* not all elements in use */
     goto p_ret_ok_00;                      /* INETA was found         */
   }
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - iml_disp_sort_ineta))
   iml_cmp = memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                     achl_ineta_raws_t,
                     iml_len_ineta );
   if (iml_cmp > 0) {                       /* after this INETA        */
     ADSL_POOL_INETA_1_G->umc_last_all_in_use = 0;  /* not all elements in use */
     goto p_ret_ok_00;                      /* INETA was found         */
   }
   goto p_cluster_56;                       /* read sequential in AVL-tree */

   p_cluster_60:                            /* no free INETA in this range found */
   iml_cmp = memcmp( ACHL_INETA_SAVE_G,
                     chrl_work1,
                     iml_len_ineta );
   if (iml_cmp <= 0) {                      /* no more INETAs in this entry */
     goto p_cluster_68;                     /* this entry has been processed */
   }
   memcpy( achl_ineta_raws_t,
           chrl_work1,
           iml_len_ineta );
   m_ineta_op_inc( achl_ineta_raws_t, iml_len_ineta );
   memcpy( chrl_work1,
           ACHL_INETA_SAVE_G,
           iml_len_ineta );
   goto p_cluster_52;                       /* compare INETAs with those received from cluster members */

   p_cluster_68:                            /* this entry has been processed */
   achl_pool_e1 += sizeof(int) + adsl_pool_ineta_1_w1->usc_ineta_length;
   iml1--;                                  /* decrement remeining number of extensions */
   if (iml1 > 0) goto p_cluster_48;         /* check this extension    */

   /* all INETAs of this pool entry are in use                         */
   ADSL_POOL_INETA_1_G->umc_last_all_in_use = (unsigned int) time( NULL );
   goto p_pool_00;                          /* search INETA in pool    */

#undef ACHL_INETA_SAVE_G
#undef ADSL_INETA_RAWS_1_G

   p_cluster_80:                            /* did not find free INETA */
   if (ADSL_CLUSTER_INETA_THIS_G->adsc_pool_ineta_1) {  /* pool of INETAs */
     /* set time all in use                                            */
     ADSL_CLUSTER_INETA_THIS_G->adsc_pool_ineta_1->umc_last_all_in_use
       = (unsigned int) time( NULL );
     goto p_pool_00;                        /* search INETA in pool    */
   }
#ifndef B140714
   if (bol_search_appl == FALSE) {          /* not INETA appl          */
     achl_fill_ineta_1 = NULL;              /* fill INETA              */
     goto p_pool_00;                        /* search INETA in pool    */
   }
#endif
   goto p_ret_err;                          /* no INETA found          */

#undef ADSL_CLUSTER_INETA_THIS_G

   p_ret_ok_00:                             /* INETA was found         */
   if (bol_search_appl == FALSE) {          /* normal INETA            */
     goto p_ret_ok_60;                      /* all complete            */
   }

   /* give port to be used                                             */
   adsl_appl_port_conf_w1 = (struct dsd_appl_port_conf *) chrl_work1;  /* configured ports for appl in work area */
   adsl_appl_port_conf_w1->usc_port_start = DEF_APPL_USE_SOURCE_P_START;  /* port to start with */
   adsl_appl_port_conf_w1->usc_no_ports = DEF_APPL_USE_SOURCE_P_NO;  /* number of ports */
   iml1 = 1;                                /* number of port entries  */
   bol1 = FALSE;                            /* not random              */
   if (adsl_raw_packet_if_conf) {           /* configuration raw-packet-interface */
     bol1 = adsl_raw_packet_if_conf->boc_random_appl_port;  /* <appl-use-random-tcp-source-port> */
     if (adsl_raw_packet_if_conf->imc_no_ele_appl_port_conf) {  /* number of elements configured ports for appl */
       adsl_appl_port_conf_w1 = adsl_raw_packet_if_conf->adsc_appl_port_conf;  /* configured ports for appl */
       iml1 = adsl_raw_packet_if_conf->imc_no_ele_appl_port_conf;  /* get number of elements configured ports for appl */
     }
   }
   iml2 = 0;                                /* position port in sequence */
   if (bol1) {                              /* random                  */
     iml3 = 0;                              /* clear index             */
     do {
       iml2 += (adsl_appl_port_conf_w1 + iml3)->usc_no_ports;
       iml3++;                              /* increment index         */
     } while (iml3 < iml1);
     iml2 = m_get_random_number( iml2 );
   }
   iml3 = 0;                                /* clear index             */
   iml1 = 0;                                /* clear number to add     */
   while (iml2 >= (adsl_appl_port_conf_w1 + iml3)->usc_no_ports) {
     iml2 -= (adsl_appl_port_conf_w1 + iml3)->usc_no_ports;
     iml3++;                                /* increment index         */
   }
   adsp_ineta_raws_1->usc_appl_port
     = (adsl_appl_port_conf_w1 + iml3)->usc_port_start + iml2;  /* port in use */

   p_ret_ok_60:                             /* all complete            */
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA check INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &((struct sockaddr_in *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 0),
                   *((unsigned char *) &((struct sockaddr_in *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 1),
                   *((unsigned char *) &((struct sockaddr_in *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 2),
                   *((unsigned char *) &((struct sockaddr_in *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   bol1 = m_htree1_avl_search( NULL, adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   if (dsl_htree1_work.adsc_found) {        /* entry already in tree   */
     sprintf( chrl_work1,
              "m_htree1_avl_search() for new element did return element l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
     bol1 = TRUE;                           /* start first record      */
     while (TRUE) {                         /* loop to print AVL tree  */
       BOOL   boh1;
       boh1 = m_htree1_avl_getnext( NULL, adsl_hac_ineta,
                                    &dsl_htree1_work, bol1 );
       if (boh1 == FALSE) break;            /* error occured           */
       if (dsl_htree1_work.adsc_found == NULL) break;  /* end of AVL tree */
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
       m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d update HOB-TUN INETA in AVL tree INETA %d.%d.%d.%d.",
                           __LINE__,
                           *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 0),
                           *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 1),
                           *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 2),
                           *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 3) );
#undef ADSL_INETA_RAWS_1_G
       bol1 = FALSE;                        /* continue no first record */
     }
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
     goto p_ret_err;                        /* no INETA found          */
   }
   bol1 = m_htree1_avl_insert( NULL, adsl_hac_ineta,
                               &dsl_htree1_work, adsl_sort_ineta_w1 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_insert() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   if (bol_search_appl) {                   /* search appl             */
     bol1 = m_htree1_avl_search( NULL, adsl_hac_user_i,
                                 &dsl_htree1_work, &adsp_ineta_raws_1->dsc_sort_user );
     if (bol1 == FALSE) {                   /* error occured           */
       sprintf( chrl_work1,
                "m_htree1_avl_search() failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       goto p_ret_err;                      /* no INETA found          */
     }
     if (dsl_htree1_work.adsc_found) {      /* entry already in tree   */
       sprintf( chrl_work1,
                "m_htree1_avl_search() for new element did return element l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       goto p_ret_err;                      /* no INETA found          */
     }
     if (iml_ineta_family == AF_INET) {     /* family IPV4 / IPV6 - IPV4 */
       adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_port = htons( adsp_ineta_raws_1->usc_appl_port );
     } else {                               /* IPV6                    */
       adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_port = htons( adsp_ineta_raws_1->usc_appl_port );
     }
     bol1 = m_htree1_avl_insert( NULL, adsl_hac_user_i,
                                 &dsl_htree1_work, &adsp_ineta_raws_1->dsc_sort_user );
     if (bol1 == FALSE) {                   /* error occured           */
       sprintf( chrl_work1,
                "m_htree1_avl_insert() failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       goto p_ret_err;                      /* no INETA found          */
     }
   }
   if (bol_route_add) {                     /* add a route             */
     /* give work to serialisation thread to add a route               */
     adsl_ser_thr_task_w1 = dss_ser_thr_ctrl.adsc_sth_free;  /* chain of free structures */
     if (adsl_ser_thr_task_w1 == NULL) {    /* we need more entries    */
       adsl_ser_thr_task_w1 = adsl_ser_thr_task_free;
       adsl_ser_thr_task_free = NULL;
     }
     dss_ser_thr_ctrl.adsc_sth_free = adsl_ser_thr_task_w1->adsc_next;
     memset( adsl_ser_thr_task_w1, 0, sizeof(struct dsd_ser_thr_task) );  /* task for serial thread */
// to-do 03.07.10 KB attention IPV6
     adsl_ser_thr_task_w1->iec_sth = ied_sth_route_ipv4_add;  /* add a route IPV4 */
     memcpy( adsl_ser_thr_task_w1->chrc_ineta,
             achl_ineta_raws_t,
             iml_len_ineta );
#ifdef B120917
     adsl_ser_thr_task_w1->umc_index_if_arp = dsl_work_i.dsc_ineta_raws_1.umc_index_if_arp;  /* holds index of compatible IF for ARP */
     adsl_ser_thr_task_w1->umc_index_if_route = dsl_work_i.dsc_ineta_raws_1.umc_index_if_route;  /* holds index of compatible IF for routes */
     adsl_ser_thr_task_w1->umc_taif_ineta = dsl_work_i.dsc_ineta_raws_1.umc_taif_ineta;  /* <TUN-adapter-use-interface-ineta> */
#endif
     adsl_ser_thr_task_w1->umc_index_if_arp = adsp_ineta_raws_1->umc_index_if_arp_ipv4;  /* holds index of compatible IF for ARP */
     adsl_ser_thr_task_w1->umc_index_if_route = adsp_ineta_raws_1->umc_index_if_route_ipv4;  /* holds index of compatible IF for routes */
     adsl_ser_thr_task_w1->umc_taif_ineta = adsp_ineta_raws_1->umc_taif_ineta_ipv4;  /* <TUN-adapter-use-interface-ineta> */
#define ABOL_POSTED ((BOOL *) adsp_hco_wothr->vprc_aux_area)  /* temporarily use this storage */
     *ABOL_POSTED = FALSE;
     adsl_ser_thr_task_w1->aboc_posted = ABOL_POSTED;  /* mark posted  */
     adsl_ser_thr_task_w1->adsc_event_posted = &adsp_hco_wothr->dsc_event;  /* event for posted */
     /* append at end of chain to process                              */
     if (dss_ser_thr_ctrl.adsc_sth_work == NULL) {  /* work as task for serial thread */
       dss_ser_thr_ctrl.adsc_sth_work = adsl_ser_thr_task_w1;  /* work as task for serial thread */
       bol_ser_post = TRUE;                 /* post serialize thread   */
     } else {
       adsl_ser_thr_task_w2 = dss_ser_thr_ctrl.adsc_sth_work;  /* get chain */
       while (adsl_ser_thr_task_w2->adsc_next) adsl_ser_thr_task_w2 = adsl_ser_thr_task_w2->adsc_next;
       adsl_ser_thr_task_w2->adsc_next = adsl_ser_thr_task_w1;
     }
   }
   dsg_global_lock.m_leave();
   if (bol_ser_post) {                      /* post serialize thread   */
#ifdef HL_UNIX
     if (dss_loconf_1.boc_listen_gw == FALSE) {  /* do not use listen gateway */
#endif
       iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_post( &iml_error );  /* event for serial thread */
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPM155W l%05d update HOB-TUN INETA event serial m_post Return Code %d Error %d.",
                         __LINE__, iml_rc, iml_error );
       }
#ifdef HL_UNIX
     } else {                               /* do use listen gateway   */
       iml_rc = write( imrs_m_fd_pipe[1], vprs_message_work, sizeof(vprs_message_work) );
       if (iml_rc != sizeof(vprs_message_work)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW m_update_htun_ineta() l%05d write pipe work error %d %d.",
                         __LINE__, iml_rc, errno );
       }
     }
#endif
   }
   while (adsl_cluster_ineta_wait_ch) {     /* wait to process INETAs this cluster member */
     adsl_cluster_ineta_wait_w1 = adsl_cluster_ineta_wait_ch;  /* get this entry */
     adsl_cluster_ineta_wait_ch = adsl_cluster_ineta_wait_ch->adsc_next;  /* remove from chain */
     adsl_cluster_ineta_wait_w1->boc_end_wait = TRUE;  /* end of waiting */
     m_hco_wothr_post( adsp_hco_wothr, adsl_cluster_ineta_wait_w1->adsc_hco_wothr );
   }
   /* make sockaddr entry valid                                        */
   switch (iml_ineta_family) {              /* family IPV4 / IPV6      */
     case AF_INET:                          /* IPV4                    */
       adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_family = AF_INET;
       break;
     case AF_INET6:                         /* IPV6                    */
       adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_family = AF_INET6;
       break;
     default:
       goto p_ret_err;                      /* return with error       */
   }
#ifdef B110314
   if (bol_route_add == FALSE) goto p_ret_end;  /* housekeeping        */
#else
   if (bol_route_add == FALSE) {            /* no add route needed     */
     bol1 = TRUE;                           /* return success          */
     goto p_ret_end;                        /* housekeeping            */
   }
#endif
   /* wait till route has been added by serialize thread               */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d %08d m_update_htun_ineta() before wait ABOL_POSTED=%p *ABOL_POSTED=%d.",
                   __LINE__, HL_THRID, ABOL_POSTED, *ABOL_POSTED );
#endif
   while (*ABOL_POSTED == FALSE) {
     m_hco_wothr_wait( adsp_hco_wothr );
   }
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d %08d m_update_htun_ineta() after  wait ABOL_POSTED=%p *ABOL_POSTED=%d.",
                   __LINE__, HL_THRID, ABOL_POSTED, *ABOL_POSTED );
#endif
   *ABOL_POSTED = FALSE;                    /* clear temporary used variable again */
   bol1 = TRUE;                             /* return success          */
   goto p_ret_end;                          /* housekeeping            */
#undef ABOL_POSTED

   p_ret_err:                               /* return with error       */
   if (bol_lock_set) {                      /* lock was set            */
     dsg_global_lock.m_leave();
   }
   while (adsl_cluster_ineta_wait_ch) {     /* wait to process INETAs this cluster member */
     adsl_cluster_ineta_wait_w1 = adsl_cluster_ineta_wait_ch;  /* get this entry */
     adsl_cluster_ineta_wait_ch = adsl_cluster_ineta_wait_ch->adsc_next;  /* remove from chain */
     adsl_cluster_ineta_wait_w1->boc_end_wait = TRUE;  /* end of waiting */
     m_hco_wothr_post( adsp_hco_wothr, adsl_cluster_ineta_wait_w1->adsc_hco_wothr );
   }
   if (achl_avl_error) {                    /* display error AVL tree  */
     m_hlnew_printf( HLOG_WARN1, "HWSPM140W update HOB-TUN INETA %s",
                     achl_avl_error );
   }
   bol1 = FALSE;                            /* return error            */

   p_ret_end:                               /* housekeeping            */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNIADU", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = adsp_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     if (bol1 == FALSE) {                   /* no INETA found          */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_update_htun_ineta( %p ) -  ac_conn1 %p SNO=%08d - returns FALSE, no INETA",
                                          __LINE__,
                                          adsp_ineta_raws_1,
                                          adsp_conn1,
                                          adsp_conn1->dsc_co_sort.imc_sno );
     } else {                               /* INETA inserted          */
       if (iml_ineta_family == AF_INET) {   /* IPV4                    */
         adsl_soa_l = (struct sockaddr *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
         iml1 = sizeof(struct sockaddr_in);
       } else {                             /* IPV6                    */
         adsl_soa_l = (struct sockaddr *) &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv6;
         iml1 = sizeof(struct sockaddr_in6);
       }
       iml_rc = getnameinfo( adsl_soa_l, iml1,
                             chrl_work1, sizeof(chrl_work1), 0, 0, NI_NUMERICHOST );
       if (iml_rc) {                            /* error occured           */
         strcpy( chrl_work1, "???" );
       }
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_update_htun_ineta( %p ) -  ac_conn1 %p SNO=%08d - returns TRUE, INETA \"%s\"",
                                          __LINE__,
                                          adsp_ineta_raws_1,
                                          adsp_conn1,
                                          adsp_conn1->dsc_co_sort.imc_sno,
                                          chrl_work1 );
     }
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (bol1)                          /* INETA inserted          */
         && (bol_search_appl)) {            /* search appl             */
       achl1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + ADSL_WTR_G1->imc_length + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl1)
       memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       ADSL_WTR_G2->imc_length = m_hlsnprintf( (char *) (ADSL_WTR_G2 + 1), 256, ied_chs_ansi_819,
                                               "  TCP-port %d group=%(ucs)s userid=%(ucs)s.",
                                               adsp_ineta_raws_1->usc_appl_port,
                                               &adsp_ineta_raws_1->dsc_user_group,
                                               &adsp_ineta_raws_1->dsc_user_name );
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G2->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G2 + 1);
       ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain       */
#undef ADSL_WTR_G2
     }
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bol_err_savebl_full) {               /* give error message later */
     m_hlnew_printf( HLOG_WARN1, "HWSPM141W update HOB-TUN INETA buffer with INETAs overflow" );
   }
   if (bol_err_illogic) {                   /* give error message illogic */
     m_hlnew_printf( HLOG_WARN1, "HWSPM142W update HOB-TUN INETA situation illogic" );
   }
   if (bol_err_resp_cluster) {              /* give error message cluster responses */
     m_hlnew_printf( HLOG_WARN1, "HWSPM143W update HOB-TUN INETA not all cluster members responded" );
   }
   if (iml_rejected) {                      /* count times rejected by other cluster members */
     m_hlnew_printf( HLOG_WARN1, "HWSPM144W update HOB-TUN INETA other cluster members rejected request %d times",
                     iml_rejected );
   }
   if (adsl_ser_thr_task_free) free( adsl_ser_thr_task_free );
   if (al_work1) m_proc_free( al_work1 );   /* work area buffer        */
   if (al_free_1) m_proc_free( al_free_1 );  /* buffer to be freed     */
   if (adsl_cluster_ineta_temp_w1) m_proc_free( adsl_cluster_ineta_temp_w1 );  /* temporary INETAs received from other cluster member */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d %08d m_update_htun_ineta() returns %d.",
                   __LINE__, HL_THRID, bol1 );
#endif
   return bol1;
} /* end m_update_htun_ineta()                                         */

extern "C" struct dsd_tun_contr_ineta *
     m_htun_ppp_acquire_local_ineta_ipv4( struct dsd_hco_wothr *adsp_hco_wothr,
                                          struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                          struct dsd_tun_contr_ineta *adsp_tun_contr_ineta ) {
   BOOL       bol1;                         /* working variable        */
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_config_ineta_1 *adsl_co_ineta_w1;  /* configured INETAs  */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* used INETA       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#ifndef HL_UNIX
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
#endif
#ifdef HL_UNIX
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_htun_ppp_acquire_local_ineta_ipv4-l%05d-T adsp_tun_contr_conn=%p adsl_conn1=%p.",
                   __LINE__, adsp_tun_contr_conn, adsl_conn1 );
#endif
   adsl_co_ineta_w1 = NULL;                 /* configured INETAs       */
#define ADSL_SESSCO1_G ((struct dsd_auxf_sessco1 *) (adsl_auxf_1_w1 + 1))
   adsl_auxf_1_w1 = adsl_conn1->adsc_auxf_1;  /* get first element     */
   while (adsl_auxf_1_w1) {                 /* loop over chain         */
     if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_sessco1) {  /* session configuration */
#ifdef B131129
       adsl_co_ineta_w1 = ADSL_SESSCO1_G->adsc_co_ineta_appl;  /* configured INETAs application / HTCP */
#else
       adsl_co_ineta_w1 = ADSL_SESSCO1_G->adsc_co_ineta_ppp;  /* configured INETAs PPP */
#endif
       break;
     }
     adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
   }
#undef ADSL_SESSCO1_G
   if (adsl_co_ineta_w1 == NULL) {          /* no configuration found  */
     if (adsl_conn1->adsc_user_entry) {     /* structure user entry    */
#ifdef B140713
       adsl_co_ineta_w1 = adsl_conn1->adsc_user_entry->adsc_config_ineta_1_appl;  /* configured INETAs application / HTCP */
#endif
       adsl_co_ineta_w1 = adsl_conn1->adsc_user_entry->adsc_config_ineta_1_ppp;  /* configured INETA PPP */
     }
   }

   if (adsp_tun_contr_ineta) {
     adsl_ineta_raws_1_w1
       = (struct dsd_ineta_raws_1 *)
           ((char *) adsp_tun_contr_ineta - offsetof( struct dsd_ineta_raws_1 , dsc_tun_contr_ineta ));  /* used INETA */
     goto p_acqu_20;                        /* start update            */
   }
   adsl_ineta_raws_1_w1 = (struct dsd_ineta_raws_1 *) malloc( sizeof(struct dsd_ineta_raws_1) );
   memset( adsl_ineta_raws_1_w1, 0, sizeof(struct dsd_ineta_raws_1 ) );
   adsl_ineta_raws_1_w1->ac_conn1 = adsl_conn1;  /* for this connection */
   adsl_ineta_raws_1_w1->dsc_htun_h = adsl_conn1->dsc_htun_h;  /* handle of HOB-TUN */
   adsl_conn1->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;

   p_acqu_20:                               /* start update            */
   bol1 = m_update_htun_ineta( adsl_ineta_raws_1_w1,
                               adsl_conn1,
                               adsp_hco_wothr,
                               ied_ineta_raws_n_ipv4,  /* INETA IPV4 */
                               adsl_co_ineta_w1 );
   if (bol1) return &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta;
   if (adsp_tun_contr_ineta) return NULL;
   adsl_conn1->adsc_ineta_raws_1 = NULL;
   free( adsl_ineta_raws_1_w1 );            /* free structure again    */
   return NULL;                             /* could not assign INETA  */
} /* end m_htun_ppp_acquire_local_ineta_ipv4()                         */

/**
   Cleanup INETA when no more used.
   The routine m_cleanup_htun_ineta() is called for INETAs of HOB-TUN and L2TP.
*/
static void m_cleanup_htun_ineta( struct dsd_ineta_raws_1 *adsp_ineta_raws_1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code 1           */
   int        iml_error;                    /* return code 2           */
   int        iml_cmp;                      /* for compare operations  */
#ifdef XYZ1
   unsigned short int usl_ineta_length;     /* length of INETA         */
#endif
   BOOL       bol_no_tun;                   /* INETA not for TUN-adapter */
   BOOL       bol_failed_del_appl;          /* failed to delete appl   */
   BOOL       bol_route_del_ipv4;           /* delete the route IPV4   */
   BOOL       bol_ser_post;                 /* post serialize thread   */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_ser_thr_task *adsl_ser_thr_task_free;  /* task for serial thread */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w1;  /* task for serial thread */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w2;  /* task for serial thread */
   struct dsd_htree1_avl_cntl *adsl_hac_ineta;
   struct dsd_htree1_avl_cntl *adsl_hac_user_i;
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   DSD_CONN_G *adsl_conn1;                  /* connection              */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct {
     struct dsd_auxf_1 dsc_auxf_1;
     struct dsd_ineta_raws_1 dsc_ineta_raws_1;  /* INETA in use        */
   } dsl_work_i;
   char       chrl_work1[ 256 ];            /* work area               */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HOB-TUN l%05d m_cleanup_htun_ineta( %p ) called",
                   __LINE__, adsp_ineta_raws_1 );
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_conn1 = (DSD_CONN_G *) adsp_ineta_raws_1->ac_conn1;
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNIADC", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     if (adsl_conn1) {                      /* with connection         */
       adsl_wt1_w1->imc_wtrt_sno = adsl_conn1->dsc_co_sort.imc_sno;  /* WSP session number */
     }
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     if (adsl_conn1 == NULL) {              /* no connection           */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_cleanup_htun_ineta( %p ) -  ac_conn1 NULL",
                                          __LINE__,
                                          adsp_ineta_raws_1 );
     } else {                               /* with connection         */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_cleanup_htun_ineta( %p ) -  ac_conn1 %p SNO=%08d.",
                                          __LINE__,
                                          adsp_ineta_raws_1,
                                          adsl_conn1,
                                          adsl_conn1->dsc_co_sort.imc_sno );
     }
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef XYZ1
   memset( &dsl_work_i, 0, sizeof(dsl_work_i) );
   bol_lock_set = FALSE;                    /* lock not set            */
   bol_err_savebl_full = FALSE;             /* give error message later */
   bol_err_illogic = FALSE;                 /* give error message illogic */
   bol_err_resp_cluster = FALSE;            /* give error message cluster responses */
#endif
   bol_route_del_ipv4 = FALSE;              /* delete the route IPV4   */
   bol_failed_del_appl = FALSE;             /* failed to delete appl   */
   bol_ser_post = FALSE;                    /* post serialize thread   */
   bol_no_tun = FALSE;                      /* INETA not for TUN-adapter */
// to-do 10.12.12 KB - check no-tun - L2TP
   if (adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_family) {  /* with IPV4 */
     bol_route_del_ipv4 = TRUE;             /* delete the route IPV4   */
   }
// to-do 15.09.12 KB - IPV4 and IPV6
#ifdef XYZ1
   switch (adsp_ineta_raws_1->iec_irs) {    /* type of INETA raw socket */
     case ied_ineta_raws_n_ipv4:            /* INETA IPV4              */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 4;  /* length of following address */
#endif
       usl_ineta_length = 4;                /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       bol_search_appl = FALSE;             /* search appl             */
       bol_route_del = TRUE;                /* delete the route        */
       break;
     case ied_ineta_raws_n_ipv6:            /* INETA IPV6              */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET6;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 16;  /* length of following address */
#endif
       usl_ineta_length = 16;               /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       bol_search_appl = FALSE;             /* search appl             */
       bol_route_del = TRUE;                /* delete the route        */
       break;
     case ied_ineta_raws_user_ipv4:         /* INETA user IPV4         */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 4;  /* length of following address */
#endif
       usl_ineta_length = 4;                /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       adsl_hac_user_i = &dss_htree1_avl_cntl_user_i_ipv4;
       bol_search_appl = TRUE;              /* search appl             */
       bol_route_del = TRUE;                /* delete the route        */
       break;
     case ied_ineta_raws_user_ipv6:         /* INETA user IPV6         */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET6;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 16;  /* length of following address */
#endif
       usl_ineta_length = 16;               /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       adsl_hac_user_i = &dss_htree1_avl_cntl_user_i_ipv6;
       bol_search_appl = TRUE;              /* search appl             */
       bol_route_del = TRUE;                /* delete the route        */
       break;
     case ied_ineta_raws_l2tp_ipv4:         /* INETA L2TP IPV4         */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 4;  /* length of following address */
#endif
       usl_ineta_length = 4;                /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       bol_search_appl = FALSE;             /* search appl             */
       bol_no_tun = TRUE;                   /* INETA not for TUN-adapter */
       break;
     case ied_ineta_raws_l2tp_ipv6:         /* INETA L2TP IPV6         */
#ifdef XYZ1
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_family = AF_INET6;  /* family IPV4 / IPV6 */
       dsl_work_i.dsc_ineta_raws_1.usc_ineta_length = 16;  /* length of following address */
#endif
       usl_ineta_length = 16;               /* length of following address */
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       bol_search_appl = FALSE;             /* search appl             */
       bol_no_tun = TRUE;                   /* INETA not for TUN-adapter */
       break;
   }
#endif
// check IPV6 later - 14.12.12 KB
   adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
   adsl_ser_thr_task_free = NULL;           /* task for serial thread  */
   if (bol_route_del_ipv4) {                /* delete the route IPV4   */
     adsl_ser_thr_task_free
       = (struct dsd_ser_thr_task *) malloc( DEF_SERIAL_FREE_POOL * sizeof(struct dsd_ser_thr_task) );
     adsl_ser_thr_task_free->adsc_next = adsl_ser_thr_task_free + DEF_SERIAL_FREE_POOL - 1;
     adsl_ser_thr_task_w1 = adsl_ser_thr_task_free + 1;
     adsl_ser_thr_task_w1->adsc_next = NULL;
     iml1 = DEF_SERIAL_FREE_POOL - 2;
     do {
       adsl_ser_thr_task_w1++;              /* next entry in pool      */
       adsl_ser_thr_task_w1->adsc_next = adsl_ser_thr_task_w1 - 1;
       iml1--;                              /* decrement index         */
     } while (iml1 > 0);
   }
   if (adsp_ineta_raws_1->boc_with_user) {  /* structure with user     */
     memcpy( &dsl_work_i.dsc_ineta_raws_1,
             adsp_ineta_raws_1,
             sizeof(struct dsd_ineta_raws_1) );
// check IPV6 later - 14.12.12 KB
     adsl_hac_user_i = &dss_htree1_avl_cntl_user_i_ipv4;
     dsl_work_i.dsc_ineta_raws_1.usc_appl_port = 0;  /* clear port in use */
     bol_failed_del_appl = TRUE;            /* failed to delete appl   */
   }
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dsg_global_lock.m_enter();
   if (adsp_ineta_raws_1->boc_with_user) {  /* structure with user     */
     do {                                   /* pseudo-loop             */
       bol1 = m_htree1_avl_search( NULL, adsl_hac_user_i,
                                   &dsl_htree1_work, &dsl_work_i.dsc_ineta_raws_1.dsc_sort_user );
       if (bol1 == FALSE) {                   /* error occured           */
         sprintf( chrl_work1,
                  "m_htree1_avl_search() appl failed l%05d.",
                  __LINE__ );               /* error code AVL tree     */
         achl_avl_error = chrl_work1;
         break;
       }
       bol1 = FALSE;                        /* no valid entry          */
       if (dsl_htree1_work.adsc_found) {    /* entry found             */
         bol1 = TRUE;                       /* valid entry found       */
       }
#define ADSL_INETA_RAWS_1_S ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_user )))
       while (TRUE) {                       /* loop over entries of same user */
         if (bol1) {                        /* entry is valid          */
           bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                                  &ADSL_INETA_RAWS_1_S->dsc_user_group,  /* Usergroup Sign On */
                                  &dsl_work_i.dsc_ineta_raws_1.dsc_user_group );  /* Usergroup Sign On */
           if (iml_cmp != 0) break;
           bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                                  &ADSL_INETA_RAWS_1_S->dsc_user_name,  /* Username Sign On */
                                  &dsl_work_i.dsc_ineta_raws_1.dsc_user_name );  /* Username Sign On */
           if (iml_cmp != 0) break;
           iml_cmp = memcmp( &ADSL_INETA_RAWS_1_S->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                             &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                             4 );
           if (iml_cmp) break;              /* not same INETA          */
           if (ADSL_INETA_RAWS_1_S->usc_appl_port == adsp_ineta_raws_1->usc_appl_port) {  /* port in use */
             bol1 = m_htree1_avl_delete( NULL, adsl_hac_user_i,
                                         &dsl_htree1_work );
             if (bol1 == FALSE) {           /* error occured           */
               sprintf( chrl_work1,
                        "m_htree1_avl_delete() appl failed l%05d.",
                        __LINE__ );               /* error code AVL tree     */
               achl_avl_error = chrl_work1;
               break;
             }
             bol_failed_del_appl = FALSE;   /* failed to delete appl   */
           } else {                         /* is same INETA           */
             bol_route_del_ipv4 = FALSE;    /* do not delete the route */
           }
         }
         bol1 = m_htree1_avl_getnext( NULL, adsl_hac_user_i,
                                      &dsl_htree1_work, FALSE );
         if (bol1 == FALSE) {               /* error occured           */
           sprintf( chrl_work1,
                    "m_htree1_avl_getnext() failed l%05d.",
                    __LINE__ );             /* error code AVL tree     */
           achl_avl_error = chrl_work1;
           break;
         }
         if (dsl_htree1_work.adsc_found == NULL) break;  /* end-of-file reached */
       }
#undef ADSL_INETA_RAWS_1_S
     } while (FALSE);
   }
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL, adsl_hac_ineta,
                                 &dsl_htree1_work, &adsp_ineta_raws_1->dsc_sort_ineta_ipv4 );
     if (bol1 == FALSE) {                   /* error occured           */
       if (achl_avl_error) break;           /* error already set       */
       sprintf( chrl_work1,
                "m_htree1_avl_search() INETA failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       break;
     }
     if (dsl_htree1_work.adsc_found == NULL) {  /* entry not found     */
       if (achl_avl_error) break;           /* error already set       */
       sprintf( chrl_work1,
                "INETA (INETA) not in AVL-tree l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       break;
     }
     bol1 = m_htree1_avl_delete( NULL, adsl_hac_ineta,
                                 &dsl_htree1_work );
     if (bol1 == FALSE) {                   /* error occured           */
       if (achl_avl_error) break;           /* error already set       */
       sprintf( chrl_work1,
                "m_htree1_avl_delete() INETA failed l%05d.",
                __LINE__ );                 /* error code AVL tree     */
       achl_avl_error = chrl_work1;
       break;
     }
   } while (FALSE);
   if (bol_route_del_ipv4) {                /* delete the route IPV4   */
     /* give work to serialisation thread to delete the route          */
     adsl_ser_thr_task_w1 = dss_ser_thr_ctrl.adsc_sth_free;  /* chain of free structures */
     if (adsl_ser_thr_task_w1 == NULL) {    /* we need more entries    */
       adsl_ser_thr_task_w1 = adsl_ser_thr_task_free;
       adsl_ser_thr_task_free = NULL;
     }
     dss_ser_thr_ctrl.adsc_sth_free = adsl_ser_thr_task_w1->adsc_next;
     memset( adsl_ser_thr_task_w1, 0, sizeof(struct dsd_ser_thr_task) );  /* task for serial thread */
// to-do 03.07.10 KB attention IPV6
     adsl_ser_thr_task_w1->iec_sth = ied_sth_route_ipv4_del;  /* delete a route IPV4 */
     memcpy( adsl_ser_thr_task_w1->chrc_ineta,
             &adsp_ineta_raws_1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
             4 );
// to-do 29.12.12 KB following three fields not used with TUN adapter in Unix
     adsl_ser_thr_task_w1->umc_index_if_arp = adsp_ineta_raws_1->umc_index_if_arp_ipv4;  /* holds index of compatible IF for ARP */
     adsl_ser_thr_task_w1->umc_index_if_route = adsp_ineta_raws_1->umc_index_if_route_ipv4;  /* holds index of compatible IF for routes */
     adsl_ser_thr_task_w1->umc_taif_ineta = adsp_ineta_raws_1->umc_taif_ineta_ipv4;  /* <TUN-adapter-use-interface-ineta> */
     /* append at end of chain to process                              */
     if (dss_ser_thr_ctrl.adsc_sth_work == NULL) {  /* work as task for serial thread */
       dss_ser_thr_ctrl.adsc_sth_work = adsl_ser_thr_task_w1;  /* work as task for serial thread */
       bol_ser_post = TRUE;                 /* post serialize thread   */
     } else {
       adsl_ser_thr_task_w2 = dss_ser_thr_ctrl.adsc_sth_work;  /* get chain */
       while (adsl_ser_thr_task_w2->adsc_next) adsl_ser_thr_task_w2 = adsl_ser_thr_task_w2->adsc_next;
       adsl_ser_thr_task_w2->adsc_next = adsl_ser_thr_task_w1;
     }
   }
   dsg_global_lock.m_leave();
   if (bol_ser_post) {                      /* post serialize thread   */
#ifdef HL_UNIX
     if (dss_loconf_1.boc_listen_gw == FALSE) {  /* do not use listen gateway */
#endif
       iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_post( &iml_error );  /* event for serial thread */
       if (iml_rc < 0) {                    /* error occured           */
// to-do 29.12.12 KB HWSPM155W double
         m_hlnew_printf( HLOG_WARN1, "HWSPM155W l%05d cleanup HOB-TUN INETA event serial m_post Return Code %d Error %d.",
                         __LINE__, iml_rc, iml_error );
       }
#ifdef HL_UNIX
     } else {                               /* do use listen gateway   */
       iml_rc = write( imrs_m_fd_pipe[1], vprs_message_work, sizeof(vprs_message_work) );
       if (iml_rc != sizeof(vprs_message_work)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW m_cleanup_htun_ineta() l%05d write pipe work error %d %d.",
                         __LINE__, iml_rc, errno );
       }
     }
#endif
   }
   if (achl_avl_error) {
// to-do 23.01.12 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d cleanup HOB-TUN AVL-tree error %s.",
                     __LINE__, achl_avl_error );
   }
   if (adsl_ser_thr_task_free) free( adsl_ser_thr_task_free );
   if (bol_failed_del_appl) {               /* failed to delete appl   */
// to-do 16.09.10 KB error number
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d cleanup HOB-TUN INETA did not delete AVL-tree entry appl",
                     __LINE__ );
   }
} /* end m_cleanup_htun_ineta()                                        */

/** a logical block was reveived from other cluster member             */
extern "C" void m_ineta_req_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr, int imp_family ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_cmp;                      /* for compare operations  */
   int        iml_data_length;              /* length of received data */
   int        iml_len_ineta;                /* length INETA in stack   */
   int        iml_disp_ineta;               /* displacement INETA in struct dsd_ineta_raws_1 */
   unsigned char ucl_more;                  /* more bit                */
   BOOL       bol_lock_set;                 /* lock is set             */
   BOOL       bol_err_savebl_full;          /* give error message later */
   struct dsd_cluster_send *adsl_clsend_w1;  /* send buffer            */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_out_cur;                /* output of values        */
   char       *achl_out_end;                /* end of output area      */
   char       *achl_error;                  /* error message           */
   char       *achl_avl_error;              /* error code AVL tree     */
   char       *achl_ineta_stack;            /* address INETA in stack  */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_cluster_ineta_this *adsl_cluster_ineta_this_w1;  /* save INETA this cluster member */
   struct dsd_htree1_avl_cntl *adsl_hac_ineta;
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct {
     struct dsd_auxf_1 dsc_auxf_1;
     struct dsd_ineta_raws_1 dsc_ineta_raws_1;  /* INETA in use        */
   } dsl_work_i;
   char       chrl_work1[ 256 ];            /* work area               */

   memset( &dsl_work_i, 0, sizeof(dsl_work_i) );
   bol_lock_set = FALSE;                    /* lock not set            */
   bol_err_savebl_full = FALSE;             /* give error message later */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   adsl_clsend_w1 = (struct dsd_cluster_send *) m_proc_alloc();
   memset( adsl_clsend_w1, 0, sizeof(struct dsd_cluster_send) );
   switch (imp_family) {                    /* family IPV4 / IPV6      */
     case AF_INET:                          /* IPV4                    */
       adsl_clsend_w1->iec_cl_type = ied_clty_ineta_resp_ipv4;  /* type is response with INETAs IPV4 */
       iml_len_ineta = 4;                   /* length INETA in stack   */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr)
              - ((char *) &dsl_work_i.dsc_ineta_raws_1);
       achl_ineta_stack                     /* address INETA in stack  */
         = (char *) &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr;
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv4;
       break;
     case AF_INET6:                         /* IPV6                    */
       adsl_clsend_w1->iec_cl_type = ied_clty_ineta_resp_ipv6;  /* type is response with INETAs IPV6 */
       iml_len_ineta = 16;                  /* length INETA in stack   */
       iml_disp_ineta                       /* displacement INETA in struct dsd_ineta_raws_1 */
         = ((char *) &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr)
              - ((char *) &dsl_work_i.dsc_ineta_raws_1);
       achl_ineta_stack                     /* address INETA in stack  */
         = (char *) &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv6.sin6_addr;
       adsl_hac_ineta = &dss_htree1_avl_cntl_ineta_ipv6;
       break;
     default:
       goto p_ret_err;                      /* return with error       */
   }
   adsl_clsend_w1->adsc_clact = adsp_clprr->adsc_clact;  /* active cluster */
   adsl_clsend_w1->adsc_gai1_send = (struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1);
   achl_out_cur = (char *) (adsl_clsend_w1 + 1) + sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_cur = achl_out_cur;
   ADSL_GAI1_W1->adsc_next = NULL;          /* end of chain            */
#undef ADSL_GAI1_W1
   achl_out_end = (char *) adsl_clsend_w1 + LEN_TCP_RECV;
   adsl_gai1_w1 = adsp_clprr->adsc_gai1_data;  /* gather input data    */
   iml_data_length = adsp_clprr->imc_data_length;  /* length of received data */

   /* first copy request id                                            */
   iml1 = sizeof(int);                      /* length to copy          */
   iml_data_length -= sizeof(int);          /* decrement length received */
   if (iml_data_length <= 0) {              /* data received too short */
     achl_error = "length data received too short - packet and sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }

   p_scan_00:                               /* scan input data         */
   iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml2 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_00;      /* continue scann input data */
     achl_error = "end of gather input sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml2 > iml1) iml2 = iml1;            /* copy only what needed   */
   memcpy( achl_out_cur, adsl_gai1_w1->achc_ginp_cur, iml2 );  /* copy input data */
   adsl_gai1_w1->achc_ginp_cur += iml2;     /* increment address input */
   achl_out_cur += iml2;                    /* increment address output */
   iml1 -= iml2;                            /* decrement length to fill */
   if (iml1) goto p_scan_00;                /* continue scann input data */

   bol_lock_set = TRUE;                     /* lock is set             */
   dsg_global_lock.m_enter();

   /* get count NHASN of following INETAs                              */
   p_chin_20:                               /* begin check INETAs      */
   iml1 = 0;                                /* for result              */
   iml2 = 4;                                /* maximum number of digits */
   while (TRUE) {                           /* loop to get length      */
     while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* no more gather input    */
         achl_error = "end of gather input";
         goto p_scan_error;                 /* invalid data received   */
       }
     }
     if (iml_data_length <= 0) {            /* not more data received  */
       achl_error = "length data received too short for count INETA";
       goto p_scan_error;                     /* invalid data received   */
     }
     iml_data_length--;                     /* decrement remaining data received */
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *adsl_gai1_w1->achc_ginp_cur & 0X7F;  /* apply new bits   */
     if ((*adsl_gai1_w1->achc_ginp_cur & 0X80) == 0) break;  /* more bit not set */
     iml2--;                                /* count this digit        */
     if (iml2 <= 0) {                       /* too many digits length  */
       achl_error = "length count INETAs NHASN too long";
       goto p_scan_error;                   /* invalid data received   */
     }
     adsl_gai1_w1->achc_ginp_cur++;         /* after last digit        */
   }
   if (iml1 <= 0) {                         /* count value invalid     */
     achl_error = "value count INETAs NHASN zero - not valid";
     goto p_scan_error;                     /* invalid data received   */
   }
   adsl_gai1_w1->achc_ginp_cur++;           /* after last digit        */
   /* retrieve following INETA                                         */
   iml_data_length -= iml_len_ineta;        /* decrement remaining data received */
   if (iml_data_length < 0) {               /* remaining data received too short */
     achl_error = "length data received too short for value INETA";
     goto p_scan_error;                     /* invalid data received   */
   }
   iml2 = iml_len_ineta;                    /* length of following INETA */
   achl1 = achl_ineta_stack;                /* target of copy          */

   p_scan_20:                               /* scan input data         */
   iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml3 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_20;      /* continue scann input data */
     achl_error = "end of gather input INETA";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml3 > iml2) iml3 = iml2;            /* copy only what needed   */
   memcpy( achl1, adsl_gai1_w1->achc_ginp_cur, iml3 );  /* copy input data */
   adsl_gai1_w1->achc_ginp_cur += iml3;     /* increment address input */
   achl1 += iml3;                           /* increment address output */
   iml2 -= iml3;                            /* decrement length to fill */
   if (iml2) goto p_scan_20;                /* continue scann input data */
   memcpy( chrl_work1, achl_ineta_stack, iml_len_ineta );
   m_ineta_op_add( chrl_work1, iml_len_ineta, iml1 - 1 );

   /* check if there is a collision and we need to reject to request   */
   if (adss_cluster_ineta_this) {           /* chain save INETA this cluster member */
#ifdef TRY100514$02
     m_hlnew_printf( HLOG_XYZ1, "HWSPM-l%05d-T m_ineta_req_cluster_recv() adss_cluster_ineta_this=%p.",
                     __LINE__, adss_cluster_ineta_this );
#endif
     adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
     do {                                   /* loop over INETAs this cluster member */
       if (adsl_cluster_ineta_this_w1->usc_ineta_family == imp_family) {  /* family IPV4 / IPV6 */
         achl1 = (char *) (adsl_cluster_ineta_this_w1 + 1);  /* first INETA */
         do {                               /* loop over all pairs of INETAs */
           do {                             /* pseudo-loop             */
             iml_cmp = memcmp( achl1,       /* INETA start             */
                               achl_ineta_stack,
                               iml_len_ineta );
             if (iml_cmp > 0) break;
             if (iml_cmp < 0) {
               iml_cmp = memcmp( achl1 + adsl_cluster_ineta_this_w1->usc_ineta_length,  /* INETA end */
                                 chrl_work1,
                                 iml_len_ineta );
               if (iml_cmp < 0) break;
             }
             /* received INETAs are in range of these saved INETAs     */
             goto p_send_rej_00;            /* send reject             */
           } while (FALSE);
           if (iml_cmp > 0) break;          /* break because elements are sorted */
           achl1 += 2 * adsl_cluster_ineta_this_w1->usc_ineta_length;  /* length of following address */
         } while (achl1 < adsl_cluster_ineta_this_w1->achc_end_used);  /* address used till here */
       }
       adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
     } while (adsl_cluster_ineta_this_w1);
   }
   bol1 = m_htree1_avl_search( (void *) "C", adsl_hac_ineta,
                               &dsl_htree1_work, &dsl_work_i.dsc_ineta_raws_1.dsc_sort_ineta_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_search() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   if (dsl_htree1_work.adsc_found) {        /* entry currently in use  */
     m_ineta_op_inc( achl_ineta_stack, iml_len_ineta );
     iml_cmp = memcmp( achl_ineta_stack,
                       chrl_work1,
                       iml_len_ineta );
     if (iml_cmp > 0) {                     /* start INETA greater end INETA */
       goto p_chin_60;                      /* this entry has been processed */
     }
   }

   p_chin_40:                               /* search sequential in AVL-tree */
   bol1 = m_htree1_avl_getnext( NULL, adsl_hac_ineta,
                                &dsl_htree1_work, FALSE );
   if (bol1 == FALSE) {                     /* error occured           */
     sprintf( chrl_work1,
              "m_htree1_avl_getnext() failed l%05d.",
              __LINE__ );                   /* error code AVL tree     */
     achl_avl_error = chrl_work1;
     goto p_ret_err;                        /* no INETA found          */
   }
   achl1 = chrl_work1;                      /* address INETA end       */
   iml1 = 1;                                /* end INETA included      */
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file reached   */
     goto p_chin_48;                        /* range of INETAs is valid */
   }
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
#ifdef XYZ1
   char *achh_disp_xyz1 = (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta;
#endif
   iml_cmp = memcmp( (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta,
                     chrl_work1,
                     iml_len_ineta );
   if (iml_cmp > 0) {                       /* after this range        */
     dsl_htree1_work.adsc_found = NULL;     /* same as end-of-file reached */
     goto p_chin_48;                        /* range of INETAs is valid */
   }
   iml1 = 0;                                /* end INETA excluded      */
   if (iml_cmp == 0) {                      /* same as last entry      */
     iml_cmp = memcmp( achl_ineta_stack,
                       chrl_work1,
                       iml_len_ineta );
     if (iml_cmp >= 0) {                    /* start INETA greater end INETA */
       goto p_chin_60;                      /* this entry has been processed */
     }
     dsl_htree1_work.adsc_found = NULL;     /* same as end-of-file reached */
     goto p_chin_48;                        /* range of INETAs is valid */
   }
#ifdef B140713
#ifndef HL_UNIX
   achl1 = (char *) (ADSL_INETA_RAWS_1_G + 1);  /* address INETA end   */
#endif
#ifdef HL_UNIX
   achl1 = (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta;  /* address INETA end */
#endif
#endif
#ifndef B140713
   achl1 = (char *) ADSL_INETA_RAWS_1_G + iml_disp_ineta;  /* address INETA end */
#endif
#undef ADSL_INETA_RAWS_1_G

   p_chin_48:                               /* range of INETAs is valid */
   iml1 = m_ineta_op_diff( achl1, achl_ineta_stack, iml_len_ineta ) + iml1;
#ifndef B140716
   if (iml1 == 0) {                         /* suppress output         */
     goto p_chin_52;                        /* output of INETAs done   */
   }
#endif
   /* first pass only to compute length of count NHASN                 */
   achl2 = achl_out_cur;                    /* save current in buffer with INETAs */
   iml2 = iml1;                             /* get number for output   */
   do {
     achl_out_cur++;                        /* increment output        */
     iml2 >>= 7;                            /* remove digits           */
   } while (iml2 > 0);
   if ((achl_out_cur + iml_len_ineta) > achl_out_end) {
     bol_err_savebl_full = TRUE;            /* give error message later */
     achl_out_cur = achl2;                  /* restore current in buffer with INETAs */
     goto p_chin_52;                        /* output of INETAs done   */
   }
   achl2 = achl_out_cur;                    /* get current in output buffer */
   ucl_more = 0;                            /* clear more bit          */
   do {                                     /* loop output length NHASN */
     *(--achl2) = (unsigned char) ((iml1 & 0X7F) | ucl_more);
     iml1 >>= 7;                            /* remove these bits       */
     ucl_more = 0X80;                       /* set more bit            */
   } while (iml1 > 0);
   memcpy( achl_out_cur, achl_ineta_stack, iml_len_ineta );
   achl_out_cur += iml_len_ineta;  /* increment current in output buffer */

   p_chin_52:                               /* output of INETAs done   */
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file reached   */
     goto p_chin_60;                        /* this entry has been processed */
   }
   memcpy( achl_ineta_stack, achl1, iml_len_ineta );
   m_ineta_op_inc( achl_ineta_stack, iml_len_ineta );
   iml_cmp = memcmp( achl_ineta_stack,
                     chrl_work1,
                     iml_len_ineta );
   if (iml_cmp <= 0) {                      /* start INETA not greater end INETA */
     goto p_chin_40;                        /* search sequential in AVL-tree */
   }

   p_chin_60:                               /* this entry has been processed */
   if (iml_data_length > 0) {               /* more data received      */
     goto p_chin_20;                        /* begin check INETAs      */
   }
   dsg_global_lock.m_leave();
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_end = achl_out_cur;
#undef ADSL_GAI1_W1
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                          /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM145W received INETAs from other cluster members - send response error %d.",
                     iml1 );
     m_proc_free( adsl_clsend_w1 );
   }
   goto p_ret_end;                          /* housekeeping            */

   p_send_rej_00:                           /* send reject             */
   dsg_global_lock.m_leave();
   bol_lock_set = FALSE;                    /* lock not set            */
#ifdef TRY100514$02
   m_hlnew_printf( HLOG_XYZ1, "HWSPM-l%05d-T m_ineta_req_cluster_recv() p_send_rej_00",
                   __LINE__ );
#endif
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_clsend_w1 + 1))
   ADSL_GAI1_W1->achc_ginp_end = (char *) (ADSL_GAI1_W1 + 1) + sizeof(int);
#undef ADSL_GAI1_W1
   switch (imp_family) {                    /* family IPV4 / IPV6      */
     case AF_INET:                          /* IPV4                    */
       adsl_clsend_w1->iec_cl_type = ied_clty_ineta_rej_ipv4;  /* type is reject for INETAs IPV4 */
       break;
     case AF_INET6:                         /* IPV6                    */
       adsl_clsend_w1->iec_cl_type = ied_clty_ineta_rej_ipv6;  /* type is reject for INETAs IPV6 */
       break;
     default:
       goto p_ret_err;                      /* return with error       */
   }
   iml1 = m_cluster_send( adsl_clsend_w1 );
   if (iml1) {                              /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM146W received INETAs from other cluster members - send response error %d.",
                     iml1 );
     m_proc_free( adsl_clsend_w1 );
   }
   goto p_ret_end;                          /* housekeeping            */

   p_scan_error:                            /* invalid data received   */
   if (bol_lock_set) {                      /* lock was set            */
     dsg_global_lock.m_leave();
     bol_lock_set = FALSE;                  /* lock not set            */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPM147W received INETAs from other cluster members - scan input data %s",
                   achl_error );
   goto p_ret_end;                          /* housekeeping            */

   p_ret_err:                               /* return with error       */
   if (bol_lock_set) {                      /* lock was set            */
     dsg_global_lock.m_leave();
   }
   m_proc_free( adsl_clsend_w1 );           /* free send buffer        */

   p_ret_end:                               /* housekeeping            */
   if (achl_avl_error) {                    /* display error AVL tree  */
     m_hlnew_printf( HLOG_WARN1, "HWSPM148W received INETAs from other cluster members - %s",
                     achl_avl_error );
   }
   if (bol_err_savebl_full) {               /* give error message later */
     m_hlnew_printf( HLOG_WARN1, "HWSPM149W received INETAs from other cluster members - buffer with INETAs overflow" );
   }
   return;                                  /* all done                */
} /* end m_ineta_req_cluster_recv()                                    */

/** a logical block was reveived from other cluster member             */
extern "C" void m_ineta_resp_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr, int imp_family ) {
   int        iml_sequ;                     /* sequence number         */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_cmp;                      /* for compare operations  */
   int        iml_data_length;              /* length of received data */
   BOOL       bol_lock_set;                 /* lock is set             */
   BOOL       bol_err_savebl_full;          /* give error message later */
   char       *achl1;                       /* working variable        */
   char       *achl_out_cur;                /* output of values        */
   char       *achl_out_end;                /* end of output area      */
   char       *achl_orig_cur;               /* check in original INETAs */
   char       *achl_temp_cur;               /* check in old temporary INETAs */
   char       *achl_error;                  /* error message           */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_cluster_ineta_this *adsl_cluster_ineta_this_w1;  /* save INETA this cluster member */
   struct dsd_cluster_ineta_temp *adsl_clinte_old;  /* temporary INETAs received from other cluster member */
   struct dsd_cluster_ineta_temp *adsl_clinte_new;  /* temporary INETAs received from other cluster member */
   char       chrl_ineta_1[ 16 ];
   char       chrl_ineta_2[ 16 ];
   char       chrl_ineta_3[ 16 ];
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#endif

   bol_lock_set = FALSE;                    /* lock not set            */
   bol_err_savebl_full = FALSE;             /* give error message later */
   adsl_clinte_new = (struct dsd_cluster_ineta_temp *) m_proc_alloc();  /* temporary INETAs received from other cluster member */
   adsl_gai1_w1 = adsp_clprr->adsc_gai1_data;  /* gather input data    */
   iml_data_length = adsp_clprr->imc_data_length;  /* length of received data */

   /* first copy request id                                            */
   iml1 = sizeof(int);                      /* length to copy          */
   iml_data_length -= sizeof(int);          /* decrement length received */
   if (iml_data_length < 0) {               /* data received too short */
     achl_error = "length data received too short - packet and sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }
   achl_out_cur = (char *) &iml_sequ;       /* target sequence number  */

   p_scan_00:                               /* scann input data        */
   iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml2 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_00;      /* continue scann input data */
     achl_error = "end of gather input sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml2 > iml1) iml2 = iml1;            /* copy only what needed   */
   memcpy( achl_out_cur, adsl_gai1_w1->achc_ginp_cur, iml2 );  /* copy input data */
   adsl_gai1_w1->achc_ginp_cur += iml2;     /* increment address input */
   achl_out_cur += iml2;                    /* increment address output */
   iml1 -= iml2;                            /* decrement length to fill */
   if (iml1) goto p_scan_00;                /* continue scann input data */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNXXX1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "l%05d m_ineta_resp_cluster_recv() iml_sequ=%d adss_cluster_ineta_this=%p.",
                                        __LINE__, iml_sequ, adss_cluster_ineta_this );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
   achl_out_cur = (char *) (adsl_clinte_new + 1);  /* output of values */
   achl_out_end = (char *) adsl_clinte_new + LEN_TCP_RECV;  /* end of output area */
   bol_lock_set = TRUE;                     /* lock is set             */
   dsg_global_lock.m_enter();
   adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
   while (adsl_cluster_ineta_this_w1) {     /* loop over chain save INETA this cluster member */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNXXX2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_ineta_resp_cluster_recv() adsl_cluster_ineta_this_w1=%p ->imc_sequ=%d iml_sequ=%d.",
                                          __LINE__, adsl_cluster_ineta_this_w1, adsl_cluster_ineta_this_w1->imc_sequ, iml_sequ );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content            /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );      /* output of WSP trace record */
     }
#endif
     if (adsl_cluster_ineta_this_w1->imc_sequ == iml_sequ) {  /* compare sequence number */
       break;
     }
     adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
   }
   if (adsl_cluster_ineta_this_w1 == NULL) {  /* corresponding save INETA this cluster member not found */
#ifdef DEBUG_141118_01                      /* 18.11.14 KB - sequence number does not match */
     if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN */
       adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
       memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
       adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data     */
       adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
       memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNXXX3", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
       adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id             */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "l%05d m_ineta_resp_cluster_recv() iml_sequ=%d adss_cluster_ineta_this=%p.",
                                          __LINE__, iml_sequ, adss_cluster_ineta_this );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
       ADSL_WTR_G1->achc_content              /* content of text / data  */
         = (char *) (ADSL_WTR_G1 + 1);
       adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
  #undef ADSL_WTR_G1
       m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     }
#endif
     achl_error = "packet contains sequ number where this WSP does not wait for";
     goto p_scan_error;                     /* invalid data received   */
#ifdef XYZ1
     return;
#endif
   }
   if (adsl_cluster_ineta_this_w1->usc_ineta_family != imp_family) {  /* family IPV4 / IPV6 */
     achl_error = "packet contains wrong INET family";
     goto p_scan_error;                     /* invalid data received   */
   }

#define USL_INETA_LEN adsl_cluster_ineta_this_w1->usc_ineta_length

   achl_orig_cur = (char *) (adsl_cluster_ineta_this_w1 + 1);  /* check in original INETAs */
   adsl_clinte_old = adsl_cluster_ineta_this_w1->adsc_cluster_ineta_temp;  /* temporary INETAs received from other cluster member */
   if (adsl_clinte_old) {                   /* compare with old INETAs */
     achl_temp_cur = (char *) (adsl_clinte_old + 1);  /* check in old temporary INETAs */
   }
   if (iml_data_length <= 0) {              /* not more data received  */
     goto p_chin_80;                        /* all entries have been processed */
   }

   /* get count NHASN of following INETAs                              */
   p_chin_20:                               /* begin check INETAs      */
   iml1 = 0;                                /* for result              */
   iml2 = 4;                                /* maximum number of digits */
   while (TRUE) {                           /* loop to get length      */
     while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain   */
       if (adsl_gai1_w1 == NULL) {          /* no more gather input    */
         achl_error = "end of gather input";
         goto p_scan_error;                 /* invalid data received   */
       }
     }
     if (iml_data_length <= 0) {            /* not more data received  */
       achl_error = "length data received too short for count INETA";
       goto p_scan_error;                     /* invalid data received   */
     }
     iml_data_length--;                     /* decrement remaining data received */
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *adsl_gai1_w1->achc_ginp_cur & 0X7F;  /* apply new bits   */
     if ((*adsl_gai1_w1->achc_ginp_cur & 0X80) == 0) break;  /* more bit not set */
     iml2--;                                /* count this digit        */
     if (iml2 <= 0) {                       /* too many digits length  */
       achl_error = "length count INETAs NHASN too long";
       goto p_scan_error;                   /* invalid data received   */
     }
     adsl_gai1_w1->achc_ginp_cur++;         /* after last digit        */
   }
// to-do 22.08.12 KB - count zero should be allowed, all INETAs in use
// but this should not be sent by other cluster member
   if (iml1 <= 0) {                         /* count value invalid     */
     achl_error = "value count INETAs NHASN zero - not valid";
     goto p_scan_error;                     /* invalid data received   */
   }
   adsl_gai1_w1->achc_ginp_cur++;           /* after last digit        */
   /* retrieve following INETA                                         */
   iml_data_length -= USL_INETA_LEN;        /* decrement remaining data received */
   if (iml_data_length < 0) {               /* remaining data received too short */
     achl_error = "length data received too short for value INETA";
     goto p_scan_error;                     /* invalid data received   */
   }
   iml2 = USL_INETA_LEN;                    /* length of following INETA */
   achl1 = chrl_ineta_1;                    /* target of copy          */

   p_scan_20:                               /* scann input data        */
   iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml3 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_20;      /* continue scann input data */
     achl_error = "end of gather input INETA";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml3 > iml2) iml3 = iml2;            /* copy only what needed   */
   memcpy( achl1, adsl_gai1_w1->achc_ginp_cur, iml3 );  /* copy input data */
   adsl_gai1_w1->achc_ginp_cur += iml3;     /* increment address input */
   achl1 += iml3;                           /* increment address output */
   iml2 -= iml3;                            /* decrement length to fill */
   if (iml2) goto p_scan_20;                /* continue scann input data */
   memcpy( chrl_ineta_2, chrl_ineta_1, USL_INETA_LEN );
   m_ineta_op_add( chrl_ineta_2, USL_INETA_LEN, iml1 - 1 );

   /* check if received INETAs have really been sent to the other cluster member */
   p_orig_20:                               /* check one entry         */
   if (achl_orig_cur >= adsl_cluster_ineta_this_w1->achc_end_used) {  /* address used till here */
     achl_error = "received INETAs not part of INETAs sent (1)";
     goto p_scan_error;                     /* invalid data received   */
   }
   iml_cmp = memcmp( chrl_ineta_2, achl_orig_cur + USL_INETA_LEN, USL_INETA_LEN );
   if (iml_cmp > 0) {                       /* check next entry        */
     achl_orig_cur += 2 * USL_INETA_LEN;    /* original take next entry */
     goto p_orig_20;                        /* check one entry         */
   }
   iml_cmp = memcmp( chrl_ineta_1, achl_orig_cur, USL_INETA_LEN );
   if (iml_cmp < 0) {                       /* received start INETA less than original start INETA */
     achl_error = "received INETAs not part of INETAs sent (2)";
     goto p_scan_error;                     /* invalid data received   */
   }
   /* received INETAs are part of INETAs sent                          */
   if (adsl_clinte_old == NULL) {           /* no old INETAs           */
     goto p_putout_20;                      /* put received INETAs in new buffer */
   }
   memcpy( chrl_ineta_3, chrl_ineta_2, USL_INETA_LEN );  /* save end INETA */

   p_temp_20:                               /* check one entry         */
   if (achl_temp_cur >= adsl_clinte_old->achc_end_used) {  /* address used till here */
     /* the other cluster members do not allow the received INETAs     */
     goto p_chin_60;                        /* this entry has been processed */
   }
   iml_cmp = memcmp( chrl_ineta_1, achl_temp_cur + USL_INETA_LEN, USL_INETA_LEN );
   if (iml_cmp > 0) {                       /* check next entry        */
     achl_temp_cur += 2 * USL_INETA_LEN;    /* temporary old next entry */
     goto p_temp_20;                        /* check one entry         */
   }
   iml_cmp = memcmp( chrl_ineta_1, achl_temp_cur, USL_INETA_LEN );
   if (iml_cmp < 0) {                       /* temporary old is higher */
     memcpy( chrl_ineta_1, achl_temp_cur, USL_INETA_LEN );  /* only this part */
   }
   iml_cmp = memcmp( chrl_ineta_2, achl_temp_cur + USL_INETA_LEN, USL_INETA_LEN );
   if (iml_cmp > 0) {                       /* temporary old is lower */
     memcpy( chrl_ineta_2, achl_temp_cur + USL_INETA_LEN, USL_INETA_LEN );  /* only this part */
   }
   iml_cmp = memcmp( chrl_ineta_1, chrl_ineta_2, USL_INETA_LEN );
   if (iml_cmp > 0) {                       /* do not output these INETAs */
     memcpy( chrl_ineta_2, chrl_ineta_1, USL_INETA_LEN );  /* set end INETA to higher value */
     goto p_putout_40;                      /* check if more INETAs received */
   }

   p_putout_20:                             /* put received INETAs in new buffer */
   if ((achl_out_cur + 2 * USL_INETA_LEN) > achl_out_end) {  /* does not fit in this block */
     bol_err_savebl_full = TRUE;            /* give error message later */
   } else {
     memcpy( achl_out_cur, chrl_ineta_1, USL_INETA_LEN );  /* copy start INETA */
     achl_out_cur += USL_INETA_LEN;
     memcpy( achl_out_cur, chrl_ineta_2, USL_INETA_LEN );  /* copy end INETA */
     achl_out_cur += USL_INETA_LEN;
   }
   if (adsl_clinte_old == NULL) {           /* no old INETAs           */
     goto p_chin_60;                        /* this entry has been processed */
   }

   p_putout_40:                             /* check if more INETAs received */
   iml_cmp = memcmp( chrl_ineta_2, chrl_ineta_3, USL_INETA_LEN );
   if (iml_cmp >= 0) {                      /* all received INETAs have been processed */
     goto p_chin_60;                        /* this entry has been processed */
   }
   memcpy( chrl_ineta_1, chrl_ineta_2, USL_INETA_LEN );  /* copy end INETA */
   m_ineta_op_inc( chrl_ineta_1, USL_INETA_LEN );  /* increment start INETA */
   memcpy( chrl_ineta_2, chrl_ineta_3, USL_INETA_LEN );  /* restore end INETA */
   goto p_temp_20;                          /* check one entry         */

   p_chin_60:                               /* this entry has been processed */
   if (iml_data_length > 0) {               /* more data received      */
     goto p_chin_20;                        /* begin check INETAs      */
   }

#undef USL_INETA_LEN

   p_chin_80:                               /* all entries have been processed */
   adsl_clinte_new->achc_end_used = achl_out_cur;  /* address used till here */
   adsl_cluster_ineta_this_w1->adsc_cluster_ineta_temp = adsl_clinte_new;  /* temporary INETAs received from other cluster member */
   adsl_cluster_ineta_this_w1->imc_resp_outstanding--;  /* decrement number of responses outstanding */
   iml1 = adsl_cluster_ineta_this_w1->imc_resp_outstanding;  /* save number of responses outstanding */
   dsg_global_lock.m_leave();
   if (iml1 == 0) {                         /* do notify waiting thread */
     /* do notify thread waiting for responses from other cluster members */
     m_hco_wothr_post( NULL, adsl_cluster_ineta_this_w1->adsc_hco_wothr );
   }
   if (adsl_clinte_old) {                   /* compare with old INETAs */
     m_proc_free( adsl_clinte_old );        /* free memory old INETAs  */
   }
   goto p_ret_end;                          /* housekeeping            */

   p_scan_error:                            /* invalid data received   */
   if (bol_lock_set) {                      /* lock was set            */
     dsg_global_lock.m_leave();
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPM150W received response INETAs from other cluster members - scan input data %s",
                   achl_error );
   m_proc_free( adsl_clinte_new );          /* free new buffer INETAs  */

   p_ret_end:                               /* housekeeping            */
   if (bol_err_savebl_full) {               /* give error message later */
     m_hlnew_printf( HLOG_WARN1, "HWSPM151W received response INETAs from other cluster members - buffer with INETAs overflow" );
   }
   return;                                  /* all done                */
} /* end m_ineta_resp_cluster_recv()                                   */

/** a logical block was reveived from other cluster member             */
extern "C" void m_ineta_rej_cluster_recv( struct dsd_cluster_proc_recv *adsp_clprr, int imp_family ) {
   int        iml_sequ;                     /* sequence number         */
   int        iml1, iml2;                   /* working variables       */
   int        iml_data_length;              /* length of received data */
   char       *achl_out_cur;                /* output of values        */
   char       *achl_error;                  /* error message           */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct dsd_cluster_ineta_this *adsl_cluster_ineta_this_w1;  /* save INETA this cluster member */

   adsl_gai1_w1 = adsp_clprr->adsc_gai1_data;  /* gather input data    */
   iml_data_length = adsp_clprr->imc_data_length;  /* length of received data */

   /* first copy request id                                            */
   if (iml_data_length != sizeof(int)) {    /* length data received invalid */
     achl_error = "length data received not as expected - packet and sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }
   achl_out_cur = (char *) &iml_sequ;       /* target sequence number  */
   iml1 = sizeof(int);                      /* length to copy          */

   p_scan_00:                               /* scann input data        */
   iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;  /* length of data */
   if (iml2 <= 0) {                         /* no more data            */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1) goto p_scan_00;      /* continue scann input data */
     achl_error = "end of gather input sequ number";
     goto p_scan_error;                     /* invalid data received   */
   }
   if (iml2 > iml1) iml2 = iml1;            /* copy only what needed   */
   memcpy( achl_out_cur, adsl_gai1_w1->achc_ginp_cur, iml2 );  /* copy input data */
   adsl_gai1_w1->achc_ginp_cur += iml2;     /* increment address input */
   achl_out_cur += iml2;                    /* increment address output */
   iml1 -= iml2;                            /* decrement length to fill */
   if (iml1) goto p_scan_00;                /* continue scann input data */

   dsg_global_lock.m_enter();
   adsl_cluster_ineta_this_w1 = adss_cluster_ineta_this;  /* get chain save INETA this cluster member */
   while (adsl_cluster_ineta_this_w1) {     /* loop over chain save INETA this cluster member */
     if (adsl_cluster_ineta_this_w1->imc_sequ == iml_sequ) {  /* compare sequence number */
       if (adsl_cluster_ineta_this_w1->usc_ineta_family != imp_family) {  /* family IPV4 / IPV6 */
         dsg_global_lock.m_leave();
         achl_error = "packet contains wrong INET family";
         goto p_scan_error;                 /* invalid data received   */
       }
       adsl_cluster_ineta_this_w1->boc_rejected = TRUE;  /* request has been rejected by other cluster member */
       adsl_cluster_ineta_this_w1->imc_resp_outstanding--;  /* decrement number of responses outstanding */
       iml1 = adsl_cluster_ineta_this_w1->imc_resp_outstanding;  /* save number of responses outstanding */
       break;                               /* all done                */
     }
     adsl_cluster_ineta_this_w1 = adsl_cluster_ineta_this_w1->adsc_next;  /* get next in chain */
   }
   dsg_global_lock.m_leave();
   if (adsl_cluster_ineta_this_w1 == NULL) {  /* corresponding save INETA this cluster member not found */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM152W received reject INETAs from other cluster members - sequ=%08X not found",
                     iml_sequ );
     return;
   }
   if (iml1 != 0) return;                   /* do not notify waiting thread */
   /* do notify thread waiting for responses from other cluster members */
   m_hco_wothr_post( NULL, adsl_cluster_ineta_this_w1->adsc_hco_wothr );
   return;

   p_scan_error:                            /* invalid data received   */
   m_hlnew_printf( HLOG_XYZ1, "HWSPM153W received reject INETAs from other cluster members - scan input data %s",
                   achl_error );
   return;
} /* end m_ineta_rej_cluster_recv()                                    */

#endif

#undef DSD_CONN_G

#ifdef D_INCL_HOB_TUN
/** find HOB-TUN handle in AVL-tree containing all INETAs              */
extern "C" void * m_find_htun_ineta( struct sockaddr_storage *dsp_soa ) {
   BOOL       bol1;                         /* working variable        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct {
     struct dsd_auxf_1 dsc_auxf_1;
     struct dsd_ineta_raws_1 dsc_ineta_raws_1;  /* INETA in use        */
   } dsl_work_i;

   dsl_htree1_work.adsc_found = NULL;       /* clear return value      */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   dsl_work_i.dsc_auxf_1.iec_auxf_def = (enum ied_auxf_def) -1;  /* type of entry invalid */
   memset( &dsl_work_i.dsc_ineta_raws_1, 0, sizeof(struct dsd_ineta_raws_1) );
#ifndef B121212
   dsl_work_i.dsc_ineta_raws_1.boc_with_user = TRUE;
#endif
   switch (dsp_soa->ss_family) {
     case AF_INET:                          /* IPV4                    */
       memcpy( &dsl_work_i.dsc_ineta_raws_1.dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
               &((struct sockaddr_in *) dsp_soa)->sin_addr,
               4 );
       dsl_work_i.dsc_ineta_raws_1.usc_appl_port = ntohs( ((struct sockaddr_in *) dsp_soa)->sin_port );
       break;
     case AF_INET6:                         /* IPV6                    */
       goto p_find_ipv6_00;                 /* find IPV6               */
     default:
       return NULL;
   }
   dsg_global_lock.m_enter();
   bol1 = m_htree1_avl_search( (void *) "S", &dss_htree1_avl_cntl_ineta_ipv4,
                               &dsl_htree1_work, &dsl_work_i.dsc_ineta_raws_1.dsc_sort_ineta_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   }
   goto p_find_80;                          /* all done                */

   p_find_ipv6_00:                          /* find IPV6               */
   dsg_global_lock.m_enter();
// to-do 06.04.10 KB not yet implemented

   p_find_80:                               /* all done                */
   dsg_global_lock.m_leave();
   if (achl_avl_error) {                      /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM154W find INETA in AVL-tree %s",
                     achl_avl_error );
   }
   if (dsl_htree1_work.adsc_found == NULL) return NULL;
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
#ifdef B130911
#ifdef TRY_110523_02                        /* HOB-TUN / HTCP session end */
   if (ADSL_INETA_RAWS_1_G->imc_state
         & (DEF_STATE_HTUN_SESS_END         /* done HOB-TUN HTCP session end */
              | DEF_STATE_HTUN_ERR_SESS_END)) {  /* done HOB-TUN HTCP session end was with error */
     return NULL;                           /* do not use this session any more */
   }
#endif
#else
   if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_FREE_R_1) {  /* done HTUN free resources */
     return NULL;                           /* do not use this session any more */
   }
#endif
   return ADSL_INETA_RAWS_1_G->dsc_htun_h;
#undef ADSL_INETA_RAWS_1_G
} /* end m_find_htun_ineta()                                           */

/** compare entries in AVL tree of INETAs IPV4                         */
static int m_cmp_ineta_n_ipv4( void *ap_option,
                               struct dsd_htree1_avl_entry *adsp_entry_1,
                               struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   int        iml_cmp;                      /* for compare             */
#define ADSL_INETA_RAWS_1_P1 ((struct dsd_ineta_raws_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
#define ADSL_INETA_RAWS_1_P2 ((struct dsd_ineta_raws_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
#ifdef TRY100514
   struct dsd_ineta_raws_1 *adsh_ineta_raws_1_p1 = ADSL_INETA_RAWS_1_P1;
   struct dsd_ineta_raws_1 *adsh_ineta_raws_1_p2 = ADSL_INETA_RAWS_1_P2;
#endif
#ifdef DEBUG_130708                         /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d m_cmp_ineta_n_ipv4() INETA P1 %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 0),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 1),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 2),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 3) );
   m_hlnew_printf( HLOG_TRACE1, "HWSPMnnnT l%05d m_cmp_ineta_n_ipv4() INETA P2 %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 0),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 1),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 2),
                   *((unsigned char *) &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr + 3) );
#endif                                      /* 08.07.13 KB check INETAs in m_update_htun_ineta() */
   iml_cmp = memcmp( &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                     &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                     4 );
   if (iml_cmp) return iml_cmp;             /* not same INETA          */
   if (ap_option) {
     if (*((char *) ap_option) == 'C') {
       return 0;
     }
     if (   (*((char *) ap_option) == 'S')
         && (   (ADSL_INETA_RAWS_1_P1->boc_with_user == FALSE)  /* structure without user */
             || (ADSL_INETA_RAWS_1_P2->boc_with_user == FALSE))) {  /* structure without user */
       return 0;                            /* is PPP, do not check the port */
     }
   }
   return ADSL_INETA_RAWS_1_P1->usc_appl_port  /* port in use          */
            - ADSL_INETA_RAWS_1_P2->usc_appl_port;  /* port in use     */
#undef ADSL_INETA_RAWS_1_P1
#undef ADSL_INETA_RAWS_1_P2
} /* end m_cmp_ineta_n_ipv4()                                          */

/** compare entries in AVL tree of INETAs IPV6                         */
static int m_cmp_ineta_n_ipv6( void *,
                               struct dsd_htree1_avl_entry *adsp_entry_1,
                               struct dsd_htree1_avl_entry *adsp_entry_2 ) {
// to-do 13.05.10 KB
#define ADSL_CO_SORT_P1 ((struct dsd_co_sort *) ((char *) adsp_entry_1 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
#define ADSL_CO_SORT_P2 ((struct dsd_co_sort *) ((char *) adsp_entry_2 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
   return ADSL_CO_SORT_P1->imc_sno - ADSL_CO_SORT_P2->imc_sno;
#undef ADSL_CO_SORT_P1
#undef ADSL_CO_SORT_P2
} /* end m_cmp_ineta_n_ipv6()                                          */

/** compare entries in AVL tree of INETAs of user IPV4                 */
static int m_cmp_ineta_user_ipv4( void *,
                                  struct dsd_htree1_avl_entry *adsp_entry_1,
                                  struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_cmp;                      /* for compare             */

#define ADSL_INETA_RAWS_1_P1 ((struct dsd_ineta_raws_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_ineta_raws_1, dsc_sort_user )))
#define ADSL_INETA_RAWS_1_P2 ((struct dsd_ineta_raws_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_ineta_raws_1, dsc_sort_user )))
   iml_cmp = 0;
   bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                          &ADSL_INETA_RAWS_1_P1->dsc_user_group,  /* Usergroup Sign On */
                          &ADSL_INETA_RAWS_1_P2->dsc_user_group );  /* Usergroup Sign On */
   if (iml_cmp != 0) return iml_cmp;
   bol1 = m_cmpi_ucs_ucs( &iml_cmp,
                          &ADSL_INETA_RAWS_1_P1->dsc_user_name,  /* Username Sign On */
                          &ADSL_INETA_RAWS_1_P2->dsc_user_name );  /* Username Sign On */
   if (iml_cmp != 0) return iml_cmp;
   iml_cmp = memcmp( &ADSL_INETA_RAWS_1_P1->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                     &ADSL_INETA_RAWS_1_P2->dsc_tun_contr_ineta.dsc_soa_local_ipv4.sin_addr,
                     4 );
   if (iml_cmp) return iml_cmp;             /* not same INETA          */
   return ADSL_INETA_RAWS_1_P1->usc_appl_port  /* port in use          */
            - ADSL_INETA_RAWS_1_P2->usc_appl_port;  /* port in use     */
#undef ADSL_INETA_RAWS_1_P1
#undef ADSL_INETA_RAWS_1_P2
} /* end m_cmp_ineta_user_ipv4()                                       */

/** compare entries in AVL tree of INETAs of user IPV6                 */
static int m_cmp_ineta_user_ipv6( void *,
                                  struct dsd_htree1_avl_entry *adsp_entry_1,
                                  struct dsd_htree1_avl_entry *adsp_entry_2 ) {
// to-do 13.05.10 KB
#define ADSL_CO_SORT_P1 ((struct dsd_co_sort *) ((char *) adsp_entry_1 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
#define ADSL_CO_SORT_P2 ((struct dsd_co_sort *) ((char *) adsp_entry_2 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
   return ADSL_CO_SORT_P1->imc_sno - ADSL_CO_SORT_P2->imc_sno;
#undef ADSL_CO_SORT_P1
#undef ADSL_CO_SORT_P2
} /* end m_cmp_ineta_user_ipv6()                                       */
#endif

/** display information about the configuration file                   */
extern "C" void m_disp_conf_file( BOOL bop_with_wsp ) {
   time_t     dsl_time;
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];
   char       chrl_work1[32];               /* work area               */

   if (bop_with_wsp == FALSE) goto p_disp_conf_00;  /* display configuration file */
   m_hlnew_printf( HLOG_INFO1, "HWSPM015I this ComputerName %.*(u8)s process-id %d.",
                   dsg_this_server.imc_len_server_name,
                   dsg_this_server.chrc_server_name,
                   dsg_this_server.imc_pid );
// to-do 02.06.10 KB - epoch started and message numbers
   dsl_time = dsg_this_server.ilc_epoch_started / 1000;  /* time in seconds */
   strftime( chrl_work1, sizeof(chrl_work1), "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
   m_hlnew_printf( HLOG_INFO1, "HWSPM016I WSP time started %s.",
                   chrl_work1 );
   m_edit_fingerprint( chrl_disp_fp, dsg_this_server.chrc_fingerprint );
   m_hlnew_printf( HLOG_INFO1, "HWSPM017I fingerprint of this HOB WebSecureProxy %.*s.",
                   sizeof(chrl_disp_fp), chrl_disp_fp );
   m_hlnew_printf( HLOG_INFO1, "HWSPM018I processing configuration file %s.",
                   adss_path_param );
   goto p_disp_conf_20;                     /* display fingerprint     */

   p_disp_conf_00:                          /* display configuration file */
   m_hlnew_printf( HLOG_INFO1, "HWSPM013I loaded configuration file %s.",
                   adss_path_param );

   p_disp_conf_20:                          /* display fingerprint     */
#ifndef HL_UNIX
   m_edit_fingerprint( chrl_disp_fp, adss_loconf_1_fill->chrc_fingerprint );
#else
   m_edit_fingerprint( chrl_disp_fp, dss_loconf_1.chrc_fingerprint );
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPM014I fingerprint (SHA1) of configuration file %.*s.",
                   sizeof(chrl_disp_fp), chrl_disp_fp );

} /* end m_disp_conf_file()                                            */

/** edit decimal                                                       */
extern "C" char * m_edit_dec_int( char *achp_target, int imp1 ) {
   int        inl1;                         /* working variable        */
   char       *achl1;                       /* working variable        */

   achl1 = achp_target + 15;
   *achl1 = 0;                              /* make zero-terminated    */
   inl1 = 3;                                /* digits between separator */
   while (TRUE) {
     *(--achl1) = (char) (imp1 % 10 + '0');
     imp1 /= 10;
     if (imp1 == 0) return achl1;
     inl1--;
     if (inl1 == 0) {
     *(--achl1) = ',';                      /* output separator        */
       inl1 = 3;                            /* digits between separator */
     }
   }
} /* end m_edit_dec_int()                                              */

/** edit decimal 64-bit numeric variable                               */
extern "C" char * m_edit_dec_long( char *achp_target, HL_LONGLONG ilp1 ) {
   int        inl1;                         /* working variable        */
   char       *achl1;                       /* working variable        */

   achl1 = achp_target + 15;
   *achl1 = 0;                              /* make zero-terminated    */
   inl1 = 3;                                /* digits between separator */
   while (TRUE) {
     *(--achl1) = (char) (ilp1 % 10 + '0');
     ilp1 /= 10;
     if (ilp1 == 0) return achl1;
     inl1--;
     if (inl1 == 0) {
     *(--achl1) = ',';                      /* output separator        */
       inl1 = 3;                            /* digits between separator */
     }
   }
} /* end m_edit_dec_long()                                             */

/** edit scientific variable as power of two                           */
static void m_edit_sci_two( char *achp_buffer, HL_LONGLONG ilp_input ) {
   if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) {
     sprintf( achp_buffer, "%dG",
              (int) (((ilp_input + ((((HL_LONGLONG) 1024 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) / (HL_LONGLONG) 2))
                    / ((HL_LONGLONG) 1024 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024))) );
   } else if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) {
     sprintf( achp_buffer, "%dM",
              (int) ((ilp_input + ((((HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) / (HL_LONGLONG) 2))
                    / ((HL_LONGLONG) 1024 * (HL_LONGLONG) 1024)) );
   } else if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1024)) {
     sprintf( achp_buffer, "%dK", (int) ((ilp_input + (((HL_LONGLONG) 1024) / (HL_LONGLONG) 2)) / (HL_LONGLONG) 1024) );
   } else {
     sprintf( achp_buffer, "%d", (int) ilp_input );
   }
} /* end m_edit_sci_two()                                              */

/** edit scientific decimal variable                                   */
static void m_edit_sci_dec( char *achp_buffer, HL_LONGLONG ilp_input ) {
   if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1000 * (HL_LONGLONG) 1000 * (HL_LONGLONG) 1000)) {
     sprintf( achp_buffer, "%dg",
              (int) (((ilp_input + ((((HL_LONGLONG) 1000 * (HL_LONGLONG) 1000 * (HL_LONGLONG) 1000)) / (HL_LONGLONG) 2))
                    / ((HL_LONGLONG) 1000 * (HL_LONGLONG) 1000 * (HL_LONGLONG) 1000))) );
   } else if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1000 * (HL_LONGLONG) 1000)) {
     sprintf( achp_buffer, "%dm",
              (int) (((ilp_input + ((((HL_LONGLONG) 1000 * (HL_LONGLONG) 1000)) / (HL_LONGLONG) 2))
                    / ((HL_LONGLONG) 1000 * (HL_LONGLONG) 1000))) );
   } else if (ilp_input > ((HL_LONGLONG) 10 * (HL_LONGLONG) 1000)) {
     sprintf( achp_buffer, "%dk", (int) ((ilp_input + ((HL_LONGLONG) 1000 / (HL_LONGLONG) 2)) / (HL_LONGLONG) 1000) );
   } else {
     sprintf( achp_buffer, "%d", (int) ilp_input );
   }
} /* end m_edit_sci_dec()                                              */

/** edit fingerprint - SHA-1 hash                                      */
extern "C" void m_edit_fingerprint( char *achp_out, char *achp_inp ) {
   unsigned char ucl_w1;                    /* working variable        */
   char       *achl_w1, *achl_w2;           /* working variables       */

   achl_w1 = achp_inp + DEF_LEN_FINGERPRINT;
   achl_w2 = achp_inp + 2;
   while (TRUE) {
     ucl_w1 = (unsigned char) *achp_inp++;
     *achp_out++ = chrstrans[ ucl_w1 >> 4 ];
     *achp_out++ = chrstrans[ ucl_w1 & 0X0F ];
     if (achp_inp >= achl_w1) return;
     if (achp_inp >= achl_w2) {
       *achp_out++ = ' ';
       achl_w2 = achp_inp + 2;
     }
   }
} /* end m_edit_fingerprint()                                          */

#ifdef NEW_REPORT_1501
/** compute time next print fingerprint                                */
static void m_time_fingerprint( dsd_time_1 *adsp_time_fingerprint, dsd_time_1 *adsp_time_cur ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   struct tm  *adsl_tm_w1;                  /* working variable        */
   struct tm  dsl_tm_l1;                    /* working variable        */
   struct tm  dsl_tm_l2;                    /* working variable        */

   adsl_tm_w1 = localtime( adsp_time_cur );
   dsl_tm_l1 = *adsl_tm_w1;
   iml1 = (dsl_tm_l1.tm_hour * 60 + dsl_tm_l1.tm_min) * 60 + dsl_tm_l1.tm_sec;
   *adsp_time_fingerprint = *adsp_time_cur - iml1 + adsg_loconf_1_inuse->imc_tod_mark_log - 1 - 3600;
   bol1 = FALSE;                            /* needs to be today       */
   while (TRUE) {                           /* loop to compute time    */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "l%05d m_time_fingerprint() time cur=%lld fingerprint=%lld.",
                     __LINE__, (HL_LONGLONG) *adsp_time_cur, (HL_LONGLONG) *adsp_time_fingerprint );
#endif
     adsl_tm_w1 = localtime( adsp_time_fingerprint );
     dsl_tm_l2 = *adsl_tm_w1;
     /* check if today                                                 */
     if (   (bol1 == FALSE)
         && (dsl_tm_l2.tm_mday != dsl_tm_l1.tm_mday)) {
       *adsp_time_fingerprint += 3600 / 2;  /* add halve an hour       */
       continue;                            /* try again               */
     }
     iml2 = (dsl_tm_l2.tm_hour * 60 + dsl_tm_l2.tm_min) * 60;
//   if (adsg_loconf_1_inuse->imc_tod_mark_log != (iml2 + 1)) {
     if (adsg_loconf_1_inuse->imc_tod_mark_log > (iml2 + 1)) {
       *adsp_time_fingerprint += 3600 / 2;  /* add halve an hour       */
       continue;                            /* try again               */
     }
     if (bol1) break;                       /* is tomorrow             */
     if (iml2 > iml1) break;                /* later this day          */
     *adsp_time_fingerprint += (24 - 1) * 60 * 60;  /* time next day - daylight saving */
     bol1 = TRUE;                           /* is tomorrow             */
   }
#ifdef HL_UNIX
   if (*adsp_time_fingerprint == 0) {
     *adsp_time_fingerprint = 1;
   }
#endif
} /* end m_time_fingerprint()                                          */
#endif

