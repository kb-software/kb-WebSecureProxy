/** Admin return Sessions                                              */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_session( struct dsd_wspadm1_q_session * adsp_wspadm1_q_session ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   int        iml_count;                    /* count entries           */
   int        iml_cmp;                      /* to compare entries      */
   char       *achl_avl_error;              /* error code AVL tree     */
#ifndef HL_UNIX
   class clconn1 *adsl_conn_w1;             /* connection              */
#else
   struct dsd_conn1 *adsl_conn_w1;          /* connection              */
#endif
   char       *achl_w1;                     /* working variable        */
   char       *achl_out;                    /* output of values        */
   struct dsd_wspadm1_session *adsl_out_se;  /* WSP Administration Session */
#ifndef EXT_WSP_ADM_SESSION_USERFLD
   void *     arl_param[7];                 /* address of additional fields */
   int        imrl_len[7];                  /* length of additional fields */
#endif
#ifdef EXT_WSP_ADM_SESSION_USERFLD
   void *     arl_param[8];                 /* address of additional fields */
   int        imrl_len[8];                  /* length of additional fields */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_co_sort dsl_co_sort_w1;       /* for connection sort     */
#ifdef XYZ1
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   int        imc_sno;                      /* session number          */
#endif
   int        imrl_ineta_port[ 24 / sizeof(int) ];  /* save INETA and Port */

   iml_count = adsp_wspadm1_q_session->imc_no_session;  /* count entries */
   if (iml_count <= 0) {                    /* invalid number          */
     /* output record type invalid parameters                          */
     adsl_sdhc1_first = (struct dsd_sdh_control_1 *) m_proc_alloc();
     memset( adsl_sdhc1_first, 0, sizeof(struct dsd_sdh_control_1) );
     achl_out = (char *) (adsl_sdhc1_first + 1);  /* output of values  */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_first + LEN_TCP_RECV);
     adsl_gai1_w1--;                        /* here is gather output   */
     adsl_sdhc1_first->adsc_gather_i_1_i = adsl_gai1_w1;  /* first gather input data */
     adsl_gai1_w1->adsc_next = NULL;
     adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
     adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
     *(achl_out + 0) = 1;                   /* length of record        */
     *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_INV_PARAM;  /* invalid parameters */
     return adsl_sdhc1_first;
   }
   memset( &dsl_co_sort_w1, 0, sizeof(struct dsd_co_sort) );
   dsl_co_sort_w1.imc_sno = adsp_wspadm1_q_session->imc_session_no;  /* session number before */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   adsl_sdhc1_first = NULL;                 /* first structure         */
#ifndef HL_UNIX
   EnterCriticalSection( &d_clconn_critsect );
#else
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
#endif
   do {                                     /* pseudo-loop             */
     bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &dsl_co_sort_w1.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     do {                                   /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                    &dsl_htree1_work, FALSE );
       if (bol1 == FALSE) {                 /* error occured           */
         achl_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#ifndef HL_UNIX
       adsl_conn_w1 = (class clconn1 *)
                        ((char *) dsl_htree1_work.adsc_found
                           - offsetof( struct dsd_co_sort, dsc_sort_1 )
                           - offsetof( class clconn1, dsc_co_sort ));
#else
       adsl_conn_w1 = (struct dsd_conn1 *)
                        ((char *) dsl_htree1_work.adsc_found
                           - offsetof( struct dsd_co_sort, dsc_sort_1 )
                           - offsetof( struct dsd_conn1, dsc_co_sort ));
#endif
       memset( imrl_len, 0, sizeof(imrl_len) );
#ifndef HL_UNIX
       EnterCriticalSection( &adsl_conn_w1->d_act_critsect );  /* critical section act */
#else
       adsl_conn_w1->dsc_critsect.m_enter();  /* critical section      */
#endif
       /* search auxf records                                          */
       adsl_auxf_1_w1 = adsl_conn_w1->adsc_auxf_1;  /* get chain of auxiliary fields */
       while (adsl_auxf_1_w1) {             /* loop over all auxiliary fields */
         switch (adsl_auxf_1_w1->iec_auxf_def) {
           case ied_auxf_certname:          /* name from certificate = DN */
             arl_param[4] = ((int *) (adsl_auxf_1_w1 + 1)) + 1;
             imrl_len[4] = m_len_vx_vx( ied_chs_utf_8,
                                        (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                        *((int *) (adsl_auxf_1_w1 + 1)) - 1,
                                        ied_chs_utf_16 );
             break;
           case ied_auxf_ident:             /* ident - userid and user-group */
             imrl_len[5] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1))->imc_len_userid;  /* length userid UTF-8 */
             imrl_len[6] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1))->imc_len_user_group;  /* length name user group UTF-8 */
#ifdef EXT_WSP_ADM_SESSION_USERFLD
             imrl_len[7] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1))->imc_len_userfld;  /* length user field any character set */
#endif
             arl_param[5] = ((struct dsd_auxf_ident_1 *) (adsl_auxf_1_w1 + 1)) + 1;
             arl_param[6] = (char *) arl_param[5] + imrl_len[5];
#ifdef EXT_WSP_ADM_SESSION_USERFLD
             arl_param[7] = (char *) arl_param[6] + imrl_len[6];
#endif
             break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       do {                                 /* pseudo-loop             */
         /* special case - adsp_wspadm1_q_session->imc_len_user_group < 0 */
         iml1 = adsp_wspadm1_q_session->imc_len_user_group;
         if (iml1 < 0) iml1 = 0;
#ifdef EXT_WSP_ADM_SESSION_USERFLD
         if (adsp_wspadm1_q_session->imc_len_userfld > 0) {  /* length user field in bytes */
           if (adsp_wspadm1_q_session->imc_len_userfld != imrl_len[7]) {  /* length not equal */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
#ifdef B140818
           if (!memcmp( (char *) (adsp_wspadm1_q_session + 1)
                                   + adsp_wspadm1_q_session->imc_len_userid
                                   + iml1,
                        arl_param[7], imrl_len[7] )) {
             break;                         /* include this entry      */
           }
           bol1 = FALSE;                    /* do not include          */
           break;                           /* all done                */
#endif
           if (memcmp( (char *) (adsp_wspadm1_q_session + 1)
                                  + adsp_wspadm1_q_session->imc_len_userid
                                  + iml1,
                       arl_param[7], imrl_len[7] )) {
               bol1 = FALSE;                /* do not include          */
             break;                         /* include this entry      */
           }
         }
#endif
         if (   (adsp_wspadm1_q_session->imc_len_userid == 0)  /* length userid UTF-8 */
             && (adsp_wspadm1_q_session->imc_len_user_group <= 0)) {  /* length name user group UTF-8 */
           break;                           /* bol1 is already true    */
         }
         if (adsp_wspadm1_q_session->boc_use_wildcard == FALSE) {  /* do not use wildcard in search  */
           if (adsp_wspadm1_q_session->imc_len_userid != imrl_len[5]) {  /* compare length userid UTF-8 */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
           if (adsp_wspadm1_q_session->imc_len_user_group >= 0) {  /* not all user groups */
             if (adsp_wspadm1_q_session->imc_len_user_group != imrl_len[6]) {  /* compare length name user group UTF-8 */
               bol1 = FALSE;                /* do not include          */
               break;                       /* all done                */
             }
           }
           if (imrl_len[5]) {
             if (memcmp( adsp_wspadm1_q_session + 1, arl_param[5], imrl_len[5] )) {
               bol1 = FALSE;                /* do not include          */
               break;                       /* all done                */
             }
           }
           if (adsp_wspadm1_q_session->imc_len_user_group >= 0) {  /* not all user groups */
             if (imrl_len[6]) {
               if (memcmp( (char *) (adsp_wspadm1_q_session + 1) + adsp_wspadm1_q_session->imc_len_userid,
                           arl_param[6], imrl_len[6] )) {
                 bol1 = FALSE;              /* do not include          */
                 break;                     /* all done                */
               }
             }
           }
           break;                           /* bol1 is already true    */
         }
         /* search with wildcard                                       */
         if (adsp_wspadm1_q_session->imc_len_userid) {  /* check userid */
           bol1 = m_cmp_wc_i_vx_vx( &iml_cmp,
                                    arl_param[5], imrl_len[5], ied_chs_utf_8,
                                    adsp_wspadm1_q_session + 1, adsp_wspadm1_q_session->imc_len_userid, ied_chs_utf_8 );
           if ((bol1 == FALSE) || iml_cmp) {  /* strings do not match  */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
         }
         if (adsp_wspadm1_q_session->imc_len_user_group >= 0) {  /* check user-group */
           bol1 = m_cmp_wc_i_vx_vx( &iml_cmp,
                                    arl_param[6], imrl_len[6], ied_chs_utf_8,
                                    (char *) (adsp_wspadm1_q_session + 1) + adsp_wspadm1_q_session->imc_len_userid,
                                    adsp_wspadm1_q_session->imc_len_user_group, ied_chs_utf_8 );
           if ((bol1 == FALSE) || iml_cmp) {  /* strings do not match  */
             bol1 = FALSE;                  /* do not include          */
             break;                         /* all done                */
           }
         }
       } while (FALSE);
       if (bol1) {                          /* return this session     */
#ifdef B120210
         while (adsl_conn_w1->dcl_tcp_r_s.getstc()) {  /* session to server is active */
           achl_w1 = NULL;                  /* no INETA yet            */
           switch (adsl_conn_w1->dcl_tcp_r_s.dsc_soa.ss_family) {
             case AF_INET:                  /* IPV4                    */
               achl_w1 = (char *) &((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_addr;
               iml1 = 4;
               break;
             case AF_INET6:                 /* IPV6                    */
               achl_w1 = (char *) &((struct sockaddr_in6 *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin6_addr;
               iml1 = 16;
               break;
           }
           if (achl_w1 == NULL) break;      /* no INETA found          */
           memcpy( imrl_ineta_port, achl_w1, iml1 );
           arl_param[3] = imrl_ineta_port;  /* copy this field later   */
           *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
             = IP_ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_port );
           imrl_len[3] = iml1 + sizeof(unsigned short int);
           break;
         }
#endif
#ifndef B120210
         switch (adsl_conn_w1->iec_servcotype) {  /* type of server connection */
           case ied_servcotype_normal_tcp:  /* normal TCP              */
             achl_w1 = NULL;                /* no INETA yet            */
#ifndef HL_UNIX
             switch (adsl_conn_w1->dcl_tcp_r_s.dsc_soa.ss_family) {
               case AF_INET:                /* IPV4                    */
                 achl_w1 = (char *) &((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_addr;
                 iml1 = 4;
#ifndef B120219
                 *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
                   = IP_ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_port );
#endif
                 break;
               case AF_INET6:               /* IPV6                    */
                 achl_w1 = (char *) &((struct sockaddr_in6 *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin6_addr;
                 iml1 = 16;
#ifndef B120219
                 *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
                   = IP_ntohs( ((struct sockaddr_in6 *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin6_port );
#endif
                 break;
             }
#else
             switch (adsl_conn_w1->dsc_tc1_server.dsc_soa_conn.ss_family) {
               case AF_INET:                /* IPV4                    */
                 achl_w1 = (char *) &((struct sockaddr_in *) &adsl_conn_w1->dsc_tc1_server.dsc_soa_conn)->sin_addr;
                 iml1 = 4;
                 *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
                   = ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dsc_tc1_server.dsc_soa_conn)->sin_port );
                 break;
               case AF_INET6:               /* IPV6                    */
                 achl_w1 = (char *) &((struct sockaddr_in6 *) &adsl_conn_w1->dsc_tc1_server.dsc_soa_conn)->sin6_addr;
                 iml1 = 16;
                 *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
                   = ntohs( ((struct sockaddr_in6 *) &adsl_conn_w1->dsc_tc1_server.dsc_soa_conn)->sin6_port );
                 break;
             }
#endif
             if (achl_w1 == NULL) break;    /* no INETA found          */
             memcpy( imrl_ineta_port, achl_w1, iml1 );
             arl_param[3] = imrl_ineta_port;  /* copy this field later */
#ifdef B120219
#ifndef HL_UNIX
             *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
               = IP_ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_port );
#else
             *((unsigned short int *) ((char *) imrl_ineta_port + iml1))
               = IP_ntohs( ((struct sockaddr_in *) &adsl_conn_w1->dcl_tcp_r_s.dsc_soa)->sin_port );
#endif
#endif
             imrl_len[3] = iml1 + sizeof(unsigned short int);
             break;
#ifdef D_INCL_HTUN
           case ied_servcotype_htun:        /* HOB-TUN                 */
// to-do 10.02.12 KB missing information
             break;
#endif
         }
#endif
         arl_param[0] = adsl_conn_w1->adsc_gate1 + 1;
         imrl_len[0] = m_len_vx_vx( ied_chs_utf_8,
                                    arl_param[0], -1, ied_chs_utf_16 );
         adsl_server_conf_1_w1 = NULL;      /* no configuration server yet */
         if (adsl_conn_w1->adsc_server_conf_1) {  /* configuration server */
           adsl_server_conf_1_w1 = adsl_conn_w1->adsc_server_conf_1;  /* get current server configuration */
#ifdef B101215
           if (adsl_server_conf_1_w1->boc_dynamic) {  /* dynamicly allocated */
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
           }
#else
           if (adsl_server_conf_1_w1->adsc_seco1_previous) {  /* has previous configuration */
             adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* configuration server previous */
           }
#endif
         }
         if (adsl_server_conf_1_w1) {       /* configuration server valid */
           if (adsl_server_conf_1_w1->inc_len_name) {  /* name has valid length */
             arl_param[1] = (char *) (adsl_server_conf_1_w1 + 1)
                                        + adsl_server_conf_1_w1->inc_no_sdh
                                          * sizeof(struct dsd_sdh_work_1);
             imrl_len[1] = m_len_vx_vx( ied_chs_utf_8,
                                        arl_param[1], -1, ied_chs_utf_16 );
           }
           switch (adsl_server_conf_1_w1->iec_scp_def) {
             case ied_scp_undef:            /* protocol undefined      */
               break;                       /* nothing to do           */
             case ied_scp_spec:             /* special protocol        */
               imrl_len[2] = adsl_server_conf_1_w1->inc_len_protocol;
               arl_param[2] = (char *) (adsl_server_conf_1_w1 + 1)
                                + adsl_server_conf_1_w1->inc_no_sdh
                                  * sizeof(struct dsd_sdh_work_1)
                                + adsl_server_conf_1_w1->inc_len_name;
               break;                       /* all done                */
             default:                       /* all other protocols     */
               iml1 = sizeof(dsrs_protdef_e) / sizeof(dsrs_protdef_e[0]);
               do {                         /* loop over all defined protocols */
                 iml1--;                    /* decrement index         */
                 if (dsrs_protdef_e[iml1].iec_scp_def == adsl_server_conf_1_w1->iec_scp_def) {
                   arl_param[2] = dsrs_protdef_e[iml1].achc_keyword;
                   imrl_len[2] = strlen( (char *) arl_param[2] );
                   break;                   /* all done                */
                 }
               } while (iml1 > 0);
               break;                       /* all done                */
           }
         }
         iml1 = sizeof(struct dsd_wspadm1_session);
         iml2 = sizeof(imrl_len) / sizeof(imrl_len[0]);  /* number of elements */
         do {                               /* add all length fields   */
           iml2--;                          /* decrement index         */
           iml1 += imrl_len[ iml2 ];        /* sum of length           */
         } while (iml2 > 0);
         do {                               /* pseudo-loop             */
           if (adsl_sdhc1_first) {          /* first structure present */
             achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                   <= ((char *) adsl_gai1_w1)) {
               adsl_gai1_w1--;              /* here is gather output   */
               (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
               break;
             }
           }
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
           memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
           achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
           achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
           adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
           adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
           if (adsl_sdhc1_first == NULL) {    /* first structure not present */
             adsl_sdhc1_first = adsl_sdhc1_w1;  /* first structure now present */
             adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure   */
             break;
           }
           adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
           adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure     */
         } while (FALSE);
         adsl_gai1_w1->adsc_next = NULL;
         adsl_out_se = (struct dsd_wspadm1_session *) achl_out;
         iml1++;                            /* add length record type  */
         *(--achl_out) = 0;                 /* record type             */
         iml2 = 0;                          /* clear more bit          */
         while (TRUE) {                     /* output length NHASN     */
           *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
           iml1 >>= 7;                      /* remove digit            */
           if (iml1 == 0) break;            /* end of output           */
           iml2 = 0X80;                     /* set more bit            */
         }
         adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
         adsl_out_se->imc_len_gate_name = imrl_len[0];  /* length gate name UTF-8 */
         adsl_out_se->imc_len_serv_ent = imrl_len[1];  /* length name Server Entry UTF-8 */
         adsl_out_se->imc_len_protocol = imrl_len[2];  /* length of protocol UTF-8 */
         adsl_out_se->imc_len_ineta_port = imrl_len[3];  /* INETA and Port connection to server */
         adsl_out_se->imc_session_no = adsl_conn_w1->dsc_co_sort.imc_sno;  /* session number */
         memcpy( adsl_out_se->chrc_ineta, adsl_conn_w1->chrc_ineta, sizeof(adsl_out_se->chrc_ineta) );  /* internet-address client char */
         adsl_out_se->imc_time_start = adsl_conn_w1->imc_time_start;  /* time session started */
         adsl_out_se->imc_c_ns_rece_c = adsl_conn_w1->inc_c_ns_rece_c;  /* count receive client */
         adsl_out_se->imc_c_ns_send_c = adsl_conn_w1->inc_c_ns_send_c;  /* count send client */
         adsl_out_se->imc_c_ns_rece_s = adsl_conn_w1->inc_c_ns_rece_s;  /* count receive server */
         adsl_out_se->imc_c_ns_send_s = adsl_conn_w1->inc_c_ns_send_s;  /* count send server */
         adsl_out_se->imc_c_ns_rece_e = adsl_conn_w1->inc_c_ns_rece_e;  /* count encrypted from cl */
         adsl_out_se->imc_c_ns_send_e = adsl_conn_w1->inc_c_ns_send_e;  /* count encrypted to clie */
         adsl_out_se->ilc_d_ns_rece_c = adsl_conn_w1->ilc_d_ns_rece_c;  /* data received client */
         adsl_out_se->ilc_d_ns_send_c = adsl_conn_w1->ilc_d_ns_send_c;  /* data sent client */
         adsl_out_se->ilc_d_ns_rece_s = adsl_conn_w1->ilc_d_ns_rece_s;  /* data received server */
         adsl_out_se->ilc_d_ns_send_s = adsl_conn_w1->ilc_d_ns_send_s;  /* data sent server */
         adsl_out_se->ilc_d_ns_rece_e = adsl_conn_w1->ilc_d_ns_rece_e;  /* data received encyrpted */
         adsl_out_se->ilc_d_ns_send_e = adsl_conn_w1->ilc_d_ns_send_e;  /* data sent encrypted */
         adsl_out_se->imc_len_name_cert = imrl_len[4];  /* length name from certificate UTF-8 */
         adsl_out_se->imc_len_userid = imrl_len[5];  /* length userid UTF-8 */
         adsl_out_se->imc_len_user_group = imrl_len[6];  /* length name user group UTF-8 */
#ifdef EXT_WSP_ADM_SESSION_USERFLD
         adsl_out_se->imc_len_userfld = imrl_len[7];  /* length user field in bytes */
#endif
         achl_out = (char *) (adsl_out_se + 1);  /* output of strings here */
         iml1 = 0;                          /* clear count entry       */
         do {                               /* loop to generate additional UTF-8 fields */
           if (imrl_len[ iml1 ] > 0) {      /* set parameter           */
             if ((iml1 <= 1) || (iml1 == 4)) {  /* get from UTF-16     */
               m_cpy_vx_vx( achl_out, imrl_len[ iml1 ], ied_chs_utf_8,
                            arl_param[ iml1 ], -1, ied_chs_utf_16 );
             } else {                       /* is already UTF-8        */
               memcpy( achl_out, arl_param[ iml1 ], imrl_len[ iml1 ] );
             }
             achl_out += imrl_len[ iml1 ];  /* add length parameter    */
           }
           iml1++;                          /* take next entry         */
         } while (iml1 < (sizeof(imrl_len) / sizeof(imrl_len[0])));
         adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
         iml_count--;                       /* decrement count entries */
       }
#ifndef HL_UNIX
       LeaveCriticalSection( &adsl_conn_w1->d_act_critsect );  /* critical section act */
#else
       adsl_conn_w1->dsc_critsect.m_leave();  /* critical section      */
#endif
     } while (iml_count > 0);
   } while (FALSE);
#ifndef HL_UNIX
   LeaveCriticalSection( &d_clconn_critsect );
#else
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
#endif
   if (achl_avl_error) {                    /* error occured           */
/* to-do 13.04.08 KB - error message */
//   m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s remove sno error %s",
//                   adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl_avl_error );
   }
   if (iml_count <= 0) {                    /* all processed           */
     return adsl_sdhc1_first;
   }
   /* output record type eof end-of-file                               */
   do {                                     /* pseudo-loop             */
     if (adsl_sdhc1_first) {                /* first structure present */
       if ((achl_out + 2 + sizeof(struct dsd_gather_i_1))
             <= ((char *) adsl_gai1_w1)) {
         adsl_gai1_w1--;                    /* here is gather output   */
         (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
         break;
       }
     }
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
     achl_out = (char *) (adsl_sdhc1_w1 + 1);  /* output of values     */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
     adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
     if (adsl_sdhc1_first == NULL) {        /* first structure not present */
       adsl_sdhc1_first = adsl_sdhc1_w1;    /* first structure now present */
       adsl_sdhc1_last = adsl_sdhc1_w1;     /* set last structure      */
       break;
     }
     adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain   */
     adsl_sdhc1_last = adsl_sdhc1_w1;       /* set last structure      */
   } while (FALSE);
   adsl_gai1_w1->adsc_next = NULL;
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
   *(achl_out + 0) = 1;                     /* length of record        */
   *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_EOF;  /* end-of-file */
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_session()                                       */

/** Admin cancel Session                                               */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_cancel_session( struct dsd_wspadm1_q_can_sess_1 *adsp_wspadm1_qcs1 ) {
   BOOL       bol1;                         /* working variable        */
   char       *achl_out;                    /* output of values        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
#ifndef HL_UNIX
   class clconn1 *adsl_conn_w1;             /* connection              */
#else
   struct dsd_conn1 *adsl_conn_w1;          /* connection              */
#endif
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_co_sort dsl_co_sort_w1;       /* for connection sort     */

   adsl_sdhc1_first = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_first, 0, sizeof(struct dsd_sdh_control_1) );
   achl_out = (char *) (adsl_sdhc1_first + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
   achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
   adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_first + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
   adsl_gai1_w1->adsc_next = NULL;
   adsl_sdhc1_first->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
   memset( &dsl_co_sort_w1, 0, sizeof(struct dsd_co_sort) );
   dsl_co_sort_w1.imc_sno = adsp_wspadm1_qcs1->imc_session_no;  /* session number to cancel */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
#ifndef HL_UNIX
   EnterCriticalSection( &d_clconn_critsect );
#else
   dss_main_critsect.m_enter();             /* enter CriticalSection   */
#endif
   bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                               &dsl_htree1_work, &dsl_co_sort_w1.dsc_sort_1 );
   if (bol1 == FALSE) {                     /* error occured           */
     achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &d_clconn_critsect );
#else
   dss_main_critsect.m_leave();             /* leave CriticalSection   */
#endif
   if (achl_avl_error) {                    /* error occured           */
/* to-do 01.10.08 KB - error message */
     adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
     adsl_gai1_w1->achc_ginp_end = achl_out + 2;  /* end of this structure */
     *(achl_out + 0) = 1;                   /* length of record        */
     *(achl_out + 1) = (unsigned char) DEF_WSPADM_RT_PROC_E;  /* processing error */
     return adsl_sdhc1_first;
   }
#define ADSL_WSPADM1_RCS1_G ((struct dsd_wspadm1_r_can_sess_1 *) achl_out)
   adsl_gai1_w1->achc_ginp_end = (char *) (ADSL_WSPADM1_RCS1_G + 1);  /* end of this structure */
   memset( ADSL_WSPADM1_RCS1_G, 0, sizeof(struct dsd_wspadm1_r_can_sess_1) );
   if (dsl_htree1_work.adsc_found) {        /* entry found             */
// to-do 19.02.12 KB subroutine cancel session - admin and timeout
#ifndef HL_UNIX
     adsl_conn_w1 = (class clconn1 *)
                      ((char *) dsl_htree1_work.adsc_found
                         - offsetof( struct dsd_co_sort, dsc_sort_1 )
                         - offsetof( class clconn1, dsc_co_sort ));
     if (adsl_conn_w1->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn_w1->achc_reason_end = "cancelled by Admin";  /* set text */
     }
     adsl_conn_w1->dcl_tcp_r_c.close1();
     if (   (adsl_conn_w1->iec_st_ses == clconn1::ied_ses_conn)  /* stat server */
         && (adsl_conn_w1->iec_servcotype == ied_servcotype_normal_tcp)) {  /* normal TCP */
       adsl_conn_w1->dcl_tcp_r_s.close1();
     }
#ifndef B160410
     adsl_conn_w1->ilc_timeout = 0;         /* timeout no more set     */
#endif
#else
     adsl_conn_w1 = (struct dsd_conn1 *)
                      ((char *) dsl_htree1_work.adsc_found
                         - offsetof( struct dsd_co_sort, dsc_sort_1 )
                         - offsetof( struct dsd_conn1, dsc_co_sort ));
     if (adsl_conn_w1->achc_reason_end == NULL) {  /* reason end session */
       adsl_conn_w1->achc_reason_end = "cancelled by Admin";  /* set text */
     }
     m_cancel_conn( adsl_conn_w1 );         /* cancel the connection   */
#endif
     ADSL_WSPADM1_RCS1_G->boc_ok = TRUE;    /* cancel session successful */
   }
   *(--achl_out) = 0;                       /* type of record          */
   *(--achl_out) = (unsigned char) (1 + sizeof(struct dsd_wspadm1_r_can_sess_1));  /* length of record */
   adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_cancel_session()                                */

/** Admin return Listen                                                */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_listen( void ) {
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_len_ineta;                /* length of INETAs        */
   char       *achl_ineta;                  /* address of INETA        */
   char       *achl_out;                    /* output of values        */
   struct dsd_wspadm1_listen_main *adsl_o_l_main;
   struct dsd_wspadm1_listen_ineta *adsl_o_l_ineta;
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working-variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first structure     */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last structure       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* output data             */
   struct dsd_loconf_1 *adsl_loconf_1_w1;   /* working var loaded conf */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gateway                 */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

   adsl_sdhc1_first = NULL;                 /* first structure         */
#ifndef HL_UNIX
   adsl_loconf_1_w1 = adss_loconf_1_anchor;  /* get anchor loaded conf  */
#else
   adsl_loconf_1_w1 = adsg_loconf_1_inuse;  /* get loaded configuration */
#endif
   do {
#ifdef XYZ1
     m_hlnew_printf( HLOG_XYZ1, "HWSPR003I configuration loaded %s", adsl_loconf_1_w1->byrc_time );
#endif
     adsl_gate_1_w1 = adsl_loconf_1_w1->adsc_gate_anchor;  /* get anchor gate */
     while (adsl_gate_1_w1) {
#ifdef XYZ1
       iml_len_ineta = sizeof(struct dsd_wspadm1_listen_main);  /* clear length of INETAs */
       adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;  /* get chain listen part of gateway */
       while (adsl_gate_listen_1_w1) {      /* loop over all listen parts */
         iml_len_ineta += 1 + 1 + sizeof(struct dsd_wspadm1_listen_ineta) + adsl_gate_listen_1_w1->imc_len_ineta;
         adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
       }
#endif
       iml3 = m_len_vx_vx( ied_chs_utf_8,
                           adsl_gate_1_w1 + 1, -1, ied_chs_utf_16 );
       iml1 = sizeof(struct dsd_wspadm1_listen_main) + iml3;
       /* find space in output area                                    */
       do {                                 /* pseudo-loop             */
         if (adsl_sdhc1_first) {            /* first structure present */
           achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
           achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
           if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                 <= ((char *) adsl_gai1_w1)) {
             adsl_gai1_w1--;                /* here is gather output   */
             (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
             break;
           }
         }
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
         memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
         achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
         achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
         adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
         adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
         if (adsl_sdhc1_first == NULL) {    /* first structure not present */
           adsl_sdhc1_first = adsl_sdhc1_w1;  /* first structure now present */
           adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure     */
           break;
         }
         adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
         adsl_sdhc1_last = adsl_sdhc1_w1;   /* set last structure      */
       } while (FALSE);
       adsl_gai1_w1->adsc_next = NULL;
       adsl_o_l_main = (struct dsd_wspadm1_listen_main *) achl_out;
       iml1++;                              /* add length record type  */
       *(--achl_out) = 0;                   /* record type             */
       iml2 = 0;                            /* clear more bit          */
       while (TRUE) {                       /* output length NHASN     */
         *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
         iml1 >>= 7;                        /* remove digit            */
         if (iml1 == 0) break;              /* end of output           */
         iml2 = 0X80;                       /* set more bit            */
       }
       adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
       memset( adsl_o_l_main, 0, sizeof(struct dsd_wspadm1_listen_main) );
       adsl_o_l_main->imc_len_gate_name = iml3;  /* length gate name UTF-8 */
       adsl_o_l_main->imc_epoch_conf_loaded = adsl_gate_1_w1->adsc_loconf_1->imc_epoch_loaded;  /* time / epoch configuration loaded */
       if (adsl_gate_1_w1->adsc_loconf_1 == adsg_loconf_1_inuse) {  /* in use now */
         adsl_o_l_main->boc_active_conf = TRUE;  /* listen is from active configuration */
       }
#ifdef NOT_YET
       adsl_o_l_main->boc_use_listen_gw;            /* listen over listen gateway */
#endif
       adsl_o_l_main->imc_gateport = adsl_gate_1_w1->imc_gateport;  /* TCP/IP port listen */
       adsl_o_l_main->imc_backlog = adsl_gate_1_w1->imc_backlog;  /* TCP/IP backlog listen */
       adsl_o_l_main->imc_timeout = adsl_gate_1_w1->itimeout;  /* timeout in seconds */
#ifdef NOT_YET
       adsl_o_l_main->imc_thresh_session;           /* threshold-session       */
       adsl_o_l_main->boc_cur_thresh_session;       /* currently over threshold-session */
       adsl_o_l_main->imc_epoch_thresh_se_notify;   /* last time of threshold-session notify */
#endif
       adsl_o_l_main->imc_session_max = adsl_gate_1_w1->i_session_max;  /* maximum number of sess */
       adsl_o_l_main->imc_session_cos = adsl_gate_1_w1->i_session_cos;  /* count start of session */
       adsl_o_l_main->imc_session_cur = adsl_gate_1_w1->i_session_cur;  /* current number of sess */
       adsl_o_l_main->imc_session_mre = adsl_gate_1_w1->i_session_mre;  /* maximum no sess reached */
       adsl_o_l_main->imc_session_exc = adsl_gate_1_w1->i_session_exc;  /* number max session exce */
       achl_out = (char *) (adsl_o_l_main + 1);  /* after this structure */
       m_cpy_vx_vx( achl_out, iml3, ied_chs_utf_8,
                    adsl_gate_1_w1 + 1, -1, ied_chs_utf_16 );
       achl_out += iml3;                    /* after name              */
       adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
       adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;  /* get chain listen part of gateway */
       while (adsl_gate_listen_1_w1) {      /* loop over all listen parts */
         iml_len_ineta = 0;                 /* clear length            */
         switch (adsl_gate_listen_1_w1->dsc_soa.ss_family) {
           case AF_INET:                    /* IPV4                    */
             achl_ineta = (char *) &((struct sockaddr_in *) &adsl_gate_listen_1_w1->dsc_soa)->sin_addr;
             iml_len_ineta = 4;
             break;
           case AF_INET6:                   /* IPV6                    */
             achl_ineta = (char *) &((struct sockaddr_in6 *) &adsl_gate_listen_1_w1->dsc_soa)->sin6_addr;
             iml_len_ineta = 16;
             break;
         }
         if (iml_len_ineta) {               /* address family valid    */
           iml1 = sizeof(struct dsd_wspadm1_listen_ineta) + iml_len_ineta;
           /* find space in output area                                */
           do {                             /* pseudo-loop             */
             achl_out += 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             if ((achl_out + iml1 + sizeof(struct dsd_gather_i_1))
                   <= ((char *) adsl_gai1_w1)) {
               adsl_gai1_w1--;              /* here is gather output   */
               (adsl_gai1_w1 + 1)->adsc_next = adsl_gai1_w1;  /* set next in chain */
               break;
             }
             adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
             memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) );
             achl_out = (char *) (adsl_sdhc1_w1 + 1) + 4 + 1 + sizeof(void *) - 1;  /* output of values */
             achl_out = (char *) (((long long int) achl_out) & (0 - sizeof(void *)));
             adsl_gai1_w1 = (struct dsd_gather_i_1 *) ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - sizeof(struct dsd_gather_i_1));
             adsl_sdhc1_w1->adsc_gather_i_1_i = adsl_gai1_w1;  /* gather input data */
             adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;  /* append to chain */
             adsl_sdhc1_last = adsl_sdhc1_w1;  /* set last structure   */
           } while (FALSE);
           adsl_gai1_w1->adsc_next = NULL;
           adsl_o_l_ineta = (struct dsd_wspadm1_listen_ineta *) achl_out;
           iml1++;                          /* add length record type  */
           *(--achl_out) = 1;               /* record type             */
           iml2 = 0;                        /* clear more bit          */
           while (TRUE) {                   /* output length NHASN     */
             *(--achl_out) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output of digit */
             iml1 >>= 7;                    /* remove digit            */
             if (iml1 == 0) break;          /* end of output           */
             iml2 = 0X80;                   /* set more bit            */
           }
           adsl_gai1_w1->achc_ginp_cur = achl_out;  /* start of this structure */
           memset( adsl_o_l_ineta, 0, sizeof(struct dsd_wspadm1_listen_ineta) );
           adsl_o_l_ineta->imc_len_ineta = iml_len_ineta;  /* length of INETA in bytes */
           achl_out = (char *) (adsl_o_l_ineta + 1);  /* after this structure */
           memcpy( achl_out, achl_ineta, iml_len_ineta );
           achl_out += iml_len_ineta;
           adsl_gai1_w1->achc_ginp_end = achl_out;  /* end of this structure */
         }
         adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
       }
       adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
     }
     adsl_loconf_1_w1 = adsl_loconf_1_w1->adsc_next;  /* get next in chain */
   } while (adsl_loconf_1_w1);              /* over all configurations */
   return adsl_sdhc1_first;
} /* end m_get_wspadm1_listen()                                        */

/** Admin return Performance Data                                      */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_perfdata( void ) {
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1;                     /* working variable        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */

   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
   achl_w1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) + 8;
   iml1 = m_get_perf_array( achl_w1, ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV) - achl_w1 );
   if (iml1 <= 0) {
// to-do 27.04.11 KB error message
     m_proc_free( adsl_sdhc1_w1 );          /* free data again         */
     return NULL;                           /* nothing prepared        */
   }
   ADSL_GAI1_G1->achc_ginp_end = achl_w1 + iml1;  /* end of data       */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop for output of length NHASN */
     *(--achl_w1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits             */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   ADSL_GAI1_G1->achc_ginp_cur = achl_w1;   /* start of data           */
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* gather input data */
   return adsl_sdhc1_w1;                    /* return data prepared    */
#undef ADSL_GAI1_G1
} /* end m_get_wspadm1_perfdata()                                      */

/** Admin control WSP Trace                                            */
extern "C" void m_ctrl_wspadm1_wsp_trace( struct dsd_wspadm1_q_wsp_trace_1 *adsp_wspadm1_qwt1, int imp_len_content ) {
   char       *achl_cur;                    /* current INETA pointer   */
   char       *achl_end;                    /* end if INETAs           */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w1;  /* WSP trace client with INETA control */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w2;  /* WSP trace client with INETA control */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX1-%05d-T m_ctrl_wspadm1_wsp_trace( %p , %d ) called",
                   __LINE__, adsp_wspadm1_qwt1, imp_len_content );
   m_console_out( (char *) adsp_wspadm1_qwt1, sizeof(struct dsd_wspadm1_q_wsp_trace_1) + imp_len_content );
#endif
   if (adsg_loconf_1_inuse->boc_allow_wsp_trace == FALSE) {  /* <allow-wsp-trace> */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW WSP Trace administration command but <allow-wsp-trace> not configured" );
     return;                                /* do nothing              */
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPMnnnI WSP Trace administration command %d.",
                   adsp_wspadm1_qwt1->iec_wawt );
   switch (adsp_wspadm1_qwt1->iec_wawt) {   /* admin WSP Trace definition */
     case ied_wawt_target:                  /* define new target       */
       goto p_adm_target_00;                /* define new target       */
     case ied_wawt_trace_new_ineta_all:     /* trace all INETAs        */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) );
         memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) );
         adsl_wtic_w2->boc_trace_ineta_all = TRUE;  /* trace all INETAS */
         adsl_wtic_w2->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         adss_wtic_active = adsl_wtic_w2;   /* WSP trace client with INETA control */
         return;                            /* all done                */
       }
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         adsl_wtic_w1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         return;                            /* all done                */
       }
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) );
       memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) );
       adsl_wtic_w2->boc_trace_ineta_all = TRUE;  /* trace all INETAS  */
       adsl_wtic_w2->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
     case ied_wawt_trace_new_ineta_spec:    /* trace specific INETA    */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content );
         memset( adsl_wtic_w2, 0, sizeof(struct dsd_wsp_tr_ineta_ctrl) + sizeof(struct dsd_wsp_tr_ineta_1) );
         adsl_wtic_w2->imc_len_inetas = sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content;  /* length of following INETAs */
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) (adsl_wtic_w2 + 1))
         ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
         ADSL_WTIA1_G1->usc_family = AF_INET;  /* family IPV4 / IPV6   */
         ADSL_WTIA1_G1->usc_length = imp_len_content;  /* length of following address */
         if (imp_len_content == 16) {       /* IPV6                    */
           ADSL_WTIA1_G1->usc_family = AF_INET6;  /* family IPV4 / IPV6 */
         }
         memcpy( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
         adss_wtic_active = adsl_wtic_w2;   /* WSP trace client with INETA control */
         return;                            /* all done                */
       }
#undef ADSL_WTIA1_G1
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         return;                            /* all done                */
       }
       /* search if INETA already set                                  */
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs   */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (achl_cur < achl_end) {
         if (   (imp_len_content == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content ))) {
           ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
           return;                          /* all done                */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
#undef ADSL_WTIA1_G1
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) + adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content );
       memcpy( adsl_wtic_w2, adsl_wtic_w1, sizeof(struct dsd_wsp_tr_ineta_ctrl) + adsl_wtic_w1->imc_len_inetas );
       adsl_wtic_w2->imc_len_inetas = adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) + imp_len_content;  /* length of following INETAs */
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) ((char *) (adsl_wtic_w2 + 1) + adsl_wtic_w1->imc_len_inetas))
       ADSL_WTIA1_G1->imc_trace_level = adsp_wspadm1_qwt1->imc_trace_level;  /* trace_level */
       ADSL_WTIA1_G1->usc_family = AF_INET;  /* family IPV4 / IPV6   */
       ADSL_WTIA1_G1->usc_length = imp_len_content;  /* length of following address */
       if (imp_len_content == 16) {         /* IPV6                    */
         ADSL_WTIA1_G1->usc_family = AF_INET6;  /* family IPV4 / IPV6  */
       }
       memcpy( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
#undef ADSL_WTIA1_G1
     case ied_wawt_trace_del_ineta_all:     /* delete trace all INETAs */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         return;                            /* all done                */
       }
       adss_wtic_active = NULL;             /* clear WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
     case ied_wawt_trace_del_ineta_spec:    /* delete trace specific INETA */
       adsl_wtic_w1 = adss_wtic_active;     /* WSP trace client with INETA control */
       if (adsl_wtic_w1 == NULL) {          /* no WSP trace client with INETA control set */
         return;                            /* all done                */
       }
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         return;                            /* all done                */
       }
       /* search if INETA already set                                  */
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs   */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (TRUE) {                       /* loop over all INETAs    */
         if (achl_cur >= achl_end) return;  /* INETA not found         */
         if (   (imp_len_content == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content ))) {
           break;                           /* INETA found             */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
       if (   (achl_cur == (char *) (adsl_wtic_w1 + 1))  /* here start INETAs */
           && ((achl_cur + sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length) >= achl_end)) {
         adss_wtic_active = NULL;           /* clear WSP trace client with INETA control */
         free( adsl_wtic_w1 );              /* free old control area   */
         return;                            /* all done                */
       }
       adsl_wtic_w2 = (struct dsd_wsp_tr_ineta_ctrl *) malloc( sizeof(struct dsd_wsp_tr_ineta_ctrl) - adsl_wtic_w1->imc_len_inetas + sizeof(struct dsd_wsp_tr_ineta_1) - imp_len_content );
       memcpy( adsl_wtic_w2, adsl_wtic_w1, achl_cur - (char *) adsl_wtic_w1 );
#define ACHL_POS_G1 (achl_cur + sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length)
       if (ACHL_POS_G1 < achl_end) {
         memcpy( (char *) adsl_wtic_w2 + (achl_cur - (char *) adsl_wtic_w1 ),
                 ACHL_POS_G1,
                 sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length );
       }
       adsl_wtic_w2->imc_len_inetas -= sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;
       adss_wtic_active = adsl_wtic_w2;     /* WSP trace client with INETA control */
       free( adsl_wtic_w1 );                /* free old control area   */
       return;                              /* all done                */
#undef ADSL_WTIA1_G1
     case ied_wawt_trace_new_core:          /* new parameters trace WSP core */
       img_wsp_trace_core_flags1 = adsp_wspadm1_qwt1->imc_trace_level;  /* WSP trace core flags */
       break;
     case ied_wawt_trace_cma_dump:          /* make a dump of the CMA  */
       dss_wsp_trace_thr_ctrl.boc_cma_dump = TRUE;  /* make CMA dump   */
       m_wsp_trace_out( NULL );             /* output of WSP trace record */
       break;
   }
   return;

   p_adm_target_00:                         /* define new target       */
   switch (adsp_wspadm1_qwt1->iec_wtt) {    /* WSP Trace target        */
     case ied_wtt_console:                  /* print on console        */
       if (imp_len_content != 0) break;
       goto p_adm_target_20;                /* parameters for target valid */
     case ied_wtt_file_ascii:               /* trace records to file ASCII */
     case ied_wtt_file_bin:                 /* trace records to file binary */
       if (imp_len_content == 0) break;
       goto p_adm_target_20;                /* parameters for target valid */
     case ied_wtt_xyz:                             /* trace records to xyz    */
       break;
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW WSP Trace administration command target invalid parameters" );
   return;

   p_adm_target_20:                         /* parameters for target valid */
   adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
   memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
   adsl_wt1_w1->iec_wtrt = ied_wtrt_control;  /* control record        */
   adsl_wt1_w1->ilc_epoch = m_get_epoch_ms();  /* time trace record recorded */
   adsl_wt1_w1->imc_wsp_trace_target = (int) adsp_wspadm1_qwt1->iec_wtt;  /* enum ied_wsp_trace_target / Trace target */
   adsl_wt1_w1->imc_len_filename = imp_len_content;  /* length of following flie-name UTF-8 */
   if (imp_len_content) {                   /* copy content            */
     memcpy( adsl_wt1_w1 + 1, adsp_wspadm1_qwt1 + 1, imp_len_content );
   }
   m_wsp_trace_out( adsl_wt1_w1 );          /* output of WSP trace record */
   return;
} /* end m_ctrl_wspadm1_wsp_trace()                                    */

/** Admin get WSP Trace active settings                                */
extern "C" struct dsd_sdh_control_1 * m_get_wspadm1_wsp_tr_act( void ) {
   int        iml1;                         /* working variable        */
   char       *achl_cur;                    /* current INETA pointer   */
   char       *achl_end;                    /* end if INETAs           */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w1;  /* WSP trace client with INETA control */

//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HWSPMXXX1-%05d-T m_get_wspadm1_wsp_tr_act() called",
                   __LINE__ );
//#endif

   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );

#define ADSL_GAI1_G1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))

#define ADSL_WSPADM1_RWTA1 ((struct dsd_wspadm1_r_wsp_tr_act_1 *) ((char *) (ADSL_GAI1_G1 + 1) + 4))

   memset( ADSL_WSPADM1_RWTA1, 0, sizeof(struct dsd_wspadm1_r_wsp_tr_act_1) );
   ADSL_WSPADM1_RWTA1->boc_allow_wsp_trace = adsg_loconf_1_inuse->boc_allow_wsp_trace;  /* configured <allow-wsp-trace> */
   ADSL_WSPADM1_RWTA1->iec_wtt = dss_wsp_trace_thr_ctrl.iec_wtt;  /* WSP Trace target */
   ADSL_WSPADM1_RWTA1->imc_wsp_trace_core_flags1 = img_wsp_trace_core_flags1;  /* WSP trace core flags */
   adsl_wtic_w1 = adss_wtic_active;         /* WSP trace client with INETA control */
   while (adsl_wtic_w1) {                   /* WSP trace client with INETA control set */
     if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS     */
       ADSL_WSPADM1_RWTA1->boc_sess_trace_ineta_all = TRUE;  /* trace all INETAS */
       ADSL_WSPADM1_RWTA1->imc_sess_ia_trace_level = adsl_wtic_w1->imc_trace_level;  /* trace all INETAS trace_level */
       break;
     }
     iml1 = 0;                              /* clear counter           */
     achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs     */
     achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
     while (achl_cur < achl_end) {          /* loop over all INETAs    */
       iml1++;                              /* increment counter       */
       achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
     }
#undef ADSL_WTIA1_G1
     ADSL_WSPADM1_RWTA1->imc_sess_no_single_ineta = iml1;  /* trace started for single INETAs */
     break;
   }
   *((unsigned char *) ADSL_WSPADM1_RWTA1 - 1) = sizeof(struct dsd_wspadm1_r_wsp_tr_act_1);  /* set length */
   ADSL_GAI1_G1->achc_ginp_cur = (char *) ADSL_WSPADM1_RWTA1 - 1;  /* start of data */
   ADSL_GAI1_G1->achc_ginp_end = (char *) (ADSL_WSPADM1_RWTA1 + 1);  /* end of data */
   adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_G1;  /* gather input data */
   return adsl_sdhc1_w1;                    /* return data prepared    */
#undef ADSL_WSPADM1_RWTA1
#undef ADSL_GAI1_G1
} /* end m_get_wspadm1_wsp_tr_act()                                    */
