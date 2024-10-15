#define TRY_150213_01
#ifdef TO_DO_150213
local varible iel_st_ses
set iec_st_ses with iel_st_ses before m_act_thread_2()
#endif
/**
  thread for Pass-thru-to-Desktop (Desktop-on-Demand) to awake the PC
  and connect to the PC.
  when HOB-TUN HTCP is used,
  the INETA adsl_ineta_raws_1_w1 is created only once
  and reused over all tries to connect.
*/
#ifndef HL_UNIX
#define DSD_CONN_G class clconn1
#else
#define DSD_CONN_G struct dsd_conn1
#endif
static htfunc1_t m_conn_pttd_thread( void * vpp_thread_arg ) {
   struct dsd_conn_pttd_socket *adsl_cpptd_so;  /* socket for w-on-lan */
   struct sockaddr dsl_soa_wol;             /* broadcast UDP wake-on-l */
   struct sockaddr_in dsl_soa_multih;       /* multih address informat */
   struct sockaddr_storage dsl_soa_desktop;  /* server address informat */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
   DSD_CONN_G *adsl_conn1;                  /* for this connection     */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_pttd_ineta *adsl_pttd_ineta;  /* chain wake-on-lan relays */
//#ifndef HL_UNIX
   struct dsd_extra_thread_entry *adsl_ete_cur;  /* current extra thread entry */
   struct dsd_extra_thread_entry *adsl_ete_last;  /* last extra thread entry */
   HL_LONGLONG ill_time_ended;              /* time / epoch ended in milliseconds */
//#endif
#ifdef D_INCL_HOB_TUN
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* INETA in use     */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension field */
#ifdef D_INCL_HOB_TUN
   enum ied_ineta_raws_def iel_irs_def;     /* type of INETA raw socket */
#endif
   socklen_t  iml_local_namelen;            /* length of name local    */
#ifdef HL_FREEBSD
   socklen_t  iml_soa_len;                  /* length of struct sockaddr */
#endif
#ifdef D_INCL_HOB_TUN
// to-do 21.09.12 KB - is this variable really needed?
   BOOL       bol_htun_new;                 /* new INETA HOB-TUN HTCP  */
#endif
   BOOL       bol_wait_done;                /* wait for starting thread done */
   BOOL       bolbroadcast;                 /* for setsockopt          */
   dsd_time_1 iml_end_time;                 /* end time allowed        */
   dsd_time_1 iml_conn_time;                /* time connect started    */
   int        iml_rc_sock;                  /* return code socket oper */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* report error            */
   int        iml_desktop_socket;           /* socket of connect       */
   char       byrlsend[ 6 + 6 * 16 ];       /* area for send           */
   int        iml_no_wol;                   /* do wake-on-lan          */
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
#ifdef TRACEHL_WOL2
   int        iml_no_udp_wol;               /* count sent WOL          */
#endif
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
#ifdef D_INCL_HOB_TUN
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
   struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
#endif
#ifndef HL_UNIX
   struct dsd_conn_pttd_ineta {             /* INETA of server = desktop */
     struct dsd_target_ineta_1 dsc_target_ineta_1;  /* definition INETA target */
     struct dsd_ineta_single_1 dsc_ineta_single_1;  /* single INETA target / listen / configured */
     char     chrc_ineta[ 16 ];             /* INETA of target         */
   } dsl_conn_pttd_ineta;
#endif
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
   char       chrl_ineta_target[ LEN_DISP_INETA ];  /* for INETA target */

#define ADSL_CPTTDT ((struct dsd_conn_pttd_thr *) vpp_thread_arg)

#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() started inc_waitconn=%d", ADSL_CPTTDT->inc_waitconn );
#endif
#ifdef TRACEHL_WOL1
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d started time=%d",
                   __LINE__, m_get_time() );
#endif
#ifdef HL_UNIX
#define ADSL_CONN_PTTD_INETA (((struct dsd_netw_post_1 *) ADSL_CPTTDT->dsc_hco_wothr.vprc_aux_area) + 1)
#define ADSL_CPI_TARGET_INETA_1 ((struct dsd_target_ineta_1 *) ADSL_CONN_PTTD_INETA)
#define ADSL_CPI_INETA_SINGLE_1 ((struct dsd_ineta_single_1 *) (ADSL_CPI_TARGET_INETA_1 + 1))
#define CHRC_CPI_INETA ((char *) (ADSL_CPI_INETA_SINGLE_1 + 1))
#endif
   bol_wait_done = FALSE;                   /* wait for starting thread done */
#ifdef D_INCL_HOB_TUN
   adsl_ineta_raws_1_w1 = NULL;             /* auxiliary extension field HOB-TUN */
   bol_htun_new = FALSE;                    /* new INETA HOB-TUN       */
#endif
   adsl_conn1 = ADSL_CPTTDT->adsc_conn1;
   if (adsl_conn1 == NULL) {                /* client has ended        */
     goto pcpttdt88;                        /* all done                */
   }
   adsl_server_conf_1_w1 = adsl_conn1->adsc_server_conf_1;  /* get server configuration */
   /* end time allowed                                                 */
   iml_end_time = m_get_time() + ADSL_CPTTDT->imc_waitconn;
#ifdef D_INCL_HTUN
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
#endif
   memset( &dsl_soa_desktop, 0, sizeof(struct sockaddr_storage) );  /* server address informat */
#ifdef TRACEHL_WOL2
   iml_no_udp_wol = 0;
#endif
   iml_no_wol = 0;                          /* do wake-on-lan          */
   if (ADSL_CPTTDT->boc_with_macaddr == FALSE) {  /* macaddr not incl  */
     goto pcpttdt20;
   }
   iml_no_wol = 2;                          /* do wake-on-lan          */
   /* prepare UDP broadcast packet to send                             */
   memset( byrlsend, 0XFF, 6 );             /* first part              */
   iml1 = 16;
   do {
     memcpy( byrlsend + sizeof(byrlsend) - iml1 * sizeof(ADSL_CPTTDT->chrc_macaddr),
             ADSL_CPTTDT->chrc_macaddr,
             sizeof(ADSL_CPTTDT->chrc_macaddr) );
     iml1--;
   } while (iml1 > 0);
   /* search which socket to use for UDP broadcast                     */
   adsl_cpptd_so = dsg_radius_control.adsc_cpttdso;
   while (adsl_cpptd_so) {                  /* loop over chain         */
     if (adsl_cpptd_so->umc_multih_ineta == ADSL_CPTTDT->umc_out_ineta)
       break;
     adsl_cpptd_so = adsl_cpptd_so->adsc_next;  /* get next in chain   */
   }
   if (adsl_cpptd_so) goto pcpttdt12;       /* entry found             */
   adsl_cpptd_so = (struct dsd_conn_pttd_socket *) malloc( sizeof(struct dsd_conn_pttd_socket) );
   adsl_cpptd_so->umc_multih_ineta = ADSL_CPTTDT->umc_out_ineta;
   adsl_cpptd_so->inc_udp_socket = socket( AF_INET, SOCK_DGRAM, 0 );
   if (adsl_cpptd_so->inc_udp_socket < 0) {
     iml_rc_sock = adsl_cpptd_so->inc_udp_socket;
     m_hlnew_printf( HLOG_WARN1, "HWSPC003W m_conn_pttd_thread() socket UDP failed with code %d %d.",
                     iml_rc_sock, D_TCP_ERROR );
     free( adsl_cpptd_so );
#ifdef XYZ1
     IP_closesocket( iml_desktop_socket );
#endif
     goto pcpttdt80;                        /* all done                */
   }
#ifdef B060518
   if (dsg_radius_control.umc_wol_r_ineta == INADDR_ANY) {  /* default */
   }
#endif
   if (adsg_loconf_1_inuse->adsc_pttd_ineta == NULL) {  /* chain wake-on-lan relays */
     bolbroadcast = TRUE;
     iml_rc_sock = setsockopt( adsl_cpptd_so->inc_udp_socket, SOL_SOCKET, SO_BROADCAST,
                               (const char *) &bolbroadcast, sizeof(bolbroadcast) );
     if (iml_rc_sock < 0) {                 /* function returned error */
       m_hlnew_printf( HLOG_WARN1, "HWSPC004W m_conn_pttd_thread() socket UDP setsockopt() Error %d %d.",
                       iml_rc_sock, D_TCP_ERROR );
     }
   }
#ifndef B120130
   memset( &dsl_soa_multih, 0, sizeof(struct sockaddr_in) );
   dsl_soa_multih.sin_family = AF_INET;
   *((UNSIG_MED *) &dsl_soa_multih.sin_addr) = adsl_cpptd_so->umc_multih_ineta;
#endif

   /* Bind the socket to the server address.                           */
   iml_rc_sock = bind( adsl_cpptd_so->inc_udp_socket,
                       (struct sockaddr *) &dsl_soa_multih, sizeof(dsl_soa_multih) );
   if (iml_rc_sock < 0) {                   /* function returned error */
     m_hlnew_printf( HLOG_WARN1, "HWSPC005W m_conn_pttd_thread() socket UDP bind() Error %d %d.",
                     iml_rc_sock, D_TCP_ERROR );
   }

#ifndef HL_UNIX
//#ifdef B080324
   EnterCriticalSection( &dsg_radius_control.dsc_critsect );
//#endif
#else
   iml_rc = dsg_radius_control.dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#endif
// to-do 26.03.08 KB
   adsl_cpptd_so->adsc_next = dsg_radius_control.adsc_cpttdso;
   dsg_radius_control.adsc_cpttdso = adsl_cpptd_so;  /* set new chain  */
#ifndef HL_UNIX
//#ifdef B080324
   LeaveCriticalSection( &dsg_radius_control.dsc_critsect );
//#endif
// to-do 26.03.08 KB
#else
   iml_rc = dsg_radius_control.dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#endif

   pcpttdt12:                               /* socket for wol found    */
   iml_no_wol--;                            /* count wake-on-lan       */
   adsl_pttd_ineta = adsg_loconf_1_inuse->adsc_pttd_ineta;
#ifdef TRACEHL_WOL1
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d pcpttdt12 iml_no_wol=%d adsl_pttd_ineta=%p",
                   __LINE__, iml_no_wol, adsl_pttd_ineta );
#endif

   pcpttdt14:                               /* send next wake-on-lan relay */
#ifdef TRACEHL_WOL1
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d pcpttdt14 adsl_pttd_ineta=%p time=%d",
                   __LINE__, adsl_pttd_ineta, m_get_time() );
#endif
   /* prepare sockaddr for broadcast                                   */
   memset( (char *) &dsl_soa_wol, 0, sizeof(struct sockaddr) );
   ((struct sockaddr_in *) &dsl_soa_wol)->sin_family = AF_INET;
   ((struct sockaddr_in *) &dsl_soa_wol)->sin_port
     = htons( dsg_radius_control.imc_port_wol );
   ((struct sockaddr_in *) &dsl_soa_wol)->sin_addr.s_addr
      = 0XFFFFFFFF;                         /* set broadcast           */
   if (adsl_pttd_ineta) {                   /* wake-on-lan INETA set   */
     ((struct sockaddr_in *) &dsl_soa_wol)->sin_addr.s_addr
        = *((UNSIG_MED *) adsl_pttd_ineta->chrc_ineta);  /* set wol relay */
     if (adsl_pttd_ineta->inc_port >= 0) {
       ((struct sockaddr_in *) &dsl_soa_wol)->sin_port
         = htons( adsl_pttd_ineta->inc_port );
     }
     adsl_pttd_ineta = adsl_pttd_ineta->adsc_next;  /* set next in chain */
   }
   iml_rc_sock = sendto( adsl_cpptd_so->inc_udp_socket,
                         byrlsend, sizeof(byrlsend),
                         0, &dsl_soa_wol, sizeof(struct sockaddr) );
   if (iml_rc_sock < 0) {
     m_hlnew_printf( HLOG_WARN1, "HWSPCxxxW m_conn_pttd_thread() socket UDP sendto() Error %d.",
                     iml_rc_sock, D_TCP_ERROR );
#ifdef TRACEHL_WOL2
   } else {
     iml_no_udp_wol++;                      /* count sent WOL          */
#endif
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d IP_sendto completed iml_rc_sock=%d socket=%d adsl_pttd_ineta=%p",
                   __LINE__, iml_rc_sock, adsl_cpptd_so->inc_udp_socket, adsl_pttd_ineta );
#endif
#ifdef TRACEHL_WOL1
   m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d IP_sendto completed iml_rc_sock=%d socket=%d adsl_pttd_ineta=%p",
                   __LINE__, iml_rc_sock, adsl_cpptd_so->inc_udp_socket, adsl_pttd_ineta );
#endif
#ifndef TRACEHL_WOL2
   if (adsl_pttd_ineta) goto pcpttdt14;     /* send next wake-on-lan relay */
#else
   if (adsl_pttd_ineta) {
     Sleep( 50 );                           /* wait some time          */
     goto pcpttdt14;                        /* send next wake-on-lan relay */
   }
#endif
   if (dsl_soa_desktop.ss_family) {         /* INETA server = desktop has not been set */
#ifdef D_INCL_HOB_TUN
     if (adsl_ineta_raws_1_w1 == NULL) {    /* auxiliary extension field HTUN */
#ifndef HL_FREEBSD
       goto pcpttdt32;                      /* do connect normal TCP   */
#endif
#ifdef HL_FREEBSD
       goto pcpttdt28;
#endif
     }
     goto pcpttdt24;                        /* do connect over HTCP    */
#else
#ifndef HL_FREEBSD
     goto pcpttdt32;                        /* do connect normal TCP   */
#endif
#ifdef HL_FREEBSD
     goto pcpttdt28;
#endif
#endif
   }

   pcpttdt20:                               /* check if query DNS      */
#ifdef XYZ1
   if (uml_desktop_ineta != 0XFFFFFFFF) {   /* valid IP-addr           */
     goto pcpttdt28;                        /* do connect              */
   }
   iml_conn_time = m_get_time();
#endif
//   adsl_hostentry = IP_gethostbyname( ADSL_CPTTDT->achc_target );
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
   dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
   dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
   adsl_addrinfo_w2 = NULL;
   iml_rc = getaddrinfo( ADSL_CPTTDT->achc_target, NULL, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
#ifdef XYZ1
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     return NULL;                           /* return error            */
   }
#endif
   if (ADSL_CPTTDT->adsc_conn1 == NULL) {   /* client has ended        */
     goto pcpttdt88;                        /* all done                */
   }
   if ((iml_rc) || (adsl_addrinfo_w2 == NULL)) {  /* could not do DNS name resolution */
     if (iml_conn_time > iml_end_time) {
       iml_rc_sock = HL_ERROR_GETHOSTBYNAME;
       goto pcpttdt80;                      /* all done                */
     }
#ifndef HL_UNIX
     Sleep( 5000 );
#else
     sleep( 5 );
#endif
     if (ADSL_CPTTDT->adsc_conn1 == NULL) {  /* client has ended       */
       goto pcpttdt88;                      /* all done                */
     }
     if (iml_no_wol > 0) goto pcpttdt12;
     goto pcpttdt20;
   }
#ifndef HL_UNIX
   memset( &dsl_conn_pttd_ineta, 0, sizeof(dsl_conn_pttd_ineta) );
   dsl_conn_pttd_ineta.dsc_target_ineta_1.imc_no_ineta = 1;  /* number of INETA */
#endif
#ifdef HL_UNIX
   memset( ADSL_CONN_PTTD_INETA, 0, sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) );
   ADSL_CPI_TARGET_INETA_1->imc_no_ineta = 1;  /* number of INETA      */
#endif
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of INETAs     */
   do {
// to-do 10.08.10 KB - check bind and family
     switch (adsl_addrinfo_w2->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (   (adsl_server_conf_1_w1->dsc_bind_out.boc_bind_needed)
             && (adsl_server_conf_1_w1->dsc_bind_out.boc_ipv4 == FALSE)) {  /* IPV4 not supported */
           break;
         }
         memcpy( &dsl_soa_desktop, adsl_addrinfo_w2->ai_addr, sizeof(struct sockaddr_in) );
         ((struct sockaddr_in *) &dsl_soa_desktop)->sin_port = htons( ADSL_CPTTDT->imc_port_target );
#ifndef HL_UNIX
         dsl_conn_pttd_ineta.dsc_ineta_single_1.usc_family = AF_INET;  /* family IPV4 / IPV6 */
         dsl_conn_pttd_ineta.dsc_ineta_single_1.usc_length = 4;  /* length of following address */
         dsl_conn_pttd_ineta.dsc_target_ineta_1.imc_len_mem  /* length of memory including this structure */
           = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 4;
         memcpy( dsl_conn_pttd_ineta.chrc_ineta,
                 &(((struct sockaddr_in *) &dsl_soa_desktop)->sin_addr),
                 4 );
#endif
#ifdef HL_UNIX
         ADSL_CPI_INETA_SINGLE_1->usc_family = AF_INET;  /* family IPV4 / IPV6 */
         ADSL_CPI_INETA_SINGLE_1->usc_length = 4;  /* length of following address */
         ADSL_CPI_TARGET_INETA_1->imc_len_mem  /* length of memory including this structure */
           = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 4;
         memcpy( CHRC_CPI_INETA,
                 &(((struct sockaddr_in *) &dsl_soa_desktop)->sin_addr),
                 4 );
#endif
#ifdef D_INCL_HOB_TUN
         iel_irs_def = ied_ineta_raws_user_ipv4;  /* INETA user IPV4   */
#endif
         break;
       case AF_INET6:                       /* IPV6                    */
         if (   (adsl_server_conf_1_w1->dsc_bind_out.boc_bind_needed)
             && (adsl_server_conf_1_w1->dsc_bind_out.boc_ipv6 == FALSE)) {  /* IPV6 not supported */
           break;
         }
         memcpy( &dsl_soa_desktop, adsl_addrinfo_w2->ai_addr, sizeof(struct sockaddr_in6) );
         ((struct sockaddr_in6 *) &dsl_soa_desktop)->sin6_port = htons( ADSL_CPTTDT->imc_port_target );
#ifndef HL_UNIX
         dsl_conn_pttd_ineta.dsc_ineta_single_1.usc_family = AF_INET6;  /* family IPV4 / IPV6 */
         dsl_conn_pttd_ineta.dsc_ineta_single_1.usc_length = 16;  /* length of following address */
         dsl_conn_pttd_ineta.dsc_target_ineta_1.imc_len_mem  /* length of memory including this structure */
           = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 16;
         memcpy( dsl_conn_pttd_ineta.chrc_ineta,
                 &(((struct sockaddr_in6 *) &dsl_soa_desktop)->sin6_addr),
                 16 );
#endif
#ifdef HL_UNIX
         ADSL_CPI_INETA_SINGLE_1->usc_family = AF_INET6;  /* family IPV4 / IPV6 */
         ADSL_CPI_INETA_SINGLE_1->usc_length = 16;  /* length of following address */
         ADSL_CPI_TARGET_INETA_1->imc_len_mem  /* length of memory including this structure */
           = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1) + 16;
         memcpy( CHRC_CPI_INETA,
                 &(((struct sockaddr_in6 *) &dsl_soa_desktop)->sin6_addr),
                 16 );
#endif
#ifdef D_INCL_HOB_TUN
         iel_irs_def = ied_ineta_raws_user_ipv6;  /* INETA user IPV6   */
#endif
         break;
     }
     if (dsl_soa_desktop.ss_family) break;  /* INETA server = desktop has been set */
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   } while (adsl_addrinfo_w3);
   freeaddrinfo( adsl_addrinfo_w2 );        /* free addresses again    */
   if (dsl_soa_desktop.ss_family == 0) {    /* INETA server = desktop has not been set */
     m_hlnew_printf( HLOG_WARN1, "HWSPCnnnW GATE=%(ux)s SNO=%08d INETA=%s connect to desktop not possible because target INETA does not correspond to multihomed",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta );
// to-do 10.08.10 KB other error number
     iml_rc_sock = HL_ERROR_GETHOSTBYNAME;
     goto pcpttdt80;                        /* all done                */
   }
#ifdef D_INCL_HOB_TUN
   if (adsl_server_conf_1_w1->boc_use_ineta_appl == FALSE) {  /* do not use HTCP */
     goto pcpttdt28;                        /* do not use HTCP         */
   }
   if (adsl_raw_packet_if_conf == NULL) {   /* no configuration raw-packet-interface */
     goto pcpttdt28;                        /* do not use HTCP         */
   }
   if (iel_irs_def != ied_ineta_raws_user_ipv4) {  /* not INETA user IPV4 */
     m_hlnew_printf( HLOG_WARN1, "HWSPCnnnW GATE=%(ux)s SNO=%08d INETA=%s connect to desktop not possible for IPV6 with use-ineta-appl because IPV6 not yet supported",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta );
     goto pcpttdt28;                        /* do not use HTCP         */
   }
   adsl_ineta_raws_1_w1 = adsl_conn1->adsc_ineta_raws_1;  /* auxiliary field for HOB-TUN */
   if (adsl_ineta_raws_1_w1 == NULL) {
     goto pcpttdt22;                        /* get new INETA HOB-TUN   */
   }
#ifdef IS_NOT_NECESSARY_100826
   if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_FREE_R_1) {  /* done HTUN free resources */
     goto pcpttdt23;                        /* with INETA HTUN         */
   }
   iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                     __LINE__, iml_rc, iml_error );
   }
   bol_wait_done = TRUE;                    /* wait for starting thread done */
   ADSL_CPTTDT->dsc_netw_post_1.boc_posted = FALSE;  /* event has not been posted */
   ADSL_CPTTDT->dsc_netw_post_1.imc_select = DEF_NETW_POST_1_HTUN_FREE_R;  /* select the events */
   ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = &ADSL_CPTTDT->dsc_netw_post_1;  /* structure to post from network callback */
   if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_FREE_R_1) {  /* done HTUN free resources */
     ADSL_CPTTDT->dsc_netw_post_1.boc_posted = TRUE;  /* event has been posted */
   }
   while (ADSL_CPTTDT->dsc_netw_post_1.boc_posted == FALSE) {  /* event has not been posted */
     iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                       __LINE__, iml_rc, iml_error );
     }
   }
#endif
   goto pcpttdt23;                          /* with INETA HOB-TUN      */

   pcpttdt22:                               /* get new INETA HOB-TUN   */
   iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                     __LINE__, iml_rc, iml_error );
   }
   bol_wait_done = TRUE;                    /* wait for starting thread done */
   adsl_ineta_raws_1_w1 = m_prepare_htun_ineta_htcp( adsl_conn1,
                                                     &ADSL_CPTTDT->dsc_hco_wothr,
                                                     iel_irs_def );
   if (adsl_ineta_raws_1_w1 == NULL) {      /* auxiliary extension field HTUN */
     m_hlnew_printf( HLOG_XYZ1, "HWSPCnnnW GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta );
     goto pcpttdt28;                        /* do not use HTCP         */
   }
   bol_htun_new = TRUE;                     /* new INETA HOB-TUN       */
//#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (adsl_auxf_1_htun + 1))
   adsl_soa_w1 = (struct sockaddr *) &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta.dsc_soa_local_ipv4;
   iml_local_namelen = sizeof(struct sockaddr_in);
   iml_rc = getnameinfo( adsl_soa_w1, iml_local_namelen,
                         chrl_ineta_local, sizeof(chrl_ineta_local),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                  /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     errno );
     strcpy( chrl_ineta_local, "???" );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                   adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta,
                   chrl_ineta_local, adsl_ineta_raws_1_w1->usc_appl_port );
   adsl_ineta_raws_1_w1->ac_conn1 = adsl_conn1;  /* set connection   */
   memset( &adsl_conn1->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );
   adsl_conn1->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type HTCP */

   pcpttdt23:                               /* with INETA HOB-TUN      */
   if (bol_wait_done == FALSE) {            /* wait for starting thread not yet done */
     iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                       __LINE__, iml_rc, iml_error );
     }
     bol_wait_done = TRUE;                  /* wait for starting thread done */
   }

   pcpttdt24:                               /* do connect over HTCP    */
   iml_conn_time = m_get_time();            /* get current time        */
// to-do 08.08.13 KB
   adsl_ineta_raws_1_w1->imc_state = DEF_STATE_HTUN_NO_FREE_INETA;  /* do not free local INETA */
#define ADSL_NETW_POST_1 ((struct dsd_netw_post_1 *) ADSL_CPTTDT->dsc_hco_wothr.vprc_aux_area)
   ADSL_NETW_POST_1->boc_posted = FALSE;    /* event has not been posted */
   ADSL_NETW_POST_1->imc_select
     = DEF_NETW_POST_1_HTUN_CONN_OK | DEF_NETW_POST_1_HTUN_FREE_R;  /* select the events */
   ADSL_NETW_POST_1->adsc_event = &ADSL_CPTTDT->dsc_hco_wothr.dsc_event;  /* event to be posted */
   adsl_ineta_raws_1_w1->adsc_netw_post_1 = ADSL_NETW_POST_1;  /* structure to post from network callback */
   adsl_conn1->adsc_sdhc1_htun_sch = NULL;  /* no buffers to send      */
   adsl_conn1->imc_send_window = 0;       /* number of bytes to be sent */
   adsl_ineta_raws_1_w1->ac_conn1 = adsl_conn1;   /* set connection    */
   adsl_conn1->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
   memset( &adsl_conn1->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
   adsl_conn1->dsc_tun_contr_conn.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type */
   memset( &dsl_tun_start_htcp, 0, sizeof(struct dsd_tun_start_htcp) );  /* HOB-TUN start interface HTCP */
#ifndef HL_UNIX
   dsl_tun_start_htcp.adsc_server_ineta = &dsl_conn_pttd_ineta.dsc_target_ineta_1;  /* server INETA */
#else
   dsl_tun_start_htcp.adsc_server_ineta = ADSL_CPI_TARGET_INETA_1;  /* server INETA */
#endif
   dsl_tun_start_htcp.imc_server_port = ADSL_CPTTDT->imc_port_target;  /* TCP/IP port connect */
   dsl_tun_start_htcp.imc_tcpc_to_msec = adsl_raw_packet_if_conf->imc_tcpc_to_msec;  /* TCP connect timeout milliseconds */
   if (dsl_tun_start_htcp.imc_tcpc_to_msec == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_to_msec = DEF_HTCP_TCPC_TO_MSEC;  /* TCP connect timeout milliseconds */
   }
   dsl_tun_start_htcp.imc_tcpc_try_no = adsl_raw_packet_if_conf->imc_tcpc_try_no;  /* TCP connect number of try */
   if (dsl_tun_start_htcp.imc_tcpc_try_no == 0) {  /* no value configured */
     dsl_tun_start_htcp.imc_tcpc_try_no = DEF_HTCP_TCPC_TRY_NO;  /* TCP connect number of try */
   }
   dsl_tun_start_htcp.boc_tcp_keepalive = adsg_loconf_1_inuse->boc_tcp_keepalive;  /* TCP KEEPALIVE */
#ifndef HL_UNIX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#else
   adsl_conn1->iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#endif
   adsl_conn1->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN       */
// dsl_tun_start_htcp.boc_connect_round_robin = FALSE;  /* do not connect round-robin */
// dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &adsl_conn1->dsc_htun_h;  /* where to put the handle created */
   dsl_tun_start_htcp.adsc_htun_h = (dsd_htun_h *) &adsl_ineta_raws_1_w1->dsc_htun_h;  /* where to put the handle created */
   adsl_conn1->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
   adsl_conn1->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN       */
   m_hl_lock_inc_1( &adsl_conn1->imc_references );  /* references to this session */
   m_htun_new_sess_htcp( &dsl_tun_start_htcp,
                         &adsl_conn1->dsc_tun_contr_conn,  /* HOB-TUN control area connection */
                         &adsl_ineta_raws_1_w1->dsc_tun_contr_ineta );  /* HOB-TUN control interface for INETA */
   adsl_conn1->dsc_htun_h = adsl_ineta_raws_1_w1->dsc_htun_h;  /* handle created */
#ifdef TRACEHL1
#ifndef HL_UNIX
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_conn_pttd_thread() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, adsl_ineta_raws_1_w1->dsc_htun_h, &adsl_ineta_raws_1_w1->dsc_tun_contr1 );
#endif
#endif
   while (ADSL_NETW_POST_1->boc_posted == FALSE) {  /* event has not been posted */
     iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                       __LINE__, iml_rc, iml_error );
     }
   }
#undef ADSL_NETW_POST_1
   adsl_ineta_raws_1_w1->adsc_netw_post_1 = NULL;  /* no more structure to post from network callback */
   if (ADSL_CPTTDT->adsc_conn1 == NULL) {   /* client has ended        */
     goto pcpttdt60;                        /* end for HOB-TUN without success */
   }
   if ((adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_CONN_OK) == 0) {  /* not done HOB-TUN connect ok */
     if (iml_conn_time > iml_end_time) {
// to-do 10.08.10 KB other error number
       iml_rc_sock = HL_ERROR_GETHOSTBYNAME;
//     goto pcpttdt60;                      /* end for HTUN without success */
       goto pcpttdt80;                      /* all done                */
     }
#ifndef HL_UNIX
     iml1 = 2000 - (m_get_time() - iml_conn_time) * 1000;  /* compute time to wait */
#else
     iml1 = 2 - (m_get_time() - iml_conn_time);  /* compute time to wait */
#endif
     if (iml1 > 0) {                        /* wait some time          */
#ifndef HL_UNIX
       Sleep( iml1 );
#else
       sleep( iml1 );
#endif
       if (ADSL_CPTTDT->adsc_conn1 == NULL) {  /* client has ended     */
         goto pcpttdt60;                    /* end for HOB-TUN without success */
       }
     }
     if (iml_no_wol > 0) goto pcpttdt12;    /* send WOL packet again   */
     goto pcpttdt24;                        /* do connect over HTCP    */
   }
   iml_rc_sock = 0;                         /* does not return error   */
   goto pcpttdt40;                          /* connect has succeeded   */
//#undef ADSL_INETA_RAWS_1_G
#endif

   pcpttdt28:                               /* do not use HOB-TUN HTCP */
   iml_desktop_socket = socket( dsl_soa_desktop.ss_family, SOCK_STREAM, 0 );
   if (iml_desktop_socket < 0) {            /* socket() failed         */
     iml_rc_sock = iml_desktop_socket;
     m_hlnew_printf( HLOG_WARN1, "HWSPC001W m_conn_pttd_thread() socket TCP failed with code %d %d.",
                     iml_rc_sock, D_TCP_ERROR );
     goto pcpttdt80;                        /* all done                */
   }
   if (adsl_server_conf_1_w1->dsc_bind_out.boc_bind_needed) {
     switch (dsl_soa_desktop.ss_family) {
       case AF_INET:                        /* IPV4                    */
         adsl_soa_w1 = (struct sockaddr *) &adsl_server_conf_1_w1->dsc_bind_out.dsc_soai4;
         iml_local_namelen = sizeof(struct sockaddr_in);
         break;
       case AF_INET6:                       /* IPV6                    */
         adsl_soa_w1 = (struct sockaddr *) &adsl_server_conf_1_w1->dsc_bind_out.dsc_soai6;
         iml_local_namelen = sizeof(struct sockaddr_in6);
         break;
     }
     iml_rc_sock = bind( iml_desktop_socket,
                         adsl_soa_w1, iml_local_namelen );
     if (iml_rc_sock < 0) {                 /* function returned error */
       m_hlnew_printf( HLOG_WARN1, "HWSPC002W m_conn_pttd_thread() socket TCP bind() Error %d %d.",
                       iml_rc_sock, D_TCP_ERROR );
       D_TCP_CLOSE( iml_desktop_socket );
       goto pcpttdt80;                      /* all done                */
     }
   }

#ifndef HL_FREEBSD
   pcpttdt32:                               /* do connect normal TCP   */
#endif
   iml_conn_time = m_get_time();            /* get current time        */
#ifndef HL_FREEBSD
   iml_rc_sock = connect( iml_desktop_socket,
                          (struct sockaddr *) &dsl_soa_desktop,
                          sizeof(dsl_soa_desktop) );
#endif
#ifdef HL_FREEBSD
   iml_soa_len = sizeof(struct sockaddr_in);  /* length of struct sockaddr target */
   if (dsl_soa_desktop.ss_family != AF_INET) {  /* is not IPv4         */
     iml_soa_len = sizeof(struct sockaddr_in6);  /* length of struct sockaddr target */
   }
   iml_rc_sock = connect( iml_desktop_socket,
                          (struct sockaddr *) &dsl_soa_desktop,
                          iml_soa_len );
#endif
   if (ADSL_CPTTDT->adsc_conn1 == NULL) {   /* client has ended        */
     D_TCP_CLOSE( iml_desktop_socket );
     goto pcpttdt88;                        /* all done                */
   }
   if (iml_rc_sock != 0) {                  /* connect failed          */
     bol1 = FALSE;                          /* not yet end             */
#ifndef HL_UNIX
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml_rc_sock = cl_tcp_r::afunc_wsaglerr();  /* get error code    */
       if (   (iml_rc_sock != WSAETIMEDOUT)
           && (iml_rc_sock != WSAECONNREFUSED)
           && (   (adsg_loconf_1_inuse->boc_pttd_cehu == FALSE)  /* <ignore-PTTD-connect-error-host-unreachable> */
               || (iml_rc_sock != ERROR_HOST_UNREACHABLE))) {
         bol1 = TRUE;
       }
     }
#else
     if (   (D_TCP_ERROR != ETIMEDOUT)
         && (D_TCP_ERROR != ECONNREFUSED)
         && (   (adsg_loconf_1_inuse->boc_pttd_cehu == FALSE)  /* <ignore-PTTD-connect-error-host-unreachable> */
             || (D_TCP_ERROR != EHOSTUNREACH))) {
       bol1 = TRUE;
     }
#endif
#ifdef HL_FREEBSD
     D_TCP_CLOSE( iml_desktop_socket );
#endif
     if (iml_conn_time > iml_end_time) bol1 = TRUE;
     if (bol1) {                            /* do not continue         */
#ifndef HL_FREEBSD
       D_TCP_CLOSE( iml_desktop_socket );
#endif
       goto pcpttdt80;                      /* all done                */
     }
#ifdef B120913
     iml1 = 2000 - (m_get_time() - iml_conn_time);  /* compute time to wait */
#else
#ifndef HL_UNIX
     iml1 = 2000 - (m_get_time() - iml_conn_time) * 1000;  /* compute time to wait */
#else
     iml1 = 2 - (m_get_time() - iml_conn_time);  /* compute time to wait */
#endif
#endif
     if (iml1 > 0) {                        /* wait some time          */
#ifndef HL_UNIX
       Sleep( iml1 );
#else
       sleep( iml1 );
#endif
       if (ADSL_CPTTDT->adsc_conn1 == NULL) {  /* client has ended     */
#ifndef HL_FREEBSD
         D_TCP_CLOSE( iml_desktop_socket );
#endif
         goto pcpttdt88;                    /* all done                */
       }
     }
     if (iml_no_wol > 0) goto pcpttdt12;
#ifndef HL_FREEBSD
     goto pcpttdt32;
#endif
#ifdef HL_FREEBSD
     goto pcpttdt28;
#endif
   }
   /* connect completed successfully                                   */
   adsl_conn1->iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP */
#ifndef HL_UNIX
   adsl_conn1->dcl_tcp_r_s.start1( adsl_conn1,
                                   (struct sockaddr *) &dsl_soa_desktop, sizeof(dsl_soa_desktop),
                                   iml_desktop_socket );
#else
#ifndef B130312
   memset( &adsl_conn1->dsc_tc1_server, 0, sizeof(struct dsd_tcp_ctrl_1) );  /* TCP control structure server */
#endif
#ifndef B150213
   memcpy( &adsl_conn1->dsc_tc1_server.dsc_soa_conn,  /* address information of connection */
           &dsl_soa_desktop,
           sizeof(dsl_soa_desktop) );
#endif
#endif
// adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* start connection to server part one */
#ifdef B101125
   adsl_conn1->iec_st_ses = clconn1::ied_ses_compl_cpttdt;  /* connect pass thru to desktop completed */
#endif
#ifndef TRY_150213_01
#ifndef HL_UNIX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* start connection to server part one */
#else
   adsl_conn1->iec_st_ses = ied_ses_start_server_1;  /* start connection to server part one */
#endif
#endif

   pcpttdt40:                               /* connect has succeeded   */
#ifndef HL_FREEBSD
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_desktop, sizeof(struct sockaddr_storage),
                         chrl_ineta_target, sizeof(chrl_ineta_target),
                         0, 0, NI_NUMERICHOST );
#endif
#ifdef HL_FREEBSD
   iml_soa_len = sizeof(struct sockaddr_in);  /* length of struct sockaddr target */
   if (dsl_soa_desktop.ss_family != AF_INET) {  /* is not IPv4         */
     iml_soa_len = sizeof(struct sockaddr_in6);  /* length of struct sockaddr target */
   }
   iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_desktop, iml_soa_len,
                         chrl_ineta_target, sizeof(chrl_ineta_target),
                         0, 0, NI_NUMERICHOST );
#endif
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPCxxxxxW GATE=%(ux)s SNO=%08d INETA=%s conn_pttd l%05d getnameinfo() returned %d %d.",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     __LINE__,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta_target, "???" );
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPC010I GATE=%(ux)s SNO=%08d INETA=%s connect to desktop %s successful",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   chrl_ineta_target );
#ifdef D_INCL_HOB_TUN
   if (adsl_conn1->iec_servcotype != ied_servcotype_normal_tcp) {  /* not normal TCP */
     goto pcpttdt80;                        /* all done                */
   }
#endif
#ifndef HL_UNIX
   adsl_conn1->dcl_tcp_r_s.start2();        /* start TCPCOMP           */
   adsl_conn1->dcl_tcp_r_s.start3();        /* receive data now        */
#ifdef D_INCL_HOB_TUN
   goto pcpttdt80;                          /* all done                */
#endif
#else
   adsl_conn1->dsc_tc1_server.boc_connected = TRUE;  /* TCP session is connected */
   iml_rc_sock = adsl_conn1->dsc_tc1_server.dsc_tcpco1_1.m_startco_fb(
                  iml_desktop_socket,
                  &dss_tcpcomp_cb1,
                  adsl_conn1 );
   if (iml_rc_sock != 0) {                  /* error occured           */
     adsl_conn1->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW nbipgw20 l%05d m_startco_mh() failed %d.",
                     __LINE__, iml_rc_sock );
     goto pcpttdt80;                        /* all done                */
   }
   adsl_conn1->dsc_tc1_server.dsc_tcpco1_1.m_recv();  /* receive data now */
// to-do 13.02.12 KB start
#ifdef D_INCL_HOB_TUN
   goto pcpttdt80;                          /* all done                */
#endif
#endif

#ifdef D_INCL_HOB_TUN
   pcpttdt60:                               /* end for HOB-TUN because connection no more available */
   bol1 = TRUE;                             /* do release HOB-TUN resources */
   if (adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_FREE_R_2) {  /* done HOB-TUN free resources */
     bol1 = FALSE;                          /* do not release HTUN resources */
   }
   adsl_ineta_raws_1_w1->ac_conn1 = NULL;   /* no more connection      */
   if (   (adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_CONN_OK)  /* done HOB-TUN connect ok */
       && (bol1)) {                         /* do release HTUN resources */
#ifndef NEW_HOB_TUN_1103
     m_htun_sess_close( adsl_ineta_raws_1_w1->dsc_htun_h );
#else
     m_htun_sess_close( adsl_conn1->dsc_htun_h );
#endif
     bol1 = FALSE;                          /* do not release HTUN resources */
   }
   if (adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_FREE_R_2) {  /* done HOB-TUN free resources */
     bol1 = FALSE;                          /* do not release HOB-TUN resources */
   }
   if (bol1) {                              /* do release HOB-TUN resources */
     m_cleanup_htun_ineta( adsl_ineta_raws_1_w1 );
     free( adsl_ineta_raws_1_w1 );          /* free the memory         */
   }
   adsl_ineta_raws_1_w1 = NULL;             /* HOB-TUN is no more used */
   if (ADSL_CPTTDT->adsc_conn1 == NULL) {   /* client has ended        */
     goto pcpttdt88;                        /* end of thread           */
   }
#endif

   pcpttdt80:                               /* all done                */
   if (iml_rc_sock) {                       /* with error              */
// to-do 26.08.10 KB - sometimes INETA in message or DNS-name
     m_hlnew_printf( HLOG_WARN1, "HWSPC006W GATE=%(ux)s SNO=%08d INETA=%s connect to desktop failed with code %d.",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, iml_rc_sock );
     /* this server cannot be used                                     */
#ifdef B120121
     if (adsl_conn1->adsc_gate1->ifunction == DEF_FUNC_SS5H) {
       adsl_conn1->adsc_server_conf_1 = NULL;
     }
#endif
#ifdef B130503
#ifndef B120121
     if (adsl_conn1->adsc_gate1->ifunction == DEF_FUNC_SS5H) {
       if (adsl_conn1->adsc_server_conf_1) {
         if (adsl_conn1->adsc_server_conf_1->inc_no_sdh >= 2) {
           free( adsl_conn1->adsrc_sdh_s_1 );
         }
         adsl_conn1->adsc_server_conf_1 = NULL;
       }
     }
#endif
#endif
/* 28.05.06 KB ??? is this good? */
//   adsl_conn1->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
#ifndef B130502
     if (adsl_conn1->adsc_int_webso_conn_1 == NULL) {  /* not connect for WebSocket applications - internal */
#ifndef B130503
       if (adsl_conn1->adsc_gate1->ifunction == DEF_FUNC_SS5H) {
         if (adsl_conn1->adsc_server_conf_1) {
           if (adsl_conn1->adsc_server_conf_1->inc_no_sdh >= 2) {
             free( adsl_conn1->adsrc_sdh_s_1 );
           }
           adsl_conn1->adsc_server_conf_1 = NULL;
         }
       }
#endif
#ifndef HL_UNIX
       adsl_conn1->iec_st_ses = clconn1::ied_ses_auth;  /* status authentication */
#else
       adsl_conn1->iec_st_ses = ied_ses_auth;  /* status authentication */
#endif
     }
#endif
   }
#ifdef TRACEHL_WOL2
   m_hlnew_printf( HLOG_TRACE1, "HWSPC006T GATE=%(ux)s SNO=%08d INETA=%s connect to desktop WOL packets sent %d.",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   iml_no_udp_wol );        /* count sent WOL          */
#endif
#ifdef D_INCL_HOB_TUN
   while (adsl_ineta_raws_1_w1) {           /* HOB-TUN is used         */
     if (   (iml_rc_sock)
         || (adsl_conn1->iec_servcotype != ied_servcotype_normal_tcp)) {  /* not normal TCP */
       if (bol_htun_new == FALSE) break;    /* not new INETA HOB-TUN   */
       adsl_conn1->adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
       break;
     }
     /* we need to free the local INETA created                        */
     adsl_conn1->adsc_ineta_raws_1 = NULL;    /* auxiliary field for HOB-TUN */
     m_cleanup_htun_ineta( adsl_ineta_raws_1_w1 );
     free( adsl_ineta_raws_1_w1 );          /* free the memory         */
     break;
   }
#endif
#ifdef OLD_1112
   if (adsl_conn1->adsc_radqu) {            /* radius still active     */
     adsl_conn1->adsc_radqu->imc_connect_error = iml_rc_sock;
     adsl_conn1->adsc_radqu->boc_did_connect = TRUE;  /* did connect */
   }
#endif
#ifndef OLD_1112
   if (adsl_conn1->adsc_wsp_auth_1) {       /* authentication active   */
     adsl_conn1->adsc_wsp_auth_1->imc_connect_error = iml_rc_sock;
     adsl_conn1->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   }
#endif
#ifdef TRY_150213_01
#ifndef HL_UNIX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* start connection to server part one */
#else
   adsl_conn1->iec_st_ses = ied_ses_start_server_1;  /* start connection to server part one */
#endif
#endif
#ifndef B140214
   if (adsl_conn1->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
#ifdef DEBUG_150220_01                      /* Dod connect too earl    */
     m_hlnew_printf( HLOG_TRACE1, "DEBUG_150220_01 l%05d m_conn_pttd_thread()", __LINE__ );
#endif
     adsl_conn1->adsc_int_webso_conn_1->imc_connect_error = iml_rc_sock;
     adsl_conn1->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify WebSocket routine */
     adsl_conn1->boc_signal_set = TRUE;     /* signal for component set */
#ifndef HL_UNIX
     adsl_conn1->iec_st_ses = clconn1::ied_ses_conn;  /* server is connected */
#else
     adsl_conn1->iec_st_ses = ied_ses_conn;  /* server is connected    */
#endif
   }
#endif
   m_clconn1_naeg1( adsl_conn1 );           /* check naegle            */
   adsl_conn1->adsc_cpttdt = NULL;          /* connect no more active  */
   bol1 = FALSE;                            /* do not activate thread  */
#ifndef HL_UNIX
   EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   iml_rc = adsl_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_enter() critical section failed %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#endif
   if (adsl_conn1->boc_st_act == FALSE) {   /* util-thread not active  */
     adsl_conn1->boc_st_act = TRUE;         /* util-thread active now  */
     bol1 = TRUE;                           /* activate thread         */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   iml_rc = adsl_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
   if (iml_rc < 0) {                        /* error occured           */
// to-do 09.08.11 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d m_leave() critical section failed %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, __LINE__, iml_rc );
   }
#endif
   if (bol1) {
     m_act_thread_2( adsl_conn1 );        /* activate m_proc_data()  */
   }

   pcpttdt88:                               /* end of thread           */
//#ifndef HL_UNIX
   ill_time_ended = m_get_epoch_ms();       /* time / epoch ended in milliseconds */
   ill_time_ended -= ADSL_CPTTDT->dsc_ete.ilc_time_started_ms;
   dss_critsect_aux.m_enter();              /* critical section        */
   adsl_ete_cur = dss_ets_pttd.adsc_ete_ch;  /* get old chain extra thread entries */
   adsl_ete_last = NULL;                    /* clear last extra thread entry */
   while (adsl_ete_cur) {                   /* loop over extra thread entries */
     if (adsl_ete_cur == &ADSL_CPTTDT->dsc_ete) {  /* found in chain extra thread entries */
       break;
     }
     adsl_ete_last = adsl_ete_cur;          /* set last extra thread entry */
     adsl_ete_cur = adsl_ete_cur->adsc_next;  /* get next in chain     */
   }
   if (adsl_ete_cur) {                      /* extra thread entry found */
     if (adsl_ete_last == NULL) {           /* at anchor of chain extra thread entries */
       dss_ets_pttd.adsc_ete_ch = adsl_ete_cur->adsc_next;  /* remove from chain */
     } else {                               /* middle in chain extra thread entries */
       adsl_ete_last->adsc_next = adsl_ete_cur->adsc_next;  /* remove from chain */
     }
   }
   dss_ets_pttd.imc_no_current--;             /* number of instances currently executing */
   dss_ets_pttd.ilc_sum_time_ms += ill_time_ended;  /* summary time executed in milliseconds */
   dss_critsect_aux.m_leave();              /* critical section        */
   if (adsl_ete_cur == NULL) {              /* extra thread entry not found */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW m_conn_pttd_thread() l%05d did not find entry in chain of extra thread entries %p.",
                     __LINE__, &ADSL_CPTTDT->dsc_ete );
   }
//#endif
   if (bol_wait_done == FALSE) {            /* wait for starting thread not yet done */
     iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_wait( &iml_error );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Wait conn_pttd Error %d/%d.",
                       __LINE__, iml_rc, iml_error );
     }
   }
   iml_rc = ADSL_CPTTDT->dsc_hco_wothr.dsc_event.m_close( &iml_error );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "m_conn_pttd_thread() l%05d Event Close conn_pttd Error %d/%d.",
                     __LINE__, iml_rc, iml_error );
   }
   free( ADSL_CPTTDT );
#ifdef OLD01
   return;
#endif
   return 0;
#undef ADSL_CPTTDT
} /* end m_conn_pttd_thread()                                          */
#undef DSD_CONN_G
#ifdef HL_UNIX
#undef ADSL_CONN_PTTD_INETA
#undef ADSL_CPI_TARGET_INETA_1
#undef ADSL_CPI_INETA_SINGLE_1
#undef CHRC_CPI_INETA
#endif
