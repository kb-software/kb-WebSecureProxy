#ifdef D_INCL_HOB_TUN
//#define FOR_CTRL_MAKE
#ifdef FOR_CTRL_MAKE
#define HL_UNIX
#define HL_LINUX
//#define HL_FREEBSD
#endif
#ifndef HL_UNIX
#ifdef B130813
/** start HOB-TUN interface                                            */
static void m_gw_start_htun( struct dsd_raw_packet_if_conf *adsp_rpi_conf ) {
#ifndef HL_UNIX
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_if_arp;                   /* interface for ARP found */
   BOOL       bol_if_route;                 /* interface for routes found */
   DWORD      dwl_ret;                      /* return code             */
   DWORD      dwl_ineta;                    /* temporary INETA         */
   unsigned long int uml_ai_buf_len;        /* length of buffer for adapter info */
   DWORD      dwl_index_if;                 /* holds index of compatible IF */
   PIP_ADAPTER_INFO adsl_adap_info_w1;      /* points to first adapter info */
   PIP_ADAPTER_INFO adsl_adap_info_w2;      /* points to first adapter info */
   IP_ADDR_STRING *adsl_ineta_cur;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d IBIPGW08.cpp m_gw_start_htun( 0X%p ) called",
                   __LINE__, adsp_rpi_conf );
#endif
   if (adsp_rpi_conf == NULL) return;
   bol_rc = m_htun_start( adsp_rpi_conf );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_start() returned %d.",
                   __LINE__, bol_rc );
#endif
   Sleep( 5000 );                           /* wait till Windows has created the TUN adapter */
   bol_if_arp = FALSE;                      /* interface for ARP found */
   bol_if_route = FALSE;                    /* interface for routes found */
   uml_ai_buf_len = 0;                      /* length of buffer for adapter info */
   adsl_adap_info_w1 = NULL;                /* points to first adapter info */
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_BUFFER_OVERFLOW) {
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w1 = (PIP_ADAPTER_INFO) malloc( uml_ai_buf_len );
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_SUCCESS) {
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w2 = adsl_adap_info_w1;
   while (adsl_adap_info_w2) {
     adsl_ineta_cur = &(adsl_adap_info_w2->IpAddressList);
     /* check all addresses                                            */
     while (adsl_ineta_cur) {
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                       __LINE__,
                       adsl_ineta_cur->IpAddress.String,
                       adsl_adap_info_w2->Index,
                       inet_addr( adsl_ineta_cur->IpAddress.String ) );
#endif
       dwl_ineta = inet_addr( adsl_ineta_cur->IpAddress.String);  /* temporary INETA */
       if (dwl_ineta == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_taif_ineta)) {  /* <TUN-adapter-use-interface-ineta> */
         dss_ser_thr_ctrl.umc_index_if_arp = adsl_adap_info_w2->Index;  /* holds index of compatible IF for ARP */
#ifndef B140131
         if (adsl_ineta_cur->Address) {
           memcpy( dss_tun_ctrl.chrc_nic_macaddr, adsl_ineta_cur->Address, sizeof(dss_tun_ctrl.chrc_nic_macaddr) );  /* macaddr NIC */
           dss_tun_ctrl.boc_with_nic_macaddr = TRUE;  /* macaddr NIC is included */
         }
#endif
         bol_if_arp = TRUE;                 /* interface for ARP found */
         if (bol_if_route) break;           /* interface for routes found */
       }
       if (dwl_ineta == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_ta_ineta_local)) {  /* <TUN-adapter-ineta> */
         dss_ser_thr_ctrl.umc_index_if_route = adsl_adap_info_w2->Index;  /* holds index of compatible IF for routes */
         bol_if_route = TRUE;               /* interface for routes found */
         if (bol_if_arp) break;             /* interface for ARP found */
       }
       adsl_ineta_cur = adsl_ineta_cur->Next;
     }
     if (adsl_ineta_cur) break;
     /* move to next interface                                         */
     adsl_adap_info_w2 = adsl_adap_info_w2->Next;
   }
   free( adsl_adap_info_w1 );
#ifdef B100806
   if (adsl_adap_info_w2 == NULL) {         /* adapter not found       */
// 31.07.10 KB error message
   }
#endif
   if (bol_if_arp == FALSE) {               /* interface for ARP found */
     m_hlnew_printf( HLOG_WARN1, "ibipgw24-l%05d-W m_gw_start_htun() no interface for ARP found",
                     __LINE__ );
   }
   if (bol_if_route == FALSE) {             /* interface for routes found */
     m_hlnew_printf( HLOG_WARN1, "ibipgw24-l%05d-W m_gw_start_htun() no interface for routes found",
                     __LINE__ );
   }
} /* end m_gw_start_htun()                                             */
#endif
#endif
#endif
#ifdef HL_UNIX
/** start HOB-TUN interface                                            */
static void m_gw_start_htun( struct dsd_raw_packet_if_conf *adsp_rpi_conf ) {
#define TRY_130109_01
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml_fd;                       /* file dexcriptor         */
   int        iml1;                         /* working variable        */
#ifdef HL_FREEBSD
   char       *achl_w1;                     /* working variable        */
#endif
   time_t     dsl_time_1;                   /* for time                */
   enum ied_ret_main_poll iel_rmp;          /* return from main poll   */
//#ifdef B160502
   struct ifreq dsl_ifreq;                  /* interface request       */
//#endif
#ifdef XYZ1
#ifdef HL_LINUX
#ifndef B160502
   struct ifreq dsl_ifreq;                  /* interface request       */
#endif
#endif
#endif
#ifdef HL_FREEBSD
#ifndef B160502
   struct in_aliasreq dsl_alreq;            /* interface request       */
#endif
   size_t     iml_size_t;
   int        iml_ip_forward;
   int        imrl_mib[ 4 ];
#endif
#ifdef XYZ1
   struct msghdr dsl_msghdr;                /* message structure       */
#endif
#ifdef TRY_130109_01
   char       chrl_liface[ IFNAMSIZ ];      /* name of logical interface */
#ifdef HL_LINUX
   struct sockaddr dsl_lhwaddr;             /* logical interface mac addr */
#endif
#endif
#ifdef HL_LINUX
   char       byrl_work1[ 16 ];             /* working area            */
#endif
#ifdef HL_FREEBSD
#ifdef B150910
   char       chrl_riface[ IFNAMSIZ ];      /* name of real interface  */
#endif
   char       byrl_work1[ 64 ];             /* working area            */
#endif

   memset( &dsg_tun_ctrl, 0, sizeof(struct dsd_tun_ctrl) );  /* HOB-TUN control area */
#ifdef HL_FREEBSD
   dsg_tun_ctrl.imc_bpf_fd = -1;            /* file-descriptor for bpf - Berkeley Packet Filter */
#endif
   if (adsp_rpi_conf == NULL) return;
#ifdef HL_LINUX
   do {                                     /* check IP forwarding     */
     iml_fd = open( D_FN_IP_FORW, O_RDONLY );
     if (iml_fd < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s open error %d.",
                       __LINE__, D_FN_IP_FORW, errno );
       break;
     }
     iml_rc = read( iml_fd, byrl_work1, sizeof(byrl_work1) );
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s read error %d.",
                       __LINE__, D_FN_IP_FORW, errno );
       close( iml_fd );
       break;
     }
#ifdef TRACEHL1
     m_console_out( (char *) byrl_work1, iml_rc );
#endif
     if (iml_rc != (1 + 1)) {
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s length read returned %d - not (1 + 1) as expected",
                       __LINE__, D_FN_IP_FORW, iml_rc );
     }
     if ((iml_rc > 1) && (byrl_work1[ iml_rc - 1 ] != CHAR_LF)) {
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s read returned last character 0X%02X - not CHAR_LF as expected",
                       __LINE__, D_FN_IP_FORW, byrl_work1[ iml_rc - 1 ] );
     }
     if (byrl_work1[ 0 ] == '0') {
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d IP forwarding switched off - TUN cannot work",
                       __LINE__ );
     } else if (byrl_work1[ 0 ] != '1') {
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s read returned first character 0X%02X - neither \'0\' nor \'1\' as expected",
                       __LINE__, D_FN_IP_FORW, byrl_work1[ iml_rc - 1 ] );
     }
     iml_rc = close( iml_fd );
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d file IP forwarding %s close error %d.",
                       __LINE__, D_FN_IP_FORW, errno );
     }
   } while (FALSE);
#endif
#ifdef HL_FREEBSD
   imrl_mib[0] = CTL_NET;
// imrl_mib[1] = PF_NET;
   imrl_mib[1] = PF_INET;
   imrl_mib[2] = IPPROTO_IP;
   imrl_mib[3] = IPCTL_FORWARDING;
   iml_ip_forward = 0;

   iml_size_t = sizeof(iml_ip_forward);

   iml_rc = sysctl( imrl_mib, 4, &iml_ip_forward, &iml_size_t, NULL, 0 );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() sysctl() returned %d errno %d iml_ip_forward %d iml_size_t %d.",
                   __LINE__, iml_rc, errno, iml_ip_forward, iml_size_t );
//#endif
   do {                                     /* pseudo-loop             */
     if (iml_rc != 0) {                     /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d sysctl() mib returned %d errno %d.",
                       __LINE__, iml_rc, errno );
       break;
     }
     if (iml_ip_forward == 1) break;
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d IP forwarding switched off - TUN cannot work",
                     __LINE__ );
   } while (FALSE);
#endif
#ifdef HL_LINUX
   if (dss_loconf_1.boc_listen_gw) {        /* no superuser rights     */
     dsg_tun_ctrl.imc_tun_socket            /* socket for HOB-TUN      */
       = socket( AF_INET, SOCK_STREAM, 0 );
     if (dsg_tun_ctrl.imc_tun_socket < 0) {   /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPT010W m_gw_start_htun() l%05d socket( AF_INET , ... ) Return Code %d Error %d.",
                       __LINE__, dsg_tun_ctrl.imc_tun_socket, errno );
     }
   } else {                                 /* do use listen-gateway   */
     dsg_tun_ctrl.imc_tun_socket            /* socket for HOB-TUN      */
       = socket( AF_PACKET, SOCK_RAW, htons( ETH_P_ARP ) );
     if (dsg_tun_ctrl.imc_tun_socket < 0) {   /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPT011W m_gw_start_htun() l%05d socket( AF_PACKET , ... , %d ) Return Code %d Error %d.",
                       __LINE__, ETH_P_ARP, dsg_tun_ctrl.imc_tun_socket, errno );
     }
   }
#endif
#ifdef HL_FREEBSD
   dsg_tun_ctrl.imc_tun_socket              /* socket for HOB-TUN      */
     = socket( AF_INET, SOCK_STREAM, 0 );
   if (dsg_tun_ctrl.imc_tun_socket < 0) {   /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPT012W m_gw_start_htun() l%05d socket( AF_INET , ... ) Return Code %d Error %d.",
                     __LINE__, dsg_tun_ctrl.imc_tun_socket, errno );
   }
   if (dss_loconf_1.boc_listen_gw == FALSE) {  /* with superuser rights */
     dsg_tun_ctrl.imc_route_socket          /* socket for HOB-TUN ARP and route */
       = socket( PF_ROUTE, SOCK_RAW, 0 );
     if (dsg_tun_ctrl.imc_route_socket < 0) {
       m_hlnew_printf( HLOG_WARN1, "HWSPT013W m_gw_start_htun() l%05d socket( PF_ROUTE , ... ) Return Code %d Error %d.",
                       __LINE__, dsg_tun_ctrl.imc_route_socket, errno );
     }
     /* create file-descriptor for bpf - Berkeley Packet Filter        */
     iml1 = 0;
     do {
       sprintf( byrl_work1, "/dev/bpf%d", iml1 );
       dsg_tun_ctrl.imc_bpf_fd = open( byrl_work1, O_RDWR );
       if (dsg_tun_ctrl.imc_bpf_fd >= 0) break;
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() open( %s ) returned errno %d.",
                       __LINE__, byrl_work1, errno );
//#endif
       iml1++;                              /* increment index         */
     } while (iml1 < MAX_TRY_BPF);
     if (dsg_tun_ctrl.imc_bpf_fd < 0) {
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_gw_start_htun() could not open bpf device",
                       __LINE__ );
     }
   }
#endif
   /* prepare GARP packet                                              */
   memset( dss_tun_send_garp.chrc_h_macaddr_destination, 0XFF, sizeof(dss_tun_send_garp.chrc_h_macaddr_destination) );  /* mac address of destination */
   memcpy( dss_tun_send_garp.chrc_const_01,  /* constants              */
           ucrs_tun_send_garp,
           sizeof(dss_tun_send_garp.chrc_const_01) );
   memset( dss_tun_send_garp.chrc_pl_macaddr_target, 0XFF, sizeof(dss_tun_send_garp.chrc_pl_macaddr_target) );  /* Target hardware address (THA) */
#ifdef HL_LINUX
   /* prepare sockaddr                                                 */
   memset( &dss_soa_arp, 0, sizeof(struct sockaddr_ll) );
   dss_soa_arp.sll_family = AF_PACKET;
   dss_soa_arp.sll_protocol = htons( ETH_P_ARP );
   dsg_tun_ctrl.imc_ifindex_nic_ipv4 = -1;
#endif
#ifdef HL_LINUX
   bol_rc = m_htun_search_interface_ipv4( adsp_rpi_conf->umc_taif_ineta_ipv4,  /* <TUN-adapter-use-interface-ineta> */
                                          dsg_tun_ctrl.chrc_riface,
                                          &dsg_tun_ctrl.dsc_rhwaddr,
                                          &dsg_tun_ctrl.imc_ifindex_nic_ipv4 );
#ifndef B150818
#define ADSL_RIFACE_L dsg_tun_ctrl.chrc_riface
#endif
#endif
#ifdef HL_FREEBSD
#ifdef B150818
   bol_rc = m_htun_search_interface_ipv4( adsp_rpi_conf->umc_taif_ineta_ipv4,  /* <TUN-adapter-use-interface-ineta> */
                                          chrl_liface,
                                          &dsg_tun_ctrl.dsc_soa_dl_r );
#endif
#ifndef B150818
   bol_rc = m_htun_search_interface_ipv4( adsp_rpi_conf->umc_taif_ineta_ipv4,  /* <TUN-adapter-use-interface-ineta> */
#ifdef B150910
                                          chrl_riface,
#endif
#ifndef B150910
                                          dsg_tun_ctrl.chrc_riface,
#endif
                                          &dsg_tun_ctrl.dsc_soa_dl_r );
#ifdef B150910
#define ADSL_RIFACE_L chrl_riface
#endif
#ifndef B150910
#define ADSL_RIFACE_L dsg_tun_ctrl.chrc_riface
#endif
#endif
#endif
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_gw_start_htun() did not find interface for <TUN-adapter-use-interface-ineta> %d.%d.%d.%d.",
                     __LINE__,
                     *((unsigned char *) &adsp_rpi_conf->umc_taif_ineta_ipv4 + 0),
                     *((unsigned char *) &adsp_rpi_conf->umc_taif_ineta_ipv4 + 1),
                     *((unsigned char *) &adsp_rpi_conf->umc_taif_ineta_ipv4 + 2),
                     *((unsigned char *) &adsp_rpi_conf->umc_taif_ineta_ipv4 + 3) );
     return;
   }
#ifdef B150818
   m_hlnew_printf( HLOG_INFO1, "HWSPT024I HOB-TUN using real interface \"%s\"",
                   chrl_liface );
#endif
#ifndef B150818
   m_hlnew_printf( HLOG_INFO1, "HWSPT024I HOB-TUN using real interface \"%s\"",
                   ADSL_RIFACE_L );
#undef ADSL_RIFACE_L
#endif
#ifdef HL_FREEBSD
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen-gateway   */
     goto p_start_20;                       /* start TUN adapter with listen-gateway */
   }
#endif
   dsg_tun_ctrl.imc_fd_tun = open( D_DEV_TUN, O_RDWR );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() open( %s , ... ) returned dsg_tun_ctrl.imc_fd_tun=%d errno %d.",
                   __LINE__, D_DEV_TUN, dsg_tun_ctrl.imc_fd_tun, errno );
//#endif
   if (dsg_tun_ctrl.imc_fd_tun < 0) {
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_gw_start_htun() open( %s , ... ) returned dsg_tun_ctrl.imc_fd_tun=%d errno %d.",
                     __LINE__, D_DEV_TUN, dsg_tun_ctrl.imc_fd_tun, errno );
     return;
   }
#ifdef HL_FREEBSD
// iml_rc = ioctl( dsg_tun_ctrl.imc_fd_tun, TUNSLMODE, &ims_true );                //  Equivalent
   iml_rc = ioctl( dsg_tun_ctrl.imc_fd_tun, TUNSLMODE, &ims_zero );                //  Equivalent
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... TUNSLMODE ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_TRACE1, "HWSPT020W ioctl( ... , TUNSLMODE , ... ) returned error %d errno %d.",
                     iml_rc, errno );
     close( dsg_tun_ctrl.imc_fd_tun );
     return;
   }

   iml_rc = ioctl( dsg_tun_ctrl.imc_fd_tun, TUNSIFHEAD, &ims_zero );               //  IFF_NO_PI
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... TUNSIFHEAD ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_TRACE1, "HWSPT021W ioctl( ... , TUNSIFHEAD , ... ) returned error %d errno %d.",
                     iml_rc, errno );
     close( dsg_tun_ctrl.imc_fd_tun );
     return;
   }

   iml_rc = ioctl( dsg_tun_ctrl.imc_fd_tun, FIONBIO, &ims_zero );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... FIONBIO ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_TRACE1, "HWSPT022W ioctl( ... , FIONBIO , ... ) retuned error %d errno %d.",
                     iml_rc, errno );
     close( dsg_tun_ctrl.imc_fd_tun );
     return;
   }
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   achl_w1 = fdevname_r( dsg_tun_ctrl.imc_fd_tun, dsl_ifreq.ifr_name, sizeof(dsl_ifreq.ifr_name) );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() fdevname_r( ... ) returned %p errno %d.",
                   __LINE__, achl_w1, errno );
   if (achl_w1 == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPT023W fdevname of TUN device returned error errno %d.",
                     errno );
     close( dsg_tun_ctrl.imc_fd_tun );
     return;
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPT025I HOB-TUN using tun-device \"%s\"",
                   achl_w1 );
#ifdef XYZ1
   dsg_tun_ctrl.imc_len_tiface = strlen( achl_w1 );  /* length of name tun interface */
   memcpy( dsg_tun_ctrl.chrc_tiface, achl_w1, dsg_tun_ctrl.imc_len_tiface + 1 );
#endif
#endif
#ifdef HL_LINUX
   if (dss_loconf_1.boc_listen_gw) {        /* do use listen-gateway   */
     goto p_start_20;                       /* start TUN adapter with listen-gateway */
   }
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   dsl_ifreq.ifr_flags = IFF_TUN | IFF_NO_PI;
   iml_rc = ioctl( dsg_tun_ctrl.imc_fd_tun, TUNSETIFF, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , TUNSETIFF , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
#endif
#ifdef TRACEHL1
#ifdef B130109
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() SIOCSIFADDR with INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) &adsp_rpi_conf->umc_ta_ineta_local + 0),
                   *((unsigned char *) &adsp_rpi_conf->umc_ta_ineta_local + 1),
                   *((unsigned char *) &adsp_rpi_conf->umc_ta_ineta_local + 2),
                   *((unsigned char *) &adsp_rpi_conf->umc_ta_ineta_local + 3) );
#endif
#endif
#ifdef TRY_130109_01
   iml1 = 0;                                /* clear index             */
   while (iml1 < adsp_rpi_conf->imc_no_ta_ineta_ipv4) {  /* <TUN-adapter-ineta> IPV4 */
     dsg_tun_ctrl.achc_ta_ineta_ipv4        /* entry <TUN-adapter-ineta> IPV4 */
       = &adsp_rpi_conf->achc_ar_ta_ineta_ipv4[ iml1 * 4 ];  /* entry array <TUN-adapter-ineta> IPV4 */
#ifdef HL_LINUX
     bol_rc = m_htun_search_interface_ipv4( *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4),  /* <TUN-adapter-use-interface-ineta> */
                                            chrl_liface,
                                            &dsl_lhwaddr,
                                            NULL );
#endif
#ifdef HL_FREEBSD
     bol_rc = m_htun_search_interface_ipv4( *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4),  /* <TUN-adapter-use-interface-ineta> */
                                            chrl_liface,
                                            NULL );
#endif
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() m_htun_search_interface_ipv4 returned %d INETA %d.%d.%d.%d.",
                     __LINE__,
                     bol_rc,
                     *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                     *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                     *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                     *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
     if (bol_rc == FALSE) break;
     iml1++;                                /* increment               */
   }
   if (iml1 >= adsp_rpi_conf->imc_no_ta_ineta_ipv4) {  /* <TUN-adapter-ineta> IPV4 */
     iml_rc = close( dsg_tun_ctrl.imc_fd_tun );
     if (iml_rc < 0) {                      /* error occured           */
     }
//   return FALSE;
     return;
   }
#endif
#ifndef XYZ1
#ifdef B160502
#define ADSL_SOCKADDR_IFR_ADDR ((struct sockaddr_in *) &dsl_ifreq.ifr_addr)
#endif
#ifdef HL_LINUX
#ifndef B160502
#define ADSL_SOCKADDR_IFR_ADDR ((struct sockaddr_in *) &dsl_ifreq.ifr_addr)
#endif
   ADSL_SOCKADDR_IFR_ADDR->sin_family = AF_INET;
#endif
#ifdef HL_FREEBSD
#ifdef B160502
   ((struct sockaddr *) ADSL_SOCKADDR_IFR_ADDR)->sa_len = sizeof(struct sockaddr_in);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_IFR_ADDR)->sa_family = AF_INET;
#endif
#ifndef B160502
#define ADSL_SOCKADDR_IFR_ADDR ((struct sockaddr_in *) &dsl_ifreq.ifr_addr)
#define ADSL_SOCKADDR_ALR_ADDR ((struct sockaddr_in *) &dsl_alreq.ifra_addr)
#define ADSL_SOCKADDR_ALR_NETM ((struct sockaddr_in *) &dsl_alreq.ifra_mask)
#define ADSL_SOCKADDR_ALR_DST ((struct sockaddr_in *) &dsl_alreq.ifra_broadaddr)
   memset( &dsl_alreq, 0, sizeof(dsl_alreq) );
   memcpy( dsl_alreq.ifra_name, dsl_ifreq.ifr_name, sizeof(dsl_ifreq.ifr_name) );
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_ADDR)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_ADDR)->sa_family = AF_INET;
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_NETM)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_NETM)->sa_family = AF_INET;
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_DST)->sa_len = sizeof(struct sockaddr);  /* total length */
   ((struct sockaddr *) ADSL_SOCKADDR_ALR_DST)->sa_family = AF_INET;
   memcpy( &ADSL_SOCKADDR_ALR_ADDR->sin_addr, dsg_tun_ctrl.achc_ta_ineta_ipv4, sizeof(UNSIG_MED) );  /* <TUN-adapter-ineta> */
   memcpy( &ADSL_SOCKADDR_ALR_NETM->sin_addr, chrs_tun_mask_ipv4, sizeof(UNSIG_MED) );  /* <TUN-adapter-network-mask> */
   //ADSL_SOCKADDR_ALR_DST->sin_addr.s_addr=ADSL_SOCKADDR_ALR_ADDR->sin_addr.s_addr|(~ADSL_SOCKADDR_ALR_NETM->sin_addr.s_addr);
// to-do 06.07.16 KB - why XOR
   ADSL_SOCKADDR_ALR_DST->sin_addr.s_addr
     = ADSL_SOCKADDR_ALR_ADDR->sin_addr.s_addr ^ (~ADSL_SOCKADDR_ALR_NETM->sin_addr.s_addr);
#endif
#endif
   *((UNSIG_MED *) &ADSL_SOCKADDR_IFR_ADDR->sin_addr)
     = *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4);  /* entry <TUN-adapter-ineta> IPV4 */
#undef ADSL_SOCKADDR_IFR_ADDR
#ifdef HL_LINUX
   memcpy( dsg_tun_ctrl.chrc_tiface, dsl_ifreq.ifr_name, IFNAMSIZ );
#ifdef TRACEHL1
   m_console_out( dsg_tun_ctrl.chrc_tiface, IFNAMSIZ );
#endif
#endif
#ifdef HL_FREEBSD
#ifndef B160502
#undef ADSL_SOCKADDR_ALR_ADDR
#undef ADSL_SOCKADDR_ALR_NETM
#undef ADSL_SOCKADDR_ALR_DST
#endif
//#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
//#endif
#endif
#ifdef B160502
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCSIFADDR, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() SIOCSIFADDR with INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
//#endif
#endif
#ifdef HL_LINUX
#ifndef B160502
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCSIFADDR, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() SIOCSIFADDR with INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
#endif
#endif
#ifdef HL_FREEBSD
#ifndef B160502
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCAIFADDR, &dsl_alreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCAIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() SIOCAIFADDR with INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
#endif
//#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
//#endif
#endif
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFFLAGS, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   dsl_ifreq.ifr_flags |= IFF_UP | IFF_RUNNING;
#ifdef HL_FREEBSD
//#ifdef DEBUG_121023_01                      /* debug listen-gateway create socket */
   m_console_out( (char *) &dsl_ifreq, sizeof(dsl_ifreq) );
//#endif
#endif
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCSIFFLAGS, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCSIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
#ifdef HL_FREEBSD
#ifdef XYZ1
   chrl_liface[ 0 ] = 0;                    /* no name yet             */
#endif
   bol_rc = m_htun_search_interface_ipv4( *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4),  /* <TUN-adapter-use-interface-ineta> */
#ifdef B150818
#ifdef B150811
#ifdef XYZ1
                                          chrl_liface,
#endif
                                          NULL,
#endif
#ifndef B150811
#ifdef B150910
                                          chrl_riface,  /* name of real interface  */
#endif
#ifndef B150910
                                          dsg_tun_ctrl.chrc_riface,  /* name of real interface  */
#endif
#endif
#endif
#ifndef B150818
                                          NULL,
#endif
                                          &dsg_tun_ctrl.dsc_soa_dl_t );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() m_htun_search_interface_ipv4 returned %d INETA %d.%d.%d.%d.",
                   __LINE__,
                   bol_rc,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
   m_console_out( (char *) &dsg_tun_ctrl.dsc_soa_dl_t, sizeof(struct sockaddr_dl) );
#ifdef XYZ1
   m_hlnew_printf( HLOG_INFO1, "HWSPT025I HOB-TUN using tun-device \"%s\"",
                   chrl_liface );
#endif
// to-do 18.08.15 KB - move elsewhere
   if (dsg_tun_ctrl.imc_bpf_fd < 0) {       /* no file-descriptor for bpf - Berkeley Packet Filter */
     goto p_start_40;                       /* continue starting TUN adapter */
   }
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
#ifdef B150910
   memcpy( dsl_ifreq.ifr_name, chrl_riface, IFNAMSIZ );
#endif
#ifndef B150910
   memcpy( dsl_ifreq.ifr_name, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );  /* name of real interface */
#endif
   iml_rc = ioctl( dsg_tun_ctrl.imc_bpf_fd, BIOCSETIF, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , BIOCSETIF , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
#endif
#endif
#ifdef XYZ1
#ifdef HL_LINUX
#define IML_USE_FD dsg_tun_ctrl.imc_tun_socket
#else
#define IML_USE_FD dsg_tun_ctrl.imc_tun_socket
#endif
#define ADSL_SOCKADDR_IFR_ADDR ((struct sockaddr_in *) &dsl_ifreq.ifr_addr)
   ADSL_SOCKADDR_IFR_ADDR->sin_family = AF_INET;
#ifdef B130109
   *((UNSIG_MED *) &ADSL_SOCKADDR_IFR_ADDR->sin_addr)
     = adsp_rpi_conf->umc_ta_ineta_local;   /* <TUN-adapter-ineta>     */
#endif
   *((UNSIG_MED *) &ADSL_SOCKADDR_IFR_ADDR->sin_addr)
     = *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4);  /* entry <TUN-adapter-ineta> IPV4 */
#undef ADSL_SOCKADDR_IFR_ADDR
#ifndef B121211
   memcpy( dsg_tun_ctrl.chrc_tiface, dsl_ifreq.ifr_name, IFNAMSIZ );
#endif
   iml_rc = ioctl( IML_USE_FD, SIOCSIFADDR, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCSIFADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() SIOCSIFADDR with INETA %d.%d.%d.%d.",
                   __LINE__,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
#endif
   iml_rc = ioctl( IML_USE_FD, SIOCGIFFLAGS, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCGIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   dsl_ifreq.ifr_flags |= IFF_UP | IFF_RUNNING;
   iml_rc = ioctl( IML_USE_FD, SIOCSIFFLAGS, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() ioctl( ... , SIOCSIFFLAGS , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
#undef IML_USE_FD
#endif
   goto p_start_40;                         /* continue starting TUN adapter */

   p_start_20:                              /* start TUN adapter with listen-gateway */
   time( &dsl_time_1 );                     /* get current time        */
   iel_rmp = m_main_poll( ied_fmp_open_tun, dsl_time_1 + D_WAIT_OPEN_TUN );
#ifdef XYZ1
   switch (iel_rmp) {                       /* check how returned      */
     case ied_rmp_timeout:                  /* timer elapsed           */
       goto p_m_poll_00;                    /* poll for events         */
     case ied_rmp_sig_end:                  /* message signal end      */
       goto p_disp_stat_00;                 /* display statistics now  */
     case ied_rmp_sig_reload:               /* message signal reload configuration */
       goto p_reload_00;                    /* received reload configuration */
     case ied_rmp_sig_check_shu:            /* message signal check shutdown */
       goto p_shutdown_00;                  /* check shutdown of this process */
     default:
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW nbipgw20 l%05d returned from m_main_poll() iel_rmp = %d invalid",
                       __LINE__, iel_rmp );
#ifdef XYZ1
       break;
   }
#endif
#ifdef HL_FREEBSD
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   achl_w1 = fdevname_r( dsg_tun_ctrl.imc_fd_tun, dsl_ifreq.ifr_name, sizeof(dsl_ifreq.ifr_name) );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() fdevname_r( ... ) returned %p errno %d.",
                   __LINE__, achl_w1, errno );
   if (achl_w1 == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPT023W fdevname of TUN device returned error errno %d.",
                     errno );
     close( dsg_tun_ctrl.imc_fd_tun );
     return;
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPT025I HOB-TUN using tun-device \"%s\"",
                   achl_w1 );
   bol_rc = m_htun_search_interface_ipv4( *((UNSIG_MED *) dsg_tun_ctrl.achc_ta_ineta_ipv4),  /* <TUN-adapter-use-interface-ineta> */
                                          NULL,
                                          &dsg_tun_ctrl.dsc_soa_dl_t );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() m_htun_search_interface_ipv4 returned %d INETA %d.%d.%d.%d.",
                   __LINE__,
                   bol_rc,
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 0),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 1),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 2),
                   *((unsigned char *) dsg_tun_ctrl.achc_ta_ineta_ipv4 + 3) );
   m_console_out( (char *) &dsg_tun_ctrl.dsc_soa_dl_t, sizeof(struct sockaddr_dl) );
#endif

   p_start_40:                              /* continue starting TUN adapter */
   /* set TUN-adapter access non-blocking                              */
   iml1 = fcntl( dsg_tun_ctrl.imc_fd_tun, F_GETFL, 0 );
   if (iml1 == -1) iml1 = 0;
   iml_rc = fcntl( dsg_tun_ctrl.imc_fd_tun, F_SETFL, iml1 | O_NONBLOCK );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_gw_start_htun() fcntl( ... , 0X%X ) returned %d errno %d.",
                   __LINE__, iml1 | O_NONBLOCK, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   bol_rc = m_htun_start( adsp_rpi_conf, &dsg_tun_ctrl );
   if (dss_loconf_1.boc_listen_gw) return;  /* do use listen-gateway   */
   iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_create( &iml_error );  /* event for serial thread */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d event serial m_create Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   iml_rc = dss_ser_thr_ctrl.dsc_thread.mc_create( &m_serial_thread, NULL );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d CreateThread Serial Error", __LINE__ );
   }
} /* end m_gw_start_htun()                                             */
#endif

#ifdef HL_UNIX
/** search the TUN interface for IPV4                                  */
#ifdef HL_LINUX
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta, char *achp_if_name,
                                          struct sockaddr *adsp_rhwaddr, int *aimp_ifindex_nic ) {
#ifdef FORKEDIT
}
#endif
#endif
#ifdef HL_FREEBSD
static BOOL m_htun_search_interface_ipv4( UNSIG_MED ump_ineta, char *achp_if_name,
                                          struct sockaddr_dl *adsp_soa_dl ) {
#endif
// int        iml1;                         /* working variable        */
   BOOL       bol_ret;                      /* return of function      */
   int        iml_rc;                       /* return code             */
   BOOL       bol_found_ineta;              /* found INETA             */
   struct ifaddrs *adsl_ifaddrs_all;        /* all interfaces          */
   struct ifaddrs *adsl_ifaddrs_first;      /* first interface with this name */
   struct ifaddrs *adsl_ifaddrs_w1;         /* working variable        */
#ifdef HL_LINUX
// int        iml_socket;                   /* socket for ioctl()      */
#ifndef B150826
   char       *achl_w1;                     /* working variable        */
#endif
   struct ifreq dsl_ifreq;                  /* interface request       */
#endif
#ifdef HL_FREEBSD
   struct sockaddr_dl *adsl_soa_dl;
#endif

   iml_rc = getifaddrs( &adsl_ifaddrs_all );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() getifaddrs() returned %d errno %d.",
                     __LINE__, iml_rc, errno );
     return FALSE;
   }
   bol_ret = FALSE;                         /* return of function      */
   adsl_ifaddrs_w1 = adsl_ifaddrs_all;      /* get all interfaces      */

   p_check_if_00:                           /* check interface new name */
   adsl_ifaddrs_first = adsl_ifaddrs_w1;    /* first interface with this name */
#ifdef HL_FREEBSD
   adsl_soa_dl = NULL;
#endif
   bol_found_ineta = FALSE;                 /* found INETA             */

   p_check_if_20:                           /* check interface same name */
#ifdef HL_FREEBSD
//#ifdef TRACEHL1
   m_console_out( (char *) adsl_ifaddrs_w1, sizeof(struct ifaddrs) );
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ifa_name",
                     __LINE__ );
   m_console_out( adsl_ifaddrs_w1->ifa_name, strlen( adsl_ifaddrs_w1->ifa_name ) );
#endif
#ifdef B150815
#ifdef HL_LINUX
   if (iml_rc < 0) {                        /* error occured           */
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
#endif
#ifdef HL_LINUX_XX
   if ((dsrl_ifreq[ iml1 ].ifr_flags & IFF_UP) == 0) {
     iml1++;                                /* next interface          */
     goto p_check_if_20;                    /* check interface         */
   }
#endif
#endif
#ifdef HL_FREEBSD
//#ifdef TRACEHL1
   if (   (adsl_ifaddrs_w1->ifa_addr)
       && (adsl_ifaddrs_w1->ifa_addr->sa_family == AF_INET)) {
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() addr family AF_INET addr %d.%d.%d.%d.",
                     __LINE__,
                     *((unsigned char *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr + 0),
                     *((unsigned char *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr + 1),
                     *((unsigned char *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr + 2),
                     *((unsigned char *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr + 3) );
   }
#endif
   /* compare interface INETA                                          */
   if (   (adsl_ifaddrs_w1->ifa_addr)
       && (adsl_ifaddrs_w1->ifa_addr->sa_family == AF_INET)
       && (*((UNSIG_MED *) &((struct sockaddr_in *) adsl_ifaddrs_w1->ifa_addr)->sin_addr) == ump_ineta)) {
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() found interface \"%s\" for INETA %d.%d.%d.%d.",
                     __LINE__,
                     adsl_ifaddrs_w1->ifa_name,
                     *((unsigned char *) &ump_ineta + 0),  /* <TUN-adapter-use-interface-ineta> */
                     *((unsigned char *) &ump_ineta + 1),  /* <TUN-adapter-use-interface-ineta> */
                     *((unsigned char *) &ump_ineta + 2),  /* <TUN-adapter-use-interface-ineta> */
                     *((unsigned char *) &ump_ineta + 3) );  /* <TUN-adapter-use-interface-ineta> */
     bol_found_ineta = TRUE;                /* found INETA             */
#ifdef B150826
#ifdef HL_LINUX
     while (aimp_ifindex_nic || adsp_rhwaddr) {  /* pseudo-loop        */
#ifdef XYZ1
       iml_socket = socket( AF_INET, SOCK_STREAM, 0 );
       if (iml_socket < 0) {                /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() socket() returned errno %d.",
                         __LINE__, errno );
         break;
       }
#endif
       while (aimp_ifindex_nic) {           /* pseudo-loop             */
         memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
         strcpy( dsl_ifreq.ifr_name, adsl_ifaddrs_w1->ifa_name );
         iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFINDEX, &dsl_ifreq );
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFINDEX , ... ) returned %d errno %d.",
                         __LINE__, iml_rc, errno );
//#endif
         if (iml_rc < 0) {                  /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() ioctl( ... SIOCGIFINDEX ... ) returned %d errno %d.",
                           __LINE__, iml_rc, errno );
           break;
         }
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ifindex 0X%08X.",
                         __LINE__, dsl_ifreq.ifr_ifindex );
//#endif
         *aimp_ifindex_nic = dsl_ifreq.ifr_ifindex;
         break;
       }
       while (adsp_rhwaddr) {               /* pseudo-loop             */
         memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
         strcpy( dsl_ifreq.ifr_name, adsl_ifaddrs_w1->ifa_name );
         iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFHWADDR, &dsl_ifreq );
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFHWADDR , ... ) returned %d errno %d.",
                         __LINE__, iml_rc, errno );
//#endif
         if (iml_rc < 0) {                  /* error occured           */
           m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() ioctl( ... SIOCGIFHWADDR ... ) returned %d errno %d.",
                           __LINE__, iml_rc, errno );
           break;
         }
         memcpy( adsp_rhwaddr, &dsl_ifreq.ifr_hwaddr, sizeof(struct sockaddr) );
         break;
       }
       break;
     }
#endif
#endif
   }
#ifdef HL_FREEBSD
   if (   (adsl_ifaddrs_w1->ifa_addr)
       && (adsl_ifaddrs_w1->ifa_addr->sa_family == AF_LINK)) {
     adsl_soa_dl = (struct sockaddr_dl *) adsl_ifaddrs_w1->ifa_addr;
   }
#endif

   adsl_ifaddrs_w1 = adsl_ifaddrs_w1->ifa_next;
   if (   (adsl_ifaddrs_w1)
       && (!strcmp( adsl_ifaddrs_w1->ifa_name, adsl_ifaddrs_first->ifa_name ))) {
     goto p_check_if_20;                    /* check interface same name */
   }
   if (bol_found_ineta == FALSE) {          /* found INETA             */
     goto p_check_if_60;                    /* end of check this interface */
   }
   bol_ret = TRUE;                          /* return of function      */
#ifdef B150826
   if (achp_if_name) {
     strcpy( achp_if_name, adsl_ifaddrs_first->ifa_name );
   }
#endif
#ifndef B150826
#ifdef HL_LINUX
   while (adsp_rhwaddr) {                   /* pseudo-loop             */
     memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
     strcpy( dsl_ifreq.ifr_name, adsl_ifaddrs_first->ifa_name );
     iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFHWADDR, &dsl_ifreq );
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFHWADDR , ... ) returned %d errno %d.",
                     __LINE__, iml_rc, errno );
//#endif
     if (iml_rc < 0) {                      /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() ioctl( ... SIOCGIFHWADDR ... ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
       break;
     }
     memcpy( adsp_rhwaddr, &dsl_ifreq.ifr_hwaddr, sizeof(struct sockaddr) );
     break;
   }
   memset( &dsl_ifreq, 0, sizeof(struct ifreq) );  /* interface request */
   strcpy( dsl_ifreq.ifr_name, adsl_ifaddrs_first->ifa_name );
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFINDEX, &dsl_ifreq );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFINDEX , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                  /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() ioctl( ... SIOCGIFINDEX ... ) returned %d errno %d.",
                     __LINE__, iml_rc, errno );
   }
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ifindex 0X%08X.",
                   __LINE__, dsl_ifreq.ifr_ifindex );
//#endif
   if (aimp_ifindex_nic) {
     *aimp_ifindex_nic = dsl_ifreq.ifr_ifindex;
   }
   if (achp_if_name) {
     achl_w1 = if_indextoname( dsl_ifreq.ifr_ifindex, achp_if_name );
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() if_indextoname( ... ) returned %p errno %d.",
                     __LINE__, achl_w1, errno );
//#endif
     if (achl_w1 == NULL) {                 /* returned error          */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() if_indextoname() returned errno %d.",
                     __LINE__, iml_rc, errno );
     }
   }
#endif
#endif
#ifdef HL_FREEBSD
#ifndef B150826
   if (achp_if_name) {
     strcpy( achp_if_name, adsl_ifaddrs_first->ifa_name );
   }
#endif
   if (   (adsp_soa_dl)
       && (adsl_soa_dl)) {
     memcpy( adsp_soa_dl, adsl_soa_dl, sizeof(struct sockaddr_dl) );
   }
#endif
   goto p_check_if_80;                      /* end of check all interface */

   p_check_if_60:                           /* end of check this interface */
   if (adsl_ifaddrs_w1) {                   /* more interfaces to follow */
     goto p_check_if_00;                    /* check interface new name */
   }

   p_check_if_80:                           /* end of check all interface */
   freeifaddrs( adsl_ifaddrs_all );
   return bol_ret;                          /* return of function      */
#ifdef XYZ1
   if (   (achp_if_name == NULL)
       && (aimp_ifindex_nic == NULL)) {
     goto p_check_if_40;                    /* hardware address        */
   }

   /* get ifindex                                                      */
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFINDEX, &dsrl_ifreq[ iml1 ] );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFINDEX , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   if (achp_if_name) {
#ifdef HL_FREEBSD
     achl_w1 = if_indextoname( dsrl_ifreq[ iml1 ].ifr_ifru.ifru_index, achp_if_name );
#else
     achl_w1 = if_indextoname( dsrl_ifreq[ iml1 ].ifr_ifindex, achp_if_name );
#endif
//#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() if_indextoname( ... ) returned %p errno %d.",
                     __LINE__, achl_w1, errno );
//#endif
     if (achl_w1 == NULL) {                 /* returned error          */
       m_hlnew_printf( HLOG_WARN1, "nbipgw20-l%05d-W m_htun_search_interface_ipv4() if_indextoname() returned errno %d.",
                     __LINE__, iml_rc, errno );
     }
   }
   if (aimp_ifindex_nic) {
#ifdef HL_FREEBSD
     *aimp_ifindex_nic = dsrl_ifreq[ iml1 ].ifr_ifru.ifru_index;  /* return number of interface */
#else
     *aimp_ifindex_nic = dsrl_ifreq[ iml1 ].ifr_ifindex;  /* return number of interface */
#endif
   }

   p_check_if_40:                           /* hardware address        */
#ifdef HL_LINUX
   if (adsp_rhwaddr == NULL) return TRUE;
#endif
#ifdef HL_FREEBSD
   if (adsp_soa_dl == NULL) return TRUE;
#endif
#ifdef HL_FREEBSD
   iml_rc = getifaddrs( &adsl_ifap );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() getifaddrs( ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }

#define ADSL_SDL ((struct sockaddr_dl *) adsl_ifap->ifa_addr)
#ifdef XYZ1
   memcpy( adsp_rhwaddr, ((char*) ADSL_SDL) + 9, sizeof(struct sockaddr) );
#endif
   memcpy( adsp_soa_dl, ADSL_SDL, sizeof(struct sockaddr_dl) );
#undef ADSL_SDL
#else
   iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCGIFHWADDR, &dsrl_ifreq[ iml1 ] );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_htun_search_interface_ipv4() ioctl( ... , SIOCGIFHWADDR , ... ) returned %d errno %d.",
                   __LINE__, iml_rc, errno );
//#endif
   if (iml_rc < 0) {                        /* error occured           */
   }
   memcpy( adsp_rhwaddr, &dsrl_ifreq[ iml1 ].ifr_hwaddr, sizeof(struct sockaddr) );
#endif
   return TRUE;
#endif
} /* end m_htun_search_interface_ipv4()                                */
#endif
#endif

#ifdef NEW_HOB_TUN_1103
extern dsd_vnic dsg_vnic;
#endif

/** thread for serializiation                                          */
static htfunc1_t m_serial_thread( void * ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml1;                         /* working variable        */
#ifndef HL_UNIX
   DWORD      dwl_ret;                      /* return code             */
#endif
   char       *achl_w1;                     /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
#ifdef HL_UNIX
// int        iml_kernel_socket;
#ifdef HL_FREEBSD
// char       *achl_w1;                     /* working variable        */
#ifdef XYZ1
   int        iml_fibnum;                   /* which FIB               */
#endif
   struct {
     struct rt_msghdr dsc_m_rtm;
     char     byrc_m_space[512];
   } dsl_m_rtmsg;
#else
   struct arpreq dsl_arpreq;                /* struct for arp requests */
#endif
#ifdef HL_LINUX
   struct rtentry dsl_routereq;             /* struct for route request */
#endif
// struct sockaddr_in dsl_app_ineta_ipv4;   /* application ineta IPV4  */
#endif
   struct dsd_ser_thr_task *adsl_sth_w1;    /* working variable        */
   struct dsd_ser_thr_task dsl_sth_work;    /* work as task for serial thread */
#ifndef HL_UNIX
   MIB_IPFORWARDROW dsl_ipforw_01;          /* to set routes           */
#endif

#ifdef HL_UNIX
#ifdef XYZ1
   iml_kernel_socket = socket( AF_INET, SOCK_STREAM, 0 );
   if (iml_kernel_socket < 0) {             /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "xxxxxxxx-%05d-W m_serial_thread socket() Return Code %d Error %d.",
                     __LINE__, iml_kernel_socket, errno );
   }
#endif
#ifdef XYZ1
#ifdef HL_FREEBSD
   iml_fibnum = -1;                         /* which FIB               */
#endif
#endif
#endif

   p_serial_00:                             /* serialisation start     */
   if (dss_ser_thr_ctrl.adsc_sth_work) {    /* work as task for serial thread */
     goto p_serial_20;                      /* found work to do        */
   }
   iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_wait( &iml_error );
   if (iml_rc == 0) goto p_serial_00;       /* serialisation start     */
// to-do 02.07.10 KB error message
   m_hlnew_printf( HLOG_WARN1, "xxxxxxxx-%05d-W m_serial_thread thread m_wait Return Code %d Error %d.",
                   __LINE__, iml_rc, iml_error );
#ifndef HL_UNIX
   Sleep( 2000 );                           /* wait some time          */
#else
   sleep( 2 );                              /* wait some time          */
#endif
   goto p_serial_00;                        /* serialisation start     */

   p_serial_20:                             /* found work to do        */
   dsg_global_lock.m_enter();               /* enter critical section  */
   adsl_sth_w1 = dss_ser_thr_ctrl.adsc_sth_work;  /* get work as task for serial thread */
   memcpy( &dsl_sth_work, adsl_sth_w1, sizeof(struct dsd_ser_thr_task) );
   dss_ser_thr_ctrl.adsc_sth_work = adsl_sth_w1->adsc_next;  /* remove from chain */
   adsl_sth_w1->adsc_next = dss_ser_thr_ctrl.adsc_sth_free;  /* get old chain free */
   dss_ser_thr_ctrl.adsc_sth_free = adsl_sth_w1;  /* set new chain free */
   dsg_global_lock.m_leave();               /* leave critical section  */
#ifdef DEBUG_HOB_TUN_1407
   goto p_seri_post;                        /* post the waiting thread */
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* generate WSP trace record - HOB-TUN */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNSER1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "serialize thread l%05d processes command",
                     __LINE__ );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
     ADSL_WTR_G2->imc_length = sizeof(dsl_sth_work);  /* length of text / data */
     ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain         */
     memcpy( ADSL_WTR_G2 + 1, &dsl_sth_work, sizeof(dsl_sth_work) );
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   switch (dsl_sth_work.iec_sth) {          /* serial thread task type */
     case ied_sth_route_ipv4_add:           /* add a route IPV4        */
#ifndef HL_UNIX
#ifdef B100731
       dwl_ret = CreateProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                      0XFFFFFFFF,  /* 255.255.255.255  */
                                      dwl_index_if );
#endif
       dwl_ret = CreateProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                      0XFFFFFFFF,  /* 255.255.255.255  */
                                      *((DWORD *) &dsl_sth_work.umc_index_if_arp) );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T CreateProxyArpEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret, dwl_ret );
//#endif
#ifdef NEW_HOB_TUN_1103
       dsg_vnic.m_add_arp_entry((char*)&dsl_sth_work.chrc_ineta, "255.255.255.255");
#endif
//#endif
       memset( &dsl_ipforw_01, 0, sizeof(MIB_IPFORWARDROW) );
       dsl_ipforw_01.dwForwardProto = MIB_IPPROTO_NETMGMT;
       dsl_ipforw_01.dwForwardIfIndex = *((DWORD *) &dsl_sth_work.umc_index_if_route);
       dsl_ipforw_01.dwForwardMetric1 = 100;
       dsl_ipforw_01.dwForwardMetric2 = -1;
       dsl_ipforw_01.dwForwardMetric3 = -1;
       dsl_ipforw_01.dwForwardMetric4 = -1;
       dsl_ipforw_01.dwForwardMetric5 = -1;
       dsl_ipforw_01.dwForwardDest = *((DWORD *) dsl_sth_work.chrc_ineta);
//     dsl_ipforw_01.dwForwardMask = *((DWORD *) ucrs_route_mask);
       dsl_ipforw_01.dwForwardMask = 0XFFFFFFFF;  /* 255.255.255.255   */
#ifndef B130825
       dsl_ipforw_01.dwForwardNextHop = m_get_next_hop();
#endif
#ifdef B100731
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) ucrs_route_next_hop);
#endif
#ifdef B120203
#ifdef B100802
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
#ifdef TRACEHL1
       m_console_out( (char *) &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
#endif
       dwl_ret = CreateIpForwardEntry( &dsl_ipforw_01 );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T CreateIpForwardEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret, dwl_ret );
//#endif
       if (dwl_ret == NO_ERROR) break;
// to-do 05.07.10 KB error message
       break;
#endif
#ifdef HL_UNIX
#ifdef HL_LINUX
       memset( &dsl_arpreq, 0, sizeof(struct arpreq) );  /* struct for arp requests */
#define ADSL_SOCKADDR_ARP ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
       ADSL_SOCKADDR_ARP->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_ARP->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#undef ADSL_SOCKADDR_ARP
       memcpy( &dsl_arpreq.arp_ha, &dsg_tun_ctrl.dsc_rhwaddr, sizeof(struct sockaddr) );
#ifdef HL_FREEBSD
       dsl_arpreq.arp_flags = ATF_PUBL;
#else
       dsl_arpreq.arp_flags = ATF_PUBL | ATF_NETMASK;
       memcpy( dsl_arpreq.arp_dev, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );
#endif
#ifdef B131217
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
       ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_ARP
#endif
#ifndef B131217
#ifdef HL_LINUX
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_netmask)
       ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_NETMASK
#endif
#endif
       iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCSARP, &dsl_arpreq );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T ioctl( ... , SIOCSARP , ... ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPT0nnW m_serial_thread l%05d INETA=%d.%d.%d.%d SIOCSARP returned %d.",
                         __LINE__,
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 0),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 1),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 2),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 3),
                         iml_rc );
       }
       /* set GARP packet                                              */
       memcpy( dss_tun_send_garp.chrc_h_macaddr_source, /* mac address of source */
               &dsg_tun_ctrl.dsc_rhwaddr.sa_data,
               sizeof(dss_tun_send_garp.chrc_h_macaddr_source) );
       memcpy( dss_tun_send_garp.chrc_pl_macaddr_source,  /* Sender hardware address (SHA) */
               &dsg_tun_ctrl.dsc_rhwaddr.sa_data,
               sizeof(dss_tun_send_garp.chrc_pl_macaddr_source) );
       *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_source)  /* Sender protocol address (SPA) */
         = *((UNSIG_MED *) dsl_sth_work.chrc_ineta);
       *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_target)  /* Target protocol address (TPA) */
         = *((UNSIG_MED *) dsl_sth_work.chrc_ineta);
       dss_soa_arp.sll_ifindex = dsg_tun_ctrl.imc_ifindex_nic_ipv4;  /* interface number of NIC IPV4 */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T ied_sth_route_ipv4_add: GARP dss_soa_arp.sll_ifindex=%d.",
                       __LINE__, dss_soa_arp.sll_ifindex );
       m_console_out( (char *) &dss_tun_send_garp, sizeof(dss_tun_send_garp) );
#endif
       iml_rc = sendto( dsg_tun_ctrl.imc_tun_socket,
                        &dss_tun_send_garp, sizeof(dss_tun_send_garp),
                        0,
                        (struct sockaddr *) &dss_soa_arp, sizeof(dss_soa_arp) );
#ifdef TRACEHL1
       iml_error = errno;                   /* error retrieved         */
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T ied_sth_route_ipv4_add: sento( GARP ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
       errno = iml_error;                   /* error retrieved         */
#endif
       if (iml_rc != sizeof(dss_tun_send_garp)) {  /* check if all sent */
         m_hlnew_printf( HLOG_WARN1, "HWSPT0nnW m_serial_thread l%05d INETA=%d.%d.%d.%d sendto() GARP returned %d.",
                         __LINE__,
                         *((UNSIG_MED *) dsl_sth_work.chrc_ineta + 0),
                         *((UNSIG_MED *) dsl_sth_work.chrc_ineta + 1),
                         *((UNSIG_MED *) dsl_sth_work.chrc_ineta + 2),
                         *((UNSIG_MED *) dsl_sth_work.chrc_ineta + 3),
                         iml_rc );
       }
       /* set route                                                        */
#ifdef XYZ1
       memset( &dsl_app_ineta_ipv4, 0, sizeof(struct sockaddr_in) );  /* application ineta IPV4 */
       dsl_app_ineta_ipv4.sin_family = AF_INET;
       *((unsigned int *) &dsl_app_ineta_ipv4.sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
       memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
       dsl_routereq.rt_dst    = *adsp_addr;
       dsl_routereq.rt_metric = 31;
       dsl_routereq.rt_dev    = adsp_tun->chrc_tiface;
#endif
       memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
#define ADSL_SOCKADDR_DST ((struct sockaddr_in *) &dsl_routereq.rt_dst)
       ADSL_SOCKADDR_DST->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#undef ADSL_SOCKADDR_DST
       dsl_routereq.rt_metric = 31;
       dsl_routereq.rt_dev = dsg_tun_ctrl.chrc_tiface;
#ifndef B121211
#define ADSL_RT_MASK ((struct sockaddr_in *) &dsl_routereq.rt_genmask)
       /* set netmask to 255.255.255.255                               */
       ADSL_RT_MASK->sin_family      = AF_INET;
       ADSL_RT_MASK->sin_addr.s_addr = 0XFFFFFFFF;
#undef ADSL_RT_MASK
#endif
       iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCADDRT, &dsl_routereq );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T ioctl( ... , SIOCADDRT , ... ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       if (iml_rc < 0) {                    /* error occured           */
       }
       break;
#endif
#ifdef HL_FREEBSD
       /*
         set ARP entry
         sample: arp -s 172.22.81.221 00:0c:29:d5:a6:27 pub
       */
#define ADSL_RTM_G (&dsl_m_rtmsg.dsc_m_rtm)
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
       memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
       ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;
       ADSL_RTM_G->rtm_version = RTM_VERSION;
       ADSL_RTM_G->rtm_inits = RTV_EXPIRE;
       ADSL_RTM_G->rtm_flags = RTF_LLDATA | RTF_STATIC | RTF_PROTO2;
       ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
       ADSL_RTM_G->rtm_pid = dsg_this_server.imc_pid;  /* set process id */
       ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
       ADSL_RTM_G->rtm_type = RTM_ADD;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
       ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
       ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
       *((unsigned int *) &ADSL_SOA_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
       memcpy( ADSL_SDL_G, &dsg_tun_ctrl.dsc_soa_dl_r, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
       memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
       ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
       *((unsigned int *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

       m_console_out( (char *) &dsl_m_rtmsg,
                      IML_MSG_LEN );
       iml_rc = write( dsg_tun_ctrl.imc_route_socket,
                       (char *) &dsl_m_rtmsg,
                       IML_MSG_LEN );

//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T write() ARP returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       while (TRUE) {
         iml_rc = read( dsg_tun_ctrl.imc_route_socket,
                        (char *) &dsl_m_rtmsg,
                        sizeof(dsl_m_rtmsg) );
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T read() ARP returned %d errno %d.",
                         __LINE__, iml_rc, errno );
//#endif
         if (iml_rc > 0) {
           m_console_out( (char *) &dsl_m_rtmsg, iml_rc );
         }
         if (iml_rc < 0) {
           break;
         }
         if (   (ADSL_RTM_G->rtm_pid == dsg_this_server.imc_pid)  /* compare process id */
             && (ADSL_RTM_G->rtm_seq == IML_MSG_SEQU)) {
           break;
         }
       }
#undef ADSL_SDL_G
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#ifdef XYZ1
       if (iml_fibnum < 0) {                /* which FIB               */
       }
       dsl_routereq.rt_fibnum = iml_fibnum;  /* which FIB              */
#endif
       /*
         send GARP packet
       */
       if (dsg_tun_ctrl.imc_bpf_fd >= 0) {  /* with file-descriptor for bpf - Berkeley Packet Filter */
         /* set GARP packet                                            */
         memcpy( dss_tun_send_garp.chrc_h_macaddr_source, /* mac address of source */
                 LLADDR( &dsg_tun_ctrl.dsc_soa_dl_r ),
                 sizeof(dss_tun_send_garp.chrc_h_macaddr_source) );
         memcpy( dss_tun_send_garp.chrc_pl_macaddr_source,  /* Sender hardware address (SHA) */
                 LLADDR( &dsg_tun_ctrl.dsc_soa_dl_r ),
                 sizeof(dss_tun_send_garp.chrc_pl_macaddr_source) );
         *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_source)  /* Sender protocol address (SPA) */
           = *((UNSIG_MED *) dsl_sth_work.chrc_ineta);
         *((UNSIG_MED *) &dss_tun_send_garp.chrc_pl_ineta_target)  /* Target protocol address (TPA) */
           = *((UNSIG_MED *) dsl_sth_work.chrc_ineta);
//#ifdef TRACEHL1
         m_console_out( (char *) &dss_tun_send_garp, sizeof(struct dsd_tun_send_garp) );
//#endif
         iml_rc = write( dsg_tun_ctrl.imc_bpf_fd, (char *) &dss_tun_send_garp, sizeof(struct dsd_tun_send_garp) );
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T write() GARP returned %d errno %d.",
                         __LINE__, iml_rc, errno );
//#endif
       }
       /*
         set route
         sample: route add -host 172.22.81.221/32 -iface tunX
       */
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
       memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
       ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;  /* to skip over non-understood messages */
       ADSL_RTM_G->rtm_version = RTM_VERSION;
       ADSL_RTM_G->rtm_type = RTM_ADD;      /* message type            */
       ADSL_RTM_G->rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC;
       ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
       ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
       ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
       ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
       *((unsigned int *) &ADSL_SOA_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
       memcpy( ADSL_SDL_G, &dsg_tun_ctrl.dsc_soa_dl_t, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
       memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
       ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
       *((unsigned int *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

       m_console_out( (char *) &dsl_m_rtmsg, IML_MSG_LEN );
       iml_rc = write( dsg_tun_ctrl.imc_route_socket,
                       (char *) &dsl_m_rtmsg, IML_MSG_LEN );

//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T write() route returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
//#undef ADSL_SOA_GATEWAY
       break;
#undef ADSL_SOA_DST
#undef ADSL_SDL_G
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#undef ADSL_RTM_G
#endif
#endif
     case ied_sth_route_ipv4_del:           /* delete a route IPV4     */
#ifndef HL_UNIX
       dwl_ret = DeleteProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                      0XFFFFFFFF,  /* 255.255.255.255  */
                                      *((DWORD *) &dsl_sth_work.umc_index_if_arp) );
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T DeleteProxyArpEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret, dwl_ret );
#endif
#ifdef B130813
#ifndef NEW_HOB_TUN_1103
       dsg_vnic.m_remove_arp_entry((char*)&dsl_sth_work.chrc_ineta, "255.255.255.255");
#endif
#endif
       memset( &dsl_ipforw_01, 0, sizeof(MIB_IPFORWARDROW) );
       dsl_ipforw_01.dwForwardProto = MIB_IPPROTO_NETMGMT;
       dsl_ipforw_01.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
       dsl_ipforw_01.dwForwardAge = INFINITE;
       dsl_ipforw_01.dwForwardIfIndex = *((DWORD *) &dsl_sth_work.umc_index_if_route);
       dsl_ipforw_01.dwForwardMetric1 = 100;
       dsl_ipforw_01.dwForwardMetric2 = -1;
       dsl_ipforw_01.dwForwardMetric3 = -1;
       dsl_ipforw_01.dwForwardMetric4 = -1;
       dsl_ipforw_01.dwForwardMetric5 = -1;
       dsl_ipforw_01.dwForwardDest = *((DWORD *) dsl_sth_work.chrc_ineta);
//     dsl_ipforw_01.dwForwardMask = *((DWORD *) ucrs_route_mask);
       dsl_ipforw_01.dwForwardMask = 0XFFFFFFFF;  /* 255.255.255.255   */
#ifndef B130825
       dsl_ipforw_01.dwForwardNextHop = m_get_next_hop();
#endif
#ifdef B100731
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) ucrs_route_next_hop);
#endif
#ifdef B100802
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
#ifdef B130911
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
#ifdef TRACEHL1
       m_console_out( (char *) &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
#endif
       dwl_ret = DeleteIpForwardEntry( &dsl_ipforw_01 );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T DeleteIpForwardEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret, dwl_ret );
//#endif
       if (dwl_ret == NO_ERROR) break;
// to-do 08.08.10 KB error message
       break;
#endif
#ifdef HL_UNIX
#ifdef HL_LINUX
       memset( &dsl_arpreq, 0, sizeof(struct arpreq) );  /* struct for arp requests */
#define ADSL_SOCKADDR_ARP ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
       ADSL_SOCKADDR_ARP->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_ARP->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#undef ADSL_SOCKADDR_ARP
       memcpy( &dsl_arpreq.arp_ha, &dsg_tun_ctrl.dsc_rhwaddr, sizeof(struct sockaddr) );
#ifdef HL_FREEBSD
       dsl_arpreq.arp_flags = ATF_PUBL;
#else
       dsl_arpreq.arp_flags = ATF_PUBL | ATF_NETMASK;
#endif
       memcpy( dsl_arpreq.arp_dev, dsg_tun_ctrl.chrc_riface, IFNAMSIZ );
#ifdef B131217
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_pa)
       ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_ARP
#endif
#ifndef B131217
#ifdef HL_LINUX
#define ADSL_SOCKADDR_NETMASK ((struct sockaddr_in *) &dsl_arpreq.arp_netmask)
       ADSL_SOCKADDR_NETMASK->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_NETMASK->sin_addr) = 0XFFFFFFFF;  /* 255.255.255.255 */
#undef ADSL_SOCKADDR_NETMASK
#endif
#endif
       iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCDARP, &dsl_arpreq );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T ioctl( ... , SIOCDARP , ... ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       if (iml_rc < 0) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPT0nnW m_serial_thread l%05d INETA=%d.%d.%d.%d SIOCDARP returned %d.",
                         __LINE__,
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 0),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 1),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 2),
                         *((unsigned int *) dsl_sth_work.chrc_ineta + 3),
                         iml_rc );
       }
       memset( &dsl_routereq, 0, sizeof(struct rtentry) );  /* struct for route request */
#define ADSL_SOCKADDR_DST ((struct sockaddr_in *) &dsl_routereq.rt_dst)
       ADSL_SOCKADDR_DST->sin_family = AF_INET;
       *((unsigned int *) &ADSL_SOCKADDR_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#undef ADSL_SOCKADDR_DST
       dsl_routereq.rt_metric = 31;
       dsl_routereq.rt_dev = dsg_tun_ctrl.chrc_tiface;
#ifndef B121211
#define ADSL_RT_MASK ((struct sockaddr_in *) &dsl_routereq.rt_genmask)
       /* set netmask to 255.255.255.255                               */
       ADSL_RT_MASK->sin_family      = AF_INET;
       ADSL_RT_MASK->sin_addr.s_addr = 0XFFFFFFFF;
#undef ADSL_RT_MASK
#endif
       iml_rc = ioctl( dsg_tun_ctrl.imc_tun_socket, SIOCDELRT, &dsl_routereq );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T ioctl( ... , SIOCDELRT , ... ) returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       if (iml_rc < 0) {                    /* error occured           */
       }
       break;
#endif
#ifdef HL_FREEBSD
       /*
         delete ARP entry
         sample: arp -d 172.22.81.221
       */
#define ADSL_RTM_G (&dsl_m_rtmsg.dsc_m_rtm)
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int))) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
       memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
       ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;
       ADSL_RTM_G->rtm_version = RTM_VERSION;
       ADSL_RTM_G->rtm_type = RTM_DELETE;
//     ADSL_RTM_G->rtm_inits = RTV_EXPIRE;
       ADSL_RTM_G->rtm_flags = RTF_UP | RTF_DONE | RTF_LLDATA | RTF_PINNED;
       ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
       ADSL_RTM_G->rtm_pid = dsg_this_server.imc_pid;  /* set process id */
       ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
       ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
       ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
       *((unsigned int *) &ADSL_SOA_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#define ADSL_SDL_G ((struct sockaddr_dl *) (dsl_m_rtmsg.byrc_m_space + sizeof(struct sockaddr_in)))
       memcpy( ADSL_SDL_G, &dsg_tun_ctrl.dsc_soa_dl_r, sizeof(struct sockaddr_dl) );
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + ((sizeof(struct sockaddr_dl) + sizeof(int) - 1) & (0 - sizeof(int)))))
       memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
       *((unsigned char *) ADSL_SOA_MASK) = 6;
       memset( (char *) ADSL_SOA_MASK + 1, 0XFF, 5 );

       m_console_out( (char *) &dsl_m_rtmsg,
                      IML_MSG_LEN );
       iml_rc = write( dsg_tun_ctrl.imc_route_socket,
                       (char *) &dsl_m_rtmsg,
                       IML_MSG_LEN );

//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T write() ARP returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
       while (TRUE) {
         iml_rc = read( dsg_tun_ctrl.imc_route_socket,
                        (char *) &dsl_m_rtmsg,
                        sizeof(dsl_m_rtmsg) );
//#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T read() ARP returned %d errno %d.",
                         __LINE__, iml_rc, errno );
//#endif
         if (iml_rc > 0) {
           m_console_out( (char *) &dsl_m_rtmsg, iml_rc );
         }
         if (iml_rc < 0) {
           break;
         }
         if (   (ADSL_RTM_G->rtm_pid == dsg_this_server.imc_pid)  /* compare process id */
             && (ADSL_RTM_G->rtm_seq == IML_MSG_SEQU)) {
           break;
         }
       }
#undef ADSL_SDL_G
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
       /*
         delete route
         sample: route del -host 172.22.81.221/32
       */
#define LEN_SOA_MASK 8
#define IML_MSG_LEN (sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in) + LEN_SOA_MASK)
#define IML_MSG_SEQU 1
       memset( &dsl_m_rtmsg, 0, IML_MSG_LEN );
       ADSL_RTM_G->rtm_msglen = IML_MSG_LEN;  /* to skip over non-understood messages */
       ADSL_RTM_G->rtm_version = RTM_VERSION;
       ADSL_RTM_G->rtm_type = RTM_DELETE;
       ADSL_RTM_G->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC;
       ADSL_RTM_G->rtm_addrs = RTA_DST | RTA_NETMASK;
       ADSL_RTM_G->rtm_seq = IML_MSG_SEQU;
#define ADSL_SOA_DST ((struct sockaddr_in *) dsl_m_rtmsg.byrc_m_space)
       ((struct sockaddr *) ADSL_SOA_DST)->sa_len = sizeof(struct sockaddr_in);  /* total length */
       ((struct sockaddr *) ADSL_SOA_DST)->sa_family = AF_INET;
       *((unsigned int *) &ADSL_SOA_DST->sin_addr)
         = *((unsigned int *) dsl_sth_work.chrc_ineta);
#define ADSL_SOA_MASK ((struct sockaddr_in *) ((char *) &dsl_m_rtmsg + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in)))
       memset( ADSL_SOA_MASK, 0, LEN_SOA_MASK );
       ((struct sockaddr *) ADSL_SOA_MASK)->sa_len = LEN_SOA_MASK;
       *((unsigned int *) &ADSL_SOA_MASK->sin_addr) = 0XFFFFFFFF;

       m_console_out( (char *) &dsl_m_rtmsg, IML_MSG_LEN );
       iml_rc = write( dsg_tun_ctrl.imc_route_socket,
                       (char *) &dsl_m_rtmsg, IML_MSG_LEN );

//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T write() route returned %d errno %d.",
                       __LINE__, iml_rc, errno );
//#endif
//#undef ADSL_SOA_GATEWAY
#undef ADSL_SOA_DST
#undef ADSL_SOA_MASK
#undef IML_MSG_LEN
#undef IML_MSG_SEQU
#undef LEN_SOA_MASK
#undef ADSL_RTM_G
#endif
#endif
   }
#ifdef DEBUG_HOB_TUN_1407

   p_seri_post:                             /* post the waiting thread */
#endif
   if (dsl_sth_work.aboc_posted) {          /* with mark posted        */
#ifndef TRY_141125_01                       /* HOB-PPP-T1 serialize-thread memory barrier */
     *dsl_sth_work.aboc_posted = TRUE;      /* mark posted             */
#endif
#ifdef TRY_141125_01                        /* HOB-PPP-T1 serialize-thread memory barrier */
     m_hl_lock_set_true_1( dsl_sth_work.aboc_posted );  /* mark posted */
#endif
   }
   if (dsl_sth_work.adsc_event_posted) {    /* event for posted        */
     iml_rc = dsl_sth_work.adsc_event_posted->m_post( &iml_error );  /* event for posted */
// to-do 02.07.10 KB error message
     if (iml_rc < 0) {                     /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_serial_thread thread m_post Return Code %d Error %d",
                     __LINE__, iml_rc, iml_error );
     }
   }
   goto p_serial_00;                        /* serialisation start     */
} /* end m_serial_thread()                                             */

#ifdef D_INCL_HOB_TUN
/** function which returns a newly allocated buffer and its length     */
extern "C" int m_htun_getrecvbuf( void **aap_handle, char **aachp_buffer ) {
#ifdef OLD01
   *aap_handle = new char[16384];
   *aachp_buffer = (char*)*aap_handle;
   return 16384;
#endif
   *aap_handle = m_proc_alloc();
   *aachp_buffer = (char *) *aap_handle + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
   return LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) - sizeof(struct dsd_gather_i_1);
} /* end m_htun_getrecvbuf()                                           */

/** function which releases a previously allocated buffer              */
extern "C" void m_htun_relrecvbuf( void *ap_handle ) {
#ifdef OLD01
   delete ap_handle;
#endif
   m_proc_free( ap_handle );
} /* end m_htun_relrecvbuf()                                           */

/** callback routine for HOB-TUN, HOB-TUN did receive data from the server */
extern "C" BOOL m_se_htun_recvbuf( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                   struct dsd_buf_vector_ele *adsp_vector,
                                   int imp_ele_vector )
{
   int        iml_index;                    /* index input buffers     */
   BOOL       bol_act;                      /* activate connection     */
   BOOL       bol_ret;                      /* return value            */
#ifndef HL_UNIX
#ifndef WSP_V24
   class clconn1 *adsl_conn1;               /* class connection        */
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last in chain        */
#ifdef B120601
   struct dsd_gather_i_1 **aadsl_gai1_w1;   /* for chaining            */
#endif

#ifndef WSP_V24
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
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "nbipgw20-l%05d-T m_se_htun_recvbuf() adsp_tun_contr_conn=%p adsl_conn1=%p.",
                   __LINE__, adsp_tun_contr_conn, adsl_conn1 );
#endif
#ifdef DEBUG_140213_01                      /* crash HOB-TUN          */
   if (adsl_conn1->iec_servcotype           /* type of server connection */
         != ied_servcotype_htun) {          /* HOB-TUN                 */
     m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-W m_se_htun_recvbuf() DEBUG_140213_01 adsl_conn1=%p iec_servcotype=%d.",
                     __LINE__, adsl_conn1, adsl_conn1->iec_servcotype );
   }
#endif
   if (adsl_conn1->adsc_sdhc1_s2) {         /* all buffer full         */
     m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-W m_se_htun_recvbuf() adsl_conn1=%p adsc_sdhc1_s2 already set",
                     __LINE__, adsl_conn1 );
     return FALSE;
   }
#ifndef B120601
/**
   the blocks sdhc1 are chained together,
   but the gather structures are not yet chained together
*/
#endif
   adsl_sdhc1_last = NULL;                  /* clear last in chain     */
   iml_index = 0;                           /* clear index input buffers */
   do {                                     /* loop over all input buffers */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) (adsp_vector + iml_index)->ac_handle;
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;
     ADSL_GAI1_W1->achc_ginp_cur = (adsp_vector + iml_index)->achc_data;
     ADSL_GAI1_W1->achc_ginp_end = (adsp_vector + iml_index)->achc_data + (adsp_vector + iml_index)->imc_len_data;
     if (adsl_sdhc1_last == NULL) {         /* is first in chain       */
       adsl_sdhc1_first = adsl_sdhc1_w1;
     } else {                               /* middle in chain         */
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;
#ifdef B120601
       *aadsl_gai1_w1 = ADSL_GAI1_W1;
#endif
     }
#undef ADSL_GAI1_W1
     adsl_sdhc1_last = adsl_sdhc1_w1;
#ifdef B120601
     aadsl_gai1_w1 = ((struct dsd_gather_i_1 **) (adsl_sdhc1_w1 + 1));
#endif
     iml_index++;                           /* increment index input buffers */
   } while (iml_index < imp_ele_vector);    /* till all buffers read   */
   bol_act = FALSE;                         /* do not activate connection */
#ifndef WSP_V24
#ifndef HL_UNIX
   EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   adsl_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
#endif
#ifdef WSP_V24
   adsl_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
   if (adsl_conn1->adsc_sdhc1_s1 == NULL) {  /* take first buffer      */
     adsl_conn1->adsc_sdhc1_s1 = adsl_sdhc1_first;  /* set first buffer */
     if (adsl_conn1->boc_st_act == FALSE) {  /* util-thread not active */
       adsl_conn1->boc_st_act = TRUE;       /* util-thread active now  */
       bol_act = TRUE;                      /* activate thread         */
     }
     bol_ret = TRUE;                        /* return value            */
#ifndef B120604
   } else if (   (adsp_tun_contr_conn->iec_tunc == ied_tunc_ppp)
              || (adsp_tun_contr_conn->iec_tunc == ied_tunc_sstp)) {
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_s1;  /* get old chain      */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w1->adsc_next = adsl_sdhc1_first;  /* append new buffers */
#ifdef XYZ1
     if (adsl_conn1->boc_st_act == FALSE) {  /* util-thread not active */
       adsl_conn1->boc_st_act = TRUE;       /* util-thread active now  */
       bol_act = TRUE;                      /* activate thread         */
     }
#endif
     bol_ret = TRUE;                        /* return value            */
#endif
   } else {                                 /* take second buffer      */
// to-do 25.11.08 KB - adsc_sdhc1_s2 already occupied ???
     adsl_conn1->adsc_sdhc1_s2 = adsl_sdhc1_first;  /* set first buffer */
     bol_ret = FALSE;                       /* return value            */
   }
#ifndef WSP_V24
#ifndef HL_UNIX
   LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   adsl_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
#endif
#ifdef WSP_V24
   adsl_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
   if (bol_act == FALSE) return bol_ret;    /* all done                */
   m_act_thread_2( adsl_conn1 );            /* activate m_proc_data()  */
   return bol_ret;                          /* all done                */
} /* end m_se_htun_recvbuf()                                           */

/** error message when HTCP connect failed                             */
extern "C" void m_htun_htcp_connect_failed( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_htun_htcp_connect_failed( %p , ... ) called",
                   __LINE__, adsp_tun_contr_conn );
#endif
#ifndef WSP_V24
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
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
#ifdef DEBUG_100923_01
     if (adsl_conn1 == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW DEBUG_100923_01 GATE=??? SNO=??? INETA=??? l%05d HTUN connect to %s getnameinfo() returned %d %d.",
                       __LINE__, chrl_ineta, iml_rc, D_TCP_ERROR );
       return;
     }
#endif
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d getnameinfo() returned %d %d.",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl1 = "";
   if ((imp_current_index + 1) < imp_total_index) {
     achl1 = " - try next INETA from DNS";  /* set additional text     */
   } else if (imp_total_index > 1) {
     achl1 = " - was last INETA from DNS";  /* set additional text     */
   }
#ifdef DEBUG_100923_01
   if (adsl_conn1 == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW DEBUG_100923_01 GATE=??? SNO=??? INETA=??? l%05d HTUN connect to %s failed %d%s",
                     __LINE__, chrl_ineta, imp_errno, achl1 );
     return;
   }
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d HTUN connect to %s failed %d%s",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   __LINE__, chrl_ineta, imp_errno, achl1 );
   return;
} /* end m_htun_htcp_connect_failed()                                  */

/** connect has been done - either successfully or the connect failed  */
extern "C" void m_htun_htcp_connect_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                         struct dsd_target_ineta_1 *adsp_target_ineta_1,
                                         void * ap_free_ti1,  /* INETA to free */
                                         struct sockaddr *adsp_soa, socklen_t imp_len_soa,
                                         int imp_errno ) {
   int        iml1;                         /* working variable        */
   int        iml_select;                   /* select the events       */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nbipgw20-l%05d-T m_htun_htcp_connect_end( %p , ... ) called",
                   __LINE__, adsp_tun_contr_conn );
#endif
#ifdef B100702
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
   if (ap_free_ti1) free( ap_free_ti1 );    /* INETA to free           */
#ifndef WSP_V24
#ifndef HL_UNIX
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#ifdef HL_UNIX
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNCBCE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_htun_htcp_connect_end( %p , %p , %p , %p , %d , %d ) conn1=%p ineta_raws_1=%p.",
                     __LINE__,
                     adsp_tun_contr_conn, adsp_target_ineta_1, ap_free_ti1, adsp_soa, imp_len_soa, imp_errno,
                     adsl_conn1, ADSL_INETA_RAWS_1_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (imp_errno == 0) goto p_conn_ok;      /* connect succeeded       */
   iml_select = DEF_NETW_POST_1_HTUN_CONN_ERR;  /* posted for HTUN connect error */
#ifndef WSP_V24
   do {                                     /* pseudo-loop             */
#ifdef OLD_1112
     if (adsl_conn1->adsc_radqu) {          /* radius still active     */
       adsl_conn1->adsc_radqu->imc_connect_error = imp_errno;
       break;
     }
#endif
#ifndef HL_UNIX
#ifdef B101214
     adsl_conn1->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
     if (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE) break;  /* not dynamicly allocated */
     adsl_conn1->iec_st_ses = clconn1::ied_ses_error_co_dyn;  /* status server error */
#else
     if (adsl_conn1->iec_st_ses != clconn1::ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
       adsl_conn1->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
     } else {
       adsl_conn1->iec_st_ses = clconn1::ied_ses_error_co_dyn;  /* status server error */
     }
#endif
#endif
#ifdef HL_UNIX
     if (adsl_conn1->iec_st_ses != ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
       adsl_conn1->iec_st_ses = ied_ses_error_conn;  /* status server error */
     } else {
       adsl_conn1->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     }
#endif
   } while (FALSE);
#endif
#ifdef WSP_V24
   do {                                     /* pseudo-loop             */
     if (adsl_conn1->iec_st_ses != ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
       adsl_conn1->iec_st_ses = ied_ses_error_conn;  /* status server error */
     } else {
       adsl_conn1->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     }
   } while (FALSE);
#endif
   goto p_ret_00;                           /* return to HOB-TUN       */

   p_conn_ok:                               /* connect succeeded       */
   memcpy( &adsl_conn1->dsc_soa_htcp_server,  /* address information for connected */
           adsp_soa,
           imp_len_soa );
   if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_NO_FREE_INETA) {  /* do not free local INETA */
     ADSL_INETA_RAWS_1_G->imc_state &= -1 - DEF_STATE_HTUN_NO_FREE_INETA;  /* do free local INETA at session end */
   }
   iml_select = DEF_NETW_POST_1_HTUN_CONN_OK;  /* posted for HOB-TUN connect ok */
   ADSL_INETA_RAWS_1_G->imc_state |= DEF_STATE_HTUN_CONN_OK;  /* done HOB-TUN connect ok */
   m_hlnew_printf( HLOG_INFO1, "HWSPnnnnI GATE=%(ux)s SNO=%08d INETA=%s connect (HTCP) to %(ux)s successful",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   (char *) (adsl_conn1->adsc_server_conf_1 + 1)
                     + adsl_conn1->adsc_server_conf_1->inc_no_sdh
                       * sizeof(struct dsd_sdh_work_1) );
#ifndef WSP_V24
#ifndef HL_UNIX
#ifndef X101214_XX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
#else
   if (adsl_conn1->iec_st_ses != clconn1::ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
     adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
   } else {
     adsl_conn1->iec_st_ses = clconn1::ied_ses_start_dyn_serv_1;  /* start connection to server part one dynamic */
   }
#endif
#endif
#ifdef HL_UNIX
   adsl_conn1->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
#endif
#endif
#ifdef WSP_V24
   adsl_conn1->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
#endif

   p_ret_00:                                /* return to HOB-TUN       */
   if (adsl_conn1->adsc_wsp_auth_1) {       /* authentication active   */
     adsl_conn1->adsc_wsp_auth_1->imc_connect_error = imp_errno;  /* set connect error */
     adsl_conn1->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   }
   if (adsl_conn1->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     adsl_conn1->adsc_int_webso_conn_1->imc_connect_error = imp_errno;  /* set connect error */
     adsl_conn1->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
   }
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (iml_select & adsl_netw_post_1->imc_select)) {  /* is selected */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted   */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_htcp_connect_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_htcp_connect_end()                                     */

#ifdef B130813
#ifndef HL_UNIX
/** WSP can free the target INETA                                      */
extern "C" void m_htun_htcp_free_target_ineta( struct dsd_tun_contr1 *adsp_tun_contr1,
                                               struct dsd_target_ineta_1 *adsp_target_ineta_1 ) {
   class clconn1 *adsl_conn_w1;             /* class connection        */

#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn_w1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn_w1 = ((class clconn1 *)
                     ((char *) adsp_tun_contr1
                        - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
   if (adsl_conn_w1->adsc_server_conf_1 == NULL) return;
   if (adsl_conn_w1->adsc_server_conf_1->inc_function != DEF_FUNC_DIR) return;
   if (adsl_conn_w1->adsc_server_conf_1->boc_dynamic) return;  /* dynamically allocated */
   if (adsl_conn_w1->adsc_server_conf_1->boc_dns_lookup_before_connect == FALSE) return;  /* needs to solve INETA before connect */
   if (adsp_target_ineta_1 == adsl_conn_w1->adsc_server_conf_1->adsc_server_ineta) return;
   free( adsp_target_ineta_1 );             /* free the memory         */
   return;
#ifndef NEW_HOB_TUN_1103
#undef ADSL_INETA_RAWS_1_G
#endif
} /* end m_htun_htcp_free_target_ineta()                               */
#endif
#endif

/** TCP session of HTCP / HOB-TUN has sent something to the server     */
extern "C" void m_htun_htcp_send_complete( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif

#ifdef B100824
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_htcp_send_complete( %p ) called",
                   __LINE__, adsp_tun_contr1 );
#endif
#ifndef WSP_V24
#ifndef HL_UNIX
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#ifdef HL_UNIX
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   ADSL_INETA_RAWS_1_G->imc_state |= DEF_STATE_HTUN_SEND_COMPL;  /* done HOB-TUN send complete - m_htun_htcp_send_complete() */
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_SEND_COMPL)) {  /* posted for HTUN HTCP send complete */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted  */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_htcp_send_complete() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   if (adsl_conn1 == NULL) return;
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_htcp_send_complete()                                   */

/** set authentication for HOB-TUN PPP, HOB-PPP-T1 or SSTP             */
extern "C" void m_htun_ppp_set_auth( struct dsd_tun_contr_conn *adsp_tun_contr_conn, char *achp_ppp_auth ) {
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tun-l%05d-T m_htun_ppp_set_auth( %p , %p ) called",
                   __LINE__, adsp_tun_contr_conn, achp_ppp_auth );
#endif
#ifndef WSP_V24
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
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
   if (adsl_conn1->adsc_server_conf_1 == NULL) return;  /* no configuration server */
   memcpy( achp_ppp_auth, adsl_conn1->adsc_server_conf_1->chrc_ppp_auth, DEF_NO_PPP_AUTH );
} /* end m_htun_ppp_set_auth()                                         */

/** TCP session of HOB-TUN, HTCP HOB-PPP-T1 or SSTP has ended          */
extern "C" void m_htun_session_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                    int imp_reason ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml1;                         /* working variable        */
   int        iml_state_l;                  /* state of HTUN / HTCP session */
   int        *aiml_state_a;                /* address state of HTUN / HTCP session */
   void       **avpl_netw_post_1;           /* address clear structure to post */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* used INETA       */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tun-l%05d-T m_htun_session_end( %p , %d ) called",
                   __LINE__, adsp_tun_contr_conn, imp_reason );
#endif
#ifndef WSP_V24
#ifndef HL_UNIX
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#ifdef HL_UNIX
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNCBSE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_htun_session_end( %p , %d ) conn1=%p ineta_raws_1=%p.",
                     __LINE__,
                     adsp_tun_contr_conn, imp_reason,
                     adsl_conn1, ADSL_INETA_RAWS_1_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef B100811
   if (adsl_conn1 == NULL) goto p_sess_end_20;  /* no connection associated */
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     /* do not set when dynamic server                                 */
     if (   (adsl_conn1->adsc_server_conf_1 == NULL)
         || (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (imp_reason == 0) {               /* normal end              */
         adsl_conn1->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         adsl_conn1->achc_reason_end = "server ended with error";
       }
     }
   }
// to-do 29.11.08 KB - notify session, start work-thread, set session-status
   p_sess_end_20:                           /* connection part has been processed */
#endif
#ifndef B140625
#ifndef B150706
   adsl_conn1->boc_survive = FALSE;         /* no more survive E-O-F client */
#endif
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B141126
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
#endif
#ifndef B141126
#ifndef WSP_V24
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
#ifndef HL_UNIX
     EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
     adsl_conn1->dsc_critsect.m_enter();    /* critical section        */
#endif
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     if (adsl_sdhc1_w1 == NULL) {
#ifndef HL_UNIX
       LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
       adsl_conn1->dsc_critsect.m_leave();  /* critical section        */
#endif
       break;
     }
     /* blocks may still have usage count                              */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get chain of blocks to free */
     while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
     adsl_sdhc1_w2->adsc_next = adsl_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     adsl_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
     adsl_conn1->adsc_sdhc1_htun_sch = NULL;  /* all buffers get freed */
#ifndef HL_UNIX
     LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
     adsl_conn1->dsc_critsect.m_leave();    /* critical section        */
#endif
     break;
   }
#endif
#ifdef WSP_V24
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_conn1->dsc_critsect.m_enter();    /* critical section        */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     if (adsl_sdhc1_w1 == NULL) {
       adsl_conn1->dsc_critsect.m_leave();  /* critical section        */
       break;
     }
     /* blocks may still have usage count                              */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get chain of blocks to free */
     while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
     adsl_sdhc1_w2->adsc_next = adsl_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     adsl_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
     adsl_conn1->adsc_sdhc1_htun_sch = NULL;  /* all buffers get freed */
     adsl_conn1->dsc_critsect.m_leave();    /* critical section        */
     break;
   }
#endif
#endif
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "xiipgw08-tun-l%05d-T m_htun_session_end() SNO=%08d ADSL_INETA_RAWS_1_G=%p adsl_conn1->adsc_server_conf_1=%p.",
                   __LINE__, adsl_conn1->dsc_co_sort.imc_sno, ADSL_INETA_RAWS_1_G, adsl_conn1->adsc_server_conf_1 );
#endif
   adsl_ineta_raws_1_w1 = ADSL_INETA_RAWS_1_G;
   if (adsl_ineta_raws_1_w1 == NULL) {
     m_act_thread_1( adsl_conn1 );          /* activate thread for session */
     return;
   }
   iml_state_l = DEF_STATE_HTUN_SESS_END;   /* done HOB-TUN HTCP session end */
   if (imp_reason) {                        /* abnormal end            */
     iml_state_l |= DEF_STATE_HTUN_ERR_SESS_END;  /* done HOB-TUN HTCP session end was with error */
   }
   adsl_ineta_raws_1_w1->imc_state |= iml_state_l;  /* state of HOB-TUN / HTCP session */
#ifndef WSP_V24
#ifndef B130909
#ifndef HL_UNIX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_rec_close;  /* received close */
#else
   adsl_conn1->iec_st_ses = ied_ses_rec_close;  /* received close      */
#endif
#endif
#endif
#ifdef WSP_V24
   adsl_conn1->iec_st_ses = ied_ses_rec_close;  /* received close      */
#endif
   adsl_netw_post_1 = adsl_ineta_raws_1_w1->adsc_netw_post_1;  /* get structure to post from network callback */
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_SESS_END)) {  /* posted for HOB-TUN HTCP session end */
     adsl_ineta_raws_1_w1->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
#ifndef TRY_141212_01                       /* HOB-TUN memory barrier  */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted  */
#else
     m_hl_lock_set_true_1( (int *) &adsl_netw_post_1->boc_posted );  /* event has been posted */
#endif
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_session_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
#ifndef TRY_130624_01
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B141126
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
#endif
#ifndef B141126
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_conn1->dsc_critsect.m_enter();    /* critical section        */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     if (adsl_sdhc1_w1 == NULL) {
       adsl_conn1->dsc_critsect.m_leave();  /* critical section        */
       break;
     }
     /* blocks may still have usage count                              */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get chain of blocks to free */
     while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
     adsl_sdhc1_w2->adsc_next = adsl_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     adsl_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
     adsl_conn1->adsc_sdhc1_htun_sch = NULL;  /* all buffers get freed */
     adsl_conn1->dsc_critsect.m_leave();    /* critical section        */
     break;
   }
#endif
#endif
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     /* do not set when dynamic server                                 */
     if (   (adsl_conn1->adsc_server_conf_1 == NULL)
         || (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (imp_reason == 0) {               /* normal end              */
         adsl_conn1->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         adsl_conn1->achc_reason_end = "server ended with error";
       }
     }
   }
#ifdef B130909
#ifndef TRY_130624_01
#ifndef HL_UNIX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_rec_close;  /* received close */
#else
   adsl_conn1->iec_st_ses = ied_ses_rec_close;  /* received close      */
#endif
#endif
#endif
#ifdef B120206
   if (   (ADSL_INETA_RAWS_1_G->iec_irs != ied_ineta_raws_n_ipv4)  /* INETA IPV4 */
       && (ADSL_INETA_RAWS_1_G->iec_irs != ied_ineta_raws_n_ipv6)) {  /* INETA IPV6 */
     goto p_sess_end_40;                    /* connection part has been processed */
   }
   ADSL_INETA_RAWS_1_G->ac_conn1 = NULL;    /* not associated with session */
   adsl_conn1->adsc_ineta_raws_1 = NULL;    /* no more INETA associated */
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef B141126
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
#endif
#ifndef B141126
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_conn1->dsc_critsect.m_enter();    /* critical section        */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     if (adsl_sdhc1_w1 == NULL) {
       adsl_conn1->dsc_critsect.m_leave();  /* critical section        */
       break;
     }
     /* blocks may still have usage count                              */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get chain of blocks to free */
     while (adsl_sdhc1_w2->adsc_next) adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;
     adsl_sdhc1_w2->adsc_next = adsl_conn1->adsc_sdhc1_inuse;  /* chain of buffers in use */
     adsl_conn1->adsc_sdhc1_inuse = adsl_sdhc1_w1;  /* append to chain */
     adsl_conn1->adsc_sdhc1_htun_sch = NULL;  /* all buffers get freed */
     adsl_conn1->dsc_critsect.m_leave();    /* critical section        */
     break;
   }
#endif
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     /* do not set when dynamic server                                 */
     if (   (adsl_conn1->adsc_server_conf_1 == NULL)
         || (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (imp_reason == 0) {               /* normal end              */
         adsl_conn1->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         adsl_conn1->achc_reason_end = "server ended with error";
       }
     }
   }

   p_sess_end_40:                           /* connection part has been processed */
#endif
#ifdef B140618
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
#endif
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_session_end()                                          */

/** session of HOB-TUN has ended, free all resources                   */
extern "C" void m_htun_htcp_free_resources( struct dsd_tun_contr_ineta *adsp_tun_contr_ineta ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   int        iml1;                         /* working variable        */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HOB-TUN l%05d m_htun_free_resources( %p ) called",
                   __LINE__, adsp_tun_contr_ineta );
#endif
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr_ineta - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr_ineta )))
#ifndef WSP_V24
#ifndef HL_UNIX
#define ADSL_CONN1_G ((class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)
#else
#define ADSL_CONN1_G ((struct dsd_conn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)
#endif
#endif
#ifdef WSP_V24
#define ADSL_CONN1_G ((struct dsd_conn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)
#endif
#ifndef B130911
   ADSL_INETA_RAWS_1_G->imc_state           /* state of HOB-TUN / HTCP session */
     |= DEF_STATE_HTUN_FREE_R_1;            /* done HTUN free resources */
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNCBTF", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_htun_htcp_free_resources( %p ) conn1=%p ineta_raws_1=%p.",
                     __LINE__,
                     adsp_tun_contr_ineta,
                     ADSL_CONN1_G, ADSL_INETA_RAWS_1_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   m_hl_lock_dec_1( &ADSL_CONN1_G->imc_references );  /* references to this session */
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_FREE_R)) {  /* posted for HOB-TUN free resources */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted   */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_htcp_free_resources() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_NO_FREE_INETA) return;  /* do not free local INETA */
   m_cleanup_htun_ineta( ADSL_INETA_RAWS_1_G );  /* remove from AVL-trees and remove ARP and route */
   free( ADSL_INETA_RAWS_1_G );             /* free memory             */
#undef ADSL_INETA_RAWS_1_G
#undef ADSL_CONN1_G
} /* end m_htun_htcp_free_resources()                                  */

/** free resources for HOB-TUN PPP, HOB-PPP-T1 or SSTP                 */
extern "C" void m_htun_ppp_free_resources( struct dsd_tun_contr_ineta *adsp_tun_contr_ineta ) {
   int        iml1;                         /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */

#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr_ineta - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr_ineta )))
#ifndef B130911
   ADSL_INETA_RAWS_1_G->imc_state           /* state of HOB-TUN / HTCP session */
     |= DEF_STATE_HTUN_FREE_R_1;            /* done HTUN free resources */
#endif
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNCBPF", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d m_htun_ppp_free_resources( %p ) ineta_raws_1=%p.",
                     __LINE__,
                     adsp_tun_contr_ineta,
                     ADSL_INETA_RAWS_1_G );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   m_cleanup_htun_ineta( ADSL_INETA_RAWS_1_G );  /* remove from AVL-trees and remove ARP and route */
   free( ADSL_INETA_RAWS_1_G );             /* free memory             */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_ppp_free_resources()                                   */

/** HOB-TUN - put a warning related to the session to the console      */
extern "C" void m_htun_warning( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                struct dsd_tun_contr_ineta *adsp_tun_contr_ineta,
                                int imp_error_number,
                                const char *achp_format, ... ) {
   int        iml_rc;                       /* return code             */
   int        iml_len;                      /* length of message       */
#ifdef B130926
   int        iml_cpy_pos;                  /* position of copy        */
#endif
   int        iml_cpy_pos_source;           /* position of copy source */
   int        iml_cpy_pos_destination;      /* position of copy destination */
   int        iml_cpy_len;                  /* length of copy          */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   va_list    dsl_list;                     /* list of arguments       */
   struct sockaddr_storage dsl_soa;         /* filled with INETA       */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
   char       chrl_port[ 32 ];              /* for message port        */
   char       chrl_msg[ 512 ];              /* area for message        */

   adsl_conn1 = NULL;                       /* for this connection     */
   if (adsp_tun_contr_conn) {               /* connected to session    */
#ifndef WSP_V24
#ifndef HL_UNIX
     adsl_conn1 = ((class clconn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( class clconn1, dsc_tun_contr_conn )));
#else
     adsl_conn1 = ((struct dsd_conn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
#endif
#ifdef WSP_V24
     adsl_conn1 = ((struct dsd_conn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
   }
//#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   if (adsl_conn1) {                        /* connection valid        */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS3%02dW GATE=%(ux)s SNO=%08d INETA=%s HOB-TUN %.*(u8)s",
                     imp_error_number,
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     iml_len, chrl_msg );
     return;                                /* all done                */
   }
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );  /* filled with INETA */
   iml_cpy_len = 0;                         /* clear length copy       */
#ifdef B130926
#ifdef B110314
   switch (ADSL_AUXF_1_G->iec_auxf_def) {
#ifdef FORKEDIT
   }
#endif
#else
   switch (ADSL_INETA_RAWS_1_G->iec_irs) {  /* type of INETA raw socket */
#endif
     case ied_ineta_raws_n_ipv4:            /* INETA IPV4              */
     case ied_ineta_raws_user_ipv4:         /* INETA user IPV4         */
     case ied_ineta_raws_l2tp_ipv4:         /* INETA L2TP IPV4         */
       dsl_soa.ss_family = AF_INET;         /* IPV4                    */
       iml_cpy_pos = offsetof( struct sockaddr_in, sin_addr );  /* position to copy */
       iml_cpy_len = 4;                     /* length to copy          */
       break;
     case ied_ineta_raws_n_ipv6:            /* INETA IPV6              */
     case ied_ineta_raws_user_ipv6:         /* INETA user IPV6         */
     case ied_ineta_raws_l2tp_ipv6:         /* INETA L2TP IPV6         */
       dsl_soa.ss_family = AF_INET6;        /* IPV6                    */
       iml_cpy_pos = offsetof( struct sockaddr_in6, sin6_addr );  /* position to compare */
       iml_cpy_len = 16;                    /* length to copy          */
       break;
   }
#endif
   if (adsp_tun_contr_ineta->dsc_soa_local_ipv4.sin_family == AF_INET) {
     dsl_soa.ss_family = AF_INET;           /* IPV4                    */
     iml_cpy_pos_source = offsetof( struct dsd_tun_contr_ineta, dsc_soa_local_ipv4 ) + offsetof( struct sockaddr_in, sin_addr );  /* position of copy source */
     iml_cpy_pos_destination = offsetof( struct sockaddr_in, sin_addr );  /* position of copy destination */
     iml_cpy_len = 4;                       /* length to copy          */
   } else if (adsp_tun_contr_ineta->dsc_soa_local_ipv6.sin6_family == AF_INET6) {
     dsl_soa.ss_family = AF_INET6;          /* IPV6                    */
     iml_cpy_pos_source = offsetof( struct dsd_tun_contr_ineta, dsc_soa_local_ipv6 ) + offsetof( struct sockaddr_in6, sin6_addr );  /* position of copy source */
     iml_cpy_pos_destination = offsetof( struct sockaddr_in6, sin6_addr );  /* position of copy destination */
     iml_cpy_len = 16;                      /* length to copy          */
   }
   strcpy( chrl_ineta, "???" );
   if (iml_cpy_len > 0) {                   /* length copy set         */
#ifdef B130926
     memcpy( (char *) &dsl_soa + iml_cpy_pos,
             ADSL_INETA_RAWS_1_G + 1,
             iml_cpy_len );
#endif
     memcpy( (char *) &dsl_soa + iml_cpy_pos_destination,
             (char *) adsp_tun_contr_ineta + iml_cpy_pos_source,
             iml_cpy_len );
     iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa, sizeof(struct sockaddr_storage),
                           chrl_ineta, sizeof(chrl_ineta),
                           0, 0, NI_NUMERICHOST );
     if (iml_rc) {           /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW HOB-TUN m_htun_warning() l%05d getnameinfo() returned %d %d.",
                       __LINE__, iml_rc, D_TCP_ERROR );
       strcpy( chrl_ineta, "???" );
     }
   }
   chrl_port[0] = 0;                        /* for message port        */
#ifdef B130926
#ifdef B110314
   if (   (ADSL_AUXF_1_G->iec_auxf_def == ied_ineta_raws_user_ipv4)  /* INETA user IPV4 */
       || (ADSL_AUXF_1_G->iec_auxf_def == ied_ineta_raws_user_ipv6)) {  /* INETA user IPV6 */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (ADSL_INETA_RAWS_1_G->iec_irs == ied_ineta_raws_user_ipv4)  /* INETA user IPV4 */
       || (ADSL_INETA_RAWS_1_G->iec_irs == ied_ineta_raws_user_ipv6)) {  /* INETA user IPV6 */
#endif
     sprintf( chrl_port, "TCP source port %d ", ADSL_INETA_RAWS_1_G->usc_appl_port );  /* port in use */
   }
#endif
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr_ineta - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr_ineta )))
   if (ADSL_INETA_RAWS_1_G->boc_with_user) {  /* structure with user   */
     sprintf( chrl_port, "TCP source port %d ", ADSL_INETA_RAWS_1_G->usc_appl_port );  /* port in use */
   }
#undef ADSL_INETA_RAWS_1_G
#ifdef B130926
   m_hlnew_printf( HLOG_WARN1, "HWSPTUN0%03d HOB-TUN message use ineta-appl %s %s%.*(u8)s",
                   imp_error_number,
                   chrl_ineta, chrl_port,
                   iml_len, chrl_msg );
#endif
   m_hlnew_printf( HLOG_WARN1, "HWSPTUN0%03dW HOB-TUN message use ineta-appl %s %s%.*(u8)s",
                   imp_error_number,
                   chrl_ineta, chrl_port,
                   iml_len, chrl_msg );
} /* end m_htun_warning()                                              */

/** HOB-TUN - put information related to the session to the console    */
extern "C" void m_htun_information( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                    struct dsd_tun_contr_ineta *adsp_tun_contr_ineta,
                                    int imp_error_number,
                                    const char *achp_format, ... ) {
   int        iml_rc;                       /* return code             */
   int        iml_len;                      /* length of message       */
   int        iml_cpy_pos_source;           /* position of copy source */
   int        iml_cpy_pos_destination;      /* position of copy destination */
   int        iml_cpy_len;                  /* length of copy          */
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   va_list    dsl_list;                     /* list of arguments       */
   struct sockaddr_storage dsl_soa;         /* filled with INETA       */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
   char       chrl_port[ 32 ];              /* for message port        */
   char       chrl_msg[ 512 ];              /* area for message        */

   adsl_conn1 = NULL;                       /* for this connection     */
   if (adsp_tun_contr_conn) {               /* connected to session    */
#ifndef WSP_V24
#ifndef HL_UNIX
     adsl_conn1 = ((class clconn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( class clconn1, dsc_tun_contr_conn )));
#else
     adsl_conn1 = ((struct dsd_conn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
#endif
#ifdef WSP_V24
     adsl_conn1 = ((struct dsd_conn1 *)
                     ((char *) adsp_tun_contr_conn
                        - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
   }
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   if (adsl_conn1) {                        /* connection valid        */
     m_hlnew_printf( HLOG_INFO1, "HWSPS3%02dI GATE=%(ux)s SNO=%08d INETA=%s HOB-TUN %.*(u8)s",
                     imp_error_number,
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     iml_len, chrl_msg );
     return;                                /* all done                */
   }
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );  /* filled with INETA */
   iml_cpy_len = 0;                         /* clear length copy       */
   if (adsp_tun_contr_ineta->dsc_soa_local_ipv4.sin_family == AF_INET) {
     dsl_soa.ss_family = AF_INET;           /* IPV4                    */
     iml_cpy_pos_source = offsetof( struct dsd_tun_contr_ineta, dsc_soa_local_ipv4 ) + offsetof( struct sockaddr_in, sin_addr );  /* position of copy source */
     iml_cpy_pos_destination = offsetof( struct sockaddr_in, sin_addr );  /* position of copy destination */
     iml_cpy_len = 4;                       /* length to copy          */
   } else if (adsp_tun_contr_ineta->dsc_soa_local_ipv6.sin6_family == AF_INET6) {
     dsl_soa.ss_family = AF_INET6;          /* IPV6                    */
     iml_cpy_pos_source = offsetof( struct dsd_tun_contr_ineta, dsc_soa_local_ipv6 ) + offsetof( struct sockaddr_in6, sin6_addr );  /* position of copy source */
     iml_cpy_pos_destination = offsetof( struct sockaddr_in6, sin6_addr );  /* position of copy destination */
     iml_cpy_len = 16;                      /* length to copy          */
   }
   strcpy( chrl_ineta, "???" );
   if (iml_cpy_len > 0) {                   /* length copy set         */
     memcpy( (char *) &dsl_soa + iml_cpy_pos_destination,
             (char *) adsp_tun_contr_ineta + iml_cpy_pos_source,
             iml_cpy_len );
     iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa, sizeof(struct sockaddr_storage),
                           chrl_ineta, sizeof(chrl_ineta),
                           0, 0, NI_NUMERICHOST );
     if (iml_rc) {                          /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW HOB-TUN m_htun_information() l%05d getnameinfo() returned %d %d.",
                       __LINE__, iml_rc, D_TCP_ERROR );
       strcpy( chrl_ineta, "???" );
     }
   }
   chrl_port[0] = 0;                        /* for message port        */
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr_ineta - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr_ineta )))
   if (ADSL_INETA_RAWS_1_G->boc_with_user) {  /* structure with user   */
     sprintf( chrl_port, "TCP source port %d ", ADSL_INETA_RAWS_1_G->usc_appl_port );  /* port in use */
   }
#undef ADSL_INETA_RAWS_1_G
   m_hlnew_printf( HLOG_INFO1, "HWSPTUN0%03dI HOB-TUN message use ineta-appl %s %s%.*(u8)s",
                   imp_error_number,
                   chrl_ineta, chrl_port,
                   iml_len, chrl_msg );
} /* end m_htun_information()                                          */

#ifndef WSP_V24
#ifndef HL_UNIX
/** enter critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_enter( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
   EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
} /* end m_htun_critsect_enter()                                       */

/** leave critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( class clconn1, dsc_tun_contr_conn )));
   LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
} /* end m_htun_critsect_leave()                                       */
#endif
#ifdef HL_UNIX
/** enter critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_enter( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   int        iml_rc;                       /* return code             */
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
   iml_rc = adsl_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
} /* end m_htun_critsect_enter()                                       */

/** leave critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   int        iml_rc;                       /* return code             */
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
   iml_rc = adsl_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
} /* end m_htun_critsect_leave()                                       */
#endif
#endif
#ifdef WSP_V24
/** enter critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_enter( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   int        iml_rc;                       /* return code             */
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
   iml_rc = adsl_conn1->dsc_critsect.m_enter();  /* enter CriticalSection */
} /* end m_htun_critsect_enter()                                       */

/** leave critical section of WSP session from HOB-TUN                 */
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
   int        iml_rc;                       /* return code             */
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */

   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
   iml_rc = adsl_conn1->dsc_critsect.m_leave();  /* leave CriticalSection */
} /* end m_htun_critsect_leave()                                       */
#endif
#ifdef FOR_ALAN_DUCA
/* enter critical section of WSP session from HTCP                     */
extern "C" void m_htun_htcp_critsect_enter( class dsc_htcp_session *adsp_htcp_session ) {
   m_htun_critsect_enter( &((struct dsd_tun_contr1 *) ((char *) adsp_htcp_session
                              - offsetof( struct dsd_tun_contr1, chrc_htcp_session ))) );
} /* end m_htun_htcp_critsect_enter()                                  */

/* leave critical section of WSP session from HTCP                     */
extern "C" void m_htun_htcp_critsect_leave( class dsc_htcp_session *adsp_htcp_session ) {
   m_htun_critsect_leave( &((struct dsd_tun_contr1 *) ((char *) adsp_htcp_session
                              - offsetof( struct dsd_tun_contr1, chrc_htcp_session ))) );
} /* end m_htun_htcp_critsect_leave()                                  */
#endif

/** callback routine for HOB-TUN, get target-filter assoziated with the session, for PPP */
extern "C" struct dsd_targfi_1 * m_htun_ppp_get_targfi( struct dsd_tun_contr_conn *adsp_tun_contr_conn ) {
#ifdef XYZ1
                                                        int *aimp_trace_level,  /* trace_level */
                                                        int *aimp_sno ) {  /* WSP session number */
#endif
#ifndef WSP_V24
#ifndef HL_UNIX
   class clconn1 *adsl_conn1;               /* class connection        */
#else
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
#endif
#ifdef WSP_V24
   struct dsd_conn1 *adsl_conn1;            /* for this connection     */
#endif
   char       *achl_stf;                    /* source target-filter    */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */

#ifndef WSP_V24
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
#endif
#ifdef WSP_V24
   adsl_conn1 = ((struct dsd_conn1 *)
                   ((char *) adsp_tun_contr_conn
                      - offsetof( struct dsd_conn1, dsc_tun_contr_conn )));
#endif
#ifdef XYZ1
   if (aimp_trace_level) *aimp_trace_level = adsl_conn1->imc_trace_level;  /* trace level set */
   if (aimp_sno) *aimp_sno = adsl_conn1->dsc_co_sort.imc_sno;  /* session number */
#endif
   adsl_targfi_w1 = m_get_session_targfi( &achl_stf, adsl_conn1 );
   if (adsl_targfi_w1 == NULL) return NULL;
   if (adsg_loconf_1_inuse->inc_network_stat >= 4) {
     m_hlnew_printf( HLOG_INFO1, "HWSPS083I GATE=%(ux)s SNO=%08d INETA=%s HOB-TUN apply target-filter %(u8)s from %s.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name, achl_stf );
   }
   return adsl_targfi_w1;
} /* end m_htun_ppp_get_targfi()                                       */

#ifndef WSP_V24
// to-do 13.08.13 KB - give better name
void m_reconnect_workaround(struct dsd_tun_contr_ineta* adsp_tun_contr_ineta, struct dsd_tun_contr_conn* adsp_tun_contr_conn) {
   m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI m_reconnect_workaround() called" );
   /* 05.01.13 KB - from HSM                                           */
    struct dsd_ineta_raws_1 * adsl_ir1 = (struct dsd_ineta_raws_1*)
       ((char*)adsp_tun_contr_ineta - offsetof(struct dsd_ineta_raws_1, dsc_tun_contr_ineta));
#ifndef HL_UNIX
    class clconn1* adsl_c1 = (class clconn1*)
       ((char*)adsp_tun_contr_conn - offsetof(class clconn1, dsc_tun_contr_conn));
#else
    struct dsd_conn1* adsl_c1 = (struct dsd_conn1*)
       ((char*)adsp_tun_contr_conn - offsetof(struct dsd_conn1, dsc_tun_contr_conn));
#endif
    // adsl_ir1->ac_conn1 = adsl_c1;
    adsl_ir1->dsc_htun_h = adsl_c1->dsc_htun_h;
    // adsl_c1->adsc_ineta_raws_1 = adsl_ir1;
#ifndef B140625
   adsl_c1->adsc_ineta_raws_1 = adsl_ir1;
   adsl_c1->iec_servcotype = ied_servcotype_htun;
   adsl_c1->adsc_ineta_raws_1->imc_state = DEF_STATE_HTUN_CONN_OK;
   adsl_c1->adsc_ineta_raws_1->ac_conn1 = adsl_c1;
#endif
}
#endif
#ifdef WSP_V24
// to-do 13.08.13 KB - give better name
void m_reconnect_workaround(struct dsd_tun_contr_ineta* adsp_tun_contr_ineta, struct dsd_tun_contr_conn* adsp_tun_contr_conn) {
   m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI m_reconnect_workaround() called" );
   /* 05.01.13 KB - from HSM                                           */
    struct dsd_ineta_raws_1 * adsl_ir1 = (struct dsd_ineta_raws_1*)
       ((char*)adsp_tun_contr_ineta - offsetof(struct dsd_ineta_raws_1, dsc_tun_contr_ineta));
    struct dsd_conn1* adsl_c1 = (struct dsd_conn1*)
       ((char*)adsp_tun_contr_conn - offsetof(struct dsd_conn1, dsc_tun_contr_conn));
    // adsl_ir1->ac_conn1 = adsl_c1;
    adsl_ir1->dsc_htun_h = adsl_c1->dsc_htun_h;
    // adsl_c1->adsc_ineta_raws_1 = adsl_ir1;
#ifndef B140625
   adsl_c1->adsc_ineta_raws_1 = adsl_ir1;
   adsl_c1->iec_servcotype = ied_servcotype_htun;
   adsl_c1->adsc_ineta_raws_1->imc_state = DEF_STATE_HTUN_CONN_OK;
   adsl_c1->adsc_ineta_raws_1->ac_conn1 = adsl_c1;
#endif
}
#endif
#endif

#ifdef OLD1506
#ifndef HL_UNIX
/** HOB-TUN has new parameters for the session                         */
static void m_session_new_params( class clconn1 *adsp_conn1 ) {
#ifdef B100702
#ifdef D_HPPPT1_1
   if (adsp_conn1->iec_servcotype == ied_servcotype_htun) {  /* HTUN   */
     *((UNSIG_MED *) &((struct sockaddr_in *) &adsp_conn1->dsc_tun_contr1.dsc_soa_local)->sin_addr)
       = adsp_conn1->umc_ineta_ppp_ipv4;                  /* INETA PPP IPV4          */
   }
#endif
#endif
// to-do 03.07.10 KB - remove this subroutine
} /* end m_session_new_params()                                        */
#endif
#endif

