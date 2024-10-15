/*
  HOBLink Authentication Library V3 - Hook
  Project HOB WebSecureProxy
  Copyright (C) HOB Germany 2005
  Copyright (C) HOB Germany 2012
  Copyright (C) HOB Germany 2014
  Copyright (C) HOB Germany 2016
  22.07.05 KB
*/

#ifndef DEF_HOBWSPAT3
#define DEF_HOBWSPAT3

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif

#ifdef OLD_1112
enum ied_at_return {                        /* return value of HOB-WSP-AT3 */
   ied_atr_end,                             /* end of authentication   */
   ied_atr_other_prot,                      /* other protocol selected */
   ied_atr_connect,                         /* do connect now          */
   ied_atr_failed,                          /* authentication failed   */
   ied_atr_err_aux,                         /* error in aux subroutine */
   ied_atr_input,                           /* wait for more input     */
   ied_atr_send_client,                     /* only data to send to the client */
   /* only xsradiq1.hpp: */
   ied_atr_display,                         /* display data            */
   /* only xsradiq1.hpp: */
   ied_atr_auth                             /* user has authenticated  */
};
#else
enum ied_at_return {                        /* return value of HOB-WSP-AT3 */
   ied_atr_end,                             /* end of authentication   */
   ied_atr_other_prot,                      /* other protocol selected */
   ied_atr_input,                           /* wait for more input     */
   ied_atr_connect,                         /* do connect now          */
   ied_atr_failed,                          /* authentication failed   */
   ied_atr_start_rec_server,                /* start receiving from the server */
   ied_atr_err_aux                          /* error in aux subroutine */
};
#endif

enum ied_at_function {                      /* input function of HOB-WSP-AT3 */
   ied_atf_normal,                          /* normal processing       */
   ied_atf_connect_ok,                      /* connect succeeded       */
   ied_atf_connect_failed,                  /* connect failed          */
   ied_atf_do_lbal,                         /* status doing load-balancing */
   ied_atf_abend                            /* function abend          */
};

enum ied_hconn_type {                       /* Hook Connect            */
// to-do 12.01.12 KB how are INETAs IPV4 or IPV6 passed ?
   ied_hconn_ineta,                         /* by INETA                */
   ied_hconn_ipv4,                          /* INETA IPV4              */
   ied_hconn_ipv6,                          /* INETA IPV6              */
   ied_hconn_def_servent,                   /* connect default server entry */
   ied_hconn_sel_servent,                   /* select server entry by name */
   ied_hconn_pttd                           /* pass thru to desktop    */
};

enum ied_conn_ret {                         /* return prepare + connect */
   ied_conn_invalid,                        /* invalid value           */
   ied_conn_ok,                             /* returned O.K.           */
   ied_conn_se_p_no,                        /* no server entry with this protocol */
   ied_conn_se_p_tm,                        /* too many server entries with this protocol */
   ied_conn_se_not_found,                   /* server entry not found  */
   ied_conn_se_oth_p,                       /* server entry has other protocol */
   ied_conn_tcp_ref,                        /* ERROR_CONNECTION_REFUSED */
/* ERROR_CONNECTION_REFUSED The remote system refused the network connection. */
   ied_conn_tcp_to,                         /* WSAETIMEDOUT            */
/* WSAETIMEDOUT A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. */
   ied_conn_tcp_act_ref,                    /* WSAECONNREFUSED         */
/* WSAECONNREFUSED No connection could be made because the target machine actively refused it. */
   ied_conn_tcp_unr,                        /* WSAEHOSTUNREACH         */
/* WSAEHOSTUNREACH A socket operation was attempted to an unreachable host. */
   ied_conn_tcp_ghbn,                       /* HL_ERROR_GETHOSTBYNAME  */
   ied_conn_xyz    /* UUUU */             /* pass thru to desktop    */
};

#ifndef DEF_HL_CHARSET
/**
   hob-xslunic1.h
   hob-xsclib01.h hob-wspat3.h hob-rdpserver1.h hob-llog01.h
   hob-netw-01.h hob-xsltime1.h hob-ipsec-01.h
*/
#define DEF_HL_CHARSET

enum ied_charset {                          /* define character set    */
   /* in the comments below the enum value lines, square brackets mean a
      "MIBenum" number, by which further reading can be looked up from
      http://www.iana.org/assignments/character-sets                   */
   ied_chs_invalid = 0,                     /* parameter is invalid    */

   ied_chs_ascii_850,                       /* ASCII 850               */
   /* [2009] "DOS-Multilingual"                                        */

   ied_chs_ansi_819,                        /* ANSI 819                */
   /* [4] ISO-8859-1, Latin1, iso-ir-100, other Windows-CP 28591       */

   ied_chs_utf_8,                           /* Unicode UTF-8           */
   /* [106] (specified in RFC 3629) Windows-CP 65001                   */

   ied_chs_utf_16,                          /* Unicode UTF-16 = WCHAR  */
   /* (mix of [1015]/[1000]) assumes native endianness of the machine  */

   ied_chs_be_utf_16,                       /* Unicode UTF-16 big endian */
   /* [1013] (two-byte-word encoding) Windows-CP 1201                  */

   ied_chs_le_utf_16,                       /* Unicode UTF-16 little endian */
   /* [1014] (two-byte-word encoding) Windows-CP 1200                  */

   ied_chs_utf_32,                          /* Unicode UTF-32          */
   /* [1001] assumes native endianness of the machine    */

   ied_chs_be_utf_32,                       /* Unicode UTF-32 big endian */
   /* [1018] (four-byte encoding) Windows-CP 65006                     */

   ied_chs_le_utf_32,                       /* Unicode UTF-32 little endian */
   /* [1019] (four-byte encoding) Windows-CP 65005                     */

   ied_chs_html_1,                          /* HTML character set      */
   /* e.g. "&uuml;", cf. www.w3.org/TR/html4/sgml/entities.html        */

   ied_chs_uri_1,                           /* URI                     */
   /* RFC 3986, e.g. encoding with percent sign like "?" to "%3F"      */

   ied_chs_idna_1,                          /* IDNA RFC 3492 etc. - Punycode */
   /* www.icann.org/en/resources/idn/rfcs,www.unicode.org/faq/idn.html */

   ied_chs_oem_437,                         /* DOS-Codepage 437        */
   /* [2011] "DOS-US"                                                  */

   ied_chs_wcp_874,                         /* Windows-Codepage  874   */
   /* [2109] (Thai)                                                    */

   ied_chs_wcp_1250,                        /* Windows-Codepage 1250   */
   /* [2250] (Central European)                                        */

   ied_chs_wcp_1251,                        /* Windows-Codepage 1251   */
   /* [2251] (Cyrillic)                                                */

   ied_chs_wcp_1252,                        /* Windows-Codepage 1252   */
   /* [2252] (Western European)                                        */

   ied_chs_wcp_1253,                        /* Windows-Codepage 1253   */
   /* [2253] (Greek)                                                   */

   ied_chs_wcp_1254,                        /* Windows-Codepage 1254   */
   /* [2254] (Turkish)                                                 */

   ied_chs_wcp_1255,                        /* Windows-Codepage 1255   */
   /* [2255] (Hebrew)                                                  */

   ied_chs_wcp_1256,                        /* Windows-Codepage 1256   */
   /* [2256] (Arabic)                                                  */

   ied_chs_wcp_1257,                        /* Windows-Codepage 1257   */
   /* [2257] (Baltic)                                                  */

   ied_chs_wcp_1258,                        /* Windows-Codepage 1258   */
   /* [2258] (Vietnamese)                                              */

   ied_chs_wcp_932,                         /* Windows-Codepage 932 (MBCS) */
   /* [2024] Windows-31J, "Microsoft Shift-JIS" (Japanese)             */

   ied_chs_wcp_936,                         /* Windows-Codepage 936 (MBCS) */
   /* [113] GBK (Mainland Chinese)                                     */

   ied_chs_wcp_949,                         /* Windows-Codepage 949 (MBCS) */
   /* "Unified Hangul Code (UHC)", "Extended Wansung" (Korean)         */

   ied_chs_wcp_950,                         /* Windows-Codepage 950 (MBCS) */
   /* (Taiwan/ Hongkong Chinese, resembles Big5 [2026])                */

   ied_chs_iso8859_2,                       /* ISO 8859-2              */
   /* [5] Latin2, iso-ir-101, Windows-CP 28592 (Central European)      */

   ied_chs_iso8859_3,                       /* ISO 8859-3              */
   /* [6] Latin3, iso-ir-109, Windows-CP 28593 (South European)        */

   ied_chs_iso8859_4,                       /* ISO 8859-4              */
   /* [7] Latin4, iso-ir-110, Windows-CP 28594 (North European/ Baltic) */

   ied_chs_iso8859_5,                       /* ISO 8859-5              */
   /* [8] iso-ir-144, Windows-CP 28595 (Cyrillic)                      */

   ied_chs_iso8859_6,                       /* ISO 8859-6              */
   /* [9] iso-ir-127, ECMA-114, ASMO-708, Windows-CP 28596 (Arabic)    */

   ied_chs_iso8859_7,                       /* ISO 8859-7              */
   /* [10] iso-ir-126, ELOT_928, ECMA-118, Greek8, Windows-CP 28597    */

   ied_chs_iso8859_8,                       /* ISO 8859-8              */
   /* [11] iso-ir-138, ISO_8859-8, Windows-CP 28598 (Hebrew)           */

   ied_chs_iso8859_9,                       /* ISO 8859-9              */
   /* [12] Latin5, iso-ir-148, Windows-CP 28599 (Turkish)              */

   ied_chs_iso8859_10,                      /* ISO 8859-10             */
   /* [13] Latin6, iso-ir-157 (Nordic)                                 */

   ied_chs_iso8859_11,                      /* ISO 8859-11             */
   /* (Thai, resembles TIS-620 [2259])                                 */

   ied_chs_iso8859_13,                      /* ISO 8859-13             */
   /* [109] Latin-7, Windows-CP 28603 (Baltic Rim/ Estonian)           */

   ied_chs_iso8859_14,                      /* ISO 8859-14             */
   /* [110] Latin8, iso-ir-199, iso-celtic                             */

   ied_chs_iso8859_15,                      /* ISO 8859-15             */
   /* [111] Latin-9, Windows-CP 28605                                  */

   ied_chs_iso8859_16                       /* ISO 8859-16             */
   /* [112] Latin10, iso-ir-226 (South-Eastern European)               */

   ied_chs_xml_utf_8,                       /**< XML Unicode UTF-8
    * ied_chs_utf_8 plus &apos; etc. (http://www.w3.org/TR/REC-xml 4.1/4.6) */

   ied_chs_xml_wcp_1252,                    /**< XML Windows-Codepage 1252
    * ied_chs_wcp_1252 plus &apos; etc., encoding="Windows-1252"       */

   ied_chs_xml_utf_16,                      /**< XML Unicode UTF-16
    * ied_chs_utf_16 plus &apos; etc.                                  */

   ied_chs_ldap_escaped_utf_8               /* LDAP UTF-8 escaped      */
};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif

#ifndef DEF_SCP
#define DEF_SCP
/* hob-xsclib01.h, hob-wspat3.h and hob-xbipgw08-2.h */
enum ied_scp_def {                          /* server-conf protocol    */
   ied_scp_undef,                           /* protocol undefined      */
   ied_scp_http,                            /* protocol HTTP           */
   ied_scp_rdp,                             /* protocol MS RDP         */
   ied_scp_hrdpe1,                          /* protocol HOB MS RDP Extension 1 */
   ied_scp_ica,                             /* protocol ICA            */
   ied_scp_ldap,                            /* protocol LDAP           */
   ied_scp_hoby,                            /* protocol HOB-Y          */
   ied_scp_3270,                            /* protocol IBM 3270       */
   ied_scp_5250,                            /* protocol IBM 5250       */
   ied_scp_vt,                              /* protocol VT (100 - 525) */
   ied_scp_socks5,                          /* protocol Socks-5        */
   ied_scp_ssh,                             /* protocol SSH Secure Shell */
   ied_scp_smb,                             /* protocol SMB server message block */
   ied_scp_hpppt1,                          /* protocol HOB-PPP-T1     */
   ied_scp_hvoip1,                          /* protocol HOB-VOIP-1     */
   ied_scp_krb5ts1,                         /* protocol KRB5TS1 Kerberos Ticket Service */
   ied_scp_sstp,                            /* protocol SSTP           */
   ied_scp_soap,                            /* protocol SOAP           */
   ied_scp_ms_rpc,                          /* protocol MS-RPC         */
   ied_scp_websocket,                       /* protocol WebSocket      */
   ied_scp_hl_dash,                         /* protocol HOBLink data share */
   ied_scp_rdg_out_d,                       /* protocol MS RDG_OUT_DATA */
   ied_scp_rdg_in_d,                        /* protocol MS RDG_IN_DATA */
   ied_scp_openvpn_1,                       /* protocol OpenVPN        */
   ied_scp_spec                             /* special protocol        */
};

#define DEF_MAX_LEN_PROT       64           /* maximum length protocol */

struct dsd_get_sc_prot_1 {                  /* get Server Entry Protocol */
   ied_charset iec_chs_scp;                 /* character set protocol  */
   void *     ac_scp;                       /* store protocol          */
   int        inc_len_scp;                  /* length of protocol in elements */
   ied_scp_def *aiec_scp_def;               /* server-conf protocol    */
};
#endif

#ifndef DEF_SET_DEF
#define DEF_SET_DEF
enum ied_set_def {                          /* server entry type       */
  ied_set_invalid = 0,                      /* entry is invalid        */
  ied_set_ss5h,                             /* SELECT-SOCKS5-HTTP      */
  ied_set_direct,                           /* connect direct to server */
  ied_set_loadbal,                          /* load balancing is used  */
  ied_set_pttd,                             /* pass-thru-to-desktop    */
  ied_set_casc_wsp,                         /* CASCADED-WSP            */
  ied_set_l2tp                              /* L2TP UDP connection     */
};
#endif

#ifdef XYZ1
enum en_at_funcauth { en_atfa_nothing, en_atfa_check_name, en_atfa_use_name };
enum en_at_typetarget { en_attt_ineta, en_attt_dns_name };
enum en_at_funcin { en_atfi_normal, en_atfi_connect_ok, en_atfi_connect_failed };
enum en_at_claddrtype { en_atca_IPV4, en_atca_IPV6 };
#endif
/* new 22.07.05 KB */
typedef void ( * amd_wspat3_proc )( struct dsd_wspat3_1 * );

/* other parameters - 25.07.05 KB */
typedef void ( * amd_wspat3_conf )( struct dsd_wspat3_1 * );

struct dsd_wspat3_conn {                    /* HOB Authentication Library V3 - Connect */
   enum ied_hconn_type iec_hconn;           /* Hook Connect            */
   struct dsd_unicode_string dsc_ucs_target;  /* INETA DNS / IPV4 / IPV6 */
// to-do 30.01.12 KB maybe struct sockaddr_storage should be included and used - with port ???
   int        imc_port;                     /* port to connect to      */
#ifdef OLD01
   char *     achc_service;                 /* address service IPV6    */
#endif
// to-do 01.02.12 KB IPV6 not supported - also wake-on-LAN packet
   UNSIG_MED  umc_out_ineta;                /* not filled yet          */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   struct dsd_unicode_string dsc_ucs_protocol;  /* protocol            */
   struct dsd_unicode_string dsc_ucs_server_entry;  /* Server Entry    */
#ifdef OLD01
   ied_charset iec_chs_servent_t;           /* character set target    */
   void *     ac_servent_target;            /* store Server Entry Name */
   int        inc_len_target;               /* length of target area in elements */
#endif
   void *     vpc_usent;                    /* user entry              */
   void *     vpc_usgro;                    /* user-group entry        */
   enum ied_set_def iec_set;                /* server entry type       */
#ifdef OLD01
   BOOL       boc_load_balancing;           /* do load-balancing first */
#endif
   /* fields for Pass-Thru-to-Desktop only                             */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        imc_waitconn;                 /* wait for connect compl  */
   void *     vpc_servent;                  /* handle to server entry  */
   enum ied_conn_ret iec_conn_ret;          /* return prepare + connect */
};

struct dsd_wspat3_1 {                       /* HOB Authentication Library V3 - 1 */
#ifdef OLD01
// inc_func;                     /* called function         */
   int        inc_func;                     /* called function         */
#endif
   enum ied_at_function iec_at_function;    /* input function of HOB-WSP-AT3 */
   enum ied_at_return iec_at_return;        /* return code             */
// int        inc_return;                   /* return code             */
   union {
     int      imc_connect_error;            /* connect error           */
// to-do 22.01.12 KB other fields may follow
   };

   char *     achc_work_area;               /* addr work-area          */
   int        imc_len_work_area;            /* length work-area        */

#ifdef OLD01
   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */
#endif
// new 27.11.11 KB
   struct dsd_gather_i_1 *adsc_gai1_in_from_client;  /* input data from client */
   struct dsd_gather_i_1 *adsc_gai1_in_from_server;  /* input data from server */
   struct dsd_gather_i_1 *adsc_gai1_out_to_client;  /* output data to client */
   struct dsd_gather_i_1 *adsc_gai1_out_to_server;  /* output data to server */

// 27.11.11 KB - whatfor needed ???
   void *     ac_exc_aux;                   /* auxiliary exchange area */
   int        imc_exc_aux;                  /* length auxiliary exchange area */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   int        imc_signal;                   /* signals occured         */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_language;                 /* language configured     */
   BOOL       boc_callagain;                /* call again              */
   BOOL       boc_server_connected;         /* connected to server     */
   BOOL       boc_eof_client;               /* End-of-File Client      */
   BOOL       boc_eof_server;               /* End-of-File Server      */
#ifdef XYZ1
   BOOL       boc_callrevdir;               /* call on reverse direction */
   BOOL       boc_eof_server;               /* End-of-File Server      */
#endif
};

/*
  parts used from xsclib01.h:
  enum ied_hlcldom_def
  struct dsd_hl_clib_dom_conf
  amd_hlclib_conf
*/
#endif
