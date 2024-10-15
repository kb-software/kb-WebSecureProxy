/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-netw-01.h                                       |*/
/*| -------------                                                     |*/
/*|  Header File for HOB Networking Functions                         |*/
/*|  KB 11.09.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifndef HL_UNIX
#ifndef HOB_DEF_SOCKLEN
#define HOB_DEF_SOCKLEN
typedef int socklen_t;
#endif
#endif
#ifdef XYZ1
#ifndef HL_UNIX
#ifndef UNSIG_MED
typedef unsigned int UNSIG_MED;
#endif
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif
#endif

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

   ied_chs_iso8859_16,                      /* ISO 8859-16             */
   /* [112] Latin10, iso-ir-226 (South-Eastern European)               */

   ied_chs_xml_utf_8,                       /* XML Unicode UTF-8       */

   ied_chs_xml_wcp_1252                     /* XML Windows-Codepage 1252 */
   /* encoding="Windows-1252"                                          */
};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif

#define HNETW_ERROR_INETA_BIND_INV          1
#define HNETW_ERROR_INETA_TARGET_INV        2
#define HNETW_ERROR_NO_MATCH_BIND_TARGET    3

/**
   The structures struct dsd_target_ineta_1
   and struct dsd_listen_ineta_1
   are followed by structures struct dsd_ineta_single_1
   and each followed by the corresponding INETA.
   These structures contain no pointers,
   so they can by copied to another area.
*/

struct dsd_target_ineta_1 {                 /* definition INETA target */
   int        imc_no_ineta;                 /* number of INETA         */
   int        imc_len_mem;                  /* length of memory including this structure */
};

struct dsd_listen_ineta_1 {                 /* definition INETA listen */
   int        imc_no_ineta;                 /* number of INETA         */
   int        imc_len_mem;                  /* length of memory including this structure */
};

struct dsd_chain_listen_ineta_1 {           /* chain INETA listen      */
   struct dsd_chain_listen_ineta_1 *adsc_next;  /* for chaining        */
   void *     vpc_work_1;                   /* needed for whatever     */
   struct dsd_target_ineta_1 dsc_listen_ineta_1;  /* definition INETA listen */
};

#ifndef DEF_HOB_INETA_S_1

/* hob-xsclib01.h and hob-netw-01.h */
#define DEF_HOB_INETA_S_1

struct dsd_ineta_single_1 {                 /* single INETA target / listen / configured */
   unsigned short int usc_family;           /* family IPV4 / IPV6      */
   unsigned short int usc_length;           /* length of following address */
};

#endif

//extern struct sockaddr_in6;

struct dsd_bind_ineta_1 {                   /* definition INETA bind   */
   BOOL       boc_bind_needed;              /* flag bind() is needed   */
   BOOL       boc_ipv4;                     /* IPV4 is supported       */
   BOOL       boc_ipv6;                     /* IPV6 is supported       */
   struct sockaddr_in dsc_soai4;            /* address information IPV4 */
   struct sockaddr_in6 dsc_soai6;           /* address information IPV6 */
};

//extern struct sockaddr_storage;

struct dsd_udp_param_1 {                    /* definition UDP parameter */
   int        imc_len_soa_bind;             /* length sockaddr bind    */
   int        imc_len_soa_target;           /* length sockaddr target  */
   struct sockaddr_storage dsc_soa_bind;    /* address information bind */
   struct sockaddr_storage dsc_soa_target;  /* address information target */
};

struct dsd_ineta_single_ret {               /* return single INETA     */
   unsigned short int usc_family;           /* family IPV4 / IPV6      */
   unsigned short int usc_length;           /* length of following address */
   char       chrc_ineta[16];               /* INETA returned          */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE struct dsd_target_ineta_1 * m_get_target_ineta( void *, int, enum ied_charset, struct dsd_bind_ineta_1 * );
extern PTYPE struct dsd_listen_ineta_1 * m_get_listen_ineta( void *, int, enum ied_charset );
extern PTYPE struct dsd_chain_listen_ineta_1 * m_get_chain_listen_ineta( void *, int, enum ied_charset );
extern PTYPE struct dsd_listen_ineta_1 * m_get_sum_chain_listen_ineta( struct dsd_chain_listen_ineta_1 * );
extern PTYPE BOOL m_get_single_ineta( int *, struct dsd_ineta_single_ret *, void *, int, enum ied_charset );
extern PTYPE int m_build_bind_ineta( struct dsd_bind_ineta_1 *, void *, int, enum ied_charset );
extern PTYPE int m_build_udp_param( struct dsd_udp_param_1 *, char *, void *, int, enum ied_charset, void *, int, enum ied_charset );
extern PTYPE int m_get_port_no( void *, int, enum ied_charset );
extern PTYPE void m_set_connect_p1( struct sockaddr_storage *, socklen_t *, struct dsd_target_ineta_1 *, int );
extern PTYPE BOOL m_cmp_ineta_1( struct sockaddr *, struct sockaddr * );
extern PTYPE void m_ineta_op_add( char *, int, int );
extern PTYPE void m_ineta_op_dec( char *, int );
extern PTYPE void m_ineta_op_inc( char *, int );
extern PTYPE int m_ineta_op_diff( char *,  char *, int );

#ifdef XYZ1
#undef D_TCP_ERROR
#undef D_TCP_CLOSE
#endif
#undef PTYPE
