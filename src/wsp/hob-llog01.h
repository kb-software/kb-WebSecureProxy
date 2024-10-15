/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-llog01.h                                        |*/
/*| -------------                                                     |*/
/*|  Header File for Log, HOB Framework                               |*/
/*|  KB 17.10.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#define D_MEM_LOG_MAX_LEN_REC 512

typedef void ( * amd_log_new_call )( struct dsd_log_new_call *, struct dsd_log_new_pass * );

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

};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif

enum ied_logreq1_def {                      /* log request 1 definition */
   ied_lreq1d_invalid,                      /* invalid value           */
   ied_lreq1d_cur_pos,                      /* return current position */
   ied_lreq1d_read_f,                       /* read forward            */
   ied_lreq1d_read_b,                       /* read backward           */
   ied_lreq1d_search_f,                     /* search forward          */
   ied_lreq1d_search_b,                     /* search backward         */
   ied_lreq1d_s_regex_f,                    /* search regular expression forward */
   ied_lreq1d_s_regex_b,                    /* search regular expression backward */
   ied_lreq1d_epoch_first,                  /* retrieve first position log with this epoch */
   ied_lreq1d_epoch_last                    /* retrieve last position log with this epoch */
};

enum ied_logreq1_ret {                      /* log request 1 definition */
   ied_lreq1r_ok,                           /* request processed o.k.  */
   ied_lreq1r_not_open,                     /* log not opened          */
   ied_lreq1r_invalid,                      /* request was invalid     */
   ied_lreq1r_eof,                          /* end of file found       */
   ied_lreq1r_invkey,                       /* search found nothing    */
   ied_lreq1r_pos_old                       /* position request too old */
};

struct dsd_log_requ_1 {                     /* memory log request      */
   ied_logreq1_def iec_logreq1_def;         /* request type            */
   ied_logreq1_ret iec_logreq1_ret;         /* return code request     */
   HL_LONGLONG ilc_position;                /* position where to read  */
   int        imc_count_filled;             /* count how often filled  */
#ifdef B100908
   int        imc_epoch;                    /* epoch / time of log record */
#endif
   HL_LONGLONG ilc_epoch;                   /* epoch / time of log record */
   int        imc_len_area;                 /* length of area to be filled */
   int        imc_len_record;               /* length of record returned */
   int        imc_len_search_a;             /* length of search area, elements */
   BOOL       boc_query_regex;              /* query is regular expression */
   ied_charset iec_chs_area;                /* character set area      */
   ied_charset iec_chs_search;              /* character set search    */
   char *     achc_area;                    /* area with log record    */
   char *     achc_search_a;                /* search key area         */
};

struct dsd_ml_search_1 {                    /* search in memory log    */
   char       *achc_cmp_str;                /* string to compare       */
   int        imc_len_cmp_str;              /* length string to compare */
   char       chc_fchar_1;                  /* first character first   */
   char       chc_fchar_2;                  /* first character second  */
};

struct dsd_log_new_pass {                   /* pass parameters new log message */
   HL_LONGLONG ilc_position;                /* position where to read  */
   int        imc_count_filled;             /* count how often filled  */
#ifdef B100908
   int        imc_epoch;                    /* epoch / time of log record */
#endif
   HL_LONGLONG ilc_epoch;                   /* epoch / time of log record */
   int        imc_msg_type;                 /* message type            */
   int        imc_len_record;               /* length of record returned */
   char *     achc_area;                    /* area with log record    */
};

struct dsd_log_new_call {                   /* parameters call new log message */
   struct dsd_log_new_call *adsc_next;      /* next in chain           */
   amd_log_new_call amc_log_new_call;       /* address callback routine */
};

extern PTYPE void m_mem_log_1_req( struct dsd_log_requ_1 * );
extern PTYPE BOOL m_search_utf8_1( char *, int, struct dsd_ml_search_1 * );
extern PTYPE BOOL m_log_new_p_register( struct dsd_log_new_call * );
extern PTYPE BOOL m_log_new_p_unreg( struct dsd_log_new_call * );
