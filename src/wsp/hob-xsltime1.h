/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsltime1                                            |*/
/*| -------------                                                     |*/
/*|  Header File of HOB Time Library                                  |*/
/*|    with date and time functions                                   |*/
/*|  KB 01.11.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef WIN32
#ifndef HL_WINALL1
#define HL_WINALL1
#endif
#endif
#ifdef WIN64
#ifndef HL_WINALL1
#define HL_WINALL1
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

   ied_chs_iso8859_16                       /* ISO 8859-16             */
   /* [112] Latin10, iso-ir-226 (South-Eastern European)               */

};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif

#ifndef DEF_HL_AUX_EPOCH_1
#define DEF_HL_AUX_EPOCH_1
enum ied_hl_aux_epoch_ret {
    ied_hl_aux_ep_failed = 0,               /* parsing failed          */
    ied_hl_aux_ep_ok,                       /* everything fine         */
    ied_hl_aux_ep_inv_format,               /* parsable but inv format */
    ied_hl_aux_ep_inv_mday,                 /* wrong monthday          */
    ied_hl_aux_ep_inv_wday,                 /* wrong weekday           */
	ied_hl_aux_ep_inv_year                  /* wrong year              */
};

struct dsd_hl_aux_epoch_1 {                 /* request compute epoch   */
   void *                    ac_epoch_str;  /* epoch                   */
   enum ied_charset          iec_chs_epoch; /* character set           */
   int                       inc_len_epoch; /* length epoch in elements */
   int                       imc_epoch_val; /* epoch value             */
   enum ied_hl_aux_epoch_ret iec_parse_ret; /* parser return           */
};
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif
extern PTYPE BOOL m_string_from_epoch( struct dsd_hl_aux_epoch_1 * );
extern PTYPE BOOL m_epoch_from_string( struct dsd_hl_aux_epoch_1 * );
#ifdef HL_WINALL1
extern PTYPE int m_win_epoch_from_filetime( struct _FILETIME * );
#endif
