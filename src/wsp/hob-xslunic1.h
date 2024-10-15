//#define SR
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xslunic1                                            |*/
/*| -------------                                                     |*/
/*|  Header File of HOB Unicode Library                               |*/
/*|  KB 01.11.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef B120813
#ifdef WIN32
#include <windows.h>
#endif
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifdef HL_UNIX
//typedef wchar_t WCHAR;
// typedef int BOOL;
//#define wchar_t HL_WCHAR
//#define HL_ULONG unsigned int
#endif

//#define XCERCES32                  /* flag to use 32 bit unicode for xcerces */
#define MAX_STR_LENGTH 2048
#define MAX_IDNAPART_LENGTH 63       /* RFC1034 max. length for a label (like e.g. "hobsoft") */
//#define ASCII_REP_CHAR (char)0x3F  /* character ?      */
#define HL_ERR_BASE64_INVCHS      (0X20000 + 1)  /* invalid character set */
#define HL_ERR_BASE64_INVCHAR     (0X20000 + 2)  /* invalid character  */
#define HL_ERR_BASE64_CHARADEL    (0X20000 + 3)  /* character after delimiter */
#define HL_ERR_BASE64_OUTOF       (0X20000 + 4)  /* overflow of output area */
#define HL_ERR_BASE64_INPSH       (0X20000 + 5)  /* input too short    */
#define HL_ERR_BASE64_INVDEL      (0X20000 + 6)  /* invalid number of delimiting characters */
#define HL_ERR_BASE64_MISC        (0X20000 + 7)  /* miscellaneous error */
#define HL_ERR_UCGETC_INPSH       (-1)           /* input too short */
#define HL_ERR_UCGETC_INV         (-2)           /* invalid data in input string */
#define HL_ERR_UCGETC_INVCHS      (-3)           /* invalid character set */
#define HL_ERR_UCGETC_META        (-4)           /* found data the caller should use otherwise */

/** @addtogroup unicode
* @{
* @file
* Header file of the unicode library.
* Note that to use the functions (defined in xslunic1.cpp) some sourcefile must
* include hob-tab-ascii-ansi-1.h as well (see comment there).
*/

#ifndef DEF_HL_CHARSET
/*
   hob-xsclib01.h hob-hlwspat2.h hob-rdpserver1.h hob-llog01.h
   hob-netw-01.h hob-xsltime1.h hob-xslunic1.h
*/
#define DEF_HL_CHARSET

/**
* define character set from a choice of standardised character encodings.
*
* In the comments for individual values, a number in square brackets indicates
* a "MIBenum" number, by which further reading can be looked up from
* http://www.iana.org/assignments/character-sets .
*/
enum ied_charset {
   ied_chs_invalid = 0,                     /**< parameter is invalid  */

   ied_chs_ascii_850,                       /**< ASCII 850
    * [2009] "DOS-Multilingual"                                        */

   ied_chs_ansi_819,                        /**< ANSI 819
    * [4] ISO-8859-1, Latin1, iso-ir-100, other Windows-CP 28591       */

   ied_chs_utf_8,                           /**< Unicode UTF-8
    * [106] (specified in RFC 3629) Windows-CP 65001                   */

   ied_chs_utf_16,                          /**< Unicode UTF-16 = WCHAR
    * (mix of [1015]/[1000]) assumes native endianness of the machine  */

   ied_chs_be_utf_16,                       /**< Unicode UTF-16 big endian
    * [1013] (two-byte-word encoding) Windows-CP 1201                  */

   ied_chs_le_utf_16,                       /**< Unicode UTF-16 little endian
    * [1014] (two-byte-word encoding) Windows-CP 1200                  */

   ied_chs_utf_32,                          /**< Unicode UTF-32
    * [1001] assumes native endianness of the machine    */

   ied_chs_be_utf_32,                       /**< Unicode UTF-32 big endian
    * [1018] (four-byte encoding) Windows-CP 65006                     */

   ied_chs_le_utf_32,                       /**< Unicode UTF-32 little endian
    * [1019] (four-byte encoding) Windows-CP 65005                     */

   ied_chs_html_1,                          /**< HTML character set
    * like "&uuml;", see http://www.w3.org/TR/html4/sgml/entities.html */

   ied_chs_uri_1,                           /**< URI
    * RFC 3986, like encoded with percent sign from "?" to "%3F"       */

   ied_chs_idna_1,                          /**< IDNA RFC 3492 etc; Punycode
    * www.icann.org/en/resources/idn/rfcs,www.unicode.org/faq/idn.html */

   ied_chs_oem_437,                         /**< DOS-Codepage 437
    * [2011] "DOS-US"                                                  */

   ied_chs_wcp_874,                         /**< Windows-Codepage  874
    * [2109] (Thai)                                                    */

   ied_chs_wcp_1250,                        /**< Windows-Codepage 1250
    * [2250] (Central European)                                        */

   ied_chs_wcp_1251,                        /**< Windows-Codepage 1251
    * [2251] (Cyrillic)                                                */

   ied_chs_wcp_1252,                        /**< Windows-Codepage 1252
    * [2252] (Western European)                                        */

   ied_chs_wcp_1253,                        /**< Windows-Codepage 1253
    * [2253] (Greek)                                                   */

   ied_chs_wcp_1254,                        /**< Windows-Codepage 1254
    * [2254] (Turkish)                                                 */

   ied_chs_wcp_1255,                        /**< Windows-Codepage 1255
    * [2255] (Hebrew)                                                  */

   ied_chs_wcp_1256,                        /**< Windows-Codepage 1256
    * [2256] (Arabic)                                                  */

   ied_chs_wcp_1257,                        /**< Windows-Codepage 1257
    * [2257] (Baltic)                                                  */

   ied_chs_wcp_1258,                        /**< Windows-Codepage 1258
    * [2258] (Vietnamese)                                              */

   ied_chs_wcp_932,                         /**< Windows-Codepage 932 (MBCS)
    * [2024] Windows-31J, "Microsoft Shift-JIS" (Japanese)             */

   ied_chs_wcp_936,                         /**< Windows-Codepage 936 (MBCS)
    * [113] GBK (Mainland Chinese)                                     */

   ied_chs_wcp_949,                         /**< Windows-Codepage 949 (MBCS)
    * "Unified Hangul Code (UHC)", "Extended Wansung" (Korean)         */

   ied_chs_wcp_950,                         /**< Windows-Codepage 950 (MBCS)
    * (Taiwan/ Hongkong Chinese, resembles Big5 [2026])                */

   ied_chs_iso8859_2,                       /**< ISO 8859-2
    * [5] Latin2, iso-ir-101, Windows-CP 28592 (Central European)      */

   ied_chs_iso8859_3,                       /**< ISO 8859-3
    * [6] Latin3, iso-ir-109, Windows-CP 28593 (South European)        */

   ied_chs_iso8859_4,                       /**< ISO 8859-4
    * [7] Latin4, iso-ir-110, Windows-CP 28594 (North European/ Baltic) */

   ied_chs_iso8859_5,                       /**< ISO 8859-5
    * [8] iso-ir-144, Windows-CP 28595 (Cyrillic)                      */

   ied_chs_iso8859_6,                       /**< ISO 8859-6
    * [9] iso-ir-127, ECMA-114, ASMO-708, Windows-CP 28596 (Arabic)    */

   ied_chs_iso8859_7,                       /**< ISO 8859-7
    * [10] iso-ir-126, ELOT_928, ECMA-118, Greek8, Windows-CP 28597    */

   ied_chs_iso8859_8,                       /**< ISO 8859-8
    * [11] iso-ir-138, ISO_8859-8, Windows-CP 28598 (Hebrew)           */

   ied_chs_iso8859_9,                       /**< ISO 8859-9
    * [12] Latin5, iso-ir-148, Windows-CP 28599 (Turkish)              */

   ied_chs_iso8859_10,                      /**< ISO 8859-10
    * [13] Latin6, iso-ir-157 (Nordic)                                 */

   ied_chs_iso8859_11,                      /**< ISO 8859-11
    * (Thai, resembles TIS-620 [2259])                                 */

   ied_chs_iso8859_13,                      /**< ISO 8859-13
    * [109] Latin-7, Windows-CP 28603 (Baltic Rim/ Estonian)           */

   ied_chs_iso8859_14,                      /**< ISO 8859-14
    * [110] Latin8, iso-ir-199, iso-celtic                             */

   ied_chs_iso8859_15,                      /**< ISO 8859-15
    * [111] Latin-9, Windows-CP 28605                                  */

   ied_chs_iso8859_16,                      /**< ISO 8859-16
    * [112] Latin10, iso-ir-226 (South-Eastern European)               */

   ied_chs_xml_utf_8,                       /**< XML Unicode UTF-8
    * ied_chs_utf_8 plus &apos; etc. (http://www.w3.org/TR/REC-xml 4.1/4.6) */

   ied_chs_xml_wcp_1252,                    /**< XML Windows-Codepage 1252
    * ied_chs_wcp_1252 plus &apos; etc., encoding="Windows-1252"       */

   ied_chs_xml_utf_16,                      /**< XML Unicode UTF-16
    * ied_chs_utf_16 plus &apos; etc.                                  */

   ied_chs_ldap_escaped_utf_8,              /**< LDAP UTF-8 escaped
    * RFC 4514 AttributeValue encoded, without the context-sensitive rules */

   ied_chs_hsf_1                            /**< HOB special file system
    * underscore-escaped                                               */
};

/** unicode string                                                     */
struct dsd_unicode_string {
   void *     ac_str;                       /**< address of string     */
   int        imc_len_str;                  /**< length of string in elements */
   enum ied_charset iec_chs_str;            /**< character set of string */
};
#endif

/** retrieve next unicode character                                    */
struct dsd_get_unicode_char {
   BOOL       boc_eof;                      /**< last unicode character retrieved */
   BOOL       boc_error;                    /**< error occured         */
   enum ied_charset iec_chs_out;            /**< character set output  */
   void *     ac_out;                       /**< address of output area */
   int        imc_len_out_bytes;            /**< length of output data in bytes */
   struct dsd_unicode_string *adsc_unicode_string;  /**< unicode string */
   char       *achc_next_char;              /**< next character, set to NULL when first called */
   char       *achc_last_char;              /**< end of input bytes    */
};

/** a character property, see ArabicShaping.txt on unicode.org         */
enum ied_unicode_joining_type {
   ied_unijointyp_t,                        /**< Transparent           */
   ied_unijointyp_u,                        /**< Non_Joining           */
   ied_unijointyp_l,                        /**< Left_Joining          */
   ied_unijointyp_d,                        /**< Dual_Joining          */
   ied_unijointyp_r,                        /**< Right_Joining         */
   ied_unijointyp_c                         /**< Join_Causing          */
};

extern PTYPE BOOL m_cmpi_u8l_u8l( int *, const char *, int, const char *, int );
extern PTYPE BOOL m_cmpi_u16z_u8l( int *, const HL_WCHAR *, const char *, int );
extern PTYPE int m_cmpi_u16z_u16z( const HL_WCHAR *, const HL_WCHAR * );
extern PTYPE BOOL m_cmp_u16z_u8z( int *, const HL_WCHAR *, const char * );
#ifdef HL_UNIX
extern PTYPE int m_cmp_u16z_u16z( const HL_WCHAR *, const HL_WCHAR * );
extern PTYPE int m_len_u16z( const HL_WCHAR * );
#endif
/* perform a comparison of strings, give type of string                */
extern PTYPE BOOL m_cmp_vx_vx( int *aimp_result,
                               const void *ap_p1, int imp_len_p1, enum ied_charset iep_cs_p1,
                               const void *ap_p2, int imp_len_p2, enum ied_charset iep_cs_p2 );
extern PTYPE BOOL m_cmpi_vx_vx( int *aimp_result,
                                const void *ap_p1, int imp_len_p1, enum ied_charset iep_cs_p1,
                                const void *ap_p2, int imp_len_p2, enum ied_charset iep_cs_p2 );
extern PTYPE BOOL m_cmp_wc_i_vx_vx( int *aimp_result,
                                    const void *ap_p1, int imp_len_p1, enum ied_charset iep_cs_p1,
                                    const void *ap_p2, int imp_len_p2, enum ied_charset iep_cs_p2 );
extern PTYPE int m_cpy_vx_vx_fl( void *ap_target,                int imp_len_target,
                                 enum ied_charset iep_cs_target,
                                 const void *ap_source,          int imp_len_source,
                                 enum ied_charset iep_cs_source, unsigned int ibp_flags );
extern PTYPE int m_cpy_lc_vx_vx_fl( void *ap_target,             int imp_len_target,
                                 enum ied_charset iep_cs_target,
                                 const void *ap_source,          int imp_len_source,
                                 enum ied_charset iep_cs_source, unsigned int ibp_flags );
extern PTYPE int m_cpy_uc_vx_vx_fl( void *ap_target,             int imp_len_target,
                                 enum ied_charset iep_cs_target,
                                 const void *ap_source,          int imp_len_source,
                                 enum ied_charset iep_cs_source, unsigned int ibp_flags );
#ifndef m_cpy_vx_vx
#define m_cpy_vx_vx(   P0,P1,P2,P3,P4,P5) m_cpy_vx_vx_fl(   (P0),(P1),(P2),(P3),(P4),(P5),0)
#define m_cpy_lc_vx_vx(P0,P1,P2,P3,P4,P5) m_cpy_lc_vx_vx_fl((P0),(P1),(P2),(P3),(P4),(P5),0)
#define m_cpy_uc_vx_vx(P0,P1,P2,P3,P4,P5) m_cpy_uc_vx_vx_fl((P0),(P1),(P2),(P3),(P4),(P5),0)
#define D_CPYVXVX_FL_NOTAIL0 0x00000001  /** Flag for m_cpy*_vx_vx_fl: do not zero-terminate */
#endif
extern PTYPE const char * m_get_name_chs( enum ied_charset );
extern PTYPE int m_cs_elem_size( enum ied_charset );
extern PTYPE BOOL m_to_lc_inplace( void *ap_p, int imp_len, enum ied_charset iep_cs );
extern PTYPE BOOL m_to_uc_inplace( void *ap_p, int imp_len, enum ied_charset iep_cs );
extern PTYPE void m_tolowercase_inplace_u32c(unsigned int *aump_c);
extern PTYPE void m_touppercase_inplace_u32c(unsigned int *aump_c);
extern PTYPE int m_len_vx_vx( enum ied_charset iep_cs_target,
                              const void *ap_source, int imp_len_source, enum ied_charset iep_cs_source );
extern PTYPE int m_stor_vx( const void *ap_source, int imp_len_source, enum ied_charset iep_cs_source );
extern PTYPE int m_len_bytes_vx( const void *ap_source, int imp_len_source, enum ied_charset iep_cs_source );
extern PTYPE BOOL m_check_vx( const void *ap_source, int imp_len_source, enum ied_charset iep_cs_source );
extern PTYPE BOOL m_cmp_ucs_ucs( int *aimp_result, const struct dsd_unicode_string *adsp_us_p1,
                                                   const struct dsd_unicode_string *adsp_us_p2 );
extern PTYPE BOOL m_cmpi_ucs_ucs( int *aimp_result, const struct dsd_unicode_string *adsp_us_p1,
                                                    const struct dsd_unicode_string *adsp_us_p2 );
extern PTYPE int m_cpy_vx_ucs( void *ap_target, int imp_len_target, enum ied_charset iep_cs_target,
                               const struct dsd_unicode_string *adsp_usc_source );
extern PTYPE int m_cpy_uc_vx_ucs( void *ap_target, int imp_len_target, enum ied_charset iep_cs_target,
                                  const struct dsd_unicode_string *adsp_usc_source );
extern PTYPE int m_len_vx_ucs( enum ied_charset iep_cs_target, const struct dsd_unicode_string *adsp_usc_source );
extern PTYPE int m_len_bytes_ucs( const struct dsd_unicode_string *adsp_usc_source );
extern PTYPE int m_get_ucs_base64( int *aimp_error, int *aimp_pos_error, char *achp_target,
                                   int imp_len_target, const struct dsd_unicode_string *adsp_usc_source );
/*extern PTYPE int m_loc_subs_i( int *ainp_results, const struct dsd_unicode_string *adsp_uca_a,
                               const struct dsd_unicode_string *adsp_usc_subs, int inp_subscount, int inp_findhowmany );*/
extern PTYPE int m_u8l_from_u16z( char *achp_target, int inp_max_len_target, const HL_WCHAR *au16p_source );
extern PTYPE int m_u8l_from_u16l( char *achp_target, int inp_max_len_target, const HL_WCHAR *awcp_source, int inp_len_source );
extern PTYPE int m_u16l_from_u8l( HL_WCHAR *awcp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
extern PTYPE int m_u16z_from_u8l( HL_WCHAR *awcp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
extern PTYPE int m_sbc_from_u16z( char *achp_target, int inp_max_chars, const HL_WCHAR *au16p_source, enum ied_charset );
extern PTYPE int m_sbc_from_u8l( char *achp_target, int inp_max_len_target, const char *au8p_source, enum ied_charset );
extern PTYPE int m_sbc_from_u32z( char *achp_target, int inp_max_chars, const int *inp_source, enum ied_charset );
extern PTYPE int m_a819l_from_u8l( char *achp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
extern PTYPE int m_a850l_from_u8l( char *achp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
extern PTYPE int m_u8l_from_a819l( char *achp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
extern PTYPE int m_u8l_from_a850l( char *achp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
#ifdef XSLUNIC_OBSOLETE_EXTERNS
extern PTYPE int m_u8l_from_a437l( char *achp_target, int inp_max_len_target, const char *achp_source, int inp_len_source );
#endif
extern PTYPE int m_count_utf8_from_a819l( const char *achp_source, int inp_len_source );
extern PTYPE BOOL m_count_u16_from_u8l( int *, const char *achp_source, int inp_len_source );
extern PTYPE int m_count_with_mb( const char *achp_source, enum ied_charset iep_cs, int inp_max_bytes );
extern PTYPE int m_count_wchar_z_to_utf8( const HL_WCHAR * awcp1 );
extern PTYPE int m_trans_wchar_z_to_utf8( char * achptarget, const HL_WCHAR * awcp1 );
extern PTYPE int m_get_wc_number( const HL_WCHAR * awcp1 );
extern PTYPE int m_get_ucs_number( const struct dsd_unicode_string * );
extern PTYPE HL_LONGLONG m_get_bytes_no( const HL_WCHAR * );
extern PTYPE HL_LONGLONG m_get_ucs_bytes_no( const struct dsd_unicode_string * );
extern PTYPE int m_rfc4514unmask( char *achp_buf, char *achp_end_buf,
                                  struct dsd_unicode_string *adsp_usc_rdn );
extern PTYPE int m_len_vx_ucsarray( enum ied_charset iep_cs_target,
                                    const struct dsd_unicode_string *adsp_sep, int inp_count,
                                    const struct dsd_unicode_string *dsrp_srcparts );
extern PTYPE int m_cpy_vx_ucsarray( char *achp_target, int inp_max_len_target,
                                    enum ied_charset iep_cs_target,
                                    const struct dsd_unicode_string *adsp_sep, int inp_count,
                                    const struct dsd_unicode_string *dsrp_srcparts );
extern PTYPE void m_get_unicode_char( struct dsd_get_unicode_char * );
extern PTYPE int m_get_vc_ch_ex( unsigned int *ump_res, const char *achp_start,
                                 const char *achp_end, enum ied_charset iep_cs );
extern PTYPE int m_hlsnprintf( void *, int, enum ied_charset, const char *, ... );
extern PTYPE int m_hlvsnprintf( void *, int, enum ied_charset, const char *, va_list );
extern PTYPE int m_hlvsnwprintf( void *, int, enum ied_charset, const char *, va_list );
/** @} */
