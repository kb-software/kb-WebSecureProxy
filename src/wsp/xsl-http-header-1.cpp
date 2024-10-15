/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsl-http-header-1.pre                               |*/
/*| -------------                                                     |*/
/*|  program for processing of HTTP headers                           |*/
/*|    on server side and on client side                              |*/
/*|  part of HOB Framework                                            |*/
/*|  KB + Alexander Urlaub 31.08.12                                   |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   do not edit xsl-http-header-1.cpp
   generated from xsl-http-header-1.pre by
     xbprecomp01.exe xsl-http-header-1.pre xsl-http-header-1.cpp
*/
/**
   RFC 2616
     Hypertext Transfer Protocol -- HTTP/1.1
   RFC 1738
     Uniform Resource Locators (URL)
*/
/**
   HTTP option fields,
   in HOB Web Server Gate,
   option fields that are sent unchanged to the other side
   in HTTP server:
     not sent to other side - to real web server
     URL
     Host:
     Cookie:
     HOB-Cookie:
     Authorization:
*/

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif




/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

//#ifndef HL_LINUX
#ifdef HL_UNIX
#include <unistd.h>
#endif
//#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
//#include <Iptypes.h>
//#include <Iphlpapi.h>
#else
#include <hob-unix01.h>
#endif
//#include <hob-xslunic1.h>
//#include <hob-netw-01.h>
//#include <hob-tab-ascii-ansi-1.h>
#define EXT_BASE64
#include <hob-tab-mime-base64.h>
#include "hob-http-header-1.h"
#ifdef HL_SDH
#include "hob-stor-sdh.h"
#endif

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#define DEF_HTTP_BLANK_TAB     4            /* size blank table        */

#define ADLER_BASE             65521        /* largest prime smaller than 65536 */
static int m_calc_adler( char *achp_buffer, int imp_len_buffer );
static int m_calc_zt_adler( const char *achp_buffer );


static HL_LONGLONG ils_http_c1 = 0X0000000048545450;

static HL_LONGLONG ils_ntlm_c1 = 0X000000004E544C4D;

struct dsd_http_method_def_tab {            /* HTTP method definition  */
   const char *achc_name;
   int        imc_len_name;                 /* length of name          */
   enum ied_http_method iec_hme;            /* HTTP method             */
};

enum ied_http_parse_opt1 {                  /* HTTP parsing options    */
   ied_hpo_user_agent = 0,                  /* User-Agent              */
   ied_hpo_accept_plain,                    /* Accept                  */
   ied_hpo_accept_language,                 /* Accept-Language         */
   ied_hpo_accept_encoding,                 /* Accept-Encoding         */
   ied_hpo_authorization,                   /* Authorization           */
   ied_hpo_connection,                      /* Connection              */
   ied_hpo_transfer_encoding,               /* Transfer-Encoding       */
   ied_hpo_upgrade,                         /* Upgrade                 */
   ied_hpo_host,                            /* Host                    */
   ied_hpo_origin,                          /* Origin                  */
   ied_hpo_dnt,                             /* DNT                     */
   ied_hpo_cookie,                          /* Cookie                  */
   ied_hpo_hob_cookie,                      /* HOB-Cookie              */
   ied_hpo_rdg_conn_id,                     /* RDG-Connection-Id       */
   ied_hpo_content_length,                  /* Content-Length          */
   ied_hpo_sec_webso_origin,                /* Sec-WebSocket-Origin    */
   ied_hpo_sec_webso_key,                   /* Sec-WebSocket-Key       */
   ied_hpo_sec_webso_prot,                  /* Sec-WebSocket-Protocol  */
   ied_hpo_sec_webso_version,               /* Sec-WebSocket-Version   */
   ied_hpo_sec_webso_ext                    /* Sec-WebSocket-Extensions */
};


struct dsd_http_parse_opt1_def_tab {        /* HTTP parsing options definition */
   int        imc_hash_name;
   enum ied_http_parse_opt1 iec_hpo;        /* HTTP parsing options    */
};

struct dsd_http_parse_connection_def_tab {  /* HTTP connection         */
   int        imc_hash_name;
   enum ied_http_connection iec_hcon;       /* HTTP connection         */
};

struct dsd_http_parse_transfer_encoding_def_tab {  /* HTTP Transfer-Encoding */
   int        imc_hash_name;
   enum ied_http_transfer_encoding iec_htre;  /* HTTP Transfer-Encoding */
};

struct dsd_http_parse_upgrade_def_tab {     /* HTTP upgrade            */
   int        imc_hash_name;
   enum ied_http_upgrade iec_hupg;          /* HTTP upgrade            */
};

static const struct dsd_http_method_def_tab dsrs_http_method_def_tab[] = {
   { "GET", 3, ied_hme_get },
   { "OPTIONS", 7, ied_hme_options },
   { "HEAD", 4, ied_hme_head },
   { "POST", 4, ied_hme_post },
   { "PUT", 3, ied_hme_put },
   { "DELETE", 6, ied_hme_delete },
   { "TRACE", 5, ied_hme_trace },
   { "CONNECT", 7, ied_hme_connect },
   { "BDELETE", 7, ied_hme_bdelete },
   { "BMOVE", 5, ied_hme_bmove },
   { "BPROPPATCH", 10, ied_hme_bproppatch },
   { "COPY", 4, ied_hme_copy },
   { "LOCK", 4, ied_hme_lock },
   { "MKCOL", 5, ied_hme_mkcol },
   { "MOVE", 4, ied_hme_move },
   { "POLL", 4, ied_hme_poll },
   { "PROPFIND", 8, ied_hme_propfind },
   { "PROPPATCH", 9, ied_hme_proppatch },
   { "SUBSCRIBE", 9, ied_hme_subscribe },
   { "SEARCH", 6, ied_hme_search },
   { "SSTP_DUPLEX_POST", 16, ied_hme_sstp },
   { "RPC_OUT_DATA", 12, ied_hme_ms_rpc },
   { "RPC_IN_DATA", 11, ied_hme_ms_rpc },
   { "RDG_OUT_DATA", 12, ied_hme_rdg_out_data },
   { "RDG_IN_DATA", 11, ied_hme_rdg_in_data },
};

/* message header                                                      */
static const struct dsd_http_parse_opt1_def_tab dsrs_http_parse_opt1_def_tab[] = {
// Cache-Control: max-age=0
// Cache-Control: no-cache
// Pragma: no-cache
// RDG-Connection-Id:
// Content-Type:
// Content-Length:
// Referer:
// Access-Control-Request-Method:
// Access-Control-Request-Headers: x-svn-rev
// X-SVN-Rev: 755744
   { (unsigned int) 0X02DC0120, ied_hpo_dnt },
   { (unsigned int) 0X059F01D8, ied_hpo_host },
   { (unsigned int) 0X0A0E028A, ied_hpo_accept_plain },
   { (unsigned int) 0X0A850294, ied_hpo_cookie },
   { (unsigned int) 0X0ACF02A2, ied_hpo_origin },
   { (unsigned int) 0X0E100302, ied_hpo_upgrade },
   { (unsigned int) 0X146D039A, ied_hpo_hob_cookie },
   { (unsigned int) 0X180603F5, ied_hpo_user_agent },
   { (unsigned int) 0X19E5044A, ied_hpo_connection },
   { (unsigned int) 0X2AEE05AB, ied_hpo_authorization },
   { (unsigned int) 0X2DBE05A4, ied_hpo_content_length },
   { (unsigned int) 0X317C05DE, ied_hpo_accept_encoding },
   { (unsigned int) 0X318C05DB, ied_hpo_accept_language },
   { (unsigned int) 0X39C7062E, ied_hpo_rdg_conn_id },
   { (unsigned int) 0X3C76065F, ied_hpo_sec_webso_key },
   { (unsigned int) 0X41EE06D3, ied_hpo_transfer_encoding },
   { (unsigned int) 0X52B2079E, ied_hpo_sec_webso_origin },
   { (unsigned int) 0X5B44081C, ied_hpo_sec_webso_version },
   { (unsigned int) 0X64120888, ied_hpo_sec_webso_prot },
   { (unsigned int) 0X769D0966, ied_hpo_sec_webso_ext },
};

/* connection                                                          */
static const struct dsd_http_parse_connection_def_tab dsrs_http_parse_conn_def_tab[] = {
   { (unsigned int) 0X152203E3, ied_hcon_keep_alive },
   { (unsigned int) 0X0B0E02C8, ied_hcon_upgrade },
};

/* Transfer-Encoding                                                   */
static const struct dsd_http_parse_transfer_encoding_def_tab dsrs_http_parse_transfer_encoding_def_tab[] = {
   { (unsigned int) 0X0B9502E2, ied_htre_chunked },
};

/* Upgrade                                                             */
static const struct dsd_http_parse_upgrade_def_tab dsrs_http_parse_upgrade_def_tab[] = {
   { (unsigned int) 0X12ED03C7, ied_hupg_websocket },
// change 11.08.14 KB - MS IE 11
   { (unsigned int) 0X11CD03A7, ied_hupg_websocket },
};

/* Sec-WebSocket-Extensions: x-webkit-deflate-frame                    */
static const int ims_sec_webso_ext_deflate = (unsigned int) 0X60090865;

/* Sec-WebSocket-Extensions: permessage-deflate                        */
static const int ims_sec_webso_ext_per_mess_def = (unsigned int) 0X4537072E;

/* Sec-WebSocket-Extensions - permessage-deflate - c2s_max_window_bits */
static const int ims_sec_webso_ext_pmd_c2s_max_window_bits = (unsigned int) 0X4AAE07B5;

/* Sec-WebSocket-Extensions - permessage-deflate - client_max_window_bits */
static const int ims_sec_webso_ext_pmd_cli_max_window_bits = (unsigned int) 0X62AD10B5;

static int imrs_http_ua_word_tab[] = {
   (unsigned int) 0X03BA017E,
   (unsigned int) 0X08340263,
   (unsigned int) 0X0A9A02C1,
   (unsigned int) 0X4A6A0753,
   (unsigned int) 0X0B1402DA
};

#define CH_TYPE_UNDEF        0              /* undefined character     */
#define CH_TYPE_CR           1              /* carriage-return         */
#define CH_TYPE_LF           2              /* line-feed               */
#define CH_TYPE_DIGIT        3              /* numeric digit           */
#define CH_TYPE_ALPHA_LOWER  4              /* alphanumeric lowercase  */
#define CH_TYPE_ALPHA_UPPER  5              /* alphanumeric uppercase  */
#define CH_TYPE_SPECIAL      6              /* special character       */
#define CH_TYPE_SEPARATOR    7              /* separator               */

static unsigned char ucrs_tab_char[256] = {

/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 0x */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 0x */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_LF,          CH_TYPE_UNDEF,         /* 0x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_CR,          CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 0x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 1x */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 1x */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 1x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 1x */
/*   0                    1                    2                    3 */
   CH_TYPE_SEPARATOR,   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 2x */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 2x */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 2x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_SPECIAL,     CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 2x */
/*   0                    1                    2                    3 */
   CH_TYPE_DIGIT,       CH_TYPE_DIGIT,       CH_TYPE_DIGIT,       CH_TYPE_DIGIT,         /* 3x */
/*   4                    5                    6                    7 */
   CH_TYPE_DIGIT,       CH_TYPE_DIGIT,       CH_TYPE_DIGIT,       CH_TYPE_DIGIT,         /* 3x */
/*   8                    9                    A                    B */
   CH_TYPE_DIGIT,       CH_TYPE_DIGIT,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 3x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 3x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 4x */
/*   4                    5                    6                    7 */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 4x */
/*   8                    9                    A                    B */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 4x */
/*   C                    D                    E                    F */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 4x */
/*   0                    1                    2                    3 */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 5x */
/*   4                    5                    6                    7 */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER,   /* 5x */
/*   8                    9                    A                    B */
   CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_ALPHA_UPPER, CH_TYPE_UNDEF,         /* 5x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 5x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 6x */
/*   4                    5                    6                    7 */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 6x */
/*   8                    9                    A                    B */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 6x */
/*   C                    D                    E                    F */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 6x */
/*   0                    1                    2                    3 */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 7x */
/*   4                    5                    6                    7 */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER,   /* 7x */
/*   8                    9                    A                    B */
   CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_ALPHA_LOWER, CH_TYPE_UNDEF,         /* 7x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 7x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 8x */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 8x */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 8x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 8x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 9x */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 9x */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 9x */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* 9x */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ax */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ax */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ax */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ax */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Bx */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Bx */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Bx */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Bx */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Cx */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Cx */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Cx */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Cx */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Dx */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Dx */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Dx */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Dx */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ex */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ex */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ex */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Ex */
/*   0                    1                    2                    3 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Fx */
/*   4                    5                    6                    7 */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Fx */
/*   8                    9                    A                    B */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,         /* Fx */
/*   C                    D                    E                    F */
   CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF,       CH_TYPE_UNDEF          /* Fx */
};

#ifndef HL_SDH
//*IF NDF CALLBACK$STORE;
#define ADSL_STOR_G (adsp_chhs1->ac_stor_1)  /* storage management     */
//*IFF;
//*#define ADSL_STOR_G adsp_chhs1->ac_stor_1   /* storage management      */
//*CEND;
#define ADSL_STOR_CHECK adsp_chhs1->ac_stor_1  /* storage management   */
#else
#define ADSL_STOR_G adsp_chhs1->adsc_stor_sdh_1  /* storage management */
#define ADSL_STOR_CHECK adsp_chhs1->adsc_stor_sdh_1  /* storage management */
#endif

extern "C" BOOL m_proc_http_header_server( const struct dsd_proc_http_header_server_1 *adsp_phhs1,
                                           struct dsd_call_http_header_server_1 *adsp_chhs1,  /* call HTTP processing at server */
                                           struct dsd_http_header_server_1 *adsp_rhs1 ) {  /* HTTP processing at server */
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   int        iml_read_pos;                 /* position read           */
   int        iml_state;                    /* state CR / LF           */
   int        iml_blank_tab;                /* position blank table    */
   int        iml_adler_1;                  /* calculate hash          */
   int        iml_adler_2;                  /* calculate hash          */
   BOOL       bol_consume_input_01;         /* consume input           */
   BOOL       bol_consume_input_02;         /* consume input           */
   BOOL       bol_pass_os;                  /* option to pass to other side */
   enum ied_http_parse_opt1 iel_hpo;        /* HTTP parsing options    */
   int        imrl_hbt[ DEF_HTTP_BLANK_TAB ];  /* blank table          */
   HL_LONGLONG ill_w1;                      /* working variable        */
   char       *achl_w1, *achl_w2, *achl_w3;  /* working variables      */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of this part        */
   char       *achl_pos;                    /* start input options to pass to other side */
   struct dsd_gather_i_1 *adsl_gai1_rp;     /* gather input read pointer */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input working variable */
   struct dsd_gather_i_1 *adsl_gai1_pos;    /* gather input options to pass to other side */
   struct dsd_http_pass_os **aadsl_ht_pos;  /* chain of HTTP option to pass to other side */
   struct dsd_http_cookie **aadsl_ht_cookie;  /* last in chain of Cookies */
   char       chrl_work1[ 512 ];            /* work area               */

   memset( adsp_rhs1, 0, sizeof(struct dsd_http_header_server_1) );  /* HTTP processing at server */
   adsl_gai1_rp = adsp_chhs1->adsc_gai1_in;  /* gather input data      */
   iml_read_pos = 0;                        /* position read           */
   iml_state = 0;                           /* state CR / LF           */
   iml_blank_tab = 0;                       /* position blank table    */

   p_pone_00:                               /* pass one start          */
   if (adsl_gai1_rp == NULL) return TRUE;
   if (iml_read_pos >= MAX_LEN_HTTP_HEADER) {
     adsp_chhs1->imc_error = HTTP_ERROR_HEADER_TOO_LONG;
     return FALSE;
   }
   achl_rp = adsl_gai1_rp->achc_ginp_cur;   /* read pointer            */
   iml_read_pos += adsl_gai1_rp->achc_ginp_end - adsl_gai1_rp->achc_ginp_cur;

   p_pone_20:                               /* pass one character      */
   if (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* at end of gather  */
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     goto p_pone_00;                        /* pass one start          */
   }
   if (*achl_rp == CHAR_CR) {               /* carriage-return         */
     if ((iml_state & 1) == 0) {            /* state CR / LF           */
       iml_state++;                         /* next state CR / LF      */
     } else {
       iml_state = 1;                       /* state CR / LF after CR  */
     }
   } else if (*achl_rp == CHAR_LF) {        /* line-feed               */
     if ((iml_state & 1) != 0) {            /* state CR / LF           */
       iml_state++;                         /* next state CR / LF      */
       if (iml_blank_tab >= 0) {            /* position blank table    */
         imrl_hbt[ iml_blank_tab ] = -1;    /* set end of table        */
         iml_blank_tab = -1;                /* do not fill table any more */
       }
       if (iml_state >= 4) {                /* double CR / LF          */
         goto p_pone_80;                    /* end of pass one         */
       }
     } else {
       iml_state = 0;                       /* reset state CR / LF     */
     }
   } else if (*achl_rp == ' ') {            /* blank                   */
     if (iml_blank_tab >= 0) {              /* position blank table    */
       imrl_hbt[ iml_blank_tab++ ]
         = iml_read_pos - (adsl_gai1_rp->achc_ginp_end - achl_rp);
       if (iml_blank_tab >= sizeof(imrl_hbt) / sizeof(imrl_hbt[0])) {
         iml_blank_tab = -1;                /* do not search any more  */
       }
     }
     iml_state = 0;                         /* state CR / LF           */
   } else {                                 /* all other characters    */
     iml_state = 0;                         /* state CR / LF           */
   }
   achl_rp++;                               /* next character          */
   goto p_pone_20;                          /* pass one character      */

   p_pone_80:                               /* end of pass one         */
   achl_rp++;                               /* after last character    */
   adsp_rhs1->imc_length_http_header        /* length of HTTP header   */
     = iml_read_pos - (adsl_gai1_rp->achc_ginp_end - achl_rp);
   if (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* at end of gather  */
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     achl_rp = NULL;
     if (adsl_gai1_rp) {                    /* still in gather         */
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* first character of new gather */
     }
   }
   if (ADSL_STOR_CHECK == NULL) {           /* check storage management */
     if (   (adsp_phhs1->boc_store_cookies)  /* store cookies          */
         || (adsp_phhs1->boc_out_os)) {     /* output fields for other side */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
   }
   adsp_rhs1->imc_content_length = -1;      /* Content-Length - -1 when not set */
   aadsl_ht_pos = NULL;                     /* no chain of HTTP option to pass to other side */
   bol_consume_input_01 = adsp_phhs1->boc_consume_input;  /* consume input */
   if (adsp_phhs1->boc_out_os) {            /* output fields for other side */
     bol_consume_input_01 = FALSE;          /* do not consume input first processing */
     aadsl_ht_pos = &adsp_rhs1->adsc_ht_pos_ch;  /* last in chain of HTTP option to pass to other side */
   }
   aadsl_ht_cookie = &adsp_rhs1->adsc_ht_cookie_ch;  /* last in chain of Cookies */
   adsp_chhs1->adsc_gai1_out = adsl_gai1_rp;  /* last gather input data */
   adsp_chhs1->achc_pos_out = achl_rp;      /* position in gather input data */

   /* process first part till CR LF                                    */
   if (imrl_hbt[0] <= 0) {                  /* check first blank       */
// to-do 08.09.12 KB error message
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   adsl_gai1_rp = adsp_chhs1->adsc_gai1_in;  /* gather input data      */
   achl_w1 = adsl_gai1_rp->achc_ginp_cur;   /* start of method         */
   if ((achl_w1 + imrl_hbt[0]) <= adsl_gai1_rp->achc_ginp_end) {  /* check in gather */
     achl_rp = achl_w1 + imrl_hbt[0];       /* scan end of method      */
     goto p_meth_20;                        /* check method            */
   }
   achl_rp = achl_w1;                       /* start here              */
   iml1 = imrl_hbt[0];                      /* get length              */
   achl_w1 = chrl_work1;                    /* fill this area          */

   p_meth_08:                               /* fill method             */
   if (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather     */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
     goto p_meth_08;                        /* fill method             */
   }
   iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_w1, achl_rp, iml2 );
   achl_w1 += iml2;
   achl_rp += iml2;
   iml1 -= iml2;
   if (iml1 > 0) {                          /* needs more data         */
     goto p_meth_08;                        /* fill method             */
   }
   achl_w1 = chrl_work1;                    /* this area filled        */

   p_meth_20:                               /* check method            */
   iml1 = 0;                                /* clear index             */
   do {
     if (   (dsrs_http_method_def_tab[ iml1 ].imc_len_name == imrl_hbt[0])  /* length of name */
         && (!memcmp( dsrs_http_method_def_tab[ iml1 ].achc_name, achl_w1, imrl_hbt[0] ))) {
       goto p_meth_40;                      /* method found            */
     }
     iml1++;                                /* increment index         */
   } while (iml1 < (sizeof(dsrs_http_method_def_tab) / sizeof(dsrs_http_method_def_tab[0])));
   adsp_rhs1->iec_hme = ied_hme_undef;      /* undefined               */
   goto p_url_00;                           /* process URL             */

   p_meth_40:                               /* method found            */
   adsp_rhs1->iec_hme = dsrs_http_method_def_tab[ iml1 ].iec_hme;  /* HTTP method */

   p_url_00:                                /* process URL             */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   achl_rp++;                               /* after space             */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (imrl_hbt[ 1 ] <= 0) {                /* second space            */
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   iml1 = imrl_hbt[ 1 ] - (imrl_hbt[ 0 ] + 1);  /* length complete URL */
   if (iml1 <= 0) {                         /* check length            */
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
// to-do 11.09.12 KB - missing ?
   adsp_rhs1->imc_length_url_path = iml1;   /* length of URL path      */
   iml2 = 0;                                /* nothing to overread     */
   if ((achl_rp + iml1) <= adsl_gai1_rp->achc_ginp_end) {  /* check in gather */
     achl_w1 = achl_rp;                     /* here is URL             */
     achl_rp += iml1;                       /* read pointer after URL  */
     bol1 = FALSE;                          /* no gather               */
     goto p_url_20;                         /* we have the URL path    */
   }
   bol1 = TRUE;                             /* with gather             */

/**
   memory for the URL path may be supplied by the calling program,
   in struct dsd_call_http_header_server_1 address achc_url_path length imc_length_url_path_buffer.
   this is helpful when no memory management is used and the calling program just
   needs to know the URL path.
   please mind, the URL path may be longer than imc_length_url_path_buffer,
   so it is shortened, but the total length is passed in
   struct dsd_http_header_server_1 imc_length_url_path.
*/
   p_url_20:                                /* we have the URL path    */
   if (adsp_chhs1->imc_length_url_path_buffer <= 0) {  /* length memory for URL path */
     goto p_url_28;                         /* no predefined buffer    */
   }
   if (iml1 > adsp_chhs1->imc_length_url_path_buffer) {  /* length memory for URL path */
     iml2 = iml1 - adsp_chhs1->imc_length_url_path_buffer;  /* part to overread */
     iml1 = adsp_chhs1->imc_length_url_path_buffer;  /* copy only length memory for URL path */
   }
   adsp_rhs1->imc_stored_url_path = iml1;   /* stored part of URL path */
   adsp_rhs1->achc_url_path = adsp_chhs1->achc_url_path;  /* address memory of URL path */
   goto p_url_40;                           /* copy the URL path       */

   p_url_28:                                /* no predefined buffer    */
   if (ADSL_STOR_CHECK == NULL) {           /* check storage management */
     iml2 = iml1;                           /* set what to overread    */
     goto p_url_60;                         /* check if we need to overread a part */
   }
   adsp_rhs1->achc_url_path = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );
   adsp_rhs1->imc_stored_url_path = iml1;   /* stored part of URL path */

   p_url_40:                                /* copy the URL path       */
   if (bol1 == FALSE) {                     /* no gather               */
     memcpy( adsp_rhs1->achc_url_path, achl_w1, iml1 );
     goto p_vers_00;                        /* get HTTP version        */
   }
   achl_w1 = adsp_rhs1->achc_url_path;      /* output of copy          */

   p_url_48:                                /* copy gather of URL path */
   iml3 = adsl_gai1_rp->achc_ginp_end - achl_rp;
   if (iml3 > iml1) iml3 = iml1;
   memcpy( achl_w1, achl_rp, iml3 );
   iml1 -= iml3;                            /* part copied             */
   achl_rp += iml3;                         /* part input consumed     */
   if (iml1 == 0) {                         /* nothing remaining       */
     goto p_url_60;                         /* check if we need to overread a part */
   }
   achl_w1 += iml3;                         /* increment output        */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   goto p_url_48;                           /* copy gather of URL path */

   p_url_60:                                /* check if we need to overread a part */
   if (bol1 == FALSE) {                     /* no gather               */
     goto p_vers_00;                        /* get HTTP version        */
   }
   if (iml2 == 0) {                         /* nothing to overread     */
     goto p_vers_00;                        /* get HTTP version        */
   }

   p_url_68:                                /* overread a part in gather */
   iml3 = adsl_gai1_rp->achc_ginp_end - achl_rp;
   if (iml3 > iml2) iml3 = iml2;
   achl_rp += iml3;
   iml2 -= iml3;                            /* subtrace what overread  */
   if (iml2 == 0) {                         /* nothing to overread     */
     goto p_vers_00;                        /* get HTTP version        */
   }
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   goto p_url_68;                            /* overread a part in gather */


   p_vers_00:                               /* get HTTP version        */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != ' ') {                   /* not found space         */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_00;                        /* process options         */
   }
   achl_rp++;                               /* next input character    */
   ill_w1 = 0;                              /* store first keyword     */
   iml1 = 0;                                /* number of characters    */

   p_vers_20:                               /* feed characters of keyword */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (   ((ucrs_tab_char[ *((unsigned char *) achl_rp) ]) == CH_TYPE_ALPHA_UPPER)  /* alphanumeric uppercase */
       && (iml1 < 8)) {                     /* check number of characters */
     ill_w1 <<= 8;                          /* shift old value         */
     ill_w1 |= *((unsigned char *) achl_rp);  /* store first keyword   */
     iml1++;                                /* number of characters    */
     achl_rp++;                             /* next input character    */
     goto p_vers_20;                        /* feed characters to keyword */
   }
   if (*achl_rp != '/') {                   /* not found slash         */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_00;                        /* process options         */
   }
   if (ill_w1 != ils_http_c1) {             /* not found HTTP          */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_00;                        /* process options         */
   }
   achl_rp++;                               /* next input character    */
   iml1 = 0;                                /* number of characters    */
   iml2 = -1;                               /* for separator - decimal-point */
   iml3 = 0;                                /* number of digits        */
   bol1 = FALSE;                            /* not carriage-return found */

   p_vers_40:                               /* feed characters of version-number */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if ((ucrs_tab_char[ *((unsigned char *) achl_rp) ]) == CH_TYPE_DIGIT) {  /* numeric digit */
     iml1 *= 10;
     iml1 += *achl_rp - '0';
     iml3++;                                /* number of digits        */
   } else if (*achl_rp == '.') {            /* decimal-point           */
     if (iml2 >= 0) {                       /* was decimal-point before */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_00;                      /* process options         */
     }
     iml2 = iml3;                           /* set number of digits before */
   } else if (*achl_rp == CHAR_CR) {
     bol1 = TRUE;                           /* carriage-return found   */
   } else {                                 /* other character         */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_00;                        /* process options         */
   }
   achl_rp++;                               /* next input character    */
   if (bol1 == FALSE) {                     /* not carriage-return found */
     goto p_vers_40;                        /* feed characters of version-number */
   }
   if (iml2 != (iml3 - 1)) {                /* check position decimal-point */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_08;                        /* after carriage-return   */
   }
   switch (iml1) {                          /* check version number    */
     case 10:                               /* 1.0                     */
       adsp_rhs1->iec_hpr = ied_hpr_http_1_0;  /* HTTP 1.0             */
       break;
     case 11:                               /* 1.1                     */
       adsp_rhs1->iec_hpr = ied_hpr_http_1_1;  /* HTTP 1.1             */
       break;
     case 20:                               /* 2.0                     */
       adsp_rhs1->iec_hpr = ied_hpr_http_2_0;  /* HTTP 2.0             */
       break;
     default:
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       break;
   }
   goto p_opt1_08;                          /* after carriage-return   */

   p_opt1_00:                               /* process options         */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_CR) {
     achl_rp++;                             /* next input character    */
     goto p_opt1_00;                        /* process options         */
   }
   achl_rp++;                               /* next input character    */

   p_opt1_08:                               /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */

   p_opt1_20:                               /* start of next option    */
   achl_pos = achl_rp;                      /* start input options to pass to other side */
   adsl_gai1_pos = adsl_gai1_rp;            /* gather input options to pass to other side */
   iml_adler_1 = 0;                         /* calculate hash          */
   iml_adler_2 = 0;                         /* calculate hash          */

   p_opt1_40:                               /* next part of option     */
   achl_end = adsl_gai1_rp->achc_ginp_end;  /* end of this part        */
   if (achl_rp >= achl_end) {
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
     goto p_opt1_40;                        /* next part of option     */
   }
   do {                                     /* loop over input         */
     if (*achl_rp == ' ') {                 /* found space             */
       goto p_opt1_48;                      /* space found in option   */
     }
     if (*achl_rp == CHAR_CR) {             /* found carriage return   */
       goto p_opt1_80;                      /* carriage-return found in option */
     }
     iml_adler_1 += *((unsigned char *) achl_rp);
     iml_adler_2 += iml_adler_1;
     if (iml_adler_1 >= ADLER_BASE) iml_adler_1 -= ADLER_BASE;
     achl_rp++;
   } while (achl_rp < achl_end);
   if (bol_consume_input_01) {              /* consume input           */
     adsl_gai1_rp->achc_ginp_cur = achl_rp;
   }
   adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain       */
   if (adsl_gai1_rp == NULL) {              /* logic error             */
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp = adsl_gai1_rp->achc_ginp_cur;   /* start of data           */
   goto p_opt1_40;                          /* next part of option     */

   p_opt1_48:                               /* space found in option   */
   iml_adler_2 %= ADLER_BASE;
   iml2 = iml_adler_1 | (iml_adler_2 << 16);
   achl_rp++;                               /* next input character    */
   bol_pass_os = aadsl_ht_pos != NULL;      /* option to pass to other side */
   iml4 = sizeof(dsrs_http_parse_opt1_def_tab) / sizeof(dsrs_http_parse_opt1_def_tab[0]);
   iml3 = 0;

   p_opt1_52:                               /* step in binary search   */
   if (iml4 == 0) goto p_opt1_56;           /* option not found in table */
// iml4 = (iml4 - 1) / 2;
   iml4 = (iml4 - 1) >> 1;
   iml1 = iml3 + iml4;
   if (iml1 >= sizeof(dsrs_http_parse_opt1_def_tab) / sizeof(dsrs_http_parse_opt1_def_tab[0])) {
     goto p_opt1_52;                        /* step in binary search   */
   }
   iml5 = dsrs_http_parse_opt1_def_tab[ iml1 ].imc_hash_name;
   if (iml5 > iml2) {                       /* compare hash of name    */
     goto p_opt1_52;                        /* step in binary search   */
   }
   if (iml5 == iml2) {                      /* compare hash of name    */
     goto p_opt1_60;                        /* option found in table   */
   }
   iml3 = iml1 + 1;                         /* search upward from here */
   iml4++;
   goto p_opt1_52;                          /* step in binary search   */

   p_opt1_56:                               /* option not found in table */
   /* option not found in table                                        */
   adsp_rhs1->boc_warning = TRUE;           /* missformed HTTP header scanned */
   goto p_opt1_68;                          /* search end of option    */

   p_opt1_60:                               /* option found in table   */
   switch (dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo) {  /* HTTP parsing options */
     case ied_hpo_user_agent:               /* User-Agent              */
       goto p_ua_00;                        /* message-header User-Agent */
     case ied_hpo_accept_plain:             /* Accept                  */
     case ied_hpo_accept_language:          /* Accept-Language         */
     case ied_hpo_accept_encoding:          /* Accept-Encoding         */
       goto p_opt1_68;                      /* search end of option    */
     case ied_hpo_authorization:            /* Authorization           */
       goto p_auth_00;                      /* process authorization   */
     case ied_hpo_connection:               /* Connection              */
     case ied_hpo_transfer_encoding:        /* Transfer-Encoding       */
     case ied_hpo_upgrade:                  /* Upgrade                 */
       goto p_const_00;                     /* find constant           */
     case ied_hpo_host:                     /* Host                    */
       goto p_ineta_port_00;                /* process INETA and port  */
     case ied_hpo_origin:                   /* Origin                  */
       goto p_ineta_port_00;                /* process INETA and port  */
     case ied_hpo_dnt:                      /* DNT                     */
       goto p_opt1_68;                      /* search end of option    */
     case ied_hpo_cookie:                   /* Cookie                  */
       goto p_cookie_00;                    /* mesage-header Cookie found */
     case ied_hpo_hob_cookie:               /* HOB-Cookie              */
       goto p_b64_pa_00;                    /* parameter MIME base64   */
     case ied_hpo_rdg_conn_id:              /* RDG-Connection-Id       */
       goto p_pass_pa_00;                   /* pass parameter          */
     case ied_hpo_content_length:           /* Content-Length          */
       goto p_number_00;                    /* find number             */
     case ied_hpo_sec_webso_origin:         /* Sec-WebSocket-Origin    */
       goto p_ineta_port_00;                /* process INETA and port  */
     case ied_hpo_sec_webso_key:            /* Sec-WebSocket-Key       */
       goto p_pass_pa_00;                   /* pass parameter          */
     case ied_hpo_sec_webso_version:        /* Sec-WebSocket-Version   */
       goto p_number_00;                    /* find number             */
     case ied_hpo_sec_webso_ext:            /* Sec-WebSocket-Extensions */
       goto p_const_00;                     /* find constant           */
   }

   p_opt1_68:                               /* search end of message-header */
   bol1 = bol_consume_input_01;             /* consume input           */
   if (bol_pass_os == FALSE) {              /* not option to pass to other side */
     bol1 = adsp_phhs1->boc_consume_input;  /* consume input           */
     if (bol1) {                            /* we need to consum previous input */
       while (adsl_gai1_pos != adsl_gai1_rp) {  /* gather input options to pass to other side */
         adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
         adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain */
         if (adsl_gai1_pos == NULL) {       /* logic error             */
           adsp_rhs1->imc_error_line = __LINE__;  /* line of error     */
           return FALSE;
         }
       }
     }
   }

   p_opt1_72:                               /* continue search end of message-header */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol1) {                            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_CR) {
     achl_rp++;                             /* next input character    */
     goto p_opt1_72;                        /* continue search end of message-header */
   }
   achl_rp++;                               /* next input character    */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */

   p_opt1_76:                               /* end of option - pass other side */
   if (bol_pass_os == FALSE) {              /* not option to pass to other side */
     goto p_opt1_20;                        /* start of next option    */
   }
   /* option to pass to other side                                     */
   adsl_gai1_w1 = adsl_gai1_pos;            /* get gather input options to pass to other side */
   achl_w1 = achl_pos;                      /* get read pointer input options to pass to other side */
   iml1 = 0;                                /* clear length            */
   while (adsl_gai1_w1 != adsl_gai1_rp) {   /* not current gather input */
     iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* get read pointer input options to pass to other side */
   }
   iml1 += achl_rp - achl_w1;               /* add length last chunk   */

   adsp_rhs1->imc_no_ht_pos++;              /* number of options to pass to other side */
   adsp_rhs1->imc_length_ht_pos += iml1;    /* length of all options to pass to other side */


   *aadsl_ht_pos = (struct dsd_http_pass_os *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, sizeof(struct dsd_http_pass_os) + iml1 );
   (*aadsl_ht_pos)->adsc_next = NULL;       /* next HTTP option to pass to other side */
   (*aadsl_ht_pos)->imc_length_pos = iml1;  /* length of option to pass to other side */
   achl_w1 = (char *) (*aadsl_ht_pos + 1);  /* copy option here        */
   aadsl_ht_pos = &((*aadsl_ht_pos)->adsc_next);  /* set for next output */

   /* copy content of option                                           */
   while (adsl_gai1_pos != adsl_gai1_rp) {  /* get gather before       */
     iml2 = adsl_gai1_pos->achc_ginp_end - achl_pos;
     if (iml2 > 0) {
       memcpy( achl_w1, achl_pos, iml2 );   /* copy part of option     */
       achl_w1 += iml2;                     /* increment address target */
     }
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
     }
     adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain   */
     if (adsl_gai1_pos == NULL) {           /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_pos = adsl_gai1_pos->achc_ginp_cur;  /* start of data        */
   }
   iml2 = achl_rp - achl_pos;
   if (iml2 > 0) {
     memcpy( achl_w1, achl_pos, iml2 );     /* copy part of option     */
   }
   goto p_opt1_20;                          /* start of next option    */

   p_opt1_80:                               /* carriage-return found in option */
   achl_rp++;                               /* next input character    */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   if (adsp_phhs1->boc_consume_input) {     /* consume input           */
     adsl_gai1_rp->achc_ginp_cur = achl_rp;
   }
   return TRUE;

   p_cookie_00:                             /* mesage-header Cookie found */
   adsp_rhs1->imc_no_ht_cookies++;          /* number of HTTP cookies  */
   bol_pass_os = FALSE;                     /* not option to pass to other side */
   if (adsp_phhs1->boc_consume_input != bol_consume_input_01) {  /* did not consume input */
     while (adsl_gai1_pos != adsl_gai1_rp) {  /* gather input options to pass to other side */
       adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
       adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain */
       if (adsl_gai1_pos == NULL) {         /* logic error             */
         adsp_rhs1->imc_error_line = __LINE__;  /* line of error       */
         return FALSE;
       }
     }
   }
   if (adsp_phhs1->boc_store_cookies == FALSE) {  /* store cookies     */
     goto p_opt1_68;                        /* search end of option    */
   }
   /* retrieve length of Cookie                                        */
   adsl_gai1_w1 = adsl_gai1_rp;             /* get current gather input */
   achl_w1 = achl_rp;                       /* get read pointer        */
   iml1 = 0;                                /* clear length of Cookie  */

   p_cookie_20:                             /* search end of Cookie    */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start of data          */
   }
   achl_w2 = (char *) memchr( achl_w1, CHAR_CR, adsl_gai1_w1->achc_ginp_end - achl_w1 );
   if (achl_w2 == NULL) {                   /* carriage-return not found */
     iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;  /* add to length of Cookie */
     achl_w1 = adsl_gai1_w1->achc_ginp_end;  /* end of gather          */
     goto p_cookie_20;                      /* search end of Cookie    */
   }
   iml1 += achl_w2 - achl_w1;               /* add to length of Cookie */
   achl_w1 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, sizeof(struct dsd_http_cookie) + iml1 );
   memset( achl_w1, 0, sizeof(struct dsd_http_cookie) );
#define ADSL_HTTP_COOKIE_G ((struct dsd_http_cookie *) achl_w1)
   ADSL_HTTP_COOKIE_G->imc_length_cookie = iml1;  /* length of cookie  */
   *aadsl_ht_cookie = ADSL_HTTP_COOKIE_G;   /* append to last in chain of Cookies */
   aadsl_ht_cookie = &ADSL_HTTP_COOKIE_G->adsc_next;  /* last in chain of Cookies */
   achl_w1 = (char *) (ADSL_HTTP_COOKIE_G + 1);
#undef ADSL_HTTP_COOKIE_G

   /* copy content of the Cookie                                       */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     iml1 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml1 > 0) {
       memcpy( achl_w1, achl_rp, iml1 );    /* copy part of Cookie     */
       achl_w1 += iml1;                     /* increment address target */
     }
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml1 = achl_w2 - achl_rp;
   if (iml1 > 0) {
     memcpy( achl_w1, achl_rp, iml1 );      /* copy part of Cookie     */
   }
   achl_rp = achl_w2 + 1;                   /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_20;                          /* start of next option    */

   p_ua_00:                                 /* message-header User-Agent */
   if (adsp_rhs1->imc_length_hua_st > 0) {  /* length of User-Agent string */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_68;                        /* search end of option    */
   }
   if (ADSL_STOR_CHECK == NULL) {           /* check storage management */
     goto p_ua_40;                          /* we process the gather structures */
   }
   /* retrieve length of User-Agent                                    */
   adsl_gai1_w1 = adsl_gai1_rp;             /* get current gather input */
   achl_w1 = achl_rp;                       /* get read pointer        */
   iml1 = 0;                                /* clear length of User-Agent */

   p_ua_08:                                 /* search end of User-Agent */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start of data          */
   }
   achl_w2 = (char *) memchr( achl_w1, CHAR_CR, adsl_gai1_w1->achc_ginp_end - achl_w1 );
   if (achl_w2 == NULL) {                   /* carriage-return not found */
     iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;  /* add to length of Cookie */
     achl_w1 = adsl_gai1_w1->achc_ginp_end;  /* set to end of input    */
     goto p_ua_08;                          /* search end of User-Agent */
   }
   iml1 += achl_w2 - achl_w1;               /* add to length of User-Agent */
   if (iml1 == 0) {                         /* User-Agent empty        */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_68;                        /* search end of option    */
   }
   achl_w1 = achl_w3 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );

   /* copy content of User-Agent                                       */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml2 > 0) {
       memcpy( achl_w3, achl_rp, iml2 );    /* copy part of User-Agent  */
       achl_w3 += iml2;                     /* increment address target */
     }
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml2 = achl_w2 - achl_rp;
   if (iml2 > 0) {
     memcpy( achl_w3, achl_rp, iml2 );      /* copy part of User-Agent */
     achl_w3 += iml2;                       /* end of User-Agent in storage-container */
   }
   adsp_rhs1->achc_hua_string = achl_w1;    /* address memory User-Agent string */
   adsp_rhs1->imc_length_hua_st = iml1;     /* length of User-Agent string */

   /* search special words in User-Agent                               */
   bol1 = FALSE;                            /* no word found           */
   do {                                     /* loop over input         */
     switch (ucrs_tab_char[ *((unsigned char *) achl_w1) ]) {
       case CH_TYPE_UNDEF:                  /* undefined character     */
       case CH_TYPE_CR:                     /* carriage-return         */
       case CH_TYPE_LF:                     /* line-feed               */
       case CH_TYPE_DIGIT:                  /* numeric digit           */
       case CH_TYPE_SEPARATOR:              /* separator               */
         if (bol1) {                        /* in word                 */
           iml_adler_2 %= ADLER_BASE;
           iml1 = iml_adler_1 | (iml_adler_2 << 16);
           bol1 = FALSE;                    /* no more in word         */
           iml2 = sizeof(imrs_http_ua_word_tab) / sizeof(imrs_http_ua_word_tab[0]);
           do {                             /* compare words           */
             iml2--;                        /* word before             */
             if (iml1 == imrs_http_ua_word_tab[ iml2 ]) {
               goto p_ua_16;                /* found special word      */
             }
           } while (iml2 > 0);
// to-do 13.12.12 KB superflous - bol1 cleared already before
           bol1 = FALSE;                    /* no more in word         */
         }
         break;
       case CH_TYPE_ALPHA_LOWER:            /* alphanumeric lowercase  */
       case CH_TYPE_ALPHA_UPPER:            /* alphanumeric uppercase  */
       case CH_TYPE_SPECIAL:                /* special character       */
         if (bol1 == FALSE) {               /* not yet start of word   */
           iml_adler_1 = 0;                 /* calculate hash          */
           iml_adler_2 = 0;                 /* calculate hash          */
           bol1 = TRUE;                     /* is word now             */
         }
         iml_adler_1 += *((unsigned char *) achl_w1);
         iml_adler_2 += iml_adler_1;
         if (iml_adler_1 >= ADLER_BASE) iml_adler_1 -= ADLER_BASE;
         break;
     }
     achl_w1++;
   } while (achl_w1 < achl_w3);
   if (bol1) {                              /* in word                 */
     iml_adler_2 %= ADLER_BASE;
     iml1 = iml_adler_1 | (iml_adler_2 << 16);
     iml2 = sizeof(imrs_http_ua_word_tab) / sizeof(imrs_http_ua_word_tab[0]);
     do {                                   /* compare words           */
       iml2--;                              /* word before             */
       if (iml1 == imrs_http_ua_word_tab[ iml2 ]) {
         goto p_ua_16;                      /* found special word      */
       }
     } while (iml2 > 0);
   }
   adsp_rhs1->iec_huad = ied_huad_normal;   /* normal device - browser */
   goto p_ua_20;                            /* end of message-header   */

   p_ua_16:                                 /* found special word      */
   switch (iml2) {                          /* check which word        */
     case 0:
       adsp_rhs1->iec_huad = ied_huad_a_ios_ipad;  /* Apple iOS iPad   */
       break;
     case 1:
       adsp_rhs1->iec_huad = ied_huad_a_ios_iphone;  /* Apple iOS iPhone */
       break;
     case 2:
       adsp_rhs1->iec_huad = ied_huad_android;  /* Android             */
       break;
     case 3:
       adsp_rhs1->iec_huad = ied_huad_citrix_rec_ipad;  /* CitrixReceiver-iPad */
       break;
     case 4:
       adsp_rhs1->iec_huad = ied_huad_ms_ie;  /* Microsoft Internet Explorer */
       break;
   }

   p_ua_20:                                 /* end of message-header   */
   achl_rp = achl_w2 + 1;                   /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_ua_40:                                 /* process the gather structures */
   bol1 = FALSE;                            /* no word found           */

   p_ua_44:                                 /* continue gather structures */
   achl_end = adsl_gai1_rp->achc_ginp_end;  /* end of this part        */
   if (achl_rp >= achl_end) {
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
     goto p_ua_44;                          /* continue gather structures */
   }
   adsp_rhs1->imc_length_hua_st += achl_end - achl_rp;  /* length of User-Agent string */
   do {                                     /* loop over input         */
     switch (ucrs_tab_char[ *((unsigned char *) achl_rp) ]) {
       case CH_TYPE_UNDEF:                  /* undefined character     */
       case CH_TYPE_CR:                     /* carriage-return         */
       case CH_TYPE_LF:                     /* line-feed               */
       case CH_TYPE_DIGIT:                  /* numeric digit           */
       case CH_TYPE_SEPARATOR:              /* separator               */
         if (bol1) {                        /* in word                 */
           iml_adler_2 %= ADLER_BASE;
           iml1 = iml_adler_1 | (iml_adler_2 << 16);
           bol1 = FALSE;                    /* no more in word         */
           iml2 = sizeof(imrs_http_ua_word_tab) / sizeof(imrs_http_ua_word_tab[0]);
           do {                             /* compare words           */
             iml2--;                        /* word before             */
             if (iml1 == imrs_http_ua_word_tab[ iml2 ]) {
               goto p_ua_60;                /* found special word      */
             }
           } while (iml2 > 0);
           bol1 = FALSE;                    /* no more in word         */
         }
         if (*achl_rp != CHAR_CR) break;
         goto p_ua_80;                      /* carriage-return found   */
       case CH_TYPE_ALPHA_LOWER:            /* alphanumeric lowercase  */
       case CH_TYPE_ALPHA_UPPER:            /* alphanumeric uppercase  */
       case CH_TYPE_SPECIAL:                /* special character       */
         if (bol1 == FALSE) {               /* not yet start of word   */
           iml_adler_1 = 0;                 /* calculate hash          */
           iml_adler_2 = 0;                 /* calculate hash          */
           bol1 = TRUE;                     /* is word now             */
         }
         iml_adler_1 += *((unsigned char *) achl_rp);
         iml_adler_2 += iml_adler_1;
         if (iml_adler_1 >= ADLER_BASE) iml_adler_1 -= ADLER_BASE;
         break;
     }
     achl_rp++;
   } while (achl_rp < achl_end);
   if (bol_consume_input_01) {              /* consume input           */
     adsl_gai1_rp->achc_ginp_cur = achl_rp;
   }
   adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain       */
   if (adsl_gai1_rp == NULL) {              /* logic error             */
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp = adsl_gai1_rp->achc_ginp_cur;   /* start of data           */
   goto p_ua_44;                            /* continue gather structures */

   p_ua_60:                                 /* found special word      */
   switch (iml2) {                          /* check which word        */
     case 0:
       adsp_rhs1->iec_huad = ied_huad_a_ios_ipad;  /* Apple iOS iPad   */
       break;
     case 1:
       adsp_rhs1->iec_huad = ied_huad_a_ios_iphone;  /* Apple iOS iPhone */
       break;
     case 2:
       adsp_rhs1->iec_huad = ied_huad_android;  /* Android             */
       break;
     case 3:
       adsp_rhs1->iec_huad = ied_huad_citrix_rec_ipad;  /* CitrixReceiver-iPad */
       break;
   }

   /* we need to search the end of the message-header and adjust the length */

   p_ua_68:                                 /* search end of User-Agent */
   achl_end = adsl_gai1_rp->achc_ginp_end;  /* end of this part        */
   if (achl_rp >= achl_end) {               /* end of gather           */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
     adsp_rhs1->imc_length_hua_st += adsl_gai1_rp->achc_ginp_end - achl_rp;  /* length of User-Agent string */
     goto p_ua_68;                          /* search end of User-Agent */
   }
   achl_w1 = (char *) memchr( achl_rp, CHAR_CR, achl_end - achl_rp );
   if (achl_w1 == NULL) {                   /* carriage-return not found */
     achl_rp = achl_end;                    /* end of gather           */
     goto p_ua_68;                          /* search end of User-Agent */
   }
   adsp_rhs1->imc_length_hua_st -= achl_end - achl_w1;  /* length of User-Agent string */
   achl_rp = achl_w1 + 1;                   /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_ua_80:                                 /* carriage-return found   */
   adsp_rhs1->imc_length_hua_st -= achl_end - achl_rp - 2;  /* length of User-Agent string */
   adsp_rhs1->iec_huad = ied_huad_normal;   /* normal device - browser */
   achl_rp++;                               /* next input character    */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_b64_pa_00:                             /* parameter MIME base64   */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
   bol_pass_os = FALSE;                     /* not option to pass to other side */
   if (adsp_phhs1->boc_consume_input != bol_consume_input_01) {  /* did not consume input */
     while (adsl_gai1_pos != adsl_gai1_rp) {  /* gather input options to pass to other side */
       adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
       adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain */
       if (adsl_gai1_pos == NULL) {         /* logic error             */
         adsp_rhs1->imc_error_line = __LINE__;  /* line of error       */
         return FALSE;
       }
     }
   }
   /* retrieve length of string                                        */
   adsl_gai1_w1 = adsl_gai1_rp;             /* get current gather input */
   achl_w1 = achl_rp;                       /* get read pointer        */
   iml1 = 0;                                /* clear length of Cookie  */

   p_b64_pa_20:                             /* search end of string    */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start of data          */
   }
   achl_w2 = (char *) memchr( achl_w1, CHAR_CR, adsl_gai1_w1->achc_ginp_end - achl_w1 );
   if (achl_w2 == NULL) {                   /* carriage-return not found */
     iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;  /* add to length of Cookie */
     achl_w1 = adsl_gai1_w1->achc_ginp_end;  /* end of gather          */
     goto p_b64_pa_20;                      /* search end of string    */
   }
   iml1 += achl_w2 - achl_w1;               /* add to length of Cookie */
   if (iml1 & 0X03) {                       /* cannot be divided by four */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_opt1_68;                        /* search end of option    */
   }
   if (iel_hpo == ied_hpo_hob_cookie) {     /* HOB-Cookie              */
     if (adsp_rhs1->imc_length_hob_cookie > 0) {  /* length of HOB-Cookie */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
   } else if (iel_hpo == ied_hpo_authorization) {  /* Authorization    */
     if (adsp_rhs1->imc_length_auth_ntlm > 0) {  /* length of NTLM authentication */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
   }
   achl_w1 = chrl_work1;                    /* pseudo output area      */
   if (ADSL_STOR_CHECK) {                   /* check storage management */
     achl_w1 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, (iml1 >> 2) * 3 );
   }
   achl_w2 = achl_w1;                       /* for output              */
   iml1 = 4;                                /* set number of characters */
   iml2 = 0;                                /* clear akkumulator       */
   iml3 = 0;                                /* delimiting equals       */
   bol1 = FALSE;                            /* not end of input        */

   p_b64_pa_40:                             /* get base64 character    */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
// to-do 22.01.13 KB - illogic
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml4 = scrs_from_base64[ *((unsigned char *) achl_rp) ];  /* get translation */
   if (iml4 < 0) {                          /* invalid character found */
     if (iml4 == -2) {                      /* delimiting equals found */
       iml3++;                              /* count delimiting equals */
     } else {
       if (*achl_rp == CHAR_CR) {           /* end of input reached    */
         bol1 = TRUE;                       /* set end of input        */
       } else {                             /* invalid character       */
         if (ADSL_STOR_CHECK) {             /* check storage management */
           adsp_phhs1->amc_store_free( ADSL_STOR_G, achl_w1 );
         }
         adsp_rhs1->boc_warning = TRUE;     /* missformed HTTP header scanned */
         goto p_opt1_68;                    /* search end of option    */
       }
     }
   } else {
     if (iml3 != 0) {                       /* delimiting equals       */
       if (ADSL_STOR_CHECK) {               /* check storage management */
         adsp_phhs1->amc_store_free( ADSL_STOR_G, achl_w1 );
       }
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
     iml2 <<= 6;                            /* shift old bits          */
     iml2 |= iml4;                          /* apply new bits          */
     iml1--;                                /* decrement number of characters */
   }
   achl_rp++;                               /* next input              */
   iml4 = 3;                                /* set number of output characters */
   if (bol1) {                              /* end of input reached    */
     if (iml1 & 0X03) {                     /* not complete sequence   */
       if (iml1 >= 3) {                     /* last bundle one - a single input character */
         if (ADSL_STOR_CHECK) {             /* check storage management */
           adsp_phhs1->amc_store_free( ADSL_STOR_G, achl_w1 );
         }
         adsp_rhs1->boc_warning = TRUE;     /* missformed HTTP header scanned */
         goto p_opt1_68;                    /* search end of option    */
       }
       iml2 <<= iml1 * 6;                   /* shift akkumulator to correct position */
       iml4 -= iml1;                        /* less output characters  */
       iml3 -= iml1;                        /* control delimiting characters */
       iml1 = 0;                            /* bundle is complete      */
     }
     if (iml3 != 0) {                       /* wrong number of delimiting characters */
       if (ADSL_STOR_CHECK) {               /* check storage management */
         adsp_phhs1->amc_store_free( ADSL_STOR_G, achl_w1 );
       }
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
     if (iml1 == 4) {                       /* complete sequence       */
       goto p_b64_pa_80;                    /* end of base64 string    */
     }
   }
   if (iml1 <= 0) {                         /* all digits found        */
     do {
       if (ADSL_STOR_CHECK) {               /* check storage management */
         *achl_w2++ = (unsigned char) (iml2 >> 16);
       } else {
         achl_w2++;                         /* only count output       */
       }
       iml2 <<= 8;                          /* shift bits              */
       iml4--;                              /* output done             */
     } while (iml4 > 0);
     if (bol1) {                            /* end of input reached    */
       goto p_b64_pa_80;                    /* end of base64 string    */
     }
     iml1 = 4;                              /* set number of characters */
     iml2 = 0;                              /* clear akkumulator       */
   }
   goto p_b64_pa_40;                        /* get base64 character    */

   p_b64_pa_80:                             /* end of base64 string    */
   if (iel_hpo == ied_hpo_hob_cookie) {     /* HOB-Cookie              */
     adsp_rhs1->imc_length_hob_cookie = achl_w2 - achl_w1;  /* length of HOB-Cookie */
     if (ADSL_STOR_CHECK) {                 /* check storage management */
       adsp_rhs1->achc_hob_cookie = achl_w1;  /* address memory of HOB-Cookie */
     }
   } else if (iel_hpo == ied_hpo_authorization) {  /* Authorization    */
     adsp_rhs1->imc_length_auth_ntlm = achl_w2 - achl_w1;  /* length of NTLM authentication */
     if (ADSL_STOR_CHECK) {                 /* check storage management */
       adsp_rhs1->achc_auth_ntlm = achl_w1;  /* address memory of NTLM authentication */
     }
   }
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_20;                          /* start of next option    */

   p_pass_pa_00:                            /* pass parameter          */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
   if (iel_hpo == ied_hpo_sec_webso_key) {  /* Sec-WebSocket-Key       */
     if (adsp_rhs1->imc_len_sec_ws_key > 0) {  /* length Sec-WebSocket-Key base64 */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
   } else if (iel_hpo == ied_hpo_sec_webso_prot) {  /* Sec-WebSocket-Protocol */
     if (adsp_rhs1->imc_len_sec_ws_prot > 0) {  /* length Sec-WebSocket-Protocol */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
   } else if (iel_hpo == ied_hpo_rdg_conn_id) {  /* RDG-Connection-Id  */
     if (adsp_rhs1->imc_length_rdg_conn_id > 0) {  /* length of RDG-Connection-Id */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
       goto p_opt1_68;                      /* search end of option    */
     }
   }

   /* retrieve length of parameter                                     */
   adsl_gai1_w1 = adsl_gai1_rp;             /* get current gather input */
   achl_w1 = achl_rp;                       /* get read pointer        */
   iml1 = 0;                                /* clear length of parameter */

   p_pass_pa_20:                            /* search end of parameter */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start of data          */
   }
   achl_w2 = (char *) memchr( achl_w1, CHAR_CR, adsl_gai1_w1->achc_ginp_end - achl_w1 );
   if (achl_w2 == NULL) {                   /* carriage-return not found */
     iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;  /* add to length of parameter */
     achl_w1 = adsl_gai1_w1->achc_ginp_end;  /* set to end of input    */
     goto p_pass_pa_20;                     /* search end of parameter */
   }
   iml1 += achl_w2 - achl_w1;               /* add to length of parameter */
   achl_w1 = NULL;                          /* no storage              */
   if (   (iel_hpo != ied_hpo_sec_webso_key)  /* Sec-WebSocket-Key     */
       || (adsp_chhs1->imc_length_sec_ws_key_buffer == 0)) {  /* length memory for Sec-WebSocket-Key base64 */
     goto p_pass_pa_24;                     /* get memory for parameter */
   }
   if (iml1 == 0) {                         /* length zero - invalid   */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_pass_pa_40;                     /* parameter has been copied */
   }
   achl_w1 = achl_w3 = adsp_chhs1->achc_sec_ws_key;  /* Sec-WebSocket-Key base64 */
   iml3 = adsp_chhs1->imc_length_sec_ws_key_buffer;  /* length memory for Sec-WebSocket-Key base64 */
   if (iml3 > iml1) iml3 = iml1;            /* part to get copied      */
   iml4 = iml3;                             /* length copied           */

   /* copy content of parameter                                        */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml2 > iml3) iml2 = iml3;          /* only part to be copied  */
     if (iml2 > 0) {
       memcpy( achl_w3, achl_rp, iml2 );    /* copy part of User-Agent  */
       achl_w3 += iml2;                     /* increment address target */
       iml3 -= iml2;                        /* decrement remaining part to be copied */
     }
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml2 = achl_w2 - achl_rp;
   if (iml2 > iml3) iml2 = iml3;            /* only part to be copied  */
   if (iml2 > 0) {
     memcpy( achl_w3, achl_rp, iml2 );      /* copy part of parameter  */
   }
   goto p_pass_pa_40;                       /* parameter has been copied */

   p_pass_pa_24:                            /* get memory for parameter */
   iml4 = 0;                                /* length copied           */
   if (ADSL_STOR_CHECK == NULL) {           /* check storage management */
     goto p_pass_pa_40;                     /* parameter has been copied */
   }
   if (iml1 == 0) {                         /* length zero - invalid   */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_pass_pa_40;                     /* parameter has been copied */
   }
   achl_w1 = achl_w3 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );
   iml4 = iml1;                             /* length copied           */

   /* copy content of parameter                                        */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml2 > 0) {
       memcpy( achl_w3, achl_rp, iml2 );    /* copy part of User-Agent  */
       achl_w3 += iml2;                     /* increment address target */
     }
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml2 = achl_w2 - achl_rp;
   if (iml2 > 0) {
     memcpy( achl_w3, achl_rp, iml2 );      /* copy part of parameter  */
   }

   p_pass_pa_40:                            /* parameter has been copied */
   if (iel_hpo == ied_hpo_sec_webso_key) {  /* Sec-WebSocket-Key       */
     adsp_rhs1->achc_sec_ws_key = achl_w1;  /* Sec-WebSocket-Key base64 */
     adsp_rhs1->imc_len_sec_ws_key = iml1;  /* length Sec-WebSocket-Key base64 */
     adsp_rhs1->imc_stored_sec_ws_key = iml4;  /* stored part of Sec-WebSocket-Key base64 */
   } else if (iel_hpo == ied_hpo_sec_webso_prot) {  /* Sec-WebSocket-Protocol */
     adsp_rhs1->achc_sec_ws_prot = achl_w1;  /* Sec-WebSocket-Protocol  */
     adsp_rhs1->imc_len_sec_ws_prot = iml1;  /* length Sec-WebSocket-Protocol */
   } else if (iel_hpo == ied_hpo_rdg_conn_id) {  /* RDG-Connection-Id  */
     adsp_rhs1->achc_rdg_conn_id = achl_w1;  /* address memory of RDG-Connection-Id */
     adsp_rhs1->imc_length_rdg_conn_id = iml1;  /* length of RDG-Connection-Id */
   }
   /* we need to consume part before                                   */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   achl_rp = achl_w2 + 1;                   /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_20;                          /* start of next option    */

   p_auth_00:                               /* process authorization   */
   bol_pass_os = FALSE;                     /* not option to pass to other side */
   if (adsp_phhs1->boc_consume_input != bol_consume_input_01) {  /* did not consume input */
     while (adsl_gai1_pos != adsl_gai1_rp) {  /* gather input options to pass to other side */
       adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
       adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain */
       if (adsl_gai1_pos == NULL) {         /* logic error             */
         adsp_rhs1->imc_error_line = __LINE__;  /* line of error       */
         return FALSE;
       }
     }
   }
   ill_w1 = 0;                              /* store first keyword     */
   iml2 = 0;                                /* number of characters    */

   p_auth_20:                               /* feed characters of keyword */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (adsp_phhs1->boc_consume_input) {   /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (   ((ucrs_tab_char[ *((unsigned char *) achl_rp) ]) == CH_TYPE_ALPHA_UPPER)  /* alphanumeric uppercase */
       && (iml2 < 8)) {                     /* check number of characters */
     ill_w1 <<= 8;                          /* shift old value         */
     ill_w1 |= *((unsigned char *) achl_rp);  /* store first keyword   */
     iml2++;                                /* number of characters    */
     achl_rp++;                             /* next input character    */
     goto p_auth_20;                        /* feed characters to keyword */
   }
   if (*achl_rp != ' ') {                   /* not found space         */
     goto p_opt1_68;                        /* search end of option    */
   }
   if (ill_w1 != ils_ntlm_c1) {             /* not found NTLM          */
     goto p_opt1_68;                        /* search end of option    */
   }
   achl_rp++;                               /* next input character    */
   goto p_b64_pa_00;                        /* parameter MIME base64   */

   p_const_00:                              /* find constant           */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
   iml_adler_1 = 0;                         /* calculate hash          */
   iml_adler_2 = 0;                         /* calculate hash          */
// to-do 07.01.14 KB - variable for stage, separated by , ; - Sec-WebSocket-Extensions:

   p_const_20:                              /* feed characters to hash */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (   (*achl_rp == CHAR_CR)             /* end of option           */
       || (*achl_rp == ',')                 /* separator               */
       || (*achl_rp == ';')) {              /* separator               */
     goto p_const_40;                       /* end of constant found   */
   }
   iml_adler_1 += *((unsigned char *) achl_rp);
   iml_adler_2 += iml_adler_1;
   if (iml_adler_1 >= ADLER_BASE) iml_adler_1 -= ADLER_BASE;
   achl_rp++;                               /* next input character    */
   goto p_const_20;                         /* feed characters to hash */

   p_const_40:                              /* end of constant found   */
   iml_adler_2 %= ADLER_BASE;
   iml1 = iml_adler_1 | (iml_adler_2 << 16);
   if (iel_hpo == ied_hpo_connection) {     /* Connection              */
     if (*achl_rp != CHAR_CR) {             /* not end of option       */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     if (adsp_rhs1->iec_hcon != ied_hcon_undef) {  /* parameter is undefined  */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     iml2 = sizeof(dsrs_http_parse_conn_def_tab) / sizeof(dsrs_http_parse_conn_def_tab[0]) - 1;
     do {                                   /* compare words           */
       if (iml1 == dsrs_http_parse_conn_def_tab[ iml2 ].imc_hash_name) {
         adsp_rhs1->iec_hcon = dsrs_http_parse_conn_def_tab[ iml2 ].iec_hcon;  /* HTTP connection */
         break;
       }
       iml2--;                              /* keyword before          */
     } while (iml2 >= 0);
     if (iml2 < 0) {                        /* keyword not found       */
       adsp_rhs1->iec_hcon = ied_hcon_unknown;  /* unknown             */
     }
   } else if (iel_hpo == ied_hpo_transfer_encoding) {  /* Transfer-Encoding */
     if (*achl_rp != CHAR_CR) {             /* not end of option       */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     if (adsp_rhs1->iec_htre != ied_htre_undef) {  /* parameter is undefined  */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     iml2 = sizeof(dsrs_http_parse_transfer_encoding_def_tab) / sizeof(dsrs_http_parse_transfer_encoding_def_tab[0]) - 1;
     do {                                   /* compare words           */
       if (iml1 == dsrs_http_parse_transfer_encoding_def_tab[ iml2 ].imc_hash_name) {
         adsp_rhs1->iec_htre = dsrs_http_parse_transfer_encoding_def_tab[ iml2 ].iec_htre;  /* HTTP Transfer-Encoding */
         break;
       }
       iml2--;                              /* keyword before          */
     } while (iml2 >= 0);
     if (iml2 < 0) {                        /* keyword not found       */
       adsp_rhs1->iec_htre = ied_htre_unknown;  /* unknown             */
     }
   } else if (iel_hpo == ied_hpo_upgrade) {  /* Upgrade                */
     if (*achl_rp != CHAR_CR) {             /* not end of option       */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     if (adsp_rhs1->iec_hupg != ied_hupg_undef) {  /* parameter is undefined  */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     iml2 = sizeof(dsrs_http_parse_upgrade_def_tab) / sizeof(dsrs_http_parse_upgrade_def_tab[0]) - 1;
     do {                                   /* compare words           */
       if (iml1 == dsrs_http_parse_upgrade_def_tab[ iml2 ].imc_hash_name) {
         adsp_rhs1->iec_hupg = dsrs_http_parse_upgrade_def_tab[ iml2 ].iec_hupg;  /* HTTP upgrade */
         break;
       }
       iml2--;                              /* keyword before          */
     } while (iml2 >= 0);
     if (iml2 < 0) {                        /* keyword not found       */
       adsp_rhs1->iec_hupg = ied_hupg_unknown;  /* unknown             */
     }
   } else if (iel_hpo == ied_hpo_sec_webso_ext) {  /* Sec-WebSocket-Extensions */
     if (iml1 == ims_sec_webso_ext_deflate) {  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
       if (adsp_rhs1->boc_sec_webso_ext_deflate) {  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
         adsp_rhs1->boc_warning = TRUE;     /* missformed HTTP header scanned */
       }
       adsp_rhs1->boc_sec_webso_ext_deflate = TRUE;  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
     } else if (iml1 == ims_sec_webso_ext_per_mess_def) {
       adsp_rhs1->umc_sec_webso_ext_pmd |= SWE_PDM_DEF;
     } else if (iml1 == ims_sec_webso_ext_pmd_c2s_max_window_bits) {
       adsp_rhs1->umc_sec_webso_ext_pmd |= SWE_PDM_C2S_MWB;  /* c2s_max_window_bits */
     } else if (iml1 == ims_sec_webso_ext_pmd_cli_max_window_bits) {  /* Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits */
// to-do 14.03.15 KB - does not work, checks ; as separator
       if (adsp_rhs1->imc_sec_webso_ext_pmd_2 != 0) {  /* Sec-WebSocket-Extensions: permessage-deflate */
         adsp_rhs1->boc_warning = TRUE;     /* missformed HTTP header scanned */
       }
       adsp_rhs1->imc_sec_webso_ext_pmd_2 = -1;  /* Sec-WebSocket-Extensions: permessage-deflate */
     } else {
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
   }
   if (*achl_rp != CHAR_CR) {               /* not end of option       */
     if (*achl_rp != ',') {                 /* not next option         */
       goto p_subopt_00;                    /* get sub-option          */
     }
     achl_rp++;                             /* after separator         */
     while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather */
       if (bol_consume_input_01) {          /* consume input           */
         adsl_gai1_rp->achc_ginp_cur = achl_rp;
       }
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* logic error             */
         adsp_rhs1->imc_error_line = __LINE__;  /* line of error       */
         return FALSE;
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data        */
     }
     if (*achl_rp != ' ') {                 /* not separator space     */
       goto p_end_opt_00;                   /* search end of option    */
     }
     achl_rp++;                             /* after space             */
     iml_adler_1 = 0;                       /* calculate hash          */
     iml_adler_2 = 0;                       /* calculate hash          */
     goto p_const_20;                       /* feed characters to hash */
   }
   achl_rp++;                               /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_subopt_00:                             /* get sub-option          */
   achl_rp++;                               /* after separator         */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != ' ') {                   /* not separator space     */
     goto p_end_opt_00;                     /* search end of option    */
   }
   achl_rp++;                               /* after space             */
   iml_adler_1 = 0;                         /* calculate hash          */
   iml_adler_2 = 0;                         /* calculate hash          */
   goto p_const_20;                         /* feed characters to hash */

   p_end_opt_00:                            /* search end of option    */
   adsp_rhs1->boc_warning = TRUE;           /* missformed HTTP header scanned */

   p_end_opt_20:                            /* search carriage-return  */
   achl_w1 = (char *) memchr( achl_rp, CHAR_CR, adsl_gai1_rp->achc_ginp_end - achl_rp );
   if (achl_w1) {
     goto p_end_opt_40;                     /* carriage-return found   */
   }
   if (bol_consume_input_01) {              /* consume input           */
     adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
   }

   p_end_opt_28:                            /* get next gather         */
   adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain       */
   if (adsl_gai1_rp == NULL) {              /* logic error             */
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   if (adsl_gai1_rp->achc_ginp_cur >= adsl_gai1_rp->achc_ginp_end) {
     goto p_end_opt_28;                     /* get next gather         */
   }
   achl_rp = adsl_gai1_rp->achc_ginp_cur;   /* start of data           */
   goto p_end_opt_20;                       /* search carriage-return  */

   p_end_opt_40:                            /* carriage-return found   */
   achl_rp = achl_w1 + 1;                   /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_predef_00:                             /* search predefined keyword */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
// to-do 24.02.13 - part missing
   goto p_opt1_76;                          /* end of option - pass other side */

   p_ineta_port_00:                         /* process INETA and port  */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
   bol_consume_input_02 = bol_consume_input_01;  /* consume input      */
   if (iel_hpo == ied_hpo_host) {           /* Host                    */
     bol_pass_os = FALSE;                   /* not option to pass to other side */
     if (adsp_phhs1->boc_consume_input != bol_consume_input_01) {  /* did not consume input */
       while (adsl_gai1_pos != adsl_gai1_rp) {  /* gather input options to pass to other side */
         adsl_gai1_pos->achc_ginp_cur = adsl_gai1_pos->achc_ginp_end;
         adsl_gai1_pos = adsl_gai1_pos->adsc_next;  /* get next in chain */
         if (adsl_gai1_pos == NULL) {       /* logic error             */
           adsp_rhs1->imc_error_line = __LINE__;  /* line of error     */
           return FALSE;
         }
       }
       bol_consume_input_02 = TRUE;         /* consume input now       */
     }
   }
   iml2 = 0;                                /* number of square-brackets */
   iml3 = 0;                                /* number of separators to ignore */
   if (   (iel_hpo == ied_hpo_origin)       /* Origin                  */
       || (iel_hpo == ied_hpo_sec_webso_origin)) {  /* Sec-WebSocket-Origin */
     iml3 = 1;                              /* number of separators to ignore */
   }
   adsl_gai1_w1 = adsl_gai1_rp;             /* get current gather input */
   achl_w1 = achl_rp;                       /* get read pointer        */
   iml1 = 0;                                /* clear length of INETA   */

   p_ineta_port_20:                         /* parse characters        */
   while (achl_w1 >= adsl_gai1_w1->achc_ginp_end) {  /* end of gather  */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
     if (adsl_gai1_w1 == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_w1 = adsl_gai1_w1->achc_ginp_cur;  /* start of data          */
   }
   iml1 += adsl_gai1_w1->achc_ginp_end - achl_w1;  /* add to length of INETA */
   do {                                     /* loop over characters    */
     switch (*((unsigned char *) achl_w1)) {
       case CHAR_CR:                        /* carriage-return         */
         goto p_ineta_port_40;              /* end of field            */
       case CHAR_LF:                        /* line-feed               */
         adsp_rhs1->imc_error_line = __LINE__;  /* line of error       */
         return FALSE;
       case ':':                            /* separator for port      */
         if (iml2 != iml3) {                /* in square brackets - IPV6 */
           if (iml3 > 0) iml3 = 0;          /* ignore first separator  */
           break;
         }
         goto p_ineta_port_40;              /* end of INETA            */
       case '[':                            /* open square bracket     */
         iml2++;                            /* increment open square bracket */
         break;
       case ']':                            /* close square bracket    */
         if (iml2 <= 0) {                   /* square brackets not open */
           adsp_rhs1->boc_warning = TRUE;   /* missformed HTTP header scanned */
           break;
         }
         iml2--;                            /* decrement open square bracket */
         break;
     }
     achl_w1++;                             /* next character          */
   } while (achl_w1 < adsl_gai1_w1->achc_ginp_end);
   goto p_ineta_port_20;                    /* parse characters        */

   p_ineta_port_40:                         /* end of INETA            */
   iml1 -= adsl_gai1_w1->achc_ginp_end - achl_w1;  /* subtract remainder from length of INETA */
   if (iml1 <= 0) {                         /* too short               */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
     goto p_ineta_port_60;                  /* check port              */
   }
   achl_w2 = NULL;                          /* do not copy INETA       */
   iml2 = iml1;                             /* number of characters to copy */
   if (iel_hpo == ied_hpo_host) {           /* Host                    */
     if (adsp_rhs1->imc_length_hostname > 0) {  /* length of hostname  */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
// to-do 08.12.12 KB - not double, memory leak
     }
     if (ADSL_STOR_CHECK) {                 /* check storage management */
       achl_w2 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );
     } else {
       if (adsp_chhs1->imc_length_hostname_buffer > 0) {  /* length memory for hostname */
         achl_w2 = adsp_chhs1->achc_hostname;  /* memory for hostname  */
         if (iml2 > adsp_chhs1->imc_length_hostname_buffer) {  /* length memory for hostname */
           iml2 = adsp_chhs1->imc_length_hostname_buffer;  /* length memory for hostname */
         }
       }
     }
     if (achl_w2 == NULL) iml2 = 0;         /* do not store something  */
     adsp_rhs1->achc_hostname = achl_w2;    /* address memory of hostname */
     adsp_rhs1->imc_length_hostname = iml1;  /* length of hostname     */
     adsp_rhs1->imc_stored_hostname = iml2;  /* stored part of hostname */
     adsp_rhs1->imc_port_hostname = -1;     /* TCP port of hostname    */
   } else if (iel_hpo == ied_hpo_origin) {  /* Origin                  */
     if (adsp_rhs1->imc_length_origin > 0) {  /* length of Origin      */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
// to-do 08.12.12 KB - not double, memory leak
     }
     if (ADSL_STOR_CHECK) {                 /* check storage management */
       achl_w2 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );
     }
     if (achl_w2 == NULL) iml2 = 0;         /* do not store something  */
     adsp_rhs1->achc_origin = achl_w2;      /* address memory of Origin */
     adsp_rhs1->imc_length_origin = iml1;   /* length of Origin        */
     adsp_rhs1->imc_port_origin = -1;       /* TCP port of Origin      */
   } else if (iel_hpo == ied_hpo_sec_webso_origin) {  /* Sec-WebSocket-Origin */
     if (adsp_rhs1->imc_length_sec_ws_origin > 0) {  /* length of Sec-WebSocket-Origin */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
// to-do 08.12.12 KB - not double, memory leak
     }
     if (ADSL_STOR_CHECK) {                 /* check storage management */
       achl_w2 = (char *) adsp_phhs1->amc_store_alloc( ADSL_STOR_G, iml1 );
     }
     if (achl_w2 == NULL) iml2 = 0;         /* do not store something  */
     adsp_rhs1->achc_sec_ws_origin = achl_w2;  /* address memory of Sec-WebSocket-Origin */
     adsp_rhs1->imc_length_sec_ws_origin = iml1;  /* length of Sec-WebSocket-Origin */
     adsp_rhs1->imc_port_sec_ws_origin = -1;  /* TCP port of Sec-WebSocket-Origin */
   }
   if (achl_w2 == NULL) {                   /* do not copy INETA       */
     goto p_ineta_port_60;                  /* check port              */
   }
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     iml1 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml1 > iml2) iml1 = iml2;          /* copy only part          */
     if (iml1 > 0) {
       memcpy( achl_w2, achl_rp, iml1 );    /* copy part of INETA      */
       achl_w2 += iml1;                     /* increment address target */
       iml2 -= iml1;                        /* subtract part copied    */
     }
     if (bol_consume_input_02) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   iml1 = achl_w1 - achl_rp;
   if (iml1 > iml2) iml1 = iml2;            /* copy only part          */
   if (iml1 > 0) {
     memcpy( achl_w2, achl_rp, iml1 );      /* copy part of INETA      */
   }

   p_ineta_port_60:                         /* check port              */
   /* we need to consume part before                                   */
   while (adsl_gai1_rp != adsl_gai1_w1) {   /* get gather before       */
     if (bol_consume_input_02) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = adsl_gai1_rp->achc_ginp_end;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   achl_rp = achl_w1 + 1;                   /* after separator or carriage-return */
   if (*achl_w1 == CHAR_CR) {
     goto p_ineta_port_80;                  /* all processed           */
   }

   iml1 = 0;                                /* clear number of port    */

   p_ineta_port_64:                         /* next digit port         */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_02) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp == CHAR_CR) {
     goto p_ineta_port_68;                  /* end of port reached     */
   }
   if ((*achl_rp >= '0') && (*achl_rp <= '9')) {
     iml1 *= 10;
     iml1 += *achl_rp - '0';
     if ((iml1 >> 16) != 0) {               /* port too high           */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
   } else {
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
   }
   achl_rp++;                               /* next input character    */
   goto p_ineta_port_64;                    /* next digit port         */

   p_ineta_port_68:                         /* end of port reached     */
   if (iml1 == 0) {                         /* port zero not valid     */
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
   } else {
     if (iel_hpo == ied_hpo_host) {         /* Host                    */
       adsp_rhs1->imc_port_hostname = iml1;  /* TCP port of hostname   */
     } else if (iel_hpo == ied_hpo_origin) {  /* Origin                */
       adsp_rhs1->imc_port_origin = iml1;   /* TCP port of Origin      */
     } else if (iel_hpo == ied_hpo_sec_webso_origin) {  /* Sec-WebSocket-Origin */
       adsp_rhs1->imc_port_sec_ws_origin = iml1;  /* TCP port of Sec-WebSocket-Origin */
     }
   }
   achl_rp++;                               /* next input character    */

   p_ineta_port_80:                         /* all processed           */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_02) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

   p_number_00:                              /* find number             */
   iel_hpo = dsrs_http_parse_opt1_def_tab[ iml1 ].iec_hpo;  /* HTTP parsing options */
   iml1 = 0;                                /* clear number            */

   p_number_20:                             /* next digit of number    */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp == CHAR_CR) {               /* end of option           */
     goto p_number_40;                       /* end of constant found   */
   }
   if ((*achl_rp >= '0') && (*achl_rp <= '9')) {
     iml1 *= 10;
     iml1 += *achl_rp - '0';
   } else {
     adsp_rhs1->boc_warning = TRUE;         /* missformed HTTP header scanned */
   }
   achl_rp++;                               /* next input character    */
   goto p_number_20;                        /* next digit of number    */

   p_number_40:                             /* end of number found     */
   if (iel_hpo == ied_hpo_content_length) {  /* Content-Length         */
     if (iml1 == 0) {                       /* zero not allowed        */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     if (adsp_rhs1->imc_content_length >= 0) {  /* Content-Length - -1 when not set */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     adsp_rhs1->imc_content_length = iml1;  /* Content-Length - -1 when not set */
   } else if (iel_hpo == ied_hpo_sec_webso_version) {  /* Sec-WebSocket-Version */
     if (iml1 == 0) {                       /* zero not allowed        */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     if (adsp_rhs1->imc_sec_ws_version != 0) {  /* Sec-WebSocket-Version */
       adsp_rhs1->boc_warning = TRUE;       /* missformed HTTP header scanned */
     }
     adsp_rhs1->imc_sec_ws_version = iml1;  /* Sec-WebSocket-Version   */
   }
   achl_rp++;                               /* after carriage-return   */
   while (achl_rp >= adsl_gai1_rp->achc_ginp_end) {  /* end of gather  */
     if (bol_consume_input_01) {            /* consume input           */
       adsl_gai1_rp->achc_ginp_cur = achl_rp;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* logic error             */
       adsp_rhs1->imc_error_line = __LINE__;  /* line of error         */
       return FALSE;
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data          */
   }
   if (*achl_rp != CHAR_LF) {
     adsp_rhs1->imc_error_line = __LINE__;  /* line of error           */
     return FALSE;
   }
   achl_rp++;                               /* next input character    */
   goto p_opt1_76;                          /* end of option - pass other side */

} /* end m_proc_http_header_server()                                   */

static int m_calc_adler( char *achp_buffer, int imp_len_buffer ) {
   int        iml_adler;
   int        iml_sum2;
   char       *achl_cur;
   char       *achl_end;

   iml_adler = iml_sum2 = 0;
   achl_cur = achp_buffer;
   achl_end = achp_buffer + imp_len_buffer;

   do {
     iml_adler += *((unsigned char *) achl_cur);
     achl_cur++;
     iml_sum2 += iml_adler;
     if (iml_adler >= ADLER_BASE) iml_adler -= ADLER_BASE;
   } while (achl_cur < achl_end);
   iml_sum2 %= ADLER_BASE;
   return iml_adler | (iml_sum2 << 16);
} /* end m_calc_adler()                                                */

static int m_calc_zt_adler( const char *achp_buffer ) {
   int        iml_adler;
   int        iml_sum2;
   char       *achl_cur;

   iml_adler = iml_sum2 = 0;
   achl_cur = (char *) achp_buffer;

   while (*achl_cur != 0) {
     iml_adler += *((unsigned char *) achl_cur);
     achl_cur++;
     iml_sum2 += iml_adler;
     if (iml_adler >= ADLER_BASE) iml_adler -= ADLER_BASE;
   }
   iml_sum2 %= ADLER_BASE;
   return iml_adler | (iml_sum2 << 16);
} /* end m_calc_zt_adler()                                             */
