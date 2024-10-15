/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: IBIPGW08                                            |*/
/*| -------------                                                     |*/
/*|  IP-Gateway Telnet for Win32 with SSL                             |*/
/*|  WebSecureProxy for Windows                                       |*/
/*|  KB 29.03.00                                                      |*/
/*|  Win64 KB 24.01.05                                                |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2000                                |*/
/*|  Copyright (C) HOB electronic 2001                                |*/
/*|  Copyright (C) HOB electronic 2002                                |*/
/*|  Copyright (C) HOB electronic 2003                                |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB 2005                                           |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2012 (VC11)                                     |*/
/*|  GCC and other C/C++ compilers                                    |*/
/*|  XERCES 2.4.0                                                     |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#define D_SDHC1_NO_SSL  -1
#define D_HTTP_MAX_DATA 1024

struct dsd_protdef_e {                      /* protocol definition     */
   char       *achc_keyword;                /* protocol name           */
   enum ied_scp_def iec_scp_def;            /* numeric value           */
};

static const struct dsd_protdef_e dsrs_protdef_e[] = {
   { "HTTP", ied_scp_http },                /* protocol HTTP           */
   { "RDP", ied_scp_rdp },                  /* protocol MS RDP         */
   { "HOB-RDP-EXT1", ied_scp_hrdpe1 },      /* protocol HOB MS RDP Extension 1 */
   { "ICA", ied_scp_ica },                  /* protocol ICA            */
   { "LDAP", ied_scp_ldap },                /* protocol LDAP           */
   { "HOBY", ied_scp_hoby },                /* protocol HOB-Y          */
   { "3270", ied_scp_3270 },                /* protocol IBM 3270       */
   { "5250", ied_scp_5250 },                /* protocol IBM 5250       */
   { "VT", ied_scp_vt },                    /* protocol VT (100 - 525) */
   { "SOCKS5", ied_scp_socks5 },            /* protocol Socks-5        */
   { "SSH", ied_scp_ssh },                  /* protocol SSH Secure Shell */
   { "SMB", ied_scp_smb },                  /* protocol SMB server message block */
   { "HOB-PPP-T1", ied_scp_hpppt1 },        /* protocol HOB-PPP-T1     */
   { "HOB-VOIP-1", ied_scp_hvoip1 },        /* protocol HOB-VOIP-1     */
   { "HOB-KRB5TS1", ied_scp_krb5ts1 },      /* protocol KRB5TS1 Kerberos Ticket Service */
   { "SSTP", ied_scp_sstp },                /* protocol SSTP           */
   { "SOAP", ied_scp_soap },                /* protocol SOAP           */
   { "MS-RPC", ied_scp_ms_rpc },            /* protocol MS-RPC         */
   { "WebSocket", ied_scp_websocket },      /* protocol WebSocket      */
   { "HL-DASH", ied_scp_hl_dash },          /* protocol HOBLink data share */
   { "RDG-OUT", ied_scp_rdg_out_d },        /* protocol MS RDG_OUT_DATA */
   { "RDG-IN", ied_scp_rdg_in_d },          /* protocol MS RDG_IN_DATA */
   { "OpenVPN-1", ied_scp_openvpn_1 }       /* protocol OpenVPN        */
};

static const char * achrs_ssl_prot[] = {    /* SSL protocol            */
   "unknown",
   "SSL",
   "TLS"
};

static const char * achrs_ssl_ci_prot[] = {  /* text cipher protocol   */
   "SSL-NULL-NULL-NULL",
   "SSL-RSA-NULL-MD5",
   "SSL-RSA-NULL-SHA",
   "SSL-RSA-EXP-RC4-40-MD5",
   "SSL-RSA-RC4-128-MD5",
   "SSL-RSA-RC4-128-SHA",
   "SSL-RSA-EXP-RC2-CBC-40-MD5",
   "SSL-RSA-IDEA-CBC-SHA",
   "SSL-RSA-EXP-DES40-CBC-SHA",
   "SSL-RSA-DES-CBC-SHA",
   "SSL-RSA-3DES-EDE-CBC-SHA",
   "SSL-DH-DSS-EXP-DES40-CBC-SHA",
   "SSL-DH-DSS-DES-CBC-SHA",
   "SSL-DH-DSS-3DES-EDE-CBC-SHA",
   "SSL-DH-RSA-EXP-DES40-CBC-SHA",
   "SSL-DH-RSA-DES-CBC-SHA",
   "SSL-DH-RSA-3DES-EDE-CBC-SHA",
   "SSL-DHE-DSS-EXP-DES40-CBC-SHA",
   "SSL-DHE-DSS-DES-CBC-SHA",
   "SSL-DHE-DSS-3DES-EDE-CBC-SHA",
   "SSL-DHE-RSA-EXP-DES40-CBC-SHA",
   "SSL-DHE-RSA-DES-CBC-SHA",
   "SSL-DHE-RSA-3DES-EDE-CBC-SHA",
   "SSL-DH-anon-EXP-RC4-40-MD5",
   "SSL-DH-anon-RC4-128-MD5",
   "SSL-DH-anon-EXP-DES-40-CBC-SHA",
   "SSL-DH-anon-DES-CBC-SHA",
   "SSL-DH-anon-3DES-EDE-CBC-SHA",
   "undefined-0X1F",
   "undefined-0X20",
   "undefined-0X21",
   "undefined-0X22",
   "undefined-0X23",
   "undefined-0X24",
   "undefined-0X25",
   "undefined-0X26",
   "undefined-0X27",
   "undefined-0X28",
   "undefined-0X29",
   "undefined-0X2A",
   "undefined-0X2B",
   "undefined-0X2C",
   "undefined-0X2D",
   "undefined-0X2E",
   "SSL-FORTEZZA-KEA-NULL-SHA",
   "SSL-FORTEZZA-KEA-FORT-CBC-SHA",
   "SSL-FORTEZZA-KEA-RC4-128-SHA",
   "SSL-RSA-AES-128-CBC-SHA",
   "SSL-DH-DSS-AES-128-CBC-SHA",
   "SSL-DH-RSA-AES-128-CBC-SHA",
   "SSL-DHE-DSS-AES-128-CBC-SHA",
   "SSL-DHE-RSA-AES-128-CBC-SHA",
   "SSL-DH-anon-AES-128-CBC-SHA",
   "SSL-RSA-AES-256-CBC-SHA",
   "SSL-DH-DSS-AES-256-CBC-SHA",
   "SSL-DH-RSA-AES-256-CBC-SHA",
   "SSL-DHE-DSS-AES-256-CBC-SHA",
   "SSL-DHE-RSA-AES-256-CBC-SHA",
   "SSL-DH-anon-AES-256-CBC-SHA",
   "unknown"
};

static const char * achrs_ssl_keyexch[] = {  /* text key exchange      */
   "unknown",
   "RSA",
   "DH-DSS",
   "DH-RSA",
   "DHE-DSS",
   "DHE-RSA"
};

static const char * achrs_ssl_ci_alg[] = {  /* text cipher algorithm   */
   "unknown",
   "RC4",
   "RC2-CBC",
   "DES-CBC",
   "DES-EDE-CBC",
   "IDEA-CBC",
   "FORTEZZA",
   "AES-CBC"
};

static const char * achrs_ssl_ci_type[] = {  /* text cipher type       */
   "Stream-C",
   "Block-C",
   "unknown"
};

static const char * achrs_ssl_mac[] = {     /* text MAC                */
   "unknown",
   "MD5",
   "SHA1"
};

static const char * achrs_ssl_auth[] = {    /* text authentication     */
   "none",
   "Server-only",
   "Client-only",
   "Server+Client"
};

static const char * achrs_ssl_compr[] = {   /* text compression        */
   "none",
   "V42bis",
   "unknown"
};

static const unsigned char ucrs_http_ssl_01[] = {  /* first part SSL input */
// 0X16, 0X03, 0X01, 0X00, 0X89, 0X01, 0X00, 0X00
   0X16, 0X03, 0X01, 0X00,
};

#ifdef B130226
static const unsigned char ucrs_http_get_01[] = {  /* first part HTTP GET input */
   'G', 'E', 'T', ' '
};
#endif

struct dsd_const_auth_kw {                  /* constants WSP-socks-mode authentication keyword */
   char       *achc_name;                   /* keyword                 */
   int        imc_max_len;                  /* maximum length of parameter */
   int        imc_displ_defined;            /* displacement where defined in structure */
   int        imc_displ_addr;               /* displacement where address in structure */
   int        imc_displ_len;                /* displacement where length in structure */
   enum ied_wanhkw_value iec_wanhkw;        /* WSP authentication header keyword value */
};

static const struct dsd_const_auth_kw dsrs_const_auth_kw[] = {
   { "language",      sizeof(int), offsetof( struct dsd_wsp_auth_normal , boc_hkw_language ),
                        -1, 0,
                        ied_wanhkw_language },  /* value is language   */
   { "userid",        MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_userid ),
                        offsetof( struct dsd_wsp_auth_normal , achc_userid ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_userid ),
                        ied_wanhkw_userid },  /* value is userid       */
   { "password",      MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_password ),
                        offsetof( struct dsd_wsp_auth_normal , achc_password ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_password ),
                        ied_wanhkw_password },  /* value is password   */
   { "host",          MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_host ),
                        offsetof( struct dsd_wsp_auth_normal , achc_host ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_host ),
                        ied_wanhkw_host },  /* value is host           */
   { "device",        MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_device ),
                        offsetof( struct dsd_wsp_auth_normal , achc_device ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_device ),
                        ied_wanhkw_device },  /* value is device       */
   { "appl",          MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_appl ),
                        offsetof( struct dsd_wsp_auth_normal , achc_appl ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_appl ),
                        ied_wanhkw_appl },  /* value is appl           */
   { "flags",         8, offsetof( struct dsd_wsp_auth_normal , boc_hkw_flags ),
                        -2, 0,
                        ied_wanhkw_flags },  /* value is flags         */
   { "server",        MAX_AUTH_IN, offsetof( struct dsd_wsp_auth_normal , boc_hkw_server ),
                        offsetof( struct dsd_wsp_auth_normal , achc_stor_servent ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_servent ),
                        ied_wanhkw_server },  /* value is server       */
   { "krb5-ticket",   MAX_AUTH_KRB5_TI, offsetof( struct dsd_wsp_auth_normal , boc_hkw_krb5_ticket ),
                        offsetof( struct dsd_wsp_auth_normal , achc_stor_krb5_ticket ),
                        offsetof( struct dsd_wsp_auth_normal , imc_len_krb5_ticket ),
                        ied_wanhkw_krb5_ticket }  /* value is krb5-ticket */
};

// to-do 11.05.15 KB - only moved, not permanently moved
static const unsigned char ucrs_http_perm_mov_01[] = {  /* HTTP permanently moved */
   'H', 'T', 'T', 'P', '/', '1', '.', '1',
   ' ', '3', '0', '2', ' ', 'F', 'o', 'u',
   'n', 'd', 0X0D, 0X0A,
   'D', 'a', 't', 'e', ':', ' '
};

static const unsigned char ucrs_http_perm_mov_02[] = {  /* HTTP permanently moved */
   0X0D, 0X0A,
   'L', 'o', 'c', 'a', 't', 'i', 'o', 'n', ':', ' ',
   'h', 't', 't', 'p', 's', ':', '/', '/'
};

static const unsigned char ucrs_http_perm_mov_03[] = {  /* HTTP permanently moved */
   0X0D, 0X0A, 'S', 'e', 'r', 'v', 'e', 'r', ':', ' '
};

static const unsigned char ucrs_http_perm_mov_04[] = {  /* HTTP permanently moved */
   0X0D, 0X0A,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-',
   'T', 'y', 'p', 'e', ':', ' ', 't', 'e',
   'x', 't', '/', 'h', 't', 'm', 'l',
   0X0D, 0X0A,
   'C', 'o', 'n', 'n', 'e', 'c', 't', 'i',
   'o', 'n', ':', ' ', 'c', 'l', 'o', 's',
   'e',
   0X0D, 0X0A,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-',
   'L', 'e', 'n', 'g', 't', 'h', ':', ' '
};

static const unsigned char ucrs_http_perm_mov_05[] = {  /* HTTP permanently moved */
   0X0D, 0X0A, 0X0D, 0X0A,
   '<', 'h', 't', 'm', 'l', '>', '<', 'h',
   'e', 'a', 'd', '>',
   0X0D, 0X0A,
   '<', 't', 'i', 't', 'l', 'e', '>', '3',
   '0', '2', ' ', 'F', 'o', 'u', 'n', 'd',
   '<', '/', 't', 'i', 't', 'l', 'e', '>',
   0X0D, 0X0A,
   '<', '/', 'h', 'e', 'a', 'd', '>', '<',
   'b', 'o', 'd', 'y', '>',
   0X0D, 0X0A,
   '<', 'h', '1', '>', 'M', 'o', 'v', 'e',
   'd', ' ', 'P', 'e', 'r', 'm', 'a', 'n',
   'e', 'n', 't', 'l', 'y', ' ', '<', '/',
   'h', '1', '>',
   0X0D, 0X0A,
   'T', 'h', 'e', ' ', 'd', 'o', 'c', 'u',
   'm', 'e', 'n', 't', ' ', 'h', 'a', 's',
   ' ', 'm', 'o', 'v', 'e', 'd', '<', 'a',
   ' ', 'h', 'r', 'e', 'f', '=', '\"',
   'h', 't', 't', 'p', 's', ':', '/', '/'
};

static const unsigned char ucrs_http_perm_mov_06[] = {  /* HTTP permanently moved */
   '\"', '>', 'h', 'e', 'r', 'e', '<', '/',
   'a', '>', '.', '<', 'p', '>',
   0X0D, 0X0A,
   '<', '/', 'b', 'o', 'd', 'y', '>', '<',
   '/', 'h', 't', 'm', 'l', '>'
};

#ifndef NOT_INCLUDED_HTTP
static const struct dsd_proc_http_header_server_1 dss_phhs1_check_01 = {
   NULL,                                    /* amc_store_alloc - storage container allocate memory */
   NULL,                                    /* amc_store_free - storage container free memory */
   FALSE,                                   /* boc_consume_input - consume input */
   FALSE,                                   /* boc_store_cookies - store cookies */
   FALSE                                    /* boc_out_os - output fields for other side */
};
#endif

static const unsigned char ucrs_sstp_mac_seed[ 29 ] = {  /* SSTP Compound MAC Key Seed */
   'S', 'S', 'T', 'P', ' ', 'i', 'n', 'n',
   'e', 'r', ' ', 'm', 'e', 't', 'h', 'o',
   'd', ' ', 'd', 'e', 'r', 'i', 'v', 'e',
   'd', ' ', 'C', 'M', 'K'
};

static const char byrs_zeroes[ 32 ] = {
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_sstp_hmac_len_const[ 3 ] = {  /* SSTP HMAC constant */
   0X20, 0, 1
};
