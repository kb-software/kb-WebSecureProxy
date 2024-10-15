/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-http-header-1.h                                 |*/
/*| -------------                                                     |*/
/*|  Header File for processing of HTTP headers                       |*/
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

#define MAX_LEN_HTTP_HEADER         2048
#define HTTP_ERROR_HEADER_TOO_LONG  1

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

#ifdef B130628
typedef void * ( * amd_store_alloc )( void **, int );
typedef void ( * amd_store_free )( void **, void * );
#else
typedef void * ( * amd_store_alloc )( void *, int );
typedef void ( * amd_store_free )( void *, void * );
#endif

enum ied_http_method {                      /* HTTP method             */
   ied_hme_invalid = 0,                     /* parameter is invalid    */
   ied_hme_options,                         /* OPTIONS                 */
   ied_hme_get,                             /* GET                     */
   ied_hme_head,                            /* HEAD                    */
   ied_hme_post,                            /* POST                    */
   ied_hme_put,                             /* PUT                     */
   ied_hme_delete,                          /* DELETE                  */
   ied_hme_trace,                           /* TRACE                   */
   ied_hme_connect,                         /* CONNECT                 */
   ied_hme_bdelete,                         /* BDELETE                 */
   ied_hme_bmove,                           /* BMOVE                   */
   ied_hme_bproppatch,                      /* BPROPPATCH              */
   ied_hme_copy,                            /* COPY                    */
   ied_hme_lock,                            /* LOCK                    */
   ied_hme_mkcol,                           /* MKCOL                   */
   ied_hme_move,                            /* MOVE                    */
   ied_hme_poll,                            /* POLL                    */
   ied_hme_propfind,                        /* PROPFIND                */
   ied_hme_proppatch,                       /* PROPPATCH               */
   ied_hme_subscribe,                       /* SUBSCRIBE               */
   ied_hme_search,                          /* SEARCH                  */
   ied_hme_sstp,                            /* SSTP_DUPLEX_POST        */
   ied_hme_ms_rpc,                          /* RPC_IN_DATA             */
   ied_hme_rdg_out_data,                    /* RDG_OUT_DATA            */
   ied_hme_rdg_in_data,                     /* RDG_IN_DATA             */
   ied_hme_undef                            /* undefined               */
};

enum ied_http_protocol {                    /* HTTP protocol           */
   ied_hpr_invalid = 0,                     /* parameter is invalid    */
   ied_hpr_http_1_0,                        /* HTTP 1.0                */
   ied_hpr_http_1_1,                        /* HTTP 1.1                */
   ied_hpr_http_2_0                         /* HTTP 2.0                */
};

enum ied_http_ua_dev {                      /* HTTP User-Agent device  */
   ied_huad_undef = 0,                      /* parameter is undefined  */
   ied_huad_normal,                         /* normal device - browser */
   ied_huad_ms_ie,                          /* Microsoft Internet Explorer */
   ied_huad_a_ios_ipad,                     /* Apple iOS iPad          */
   ied_huad_a_ios_iphone,                   /* Apple iOS iPhone        */
   ied_huad_android,                        /* Android                 */
   ied_huad_citrix_rec_ipad                 /* CitrixReceiver-iPad     */
};

enum ied_http_connection {                  /* HTTP connection         */
   ied_hcon_undef = 0,                      /* parameter is undefined  */
   ied_hcon_keep_alive,                     /* keep-alive              */
   ied_hcon_upgrade,                        /* upgrade (WebSocket)     */
   ied_hcon_unknown                         /* unknown                 */
};

enum ied_http_upgrade {                     /* HTTP upgrade            */
   ied_hupg_undef = 0,                      /* parameter is undefined  */
   ied_hupg_websocket,                      /* websocket               */
   ied_hupg_unknown                         /* unknown                 */
};

enum ied_http_transfer_encoding {           /* HTTP Transfer-Encoding  */
   ied_htre_undef = 0,                      /* parameter is undefined  */
   ied_htre_chunked,                        /* chunked                 */
   ied_htre_unknown                         /* unknown                 */
};

enum ied_http_content_type {                /* HTTP Content-Type       */
   ied_htct_undef = 0,                      /* parameter is undefined  */
   ied_htct_text_html,                      /* text/html               */
   ied_htct_unknown                         /* unknown                 */
};

enum ied_http_content_encoding {            /* HTTP Content-Encoding   */
   ied_htce_undef = 0,                      /* parameter is undefined  */
   ied_htce_gzip,                           /* gzip                    */
   ied_htce_unknown                         /* unknown                 */
};

/* the cookie is immediately after this piece of storage               */
struct dsd_http_cookie {                    /* HTTP cookie             */
   struct dsd_http_cookie *adsc_next;       /* next HTTP cookie in chain */
   int        imc_length_cookie;            /* length of cookie        */
};

/* the option, keyword and value, including CR LF, is stored immediately after this piece of storage */
struct dsd_http_pass_os {                   /* HTTP option to pass to other side */
   struct dsd_http_pass_os *adsc_next;      /* next HTTP option to pass to other side */
   int        imc_length_pos;               /* length of option to pass to other side */
};

struct dsd_http_header_server_1 {           /* HTTP processing at server */
   int        imc_length_http_header;       /* length of HTTP header   */
   BOOL       imc_error_line;               /* line of error           */
   BOOL       boc_warning;                  /* missformed HTTP header scanned */
   int        imc_content_length;           /* Content-Length - -1 when not set */
   enum ied_http_method iec_hme;            /* HTTP method             */
   enum ied_http_protocol iec_hpr;          /* HTTP protocol           */
   enum ied_http_connection iec_hcon;       /* HTTP connection         */
   enum ied_http_upgrade iec_hupg;          /* HTTP upgrade            */
   enum ied_http_transfer_encoding iec_htre;  /* HTTP Transfer-Encoding */
   char       *achc_url_path;               /* address memory of URL path */
   int        imc_length_url_path;          /* length of URL path      */
   int        imc_stored_url_path;          /* stored part of URL path */
   struct dsd_http_pass_os *adsc_ht_pos_ch;  /* chain of HTTP option to pass to other side */
   int        imc_no_ht_pos;                /* number of options to pass to other side */
   int        imc_length_ht_pos;            /* length of all options to pass to other side */
/**
   3 fields hostname
   int        imc_port_hostname;
   -1 when not set
*/
   char       *achc_hostname;               /* address memory of hostname */
   int        imc_length_hostname;          /* length of hostname      */
   int        imc_stored_hostname;          /* stored part of hostname */
   int        imc_port_hostname;            /* TCP port of hostname    */
   char       *achc_origin;                 /* address memory of Origin */
   int        imc_length_origin;            /* length of Origin        */
   int        imc_port_origin;              /* TCP port of Origin      */
   struct dsd_http_cookie *adsc_ht_cookie_ch;  /* chain of HTTP cookies */
   int        imc_no_ht_cookies;            /* number of HTTP cookies  */
   enum ied_http_ua_dev iec_huad;           /* HTTP User-Agent device  */
   char       *achc_hua_string;             /* address memory User-Agent string */
   int        imc_length_hua_st;            /* length of User-Agent string */
   char       *achc_hob_cookie;             /* address memory of HOB-Cookie */
   int        imc_length_hob_cookie;        /* length of HOB-Cookie    */
   char       *achc_auth_ntlm;              /* address memory of NTLM authentication */
   int        imc_length_auth_ntlm;         /* length of NTLM authentication */
   char       *achc_rdg_conn_id;            /* address memory of RDG-Connection-Id */
   int        imc_length_rdg_conn_id;       /* length of RDG-Connection-Id */
// Cache-Control: max-age=0
// Cache-Control: no-cache
// Pragma: no-cache
// RDG-Connection-Id:
// Authentication, mainly NTLM
   /* fields for WebSocket                                             */
   char       *achc_sec_ws_origin;          /* address memory of Sec-WebSocket-Origin */
   int        imc_length_sec_ws_origin;     /* length of Sec-WebSocket-Origin */
   int        imc_port_sec_ws_origin;       /* TCP port of Sec-WebSocket-Origin */
   char       *achc_sec_ws_key;             /* Sec-WebSocket-Key base64 */
   int        imc_len_sec_ws_key;           /* length Sec-WebSocket-Key base64 */
   int        imc_stored_sec_ws_key;        /* stored part of Sec-WebSocket-Key base64 */
   char       *achc_sec_ws_prot;            /* Sec-WebSocket-Protocol  */
   int        imc_len_sec_ws_prot;          /* length Sec-WebSocket-Protocol */
   int        imc_sec_ws_version;           /* Sec-WebSocket-Version   */
   BOOL       boc_sec_webso_ext_deflate;    /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
   unsigned int umc_sec_webso_ext_pmd;      /* Sec-WebSocket-Extensions: permessage-deflate */
   int        imc_sec_webso_ext_pmd_2;      /* Sec-WebSocket-Extensions: permessage-deflate */
#define SWE_PDM_DEF       1
#define SWE_PDM_C2S_MWB   2                 /* c2s_max_window_bits     */
};

struct dsd_proc_http_header_server_1 {      /* process HTTP processing at server */
   amd_store_alloc amc_store_alloc;         /* allocate memory         */
   amd_store_free amc_store_free;           /* free memory             */
   BOOL       boc_consume_input;            /* consume input           */
   BOOL       boc_store_cookies;            /* store cookies           */
   BOOL       boc_out_os;                   /* output fields for other side */
};

/* variable input and output for processing                            */
struct dsd_call_http_header_server_1 {      /* call HTTP processing at server */
   int        imc_error;                    /* returned error          */
   struct dsd_gather_i_1 *adsc_gai1_in;     /* gather input data       */
   struct dsd_gather_i_1 *adsc_gai1_out;    /* last gather input data  */
   char       *achc_pos_out;                /* position in gather input data */
   char       *achc_url_path;               /* memory for URL path     */
   int        imc_length_url_path_buffer;   /* length memory for URL path */
/**
   2 fields hostname
*/
   char       *achc_hostname;               /* memory for hostname     */
   int        imc_length_hostname_buffer;   /* length memory for hostname */
/**
   2 fields Sec-WebSocket-Key base64
*/
   char       *achc_sec_ws_key;             /* Sec-WebSocket-Key base64 */
   int        imc_length_sec_ws_key_buffer;  /* length memory for Sec-WebSocket-Key base64 */
#ifndef HL_SDH
   void *     ac_stor_1;                    /* storage management      */
#else
   struct dsd_stor_sdh_1 *adsc_stor_sdh_1;  /* storage management      */
#endif
};

struct dsd_http_header_client_1 {           /* HTTP processing at client */
   int        imc_length_http_header;       /* length of HTTP header   */
   BOOL       boc_warning;                  /* missformed HTTP header scanned */
   int        imc_status_code;              /* status code in response */
   int        imc_content_length;           /* Content-Length - -1 when not set */
// 21.02.13 KB - additional enum with most used values?
   char       *achc_reason_phrase;          /* response reason phrase  */
   int        imc_length_reason_phrase;     /* length of reason_phrase */
   struct dsd_http_pass_os *adsc_ht_pos_ch;  /* chain of HTTP option to pass to other side */
   int        imc_no_ht_pos;                /* number of options to pass to other side */
   int        imc_length_ht_pos;            /* length of all options to pass to other side */
   struct dsd_http_cookie *adsc_ht_cookie_ch;  /* chain of HTTP cookies */
   int        imc_no_ht_cookies;            /* number of HTTP cookies  */
   int        imc_date_epoch;               /* Date as Epoch value     */
   enum ied_http_transfer_encoding iec_htre;  /* HTTP Transfer-Encoding */
   enum ied_http_content_type iec_htct;     /* HTTP Content-Type       */
   enum ied_http_content_encoding iec_htce;  /* HTTP Content-Encoding  */
// Authentication, mainly NTLM
// Content-Type:
// Server:
// WWW-Authenticate:
// Date:
// Content-Length:
};

struct dsd_proc_http_header_client_1 {      /* process HTTP processing at client */
   amd_store_alloc amc_store_alloc;         /* allocate memory         */
   amd_store_free amc_store_free;           /* free memory             */
   BOOL       boc_consume_input;            /* consume input           */
   BOOL       boc_store_cookies;            /* store cookies           */
   BOOL       boc_out_os;                   /* output fields for other side */
   BOOL       boc_date_os;                  /* output Date option for other side */
   BOOL       boc_date_decode_epoch;        /* decode Date as Epoch    */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE BOOL m_proc_http_header_server( const struct dsd_proc_http_header_server_1 *adsp_phhs1,
                                             struct dsd_call_http_header_server_1 *adsp_chhs1,  /* call HTTP processing at server */
                                             struct dsd_http_header_server_1 *adsp_hhs1 );  /* HTTP processing at server */
