/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-gw-ppp-1.h                                      |*/
/*| -------------                                                     |*/
/*|  header file for PPP                                              |*/
/*|  KB 10.11.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC or other Unix C-Compilers                                    |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
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

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#define D_LEN_L2TP_HEADER      8            /* length of L2TP header   */
#define D_PPP_OPT_SE_ACFC      1            /* Address-and-Control-Field-Compression (ACFC) */
#define D_PPP_OPT_CL_ACFC      2            /* Address-and-Control-Field-Compression (ACFC) */
#define D_PPP_OPT_SE_PFC       4            /* Protocol-Field-Compression (PFC) */
#define D_PPP_OPT_CL_PFC       8            /* Protocol-Field-Compression (PFC) */
#define D_PPP_OPT_SE_AUTH      0X10         /* server requests authentication */
#define D_PPP_OPT_CL_AUTH      0X20         /* client requests authentication */
#define D_PPP_OPT_CONF_ACK     0X40         /* Configure-Ack received  */
#define D_PPP_OPT_AUTH_OK      0X80         /* authentication succeeded */
#define D_PPP_OPT_IPCP_SEND    0X0100       /* IPCP send INETAS complete */
#define D_PPP_OPT_IPCP_RECV    0X0200       /* IPCP receive INETAS complete */
#define D_PPP_OPT_HS_COMPL     0X0400       /* handshake is complete   */
#define D_PPP_OPT_ENDED        0X0800       /* PPP module has ended    */

#define D_INETA_OPT_SET        1            /* INETA set for IPCP      */
#define D_INETA_OPT_REJECTED   2            /* INETA rejected          */

#define LEN_MSCV2_CHALLENGE    16           /* length MS-CHAP-V2 challenge */
#define LEN_MSCV2_RESPONSE     48           /* length MS-CHAP-V2 response */
#define LEN_MSCV2_CHANGE_PWD   582          /* length MS-CHAP-V2 change password */

#ifdef XYZ1
#define D_PPP_EAP_MS_AUTH      26
#endif

#ifndef DEF_INCL_PPP_AUTH
#define DEF_INCL_PPP_AUTH
#define DEF_NO_PPP_AUTH        8            /* configured <PPP-authentication-method> */
enum ied_ppp_auth_def {                     /* authentication-methods  */
   ied_pppa_invalid = 0,                    /* is invalid              */
   ied_pppa_pass_thru,                      /* pass-thru               */
   ied_pppa_none,                           /* no authentication       */
   ied_pppa_pap,                            /* PAP                     */
   ied_pppa_chap,                           /* CHAP                    */
   ied_pppa_ms_chap_v2,                     /* MS-CHAP-V2              */
   ied_pppa_eap                             /* EAP                     */
};
#endif

enum ied_ppp_auth_record {                  /* type of authentication record */
   ied_par_invalid = 0,                     /* is invalid              */
   ied_par_userid,                          /* userid - EAP identitiy  */
   ied_par_password,                        /* password (PAP)          */
   ied_par_mscv2_challenge,                 /* MS-CHAP-V2 challenge    */
   ied_par_mscv2_response,                  /* MS-CHAP-V2 response     */
   ied_par_mscv2_success,                   /* MS-CHAP-V2 success      */
   ied_par_mscv2_failure,                   /* MS-CHAP-V2 failure      */
   ied_par_mscv2_change_pwd,                /* MS-CHAP-V2 change password */
   ied_par_eap_recv_1,                      /* EAP received and not yet processed */
   ied_par_eap_recv_2,                      /* EAP received and already processed */
   ied_par_eap_send_1,                      /* EAP to send             */
   ied_par_eap_send_2,                      /* EAP sent but not yet acknowledged */
   ied_par_eap_send_3,                      /* EAP sent and acknowledged */
   ied_par_radius_1,                        /* used for Radius         */
   ied_par_radius_2,                        /* used for Radius         */
   ied_par_aux                              /* auxiliary record        */
};

#ifndef B130123
enum ied_ppp_auth_rc {                      /* PPP authentication return code */
   ied_pppar_ok = 0,                        /* authentication was checked O.K. */
   ied_pppar_cont,                          /* authentication continue processing */
   ied_pppar_userid_inv,                    /* userid invalid          */
   ied_pppar_password_inv,                  /* password invalid        */
   ied_pppar_auth_failed,                   /* authentication failed   */
   ied_pppar_misc                           /* miscellaneous           */
};
#endif

/* PPP server sends packet to the client                               */
typedef void ( * amd_ppp_se_send )( struct dsd_ppp_server_1 *, struct dsd_buf_vector_ele * );

/* PPP server do authentication                                        */
typedef void ( * amd_ppp_se_auth )( struct dsd_ppp_server_1 * );

#ifdef HL_PPP_CLIENT
/* PPP client do authentication                                        */
typedef void ( * amd_ppp_cl_auth )( struct dsd_ppp_client_1 * );
#else
/* PPP client do authentication                                        */
typedef void ( * amd_ppp_cl_auth )( struct dsd_ppp_client_1 *, enum ied_ppp_auth_def );
#endif

/* PPP server get INETA client                                         */
typedef char * ( * amd_ppp_se_get_ineta_client )( struct dsd_ppp_server_1 * );

/* PPP server handshake is complete                                    */
typedef void ( * amd_ppp_se_hs_compl )( struct dsd_ppp_server_1 * );

/* PPP server abend with message                                       */
// do-to 07.05.12 KB - add va_list
typedef void ( * amd_ppp_se_abend )( struct dsd_ppp_server_1 *, char * );

/* PPP client sends packet to the server                               */
typedef void ( * amd_ppp_cl_send )( struct dsd_ppp_client_1 *, char *, int );

/* PPP client abend with message                                       */
// do-to 07.05.12 KB - add va_list
typedef void ( * amd_ppp_cl_abend )( struct dsd_ppp_client_1 *, char * );

#ifdef HL_PPP_CLIENT
// remove struct dsd_ppp_auth_1 05.05.12 KB
struct dsd_ppp_auth_1 {                     /* for authentication      */
   char       chc_ident;                    /* ident received          */
   int        imc_len_userid;               /* length userid           */
   int        imc_len_password;             /* length password         */
   enum ied_charset iec_chs_auth;           /* character set authentication */
};
#endif

struct dsd_ppp_auth_header {                /* storage for authentication */
   struct dsd_ppp_server_1 *adsc_ppp_server_1;  /* PPP server          */
   char       *achc_stor_end;               /* end of this storage     */
   void *     vpc_radius;                   /* for Radius authentication */
   struct dsd_ppp_auth_record *adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   enum ied_ppp_auth_def iec_ppp_auth;      /* authentication-method in use */
   char       chc_ident;                    /* ident received          */
#ifdef XYZ1
   BOOL       boc_async_active;             /* asynchronous request is active */
#endif
   int        imc_state;                    /* state of processing     */
};

struct dsd_ppp_auth_record {                /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsc_next;   /* for chaining            */
   enum ied_ppp_auth_record iec_par;        /* type of authentication record */
   int        imc_len_data;                 /* length of the data      */
#ifdef XYZ1
   void *     vpc_userfld;                  /* userfield for certain use */
#endif
};

#ifdef XYZ1
/* the structure is followed by userid and password - charset ???      */
struct dsd_ppp_auth_rec_pap {               /* record for auth pap     */
   char       chc_ident;                    /* ident received          */
   int        imc_len_userid;               /* length userid           */
   int        imc_len_password;             /* length password         */
   enum ied_charset iec_chs_auth;           /* character set authentication */
};
#endif

struct dsd_ppp_server_1 {                   /* PPP server              */
   amd_ppp_se_send amc_ppp_se_send;         /* PPP server sends packet to the client */
   amd_ppp_se_auth amc_ppp_se_auth;         /* PPP server do authentication */
   amd_ppp_se_get_ineta_client amc_ppp_se_get_ineta_client;  /* PPP server get INETA client */
   amd_ppp_se_hs_compl amc_ppp_se_hs_compl;  /* PPP server handshake is complete */
   amd_ppp_se_abend amc_ppp_se_abend;       /* PPP server abend with message */
   int        imc_options;                  /* options negotiated      */
   int        imc_auth_no;                  /* index for authentification */
   char       chrc_magic_number_cl[4];      /* magic number client     */
   char       chrc_magic_number_se[4];      /* magic number server     */
   short int  isc_recv_ident_lcp_conf;      /* received identification LCP configure */
   unsigned char ucc_send_ident_lcp_conf;   /* sent identification LCP configure */
   unsigned int umc_mtc_se;                 /* maximum receive unit from server */
   unsigned int umc_mtc_cl;                 /* maximum receive unit from client */
   void *     vpc_handle;                   /* handle L2TP or HTUN     */
#ifdef B120505
   struct dsd_ppp_auth_1 *adsc_ppp_auth_1;  /* for authentication      */
#endif
   struct dsd_ppp_auth_header *adsc_ppp_auth_header;  /* storage for authentication */
// to-do 06.05.12 KB - remove vpc_radius
   void *     vpc_radius;                   /* for Radius authentication */
   struct dsd_ppp_client_1 *adsc_ppp_cl_1;  /* PPP client              */
   char       chrrc_ineta[5][4];            /* INETAs                  */
   char       chrc_ineta_stat[5];           /* state of corresponding INETA */
   char       chrc_ppp_auth[ DEF_NO_PPP_AUTH ];  /* configured <PPP-authentication-method> */
};

struct dsd_ppp_client_1 {                   /* PPP client              */
   amd_ppp_cl_send amc_ppp_cl_send;         /* PPP client sends packet to the server */
#ifdef HL_PPP_CLIENT
   amd_ppp_cl_auth amc_ppp_cl_auth;         /* PPP client do authentication */
#else
   amd_ppp_cl_auth amc_ppp_cl_auth;         /* PPP client do authentication */
#endif
   amd_ppp_cl_abend amc_ppp_cl_abend;       /* PPP client abend with message */
   int        imc_options;                  /* options negotiated      */
   char       chrc_magic_number_cl[4];      /* magic number client     */
   char       chrc_magic_number_se[4];      /* magic number server     */
   short int  isc_recv_ident_lcp_conf;      /* received identification LCP configure */
   unsigned char ucc_send_ident;            /* send identifier         */
   int        imc_auth_no;                  /* index for authentification */
// unsigned int umc_mtc_se;                 /* maximum receive unit from server */
// unsigned int umc_mtc_cl;                 /* maximum receive unit from client */
#ifdef HL_PPP_CLIENT
   unsigned int umc_mtc_se;                 /* maximum receive unit from server */
   unsigned int umc_mtc_cl;                 /* maximum receive unit from client */
#endif
#ifdef B120826
#ifdef HL_PPP_CLIENT
   struct dsd_ppp_auth_1 *adsc_ppp_auth_1;  /* for authentication      */
#else
   struct dsd_ppp_auth_header *adsc_ppp_auth_header;  /* storage for authentication */
#endif
#else
   struct dsd_ppp_auth_header *adsc_ppp_auth_header;  /* storage for authentication */
#endif
   char       *achc_ipcp_save;              /* saved block for IPCP    */
#ifndef HL_PPP_CLIENT
   struct dsd_ppp_server_1 *adsc_ppp_se_1;  /* PPP server              */
#endif
   char       chrc_ineta[4];                /* INETA                   */
#ifdef HL_PPP_CLIENT
   char       chrrc_ineta[5][4];            /* INETAs                  */
   char       chrc_ineta_stat[5];           /* state of corresponding INETA */
#endif
};

#ifdef XYZ1
#define D_CACHE_TF_IPV4_NO_ENTRY    64      /* entries cache entry IPV4 */

#define D_CACHE_TF_IPV4_LEN         8       /* length array cache entry IPV4 */
#define D_CACHE_TF_IPV4_INETA       4       /* length array cache entry INETA */
#define D_CACHE_TF_IPV4_PROTO       1       /* length array cache entry protocol */
#define D_CACHE_TF_IPV4_PORT        2       /* length array cache entry protocol */

enum ied_ret_cf {                           /* return value from processing target filter */
   ied_rcf_incompl = 0,                     /* packet is incomplete    */
   ied_rcf_invalid,                         /* packet is invalid       */
   ied_rcf_drop,                            /* drop packet             */
   ied_rcf_ok                               /* packet is o.k.          */
};

struct dsd_ppp_targfi_cache_1 {             /* cache entry PPP target filter */
   struct dsd_ppp_targfi_cache_1 *adsc_next;  /* next in chain         */
   char       chrc_cache_e[ D_CACHE_TF_IPV4_LEN ];  /* cache entry     */
};

struct dsd_ppp_targfi_act_1 {               /* active target filter    */
   struct dsd_targfi_1 *adsc_targfi_1;      /* used target filter      */
   struct dsd_ppp_targfi_cache_1 *adsc_ce_act;  /* chain active cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_1 *adsc_ce_empty;  /* chain empty cache entries PPP target filter */
   struct dsd_ppp_targfi_cache_1 dsrc_ce[ D_CACHE_TF_IPV4_NO_ENTRY ];  /* cache entries PPP target filter */
};

extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 * );
extern PTYPE ied_ret_cf m_proc_ppp_targfi( void *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );
#endif

/* start PPP control sequences on server side, do also on client side if configured */
extern PTYPE void m_start_ppp_server_cs( struct dsd_ppp_server_1 * );

/* process PPP control sequence on server side                         */
extern PTYPE void m_recv_ppp_server_cs( struct dsd_ppp_server_1 *, char *, int );

/* process PPP control sequence on client side                         */
extern PTYPE void m_recv_ppp_client_cs( struct dsd_ppp_client_1 *, char *, int );

/* PPP server authentication is complete                               */
extern PTYPE void m_auth_compl_ppp_server( struct dsd_ppp_server_1 *, enum ied_ppp_auth_rc );

#ifdef HL_PPP_CLIENT
/* authentication of client                                            */
//extern PTYPE void m_auth_ppp_client( struct dsd_ppp_client_1 *, struct dsd_ppp_auth_1 * );
extern PTYPE void m_auth_ppp_client( struct dsd_ppp_client_1 * );
#endif

/* close PPP control sequences on server side, do also on client side if configured */
extern PTYPE void m_close_ppp_server_cs( struct dsd_ppp_server_1 * );

#ifdef HL_PPP_CLIENT
/* start PPP control sequences on client side                          */
extern PTYPE void m_start_ppp_client_cs( struct dsd_ppp_client_1 * );
#endif
