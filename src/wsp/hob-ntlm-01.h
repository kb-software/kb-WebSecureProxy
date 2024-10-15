/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-ntlm-01.h                                       |*/
/*| -------------                                                     |*/
/*|  Header File for processing of NTLM                               |*/
/*|    NT LAN Manager                                                 |*/
/*|  part of HOB Framework                                            |*/
/*|  KB 01.01.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   include of header files needed before:
     hob-xslunic1.h
*/

#define LEN_MSV_CHANNEL_BINDINGS 16         /* length channel bindings hash */
#define LEN_NTLM_SIGN_KEY        16         /* length sign key of NTLM      */

typedef BOOL ( * amd_get_epoch )( void *, HL_LONGLONG * );
typedef BOOL ( * amd_get_random )( void *, char *, int );

#ifndef DEF_HL_NTLM_FUNC
#define DEF_HL_NTLM_FUNC

enum ied_ntlm_function {                    /* NTLM request function to process */
   ied_ntlmf_invalid = 0,                   /* parameter is invalid    */
   ied_ntlmf_neg_gen,                       /* generate NTLMSSP_NEGOTIATE */
   ied_ntlmf_neg_check,                     /* check NTLMSSP_NEGOTIATE */
   ied_ntlmf_chal_gen,                      /* generate NTLMSSP_CHALLENGE */
   ied_ntlmf_auth_gen,                      /* generate NTLMSSP_AUTH   */
   ied_ntlmf_auth_prep,                     /* prepare from NTLMSSP_AUTH */
   ied_ntlmf_auth_check                     /* check NTLMSSP_AUTH      */
};
#endif

struct dsd_ntlm_req {                       /* NTLM request            */
   void *     vpc_userfld;                  /* userfield for callbacks */
   amd_get_epoch amc_get_epoch;             /* callback get epoch      */
   amd_get_random amc_get_random;           /* callback get random     */
   int        imc_ret_error_line;           /* returns line with error */
   enum ied_ntlm_function iec_ntlmf;        /* NTLM request function to process */
   BOOL       boc_gssapi;                   /* use GSSAPI              */
   char       *achc_negotiate;              /* address of packet NTLMSSP_NEGOTIATE */
   int        imc_len_negotiate;            /* length of packet NTLMSSP_NEGOTIATE */
// int        imc_offset_negotiate;         /* offset of content NTLMSSP_NEGOTIATE */
   char       *achc_challenge;              /* address of packet NTLMSSP_CHALLENGE */
   int        imc_len_challenge;            /* length of packet NTLMSSP_CHALLENGE */
// int        imc_offset_challenge;         /* offset of content NTLMSSP_CHALLENGE */
   char       *achc_auth;                   /* address of packet NTLMSSP_AUTH */
   int        imc_len_auth;                 /* length of packet NTLMSSP_AUTH */
// int        imc_offset_auth;              /* offset of content NTLMSSP_AUTH */
   char       *achc_msv_channel_bindings;   /* channel bindings hash   */
   char       *achc_ntlm_sign_key;          /* NTLM signing key        */
   struct dsd_unicode_string dsc_ucs_domain;  /* domain name           */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid / user name    */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
   struct dsd_unicode_string dsc_ucs_workstation;  /* workstation      */
   struct dsd_unicode_string dsc_ucs_prot_target;  /* protocol and target */
   struct dsd_unicode_string dsc_ucs_targetname;  /* TargetName        */
   struct dsd_unicode_string dsc_ucs_netbios_computer_name;
   struct dsd_unicode_string dsc_ucs_netbios_domain_name;
   struct dsd_unicode_string dsc_ucs_dns_computer_name;
   struct dsd_unicode_string dsc_ucs_dns_domain_name;
   struct dsd_unicode_string dsc_ucs_dns_tree_name;
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE BOOL m_proc_ntlm_req( struct dsd_ntlm_req * );
