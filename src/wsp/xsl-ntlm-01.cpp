#ifdef TO_DO_140320
ied_ntlmf_auth_check:             /* check NTLMSSP_AUTH      */
bol_check_channel_bindings
#endif
#define TRY_140319_01
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsl-ntlm-01.cpp                                     |*/
/*| -------------                                                     |*/
/*|  program for processing of NTLM authentication                    |*/
/*|    NT LAN Manager                                                 |*/
/*|    on server side and on client side                              |*/
/*|  part of HOB Framework                                            |*/
/*|  KB 01.01.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* RFC 2104 HMAC: Keyed-Hashing for Message Authentication             */

/* [MS-NLMP].pdf
   NT LAN Manager (NTLM) Authentication Protocol Specification         */

/**
   this implementation of NTLMv2 can generate NTLMSSP_AUTH
   when no domain name is passed from the calling program.
   When no domain name is passed from the calling program,
   the domain name of the server, passed in NTLMSSP_CHALLENGE, is used.
   This is different from the Microsoft implementation,
   but more convenient for users who have to enter the credentials.
*/

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
#include <stdint.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <windows.h>
//#include <Iptypes.h>
//#include <Iphlpapi.h>
#else
#include "hob-unix01.h"
#endif
#include <hob-xslunic1.h>
#include <hob-encry-1.h>
//#include <hob-tab-ascii-ansi-1.h>
//#include <hob-tab-mime-base64.h>
#include "hob-ntlm-01.h"

#define LEN_LM_RESP   24                    /* length LmChallengeResponse */
#ifdef B130427
#ifdef B130311
#define D_NTLM_AUTH_FLAGS   0XE2888215
#else
#define D_NTLM_AUTH_FLAGS   0XA2888205
#endif
#else
#define D_NTLM_AUTH_FLAGS_NORMAL 0XA2888205
#define D_NTLM_AUTH_FLAGS_GSSAPI 0XE2888215
#endif
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0X00080000
#define NTLMSSP_NEGOTIATE_KEY_EXCH 0X40000000
#define NTLMSSP_NEGOTIATE_128  0X20000000
#define NTLMSSP_NEGOTIATE_56   0X80000000
#define NTLMSSP_NEGOTIATE_SIGN 0X00000010
#define NTLMSSP_REQUEST_TARGET 0X00000004

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static inline short int m_get_le2( char *achp_source );
static inline int m_get_le4( char *achp_source );
static inline void m_put_le2( char *achp_target, int imp1 );
static inline void m_put_le4( char *achp_target, int imp1 );
static inline void m_put_le8( char *achp_target, HL_LONGLONG ilp1 );
static inline void m_put_be2( char *achp_target, int imp1 );

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

struct dsd_ntlm_fields_1 {                  /* NTLM fields             */
   unsigned short int usc_len;
   unsigned short int usc_maxlen;
   unsigned int umc_buffer_offset;
};

/* 2.2.1.1   NEGOTIATE_MESSAGE                                         */
struct dsd_ntlm_neg_message {               /* NTLM NEGOTIATE message  */
   char       byrc_signature[ 8 ];
   unsigned int umc_message_type;
   unsigned int umc_negotiate_flags;
   struct dsd_ntlm_fields_1 dsc_domain_name;
   struct dsd_ntlm_fields_1 dsc_workstation;
   char       byrc_version[ 8 ];
};

/* 2.2.1.2   CHALLENGE_MESSAGE                                         */
struct dsd_ntlm_chal_message {              /* NTLM CHALLENGE message  */
   char       byrc_signature[ 8 ];
   unsigned int umc_message_type;
   struct dsd_ntlm_fields_1 dsc_target_name;
   unsigned int umc_negotiate_flags;
   char       byrc_server_challenge[ 8 ];
   char       byrc_reserved_01[ 8 ];
   struct dsd_ntlm_fields_1 dsc_target_info;
   char       byrc_version[ 8 ];
};

struct dsd_ntlm_auth_message {              /* NTLM AUTH message       */
   char       byrc_signature[ 8 ];
   unsigned int umc_message_type;
   struct dsd_ntlm_fields_1 dsc_lm_challenge_response;
   struct dsd_ntlm_fields_1 dsc_nt_challenge_response;
   struct dsd_ntlm_fields_1 dsc_domain_name;
   struct dsd_ntlm_fields_1 dsc_username;
   struct dsd_ntlm_fields_1 dsc_workstation;
   struct dsd_ntlm_fields_1 dsc_encrypted_random_session_key;
   unsigned int umc_negotiate_flags;
   char       byrc_version[ 8 ];
   char       byrc_mic[ 16 ];
};

#ifdef XYZ1
#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const char byrs_ntlm_signature[ 8 ]
     = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

static const unsigned char byrs_gss_api_p01[] = {
   /* contains four length fields                                      */
   0XA1, 0X82, 0X02, 0X37,
   0X30, 0X82, 0X02, 0X33,
   0XA0, 0X03, 0X0A, 0X01,/*SCHMIDJS changed 0XA0 to 0X0A*/
   0X01, 0XA2, 0X82, 0X02,
   0X16, 0X04, 0X82, 0X02,
   0X12
};

#ifdef B130123
static const unsigned char byrs_gss_api_p02[] = {
   0XA3, 0X12, 0X04, 0X10,
   // SCHMIDJS ntlm signature
   0X01, 0X00, 0X00, 0X00,
   0X66, 0XF3, 0X7B, 0XDE,
   0X27, 0X47, 0X64, 0X3C,
   0X00, 0X00, 0X00, 0X00
};
#else
static const unsigned char byrs_gss_api_p02[] = {
   0XA3, 0X12, 0X04, 0X10,
   // SCHMIDJS ntlm signature
   0X01, 0X00, 0X00, 0X00
};
#endif

/** ASN.1 for challenge                                                */
static const unsigned char byrs_gss_api_p03[] = {
   /* contains six length fields                                       */
   0X30, 0X82, 0XFF, 0XFF,
   0XA0, 0X03, 0X02, 0X01, 0X03, 0XA1, 0X82, 0XFF, 0XFF,
   0X30, 0X82, 0XFF, 0XFF,
   0X30, 0X82, 0XFF, 0XFF,
   0XA0, 0X82, 0XFF, 0XFF,
   0X04, 0X82, 0XFF, 0XFF
};

static const unsigned char byrs_ntlm_version[] = {
   0X06, 0X01, 0XB1, 0X1D, 0X00, 0X00, 0X00, 0X0F
};

static const unsigned char byrs_ntlm_magic_cl2se_01[] = {
  's', 'e', 's', 's', 'i', 'o', 'n', ' ',
  'k', 'e', 'y', ' ', 't', 'o', ' ', 'c',
  'l', 'i', 'e', 'n', 't', '-', 't', 'o',
  '-', 's', 'e', 'r', 'v', 'e', 'r', ' ',
  's', 'i', 'g', 'n', 'i', 'n', 'g', ' ',
  'k', 'e', 'y', ' ', 'm', 'a', 'g', 'i',
  'c', ' ', 'c', 'o', 'n', 's', 't', 'a',
  'n', 't', 0
};

static const unsigned char byrs_ntlm_magic_cl2se_02[] = {
  's', 'e', 's', 's', 'i', 'o', 'n', ' ',
  'k', 'e', 'y', ' ', 't', 'o', ' ', 'c',
  'l', 'i', 'e', 'n', 't', '-', 't', 'o',
  '-', 's', 'e', 'r', 'v', 'e', 'r', ' ',
  's', 'e', 'a', 'l', 'i', 'n', 'g', ' ',
  'k', 'e', 'y', ' ', 'm', 'a', 'g', 'i',
  'c', ' ', 'c', 'o', 'n', 's', 't', 'a',
  'n', 't', 0
};

static const unsigned char byrs_ntlm_magic_se2cl_01[] = {
  's', 'e', 's', 's', 'i', 'o', 'n', ' ',
  'k', 'e', 'y', ' ', 't', 'o', ' ', 's',
  'e', 'r', 'v', 'e', 'r', '-', 't', 'o',
  '-', 'c', 'l', 'i', 'e', 'n', 't', ' ',
  's', 'i', 'g', 'n', 'i', 'n', 'g', ' ',
  'k', 'e', 'y', ' ', 'm', 'a', 'g', 'i',
  'c', ' ', 'c', 'o', 'n', 's', 't', 'a',
  'n', 't', 0
};

static const unsigned char byrs_ntlm_magic_se2cl_02[] = {
  's', 'e', 's', 's', 'i', 'o', 'n', ' ',
  'k', 'e', 'y', ' ', 't', 'o', ' ', 's',
  'e', 'r', 'v', 'e', 'r', '-', 't', 'o',
  '-', 'c', 'l', 'i', 'e', 'n', 't', ' ',
  's', 'e', 'a', 'l', 'i', 'n', 'g', ' ',
  'k', 'e', 'y', ' ', 'm', 'a', 'g', 'i',
  'c', ' ', 'c', 'o', 'n', 's', 't', 'a',
  'n', 't', 0
};

/*+-------------------------------------------------------------------+*/
/*| Procedures.                                                       |*/
/*+-------------------------------------------------------------------+*/

extern "C" BOOL m_proc_ntlm_req( struct dsd_ntlm_req *adsp_ntlm_req ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_msv_channel_bindings;     /* check channel bindings hash */
   int        iml1, iml2, iml3;             /* working variables       */
   unsigned int uml1, uml2;                 /* working variables       */
   int        iml_len_domain;               /* length of domain name in bytes */
   int        iml_len_nt_chal;              /* length of NtChallenge   */
   unsigned int uml_negotiate_message_flags;
   unsigned int uml_challenge_message_flags;
   HL_LONGLONG ill_chal_time;               /* MsvAvTimestamp          */
   struct dsd_ntlm_neg_message *adsl_nm1_neg;  /* NTLM NEGOTIATE message  */
   struct dsd_ntlm_chal_message *adsl_nm1_chal;  /* NTLM message CHALLENGE */
   struct dsd_ntlm_auth_message *adsl_nm1_auth;  /* NTLM message AUTH  */
   char       *achl_w1;                     /* working variable        */
   char       *achl_mem_end;                /* check end of memory     */
   char       *achl_nm1_auth_pl;            /* AUTH payload            */
#ifdef XYZ1
   char       *achl_nm1_auth_mic;           /* AUTH MIC                */
#endif
   char       *achl_nt_chal;                /* start of NtChallengeFields */
   char       *achl_domain;                 /* address of domain name  */
   struct dsd_unicode_string *adsl_ucs_w1;  /* working variable        */
   struct dsd_unicode_string dsl_ucs_targetname;  /* TargetName        */
   struct dsd_unicode_string dsl_ucs_domain;  /* authentication domain name */
   int        imrl_md4_array[ MD4_ARRAY_SIZE ];  /* for MD4            */
   int        imrl_md5_array[ MD5_ARRAY_SIZE ];  /* for MD5            */
   char       byrl_hmac_1[ 64 ];            /* for HMAC                */
   char       byrl_hmac_2[ 64 ];            /* for HMAC                */
#ifdef XYZ1
   union {
     char     byrl_md4_pwd[ 16 ];           /* MD4 of password         */
     char     byrl_ntowfv2[ 16 ];           /* NTOWFv2                 */
   };
#endif
   char       byrl_md4_pwd[ 16 ];           /* MD4 of password         */
   char       chrl_rc4_state[ RC4_STATE_SIZE ];  /* RC4 state array    */
   char       byrl_work1[ 2048 ];           /* work area               */

   switch (adsp_ntlm_req->iec_ntlmf) {      /* NTLM request function to process */
     case ied_ntlmf_neg_gen:                /* generate NTLMSSP_NEGOTIATE */
       goto p_neg_gen_00;                   /* generate NTLMSSP_NEGOTIATE */
     case ied_ntlmf_neg_check:              /* check NTLMSSP_NEGOTIATE */
       goto p_neg_check_00;                 /* check NTLMSSP_NEGOTIATE */
     case ied_ntlmf_chal_gen:               /* generate NTLMSSP_CHALLENGE */
       goto p_chal_00;                      /* process CHALLENGE       */
     case ied_ntlmf_auth_prep:              /* prepare from NTLMSSP_AUTH */
     case ied_ntlmf_auth_check:             /* check NTLMSSP_AUTH      */
     case ied_ntlmf_auth_gen:               /* generate NTLMSSP_AUTH   */
       goto p_auth_00;                      /* process AUTH            */
   }
   adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
   return FALSE;

   p_neg_gen_00:                            /* generate NTLMSSP_NEGOTIATE */
// to-do 30.05.13 KB - GSSAPI missing
   iml1 = sizeof(struct dsd_ntlm_neg_message);
   iml2 = 0;
   while (adsp_ntlm_req->dsc_ucs_domain.imc_len_str != 0) {  /* domain name */
     iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                          &adsp_ntlm_req->dsc_ucs_domain );
     if (iml2 <= 0) break;                  /* no valid content        */
     iml1 += iml2 * sizeof(HL_WCHAR);
     break;
   }
   iml3 = 0;
   while (adsp_ntlm_req->dsc_ucs_workstation.imc_len_str != 0) {  /* workstation */
     iml3 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                          &adsp_ntlm_req->dsc_ucs_workstation );
     if (iml3 <= 0) break;                  /* no valid content        */
     iml1 += iml3 * sizeof(HL_WCHAR);
     break;
   }
   if (adsp_ntlm_req->imc_len_negotiate < iml1) {  /* length of packet NTLMSSP_NEGOTIATE */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   adsl_nm1_neg = (struct dsd_ntlm_neg_message *) adsp_ntlm_req->achc_negotiate;  /* NTLM NEGOTIATE message  */
   memset( adsl_nm1_neg, 0, sizeof(struct dsd_ntlm_neg_message) );  /* address of packet NTLMSSP_NEGOTIATE */
   memcpy( adsl_nm1_neg->byrc_signature, byrs_ntlm_signature, sizeof(byrs_ntlm_signature) );
   m_put_le4( (char *) &adsl_nm1_neg->umc_message_type, 1 );
   uml1 = D_NTLM_AUTH_FLAGS_NORMAL;
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
     uml1 = D_NTLM_AUTH_FLAGS_GSSAPI;
   }
   m_put_le4( (char *) &adsl_nm1_neg->umc_negotiate_flags, uml1 );
   memcpy( adsl_nm1_neg->byrc_version, byrs_ntlm_version, sizeof(byrs_ntlm_version) );
   achl_w1 = (char *) (adsl_nm1_neg + 1);
   if (iml2 > 0) {                          /* domain name             */
     uml1 = iml2 * sizeof(HL_WCHAR);
     m_put_le2( (char *) &adsl_nm1_neg->dsc_domain_name.usc_len, uml1 );
     m_put_le2( (char *) &adsl_nm1_neg->dsc_domain_name.usc_maxlen, uml1 );
     uml1 = achl_w1 - ((char *) adsl_nm1_neg);
     m_put_le4( (char *) &adsl_nm1_neg->dsc_domain_name.umc_buffer_offset, uml1 );
     m_cpy_vx_ucs( achl_w1, iml2, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &adsp_ntlm_req->dsc_ucs_domain );
     achl_w1 += iml2 * sizeof(HL_WCHAR);
   }
   if (iml3 > 0) {                          /* workstation             */
     uml1 = iml3 * sizeof(HL_WCHAR);
     m_put_le2( (char *) &adsl_nm1_neg->dsc_workstation.usc_len, uml1 );
     m_put_le2( (char *) &adsl_nm1_neg->dsc_workstation.usc_maxlen, uml1 );
     uml1 = achl_w1 - ((char *) adsl_nm1_neg);
     m_put_le4( (char *) &adsl_nm1_neg->dsc_workstation.umc_buffer_offset, uml1 );
     m_cpy_vx_ucs( achl_w1, iml3, ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                   &adsp_ntlm_req->dsc_ucs_workstation );
   }
   adsp_ntlm_req->imc_len_negotiate = iml1;  /* length of packet NTLMSSP_NEGOTIATE */
   return TRUE;                             /* all done                */

   p_neg_check_00:                          /* check NTLMSSP_NEGOTIATE */
   adsl_nm1_neg = (struct dsd_ntlm_neg_message *) adsp_ntlm_req->achc_negotiate;  /* NTLM NEGOTIATE message  */
   achl_mem_end = (char *) adsl_nm1_neg + adsp_ntlm_req->imc_len_negotiate;  /* check end of memory */
// to-do 03.03.13 KB GSS-API
   if (adsp_ntlm_req->boc_gssapi == FALSE) {  /* use GSSAPI            */
     goto p_neg_check_20;                   /* GSSAPI processed - pure NTLM packet */
   }

/**
   implemented 07.12.15 KB - for CredSSP from mstsc
*/
   if (((char *) adsl_nm1_neg + 2) > achl_mem_end) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (*((char *) adsl_nm1_neg) != 0X30) {  /* not ASN.1               */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   achl_w1 = (char *) adsl_nm1_neg + 1 + 1;  /* after length           */
   iml1 = *((unsigned char *) adsl_nm1_neg + 1);  /* get length        */
   if (iml1 >= 0X80) {                      /* length in multiple bytes */
     iml2 = iml1 & 0X7F;
     if (iml2 == 0) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if ((achl_w1 + iml2) > achl_mem_end) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     /* not checked: number too big                                    */
     iml1 = 0;
     do {                                   /* loop number big endian  */
       iml1 <<= 8;
       iml1 |= *((unsigned char *) achl_w1);
       achl_w1++;
       iml2--;                              /* decrement index         */
     } while (iml2 > 0);
   }
   if ((achl_w1 + iml1) != achl_mem_end) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   adsl_nm1_neg = (struct dsd_ntlm_neg_message *) (achl_w1 + 15);

   p_neg_check_20:                          /* GSSAPI processed - pure NTLM packet */
   if (((char *) (adsl_nm1_neg + 1)) > achl_mem_end) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (memcmp( adsl_nm1_neg->byrc_signature, byrs_ntlm_signature, sizeof(byrs_ntlm_signature) )) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   uml1
     = *((unsigned char *) &adsl_nm1_neg->umc_message_type + 0)
         | (*((unsigned char *) &adsl_nm1_neg->umc_message_type + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_neg->umc_message_type + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_neg->umc_message_type + 3) << 24);
   if (uml1 != 1) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   /* check domain name                                                */
   uml1
     = *((unsigned char *) &adsl_nm1_neg->dsc_domain_name.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_neg->dsc_domain_name.usc_len + 1) << 8);
   if (uml1 > 0) {                          /* with domain name        */
     uml2
       = *((unsigned char *) &adsl_nm1_neg->dsc_domain_name.umc_buffer_offset + 0)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_domain_name.umc_buffer_offset + 1) << 8)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_domain_name.umc_buffer_offset + 2) << 16)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_domain_name.umc_buffer_offset + 3) << 24);
     if (uml2 < sizeof(struct dsd_ntlm_neg_message)) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (((char *) adsl_nm1_neg + uml2 + uml1) > achl_mem_end) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (uml1 & 1) {                        /* number of bytes not even */
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     adsp_ntlm_req->dsc_ucs_domain.ac_str = (char *) adsl_nm1_neg + uml2;
     adsp_ntlm_req->dsc_ucs_domain.imc_len_str = uml1 / sizeof(HL_WCHAR);
     adsp_ntlm_req->dsc_ucs_domain.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   }
   /* check workstation                                                */
   uml1
     = *((unsigned char *) &adsl_nm1_neg->dsc_workstation.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_neg->dsc_workstation.usc_len + 1) << 8);
   if (uml1 > 0) {                          /* with workstation name   */
     uml2
       = *((unsigned char *) &adsl_nm1_neg->dsc_workstation.umc_buffer_offset + 0)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_workstation.umc_buffer_offset + 1) << 8)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_workstation.umc_buffer_offset + 2) << 16)
           | (*((unsigned char *) &adsl_nm1_neg->dsc_workstation.umc_buffer_offset + 3) << 24);
     if (uml2 < sizeof(struct dsd_ntlm_neg_message)) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (((char *) adsl_nm1_neg + uml2 + uml1) > achl_mem_end) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (uml1 & 1) {                        /* number of bytes not even */
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     adsp_ntlm_req->dsc_ucs_workstation.ac_str = (char *) adsl_nm1_neg + uml2;
     adsp_ntlm_req->dsc_ucs_workstation.imc_len_str = uml1 / sizeof(HL_WCHAR);
     adsp_ntlm_req->dsc_ucs_workstation.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   }
   return TRUE;

   p_chal_00:                               /* process CHALLENGE       */
   adsl_nm1_chal = (struct dsd_ntlm_chal_message *) adsp_ntlm_req->achc_challenge;  /* NTLM message CHALLENGE */
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
     adsl_nm1_chal = (struct dsd_ntlm_chal_message *) (adsp_ntlm_req->achc_challenge + sizeof(byrs_gss_api_p03));  /* NTLM message CHALLENGE */
   }
   achl_mem_end = (char *) (adsl_nm1_chal + 1);  /* output end of memory */
   if (achl_mem_end > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   adsl_nm1_neg = (struct dsd_ntlm_neg_message *) adsp_ntlm_req->achc_negotiate;  /* NTLM NEGOTIATE message  */
   memcpy( adsl_nm1_chal->byrc_signature, byrs_ntlm_signature, sizeof(byrs_ntlm_signature) );
   m_put_le4( (char *) &adsl_nm1_chal->umc_message_type, 2 );
   uml_negotiate_message_flags
     = *((unsigned char *) &adsl_nm1_neg->umc_negotiate_flags + 0)
         | (*((unsigned char *) &adsl_nm1_neg->umc_negotiate_flags + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_neg->umc_negotiate_flags + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_neg->umc_negotiate_flags + 3) << 24);
   if ((uml_negotiate_message_flags & NTLMSSP_REQUEST_TARGET) == 0) {
     memset( &adsl_nm1_chal->dsc_target_name, 0, sizeof(struct dsd_ntlm_fields_1) );
     goto p_chal_20;                        /* after TargetName        */
   }
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_targetname );  /* TargetName */
   if ((achl_mem_end + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - achl_mem_end,
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_targetname );  /* TargetName */
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( (char *) &adsl_nm1_chal->dsc_target_name.usc_len, iml1 );
   m_put_le2( (char *) &adsl_nm1_chal->dsc_target_name.usc_maxlen, iml1 );
   m_put_le4( (char *) &adsl_nm1_chal->dsc_target_name.umc_buffer_offset, achl_mem_end - ((char *) adsl_nm1_chal) );
   achl_mem_end += iml1;                    /* end of TargetName       */

   p_chal_20:                               /* after TargetName        */
#ifdef B130427
   m_put_le4( (char *) &adsl_nm1_chal->umc_negotiate_flags,
              (unsigned int) D_NTLM_AUTH_FLAGS );
#else
   uml1 = D_NTLM_AUTH_FLAGS_NORMAL;
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
     uml1 = D_NTLM_AUTH_FLAGS_GSSAPI;
   }
   m_put_le4( (char *) &adsl_nm1_chal->umc_negotiate_flags, uml1 );
#endif
   /* NTLM server challenge                                            */
   bol_rc = adsp_ntlm_req->amc_get_random( adsp_ntlm_req->vpc_userfld,
                                           adsl_nm1_chal->byrc_server_challenge,
                                           sizeof(adsl_nm1_chal->byrc_server_challenge) );
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   memset( adsl_nm1_chal->byrc_reserved_01, 0, sizeof(adsl_nm1_chal->byrc_reserved_01) );
   achl_w1 = achl_mem_end;                  /* save start TargetInfoFields */
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_netbios_computer_name );
   if ((achl_mem_end + 4 + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end + 4,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - (achl_mem_end + 4),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_netbios_computer_name );
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( achl_mem_end + 0, 1 );
   m_put_le2( achl_mem_end + 2, iml1 );
   achl_mem_end += 4 + iml1;
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_netbios_domain_name );
   if ((achl_mem_end + 4 + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end + 4,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - (achl_mem_end + 4),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_netbios_domain_name );
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( achl_mem_end + 0, 2 );
   m_put_le2( achl_mem_end + 2, iml1 );
   achl_mem_end += 4 + iml1;
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_computer_name );
   if ((achl_mem_end + 4 + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end + 4,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - (achl_mem_end + 4),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_computer_name );
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( achl_mem_end + 0, 3 );
   m_put_le2( achl_mem_end + 2, iml1 );
   achl_mem_end += 4 + iml1;
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_domain_name );
   if ((achl_mem_end + 4 + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end + 4,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - (achl_mem_end + 4),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_domain_name );
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( achl_mem_end + 0, 4 );
   m_put_le2( achl_mem_end + 2, iml1 );
   achl_mem_end += 4 + iml1;
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_tree_name );
   if ((achl_mem_end + 4 + iml1 * sizeof(HL_WCHAR)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml2 = m_cpy_vx_ucs( achl_mem_end + 4,
                        (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)
                          - (achl_mem_end + 4),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_dns_tree_name );
   if (iml2 != iml1) {                      /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le2( achl_mem_end + 0, 5 );
   m_put_le2( achl_mem_end + 2, iml1 );
   achl_mem_end += 4 + iml1;
   /* Timestamp                                                        */
   if ((achl_mem_end + 4 + sizeof(HL_LONGLONG)) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   bol_rc = adsp_ntlm_req->amc_get_epoch( adsp_ntlm_req->vpc_userfld,
                                          &ill_chal_time );
   m_put_le2( achl_mem_end + 0, 7 );
   m_put_le2( achl_mem_end + 2, sizeof(HL_LONGLONG) );
   ill_chal_time *= 1000 * 10;
#ifdef B150103
// ill_chal_time += 116444736000000000L;    /* from Johannes Schmidt   */
#ifndef HL_FREEBSD
   ill_chal_time += 116444736000000000L;    /* from Johannes Schmidt   */
#endif
#ifdef HL_FREEBSD
   ill_chal_time += 116444736000000000LL;   /* from Johannes Schmidt   */
#endif
#endif
#ifndef B150103
   ill_chal_time += (HL_LONGLONG) 116444736 * (HL_LONGLONG) 1000000000;
#endif

   m_put_le8( achl_mem_end + 4, ill_chal_time );
   achl_mem_end += 4 + sizeof(HL_LONGLONG);
   if ((achl_mem_end + 4) > (adsp_ntlm_req->achc_challenge + adsp_ntlm_req->imc_len_challenge)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   memset( achl_mem_end, 0, 4 );            /* end of list             */
   achl_mem_end += 4;
   m_put_le2( (char *) &adsl_nm1_chal->dsc_target_info.usc_len, achl_mem_end - achl_w1 );
   m_put_le2( (char *) &adsl_nm1_chal->dsc_target_info.usc_maxlen, achl_mem_end - achl_w1 );
   m_put_le4( (char *) &adsl_nm1_chal->dsc_target_info.umc_buffer_offset, achl_w1 - ((char *) adsl_nm1_chal) );
   memcpy( adsl_nm1_chal->byrc_version, byrs_ntlm_version, sizeof(byrs_ntlm_version) );
   adsp_ntlm_req->imc_len_challenge = achl_mem_end - adsp_ntlm_req->achc_challenge;  /* length of packet NTLMSSP_CHALLENGE */
   if (adsp_ntlm_req->boc_gssapi == FALSE) {  /* use GSSAPI            */
     return TRUE;
   }
   memcpy( adsp_ntlm_req->achc_challenge, byrs_gss_api_p03, sizeof(byrs_gss_api_p03) );  /* NTLM message AUTH */
   /* set length ASN.1 in GSS_API fields                               */
   iml1 = achl_mem_end - ((char *) adsl_nm1_chal);
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X02, iml1 + sizeof(byrs_gss_api_p03) - 0X02 - 2 );
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X0B, iml1 + sizeof(byrs_gss_api_p03) - 0X0B - 2 );
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X0F, iml1 + sizeof(byrs_gss_api_p03) - 0X0F - 2 );
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X13, iml1 + sizeof(byrs_gss_api_p03) - 0X13 - 2 );
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X17, iml1 + sizeof(byrs_gss_api_p03) - 0X17 - 2 );
   m_put_be2( adsp_ntlm_req->achc_challenge + 0X1B, iml1 + sizeof(byrs_gss_api_p03) - 0X1B - 2 );
   return TRUE;

   p_auth_00:                               /* process AUTH            */
   adsl_nm1_chal = (struct dsd_ntlm_chal_message *) adsp_ntlm_req->achc_challenge;  /* NTLM message CHALLENGE */
   adsl_nm1_auth = (struct dsd_ntlm_auth_message *) adsp_ntlm_req->achc_auth;  /* NTLM message AUTH */
   dsl_ucs_targetname = adsp_ntlm_req->dsc_ucs_targetname;  /* TargetName */
   dsl_ucs_domain = adsp_ntlm_req->dsc_ucs_domain;  /* authentication domain name */
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
//   adsl_nm1_chal = (struct dsd_ntlm_chal_message *) (adsp_ntlm_req->achc_challenge + 0X23);  /* NTLM message CHALLENGE */
// to-do 24.08.13 KB - decode ASN.1 correct
#ifdef XYZ1
     achl_w1 = adsp_ntlm_req->achc_challenge;
     iml1 = *(achl_w1 + 0X1C) & 0X0F;       /* number of digits        */
     achl_w1 += 0X1C + iml1;                /* after length            */
     iml1 = *(achl_w1 + 0X02) & 0X0F;       /* number of digits        */
     adsl_nm1_chal = (struct dsd_ntlm_chal_message *) (achl_w1 + iml1 + 3);  /* NTLM message CHALLENGE */
#endif
     achl_w1 = adsp_ntlm_req->achc_challenge;
     iml1 = *(achl_w1 + 0X01) & 0X0F;       /* number of digits        */
     achl_w1 += 0X03 + iml1;                /* after length            */
     iml1 = *achl_w1 & 0X0F;                /* number of digits        */
     achl_w1 += 0X15 + iml1;                /* after length            */
     iml1 = *achl_w1 & 0X0F;                /* number of digits        */
     achl_w1 += iml1;                       /* after length            */
     iml1 = *(achl_w1 + 0X02) & 0X0F;       /* number of digits        */
     adsl_nm1_chal = (struct dsd_ntlm_chal_message *) (achl_w1 + iml1 + 3);  /* NTLM message CHALLENGE */
     adsl_nm1_auth = (struct dsd_ntlm_auth_message *) (adsp_ntlm_req->achc_auth + sizeof(byrs_gss_api_p01));  /* NTLM message AUTH */
   }
   if ((((char *) (adsl_nm1_chal + 1)) - adsp_ntlm_req->achc_challenge)
         > adsp_ntlm_req->imc_len_challenge) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if ((((char *) (adsl_nm1_auth + 1)) - adsp_ntlm_req->achc_auth)
         > adsp_ntlm_req->imc_len_auth) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   uml_challenge_message_flags
     = *((unsigned char *) &adsl_nm1_chal->umc_negotiate_flags + 0)
         | (*((unsigned char *) &adsl_nm1_chal->umc_negotiate_flags + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_chal->umc_negotiate_flags + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_chal->umc_negotiate_flags + 3) << 24);
   if (adsp_ntlm_req->iec_ntlmf == ied_ntlmf_auth_gen) {  /* do not fill fields from NTLMSSP_AUTH */
     goto p_auth_20;                        /* check challenge         */
   }
   if (memcmp( adsl_nm1_auth->byrc_signature, byrs_ntlm_signature, sizeof(byrs_ntlm_signature) )) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   uml1
     = *((unsigned char *) &adsl_nm1_auth->umc_message_type + 0)
         | (*((unsigned char *) &adsl_nm1_auth->umc_message_type + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_auth->umc_message_type + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_auth->umc_message_type + 3) << 24);
   if (uml1 != 3) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   /* check domain name                                                */
   uml1
     = *((unsigned char *) &adsl_nm1_auth->dsc_domain_name.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_domain_name.usc_len + 1) << 8);
   if (uml1 == 0) {                         /* no domain name          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   uml2
     = *((unsigned char *) &adsl_nm1_auth->dsc_domain_name.umc_buffer_offset + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_domain_name.umc_buffer_offset + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_domain_name.umc_buffer_offset + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_domain_name.umc_buffer_offset + 3) << 24);
   if (uml2 < sizeof(struct dsd_ntlm_auth_message)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (((char *) adsl_nm1_auth + uml2 + uml1) > (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (uml1 & 1) {                          /* number of bytes not even */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   adsp_ntlm_req->dsc_ucs_domain.ac_str = (char *) adsl_nm1_auth + uml2;
   adsp_ntlm_req->dsc_ucs_domain.imc_len_str = uml1 / sizeof(HL_WCHAR);
   adsp_ntlm_req->dsc_ucs_domain.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   achl_domain = (char *) adsl_nm1_auth + uml2;  /* address of domain name */
   iml_len_domain = uml1;                   /* length of domain name in bytes */
   /* check user name                                                  */
   uml1
     = *((unsigned char *) &adsl_nm1_auth->dsc_username.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_username.usc_len + 1) << 8);
   if (uml1 == 0) {                         /* no user name            */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   uml2
     = *((unsigned char *) &adsl_nm1_auth->dsc_username.umc_buffer_offset + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_username.umc_buffer_offset + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_username.umc_buffer_offset + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_username.umc_buffer_offset + 3) << 24);
   if (uml2 < sizeof(struct dsd_ntlm_auth_message)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (((char *) adsl_nm1_auth + uml2 + uml1) > (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (uml1 & 1) {                          /* number of bytes not even */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   adsp_ntlm_req->dsc_ucs_userid.ac_str = (char *) adsl_nm1_auth + uml2;
   adsp_ntlm_req->dsc_ucs_userid.imc_len_str = uml1 / sizeof(HL_WCHAR);
   adsp_ntlm_req->dsc_ucs_userid.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   /* check workstation                                                */
   uml1
     = *((unsigned char *) &adsl_nm1_auth->dsc_workstation.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_workstation.usc_len + 1) << 8);
   if (uml1 > 0) {                          /* with workstation        */
     uml2
       = *((unsigned char *) &adsl_nm1_auth->dsc_workstation.umc_buffer_offset + 0)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_workstation.umc_buffer_offset + 1) << 8)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_workstation.umc_buffer_offset + 2) << 16)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_workstation.umc_buffer_offset + 3) << 24);
     if (uml2 < sizeof(struct dsd_ntlm_auth_message)) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (((char *) adsl_nm1_auth + uml2 + uml1) > (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     if (uml1 & 1) {                        /* number of bytes not even */
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     adsp_ntlm_req->dsc_ucs_workstation.ac_str = (char *) adsl_nm1_auth + uml2;
     adsp_ntlm_req->dsc_ucs_workstation.imc_len_str = uml1 / sizeof(HL_WCHAR);
     adsp_ntlm_req->dsc_ucs_workstation.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   }
   /* check fields from NtChallengeResponseFields                      */
   uml1
     = *((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_len + 1) << 8);
   uml2
     = *((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 3) << 24);
   if ((((char *) adsl_nm1_auth + uml2 + uml1) - adsp_ntlm_req->achc_auth)
         > adsp_ntlm_req->imc_len_auth) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   achl_nt_chal = (char *) adsl_nm1_auth + uml2;  /* start of NtChallengeFields */
   iml_len_nt_chal = uml1;                  /* length of NtChallenge   */
   adsp_ntlm_req->dsc_ucs_netbios_computer_name.imc_len_str = 0;  /* clear length of string in elements */
   adsp_ntlm_req->dsc_ucs_netbios_domain_name.imc_len_str = 0;  /* clear length of string in elements */
   adsp_ntlm_req->dsc_ucs_dns_computer_name.imc_len_str = 0;  /* clear length of string in elements */
   adsp_ntlm_req->dsc_ucs_dns_domain_name.imc_len_str = 0;  /* clear length of string in elements */
   adsp_ntlm_req->dsc_ucs_dns_tree_name.imc_len_str = 0;  /* clear length of string in elements */
   ill_chal_time = 0;                       /* MsvAvTimestamp          */
   /* loop over NtChallengeResponseFields                              */
   iml1 = 44;
   do {                                     /* loop                    */
     if ((iml1 + 4) > uml1) break;
     iml2 = *((unsigned char *) achl_nt_chal + iml1 + 0 + 0)
              | (*((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 0 + 1) << 8);
     if (iml2 == 0) break;
     iml3 = *((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 2 + 0)
              | (*((unsigned char *) achl_nt_chal + iml1 + 2 + 1) << 8);
     if ((iml1 + 4 + iml3) > uml1) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     adsl_ucs_w1 = NULL;                    /* no unicode string       */
     switch (iml2) {                        /* item type               */
       case 1:
         adsl_ucs_w1 = &adsp_ntlm_req->dsc_ucs_netbios_computer_name;
         break;
       case 2:
         adsl_ucs_w1 = &adsp_ntlm_req->dsc_ucs_netbios_domain_name;
         break;
       case 3:
         adsl_ucs_w1 = &adsp_ntlm_req->dsc_ucs_dns_computer_name;
         break;
       case 4:
         adsl_ucs_w1 = &adsp_ntlm_req->dsc_ucs_dns_domain_name;
         break;
       case 5:
         adsl_ucs_w1 = &adsp_ntlm_req->dsc_ucs_dns_tree_name;
         break;
       case 7:
         if (ill_chal_time != 0) {          /* MsvAvTimestamp          */
           adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
           return FALSE;
         }
         ill_chal_time                      /* MsvAvTimestamp          */
           = ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 0))
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 1) << 8)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 2) << 16)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 3) << 24)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 4) << 32)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 5) << 40)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 6) << 48)
               | ((HL_LONGLONG) *((unsigned char *) achl_nt_chal + iml1 + 4 + 7) << 56);
         if (ill_chal_time == 0) {          /* MsvAvTimestamp          */
           adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
           return FALSE;
         }
         break;
     }
     if (adsl_ucs_w1) {                     /* set unicode string      */
       if (iml3 & 1) {                      /* length not even         */
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
       adsl_ucs_w1->ac_str = achl_nt_chal + iml1 + 4;  /* address of string */
       adsl_ucs_w1->imc_len_str = iml3 / sizeof(HL_WCHAR);  /* length of string in elements */
       adsl_ucs_w1->iec_chs_str = ied_chs_le_utf_16;  /* character set of string */
#ifdef XYZ1
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
       if (   (iml2 == 1)
           && (dsl_ucs_targetname.imc_len_str == 0)) {  /* TargetName  */
         dsl_ucs_targetname = *adsl_ucs_w1;
       }
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
       if (   (iml2 == 2)
           && (dsl_ucs_domain.imc_len_str == 0)) {  /* authentication domain name */
         dsl_ucs_domain = *adsl_ucs_w1;
       }
#endif
     }
     iml1 += 4 + iml3;
   } while (iml1 < uml1);
   if (ill_chal_time == 0) {                /* MsvAvTimestamp          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   if (adsp_ntlm_req->iec_ntlmf == ied_ntlmf_auth_prep) {  /* prepare from NTLMSSP_AUTH */
     return TRUE;                           /* all done                */
   }
   goto p_auth_40;                          /* check content of NTLMSSP_AUTH */

   p_auth_20:                               /* check challenge         */
   /* get fields from NTLM message CHALLENGE                           */
   uml1
     = *((unsigned char *) &adsl_nm1_chal->dsc_target_info.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_chal->dsc_target_info.usc_len + 1) << 8);
   uml2
     = *((unsigned char *) &adsl_nm1_chal->dsc_target_info.umc_buffer_offset + 0)
         | (*((unsigned char *) &adsl_nm1_chal->dsc_target_info.umc_buffer_offset + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_chal->dsc_target_info.umc_buffer_offset + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_chal->dsc_target_info.umc_buffer_offset + 3) << 24);
   if ((((char *) adsl_nm1_chal + uml2 + uml1) - adsp_ntlm_req->achc_challenge)
         > adsp_ntlm_req->imc_len_challenge) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   ill_chal_time = 0;                       /* MsvAvTimestamp          */
   /* loop over TargetInfoFields                                       */
   iml1 = 0;
   do {                                     /* loop                    */
     if ((iml1 + 4) > uml1) break;
     iml2 = *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 0 + 0)
              | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 0 + 1) << 8);
     if (iml2 == 0) break;
     iml3 = *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 2 + 0)
              | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 2 + 1) << 8);
     if ((iml1 + 4 + iml3) > uml1) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
//#ifdef XYZ1
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
     if (   (iml2 == 1)
         && (dsl_ucs_targetname.imc_len_str == 0)) {  /* TargetName    */
       dsl_ucs_targetname.ac_str = (char *) adsl_nm1_chal + uml2 + iml1 + 4;  /* address of string */
       dsl_ucs_targetname.imc_len_str = iml3 / sizeof(HL_WCHAR);  /* length string in elements */
       dsl_ucs_targetname.iec_chs_str = ied_chs_le_utf_16;  /* character set string - Unicode UTF-16 little endian */
     }
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
     if (   (iml2 == 2)
         && (dsl_ucs_domain.imc_len_str == 0)) {  /* authentication domain name */
       dsl_ucs_domain.ac_str = (char *) adsl_nm1_chal + uml2 + iml1 + 4;  /* address of string */
       dsl_ucs_domain.imc_len_str = iml3 / sizeof(HL_WCHAR);  /* length string in elements */
       dsl_ucs_domain.iec_chs_str = ied_chs_le_utf_16;  /* character set string - Unicode UTF-16 little endian */
     }
//#endif
     if (iml2 == 7) {
       if (ill_chal_time != 0) {            /* MsvAvTimestamp          */
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
#ifdef B130131
#ifdef B130123
       ill_chal_time                        /* MsvAvTimestamp          */
         = *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#else
       ill_chal_time                        /* MsvAvTimestamp          */
         = (HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#endif
#else
       ill_chal_time                        /* MsvAvTimestamp          */
         = ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0))
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#endif
       if (ill_chal_time == 0) {            /* MsvAvTimestamp          */
         return FALSE;
       }
     }
     iml1 += 4 + iml3;
   } while (iml1 < uml1);

   achl_nm1_auth_pl = (char *) (adsl_nm1_auth + 1);  /* AUTH payload   */
   memcpy( adsl_nm1_auth->byrc_signature, byrs_ntlm_signature, sizeof(byrs_ntlm_signature) );
   m_put_le4( (char *) &adsl_nm1_auth->umc_message_type, 3 );
// memset( &adsl_nm1_auth->dsc_lm_challenge_response, 0, sizeof(struct dsd_ntlm_fields_1) );
   /* LAN Manager Response empty - only zeroes                         */
   memset( achl_nm1_auth_pl, 0, LEN_LM_RESP );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_lm_challenge_response.usc_len, LEN_LM_RESP );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_lm_challenge_response.usc_maxlen, LEN_LM_RESP );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_lm_challenge_response.umc_buffer_offset, achl_nm1_auth_pl - ((char *) adsl_nm1_auth) );
   achl_nm1_auth_pl += LEN_LM_RESP;
   /* compute NtChallengeResponse                                      */
   achl_nt_chal = achl_nm1_auth_pl;         /* start of NtChallengeFields */
   achl_nm1_auth_pl += 16;
   *achl_nm1_auth_pl++ = 0X01;
   *achl_nm1_auth_pl++ = 0X01;
   memset( achl_nm1_auth_pl, 0, 2 + 4 );
   achl_nm1_auth_pl += 2 + 4;
   achl_w1 = achl_nm1_auth_pl;
   if (ill_chal_time != 0) {                /* MsvAvTimestamp          */
     iml1 = 0;
     do {
       *achl_nm1_auth_pl++ = (unsigned char) (ill_chal_time >> (iml1 << 3));
       iml1++;
     } while (iml1 < 8);
#ifdef B150207
/* problem SAMBA */
   } else {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
#endif
   }
   adsp_ntlm_req->amc_get_random( adsp_ntlm_req->vpc_userfld, achl_nm1_auth_pl, 8 );
   achl_nm1_auth_pl += 8;
   memset( achl_nm1_auth_pl, 0, 4 );
   achl_nm1_auth_pl += 4;
   /* attribute pairs                                                  */
   iml1 = m_cpy_vx_ucs( achl_nm1_auth_pl + 4,
                        (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                          - (achl_nm1_auth_pl + 4),
                        ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                        &dsl_ucs_targetname );  /* TargetName          */
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 1;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
   iml1 = m_cpy_vx_ucs( achl_nm1_auth_pl + 4,
                        (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                          - (achl_nm1_auth_pl + 4),
                        ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                        &dsl_ucs_domain );  /* authentication domain name */
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 2;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
#ifdef B140319
   iml1 = m_cpy_vx_vx( achl_nm1_auth_pl + 4,
                       (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                         - (achl_nm1_auth_pl + 4),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (void *) "hobtest01.local",
                       -1,
                       ied_chs_utf_8 );
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 4;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
   iml1 = m_cpy_vx_vx( achl_nm1_auth_pl + 4,
                       (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                         - (achl_nm1_auth_pl + 4),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (void *) "HOBC01J022.hobtest01.local",
                       -1,
                       ied_chs_utf_8 );
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 3;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
   iml1 = m_cpy_vx_vx( achl_nm1_auth_pl + 4,
                       (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                         - (achl_nm1_auth_pl + 4),
                       ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                       (void *) "hobtest01.local",
                       -1,
                       ied_chs_utf_8 );
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 5;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
#endif
   *(achl_nm1_auth_pl + 0 + 0) = 7;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = 8;
   *(achl_nm1_auth_pl + 2 + 1) = 0;
   memcpy( achl_nm1_auth_pl + 4, achl_w1, 8 );
   achl_nm1_auth_pl += 4 + 8;
   iml1 = m_cpy_vx_ucs( achl_nm1_auth_pl + 4,
                        (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                          - (achl_nm1_auth_pl + 4),
                        ied_chs_le_utf_16,   /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_prot_target );
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   iml1 *= sizeof(HL_WCHAR);                /* length in bytes         */
   *(achl_nm1_auth_pl + 0 + 0) = 9;
   *(achl_nm1_auth_pl + 0 + 1) = 0;
   *(achl_nm1_auth_pl + 2 + 0) = (unsigned char) iml1;
   *(achl_nm1_auth_pl + 2 + 1) = (unsigned char) (iml1 >> 8);
   achl_nm1_auth_pl += 4 + iml1;
   if (adsp_ntlm_req->achc_msv_channel_bindings) {  /* channel bindings hash */
     *(achl_nm1_auth_pl + 0 + 0) = 0X000A;
     *(achl_nm1_auth_pl + 0 + 1) = 0;
     *(achl_nm1_auth_pl + 0 + 2) = (unsigned char) LEN_MSV_CHANNEL_BINDINGS;
     *(achl_nm1_auth_pl + 0 + 3) = 0;
     memcpy( achl_nm1_auth_pl + 4,
             adsp_ntlm_req->achc_msv_channel_bindings,  /* channel bindings hash */
             LEN_MSV_CHANNEL_BINDINGS );    /* length channel bindings hash */
     achl_nm1_auth_pl += 4 + LEN_MSV_CHANNEL_BINDINGS;
   }
#ifdef TRY_140319_01
   memset( achl_nm1_auth_pl, 0, 12 );
   achl_nm1_auth_pl += 12;
#endif
   /* end of NtChallengeResponse                                       */
   iml_len_nt_chal = achl_nm1_auth_pl - achl_nt_chal;  /* length of NtChallenge */
#ifdef XYZ1
   achl_nm1_auth_mic = achl_nm1_auth_pl;    /* AUTH MIC                */
   achl_nm1_auth_pl += 16;                  /* space for MIC           */
#endif
   m_put_le2( (char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_len, iml_len_nt_chal );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_maxlen, iml_len_nt_chal );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset, achl_nt_chal - ((char *) adsl_nm1_auth) );
//#define D_DOMAIN_SPEC
#ifdef WORK_140319
#ifndef D_DOMAIN_SPEC
   /* get domain from challenge                                        */
   iml_len_domain = m_get_le2( (char *) &adsl_nm1_chal->dsc_target_name.usc_len );
   memcpy( achl_nm1_auth_pl,
           (char *) adsl_nm1_chal + m_get_le4( (char *) &adsl_nm1_chal->dsc_target_name.umc_buffer_offset ),
           iml_len_domain );
#endif
#endif
   iml_len_domain = m_cpy_vx_ucs( achl_nm1_auth_pl,
                                  (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                                    - achl_nm1_auth_pl,
                                  ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                                  &dsl_ucs_domain )  /* authentication domain name */
                      * sizeof(HL_WCHAR);
   if (iml_len_domain < 0) {                /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   m_put_le2( (char *) &adsl_nm1_auth->dsc_domain_name.usc_len, iml_len_domain );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_domain_name.usc_maxlen, iml_len_domain );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_domain_name.umc_buffer_offset, achl_nm1_auth_pl - ((char *) adsl_nm1_auth) );
   achl_domain = achl_nm1_auth_pl;          /* address of domain name  */
   achl_nm1_auth_pl += iml_len_domain;
   iml1 = m_cpy_vx_ucs( achl_nm1_auth_pl,
                        (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                          - achl_nm1_auth_pl,
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_userid )  /* userid    */
            * sizeof(HL_WCHAR);
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   m_put_le2( (char *) &adsl_nm1_auth->dsc_username.usc_len, iml1 );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_username.usc_maxlen, iml1 );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_username.umc_buffer_offset, achl_nm1_auth_pl - ((char *) adsl_nm1_auth) );
   achl_nm1_auth_pl += iml1;
   iml1 = m_cpy_vx_ucs( achl_nm1_auth_pl,
                        (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth)
                          - achl_nm1_auth_pl,
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_workstation )  /* workstation */
            * sizeof(HL_WCHAR);
   if (iml1 < 0) {                          /* returned error          */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   m_put_le2( (char *) &adsl_nm1_auth->dsc_workstation.usc_len, iml1 );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_workstation.usc_maxlen, iml1 );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_workstation.umc_buffer_offset, achl_nm1_auth_pl - ((char *) adsl_nm1_auth) );
   achl_nm1_auth_pl += iml1;
   iml1 = 0;
   if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
     iml1 = 16;
   }
   m_put_le2( (char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.usc_len, iml1 );
   m_put_le2( (char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.usc_maxlen, iml1 );
   m_put_le4( (char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.umc_buffer_offset, achl_nm1_auth_pl - ((char *) adsl_nm1_auth) );
#ifdef B140319
   achl_nm1_auth_pl += iml1;
#endif

   p_auth_40:                               /* check content of NTLMSSP_AUTH */
   /* HMAC 16 bytes                                                    */
   iml1 = m_cpy_vx_ucs( byrl_work1, sizeof(byrl_work1), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &adsp_ntlm_req->dsc_ucs_password )  /* password */
            * sizeof(HL_WCHAR);
   MD4_Init( imrl_md4_array );
   MD4_Update( imrl_md4_array, byrl_work1, 0, iml1 );
   MD4_Final( imrl_md4_array, byrl_md4_pwd, 0 );
#ifdef TRACEHL1
#ifdef XYZ1
   m_console_out( byrl_md4_pwd, MD4_DIGEST_LEN );
#endif
#endif
   iml1 = m_cpy_uc_vx_ucs( byrl_work1, sizeof(byrl_work1), ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                           &adsp_ntlm_req->dsc_ucs_userid )  /* userid */
            * sizeof(HL_WCHAR);

   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml2 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml2 ] ^= byrl_md4_pwd[ iml2 ];
     byrl_hmac_2[ iml2 ] ^= byrl_md4_pwd[ iml2 ];
     iml2++;                                /* increment index         */
   } while (iml2 < sizeof(byrl_md4_pwd));
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, byrl_work1, 0, iml1 );
   /* domain name                                                      */
   MD5_Update( imrl_md5_array, achl_domain, 0, iml_len_domain );
   MD5_Final( imrl_md5_array, byrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, byrl_work1, 0, 16 );
   MD5_Final( imrl_md5_array, byrl_work1, 0 );
   /* end of HMAC                                                      */
   /* NTOWFv2 in first 16 bytes of byrl_work1, remainder (MD-5 hash) discarded */
   /* compute MIC                                                      */
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml1 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml1 ] ^= byrl_work1[ iml1 ];
     byrl_hmac_2[ iml1 ] ^= byrl_work1[ iml1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < 16);
   achl_w1 = achl_nt_chal;
   if (adsp_ntlm_req->iec_ntlmf == ied_ntlmf_auth_check) {  /* check NTLMSSP_AUTH */
     achl_w1 = byrl_work1 + 32;
   }
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, adsl_nm1_chal->byrc_server_challenge, 0, sizeof(adsl_nm1_chal->byrc_server_challenge) );
   MD5_Update( imrl_md5_array, achl_nt_chal + 16, 0, iml_len_nt_chal - 16 );
   MD5_Final( imrl_md5_array, byrl_work1 + 16, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, byrl_work1 + 16, 0, 16 );
#ifdef B130311
   MD5_Final( imrl_md5_array, achl_nt_chal, 0 );
#else
   MD5_Final( imrl_md5_array, achl_w1, 0 );
#endif
   if (adsp_ntlm_req->iec_ntlmf != ied_ntlmf_auth_check) {  /* check NTLMSSP_AUTH */
     goto p_auth_60;                        /* continue check content of NTLMSSP_AUTH */
   }
   if (memcmp( byrl_work1 + 32, achl_nt_chal, 16 )) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }

   /* check NtChallengeResponseFields                                  */
   /* get fields from NTLM message NTLMSSP_AUTH                        */
   uml1
     = *((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_len + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.usc_len + 1) << 8);
   uml2
     = *((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 0)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 1) << 8)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 2) << 16)
         | (*((unsigned char *) &adsl_nm1_auth->dsc_nt_challenge_response.umc_buffer_offset + 3) << 24);
   if ((((char *) adsl_nm1_auth + uml2 + uml1) - adsp_ntlm_req->achc_auth)
         > adsp_ntlm_req->imc_len_auth) {
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }
   ill_chal_time = 0;                       /* MsvAvTimestamp          */
   bol_msv_channel_bindings = FALSE;        /* check channel bindings hash */
   if (adsp_ntlm_req->achc_msv_channel_bindings) {  /* channel bindings hash */
     bol_msv_channel_bindings = TRUE;       /* check channel bindings hash */
   }
   /* loop over NtChallengeResponseFields                              */
   iml1 = 44;
   do {                                     /* loop                    */
     if ((iml1 + 4) > uml1) break;
     iml2 = *((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 0 + 0)
              | (*((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 0 + 1) << 8);
     if (iml2 == 0) break;
     iml3 = *((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 2 + 0)
              | (*((unsigned char *) adsl_nm1_auth + uml2 + iml1 + 2 + 1) << 8);
     if ((iml1 + 4 + iml3) > uml1) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
#ifdef XYZ1
//#ifdef XYZ1
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
     if (   (iml2 == 1)
         && (dsl_ucs_targetname.imc_len_str == 0)) {  /* TargetName    */
       dsl_ucs_targetname.ac_str = (char *) adsl_nm1_chal + uml2 + iml1 + 4;  /* address of string */
       dsl_ucs_targetname.imc_len_str = iml3 / sizeof(HL_WCHAR);  /* length string in elements */
       dsl_ucs_targetname.iec_chs_str = ied_chs_le_utf_16;  /* character set string - Unicode UTF-16 little endian */
     }
// to-do 19.03.14 KB - use Unicode Library function for length - maybe only terminating zero
     if (   (iml2 == 2)
         && (dsl_ucs_domain.imc_len_str == 0)) {  /* authentication domain name */
       dsl_ucs_domain.ac_str = (char *) adsl_nm1_chal + uml2 + iml1 + 4;  /* address of string */
       dsl_ucs_domain.imc_len_str = iml3 / sizeof(HL_WCHAR);  /* length string in elements */
       dsl_ucs_domain.iec_chs_str = ied_chs_le_utf_16;  /* character set string - Unicode UTF-16 little endian */
     }
//#endif
     if (iml2 == 7) {
       if (ill_chal_time != 0) {            /* MsvAvTimestamp          */
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
#ifdef B130131
#ifdef B130123
       ill_chal_time                        /* MsvAvTimestamp          */
         = *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#else
       ill_chal_time                        /* MsvAvTimestamp          */
         = (HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | (HL_LONGLONG) (*((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#endif
#else
       ill_chal_time                        /* MsvAvTimestamp          */
         = ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 0))
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 1) << 8)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 2) << 16)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 3) << 24)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 4) << 32)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 5) << 40)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 6) << 48)
             | ((HL_LONGLONG) *((unsigned char *) adsl_nm1_chal + uml2 + iml1 + 4 + 7) << 56);
#endif
       if (ill_chal_time == 0) {            /* MsvAvTimestamp          */
         return FALSE;
       }
     }
#endif
     if (iml2 == 0X000A) {                  /* MsvChannelBindings      */
       if (iml3 != LEN_MSV_CHANNEL_BINDINGS) {  /* length channel bindings hash */
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
       if (bol_msv_channel_bindings == FALSE) {  /* check channel bindings hash */
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
       if (memcmp( (char *) adsl_nm1_auth + uml2 + iml1 + 4,
                   adsp_ntlm_req->achc_msv_channel_bindings,  /* channel bindings hash */
                   LEN_MSV_CHANNEL_BINDINGS )) {
         adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
         return FALSE;
       }
       bol_msv_channel_bindings = FALSE;    /* channel bindings hash checked */
     }
     iml1 += 4 + iml3;
   } while (iml1 < uml1);
   if (bol_msv_channel_bindings) {          /* check channel bindings hash */
     adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
     return FALSE;
   }

   p_auth_60:                               /* continue check content of NTLMSSP_AUTH */
   /* generate KeyExchangeKey                                          */
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml1 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml1 ] ^= byrl_work1[ iml1 ];
     byrl_hmac_2[ iml1 ] ^= byrl_work1[ iml1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < 16);
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, achl_nt_chal, 0, 16 );
   MD5_Final( imrl_md5_array, byrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, byrl_work1, 0, 16 );
   MD5_Final( imrl_md5_array, byrl_work1, 0 );
// temporary - line 00909
   achl_w1 = byrl_work1;                    /* KeyExchangeKey          */
   if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
#define ACHL_RANDOM_G (byrl_work1 + 16)
#ifdef B130311
//#define ACHL_RC4_OUT (byrl_work1 + 32)
     adsp_ntlm_req->amc_get_random( adsp_ntlm_req->vpc_userfld, ACHL_RANDOM_G, 16 );
#else
     uml1
       = *((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.usc_len + 0)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.usc_len + 1) << 8);
     uml2
       = *((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.umc_buffer_offset + 0)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.umc_buffer_offset + 1) << 8)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.umc_buffer_offset + 2) << 16)
           | (*((unsigned char *) &adsl_nm1_auth->dsc_encrypted_random_session_key.umc_buffer_offset + 3) << 24);
     if ((((char *) adsl_nm1_auth + uml2 + uml1) - adsp_ntlm_req->achc_auth)
           > adsp_ntlm_req->imc_len_auth) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
#endif
#ifdef B130131
     RC4_SetKey( chrl_rc4_state, ACHL_RANDOM_G, 0, 16 );
#else
     RC4_SetKey( chrl_rc4_state, byrl_work1, 0, 16 );
#endif
#ifdef B130311
#ifdef B130123
     RC4( ACHL_RANDOM_G, 0, 16, achl_nm1_auth_pl, 0, chrl_rc4_state );
#else
     RC4( ACHL_RANDOM_G, 0, 16, achl_nm1_auth_pl - 16, 0, chrl_rc4_state );
#endif
#else
     RC4( ACHL_RANDOM_G, 0, 16, (char *) adsl_nm1_auth + uml2, 0, chrl_rc4_state );
#endif
     achl_w1 = ACHL_RANDOM_G;
#ifndef B140331
     achl_nm1_auth_pl += 16;
#endif
//#undef ACHL_RC4_OUT
#undef ACHL_RANDOM_G
   }
   if (adsp_ntlm_req->achc_ntlm_sign_key) {  /* NTLM signing key       */
     memcpy( adsp_ntlm_req->achc_ntlm_sign_key, achl_w1, LEN_NTLM_SIGN_KEY );  /* length sign key of NTLM */
   }
   if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
#define ACHL_CLIENT_SIGNKEY (byrl_work1 + 32 + 16)
#define ACHL_CLIENT_SEALKEY (byrl_work1 + 32 + 16 + 16)
#define ACHL_SERVER_SIGNKEY (byrl_work1 + 32 + 16 + 16 + 16)
#define ACHL_SERVER_SEALKEY (byrl_work1 + 32 + 16 + 16 + 16 + 16)
#define ACHL_CLIENT_HANDLE (byrl_work1 + 32 + 16 + 16 + 16 + 16 + 16)
#define ACHL_SERVER_HANDLE (byrl_work1 + 32 + 16 + 16 + 16 + 16 + 16 + RC4_STATE_SIZE)
     MD5_Init( imrl_md5_array );
     MD5_Update( imrl_md5_array, achl_w1, 0, 16 );
     MD5_Update( imrl_md5_array, (char *) byrs_ntlm_magic_cl2se_01, 0, sizeof(byrs_ntlm_magic_cl2se_01) );
     MD5_Final( imrl_md5_array, ACHL_CLIENT_SIGNKEY, 0 );
     iml1 = 4;
     if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_128) {
       iml1 = 16;
     } else if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_56) {
       iml1 = 6;
     }
     MD5_Init( imrl_md5_array );
     MD5_Update( imrl_md5_array, achl_w1, 0, iml1 );
     MD5_Update( imrl_md5_array, (char *) byrs_ntlm_magic_cl2se_02, 0, sizeof(byrs_ntlm_magic_cl2se_02) );
     MD5_Final( imrl_md5_array, ACHL_CLIENT_SEALKEY, 0 );
     MD5_Init( imrl_md5_array );
     RC4_SetKey( ACHL_CLIENT_HANDLE, ACHL_CLIENT_SEALKEY, 0, 16 );
     MD5_Update( imrl_md5_array, achl_w1, 0, 16 );
     MD5_Update( imrl_md5_array, (char *) byrs_ntlm_magic_se2cl_01, 0, sizeof(byrs_ntlm_magic_cl2se_01) );
     MD5_Final( imrl_md5_array, ACHL_SERVER_SIGNKEY, 0 );
     MD5_Init( imrl_md5_array );
     MD5_Update( imrl_md5_array, achl_w1, 0, iml1 );
     MD5_Update( imrl_md5_array, (char *) byrs_ntlm_magic_se2cl_02, 0, sizeof(byrs_ntlm_magic_cl2se_02) );
     MD5_Final( imrl_md5_array, ACHL_SERVER_SEALKEY, 0 );
     RC4_SetKey( ACHL_SERVER_HANDLE, ACHL_SERVER_SEALKEY, 0, 16 );
   }
   memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
   memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
   iml1 = 0;                                /* clear index             */
   do {
     byrl_hmac_1[ iml1 ] ^= achl_w1[ iml1 ];
     byrl_hmac_2[ iml1 ] ^= achl_w1[ iml1 ];
     iml1++;                                /* increment index         */
   } while (iml1 < 16);
#ifdef B130123
   achl_nm1_auth_pl += 16;
#endif
   if (adsp_ntlm_req->iec_ntlmf == ied_ntlmf_auth_gen) {  /* do not fill fields from NTLMSSP_AUTH */
#ifdef B130427
     m_put_le4( (char *) &adsl_nm1_auth->umc_negotiate_flags,
                (unsigned int) D_NTLM_AUTH_FLAGS );
#else
     uml1 = D_NTLM_AUTH_FLAGS_NORMAL;
     if (adsp_ntlm_req->boc_gssapi) {       /* use GSSAPI              */
       uml1 = D_NTLM_AUTH_FLAGS_GSSAPI;
     }
     m_put_le4( (char *) &adsl_nm1_auth->umc_negotiate_flags, uml1 );
#endif
     memcpy( adsl_nm1_auth->byrc_version, byrs_ntlm_version, sizeof(byrs_ntlm_version) );
     iml1 = achl_nm1_auth_pl - ((char *) adsl_nm1_auth);  /* length of NTLMSSP_AUTH */
   } else {                                 /* check NTLMSSP_AUTH      */
     memcpy( byrl_work1 + 32, adsl_nm1_auth->byrc_mic, sizeof(adsl_nm1_auth->byrc_mic) );  /* save MIC */
     iml1 = (adsp_ntlm_req->achc_auth + adsp_ntlm_req->imc_len_auth) - ((char *) adsl_nm1_auth);
   }
   memset( adsl_nm1_auth->byrc_mic, 0, sizeof(adsl_nm1_auth->byrc_mic) );
   iml2 = 0;                                /* clear length GSSAPI header */
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
     iml2 = 62;                             /* set length GSSAPI header */
   }
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
   MD5_Update( imrl_md5_array, adsp_ntlm_req->achc_negotiate + iml2, 0, adsp_ntlm_req->imc_len_negotiate - iml2 );
   MD5_Update( imrl_md5_array, (char *) adsl_nm1_chal, 0, adsp_ntlm_req->imc_len_challenge - (((char *) adsl_nm1_chal) - adsp_ntlm_req->achc_challenge) );
   MD5_Update( imrl_md5_array, (char *) adsl_nm1_auth, 0, iml1 );
   MD5_Final( imrl_md5_array, byrl_work1, 0 );
   MD5_Init( imrl_md5_array );
   MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
   MD5_Update( imrl_md5_array, byrl_work1, 0, 16 );
   MD5_Final( imrl_md5_array, adsl_nm1_auth->byrc_mic, 0 );
   if (adsp_ntlm_req->iec_ntlmf == ied_ntlmf_auth_check) {  /* check NTLMSSP_AUTH */
     if (memcmp( adsl_nm1_auth->byrc_mic, byrl_work1 + 32, sizeof(adsl_nm1_auth->byrc_mic) )) {
       adsp_ntlm_req->imc_ret_error_line = __LINE__;  /* returns line with error */
       return FALSE;
     }
     return TRUE;
   }
#define IMS_CLIENT_SIGN_COUNTER 0
#define ACHL_SIG_NUM (byrl_work1 + 0)
#define IMS_SIGN_TARGET_OFFSET (0x6C - 0X40 - 24)
#define IMS_SING_TARGET_LENGTH 14
   if (   (adsp_ntlm_req->boc_gssapi)       /* use GSSAPI              */
       && (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_SIGN)) {
     if (uml_challenge_message_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
       m_put_le4( ACHL_SIG_NUM,
                  (unsigned int) IMS_CLIENT_SIGN_COUNTER );
       memset( byrl_hmac_1, 0X36, sizeof(byrl_hmac_1) );  /* for HMAC      */
       memset( byrl_hmac_2, 0X5C, sizeof(byrl_hmac_2) );  /* for HMAC      */
       iml1 = 0;                                /* clear index             */
       do {
         byrl_hmac_1[ iml1 ] ^= *(ACHL_CLIENT_SIGNKEY + iml1);
         byrl_hmac_2[ iml1 ] ^= *(ACHL_CLIENT_SIGNKEY + iml1);
         iml1++;                                /* increment index         */
       } while (iml1 < 16);
       MD5_Init( imrl_md5_array );
       MD5_Update( imrl_md5_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
       MD5_Update( imrl_md5_array, ACHL_SIG_NUM, 0, 4 );
       MD5_Update( imrl_md5_array, adsp_ntlm_req->achc_negotiate + IMS_SIGN_TARGET_OFFSET, 0, IMS_SING_TARGET_LENGTH );
       MD5_Final( imrl_md5_array, byrl_work1, 0 );
       MD5_Init( imrl_md5_array );
       MD5_Update( imrl_md5_array, byrl_hmac_2, 0, sizeof(byrl_hmac_2) );
       MD5_Update( imrl_md5_array, byrl_work1, 0, 16 );
       MD5_Final( imrl_md5_array, byrl_work1, 0 );
#ifdef B130123
       RC4( byrl_work1, 0, 8, achl_nm1_auth_pl - 16 + 4, 0, ACHL_CLIENT_HANDLE );
#else
       RC4( byrl_work1, 0, 8, achl_nm1_auth_pl + sizeof(byrs_gss_api_p02), 0, ACHL_CLIENT_HANDLE );
#endif
     } else {
     }
#ifdef B130123
// 24.01.13 KB - occasionally deleted
#else
     m_put_le4( achl_nm1_auth_pl + sizeof(byrs_gss_api_p02) + 8,
                (unsigned int) IMS_CLIENT_SIGN_COUNTER );
#endif
   }

#undef ACHL_CLIENT_SIGNKEY
#undef ACHL_CLIENT_SEALKEY
#undef ACHL_SERVER_SIGNKEY
#undef ACHL_SERVER_SEALKEY
#undef ACHL_CLIENT_HANDLE
#undef ACHL_SERVER_HANDLE
   if (adsp_ntlm_req->boc_gssapi) {         /* use GSSAPI              */
     memcpy( adsp_ntlm_req->achc_auth, byrs_gss_api_p01, sizeof(byrs_gss_api_p01) );  /* NTLM message AUTH */
     /* set length ASN.1 in GSS_API fields                             */
     iml1 = achl_nm1_auth_pl - ((char *) adsl_nm1_auth);
     m_put_be2( adsp_ntlm_req->achc_auth + 2, iml1 + sizeof(byrs_gss_api_p01) + sizeof(byrs_gss_api_p02) + 12 - 4 );
     m_put_be2( adsp_ntlm_req->achc_auth + 6, iml1 + sizeof(byrs_gss_api_p01) + sizeof(byrs_gss_api_p02) + 12 - 8 );
     m_put_be2( adsp_ntlm_req->achc_auth + 15, iml1 + sizeof(byrs_gss_api_p01) - 17 );
     m_put_be2( adsp_ntlm_req->achc_auth + 19, iml1 + sizeof(byrs_gss_api_p01) - 21 );
     memcpy( achl_nm1_auth_pl, byrs_gss_api_p02, sizeof(byrs_gss_api_p02) );  /* NTLM message AUTH */
     achl_nm1_auth_pl += sizeof(byrs_gss_api_p02) + 12;  /* NTLM message AUTH */
   }

// memcpy( adsp_ntlm_req->achc_auth, "TEST", 4 );                   /* address of packet NTLMSSP_AUTH */
// adsp_ntlm_req->imc_len_auth = 4;
   adsp_ntlm_req->imc_len_auth = achl_nm1_auth_pl - adsp_ntlm_req->achc_auth;
   return TRUE;
} /* end m_proc_ntlm_req()                                             */

/** input two bytes little endian                                      */
static inline short int m_get_le2( char *achp_source ) {
   return *((short int *) achp_source);
} /* end m_get_le2()                                                   */

/** input four bytes little endian                                     */
static inline int m_get_le4( char *achp_source ) {
   return *((int *) achp_source);
} /* end m_get_le4()                                                   */

/** output two bytes little endian                                     */
static inline void m_put_le2( char *achp_target, int imp1 ) {
   *((unsigned short int *) achp_target) = (unsigned short int) imp1;
} /* m_put_le2()                                                       */

/** output four bytes little endian                                    */
static inline void m_put_le4( char *achp_target, int imp1 ) {
   *((unsigned int *) achp_target) = (unsigned int) imp1;
} /* end m_put_le4()                                                   */

/** output eight bytes little endian                                   */
static inline void m_put_le8( char *achp_target, HL_LONGLONG ilp1 ) {
   *((unsigned char *) achp_target + 0) = (unsigned char) ilp1;
   *((unsigned char *) achp_target + 1) = (unsigned char) (ilp1 >> 8);
   *((unsigned char *) achp_target + 2) = (unsigned char) (ilp1 >> 16);
   *((unsigned char *) achp_target + 3) = (unsigned char) (ilp1 >> 24);
   *((unsigned char *) achp_target + 4) = (unsigned char) (ilp1 >> 32);
   *((unsigned char *) achp_target + 5) = (unsigned char) (ilp1 >> 40);
   *((unsigned char *) achp_target + 6) = (unsigned char) (ilp1 >> 48);
   *((unsigned char *) achp_target + 7) = (unsigned char) (ilp1 >> 56);
} /* end m_put_le8()                                                   */

/** output two bytes big endian                                        */
static inline void m_put_be2( char *achp_target, int imp1 ) {
   *((unsigned char *) achp_target + 0) = (unsigned char) (imp1 >> 8);
   *((unsigned char *) achp_target + 1) = (unsigned char) imp1;
} /* m_put_be2()                                                       */
