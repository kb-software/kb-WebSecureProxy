//#define TRACEHL1
#define DEF_SSL_WSP_TRACE
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsthlse3                                            |*/
/*| -------------                                                     |*/
/*|  Test HOBLink Server Encryption / Dummy Program                   |*/
/*|  Version 3                                                        |*/
/*|  KB 25.05.00 / KB 09.08.04 / 14.08.09                             |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2000                                |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all versions                                                 |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */
/* #define MAKELOAD */
#define CERTIFICATE_01

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HL_WINALL1
#include <windows.h>
#else
#include "hob-unix01.h"
#endif
#ifdef B121009
#define __XHSERVIF__
#include <hob-xshlse03.h>
#include "HOBSSLTP.h"
#endif
#include <hob-ssl-01.h>
#ifdef DEF_SSL_WSP_TRACE
#include <hob-xsclib01.h>
#endif

#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

#define GHFW(str) ((unsigned int) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((unsigned short int) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))

#define TID    DWORD
#define HEV    void *
#define HQUEUE void *
#define APIRET int
#define HL_SSL_VERS "xsthlse3 Test Library - Dummy 14.08.09"

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Constant data.                                                    |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HLSE_SSL_TIMEOUT 120            /* Timeout for SSL         */
#ifndef OLD_0410
#ifdef CERTIFICATE_01

#ifdef OLD03
static const WCHAR wcrs_dn[] = L"DN-from-certificate 14.08.09 KB";
#else
static const char chrs_dn[] = "DN-from-certificate 14.08.09 KB";
#endif

static const char chrs_fingerprint[] = {
   0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07,
   0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F,
   0X10, 0X11, 0X12, 0X13 };

static const char chrs_cerificate[] = {
   0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07,
   0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F,
   0X10, 0X11, 0X12, 0X13, 0X11, 0X15, 0X16, 0X17,
   0X18, 0X19, 0X1A, 0X1B, 0X1C, 0X1D, 0X1E, 0X1F,
   0X20, 0X21, 0X22, 0X23 };

#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

typedef struct {
  int   icount1;                            /* working variable        */
  int   icount2;                            /* working variable        */
  BOOL  bo_callback;                        /* callback done           */
#ifdef B121009
  HSSL_QUERYINFO dconfig;
#endif
//struct dsd_ssl_query_info dsc_ssl_query_info;
} DSTOR;

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

extern "C" void m_hlse03( struct dsd_hl_ssl_s_3 *adsp_hlse03 ) {
   int        inl1, inl2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   DSTOR      *adsl_stor;
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input            */
#ifdef MAKELOAD
   void     *ah1;
#endif
#ifndef OLD_0410
   struct dsd_hl_ssl_ccb_1 dsl_ccb_1;       /* callback parameters     */
#ifdef B121009
   HSSL_QUERYINFO dsl_hssl_queryinfo;
#endif
   struct dsd_ssl_query_info dsl_ssl_query_info;
#endif
   BOOL       bol_to_server;                /* something sent to server */
   BOOL       bol_to_client;                /* something sent to client */

#ifdef TRACEHL1
     {
       char *achh1 = "--- invalid ---";
       int inh_client_gather = 0;
       int inh_client_lendata = 0;
       int inh_server_gather = 0;
       int inh_server_lendata = 0;
       if (adsp_hlse03->inc_func == DEF_IFUNC_START) {
         achh1 = "DEF_IFUNC_START";
       } else if (adsp_hlse03->inc_func == DEF_IFUNC_CONT) {
         achh1 = "DEF_IFUNC_CONT";
       }
       if (adsp_hlse03->inc_func == DEF_IFUNC_CONT) {
         adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromcl;
         while (adsl_gai1_w1) {
           inh_client_gather++;
           inh_client_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         }
         adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromse;
         while (adsl_gai1_w1) {
           inh_server_gather++;
           inh_server_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         }
       }
       printf( "m_hlse03 called inc_func = %d / %s *** fr-cl gather=%d len=%d * fr-se gather=%d len=%d.\n",
               adsp_hlse03->inc_func, achh1,
               inh_client_gather, inh_client_lendata, inh_server_gather, inh_server_lendata );
       if (adsp_hlse03->boc_eof_client) {
         printf( "m_hlse03 called with boc_eof_client +++\n" );
       }
       if (adsp_hlse03->boc_eof_server) {
         printf( "m_hlse03 called with boc_eof_server +++\n" );
       }
     }
#endif
#ifdef DEF_SSL_WSP_TRACE
   if (adsp_hlse03->imc_trace_level) {    /* WSP trace level         */
     struct dsd_wsp_trace_header dsl_wtrh;  /* WSP trace header      */
     char       chrl_work1[ 2048 ];       /* work area               */
     char *achh1 = "--- invalid ---";
     int inh_client_gather = 0;
     int inh_client_lendata = 0;
     int inh_server_gather = 0;
     int inh_server_lendata = 0;
     if (adsp_hlse03->inc_func == DEF_IFUNC_START) {
       achh1 = "DEF_IFUNC_START";
     } else if (adsp_hlse03->inc_func == DEF_IFUNC_CONT) {
       achh1 = "DEF_IFUNC_CONT";
     }
     if (adsp_hlse03->inc_func == DEF_IFUNC_CONT) {
       adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromcl;
       while (adsl_gai1_w1) {
         inh_client_gather++;
         inh_client_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
       adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromse;
       while (adsl_gai1_w1) {
         inh_server_gather++;
         inh_server_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       }
     }
     memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( dsl_wtrh.chrc_wtrt_id, "SSSLI001", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
     dsl_wtrh.imc_wtrh_sno = adsp_hlse03->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
     dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "m_hlse03 called inc_func = %d / %s *** fr-cl gather=%d len=%d/0X%X * fr-se gather=%d len=%d/0X%X boc_eof_client=%d boc_eof_server=%d.",
                                        adsp_hlse03->inc_func, achh1,
                                        inh_client_gather, inh_client_lendata, inh_client_lendata,
                                        inh_server_gather, inh_server_lendata, inh_server_lendata,
                                        adsp_hlse03->boc_eof_client,
                                        adsp_hlse03->boc_eof_server );
     bol1 = adsp_hlse03->amc_aux( adsp_hlse03->vpc_userfld,  /* User Field Subroutine */
                                  DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                  &dsl_wtrh,
                                  0 );
#undef ADSL_WTR_G1
   }
#endif
   if (adsp_hlse03->inc_func == DEF_IFUNC_START) {
     adsp_hlse03->inc_func = DEF_IFUNC_CONT;
     adsp_hlse03->inc_return = DEF_IRET_NORMAL;
     bol1 = (*adsp_hlse03->amc_aux)( adsp_hlse03->vpc_userfld, DEF_AUX_MEMGET, &adsl_stor, sizeof(DSTOR) );
                                            /* get memory              */
     if (bol1 == FALSE) {
       adsp_hlse03->inc_return = DEF_IRET_ERRAU;  /* message error     */
       return;                              /* return to main-prog     */
     }
     memset( adsl_stor, 0, sizeof(DSTOR) );  /* clear buffer           */
     adsp_hlse03->ac_ext = adsl_stor;       /* store address of fields */
#ifndef OLD01
#ifndef OLD_0410
     memset( &dsl_ccb_1, 0, sizeof(dsl_ccb_1) );
     dsl_ccb_1.vpc_userfld = adsp_hlse03->vpc_userfld;
#ifdef B121009
     dsl_ccb_1.ac_conndata = &dsl_hssl_queryinfo;
#endif
     dsl_ccb_1.ac_conndata = &dsl_ssl_query_info;
#ifdef CERTIFICATE_01
#ifdef OLD02
     memcpy( dsl_hssl_queryinfo.hssl_byPartnerName, wcrs_dn, sizeof(wcrs_dn) );
#endif
#ifdef OLD03
     { int inh1;
       unsigned short int * awch1;
       inh1 = sizeof(wcrs_dn) / sizeof(wcrs_dn[0]);
       awch1 = (unsigned short int *) dsl_hssl_queryinfo.hssl_byPartnerName;
       do {
         inh1--;
         *(awch1 + inh1) = GHHW( *((unsigned short int *) wcrs_dn + inh1) );
       } while (inh1);
     }
#endif
     {
       int inh1;
       unsigned short int * awch1;
       inh1 = sizeof(chrs_dn) / sizeof(chrs_dn[0]);
#ifdef B121009
       awch1 = (unsigned short int *) dsl_hssl_queryinfo.hssl_byPartnerName;
#endif
       awch1 = (unsigned short int *) dsl_ssl_query_info.ucrc_partner_name;
       do {
         inh1--;
         *(awch1 + inh1) = GHHW( (unsigned short int) *(chrs_dn + inh1) );
       } while (inh1);
     }
#ifdef OLD03
     dsl_hssl_queryinfo.hssl_byPartnerNameLength = sizeof(wcrs_dn) / sizeof(wcrs_dn[0]);
#endif
#ifdef B121009
     dsl_hssl_queryinfo.hssl_byPartnerNameLength = sizeof(chrs_dn) / sizeof(chrs_dn[0]);
#endif
     dsl_ssl_query_info.ucc_partner_name_length = sizeof(chrs_dn) / sizeof(chrs_dn[0]);
     dsl_ccb_1.achc_fingerprint = (char *) chrs_fingerprint;
     dsl_ccb_1.achc_certificate = (char *) chrs_cerificate;
     dsl_ccb_1.inc_len_certificate = sizeof(chrs_cerificate);
#endif
     adsp_hlse03->amc_conn_callback( &dsl_ccb_1 );
#else
#ifdef B121009
     adsp_hlse03->amc_conn_callback( adsp_hlse03->vpc_userfld, 0, &adsl_stor->dconfig );
#endif
     adsp_hlse03->amc_conn_callback( adsp_hlse03->vpc_userfld, 0, &adsl_stor->dsc_ssl_query_info );
#endif
#endif
#ifdef MAKELOAD
     inl1 = 100;
     inl2 = 100;
     inl1 *= inl2 * 100;
     do {
       inl1--;
       inl2 = GetCurrentProcessId();
       ah1 = malloc( 311 );
       free( ah1 );
     } while (inl1);
#endif
     return;
   }
   if (adsp_hlse03->inc_func != DEF_IFUNC_CONT) {
     adsp_hlse03->inc_return = 3;
     return;
   }
   adsl_stor = (DSTOR *) adsp_hlse03->ac_ext;  /* get address of fields */
   bol_to_server = FALSE;                   /* something sent to server */
   adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromcl;
   while (TRUE) {
     if (adsl_gai1_w1 == NULL) break;
     if (adsp_hlse03->boc_eof_server) {     /* End-of-File Server      */
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     } else {                               /* can send now            */
       inl1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       inl2 = adsp_hlse03->achc_tose_end - adsp_hlse03->achc_tose_cur;
       if (inl2 <= 0) break;
       if (inl1 > inl2) inl1 = inl2;
       if (inl1) {
         memcpy( adsp_hlse03->achc_tose_cur, adsl_gai1_w1->achc_ginp_cur, inl1 );
         adsl_gai1_w1->achc_ginp_cur += inl1;
         adsp_hlse03->achc_tose_cur += inl1;
         bol_to_server = TRUE;              /* something sent to server */
       }
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   bol_to_client = FALSE;                   /* something sent to client */
   adsl_gai1_w1 = adsp_hlse03->adsc_gai1_fromse;
   while (TRUE) {
     if (adsl_gai1_w1 == NULL) break;
     if (adsp_hlse03->boc_eof_client) {     /* End-of-File Client      */
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     } else {                               /* can send now            */
       inl1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       inl2 = adsp_hlse03->achc_tocl_end - adsp_hlse03->achc_tocl_cur;
       if (inl2 <= 0) break;
       if (inl1 > inl2) inl1 = inl2;
       if (inl1) {
         memcpy( adsp_hlse03->achc_tocl_cur, adsl_gai1_w1->achc_ginp_cur, inl1 );
         adsl_gai1_w1->achc_ginp_cur += inl1;
         adsp_hlse03->achc_tocl_cur += inl1;
         bol_to_client = TRUE;              /* something sent to client */
       }
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (   (bol_to_server == FALSE)          /* nothing sent to server  */
       && (bol_to_client == FALSE)          /* nothing sent to client  */
       && (   (adsp_hlse03->boc_eof_client)  /* End-of-File Client     */
           || (adsp_hlse03->boc_eof_server))) {  /* End-of-File Server */
     bol1 = (*adsp_hlse03->amc_aux)( adsp_hlse03->vpc_userfld, DEF_AUX_MEMFREE, &adsl_stor, sizeof(DSTOR) );
                                            /* free memory             */
     if (bol1 == FALSE) {
       adsp_hlse03->inc_return = DEF_IRET_ERRAU;  /* message error     */
       return;                              /* return to main-prog     */
     }
     adsp_hlse03->inc_return = DEF_IRET_END;
     return;
   }
#ifdef MAKELOAD
   if (inl1) {
     inl1 *= 100 * 100;
     do {
       inl1--;
       inl2 = GetCurrentProcessId();
       ah1 = malloc( 517 );
       free( ah1 );
     } while (inl1);
   }
#endif
} /* end m_hlse03()                                                    */

#ifdef B160504
extern "C" int m_se_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                    char * achp_certdatabuf, int inp_certdatalen,
                                    char * achp_pdwbuf, int inp_pdwlen,
                                    BOOL boc_pwdfileflag,
                                    struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                    BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                    void * vpp_userfld,
                                    void ** avpp_config_id ) {
   *avpp_config_id = (void *) 513;
   return 0;
} /* end m_se_registerconfig()                                         */
#endif
#ifdef B160629
#ifndef B160504
extern "C" int m_se_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                    char * achp_certdatabuf, int inp_certdatalen,
                                    char * achp_pdwbuf, int inp_pdwlen,
                                    BOOL boc_pwdfileflag,
                                    struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                    BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                    void * vpp_userfld,
                                    void ** avpp_config_id,
                                    BOOL ) {
   *avpp_config_id = (void *) 513;
   return 0;
} /* end m_se_registerconfig()                                         */
#endif
#endif
#ifndef B160629
extern "C" int m_se_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                    char * achp_certdatabuf, int inp_certdatalen,
                                    char * achp_pdwbuf, int inp_pdwlen,
                                    BOOL boc_pwdfileflag,
                                    struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                    BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                    void * vpp_userfld,
                                    void ** avpp_config_id,
                                    BOOL bop_use_aux_seeding ) {
   BOOL       bol_rc;                       /* return code             */
   char       byrl_random[ 64 ];

   if (bop_use_aux_seeding) {
     bol_rc = (amp_aux)( vpp_userfld,
                         DEF_AUX_SECURE_RANDOM_SEED,
                         byrl_random,
                         sizeof(byrl_random) );
     if (bol_rc == FALSE) {
       return -1234;
     }
   }
   *avpp_config_id = (void *) 513;
   return 0;
} /* end m_se_registerconfig()                                         */
#endif

extern "C" int m_hssl_getversioninfo( int *aimp_version, char *achp_text, int *aimp_length ) {
   char       byrl_text[] = HL_SSL_VERS;
   int        iml1;

   if (aimp_version) {
     *aimp_version = 0X01010101;
     return HSSL_OP_OK;
   }
   iml1 = sizeof(byrl_text);
   if (achp_text == NULL) {
     *aimp_length = iml1;
     return HSSL_OP_OK;
   }
   if (iml1 > *aimp_length) iml1 = *aimp_length;
   *aimp_length = iml1;
   memcpy( achp_text, byrl_text, iml1 - 1 );
   *(achp_text + iml1 - 1) = 0;             /* make zero-terminated    */
   return HSSL_OP_OK;
} /* end m_hssl_getversioninfo()                                       */

extern "C" int m_se_get_conf_timeout( void *vpp_config_id ) {
   return DEF_HLSE_SSL_TIMEOUT;
} /* end m_se_get_conf_timeout()                                       */

#ifdef B160629
//#ifndef HL_LINUX
extern "C" int m_secdrbg_randbytes( char *abyp_dstbuf, int imp_dstlen ) {
   int        iml1;
   HL_LONGLONG ill1;

   if (imp_dstlen <= 0) return -1;
   iml1 = 0;
   do {
     ill1 = (HL_LONGLONG) rand() * 256;
     *((unsigned char *) abyp_dstbuf + iml1) = ill1 / (RAND_MAX + 1);
     iml1++;
   } while (iml1 < imp_dstlen);
   return 0;
} /* end m_secdrbg_randbytes()                                         */
//#endif
#endif

extern "C" int m_get_ssl_server_cert_dns_names( void * vpp_config_id, struct dsd_unicode_string *adsrp_ucs_dns_name, int imp_no_dns_name ) {
   struct dsd_unicode_string *adsl_ucs_dns_name_w1;

   if (imp_no_dns_name <= 0) return -1;
   adsl_ucs_dns_name_w1 = adsrp_ucs_dns_name;
   adsl_ucs_dns_name_w1->ac_str = (void *) "www.test.hob.de";  /* address of string */
   adsl_ucs_dns_name_w1->imc_len_str = strlen( (char *) adsl_ucs_dns_name_w1->ac_str );  /* length string in elements */
   adsl_ucs_dns_name_w1->iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   if (imp_no_dns_name == 1) return 2;
   adsl_ucs_dns_name_w1++;
   adsl_ucs_dns_name_w1->ac_str = (void *) "www.test-02.hob.de";  /* address of string */
   adsl_ucs_dns_name_w1->imc_len_str = strlen( (char *) adsl_ucs_dns_name_w1->ac_str );  /* length string in elements */
   adsl_ucs_dns_name_w1->iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   return 2;
} /* m_get_ssl_server_cert_dns_names()                                 */

/**
   routine for SSTP,
   [MS-SSTP].pdf
   2.2.7 Crypto Binding Attribute
*/
extern "C" BOOL m_ssl_check_cert( struct dsd_hl_ssl_s_3 *adsp_hlse03s,
                                  int imp_hash_protocol,
                                  char *achp_nonce, int imp_len_nonce,
                                  char *achp_cert_hash, int imp_len_cert_hash,
                                  char *achp_compound_mac, int imp_len_compound_mac ) {
   return TRUE;
} /* end m_ssl_check_cert()                                            */

extern "C" BOOL m_get_server_certificate( void **aap_addr,
                                          int *aimp_len,
                                          void * avop_ssl_con ) {
   return TRUE;
} /* end m_get_server_certificate()                                    */

