#ifdef TRACEHL_KB
#define TRACEHL1
#endif
#ifndef HL_UNIX
//#define TRACEHL1
#endif
#define DEF_EXT_PRINTF
//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsthlcl1                                            |*/
/*| -------------                                                     |*/
/*|  Test HOBLink Client Side SSL Encryption / Dummy Program          |*/
/*|  KB 20.06.06                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
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
#include <hob-xshlcl01.h>
#include <hob-xshlse03.h>
#include "HOBSSLTP.h"
#endif
#ifdef D_SSL_GUI
#include "hob-xsclib01.h"
#endif
#ifndef B160504
#ifdef HL_UNIX
#include "hob-xsclib01.h"
#endif
#endif
#include <hob-ssl-01.h>

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
#define HL_SSL_VERS "xsthlcl1 Client-Side SSL Test Library - Dummy 20.06.06"

#ifndef DEF_EXT_PRINTF
#define GEN_PRINTF printf
#else
#define GEN_PRINTF m_hl1_printf
extern "C" int m_hl1_printf( char *, ... );
#endif

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
static const WCHAR wcrs_dn[] = L"DN-from-certificate 20.06.06 KB";
#else
static const char chrs_dn[] = "DN-from-certificate 20.06.06 KB";
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

#ifdef D_SSL_GUI
static const char chrs_ap_ssl_gui[] = {
   'S', 'S', 'L', '-', 'G', 'U', 'I'
};

static const char chrs_ap_w01[] = "message over aux-pipe SSL-GUI\n\
certificate is invalid\n\
enter 0 to end connection\n\
enter 1 to accept invalid certificate\n\
enter 2 to display certificate\n";

static const char chrs_ap_w02[] = "message over aux-pipe SSL-GUI\n\
certificate content\n\
bla bla bla\n\
enter 0 to end connection\n\
enter 1 to accept invalid certificate\n";

static const struct dsd_gather_i_1 dss_gai1_ap_w01 = {
   NULL,                                    /* adsc_next - next in chain */
   (char *) chrs_ap_w01,                    /* achc_ginp_cur - current position        */
   (char *) chrs_ap_w01 + sizeof(chrs_ap_w01) - 1  /* achc_ginp_end - end of input data */
};

static const struct dsd_gather_i_1 dss_gai1_ap_w02 = {
   NULL,                                    /* adsc_next - next in chain */
   (char *) chrs_ap_w02,                    /* achc_ginp_cur - current position        */
   (char *) chrs_ap_w02 + sizeof(chrs_ap_w02) - 1  /* achc_ginp_end - end of input data */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

#ifdef D_SSL_GUI
enum ied_csssl_state {                      /* state of client-side SSL */
   ied_csssls_start = 0,                    /* start aux-pipe          */
   ied_csssls_op_reply,                     /* wait for operator reply */
   ied_csssls_normal                        /* normal processing       */
};
#endif

struct dsd_stor_1 {
  int   icount1;                            /* working variable        */
  int   icount2;                            /* working variable        */
  BOOL  bo_callback;                        /* callback done           */
#ifdef B121009
  HSSL_QUERYINFO dconfig;
#endif
#ifdef D_SSL_GUI
   enum ied_csssl_state iec_csssls;         /* state of client-side SSL */
   void *     vpc_aux_pipe_handle;          /* handle of aux-pipe      */
#endif
};

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

extern "C" void m_hlcl01( struct dsd_hl_ssl_c_1 *adsp_hlcl01 ) {
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   dsd_stor_1 *adsl_stor;
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
#ifndef OLD_0508
   BOOL       bol_to_server;                /* something sent to server */
   BOOL       bol_to_client;                /* something sent to client */
#endif
#ifdef D_SSL_GUI
   struct dsd_aux_pipe_req_1 dsl_apr1;      /* aux-pipe request        */
#endif

#ifdef TRACEHL1
     {
       char *achh1 = "--- invalid ---";
       int inh_client_gather = 0;
       int inh_client_lendata = 0;
       int inh_server_gather = 0;
       int inh_server_lendata = 0;
       if (adsp_hlcl01->inc_func == DEF_IFUNC_START) {
         achh1 = "DEF_IFUNC_START";
       } else if (adsp_hlcl01->inc_func == DEF_IFUNC_CONT) {
         achh1 = "DEF_IFUNC_CONT";
       }
       if (adsp_hlcl01->inc_func == DEF_IFUNC_CONT) {
         adsl_gai1_w1 = adsp_hlcl01->adsc_gai1_in_cl;
         while (adsl_gai1_w1) {
           inh_client_gather++;
           inh_client_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         }
         adsl_gai1_w1 = adsp_hlcl01->adsc_gai1_in_se;
         while (adsl_gai1_w1) {
           inh_server_gather++;
           inh_server_lendata += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         }
       }
       GEN_PRINTF( "m_hlcl01 called inc_func = %d / %s *** fr-cl gather=%d len=%d * fr-se gather=%d len=%d\n",
               adsp_hlcl01->inc_func, achh1,
               inh_client_gather, inh_client_lendata, inh_server_gather, inh_server_lendata );
       if (adsp_hlcl01->boc_eof_client) {
         GEN_PRINTF( "m_hlcl01 called with boc_eof_client +++\n" );
       }
       if (adsp_hlcl01->boc_eof_server) {
         GEN_PRINTF( "m_hlcl01 called with boc_eof_server +++\n" );
       }
     }
#endif
   if (adsp_hlcl01->inc_func == DEF_IFUNC_START) {
     adsp_hlcl01->inc_func = DEF_IFUNC_CONT;
     adsp_hlcl01->inc_return = DEF_IRET_NORMAL;
     bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld, DEF_AUX_MEMGET, &adsl_stor, sizeof(dsd_stor_1) );
                                            /* get memory              */
     if (bol1 == FALSE) {
       adsp_hlcl01->inc_return = DEF_IRET_ERRAU;  /* message error     */
       return;                              /* return to main-prog     */
     }
     memset( adsl_stor, 0, sizeof(dsd_stor_1) );  /* clear buffer      */
     adsp_hlcl01->vpc_ext = adsl_stor;      /* store address of fields */
#ifndef OLD01
#ifndef OLD_0410
     memset( &dsl_ccb_1, 0, sizeof(dsl_ccb_1) );
     dsl_ccb_1.vpc_userfld = adsp_hlcl01->vpc_userfld;
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
     adsp_hlcl01->amc_conn_callback( &dsl_ccb_1 );
#else
     adsp_hlcl01->amc_conn_callback( adsp_hlcl01->vpc_userfld, 0, &adsl_stor->dconfig );
#endif
#endif
#ifdef MAKELOAD
     iml1 = 100;
     iml2 = 100;
     iml1 *= iml2 * 100;
     do {
       iml1--;
       iml2 = GetCurrentProcessId();
       ah1 = malloc( 311 );
       free( ah1 );
     } while (iml1);
#endif
     return;
   }
   if (adsp_hlcl01->inc_func != DEF_IFUNC_CONT) {
     adsp_hlcl01->inc_return = 3;
     return;
   }
   adsl_stor = (dsd_stor_1 *) adsp_hlcl01->vpc_ext;  /* get address of fields */
#ifdef D_SSL_GUI
   switch (adsl_stor->iec_csssls) {         /* state of client-side SSL */
     case ied_csssls_start:                 /* start aux-pipe          */
       goto p_ssl_gui_start;                /* start to process SSL-GUI */
     case ied_csssls_op_reply:              /* wait for operator reply */
       goto p_ssl_gui_reply;                /* received reply from SSL-GUI */
     case ied_csssls_normal:                /* normal processing       */
       break;
     default:
       GEN_PRINTF( "m_hlcl01 l%05d adsl_stor->iec_csssls = %d - invalid\n",
                   __LINE__, adsl_stor->iec_csssls );
       adsp_hlcl01->inc_return = DEF_IRET_END;
       return;
   }

   p_proc_data:                             /* process data            */
#endif
#ifndef OLD_0508
   bol_to_server = FALSE;                   /* something sent to server */
   bol_to_client = FALSE;                   /* something sent to client */
#endif
#ifdef OLD_0508
   if (adsp_hlcl01->boc_socket_alive == FALSE) {
     bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld, DEF_AUX_MEMFREE, &adsl_stor, sizeof(dsd_stor_1) );
                                            /* free memory             */
     if (bol1 == FALSE) {
       adsp_hlcl01->inc_return = DEF_IRET_ERRAU;  /* message error     */
       return;                              /* return to main-prog     */
     }
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
#endif
#ifdef OLD01
   if (adsl_stor->bo_callback == FALSE) {
     adsl_stor->bo_callback = TRUE;
     adsp_hlcl01->pCallback( adsp_hlcl01, 0, &adsl_stor->dconfig );
   }
#endif
   /* first copy input from client                                     */
   adsl_gai1_w1 = adsp_hlcl01->adsc_gai1_in_cl;
   while (TRUE) {
     if (adsl_gai1_w1 == NULL) break;
#ifndef OLD_0508
     if (adsp_hlcl01->boc_eof_client) {     /* End-of-File Client      */
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     } else {                               /* can send now            */
#endif
       iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2 = adsp_hlcl01->achc_out_se_end - adsp_hlcl01->achc_out_se_cur;
       if (iml2 <= 0) break;
       if (iml1 > iml2) iml1 = iml2;
       if (iml1) {
         memcpy( adsp_hlcl01->achc_out_se_cur, adsl_gai1_w1->achc_ginp_cur, iml1 );
         adsl_gai1_w1->achc_ginp_cur += iml1;
         adsp_hlcl01->achc_out_se_cur += iml1;
#ifndef OLD_0508
         bol_to_server = TRUE;              /* something sent to server */
#endif
       }
#ifndef OLD_0508
     }
#endif
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   /* second copy input from server                                     */
   adsl_gai1_w1 = adsp_hlcl01->adsc_gai1_in_se;
   while (TRUE) {
     if (adsl_gai1_w1 == NULL) break;
#ifndef OLD_0508
     if (adsp_hlcl01->boc_eof_server) {     /* End-of-File Server      */
       adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     } else {                               /* can send now            */
#endif
       iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml2 = adsp_hlcl01->achc_out_cl_end - adsp_hlcl01->achc_out_cl_cur;
       if (iml2 <= 0) break;
       if (iml1 > iml2) iml1 = iml2;
       if (iml1) {
         memcpy( adsp_hlcl01->achc_out_cl_cur, adsl_gai1_w1->achc_ginp_cur, iml1 );
         adsl_gai1_w1->achc_ginp_cur += iml1;
         adsp_hlcl01->achc_out_cl_cur += iml1;
#ifndef OLD_0508
         bol_to_client = TRUE;              /* something sent to client */
#endif
       }
#ifndef OLD_0508
     }
#endif
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (   (bol_to_server == FALSE)          /* nothing sent to server  */
       && (bol_to_client == FALSE)          /* nothing sent to client  */
       && (  (adsp_hlcl01->boc_eof_client)  /* End-of-File Client      */
           || (adsp_hlcl01->boc_eof_server))) {  /* End-of-File Server */
     bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld, DEF_AUX_MEMFREE, &adsl_stor, sizeof(dsd_stor_1) );
                                            /* free memory             */
     if (bol1 == FALSE) {
       adsp_hlcl01->inc_return = DEF_IRET_ERRAU;  /* message error     */
       return;                              /* return to main-prog     */
     }
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
#ifdef MAKELOAD
   if (iml1) {
     iml1 *= 100 * 100;
     do {
       iml1--;
       iml2 = GetCurrentProcessId();
       ah1 = malloc( 517 );
       free( ah1 );
     } while (iml1);
   }
#endif
#ifdef D_SSL_GUI
   return;

   p_ssl_gui_start:                         /* start to process SSL-GUI */
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_open;         /* open, client side open  */
   dsl_apr1.achc_aux_pipe_name = (char *) chrs_ap_ssl_gui;  /* address name of aux-pipe */
   dsl_apr1.imc_len_aux_pipe_name = sizeof(chrs_ap_ssl_gui);  /* length of name of aux-pipe */
   dsl_apr1.iec_aps = ied_aps_session;      /* for current session     */
   dsl_apr1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set         */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d vpc_aux_pipe_handle=%p.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.vpc_aux_pipe_handle );
#endif
   if (   (bol1 == FALSE)
       || (dsl_apr1.iec_aprc != ied_aprc_ok)) {  /* command returns o.k. */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d vpc_aux_pipe_handle=%p.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.vpc_aux_pipe_handle );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   adsl_stor->vpc_aux_pipe_handle = dsl_apr1.vpc_aux_pipe_handle;  /* save handle of aux-pipe */

   /* send text to SSL-GUI                                             */
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_write;        /* write to session        */
   dsl_apr1.vpc_aux_pipe_handle = adsl_stor->vpc_aux_pipe_handle;  /* get handle of aux-pipe */
   dsl_apr1.adsc_gai1_data = (struct dsd_gather_i_1 *) &dss_gai1_ap_w01;  /* send data */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE ied_apc_write returned %d error %d adsc_gai1_data=%p.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
#endif
   if (   (bol1 == FALSE)
       || (dsl_apr1.iec_aprc != ied_aprc_ok)) {  /* command returns o.k. */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   adsl_stor->iec_csssls = ied_csssls_op_reply;  /* wait for operator reply */
   return;                                  /* wait for reply from operator */

   p_ssl_gui_reply:                         /* received reply from SSL-GUI */
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_state;        /* check state session     */
   dsl_apr1.vpc_aux_pipe_handle = adsl_stor->vpc_aux_pipe_handle;  /* get handle of aux-pipe */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE ied_apc_state returned %d error %d adsc_gai1_data=%p.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
#endif
   if (bol1 == FALSE) {                     /* error occured           */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d adsc_gai1_data=%p.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   if (dsl_apr1.iec_aprc == ied_aprc_idle) {  /* command returns nothing */
     return;
   }
   if (dsl_apr1.iec_aprc != ied_aprc_read_buf) {  /* command returns read buffers */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d adsc_gai1_data=%p.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   if (dsl_apr1.adsc_gai1_data == NULL) {   /* no data read            */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d adsc_gai1_data=%p.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   adsl_gai1_w1 = dsl_apr1.adsc_gai1_data;  /* data read               */
   iml1 = 0;                                /* number of characters    */
   do {
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (iml1 != 1) {                         /* number of bytes read    */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d adsc_gai1_data=%p length=%d - invalid\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data, iml1 );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   adsl_gai1_w1 = dsl_apr1.adsc_gai1_data;  /* data read               */
   while (TRUE) {
     if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (*adsl_gai1_w1->achc_ginp_cur == '0') {
     GEN_PRINTF( "m_hlcl01 l%05d client-side SSL ended by operator\n",
                 __LINE__ );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   if (*adsl_gai1_w1->achc_ginp_cur == '1') {
     goto p_ssl_gui_end;                    /* reply o.k. read from SSL-GUI */
   }
   if (*adsl_gai1_w1->achc_ginp_cur != '2') {
     GEN_PRINTF( "m_hlcl01 l%05d operator input 0X%02X invalid\n",
                 __LINE__, *((unsigned char *) adsl_gai1_w1->achc_ginp_cur) );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_free_read_buffer;  /* free passed read buffers */
   dsl_apr1.vpc_aux_pipe_handle = adsl_stor->vpc_aux_pipe_handle;  /* get handle of aux-pipe */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE ied_apc_free_read_buffer returned %d error %d.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc );
#endif
   if (   (bol1 == FALSE)
       || (dsl_apr1.iec_aprc != ied_aprc_ok)) {  /* command returns o.k. */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }

   /* send text to SSL-GUI                                             */
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_write;        /* write to session        */
   dsl_apr1.vpc_aux_pipe_handle = adsl_stor->vpc_aux_pipe_handle;  /* get handle of aux-pipe */
   dsl_apr1.adsc_gai1_data = (struct dsd_gather_i_1 *) &dss_gai1_ap_w02;  /* send data */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE ied_apc_write returned %d error %d adsc_gai1_data=%p.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.adsc_gai1_data );
#endif
   if (   (bol1 == FALSE)
       || (dsl_apr1.iec_aprc != ied_aprc_ok)) {  /* command returns o.k. */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc );
     adsp_hlcl01->inc_return = DEF_IRET_END;
   }
   return;

   /** close aux-pipe connection                                       */
   p_ssl_gui_end:                           /* reply o.k. read from SSL-GUI */
   memset( &dsl_apr1, 0, sizeof(struct dsd_aux_pipe_req_1) );  /* aux-pipe request */
   dsl_apr1.iec_apc = ied_apc_close_conn;   /* close single connection */
   dsl_apr1.vpc_aux_pipe_handle = adsl_stor->vpc_aux_pipe_handle;  /* get handle of aux-pipe */
   bol1 = (*adsp_hlcl01->amc_aux)( adsp_hlcl01->vpc_userfld,
                                   DEF_AUX_PIPE, /* aux-pipe           */
                                   &dsl_apr1,  /* aux-pipe request     */
                                   sizeof(struct dsd_aux_pipe_req_1) );
#ifdef TRACEHL1
   GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE ied_apc_close_conn returned %d error %d.\n",
               __LINE__, bol1, dsl_apr1.iec_aprc );
#endif
   if (   (bol1 == FALSE)
       || (dsl_apr1.iec_aprc != ied_aprc_ok)) {  /* command returns o.k. */
     GEN_PRINTF( "m_hlcl01 l%05d aux() DEF_AUX_PIPE returned %d error %d vpc_aux_pipe_handle=%p.\n",
                 __LINE__, bol1, dsl_apr1.iec_aprc, dsl_apr1.vpc_aux_pipe_handle );
     adsp_hlcl01->inc_return = DEF_IRET_END;
     return;
   }
   adsl_stor->iec_csssls = ied_csssls_normal;  /* normal processing    */
   goto p_proc_data;                        /* process data            */
#endif
} /* end m_hlcl01()                                                    */

#ifdef B160504
extern "C" int m_cl_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                    char * achp_certdatabuf, int inp_certdatalen,
                                    char * achp_pdwbuf, int inp_pdwlen,
                                    BOOL boc_pwdfileflag,
                                    struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                    BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                    void * vpp_userfld,
                                    void ** avpp_config_id ) {
   *avpp_config_id = (void *) 771;
   return 0;
} /* m_cl_registerconfig()                                             */
#endif
#ifndef B160504
extern "C" int m_cl_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                    char * achp_certdatabuf, int inp_certdatalen,
                                    char * achp_pdwbuf, int inp_pdwlen,
                                    BOOL boc_pwdfileflag,
                                    struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                    BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                    void * vpp_userfld,
                                    void ** avpp_config_id,
                                    BOOL ) {
   *avpp_config_id = (void *) 771;
   return 0;
} /* m_cl_registerconfig()                                             */
#endif

extern "C" BOOL m_ssl_seed_rng( void ) {
   return TRUE;
} /* m_ssl_seed_rng()                                                  */

#ifdef OLD01
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
}
#endif

extern "C" int m_cl_get_conf_timeout( void *vpp_config_id ) {
   return DEF_HLSE_SSL_TIMEOUT;
}
