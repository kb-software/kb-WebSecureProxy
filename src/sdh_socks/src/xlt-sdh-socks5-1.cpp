//#define TRACEHL1
#define NEW_WSP_1102
//#define DEF_TEST_CSSSL                      /* 23.06.06 KB Test Client-Side SSL */
#ifdef COMMENTS
missing: send INETA Bind and Port to Socks 5 Client
         end connection when server TCP session ended
bug detected 31.08.11 KB
           case ied_s5stat_meth_f:          /* field with METHODS      */
// to-do 31.08.11 KB decrement iml1
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xlt-sdh-socks5-1                                    |*/
/*| -------------                                                     |*/
/*|  DLL / Library for WebSecureProxy                                 |*/
/*|    Server-Data-Hook                                               |*/
/*|  Socks 5 Proxy                                                    |*/
/*|    client sends Socks packets to tell WebSecureProxy              |*/
/*|    which connection to start                                      |*/
/*|  KB 28.05.05                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2005                                   |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
   Socks5 RFC 1928
*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

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
#else
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "hob-unix01.h"
#ifdef HL_FREEBSD
#include <netinet/in.h>
#endif
#endif
			   
//#include <hob-tab-ascii-ansi-1.h>
//#include <hob-tab-mime-base64.h>

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

extern "C" int m_hlvsnprintf( void *achp_target, int imp_max_len_target,
                              enum ied_charset iep_cs_target,
                              const char *achp_format, va_list dsp_list );


#define DEF_HL_INCL_INET
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#define D_TCP_ERROR WSAGetLastError()
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#define D_TCP_ERROR errno
#endif

#define D_DEST_IPV4ADDR           1
#define D_DEST_IPV6ADDR           4

#define MAX_LEN_USERID            512       /* maximum length userid   */
#define MAX_LEN_DOMAIN            256       /* maximum length destination domain */

/* Relay - Session Status - for Socks etc.                             */
enum ied_relsstat_type {
   ied_relsstat_normal,                     /* connection is normal    */
   ied_relsstat_s5r1,                       /* receive first packet Socks5 */
   ied_relsstat_s5req                       /* receive Socks5 request  */
};

/* Relay - Session Status - Socks 4 or Socks 5                         */
#ifdef B120809
enum ied_s5stat_type {
   ied_s5stat_bp1,                          /* begin first packet      */
   ied_s5stat_nmeth,                        /* NMETHODS                */
   ied_s5stat_meth_f,                       /* METHODS field           */
   ied_s5stat_preq_b,                       /* packet request begin    */
   ied_s5stat_preq_cmd,                     /* packet request CMD      */
   ied_s5stat_preq_rsv,                     /* packet request reserved */
   ied_s5stat_preq_atyp,                    /* packet request address type */
   ied_s5stat_preq_nooct,                   /* packet request number of octets */
   ied_s5stat_preq_daddr,                   /* packet request destination address */
   ied_s5stat_preq_dport                    /* packet request destination port */
};
#endif
enum ied_s_stat_type {
   ied_sall_stat_bp1,                       /* begin first packet      */
   ied_s4stat_cc,                           /* get SOCKS command code  */
   ied_s4stat_dstport,                      /* Socks 4 destination port */
   ied_s4stat_dstip,                        /* Socks 4 destination IP address */
   ied_s4stat_userid,                       /* Socks 4 userid          */
   ied_s4stat_domain,                       /* Socks 4 destination domain */
   ied_s5stat_nmeth,                        /* NMETHODS                */
   ied_s5stat_meth_f,                       /* METHODS field           */
   ied_s5stat_send_resp_1,                  /* send response authentication method */
   ied_s5stat_preq_b,                       /* packet request begin    */
   ied_s5stat_preq_cmd,                     /* packet request CMD      */
   ied_s5stat_preq_rsv,                     /* packet request reserved */
   ied_s5stat_preq_atyp,                    /* packet request address type */
   ied_s5stat_preq_nooct,                   /* packet request number of octets */
   ied_s5stat_preq_daddr,                   /* packet request destination address */
   ied_s5stat_preq_dport,                   /* packet request destination port */
   ied_sall_stat_do_connect                 /* do connect now          */
};

struct dsd_clib1_data_1 {                   /* structure session       */
   enum ied_relsstat_type iec_relsstat;     /* session status          */
#ifdef B120809
// char       chc_socks_vers;               /* Socks version (4 / 5)   */
   int        imc_send_client;              /* length send to client   */
   char       chrc_send_client[22];         /* area send to client     */
#endif
};

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

/* Socks 5 response no authentication                                  */
static const char chrs_socks5_resp_noauth[] = { 0X05, 0X00 };

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );

/*+-------------------------------------------------------------------+*/
/*| Entry for the Server-Data-Hook.                                   |*/
/*+-------------------------------------------------------------------+*/

/** subroutine to process the copy library function                    */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_port;                     /* fill with port number   */
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
#ifdef TRACEHL1
   char       chl1;                         /* working variable        */
#endif
   char       chl_socks_vers;               /* Socks version (4 / 5)   */
   char       chl_preq_atyp;                /* address type received   */
   char       *achl1;                       /* working variable        */
   char       *achl_work_1;                 /* position work area, up  */
   char       *achl_work_2;                 /* position work area, dow */
   ied_s_stat_type iel_s5stat;              /* Socks5 Session State    */
   char       *achl_rb;                     /* read in block           */
   char       chrl_proto_1[ 2 ];            /* display protocol        */
   struct dsd_clib1_data_1 *adsl_cl1d1_1;   /* for addressing          */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_aux_tcp_conn_1 dsl_atc1_1;    /* TCP Connect to Server   */
   union {
     struct sockaddr_in6 dsl_soa_l;
     struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
   };

   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
#ifdef TRACEHL1
   {
     char *achh_text = "invalid function";
     switch (adsp_hl_clib_1->inc_func) {
       case DEF_IFUNC_START:
         achh_text = "DEF_IFUNC_START";
         break;
       case DEF_IFUNC_CLOSE:
         achh_text = "DEF_IFUNC_CLOSE";
         break;
       case DEF_IFUNC_FROMSERVER:
         achh_text = "DEF_IFUNC_FROMSERVER";
         break;
       case DEF_IFUNC_TOSERVER:
         achh_text = "DEF_IFUNC_TOSERVER";
         break;
       case DEF_IFUNC_REFLECT:
         achh_text = "DEF_IFUNC_REFLECT";
         break;
     }
     iml1 = iml2 = 0;                       /* length input data       */
     adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     bol1 = FALSE;
     chl1 = 0;
     while (adsl_gai1_inp_1) {
       iml2++;
       iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (   (adsl_gai1_inp_1->achc_ginp_end > adsl_gai1_inp_1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X.",
                   __LINE__, adsp_hl_clib_1->inc_func, achh_text,
                   adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
   }
#endif
#define CHRL_WORK_1 adsp_hl_clib_1->achc_work_area
#define CHRL_WORK_2 (adsp_hl_clib_1->achc_work_area + 512)
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) (adsp_hl_clib_1->achc_work_area + adsp_hl_clib_1->inc_len_work_area - sizeof(struct dsd_gather_i_1)))
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_data_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       memset( adsp_hl_clib_1->ac_ext, 0, sizeof(struct dsd_clib1_data_1) );
       /* receive first packet Socks5                                  */
       ((struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext)->iec_relsstat = ied_relsstat_s5r1;
       return;
     case DEF_IFUNC_CLOSE:
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_data_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       }
       return;
   }
   adsl_cl1d1_1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
#ifdef TRACEHL1
   if (adsp_hl_clib_1->boc_eof_client) {    /* End-of-File Client      */
     m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T end-of-file Client",
                   __LINE__ );
   }
   if (adsp_hl_clib_1->boc_eof_server) {    /* End-of-File Server      */
     m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T end-of-file Server",
                   __LINE__ );
   }
   m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T adsl_cl1d1_1=%p adsl_cl1d1_1->iec_relsstat=%d.",
                 __LINE__, adsl_cl1d1_1, adsl_cl1d1_1->iec_relsstat );
#endif
#define IEL_RELSSTAT_G adsl_cl1d1_1->iec_relsstat
//#define CHL_SOCKS_VERS adsl_cl1d1_1->chc_socks_vers
   if (IEL_RELSSTAT_G == ied_relsstat_normal) {  /* connection is normal */
     goto pcopy_00;                         /* copy input to output    */
   }
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_REFLECT) {
     m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W invalid function - inc_func=%d.",
                   __LINE__, adsp_hl_clib_1->inc_func );
     return;
   }
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) {  /* no input data */
     return;
   }
   chrl_proto_1[ 0 ] = 0;                   /* display protocol empty  */
   /* examine data received - protocol Socks 5                         */
   switch (IEL_RELSSTAT_G) {
     case ied_relsstat_s5r1:                /* receive first packet Socks5 */
       iel_s5stat = ied_sall_stat_bp1;      /* begin first packet      */
       break;
     case ied_relsstat_s5req:               /* receive Socks5 request  */
       iel_s5stat = ied_s5stat_preq_b;      /* packet request begin    */
       chl_socks_vers = 0X05;               /* set Socks-5             */
       break;
     default:
       m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W invalid IEL_RELSSTAT_G - IEL_RELSSTAT_G=%d.",
                     __LINE__, IEL_RELSSTAT_G );
       return;
   }
/**
   input is not consumed
   when the input does not contain all data of the packet,
   the SDH simply returns,
   so scanning of the complete packet will be done
   when called again, maybe with more input.
*/
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   do {                                     /* loop over input data    */
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) {
       achl_rb = adsl_gai1_inp_1->achc_ginp_cur;  /* start scann here  */
       while (   (achl_rb < adsl_gai1_inp_1->achc_ginp_end)  /* loop over input data */
              || (iel_s5stat == ied_sall_stat_do_connect)) {  /* do connect now */
         iml1 = adsl_gai1_inp_1->achc_ginp_end - achl_rb;  /* length remaining */
         switch (iel_s5stat) {              /* depending on state      */
           case ied_sall_stat_bp1:          /* begin first record      */
             chl_socks_vers = *achl_rb++;   /* get first byte          */
             if (chl_socks_vers == 0X04) {  /* is Socks4               */
               iel_s5stat = ied_s4stat_cc;  /* get SOCKS command code  */
               break;
             }
             if (chl_socks_vers != 0X05) {  /* is not Socks5           */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             iel_s5stat = ied_s5stat_nmeth;  /* get NMETHODS           */
             break;
           case ied_s4stat_cc:              /* get SOCKS command code  */
             if (*achl_rb != 1) {           /* is not CONNECT          */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s4stat_dstport;  /* Socks 4 destination port */
             iml3 = 2;                      /* length of port          */
             iml_port = 0;                  /* clear numeric value     */
             break;
           case ied_s4stat_dstport:         /* Socks 4 destination port */
             while (TRUE) {
               iml_port <<= 8;              /* shift previous value    */
               iml_port |= (unsigned char) *achl_rb++;  /* get input   */
               iml3--;                      /* one byte processed      */
               if (iml3 == 0) break;        /* end of port             */
               if (achl_rb >= adsl_gai1_inp_1->achc_ginp_end) break;  /* end of input data */
             }
             if (iml3 > 0) break;           /* not yet end of port     */
             iel_s5stat = ied_s4stat_dstip;  /* Socks 4 destination IP address */
             iml3 = 4;                      /* number of bytes to follow */
             iml2 = 0;                      /* position INETA          */
             break;
           case ied_s4stat_dstip:           /* Socks 4 destination IP address */
             iml4 = iml1;                   /* so many characters      */
             if (iml4 > (iml3 - iml2)) iml4 = iml3 - iml2;  /* only so many for field */
             memcpy( CHRL_WORK_1 + iml2, achl_rb, iml4 );  /* copy part of field */
             iml2 += iml4;                  /* filled so far           */
             achl_rb += iml4;               /* so many input characters */
             if (iml2 < iml3) break;        /* field not yet filled    */
#ifdef B120815
             /* check Socks4A                                          */
             if (   (*(CHRL_WORK_1 + 0) == 0)
                 && (*(CHRL_WORK_1 + 1) == 0)
                 && (*(CHRL_WORK_1 + 2) == 0)) {
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
#endif
             iel_s5stat = ied_s4stat_userid;  /* Socks 4 userid        */
             iml2 = MAX_LEN_USERID;         /* maximum length userid   */
             break;
           case ied_s4stat_userid:          /* Socks 4 userid          */
             if (iml1 > iml2) {             /* check userid too long   */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             iml2 -= iml1;                  /* subtract length this chunk */
             do {                           /* loop over input userid, search NULL */
               if (*achl_rb++ == 0) break;  /* end of userid found     */
               iml1--;                      /* decrement length remaining input */
             } while (iml1 > 0);
             if (iml1 <= 0) break;          /* needs more input        */
             /* check Socks4A                                          */
             if (   (*(CHRL_WORK_1 + 0) == 0)
                 && (*(CHRL_WORK_1 + 1) == 0)
                 && (*(CHRL_WORK_1 + 2) == 0)) {
               chrl_proto_1[ 0 ] = 'A';     /* display protocol set    */
               chrl_proto_1[ 1 ] = 0;       /* display protocol set    */
               iml2 = 0;                    /* start of field          */
               iel_s5stat = ied_s4stat_domain;  /* Socks 4 destination domain */
               break;
             }
             sprintf( CHRL_WORK_2, "%u.%u.%u.%u",
                      (unsigned char) CHRL_WORK_1[0], (unsigned char) CHRL_WORK_1[1],
                      (unsigned char) CHRL_WORK_1[2], (unsigned char) CHRL_WORK_1[3] );
             achl1 = CHRL_WORK_2;           /* here is INETA           */
             iel_s5stat = ied_sall_stat_do_connect;  /* do connect now */
             break;
           case ied_s4stat_domain:          /* Socks 4 destination domain */
             do {                           /* loop to copy destination domain name */
               if (*achl_rb == 0) {         /* no auth found           */
                 achl_rb++;                 /* this byte processed     */
                 CHRL_WORK_1[ iml2 ] = 0;   /* INETA zero-terminated   */
                 achl1 = CHRL_WORK_1;       /* here is INETA           */
                 iel_s5stat = ied_sall_stat_do_connect;  /* do connect now */
                 break;
               }
               if (iml2 >= MAX_LEN_DOMAIN) {  /* maximum length destination domain */
                 iml1 = __LINE__;           /* set line number source  */
                 goto psock_20;             /* invalid data in packet  */
               }
               CHRL_WORK_1[ iml2++ ] = *achl_rb++;  /* copy input      */
               iml1--;                      /* decrement characters input */
             } while (iml1 > 0);
             break;                         /* needs more input data   */
           case ied_s5stat_nmeth:           /* NMETHODS field          */
             if (*achl_rb == 0) {           /* field is empty          */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             iml2 = *achl_rb;               /* get NMETHODS            */
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s5stat_meth_f;  /* get field with METHODS */
             bol1 = FALSE;                  /* not yet no auth         */
             break;
           case ied_s5stat_meth_f:          /* field with METHODS      */
             do {
               if (*achl_rb == 0) {         /* no auth found           */
                 if (bol1) {                /* no auth already set     */
                   iml1 = __LINE__;         /* set line number source  */
                   goto psock_20;           /* invalid data in packet  */
                 }
                 bol1 = TRUE;               /* now no auth found       */
               }
               achl_rb++;                   /* input processed         */
               iml2--;                      /* one method decoded      */
               if (achl_rb >= adsl_gai1_inp_1->achc_ginp_end) break;
// to-do 31.08.11 KB decrement iml1 / usage iml2 in next statement
//           } while (iml1 > 0);
             } while (iml2 > 0);
             if (iml2 > 0) break;           /* receive more data       */
             if (bol1 == FALSE) {           /* no auth already set     */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             /* now send response                                      */
             IEL_RELSSTAT_G = ied_relsstat_s5req;  /* receive Socks5 request */
             achl1 = (char *) chrs_socks5_resp_noauth;  /* this field to send */
             iml1 = sizeof(chrs_socks5_resp_noauth);  /* length of data */
             goto psock_40;                 /* send response for socks */
           case ied_s5stat_preq_b:          /* packet request begin    */
             if (*achl_rb != 0X05) {        /* is not Socks5           */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s5stat_preq_cmd;  /* packet request CMD  */
             break;
           case ied_s5stat_preq_cmd:        /* packet request CMD      */
             if (*achl_rb != 1) {           /* is not connect          */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s5stat_preq_rsv;  /* packet request reseved */
             break;
           case ied_s5stat_preq_rsv:        /* packet request reserved */
             if (*achl_rb != 0) {           /* is not empty            */
               iml1 = __LINE__;             /* set line number source  */
               goto psock_20;               /* invalid data in packet  */
             }
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s5stat_preq_atyp;  /* packet request address type */
             break;
           case ied_s5stat_preq_atyp:       /* packet request address type */
             chl_preq_atyp = *achl_rb++;    /* address type received   */
             switch (chl_preq_atyp) {       /* address type            */
               case 1:                      /* INETA IPV4              */
                 iml3 = 4;                  /* number of bytes to follow */
                 break;
               case 3:                      /* domain name             */
                 iml3 = 0;                  /* number of bytes to follow - variable */
                 break;
               case 4:                      /* INETA IPV6              */
                 iml3 = 16;                 /* number of bytes to follow */
                 break;
               default:
                 iml1 = __LINE__;           /* set line number source  */
                 goto psock_20;             /* invalid data in packet  */
             }
             iel_s5stat = ied_s5stat_preq_daddr;  /* packet request destination address */
             if (iml3 == 0) iel_s5stat = ied_s5stat_preq_nooct;  /* packet request number of octets */
             iml2 = 0;                      /* position INETA          */
             break;
           case ied_s5stat_preq_nooct:      /* packet request number of octets */
             iml3 = *((unsigned char *) achl_rb);
             achl_rb++;                     /* this byte processed     */
             iel_s5stat = ied_s5stat_preq_daddr;  /* packet request destination address */
             if (iml3) break;               /* all valid               */
             iml1 = __LINE__;               /* set line number source  */
             goto psock_20;                 /* invalid data in packet  */
           case ied_s5stat_preq_daddr:      /* packet request destination address */
             iml4 = iml1;                   /* so many characters      */
             if (iml4 > (iml3 - iml2)) iml4 = iml3 - iml2;  /* only so many for field */
             memcpy( CHRL_WORK_1 + iml2, achl_rb, iml4 );  /* copy part of field */
             iml2 += iml4;                  /* filled so far           */
             achl_rb += iml4;               /* so many input characters */
             if (iml2 < iml3) break;        /* field not yet filled    */
             iel_s5stat = ied_s5stat_preq_dport;  /* packet request destination port */
             iml3 = 2;                      /* length of port          */
             iml_port = 0;                  /* clear numeric value     */
             break;
           case ied_s5stat_preq_dport:      /* packet request destination port */
             while (TRUE) {
               iml_port <<= 8;              /* shift previous value    */
               iml_port |= (unsigned char) *achl_rb++;  /* get input   */
               iml3--;                      /* one byte processed      */
               if (iml3 == 0) break;        /* end of port             */
               if (achl_rb >= adsl_gai1_inp_1->achc_ginp_end) break;  /* end of input data */
             }
             if (iml3 > 0) break;           /* not yet end of port     */
             switch (chl_preq_atyp) {       /* address type            */
               case 1:                      /* INETA IPV4              */
                 sprintf( CHRL_WORK_2, "%u.%u.%u.%u",
                          (unsigned char) CHRL_WORK_1[0], (unsigned char) CHRL_WORK_1[1],
                          (unsigned char) CHRL_WORK_1[2], (unsigned char) CHRL_WORK_1[3] );
                 achl1 = CHRL_WORK_2;       /* here is INETA           */
                 break;
               case 3:                      /* domain name             */
                 *(CHRL_WORK_1 + iml2) = 0;  /* make zero-terminated   */
                 achl1 = CHRL_WORK_1;       /* here is INETA           */
                 break;
               case 4:                      /* INETA IPV6              */
                 memset( &dsl_soa_l, 0, sizeof(struct sockaddr_in6) );
                 dsl_soa_l.sin6_family = AF_INET6;
                 memcpy( &dsl_soa_l.sin6_addr, CHRL_WORK_1, 16 );
                 iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_l, sizeof(struct sockaddr_in6),
                                       CHRL_WORK_2, 128, 0, 0, NI_NUMERICHOST );
                 if (iml_rc) {              /* error occured           */
                   m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W IPV6 getnameinfo() returned %d %d.",
                                 __LINE__, iml_rc, D_TCP_ERROR );
                   iml1 = __LINE__;         /* set line number source  */
                   goto psock_20;           /* invalid data in packet  */
                 }
                 achl1 = CHRL_WORK_2;       /* here is INETA           */
                 break;
             }
             /* fall thru                                              */
           case ied_sall_stat_do_connect:   /* do connect now          */
             /* give message of connect                                */
             m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-I Socks %d%s connect INETA %s port %d.",
                           __LINE__, chl_socks_vers, chrl_proto_1,achl1, iml_port );
             IEL_RELSSTAT_G = ied_relsstat_normal;  /* receive normal data */
             /* connect to server now                                  */
             memset( &dsl_atc1_1, 0, sizeof(dsl_atc1_1) );
             dsl_atc1_1.dsc_target_ineta.ac_str = achl1;  /* address of string */
             dsl_atc1_1.dsc_target_ineta.imc_len_str = -1;  /* length string in elements */
             dsl_atc1_1.dsc_target_ineta.iec_chs_str = D_CHARSET_IP;  /* character set string */
             dsl_atc1_1.imc_server_port = iml_port;
#ifdef DEF_TEST_CSSSL                       /* 23.06.06 KB Test Client-Side SSL */
             dsl_atc1_1.dsc_aux_tcp_def.ibc_ssl_client = 1;  /* use client-side SSL */
#endif
             bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                             DEF_AUX_TCP_CONN,
                                             &dsl_atc1_1,
                                             sizeof(dsl_atc1_1) );
             if (bol1 == FALSE) {
               adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
               return;
             }
#ifdef TRACEHL1
             m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T after DEF_AUX_TCP_CONN bol1=%d iec_tcpconn_ret=%d.",
                           __LINE__, bol1, dsl_atc1_1.iec_tcpconn_ret );
#endif
             if (dsl_atc1_1.iec_tcpconn_ret == ied_tcr_ok) {  /* connect successful */
               bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                               DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
                                               &dsl_agsi,  /* get information about the session */
                                               sizeof(struct dsd_aux_get_session_info) );
               if (bol1 == FALSE) {
                 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                 return;
               }
               if (dsl_agsi.iec_ass == ied_ass_invalid) {  /* invalid  */
                 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                 return;
               }
#ifdef B120809
               *(adsl_cl1d1_1->chrc_send_client + 0) = 0X05;  /* set Socks 5 */
               memset( adsl_cl1d1_1->chrc_send_client + 1, 0, 2 );  /* clear response area */
               switch (dsl_agsi.dsc_soa_server_this.ss_family) {
                 case AF_INET:              /* IPV4                    */
                   *(adsl_cl1d1_1->chrc_send_client + 3) = D_DEST_IPV4ADDR;  /* ATYP */
                   memcpy( adsl_cl1d1_1->chrc_send_client + 4,
                           &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_addr,
                           4 );
                   memcpy( adsl_cl1d1_1->chrc_send_client + 4 + 4,
                           &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_port,
                           2 );
                   adsl_cl1d1_1->imc_send_client = 4 + 4 + 2;  /* set length to send */
                   break;
                 case AF_INET6:             /* IPV6                    */
                   *(adsl_cl1d1_1->chrc_send_client + 3) = D_DEST_IPV6ADDR;  /* ATYP */
                   memcpy( adsl_cl1d1_1->chrc_send_client + 4,
                           &((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_this)->sin6_addr,
                           16 );
                   memcpy( adsl_cl1d1_1->chrc_send_client + 4 + 16,
                           &((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_this)->sin6_port,
                           2 );
                   adsl_cl1d1_1->imc_send_client = 4 + 16 + 2;  /* set length to send */
                   break;
                 default:                   /* family not found        */
                   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                   return;
               }
               adsp_hl_clib_1->boc_callrevdir = TRUE;  /* call on reverse direction */
               iml1 = 0;                    /* nothing to send now     */
               goto psock_40;               /* send response for socks */
#endif
               if (chl_socks_vers != 0X05) {  /* is not Socks5         */
                 *(CHRL_WORK_1 + 0) = 0;    /* VN reply code           */
                 *(CHRL_WORK_1 + 1) = (unsigned char) 90;  /* CD request granted */
                 /* can only be IPV4                                   */
                 memcpy( CHRL_WORK_1 + 2,
                         &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_port,
                         2 );
                 memcpy( CHRL_WORK_1 + 4,
                         &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_addr,
                         4 );
                 achl1 = CHRL_WORK_1;       /* send this area          */
                 iml1 = 8;                  /* length of data          */
                 goto psock_40;             /* send response for socks */
               }
               *(CHRL_WORK_1 + 0) = 0X05;   /* set Socks 5             */
               memset( CHRL_WORK_1 + 1, 0, 2 );  /* clear response area */
               switch (dsl_agsi.dsc_soa_server_this.ss_family) {
                 case AF_INET:              /* IPV4                    */
                   *(CHRL_WORK_1 + 3) = D_DEST_IPV4ADDR;  /* ATYP      */
                   memcpy( CHRL_WORK_1 + 4,
                           &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_addr,
                           4 );
                   memcpy( CHRL_WORK_1 + 4 + 4,
                           &((struct sockaddr_in *) &dsl_agsi.dsc_soa_server_this)->sin_port,
                           2 );
                   iml1 = 4 + 4 + 2;        /* set length to sent      */
                   break;
                 case AF_INET6:             /* IPV6                    */
                   *(CHRL_WORK_1 + 3) = D_DEST_IPV6ADDR;  /* ATYP      */
                   memcpy( CHRL_WORK_1 + 4,
                           &((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_this)->sin6_addr,
                           16 );
                   memcpy( CHRL_WORK_1 + 4 + 16,
                           &((struct sockaddr_in6 *) &dsl_agsi.dsc_soa_server_this)->sin6_port,
                           2 );
                   iml1 = 4 + 16 + 2;       /* set length to sent      */
                   break;
                 default:                   /* family not found        */
                   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                   return;
               }
               achl1 = CHRL_WORK_1;         /* send this area          */
               goto psock_40;               /* send response for socks */
             }
             /* now send response about the error                      */
             if (chl_socks_vers != 0X05) {  /* is not Socks5           */
               memset( CHRL_WORK_1, 0, 8 );  /* clear response area    */
               *(CHRL_WORK_1 + 1) = (unsigned char) 91;  /* CD request failed */
               achl1 = CHRL_WORK_1;         /* send this area          */
               iml1 = 8;                    /* length of data          */
               goto psock_40;               /* send response for socks */
             }
             iml1 = 0X01;                   /* general SOCKS server failure */
             switch (dsl_atc1_1.iec_tcpconn_ret) {
               case ied_tcr_invalid:        /* parameter is invalid    */
                 break;                     /* default response        */
               case ied_tcr_no_ocos:        /* option-connect-other-server not configured */
                 break;                     /* default response        */
               case ied_tcr_no_cs_ssl:      /* no Client-Side SSL configured */
                 break;                     /* default response        */
               case ied_tcr_denied_tf:      /* access denied because of target-filter */
                 iml1 = 0X02;               /* connection not allowed by ruleset */
                 break;                     /* send response           */
               case ied_tcr_hostname:       /* host-name not in DNS    */
                 break;                     /* default response        */
               case ied_tcr_no_route:       /* no route to host        */
                 iml1 = 0X03;               /* Network unreachable     */
                 break;                     /* send response           */
               case ied_tcr_refused:        /* connection refused      */
                 iml1 = 0X05;               /* Connection refused      */
                 break;                     /* send response           */
               case ied_tcr_timeout:        /* connection timed out    */
                 break;                     /* default response        */
               case ied_tcr_error:          /* other error             */
                 break;                     /* default response        */
             }
             *(CHRL_WORK_1 + 0) = 0X05;     /* socks response          */
             *(CHRL_WORK_1 + 1) = (unsigned char) iml1;  /* error code */
             memset( CHRL_WORK_1 + 2, 0, 8 );  /* clear response area  */
             *(CHRL_WORK_1 + 3) = D_DEST_IPV4ADDR;  /* ATYP            */
             achl1 = CHRL_WORK_1;           /* send this area          */
             iml1 = 10;                     /* length of data          */
             goto psock_40;                 /* send response for socks */
         }
       }
       break;                               /* valid data found        */
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
   } while (adsl_gai1_inp_1);
   return;

   psock_20:                                /* invalid data in packet  */
   m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W Socks 5 invalid data received line %05d.",
                 __LINE__, iml1 );
   return;

   psock_40:                                /* send response for socks */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-T psock_40 adsl_cl1d1_1=%p adsl_cl1d1_1->iec_relsstat=%d.",
                 __LINE__, adsl_cl1d1_1, adsl_cl1d1_1->iec_relsstat );
#endif
   /* first mark how far the receive blocks are processed              */
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (adsl_gai1_inp_2) {                /* loop over all entries   */
     if (adsl_gai1_inp_2 == adsl_gai1_inp_1) {  /* current block found */
       adsl_gai1_inp_2->achc_ginp_cur = achl_rb;  /* processed till here */
       break;
     }
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   if (iml1 == 0) return;                   /* no data to send         */
   memset( ADSL_GAI1_OUT_W, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl1;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl1 + iml1;
#ifndef NEW_WSP_1102
   adsp_hl_clib_1->adsc_gather_i_1_out = ADSL_GAI1_OUT_W;
#else
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
#endif
   return;

   pcopy_00:                                /* copy input to output    */
   if (   (adsp_hl_clib_1->inc_func != DEF_IFUNC_FROMSERVER)
       && (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)) {
     m_sdh_printf( &dsl_sdh_call_1, "xlt-sdh-socks5-1-l%05d-W invalid function - inc_func=%d.",
                   __LINE__, adsp_hl_clib_1->inc_func );
     return;
   }
#ifdef B120809
   if (   (adsl_cl1d1_1->imc_send_client > 0)  /* length to send       */
       && (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER)) {
     memset( ADSL_GAI1_OUT_W, 0, sizeof(struct dsd_gather_i_1) );
     ADSL_GAI1_OUT_W->achc_ginp_cur = adsl_cl1d1_1->chrc_send_client;
     ADSL_GAI1_OUT_W->achc_ginp_end = adsl_cl1d1_1->chrc_send_client
                                        + adsl_cl1d1_1->imc_send_client;
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = ADSL_GAI1_OUT_W;
#else
     adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
#endif
     adsl_cl1d1_1->imc_send_client = 0;     /* data sent now           */
     return;
   }
#endif
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) {  /* no input data */
#ifdef B130806
     return;
#endif
#ifndef B130806
     goto pcopy_40;                         /* end of copy operations  */
#endif
   }
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* here is work area */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;

   pcopy_20:                                /* next gather input       */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) return;
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
   adsl_gai1_out_1->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_end;
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
       adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
     } else {                               /* send to server          */
       adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
     }
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
   adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
   if (adsl_gai1_inp_1 != NULL) goto pcopy_20;  /* next gather         */
#ifndef B130806

   pcopy_40:                                /* end of copy operations  */
   if (adsp_hl_clib_1->boc_eof_server == FALSE) {  /* not End-of-File Server */
     return;                                /* nothing more to do      */
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection should be ended */
#endif
   return;
}

/** subroutine for output to console                                   */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()                                                */
