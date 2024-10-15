#ifndef HL_UNIX
#define TRY_100712
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xslnetw1                                            |*/
/*| -------------                                                     |*/
/*|  HOB common library - Networking                                  |*/
/*|  Project WSP, WSPnG, HCU2 and HL-VPN V2                           |*/
/*|  KB 11.09.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*| EXPECTED chpa_input:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#include <sys/timeb.h>
//#include <wchar.h>
#ifndef HL_UNIX
//#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
//#include <iswcord1.h>
//#include <hob-xslhcla1.hpp>
//#include <hob-xslcontr.h>
#include <hob-xslunic1.h>
#ifdef B140122
#include <ws2ipdef.h>
#endif
#include <hob-netw-01.h>
#else
#include <errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "hob-unix01.h"
#include <hob-xslunic1.h>
//#include "hob-xslhcla1.hpp"
//#include "hob-xslcontr.h"
#include "hob-netw-01.h"
#endif

/*+-------------------------------------------------------------------+*/
/*| Definitions for the Compiler.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifndef WIN64
typedef long int dsd_time_1;
#else
typedef __int64 dsd_time_1;
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifndef HL_UNIX
#ifndef UNSIG_MED
typedef unsigned int UNSIG_MED;
#endif
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#endif

#define D_MAXLEN_INETA 512

#define m_ip_getaddrinfo getaddrinfo
#define m_ip_freeaddrinfo freeaddrinfo

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

extern "C" int m_hl1_printf( const char *aptext, ... );

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Constant data.                                                    |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Procedure Sections.                                               |*/
/*+-------------------------------------------------------------------+*/

/** generate structure INETA for connect to target                     */
extern "C" struct dsd_target_ineta_1 * m_get_target_ineta( void *ap_ineta, int imp_len_ineta, ied_charset iep_cs_ineta,
                                                           struct dsd_bind_ineta_1 *adsp_biineta1 ) {
   int        iml_rc;                       /* return code             */
   int        iml_count;                    /* count entries           */
   int        iml_lenmem;                   /* memory needed           */
#ifdef HL_UNIX
   int        iml_cmp_pos;                  /* position to compare     */
   int        iml_cmp_len;                  /* length to compare       */
#endif
   char       *achl_ineta;                  /* address of INETA        */
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
#ifdef HL_UNIX
   struct addrinfo *adsl_addrinfo_w4;
#endif
   struct dsd_target_ineta_1 *adsl_target_ineta_1_w1;  /* definition INETA target */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */
   char       chrl_work_ineta[ D_MAXLEN_INETA ];

   achl_ineta = (char *) ap_ineta;
   if (   (iep_cs_ineta != ied_chs_idna_1)
       || (imp_len_ineta >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                           ap_ineta, imp_len_ineta, iep_cs_ineta );
     if (iml_rc <= 0) return NULL;          /* string not valid        */
     achl_ineta = chrl_work_ineta;
   }
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
#ifdef TRY_100712
   dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
   dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
#endif
   adsl_addrinfo_w2 = NULL;
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     return NULL;                           /* return error            */
   }
#ifdef TRACEHL1
   printf( "xslnetw1-%05d-T AF_INET=%d AF_INET6=%d\n",
           __LINE__, AF_INET, AF_INET6 );
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
   while (adsl_addrinfo_w3) {
     printf( "xslnetw1-%05d-T getaddrinfo ai_family=%d\n",
             __LINE__, adsl_addrinfo_w3->ai_family );
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:
         printf( "xslnetw1-%05d-T getaddrinfo &adsl_addrinfo_w3->ai_addr=0X%p &(((struct sockaddr_in *) &adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr)=0X%p\n",
                 __LINE__,
                 &adsl_addrinfo_w3->ai_addr,
                 &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) );
         printf( "xslnetw1-%05d-T getaddrinfo ai_family AF_INET INETA=%d.%d.%d.%d\n",
                 __LINE__,
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 0),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 1),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 2),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 3) );
         break;
       default:
         printf( "xslnetw1-%05d-T getaddrinfo ai_family undefined\n",
                 __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
   iml_count = 0;                           /* clear count entries     */
   iml_lenmem = sizeof(struct dsd_target_ineta_1);  /* set memory needed initial */
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
#ifndef HL_UNIX
   while (adsl_addrinfo_w3) {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv4 == FALSE)) {  /* IPV4 not supported */
           break;
         }
         iml_count++;                       /* count entry             */
         iml_lenmem += sizeof(struct dsd_ineta_single_1) + 4;  /* add length memory needed */
         break;
       case AF_INET6:                       /* IPV6                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv6 == FALSE)) {  /* IPV6 not supported */
           break;
         }
         iml_count++;                       /* count entry             */
         iml_lenmem += sizeof(struct dsd_ineta_single_1) + 16;  /* add length memory needed */
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
#ifdef HL_UNIX
   while (adsl_addrinfo_w3) {
     iml_cmp_len = 0;                       /* length to compare       */
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv4 == FALSE)) {  /* IPV4 not supported */
           break;
         }
         iml_cmp_pos = offsetof( struct sockaddr_in, sin_addr );  /* position to compare */
         iml_cmp_len = 4;                   /* length to compare       */
         break;
       case AF_INET6:                       /* IPV6                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv6 == FALSE)) {  /* IPV6 not supported */
           break;
         }
         iml_cmp_pos = offsetof( struct sockaddr_in6, sin6_addr );  /* position to compare */
         iml_cmp_len = 16;                  /* length to compare       */
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     while (iml_cmp_len) {                  /* we want output          */
       adsl_addrinfo_w4 = adsl_addrinfo_w2;  /* get first INETA again  */
       while (adsl_addrinfo_w4 != adsl_addrinfo_w3) {
         if (   (adsl_addrinfo_w4->ai_family == adsl_addrinfo_w3->ai_family)
             && (!memcmp( (char *) (adsl_addrinfo_w4->ai_addr) + iml_cmp_pos,
                          (char *) (adsl_addrinfo_w3->ai_addr) + iml_cmp_pos,
                          iml_cmp_len ))) {
           iml_cmp_len = 0;                 /* we do not want output   */
           break;
         }
         adsl_addrinfo_w4 = adsl_addrinfo_w4->ai_next;  /* get next in chain */
       }
       if (iml_cmp_len == 0) break;         /* we do not want output   */
       iml_count++;                         /* count entry             */
       iml_lenmem += sizeof(struct dsd_ineta_single_1) + iml_cmp_len;  /* add length memory needed */
       break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
#ifdef TRACEHL1
   printf( "xslnetw1-%05d-T m_get_target_ineta() iml_count=%d iml_lenmem=%d.\n",
               __LINE__, iml_count, iml_lenmem );
#endif
   if (iml_count == 0) {
     m_ip_freeaddrinfo( adsl_addrinfo_w2 );  /* free addresses again   */
     return NULL;
   }
   adsl_target_ineta_1_w1 = (struct dsd_target_ineta_1 *) malloc( iml_lenmem );
   adsl_target_ineta_1_w1->imc_no_ineta = iml_count;  /* number of INETA */
   adsl_target_ineta_1_w1->imc_len_mem = iml_lenmem;  /* length of memory including this structure */
   adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsl_target_ineta_1_w1 + 1);
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
#ifndef HL_UNIX
   while (adsl_addrinfo_w3) {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv4 == FALSE)) {  /* IPV4 not supported */
           break;
         }
         adsl_ineta_s_w1->usc_family = AF_INET;  /* family IPV4        */
         adsl_ineta_s_w1->usc_length = 4;   /* length of following address */
         memcpy( adsl_ineta_s_w1 + 1,
                 &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr),
                 4 );
         adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) ((char *) (adsl_ineta_s_w1 + 1) + 4);
         break;
       case AF_INET6:                       /* IPV6                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv6 == FALSE)) {  /* IPV6 not supported */
           break;
         }
         adsl_ineta_s_w1->usc_family = AF_INET6;  /* family IPV6       */
         adsl_ineta_s_w1->usc_length = 16;  /* length of following address */
         memcpy( adsl_ineta_s_w1 + 1,
                 &(((struct sockaddr_in6 *) adsl_addrinfo_w3->ai_addr)->sin6_addr),
                 16 );
         adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) ((char *) (adsl_ineta_s_w1 + 1) + 16);
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
#ifdef HL_UNIX
   while (adsl_addrinfo_w3) {
     iml_cmp_len = 0;                       /* length to compare       */
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv4 == FALSE)) {  /* IPV4 not supported */
           break;
         }
         iml_cmp_pos = offsetof( struct sockaddr_in, sin_addr );  /* position to compare */
         iml_cmp_len = 4;                   /* length to compare       */
         break;
       case AF_INET6:                       /* IPV6                    */
         if (   adsp_biineta1
             && (adsp_biineta1->boc_bind_needed)
             && (adsp_biineta1->boc_ipv6 == FALSE)) {  /* IPV6 not supported */
           break;
         }
         iml_cmp_pos = offsetof( struct sockaddr_in6, sin6_addr );  /* position to compare */
         iml_cmp_len = 16;                  /* length to compare       */
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     while (iml_cmp_len) {                  /* we want output          */
       adsl_addrinfo_w4 = adsl_addrinfo_w2;  /* get first INETA again  */
       while (adsl_addrinfo_w4 != adsl_addrinfo_w3) {
         if (   (adsl_addrinfo_w4->ai_family == adsl_addrinfo_w3->ai_family)
             && (!memcmp( (char *) (adsl_addrinfo_w4->ai_addr) + iml_cmp_pos,
                          (char *) (adsl_addrinfo_w3->ai_addr) + iml_cmp_pos,
                          iml_cmp_len ))) {
           iml_cmp_len = 0;                 /* we do not want output   */
           break;
         }
         adsl_addrinfo_w4 = adsl_addrinfo_w4->ai_next;  /* get next in chain */
       }
       if (iml_cmp_len == 0) break;         /* we do not want output   */
       adsl_ineta_s_w1->usc_family = adsl_addrinfo_w3->ai_family;  /* family IPV4 / IPV6 */
       adsl_ineta_s_w1->usc_length = iml_cmp_len;  /* length of following address */
       memcpy( adsl_ineta_s_w1 + 1,
               (char *) (adsl_addrinfo_w3->ai_addr) + iml_cmp_pos,
               iml_cmp_len );
#ifdef TRACEHL1
       printf( "xslnetw1-%05d-T m_get_target_ineta() adsl_ineta_s_w1=%p iml_cmp_pos=%d iml_cmp_len=%d.\n",
               __LINE__, adsl_ineta_s_w1, iml_cmp_pos, iml_cmp_len );
       printf( "xslnetw1-%05d-T m_get_target_ineta() INETA=0X%08X.\n",
               __LINE__, *((unsigned int *) (adsl_ineta_s_w1 + 1)) );
#endif
       adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) ((char *) (adsl_ineta_s_w1 + 1) + iml_cmp_len);
       break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
   m_ip_freeaddrinfo( adsl_addrinfo_w2 );   /* free addresses again    */
   return adsl_target_ineta_1_w1;           /* return structure build  */
} /* end m_get_target_ineta()                                          */

/** generate structure INETA for listen                                */
extern "C" struct dsd_listen_ineta_1 * m_get_listen_ineta( void *ap_ineta, int imp_len_ineta, ied_charset iep_cs_ineta ) {
   int        iml_rc;                       /* return code             */
   int        iml_count;                    /* count entries           */
   int        iml_lenmem;                   /* memory needed           */
   char       *achl_ineta;                  /* address of INETA        */
#ifdef HL_UNIX
   const char       *achl_service;                /* service name for cheeting */
#endif
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
   struct dsd_listen_ineta_1 *adsl_listen_ineta_1_w1;  /* definition INETA listen */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA listen     */
   char       chrl_work_ineta[ D_MAXLEN_INETA ];

#ifndef B080529
   achl_ineta = NULL;
#endif
   if ((ap_ineta) && (imp_len_ineta)) {
     if (*((char *) ap_ineta)) {
       achl_ineta = (char *) ap_ineta;
     }
     if (   (iep_cs_ineta != ied_chs_idna_1)
         || (imp_len_ineta > 0)) {
       iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                             ap_ineta, imp_len_ineta, iep_cs_ineta );
#ifdef B120910
       if (iml_rc <= 0) return NULL;        /* string not valid        */
#else
       if (iml_rc < 0) return NULL;         /* string not valid        */
#endif
       achl_ineta = chrl_work_ineta;
     }
#ifdef B080529
   } else {                                 /* no INETA passed - take ANY */
     chrl_work_ineta[0] = 0;                /* zero length string      */
     achl_ineta = chrl_work_ineta;
#endif
   }
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_flags    = AI_PASSIVE;
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
#ifdef XYZ_080529
   dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
   dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
#endif
#ifdef HL_UNIX
   dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
   dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
   achl_service = NULL;                     /* service name for cheeting */
   if (achl_ineta == NULL) {                /* only one NULL allowed   */
     achl_service = "http";
   }
#endif
   adsl_addrinfo_w2 = NULL;
#ifndef HL_UNIX
#ifdef B080529
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
#else
   iml_rc = m_ip_getaddrinfo( achl_ineta, "", &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
#endif
#else
   iml_rc = m_ip_getaddrinfo( achl_ineta, achl_service, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
#endif
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d.",
                   __LINE__, iml_rc, D_TCP_ERROR );
     return NULL;                           /* return error            */
   }
#ifdef TRACEHL1
   printf( "xslnetw1-%05d-T AF_INET=%d AF_INET6=%d\n",
           __LINE__, AF_INET, AF_INET6 );
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
   while (adsl_addrinfo_w3) {
     printf( "xslnetw1-%05d-T getaddrinfo ai_family=%d\n",
             __LINE__, adsl_addrinfo_w3->ai_family );
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:
         printf( "xslnetw1-%05d-T getaddrinfo &adsl_addrinfo_w3->ai_addr=0X%p &(((struct sockaddr_in *) &adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr)=0X%p\n",
                 __LINE__,
                 &adsl_addrinfo_w3->ai_addr,
                 &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) );
         printf( "xslnetw1-%05d-T getaddrinfo ai_family AF_INET INETA=%d.%d.%d.%d\n",
                 __LINE__,
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 0),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 1),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 2),
                 *((unsigned char *) &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr) + 3) );
         break;
       default:
         printf( "xslnetw1-%05d-T getaddrinfo ai_family undefined\n",
                 __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
#endif
   iml_count = 0;                           /* clear count entries     */
   iml_lenmem = sizeof(struct dsd_listen_ineta_1);  /* set memory needed initial */
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
   while (adsl_addrinfo_w3) {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         iml_count++;                       /* count entry             */
         iml_lenmem += sizeof(struct dsd_ineta_single_1) + 4;  /* add length memory needed */
         break;
       case AF_INET6:                       /* IPV6                    */
         iml_count++;                       /* count entry             */
         iml_lenmem += sizeof(struct dsd_ineta_single_1) + 16;  /* add length memory needed */
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
   if (iml_count == 0) {
     m_ip_freeaddrinfo( adsl_addrinfo_w2 );  /* free addresses again   */
     return NULL;
   }
   adsl_listen_ineta_1_w1 = (struct dsd_listen_ineta_1 *) malloc( iml_lenmem );
   adsl_listen_ineta_1_w1->imc_no_ineta = iml_count;  /* number of INETA */
   adsl_listen_ineta_1_w1->imc_len_mem = iml_lenmem;  /* length of memory including this structure */
   adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsl_listen_ineta_1_w1 + 1);
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain of addresses  */
   while (adsl_addrinfo_w3) {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         adsl_ineta_s_w1->usc_family = AF_INET;  /* family IPV4        */
         adsl_ineta_s_w1->usc_length = 4;   /* length of following address */
         memcpy( adsl_ineta_s_w1 + 1,
                 &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr),
                 4 );
         adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) ((char *) (adsl_ineta_s_w1 + 1) + 4);
         break;
       case AF_INET6:                       /* IPV6                    */
         adsl_ineta_s_w1->usc_family = AF_INET6;  /* family IPV6       */
         adsl_ineta_s_w1->usc_length = 16;  /* length of following address */
         memcpy( adsl_ineta_s_w1 + 1,
                 &(((struct sockaddr_in6 *) adsl_addrinfo_w3->ai_addr)->sin6_addr),
                 16 );
         adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) ((char *) (adsl_ineta_s_w1 + 1) + 16);
         break;
       default:
         m_hl1_printf( "xslnetw1-%05d-W getaddrinfo ai_family undefined",
                       __LINE__ );
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   }
   m_ip_freeaddrinfo( adsl_addrinfo_w2 );   /* free addresses again    */
   return adsl_listen_ineta_1_w1;           /* return structure build  */
} /* end m_get_listen_ineta()                                          */

/** return a single INETA                                              */
extern "C" BOOL m_get_single_ineta( int *aimp_error, struct dsd_ineta_single_ret *adsp_ineta_sret,
                                    void *ap_ineta, int imp_len_ineta, ied_charset iep_cs_ineta ) {
   int        iml_rc;                       /* return code             */
   char       *achl_ineta;                  /* address of INETA        */
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
   char       chrl_work_ineta[ D_MAXLEN_INETA ];

   if (aimp_error) *aimp_error = 0;
   memset( adsp_ineta_sret, 0, sizeof(struct dsd_ineta_single_ret) );
   achl_ineta = (char *) ap_ineta;
   if (   (iep_cs_ineta != ied_chs_idna_1)
       || (imp_len_ineta >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                           ap_ineta, imp_len_ineta, iep_cs_ineta );
     if (iml_rc <= 0) {                     /* string not valid        */
       if (aimp_error) *aimp_error = -2;
       return FALSE;
     }
     achl_ineta = chrl_work_ineta;
   }
   if (*achl_ineta == 0) {                  /* string is empty         */
     if (aimp_error) *aimp_error = -1;
     return FALSE;                          /* report error            */
   }
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
   adsl_addrinfo_w2 = NULL;
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     if (aimp_error) *aimp_error = D_TCP_ERROR;
     return FALSE;                          /* report error            */
   }
   if (adsl_addrinfo_w2 == NULL) {          /* no INETA returned       */
     if (aimp_error) *aimp_error = -2;
     return FALSE;                          /* report error            */
   }
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain               */
   do {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         memcpy( adsp_ineta_sret->chrc_ineta,
                 &(((struct sockaddr_in *) adsl_addrinfo_w3->ai_addr)->sin_addr.s_addr),
                 4 );
         adsp_ineta_sret->usc_length = 4;   /* set length INETA        */
         adsp_ineta_sret->usc_family = AF_INET;  /* set family INETA   */
         break;
       case AF_INET6:                       /* IPV6                    */
         memcpy( adsp_ineta_sret->chrc_ineta,
                 &(((struct sockaddr_in6 *) adsl_addrinfo_w3->ai_addr)->sin6_addr),
                 16 );
         adsp_ineta_sret->usc_length = 16;  /* set length INETA        */
         adsp_ineta_sret->usc_family = AF_INET6;  /* set family INETA  */
         break;
     }
     if (adsp_ineta_sret->usc_length) break;
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   } while (adsl_addrinfo_w3);
   m_ip_freeaddrinfo( adsl_addrinfo_w2 );   /* free addresses again    */
   if (adsp_ineta_sret->usc_length == 0) {  /* not INETA found         */
     if (aimp_error) *aimp_error = -3;
     return FALSE;                          /* report error            */
   }
   return TRUE;                             /* all done, no error      */
} /* end m_get_single_ineta()                                          */

/** build structures for bind used with connect                        */
extern "C" int m_build_bind_ineta( struct dsd_bind_ineta_1 *adsp_biineta1,
                                   void *ap_ineta, int imp_len_ineta, ied_charset iep_cs_ineta ) {
   int        iml_rc;                       /* return code             */
   char       *achl_ineta;                  /* address of INETA        */
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
   char       chrl_work_ineta[ D_MAXLEN_INETA ];

   memset( adsp_biineta1, 0, sizeof(struct dsd_bind_ineta_1) );
   if (ap_ineta == NULL) return 0;          /* no bind necessary       */
   achl_ineta = (char *) ap_ineta;
   if (   (iep_cs_ineta != ied_chs_idna_1)
       || (imp_len_ineta >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                           ap_ineta, imp_len_ineta, iep_cs_ineta );
     if (iml_rc < 0) return -1;             /* string not valid        */
     achl_ineta = chrl_work_ineta;
   }
   if (*achl_ineta == 0) return 0;          /* no bind necessary       */
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
   adsl_addrinfo_w2 = NULL;
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     return D_TCP_ERROR;                    /* return error            */
   }
   if (adsl_addrinfo_w2 == NULL) {          /* no INETA returned       */
     return -1;                             /* return error            */
   }
   adsl_addrinfo_w3 = adsl_addrinfo_w2;     /* get chain               */
   do {
     switch (adsl_addrinfo_w3->ai_family) {
       case AF_INET:                        /* IPV4                    */
         if (adsp_biineta1->boc_ipv4) break;  /* IPV4 already supported */
         memcpy( &adsp_biineta1->dsc_soai4, adsl_addrinfo_w3->ai_addr, sizeof(struct sockaddr_in) );
         adsp_biineta1->boc_ipv4 = TRUE;    /* IPV4 supported          */
         break;
       case AF_INET6:                       /* IPV6                    */
         if (adsp_biineta1->boc_ipv6) break;  /* IPV6 already supported */
         memcpy( &adsp_biineta1->dsc_soai6, adsl_addrinfo_w3->ai_addr, sizeof(struct sockaddr_in6) );
         adsp_biineta1->boc_ipv6 = TRUE;    /* IPV6 supported          */
         break;
     }
     adsl_addrinfo_w3 = adsl_addrinfo_w3->ai_next;  /* get next in chain */
   } while (adsl_addrinfo_w3);
   m_ip_freeaddrinfo( adsl_addrinfo_w2 );   /* free addresses again    */
   if (   (adsp_biineta1->boc_ipv4 == FALSE)  /* IPV4 not supported    */
       && (adsp_biineta1->boc_ipv6 == FALSE)) {  /* IPV6 not supported */
     return -2;
   }
   adsp_biineta1->boc_bind_needed = TRUE;   /* flag bind() is needed   */
   return 0;                                /* all done, no error      */
} /* end m_build_bind_ineta()                                          */

/**
   build parameter area for a multihomed UDP target
   it is necessary that the protocols of bind and target match
*/
extern "C" int m_build_udp_param( struct dsd_udp_param_1 *adsp_udp_param_1, char *achp_errmsg,
                                  void *ap_bind, int imp_len_bind, ied_charset iep_cs_bind,
                                  void *ap_target, int imp_len_target, ied_charset iep_cs_target ) {
// int        iml1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   char       *achl_ineta;                  /* address of INETA        */
   struct addrinfo dsl_addrinfo_bind;       /* for bind                */
   struct addrinfo dsl_addrinfo_target;     /* for target              */
   struct addrinfo *adsl_addrinfo_bind_w1;  /* walk thru chain of INETA */
   struct addrinfo *adsl_addrinfo_bind_w2;  /* walk thru chain of INETA */
   struct addrinfo *adsl_addrinfo_target_w1;  /* walk thru chain of INETA */
   struct addrinfo *adsl_addrinfo_target_w2;  /* walk thru chain of INETA */
   char       chrl_work_ineta[ D_MAXLEN_INETA ];

   adsl_addrinfo_bind_w1 = NULL;            /* clear walk thru chain of INETA */
   if (   (ap_bind == NULL)
       || (imp_len_bind == 0)) {
     goto p_udp_ta_20;                      /* process target          */
   }
   achl_ineta = (char *) ap_bind;           /* here is INETA bind      */
   if (   (iep_cs_bind != ied_chs_idna_1)
       || (imp_len_bind >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                           ap_bind, imp_len_bind, iep_cs_bind );
     if (iml_rc == 0) {                     /* string is empty         */
       goto p_udp_ta_20;                    /* process target          */
     }
     if (iml_rc < 0) {                      /* string not valid        */
       sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA bind contains invalid characters",
                __LINE__ );
       return -1;                           /* return error            */
     }
     achl_ineta = chrl_work_ineta;
   }
   if (*achl_ineta == 0) {                  /* no bind necessary       */
     goto p_udp_ta_20;                      /* process target          */
   }
   memset( &dsl_addrinfo_bind, 0, sizeof(dsl_addrinfo_bind) );
   dsl_addrinfo_bind.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
// adsl_addrinfo_w2 = NULL;
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_bind, &adsl_addrinfo_bind_w1 );
   if (iml_rc) {
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA bind getaddrinfo Error %d %d",
              __LINE__, iml_rc, D_TCP_ERROR );
     return -1;                             /* return error            */
   }
   if (adsl_addrinfo_bind_w1 == NULL) {     /* no INETA returned       */
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA bind could not be resolved",
              __LINE__ );
     return -1;                             /* return error            */
   }

   p_udp_ta_20:                             /* process target          */
   adsl_addrinfo_target_w1 = NULL;          /* clear walk thru chain of INETA */
   if (   (ap_target == NULL)
       || (imp_len_target == 0)) {
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target found empty string 1",
              __LINE__ );
     if (adsl_addrinfo_bind_w1) {           /* bind returned INETA     */
       m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
     }
     return -1;                             /* return error            */
   }
   achl_ineta = (char *) ap_target;         /* here is INETA target    */
   if (   (iep_cs_target != ied_chs_idna_1)
       || (imp_len_target >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_ineta, sizeof(chrl_work_ineta), ied_chs_idna_1,
                           ap_target, imp_len_target, iep_cs_target );
     if (iml_rc == 0) {                     /* string is empty         */
       sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target found empty string 2",
                __LINE__ );
       if (adsl_addrinfo_bind_w1) {         /* bind returned INETA     */
         m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
       }
       return -1;                           /* return error            */
     }
     if (iml_rc < 0) {                      /* string not valid        */
       sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target contains invalid characters",
                __LINE__ );
       if (adsl_addrinfo_bind_w1) {         /* bind returned INETA     */
         m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
       }
       return -1;                           /* return error            */
     }
     achl_ineta = chrl_work_ineta;
   }
   if (*achl_ineta == 0) {                  /* no bind necessary       */
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target found empty string 3",
              __LINE__ );
     if (adsl_addrinfo_bind_w1) {           /* bind returned INETA     */
       m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
     }
     return -1;                             /* return error            */
   }
   memset( &dsl_addrinfo_target, 0, sizeof(dsl_addrinfo_target) );
   dsl_addrinfo_target.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
   adsl_addrinfo_target_w1 = NULL;
   iml_rc = m_ip_getaddrinfo( achl_ineta, NULL, &dsl_addrinfo_target, &adsl_addrinfo_target_w1 );
   if (iml_rc) {
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target getaddrinfo Error %d %d",
              __LINE__, iml_rc, D_TCP_ERROR );
     if (adsl_addrinfo_bind_w1) {           /* bind returned INETA     */
       m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
     }
     return -1;                             /* return error            */
   }
   if (adsl_addrinfo_target_w1 == NULL) {   /* no INETA returned       */
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA target could not be resolved",
              __LINE__ );
     if (adsl_addrinfo_bind_w1) {           /* bind returned INETA     */
       m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
     }
     return -1;                             /* return error            */
   }
   adsl_addrinfo_target_w2 = adsl_addrinfo_target_w1;  /* get first target */
   if (adsl_addrinfo_bind_w1 == NULL) {     /* no INETA for bind       */
     goto p_udp_ta_80;                      /* bind and target match   */
   }
   adsl_addrinfo_bind_w2 = adsl_addrinfo_bind_w1;  /* get first INETA of bind */

   p_udp_ta_40:                             /* search bind for target  */
   if (adsl_addrinfo_bind_w2->ai_family != adsl_addrinfo_target_w2->ai_family) {
     adsl_addrinfo_bind_w2 = adsl_addrinfo_bind_w2->ai_next;  /* get next in chain */
     if (adsl_addrinfo_bind_w2) {           /* found more INETA        */
       goto p_udp_ta_40;                    /* search bind for target  */
     }
     adsl_addrinfo_target_w2 = adsl_addrinfo_target_w2->ai_next;  /* get next in chain */
     if (adsl_addrinfo_target_w2) {         /* found more INETA        */
       adsl_addrinfo_bind_w2 = adsl_addrinfo_bind_w1;  /* get first INETA of bind */
       goto p_udp_ta_40;                    /* search bind for target  */
     }
     sprintf( achp_errmsg, "xslnetw1-l%05d-W m_build_udp_param() INETA bind and target have different protocol",
              __LINE__ );
     if (adsl_addrinfo_bind_w1) {           /* bind returned INETA     */
       m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
     }
     m_ip_freeaddrinfo( adsl_addrinfo_target_w1 );  /* free addresses again */
     return -1;                             /* return error            */
   }

   p_udp_ta_80:                             /* bind and target match   */
   memset( adsp_udp_param_1, 0, sizeof(struct dsd_udp_param_1) );
   adsp_udp_param_1->dsc_soa_bind.ss_family = adsl_addrinfo_target_w2->ai_family;
   adsp_udp_param_1->dsc_soa_target.ss_family = adsl_addrinfo_target_w2->ai_family;
   adsp_udp_param_1->imc_len_soa_bind = sizeof(struct sockaddr_in);
   adsp_udp_param_1->imc_len_soa_target = sizeof(struct sockaddr_in);
   if (adsl_addrinfo_target_w2->ai_family == AF_INET6) {
     adsp_udp_param_1->imc_len_soa_bind = sizeof(struct sockaddr_in6);
     adsp_udp_param_1->imc_len_soa_target = sizeof(struct sockaddr_in6);
   }
// iml1 = 4;                                /* length to copy IPV4     */
// if (adsl_addrinfo_target_w2->ai_family == AF_INET6) {
//   iml1 = 16;                             /* length to copy IPV6     */
// }
   if (adsl_addrinfo_bind_w1) {             /* bind returned INETA     */
     memcpy( &adsp_udp_param_1->dsc_soa_bind,
             adsl_addrinfo_bind_w2->ai_addr,
             adsl_addrinfo_target_w2->ai_addrlen );
   }
   memcpy( &adsp_udp_param_1->dsc_soa_target,
           adsl_addrinfo_target_w2->ai_addr,
           adsl_addrinfo_target_w2->ai_addrlen );
   if (adsl_addrinfo_bind_w1) {             /* bind returned INETA     */
     m_ip_freeaddrinfo( adsl_addrinfo_bind_w1 );  /* free addresses again */
   }
   m_ip_freeaddrinfo( adsl_addrinfo_target_w1 );  /* free addresses again */
   return 0;
} /* end m_build_udp_param()                                           */

/** retrieve integer port number from string                           */
extern "C" int m_get_port_no( void *ap_port, int imp_len_port, ied_charset iep_cs_port ) {
   int        iml_rc;                       /* return code             */
#ifdef HL_SOLARIS
   char       *achl_w1;                     /* working variable        */
#endif
   char       *achl_port;                   /* address of port         */
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   char       chrl_work_port[ D_MAXLEN_INETA ];

   if (ap_port == NULL) return -1;          /* no port given           */
   achl_port = (char *) ap_port;
   if (   (iep_cs_port != D_CHARSET_IP)
       || (imp_len_port >= 0)) {
     iml_rc = m_cpy_vx_vx( chrl_work_port, sizeof(chrl_work_port), D_CHARSET_IP,
                           ap_port, imp_len_port, iep_cs_port );
     if (iml_rc <= 0) return -1;            /* string not valid        */
     achl_port = chrl_work_port;
   }
   if (*achl_port == 0) return -1;          /* no port given           */
#ifdef HL_SOLARIS
   /* check if port numeric                                            */
   achl_w1 = achl_port;                     /* beginning of port       */
   iml_rc = 0;                              /* clear number            */
   while (TRUE) {                           /* loop to check port numeric */
     if ((*achl_w1 < '0') || (*achl_w1 > '9')) break;
     iml_rc *= 10;                          /* shift old value         */
     iml_rc += *achl_w1 - '0';
     achl_w1++;                             /* after this digit        */
     if (*achl_w1 == 0) return iml_rc;      /* numeric port given      */
   }
#endif
   memset( &dsl_addrinfo_w1, 0, sizeof(dsl_addrinfo_w1) );
   dsl_addrinfo_w1.ai_family   = AF_UNSPEC;
// dsl_addrinfo_w1.ai_socktype = SOCK_STREAM;
// dsl_addrinfo_w1.ai_protocol = IPPROTO_TCP;
   adsl_addrinfo_w2 = NULL;
   iml_rc = m_ip_getaddrinfo( NULL, achl_port, &dsl_addrinfo_w1, &adsl_addrinfo_w2 );
   if (iml_rc) {
     m_hl1_printf( "xslnetw1-%05d-E getaddrinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     return -1;                             /* return error            */
   }
   if (adsl_addrinfo_w2 == NULL) {          /* no INETA returned       */
     return -1;                             /* return error            */
   }
   if (adsl_addrinfo_w2->ai_addr == NULL) {  /* no INETA returned      */
     m_ip_freeaddrinfo( adsl_addrinfo_w2 );  /* free addresses again   */
     return -1;                             /* return error            */
   }
   iml_rc = htons( ((struct sockaddr_in *) (adsl_addrinfo_w2->ai_addr))->sin_port );
   m_ip_freeaddrinfo( adsl_addrinfo_w2 );   /* free addresses again    */
   return iml_rc;
} /* end m_get_port_no()                                               */

/**
   fill structure sockaddr for next connect()
*/
extern "C" void m_set_connect_p1( struct sockaddr_storage *adsp_soa, socklen_t *aimp_len_soa,
                                  struct dsd_target_ineta_1 *adsp_target_ineta_1, int imp_no_member ) {
   int        iml_count;                    /* count entries           */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */

   iml_count = 0;                           /* clear count entries     */
   adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsp_target_ineta_1 + 1);
   while (iml_count < imp_no_member) {      /* overread members before */
     adsl_ineta_s_w1
       = (struct dsd_ineta_single_1 *)
           ((char *) (adsl_ineta_s_w1 + 1) + adsl_ineta_s_w1->usc_length);
     iml_count++;                           /* count entry             */
   }
   memset( adsp_soa, 0, sizeof(struct sockaddr_storage) );
   ((struct sockaddr *) adsp_soa)->sa_family = adsl_ineta_s_w1->usc_family;
   switch (adsl_ineta_s_w1->usc_family) {
     case AF_INET:
       *((UNSIG_MED *) &(((struct sockaddr_in *) adsp_soa)->sin_addr))
         = *((UNSIG_MED *) (adsl_ineta_s_w1 + 1));
       *aimp_len_soa = sizeof(struct sockaddr_in);
       break;
     case AF_INET6:
       memcpy( &((struct sockaddr_in6 *) adsp_soa)->sin6_addr,
               adsl_ineta_s_w1 + 1,
               16 );
       *aimp_len_soa = sizeof(struct sockaddr_in6);
       break;
   }
} /* end m_set_connect_p1()                                            */

/**
   compare INETA of sockaddr structured,
   family and INETA have to be identical,
   the port may differ
*/
extern "C" BOOL m_cmp_ineta_1( struct sockaddr *adsp_soa_p1, struct sockaddr *adsp_soa_p2 ) {
   int        iml_len_cmp;                  /* length to compare       */
   int        iml_disp_cmp;                 /* displacement to compare */

   if (adsp_soa_p1->sa_family != adsp_soa_p2->sa_family) {
     return FALSE;                          /* family different        */
   }
   iml_len_cmp = 4;                         /* length to compare IPV4  */
   iml_disp_cmp = offsetof( struct sockaddr_in, sin_addr );  /* displacement to compare IPV4 */
   if (adsp_soa_p1->sa_family == AF_INET6) {
     iml_len_cmp = 16;                      /* length to compare IPV6  */
     iml_disp_cmp = offsetof( struct sockaddr_in6, sin6_addr );  /* displacement to compare IPV4 */
   }
   return !memcmp( (char *) adsp_soa_p1 + iml_disp_cmp,
                   (char *) adsp_soa_p2 + iml_disp_cmp,
                   iml_len_cmp );
} /* end m_cmp_ineta_1()                                               */

/** add value arithmetic to INETA                                      */
extern "C" void m_ineta_op_add( char *achp_ineta, int imp_len_ineta, int imp_op ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */

   iml1 = imp_op;                           /* get operand             */
   achl1 = achp_ineta + imp_len_ineta;      /* start at end of ineta   */
   do {
     achl1--;                               /* byte in INETA before    */
     iml1 += *((unsigned char *) achl1);    /* add old value           */
     *((unsigned char *) achl1) = iml1;     /* store new byte          */
     iml1 >>= 8;                            /* remove bits             */
     if (iml1 == 0) return;                 /* end of operation        */
   } while (achl1 > achp_ineta);
   return;
} /* end m_ineta_op_add()                                              */

/** increment arithmetic INETA                                         */
extern "C" void m_ineta_op_inc( char *achp_ineta, int imp_len_ineta ) {
   char       *achl1;                       /* working variable        */

   achl1 = achp_ineta + imp_len_ineta;      /* start at end of ineta   */
   do {
     achl1--;                               /* byte in INETA before    */
     (*((unsigned char *) achl1))++;        /* increment byte          */
     if (*((unsigned char *) achl1) != 0) return;  /* no overflow      */
   } while (achl1 > achp_ineta);
   return;
} /* end m_ineta_op_inc()                                              */

/** decrement arithmetic INETA                                         */
extern "C" void m_ineta_op_dec( char *achp_ineta, int imp_len_ineta ) {
   char       *achl1;                       /* working variable        */

   achl1 = achp_ineta + imp_len_ineta;      /* start at end of ineta   */
   do {
     achl1--;                               /* byte in INETA before    */
     (*((unsigned char *) achl1))--;        /* decrement byte          */
     if (*((unsigned char *) achl1) != 0XFF) return;  /* no overflow   */
   } while (achl1 > achp_ineta);
   return;
} /* end m_ineta_op_dec()                                              */

/** compute arithmetic difference between two INETAs                   */
extern "C" int m_ineta_op_diff( char *achp_ineta_p1,  char *achp_ineta_p2, int imp_len_ineta ) {
   int        iml1;                         /* working variable        */
   char       *achl1, *achl2, *achl3;       /* working variables       */

   achl1 = achp_ineta_p1;
   achl2 = achp_ineta_p2;
   achl3 = achp_ineta_p1 + imp_len_ineta;
   iml1 = 0;
   do {
     if (iml1 >= 0X10000) return -1;
     iml1 <<= 8;
     iml1 += *((unsigned char *) achl1);
     iml1 -= *((unsigned char *) achl2);
     achl1++;
     achl2++;
   } while (achl1 < achl3);
   return iml1;
} /* end m_ineta_op_diff()                                             */
