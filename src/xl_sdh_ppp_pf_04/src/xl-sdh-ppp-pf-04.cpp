#define NEW_WSP_1102
//#define TRACEHL1
//#define TRACEHL_DNS
//#define TRACEHL_090905
//#define DEBUG_101027_01
//#define DEBUG_101028_01
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-sdh-ppp-pf-04                                    |*/
/*| -------------                                                     |*/
/*|  DLL / Library for HOB WebSecureProxy                             |*/
/*|    Server-Data-Hook                                               |*/
/*|  PPP Packet-Filter 04 with crosswise NAT                          |*/
/*|  KB 23.03.09                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC                                                 |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
   when data from client:
     first crosswise NAT
     second normal NAT
   when data from server:
     first normal NAT
     second crosswise NAT
*/

#ifdef TRACEHL_DNS
#ifndef TRACEHL_TIME
#define TRACEHL_TIME
#endif
#endif

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

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef HL_UNIX
#include <conio.h>
#include <windows.h>
#ifdef TRACEHL_TIME
#include <sys/timeb.h>
#endif
#else
#include <netinet/in.h>
#ifdef TRACEHL_TIME
#include <sys/time.h>
#endif
#include "hob-hunix01.h"
#endif
//#include "hob-xsclib01.h"
#include <hob-xslunic1.h>
//MJ #include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/
#ifdef USE_OLD_XERCES // MJ 28.04.10
    #include <xercesc/util/PlatformUtils.hpp>
    #include <xercesc/parsers/AbstractDOMParser.hpp>
    #include <xercesc/dom/DOMImplementation.hpp>
    #include <xercesc/dom/DOMImplementationLS.hpp>
    #include <xercesc/dom/DOMImplementationRegistry.hpp>
    #include <xercesc/dom/DOMBuilder.hpp>
    #include <xercesc/dom/DOMException.hpp>
    #include <xercesc/dom/DOMDocument.hpp>
    #include <xercesc/dom/DOMNodeList.hpp>
    #include <xercesc/dom/DOMError.hpp>
    #include <xercesc/dom/DOMLocator.hpp>
#else
    #ifdef HL_HPUX
        #include <iostream>
    #endif
    #include <xercesc/dom/impl/DOMElementImpl.hpp>
    #include <xercesc/dom/DOMNode.hpp>
#endif
//MJ #ifndef HL_UNIX
#include "IBIPGW08-X1.hpp"
//MJ #else
//MJ #include "NBIPGW08-X1.hpp"
//MJ #endif
//#include <fstream.h>

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef OLD01
#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#endif
#endif

#define MAX_DNS_INETA          32           /* maximum number of INETA in DNS response */
#define MAX_DNS_QUEUED         8            /* maximum number of DNS responses queued */

#define MAX_LEN_NHASN          4            /* maximum length NHASN length */
#define D_POS_IPH_DCHS         10           /* position checksum in IP header */
#define D_LEN_UDP_HEADER       8            /* length of UDP header    */
#define D_EXT_SIP              64           /* SIP packet to be extended */
#define D_LEN_RESP_START       128          /* size maximum of RESPONSE-START */

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */
#define CHAR_TELNET_ESC        0XFF         /* telnet escape           */

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

struct dsd_clib1_conf {                     /* configuration data      */
   int        imc_nat_e1;                   /* number of entries NAT   */
   int        imc_len_dns_resp;             /* length of DNS responses */
   BOOL       boc_cross_nat;                /* use crosswise NAT       */
   BOOL       boc_alg_sip;                  /* use ALG for SIP VoIP protocol */
   UNSIG_MED  umc_cnat_ineta_real;          /* real INETA              */
   UNSIG_MED  umc_cnat_ineta_translated;    /* translated INETA        */
   UNSIG_MED  umc_cnat_mask_and_1;          /* mask for AND            */
   UNSIG_MED  umc_cnat_mask_and_2;          /* mask for AND            */
};

struct dsd_nat_entry_1 {                    /* structure NAT entry     */
   UNSIG_MED  umc_ineta_real;               /* real INETA              */
   UNSIG_MED  umc_ineta_translated;         /* translated INETA        */
   UNSIG_MED  umc_mask_and_1;               /* mask for AND            */
   UNSIG_MED  umc_mask_and_2;               /* mask for AND            */
   int        imc_prefix;                   /* prefix                  */
};

struct dsd_dns_resp_1 {                     /* structure DNS response  */
   int        imc_len_stor;                 /* storage reserved        */
   int        imc_len_entry;                /* length of entry         */
   int        imc_len_dns_n;                /* length DNS name         */
};

struct dsd_query_dns_resp_1 {               /* structure query DNS response */
   UNSIG_MED  umc_ineta_source;             /* INETA source            */
   UNSIG_MED  umc_ineta_dest;               /* INETA destination       */
   char       chrs_port_dest[2];            /* destination port        */
   char       chrs_id[2];                   /* transaction ID          */
   struct dsd_dns_resp_1 *adsc_dnsr1;       /* structure DNS response  */
};

struct dsd_clib1_contr_1 {                  /* structure session control */
   BOOL       boc_client_header;            /* client header has been received */
   BOOL       boc_cross_nat;                /* use crosswise NAT       */
   int        imc_no_qdnsr1;                /* number of responses queued */
   struct dsd_query_dns_resp_1 dsrc_qdnsr1[ MAX_DNS_QUEUED ];  /* structure query DNS response */
};

static const char * achrs_node_main[] = {
   "NAT-entry",
   "exclude-DNS-name",
   "DNS-ineta",
   "crosswise-NAT",
   "ALG-SIP"
};

static const char * achrs_node_nat[] = {
   "real-ineta",
   "translated-ineta",
   "prefix"
};

static const char * achrs_node_dnsi1[] = {
   "DNS-name",
   "ineta"
};

static const char * achrs_node_cnat[] = {
   "real-network-ineta",
   "translated-network-ineta",
   "prefix"
};

static const unsigned char ucrs_recv_contr_01[] = {
   'S', 'T', 'A', 'R', 'T'
};

static const unsigned char ucrs_recv_contr_02[] = {
   'R', 'E', 'C', 'O', 'N', 'N', 'E', 'C',
   'T'
};

static const unsigned char ucrs_recv_locineta[] = {
   'L', 'O', 'C', 'A', 'L', '-', 'I', 'N',
   'E', 'T', 'A', '='
};

static const unsigned char ucrs_ctrl_ipcp[] = {
   0X80, 0X21
};

/* 1 = digit                                                           */
/* 2 = dot                                                             */
/* 3 = separator                                                       */
/* 4 = character                                                       */
/* 5 = invalid                                                         */
static const unsigned char ucrs_tab_char_sip[ 256 ] = {
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 5, 5,  /* 0X00 till 0X0F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X10 till 0X1F  */
   3, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 5, 2, 5,  /* 0X20 till 0X2F  */
   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 5, 3, 3, 5,  /* 0X30 till 0X3F  */
   3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0X40 till 0X4F  */
   4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5,  /* 0X50 till 0X5F  */
   5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0X60 till 0X6F  */
   4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5,  /* 0X70 till 0X7F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X80 till 0X8F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0X90 till 0X9F  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XA0 till 0XAF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XB0 till 0XBF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XC0 till 0XCF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XD0 till 0XDF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,  /* 0XE0 till 0XEF  */
   5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5   /* 0XF0 till 0XFF  */
};

/* invalid - not found - part 1                                        */
static const unsigned char chrs_dns_r_i_1[] = {
   (unsigned char) 0X85, (unsigned char) 0X83,  /* Response etc.       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* all types of response - part 2                                      */
static const unsigned char chrs_dns_r_a_2[] = {
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
};

/* successful - found - part 1                                         */
static const unsigned char chrs_dns_r_s_1[] = {
   (unsigned char) 0X85, (unsigned char) 0X80,  /* Response etc.       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* successful - found - part 3 - with INETA                            */
static const unsigned char chrs_dns_r_s_3[] = {
   (unsigned char) 0XC0, (unsigned char) 0X0C,  /* DNS name compressed */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type to live        */
   (unsigned char) 0X51, (unsigned char) 0X80,  /* 1 Day               */
   (unsigned char) 0X00, (unsigned char) 0X04,  /* Data length         */
};

/* DNS query part one                                                  */
static const unsigned char chrs_dns_query_1[] = {
   (unsigned char) 0X01, (unsigned char) 0X00,  /* Flags standard query */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* QDCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ANCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* NSCOUNT             */
   (unsigned char) 0X00, (unsigned char) 0X00,  /* ARCOUNT             */
};

/* DNS query part two                                                  */
static const unsigned char chrs_dns_query_2[] = {
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Type A 0001         */
   (unsigned char) 0X00, (unsigned char) 0X01,  /* Class IN 0001       */
};

static const unsigned char chrs_port_dns[] = {
   (unsigned char) 0,
   (unsigned char) 53
};

static const unsigned char chrs_port_sip[] = {  /* port 5060           */
   (unsigned char) 0X13,
   (unsigned char) 0XC4
};

static const unsigned char ucrs_sip_cont_len[] = {  /* SIP Content-Length */
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 't', 'e', 'n', 't', '-',
   'L', 'e', 'n', 'g', 't', 'h', ':'
};

static int m_get_dns_name( char *, int, HL_WCHAR * );
static BOOL m_check_dns_n_double( char *, int, struct dsd_clib1_conf * );
static int m_get_ineta_w( UNSIG_MED *, HL_WCHAR * );
static int m_get_ineta_a( UNSIG_MED *, char *, char * );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
static int m_get_date_time( char *achp_buff );
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *achp_buff, int implength );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );
#ifdef TRACEHL_TIME
static HL_LONGLONG m_get_epoch_ms( void );
#endif

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/* subroutine to process the configuration data                        */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_alg_sip_conf;             /* use ALG for SIP VoIP protocol configured */
   int        iml1, iml2;                   /* working variables       */
   int        iml_cmp;                      /* compare values          */
   int        iml_val;                      /* value in array          */
   int        iml_no_ineta;                 /* count INETA             */
   int        iml_len_dns_n;                /* length DNS name         */
   int        iml_cnat_prefix;              /* cnat prefix             */
// UNSIG_MED  uml_ineta_w1;                 /* working-variable INETA  */
   UNSIG_MED  *auml_w1;                     /* working-variable        */
   char       *achl_stor_new;               /* new storage             */
   char       *achl_stor_old;               /* old storage             */
   char       *achl_w1;                     /* working-variable        */
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
   DOMNode    *adsl_node_3;                 /* node for navigation     */
   HL_WCHAR   *awcl1;                       /* working variable        */
   HL_WCHAR   *awcl_name;                   /* name of Node            */
   HL_WCHAR   *awcl_value;                  /* value of Node           */
   HL_WCHAR   *awcl_dns_name;               /* save DNS name           */
   struct dsd_nat_entry_1 *adsl_nat_entry_1_w1;  /* structure NAT entry */
   struct dsd_dns_resp_1 *adsl_dnsr1_new;   /* new DNS response        */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_nat_entry_1 dsl_nat_entry_1;  /* structure NAT entry     */
   struct dsd_clib1_conf dsl_clco;          /* configuration data      */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */
   char       chrl_dns_name[256];           /* for DNS name            */
   UNSIG_MED  umrl_ineta[ MAX_DNS_INETA ];  /* for INETAs              */

#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-04-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p\n",
           __LINE__, adsp_hlcldomf );
#endif
   dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-I V1.3 " __DATE__ " m_hlclib_conf() called",
                 __LINE__ );
#ifdef TRACEHL_090905
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T sizeof(struct dsd_hl_clib_1)=%d offsetof( ..., boc_callrevdir )=%d TRUE=%d.",
                 __LINE__, sizeof(struct dsd_hl_clib_1), offsetof( struct dsd_hl_clib_1, boc_callrevdir ), TRUE );
#endif
#ifdef NOT_YET_080308_01
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  adsp_hlcldomf->aac_conf,
                                  sizeof(struct dsd_clib1_4_1) );
   if (bol1 == FALSE) {
     return FALSE;
   }
   memset( *adsp_hlcldomf->aac_conf, 0, sizeof(struct dsd_clib1_4_1) );
   ((struct dsd_clib1_4_1 *) *adsp_hlcldomf->aac_conf)->imc_flags_1
     = adsp_hlcldomf->imc_flags_1;
#endif

   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return FALSE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }

   memset( &dsl_clco, 0, sizeof(struct dsd_clib1_conf) );  /* configuration data */
   achl_stor_new = NULL;                    /* new storage             */
   bol_alg_sip_conf = FALSE;                /* use ALG for SIP VoIP protocol configured */

   pdomc20:                                 /* process DOM node        */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc80;                          /* get next sibling        */
   }
   awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-04-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl1 );
#endif
   iml_val = sizeof(achrs_node_main) / sizeof(achrs_node_main[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl1, (char *) achrs_node_main[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* keyword not found       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error first element name \"%(ux)s\" undefined - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   switch (iml_val) {                       /* check keyword           */
     case 2:
       goto p_excl_dns_00;                  /* exclude DNS name        */
     case 3:
       goto p_dns_ineta_00;                 /* retrieve DNS-ineta      */
     case 4:
       goto p_cnat_00;                      /* crosswise NAT           */
     case 5:
       goto p_alg_sip_00;                   /* ALG-SIP                 */
   }
   memset( &dsl_nat_entry_1, 0, sizeof(struct dsd_nat_entry_1) );  /* structure NAT entry */
   dsl_nat_entry_1.imc_prefix = -1;         /* prefix not yet set      */

   pdomc40:                                 /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-04-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_nat) / sizeof(achrs_node_nat[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_nat[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 3) goto p_dom_nat_ineta_00;  /* retrieve INETA       */
   if (dsl_nat_entry_1.imc_prefix >= 0) {   /* prefix already set      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" double - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   iml1 = m_get_wc_number( awcl_value );
   if (iml1 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" not numeric - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   if ((iml1 <= 0) || (iml1 > 32)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" not in range 1 ... 32 - value \"%(ux)s\" / %d - ignored",
                   __LINE__, awcl_name, awcl_value, iml1 );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   dsl_nat_entry_1.imc_prefix = iml1;       /* set prefix              */
   goto pdomc56;                            /* get next sibling stage 2 */

   p_dom_nat_ineta_00:                      /* retrieve INETA          */
   auml_w1 = &dsl_nat_entry_1.umc_ineta_real;  /* real INETA           */
   if (iml_val == 2) {
     auml_w1 = &dsl_nat_entry_1.umc_ineta_translated;  /* translated INETA */
   }
   if (*auml_w1 != 0) {                     /* already set             */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" double - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   iml1 = 0;                                /* first digit             */
   awcl1 = awcl_value;                      /* get value               */

   p_dom_nat_ineta_20:                      /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((*awcl1 >= '0') && (*awcl1 <= '9')) {
     iml2 *= 10;                            /* shift old value         */
     iml2 += *awcl1 - '0';
     if (iml2 >= 256) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" INETA digits too high - value \"%(ux)s\" - ignored",
                     __LINE__, awcl_name, awcl_value );
       goto pdomc56;                        /* get next sibling stage 2 */
     }
     awcl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) {                     /* no digit found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" INETA invalid, no digit found - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (*awcl1 == 0) goto p_dom_nat_ineta_40;  /* INETA decoded       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" INETA invalid, too many parts - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   if (*awcl1 == '.') {                     /* separator found         */
     awcl1++;                               /* next character          */
     goto p_dom_nat_ineta_20;               /* retrieve number of INETA */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" INETA invalid, contains invalid character - value \"%(ux)s\" - ignored",
                 __LINE__, awcl_name, awcl_value );
   goto pdomc56;                            /* get next sibling stage 2 */

   p_dom_nat_ineta_40:                      /* INETA decoded           */
   if (*((UNSIG_MED *) chrl_ineta_w1) == 0) {  /* invalid value        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"NAT-entry\" \"%(ux)s\" INETA invalid, 0.0.0.0 not allowed - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc56;                          /* get next sibling stage 2 */
   }
   *auml_w1 = *((UNSIG_MED *) chrl_ineta_w1);  /* set decoded INETA    */

   pdomc56:                                 /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto pdomc40;           /* process DOM node stage 2 */
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_nat_entry_1, sizeof(dsl_nat_entry_1) );
#endif
   if (dsl_nat_entry_1.umc_ineta_real == 0) {  /* no real INETA        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" \"real-ineta\" missing - NAT-entry ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (dsl_nat_entry_1.umc_ineta_translated == 0) {  /* no translated INETA */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" \"translated-ineta\" missing - NAT-entry ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_nat_entry_1.umc_mask_and_1 = 0XFFFFFFFF;
   if ((dsl_nat_entry_1.imc_prefix >= 0) && (dsl_nat_entry_1.imc_prefix < 32)) {  /* prefix defined   */
     iml1 = -1 << (32 - dsl_nat_entry_1.imc_prefix);
     chrl_ineta_w1[0] = (unsigned char) (iml1 >> 24);
     chrl_ineta_w1[1] = (unsigned char) (iml1 >> 16);
     chrl_ineta_w1[2] = (unsigned char) (iml1 >> 8);
     chrl_ineta_w1[3] = (unsigned char) iml1;
     dsl_nat_entry_1.umc_mask_and_1 = *((UNSIG_MED *) chrl_ineta_w1);  /* set decoded mask / big, little endian */
   }
   dsl_nat_entry_1.umc_mask_and_2 = -1 ^ dsl_nat_entry_1.umc_mask_and_1;
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_nat_entry_1, sizeof(dsl_nat_entry_1) );
#endif
   if ((dsl_nat_entry_1.umc_ineta_real & dsl_nat_entry_1.umc_mask_and_2) != 0) {  /* real INETA invalid */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" \"real-ineta\" invalid, prefix - NAT-entry ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if ((dsl_nat_entry_1.umc_ineta_translated  & dsl_nat_entry_1.umc_mask_and_2) != 0) {  /* translated INETA invalid */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" \"translated-ineta\" invalid, prefix - NAT-entry ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (dsl_nat_entry_1.umc_ineta_real == dsl_nat_entry_1.umc_ineta_translated) {  /* real equal translated INETA */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" real-ineta equals translated-ineta - NAT-entry ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   /* check if other definitions are overlapped                        */
   if (dsl_clco.imc_nat_e1) {               /* is not first entry      */
     iml1 = 0;
     adsl_nat_entry_1_w1 = (struct dsd_nat_entry_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf));
     do {                                   /* loop over old NAT entries */
       iml1++;                              /* increment index         */
       if ((adsl_nat_entry_1_w1->umc_ineta_real & dsl_nat_entry_1.umc_mask_and_1)
             == (dsl_nat_entry_1.umc_ineta_real & adsl_nat_entry_1_w1->umc_mask_and_1)) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" real-ineta overlaps entry valid as %d - NAT-entry ignored",
                       __LINE__, iml1 );
         goto pdomc80;                      /* DOM node processed - next */
       }
       if ((adsl_nat_entry_1_w1->umc_ineta_translated & dsl_nat_entry_1.umc_mask_and_1)
             == (dsl_nat_entry_1.umc_ineta_translated & adsl_nat_entry_1_w1->umc_mask_and_1)) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"NAT-entry\" translated-ineta overlaps entry valid as %d - NAT-entry ignored",
                       __LINE__, iml1 );
         goto pdomc80;                      /* DOM node processed - next */
       }
       adsl_nat_entry_1_w1++;               /* next NAT entry          */
     } while (iml1 < dsl_clco.imc_nat_e1);
   }
   /* NAT-entry is valid, add to configuration                         */
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + (dsl_clco.imc_nat_e1 + 1) * sizeof(dsd_nat_entry_1)
                                    + dsl_clco.imc_len_dns_resp );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
               + dsl_clco.imc_len_dns_resp );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                      + dsl_clco.imc_len_dns_resp );
   }
   memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf) + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1),
           &dsl_nat_entry_1,
           sizeof(dsd_nat_entry_1) );
   dsl_clco.imc_nat_e1++;                   /* increment defined NAT entry */
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   p_cnat_00:                               /* crosswise NAT           */
   if (dsl_clco.boc_cross_nat) {            /* use crosswise NAT       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" defined double - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_clco.umc_cnat_ineta_real = dsl_clco.umc_cnat_ineta_translated = 0;  /* clear INETAs */
   iml_cnat_prefix = -1;                    /* prefix not yet set      */

   p_cnat_40:                                 /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-04-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_cnat) / sizeof(achrs_node_cnat[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_cnat[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 3) goto p_cnat_44;        /* retrieve INETA          */
   if (iml_cnat_prefix >= 0) {              /* prefix already set      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" double - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   iml1 = m_get_wc_number( awcl_value );
   if (iml1 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" not numeric - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   if ((iml1 <= 0) || (iml1 > 32)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" not in range 1 ... 32 - value \"%(ux)s\" / %d - ignored",
                   __LINE__, awcl_name, awcl_value, iml1 );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   iml_cnat_prefix = iml1;                  /* set prefix              */
   goto p_cnat_56;                          /* get next sibling stage 2 */

   p_cnat_44:                               /* retrieve INETA          */
   auml_w1 = &dsl_clco.umc_cnat_ineta_real;  /* real INETA             */
   if (iml_val == 2) {
     auml_w1 = &dsl_clco.umc_cnat_ineta_translated;  /* translated INETA */
   }
   if (*auml_w1 != 0) {                     /* already set             */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" double - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   iml1 = 0;                                /* first digit             */
   awcl1 = awcl_value;                      /* get value               */

   p_cnat_48:                               /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((*awcl1 >= '0') && (*awcl1 <= '9')) {
     iml2 *= 10;                            /* shift old value         */
     iml2 += *awcl1 - '0';
     if (iml2 >= 256) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" INETA digits too high - value \"%(ux)s\" - ignored",
                     __LINE__, awcl_name, awcl_value );
       goto p_cnat_56;                      /* get next sibling stage 2 */
     }
     awcl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) {                     /* no digit found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" INETA invalid, no digit found - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                          /* get next sibling stage 2 */
   }
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (*awcl1 == 0) goto p_cnat_52;       /* INETA decoded           */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" INETA invalid, too many parts - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   if (*awcl1 == '.') {                     /* separator found         */
     awcl1++;                               /* next character          */
     goto p_cnat_48;                        /* retrieve number of INETA */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" INETA invalid, contains invalid character - value \"%(ux)s\" - ignored",
                 __LINE__, awcl_name, awcl_value );
   goto p_cnat_56;                          /* get next sibling stage 2 */

   p_cnat_52:                               /* INETA decoded           */
   if (*((UNSIG_MED *) chrl_ineta_w1) == 0) {  /* invalid value        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"crosswise-NAT\" \"%(ux)s\" INETA invalid, 0.0.0.0 not allowed - value \"%(ux)s\" - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto p_cnat_56;                        /* get next sibling stage 2 */
   }
   *auml_w1 = *((UNSIG_MED *) chrl_ineta_w1);  /* set decoded INETA    */

   p_cnat_56:                                 /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto p_cnat_40;         /* process DOM node stage 2 */
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_clco, sizeof(dsl_clco) );
#endif
   if (dsl_clco.umc_cnat_ineta_real == 0) {  /* no real INETA          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"crosswise-NAT\" \"real-network-ineta\" missing - crosswise-NAT ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (dsl_clco.umc_cnat_ineta_translated == 0) {  /* no translated INETA */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"crosswise-NAT\" \"translated-network-ineta\" missing - crosswise-NAT ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_clco.umc_cnat_mask_and_1 = 0XFFFFFFFF;
   if ((iml_cnat_prefix >= 0) && (iml_cnat_prefix < 32)) {  /* prefix defined   */
     iml1 = -1 << (32 - iml_cnat_prefix);
     chrl_ineta_w1[0] = (unsigned char) (iml1 >> 24);
     chrl_ineta_w1[1] = (unsigned char) (iml1 >> 16);
     chrl_ineta_w1[2] = (unsigned char) (iml1 >> 8);
     chrl_ineta_w1[3] = (unsigned char) iml1;
     dsl_clco.umc_cnat_mask_and_1 = *((UNSIG_MED *) chrl_ineta_w1);  /* set decoded mask / big, little endian */
   }
   dsl_clco.umc_cnat_mask_and_2 = -1 ^ dsl_clco.umc_cnat_mask_and_1;
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_clco, sizeof(dsl_clco) );
#endif
   if ((dsl_clco.umc_cnat_ineta_real & dsl_clco.umc_cnat_mask_and_2) != 0) {  /* real INETA invalid */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"crosswise-NAT\" \"real-network-ineta\" invalid, prefix - crosswise-NAT ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if ((dsl_clco.umc_cnat_ineta_translated  & dsl_clco.umc_cnat_mask_and_2) != 0) {  /* translated INETA invalid */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"crosswise-NAT\" \"translated-network-ineta\" invalid, prefix - crosswise-NAT ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (dsl_clco.umc_cnat_ineta_real == dsl_clco.umc_cnat_ineta_translated) {  /* real equal translated INETA */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error \"crosswise-NAT\" real-network-ineta equals translated-network-ineta - crosswise-NAT ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   dsl_clco.boc_cross_nat = TRUE;           /* use crosswise NAT       */
   goto pdomc80;                            /* DOM node processed - next */

   p_alg_sip_00:                            /* ALG-SIP                 */
   if (bol_alg_sip_conf) {                  /* use ALG for SIP VoIP protocol configured */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"ALG-SIP\" defined double - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"ALG-SIP\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   while (TRUE) {                           /* pseudo-loop             */
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       dsl_clco.boc_alg_sip = TRUE;         /* use ALG for SIP VoIP protocol */
       break;
     }
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"ALG-SIP\" value neither YES nor NO - \"%(ux)s\" - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   } while (FALSE);
   bol_alg_sip_conf = TRUE;                 /* use ALG for SIP VoIP protocol configured */
   goto pdomc80;                            /* DOM node processed - next */

   p_excl_dns_00:                           /* exclude DNS name        */
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"exclude-DNS-name\" no value found - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   iml_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (iml_len_dns_n < 0) {                 /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"exclude-DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
   bol1 = m_check_dns_n_double( chrl_dns_name, iml_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"exclude-DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
   iml1 = dsl_clco.imc_len_dns_resp;        /* save old length         */
   iml2 = sizeof(chrs_dns_r_i_1) + iml_len_dns_n + sizeof(chrs_dns_r_a_2);
   dsl_clco.imc_len_dns_resp
     += sizeof(struct dsd_dns_resp_1)
          + (iml2 + sizeof(void *) - 1)
            & (0 - sizeof(void *));
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                    + dsl_clco.imc_len_dns_resp );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1) + iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                      + iml1 );
   }
   /* new DNS response                                                 */
   adsl_dnsr1_new
     = (struct dsd_dns_resp_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                    + iml1 );
   adsl_dnsr1_new->imc_len_stor = dsl_clco.imc_len_dns_resp - iml1;  /* storage reserved */
   adsl_dnsr1_new->imc_len_entry = iml2;    /* length of entry         */
   adsl_dnsr1_new->imc_len_dns_n = iml_len_dns_n;  /* length DNS name  */
   achl_w1 = (char *) (adsl_dnsr1_new + 1);
   memcpy( achl_w1, chrs_dns_r_i_1, sizeof(chrs_dns_r_i_1) );
   achl_w1 += sizeof(chrs_dns_r_i_1);
   memcpy( achl_w1, chrl_dns_name, iml_len_dns_n );
   achl_w1 += iml_len_dns_n;
   memcpy( achl_w1, chrs_dns_r_a_2, sizeof(chrs_dns_r_a_2) );
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   p_dns_ineta_00:                          /* retrieve DNS-ineta      */
   iml_no_ineta = 0;                        /* no INETA till now       */
   iml_len_dns_n = 0;                       /* clear length DNS name   */

   p_dns_ineta_20:                          /* process DOM node stage 2 */
   if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xl-sdh-ppp-pf-04-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl_name );
#endif
   iml_val = sizeof(achrs_node_dnsi1) / sizeof(achrs_node_dnsi1[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl_name, (char *) achrs_node_dnsi1[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" child \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_3 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   do {                                     /* search value            */
     if (((int) (long long) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_3 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_3,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_3);
   if (adsl_node_3 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_3, ied_hlcldom_get_node_value );  /* getNodeValue() */
   if (iml_val != 1) goto p_dns_ineta_40;   /* retrieve INETA          */
   /* retrieve DNS-name                                                */
   if (iml_len_dns_n > 0) {                 /* check length DNS name   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" defined double - \"%(ux)s\" ignored",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml_len_dns_n = m_get_dns_name( chrl_dns_name, sizeof(chrl_dns_name), (HL_WCHAR *) awcl_value );
   if (iml_len_dns_n < 0) {                 /* DNS name is not valid   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
   }
   awcl_dns_name = awcl_value;              /* save DNS name           */
   goto p_dns_ineta_60;                     /* get next sibling stage 2 */

   p_dns_ineta_40:                          /* retrieve INETA          */
   if (iml_no_ineta >= MAX_DNS_INETA) {     /* INETA array filled      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" ignored - too many entries",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml1 = m_get_ineta_w( &umrl_ineta[ iml_no_ineta ], (HL_WCHAR *) awcl_value );
   if (iml1 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" invalid - ignored",
                   __LINE__, awcl_value );
     goto p_dns_ineta_60;                   /* get next sibling stage 2 */
   }
   iml1 = 0;                                /* clear index             */
   while (iml1 < iml_no_ineta) {            /* loop over all entries before */
     if (umrl_ineta[ iml1 ] == umrl_ineta[ iml_no_ineta ]) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"ineta\" value \"%(ux)s\" defined double - ignored",
                     __LINE__, awcl_value );
       goto p_dns_ineta_60;                 /* get next sibling stage 2 */
     }
     iml1++;                                /* increment index         */
   }
   iml_no_ineta++;                          /* count INETA             */

   p_dns_ineta_60:                          /* get next sibling stage 2 */
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_2) goto p_dns_ineta_20;    /* process DOM node stage 2 */
   if (iml_no_ineta <= 0) {                 /* no INETA defined        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" no \"ineta\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   if (iml_len_dns_n <= 0) {                /* DNS name is not defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" no \"DNS-name\" defined - ignored",
                   __LINE__ );
     goto pdomc80;                          /* DOM node processed - next */
   }
   bol1 = m_check_dns_n_double( chrl_dns_name, iml_len_dns_n, (struct dsd_clib1_conf *) achl_stor_new );
   if (bol1 == FALSE) {                     /* DNS name already defined */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W Error element \"DNS-ineta\" \"DNS-name\" value \"%(ux)s\" DNS-name already configured before - ignored",
                   __LINE__, awcl_dns_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
   iml1 = dsl_clco.imc_len_dns_resp;        /* save old length         */
   iml2 = sizeof(chrs_dns_r_s_1) + iml_len_dns_n + sizeof(chrs_dns_r_a_2)
            + iml_no_ineta * (sizeof(chrs_dns_r_s_3) + sizeof(UNSIG_MED));
   dsl_clco.imc_len_dns_resp
     += sizeof(struct dsd_dns_resp_1)
          + (iml2 + sizeof(void *) - 1)
            & (0 - sizeof(void *));
   achl_stor_old = achl_stor_new;           /* save storage            */
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &achl_stor_new,
                                  sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                    + dsl_clco.imc_len_dns_resp );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   if (achl_stor_old) {                     /* copy old values         */
     memcpy( achl_stor_new + sizeof(struct dsd_clib1_conf),
             achl_stor_old + sizeof(struct dsd_clib1_conf),
             dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1) + iml1 );
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &achl_stor_old,
                                    sizeof(struct dsd_clib1_conf)
                                      + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                      + iml1 );
   }
   /* new DNS response                                                 */
   adsl_dnsr1_new
     = (struct dsd_dns_resp_1 *) (achl_stor_new + sizeof(struct dsd_clib1_conf)
                                    + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                                    + iml1 );
   adsl_dnsr1_new->imc_len_stor = dsl_clco.imc_len_dns_resp - iml1;  /* storage reserved */
   adsl_dnsr1_new->imc_len_entry = iml2;    /* length of entry         */
   adsl_dnsr1_new->imc_len_dns_n = iml_len_dns_n;  /* length DNS name  */
   achl_w1 = (char *) (adsl_dnsr1_new + 1);
   memcpy( achl_w1, chrs_dns_r_s_1, sizeof(chrs_dns_r_s_1) );
   *((unsigned char *) achl_w1 + 4 + 0) = (unsigned char) (iml_no_ineta >> 8);
   *((unsigned char *) achl_w1 + 4 + 1) = (unsigned char) iml_no_ineta;
   achl_w1 += sizeof(chrs_dns_r_s_1);
   memcpy( achl_w1, chrl_dns_name, iml_len_dns_n );
   achl_w1 += iml_len_dns_n;
   memcpy( achl_w1, chrs_dns_r_a_2, sizeof(chrs_dns_r_a_2) );
   achl_w1 += sizeof(chrs_dns_r_a_2);
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop to copy all INETA  */
     memcpy( achl_w1, chrs_dns_r_s_3, sizeof(chrs_dns_r_s_3) );
     achl_w1 += sizeof(chrs_dns_r_s_3);
     memcpy( achl_w1, &umrl_ineta[ iml1 ], sizeof(UNSIG_MED) );
     achl_w1 += sizeof(UNSIG_MED);
     iml1++;                                /* increment index         */
   } while (iml1 < iml_no_ineta);
   memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   goto pdomc80;                            /* DOM node processed - next */

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */
   if (achl_stor_new == NULL) {             /* no NAT-entries found    */
     if (dsl_clco.boc_cross_nat == FALSE) {  /* do not use crosswise NAT */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W m_hlclib_conf() no valid entries found",
                     __LINE__ );
       return FALSE;
     }
     bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &achl_stor_new,
                                    sizeof(struct dsd_clib1_conf) );
     if (bol1 == FALSE) {                   /* error occured           */
       return FALSE;
     }
     memcpy( achl_stor_new, &dsl_clco, sizeof(struct dsd_clib1_conf) );
   }
   if (   (((struct dsd_clib1_conf *) achl_stor_new)->imc_nat_e1 == 0)  /* number of entries NAT */
       && (((struct dsd_clib1_conf *) achl_stor_new)->boc_cross_nat == FALSE)) {  /* do not use crosswise NAT */
     if (((struct dsd_clib1_conf *) achl_stor_new)->boc_alg_sip) {  /* use ALG for SIP VoIP protocol */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W m_hlclib_conf() ALG-SIP configured but no NAT configured - ALG-SIP ignored",
                     __LINE__ );
       ((struct dsd_clib1_conf *) achl_stor_new)->boc_alg_sip = FALSE;  /* do not use ALG for SIP VoIP protocol */
     }
   }
   *adsp_hlcldomf->aac_conf = achl_stor_new;  /* save configuration data */
#ifdef TRACEHL1
   m_sdh_console_out( &dsl_sdh_call_1,
                      achl_stor_new,
                      sizeof(struct dsd_clib1_conf)
                        + dsl_clco.imc_nat_e1 * sizeof(dsd_nat_entry_1)
                        + dsl_clco.imc_len_dns_resp );
#endif
   return TRUE;
} /* end m_hlclib_conf()                                               */

/* retrieve DNS name                                                   */
static int m_get_dns_name( char *achp_out, int imp_len_out, HL_WCHAR *awcp_value ) {
   char       *achl_wp, *achl_end;          /* write pointer, end      */
   char       *achl_first;                  /* first element with length */

   achl_wp = achp_out;                      /* get output              */
   achl_end = achp_out + imp_len_out;       /* end of output           */

   p_out_00:                                /* output next part        */
   achl_first = achl_wp;                    /* save start element      */
   achl_wp++;                               /* start here              */
   if (achl_wp >= achl_end) return -1;      /* output too long         */

   p_out_20:                                /* output characters       */
   if (*awcp_value >= 0X80) return -1;      /* invalid character       */
   if (   (*awcp_value != 0)                /* not end of string       */
       && (*awcp_value != '.')) {           /* is not separator        */
     if (achl_wp >= achl_end) return -1;    /* output too long         */
     *achl_wp++ = (unsigned char) *awcp_value++;  /* copy value        */
     goto p_out_20;                         /* output characters       */
   }
   *achl_first = (unsigned char) (achl_wp - (achl_first + 1));
   if (*achl_first == 0) return -1;         /* only . / separator      */
   if (*awcp_value != 0) {                  /* not end of string       */
     awcp_value++;                          /* next input character    */
     goto p_out_00;                         /* output next part        */
   }
   if (achl_wp >= achl_end) return -1;      /* output too long         */
   *achl_wp++ = 0;                          /* set length zero as end  */
   return achl_wp - achp_out;               /* all done                */
} /* end m_get_dns_name()                                              */

static BOOL m_check_dns_n_double( char *achp_dns_n, int imp_len_dns_n, struct dsd_clib1_conf *adsp_clco ) {
   char       *achl_w1;                     /* working-variable        */
   char       *achl_end;                    /* end of configuration    */

   if (adsp_clco == NULL) return TRUE;      /* first configured value  */
   if (adsp_clco->imc_len_dns_resp == 0) return TRUE;  /* no values before */
   achl_w1 = (char *) (adsp_clco + 1) + adsp_clco->imc_nat_e1 * sizeof(dsd_nat_entry_1);
   achl_end = achl_w1 + adsp_clco->imc_len_dns_resp;  /* add length of DNS responses */
   do {                                     /* loop over all DNS responses */
#define ADSL_DNSR1_W1 ((struct dsd_dns_resp_1 *) achl_w1)
     if (   (imp_len_dns_n == ADSL_DNSR1_W1->imc_len_dns_n)
         && (!memcmp( achp_dns_n, (char *) (ADSL_DNSR1_W1 + 1) + sizeof(chrs_dns_r_i_1), imp_len_dns_n ))) {
       return FALSE;                        /* DNS name already defined */
     }
     achl_w1 += ADSL_DNSR1_W1->imc_len_stor;  /* add storage reserved  */
#undef ADSL_DNSR1_W1
   } while (achl_w1 < achl_end);
   return TRUE;                             /* all valid               */
} /* end m_check_dns_n_double()                                        */

/* subroutine to process the copy library function                     */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_output;                   /* output has been done    */
   int        iml_len_nhasn;                /* length bytes NHASN      */
   int        iml_len_packet;               /* length bytes packet     */
   int        iml_pos_packet;               /* position in packet      */
   int        iml_len_ip_header;            /* length of IP header     */
   int        iml_xchg_pos_packet;          /* exchange in IP header   */
   int        iml_udp_pos_port;             /* port in UDP header      */
   int        iml_type;                     /* type of RR              */
   int        iml_class;                    /* class of RR             */
   int        iml_chs;                      /* calculate checksum      */
   int        iml_cmp_disp_ineta;           /* displacement INETA to compare */
   int        iml_repl_disp_ineta;          /* displacement INETA to replace */
   int        iml_len_dns_n;                /* length DNS name         */
   UNSIG_MED  uml_ineta_w1;                 /* working-variable        */
#ifdef TRACEHL1
   char       chl1;                         /* working variable        */
#endif
   char       chl_protocol;                 /* protocol from IP header */
   char       *achl1, *achl2, *achl3, *achl4, *achl5;  /* working variables */
   char       *achl_end;                    /* end of string to examine */
   char       *achl_work_1;                 /* position work area, up  */
   char       *achl_work_2;                 /* position work area, dow */
   char       *achl_inp;                    /* input data              */
   char       *achl_packet;                 /* start of packet         */
   char       *achl_sip_packet;             /* start of SIP packet     */
   UNSIG_MED  *auml_cnet_so;                /* cnet INETA source       */
   UNSIG_MED  *auml_cnet_de;                /* cnet INETA destination  */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_gather_i_1 *adsl_gai1_inp_start;  /* start input data    */
   struct dsd_gather_i_1 *adsl_gai1_inp_packet;  /* input packet data  */
   struct dsd_gather_i_1 *adsl_gai1_inp_w1;  /* input data             */
   struct dsd_gather_i_1 *adsl_gai1_inp_w2;  /* input data             */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_nat_entry_1 *adsl_nat_entry_1_w1;  /* structure NAT entry */
   struct dsd_nat_entry_1 *adsl_nat_entry_1_header;  /* structure NAT entry */
   struct dsd_query_dns_resp_1 *adsl_qdnsr1_w1;  /* structure query DNS response */
   struct dsd_dns_resp_1 *adsl_dnsr1;       /* structure DNS response  */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   char       chrl_dns_name[ 256 ];         /* for DNS name            */
#ifdef B110701
   char       chrl_work1[ 1024 ];           /* work area               */
#else
   char       chrl_work1[ 2048 ];           /* work area               */
#endif

   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
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
     adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     bol1 = FALSE;
     chl1 = 0;
     while (adsl_gai1_inp_w1) {
       iml2++;
       iml1 += adsl_gai1_inp_w1->achc_ginp_end - adsl_gai1_inp_w1->achc_ginp_cur;
       if (   (adsl_gai1_inp_w1->achc_ginp_end > adsl_gai1_inp_w1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_w1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next in chain */
     }
     printf( "xl-sdh-ppp-pf-04 m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X\n",
             adsp_hl_clib_1->inc_func, achh_text,
             adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
     fflush( stdout );
#ifdef OLD01
     if (adsl_contr_1) {                    /* memory allocated        */
       adsl_contr_1->imc_count_call++;      /* count all calls         */
       if (adsl_contr_1->imc_count_call > 40) {  /* already too many   */
#ifndef HL_UNIX
         Sleep( 500 );
#else
         sleep( 1 );
#endif
       }
     }
#endif
   }
#endif
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
//     memset( adsp_hl_clib_1->ac_ext, 0, sizeof(struct dsd_clib1_contr_1) );
       ((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext)->boc_client_header = FALSE;  /* no client header has been received */
       ((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext)->boc_cross_nat = FALSE;  /* use crosswise NAT */
       ((struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext)->imc_no_qdnsr1 = 0;  /* number of responses queued */
       return;
     case DEF_IFUNC_CLOSE:
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       }
       return;
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
       return;
   }
#ifdef TRACEHL_DNS
   if (adsl_contr_1->imc_no_qdnsr1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld called inc_func=%d imc_no_qdnsr1=%d adsc_gather_i_1_in=0X%p.",
                   __LINE__, m_get_epoch_ms(),
                   adsp_hl_clib_1->inc_func, adsl_contr_1->imc_no_qdnsr1,
                   adsp_hl_clib_1->adsc_gather_i_1_in );
   }
#endif
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) {
     if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
         || (adsl_contr_1->imc_no_qdnsr1 == 0)) {
       return;
     }
   }
#define ADSL_CLCO ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   bol_output = FALSE;                      /* clear output has been done */
   if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
       || (adsl_contr_1->imc_no_qdnsr1 == 0)) {
     goto p_out_dns_80;                     /* end of output stored DNS */
   }
   adsl_qdnsr1_w1 = adsl_contr_1->dsrc_qdnsr1;

   p_out_dns_20:                            /* output stored DNS one entry */
   adsl_dnsr1 = adsl_qdnsr1_w1->adsc_dnsr1;  /* structure DNS response */
   achl_work_2 -= 2 * sizeof(struct dsd_gather_i_1);
   achl1 = achl_work_1 + MAX_LEN_NHASN;     /* start of packet         */
   achl_work_1 += MAX_LEN_NHASN + 1 + 20 + D_LEN_UDP_HEADER + 2;
// to-do 28.03.09 crosswise NAT INETA in DNS response
   if (achl_work_1 > achl_work_2) {         /* no space for output     */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     iml1 = (char *) (adsl_contr_1->dsrc_qdnsr1 + adsl_contr_1->imc_no_qdnsr1)
              - (char *) adsl_dnsr1;
     memmove( adsl_contr_1->dsrc_qdnsr1,
              adsl_dnsr1,
              iml1 );
     adsl_contr_1->imc_no_qdnsr1
       = iml1 / sizeof(struct dsd_query_dns_resp_1);
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
#define ADSL_GAI1_G (((struct dsd_gather_i_1 *) achl_work_2) + 1)
   ADSL_GAI1_G->adsc_next = adsl_gai1_out_2;  /* get chain before      */
   ADSL_GAI1_G->achc_ginp_cur = (char *) (adsl_dnsr1 + 1);
   ADSL_GAI1_G->achc_ginp_end = (char *) (adsl_dnsr1 + 1) + adsl_dnsr1->imc_len_entry;
   bol_output = TRUE;                       /* output has been done    */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = ADSL_GAI1_G;
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = ADSL_GAI1_G;           /* this is last output     */
#undef ADSL_GAI1_G
// bol_output = TRUE;                       /* output has been done    */
   achl2 = achl1;
   *achl2++ = '4';                          /* PPP IPV4 data           */
   *achl2++ = (unsigned char) 0X45;         /* IPV4 and length         */
   *achl2++ = 0;                            /* Type of Service         */
   iml1 = 20 + D_LEN_UDP_HEADER + 2 + adsl_dnsr1->imc_len_entry;
   *achl2++ = (unsigned char) (iml1 >> 8);  /* first part Total Length */
   *achl2++ = (unsigned char) iml1;         /* second part Total Length */
   *achl2++ = (unsigned char) 0X01;         /* first part Identification */
   *achl2++ = (unsigned char) 0X6A;         /* second part Identification */
   *achl2++ = 0;                            /* Flags + first part Fragment Offset */
   *achl2++ = 0;                            /* second part Fragment Offset */
   *achl2++ = (unsigned char) 0X80;         /* Time to live            */
   *achl2++ = (unsigned char) IPPROTO_UDP;  /* Protocol UDP            */
   *achl2++ = 0;                            /* first part Header checksum */
   *achl2++ = 0;                            /* second part Header checksum */
   memcpy( achl2, &adsl_qdnsr1_w1->umc_ineta_dest, sizeof(UNSIG_MED) );
#ifdef XYZ1
   if (adsl_contr_1->boc_cross_nat) {       /* use crosswise NAT       */
     memcpy( &uml_ineta_w1, achl2, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl2, &uml_ineta_w1, sizeof(UNSIG_MED) );
     }
   }
#endif
   achl2 += sizeof(UNSIG_MED);
   memcpy( achl2, &adsl_qdnsr1_w1->umc_ineta_source, sizeof(UNSIG_MED) );
#ifdef XYZ1
   if (adsl_contr_1->boc_cross_nat) {       /* use crosswise NAT       */
     memcpy( &uml_ineta_w1, achl2, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_real | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl2, &uml_ineta_w1, sizeof(UNSIG_MED) );
     }
   }
#endif
   achl2 += sizeof(UNSIG_MED);
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld send DNS response part one",
                 __LINE__, m_get_epoch_ms() );
   m_sdh_console_out( &dsl_sdh_call_1, achl1, achl2 - achl1 );
#endif
   /* calculate header checksum                                        */
   achl3 = achl1 + 1;                       /* here is start IP header */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                           */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in header */
   } while (achl3 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl1 + 1 + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + 1 + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   /* build UDP header                                                 */
   memcpy( achl2, chrs_port_dns, sizeof(chrs_port_dns) );
   achl2 += sizeof(chrs_port_dns);
   memcpy( achl2, adsl_qdnsr1_w1->chrs_port_dest, sizeof(adsl_qdnsr1_w1->chrs_port_dest) );
   achl2 += sizeof(adsl_qdnsr1_w1->chrs_port_dest);
   iml1 = D_LEN_UDP_HEADER + 1 + adsl_dnsr1->imc_len_entry;
   *achl2++ = (unsigned char) (iml1 >> 8);  /* first part Length UDP packet */
   *achl2++ = (unsigned char) iml1;         /* second part Length UDP packet */
   *achl2++ = 0;                            /* first part checksum     */
   *achl2++ = 0;                            /* second part checksum    */
   memcpy( achl2, adsl_qdnsr1_w1->chrs_id, sizeof(adsl_qdnsr1_w1->chrs_id) );
   achl2 += sizeof(adsl_qdnsr1_w1->chrs_id);
   /* calculate UDP checksum                                           */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in data   */
   } while (achl3 < achl2);
   /* checksum over constant part                                      */
   achl3 = (char *) (adsl_dnsr1 + 1);
   achl2 = achl3 + (adsl_dnsr1->imc_len_entry & (0 - 2));
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl3 + 0) << 8)
                  | *((unsigned char *) achl3 + 1);
     achl3 += 2;                            /* next position in data   */
   } while (achl3 < achl2);
   if (adsl_dnsr1->imc_len_entry & 1) {     /* one byte remaining      */
     iml_chs += *((unsigned char *) achl3 + 0) << 8;
   }
   /* fields in the IP header                                          */
   achl2 = achl1 + 1 + 12;                  /* start source address    */
   achl3 = achl2 + 4 + 4;                   /* after destination address */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl2 + 0) << 8)
                  | *((unsigned char *) achl2 + 1);
     achl2 += 2;                            /* next position in data   */
   } while (achl2 < achl3);
   iml_chs += ((unsigned char) IPPROTO_UDP) + D_LEN_UDP_HEADER + 1 + adsl_dnsr1->imc_len_entry;
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl1 + 1 + 20 + 6 + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl1 + 1 + 20 + 6 + 1) = (unsigned char) iml_chs;
   /* packet has been prepared                                         */
   iml1 = (achl_work_1 - achl1) + adsl_dnsr1->imc_len_entry;  /* length of packet */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits             */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
#ifdef TRACEHL1
   iml1 = (achl_work_1 - achl1) + adsl_dnsr1->imc_len_entry;  /* length of packet */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T DNS response packet len=%d.",
                 __LINE__, iml1 );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_out_1, iml1 );
#endif
#ifdef TRACEHL_DNS
   iml1 = (achl_work_1 - achl1) + adsl_dnsr1->imc_len_entry;  /* length of packet */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld DNS response packet len=%d.",
                 __LINE__, m_get_epoch_ms(), iml1 );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_out_1, iml1 );
#endif
   adsl_qdnsr1_w1++;                        /* next entry output       */
   if (adsl_qdnsr1_w1
         < (adsl_contr_1->dsrc_qdnsr1 + adsl_contr_1->imc_no_qdnsr1)) {
     goto p_out_dns_20;                     /* output stored DNS one entry */
   }
   adsl_contr_1->imc_no_qdnsr1 = 0;         /* no more entry           */
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) return;

   p_out_dns_80:                            /* end of output stored DNS */
   adsl_gai1_inp_start = adsl_gai1_inp_w1 = adsp_hl_clib_1->adsc_gather_i_1_in;  /* start input data */
   achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start input data    */
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER) {
     iml_cmp_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_real );  /* displacement INETA to compare */
     iml_repl_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_translated );  /* displacement INETA to replace */
     iml_xchg_pos_packet = 12;              /* exchange in IP header   */
     iml_udp_pos_port = 0;                  /* port in UDP header      */
     auml_cnet_so = &ADSL_CLCO->umc_cnat_ineta_real;  /* cnet INETA source */
     auml_cnet_de = &ADSL_CLCO->umc_cnat_ineta_translated;  /* cnet INETA destination */
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     iml_cmp_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_translated );  /* displacement INETA to compare */
     iml_repl_disp_ineta = offsetof( struct dsd_nat_entry_1, umc_ineta_real );  /* displacement INETA to replace */
     iml_xchg_pos_packet = 16;              /* exchange in IP header   */
     iml_udp_pos_port = 2;                  /* port in UDP header      */
     auml_cnet_so = &ADSL_CLCO->umc_cnat_ineta_translated;  /* cnet INETA source */
     auml_cnet_de = &ADSL_CLCO->umc_cnat_ineta_real;  /* cnet INETA destination */
     if (adsl_contr_1->boc_client_header) {  /* client header has been received */
       goto p_check_tcp_00;                 /* check TCP packet        */
     }
   } else {                                 /* is other function       */
     return;                                /* nothing to do           */
   }
   bol1 = FALSE;                            /* reset state             */

   p_header_00:                             /* search in header        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) return;  /* end of input data       */
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   if (*achl_inp == CHAR_CR) {              /* carriage-return found   */
     bol1 = TRUE;                           /* set state               */
   } else if (*achl_inp == CHAR_LF) {       /* line-feed found         */
     if (bol1) {                            /* found carriage-return before */
       achl_inp++;                          /* after this character    */
       adsl_contr_1->boc_client_header = TRUE;  /* client header has been received */
       goto p_out_00;                       /* output of these data    */
     }
   } else {                                 /* normal character received */
     bol1 = FALSE;                          /* set state               */
   }
   achl_inp++;                              /* after this character    */
   goto p_header_00;                        /* search in header        */

   p_check_tcp_00:                          /* check TCP packet        */
   iml_len_nhasn = 0;                       /* clear length bytes NHASN */
   iml_len_packet = 0;                      /* clear length bytes packet */

   p_check_tcp_20:                          /* decode length NHASN     */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
       if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
           && (adsl_contr_1->imc_no_qdnsr1)) {  /* number of responses queued */
         adsp_hl_clib_1->boc_callrevdir = TRUE;  /* call on reverse direction */
       }
       return;                              /* to be called again      */
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   iml_len_packet <<= 7;                    /* shift old value         */
   iml_len_packet |= *achl_inp++ & 0X7F;    /* apply new bits          */
   iml_len_nhasn++;                         /* increment length bytes NHASN */
   if ((unsigned char) *(achl_inp - 1) & 0X80) {  /* more bit set      */
     if (iml_len_nhasn > MAX_LEN_NHASN) goto p_inv_data_00;  /* input data invalid */
     goto p_check_tcp_20;                   /* decode length NHASN     */
   }
   if (iml_len_packet <= 1) goto p_inv_data_00;  /* input data invalid */
   achl_packet = achl_inp;                  /* start of packet         */
   adsl_gai1_inp_packet = adsl_gai1_inp_w1;  /* input packet data      */
   iml1 = iml_len_packet;                   /* get length packet       */

   p_check_tcp_40:                          /* read over packet        */
   while (achl_inp >= adsl_gai1_inp_w1->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_w1 = adsl_gai1_inp_w1->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_w1 == NULL) {        /* end of input data       */
       if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
           && (adsl_contr_1->imc_no_qdnsr1)) {  /* number of responses queued */
         adsp_hl_clib_1->boc_callrevdir = TRUE;  /* call on reverse direction */
       }
       return;                              /* to be called again      */
     }
     achl_inp = adsl_gai1_inp_w1->achc_ginp_cur;  /* start in gather   */
   }
   iml2 = adsl_gai1_inp_w1->achc_ginp_end - achl_inp;  /* length this part */
   if (iml2 > iml1) iml2 = iml1;            /* only as long as requested */
   achl_inp += iml2;                        /* add length this part    */
   iml1 -= iml2;                            /* subtract length this part */
   if (iml1) goto p_check_tcp_40;           /* read over packet        */

   /* check if PPP data, IP, IPV4                                      */
   iml1 = 0;                                /* reset state             */

   p_check_tcp_60:                          /* check first part packet */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (achl_packet == achl_inp) goto p_out_00;  /* content too short   */
   switch (iml1) {                          /* depend on state         */
     case 0:
       if (*achl_packet == '4') {           /* PPP IPV4 data found     */
         iml1 = 1;                          /* next is packet case 2   */
         break;
       }
       if (*achl_packet == '1') break;      /* PPP data found          */
       if (   (ADSL_CLCO->boc_cross_nat)    /* use crosswise NAT       */
           && (*achl_packet == '0')) {
         goto p_contr_00;                   /* control packet found    */
       }
       goto p_out_00;                       /* output unchanged        */
     case 1:
       iml1 = 2;                            /* next is end of compare  */
       if (   (adsl_contr_1->boc_cross_nat)  /* use crosswise NAT      */
           && (((unsigned char) *achl_packet) == ucrs_ctrl_ipcp[0])) {
         goto p_ipcp_00;                    /* process IPCP            */
       }
       goto p_out_00;                       /* output unchanged        */
     case 2:                                /* check IPV4 header       */
       if ((*achl_packet & 0XF0) != 0X40) goto p_out_00;  /* not IPV4  */
       break;
   }
   achl_packet++;                           /* increment input         */
   iml1++;                                  /* increment state         */
   if (iml1 < 3) goto p_check_tcp_60;       /* check first part packet */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_start, iml_len_nhasn + iml_len_packet );
#endif
   iml_len_ip_header = (*(achl_packet - 1) & 0X0F) << 2;  /* length of IP header */
   if (iml_len_packet < (1 + 20)) {         /* packet too short        */
     goto p_out_00;                         /* output unchanged        */
   }
   adsl_nat_entry_1_header = NULL;          /* do not replace INETA    */
   achl_sip_packet = NULL;                  /* clear start of SIP packet */
   iml1 = 9 - (3 - 2);                      /* position protocol       */

   p_check_tcp_64:                          /* overread part before protocol */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_tcp_64;           /* overread part before protocol */
   chl_protocol = *achl_packet;             /* protocol from IP header */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet chl_protocol=0X%02X.",
                 __LINE__, (unsigned char) chl_protocol );
#endif
   iml_pos_packet = 9;                      /* position in packet      */

   /* check if the INETA has to be modified                            */
   iml1 = iml_xchg_pos_packet - iml_pos_packet;  /* Source / Destination Address */
   iml_pos_packet += iml1;                  /* position in packet      */
   if (iml_pos_packet > iml_len_packet) {   /* packet too short        */
     goto p_out_00;                         /* output unchanged        */
   }

   p_check_tcp_68:                          /* overread part before INETA */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_tcp_68;           /* overread part before INETA */
   iml1 = 4;                                /* copy INETA              */
   achl1 = chrl_work1;                      /* output area             */
   iml_pos_packet += iml1;                  /* position in packet      */

   p_check_tcp_72:                          /* copy INETA              */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_tcp_72;           /* copy INETA              */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet iml_pos_packet=%d INETA=%d.%d.%d.%d.",
                 __LINE__, iml_pos_packet,
                 *((unsigned char *) chrl_work1 + 0 ),
                 *((unsigned char *) chrl_work1 + 1 ),
                 *((unsigned char *) chrl_work1 + 2 ),
                 *((unsigned char *) chrl_work1 + 3 ) );
#endif
   iml1 = ADSL_CLCO->imc_nat_e1;            /* get number of NAT-entry */
   if (iml1 == 0) {                         /* no NAT defined          */
     goto p_check_sip_00;                   /* has to check SIP        */
   }
   if (   (adsl_contr_1->boc_cross_nat)     /* use crosswise NAT       */
       && (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)) {
     if ((*((UNSIG_MED *) chrl_work1) & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       *((UNSIG_MED *) chrl_work1) = ADSL_CLCO->umc_cnat_ineta_real
           | (*((UNSIG_MED *) chrl_work1) & ADSL_CLCO->umc_cnat_mask_and_2);
     }
   }
   adsl_nat_entry_1_header = (struct dsd_nat_entry_1 *) (ADSL_CLCO + 1);
   while (TRUE) {                           /* loop over INETA real    */
     if ((*((UNSIG_MED *) chrl_work1) & adsl_nat_entry_1_header->umc_mask_and_1)
           == *((UNSIG_MED *) ((char *) adsl_nat_entry_1_header + iml_cmp_disp_ineta))) break;
     iml1--;                                /* decrement index         */
     if (iml1 < 0) {                        /* end of array            */
       adsl_nat_entry_1_header = NULL;      /* do not replace INETA    */
       goto p_check_sip_00;                 /* has to check SIP        */
     }
     adsl_nat_entry_1_header++;             /* check next NAT entry    */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d INETA to modify",
                 __LINE__, iml_len_nhasn, iml_len_packet );
#endif

   p_check_sip_00:                          /* has to check SIP        */
   if (chl_protocol != IPPROTO_UDP) {       /* protocol from IP header */
     goto p_copy_00;                        /* check what to do with packet */
   }
   if (ADSL_CLCO->boc_alg_sip == FALSE) {   /* do not use ALG for SIP VoIP protocol */
     goto p_check_dns_00;                   /* has to check DNS        */
   }
   if (   (adsl_nat_entry_1_header == NULL)  /* no normal NAT          */
       && (adsl_contr_1->boc_cross_nat == FALSE)) {  /* do not use crosswise NAT */
     goto p_check_dns_00;                   /* has to check DNS        */
   }
   /* displacement zero in UDP header is source port, displacement two is destination port */
   if ((iml_len_ip_header + 2 * 2) > iml_len_packet) {  /* packet too short */
     goto p_copy_00;                        /* check what to do with packet */
   }
   iml1 = iml_len_ip_header - iml_pos_packet;
   iml_pos_packet += iml1;                  /* position in packet      */

   p_check_sip_04:                          /* overread part before UDP source port */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_sip_04;           /* overread part before UDP source port */
   iml1 = 4;                                /* copy source and destination port */
   achl1 = chrl_work1;                      /* output area             */
   iml_pos_packet += iml1;                  /* position in packet      */

   p_check_sip_08:                          /* copy UDP source and destination port */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_sip_08;           /* copy UDP source and destination port */
   if (*((unsigned short int *) chrs_port_dns) == *((unsigned short int *) (chrl_work1 + iml_udp_pos_port))) {
     if (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->imc_len_dns_resp) {  /* length of DNS responses */
       goto p_check_dns_20;                 /* this is UDP DNS packet  */
     }
     goto p_copy_00;                        /* check what to do with packet */
   }
   if (*((unsigned short int *) chrs_port_sip) == *((unsigned short int *) (chrl_work1 + 0))) {
     goto p_check_sip_20;                   /* this is UDP SIP packet  */
   }
   if (*((unsigned short int *) chrs_port_sip) != *((unsigned short int *) (chrl_work1 + 2))) {
     goto p_copy_00;                        /* check what to do with packet */
   }

   p_check_sip_20:                          /* this is UDP SIP packet  */
   /* copy the SIP packet to the work area                             */
   if ((iml_len_packet) > sizeof(chrl_work1)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W p_check_sip_20 SIP packet too long %d.",
                   __LINE__, iml_len_packet );
     goto p_out_00;                         /* output unchanged        */
   }
   if ((achl_work_1 + iml_len_packet + D_EXT_SIP + sizeof(struct dsd_gather_i_1))
         > achl_work_2) {
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
   achl1 = achl_packet = achl_sip_packet = chrl_work1;  /* output here */
   iml1 = iml_len_packet;                   /* length to copy          */
   iml2 = iml_len_nhasn;                    /* so much to overread     */

   p_check_sip_40:                          /* copy part of the packet */
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml3 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > 0) {                          /* something to overread   */
     iml4 = iml3;                           /* length of packet        */
     if (iml4 > iml2) iml4 = iml2;          /* only so much            */
     adsl_gai1_inp_start->achc_ginp_cur += iml4;
     iml2 -= iml4;
     iml3 -= iml4;
     if (iml3 == 0) goto p_check_sip_40;    /* needs more input        */
   }
   if (iml3 > iml1) iml3 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml3 );
   achl1 += iml3;
   adsl_gai1_inp_start->achc_ginp_cur += iml3;
   iml1 -= iml3;
   if (iml1) goto p_check_sip_40;           /* copy part of the packet */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   bol_output = TRUE;                       /* output has been done    */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
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
   goto p_copy_60;                          /* packet has been copied  */

   p_check_dns_00:                          /* has to check DNS        */
   if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->imc_len_dns_resp == 0)) {  /* length of DNS responses */
     goto p_copy_00;                        /* check what to do with packet */
   }
   /* displacement zero in UDP header is source port                   */
   if ((iml_len_ip_header + iml_udp_pos_port + 2) > iml_len_packet) {  /* packet too short */
     goto p_copy_00;                        /* check what to do with packet */
   }
   iml1 = iml_len_ip_header + iml_udp_pos_port - iml_pos_packet;
   iml_pos_packet += iml1;                  /* position in packet      */

   p_check_dns_04:                          /* overread part before UDP source port */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_dns_04;           /* overread part before UDP source port */
   iml1 = 2;                                /* copy source port        */
   achl1 = chrl_work1;                      /* output area             */
   iml_pos_packet += iml1;                  /* position in packet      */

   p_check_dns_08:                          /* copy UDP source port    */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_check_dns_08;           /* copy UDP source port    */
   if (*((unsigned short int *) chrs_port_dns) != *((unsigned short int *) chrl_work1)) {
     goto p_copy_00;                        /* check what to do with packet */
   }

   p_check_dns_20:                          /* this is UDP DNS packet  */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 1.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
#endif
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 1.",
                 __LINE__, m_get_epoch_ms(), iml_len_nhasn, iml_len_packet );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_start, iml_len_nhasn + iml_len_packet );
#endif
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER) {
     goto p_copy_20;                        /* copy the packet         */
   }
   /* check if DNS name as requested                                   */
// to-do 27.10.10 KB - is 2 correct?
#ifdef B101027
   if (iml_len_packet < (2 + iml_len_ip_header + D_LEN_UDP_HEADER
                           + 2 + sizeof(chrs_dns_query_1) + 2 + sizeof(chrs_dns_query_2))) {  /* packet too short */
     goto p_copy_00;                        /* check what to do with packet */
   }
#endif
   if (iml_len_packet < (1 + iml_len_ip_header + D_LEN_UDP_HEADER
                           + 2 + sizeof(chrs_dns_query_1) + 2 + sizeof(chrs_dns_query_2))) {  /* packet too short */
     goto p_copy_00;                        /* check what to do with packet */
   }
   iml1 = iml_len_ip_header + D_LEN_UDP_HEADER + 2 - iml_pos_packet;
   iml_pos_packet += iml1;                  /* position in packet      */

   p_name_dns_20:                           /* overread part before start of UDP packet after ID */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_20;            /* overread part before start of UDP packet after ID */
   /* copy part 1                                                      */
   iml1 = sizeof(chrs_dns_query_1);         /* copy part 1             */
   achl1 = chrl_work1;                      /* output area             */
   iml_pos_packet += iml1;                  /* position in packet      */

   p_name_dns_40:                           /* copy DNS control fields */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_40;            /* copy DNS control fields */
   if (memcmp( chrl_work1, chrs_dns_query_1, sizeof(chrs_dns_query_1) )) {
     goto p_copy_00;                        /* check what to do with packet */
   }
   /* get the DNS name                                                 */
   achl1 = achl2 = chrl_dns_name;           /* output DNS name         */

   p_name_dns_60:                           /* copy DNS name           */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (achl1 >= (chrl_dns_name + sizeof(chrl_dns_name))) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W p_name_dns_60 DNS name too long", __LINE__ );
     goto p_copy_00;                        /* check what to do with packet */
   }
   *achl1 = *achl_packet++;                 /* get next byte           */
   if (achl1 < achl2) {                     /* not yet at end this part */
     achl1++;                               /* next output             */
     goto p_name_dns_60;                    /* copy DNS name           */
   }
   achl2 += 1 + (unsigned char) *achl1++;
   if (achl1 < achl2) {                     /* not yet at end this part */
     goto p_name_dns_60;                    /* copy DNS name           */
   }
   /* end of DNS name                                                  */
   iml_len_dns_n = achl1 - chrl_dns_name;   /* length DNS name         */
   iml_pos_packet += iml_len_dns_n;         /* position in packet      */
   if ((iml_len_packet - 1 - iml_pos_packet) != sizeof(chrs_dns_query_2)) {
     goto p_copy_00;                        /* check what to do with packet */
   }
   /* copy part 2 of DNS query                                         */
   iml1 = sizeof(chrs_dns_query_2);         /* copy part 2             */
   achl1 = chrl_work1;                      /* output area             */
   iml_pos_packet += iml1;                  /* position in packet      */

   p_name_dns_80:                           /* copy DNS query last part */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, achl_packet, iml2 );
   achl_packet += iml2;
   achl1 += iml2;
   iml1 -= iml2;
   if (iml1) goto p_name_dns_80;            /* copy DNS query last part */
   if (memcmp( chrl_work1, chrs_dns_query_2, sizeof(chrs_dns_query_2) )) {
     goto p_copy_00;                        /* check what to do with packet */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet DNS query found iml_len_nhasn=%d iml_len_packet=%d iml_len_dns_n=%d.",
                 __LINE__, iml_len_nhasn, iml_len_packet, iml_len_dns_n );
#endif
   achl1 = (char *) adsp_hl_clib_1->ac_conf + sizeof(struct dsd_clib1_conf)
                      + ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->imc_nat_e1 * sizeof(dsd_nat_entry_1);
   achl2 = achl1 + ((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->imc_len_dns_resp;  /* add length of DNS responses */
   do {                                     /* loop over all DNS responses */
#define ADSL_DNSR1_W1 ((struct dsd_dns_resp_1 *) achl1)
     if (   (iml_len_dns_n == ADSL_DNSR1_W1->imc_len_dns_n)
         && (!memcmp( chrl_dns_name, (char *) (ADSL_DNSR1_W1 + 1) + sizeof(chrs_dns_r_i_1), iml_len_dns_n ))) {
       goto p_found_dns_name;               /* DNS name found          */
     }
     achl1 += ADSL_DNSR1_W1->imc_len_stor;  /* add storage reserved    */
#undef ADSL_DNSR1_W1
   } while (achl1 < achl2);
   goto p_copy_00;                          /* check what to do with packet */

   p_found_dns_name:                        /* DNS name found          */
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld p_found_dns_name: adsl_contr_1->imc_no_qdnsr1 = %d.",
                 __LINE__, m_get_epoch_ms(), adsl_contr_1->imc_no_qdnsr1 );
#endif
   if (adsl_contr_1->imc_no_qdnsr1 >= MAX_DNS_QUEUED) {
     adsp_hl_clib_1->boc_callrevdir = TRUE;  /* call on reverse direction */
     return;                                /* to be called again      */
   }
   adsl_qdnsr1_w1 = adsl_contr_1->dsrc_qdnsr1 + adsl_contr_1->imc_no_qdnsr1;
   adsl_qdnsr1_w1->adsc_dnsr1 = (struct dsd_dns_resp_1 *) achl1;  /* structure DNS response */
   /* copy first part of packet to work area                           */
// to-do 27.10.10 KB - is 2 correct?
   iml1 = iml_len_nhasn + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 2;
   achl1 = chrl_work1;                      /* output area             */

   p_found_dn_20:                           /* copy part of the packet */
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_found_dn_20;            /* copy part of the packet */

   /* ignore till end of the packet                                    */
// to-do 27.10.10 KB - is 2 correct?
   iml1 = iml_len_packet - 1 - (iml_len_ip_header + D_LEN_UDP_HEADER + 2);

   p_found_dn_40:                           /* ignore remaining part of packet */
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_found_dn_40;            /* ignore remaining part of packet */

   /* fill structure to send in reverse direction                      */
   memcpy( &adsl_qdnsr1_w1->umc_ineta_source,  /* INETA source         */
           chrl_work1 + iml_len_nhasn + 1 + 12,
           sizeof(UNSIG_MED) );
   memcpy( &adsl_qdnsr1_w1->umc_ineta_dest,  /* INETA destination      */
           chrl_work1 + iml_len_nhasn + 1 + 16,
           sizeof(UNSIG_MED) );
   memcpy( adsl_qdnsr1_w1->chrs_port_dest,  /* destination port        */
           chrl_work1 + iml_len_nhasn + 1 + iml_len_ip_header + 0,
           sizeof(adsl_qdnsr1_w1->chrs_port_dest) );
   memcpy( adsl_qdnsr1_w1->chrs_id,         /* transaction ID          */
           chrl_work1 + iml_len_nhasn + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 0,
           sizeof(adsl_qdnsr1_w1->chrs_id) );
   adsl_contr_1->imc_no_qdnsr1++;
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet DNS query put to queue",
                 __LINE__ );
#endif
#ifdef TRACEHL_DNS
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T time=%lld packet DNS query put to queue",
                 __LINE__, m_get_epoch_ms() );
   m_sdh_console_out( &dsl_sdh_call_1, (char *) adsl_qdnsr1_w1, sizeof(struct dsd_query_dns_resp_1) );
#endif
   goto p_check_tcp_00;                     /* check TCP packet        */

   p_copy_00:                               /* check what to do with packet */
   if (adsl_nat_entry_1_header) goto p_copy_20;  /* copy the packet    */
   if (adsl_contr_1->boc_cross_nat == FALSE) {  /* do not use crosswise NAT */
     goto p_out_00;                         /* output unchanged        */
   }

   p_copy_20:                               /* copy the packet         */
   achl1 = achl_work_1;                     /* output here             */
   achl_packet = achl_work_1 + iml_len_nhasn;  /* here comes packet    */
   iml1 = iml_len_nhasn + iml_len_packet;   /* length to copy          */
   achl_work_1 += iml1;                     /* here is space for the packet */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* work-area too small     */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
   bol_output = TRUE;                       /* output has been done    */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
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

   p_copy_40:                               /* copy part of the packet */
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_copy_40;                /* copy part of the packet */

   p_copy_60:                               /* packet has been copied  */
   bol1 = FALSE;                            /* packet not changed      */
   if (   (adsl_contr_1->boc_cross_nat)     /* use crosswise NAT       */
       && (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)) {
     /* first INETA source                                             */
     /* attention alignment                                            */
     memcpy( &uml_ineta_w1, achl_packet + 1 + 12, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_real | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl_packet + 1 + 12, &uml_ineta_w1, sizeof(UNSIG_MED) );
       bol1 = TRUE;                         /* packet changed          */
     }
     /* second INETA destination                                       */
     /* attention alignment                                            */
     memcpy( &uml_ineta_w1, achl_packet + 1 + 16, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_real | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl_packet + 1 + 16, &uml_ineta_w1, sizeof(UNSIG_MED) );
       bol1 = TRUE;                         /* packet changed          */
     }
   }
   if (adsl_nat_entry_1_header) {           /* do replace INETA in IP header */
     /* attention alignment                                            */
     memcpy( &uml_ineta_w1, achl_packet + 1 + iml_xchg_pos_packet, sizeof(UNSIG_MED) );
     uml_ineta_w1
       = *((UNSIG_MED *) ((char *) adsl_nat_entry_1_header + iml_repl_disp_ineta))
           | (uml_ineta_w1
                & adsl_nat_entry_1_header->umc_mask_and_2);
     memcpy( achl_packet + 1 + iml_xchg_pos_packet, &uml_ineta_w1, sizeof(UNSIG_MED) );
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T INETA in packet replaced iml_xchg_pos_packet=%d iml_repl_disp_ineta=%d uml_ineta_w1=0X%08X.",
                   __LINE__, iml_xchg_pos_packet, iml_repl_disp_ineta, uml_ineta_w1 );
     m_sdh_console_out( &dsl_sdh_call_1, achl_packet, iml_len_packet );
#endif
     bol1 = TRUE;                           /* packet changed          */
   }
   if (   (adsl_contr_1->boc_cross_nat)     /* use crosswise NAT       */
       && (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)) {
     /* first INETA source                                             */
     /* attention alignment                                            */
     memcpy( &uml_ineta_w1, achl_packet + 1 + 12, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl_packet + 1 + 12, &uml_ineta_w1, sizeof(UNSIG_MED) );
       bol1 = TRUE;                         /* packet changed          */
     }
     /* second INETA destination                                       */
     /* attention alignment                                            */
     memcpy( &uml_ineta_w1, achl_packet + 1 + 16, sizeof(UNSIG_MED) );
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       memcpy( achl_packet + 1 + 16, &uml_ineta_w1, sizeof(UNSIG_MED) );
       bol1 = TRUE;                         /* packet changed          */
     }
   }
   if (achl_sip_packet) goto p_copy_84;     /* is SIP packet           */
   if (bol1) {                              /* IP header has been changed */
     /* calculate checksum of IP-header                                */
     /* clear old checksum                                             */
     *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 0) = 0;
     *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 1) = 0;
     achl1 = achl_packet + 1;               /* start of IP header      */
     achl2 = achl1 + iml_len_ip_header;     /* end of IP header        */
     iml_chs = 0;                           /* calculate checksum      */
     do {                                   /* loop over IP header     */
       /* calculate checksum                                           */
       iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                    | *((unsigned char *) achl1 + 1);
       achl1 += 2;                          /* next position in header */
     } while (achl1 < achl2);
     while ((iml_chs >> 16) != 0) {         /* continue carry          */
       iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
     }
     iml_chs = ~iml_chs;                      /* negate result           */
     *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
     *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   }
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
     goto p_copy_80;                        /* end of packet change    */
   }
   if (   (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->imc_nat_e1 == 0)  /* check number of NAT-entry */
       && (adsl_contr_1->boc_cross_nat == FALSE)) {  /* use crosswise NAT */
     goto p_copy_80;                        /* end of packet change    */
   }
   if (*(achl_packet + 1 + 9) != IPPROTO_UDP) {  /* protocol from IP header */
     goto p_copy_80;                        /* end of packet change    */
   }
   if (iml_len_packet < (1 + iml_len_ip_header + 2)) {  /* packet too short */
     goto p_copy_80;                        /* end of packet change    */
   }
   if (memcmp( achl_packet + 1 + iml_len_ip_header + 0, chrs_port_dns, 2 )) {
     goto p_copy_80;                        /* end of packet change    */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet iml_len_nhasn=%d iml_len_packet=%d UDP DNS query found 2.",
                 __LINE__, iml_len_nhasn, iml_len_packet );
#endif
   /* check if response                                                */
   if ((*(achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 2) & 0X80) == 0) {
     goto p_copy_80;                        /* end of packet change    */
   }
   /* check RCODE                                                      */
   if ((*(achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 2 + 1) & 0X0F) != 0) {
     goto p_copy_80;                        /* end of packet change    */
   }
   /* get QDCOUNT                                                      */
   iml1 = (*((unsigned char *) achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 4 + 0) << 8)
            | *((unsigned char *) achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 4 + 1);
   /* get ANCOUNT                                                      */
   iml2 = (*((unsigned char *) achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 6 + 0) << 8)
            | *((unsigned char *) achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 6 + 1);
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T packet UDP DNS query found 3 iml1=%d iml2=%d.",
                 __LINE__, iml1, iml2 );
#endif
   achl1 = achl_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER + 12;  /* here starts question section */
   while (iml1 > 0) {                       /* loop over all questions */
     while (TRUE) {                         /* loop over elements of name */
       if (achl1 > achl_work_1) goto p_copy_80;  /* after end of record */
       iml3 = *((unsigned char *) achl1);
       if (iml3 >= 64) {                    /* compression used        */
         achl1 += 2;                        /* after compression index */
         break;                             /* all done                */
       }
       achl1 += 1 + iml3;
       if (iml3 == 0) break;
     }
     achl1 += 4;                            /* ignore QTYPE and QCLASS */
     iml1--;                                /* this question has been processed */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T DNS query iml2=%d achl_packet=%p achl1=%p.",
                 __LINE__, iml2, achl_packet, achl1 );
#endif
   while (iml2 > 0) {                       /* loop over all resource records */
     while (TRUE) {                         /* loop over elements of name */
       if (achl1 > achl_work_1) goto p_copy_80;  /* after end of record */
       iml3 = *((unsigned char *) achl1);
       if (iml3 >= 64) {                    /* compression used        */
         achl1 += 2;                        /* after compression index */
         break;                             /* all done                */
       }
       achl1 += 1 + iml3;
       if (iml3 == 0) break;
     }
     iml_type = (*((unsigned char *) achl1 + 0 + 0) << 8)
                  | *((unsigned char *) achl1 + 0 + 1);
     iml_class = (*((unsigned char *) achl1 + 2 + 0) << 8)
                  | *((unsigned char *) achl1 + 2 + 1);
     iml3 = (*((unsigned char *) achl1 + 8 + 0) << 8)
              | *((unsigned char *) achl1 + 8 + 1);
     achl2 = achl1 + 10;
     achl1 += 10 + iml3;                    /* after this RR           */
     if (achl1 > achl_work_1) goto p_copy_80;  /* after end of record  */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T DNS query iml2=%d achl_packet=%p achl1=%p iml_type=%d iml_class=%d iml3=%d.",
                   __LINE__, iml2, achl_packet, achl1, iml_type,iml_class, iml3 );
#endif
     if (    (iml_type == 1)                /* A 1 a host address      */
          && (iml_class == 1)               /* IN 1 the Internet       */
          && (iml3 == 4)) {                 /* length INETA IPV4       */
       /* attention alignment                                          */
       memcpy( &uml_ineta_w1, achl2, sizeof(UNSIG_MED) );
       iml4 = ADSL_CLCO->imc_nat_e1;        /* get number of NAT-entry */
       adsl_nat_entry_1_w1 = (struct dsd_nat_entry_1 *) (ADSL_CLCO + 1);
       do {                                 /* loop over INETA real    */
         if ((uml_ineta_w1 & adsl_nat_entry_1_w1->umc_mask_and_1)
               == adsl_nat_entry_1_w1->umc_ineta_real) {
           uml_ineta_w1
             = adsl_nat_entry_1_w1->umc_ineta_translated
                 | (uml_ineta_w1 & adsl_nat_entry_1_w1->umc_mask_and_2);
           memcpy( achl2, &uml_ineta_w1, sizeof(UNSIG_MED) );
#ifdef TRACEHL1
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T DNS UDP INETA replaced",
                         __LINE__ );
#endif
           bol1 = TRUE;                     /* packet changed          */
           break;                           /* all done                */
         }
         adsl_nat_entry_1_w1++;             /* check next NAT entry    */
         iml4--;                            /* decrement index         */
       } while (iml4 > 0);
       if (adsl_contr_1->boc_cross_nat) {   /* use crosswise NAT       */
         if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
           uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
           memcpy( achl2, &uml_ineta_w1, sizeof(UNSIG_MED) );
           bol1 = TRUE;                     /* packet changed          */
         }
       }
     }
     iml2--;                                /* this resource record has been processed */
   }

   p_copy_80:                               /* end of packet change    */
   if (achl_sip_packet == NULL) {           /* not SIP packet          */
     if (bol1 == FALSE) goto p_check_tcp_00;  /* packet is unchanged   */
     goto p_copy_92;                        /* make new checksum       */
   }

   p_copy_84:                               /* is SIP packet           */
   /* apply ALG SIP                                                    */
   achl1 = achl_sip_packet + 1 + iml_len_ip_header + D_LEN_UDP_HEADER;  /* start input to copy */
   achl2 = achl_sip_packet + iml_len_packet;  /* end input to copy     */
   achl3 = achl_packet = achl_work_1 + MAX_LEN_NHASN;  /* start output of copy */
   achl4 = achl_sip_packet;                 /* copied so far           */
   iml2 = 0;                                /* state CR LF             */
   achl5 = NULL;                            /* CR LF CR LF not found   */

   p_alg_sip_20:                            /* search invalid characters */
#ifdef B101022
   while ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 3)) achl1++;
#endif
   while (achl1 < achl2) {
     switch ((unsigned char) *achl1) {
       case CHAR_CR:
         if ((iml2 & 1) == 0) {
           iml2++;                          /* next state              */
           break;
         }
         iml2 = 1;                          /* CR found                */
         break;
       case CHAR_LF:
         if ((iml2 & 1) == 0) {             /* not CR before           */
           iml2 = 0;                        /* state CR LF             */
           break;
         }
         iml2++;                            /* next state              */
         if (iml2 < 4) break;               /* not CR LF CR LF         */
#ifdef DEBUG_101028_01
         if (memcmp( achl1 - 3 - 2, " 0", 2 )) {
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T SIP NAT Content-Length not zero",
                         __LINE__ );
         }
#endif
         achl5 = achl1 - 3;                 /* CR LF CR LF found       */
         achl5 += achl3 - achl4;            /* pointer to output area  */
         break;
       default:
         iml2 = 0;                          /* state CR LF             */
         break;
     }
     if (ucrs_tab_char_sip[ (unsigned char) *achl1 ] == 3) break;
     achl1++;                               /* next character          */
   }
   if (achl1 >= achl2) goto p_alg_sip_60;   /* copy last part          */
   achl1++;                                 /* after separator         */
   if (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 1) goto p_alg_sip_20;  /* search invalid characters */
   iml1 = achl1 - achl4;                    /* get length input        */
   if ((achl3 + iml1) > achl_work_2) goto p_illogic_00;  /* program illogic */
   memcpy( achl3, achl4, iml1 );            /* copy content            */
   achl3 += iml1;                           /* this is end packet      */
   achl4 = achl1;                           /* save start string       */
   while ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] <= 2)) achl1++;
   if ((achl1 < achl2) && (ucrs_tab_char_sip[ (unsigned char) *achl1 ] != 3)) {
     goto p_alg_sip_20;                     /* search invalid characters */
   }
   iml1 = m_get_ineta_a( &uml_ineta_w1, achl4, achl1 );
   if (iml1) goto p_alg_sip_20;             /* was not valid INETA     */
   bol1 = FALSE;                            /* nothing changed yet     */
   if (   (adsl_contr_1->boc_cross_nat)     /* use crosswise NAT       */
       && (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)) {
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_real | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       bol1 = TRUE;                         /* packet changed          */
     }
   }
// to-do 31.03.09 KB - only one to be changed
   while (adsl_nat_entry_1_header) {        /* do normal NAT           */
     if ((uml_ineta_w1 & adsl_nat_entry_1_header->umc_mask_and_1) == adsl_nat_entry_1_header->umc_ineta_real) {
       uml_ineta_w1
         = adsl_nat_entry_1_header->umc_ineta_translated
           | (uml_ineta_w1
                & adsl_nat_entry_1_header->umc_mask_and_2);
       bol1 = TRUE;                         /* INETA has been changed  */
       break;
     }
     if ((uml_ineta_w1 & adsl_nat_entry_1_header->umc_mask_and_1) == adsl_nat_entry_1_header->umc_ineta_translated) {
       uml_ineta_w1
         = adsl_nat_entry_1_header->umc_ineta_real
           | (uml_ineta_w1
                & adsl_nat_entry_1_header->umc_mask_and_2);
       bol1 = TRUE;                         /* INETA has been changed  */
     }
     break;
   }
   if (   (adsl_contr_1->boc_cross_nat)     /* use crosswise NAT       */
       && (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)) {
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       bol1 = TRUE;                         /* packet changed          */
     }
   }
#ifdef XYZ1
   while (adsl_contr_1->boc_cross_nat) {    /* use crosswise NAT       */
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_translated | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       bol1 = TRUE;                         /* INETA has been changed  */
       break;
     }
     if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_translated) {
       uml_ineta_w1 = ADSL_CLCO->umc_cnat_ineta_real | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
       bol1 = TRUE;                         /* INETA has been changed  */
     }
     break;
   }
#endif
   if (bol1 == FALSE) goto p_alg_sip_20;    /* nothing changed         */
#ifdef B110701
   if ((achl3 + 15) > achl_work_2) goto p_illogic_00;  /* program illogic */
#else
   if ((achl3 + 15 + 1) > achl_work_2) goto p_illogic_00;  /* program illogic */
#endif
   achl3 += sprintf( achl3, "%d.%d.%d.%d",
              *((unsigned char *) &uml_ineta_w1 + 0),
              *((unsigned char *) &uml_ineta_w1 + 1),
              *((unsigned char *) &uml_ineta_w1 + 2),
              *((unsigned char *) &uml_ineta_w1 + 3) );
   achl4 = achl1;                           /* input processed so far  */
   goto p_alg_sip_20;                       /* continue searching      */

   p_alg_sip_60:                            /* copy last part          */
   iml1 = achl1 - achl4;                    /* get length input        */
   if (iml1 > 0) {                          /* something to copy       */
     if ((achl3 + iml1) > achl_work_2) goto p_illogic_00;  /* program illogic */
     memcpy( achl3, achl4, iml1 );          /* copy content            */
     achl3 += iml1;                         /* this is end packet      */
   }
   /* set length of packet                                             */
   while (   (achl5)
          && ((achl5 + 4) != achl3)) {
     achl1 = achl5;                         /* end of CR LF CR LF      */
     while ((achl1 > achl_packet) && (*(achl1 - 1) != 0X20)) achl1--;
     if (achl1 <= achl_packet) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W SIP NAT packet-length error 01",
                     __LINE__ );
       break;
     }
     if ((achl1 - 1 - sizeof(ucrs_sip_cont_len)) <= achl_packet) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W SIP NAT packet-length error 02",
                     __LINE__ );
       break;
     }
     if (memcmp( (achl1 - 1 - sizeof(ucrs_sip_cont_len)),
                 ucrs_sip_cont_len,
                 sizeof(ucrs_sip_cont_len) )) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W SIP NAT packet-length error 03",
                     __LINE__ );
       break;
     }
     /* compute length of length in ASCII                              */
     iml2 = iml3 = achl3 - (achl5 + 4);     /* length of last part     */
     iml4 = 0;
     do {
       iml4++;                              /* count the digit         */
       iml2 /= 10;                          /* divide number           */
     } while (iml2 > 0);
     iml2 = iml4 - (achl5 - achl1);         /* compute difference in number of digits */
     if (iml2) {                            /* different number of ASCII digits */
       memmove( achl5 + iml2,
                achl5,
                achl3 - achl5 );
       achl3 += iml2;                       /* new end of packet       */
       achl5 += iml2;                       /* new end of ASCII number */
     }
     do {
       *(--achl5) = (iml3 % 10) + '0';      /* output one digit        */
       iml3 /= 10;                          /* divide number           */
     } while (iml3 > 0);
     break;
   }
   iml_len_packet = iml1 = achl3 - achl_packet;  /* length of packet   */
   /* set length in the IP header                                      */
   iml2 = iml_len_packet - 1;
   achl1 = achl_packet + 1 + 2;             /* here is length          */
   *(achl1 + 0) = (unsigned char) (iml2 >> 8);  /* first byte length big endian */
   *(achl1 + 1) = (unsigned char) iml2;     /* second byte length big endian */
   /* calculate checksum of IP-header                                  */
   /* clear old checksum                                               */
   *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 0) = 0;
   *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 1) = 0;
   achl1 = achl_packet + 1;                 /* start of IP header      */
   achl2 = achl1 + iml_len_ip_header;       /* end of IP header        */
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over IP header     */
     /* calculate checksum                                           */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in header */
   } while (achl1 < achl2);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl_packet + 1 + D_POS_IPH_DCHS + 1) = (unsigned char) iml_chs;
   /* set length in the UDP header                                     */
   iml2 = iml_len_packet - (1 + iml_len_ip_header);
   achl1 = achl_packet + 1 + iml_len_ip_header + 4;  /* here is length */
   *(achl1 + 0) = (unsigned char) (iml2 >> 8);  /* first byte length big endian */
   *(achl1 + 1) = (unsigned char) iml2;     /* second byte length big endian */
   /* output length NHASN                                              */
   achl1 = achl_packet;                     /* end of NHASN            */
   iml2 = 0;                                /* clear more bit          */
   do {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove bits set         */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   /* use gather structure prepared before                             */
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1 = achl3;

   p_copy_92:                               /* make new checksum       */
#ifdef DEBUG_101027_01
   if (iml_len_packet == (1 + 59)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T p_copy_92 iml_len_packet=%d (-1)",
                   __LINE__, iml_len_packet );
   }
#endif
   if (*(achl_packet + 1 + 9) == IPPROTO_TCP) {  /* protocol TCP from IP header */
     achl3 = achl_packet + 1 + iml_len_ip_header + 16;
   } else if (*(achl_packet + 1 + 9) == IPPROTO_UDP) {  /* protocol UDP from IP header */
     achl3 = achl_packet + 1 + iml_len_ip_header + 6;
   } else goto p_check_tcp_00;              /* no new checksum needed  */
   achl1 = achl_packet + 1 + iml_len_ip_header;  /* start of header and data */
// achl2 = achl_packet + 1 + ((iml_len_packet - 1) & (-2));  /* end of data, even */
   achl2 = achl_packet + iml_len_packet - 1;  /* end of data, even or odd */
   if ((achl3 + 2) > achl2) goto p_check_tcp_00;  /* packet is too short */
   /* clear old checksum                                               */
   *((unsigned char *) achl3 + 0) = 0;
   *((unsigned char *) achl3 + 1) = 0;
   iml_chs = 0;                             /* calculate checksum      */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in data   */
   } while (achl1 < achl2);
   if (achl1 < achl_work_1) {               /* one byte remaining      */
     iml_chs += *((unsigned char *) achl1 + 0) << 8;
   }
   /* fields in the IP header                                          */
   achl1 = achl_packet + 1 + 12;            /* start source address    */
   achl2 = achl1 + 4 + 4;                   /* after destination address */
   do {                                     /* loop over data          */
     /* calculate checksum                                             */
     iml_chs += (*((unsigned char *) achl1 + 0) << 8)
                  | *((unsigned char *) achl1 + 1);
     achl1 += 2;                            /* next position in data   */
   } while (achl1 < achl2);
   iml_chs += ((unsigned char) *(achl_packet + 1 + 9)) + iml_len_packet - (1 + iml_len_ip_header);
   while ((iml_chs >> 16) != 0) {           /* continue carry          */
     iml_chs = (iml_chs & 0X0000FFFF) + (iml_chs >> 16);
   }
   iml_chs = ~iml_chs;                      /* negate result           */
   *((unsigned char *) achl3 + 0) = (unsigned char) (iml_chs >> 8);
   *((unsigned char *) achl3 + 1) = (unsigned char) iml_chs;
   goto p_check_tcp_00;                     /* check TCP packet        */

   p_ipcp_00:                               /* process IPCP            */
   achl_packet++;                           /* increment input         */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   if (((unsigned char) *achl_packet) != ucrs_ctrl_ipcp[1]) {
     goto p_out_00;                         /* output unchanged        */
   }
   /* copy the complete packet to the work-area                        */
   achl1 = achl_work_1;                     /* output here             */
   achl_packet = achl_work_1 + iml_len_nhasn;  /* here comes packet    */
   iml1 = iml_len_nhasn + iml_len_packet;   /* length to copy          */
   achl_work_1 += iml1;                     /* here is space for the packet */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* work-area too small     */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
   bol_output = TRUE;                       /* output has been done    */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
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

   p_ipcp_20:                               /* copy part of the packet */
   while (adsl_gai1_inp_start->achc_ginp_cur >= adsl_gai1_inp_start->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   iml2 = adsl_gai1_inp_start->achc_ginp_end - adsl_gai1_inp_start->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl1, adsl_gai1_inp_start->achc_ginp_cur, iml2 );
   achl1 += iml2;
   adsl_gai1_inp_start->achc_ginp_cur += iml2;
   iml1 -= iml2;
   if (iml1) goto p_ipcp_20;                /* copy part of the packet */
   if (iml_len_packet < (2 + 4)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet too short",
                   __LINE__ );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   iml1 = (*((unsigned char *) achl_packet + 1 + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_packet + 1 + 2 + 2 + 1);
   achl1 = achl_packet + 1 + 2 + iml1;
   if (achl1 > (achl_packet + iml_len_packet)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet length invalid",
                   __LINE__ );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   if (   (*(achl_packet + 1 + 2 + 0) < 1)
       || (*(achl_packet + 1 + 2 + 0) > 4)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet code 0X%02X invalid",
                   __LINE__, (unsigned char) *(achl_packet + 2 + 0) );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   achl2 = achl_packet + 1 + 2 + 4;         /* start scanning          */

   p_ipcp_40:                               /* scan option IPCP        */
   if (achl2 == achl1) goto p_check_tcp_00;  /* check TCP packet       */
   if ((achl2 + 2) > achl1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet no space for option",
                   __LINE__ );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   iml1 = (unsigned char) *(achl2 + 1);     /* get length option       */
   if (iml1 < 2) {                          /* length option too short */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet length option %d too short",
                   __LINE__, iml1 );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   achl3 = achl2;                           /* save this position      */
   achl2 += iml1;                           /* after this option       */
   if (achl2 > achl1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet option too long",
                   __LINE__ );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   while (TRUE) {                           /* pseudo-loop             */
     if (*achl3 == 3) break;
     if (   (((unsigned char) *achl3) >= 0X81)
         && (((unsigned char) *achl3) <= 0X84)) {
       break;
     }
     goto p_ipcp_40;                        /* this option IPCP unchanged */
   }
   if (iml1 != (2 + sizeof(UNSIG_MED))) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W PPP IPCP packet length option %d for INETA invalid",
                   __LINE__, iml1 );
     goto p_check_tcp_00;                   /* check TCP packet        */
   }
   memcpy( &uml_ineta_w1, achl3 + 2, sizeof(UNSIG_MED) );
   if (uml_ineta_w1 == 0) goto p_ipcp_40;   /* this option IPCP unchanged */
   if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) != *auml_cnet_so) {
     goto p_ipcp_40;                        /* this option IPCP unchanged */
   }
   uml_ineta_w1 = *auml_cnet_de | (uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_2);
   memcpy( achl3 + 2, &uml_ineta_w1, sizeof(UNSIG_MED) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-T PPP IPCP packet INETA replaced",
                 __LINE__ );
#endif
   goto p_ipcp_40;                          /* scan option IPCP        */

   p_contr_00:                              /* control packet found    */
   if (   (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)
       && (adsl_contr_1->boc_cross_nat == FALSE)) {  /* do not use crosswise NAT */
     goto p_out_00;                         /* end of command          */
   }
   achl_packet++;                           /* after control character '0' */
   achl1 = achl_packet;                     /* here starts control packet */
   iml_len_packet--;                        /* remaining length        */
   achl2 = achl_packet + iml_len_packet;    /* end of control packet   */
   if (achl2 <= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     achl_packet = achl2;                   /* set end of packet       */
     goto p_contr_20;                       /* packet is in one chunk  */
   }
   achl1 = achl2 = chrl_work1;              /* copy to work area       */
   if (iml_len_packet > sizeof(chrl_work1)) iml_len_packet = sizeof(chrl_work1);
   iml1 = iml_len_packet;                   /* length to copy          */

   p_contr_04:                              /* copy one part of the packet */
   while (achl_packet >= adsl_gai1_inp_packet->achc_ginp_end) {  /* end of gather */
     adsl_gai1_inp_packet = adsl_gai1_inp_packet->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_inp_packet == NULL) goto p_illogic_00;  /* program illogic */
     achl_packet = adsl_gai1_inp_packet->achc_ginp_cur;  /* start in gather */
   }
   iml2 = adsl_gai1_inp_packet->achc_ginp_end - achl_packet;  /* length this chunk */
   if (iml2 > iml1) iml2 = iml1;            /* so much to copy         */
   memcpy( achl2, achl_packet, iml2 );
   achl2 += iml2;
   achl_packet += iml2;
   iml1 -= iml2;
   if (iml1) goto p_contr_04;               /* more to copy            */

   p_contr_20:                              /* packet is in one chunk  */
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) goto p_se_contr_00;  /* received control from server */
   achl3 = achl1 + sizeof(ucrs_recv_contr_01);
   if (!memcmp( achl1, ucrs_recv_contr_01, sizeof(ucrs_recv_contr_01) )) {
     goto p_contr_24;                       /* command is valid        */
   }
   if (memcmp( achl1, ucrs_recv_contr_02, sizeof(ucrs_recv_contr_02) )) {
     goto p_out_00;                         /* other command found     */
   }
   achl3 = achl1 + sizeof(ucrs_recv_contr_02);

   p_contr_24:                              /* command is valid        */
   if (achl3 >= achl2) goto p_out_00;       /* end of command found    */
   if (*achl3 != ' ') goto p_out_00;        /* not separated by blank  */

   p_contr_28:                              /* search next keyword     */
   while ((achl3 < achl2) && (*achl3 == ' ')) achl3++;  /* overread spaces */
   if (achl3 >= achl2) goto p_out_00;       /* end of command found    */
#ifdef B110317
   achl4 = (char *) memchr( achl3, ' ', achl2 - achl4 );
#else
   achl4 = (char *) memchr( achl3, ' ', achl2 - achl3 );
#endif
   if (achl4 == NULL) achl4 = achl2;        /* end of control packet   */
   if (memcmp( achl3, ucrs_recv_locineta, sizeof(ucrs_recv_locineta) )) {
     achl3 = achl4;                         /* after this keyword      */
     goto p_contr_28;                       /* search next keyword     */
   }
   achl3 += sizeof(ucrs_recv_locineta);
   iml1 = m_get_ineta_a( &uml_ineta_w1, achl3, achl4 );
   if (iml1) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W LOCAL-INETA=\"%.*s\" invalid",
                   __LINE__, achl4 - achl3, achl3 );
     goto p_out_00;                         /* end of command          */
   }
   if ((uml_ineta_w1 & ADSL_CLCO->umc_cnat_mask_and_1) == ADSL_CLCO->umc_cnat_ineta_real) {
     adsl_contr_1->boc_cross_nat = TRUE;    /* use crosswise NAT       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-I LOCAL-INETA=\"%.*s\" - use crosswise-NAT",
                   __LINE__, achl4 - achl3, achl3 );
   }
   goto p_out_00;                           /* output data unchanged   */

   p_se_contr_00:                           /* received control from server */
   if (   (iml_len_packet <= 15)
       || (memcmp( achl1, "RESPONSE-START ", 15 ))) {
     goto p_out_00;                         /* copy command unchanged  */
   }
   achl2 = achl1 + 15;                      /* scan from here          */
   achl_end = achl1 + iml_len_packet;       /* end of packet           */
   achl5 = NULL;                            /* tunnel-id not found     */
   while (TRUE) {                           /* loop over keywords      */
     while ((achl2 < achl_end) && (*achl2 == ' ')) achl2++;
     if (achl2 >= achl_end) break;
     achl3 = (char *) memchr( achl2, ' ', achl_end - achl2 );
     if (achl3 == NULL) achl3 = achl_end;   /* no space found          */
     achl4 = (char *) memchr( achl2, '=', achl3 - achl2 );
     if (achl4 == NULL) {                   /* no equals found         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W received keyword without \'=\' in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     iml3 = achl4 - achl2;                  /* get length of string    */
     if (iml3 <= 0) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W received keyword length zero before \'=\' in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     if (   (iml3 != 9)
         || (memcmp( achl2, "TUNNEL-ID", 9 ))) {
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     achl4++;                               /* after equals            */
     iml4 = achl3 - achl4;                  /* length of value         */
     if (iml4 <= 0) {                       /* value too short         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W received value too short with keyword \"%.*s\" in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml3, achl2, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     if (achl5) {                           /* tunnel-id already set   */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W received TUNNEL-ID= twice in RESPONSE-START packet \"%.*s\".",
                     __LINE__, iml_len_packet, achl1 );
       achl2 = achl3;                       /* set end of keyword      */
       continue;                            /* ignore this keyword     */
     }
     iml2 = iml4;                           /* set length tunnel-id    */
     achl5 = achl4;                         /* save address tunnel-id  */
     achl2 = achl3;                         /* set end of keyword      */
   }
   if (achl5 == NULL) {                     /* tunnel-id not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-W did not received TUNNEL-ID= in RESPONSE-START packet \"%.*s\".",
                   __LINE__, iml_len_packet, achl1 );
     goto p_out_00;                         /* copy command unchanged  */
   }
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if ((achl_work_1 + D_LEN_RESP_START + iml2) > achl_work_2) {  /* no space for output */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) achl_work_2)
   ADSL_GAI1_G->adsc_next = NULL;           /* set last in chain       */
   bol_output = TRUE;                       /* output has been done    */
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = ADSL_GAI1_G;
#else
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
       adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_G;  /* output data to client */
     } else {                               /* send to server          */
       adsp_hl_clib_1->adsc_gai1_out_to_server = ADSL_GAI1_G;  /* output data to server */
     }
#endif
   } else {
     adsl_gai1_out_2->adsc_next = ADSL_GAI1_G;
   }
   adsl_gai1_out_2 = ADSL_GAI1_G;           /* this is last output     */
   achl_work_1 += 2;                        /* leave space for length  */
   iml1 = sprintf( achl_work_1, "0RESPONSE-START TUNNEL-ID=%.*s \
SERVER-NETWORK-INETA=%d.%d.%d.%d \
SERVER-NETWORK-MASK=%d.%d.%d.%d",
                   iml2, achl5,
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_ineta_translated + 0 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_ineta_translated + 1 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_ineta_translated + 2 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_ineta_translated + 3 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_mask_and_1 + 0 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_mask_and_1 + 1 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_mask_and_1 + 2 ),
                   *((unsigned char *) &ADSL_CLCO->umc_cnat_mask_and_1 + 3 ) );
   achl1 = achl_work_1;                     /* get position output     */
   achl_work_1 += iml1;                     /* after output            */
   if (iml1 < 0X80) {
     *(--achl1) = (unsigned char) iml1;
   } else {
     *(--achl1) = (unsigned char) (iml1 & 0X7F);
     *(--achl1) = (unsigned char) ((iml1 >> 7) | 0X80);
   }
   ADSL_GAI1_G->achc_ginp_cur = achl1;
   ADSL_GAI1_G->achc_ginp_end = achl_work_1;
#undef ADSL_GAI1_G
   /* remove the received packet                                       */
   while (adsl_gai1_inp_start != adsl_gai1_inp_packet) {
     adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
     if (adsl_gai1_inp_start == NULL) goto p_illogic_00;  /* program illogic */
   }
   adsl_gai1_inp_start->achc_ginp_cur = achl_packet;  /* processed so far */
   goto p_check_tcp_00;                     /* check TCP packet        */

   p_out_00:                                /* output data unchanged   */
   /* check if enough space in output area                             */
   iml1 = sizeof(struct dsd_gather_i_1);
   adsl_gai1_inp_w2 = adsl_gai1_inp_start;  /* start from first gather */
   while (adsl_gai1_inp_w2 != adsl_gai1_inp_w1) {
     adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
     if (adsl_gai1_inp_w2 == NULL) goto p_illogic_00;  /* program illogic */
     iml1 += sizeof(struct dsd_gather_i_1);
   }
   if ((achl_work_2 - iml1) < achl_work_1) {  /* not enough space      */
     if (bol_output == FALSE) goto p_out_80;  /* overflow              */
     adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
     return;                                /* to be called again      */
   }
   bol_output = TRUE;                       /* output has been done    */

   p_out_20:                                /* output data unchanged   */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) goto p_out_80;  /* overflow          */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_cur;
   adsl_gai1_out_1->achc_ginp_end = adsl_gai1_inp_start->achc_ginp_end;
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
   if (adsl_gai1_inp_start != adsl_gai1_inp_w1) {
     adsl_gai1_inp_start->achc_ginp_cur = adsl_gai1_inp_start->achc_ginp_end;
     adsl_gai1_inp_start = adsl_gai1_inp_start->adsc_next;
     if (adsl_gai1_inp_start) goto p_out_20;  /* output next part      */
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_gai1_inp_start->achc_ginp_cur = achl_inp;  /* processed so far */
   adsl_gai1_out_1->achc_ginp_end = achl_inp;  /* output only till here */
   goto p_check_tcp_00;                     /* check TCP packet        */

   p_out_80:                                /* overflow in work-area   */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-E p_out_80 overflow work-area", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_inv_data_00:                           /* input data invalid      */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-E p_inv_data_00 input data invalid", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_illogic_00:                            /* program illogic         */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-ppp-pf-04-l%05d-E p_illogic_00 program illogic", __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;
#undef ADSL_CLCO
} /* end m_hlclib01()                                                  */

static int m_get_ineta_w( UNSIG_MED *amp_ineta, HL_WCHAR *awcp_value ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   HL_WCHAR   *awcl1;                       /* working variable        */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */

   iml1 = 0;                                /* first digit             */
   awcl1 = awcp_value;                      /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((*awcl1 >= '0') && (*awcl1 <= '9')) {
     iml2 *= 10;                            /* shift old value         */
     iml2 += *awcl1 - '0';
     if (iml2 >= 256) return -1;
     awcl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return -1;            /* no digit found          */
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (*awcl1 != 0) return -1;            /* too many parts          */
     /* INETA decoded                                                  */
     *amp_ineta = *((UNSIG_MED *) chrl_ineta_w1);
     return 0;                              /* all valid               */
   }
   if (*awcl1 == '.') {                     /* separator found         */
     awcl1++;                               /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return -1;
} /* end m_get_ineta_w()                                               */

/* retrieve INETA of string                                            */
static int m_get_ineta_a( UNSIG_MED *amp_ineta, char *achp_value, char *achp_end ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl1;                       /* working variable        */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */

   iml1 = 0;                                /* first digit             */
   achl1 = achp_value;                      /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((achl1 < achp_end) && (*achl1 >= '0') && (*achl1 <= '9')) {
     iml2 *= 10;                            /* shift old value         */
     iml2 += *achl1 - '0';
     if (iml2 >= 256) return -1;
     achl1++;                               /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return -1;            /* no digit found          */
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (achl1 != achp_end) return -1;      /* too many parts          */
     /* INETA decoded                                                  */
     *amp_ineta = *((UNSIG_MED *) chrl_ineta_w1);
     return 0;                              /* all valid               */
   }
   if (*achl1 == '.') {                     /* separator found         */
     achl1++;                               /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return -1;
} /* end m_get_ineta_a()                                               */

/* subroutine for output to console                                    */
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

/* subroutine to display date and time                                 */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/* subroutine to dump storage-content to console                       */
static void m_sdh_console_out( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                               char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_sdh_console_out()                                           */

/* dump output data from gather structures                             */
static void m_dump_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
  struct dsd_gather_i_1 *adsp_gather_i_1_in,  /* input data            */
  int imp_len_trace_input ) {               /* length trace-input      */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   char       *achl_cur;                    /* position in gather      */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   adsl_gai1_w1 = adsp_gather_i_1_in;
   if (adsl_gai1_w1 == NULL) return;
   achl_cur = adsl_gai1_w1->achc_ginp_cur;
   iml1 = 0;
   while (iml1 < imp_len_trace_input) {
     iml2 = iml1 + 16;
     if (iml2 > imp_len_trace_input) iml2 = imp_len_trace_input;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       while (achl_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         if (adsl_gai1_w1 == NULL) return;
         achl_cur = adsl_gai1_w1->achc_ginp_cur;
       }
       byl1 = *achl_cur++;
       iml1++;
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_dump_gather()                                               */

#ifdef TRACEHL_TIME
/* return the Epoch value in milliseconds                              */
static HL_LONGLONG m_get_epoch_ms( void ) {
#ifndef HL_UNIX
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

   return ( timebuffer.time * 1000 + timebuffer.millitm );
#else
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (dsl_timeval.tv_sec * 1000 + dsl_timeval.tv_usec / 1000);
#endif
} /* end m_get_epoch_ms()                                              */
#endif
