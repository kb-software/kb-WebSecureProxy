#define DEBUG_140402_01                     /* memory-leak PPP authentication */
#ifdef TO_DO_130105
 define TRY_130104_01                       /* problem solved by HSM   */
   needed because no authentication handled out.
   better solution:
   call m_ppp_server_set_inetas() when sending LCP Configuration Ack
   and no authentication
   05.01.13  KB
#endif
#define NOT_YET_AUTH_COMPL                  /* 03.09.12 KB - authentication not yet complete */
#define TRY_111117_01
//#define TRACEHL1
#define TRY_081120
#define TRY_081201
#define TRY_081202
#define TRY_081203
//#define TRY_081204_01
#define TRY_081204_02
#define TRY_120509_01
#define TRY_130104_01                       /* problem solved by HSM   */
#ifdef TRACEHL1
#define TRACEHL_081204
#endif
#ifdef TO_DO
--- 18.10.11 ---
client send to server - not fixed, acquire buffer, xbhpppt3
   achl1 = m_get_wsptun_ineta_ipv4_adapter();  /* get address INETA IPV4 of adapater */
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-ppp                                           |*/
/*| -------------                                                     |*/
/*|  Subroutine which handles PPP in the gateways or clients          |*/
/*|  The Point-to-Point Protocol (PPP) RFC 1661 (rfc1661)             |*/
/*|  to be used in the SSL gateway HOB WebSecureProxy                 |*/
/*|  and in the IPsec components HOBLink VPN                          |*/
/*|  KB 10.11.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   compiler-settings:
     HL_PPP_CLIENT    PPP client only,       for xbhpppt3
     HL_IPSEC_01      not authentication,    for ibipseccl01
*/
/**
   differences in L2TP server behavior:
   start negotiation:
     LINUX:
       L2TP server sends first LCP Configure-Request
     Microsoft:
       L2TP client sends first LCP Configure-Request
   09.05.12  KB
*/
/**
   RFC 1172
     The PPP Internet Protocol Control Protocol (IPCP)
   RFC 1877
     PPP Internet Protocol Control Protocol Extensions for
         Name Server Addresses
*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef OLD01
#include <iostream>
#include <ostream>
#include <fstream>

using namespace std;
#endif

#ifdef TRACEHL1
#define TRACEHL_CO_OUT
#endif
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
#define TRACEHL_CO_OUT
#endif
#ifdef TRACEHL_CO_OUT
extern "C" int m_hl1_printf( char *, ... );
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifdef XYZ2
#include <conio.h>
#endif
#include <time.h>
#ifdef HL_UNIX
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#ifndef HL_LINUX
#include <netinet/in.h>
#endif
//#include <sys/stropts.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
//#include <xti.h>
#ifndef HL_LINUX
#include <unistd.h>
#endif
#include <sys/types.h>
#ifdef HL_OPENUNIX
#include <rpc/types.h>
#endif
#include <sys/ipc.h>
#include <sys/sem.h>
#ifdef HL_LINUX
#include <sys/time.h>
//#include <LiS/sys/xti_ip.h>
#endif
#include <limits.h>
#include <dlfcn.h>
#include "hob-unix01.h"
//#include "hob-xslhcla1.hpp"
//#include "hob-thread.hpp"
#endif
#ifndef HL_UNIX
//#include <wchar.h>
#include <winsock2.h>
#ifdef HL_IPV6
//#include <ws2tcpip.h>
//#include <wspiapi.h>
#endif
//#include <hob-wtspo1.h>
#ifndef B130813
#include <ws2tcpip.h>
#endif
#endif
#include <hob-xslunic1.h>
//#include <hob-xsltime1.h>
#ifndef HL_UNIX
//#include <hob-thread.hpp>
//#include <iswcord1.h>
#endif
//#include "hob-hlwspat2.h"
//#include <hob-wspsu1.h>
#ifndef HL_UNIX
//#include <hob-avl03.h>
#else
//#include "hob-avl03.h"
#endif
#ifndef HL_UNIX
typedef int socklen_t;
#endif

#include "hob-tun01.h"
#include "hob-gw-ppp-1.h"

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif

#define D_SPACE_HEADER       128            /* space for header        */

#define M_STR_HELPER(x) #x
#define M_STR(x) M_STR_HELPER(x)
#define M_DEF_LINE_STR (__LINE__>9999?M_STR(__LINE__):(__LINE__>999?"0"M_STR(__LINE__):(__LINE__>99?"00"M_STR(__LINE__):(__LINE__>9?"000"M_STR(__LINE__):("0000"M_STR(__LINE__))))))

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

typedef void ( * amd_client_auth_send )( struct dsd_ppp_client_1 * );

struct dsd_auth_tab_entry {                 /* entry authentication table */
   const unsigned char *aucc_auth_entry;    /* control sequence        */
// to-do 06.05.12 KB - add length of control sequence ??? - or not needed as part of array
   amd_client_auth_send amc_client_auth_send;  /* routine to be processed */
   enum ied_ppp_auth_def iec_pppa;          /* authentication-methods  */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static void m_ppp_client_send_conf( struct dsd_ppp_client_1 * );
static void m_ppp_server_send_conf( struct dsd_ppp_server_1 * );
static void m_client_auth_send_pap( struct dsd_ppp_client_1 * );
static void m_client_auth_send_chap_1( struct dsd_ppp_client_1 * );
static void m_server_auth_send_mscv2_1( struct dsd_ppp_server_1 * );
static void m_server_auth_send_eap_1( struct dsd_ppp_server_1 * );
static void m_ppp_server_ipcp_pass( struct dsd_ppp_server_1 *, char *, int, BOOL );
#ifdef HL_PPP_CLIENT
static void m_ppp_client_send_ipcp( struct dsd_ppp_client_1 * );
#endif
static void m_ppp_server_set_inetas( struct dsd_ppp_server_1 * );
#ifdef TRACEHL1
static int m_get_date_time( char *achp_buff );
static void m_console_out( char *achp_buff, int implength );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

#ifndef B140325
static const unsigned char ucrs_ctrl_ppp[] = {
   0XFF, 0X03
};
#endif

static const unsigned char ucrs_ctrl_lcp[] = {
   0XC0, 0X21
};

static const unsigned char ucrs_ctrl_ipcp[] = {
   0X80, 0X21
};

#ifdef OLD01
static const unsigned char ucrs_ctrl_ipv6cp[] = {
   0X80, 0X57
};
#endif

static const unsigned char ucrs_send_lcp_prot_rej[] = {
   0XC0, 0X21,                              /* LCP                     */
   0X08                                     /* Protocol-Reject         */
};

static const unsigned char ucrs_send_conf_1[] = {
   0XFF, 0X03,
   0XC0, 0X21,                              /* LCP                     */
   0X01                                     /* Configure-Request       */
};

static const unsigned char ucrs_send_conf_2[] = {
   0X07, 0X02,                              /* 7 / Protocol-Field-Compression PFC */
   0X08, 0X02                               /* 8 / Address-and-Control-Field-Compression ACFC */
};

/* array with minimum and maximum length of the options                */
#ifndef TRY_081201
static const unsigned char ucrs_ppp_opt_len[] = {
   0, 0,                                    /* 0 / invalid             */
   2 + 2, 2 + 2,                            /* 1 / Maximum-Receive-Unit MRU */
   0, 0,                                    /* 2 / invalid             */
   2 + 2, 2 + 8,                            /* 3 / Authentication-Protocol */
   2 + 2, 2 + 8,                            /* 4 / Quality-Protocol    */
   2 + 4, 2 + 4,                            /* 5 / Magic-Number        */
   0, 0,                                    /* 6 / invalid             */
   2 + 0, 2 + 0,                            /* 7 / Protocol-Field-Compression PFC */
   2 + 0, 2 + 0,                            /* 8 / Address-and-Control-Field-Compression ACFC */
};
#else
static const unsigned char ucrs_ppp_opt_len[] = {
   0, 0,                                    /* 0 / invalid             */
   2 + 2, 2 + 2,                            /* 1 / Maximum-Receive-Unit MRU */
   2 + 4, 2 + 4,                            /* 2 / Async-Control-Character-Map RFC 1172 */
   2 + 2, 2 + 8,                            /* 3 / Authentication-Protocol */
   2 + 2, 2 + 8,                            /* 4 / Quality-Protocol    */
   2 + 4, 2 + 4,                            /* 5 / Magic-Number        */
   0, 0,                                    /* 6 / invalid             */
   2 + 0, 2 + 0,                            /* 7 / Protocol-Field-Compression PFC */
   2 + 0, 2 + 0,                            /* 8 / Address-and-Control-Field-Compression ACFC */
};
#endif

static const unsigned char ucrs_auth_prot_pap[] = {
   0X03, 0X04, 0XC0, 0X23
};

/* MS-CHAP-V2                                                          */
static const unsigned char ucrs_auth_prot_chap_1[] = {
   0X03, 0X05, 0XC2, 0X23, 0X81
};

/* EAP                                                                 */
static const unsigned char ucrs_auth_prot_eap_1[] = {
   0X03, 0X04, 0XC2, 0X27
};

#ifdef TRY_081201
static const unsigned char ucrs_four_zero[] = {
   0X00, 0X00, 0X00, 0X00
};
#endif

static const unsigned char ucrs_pap_ack[] = {
   0XC0, 0X23, 0X02, 0XFF, 0X00, 0X0D,
   0X08, 'L', 'o', 'g', 'i', 'n', ' ', 'o', 'k'
};

static const unsigned char ucrs_pap_nak[] = {
   0XC0, 0X23, 0X03, 0XFF, 0X00, 0X14,
   0X0F, 'L', 'o', 'g', 'i', 'n', ' ', 'i', 'n', 'c', 'o', 'r', 'r', 'e', 'c', 't'
};

static const unsigned char ucrs_eap_request_identity[] = {
   0XC2, 0X27, 0X01, 0XFF, 0X00, 0X05,
   0X01
};

static const unsigned char ucrs_eap_nak[] = {
   0X04, 0XFF, 0X00, 0X04
};

static const unsigned char ucrs_eap_ack[] = {
   0XC2, 0X27, 0X03, 0XFF, 0X00, 0X04
};

static const unsigned char ucrs_send_ipcp_confreq_1[] = {
   0X80, 0X21, 0X01, 0X00, 0X00, 0X0A,
   0X03, 0X06
};

#ifdef HL_PPP_CLIENT
static const unsigned char ucrs_send_ipcp_index_ineta[] = {
   3, 129, 130, 131, 132
};
#endif

#ifdef OLD01
static const unsigned char *aucrs_auth_tab[] = {
   ucrs_auth_prot_pap,
   ucrs_auth_prot_chap_1
};
#endif

#ifdef B081121
static const struct dsd_auth_tab_entry dsrs_auth_tab[] = {  /* authentication table */
   {
     ucrs_auth_prot_pap,
     &m_client_auth_send_pap
     ied_pppa_pap                           /* PAP                     */
   },
   {
     ucrs_auth_prot_chap_1,
     &m_client_auth_send_chap_1,
     ied_pppa_ms_chap_v2                    /* MS-CHAP-V2              */
   }
};
#else
static const struct dsd_auth_tab_entry dsrs_auth_tab[] = {  /* authentication table */
   {
     ucrs_auth_prot_pap,
     &m_client_auth_send_pap,
     ied_pppa_pap                           /* PAP                     */
   }
};
#endif


#ifdef TRACEHL1
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_PPP_CLIENT
/** start PPP control sequences on server side, do also on client side if configured */
extern "C" void m_start_ppp_server_cs( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   adsp_ppp_se_1->isc_recv_ident_lcp_conf = -1;  /* received identification LCP configure */
   if (adsp_ppp_se_1->adsc_ppp_cl_1 == NULL) {  /* without PPP client  */
     m_ppp_server_send_conf( adsp_ppp_se_1 );  /* send Configure-Request */
   } else {
     adsp_ppp_se_1->adsc_ppp_cl_1->isc_recv_ident_lcp_conf = -1;  /* received identification LCP configure */
   }
} /* end m_start_ppp_server_cs()                                       */
#endif

#ifdef HL_PPP_CLIENT
/** start PPP control sequences on client side                         */
extern "C" void m_start_ppp_client_cs( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   adsp_ppp_cl_1->isc_recv_ident_lcp_conf = -1;  /* received identification LCP configure */
//#ifdef B111019
   m_ppp_client_send_conf( adsp_ppp_cl_1 );
//#endif
} /* end m_start_ppp_client_cs()                                       */
#endif

/**
  order numbers are not checked for ascending order
  it is not checked if orders are double
*/
/** process PPP control sequence on server side                        */
extern "C" void m_recv_ppp_server_cs( struct dsd_ppp_server_1 *adsp_ppp_se_1,
                                      char *achp_inp, int imp_len_inp ) {
   int        iml1, iml2;                   /* working variables       */
#ifndef B131113
   int        iml_len_userid;               /* length userid           */
   int        iml_len_password;             /* length password         */
#endif
   enum ied_ppp_auth_def iel_ppp_auth;      /* authentication-methods  */
   BOOL       bol_nak;                      /* has to send Nak         */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of input            */
   char       *achl_record;                 /* address of record       */
// char       *achl_auth;                   /* authentication protocol */
// int        iml_remainder;                /* remaining length packet */
   struct dsd_ppp_auth_record *adsl_par_cur;  /* current record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_last;  /* last record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_mscv2_userid;  /* record in storage for authentication */
#ifndef NOT_YET_AUTH_COMPL
   struct dsd_ppp_auth_1 *adsl_auths_p1;    /* for authentication      */
   struct dsd_ppp_auth_1 dsl_auths_s1;      /* for authentication      */
#endif
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */
   union {
     char *   achrl_option_inv[ 16 ];       /* invalid options         */
   };
   char       chrl_buf[ 256 ];              /* buffer for message      */

#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_server_cs( %p , %p , %d ) called",
                 __LINE__, adsp_ppp_se_1, achp_inp, imp_len_inp );
   iml1 = imp_len_inp;
#ifdef B111025
   if (iml1 > 16) iml1 = 16;
#endif
   m_console_out( achp_inp, iml1 );
#endif
#ifndef B150622
   dsl_buf_ve.ac_handle = NULL;             /* no buffer acquired      */
#endif
   if (imp_len_inp <= 2) {                  /* packet too short        */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_rp = achp_inp;                      /* get address input       */
   achl_end = achp_inp + imp_len_inp;       /* compute end input       */
#ifdef B101122
   if ((adsp_ppp_se_1->imc_options & (D_PPP_OPT_CL_ACFC | D_PPP_OPT_SE_ACFC)) != (D_PPP_OPT_CL_ACFC | D_PPP_OPT_SE_ACFC)) {  /* Address-and-Control-Field-Compression (ACFC) */
#ifdef FORKEDIT
   }
#endif
#endif
#ifdef B150622
   dsl_buf_ve.ac_handle = NULL;             /* no buffer acquired      */
#endif
#ifdef B120504
   if ((adsp_ppp_se_1->imc_options & D_PPP_OPT_CL_ACFC) == 0) {  /* Address-and-Control-Field-Compression (ACFC) */
#ifdef FORKEDIT
   }
#endif
#else
   if ((adsp_ppp_se_1->imc_options & D_PPP_OPT_SE_ACFC) == 0) {  /* Address-and-Control-Field-Compression (ACFC) */
#endif
     if ((unsigned char) *achl_rp != 0XFF) {  /* check first control character */
#ifndef NO_D_081115
       iml1 = __LINE__;
#endif
       goto p_inv_00;                       /* packet invalid          */
     }
     achl_rp++;                             /* increment read pointer  */
     if ((unsigned char) *achl_rp != 0X03) {  /* check second control character */
#ifndef NO_D_081115
       iml1 = __LINE__;
#endif
       goto p_inv_00;                       /* packet invalid          */
     }
     achl_rp++;                             /* increment read pointer  */
#ifdef B140325
     if ((achl_end - achl_rp) <= 2) {       /* packet too short        */
#ifndef NO_D_081115
       iml1 = __LINE__;
#endif
       goto p_inv_00;                       /* packet invalid          */
     }
#endif
#ifdef XYZ1
#ifndef NO_D_081115
   } else {
     chrl_buf[0] = 5;
#endif
#endif
#ifndef B140325
   } else {
     if (!memcmp( achl_rp, ucrs_ctrl_ppp, sizeof(ucrs_ctrl_ppp) )) {
       achl_rp += sizeof(ucrs_ctrl_ppp);
     }
#endif
   }
#ifndef B140325
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   if (memcmp( achl_rp, ucrs_ctrl_lcp, sizeof(ucrs_ctrl_lcp) )) {
#ifndef NO_D_081115
     iml1 = __LINE__;
#endif
     goto p_lcp_end;                        /* is not LCP              */
   }
   switch (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp))) {
     case 1:                                /* Configure-Request       */
       goto p_lcp_opt_code_conf_requ;       /* received Configure-Request */
     case 2:                                /* Configure-Ack           */
       adsp_ppp_se_1->imc_options |= (D_PPP_OPT_SE_PFC | D_PPP_OPT_SE_ACFC | D_PPP_OPT_CONF_ACK);  /* Configure-Ack received */
       if (adsp_ppp_se_1->chrc_ppp_auth[ adsp_ppp_se_1->imc_auth_no ] == ((unsigned char) ied_pppa_none)) {  /* no authentication */
         return;
       }
#ifndef B150619
       /* need to check if authentication requested, but not exchanged */
       adsp_ppp_se_1->imc_options |= D_PPP_OPT_SE_AUTH;  /* server requests authentication */
#endif
       adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
       if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
         return;
       }
       switch (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth) {  /* authentication-method in use */
         case ied_pppa_ms_chap_v2:          /* MS-CHAP-V2              */
           /* send authentication for MS-CHAPV2 challenge as server to client */
           m_server_auth_send_mscv2_1( adsp_ppp_se_1 );
           break;
#ifndef B140302
         case ied_pppa_eap:                 /* EAP                     */
           /* send EAP Request Identity as server to client            */
           m_server_auth_send_eap_1( adsp_ppp_se_1 );
           break;
#endif
       }
       return;
     case 3:                                /* Configure-Nak           */
#ifdef B120504
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak" );
       return;
#endif
       goto p_lcp_opt_code_conf_nak;        /* received Configure-Nak  */
     case 4:                                /* Configure-Reject        */
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 4 Configure-Reject" );
       return;
     case 5:                                /* Terminate-Request       */
#ifndef B140325
       goto p_lcp_term_00;                  /* terminate request       */
#endif
     case 6:                                /* Terminate-Ack           */
     case 7:                                /* Code-Reject             */
     case 8:                                /* Protocol-Reject         */
       break;
     case 9:                                /* Echo-Request            */
       goto p_se_lcp_echo_req_00;           /* process LCP Echo-Request */
     case 10:                               /* Echo-Reply              */
     case 11:                               /* Discard-Request         */
//   default:                               /* other value             */
       break;
     case 12:                               /* Identification / not in RFC */
       return;
   }
   sprintf( chrl_buf, "received LCP code %d - unknown",
            *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp)) );
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, chrl_buf );
   return;

   p_lcp_opt_code_conf_requ:                /* received Configure-Request */
#ifndef B140325
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   /* check identifier                                                 */
   if (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1)
         == adsp_ppp_se_1->isc_recv_ident_lcp_conf) {  /* received identification LCP configure */
     return;                                /* ignore this packet      */
   }
   adsp_ppp_se_1->isc_recv_ident_lcp_conf
     = *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1);
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_rp += sizeof(ucrs_ctrl_lcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count invalid options   */
#ifndef TRY_081201
   achl1 = NULL;                            /* no authentication yet   */
#else
   achl1 = achl2 = NULL;                    /* no authentication and no Async-Control-Character-Map */
#endif

   p_lcp_opt_00:                            /* check options LCP       */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml2 = *((unsigned char *) achl_rp);     /* get option type         */
   if (   (iml2 >= (sizeof(ucrs_ppp_opt_len) / sizeof(ucrs_ppp_opt_len[0]) / 2))
       || (ucrs_ppp_opt_len[ iml2 * 2 ] == 0)) {
     if (iml1 >= (sizeof(achrl_option_inv) / sizeof(achrl_option_inv[0]))) {
       goto p_inv_00;                       /* too many invalid options */
     }
     achrl_option_inv[ iml1++ ] = achl_rp;  /* save option invalid     */
   } else {
     if (   (*((unsigned char *) achl_rp + 1) < ucrs_ppp_opt_len[ iml2 * 2 + 0 ])
         || (*((unsigned char *) achl_rp + 1) > ucrs_ppp_opt_len[ iml2 * 2 + 1 ])) {
       goto p_inv_00;                       /* options length invalid  */
     }
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* authentication-protocol */
     achl1 = achl_rp;                       /* save authentication-protocol */
#ifdef TRY_081201
   } else if (*((unsigned char *) achl_rp) == 2) {  /* Async-Control-Character-Map */
     achl2 = achl_rp;                       /* save Async-Control-Character-Map */
#endif
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_lcp_opt_00;                     /* check options LCP       */
   }
   if (iml1 == 0) goto p_lcp_opt_20;        /* all options are valid   */
   /* send Configure-Reject                                            */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, achp_inp, (achl_record - 2) - achp_inp );
   achl2 = dsl_buf_ve.achc_data + (achl_record - achp_inp);
   iml2 = 0;                                /* clear index             */
   do {                                     /* loop output of invalid options */
     if ((achl2 + *((unsigned char *) achrl_option_inv[ iml2 ] + 1)) > achl1) {
       goto p_inv_00;                       /* output packet is too long */
     }
     memcpy( achl2, achrl_option_inv[ iml2 ], *((unsigned char *) achrl_option_inv[ iml2 ] + 1) );
     achl2 += *((unsigned char *) achrl_option_inv[ iml2 ] + 1);
     iml2++;                                /* end of this option      */
   } while (iml2 < iml1);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 4;  /* Configure-Reject */
   iml1 = achl2 - (dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = achl2 - dsl_buf_ve.achc_data;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;

   p_lcp_opt_20:                            /* all options are valid   */
#ifndef TRY_081201
   if (   (achl1 == NULL)                   /* no authentication-protocol */
       || (!memcmp( achl1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) ))) {
     goto p_lcp_opt_40;                     /* Configure-Request is valid */
   }
   /* send Configure-Nak                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1)) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, (achl_record - 2) - achp_inp );
   memcpy( dsl_buf_ve.achc_data + (achl_record - achp_inp), ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) );
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml1 = 4 + sizeof(ucrs_auth_prot_chap_1);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1);  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;
#else
   iml2 = 2;
   if (   (achl1 == NULL)                   /* no authentication-protocol */
       || (!memcmp( achl1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) ))) {
     iml2--;                                /* authentication-protocol is valid */
   }
   if (   (achl2 == NULL)                   /* no Async-Control-Character-Map */
       || (!memcmp( achl2 + 2, ucrs_four_zero, sizeof(ucrs_four_zero) ))) {
     iml2--;                                /* Async-Control-Character-Map is valid */
   }
   if (iml2 == 0) {                         /* all is valid            */
     goto p_lcp_opt_40;                     /* Configure-Request is valid */
   }
   /* send Configure-Nak                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl3 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
// if ((dsl_buf_ve.achc_data + (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1)) > achl3) {
//   goto p_inv_00;                         /* output packet is too long */
// }
   memcpy( dsl_buf_ve.achc_data, achp_inp, (achl_record - 2) - achp_inp );
   iml1 = 0;                                /* no data yet             */
   if (   (achl2)                           /* with Async-Control-Character-Map */
       && (memcmp( achl2 + 2, ucrs_four_zero, sizeof(ucrs_four_zero) ))) {
     *(dsl_buf_ve.achc_data + (achl_record - achp_inp) + 0) = (unsigned char) 2;  /* Async-Control-Character-Map */
     *(dsl_buf_ve.achc_data + (achl_record - achp_inp) + 1) = (unsigned char) (2 + sizeof(ucrs_four_zero));  /* length of option */
     memcpy( dsl_buf_ve.achc_data + (achl_record - achp_inp) + 2, ucrs_four_zero, sizeof(ucrs_four_zero) );
     iml1 = 2 + sizeof(ucrs_four_zero);     /* after this option       */
   }
   if (   (achl1)                           /* with authentication-protocol */
       && (memcmp( achl1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) ))) {
     memcpy( dsl_buf_ve.achc_data + (achl_record - achp_inp) + iml1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) );
     iml1 += sizeof(ucrs_auth_prot_chap_1);  /* after this option      */
   }
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml1 += 4;                               /* add length header       */
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = (achl_record - achp_inp) - 4 + iml1;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;
#endif

   p_lcp_opt_40:                            /* Configure-Request is valid */
   if (achl1) {                             /* with valid authentication-protocol */
     adsp_ppp_se_1->imc_options |= D_PPP_OPT_CL_AUTH;  /* client requests authentication */
   }
   achl_rp = achl_record;                   /* restore address of record */

   p_lcp_opt_44:                            /* set option value        */
   switch (*((unsigned char *) achl_rp)) {  /* check option type       */
     case 1:                                /* 1 / Maximum-Receive-Unit MRU */
       adsp_ppp_se_1->umc_mtc_cl = (*((unsigned char *) achl_rp + 2 + 0) << 8)
                                     | *((unsigned char *) achl_rp + 2 + 1);
       break;
     case 5:                                /* 5 / Magic-Number        */
       memcpy( adsp_ppp_se_1->chrc_magic_number_cl, achl_rp + 2, sizeof(adsp_ppp_se_1->chrc_magic_number_cl) );
       break;
     case 7:                                /* 7 / Protocol-Field-Compression PFC */
       adsp_ppp_se_1->imc_options |= D_PPP_OPT_CL_PFC;  /* Protocol-Field-Compression (PFC) */
       break;
     case 8:                                /* 8 / Address-and-Control-Field-Compression ACFC */
       adsp_ppp_se_1->imc_options |= D_PPP_OPT_CL_ACFC;  /* Address-and-Control-Field-Compression (ACFC) */
       break;
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_lcp_opt_44;                     /* set option value        */
   }
   if ((adsp_ppp_se_1->imc_options & (D_PPP_OPT_CL_PFC | D_PPP_OPT_CL_ACFC)) != (D_PPP_OPT_CL_PFC | D_PPP_OPT_CL_ACFC)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 1 Configure-Request without PCF / ACFC" );
     return;
   }
   /* send Configure-Ack                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, imp_len_inp );
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 2;  /* Configure-Ack */
   dsl_buf_ve.imc_len_data = imp_len_inp;   /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
#ifndef HL_PPP_CLIENT
#ifndef TRY_081202
   if (adsp_ppp_se_1->adsc_ppp_cl_1 == NULL) return;
   m_ppp_client_send_conf( adsp_ppp_se_1->adsc_ppp_cl_1 );
#endif
#ifdef TRY_120509_01
   if (adsp_ppp_se_1->adsc_ppp_cl_1 == NULL) return;
   if (adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_CONF_ACK) return;  /* Configure-Ack received */
   m_ppp_client_send_conf( adsp_ppp_se_1->adsc_ppp_cl_1 );
#endif
#endif
   return;

   p_lcp_opt_code_conf_nak:                 /* received Configure-Nak  */
#ifndef B140325
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
#ifdef XYZ1
   /* check identifier                                                 */
   if (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1)
         == adsp_ppp_se_1->isc_recv_ident_lcp_conf) {  /* received identification LCP configure */
     return;                                /* ignore this packet      */
   }
   adsp_ppp_se_1->isc_recv_ident_lcp_conf
     = *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1);
#endif
   if (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1)
           != adsp_ppp_se_1->ucc_send_ident_lcp_conf) {  /* sent identification LCP configure */
     return;                                /* ignore this packet      */
   }
   if (adsp_ppp_se_1->imc_options & D_PPP_OPT_CONF_ACK) {  /* Configure-Ack received */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_rp += sizeof(ucrs_ctrl_lcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count invalid options   */
   achl1 = NULL;                            /* no authentication yet   */

   p_lcp_nak_00:                            /* check options LCP Nak   */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* authentication-protocol */
     if (achl1) {                           /* option double           */
       goto p_inv_00;                       /* packet invalid          */
     }
     achl1 = achl_rp;                       /* save authentication-protocol */
   } else {
     iml1++;                                /* count option not recognized */
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
#ifdef B150610
     goto p_lcp_opt_00;                     /* check options LCP       */
#endif
#ifndef B150610
     goto p_lcp_nak_00;                     /* check options LCP Nak   */
#endif
   }
   if (iml1 > 0) {                          /* options not recognized found */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak - options not recognized" );
     return;
   }
   if (achl1 == NULL) {                     /* option authentication-protocol not found */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak - no option authentication-protocol" );
     return;
   }
   if (!memcmp( achl1, ucrs_auth_prot_pap, sizeof(ucrs_auth_prot_pap) )) {
     iel_ppp_auth = ied_pppa_pap;           /* PAP                     */
   } else if (!memcmp( achl1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) )) {
     iel_ppp_auth = ied_pppa_ms_chap_v2;    /* MS-CHAP-V2              */
#ifndef B140302
   } else if (!memcmp( achl1, ucrs_auth_prot_eap_1, sizeof(ucrs_auth_prot_eap_1) )) {
     iel_ppp_auth = ied_pppa_eap;           /* EAP                     */
#endif
   } else {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak - authentication-protocol received not supported" );
     return;
   }
   iml1 = DEF_NO_PPP_AUTH - 1;              /* index of last element   */
   do {                                     /* loop to find configured authentication-protocol */
     if (((unsigned char) iel_ppp_auth) == adsp_ppp_se_1->chrc_ppp_auth[ iml1 ]) break;
     iml1--;
   } while (iml1 >= 0);
   if (iml1 < 0) {                          /* authentication-protocol not configured */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak - authentication-protocol received not configured" );
     return;
   }
   if (iml1 == adsp_ppp_se_1->imc_auth_no) {  /* authentication-protocol already sent */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received LCP code 3 Configure-Nak - authentication-protocol received already sent" );
     return;
   }
   adsp_ppp_se_1->imc_auth_no = iml1;       /* try this authentication-protocol */
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   m_ppp_server_send_conf( adsp_ppp_se_1 );  /* send new Configure-Request */
   return;                                  /* wait for response       */

   p_se_lcp_echo_req_00:                    /* process LCP Echo-Request */
#ifndef B140325
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (iml1 != (4 + sizeof(adsp_ppp_se_1->chrc_magic_number_cl))) goto p_inv_00;  /* packet invalid */
   if (memcmp( achl_rp + sizeof(ucrs_ctrl_lcp) + 4,
               adsp_ppp_se_1->chrc_magic_number_cl,
               sizeof(adsp_ppp_se_1->chrc_magic_number_cl) )) {
     goto p_inv_00;                         /* packet invalid          */
   }
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_lcp) + 4 + sizeof(adsp_ppp_se_1->chrc_magic_number_se)) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, ucrs_ctrl_lcp, sizeof(ucrs_ctrl_lcp) );
   *(dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_lcp) + 0) = 10;  /* Echo-Reply */
   *(dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_lcp) + 1) = *(achl_rp + sizeof(ucrs_ctrl_lcp) + 1);  /* copy identifier */
   *(dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_lcp) + 2 + 0) = 0;  /* first byte length */
   *(dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_lcp) + 2 + 1) = (unsigned char) (4 + sizeof(adsp_ppp_se_1->chrc_magic_number_se));  /* second byte length */
   dsl_buf_ve.imc_len_data = sizeof(ucrs_ctrl_lcp) + 4 + sizeof(adsp_ppp_se_1->chrc_magic_number_se);  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

#ifndef B140325
   p_lcp_term_00:                           /* terminate request       */
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   /* send Terminate-Ack                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, imp_len_inp );
   *(dsl_buf_ve.achc_data + ((achl_rp + sizeof(ucrs_ctrl_lcp) + 0) - achp_inp)) = (unsigned char) 6;  /* Terminate-Ack */
   dsl_buf_ve.imc_len_data = imp_len_inp;   /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received Terminate-Request - connection ended" );
   return;
#endif

   p_lcp_end:                               /* is not LCP              */
   if (memcmp( achl_rp, ucrs_auth_prot_pap + 2, 2 )) {
#ifdef B120505
     goto p_auth_end;                       /* is not authentication   */
#endif
     goto p_chap_00;                        /* check if CHAP authentication */
   }
   switch (*((unsigned char *) achl_rp + 2)) {
     case 1:                                /* Authenticate-Request    */
       break;
     default:                               /* other Code              */
       goto p_inv_00;                       /* packet is invalid       */
   }
#ifdef B120505
   if (adsp_ppp_se_1->adsc_ppp_auth_1) {    /* authentication parameters already set */
     return;                                /* discard this record     */
   }
#endif
   if (adsp_ppp_se_1->imc_options & D_PPP_OPT_AUTH_OK) {  /* authentication succeeded before */
     return;                                /* discard this record     */
   }
   iml1 = (*((unsigned char *) achl_rp + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + 2 + 2 + 1);
   if ((achl_rp + 2 + iml1) != achl_end) {  /* length is invalid       */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef B131113
#ifndef NOT_YET_AUTH_COMPL
   achl_record = achl_rp;                   /* save address of record  */
   dsl_auths_s1.chc_ident = *((unsigned char *) achl_rp + 2 + 1);  /* save ident */
   achl_rp += 2 + 2 + 2;                    /* Peer-ID Length          */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   dsl_auths_s1.imc_len_userid = (unsigned char) *achl_rp;  /* get length userid */
#ifndef HL_IPSEC_01
   if (dsl_auths_s1.imc_len_userid == 0) {  /* userid too short        */
     goto p_inv_00;                         /* packet is invalid       */
   }
#endif
   if ((achl_rp + 1 + dsl_auths_s1.imc_len_userid) >= achl_end) {  /* userid too long */
     goto p_inv_00;                         /* packet is invalid       */
   }
   dsl_auths_s1.imc_len_password = *((unsigned char *) achl_rp + 1 + dsl_auths_s1.imc_len_userid);  /* get length password */
#ifndef HL_IPSEC_01
   if (dsl_auths_s1.imc_len_password == 0) {  /* password too short    */
     goto p_inv_00;                         /* packet is invalid       */
   }
#endif
   if ((achl_rp + 1 + dsl_auths_s1.imc_len_userid + 1 + dsl_auths_s1.imc_len_password) != achl_end) {  /* length not correct */
     goto p_inv_00;                         /* packet is invalid       */
   }
#ifdef B120505
   dsl_auths_s1.iec_chs_auth = ied_chs_ansi_819;  /* character set authentication */
   adsl_auths_p1 = (struct dsd_ppp_auth_1 *) malloc( sizeof(struct dsd_ppp_auth_1)
                                                       + dsl_auths_s1.imc_len_userid
                                                       + dsl_auths_s1.imc_len_password );
   memcpy( adsl_auths_p1, &dsl_auths_s1, sizeof(struct dsd_ppp_auth_1) );
   memcpy( adsl_auths_p1 + 1, achl_rp + 1, dsl_auths_s1.imc_len_userid );  /* copy userid */
   memcpy( (char *) (adsl_auths_p1 + 1) + dsl_auths_s1.imc_len_userid,
           achl_rp + 1 + dsl_auths_s1.imc_len_userid + 1,
           dsl_auths_s1.imc_len_password );  /* copy password          */
   adsp_ppp_se_1->adsc_ppp_auth_1 = adsl_auths_p1;  /* authentication parameters */
#endif
#ifndef HL_IPSEC_01
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;
#endif
#ifdef HL_IPSEC_01
   Sleep( 200 );
   m_auth_compl_ppp_server( adsp_ppp_se_1, ied_pppar_ok );  /* authentication was checked O.K. */
   return;
#endif
#else
#ifdef HL_IPSEC_01
   Sleep( 200 );
   m_auth_compl_ppp_server( adsp_ppp_se_1, ied_pppar_ok );  /* authentication was checked O.K. */
   return;
#else
     goto p_inv_00;                         /* packet invalid          */
#endif
#endif
#endif
#ifndef B131113
   iml2 = *((unsigned char *) achl_rp + 2 + 1);  /* save ident         */
   achl_rp += 2 + 2 + 2;                    /* Peer-ID Length          */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml_len_userid = (unsigned char) *achl_rp;  /* get length userid    */
#ifndef HL_IPSEC_01
   if (iml_len_userid == 0) {               /* userid too short        */
     goto p_inv_00;                         /* packet is invalid       */
   }
#endif
   if ((achl_rp + 1 + iml_len_userid) >= achl_end) {  /* userid too long */
     goto p_inv_00;                         /* packet is invalid       */
   }
   iml_len_password = *((unsigned char *) achl_rp + 1 + iml_len_userid);  /* get length password */
#ifndef HL_IPSEC_01
   if (iml_len_password == 0) {             /* password too short      */
     goto p_inv_00;                         /* packet is invalid       */
   }
#endif
   if ((achl_rp + 1 + iml_len_userid + 1 + iml_len_password) != achl_end) {  /* length not correct */
     goto p_inv_00;                         /* packet is invalid       */
   }
#ifndef HL_IPSEC_01
   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "l" M_STR(M_DEF_LINE_STR) " received PAP authentication - no storage for authentication - illogic" );
     return;
   }
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_pap) {  /* authentication-method in use - PAP */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "l" M_STR(M_DEF_LINE_STR) " received PAP authentication - authentication-method not PAP" );
     return;
   }
   adsp_ppp_se_1->adsc_ppp_auth_header->chc_ident = (unsigned char) iml2;  /* ident received */
   /* all previous authentication records can be overwritten           */
   adsl_par_cur = (struct dsd_ppp_auth_record *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* record in storage for authentication */
// adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_userid;  /* type of authentication record - userid */
   adsl_par_cur->imc_len_data = iml_len_userid;  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   memcpy( AUCL_PAR_DATA, achl_rp + 1, iml_len_userid );
#undef AUCL_PAR_DATA
   adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_cur;  /* chain of records in storage for authentication */
   adsl_par_last = adsl_par_cur;            /* save last in chain      */
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) ((char *) (adsl_par_last + 1) + adsl_par_last->imc_len_data + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record) + iml_len_password)
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 01" );
     return;
   }
   adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_password;  /* password (PAP)        */
   adsl_par_cur->imc_len_data = iml_len_password;  /* length password  */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   memcpy( AUCL_PAR_DATA, achl_rp + 1 + iml_len_userid + 1, iml_len_password );
#undef AUCL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain        */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;                                  /* wait for authentication to be completed */
#else
   Sleep( 200 );
   m_auth_compl_ppp_server( adsp_ppp_se_1, ied_pppar_ok );  /* authentication was checked O.K. */
   return;
#endif
#endif

   p_chap_00:                               /* check if CHAP authentication */
   if (memcmp( achl_rp, ucrs_auth_prot_chap_1 + 2, 2 )) {
#ifdef B140302
     goto p_auth_end;                       /* is not authentication   */
#else
     goto p_eap_00;                         /* check if EAP authentication */
#endif
   }
   if (*((unsigned char *) achl_rp + 2 + 1)
           != adsp_ppp_se_1->ucc_send_ident_lcp_conf) {  /* sent identification LCP configure */
     return;                                /* ignore this packet      */
   }
   if ((adsp_ppp_se_1->imc_options & D_PPP_OPT_CONF_ACK) == 0) {  /* Configure-Ack not received */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml1 = (*((unsigned char *) achl_rp + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + 2 + 2 + 1);
   if ((achl_rp + 2 + iml1) != achl_end) {  /* length is invalid       */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef XYZ1
   if (iml1 <= 0) {                         /* length too short        */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - no storage for authentication - illogic" );
     return;
   }
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_ms_chap_v2) {  /* authentication-method in use - MS-CHAP-V2 */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method not MS-CHAP-V2" );
     return;
   }
   switch (*((unsigned char *) achl_rp + 2 + 0)) {  /* check code response */
     case 2:
       goto p_chap_20;                      /* received CHAP authentication response */
     case 7:
       goto p_chap_40;                      /* received CHAP authentication change password */
   }
// to-do 09.05.12 KB - va_list - %d with code
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - received code not supported" );
   return;

   p_chap_20:                               /* received CHAP authentication response */
   if (iml1 < (4 + LEN_MSCV2_RESPONSE + 1 + 1)) {  /* length too short */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 2 + 2 + 1 + 1) != (LEN_MSCV2_RESPONSE + 1)) {  /* length MS-CHAP-V2 response */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 2 + 2 + 1 + 1 + 1 + LEN_MSCV2_RESPONSE) != 0) {  /* after MS-CHAP-V2 response */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (adsp_ppp_se_1->adsc_ppp_auth_header->vpc_radius) {  /* Radius authentication active */
     return;                                /* nothing to do           */
   }
   /* create two records in storage for authentication, delete old records */
   adsl_par_last = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   if (   (adsl_par_last == NULL)
       || (adsl_par_last->iec_par != ied_par_mscv2_challenge)) {  /* MS-CHAP-V2 challenge */
// to-do 09.05.12 KB va-list - add __LINE__
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 01" );
     return;
   }
#ifdef XYZ1
   achl1 = (char *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* end of storage used */
   adsl_par_last = NULL;                    /* clear last in chain     */
   while (adsl_par_cur) {                   /* loop over records in storage for authentication */
     achl2 = (char *) (adsl_par_cur + 1) + adsl_par_cur->imc_len_data;  /* end of this record */
     if (achl2 > achl1) achl1 = achl2;      /* in use till here        */
     adsl_par_last = adsl_par_cur;          /* save last in chain      */
     adsl_par_cur = adsl_par_cur->adsc_next;  /* get next in chain     */
   }
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) (achl1 + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
#endif
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) ((char *) (adsl_par_last + 1) + adsl_par_last->imc_len_data + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record)
             + (iml1 - (2 + 1 + 1 + 1 + LEN_MSCV2_RESPONSE + 1)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 02" );
     return;
   }
// adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_userid;  /* type of authentication record - userid */
   adsl_par_cur->imc_len_data = iml1 - (2 + 1 + 1 + 1 + LEN_MSCV2_RESPONSE + 1);  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   memcpy( AUCL_PAR_DATA, achl_rp + 2 + 2 + 1 + 1 + 1 + LEN_MSCV2_RESPONSE + 1, adsl_par_cur->imc_len_data );
#undef AUCL_PAR_DATA
   if (adsl_par_last == NULL) {             /* at beginning of chain   */
     adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_cur;  /* chain of records in storage for authentication */
   } else {                                 /* append to chain         */
     adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain      */
   }
   adsl_par_last = adsl_par_cur;            /* save last in chain      */
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) ((char *) (adsl_par_last + 1) + adsl_par_last->imc_len_data + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record) + LEN_MSCV2_RESPONSE)
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 03" );
     return;
   }
   adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_mscv2_response;  /* type of authentication record - MS-CHAP-V2 response */
   adsl_par_cur->imc_len_data = LEN_MSCV2_RESPONSE;  /* length MS-CHAP-V2 response */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   memcpy( AUCL_PAR_DATA, achl_rp + 2 + 2 + 1 + 1 + 1, LEN_MSCV2_RESPONSE );
#undef AUCL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain        */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;                                  /* wait for authentication to be completed */

   p_chap_40:                               /* received CHAP authentication change password */
/**
   attention:
   in the packet of change password, there is no more userid,
   so the userid needs to be used from the previous authentication response
*/
   if (iml1 != (4 + LEN_MSCV2_CHANGE_PWD)) {  /* length MS-CHAP-V2 change password */
     goto p_inv_00;                         /* packet invalid          */
   }
   adsl_par_cur = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   if (   (adsl_par_cur == NULL)
       || (adsl_par_cur->iec_par != ied_par_mscv2_challenge)) {  /* MS-CHAP-V2 challenge */
// to-do 09.05.12 KB va-list - add __LINE__
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 02" );
     return;
   }
   adsl_par_last = adsl_par_cur->adsc_next;  /* next in chain of records in storage for authentication */
   if (   (adsl_par_last == NULL)
       || (adsl_par_last->iec_par != ied_par_userid)) {  /* type of authentication record - userid */
// to-do 09.05.12 KB va-list - add __LINE__
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received CHAP response - authentication-method MS-CHAP-V2 storage for authentication invalid 03" );
     return;
   }
   /* create one record in storage for authentication, delete old records */
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) ((char *) (adsl_par_last + 1) + adsl_par_last->imc_len_data + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record) + LEN_MSCV2_CHANGE_PWD)
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 04" );
     return;
   }
   adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_mscv2_change_pwd;  /* MS-CHAP-V2 change password */
   adsl_par_cur->imc_len_data = LEN_MSCV2_CHANGE_PWD;  /* length MS-CHAP-V2 change password */
#define ACHL_PAR_DATA ((char *) (adsl_par_cur + 1))
   memcpy( ACHL_PAR_DATA, achl_rp + 2 + 2 + 1 + 1, LEN_MSCV2_CHANGE_PWD );  /* length MS-CHAP-V2 change password */
#undef ACHL_PAR_DATA
   adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain        */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;                                  /* wait for authentication to be completed */

#ifndef B140302
   p_eap_00:                                /* check if EAP authentication */
   if (memcmp( achl_rp, ucrs_auth_prot_eap_1 + 2, 2 )) {
     goto p_auth_end;                       /* is not authentication   */
   }
//#ifdef NOT_YET_140323
   if (*((unsigned char *) achl_rp + 2 + 1)
           != adsp_ppp_se_1->ucc_send_ident_lcp_conf) {  /* sent identification LCP configure */
     return;                                /* ignore this packet      */
   }
//#endif
   if ((adsp_ppp_se_1->imc_options & D_PPP_OPT_CONF_ACK) == 0) {  /* Configure-Ack not received */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml1 = (*((unsigned char *) achl_rp + 2 + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + 2 + 2 + 1);
   if ((achl_rp + 2 + iml1) != achl_end) {  /* length is invalid       */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef XYZ1
   if (iml1 <= 0) {                         /* length too short        */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - no storage for authentication - illogic" );
     return;
   }
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_eap) {  /* authentication-method in use - EAP */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - authentication-method not EAP" );
     return;
   }
   switch (*((unsigned char *) achl_rp + 2 + 0)) {  /* check code response */
     case 2:
       goto p_eap_20;                       /* received CHAP authentication response */
#ifdef XYZ1
     case 7:
       goto p_chap_40;                      /* received CHAP authentication change password */
#endif
   }
// to-do 09.05.12 KB - va_list - %d with code
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - received code not supported" );
   return;

   p_eap_20:                                /* received EAP authentication response */
   if ((achl_rp + 2 + 4 + 1) > achl_end) {  /* received field type     */
     goto p_inv_00;                         /* packet is invalid       */
   }
#define UCL_EAP_TYPE *((unsigned char *) achl_rp + 2 + 4)
#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_server_cs( %p , %p , %d ) p_eap_20: UCL_EAP_TYPE %d.",
                 __LINE__, adsp_ppp_se_1, achp_inp, imp_len_inp, UCL_EAP_TYPE );
   m_console_out( achl_rp, 2 + iml1 );
#endif
#ifdef XYZ1
   if (   (UCL_EAP_TYPE != 1)               /* type not identity       */
       && (UCL_EAP_TYPE != D_PPP_EAP_MS_AUTH)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - invalid type" );
     return;
   }
#endif
   achl1 = (char *) (adsp_ppp_se_1->adsc_ppp_auth_header + 1);  /* end of storage used */
   adsl_par_cur = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   adsl_par_last = NULL;                    /* clear last in chain     */
#ifdef XYZ1
   adsl_par_mscv2_userid = NULL;            /* record in storage for authentication */
#endif
   while (adsl_par_cur) {                   /* loop over records in storage for authentication */
     if (adsl_par_cur->iec_par == ied_par_userid) {  /* type of authentication record - userid */
       if (UCL_EAP_TYPE == 1) {             /* type identity           */
         adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - received identity - userid double" );
         return;                            /* all done                */
       }
#ifdef XYZ1
       if (adsl_par_mscv2_userid != NULL) {  /* check userid / identity double */
         adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received EAP response - stored identity double - illogic" );
         return;                            /* all done                */
       }
       adsl_par_mscv2_userid = adsl_par_cur;  /* record in storage for authentication */
#endif
     }
     achl2 = (char *) (adsl_par_cur + 1) + adsl_par_cur->imc_len_data;  /* end of this record */
     if (achl2 > achl1) achl1 = achl2;      /* in use till here        */
     adsl_par_last = adsl_par_cur;          /* save last in chain      */
     adsl_par_cur = adsl_par_cur->adsc_next;  /* get next in chain     */
   }
   if (UCL_EAP_TYPE != 1) {                 /* type not identity       */
     goto p_eap_40;                         /* received EAP other packet */
   }
#undef UCL_EAP_TYPE
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) (achl1 + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record)
             + (iml1 - (2 + 1 + 1 + 1)))
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 05" );
     return;
   }
   adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_userid;  /* type of authentication record - userid */
   adsl_par_cur->imc_len_data = iml1 - (2 + 1 + 1 + 1);  /* length of the data */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   if (adsl_par_cur->imc_len_data > 0) {
     memcpy( AUCL_PAR_DATA, achl_rp + 2 + 2 + 1 + 1 + 1, adsl_par_cur->imc_len_data );
   }
#undef AUCL_PAR_DATA
   if (adsl_par_last == NULL) {             /* at beginning of chain   */
     adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_cur;  /* chain of records in storage for authentication */
   } else {                                 /* append to chain         */
     adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain      */
   }
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;                                  /* wait for authentication to be completed */

   p_eap_40:                                /* received EAP other packet */
   adsl_par_cur = (struct dsd_ppp_auth_record *)
                    ((long long int) (achl1 + sizeof(void *) - 1)
                       & (0 - sizeof(void *)));
   if (((char *) adsl_par_cur + sizeof(struct dsd_ppp_auth_record) + iml1)
         > adsp_ppp_se_1->adsc_ppp_auth_header->achc_stor_end) {  /* end of this storage */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "storage for authentication data exceeded 06" );
     return;
   }
   adsl_par_cur->adsc_next = NULL;          /* clear chain             */
   adsl_par_cur->iec_par = ied_par_eap_recv_1;  /* EAP received and not yet processed */
   adsl_par_cur->imc_len_data = iml1;       /* length of the data      */
#define AUCL_PAR_DATA ((unsigned char *) (adsl_par_cur + 1))
   memcpy( AUCL_PAR_DATA, achl_rp + 2, iml1 );
#undef AUCL_PAR_DATA
   if (adsl_par_last == NULL) {             /* at beginning of chain   */
     adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record = adsl_par_cur;  /* chain of records in storage for authentication */
   } else {                                 /* append to chain         */
     adsl_par_last->adsc_next = adsl_par_cur;  /* append to chain      */
   }
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   return;                                  /* wait for authentication to be completed */

   p_eap_60:                                /* received EAP MS-AUTH part two */
   return;
#endif

   p_auth_end:                              /* is not authentication   */
   if (memcmp( achl_rp, ucrs_ctrl_ipcp, sizeof(ucrs_ctrl_ipcp) )) {
#ifndef NO_D_081115
     iml1 = __LINE__;
#endif
#ifdef TRACEHL1
     m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_server_cs() p_auth_end:",
                   __LINE__ );
     m_console_out( achl_rp, sizeof(ucrs_ctrl_ipcp) );
#endif
     goto p_ipcp_end;                       /* is not IPCP             */
   }
   switch (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp))) {
     case 1:                                /* Configure-Request       */
       goto p_ipcp_opt_code_conf_requ;      /* received Configure-Request */
     case 2:                                /* Configure-Ack           */
//     adsp_ppp_se_1->imc_options |= (D_PPP_OPT_SE_PFC | D_PPP_OPT_SE_ACFC | D_PPP_OPT_CONF_ACK);  /* Configure-Ack received */
       return;
     case 3:                                /* Configure-Nak           */
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received IPCP code 3 Configure-Nak" );
       return;
     case 4:                                /* Configure-Reject        */
       adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received IPCP code 4 Configure-Reject" );
       return;
     case 5:                                /* Terminate-Request       */
     case 6:                                /* Terminate-Ack           */
     case 7:                                /* Code-Reject             */
     case 8:                                /* Protocol-Reject         */
     case 9:                                /* Echo-Request            */
     case 10:                               /* Echo-Reply              */
     case 11:                               /* Discard-Request         */
//   default:                               /* other value             */
       break;
//   case 12:                               /* not in RFC              */
//     return;
   }
   sprintf( chrl_buf, "received IPCP code %d - unknown",
            *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp)) );
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, chrl_buf );
   return;

   p_ipcp_opt_code_conf_requ:               /* received Configure-Request */
#ifdef OLD01
   /* check identifier                                                 */
   if (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1)
         == adsp_ppp_se_1->isc_recv_ident_lcp_conf) {  /* received identification LCP configure */
     return;                                /* ignore this packet      */
   }
   adsp_ppp_se_1->isc_recv_ident_lcp_conf
     = *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1);
#endif
#ifndef B140325
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef TRY_130104_01                        /* problem solved by HSM   */
   /* KB 04.01.13 - should not be set here, should have been set before. */
   /* this point in the program may be passed multiple times, but m_ppp_server_set_inetas() should be called only once. */
   /* may problem because of authentication MS-CHAP-V2. */
   m_ppp_server_set_inetas( adsp_ppp_se_1 );  /* begin IPCP            */
#endif
   if (   (adsp_ppp_se_1->adsc_ppp_cl_1)    /* with PPP client         */
       && ((adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_SEND) == 0)) {  /* IPCP send INETAS not complete */
#ifdef TRACEHL_081204
     m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_recv_ppp_server_cs() call m_ppp_server_ipcp_pass() imc_options=0X%08X",
                   __LINE__, adsp_ppp_se_1->adsc_ppp_cl_1->imc_options );
#endif
     m_ppp_server_ipcp_pass( adsp_ppp_se_1, achp_inp, imp_len_inp, FALSE );
     return;                                /* all done                */
   }
   achl_rp += sizeof(ucrs_ctrl_lcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count invalid options   */
   achl1 = NULL;                            /* no INETA yet            */
   bol_nak = FALSE;                         /* do not send Nak         */

   p_ipcp_opt_00:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml2 = -1;                               /* invalid option number   */
   if (*((unsigned char *) achl_rp) == 3) {  /* option type INETA      */
     iml2 = 0;
     if (achl1) {                           /* INETA already set       */
       goto p_inv_00;                       /* options length invalid  */
     }
     achl1 = achl_rp;                       /* save INETA              */
   } else if (   (*((unsigned char *) achl_rp) >= 129)
              && (*((unsigned char *) achl_rp) <= 132)) {
     iml2 = *((unsigned char *) achl_rp) - 129 + 1;
   }
   while (iml2 >= 0) {                      /* valid INETA found       */
     if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {
       goto p_inv_00;                       /* options length invalid  */
     }
     if ((adsp_ppp_se_1->chrc_ineta_stat[ iml2 ] & D_INETA_OPT_SET) == 0) {  /* INETA not set for IPCP */
       iml2 = -1;                           /* send option in Configure-Reject */
       break;
     }
     if (!memcmp( achl_rp + 2, &adsp_ppp_se_1->chrrc_ineta[ iml2 ][0], sizeof(UNSIG_MED) )) break;
     bol_nak = TRUE;                        /* do send Nak             */
     break;
   }
   if (iml2 < 0) {                          /* is not INETA            */
     if (iml1 >= (sizeof(achrl_option_inv) / sizeof(achrl_option_inv[0]))) {
       goto p_inv_00;                       /* too many invalid options */
     }
     achrl_option_inv[ iml1++ ] = achl_rp;  /* save option invalid     */
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_opt_00;                    /* check options IPCP      */
   }
   if (iml1 == 0) goto p_ipcp_opt_20;       /* all options are valid   */
   /* send Configure-Reject                                            */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, achp_inp, (achl_record - 2) - achp_inp );
   achl2 = dsl_buf_ve.achc_data + (achl_record - achp_inp);
   iml2 = 0;                                /* clear index             */
   do {                                     /* loop output of invalid options */
     if ((achl2 + *((unsigned char *) achrl_option_inv[ iml2 ] + 1)) > achl1) {
       goto p_inv_00;                       /* output packet is too long */
     }
     memcpy( achl2, achrl_option_inv[ iml2 ], *((unsigned char *) achrl_option_inv[ iml2 ] + 1) );
     achl2 += *((unsigned char *) achrl_option_inv[ iml2 ] + 1);
     iml2++;                                /* end of this option      */
   } while (iml2 < iml1);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 4;  /* Configure-Reject */
   iml1 = achl2 - (dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = achl2 - dsl_buf_ve.achc_data;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;

   p_ipcp_opt_20:                           /* all options are valid   */
   if (achl1 == NULL) {                     /* INETA not set           */
     goto p_inv_00;                         /* packet is invalid       */
   }
   if (bol_nak == FALSE) {                  /* do send Nak not necessary */
     goto p_ipcp_opt_40;                    /* all options checked     */
   }
   /* send Configure-Nak                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   achl_rp = achl_record;                   /* restore address of record */
   memcpy( dsl_buf_ve.achc_data, achp_inp, (achl_record - 2) - achp_inp );
   achl2 = dsl_buf_ve.achc_data + (achl_record - achp_inp);

   p_ipcp_opt_24:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* option type INETA      */
     iml2 = 0;
   } else if (   (*((unsigned char *) achl_rp) >= 129)
              && (*((unsigned char *) achl_rp) <= 132)) {
     iml2 = *((unsigned char *) achl_rp) - 129 + 1;
   } else {
     goto p_inv_00;                         /* program illogic         */
   }
   if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {
     goto p_inv_00;                         /* options length invalid  */
   }
   if ((achl2 + *((unsigned char *) achl_rp + 1)) > achl1) {  /* record too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   memcpy( achl2, achl_rp, 2 );             /* copy first part         */
   memcpy( achl2 + 2, &adsp_ppp_se_1->chrrc_ineta[ iml2 ][0], sizeof(UNSIG_MED) );  /* copy second part */
   achl2 += 2 + sizeof(UNSIG_MED);
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_opt_24;                    /* check options IPCP      */
   }
   if ((dsl_buf_ve.achc_data + (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1)) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml1 = achl2 - (dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = achl2 - dsl_buf_ve.achc_data;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

   p_ipcp_opt_40:                           /* all options checked     */
#ifndef B150619
   /* check if authentication requested, but not exchanged             */
   if ((adsp_ppp_se_1->imc_options & (D_PPP_OPT_SE_AUTH | D_PPP_OPT_AUTH_OK)) == (D_PPP_OPT_SE_AUTH | 0)) {
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "requested PPP authentication not done - someone is hacking" );
     if (dsl_buf_ve.ac_handle) {            /* need to free buffer again */
       m_htun_relrecvbuf( dsl_buf_ve.ac_handle );  /* free buffer again */
     }
     return;
   }
#endif
   adsp_ppp_se_1->imc_options |= D_PPP_OPT_HS_COMPL;  /* handshake is complete */
#ifndef B150509
   if (adsp_ppp_se_1->amc_ppp_se_hs_compl) {  /* PPP server handshake is complete */
     adsp_ppp_se_1->amc_ppp_se_hs_compl( adsp_ppp_se_1 );  /* call callback routine */
   }
#endif
   /* send Configure-Ack                                               */
   iml2 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml2;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, imp_len_inp );
   *(dsl_buf_ve.achc_data + (achl_record - achp_inp) - 4) = (unsigned char) 2;  /* Configure-Ack */
   dsl_buf_ve.imc_len_data = imp_len_inp;   /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

   p_ipcp_end:                              /* is not IPCP             */
#ifdef OLD01
   if (memcmp( achl_rp, ucrs_ctrl_ipv6cp, sizeof(ucrs_ctrl_ipv6cp) )) {
#ifndef NO_D_081115
     iml1 = __LINE__;
#endif
     goto p_ipv6cp_end;                     /* is not IPV6CP           */
   }

   p_ipv6cp_end:                            /* is not IPV6CP           */
#endif
#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_server_cs() send Protocol-Reject",
                 __LINE__ );
#endif
   /* send Protocol-Reject                                             */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + 2 + 4 + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, ucrs_send_lcp_prot_rej, sizeof(ucrs_send_lcp_prot_rej) );
   memcpy( dsl_buf_ve.achc_data + 2 + 4, achp_inp, imp_len_inp );
/* identifier */
#ifndef B150509
   *(dsl_buf_ve.achc_data + 2 + 1)
     = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* send identification LCP configure */
// adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
#endif
   iml1 = 4 + imp_len_inp;
   *(dsl_buf_ve.achc_data + 2 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1)
      = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = 2 + 4 + imp_len_inp;  /* set length       */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

   p_inv_00:                                /* packet invalid          */
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received invalid packet" );
// to-do 10.11.08 KB
   if (dsl_buf_ve.ac_handle) {              /* need to free buffer again */
     m_htun_relrecvbuf( dsl_buf_ve.ac_handle );  /* free buffer again  */
   }
   return;
} /* end m_recv_ppp_server_cs()                                        */

/** process PPP control sequence on client side                        */
extern "C" void m_recv_ppp_client_cs( struct dsd_ppp_client_1 *adsp_ppp_cl_1,
                                      char *achp_inp, int imp_len_inp ) {
   int        iml1, iml2;                   /* working variables       */
#ifdef TRY_111117_01
#ifdef HL_PPP_CLIENT
   BOOL       bol_ipcp_send;                /* IPCP has been sent      */
#endif
#endif
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of input            */
   char       *achl_record;                 /* address of record       */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */
   union {
     char *   achrl_option_inv[ 16 ];       /* invalid options         */
   };
   char       chrl_buf[ 256 ];              /* send buffer             */

   if (imp_len_inp <= 2) {                  /* packet too short        */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_client_cs( %p , %p , %d ) called imc_options=0X%X.",
                 __LINE__, adsp_ppp_cl_1, achp_inp, imp_len_inp, adsp_ppp_cl_1->imc_options );
   iml1 = imp_len_inp;
#ifdef B111025
   if (iml1 > 16) iml1 = 16;
#endif
   m_console_out( achp_inp, iml1 );
#endif
   achl_rp = achp_inp;                      /* get address input       */
   achl_end = achp_inp + imp_len_inp;       /* compute end input       */
   if ((adsp_ppp_cl_1->imc_options & (D_PPP_OPT_CL_ACFC | D_PPP_OPT_SE_ACFC)) != (D_PPP_OPT_CL_ACFC | D_PPP_OPT_SE_ACFC)) {  /* Address-and-Control-Field-Compression (ACFC) */
     if ((unsigned char) *achl_rp != 0XFF) {  /* check first control character */
       goto p_inv_00;                       /* packet invalid          */
     }
     achl_rp++;                             /* increment read pointer  */
     if ((unsigned char) *achl_rp != 0X03) {  /* check second control character */
       goto p_inv_00;                       /* packet invalid          */
     }
     achl_rp++;                             /* increment read pointer  */
#ifdef B140325$ERR$ERR
     if ((achl_end - achl_rp) <= 2) {       /* packet too short        */
       goto p_inv_00;                       /* packet invalid          */
     }
#endif
#ifdef B140325$ERR
   } else {
     if (!memcmp( achl_rp, ucrs_ctrl_ppp, sizeof(ucrs_ctrl_ppp) )) {
       achl_rp += sizeof(ucrs_ctrl_ppp);
     }
#endif
   }
#ifdef B140325$ERR
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   if (memcmp( achl_rp, ucrs_ctrl_lcp, sizeof(ucrs_ctrl_lcp) )) {
     goto p_lcp_end;                        /* is not LCP              */
   }
   switch (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp))) {
     case 1:                                /* Configure-Request       */
       goto p_lcp_opt_code_conf_requ;       /* received Configure-Request */
     case 2:                                /* Configure-Ack           */
       adsp_ppp_cl_1->imc_options |= (D_PPP_OPT_SE_PFC | D_PPP_OPT_SE_ACFC | D_PPP_OPT_CONF_ACK);  /* Configure-Ack received */
       iml1 = adsp_ppp_cl_1->imc_auth_no;   /* get index authentication method */
#ifndef HL_PPP_CLIENT
       if (iml1 >= 0) {                     /* do we need authentication ? */
         adsp_ppp_cl_1->amc_ppp_cl_auth( adsp_ppp_cl_1, dsrs_auth_tab[ iml1 ].iec_pppa );
       }
       if ((adsp_ppp_cl_1->adsc_ppp_se_1->imc_options & D_PPP_OPT_AUTH_OK) == 0) return;  /* authentication not yet succeeded */
#endif
       if (iml1 < 0) {                      /* index for authentification not set */
         adsp_ppp_cl_1->imc_options |= D_PPP_OPT_AUTH_OK;  /* authentication succeeded */
#ifdef XYZ1
#ifdef HL_PPP_CLIENT
         m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
#endif
         return;                            /* all done                */
       }
       dsrs_auth_tab[ iml1 ].amc_client_auth_send( adsp_ppp_cl_1 );
// to-do 06.05.12 KB - do we need to:
//     m_ppp_server_set_inetas( adsp_ppp_se_1 );  /* begin IPCP            */
       return;
     case 3:                                /* Configure-Nak           */
       adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received LCP code 3 Configure-Nak" );
       return;
     case 4:                                /* Configure-Reject        */
       adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received LCP code 4 Configure-Reject" );
       return;
     case 5:                                /* Terminate-Request       */
#ifdef B140325$ERR
       goto p_lcp_term_00;                  /* terminate request       */
#endif
     case 6:                                /* Terminate-Ack           */
     case 7:                                /* Code-Reject             */
     case 8:                                /* Protocol-Reject         */
       break;
     case 9:                                /* Echo-Request            */
       goto p_cl_lcp_echo_req_00;           /* process LCP Echo-Request */
     case 10:                               /* Echo-Reply              */
     case 11:                               /* Discard-Request         */
//   default:                               /* other value             */
       break;
   }
   sprintf( chrl_buf, "received LCP code %d - unknown",
            *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp)) );
   adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, chrl_buf );
   return;

   p_lcp_opt_code_conf_requ:                /* received Configure-Request */
#ifdef B140325$ERR
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   /* check identification                                             */
   if (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1)
         == adsp_ppp_cl_1->isc_recv_ident_lcp_conf) {  /* received identification LCP configure */
     return;                                /* ignore this packet      */
   }
   adsp_ppp_cl_1->isc_recv_ident_lcp_conf
     = *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 1);
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_rp += sizeof(ucrs_ctrl_lcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count invalid options   */
#ifndef TRY_081201
   achl1 = NULL;                            /* no authentication yet   */
#else
   achl1 = achl2 = NULL;                    /* no authentication and no Async-Control-Character-Map */
#endif

   p_lcp_opt_00:                            /* check options LCP       */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml2 = *((unsigned char *) achl_rp);     /* get option type         */
   if (   (iml2 >= (sizeof(ucrs_ppp_opt_len) / sizeof(ucrs_ppp_opt_len[0]) / 2))
       || (ucrs_ppp_opt_len[ iml2 * 2 ] == 0)) {
     if (iml1 >= (sizeof(achrl_option_inv) / sizeof(achrl_option_inv[0]))) {
       goto p_inv_00;                       /* too many invalid options */
     }
     achrl_option_inv[ iml1++ ] = achl_rp;  /* save option invalid     */
   } else {
     if (   (*((unsigned char *) achl_rp + 1) < ucrs_ppp_opt_len[ iml2 * 2 + 0 ])
         || (*((unsigned char *) achl_rp + 1) > ucrs_ppp_opt_len[ iml2 * 2 + 1 ])) {
       goto p_inv_00;                       /* options length invalid  */
     }
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* authentication-protocol */
     achl1 = achl_rp;                       /* save authentication-protocol */
#ifdef TRY_081201
   } else if (*((unsigned char *) achl_rp) == 2) {  /* Async-Control-Character-Map */
     achl2 = achl_rp;                       /* save Async-Control-Character-Map */
#endif
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_lcp_opt_00;                     /* check options LCP       */
   }
   if (iml1 == 0) goto p_lcp_opt_20;        /* all options are valid   */
   /* send Configure-Reject                                            */
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, (achl_record - 2) - achp_inp );
   achl2 = chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp);
   iml2 = 0;                                /* clear index             */
   do {                                     /* loop output of invalid options */
     if ((achl2 + *((unsigned char *) achrl_option_inv[ iml2 ] + 1)) > (chrl_buf + sizeof(chrl_buf))) {
       goto p_inv_00;                       /* output packet is too long */
     }
     memcpy( achl2, achrl_option_inv[ iml2 ], *((unsigned char *) achrl_option_inv[ iml2 ] + 1) );
     achl2 += *((unsigned char *) achrl_option_inv[ iml2 ] + 1);
     iml2++;                                /* end of this option      */
   } while (iml2 < iml1);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 4;  /* Configure-Reject */
   iml1 = achl2 - (chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   achl2 - (chrl_buf + D_LEN_L2TP_HEADER) );
   return;                                  /* all done                */

   p_lcp_opt_20:                            /* all options are valid   */
   iml1 = -1;                               /* index no authentication */
#ifndef TRY_081201
   if (achl1 == NULL) {                     /* no authentication-protocol */
     goto p_lcp_opt_40;                     /* authentication-protocol is valid */
   }
#else
   if (achl1 == NULL) {                     /* no authentication-protocol */
     goto p_lcp_opt_24;                     /* authentication-protocol is valid */
   }
#endif
   /* check against table of supported authentication-protocols        */
#ifdef OLD01
   iml1 = sizeof(aucrs_auth_tab) / sizeof(aucrs_auth_tab[0]);
   do {                                     /* loop over all entries   */
     iml1--;                                /* decrement index         */
     achl2 = (char *) aucrs_auth_tab[ iml1 ];
     if (!memcmp( achl1, achl2, *((unsigned char *) achl1 + 1) )) {
       goto p_lcp_opt_40;                   /* authentication-protocol is valid */
     }
   } while (iml1 > 0);
#endif
#ifndef TRY_081201
   iml1 = sizeof(dsrs_auth_tab) / sizeof(dsrs_auth_tab[0]);
   do {                                     /* loop over all entries   */
     iml1--;                                /* decrement index         */
     achl2 = (char *) dsrs_auth_tab[ iml1 ].aucc_auth_entry;
     if (!memcmp( achl1, achl2, *((unsigned char *) achl1 + 1) )) {
       goto p_lcp_opt_40;                   /* authentication-protocol is valid */
     }
   } while (iml1 > 0);
   /* send Configure-Nak                                               */
   if ((D_LEN_L2TP_HEADER + (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1))
         > sizeof(chrl_buf)) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, (achl_record - 2) - achp_inp );
#ifdef B081125
   memcpy( chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp), ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) );
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml1 = 4 + sizeof(ucrs_auth_prot_chap_1);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   ((achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1)) );
#else
   memcpy( chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp), ucrs_auth_prot_pap, sizeof(ucrs_auth_prot_pap) );
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml1 = 4 + sizeof(ucrs_auth_prot_chap_1);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   ((achl_record - achp_inp) + sizeof(ucrs_auth_prot_pap)) );
#endif
   return;
#else
   if (achl1 == NULL) {                     /* no authentication-protocol */
     goto p_lcp_opt_24;                     /* authentication-protocol checked */
   }
   iml1 = sizeof(dsrs_auth_tab) / sizeof(dsrs_auth_tab[0]);
   while (TRUE) {                           /* loop over all entries   */
     if (iml1 == 0) {                       /* at end of array         */
       iml1 = -2;                           /* set invalid authentication-protocol */
       break;
     }
     iml1--;                                /* decrement index         */
     achl3 = (char *) dsrs_auth_tab[ iml1 ].aucc_auth_entry;
     if (!memcmp( achl1, achl3, *((unsigned char *) achl1 + 1) )) {
       goto p_lcp_opt_24;                   /* authentication-protocol checked */
     }
   }

   p_lcp_opt_24:                            /* authentication-protocol checked */
   if (   (achl2)                           /* with Async-Control-Character-Map */
       && (!memcmp( achl2 + 2, ucrs_four_zero, sizeof(ucrs_four_zero) ))) {
     achl2 = NULL;                          /* Async-Control-Character-Map is valid */
   }
   if ((iml1 >= -1) && (achl2 == NULL)) goto p_lcp_opt_40;  /* Configure-Request is valid */
   /* send Configure-Nak                                               */
// if ((D_LEN_L2TP_HEADER + (achl_record - achp_inp) + sizeof(ucrs_auth_prot_chap_1))
//       > sizeof(chrl_buf)) {
//   goto p_inv_00;                         /* output packet is too long */
// }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, (achl_record - 2) - achp_inp );
   iml2 = 0;                                /* no data till now        */
   if (achl2) {                             /* Async-Control-Character-Map not valid */
     *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) + 0) = (unsigned char) 2;  /* Async-Control-Character-Map */
     *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) + 1) = (unsigned char) (2 + sizeof(ucrs_four_zero));  /* length of option */
     memcpy( chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) + 2, ucrs_four_zero, sizeof(ucrs_four_zero) );
     iml2 = 2 + sizeof(ucrs_four_zero);     /* after this option       */
   }
#ifdef B081125
   if (iml1 < -1) {                         /* authentication-protocol not valid */
     memcpy( chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) + iml2, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) );
     iml2 += sizeof(ucrs_auth_prot_chap_1);  /* after this option      */
   }
#else
   if (iml1 < -1) {                         /* authentication-protocol not valid */
     memcpy( chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) + iml2, ucrs_auth_prot_pap, sizeof(ucrs_auth_prot_pap) );
     iml2 += sizeof(ucrs_auth_prot_pap);    /* after this option       */
   }
#endif
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 3;  /* Configure-Nak */
   iml2 += 4;                               /* add length header       */
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml2 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml2;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   ((achl_record - achp_inp) - 4 + iml2) );
   return;
#endif

   p_lcp_opt_40:                            /* Configure-Request is valid */
#ifdef OLD01
   if (achl1) {                             /* with valid authentication-protocol */
     adsp_ppp_cl_1->imc_options |= D_PPP_OPT_CL_AUTH;  /* client requests authentication */
   }
#endif
   adsp_ppp_cl_1->imc_auth_no = iml1;       /* index for authentification */
   achl_rp = achl_record;                   /* restore address of record */

   p_lcp_opt_44:                            /* set option value        */
   switch (*((unsigned char *) achl_rp)) {  /* check option type       */
     case 1:                                /* 1 / Maximum-Receive-Unit MRU */
#ifndef HL_PPP_CLIENT
       adsp_ppp_cl_1->adsc_ppp_se_1->umc_mtc_se = (*((unsigned char *) achl_rp + 2 + 0) << 8)
                                                    | *((unsigned char *) achl_rp + 2 + 1);
#endif
#ifdef HL_PPP_CLIENT
       adsp_ppp_cl_1->umc_mtc_se = (*((unsigned char *) achl_rp + 2 + 0) << 8)
                                     | *((unsigned char *) achl_rp + 2 + 1);
#endif
       break;
     case 5:                                /* 5 / Magic-Number        */
       memcpy( adsp_ppp_cl_1->chrc_magic_number_se, achl_rp + 2, sizeof(adsp_ppp_cl_1->chrc_magic_number_se) );
       break;
     case 7:                                /* 7 / Protocol-Field-Compression PFC */
       adsp_ppp_cl_1->imc_options |= D_PPP_OPT_CL_PFC;  /* Protocol-Field-Compression (PFC) */
       break;
     case 8:                                /* 8 / Address-and-Control-Field-Compression ACFC */
       adsp_ppp_cl_1->imc_options |= D_PPP_OPT_CL_ACFC;  /* Address-and-Control-Field-Compression (ACFC) */
       break;
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_lcp_opt_44;                     /* set option value        */
   }
   if ((adsp_ppp_cl_1->imc_options & (D_PPP_OPT_CL_PFC | D_PPP_OPT_CL_ACFC)) != (D_PPP_OPT_CL_PFC | D_PPP_OPT_CL_ACFC)) {
     adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received LCP code 1 Configure-Request without PCF / ACFC" );
     return;
   }
   /* send Configure-Ack                                               */
   if ((D_LEN_L2TP_HEADER + imp_len_inp) > sizeof(chrl_buf)) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, imp_len_inp );
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 2;  /* Configure-Ack */
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   imp_len_inp );
#ifndef HL_PPP_CLIENT
   m_ppp_server_send_conf( adsp_ppp_cl_1->adsc_ppp_se_1 );
#endif
#ifndef HL_PPP_CLIENT
#ifdef TRY_081202
   if ((adsp_ppp_cl_1->imc_options & D_PPP_OPT_CONF_ACK) == 0) {  /* Configure-Ack not yet received */
     m_ppp_client_send_conf( adsp_ppp_cl_1 );
   }
#endif
#endif
#ifdef HL_PPP_CLIENT
#ifdef B130904
#ifdef B120902
   m_ppp_client_send_conf( adsp_ppp_cl_1 );
#endif
   adsp_ppp_cl_1->amc_ppp_cl_auth( adsp_ppp_cl_1 );
#else
// to-do 04.09.13 KB - is authentication none configured ???
   if (adsp_ppp_cl_1->imc_auth_no >= 0) {   /* index for authentification */
     adsp_ppp_cl_1->amc_ppp_cl_auth( adsp_ppp_cl_1 );
   } else {                                 /* no authentication       */
     m_ppp_client_send_conf( adsp_ppp_cl_1 );
   }
#endif
#endif
   return;                                  /* all done                */

   p_cl_lcp_echo_req_00:                    /* process LCP Echo-Request */
#ifdef B140325$ERR
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (iml1 != (4 + sizeof(adsp_ppp_cl_1->chrc_magic_number_se))) goto p_inv_00;  /* packet invalid */
   if (memcmp( achl_rp + sizeof(ucrs_ctrl_lcp) + 4,
               adsp_ppp_cl_1->chrc_magic_number_se,
               sizeof(adsp_ppp_cl_1->chrc_magic_number_se) )) {
     goto p_inv_00;                         /* packet invalid          */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_ctrl_lcp, sizeof(ucrs_ctrl_lcp) );
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_lcp) + 0) = 10;  /* Echo-Reply */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_lcp) + 1) = *(achl_rp + sizeof(ucrs_ctrl_lcp) + 1);  /* copy identifier */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_lcp) + 2 + 0) = 0;  /* first byte length */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_lcp) + 2 + 1) = (unsigned char) (4 + sizeof(adsp_ppp_cl_1->chrc_magic_number_cl));  /* second byte length */
   memcpy( chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_lcp) + 4,
           adsp_ppp_cl_1->chrc_magic_number_cl,
           sizeof(adsp_ppp_cl_1->chrc_magic_number_cl) );  /* copy magic number */
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   sizeof(ucrs_ctrl_lcp) + 4 + sizeof(adsp_ppp_cl_1->chrc_magic_number_cl) );
   return;                                  /* all done                */

#ifdef B140325$ERR
   p_lcp_term_00:                           /* terminate request       */
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 2) > achl_end) {  /* packet not long enough */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_lcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
   /* send Terminate-Ack                                               */
   if ((D_LEN_L2TP_HEADER + imp_len_inp) > sizeof(chrl_buf)) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, imp_len_inp );
   *(chrl_buf + D_LEN_L2TP_HEADER + ((achl_rp + sizeof(ucrs_ctrl_lcp) + 0) - achp_inp)) = (unsigned char) 6;  /* Terminate-Ack */
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   imp_len_inp );
   adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received Terminate-Request - connection ended" );
   return;
#endif

   p_lcp_end:                               /* is not LCP              */
#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_client_cs() p_lcp_end: imc_auth_no=%d.",
                 __LINE__, adsp_ppp_cl_1->imc_auth_no );
#endif
   iml1 = adsp_ppp_cl_1->imc_auth_no;       /* index for authentication */
   if (iml1 < 0) {                          /* no authentication required */
     goto p_auth_end;                       /* is not authentication   */
   }
   if (memcmp( achl_rp, (char *) dsrs_auth_tab[ iml1 ].aucc_auth_entry + 2, 2 )) {
     goto p_auth_end;                       /* is not authentication   */
   }
   switch (*((unsigned char *) achl_rp + 2)) {
     case 1:                                /* Authenticate-Request    */
       adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received Authenticate-Request - invalid" );
       return;
     case 2:                                /* Authenticate-Ack        */
       break;
     case 3:                                /* Authenticate-Nak        */
       adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received Authenticate-Nak - authentication failed" );
       return;
     default:                               /* other Code              */
       goto p_inv_00;                       /* packet is invalid       */
   }
   /* missing: check identifier                                        */
   adsp_ppp_cl_1->imc_options |= D_PPP_OPT_AUTH_OK;  /* authentication succeeded */
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->achc_ipcp_save == NULL) return;  /* no IPCP saved */
#ifdef TRACEHL_081204
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_recv_ppp_client_cs() call m_ppp_server_ipcp_pass() imc_options=0X%08X",
                 __LINE__, adsp_ppp_cl_1->imc_options );
#endif
   m_ppp_server_ipcp_pass( adsp_ppp_cl_1->adsc_ppp_se_1,
                           adsp_ppp_cl_1->achc_ipcp_save,
                           2 + ((*((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
                                  | *((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 1)),
                           TRUE );
#endif
#ifdef XYZ1
#ifdef HL_PPP_CLIENT
   m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
#endif
   return;                                  /* all done                */

   p_auth_end:                              /* is not authentication   */
   if (memcmp( achl_rp, ucrs_ctrl_ipcp, sizeof(ucrs_ctrl_ipcp) )) {
#ifndef NO_D_081115
     iml1 = __LINE__;
#endif
     goto p_ipcp_end;                       /* is not IPCP             */
   }
   switch (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp))) {
     case 1:                                /* Configure-Request       */
       goto p_ipcp_opt_code_conf_requ;      /* received Configure-Request */
     case 2:                                /* Configure-Ack           */
       goto p_ipcp_ack_00;                  /* received Configure-Ack  */
     case 3:                                /* Configure-Nak           */
       goto p_ipcp_nak_00;                  /* received Configure-Nak  */
     case 4:                                /* Configure-Reject        */
       goto p_ipcp_rej_00;                  /* received Configure-Reject */
   }
   sprintf( chrl_buf, "received IPCP code %d - unknown",
            *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_lcp)) );
   adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, chrl_buf );
   return;

   p_ipcp_opt_code_conf_requ:               /* received Configure-Request */
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_ipcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifndef TRY_111117_01
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_RECV) {  /* IPCP receive INETAS complete */
     return;                                /* discard the record      */
   }
#endif
#endif
#ifdef TRY_111117_01
#ifdef HL_PPP_CLIENT
   bol_ipcp_send = FALSE;                   /* IPCP has been sent      */
   if (adsp_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_RECV) {  /* IPCP receive INETAS complete */
     bol_ipcp_send = TRUE;                  /* IPCP has been sent      */
   }
#endif
#endif
   achl_rp += sizeof(ucrs_ctrl_ipcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count invalid options   */
   achl1 = NULL;                            /* no INETA yet            */

   p_ipcp_opt_00:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp) != 3) {  /* check option type      */
     if (iml1 >= (sizeof(achrl_option_inv) / sizeof(achrl_option_inv[0]))) {
       goto p_inv_00;                       /* too many invalid options */
     }
     achrl_option_inv[ iml1++ ] = achl_rp;  /* save option invalid     */
   } else {
     if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {  /* check option length */
       goto p_inv_00;                       /* options length invalid  */
     }
     if (achl1) {                           /* INETA already set       */
       goto p_inv_00;                       /* options length invalid  */
     }
     achl1 = achl_rp;                       /* save INETA              */
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_opt_00;                    /* check options IPCP      */
   }
   if (iml1 == 0) goto p_ipcp_opt_20;       /* all options are valid   */
   /* send Configure-Reject                                            */
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, (achl_record - 2) - achp_inp );
   achl2 = chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp);
   iml2 = 0;                                /* clear index             */
   do {                                     /* loop output of invalid options */
     if ((achl2 + *((unsigned char *) achrl_option_inv[ iml2 ] + 1)) > (chrl_buf + sizeof(chrl_buf))) {
       goto p_inv_00;                       /* output packet is too long */
     }
     memcpy( achl2, achrl_option_inv[ iml2 ], *((unsigned char *) achrl_option_inv[ iml2 ] + 1) );
     achl2 += *((unsigned char *) achrl_option_inv[ iml2 ] + 1);
     iml2++;                                /* end of this option      */
   } while (iml2 < iml1);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 4;  /* Configure-Reject */
   iml1 = achl2 - (chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4 + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   achl2 - (chrl_buf + D_LEN_L2TP_HEADER) );
   return;                                  /* all done                */

   p_ipcp_opt_20:                           /* all options are valid   */
   if (achl1 == NULL) {                     /* INETA not set           */
     goto p_inv_00;                         /* packet is invalid       */
   }
   memcpy( adsp_ppp_cl_1->chrc_ineta,
           achl1 + 2,
           sizeof(adsp_ppp_cl_1->chrc_ineta) );
   if (*((UNSIG_MED *) adsp_ppp_cl_1->chrc_ineta) == 0) {  /* INETA empty */
     goto p_inv_00;                         /* packet is invalid       */
   }
   adsp_ppp_cl_1->imc_options |= D_PPP_OPT_IPCP_RECV;  /* IPCP receive INETAS complete */
#ifdef XYZ1
#ifdef HL_PPP_CLIENT
   m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
#endif
   /* send Configure-Ack                                               */
   if ((D_LEN_L2TP_HEADER + imp_len_inp) > sizeof(chrl_buf)) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, achp_inp, imp_len_inp );
   *(chrl_buf + D_LEN_L2TP_HEADER + (achl_record - achp_inp) - 4) = (unsigned char) 2;  /* Configure-Ack */
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   imp_len_inp );
#ifndef HL_PPP_CLIENT
   /* send Configure-Request PPP server to client                      */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, imp_len_inp );
/* identifier */
   dsl_buf_ve.imc_len_data = imp_len_inp;   /* set length              */
   adsp_ppp_cl_1->adsc_ppp_se_1->amc_ppp_se_send( adsp_ppp_cl_1->adsc_ppp_se_1, &dsl_buf_ve );
#endif
#ifndef TRY_111117_01
#ifdef HL_PPP_CLIENT
   m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
#endif
#ifdef TRY_111117_01
#ifdef HL_PPP_CLIENT
   if (bol_ipcp_send == FALSE) {            /* IPCP has not been sent  */
     m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
   }
#endif
#endif
   return;                                  /* all done                */

   p_ipcp_ack_00:                           /* received Configure-Ack  */
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->achc_ipcp_save == NULL) {  /* no IPCP saved      */
     return;                                /* discard this packet     */
   }
#endif
#ifdef OLD01
   /* send Ack to the client                                           */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   if ((dsl_buf_ve.achc_data + imp_len_inp) > achl1) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( dsl_buf_ve.achc_data, achp_inp, imp_len_inp );
   /* use identifier of original packet                                */
   *(dsl_buf_ve.achc_data + sizeof(ucrs_ctrl_ipcp) + 1)
     = *(adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 1);
   dsl_buf_ve.imc_len_data = imp_len_inp;   /* set length              */
   adsp_ppp_cl_1->adsc_ppp_se_1->amc_ppp_se_send( adsp_ppp_cl_1->adsc_ppp_se_1, &dsl_buf_ve );
#endif
#ifndef TRY_081203
   adsp_ppp_cl_1->imc_options |= D_PPP_OPT_IPCP_SEND;  /* IPCP send INETAS complete */
#endif
#ifdef TRACEHL_081204
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_recv_ppp_client_cs() call m_ppp_server_ipcp_pass() imc_options=0X%08X",
                 __LINE__, adsp_ppp_cl_1->imc_options );
#endif
#ifndef TRY_081204_02
   m_ppp_server_ipcp_pass( adsp_ppp_cl_1->adsc_ppp_se_1,
                           adsp_ppp_cl_1->achc_ipcp_save,
                           2 + ((*((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
                                  | *((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 1)),
                           TRUE );
#endif
#ifdef TRY_081203
   adsp_ppp_cl_1->imc_options |= D_PPP_OPT_IPCP_SEND;  /* IPCP send INETAS complete */
#endif
#ifndef HL_PPP_CLIENT
   free( adsp_ppp_cl_1->achc_ipcp_save );   /* free memory             */
   adsp_ppp_cl_1->achc_ipcp_save = NULL;    /* no more saved block for IPCP */
#endif
#ifdef HL_PPP_CLIENT
#ifdef XYZ1
#ifndef B150619
   /* check if authentication requested, but not exchanged             */
   if ((adsp_ppp_cl_1->imc_options & (D_PPP_OPT_SE_AUTH | D_PPP_OPT_AUTH_OK)) == (D_PPP_OPT_SE_AUTH | 0)) {
     adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "PPP authentication not done - illogic" );
     return;
   }
#endif
#endif
   adsp_ppp_cl_1->imc_options |= D_PPP_OPT_HS_COMPL;  /* handshake is complete */
#endif
   return;                                  /* all done                */

   p_ipcp_nak_00:                           /* received Configure-Nak  */
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_ipcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef OLD01
   if (adsp_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_RECV) {  /* IPCP receive INETAS complete */
     return;                                /* discard the record      */
   }
#endif
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->achc_ipcp_save == NULL) {  /* no IPCP saved      */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   achl_rp += sizeof(ucrs_ctrl_ipcp) + 2 + 2;

   p_ipcp_nak_20:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* option type INETA      */
     iml2 = 0;
   } else if (   (*((unsigned char *) achl_rp) >= 129)
              && (*((unsigned char *) achl_rp) <= 132)) {
     iml2 = *((unsigned char *) achl_rp) - 129 + 1;
   } else {                                 /* invalid option received */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {  /* check option length */
     goto p_inv_00;                         /* options length invalid  */
   }
#ifndef HL_PPP_CLIENT
   memcpy( &adsp_ppp_cl_1->adsc_ppp_se_1->chrrc_ineta[ iml2 ][0],
           achl_rp + 2,
           sizeof(UNSIG_MED) );
   if (*((UNSIG_MED *) &adsp_ppp_cl_1->adsc_ppp_se_1->chrrc_ineta[ iml2 ][0]) == 0) {
     goto p_inv_00;                         /* INETA zero not allowed  */
   }
   adsp_ppp_cl_1->adsc_ppp_se_1->chrc_ineta_stat[ iml2 ] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
#endif
#ifdef HL_PPP_CLIENT
   memcpy( &adsp_ppp_cl_1->chrrc_ineta[ iml2 ][0],
           achl_rp + 2,
           sizeof(UNSIG_MED) );
   if (*((UNSIG_MED *) &adsp_ppp_cl_1->chrrc_ineta[ iml2 ][0]) == 0) {
     goto p_inv_00;                         /* INETA zero not allowed  */
   }
   adsp_ppp_cl_1->chrc_ineta_stat[ iml2 ] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
#endif
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_nak_20;                    /* check options IPCP      */
   }
#ifdef TRACEHL_081204
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_recv_ppp_client_cs() call m_ppp_server_ipcp_pass() imc_options=0X%08X",
                 __LINE__, adsp_ppp_cl_1->imc_options );
#endif
#ifndef HL_PPP_CLIENT
   m_ppp_server_ipcp_pass( adsp_ppp_cl_1->adsc_ppp_se_1,
                           adsp_ppp_cl_1->achc_ipcp_save,
                           2 + ((*((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
                                  | *((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 1)),
                           TRUE );
#endif
#ifdef HL_PPP_CLIENT
   m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
   return;                                  /* all done                */

   p_ipcp_rej_00:                           /* received Configure-Reject */
   iml1 = (*((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
            | *((unsigned char *) achl_rp + sizeof(ucrs_ctrl_ipcp) + 2 + 1);
   if ((achl_rp + sizeof(ucrs_ctrl_ipcp) + iml1) != achl_end) {  /* length is invalid */
     goto p_inv_00;                         /* packet invalid          */
   }
#ifdef OLD01
   if (adsp_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_RECV) {  /* IPCP receive INETAS complete */
     return;                                /* discard the record      */
   }
#endif
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->achc_ipcp_save == NULL) {  /* no IPCP saved      */
     goto p_inv_00;                         /* packet invalid          */
   }
#endif
   achl_rp += sizeof(ucrs_ctrl_ipcp) + 2 + 2;

   p_ipcp_rej_20:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp) == 3) {  /* option type INETA      */
     iml2 = 0;
   } else if (   (*((unsigned char *) achl_rp) >= 129)
              && (*((unsigned char *) achl_rp) <= 132)) {
     iml2 = *((unsigned char *) achl_rp) - 129 + 1;
   } else {                                 /* invalid option received */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {  /* check option length */
     goto p_inv_00;                         /* options length invalid  */
   }
#ifndef HL_PPP_CLIENT
   adsp_ppp_cl_1->adsc_ppp_se_1->chrc_ineta_stat[ iml2 ] |= D_INETA_OPT_REJECTED;  /* INETA rejected */
#endif
#ifdef HL_PPP_CLIENT
   adsp_ppp_cl_1->chrc_ineta_stat[ iml2 ] |= D_INETA_OPT_REJECTED;  /* INETA rejected */
#endif
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_rej_20;                    /* check options IPCP      */
   }
#ifdef TRACEHL_081204
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_recv_ppp_client_cs() call m_ppp_server_ipcp_pass() imc_options=0X%08X",
                 __LINE__, adsp_ppp_cl_1->imc_options );
#endif
#ifndef HL_PPP_CLIENT
   m_ppp_server_ipcp_pass( adsp_ppp_cl_1->adsc_ppp_se_1,
                           adsp_ppp_cl_1->achc_ipcp_save,
                           2 + ((*((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 0) << 8)
                                  | *((unsigned char *) adsp_ppp_cl_1->achc_ipcp_save + sizeof(ucrs_ctrl_ipcp) + 2 + 1)),
                           TRUE );
#endif
#ifdef HL_PPP_CLIENT
   m_ppp_client_send_ipcp( adsp_ppp_cl_1 );  /* send IPCP INETAs as client to server */
#endif
   return;                                  /* all done                */

   p_ipcp_end:                              /* is not IPCP             */
#ifdef OLD01
   if (memcmp( achl_rp, ucrs_ctrl_ipv6cp, sizeof(ucrs_ctrl_ipv6cp) )) {
#ifndef NO_D_081115
     iml1 = __LINE__;
#endif
     goto p_ipv6cp_end;                     /* is not IPV6CP           */
   }

   p_ipv6cp_end:                            /* is not IPV6CP           */
#endif
#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_client_cs() send Protocol-Reject",
                 __LINE__ );
#endif
   /* send Protocol-Reject                                             */
   if ((D_LEN_L2TP_HEADER + 2 + 4 + imp_len_inp) > sizeof(chrl_buf)) {
     goto p_inv_00;                         /* output packet is too long */
   }
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_send_lcp_prot_rej, sizeof(ucrs_send_lcp_prot_rej) );
   memcpy( chrl_buf + D_LEN_L2TP_HEADER + 2 + 4, achp_inp, imp_len_inp );
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 1) = adsp_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
   iml1 = 4 + imp_len_inp;
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   2 + 4 + imp_len_inp );
   return;                                  /* all done                */

   p_inv_00:                                /* packet invalid          */
// to-do 12.11.08 KB
   adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "received invalid packet" );
   return;
} /* end m_recv_ppp_client_cs()                                        */

#ifndef HL_PPP_CLIENT
/** authentication is complete - successful or not                     */
extern "C" void m_auth_compl_ppp_server( struct dsd_ppp_server_1 *adsp_ppp_se_1, enum ied_ppp_auth_rc iep_ppp_auth_rc ) {
   int        iml1;                         /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
#ifdef XYZ1
   struct dsd_ppp_auth_record *adsl_par_mscv2_challenge;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_mscv2_userid;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_mscv2_success;  /* record in storage for authentication */
#endif
   struct dsd_ppp_auth_record *adsl_par_eap_send_1;  /* record in storage for authentication - EAP to send */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */

   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_auth_compl_ppp_server() no adsc_ppp_auth_header - illogic" );
     return;
   }
   switch (iep_ppp_auth_rc) {               /* PPP authentication return code */
     case ied_pppar_ok:                     /* authentication was checked O.K. */
       goto m_auth_ok_00;                   /* authentication was checked O.K. */
     case ied_pppar_cont:                   /* authentication continue processing */
       goto m_auth_cont_00;                 /* continue processing     */
     case ied_pppar_userid_inv:             /* userid invalid          */
     case ied_pppar_password_inv:           /* password invalid        */
     case ied_pppar_auth_failed:            /* authentication failed   */
       goto m_auth_failed;                  /* authentication failed   */
   }
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "authentication serious error" );
   return;                                  /* all done                */

   m_auth_cont_00:                          /* continue processing     */
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth != ied_pppa_eap) {  /* authentication-method in use - EAP */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "authentication continue but no EAP - illogic" );
     return;                                /* all done                */
   }
#ifdef XYZ1
   adsl_par_mscv2_challenge = NULL;         /* record in storage for authentication */
   adsl_par_mscv2_userid = NULL;            /* record in storage for authentication */
   adsl_par_mscv2_success = NULL;           /* record in storage for authentication */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_mscv2_challenge:        /* MS-CHAP-V2 challenge    */
         adsl_par_mscv2_challenge = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_userid:                 /* userid                  */
         adsl_par_mscv2_userid = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_mscv2_success:          /* type of authentication record - MS-CHAP-V2 success */
         adsl_par_mscv2_success = adsl_par_w1;  /* record in storage for authentication */
         break;
#ifdef XYZ1
       case ied_par_mscv2_response:         /* MS-CHAP-V2 response     */
         adsl_par_mscv2_response = adsl_par_w1;  /* record in storage for authentication */
         break;
       case ied_par_mscv2_change_pwd:       /* MS-CHAP-V2 change password */
         adsl_par_mscv2_change_pwd = adsl_par_w1;  /* record in storage for authentication */
         break;
#endif
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (   (adsl_par_mscv2_userid == NULL)   /* no userid - identity    */
       || (adsl_par_mscv2_challenge == NULL)) {  /* no MS-CHAP-V2 challenge */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_auth_compl_ppp_server() no MS-CHAP-V2 identity and challenge - illogic" );
     m_htun_relrecvbuf( dsl_buf_ve.ac_handle );  /* free buffer again  */
     return;
   }
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_request_identity, 3 );
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   *(dsl_buf_ve.achc_data + 2 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   if (adsl_par_mscv2_success) {            /* packet with success     */
     goto m_auth_cont_20;                   /* EAP MS-CHAP-V2 success  */
   }
   iml1 = 10 + LEN_MSCV2_CHALLENGE + adsl_par_mscv2_userid->imc_len_data;
   *(dsl_buf_ve.achc_data + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1) = (unsigned char) iml1;
   *(dsl_buf_ve.achc_data + 2 + 4 + 0) = (unsigned char) D_PPP_EAP_MS_AUTH;
   *(dsl_buf_ve.achc_data + 2 + 4 + 1) = 1;  /* opcode challenge       */
   *(dsl_buf_ve.achc_data + 2 + 4 + 2) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   iml1 -= 5;
   *(dsl_buf_ve.achc_data + 2 + 4 + 3 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 4 + 3 + 1) = (unsigned char) iml1;
   *(dsl_buf_ve.achc_data + 2 + 4 + 5) = (unsigned char) LEN_MSCV2_CHALLENGE;
   memcpy( dsl_buf_ve.achc_data + 2 + 4 + 6,
#ifdef B140318
           adsl_par_mscv2_challenge + 1,
#else
           (char *) (adsl_par_mscv2_challenge + 1) + 1,
#endif
           LEN_MSCV2_CHALLENGE );           /* length MS-CHAP-V2 challenge */
   memcpy( dsl_buf_ve.achc_data + 2 + 4 + 6 + LEN_MSCV2_CHALLENGE,
           adsl_par_mscv2_userid + 1,
           adsl_par_mscv2_userid->imc_len_data );  /* length of userid */
   dsl_buf_ve.imc_len_data = 2 + 5 + iml1;  /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

   m_auth_cont_20:                          /* EAP MS-CHAP-V2 success  */
   iml1 = 4 + 1 + 4 + adsl_par_mscv2_success->imc_len_data;  /* length of the data */
   *(dsl_buf_ve.achc_data + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1) = (unsigned char) iml1;
   *(dsl_buf_ve.achc_data + 2 + 4 + 0) = (unsigned char) D_PPP_EAP_MS_AUTH;
   *(dsl_buf_ve.achc_data + 2 + 4 + 1) = 3;  /* opcode success         */
   *(dsl_buf_ve.achc_data + 2 + 4 + 2) = adsp_ppp_se_1->ucc_send_ident_lcp_conf - 1;  /* sent identification LCP configure */
   iml1 -= 5;
   *(dsl_buf_ve.achc_data + 2 + 4 + 3 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 4 + 3 + 1) = (unsigned char) iml1;
   memcpy( dsl_buf_ve.achc_data + 2 + 4 + 1 + 4,
           adsl_par_mscv2_success + 1,
           adsl_par_mscv2_success->imc_len_data );
   dsl_buf_ve.imc_len_data = 2 + 5 + iml1;  /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */
#endif
   adsl_par_eap_send_1 = NULL;              /* record in storage for authentication - EAP to send */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_eap_send_1:             /* EAP to send             */
         adsl_par_eap_send_1 = adsl_par_w1;  /* record in storage for authentication - EAP to send */
         break;
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_eap_send_1 == NULL) {       /* nothing to send         */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_auth_compl_ppp_server() no EAP data to send - illogic" );
     return;
   }
   adsl_par_eap_send_1->iec_par = ied_par_eap_send_2;  /* EAP sent but not yet acknowledged */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
#ifdef XYZ1
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_request_identity, 3 );
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   iml1 = 4 + adsl_par_eap_send_1->imc_len_data;  /* length of the data */
   *(dsl_buf_ve.achc_data + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1) = (unsigned char) iml1;
   memcpy( dsl_buf_ve.achc_data + 2 + 4,
           adsl_par_eap_send_1 + 1,
           adsl_par_eap_send_1->imc_len_data );
#endif
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_request_identity, 2 );
   iml1 = adsl_par_eap_send_1->imc_len_data;  /* length of the data */
   memcpy( dsl_buf_ve.achc_data + 2,
           adsl_par_eap_send_1 + 1,
           iml1 );
   adsp_ppp_se_1->ucc_send_ident_lcp_conf = *(dsl_buf_ve.achc_data + 2 + 1);  /* sent identification LCP configure */
   dsl_buf_ve.imc_len_data = 2 + iml1;      /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */

   m_auth_failed:                           /* authentication failed   */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
#ifdef XYZ1
#ifndef B131115
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth == ied_pppa_pap) {  /* authentication-method in use - PAP */
     goto m_auth_fa_20;                     /* authentication failed PAP */
   }
#endif
#endif
   switch( adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth ) {
     case ied_pppa_pap:                     /* authentication-method in use - PAP */
       goto m_auth_fa_20;                   /* authentication failed PAP */
     case ied_pppa_eap:                     /* EAP                     */
       goto m_auth_fa_40;                   /* authentication failed EAP */
   }
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over records in storage for authentication */
     if (adsl_par_w1->iec_par == ied_par_mscv2_failure) break;  /* MS-CHAP-V2 failure */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_w1 == NULL) {               /* no MS-CHAP-V2 failure   */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_auth_compl_ppp_server() no MS-CHAP-V2 failure - illogic" );
     m_htun_relrecvbuf( dsl_buf_ve.ac_handle );  /* free buffer again  */
     return;
   }
   memcpy( dsl_buf_ve.achc_data, ucrs_auth_prot_chap_1 + 2, 2 );
   memcpy( dsl_buf_ve.achc_data + 2, adsl_par_w1 + 1, adsl_par_w1->imc_len_data );  /* copy data */
   *(dsl_buf_ve.achc_data + 2 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   dsl_buf_ve.imc_len_data = 2 + adsl_par_w1->imc_len_data;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;                                  /* all done                */
//------
#ifndef B131115
   m_auth_fa_20:                            /* authentication failed PAP */
#endif
   memcpy( dsl_buf_ve.achc_data, ucrs_pap_nak, sizeof(ucrs_pap_nak) );
#ifdef B120505
   dsl_buf_ve.achc_data[3] = adsp_ppp_se_1->adsc_ppp_auth_1->chc_ident;  /* ident received */
   dsl_buf_ve.imc_len_data = sizeof(ucrs_pap_nak);
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   free( adsp_ppp_se_1->adsc_ppp_auth_1 );  /* free memory for authentication */
   adsp_ppp_se_1->adsc_ppp_auth_1 = NULL;   /* no more memory for authentication */
#endif
#ifndef B131115
   dsl_buf_ve.achc_data[3] = adsp_ppp_se_1->adsc_ppp_auth_header->chc_ident;  /* ident received */
   dsl_buf_ve.imc_len_data = sizeof(ucrs_pap_nak);
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
#endif
   return;                                  /* all done                */

   m_auth_fa_40:                            /* authentication failed EAP */
   adsl_par_eap_send_1 = NULL;              /* record in storage for authentication - EAP to send */
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over chain of records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_eap_send_1:             /* EAP to send             */
         adsl_par_eap_send_1 = adsl_par_w1;  /* record in storage for authentication - EAP to send */
         break;
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_request_identity, 2 );
   if (adsl_par_eap_send_1 == NULL) {       /* nothing to send         */
     memcpy( dsl_buf_ve.achc_data + 2,
             ucrs_eap_nak,
             sizeof(ucrs_eap_nak) );
     iml1 = sizeof(ucrs_eap_nak);
   } else {
     adsl_par_eap_send_1->iec_par = ied_par_eap_send_2;  /* EAP sent but not yet acknowledged */
     iml1 = adsl_par_eap_send_1->imc_len_data;  /* length of the data  */
     memcpy( dsl_buf_ve.achc_data + 2,
             adsl_par_eap_send_1 + 1,
             iml1 );
   }
   adsp_ppp_se_1->ucc_send_ident_lcp_conf = *(dsl_buf_ve.achc_data + 2 + 1);  /* sent identification LCP configure */
   dsl_buf_ve.imc_len_data = 2 + iml1;      /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
#ifdef B140512
#ifndef B140402
   /* we need to free the memory for authentication                    */
#ifndef B140509
   adsp_ppp_se_1->imc_options |= D_PPP_OPT_ENDED;  /* PPP module has ended */
#endif
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
#endif
#endif
   return;                                  /* all done                */

   m_auth_ok_00:                            /* authentication was checked O.K. */
   adsp_ppp_se_1->imc_options |= D_PPP_OPT_AUTH_OK;  /* authentication succeeded */
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   achl1 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
#ifdef XYZ1
#ifndef B131115
   if (adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth == ied_pppa_pap) {  /* authentication-method in use - PAP */
     goto m_auth_ok_08;                     /* PAP authentication succeeded */
   }
#endif
#endif
   switch( adsp_ppp_se_1->adsc_ppp_auth_header->iec_ppp_auth ) {
     case ied_pppa_pap:                     /* authentication-method in use - PAP */
       goto m_auth_ok_08;                   /* PAP authentication succeeded */
     case ied_pppa_eap:                     /* EAP                     */
       goto m_auth_ok_12;                   /* EAP authentication succeeded */
   }
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over records in storage for authentication */
     if (adsl_par_w1->iec_par == ied_par_mscv2_success) break;  /* type of authentication record - MS-CHAP-V2 success */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_w1 == NULL) {               /* no MS-CHAP-V2 success   */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_auth_compl_ppp_server() no MS-CHAP-V2 success - illogic" );
     m_htun_relrecvbuf( dsl_buf_ve.ac_handle );  /* free buffer again  */
     return;
   }
   memcpy( dsl_buf_ve.achc_data, ucrs_auth_prot_chap_1 + 2, 2 );
   *(dsl_buf_ve.achc_data + 2) = (unsigned char) 3;  /* code success   */
   *(dsl_buf_ve.achc_data + 2 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   iml1 = 1 + 1 + 2 + adsl_par_w1->imc_len_data;  /* length of the data */
   *(dsl_buf_ve.achc_data + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1) = (unsigned char) iml1;
   memcpy( dsl_buf_ve.achc_data + 2 + 2 + 1 + 1, adsl_par_w1 + 1, adsl_par_w1->imc_len_data );
   dsl_buf_ve.imc_len_data = 2 + iml1;      /* set length              */
// adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
// return;
   /* we need to free the memory for authentication                    */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   goto m_auth_ok_20;                       /* authentication packet has been prepared */
//----

#ifndef B131115
   m_auth_ok_08:                            /* PAP authentication succeeded */
#ifdef B131204
   /* we need to free the memory for authentication                    */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
#endif
#endif
   memcpy( dsl_buf_ve.achc_data, ucrs_pap_ack, sizeof(ucrs_pap_ack) );
#ifdef B120505
   dsl_buf_ve.achc_data[3] = adsp_ppp_se_1->adsc_ppp_auth_1->chc_ident;  /* ident received */
#endif
#ifndef B131115
   dsl_buf_ve.achc_data[3] = adsp_ppp_se_1->adsc_ppp_auth_header->chc_ident;  /* ident received */
#endif
   dsl_buf_ve.imc_len_data = sizeof(ucrs_pap_ack);
#ifndef B131204
   /* we need to free the memory for authentication                    */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
#endif
   goto m_auth_ok_20;                       /* authentication packet has been prepared */

   m_auth_ok_12:                            /* EAP authentication succeeded */
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_recv_ppp_client_cs() m_auth_ok_12: adsp_ppp_se_1->imc_options=0X%08X.",
                 __LINE__, adsp_ppp_se_1->imc_options );
#endif
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_ack, sizeof(ucrs_eap_ack) );
   dsl_buf_ve.achc_data[3] = adsp_ppp_se_1->adsc_ppp_auth_header->chc_ident;  /* ident received */
   dsl_buf_ve.imc_len_data = sizeof(ucrs_eap_ack);
   /* we need to free the memory for authentication                    */
   adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */

   m_auth_ok_20:                            /* authentication packet has been prepared */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
#ifndef HL_IPSEC_01
   if (adsp_ppp_se_1->adsc_ppp_cl_1 == NULL) {  /* not with client     */
     goto m_auth_ok_40;                     /* can begin IPCP now      */
   }
#ifdef B120505
   adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_1 = adsp_ppp_se_1->adsc_ppp_auth_1;  /* for authentication this client to server */
   adsp_ppp_se_1->adsc_ppp_auth_1 = NULL;   /* no more memory for authentication */
#endif
   if ((adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_CONF_ACK) == 0) return;  /* not yet Configure-Ack received */
   iml1 = adsp_ppp_se_1->adsc_ppp_cl_1->imc_auth_no;  /* get index     */
   if (iml1 < 0) {                          /* index for authentification not set */
     adsp_ppp_se_1->adsc_ppp_cl_1->imc_options |= D_PPP_OPT_AUTH_OK;  /* authentication succeeded */
     goto m_auth_ok_40;                     /* can begin IPCP now      */
   }
#ifndef HL_PPP_CLIENT
   adsp_ppp_se_1->adsc_ppp_cl_1->amc_ppp_cl_auth( adsp_ppp_se_1->adsc_ppp_cl_1, dsrs_auth_tab[ iml1 ].iec_pppa );
   if ((adsp_ppp_se_1->imc_options & D_PPP_OPT_AUTH_OK) == 0) return;  /* authentication not yet succeeded */
#endif
   dsrs_auth_tab[ iml1 ].amc_client_auth_send( adsp_ppp_se_1->adsc_ppp_cl_1 );

   m_auth_ok_40:                            /* can begin IPCP now      */
#endif
#ifndef TRY_130104_01                       /* problem solved by HSM   */
   m_ppp_server_set_inetas( adsp_ppp_se_1 );  /* begin IPCP            */
#endif
   return;                                  /* all done                */
} /* end m_auth_compl_ppp_server()                                     */
#endif
#ifdef HL_PPP_CLIENT
#ifdef B120902
/* authentication of client                                            */
extern "C" void m_auth_ppp_client( struct dsd_ppp_client_1 *adsp_ppp_cl_1, struct dsd_ppp_auth_1 *adsp_ppp_auth_1 ) {
   int        iml1;                         /* working variable        */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T %s m_auth_ppp_client( %p , %p )",
                 __LINE__, chrl_date_time, adsp_ppp_cl_1, adsp_ppp_auth_1 );
#endif
#ifdef NOT_YET_120826
   iml1 = adsp_ppp_cl_1->imc_auth_no;       /* get index               */
   if (iml1 < 0) {                          /* index for authentification not set */
     adsp_ppp_cl_1->imc_options |= D_PPP_OPT_AUTH_OK;  /* authentication succeeded */
     return;
   }
   adsp_ppp_cl_1->adsc_ppp_auth_1 = adsp_ppp_auth_1;
   dsrs_auth_tab[ iml1 ].amc_client_auth_send( adsp_ppp_cl_1 );
   adsp_ppp_cl_1->adsc_ppp_auth_1 = NULL;
#endif
   return;                                  /* all done                */
} /* end m_auth_ppp_client()                                           */
#endif
/** authentication of client                                           */
extern "C" void m_auth_ppp_client( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T %s m_auth_ppp_client( %p )",
                 __LINE__, chrl_date_time, adsp_ppp_cl_1 );
#endif
   /* 02.09.12 KB - only PAP implemented                               */
   dsrs_auth_tab[ 0 ].amc_client_auth_send( adsp_ppp_cl_1 );
   return;                                  /* all done                */
} /* end m_auth_ppp_client()                                           */
#endif

/** close PPP control sequences on server side, do also on client side if configured */
extern "C" void m_close_ppp_server_cs( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
#ifdef DEBUG_140402_01                      /* memory-leak PPP authentication */
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_close_ppp_server_cs( %p )",
                 __LINE__, adsp_ppp_se_1 );
#endif
#ifdef B120505
   if (adsp_ppp_se_1->adsc_ppp_auth_1) {    /* for authentication this client to server */
     free( adsp_ppp_se_1->adsc_ppp_auth_1 );  /* free memory           */
     adsp_ppp_se_1->adsc_ppp_auth_1 = NULL;  /* no more memory for authentication */
   }
#endif
   adsp_ppp_se_1->imc_options |= D_PPP_OPT_ENDED;  /* PPP module has ended */
   if (adsp_ppp_se_1->adsc_ppp_auth_header) {  /* with memory for authentication */
     adsp_ppp_se_1->amc_ppp_se_auth( adsp_ppp_se_1 );  /* call authentication routine */
   }
   if (adsp_ppp_se_1->adsc_ppp_cl_1 == NULL) return;  /* not with client */
#ifdef B120506
   if (adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_1) {  /* for authentication this client to server */
     free( adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_1 );  /* free memory */
     adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_1 = NULL;  /* no more memory for authentication */
   }
#endif
#ifndef B140402
   if (adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_header) {  /* for authentication this client to server */
     adsp_ppp_se_1->adsc_ppp_cl_1->amc_ppp_cl_auth( adsp_ppp_se_1->adsc_ppp_cl_1, ied_pppa_invalid );
     adsp_ppp_se_1->adsc_ppp_cl_1->adsc_ppp_auth_header = NULL;  /* no more memory for authentication */
   }
#endif
   if (adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save) {  /* saved block for IPCP */
     free( adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save );  /* free memory */
     adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save = NULL;  /* no more saved block for IPCP */
   }
} /* end m_close_ppp_server_cs()                                       */

/** send Configure-Request as client to server                         */
static void m_ppp_client_send_conf( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   char       chrl_buf[ 256 ];              /* send buffer             */

#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_ppp_client_send_conf() called",
                 __LINE__ );
#endif
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_send_conf_1, sizeof(ucrs_send_conf_1) );
   achl1 = chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_send_conf_1) + 3;
#ifndef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->adsc_ppp_se_1->umc_mtc_cl) {
     *achl1++ = 1;                          /* Maximum-Receive-Unit MRU */
     *achl1++ = 2 + 2;                      /* size of option          */
     *achl1++ = (unsigned char) (adsp_ppp_cl_1->adsc_ppp_se_1->umc_mtc_cl >> 8);
     *achl1++ = (unsigned char) adsp_ppp_cl_1->adsc_ppp_se_1->umc_mtc_cl;
   }
#endif
#ifdef HL_PPP_CLIENT
   if (adsp_ppp_cl_1->umc_mtc_cl) {
     *achl1++ = 1;                          /* Maximum-Receive-Unit MRU */
     *achl1++ = 2 + 2;                      /* size of option          */
     *achl1++ = (unsigned char) (adsp_ppp_cl_1->umc_mtc_cl >> 8);
     *achl1++ = (unsigned char) adsp_ppp_cl_1->umc_mtc_cl;
   }
#endif
   *achl1++ = 5;                            /* Magic-Number            */
#ifndef HL_PPP_CLIENT
   *achl1++ = 2 + sizeof(adsp_ppp_cl_1->adsc_ppp_se_1->chrc_magic_number_cl);  /* size of option */
   memcpy( achl1, adsp_ppp_cl_1->adsc_ppp_se_1->chrc_magic_number_cl, sizeof(adsp_ppp_cl_1->adsc_ppp_se_1->chrc_magic_number_cl) );
   achl1 += sizeof(adsp_ppp_cl_1->adsc_ppp_se_1->chrc_magic_number_cl);
#endif
#ifdef HL_PPP_CLIENT
   *achl1++ = 2 + sizeof(adsp_ppp_cl_1->chrc_magic_number_cl);  /* size of option */
   memcpy( achl1, adsp_ppp_cl_1->chrc_magic_number_cl, sizeof(adsp_ppp_cl_1->chrc_magic_number_cl) );
   achl1 += sizeof(adsp_ppp_cl_1->chrc_magic_number_cl);
#endif
   memcpy( achl1, ucrs_send_conf_2, sizeof(ucrs_send_conf_2) );
   achl1 += sizeof(ucrs_send_conf_2);
#ifdef TRY_081202
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
#endif
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_send_conf_1) + 0) = adsp_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
   iml1 = achl1 - (chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_send_conf_1) - 1);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_send_conf_1) + 1) = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_send_conf_1) + 2) = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   achl1 - (chrl_buf + D_LEN_L2TP_HEADER) );
} /* end m_ppp_client_send_conf()                                      */

/** send Configure-Request as server to client                         */
static void m_ppp_server_send_conf( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   int        iml1;                         /* working-variable        */
   char       *achl1, *achl2;               /* working variables       */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */

   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl2 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, ucrs_send_conf_1, sizeof(ucrs_send_conf_1) );
   achl1 = dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) + 3;
   if (adsp_ppp_se_1->umc_mtc_se) {
     *achl1++ = 1;                          /* Maximum-Receive-Unit MRU */
     *achl1++ = 2 + 2;                      /* size of option          */
     *achl1++ = (unsigned char) (adsp_ppp_se_1->umc_mtc_se >> 8);
     *achl1++ = (unsigned char) adsp_ppp_se_1->umc_mtc_se;
   }
#ifdef B120504
   memcpy( achl1, ucrs_auth_prot_pap, sizeof(ucrs_auth_prot_pap) );
   achl1 += sizeof(ucrs_auth_prot_pap);
#endif
   switch (adsp_ppp_se_1->chrc_ppp_auth[ adsp_ppp_se_1->imc_auth_no ]) {
     case ied_pppa_pap:                     /* PAP                     */
       memcpy( achl1, ucrs_auth_prot_pap, sizeof(ucrs_auth_prot_pap) );
       achl1 += sizeof(ucrs_auth_prot_pap);
       break;
//   case ied_pppa_chap:                    /* CHAP                    */
     case ied_pppa_ms_chap_v2:              /* MS-CHAP-V2              */
       memcpy( achl1, ucrs_auth_prot_chap_1, sizeof(ucrs_auth_prot_chap_1) );
       achl1 += sizeof(ucrs_auth_prot_chap_1);
       break;
//   case ied_pppa_eap:                     /* EAP                     */
#ifndef B140302
     case ied_pppa_eap:                     /* EAP                     */
       memcpy( achl1, ucrs_auth_prot_eap_1, sizeof(ucrs_auth_prot_eap_1) );
       achl1 += sizeof(ucrs_auth_prot_eap_1);
       break;
#endif
   }
   *achl1++ = 5;                            /* Magic-Number            */
   *achl1++ = 2 + sizeof(adsp_ppp_se_1->chrc_magic_number_se);  /* size of option */
   memcpy( achl1, adsp_ppp_se_1->chrc_magic_number_se, sizeof(adsp_ppp_se_1->chrc_magic_number_se) );
   achl1 += sizeof(adsp_ppp_se_1->chrc_magic_number_se);
   memcpy( achl1, ucrs_send_conf_2, sizeof(ucrs_send_conf_2) );
   achl1 += sizeof(ucrs_send_conf_2);
   iml1 = achl1 - (dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) - 1);
#ifdef B120505
   *(dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) + 0) = 0;  /* identifier */
#else
   *(dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) + 0) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;   /* sent identification LCP configure */
#endif
   *(dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) + 1) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + sizeof(ucrs_send_conf_1) + 2) = (unsigned char) iml1;
   dsl_buf_ve.imc_len_data = achl1 - dsl_buf_ve.achc_data;  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
} /* end m_ppp_server_send_conf()                                      */

#ifdef B120506
/* send authentication for PAP as client to server                     */
static void m_client_auth_send_pap( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_ppp_auth_1 *adsl_ppp_auth_1;  /* for authentication      */
   char       chrl_buf[ 1024 ];             /* send buffer             */

/* attention - credentials have to be ANSI-819 */
   adsl_ppp_auth_1 = adsp_ppp_cl_1->adsc_ppp_auth_1;  /* get data for authentication */
   if (adsl_ppp_auth_1 == NULL) return;     /* no data for authentication */
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_auth_prot_pap + 2, 2 );
   achl1 = chrl_buf + D_LEN_L2TP_HEADER + 2 + 4;
   *achl1++ = (unsigned char) adsl_ppp_auth_1->imc_len_userid;  /* length userid */
   memcpy( achl1, adsl_ppp_auth_1 + 1, adsl_ppp_auth_1->imc_len_userid );  /* copy userid */
   achl1 += adsl_ppp_auth_1->imc_len_userid;  /* after userid          */
   *achl1++ = (unsigned char) adsl_ppp_auth_1->imc_len_password;  /* length password */
   memcpy( achl1,
           (char *) (adsl_ppp_auth_1 + 1) + adsl_ppp_auth_1->imc_len_userid,
           adsl_ppp_auth_1->imc_len_password );  /* copy password      */
   achl1 += adsl_ppp_auth_1->imc_len_password;  /* after password      */
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 0) = 1;  /* Code Authenticate-Request */
   adsl_ppp_auth_1->chc_ident = adsp_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 1) = adsl_ppp_auth_1->chc_ident;
   iml1 = achl1 - (chrl_buf + D_LEN_L2TP_HEADER + 2);
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 1) = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   achl1 - (chrl_buf + D_LEN_L2TP_HEADER) );
} /* end m_client_auth_send_pap()                                      */
#endif

/** send authentication for PAP as client to server                    */
static void m_client_auth_send_pap( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_userid;  /* record in storage for authentication */
   struct dsd_ppp_auth_record *adsl_par_password;  /* record in storage for authentication */
   char       chrl_buf[ 1024 ];             /* send buffer             */

   if (adsp_ppp_cl_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "m_client_auth_send_pap() no adsc_ppp_auth_header - illogic" );
     return;
   }
   adsl_par_userid = NULL;                  /* clear userid - record in storage for authentication */
   adsl_par_password = NULL;                /* clear password - record in storage for authentication */
   adsl_par_w1 = adsp_ppp_cl_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over records in storage for authentication */
     switch (adsl_par_w1->iec_par) {        /* type of authentication record */
       case ied_par_userid:                 /* type of authentication record - userid */
         adsl_par_userid = adsl_par_w1;     /* set userid - record in storage for authentication */
         break;
       case ied_par_password:               /* type of authentication record - password */
         adsl_par_password = adsl_par_w1;   /* set password - record in storage for authentication */
         break;
     }
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_userid == NULL) {           /* no userid               */
     adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "m_client_auth_send_pap() no userid - illogic" );
     return;
   }
/* attention - credentials have to be ANSI-819 */
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_auth_prot_pap + 2, 2 );
   achl1 = chrl_buf + D_LEN_L2TP_HEADER + 2 + 4;
   *achl1++ = (unsigned char) adsl_par_userid->imc_len_data;  /* length userid */
   memcpy( achl1, adsl_par_userid + 1, adsl_par_userid->imc_len_data );  /* copy userid */
   achl1 += adsl_par_userid->imc_len_data;  /* after userid            */
   if (adsl_par_password == NULL) {         /* no password             */
     *achl1++ = 0;                          /* length password         */
   } else {                                 /* with password           */
     *achl1++ = (unsigned char) adsl_par_password->imc_len_data;  /* length password */
     memcpy( achl1, adsl_par_password + 1, adsl_par_password->imc_len_data );  /* copy password */
     achl1 += adsl_par_password->imc_len_data;  /* after password      */
   }
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 0) = 1;  /* Code Authenticate-Request */
// adsl_ppp_auth_1->chc_ident = adsp_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
// *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 1) = adsl_ppp_auth_1->chc_ident;
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 1) = adsp_ppp_cl_1->ucc_send_ident;
   iml1 = achl1 - (chrl_buf + D_LEN_L2TP_HEADER + 2);
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + 2 + 2 + 1) = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   achl1 - (chrl_buf + D_LEN_L2TP_HEADER) );
} /* end m_client_auth_send_pap()                                      */

/** send authentication for CHAP 1 as client to server                 */
static void m_client_auth_send_chap_1( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   adsp_ppp_cl_1->amc_ppp_cl_abend( adsp_ppp_cl_1, "MS-CHAP-V2 not supported" );
} /* end m_client_auth_send_chap_1()                                   */

/** send authentication for MS-CHAPV2 challenge as server to client    */
static void m_server_auth_send_mscv2_1( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   int        iml1;                         /* working variable        */
   struct dsd_ppp_auth_record *adsl_par_w1;  /* record in storage for authentication */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */

   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_server_auth_send_mscv2_1() no adsc_ppp_auth_header - illogic" );
     return;
   }
   adsl_par_w1 = adsp_ppp_se_1->adsc_ppp_auth_header->adsc_ppp_auth_record;  /* chain of records in storage for authentication */
   while (adsl_par_w1) {                    /* loop over records in storage for authentication */
     if (adsl_par_w1->iec_par == ied_par_mscv2_challenge) break;  /* type of authentication record - MS-CHAP-V2 challenge */
     adsl_par_w1 = adsl_par_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_par_w1 == NULL) {               /* no MS-CHAP-V2 challenge */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_server_auth_send_mscv2_1() no MS-CHAP-V2 challenge - illogic" );
     return;
   }
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, ucrs_auth_prot_chap_1 + 2, 2 );
   *(dsl_buf_ve.achc_data + 2) = (unsigned char) 1;  /* code challenge */
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   *(dsl_buf_ve.achc_data + 2 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   iml1 = 1 + 1 + 2 + adsl_par_w1->imc_len_data;  /* length of the data */
   *(dsl_buf_ve.achc_data + 2 + 2 + 0) = (unsigned char) (iml1 >> 8);
   *(dsl_buf_ve.achc_data + 2 + 2 + 1) = (unsigned char) iml1;
   memcpy( dsl_buf_ve.achc_data + 2 + 2 + 1 + 1, adsl_par_w1 + 1, adsl_par_w1->imc_len_data );
   dsl_buf_ve.imc_len_data = 2 + iml1;      /* set length              */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;
} /* end m_server_auth_send_mscv2_1()                                  */

/** send EAP Request Identity as server to client                      */
static void m_server_auth_send_eap_1( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   int        iml1;                         /* working variable        */
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */

#ifdef XYZ1
   if (adsp_ppp_se_1->adsc_ppp_auth_header == NULL) {  /* no storage for authentication */
     adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "m_server_auth_send_eap_1() no adsc_ppp_auth_header - illogic" );
     return;
   }
#endif
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, ucrs_eap_request_identity, sizeof(ucrs_eap_request_identity) );
   adsp_ppp_se_1->ucc_send_ident_lcp_conf++;  /* increment sent identification LCP configure */
   *(dsl_buf_ve.achc_data + 2 + 1) = adsp_ppp_se_1->ucc_send_ident_lcp_conf;  /* sent identification LCP configure */
   dsl_buf_ve.imc_len_data = sizeof(ucrs_eap_request_identity);  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
   return;
} /* end m_server_auth_send_eap_1()                                    */

/** process IPCP from PPP client if passed thru over L2TP              */
static void m_ppp_server_ipcp_pass( struct dsd_ppp_server_1 *adsp_ppp_se_1,
                                    char *achp_inp, int imp_len_inp,
                                    BOOL bop_resend ) {
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_len;                      /* length of packet        */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of input            */
   char       *achl_record;                 /* address of record       */
   union {
     char *   achrl_option_send[ 16 ];      /* options to be sent      */
   };
   char       chrl_buf[ 256 ];              /* send buffer             */
#ifdef TRACEHL1
   char       chrl_date_time[ 32 ];         /* for date and time       */
#endif

#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T %s m_ppp_server_ipcp_pass( ... , %d ) imc_options=0X%08X",
                 __LINE__, chrl_date_time, bop_resend, adsp_ppp_se_1->adsc_ppp_cl_1->imc_options );
#endif
#ifdef TRY_081203
   if (adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_SEND) return;  /* IPCP send INETAS already complete */
#endif
#ifdef TRY_081204_01
   if (adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_IPCP_RECV) return;  /* IPCP receive INETAS complete */
#endif
   if (bop_resend == FALSE) {               /* is not resent           */
     if (adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save) {  /* saved block for IPCP */
       return;                              /* discard this record     */
     }
     adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save = (char *) malloc( imp_len_inp );
     memcpy( adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save, achp_inp, imp_len_inp );
   }
   if ((adsp_ppp_se_1->adsc_ppp_cl_1->imc_options & D_PPP_OPT_AUTH_OK) == 0) {  /* authentication not yet succeeded */
     return;                                /* wait till authenticated */
   }
   achl_rp = achp_inp;                      /* get address input       */
   achl_end = achp_inp + imp_len_inp;       /* compute end input       */
   achl_rp += sizeof(ucrs_ctrl_ipcp) + 2 + 2;
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   achl_record = achl_rp;                   /* save address of record  */
   iml1 = 0;                                /* count options to send   */
   iml_len = sizeof(ucrs_ctrl_ipcp) + 2 + 2;  /* length of packet      */

   p_ipcp_opt_00:                           /* check options IPCP      */
   if ((achl_rp + 2) > achl_end) {          /* packet not long enough  */
     goto p_inv_00;                         /* packet invalid          */
   }
   if (*((unsigned char *) achl_rp + 1) < 2) {  /* length too short    */
     goto p_inv_00;                         /* packet invalid          */
   }
   if ((achl_rp + *((unsigned char *) achl_rp + 1)) > achl_end) {  /* option too long */
     goto p_inv_00;                         /* packet invalid          */
   }
   iml2 = -1;                               /* invalid option number   */
   if (*((unsigned char *) achl_rp) == 3) {  /* option type INETA      */
     iml2 = 0;
   } else if (   (*((unsigned char *) achl_rp) >= 129)
              && (*((unsigned char *) achl_rp) <= 132)) {
     iml2 = *((unsigned char *) achl_rp) - 129 + 1;
   }
   while (iml2 >= 0) {                      /* option that should be sent */
     if (*((unsigned char *) achl_rp + 1) != (2 + sizeof(UNSIG_MED))) {
       goto p_inv_00;                       /* options length invalid  */
     }
     if (adsp_ppp_se_1->chrc_ineta_stat[ iml2 ] & D_INETA_OPT_REJECTED) break;  /* INETA rejected */
     if (iml1 >= (sizeof(achrl_option_send) / sizeof(achrl_option_send[0]))) {
       goto p_inv_00;                       /* too many invalid options */
     }
     achrl_option_send[ iml1++ ] = achl_rp;  /* save option to be sent */
     iml_len += 2 + sizeof(UNSIG_MED);      /* increment length to send */
     break;
   }
   achl_rp += *((unsigned char *) achl_rp + 1);  /* end of this option */
   if (achl_rp < achl_end) {                /* more options follow     */
     goto p_ipcp_opt_00;                    /* check options IPCP      */
   }
   if (iml1 == 0) goto p_inv_00;            /* no options to be sent found */
   if ((D_LEN_L2TP_HEADER + iml_len) > sizeof(chrl_buf)) goto p_inv_00;  /* packet too long */
   /* send Configure-Request from client to server                     */
#ifdef TRACEHL_081204
   m_hl1_printf( "HWSPPPP01T l%05d xs-gw-ppp T m_ppp_server_ipcp_pass() imc_options=0X%08X send Configure-Request",
                 __LINE__, adsp_ppp_se_1->adsc_ppp_cl_1->imc_options );
#endif
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_ctrl_ipcp, sizeof(ucrs_ctrl_ipcp) );
   achl1 = chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 4;
   iml3 = 0;                                /* clear index             */
   do {                                     /* loop output of options to send */
     memcpy( achl1, achrl_option_send[ iml3 ], *((unsigned char *) achrl_option_send[ iml3 ] + 1) );
     if (*((unsigned char *) achl1) == 3) {  /* option type INETA      */
       iml2 = 0;
     } else if (   (*((unsigned char *) achl1) >= 129)
                && (*((unsigned char *) achl1) <= 132)) {
       iml2 = *((unsigned char *) achl1) - 129 + 1;
     } else {
       goto p_inv_00;                       /* program illogic         */
     }
     if (adsp_ppp_se_1->chrc_ineta_stat[ iml2 ] & D_INETA_OPT_SET) {  /* INETA set for IPCP */
       memcpy( achl1 + 2, &adsp_ppp_se_1->chrrc_ineta[ iml2 ][0], sizeof(UNSIG_MED) );
     }
     achl1 += *((unsigned char *) achrl_option_send[ iml3 ] + 1);
     iml3++;                                /* end of this option      */
   } while (iml3 < iml1);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 0) = (unsigned char) 1;  /* Configure-Request */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 1) = adsp_ppp_se_1->adsc_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_se_1->adsc_ppp_cl_1->ucc_send_ident++;  /* increment send identifier */
   iml1 = iml_len - sizeof(ucrs_ctrl_ipcp);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_se_1->adsc_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_se_1->adsc_ppp_cl_1,
                                                  chrl_buf + D_LEN_L2TP_HEADER,
                                                  iml_len );
#ifdef OLD01
   if (bop_resend) return;                  /* is resend               */
   adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save = (char *) malloc( imp_len_inp );
   memcpy( adsp_ppp_se_1->adsc_ppp_cl_1->achc_ipcp_save, achp_inp, imp_len_inp );
#endif
   return;                                  /* wait till response from PPP server */

   p_inv_00:                                /* packet invalid          */
// to-do 19.11.08 KB
   adsp_ppp_se_1->amc_ppp_se_abend( adsp_ppp_se_1, "received invalid packet" );
   return;
} /* end m_ppp_server_ipcp_pass()                                      */

#ifdef HL_PPP_CLIENT
/** send IPCP INETAs as client to server                               */
static void m_ppp_client_send_ipcp( struct dsd_ppp_client_1 *adsp_ppp_cl_1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   char       chrl_buf[ 256 ];              /* send buffer             */

#ifdef TRACEHL1
   m_hl1_printf( "xs-gw-ppp-l%05d-T m_ppp_client_send_ipcp() called",
                 __LINE__ );
#endif
   memcpy( chrl_buf + D_LEN_L2TP_HEADER, ucrs_ctrl_ipcp, sizeof(ucrs_ctrl_ipcp) );
   achl1 = chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 4;
   iml1 = 0;                                /* clear index             */
   do {                                     /* loop output of options to send */
     if ((adsp_ppp_cl_1->chrc_ineta_stat[ iml1 ] & D_INETA_OPT_REJECTED) == 0) {  /* INETA not rejected */
       *(achl1 + 0) = ucrs_send_ipcp_index_ineta[ iml1 ];  /* option type */
       *(achl1 + 1) = 1 + 1 + sizeof(UNSIG_MED);  /* length of option  */
       memcpy( achl1 + 2, &adsp_ppp_cl_1->chrrc_ineta[ iml1 ][0], sizeof(UNSIG_MED) );
       achl1 += 1 + 1 + sizeof(UNSIG_MED);  /* after this option       */
     }
     iml1++;                                /* end of this option      */
   } while (iml1 < (sizeof(adsp_ppp_cl_1->chrrc_ineta) / sizeof(adsp_ppp_cl_1->chrrc_ineta[0])));
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 0) = (unsigned char) 1;  /* Configure-Request */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 1) = adsp_ppp_cl_1->ucc_send_ident;  /* send identifier */
   adsp_ppp_cl_1->ucc_send_ident++;         /* increment send identifier */
   iml1 = achl1 - (chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp));  /* length of packet */
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 2 + 0)
      = (unsigned char) (iml1 >> 8);
   *(chrl_buf + D_LEN_L2TP_HEADER + sizeof(ucrs_ctrl_ipcp) + 2 + 1)
      = (unsigned char) iml1;
   adsp_ppp_cl_1->amc_ppp_cl_send( adsp_ppp_cl_1,
                                   chrl_buf + D_LEN_L2TP_HEADER,
                                   sizeof(ucrs_ctrl_ipcp) + iml1 );
} /* end m_ppp_client_send_ipcp()                                      */
#endif

/** set the configured INETAs                                          */
static void m_ppp_server_set_inetas( struct dsd_ppp_server_1 *adsp_ppp_se_1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   struct dsd_wsptun_conf_1 *adsl_wsptun_conf_1;
   struct dsd_buf_vector_ele dsl_buf_ve;    /* vector with data to send */

   if (adsp_ppp_se_1->adsc_ppp_cl_1) {      /* with PPP client         */
     achl1 = adsp_ppp_se_1->amc_ppp_se_get_ineta_client( adsp_ppp_se_1 );
     if (achl1 == NULL) return;             /* is not configured       */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[0][0]) = *((UNSIG_MED *) achl1);
     adsp_ppp_se_1->chrc_ineta_stat[0] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
     return;                                /* all done                */
   }
   achl1 = adsp_ppp_se_1->amc_ppp_se_get_ineta_client( adsp_ppp_se_1 );
#ifndef B150520
   if (achl1 == NULL) return;               /* is not configured       */
#endif
   *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[0][0]) = *((UNSIG_MED *) achl1);
   adsp_ppp_se_1->chrc_ineta_stat[0] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   adsl_wsptun_conf_1 = m_get_wsptun_conf_1();
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_pri)) {  /* primary DNS INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[1][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_pri);
     adsp_ppp_se_1->chrc_ineta_stat[1] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
#ifdef B121015
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_sec)) {  /* secondary DNS INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[2][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_sec);
     adsp_ppp_se_1->chrc_ineta_stat[2] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_pri)) {  /* primary wins INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[3][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_pri);
     adsp_ppp_se_1->chrc_ineta_stat[3] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
#else
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_pri)) {  /* primary wins INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[2][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_pri);
     adsp_ppp_se_1->chrc_ineta_stat[2] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_sec)) {  /* secondary DNS INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[3][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_dns_sec);
     adsp_ppp_se_1->chrc_ineta_stat[3] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
#endif
   if (*((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_sec)) {  /* secondary wins INETA IPV4 */
     *((UNSIG_MED *) &adsp_ppp_se_1->chrrc_ineta[4][0]) = *((UNSIG_MED *) &adsl_wsptun_conf_1->chrc_ipv4_nbns_sec);
     adsp_ppp_se_1->chrc_ineta_stat[4] |= D_INETA_OPT_SET;  /* INETA set for IPCP */
   }
   /* send IPCP Configure-Request from PPP server to PPP client        */
   achl1 = m_get_wsptun_ineta_ipv4_adapter();  /* get address INETA IPV4 of adapater */
// to-do 18.08.10 KB - achl1 may be NULL
   if (achl1 == NULL) {                     /* could not get adapter address */
     return;
   }
   iml1 = m_htun_getrecvbuf( &dsl_buf_ve.ac_handle, &dsl_buf_ve.achc_data );
// achl2 = dsl_buf_ve.achc_data + iml1;     /* end of buffer           */
   dsl_buf_ve.achc_data += D_SPACE_HEADER;  /* leave space for header  */
   memcpy( dsl_buf_ve.achc_data, ucrs_send_ipcp_confreq_1, sizeof(ucrs_send_ipcp_confreq_1) );
   memcpy( dsl_buf_ve.achc_data + sizeof(ucrs_send_ipcp_confreq_1), achl1, sizeof(UNSIG_MED) );
   dsl_buf_ve.imc_len_data = sizeof(ucrs_send_ipcp_confreq_1) + sizeof(UNSIG_MED);  /* set length */
   adsp_ppp_se_1->amc_ppp_se_send( adsp_ppp_se_1, &dsl_buf_ve );
} /* end m_ppp_server_set_inetas()                                     */

#ifdef TRACEHL1
/** subroutine to display date and time                                */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

/** subroutine to dump storage-content to console                      */
static void m_console_out( char *achp_buff, int implength ) {
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
     m_hl1_printf( "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                            */
#endif
