//#define D_MAKE_INVALID
#ifdef D_DOTO_120106
global variable with number of currently
connected cluster member of the same group
#endif
#ifdef D_DOTO_050331
0X10 - 0X12 received from server - INETA
UDP-packet contains 0X12 INETA + port) instead of 0X10 (port)
send only once to client, but send multiple to client if list of applications
INETA 4 or 16 bytes long / IPV6
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: XSLBGW01                                            |*/
/*| -------------                                                     |*/
/*|  HOBLink Secure / Load-Balancing Gateway                          |*/
/*|  KB 05.02.01                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2001                                |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 / VC8                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef OLD_1112
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
#ifdef MAKEDEF1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HL_WINALL1
#include <windows.h>
#else
#include "solaris.h"
#endif
#define __XHSERVIF__
#include "XSHLSE01.H"

#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((USHORT) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))

#define TID    DWORD
#define HEV    void *
#define HQUEUE void *
#define APIRET int
#endif
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifdef HL_UNIX
#ifdef HL_LINUX
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif
#endif
#ifndef HL_X86
#ifndef INETA_LOAD_BYTE
#define INETA_LOAD_BYTE
#endif
#else
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif
#endif
#endif
#ifdef WIN64
#ifdef _IA64_
#ifndef INETA_LOAD_BYTE
#define INETA_LOAD_BYTE
#endif
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif
#endif
#ifdef WIN32
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif
#endif
#endif

#define DEF_ERR_BLADE_IN_USE 20000
#define DEF_NOSHAREDEVIATION 1000

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Constant data.                                                    |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static char chrs_send1[] = {
  'H', 'O', 'B', ' ', 'L', 'B', 0, 'Q', 0
};

static char chrs_rece1[] = {
  'H', 'O', 'B', ' ', 'L', 'B', 0, 'R', 0
};

/*+-------------------------------------------------------------------+*/
/*| Internal used structures and classes.                             |*/
/*+-------------------------------------------------------------------+*/

struct dsd_lb_rec_server {                  /* server definition received */
   struct dsd_lb_rec_server *adsc_next;     /* next in chain           */
   char       chrc_ineta_port[ 2 + 16 + 2 ];  /* save INETA and port   */
#ifdef OLD_1112
   UNSIG_MED ulineta;                       /* IP address to connect   */
   int        imc_port;                     /* port set                */
#endif
   int        imc_load;                     /* load received           */
   int        imc_disconnect;               /* disconnected sessions   */
   BOOL       boc_appl;                     /* appl received           */
   int        imc_len_fields;               /* length of fields        */
};

struct DCHECK_SERVER {                      /* server definition rece  */
   UNSIG_MED ulineta;                       /* IP address to connect   */
   BOOL  bo_received_LB;                    /* something received      */
};
#ifndef OLD_1112
struct dsd_check_server {                   /* server definition received */
   struct dsd_wtsg_1 *adsc_wtsg_1;          /* gateway LB INETA        */
   BOOL       boc_received_lb;              /* something received      */
};
#endif

struct dsd_chineta {                        /* chained INETA           */
   struct dsd_chineta *adsc_next;           /* chain                   */
   int        imc_filled;                   /* length filled           */
   char       chrc_ineta_str[ 1024 ];       /* INETA structures        */
};

struct dsd_lbal_conn_server {               /* fields for connect to server */
   char       chrc_ineta_port[ 2 + 16 + 2 ];  /* save INETA and port   */
   BOOL       boc_other_server;             /* already connected to other servers */
};

class dsd_lbal_gw_1 {                       /* class load balancing GW */
   private:
     void *   aclparam;                     /* from calling program    */
     int      imc_function;                 /* function requested      */
     int      imc_reclen;                   /* received from client    */
     char     *achc_recbuf;                 /* received from client    */
     struct dsd_chineta *adsc_chineta_save;  /* saved INETA            */
     struct dsd_lb_rec_server *adsc_lb_rec_server;  /* chain of server received */
     struct dsd_lb_rec_server *adsc_lrs_cluster;  /* VDI cluster request */
#ifdef OLD_1112
     struct DCHECK_SERVER *ad_che_server;   /* array of server check   */
#endif
#ifndef OLD_1112
     struct dsd_check_server *adsrc_check_server;  /* array server definition received */
#endif
     int      imc_arraylen_check;           /* length of array         */
     enum en_timeout { en_to_notset, en_to_time1, en_to_time2, en_to_bstrtime };
     enum en_timeout ienum_to;              /* status timeout          */
     BOOL     boc_s_appl;                   /* search application      */
     int      imc_time1;                    /* timer wait all          */
     int      imc_time2;                    /* timer wait any          */
     BOOL     boc_is_blade_server;          /* function BLADEGATE / VDI */
     int      imc_start_time;               /* save start time in sec  */
     BOOL     boc_reconnect;                /* reconnect requested from WTS client */
     char     chrc_ineta_port[ 2 + 16 + 2 ];  /* save INETA and Port   */
     BOOL     boc_other_server;             /* already connected to other servers */
     int      imc_nosharedeviation;         /* percentage configured   */
     void m_check_other_server( struct dsd_lbal_conn_server *, struct dsd_lb_rec_server * );
   public:
#ifndef B170329
     void *   ac_free_mem;                  /* free memory             */
#endif
     /* constructor                                                    */
     dsd_lbal_gw_1( void *apparam,
                    int iptime1, int iptime2,
                    struct dsd_wtsg_1 *adsp_wtsg_1,
                    BOOL bop_is_blade_server ) {
#ifdef OLD_1112
       struct dsd_wtsg_1 *audwtsg1;
       int iu1;
#endif
#ifndef OLD_1112
       int    iml1;                         /* working variable        */
       struct dsd_wtsg_1 *adsl_wtsg_1_w1;   /* gateway LB INETA        */
#endif

#ifdef TRACEHLC
       m_check_aclconn1( apparam, 1 );
#endif
       aclparam = apparam;                  /* save parameter fr user  */
       imc_reclen = 0;                      /* nothing received yet    */
       imc_function = -1;                   /* function not set        */
       adsc_lb_rec_server = NULL;           /* chain of server rece    */
       adsc_lrs_cluster = NULL;             /* VDI cluster request     */
       adsc_chineta_save = NULL;            /* saved INETA             */
       ienum_to = en_to_notset;             /* status timeout          */
       boc_s_appl = FALSE;                  /* search application      */
       imc_time1 = iptime1;                 /* get timer wait all      */
       imc_time2 = iptime2;                 /* get timer wait any      */
       boc_is_blade_server = bop_is_blade_server;  /* func BLADEGATE / VDI */
       imc_arraylen_check = 0;              /* length of array         */
       boc_reconnect = FALSE;               /* reconnect requested from WTS client */
       boc_other_server = FALSE;            /* already connected to other servers */
       imc_nosharedeviation = DEF_NOSHAREDEVIATION;  /* percentage configured */
       this->chrc_ineta_port[0] = 0;        /* reset save INETA and Port */
#ifndef B170329
       this->ac_free_mem = NULL;            /* free memory             */
#endif
#ifdef OLD_1112
       if (adsp_wtsg_1) {
         audwtsg1 = adsp_wtsg_1;             /* get anchor              */
         do {
           imc_arraylen_check++;           /* length of array         */
           audwtsg1 = audwtsg1->adsc_next;
         } while (audwtsg1);
         ad_che_server = (struct DCHECK_SERVER *)
                           malloc( imc_arraylen_check
                                   * sizeof(struct DCHECK_SERVER) );
         iu1 = 0;                           /* set index               */
         audwtsg1 = adsp_wtsg_1;               /* get anchor              */
         do {
           (ad_che_server + iu1)->ulineta = audwtsg1->umc_ineta;
           (ad_che_server + iu1)->bo_received_LB = FALSE;
           iu1++;                           /* count element           */
           audwtsg1 = audwtsg1->adsc_next;
         } while (audwtsg1);
       }
#endif
#ifndef OLD_1112
       if (adsp_wtsg_1) {
         adsl_wtsg_1_w1 = adsp_wtsg_1;      /* get anchor              */
         do {
           imc_arraylen_check++;            /* length of array         */
           adsl_wtsg_1_w1 = adsl_wtsg_1_w1->adsc_next;  /* get next in chain */
         } while (adsl_wtsg_1_w1);
         adsrc_check_server = (struct dsd_check_server *)  /* array server definition received */
                                malloc( imc_arraylen_check
                                          * sizeof(struct dsd_check_server) );
         iml1 = 0;                          /* clear index             */
         adsl_wtsg_1_w1 = adsp_wtsg_1;      /* get anchor              */
         do {
           (adsrc_check_server + iml1)->adsc_wtsg_1 = adsl_wtsg_1_w1;  /* gateway LB INETA */
           (adsrc_check_server + iml1)->boc_received_lb = FALSE;
           iml1++;                          /* count element           */
           adsl_wtsg_1_w1 = adsl_wtsg_1_w1->adsc_next;  /* get next in chain */
         } while (adsl_wtsg_1_w1);
       }
#endif
     }
     /* destructor                                                     */
     ~dsd_lbal_gw_1( void ) {
       struct dsd_lb_rec_server *adsl_lb_rec_server;  /* server received */
       struct dsd_chineta *adsl_chineta_save_1;  /* saved INETA        */

       if (imc_reclen) {                    /* already something in buffer */
         free( achc_recbuf );               /* free buffer TCP/IP      */
       }
       while (adsc_lb_rec_server) {         /* chain of server received */
         adsl_lb_rec_server = adsc_lb_rec_server;
         adsc_lb_rec_server = adsc_lb_rec_server->adsc_next;
         free( adsl_lb_rec_server );
       }
       if (imc_arraylen_check) {            /* length of array         */
#ifdef OLD_1112
         free( ad_che_server );
#endif
#ifndef OLD_1112
         free( adsrc_check_server );        /* array server definition received */
#endif
       }
       while (adsc_chineta_save) {          /* free all buffers        */
         adsl_chineta_save_1 = adsc_chineta_save;
         adsc_chineta_save = adsl_chineta_save_1->adsc_next;
         free( adsl_chineta_save_1 );
       }
#ifndef B170329
       if (this->ac_free_mem) {             /* free memory             */
         m_proc_free( this->ac_free_mem );  /* free memory             */
       }
#endif
     }

     /* something received from client                                 */
     void m_proc_cl_recv( char *achp_received, int imp_len_received,
                          char *achp_workarea_start, int imp_workarea_len,
                          char **aachp_ret_msg, int *aimp_ret_msg_len ) {
       int    iml1, iml2;                   /* working variables       */
       int    iml_packet;                   /* index in packet         */
//     int iu1, iu2;
       BOOL   bol1;                         /* working variable        */
       int    iml_prev_function;
//     int    iml1, iml2;                   /* working variable        */
       char   *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5, *achl_w6;  /* working variables */
       char   *achl_send1;
#ifdef OLD_1112
       UNSIG_MED uluineta;                  /* IP address to connect   */
       int iuport;                          /* port set                */
#endif
#ifdef OLD_1112
       int    iml_port;                     /* port set                */
#endif
#ifndef OLD_1112
       int    iml_ineta_len;                /* length INETA received   */
#endif
       int    iml_len_name;                 /* length of name          */
       char   *achl_name;                   /* address of name         */
       int    iml_len_domain;               /* length of domain        */
       char   *achl_domain;                 /* address of domain       */
       struct dsd_lb_rec_server *adsl_lb_rec_server;  /* server received */
       struct dsd_chineta *adsl_chineta_save_1;  /* saved INETA        */
#ifndef OLD_1112
       char   chrl_ineta_port[ 2 + 16 + 2 ];  /* area for INETA and port */
       struct sockaddr_storage dsl_soa_l;
#endif

#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_cl_recv called / imp_len_received=%d.", imp_len_received );
#endif
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 11 );
#endif
       iml_packet = 0;                      /* nothing received yet    */
       if (imp_len_received == 0) return;   /* nothing new             */
       if (imc_reclen) {                    /* already something in buffer */
         iml_packet = imp_len_received + imc_reclen;  /* length together */
         achl_w1 = (char *) malloc( iml_packet );  /* acquire storage  */
         memcpy( achl_w1, achc_recbuf, imc_reclen );  /* copy old      */
         memcpy( achl_w1 + imc_reclen, achp_received, imp_len_received );  /* copy new */
         free( achc_recbuf );               /* free old memory         */
         achc_recbuf = achl_w1;             /* set new buffer          */
         imc_reclen = iml_packet;           /* set how much in buffer  */
       } else {
         achl_w1 = achp_received;           /* set what received       */
         iml_packet = imp_len_received;     /* set length received     */
       }
#ifdef OLD_1112
       iuport = -1;                         /* do not connect          */
#endif
#ifdef OLD_1112
       iml_port = -1;                       /* do not connect          */
#endif
#ifndef OLD_1112
       iml_ineta_len = 0;                   /* do not connect          */
#endif

       pclre_rec20:                         /* process record          */
       if (iml_packet < 2) {                /* not complete record     */
         if (imc_reclen) return;            /* is already in buffer    */
         imc_reclen = imp_len_received;     /* set length received     */
         achc_recbuf = (char *) malloc( imc_reclen );  /* acquire storage */
         memcpy( achc_recbuf, achp_received, imc_reclen );  /* copy data received */
         return;                            /* all done                */
       }
       achl_w2 = achl_w1 + iml_packet;      /* end of storage          */
       iml1 = 0;                            /* set length              */
       achl_w3 = achl_w1;                   /* start at beginning      */
       while ((achl_w3 < achl_w2) && ((*achl_w3 & 0X80) != 0)) {
         iml1 <<= 7;
         iml1 |= *achl_w3 & 0X7F;
         achl_w3++;
       }
       if (achl_w3 >= achl_w2) {            /* not complete record     */
         if (imc_reclen) return;            /* is already in buffer    */
         imc_reclen = imp_len_received;     /* set length received     */
         achc_recbuf = (char *) malloc( imc_reclen );  /* acquire storage */
         memcpy( achc_recbuf, achp_received, imc_reclen );  /* copy data received */
         return;                            /* all done                */
       }
       iml1 <<= 7;
       iml1 |= *achl_w3 & 0X7F;
       achl_w3++;
       achl_w4 = achl_w1 + iml1;            /* end of this record      */
       if (achl_w4 > achl_w2) {             /* not complete record     */
         if (imc_reclen) return;            /* is already in buffer    */
         imc_reclen = imp_len_received;     /* set length received     */
         achc_recbuf = (char *) malloc( imc_reclen );  /* acquire storage */
         memcpy( achc_recbuf, achp_received, imc_reclen );  /* copy data received */
         return;                            /* all done                */
       }
       iml_prev_function = imc_function;    /* save previous function  */
       iml_len_name = 0;                    /* length of name          */
       achl_name = 0;                       /* address of name         */
       iml_len_domain = 0;                  /* length of domain        */
       achl_domain = 0;                     /* address of domain       */
       if ((achl_w3 + sizeof(chrs_send1)) > achl_w4) goto pclre_err00;
       if (memcmp( achl_w3, chrs_send1, sizeof(chrs_send1) )) {
         goto pclre_err00;
       }
       achl_w3 += sizeof(chrs_send1);
       achl_send1 = achp_workarea_start;    /* put in work area        */
       while (achl_w3 < achl_w4) {          /* loop over input packet  */
         iml2 = 0;                          /* set length              */
         achl_w5 = achl_w3;                 /* save beginning          */
         while ((achl_w3 < achl_w4) && ((*achl_w3 & 0X80) != 0)) {
           iml2 <<= 7;
           iml2 |= *achl_w3 & 0X7F;
           achl_w3++;
         }
         if (achl_w3 >= achl_w4) goto pclre_err00;
         iml2 <<= 7;
         iml2 |= *achl_w3 & 0X7F;
         achl_w3++;
         if (iml2 < 2) goto pclre_err00;
         achl_w5 += iml2;
         if (achl_w5 > achl_w4) goto pclre_err00;
         if (achl_w3 >= achl_w5) goto pclre_err00;
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_cl_recv received struct %02X current=%p end=%p.",
                         (unsigned char) *achl_w3, achl_w3, achl_w5 );
#endif
         if (((unsigned char) *achl_w3) < 0X40) {
#ifdef OLD_1112
           if (iuport >= 0) goto pclre_err00;
#endif
#ifndef OLD_1112
           if (iml_ineta_len > 0) {         /* length INETA received   */
             goto pclre_err00;
           }
#endif
           if (((unsigned char) *achl_w3) == 0X01) {  /* name found    */
             if (iml_len_name > 0) goto pclre_err00;
             achl_name = achl_w3 + 1;       /* name starts here        */
             achl_w6 = achl_name;           /* search zero             */
             while ((achl_w6 < achl_w5) && (*achl_w6)) achl_w6++;
             iml_len_name = achl_w6 - achl_name;  /* length of name    */
             achl_w6++;                     /* after zero              */
             achl_domain = achl_w6;         /* domain starts here      */
             while ((achl_w6 < achl_w5) && (*achl_w6)) achl_w6++;
             iml_len_domain = achl_w6 - achl_domain;  /* length of domain */
#ifdef TRACEHLS
             m_hlnew_printf( HLOG_TRACE1, "+++ found iml_len_name:%d iml_len_domain:%d iu2:%d.", iml_len_name, iml_len_domain, iu2 );
#endif
           } else if (((unsigned char) *achl_w3) == 0X02) {  /* appl found */
             if (iml_prev_function < 0) {
               boc_s_appl = TRUE;           /* search application      */
             }
#ifdef TRACEHLS
             m_hlnew_printf( HLOG_TRACE1, "+++ found appl iml2:%d.", iml2 );
#endif
           } else if (((unsigned char) *achl_w3) == 0X05) {  /* already connected to server */
             boc_other_server = TRUE;       /* already connected to other servers */
           } else if (((unsigned char) *achl_w3) == 0X06) {  /* nosharedeviation */
             imc_nosharedeviation = 0;      /* percentage configured */
             achl_w6 = achl_w3 + 1;         /* here starts number big endian */
             while (achl_w6 < achl_w5) {    /* get all digits          */
               imc_nosharedeviation <<= 8;  /* shift old value         */
               imc_nosharedeviation |= (unsigned char) *achl_w6;  /* apply new bits */
               achl_w6++;                   /* these digits processed  */
             }
           }
           if (achl_send1 == achp_workarea_start) {
             memcpy( achl_send1, chrs_send1, sizeof(chrs_send1) );
             achl_send1 += sizeof(chrs_send1);
           }
           memcpy( achl_send1, achl_w5 - iml2, iml2 );
           achl_send1 += iml2;
#ifdef TRACEHLS
           m_hlnew_printf( HLOG_TRACE1, "+++ memcpy to ouput iml2:%d.", iml2 );
#endif
         } else if (((unsigned char) *achl_w3) == 0X40) {
           if ((achl_w3 + 2) != achl_w5) goto pclre_err00;
           if (imc_function >= 0) goto pclre_err00;
           imc_function = (unsigned char) *(achl_w3 + 1);  /* set function */
#ifdef TRACEHLS
           m_hlnew_printf( HLOG_TRACE1, "+++ found imc_function:%d.", imc_function );
#endif
#ifdef TRACEHL1
           m_hlnew_printf( HLOG_TRACE1, "+++ found imc_function:%d.", imc_function );
#endif
         } else if (((unsigned char) *achl_w3) == 0X41) {
           /* start communication                                      */
           iml_ineta_len = achl_w5 - achl_w3 - 1 - 2;  /* length INETA received */
           if (   (iml_ineta_len != 4)      /* not IPV4                */
               && (iml_ineta_len != 16)) {  /* not IPV6                */
             goto pclre_err00;
           }
           if (iml_prev_function >= 0) {     /* is normal connect       */
             if (iml_prev_function != 0) goto pclre_err00;
             if (achl_send1 != achp_workarea_start) goto pclre_err00;
             /* check if INETA is valid, in list of INETA sent         */
#ifdef D_MAKE_INVALID
/* UUUU */
             *(achl_w3 + 2) = 1 + iml_ineta_len + 2;
             *(achl_w3 + 3) += 1;
#endif
             bol1 = FALSE;                  /* INETA not yet found     */
             adsl_chineta_save_1 = adsc_chineta_save;  /* get saved INETA */
             while (adsl_chineta_save_1) {
               iml1 = 0;                    /* beginning of buffer     */
               while (iml1 < adsl_chineta_save_1->imc_filled) {
                 iml2 = iml1;               /* save this entry         */
                 iml1 += 1 + (unsigned char) adsl_chineta_save_1->chrc_ineta_str[ iml2 ];
                 if (iml1 > adsl_chineta_save_1->imc_filled) {  /* invalid length */
                   goto pclre_err00;
                 }
                 if (   (adsl_chineta_save_1->chrc_ineta_str[ iml2 ] == (iml_ineta_len + 2))
                     && (!memcmp( &adsl_chineta_save_1->chrc_ineta_str[ iml2 + 1 ],
                                  achl_w3 + 1,
                                  iml_ineta_len + 2 ))) {
                   bol1 = TRUE;             /* this INETA found in table */
                   break;
                 }
               }
               adsl_chineta_save_1 = adsl_chineta_save_1->adsc_next;
             }
             if (bol1 == FALSE) {           /* INETA not yet found     */
#ifdef B090417
               m_display( "dsd_lbal_gw_1::m_proc_cl_recv client has sent invalid INETA" );
#else
               m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d client has sent invalid INETA", __LINE__ );
#endif
               return;
             }
#ifdef OLD_1112
#ifndef INETA_LOAD_BYTE
             uluineta = *((UNSIG_MED *) (au3 + 1));
#else
#ifndef __LITTLE_ENDIAN
             iu2 = 4;
             uluineta = 0;
             do {
               iu2--;
               uluineta <<= 8;
               uluineta |= (unsigned char) *(au3 + 4 - iu2);
             } while (iu2 > 0);
#else
             iu2 = 4;
             uluineta = 0;
             do {
               iu2--;
               uluineta <<= 8;
               uluineta |= (unsigned char) *(au3 + 1 + iu2);
             } while (iu2 > 0);
#endif
#endif
             iuport = ((unsigned char) *(au3 + 5) << 8)
                      | ((unsigned char) *(au3 + 6));
#endif
#ifdef XYZ1
             memset( &dsl_soa_l, 0, sizeof(struct sockaddr_storage) );
             if (iml_ineta_len == 4) {      /* IPV4                    */
               dsl_soa_l.ss_family = AF_INET;
               memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_addr,
                       achl_w3 + 1,
                       4 );
               memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_port,
                       achl_w3 + 1 + 4,
                       2 );
             } else {                       /* IPV6                    */
               dsl_soa_l.ss_family = AF_INET6;
               memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr,
                       achl_w3 + 1,
                       16 );
               memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_port,
                       achl_w3 + 1 + 16,
                       2 );
             }
#endif
             chrl_ineta_port[ 0 ] = (unsigned char) (2 + iml_ineta_len + 2);
             chrl_ineta_port[ 1 ] = (unsigned char) 0X12;
             memcpy( chrl_ineta_port + 2, achl_w3 + 1, iml_ineta_len + 2 );
           } else {                         /* is reconnect            */
             if (imc_function >= 0) goto pclre_err00;
             boc_reconnect = TRUE;          /* reconnect requested from WTS client */
             /* save INETA and Port                                    */
#ifdef OLD_1112
             memcpy( this->chrc_ineta_port, achl_w3 + 1, achl_w5 - (achl_w3 + 1) );
             /* put Tag 04 in packet used for load balancing query     */
             if (achl_send1 == achp_workarea_start) {
               memcpy( achl_send1, chrs_send1, sizeof(chrs_send1) );
               achl_send1 += sizeof(chrs_send1);
             }
             iml2 = achl_w5 - (achl_w3 + 1);  /* length INETA and port */
             *achl_send1++ = (unsigned char) (2 + iml2);
             *achl_send1++ = 0X04;          /* tag INETA and port      */
             memcpy( achl_send1, achl_w3 + 1, iml2 );
             achl_send1 += iml2;
#endif
#ifndef OLD_1112
             this->chrc_ineta_port[ 0 ] = (unsigned char) (2 + iml_ineta_len + 2 );
             this->chrc_ineta_port[ 1 ] = 0X12;
             memcpy( &this->chrc_ineta_port[ 2 ], achl_w3 + 1, iml_ineta_len + 2 );
             /* put Tag 04 in packet used for load balancing query     */
             if (achl_send1 == achp_workarea_start) {
               memcpy( achl_send1, chrs_send1, sizeof(chrs_send1) );
               achl_send1 += sizeof(chrs_send1);
             }
             *achl_send1++ = (unsigned char) (2 + iml_ineta_len + 2);
             *achl_send1++ = 0X04;          /* tag INETA and port      */
             memcpy( achl_send1, achl_w3 + 1, iml_ineta_len + 2 );
             achl_send1 += iml_ineta_len + 2;
#endif
           }
         }
         achl_w3 = achl_w5;                 /* set end of this struct  */
       }
       if ((imc_function < 0) && (boc_reconnect == FALSE)) goto pclre_err00;
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 2 );
#endif
       if (iml_prev_function < 0) {          /* was first record        */
         iml1 = HLGW_check_name( aclparam,
                                 achl_name, iml_len_name,
                                 achl_domain, iml_len_domain );
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "XSLGGW01-m_proc_cl_recv()-%05d HLGW_check_name() achl_name=%p iml_len_name=%d achl_domain=%p iml_len_domain=%d returned=%d",
                         __LINE__, achl_name, iml_len_name, achl_domain, iml_len_domain, iml1 );
#endif
         if (iml1) {                        /* error occured           */
           achl_w4 = achp_workarea_start;   /* get workarea            */
           memcpy( achl_w4 + 1, chrs_rece1, sizeof(chrs_rece1) );
           achl_w5 = achl_w4 + 1 + sizeof(chrs_rece1);  /* length record */
           *achl_w4 = 5 + sizeof(chrs_rece1);  /* length record           */
           *(achl_w5 + 0) = 4;              /* length structure        */
           *(achl_w5 + 1) = 0X4A;           /* error record            */
           *((unsigned char *) (achl_w5 + 2))
             = (unsigned char) (iml1 >> 8);  /* first byte error       */
           *((unsigned char *) (achl_w5 + 3))
             = (unsigned char) iml1;        /* second byte error       */
           *aimp_ret_msg_len = 5 + sizeof(chrs_rece1);  /* length record */
           *aachp_ret_msg = achl_w4;        /* set area to send        */
           achl_send1 = achp_workarea_start;  /* send nothing          */
           HLGW_set_abend( aclparam );      /* set abend               */
         }
       }
       if (achl_send1 > achp_workarea_start) {  /* something to send   */
#ifdef B120824
         if (imc_function > 0) {            /* gateway process request */
#ifdef FORKEDIT
         }
#endif
#else
         if (   (this->imc_function > 0)    /* gateway process request */
             || (this->boc_reconnect)) {    /* is reconnect            */
#endif
           if (ienum_to != en_to_notset) {  /* status timeout          */
             goto pclre_err00;
           }
           ienum_to = en_to_time1;          /* status timeout          */
#ifdef TRACEHLC
           m_check_aclconn1( aclparam, 3 );
#endif
           HLGW_set_timer( aclparam, imc_time1 );  /* time wait all   */
#ifdef TRACEHLC
           m_check_aclconn1( aclparam, 12 );
#endif
           if (boc_is_blade_server) {       /* function BLADEGATE / VDI */
             imc_start_time = m_get_time();  /* save start time in sec */
           }
         }
         HLGW_sendto_LB( aclparam, achp_workarea_start, achl_send1 - achp_workarea_start );
       }
       iml_packet = achl_w2 - achl_w3;      /* size of next record     */
#ifdef OLD_1112
       while (iuport >= 0) {                /* start communication     */
         if (iu1) goto pclre_err00;
         if (boc_is_blade_server) {         /* function BLADEGATE      */
           bol1 = dcl_blasetr_1::m_check_ineta( uluineta, dcl_blasetr_1::en_ca_stage1 );
           if (bol1 == FALSE) {             /* server is not valid     */
             au4 = achp_workarea_start;                /* get workarea            */
             memcpy( au4 + 1, chrs_rece1, sizeof(chrs_rece1) );
             au5 = au4 + 1 + sizeof(chrs_rece1);  /* length record    */
             *au4 = 5 + sizeof(chrs_rece1);  /* length record         */
             *(au5 + 0) = 4;                /* length structure        */
             *(au5 + 1) = 0X49;             /* error record            */
             *((unsigned char *) (au5 + 2))
               = (unsigned char) (DEF_ERR_BLADE_IN_USE >> 8);  /* first byte error */
             *((unsigned char *) (au5 + 3))
               = (unsigned char) DEF_ERR_BLADE_IN_USE;  /* second byte error */
             *aimp_ret_msg_len = 5 + sizeof(chrs_rece1);  /* length record   */
             *aachp_ret_msg = au4;              /* set area to send        */
             break;                         /* set message now         */
           }
           if (adsg_loconf_1_inuse->adsc_cluster) {  /* pointer to main cluster structure */
             while (adsc_lb_rec_server) {   /* chain of server received */
               adsl_lb_rec_server = adsc_lb_rec_server;
               adsc_lb_rec_server = adsc_lb_rec_server->next;
               free( adsl_lb_rec_server );
             }
             adsc_lb_rec_server = (struct dsd_lb_rec_server *) malloc( sizeof(struct dsd_lb_rec_server) );
             memset( adsc_lb_rec_server, 0, sizeof(struct dsd_lb_rec_server) );
             adsc_lb_rec_server->ulineta = uluineta;
             adsc_lb_rec_server->imc_port = iuport;
             adsc_lrs_cluster = adsc_lb_rec_server;  /* trimming twin request  */
             ienum_to = en_to_bstrtime;     /* status timeout          */
#ifdef TRACEHLC
             m_check_aclconn1( aclparam, 4 );
#endif
             HLGW_set_timer( aclparam, 1 );  /* time wait trimming twi */
#ifdef TRACEHLC
             m_check_aclconn1( aclparam, 13 );
#endif
             break;                         /* wait for timeout        */
           }
         }
#ifdef TRACEHLC
         m_check_aclconn1( aclparam, 5 );
#endif
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_cl_recv l%05d HLGW_start_conn( iuport=%d )", __LINE__, iuport );
#endif
#ifdef OLD_1112
         iu2 = HLGW_start_conn( aclparam, uluineta, iuport );
#endif
// to-do 04.01.12 KB conn with sockaddr
         iml2 = HLGW_start_conn( aclparam, (struct sockaddr *) &dsl_soa_l );
         achl_w4 = achp_workarea_start;     /* get workarea            */
         memcpy( achl_w4 + 1, chrs_rece1, sizeof(chrs_rece1) );
         achl_w5 = achl_w4 + 1 + sizeof(chrs_rece1);  /* length record        */
         if (iml2) {                        /* error occured           */
           *achl_w4 = 5 + sizeof(chrs_rece1);  /* length record        */
           *(achl_w5 + 0) = 4;              /* length structure        */
           *(achl_w5 + 1) = 0X49;           /* error record            */
           *((unsigned char *) (achl_w5 + 2))
             = (unsigned char) (iml2 >> 8);  /* first byte error       */
           *((unsigned char *) (achl_w5 + 3))
             = (unsigned char) iml2;        /* second byte error       */
           *aimp_ret_msg_len = 5 + sizeof(chrs_rece1);  /* length record */
         } else {
// to-do 04.01.12 KB
           *achl_w4 = 9 + sizeof(chrs_rece1);  /* length record           */
           *(achl_w5 + 0) = 8;                  /* length structure        */
           *(achl_w5 + 1) = 0X48;           /* connect record          */
#ifdef OLD01
           *((unsigned char *) (au5 + 2))
             = (unsigned char) (uluineta >> 24);  /* first byte IP add */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 16);  /* second byte IP a  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 8);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) uluineta;    /* fourth byte IP addr     */
#else
#ifndef INETA_LOAD_BYTE
           *((UNSIG_MED *) (au5 + 2)) = uluineta;
#else
#ifndef __LITTLE_ENDIAN
           *((unsigned char *) (au5 + 2))
             = (unsigned char) (uluineta >> 24);  /* first byte IP add */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 16);  /* second byte IP a  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 8);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) uluineta;    /* fourth byte IP addr     */
#else
           *((unsigned char *) (au5 + 2))
             = (unsigned char) uluineta;    /* first byte IP address   */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 8);  /* second byte IP ad  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 16);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) (uluineta >> 24);  /* fourth byte IP addr */
#endif
#endif
#endif
           *((unsigned char *) (au5 + 6))
             = (unsigned char) (iuport >> 8);  /* first byte port      */
           *((unsigned char *) (au5 + 7))
             = (unsigned char) iuport;      /* second byte port        */
           *aimp_ret_msg_len = 9 + sizeof(chrs_rece1);  /* length record     */
         }
         *aachp_ret_msg = achl_w4;          /* set area to send        */
         break;
       }
#endif
#ifndef OLD_1112
       while (iml_ineta_len > 0) {          /* start communication     */
#ifndef B120827
         if (this->boc_reconnect) break;    /* is reconnect            */
#endif
         if (iml_packet) goto pclre_err00;
         if (boc_is_blade_server) {         /* function BLADEGATE      */
//         bol1 = dcl_blasetr_1::m_check_ineta( uluineta, dcl_blasetr_1::en_ca_stage1 );
           bol1 = dcl_blasetr_1::m_check_ineta( chrl_ineta_port, dcl_blasetr_1::en_ca_stage1 );
// to-do 04.01.12 KB with sockaddr
           if (bol1 == FALSE) {             /* server is not valid     */
             achl_w4 = achp_workarea_start;  /* get workarea           */
             memcpy( achl_w4 + 1, chrs_rece1, sizeof(chrs_rece1) );
             achl_w5 = achl_w4 + 1 + sizeof(chrs_rece1);  /* length record */
             *achl_w4 = 5 + sizeof(chrs_rece1);  /* length record      */
             *(achl_w5 + 0) = 4;            /* length structure        */
             *(achl_w5 + 1) = 0X49;         /* error record            */
             *((unsigned char *) (achl_w5 + 2))
               = (unsigned char) (DEF_ERR_BLADE_IN_USE >> 8);  /* first byte error */
             *((unsigned char *) (achl_w5 + 3))
               = (unsigned char) DEF_ERR_BLADE_IN_USE;  /* second byte error */
             *aimp_ret_msg_len = 1 + sizeof(chrs_rece1) + 4;  /* length record */
             *aachp_ret_msg = achl_w4;      /* set area to send        */
             break;                         /* set message now         */
           }
           if (adsg_loconf_1_inuse->adsc_cluster) {  /* pointer to main cluster structure */
             while (adsc_lb_rec_server) {   /* chain of server received */
               adsl_lb_rec_server = adsc_lb_rec_server;
               adsc_lb_rec_server = adsc_lb_rec_server->adsc_next;
               free( adsl_lb_rec_server );
             }
             adsc_lb_rec_server = (struct dsd_lb_rec_server *) malloc( sizeof(struct dsd_lb_rec_server) );
             memset( adsc_lb_rec_server, 0, sizeof(struct dsd_lb_rec_server) );
#ifdef XYZ1
             adsc_lb_rec_server->ulineta = uluineta;
             adsc_lb_rec_server->imc_port = iuport;
             adsc_lrs_cluster = adsc_lb_rec_server;  /* trimming twin request  */
#endif
             memcpy( adsc_lb_rec_server->chrc_ineta_port,
                     chrl_ineta_port,
                     sizeof(adsc_lb_rec_server->chrc_ineta_port) );
             adsc_lrs_cluster = adsc_lb_rec_server;  /* VDI cluster request */
// to-do 04.01.12 KB with sockaddr
             ienum_to = en_to_bstrtime;     /* status timeout          */
#ifdef TRACEHLC
             m_check_aclconn1( aclparam, 4 );
#endif
             HLGW_set_timer( aclparam, 1 );  /* time wait trimming twi */
#ifdef TRACEHLC
             m_check_aclconn1( aclparam, 13 );
#endif
             break;                         /* wait for timeout        */
           }
         }
#ifdef TRACEHLC
         m_check_aclconn1( aclparam, 5 );
#endif
#ifdef B120211
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_cl_recv l%05d HLGW_start_conn( iuport=%d )", __LINE__, iuport );
#endif
#endif
#ifdef OLD_1112
         iu2 = HLGW_start_conn( aclparam, uluineta, iuport );
#endif
//ifdef B120824
// to-do 04.01.12 KB conn with sockaddr
         memset( &dsl_soa_l, 0, sizeof(struct sockaddr_storage) );
         if (chrl_ineta_port[ 0 ] == (2 + 4 + 2)) {  /* IPV4           */
           dsl_soa_l.ss_family = AF_INET;
           memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_addr,
                   &chrl_ineta_port[ 2 ],
                   4 );
           memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_port,
                   &chrl_ineta_port[ 2 + 4 ],
                   2 );
         } else {                           /* IPV6                    */
           dsl_soa_l.ss_family = AF_INET6;
           memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr,
                   &chrl_ineta_port[ 2 ],
                   16 );
           memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_port,
                   &chrl_ineta_port[ 2 + 16 ],
                   2 );
         }
         iml2 = HLGW_start_conn( aclparam, (struct sockaddr *) &dsl_soa_l );
         achl_w4 = achp_workarea_start;                    /* get workarea            */
         memcpy( achl_w4 + 1, chrs_rece1, sizeof(chrs_rece1) );
         achl_w5 = achl_w4 + 1 + sizeof(chrs_rece1);  /* length record        */
         if (iml2) {                        /* error occured           */
           *achl_w4 = 5 + sizeof(chrs_rece1);  /* length record        */
           *(achl_w5 + 0) = 4;              /* length structure        */
           *(achl_w5 + 1) = 0X49;           /* error record            */
           *((unsigned char *) (achl_w5 + 2))
             = (unsigned char) (iml2 >> 8);  /* first byte error       */
           *((unsigned char *) (achl_w5 + 3))
             = (unsigned char) iml2;        /* second byte error       */
           *aimp_ret_msg_len = 5 + sizeof(chrs_rece1);  /* length record */
         } else {
// to-do 04.01.12 KB
#ifdef XYZ1
           *achl_w4 = 9 + sizeof(chrs_rece1);  /* length record           */
           *(achl_w5 + 0) = 8;                  /* length structure        */
           *(achl_w5 + 1) = 0X48;           /* connect record          */
#ifdef OLD01
           *((unsigned char *) (au5 + 2))
             = (unsigned char) (uluineta >> 24);  /* first byte IP add */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 16);  /* second byte IP a  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 8);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) uluineta;    /* fourth byte IP addr     */
#else
#ifndef INETA_LOAD_BYTE
           *((UNSIG_MED *) (au5 + 2)) = uluineta;
#else
#ifndef __LITTLE_ENDIAN
           *((unsigned char *) (au5 + 2))
             = (unsigned char) (uluineta >> 24);  /* first byte IP add */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 16);  /* second byte IP a  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 8);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) uluineta;    /* fourth byte IP addr     */
#else
           *((unsigned char *) (au5 + 2))
             = (unsigned char) uluineta;    /* first byte IP address   */
           *((unsigned char *) (au5 + 3))
             = (unsigned char) (uluineta >> 8);  /* second byte IP ad  */
           *((unsigned char *) (au5 + 4))
             = (unsigned char) (uluineta >> 16);  /* third byte IP addr */
           *((unsigned char *) (au5 + 5))
             = (unsigned char) (uluineta >> 24);  /* fourth byte IP addr */
#endif
#endif
#endif
           *((unsigned char *) (au5 + 6))
             = (unsigned char) (iuport >> 8);  /* first byte port      */
           *((unsigned char *) (au5 + 7))
             = (unsigned char) iuport;      /* second byte port        */
           *aimp_ret_msg_len = 9 + sizeof(chrs_rece1);  /* length record     */
#endif
           *achl_w4 = 1 + sizeof(chrs_rece1) + 2 + iml_ineta_len + 2;  /* length record */
           *(achl_w5 + 0) = 2 + iml_ineta_len + 2;  /* length structure */
           *(achl_w5 + 1) = 0X48;           /* connect record          */
#ifdef XYZ1
           if (iml_ineta_len == 4) {        /* IPV4                    */
             memcpy( achl_w5 + 2,
                     &((struct sockaddr_in *) &dsl_soa_l)->sin_addr,
                     4 );
             memcpy( achl_w5 + 2 + 4,
                     &((struct sockaddr_in *) &dsl_soa_l)->sin_port,
                     2 );
           } else {                         /* IPV6                    */
             memcpy( achl_w5 + 2,
                     &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr,
                     16 );
             memcpy( achl_w5 + 2 + 16,
                     &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_port,
                     2 );
           }
#endif
           memcpy( achl_w5 + 2, chrl_ineta_port + 2, iml_ineta_len + 2 );
           *aimp_ret_msg_len = 1 + sizeof(chrs_rece1) + 2 + iml_ineta_len + 2;  /* length record */
         }
         *aachp_ret_msg = achl_w4;          /* set area to send        */
//endif
         break;
       }
#endif
       if (iml_packet) {                    /* some data not processed */
         achl_w1 = (char *) malloc( iml_packet );
         memcpy( achl_w1, achl_w3, iml_packet );  /* copy old record   */
         if (imc_reclen) free( achc_recbuf );  /* free old memory      */
         achc_recbuf = achl_w1;             /* set new buffer          */
         imc_reclen = iml_packet;           /* set length new buffer   */
         goto pclre_rec20;                  /* process next record     */
       }
       if (   (boc_other_server == FALSE)   /* already connected to other servers */
           && (imc_reclen)) {               /* record is in buffer     */
         free( achc_recbuf );               /* free old memory         */
         imc_reclen = 0;                    /* no more buffer          */
       }
       return;

       pclre_err00:                         /* invalid data received   */
#ifdef B090417
       m_display( "dsd_lbal_gw_1::m_proc_cl_recv pclre_err00" );
#else
       m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d pclre_err00 invalid load-balancind data received", __LINE__ );
       HLGW_set_abend( aclparam );          /* set abend               */
#endif
       return;
     }

#ifndef OLD_1112
     void m_proc_se_recv( struct sockaddr *adsp_soa,
                          char *achp_received, int imp_len_received,
                          BOOL bop_timed_out,
                          char *achp_workarea_start, int imp_workarea_len,
                          char **aachp_ret_msg, int *aimp_ret_msg_len ) {
       BOOL   bol1;                         /* working variable        */
       int    iml1, iml2, iml3, iml4, iml5;  /* working variables      */
       int    iml_ineta_len;                /* length INETA received   */
       char   *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5;  /* working variables */
#ifdef XYZ1
       int iu1, iu2;
       char *au1, *au2, *au3, *au4;
#endif
       char   *achl_start_field;            /* save start of field     */
       char   *achl_send1;
#ifdef XYZ1
       BOOL bou1;
       BOOL bol1;                           /* working variable        */
       int    iml1, iml2;                   /* working variables       */
       char   chrl_work1[8];                /* area for INETA          */
       BOOL   bol_ineta;                    /* INETA received          */
#endif
       BOOL   bol_load_set;                 /* load has been set       */
#ifdef XYZ1
       UNSIG_MED uml_ineta;                 /* save INETA              */
       UNSIG_MED uml_cmp_i;                 /* compare INETA           */
       int  iuport;                         /* port set                */
#endif
       int    iml_load_w1;                  /* load received           */
       int    iml_load_w2;                  /* load received           */
       int    iml_disconnect;               /* count disconnected sessions */
       int    iml_len_packet;               /* save length packet      */
       struct dsd_lb_rec_server *adsl_lb_rec_server_w1;  /* structure received */
       struct dsd_lb_rec_server *adsl_lb_rec_server_w2;  /* structure received */
       struct dsd_lb_rec_server *adsl_lb_rec_server_w3;  /* structure received */
       struct dsd_chineta *adsl_chineta_save_1;  /* saved INETA        */
       struct dsd_lbal_conn_server dsl_lbcs_1;  /* fields for connect to server */
       struct dsd_lbal_conn_server dsl_lbcs_2;  /* fields for connect to server */
#ifndef OLD_1112
       char   chrl_ineta_port[ 2 + 16 + 2 ];  /* area for INETA and port */
       struct sockaddr_storage dsl_soa_l;   /* sockaddr for connect    */
#endif

#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv l%05d soa=%p received=%p len=%d timer=%d.",
                       __LINE__, adsp_soa, achp_received, imp_len_received, bop_timed_out );
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv called / imc_function=%d / imp_len_received=%d.", imc_function, imp_len_received );
#endif
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 10 );
#endif
#ifndef B110523
       dsl_lbcs_2.boc_other_server = FALSE;  /* not connected to other servers */
#endif
       if (imp_len_received == 0) goto psere_tim00;  /* check timeout  */

//     psere_sca00:                         /* scan record from server */
       adsl_lb_rec_server_w1 = NULL;        /* structure received      */
       if (imp_len_received <= sizeof(chrs_rece1)) goto psere_err00;
       if (memcmp( achp_received, chrs_rece1, sizeof(chrs_rece1) )) {
         goto psere_err00;
       }
       achl_w1 = achp_received + sizeof(chrs_rece1);  /* start here    */
       achl_w2 = achp_received + imp_len_received;  /* end of data received */
#ifdef XYZ1
       uml_ineta = ump_ineta;               /* get INETA received      */
#endif
#ifdef OLD_1112
       if (imc_function > 0) goto psere_sto00;  /* store internally   */
       if (boc_reconnect) goto psere_sto00;  /* do reconnect           */
#endif
#ifdef OLD_1112
       bol_ineta = FALSE;                   /* reset INETA received    */
       chrl_work1[0] = 8;                   /* length structure        */
       chrl_work1[1] = 0X12;                /* set tag                 */
#ifdef INETA_LOAD_BYTE
#ifndef __LITTLE_ENDIAN
       *((unsigned char *) &chrl_work1[2])
         = (unsigned char) (ump_ineta >> 24);  /* first part IP addr   */
       *((unsigned char *) &chrl_work1[3])
         = (unsigned char) (ump_ineta >> 16);  /* second part IP addr  */
       *((unsigned char *) &chrl_work1[4])
         = (unsigned char) (ump_ineta >> 8);  /* third part IP addr    */
       *((unsigned char *) &chrl_work1[5])
         = (unsigned char) ump_ineta;       /* fourth part IP addr     */
#else
       *((unsigned char *) &chrl_work1[2])
         = (unsigned char) ump_ineta;       /* first part IP addr      */
       *((unsigned char *) &chrl_work1[3])
         = (unsigned char) (ump_ineta >> 8);  /* second part IP addr   */
       *((unsigned char *) &chrl_work1[4])
         = (unsigned char) (ump_ineta >> 16);  /* third part IP addr   */
       *((unsigned char *) &chrl_work1[5])
         = (unsigned char) (ump_ineta >> 24);  /* fourth part IP addr  */
#endif
#else
       *((UNSIG_MED *) &chrl_work1[2]) = ump_ineta;
#endif
#endif
       iml_ineta_len = 0;                   /* reset INETA received    */
       chrl_ineta_port[1] = 0X12;           /* set tag                 */
       if (adsp_soa->sa_family == AF_INET) {  /* IPV4                  */
         chrl_ineta_port[0] = 2 + 4 + 2;    /* length structure        */
         memcpy( &chrl_ineta_port[2], &((struct sockaddr_in *) adsp_soa)->sin_addr, 4 );
       } else {                             /* IPV6                    */
         chrl_ineta_port[0] = 2 + 16 + 2;   /* length structure        */
         memcpy( &chrl_ineta_port[2], &((struct sockaddr_in6 *) adsp_soa)->sin6_addr, 16 );
       }
#ifndef OLD_1112
       if (imc_function > 0) goto psere_sto00;  /* store internally   */
       if (boc_reconnect) goto psere_sto00;  /* do reconnect           */
#endif
       achl_send1 = NULL;                   /* not yet send buffer     */

       psere_sca20:                         /* find length             */
       iml1 = 0;                            /* set length              */
       achl_w3 = achl_w4 = achl_w1;         /* save beginning          */
       while ((achl_w1 < achl_w2) && ((*achl_w1 & 0X80) != 0)) {
         iml1 <<= 7;
         iml1 |= *achl_w1 & 0X7F;
         achl_w1++;
       }
       if (achl_w1 >= achl_w2) goto psere_err00;
       iml1 <<= 7;
       iml1 |= *achl_w1 & 0X7F;
       achl_w1++;
       if (iml1 < 2) goto psere_err00;
       achl_w3 += iml1;                     /* end of this structure   */
       if (achl_w3 > achl_w2) goto psere_err00;
       bol1 = FALSE;
       if ((unsigned char) *achl_w1 <= 0X0F) bol1 = TRUE;
       if (   ((unsigned char) *achl_w1 >= 0X30)
           && ((unsigned char) *achl_w1 <= 0X3F)) {
         bol1 = TRUE;                       /* copy fields             */
       }
       if ((unsigned char) *achl_w1 == 0X10) {  /* port received       */
         if ((achl_w3 - achl_w1) != 3) goto psere_err00;
         if (iml_ineta_len) goto psere_err00;  /* check INETA received */
         iml_ineta_len = 4;                 /* set INETA received      */
         achl_w5 = &chrl_ineta_port[ 2 + 4 ];  /* position port IPV4   */
         if (chrl_ineta_port[0] != (2 + 4 + 2)) {  /* is not IPV4      */
           iml_ineta_len = 16;              /* set INETA received      */
           achl_w5 = &chrl_ineta_port[ 2 + 16 ];  /* position port IPV6 */
         }
         memcpy( achl_w5, achl_w1 + 1, 2 );  /* copy port              */
       } else if ((unsigned char) *achl_w1 == 0X12) {  /* INETA and port received */
         if (iml_ineta_len) goto psere_err00;  /* check INETA received */
         iml_ineta_len = (achl_w3 - achl_w1) - 1 - 2;  /* get length of INETA */
         if (   (iml_ineta_len != 4)        /* not IPV4                */
             && (iml_ineta_len != 16)) {    /* not IPV6                */
           goto psere_err00;
         }
         chrl_ineta_port[0] = (unsigned char) (2 + iml_ineta_len + 2);  /* set length */
         memcpy( &chrl_ineta_port[2], achl_w1 + 1, iml_ineta_len + 2 );  /* copy INETA and port */
       }
       if (bol1) {                          /* structure to copy       */
         if (achl_send1 == NULL) {          /* beginning of data       */
           achl_send1 = achp_workarea_start + 2;  /* after record length */
           memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
           achl_send1 += sizeof(chrs_rece1);
         }
         memcpy( achl_send1, achl_w4, iml1 );  /* copy structure       */
         achl_send1 += iml1;                /* increment length data   */
       }
       achl_w1 = achl_w3;                   /* start of next structure */
       if (achl_w1 < achl_w2) goto psere_sca20;  /* get next structure */
       if (this->boc_is_blade_server) {     /* function BLADEGATE / VDI */
// to-do 05.01.12 KB
#ifdef XYZ1
#ifndef INETA_LOAD_BYTE
         uml_ineta = *((UNSIG_MED *) (chrl_work1 + 2));
#else
#ifndef __LITTLE_ENDIAN
         iu2 = 4;
         uml_ineta = 0;
         do {
           iu2--;
           uml_ineta <<= 8;
           uml_ineta |= (unsigned char) *(chrl_work1 + 2 + 3 - iu2);
         } while (iu2 > 0);
#else
         iu2 = 4;
         uml_ineta = 0;
         do {
           iu2--;
           uml_ineta <<= 8;
           uml_ineta |= (unsigned char) *(chrl_work1 + 2 + iu2);
         } while (iu2 > 0);
#endif
#endif
         bol1 = dcl_blasetr_1::m_check_ineta( uml_ineta, dcl_blasetr_1::en_ca_check );
         if (bol1 == FALSE) {               /* server is not valid     */
           goto psere_tim00;                /* remove this server      */
         }
#endif
       }
       if (iml_ineta_len) {                 /* check INETA received    */
         /* check if this INETA already saved                          */
         bol1 = TRUE;                       /* do save this INETA      */
         adsl_chineta_save_1 = adsc_chineta_save;  /* get saved INETA  */
         while (adsl_chineta_save_1) {
           iml1 = 0;                        /* beginning of buffer     */
           while (iml1 < adsl_chineta_save_1->imc_filled) {
             iml2 = iml1;                   /* save this entry         */
             iml1 += 1 + (unsigned char) adsl_chineta_save_1->chrc_ineta_str[ iml2 ];
             if (iml1 > adsl_chineta_save_1->imc_filled) {  /* invalid length */
               goto psere_err00;
             }
             if (   (adsl_chineta_save_1->chrc_ineta_str[ iml2 ] == (iml_ineta_len + 2))
                 && (!memcmp( &adsl_chineta_save_1->chrc_ineta_str[ iml2 + 1 ],
                              &chrl_ineta_port[2],
                              iml_ineta_len + 2 ))) {
               bol1 = FALSE;                /* this INETA already saved */
               break;
             }
           }
           adsl_chineta_save_1 = adsl_chineta_save_1->adsc_next;
         }
         /* save this INETA                                            */
         if (bol1) {
           adsl_chineta_save_1 = adsc_chineta_save;  /* get saved INETA */
           if (   (adsl_chineta_save_1 == NULL)
               || ((adsl_chineta_save_1->imc_filled + 1 + iml_ineta_len + 2)
                     > sizeof(adsl_chineta_save_1->chrc_ineta_str))) {
             adsl_chineta_save_1 = (struct dsd_chineta *) malloc( sizeof(struct dsd_chineta) );
             adsl_chineta_save_1->imc_filled = 0;
             adsl_chineta_save_1->adsc_next = adsc_chineta_save;
             adsc_chineta_save = adsl_chineta_save_1;
           }
           adsl_chineta_save_1->chrc_ineta_str[ adsl_chineta_save_1->imc_filled++ ] = iml_ineta_len + 2;
           memcpy( &adsl_chineta_save_1->chrc_ineta_str[ adsl_chineta_save_1->imc_filled ],
                   &chrl_ineta_port[2],
                   iml_ineta_len + 2 );
           adsl_chineta_save_1->imc_filled += iml_ineta_len + 2;
         }
         if (achl_send1 == NULL) {          /* beginning of data       */
           achl_send1 = achp_workarea_start + 2;  /* after record length */
           memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
           achl_send1 += sizeof(chrs_rece1);
         }
         memcpy( achl_send1, chrl_ineta_port, 2 + iml_ineta_len + 2 );  /* copy structure INETA */
         achl_send1 += 2 + iml_ineta_len + 2;  /* increment length data */
       }
       if (achl_send1) {                    /* something to send       */
         achl_w1 = achp_workarea_start + 1;  /* record begins here     */
         iml1 = achl_send1 - achl_w1;       /* compute length          */
         if (iml1 >= 0X80) {
           achl_w1 = achp_workarea_start;   /* record begins here      */
           iml1++;                          /* increment length        */
           *achl_w1 = (iml1 >> 7) | 0X80;   /* set first byte length   */
         }
         *(achp_workarea_start + 1) = iml1 & 0X7F;  /* set length      */
         *aachp_ret_msg = achl_w1;          /* set area to send        */
         *aimp_ret_msg_len = iml1;          /* set length to send      */
       }
       goto psere_tim00;                    /* check timeout           */

       psere_sto00:                         /* store internally        */
       iml_load_w1 = -1;
#ifdef XYZ1
       iuport = -1;
#endif
#ifdef OLD_1112
#ifndef OLD_1112
       iml_ineta_len = 0;                   /* reset INETA received    */
#endif
#endif
       iml_disconnect = 0;                  /* count disconnected sess */
       iml_len_packet = achl_w2 - achl_w1;  /* save length packet      */

       psere_sto20:                         /* find length             */
       iml1 = 0;                            /* set length              */
       achl_start_field = achl_w3 = achl_w1;  /* save start of field   */
       while ((achl_w1 < achl_w2) && ((*achl_w1 & 0X80) != 0)) {
         iml1 <<= 7;
         iml1 |= *achl_w1 & 0X7F;
         achl_w1++;
       }
       if (achl_w1 >= achl_w2) goto psere_err00;
       iml1 <<= 7;
       iml1 |= *achl_w1 & 0X7F;
       achl_w1++;
       if (iml1 < 2) goto psere_err00;
       achl_w3 += iml1;                     /* end of this structure   */
       if (achl_w3 > achl_w2) goto psere_err00;
       switch ((unsigned char) *achl_w1) {
         case 0X00:                         /* load                    */
           if ((achl_w3 - achl_w1) != 3) goto psere_err00;
           if (iml_load_w1 >= 0) goto psere_err00;
           iml_load_w1 = ((unsigned char) *(achl_w1 + 1) << 8)
                    | ((unsigned char) *(achl_w1 + 2));
           break;
         case 0X08:                         /* desktop disc / conn / o */
           if ((achl_w3 - achl_w1) < 3) goto psere_err00;
           if (this->boc_s_appl) break;     /* search application      */
           if (iml_disconnect > 0) goto psere_err00;
           iml_disconnect = ((unsigned char) *(achl_w1 + 1) << 8)
                          | ((unsigned char) *(achl_w1 + 2));
           break;
         case 0X10:                         /* RDP port                */
           if ((achl_w3 - achl_w1) != 3) goto psere_err00;
           if (iml_ineta_len) goto psere_err00;  /* check INETA received */
           iml_ineta_len = 4;               /* set INETA received      */
           achl_w5 = &chrl_ineta_port[ 2 + 4 ];  /* position port IPV4 */
           if (chrl_ineta_port[0] != (2 + 4 + 2)) {  /* is not IPV4    */
             iml_ineta_len = 16;            /* set INETA received      */
             achl_w5 = &chrl_ineta_port[ 2 + 16 ];  /* position port IPV6 */
           }
           memcpy( achl_w5, achl_w1 + 1, 2 );  /* copy port            */
           break;
         case 0X12:                         /* RDP INETA and port      */
           if (iml_ineta_len) goto psere_err00;  /* check INETA received */
           iml_ineta_len = (achl_w3 - achl_w1) - 1 - 2;  /* get length of INETA */
           if (   (iml_ineta_len != 4)      /* not IPV4                */
               && (iml_ineta_len != 16)) {  /* not IPV6                */
             goto psere_err00;
           }
           chrl_ineta_port[0] = (unsigned char) (2 + iml_ineta_len + 2);  /* set length */
           memcpy( &chrl_ineta_port[2], achl_w1 + 1, iml_ineta_len + 2 );  /* copy INETA and port */
           break;
         case 0X30:                         /* appl-definition         */
           if ((achl_w3 - achl_w1) <= 3) goto psere_err00;
           if (   (adsl_lb_rec_server_w1)
               && (adsl_lb_rec_server_w1->boc_appl)) {
             goto psere_err00;              /* structure received      */
           }
           if (boc_s_appl == FALSE) goto psere_err00;  /* search appl  */
           if (adsl_lb_rec_server_w1 == NULL) {  /* no memory yet      */
             adsl_lb_rec_server_w1
               = (struct dsd_lb_rec_server *) malloc( sizeof(struct dsd_lb_rec_server)
                                                  + iml_len_packet );
             adsl_lb_rec_server_w1->imc_len_fields = 0;  /* clear length of fields */
           }
           adsl_lb_rec_server_w1->imc_disconnect = 0;
           memcpy( (char *) (adsl_lb_rec_server_w1 + 1) + adsl_lb_rec_server_w1->imc_len_fields,
                   achl_start_field, achl_w3 - achl_start_field );
           adsl_lb_rec_server_w1->imc_len_fields += achl_w3 - achl_start_field;
           adsl_lb_rec_server_w1->boc_appl = TRUE;  /* appl received   */
           achl_w1++;                       /* start here              */
           do {                             /* search disconnected     */
             achl_w4 = achl_w1;             /* save beginning          */
             iml1 = 0;                      /* set length              */
             while ((achl_w1 < achl_w3) && ((*achl_w1 & 0X80) != 0)) {
               iml1 <<= 7;
               iml1 |= *achl_w1 & 0X7F;
               achl_w1++;
             }
             if (achl_w1 >= achl_w3) goto psere_err00;
             iml1 <<= 7;
             iml1 |= *achl_w1 & 0X7F;
             achl_w1++;
#ifdef TRACEHLS
             m_hlnew_printf( HLOG_TRACE1, "+++ found appl TAG %02X.", (unsigned char) *achl_w1 );
#endif
             if ((unsigned char) *achl_w1 == 0X08) {
               if ((achl_w4 + iml1 - achl_w1) < 3) goto psere_err00;
               if (adsl_lb_rec_server_w1->imc_disconnect > 0) goto psere_err00;
               adsl_lb_rec_server_w1->imc_disconnect
                 = ((unsigned char) *(achl_w1 + 1) << 8)
                   | ((unsigned char) *(achl_w1 + 2));
#ifdef TRACEHLS
               m_hlnew_printf( HLOG_TRACE1, "+++ received disc-0X08 adsl_lb_rec_server:%p from %d.%d.%d.%d load:%d port:%d disconnect:%d.",
                       adsl_lb_rec_server_w1,
                       ump_ineta & 0XFF,
                       (ump_ineta >> 8) & 0XFF,
                       (ump_ineta >> 16) & 0XFF,
                       (ump_ineta >> 24) & 0XFF,
                       iml_load_w1, iuport, adsl_lb_rec_server_w1->imc_disconnect );
#endif
             }
             achl_w1 = achl_w4 + iml1;      /* set end of structure    */
           } while (achl_w1 < achl_w3);
           break;
         default:
           iml2 = (unsigned char) *achl_w1 & 0XF0;  /* get 4 bits      */
           if ((iml2 != 0) && (iml2 != 0X30)) break;
           /* copy this field to output                                */
           if (adsl_lb_rec_server_w1 == NULL) {  /* no memory yet      */
             adsl_lb_rec_server_w1
               = (struct dsd_lb_rec_server *) malloc( sizeof(struct dsd_lb_rec_server)
                                                        + iml_len_packet );
             adsl_lb_rec_server_w1->imc_len_fields = 0;  /* clear length of fields */
             adsl_lb_rec_server_w1->imc_disconnect = 0;
             adsl_lb_rec_server_w1->boc_appl = FALSE;  /* no appl received yet */
           }
           memcpy( (char *) (adsl_lb_rec_server_w1 + 1) + adsl_lb_rec_server_w1->imc_len_fields,
                   achl_start_field, achl_w3 - achl_start_field );
           adsl_lb_rec_server_w1->imc_len_fields += achl_w3 - achl_start_field;
           break;
       }
       achl_w1 = achl_w3;                   /* start of next structure */
       if (achl_w1 < achl_w2) goto psere_sto20;  /* get next structure */
       if (iml_ineta_len == 0) {            /* check INETA received    */
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_proc_se_recv no port received" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d no port received", __LINE__ );
#endif
         goto psere_err00;
       }
#ifdef OLD_1112
       if (boc_reconnect) {                 /* do reconnect            */
#ifndef INETA_LOAD_BYTE
         uml_cmp_i = *((UNSIG_MED *) chrc_ineta_port);
#else
#ifndef __LITTLE_ENDIAN
         iu2 = 4;
         uml_cmp_i = 0;
         do {
           iu2--;
           uml_cmp_i <<= 8;
           uml_cmp_i |= (unsigned char) *(chrc_ineta_port + 3 - iu2);
         } while (iu2 > 0);
#else
         iu2 = 4;
         uml_cmp_i = 0;
         do {
           iu2--;
           uml_cmp_i <<= 8;
           uml_cmp_i |= (unsigned char) *(chrc_ineta_port + iu2);
         } while (iu2 > 0);
#endif
#endif
         if (uml_cmp_i != uml_ineta) {      /* different from INETA searched for */
           goto psere_tim00;                /* check only timeout      */
         }
         iu2 = ((unsigned char) *(chrc_ineta_port + 4) << 8)
               | ((unsigned char) *(chrc_ineta_port + 4 + 1));
         if (iu2 != iuport) {               /* different from port searched for */
           goto psere_tim00;                /* check only timeout      */
         }
         /* we do connect right now                                    */
         boc_other_server = FALSE;          /* already connected to other servers */
#ifdef B100617
         m_check_other_server( &dsl_lbcs_2, adsl_lb_rec_server_w2 );  /* already connected to other servers */
#else
         m_check_other_server( &dsl_lbcs_2, adsl_lb_rec_server_w1 );  /* already connected to other servers */
// 18.06.10 KB - only temporary solution
         memcpy( &dsl_lbcs_2.chrc_ineta_port, this->chrc_ineta_port, sizeof(this->chrc_ineta_port) );
#endif
         goto psere_start;                  /* server found            */
       }
#endif
#ifndef B120816
       if (this->boc_reconnect) {           /* do reconnect            */
         if ((2 + iml_ineta_len + 2) != (unsigned char) this->chrc_ineta_port[ 0 ]) {  /* compare length */
           goto psere_tim00;                /* check only timeout      */
         }
         if (memcmp( chrl_ineta_port + 2, this->chrc_ineta_port + 2, iml_ineta_len + 2 )) {
           goto psere_tim00;                /* check only timeout      */
         }
         /* we do connect right now                                    */
         this->boc_other_server = FALSE;    /* already connected to other servers */
#ifdef B100617
         m_check_other_server( &dsl_lbcs_2, adsl_lb_rec_server_w2 );  /* already connected to other servers */
#else
         m_check_other_server( &dsl_lbcs_2, adsl_lb_rec_server_w1 );  /* already connected to other servers */
// 18.06.10 KB - only temporary solution
         memcpy( &dsl_lbcs_2.chrc_ineta_port, this->chrc_ineta_port, sizeof(this->chrc_ineta_port) );
#endif
         goto psere_start;                  /* server found            */
       }
#endif
       if (iml_load_w1 < 0) {               /* error no load received  */
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_proc_se_recv no load received" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d no load received", __LINE__ );
#endif
         goto psere_err00;
       }
       if (adsl_lb_rec_server_w1 == NULL) {  /* structure received     */
         if (boc_s_appl) goto psere_err00;  /* search application      */
         adsl_lb_rec_server_w1 = (struct dsd_lb_rec_server *) malloc( sizeof(struct dsd_lb_rec_server) );
         adsl_lb_rec_server_w1->imc_len_fields = 0;  /* clear length of fields */
         adsl_lb_rec_server_w1->boc_appl = FALSE;  /* no appl received yet  */
       }
       if (adsl_lb_rec_server_w1->boc_appl == FALSE) {  /* no appl received */
         adsl_lb_rec_server_w1->imc_disconnect = iml_disconnect;
       }
#ifdef OLD_1112
       adsl_lb_rec_server_w1->ulineta = uml_ineta;
       adsl_lb_rec_server_w1->imc_port = iuport;
#endif
#ifndef OLD_1112
#ifdef XYZ1
       adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] = (unsigned char) (2 + iml_ineta_len + 2);
       adsl_lb_rec_server_w1->chrc_ineta_port[ 1 ] = 0X12;
       if (iml_ineta_len == 4) {            /* IPV4                    */
         memcpy( &adsl_lb_rec_server_w1->chrc_ineta_port[ 2 ],
                 &((struct sockaddr_in *) &dsl_soa_l)->sin_addr,
                 4 );
         memcpy( &adsl_lb_rec_server_w1->chrc_ineta_port[ 2 + 4 ],
                 &((struct sockaddr_in *) &dsl_soa_l)->sin_port,
                 2 );
       } else {                             /* IPV6                    */
         memcpy( &adsl_lb_rec_server_w1->chrc_ineta_port[ 2 ],
                 &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr,
                 16 );
         memcpy( &adsl_lb_rec_server_w1->chrc_ineta_port[ 2 + 16 ],
                 &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_port,
                 2 );
       }
#endif
       memcpy( adsl_lb_rec_server_w1->chrc_ineta_port, chrl_ineta_port, 2 + iml_ineta_len + 2 );
#endif
       adsl_lb_rec_server_w1->imc_load = iml_load_w1;
       adsl_lb_rec_server_w1->adsc_next = adsc_lb_rec_server;  /* get old chain */
       adsc_lb_rec_server = adsl_lb_rec_server_w1;  /* set new chain   */
#ifdef TRACEHLS
       m_hlnew_printf( HLOG_TRACE1, "+++ received adsl_lb_rec_server:%p from %d.%d.%d.%d load:%d port:%d disconnect:%d.",
               adsl_lb_rec_server_w1,
               uml_ineta & 0XFF,
               (uml_ineta >> 8) & 0XFF,
               (uml_ineta >> 16) & 0XFF,
               (uml_ineta >> 24) & 0XFF,
               iml_load_w1, iuport, adsl_lb_rec_server_w1->imc_disconnect );
#endif
       if (ienum_to == en_to_bstrtime) {    /* wait for other cluster member  */
         goto psere_tim00;                  /* check only timeout      */
       }
       if (iml_ineta_len) {                 /* check INETA received    */
         if (imc_function == 1) goto psere_cho00;  /* take first one   */
         if (ienum_to == en_to_time2) {     /* wait for any            */
           goto psere_cho00;                /* choose server           */
          }
       }
       if (this->imc_arraylen_check == 0) {  /* length of array        */
         goto psere_tim00;                  /* check timeout           */
       }
#ifdef OLD_1112
       iu1 = 0;
       do {
         if ((ad_che_server + iu1)->ulineta == uml_ineta) {
           (ad_che_server + iu1)->bo_received_LB = TRUE;
         } else if ((ad_che_server + iu1)->bo_received_LB == FALSE) {
           goto psere_tim00;                /* check timeout           */
         }
         iu1++;                             /* check next server       */
       } while (iu1 < imc_arraylen_check);
#endif
#ifndef OLD_1112
       iml2 = adsp_soa->sa_family;          /* get family              */
       if (iml2 == AF_INET) {               /* IPV4                    */
         iml3 = offsetof( struct sockaddr_in, sin_addr );
         iml4 = 4;                          /* length of INETA         */
         iml5 = offsetof( struct sockaddr_in, sin_port );
       } else {                             /* IPV6                    */
         iml3 = offsetof( struct sockaddr_in6, sin6_addr );
         iml4 = 16;                         /* length of INETA         */
         iml5 = offsetof( struct sockaddr_in6, sin6_port );
       }
       iml1 = 0;
       bol1 = FALSE;                        /* no server found which did not respond */
       do {
         if (   ((adsrc_check_server + iml1)->adsc_wtsg_1->dsc_soa.ss_family == iml2)
             && !memcmp( (char *) &(adsrc_check_server + iml1)->adsc_wtsg_1->dsc_soa + iml3,
                         (char *) adsp_soa + iml3,
                         iml4 )
             && !memcmp( (char *) &(adsrc_check_server + iml1)->adsc_wtsg_1->dsc_soa + iml5,
                         (char *) adsp_soa + iml5,
                         2 )) {
           (adsrc_check_server + iml1)->boc_received_lb = TRUE;
           if (bol1) {                      /* server found which did not respond */
             goto psere_tim00;              /* check timeout           */
           }
         } else if ((adsrc_check_server + iml1)->boc_received_lb == FALSE) {
           bol1 = TRUE;                     /* server found which did not respond */
         }
         iml1++;                            /* check next server       */
       } while (iml1 < this->imc_arraylen_check);
       if (bol1) {                          /* server found which did not respond */
         goto psere_tim00;                  /* check timeout           */
       }
#endif
       /* all servers have responded                                   */
       goto psere_cho00;                    /* choose server           */

       psere_err00:                         /* invalid data received   */
#ifdef B090417
       m_display( "dsd_lbal_gw_1::m_proc_se_recv psere_err00" );
#else
       m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d psere_err00 invalid data received", __LINE__ );
#endif
       if (adsl_lb_rec_server_w1) free( adsl_lb_rec_server_w1 );  /* structure received */
#ifdef NOT_NEEDED_120106
       HLGW_set_abend( aclparam );          /* set abend               */
       return;
#endif

       psere_tim00:                         /* check timeout           */
       if (bop_timed_out == FALSE) return;
       if (ienum_to == en_to_time2) {       /* wait for any            */
         goto psere_tim20;
       }
       if (ienum_to == en_to_bstrtime) {    /* wait for other cluster member */
         goto psere_vdi80;
       }
       if (adsc_lb_rec_server) {            /* server found            */
         goto psere_cho00;                  /* choose server           */
       }
       ienum_to = en_to_time2;              /* status timeout          */
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 6 );
#endif
       HLGW_set_timer( aclparam, imc_time2 );  /* time wait any       */
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 14 );
#endif
       return;

       psere_tim20:                         /* nobody connected        */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv called / timed out" );
#endif
       achl_send1 = achp_workarea_start + 2;  /* after record length   */
       memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
       achl_send1 += sizeof(chrs_rece1);
       *(achl_send1 + 0) = 4;               /* length structure        */
       *(achl_send1 + 1) = 0X4A;            /* error record            */
       *((unsigned char *) (achl_send1 + 2)) = 0;
       *((unsigned char *) (achl_send1 + 3)) = 1;
       achl_send1 += 4;                     /* set end record          */
       achl_w1 = achp_workarea_start + 1;   /* record begins here      */
       iml1 = achl_send1 - achl_w1;         /* compute length          */
       if (iml1 >= 0X80) {
         achl_w1 = achp_workarea_start;     /* record begins here      */
         iml1++;                            /* increment length        */
         *achl_w1 = (iml1 >> 7) | 0X80;     /* set first byte length   */
       }
       *(achp_workarea_start + 1) = iml1 & 0X7F;  /* set length        */
       *aachp_ret_msg = achl_w1;            /* set area to send        */
       *aimp_ret_msg_len = iml1;            /* set length to send      */
       HLGW_set_abend( aclparam );          /* set abend               */
       return;

       psere_cho00:                         /* search which server     */
#ifdef OLD01
       /* inserted 31.03.05 KB                                         */
       if (imc_function <= 0) return;
#endif
#ifdef B110523
#ifndef B100507
       dsl_lbcs_2.boc_other_server = FALSE;  /* not connected to other servers */
#endif
#endif
       if (boc_is_blade_server) {           /* function BLADEGATE / VDI */
         goto psere_vdi00;                  /* search blade server     */
       }
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       adsl_lb_rec_server_w2 = NULL;        /* no server found         */
       if (   (adsl_lb_rec_server_w1)
           && (adsl_lb_rec_server_w1->adsc_next == NULL)) {  /* only one server */
         adsl_lb_rec_server_w2 = adsl_lb_rec_server_w1;  /* set server found */
         m_check_other_server( &dsl_lbcs_2, adsl_lb_rec_server_w2 );  /* already connected to other servers */
         goto psere_start;                  /* server found            */
       }
       bol_load_set = FALSE;                /* load not yet set        */
       if (imc_function != 3) goto psere_cho20;  /* not disconnected   */
       /* check if disconnected sessions                               */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
#ifdef OLD_1112
         if (   (adsl_lb_rec_server_w1->imc_disconnect)
             && (adsl_lb_rec_server_w1->imc_port >= 0)) {
           m_check_other_server( &dsl_lbcs_1, adsl_lb_rec_server_w1 );  /* already connected to other servers */
           iml_load_w2 = adsl_lb_rec_server_w1->imc_load;
           if (dsl_lbcs_1.boc_other_server) {
             iml_load_w2 -= imc_nosharedeviation;  /* percentage configured */
           }
           if (   (bol_load_set == FALSE)
               || (iml_load_w2 <= iml_load_w1)) {
             iml_load_w1 = iml_load_w2;
             adsl_lb_rec_server_w2 = adsl_lb_rec_server_w1;  /* set server found */
             memcpy( &dsl_lbcs_2, &dsl_lbcs_1, sizeof(struct dsd_lbal_conn_server) );
             bol_load_set = TRUE;           /* load has been set       */
           }
         }
#endif
#ifndef OLD_1112
         if (   (adsl_lb_rec_server_w1->imc_disconnect)  /* disconnected */
             && (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0)) {  /* entry is valid */
           m_check_other_server( &dsl_lbcs_1, adsl_lb_rec_server_w1 );  /* already connected to other servers */
           iml_load_w2 = adsl_lb_rec_server_w1->imc_load;
           if (dsl_lbcs_1.boc_other_server) {
             iml_load_w2 -= imc_nosharedeviation;  /* percentage configured */
           }
           if (   (bol_load_set == FALSE)
               || (iml_load_w2 <= iml_load_w1)) {
             iml_load_w1 = iml_load_w2;
             adsl_lb_rec_server_w2 = adsl_lb_rec_server_w1;  /* set server found */
             memcpy( &dsl_lbcs_2, &dsl_lbcs_1, sizeof(struct dsd_lbal_conn_server) );
             bol_load_set = TRUE;           /* load has been set       */
           }
         }
#endif
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       if (adsl_lb_rec_server_w2) goto psere_start;  /* server found   */
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */

       psere_cho20:                         /* search which server     */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
#ifdef TRACEHLS
         m_hlnew_printf( HLOG_TRACE1, "+++ while adsl_lb_rec_server:%p load:%d port:%d.",
                         adsl_lb_rec_server_w1, adsl_lb_rec_server_w1->imc_load, adsl_lb_rec_server_w1->imc_port );
#endif
#ifdef OLD_1112
         if (adsl_lb_rec_server_w1->imc_port >= 0)
#endif
         if (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0) {  /* entry is valid */
           m_check_other_server( &dsl_lbcs_1, adsl_lb_rec_server_w1 );  /* already connected to other servers */
           iml_load_w2 = adsl_lb_rec_server_w1->imc_load;
           if (dsl_lbcs_1.boc_other_server) {
             iml_load_w2 -= imc_nosharedeviation;  /* percentage configured */
           }
           if (   (bol_load_set == FALSE)
               || (iml_load_w2 <= iml_load_w1)) {
             iml_load_w1 = iml_load_w2;
             adsl_lb_rec_server_w2 = adsl_lb_rec_server_w1;  /* set server found */
             memcpy( &dsl_lbcs_2, &dsl_lbcs_1, sizeof(struct dsd_lbal_conn_server) );
             bol_load_set = TRUE;           /* load has been set       */
#ifdef TRACEHLS
             m_hlnew_printf( HLOG_TRACE1, "+++ choose adsl_lb_rec_server:%p load:%d.",
                             adsl_lb_rec_server_w2, iml_load_w1 );
#endif
           }
         }
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
#ifdef OLD_1112
       if (adsl_lb_rec_server_w2 == NULL) return;
       goto psere_start;                    /* server found            */
#endif
#ifndef OLD_1112
       if (adsl_lb_rec_server_w2) goto psere_start;  /* server found   */
       goto psere_tim00;                    /* check timeout           */
#endif

       psere_vdi00:                         /* search which VDI server */
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       adsl_lb_rec_server_w2 = NULL;        /* no server found         */
       if (   (adsl_lb_rec_server_w1)
           && (adsl_lb_rec_server_w1->adsc_next == NULL)) {  /* only one server */
         adsl_lb_rec_server_w2 = adsl_lb_rec_server_w1;  /* set server found */
         goto psere_vdi40;                  /* check if this valid     */
       }
       iml_load_w1 = -1;
       if (imc_function != 3) goto psere_vdi20;  /* not disconnected   */
       /* check if disconnected sessions                               */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
         if (   (adsl_lb_rec_server_w1->imc_disconnect)
//           && (adsl_lb_rec_server_w1->imc_port >= 0)
             && (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (   (iml_load_w1 < 0)
                 || (adsl_lb_rec_server_w1->imc_load <= iml_load_w1))) {
           iml_load_w1 = adsl_lb_rec_server_w1->imc_load;
         }
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       if (iml_load_w1 < 0) {               /* no server found         */
         goto psere_vdi20;                  /* search which server     */
       }
       iml1 = 0;                            /* count the server        */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
         if (   (adsl_lb_rec_server_w1->imc_disconnect)
//           && (adsl_lb_rec_server_w1->imc_port >= 0)
             && (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (adsl_lb_rec_server_w1->imc_load == iml_load_w1)) {
           iml1++;                          /* count this entry        */
         }
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       iml2 = 0;                            /* search first one        */
       if (iml1 > 1) {                      /* get random number       */
         iml2 = m_get_random_number( iml1 );
       }
       iml1 = 0;                            /* count the server        */
       adsl_lb_rec_server_w2 = adsc_lb_rec_server;  /* get chain       */
       while (adsl_lb_rec_server_w2) {      /* loop over all received  */
         if (   (adsl_lb_rec_server_w2->imc_disconnect)
//           && (adsl_lb_rec_server_w2->imc_port >= 0)
             && (adsl_lb_rec_server_w2->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (adsl_lb_rec_server_w2->imc_load == iml_load_w1)) {
           if (iml1 == iml2) break;
           iml1++;                          /* count this entry        */
         }
         adsl_lb_rec_server_w2 = adsl_lb_rec_server_w2->adsc_next;
       }
       if (adsl_lb_rec_server_w2 == NULL) {
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_proc_se_recv psere_vdi00 server not found" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d psere_vdi00 server not found", __LINE__ );
#endif
         goto psere_tim20;                  /* report no server found  */
       }
       goto psere_vdi40;                    /* check if server valid   */

       psere_vdi20:                         /* search which server     */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
#ifdef TRACEHLS
         m_hlnew_printf( HLOG_TRACE1, "+++ while adsl_lb_rec_server:%p load:%d port:%d.",
                         adsl_lb_rec_server_w1, adsl_lb_rec_server_w1->imc_load, adsl_lb_rec_server_w1->imc_port );
#endif
//       if (   (adsl_lb_rec_server_w1->imc_port >= 0))
         if (   (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (   (iml_load_w1 < 0)
                 || (adsl_lb_rec_server_w1->imc_load <= iml_load_w1))) {
           iml_load_w1 = adsl_lb_rec_server_w1->imc_load;
         }
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       if (iml_load_w1 < 0) return;
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       iml1 = 0;                            /* count the server        */
       while (adsl_lb_rec_server_w1) {      /* loop over all received  */
         if (   (adsl_lb_rec_server_w1->imc_disconnect)
//           && (adsl_lb_rec_server_w1->imc_port >= 0)
             && (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (adsl_lb_rec_server_w1->imc_load == iml_load_w1)) {
           iml1++;                          /* count this entry        */
         }
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       iml2 = 0;                            /* search first one        */
       if (iml1 > 1) {                      /* get random number       */
         iml2 = m_get_random_number( iml1 );
       }
       iml1 = 0;                            /* count the server        */
       adsl_lb_rec_server_w2 = adsc_lb_rec_server;  /* get chain       */
       while (adsl_lb_rec_server_w2) {      /* loop over all received  */
//       if (   (adsl_lb_rec_server_w2->imc_port >= 0))
         if (   (adsl_lb_rec_server_w2->chrc_ineta_port[ 0 ] != 0)  /* entry is valid */
             && (adsl_lb_rec_server_w2->imc_load == iml_load_w1)) {
           if (iml1 == iml2) break;
           iml1++;                          /* count this entry        */
         }
         adsl_lb_rec_server_w2 = adsl_lb_rec_server_w2->adsc_next;
       }
       if (adsl_lb_rec_server_w2 == NULL) {
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_proc_se_recv psere_vdi20 server not found" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d psere_vdi20 server not found", __LINE__ );
#endif
         goto psere_tim20;                  /* report no server found  */
       }

       psere_vdi40:                         /* check if server valid   */
       bol1 = dcl_blasetr_1::m_check_ineta( adsl_lb_rec_server_w2->chrc_ineta_port, dcl_blasetr_1::en_ca_stage1 );
       if (bol1 == FALSE) {                 /* server is not valid     */
         goto psere_vdi60;                  /* remove this server      */
       }
       if (adsg_loconf_1_inuse->adsc_cluster == NULL) {  /* pointer to main cluster structure */
#ifndef B120116
         memcpy( &dsl_lbcs_2.chrc_ineta_port, adsl_lb_rec_server_w2->chrc_ineta_port, sizeof(dsl_lbcs_2.chrc_ineta_port) );
#endif
         goto psere_start;                  /* server found            */
       }
       adsc_lrs_cluster = adsl_lb_rec_server_w2;    /* trimming twin request   */
       ienum_to = en_to_bstrtime;           /* status timeout          */
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 7 );
#endif
       HLGW_set_timer( aclparam, 1 );       /* time wait other cluster member */
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 15 );
#endif
       return;                              /* wait for timeout        */

       psere_vdi60:                         /* remove server from list */
       if (imc_function == 0) goto psere_vdi64;
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       adsl_lb_rec_server_w3 = NULL;        /* no server before        */
       while (adsl_lb_rec_server_w1) {      /* loop over all found servers */
         if (adsl_lb_rec_server_w1 == adsl_lb_rec_server_w2) break;
         adsl_lb_rec_server_w3 = adsl_lb_rec_server_w1;  /* save previous one */
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       if (adsl_lb_rec_server_w1 == NULL) {
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_proc_se_recv psere_vdi60 server not found" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_proc_cl_recv l%05d psere_vdi60 server not found", __LINE__ );
#endif
         goto psere_vdi00;                  /* search which VDI server */
       }
       if (adsl_lb_rec_server_w3 == NULL) {  /* no server before       */
         adsc_lb_rec_server = adsl_lb_rec_server_w1->adsc_next;
       } else {
         adsl_lb_rec_server_w3->adsc_next = adsl_lb_rec_server_w1->adsc_next;
       }
       free( adsl_lb_rec_server_w1 );       /* free this entry         */
       adsl_lb_rec_server_w1 = adsc_lb_rec_server;  /* get chain       */
       while (adsl_lb_rec_server_w1) {      /* loop over all found servers */
#ifdef OLD_1112
         if (adsl_lb_rec_server_w1->imc_port >= 0) {  /* entry is valid */
           goto psere_vdi00;                /* search which VDI server */
         }
#endif
#ifndef OLD_1112
         if (adsl_lb_rec_server_w1->chrc_ineta_port[ 0 ] != 0) {  /* entry is valid */
           goto psere_vdi00;                /* search which VDI server */
         }
#endif
         adsl_lb_rec_server_w1 = adsl_lb_rec_server_w1->adsc_next;
       }
       iml1 = m_get_time();                 /* get time in seconds     */
       if (iml1 >= (imc_start_time + imc_time1 + imc_time2)) {
         goto psere_tim20;                  /* report no server found  */
       }
       if (ienum_to != en_to_bstrtime) {    /* wait for other cluster member  */
         goto psere_tim00;                  /* wait for next action    */
       }
       ienum_to = en_to_time1;              /* status timeout          */
       iml2 = (imc_start_time + imc_time1) - iml1;  /* after first ti */
       if (iml2 <= 0) {
         iml2 += imc_time2;                 /* add second time         */
         if (iml2 <= 0) goto psere_tim20;   /* report no server found  */
         ienum_to = en_to_time2;            /* status timeout          */
       }
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 8 );
#endif
       HLGW_set_timer( aclparam, iml2 );    /* time wait set           */
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 16 );
#endif
       return;                              /* wait for next call      */

       psere_vdi64:                         /* came from client        */
       achl_send1 = achp_workarea_start + 2;  /* after record length   */
       memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
       achl_send1 += sizeof(chrs_rece1);
       *(achl_send1 + 0) = 4;               /* length structure        */
       *(achl_send1 + 1) = 0X49;            /* error record            */
       *((unsigned char *) (achl_send1 + 2))
         = (unsigned char) (DEF_ERR_BLADE_IN_USE >> 8);  /* first byte error */
       *((unsigned char *) (achl_send1 + 3))
         = (unsigned char) DEF_ERR_BLADE_IN_USE;  /* second byte error */
       achl_send1 += 4;                     /* set end record          */
       achl_w1 = achp_workarea_start + 1;   /* record begins here      */
       iml1 = achl_send1 - achl_w1;         /* compute length          */
       if (iml1 >= 0X80) {
         achl_w1 = achp_workarea_start;     /* record begins here      */
         iml1++;                            /* increment length        */
         *achl_w1 = (iml1 >> 7) | 0X80;     /* set first byte length   */
       }
       *(achp_workarea_start + 1) = iml1 & 0X7F;  /* set length        */
#ifdef XYZ1
       *aachp_ret_msg = achl_w1;                    /* set area to send        */
       *aimp_ret_msg_len = iml1;                    /* set length to send      */
       HLGW_set_abend( aclparam );          /* set abend               */
       return;
#endif

       psere_vdi80:                         /* timeout trimming twin   */
       adsl_lb_rec_server_w2 = adsc_lrs_cluster;  /* VDI cluster request */
       bol1 = dcl_blasetr_1::m_check_ineta( adsl_lb_rec_server_w2->chrc_ineta_port, dcl_blasetr_1::en_ca_stage2 );
       if (bol1 == FALSE) {                 /* server is not valid     */
         goto psere_vdi60;                  /* remove this server      */
       }
#ifndef B120116
       memcpy( &dsl_lbcs_2.chrc_ineta_port, adsl_lb_rec_server_w2->chrc_ineta_port, sizeof(dsl_lbcs_2.chrc_ineta_port) );
#endif

       psere_start:                         /* server found            */
#ifdef OLD_1112
       achl_send1 = achp_workarea_start + 2;              /* after record length     */
       memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
       achl_send1 += sizeof(chrs_rece1);
       if (boc_reconnect == FALSE) {        /* is not reconnect        */
#ifdef B070509
         if (adsl_lb_rec_server_w2->i_len_appl) {
           iu1 = adsl_lb_rec_server_w2->i_len_appl + 2;
           if (iu1 >= 0X80) {
             iu1++;                         /* increment length        */
             *((unsigned char *) achl_send1++) = iu1 >> 8;
           }
           *((unsigned char *) achl_send1++) = iu1;
           *((unsigned char *) achl_send1++) = 0X30;
           memcpy( achl_send1, adsl_lb_rec_server_w2 + 1, adsl_lb_rec_server_w2->i_len_appl );
           achl_send1 += adsl_lb_rec_server_w2->i_len_appl;
         }
#endif
         if (adsl_lb_rec_server_w2->imc_len_fields) {  /* with additional fields */
           memcpy( achl_send1, adsl_lb_rec_server_w2 + 1, adsl_lb_rec_server_w2->imc_len_fields );
           achl_send1 += adsl_lb_rec_server_w2->imc_len_fields;
         }
         uml_ineta = adsl_lb_rec_server_w2->ulineta;
         iuport = adsl_lb_rec_server_w2->imc_port;
       }
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 9 );
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv l%05d before HLGW_start_conn() dsl_lbcs_2.boc_other_server=%d.",
                       __LINE__, dsl_lbcs_2.boc_other_server );
#endif
       if (dsl_lbcs_2.boc_other_server) {   /* already connected to other servers */
         *(achl_send1 + 0) = 8;             /* length structure        */
         *(achl_send1 + 1) = 0X4B;          /* user other server       */
         memcpy( achl_send1 + 2, &dsl_lbcs_2.chrc_ineta_port, 6 );
         achl_send1 += 8;                   /* set end record          */
       } else {
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv l%05d HLGW_start_conn( aclparam=%p , uml_ineta=0X%08X , port=%d )",
               __LINE__, aclparam, uml_ineta, iuport );
#endif
         iu2 = HLGW_start_conn( aclparam, uml_ineta, iuport );
         if (iu2) {                         /* error occured           */
           *(achl_send1 + 0) = 4;           /* length structure        */
           *(achl_send1 + 1) = 0X49;        /* error record            */
           *((unsigned char *) (achl_send1 + 2))
             = (unsigned char) (iu2 >> 8);  /* first byte error        */
           *((unsigned char *) (achl_send1 + 3))
             = (unsigned char) iu2;         /* second byte error       */
           achl_send1 += 4;                 /* set end record          */
         } else {
           *(achl_send1 + 0) = 8;           /* length structure        */
           *(achl_send1 + 1) = 0X48;        /* connect record          */
#ifdef B080909
#ifdef INETA_LOAD_BYTE
#ifndef __LITTLE_ENDIAN
           *((unsigned char *) (achl_send1 + 2))
             = (unsigned char) (uml_ineta >> 24);  /* first byte IP add */
           *((unsigned char *) (achl_send1 + 3))
             = (unsigned char) (uml_ineta >> 16);  /* second byte IP a */
           *((unsigned char *) (achl_send1 + 4))
             = (unsigned char) (uml_ineta >> 8);  /* third byte IP addr */
           *((unsigned char *) (achl_send1 + 5))
             = (unsigned char) uml_ineta;   /* fourth byte IP addr     */
#else
           *((unsigned char *) (achl_send1 + 2))
             = (unsigned char) uml_ineta;   /* first byte IP addr      */
           *((unsigned char *) (achl_send1 + 3))
             = (unsigned char) (uml_ineta >> 8);  /* second byte IP addr */
           *((unsigned char *) (achl_send1 + 4))
             = (unsigned char) (uml_ineta >> 16);  /* third byte IP addr */
           *((unsigned char *) (achl_send1 + 5))
             = (unsigned char) (uml_ineta >> 24);  /* fourth byte IP addr */
#endif
#else
           *((UNSIG_MED *) (achl_send1 + 2)) = uml_ineta;
#endif
           *((unsigned char *) (achl_send1 + 6))
             = (unsigned char) (iuport >> 8);  /* first byte port      */
           *((unsigned char *) (achl_send1 + 7))
             = (unsigned char) iuport;      /* second byte port        */
#else
           memcpy( achl_send1 + 2, &dsl_lbcs_2.chrc_ineta_port, 6 );
#endif
           achl_send1 += 8;                    /* set end record          */
         }
       }
       au1 = achp_workarea_start + 1;                  /* record begins here      */
       iu1 = achl_send1 - au1;                 /* compute length          */
       if (iu1 >= 0X80) {
         au1 = achp_workarea_start;                    /* record begins here      */
         iu1++;                             /* increment length        */
         *au1 = (iu1 >> 7) | 0X80;          /* set first byte length   */
       }
       *(achp_workarea_start + 1) = iu1 & 0X7F;        /* set length              */
       *aachp_ret_msg = au1;                    /* set area to send        */
       *aimp_ret_msg_len = iu1;                    /* set length to send      */
       return;
#endif
#ifndef OLD_1112
       achl_send1 = achp_workarea_start + 2;  /* after record length   */
       memcpy( achl_send1, chrs_rece1, sizeof(chrs_rece1) );
       achl_send1 += sizeof(chrs_rece1);
       if (boc_reconnect == FALSE) {        /* is not reconnect        */
         if (adsl_lb_rec_server_w2->imc_len_fields) {  /* with additional fields */
           memcpy( achl_send1, adsl_lb_rec_server_w2 + 1, adsl_lb_rec_server_w2->imc_len_fields );
           achl_send1 += adsl_lb_rec_server_w2->imc_len_fields;
         }
       }
#ifdef TRACEHLC
       m_check_aclconn1( aclparam, 9 );
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv l%05d before HLGW_start_conn() dsl_lbcs_2.boc_other_server=%d.",
                       __LINE__, dsl_lbcs_2.boc_other_server );
#endif
       if (dsl_lbcs_2.boc_other_server) {   /* already connected to other servers */
         iml1 = (unsigned char) dsl_lbcs_2.chrc_ineta_port[ 0 ];  /* get length */
         *(achl_send1 + 0) = iml1;          /* length structure        */
         *(achl_send1 + 1) = 0X4B;          /* user other server       */
         memcpy( achl_send1 + 2, &dsl_lbcs_2.chrc_ineta_port[ 2 ], iml1 - 2 );
         achl_send1 += iml1;                /* set end record          */
       } else {
#ifdef B120211
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_proc_se_recv l%05d HLGW_start_conn( aclparam=%p , uml_ineta=0X%08X , port=%d )",
               __LINE__, aclparam, uml_ineta, iuport );
#endif
#endif
         memset( &dsl_soa_l, 0, sizeof(struct sockaddr_storage) );
         if (dsl_lbcs_2.chrc_ineta_port[ 0 ] == (2 + 4 + 2)) {  /* IPV4 */
           dsl_soa_l.ss_family = AF_INET;
           memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_addr,
                   &dsl_lbcs_2.chrc_ineta_port[ 2 ],
                   4 );
           memcpy( &((struct sockaddr_in *) &dsl_soa_l)->sin_port,
                   &dsl_lbcs_2.chrc_ineta_port[ 2 + 4 ],
                   2 );
         } else {                           /* IPV6                    */
           dsl_soa_l.ss_family = AF_INET6;
           memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_addr,
                   &dsl_lbcs_2.chrc_ineta_port[ 2 ],
                   16 );
           memcpy( &((struct sockaddr_in6 *) &dsl_soa_l)->sin6_port,
                   &dsl_lbcs_2.chrc_ineta_port[ 2 + 16 ],
                   2 );
         }
         iml1 = HLGW_start_conn( aclparam, (struct sockaddr *) &dsl_soa_l );
         if (iml1) {                        /* error occured           */
           *(achl_send1 + 0) = 4;           /* length structure        */
           *(achl_send1 + 1) = 0X49;        /* error record            */
           *((unsigned char *) (achl_send1 + 2))
             = (unsigned char) (iml1 >> 8);  /* first byte error        */
           *((unsigned char *) (achl_send1 + 3))
             = (unsigned char) iml1;        /* second byte error       */
           achl_send1 += 4;                 /* set end record          */
         } else {
           iml1 = (unsigned char) dsl_lbcs_2.chrc_ineta_port[ 0 ];  /* get length INETA and port */
           memcpy( achl_send1, dsl_lbcs_2.chrc_ineta_port, iml1 );  /* copy length, INETA and port */
           *(achl_send1 + 1) = 0X48;        /* connect record          */
           achl_send1 += iml1;              /* set end record          */
         }
       }
       achl_w1 = achp_workarea_start + 1;   /* record begins here      */
       iml1 = achl_send1 - achl_w1;         /* compute length          */
       if (iml1 >= 0X80) {
         achl_w1 = achp_workarea_start;     /* record begins here      */
         iml1++;                            /* increment length        */
         *achl_w1 = (iml1 >> 7) | 0X80;     /* set first byte length   */
       }
       *(achp_workarea_start + 1) = iml1 & 0X7F;  /* set length        */
       *aachp_ret_msg = achl_w1;            /* set area to send        */
       *aimp_ret_msg_len = iml1;            /* set length to send      */
       return;
#endif
     } /* end m_proc_se_recv()                                         */
#endif
};


void dsd_lbal_gw_1::m_check_other_server( struct dsd_lbal_conn_server *adsp_lbcs,
                                          struct dsd_lb_rec_server *adsp_lbr_server ) {
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of data             */

   adsp_lbcs->boc_other_server = FALSE;     /* already connected to other servers */
#ifdef OLD_1112
#ifdef INETA_LOAD_BYTE
#ifndef __LITTLE_ENDIAN
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 0))
     = (unsigned char) (adsp_lbr_server->ulineta >> 24);  /* first byte IP add */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 1))
     = (unsigned char) (adsp_lbr_server->ulineta >> 16);  /* second byte IP a */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 2))
     = (unsigned char) (adsp_lbr_server->ulineta >> 8);  /* third byte IP addr */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 3))
     = (unsigned char) adsp_lbr_server->ulineta;  /* fourth byte IP addr */
#else
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 0))
     = (unsigned char) adsp_lbr_server->ulineta;  /* first byte IP addr */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 1))
     = (unsigned char) (adsp_lbr_server->ulineta >> 8);  /* second byte IP addr */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 2))
     = (unsigned char) (adsp_lbr_server->ulineta >> 16);  /* third byte IP addr */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 3))
     = (unsigned char) (adsp_lbr_server->ulineta >> 24);  /* fourth byte IP addr */
#endif
#else
   *((UNSIG_MED *) (adsp_lbcs->chrc_ineta_port + 0)) = adsp_lbr_server->ulineta;
#endif
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 4))
     = (unsigned char) (adsp_lbr_server->imc_port >> 8);  /* first byte port */
   *((unsigned char *) (adsp_lbcs->chrc_ineta_port + 5))
     = (unsigned char) adsp_lbr_server->imc_port;  /* second byte port    */
#endif
#ifndef OLD_1112
   memcpy( adsp_lbcs->chrc_ineta_port, adsp_lbr_server->chrc_ineta_port, sizeof(adsp_lbcs->chrc_ineta_port) );
#endif
   if (this->boc_other_server == FALSE) return;  /* already connected to other servers */
   /* loop thru control record from client                             */
   achl_rp = achc_recbuf;                   /* start of data           */
   achl_end = achc_recbuf + imc_reclen;     /* end of data             */
   iml1 = 0;                                /* set length              */
   while ((achl_rp < achl_end) && ((*achl_rp & 0X80) != 0)) {
     iml1 <<= 7;
     iml1 |= *achl_rp & 0X7F;
     achl_rp++;
   }
   if (achl_rp >= achl_end) {
#ifdef B090417
     m_display( "dsd_lbal_gw_1::m_check_other_server end of record while retrieving length" );
#else
     m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_check_other_server l%05d end of record while retrieving length", __LINE__ );
#endif
     return;
   }
   iml1 <<= 7;
   iml1 |= *achl_rp & 0X7F;
   achl_rp++;
   if (iml1 != imc_reclen) {                /* length not correct      */
#ifdef B090417
     m_display( "dsd_lbal_gw_1::m_check_other_server different length record retrieved" );
#else
     m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_check_other_server l%05d different length record retrieved", __LINE__ );
#endif
     return;
   }
   achl_rp += sizeof(chrs_send1);           /* after eye-catcher       */
   while (achl_rp < achl_end) {             /* loop over input packet  */
     iml1 = 0;                              /* set length              */
     achl_w1 = achl_rp;                     /* save beginning          */
     while ((achl_rp < achl_end) && ((*achl_rp & 0X80) != 0)) {
       iml1 <<= 7;
       iml1 |= *achl_rp & 0X7F;
       achl_rp++;
     }
     if (achl_rp >= achl_end) goto p_check_err_00;
     iml1 <<= 7;
     iml1 |= *achl_rp & 0X7F;
     achl_rp++;
     if (iml1 < 2) goto p_check_err_00;
     achl_w1 += iml1;
     if (achl_w1 > achl_end) goto p_check_err_00;
     if (achl_rp >= achl_w1) goto p_check_err_00;
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "dsd_lbal_gw_1::m_check_other_server received struct %02X current=%p end=%p.",
                     (unsigned char) *achl_rp, achl_rp, achl_w1 );
#endif
     if (((unsigned char) *achl_rp) == 0X05) {  /* already connected to server */
#ifdef OLD_1112
       if ((achl_rp + 1 + 6) != achl_w1) {
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_check_other_server INETA + port invalid length" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_check_other_server l%05d INETA + port invalid length", __LINE__ );
#endif
         return;
       }
       if (!memcmp( achl_rp + 1, adsp_lbcs->chrc_ineta_port, 6 )) {
         adsp_lbcs->boc_other_server = TRUE;  /* already connected to other servers */
         return;
       }
#endif
#ifndef OLD_1112
       iml1 = achl_w1 - achl_rp - 1 - 2;    /* length INETA            */
       if (   (iml1 != 4)                   /* not IPV4                */
           && (iml1 != 16)) {               /* not IPV6                */
#ifdef B090417
         m_display( "dsd_lbal_gw_1::m_check_other_server INETA + port invalid length" );
#else
         m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_check_other_server l%05d INETA + port invalid length", __LINE__ );
#endif
         return;
       }
       if (   ((2 + iml1 + 2) == adsp_lbcs->chrc_ineta_port[ 0 ])  /* length equal */
           && !memcmp( achl_rp + 1, &adsp_lbcs->chrc_ineta_port[ 2 ], iml1 + 2)) {
         adsp_lbcs->boc_other_server = TRUE;  /* already connected to other servers */
         return;
       }
#endif
     }
     achl_rp = achl_w1;                     /* here is next structure */
   }
   return;                                  /* other servers do not match */

   p_check_err_00:                          /* invalid data received   */
#ifdef B090417
   m_display( "dsd_lbal_gw_1::m_check_other_server p_check_err_00" );
#else
   m_hlgw_printf( aclparam, "dsd_lbal_gw_1::m_check_other_server l%05d p_check_err_00 invalid data received", __LINE__ );
#endif
   return;
} /* end dsd_lbal_gw_1::m_check_other_server()                         */
