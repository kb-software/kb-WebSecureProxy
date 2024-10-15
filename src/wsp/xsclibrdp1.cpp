//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsclibrdp1                                          |*/
/*| -------------                                                     |*/
/*|  Server-Data-Hook directly linked into the HOB WebSecureProxy     |*/
/*|  RDP for True Windows Single Server                               |*/
/*|  KB 27.02.06                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005                                            |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
   see HOBTEXT SOFTWARE.HLSEC.HOBRDPE1
   and HOBTEXT SOFTWARE.HLSEC.HOBRDPE3

   CONNECT INETA=xyz PORT=nnn
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
#include <sys/socket.h>
#include <netinet/in.h>
#include "hob-unix01.h"
#endif
#include <hob-xslunic1.h>
#include <hob-netw-01.h>
#define DEF_HL_INCL_INET
#include "hob-xsclib01.h"

extern "C" BOOL m_tcp_dynamic_conn( void *, struct dsd_aux_tcp_conn_1 *, struct dsd_target_ineta_1 *, void *, BOOL );
extern "C" int m_tcp_static_conn( void *, BOOL );
extern "C" BOOL m_tcp_close( void * );

static int m_sdh_printf( struct dsd_sdh_call_1 *, char *, ... );

#ifdef TRACEHL1
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *, int );
static void m_console_out( char *achp_buff, int implength );
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

enum ied_conn_state {                       /* connection state        */
   ied_cos_start = 0,                       /* start of connection     */
   ied_cos_cont,                            /* continue                */
   ied_xyz_error                            /* error, no valid response */
};

struct dsd_clib1_data_1 {                   /* structure session       */
   enum ied_conn_state iec_cos;             /* connection state        */
   int        inrc_prot_1[2];               /* protocol status         */
                                            /* 0 = FROMSERVER          */
                                            /* 1 = TOSERVER            */
/**
   0X80000000   T.123 first byte, reserved
   0X80000001   T.123 first byte length
   0X80000002   T.123 second byte length
   0X80004000   T.123 HOB special
   0X80002000   T.123 HOB special command
   0X80008000   RDP-5 first byte, length
   0X80008001   RDP-5 second byte length
*/
   BOOL       boc_error;                    /* error displayed         */
   BOOL       boc_dynamic;                  /* with dynamic connect    */
   char       chrc_ineta[ 1 + 16 + 2 ];     /* field for INETA         */
};

static const char chrs_out_t123_1[] = { 0X03 };

static const unsigned char ucrs_out_ack_conn[] = { 0X03, 0XFF, 0X00, 0X05, 0X00 };

static const unsigned char ucrs_out_no_server[] = {
   0X03, 0XFF, 0X00, 0X06, 0X01, 0X00
};

static const unsigned char ucrs_comm_connect[] = {
   'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '
};

static const unsigned char ucrs_comm_ineta[] = {
   'I', 'N', 'E', 'T', 'A', '='
};

static const unsigned char ucrs_comm_port[] = {
   'P', 'O', 'R', 'T', '='
};

/** subroutine to process the copy library function                    */
extern "C" void m_rdp1_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
#ifdef TRACEHL1
   char       chl1;                         /* working variable        */
#endif
   int        iml1, iml2, iml3;             /* working variables       */
#ifdef B121117
   BOOL       bol1, bol2;                   /* working variables       */
#endif
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_connected;                /* connected to server     */
   int        iml_ineta_len;                /* length INETA            */
   int        iml_port;                     /* port to connect to      */
   struct dsd_clib1_data_1 *adsl_cl1d1_1;   /* for addressing          */
   int        *aiml_prot_1;                 /* pointer to protocol status */
   char       *achl1, *achl2, *achl3, *achl4;  /* working variables    */
   char       *achl_ineta_start;            /* start of INETA          */
   struct dsd_target_ineta_1 *adsl_server_ineta_w1;  /* server INETA   */
   void *     al_free_ti1;                  /* INETA to be freed       */
   char       *achl_work_1;                 /* working variable        */
   char       *achl_work_2;                 /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_aux_query_receive dsl_aux_query_receive;  /* query if more to receive */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_aux_get_session_info dsl_ag_sess_info;  /* get information about the session */
   struct dsd_aux_tcp_conn_1 dsl_aux_tcp_conn_1; /* TCP Connect to Server */
   char       chrl_work1[512];              /* work area               */

   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
#ifdef TRACEHL1
   {
     char *achh_text = "invalid function";
     char chrh_buffer[ 8 ];
     int inh1 = 0;
     int inh2 = 0;
     int inh_buffer = 0;
     char *achh_rp;
     memset( chrh_buffer, 0, sizeof(chrh_buffer) );
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
       achh_rp = adsl_gai1_inp_1->achc_ginp_cur;
       while ((inh_buffer < sizeof(chrh_buffer)) && (achh_rp < adsl_gai1_inp_1->achc_ginp_end)) {
         chrh_buffer[ inh_buffer++ ] = *achh_rp++;
       }
       iml2++;
       iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (   (adsl_gai1_inp_1->achc_ginp_end > adsl_gai1_inp_1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_START) {
       adsl_cl1d1_1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
       if (adsl_cl1d1_1 == NULL) {
         printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X not storage\n",
                 __LINE__, adsp_hl_clib_1->inc_func, achh_text,
                 adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
         fflush( stdout );
         return;
       }
       inh1 = adsl_cl1d1_1->inrc_prot_1[0];
       inh2 = adsl_cl1d1_1->inrc_prot_1[1];
     }
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X prot=%08X/%08X\n",
             __LINE__, adsp_hl_clib_1->inc_func, achh_text,
             adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1,
             inh1, inh2 );
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() data %02X %02X %02X %02X %02X %02X %02X %02X.\n",
             __LINE__,
             (unsigned char) chrh_buffer[ 0 ],
             (unsigned char) chrh_buffer[ 1 ],
             (unsigned char) chrh_buffer[ 2 ],
             (unsigned char) chrh_buffer[ 3 ],
             (unsigned char) chrh_buffer[ 4 ],
             (unsigned char) chrh_buffer[ 5 ],
             (unsigned char) chrh_buffer[ 6 ],
             (unsigned char) chrh_buffer[ 7 ] );
     fflush( stdout );
   }
#endif
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
     case DEF_IFUNC_FROMSERVER:
       adsl_cl1d1_1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
       aiml_prot_1 = &adsl_cl1d1_1->inrc_prot_1[0];
       break;
     case DEF_IFUNC_TOSERVER:
       adsl_cl1d1_1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
       aiml_prot_1 = &adsl_cl1d1_1->inrc_prot_1[1];
       break;
     case DEF_IFUNC_REFLECT:                /* reflect data            */
       adsl_cl1d1_1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
       aiml_prot_1 = &adsl_cl1d1_1->inrc_prot_1[1];
       break;
     default:
       return;
   }

   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   if (   (adsp_hl_clib_1->boc_eof_server)  /* server has ended        */
       && (adsl_cl1d1_1->inrc_prot_1[0] == 0)
       && (adsl_cl1d1_1->inrc_prot_1[1] == 0)
       && (adsp_hl_clib_1->adsc_gather_i_1_in == NULL)) {
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W TCP connection with server ended",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection should be ended */
     return;
   }
   if (adsl_cl1d1_1->iec_cos != ied_cos_start) {  /* start of connection */
     goto p_start_60;                       /* after start             */
   }
   adsl_cl1d1_1->iec_cos = ied_cos_cont;    /* continue                */
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_REFLECT) {  /* reflect data */
     goto p_start_40;                       /* send first packet with server */
   }
// 28.07.10 KB - check server connected
   adsl_cl1d1_1->boc_dynamic = TRUE;        /* with dynamic connect    */
   /* send packet with message no server configured                    */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* no more space in work-area */
// to-do 28.07.10 KB error message
     return;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = (char *) ucrs_out_no_server;
   adsl_gai1_out_1->achc_ginp_end = (char *) ucrs_out_no_server + sizeof(ucrs_out_no_server);
   adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
   adsl_gai1_out_2 = adsl_gai1_out_1;
// to-do 30.07.10 KB other state
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   if (adsl_gai1_inp_1 == NULL) return;     /* no data received        */
   goto p_start_80;                         /* after start part two    */

   p_start_40:                              /* send first packet with server */
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() p_start_40 send first packet with server\n",
           __LINE__ );
   fflush( stdout );
#endif
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) return;   /* no more space in work-area */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = (char *) ucrs_out_ack_conn;
   adsl_gai1_out_1->achc_ginp_end = (char *) ucrs_out_ack_conn + sizeof(ucrs_out_ack_conn);
   if (adsl_gai1_out_2 == NULL) {
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;

   p_start_60:                              /* after start part one    */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   if (adsl_gai1_inp_1 == NULL) {
     return;
   }

   p_start_80:                              /* after start part two    */

   pne_gath_00:                             /* next gather             */
   achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data       */
   if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) return;   /* no more space in work-area */

   pne_gath_20:                             /* check input             */
   if (*aiml_prot_1 > 0) {                  /* search more in frame    */
     achl1 += *aiml_prot_1;                 /* add to pointer input    */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* at or after end of input data */
       *aiml_prot_1 = achl1 - adsl_gai1_inp_1->achc_ginp_end;
       goto pne_gath_60;                    /* copy all data           */
     }
     *aiml_prot_1 = 0;                      /* now at start of frame   */
   }
   if (*aiml_prot_1 == 0) {                 /* at start of frame       */
     *aiml_prot_1 = 0X80008000;             /* set RDP-5 default       */
     if (*achl1 == 0X03) {                  /* found T.123             */
       *aiml_prot_1 = 0X80000000;           /* set T.123 reserved      */
     }
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {
         goto pne_gath_60;                  /* copy all data           */
       }
       if (*aiml_prot_1 == 0X80008000) {    /* RDP-5                   */
         goto pne_gath_60;                  /* copy all data           */
       }
       achl1--;                             /* byte before             */
       if (achl1 == adsl_gai1_inp_1->achc_ginp_cur) {  /* only this byte */
         adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
         goto pne_gath_80;                  /* ignore this input       */
       }
// to-do 18.12.10 KB - should these data be ignored if no connection to the server ???
       /* copy without last byte                                       */
       adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
       adsl_gai1_out_1->adsc_next = NULL;
       adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_out_1->achc_ginp_end = achl1;
       adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
       if (adsl_gai1_out_2 == NULL) {
         if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
           adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
         } else {                           /* send to server          */
           adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
         }
       } else {
         adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
       }
       adsl_gai1_out_2 = adsl_gai1_out_1;
       goto pne_gath_80;                    /* get next input          */
     }
   }
   if (*aiml_prot_1 == 0X80008000) {        /* RDP-5 first byte length */
     if ((*achl1 & 0X80) == 0) {            /* length in one bytes     */
       *aiml_prot_1 = *achl1 - 2;           /* set length to follow    */
       if (*aiml_prot_1 <= 0) {             /* length too short        */
         if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
           m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() invalid frame sequence",
                         __LINE__ );
           adsl_cl1d1_1->boc_error = TRUE;  /* error displayed now     */
         }
         *aiml_prot_1 = 0;                  /* try frame boundary to synchronize */
       }
       achl1++;                             /* next input              */
       if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
         goto pne_gath_60;                  /* copy all data           */
       }
       goto pne_gath_20;                    /* check input             */
     }
     (*aiml_prot_1)++;                      /* then second byte length */
     *aiml_prot_1 |= *achl1 << 24;          /* save length             */
#ifdef TRACEHL1
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() *aiml_prot_1 == 0X80008000 new=%02X result=%08X\n",
             __LINE__, (unsigned char) *achl1, *aiml_prot_1 );
     fflush( stdout );
#endif
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       goto pne_gath_60;                    /* copy all data           */
     }
   }
   if ((*aiml_prot_1 & 0X80FFFFFF) == 0X80008001) {  /* RDP-5 second byte length */
#ifdef OLD01
     *aiml_prot_1 |= *achl1 << 16;          /* save length             */
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
#endif
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 |= (unsigned char) *achl1;  /* save length           */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
     *aiml_prot_1 -= 3;                     /* set length to follow    */
#ifdef TRACEHL1
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() *aiml_prot_1 == 0X80008001 new=%02X result=%08X\n",
             __LINE__, (unsigned char) *achl1, *aiml_prot_1 );
     fflush( stdout );
#endif
     if (*aiml_prot_1 <= 0) {               /* length too short        */
       if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
         m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() invalid frame sequence",
                       __LINE__ );
         adsl_cl1d1_1->boc_error = TRUE;    /* error displayed now     */
       }
       *aiml_prot_1 = 0;                    /* try frame boundary to synchronize */
     }
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       goto pne_gath_60;                    /* copy all data           */
     }
     goto pne_gath_20;                      /* check input             */
   }
   if (*aiml_prot_1 == 0X80002000) {        /* is at T.123 HOB special command */
     goto pne_comm_00;                      /* command found           */
   }
   if (*aiml_prot_1 == 0X80000000) {        /* is at T.123 reserved    */
     (*aiml_prot_1)++;                      /* set T.123 first byte length */
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_FROMSERVER) {
       if ((unsigned char) *achl1 == 0XFF) {  /* found HOB special     */
#ifdef TRACEHL1
         printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() HOB special found\n",
                 __LINE__ );
         fflush( stdout );
#endif
// to-do 18.12.10 KB - should these data be ignored if no connection to the server ???
         /* copy without last byte                                      */
         if (achl1 > (adsl_gai1_inp_1->achc_ginp_cur + 1)) {  /* not after 0X03 - removed */
           adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
           adsl_gai1_out_1->adsc_next = NULL;
           adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
           adsl_gai1_out_1->achc_ginp_end = achl1 - 2;
           adsl_gai1_inp_1->achc_ginp_cur = achl1 - 2;
           if (adsl_gai1_out_2 == NULL) {
             if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
               adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
             } else {                       /* send to server          */
               adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
             }
           } else {
             adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
           }
           adsl_gai1_out_2 = adsl_gai1_out_1;
           achl_work_2 -= sizeof(struct dsd_gather_i_1);
         }
         *aiml_prot_1 = 0X80004000;         /* INETA follows           */
         achl1++;                           /* next input              */
         if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;
         goto pne_gath_40;                  /* get INETA               */
       }
       if (achl1 == adsl_gai1_inp_1->achc_ginp_cur) {  /* after 0X03 - removed */
// to-do 18.12.10 KB - should these data be ignored if no connection to the server ???
         /* check if more output possible                              */
         if ((achl_work_2 - sizeof(struct dsd_gather_i_1))
               < achl_work_1) return;
         adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
         adsl_gai1_out_1->adsc_next = NULL;
         adsl_gai1_out_1->achc_ginp_cur = (char *) chrs_out_t123_1;
         adsl_gai1_out_1->achc_ginp_end = (char *) chrs_out_t123_1 + sizeof(chrs_out_t123_1);
         if (adsl_gai1_out_2 == NULL) {
           if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
             adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
           } else {                         /* send to server          */
             adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
           }
         } else {
           adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
         }
         adsl_gai1_out_2 = adsl_gai1_out_1;
         achl_work_2 -= sizeof(struct dsd_gather_i_1);
       }
     }
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_60;
   }
   if (*aiml_prot_1 == 0X80000001) {        /* is at T.123 first byte length */
     if (*achl1 & 0X80) {                   /* length too high         */
       if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
         m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() invalid frame sequence",
                       __LINE__ );
         adsl_cl1d1_1->boc_error = TRUE;    /* error displayed now     */
       }
       *aiml_prot_1 = 0;                    /* try frame boundary to synchronize */
     }
     *aiml_prot_1 |= *achl1 << 24;          /* save length             */
     (*aiml_prot_1)++;                      /* then second byte length */
#ifdef TRACEHL1
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() *aiml_prot_1 == 0X80000001 new=%02X result=%08X\n",
             __LINE__, (unsigned char) *achl1, *aiml_prot_1 );
     fflush( stdout );
#endif
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) goto pne_gath_80;
   }
   if ((*aiml_prot_1 & 0X80FFFFFF) == 0X80000002) {  /* is at T.123 second byte length */
#ifdef OLD01
     *aiml_prot_1 |= ((unsigned char) *achl1) << 16;  /* save length   */
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
#endif
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 |= (unsigned char) *achl1;  /* save length           */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
     *aiml_prot_1 -= 4;                     /* set length to follow    */
#ifdef TRACEHL1
     printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() *aiml_prot_1 == 0X80000002 new=%02X result=%08X\n",
             __LINE__, (unsigned char) *achl1, *aiml_prot_1 );
     fflush( stdout );
#endif
     if (*aiml_prot_1 <= 0) {               /* new length of frame invalid */
       if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
         m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() invalid frame sequence",
                       __LINE__ );
         adsl_cl1d1_1->boc_error = TRUE;    /* error displayed now     */
       }
       *aiml_prot_1 = 0;                    /* try frame boundary to synchronize */
     }
     achl1++;                               /* next input              */
     if (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       goto pne_gath_60;                    /* copy all data           */
     }
     goto pne_gath_20;                      /* check input             */
   }
   if ((*aiml_prot_1 & 0XFFFFF000) != 0X80004000) {
     if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
       m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() logic-error invalid length %08X.",
                     __LINE__, *aiml_prot_1 );
       adsl_cl1d1_1->boc_error = TRUE;      /* error displayed now     */
     }
     *aiml_prot_1 = 0;                      /* try frame boundary to synchronize */
     goto pne_gath_20;                      /* check input             */
   }

   pne_gath_40:                             /* get INETA               */
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() pne_gath_40 *aiml_prot_1=%08X achl1=%p adsl_gai1_inp_1=%p achc_ginp_cur=%p achc_ginp_end=%p\n",
            __LINE__, *aiml_prot_1, achl1, adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, adsl_gai1_inp_1->achc_ginp_end );
   fflush( stdout );
   m_console_out( adsl_gai1_inp_1->achc_ginp_cur, adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur );
#endif
   iml1 = *aiml_prot_1 - 0X80004000;        /* position in area        */
   if (iml1 == 0) {                         /* is at start of area     */
     adsl_cl1d1_1->chrc_ineta[0] = *achl1++;  /* get first byte        */
     iml1 = 1;                              /* now after first position */
   }
   switch ((unsigned char) adsl_cl1d1_1->chrc_ineta[0]) {
     case 0:                                /* is only reconnect       */
       iml2 = 0;                            /* nothing more to follow  */
       break;
     case 1:                                /* is IPV4                 */
       iml2 = 4 + 2;                        /* INETA and Port follow   */
       break;
     case 2:                                /* is IPV6                 */
       iml2 = 16 + 2;                       /* INETA and Port follow   */
       break;
     case 3:                                /* is command              */
       *aiml_prot_1 = 0X80002000;           /* command follows         */
       adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
       while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {
         adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
         adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
       }
       adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* processed so far    */
       goto pne_comm_00;                    /* command found           */
     default:
       if (adsl_cl1d1_1->boc_error == FALSE) {  /* error not yet displayed */
         m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() invalid HOB special %02X.",
                       __LINE__, (unsigned char) adsl_cl1d1_1->chrc_ineta[0] );
         adsl_cl1d1_1->boc_error = TRUE;    /* error displayed now     */
       }
       *aiml_prot_1 = 0;                    /* try frame boundary to synchronize */
       goto pne_gath_20;                    /* check input             */
   }
   iml2 -= iml1 - 1;                        /* compute what is missing */
   if (iml2 > 0) {                          /* get more data           */
     iml3 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* so much in block */
     if (iml3 > iml2) iml3 = iml2;          /* only to fill area       */
     memcpy( &adsl_cl1d1_1->chrc_ineta[ iml1 ], achl1, iml3 );
     achl1 += iml3;                         /* increment input         */
     *aiml_prot_1 += iml3;                  /* increment position      */
     iml2 -= iml3;                          /* decrement remainder     */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* data processed so far   */
   if (iml2 > 0) goto pne_gath_80;          /* needs more data         */
   *aiml_prot_1 = 0;                        /* now next frame          */
   /* check if more data from server                                   */
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_QUERY_RECEIVE,  /* query TCP data */
                                   &dsl_aux_query_receive,
                                   sizeof(dsl_aux_query_receive) );
   if (bol1 == FALSE) {                     /* function returned error */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_aux_query_receive.boc_data_server) return;  /* can receive more */
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   goto pne_conn_20;                        /* do connect now          */

   pne_gath_60:                             /* copy all data           */
// 15.12.10 KB - start
   if (adsp_hl_clib_1->inc_func == DEF_IFUNC_REFLECT) {  /* reflect data */
     goto pne_gath_80;                      /* end of input gather     */
   }
// 15.12.10 KB - end
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
   adsl_gai1_out_1->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_end;
   adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
   if (adsl_gai1_out_2 == NULL) {
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
       adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
     } else {                               /* send to server          */
       adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
     }
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;

   pne_gath_80:                             /* end of input gather     */
   adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
   if (adsl_gai1_inp_1 != NULL) goto pne_gath_00;  /* next gather      */
   return;

   pne_comm_00:                             /* command found           */
   iml1 = 0;                                /* clear result            */
   iml2 = 4;                                /* set maximum number of digits */
   while (TRUE) {                           /* loop to decode length NHASN */
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) return;  /* wait for more data     */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml3 = (signed char) *achl1++;         /* get next character      */
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= iml3 & 0X7F;                   /* apply new bits          */
     if (iml3 >= 0) break;                  /* end of NHASN            */
     iml2--;                                /* decrement number of digits */
     if (iml2 <= 0) {                       /* too many digits NHASN   */
       m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command too many digits length NHASN",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end   */
       return;
     }
   }
   if (iml1 <= 0) {                         /* invalid value length NHASN */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command too short",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
     achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data     */
   }
   iml2 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* how much in this chunk */
   if (iml2 >= iml1) {                      /* command in one chunk    */
     achl2 = achl1;                         /* here is command         */
     achl1 += iml1;                         /* the command has been processed */
     goto p_comm_20;                        /* achl2 and iml1 point to command */
   }
   if (iml1 > sizeof(chrl_work1)) {         /* command too long        */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT too long",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl2 = achl3 = chrl_work1;
   iml2 = iml1;                             /* get length total        */
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) return;  /* wait for more data     */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml3 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* how much in this chunk */
     if (iml3 > iml2) iml3 = iml2;
     memcpy( achl3, achl1, iml3 );          /* copy input area         */
     achl3 += iml3;                         /* increment output        */
     achl1 += iml3;                         /* increment input         */
     iml2 -= iml3;                          /* subtract from length    */
     if (iml2 <= 0) break;
   }

   p_comm_20:                               /* achl2 and iml1 point to command */
   *aiml_prot_1 = 0;                        /* record processed        */
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* processed so far        */
   iml2 = memcmp( achl2, ucrs_comm_connect, sizeof(ucrs_comm_connect) );
   if (iml2) {                              /* does not compare        */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT not found",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl3 = achl2 + sizeof(ucrs_comm_connect);
   iml_ineta_len = -1;                      /* length INETA            */
   iml_port = -1;                           /* port to connect to      */

   p_comm_40:                               /* search keyword          */
   iml3 = memcmp( achl3, ucrs_comm_ineta, sizeof(ucrs_comm_ineta) );
   if (iml3 == 0) goto p_comm_ineta_00;     /* INETA found             */
   iml3 = memcmp( achl3, ucrs_comm_port, sizeof(ucrs_comm_port) );
   if (iml3 == 0) goto p_comm_port_00;      /* port found              */
   m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT invalid keyword",
                 __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end       */
   return;

   p_comm_ineta_00:                         /* INETA found             */
   if (iml_ineta_len >= 0) {                /* length INETA            */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT INETA double",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl3 += sizeof(ucrs_comm_ineta);
   iml2 = (achl2 + iml1) - achl3;
   if (iml2 <= 0) {                         /* length too short        */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT INETA not complete",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl4 = (char *) memchr( achl3, ' ', iml2 );
   if (achl4 == NULL) {                     /* till end of input       */
     achl4 = achl3 + iml2;                  /* set end of input        */
   }
   achl_ineta_start = achl3;                /* start of INETA          */
   iml_ineta_len = achl4 - achl3;           /* length INETA            */
   achl3 = achl4 + 1;                       /* position on next keyword */
   if (achl3 < (achl2 + iml1)) goto p_comm_40;  /* search keyword      */
   achl4--;                                 /* set on end              */
   if (achl4 != achl3) {                    /* is not end              */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT no end found",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   goto p_comm_60;                          /* all parameters scanned  */

   p_comm_port_00:                          /* port found              */
   if (iml_port >= 0) {                     /* port to connect to      */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT PORT double",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl3 += sizeof(ucrs_comm_port);
   achl4 = achl2 + iml1;                    /* end of command          */
   if (achl4 > (achl3 + 8)) achl4 = achl3 + 8;  /* maximum length number */
   iml_port = 0;                            /* port to connect to      */
   while (   (achl3 < achl4)
          && (*achl3 >= '0')
          && (*achl3 <= '9')) {
     iml_port *= 10;                        /* shift result            */
     iml_port += *achl3++ - '0';
   }
   if (iml_port <= 0) {                     /* port too small          */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT received PORT too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   if (iml_port >= 0X010000) {              /* port too high           */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT received PORT too high",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   if (achl3 >= (achl2 + iml1)) {           /* end of command reached  */
     goto p_comm_60;                        /* all parameters scanned  */
   }
   if (*achl3 != ' ') {                     /* not followed by space   */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT received PORT not followed by space",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   achl3++;                                 /* after space             */
   if (achl3 >= (achl2 + iml1)) {           /* end of command reached  */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT not complete",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   goto p_comm_40;                          /* search keyword          */

   p_comm_60:                               /* all parameters scanned  */
   if (iml_ineta_len < 0) {                 /* INETA not found         */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT received without INETA",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   if (iml_port < 0) {                      /* port to connect to      */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E command CONNECT received without PORT",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection end     */
     return;
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
                                   &dsl_ag_sess_info,
                                   sizeof(struct dsd_aux_get_session_info) );
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W aux() DEF_AUX_GET_SESSION_INFO returned FALSE",
                   __LINE__ );
     return;
   }
   adsl_server_ineta_w1 = m_get_target_ineta( achl_ineta_start, iml_ineta_len, ied_chs_utf_8,
                                              dsl_ag_sess_info.adsc_bind_out );
   bol_connected = FALSE;                   /* connected to server     */
   al_free_ti1 = adsl_server_ineta_w1;
   if (adsl_server_ineta_w1) goto pne_conn_40;  /* all prepared for connect */
   dsl_aux_tcp_conn_1.iec_tcpconn_ret = ied_tcr_hostname;  /* host-name not in DNS */
   goto p_conn_err_00;                      /* error from connect      */

   pne_conn_00:                             /* send remaining frame    */
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() pne_conn_00 prot=%08X\n",
           __LINE__, *aiml_prot_1 );
   fflush( stdout );
#endif
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) return;   /* no more space in work-area */
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl_work_1;
   /* special cases output to client, while decoding header            */
   if (*aiml_prot_1 == 0X80008000) {        /* RDP-5 first byte length */
     *aiml_prot_1 = 1;                      /* only one byte as data   */
     *achl_work_1++ = 0X03;                 /* fill output             */
   }
   if ((*aiml_prot_1 & 0X80FFFFFF) == 0X80008001) {  /* RDP-5 second byte length */
#ifdef OLD01
     *aiml_prot_1 |= 0X04 << 16;            /* save length             */
     *aiml_prot_1 >>= 16;                   /* make length             */
#endif
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 |= 0X04;                  /* save length             */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
     *aiml_prot_1 -= 3;                     /* set length to follow    */
     *achl_work_1++ = 0X04;                 /* fill output             */
   }
   if (*aiml_prot_1 == 0X80000000) {        /* is at T.123 reserved    */
     (*aiml_prot_1)++;                      /* set T.123 first byte length */
     *achl_work_1++ = 0X00;                 /* fill output             */
   }
   if (*aiml_prot_1 == 0X80000001) {        /* is at T.123 first byte length */
     (*aiml_prot_1)++;                      /* then second byte length */
     *achl_work_1++ = 0X00;                 /* fill output             */
   }
   if ((*aiml_prot_1 & 0X80FFFFFF) == 0X80000002) {  /* is at T.123 second byte length */
#ifdef OLD01
     *aiml_prot_1 |= 0X05 << 16;            /* save length             */
     *aiml_prot_1 >>= 16;                   /* make length             */
#endif
     *aiml_prot_1 >>= 16;                   /* make length             */
     *aiml_prot_1 |= 0X05;                  /* save length             */
     *aiml_prot_1 &= 0X00007FFF;            /* only 15 bit             */
     *aiml_prot_1 -= 4;                     /* set length to follow    */
     *achl_work_1++ = 0X05;                 /* fill output             */
   }
   if (*aiml_prot_1 <= 0) {                 /* not correct value       */
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_rdp1_hlclib01() logic-error output invalid length %08X.",
                   __LINE__, *aiml_prot_1 );
     *aiml_prot_1 = 1;                      /* pseudo-value            */
   }
   /* *aiml_prot_1 is greater zero now                                 */
   /* now zeroes are supplied as frame                                 */
   iml1 = achl_work_2 - achl_work_1;        /* remaining length in work-area */
   if (iml1 > *aiml_prot_1) iml1 = *aiml_prot_1;  /* only as much as requested */
   memset( achl_work_1, 0, iml1 );
   achl_work_1 += iml1;                     /* increment pointer output */
   *aiml_prot_1 -= iml1;                    /* adjust frame length     */
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
   if (adsl_gai1_out_2 == NULL) {
     if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {  /* send to client */
       adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
     } else {                               /* send to server          */
       adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_gai1_out_1;  /* output data to server */
     }
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   if (*aiml_prot_1) {                      /* more data to send       */
     adsp_hl_clib_1->boc_callagain = TRUE;
     return;
   }

   pne_conn_20:                             /* do connect now          */
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() pne_conn_20 do connect now\n",
           __LINE__ );
   fflush( stdout );
#endif
#ifdef TRACEHL1
   m_console_out( adsl_cl1d1_1->chrc_ineta, sizeof(adsl_cl1d1_1->chrc_ineta) );
#endif
// 31.07.10 KB change connect
   /* prepare INETA for connect                                        */
   adsl_server_ineta_w1 = NULL;             /* pass argument           */
   al_free_ti1 = NULL;
   iml_port = 0;                            /* no port yet             */
#define ADSL_SERVER_INETA_G ((struct dsd_target_ineta_1 *) chrl_work1)
   memset( ADSL_SERVER_INETA_G, 0, sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1));
#define ADSL_INETA_SINGLE_1_G ((struct dsd_ineta_single_1 *) (ADSL_SERVER_INETA_G + 1))
   switch ((unsigned char) adsl_cl1d1_1->chrc_ineta[0]) {
     case 1:                                /* IPV4                    */
       ADSL_INETA_SINGLE_1_G->usc_family = AF_INET;  /* family IPV4 / IPV6 */
       ADSL_INETA_SINGLE_1_G->usc_length = 4;  /* length of following address */
       break;
     case 2:                                /* IPV6                    */
       ADSL_INETA_SINGLE_1_G->usc_family = AF_INET6;  /* family IPV4 / IPV6 */
       ADSL_INETA_SINGLE_1_G->usc_length = 16;  /* length of following address */
       break;
   }
   if (ADSL_INETA_SINGLE_1_G->usc_length) {  /* length of following address */
     memcpy( ADSL_INETA_SINGLE_1_G + 1,
             adsl_cl1d1_1->chrc_ineta + 1,
             ADSL_INETA_SINGLE_1_G->usc_length );
     ADSL_SERVER_INETA_G->imc_no_ineta = 1;  /* number of INETA        */
     ADSL_SERVER_INETA_G->imc_len_mem       /* length of memory including this structure */
       = sizeof(struct dsd_target_ineta_1) + sizeof(struct dsd_ineta_single_1)
           + ADSL_INETA_SINGLE_1_G->usc_length;
#define ACHL_PORT_G (adsl_cl1d1_1->chrc_ineta + 1 + ADSL_INETA_SINGLE_1_G->usc_length)
     iml_port = (*((unsigned char *) ACHL_PORT_G + 0) << 8)
                  | *((unsigned char *) ACHL_PORT_G + 1);
#undef ACHL_PORT_G
     adsl_server_ineta_w1 = ADSL_SERVER_INETA_G;  /* pass argument     */
   }
#undef ADSL_INETA_SINGLE_1
   bol_connected = TRUE;                    /* connected to server     */

   pne_conn_40:                             /* all prepared for connect */
   if (bol_connected == FALSE) {            /* check connected to server */
     goto pne_conn_44;                      /* no more connected to server */
   }
   bol1 = m_tcp_close( adsp_hl_clib_1->vpc_userfld );
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() m_tcp_close() returned %d.\n",
           __LINE__, bol1 );
   fflush( stdout );
#endif
// to-do 15.08.10 KB check return
   if (bol1 == FALSE) {                     /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_tcp_close() returned FALSE",
                   __LINE__ );
     return;
   }

   pne_conn_44:                             /* no more connected to server */
#ifndef B131212
   /* ignore output we sent before                                     */
   adsl_gai1_out_2 = NULL;                  /* output data             */
#endif
   if (adsl_server_ineta_w1 == NULL) {      /* do static connect       */
     iml1 = m_tcp_static_conn( adsp_hl_clib_1->vpc_userfld, TRUE );
     achl1 = "m_tcp_static_conn()";
     if (iml1 == 0) {                       /* connect successful      */
       goto pne_conn_48;
     }
     achl2 = achl_work_1;                   /* save address output error */
     achl_work_1 += sprintf( achl_work_1, "error from static connect %d", iml1 ) + 1;
     goto p_conn_err_20;                    /* connect error set       */
   }
   memset( &dsl_aux_tcp_conn_1, 0, sizeof(struct dsd_aux_tcp_conn_1) ); /* TCP Connect to Server */
#ifndef B131212
   if (iml_port == 0) iml_port = 3389;
#endif
   dsl_aux_tcp_conn_1.imc_server_port = iml_port;  /* port of server   */
   bol1 = m_tcp_dynamic_conn( adsp_hl_clib_1->vpc_userfld,
                              &dsl_aux_tcp_conn_1,
                              adsl_server_ineta_w1,
                              al_free_ti1,
                              adsl_cl1d1_1->boc_dynamic );
#ifdef TRACEHL1
   printf( "xsclibrdp1-l%05d-T m_rdp1_hlclib01() m_tcp_dynamic_conn() returned %d iec_tcpconn_ret=%d.\n",
           __LINE__, bol1, dsl_aux_tcp_conn_1.iec_tcpconn_ret );
   fflush( stdout );
#endif
#ifdef B12117
// to-do 15.08.10 KB check return
   if (   (adsl_server_ineta_w1)
       && (adsl_server_ineta_w1 != ADSL_SERVER_INETA_G)) {
     free( adsl_server_ineta_w1 );          /* free memory             */
#ifdef NOT_POSSiBLE_XYZ
     bol2 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsl_server_ineta_w1,
                                     sizeof(struct dsd_clib1_data_1) );
     if (bol2 == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
#endif
   }
#endif
#undef ADSL_SERVER_INETA_G
   if (bol1 == FALSE) {                     /* connect invalid parameters */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-W m_tcp_dynamic_conn() returned FALSE",
                   __LINE__ );
     return;
   }
   achl1 = "m_tcp_dynamic_conn()";
   if (dsl_aux_tcp_conn_1.iec_tcpconn_ret != ied_tcr_ok) {  /* connect successful */
     goto p_conn_err_00;                    /* error from connect      */
   }

   pne_conn_48:                             /* connected was successful */
   /* send to client, that we did connect                              */
   adsl_cl1d1_1->iec_cos = ied_cos_cont;    /* continue                */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* no more space in work-area */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E %s succeeded - no space in work area",
                   __LINE__, achl1 );
     return;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = (char *) ucrs_out_ack_conn;
   adsl_gai1_out_1->achc_ginp_end = (char *) ucrs_out_ack_conn + sizeof(ucrs_out_ack_conn);
   if (adsl_gai1_out_2 == NULL) {
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   return;

   p_conn_err_00:                           /* error from connect      */
// to-do 08.12.10 KB
   switch (dsl_aux_tcp_conn_1.iec_tcpconn_ret) {
     case ied_tcr_invalid:                  /* parameter is invalid    */
       achl2 = "error ied_tcr_invalid - parameter is invalid";
       break;
     case ied_tcr_no_ocos:                  /* option-connect-other-server not configured */
       achl2 = "error ied_tcr_no_ocos - option-connect-other-server not configured";
       break;
     case ied_tcr_no_cs_ssl:                /* no Client-Side SSL configured */
       achl2 = "error ied_tcr_no_cs_ssl - no Client-Side SSL configured";
       break;
     case ied_tcr_denied_tf:                /* access denied because of target-filter */
       achl2 = "error ied_tcr_denied_tf - access denied because of target-filter";
       break;
     case ied_tcr_hostname:                 /* host-name not in DNS    */
       achl2 = "error ied_tcr_hostname - host-name not in DNS";
       break;
     case ied_tcr_no_route:                 /* no route to host        */
       achl2 = "error ied_tcr_no_route - no route to host";
       break;
     case ied_tcr_refused:                  /* connection refused      */
       achl2 = "error ied_tcr_refused - connection refused";
       break;
     case ied_tcr_timeout:                  /* connection timed out    */
       achl2 = "error ied_tcr_timeout - connection timed out";
       break;
     case ied_tcr_error:                    /* other error             */
       achl2 = "error ied_tcr_error - error not specified";
       break;
     default:                               /* error undefined         */
       achl2 = "error undefined";
       break;
   }

   p_conn_err_20:                           /* connect error set       */
   achl_work_2 -= 2 * sizeof(struct dsd_gather_i_1) + 8;
   if (achl_work_2 < achl_work_1) {         /* no more space in work-area */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     m_sdh_printf( &dsl_sdh_call_1, "xsclibrdp1-l%05d-E %s failed - no space in work area",
                   __LINE__, achl1 );
     return;
   }
#define ADSL_GAI1_OUT_G1 ((struct dsd_gather_i_1 *) achl_work_2)
#define ADSL_GAI1_OUT_G2 ((struct dsd_gather_i_1 *) achl_work_2 + 1)
#define ACHL_OUT_G       ((char *) (ADSL_GAI1_OUT_G2 + 1))
   iml1 = strlen( achl2 );
   iml2 = iml1 + 5;
   *(ACHL_OUT_G + 0) = (unsigned char) 0X03;
   *(ACHL_OUT_G + 1) = (unsigned char) 0XFF;
   *(ACHL_OUT_G + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_OUT_G + 3) = (unsigned char) iml2;
   *(ACHL_OUT_G + 4) = (unsigned char) 0X02;
   ADSL_GAI1_OUT_G1->adsc_next = ADSL_GAI1_OUT_G2;
   ADSL_GAI1_OUT_G1->achc_ginp_cur = ACHL_OUT_G;
   ADSL_GAI1_OUT_G1->achc_ginp_end = ACHL_OUT_G + 5;
   ADSL_GAI1_OUT_G2->adsc_next = NULL;
   ADSL_GAI1_OUT_G2->achc_ginp_cur = achl2;
   ADSL_GAI1_OUT_G2->achc_ginp_end = achl2 + iml1;
   if (adsl_gai1_out_2 == NULL) {
     adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_G1;  /* output data to client */
   } else {
     adsl_gai1_out_2->adsc_next = ADSL_GAI1_OUT_G1;
   }
   return;
#undef ADSL_GAI1_OUT_G1
#undef ADSL_GAI1_OUT_G2
#undef ACHL_OUT_G
} /* end m_rdp1_hlclib01()                                             */

/** subroutine for output to console                                   */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achptext, ... ) {
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

#ifdef TRACEHL1
/** subroutine to dump storage-content to console, called from SDH     */
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
     m_sdh_printf( adsp_sdh_call_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_sdh_console_out()                                           */

/** subroutine to dump storage-content to console, called direct       */
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
     printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
   }
   fflush( stdout );
} /* end m_console_out()                                            */
#endif
