//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsrdptracer1                                        |*/
/*| -------------                                                     |*/
/*|  Subroutine for RDP-Accelerator                                   |*/
/*|    prints and interprets data given from calling program          |*/
/*|  KB 01.05.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005                                            |*/
/*|  GCC or other Unix compilers                                      |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
#include <windows.h>
#else
#include "hob-hunix01.h"
#endif
#include "hob-xsclib01.h"
#ifndef B150216
#ifdef HL_RDP_WEBTERM
/* only needed for HOBLink WebTerm RDP */
#include "hob-cd-record-1.h"
#include "hob-encry-1.h"
#include "hob-webterm-rdp-01.h"
#endif
#endif
#ifndef B110502
#include "hob-xsrdpvch1.h"
#endif
#include "hob-rdptracer1.h"

#define HL_WT_DATA_SIZE_1     16            /* size of data when 01 is given */
#define HL_WT_DATA_SIZE_2     64            /* size of data when 10 is given */

static void m_virt_ch_out( struct dsd_wsp_trace_header *, char *, struct dsd_call_rdptrac_1 * );
static void m_se2cl_r5_pdu( struct dsd_wsp_trace_header *, char *, struct dsd_call_rdptrac_1 * );
static void m_dump_gather( char *, struct dsd_call_rdptrac_1 *, struct dsd_gather_i_1 *, int );

/* subroutine to trace the passed data                                 */
extern "C" void m_hlrdptra1e( struct dsd_call_rdptrac_1 *adsp_rdptr1 ) {
// int        inl_no_copy;                  /* copy number of bytes    */
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol1;                         /* working variable        */
   char       *achl1;                       /* working variable        */
   char       *achl_work_1;                 /* position work area, up  */
   char       *achl_work_2;                 /* position work area, dow */
// char       *achl_end;                    /* end of data             */
// char       *achl_replace;                /* pointer to replace data */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header        */
   char       chrl_work1[ 2048 ];           /* work area               */

#ifdef TRACEHL1
   {
     char *achh_text = "invalid function";
     switch (adsp_rdptr1->imc_func) {
       case DEF_IFUNC_START:
         achh_text = "DEF_IFUNC_START";
         break;
       case DEF_IFUNC_CONT:
         achh_text = "DEF_IFUNC_CONT";
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
     }
     printf( "xsrdptracer m_hlrdptra1e() called imc_func=%d %s\n",
             adsp_rdptr1->imc_func, achh_text );
   }
#endif
   if (adsp_rdptr1->imc_func == DEF_IFUNC_START) {
     adsp_rdptr1->imc_func = DEF_IFUNC_CONT;
     return;
   }
   if (adsp_rdptr1->imc_func == DEF_IFUNC_CLOSE) {  /* check normal end */
     adsp_rdptr1->imc_return = DEF_IRET_END;  /* set normal end        */
     return;
   }
   switch (adsp_rdptr1->iec_tr_command) {   /* tracer component command */
     case ied_trc_recv_client:              /* received from client    */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$001", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "record from client length %d/0X%X.",
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_recv_server:              /* received from server    */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$002", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "record from server length %d/0X%X.",
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_virt_ch:                  /* virtual channels        */
       m_virt_ch_out( &dsl_wtrh, chrl_work1, adsp_rdptr1 );  /* output */
       return;
     case ied_trc_cl2se_r5:                 /* client to server RDP 5, decrypted */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$004", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "client to server RDP 5 no-events %d displacement %d/0X%X length %d/0X%X.",
                                          (adsp_rdptr1->imc_prot1 & 0X0F),  /* variable field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_cl2se_decry:              /* client to server, decrypted */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$005", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "client to server decrypted virt-ch %04X displacement %d/0X%X length %d/0X%X.",
                                          adsp_rdptr1->usc_vch_no,  /* virtual channel no com */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_se2cl_decry:              /* server to client, decrypted */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$006", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "server to client decrypted displacement %d/0X%X length %d/0X%X.",
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_se2cl_r5_pdu:             /* server to client, RDP 5 PDU */
       m_se2cl_r5_pdu( &dsl_wtrh, chrl_work1, adsp_rdptr1 );  /* output */
       return;
     case ied_trc_server_cert:              /* server certificate      */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$008", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "server certificate displacement %d/0X%X length %d/0X%X.",
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_se2cl_vch:                /* server to client virtual channel */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$009", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "server to client virtual channel %04X len-total %d/0X%X ch-flags %02X%02X%02X%02X displacement %d/0X%X %c length %d/0X%X.",
                                          adsp_rdptr1->usc_vch_no,  /* virtual channel no com */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[0],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[1],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[2],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[3],  /* virtual channel flags */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->chc_type_disp,  /* type of displacement */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_cl2se_vch:                /* client to server virtual channel */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$010", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "client to server virtual channel %04X len-total %d/0X%X ch-flags %02X%02X%02X%02X displacement %d/0X%X %c length %d/0X%X.",
                                          adsp_rdptr1->usc_vch_no,  /* virtual channel no com */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[0],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[1],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[2],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[3],  /* virtual channel flags */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                          adsp_rdptr1->chc_type_disp,  /* type of displacement */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_se2cl_gen_vch:            /* server to client virtual channel generated */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$011", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "server to client generated virtual channel %04X len-total %d/0X%X ch-flags %02X%02X%02X%02X length %d/0X%X.",
                                          adsp_rdptr1->usc_vch_no,  /* virtual channel no com */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[0],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[1],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[2],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[3],  /* virtual channel flags */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_cl2se_gen_vch:            /* client to server virtual channel generated */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$012", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                          "client to server generated virtual channel %04X len-total %d/0X%X ch-flags %02X%02X%02X%02X length %d/0X%X.",
                                          adsp_rdptr1->usc_vch_no,  /* virtual channel no com */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          adsp_rdptr1->imc_prot1,  /* virtual channel length uncompressed */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[0],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[1],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[2],  /* virtual channel flags */
                                          (unsigned char) adsp_rdptr1->chrc_vch_flags[3],  /* virtual channel flags */
                                          adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                          adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
       if (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_se2cl_msg:                /* server to client message */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$013", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       /* prepare for m_dump_gather()                                  */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = 0;         /* nothing passed yet      */
       if (   (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2))
           && (adsp_rdptr1->imc_len_trace_input > 0)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       ADSL_WTR_G1->achc_content = adsp_rdptr1->achc_trace_input;  /* content passed */
       ADSL_WTR_G1->imc_length = strlen( adsp_rdptr1->achc_trace_input );  /* length of zero-terminated string */
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
     case ied_trc_cl2se_msg:                /* client to server message */
       memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
       memcpy( dsl_wtrh.chrc_wtrt_id, "RATR$014", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
       dsl_wtrh.imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
       dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
       memset( chrl_work1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed          */
       /* prepare for m_dump_gather()                                  */
       ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
       ADSL_WTR_G1->imc_length = 0;         /* nothing passed yet      */
       if (   (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2))
           && (adsp_rdptr1->imc_len_trace_input > 0)) {
         iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_1;        /* size of data when 01 is given */
         } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
           iml1 = HL_WT_DATA_SIZE_2;        /* size of data when 10 is given */
         }
         if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
           iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
         }
         m_dump_gather( chrl_work1,
                        adsp_rdptr1,
                        adsp_rdptr1->adsc_gather_i_1_in,
                        iml1 );
       }
       ADSL_WTR_G1->achc_content = adsp_rdptr1->achc_trace_input;  /* content passed */
       ADSL_WTR_G1->imc_length = strlen( adsp_rdptr1->achc_trace_input );  /* length of zero-terminated string */
       bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                    &dsl_wtrh,
                                                    0 );
#undef ADSL_WTR_G1
       break;
   }
   return;
} /* end m_hlrdptra1e()                                                */

/* virtual channels                                                    */
static void m_virt_ch_out( struct dsd_wsp_trace_header *adsp_wtrh,
                           char *chrp_out,
                           struct dsd_call_rdptrac_1 *adsp_rdptr1 ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */

   iml1 = adsp_rdptr1->imc_len_trace_input;  /* number of virtual channels */
   while (iml1) {                           /* loop over all virtual channels */
#define D_ADSL_VCH (((struct dsd_rdp_vc_1 *) adsp_rdptr1->achc_trace_input) + (adsp_rdptr1->imc_len_trace_input - iml1))
     memset( adsp_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
     memcpy( adsp_wtrh->chrc_wtrt_id, "RATR$003", sizeof(adsp_wtrh->chrc_wtrt_id) );  /* Id of trace record */
     adsp_wtrh->imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrp_out)
     adsp_wtrh->adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
     memset( chrp_out, 0, sizeof(struct dsd_wsp_trace_record) );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrp_out)
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
     ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                        "virtual channel %04X name %.*s flags %08X.",
                                        D_ADSL_VCH->usc_vch_no,  /* virtual channel no com */
                                        (int)sizeof(D_ADSL_VCH->byrc_name),
                                        D_ADSL_VCH->byrc_name,
                                        D_ADSL_VCH->imc_flags );  /* flags */
     bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                  DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                  adsp_wtrh,
                                                  0 );
#undef ADSL_WTR_G1
#undef D_ADSL_VCH
     iml1--;                                /* decrement number entry  */
   }
   return;
} /* end m_virt_ch_out()                                               */

/* server to client RDP 5 PDU                                          */
static void m_se2cl_r5_pdu( struct dsd_wsp_trace_header *adsp_wtrh,
                            char *chrp_out,
                            struct dsd_call_rdptrac_1 *adsp_rdptr1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */

   memset( adsp_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
   memcpy( adsp_wtrh->chrc_wtrt_id, "RATR$007", sizeof(adsp_wtrh->chrc_wtrt_id) );  /* Id of trace record */
   adsp_wtrh->imc_wtrh_sno = adsp_rdptr1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrp_out)
   adsp_wtrh->adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
   memset( chrp_out, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
   ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                      "server to client RDP 5 PDU type %02X displacement %d/0X%X length %d/0X%X.",
                                      (unsigned char) adsp_rdptr1->chc_prot_r5_pdu_type,  /* RDP 5 PDU type */
                                      adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                      adsp_rdptr1->imc_disp_field,  /* displacement of field */
                                      adsp_rdptr1->imc_len_trace_input,  /* length trace-input */
                                      adsp_rdptr1->imc_len_trace_input );  /* length trace-input */
   if (   (adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2))
       && (adsp_rdptr1->imc_len_trace_input > 0)) {
     iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
     if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA1) {  /* shorted data */
       iml1 = HL_WT_DATA_SIZE_1;            /* size of data when 01 is given */
     } else if ((adsp_rdptr1->adsc_hl_clib_1->imc_trace_level & (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == HL_AUX_WT_DATA2) {  /* shorted data */
       iml1 = HL_WT_DATA_SIZE_2;            /* size of data when 10 is given */
     }
     if (iml1 > adsp_rdptr1->imc_len_trace_input) {  /* length of data to dump */
       iml1 = adsp_rdptr1->imc_len_trace_input;  /* length of data to dump */
     }
     m_dump_gather( chrp_out,
                    adsp_rdptr1,
                    adsp_rdptr1->adsc_gather_i_1_in,
                    iml1 );
   }
   bol1 = adsp_rdptr1->adsc_hl_clib_1->amc_aux( adsp_rdptr1->adsc_hl_clib_1->vpc_userfld,  /* User Field Subroutine */
                                                DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                                adsp_wtrh,
                                                0 );
#undef ADSL_WTR_G1
} /* end m_se2cl_r5_pdu()                                              */

static void m_dump_gather( char *chrp_out,
                           struct dsd_call_rdptrac_1 *adsp_rdptr1,
                           struct dsd_gather_i_1 *adsp_gather_i_1_in,  /* input data */
                           int imp_len_trace_input ) {  /* length trace-input */
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1;                     /* working variables       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

   adsl_gai1_w1 = adsp_gather_i_1_in;
   if (adsl_gai1_w1 == NULL) return;
   iml1 = imp_len_trace_input;              /* get length input        */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrp_out)
   achl_w1 = (char *) ((long long int) (ADSL_WTR_G1->achc_content + ADSL_WTR_G1->imc_length + sizeof(void *) - 1)
                         & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
   adsl_wtr_w1 = NULL;                      /* WSP trace record      */
   do {                                     /* loop over all gather input */
     iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml2 > 0) {                        /* data in this gather     */
       memset( achl_w1, 0, sizeof(struct dsd_wsp_trace_record) );
       ADSL_WTR_G2->achc_content = adsl_gai1_w1->achc_ginp_cur;
       if (iml2 > iml1) iml2 = iml1;
       ADSL_WTR_G2->imc_length = iml2;
       ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
       if (adsl_wtr_w1 == NULL) {
         ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
       } else {
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;
         adsl_wtr_w1->boc_more = TRUE;      /* more data to follow     */
       }
       iml1 -= iml2;
       if (iml1 <= 0) return;
       adsl_wtr_w1 = ADSL_WTR_G2;
       achl_w1 += sizeof(struct dsd_wsp_trace_record);
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather in chain */
   } while (adsl_gai1_w1);
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
} /* end m_dump_gather()                                               */
