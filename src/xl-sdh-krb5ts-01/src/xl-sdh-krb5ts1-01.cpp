#define NEW_WSP_1102
//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-sdh-krb5ts1-01                                   |*/
/*| -------------                                                     |*/
/*|  DLL / Library for WebSecureProxy                                 |*/
/*|  Kerberos 5 / Heimdal Functions                                   |*/
/*|  implements Service Ticket functions                              |*/
/*|  KB 30.09.09                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC                                                 |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */
/**
   what can be configured:
   <trace-krb5-api>YES/NO
   <trace-network>YES/NO
*/

#define HL_ERROR_CODE_FUNCTION_FAILED 64

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
    #include <conio.h>
    #include <windows.h>
#else
    #include <hob-unix01.h>
    #include <stdarg.h>
#endif
#include <time.h>
#include <hob-xslunic1.h>
//MJ #include <hob-tab-ascii-ansi-1.h>

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#include <xercesc/dom/DOMAttr.hpp>

#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
//#define DEF_HL_INCL_INET
#include "hob-xsclib01.h"

static const char * m_get_rc_aux_krb5( enum ied_ret_krb5_def );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *, int );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

struct dsd_clib1_conf {                     /* configured values       */
   BOOL       boc_trace_krb5_api;           /* <trace-krb5-api>        */
   BOOL       boc_trace_network;            /* <trace-network>         */
};

struct dsd_clib1_contr_1 {                  /* structure session control */
   void *     vpc_krb5_handle;              /* Kerberos handle         */
   char       *achc_trace_inp;              /* trace input so far      */
};

static const char * achrs_node_conf_1[] = {
   "trace-krb5-api",
   "trace-network"
};

#define DEF_XML_TRACE_KRB5_API         0    /* <trace-krb5-api>        */
#define DEF_XML_TRACE_NETWORK          1    /* <trace-network>         */
#define DEF_XML_MAX                    2    /* number of entries       */

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/* subroutine to process the configuration data                        */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol1, bol2;                   /* working variables       */
   int        iml1, iml2;                   /* working variables       */
   int        iml_cmp;                      /* compare values          */
#ifdef XYZ1
   int        iml_val;                      /* value in array          */
   int        iml_count_mapte_def;          /* count map target entry definitions */
   BOOL       bol_cont_cl_ineta_set_1;      /* contains client INETA set over all */
   BOOL       bol_cont_cl_ineta_set_2;      /* contains client INETA set map target entry */
   UNSIG_MED  uml_mask_and_1_w1;            /* mask for AND            */
   UNSIG_MED  uml_mask_and_2_w1;            /* mask for AND            */
   UNSIG_MED  uml_mask_and_1_w2;            /* mask for AND            */
// UNSIG_MED  uml_mask_and_2_w2;            /* mask for AND            */
// UNSIG_MED  uml_ineta_w1;                 /* working-variable INETA  */
   UNSIG_MED  *auml_w1;                     /* working-variable        */
   char       *achl_stor_new;               /* new storage             */
   char       *achl_stor_old;               /* old storage             */
#endif
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
#ifdef XYZ1
   DOMNode    *adsl_node_3;                 /* node for navigation     */
   HL_WCHAR   *awcl1;                       /* working variable        */
#endif
   HL_WCHAR   *awcl_value;                  /* value of Node           */
#ifdef XYZ1
   struct dsd_map_target_entry_1 *adsl_mapte_1_w1;  /* structure map target entry */
#endif
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
#ifdef XYZ1
   struct dsd_map_target_entry_1 dsl_mapte_1;  /* structure map target entry */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */
#endif
// new 18.09.10 KB
   HL_WCHAR   *awcl_name;                   /* name of Node            */
   BOOL       borl_double[ DEF_XML_MAX ];   /* number of entries       */
   struct dsd_clib1_conf dsl_clib1_conf;    /* configured values       */

   dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-T m_hlclib_conf() called adsp_hlcldomf=%p.",
                 __LINE__, adsp_hlcldomf );
#endif
   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return FALSE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }
   memset( &dsl_clib1_conf, 0, sizeof(struct dsd_clib1_conf) );  /* configured values */
   memset( borl_double, 0, sizeof(borl_double) );  /* clear indicator double */

   pdomc20:                                 /* process DOM node        */
#ifdef KB_ORG
   iml1 = (int) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type );
#else
   size_t uiml_temp = (size_t) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type );
   iml1 = (int) uiml_temp;
#endif
   if (iml1 != DOMNode::ELEMENT_NODE) {
     goto pdomc80;                          /* get next sibling        */
   }
   awcl_name = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-T m_hlclib_conf() found Node \"%(ux)s\"",
                 __LINE__, awcl_name );
#endif
   iml1 = 0;                                /* clear index             */
   while (TRUE) {                           /* loop over all defined keywords */
     bol1 = m_cmp_vx_vx( &iml_cmp,
                         awcl_name, -1, ied_chs_utf_16,
                         (void *) achrs_node_conf_1[ iml1 ], -1, ied_chs_utf_8 );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       break;
     }
     iml1++;                                /* increment index         */
     if (iml1 >= (sizeof(achrs_node_conf_1) / sizeof(achrs_node_conf_1[0]))) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W m_hlclib_conf() found undefined Node \"%(ux)s\" - ignored",
                     __LINE__, awcl_name );
       goto pdomc80;                        /* get next sibling        */
     }
   }
   if (borl_double[ iml1 ]) {               /* check indicator double */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W Error Node \"%(ux)s\" defined double - ignored",
                   __LINE__, awcl_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W Error Node \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
#ifdef KB_ORG
     iml2 = (int) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type );
#else
     size_t uiml_temp2 = (size_t) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type );
     iml2 = (int) uiml_temp2;
#endif
     if (iml2 == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W Error Node \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl_name );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   do {                                     /* pseudo-loop             */
     bol1 = m_cmp_vx_vx( &iml_cmp,
                         awcl_value, -1, ied_chs_utf_16,
                         (void*)"YES", -1, ied_chs_utf_8 );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       bol2 = TRUE;                         /* set YES                 */
       break;
     }
     bol1 = m_cmp_vx_vx( &iml_cmp,
                         awcl_value, -1, ied_chs_utf_16,
                         (void*)"NO", -1, ied_chs_utf_8 );
     if ((bol1) && (iml_cmp == 0)) {        /* strings are equal       */
       bol2 = FALSE;                        /* set NO                  */
       break;
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-W Error Node \"%(ux)s\" value \"%(ux)s\" neither YES nor NO - ignored",
                   __LINE__, awcl_name, awcl_value );
     goto pdomc80;                          /* DOM node processed - next */
   } while (FALSE);
   switch (iml1) {                          /* on keyword found        */
     case DEF_XML_TRACE_KRB5_API:           /* <trace-krb5-api>        */
       dsl_clib1_conf.boc_trace_krb5_api = bol2;  /* <trace-krb5-api>  */
       borl_double[ DEF_XML_TRACE_KRB5_API ] = TRUE;  /* set indicator double */
       break;
     case DEF_XML_TRACE_NETWORK:            /* <trace-network>         */
       dsl_clib1_conf.boc_trace_network = bol2;  /* <trace-network>    */
       borl_double[ DEF_XML_TRACE_NETWORK ] = TRUE;  /* set indicator double */
       break;
   }

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */

   /* search if any value set                                          */
   iml1 = sizeof(struct dsd_clib1_conf);    /* length configured values */
   do {
     iml1--;                                /* decrement index         */
     if (*((char *) &dsl_clib1_conf + iml1) != 0) break;
   } while (iml1 > 0);
   if (iml1 == 0) {                         /* nothing configured      */
     return TRUE;                           /* we do not need any configuration */
   }
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  adsp_hlcldomf->aac_conf,
                                  sizeof(struct dsd_clib1_conf) );
   if (bol1 == FALSE) {                     /* error occured           */
     return FALSE;
   }
   memcpy( *adsp_hlcldomf->aac_conf,
           &dsl_clib1_conf,
           sizeof(struct dsd_clib1_conf) );
   return TRUE;                             /* all done                */
} /* end m_hlclib_conf()                                               */

/* subroutine to process the copy library function                     */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
#ifdef XYZ1
   int        inl_no_copy;                  /* copy number of bytes    */
#endif
   int        iml1, iml2;                   /* working variables       */
   int        iml_len_p;                    /* length of packet        */
   int        iml_rem;                      /* remaining part in last packet */
   int        iml_len_hostname;             /* length hostname         */
   signed char chl1;                        /* working variable        */
   BOOL       bol1;                         /* working variable        */
#ifdef TRACEHL1
// char       chl1;                         /* working variable        */
#endif
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   const char *achl4;                       /* working variables       */
   char       *achl_out;                    /* output, send to client  */
   char       *achl_fill_cur;               /* current position to fill */
   char       *achl_fill_end;               /* end position to fill    */
   char       *achl_work_1;
   char       *achl_work_2;
   char       *achl_end;                    /* end of data             */
   char       *achl_replace;                /* pointer to replace data */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 **aadsl_gai1_w1;   /* pointer to output data  */
   union {
     struct dsd_aux_get_krb5_entry dsl_agke;  /* retrieve configured Kerberos 5 KDC */
     struct dsd_aux_krb5_sign_on_1 dsl_akso1;  /* Kerberos 5 Sign On   */
//--
     struct dsd_aux_krb5_se_ti_get_1 dsl_akstg1;  /* Kerberos get Service Ticket */
     struct dsd_aux_krb5_se_ti_c_r_1 dsl_akstc1;  /* Kerberos check Service Ticket Response */
     struct dsd_aux_krb5_decrypt dsl_akdec1;  /* Kerberos decrypt data */
     struct dsd_aux_krb5_se_ti_rel_1 dsl_akstr1;  /* Kerberos release Service Ticket Resources */
   };
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_gather_i_1 dsl_gai1_l1;       /* local gather            */
   char       chrl_work1[ 512 ];            /* work area               */

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
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T m_hlclib01() called inc_func=%d %s input=%p len=%d pieces=%d cont=0X%02X.",
                   __LINE__,
                   adsp_hl_clib_1->inc_func, achh_text,
                   adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
   }
#endif
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* connection should be ended */
         return;
       }
       memset( adsp_hl_clib_1->ac_ext, 0, sizeof(struct dsd_clib1_contr_1) );
       return;
     case DEF_IFUNC_CLOSE:
       adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
       if (adsl_contr_1->vpc_krb5_handle) {  /* Kerberos handle set    */
         memset( &dsl_akstr1, 0, sizeof(struct dsd_aux_krb5_se_ti_rel_1) );  /* Kerberos release Service Ticket Resources */
         dsl_akstr1.vpc_handle = adsl_contr_1->vpc_krb5_handle;
         if (   (adsp_hl_clib_1->ac_conf)
             && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_SE_TI_REL parameter area",
                         __LINE__ );
           m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akstr1, sizeof(struct dsd_aux_krb5_se_ti_rel_1) );
         }
         bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                         DEF_AUX_KRB5_SE_TI_REL,  /* Kerberos release Service Ticket Resources */
                                         &dsl_akstr1,
                                         sizeof(struct dsd_aux_krb5_se_ti_rel_1) );
       }
       bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &adsp_hl_clib_1->ac_ext,
                                       sizeof(struct dsd_clib1_contr_1) );
       if (bol1 == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       }
       return;
#ifdef XYZ1
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
       return;
#endif
   }
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_REFLECT) return;
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   achl_work_1 = adsp_hl_clib_1->achc_work_area;  /* addr work-area    */
   achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   if (adsl_gai1_inp_1 == NULL) return;
   if (adsp_hl_clib_1->ac_conf == NULL) goto p_recv_40;
   if (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_network == FALSE) goto p_recv_40;  /* <trace-network> */
   adsl_gai1_inp_2 = adsl_gai1_inp_1;       /* dump all input          */
   if (adsl_contr_1->achc_trace_inp == NULL) {  /* trace input so far  */
     goto p_recv_20;                        /* trace data set          */
   }
   adsl_gai1_w1 = adsl_gai1_inp_2;          /* get input to dump       */
   do {
     if (   (adsl_contr_1->achc_trace_inp >= adsl_gai1_w1->achc_ginp_cur)
         && (adsl_contr_1->achc_trace_inp <= adsl_gai1_w1->achc_ginp_end)) {
       break;
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (adsl_gai1_w1 == NULL) {
     goto p_recv_20;                        /* trace data set          */
   }
   if (adsl_contr_1->achc_trace_inp == adsl_gai1_w1->achc_ginp_end) {
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   while (   (adsl_gai1_w1)
          && (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end)) {
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_w1 == NULL) {
     goto p_recv_20;                        /* trace data set          */
   }
   dsl_gai1_l1.adsc_next = adsl_gai1_w1->adsc_next;  /* pass next in chain */
   dsl_gai1_l1.achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
   dsl_gai1_l1.achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
   if (   (adsl_contr_1->achc_trace_inp >= adsl_gai1_w1->achc_ginp_cur)
       && (adsl_contr_1->achc_trace_inp <= adsl_gai1_w1->achc_ginp_end)) {
     dsl_gai1_l1.achc_ginp_cur = adsl_contr_1->achc_trace_inp;
   }
   adsl_gai1_inp_2 = &dsl_gai1_l1;          /* pass new gather         */

   p_recv_20:                               /* trace data set          */
   adsl_gai1_w1 = adsl_gai1_inp_2;          /* get input to dump       */
   iml1 = 0;                                /* clear length            */
   do {
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_contr_1->achc_trace_inp = adsl_gai1_w1->achc_ginp_end;  /* save the end */
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T input data received length=%d/0X%X.",
                 __LINE__, iml1, iml1 );
   m_dump_gather( &dsl_sdh_call_1, adsl_gai1_inp_2, iml1 );

   p_recv_40:                               /* data received           */
   /* check if input packet complete                                   */
   achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data       */
   iml_len_p = 0;                           /* clear length of packet  */
   iml1 = 4;
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
       if (adsl_gai1_inp_1 == NULL) return;  /* frame not complete     */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     chl1 = *achl1++;                       /* get new byte            */
     iml_len_p <<= 7;                       /* shift old length of packet */
     iml_len_p |= chl1 & 0X7F;              /* apply new bit to length of packet */
     if (chl1 >= 0) break;                  /* no more bit set         */
     iml1--;                                /* decrement control length of NHASN */
     if (iml1 <= 0) {                       /* too many digits         */
// to-do 30.09.09 KB error-message, abend
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E length received packet NHASN too many digits",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code      */
       return;
     }
   }
   if (iml_len_p < 2) {                     /* check length of packet  */
// to-do 30.09.09 KB error-message, abend
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E length received packet too short",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   iml_rem = iml_len_p;                     /* get length of packet    */
   adsl_gai1_inp_2 = adsl_gai1_inp_1;       /* get gather input        */
   achl2 = achl1;                           /* get pointer input       */
   while (TRUE) {
     iml_rem -= adsl_gai1_inp_2->achc_ginp_end - achl2;  /* get bytes in this gather */
     if (iml_rem <= 0) break;               /* frame is complete       */
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next input gather in chain */
     if (adsl_gai1_inp_2 == NULL) return;   /* frame not complete      */
     achl2 = adsl_gai1_inp_2->achc_ginp_cur;  /* get start of data     */
   }
   /* frame is complete                                                */
   while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
     adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
     if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
     achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data     */
   }
   chl1 = *achl1++;                         /* get function            */
   iml_len_p--;                             /* decrement length of packet */
   switch (chl1) {                          /* check function          */
     case '0':                              /* get service ticket      */
       goto p_servti_00;                    /* process service ticket  */
     case '1':                              /* check service ticket response */
       goto p_reseti_00;                    /* process response service ticket */
     case '3':                              /* Kerberos decrypt data   */
       goto p_decrypt_00;                   /* process Kerberos decrypt data */
   }
// to-do 30.09.09 KB invalid function, error-message, abend
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E received function 0X%02X - invalid",
                 __LINE__, (unsigned char) chl1 );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;

   p_servti_00:                             /* process service ticket  */
   if (adsl_contr_1->vpc_krb5_handle) {     /* Kerberos handle already set */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 function 0 and Kerberos handle already set",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   memset( &dsl_akstg1, 0, sizeof(struct dsd_aux_krb5_se_ti_get_1) );  /* clear Kerberos get Service Ticket */
   /* first get options NHASN                                          */
// dsl_akstg1.imc_options = 0;              /* clear options           */
   iml1 = 4;                                /* set maximum length NHASN */
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
       adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
       if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml_len_p--;                           /* decrement length of packet */
     chl1 = *achl1++;                       /* get new byte            */
     dsl_akstg1.imc_options <<= 7;          /* shift old options       */
     dsl_akstg1.imc_options |= chl1 & 0X7F;  /* apply new bits to options */
     if (chl1 >= 0) break;                  /* no more bit set         */
     iml1--;                                /* decrement control length of NHASN */
     if (iml1 <= 0) {                       /* too many digits         */
// to-do 30.09.09 KB error-message, abend
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 options NHASN too many digits",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code      */
       return;
     }
     if (iml_len_p <= 0) {                  /* check length of packet  */
// to-do 30.09.09 KB error-message, abend
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 options not format NHASN",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code      */
       return;
     }
   }
   if (iml_len_p <= 0) {                    /* check length of packet  */
// to-do 30.09.09 KB error-message, abend
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 after options no hostname",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
     adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
     if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
     achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data     */
   }
// dsl_akstg1.dsc_server_name.imc_len_str = iml_len_p;  /* length string in elements */
   iml_len_hostname = iml_len_p;            /* save length hostname    */
   dsl_akstg1.dsc_server_name.iec_chs_str = ied_chs_utf_8;  /* character set string */
   dsl_akstg1.dsc_server_name.ac_str = achl1;  /* address of string */
   if ((achl1 + iml_len_p) <= adsl_gai1_inp_1->achc_ginp_end) {  /* check if we can use in one chunk */
     goto p_servti_20;                      /* hostname set            */
   }
   if (iml_len_p > sizeof(chrl_work1)) {    /* length of hostname too long */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 length hostname too high %d.",
                   __LINE__, iml_len_p );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
// to-do 30.09.09 KB error-message, abend
   }
   dsl_akstg1.dsc_server_name.ac_str = chrl_work1;  /* address of string */
   achl3 = chrl_work1;                      /* target of copy hostname */
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
       adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
       if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml1 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* length in this gather */
     if (iml1 > iml_len_p) iml1 = iml_len_p;  /* only this part        */
     memcpy( achl3, achl1, iml1 );          /* copy this part          */
     achl3 += iml1;                         /* add length to target    */
     achl1 += iml1;                         /* add length to source    */
     iml_len_p -= iml1;                     /* subtract length from length of packet */
     if (iml_len_p <= 0) break;             /* all copied              */
   }

   p_servti_20:                             /* hostname set            */
   adsl_gai1_inp_1->achc_ginp_cur = achl1 + iml_len_p;  /* gather has been processed */
   if (adsl_gai1_inp_1->achc_ginp_cur == adsl_contr_1->achc_trace_inp) {
     adsl_contr_1->achc_trace_inp = NULL;
   }
   achl1 = (char *) memchr( dsl_akstg1.dsc_server_name.ac_str,
                            '@',
                            iml_len_hostname );
   if (achl1 == NULL) {                     /* no realm found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_00 no realm in request from client",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
// to-do 30.09.09 KB error-message, abend
   }
   dsl_akstg1.dsc_server_name.imc_len_str
     = (int)(achl1 - (char*)dsl_akstg1.dsc_server_name.ac_str);  /* length string in elements */
   achl1 = achl_work_1 + 12;                /* space for response      */
   if ((achl1 + MAX_KRB5_SE_TI) > achl_work_2) {  /* not enough space in work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   dsl_akstg1.achc_ticket_buffer = achl1;   /* address buffer for service ticket */
   dsl_akstg1.imc_ticket_buffer_len = MAX_KRB5_SE_TI;  /* maximum length Kerberos 5 Service Ticket */
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_SE_TI_GET parameter area",
                   __LINE__ );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akstg1, sizeof(struct dsd_aux_krb5_se_ti_get_1) );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_SE_TI_GET server-name len=%d/0X%X.",
                   __LINE__,
                   dsl_akstg1.dsc_server_name.imc_len_str,
                   dsl_akstg1.dsc_server_name.imc_len_str );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) dsl_akstg1.dsc_server_name.ac_str, dsl_akstg1.dsc_server_name.imc_len_str );
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_KRB5_SE_TI_GET,  /* Kerberos get Service Ticket */
                                   &dsl_akstg1,
                                   sizeof(struct dsd_aux_krb5_se_ti_get_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_servti_20 aux DEF_AUX_KRB5_SE_TI_GET returned %d.",
                 __LINE__, bol1 );
#endif
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     achl4 = m_get_rc_aux_krb5( dsl_akdec1.iec_ret_krb5 );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T return DEF_AUX_KRB5_SE_TI_GET rc1=%d rc2=%d %s handle=%p ticket-length=%d/0X%X.",
                   __LINE__, bol1, dsl_akstg1.iec_ret_krb5, achl4, dsl_akstg1.vpc_handle, dsl_akstg1.imc_ticket_length, dsl_akstg1.imc_ticket_length );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akstg1, sizeof(struct dsd_aux_krb5_se_ti_get_1) );
     if (dsl_akstg1.imc_ticket_length > 0) {  /* returned length of ticket */
       m_sdh_console_out( &dsl_sdh_call_1, achl1, dsl_akstg1.imc_ticket_length );
     }
   }
   adsl_contr_1->vpc_krb5_handle = dsl_akstg1.vpc_handle;  /* Kerberos handle */
   achl_work_1 = achl1 + dsl_akstg1.imc_ticket_length;  /* length of returned service ticket */
   /* output return code                                               */
   iml1 = dsl_akstg1.iec_ret_krb5;          /* return from Kerberos    */
   if (bol1 == FALSE) iml1 = HL_ERROR_CODE_FUNCTION_FAILED;
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   *(--achl1) = '0';                        /* set function            */
   iml1 = achl_work_1 - achl1;              /* length of data          */
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* work area too small     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_servti_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;                                /* return of SDH           */
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   if (adsp_hl_clib_1->ac_conf == NULL) return;
   if (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_network == FALSE) return;  /* <trace-network> */
   iml1 = achl_work_1 - achl1;              /* length sent             */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_servti_20 send response DEF_AUX_KRB5_SE_TI_GET length=%d/0X%X.",
                 __LINE__, iml1, iml1 );
   m_sdh_console_out( &dsl_sdh_call_1, achl1, iml1 );
   return;

   p_reseti_00:                             /* process response service ticket */
   if (adsl_contr_1->vpc_krb5_handle == NULL) {  /* Kerberos handle not set */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_reseti_00 function 1 and Kerberos handle not set",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   memset( &dsl_akstc1, 0, sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );  /* clear Kerberos check Service Ticket Response */
   dsl_akstc1.achc_response_buffer = achl1;  /* address buffer of response */
   dsl_akstc1.imc_response_length = iml_len_p;  /* length of response  */
   if ((achl1 + iml_len_p) <= adsl_gai1_inp_1->achc_ginp_end) {  /* check if we can use in one chunk */
     goto p_reseti_20;                      /* response service ticket set */
   }
   if (iml_len_p > sizeof(chrl_work1)) {    /* length of response service ticket too long */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_reseti_00 length response service ticket too high %d.",
                   __LINE__, iml_len_p );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
// to-do 30.09.09 KB error-message, abend
   }
   dsl_akstc1.achc_response_buffer = chrl_work1;  /* address buffer of response */
   achl3 = chrl_work1;                      /* target of copy response service ticket */
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
       adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
       if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml1 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* length in this gather */
     if (iml1 > iml_len_p) iml1 = iml_len_p;  /* only this part        */
     memcpy( achl3, achl1, iml1 );          /* copy this part          */
     achl3 += iml1;                         /* add length to target    */
     achl1 += iml1;                         /* add length to source    */
     iml_len_p -= iml1;                     /* subtract length from length of packet */
     if (iml_len_p <= 0) break;             /* all copied              */
   }

   p_reseti_20:                             /* response service ticket set */
   adsl_gai1_inp_1->achc_ginp_cur = achl1 + iml_len_p;  /* gather has been processed */
   if (adsl_gai1_inp_1->achc_ginp_cur == adsl_contr_1->achc_trace_inp) {
     adsl_contr_1->achc_trace_inp = NULL;
   }
   dsl_akstc1.vpc_handle = adsl_contr_1->vpc_krb5_handle;
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_SE_TI_C_R parameter area",
                   __LINE__ );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akstc1, sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_SE_TI_C_R response-ticket len=%d/0X%X.",
                   __LINE__, dsl_akstc1.imc_response_length, dsl_akstc1.imc_response_length );
     m_sdh_console_out( &dsl_sdh_call_1, dsl_akstc1.achc_response_buffer, dsl_akstc1.imc_response_length );
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_KRB5_SE_TI_C_R,  /* Kerberos check Service Ticket Response */
                                   &dsl_akstc1,
                                   sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_reseti_20 aux DEF_AUX_KRB5_SE_TI_C_R returned %d.",
                 __LINE__, bol1 );
#endif
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     achl4 = m_get_rc_aux_krb5( dsl_akstc1.iec_ret_krb5 );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T return DEF_AUX_KRB5_SE_TI_C_R rc1=%d rc2=%d %s parameter area",
                   __LINE__, bol1, dsl_akstc1.iec_ret_krb5, achl4 );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akstc1, sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );
   }
   achl1 = achl_work_1 + 12;                /* space for response      */
   if (achl1 > achl_work_2) {               /* not enough space in work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_reseti_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   achl_work_1 = achl1;                     /* end of output           */
   /* output return code                                               */
   iml1 = dsl_akstc1.iec_ret_krb5;          /* return from Kerberos    */
   if (bol1 == FALSE) iml1 = HL_ERROR_CODE_FUNCTION_FAILED;
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   *(--achl1) = '1';                        /* set function            */
   iml1 = achl_work_1 - achl1;              /* length of data          */
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* work area too small     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_reseti_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;                                /* return of SDH           */
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   if (adsp_hl_clib_1->ac_conf == NULL) return;
   if (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_network == FALSE) return;  /* <trace-network> */
   iml1 = achl_work_1 - achl1;              /* length sent             */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_reseti_20 send response DEF_AUX_KRB5_SE_TI_C_R length=%d/0X%X.",
                 __LINE__, iml1, iml1 );
   m_sdh_console_out( &dsl_sdh_call_1, achl1, iml1 );
   return;

   p_decrypt_00:                            /* process Kerberos decrypt data */
   if (adsl_contr_1->vpc_krb5_handle == NULL) {  /* Kerberos handle not set */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_decrypt_00 function 3 and Kerberos handle not set",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   memset( &dsl_akdec1, 0, sizeof(struct dsd_aux_krb5_decrypt) );  /* clear Kerberos decrypt data */
   dsl_akdec1.achc_inp_enc_data = achl1;    /* input encrypted data    */
   dsl_akdec1.imc_len_inp_enc_data = iml_len_p;  /* length input encrypted data */
   if ((achl1 + iml_len_p) <= adsl_gai1_inp_1->achc_ginp_end) {  /* check if we can use in one chunk */
     goto p_decrypt_20;                     /* encrypted data set      */
   }
   if (iml_len_p > sizeof(chrl_work1)) {    /* length of response service ticket too long */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_decrypt_00 length encrypted data too high %d.",
                   __LINE__, iml_len_p );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
// to-do 30.09.09 KB error-message, abend
   }
   dsl_akdec1.achc_inp_enc_data = chrl_work1;  /* input encrypted data */
   achl3 = chrl_work1;                      /* target of copy response service ticket */
   while (TRUE) {
     while (achl1 >= adsl_gai1_inp_1->achc_ginp_end) {  /* check if more data */
       adsl_gai1_inp_1->achc_ginp_cur = achl1;  /* gather has been processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next input gather in chain */
       if (adsl_gai1_inp_1 == NULL) goto p_illogic_00;  /* frame not complete */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* get start of data   */
     }
     iml1 = adsl_gai1_inp_1->achc_ginp_end - achl1;  /* length in this gather */
     if (iml1 > iml_len_p) iml1 = iml_len_p;  /* only this part        */
     memcpy( achl3, achl1, iml1 );          /* copy this part          */
     achl3 += iml1;                         /* add length to target    */
     achl1 += iml1;                         /* add length to source    */
     iml_len_p -= iml1;                     /* subtract length from length of packet */
     if (iml_len_p <= 0) break;             /* all copied              */
   }

   p_decrypt_20:                            /* encrypted data set      */
   adsl_gai1_inp_1->achc_ginp_cur = achl1 + iml_len_p;  /* gather has been processed */
   if (adsl_gai1_inp_1->achc_ginp_cur == adsl_contr_1->achc_trace_inp) {
     adsl_contr_1->achc_trace_inp = NULL;
   }
   achl1 = achl_work_1 + 12;                /* space for response      */
   iml1 = dsl_akdec1.imc_len_inp_enc_data + 32;  /* space needed for decrypted data */
   if ((achl1 + iml1) > achl_work_2) {      /* not enough space in work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_decrypt_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;
   }
   dsl_akdec1.achc_out_dec_buffer = achl1;  /* output buffer for decrypted data */
   dsl_akdec1.imc_dec_buffer_len = iml1;    /* length output buffer for decrypted data */
   dsl_akdec1.vpc_handle = adsl_contr_1->vpc_krb5_handle;
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_DECRYPT parameter area",
                   __LINE__ );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akdec1, sizeof(struct dsd_aux_krb5_decrypt) );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T call DEF_AUX_KRB5_DECRYPT enc_data len=%d/0X%X.",
                   __LINE__,
                   dsl_akdec1.imc_len_inp_enc_data,
                   dsl_akdec1.imc_len_inp_enc_data );
     m_sdh_console_out( &dsl_sdh_call_1, dsl_akdec1.achc_inp_enc_data, dsl_akdec1.imc_len_inp_enc_data );
   }
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_KRB5_DECRYPT,  /* Kerberos decrypt data */
                                   &dsl_akdec1,
                                   sizeof(dsd_aux_krb5_decrypt) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_decrypt_20 aux DEF_AUX_KRB5_DECRYPT returned %d.",
                 __LINE__, bol1 );
#endif
   if (   (adsp_hl_clib_1->ac_conf)
       && (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_krb5_api)) {  /* <trace-krb5-api> */
     achl4 = m_get_rc_aux_krb5( dsl_akdec1.iec_ret_krb5 );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T return DEF_AUX_KRB5_DECRYPT rc1=%d rc2=%d %s parameter area",
                   __LINE__, bol1, dsl_akdec1.iec_ret_krb5, achl4 );
     m_sdh_console_out( &dsl_sdh_call_1, (char *) &dsl_akdec1, sizeof(struct dsd_aux_krb5_decrypt) );
     if (dsl_akdec1.imc_dec_len_ret) {      /* returned length of decrypted data */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T return DEF_AUX_KRB5_DECRYPT dec_buffer len=%d/0X%X.",
                     __LINE__,
                     dsl_akdec1.imc_dec_buffer_len,
                     dsl_akdec1.imc_dec_buffer_len );
       m_sdh_console_out( &dsl_sdh_call_1, dsl_akdec1.achc_out_dec_buffer, dsl_akdec1.imc_dec_len_ret );
     }
   }
   achl_work_1 = achl1 + dsl_akdec1.imc_dec_len_ret;  /* end of output */
   /* output return code                                               */
   iml1 = dsl_akdec1.iec_ret_krb5;          /* return from Kerberos    */
   if (bol1 == FALSE) iml1 = HL_ERROR_CODE_FUNCTION_FAILED;
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   *(--achl1) = '3';                        /* set function            */
   iml1 = achl_work_1 - achl1;              /* length of data          */
   iml2 = 0;                                /* clear more bit          */
   while (TRUE) {
     *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* remove these bits       */
     if (iml1 == 0) break;                  /* all done                */
     iml2 = 0X80;                           /* set more bit            */
   }
   achl_work_2 -= sizeof(struct dsd_gather_i_1);
   if (achl_work_2 < achl_work_1) {         /* work area too small     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_decrypt_20 work area too small",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code        */
     return;                                /* return of SDH           */
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) achl_work_2;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   adsl_gai1_out_1->achc_ginp_end = achl_work_1;
   if (adsl_gai1_out_2 == NULL) {
#ifndef NEW_WSP_1102
     adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_1;
#else
     adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_1;  /* output data to client */
#endif
   } else {
     adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   }
   adsl_gai1_out_2 = adsl_gai1_out_1;
   if (adsp_hl_clib_1->ac_conf == NULL) return;
   if (((struct dsd_clib1_conf *) adsp_hl_clib_1->ac_conf)->boc_trace_network == FALSE) return;  /* <trace-network> */
   iml1 = achl_work_1 - achl1;              /* length sent             */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-T p_decrypt_20 send response DEF_AUX_KRB5_DECRYPT length=%d/0X%X.",
                 __LINE__, iml1, iml1 );
   m_sdh_console_out( &dsl_sdh_call_1, achl1, iml1 );
   return;

   p_illogic_00:                            /* program illogic         */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-krb5ts1-01-l%05d-E p_illogic_00",
                 __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* return code          */
   return;
} /* end m_hlclib01()                                                  */

static const char * m_get_rc_aux_krb5( enum ied_ret_krb5_def iep_ret_krb5 ) {
   const char     *achl_ret;                /* string returned         */

   achl_ret = "*unknown*";
   switch (iep_ret_krb5) {
     case ied_ret_krb5_ok:                  /* success                 */
       achl_ret = "ied_ret_krb5_ok";
       break;
     case ied_ret_krb5_kdc_not_conf:        /* KDC not configured      */
       achl_ret = "ied_ret_krb5_kdc_not_conf";
       break;
     case ied_ret_krb5_kdc_not_sel:         /* KDC not selected        */
       achl_ret = "ied_ret_krb5_kdc_not_sel";
       break;
     case ied_ret_krb5_no_sign_on:          /* session not signed on   */
       achl_ret = "ied_ret_krb5_no_sign_on";
       break;
     case ied_ret_krb5_kdc_inv:             /* KDC invalid             */
       achl_ret = "ied_ret_krb5_kdc_inv";
       break;
     case ied_ret_krb5_userid_unknown:      /* Userid unknown          */
       achl_ret = "ied_ret_krb5_userid_unknown";
       break;
     case ied_ret_krb5_password:            /* password invalid        */
       achl_ret = "ied_ret_krb5_password";
       break;
     case ied_ret_krb5_no_tgt:              /* TGT not found           */
       achl_ret = "ied_ret_krb5_no_tgt";
       break;
     case ied_ret_krb5_buf_too_sm:          /* buffer size is too small */
       achl_ret = "ied_ret_krb5_buf_too_sm";
       break;
     case ied_ret_krb5_misc:                /* miscellaneous error     */
       achl_ret = "ied_ret_krb5_misc";
       break;
   }
   return achl_ret;
} /* end m_get_rc_aux_krb5()                                           */

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
