//#define TRACEHL1
//#define TRACEHL_091208_01
//#define TRACEHL_091210_01
//#define TRACEHL_091210_02
//#define TEST_090927_02                      /* smaller window          */
//#define DEBUG_120209_01                     /* mark inc / dec          */
#define VALID_REQ_ID  /* to-do 14.11.07 KB */
#define MAX_FILE_LEN (16 * 1024 * 1024)
#ifndef TEST_090927_02
#define MAX_VC_WINDOW (64 * 1024)
#else
#define MAX_VC_WINDOW 256
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsrdpvch1                                           |*/
/*| -------------                                                     |*/
/*|  Subroutine for RDP-Accelerator                                   |*/
/*|    handles virtual channels                                       |*/
/*|  KB 28.10.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*| The RDP-ACC Server-Data-Hook needs configuration data,            |*/
/*| these are defined in the WSP XML file as <configuration-section>. |*/
/*| parameters can only be specified in <connection>:                 |*/
/*| The following keywords are defined:                               |*/
/*| <disable-MS-clipboard>                                            |*/
/*| <disable-MS-local-drive-mapping>                                  |*/
/*| <disable-HOB-local-drive-mapping>                                 |*/
/*| <ldm-virus-checking-service>  name of the service                 |*/
/*| <ldm-virus-checking-maximum-file-size>  example: 16 MB            |*/
/*| <encryption-to-client>  automatic/low/medium/high                 |*/
/*| <compression-to-server>  automatic/NO/YES                         |*/
/*| <trace-level>                                                     |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/**
 * disable-HOB-local-drive-mapping
 * the flag
 * in HSUBCHN zero
 * start request from client to server
 * ??? from server to client ???
 * see document SOFTWARE.HLJWT.HENHTS01
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
#include <windows.h>
#else
#include "hob-unix01.h"
#include <stdarg.h> //DD20150127
#include <stdint.h> //DD20150127
#endif
#include <hob-xslunic1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#ifdef B131029
#include <HLTABAW2.h>
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#ifdef B101209
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

#include <xercesc/dom/DOMAttr.hpp>

#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

#endif
#ifdef OLD01
#ifndef HL_UNIX
#include "IBIPGW08-X1.hpp"
#else
#include "NBIPGW08-X1.hpp"
#endif
#endif
//#include <fstream.h>
#ifndef NO_TRY_080726
#include <xercesc/util/XMLString.hpp>
XERCES_CPP_NAMESPACE_USE
#endif

/**
 * from PChannel.h
*/

/****************************************************************************/
/* Maximum amount of data that is sent in one operation.  Data larger than  */
/* this is segmented into chunks of this size and sent as multiple          */
/* operations.                                                              */
/****************************************************************************/
#define CHANNEL_CHUNK_LENGTH    1600

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#include "hob-stor-sdh.h"
#include "hob-xsrdpvch1.h"

/*+-------------------------------------------------------------------+*/
/*| Precompiler constants.                                            |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

//#define D_HOBLDM_LEN_READ      512
#define D_HOBLDM_LEN_READ      1024

#define RDPDR_CTYP_CORE        0X4472
#define PAKID_CORE_SERVER_CAPABILITY 0X5350
#define PAKID_CORE_DEVICELIST_ANNOUNCE 0X4441
#define PAKID_CORE_DEVICE_REPLY 0X6472
#define CAP_DRIVE_TYPE         0X0004
#define RDPDR_DTYP_FILESYSTEM  0X00000008

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static void m_copy_tose_save( struct dsd_rdp_param_vch_1 *,
                              struct dsd_pch_save_1 **,  /* save data from virtual channel */
                              char *, int );
static char * m_edit_dec_long( char *, HL_LONGLONG );
static int m_sdh_printf( struct dsd_sdh_call_1 *, char *, ... );
static int m_get_date_time( char *achp_buff );
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *achp_buff, int implength );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

struct dsd_rdpvch1_contr {                  /* main structure virus checking */
   struct dsd_rdpvch1_file *adsc_rdpvch1_file;  /* chain of open files */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1_frse;  /* RDP virtual channel from server */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1_tose;  /* RDP virtual channel to server */
   void *     vpc_sequ_handle;              /* handle of service query */
};

enum ied_file_status_def {                  /* file status             */
   ied_fist_send_open,                      /* send open command       */
   ied_fist_wait_repl_open,                 /* wait for reply for open */
   ied_fist_read_file,                      /* read next part of file  */
   ied_fist_wait_repl_read,                 /* wait for reply for read */
   ied_fist_wait_window,                    /* wait for window to be extended */
   ied_fist_wait_vircheck,                  /* wait for virus checking */
#ifdef XYZ1
// to-do 18.09.09 KB - is normal reply? if yes, send now to server and do cleanup
// open_ok not needed
   ied_fist_return_open_ok,                 /* return open o.k.        */
#endif
   ied_fist_return_open_error,              /* return open error       */
   ied_fist_return_oe_and_close,            /* return open error and close file */
   ied_fist_client_send_close,              /* send close to client    */
   ied_fist_client_wait_close               /* wait for response close from client */
};

enum ied_rtose_def {                        /* received to server status */
   ied_rtose_subchn,                        /* receive HSUBCHN         */
   ied_rtose_req_id,                        /* receive request id      */
   ied_rtose_ret_code,                      /* receive return code     */
   ied_rtose_op_handle,                     /* receive open handle     */
   ied_rtose_op_info_1,                     /* information from file open */
   ied_rtose_op_chl_file_folder,            /* flag file / folder      */
   ied_rtose_op_len_name,                   /* length of name          */
   ied_rtose_op_ret_name,                   /* return name             */
   ied_rtose_read_length,                   /* receive length read     */
   ied_rtose_wait_repl_open,                /* wait for reply for open to-do invalid */
   ied_rtose_cch_nhasn_len,                 /* control packet length NHASN */
   ied_rtose_cch_record                     /* control packet record   */
};

struct dsd_rdpvch1_file {                   /* structure virus checking one file */
   struct dsd_rdpvch1_file *adsc_next;      /* for chaining            */
   ied_file_status_def iec_fist;            /* file status             */
   unsigned char chc_subchn;                /* sub-channel no          */
   unsigned char chc_flag_full_path;        /* flag full path file-name */
   unsigned char chc_open_error;            /* return open error to server */
   unsigned char chc_file_folder;           /* is not normal file      */
   unsigned int umc_ldm_handle;             /* handle of file          */
   unsigned int umc_ldm_req_id;             /* request id              */
   unsigned int umc_ldm_access_mask;        /* access mask             */
   unsigned int umc_ldm_create_disposition;  /* create disposition     */
   unsigned int umc_ldm_ret_code;           /* return error from client */
   BOOL       boc_more_cl2se;               /* more bit client to server in datastream */
   BOOL       boc_more_se2cl;               /* more bit server to client in datastream */
   char       *achc_ret_name;               /* name returned           */
   char       *achc_ret_error;              /* error returned to server */
   int        imc_len_name;                 /* length of name in bytes */
   int        imc_ret_len_name;             /* returned length of name in bytes */
   int        imc_len_error;                /* length return error     */
   HL_LONGLONG ilc_read_disp;               /* disposition read file   */
   struct dsd_se_vch_contr_1 dsc_sevchcontr1;  /* service virus checking control area */
   char       chrc_open_info_1[ 58 ];       /* information from file open */
};

struct dsd_pch_save_1 {                     /* save data from virtual channel */
   struct dsd_pch_save_1 *adsc_next;        /* next in chain           */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
   char       *achc_filled;                 /* filled so far           */
   struct dsd_pch_save_2 *adsc_pchs2;       /* send Server Device Announce Response */
#ifndef B100201
   unsigned int umc_vch_ulen;               /* length of total chain   */
#endif
   BOOL       boc_sent;                     /* data have been sent     */
   char       chc_segfl;                    /* segmentation flag       */
};

/* for Server Device Announce Response                                 */
struct dsd_pch_save_2 {                     /* save data from virtual channel */
   struct dsd_pch_save_2 *adsc_next;        /* next in chain           */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
   char       *achc_filled;                 /* filled so far           */
   char       *achc_removed;                /* removed from packet     */
};

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const char * achrs_node_conf[] = {
   "disable-MS-clipboard",
   "disable-MS-local-drive-mapping",
   "disable-HOB-local-drive-mapping",
   "ldm-virus-checking-service",
   "ldm-virus-checking-maximum-file-size",
   "encryption-to-client",
   "compression-to-server",
   "trace-level"
};

static const char * achrs_node_enc2cl[] = {
   "automatic",
   "low",
   "medium",
   "high"
};

static const char * achrs_node_comp2se[] = {
   "automatic",
   "NO",
   "YES"
};

static const unsigned char usrs_command_open_vch[] = { 0X50, 0X00, 0X00, 0X00 };
static const unsigned char usrs_command_open_normal[] = { 0X00, 0X00, 0X00, 0X00 };
static const unsigned char usrc_vch_segfl[] = { 0X03, 0X00 };  /* virtual channel segmentation flags */

#ifdef B091221
static const unsigned char usrs_ms_serv_cap_01[] = {
   (unsigned char) RDPDR_CTYP_CORE, (unsigned char) (RDPDR_CTYP_CORE >> 8),  /* 72 44 */
   (unsigned char) PAKID_CORE_SERVER_CAPABILITY, (unsigned char) (PAKID_CORE_SERVER_CAPABILITY >> 8),  /* 50 53 */
};
#endif

static const unsigned char usrs_ms_cli_anno_01[] = {
   (unsigned char) RDPDR_CTYP_CORE, (unsigned char) (RDPDR_CTYP_CORE >> 8),  /* 72 44 */
   (unsigned char) PAKID_CORE_DEVICELIST_ANNOUNCE, (unsigned char) (PAKID_CORE_DEVICELIST_ANNOUNCE >> 8)  /* 41 44 */
};

static const unsigned char usrs_ms_serv_dev_repl_01[] = {
   (unsigned char) RDPDR_CTYP_CORE, (unsigned char) (RDPDR_CTYP_CORE >> 8),  /* 72 44 */
   (unsigned char) PAKID_CORE_DEVICE_REPLY, (unsigned char) (PAKID_CORE_DEVICE_REPLY >> 8),  /* 72 64 */
   0, 0, 0, 0,                              /* DeviceId                */
   0, 0, 0, 0                               /* ResultCode              */
};

static const unsigned char ucrs_found_virus_00[] = {
   'f', 'i', 'l', 'e', ' ', 'c', 'o', 'n',
   't', 'a', 'i', 'n', 's', ' ', 'V', 'i',
   'r', 'u', 's', ' '
};

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*+-------------------------------------------------------------------+*/
/*| Procedure section.                                                |*/
/*+-------------------------------------------------------------------+*/

/** subroutine to process the configuration data                       */


extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol1, bol2;                   /* working variables       */
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* compare values          */
   int        iml_enc2cl;                   /* encryption-to-client    */
   int        iml_comp2se;                  /* compression-to-server   */
   BOOL       bol_disa_ms_clipb;            /* disable MS clipboard    */
   BOOL       bol_disa_ms_ldm;              /* disable MS local-drive-mapping */
   BOOL       bol_disa_hob_ldm;             /* disable HOB local-drive-mapping */
   HL_WCHAR   *awcl_ldm_vch_serv;           /* ldm virus-checking service name */
   HL_LONGLONG ill_ldm_max_file_size;       /* maximum file-size virus-checking */
   int        iml_trace_level;              /* configured trace level  */
   BOOL       borl_double[3];               /* check if defined double */
   int        iml_val;                      /* value in array          */
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
   HL_WCHAR   *awcl1;                       /* working variable        */
   HL_WCHAR   *awcl_value;                  /* value of Node           */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

#ifdef TRACEHL1
   printf( "xsrdpvch1-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p\n",
           __LINE__, adsp_hlcldomf );
#endif
   dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-I V1.2 " __DATE__ " m_hlclib_conf() called",
                 __LINE__ );

   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return FALSE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }

   bol_disa_ms_clipb = FALSE;               /* reset disable MS clipboard */
   bol_disa_ms_ldm = FALSE;                 /* reset disable MS local-drive-mapping */
   bol_disa_hob_ldm = FALSE;                /* reset disable HOB local-drive-mapping */
   awcl_ldm_vch_serv = NULL;                /* reset ldm virus-checking service name */
   ill_ldm_max_file_size = 0;               /* reset maximum file-size virus-checking */
   iml_enc2cl = -1;                         /* reset encryption-to-client */
   iml_comp2se = -1;                        /* reset compression-to-server */
   iml_trace_level = -1;                    /* reset configured trace level */
   memset( borl_double, 0, sizeof(borl_double) );  /* reset check if defined double */

   pdomc20:                                 /* process DOM node        */
#ifndef HL_LINUX
   if (((long long int) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
#else
   if (((uintptr_t) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
#endif
     goto pdomc80;                          /* get next sibling        */
   }
   awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
   printf( "xsrdpvch1-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl1 );
#endif
   iml_val = sizeof(achrs_node_conf) / sizeof(achrs_node_conf[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl1, (char *) achrs_node_conf[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
#ifndef HL_LINUX
     if (((long long int) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
#else
     if (((uintptr_t) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
#endif
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   bol1 = TRUE;                             /* value not double        */
   switch (iml_val) {                       /* depending on keyword found */
     case 1:                                /* <disable-MS-clipboard>  */
       if (borl_double[0]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         bol_disa_ms_clipb = TRUE;          /* set disable MS clipboard */
         borl_double[0] = TRUE;             /* set check if defined double */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         borl_double[0] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case 2:                                /* <disable-MS-local-drive-mapping> */
       if (borl_double[1]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         bol_disa_ms_ldm = TRUE;            /* set disable MS local-drive-mapping */
         borl_double[1] = TRUE;             /* set check if defined double */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         borl_double[1] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case 3:                                /* <disable-HOB-local-drive-mapping> */
       if (borl_double[2]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         bol_disa_hob_ldm = TRUE;           /* set disable HOB local-drive-mapping */
         borl_double[2] = TRUE;             /* set check if defined double */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         borl_double[2] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case 4:                                /* <ldm-virus-checking-service> */
       if (awcl_ldm_vch_serv) {             /* check ldm virus-checking service name */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       awcl_ldm_vch_serv = awcl_value;      /* set ldm virus-checking service name */
       break;
     case 5:                                /* <ldm-virus-checking-maximum-file-size> */
       if (ill_ldm_max_file_size) {         /* check maximum file-size virus-checking */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       ill_ldm_max_file_size = m_get_bytes_no( awcl_value );
       if (ill_ldm_max_file_size > 0) break;  /* value is valid        */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value not valid size in bytes - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       ill_ldm_max_file_size = 0;           /* value not set           */
       break;
     case 6:                                /* <encryption-to-client>  */
       if (iml_enc2cl >= 0) {               /* check encryption-to-client */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       iml_val = sizeof(achrs_node_enc2cl) / sizeof(achrs_node_enc2cl[0]);
       do {
         bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, (char *) achrs_node_enc2cl[ iml_val - 1 ] );
         if ((bol2) && (iml_cmp == 0)) break;  /* strings are equal    */
         iml_val--;                         /* decrement index         */
       } while (iml_val > 0);
       if (iml_val == 0) {                  /* parameter not found     */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" not defined - ignored",
                       __LINE__, awcl1, awcl_value );
         break;
       }
       iml_enc2cl = iml_val - 1;            /* set encryption-to-client */
       break;
     case 7:                                /* <compression-to-server> */
       if (iml_comp2se >= 0) {              /* check compression-to-server */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       iml_val = sizeof(achrs_node_comp2se) / sizeof(achrs_node_comp2se[0]);
       do {
         bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, (char *) achrs_node_comp2se[ iml_val - 1 ] );
         if ((bol2) && (iml_cmp == 0)) break;  /* strings are equal    */
         iml_val--;                         /* decrement index         */
       } while (iml_val > 0);
       if (iml_val == 0) {                  /* parameter not found     */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" not defined - ignored",
                       __LINE__, awcl1, awcl_value );
         break;
       }
       iml_comp2se = iml_val - 1;           /* set compression-to-server */
       break;
     case 8:                                /* <trace-level>           */
       if (iml_trace_level >= 0) {          /* check trace-level       */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       iml_val = m_get_wc_number( awcl_value );
       if (iml_val < 0) {                   /* is not numeric          */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" not numeric - ignored",
                       __LINE__, awcl1, awcl_value );
         break;
       }
       iml_trace_level = iml_val;           /* configured trace level  */
       break;
   }
   if (bol1 == FALSE) {                     /* value is double         */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" already defined before - ignored",
                   __LINE__, awcl1, awcl_value );
   }

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */
   iml1 = 0;                                /* clear size in bytes     */
   while (awcl_ldm_vch_serv) {              /* ldm virus-checking service name */
     if (bol_disa_hob_ldm) {                /* disable HOB local-drive-mapping */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W \"disable-HOB-local-drive-mapping\" set but also \"ldm-virus-checking-service\" - Virus-Checking not activated",
                     __LINE__ );
       break;
     }
     iml1 = m_len_vx_vx( ied_chs_utf_8,
                         awcl_ldm_vch_serv, -1, ied_chs_utf_16 );
     break;
   }
   if ((ill_ldm_max_file_size) && (iml1 == 0)) {  /* maximum file-size virus-checking */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W \"ldm-virus-checking-maximum-file-size\" set but no \"ldm-virus-checking-service\" - ignored",
                   __LINE__ );
     ill_ldm_max_file_size = 0;             /* clear maximum file-size virus-checking */
   }
   bol1 = adsp_hlcldomf->amc_aux( adsp_hlcldomf->vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  adsp_hlcldomf->aac_conf,
                                  sizeof(struct dsd_rdpvch1_config) + iml1 );
   if (bol1 == FALSE) {
     return FALSE;
   }
#define ADSL_RDPVCH1_CONFIG ((struct dsd_rdpvch1_config *) *adsp_hlcldomf->aac_conf)
   if (iml_trace_level < 0) iml_trace_level = 0;  /* set no trace      */
   ADSL_RDPVCH1_CONFIG->imc_trace_level = iml_trace_level;  /* configured trace level */
   if (iml_enc2cl < 0) iml_enc2cl = 0;      /* set automatic           */
   ADSL_RDPVCH1_CONFIG->imc_enc2cl = iml_enc2cl;  /* encryption-to-client */
   if (iml_comp2se < 0) iml_comp2se = 0;    /* set automatic           */
   ADSL_RDPVCH1_CONFIG->imc_comp2se = iml_comp2se;  /* compression-to-server */
   ADSL_RDPVCH1_CONFIG->boc_disa_ms_clipb = bol_disa_ms_clipb;  /* disable MS clipboard */
   ADSL_RDPVCH1_CONFIG->boc_disa_ms_ldm = bol_disa_ms_ldm;  /* disable MS local-drive-mapping */
   ADSL_RDPVCH1_CONFIG->boc_disa_hob_ldm = bol_disa_hob_ldm;  /* disable HOB local-drive-mapping */
   ADSL_RDPVCH1_CONFIG->imc_len_ldm_vch_serv = iml1;  /* length ldm virus-checking service name */
   ADSL_RDPVCH1_CONFIG->ilc_ldm_max_file_size = ill_ldm_max_file_size;  /* maximum file-size virus-checking */
   if (iml1) {                              /* set ldm virus-checking service name */
     m_cpy_vx_vx( ADSL_RDPVCH1_CONFIG + 1, iml1, ied_chs_utf_8,
                  awcl_ldm_vch_serv, -1, ied_chs_utf_16 );
   }
   return TRUE;
#undef ADSL_RDPVCH1_CONFIG
} /* end m_hlclib_conf()                                               */

extern "C" BOOL m_rdp_vch1_init( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query     */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_init( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
   if (adsp_p1->adsc_conf->imc_trace_level > 0) {  /* configured trace level */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_init()",
                   __LINE__ );
   }
   if (adsp_p1->adsc_conf->imc_len_ldm_vch_serv == 0) {  /* length ldm virus-checking service name */
     return TRUE;                           /* virus-checking not configured */
   }
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_open;  /* service open connection */
   dsl_aux_sequ1.ac_service_name = adsp_p1->adsc_conf + 1;
   dsl_aux_sequ1.imc_len_service_name = adsp_p1->adsc_conf->imc_len_ldm_vch_serv;
   dsl_aux_sequ1.iec_chs_service_name = ied_chs_utf_8;
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                DEF_AUX_SERVICE_REQUEST,  /* service request */
                                                &dsl_aux_sequ1,
                                                sizeof(struct dsd_aux_service_query_1) );
   if (bol1 == FALSE) return FALSE;
   if (dsl_aux_sequ1.iec_ret_service != ied_ret_service_ok) {  /* check service return code */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E Virus Checker Service %.*(u8)s could not be started",
                   __LINE__, adsp_p1->adsc_conf->imc_len_ldm_vch_serv, adsp_p1->adsc_conf + 1 );
     return FALSE;
   }
   adsp_p1->dsc_s1.ac_vir_ch_1 = m_aux_stor_alloc( adsp_p1->adsc_stor_sdh_1,
                                                   sizeof(struct dsd_rdpvch1_contr) );
   memset( adsp_p1->dsc_s1.ac_vir_ch_1, 0, sizeof(struct dsd_rdpvch1_contr) );
   ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->vpc_sequ_handle
     = dsl_aux_sequ1.vpc_sequ_handle;       /* handle of service query */
   return TRUE;
} /* end m_rdp_vch1_init()                                             */

extern "C" ied_sdh_ret1 m_rdp_vch1_rec_frse( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
// struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* gather data from channel */
// int        imc_len_vch_input;            /* length of data from channel */
   BOOL       bol_copy;                     /* do copy data            */
   BOOL       bol_virus_scan;               /* do virus checking       */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_out_1;                  /* output pointer          */
   struct dsd_gather_i_1 *adsl_gather_i_1_w1;  /* gather data from channel */
   int        iml_len_r;                    /* remaining length        */
   int        iml_pos;                      /* position input          */
   int        iml_len_d, iml_len_f;         /* length of input         */
   int        iml_cap_type;                 /* capability type         */
   int        iml_cap_no_1;                 /* number of capabilities 1 */
   int        iml_cap_no_2;                 /* number of capabilities 2 */
   int        iml_remove_cap_no;            /* remove number of capabilities */
   int        iml_remove_len;               /* remove from this packet */
   unsigned char ucl_subchn;                /* sub-channel no          */
   unsigned int uml_ldm_handle;             /* handle of file          */
   unsigned int uml_ldm_req_id;             /* request id              */
   unsigned int uml_ldm_command;            /* command                 */
   unsigned int uml_ldm_access_mask;        /* access mask             */
   unsigned int uml_ldm_create_disposition;  /* create disposition     */
   unsigned char chl_flag_full_path;        /* flag full path file-name */
   unsigned int uml_len_name;               /* length of name          */
   int        iml_len_name;                 /* length of name          */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w1;  /* structure of file */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   char       chrl_work1[ 256 ];            /* workarea                */

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_frse( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
#ifdef B091208
#ifndef TRACEHL_091208_01
   if (adsp_p1->ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
   /* save virtual channel structure                                   */
   ((struct dsd_rdpvch1_contr *) adsp_p1->ac_vir_ch_1)->adsc_rdp_vc_1_frse
     = adsp_p1->adsc_rdp_vc_1;
#endif
#endif
#ifndef B091221
   if ((adsp_p1->adsc_rdp_vc_1->chc_hob_vch & 0XF0) != 0X30) {  /* virtual channel HOB special */
     return ied_sdhr1_ok;                   /* send packet unchanged   */
   }
#endif
   /* check if only in chain - segmented                               */
   if (*((unsigned short int *) adsp_p1->chrc_vch_segfl)
         != (*((unsigned short int *) usrc_vch_segfl))) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel segmentation invalid",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
   adsl_gather_i_1_w1 = adsp_p1->adsc_gather_i_1_in;
   iml_len_r = adsp_p1->imc_len_vch_input;
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_frse() request length=%d/0X%08X.",
                 __LINE__, iml_len_r, iml_len_r );
   m_dump_gather( &dsl_sdh_call_1, adsl_gather_i_1_w1, iml_len_r );
#endif
#ifdef TRACEHL_091208_01
   if (adsp_p1->adsc_rdp_vc_1->chc_hob_vch == 'd') {  /* virtual channel HOB special */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T received from virtual channel \'d\'.",
                   __LINE__ );
//   return ied_sdhr1_ok;  /* not configured */
   }
#endif
#ifdef B091221
   if ((adsp_p1->adsc_rdp_vc_1->chc_hob_vch & 0XF0) != 0X30) {  /* virtual channel HOB special */
     goto p_rdpdr_00;                       /* is not HOB channel      */
   }
#endif
#ifdef B100209
   if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
#else
   if (   (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL)  /* not configured     */
       && (adsp_p1->adsc_conf->imc_trace_level <= 0)) {  /* configured trace level */
     return ied_sdhr1_ok;
   }
#endif
   /* save virtual channel structure                                   */
#ifdef B131101
   ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_frse
     = adsp_p1->adsc_rdp_vc_1;
#else
   if (adsp_p1->dsc_s1.ac_vir_ch_1) {
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_frse
       = adsp_p1->adsc_rdp_vc_1;
   }
#endif
   bol_virus_scan = FALSE;                  /* no virus checking       */
   iml_pos = 0;
   achl2 = (char *) &ucl_subchn;
   achl3 = (char *) &ucl_subchn + sizeof(ucl_subchn);
   bol_copy = TRUE;                         /* do copy data            */

   p_scan_00:                               /* scan input              */
   if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_ok;
   achl1 = adsl_gather_i_1_w1->achc_ginp_cur;

   p_scan_04:                               /* scan input              */
   if (iml_len_r <= 0) return ied_sdhr1_ok;
   iml_len_d = adsl_gather_i_1_w1->achc_ginp_end - achl1;
   if (iml_len_d <= 0) {                    /* no more data            */
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     goto p_scan_00;                        /* scan input              */
   }
   iml_len_f = achl3 - achl2;
   if (iml_len_f > iml_len_d) iml_len_f = iml_len_d;
   if (iml_len_f > iml_len_r) iml_len_f = iml_len_r;
   if (bol_copy) {                          /* do copy data            */
     memcpy( achl2, achl1, iml_len_f );
   }
   achl2 += iml_len_f;
   achl1 += iml_len_f;
   iml_len_r -= iml_len_f;
   if (achl2 < achl3) goto p_scan_04;       /* needs more data         */
   iml_pos++;                               /* next field              */
   switch (iml_pos) {                       /* depending on field      */
     case 1:                                /* end of HSUBCHN          */
       if (   (ucl_subchn == 0)             /* control channel         */
           || ((ucl_subchn & 0X40) != 0)) {  /* is not local drive mapping */
         return ied_sdhr1_ok;
       }
       if (ucl_subchn & 0X80) {             /* with more flag          */
         goto p_more_00;                    /* check more flag         */
       }
       achl2 = (char *) &uml_ldm_handle;
       achl3 = (char *) &uml_ldm_handle + sizeof(uml_ldm_handle);
       goto p_scan_04;                      /* scan input              */
     case 2:                                /* end of handle           */
       achl2 = (char *) &uml_ldm_req_id;
       achl3 = (char *) &uml_ldm_req_id + sizeof(uml_ldm_req_id);
       goto p_scan_04;                      /* scan input              */
     case 3:                                /* end of request id       */
       achl2 = (char *) &uml_ldm_command;
       achl3 = (char *) &uml_ldm_command + sizeof(uml_ldm_command);
       goto p_scan_04;                      /* scan input              */
     case 4:                                /* end of command          */
#ifdef B100209
       if (uml_ldm_command != *((unsigned int *) usrs_command_open_vch)) {
         return ied_sdhr1_ok;
       }
#else
       if (uml_ldm_command == *((unsigned int *) usrs_command_open_vch)) {
         bol_virus_scan = TRUE;             /* do virus checking       */
       } else if (uml_ldm_command == *((unsigned int *) usrs_command_open_normal)) {
         if (adsp_p1->adsc_conf->imc_trace_level < 2) {  /* configured trace level */
           goto p_more_00;                  /* check more flag         */
         }
       } else {
         goto p_more_00;                    /* check more flag         */
       }
#endif
       achl2 = NULL;
//     achl3 = achl2 + 45 - (1 + 4 + 4 + 4);
       achl3 = achl2 + 4;
       bol_copy = FALSE;                    /* do not copy data        */
       goto p_scan_04;                      /* scan input              */
     case 5:
       achl2 = (char *) &uml_ldm_access_mask;
       achl3 = (char *) &uml_ldm_access_mask + sizeof(uml_ldm_access_mask);
       bol_copy = TRUE;                     /* do copy data            */
       goto p_scan_04;                      /* scan input              */
     case 6:                                /* end of access mask      */
       achl2 = NULL;
       achl3 = achl2 + 16;
       bol_copy = FALSE;                    /* do not copy data        */
       goto p_scan_04;                      /* scan input              */
     case 7:
       achl2 = (char *) &uml_ldm_create_disposition;
       achl3 = (char *) &uml_ldm_create_disposition + sizeof(uml_ldm_create_disposition);
       bol_copy = TRUE;                     /* do copy data            */
       goto p_scan_04;                      /* scan input              */
     case 8:                                /* end of create disposition */
       achl2 = NULL;
       achl3 = achl2 + 4;
       bol_copy = FALSE;                    /* do not copy data        */
       goto p_scan_04;                      /* scan input              */
     case 9:
       achl2 = (char *) &uml_len_name;
       achl3 = (char *) &uml_len_name + sizeof(uml_len_name);
       bol_copy = TRUE;                     /* do copy data            */
       goto p_scan_04;                      /* scan input              */
     case 10:                               /* end of length name      */
       achl2 = (char *) &chl_flag_full_path;
       achl3 = (char *) &chl_flag_full_path + sizeof(chl_flag_full_path);
       goto p_scan_04;                      /* scan input              */
     case 11:                               /* get file-name           */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_frse() request 0X50 get file-name",
                     __LINE__ );
#endif
       iml_len_name = *((unsigned char *) &uml_len_name + 0)
                      | (*((unsigned char *) &uml_len_name + 1) << 8)
                      | (*((unsigned char *) &uml_len_name + 2) << 16)
                      | (*((unsigned char *) &uml_len_name + 3) << 24);
       /* check if length file-name valid                              */
       if (   (iml_len_name > 0X400)
           || (iml_len_name == 0)
           || (iml_len_name > iml_len_r)) {
         dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel invalid length file-name %d.",
                       __LINE__, iml_len_name );
         return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
       }
       adsl_rdpvch1_file_w1 = (struct dsd_rdpvch1_file *) m_aux_stor_alloc(
                                 adsp_p1->adsc_stor_sdh_1,
                                 sizeof(struct dsd_rdpvch1_file) + iml_len_name );
       adsl_rdpvch1_file_w1->imc_len_name = iml_len_name;
       adsl_rdpvch1_file_w1->achc_ret_name = NULL;
       adsl_rdpvch1_file_w1->imc_len_error = 0;
       adsl_rdpvch1_file_w1->achc_ret_error = NULL;
       adsl_rdpvch1_file_w1->umc_ldm_ret_code = 0;  /* no error till now */
       adsl_rdpvch1_file_w1->ilc_read_disp = 0;  /* clear disposition read file */
       adsl_rdpvch1_file_w1->boc_more_cl2se = FALSE;  /* more bit client to server in datastream */
       adsl_rdpvch1_file_w1->boc_more_se2cl = FALSE;  /* more bit server to client in datastream */
       memset( &adsl_rdpvch1_file_w1->dsc_sevchcontr1, 0, sizeof(struct dsd_se_vch_contr_1) );
       adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_max_diff_window = MAX_VC_WINDOW;  /* maximum difference window */
       achl2 = (char *) (adsl_rdpvch1_file_w1 + 1);
       achl3 = (char *) (adsl_rdpvch1_file_w1 + 1) + iml_len_name;
       goto p_scan_04;                      /* scan input              */
   }
   if (adsp_p1->adsc_conf->imc_trace_level > 0) {  /* configured trace level */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     achl1 = "with Virus-Checking";
     if (bol_virus_scan == FALSE) {         /* no virus checking       */
       achl1 = "normal";
     }
     iml1 = iml_len_name;
     /* remove zero-terminated at the end of the file-name             */
     if (   (*((char *) (adsl_rdpvch1_file_w1 + 1) + iml_len_name - 1) == 0)
         && (*((char *) (adsl_rdpvch1_file_w1 + 1) + iml_len_name - 2) == 0)) {
       iml1 -= 2;
     }
     iml2 = m_cpy_vx_vx( chrl_work1, sizeof(chrl_work1), ied_chs_utf_8,
                         adsl_rdpvch1_file_w1 + 1, iml1 >> 1, ied_chs_le_utf_16 );
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T open from server %s file %.*(u8)s.",
                   __LINE__, achl1, iml2, chrl_work1 );
   }
   if (   (bol_virus_scan == FALSE)         /* no virus checking       */
       || (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL)) {  /* not configured  */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1 );  /* free memory request */
     return ied_sdhr1_ok;
   }
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_send_open;  /* send open command */
   adsl_rdpvch1_file_w1->chc_subchn = ucl_subchn;  /* sub-channel no   */
   adsl_rdpvch1_file_w1->umc_ldm_handle = uml_ldm_handle;  /* handle of file */
   adsl_rdpvch1_file_w1->umc_ldm_req_id = uml_ldm_req_id;  /* request id */
   adsl_rdpvch1_file_w1->umc_ldm_access_mask = uml_ldm_access_mask;  /* access mask */
   adsl_rdpvch1_file_w1->umc_ldm_create_disposition = uml_ldm_create_disposition;  /* create disposition */
   adsl_rdpvch1_file_w1->chc_flag_full_path = chl_flag_full_path;  /* flag full path file-name */
   adsl_rdpvch1_file_w1->adsc_next = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
   ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file = adsl_rdpvch1_file_w1;
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_frse() request uml_ldm_req_id=0X%08X.",
                 __LINE__, uml_ldm_req_id );
#endif
   return ied_sdhr1_failed;                 /* do not send data to server */

   p_more_00:                               /* check more flag         */
   if (((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file == NULL) {
     return ied_sdhr1_ok;
   }
   bol1 = FALSE;
   if (ucl_subchn & 0X80) {                 /* with more flag          */
     bol1 = TRUE;
   }
   adsl_rdpvch1_file_w1 = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
   do {                                     /* loop over all files currently processed */
     if ((adsl_rdpvch1_file_w1->chc_subchn & 0X7F) == (ucl_subchn & 0X7F)) {  /* sub-channel no */
       adsl_rdpvch1_file_w1->boc_more_se2cl = bol1;  /* more bit server to client in datastream */
     }
     adsl_rdpvch1_file_w1 = adsl_rdpvch1_file_w1->adsc_next;  /* get next in chain */
   } while (adsl_rdpvch1_file_w1);
   return ied_sdhr1_ok;
#ifdef B091221
   p_rdpdr_00:                              /* is not HOB channel      */
   if (adsp_p1->adsc_rdp_vc_1->chc_hob_vch != 'd') {  /* virtual channel HOB special */
     return ied_sdhr1_ok;                   /* send packet unchanged   */
   }
   if (iml_len_r <= (sizeof(usrs_ms_serv_cap_01) + 4)) return ied_sdhr1_ok;
   /* compare if header like we search for                             */
   achl2 = (char *) usrs_ms_serv_cap_01;
   iml1 = sizeof(usrs_ms_serv_cap_01);
   if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_ok;
   while (TRUE) {
     achl1 = adsl_gather_i_1_w1->achc_ginp_cur;
     iml2 = adsl_gather_i_1_w1->achc_ginp_end - achl1;
     if (iml2 > iml1) iml2 = iml1;
     if (memcmp( achl2, achl1, iml2 )) return ied_sdhr1_ok;
     achl1 += iml2;
     iml1 -= iml2;
     if (iml1 <= 0) break;
     achl2 += iml2;
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;
     if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_fatal_error;
   }
   iml1 = 4;                                /* number of bytes to scan */
   do {                                     /* loop to get these bytes */
     if (achl1 >= adsl_gather_i_1_w1->achc_ginp_end) {
       adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;
       if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_fatal_error;
       achl1 = adsl_gather_i_1_w1->achc_ginp_cur;
     }
     switch (iml1) {                        /* check which character   */
       case 4:
         iml_cap_no_1 = (unsigned char) *achl1;  /* number of capabilities 1 */
         break;
       case 3:
         iml_cap_no_1 |= ((unsigned char) *achl1) << 8;  /* number of capabilities 1 */
         break;
     }
     achl1++;                               /* this byte processed     */
     iml1--;                                /* decrement number of bytes to process */
   } while (iml1 > 0);
   if (iml_cap_no_1 <= 0) return ied_sdhr1_fatal_error;
   iml_len_r -= sizeof(usrs_ms_serv_cap_01) + 4;
   iml_cap_no_2 = 0;                        /* number of capabilities 2 */
   iml_remove_cap_no = 0;                   /* remove number of capabilities */
   iml_remove_len = 0;                      /* remove from this packet */
   iml_cap_type = 0;                        /* capability type         */
   iml_pos = 0;                             /* get capability type     */
   iml_len_f = sizeof(unsigned short int);  /* get number little endian */
// iml1 = iml2 = 0;                         /* clear numbers           */

   p_rdpdr_20:                              /* decode following values */
   if (iml_len_r <= 0) goto p_rdpdr_48;     /* packet has been checked */
   iml_len_d = adsl_gather_i_1_w1->achc_ginp_end - achl1;
   if (iml_len_d <= 0) {                    /* no more data            */
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_fatal_error;
     goto p_rdpdr_20;                       /* decode following values */
   }
   if (iml_len_d > iml_len_r) iml_len_d = iml_len_r;

   p_rdpdr_40:                              /* fill field              */
   switch (iml_pos) {                       /* depending on field      */
     case 0:                                /* capability type         */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_20;  /* decode following values */
         iml_cap_type |= ((unsigned char) *achl1) << ((sizeof(unsigned short int) - iml_len_f) << 3);
         achl1++;                           /* this byte processed     */
         iml_len_d--;                       /* decrement length field  */
         iml_len_f--;                       /* decrement length field  */
         iml_len_r--;                       /* decrement remaining length of packet */
       } while (iml_len_f > 0);
       iml_pos = 1;                         /* get capability length   */
       iml_len_f = sizeof(unsigned short int);  /* get number little endian */
       iml1 = 0;                            /* clear field to fill     */
       goto p_rdpdr_40;                     /* fill field              */
     case 1:                                /* capability length       */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_20;  /* decode following values */
         iml1 |= ((unsigned char) *achl1) << ((sizeof(unsigned short int) - iml_len_f) << 3);
         achl1++;                           /* this byte processed     */
         iml_len_d--;                       /* decrement length field  */
         iml_len_f--;                       /* decrement length field  */
         iml_len_r--;                       /* decrement remaining length of packet */
       } while (iml_len_f > 0);
       iml_len_f = iml1 - 2 * sizeof(unsigned short int);
       if (iml_len_f <= 0) return ied_sdhr1_fatal_error;
       if (iml_cap_type == CAP_DRIVE_TYPE) {
         iml_remove_cap_no++;               /* remove number of capabilities */
         iml_remove_len += iml1;            /* remove from this packet */
       }
       iml_pos = 2;                         /* get capability values   */
       goto p_rdpdr_40;                     /* fill field              */
     case 2:                                /* capability values       */
       if (iml_len_d <= 0) goto p_rdpdr_20;  /* decode following values */
       iml1 = iml_len_d;                    /* get length this chunk   */
       if (iml1 > iml_len_f) iml1 = iml_len_f;  /* only this field     */
       achl1 += iml1;                       /* ignore this part        */
       iml_len_d -= iml1;                   /* decrement length field  */
       iml_len_f -= iml1;                   /* decrement length field  */
       iml_len_r -= iml1;                   /* decrement remaining length of packet */
       if (iml_len_f > 0) goto p_rdpdr_40;  /* fill field              */
       iml_cap_no_2++;                      /* number of capabilities 2 */
       iml_cap_type = 0;                    /* capability type         */
       iml_pos = 0;                         /* get capability type     */
       iml_len_f = sizeof(unsigned short int);  /* get number little endian */
       goto p_rdpdr_40;                     /* fill field              */
   }

   p_rdpdr_48:                              /* packet has been checked */
   if (iml_pos != 0) return ied_sdhr1_fatal_error;  /* get capability type */
   if (iml_len_f != sizeof(unsigned short int)) return ied_sdhr1_fatal_error;  /* get number little endian */
   if (iml_cap_no_2 != iml_cap_no_1) return ied_sdhr1_fatal_error;
   if (iml_remove_cap_no <= 0) {            /* nothing to remove from this packet */
     return ied_sdhr1_ok;                   /* send packet unchanged   */
   }
#ifdef TRACEHL_091210_02
   if (iml_remove_cap_no > 0) {             /* something to remove from this packet */
     return ied_sdhr1_ok;                   /* send packet unchanged   */
   }
#endif
   iml_len_r = adsp_p1->imc_len_vch_input;
   if (iml_len_r <= (sizeof(usrs_ms_serv_cap_01) + 4 + iml_remove_len)) {
     return ied_sdhr1_failed;               /* do not send data to server */
   }
   /* copy input to a buffer which can be sent without copying   */
   achl_out_1 = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += iml_len_r - iml_remove_len;
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_gather_i_1) + 2 * sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;    /* fatal error occured, abend */
   }
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + 2 * sizeof(void *)))
   ADSL_GAI1_O1->adsc_next = 0;
   ADSL_GAI1_O1->achc_ginp_cur = achl_out_1;  /* set start of buffered record */
   ADSL_GAI1_O1->achc_ginp_end = achl_out_1 + iml_len_r - iml_remove_len;  /* set end of buffered record */
#undef ADSL_GAI1_O1
   memcpy( achl_out_1, usrs_ms_serv_cap_01, sizeof(usrs_ms_serv_cap_01) );
   achl_out_1 += sizeof(usrs_ms_serv_cap_01);
   iml1 = iml_cap_no_1 - iml_remove_cap_no;
   *achl_out_1++ = (unsigned int) iml1;
   *achl_out_1++ = (unsigned int) (iml1 << 8);
   *achl_out_1++ = 0;
   *achl_out_1++ = 0;
   adsl_gather_i_1_w1 = adsp_p1->adsc_gather_i_1_in;
   achl1 = adsl_gather_i_1_w1->achc_ginp_cur;
   iml_pos = 2;                             /* ignore data             */
   iml_len_f = sizeof(usrs_ms_serv_cap_01) + 4;

   p_rdpdr_64:                              /* decode following values */
   if (iml_len_r <= 0) goto p_rdpdr_72;     /* packet has been copied */
   iml_len_d = adsl_gather_i_1_w1->achc_ginp_end - achl1;
   if (iml_len_d <= 0) {                    /* no more data            */
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_fatal_error;
     goto p_rdpdr_64;                       /* decode following values */
   }
   if (iml_len_d > iml_len_r) iml_len_d = iml_len_r;

   p_rdpdr_68:                              /* fill field              */
   switch (iml_pos) {                       /* depending on field      */
     case 0:                                /* capability type         */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_64;  /* decode following values */
         iml_cap_type |= ((unsigned char) *achl1) << ((sizeof(unsigned short int) - iml_len_f) << 3);
         achl1++;                           /* this byte processed     */
         iml_len_d--;                       /* decrement length field  */
         iml_len_f--;                       /* decrement length field  */
         iml_len_r--;                       /* decrement remaining length of packet */
       } while (iml_len_f > 0);
       iml_pos = 1;                         /* get capability length   */
       iml_len_f = sizeof(unsigned short int);  /* get number little endian */
       iml1 = 0;                            /* clear field to fill     */
       goto p_rdpdr_68;                     /* fill field              */
     case 1:                                /* capability length       */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_64;  /* decode following values */
         iml1 |= ((unsigned char) *achl1) << ((sizeof(unsigned short int) - iml_len_f) << 3);
         achl1++;                           /* this byte processed     */
         iml_len_d--;                       /* decrement length field  */
         iml_len_f--;                       /* decrement length field  */
         iml_len_r--;                       /* decrement remaining length of packet */
       } while (iml_len_f > 0);
       iml_len_f = iml1 - 2 * sizeof(unsigned short int);
       if (iml_len_f <= 0) return ied_sdhr1_fatal_error;
       if (iml_cap_type == CAP_DRIVE_TYPE) {  /* data to be ignored    */
         iml_pos = 2;                       /* get capability values   */
         goto p_rdpdr_68;                   /* fill field              */
       }
       *achl_out_1++ = (unsigned char) iml_cap_type;
       *achl_out_1++ = (unsigned char) (iml_cap_type << 8);
       *achl_out_1++ = (unsigned char) iml1;
       *achl_out_1++ = (unsigned char) (iml1 << 8);
       iml_pos = 3;                         /* copy data               */
       goto p_rdpdr_68;                     /* fill field              */
     case 2:                                /* capability values       */
       if (iml_len_d <= 0) goto p_rdpdr_64;  /* decode following values */
       iml1 = iml_len_d;                    /* get length this chunk   */
       if (iml1 > iml_len_f) iml1 = iml_len_f;  /* only this field     */
       achl1 += iml1;                       /* ignore this part        */
       iml_len_d -= iml1;                   /* decrement length field  */
       iml_len_f -= iml1;                   /* decrement length field  */
       iml_len_r -= iml1;                   /* decrement remaining length of packet */
       if (iml_len_f > 0) goto p_rdpdr_68;  /* fill field              */
       iml_cap_type = 0;                    /* capability type         */
       iml_pos = 0;                         /* get capability type     */
       iml_len_f = sizeof(unsigned short int);  /* get number little endian */
       goto p_rdpdr_68;                     /* fill field              */
     case 3:                                /* copy data               */
       if (iml_len_d <= 0) goto p_rdpdr_64;  /* decode following values */
       iml1 = iml_len_d;                    /* get length this chunk   */
       if (iml1 > iml_len_f) iml1 = iml_len_f;  /* only this field     */
       memcpy( achl_out_1, achl1, iml1 );   /* copy this part          */
       achl1 += iml1;                       /* after part copied       */
       achl_out_1 += iml1;                  /* increment address output */
       iml_len_d -= iml1;                   /* decrement length field  */
       iml_len_f -= iml1;                   /* decrement length field  */
       iml_len_r -= iml1;                   /* decrement remaining length of packet */
       if (iml_len_f > 0) goto p_rdpdr_68;  /* fill field              */
       iml_cap_type = 0;                    /* capability type         */
       iml_pos = 0;                         /* get capability type     */
       iml_len_f = sizeof(unsigned short int);  /* get number little endian */
       goto p_rdpdr_68;                     /* fill field              */
   }

   p_rdpdr_72:                              /* packet has been copied */
   if (iml_pos != 0) return ied_sdhr1_fatal_error;  /* get capability type */
   if (iml_len_f != sizeof(unsigned short int)) return ied_sdhr1_fatal_error;  /* get number little endian */
   /* the buffered record has to be sent later at m_rdp_vch1_get_frse() */
   *((void **) ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + (2 - 1) * sizeof(void *))))
     = adsp_p1->adsc_rdp_vc_1;
   *((void **) ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper))) = NULL;
   if (adsp_p1->ac_chain_send_frse == NULL) {  /* chain of buffers to be sent to the client */
     adsp_p1->ac_chain_send_frse = adsp_p1->adsc_output_area_1->achc_upper;  /* chain of buffers to be sent to the client */
   } else {                           /* middle in chain         */
     /* search end of chain, append at end of chain              */
     achl2 = (char *) adsp_p1->ac_chain_send_frse;  /* chain of buffers to be sent to the client */
     do {
       achl3 = achl2;                 /* save previous element   */
       achl2 = (char *) *((void **) achl2);  /* get next in chain */
     } while (achl2);
     *((void **) achl3) = adsp_p1->adsc_output_area_1->achc_upper;  /* append to chain of buffers to be sent to the client */
   }
   return ied_sdhr1_failed;           /* do not send data to server */
   iml_len_f = achl3 - achl2;
// to-do 08.12.09 KB
   return ied_sdhr1_ok;
#endif
} /* end m_rdp_vch1_rec_frse()                                         */

extern "C" enum ied_sdh_ret1 m_rdp_vch1_rec_tose( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_send_tose_changed;        /* send to server packet has been changed */
   int        iml1, iml2;                   /* working variables       */
   char       chl1;                         /* working variable        */
#ifndef B111012
   enum ied_sdh_ret1 iel_sdh_ret1;          /* return value            */
#endif
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_out_1, *achl_out_2;     /* output pointers         */
   unsigned short int *ausl1;               /* working variable        */
   BOOL       bol_copy;                     /* do copy data            */
   int        iml_send_name;                /* length send name        */
   struct dsd_gather_i_1 *adsl_gather_i_1_w1;  /* gather data from channel */
   struct dsd_gather_i_1 *adsl_gather_i_1_w2;  /* working variable gather data */
   struct dsd_gather_i_1 *adsl_gai1_o_w1;   /* gather output data      */
   struct dsd_pch_save_1 *adsl_pch_save_1_first;  /* save data from virtual channel */
   struct dsd_pch_save_1 *adsl_pch_save_1_w1;  /* save data from virtual channel */
   struct dsd_pch_save_2 *adsl_pch_save_2_w1;  /* save data from virtual channel */
   int        iml_len_r;                    /* remaining length        */
// int        iml_pos;                      /* position input          */
   enum ied_rtose_def iel_rtose;            /* received to server status */
   int        iml_len_d, iml_len_f;         /* length of input         */
   unsigned char ucl_subchn;                /* sub-channel no          */
   unsigned char chl_file_folder;           /* flag file / folder      */
// unsigned int uml_ldm_handle;             /* handle of file          */
   unsigned int uml_ldm_req_id;             /* request id              */
   unsigned int uml_ldm_ret_code;           /* return code             */
// unsigned int uml_ldm_command;            /* command                 */
// unsigned int uml_ldm_access_mask;        /* access mask             */
// unsigned int uml_ldm_create_disposition;  /* create disposition     */
// unsigned char chl_flag_full_path;        /* flag full path file-name */
   unsigned int uml_len_name;               /* length of name          */
   unsigned int uml_len_read;               /* length data read        */
   int        iml_len_name;                 /* length of name          */
   int        iml_len_data;                 /* length of data          */
   HL_LONGLONG ill1;                        /* working-variable        */
   HL_LONGLONG ill2;                        /* working-variable        */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w1;  /* structure of file */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w2;  /* structure of file */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_cur;  /* current element in chain */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_last;  /* last element in chain */
   struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query     */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   char       chrl_work1[ 128 ];            /* work area               */
   char       chrl_ns_num[ 16 ];            /* for number              */

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
#ifdef TRACEHL_091210_01
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   adsl_gather_i_1_w1 = adsp_p1->adsc_gather_i_1_in;
   iml_len_r = adsp_p1->imc_len_vch_input;
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() request length=%d/0X%08X.",
                 __LINE__, iml_len_r, iml_len_r );
   m_dump_gather( &dsl_sdh_call_1, adsl_gather_i_1_w1, iml_len_r );
#endif
#ifdef OLD01
   if (adsp_p1->ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
   if (((struct dsd_rdpvch1_contr *) adsp_p1->ac_vir_ch_1)->adsc_rdpvch1_file == NULL) {
     return ied_sdhr1_ok;
   }
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() packet received",
                 __LINE__ );
#endif
#ifndef B111205
   iel_sdh_ret1 = ied_sdhr1_ok;             /* return value            */
#endif
   if ((adsp_p1->adsc_rdp_vc_1->chc_hob_vch & 0XF0) != 0X30) {  /* virtual channel HOB special */
     goto p_rdpdr_00;                       /* is not HOB channel      */
   }
   if (adsp_p1->adsc_conf->boc_disa_hob_ldm == FALSE) {  /* not disable HOB local-drive-mapping */
     if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
     if (((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file == NULL) {
       return ied_sdhr1_ok;
     }
   }
   /* save virtual channel structure                                   */
   if (adsp_p1->dsc_s1.ac_vir_ch_1) {       /* is configured           */
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_tose
       = adsp_p1->adsc_rdp_vc_1;
   }
   /* check if only in chain - segmented                               */
   if (*((unsigned short int *) adsp_p1->chrc_vch_segfl)
         != (*((unsigned short int *) usrc_vch_segfl))) {
#ifndef OLD01
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel segmentation invalid",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
#else
     return ied_sdhr1_ok;
#endif
   }
   adsl_gather_i_1_w1 = adsp_p1->adsc_gather_i_1_in;
   iml_len_r = adsp_p1->imc_len_vch_input;
   iel_rtose = ied_rtose_subchn;            /* receive HSUBCHN         */
   achl2 = (char *) &ucl_subchn;
   achl3 = (char *) &ucl_subchn + sizeof(ucl_subchn);
   bol_copy = TRUE;                         /* do copy data            */
#ifdef B111205
#ifndef B111012
   iel_sdh_ret1 = ied_sdhr1_ok;             /* return value            */
#endif
#endif

   p_scan_00:                               /* scan input              */
// to-do 24.11.09 KB - error when control record
   if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_ok;
   achl1 = adsl_gather_i_1_w1->achc_ginp_cur;

   p_scan_04:                               /* scan input              */
// to-do 24.11.09 KB - error when control record
   if (iml_len_r <= 0) return ied_sdhr1_ok;
   iml_len_d = adsl_gather_i_1_w1->achc_ginp_end - achl1;
   if (iml_len_d <= 0) {                    /* no more data            */
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     goto p_scan_00;                        /* scan input              */
   }
#ifdef OLD01
   iml_len_f = achl3 - achl2;
   if (iml_len_f > iml_len_d) iml_len_f = iml_len_d;
   if (iml_len_f > iml_len_r) iml_len_f = iml_len_r;
   if (bol_copy) {                          /* do copy data            */
     memcpy( achl2, achl1, iml_len_f );
   }
   achl2 += iml_len_f;
   achl1 += iml_len_f;
   iml_len_r -= iml_len_f;
   if (achl2 < achl3) goto p_scan_04;       /* needs more data         */
#endif
   if (bol_copy) {                          /* do copy data            */
     iml_len_f = achl3 - achl2;
     if (iml_len_f > iml_len_d) iml_len_f = iml_len_d;
     if (iml_len_f > iml_len_r) iml_len_f = iml_len_r;
     memcpy( achl2, achl1, iml_len_f );
     achl2 += iml_len_f;
     achl1 += iml_len_f;
     iml_len_r -= iml_len_f;
     if (achl2 < achl3) goto p_scan_04;     /* needs more data         */
   }
// iml_pos++;                               /* next field              */
   switch (iel_rtose) {                     /* depending on field      */
     case ied_rtose_subchn:                 /* receive HSUBCHN         */
       if ((ucl_subchn & 0X40) != 0) {      /* is not local drive mapping */
         return ied_sdhr1_ok;
       }
       if (ucl_subchn & 0X80) {             /* with more flag          */
         goto p_more_00;                    /* check more flag         */
       }
       if (ucl_subchn == 0) {               /* control channel         */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() subchannel zero",
                       __LINE__ );
         m_dump_gather( &dsl_sdh_call_1, adsl_gather_i_1_w1, 1 + iml_len_r );
#endif
         if (adsp_p1->adsc_conf->boc_disa_hob_ldm == FALSE) {  /* not disable HOB local-drive-mapping */
#ifdef B111012
           return ied_sdhr1_ok;
#else
           goto p_more_00;                  /* check more flag         */
#endif
         }
         /* copy input to a buffer which can be sent without copying   */
         achl_out_1 = adsp_p1->adsc_output_area_1->achc_lower;
         adsp_p1->adsc_output_area_1->achc_lower += 1 + iml_len_r;
         adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_gather_i_1) + 2 * sizeof(void *);
         adsp_p1->adsc_output_area_1->achc_upper
           = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
         if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
           dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
           dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
           m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                         __LINE__ );
           return ied_sdhr1_fatal_error;    /* fatal error occured, abend */
         }
         memset( adsp_p1->adsc_output_area_1->achc_upper, 0, 2 * sizeof(void *) + sizeof(struct dsd_gather_i_1) );  /* clear chain and other fields */
         bol1 = FALSE;                      /* no start request received */
         bol_send_tose_changed = FALSE;     /* send to server packet has been changed */
         *achl_out_1 = 0;                   /* clear HOB channel number */
         achl_out_2 = achl_out_1 + 1;
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + 2 * sizeof(void *)))
         ADSL_GAI1_O1->achc_ginp_cur = achl_out_1;  /* set start of buffered record */
#undef ADSL_GAI1_O1
         iel_rtose = ied_rtose_cch_nhasn_len;  /* control packet length NHASN */
         iml1 = 0;                          /* clear result            */
         iml2 = 3;                          /* set maximum number of digits */
         bol_copy = FALSE;                  /* do not copy data        */
         goto p_scan_04;                    /* scan input              */
       }
#ifdef B111012
       if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
#else
       if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) {  /* not configured   */
         goto p_more_00;                    /* check more flag         */
       }
#endif
       if (((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file == NULL) {
#ifdef B111012
         return ied_sdhr1_ok;
#else
         goto p_more_00;                    /* check more flag         */
#endif
       }
       achl2 = (char *) &uml_ldm_req_id;
       achl3 = (char *) &uml_ldm_req_id + sizeof(uml_ldm_req_id);
       iel_rtose = ied_rtose_req_id;        /* receive request id      */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_req_id:                 /* receive request id      */
       achl2 = (char *) &uml_ldm_ret_code;
       achl3 = (char *) &uml_ldm_ret_code + sizeof(uml_ldm_ret_code);
       iel_rtose = ied_rtose_ret_code;      /* receive return code     */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_ret_code:               /* receive return code     */
       adsl_rdpvch1_file_w1 = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
       adsl_rdpvch1_file_w2 = NULL;         /* clear last in chain     */
       while (adsl_rdpvch1_file_w1) {       /* loop over all open files */
         if (   (adsl_rdpvch1_file_w1->chc_subchn == ucl_subchn)  /* sub-channel no */
             && (adsl_rdpvch1_file_w1->umc_ldm_req_id == uml_ldm_req_id)) {  /* request id */
           break;                           /* file found              */
         }
         adsl_rdpvch1_file_w2 = adsl_rdpvch1_file_w1;  /* save last in chain */
         adsl_rdpvch1_file_w1 = adsl_rdpvch1_file_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_rdpvch1_file_w1 == NULL) {  /* other packet received   */
#ifdef B111012
         return ied_sdhr1_ok;
#else
         goto p_more_00;                    /* check more flag         */
#endif
       }
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() found response adsl_rdpvch1_file_w1=%p iec_fist=%d.",
                     __LINE__, adsl_rdpvch1_file_w1, adsl_rdpvch1_file_w1->iec_fist );
#endif
       switch (adsl_rdpvch1_file_w1->iec_fist) {
         case ied_fist_wait_repl_open:      /* wait for reply for open */
           if (uml_ldm_ret_code) {          /* error from open         */
             adsl_rdpvch1_file_w1->umc_ldm_ret_code = uml_ldm_ret_code;  /* save return code */
             adsl_rdpvch1_file_w1->chc_open_error = 0X01;  /* return open error to server */
             adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_open_error;  /* return open error */
#ifdef B111012
             return ied_sdhr1_failed;       /* do not send to server   */
#else
             iel_sdh_ret1 = ied_sdhr1_failed;  /* do not send data to server */
             goto p_more_00;                /* check more flag         */
#endif
           }
           achl2 = (char *) &adsl_rdpvch1_file_w1->umc_ldm_handle;  /* handle of file */
           achl3 = (char *) &adsl_rdpvch1_file_w1->umc_ldm_handle
                              + sizeof(adsl_rdpvch1_file_w1->umc_ldm_handle);
           iel_rtose = ied_rtose_op_handle;  /* receive open handle    */
           goto p_scan_04;                  /* scan input              */
         case ied_fist_wait_repl_read:      /* wait for reply for read */
           if (uml_ldm_ret_code) {          /* error from read         */
             dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
             dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
             m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel after file read return code 0X%08X.",
                           __LINE__, uml_ldm_ret_code );
             return ied_sdhr1_fatal_error;  /* fatal error occured, abend */
           }
           achl2 = (char *) &uml_len_read;  /* length data read        */
           achl3 = (char *) &uml_len_read + sizeof(uml_len_read);
           iel_rtose = ied_rtose_read_length;  /* receive length read  */
           goto p_scan_04;                  /* scan input              */
         case ied_fist_client_wait_close:   /* wait for response close from client */
           goto p_close_00;                 /* close file              */
       }
       dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel data not requested",
                     __LINE__ );
       return ied_sdhr1_fatal_error;        /* fatal error occured, abend */
     case ied_rtose_op_handle:              /* receive open handle     */
       achl2 = (char *) adsl_rdpvch1_file_w1->chrc_open_info_1;  /* information from file open */
       achl3 = (char *) adsl_rdpvch1_file_w1->chrc_open_info_1
                          + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1);
       iel_rtose = ied_rtose_op_info_1;     /* information from file open */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_op_info_1:              /* information from file open */
       achl2 = (char *) &chl_file_folder;   /* flag file / folder      */
       achl3 = (char *) &chl_file_folder + sizeof(chl_file_folder);
       iel_rtose = ied_rtose_op_chl_file_folder;  /* flag file / folder */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_op_chl_file_folder:     /* flag file / folder      */
       achl2 = (char *) &uml_len_name;
       achl3 = (char *) &uml_len_name + sizeof(uml_len_name);
       iel_rtose = ied_rtose_op_len_name;   /* length of name          */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_op_len_name:            /* length of name          */
       iml_len_name = *((unsigned char *) &uml_len_name + 0)
                      | (*((unsigned char *) &uml_len_name + 1) << 8)
                      | (*((unsigned char *) &uml_len_name + 2) << 16)
                      | (*((unsigned char *) &uml_len_name + 3) << 24);
       if (   (iml_len_name > 0X400)
           || (iml_len_name <= 0)
           || (iml_len_name > iml_len_r)) {
         dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel invalid length file-name %d.",
                       __LINE__, iml_len_name );
         return ied_sdhr1_fatal_error;      /* fatal error occured, abend */
       }
       achl2 = (char *) m_aux_stor_alloc(
                          adsp_p1->adsc_stor_sdh_1,
                          iml_len_name );
       adsl_rdpvch1_file_w1->achc_ret_name = achl2;
       adsl_rdpvch1_file_w1->imc_ret_len_name = iml_len_name;
       achl3 = achl2 + iml_len_name;
       iel_rtose = ied_rtose_op_ret_name;   /* return name             */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_op_ret_name:            /* return name             */
       if (chl_file_folder) {               /* is not normal file      */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() received file-folder - will not be virus-checked",
                       __LINE__ );
#endif
#ifdef XYZ1
// to-do 18.09.09 KB - is normal reply? if yes, send now to server and do cleanup
         adsl_rdpvch1_file_w1->chc_file_folder = chl_file_folder;  /* is not normal file */
         adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_open_ok;  /* return open o.k. */
         return ied_sdhr1_failed;           /* do not send data to server */
#endif
         goto p_send_resp_open;             /* virus checking not needed, send response open to server */
       }
       /* check if file empty or too big                               */
       ill1 = *((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 0)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 1) << 8)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 2) << 16)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 3) << 24)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 4) << 32)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 5) << 40)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 6) << 48)
                | (*((unsigned char *) adsl_rdpvch1_file_w1->chrc_open_info_1 + 45 + 7) << 56);
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() size of file %lld.",
                     __LINE__, ill1 );
#endif
       if (ill1 == 0) {                     /* file is empty           */
#ifdef XYZ1
// to-do 18.09.09 KB - is normal reply? if yes, send now to server and do cleanup
         adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_open_ok;  /* return open o.k. */
         return ied_sdhr1_failed;           /* do not send data to server */
#endif
         goto p_send_resp_open;             /* virus checking not needed, send response open to server */
       }
       ill2 = adsp_p1->adsc_conf->ilc_ldm_max_file_size;  /* maximum file-size virus-checking */
       if (ill2 == 0) ill2 = (HL_LONGLONG) MAX_FILE_LEN;  /* set default maximum */
       if (ill1 <= ill2) {                  /* file not too big        */
         goto p_send_fna_00;                /* send file-name          */
       }
       goto p_file_too_big_00;              /* file is too big         */
     case ied_rtose_read_length:            /* receive length read     */
       goto p_send_data_00;                 /* send data               */
     case ied_rtose_cch_nhasn_len:          /* control packet length NHASN */
       while (TRUE) {
         chl1 = *achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
         iml1 <<= 7;                        /* shift old value         */
         iml1 |= chl1 & 0X7F;               /* apply new bits          */
         if (((signed char) chl1) >= 0) break;  /* was last digit      */
         iml2--;                            /* decrement maximum number of digits */
         if (iml2 <= 0) {                   /* too many digits NHASN   */
           dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
           dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
           m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel control record length NHASN too long",
                         __LINE__ );
           return ied_sdhr1_fatal_error;    /* fatal error occured, abend */
         }
         if (iml_len_d <= 0) {
           goto p_scan_00;                  /* scan input              */
         }
       }
       if (iml1 <= 0) {                     /* length too short        */
         dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel control record length NHASN zero",
                       __LINE__ );
         return ied_sdhr1_fatal_error;      /* fatal error occured, abend */
       }
       if (iml1 > iml_len_r) {              /* greater length remaining */
         dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel control record length NHASN greater than length remaining packet",
                       __LINE__ );
         return ied_sdhr1_fatal_error;      /* fatal error occured, abend */
       }
       /* output length NHASN to buffered record                       */
       iml2 = iml1;                         /* get length              */
       do {                                 /* loop to make space for length NHASN */
         achl_out_2++;                      /* needs space for digit   */
         iml2 >>= 7;                        /* remove bits             */
       } while (iml2 > 0);
       achl2 = achl_out_2;                  /* get end of output NHASN */
       iml2 = iml1;                         /* get length              */
       chl1 = 0;                            /* clear more bit          */
       while (TRUE) {                       /* loop for ouput of length NHASN */
         *(--achl2) = (unsigned char) ((iml2 & 0X7F) | (unsigned char) chl1);  /* output one digit   */
         iml2 >>= 7;                        /* remove bits             */
         if (iml2 <= 0) break;              /* last digit reached      */
         chl1 = (unsigned char) 0X80;       /* set more bit            */
       }
       /* next copy record content to buffer                           */
       achl2 = achl_out_2;                  /* start of target area    */
       achl3 = achl_out_2 + iml1;           /* end of target area      */
       bol_copy = TRUE;                     /* do copy data            */
       iel_rtose = ied_rtose_cch_record;    /* control packet record   */
       goto p_scan_04;                      /* scan input              */
     case ied_rtose_cch_record:             /* control packet record   */
       if (*achl_out_2 == 0) {              /* start request found     */
         if (bol1) {                        /* start request double    */
           dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
           dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
           m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E received from virtual channel control record start request double",
                         __LINE__ );
           return ied_sdhr1_fatal_error;    /* fatal error occured, abend */
         }
         bol1 = TRUE;                       /* set state               */
         if (   (iml1 > 5)
             && (*((signed char *) (achl_out_2 + 5)) < 0)) {  /* bit 0X80 Start Local Drive Mapping */
           *(achl_out_2 + 5) = 0;           /* do not Start Local Drive Mapping */
           bol_send_tose_changed = TRUE;    /* send to server packet has been changed */
         }
       }
       if (iml_len_r <= 0) {                /* at end of record        */
         if (bol_send_tose_changed == FALSE) {  /* send to server packet has not been changed */
#ifdef B111012
           return ied_sdhr1_ok;
#else
           goto p_more_00;                  /* check more flag         */
#endif
         }
         /* the buffered record has to be sent later at m_rdp_vch1_get_tose() */
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + 2 * sizeof(void *)))
         ADSL_GAI1_O1->achc_ginp_end = achl_out_2 + iml1;  /* set end of buffered record */
#undef ADSL_GAI1_O1
         *((void **) ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + (2 - 1) * sizeof(void *))))
           = adsp_p1->adsc_rdp_vc_1;
         if (adsp_p1->ac_chain_send_tose == NULL) {  /* chain of buffers to be sent to the server */
           adsp_p1->ac_chain_send_tose = adsp_p1->adsc_output_area_1->achc_upper;  /* chain of buffers to be sent to the server */
         } else {                           /* middle in chain         */
           /* search end of chain, append at end of chain              */
           achl2 = (char *) adsp_p1->ac_chain_send_tose;  /* chain of buffers to be sent to the server */
           do {
             achl3 = achl2;                 /* save previous element   */
             achl2 = (char *) *((void **) achl2);  /* get next in chain */
           } while (achl2);
           *((void **) achl3) = adsp_p1->adsc_output_area_1->achc_upper;  /* append to chain of buffers to be sent to the server */
         }
#ifdef B111012
         return ied_sdhr1_failed;           /* do not send data to server */
#else
         iel_sdh_ret1 = ied_sdhr1_failed;   /* do not send data to server */
         goto p_more_00;                    /* check more flag         */
#endif
       }
       achl_out_2 += iml1;                  /* after buffered record   */
       iel_rtose = ied_rtose_cch_nhasn_len;  /* control packet length NHASN */
       iml1 = 0;                            /* clear result            */
       iml2 = 3;                            /* set maximum number of digits */
       bol_copy = FALSE;                    /* do not copy data        */
       goto p_scan_04;                      /* scan input              */
   }
#ifdef B111012
   return ied_sdhr1_ok;                     /* send packet to server   */
#else
   goto p_more_00;                          /* check more flag         */
#endif

   p_send_fna_00:                           /* send file-name          */
   iml_send_name = adsl_rdpvch1_file_w1->imc_len_name / sizeof(unsigned short int);  /* length send name */
   ausl1 = (unsigned short int *) (adsl_rdpvch1_file_w1 + 1);
   while ((iml_send_name > 0) && (*(ausl1 + iml_send_name - 1) == 0)) iml_send_name--;
   if (iml_send_name <= 0) iml_send_name = 1;
   iml1 = m_len_vx_vx( ied_chs_utf_8, adsl_rdpvch1_file_w1 + 1, iml_send_name, ied_chs_le_utf_16 );
   achl1 = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += iml1;
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_gather_i_1) + sizeof(struct dsd_se_vch_req_1);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#define ADSL_SEVCHREQ1 ((struct dsd_se_vch_req_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_se_vch_req_1)))
   memset( adsp_p1->adsc_output_area_1->achc_upper, 0, sizeof(struct dsd_se_vch_req_1) + sizeof(struct dsd_gather_i_1) );
   m_cpy_vx_vx( achl1, iml1, ied_chs_utf_8,
                adsl_rdpvch1_file_w1 + 1, iml_send_name, ied_chs_le_utf_16 );
   ADSL_GAI1_O1->achc_ginp_cur = achl1;
   ADSL_GAI1_O1->achc_ginp_end = achl1 + iml1;
   ADSL_SEVCHREQ1->adsc_gai1_data = ADSL_GAI1_O1;
   ADSL_SEVCHREQ1->iec_vchreq1 = ied_vchreq_filename;  /* filename     */
   adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1 = ADSL_SEVCHREQ1;
//#undef ADSL_SEVCHREQ1
#undef ADSL_GAI1_O1
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_read_file;  /* read next part of file */
   goto p_start_req;                        /* start the request       */

   p_send_data_00:                          /* send data               */
   iml_len_data = *((unsigned char *) &uml_len_read + 0)
                  | (*((unsigned char *) &uml_len_read + 1) << 8)
                  | (*((unsigned char *) &uml_len_read + 2) << 16)
                  | (*((unsigned char *) &uml_len_read + 3) << 24);
   if (   (iml_len_data != iml_len_r)
       || (((unsigned int) iml_len_data) > D_HOBLDM_LEN_READ)) {
     // to-do 12.11.07 KB - close file and send error message to server
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E iml_len_data, length data received, invalid",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
   /* count the number of gather structures needed                     */
   iml1 = 0;                                /* clear count gather      */
   while (iml_len_data) {                   /* data to send to virus checker */
     adsl_rdpvch1_file_w1->ilc_read_disp += iml_len_data;  /* update disposition read file */
     iml2 = iml_len_r;                      /* remaining data          */
     if (iml_len_d > 0) {                   /* still data in this gather */
       iml1 = 1;                            /* one gather for first data */
       iml2 -= adsl_gather_i_1_w1->achc_ginp_end - achl1;
       if (iml2 <= 0) break;                /* no more data to follow  */
     }
     adsl_gather_i_1_w2 = adsl_gather_i_1_w1;
     while (adsl_gather_i_1_w2) {           /* loop over remaining gather structures */
       iml1++;                              /* one gather for these data */
       iml2 -= adsl_gather_i_1_w2->achc_ginp_end - adsl_gather_i_1_w2->achc_ginp_cur;
       if (iml2 <= 0) break;                /* no more data to follow  */
       adsl_gather_i_1_w2 = adsl_gather_i_1_w2->adsc_next;  /* get next in chain */
     }
     break;
   }
   adsp_p1->adsc_output_area_1->achc_upper -= iml1 * sizeof(struct dsd_gather_i_1) + sizeof(struct dsd_se_vch_req_1);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
//#define ADSL_SEVCHREQ1 ((struct dsd_se_vch_req_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_se_vch_req_1)))
   memset ( adsp_p1->adsc_output_area_1->achc_upper, 0, sizeof(struct dsd_se_vch_req_1) );
   ADSL_SEVCHREQ1->adsc_gai1_data = NULL;
   ADSL_SEVCHREQ1->iec_vchreq1 = ied_vchreq_eof;  /* End-of-File       */
   /* remove old requests and put this request at end of chain         */
   adsl_sevchreq1_cur = adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1;
   adsl_sevchreq1_last = NULL;              /* last element in chain   */
   while (TRUE) {                           /* loop over all requests  */
     if (adsl_sevchreq1_cur == NULL) break;  /* end of chain reached   */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() chain adsl_sevchreq1_cur=%p.",
                   __LINE__, adsl_sevchreq1_cur );
#endif
     if (adsl_sevchreq1_cur->iec_stat != ied_vchstat_done) {  /* leave element in chain */
       adsl_sevchreq1_last = adsl_sevchreq1_cur;  /* save last element in chain */
       adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
       continue;
     }
     /* remove this element from the chain                             */
     if (adsl_sevchreq1_last == NULL) {     /* is first in chain now   */
       adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1 = adsl_sevchreq1_cur->adsc_next;
     } else {                               /* middle in chain         */
       adsl_sevchreq1_last->adsc_next = adsl_sevchreq1_cur->adsc_next;
     }
     /* storage needs no longer be fixed in memory                     */
     if (adsl_sevchreq1_cur->iec_vchreq1 == ied_vchreq_content) {  /* content of file */
       adsl_gai1_o_w1 = adsl_sevchreq1_cur->adsc_gai1_data;
       while (adsl_gai1_o_w1) {             /* loop over all gather structures */
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
         dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
         dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
         m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-dec file data adsl_gai1_o_w1->achc_ginp_cur=%p.",
                       __LINE__, adsl_gai1_o_w1->achc_ginp_cur );
#endif
         bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                      DEF_AUX_MARK_WORKAREA_DEC,  /* decrement usage count in work area */
                                                      adsl_gai1_o_w1->achc_ginp_cur,
                                                      0 );
         adsl_gai1_o_w1 = adsl_gai1_o_w1->adsc_next;  /* get next in chain */
       }
     }
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-dec request adsl_sevchreq1_cur=%p.",
                   __LINE__, adsl_sevchreq1_cur );
#endif
     bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                  DEF_AUX_MARK_WORKAREA_DEC,  /* decrement usage count in work area */
                                                  adsl_sevchreq1_cur,
                                                  0 );
     adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() chain adsl_sevchreq1_last=%p ADSL_SEVCHREQ1=%p.",
                 __LINE__, adsl_sevchreq1_last, ADSL_SEVCHREQ1 );
#endif
   if (adsl_sevchreq1_last == NULL) {       /* is first in chain now   */
     adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1 = ADSL_SEVCHREQ1;
   } else {                                 /* append to chain         */
     adsl_sevchreq1_last->adsc_next = ADSL_SEVCHREQ1;
   }
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_wait_vircheck;  /* wait for virus checking */
   while (iml_len_data) {                   /* data to send to virus checker */
     ADSL_SEVCHREQ1->iec_vchreq1 = ied_vchreq_content;  /* content of file */
     ADSL_SEVCHREQ1->adsc_gai1_data = ADSL_GAI1_O1;  /* output here    */
     adsl_gai1_o_w1 = ADSL_GAI1_O1;         /* output here             */
     if (iml_len_d > 0) {                   /* still data in this gather */
       iml2 = adsl_gather_i_1_w1->achc_ginp_end - achl1;
       if (iml2 > iml_len_r) iml2 = iml_len_r;  /* only remaining data */
       adsl_gai1_o_w1->achc_ginp_cur = achl1;  /* here start data      */
       adsl_gai1_o_w1->achc_ginp_end = achl1 + iml2;  /* end of data   */
       adsl_gai1_o_w1->adsc_next = adsl_gai1_o_w1 + 1;
       adsl_gai1_o_w1++;                    /* next output to next gather */
       adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1 += iml2;  /* bytes sent first step */
       iml_len_r -= iml2;                   /* updata remaining data   */
     }
     while (adsl_gather_i_1_w1) {           /* loop over remaining gather structures */
       if (iml_len_r <= 0) break;           /* no more data            */
       iml2 = adsl_gather_i_1_w1->achc_ginp_end - adsl_gather_i_1_w1->achc_ginp_cur;
       if (iml2 > iml_len_r) iml2 = iml_len_r;  /* only remaining data */
       adsl_gai1_o_w1->achc_ginp_cur = adsl_gather_i_1_w1->achc_ginp_cur;  /* here start data */
       adsl_gai1_o_w1->achc_ginp_end = adsl_gather_i_1_w1->achc_ginp_cur + iml2;  /* end of data */
       adsl_gai1_o_w1->adsc_next = adsl_gai1_o_w1 + 1;
       adsl_gai1_o_w1++;                    /* next output to next gather */
       adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1 += iml2;  /* bytes sent first step */
       iml_len_r -= iml2;                   /* updata remaining data   */
       adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     }
     (adsl_gai1_o_w1 - 1)->adsc_next = NULL;  /* end of chain          */
     /* lock data in memory                                            */
     adsl_gai1_o_w1 = ADSL_GAI1_O1;         /* output here             */
     do {                                   /* loop over gather output data */
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
       dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-inc file data adsl_gai1_o_w1->achc_ginp_cur=%p.",
                     __LINE__, adsl_gai1_o_w1->achc_ginp_cur );
#endif
       bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                    DEF_AUX_MARK_WORKAREA_INC,  /* increment usage count in work area */
                                                    adsl_gai1_o_w1->achc_ginp_cur,
                                                    0 );
       adsl_gai1_o_w1 = adsl_gai1_o_w1->adsc_next;  /* get next in chain */
     } while (adsl_gai1_o_w1);
     adsl_rdpvch1_file_w1->iec_fist = ied_fist_read_file;  /* read next part of file */
     if ((adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1
            - adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_2)
              <= adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_max_diff_window) {
       break;
     }
#ifdef TRACEHL1
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T set ied_fist_wait_window ilc_window_1=%lld ilc_window_2=%lld.",
                   __LINE__,
                   adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1,
                   adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_2 );
#endif
     adsl_rdpvch1_file_w1->iec_fist = ied_fist_wait_window;  /* wait for window to be extended */
     adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
#ifdef XYZ1
     return ied_sdhr1_failed;               /* do not send data to server */
#endif
     break;
   }
#undef ADSL_GAI1_O1
#ifdef OLD01
// 12.11.07 to-do if window to small, wait for data sent
#endif

   p_start_req:                             /* start the request       */
   /* start request to service                                         */
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_requ;  /* service request */
   dsl_aux_sequ1.vpc_sequ_handle
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->vpc_sequ_handle;  /* handle of service query */
   dsl_aux_sequ1.ac_control_area = &adsl_rdpvch1_file_w1->dsc_sevchcontr1;  /* control area request */
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                DEF_AUX_SERVICE_REQUEST,  /* service request */
                                                &dsl_aux_sequ1,
                                                sizeof(struct dsd_aux_service_query_1) );
   if (bol1 == FALSE) return ied_sdhr1_fatal_error;  /* fatal error occured, abend */
   /* lock memory areas                                                */
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-inc start-request ADSL_SEVCHREQ1=%p ...->iec_vchreq1=%d.",
                 __LINE__, ADSL_SEVCHREQ1, ADSL_SEVCHREQ1->iec_vchreq1 );
#endif
   bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                DEF_AUX_MARK_WORKAREA_INC,  /* increment usage count in work area */
                                                ADSL_SEVCHREQ1,
                                                0 );
   if (bol1 == FALSE) return ied_sdhr1_fatal_error;  /* fatal error occured, abend */
   adsp_p1->boc_callrevdir = TRUE;          /* call on reverse direction */
#ifdef B111012
   return ied_sdhr1_failed;                 /* do not send data to server */
#else
   iel_sdh_ret1 = ied_sdhr1_failed;         /* do not send data to server */
   goto p_more_00;                          /* check more flag         */
#endif
#undef ADSL_SEVCHREQ1

   p_file_too_big_00:                       /* file is too big         */
   adsl_rdpvch1_file_w1->imc_len_error
     = sprintf( chrl_work1, "file-size %s - too big to be Virus-Checked",
                m_edit_dec_long( chrl_ns_num, ill1 ) );
   adsl_rdpvch1_file_w1->achc_ret_error = (char *) m_aux_stor_alloc(
                                            adsp_p1->adsc_stor_sdh_1,
                                            adsl_rdpvch1_file_w1->imc_len_error );
   memcpy( adsl_rdpvch1_file_w1->achc_ret_error, chrl_work1, adsl_rdpvch1_file_w1->imc_len_error );
   adsl_rdpvch1_file_w1->chc_open_error = 0X12;  /* return open error to server */
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
   adsp_p1->boc_callrevdir = TRUE;          /* call on reverse direction */
#ifdef B111012
   return ied_sdhr1_failed;                 /* do not send data to server */
#else
   iel_sdh_ret1 = ied_sdhr1_failed;         /* do not send data to server */
   goto p_more_00;                          /* check more flag         */
#endif

   p_send_resp_open:                        /* virus checking not needed, send response open to server */
#ifdef B091119
   adsl_rdpvch1_file_w2->adsc_next = adsl_rdpvch1_file_w1->adsc_next;  /* remove request from chain */
   free( adsl_rdpvch1_file_w1 );            /* free memory request     */
#else
   if (adsl_rdpvch1_file_w2 == NULL) {      /* at beginning of chain   */
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file
       = adsl_rdpvch1_file_w1->adsc_next;   /* remove request from chain */
   } else {
     adsl_rdpvch1_file_w2->adsc_next = adsl_rdpvch1_file_w1->adsc_next;  /* remove request from chain */
   }
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1 );
#endif
#ifdef B111012
   return ied_sdhr1_ok;                     /* send packet to server   */
#else
   goto p_more_00;                          /* check more flag         */
#endif

   p_close_00:                              /* close file              */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_rec_tose() return code close %d.",
                 __LINE__, uml_ldm_ret_code );
#endif
   if (uml_ldm_ret_code) {                  /* error from close        */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-W close file Virus-Checked returned 0X%08X.",
                   __LINE__, uml_ldm_ret_code );
   }
   /* do cleanup                                                       */
   if (adsl_rdpvch1_file_w2 == NULL) {      /* remove at anchor of chain */
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file
        = adsl_rdpvch1_file_w1->adsc_next;  /* set new anchor          */
   } else {                                 /* remove middle in chain  */
     adsl_rdpvch1_file_w2->adsc_next = adsl_rdpvch1_file_w1->adsc_next;  /* remove from chain */
   }
   /* free file-name                                                   */
#ifdef B120112
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
#else
   if (adsl_rdpvch1_file_w1->achc_ret_name) {  /* storage with name exists */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
   }
#endif
   if (adsl_rdpvch1_file_w1->achc_ret_error) {
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_error );
   }
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1 );
#ifdef B111012
   return ied_sdhr1_failed;                 /* do not send data to server */
#else
   iel_sdh_ret1 = ied_sdhr1_failed;         /* do not send data to server */
   goto p_more_00;                          /* check more flag         */
#endif

   p_rdpdr_00:                              /* is not HOB channel      */
   if (adsp_p1->adsc_conf->boc_disa_ms_ldm == FALSE) {  /* not disable MS local-drive-mapping */
#ifdef B111012
     return ied_sdhr1_ok;                   /* send packet to server   */
#else
     goto p_more_00;                        /* check more flag         */
#endif
   }
   if (((adsp_p1->chrc_vch_segfl[0] & 1)
         ^ adsp_p1->adsc_rdp_vc_1->chc_tose_segfl) == 0) {
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
   if (adsp_p1->chrc_vch_segfl[0] & 1) {    /* first packet in chain   */
     adsp_p1->adsc_rdp_vc_1->chc_tose_segfl = 1;
     adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 1;  /* to server status 1, read header */
     adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
     adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3 = 0;  /* to server status 3, result */
   }
   if (adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 == 0) {  /* to server status 1, overread packet */
     if (adsp_p1->chrc_vch_segfl[0] & 2) {
       adsp_p1->adsc_rdp_vc_1->chc_tose_segfl = 0;
     }
#ifdef B111012
     return ied_sdhr1_ok;                   /* send packet to server   */
#else
     goto p_more_00;                        /* check more flag         */
#endif
   }
#ifndef B100201
#define IML_PCH_SAVE_DEVCO *((int *) ((char *) (adsl_pch_save_1_first + 1) + sizeof(usrs_ms_cli_anno_01)))
#define UML_VCH_ULEN (adsl_pch_save_1_first->umc_vch_ulen)  /* length of total chain */
#endif
   if (adsp_p1->adsc_rdp_vc_1->ac_tose_pch_save_1_save) {  /* save data from this channel */
     adsl_pch_save_1_first = (struct dsd_pch_save_1 *) adsp_p1->adsc_rdp_vc_1->ac_tose_pch_save_1_save;  /* get save data from this channel */
     adsl_pch_save_1_w1 = adsl_pch_save_1_first;  /* get first block   */
     while (adsl_pch_save_1_w1->adsc_next) {  /* loop to search last in chain */
       adsl_pch_save_1_w1 = adsl_pch_save_1_w1->adsc_next;  /* get next in chain */
     }
#ifndef B100201
     UML_VCH_ULEN += adsp_p1->imc_len_vch_input;  /* length of total chain */
#endif
   }
   adsl_gather_i_1_w1 = adsp_p1->adsc_gather_i_1_in;
   iml_len_r = adsp_p1->imc_len_vch_input;

   p_rdpdr_sc_00:                           /* scan input              */
   if (adsl_gather_i_1_w1 == NULL) return ied_sdhr1_fatal_error;
   achl1 = adsl_gather_i_1_w1->achc_ginp_cur;

   p_rdpdr_sc_04:                           /* scan input              */
   if (iml_len_r <= 0) goto p_rdpdr_sc_60;  /* end of input            */
   iml_len_d = adsl_gather_i_1_w1->achc_ginp_end - achl1;
   if (iml_len_d <= 0) {                    /* no more data            */
     adsl_gather_i_1_w1 = adsl_gather_i_1_w1->adsc_next;  /* get next in chain */
     goto p_rdpdr_sc_00;                    /* scan input              */
   }
   if (iml_len_d > iml_len_r) iml_len_d = iml_len_r;

   p_rdpdr_sc_20:                           /* get part of input       */
   switch (adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1) {  /* to server status 1, overread packet */
     case 1:                                /* get header              */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3
           |= ((unsigned char) *achl1) << ((3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3
             != (RDPDR_CTYP_CORE | (PAKID_CORE_DEVICELIST_ANNOUNCE << 16))) {
         adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 0;  /* to server status 1, overread packet */
         if (adsp_p1->chrc_vch_segfl[0] & 2) {
           adsp_p1->adsc_rdp_vc_1->chc_tose_segfl = 0;
         }
#ifdef B111012
         return ied_sdhr1_ok;               /* send packet to server   */
#else
         goto p_more_00;                    /* check more flag         */
#endif
       }
       adsl_pch_save_1_w1 = (struct dsd_pch_save_1 *) m_aux_stor_alloc(
                              adsp_p1->adsc_stor_sdh_1,
                              sizeof(struct dsd_pch_save_1) + CHANNEL_CHUNK_LENGTH );
       memset( adsl_pch_save_1_w1, 0, sizeof(struct dsd_pch_save_1) );
//     adsl_pch_save_1_w1->adsc_next = NULL;  /* next in chain           */
       adsl_pch_save_1_w1->achc_filled = (char *) (adsl_pch_save_1_w1 + 1)
                                           + sizeof(usrs_ms_cli_anno_01)
                                           + sizeof(int);  /* filled so far */
       adsl_pch_save_1_w1->adsc_rdp_vc_1 = adsp_p1->adsc_rdp_vc_1;  /* RDP virtual channel */
       adsl_pch_save_1_w1->chc_segfl = 1;   /* segmentation flag       */
       adsl_pch_save_1_first = adsl_pch_save_1_w1;
       adsp_p1->adsc_rdp_vc_1->ac_tose_pch_save_1_save = adsl_pch_save_1_w1;  /* save data from this channel */
       memcpy( adsl_pch_save_1_w1 + 1, usrs_ms_cli_anno_01, sizeof(usrs_ms_cli_anno_01) );
#ifdef B100201
#define IML_PCH_SAVE_DEVCO *((int *) ((char *) (adsl_pch_save_1_w1 + 1) + sizeof(usrs_ms_cli_anno_01)))
#endif
       IML_PCH_SAVE_DEVCO = 0;              /* clear DeviceCount       */
#ifndef B100201
       UML_VCH_ULEN = adsp_p1->imc_len_vch_input;  /* length of total chain */
#endif
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 2;  /* to server status 1, read DeviceCount */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3 = 0;  /* to server status 3, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 2:                                /* get DeviceCount         */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3
           |= ((unsigned char) *achl1) << (( 3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3 <= 0) return ied_sdhr1_fatal_error;
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 3;  /* to server status 1, read DeviceType */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 3:                                /* get DeviceType          */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4
           |= ((unsigned char) *achl1) << ((3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 == RDPDR_DTYP_FILESYSTEM) {
         adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 4;  /* to server status 1, DeviceId for Disk Filesystem */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, DeviceId */
         goto p_rdpdr_sc_20;                /* get part of input       */
       }
       IML_PCH_SAVE_DEVCO = IML_PCH_SAVE_DEVCO + 1;  /* increment DeviceCount */
       chrl_work1[0] = (unsigned char) adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;
       chrl_work1[1] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 8);
       chrl_work1[2] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 16);
       chrl_work1[3] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 24);
       m_copy_tose_save( adsp_p1, &adsl_pch_save_1_w1, chrl_work1, 4 );
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 8;  /* to server status 1, overread data */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 12;  /* to server status 2, length */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 4:                                /* get DeviceId for Disk Filesystem */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4
           |= ((unsigned char) *achl1) << ((3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
#define ADSL_PCHS2 adsl_pch_save_1_first->adsc_pchs2
       if (ADSL_PCHS2 == NULL) {            /* send Server Device Announce Response */
         ADSL_PCHS2 = (struct dsd_pch_save_2 *) m_aux_stor_alloc(
                              adsp_p1->adsc_stor_sdh_1,
                              sizeof(struct dsd_pch_save_2)
                                + adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3 * 4 );
//       memset( ADSL_PCHS2, 0, sizeof(struct dsd_pch_save_2) );
         ADSL_PCHS2->adsc_next = NULL;
         ADSL_PCHS2->adsc_rdp_vc_1 = adsp_p1->adsc_rdp_vc_1;  /* RDP virtual channel */
         ADSL_PCHS2->achc_filled = (char *) (ADSL_PCHS2 + 1);
         ADSL_PCHS2->achc_removed = (char *) (ADSL_PCHS2 + 1);
       }
       *(ADSL_PCHS2->achc_filled)++ = (unsigned char) adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;
       *(ADSL_PCHS2->achc_filled)++ = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 8);
       *(ADSL_PCHS2->achc_filled)++ = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 16);
       *(ADSL_PCHS2->achc_filled)++ = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 << 24);
#undef ADSL_PCHS2
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 5;  /* to server status 1, overread data */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 8;  /* to server status 2, length */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 5:                                /* overread data           */
       if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input          */
       iml1 = iml_len_d;
       if (iml1 > adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) {
         iml1 = adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2;
       }
       achl1 += iml1;
       iml_len_r -= iml1;                   /* decrement length remaining */
       iml_len_d -= iml1;                   /* decrement length this chunk */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 -= iml1;
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0) goto p_rdpdr_sc_04;  /* scan input */
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 6;  /* to server status 1, read DeviceDataLength */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 6:                                /* get DeviceDataLength    */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4
           |= ((unsigned char) *achl1) << ((3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3--;  /* one device processed */
#ifndef B100201
       UML_VCH_ULEN -= 12 + adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;  /* length of total chain */
#endif
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 == 0) {
         adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 3;  /* to server status 1, read DeviceType */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
         goto p_rdpdr_sc_20;                /* get part of input       */
       }
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 7;  /* to server status 1, read DeviceData */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 7:                                /* get DeviceData          */
       if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
       iml1 = iml_len_d;
       if (iml1 > adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4) {
         iml1 = adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;
       }
       achl1 += iml1;
       iml_len_r -= iml1;                   /* decrement length remaining */
       iml_len_d -= iml1;                   /* decrement length this chunk */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 -= iml1;
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 > 0) goto p_rdpdr_sc_04;  /* scan input */
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 3;  /* to server status 1, read DeviceType */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
   /* the following cases are for copying the data to be sent          */
     case 8:                                /* overread data           */
       if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input          */
       iml1 = iml_len_d;
       if (iml1 > adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) {
         iml1 = adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2;
       }
       m_copy_tose_save( adsp_p1, &adsl_pch_save_1_w1, achl1, iml1 );
       achl1 += iml1;
       iml_len_r -= iml1;                   /* decrement length remaining */
       iml_len_d -= iml1;                   /* decrement length this chunk */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 -= iml1;
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0) goto p_rdpdr_sc_04;  /* scan input */
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 9;  /* to server status 1, read DeviceDataLength */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 9:                                /* get DeviceDataLength    */
       do {
         if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2--;
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4
           |= ((unsigned char) *achl1) << ((3 - adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2) << 3);
         achl1++;
         iml_len_r--;                       /* decrement length remaining */
         iml_len_d--;                       /* decrement length this chunk */
       } while (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 > 0);
       chrl_work1[0] = (unsigned char) adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;
       chrl_work1[1] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 >> 8);
       chrl_work1[2] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 >> 16);
       chrl_work1[3] = (unsigned char) (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 >> 24);
       m_copy_tose_save( adsp_p1, &adsl_pch_save_1_w1, chrl_work1, 4 );
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3--;  /* one device processed */
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 == 0) {
         adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 3;  /* to server status 1, read DeviceType */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
         adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
         goto p_rdpdr_sc_20;                /* get part of input       */
       }
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 10;  /* to server status 1, read DeviceData */
       goto p_rdpdr_sc_20;                  /* get part of input       */
     case 10:                               /* get DeviceData          */
       if (iml_len_d <= 0) goto p_rdpdr_sc_04;  /* scan input        */
       iml1 = iml_len_d;
       if (iml1 > adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4) {
         iml1 = adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4;
       }
       m_copy_tose_save( adsp_p1, &adsl_pch_save_1_w1, achl1, iml1 );
       achl1 += iml1;
       iml_len_r -= iml1;                   /* decrement length remaining */
       iml_len_d -= iml1;                   /* decrement length this chunk */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 -= iml1;
       if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 > 0) goto p_rdpdr_sc_04;  /* scan input */
       adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 = 3;  /* to server status 1, read DeviceType */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 = 4;  /* to server status 2, length */
       adsp_p1->adsc_rdp_vc_1->imc_tose_stat_4 = 0;  /* to server status 4, result */
       goto p_rdpdr_sc_20;                  /* get part of input       */
   }

   p_rdpdr_sc_60:                           /* end of input            */
   if ((adsp_p1->chrc_vch_segfl[0] & 2) == 0) {  /* not last segment   */
#ifdef B111012
     return ied_sdhr1_failed;               /* do not send data to server */
#else
     iel_sdh_ret1 = ied_sdhr1_failed;       /* do not send data to server */
     goto p_more_00;                        /* check more flag         */
#endif
   }
   if (adsp_p1->adsc_rdp_vc_1->chc_tose_stat_1 != 3) return ied_sdhr1_fatal_error;  /* to server status 1, read DeviceType */
   if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_2 != 4) return ied_sdhr1_fatal_error;  /* to server status 2, length */
   if (adsp_p1->adsc_rdp_vc_1->imc_tose_stat_3 != 0) return ied_sdhr1_fatal_error;  /* to server status 3, DeviceCount */
   adsp_p1->adsc_rdp_vc_1->chc_tose_segfl = 0;
   if (   (adsl_pch_save_1_first->adsc_pchs2 == NULL)
       && (adsl_pch_save_1_w1 == adsl_pch_save_1_first)
       && (adsp_p1->chrc_vch_segfl[0] & 1)) {  /* was first segment    */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_pch_save_1_first );
     adsp_p1->adsc_rdp_vc_1->ac_tose_pch_save_1_save = NULL;  /* save data from this channel */
#ifdef B111012
     return ied_sdhr1_ok;                   /* send packet to server   */
#else
     goto p_more_00;                        /* check more flag         */
#endif
   }
#ifndef B111012
   iel_sdh_ret1 = ied_sdhr1_failed;         /* do not send data to server */
#endif
   if (adsl_pch_save_1_first->adsc_pchs2) {  /* needs Server Device Announce Response */
     if (adsp_p1->dsc_s1.ac_frse_pch_save_2_send == NULL) {  /* send data from this channel */
       adsp_p1->dsc_s1.ac_frse_pch_save_2_send = adsl_pch_save_1_first->adsc_pchs2;
     } else {
       adsl_pch_save_2_w1 = (struct dsd_pch_save_2 *) adsp_p1->dsc_s1.ac_frse_pch_save_2_send;
       while (adsl_pch_save_2_w1->adsc_next) adsl_pch_save_2_w1 = adsl_pch_save_2_w1->adsc_next;
       adsl_pch_save_2_w1->adsc_next = adsl_pch_save_1_first->adsc_pchs2;
     }
     adsp_p1->boc_callrevdir = TRUE;        /* call on reverse direction */
   }
   iml1 = IML_PCH_SAVE_DEVCO;               /* has to send little endian */
   if (iml1 == 0) {                         /* nothing left to send    */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_pch_save_1_first );
     adsp_p1->adsc_rdp_vc_1->ac_tose_pch_save_1_save = NULL;  /* save data from this channel */
#ifdef B111012
     return ied_sdhr1_failed;               /* do not send data to server */
#else
     goto p_more_00;                        /* check more flag         */
#endif
   }
#ifdef B110525
   *((char *) (adsl_pch_save_1_w1 + 1) + sizeof(usrs_ms_cli_anno_01) + 0) = (unsigned char) iml1;
   *((char *) (adsl_pch_save_1_w1 + 1) + sizeof(usrs_ms_cli_anno_01) + 1) = (unsigned char) (iml1 << 8);
   *((char *) (adsl_pch_save_1_w1 + 1) + sizeof(usrs_ms_cli_anno_01) + 2) = (unsigned char) (iml1 << 16);
   *((char *) (adsl_pch_save_1_w1 + 1) + sizeof(usrs_ms_cli_anno_01) + 3) = (unsigned char) (iml1 << 24);
#else
   /* put total length in first packet                                 */
   *((char *) (adsl_pch_save_1_first + 1) + sizeof(usrs_ms_cli_anno_01) + 0) = (unsigned char) iml1;
   *((char *) (adsl_pch_save_1_first + 1) + sizeof(usrs_ms_cli_anno_01) + 1) = (unsigned char) (iml1 << 8);
   *((char *) (adsl_pch_save_1_first + 1) + sizeof(usrs_ms_cli_anno_01) + 2) = (unsigned char) (iml1 << 16);
   *((char *) (adsl_pch_save_1_first + 1) + sizeof(usrs_ms_cli_anno_01) + 3) = (unsigned char) (iml1 << 24);
#endif
   adsl_pch_save_1_w1->chc_segfl |= 2;      /* segmentation flag, last segment */
   if (adsp_p1->dsc_s1.ac_tose_pch_save_1_send == NULL) {  /* send data from this channel */
     adsp_p1->dsc_s1.ac_tose_pch_save_1_send = adsl_pch_save_1_first;  /* send data from this channel */
#ifdef B111012
     return ied_sdhr1_failed;               /* do not send data to server */
#else
     goto p_more_00;                        /* check more flag         */
#endif
   }
   adsl_pch_save_1_w1 = (struct dsd_pch_save_1 *) adsp_p1->dsc_s1.ac_tose_pch_save_1_send;
   while (adsl_pch_save_1_w1->adsc_next) adsl_pch_save_1_w1 = adsl_pch_save_1_w1->adsc_next;
   adsl_pch_save_1_w1->adsc_next = adsl_pch_save_1_first;
#ifdef B111012
   return ied_sdhr1_failed;                 /* do not send data to server */
#endif
#undef IML_PCH_SAVE_DEVCO

   p_more_00:                               /* check more flag         */
   if (((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file == NULL) {
#ifdef B111012
     return ied_sdhr1_ok;
#else
     return iel_sdh_ret1;                   /* return value            */
#endif
   }
   bol1 = FALSE;
   if (ucl_subchn & 0X80) {                 /* with more flag          */
     bol1 = TRUE;
   }
   adsl_rdpvch1_file_w1 = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
   do {                                     /* loop over all files currently processed */
     if ((adsl_rdpvch1_file_w1->chc_subchn & 0X7F) == (ucl_subchn & 0X7F)) {  /* sub-channel no */
       adsl_rdpvch1_file_w1->boc_more_cl2se = bol1;  /* more bit client to server in datastream */
     }
     adsl_rdpvch1_file_w1 = adsl_rdpvch1_file_w1->adsc_next;  /* get next in chain */
   } while (adsl_rdpvch1_file_w1);
#ifdef B111012
   return ied_sdhr1_ok;
#else
   return iel_sdh_ret1;                     /* return value            */
#endif
} /* end m_rdp_vch1_rec_tose()                                         */

extern "C" ied_sdh_ret1 m_rdp_vch1_get_frse( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
#ifndef B120119
   BOOL       bol1;                         /* working variable        */
#endif
   char       *achl_buf;                    /* buffer command createfile */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w1;  /* structure of file */
   struct dsd_pch_save_2 *adsl_pch_save_2_w1;  /* save data from virtual channel */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
#ifndef B120119
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
#endif

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_frse( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
   if (adsp_p1->ac_chain_send_frse == NULL) {  /* chain of buffers to be sent to the client */
     goto p_get_frse_20;                    /* check send packets to client */
   }
   achl_buf = (char *) adsp_p1->ac_chain_send_frse;  /* get chain of buffers to be sent to the client */
   adsp_p1->ac_chain_send_frse = *((void **) achl_buf);  /* remove from chain of buffers to be sent to the client */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_sc_vch_out);
#else
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_rdp_vch_io);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) adsp_p1->adsc_output_area_1->achc_upper)
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) adsp_p1->adsc_output_area_1->achc_upper)
#endif
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (achl_buf + 2 * sizeof(void *)))
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = (struct dsd_rdp_vc_1 *) *((void **) (achl_buf + (2 - 1) * sizeof(void *)));
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen
     = ADSL_GAI1_O1->achc_ginp_end - ADSL_GAI1_O1->achc_ginp_cur;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   return ied_sdhr1_ok;                     /* send packet to client   */

   p_get_frse_20:                           /* check send packets to client */
   if (adsp_p1->dsc_s1.ac_frse_pch_save_2_send == NULL) {  /* send data from this channel */
     goto p_get_frse_40;                    /* check if virus checking is processed */
   }
   adsl_pch_save_2_w1 = (struct dsd_pch_save_2 *) adsp_p1->dsc_s1.ac_frse_pch_save_2_send;  /* save data from virtual channel */
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += sizeof(usrs_ms_serv_dev_repl_01);
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
   memcpy( achl_buf, usrs_ms_serv_dev_repl_01, sizeof(usrs_ms_serv_dev_repl_01) );
   memcpy( achl_buf + 4, adsl_pch_save_2_w1->achc_removed, 4 );
   adsl_pch_save_2_w1->achc_removed += 4;
   if (adsl_pch_save_2_w1->achc_removed >= adsl_pch_save_2_w1->achc_filled) {
     adsp_p1->dsc_s1.ac_frse_pch_save_2_send = adsl_pch_save_2_w1->adsc_next;  /* remove from chain */
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_pch_save_2_w1 );
   }
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_sc_vch_out)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_rdp_vch_io)))
#endif
   memset( ADSL_GAI1_O1, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + sizeof(usrs_ms_serv_dev_repl_01);
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1 = adsl_pch_save_2_w1->adsc_rdp_vc_1;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = sizeof(usrs_ms_serv_dev_repl_01);
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;  /* segmentation flag    */
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   return ied_sdhr1_ok;                     /* send packet to server   */

   p_get_frse_40:                           /* check if virus checking is processed */
   if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
#define LEN_CO_CF 50
   adsl_rdpvch1_file_w1 = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
   while (adsl_rdpvch1_file_w1) {           /* loop over all open files */
     if (adsl_rdpvch1_file_w1->boc_more_se2cl == FALSE) {  /* more bit server to client in datastream */
       switch (adsl_rdpvch1_file_w1->iec_fist) {
         case ied_fist_read_file:           /* read next part of file  */
           goto p_send_read_00;             /* send read request       */
         case ied_fist_wait_window:         /* wait for window to be extended */
#ifdef TRACEHL1
           m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_frse() adsl_rdpvch1_file_w1=%p boc_wait_window=%d ilc_window_1=%lld ilc_window_2=%lld.",
                         __LINE__, adsl_rdpvch1_file_w1, adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window,
                         adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1, adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_2 );
#endif
           if (adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window) break;  /* wait till window smaller */
           adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
           if ((adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_1
                  - adsl_rdpvch1_file_w1->dsc_sevchcontr1.ilc_window_2)
                    > adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_max_diff_window) {
             break;
           }
           adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window = FALSE;  /* no wait till window smaller */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_read_file;  /* read next part of file */
           goto p_send_read_00;             /* send read request       */
         case ied_fist_send_open:           /* send open command       */
           goto p_send_open_00;             /* send open request       */
         case ied_fist_client_send_close:   /* send close to client    */
           goto p_send_close_00;            /* send close request      */
       }
     }
     adsl_rdpvch1_file_w1 = adsl_rdpvch1_file_w1->adsc_next;  /* get next in chain */
   }
   return ied_sdhr1_ok;                     /* nothing to send         */

   p_send_open_00:                          /* send open request       */
   /* send real command open file to client                            */
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_CO_CF;  /* length command createfile */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + 2 * sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + 2 * sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O2 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) (adsp_p1->adsc_output_area_1->achc_upper + 2 * sizeof(struct dsd_gather_i_1)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) (adsp_p1->adsc_output_area_1->achc_upper + 2 * sizeof(struct dsd_gather_i_1)))
#endif
   *(achl_buf + 0) = (char) adsl_rdpvch1_file_w1->chc_subchn;
   memcpy( achl_buf + 1, &adsl_rdpvch1_file_w1->umc_ldm_handle, sizeof(adsl_rdpvch1_file_w1->umc_ldm_handle) );
   memcpy( achl_buf + 5, &adsl_rdpvch1_file_w1->umc_ldm_req_id, sizeof(adsl_rdpvch1_file_w1->umc_ldm_req_id) );
   memset( achl_buf + 9, 0, 8 );
   memcpy( achl_buf + 17, &adsl_rdpvch1_file_w1->umc_ldm_access_mask, sizeof(adsl_rdpvch1_file_w1->umc_ldm_access_mask) );
   memset( achl_buf + 21, 0, 16 );
   memcpy( achl_buf + 37, &adsl_rdpvch1_file_w1->umc_ldm_create_disposition, sizeof(adsl_rdpvch1_file_w1->umc_ldm_create_disposition) );
   memset( achl_buf + 41, 0, 4 );
   *(achl_buf + 45 + 0) = (unsigned char) adsl_rdpvch1_file_w1->imc_len_name;
   *(achl_buf + 45 + 1) = (unsigned char) (adsl_rdpvch1_file_w1->imc_len_name >> 8);
   *(achl_buf + 45 + 2) = (unsigned char) (adsl_rdpvch1_file_w1->imc_len_name >> 16);
   *(achl_buf + 45 + 3) = (unsigned char) (adsl_rdpvch1_file_w1->imc_len_name >> 24);
   *(achl_buf + 49) = (char) adsl_rdpvch1_file_w1->chc_flag_full_path;
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + LEN_CO_CF;
   ADSL_GAI1_O1->adsc_next = ADSL_GAI1_O2;
   ADSL_GAI1_O2->achc_ginp_cur = (char *) (adsl_rdpvch1_file_w1 + 1);
   ADSL_GAI1_O2->achc_ginp_end = (char *) (adsl_rdpvch1_file_w1 + 1) + adsl_rdpvch1_file_w1->imc_len_name;
   ADSL_GAI1_O2->adsc_next = NULL;
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_frse;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = LEN_CO_CF + adsl_rdpvch1_file_w1->imc_len_name;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_GAI1_O2
#undef ADSL_SC_VCH_OUT
#undef LEN_CO_CF
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_wait_repl_open;  /* wait for reply for open */
#ifdef TRACEHL1
   printf( "xsrdpvch1.cpp l%05d m_rdp_vch1_get_frse() send CreateFile adsl_rdpvch1_file_w1=%p\n",
           __LINE__, adsl_rdpvch1_file_w1 );
#endif
   return ied_sdhr1_ok;

   p_send_read_00:                          /* send read request       */
   /* first check if already error received from virus checking        */
   if (adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_active) {  /* virus checking not active */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_frse() p_send_read_00 adsl_rdpvch1_file_w1=%p iec_vchcompl=%d.",
                   __LINE__, adsl_rdpvch1_file_w1, adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl );
#endif
     return ied_sdhr1_ok;
   }
#define LEN_CO_RF 49
#ifdef TRACEHL1
   printf( "xsrdpvch1.cpp l%05d m_rdp_vch1_get_frse() send ReadFile adsl_rdpvch1_file_w1=%p.\n",
           __LINE__, adsl_rdpvch1_file_w1 );
#endif
   /* send real command read file to client                            */
#ifdef B120119
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_CO_RF;  /* length command readfile */
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#endif
#ifndef B120119
#ifdef B120410
   if ((adsp_p1->adsc_output_area_1->achc_lower + LEN_CO_RF)
         > (adsp_p1->adsc_output_area_1->achc_upper
              - sizeof(struct dsd_sc_vch_out) - sizeof(struct dsd_gather_i_1) - sizeof(void *))) {
#ifdef FORKEDIT
   }
#endif
#else
   if ((adsp_p1->adsc_output_area_1->achc_lower + LEN_CO_RF)
         > (adsp_p1->adsc_output_area_1->achc_upper
              - sizeof(struct dsd_rdp_vch_io) - sizeof(struct dsd_gather_i_1) - sizeof(void *))) {
#endif
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                  DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                  &dsl_aux_get_workarea,
                                                  sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E acquire work-area returned FALSE",
                     __LINE__ );
       return ied_sdhr1_fatal_error;        /* fatal error occured, abend */
     }
     adsp_p1->adsc_output_area_1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     adsp_p1->adsc_output_area_1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
#ifdef B121003
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = adsp_p1->adsc_output_area_1->achc_lower;
#ifdef B120424
     if (adsp_p1->adsc_output_area_1->adsc_gai1_o1 == NULL) {
     adsp_p1->adsc_output_area_1->adsc_gai1_o1 = ADSL_GAI1_OUT_G;
     } else {
       adsp_p1->adsc_output_area_1->adsc_gai1_o1->adsc_next = ADSL_GAI1_OUT_G;
     }
     adsp_p1->adsc_output_area_1->adsc_gai1_o1 = ADSL_GAI1_OUT_G;  /* this is last one */
#else
     *adsp_p1->adsc_output_area_1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     adsp_p1->adsc_output_area_1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#endif
#undef ADSL_GAI1_OUT_G
#endif
   }
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_CO_RF;  /* length command readfile */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
#endif
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#endif
   *(achl_buf + 0) = (char) adsl_rdpvch1_file_w1->chc_subchn;
   memcpy( achl_buf + 1, &adsl_rdpvch1_file_w1->umc_ldm_handle, sizeof(adsl_rdpvch1_file_w1->umc_ldm_handle) );
#ifndef VALID_REQ_ID  /* to-do 14.11.07 KB */
   adsl_rdpvch1_file_w1->umc_ldm_req_id++;
#endif
   memcpy( achl_buf + 5, &adsl_rdpvch1_file_w1->umc_ldm_req_id, sizeof(adsl_rdpvch1_file_w1->umc_ldm_req_id) );
   *(achl_buf + 9) = (unsigned char) 0X03;  /* command read            */
   memset( achl_buf + 9 + 1, 0, 8 - 1 );
   *(achl_buf + 17 + 0) = (unsigned char) D_HOBLDM_LEN_READ;
   *(achl_buf + 17 + 1) = (unsigned char) (D_HOBLDM_LEN_READ >> 8);
   *(achl_buf + 17 + 2) = (unsigned char) (D_HOBLDM_LEN_READ >> 16);
   *(achl_buf + 17 + 3) = (unsigned char) (D_HOBLDM_LEN_READ >> 24);
   *(achl_buf + 21 + 0) = (unsigned char) adsl_rdpvch1_file_w1->ilc_read_disp;
   *(achl_buf + 21 + 1) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 8);
   *(achl_buf + 21 + 2) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 16);
   *(achl_buf + 21 + 3) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 24);
   *(achl_buf + 21 + 4) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 32);
   *(achl_buf + 21 + 5) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 40);
   *(achl_buf + 21 + 6) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 48);
   *(achl_buf + 21 + 7) = (unsigned char) (adsl_rdpvch1_file_w1->ilc_read_disp >> 56);
   memset( achl_buf + 29, 0, 20 );
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + LEN_CO_RF;
   ADSL_GAI1_O1->adsc_next = NULL;
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_frse;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = LEN_CO_RF;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
#undef LEN_CO_RF
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_wait_repl_read;  /* wait for reply for read */
   return ied_sdhr1_ok;

   p_send_close_00:                         /* send close request      */
#define LEN_CO_CF 49
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_frse() send close adsl_rdpvch1_file_w1=%p.",
                 __LINE__, adsl_rdpvch1_file_w1 );
#endif
   /* send real command close handle to client                         */
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_CO_CF;  /* length command close */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#endif
   *(achl_buf + 0) = (char) adsl_rdpvch1_file_w1->chc_subchn;
   memcpy( achl_buf + 1, &adsl_rdpvch1_file_w1->umc_ldm_handle, sizeof(adsl_rdpvch1_file_w1->umc_ldm_handle) );
#ifndef VALID_REQ_ID  /* to-do 14.11.07 KB */
   adsl_rdpvch1_file_w1->umc_ldm_req_id++;
#endif
   memcpy( achl_buf + 5, &adsl_rdpvch1_file_w1->umc_ldm_req_id, sizeof(adsl_rdpvch1_file_w1->umc_ldm_req_id) );
   *(achl_buf + 9) = (unsigned char) 0X02;  /* command close           */
   memset( achl_buf + 9 + 1, 0, (8 - 1) + 32 );
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + LEN_CO_CF;
   ADSL_GAI1_O1->adsc_next = NULL;
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_frse;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = LEN_CO_CF;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
#undef LEN_CO_CF
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_client_wait_close;  /* wait for response close from client */
   return ied_sdhr1_ok;
} /* end m_rdp_vch1_get_frse()                                         */

extern "C" ied_sdh_ret1 m_rdp_vch1_get_tose( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
#ifndef B120209
   BOOL       bol1;                         /* working variable        */
#endif
   int        iml1;                         /* working variable        */
   char       *achl_buf;                    /* buffer command createfile */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w1;  /* structure of file */
   struct dsd_rdpvch1_file *adsl_rdpvch1_file_w2;  /* structure of file */
#ifndef B120209
   struct dsd_se_vch_req_1 *adsl_sevchreq1_cur;  /* current element in chain */
   struct dsd_gather_i_1 *adsl_gai1_o_w1;   /* gather output data      */
#endif
   struct dsd_pch_save_1 *adsl_pch_save_1_w1;  /* save data from virtual channel */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
   if (adsp_p1->ac_chain_send_tose == NULL) {  /* chain of buffers to be sent to the server */
     goto p_get_tose_20;                    /* check send packets to server */
   }
   achl_buf = (char *) adsp_p1->ac_chain_send_tose;  /* get chain of buffers to be sent to the server */
   adsp_p1->ac_chain_send_tose = *((void **) achl_buf);  /* remove from chain of buffers to be sent to the server */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_sc_vch_out);
#else
   adsp_p1->adsc_output_area_1->achc_upper -= sizeof(struct dsd_rdp_vch_io);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) adsp_p1->adsc_output_area_1->achc_upper)
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) adsp_p1->adsc_output_area_1->achc_upper)
#endif
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (achl_buf + 2 * sizeof(void *)))
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = (struct dsd_rdp_vc_1 *) *((void **) (achl_buf + (2 - 1) * sizeof(void *)));
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen
     = ADSL_GAI1_O1->achc_ginp_end - ADSL_GAI1_O1->achc_ginp_cur;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   return ied_sdhr1_ok;                     /* send packet to server   */

   p_get_tose_20:                           /* check send packets to server */
   if (adsp_p1->dsc_s1.ac_tose_pch_save_1_send == NULL) goto p_get_tose_40;  /* check if virus checking is processed */
   adsl_pch_save_1_w1 = (struct dsd_pch_save_1 *) adsp_p1->dsc_s1.ac_tose_pch_save_1_send;
   if (adsl_pch_save_1_w1->boc_sent) {      /* already sent to server  */
     adsp_p1->dsc_s1.ac_tose_pch_save_1_send = adsl_pch_save_1_w1->adsc_next;  /* remove from chain */
#ifndef B100201
     if (adsp_p1->dsc_s1.ac_tose_pch_save_1_send) {  /* segment that follows */
       ((struct dsd_pch_save_1 *) adsp_p1->dsc_s1.ac_tose_pch_save_1_send)->umc_vch_ulen
         = adsl_pch_save_1_w1->umc_vch_ulen;  /* length of total chain */
     }
#endif
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_pch_save_1_w1 );
     goto p_get_tose_20;                    /* check send packets to server */
   }
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_sc_vch_out)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) adsp_p1->adsc_output_area_1->achc_upper)
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_rdp_vch_io)))
#endif
   memset( ADSL_GAI1_O1, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_O1->achc_ginp_cur = (char *) (adsl_pch_save_1_w1 + 1);
   ADSL_GAI1_O1->achc_ginp_end = adsl_pch_save_1_w1->achc_filled;
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1 = adsl_pch_save_1_w1->adsc_rdp_vc_1;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
#ifdef B100201
   ADSL_SC_VCH_OUT->umc_vch_ulen
     = ADSL_GAI1_O1->achc_ginp_end - ADSL_GAI1_O1->achc_ginp_cur;
#else
   ADSL_SC_VCH_OUT->umc_vch_ulen = adsl_pch_save_1_w1->umc_vch_ulen;
#endif
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = adsl_pch_save_1_w1->chc_segfl;  /* segmentation flag */
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   adsl_pch_save_1_w1->boc_sent = TRUE;     /* has been sent to server */
   return ied_sdhr1_ok;                     /* send packet to server   */

   p_get_tose_40:                           /* check if virus checking is processed */
   if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return ied_sdhr1_ok;  /* not configured */
   adsl_rdpvch1_file_w1 = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file;
   adsl_rdpvch1_file_w2 = NULL;             /* clear last in chain     */
   while (adsl_rdpvch1_file_w1) {           /* loop over all open files */
     if (adsl_rdpvch1_file_w1->iec_fist == ied_fist_wait_window) {  /* wait for window to be extended */
#ifdef TRACEHL1
       dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose() adsl_rdpvch1_file_w1=%p boc_wait_window=%d.",
                     __LINE__, adsl_rdpvch1_file_w1, adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window );
#endif
       if (   (adsl_rdpvch1_file_w1->dsc_sevchcontr1.boc_wait_window == FALSE)  /* no more wait till window smaller */
           && (adsl_rdpvch1_file_w1->boc_more_se2cl == FALSE)) {  /* more bit server to client in datastream */
         adsp_p1->boc_callrevdir = TRUE;    /* call on reverse direction */
       }
     }
#ifndef B120209
     /* release storage used                                           */
     while (adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1) {  /* loop to free all requests */
       adsl_sevchreq1_cur = adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1;  /* get request */
       if (   (adsl_sevchreq1_cur->iec_stat != ied_vchstat_done)  /* leave element in chain */
           && (adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl == ied_vchcompl_active)) {  /* virus checking active */
         break;
       }
       adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1 = adsl_sevchreq1_cur->adsc_next;  /* remove from chain */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose() free adsl_sevchreq1_cur=%p.",
                     __LINE__, adsl_sevchreq1_cur );
#endif
       /* storage needs no longer be fixed in memory                   */
       if (adsl_sevchreq1_cur->iec_vchreq1 == ied_vchreq_content) {  /* content of file */
         adsl_gai1_o_w1 = adsl_sevchreq1_cur->adsc_gai1_data;
         while (adsl_gai1_o_w1) {           /* loop over all gather structures */
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
           dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
           dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
           m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-dec file data adsl_gai1_o_w1->achc_ginp_cur=%p.",
                         __LINE__, adsl_gai1_o_w1->achc_ginp_cur );
#endif
           bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                        DEF_AUX_MARK_WORKAREA_DEC,  /* decrement usage count in work area */
                                                        adsl_gai1_o_w1->achc_ginp_cur,
                                                        0 );
           adsl_gai1_o_w1 = adsl_gai1_o_w1->adsc_next;  /* get next in chain */
         }
       }
#ifdef DEBUG_120209_01                      /* mark inc / dec          */
       dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
       m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T mark-dec request adsl_sevchreq1_cur=%p.",
                     __LINE__, adsl_sevchreq1_cur );
#endif
       bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                    DEF_AUX_MARK_WORKAREA_DEC,  /* decrement usage count in work area */
                                                    adsl_sevchreq1_cur,
                                                    0 );
     }
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose() adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1=%p.",
                   __LINE__, adsl_rdpvch1_file_w1->dsc_sevchcontr1.adsc_sevchreq1 );
#endif
#endif
     if (adsl_rdpvch1_file_w1->boc_more_cl2se == FALSE) {  /* more bit client to server in datastream */
       if (   (adsl_rdpvch1_file_w1->iec_fist == ied_fist_return_open_error)  /* return open error */
           || (adsl_rdpvch1_file_w1->iec_fist == ied_fist_return_oe_and_close)) {  /* return open error and close file */
         goto p_return_open_error_00;       /* send open error         */
       }
//   if (adsl_rdpvch1_file_w1->iec_fist == ied_fist_wait_vircheck) {  /* wait for virus checking */
#ifdef OLD01
       if (adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_active) {  /* virus checking not active */
         printf( "UUUU 09.07.08 KB\n" );
         if (adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl == ied_vchcompl_ok) {  /* file has no virus */
           goto p_return_open_ok_00;        /* send open o.k.          */
         }
       }
#endif
       switch (adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl) {  /* check how completed */
         case ied_vchcompl_ok:              /* file has no virus       */
           goto p_return_open_ok_00;        /* send open o.k.          */
         case ied_vchcompl_no_server:       /* the necessary servers not found */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
           adsl_rdpvch1_file_w1->chc_open_error = 0X11;  /* return open error to server */
           goto p_return_open_error_00;     /* send open error         */
         case ied_vchcompl_comm_error:      /* communication error     */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
           adsl_rdpvch1_file_w1->chc_open_error = 0X13;  /* return open error to server */
           goto p_return_open_error_00;     /* send open error         */
         case ied_vchcompl_vch_inv_resp:    /* invalid response from virus checker */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
           adsl_rdpvch1_file_w1->chc_open_error = 0X15;  /* return open error to server */
           goto p_return_open_error_00;     /* send open error         */
         case ied_vchcompl_vch_timeout:     /* timeout while virus checking */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
           adsl_rdpvch1_file_w1->chc_open_error = 0X14;  /* return open error to server */
           goto p_return_open_error_00;     /* send open error         */
         case ied_vchcompl_virus:           /* file contains virus     */
           adsl_rdpvch1_file_w1->iec_fist = ied_fist_return_oe_and_close;  /* return open error and close file */
           adsl_rdpvch1_file_w1->chc_open_error = 0X10;  /* return open error to server */
           goto p_return_open_error_00;     /* send open error         */
       }
       /**
          remaining: ied_vchcompl_active -  virus checking active
                     ied_vchcompl_idle   -  nothing to do
       */
//   }
     }
     adsl_rdpvch1_file_w2 = adsl_rdpvch1_file_w1;  /* save last in chain */
     adsl_rdpvch1_file_w1 = adsl_rdpvch1_file_w1->adsc_next;  /* get next in chain */
   }
   return ied_sdhr1_ok;                     /* nothing to send         */

   p_return_open_error_00:                  /* send open error         */
#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose() adsl_rdpvch1_file_w1=%p p_return_open_error_00 chc_open_error=%d.",
                 __LINE__, adsl_rdpvch1_file_w1, adsl_rdpvch1_file_w1->chc_open_error );
#endif
   adsl_rdpvch1_file_w1->dsc_sevchcontr1.iec_vchcompl = ied_vchcompl_idle;  /* nothing to do */
   iml1 = adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_len_virus_name;  /* length returned virus name */
   if (iml1 > 0) iml1 += sizeof(ucrs_found_virus_00);
   else iml1 = adsl_rdpvch1_file_w1->imc_len_error;
#define LEN_RET_ERROR 17
   /* send real response open file to server                           */
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_RET_ERROR + iml1;  /* length return values */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#endif
   *(achl_buf + 0) = (char) adsl_rdpvch1_file_w1->chc_subchn;
   memcpy( achl_buf + 1, &adsl_rdpvch1_file_w1->umc_ldm_req_id, sizeof(adsl_rdpvch1_file_w1->umc_ldm_req_id) );
   *(achl_buf + 5) = adsl_rdpvch1_file_w1->chc_open_error;  /* return open error to server */
   memset( achl_buf + 6, 0, 3 );            /* clear other hexa digits */
   *(achl_buf + 9 + 0) = (unsigned char) adsl_rdpvch1_file_w1->umc_ldm_ret_code;
   *(achl_buf + 9 + 1) = (unsigned char) (adsl_rdpvch1_file_w1->umc_ldm_ret_code >> 8);
   *(achl_buf + 9 + 2) = (unsigned char) (adsl_rdpvch1_file_w1->umc_ldm_ret_code >> 16);
   *(achl_buf + 9 + 3) = (unsigned char) (adsl_rdpvch1_file_w1->umc_ldm_ret_code >> 24);
   *(achl_buf + 13 + 0) = (unsigned char) iml1;
   *(achl_buf + 13 + 1) = (unsigned char) (iml1 >> 8);
   *(achl_buf + 13 + 2) = (unsigned char) (iml1 >> 16);
   *(achl_buf + 13 + 3) = (unsigned char) (iml1 >> 24);
   if (adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_len_virus_name) {  /* length returned virus name */
     memcpy( achl_buf + LEN_RET_ERROR,
             ucrs_found_virus_00,
             sizeof(ucrs_found_virus_00) );
     memcpy( achl_buf + LEN_RET_ERROR + sizeof(ucrs_found_virus_00),
             adsl_rdpvch1_file_w1->dsc_sevchcontr1.chrc_virus_name,
             adsl_rdpvch1_file_w1->dsc_sevchcontr1.imc_len_virus_name );
   } else if (adsl_rdpvch1_file_w1->imc_len_error) {
     memcpy( achl_buf + LEN_RET_ERROR,
             adsl_rdpvch1_file_w1->achc_ret_error,
             adsl_rdpvch1_file_w1->imc_len_error );
   }
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + LEN_RET_ERROR + iml1;
   ADSL_GAI1_O1->adsc_next = NULL;
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_tose;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = LEN_RET_ERROR;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef LEN_RET_ERROR
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   if (adsl_rdpvch1_file_w1->iec_fist == ied_fist_return_oe_and_close) {  /* return open error and close file */
     adsl_rdpvch1_file_w1->iec_fist = ied_fist_client_send_close;  /* send close to client */
     adsp_p1->boc_callrevdir = TRUE;        /* call on reverse direction */
     return ied_sdhr1_ok;
   }
   /* do cleanup                                                       */
   if (adsl_rdpvch1_file_w2 == NULL) {      /* remove at anchor of chain */
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file
        = adsl_rdpvch1_file_w1->adsc_next;  /* set new anchor          */
   } else {                                 /* remove middle in chain  */
     adsl_rdpvch1_file_w2->adsc_next = adsl_rdpvch1_file_w1->adsc_next;  /* remove from chain */
   }
   /* free file-name                                                   */
#ifdef B120112
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
#else
   if (adsl_rdpvch1_file_w1->achc_ret_name) {  /* storage with name exists */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
   }
#endif
   if (adsl_rdpvch1_file_w1->achc_ret_error) {
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_error );
   }
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1 );
#ifdef TRACEHL1
   printf( "xsrdpvch1.cpp l%05d m_rdp_vch1_get_tose() return code open error\n",
           __LINE__ );
#endif
   return ied_sdhr1_ok;

#ifdef XYZ1
   p_return_oe_misc_00:                     /* send miscellaneos open errors */
   adsl_rdpvch1_file_w1->iec_fist = ied_fist_client_send_close;  /* send close to client */
   return;
#endif

   p_return_open_ok_00:                     /* send open o.k.          */
#define LEN_RET_DATA (1 + 12 + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1) + 1 + 4 + 2)
   /* send real response open file to server                           */
   achl_buf = adsp_p1->adsc_output_area_1->achc_lower;
   adsp_p1->adsc_output_area_1->achc_lower += LEN_RET_DATA + adsl_rdpvch1_file_w1->imc_ret_len_name;  /* length return values */
#ifdef B120410
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_sc_vch_out) + sizeof(struct dsd_gather_i_1);
#else
   adsp_p1->adsc_output_area_1->achc_upper
     -= sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#endif
// adsp_p1->adsc_output_area_1->achc_upper &= 0 - sizeof(void *);
   adsp_p1->adsc_output_area_1->achc_upper
     = (char *) ((adsp_p1->adsc_output_area_1->achc_upper - (char *) 0) & (0 - sizeof(void *)));
   if (adsp_p1->adsc_output_area_1->achc_lower > adsp_p1->adsc_output_area_1->achc_upper) {
     dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
     dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
     m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-E work-area buffer overflow",
                   __LINE__ );
     return ied_sdhr1_fatal_error;          /* fatal error occured, abend */
   }
#define ADSL_GAI1_O1 ((struct dsd_gather_i_1 *) adsp_p1->adsc_output_area_1->achc_upper)
#ifdef B120410
#define ADSL_SC_VCH_OUT ((struct dsd_sc_vch_out *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#else
#define ADSL_SC_VCH_OUT ((struct dsd_rdp_vch_io *) (adsp_p1->adsc_output_area_1->achc_upper + sizeof(struct dsd_gather_i_1)))
#endif
   *(achl_buf + 0) = (char) adsl_rdpvch1_file_w1->chc_subchn;
   memcpy( achl_buf + 1, &adsl_rdpvch1_file_w1->umc_ldm_req_id, sizeof(adsl_rdpvch1_file_w1->umc_ldm_req_id) );
   memset( achl_buf + 5, 0, 4 );            /* clear return code       */
   memcpy( achl_buf + 9, &adsl_rdpvch1_file_w1->umc_ldm_handle, sizeof(adsl_rdpvch1_file_w1->umc_ldm_handle) );
   memcpy( achl_buf + 13,
           adsl_rdpvch1_file_w1->chrc_open_info_1,
           sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1) );
   *(achl_buf + 13 + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1)) = 0;  /* flag file / folder */
#define ACHL_OUT_1 (achl_buf + 13 + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1) + 1)
   *(ACHL_OUT_1 + 0) = (unsigned char) adsl_rdpvch1_file_w1->imc_ret_len_name;
   *(ACHL_OUT_1 + 1) = (unsigned char) (adsl_rdpvch1_file_w1->imc_ret_len_name >> 8);
   *(ACHL_OUT_1 + 2) = (unsigned char) (adsl_rdpvch1_file_w1->imc_ret_len_name >> 16);
   *(ACHL_OUT_1 + 3) = (unsigned char) (adsl_rdpvch1_file_w1->imc_ret_len_name >> 24);
   memcpy( achl_buf + 9 + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1) + 5 + 4,
           adsl_rdpvch1_file_w1->achc_ret_name,
           adsl_rdpvch1_file_w1->imc_ret_len_name );
   memset( achl_buf + 1 + 8 + sizeof(adsl_rdpvch1_file_w1->chrc_open_info_1) + 5 + 4 + adsl_rdpvch1_file_w1->imc_ret_len_name,
           0, 2 );                          /* make zero-terminated    */
   ADSL_GAI1_O1->achc_ginp_cur = achl_buf;
   ADSL_GAI1_O1->achc_ginp_end = achl_buf + LEN_RET_DATA + adsl_rdpvch1_file_w1->imc_ret_len_name;
   ADSL_GAI1_O1->adsc_next = NULL;
#ifdef TRACEHL1
// dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
// dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_get_tose() p_return_open_ok_00 len=%d.",
                 __LINE__, ADSL_GAI1_O1->achc_ginp_end - ADSL_GAI1_O1->achc_ginp_cur );
   m_sdh_console_out( &dsl_sdh_call_1, ADSL_GAI1_O1->achc_ginp_cur, ADSL_GAI1_O1->achc_ginp_end - ADSL_GAI1_O1->achc_ginp_cur );
#endif
#ifdef B120410
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_sc_vch_out) );
#else
   memset( ADSL_SC_VCH_OUT, 0, sizeof(struct dsd_rdp_vch_io) );
#endif
   ADSL_SC_VCH_OUT->adsc_rdp_vc_1
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdp_vc_1_tose;
#ifdef B120410
   ADSL_SC_VCH_OUT->adsc_gai1_out = ADSL_GAI1_O1;
#else
   ADSL_SC_VCH_OUT->adsc_gai1_data = ADSL_GAI1_O1;
#endif
   ADSL_SC_VCH_OUT->umc_vch_ulen = LEN_RET_DATA + adsl_rdpvch1_file_w1->imc_ret_len_name;
   ADSL_SC_VCH_OUT->chrc_vch_segfl[0] = 0X03;
   adsp_p1->adsc_sc_vch_out = ADSL_SC_VCH_OUT;  /* send output on virtual channel */
#undef LEN_RET_DATA
#undef ADSL_GAI1_O1
#undef ADSL_SC_VCH_OUT
   /* do cleanup                                                       */
   if (adsl_rdpvch1_file_w2 == NULL) {      /* remove at anchor of chain */
     ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->adsc_rdpvch1_file
        = adsl_rdpvch1_file_w1->adsc_next;  /* set new anchor          */
   } else {                                 /* remove middle in chain  */
     adsl_rdpvch1_file_w2->adsc_next = adsl_rdpvch1_file_w1->adsc_next;  /* remove from chain */
   }
   /* free file-name                                                   */
#ifdef B120112
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
#else
   if (adsl_rdpvch1_file_w1->achc_ret_name) {  /* storage with name exists */
     m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1->achc_ret_name );
   }
#endif
   m_aux_stor_free( adsp_p1->adsc_stor_sdh_1, adsl_rdpvch1_file_w1 );
#ifdef TRACEHL1
   printf( "xsrdpvch1.cpp l%05d m_rdp_vch1_get_tose() return open o.k.\n",
           __LINE__ );
#endif
   return ied_sdhr1_ok;                     /* send packet to server   */
} /* end m_rdp_vch1_get_tose()                                         */

extern "C" void m_rdp_vch1_close( struct dsd_rdp_param_vch_1 *adsp_p1 ) {
   BOOL       bol1;                         /* working variable        */
   struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query     */
#ifdef TRACEHL1
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
#endif

#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = adsp_p1->adsc_stor_sdh_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_p1->adsc_stor_sdh_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xsrdpvch1-l%05d-T m_rdp_vch1_close( adsp_p1=%p )",
                 __LINE__, adsp_p1 );
#endif
   if (adsp_p1->dsc_s1.ac_vir_ch_1 == NULL) return;  /* was not initialized */
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_close;  /* service close connection */
   dsl_aux_sequ1.vpc_sequ_handle
     = ((struct dsd_rdpvch1_contr *) adsp_p1->dsc_s1.ac_vir_ch_1)->vpc_sequ_handle;  /* handle of service query */
   bol1 = (*adsp_p1->adsc_stor_sdh_1->amc_aux)( adsp_p1->adsc_stor_sdh_1->vpc_userfld,
                                                DEF_AUX_SERVICE_REQUEST,  /* service request */
                                                &dsl_aux_sequ1,
                                                sizeof(struct dsd_aux_service_query_1) );
} /* end m_rdp_vch1_close()                                            */

/* copy a part of the data to the output area                          */
static void m_copy_tose_save( struct dsd_rdp_param_vch_1 *adsp_p1,
                              struct dsd_pch_save_1 **aadsp_pch_save_1,  /* save data from virtual channel */
                              char *achp_input, int imp_len_input ) {
   int        iml1;                         /* working variable        */
   struct dsd_pch_save_1 *adsl_pch_save_1_w1;  /* save data from virtual channel */

   adsl_pch_save_1_w1 = *aadsp_pch_save_1;

   p_copy_20:                               /* continue copying        */
   iml1 = ((char *) (adsl_pch_save_1_w1 + 1) + CHANNEL_CHUNK_LENGTH) - adsl_pch_save_1_w1->achc_filled;
   if (iml1 > imp_len_input) iml1 = imp_len_input;
   if (iml1 > 0) {
     memcpy( adsl_pch_save_1_w1->achc_filled, achp_input, iml1 );
     achp_input += iml1;                    /* increment input         */
     adsl_pch_save_1_w1->achc_filled += iml1;  /* increment output     */
     imp_len_input -= iml1;                 /* decrement length        */
     if (imp_len_input <= 0) return;        /* all done                */
   }
   *aadsp_pch_save_1 = (struct dsd_pch_save_1 *) m_aux_stor_alloc(
                              adsp_p1->adsc_stor_sdh_1,
                              sizeof(struct dsd_pch_save_1) + CHANNEL_CHUNK_LENGTH );
   adsl_pch_save_1_w1->adsc_next = *aadsp_pch_save_1;  /* append to chain */
   adsl_pch_save_1_w1 = *aadsp_pch_save_1;  /* get new buffer          */
   memset( adsl_pch_save_1_w1, 0, sizeof(struct dsd_pch_save_1) );
// adsl_pch_save_1_w1->adsc_next = NULL;    /* next in chain           */
   adsl_pch_save_1_w1->adsc_rdp_vc_1 = adsp_p1->adsc_rdp_vc_1;      /* RDP virtual channel */
   adsl_pch_save_1_w1->achc_filled = (char *) (adsl_pch_save_1_w1 + 1);
// adsl_pch_save_1_w1->chc_segfl = 0;       /* segmentation flag       */
   goto p_copy_20;                          /* continue copying        */
} /* end m_copy_tose_save()                                            */

/* edit a long integer number for decimal display                      */
static char * m_edit_dec_long( char *achp_target, HL_LONGLONG ilp1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;

   achl1 = achp_target + 15;
   *achl1 = 0;                              /* make zero-terminated    */
   iml1 = 3;                                /* digits between separator */
   while (TRUE) {
     *(--achl1) = (char) (ilp1 % 10 + '0');
     ilp1 /= 10;
     if (ilp1 == 0) return achl1;
     iml1--;
     if (iml1 == 0) {
     *(--achl1) = ',';                      /* output separator        */
       iml1 = 3;                            /* digits between separator */
     }
   }
} /* end m_edit_dec_long()                                             */

/* subroutine for output to console                                    */
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
