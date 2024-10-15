//#define NO_WT_COMPRESSION
//#define TRY_NO_VIRCH_01                     /* 23.04.12 KB - try without virtual channels */
//#define DEBUG_120330_01 10
//#define DEBUG_130324_01
//#define TRACEHL1
//#define TRY_120407_01                       /* ied_clc_conn_fin / Connection Finalization done */
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-webterm-uni-01.cpp                               |*/
/*| -------------                                                     |*/
/*|  Server-Data-Hook (SDH) for HOB WebTerm                           |*/
/*|    HTML5 / WebSocket server                                       |*/
/*|    universal                                                      |*/
/*|  KB 25.01.14                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */
#define MAX_INP_GATHER         16           /* number of input gather to be processed */
#define MIN_SPACE_IN_OUTPUT    64           /* minumum space in output area */
#define NOCOMPR TRUE
#define MAX_TARGET_URL 256

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

//used for output messages - 
//for this to work do not exceed ((1 << (32-IM_MAX_STATUS_BITS))-1) statuses and ((1 << IM_MAX_STATUS_BITS)-1) lines of code in a file
//20 allows for 4095 status codes and over 1 million LOC
#define IM_MAX_STATUS_BITS 20
#define WTE_ERR(_x_) ((_x_ << IM_MAX_STATUS_BITS) | __LINE__)

//additional information about configuration search
#define TRACE_JTERMCONF_SEARCH 0

enum IED_STATUS
{    
    IE_WSO_SUCCESS = 0,
    IE_WSO_OPENED,
    IE_WSO_CLOSING,
    IE_WSO_CALLCLIENT,  
    IE_WSO_DATA,   
    IE_WSO_CLOSED,
    IE_WSO_ERRSTART, //values after this are errors
    IE_WSO_CLIENT_EOF,
    IE_WSO_HTTP_ERR,    
    IE_WSO_COMPR_ERR,
    IE_WSO_DATA_ERR,
    IE_WSO_ERR,    
    IE_WSO_AUXERR,
    IE_WSO_ILLOGIC//unrecoverable error - something is wrong in code
};

enum ied_emulation_type
{ 	 
    IE_EMU_TYPE_UNKNOWN = -1,
    IE_EMU_TYPE_TN3270 = 1, 
    IE_EMU_TYPE_TN5250 = 2, 
    IE_EMU_TYPE_VT525 = 3    
};


struct dsd_jterm_userrights
{
    bool bo_can_use_3270;
    bool bo_can_use_5250;
    bool bo_can_use_vt;
};


struct dsd_error_msg
{
    int imc_len;
    const char* chrc_msg;
};

static const dsd_error_msg dsg_error_messages[] =
{
    {sizeof("") - 1,""}, //success
    {sizeof("Unexpected Target") - 1,"Unexpected Target"}, 
    {sizeof("Unexpected Target") - 1,"Unexpected Target"}, 
    {sizeof("Unexpected Port") - 1,"Unexpected Port"}, 
    {sizeof("Unexpected Target Type") - 1,"Unexpected Target Type"}, 
    {sizeof("Connection to target not allowed") - 1,"Connection to target not allowed"}
};


static int IM_MAX_ERR = sizeof(dsg_error_messages)/sizeof(dsd_error_msg);

#define HL_WT_JS_VERSION       1            /* version of WT JS client */

static const char * achrs_wt_js_first[] = {
   "version",
   "width",
   "height"
};

struct dsd_wt_record_1 {                    /* WebTerm record          */
    struct dsd_wt_record_1 *adsc_next;       /* for chaining            */
    struct dsd_gather_i_1 *adsc_gai1_data;   /* output data be be sent to client */
    unsigned char ucc_record_type;           /* record type             */
};


static int m_out_nhasn1( char *achp_out, int imp_number ) {
    int        iml_number;                   /* number to encode        */
    int        iml_length;                   /* length output           */
    int        iml_more;                     /* more flag               */
    char       *achl_out;                    /* address of output       */

    iml_number = imp_number;                 /* number to encode        */
    iml_length = 0;                          /* length output           */
    do {                                     /* loop to count length    */
        iml_number >>= 7;                      /* shift content           */
        iml_length++;                          /* length output           */
    } while (iml_number > 0);

    iml_number = imp_number;                 /* number to encode        */
    iml_more = 0;                            /* more flag               */
    achl_out = achp_out + iml_length;        /* address of output       */
    do {                                     /* loop to count length    */
        *(--achl_out) = (unsigned char) (iml_number & 0X7F) | iml_more;
        iml_number >>= 7;                      /* shift content           */
        iml_more = 0X80;                       /* more flag               */
    } while (iml_number > 0);

    return iml_length;                       /* length output           */
} /* end m_out_nhasn1()                                                */


int m_hasn1_len(unsigned int imp_value) {
    int iml_count = 0;
    do
    {
        imp_value >>= 7;
        iml_count++;
    } while (imp_value != 0);
    return iml_count;
}



int m_consume(struct dsd_gather_i_1* dsp_gather,int imp_len);
//#define WIN32_LEAN_AND_MEAN

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
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
#include <netdb.h>
#include "hob-unix01.h"
#endif
#define HOB_XSLUNIC1_H
#include <hob-xslunic1.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include "hob-stor-sdh.h"
#include <hob-encry-1.h>
#include "hob-cd-record-1.h"
#include <hob-avl03.h>
#include <hob-http-header-1.h>



//

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#include <xercesc/dom/DOMAttr.hpp>

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

//DOMNode required by hob-xsclib01.h
#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include "hob-xsclib01.h"
#endif //_HOB_XSCLIB01_H
//#include "hob-xsclib01.h" already included in LDAP

/**
 * For LDAP JTERM config
 * LDAP library includes xerces - DOMNode must be undefined (for clang compiler in FreeBSD)
 **/
#undef DOMNode
#include <ds_ldap.h>

//DOMNode needs to be defined if used in m_hlclib_conf
#define DOMNode XERCES_CPP_NAMESPACE::DOMNode


#include <ds_hstring.h>
#include <ds_usercma.h>
#include <ds_wsp_helper.h>
#include <ds_attribute_string.h>
#include <ds_xml.h>

#ifdef XYZ1
#define D_M_CDX_ENC m_cdr_dummy_enc
#define D_M_CDX_DEC m_cdr_dummy_dec
#endif

#define D_M_CDX_ENC m_cdr_zlib_1_enc

#define D_M_CDX_DEC m_cdr_zlib_1_dec

#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#define D_TCP_ERROR WSAGetLastError()
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#define D_TCP_ERROR errno
#endif

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#ifdef XYZ1
struct dsd_rdpcs1_session {                 /* structure subroutine session */
   BOOL       boc_start;                    /* start is active         */
   int        imc_ret_len_name;             /* returned length of name in bytes */
};


/* MJ 27.01.09: config structure definition                            */
struct dsd_server {
    char* ach_ip;
    int   in_port;
};

struct dsd_config {
    struct dsd_server ds_server;
};
#endif

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   struct dsd_clib1_contr_1 *adsc_contr_1;  /* for addressing          */
   char       *achc_lower;                  /* lower addr output area  */
   char       *achc_upper;                  /* higher addr output area */
   struct dsd_gather_i_1 **aadsrc_gai1_client;  /* output data to client */
   struct dsd_gather_i_1 **aadsrc_gai1_server;  /* output data to server */
      int        imc_trace_level;              /* WSP trace level         */
   int        imc_sno;                      /* session number          */
};

struct dsd_subaux_userfld {                 /* for aux calls           */
   struct dsd_hl_clib_1 *adsc_hl_clib_1;
};

struct dsd_clib1_conf_1 {                   /* structure configuration */
   int        imc_webso_compr;              /* <WebSocket-compression-level> */
};

enum ied_cl_compression {                   /* compression with WebSocket client */
   ied_clcomp_none = 0,                     /* no compression          */
   ied_clcomp_xwdf,                         /* x-webkit-deflate-frame  */
   ied_clcomp_pmd_2                         /* permessage-deflate      */
};

struct dsd_clib1_contr_1 {                  /* structure session control */
   BOOL       boc_started;                  /* connection to client has been started */
   BOOL       boc_conn_close_sent;          /* has already sent connection close */
   //MS sendconfigonopen BOOL boc_sendconfig;
   char       chrc_ws_mask[ 4 ];            /* mask for WebSocket input */
   enum ied_cl_compression iec_clcomp;      /* compression with client WebSocket */
   struct dsd_cdr_ctrl dsc_cdrf_dec;        /* compress data record oriented control - decode, input */
   struct dsd_cdr_ctrl dsc_cdrf_enc;        /* compress data record oriented control - encode, output */
    struct dsd_aux_webso_conn_1 dsc_awc1;    /* connect for WebSocket applications */
    int        imc_wts_port;                 /* port of the WSP         */
    int        imc_len_wts_ineta;            /* length of INETA WTS     */
    char       chrc_wts_ineta[ 16 ];         /* INETA IPV4 / IPV6 to connect to */    
    int        imc_len_client_ineta;         /* length INETA client     */
    char       chrc_client_ineta[ 128 ];     /* INETA to be passed      */
    int        imc_wt_js_width;              /* WT-JS screen width      */
    int        imc_wt_js_height;             /* WT-JS screen height     */
    char chrc_target_name[MAX_TARGET_URL]; //session name - limited in EA Admin to 100 chars
    int imc_target_name_len;
    int imc_port;
    ied_emulation_type iec_target_type;
    struct dsd_jterm_userrights dsc_user_rights;
};

static BOOL m_reply_http( struct dsd_sdh_call_1 *, char *, int );
//static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *, struct dsd_clib1_contr_1 *, struct dsd_gather_i_1 * );
static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *adsp_sdh_call_1,
struct dsd_clib1_contr_1 *adsp_contr_1,
struct dsd_wt_record_1 *adsp_wtr1 );
#ifdef XYZ1
static int m_out_nhasn1( char *achp_out, int imp_number );
#endif
static BOOL m_get_new_workarea( struct dsd_sdh_call_1 * );
#ifdef XYZ1
static BOOL m_sub_aux( void * vpp_userfld, int imp_func, void * ap_param, int imp_length );
#endif
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
#ifdef XYZ1
static int m_get_date_time( char *achp_buff );
#endif
static void m_sdh_console_out( struct dsd_sdh_call_1 *, char *achp_buff, int implength );
static void m_dump_gather( struct dsd_sdh_call_1 *, struct dsd_gather_i_1 *, int );

BOOL m_get_nhasn_len(dsd_gather_i_1* adsp_gather, char* achp_cur,
                     int* aimp_length, int* aimp_bytes);
BOOL m_get_nhasn_len(char* achp_data, char* achp_end,
                     int* aimp_length, int* aimp_bytes);
int m_get_jterm_config(struct dsd_hl_clib_1* adsp_hlclib,char* achp_configname,char* achp_configname_end,int imp_configname_len,char* achp_dst,char* achp_dst_end);
int m_search_session(ds_hstring ds_jterm_config, ds_wsp_helper*   dsp_wsp_helper,  
                     char* achp_configname, int imp_configname_len, 
                     char* achp_dst,char* achp_dst_end,
                     ds_attribute_string* dsl_config_attribute_own,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_tree,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_group,
                    dsd_clib1_contr_1* adsp_contr_1
                     );
int m_get_connection(ds_hstring ds_jterm_config, ds_wsp_helper* dsl_wsp_helper,
                     char* achp_dst,char* achp_dst_end,
                     const char *ach_connid_value, int im_connid_len,
                     dsd_clib1_contr_1* adsp_contr_1
                     );
void m_add_rights(ds_hstring ds_jterm_config, ds_wsp_helper* dsl_wsp_helper, dsd_jterm_userrights* adsp_userrights);
int m_connect_to_target(struct dsd_hl_clib_1* adsp_hlclib,char* achp_ineta, int imp_ineta_len, int imp_port, ied_emulation_type iep_target);

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const struct dsd_proc_http_header_server_1 dss_phhs1 = {
   NULL,                                    /* amc_stor_alloc - storage container allocate memory */
   NULL,                                    /* amc_stor_free - storage container free memory */
   TRUE,                                    /* boc_consume_input - consume input */
   FALSE,                                   /* boc_store_cookies - store cookies */
   FALSE                                    /* boc_out_os - output fields for other side */
};

static const unsigned char ucrs_http_reply_01[] = {
   'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '1', '0', '1', ' ', 'S', 'w', 'i',
   't', 'c', 'h', 'i', 'n', 'g', ' ', 'P', 'r', 'o', 't', 'o', 'c', 'o', 'l', 's',
   CHAR_CR, CHAR_LF,
   'U', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ', 'w', 'e', 'b', 's', 'o',
   'c', 'k', 'e', 't',
   CHAR_CR, CHAR_LF,
   'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n',
   ':', ' ', 'U', 'p', 'g', 'r', 'a', 'd', 'e',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W',
   'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'A', 'c', 'c', 'e', 'p', 't', ':',
   ' '
};

static const unsigned char ucrs_http_reply_02[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_http_reply_03[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-',
   'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's', ':', ' ',
   'x', '-', 'w', 'e', 'b', 'k', 'i', 't', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e', '-', 'f', 'r', 'a', 'm', 'e',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_http_reply_04[] = {
   CHAR_CR, CHAR_LF,
   'S',
   'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'P', 'r', 'o',
   't', 'o', 'c', 'o', 'l', ':', ' ',
   'w', 'e', 'b', 't', 'e', 'r', 'm', '0', '1', '.', 'h', 'o', 'b', 's', 'o', 'f',
   't', '.', 'c', 'o', 'm',
   CHAR_CR, CHAR_LF,
   'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-',
   'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's', ':', ' ',
   'p', 'e', 'r', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e',
   CHAR_CR, CHAR_LF,
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_websocket_reply_key[] = {
   '2', '5', '8', 'E', 'A', 'F', 'A', '5', '-', 'E', '9', '1', '4', '-', '4', '7',
   'D', 'A', '-', '9', '5', 'C', 'A', '-', 'C', '5', 'A', 'B', '0', 'D', 'C', '8',
   '5', 'B', '1', '1'
};

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

#ifdef DEBUG_120330_01
static int ims_debug_1_01;
#endif

#ifdef NOT_YET_120305
/**
 * function m_read_config
 * read in configuration and save to our config pointer
 *
 * @author      Michael Jakobs, 27.01.09
 * @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
 * @return      BOOL
*/
BOOL m_read_config( struct dsd_hl_clib_dom_conf *ads_conf )
{
    DOMNode* ads_pnode;                     // parent domnode
    DOMNode* ads_cnode;                     // child  domnode
    WCHAR*   wach_name;                     // pointer to nodename
    WCHAR*   wach_value;                    // pointer to nodevalue
    char*    ach_value;                     // pointer to nodevalue in utf8
    int      in_len_value;                  // length of nodevalue in utf8
    BOOL     bo_ret;                        // error code for aux calls
    int      in_compare;                    // return code for compare
    int      in_port                = -1;   // temporary buffer for reading server port
    struct   dsd_server* ads_server = NULL; // temporary buffer for reading server structure
    int      in_additional          = 0;    // additional needed bytes at the end of our config struct for char*


    ads_pnode = (DOMNode*)ads_conf->amc_call_dom( ads_conf->adsc_node_conf,
                                                  ied_hlcldom_get_first_child );
    if ( ads_pnode == NULL ) {
        return FALSE;
    }

    while ( ads_pnode != NULL ) {
        if ( (int)ads_conf->amc_call_dom( ads_pnode, ied_hlcldom_get_node_type ) == DOMNode::ELEMENT_NODE ) {
            wach_name = (WCHAR*)  ads_conf->amc_call_dom( ads_pnode,
                                                          ied_hlcldom_get_node_name );
            ads_cnode = (DOMNode*)ads_conf->amc_call_dom( ads_pnode,
                                                          ied_hlcldom_get_first_child );
            if ( ads_cnode == NULL ) {
                // we found an empty <tag></tag>
                ads_pnode = (DOMNode*)ads_conf->amc_call_dom( ads_pnode,
                                                              ied_hlcldom_get_next_sibling );
                continue;
            }

            if ( (int)ads_conf->amc_call_dom( ads_cnode, ied_hlcldom_get_node_type ) != DOMNode::TEXT_NODE ) {
                // our node is not a textnode
                continue;
            }

            // get node value and transform it to utf8:
            wach_value   = (WCHAR*)ads_conf->amc_call_dom( ads_cnode, ied_hlcldom_get_node_value );
            in_len_value = m_len_vx_vx( ied_chs_utf_8, wach_value,
                                        (int)wcslen(wach_value), ied_chs_utf_16 );
            bo_ret = ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMGET,
                                        &ach_value, in_len_value + 1 );
            if ( bo_ret == FALSE || ach_value == NULL ) {
                return FALSE;
            }
            memset( ach_value, 0, in_len_value + 1 );
            m_cpy_vx_vx( ach_value, in_len_value, ied_chs_utf_8, wach_value,
                         (int)wcslen(wach_value), ied_chs_utf_16 );

            // compare node name:
            bo_ret = m_cmpi_vx_vx( &in_compare,
                                   wach_name, (int)wcslen(wach_name), ied_chs_utf_16,
                                   "serverineta", (int)strlen("serverineta"), ied_chs_utf_8 );
            if ( in_compare == 0 && bo_ret == TRUE ) {
                // we have found server ip entry
                in_additional += in_len_value + 1;
                bo_ret = ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMGET,
                                            &ads_server, sizeof(dsd_server) + in_len_value + 1 );
                if ( bo_ret == FALSE || ads_server == NULL ) {
                    return FALSE;
                }
                memset( ads_server, 0, sizeof(dsd_server) + in_len_value + 1 );
                // copy string behind structure:
                for ( int in_1 = 0; in_1 < in_len_value; in_1++ ) {
                    ((char*)ads_server + sizeof(dsd_server))[in_1] = ach_value[in_1];
                }
                ads_server->ach_ip  = ((char*)ads_server + sizeof(dsd_server));
                // check if port was already read in:
                if ( in_port > 0 ) {
                    ads_server->in_port = in_port;
                }
            }

            bo_ret = m_cmpi_vx_vx( &in_compare,
                                   wach_name, (int)wcslen(wach_name), ied_chs_utf_16,
                                   "serverport", (int)strlen("serverport"), ied_chs_utf_8 );
            if ( in_compare == 0 && bo_ret == TRUE ) {
                in_port = atoi( ach_value );
                // check if ineta was already read in:
                if ( ads_server != NULL ) {
                    ads_server->in_port = in_port;
                }
            }

            ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMFREE,
                               &ach_value, in_len_value + 1 );
        }
        ads_pnode = (DOMNode*)ads_conf->amc_call_dom( ads_pnode,
                                                      ied_hlcldom_get_next_sibling );
    }


    // we have read all our entries:
    // -> get memory for our config structure + additional needed bytes
    bo_ret = ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMGET,
                                ads_conf->aac_conf, sizeof(dsd_config) + in_additional );
    if ( bo_ret == FALSE || (*ads_conf->aac_conf) == NULL ) {
        return FALSE;
    }
    memset( (*ads_conf->aac_conf), 0, sizeof(dsd_config) + in_additional );

    ((struct dsd_config*)*ads_conf->aac_conf)->ds_server.ach_ip  = ((char*)*ads_conf->aac_conf + sizeof(dsd_config));
    ((struct dsd_config*)*ads_conf->aac_conf)->ds_server.in_port = ads_server->in_port;
    // copy string behind structure:
    for ( int in_1 = 0; in_1 < (int)strlen(ads_server->ach_ip); in_1++ ) {
        ((char*)*ads_conf->aac_conf + sizeof(dsd_config))[in_1] = ads_server->ach_ip[in_1];
    }

    //free temporary server structure
    ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_MEMFREE,
                       &ads_server, sizeof(dsd_server) + strlen(ads_server->ach_ip) + 1 );
    return TRUE;
} // end of m_read_config


/**
 * function m_hlclib_conf
 * read in configuration and initialize some other stuff
 *
 * @author      Michael Jakobs, 27.01.09
 * @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
 * @return      BOOL
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf(struct dsd_hl_clib_dom_conf *ads_conf)
{
    // check input structure:
    if ( ads_conf == NULL ) {
        printf( "xlrdpa1 l%05d m_hlclib_conf() called with ads_conf == NULL\n",
                __LINE__ );
        return FALSE;
    }
	if (ads_conf->adsc_node_conf == NULL) { // there is no entry in configuration file
        char* ach_message = "There is no configuration for xlrdpa1 defined in configuration file\n";
        ads_conf->amc_aux( ads_conf->vpc_userfld, DEF_AUX_CONSOLE_OUT, ach_message, strlen(ach_message) );
		return FALSE;
	}

    return m_read_config( ads_conf );
} // end of m_hlclib_conf
#endif

extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf(struct dsd_hl_clib_dom_conf *ads_conf)
{
    return TRUE;
}

#ifdef HL_TRACE
  #define SDH_PRINTF(x) m_sdh_printf x 
  #ifdef HL_TRACEDBG
    #define SDH_PRINTF_DBG(x) m_sdh_printf x 
  #else
    #define SDH_PRINTF_DBG(x)
  #endif    
  #ifdef HL_TRACEVRB
    #define SDH_PRINTF_VRB(x) m_sdh_printf x 
  #else
    #define SDH_PRINTF_VRB(x)
  #endif    
#else
  #define SDH_PRINTF(x)
  #define SDH_PRINTF_DBG(x)
  #define SDH_PRINTF_VRB(x)    
#endif

#define SDH_PRINTF_ERR(x) m_sdh_printf x


void m_printerr(dsd_sdh_call_1* dsl_sdh_call_1, int imp_err)
{
    int iml_line = imp_err & ((1 << IM_MAX_STATUS_BITS) -1);
    int iml_code = imp_err >> IM_MAX_STATUS_BITS;
    switch (iml_code)
    {
    default:
         SDH_PRINTF((dsl_sdh_call_1,"Webterm uni error %d - %d",iml_code, iml_line));
        break;
    }
}

int m_websocket_call00(struct dsd_hl_clib_1 * adsp_hl_clib_1, int* imp_out);


extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {

   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_subaux_userfld dsl_subaux_userfld;  /* for aux calls     */
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   dsl_sdh_call_1.achc_lower = dsl_sdh_call_1.achc_upper = NULL;  /* addr output area */
   dsl_sdh_call_1.aadsrc_gai1_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   dsl_sdh_call_1.aadsrc_gai1_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   dsl_subaux_userfld.adsc_hl_clib_1 = adsp_hl_clib_1;
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hl_clib_1->ac_ext;
   dsl_sdh_call_1.adsc_contr_1 = adsl_contr_1;  /* for addressing      */
   BOOL bol_rc;

   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
       bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_contr_1,
                                    sizeof(struct dsd_clib1_contr_1) );
       if (bol_rc == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       adsp_hl_clib_1->ac_ext = adsl_contr_1;
       memset( adsl_contr_1, 0, sizeof(struct dsd_clib1_contr_1) );
       return;
     case DEF_IFUNC_REFLECT:
#ifdef TRACEHL_DNS
       m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-T time=%lld called DEF_IFUNC_REFLECT",
                   __LINE__, m_get_epoch_ms() );
#endif
//       return;
     case DEF_IFUNC_TOSERVER:
       //goto p_inp_client_00;                /* input from client       */
         break;
     case DEF_IFUNC_FROMSERVER:
         {
       //if (adsp_hl_clib_1->boc_eof_server) {  /* End-of-File Server    */
       //  goto p_end_server_00;              /* received end connection to server */
       //}
       //if (adsp_hl_clib_1->adsc_gather_i_1_in) {  /* with input data   */
       //  goto p_inp_server_00;              /* process RDP client      */
       //}
       //return;

        /* int iml_out = 0;
         int iml_ret = m_websocket_call00(adsp_hl_clib_1,&iml_out);*/
         
             if (!adsp_hl_clib_1->adsc_gather_i_1_in)
             {
                /*MS sendconfigonopen
                if (adsl_contr_1->boc_sendconfig)
                 {
                     
                    //3270 config TODO:only send relevant config (not 2370 to VT etc)
                    
                    dsd_wt_record_1 dsl_record;
                    dsl_record.adsc_next = NULL;
                    dsl_record.ucc_record_type = 1;
                    char* achl_testconfig = "<TN3270E>yes</TN3270E>";
                    
                    char* achl_work_1 = adsp_hl_clib_1->achc_work_area;  
                    char* achl_work_2 = achl_work_1 + adsp_hl_clib_1->inc_len_work_area;  
                    achl_work_2 -= sizeof(struct dsd_gather_i_1);

                    memcpy(achl_work_1,achl_testconfig,strlen(achl_testconfig));
                    
                    dsd_gather_i_1* dsl_g = (dsd_gather_i_1*) achl_work_2;
                    dsl_g->adsc_next = NULL;
                    dsl_g->achc_ginp_cur = achl_work_1;
                    dsl_g->achc_ginp_end = achl_work_1+ strlen(achl_testconfig);
                    
                    dsl_record.adsc_gai1_data = dsl_g;
                    m_send_websocket_data(&dsl_sdh_call_1,adsl_contr_1,&dsl_record);
                    adsl_contr_1->boc_sendconfig = FALSE;
                 }      */
                 return;
             }
             dsd_wt_record_1 dsl_record;
             dsl_record.adsc_next = NULL;
             dsl_record.ucc_record_type = 0;
             dsl_record.adsc_gai1_data = adsp_hl_clib_1->adsc_gather_i_1_in;


             int iml_read = m_send_websocket_data( &dsl_sdh_call_1, adsl_contr_1, &dsl_record );


             if (iml_read == 0) {                   
                 adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
             }

             //consume server input
             m_consume(adsp_hl_clib_1->adsc_gather_i_1_in,iml_read);   

         }
         return;
     case DEF_IFUNC_CLOSE:
         if (adsl_contr_1->iec_clcomp != ied_clcomp_none) {  /* with compression */
             adsl_contr_1->dsc_cdrf_dec.vpc_userfld = dsl_sdh_call_1.vpc_userfld;  /* User Field Subroutine */
             adsl_contr_1->dsc_cdrf_dec.amc_aux = dsl_sdh_call_1.amc_aux;  /* auxiliary subroutine */
             adsl_contr_1->dsc_cdrf_dec.adsc_gai1_in = NULL;  /* input data */
             D_M_CDX_DEC( &adsl_contr_1->dsc_cdrf_dec );
         }
         bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
             DEF_AUX_MEMFREE,
             &adsp_hl_clib_1->ac_ext,
             sizeof(struct dsd_clib1_contr_1) );
         if (bol_rc == FALSE) {               /* error occured           */
             adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         }
         return;


   }

    int iml_reply = -1;
    int iml_ret = m_websocket_call00(adsp_hl_clib_1,&iml_reply);

    if (iml_ret >> IM_MAX_STATUS_BITS)//iml_ret != IE_WSO_SUCCESS && iml_ret != IE_WSO_CALLCLIENT)
    {     
        //websocket call error
        m_printerr(&dsl_sdh_call_1,iml_ret);
    }
    //-1 is when the websocket data received had no known data
    if (iml_reply != IE_WSO_SUCCESS && iml_reply != -1)
    {     
        //SSH protocol error
        m_printerr(&dsl_sdh_call_1,iml_reply);
    }

    /*MS sendconfigonopen
    if (iml_ret == IE_WSO_OPENED)
    {
        adsp_hl_clib_1->boc_callrevdir = TRUE;
        adsl_contr_1->boc_sendconfig = TRUE;
        
    } */


   return;                                  /* all done                */
} /* end m_hlclib01()                                                  */

static BOOL m_reply_http( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achp_key, int imp_len_key ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   char       *achl_w1, *achl_w2;           /* working variables       */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   char       byrl_sha1_digest[ SHA_DIGEST_LEN ];  /* result SHA-1     */

   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower)
         < (3 * sizeof(struct dsd_gather_i_1) + (SHA_DIGEST_LEN + 3 - 1) / 3) * 4) {  /* need buffer */
     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
     if (bol_rc == FALSE) return FALSE;
   }
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, achp_key, 0, imp_len_key );
   SHA1_Update( imrl_sha1, (char *) ucrs_websocket_reply_key, 0, sizeof(ucrs_websocket_reply_key) );
   SHA1_Final( imrl_sha1, byrl_sha1_digest, 0 );
   adsp_sdh_call_1->achc_upper -= 3 * sizeof(struct dsd_gather_i_1);
#define ADSRL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
   ADSRL_GAI1_G[0].achc_ginp_cur = (char *) ucrs_http_reply_01;
   ADSRL_GAI1_G[0].achc_ginp_end = (char *) ucrs_http_reply_01 + sizeof(ucrs_http_reply_01);
   ADSRL_GAI1_G[0].adsc_next = &ADSRL_GAI1_G[1];
   iml1 = sizeof(byrl_sha1_digest) / 3;     /* length of digest        */
   achl_w1 = byrl_sha1_digest;              /* address of input        */
   achl_w2 = adsp_sdh_call_1->achc_lower;   /* output area             */
   ADSRL_GAI1_G[1].achc_ginp_cur = achl_w2;
   while (iml1 > 0) {                       /* loop output MIME base64 */
     iml2 = (*((unsigned char *) achl_w1 + 0) << 16)
              | (*((unsigned char *) achl_w1 + 1) << 8)
              | *((unsigned char *) achl_w1 + 2);
     achl_w1 += 3;                          /* after these three bytes */
     iml3 = 4;
     do {                                   /* loop output four characters MIME base64 */
       iml3--;                              /* decrement index         */
       *achl_w2++ = (char) ucrs_base64[ (iml2 >> (iml3 * 6)) & 0X3F ];
     } while (iml3 > 0);
     iml1--;                                /* three input bytes processed */
   }
   iml1 = ((char *) byrl_sha1_digest + sizeof(byrl_sha1_digest)) - achl_w1;
   if (iml1 > 0) {                          /* more characters to encode */
     iml2 = 0;                              /* clear akkumumator       */
     iml3 = iml1;                           /* get number of characters */
     do {
       iml2 <<= 8;                          /* shift old value         */
       iml2 |= *((unsigned char *) achl_w1);
       achl_w1++;
       iml3--;                              /* decrement index         */
     } while (iml3 > 0);
     iml2 <<= (3 - iml1) * 8;               /* shift remaining         */
     iml3 = 4;
     iml4 = 3 - iml1;                       /* set stopper             */
     do {                                   /* loop output four characters MIME base64 */
       iml3--;                              /* decrement index         */
       *achl_w2++ = (char) ucrs_base64[ (iml2 >> (iml3 * 6)) & 0X3F ];
     } while (iml3 > iml4);
     do {
       *achl_w2++ = '=';                    /* fill last character     */
       iml4--;                              /* decrement index         */
     } while (iml4 > 0);
   }
   ADSRL_GAI1_G[1].achc_ginp_end = achl_w2;
   adsp_sdh_call_1->achc_lower = achl_w2;
   ADSRL_GAI1_G[1].adsc_next = &ADSRL_GAI1_G[2];
   ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_02;
   ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_02 + sizeof(ucrs_http_reply_02);
   ADSRL_GAI1_G[2].adsc_next = NULL;
   if (adsp_sdh_call_1->adsc_contr_1->iec_clcomp == ied_clcomp_xwdf) {  /* x-webkit-deflate-frame */
     ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_03;
     ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_03 + sizeof(ucrs_http_reply_03);
   } else if (adsp_sdh_call_1->adsc_contr_1->iec_clcomp == ied_clcomp_pmd_2) {  /* permessage-deflate */
     ADSRL_GAI1_G[2].achc_ginp_cur = (char *) ucrs_http_reply_04;
     ADSRL_GAI1_G[2].achc_ginp_end = (char *) ucrs_http_reply_04 + sizeof(ucrs_http_reply_04);
   }
   *adsp_sdh_call_1->aadsrc_gai1_client = &ADSRL_GAI1_G[0];  /* output data to client */
   adsp_sdh_call_1->aadsrc_gai1_client = &ADSRL_GAI1_G[2].adsc_next;  /* next output data to client */
   return TRUE;
} /* end m_reply_http()                                                */

//static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *adsp_sdh_call_1,
//                                   struct dsd_clib1_contr_1 *adsp_contr_1,
//                                   struct dsd_gather_i_1 *adsp_gai1_inp ) {
//   BOOL       bol_rc;                       /* return code             */
//   int        iml1, iml2, iml3;             /* working variables       */
//   char       *achl_end_header;             /* end of header           */
//   struct dsd_gather_i_1 *adsl_gai1_first_out;  /* gather of first output */
//   struct dsd_gather_i_1 *adsl_gai1_last_out;  /* gather of last output */
//   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
//// struct dsd_gather_i_1 **aadsl_gai1_ch;   /* chain of gather         */
//
//   if (adsp_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
//     goto p_suc_00;                         /* send uncompressed       */
//   }
//   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) <= (2 + 8 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
//     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
//     if (bol_rc == FALSE) return FALSE;
//   }
//   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
//   adsp_sdh_call_1->achc_lower += 2 + 8;    /* leave spave for header  */
//   achl_end_header = adsp_sdh_call_1->achc_lower;  /* end of header    */
//   adsl_gai1_first_out = (struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper;  /* gather of first output */
//   iml1 = 0;                                /* clear length compressed data */
//   adsp_contr_1->dsc_cdrf_enc.vpc_userfld = adsp_sdh_call_1->vpc_userfld;  /* User Field Subroutine */
//   adsp_contr_1->dsc_cdrf_enc.amc_aux = adsp_sdh_call_1->amc_aux;  /* auxiliary subroutine */
//   adsp_contr_1->dsc_cdrf_enc.adsc_gai1_in = adsp_gai1_inp;  /* input to compression */
//   adsp_contr_1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
//#ifndef WHY_DOES_THIS_NOT_WORK_140108
//   adsp_contr_1->dsc_cdrf_enc.boc_sr_flush = FALSE;  /* end-of-record output */
//#endif
//
//   p_sco_20:                                /* call compression        */
//   /* compress input                                                   */
//   adsp_contr_1->dsc_cdrf_enc.achc_out_cur = adsp_sdh_call_1->achc_lower;  /* current end of output data */
//   adsp_contr_1->dsc_cdrf_enc.achc_out_end = adsp_sdh_call_1->achc_upper;  /* end of buffer for output data */
//   D_M_CDX_ENC( &adsp_contr_1->dsc_cdrf_enc );
//#ifdef TRACEHL1
//   m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T D_M_CDX_ENC() returned im_return=%d.",
//                 __LINE__,
//                 adsp_contr_1->dsc_cdrf_enc.imc_return );
//#endif
//   if (adsp_contr_1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
//// to-do 08.01.14 KB error message
//     return FALSE;
//   }
//#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
//   ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
//   ADSL_GAI1_G->achc_ginp_end = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
//   *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
//   adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
//   iml2 = adsp_contr_1->dsc_cdrf_enc.achc_out_cur - adsp_sdh_call_1->achc_lower;
//   iml1 += iml2;
//   if (adsp_contr_1->dsc_cdrf_enc.boc_sr_flush) {  /* end-of-record output */
//     goto p_sco_40;                         /* end of compression      */
//   }
//   adsl_gai1_last_out = ADSL_GAI1_G;        /* gather of last output   */
//#undef ADSL_GAI1_G
////#ifdef TRACEHL1
//   if (adsp_contr_1->dsc_cdrf_enc.achc_out_cur != adsp_sdh_call_1->achc_upper) {
//     m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T m_send_websocket_data() zLib error achc_out_cur=%p achc_upper=%p output=%d/0X%X.",
//                   __LINE__, adsp_contr_1->dsc_cdrf_enc.achc_out_cur, adsp_sdh_call_1->achc_upper, iml2, iml2 );
//   }
////#endif
//   bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
//   if (bol_rc == FALSE) return FALSE;
//   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
//   goto p_sco_20;                           /* call compression        */
//
//   p_sco_40:                                /* end of compression      */
//   adsp_sdh_call_1->achc_lower = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
//   *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
//   while (iml1 >= 126) {                    /* more than in one byte   */
//     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
//       achl_end_header -= 2;
//       *(achl_end_header + 0) = (unsigned char) (iml1 >> 8);
//       *(achl_end_header + 1) = (unsigned char) iml1;
//       iml1 = 126;
//       break;
//     }
//     achl_end_header -= 8;
//     iml2 = 8;                              /* output 64 bits          */
//     do {                                   /* loop output digits      */
//       iml2--;                              /* decrement index         */
//       *(achl_end_header + iml2) = (unsigned char) iml1;
//       iml1 >>= 8;                          /* shift bits              */
//     } while (iml2 > 0);
//     iml1 = 127;
//     break;
//   }
//   achl_end_header -= 2;
//   *(achl_end_header + 0) = (unsigned char) 0XC2;
//   *(achl_end_header + 1) = (unsigned char) iml1;
//   adsl_gai1_first_out->achc_ginp_cur = achl_end_header;
//#ifdef TRACEHL1
//   m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T m_send_websocket_data() last block %d.",
//                 __LINE__, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
//   m_sdh_console_out( adsp_sdh_call_1, achl_end_header, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
//#endif
//   return TRUE;
//
//   p_suc_00:                                /* send uncompressed       */
//   iml1 = 0;                                /* length of output data   */
//   adsl_gai1_w1 = adsp_gai1_inp;            /* output data be be sent to client */
//   while (adsl_gai1_w1) {                   /* loop to count length of data */
//     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
//     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
//   }
//   iml2 = sizeof(struct dsd_gather_i_1) + 2;  /* minimum sizeof of header */
//   while (iml1 >= 126) {                    /* more than in one byte   */
//     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
//       iml2 = sizeof(struct dsd_gather_i_1) + 2 + 2;  /* minimum sizeof of header */
//       break;
//     }
//     iml2 = sizeof(struct dsd_gather_i_1) + 2 + 8;  /* minimum sizeof of header */
//     break;
//   }
//   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < iml2) {  /* need buffer */
//     bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
//     if (bol_rc == FALSE) return FALSE;
//   }
//   iml2 -= sizeof(struct dsd_gather_i_1);   /* minimum sizeof of header */
//   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
//#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
//   ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
//   ADSL_GAI1_G->achc_ginp_end = adsp_sdh_call_1->achc_lower + iml2;
//// aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather        */
//   *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
//   adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
//#undef ADSL_GAI1_G
//   *(adsp_sdh_call_1->achc_lower + 0) = (unsigned char) 0X82;
//   *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) iml1;
//   while (iml1 >= 126) {                    /* more than in one byte   */
//     if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
//       *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 126;
//       *(adsp_sdh_call_1->achc_lower + 2) = (unsigned char) (iml1 >> 8);
//       *(adsp_sdh_call_1->achc_lower + 3) = (unsigned char) iml1;
//       break;
//     }
//     *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 127;
//     iml3 = 8;                              /* output 64 bits          */
//     do {                                   /* loop output digits      */
//       iml3--;                              /* decrement index         */
//       *(adsp_sdh_call_1->achc_lower + 2 + iml3) = (unsigned char) iml1;
//       iml1 >>= 8;                          /* shift bits              */
//     } while (iml3 > 0);
//     break;
//   }
//   adsp_sdh_call_1->achc_lower += iml2;
//   adsl_gai1_w1 = adsp_gai1_inp;            /* output data be be sent to client */
//   do {                                     /* loop to make gather for output */
//     if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < sizeof(struct dsd_gather_i_1)) {  /* need buffer */
//       bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
//       if (bol_rc == FALSE) return FALSE;
//     }
//     adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
//#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
////   *aadsl_gai1_ch = ADSL_GAI1_G;          /* chain of gather         */
//     ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
//     ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
////   aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather      */
//     *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
//     adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
//#undef ADSL_GAI1_G
//     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;  /* input consumed */
//     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
//   } while (adsl_gai1_w1);
//// *aadsl_gai1_ch = NULL;                   /* chain of gather         */
//   *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
//   return TRUE;
//} /* end m_send_websocket_data()                                       */


static BOOL m_send_websocket_data( struct dsd_sdh_call_1 *adsp_sdh_call_1,
struct dsd_clib1_contr_1 *adsp_contr_1,
struct dsd_wt_record_1 *adsp_wtr1 ) {
    BOOL       bol_rc;                       /* return code             */
    int        iml1, iml2, iml3;             /* working variables       */
    char       *achl_w1;                     /* working variable        */
    char       *achl_end_header;             /* end of header           */
    struct dsd_gather_i_1 *adsl_gai1_first_out;  /* gather of first output */
    struct dsd_gather_i_1 *adsl_gai1_last_out;  /* gather of last output */
    struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
    struct dsd_wsp_trace_record **aadsl_wtr_w1;
    // struct dsd_gather_i_1 **aadsl_gai1_ch;   /* chain of gather         */
    struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header      */
    struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
    char       chrl_work1[ 1024 ];           /* work area               */

    int iml_outputbytes = 0;

    if (adsp_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
        goto p_suc_00;                         /* send uncompressed       */
    }
    dsrl_gai1_work[ 0 ].achc_ginp_cur = (char *) &adsp_wtr1->ucc_record_type;  /* record type */
    dsrl_gai1_work[ 0 ].achc_ginp_end = (char *) &adsp_wtr1->ucc_record_type + 1;  /* end record type */
    iml1 = 0;                                /* set index gather        */
    iml2 = 1;                                /* set length output       */
    adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
    while (adsl_gai1_w1) {                   /* loop to count length of data */
        if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
            iml1++;                              /* increment index gather  */
            if (iml1 >= MAX_INP_GATHER) {        /* overflow in gather array */
                m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-W m_send_websocket_data() overflow MAX_INP_GATHER",
                    __LINE__ );
                return FALSE;
            }
            dsrl_gai1_work[ iml1 - 1 ].adsc_next = &dsrl_gai1_work[ iml1 ];
            dsrl_gai1_work[ iml1 ].achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
            dsrl_gai1_work[ iml1 ].achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
            iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
        }
        adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
    }
    dsrl_gai1_work[ iml1 ].adsc_next = NULL;
    iml_outputbytes = iml2-1;
    if (adsp_sdh_call_1->imc_trace_level) {  /* WSP trace level         */
        memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
        memcpy( dsl_wtrh.chrc_wtrt_id, "SWTROU01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
        dsl_wtrh.imc_wtrh_sno = adsp_sdh_call_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work1)
        dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
        memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
        ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
        ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
        ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
            "xl-webterm-uni-01 l%05d output to client before compression gather=%d length=%d/0X%X.",
            __LINE__, iml1 + 1, iml2, iml2 );
        achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
        aadsl_wtr_w1 = &ADSL_WTR_G1->adsc_next;
        iml2 = 0;
        while (TRUE) {
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
            memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
            ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed   */
            ADSL_WTR_G2->achc_content = dsrl_gai1_work[ iml2 ].achc_ginp_cur;   /* content of text / data  */
            ADSL_WTR_G2->imc_length = dsrl_gai1_work[ iml2 ].achc_ginp_end - dsrl_gai1_work[ iml2 ].achc_ginp_cur;
            *aadsl_wtr_w1 = ADSL_WTR_G2;
            iml2++;                              /* increment index         */
            if (iml2 >= (iml1 + 1)) break;
            ADSL_WTR_G2->boc_more = TRUE;        /* more data to follow     */
            aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
            achl_w1 += sizeof(struct dsd_wsp_trace_record);
        }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
        bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
            DEF_AUX_WSP_TRACE,  /* write WSP trace */
            &dsl_wtrh,
            0 );
    }
    if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) <= (2 + 8 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
        bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
        if (bol_rc == FALSE) return FALSE;
    }
    adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
    adsp_sdh_call_1->achc_lower += 2 + 8;    /* leave spave for header  */
    achl_end_header = adsp_sdh_call_1->achc_lower;  /* end of header    */
    adsl_gai1_first_out = (struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper;  /* gather of first output */
    iml1 = 0;                                /* clear length compressed data */
    adsp_contr_1->dsc_cdrf_enc.vpc_userfld = adsp_sdh_call_1->vpc_userfld;  /* User Field Subroutine */
    adsp_contr_1->dsc_cdrf_enc.amc_aux = adsp_sdh_call_1->amc_aux;  /* auxiliary subroutine */
    adsp_contr_1->dsc_cdrf_enc.adsc_gai1_in = dsrl_gai1_work;  /* input data */
    adsp_contr_1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
    adsp_contr_1->dsc_cdrf_enc.boc_sr_flush = FALSE;  /* end-of-record output */
#endif

p_sco_20:                                /* call compression        */
    /* compress input                                                   */
    adsp_contr_1->dsc_cdrf_enc.achc_out_cur = adsp_sdh_call_1->achc_lower;  /* current end of output data */
    adsp_contr_1->dsc_cdrf_enc.achc_out_end = adsp_sdh_call_1->achc_upper;  /* end of buffer for output data */
    D_M_CDX_ENC( &adsp_contr_1->dsc_cdrf_enc );
#ifdef TRACEHL1
    m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T D_M_CDX_ENC() returned im_return=%d.",
        __LINE__,
        adsp_contr_1->dsc_cdrf_enc.imc_return );
#endif
    if (adsp_contr_1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
        // to-do 08.01.14 KB error message
        return FALSE;
    }
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
    ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
    ADSL_GAI1_G->achc_ginp_end = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
    *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
    adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
    iml2 = adsp_contr_1->dsc_cdrf_enc.achc_out_cur - adsp_sdh_call_1->achc_lower;
    iml1 += iml2;
    if (adsp_contr_1->dsc_cdrf_enc.boc_sr_flush) {  /* end-of-record output */
        goto p_sco_40;                         /* end of compression      */
    }
    adsl_gai1_last_out = ADSL_GAI1_G;        /* gather of last output   */
#undef ADSL_GAI1_G
    //#ifdef TRACEHL1
    if (adsp_contr_1->dsc_cdrf_enc.achc_out_cur != adsp_sdh_call_1->achc_upper) {
        m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T m_send_websocket_data() zLib error achc_out_cur=%p achc_upper=%p output=%d/0X%X.",
            __LINE__, adsp_contr_1->dsc_cdrf_enc.achc_out_cur, adsp_sdh_call_1->achc_upper, iml2, iml2 );
    }
    //#endif
    bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
    if (bol_rc == FALSE) return FALSE;
    adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
    goto p_sco_20;                           /* call compression        */

p_sco_40:                                /* end of compression      */
    adsp_sdh_call_1->achc_lower = adsp_contr_1->dsc_cdrf_enc.achc_out_cur;
    *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
    while (iml1 >= 126) {                    /* more than in one byte   */
        if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
            achl_end_header -= 2;
            *(achl_end_header + 0) = (unsigned char) (iml1 >> 8);
            *(achl_end_header + 1) = (unsigned char) iml1;
            iml1 = 126;
            break;
        }
        achl_end_header -= 8;
        iml2 = 8;                              /* output 64 bits          */
        do {                                   /* loop output digits      */
            iml2--;                              /* decrement index         */
            *(achl_end_header + iml2) = (unsigned char) iml1;
            iml1 >>= 8;                          /* shift bits              */
        } while (iml2 > 0);
        iml1 = 127;
        break;
    }
    achl_end_header -= 2;
    *(achl_end_header + 0) = (unsigned char) 0XC2;
    *(achl_end_header + 1) = (unsigned char) iml1;
    adsl_gai1_first_out->achc_ginp_cur = achl_end_header;
#ifdef TRACEHL1
    m_sdh_printf( adsp_sdh_call_1, "xl-webterm-uni-01-l%05d-T m_send_websocket_data() last block %d.",
        __LINE__, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
    m_sdh_console_out( adsp_sdh_call_1, achl_end_header, adsl_gai1_first_out->achc_ginp_end - achl_end_header );
#endif
    return iml_outputbytes;                             /* all done                */

p_suc_00:                                /* send uncompressed       */
    iml1 = 1;                                /* length of output data   */
    adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
    while (adsl_gai1_w1) {                   /* loop to count length of data */
        iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
        adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
    }
    iml_outputbytes = iml1-1;
    iml2 = sizeof(struct dsd_gather_i_1) + 2 + 1;  /* minimum sizeof of header */
    while (iml1 >= 126) {                    /* more than in one byte   */
        if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
            iml2 = sizeof(struct dsd_gather_i_1) + 2 + 2 + 1;  /* minimum sizeof of header */
            break;
        }
        iml2 = sizeof(struct dsd_gather_i_1) + 2 + 8 + 1;  /* minimum sizeof of header */
        break;
    }
    if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < iml2) {  /* need buffer */
        bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
        if (bol_rc == FALSE) return FALSE;
    }
    iml2 -= sizeof(struct dsd_gather_i_1);   /* minimum sizeof of header */
    adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
    ADSL_GAI1_G->achc_ginp_cur = adsp_sdh_call_1->achc_lower;
    ADSL_GAI1_G->achc_ginp_end = adsp_sdh_call_1->achc_lower + iml2;
    // aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather        */
    *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
    adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
    *(adsp_sdh_call_1->achc_lower + 0) = (unsigned char) 0X82;
    *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) iml1;
    while (iml1 >= 126) {                    /* more than in one byte   */
        if (iml1 < (64 * 1024)) {              /* fits in two bytes       */
            *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 126;
            *(adsp_sdh_call_1->achc_lower + 2) = (unsigned char) (iml1 >> 8);
            *(adsp_sdh_call_1->achc_lower + 3) = (unsigned char) iml1;
            break;
        }
        *(adsp_sdh_call_1->achc_lower + 1) = (unsigned char) 127;
        iml3 = 8;                              /* output 64 bits          */
        do {                                   /* loop output digits      */
            iml3--;                              /* decrement index         */
            *(adsp_sdh_call_1->achc_lower + 2 + iml3) = (unsigned char) iml1;
            iml1 >>= 8;                          /* shift bits              */
        } while (iml3 > 0);
        break;
    }
    *(adsp_sdh_call_1->achc_lower + iml2 - 1) = adsp_wtr1->ucc_record_type;  /* record type */
    adsp_sdh_call_1->achc_lower += iml2;
    adsl_gai1_w1 = adsp_wtr1->adsc_gai1_data;   /* output data be be sent to client */
    while (adsl_gai1_w1) {                   /* loop to count length of data */
        if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower) < sizeof(struct dsd_gather_i_1)) {  /* need buffer */
            bol_rc = m_get_new_workarea( adsp_sdh_call_1 );
            if (bol_rc == FALSE) return FALSE;
        }
        adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
        //   *aadsl_gai1_ch = ADSL_GAI1_G;          /* chain of gather         */
        ADSL_GAI1_G->achc_ginp_cur = adsl_gai1_w1->achc_ginp_cur;
        ADSL_GAI1_G->achc_ginp_end = adsl_gai1_w1->achc_ginp_end;
        //   aadsl_gai1_ch = &ADSL_GAI1_G->adsc_next;  /* chain of gather      */
        *adsp_sdh_call_1->aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
        adsp_sdh_call_1->aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
        adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
    }
    // *aadsl_gai1_ch = NULL;                   /* chain of gather         */
    *adsp_sdh_call_1->aadsrc_gai1_client = NULL;  /* output data to client */
    return iml_outputbytes;
}

static BOOL m_get_new_workarea( struct dsd_sdh_call_1 *adsp_sdh_call_1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */

   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                         &dsl_aux_get_workarea,
                                         sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   adsp_sdh_call_1->achc_lower              /* lower addr output area  */
     = dsl_aux_get_workarea.achc_work_area;  /* addr work-area returned */
   adsp_sdh_call_1->achc_upper              /* higher addr output area */
     = dsl_aux_get_workarea.achc_work_area  /* addr work-area returned */
         + dsl_aux_get_workarea.imc_len_work_area;  /* length work-area returned */
   return TRUE;
} /* end m_get_new_workarea()                                          */

#ifdef XYZ1
static int m_out_nhasn1( char *achp_out, int imp_number ) {
   int        iml_number;                   /* number to encode        */
   int        iml_length;                   /* length output           */
   int        iml_more;                     /* more flag               */
   char       *achl_out;                    /* address of output       */

   iml_number = imp_number;                 /* number to encode        */
   iml_length = 0;                          /* length output           */
   do {                                     /* loop to count length    */
     iml_number >>= 7;                      /* shift content           */
     iml_length++;                          /* length output           */
   } while (iml_number > 0);

   iml_number = imp_number;                 /* number to encode        */
   iml_more = 0;                            /* more flag               */
   achl_out = achp_out + iml_length;        /* address of output       */
   do {                                     /* loop to count length    */
     *(--achl_out) = (unsigned char) (iml_number & 0X7F) | iml_more;
     iml_number >>= 7;                      /* shift content           */
     iml_more = 0X80;                       /* more flag               */
   } while (iml_number > 0);

   return iml_length;                       /* length output           */
} /* end m_out_nhasn1()                                                */

static BOOL m_sub_aux( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
#ifdef XYZ1
   char       *achl1;                       /* working-variable        */
   int        iml1;                         /* working-variable        */
   struct dsd_workarea_1 *adsl_workarea_1_w1;  /* work area            */
#endif
   struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
   struct dsd_session_timer *adsl_session_timer_w1;  /* session timer  */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */

#define X_ADSL_PARAM  *((void **) ap_param)
#define ADSL_SUBAUX_UF ((struct dsd_subaux_userfld *) vpp_userfld)  /* for aux calls */
#define ADSL_HL_CLIB_1 ADSL_SUBAUX_UF->adsc_hl_clib_1
#ifdef TRACEHL1
   dsl_sdh_call_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-T m_sub_aux() imp_func=%d.",
                 __LINE__, imp_func );
#endif
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_MEMGET:                   /* get some memory         */
     case DEF_AUX_MEMFREE:                  /* free memory             */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
     case DEF_AUX_CONSOLE_OUT:
     case DEF_AUX_CO_UNICODE:
     case DEF_AUX_RANDOM_RAW:
     case DEF_AUX_RANDOM_BASE64:
     case DEF_AUX_MARK_WORKAREA_INC:        /* increment usage count in work area */
     case DEF_AUX_MARK_WORKAREA_DEC:        /* decrement usage count in work area */
       return (*ADSL_HL_CLIB_1->amc_aux)( ADSL_HL_CLIB_1->vpc_userfld,
                                          imp_func, ap_param, imp_length );
     case DEF_AUX_GET_T_MSEC:               /* get time / epoch in milliseconds */
#ifdef XYZ1
       if (imp_length != sizeof(HL_LONGLONG)) return FALSE;  /* invalid size */
       if ((((HL_LONGLONG) ap_param) & (sizeof(void *) - 1))) return FALSE;  /* misaligned */
       *((HL_LONGLONG *) ap_param) = ADSL_SUBAUX_UF->ilc_epoch;
       return TRUE;                         /* all done                */
#endif
       return FALSE;                        /* not yet implemented     */
     case DEF_AUX_TIMER1_SET:               /* set timer in milliseconds */
     case DEF_AUX_TIMER1_REL:               /* release timer set before */
//     goto p_timer_00;                     /* release the timer, when set */
       return FALSE;                        /* not yet implemented     */
     case DEF_AUX_TIMER1_QUERY:             /* return struct dsd_timer1_ret */
#ifdef XYZ1
       if (imp_length != sizeof(struct dsd_timer1_ret)) return FALSE;
#define ADSL_TIMER1_RET_G ((struct dsd_timer1_ret *) ap_param)
       ADSL_TIMER1_RET_G->ilc_epoch = ADSL_SUBAUX_UF->ilc_epoch;  /* epoch in milliseconds */
       if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
         ADSL_TIMER1_RET_G->boc_timer_set = FALSE;  /* a timer is not set */
         ADSL_TIMER1_RET_G->ilc_timer = 0;  /* epoch when timer elapses */
         return TRUE;                       /* all done                */
       }
       ADSL_TIMER1_RET_G->boc_timer_set = TRUE;  /* a timer is set     */
       ADSL_TIMER1_RET_G->ilc_timer = ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end;  /* epoch when timer elapses */
       return TRUE;                         /* all done                */
#undef ADSL_TIMER1_RET_G
#endif
       return FALSE;                        /* not yet implemented     */
   }
   return FALSE;

#ifdef XYZ1
   p_timer_00:                              /* release the timer, when set */
   adsl_contr_1 = (struct dsd_clib1_contr_1 *) ADSL_HL_CLIB_1->ac_ext;
   if (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end == 0) {  /* epoch timer not set */
     goto p_timer_60;                       /* set the timer           */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = 0;  /* reset epoch timer */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_contr_1->adsc_session_timer) {  /* is first in chain */
     adsl_contr_1->adsc_session_timer = adsl_contr_1->adsc_session_timer->adsc_next;  /* remove from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   if (adsl_session_timer_w1 == NULL) {     /* chain is empty          */
     goto p_timer_40;                       /* timer chain corrupted   */
   }

   p_timer_20:                              /* search timer in chain   */
   if (ADSL_SUBAUX_UF->adsc_session_timer == adsl_session_timer_w1->adsc_next) {  /* check if next from here */
     adsl_session_timer_w1->adsc_next = adsl_session_timer_w1->adsc_next->adsc_next;  /* remove entry from chain */
     goto p_timer_60;                       /* set the timer           */
   }
   adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   if (adsl_session_timer_w1) goto p_timer_20;  /* search timer in chain */

   p_timer_40:                              /* timer chain corrupted   */
   dsl_sdh_call_1.amc_aux = ADSL_HL_CLIB_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = ADSL_HL_CLIB_1->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-W m_sub_aux() imp_func=%d adsc_sdh_tcp_1=%p timer chain corrupted",
                 __LINE__, imp_func, ADSL_SUBAUX_UF->adsc_sdh_tcp_1 );

   p_timer_60:                              /* set the timer           */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = FALSE;  /* timer is currently not running */
   if (imp_func != DEF_AUX_TIMER1_SET) return TRUE;  /* do not set timer in milliseconds */
   ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end = ADSL_SUBAUX_UF->ilc_epoch + imp_length;  /* set epoch timer */
   ADSL_SUBAUX_UF->adsc_sdh_tcp_1->boc_timer_running = TRUE;  /* timer is currently running */
// ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = NULL;  /* clear chain */
   if (   (adsl_contr_1->adsc_session_timer == NULL)  /* chain is empty */
       || (ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end < adsl_contr_1->adsc_session_timer->ilc_epoch_end)) {
     ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_contr_1->adsc_session_timer;  /* set chain */
     adsl_contr_1->adsc_session_timer = ADSL_SUBAUX_UF->adsc_session_timer;  /* set new anchor */
     return TRUE;                           /* all done                */
   }
   adsl_session_timer_w1 = adsl_contr_1->adsc_session_timer;  /* get chain */
   while (   (adsl_session_timer_w1->adsc_next)
          && (adsl_session_timer_w1->adsc_next->ilc_epoch_end <= ADSL_SUBAUX_UF->adsc_session_timer->ilc_epoch_end)) {
     adsl_session_timer_w1 = adsl_session_timer_w1->adsc_next;  /* get next in chain */
   }
   ADSL_SUBAUX_UF->adsc_session_timer->adsc_next = adsl_session_timer_w1->adsc_next;  /* set end of chain */
   adsl_session_timer_w1->adsc_next = ADSL_SUBAUX_UF->adsc_session_timer;  /* insert new entry in chain */
   return TRUE;                             /* all done                */
#endif

#undef X_ADSL_PARAM
#undef ADSL_SUBAUX_UF
#undef ADSL_HL_CLIB_1
} /* end m_sub_aux()                                                   */
#endif

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


  /////////////////////

int m_fromclient_data(struct dsd_hl_clib_1* adsp_hlclib, char* achp_data, char* achp_dataend)
{
   char* achl_work_1 = adsp_hlclib->achc_work_area;  /* addr work-area    */
   char* achl_work_2 = achl_work_1 + adsp_hlclib->inc_len_work_area;  /* length work-area */
   achl_work_2 -= sizeof(struct dsd_gather_i_1);

   if (!achp_data)
       return -1;
   char chr_type = *achp_data;
   if (chr_type == 1)
   {
       //control data
       int iml_len = 0;
       int iml_bytes = 0;
       achp_data++;
       if (!m_get_nhasn_len(achp_data, achp_dataend, &iml_len, &iml_bytes))
           return -2;

       //get specified config
       achp_data += iml_bytes;
       
       int iml_configlen = m_get_jterm_config(adsp_hlclib,achp_data,achp_dataend,iml_len,&achl_work_1[5],achl_work_2);
       

       if (iml_configlen <= 0)
       {
           if (iml_configlen == -1)
           {
               //TODO: size of work area not large enough to hold jterm config (?)
           }
           return 0;
       }

       iml_bytes = m_hasn1_len(iml_configlen);
       achl_work_1 += (5 - iml_bytes);

       iml_bytes = m_out_nhasn1(achl_work_1,iml_configlen);
       //char* achl_start = achl_work_1 + (5 - iml_bytes);
       

       dsd_wt_record_1 dsl_record;
       dsl_record.adsc_next = NULL;
       dsl_record.ucc_record_type = 1;
       //char* achl_testconfig = "<TN3270E>yes</TN3270E>";

       //char* achl_work_1 += iml_configlen;
       //achl_work_2 -= sizeof(struct dsd_gather_i_1);

       //memcpy(achl_work_1,achl_testconfig,strlen(achl_testconfig));

       dsd_gather_i_1* dsl_g = (dsd_gather_i_1*) achl_work_2;
       dsl_g->adsc_next = NULL;
       dsl_g->achc_ginp_cur = achl_work_1 ;
       dsl_g->achc_ginp_end = achl_work_1 + iml_bytes + iml_configlen; //strlen(achl_testconfig);
       dsl_record.adsc_gai1_data = dsl_g;


       struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
       //struct dsd_subaux_userfld dsl_subaux_userfld;  /* for aux calls     */
       struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
       dsl_sdh_call_1.amc_aux = adsp_hlclib->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_hlclib->vpc_userfld;  /* User Field Subroutine */
       dsl_sdh_call_1.achc_lower = dsl_sdh_call_1.achc_upper = NULL;  /* addr output area */
       dsl_sdh_call_1.aadsrc_gai1_client = &adsp_hlclib->adsc_gai1_out_to_client;  /* output data to client */
       dsl_sdh_call_1.aadsrc_gai1_server = &adsp_hlclib->adsc_gai1_out_to_server;  /* output data to server */
       //dsl_subaux_userfld.adsc_hl_clib_1 = adsp_hl_clib_1;
       adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hlclib->ac_ext;
       dsl_sdh_call_1.adsc_contr_1 = adsl_contr_1;  /* for addressing      */
       
       m_send_websocket_data(&dsl_sdh_call_1,adsl_contr_1,&dsl_record);
      //MS sendconfigonopen adsl_contr_1->boc_sendconfig = FALSE;



   }
   if (chr_type == 2)
   {
       achp_data++; //channel (2 - connect)

       ied_emulation_type iel_emulation_type  = (ied_emulation_type)(*achp_data++);

       int iml_tot_len = 0;
       int iml_bytes = 0;
       if (!m_get_nhasn_len(achp_data, achp_dataend, &iml_tot_len, &iml_bytes))
       {
           return -211; //corrupted data??
       }
       
       achp_data += iml_bytes;
       if (achp_dataend-achp_data < iml_tot_len)
       {
           //not enough bytes received ??
           return -22;
       }

       int iml_ineta_len;
       if (!m_get_nhasn_len(achp_data, achp_dataend, &iml_ineta_len, &iml_bytes))
       {
           return -212;
       }

       achp_data += iml_bytes;

       //ineta in achp_data till achp_Data + iml_ineta_len
       char* achl_ineta = achp_data;
       achp_data += iml_ineta_len;
       
       int iml_port;
       if (!m_get_nhasn_len(achp_data, achp_dataend, &iml_port, &iml_bytes))
       {
           return -213;
       }               
       if (iml_port <= 0)
           iml_port = 23; //set default port

       achp_data += iml_bytes;

       //TODO other params if needed (password?)

       int iml_ret = m_connect_to_target(adsp_hlclib,achl_ineta,iml_ineta_len,iml_port,iel_emulation_type );

       //send client error message or success (0)

       int iml_msglen = 0;
       if (iml_ret > 0 && iml_ret < IM_MAX_ERR)
       {           
           iml_msglen = dsg_error_messages[iml_ret].imc_len;     
           memcpy(&achl_work_1[10],dsg_error_messages[iml_ret].chrc_msg,iml_msglen);
       }
       iml_bytes = m_hasn1_len(iml_msglen);
       int iml_ret_bytes = m_hasn1_len(iml_ret);
       
       achl_work_1 += (10 - iml_bytes - iml_ret_bytes);

       iml_ret_bytes = m_out_nhasn1(achl_work_1,iml_ret);
       iml_bytes = m_out_nhasn1(achl_work_1+iml_ret_bytes,iml_msglen);

       dsd_wt_record_1 dsl_record;
       dsl_record.adsc_next = NULL;
       dsl_record.ucc_record_type = 2;

       dsd_gather_i_1* dsl_g = (dsd_gather_i_1*) achl_work_2;
       dsl_g->adsc_next = NULL;
       dsl_g->achc_ginp_cur = achl_work_1 ;
       dsl_g->achc_ginp_end = achl_work_1 + iml_bytes + iml_ret_bytes + iml_msglen; 
       dsl_record.adsc_gai1_data = dsl_g;


       struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
       //struct dsd_subaux_userfld dsl_subaux_userfld;  /* for aux calls     */
       struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
       dsl_sdh_call_1.amc_aux = adsp_hlclib->amc_aux;  /* auxiliary subroutine */
       dsl_sdh_call_1.vpc_userfld = adsp_hlclib->vpc_userfld;  /* User Field Subroutine */
       dsl_sdh_call_1.achc_lower = dsl_sdh_call_1.achc_upper = NULL;  /* addr output area */
       dsl_sdh_call_1.aadsrc_gai1_client = &adsp_hlclib->adsc_gai1_out_to_client;  /* output data to client */
       dsl_sdh_call_1.aadsrc_gai1_server = &adsp_hlclib->adsc_gai1_out_to_server;  /* output data to server */
       //dsl_subaux_userfld.adsc_hl_clib_1 = adsp_hl_clib_1;
       adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hlclib->ac_ext;
       dsl_sdh_call_1.adsc_contr_1 = adsl_contr_1;  /* for addressing      */
       
       m_send_websocket_data(&dsl_sdh_call_1,adsl_contr_1,&dsl_record);
   }
   //chr_type == 0 normal data to forward to server

   if (chr_type == 0)
   {
       dsd_gather_i_1* adsl_gather = (struct dsd_gather_i_1 *) achl_work_2;
       adsl_gather->achc_ginp_cur = achp_data+1;
       adsl_gather->achc_ginp_end = achp_dataend;
       adsl_gather->adsc_next = NULL;         /* clear chain field       */
       adsp_hlclib->adsc_gai1_out_to_server = adsl_gather;  /* output data to server */
   }
   return 0;

}

  int m_websocket_call00(struct dsd_hl_clib_1 * adsp_hl_clib_1, int* imp_out)
{         
    BOOL       bol1;                         /* working variable        */
    BOOL       bol_rc;                       /* return code             */
    int        iml_rc;                       /* return code             */
    struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
    struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
    struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
    struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header      */
    char       chrl_work1[ 32 * 2048 ];      /* work area               */
    char       chrl_work2[ 32 * 2048 ];      /* work area               */
    char       chrl_work3[ 1024 ];           /* work area               */
    char       *achl_keyb_mouse;             /* position work area, keyboard and mouse events */
    char       *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5;     
    int        iml_len_header;               /* length header WebSocket record */
    struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* input data read pointer */
    char       *achl_inp_rp;                 /* input read pointer      */
    char       byl_opcode;                   /* opcode of WebSocket frame */
    BOOL       bol_connection_closed;        /* WebSocket connection close */
    int        iml_len_payload;              /* length payload WebSocket record */
    BOOL       bol_compressed;               /* input is compressed     */
    int        *aiml_w1;                     /* address of int          */
    int        iml_wt_js_version;            /* version of WT JS client */

    int        iml1,iml2,iml3;             /* working variables       */
#ifndef HL_UNIX
    union {
        struct {
#endif
            struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
            struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
#ifndef HL_UNIX
        };
#endif
        struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
#ifdef XYZ1
        struct dsd_aux_webso_conn_1 dsl_awc1;  /* connect for WebSocket applications */
#endif
        struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
#ifndef HL_UNIX
        struct {
#endif
            struct dsd_sdh_ident_set_1 dsl_g_idset1;  /* settings for given ident */
            struct dsd_hl_aux_c_cma_1 dsl_accma1;  /* command common memory area */
            struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR    */
#ifndef HL_UNIX
        };
        struct {
#endif
            struct sockaddr_storage dsl_soa_l;
            struct dsd_aux_tcp_conn_1 dsl_atc1_1;  /* TCP Connect to Server */
#ifndef HL_UNIX
        };
#endif
        /*struct {
            struct dsd_webterm_dod_info dsc_wt_dod_info;
            char   chrc_dod_ineta[ 512 ];
        } dsl_dod_query;*/
#ifndef HL_UNIX
    };
#endif

    struct dsd_clib1_contr_1 *adsl_contr_1;  /* for addressing          */
    
    adsl_contr_1 = (dsd_clib1_contr_1*)adsp_hl_clib_1->ac_ext;
    struct dsd_sdh_call_1 dsl_output_area_1;  /* SDH call structure     */

    dsl_output_area_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
    dsl_output_area_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
    dsl_output_area_1.achc_lower = dsl_output_area_1.achc_upper = NULL;  /* addr output area */
    dsl_output_area_1.aadsrc_gai1_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
    dsl_output_area_1.imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
    dsl_output_area_1.imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */

    dsl_output_area_1.adsc_contr_1 = adsl_contr_1;  /* for addressing      */


    if (adsp_hl_clib_1->boc_eof_client) {    /* End-of-File Client      */
        //MS-removing RDPACC 
        //if (   (adsl_contr_1->dsc_c_wtrc1.inc_return == DEF_IRET_NORMAL)  /* o.k. returned */
        //  && (adsl_contr_1->dsc_c_wtrc1.inc_func != DEF_IFUNC_START)) {  /* RDP-ACC already started */
        //adsl_contr_1->dsc_c_wtrc1.inc_func = DEF_IFUNC_CLOSE;  /* close RDP-ACC now */
        //goto p_rdp_client_08;                /* end RDP-ACC             */
        //}
        return WTE_ERR(IE_WSO_CLIENT_EOF);
    }

    if (   (((int) adsl_contr_1->dsc_awc1.iec_cwc) == 0)
        || (adsl_contr_1->dsc_awc1.iec_cwc == ied_cwc_close)) {  /* close connection to internal routine */
            goto p_call_40;                        /* continue call of SDH    */
    }

    adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_status;  /* check status   */

p_status_00:                             /* check the status        */
    bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
        DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
        &adsl_contr_1->dsc_awc1,
        sizeof(struct dsd_aux_webso_conn_1) );
    if (bol_rc == FALSE) {                   /* returned error          */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
            __LINE__ );
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_AUXERR);
    }

    if (adsl_contr_1->dsc_awc1.imc_len_data_recv > 0) {  /* check length data received */
        m_sdh_console_out( &dsl_output_area_1,
            adsl_contr_1->dsc_awc1.achc_data_recv,  /* address data received */
            adsl_contr_1->dsc_awc1.imc_len_data_recv );  /* length data received */
        if (adsl_contr_1->dsc_awc1.boc_internal_act) {  /* still more to do */
            goto p_status_00;                    /* check the status        */
        }
    }
    if (adsl_contr_1->dsc_awc1.boc_internal_act == FALSE) {  /* internal WebSocket component active */
        goto p_webso_60;                       /* status WebSocket no more active */
    }

p_call_40:                               /* continue call of SDH    */
    switch (adsp_hl_clib_1->inc_func) {
case DEF_IFUNC_TOSERVER:
    goto p_inp_client_00;                /* input from client       */
case DEF_IFUNC_FROMSERVER:
    if (adsp_hl_clib_1->boc_eof_server) {  /* End-of-File Server    */
        //goto p_end_server_00;              /* received end connection to server */
    }
    if (adsp_hl_clib_1->adsc_gather_i_1_in) {  /* with input data   */
        //goto p_rdp_client_00;              /* process RDP client      */
    }
    return WTE_ERR(IE_WSO_DATA);//error??
case DEF_IFUNC_REFLECT:
    goto p_inp_client_00;                /* input from client       */
    }

p_inp_client_00:                         /* input from client       */
    adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
    if (adsl_gai1_inp_1 == NULL) return WTE_ERR(IE_WSO_DATA);     /* no input data           */
    if (adsl_contr_1->boc_started) {         /* connection to client has been started */
        goto p_inp_client_20;                  /* input from client, WebSocket protocol */
    }
    /* process incoming HTTP header                                     */
    memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */
    dsl_chhs1.adsc_gai1_in = adsl_gai1_inp_1;  /* gather input data     */
    // dsl_chhs1.achc_url_path = byrl_http_url_path;  /* memory for URL path */
    // dsl_chhs1.imc_length_url_path_buffer = sizeof(byrl_http_url_path);  /* length memory for URL path */
    dsl_chhs1.achc_sec_ws_key = chrl_work1;  /* Sec-WebSocket-Key base64 */
    dsl_chhs1.imc_length_sec_ws_key_buffer = sizeof(chrl_work1);  /* length memory for Sec-WebSocket-Key base64 */

    bol_rc = m_proc_http_header_server( &dss_phhs1,  /* HTTP processing at server */
        &dsl_chhs1,  /* call HTTP processing at server */
        &dsl_hhs1 );  /* HTTP processing at server */

    if (bol_rc == FALSE) {                   /* error occured           */
#ifdef XYZ1
        // to-do 19.03.13 - additional error information
        m_sdh_printf( &dsl_output_area_1, "xltwspat302-l%05d-W m_wspat3_proc() m_proc_http_header_server() returned error",
            __LINE__ );
        adsp_wspat3_1->iec_at_return = ied_atr_failed;  /* authentication failed */
#endif
        return WTE_ERR(IE_WSO_HTTP_ERR);
    }

    if (dsl_hhs1.imc_length_http_header == 0) {  /* length of HTTP header */
        return WTE_ERR(IE_WSO_DATA);                                /* wait for more input data */
    }
    if (dsl_hhs1.imc_len_sec_ws_key == 0) {  /* length Sec-WebSocket-Key base64 */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_ERR);                                /* error                   */
    }
    if (dsl_hhs1.imc_len_sec_ws_key != dsl_hhs1.imc_stored_sec_ws_key) {  /* stored part of Sec-WebSocket-Key base64 */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_ERR);                                /* error                   */
    }

#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf)  /* structure configuration */
    if (   (dsl_hhs1.boc_sec_webso_ext_deflate)  /* Sec-WebSocket-Extensions: x-webkit-deflate-frame */
        && (   (ADSL_CC1 == NULL)            /* no configuration        */
        || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
            adsl_contr_1->iec_clcomp = ied_clcomp_xwdf;  /* x-webkit-deflate-frame */
    }
#ifdef XYZ1
    if (   (dsl_hhs1.imc_sec_webso_ext_pmd_2 != 0)  /* Sec-WebSocket-Extensions: permessage-deflate */
        && (   (ADSL_CC1 == NULL)            /* no configuration        */
        || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
            adsl_contr_1->iec_clcomp = ied_clcomp_pmd_2;  /* permessage-deflate */
    }
#endif
    if (   (dsl_hhs1.umc_sec_webso_ext_pmd != 0)  /* Sec-WebSocket-Extensions: permessage-deflate */
        && (   (ADSL_CC1 == NULL)            /* no configuration        */
        || (ADSL_CC1->imc_webso_compr > 0))) {  /* <WebSocket-compression-level> */
            adsl_contr_1->iec_clcomp = ied_clcomp_pmd_2;  /* permessage-deflate */
    }
#undef ADSL_CC1

#if NOCOMPR
    //MS compression not working (chrome(
    adsl_contr_1->iec_clcomp = ied_clcomp_none;
#endif

    bol_rc = m_reply_http( &dsl_output_area_1,
        dsl_hhs1.achc_sec_ws_key,  /* Sec-WebSocket-Key base64 */
        dsl_hhs1.imc_len_sec_ws_key );  /* length Sec-WebSocket-Key base64 */
    if (bol_rc == FALSE) {                   /* error occured           */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_HTTP_ERR);
    }

    adsl_contr_1->boc_started = TRUE;        /* connection to client has been started */

    /* get parameters about the client                                  */
    memset( &dsl_agsi, 0, sizeof(struct dsd_aux_get_session_info) );  /* get information about the session */
    bol_rc = (*dsl_output_area_1.amc_aux)( dsl_output_area_1.vpc_userfld,
        DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
        &dsl_agsi,
        sizeof(struct dsd_aux_get_session_info) );
    if (bol_rc == FALSE) {                   /* error occured           */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_AUXERR);
    }
    iml_rc = getnameinfo( (struct sockaddr *) &dsl_agsi.dsc_soa_client, sizeof(struct sockaddr_storage),
        chrl_work1, sizeof(chrl_work1), 0, 0, NI_NUMERICHOST );

    if (iml_rc) {                            /* error occured           */
        //   m_hlnew_printf( HLOG_XYZ1, "HWSPM062W GATE=%(ux)s getnameinfo() returned %d %d.",
        //                   apdg1 + 1, rcu, D_TCP_ERROR );
        strcpy( chrl_work1, "???" );
    }
    iml_rc = m_cpy_vx_vx( adsl_contr_1->chrc_client_ineta,
        sizeof(adsl_contr_1->chrc_client_ineta),
        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
        chrl_work1,
        -1,                /* zero-terminated         */
        ied_chs_utf_8 );
    adsl_contr_1->imc_len_client_ineta = (iml_rc + 1) * sizeof(HL_WCHAR);  /* length INETA client */

    if (adsl_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
        goto p_cl_sta_40;                      /* continue start client   */
    }

    /* start de-compression input                                       */
    // memset( &adsl_contr_1->dsc_cdrf_dec, 0, sizeof(struct dsd_cdr_ctrl) );  /* compress data record oriented control */
    adsl_contr_1->dsc_cdrf_dec.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
    adsl_contr_1->dsc_cdrf_dec.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
    adsl_contr_1->dsc_cdrf_dec.imc_param_1 = 1;
#endif
    adsl_contr_1->dsc_cdrf_dec.imc_param_2 = -15;
    adsl_contr_1->dsc_cdrf_dec.imc_param_3 = 1;
    D_M_CDX_DEC( &adsl_contr_1->dsc_cdrf_dec );
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T D_M_CDX_DEC() returned im_return=%d.",
        __LINE__,
        adsl_contr_1->dsc_cdrf_dec.imc_return );
#endif
    if (adsl_contr_1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
        // to-do 07.01.14 KB error message
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_COMPR_ERR); //TODO MS what is this error?
    }

    /* start compression output                                         */
    // memset( &adsl_contr_1->dsc_cdrf_enc, 0, sizeof(struct dsd_cdr_ctrl) );  /* compress data record oriented control */
    adsl_contr_1->dsc_cdrf_enc.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
    adsl_contr_1->dsc_cdrf_enc.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
#ifndef WHY_DOES_THIS_NOT_WORK_140108
    adsl_contr_1->dsc_cdrf_enc.imc_param_1 = 1;
#endif
    adsl_contr_1->dsc_cdrf_enc.imc_param_2 = -15;
    adsl_contr_1->dsc_cdrf_enc.imc_param_3 = 1;
    D_M_CDX_ENC( &adsl_contr_1->dsc_cdrf_enc );
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T D_M_CDX_ENC() returned im_return=%d.",
        __LINE__,
        adsl_contr_1->dsc_cdrf_enc.imc_return );
#endif
    if (adsl_contr_1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
        // to-do 07.01.14 KB error message
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_COMPR_ERR);
    }

#ifdef B150318
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-I compression x-webkit-deflate-frame active",
        __LINE__ );
#endif
    switch (adsl_contr_1->iec_clcomp) {      /* compression with WebSocket client */
    case ied_clcomp_xwdf:                  /* x-webkit-deflate-frame  */
        achl_w1 = (char *) "x-webkit-deflate-frame";
        break;
    case ied_clcomp_pmd_2:                 /* permessage-deflate      */
        achl_w1 = (char *) "permessage-deflate";
        break;
    default:
        achl_w1 = (char *) "* undef *";
        break;
    }
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-I compression %s active (iec_clcomp=%d)",
        __LINE__, achl_w1, adsl_contr_1->iec_clcomp );

p_cl_sta_40:                             /* continue start client   */


    
    
    
    return IE_WSO_OPENED;


p_inp_client_20:                         /* input from client, WebSocket protocol */
    //achl_keyb_mouse = chrl_work2;            /* position work area, keyboard and mouse events */
    //MS-RDP! adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch = NULL;  /* chain of client commands, input */
    //MS-RDP! aadsl_cc_co1_l = &adsl_contr_1->dsc_c_wtrc1.adsc_cc_co1_ch;  /* position chain of client commands, input */

p_inp_client_24:                         /* check if input from client */
    while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
        adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
        if (adsl_gai1_inp_1 == NULL) {
            goto p_inp_client_end;               /* input from client processed */
        }
    }
    iml_len_header = 2;                      /* length header needed    */

p_inp_client_28:                         /* copy header to contiguos area */
    adsl_gai1_inp_rp = adsl_gai1_inp_1;      /* input data read pointer */
    achl_inp_rp = achl_w1 = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
    iml1 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
    if (iml1 >= iml_len_header) {
        achl_inp_rp += 2;                      /* this part processed     */
        goto p_inp_client_40;                  /* content contiguous      */
    }

    achl_w1 = achl_w2 = chrl_work1;          /* output area             */
    iml1 = iml_len_header;                   /* length header needed    */
    while (TRUE) {
        iml3 = adsl_gai1_inp_rp->achc_ginp_end - adsl_gai1_inp_rp->achc_ginp_cur;
        if (iml3 > iml1) iml3 = iml1;
        memcpy( achl_w2, adsl_gai1_inp_rp->achc_ginp_cur, iml3 );
        iml1 -= iml3;
        if (iml1 <= 0) {                       /* all data found          */
            achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur + iml3;  /* input read pointer */
            break;
        }
        adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
        if (adsl_gai1_inp_rp == NULL) {        /* wait for more input data */
            goto p_inp_client_end;               /* input from client processed */
        }
        achl_w2 += iml3;
    }
    if (iml_len_header != 2) {               /* not minimum header      */
        goto p_inp_client_48;                  /* header in contiguos area */
    }
    iml1 = iml_len_header;                   /* current length header   */

p_inp_client_40:                         /* header contiguous       */
#ifdef B150120
    if ((*((unsigned char *) achl_w1) & 0XBF) != 0X82) {  /* first byte invalid  */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W first byte record header 0X%02X invalid",
            __LINE__, *((unsigned char *) achl_w1) );
        /* input invalid */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return;
    }
    // to-do 05.11.13 KB - every input record needs to contain mask
    if (*(achl_w1 + 1) & 0X80) {             /* with mask               */
        iml_len_header = 2 + sizeof(adsl_contr_1->chrc_ws_mask);  /* length header needed */
    }
#endif
    if (   ((*((unsigned char *) achl_w1) & 0XBF) != 0X82)   /* Binary Frame */
        && ((*((unsigned char *) achl_w1) & 0XBF) != 0X88)  /* Connection Close Frame */
        && ((*((unsigned char *) achl_w1) & 0XBF) != 0X8A)) {  /* pong Frame */
            m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W first byte record header 0X%02X invalid",
                __LINE__, *((unsigned char *) achl_w1) );
            adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
            return WTE_ERR(IE_WSO_DATA_ERR);
    }
    if ((*(achl_w1 + 1) & 0X80) == 0) {      /* not with mask           */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W second byte record header 0X%02X contains no mask",
            __LINE__, *((unsigned char *) achl_w1 + 1) );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    byl_opcode = *achl_w1;                   /* opcode of WebSocket frame */
    bol_connection_closed = FALSE;           /* WebSocket connection close */
    if ((*((unsigned char *) achl_w1) & 0XBF) == 0X88) {  /* connection close */
        bol_connection_closed = TRUE;          /* WebSocket connection close */
    }
    iml_len_header = 2 + sizeof(adsl_contr_1->chrc_ws_mask);  /* length header needed */
    iml_len_payload = iml2 = *(achl_w1 + 1) & 0X7F;  /* length of payload */
    if (iml2 == 126) {                       /* two bytes length        */
        iml_len_header += 2;                   /* length header needed    */
    } else if (iml2 == 127) {                /* eight bytes length      */
        iml_len_header += 8;                   /* length header needed    */
    }
    if (iml1 < iml_len_header) {             /* not in this gather      */
        goto p_inp_client_28;                  /* copy header to contiguos area */
    }
    achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur + iml_len_header;  /* input read pointer */

p_inp_client_48:                         /* header in contiguos area */
    achl_w2 = achl_w1 + 2;                   /* address of mask         */
    if (iml2 == 126) {                       /* two bytes length        */
        iml_len_payload                        /* length of payload       */
            = (*((unsigned char *) achl_w1 + 2 + 0) << 8)
            | *((unsigned char *) achl_w1 + 2 + 1);
        achl_w2 = achl_w1 + 2 + 2;             /* address of mask         */
    } else if (iml2 == 127) {                /* eight bytes length      */
        if (   (*((unsigned char *) achl_w1 + 2 + 0) != 0)
            || (*((unsigned char *) achl_w1 + 2 + 1) != 0)
            || (*((unsigned char *) achl_w1 + 2 + 2) != 0)
            || (*((unsigned char *) achl_w1 + 2 + 3) != 0)
            || (*((unsigned char *) achl_w1 + 2 + 4) != 0)) {
                m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W length in record header received too high - input invalid",
                    __LINE__ );
                /* input invalid */
                adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
                return WTE_ERR(IE_WSO_DATA_ERR);
        }
        iml_len_payload                        /* length of payload       */
            = (*((unsigned char *) achl_w1 + 2 + 5) << 16)
            | (*((unsigned char *) achl_w1 + 2 + 6) << 8)
            | *((unsigned char *) achl_w1 + 2 + 7);
        achl_w2 = achl_w1 + 2 + 8;             /* address of mask         */
    }
    if (iml_len_payload == 0) {              /* length of payload       */
        goto p_inp_client_60;                  /* complete record received */
    }
    /* check if complete payload received                               */
    iml1 = iml_len_payload;                  /* length of payload       */
    adsl_gai1_w1 = adsl_gai1_inp_rp;         /* input data read pointer */
    achl_w3 = achl_inp_rp;                   /* input read pointer      */
    while (TRUE) {
        iml2 = adsl_gai1_w1->achc_ginp_end - achl_w3;
        if (iml2 > iml1) iml2 = iml1;
        iml1 -= iml2;
        if (iml1 <= 0) break;                  /* all data received       */
        adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
        if (adsl_gai1_w1 == NULL) {            /* wait for more input data */
            goto p_inp_client_end;               /* input from client processed */
        }
        achl_w3 = adsl_gai1_w1->achc_ginp_cur;
    }



p_inp_client_60:                         /* complete record received */
    if (*(achl_w1 + 1) & 0X80) {             /* with mask               */
#ifdef TRACEHL1
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T record with mask record length %d/0X%X.",
            __LINE__, iml_len_payload, iml_len_payload );
#endif
        memcpy( adsl_contr_1->chrc_ws_mask, achl_w2, sizeof(adsl_contr_1->chrc_ws_mask) );  /* copy the mask */
    }
    if (iml_len_payload == 0) {              /* length of payload       */
        goto p_inp_client_80;                  /* input record processed  */
    }
    bol_compressed = FALSE;                  /* input is compressed     */
    if ((*((unsigned char *) achl_w1) & 0X40) == 0) {  /* no compression */
        goto p_inp_client_64;                  /* record not compressed   */
    }
    if (adsl_contr_1->iec_clcomp == ied_clcomp_none) {  /* no compression */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T received record compressed but not handled out",
            __LINE__ );
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_COMPR_ERR);
    }
    bol_compressed = TRUE;                   /* input is compressed     */
    /* consume length iml_len_header from input                         */
    while (adsl_gai1_inp_1 != adsl_gai1_inp_rp) {  /* not current gather */
        adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
        adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
        if (adsl_gai1_inp_1 == NULL) {
            /* programm illogic                                                 */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_ILLOGIC);
        }
    }
    achl_w4 = adsl_contr_1->chrc_ws_mask;    /* start of mask           */
    achl_w5 = achl_w4 + sizeof(adsl_contr_1->chrc_ws_mask);  /* end of mask */
    iml1 = iml_len_payload;                  /* length of payload       */
    iml2 = 0;                                /* position in array gather */

p_cl_in_dec_00:                          /* decode and decompress input */
    achl_w2 = achl_inp_rp;                   /* current input pointer   */
    iml3 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
    if (iml3 > iml1) iml3 = iml1;
    achl_w3 = achl_w2 + iml3;                 /* end of input area       */
    do {
        *achl_w2++ ^= *achl_w4++;
        if (achl_w4 >= achl_w5) achl_w4 = adsl_contr_1->chrc_ws_mask;
    } while (achl_w2 < achl_w3);
    dsrl_gai1_work[ iml2 ].achc_ginp_cur = achl_inp_rp;
    achl_inp_rp += iml3;
    dsrl_gai1_work[ iml2 ].achc_ginp_end = achl_inp_rp;
    adsl_gai1_inp_1->achc_ginp_cur = achl_inp_rp;
    iml1 -= iml3;
    if (iml1 > 0) {                          /* more input              */
        iml2++;                                /* next gather             */
        if (iml2 >= (MAX_INP_GATHER)) {        /* number of input gather to be processed */
            /* programm illogic                                                 */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_ILLOGIC);
        }
        dsrl_gai1_work[ iml2 - 1 ].adsc_next = &dsrl_gai1_work[ iml2 ];
        adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
        if (adsl_gai1_inp_1 == NULL) {         /* end of data, illogic    */
            /* programm illogic                                                 */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_ILLOGIC);
        }
        achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
        goto p_cl_in_dec_00;                   /* decode and decompress input */
    }

    dsrl_gai1_work[ iml2 ].adsc_next = NULL;

    /* de-compress input                                                */
    adsl_contr_1->dsc_cdrf_dec.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
    adsl_contr_1->dsc_cdrf_dec.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
    adsl_contr_1->dsc_cdrf_dec.adsc_gai1_in = dsrl_gai1_work;  /* input data */
    adsl_contr_1->dsc_cdrf_dec.achc_out_cur = chrl_work1;  /* current end of output data */
    adsl_contr_1->dsc_cdrf_dec.achc_out_end = chrl_work1 + sizeof(chrl_work1);  /* end of buffer for output data */
    adsl_contr_1->dsc_cdrf_dec.boc_mp_flush = TRUE;  /* end-of-record input */
    D_M_CDX_DEC( &adsl_contr_1->dsc_cdrf_dec );
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T D_M_CDX_DEC() returned im_return=%d.",
        __LINE__,
        adsl_contr_1->dsc_cdrf_dec.imc_return );
#endif
    if (adsl_contr_1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
        // to-do 07.01.14 KB error message
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_COMPR_ERR);
    }
    if (adsl_contr_1->dsc_cdrf_dec.boc_sr_flush == FALSE) {  /* end-of-record output */
        // to-do 07.01.14 KB error message
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_COMPR_ERR);
    }
    achl_w1 = chrl_work1;                    /* output area             */
    iml_len_payload = adsl_contr_1->dsc_cdrf_dec.achc_out_cur - chrl_work1;  /* length of payload */
    goto p_inp_client_72;                    /* input decoded           */

p_inp_client_64:                         /* record not compressed   */
    achl_w1 = achl_inp_rp;                   /* current input pointer   */
    if ((adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp) >= iml_len_payload) {
        goto p_inp_client_68;                  /* payload in contiguous memory */
    }
    if (iml_len_payload > sizeof(chrl_work1)) {  /* length of payload   */
        /* input invalid */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    achl_w1 = achl_w2 = chrl_work1;          /* output area             */
    iml1 = iml_len_payload;                  /* length of payload       */
    while (TRUE) {
        iml2 = adsl_gai1_inp_rp->achc_ginp_end - achl_inp_rp;
        if (iml2 > iml1) iml2 = iml1;
        memcpy( achl_w2, achl_inp_rp, iml2 );
        iml1 -= iml3;
        if (iml1 <= 0) {                       /* all data found          */
            break;
        }
        adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
        if (adsl_gai1_inp_rp == NULL) {        /* end of data, illogic    */
            /* programm illogic                                                 */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_ILLOGIC);
        }
        achl_w2 += iml2;
        achl_inp_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* input read pointer */
    }

p_inp_client_68:                         /* payload in contiguous memory */
    achl_w2 = achl_w1;                       /* start of input area     */
    achl_w3 = achl_w1 + iml_len_payload;     /* end of input area       */
    achl_w4 = adsl_contr_1->chrc_ws_mask;    /* start of mask           */
    achl_w5 = achl_w4 + sizeof(adsl_contr_1->chrc_ws_mask);  /* end of mask */
    do {
        *achl_w2++ ^= *achl_w4++;
        if (achl_w4 >= achl_w5) achl_w4 = adsl_contr_1->chrc_ws_mask;
    } while (achl_w2 < achl_w3);

p_inp_client_72:                         /* input decoded           */
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T decoded input record length %d/0X%X.",
        __LINE__, iml_len_payload, iml_len_payload );
    m_sdh_console_out( &dsl_output_area_1, achl_w1, iml_len_payload );
#endif
    if (dsl_output_area_1.imc_trace_level) {    /* WSP trace level         */
        memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
        memcpy( dsl_wtrh.chrc_wtrt_id, "SWTRIN01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
        dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
        dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
        memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
        ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
        ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
        ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
            "xl-webterm-uni-01 l%05d input from client decoded length=%d/0X%X.",
            __LINE__, iml_len_payload, iml_len_payload );
        achl_w2 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w2)
        memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
        ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
        ADSL_WTR_G2->achc_content = achl_w1;   /* content of text / data  */
        ADSL_WTR_G2->imc_length = iml_len_payload;
        ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
        bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
            DEF_AUX_WSP_TRACE,  /* write WSP trace */
            &dsl_wtrh,
            0 );
    }
    if ((byl_opcode & 0XBF) == 0X8A) {       /* pong Frame              */
        goto p_inp_client_76;                  /* input processed         */
    }
    if (bol_connection_closed) {             /* WebSocket connection close */
        goto p_inp_client_76;                  /* input processed         */
    }
    switch (*achl_w1) {                      /* record type             */
case 0X20:
    goto p_webso_00;                     /* WebSocket functions     */
default:
    *imp_out = m_fromclient_data(adsp_hl_clib_1, achl_w1, achl_w3);
case 0X21:                             /* mouse / keyboard        */
    break;
    //MS_RDP!!
    //#define ACHL_G_KEYB_MOUSE (achl_keyb_mouse + sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb))
    //       iml1 = chrl_work2 + sizeof(chrl_work2) - ACHL_G_KEYB_MOUSE;
    //       if (iml1 <= 0) {                     /* no area for keys        */
    //         m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W overflow output area for m_proc_mouse_keyboard()",
    //                       __LINE__ );
    //         break;
    //       }
    //#define ADSL_G_CC_CO1 ((struct dsd_cc_co1 *) achl_keyb_mouse)
    //#define ADSL_G_EVENTS_MOUSE_KEYB ((struct dsd_cc_events_mouse_keyb *) (ADSL_G_CC_CO1 + 1))
    //       memset( achl_keyb_mouse, 0, sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb) );
    //       ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order = 0;  /* count keyboard and mouse events */
    //       iml1 = m_proc_mouse_keyboard( ACHL_G_KEYB_MOUSE, iml1,
    //                                     &ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order,
    //                                     achl_w1 + 1, iml_len_payload - 1 );
    //       if (iml1 < 0) {
    //         m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-W m_proc_mouse_keyboard() returned error",
    //                       __LINE__ );
    //         break;
    //       }
    //#ifdef TRACEHL1
    //       m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T m_proc_mouse_keyboard() returned %d/0X%X events %d.",
    //                     __LINE__, iml1, iml1, ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order );
    //#endif
    //       if (dsl_output_area_1.imc_trace_level) {  /* WSP trace level       */
    //         memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
    //         memcpy( dsl_wtrh.chrc_wtrt_id, "SWTRKEM1", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
    //         dsl_wtrh.imc_wtrh_sno = dsl_output_area_1.imc_sno;  /* WSP session number */
    //#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) chrl_work3)
    //         dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
    //         memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
    //         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
    //         ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
    //         ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
    //                                            "xl-webterm-uni-01 l%05d m_proc_mouse_keyboard() returned=%d imc_no_order=%d.",
    //                                            __LINE__, iml1, ADSL_G_EVENTS_MOUSE_KEYB->imc_no_order );
    //         achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
    //#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
    //         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
    //         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
    //         ADSL_WTR_G2->achc_content = ACHL_G_KEYB_MOUSE;  /* content of text / data */
    //         ADSL_WTR_G2->imc_length = iml1;
    //         ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;
    //#undef ADSL_WTR_G1
    //#undef ADSL_WTR_G2
    //         bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
    //                                             DEF_AUX_WSP_TRACE,  /* write WSP trace */
    //                                             &dsl_wtrh,
    //                                             0 );
    //       }
    //       if (iml1 == 0) {
    //         break;
    //       }
    //#ifdef TRACEHL1
    //       m_sdh_console_out( &dsl_output_area_1, ACHL_G_KEYB_MOUSE, iml1 );
    //#endif
    //       ADSL_G_EVENTS_MOUSE_KEYB->achc_event_buf = ACHL_G_KEYB_MOUSE;  /* buffer with events */
    //       ADSL_G_EVENTS_MOUSE_KEYB->imc_events_len = iml1;  /* length of events */
    //       ADSL_G_CC_CO1->iec_cc_command = ied_ccc_events_mouse_keyb;  /* events from mouse or keyboard */
    //       *aadsl_cc_co1_l = ADSL_G_CC_CO1;     /* append to chain         */
    //       aadsl_cc_co1_l = &ADSL_G_CC_CO1->adsc_next;  /* position chain of client commands, input */
    //       achl_keyb_mouse += (sizeof(struct dsd_cc_co1) + sizeof(struct dsd_cc_events_mouse_keyb) + iml1 + sizeof(void *) - 1)
    //                            & (0 - sizeof(void *));
    //       break;
    //#undef ACHL_G_KEYB_MOUSE
    //#undef ADSL_G_CC_CO1
    //#undef ADSL_G_EVENTS_MOUSE_KEYB
    }


p_inp_client_76:                         /* input processed         */
    if (bol_compressed) {                    /* input is compressed     */
        if ((((unsigned char) byl_opcode) & 0XBF) == 0X8A) {  /* pong Frame */
            goto p_webso_pong_00;                /* received pong           */
        }
        if (bol_connection_closed) {           /* WebSocket connection close */
            goto p_webso_cc_00;                  /* received connection close */
        }
        goto p_inp_client_24;                  /* check if input from client */
    }

p_inp_client_80:                         /* input record processed  */
    iml1 = iml_len_header + iml_len_payload;  /* length complete record */
    do {
        iml2 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
        if (iml2 > iml1) iml2 = iml1;
        adsl_gai1_inp_1->achc_ginp_cur += iml2;
        iml1 -= iml2;
        if (iml1 <= 0) {                       /* all data consumed       */
            if ((((unsigned char) byl_opcode) & 0XBF) == 0X8A) {  /* pong Frame */
                goto p_webso_pong_00;              /* received pong           */
            }
            if (bol_connection_closed) {         /* WebSocket connection close */
                goto p_webso_cc_00;                /* received connection close */
            }
            goto p_inp_client_24;                /* check if input from client */
        }
        adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
    } while (adsl_gai1_inp_1);
    /* programm illogic                                                 */
    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
    return WTE_ERR(IE_WSO_ILLOGIC);

p_inp_client_end:                        /* input from client processed */
    //  if (achl_keyb_mouse == chrl_work2) return;  /* position work area, keyboard and mouse events */
    //#ifndef B150213
    //MS_RDP!!   if (adsl_contr_1->dsc_c_wtrc1.inc_return != DEF_IRET_NORMAL) {  /* not o.k. returned */
    //return;
    //}
    //#endif
    //   adsl_contr_1->dsc_c_wtrc1.vpc_userfld = dsl_output_area_1.vpc_userfld;  /* User Field Subroutine */
    //   adsl_contr_1->dsc_c_wtrc1.amc_aux = dsl_output_area_1.amc_aux;  /* auxiliary subroutine */
    //   adsl_contr_1->dsc_c_wtrc1.adsc_gather_i_1_in = NULL;
    return IE_WSO_CALLCLIENT;//goto p_rdp_client_20;                    /* call RDP client         */

p_webso_pong_00:                         /* received pong           */
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T received pong iml_len_payload=%d.",
        __LINE__, iml_len_payload );
#endif
    goto p_inp_client_24;                    /* check if input from client */

p_webso_cc_00:                           /* received connection close */
    bol_connection_closed = FALSE;           /* WebSocket connection close */
    /* MS-IE does not send reason                                       */
    iml1 = 0;
    if (iml_len_payload == 0) {              /* nothing from MS-IE      */
        goto p_webso_cc_20;                    /* reason in iml1          */
    }
    if (iml_len_payload != 2) {              /* length complete record  */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E p_webso_cc_00: - received connection close - length payload %d invalid",
            __LINE__, iml_len_payload );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    iml1 = (*((unsigned char *) achl_w1 + 0) << 8)
        | *((unsigned char *) achl_w1 + 1);

p_webso_cc_20:                           /* reason in iml1          */
    //#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T p_webso_cc_00: - received connection close - reason %d.",
        __LINE__, iml1 );
    //#endif
    if (adsl_contr_1->boc_conn_close_sent) {  /* has already sent connection close */
        adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* set normal end     */
        goto p_inp_client_24;                  /* check if input from client */
    }
    if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
        bol_rc = m_get_new_workarea( &dsl_output_area_1 );
        if (bol_rc == FALSE) {
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_AUXERR);
        }
    }
    *(dsl_output_area_1.achc_lower + 0) = (unsigned char) 0X88;
    *(dsl_output_area_1.achc_lower + 1) = (unsigned char) 2;
    *(dsl_output_area_1.achc_lower + 2 + 0) = (unsigned char) (1000 >> 8);
    *(dsl_output_area_1.achc_lower + 2 + 1) = (unsigned char) 1000;
    dsl_output_area_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_output_area_1.achc_upper)
    ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
    dsl_output_area_1.achc_lower += 2 + 2;
    ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
    ADSL_GAI1_G->adsc_next = NULL;
    *dsl_output_area_1.aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
    dsl_output_area_1.aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
    goto p_inp_client_24;                    /* check if input from client */

p_webso_server_close_00:                 /* server has closed connection */
    if (adsp_hl_clib_1->boc_eof_server) {    /* End-of-File Server    */
        goto p_webso_server_close_20;          /* WebSocket shutdown      */
    }
    bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
        DEF_AUX_TCP_CLOSE,  /* close TCP to Server */
        NULL,
        0 );
    if (bol_rc == FALSE) {
        m_sdh_printf( &dsl_output_area_1, "xlt-rdp-cl-se-01-l%05d-W DEF_AUX_TCP_CLOSE WTS returned FALSE",
            __LINE__ );
#ifdef XYZ1
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return;
#endif
    }

p_webso_server_close_20:                 /* WebSocket shutdown      */
#ifdef XYZ1
    switch (adsp_ah1->iec_scc) {             /* server component command */
case ied_scc_invalid:                  /* command is invalid      */
    return TRUE;
case ied_scc_end_session:              /* end of session server side */
    iml1 = 1000;
    break;
case ied_scc_end_shutdown:             /* shutdown of server      */
    iml1 = 1001;
    break;
default:
    return FALSE;
    }
    if ((adsp_oa->achc_upper - adsp_oa->achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
        bol_rc = m_get_new_workarea( adsp_oa );
        if (bol_rc == FALSE) return FALSE;
    }
#endif
    iml1 = 1000;
    if (adsl_contr_1->boc_conn_close_sent) return WTE_ERR(IE_WSO_CLOSED);  /* has already sent connection close */
    if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (2 + 2 + sizeof(struct dsd_gather_i_1))) {  /* need buffer */
        bol_rc = m_get_new_workarea( &dsl_output_area_1 );
        if (bol_rc == FALSE) {
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_AUXERR);
        }
    }
    *(dsl_output_area_1.achc_lower + 0) = (unsigned char) 0X88;
    *(dsl_output_area_1.achc_lower + 1) = (unsigned char) 2;
    *(dsl_output_area_1.achc_lower + 2 + 0) = (unsigned char) (iml1 >> 8);
    *(dsl_output_area_1.achc_lower + 2 + 1) = (unsigned char) iml1;
    dsl_output_area_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) dsl_output_area_1.achc_upper)
    ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
    dsl_output_area_1.achc_lower += 2 + 2;
    ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
    ADSL_GAI1_G->adsc_next = NULL;
    *dsl_output_area_1.aadsrc_gai1_client = ADSL_GAI1_G;  /* output data to client */
    // dsl_output_area_1.aadsrc_gai1_client = &ADSL_GAI1_G->adsc_next;  /* next output data to client */
#undef ADSL_GAI1_G
    adsl_contr_1->boc_conn_close_sent = TRUE;  /* has already sent connection close */
    return IE_WSO_CLOSED;                                  /* all done                */

p_webso_00:                              /* WebSocket functions     */
    if (((int) adsl_contr_1->dsc_awc1.iec_cwc) != 0) {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01 m_hlclib01() l%05d p_webso_00 invalid",
            __LINE__ );
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_ERR);
    }
    achl_w2 = achl_w1 + 1;                   /* start of command string */
#ifdef PROBLEM_JS_140205
    if (*(achl_w1 + iml_len_payload - 1) == 0) {
        iml_len_payload--;
    }
    iml1 = 1;
    while (iml1 < iml_len_payload) {
        if (*(achl_w1 + iml1) == 0) {
            *(achl_w1 + iml1) = ' ';
        }
        iml1++;
    }
#endif
    achl_w3 = achl_w1 + iml_len_payload;     /* end of input area       */
    iml_wt_js_version = -1;                  /* version of WT JS client */

p_webso_20:                              /* scan string from WS-JS  */
    if (achl_w2 >= achl_w3) {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - invalid 01",
            __LINE__, iml_len_payload, achl_w1 );
#ifdef PROBLEM_KB_140210
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T achl_w1=%p achl_w2=%p achl_w3=%p.",
            __LINE__, achl_w1, achl_w2, achl_w3 );
        goto p_webso_28;                       /* found values            */
#endif
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    achl_w4 = (char *) memchr( achl_w2, '=', achl_w3 - achl_w2 );
    if (achl_w4 == NULL) {                   /* separator not found     */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d no equals - invalid 02",
            __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    iml1 = achl_w4 - achl_w2;                /* length of keyword       */
    iml2 = sizeof(achrs_wt_js_first) / sizeof(achrs_wt_js_first[0]);
    do {
        if (   (strlen( achrs_wt_js_first[ iml2 - 1 ] ) == iml1)
            && (!memcmp( achrs_wt_js_first[ iml2 - 1 ], achl_w2, iml1 ))) {
                break;
        }
        iml2--;                                /* decrement index         */
    } while (iml2 > 0);
    if (iml2 == 0) {                         /* parameter not found     */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword not recognized - invalid 03",
            __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    switch (iml2) {
case (0 + 1):
    aiml_w1 = &iml_wt_js_version;        /* version of WT JS client */
    break;
case (1 + 1):
    aiml_w1 = &adsl_contr_1->imc_wt_js_width;  /* WT-JS screen width */
    break;
case (2 + 1):
    aiml_w1 = &adsl_contr_1->imc_wt_js_height;  /* WT-JS screen height */
    break;
default:
    adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
    return WTE_ERR(IE_WSO_ERR);
    }
    if (*aiml_w1 > 0) {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d double - invalid 04",
            __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    achl_w4++;                               /* after equals            */
    if (achl_w4 >= achl_w3) {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d no value - invalid 05",
            __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    iml1 = 0;
    while (   (achl_w4 < achl_w3)
        && ((*achl_w4 >= '0') && (*achl_w4 <= '9'))) {
            iml1 *= 10;
            iml1 += *achl_w4 - '0';
            achl_w4++;
    }
    if (iml1 <= 0) {
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d keyword no %d value invalid - invalid 06",
            __LINE__, iml_len_payload, achl_w1, achl_w2 - achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    *aiml_w1 = iml1;
    if (achl_w4 >= achl_w3) {                /* end of string           */
        goto p_webso_28;                       /* found values            */
    }
    if (*achl_w4 != ' ') {                   /* separator invalid       */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" - pos %d invalid separator 0X%02X - invalid 06",
            __LINE__, iml_len_payload, achl_w1, achl_w4 - achl_w1, (unsigned char) *achl_w4 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    achl_w2 = achl_w4 + 1;                   /* next keyword            */
    goto p_webso_20;                         /* scan string from WS-JS  */

p_webso_28:                              /* found values            */
#ifdef TRACEHL1
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-T command 0X20 version=%d width=%d height=%d.",
        __LINE__, iml_wt_js_version, adsl_contr_1->imc_wt_js_width, adsl_contr_1->imc_wt_js_height );
#endif
    if (iml_wt_js_version < 0) {             /* version of WT JS client */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" no version= - invalid 07",
            __LINE__, iml_len_payload, achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    if (iml_wt_js_version != HL_WT_JS_VERSION) {  /* version of WT JS client */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" version=%d but requested=%d - invalid 08",
            __LINE__, iml_len_payload, achl_w1, iml_wt_js_version, HL_WT_JS_VERSION );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    if (adsl_contr_1->imc_wt_js_width <= 0) {  /* WT-JS screen width    */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" no width= - invalid 09",
            __LINE__, iml_len_payload, achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    if (adsl_contr_1->imc_wt_js_height <= 0) {  /* WT-JS screen height  */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01-l%05d-E received from WT-JS client \"%.*s\" no height= - invalid 10",
            __LINE__, iml_len_payload, achl_w1 );
        adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
        return WTE_ERR(IE_WSO_DATA_ERR);
    }
    // to-do 06.02.14 KB - bol1 correct ???
    bol1 = FALSE;                            /* no input                */

    adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_open;  /* open - connect to internal routine */
    adsl_contr_1->dsc_awc1.imc_signal = 0X00000020;  /* signal to set   */
    bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
        DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
        &adsl_contr_1->dsc_awc1,
        sizeof(struct dsd_aux_webso_conn_1) );
    if (bol_rc == FALSE) {                   /* returned error          */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
            __LINE__ );
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_AUXERR);;
    }
#ifdef TRACEHL2X
    m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned type of WebSocket connect - iec_twc %d.",
        __LINE__, adsl_contr_1->dsc_awc1.iec_twc );
#endif
    switch (adsl_contr_1->dsc_awc1.iec_twc) {  /* type of WebSocket connect */
case ied_twc_static:                   /* static, server configured */
    //     goto p_conn_00;                      /* connect to server       */
    break;
    //   case ied_twc_dynamic:                  /* dynamic, nothing configured */
case ied_twc_lbal:                     /* WTS load-balancing      */
    //MS_RDP!!goto p_lbvdi_s_00;                   /* send WTS load-balancing or VDI */
case ied_twc_vdi:                      /* VDI                     */
    //MS_RDP!!goto p_lbvdi_s_00;                   /* send WTS load-balancing or VDI */
case ied_twc_pttd:                     /* pass thru to desktop - DOD desktop-on-demand */
    //MS_RDP!!goto p_webso_40;                     /* WebSocket DoD - desktop-on-demand */
default:
    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
    return WTE_ERR(IE_WSO_ERR);
    }
    // bol1 = TRUE;                             /* need to process input   */
    // to-do 06.02.14 KB - bol1 correct ???
    goto p_webso_80;                         /* close WebSocket         */


p_webso_60:                              /* status WebSocket no more active */
    bol1 = FALSE;                            /* need to check input     */
    if (adsl_contr_1->dsc_awc1.boc_connected) {  /* connected to target / server */
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
        memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
        ADSL_WTR1_G->ucc_record_type = 0X08;   /* record type             */
        ADSL_WTR1_G->adsc_gai1_data = NULL;    /* output data be be sent to client */
        bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
        if (bol_rc == FALSE) {                 /* error occured           */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_ERR);
        }
        goto p_webso_80;                       /* close WebSocket         */
#undef ADSL_WTR1_G
    }

#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) chrl_work1)
    memset( ADSL_WTR1_G, 0, sizeof(struct dsd_wt_record_1) + sizeof(struct dsd_gather_i_1) );
    ADSL_WTR1_G->ucc_record_type = 0X09;     /* record type             */
#define ADSL_GAI1_G ((struct dsd_gather_i_1 *) (ADSL_WTR1_G + 1))
    if ((dsl_output_area_1.achc_upper - dsl_output_area_1.achc_lower) < (6 + 40)) {  /* need buffer */
        bol_rc = m_get_new_workarea( &dsl_output_area_1 );
        if (bol_rc == FALSE) {
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
            return WTE_ERR(IE_WSO_AUXERR);
        }
    }
    ADSL_GAI1_G->achc_ginp_cur = dsl_output_area_1.achc_lower;
    dsl_output_area_1.achc_lower
        += m_out_nhasn1( dsl_output_area_1.achc_lower, adsl_contr_1->dsc_awc1.imc_connect_error );  /* connect error */
    if (adsl_contr_1->dsc_awc1.imc_connect_error != 30000) {  /* connect error */
        iml1 = sprintf( dsl_output_area_1.achc_lower, "server connect error %d.",
            adsl_contr_1->dsc_awc1.imc_connect_error );  /* connect error */
    } else {
        iml1 = sprintf( dsl_output_area_1.achc_lower, "load-balancing - no server replied" );
    }
    dsl_output_area_1.achc_lower += iml1;
    ADSL_GAI1_G->achc_ginp_end = dsl_output_area_1.achc_lower;
    ADSL_WTR1_G->adsc_gai1_data = ADSL_GAI1_G;  /* output data be be sent to client */
#undef ADSL_GAI1_G
    bol_rc = m_send_websocket_data( &dsl_output_area_1, adsl_contr_1, ADSL_WTR1_G );
    if (bol_rc == FALSE) {                   /* error occured           */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_ERR);
    }
#undef ADSL_WTR1_G

    bol1 = TRUE;                             /* do not start RDP        */
    adsl_gai1_inp_1 = NULL;                  /* no input from client    */

p_webso_80:                              /* close WebSocket         */
    adsl_contr_1->dsc_awc1.iec_cwc = ied_cwc_close;  /* close connection to internal routine */
    bol_rc = dsl_output_area_1.amc_aux( dsl_output_area_1.vpc_userfld,
        DEF_AUX_WEBSO_CONN,  /* connect for WebSocket applications */
        &adsl_contr_1->dsc_awc1,
        sizeof(struct dsd_aux_webso_conn_1) );
    if (bol_rc == FALSE) {                   /* returned error          */
        m_sdh_printf( &dsl_output_area_1, "xl-webterm-uni-01 m_hlclib01() l%05d DEF_AUX_WEBSO_CONN returned error",
            __LINE__ );
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
        return WTE_ERR(IE_WSO_AUXERR);
    }
    // to-do 06.02.14 KB - bol1 correct ???
    if (bol1) {                              /* need to process input   */
        if (adsl_gai1_inp_1 == NULL) return WTE_ERR(IE_WSO_DATA_ERR);   /* no input from client    */
        goto p_inp_client_76;                  /* input processed         */
    }

    //MS _ SKIPPED _ ELSE START RDP CLIENT



    return IE_WSO_SUCCESS;
}


int m_consume(struct dsd_gather_i_1* dsp_gather,int imp_len)
{                                   
    while (dsp_gather)
    {
        int iml_len = dsp_gather->achc_ginp_end - dsp_gather->achc_ginp_cur;
        if (iml_len >= imp_len)
        {            
            dsp_gather->achc_ginp_cur += imp_len;
            return 0;
        }
        dsp_gather->achc_ginp_cur = dsp_gather->achc_ginp_end;
        imp_len -= iml_len;
        dsp_gather = dsp_gather->adsc_next;        
    }
    return -1;
    

}


BOOL m_get_nhasn_len(dsd_gather_i_1* adsp_gather, char* achp_cur,
                     int* aimp_length, int* aimp_bytes)
{
    int iml_len = 0;
    int iml_len_nhasn = 0;

    dsd_gather_i_1* adsl_currgather = adsp_gather;
    char* achl_cur = achp_cur;
    while (adsl_currgather) {        
        while (achl_cur < adsl_currgather->achc_ginp_end) {
            iml_len <<= 7;                /* shift old value         */
            iml_len |= *achl_cur & 0x7f;    /* apply new bits          */
            iml_len_nhasn++;                 /* increment length bytes NHASN */
            if (!(*achl_cur & 0x80)) {        /* more bit not set      */
                // the length is complete
                *aimp_length = iml_len;
                *aimp_bytes = iml_len_nhasn;
                return TRUE;
            }
            achl_cur++;
        }
        // we used all bytes in current gather
        adsl_currgather = adsl_currgather->adsc_next;
        if (adsl_currgather)
            achl_cur = adsl_currgather->achc_ginp_cur;
    }
    // only arrives here if we ran out of bytes
    return FALSE;
}

BOOL m_get_nhasn_len(char* achp_data, char* achp_end,
                     int* aimp_length, int* aimp_bytes)
{
    int iml_len = 0;
    int iml_len_nhasn = 0;

   // dsd_gather_i_1* adsl_currgather = adsp_gather;
    char* achl_cur = achp_data;
       
        while (achl_cur < achp_end) {
            iml_len <<= 7;                /* shift old value         */
            iml_len |= *achl_cur & 0x7f;    /* apply new bits          */
            iml_len_nhasn++;                 /* increment length bytes NHASN */
            if (!(*achl_cur & 0x80)) {        /* more bit not set      */
                // the length is complete
                *aimp_length = iml_len;
                *aimp_bytes = iml_len_nhasn;
                return TRUE;
            }
            achl_cur++;
        }
        // we used all bytes in current gather
        
    
    // only arrives here if we ran out of bytes
    return FALSE;
}




/**
 * @param achp_configname The start of the configuration name
 * @param achp_configname_end The end of the configuration name buffer
 * @param imp_configname_len The configuration name length
 * @param achp_dst The destination buffer - where the configuration is written
 * @param achp_dst_end End of the destination buffer
 */
int m_get_jterm_config(struct dsd_hl_clib_1* adsp_hlclib, char* achp_configname,char* achp_configname_end,int imp_configname_len,char* achp_dst,char* achp_dst_end)
{
    if (achp_configname_end - achp_configname < imp_configname_len)
        return -1;

    struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
    dsl_sdh_call_1.amc_aux = adsp_hlclib->amc_aux;  /* auxiliary subroutine */
    dsl_sdh_call_1.vpc_userfld = adsp_hlclib->vpc_userfld;  /* User Field Subroutine */

    struct dsd_clib1_contr_1* adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hlclib->ac_ext;

    int iml_available = achp_dst_end - achp_dst;
    
    class  ds_wsp_helper   dsl_wsp_helper;       
    dsl_wsp_helper.m_init_trans( adsp_hlclib );

    ds_ldap ds_ldap_instance;
    ds_ldap_instance.m_init(&dsl_wsp_helper);

    dsd_sdh_ident_set_1 ds_ident;
    dsl_wsp_helper.m_cb_get_ident(&ds_ident);
    ds_usercma dsl_ucma;
    if (!ds_usercma::m_get_usercma( &dsl_wsp_helper, &dsl_ucma )) {
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E No user config in LDAP",
            __LINE__);
        return -3;
    }
    struct dsd_getuser dsl_user;
    dsl_ucma.m_get_user( &dsl_user );

    BOOL bol_ret = dsl_ucma.m_select_config_ldap();
    if (!bol_ret)
    {     
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E unable to connect to LDAP",
            __LINE__);
        return -4;
    }

    int inl_ret = ds_ldap_instance.m_simple_bind();
    if (inl_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E unable to connect to LDAP \"%.*s\"",
            __LINE__, hstr.m_get_len(), hstr.m_get_ptr() );

        return -2;
    }
    ds_hstring hstr_config_name(&dsl_wsp_helper, achp_configname,imp_configname_len);
    const ds_hstring hstr_hobhobte(&dsl_wsp_helper,"hobhobte");
//    ds_hvector<ds_attribute_string> dsl_config_attributes(&dsl_wsp_helper);
    //ds_hvector<ds_attribute_string> dsl_config_attributes_own(&dsl_wsp_helper);
    ds_hvector<ds_attribute_string> dsl_config_attributes_tree(&dsl_wsp_helper);
    ds_hvector<ds_attribute_string> dsl_config_attributes_group(&dsl_wsp_helper);
    ds_attribute_string dsl_config_attribute_own(&dsl_wsp_helper);

    
    int inl_domain_auth = dsl_user.inc_auth_method;
    const ds_hstring hstr_our_dn = dsl_user.dsc_userdn;

    //int im_ret = ds_ldap_instance.m_read_attributes(&hstr_hobhobte, NULL, &hstr_our_dn, ied_sear_superlevel,&dsl_config_attributes);
    int im_ret = ds_ldap_instance.m_collect_attributes( &hstr_our_dn, 
                                                        &hstr_hobhobte,
                                                        &dsl_config_attribute_own,
                                                        &dsl_config_attributes_group,
                                                        &dsl_config_attributes_tree
                                                        );

    if (im_ret)
    {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E unable to connect to LDAP \"%.*s\"",
            __LINE__, hstr.m_get_len(), hstr.m_get_ptr() );
        return -5;
    }

    if (!dsl_config_attribute_own.m_get_values().m_size() && !dsl_config_attributes_group.m_size() && !dsl_config_attributes_tree.m_size() )
    {
    
        //no attribute found
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E no jterm config found for DN \"%.*s\"",
            __LINE__, hstr_our_dn.m_get_len(), hstr_our_dn.m_get_ptr() );
        return -6;
    }

   
    
    bool bo_session_found = false;
    int iml_ret = 0;
    if (dsl_config_attribute_own.m_get_values().m_size())
    {
    
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attribute_own.m_get_value_at(0);


        iml_ret = m_search_session(ds_jterm_config, &dsl_wsp_helper, achp_configname, imp_configname_len, achp_dst, achp_dst_end,
            &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group,adsl_contr_1);
        if (iml_ret > 0)
        {
            bo_session_found = true;
            //return iml_ret;
        }
#if TRACE_JTERMCONF_SEARCH
        else //if (iml_ret < 0)
        {
            m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-I no jterm config found in user (code:%d) for DN \"%.*s\" config:\"%.*s\"",
                __LINE__, iml_ret, hstr_our_dn.m_get_len(), hstr_our_dn.m_get_ptr(), ds_jterm_config.m_get_len(), ds_jterm_config.m_get_ptr() );
        }
#endif
        m_add_rights(ds_jterm_config, &dsl_wsp_helper, &adsl_contr_1->dsc_user_rights);

    }

    int iml_config_count = dsl_config_attributes_tree.m_size();
    int iml_nextconfig = 0;
    while (iml_nextconfig < iml_config_count)
    {
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attributes_tree.m_get(iml_nextconfig).m_get_value_at(0);
  
    
        if (!bo_session_found){
            iml_ret = m_search_session(ds_jterm_config, &dsl_wsp_helper, achp_configname, imp_configname_len, achp_dst, achp_dst_end,
                &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group,adsl_contr_1);
        
            if (iml_ret > 0)
            {
                bo_session_found = true;
            }
#if TRACE_JTERMCONF_SEARCH
            else //if (iml_ret < 0)
            {
                m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-I no jterm config found in tree (code:%d) for DN \"%.*s\" config:\"%.*s\"",
                    __LINE__, iml_ret, hstr_our_dn.m_get_len(), hstr_our_dn.m_get_ptr(), ds_jterm_config.m_get_len(), ds_jterm_config.m_get_ptr() );
            }
#endif
        }

        m_add_rights(ds_jterm_config, &dsl_wsp_helper, &adsl_contr_1->dsc_user_rights);

        iml_nextconfig++;
    }


    iml_config_count = dsl_config_attributes_group.m_size();
    iml_nextconfig = 0;
    while (iml_nextconfig < iml_config_count)
    {
        // parse the attribute
        ds_hstring ds_jterm_config = dsl_config_attributes_group.m_get(iml_nextconfig).m_get_value_at(0);
      
        if (!bo_session_found){
            iml_ret = m_search_session(ds_jterm_config, &dsl_wsp_helper, achp_configname, imp_configname_len, achp_dst, achp_dst_end,
                &dsl_config_attribute_own,&dsl_config_attributes_tree,&dsl_config_attributes_group, adsl_contr_1);
            if (iml_ret > 0)
            {
                bo_session_found = true;
            }
#if TRACE_JTERMCONF_SEARCH
            else //if (iml_ret < 0)
            {
                m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-I no jterm config found in groups (code:%d) for DN \"%.*s\" config:\"%.*s\"",
                    __LINE__, iml_ret, hstr_our_dn.m_get_len(), hstr_our_dn.m_get_ptr(), ds_jterm_config.m_get_len(), ds_jterm_config.m_get_ptr() );
            }
#endif
        }

        m_add_rights(ds_jterm_config, &dsl_wsp_helper, &adsl_contr_1->dsc_user_rights);

        iml_nextconfig++;
    }

    if (bo_session_found)
    {
        return iml_ret;
    }


    m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-I no matching jterm config found in for DN \"%.*s\" ",
                __LINE__, hstr_our_dn.m_get_len(), hstr_our_dn.m_get_ptr() );
    return -1;

}

int m_search_session(ds_hstring ds_jterm_config, ds_wsp_helper*   dsp_wsp_helper,  
                     char* achp_configname, int imp_configname_len, 
                     char* achp_dst,char* achp_dst_end,
                     ds_attribute_string* dsl_config_attribute_own,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_tree,
                    ds_hvector<ds_attribute_string>* dsl_config_attributes_group,
                    dsd_clib1_contr_1* adsp_contr_1
                     )
{
// build an object structure from xml
    ds_xml dsl_xml;
    dsl_xml.m_init(dsp_wsp_helper);
    ds_hstring ds_conn_scheme(dsp_wsp_helper);
    

    dsd_xml_tag *ads_jterm_root = dsl_xml.m_from_xml(ds_jterm_config.m_const_str());
    if (!ads_jterm_root) {        
        return -7;
    }
    // it the structure is not valid return exception
    if (memcmp(ads_jterm_root->ach_data, "root", ads_jterm_root->in_len_data) != 0) {        
        return -8;
    }

    //get the Sessions attribute
    const char *ach_tmp_value;
    int im_tmp_len;
    dsd_xml_tag* adsl_sessions = dsl_xml.m_get_value(ads_jterm_root, "Sessions", &ach_tmp_value, &im_tmp_len);
    if (!adsl_sessions)
    {        
        return -10;
    }

    /*const char* ach_display_value;
    int im_display_len;*/
    dsd_xml_tag* adsl_display = dsl_xml.m_get_value(adsl_sessions, "Display", &ach_tmp_value, &im_tmp_len);
    if (!adsl_display)
    {
        return -11;
    }

    dsd_xml_tag* adsl_next_session = adsl_display->ads_child;
    
    BOOL bol_found = FALSE;
    
    const char* ach_ssname_value;
    int im_ssname_len;

    while (adsl_next_session && !bol_found)
    {
        
        dsd_xml_tag* adsl_session_name = dsl_xml.m_get_value(adsl_next_session, "SSName", &ach_ssname_value, &im_ssname_len);
        //compare
        if (adsl_session_name && 
            im_ssname_len == imp_configname_len &&
            !memcmp(ach_ssname_value,achp_configname,im_ssname_len) )
        {
            bol_found = TRUE;
            break;
        }
        
        //next session
        adsl_next_session = adsl_next_session->ads_next;
    }

    if (!bol_found)
    {        
        return -11;

    }

    //if found get the connection ID
    const char* achl_connid_value;
    int iml_connid_len;
    dsd_xml_tag* adsl_connection = dsl_xml.m_get_value(adsl_next_session, "Connection", &achl_connid_value, &iml_connid_len);

    if (!adsl_connection || !achl_connid_value || iml_connid_len == 0)
    {             
        return -12;
    }

    //check if the connection is in another level
    
    const char* achl_loconn_value;
    int iml_loconn_len;
    dsd_xml_tag* dsl_loconn = dsl_xml.m_get_value(adsl_next_session, "LO_Connection", &achl_loconn_value, &iml_loconn_len);
    if (dsl_loconn && achl_loconn_value && iml_loconn_len > 0)
    {
        BOOL bol_dn_found = FALSE;
        //the connection is at another LDAP level
        {
            const ds_hstring dsl_dn = dsl_config_attribute_own->m_get_dn();
            if (dsl_dn.m_get_len() == iml_loconn_len)
            {
                if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                {
                    ds_conn_scheme = dsl_config_attribute_own->m_get_value_at(0);
                    bol_dn_found = true;         
                }
            }
        }
        if (!bol_dn_found)
        {
            size_t iml_config_count = dsl_config_attributes_group->m_size();
            size_t iml_nextconfig = 0;
            while (iml_nextconfig < iml_config_count && !bol_dn_found)
            {
                const ds_hstring dsl_dn = dsl_config_attributes_group->m_get(iml_nextconfig).m_get_dn();                        
                if (dsl_dn.m_get_len() == iml_loconn_len)
                {
                    if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                    {
                        ds_conn_scheme = dsl_config_attributes_group->m_get(iml_nextconfig).m_get_value_at(0);
                        bol_dn_found = true;
                    }
                } 
                iml_nextconfig++;
            }      
        }
        if (!bol_dn_found)
        {
            size_t iml_config_count = dsl_config_attributes_tree->m_size();
            size_t iml_nextconfig = 0;
            while (iml_nextconfig < iml_config_count && !bol_dn_found)
            {
                const ds_hstring dsl_dn = dsl_config_attributes_tree->m_get(iml_nextconfig).m_get_dn();                        
                if (dsl_dn.m_get_len() == iml_loconn_len)
                {
                    if (!memcmp(dsl_dn.m_get_ptr(),achl_loconn_value,iml_loconn_len))
                    {
                        ds_conn_scheme = dsl_config_attributes_tree->m_get(iml_nextconfig).m_get_value_at(0);
                        bol_dn_found = true;
                    }
                } 
                iml_nextconfig++;
            }      
        }   
        if (!bol_dn_found)
        {
            //if we had an LO_Connection but did not find the relevant dn with the specified connection number in the user/tree/group return error
            return -13;
        }
        
    } else //no LO_connection
    {
        ds_conn_scheme = ds_jterm_config;
    }

    return m_get_connection(ds_conn_scheme,dsp_wsp_helper,achp_dst,achp_dst_end,achl_connid_value,iml_connid_len, adsp_contr_1);

}


int m_get_connection(ds_hstring ds_jterm_config, ds_wsp_helper* dsl_wsp_helper,
                     char* achp_dst,char* achp_dst_end,
                     const char *ach_connid_value, int im_connid_len,
                     dsd_clib1_contr_1* adsp_contr_1
                     )
{
    ds_xml dsl_xml;
    dsl_xml.m_init(dsl_wsp_helper);

    dsd_xml_tag *ads_jterm_root = dsl_xml.m_from_xml(ds_jterm_config.m_const_str());
    if (!ads_jterm_root) 
    {        
        return -64;
    }

    const char *ach_tmp_value;
    int im_tmp_len;

    dsd_xml_tag* adsl_schemes = dsl_xml.m_get_value(ads_jterm_root, "Schemes", &ach_tmp_value, &im_tmp_len);
    if (!adsl_schemes)
    {        
        return -65;
    }

    /*const char* ach_conn_value;
    int im_conn_len;*/
    dsd_xml_tag* adsl_connection = dsl_xml.m_get_value(adsl_schemes, "Connection", &ach_tmp_value, &im_tmp_len);
    if (!adsl_connection)
    {
        return -66;
    }
    dsd_xml_tag* adsl_next_scheme = adsl_connection->ads_child;
    
    BOOL bol_found = FALSE;
    
    /*const char* ach_ssname_value;
    int im_ssname_len;*/

    while (adsl_next_scheme && !bol_found)
    {

        if (adsl_next_scheme->in_len_data == im_connid_len+2 &&
            adsl_next_scheme->ach_data[0] == '_' && 
            adsl_next_scheme->ach_data[1] == '_' &&
            !memcmp(&(adsl_next_scheme->ach_data[2]),ach_connid_value,adsl_next_scheme->in_len_data-2) )
        {
            bol_found = TRUE;
            break;
        }

        adsl_next_scheme = adsl_next_scheme->ads_next;
    }

    if (!bol_found)
    {        
        return -66;

    }

    const char* achl_schemestart = adsl_next_scheme->ach_data - 1; //start from initial "<" - this is not included in ach_data

    int iml_remaining_len = ds_jterm_config.m_get_ptr()+ds_jterm_config.m_get_len() - achl_schemestart;
    int iml_endtagend = 0; //has to be 0 before calling m_get_end_tag
    int iml_endtagstart = 0;//has to be 0 before calling m_get_end_tag
    bool bol_ret = dsl_xml.m_get_end_tag(adsl_next_scheme->ach_data,iml_remaining_len,&iml_endtagend,&iml_endtagstart,adsl_next_scheme->ach_data,adsl_next_scheme->in_len_data);

    if (achp_dst_end - achp_dst < iml_endtagend+1)
    {
        return -1; //not enough memory in work area
    }

    //get the connection type - required for rights
   
    adsp_contr_1->iec_target_type = IE_EMU_TYPE_UNKNOWN;
    dsd_xml_tag* dsl_tmptag = dsl_xml.m_get_value(adsl_next_scheme,"SubConnType", &ach_tmp_value, &im_tmp_len);
    if (im_tmp_len == 10)
    {
        if (!memcmp(ach_tmp_value,"3270TELNET",im_tmp_len))
        {
            adsp_contr_1->iec_target_type = IE_EMU_TYPE_TN3270;
        }
        else if (!memcmp(ach_tmp_value,"5250TELNET",im_tmp_len))
        {
            adsp_contr_1->iec_target_type = IE_EMU_TYPE_TN5250;
        }
    }
    else if (im_tmp_len == 8)
    {
        if (!memcmp(ach_tmp_value,"VTTELNET",im_tmp_len))
        {
            adsp_contr_1->iec_target_type = IE_EMU_TYPE_VT525;
        }
    }
    //get the server url
    dsd_xml_tag* dsl_servername = NULL;
    dsd_xml_tag* dsl_port = NULL;
    const char *ach_srv_name = NULL;
    int im_srv_name_len = 0;
    const char *ach_port = NULL;
    int im_port_len = 0;
    if (adsp_contr_1->iec_target_type == IE_EMU_TYPE_TN3270)
    {
        dsl_servername = dsl_xml.m_get_value(adsl_next_scheme,"Address", &ach_srv_name, &im_srv_name_len);
        dsl_port = dsl_xml.m_get_value(adsl_next_scheme,"RemotePort", &ach_port, &im_port_len);       
    }
    else if (adsp_contr_1->iec_target_type == IE_EMU_TYPE_TN5250 || adsp_contr_1->iec_target_type == IE_EMU_TYPE_VT525)
    {
        dsl_servername = dsl_xml.m_get_value(adsl_next_scheme,"Host", &ach_srv_name, &im_srv_name_len);
        dsl_port = dsl_xml.m_get_value(adsl_next_scheme,"Port", &ach_port, &im_port_len);
    }
    if (ach_srv_name && im_srv_name_len < MAX_TARGET_URL)
    {
        memcpy(adsp_contr_1->chrc_target_name,ach_srv_name,im_srv_name_len);
        adsp_contr_1->imc_target_name_len = im_srv_name_len;
    }
    adsp_contr_1->imc_port = 23;
    if (ach_port && im_port_len < 6)
    {
        int iml_port = 0;
        while (im_port_len--)
        {
                iml_port = iml_port*10 + *ach_port++ - '0';
        }
        if (iml_port > 0 && iml_port < 65536)
        {
            adsp_contr_1->imc_port = iml_port;
        }

    }

    memcpy(achp_dst,achl_schemestart,iml_endtagend+1);
    return iml_endtagend+1;
}


void m_add_rights(ds_hstring ds_jterm_config, ds_wsp_helper* dsl_wsp_helper, dsd_jterm_userrights* adsp_userrights)
{
    ds_xml dsl_xml;
    dsl_xml.m_init(dsl_wsp_helper);

    dsd_xml_tag *ads_jterm_root = dsl_xml.m_from_xml(ds_jterm_config.m_const_str());
    if (!ads_jterm_root) 
    {        
        return;
    }

    const char *ach_tmp_value;
    int im_tmp_len;

    dsd_xml_tag* adsl_userdata = dsl_xml.m_get_value(ads_jterm_root, "UserData", &ach_tmp_value, &im_tmp_len);
    if (!adsl_userdata)
    {        
        return;
    }

    dsd_xml_tag* adsl_rights = dsl_xml.m_get_value(adsl_userdata, "Rights", &ach_tmp_value, &im_tmp_len);
    if (!adsl_rights)
    {
        return;
    }
    
    dsd_xml_tag* adsl_tmp = NULL;
    ach_tmp_value = "";
    adsl_tmp = dsl_xml.m_get_value(adsl_rights, "CanUse3270", &ach_tmp_value, &im_tmp_len);
    if (adsl_tmp && im_tmp_len == 1 && *ach_tmp_value == 'Y' ) 
    {
        adsp_userrights->bo_can_use_3270 = true;
    }

    adsl_tmp = NULL;
    ach_tmp_value = "";
    adsl_tmp = dsl_xml.m_get_value(adsl_rights, "CanUse5250", &ach_tmp_value, &im_tmp_len);
    if (adsl_tmp && im_tmp_len == 1 && *ach_tmp_value == 'Y' ) 
    {
        adsp_userrights->bo_can_use_5250 = true;
    }

    adsl_tmp = NULL;
    ach_tmp_value = "";
    adsl_tmp = dsl_xml.m_get_value(adsl_rights, "CanUseVT", &ach_tmp_value, &im_tmp_len);
    if (adsl_tmp && im_tmp_len == 1 && *ach_tmp_value == 'Y' ) 
    {
        adsp_userrights->bo_can_use_vt = true;
    }
    
    

}

int m_connect_to_target(struct dsd_hl_clib_1* adsp_hlclib,char* achp_ineta, int imp_ineta_len, int imp_port, ied_emulation_type iep_target )
{
    struct dsd_sdh_call_1 dsl_sdh_call_1; 
    dsl_sdh_call_1.amc_aux = adsp_hlclib->amc_aux;  /* auxiliary subroutine */
    dsl_sdh_call_1.vpc_userfld = adsp_hlclib->vpc_userfld;  /* User Field Subroutine */
    struct dsd_clib1_contr_1* adsl_contr_1 = (struct dsd_clib1_contr_1 *) adsp_hlclib->ac_ext;

    //check that the values from the client match the values from the server (optionally ignore the values from the client)
    if (imp_ineta_len != adsl_contr_1->imc_target_name_len)
    {
         m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server - ineta mismatch, expected: %.*s received: %.*s ",
            __LINE__,adsl_contr_1->imc_target_name_len,adsl_contr_1->chrc_target_name,imp_ineta_len,achp_ineta );
        return 1;
    }
    if (memcmp(achp_ineta,adsl_contr_1->chrc_target_name,imp_ineta_len))
    {
         m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server - ineta mismatch, expected: %.*s received: %.*s ",
            __LINE__,adsl_contr_1->imc_target_name_len,adsl_contr_1->chrc_target_name,imp_ineta_len,achp_ineta );
        return 2;
    }
    if (imp_port != adsl_contr_1->imc_port)
    {
         m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server - port mismatch, expected: %d received: %d ",
            __LINE__,adsl_contr_1->imc_port, imp_port);
        return 3;
    }
    if (iep_target != adsl_contr_1->iec_target_type)
    {
         m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server - target type mismatch, expected: %d received: %d ",
            __LINE__,adsl_contr_1->iec_target_type,iep_target );
        return 4;
    }

    //check rights
    bool bol_connection_allowed = false;
    switch (adsl_contr_1->iec_target_type)
    {
        case IE_EMU_TYPE_TN3270:
            bol_connection_allowed = adsl_contr_1->dsc_user_rights.bo_can_use_3270;
            break;
        case IE_EMU_TYPE_TN5250:
            bol_connection_allowed = adsl_contr_1->dsc_user_rights.bo_can_use_5250;
            break;
        case IE_EMU_TYPE_VT525:
            bol_connection_allowed = adsl_contr_1->dsc_user_rights.bo_can_use_vt;
            break;
        default:
            break;
    }

    if (!bol_connection_allowed)
    {
         m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server %.*s - not enough connection rights",
            __LINE__,adsl_contr_1->imc_target_name_len,adsl_contr_1->chrc_target_name );
         return 5;
    }

    /*int iml_port = 23;
    if (im_port_len != 0)
    {
        iml_port = atoi(ach_port_value);
    } */
    //connect to server
    struct dsd_aux_tcp_conn_1 dsl_atc1_1 = {ied_tcr_ok};  /* TCP Connect to Server   */   

    
    dsl_atc1_1.dsc_target_ineta.ac_str = (void*)achp_ineta;
    dsl_atc1_1.dsc_target_ineta.imc_len_str = imp_ineta_len;
    dsl_atc1_1.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;
    
    dsl_atc1_1.imc_server_port = imp_port;  /* server-port */

    BOOL bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
        DEF_AUX_TCP_CONN,
        &dsl_atc1_1,
        sizeof(struct dsd_aux_tcp_conn_1) );
    if (dsl_atc1_1.iec_tcpconn_ret != ied_tcr_ok) {  /* connect successful */
        m_sdh_printf( &dsl_sdh_call_1, "xl-webterm-uni-01-l%05d-E could not connect to server - error %d.",
            __LINE__, dsl_atc1_1.iec_tcpconn_ret );

        return 6;
    }
    return 0;
}
