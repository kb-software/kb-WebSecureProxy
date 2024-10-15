//#define TRY_141118_01                       /* SHA256 init             */
//#define DEBUG_150317_01                     /* signing Compounded Requests */
//#define TRY_150302_01                       /* DEF_AUX_KRB5_SE_TI_C_R  */
//does not work, 03.03.15 KB
//#define TRACEHL1
#define NO_EVENT_LOG
#define TRY_111209_01                       /* wait till INETA set     */
#ifdef TO_DO_111127
delete DNS cache
#endif
//#define NO_TUN_DRIVER
//#define TEST_AST_01
//#define TEST_PIPE_111119
//#define D_CONFIGURED_LOCAL_INETA "172.22.11.79"
#define HL_TCP_RCVBUF (64 * 1024)           /* socket option           */
#define HL_CHECK_TIME                       /* check time needed in computing */
#define HL_CHECK_MINIMUM 200                /* check minimum wait time */
#ifdef TO_DO_110619
// m_connect_wsp() pass sockaddr_storage of server after local
#endif
//#define TRACEHL1
#define NEW_110214
#define DEBUG_110505_01
//#define DEF_NO_UDP_SEND
//#define PROD_101022
#ifndef PROD_101022
#define HL_EXT_AUTH_01
#endif
//#define DEF_PROG_ARGS
//#define TRACEHL_KB
//#define TRY_090930_01
//#define TRACEHL_090930_01
//#define TRY_090108_01
//#define TRY_090109_01 2  /* seconds to wait */
#define TRY_090119_01
//#define TRY_090126_01 2  /* millisecondes to wait */
#define TRY_090126_01 1  /* millisecondes to wait */
#define TRY_090308_01                       /* received StopCCN        */
#define TRY_110201_01 4                     /* Sleep - wouldblock      */
#ifndef TRACEHL_KB
#define D_NO_WARNING
#endif
#ifdef TRACEHL_KB
//#define TRY_080205
#define TRACEHL1
#define TRACEHL_SSL_STATE
//#define PROBLEM_080111_01
//#define D_SLEEP_080110
#define DEBUG_141231_01                     /* memory corrupted        */
#endif
#ifdef DEF_NO_UDP_SEND
#define TRACEHL1
#define HL_EXT_AUTH_01
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsl-smb-cl-01                                       |*/
/*| -------------                                                     |*/
/*|  HOB SMB Client                                                   |*/
/*|    MS Server Message Block                                        |*/
/*|    also CIFS                                                      |*/
/*|  part of HOB Framework                                            |*/
/*|  KB 28.04.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* see HOBTEXT SOFTWARE.HLSEC.DASH-PR1                                 */

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <time.h>
#include <sys/timeb.h>
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>
#endif
#ifdef HL_UNIX
#include <stdarg.h>
#include <string.h>
#include <hob-unix01.h>
#endif
#include <stdio.h>
#include <stddef.h>
#ifdef XYZ1
#ifdef B121230
#include <hob-xshlcl01.h>
#include <hob-xshlse03.h>
#else
#include <hob-ssl-01.h>
#endif
#endif
#include <hob-xslunic1.h>
#include <hob-xsclib01.h>
#include <stdint.h>
#include <hob-encry-1.h>
/* pseudo-entry, cannot be used in Server-Data-Hook                    */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   return 0;
} /* end m_hl1_printf()                                                */
#include <hob-smb-01.h>
#include <hob-ntlm-01.h>
//#include "hob-xshlssle.h"
//#include "HOBSSLTP.H"
#ifdef XYZ1
#include "hob-lhwsm01.h"
#include "hob-hpppt1-oper-1.h"
#ifdef D_SLEEP_080110
#include <conio.h>
#endif
#ifndef NO_EVENT_LOG
#include <hobmsg01.h>
#endif
#endif

#ifdef XYZ1
#ifndef DEF_PROG_ARGS
#define DEF_TIMEOUT_PIPE       30           /* seconds timeout pipe    */
#define LEN_READ_PIPE          4096         /* length read from pipe   */
#define DEF_PIPE_STATUS        (-4)         /* pipe status decode length NHASN */
#endif
#ifdef DEF_PROG_ARGS
#define DEF_MIME_STATUS        (-4)         /* MIME status decode length NHASN */
#endif
#define TIMER_TCP_RECONN       15           /* seconds reconnect TCP   */
#define TIMER_TCP_NORECO       (60 * 2)     /* seconds timeout when not possible to reconnect TCP */
#ifndef HL_UNIX
#define D_NO_WAIT_EVENT        32           /* number of wait events   */
#endif
#ifdef HL_UNIX
#define D_POLL_MAX             32           /* maximum number of poll events */
#endif
#define D_BUFFER_LEN           8192         /* length of receive buffer */
#define LEN_FILE_NAME          1024         /* maximum length of file name */
#define MAX_DIR_STACK          64           /* maximum stack of nested directories */
#define LEN_DIR_BLOCK          (16 * 1024)  /* length of directory block */
#endif
#define LEN_SMB_DIR            (32 * 1024)
#define LEN_SMB_IO             (32 * 1024)
#define LEN_SMB_CHANGE_NOTIFY  32

#ifdef XYZ1
#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))
#endif


#ifdef XYZ1
#ifndef HL_UNIX
//typedef unsigned int UNSIG_MED;
typedef int socklen_t;
#else
//#define UNSIG_MED unsigned int
#endif
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef HL_EXT_AUTH_01
#define D_LEN_WSM_SL  6                     /* length WSP-socks-mode server list */
#endif

#define CHAR_PERCENT   0X25

#ifdef HL_CHECK_TIME                        /* check time needed in computing */
#define LEN_EDIT 32
#endif
#endif
#define LEN_SMB_BL_LEN 4                    /* length of SMB block length */

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static BOOL m_dir_local( struct dsd_dir_cmd * );
static int m_cmp_file( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static BOOL m_cb_get_epoch( void *, HL_LONGLONG * );
static BOOL m_cb_get_random( void *, char *, int );
static inline short int m_get_le2( char *achp_source );
static inline int m_get_le4( char *achp_source );
static inline void m_put_le2( char *achp_target, int imp1 );
static inline void m_put_le4( char *achp_target, int imp1 );
static inline void m_put_le8( char *achp_target, HL_LONGLONG ilp1 );
static inline void m_put_be2( char *achp_target, int imp1 );
#ifdef XYZ1
static void m_smb2_prot( char * );
static HL_LONGLONG m_get_epoch_ms( void );
#ifdef DYN_LOAD_WSA
static void m_error_dynload( char *, int );
#endif
extern "C" int m_hl1_printf( char *, ... );
static int m_err_printf( char *, ... );
static int m_get_date_time( char *achp_buff );
#ifdef HL_CHECK_TIME                        /* check time needed in computing */
static char * m_edit_dec_long_1( char *achp_target, HL_LONGLONG ilp1 );
#endif
#endif
#ifdef XYZ1
static void m_console_out( char *achp_buff, int implength );
#endif
// new 04.05.13 KB
static int m_scan_smb_header( struct dsd_gather_i_1 *adsp_gai1_in, struct dsd_gather_i_1 **aadsp_gai1_out, char **aachp_out );
static void m_gen_smb_sign_key( struct dsd_smb_cl_session *, char * );
static BOOL m_check_smb_signature( struct dsd_smb_cl_session *, struct dsd_smb2_hdr_sync *,
                                   struct dsd_gather_i_1 *, int );
static void m_fill_smb_signature( struct dsd_smb_cl_session *, struct dsd_smb2_hdr_sync *,
                                  struct dsd_gather_i_1 * );
static int m_consume_input( struct dsd_gather_i_1 *adsp_gai1_in, int imp_len );
static BOOL m_acquire_work_area( struct dsd_sdh_call_1 * );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

enum ied_smb_cs_state {                     /* state SMB client session */
   ied_smb_cs_wait = 0,                     /* wait for next command   */
   ied_smb_cs_start_01,                     /* process start of SMB session */
   ied_smb_cs_start_02,                     /* Negotiate Protocol Request */
   ied_smb_cs_start_03,                     /* has sent NTLM negotiate */
   ied_smb_cs_start_04,                     /* has sent NTLM authenticate */
   ied_smb_cs_start_krb5,                   /* has sent Kerberos authentication */
   ied_smb_cs_start_05,                     /* has sent TreeConnect    */
   ied_smb_cs_reply_dir,                    /* wait for reply for dir  */
   ied_smb_cs_resp_write,                   /* wait for response for WRITE */
   ied_smb_cs_resp_set_info,                /* wait for response for SET_INFO */
   ied_smb_cs_reply_close,                  /* wait for reply for close */
   ied_smb_cs_reply_cancel,                 /* wait for reply for cancel */
#ifdef B141213
   ied_smb_cs_reply_ch_not_ao,              /* wait for change notify out of order */
#endif
   ied_smb_cs_reply_echo,                   /* wait for reply for echo */
   ied_smb_cs_xyz
};

enum ied_smb_ce_type {                      /* SMB client extra data type */
   ied_smb_cet_ntlm_cha = 0,                /* save NTLM challenge     */
   ied_smb_cet_change_ntfy,                 /* CHANGE_NOTIFY           */
   ied_smb_cet_xyz
};

struct dsd_smb_cl_extra {                   /* SMB client extra data   */
   struct dsd_smb_cl_extra *adsc_next;      /* for chaining            */
   enum ied_smb_ce_type iec_smb_cet;        /* SMB client extra data type */
   int        imc_len;                      /* length SMB client extra data */
};

enum ied_smb_ce_ntfy {                      /* extra data CHANGE_NOTIFY state */
   ied_smb_cen_start = 0,                   /* CHANGE NOTIFY started   */
   ied_smb_cen_active,                      /* CHANGE NOTIFY active    */
   ied_smb_cen_cancelled                    /* CHANGE NOTIFY cancelled */
};

struct dsd_smb_ce_ntfy {                    /* extra data CHANGE_NOTIFY */
   enum ied_smb_ce_ntfy iec_smb_cen;        /* extra data CHANGE_NOTIFY state */
   unsigned short int usc_flags;            /* Flags                   */
   unsigned int umc_completion_filter;      /* CompletionFilter        */
   void *     vpc_userfld;                  /* User Field CHANGE_NOTIFY */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   HL_LONGLONG ulc_command_sequence_number;
   HL_LONGLONG ulc_async_id;                /* AsyncId                 */
};

struct dsd_smb_cl_session {                 /* SMB client session      */
   enum ied_smb_cs_state iec_smb_cs;        /* state SMB client session */
   BOOL       boc_smb_cs_reply_ch_not_ao;   /* wait for change notify out of order */
   BOOL       boc_signed;                   /* SMB2 packets need to be signed */
   HL_LONGLONG ulc_command_sequence_number;
   char       chrc_session_id[ 8 ];
   char       chrc_tree_id[ 4 ];
   char       chrc_file_id[ 16 ];           /* FileId                  */
   HL_LONGLONG ulc_offset;
   struct dsd_smb_cl_extra *adsc_sce_ch;    /* chain SMB client extra data */
   void *     vpc_krb5_handle;              /* Kerberos handle         */
   int        imrc_sign_array[ SHA256_ARRAY_SIZE ];  /* for SHA-256    */
   char       byrc_hmac_2[ 64 ];            /* for HMAC                */
};

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* helper routine pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   char       *achc_lower;                  /* work area lower address */
   char       *achc_upper;                  /* work area upper address */
};

#ifdef XYZ1
struct dsd_dir_cmd {                        /* command to retrieve directory */
   struct dsd_unicode_string dsc_ucs_dir;   /* name of directory       */
};

struct dsd_dir_bl_1 {                       /* directory block 1 - chaining */
   struct dsd_dir_bl_1 *adsc_next;          /* next in chain           */
   char       *achc_end_file;               /* end of files            */
};

#ifdef XYZ1
struct dsd_dir_bl_2 {                       /* directory block 2 - header */
   struct dsd_htree1_avl_cntl dsc_htree1_avl_file;
   int   imc_no_files;                      /* number of files         */
   int   imc_no_dir;                        /* number of directories   */
};
#endif

struct dsd_dir_stack_1 {                    /* stack entry directory   */
   struct dsd_file_1 *adsc_f1_dir_cur;      /* entry of file currently directory */
   struct dsd_file_1 *adsc_f1_dir_last;     /* entry of file last directory */
   struct dsd_dir_bl_1 *adsc_db1_cur;       /* directory block current */
   int        imc_pos_dn;                   /* position in directory name */
};
#endif

enum ied_state_conn {                       /* state of connection     */
   ied_stc_auth_send = 0,                   /* send authentication     */
   ied_stc_smb_np_resp_1,                   /* receive authentication  */
   ied_stc_smb_np_resp_2,                   /* receive authentication  */
   ied_stc_smb_ntlm,                        /* receive authentication  */
   ied_stc_smb_treeconnect_01,              /* send TreeConnect        */
   ied_stc_smb_create_request_file,
   ied_stc_smb_find_01,
   ied_stc_smb_xyz                     /* receive authentication  */
};

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static const char byrs_zeroes[ 16 ] = {
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

/* from jbt_smb_cl_01.java                                             */
static unsigned char byrs_smb_npr_01[] = {  /* Negotiate Protocol Request */
   0X00, 0X00, 0X00, 0X9B,
   0XFF,
   'S', 'M', 'B',
   0X72, 0X00, 0X00, 0X00,
   0X00, 0X18, 0X53, 0XC8,
   0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00,
   0XFF, 0XFF, 0XFF, 0XFE,
   0X00, 0X00, 0X00, 0X00,
   0X00, 0X78, 0X00, 0X02,
   'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O',
   'R', 'K', ' ', 'P', 'R', 'O', 'G', 'R',
   'A', 'M', ' ', '1', '.', '0',
   0X00, 0X02,
   'L', 'A', 'N', 'M', 'A', 'N', '1', '.',
   '0',
   0X00, 0X02,
   'W', 'i', 'n', 'd', 'o', 'w', 's', ' ',
   'f', 'o', 'r', ' ', 'W', 'o', 'r', 'k',
   'g', 'r', 'o', 'u', 'p', 's', ' ', '3',
   '.', '1', 'a',
   0X00, 0X02,
   'L', 'M', '1', '.', '2', 'X', '0', '0',
   '2',
   0X00, 0X02,
   'L', 'A', 'N', 'M', 'A', 'N', '2', '.',
   '1',
   0X00, 0X02,
   'N', 'T', ' ', 'L', 'M', ' ', '0', '.',
   '1', '2',
   0X00, 0X02,
   'S', 'M', 'B', ' ', '2', '.', '0', '0',
   '2',
   0X00, 0X02,
   'S', 'M', 'B', ' ', '2', '.', '?', '?',
   '?',
   0X00
};

static unsigned char byrs_smb_npr_02[] = {  /* Negotiate Protocol Request */
  0X00, 0X00, 0X00, 0X68,
  0XFE,
  'S', 'M', 'B',
  0X40, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X01, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0XFF, 0XFE, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  /* end of SMB2 header                                                */
  0X24, 0X00, 0X02, 0X00,
  0X01, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X16, 0XDA, 0X07, 0XBF,
  0XA5, 0X2C, 0XE2, 0X11,
  0X9F, 0X42, 0X00, 0X25,
  0XB3, 0XE4, 0X41, 0X5E,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X02, 0X02, 0X10, 0X02
};

static unsigned char byrs_smb_ntlm_neg[] = {  /* NTLMSSP_NEGOTIATE */
  0X00, 0X00, 0X00, 0XA2,
  0XFE,
  'S', 'M', 'B',
  0X40, 0X00,
  0X01, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X01, 0X00,
  0X1F, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X02, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0XFF, 0XFE, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  /* end of SMB2 header                                                */
  0X19, 0X00,
  0X00,
  0X01,
  0X01, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X58, 0X00, 0X4A, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X60, 0X48, 0X06, 0X06,
  0X2B, 0X06, 0X01, 0X05,
  0X05, 0X02, 0XA0, 0X3E,
  0X30, 0X3C, 0XA0, 0X0E,
  0X30, 0X0C, 0X06, 0X0A,
  0X2B, 0X06, 0X01, 0X04,
  0X01, 0X82, 0X37, 0X02,
  0X02, 0X0A, 0XA2, 0X2A,
  0X04, 0X28,
  'N', 'T', 'L', 'M', 'S', 'S', 'P',
  0X00,
  0X01, 0X00, 0X00, 0X00,
  0X97, 0X82, 0X08, 0XE2,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X06, 0X01, 0XB1, 0X1D,
  0X00, 0X00, 0X00, 0X0F
};

static unsigned char byrs_smb_krb5_req[] = {  /* SMB2 Session Setup Request */
  0X00, 0X00, 0XFF, 0XFF,                   /* length                  */
  0XFE,
  'S', 'M', 'B',
  0X40, 0X00,
  0X01, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X01, 0X00,
  0X1F, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X02, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0XFF, 0XFE, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  /* end of SMB2 header                                                */
  0X19, 0X00,                               /* length                  */
  0X00,
  0X02,                                     /* Security mode           */
#ifdef TRY_140123
  0X00,                                     /* Security mode           */
#endif
  0X01, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X58, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00
};

static const unsigned char byrs_smb2_eyecatcher[] = {  /* SMB2 eyecacher */
  0XFE,
  'S', 'M', 'B'
};

static const unsigned char byrs_krb5_prot_name[] = {  /* name of SMB2 protocol for SPN = service principal name */
  'c', 'i', 'f', 's', '/'
};

#ifdef XYZ1
static unsigned char byrs_smb2_create_req_01[] = {  /* SMB2 create request */
  0X39, 0X00,                               /* length + dynamic part   */
  0X00, 0X00, 0X02, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  /* create flags     */
  0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  /* filler - unknown */
  0X81, 0X00, 0X10, 0X00,                   /* access mask             */
  0X00, 0X00, 0X00, 0X00,                   /* file attributes         */
  0X07, 0X00, 0X00, 0X00,                   /* SHARE_DELETE SHARE_WRITE SHARE_READ */
  0X01, 0X00, 0X00, 0X00,                   /* disposition             */
  0X21, 0X00, 0X00, 0X00,                   /* create options          */
  /* file name                                                         */
  0X78, 0X00,                               /* offset                  */
  0X00, 0X00,                               /* length                  */
  /* extra info                                                        */
  0X80, 0X00, 0X00, 0X00, 0X58, 0X00, 0X00, 0X00, 0X00, 0X00,
  0X4B, 0X00, 0X42, 0X00, 0X49, 0X00,
  0X28, 0X00, 0X00, 0X00, 0X10, 0X00, 0X04, 0X00, 0X00, 0X00,
  0X18, 0X00, 0X10, 0X00, 0X00, 0X00, 0X44, 0X48, 0X6E, 0X51, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
  0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X18, 0X00,
  0X00, 0X00, 0X10, 0X00, 0X04, 0X00, 0X00, 0X00, 0X18, 0X00, 0X00, 0X00, 0X00, 0X00, 0X4D, 0X78,
  0X41, 0X63, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X10, 0X00, 0X04, 0X00, 0X00, 0X00,
  0X18, 0X00, 0X00, 0X00, 0X00, 0X00, 0X51, 0X46, 0X69, 0X64, 0X00, 0X00, 0X00, 0X00
};
#endif

#ifdef XYZ1
static unsigned char byrs_smb2_find_req_01[] = {  /* SMB2 find request */
  0X21, 0X00,
  0X25, 0X00, 0X00, 0X00, 0X00, 0X00, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
  0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0X60, 0X00, 0X02, 0X00, 0X00, 0X00, 0X01, 0X00, 0X2A, 0X00,
  0XEA, 0X0A, 0X42, 0XBB, 0X0E, 0XE5
};

static unsigned char byrs_smb2_find_req_02[] = {  /* SMB2 find request */
  0X21, 0X00,
  0X25, 0X00, 0X00, 0X00, 0X00, 0X00, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
  0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0X60, 0X00, 0X02, 0X00, 0X80, 0X00, 0X00, 0X00, 0X2A, 0X00
// 02 00 80 00  00 00 2A 00
};
#endif

#ifdef XYZ1
#ifdef DEF_PROG_ARGS
static const unsigned char ucrs_decode_mime[] = {
   0X41, 0X41, 0X41, 0X41,                  /* 00 - 03 */
   0X41, 0X41, 0X41, 0X41,                  /* 04 - 07 */
   0X41, 0X41, 0X41, 0X41,                  /* 08 - 0B */
   0X41, 0X41, 0X41, 0X41,                  /* 0C - 0F */
   0X41, 0X41, 0X41, 0X41,                  /* 10 - 13 */
   0X41, 0X41, 0X41, 0X41,                  /* 14 - 17 */
   0X41, 0X41, 0X41, 0X41,                  /* 18 - 1B */
   0X41, 0X41, 0X41, 0X41,                  /* 1C - 1F */
   0X41, 0X41, 0X41, 0X41,                  /* 20 - 23 */
   0X41, 0X41, 0X41, 0X41,                  /* 24 - 27 */
   0X41, 0X41, 0X41, 0X3E,                  /* 28 - 2B */
   0X41, 0X41, 0X41, 0X3F,                  /* 2C - 2F */
   0X34, 0X35, 0X36, 0X37,                  /* 30 - 33 */
   0X38, 0X39, 0X3A, 0X3B,                  /* 34 - 37 */
   0X3C, 0X3D, 0X41, 0X41,                  /* 38 - 3B */
   0X41, 0X40, 0X41, 0X41,                  /* 3C - 3F */
   0X41, 0X00, 0X01, 0X02,                  /* 40 - 43 */
   0X03, 0X04, 0X05, 0X06,                  /* 44 - 47 */
   0X07, 0X08, 0X09, 0X0A,                  /* 48 - 4B */
   0X0B, 0X0C, 0X0D, 0X0E,                  /* 4C - 4F */
   0X0F, 0X10, 0X11, 0X12,                  /* 50 - 53 */
   0X13, 0X14, 0X15, 0X16,                  /* 54 - 57 */
   0X17, 0X18, 0X19, 0X41,                  /* 58 - 5B */
   0X41, 0X41, 0X41, 0X41,                  /* 5C - 5F */
   0X41, 0X1A, 0X1B, 0X1C,                  /* 60 - 63 */
   0X1D, 0X1E, 0X1F, 0X20,                  /* 64 - 67 */
   0X21, 0X22, 0X23, 0X24,                  /* 68 - 6B */
   0X25, 0X26, 0X27, 0X28,                  /* 6C - 6F */
   0X29, 0X2A, 0X2B, 0X2C,                  /* 70 - 73 */
   0X2D, 0X2E, 0X2F, 0X30,                  /* 74 - 77 */
   0X31, 0X32, 0X33, 0X41,                  /* 78 - 7B */
   0X41, 0X41, 0X41, 0X41,                  /* 7C - 7F */
   0X41, 0X41, 0X41, 0X41,                  /* 80 - 83 */
   0X41, 0X41, 0X41, 0X41,                  /* 84 - 87 */
   0X41, 0X41, 0X41, 0X41,                  /* 88 - 8B */
   0X41, 0X41, 0X41, 0X41,                  /* 8C - 8F */
   0X41, 0X41, 0X41, 0X41,                  /* 90 - 93 */
   0X41, 0X41, 0X41, 0X41,                  /* 94 - 97 */
   0X41, 0X41, 0X41, 0X41,                  /* 98 - 9B */
   0X41, 0X41, 0X41, 0X41,                  /* 9C - 9F */
   0X41, 0X41, 0X41, 0X41,                  /* A0 - A3 */
   0X41, 0X41, 0X41, 0X41,                  /* A4 - A7 */
   0X41, 0X41, 0X41, 0X41,                  /* A8 - AB */
   0X41, 0X41, 0X41, 0X41,                  /* AC - AF */
   0X41, 0X41, 0X41, 0X41,                  /* B0 - B3 */
   0X41, 0X41, 0X41, 0X41,                  /* B4 - B7 */
   0X41, 0X41, 0X41, 0X41,                  /* B8 - BB */
   0X41, 0X41, 0X41, 0X41,                  /* BC - BF */
   0X41, 0X41, 0X41, 0X41,                  /* C0 - C3 */
   0X41, 0X41, 0X41, 0X41,                  /* C4 - C7 */
   0X41, 0X41, 0X41, 0X41,                  /* C8 - CB */
   0X41, 0X41, 0X41, 0X41,                  /* CC - CF */
   0X41, 0X41, 0X41, 0X41,                  /* D0 - D3 */
   0X41, 0X41, 0X41, 0X41,                  /* D4 - D7 */
   0X41, 0X41, 0X41, 0X41,                  /* D8 - DB */
   0X41, 0X41, 0X41, 0X41,                  /* DC - DF */
   0X41, 0X41, 0X41, 0X41,                  /* E0 - E3 */
   0X41, 0X41, 0X41, 0X41,                  /* E4 - E7 */
   0X41, 0X41, 0X41, 0X41,                  /* E8 - EB */
   0X41, 0X41, 0X41, 0X41,                  /* EC - EF */
   0X41, 0X41, 0X41, 0X41,                  /* F0 - F3 */
   0X41, 0X41, 0X41, 0X41,                  /* F4 - F7 */
   0X41, 0X41, 0X41, 0X41,                  /* F8 - FB */
   0X41, 0X41, 0X41, 0X41                   /* FC - FF */
};
#endif
#endif

#ifdef XYZ1
static unsigned char ucrs_wsm_first_msg[] = {
   0X05, 0X00,
   'H', 'O', 'B', '-', 'P', 'P', 'P', '-', 'T', '1',
//#ifdef B111015
   0X00,
   'u', 's', 'e', 'r', 'i', 'd', '=', 'p', 'r', 'o', 'g', '0', '1',
   0X00,
   'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', 'p', '1', '2', '3', 'p', '1', '2', '3',
   0X00,
// 's', 'e', 'r', 'v', 'e', 'r', '=', 'L', '2', 'T', 'P', '0', '1',
   's', 'e', 'r', 'v', 'e', 'r', '=', 'H', 'P', 'P', 'P', 'T', '1', '-', 'E', '1',
//#endif
   0X00, 0X00,
   0X03, 0X00, 0X83, 0X84
};
#endif

#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
static struct dsd_sdh_call_1 *adss_sdh_call_1 = NULL;  /* SDH call structure      */
#endif

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

extern "C" void m_smb_cl_call( struct dsd_hl_smb_cl_ctrl *adsp_smbcl_ctrl ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_more;                     /* status more             */
   BOOL       bol_cont_prev;                /* continue previous header */
   BOOL       bol_cont_next;                /* continue next header    */
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_recv_len;                 /* length received         */
   int        iml_recv_rem;                 /* remainder data received */
   int        iml_recv_next;                /* next data received      */
   int        iml_ret_error;                /* return error            */
   unsigned int uml_nt_status;
   char       *achl_rp;                     /* read pointer input      */
   char       *achl_wa;                     /* pointer to work area    */
   char       *achl_w1;                     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_rp;     /* gather read pointer     */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_smb_cl_session *adsl_scs;     /* SMB client session      */
   struct dsd_smbcc_in_cmd *adsl_smbcc_in_c1;  /* input command        */
   struct dsd_smbcc_in_cmd *adsl_smbcc_in_c2;  /* input command        */
   struct dsd_smb2_hdr_sync *adsl_smb2_hdr_l;  /* address SMB2 header  */
   struct dsd_smb_cl_extra *adsl_sce_w1;    /* SMB client extra data   */
   struct dsd_smb_cl_extra *adsl_sce_last;  /* SMB client extra data   */
   struct dsd_smbcc_out_cmd **aadsl_smbcc_out_next;  /* for chain of output commands */
// struct dsd_manage_work_area dsl_mwa_l;  /* temporary work area   */
// struct dsd_comm_block dsl_commbl_l;   /* communication block working variable */
   struct dsd_aux_get_workarea dsl_agwa_l;  /* acquire additional work area */
   struct dsd_aux_get_send_buffer dsl_agsb_l;  /* acquire send buffer  */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   union {
     struct dsd_ntlm_req dsl_ntlm_req;      /* NTLM request            */
     struct dsd_aux_krb5_se_ti_get_1 dsl_akstg1;  /* Kerberos get Service Ticket */
     struct dsd_aux_krb5_se_ti_c_r_1 dsl_akstc1;  /* Kerberos check Service Ticket Response */
     struct dsd_aux_krb5_get_session_key dsl_akgsk;  /* retrieve Kerberos-5 session key */
     struct dsd_aux_krb5_se_ti_rel_1 dsl_akstr1;  /* Kerberos release Service Ticket Resources */
   };
     struct dsd_gather_i_1 dsl_gai1_l;      /* gather input data       */
// };
   union {
//   struct dsd_unicode_string dsl_ucs_work;  /* unicode string        */
     char       chrl_file_id[ 16 ];         /* FileId                  */
   };
   char       byrl_work_smb2_hdr[ sizeof(struct dsd_smb2_hdr_sync) ];  /* space for SMB2 header */
   char       byrl_work_01[ 256 ];          /* work area               */

   dsl_sdh_call_1.amc_aux = adsp_smbcl_ctrl->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_smbcl_ctrl->vpc_userfld;  /* User Field Subroutine */
   dsl_sdh_call_1.achc_lower = NULL;        /* work area lower address */
   dsl_sdh_call_1.achc_upper = NULL;        /* work area upper address */
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   adss_sdh_call_1 = &dsl_sdh_call_1;       /* SDH call structure      */
#endif
   iml_ret_error = 1;                       /* return error            */
   if (adsp_smbcl_ctrl->ac_ext == NULL) {   /* attached buffer pointer */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                      DEF_AUX_MEMGET,  /* get a block of memory */
                                      &adsp_smbcl_ctrl->ac_ext,
                                      sizeof(struct dsd_smb_cl_session) );  /* SMB client session */
     memset( adsp_smbcl_ctrl->ac_ext, 0, sizeof(struct dsd_smb_cl_session) );  /* SMB client session */
   }
   adsl_scs = (struct dsd_smb_cl_session *) adsp_smbcl_ctrl->ac_ext;  /* SMB client session */
//#ifdef XYZ1
// 08.05.14 KB
   adsp_smbcl_ctrl->adsc_smbcc_out_ch = NULL;  /* clear chain of output commands */
//#endif
   aadsl_smbcc_out_next                     /* for chain of output commands */
    = &adsp_smbcl_ctrl->adsc_smbcc_out_ch;  /* chain of output commands */
#ifdef TRACEHL1
   iml1 = 0;
   if (adsp_smbcl_ctrl->adsc_smbcc_in_ch) {
     iml1 = (int) adsp_smbcl_ctrl->adsc_smbcc_in_ch->iec_smbcc_in;
   }
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d iec_smb_cs=%d boc_smb_cs_reply_ch_not_ao=%d adsc_smbcc_in_ch=%p iec_smbcc_in=%d adsc_gai1_nw_recv=%p.",
                 __LINE__, adsl_scs->iec_smb_cs, adsl_scs->boc_smb_cs_reply_ch_not_ao, adsp_smbcl_ctrl->adsc_smbcc_in_ch, iml1, adsp_smbcl_ctrl->adsc_gai1_nw_recv );
#endif
#ifdef WAS_BEFORE
   switch (adsl_scs->iec_smb_cs) {          /* state SMB client session */
     case ied_smb_cs_wait:                  /* wait for next command   */
       goto p_in_cmd_00;                    /* process new commands    */
     case ied_smb_cs_start_01:              /* process start of SMB session */
     case ied_smb_cs_start_02:              /* Negotiate Protocol Request */
     case ied_smb_cs_start_03:              /* has sent NTLM negotiate */
     case ied_smb_cs_start_04:              /* has sent NTLM authenticate */
     case ied_smb_cs_start_05:              /* has sent TreeConnect    */
     case ied_smb_cs_reply_dir:             /* wait for reply for dir  */
     case ied_smb_cs_reply_close:           /* wait for reply for close */
       goto p_in_recv_00;                   /* wait for blocks received */
   }
   return;
#endif
#ifdef XYZ1
   if (adsl_scs->iec_smb_cs == ied_smb_cs_wait) {  /* wait for next command */
     goto p_in_cmd_00;                      /* process new commands    */
   }
   goto p_in_recv_00;                       /* wait for blocks received */

   p_in_cmd_00:                             /* process new commands    */
#endif
#ifndef B150211
   /* waste of CPU cycles ??? 11.02.15 KB                              */
   iml_recv_next = 0;                       /* more data received      */
#endif
   if (adsl_scs->iec_smb_cs != ied_smb_cs_wait) {  /* wait for next command */
     goto p_in_recv_00;                     /* check blocks received   */
   }
#ifdef B140114
   if (adsp_smbcl_ctrl->adsc_smbcc_in_ch == NULL) return;  /* chain of input commands */
#endif
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {          /* no input command        */
     goto p_in_recv_00;                     /* check blocks received   */
   }

   p_in_cmd_20:                             /* we have new command     */
   switch (adsl_smbcc_in_c1->iec_smbcc_in) {  /* command input to SMB component */
     case ied_smbcc_in_start:               /* command input start     */
       goto p_in_start_00;                  /* process command input start */
     case ied_smbcc_in_create:              /* command SMB2 create     */
       goto p_in_create_00;                 /* command SMB2 create     */
     case ied_smbcc_in_write:               /* command SMB2 write data */
       goto p_in_write_00;                  /* command SMB2 write data */
     case ied_smbcc_in_set_info_file:       /* command SMB2 set-info file */
       goto p_in_sif_00;                    /* command SMB2 set-info file */
     case ied_smbcc_in_rename_file:         /* command SMB2 rename open file */
       goto p_in_rnf_00;                    /* command SMB2 rename file */
     case ied_smbcc_in_close:               /* command SMB2 close      */
       goto p_in_close_00;                  /* command SMB2 close      */
     case ied_smbcc_in_del_notify:          /* command delete notify - FindCloseChangeNotification */
       goto p_in_del_ch_ntfy_00;            /* command SMB2 cancel     */
     case ied_smbcc_in_echo:                /* command echo - keepalive */
       goto p_in_echo_00;                   /* command SMB2 echo - keep-alive */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_in_cmd_20: adsl_smbcc_in_c1=%p ->iec_smbcc_in=%d.",
                 __LINE__, adsl_smbcc_in_c1, adsl_smbcc_in_c1->iec_smbcc_in );
#endif
   iml1 = __LINE__;
   goto p_invdat_00;                        /* invalid data received   */

   p_in_start_00:                           /* process command input start */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_GET_SEND_BUFFER returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) byrs_smb_npr_01;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) byrs_smb_npr_01 + sizeof(byrs_smb_npr_01);
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_01;                 /* process start of SMB session */
   return;

   p_in_recv_00:                            /* wait for blocks received */
   if (adsp_smbcl_ctrl->adsc_gai1_nw_recv == NULL) return;  /* received from the network */

   p_in_recv_04:                            /* read SMB block          */
   iml_recv_len = m_scan_smb_header( adsp_smbcl_ctrl->adsc_gai1_nw_recv,
                                     &adsl_gai1_rp,
                                     &achl_rp );
   if (iml_recv_len < 0) return;            /* wait for more data      */
   iml_recv_rem = iml_recv_len;             /* remainder data received */
   bol_cont_prev = FALSE;                   /* continue previous header */

   p_in_recv_08:                            /* process next SMB2 header */
   iml_recv_rem -= sizeof(struct dsd_smb2_hdr_sync);  /* length SMB2 header */
   if (iml_recv_rem < 0) {                  /* less than SMB2 header   */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }

   adsl_smb2_hdr_l = (struct dsd_smb2_hdr_sync *) achl_rp;  /* address SMB2 header */
   iml1 = adsl_gai1_rp->achc_ginp_end - achl_rp;  /* length in this gather */
   if (iml1 >= sizeof(struct dsd_smb2_hdr_sync)) {  /* complete SMB2 header in contigous memory */
     achl_rp += sizeof(struct dsd_smb2_hdr_sync);  /* after SMB2 header     */
     goto p_in_recv_40;                     /* complete SMB2 header in contigous memory */
   }
   achl_w1 = byrl_work_smb2_hdr;            /* space for SMB2 header   */
   iml2 = sizeof(struct dsd_smb2_hdr_sync);
   while (TRUE) {
     memcpy( achl_w1, achl_rp, iml1 );
     achl_w1 += iml1;
     achl_rp += iml1;
     iml2 -= iml1;
     if (iml2 == 0) break;
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     iml1 = adsl_gai1_rp->achc_ginp_end - achl_rp;  /* length in this gather */
     if (iml1 > iml2) iml1 = iml2;          /* only this part to copy  */
   }
   adsl_smb2_hdr_l = (struct dsd_smb2_hdr_sync *) byrl_work_smb2_hdr;  /* address SMB2 header */

   p_in_recv_40:                            /* complete SMB2 header in contigous memory */
   iml1 = memcmp( adsl_smb2_hdr_l->chrc_eye_catcher,
                  byrs_smb2_eyecatcher,
                  sizeof(adsl_smb2_hdr_l->chrc_eye_catcher) );
   if (iml1 != 0) {                         /* did not find SMB2 header */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d received SMB2 header umc_nt_status=0X%08X usc_command=0X%04X.",
                 __LINE__,
                 m_get_le4( (char *) &adsl_smb2_hdr_l->umc_nt_status ),
                 m_get_le2( (char *) &adsl_smb2_hdr_l->usc_command ) );
#endif
   uml_nt_status = m_get_le4( (char *) &adsl_smb2_hdr_l->umc_nt_status );
   bol1 = FALSE;
   if (m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_RELATED_OPERATIONS) {
     bol1 = TRUE;
   }
   if (bol1 != bol_cont_prev) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   bol_cont_next = FALSE;                   /* continue next header    */
   iml2 = m_get_le4( (char *) &adsl_smb2_hdr_l->umc_chain_offset );
   if (iml2 > 0) {
     iml2 -= sizeof(struct dsd_smb2_hdr_sync);
     if (iml2 < 0) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
     if (iml2 > iml_recv_rem) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
     bol_cont_next = TRUE;                  /* continue next header    */
   }
   if (uml_nt_status != HL_STATUS_PENDING) {
     goto p_in_recv_60;                     /* SMB2 header valid so far */
   }
   if (bol_cont_next) {                     /* continue next header    */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (m_get_le2( (char *) &adsl_smb2_hdr_l->usc_command ) == HL_SMB2_CHANGE_NOTIFY) {  /* 0X000F */
     goto p_set_ntfy_resp_00;               /* received CHANGE_NOTIFY response */
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;

   p_in_recv_60:                            /* SMB2 header valid so far */
#ifdef B141129
   if (adsl_scs->boc_signed == FALSE) {     /* SMB2 packets need to be signed */
//#ifdef NOT_YET_141126
     if (m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_SIGNED) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
//#endif
     goto p_in_recv_80;                     /* signature has been checked */
   }
   if ((m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_SIGNED) == 0) {
     if (uml_nt_status != 0) {              /* packet with state not signed */
       goto p_in_recv_80;                   /* signature has been checked */
     }
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifndef B150306
   iml1 = m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_SIGNED;
   if (   (adsl_scs->boc_signed == FALSE)   /* SMB2 packets need to be signed */
       && (iml1 == 0)) {
     goto p_in_recv_80;                     /* signature has been checked */
   }
   if (iml1 == 0) {                         /* packet is not signed    */
     if (uml_nt_status != 0) {              /* packet with state not signed */
       goto p_in_recv_80;                   /* signature has been checked */
     }
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (adsl_scs->iec_smb_cs == ied_smb_cs_start_krb5) {  /* has sent Kerberos authentication */
     goto p_in_sta_krb5_00;                 /* start kerberos - received reply */
   }
#ifdef B150306
   if ((m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_SIGNED) == 0) {
     goto p_in_recv_80;                     /* signature has been checked */
   }
#endif
   dsl_gai1_l.achc_ginp_cur = achl_rp;
   dsl_gai1_l.achc_ginp_end = adsl_gai1_rp->achc_ginp_end;
   dsl_gai1_l.adsc_next = adsl_gai1_rp->adsc_next;
   iml1 = iml_recv_rem;                     /* remainder data received */
   if (bol_cont_next) {                     /* continue next header    */
     iml1 = iml2;
   }
   bol_rc = m_check_smb_signature( adsl_scs,
                                   adsl_smb2_hdr_l,
                                   &dsl_gai1_l,  /* blocks received    */
                                   iml1 );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }

   p_in_recv_80:                            /* signature has been checked */
   switch (m_get_le2( (char *) &adsl_smb2_hdr_l->usc_command )) {
     case HL_SMB2_CREATE:                   /* 0X0005                  */
       goto p_create_resp_00;               /* process response to create */
     case HL_SMB2_CLOSE:                    /* 0X0006                  */
       goto p_close_resp_00;                /* process response to close */
     case HL_SMB2_READ:                     /* 0X0008                  */
       goto p_read_resp_00;                 /* SMB2 READ Response      */
     case HL_SMB2_WRITE:                    /* 0X0009                  */
       goto p_write_resp_00;                /* response to SMB2 write data */
     case HL_SMB2_ECHO:                     /* 0X000D                  */
       goto p_echo_resp_00;                 /* response to SMB2 echo   */
     case HL_SMB2_QUERY_DIRECTORY:          /* 0X000E                  */
       goto p_qd_resp_00;                   /* process response to query-directory */
     case HL_SMB2_CHANGE_NOTIFY:            /* 0X000F                  */
       goto p_set_ntfy_resp_00;             /* received CHANGE_NOTIFY response */
     case HL_SMB2_SET_INFO:                 /* 0X0011                  */
       goto p_resp_set_info_00;             /* received SET_INFO response */
   }
   switch (adsl_scs->iec_smb_cs) {          /* state SMB client session */
#ifdef XYZ1
     case ied_smb_cs_start_krb5:            /* has sent Kerberos authentication */
       goto p_in_sta_krb5_00;               /* start kerberos - received reply */
#endif
     case ied_smb_cs_start_02:              /* Negotiate Protocol Request */
       goto p_in_start_40;                  /* send authentication     */
     case ied_smb_cs_start_03:              /* has sent NTLM negotiate */
       goto p_in_start_60;                  /* send NTLM authenticate  */
     case ied_smb_cs_start_04:              /* has sent NTLM authenticate */
       goto p_in_start_80;                  /* end of authentication   */
     case ied_smb_cs_start_05:              /* has sent TreeConnect    */
       goto p_in_start_88;                  /* resonse to TreeConnect  */
#ifdef XYZ1
     case ied_smb_cs_reply_dir:             /* wait for reply for dir  */
       goto p_in_dir_00;                    /* check response to dir   */
#endif
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) byrs_smb_npr_02;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) byrs_smb_npr_02 + sizeof(byrs_smb_npr_02);
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_02;                 /* Negotiate Protocol Request */
   return;

   p_in_start_40:                           /* send authentication     */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_GET_SEND_BUFFER returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#define ADSL_SMBCC_IN_START_G ((struct dsd_smbcc_in_start *) (adsl_smbcc_in_c1 + 1))
   if (ADSL_SMBCC_IN_START_G->boc_krb5) {   /* use Kerberos 5 authentication */
     goto p_in_start_48;                    /* Kerberos 5 authentication */
   }

   /* send NTLM negotiate                                              */
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) byrs_smb_ntlm_neg;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) byrs_smb_ntlm_neg + sizeof(byrs_smb_ntlm_neg);
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_03;                 /* has sent NTLM negotiate */
   return;

   p_in_start_48:                           /* Kerberos 5 authentication */
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - 1)
   memcpy( dsl_agsb_l.achc_send_buffer, byrs_smb_krb5_req, sizeof(byrs_smb_krb5_req) );  /* SMB2 Session Setup Request */
   memset( &dsl_akstg1, 0, sizeof(struct dsd_aux_krb5_se_ti_get_1) );  /* clear Kerberos get Service Ticket */
   dsl_akstg1.imc_options = HL_KRB5_OPT_MUTUAL | HL_KRB5_OPT_GSSAPI;
// dsl_akstg1.dsc_server_name = ADSL_SMBCC_IN_START_G->dsc_ucs_target_ineta;

   /* build SPN = service principal name                               */
   memcpy( byrl_work_01, byrs_krb5_prot_name, sizeof(byrs_krb5_prot_name) );
   iml1 = m_cpy_vx_ucs( byrl_work_01 + sizeof(byrs_krb5_prot_name),
                        sizeof(byrl_work_01) - sizeof(byrs_krb5_prot_name),
                        ied_chs_utf_8,
                        &ADSL_SMBCC_IN_START_G->dsc_ucs_target_ineta );
   if (iml1 < 0) {                          /* string too long         */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   dsl_akstg1.dsc_server_name.ac_str = byrl_work_01;  /* address of string */
   dsl_akstg1.dsc_server_name.imc_len_str = sizeof(byrs_krb5_prot_name) + iml1;  /* length string in elements */
   dsl_akstg1.dsc_server_name.iec_chs_str = ied_chs_utf_8;  /* character set string */

   dsl_akstg1.achc_ticket_buffer = dsl_agsb_l.achc_send_buffer + sizeof(byrs_smb_krb5_req);   /* address buffer for service ticket */
   dsl_akstg1.imc_ticket_buffer_len         /* maximum length Kerberos 5 Service Ticket */
     = dsl_agsb_l.imc_len_send_buffer - sizeof(byrs_smb_krb5_req) - sizeof(struct dsd_gather_i_1);
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_SE_TI_GET,  /* Kerberos get Service Ticket */
                                    &dsl_akstg1,
                                    sizeof(struct dsd_aux_krb5_se_ti_get_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_GET returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akstg1.iec_ret_krb5 != ied_ret_krb5_ok) {  /* not success   */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_GET returned error %d.",
                   __LINE__, dsl_akstg1.iec_ret_krb5 );
     goto p_abend_00;                       /* abend of connection     */
   }
   adsl_scs->vpc_krb5_handle = dsl_akstg1.vpc_handle;  /* Kerberos handle */
   *(dsl_agsb_l.achc_send_buffer + 0X52 + 0) = (unsigned char) dsl_akstg1.imc_ticket_length;
   *(dsl_agsb_l.achc_send_buffer + 0X52 + 1) = (unsigned char) (dsl_akstg1.imc_ticket_length >> 8);
   iml1 = sizeof(byrs_smb_krb5_req) - LEN_SMB_BL_LEN + dsl_akstg1.imc_ticket_length;
   *(dsl_agsb_l.achc_send_buffer + 2) = (unsigned char) (iml1 >> 8);
   *(dsl_agsb_l.achc_send_buffer + 3) = (unsigned char) iml1;
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = dsl_agsb_l.achc_send_buffer;
   ADSL_GAI1_SEND->achc_ginp_end
     = (char *) dsl_agsb_l.achc_send_buffer + sizeof(byrs_smb_krb5_req) + dsl_akstg1.imc_ticket_length;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
#ifdef B141201
   memset( &dsl_akgsk, 0, sizeof(struct dsd_aux_krb5_get_session_key) );  /* retrieve Kerberos-5 session key */
   dsl_akgsk.vpc_handle = adsl_scs->vpc_krb5_handle;  /* Kerberos handle */
   dsl_akgsk.achc_key_buffer = byrl_work_01;  /* output buffer for key data */
   dsl_akgsk.imc_key_buffer_len = MAX_KRB5_SE_KEY;  /* length output buffer for key data */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_GET_SESS_KEY,  /* Kerberos-5 retrieve session key */
                                    &dsl_akgsk,
                                    sizeof(struct dsd_aux_krb5_get_session_key) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akgsk.iec_ret_krb5 != ied_ret_krb5_ok) {  /* not success   */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned error %d.",
                   __LINE__, dsl_akgsk.iec_ret_krb5 );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akgsk.imc_key_len_ret == 0) {    /* length of actual key data */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned length session key zero",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akgsk.imc_key_len_ret < LEN_SMB2_SIGN_KEY) {  /* length sign key of SMB2 */
     memset( byrl_work_01 + dsl_akgsk.imc_key_len_ret, 0, LEN_SMB2_SIGN_KEY - dsl_akgsk.imc_key_len_ret );
   }
   m_gen_smb_sign_key( adsl_scs, byrl_work_01 );
   adsl_scs->boc_signed = TRUE;             /* SMB2 packets need to be signed */
#endif
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_krb5;               /* has sent Kerberos authentication */
   return;

#undef ADSL_SMBCC_IN_START_G

   p_in_sta_krb5_00:                        /* start kerberos - received reply */
   if (uml_nt_status != 0) {                /* received status         */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() reply to Kerberos ticket - received status 0X%08X.",
                   __LINE__, uml_nt_status );
     goto p_abend_00;                       /* abend of connection     */
   }
   if ((m_get_le4( (char *) &adsl_smb2_hdr_l->umc_flags ) & HL_SMB2_FLAGS_SIGNED) == 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (iml_recv_rem > sizeof(byrl_work_01)) {  /* reply too long       */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memcpy( adsl_scs->chrc_session_id, adsl_smb2_hdr_l->chrc_session_id, sizeof(adsl_scs->chrc_session_id) );
   dsl_gai1_l.achc_ginp_cur = achl_rp;
   dsl_gai1_l.achc_ginp_end = adsl_gai1_rp->achc_ginp_end;
   dsl_gai1_l.adsc_next = adsl_gai1_rp->adsc_next;
   achl_w1 = achl_rp;                       /* pointer to set-info response header */
   if ((achl_rp + iml_recv_rem) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += iml_recv_rem;
     goto p_in_sta_krb5_20;                 /* start kerberos - buffer at achl_w1 */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = iml_recv_rem;                     /* response to set-info    */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + iml_recv_rem - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_sta_krb5_20:                        /* start kerberos - buffer at achl_w1 */
#define ADSL_SMB2_SESS_SU_RESP_G ((struct dsd_smb2_session_setup_response *) achl_w1)
   iml1 = m_get_le2( (char *) &ADSL_SMB2_SESS_SU_RESP_G->usc_structure_size );  /* StructureSize */
   if ((iml1 & -2) > iml_recv_rem) {        /* greater remaining part  */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml2 = m_get_le2( (char *) &ADSL_SMB2_SESS_SU_RESP_G->usc_security_buffer_offset );  /* SecurityBufferOffset */
   if (iml2 < (sizeof(struct dsd_smb2_hdr_sync) + (iml1 & -2))) {  /* offset too short */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml3 = m_get_le2( (char *) &ADSL_SMB2_SESS_SU_RESP_G->usc_security_buffer_length );  /* SecurityBufferLength */
   if ((iml2 - sizeof(struct dsd_smb2_hdr_sync) + iml3) > iml_recv_rem) {  /* greater remaining part */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#undef ADSL_SMB2_SESS_SU_RESP_G
   memset( &dsl_akstc1, 0, sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );  /* Kerberos check Service Ticket Response */
   dsl_akstc1.vpc_handle = adsl_scs->vpc_krb5_handle;  /* Kerberos handle */
#ifndef TRY_150302_01                       /* DEF_AUX_KRB5_SE_TI_C_R  */
   dsl_akstc1.achc_response_buffer          /* address buffer of response */
     = achl_w1 + iml2 - sizeof(struct dsd_smb2_hdr_sync);
#endif
#ifdef TRY_150302_01                        /* DEF_AUX_KRB5_SE_TI_C_R  */
   dsl_akstc1.achc_response_buffer          /* address buffer of response */
     = achl_w1 + iml2;
#endif
   dsl_akstc1.imc_response_length = iml3;   /* length of response      */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_SE_TI_C_R,  /* Kerberos check Service Ticket Response */
                                    &dsl_akstc1,
                                    sizeof(struct dsd_aux_krb5_se_ti_c_r_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_C_R returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akstc1.iec_ret_krb5 != ied_ret_krb5_ok) {  /* not success   */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_C_R returned error %d.",
                   __LINE__, dsl_akstc1.iec_ret_krb5 );
//#ifdef NOT_YET_140121
     goto p_abend_00;                       /* abend of connection     */
//#endif
   }

   memset( &dsl_akgsk, 0, sizeof(struct dsd_aux_krb5_get_session_key) );  /* retrieve Kerberos-5 session key */
   dsl_akgsk.vpc_handle = adsl_scs->vpc_krb5_handle;  /* Kerberos handle */
   dsl_akgsk.achc_key_buffer = byrl_work_01;  /* output buffer for key data */
   dsl_akgsk.imc_key_buffer_len = MAX_KRB5_SE_KEY;  /* length output buffer for key data */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_GET_SESS_KEY,  /* Kerberos-5 retrieve session key */
                                    &dsl_akgsk,
                                    sizeof(struct dsd_aux_krb5_get_session_key) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akgsk.iec_ret_krb5 != ied_ret_krb5_ok) {  /* not success   */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned error %d.",
                   __LINE__, dsl_akgsk.iec_ret_krb5 );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akgsk.imc_key_len_ret == 0) {    /* length of actual key data */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned length session key zero",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_GET_SESS_KEY returned length session key %d - LEN_SMB2_SIGN_KEY %d.",
                 __LINE__, dsl_akgsk.imc_key_len_ret, LEN_SMB2_SIGN_KEY );
#endif
   if (dsl_akgsk.imc_key_len_ret < LEN_SMB2_SIGN_KEY) {  /* length sign key of SMB2 */
     memset( byrl_work_01 + dsl_akgsk.imc_key_len_ret, 0, LEN_SMB2_SIGN_KEY - dsl_akgsk.imc_key_len_ret );
   }
   m_gen_smb_sign_key( adsl_scs, byrl_work_01 );
   adsl_scs->boc_signed = TRUE;             /* SMB2 packets need to be signed */

   memset( &dsl_akstr1, 0, sizeof(struct dsd_aux_krb5_se_ti_rel_1) );  /* Kerberos release Service Ticket Resources */
   dsl_akstr1.vpc_handle = adsl_scs->vpc_krb5_handle;  /* Kerberos handle */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_SE_TI_REL,  /* Kerberos release Service Ticket Resources */
                                    &dsl_akstc1,
                                    sizeof(struct dsd_aux_krb5_se_ti_rel_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_REL returned FALSE",
                   __LINE__ );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (dsl_akstr1.iec_ret_krb5 != ied_ret_krb5_ok) {  /* not success   */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_REL returned error %d.",
                   __LINE__, dsl_akstr1.iec_ret_krb5 );
     goto p_abend_00;                       /* abend of connection     */
   }
   adsl_scs->vpc_krb5_handle = NULL;        /* clear Kerberos handle   */

   bol_rc = m_check_smb_signature( adsl_scs,
                                   adsl_smb2_hdr_l,
                                   &dsl_gai1_l,  /* blocks received    */
                                   iml_recv_rem );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef XYZ1
   iml1 = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml1 < 0) {                          /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml1 > 0) {                          /* more data received      */
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   adsl_scs->ulc_command_sequence_number = 2;
   goto p_in_start_80;                      /* end of authentication   */

   p_in_start_60:                           /* send NTLM authenticate  */
   memcpy( adsl_scs->chrc_session_id, adsl_smb2_hdr_l->chrc_session_id, sizeof(adsl_scs->chrc_session_id) );
   /* save NTLM challenge                                              */
   iml_recv_len -= sizeof(struct dsd_smb2_hdr_sync);  /* subtract length SMB2 header */

   /* consume 8 bytes of header                                        */
   if (iml_recv_len <= 8) {                 /* too short               */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml1 = 8;                                /* number of bytes to consume */
   iml_recv_len -= iml1;                    /* length remaining        */
   while (TRUE) {
     iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;  /* length in this gather */
     if (iml2 > iml1) iml2 = iml1;          /* only this part to copy  */
     achl_rp += iml2;
     iml1 -= iml2;
     if (iml1 == 0) break;
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
   }

   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_MEMGET,  /* get a block of memory */
                                    &adsl_sce_w1,
                                    sizeof(struct dsd_smb_cl_extra) + iml_recv_len );  /* SMB client extra data   */
   adsl_sce_w1->iec_smb_cet = ied_smb_cet_ntlm_cha;  /* save NTLM challenge */
   adsl_sce_w1->imc_len = iml_recv_len;     /* length SMB client extra data */
   adsl_sce_w1->adsc_next = adsl_scs->adsc_sce_ch;  /* get old chain SMB client extra data */
   adsl_scs->adsc_sce_ch = adsl_sce_w1;     /* set new chain SMB client extra data */
   iml1 = iml_recv_len;                     /* get length              */
   achl_w1 = (char *) (adsl_sce_w1 + 1);    /* copy here               */
   while (TRUE) {
     iml2 = adsl_gai1_rp->achc_ginp_end - achl_rp;  /* length in this gather */
     if (iml2 > iml1) iml2 = iml1;          /* only this part to copy  */
     memcpy( achl_w1, achl_rp, iml2 );
     achl_w1 += iml2;
     achl_rp += iml2;
     iml1 -= iml2;
     if (iml1 == 0) break;
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
   }

   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define IML_LEN_REQ_AUTH 24

   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#define ADSL_SMBCC_IN_START_G ((struct dsd_smbcc_in_start *) (adsl_smbcc_in_c1 + 1))
#ifdef XYZ1
   if (ADSL_SMBCC_IN_START_G->boc_krb5) {   /* use Kerberos 5 authentication */
     goto p_in_start_64;                    /* Kerberos 5 authentication */
   }
#endif
   memset( &dsl_ntlm_req, 0, sizeof(struct dsd_ntlm_req) );  /* NTLM request */
   dsl_ntlm_req.vpc_userfld = dsl_sdh_call_1.vpc_userfld;  /* userfield for callbacks */
   dsl_ntlm_req.amc_get_epoch = &m_cb_get_epoch;  /* callback get epoch */
   dsl_ntlm_req.amc_get_random = &m_cb_get_random;  /* callback get random */
   dsl_ntlm_req.boc_gssapi = TRUE;          /* use GSSAPI              */
   dsl_ntlm_req.achc_negotiate = (char *) byrs_smb_ntlm_neg + sizeof(struct dsd_smb2_hdr_sync) + 24;  /* address of packet NTLMSSP_NEGOTIATE */
   dsl_ntlm_req.imc_len_negotiate = sizeof(byrs_smb_ntlm_neg) - sizeof(struct dsd_smb2_hdr_sync) - 24;  /* length of packet NTLMSSP_NEGOTIATE */
// dsl_ntlm_req.imc_offset_negotiate = 0X40 + 24;         /* offset of content NTLMSSP_NEGOTIATE */
   dsl_ntlm_req.achc_challenge = (char *) (adsl_sce_w1 + 1);  /* address of packet NTLMSSP_CHALLENGE */
   dsl_ntlm_req.imc_len_challenge = iml_recv_len;  /* length of packet NTLMSSP_CHALLENGE */
// dsl_ntlm_req.imc_offset_challenge = ADSL_SMB2_HDR_IN->usc_header_length + 8;         /* offset of content NTLMSSP_CHALLENGE */
   dsl_ntlm_req.achc_auth = ACHL_SEND_BUF + LEN_SMB_BL_LEN + sizeof(struct dsd_smb2_hdr_sync) + IML_LEN_REQ_AUTH;  /* address of packet NTLMSSP_AUTH */
   dsl_ntlm_req.imc_len_auth = (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - (ACHL_SEND_BUF + LEN_SMB_BL_LEN + sizeof(struct dsd_smb2_hdr_sync) + IML_LEN_REQ_AUTH);  /* length of packet NTLMSSP_AUTH */
// dsl_ntlm_req.imc_offset_auth = 0X40 + IML_LEN_REQ_AUTH;  /* offset of content NTLMSSP_AUTH */
   dsl_ntlm_req.dsc_ucs_domain = ADSL_SMBCC_IN_START_G->dsc_ucs_domain;  /* domain */
   dsl_ntlm_req.dsc_ucs_userid = ADSL_SMBCC_IN_START_G->dsc_ucs_userid;  /* userid */
   dsl_ntlm_req.dsc_ucs_password = ADSL_SMBCC_IN_START_G->dsc_ucs_password;  /* password */
   dsl_ntlm_req.dsc_ucs_workstation = ADSL_SMBCC_IN_START_G->dsc_ucs_workstation;  /* workstation */
   memcpy( byrl_work_01 + LEN_NTLM_SIGN_KEY, "cifs/", 5 );
   iml1 = m_cpy_vx_ucs( byrl_work_01 + LEN_NTLM_SIGN_KEY + 5,
                        sizeof(byrl_work_01) - LEN_NTLM_SIGN_KEY - 5,
                        ied_chs_utf_8,
                        &ADSL_SMBCC_IN_START_G->dsc_ucs_target_ineta );
   if (iml1 < 0) {                          /* string too long         */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   dsl_ntlm_req.dsc_ucs_prot_target.ac_str = byrl_work_01 + LEN_NTLM_SIGN_KEY;
   dsl_ntlm_req.dsc_ucs_prot_target.imc_len_str = 5 + iml1;
   dsl_ntlm_req.dsc_ucs_prot_target.iec_chs_str = ied_chs_utf_8;
   dsl_ntlm_req.achc_ntlm_sign_key = byrl_work_01;  /* NTLM signing key */
   dsl_ntlm_req.iec_ntlmf = ied_ntlmf_auth_gen;  /* generate NTLMSSP_AUTH */
   bol_rc = m_proc_ntlm_req( &dsl_ntlm_req );
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d m_proc_ntlm_req() returned %d imc_ret_error_line=%d.",
                 __LINE__, bol_rc, dsl_ntlm_req.imc_ret_error_line );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   m_gen_smb_sign_key( adsl_scs, byrl_work_01 );
#ifdef XYZ1
   adsl_scs->boc_signed = TRUE;             /* SMB2 packets need to be signed */
#endif
   iml1 = sizeof(struct dsd_smb2_hdr_sync) + IML_LEN_REQ_AUTH + dsl_ntlm_req.imc_len_auth;
#ifdef XYZ1
   goto p_in_start_68;                      /* output has been prepared */

   p_in_start_64:                           /* Kerberos 5 authentication */
   memset( &dsl_akstg1, 0, sizeof(struct dsd_aux_krb5_se_ti_get_1) );  /* clear Kerberos get Service Ticket */
   dsl_akstg1.imc_options = HL_KRB5_OPT_GSSAPI;
   dsl_akstg1.dsc_server_name = ADSL_SMBCC_IN_START_G->dsc_ucs_target_ineta;

   p_in_start_68:                           /* output has been prepared */
#endif
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml1 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml1 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml1 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml1;
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher,
           byrs_smb2_eyecatcher,
           sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   ADSL_SMB2_HDR_OUT->ulc_command_sequence_number = 3;
   ADSL_SMB2_HDR_OUT->usc_header_length = sizeof(struct dsd_smb2_hdr_sync);
   ADSL_SMB2_HDR_OUT->usc_credit_charge = 1;
   ADSL_SMB2_HDR_OUT->umc_nt_status = 0;
   ADSL_SMB2_HDR_OUT->usc_command = 1;  /* Command: SessionSetup */
   ADSL_SMB2_HDR_OUT->usc_credits_granted = 31;
   ADSL_SMB2_HDR_OUT->umc_flags = 0;
   ADSL_SMB2_HDR_OUT->umc_chain_offset = 0;
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ACHL_SMB2_REQ_OUT ((char *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ACHL_SMB2_REQ_OUT, 0, IML_LEN_REQ_AUTH );
   *(ACHL_SMB2_REQ_OUT + 0) = IML_LEN_REQ_AUTH | 1;
   *(ACHL_SMB2_REQ_OUT + 3) = 1;
   *(ACHL_SMB2_REQ_OUT + 4) = 1;
   *(ACHL_SMB2_REQ_OUT + 12) = sizeof(struct dsd_smb2_hdr_sync) + IML_LEN_REQ_AUTH;
   *((unsigned short int *) (ACHL_SMB2_REQ_OUT + 14)) = dsl_ntlm_req.imc_len_auth;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + sizeof(struct dsd_smb2_hdr_sync) + IML_LEN_REQ_AUTH + dsl_ntlm_req.imc_len_auth;
#ifdef XYZ1
#ifdef TRACEHL1
         m_hl1_printf( "xbdash01-l%05d-T send length %d/0X%X.",
                        __LINE__, ADSL_GAI1_SEND->achc_ginp_end - ADSL_GAI1_SEND->achc_ginp_cur, ADSL_GAI1_SEND->achc_ginp_end - ADSL_GAI1_SEND->achc_ginp_cur );
         m_console_out( (char *) ADSL_GAI1_SEND->achc_ginp_cur, ADSL_GAI1_SEND->achc_ginp_end - ADSL_GAI1_SEND->achc_ginp_cur );
#endif
#endif
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv,
                                    LEN_SMB_BL_LEN + sizeof(struct dsd_smb2_hdr_sync) + 8 + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_scs->ulc_command_sequence_number = 3;
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_04;                 /* has sent NTLM authenticate */
   return;
#undef ACHL_SEND_BUF
#undef IML_LEN_REQ_AUTH
#undef ADSL_SMBCC_IN_START_G
#undef ADSL_SMB2_HDR_OUT
#undef ACHL_SMB2_REQ_OUT

   p_in_start_80:                           /* end of authentication   */
   if (uml_nt_status != 0) {                /* error authentication    */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d authentication failed - NT-STATUS %08X.",
                   __LINE__, uml_nt_status );
#ifdef B151216
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
#endif
     iml_ret_error = 2;                     /* return error authentication */
     goto p_abend_00;                       /* abend of connection     */
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, 3 );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
#ifdef XYZ1
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, 4 );
#endif
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ACHL_SMB2_REQ_OUT ((char *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ACHL_SMB2_REQ_OUT, 0, 8 );
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#define ADSL_SMBCC_IN_START_G ((struct dsd_smbcc_in_start *) (adsl_smbcc_in_c1 + 1))
   iml1 = m_cpy_vx_ucs( ACHL_SMB2_REQ_OUT + 8,
                        256,
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_START_G->dsc_ucs_tree_name );  /* name of tree to connect to */
   if (iml1 < 0) {                          /* string too long         */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   m_put_le2( ACHL_SMB2_REQ_OUT + 6, iml1 * sizeof(HL_WCHAR) );
   *(ACHL_SMB2_REQ_OUT + 0) = 0X09;
   m_put_le2( ACHL_SMB2_REQ_OUT + 4, sizeof(struct dsd_smb2_hdr_sync) + 8 );
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = ACHL_SMB2_REQ_OUT;
     dsl_gai1_l.achc_ginp_end = ACHL_SMB2_REQ_OUT + 8 + iml1 * sizeof(HL_WCHAR);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = sizeof(struct dsd_smb2_hdr_sync) + 8 + iml1 * sizeof(HL_WCHAR);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_start_05;                 /* has sent TreeConnect    */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMBCC_IN_START_G
#undef ACHL_SMB2_REQ_OUT

   p_in_start_88:                           /* resonse to TreeConnect  */
   if (uml_nt_status != 0) {
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d TreeConnect NT-STATUS 0X%08X.",
                   __LINE__, uml_nt_status );
     goto p_abend_00;                       /* abend of connection     */
   }
   if (iml_recv_len != (sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_tree_connect_response))) {  /* SMB2 TREE_CONNECT Response */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memcpy( adsl_scs->chrc_tree_id, &adsl_smb2_hdr_l->umc_tree_id, sizeof(adsl_scs->chrc_tree_id) );
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef XYZ1
   adsl_scs->ulc_command_sequence_number = 4;
#endif
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   return;

   p_in_create_00:                          /* command SMB2 create     */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_smbcc_in_c1 + 1))
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)

#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   //dsd_smb2_hdr_sync* adsl_test_hdr_1 = ADSL_SMB2_HDR_OUT;
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_CREATE );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_CREATE_RQ ((struct dsd_smb2_create_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_CREATE_RQ, 0, sizeof(struct dsd_smb2_create_request) );
   m_put_le2( (char *) &ADSL_SMB2_CREATE_RQ->usc_structure_size, sizeof(struct dsd_smb2_create_request) + 1);   /* StructureSize */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_impersonation_level, 2 );  /* ImpersonationLevel */
#ifdef WAS_BEFORE
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_desired_access, 0X00100081 );  /* DesiredAccess */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_share_access, 7 );  /* ShareAccess */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_create_disposition, 1 );  /* CreateDisposition */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_create_options, 0X21 );  /* CreateOptions */
#endif
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_desired_access, ADSL_SMBCC_IN_CREATE_G->umc_desired_access );  /* DesiredAccess */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_file_attributes, ADSL_SMBCC_IN_CREATE_G->umc_file_attributes );  /* FileAttributes */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_share_access, ADSL_SMBCC_IN_CREATE_G->umc_share_access );  /* ShareAccess */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_create_disposition, ADSL_SMBCC_IN_CREATE_G->umc_create_disposition );  /* CreateDisposition */
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_create_options, ADSL_SMBCC_IN_CREATE_G->umc_create_options );  /* CreateOptions */
   iml1 = m_cpy_vx_ucs( ADSL_SMB2_CREATE_RQ + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_SMB2_CREATE_RQ + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name );  /* filename */
   if (iml1 < 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   m_put_le2( (char *) &ADSL_SMB2_CREATE_RQ->usc_name_offset, ((char *) (ADSL_SMB2_CREATE_RQ + 1)) - ((char *) ADSL_SMB2_HDR_OUT) );  /* NameOffset */
   m_put_le2( (char *) &ADSL_SMB2_CREATE_RQ->usc_name_length, iml1 * sizeof(HL_WCHAR) );  /* NameLength */
   adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
   if (   (adsl_smbcc_in_c2 == NULL)
       && (ADSL_SMBCC_IN_CREATE_G->iec_sicd == ied_sicd_appended)) {  /* see command appended */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (   (adsl_smbcc_in_c2 == NULL)
       || (adsl_smbcc_in_c2->iec_smbcc_in == ied_smbcc_in_complete_file_read)  /* command read complete file */
       || (adsl_smbcc_in_c2->iec_smbcc_in == ied_smbcc_in_set_notify)) {  /* command set notify - FindFirstChangeNotification */
     iml2 = (char *) (ADSL_SMB2_CREATE_RQ + 1) + iml1 * sizeof(HL_WCHAR)
              - (char *) ADSL_SMB2_HDR_OUT;
	 bol_cont_next = FALSE;			/*This isn't compounded*/
     goto p_in_create_20;                   /* SMB2 create request complete */
   }
   if (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_query_directory) {  /* command SMB2 query-directory */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }

   bol_cont_next = TRUE; //This is Compounded
   adsl_smb2_hdr_l = (struct dsd_smb2_hdr_sync *) ((char *) (ADSL_SMB2_CREATE_RQ + 1) + ((iml1 * sizeof(HL_WCHAR) + sizeof(HL_LONGLONG) - 1) & (0 - sizeof(HL_LONGLONG))));
   //dsd_smb2_hdr_sync* adsl_test_hdr_2 = adsl_smb2_hdr_l;
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_chain_offset, ((char *) adsl_smb2_hdr_l) - ((char *) ADSL_SMB2_HDR_OUT) );
   memset( adsl_smb2_hdr_l, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( adsl_smb2_hdr_l->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(adsl_smb2_hdr_l->chrc_eye_catcher) );
   m_put_le2( (char *) &adsl_smb2_hdr_l->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &adsl_smb2_hdr_l->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
#ifdef B150316
   m_put_le4( (char *) &ADSL_SMB2_CREATE_RQ->umc_flags, HL_SMB2_FLAGS_RELATED_OPERATIONS );
#endif
   iml2 = HL_SMB2_FLAGS_RELATED_OPERATIONS;
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     iml2 = HL_SMB2_FLAGS_RELATED_OPERATIONS | HL_SMB2_FLAGS_SIGNED;
   }
   m_put_le4( (char *) &adsl_smb2_hdr_l->umc_flags, iml2 );
   m_put_le2( (char *) &adsl_smb2_hdr_l->usc_command, HL_SMB2_QUERY_DIRECTORY );
   m_put_le2( (char *) &adsl_smb2_hdr_l->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &adsl_smb2_hdr_l->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &adsl_smb2_hdr_l->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &adsl_smb2_hdr_l->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(adsl_smb2_hdr_l->umc_tree_id) );
   memcpy( adsl_smb2_hdr_l->chrc_session_id, adsl_scs->chrc_session_id, sizeof(adsl_smb2_hdr_l->chrc_session_id) );
#define ADSL_SMBCC_IN_QD_G ((struct dsd_smbcc_in_query_directory *) (adsl_smbcc_in_c2 + 1))
#define ADSL_SMB2_QUERY_DIR_G ((struct dsd_smb2_query_directory_request *) (adsl_smb2_hdr_l + 1))
   memset( ADSL_SMB2_QUERY_DIR_G, 0, sizeof(struct dsd_smb2_query_directory_request) );
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_structure_size, sizeof(struct dsd_smb2_query_directory_request) + 1 );
   ADSL_SMB2_QUERY_DIR_G->chc_file_information_class = HL_SMB2_QD_FILE_DIRECTORY_INFORMATION;  /* FileInformationClass */
// ADSL_SMB2_QUERY_DIR_G->chc_file_information_class = HL_SMB2_QD_FILE_ID_BOTH_DIRECTORY_INFORMATION;  /* FileIdBothDirectoryInformation */
// memset( ADSL_SMB2_QUERY_DIR_G->chrc_file_index, 0XFF, sizeof(ADSL_SMB2_QUERY_DIR_G->chrc_file_index) );  /* FileIndex */
   memset( ADSL_SMB2_QUERY_DIR_G->chrc_file_id, 0XFF, sizeof(ADSL_SMB2_QUERY_DIR_G->chrc_file_id) );  /* FileId */
#ifdef B140519
   iml1 = m_cpy_vx_ucs( ADSL_SMB2_QUERY_DIR_G + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_SMBCC_IN_QD_G + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern );
#endif
   iml3 = m_cpy_vx_ucs( ADSL_SMB2_QUERY_DIR_G + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_SMB2_QUERY_DIR_G + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern );
   if (iml3 < 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_file_name_offset, ((char *) (ADSL_SMB2_QUERY_DIR_G + 1)) - ((char *) adsl_smb2_hdr_l) );  /* FileNameOffset */
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_file_name_length, iml3 * sizeof(HL_WCHAR) );  /* FileNameLength */
// m_put_le4( (char *) &ADSL_SMB2_QUERY_DIR_G->umc_output_buffer_length, 0X00010000 );  /* OutputBufferLength */
// m_put_le4( (char *) &ADSL_SMB2_QUERY_DIR_G->umc_output_buffer_length, 0X00001000 );  /* OutputBufferLength */
   m_put_le4( (char *) &ADSL_SMB2_QUERY_DIR_G->umc_output_buffer_length, LEN_SMB_DIR );  /* OutputBufferLength */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_QUERY_DIR_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_QUERY_DIR_G + 1) + iml3 * sizeof(HL_WCHAR);
     dsl_gai1_l.adsc_next = NULL;
	 m_fill_smb_signature( adsl_scs, adsl_smb2_hdr_l, &dsl_gai1_l );
   }

   iml2 = (char *) (ADSL_SMB2_QUERY_DIR_G + 1) + iml3 * sizeof(HL_WCHAR)
            - (char *) ADSL_SMB2_HDR_OUT;

   p_in_create_20:                          /* SMB2 create request complete */
#define ACHL_SMB2_REQ_OUT ((char *) (ADSL_SMB2_HDR_OUT + 1))
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = ACHL_SMB2_REQ_OUT;
#ifdef XYZ1
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_CREATE_RQ + 1) + iml1 * sizeof(HL_WCHAR);
#endif

	 if (bol_cont_next) {
		dsl_gai1_l.achc_ginp_end = (char *) adsl_smb2_hdr_l; //End of First is Start of Second Header
	 } else {
		dsl_gai1_l.achc_ginp_end = (char *) ADSL_SMB2_HDR_OUT + iml2;
	 }
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
#undef ACHL_SMB2_REQ_OUT
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
//  = ied_smb_cs_xyz;
     = ied_smb_cs_reply_dir;                /* wait for reply for dir  */
   return;
#undef ADSL_SMBCC_IN_CREATE_G
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_CREATE_RQ
#undef ADSL_SMBCC_IN_QD_G
#undef ADSL_SMB2_QUERY_DIR_G

   p_create_resp_00:                        /* process response to create */
#ifdef B141101
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_dir) {  /* wait for reply for dir */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifdef B141213
   if (   (adsl_scs->iec_smb_cs != ied_smb_cs_reply_dir)  /* wait for reply for dir */
       && (adsl_scs->iec_smb_cs != ied_smb_cs_reply_ch_not_ao)) {  /* wait for change notify out of order */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_dir) {  /* wait for reply for dir */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B141029
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifdef WAS_BEFORE
   if (bol_cont_next == FALSE) {            /* continue next header    */
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml2 -= sizeof(struct dsd_smb2_create_response);  /* SMB2 CREATE Response */
   if (iml2 < 0) {                          /* less than SMB2 CREATE Response header */
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (uml_nt_status != 0) {
     goto p_create_resp_40;                 /* receive NT-STATUS       */
   }
   if (bol_cont_next) {                     /* continue next header    */
     iml2 -= sizeof(struct dsd_smb2_create_response);  /* SMB2 CREATE Response */
     if (iml2 < 0) {                        /* less than SMB2 CREATE Response header */
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
   }
// to-do 12.05.13 KB - should we subtract iml2 ?
   iml_recv_rem -= sizeof(struct dsd_smb2_create_response);  /* remainder data received */
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(struct dsd_smb2_create_response)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(struct dsd_smb2_create_response);
     goto p_create_resp_20;                 /* SMB2 CREATE Response    */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(struct dsd_smb2_create_response);  /* set count       */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(struct dsd_smb2_create_response) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_create_resp_20:                        /* SMB2 CREATE Response    */
#define ADSL_CR_G ((struct dsd_smb2_create_response *) achl_w1)  /* SMB2 CREATE Response */
   memcpy( adsl_scs->chrc_file_id, ADSL_CR_G->chrc_file_id, sizeof(adsl_scs->chrc_file_id) );  /* FileId */
#undef ADSL_CR_G
   /* overread padding                                                 */
   while (iml2 > 0) {                       /* loop to ignore data     */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml2) iml4 = iml2;
     iml2 -= iml4;
     achl_rp += iml4;
   }
   if (bol_cont_next == FALSE) {            /* continue next header    */
#ifdef B141101
     adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
     if (adsl_smbcc_in_c1 == NULL) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
     if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
#endif
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_smbcc_in_c1 + 1))
     switch (ADSL_SMBCC_IN_CREATE_G->iec_sicd) {  /* command input create disposition */
       case ied_sicd_appended:              /* see command appended    */
         break;
       case ied_sicd_close:                 /* close immediately       */
#ifdef XYZ1
         goto p_create_resp_80;             /* process response to create - send next command */
#ifdef B140513
       case ied_sicd_delete:                /* delete file / directory */
         goto p_create_resp_80;             /* process response to create - send next command */
#endif
#endif
       case ied_sicd_delete_file:           /* delete file             */
       case ied_sicd_delete_dir:            /* delete directory        */
         goto p_create_resp_80;             /* process response to create - send next command */
       case ied_sicd_keep_open:             /* keep file for following operations */
         goto p_create_resp_60;             /* process response to create - keep open */
       default:
         iml1 = __LINE__;
         goto p_invdat_00;                  /* invalid data in input command */
     }
#undef ADSL_SMBCC_IN_CREATE_G
     adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
     if (adsl_smbcc_in_c2 == NULL) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
     switch (adsl_smbcc_in_c2->iec_smbcc_in) {   /* command input to SMB component */
       case ied_smbcc_in_complete_file_read:  /* command read complete file */
         goto p_read_req_00;                /* read request            */
       case ied_smbcc_in_set_notify:        /* command set notify - FindFirstChangeNotification */
         goto p_send_set_ntfy_00;           /* send CHANGE_NOTIFY      */
     }
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   bol_cont_prev = TRUE;                    /* continue previous header */
   goto p_in_recv_08;                       /* process next SMB2 header */

   p_create_resp_40:                        /* receive NT-STATUS       */
   if (bol_cont_next) {                     /* continue next header    */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B141101
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   adsl_smbcc_in_c1->umc_nt_status = uml_nt_status;  /* returned SMB state */
   switch (uml_nt_status) {                 /* NT-STATUS returned      */
     case HL_STATUS_ACCESS_DENIED:          /* 0XC0000022              */
       adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_access_denied;  /* access denied */
       break;
     case HL_STATUS_OBJECT_NAME_NOT_FOUND:  /* 0XC0000034              */
       adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_not_found;  /* file not found or simular */
       break;
     case HL_STATUS_SHARING_VIOLATION:      /* 0XC0000043              */
       adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_locked;  /* file is locked */
       break;
     default:
       adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_misc_error;  /* miscellaneous error */
       break;
   }
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */

   p_create_resp_60:                        /* process response to create - keep open */
   if ((sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_create))
         > (dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)) {  /* check work area */
     bol_rc = m_acquire_work_area( &dsl_sdh_call_1 );
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_create);
#define ADSL_SOC_G ((struct dsd_smbcc_out_cmd *) dsl_sdh_call_1.achc_upper)  /* HOBLink SMB Client Control - output command */
#define ADSL_SOCR_G ((struct dsd_smbcc_out_create *) (ADSL_SOC_G + 1))  /* command output SMB2 create */
#define ADSL_CR_G ((struct dsd_smb2_create_response *) achl_w1)  /* SMB2 CREATE Response */
   memcpy( ADSL_SOCR_G->chrc_file_id, ADSL_CR_G->chrc_file_id, sizeof(ADSL_SOCR_G->chrc_file_id) );  /* FileId */
#undef ADSL_CR_G
   ADSL_SOC_G->iec_smbcc_out                /* command output from SMB component */
     = ied_smbcc_out_create;                /* response to create      */
   ADSL_SOC_G->adsc_next = NULL;            /* end of chain            */
   *aadsl_smbcc_out_next = ADSL_SOC_G;      /* for chain of output commands */
#undef ADSL_SOC_G
#undef ADSL_SOCR_G
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */

   p_create_resp_80:                        /* process response to create - send next command */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_smbcc_in_c1 + 1))
   switch (ADSL_SMBCC_IN_CREATE_G->iec_sicd) {  /* command input create disposition */
     case ied_sicd_close:                   /* close immediately       */
#ifdef XYZ1
       memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#ifdef XYZ1
#ifndef B140513
       iml1 = 0;                            /* Flags                   */
#endif
#endif
       goto p_send_close;                   /* send close request      */
     case ied_sicd_delete_file:             /* delete file             */
#endif
       memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#ifdef XYZ1
#ifndef B140513
       iml1 = 1;                            /* Flags                   */
#endif
#endif
       goto p_send_close;                   /* send close request      */
#ifdef B140513
     case ied_sicd_delete:                  /* delete file / directory */
       goto p_delete_00;                    /* delete file / directory */
#endif
     case ied_sicd_delete_dir:              /* delete directory        */
       goto p_delete_00;                    /* delete directory        */
   }
   iml1 = __LINE__;
   goto p_invdat_00;                        /* invalid data in input command */
#undef ADSL_SMBCC_IN_CREATE_G

   p_in_write_00:                           /* command SMB2 write data */
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_smbcc_in_c1 + 1))
   adsl_gai1_w1 = ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data;  /* data to be written */
   iml1 = 0;                                /* clear count             */
   while (adsl_gai1_w1) {                   /* loop over data to be written */
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   if (iml1 == 0) {                         /* no data to write        */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_WRITE );  /* 0X0009 */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_WRITE_REQ_G ((struct dsd_smb2_write_request *) (ADSL_SMB2_HDR_OUT + 1))  /* SMB2 WRITE Request */
   memset( ADSL_SMB2_WRITE_REQ_G, 0, sizeof(struct dsd_smb2_write_request) );
   m_put_le2( (char *) &ADSL_SMB2_WRITE_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_write_request) + 1 );
   m_put_le2( (char *) &ADSL_SMB2_WRITE_REQ_G->usc_data_offset, sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_write_request) );  /* DataOffset */
   m_put_le4( (char *) &ADSL_SMB2_WRITE_REQ_G->umc_length, iml1 );  /* Length */
   m_put_le8( (char *) &ADSL_SMB2_WRITE_REQ_G->ulc_offset, ADSL_SMBCC_IN_WRITE_G->ulc_offset );  /* Offset */
   memcpy( ADSL_SMB2_WRITE_REQ_G->chrc_file_id, ADSL_SMBCC_IN_WRITE_G->chrc_file_id, sizeof(ADSL_SMB2_WRITE_REQ_G->chrc_file_id) );  /* FileId */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_WRITE_REQ_G;
#ifdef B150401
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_WRITE_REQ_G + 1) + iml1;
#endif
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_WRITE_REQ_G + 1);
     dsl_gai1_l.adsc_next = ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data;  /* data to be written */
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_WRITE_REQ_G + 1) + iml1) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) (ADSL_SMB2_WRITE_REQ_G + 1);
   ADSL_GAI1_SEND->adsc_next = ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data;  /* data to be written */
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_resp_write;               /* wait for response for WRITE */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_WRITE_REQ_G
#undef ADSL_SMBCC_IN_WRITE_G

   p_write_resp_00:                         /* response to SMB2 write data */
   if (adsl_scs->iec_smb_cs != ied_smb_cs_resp_write) {  /* wait for response for WRITE */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_rem -= sizeof(struct dsd_smb2_write_response);  /* remainder data received */
   if (iml_recv_rem != 0) {                 /* not equal WRITE Response */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;

   p_in_sif_00:                             /* command SMB2 set-info file */
#define ADSL_SMBCC_IN_SIF_G ((struct dsd_smbcc_in_set_info_file *) (adsl_smbcc_in_c1 + 1))
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_SET_INFO );  /* 0X0011 */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_SET_INFO_REQ_G ((struct dsd_smb2_set_info_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_SET_INFO_REQ_G, 0, sizeof(struct dsd_smb2_set_info_request) );
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_set_info_request) + 1 );
   ADSL_SMB2_SET_INFO_REQ_G->ucc_info_type  /* InfoType                */
     = HL_SMB2_0_INFO_FILE;                 /* 0X01                    */
   ADSL_SMB2_SET_INFO_REQ_G->ucc_file_info_class  /* FileInfoClass     */
     = HL_SMB2_FILE_BASIC_INFO;             /* 0X04                    */
   m_put_le4( (char *) &ADSL_SMB2_SET_INFO_REQ_G->umc_buffer_length, sizeof(struct dsd_fs_file_basic_information) );  /* OutputBufferLength */
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_buffer_offset, sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_set_info_request) );  /* InputBufferOffset */
   memcpy( ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id, ADSL_SMBCC_IN_SIF_G->chrc_file_id, sizeof(ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id) );  /* FileId */
   memcpy( ADSL_SMB2_SET_INFO_REQ_G + 1, &ADSL_SMBCC_IN_SIF_G->dsc_fs_file_basic_information, sizeof(struct dsd_fs_file_basic_information) );  /* File System FileBasicInformation */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) (ADSL_SMB2_HDR_OUT + 1);
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + sizeof(struct dsd_fs_file_basic_information);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + sizeof(struct dsd_fs_file_basic_information)) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + sizeof(struct dsd_fs_file_basic_information);
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_resp_set_info;            /* wait for response for SET_INFO */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_SET_INFO_REQ_G
#undef ADSL_SMBCC_IN_SIF_G

   p_in_rnf_00:                             /* command SMB2 rename open file */
#define ADSL_SMBCC_IN_RNF_G ((struct dsd_smbcc_in_rename_file *) (adsl_smbcc_in_c1 + 1))
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_SET_INFO );  /* 0X0011 */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_SET_INFO_REQ_G ((struct dsd_smb2_set_info_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_SET_INFO_REQ_G, 0, sizeof(struct dsd_smb2_set_info_request) );
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_set_info_request) + 1 );
   ADSL_SMB2_SET_INFO_REQ_G->ucc_info_type  /* InfoType                */
     = HL_SMB2_0_INFO_FILE;                 /* 0X01                    */
   ADSL_SMB2_SET_INFO_REQ_G->ucc_file_info_class  /* FileInfoClass     */
     = HL_SMB2_FILE_RENAME_INFO;            /* 0X0A / 10               */
   memcpy( ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id, ADSL_SMBCC_IN_RNF_G->chrc_file_id, sizeof(ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id) );  /* FileId */
#define ADSL_FS_FRI_G ((struct dsd_fs_file_rename_information_type_2 *) (ADSL_SMB2_SET_INFO_REQ_G + 1))
   memset( ADSL_FS_FRI_G, 0, sizeof(struct dsd_fs_file_rename_information_type_2) );
   ADSL_FS_FRI_G->chc_replace_if_exists = 1;  /* ReplaceIfExists       */
   iml1 = m_cpy_vx_ucs( ADSL_FS_FRI_G + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_FS_FRI_G + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_RNF_G->dsc_ucs_new_file_name );  /* new filename */
   if (iml1 < 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml1 *= sizeof(HL_WCHAR);
   m_put_le4( (char *) &ADSL_FS_FRI_G->umc_file_name_length, iml1 );  /* FileNameLength */
   m_put_le4( (char *) &ADSL_SMB2_SET_INFO_REQ_G->umc_buffer_length, sizeof(struct dsd_fs_file_rename_information_type_2) + iml1 );  /* OutputBufferLength */
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_buffer_offset, sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_set_info_request) );  /* InputBufferOffset */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_SET_INFO_REQ_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_FS_FRI_G + 1) + iml1;
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_FS_FRI_G + 1) + iml1) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) (ADSL_FS_FRI_G + 1) + iml1;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_resp_set_info;            /* wait for response for SET_INFO */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_SET_INFO_REQ_G
#undef ADSL_SMBCC_IN_RNF_G
#undef ADSL_FS_FRI_G

#ifdef B140513
   p_delete_00:                             /* delete file / directory */
#endif
   p_delete_00:                             /* delete directory        */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_SET_INFO );  /* 0X0011 */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_SET_INFO_REQ_G ((struct dsd_smb2_set_info_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_SET_INFO_REQ_G, 0, sizeof(struct dsd_smb2_set_info_request) );
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_set_info_request) + 1 );
// m_put_le2( (char *) &ADSL_SMB2_READ_REQ_DIR_G->usc_structure_size, sizeof(struct dsd_smb2_read_request) );
   ADSL_SMB2_SET_INFO_REQ_G->ucc_info_type  /* InfoType                */
     = HL_SMB2_0_INFO_FILE;                 /* 0X01                    */
   ADSL_SMB2_SET_INFO_REQ_G->ucc_file_info_class  /* FileInfoClass     */
     = HL_SMB2_FILE_DISPOSITION_INFO;       /* 0X0D                    */
   m_put_le4( (char *) &ADSL_SMB2_SET_INFO_REQ_G->umc_buffer_length, 1 );  /* OutputBufferLength */
   m_put_le2( (char *) &ADSL_SMB2_SET_INFO_REQ_G->usc_buffer_offset, sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_set_info_request) );  /* InputBufferOffset */
   memcpy( ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id, adsl_scs->chrc_file_id, sizeof(ADSL_SMB2_SET_INFO_REQ_G->chrc_file_id) );  /* FileId */
   *((char *) (ADSL_SMB2_SET_INFO_REQ_G + 1)) = 0X01;  /* delete on close */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_SET_INFO_REQ_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + 1;
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + 1) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) (ADSL_SMB2_SET_INFO_REQ_G + 1) + 1;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_resp_set_info;            /* wait for response for SET_INFO */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_SET_INFO_REQ_G

   p_resp_set_info_00:                      /* received SET_INFO response */
   if (adsl_scs->iec_smb_cs != ied_smb_cs_resp_set_info) {  /* wait for response for SET_INFO */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef XYZ1
   if (iml_recv_rem > sizeof(struct dsd_smb2_set_info_response)) {
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (iml_recv_rem < sizeof(unsigned short int)) {
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (iml_recv_rem != sizeof(struct dsd_smb2_set_info_response)) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   achl_w1 = achl_rp;                       /* pointer to set-info response header */
   if ((achl_rp + iml_recv_rem) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += iml_recv_rem;
     goto p_resp_set_info_20;               /* set-info information ready to be set */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = iml_recv_rem;                     /* response to set-info    */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + iml_recv_rem - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_resp_set_info_20:                      /* set-info information ready to be set */
#define ADSL_SMB2_SET_INFO_RESP_G ((struct dsd_smb2_set_info_response *) achl_w1)
   if (iml_recv_rem != m_get_le2( (char *) &ADSL_SMB2_SET_INFO_RESP_G->usc_structure_size )){  /* StructureSize */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#undef ADSL_SMB2_SET_INFO_RESP_G
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_smbcc_in_c1 + 1))
#ifdef B140513
   if (   (adsl_smbcc_in_c1->iec_smbcc_in == ied_smbcc_in_create)  /* command SMB2 create */
       && (ADSL_SMBCC_IN_CREATE_G->iec_sicd == ied_sicd_delete)) {  /* delete file / directory */
     memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
     goto p_send_close;                     /* send close request      */
   }
#endif
   if (   (adsl_smbcc_in_c1->iec_smbcc_in == ied_smbcc_in_create)  /* command SMB2 create */
       && (ADSL_SMBCC_IN_CREATE_G->iec_sicd == ied_sicd_delete_dir)) {  /* delete directory */
     memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#ifdef XYZ1
#ifndef B140513
     iml1 = 0;                              /* Flags                   */
#endif
#endif
     goto p_send_close;                     /* send close request      */
   }
#undef ADSL_SMBCC_IN_CREATE_G
#ifdef B140428
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_set_info_file) {  /* command SMB2 set-info file */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (   (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_set_info_file)  /* command SMB2 set-info file */
       && (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_rename_file)) {  /* command SMB2 rename open file */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */

   p_close_resp_00:                         /* process response to close */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_close_resp_00: ..->iec_smb_cs=%d.",
                 __LINE__,
                 adsl_scs->iec_smb_cs );
#endif
#ifdef B140429
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_close) {  /* wait for reply for close */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifdef B141213
   if (   (adsl_scs->iec_smb_cs != ied_smb_cs_reply_close)  /* wait for reply for close */
       && (adsl_scs->iec_smb_cs != ied_smb_cs_reply_ch_not_ao)) {  /* wait for change notify out of order */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_close) {  /* wait for reply for close */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_rem -= sizeof(struct dsd_smb2_close_response);  /* remainder data received */
   if (iml_recv_rem != 0) {                 /* not equal close response header */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if ((sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_close_info))
         > (dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)) {  /* check work area */
     bol_rc = m_acquire_work_area( &dsl_sdh_call_1 );
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_close_info);
   achl_wa = dsl_sdh_call_1.achc_upper;     /* pointer to work area    */
   achl_w1 = achl_rp;                       /* pointer to close response header */
   if ((achl_rp + sizeof(struct dsd_smb2_close_response)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(struct dsd_smb2_close_response);
     goto p_close_resp_20;                  /* directory information ready to be set */
   }
   if (sizeof(struct dsd_smb2_close_response)
         > (dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)) {  /* check work area */
     bol_rc = m_acquire_work_area( &dsl_sdh_call_1 );
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smb2_close_response);
   achl_w1 = dsl_sdh_call_1.achc_upper;     /* pointer to close response header */
   iml3 = sizeof(struct dsd_smb2_close_response);  /* close response   */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( dsl_sdh_call_1.achc_upper + sizeof(struct dsd_smb2_close_response) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_close_resp_20:                         /* directory information ready to be set */
#define ADSL_SMB2_CLOSE_RESP_G ((struct dsd_smb2_close_response *) achl_w1)
#define ADSL_SOC_G ((struct dsd_smbcc_out_cmd *) achl_wa)  /* HOBLink SMB Client Control - output command */
#define ADSL_SOCI_G ((struct dsd_smbcc_out_close_info *) (ADSL_SOC_G + 1))  /* command output close information */
   ADSL_SOCI_G->adsc_fdi = (struct dsd_smbcc_file_directory_information *) ADSL_SMB2_CLOSE_RESP_G->chrc_creation_time;  /* FileDirectoryInformation */
   ADSL_SOCI_G->umc_file_attributes = ADSL_SMB2_CLOSE_RESP_G->umc_file_attributes;  /* FileAttributes */
   *aadsl_smbcc_out_next = ADSL_SOC_G;      /* for chain of output commands */
   aadsl_smbcc_out_next = &ADSL_SOC_G->adsc_next;  /* for chaining     */
   ADSL_SOC_G->iec_smbcc_out                /* command output from SMB component */
     = ied_smbcc_out_close_info;            /* close information       */
#undef ADSL_SMB2_CLOSE_RESP_G
#undef ADSL_SOC_G
#undef ADSL_SOCI_G

   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_smbcc_in_c1 + 1))
   if (   (adsl_smbcc_in_c1->iec_smbcc_in == ied_smbcc_in_close)  /* command SMB2 close */
       || (adsl_smbcc_in_c1->iec_smbcc_in == ied_smbcc_in_del_notify)  /* command delete notify - FindCloseChangeNotification */
       || (   (adsl_smbcc_in_c1->iec_smbcc_in == ied_smbcc_in_create)  /* command SMB2 create */
           && (ADSL_SMBCC_IN_CREATE_G->iec_sicd != ied_sicd_appended))) {  /* see command appended */
     if (adsl_smbcc_in_c2) {
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
#ifdef B141027
     adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
     adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
     goto p_close_resp_40;                  /* process response to close */
   }
#undef ADSL_SMBCC_IN_CREATE_G
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
#ifdef WAS_BEFORE
   if (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_query_directory) {  /* command SMB2 query-directory */
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (adsl_smbcc_in_c2 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (    (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_query_directory)  /* command SMB2 query-directory */
       &&  (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_complete_file_read)) {  /* command read complete file */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B141027
   adsl_smbcc_in_c2->boc_processed = TRUE;     /* the command has been processed */
#endif
   adsl_smbcc_in_c2->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */

   p_close_resp_40:                         /* process response to close */
   *aadsl_smbcc_out_next = NULL;            /* for chain of output commands */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */

   p_read_req_00:                           /* read request            */
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
   if (adsl_smbcc_in_c2 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_complete_file_read) {  /* command read complete file */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_scs->ulc_offset = 0;

   p_read_req_20:                           /* send read request       */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif

   p_send_read:                             /* send read request       */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_READ );  /* 0X0008 */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_READ_REQ_DIR_G ((struct dsd_smb2_read_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_READ_REQ_DIR_G, 0, sizeof(struct dsd_smb2_read_request) );
   m_put_le2( (char *) &ADSL_SMB2_READ_REQ_DIR_G->usc_structure_size, sizeof(struct dsd_smb2_read_request) + 1 );
// m_put_le2( (char *) &ADSL_SMB2_READ_REQ_DIR_G->usc_structure_size, sizeof(struct dsd_smb2_read_request) );
   ADSL_SMB2_READ_REQ_DIR_G->chc_padding = 0X50;  /* Padding           */
   m_put_le4( (char *) &ADSL_SMB2_READ_REQ_DIR_G->umc_length, LEN_SMB_IO );  /* Length */
   m_put_le8( (char *) &ADSL_SMB2_READ_REQ_DIR_G->ulc_offset, adsl_scs->ulc_offset );
   memcpy( ADSL_SMB2_READ_REQ_DIR_G->chrc_file_id, adsl_scs->chrc_file_id, sizeof(ADSL_SMB2_READ_REQ_DIR_G->chrc_file_id) );  /* FileId */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_READ_REQ_DIR_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_READ_REQ_DIR_G + 1) + 1;
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   *((char *) (ADSL_SMB2_READ_REQ_DIR_G + 1)) = 0;  /* padding         */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_READ_REQ_DIR_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_READ_REQ_DIR_G + 1) + 1;
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_READ_REQ_DIR_G + 1) + 1) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#ifdef DEBUG_141231_01                      /* memory corrupted        */
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_send_read: DEBUG_141231_01 ..->adsc_gai1_nw_send=%p iml_recv_next=%d.",
                 __LINE__,
                 adsp_smbcl_ctrl->adsc_gai1_nw_send,
                 iml_recv_next );
#endif
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
// adsl_scs->iec_smb_cs                     /* state SMB client session */
//   = ied_smb_cs_start_05;                 /* has sent TreeConnect    */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ACHL_SMB2_READ_REQ_DIR_G

   p_read_resp_00:                          /* SMB2 READ Response      */
   if (uml_nt_status == HL_STATUS_END_OF_FILE) {
     iml2 = 0;                              /* no data processed       */
     goto p_read_resp_60;                   /* data SMB2 READ Response copied */
   }
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_rem -= sizeof(struct dsd_smb2_read_response);  /* remainder data received */
   if (iml_recv_rem < 0) {                  /* less than READ Response */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(struct dsd_smb2_read_response)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(struct dsd_smb2_read_response);
     goto p_read_resp_20;                   /* SMB2 READ Response      */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(struct dsd_smb2_read_response);  /* set count         */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(struct dsd_smb2_read_response) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_read_resp_20:                          /* SMB2 READ Response      */
#define ADSL_RR_G ((struct dsd_smb2_read_response *) achl_w1)  /* SMB2 READ Response */
// memcpy( adsl_scs->chrc_file_id, ADSL_CR_G->chrc_file_id, sizeof(adsl_scs->chrc_file_id) );  /* FileId */
   iml1 = ADSL_RR_G->ucc_data_offset;       /* DataOffset              */
   iml1 -= sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_read_response);
   if (iml1 < 0) {                          /* DataOffset too short    */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml2 = m_get_le4( (char *) &ADSL_RR_G->umc_data_length );  /* DataLength */
   if (iml_recv_rem != (iml1 + iml2)) {     /* invalid length          */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   while (iml1 > 0) {                       /* overread DataOffset     */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml1) iml4 = iml1;
     iml1 -= iml4;
     achl_rp += iml4;
   }
#undef ADSL_RR_G
#ifdef XYZ1
   if (iml2 == 0) {
     goto p_send_close;                     /* send close request      */
   }
#endif
   if (iml2 == 0) {
     goto p_read_resp_60;                   /* data SMB2 READ Response copied */
   }
   iml1 = iml2;                             /* number of bytes to copy */

   p_read_resp_40:                          /* copy SMB2 READ Response data */
   while (TRUE) {                           /* loop for input data     */
     iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
     if (iml4 > 0) break;                   /* input data found        */
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain     */
     if (adsl_gai1_rp == NULL) {            /* no more data            */
       goto p_illogic_00;                   /* program illogic         */
     }
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
   }
   if (iml4 > iml1) iml4 = iml1;            /* number of bytes in this chunk */
   if ((sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_read))
         > (dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)) {  /* check work area */
     bol_rc = m_acquire_work_area( &dsl_sdh_call_1 );
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_read);

#define ADSL_SOC_G ((struct dsd_smbcc_out_cmd *) dsl_sdh_call_1.achc_upper)  /* HOBLink SMB Client Control - output command */
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (ADSL_SOC_G + 1))

   *aadsl_smbcc_out_next = ADSL_SOC_G;      /* for chain of output commands */
   aadsl_smbcc_out_next = &ADSL_SOC_G->adsc_next;  /* for chaining     */
   ADSL_SOC_G->iec_smbcc_out                /* command output from SMB component */
     = ied_smbcc_out_read;                  /* data read               */
   ADSL_SOR_G->achc_data = achl_rp;         /* address of data         */
   ADSL_SOR_G->imc_length = iml4;           /* length of the data      */
#ifndef B140511
   achl_rp += iml4;                         /* input processed         */
#endif
   iml1 -= iml4;                            /* subtrace part of data   */
   if (iml1 > 0) {                          /* more data to pass       */
     goto p_read_resp_40;                   /* copy SMB2 READ Response data */
   }
   adsl_scs->ulc_offset += iml2;            /* increment offset        */
   *aadsl_smbcc_out_next = NULL;            /* for chain of output commands */

   p_read_resp_60:                          /* data SMB2 READ Response copied */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (iml2 == LEN_SMB_IO) {                /* full frame received     */
     goto p_send_read;                      /* send read request       */
   }
   memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#ifdef XYZ1
#ifndef B140513
   iml1 = 0;                                /* Flags                   */
#endif
#endif
   goto p_send_close;                       /* send close request      */

#undef ADSL_SOC_G
#undef ADSL_SOR_G

   p_qd_resp_00:                            /* process response to query-directory */
#ifdef B140507
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_dir) {  /* wait for reply for dir */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   if (   (adsl_scs->iec_smb_cs != ied_smb_cs_reply_dir)  /* wait for reply for dir */
       && (adsl_scs->iec_smb_cs != ied_smb_cs_reply_close)) {  /* wait for reply for close */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (uml_nt_status == 0) {
     goto p_in_dir_00;                      /* check response to dir   */
   }
   if (uml_nt_status != HL_STATUS_NO_MORE_FILES) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   memcpy( chrl_file_id, adsl_scs->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#ifdef B140507
   goto p_send_close;                       /* send close request      */
#endif
   if (adsl_scs->iec_smb_cs == ied_smb_cs_reply_dir) {  /* wait for reply for dir */
#ifdef XYZ1
#ifndef B140513
     iml1 = 0;                              /* Flags                   */
#endif
#endif
     goto p_send_close;                     /* send close request      */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;

   p_in_close_00:                           /* command SMB2 close      */
#define ADSL_SMBCC_IN_CLOSE_G ((struct dsd_smbcc_in_close *) (adsl_smbcc_in_c1 + 1))  /* command input SMB2 close */
   memcpy( chrl_file_id, ADSL_SMBCC_IN_CLOSE_G->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#undef ADSL_SMBCC_IN_CLOSE_G
#ifdef XYZ1
#ifndef B140513
   iml1 = 0;                                /* Flags                   */
#endif
#endif

   p_send_close:                            /* send close request      */
   /* send close request                                               */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_CLOSE );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_CLOSE_G ((struct dsd_smb2_close_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_CLOSE_G, 0, sizeof(struct dsd_smb2_close_request) );
   m_put_le2( (char *) &ADSL_SMB2_CLOSE_G->usc_structure_size, sizeof(struct dsd_smb2_close_request) );
#ifdef XYZ1
#ifndef B140513
   m_put_le2( (char *) &ADSL_SMB2_CLOSE_G->usc_flags, iml1 );  /* Flags */
#endif
#endif
   memcpy( ADSL_SMB2_CLOSE_G->chrc_file_id, chrl_file_id, sizeof(ADSL_SMB2_CLOSE_G->chrc_file_id) );  /* FileId */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_CLOSE_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_CLOSE_G + 1);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_CLOSE_G + 1)) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_reply_close;              /* wait for reply for close */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_CLOSE_G

   p_in_dir_00:                             /* check response to dir   */
   iml_recv_rem -= sizeof(struct dsd_smb2_query_directory_response);  /* SMB2 QUERY_DIRECTORY Response */
   if (iml_recv_rem < 0) {                  /* less than SMB2 header   */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(struct dsd_smb2_query_directory_response)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(struct dsd_smb2_query_directory_response);
     goto p_in_dir_08;                      /* SMB2 QUERY_DIRECTORY Response */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(struct dsd_smb2_query_directory_response);  /* set count */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(struct dsd_smb2_query_directory_response) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_dir_08:                             /* SMB2 QUERY_DIRECTORY Response */
#define ADSL_QDR_G ((struct dsd_smb2_query_directory_response *) achl_w1)  /* SMB2 QUERY_DIRECTORY Response */
   iml2 = m_get_le2( (char *) &ADSL_QDR_G->usc_output_buffer_offset );
   iml2 -= sizeof(struct dsd_smb2_hdr_sync) + sizeof(struct dsd_smb2_query_directory_response);  /* length headers */
   if (iml2 < 0) {                          /* less than SMB2 header   */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (iml2 >= iml_recv_rem) {              /* more than data in this block */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   /* overread padding                                                 */
   while (iml2 > 0) {                       /* loop to ignore data     */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml2) iml4 = iml2;
     iml2 -= iml4;
     achl_rp += iml4;
   }
#undef ADSL_QDR_G

   memset( &dsl_agwa_l, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_agwa_l,  /* acquire additional work area */
                                    sizeof(struct dsd_aux_get_workarea) );
   dsl_sdh_call_1.achc_lower = dsl_agwa_l.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_agwa_l.achc_work_area + dsl_agwa_l.imc_len_work_area;

   p_in_dir_20:                             /* process one directory entry */
   if (iml_recv_rem <= sizeof(struct dsd_fs_file_directory_information)) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(unsigned int)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(unsigned int);
     goto p_in_dir_24;                      /* field NextEntryOffset in contiguous memory */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(unsigned int);             /* set count               */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(unsigned int) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_dir_24:                             /* field NextEntryOffset in contiguous memory */
   iml2 = m_get_le4( achl_w1 );
   if (iml2 != 0) {                         /* NextEntryOffset - pointer to next structure */
     if (iml2 >= iml_recv_rem) {            /* NextEntryOffset too big */
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
   }

   /* ignore FileIndex                                                 */
   iml3 = sizeof(unsigned int);
   do {                                     /* loop to ignore data     */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_dir);
   achl_wa = dsl_sdh_call_1.achc_upper;     /* pointer to work area    */
#define ADSL_SOD_G ((struct dsd_smbcc_out_dir *) (achl_wa + sizeof(struct dsd_smbcc_out_cmd)))  /* command output SMB2 query-directory */
   ADSL_SOD_G->adsc_fdi = (struct dsd_smbcc_file_directory_information *) achl_rp;  /* FileDirectoryInformation */
   if ((achl_rp + sizeof(struct dsd_smbcc_file_directory_information)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(struct dsd_smbcc_file_directory_information);
     goto p_in_dir_28;                      /* directory information processed */
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_file_directory_information);
   ADSL_SOD_G->adsc_fdi = (struct dsd_smbcc_file_directory_information *) dsl_sdh_call_1.achc_upper;  /* FileDirectoryInformation */
   iml3 = sizeof(struct dsd_smbcc_file_directory_information);  /* FileDirectoryInformation */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( dsl_sdh_call_1.achc_upper + sizeof(struct dsd_smbcc_file_directory_information) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_dir_28:                             /* directory information processed */
   /* get FileAttributes                                               */
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(unsigned int)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(unsigned int);
     goto p_in_dir_32;                      /* FileAttributes          */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(unsigned int);             /* set count               */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(unsigned int) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_dir_32:                             /* FileAttributes          */
   ADSL_SOD_G->umc_file_attributes = m_get_le4( achl_w1 );  /* FileAttributes */

   /* FileNameLength                                                   */
   achl_w1 = achl_rp;                       /* current position        */
   if ((achl_rp + sizeof(unsigned int)) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += sizeof(unsigned int);
     goto p_in_dir_36;                      /* FileNameLength          */
   }
   achl_w1 = byrl_work_01;                  /* copy variable to here   */
   iml3 = sizeof(unsigned int);             /* set count               */
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( byrl_work_01 + sizeof(unsigned int) - iml3, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
   } while (iml3 > 0);

   p_in_dir_36:                             /* FileNameLength          */
   iml3 = m_get_le4( achl_w1 );             /* FileNameLength          */
   if (iml3 & 1) {                          /* not length WCHAR        */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_rem -= sizeof(struct dsd_fs_file_directory_information) + iml3;  /* remainder data received */
   if (iml_recv_rem < 0) {                  /* more than received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   bol_more = FALSE;                        /* no more data            */
   if (iml2 != 0) {                         /* NextEntryOffset - pointer to next structure */
     iml2 -= sizeof(struct dsd_fs_file_directory_information) + iml3;
     if (iml2 < 0) {                        /* NextEntryOffset too small */
       iml1 = __LINE__;
       goto p_invdat_00;                    /* invalid data received   */
     }
     bol_more = TRUE;                       /* more data to follow     */
   }
   ADSL_SOD_G->dsc_ucs_file_name.imc_len_str = iml3 >> 1;
   ADSL_SOD_G->dsc_ucs_file_name.iec_chs_str = ied_chs_le_utf_16;  /* Unicode UTF-16 little endian */
   ADSL_SOD_G->dsc_ucs_file_name.ac_str = achl_rp;
   if ((achl_rp + iml3) <= adsl_gai1_rp->achc_ginp_end) {
     achl_rp += iml3;
     goto p_in_dir_40;                      /* FileName processed      */
   }
   ADSL_SOD_G->dsc_ucs_file_name.ac_str = achl_w1 = dsl_sdh_call_1.achc_lower;
   dsl_sdh_call_1.achc_lower += iml3;
   do {                                     /* loop to copy field      */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml3) iml4 = iml3;
     memcpy( achl_w1, achl_rp, iml4 );
     iml3 -= iml4;
     achl_rp += iml4;
     achl_w1 += iml4;
   } while (iml3 > 0);

   p_in_dir_40:                             /* FileName processed      */
   iml_recv_rem -= iml2;                    /* remainder data received */
   /* overread padding                                                 */
   while (iml2 > 0) {                       /* loop to ignore data     */
     while (TRUE) {                         /* loop for input data     */
       iml4 = adsl_gai1_rp->achc_ginp_end - achl_rp;
       if (iml4 > 0) break;                 /* input data found        */
       adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next in chain   */
       if (adsl_gai1_rp == NULL) {          /* no more data            */
         goto p_illogic_00;                 /* program illogic         */
       }
       achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* start of data this gather */
     }
     if (iml4 > iml2) iml4 = iml2;
     iml2 -= iml4;
     achl_rp += iml4;
   }
#define ADSL_SOC_G ((struct dsd_smbcc_out_cmd *) achl_wa)  /* HOBLink SMB Client Control - output command */
   *aadsl_smbcc_out_next = ADSL_SOC_G;      /* for chain of output commands */
   aadsl_smbcc_out_next = &ADSL_SOC_G->adsc_next;  /* for chaining     */
   ADSL_SOC_G->iec_smbcc_out                /* command output from SMB component */
     = ied_smbcc_out_dir;                   /* directory information   */
   if (bol_more) {                          /* more data to follow     */
     goto p_in_dir_20;                      /* process one directory entry */
   }
#ifdef XYZ1
   if (iml_recv_rem > 0) {
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   *aadsl_smbcc_out_next = NULL;            /* for chain of output commands */
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#undef ADSL_SOD_G
#undef ADSL_SOC_G

   /* send request to send more                                        */
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
   if (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_query_directory) {  /* command SMB2 query-directory */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#define ADSL_SMBCC_IN_QD_G ((struct dsd_smbcc_in_query_directory *) (adsl_smbcc_in_c2 + 1))
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_QUERY_DIRECTORY );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_QUERY_DIR_G ((struct dsd_smb2_query_directory_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_QUERY_DIR_G, 0, sizeof(struct dsd_smb2_query_directory_request) );
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_structure_size, sizeof(struct dsd_smb2_query_directory_request) + 1 );
   ADSL_SMB2_QUERY_DIR_G->chc_file_information_class = HL_SMB2_QD_FILE_DIRECTORY_INFORMATION;  /* FileInformationClass */
// ADSL_SMB2_QUERY_DIR_G->chc_file_information_class = HL_SMB2_QD_FILE_ID_BOTH_DIRECTORY_INFORMATION;  /* FileIdBothDirectoryInformation */
// memset( ADSL_SMB2_QUERY_DIR_G->chrc_file_index, 0XFF, sizeof(ADSL_SMB2_QUERY_DIR_G->chrc_file_index) );  /* FileIndex */
   memcpy( ADSL_SMB2_QUERY_DIR_G->chrc_file_id, adsl_scs->chrc_file_id, sizeof(ADSL_SMB2_QUERY_DIR_G->chrc_file_id) );  /* FileId */
#ifdef B140519
   iml1 = m_cpy_vx_ucs( ADSL_SMB2_QUERY_DIR_G + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_SMBCC_IN_QD_G + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern );
#endif
   iml1 = m_cpy_vx_ucs( ADSL_SMB2_QUERY_DIR_G + 1,
                        (dsl_agsb_l.achc_send_buffer + dsl_agsb_l.imc_len_send_buffer) - ((char *) (ADSL_SMB2_QUERY_DIR_G + 1)),
                        ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern );
   if (iml1 < 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_file_name_offset, ((char *) (ADSL_SMB2_QUERY_DIR_G + 1)) - ((char *) ADSL_SMB2_HDR_OUT) );  /* FileNameOffset */
   m_put_le2( (char *) &ADSL_SMB2_QUERY_DIR_G->usc_file_name_length, iml1 * sizeof(HL_WCHAR) );  /* FileNameLength */
// m_put_le4( (char *) &ADSL_SMB2_QUERY_DIR_G->umc_output_buffer_length, 0X00010000 );  /* OutputBufferLength */
   m_put_le4( (char *) &ADSL_SMB2_QUERY_DIR_G->umc_output_buffer_length, 0X00001000 );  /* OutputBufferLength */
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_QUERY_DIR_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_QUERY_DIR_G + 1) + iml1 * sizeof(HL_WCHAR);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = (char *) (ADSL_SMB2_QUERY_DIR_G + 1) + iml1 * sizeof(HL_WCHAR)
            - (char *) ADSL_SMB2_HDR_OUT;
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;
#undef ADSL_SMBCC_IN_QD_G
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_QUERY_DIR_G

   p_send_set_ntfy_00:                      /* send CHANGE_NOTIFY      */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_send_set_ntfy_00: adsl_scs->adsc_sce_ch=%p.",
                 __LINE__, adsl_scs->adsc_sce_ch );
#endif
#ifdef B131228
#define ADSL_SMBCC_IN_SN_G ((struct dsd_smbcc_in_set_ntfy *) (adsl_smbcc_in_c1 + 1))
#endif
#define ADSL_SMBCC_IN_SN_G ((struct dsd_smbcc_in_set_ntfy *) (adsl_smbcc_in_c2 + 1))
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_MEMGET,  /* get a block of memory */
                                    &adsl_sce_w1,
                                    sizeof(struct dsd_smb_cl_extra)  /* SMB client extra data */
                                      + sizeof(struct dsd_smb_ce_ntfy) );  /* extra data CHANGE_NOTIFY */
   memset( adsl_sce_w1, 0, sizeof(struct dsd_smb_cl_extra) + sizeof(struct dsd_smb_ce_ntfy) );
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
   adsl_sce_w1->iec_smb_cet = ied_smb_cet_change_ntfy;  /* CHANGE_NOTIFY */
   ADSL_CEN_G->vpc_userfld = ADSL_SMBCC_IN_SN_G->vpc_userfld;
#define ADSL_CR_G ((struct dsd_smb2_create_response *) achl_w1)  /* SMB2 CREATE Response */
   memcpy( ADSL_CEN_G->chrc_file_id, ADSL_CR_G->chrc_file_id, sizeof(ADSL_CEN_G->chrc_file_id) );  /* FileId */
#undef ADSL_CR_G
   ADSL_CEN_G->usc_flags = ADSL_SMBCC_IN_SN_G->usc_flags;  /* Flags    */
   ADSL_CEN_G->umc_completion_filter = ADSL_SMBCC_IN_SN_G->umc_completion_filter;  /* CompletionFilter */
   adsl_sce_w1->adsc_next = adsl_scs->adsc_sce_ch;  /* get old chain SMB client extra data */
   adsl_scs->adsc_sce_ch = adsl_sce_w1;     /* set new chain SMB client extra data */
#undef ADSL_SMBCC_IN_SN_G

   p_send_set_ntfy_20:                      /* send CHANGE_NOTIFY request */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_CHANGE_NOTIFY );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   memcpy( &ADSL_CEN_G->ulc_command_sequence_number,
           &adsl_scs->ulc_command_sequence_number,
           sizeof(ADSL_CEN_G->ulc_command_sequence_number) );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_CH_NTFY_REQ_G ((struct dsd_smb2_change_notify_request *) (ADSL_SMB2_HDR_OUT + 1))
   memset( ADSL_SMB2_CH_NTFY_REQ_G, 0, sizeof(struct dsd_smb2_change_notify_request) );
   m_put_le2( (char *) &ADSL_SMB2_CH_NTFY_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_change_notify_request) );
   m_put_le2( (char *) &ADSL_SMB2_CH_NTFY_REQ_G->usc_flags, ADSL_CEN_G->usc_flags );
   m_put_le4( (char *) &ADSL_SMB2_CH_NTFY_REQ_G->umc_output_buffer_length, LEN_SMB_CHANGE_NOTIFY );  /* OutputBufferLength */
   m_put_le4( (char *) &ADSL_SMB2_CH_NTFY_REQ_G->umc_completion_filter, ADSL_CEN_G->umc_completion_filter );
#ifdef B140114
   memcpy( ADSL_SMB2_CH_NTFY_REQ_G->chrc_file_id, adsl_scs->chrc_file_id, sizeof(ADSL_SMB2_CH_NTFY_REQ_G->chrc_file_id) );  /* FileId */
#endif
   memcpy( ADSL_SMB2_CH_NTFY_REQ_G->chrc_file_id, ADSL_CEN_G->chrc_file_id, sizeof(ADSL_SMB2_CH_NTFY_REQ_G->chrc_file_id) );  /* FileId */
#undef ADSL_CEN_G
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_CH_NTFY_REQ_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_CH_NTFY_REQ_G + 1);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_CH_NTFY_REQ_G + 1)) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
   *aadsl_smbcc_out_next = NULL;            /* clear and of chain of output commands */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_CH_NTFY_REQ_G

   p_set_ntfy_resp_00:                      /* received CHANGE_NOTIFY response */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: adsl_scs->adsc_sce_ch=%p.",
                 __LINE__, adsl_scs->adsc_sce_ch );
#endif
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
   adsl_sce_w1 = adsl_scs->adsc_sce_ch;     /* get chain SMB client extra data */
   adsl_sce_last = NULL;                    /* SMB client extra data   */
   while (adsl_sce_w1) {                    /* loop over extra data    */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: adsl_sce_w1=%p ...->iec_smb_cet=%d.",
                   __LINE__, adsl_sce_w1, adsl_sce_w1->iec_smb_cet );
#endif
     if (   (adsl_sce_w1->iec_smb_cet == ied_smb_cet_change_ntfy)  /* CHANGE_NOTIFY */
         && (!memcmp( &ADSL_CEN_G->ulc_command_sequence_number,
                      &adsl_smb2_hdr_l->ulc_command_sequence_number,
                      sizeof(ADSL_CEN_G->ulc_command_sequence_number) ))) {
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: found adsl_sce_w1=%p ADSL_CEN_G->iec_smb_cen=%d.",
                     __LINE__, adsl_sce_w1, ADSL_CEN_G->iec_smb_cen );
#endif
       break;
     }
     adsl_sce_last = adsl_sce_w1;           /* SMB client extra data   */
     adsl_sce_w1 = adsl_sce_w1->adsc_next;  /* get next in chain       */
   }
   if (adsl_sce_w1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: uml_nt_status=0X%08X.",
                 __LINE__, uml_nt_status );
#endif
   if (   (uml_nt_status == 0)
//#ifdef B141029
       || (uml_nt_status == HL_STATUS_PENDING)
//#endif
       || (uml_nt_status == HL_STATUS_STATUS_CANCELLED)
       || (uml_nt_status == HL_STATUS_NOTIFY_ENUM_DIR)) {
     goto p_set_ntfy_resp_08;               /* received CHANGE_NOTIFY response status normal */
   }
   if (uml_nt_status != HL_STATUS_NOTIFY_CLEANUP) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: remove adsl_sce_w1=%p.",
                 __LINE__, adsl_sce_w1 );
#endif
   if (adsl_sce_last == NULL) {             /* SMB client extra data   */
     adsl_scs->adsc_sce_ch = adsl_sce_w1->adsc_next;  /* remove from chain SMB client extra data */
   } else {                                 /* middle in chain         */
     adsl_sce_last->adsc_next = adsl_sce_w1->adsc_next;  /* remove from chain */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_MEMFREE,  /* release a block of memory */
                                    &adsl_sce_w1,
                                    0 );
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */

   p_set_ntfy_resp_08:                      /* received CHANGE_NOTIFY response status normal */
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1 == NULL) {
     goto p_set_ntfy_resp_20;               /* received CHANGE_NOTIFY out of order */
   }
   if (adsl_smbcc_in_c1->iec_smbcc_in != ied_smbcc_in_create) {  /* command SMB2 create */
     goto p_set_ntfy_resp_20;               /* received CHANGE_NOTIFY out of order */
   }
   adsl_smbcc_in_c2 = adsl_smbcc_in_c1->adsc_next;
   if (   (adsl_smbcc_in_c2 == NULL)
       || (adsl_smbcc_in_c2->iec_smbcc_in != ied_smbcc_in_set_notify)) {  /* command set notify - FindFirstChangeNotification */
     goto p_set_ntfy_resp_20;               /* received CHANGE_NOTIFY out of order */
   }
#define ADSL_SMBCC_IN_SN_G ((struct dsd_smbcc_in_set_ntfy *) (adsl_smbcc_in_c2 + 1))
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d ADSL_CEN_G->vpc_userfld=%p ADSL_SMBCC_IN_SN_G->vpc_userfld=%p.",
                 __LINE__, ADSL_CEN_G->vpc_userfld, ADSL_SMBCC_IN_SN_G->vpc_userfld );
#endif
   if (ADSL_CEN_G->vpc_userfld != ADSL_SMBCC_IN_SN_G->vpc_userfld) {
     goto p_set_ntfy_resp_20;               /* received CHANGE_NOTIFY out of order */
   }
   if (uml_nt_status != HL_STATUS_PENDING) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   ADSL_CEN_G->iec_smb_cen                  /* extra data CHANGE_NOTIFY state */
     = ied_smb_cen_active;                  /* CHANGE NOTIFY active    */
#define ADSL_SMB2_HDR_G ((dsd_smb2_hdr_async *) adsl_smb2_hdr_l)  /* SMB2 header ASYNC */
   memcpy( &ADSL_CEN_G->ulc_async_id,       /* AsyncId                 */
           &ADSL_SMB2_HDR_G->ulc_async_id,
           sizeof(ADSL_CEN_G->ulc_async_id) );
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
   adsl_smbcc_in_c2->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_smbcc_in_c2->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_00: command processed",
                 __LINE__ );
#endif
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;                                  /* all done                */
#undef ADSL_CEN_G
#undef ADSL_SMBCC_IN_SN_G
#undef ADSL_SMB2_HDR_G

   p_set_ntfy_resp_20:                      /* received CHANGE_NOTIFY out of order */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_set_ntfy_resp_20: received out of order ->iec_smb_cs=%d ->boc_smb_cs_reply_ch_not_ao=%d uml_nt_status=0X%08X.",
                 __LINE__, adsl_scs->iec_smb_cs, adsl_scs->boc_smb_cs_reply_ch_not_ao, uml_nt_status );
#endif
#ifdef B140204
// to-do 15.01.14 KB
   if (uml_nt_status == 0) {
     goto p_set_ntfy_resp_40;               /* received CHANGE_NOTIFY status NULL */
   }
#endif
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
   if (uml_nt_status == 0) {
     if (ADSL_CEN_G->iec_smb_cen == ied_smb_cen_cancelled) {  /* CHANGE NOTIFY cancelled */
       goto p_in_del_ch_ntfy_40;            /* command SMB2 cancel - response received */
     }
     if (ADSL_CEN_G->iec_smb_cen == ied_smb_cen_active) {  /* CHANGE NOTIFY active */
       goto p_set_ntfy_resp_40;             /* received CHANGE_NOTIFY status something changed */
     }
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#undef ADSL_CEN_G
   if (uml_nt_status == HL_STATUS_NOTIFY_ENUM_DIR) {
     goto p_set_ntfy_resp_40;               /* received CHANGE_NOTIFY status something changed */
   }
   if (uml_nt_status == HL_STATUS_STATUS_CANCELLED) {
     goto p_in_del_ch_ntfy_40;              /* command SMB2 cancel - response received */
   }
   if (uml_nt_status != HL_STATUS_PENDING) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#ifdef B140507
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_ch_not_ao) {  /* wait for change notify out of order */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
#define ADSL_SMB2_HDR_G ((dsd_smb2_hdr_async *) adsl_smb2_hdr_l)  /* SMB2 header ASYNC */
   memcpy( &ADSL_CEN_G->ulc_async_id,       /* AsyncId                 */
           &ADSL_SMB2_HDR_G->ulc_async_id,
           sizeof(ADSL_CEN_G->ulc_async_id) );
#undef ADSL_CEN_G
#undef ADSL_SMB2_HDR_G
#ifdef B141213
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
#endif
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B141213
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
   if (adsl_smbcc_in_c1) {                  /* found input command     */
     goto p_in_cmd_20;                      /* we have new command     */
   }
#endif
// to-do 13.12.14 KB - should we first check if more input data - could be incomplete ???
   if (adsl_scs->iec_smb_cs == ied_smb_cs_wait) {  /* wait for next command */
     adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
     if (adsl_smbcc_in_c1) {                /* found input command     */
       goto p_in_cmd_20;                    /* we have new command     */
     }
   }
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;

   p_set_ntfy_resp_40:                      /* received CHANGE_NOTIFY status NULL */
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
#ifdef B140204
// to-do 15.01.14 KB
   if (ADSL_CEN_G->iec_smb_cen != ied_smb_cen_active) {  /* CHANGE NOTIFY active */
     goto p_in_del_ch_ntfy_40;              /* command SMB2 cancel - response received */
   }
#endif
   if ((sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_change_notify))
         > (dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)) {  /* check work area */
     bol_rc = m_acquire_work_area( &dsl_sdh_call_1 );
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_smbcc_out_cmd) + sizeof(struct dsd_smbcc_out_change_notify);

#define ADSL_SOC_G ((struct dsd_smbcc_out_cmd *) dsl_sdh_call_1.achc_upper)  /* HOBLink SMB Client Control - output command */
#define ADSL_SOCN_G ((struct dsd_smbcc_out_change_notify *) (ADSL_SOC_G + 1))

   ADSL_SOCN_G->vpc_userfld = ADSL_CEN_G->vpc_userfld;

   ADSL_SOC_G->adsc_next = NULL;            /* clear chain             */
   ADSL_SOC_G->iec_smbcc_out                /* command output from SMB component */
     = ied_smbcc_out_change_notify;         /* change notify received  */

   *aadsl_smbcc_out_next = ADSL_SOC_G;      /* for chain of output commands */
   aadsl_smbcc_out_next = &ADSL_SOC_G->adsc_next;  /* for chaining     */

#undef ADSL_SOC_G
#undef ADSL_SOCN_G
#undef ADSL_CEN_G

#ifdef B140114
   iml1 = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml1 < 0) {                          /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifdef B141213
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_reply_ch_not_ao;          /* wait for change notify out of order */
#endif
   adsl_scs->boc_smb_cs_reply_ch_not_ao = TRUE;  /* wait for change notify out of order */
   goto p_send_set_ntfy_20;                 /* send CHANGE_NOTIFY request */

   p_in_del_ch_ntfy_00:                     /* command SMB2 cancel     */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_in_del_ch_ntfy_00: SMB2 CANCEL",
                 __LINE__ );
#endif
#define ADSL_SMBCC_IN_DN_G ((struct dsd_smbcc_in_del_ntfy *) (adsl_smbcc_in_c1 + 1))
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
   adsl_sce_w1 = adsl_scs->adsc_sce_ch;     /* get chain SMB client extra data */
   adsl_sce_last = NULL;                    /* SMB client extra data   */
   while (adsl_sce_w1) {                    /* loop over extra data    */
     if (   (adsl_sce_w1->iec_smb_cet == ied_smb_cet_change_ntfy)  /* CHANGE_NOTIFY */
         && (ADSL_CEN_G->vpc_userfld == ADSL_SMBCC_IN_DN_G->vpc_userfld)) {
       break;
     }
     adsl_sce_last = adsl_sce_w1;           /* SMB client extra data   */
     adsl_sce_w1 = adsl_sce_w1->adsc_next;  /* get next in chain       */
   }
#undef ADSL_SMBCC_IN_DN_G
   if (adsl_sce_w1 == NULL) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   ADSL_CEN_G->iec_smb_cen                  /* extra data CHANGE_NOTIFY state */
     = ied_smb_cen_cancelled;               /* CHANGE NOTIFY cancelled */
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_in_del_ch_ntfy_00: extra-data found",
                 __LINE__ );
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_async *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_structure_size, sizeof(struct dsd_smb2_hdr_async) );
// m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_CANCEL );  /* 0X000C */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_ASYNC_COMMAND );  /* 0X02 */
   memcpy( &ADSL_SMB2_HDR_OUT->ulc_async_id,  /* AsyncId               */
           &ADSL_CEN_G->ulc_async_id,
           sizeof(ADSL_SMB2_HDR_OUT->ulc_async_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_CANCEL_REQ_G ((struct dsd_smb2_cancel_request *) (ADSL_SMB2_HDR_OUT + 1))  /* SMB2 CANCEL Request */
   memset( ADSL_SMB2_CANCEL_REQ_G, 0, sizeof(struct dsd_smb2_cancel_request) );
   m_put_le2( (char *) &ADSL_SMB2_CANCEL_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_cancel_request) );
#undef ADSL_CEN_G
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED | HL_SMB2_FLAGS_ASYNC_COMMAND );  /* 0X02 */
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_CANCEL_REQ_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_CANCEL_REQ_G + 1);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, (struct dsd_smb2_hdr_sync *) ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_CANCEL_REQ_G + 1)) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   memset( ADSL_GAI1_SEND, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) ACHL_SEND_BUF + LEN_SMB_BL_LEN + iml2;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_reply_cancel;             /* wait for reply for cancel */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT

   p_in_del_ch_ntfy_40:                     /* command SMB2 cancel - response received */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_in_del_ch_ntfy_40: adsl_sce_w1=%p.",
                 __LINE__, adsl_sce_w1 );
#endif
#define ADSL_CEN_G ((struct dsd_smb_ce_ntfy *) (adsl_sce_w1 + 1))  /* extra data CHANGE_NOTIFY */
   if (ADSL_CEN_G->iec_smb_cen != ied_smb_cen_cancelled) {  /* CHANGE NOTIFY cancelled */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   memcpy( chrl_file_id, ADSL_CEN_G->chrc_file_id, sizeof(chrl_file_id) );  /* FileId */
#undef ADSL_CEN_G
#ifdef B140114
   if (adsl_sce_last == NULL) {             /* SMB client extra data   */
     adsl_scs->adsc_sce_ch = adsl_sce_w1->adsc_next;  /* remove from chain SMB client extra data */
   } else {                                 /* middle in chain         */
     adsl_sce_last->adsc_next = adsl_sce_w1->adsc_next;  /* remove from chain */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_MEMFREE,  /* release a block of memory */
                                    &adsl_sce_w1,
                                    0 );
#endif
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
#ifdef B140429
   if (iml1 > 0) {                          /* more data received      */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
#endif
#ifdef XYZ1
#ifndef B140513
   iml1 = 0;                                /* Flags                   */
#endif
#endif
   goto p_send_close;                       /* send close request      */

//-------
   p_in_echo_00:                            /* command SMB2 echo - keep-alive */
   memset( &dsl_agsb_l, 0, sizeof(struct dsd_aux_get_send_buffer) );  /* acquire send buffer */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_GET_SEND_BUFFER,
                                    &dsl_agsb_l,  /* acquire send buffer */
                                    sizeof(struct dsd_aux_get_send_buffer) );
#define ACHL_SEND_BUF (dsl_agsb_l.achc_send_buffer + sizeof(struct dsd_gather_i_1) + sizeof(void *) - LEN_SMB_BL_LEN)
#define ADSL_SMB2_HDR_OUT ((struct dsd_smb2_hdr_sync *) (ACHL_SEND_BUF + LEN_SMB_BL_LEN))
   memset( ADSL_SMB2_HDR_OUT, 0, sizeof(struct dsd_smb2_hdr_sync) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_eye_catcher, byrs_smb2_eyecatcher, sizeof(ADSL_SMB2_HDR_OUT->chrc_eye_catcher) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_header_length, sizeof(struct dsd_smb2_hdr_sync) );
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credit_charge, 1 );
//   unsigned int umc_nt_status;
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_command, HL_SMB2_ECHO );  /* 0X000D */
   m_put_le2( (char *) &ADSL_SMB2_HDR_OUT->usc_credits_granted, 1 );
// unsigned int umc_flags;
// unsigned int umc_chain_offset;
   adsl_scs->ulc_command_sequence_number++;
   m_put_le8( (char *) &ADSL_SMB2_HDR_OUT->ulc_command_sequence_number, adsl_scs->ulc_command_sequence_number );
   m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_process_id, 0X0000FEFF );
// unsigned int umc_tree_id;
   memcpy( &ADSL_SMB2_HDR_OUT->umc_tree_id, adsl_scs->chrc_tree_id, sizeof(ADSL_SMB2_HDR_OUT->umc_tree_id) );
   memcpy( ADSL_SMB2_HDR_OUT->chrc_session_id, adsl_scs->chrc_session_id, sizeof(ADSL_SMB2_HDR_OUT->chrc_session_id) );
#define ADSL_SMB2_ECHO_REQ_G ((struct dsd_smb2_echo_request *) (ADSL_SMB2_HDR_OUT + 1))  /* SMB2 ECHO Request */
   memset( ADSL_SMB2_ECHO_REQ_G, 0, sizeof(struct dsd_smb2_echo_request) );
   m_put_le2( (char *) &ADSL_SMB2_ECHO_REQ_G->usc_structure_size, sizeof(struct dsd_smb2_echo_request) );
   if (adsl_scs->boc_signed) {              /* SMB2 packets need to be signed */
     m_put_le4( (char *) &ADSL_SMB2_HDR_OUT->umc_flags, HL_SMB2_FLAGS_SIGNED );
     dsl_gai1_l.achc_ginp_cur = (char *) ADSL_SMB2_ECHO_REQ_G;
     dsl_gai1_l.achc_ginp_end = (char *) (ADSL_SMB2_ECHO_REQ_G + 1);
     dsl_gai1_l.adsc_next = NULL;
     m_fill_smb_signature( adsl_scs, ADSL_SMB2_HDR_OUT, &dsl_gai1_l );
   }
   iml2 = ((char *) (ADSL_SMB2_ECHO_REQ_G + 1)) - ((char *) ADSL_SMB2_HDR_OUT);
   *(ACHL_SEND_BUF + 0) = (unsigned char) (iml2 >> 24);
   *(ACHL_SEND_BUF + 1) = (unsigned char) (iml2 >> 16);
   *(ACHL_SEND_BUF + 2) = (unsigned char) (iml2 >> 8);
   *(ACHL_SEND_BUF + 3) = (unsigned char) iml2;
#define ADSL_GAI1_SEND ((struct dsd_gather_i_1 *) dsl_agsb_l.achc_send_buffer)
   ADSL_GAI1_SEND->achc_ginp_cur = (char *) ACHL_SEND_BUF;
   ADSL_GAI1_SEND->achc_ginp_end = (char *) (ADSL_SMB2_ECHO_REQ_G + 1);
   ADSL_GAI1_SEND->adsc_next = NULL;
   adsp_smbcl_ctrl->adsc_gai1_nw_send = ADSL_GAI1_SEND;  /* send over network */
#undef ADSL_GAI1_SEND
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_reply_echo;               /* wait for reply for echo */
   return;
#undef ACHL_SEND_BUF
#undef ADSL_SMB2_HDR_OUT
#undef ADSL_SMB2_ECHO_REQ_G

   p_echo_resp_00:                          /* response to SMB2 echo   */
   if (adsl_scs->iec_smb_cs != ied_smb_cs_reply_echo) {  /* wait for reply for echo */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   if (uml_nt_status != 0) {
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_rem -= sizeof(struct dsd_smb2_echo_response);  /* remainder data received */
   if (iml_recv_rem != 0) {                 /* not equal WRITE Response */
     iml1 = __LINE__;
     goto p_invdat_00;                      /* invalid data received   */
   }
   iml_recv_next = m_consume_input( adsp_smbcl_ctrl->adsc_gai1_nw_recv, LEN_SMB_BL_LEN + iml_recv_len );
   if (iml_recv_next < 0) {                 /* not enough data         */
     goto p_illogic_00;                     /* program illogic         */
   }
   adsl_smbcc_in_c1 = adsp_smbcl_ctrl->adsc_smbcc_in_ch;  /* chain of input commands */
#ifdef B141027
   adsl_smbcc_in_c1->boc_processed = TRUE;  /* the command has been processed */
#endif
   adsl_smbcc_in_c1->iec_smbcc_in_r = ied_smbcc_in_r_ok;  /* command processed without error */
   adsl_scs->iec_smb_cs                     /* state SMB client session */
     = ied_smb_cs_wait;                     /* wait for next command   */
   if (iml_recv_next > 0) {                 /* more data received      */
     goto p_in_recv_04;                     /* read SMB block          */
   }
   return;
//-------

   p_invdat_00:                             /* invalid data received   */
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_invdat_00: line=%05d.",
                 __LINE__, iml1 );
   goto p_abend_00;                         /* abend of connection     */

   p_illogic_00:                            /* program illogic         */
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_illogic_00:",
                 __LINE__ );

   p_abend_00:                              /* abend of connection     */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d p_abend_00: adsl_scs->vpc_krb5_handle=%p adsl_scs->adsc_sce_ch=%p.",
                 __LINE__, adsl_scs->vpc_krb5_handle, adsl_scs->adsc_sce_ch );
#endif
   if (adsl_scs->vpc_krb5_handle == NULL) {  /* Kerberos handle        */
     goto p_abend_20;                       /* continue abend of connection */
   }
   memset( &dsl_akstr1, 0, sizeof(struct dsd_aux_krb5_se_ti_rel_1) );  /* Kerberos release Service Ticket Resources */
   dsl_akstr1.vpc_handle = adsl_scs->vpc_krb5_handle;
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                    DEF_AUX_KRB5_SE_TI_REL,  /* Kerberos release Service Ticket Resources */
                                    &dsl_akstr1,
                                    sizeof(struct dsd_aux_krb5_se_ti_rel_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_KRB5_SE_TI_REL returned FALSE",
                   __LINE__ );
   }

   p_abend_20:                              /* continue abend of connection */
   while (adsl_scs->adsc_sce_ch) {          /* check chain SMB client extra data */
     adsl_sce_w1 = adsl_scs->adsc_sce_ch;   /* get chain SMB client extra data */
     adsl_scs->adsc_sce_ch = adsl_sce_w1->adsc_next;  /* remove from chain SMB client extra data */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,  /* User Field Subroutine */
                                      DEF_AUX_MEMFREE,  /* release a block of memory */
                                      &adsl_sce_w1,
                                      0 );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_sdh_printf( &dsl_sdh_call_1, "m_smb_cl_call() l%05d DEF_AUX_MEMFREE returned FALSE",
                     __LINE__ );
     }
   }

   adsp_smbcl_ctrl->imc_ret_error = iml_ret_error;  /* return error    */
   return;
} /* end m_smb_cl_call()                                               */

/** scan first part of received SMB header, the length field           */
static int m_scan_smb_header( struct dsd_gather_i_1 *adsp_gai1_in, struct dsd_gather_i_1 **aadsp_gai1_out, char **aachp_out ) {
   int        iml1;                         /* working variable        */
   int        iml_recv_len;                 /* length to be returned   */
   char       *achl_rp;                     /* read pointer input      */
   struct dsd_gather_i_1 *adsl_gai1_rp;     /* gather read pointer     */

   iml1 = LEN_SMB_BL_LEN;                   /* length of SMB block length */
   adsl_gai1_rp = adsp_gai1_in;             /* get gather input        */
   iml_recv_len = 0;                        /* for compiler only       */
   while (adsl_gai1_rp) {                   /* enough input            */
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* get start of gather    */
     while (achl_rp < adsl_gai1_rp->achc_ginp_end) {  /* bytes to get scanned */
       iml_recv_len <<= 8;                  /* length to be returned   */
       iml_recv_len |= *((unsigned char *) achl_rp);  /* length to be returned */
       iml1--;                              /* length of SMB block length */
       achl_rp++;                           /* increment input         */
       if (iml1 == 0) {                     /* complete length scanned */
         goto p_scan_20;                    /* check if SMB packet complete */
       }
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next gather in chain */
   }
   return -1;

   p_scan_20:                               /* check if SMB packet complete */
   *aadsp_gai1_out = adsl_gai1_rp;
   *aachp_out = achl_rp;
   iml1 = iml_recv_len;                     /* get length of payload   */
   while (TRUE) {                           /* loop over remaining gathers */
     iml1 -= adsl_gai1_rp->achc_ginp_end - achl_rp;  /* bytes in this gather */
     if (iml1 <= 0) {                       /* all data of this block  */
       return iml_recv_len;
     }
     adsl_gai1_rp = adsl_gai1_rp->adsc_next;  /* get next gather in chain */
     if (adsl_gai1_rp == NULL) break;       /* end of input data       */
     achl_rp = adsl_gai1_rp->achc_ginp_cur;  /* get start of gather    */
   }
   return -1;
} /* end m_scan_smb_header()                                           */

/** calculate the SMB2 sign key                                        */
static void m_gen_smb_sign_key( struct dsd_smb_cl_session *adsp_scs, char *achp_sign_key ) {
   int        iml1;                         /* working variable        */
   char       byrl_hmac_1[ 64 ];            /* for HMAC                */

   iml1 = 0;                                /* clear index             */
   do {                                     /* loop feed key to constants */
     byrl_hmac_1[ iml1 ] = (unsigned char) *((unsigned char *) achp_sign_key + iml1) ^ 0X36;
     adsp_scs->byrc_hmac_2[ iml1 ] = (unsigned char) *((unsigned char *) achp_sign_key + iml1) ^ 0X5C;
     iml1++;                                /* increment index         */
   } while (iml1 < LEN_SMB2_SIGN_KEY);      /* length sign key of SMB2 */
   memset( byrl_hmac_1 + LEN_SMB2_SIGN_KEY, 0X36, sizeof(byrl_hmac_1) - LEN_SMB2_SIGN_KEY );
   memset( adsp_scs->byrc_hmac_2 + LEN_SMB2_SIGN_KEY,
           0X5C,
           sizeof(adsp_scs->byrc_hmac_2) - LEN_SMB2_SIGN_KEY );
#ifdef TRY_141118_01                        /* SHA256 init             */
   memset( adsp_scs->imrc_sign_array, 0, sizeof(adsp_scs->imrc_sign_array) );
#endif
   SHA256_Init( adsp_scs->imrc_sign_array );
   SHA256_Update( adsp_scs->imrc_sign_array, byrl_hmac_1, 0, sizeof(byrl_hmac_1) );
} /* m_gen_smb_sign_key()                                              */

/** check the signature of a received SMB2 header                      */
static BOOL m_check_smb_signature( struct dsd_smb_cl_session *adsp_scs,
                                   struct dsd_smb2_hdr_sync *adsp_smb2_hdr,
                                   struct dsd_gather_i_1 *adsp_gai1_recv,
                                   int imp_len_data ) {
   int        iml1, iml2;                   /* working variables       */
   struct dsd_gather_i_1 *adsl_gai1_recv_rp;   /* block received from SMB server */
   int        imrl_sha256_array[ SHA256_ARRAY_SIZE ];  /* for SHA-256  */
   char       byrl_digest[ SHA256_DIGEST_LEN ];

   memcpy( imrl_sha256_array,
           adsp_scs->imrc_sign_array,
           sizeof(imrl_sha256_array) );
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   m_sdh_printf( adss_sdh_call_1, "m_smb_cl_call() l%05d m_check_smb_signature() first=0X%02X last=0X%02X.",
                 __LINE__,
                 *((unsigned char *) adsp_smb2_hdr),
                 *((unsigned char *) adsp_smb2_hdr + offsetof( struct dsd_smb2_hdr_sync , chrc_signature ) - 1) );
#endif
   SHA256_Update( imrl_sha256_array,
                  (char *) adsp_smb2_hdr,
                  0,
                  offsetof( struct dsd_smb2_hdr_sync , chrc_signature ) );
   SHA256_Update( imrl_sha256_array,
                  (char *) byrs_zeroes,
                  0,
                  sizeof(adsp_smb2_hdr->chrc_signature) );
   if (imp_len_data == 0) {
     goto p_proc_60;                        /* variable data have been processed */
   }
   adsl_gai1_recv_rp = adsp_gai1_recv;
   iml1 = imp_len_data;

   p_proc_20:                               /* process variable input  */
   iml2 = adsl_gai1_recv_rp->achc_ginp_end - adsl_gai1_recv_rp->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   m_sdh_printf( adss_sdh_call_1, "m_smb_cl_call() l%05d m_check_smb_signature() length=%d/0X%X first=0X%02X last=0X%02X.",
                 __LINE__,
                 iml2, iml2,
                 *((unsigned char *) adsl_gai1_recv_rp->achc_ginp_cur),
                 *((unsigned char *) adsl_gai1_recv_rp->achc_ginp_cur + iml2 - 1) );
#endif
   SHA256_Update( imrl_sha256_array,
                  adsl_gai1_recv_rp->achc_ginp_cur,
                  0,
                  iml2 );
   iml1 -= iml2;
   if (iml1 <= 0) {                         /* all data processed      */
     goto p_proc_60;                        /* variable data have been processed */
   }
   adsl_gai1_recv_rp = adsl_gai1_recv_rp->adsc_next;  /* get next in chain */
   if (adsl_gai1_recv_rp) {                 /* more data to process    */
     goto p_proc_20;                        /* process variable input  */
   }
   return FALSE;

   p_proc_60:                               /* variable data have been processed */
   SHA256_Final( imrl_sha256_array, byrl_digest, 0 );
#ifdef TRY_141118_01                        /* SHA256 init             */
   memset( imrl_sha256_array, 0, sizeof(imrl_sha256_array) );
#endif
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array,
                  adsp_scs->byrc_hmac_2,
                  0,
                  sizeof(adsp_scs->byrc_hmac_2) );
   SHA256_Update( imrl_sha256_array,
                  byrl_digest,
                  0,
                  sizeof(byrl_digest) );
   SHA256_Final( imrl_sha256_array, byrl_digest, 0 );
   iml1 = memcmp( adsp_smb2_hdr->chrc_signature,
                  byrl_digest,
                  sizeof(adsp_smb2_hdr->chrc_signature) );
   if (iml1 == 0) return TRUE;
   return FALSE;
} /* end m_check_smb_signature()                                       */

/** fill the signature of a outgoing SMB2 header / field               */
static void m_fill_smb_signature( struct dsd_smb_cl_session *adsp_scs,
                                  struct dsd_smb2_hdr_sync *adsp_smb2_hdr,
                                  struct dsd_gather_i_1 *adsp_gai1_send ) {  /* gather input data to send */
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   int        iml1;                         /* working variable        */
#endif
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   int        imrl_sha256_array[ SHA256_ARRAY_SIZE ];  /* for SHA-256  */
   char       byrl_digest[ SHA256_DIGEST_LEN ];

   memcpy( imrl_sha256_array,
           adsp_scs->imrc_sign_array,
           sizeof(imrl_sha256_array) );
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   m_sdh_printf( adss_sdh_call_1, "m_smb_cl_call() l%05d m_fill_smb_signature() first=0X%02X last=0X%02X.",
                 __LINE__,
                 *((unsigned char *) adsp_smb2_hdr),
                 *((unsigned char *) adsp_smb2_hdr + offsetof( struct dsd_smb2_hdr_sync , chrc_signature ) - 1) );
#endif
   SHA256_Update( imrl_sha256_array,
                  (char *) adsp_smb2_hdr,
                  0,
                  offsetof( struct dsd_smb2_hdr_sync , chrc_signature ) );
   SHA256_Update( imrl_sha256_array,
                  (char *) byrs_zeroes,
                  0,
                  sizeof(adsp_smb2_hdr->chrc_signature) );
   if (adsp_gai1_send == NULL) {
     goto p_proc_60;                        /* variable data have been processed */
   }
   adsl_gai1_w1 = adsp_gai1_send;

   p_proc_20:                               /* process variable input  */
#ifdef DEBUG_150317_01                      /* signing Compounded Requests */
   iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
   m_sdh_printf( adss_sdh_call_1, "m_smb_cl_call() l%05d m_fill_smb_signature() length=%d/0X%X first=0X%02X last=0X%02X.",
                 __LINE__,
                 iml1, iml1,
                 *((unsigned char *) adsl_gai1_w1->achc_ginp_cur),
                 *((unsigned char *) adsl_gai1_w1->achc_ginp_cur + iml1 - 1) );
#endif
   SHA256_Update( imrl_sha256_array,
                  adsl_gai1_w1->achc_ginp_cur,
                  0,
                  adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
   adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain       */
   if (adsl_gai1_w1) {                      /* more data to process    */
     goto p_proc_20;                        /* process variable input  */
   }

   p_proc_60:                               /* variable data have been processed */
   SHA256_Final( imrl_sha256_array, byrl_digest, 0 );
   SHA256_Init( imrl_sha256_array );
   SHA256_Update( imrl_sha256_array,
                  adsp_scs->byrc_hmac_2,
                  0,
                  sizeof(adsp_scs->byrc_hmac_2) );
   SHA256_Update( imrl_sha256_array,
                  byrl_digest,
                  0,
                  sizeof(byrl_digest) );
   SHA256_Final( imrl_sha256_array, byrl_digest, 0 );
   memcpy( adsp_smb2_hdr->chrc_signature,
           byrl_digest,
           sizeof(adsp_smb2_hdr->chrc_signature) );
   return;
} /* end m_fill_smb_signature()                                        */

/** consume input of one SMB block                                     */
static int m_consume_input( struct dsd_gather_i_1 *adsp_gai1_in, int imp_len ) {
   int        iml1;                         /* working variable        */

   while (adsp_gai1_in) {                   /* loop over gather input  */
     iml1 = adsp_gai1_in->achc_ginp_end - adsp_gai1_in->achc_ginp_cur;  /* bytes in this gather */
     if (iml1 > imp_len) iml1 = imp_len;
     imp_len -= iml1;
     adsp_gai1_in->achc_ginp_cur += iml1;   /* set consumed            */
     if (adsp_gai1_in->achc_ginp_cur < adsp_gai1_in->achc_ginp_end) {  /* more bytes in this gather */
       return 1;                            /* found more data         */
     }
     adsp_gai1_in = adsp_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (imp_len == 0) return 0;              /* all data consumed       */
   return -1;                               /* not enough data         */
} /* end m_consume_input()                                             */

/** subroutine to acuire work areale                                   */
static BOOL m_acquire_work_area( struct dsd_sdh_call_1 *adsp_sdh_call_1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_aux_get_workarea dsl_agwa_l;  /* acquire additional work area */

   memset( &dsl_agwa_l, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,  /* User Field Subroutine */
                                      DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                      &dsl_agwa_l,  /* acquire additional work area */
                                      sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) return FALSE;       /* error occured           */
   adsp_sdh_call_1->achc_lower = dsl_agwa_l.achc_work_area;
   adsp_sdh_call_1->achc_upper = dsl_agwa_l.achc_work_area + dsl_agwa_l.imc_len_work_area;
   return TRUE;
} /* end m_acquire_work_area()                                         */

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

#ifdef XYZ1
/* subroutine to display date and time                                 */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */
#endif

/** subroutine to dump storage-content to console                      */
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

/** callback-routine for NTLM, get epoch value                         */
static BOOL m_cb_get_epoch( void * ap_userfld, HL_LONGLONG *ailp_epoch ) {
#ifdef XYZ1
   *ailp_epoch = 0;
   return TRUE;
#endif
#define ADSL_SDH_CALL_1 ((struct dsd_sdh_call_1 *) ap_userfld)
   return (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
                                       DEF_AUX_GET_T_MSEC,  /* get time / epoch in milliseconds */
                                       ailp_epoch, sizeof(HL_LONGLONG) );
#undef ADSL_SDH_CALL_1
} /* end m_cb_get_epoch()                                              */

/** callback-routine for NTLM, get secure random, sent to client       */
static BOOL m_cb_get_random( void * ap_userfld, char *achp_buffer, int imp_length ) {
#ifdef XYZ1
   memset( achp_buffer, 'A', imp_length );
   return TRUE;
#endif
#define ADSL_SDH_CALL_1 ((struct dsd_sdh_call_1 *) ap_userfld)
   return (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
#ifdef B160710
                                       DEF_AUX_SECURE_RANDOM,  /* get secure random */
#endif
                                       DEF_AUX_RANDOM_VISIBLE,  /* get visible secure random - nonce */
                                       achp_buffer, imp_length );
#undef ADSL_SDH_CALL_1
} /* end m_cb_get_epoch()                                              */

/** input two bytes little endian                                      */
static inline short int m_get_le2( char *achp_source ) {
   return *((short int *) achp_source);
} /* end m_get_le2()                                                   */

/** input four bytes little endian                                     */
static inline int m_get_le4( char *achp_source ) {
   return *((int *) achp_source);
} /* end m_get_le4()                                                   */

/** output two bytes little endian                                     */
static inline void m_put_le2( char *achp_target, int imp1 ) {
   *((unsigned short int *) achp_target) = (unsigned short int) imp1;
} /* m_put_le2()                                                       */

/** output four bytes little endian                                    */
static inline void m_put_le4( char *achp_target, int imp1 ) {
   *((unsigned int *) achp_target) = (unsigned int) imp1;
} /* end m_put_le4()                                                   */

/** output eight bytes little endian                                   */
static inline void m_put_le8( char *achp_target, HL_LONGLONG ilp1 ) {
   *((unsigned char *) achp_target + 0) = (unsigned char) ilp1;
   *((unsigned char *) achp_target + 1) = (unsigned char) (ilp1 >> 8);
   *((unsigned char *) achp_target + 2) = (unsigned char) (ilp1 >> 16);
   *((unsigned char *) achp_target + 3) = (unsigned char) (ilp1 >> 24);
   *((unsigned char *) achp_target + 4) = (unsigned char) (ilp1 >> 32);
   *((unsigned char *) achp_target + 5) = (unsigned char) (ilp1 >> 40);
   *((unsigned char *) achp_target + 6) = (unsigned char) (ilp1 >> 48);
   *((unsigned char *) achp_target + 7) = (unsigned char) (ilp1 >> 56);
} /* end m_put_le8()                                                   */

/** output two bytes big endian                                        */
static inline void m_put_be2( char *achp_target, int imp1 ) {
   *((unsigned char *) achp_target + 0) = (unsigned char) (imp1 >> 8);
   *((unsigned char *) achp_target + 1) = (unsigned char) imp1;
} /* m_put_le2()                                                       */

#ifdef XYZ1
/** protocol output of SMB2 header                                     */
static void m_smb2_prot( char *achp_data ) {
#define ADSL_SMB2_HDR_IN ((struct dsd_smb2_hdr_sync *) achp_data)
   if (memcmp( ADSL_SMB2_HDR_IN->chrc_eye_catcher,
               byrs_smb2_eyecatcher,
               sizeof(ADSL_SMB2_HDR_IN->chrc_eye_catcher) )) {
     m_hl1_printf( "xbdash01-l%05d-W m_smb2_prot() eye-cacher invalid",
                   __LINE__ );
   }
   if (m_get_le2( (char *) &ADSL_SMB2_HDR_IN->usc_header_length ) != sizeof(struct dsd_smb2_hdr_sync)) {
     m_hl1_printf( "xbdash01-l%05d-W m_smb2_prot() invalid usc_header_length 0X%04X",
                   __LINE__, m_get_le2( (char *) &ADSL_SMB2_HDR_IN->usc_header_length ) );
   }
   m_hl1_printf( "xbdash01-l%05d-T m_smb2_prot() umc_nt_status 0X%08X",
                 __LINE__, m_get_le4( (char *) &ADSL_SMB2_HDR_IN->umc_nt_status ) );
   m_hl1_printf( "xbdash01-l%05d-T m_smb2_prot() umc_tree_id 0X%08X",
                 __LINE__, m_get_le4( (char *) &ADSL_SMB2_HDR_IN->umc_tree_id ) );
#undef ADSL_SMB2_HDR_IN
} /* end m_smb2_prot()                                                 */
#endif

#ifdef XYZ1
static int m_err_printf( char *aptext, ... ) {
   va_list    dsl_argptr;
   int        iml1;                         /* working-variable        */

   va_start( dsl_argptr, aptext );
   iml1 = vsnprintf( chrs_error_msg, sizeof(chrs_error_msg), aptext, dsl_argptr );
   va_end( dsl_argptr );
   m_hl1_printf( "%.*s", iml1, chrs_error_msg );
   achs_reason_end = chrs_error_msg;        /* reason for end          */
   return iml1;
} /* end m_err_printf()                                                */

/* subroutine to display date and time                                 */
static int m_get_date_time( char *achp_buff ) {
   time_t     dsl_time;

   time( &dsl_time );
   return strftime( achp_buff, 18, "%d.%m.%y %H:%M:%S", localtime( &dsl_time ) );
} /* end m_get_date_time()                                             */

#ifdef HL_CHECK_TIME                        /* check time needed in computing */
static char * m_edit_dec_long_1( char *achp_target, HL_LONGLONG ilp1 ) {
   int        iml1;                         /* working variable        */
   char       *achl1;                       /* working variable        */

   achl1 = achp_target + LEN_EDIT - 1;
   *achl1 = 0;                              /* make zero-terminated    */
   iml1 = 3;                                /* digits between separator */
   while (TRUE) {
     *(--achl1) = (char) (ilp1 % 10 + '0');
     ilp1 /= 10;
     if (ilp1 == 0) return achl1;
     iml1--;
     if (iml1 == 0) {
       *(--achl1) = ',';                    /* output separator        */
       iml1 = 3;                            /* digits between separator */
     }
   }
} /* end m_edit_dec_long_1()                                           */
#endif

/* subroutine to dump storage-content to console                       */
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
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
     m_hl1_printf( "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                            */
#endif
