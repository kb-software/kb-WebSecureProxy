#undef TRACEHL_KB
#undef TRACEHL1
#define WA_160809_01
#define WA_160813_01
#define WA_170113_01
//#define DEBUG_160810_01
//#define DEBUG_170119_01
//#define TRACEHL1
#ifdef TRACEHL1
#define LOG_INSURE_01
#endif
#ifdef TO_DO_140527
reconnect to SMB server
after reconnect check
enum ied_cl_state {}                         /* state of connection to client */
if in notify
---
when started, display device and account - or role
- 17.01.16 -
  <local>
    <encryption-required>YES/NO
#endif
//#define TRACEHL1
//#define TRACEHL_KB
#ifdef TRACEHL_KB
#define TRACEHL1
#define DEBUG_140823_01
#define DEBUG_140925_01
//#define DEBUG_141101_01
//#define DEBUG_141129_01
#define DEBUG_141231_02                     /* gather to virus-checker empty */
#define DEBUG_150302_01                     /* simulate configuration create shared directory */
#define DEBUG_160115_01                     /* show notify             */
#define DEBUG_170209_01                     /* server to client, data at end missing */
#define HELP_DEBUG
#endif
#define WA_150302_01                        /* problem Unicode library */
//#define DEBUG_170410_01                     /* address adsc_file_1_parent invalid */
#define DEBUG_170413_01                     /* address adsl_a1 invalid */
//#define TRY_KRB5
//#define DEBUG_131228_01
#ifdef TO_DO_140101
   p_resp_vch_60:                           /* end of virus-checking   */
send message virus found to client
set **aadsl_gai1_ch1;  /* chain of gather         */
---
flags with 0X
p_cxd_40:
03.01,15 KB
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xl-sdh-dash-01                                      |*/
/*| -------------                                                     |*/
/*|  DLL / Library for WebSecureProxy                                 |*/
/*|    Server-Data-Hook                                               |*/
/*|  HOBLink DASH - data share                                        |*/
/*|  KB 04.07.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2012 (VC11)                                     |*/
/*|  complilers on Unix                                               |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
 * Virus-Checking can be done to files received from the DASH client,
 * and also to files read from the SMB2 (file-) server.
 * When Virus-Checking is done, the data are not immediately written
 * to the target, instead the data are written to the WSP Swap Storage.
 * When there is no virus in the file,
 * the content is written to the target.
*/

/**
 * Windows FILEDATE like NTLM,
 * TimeStamp (8 bytes): A 64-bit unsigned integer that contains the current system time,
 * represented as the number of 100 nanosecond ticks elapsed since midnight of January 1,
 * 1601 (UTC).
*/

/* #define TRACEHL1 */

/**
 * flow of this program, SDH
 * the client (XBDASH02) connects to the WSP
 * and WSM (WebSecureProxy Socks-Mode) is processed.
 * the client is only slave and gets all commands from this SDH.
 * the client sends what is configured:
 * - profile name (optional)
 * - time-keepalive (optional)
 * - reconnect
 * this SDH reads the corresponding configuration file from disk,
 * planned later from LDAP.
 * the configuration file is processed in m_proc_xml_conf().
 * then, this SDH connects to the file server (protocol SMB2)
 * reads to complete directory from the file server,
 * and simultaniously requests the directory from the client.
 * the directory from the client is not retrieved
 * when the client says, it is a reconnect,
 * and the content of the synchronize-file is still the same as on the client.
 * during synchronization, certain memory is needed,
 * and this memory is not needed while this SDH only waits
 * for notify from client or server.
 * so this extra memory, needed only during synchronziation,
 * is stored in adsl_dwa and adsl_cl1->ac_work_data.
 * the memory at adsl_cl1 is always available.
 * adsl_a1 is part of the memory adressed by adsl_dwa.
 *
 * the directories of the client and the SMB-server are kept
 * in AVL-trees.
 * There is also the old state, the last synchronized state,
 * in an AVL-tree. These three trees are compared in the
 * function m_next_action(), and the routine m_next_action()
 * finds and gives command output that needs to be done (for example copy or delete a file).
 * The fields for the AVL-trees are:
 * adsc_db1_sync, adsc_db1_local (= client), adsc_db1_remote (= SMB-server).
 * sometimes, these values contain trees which is the same as one of the other fields.
*/

#ifndef HL_UNIX
#ifdef HL_LINUX
#define HL_UNIX
#endif
#ifdef HL_FREEBSD
#define HL_UNIX
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "hob-unix01.h"
#endif
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>
#include <hob-xslunic1.h>
#ifdef XYZ1
#define DEF_HL_INCL_INET
#define DEF_HL_INCL_DOM
//#define DEF_HL_NO_XERCES
#include "hob-xsclib01.h"
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#ifdef B140118
#include "hob-xml-dom-parser-01.hpp"
#else
#include "hob-xml-dom-parser-02.h"
#endif
#include <hob-smb-01.h>
#include <hob-dash-01.h>
#include "hob-cd-file-1.h"

#define NO_INCL_RDPVCH1_CONFIG
#ifndef NOT_KB_DIRECT
#ifndef HL_UNIX
#ifndef RUN_ON_KBID
#include "D:\AKBI61\RDPACC\hob-xsrdpvch1.h"
#else
#include "C:\AKBID1\RDPACC\hob-xsrdpvch1.h"
#endif
#else
#include "hob-xsrdpvch1.h"
#endif
#else
#include "hob-xsrdpvch1.h"
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#include <xercesc/dom/DOMAttr.hpp>

#define DOMNode XERCES_CPP_NAMESPACE::DOMNode

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#include "hob-xsclib01.h"

#ifdef XYZ1
#ifndef HL_UNIX
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#define D_TCP_ERROR WSAGetLastError()
#else
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#define D_TCP_ERROR errno
#endif
#endif

#define D_TIME_BACKLOG         30           /* timer in seconds when to try backlog operations again */
//#define D_TIME_BACKLOG         5            /* timer in seconds when to try backlog operations again */
//#define MAX_LEN_NHASN          4            /* maximum length NHASN number */
#define MAX_LEN_NHASN          6            /* maximum length NHASN number */
#define MAX_EYE_CATCHER        128          /* maximum length eye-catcher */
#define DASH_CHANNEL           1            /* DASH channel used       */
#define LEN_FILE_NAME          1024         /* maximum length of file name */
#define MAX_DIR_STACK          64           /* maximum stack of nested directories */
#define LEN_DIR_BLOCK          (16 * 1024)  /* length of directory block */
#define MAX_XML_DOM_STACK      64           /* maximum stack of nested XML / DOM nodes */
#define LEN_MEM_BLOCK          (16 * 1024)  /* length of memory block  */
#define MAX_INP_GATHER         16           /* number of input gather to be processed */
#define MAX_PASSWORD           256          /* maximum length of password */
#define D_KEEPALIVE_DEVIATION  2            /* deviation keepalive server in seconds */
#define D_SMB2_ECHO            950          /* default SMB2 <interval-echo> */

#define LEN_UNIX_DIR_ATTR      4            /* length of Unix directory attribute */
#define LEN_UNIX_FILETIME      4            /* length of Unix file time */
#define CHECK_UNIX_ISDIR       0X00004000   /* check Unix S_ISDIR(m)   */

#define MSG_ERROR_01           "abend HOBLink DASH server"
#define MAX_LEN_MSG_CLIENT     256

#ifdef B140428
#define CONF_NODE_L0           "dash-client-configuration"
#endif
#define CONF_NODE_L0           "dash-proxy-configuration"
#define XML_NODE_L0            "dash-synchronize-file"
#ifdef XYZ1
#define D_DEST_IPV4ADDR           1
#define D_DEST_IPV6ADDR           4

#define MAX_LEN_USERID            512       /* maximum length userid   */
#define MAX_LEN_DOMAIN            256       /* maximum length destination domain */
#endif

#define TIME_ADJUST ((HL_LONGLONG) 116444736 * (HL_LONGLONG) 1000000000)

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#ifndef TEST_090927_02
#define MAX_VC_WINDOW (64 * 1024)
#else
#define MAX_VC_WINDOW 256
#endif
#define NO_VC_REQ1             16           /* number of concurrent requests */
#define NO_SS_AHEAD            8            /* number of swap storage ahead */

enum ied_tdpc_function {                    /* type dash-proxy-configuration */
   ied_tdpc_invalid = 0,                    /* invalid                 */
   ied_tdpc_local_file_01,                  /* local-file-01           */
   ied_tdpc_xyz1
};

/**
   following this structure, there may be
   - the name of the directory name dash-proxy-configuration
   - the name of the directory name dash-server-credentials
   - the name of the virus-checking service name
   in UTF-8
*/
struct dsd_clib1_conf_1 {                   /* structure configuration */
   enum ied_tdpc_function iec_tdpc;         /* type dash-proxy-configuration */
   enum ied_tdpc_function iec_cred_tdpc;    /* credentials type dash-proxy-configuration */
   int        imc_seml;                     /* <send-error-messages-level> */
   int        imc_log_ls;                   /* <log-level-share>       */
   int        imc_len_dir_dpc;              /* length directory name dash-proxy-configuration */
   int        imc_len_dir_cred;             /* length directory name dash-server-credentials */
   int        imc_len_file_vch_serv;        /* length file virus-checking service name */
   HL_LONGLONG ilc_max_file_size;           /* maximum file-size       */
   BOOL       boc_virch_local;              /* virus checking data from local / client */
   BOOL       boc_virch_server;             /* virus checking data from server / SMB */
};

enum ied_sync_function {                    /* synchronize function    */
   ied_syfu_invalid = 0,                    /* invalid                 */
   ied_syfu_duplex,                         /* both-directions         */
   ied_syfu_read_client,                    /* read-from-client        */
   ied_syfu_read_server                     /* read-from-server        */
};

enum ied_sync_file_type {                   /* synchronize-file type   */
   ied_syft_invalid = 0,                    /* invalid                 */
   ied_syft_local_file_01,                  /* local-file-01           */
   ied_syft_local_file_02,                  /* local-file-02           */
   ied_syff_serv_file_01,                   /* service-file-01         */
   ied_syff_serv_file_02,                   /* service-file-02         */
   ied_syff_ldap                            /* LDAP                    */
};

enum ied_smb2_auth_type {                   /* SMB2 authentication type */
   ied_s2at_invalid = 0,                    /* invalid                 */
   ied_s2at_xml_conf,                       /* domain, userid, password configured */
   ied_s2at_cred_cache,                     /* single sign on with WSP credentials */
   ied_s2at_krb5,                           /* Kerberos 5              */
   ied_s2at_ask_user_pwd                    /* ask user for password   */
};

struct dsd_conf_main {                      /* configuration           */
   enum ied_sync_function iec_syfu;         /* synchronize function    */
   enum ied_sync_file_type iec_syft;        /* synchronize-file type   */
   int        imc_server_port;              /* server-port             */
#ifdef B150411
// to-do 04.03.15 KB - remove
   BOOL       boc_krb5;                     /* use-krb5-signon         */
#endif
   enum ied_smb2_auth_type iec_s2at;        /* SMB2 authentication type */
   BOOL       boc_windows_fs;               /* is Windows file system  */
   int        imc_local_keepalive;          /* local <time-keepalive>  */
   BOOL       boc_local_create_shared_dir;  /* local create shared directory */
   int        imc_server_echo;              /* server <interval-echo>  */
   BOOL       boc_server_always_echo;       /* server <always-send-echo> */
   BOOL       boc_server_create_shared_dir;  /* server create shared directory */
   int        imc_seml;                     /* <send-error-messages-level> */
   int        imc_log_ls;                   /* <log-level-share>       */
   struct dsd_unicode_string dsc_ucs_server_ineta;  /* server-ineta    */
   struct dsd_unicode_string dsc_ucs_domain;  /* domain                */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid                */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
   struct dsd_unicode_string dsc_ucs_server_tree;  /* server SMB tree  */
   struct dsd_unicode_string dsc_ucs_server_dir;  /* server SMB directory */
   struct dsd_unicode_string dsc_ucs_server_temp_fn;  /* server SMB temporary file-name */
   struct dsd_unicode_string dsc_ucs_local_dir;  /* local directory    */
   struct dsd_unicode_string dsc_ucs_local_temp_fn;  /* local temporary file-name */
   struct dsd_unicode_string dsc_ucs_sync_fn;  /* synchronize file-name */
   HL_LONGLONG ilc_quota_local;             /* disk quota on client    */
   HL_LONGLONG ilc_quota_server;            /* disk quota on SMB server */
};

enum ied_cl_state {                         /* state of connection to client */
   ied_clst_rec_eye_catcher = 0,            /* receive eye-catcher     */
   ied_clst_rec_log_in,                     /* receive log-in          */
   ied_clst_rec_active_channels,            /* receive active channels */
   ied_clst_idle,                           /* client is idle          */
   ied_clst_resp_cred_1,                    /* wait for response credentials */
#ifdef B160323
   ied_clst_resp_file_control,              /* wait for response file-control */
#endif
#ifndef B160323
   ied_clst_resp_file_control_w,            /* wait for response file-control */
   ied_clst_resp_file_control_p,            /* process after response file-control */
#endif
   ied_clst_resp_set_ch_notify,             /* wait for response set change notify */
   ied_clst_resp_del_ch_notify_normal,      /* wait for response delete change notify - normal */
   ied_clst_resp_del_ch_notify_vc,          /* wait for response delete change notify - virus checking */
   ied_clst_resp_all_dir_1,                 /* wait for response all directories - start */
   ied_clst_resp_all_dir_2,                 /* wait for response all directories - continue */
   ied_clst_resp_end,                       /* wait for response end command */
   ied_clst_resp_read_file_normal,          /* wait for read file normal */
   ied_clst_resp_read_file_compressed,      /* wait for read file compressed */
   ied_clst_write_file_normal,              /* write file normal       */
   ied_clst_write_file_compressed,          /* write file compressed   */
   ied_clst_resp_write_file,                /* wait for response write file */
   ied_clst_resp_misc,                      /* wait for response miscellaneous command */
   ied_clst_end_read_file,                  /* received end read file  */
#ifndef B150127
   ied_clst_end_virus_checked,              /* received end read file and virus checked */
#endif
   ied_clst_xyz
};

struct dsd_dir_bl_1 {                       /* directory block 1 - chaining */
   struct dsd_dir_bl_1 *adsc_next;          /* next in chain           */
   char       *achc_end_file;               /* end of files            */
};

struct dsd_dir_bl_2 {                       /* directory block 2 - header */
   struct dsd_htree1_avl_cntl dsc_htree1_avl_file;
   int        imc_no_files;                 /* number of files         */
   int        imc_no_dir;                   /* number of directories   */
   BOOL       boc_unix;                     /* is Unix filesystem      */
};

struct dsd_dir_stack_1 {                    /* stack entry directory   */
   struct dsd_file_1 *adsc_f1_dir_cur;      /* entry of file currently directory */
   struct dsd_file_1 *adsc_f1_dir_last;     /* entry of file last directory */
   struct dsd_dir_bl_1 *adsc_db1_cur;       /* directory block current */
   int        imc_pos_dn;                   /* position in directory name */
};

struct dsd_file_1 {                         /* entry of a single file  */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   struct dsd_file_1 *adsc_file_1_parent;   /* entry of parent directory */
   struct dsd_file_1 *adsc_file_1_same_n;   /* chain of entries same name */
   struct dsd_unicode_string dsc_ucs_file;  /* name of file            */
   DWORD      dwc_file_attributes;
   enum ied_dash_access iec_dac;            /* access                  */
   BOOL       boc_exclude_compression;      /* <exclude-compression>   */
   unsigned int umc_flags;                  /* flags for processing    */
#define D_FILE_1_FLAG_ACCESS  0X01          /* access not allowed      */
#define D_FILE_1_FLAG_SIZE    0X02          /* file too big            */
#define D_FILE_1_FLAG_QUOTA   0X04          /* disk quota exceeded     */
#define D_FILE_1_FLAG_NOT_CL  0X08          /* file not on client      */
#define D_FILE_1_FLAG_NOT_SE  0X10          /* file not on server      */
   FILETIME   dsc_last_write_time;
   HL_LONGLONG ilc_file_size;               /* size of file            */
   char       *achc_virus_client;           /* virus found on client   */
   char       *achc_virus_server;           /* virus found on server   */
};

struct dsd_xml_dir_bl {                     /* XML directory block - chaining */
   struct dsd_xml_dir_bl *adsc_next;        /* next in chain           */
   char       *achc_end_data;               /* end of data             */
};

enum ied_action_state {                     /* state of action         */
   ied_acs_invalid = 0,                     /* invalid state           */
   ied_acs_copy_lo2re,                      /* copy from local to remote */
   ied_acs_copy_re2lo,                      /* copy from remote to local */
   ied_acs_create_dir_local,                /* create directory local  */
   ied_acs_create_dir_remote,               /* create directory remote */
   ied_acs_delete_file_local,               /* delete file local       */
   ied_acs_delete_file_remote,              /* delete file remote      */
   ied_acs_delete_dir_local,                /* delete directory local  */
   ied_acs_delete_dir_remote,               /* delete directory remote */
   ied_acs_done                             /* all done                */
};

struct dsd_action_1 {                       /* what action to do       */
   struct dsd_file_1 *adsc_f1_action;       /* entry of file current action */
   enum ied_action_state iec_acs;           /* state of action         */
#ifdef TRACEHL1
   int        imc_trace_call;               /* trace call number       */
   int        imc_trace_line;               /* line number for tracing */
#endif
   BOOL       boc_write_server;             /* can write to SMB server */
   BOOL       boc_write_local;              /* can write local         */
   int        imc_errors;                   /* files with errors       */
   int        imc_dir_nesting;              /* counter directory nesting */
   int        imc_dir_delete;               /* number to delete directory */
   BOOL       boc_dir_ne_lo_re;             /* TRUE means remote       */
   BOOL       boc_start;                    /* start processing        */
   BOOL       boc_changed_local;            /* changes local           */
   BOOL       boc_notify_local;             /* notify from client received */
   BOOL       boc_changed_remote;           /* changes remote          */
   BOOL       boc_notify_remote;            /* notify from server received */
   BOOL       boc_changed_sync;             /* need to write synchronize file */
   BOOL       boc_valid_sync;               /* valid AVL-entry sync    */
   BOOL       boc_valid_local;              /* valid AVL-entry local   */
   BOOL       boc_valid_remote;             /* valid AVL-entry remote  */
// BOOL       boc_unix_local;               /* local is Unix file system */
#ifdef B150207
   HL_LONGLONG ilc_sum_size_local;          /* sum file size client    */
   HL_LONGLONG ilc_sum_size_server;         /* sum file size SMB server */
#endif
   HL_LONGLONG ilc_size_replaced;           /* size of file that is being replaced */
   struct dsd_dir_bl_1 *adsc_db1_sync;      /* directory block 1 - synchonization */
   struct dsd_dir_bl_1 *adsc_db1_local;     /* directory block 1 - local */
   struct dsd_dir_bl_1 *adsc_db1_remote;    /* directory block 1 - remote */
   struct dsd_dir_bl_1 *adsc_db1_new_start;  /* directory block 1 - new */
   struct dsd_dir_bl_1 *adsc_db1_new_cur;   /* directory block 1 - chaining - current */
   struct dsd_dir_bl_1 *adsc_db1_new_last;  /* directory block 1 - chaining - last */
#ifdef NOT_USEFUL
   struct dsd_file_1 *adsc_f1_save_01;      /* save entry to continue  */
#endif
   struct dsd_file_1 *adsc_f1_new_cur;      /* current entry new       */
   char       *achc_fn_new_low;             /* low address of file names */
   struct dsd_htree1_avl_work dsc_htree1_work_sync;  /* work-area for AVL-Tree */
   struct dsd_htree1_avl_work dsc_htree1_work_local;  /* work-area for AVL-Tree */
   struct dsd_htree1_avl_work dsc_htree1_work_remote;  /* work-area for AVL-Tree */
   struct dsd_htree1_avl_work dsc_htree1_work_new;  /* work-area for AVL-Tree */
   struct dsd_file_1 *adsrc_f1_dir_nesting[ MAX_DIR_STACK ];  /* stack entry directory */
#ifndef B170321
   struct dsd_file_1 *adsrc_f1_outdir_nesting[ MAX_DIR_STACK ];  /* stack entry directory */
/*
 * adsc_f1_new_cur is used later for output of XML data,
 * but adsc_file_1_parent points to an area which will be freed.
*/
#endif
};

struct dsd_dir_work_1 {                     /* directory operations work area */
   struct dsd_dir_bl_1 *adsc_db1_start;     /* directory block 1 - chaining - start */
   struct dsd_dir_bl_1 *adsc_db1_cur;       /* directory block 1 - chaining - current */
   struct dsd_dir_bl_1 *adsc_db1_last;      /* directory block 1 - chaining - last */
   struct dsd_file_1 *adsc_f1_cur;          /* entry of a single file  */
   struct dsd_file_1 *adsc_f1_used;         /* last used single file   */
   struct dsd_file_1 *adsc_file_1_parent;   /* entry of parent directory */
   char       *achc_fn_low;                 /* low address of file names */
   HL_LONGLONG ilc_sum_size_local;          /* sum file size client    */
   int        imc_file_tag;                 /* save tag of file / directory */
};

struct dsd_dir_work_2 {                     /* directory operations work area */
   struct dsd_dir_bl_1 *adsc_db1_start;     /* directory block 1 - chaining - start */
   struct dsd_dir_bl_1 *adsc_db1_cur;       /* directory block 1 - chaining - current */
   struct dsd_dir_bl_1 *adsc_db1_last;      /* directory block 1 - chaining - last */
   struct dsd_file_1 *adsc_f1_cur;          /* entry of a single file  */
   struct dsd_file_1 *adsc_f1_used;         /* last used single file   */
   struct dsd_file_1 *adsc_file_1_parent;   /* entry of parent directory */
   char       *achc_fn_low;                 /* low address of file names */
   char       *achc_l_fn_exclude;           /* local filename to exclude */
   char       *achc_s_fn_exclude;           /* server filename to exclude */
   HL_LONGLONG ilc_sum_size_server;         /* sum file size SMB server */
   int        imc_ds1_index;                /* index of stack entry directory */
// int        imc_file_tag;                 /* save tag of file / directory */
   int        imc_l_fn_exclude_index;       /* local index directory compare filename to exclude */
   int        imc_l_fn_exclude_end;         /* local end filename to exclude */
   int        imc_l_fn_exclude_this;        /* local position compare filename to exclude */
   int        imc_l_fn_exclude_next;        /* local position end compare filename to exclude */
   int        imc_s_fn_exclude_index;       /* server index directory compare filename to exclude */
   int        imc_s_fn_exclude_end;         /* server end filename to exclude */
   int        imc_s_fn_exclude_this;        /* server position compare filename to exclude */
   int        imc_s_fn_exclude_next;        /* server position end compare filename to exclude */
};

struct dsd_work_in_dir_compr {              /* input directory compressed */
   int        imc_ds1_index;                /* index of stack entry directory */
   struct dsd_cdf_ctrl dsc_cdf_ctrl;        /* compress data file oriented control */
   struct dsd_gather_i_1 dsrc_gai1_data[ 2 ];  /* output from compression */
   struct dsd_file_1 *adsrc_f1_dir_nesting[ MAX_DIR_STACK ];  /* stack entry directory */
   struct dsd_dir_work_1 dsc_dw1;           /* directory operations work area */
#define LEN_CHUNK_DECO (16 + LEN_FILE_NAME)
   char       byrc_deco[ 2 * LEN_CHUNK_DECO ];  /* decompressed data   */
};

enum ied_vcend_state {                      /* state virus-checking end */
   ied_vcend_normal = 0,                    /* normal state, not yet end */
   ied_vcend_recv_end,                      /* end input received      */
   ied_vcend_wait_send_end,                 /* wait to send end to virus-checker */
   ied_vcend_end_sent                       /* end sent to virus-checker */
};

struct dsd_work_vch_1 {                     /* virus-checking          */
   void *     vpc_aux_swap_stor_handle;     /* handle of swap storage  */
   struct dsd_se_vch_contr_1 dsc_sevchcontr1;  /* service virus checking control area */
   struct dsd_se_vch_req_1 dsrc_sevchreq1[ NO_VC_REQ1 ];  /* service virus checking requests */
   struct dsd_gather_i_1 dsrc_gai1_vch_data[ NO_VC_REQ1 ];  /* data for virus-checking */
   char       *achrc_stor_addr_vc[ NO_VC_REQ1 ];  /* storage addresses */
   char       *achrc_stor_addr_ss[ NO_SS_AHEAD ];  /* storage addresses */
   char       *achc_vc_written;             /* address written to virus-checking */
   int        imc_ss_ahead;                 /* swap storage in use     */
   int        imc_index_re;                 /* index of dataset / chunk - read */
   int        imc_index_wr;                 /* index of dataset / chunk - write */
#ifdef XYZ1
   BOOL       boc_eof;                      /* end-of-file reached     */
#endif
   enum ied_vcend_state iec_vcend;          /* state virus-checking end */
};

struct dsd_work_in_file_vch {               /* input file with virus-checking */
   HL_LONGLONG ilc_read_position;           /* progress content received from client */
   union {
     struct {
       char   *achc_out;                    /* current output          */
       char   *achc_end;                    /* end of output area      */
     };
     struct dsd_cdf_ctrl dsc_cdf_ctrl;      /* compress data file oriented control */
   };
   struct dsd_work_vch_1 dsc_wvc1;          /* virus-checking          */
   int        imc_len_fn;                   /* length filename         */
   char       byrc_fn[ LEN_FILE_NAME ];     /* filename                */
};

struct dsd_work_ss2smb {                    /* copy from Swap Storage to SMB */
   HL_LONGLONG ilc_read_position;           /* progress content received from client */
   void *     vpc_aux_swap_stor_handle;     /* handle of swap storage  */
   int        imc_index_re;                 /* index of dataset / chunk - read */
   struct dsd_gather_i_1 dsc_gai1_data;     /* output to SMB           */
};

struct dsd_work_smb2cl {                    /* copy from SMB to client */
   HL_LONGLONG ilc_read_position;           /* progress content received from SMB */
   char       *achc_output;                 /* output data till here   */
   struct dsd_cdf_ctrl dsc_cdf_ctrl;        /* compress data file oriented control */
};

struct dsd_work_smb2ss {                    /* copy from SMB to Swap Storage */
   HL_LONGLONG ilc_read_position;           /* progress content received from SMB */
   char       *achc_output;                 /* output data till here   */
   struct dsd_work_vch_1 dsc_wvc1;          /* virus-checking          */
};

struct dsd_work_ss2cl {                     /* copy from Swap Storage to client */
   HL_LONGLONG ilc_read_position;           /* progress content received from client */
   void *     vpc_aux_swap_stor_handle;     /* handle of swap storage  */
   int        imc_index_re;                 /* index of dataset / chunk - read */
   struct dsd_cdf_ctrl dsc_cdf_ctrl;        /* compress data file oriented control */
};

struct dsd_work_cl2smb {                    /* copy client to server SMB */
// HL_LONGLONG ilc_read_position;           /* progress content received from client */
   struct dsd_cdf_ctrl dsc_cdf_ctrl;        /* compress data file oriented control */
   struct dsd_gather_i_1 dsrc_gai1_write[ MAX_INP_GATHER ];  /* output data */
};

struct dsd_cf_backlog {                     /* copy file backlog       */
   struct dsd_cf_backlog *adsc_next;        /* for chaining            */
   struct dsd_file_1 *adsc_f1_action;       /* entry of file current action */
   enum ied_action_state iec_acs;           /* state of action         */
};

enum ied_smb_conn_state {                   /* state of SMB connection */
   ied_scs_start = 0,                       /* start SMB connection    */
   ied_scs_connected,                       /* SMB connection connected */
   ied_scs_closed,                          /* SMB connection closed   */
   ied_scs_idle,                            /* idle, nothing to do     */
   ied_scs_echo,                            /* sent Echo - keep-alive  */
   ied_scs_query_dir,                       /* query-directory         */
   ied_scs_read_file,                       /* read file from server   */
   ied_scs_read_smb2ss_01,                  /* read file from server / open */
   ied_scs_read_smb2ss_end,                 /* read file from server / end */
   ied_scs_read_smb2cl_01,                  /* read file from server / open */
   ied_scs_read_smb2cl_02,                  /* read file from server / data */
   ied_scs_read_smb2cl_03,                  /* read file from server / close */
#ifdef WAS_BEFORE
// ied_scs_next_action,                     /* check for next action   */
#endif
   ied_scs_write_ss2smb_01,                 /* write file / open       */
   ied_scs_write_ss2smb_02,                 /* write file / write      */
   ied_scs_write_ss2smb_03,                 /* write file / rename     */
   ied_scs_write_ss2smb_04,                 /* write file / do close   */
   ied_scs_write_ss2smb_05,                 /* write file / did close  */
   ied_scs_write_cl2smb_01,                 /* write file / open       */
   ied_scs_write_cl2smb_02,                 /* write file / write      */
   ied_scs_write_wait,                      /* write file / wait for next input */
#ifdef XYZ1
   ied_scs_write_01,                        /* write file / open       */
   ied_scs_write_02,                        /* write file / write      */
   ied_scs_write_03,                        /* write file / set file info */
   ied_scs_write_04,                        /* write file / do close   */
   ied_scs_write_05,                        /* write file / did close  */
#endif
#ifdef XYZ1
   ied_scs_create_dir,                      /* create directory        */
   ied_scs_delete,                          /* delete file / directory */
#endif
   ied_scs_create_misc,                     /* SMB miscellaneous command */
   ied_scs_set_change_ntfy,                 /* set change notify       */
   ied_scs_del_change_ntfy,                 /* delete change notify    */
   ied_scs_wait                             /* wait for notify         */
};

struct dsd_dash_work_all {                  /* all dash operations work area */
   unsigned int umc_state;                  /* state of processing     */
#define DWA_STATE_DIR_CLIENT  0X01
#define DWA_STATE_DIR_SERVER  0X02
#define DWA_STATE_XML_SYNC    0X04
#define DWA_STATE_XML_WRITE   0X08
#define DWA_STATE_VCH_STARTED 0X10
#define DWA_STATE_VCH_ACT     0X20
#define DWA_STATE_2CL_NORMAL  0X40          /* send to client normal   */
#define DWA_STATE_2CL_COMPR   0X80          /* send to client compressed */
   BOOL       boc_virch_server;             /* virus checking data from server / SMB */
   BOOL       boc_virch_local;              /* virus checking data from local / client */
   BOOL       boc_put_cred;                 /* put / write credendials */
   int        imc_rl;                       /* remainder record not yet processed */
#ifdef XYZ1
// to-do 30.08.14 KB - move following two fields to dwa
// to-do 31.08.14 KB - acquire memory for dwa at start
   int        imc_proc_active_channels;     /* need to process active channels client  */
   BOOL       boc_reconnect;                /* reconnect from client successful */
#endif
   void *     vpc_sequ_handle;              /* handle of service query */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   HL_LONGLONG ulc_offset;                  /* Offset                  */
   struct dsd_gather_i_1 *adsc_gai1_in_from_client;  /* input data from client */
   struct dsd_dash_fc_execute dsc_dfcexe;   /* execute DASH file control */
   char       byrc_smbcc_in[ 512 ];
   struct dsd_dir_stack_1 dsrc_ds1[ MAX_DIR_STACK ];  /* stack entry directory */
   char       byrc_server_fn[ LEN_FILE_NAME ];
   int        imc_local_pos_fn_start;
   int        imc_local_pos_fn_end;
   int        imc_server_pos_fn_start;
   int        imc_server_pos_fn_end;
   struct dsd_cf_backlog *adsc_cf_backlog;  /* chain copy file backlog */
   struct dsd_cf_backlog *adsc_cf_bl_cur;   /* current entry copy file backlog */
   struct dsd_action_1 dsc_a1;              /* what action to do       */
   struct dsd_dir_work_2 dsc_dw2;           /* directory operations work area */
   union {
     struct dsd_work_in_dir_compr dsc_work_idc;  /* input directory compressed */
     struct dsd_work_in_file_vch dsc_work_ifvc;  /* input file with virus-checking */
     struct dsd_work_smb2cl dsc_work_smb2cl;  /* copy from SMB to client */
     struct dsd_work_ss2smb dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
     struct dsd_work_smb2ss dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
     struct dsd_work_ss2cl dsc_work_ss2cl;  /* copy from Swap Storage to client */
     struct dsd_work_cl2smb dsc_work_cl2smb;  /* copy client to server SMB */
   };
};

struct dsd_clib1_data_1 {                   /* structure session       */
   enum ied_cl_state iec_clst;              /* state of connection to client */
   enum ied_smb_conn_state iec_scs;         /* state of SMB connection */
   int        imc_client_protocol;          /* protocol of client      */
   int        imc_capabilities;             /* capabilities client     */
   int        imc_keepalive;                /* keepalive client        */
   int        imc_len_data_from_client;     /* input length data received from client */
// to-do 30.08.14 KB - move following two fields to dwa - not possible, dwa acquired later
   int        imc_proc_active_channels;     /* need to process active channels client */
   BOOL       boc_reconnect;                /* reconnect from client successful */
   BOOL       boc_smb_connected;            /* connected to SMB server */
   char       *achc_workstation_id;         /* address workstation-id  */
   char       *achc_profile;                /* address profile         */
   int        imc_len_workstation_id;       /* length workstation-id   */
   int        imc_len_profile;              /* length profile          */
#ifdef B150411
   int        imc_epoch_keepalive;          /* time to send keepalive  */
   int        imc_epoch_backlog;            /* time to process backlog */
#endif
   HL_LONGLONG ilc_epoch_keepalive;         /* time to send keepalive - seconds */
   HL_LONGLONG ilc_epoch_backlog;           /* time to process backlog - seconds */
#ifndef B150207
   HL_LONGLONG ilc_sum_size_local;          /* sum file size client    */
   HL_LONGLONG ilc_sum_size_server;         /* sum file size SMB server */
#endif
   HL_LONGLONG ilc_epoch_smb;               /* epoch last call to SMB  */
   char       *achc_sign_in;                /* storage for sign in     */
   struct dsd_conf_main dsc_cm;             /* configuration           */
   char       chrc_password[ MAX_PASSWORD ];  /* space need to store password when encrypted */
#ifdef XYZ1
//
   enum ied_relsstat_type iec_relsstat;     /* session status          */
#endif
   void *     ac_work_data;                 /* data for work           */
   void *     ac_conf_file_control;         /* configuration of file control */
   struct dsd_dir_bl_1 *adsc_db1_resync;    /* directory block 1 - state for resync */
   BOOL       boc_local_notify;             /* notify local / client is active */
   BOOL       boc_server_notify;            /* notify SMB server is active */
#ifdef XYZ1
   struct dsd_dir_bl_1 *adsc_db1_sync;      /* directory block 1 - synchonization */
   struct dsd_dir_bl_1 *adsc_db1_local;     /* directory block 1 - local */
   struct dsd_dir_bl_1 *adsc_db1_remote;    /* directory block 1 - remote */
#endif
#ifdef XYZ1
// 15.09.13 KB - the following fields are moved to struct dsd_dash_work_all
   char       chrc_file_id[ 16 ];           /* FileId                  */
   HL_LONGLONG ulc_offset;                  /* Offset                  */
   struct dsd_dash_fc_execute dsc_dfcexe;   /* execute DASH file control */
#endif
   struct dsd_hl_smb_cl_ctrl dsc_smbcl_ctrl;  /* HOBLink SMB Client Control */
   struct dsd_smbcc_in_cmd dsc_smbcc_in_cmd;  /* HOBLink SMB Client Control - input command */
#ifdef XYZ1
   char       byrc_smbcc_in[ 512 ];
   struct dsd_dir_stack_1 dsrc_ds1[ MAX_DIR_STACK ];  /* stack entry directory */
#endif
#ifdef TRACEHL1
   int        imh_len_inp_compr;
   int        imh_len_out_compr;
#endif
};

typedef int ( * amd_cmp_time_var_1 )( FILETIME *, FILETIME * );

struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* auxiliary callback routine pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   char       *achc_lower;                  /* work area lower address */
   char       *achc_upper;                  /* work area upper address */
   amd_cmp_time_var_1 amc_cmp_time_var_1;   /* routine to compare time values */
   struct dsd_gather_i_1 **aadsc_gai1_out_to_client;  /* output data to client */
   struct dsd_hl_clib_1 *adsc_hl_clib_1;    /* original structure      */
   struct dsd_clib1_data_1 *adsc_cl1d1_1;   /* structure session       */
   struct dsd_clib1_conf_1 *adsc_conf;      /* structure configuration */
};

struct dsd_mem_manage {                     /* manage memory           */
   struct dsd_mem_manage *adsc_next;        /* for chaining            */
};

struct dsd_xml_nesting {                    /* XML / DOM nesting       */
   void *     ac_node;                      /* node                    */
   struct dsd_unicode_string *adsc_ucs_node;  /* name of node          */
};

struct dsd_xml_2_mem {                      /* convert XML / DOM to memory */
   void *     vpc_node_conf;                /* part of configuration   */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* aux-call routine pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   void * (* amc_call_dom) ( void * vpp_userfld, void * vpp_node, ied_hlcldom_def );  /* call DOM */
   struct dsd_mem_manage *adsc_mem_ch;      /* chain of managed memory */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* gather of data          */
};

enum ied_prog_cont {                        /* continue in program     */
   ied_prco_nothing = 0,                    /* nothing more to do      */
   ied_prco_smb_change_ntfy                 /* SMB send change notify request */
};

#ifdef XYZ1
static const unsigned char ucrs_mask_attribute[ sizeof(unsigned int) ] = {
   (unsigned char) (-1 - FILE_ATTRIBUTE_ARCHIVE),
   (unsigned char) ((-1 - FILE_ATTRIBUTE_ARCHIVE) >> 8),
   (unsigned char) ((-1 - FILE_ATTRIBUTE_ARCHIVE) >> 16),
   (unsigned char) ((-1 - FILE_ATTRIBUTE_ARCHIVE) >> 24)
};
#endif

static const char * achrs_node_conf[] = {
   "send-error-messages-level",
   "log-level-share",
   "type-dash-proxy-configuration",
   "directory-dash-proxy-configuration",
   "type-dash-server-credentials",
   "directory-dash-server-credentials",
   "file-virus-checking-service",
   "file-virus-checking-maximum-file-size",
   "virus-checking-files-from-client",
   "virus-checking-files-from-server"
};

static const unsigned char ucrs_eye_catcher_protocol[] = {
   'H', 'O', 'B', ' ', 'D', 'A', 'S', 'H',
   ' ', 'V'
};

static const char chrs_cma_pwd_prefix[] = {
  'U', 'S', 'E', 'R', '-', 'P', 'W', 'D', 0
};

static const unsigned char ucrs_disk_dpc_start[] = {
   'D', 'A', 'S', 'H', '-', '-', '-'
};

static const unsigned char ucrs_disk_cred_start[] = {
   'U', 'C', '-', 'D', 'A', 'S', 'H', '-', '-', '-'
};

static const unsigned char ucrs_disk_separator[] = {
   '-', '-', '-'
};

static const unsigned char ucrs_disk_dpc_end[] = {
   '.', 'x', 'm', 'l'
};

static const unsigned char ucrs_disk_cred_end[] = {
   '.', 'd', 'a', 't'
};

static const unsigned char ucrs_cred_file_eyecatcher[] = {
   'H', 'O', 'B', ' ',
   'C', 'R', 'E', 'D', 'E', 'N', 'T', 'I', 'A', 'L', 'S', ' ',
   'V', '0', '1'
};

static const unsigned char ucrs_cred_file_separator[] = {
   CHAR_CR, CHAR_LF, 'P', 'W', 'D', ':'
};

static const unsigned char ucrs_xml_start[] = {
   '<', '?', 'x', 'm', 'l', ' ', 'v', 'e',
   'r', 's', 'i', 'o', 'n', '=',
   '\"', '1', '.', '0', '\"', ' ',
   'e', 'n', 'c', 'o', 'd', 'i', 'n', 'g',
   '=', '\"', 'u', 't', 'f', '-', '8', '\"',
   '?', '>',
   CHAR_CR, CHAR_LF,
   '<', 'd', 'a', 's', 'h', '-', 's', 'y',
   'n', 'c', 'h', 'r', 'o', 'n', 'i', 'z',
   'e', '-', 'f', 'i', 'l', 'e', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_end[] = {
   '<', '/', 'd', 'a', 's', 'h', '-', 's',
   'y', 'n', 'c', 'h', 'r', 'o', 'n', 'i',
   'z', 'e', '-', 'f', 'i', 'l', 'e', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_dir_start[] = {
   ' ', ' ',
   '<', 'd', 'i', 'r', 'e', 'c', 't', 'o',
   'r', 'y', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_dir_end[] = {
   ' ', ' ',
   '<', '/', 'd', 'i', 'r', 'e', 'c', 't',
   'o', 'r', 'y', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_file_start[] = {
   ' ', ' ',
   '<', 'f', 'i', 'l', 'e', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_file_end[] = {
   ' ', ' ',
   '<', '/', 'f', 'i', 'l', 'e', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_entry_t01[] = {
   ' ', ' ', ' ', ' ',
   '<', 'n', 'a', 'm', 'e', '>'
};

static const unsigned char ucrs_xml_entry_t02[] = {
   '<', '/', 'n', 'a', 'm', 'e', '>',
   CHAR_CR, CHAR_LF,
   ' ', ' ', ' ', ' ',
   '<', 'a', 't', 't', 'r', 'i', 'b', 'u',
   't', 'e', 's', '>', '0', 'X'
};

static const unsigned char ucrs_xml_entry_t03[] = {
   '<', '/', 'a', 't', 't', 'r', 'i', 'b',
   'u', 't', 'e', 's', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_entry_t04[] = {
   ' ', ' ', ' ', ' ',
   '<', 'l', 'a', 's', 't', '-', 'w', 'r',
   'i', 't', 'e', '-', 't', 'i', 'm', 'e',
   '>'
};

static const unsigned char ucrs_xml_entry_t05[] = {
   '<', '/', 'l', 'a', 's', 't', '-', 'w',
   'r', 'i', 't', 'e', '-', 't', 'i', 'm',
   'e', '>',
   CHAR_CR, CHAR_LF,
   ' ', ' ', ' ', ' ',
   '<', 's', 'i', 'z', 'e', '>'
};

static const unsigned char ucrs_xml_entry_t06[] = {
   '<', '/', 's', 'i', 'z', 'e', '>',
   CHAR_CR, CHAR_LF
};

#ifdef XYZ1
// to-do 12.05.13 KB - virus
static unsigned char ucrs_xml_entry_virus_sta[] = {
   ' ', ' ', ' ', ' ',
   '<', 'v', 'i', 'r', 'u', 's', '>'
};

static unsigned char ucrs_xml_entry_virus_end[] = {
   '<', '/', 'v', 'i', 'r', 'u', 's', '>',
   CHAR_CR, CHAR_LF
};
#endif

static const unsigned char ucrs_xml_entry_state_sta[] = {
   ' ', ' ', ' ', ' ',
   '<', 'e', 'r', 'r', 'o', 'r', '-', 's', 't', 'a', 't', 'e', '>', '0', 'X'
};

static const unsigned char ucrs_xml_entry_state_end[] = {
   '<', '/', 'e', 'r', 'r', 'o', 'r', '-', 's', 't', 'a', 't', 'e', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_entry_virus_client_sta[] = {
   ' ', ' ', ' ', ' ',
   '<', 'v', 'i', 'r', 'u', 's', '-', 'c', 'l', 'i', 'e', 'n', 't', '>'
};

static const unsigned char ucrs_xml_entry_virus_client_end[] = {
   '<', '/', 'v', 'i', 'r', 'u', 's', '-', 'c', 'l', 'i', 'e', 'n', 't', '>',
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_xml_entry_virus_server_sta[] = {
   ' ', ' ', ' ', ' ',
   '<', 'v', 'i', 'r', 'u', 's', '-', 's', 'e', 'r', 'v', 'e', 'r', '>'
};

static const unsigned char ucrs_xml_entry_virus_server_end[] = {
   '<', '/', 'v', 'i', 'r', 'u', 's', '-', 's', 'e', 'r', 'v', 'e', 'r', '>',
   CHAR_CR, CHAR_LF
};

static const char * achrs_conf_level_1[] = {
   "SMB-server",
   "local",
   "synchronize-file",
   "synchronize-function",
   "file-control",
   "send-error-messages-level",
   "log-level-share"
};

#define KW_CONF_L1_SERVER    0
#define KW_CONF_L1_LOCAL     1
#define KW_CONF_L1_SYNC_FILE 2
#define KW_CONF_L1_SYNC_FN   3
#define KW_CONF_L1_FILE_CTRL 4
#define KW_CONF_L1_SEML      5
#define KW_CONF_L1_LOG_LS    6

static const char * achrs_conf_server_l_2[] = {
   "serverineta",
   "serverport",
   "sign-on-credentials",
   "domain",
   "userid",
   "password-plain",
   "password-encrypted",
   "Windows-file-system",
   "SMB-tree-name",
   "directory",
   "create-shared-directory",
   "temporary-file",
   "disk-quota",
   "always-send-echo",
   "interval-echo"
};

#define KW_CONF_L2_SE_SINETA 0
#define KW_CONF_L2_SE_SPORT  1
#define KW_CONF_L2_SE_SOCRED 2
#define KW_CONF_L2_SE_DOMAIN 3
#define KW_CONF_L2_SE_USERID 4
#define KW_CONF_L2_SE_PWD_PL 5
#define KW_CONF_L2_SE_PWD_EN 6
#define KW_CONF_L2_SE_WIN_FS 7
#define KW_CONF_L2_SE_TREE   8
#define KW_CONF_L2_SE_DIR    9
#define KW_CONF_L2_SE_CSD    10
#define KW_CONF_L2_SE_TEMP_F 11
#define KW_CONF_L2_SE_D_QUOTA 12
#define KW_CONF_L2_SE_AS_ECHO 13
#define KW_CONF_L2_SE_INTV_ECHO 14

static const char * achrs_conf_local_l_2[] = {
   "directory",
   "create-shared-directory",
   "temporary-file",
   "disk-quota",
   "time-keepalive"
};

#define KW_CONF_L2_LO_DIR    0
#define KW_CONF_L2_LO_CSD    1
#define KW_CONF_L2_LO_TEMP_F 2
#define KW_CONF_L2_LO_D_QUOTA 3
#define KW_CONF_L2_LO_KEEP_A 4

static const char * achrs_conf_sync_f_l_2[] = {
   "type",
   "filename"
};

#define KW_CONF_L2_SYNCF_TYPE 0
#define KW_CONF_L2_SYNCF_FN  1

struct dsd_conf_s2at_type_tab {             /* type sign-on-credentials */
   const char       *achc_name;
   enum ied_smb2_auth_type iec_s2at;        /* SMB2 authentication type */
};

static const struct dsd_conf_s2at_type_tab dsrs_conf_s2at_type_tab[] = {
   {
     "configured",
     ied_s2at_xml_conf                      /* domain, userid, password configured */
   },
   {
     "Kerberos-5",
     ied_s2at_krb5                          /* Kerberos 5              */
   },
   {
     "credential-cache",
     ied_s2at_cred_cache                    /* single sign on with WSP credentials */
   },
   {
     "ask-user-for-password",
     ied_s2at_ask_user_pwd                  /* ask user for password   */
   }
};

struct dsd_conf_syncf_type_tab {            /* type synchronize-file   */
   const char       *achc_name;
   enum ied_sync_file_type iec_syft;        /* synchronize-file type   */
};

static const struct dsd_conf_syncf_type_tab dsrs_conf_syncf_type_tab[] = {
   {
     "local-file-01",
     ied_syft_local_file_01                 /* local-file-01           */
   },
   {
     "local-file-02",
     ied_syft_local_file_02                 /* local-file-02           */
   },
   {
     "service-file-01",
     ied_syff_serv_file_01                  /* service-file-01         */
   },
   {
     "service-file-02",
     ied_syff_serv_file_02                  /* service-file-02         */
   },
   {
     "LDAP",
     ied_syff_ldap                          /* LDAP                    */
   }
};

static const char * achrs_conf_sync_fu_l_2[] = {
   "both-directions",
   "read-from-client",
   "read-from-server"
};

#define KW_CONF_L2_SF_DUPLEX 0
#define KW_CONF_L2_SF_READ_C 1
#define KW_CONF_L2_SF_READ_S 2

static const char * achrs_kw_level_1[] = {
   "directory",
   "file"
};

#define KW_L1_DIR            0
#define KW_L1_FILE           1

static const char * achrs_kw_level_2[] = {
   "name",
   "attributes",
   "last-write-time",
   "size",
   "error-state",
   "virus-client",
   "virus-server"
};

#define KW_L2_NAME           0
#define KW_L2_ATTR           1
#define KW_L2_LWT            2
#define KW_L2_SIZE           3
#define KW_L2_STATE          4
#define KW_L2_VIR_CL         5
#define KW_L2_VIR_SE         6

static const unsigned char ucrs_node_separator[] = {
   '<', '/'
};

static const unsigned char ucrs_node_end[] = {
// '>', CHAR_CR, CHAR_LF
   CHAR_CR, CHAR_LF
};

static const unsigned char ucrs_dash_send_set_ch_notify[] = {
   0X05,                                    /* length record           */
   0X01,                                    /* channel                 */
   DASH_DCH_SE2CL_SET_CH_NOTIFY,            /* set change notify       */
   0X02, 0X01, 0X00                         /* notify token            */
};

static const unsigned char ucrs_dash_send_del_ch_notify[] = {
   0X03,                                    /* length record           */
   0X01,                                    /* channel                 */
   DASH_DCH_SE2CL_DEL_CH_NOTIFY,            /* delete change notify    */
   0X00                                     /* notify token            */
};

static const unsigned char ucrs_dash_send_all_dir[] = {
   0X05,                                    /* length record           */
   0X01,                                    /* channel                 */
// to-do 23.03.16 KB - 0X10 should be defined in hob-dash-01.h
   0X10,                                    /* send all directories    */
   0X02, 0X01, 0X01                         /* with compression        */
};

static const unsigned char ucrs_dash_send_cred[] = {
   0X03,                                    /* length record           */
   0X00,                                    /* channel                 */
   DASH_DCH_SE2CL_CREDENTIALS,
   0X01                                     /* password                */
};

static const unsigned char ucrs_keepalive[] = {
   0X02,                                    /* length packet           */
   0,                                       /* channel - control channel */
   0X7F                                     /* tag keepalive           */
};

static const HL_WCHAR wcrs_ignore_fn[ 2 ] = { '.', '.' };

#ifndef COMPR_RL
/** for zLib compresssion                                              */
static const unsigned char ucrs_eye_catcher[8] =
  { 0X48, 0X4F, 0X42, 0XC8, 0XD6, 0XC2, 0XFE, 0X02 };
#else
/** for run-length compression                                         */
static const unsigned char ucrs_eye_catcher[8] =
  { 0X48, 0X4F, 0X42, 0XC8, 0XD6, 0XC2, 0XFE, 0X00 };
#endif

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static BOOL m_proc_xml_conf( struct dsd_sdh_call_1 *, struct dsd_clib1_data_1 *, char *, int );
static void * m_call_xml_dom( void * vpp_userfld, void * vpp_node, ied_hlcldom_def iep_hlcldom_def );
static BOOL m_xml_aux( void * vpp_userfld, int iml_func, void * adsp_param, int imp_length );
static int m_get_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1, struct dsd_sdh_ident_set_1 *adsp_g_idset1 );
static BOOL m_put_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1 );
static int m_filename_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                       struct dsd_sdh_ident_set_1 *adsp_g_idset1,
                                       char **aachp_fn_last,
                                       char *achp_buf_start, char *achp_buf_end );
#ifdef XYZ1
static BOOL m_xml_2_mem( struct dsd_xml_2_mem * );
#endif
static int m_build_file_name_utf8( struct dsd_sdh_call_1 *, struct dsd_file_1 *, char *, char );
static int m_get_input_nhasn( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_gather_i_1 **aadsp_gai1_inp_rp,
                              char **aachp_rp,
                              int *aimp_rec_len );
static BOOL m_copy_from_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                struct dsd_gather_i_1 **aadsp_gai1_inp_rp,
                                char **aachp_rp,
                                char *achp_target,
                                int imp_len );
static BOOL m_check_input_complete( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_rp,
                                    char *achp_rp,
                                    int imp_rec_len );
static BOOL m_consume_input_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_all,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_rp,
                                    char *achp_rp );
static BOOL m_next_action( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                           struct dsd_action_1 *adsp_a1 );
static BOOL m_work_vc_init( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                            struct dsd_work_vch_1 *adsp_wvc1,  /* virus-checking */
                            struct dsd_dash_work_all *adsp_dwa,  /* all dash operations work area */
                            char *achp_filename, int imp_len_filename );
static BOOL m_work_vc_end( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                           struct dsd_work_vch_1 *adsp_wvc1,  /* virus-checking */
                           struct dsd_dash_work_all *adsp_dwa,  /* all dash operations work area */
                           char *achp_end, BOOL *abop_call_vc );
static BOOL m_read_xml_sync_file( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                  struct dsd_unicode_string *adsp_ucs_fn,
                                  struct dsd_dir_bl_1 **aadsp_db1,
                                  HL_LONGLONG * );
static BOOL m_create_xml_dir( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_xml_dir_bl **aadsp_xdb, struct dsd_dir_bl_1 *adsp_db1 );
static BOOL m_write_xml_sync_file( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                   struct dsd_unicode_string *adsp_ucs_fn, struct dsd_xml_dir_bl *adsp_xdb );
static BOOL m_dir_free( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                        struct dsd_dir_bl_1 *adsp_db1 );
static int m_cmp_file( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#ifdef B150411
static int m_cmp_longlong_1( char *, char * );
#endif
static int m_cmp_time_win_1( FILETIME *, FILETIME * );
static int m_cmp_time_unix_1( FILETIME *, FILETIME * );
#ifdef B140102
static int m_cmp_longlong_2( char *, HL_LONGLONG );
#endif
static inline void m_get_le4( int *aimp_out, char *achp_source );
static inline void m_get_le8( HL_LONGLONG *ailp_out, char *achp_source );
static int m_get_ucs_int( struct dsd_unicode_string * );
static BOOL m_get_ucs_hex( unsigned int *aump_p, struct dsd_unicode_string *adsp_ucs_p );
static BOOL m_get_ucs_longlong( HL_LONGLONG *aulp_p, struct dsd_unicode_string *adsp_ucs_p );
static unsigned int m_unix_file_time( FILETIME *adsp_ft );
static void * m_sub_alloc( void *, size_t );
static void m_sub_free( void *, void * );
static BOOL m_sub_aux( void *, int, void *, int );
#ifdef TRACEHL1
static void m_trace_dir( struct dsd_sdh_call_1 *, struct dsd_dir_bl_1 *, char * );
#endif
static int m_sdh_msg_cl( struct dsd_sdh_call_1 *adsp_sdh_call_1, int imp_cn, int imp_tag, const char *achptext, ... );
static int m_sdh_printf( struct dsd_sdh_call_1 *, const char *, ... );
static void m_sdh_msg_log_tr( struct dsd_sdh_call_1 *adsp_sdh_call_1, BOOL bop_log, const char *achptext, ... );
#ifdef DEBUG_140823_01
static void m_print_gather( struct dsd_sdh_call_1 *, int, char *, struct dsd_gather_i_1 * );
#endif
#ifdef DEBUG_170410_01                      /* address adsc_file_1_parent invalid */
static void m_check_parent_1( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_dir_bl_1 *adsp_db1_check,  /* directory block 1 */
                              char *achp_text, int imp_line );
#endif  /* DEBUG_170410_01                     address adsc_file_1_parent invalid */

/*+-------------------------------------------------------------------+*/
/*| Entries for the Server-Data-Hook.                                 |*/
/*+-------------------------------------------------------------------+*/

/** subroutine to process the configuration data                       */
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_hlcldomf ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol1, bol2;                   /* working variables       */
   int        iml_cmp;                      /* compare values          */
   HL_WCHAR   *awcl_dir_dpc;                /* directory-dash-proxy-configuration */
   HL_WCHAR   *awcl_dir_cred;               /* directory-dash-server-credentials */
   HL_WCHAR   *awcl_file_vch_serv;          /* file virus-checking service name */
   BOOL       borl_double[10];              /* check if defined double */
   int        iml_val;                      /* value in array          */
   DOMNode    *adsl_node_1;                 /* node for navigation     */
   DOMNode    *adsl_node_2;                 /* node for navigation     */
   HL_WCHAR   *awcl1;                       /* working variable        */
   HL_WCHAR   *awcl_value;                  /* value of Node           */
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_clib1_conf_1 dsl_cc_l;        /* configuration           */

#ifdef TRACEHL1
   printf( "xl-sdh-dash-01-l%05d-T m_hlclib_conf() called adsp_hlcldomf=%p.\n",
           __LINE__, adsp_hlcldomf );
#endif
   dsl_sdh_call_1.amc_aux = adsp_hlcldomf->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hlcldomf->vpc_userfld;  /* User Field Subroutine */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I V1.2 " __DATE__ " m_hlclib_conf() called",
                 __LINE__ );

   if (adsp_hlcldomf->adsc_node_conf == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_hlclib_conf() no Node configured",
                   __LINE__ );
     return FALSE;
   }

   /* getFirstChild()                                                  */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsp_hlcldomf->adsc_node_conf,
                                                          ied_hlcldom_get_first_child );
   if (adsl_node_1 == NULL) {               /* no Node returned        */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_hlclib_conf() no getFirstChild()",
                   __LINE__ );
     return FALSE;
   }

   memset( &dsl_cc_l, 0, sizeof(struct dsd_clib1_conf_1) );  /* configuration */
   awcl_dir_dpc = NULL;                     /* directory-dash-proxy-configuration */
   awcl_dir_cred = NULL;                    /* directory-dash-server-credentials */
   awcl_file_vch_serv = NULL;               /* reset file virus-checking service name */
   memset( borl_double, 0, sizeof(borl_double) );  /* reset check if defined double */

   pdomc20:                                 /* process DOM node        */
   if (((int) (size_t) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_type ))
         != DOMNode::ELEMENT_NODE) {
     goto pdomc80;                          /* get next sibling        */
   }
   awcl1 = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_1, ied_hlcldom_get_node_name );
#ifdef TRACEHL1
#ifndef HL_UNIX
   printf( "xl-sdh-dash-01-l%05d-T m_hlclib_conf() found node %S\n", __LINE__, awcl1 );
#endif
#endif
   iml_val = sizeof(achrs_node_conf) / sizeof(achrs_node_conf[0]);
   do {
     bol1 = m_cmp_u16z_u8z( &iml_cmp, awcl1, (char *) achrs_node_conf[ iml_val - 1 ] );
     if ((bol1) && (iml_cmp == 0)) break;   /* strings are equal       */
     iml_val--;                             /* decrement index         */
   } while (iml_val > 0);
   if (iml_val == 0) {                      /* parameter not found     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" not defined - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (adsl_node_2 == NULL) {               /* no child found          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" has no child - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   do {                                     /* search value            */
     if (((int) (size_t) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_type ))
           == DOMNode::TEXT_NODE) break;
     adsl_node_2 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_2,
                                                            ied_hlcldom_get_next_sibling );
   } while (adsl_node_2);
   if (adsl_node_2 == NULL) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" no value found - ignored",
                   __LINE__, awcl1 );
     goto pdomc80;                          /* DOM node processed - next */
   }
   awcl_value = (HL_WCHAR *) adsp_hlcldomf->amc_call_dom( adsl_node_2, ied_hlcldom_get_node_value );  /* getNodeValue() */
   bol1 = TRUE;                             /* value not double        */
   switch (iml_val) {                       /* depending on keyword found */
     case (0 + 1):                          /* <send-error-messages-level> */
       if (borl_double[0]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.imc_seml = m_get_wc_number( awcl_value );
       if (dsl_cc_l.imc_seml >= 0) {        /* value is valid          */
         borl_double[0] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" not numeric - ignored",
                     __LINE__, awcl1, awcl_value );
       dsl_cc_l.imc_seml = 0;               /* value not configured    */
       break;
     case (1 + 1):                          /* <log-level-share>       */
       if (borl_double[1]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.imc_log_ls = m_get_wc_number( awcl_value );
       if (dsl_cc_l.imc_seml >= 0) {        /* value is valid          */
         borl_double[1] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" not numeric - ignored",
                     __LINE__, awcl1, awcl_value );
       dsl_cc_l.imc_log_ls = 0;             /* value not configured    */
       break;
     case (2 + 1):                          /* <type-dash-proxy-configuration> */
       if (borl_double[2]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "local-file-01" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         dsl_cc_l.iec_tdpc = ied_tdpc_local_file_01;  /* local-file-01 */
         borl_double[2] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value not local-file-01 - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case (3 + 1):                          /* <directory-dash-proxy-configuration> */
       if (awcl_dir_dpc) {                  /* check directory-dash-proxy-configuration */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       awcl_dir_dpc = awcl_value;           /* set directory-dash-proxy-configuration */
       break;
     case (4 + 1):                          /* <type-dash-server-credentials> */
       if (borl_double[4]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "local-file-01" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         dsl_cc_l.iec_cred_tdpc = ied_tdpc_local_file_01;  /* local-file-01 */
         borl_double[4] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value not local-file-01 - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case (5 + 1):                          /* <directory-dash-server-credentials> */
       if (awcl_dir_cred) {                 /* check directory-dash-server-credentials */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       awcl_dir_cred = awcl_value;          /* set directory-dash-server-credentials */
       break;
     case (6 + 1):                          /* <file-virus-checking-service> */
       if (awcl_file_vch_serv) {            /* check file virus-checking service name */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       awcl_file_vch_serv = awcl_value;     /* set file virus-checking service name */
       break;
     case (7 + 1):                          /* <file-virus-checking-maximum-file-size> */
       if (dsl_cc_l.ilc_max_file_size) {    /* value already defined   */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       dsl_cc_l.ilc_max_file_size = m_get_bytes_no( awcl_value );  /* maximum file-size */
       if (dsl_cc_l.ilc_max_file_size > 0) {  /* value is valid        */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value not valid size in bytes - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       dsl_cc_l.ilc_max_file_size = 0;      /* value not set           */
       break;
     case (8 + 1):                          /* <virus-checking-files-from-client> */
       if (borl_double[8]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         dsl_cc_l.boc_virch_local = TRUE;   /* virus checking data from local / client */
         borl_double[8] = TRUE;             /* set check if defined double */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         borl_double[8] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
     case (9 + 1):                          /* <virus-checking-files-from-server> */
       if (borl_double[9]) {                /* check if defined double */
         bol1 = FALSE;                      /* value double            */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "YES" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         dsl_cc_l.boc_virch_server = TRUE;  /* virus checking data from server / WSP */
         borl_double[9] = TRUE;             /* set check if defined double */
         break;
       }
       bol2 = m_cmp_u16z_u8z( &iml_cmp, awcl_value, "NO" );
       if ((bol2) && (iml_cmp == 0)) {      /* strings are equal       */
         borl_double[9] = TRUE;             /* set check if defined double */
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value neither YES nor NO - \"%(ux)s\" - ignored",
                     __LINE__, awcl1, awcl_value );
       break;
   }
   if (bol1 == FALSE) {                     /* value is double         */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Error element \"%(ux)s\" value \"%(ux)s\" already defined before - ignored",
                   __LINE__, awcl1, awcl_value );
   }

   pdomc80:                                 /* DOM node processed - next */
   adsl_node_1 = (DOMNode *) adsp_hlcldomf->amc_call_dom( adsl_node_1,
                                                          ied_hlcldom_get_next_sibling );
   if (adsl_node_1) goto pdomc20;           /* process DOM node        */

   if (dsl_cc_l.iec_tdpc == ied_tdpc_invalid) {  /* invalid            */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W \"type-dash-proxy-configuration\" not set - set to default \"local-file-01\"",
                   __LINE__ );
     dsl_cc_l.iec_tdpc = ied_tdpc_local_file_01;  /* local-file-01     */
   }

   while (awcl_dir_dpc) {                   /* directory-dash-proxy-configuration */
     dsl_cc_l.imc_len_dir_dpc = m_len_vx_vx( ied_chs_utf_8,
                                             awcl_dir_dpc, -1, ied_chs_utf_16 );
     if (dsl_cc_l.imc_len_dir_dpc > 0) break;
// to-do 21.09.14 KB - error message
     dsl_cc_l.imc_len_dir_dpc = 0;
     break;
   }

   while (awcl_dir_cred) {                  /* directory-dash-server-credentials */
     dsl_cc_l.imc_len_dir_cred = m_len_vx_vx( ied_chs_utf_8,
                                              awcl_dir_cred, -1, ied_chs_utf_16 );
     if (dsl_cc_l.imc_len_dir_cred > 0) break;
// to-do 21.09.14 KB - error message
     dsl_cc_l.imc_len_dir_cred = 0;
     break;
   }

   while (awcl_file_vch_serv) {             /* file virus-checking service name */
     if (   (dsl_cc_l.boc_virch_local == FALSE)  /* virus checking data from local / client */
         && (dsl_cc_l.boc_virch_server == FALSE)) {  /* virus checking data from server / WSP */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W \"file-virus-checking-service\" set but neither \"virus-checking-files-from-client\" nor \"virus-checking-files-from-server\" - Virus-Checking not activated",
                     __LINE__ );
       break;
     }
     dsl_cc_l.imc_len_file_vch_serv = m_len_vx_vx( ied_chs_utf_8,
                                                   awcl_file_vch_serv, -1, ied_chs_utf_16 );
     if (dsl_cc_l.imc_len_file_vch_serv > 0) break;
// to-do 21.09.14 KB - error message
     dsl_cc_l.imc_len_file_vch_serv = 0;
     break;
   }
   if (   (dsl_cc_l.ilc_max_file_size)      /* maximum file-size       */
       && (dsl_cc_l.imc_len_file_vch_serv == 0)) {  /* no virus checking */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W no \"file-virus-checking-service\" but \"file-virus-checking-maximum-file-size\" - file-virus-checking-maximum-file-size ignored",
                   __LINE__ );
     dsl_cc_l.ilc_max_file_size = 0;        /* maximum file-size       */
   }

   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    adsp_hlcldomf->aac_conf,
                                    sizeof(struct dsd_clib1_conf_1)
                                      + dsl_cc_l.imc_len_dir_dpc  /* length directory name dash-proxy-configuration */
                                      + dsl_cc_l.imc_len_dir_cred  /* length directory name dash-server-credentials */
                                      + dsl_cc_l.imc_len_file_vch_serv );  /* structure configuration */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
#define ADSL_CC1 ((struct dsd_clib1_conf_1 *) (*adsp_hlcldomf->aac_conf))  /* structure configuration */
   memcpy( ADSL_CC1, &dsl_cc_l, sizeof(struct dsd_clib1_conf_1) );
   if (dsl_cc_l.imc_len_dir_dpc) {          /* length directory name dash-proxy-configuration */
#ifdef B160808
     m_cpy_vx_vx( ADSL_CC1 + 1, dsl_cc_l.imc_len_dir_cred, ied_chs_utf_8,
                  awcl_dir_dpc, -1, ied_chs_utf_16 );
#endif
     m_cpy_vx_vx( ADSL_CC1 + 1, dsl_cc_l.imc_len_dir_dpc, ied_chs_utf_8,
                  awcl_dir_dpc, -1, ied_chs_utf_16 );
   }
   if (dsl_cc_l.imc_len_dir_cred) {         /* length directory name dash-server-credentials */
     m_cpy_vx_vx( (char *) (ADSL_CC1 + 1) + dsl_cc_l.imc_len_dir_dpc, dsl_cc_l.imc_len_dir_cred, ied_chs_utf_8,
                  awcl_dir_cred, -1, ied_chs_utf_16 );
   }
   if (dsl_cc_l.imc_len_file_vch_serv) {
     m_cpy_vx_vx( (char *) (ADSL_CC1 + 1) + dsl_cc_l.imc_len_dir_dpc + dsl_cc_l.imc_len_dir_cred, dsl_cc_l.imc_len_file_vch_serv, ied_chs_utf_8,
                  awcl_file_vch_serv, -1, ied_chs_utf_16 );
   }
   return TRUE;
#undef ADSL_CC1
} /* end m_hlclib_conf()                                               */

/** subroutine to process the copy library function                    */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_cmp;                      /* for compare             */
   int        iml_port;                     /* fill with port number   */
   int        iml_rl;                       /* record length           */
   int        iml_cn;                       /* channel number          */
   int        iml_tag;                      /* tag of record           */
   int        iml_st;                       /* sub-tag of field        */
   int        iml_flags;                    /* flags                   */
   int        iml_len_directory;            /* length of directory     */
   int        iml_len_workstation_id;       /* length workstation-id   */
   int        iml_len_profile;              /* length profile          */
   int        iml_seml;                     /* <send-error-messages-level> */
   int        iml_use_log_ls;               /* use log-level-share     */
#ifdef XYZ1
   int        iml_active_channels;          /* active channels client  */
#endif
   int        iml_error_1, iml_error_2, iml_error_3;  /* values received error */
#ifdef B150411
//#ifdef B150331
   int        iml_epoch_cur;                /* time when called        */
//#endif
#endif
   int        iml_send;                     /* count data to send      */
   int        iml_in_gather;                /* count data in gather    */
#ifdef TRACEHL1
   int imh_len_compr;
#endif
   BOOL       bol1;                         /* working variable        */
   char       chl1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_call_smb_cl;              /* call SMB client         */
#ifdef XYZ1
   BOOL       bol_next_action;              /* find the next action to do */
#endif
   BOOL       bol_call_vc;                  /* call virus-checking     */
   BOOL       bol_resync_lo_re;             /* TRUE means remote       */
   BOOL       bol_put_cred;                 /* put / write credendials */
#ifdef XYZ1
#ifdef TRACEHL1
   char       chl1;                         /* working variable        */
#endif
#endif
   enum ied_prog_cont iel_prco;             /* continue in program     */
   HL_LONGLONG ill_epoch_cur;               /* time when called        */
   HL_LONGLONG ill_epoch_smb;               /* time when SMB2 Echo needs to be sent */
   HL_LONGLONG ill_w1;                      /* working variable        */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4, *achl_w5;  /* working variables */
   const char *achl_wc1, *achl_wc2;         /* working variables */
   char       *achl_workstation_id;         /* address workstation-id  */
   char       *achl_profile;                /* address profile         */
   struct dsd_file_1 *adsl_f1_w1;           /* entry of a single file  */
   char       *achl_rp;                     /* read pointer in block   */
   struct dsd_smbcc_out_cmd *adsl_smbcc_out_w1;  /* output command     */
   struct dsd_unicode_string *adsl_ucs_dir_w1;  /* pointer to directory name */
   struct dsd_clib1_data_1 *adsl_cl1;       /* for addressing          */
   struct dsd_clib1_conf_1 *adsl_conf;      /* structure configuration */
   struct dsd_dash_work_all *adsl_dwa;      /* all dash operations work area */
   struct dsd_work_in_file_vch_normal *adsl_dwifvn;  /* input file normal with virus-checking */
   struct dsd_work_in_file_vch *adsl_dwifvc;  /* input file compressed with virus-checking */
   struct dsd_work_vch_1 *adsl_wvc1;        /* virus-checking          */
   struct dsd_cdf_ctrl *adsl_cdf_ctrl;      /* compress data file oriented control */
   struct dsd_work_ss2smb *adsl_wss2smb;    /* copy from Swap Storage to SMB */
   struct dsd_work_smb2cl *adsl_wsmb2cl;    /* copy from SMB to client */
   struct dsd_work_smb2ss *adsl_wsmb2ss;    /* copy from SMB to Swap Storage */
   struct dsd_work_ss2cl *adsl_wss2cl;      /* copy from Swap Storage to client */
   struct dsd_work_cl2smb *adsl_wcl2smb;    /* copy client to server SMB */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_cur;  /* current element in chain */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_last;  /* last element in chain */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_w1;  /* temporary element in chain */
   struct dsd_action_1 *adsl_a1;            /* what action to do       */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_2;  /* input data              */
#ifdef DEBUG_140925_01
   struct dsd_gather_i_1 *adsl_gai1_inp_check;  /* check input data    */
#endif
#ifdef XYZ1
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#endif
   struct dsd_gather_i_1 **aadsl_gai1_ch1;  /* chain of gather         */
   struct dsd_cf_backlog *adsl_cf_backlog_w1;  /* copy file backlog    */
   struct dsd_cf_backlog *adsl_cf_backlog_w2;  /* copy file backlog    */
   struct dsd_wsp_trace_record **aadsl_wtr_w1;
   union {
     struct dsd_work_in_dir_compr *adsl_work_idc;  /* input directory compressed */
     struct dsd_xml_dir_bl *adsl_xdb_w1;    /* XML directory block - chaining */
   };
   struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
   struct dsd_unicode_string dsl_ucs_file_l;  /* name of file          */
   struct dsd_dir_work_1 dsl_dw1;           /* directory operations work area */
   struct dsd_dir_work_2 dsl_dw2;           /* directory operations work area */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
   union {
#ifdef XYZ1
     struct sockaddr_in6 dsl_soa_l;
     struct dsd_aux_get_session_info dsl_agsi;  /* get information about the session */
     struct dsd_sdh_ident_set_1 dsl_g_idset1;  /* settings for given ident */
#endif
#ifdef B130919
     struct dsd_hl_aux_diskfile_1 dsl_aux_df1_1;  /* diskfile request  */
#endif
     struct dsd_aux_file_io_req_1 dsl_fior1;  /* file IO request       */
     struct dsd_hl_aux_c_cma_1 dsl_accma1;    /* command common memory area */
     struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR      */
     struct dsd_aux_tcp_conn_1 dsl_atc1_1;  /* TCP Connect to Server   */
     struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query   */
     struct dsd_aux_swap_stor_req_1 dsl_astr1;  /* swap storage request */
     struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
     struct dsd_timer1_ret dsl_timer1_ret;  /* timer return values     */
     struct dsd_wsp_trace_header dsl_wtrh;  /* WSP trace header        */
   };
   struct dsd_sdh_ident_set_1 dsl_g_idset1;  /* settings for given ident */
   char       byrl_server_fn[ LEN_FILE_NAME ];
   char       byrl_work1[ 2048 ];           /* work area               */

   dsl_sdh_call_1.amc_aux = adsp_hl_clib_1->amc_aux;  /* auxiliary subroutine */
   dsl_sdh_call_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;  /* User Field Subroutine */
   dsl_sdh_call_1.adsc_hl_clib_1 = adsp_hl_clib_1;  /* original structure */
#ifdef WA_160809_01
   adsl_dwa = NULL;                         /* all dash operations work area */
   adsl_a1 = NULL;
#endif
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
#ifdef DEBUG_140823_01
       if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_hlclib01() called DEF_IFUNC_TOSERVER chain of gather input adsl_gai1_inp_1=%p.",
                       __LINE__, adsl_gai1_inp_1 );
       }
#endif
       iml2++;
       iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (   (adsl_gai1_inp_1->achc_ginp_end > adsl_gai1_inp_1->achc_ginp_cur)
           && (bol1 == FALSE)) {
         chl1 = *adsl_gai1_inp_1->achc_ginp_cur;
         bol1 = TRUE;
       }
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_hlclib01() called inc_func=%d %s signal=%08X boc_send_client_blocked=%d input=%p len=%d pieces=%d cont=0X%02X.",
                   __LINE__, adsp_hl_clib_1->inc_func, achh_text,
                   adsp_hl_clib_1->imc_signal,
                   adsp_hl_clib_1->boc_send_client_blocked,
                   adsp_hl_clib_1->adsc_gather_i_1_in, iml1, iml2, (unsigned char) chl1 );
   }
   iml_rl = iml_in_gather = iml1 = 0;
   adsl_gai1_inp_1 = NULL;
#endif
#ifdef XYZ1
#define CHRL_WORK_1 adsp_hl_clib_1->achc_work_area
#define CHRL_WORK_2 (adsp_hl_clib_1->achc_work_area + 512)
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) (adsp_hl_clib_1->achc_work_area + adsp_hl_clib_1->inc_len_work_area - sizeof(struct dsd_gather_i_1)))
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
       adsl_cl1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
       adsl_cl1->dsc_cm.imc_server_echo = -1;  /* server <interval-echo> */
       adsl_cl1->dsc_cm.imc_seml = -1;      /* <send-error-messages-level> */
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
   }
   dsl_sdh_call_1.achc_lower = adsp_hl_clib_1->achc_work_area;  /* work area lower address */
   dsl_sdh_call_1.achc_upper = dsl_sdh_call_1.achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* work area upper address */
   dsl_sdh_call_1.amc_cmp_time_var_1 = &m_cmp_time_unix_1;  /* routine to compare time values */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   adsl_cl1 = (struct dsd_clib1_data_1 *) adsp_hl_clib_1->ac_ext;
   adsl_conf = (struct dsd_clib1_conf_1 *) adsp_hl_clib_1->ac_conf;  /* structure configuration */
   dsl_sdh_call_1.adsc_cl1d1_1 = adsl_cl1;  /* structure session       */
   dsl_sdh_call_1.adsc_conf = adsl_conf;    /* structure configuration */
   if (adsl_cl1->dsc_cm.boc_windows_fs) {   /* is Windows file system  */
     dsl_sdh_call_1.amc_cmp_time_var_1 = &m_cmp_time_win_1;  /* routine to compare time values */
   }
   iml_seml = adsl_conf->imc_seml;          /* <send-error-messages-level> */
   if (adsl_cl1->dsc_cm.imc_seml >= 0) {    /* <send-error-messages-level> */
     iml_seml = adsl_cl1->dsc_cm.imc_seml;  /* <send-error-messages-level> */
   }
   iml_use_log_ls = adsl_conf->imc_log_ls;  /* use log-level-share     */
   if (adsl_cl1->dsc_cm.imc_log_ls > iml_use_log_ls) {  /* <log-level-share> */
     iml_use_log_ls = adsl_cl1->dsc_cm.imc_log_ls;  /* use log-level-share */
   }
   adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   if (adsp_hl_clib_1->boc_eof_client) {    /* End-of-File Client      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W end-of-file Client",
                   __LINE__ );
   }
   if (adsp_hl_clib_1->boc_eof_server) {    /* End-of-File Server      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W end-of-file Server",
                   __LINE__ );
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T adsl_cl1=%p adsl_cl1->iec_clst=%d adsl_cl1->iec_scs=%d.",
                 __LINE__, adsl_cl1, adsl_cl1->iec_clst, adsl_cl1->iec_scs );
#endif
#ifdef B150331
   iml_epoch_cur = 0;                       /* time when called */
   if (   (adsl_cl1->imc_epoch_keepalive)   /* time to send keepalive  */
       || (adsl_cl1->imc_epoch_backlog)) {  /* time to process backlog */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_GET_TIME,  /* get current time */
                                      &iml_epoch_cur,  /* time when called */
                                      sizeof(int) );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
//   if (iml_epoch_cur == 0) iml_epoch_cur = 1;  /* January 18th 2038  */
   }
#endif
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_T_MSEC,  /* get time / epoch in milliseconds */
                                    &ill_epoch_cur,  /* time when called */
                                    sizeof(HL_LONGLONG) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef B150411
//#ifdef B150331
   iml_epoch_cur = ill_epoch_cur / 1000;    /* time when called */
//#endif
#endif
#ifdef DEBUG_140925_01
   if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_FROMSERVER)
       && (adsl_dwa)) {
     adsl_gai1_inp_check = adsl_dwa->adsc_gai1_in_from_client;  /* check input data */
     iml1 = iml2 = 0;
     adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
     while (adsl_gai1_inp_2) {              /* loop over all gather    */
       iml3 = adsl_gai1_inp_2->achc_ginp_end - adsl_gai1_inp_2->achc_ginp_cur;
       iml1++;                              /* count gather            */
       iml2 += iml3;
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T adsc_gai1_in_from_client %d. gai1=%p len=%d/0X%X.",
                   __LINE__, iml1, adsl_gai1_inp_2, iml3, iml3 );
       adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T adsc_gai1_in_from_client total gather=%d len=%d/0X%X.",
                   __LINE__, iml1, iml2, iml2 );
   } else {
     adsl_gai1_inp_check = NULL;            /* check input data        */
     if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
       adsl_gai1_inp_check = adsp_hl_clib_1->adsc_gather_i_1_in;
     }
   }
#endif
#ifdef HELP_DEBUG
   struct dsd_dir_bl_2 *ADSL_DB2_G = NULL;
#endif
   iel_prco = ied_prco_nothing;             /* nothing more to do      */
   bol_call_smb_cl = FALSE;                 /* call SMB client         */
   bol_call_vc = FALSE;                     /* call virus-checking     */
   if (   (adsl_dwa == NULL)
       || ((adsl_dwa->umc_state & DWA_STATE_VCH_ACT) == 0)) {  /* state of processing */
     goto p_resp_vch_80;                    /* end response virus checker */
   }
   adsl_wvc1 = NULL;                        /* not yet virus-checking  */
   if (   (adsl_cl1->iec_clst == ied_clst_resp_read_file_normal)  /* wait for read file normal */
       || (adsl_cl1->iec_clst == ied_clst_resp_read_file_compressed)  /* wait for read file compressed */
       || (adsl_cl1->iec_clst == ied_clst_end_read_file)) {  /* received end read file */
     adsl_dwifvc = &adsl_dwa->dsc_work_ifvc;  /* input file with virus-checking */
#ifdef TRACEHL1
     adsl_dwifvc->dsc_cdf_ctrl.vpc_userfld = (void *) 3;  /* User Field Subroutine */
#endif
     adsl_wvc1 = &adsl_dwifvc->dsc_wvc1;    /* virus-checking          */
   }
   if (   (adsl_cl1->iec_scs == ied_scs_read_smb2ss_01)  /* read file from server / open */
       || (adsl_cl1->iec_scs == ied_scs_read_smb2ss_end)) {  /* read file from server / end */
     adsl_wsmb2ss = &adsl_dwa->dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
     adsl_wvc1 = &adsl_wsmb2ss->dsc_wvc1;   /* virus-checking          */
   }
   if (adsl_wvc1 == NULL) {                 /* virus-checking not set  */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W virus checker invalid state %d.",
                   __LINE__, adsl_cl1->iec_clst );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
#ifdef TRACEHL1
   achl_wc1 = "- unknown -";
   switch (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl) {  /* completion code */
     case ied_vchcompl_active:              /* virus checking active   */
       achl_wc1 = "ied_vchcompl_active";
       break;
     case ied_vchcompl_idle:                /* nothing to do           */
       achl_wc1 = "ied_vchcompl_idle";
       break;
     case ied_vchcompl_ok:                  /* file has no virus       */
       achl_wc1 = "ied_vchcompl_ok";
       break;
     case ied_vchcompl_no_server:           /* the necessary servers not found */
       achl_wc1 = "ied_vchcompl_no_server";
       break;
     case ied_vchcompl_comm_error:          /* communication error     */
       achl_wc1 = "ied_vchcompl_comm_error";
       break;
     case ied_vchcompl_vch_inv_resp:        /* invalid response from virus checker */
       achl_wc1 = "ied_vchcompl_vch_inv_resp";
       break;
     case ied_vchcompl_vch_timeout:         /* timeout while virus checking */
       achl_wc1 = "ied_vchcompl_vch_timeout";
       break;
     case ied_vchcompl_virus:               /* file contains virus     */
       achl_wc1 = "ied_vchcompl_virus";
       break;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T dsc_sevchcontr1 iec_vchcompl=%d %s ilc_window_1=%lld ilc_window_2=%lld boc_wait_window=%d.",
                 __LINE__, adsl_wvc1->dsc_sevchcontr1.iec_vchcompl, achl_wc1,
                 adsl_wvc1->dsc_sevchcontr1.ilc_window_1,  /* bytes sent first step   */
                 adsl_wvc1->dsc_sevchcontr1.ilc_window_2,  /* bytes sent second step  */
                 adsl_wvc1->dsc_sevchcontr1.boc_wait_window );  /* wait till window smaller */
   adsl_sevchreq1_cur = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
   iml1 = 0;                                /* clear count             */
   while (adsl_sevchreq1_cur) {             /* service virus checking request */
     iml1++;                                /* increment count         */
     achl_wc1 = "- unknown -";
     switch (adsl_sevchreq1_cur->iec_vchreq1) {  /* request type       */
       case ied_vchreq_filename:            /* filename                */
         achl_wc1 = "ied_vchreq_filename";
         break;
       case ied_vchreq_content:             /* content of file         */
         achl_wc1 = "ied_vchreq_content";
         break;
       case ied_vchreq_eof:                 /* End-of-File             */
         achl_wc1 = "ied_vchreq_eof";
         break;
     }
     achl_wc2 = "- unknown -";
     switch (adsl_sevchreq1_cur->iec_stat) {  /* state of request      */
       case ied_vchstat_active:             /* data not sent yet       */
         achl_wc2 = "ied_vchstat_active";
       case ied_vchstat_sent:               /* data have been sent     */
         achl_wc2 = "ied_vchstat_sent";
       case ied_vchstat_done:               /* area can be freed       */
         achl_wc2 = "ied_vchstat_done";
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T dsd_se_vch_req_1 %03d / %03d iec_vchreq1=%d %s iec_stat=%d %s.",
                   __LINE__, iml1,
                   adsl_sevchreq1_cur - adsl_wvc1->dsrc_sevchreq1,
                   adsl_sevchreq1_cur->iec_vchreq1, achl_wc1,
                   adsl_sevchreq1_cur->iec_stat, achl_wc2 );
     adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
   }
   achl_wc1 = "- unknown -";
   switch (adsl_wvc1->iec_vcend) {          /* state virus-checking end */
     case ied_vcend_normal:                 /* normal state, not yet end */
       achl_wc1 = "ied_vcend_normal";
       break;
     case ied_vcend_recv_end:               /* end input received      */
       achl_wc1 = "ied_vcend_recv_end";
       break;
     case ied_vcend_wait_send_end:          /* wait to send end to virus-checker */
       achl_wc1 = "ied_vcend_wait_send_end";
       break;
     case ied_vcend_end_sent:               /* end sent to virus-checker */
       achl_wc1 = "ied_vcend_end_sent";
       break;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T iec_vcend=%d %s.",
                 __LINE__, adsl_wvc1->iec_vcend, achl_wc1 );
#endif
#ifdef B150101
   if (   (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_active)  /* virus checking active */
       && (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_idle)) {  /* nothing to do */
     goto p_resp_vch_60;                    /* end of virus-checking   */
   }
#endif

   /* remove old requests                                              */
   /**
      here, the chunks of SWAP-STOR are written.
      of every chunk, one request needs to stay in the chain
      as long as this is where adsl_wvc1->achc_vc_written points to an active request.
      this is needed, so that, when virus-checking ends,
      the last block is also written to SWAP-STOR.
   */
   adsl_sevchreq1_cur = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
   adsl_sevchreq1_last = NULL;              /* last element in chain   */
   while (TRUE) {                           /* loop over all requests  */
     if (adsl_sevchreq1_cur == NULL) break;  /* end of chain reached   */
     if (adsl_sevchreq1_cur->iec_stat != ied_vchstat_done) {  /* leave element in chain */
       adsl_sevchreq1_last = adsl_sevchreq1_cur;  /* save last element in chain */
       adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
       continue;
     }
#ifdef B150101
     /* remove this element from the chain                             */
     if (adsl_sevchreq1_last == NULL) {     /* is first in chain now   */
       adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = adsl_sevchreq1_cur->adsc_next;
     } else {                               /* middle in chain         */
       adsl_sevchreq1_last->adsc_next = adsl_sevchreq1_cur->adsc_next;
     }
#endif
#ifndef B150101
     bol1 = FALSE;                          /* do not save block       */
#endif
     /* check if storage can be written to swap storage                */
     while (adsl_sevchreq1_cur->iec_vchreq1 == ied_vchreq_content) {  /* content of file */
       achl_w1 = adsl_wvc1->achrc_stor_addr_vc[ adsl_sevchreq1_cur - adsl_wvc1->dsrc_sevchreq1 ];
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_141231_02 adsl_sevchreq1_cur=%p adsl_wvc1->dsrc_sevchreq1=%p index=%d achl_w1=%p.",
                   __LINE__, adsl_sevchreq1_cur, adsl_wvc1->dsrc_sevchreq1, adsl_sevchreq1_cur - adsl_wvc1->dsrc_sevchreq1, achl_w1 );
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_141231_02 adsl_wvc1->achrc_stor_addr_ss[ 0 ]=%p.",
                   __LINE__, adsl_wvc1->achrc_stor_addr_ss[ 0 ] );
#endif
#ifdef B150101
#ifdef B141231
       if (achl_w1 == adsl_wvc1->achrc_stor_addr_ss[ 0 ]) break;
#endif
#ifndef B141231
       if (   (achl_w1 == adsl_wvc1->achrc_stor_addr_ss[ 0 ])
           && (adsl_wvc1->achc_vc_written != (achl_w1 + LEN_BLOCK_SWAP))) {
         break;                             /* chunk still in use      */
       }
#endif
#endif
#ifndef B150101
#ifdef XYZ1
       if (   (adsl_wvc1->achc_vc_written >= achl_w1)
           && (adsl_wvc1->achc_vc_written < (achl_w1 + LEN_BLOCK_SWAP))) {
         break;                             /* chunk still in use      */
       }
#endif
#ifdef XYZ1
       if (adsl_wvc1->iec_vcend != ied_vcend_end_sent) {  /* end sent to virus-checker */
         if (   (adsl_wvc1->achc_vc_written >= achl_w1)
             && (adsl_wvc1->achc_vc_written < (achl_w1 + LEN_BLOCK_SWAP))) {
           bol1 = TRUE;                     /* do save block           */
           break;                           /* chunk still in use      */
         }
       } else {                             /* already processing end  */
         /* if only single chunk SWAP-STOR, do not write               */
         if (adsl_wvc1->imc_index_re == 1) break;  /* index of dataset / chunk - read */
       }
#endif
#endif
       /* check if in other virus checking request                     */
       adsl_sevchreq1_w1 = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
       while (adsl_sevchreq1_w1) {          /* loop over other requests */
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_141231_02 adsl_sevchreq1_w1=%p adsl_wvc1->dsrc_sevchreq1=%p index=%d addr=%p.",
                       __LINE__, adsl_sevchreq1_w1, adsl_wvc1->dsrc_sevchreq1, adsl_sevchreq1_w1 - adsl_wvc1->dsrc_sevchreq1,
                       adsl_wvc1->achrc_stor_addr_vc[ adsl_sevchreq1_w1 - adsl_wvc1->dsrc_sevchreq1 ] );
#endif
#ifdef B150101
         if (   (adsl_sevchreq1_w1->iec_vchreq1 == ied_vchreq_content)  /* content of file */
             && (achl_w1 == adsl_wvc1->achrc_stor_addr_vc[ adsl_sevchreq1_w1 - adsl_wvc1->dsrc_sevchreq1 ])) {
           break;                           /* swap storage memory still in use */
         }
#endif
#ifndef B150101
         if (   (adsl_sevchreq1_w1 != adsl_sevchreq1_cur)  /* not current element */
             && (adsl_sevchreq1_w1->iec_vchreq1 == ied_vchreq_content)  /* content of file */
             && (achl_w1 == adsl_wvc1->achrc_stor_addr_vc[ adsl_sevchreq1_w1 - adsl_wvc1->dsrc_sevchreq1 ])) {
           break;                           /* swap storage memory still in use */
         }
#endif
         adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;  /* get next in chain */
       }
       if (adsl_sevchreq1_w1) break;        /* address found in other request */
#ifndef B150101
       if (adsl_wvc1->iec_vcend != ied_vcend_end_sent) {  /* end sent to virus-checker */
         if (   (adsl_wvc1->achc_vc_written >= achl_w1)
             && (adsl_wvc1->achc_vc_written < (achl_w1 + LEN_BLOCK_SWAP))) {
           bol1 = TRUE;                     /* do save block           */
           break;                           /* chunk still in use      */
         }
       } else {                             /* already processing end  */
         /* if only single chunk SWAP-STOR, do not write               */
         if (adsl_wvc1->imc_index_re == 1) break;  /* index of dataset / chunk - read */
       }
#endif
       /* release block for buffering in swap storage                  */
       memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
       dsl_astr1.iec_swsc = ied_swsc_write;  /* write swap storage buffer */
       dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
       dsl_astr1.achc_stor_addr = achl_w1;  /* storage address         */
       dsl_astr1.imc_index = adsl_wvc1->imc_index_wr;  /* index of dataset / chunk - write */
       bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                        DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                        &dsl_astr1,  /* swap storage request */
                                        sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
       if (bol_rc == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.               */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                       __LINE__, dsl_astr1.iec_swsr );
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       adsl_wvc1->imc_index_wr++;           /* index of dataset / chunk - write */
       break;
     }
#ifndef B150101
     if (bol1) {                            /* do save block           */
       adsl_sevchreq1_last = adsl_sevchreq1_cur;  /* save last element in chain */
       adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
       continue;
     }
     /* remove this element from the chain                             */
     if (adsl_sevchreq1_last == NULL) {     /* is first in chain now   */
       adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = adsl_sevchreq1_cur->adsc_next;
     } else {                               /* middle in chain         */
       adsl_sevchreq1_last->adsc_next = adsl_sevchreq1_cur->adsc_next;
     }
#endif
     *((int *) &adsl_sevchreq1_cur->iec_stat) = -1;  /* set unused     */
     adsl_sevchreq1_cur = adsl_sevchreq1_cur->adsc_next;  /* get next in chain */
   }
#ifndef B150101
   if (   (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_active)  /* virus checking active */
       && (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_idle)) {  /* nothing to do */
     goto p_resp_vch_60;                    /* end of virus-checking   */
   }
#endif
   if (adsl_wvc1->imc_ss_ahead <= 1) {      /* swap storage in use     */
     goto p_resp_vch_40;                    /* check end virus checker */
   }
#ifndef B141231
   if (adsl_wvc1->achc_vc_written == (adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP)) {
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_141231_02 adsl_wvc1->achc_vc_written=%p end of chunk.",
                   __LINE__, adsl_wvc1->achc_vc_written );
#endif
     goto p_resp_vch_24;                    /* not need to send data of this chunk */
   }
#endif

   p_resp_vch_20:                           /* search for free request */
#ifdef XYZ1
#ifndef B141231
   if (adsl_wvc1->achc_vc_written == (adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP)) {
     goto p_resp_vch_40;                    /* check end virus checker */
   }
#endif
#endif
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->achc_vc_written == (adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   iml1 = 0;                                /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_stat) < 0) break;  /* check unused */
     iml1++;                                /* increment index         */
   } while (iml1 < NO_VC_REQ1);             /* number of concurrent requests */
   if (iml1 >= NO_VC_REQ1) {                /* number of concurrent requests */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_resp_vch_20: buffer full, wait virus-checker, set boc_wait_window",
                   __LINE__ );
#endif
     adsl_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     bol_call_vc = TRUE;                    /* call virus-checking     */
     goto p_resp_vch_80;                    /* end response virus checker */
   }
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur = adsl_wvc1->achc_vc_written;  /* address written to virus-checking */
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end = adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP;
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].adsc_next = NULL;
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur >= adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   adsl_wvc1->achrc_stor_addr_vc[ iml1 ] = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   memset( &adsl_wvc1->dsrc_sevchreq1[ iml1 ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].adsc_gai1_data = &adsl_wvc1->dsrc_gai1_vch_data[ iml1 ];
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_vchreq1 = ied_vchreq_content;  /* content of file */
   if (adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   }
   adsl_wvc1->dsc_sevchcontr1.ilc_window_1
     += (adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP) - adsl_wvc1->achc_vc_written;
   bol_call_vc = TRUE;                      /* call virus-checking     */
#ifndef B141231

   p_resp_vch_24:                           /* this chunk has been sent */
#endif
   adsl_wvc1->imc_ss_ahead--;               /* swap storage in use     */
   memmove( &adsl_wvc1->achrc_stor_addr_ss[ 0 ],
            &adsl_wvc1->achrc_stor_addr_ss[ 1 ],
            adsl_wvc1->imc_ss_ahead * sizeof(adsl_wvc1->achrc_stor_addr_ss[ 0 ]) );
   adsl_wvc1->achc_vc_written = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* address written to virus-checking */
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->achc_vc_written == (adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif

   if (adsl_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     goto p_resp_vch_20;                    /* search for free request */
   }

   p_resp_vch_40:                           /* check end virus checker */
   if (adsl_wvc1->iec_vcend == ied_vcend_normal) {  /* normal state, not yet end */
     goto p_resp_vch_80;                    /* end response virus checker */
   }
   if (   (adsl_cl1->iec_clst == ied_clst_resp_read_file_compressed)  /* wait for read file compressed */
       || (adsl_cl1->iec_clst == ied_clst_end_read_file)) {  /* received end read file */
     achl_w1 = adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur;
   }
   if (   (adsl_cl1->iec_scs == ied_scs_read_smb2ss_01)  /* read file from server / open */
       || (adsl_cl1->iec_scs == ied_scs_read_smb2ss_end)) {  /* read file from server / end */
     achl_w1 = adsl_wsmb2ss->achc_output;
   }
   bol_rc = m_work_vc_end( &dsl_sdh_call_1,
                           adsl_wvc1,       /* virus-checking          */
                           adsl_dwa,        /* all dash operations work area */
                           achl_w1,
                           &bol_call_vc );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   goto p_resp_vch_80;                      /* end response virus checker */

   p_resp_vch_60:                           /* end of virus-checking   */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_resp_vch_60: - end of virus-checking",
                 __LINE__ );
#endif
   adsl_dwa->umc_state &= -1 - DWA_STATE_VCH_ACT;  /* state of processing */
   if (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl == ied_vchcompl_ok) {  /* file has no virus */
     if (   (adsl_cl1->iec_clst == ied_clst_resp_read_file_compressed)  /* wait for read file compressed */
         || (adsl_cl1->iec_clst == ied_clst_end_read_file)) {  /* received end read file */
#ifndef B150127
       adsl_cl1->iec_clst = ied_clst_end_virus_checked;  /* received end read file and virus checked */
#endif
       goto p_ss2smb_00;                    /* copy from Swap Storage to SMB */
     }
     if (   (adsl_cl1->iec_scs == ied_scs_read_smb2ss_01)  /* read file from server / open */
         || (adsl_cl1->iec_scs == ied_scs_read_smb2ss_end)) {  /* read file from server / end */
       goto p_ss2cl_00;                     /* copy from Swap Storage to client */
     }
   }
   if (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl != ied_vchcompl_virus) {  /* file contains virus */
     goto p_resp_vch_72;                    /* abend of virus-checking */
   }

   /* close Swap Storage, Virus needs to be cleared                    */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_clear_and_close;  /* clear content and close swap storage */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
#ifdef B150102
   achl_w1 = (char *) &adsl_a1->adsc_f1_action->achc_virus_client;  /* virus found on client */
   achl_wc2 = "DASH client";
   if (   (adsl_cl1->iec_scs == ied_scs_read_smb2ss_01)  /* read file from server / open */
       || (adsl_cl1->iec_scs == ied_scs_read_smb2ss_end)) {  /* read file from server / end */
     achl_w1 = (char *) &adsl_a1->adsc_f1_action->achc_virus_server;  /* virus found on server */
     achl_wc2 = "SMB server";
   }
#endif
#ifndef B150110
   adsl_a1->boc_changed_sync = TRUE;        /* need to write synchronize file */
#endif
   if (   (adsl_cl1->iec_scs == ied_scs_read_smb2ss_01)  /* read file from server / open */
       || (adsl_cl1->iec_scs == ied_scs_read_smb2ss_end)) {  /* read file from server / end */
     achl_wc1 = (char *) &adsl_a1->adsc_f1_action->achc_virus_server;  /* virus found on server */
     achl_wc2 = "SMB server";
#ifdef B150110
     adsl_a1->boc_changed_remote = TRUE;    /* changes remote          */
#endif
     adsl_a1->adsc_f1_action->umc_flags |= D_FILE_1_FLAG_NOT_CL;  /* file not on client */
   } else {
     achl_w1 = (char *) &adsl_a1->adsc_f1_action->achc_virus_client;  /* virus found on client */
     achl_wc2 = "DASH client";
#ifdef B150110
     adsl_a1->boc_changed_local = TRUE;     /* changes local           */
#endif
   }
   iml1 = m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, byrl_server_fn, '\\' );
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W %s file \"%.*(u8)s\" found virus \"%.*(u8)s\"",
                 __LINE__, achl_wc2,
                 iml1, byrl_server_fn,
                 adsl_wvc1->dsc_sevchcontr1.imc_len_virus_name, adsl_wvc1->dsc_sevchcontr1.chrc_virus_name );
// to-do 01.01.14 KB send message to client
   if (iml_seml >= 4) {                     /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W %s file \"%.*(u8)s\" found virus \"%.*(u8)s\"",
                   __LINE__, achl_wc2,
                   iml1, byrl_server_fn,
                   adsl_wvc1->dsc_sevchcontr1.imc_len_virus_name, adsl_wvc1->dsc_sevchcontr1.chrc_virus_name );
   }
   if ((adsl_a1->achc_fn_new_low - adsl_wvc1->dsc_sevchcontr1.imc_len_virus_name - 1) < ((char *) adsl_a1->adsc_f1_new_cur)) {
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_MEMGET,  /* get some memory */
                                      &adsl_a1->adsc_db1_new_cur,
                                      LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_a1->adsc_db1_new_last->adsc_next = adsl_a1->adsc_db1_new_cur;  /* directory block 1 - chaining */
     adsl_a1->adsc_db1_new_last->achc_end_file = (char *) adsl_a1->adsc_f1_new_cur;  /* end of files */
     adsl_a1->adsc_f1_new_cur = (struct dsd_file_1 *) ((char *) (adsl_a1->adsc_db1_new_cur + 1));
     adsl_a1->adsc_db1_new_last = adsl_a1->adsc_db1_new_cur;  /* directory block 1 - chaining - last */
     adsl_a1->achc_fn_new_low = (char *) adsl_a1->adsc_db1_new_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   *(adsl_a1->achc_fn_new_low - 1) = 0;     /* make zero-terminated    */
   adsl_a1->achc_fn_new_low -= adsl_wvc1->dsc_sevchcontr1.imc_len_virus_name + 1;
   memcpy( adsl_a1->achc_fn_new_low,
           adsl_wvc1->dsc_sevchcontr1.chrc_virus_name,
           adsl_wvc1->dsc_sevchcontr1.imc_len_virus_name );
   *((void **) achl_w1) = adsl_a1->achc_fn_new_low;  /* set virus name */
   adsl_a1->imc_errors++;                   /* count files with errors */
   adsl_cl1->iec_clst = ied_clst_idle;      /* client is idle          */
// to-do 01.01.14 KB - set adsl_cl1->iec_scs
   if (adsl_dwa->adsc_cf_bl_cur) {          /* current entry copy file backlog - processing backlog */
     goto p_proc_bl_40;                     /* delete backlog entry    */
   }
   goto p_next_action_00;                   /* check for next action   */

   p_resp_vch_72:                           /* abend of virus-checking */
   achl_wc1 = "- unknown -";
   switch (adsl_wvc1->dsc_sevchcontr1.iec_vchcompl) {  /* completion code */
     case ied_vchcompl_no_server:           /* the necessary servers not found */
       achl_wc1 = "ied_vchcompl_no_server - the necessary servers not found";
       break;
     case ied_vchcompl_comm_error:          /* communication error     */
       achl_wc1 = "ied_vchcompl_comm_error - communication error";
       break;
     case ied_vchcompl_vch_inv_resp:        /* invalid response from virus checker */
       achl_wc1 = "ied_vchcompl_vch_inv_resp - invalid response from virus checker";
       break;
     case ied_vchcompl_vch_timeout:         /* timeout while virus checking */
       achl_wc1 = "ied_vchcompl_vch_timeout - timeout while virus checking";
       break;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E error virus-checking iec_vchcompl=%d %s.",
                 __LINE__, adsl_wvc1->dsc_sevchcontr1.iec_vchcompl, achl_wc1 );
   if (iml_seml >= 9) {                     /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E error virus-checking iec_vchcompl=%d %s.",
                 __LINE__, adsl_wvc1->dsc_sevchcontr1.iec_vchcompl, achl_wc1 );
   }
   iml1 = __LINE__;
   goto p_error_int_error;                  /* internal error has occured */

   p_resp_vch_80:                           /* end response virus checker */
   while (adsp_hl_clib_1->boc_eof_server) {  /* End-of-File Server     */
     if (   (adsl_cl1->iec_scs == ied_scs_start)  /* start SMB connection */
         && (adsl_cl1->boc_smb_connected)) {   /* connected to SMB server */
       adsl_cl1->boc_smb_connected = FALSE;  /* connected to SMB server */
       bol_put_cred = FALSE;                /* put / write credendials */
       goto p_smb_conn_00;                  /* connect to SMB server   */
     }
     if (adsl_cl1->iec_clst == ied_clst_resp_cred_1) {  /* wait for response credentials */
       break;                               /* nothing special         */
     }
     if (adsl_cl1->iec_scs != ied_scs_idle) {  /* idle, nothing to do  */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB-server closed in server state %d - invalid",
                     __LINE__, adsl_cl1->iec_scs );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     if (adsl_cl1->boc_server_notify) {     /* notify SMB server is active */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB-server closed while waiting for notify - invalid",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     if (adsl_cl1->iec_clst != ied_clst_idle) {  /* client is idle     */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB-server closed in client state %d - invalid",
                     __LINE__, adsl_cl1->iec_clst );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsl_cl1->iec_scs = ied_scs_closed;    /* SMB connection closed   */
     break;
   }
   if (   (adsl_dwa == NULL)
       || (adsl_dwa->adsc_cf_backlog == NULL)  /* we have no chain copy file backlog */
       || (adsl_dwa->adsc_cf_bl_cur)) {     /* current entry copy file backlog */
     goto p_start_00;                       /* start normal processing */
   }
   if (   (adsp_hl_clib_1->inc_func != DEF_IFUNC_REFLECT)
       && (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)
       && (adsp_hl_clib_1->adsc_gather_i_1_in != NULL)) {
     goto p_smb_rec_00;                     /* received from SMB server */
   }
#ifdef B140826
   /* check if we still wait for the timer set for backlog             */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TIMER1_QUERY,  /* return struct dsd_timer1_ret */
                                    &dsl_timer1_ret,  /* timer return values */
                                    sizeof(struct dsd_timer1_ret) );
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_timer1_ret.boc_timer_set) return;  /* a timer is set and active */
#endif
#ifdef B150411
   if (   (adsl_cl1->imc_epoch_backlog == 0)  /* time to process backlog */
       || ((iml_epoch_cur - adsl_cl1->imc_epoch_backlog) < 0)) {  /* not yet elapsed */
     goto p_ret_00;                         /* return                  */
   }
   adsl_cl1->imc_epoch_backlog = 0;         /* clear time to process backlog */
#endif
   if (   (adsl_cl1->ilc_epoch_backlog == 0)  /* time to process backlog */
       || ((ill_epoch_cur / 1000 - adsl_cl1->ilc_epoch_backlog) < 0)) {  /* not yet elapsed */
     goto p_ret_00;                         /* return                  */
   }
   adsl_cl1->ilc_epoch_backlog = 0;         /* clear time to process backlog */
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   if (adsl_cl1->iec_scs == ied_scs_closed) {  /* SMB connection closed */
     adsl_cl1->iec_scs = ied_scs_start;     /* start SMB connection    */
     adsl_cl1->boc_smb_connected = FALSE;   /* connected to SMB server */
     bol_put_cred = FALSE;                  /* put / write credendials */
     goto p_smb_conn_00;                    /* connect to SMB server   */
   }
   adsl_dwa->adsc_cf_bl_cur = adsl_dwa->adsc_cf_backlog;  /* process chain copy file backlog */
   goto p_proc_bl_00;                       /* process backlog         */

   p_start_00:                              /* start normal processing */
   if (   (adsp_hl_clib_1->inc_func != DEF_IFUNC_REFLECT)
       && (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER)) {
     goto p_smb_rec_00;                     /* received from SMB server */
   }
   adsl_gai1_inp_1 = adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   iml1 = 0;                                /* length of data          */
   while (adsl_gai1_inp_2) {
     iml1 += adsl_gai1_inp_2->achc_ginp_end - adsl_gai1_inp_2->achc_ginp_cur;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   if (   (iml1 != adsl_cl1->imc_len_data_from_client)  /* input length data received from client */
       && (adsl_cl1->imc_keepalive > 0)) {  /* keepalive client        */
#ifdef B150411
     adsl_cl1->imc_epoch_keepalive          /* time to send keepalive  */
       = iml_epoch_cur + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
#endif
     adsl_cl1->ilc_epoch_keepalive          /* time to send keepalive  */
       = ill_epoch_cur / 1000 + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
   }

   p_client_rec_00:                         /* check received from client */
   if (adsl_gai1_inp_1 == NULL) {           /* no input data           */
     if (adsl_dwa) {
       if (adsl_dwa->umc_state & DWA_STATE_2CL_NORMAL) {  /* send to client normal */
         goto p_ss2cl_60;                   /* chunk Swap Storage without compression sent */
       }
       if (adsl_dwa->umc_state & DWA_STATE_2CL_COMPR) {  /* send to client compressed */
         goto p_ss2cl_20;                   /* copy something from SWAP-STOR to client */
       }
     }
     goto p_ret_00;                         /* return                  */
   }
   if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {  /* no data this gather */
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     goto p_client_rec_00;                  /* check received from client */
   }
#ifdef XYZ1
   switch (adsl_cl1->iec_clst) {        /* state of connection to client */
     case ied_clst_rec_eye_catcher:         /* receive eye-catcher     */
       goto p_rec_eye_catcher_00;           /* check received eye-catcher */
   }
   return;
#endif
   if (adsl_cl1->iec_clst != ied_clst_rec_eye_catcher) {  /* receive eye-catcher */
     if (adsl_dwa) {
       adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
     }
     goto p_client_rec_20;                  /* continue received from client */
   }

// p_rec_eye_catcher_00:                    /* check received eye-catcher */
   achl_w1 = byrl_work1;                    /* address to copy to      */
   bol1 = FALSE;                            /* state <CR><LF>          */
   achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here   */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* wait for more input data */
         goto p_ret_00;                     /* return                  */
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     do {                                   /* loop data this gater    */
       if (*achl_rp == CHAR_CR) {           /* carriage-return found   */
         achl_w2 = achl_w1;                 /* save start <CR><LF>     */
         bol1 = TRUE;                       /* state <CR><LF>          */
       } else if (*achl_rp == CHAR_LF) {    /* line-feed found         */
         if (bol1) {                        /* state <CR><LF>          */
           goto p_rec_eye_catcher_20;       /* end eye-catcher         */
         }
       } else {                             /* other character         */
         bol1 = FALSE;                      /* state <CR><LF>          */
       }
       if (achl_w1 >= (byrl_work1 + MAX_EYE_CATCHER)) {  /* maximum length eye-catcher */
         goto p_rec_eye_catcher_80;         /* eye-catcher too long    */
       }
       *achl_w1++ = *achl_rp++;             /* copy character          */
     } while (achl_rp < adsl_gai1_inp_1->achc_ginp_end);
   }

   p_rec_eye_catcher_20:                    /* end eye-catcher         */
   achl_rp++;                               /* after <LF>              */
   iml1 = achl_w2 - byrl_work1;             /* length received eye-catcher */
   if (   (iml1 != (sizeof(ucrs_eye_catcher_protocol) + 2))
       || (memcmp( byrl_work1, ucrs_eye_catcher_protocol, sizeof(ucrs_eye_catcher_protocol) ))) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E received invalid eye-catcher \"%.*s\"",
                   __LINE__, iml1, byrl_work1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   adsl_cl1->imc_client_protocol            /* protocol of client      */
     = (*(byrl_work1 + sizeof(ucrs_eye_catcher_protocol) + 0) - '0') * 10
         + (*(byrl_work1 + sizeof(ucrs_eye_catcher_protocol) + 1) - '0');
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client has protocol version %02d.",
                 __LINE__, adsl_cl1->imc_client_protocol );
   if (   (adsl_cl1->imc_client_protocol < 1)
       || (adsl_cl1->imc_client_protocol > 2)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E client protocol version %02d not supported",
                   __LINE__, adsl_cl1->imc_client_protocol );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E client protocol version %02d not supported",
                     __LINE__, adsl_cl1->imc_client_protocol );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;  /* scanning done up to here */
   adsl_cl1->iec_clst = ied_clst_rec_log_in;  /* receive log-in        */
   goto p_client_rec_00;                    /* check received from client */

   p_rec_eye_catcher_80:                    /* eye-catcher too long    */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received eye-catcher too long - start \"%.*s\"",
                 __LINE__, 16, byrl_work1 );
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;

   p_client_rec_20:                         /* continue received from client */
   /* first get length of this record                                  */
//#ifdef WAS_131223
   iml_rl = 0;                              /* record length           */
#ifndef B170209
   if (adsl_dwa) {
     iml_rl = adsl_dwa->imc_rl;             /* remainder record not yet processed */
     if (iml_rl != 0) {                     /* remainder record not yet processed */
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_client_rec_20: adsl_dwa->imc_rl=%d/0X%X.",
                     __LINE__, iml_rl, iml_rl );
#endif
       if (adsl_cl1->iec_clst               /* state of connection to client */
             == ied_clst_resp_read_file_compressed) {  /* wait for read file compressed */
         goto p_cl_rfc_00;                  /* read file compressed    */
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W searching for command but adsl_dwa->imc_rl set %d/0X%X.",
                     __LINE__, iml_rl, iml_rl );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
   }
#endif
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here   */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* wait for more input data */
         if (adsl_dwa) {
           if (adsl_dwa->umc_state & DWA_STATE_2CL_NORMAL) {  /* send to client normal */
             goto p_ss2cl_60;               /* chunk Swap Storage without compression sent */
           }
           if (adsl_dwa->umc_state & DWA_STATE_2CL_COMPR) {  /* send to client compressed */
             goto p_ss2cl_20;               /* copy something from SWAP-STOR to client */
           }
         }
         goto p_ret_00;                     /* return                  */
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml_rl <<= 7;                          /* shift old value         */
     iml_rl |= *achl_rp & 0X7F;             /* apply new bits          */
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received length record NHASN too many digits",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
//#endif
   if (iml_rl == 0) {                       /* length record too short */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received length record NHASN %d too short",
                   __LINE__, iml_rl );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   /* check if record complete in input data                           */
   iml1 = iml_rl;                           /* get length record       */
   achl_w1 = achl_rp;                       /* get current input pointer */
   adsl_gai1_inp_2 = adsl_gai1_inp_1;       /* get current gather      */
   while (TRUE) {                           /* loop to check if record complete */
     iml2 = adsl_gai1_inp_2->achc_ginp_end - achl_w1;
     iml1 -= iml2;                          /* compute remaining part  */
     if (iml1 <= 0) break;                  /* complete record found   */
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* wait for more input     */
       goto p_ret_00;                       /* return                  */
     }
     achl_w1 = adsl_gai1_inp_2->achc_ginp_cur;  /* start of this gather */
   }
   /* decode channel number                                            */
   iml_cn = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml_cn < 0) {                        /* not valid channel number */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (adsl_cl1->iec_clst == ied_clst_rec_log_in) {  /* receive log-in */
     if (iml_cn != 0) {                     /* not control channel     */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received channel number %d while log in - not allowed",
                     __LINE__, iml_cn );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
   }
   /* get tag of record                                                */
#ifdef WAS_BEFOR_130917
   iml_tag = 0;                             /* tag of record           */
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   while (TRUE) {                           /* loop over input data    */
     if (iml_rl <= 0) {                     /* NHASN exceeds record length */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received channel number %d tag longer than record length",
                     __LINE__, iml_cn );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received channel number NHASN program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml_tag <<= 7;                         /* shift old value         */
     iml_tag |= *achl_rp & 0X7F;            /* apply new bits          */
     iml_rl--;                              /* record length           */
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received channel number %d tag NHASN too many digits",
                     __LINE__, iml_cn );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
#endif
   iml_tag = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml_tag < 0) {                       /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml_cn != 0) {                       /* not control channel     */
     goto p_client_rec_40;                  /* received data channel   */
   }
   if (iml_tag != 0) {                      /* not log in              */
     if (iml_tag == 127) {                  /* keepalive               */
       if (iml_rl > 0) {                    /* record too long         */
         iml1 = __LINE__;                   /* set line of error       */
         goto p_cl_inv_dat;                 /* invalid data received from client */
       }
       bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
       if (bol_rc == FALSE) {               /* returned error          */
         iml1 = __LINE__;                   /* set line of error       */
         goto p_cl_illogic;                 /* illogic processing of data received from client */
       }
       goto p_client_rec_00;                /* check received from client */
     }
     if (iml_tag == DASH_DCH_CL2SE_CREDENTIALS) {  /* credentials      */
       goto p_ask_user_cred_40;             /* process response ask user for credentials */
     }
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }

   /* process sign in                                                  */
   iml_len_workstation_id = 0;              /* length workstation-id   */
   iml_len_profile = 0;                     /* length profile          */
#ifdef XYZ1
   iml_active_channels = 0;                 /* active channels client  */
#endif
   ill_w1 = 0;                              /* received epoch of client */

   p_client_rec_28:                         /* next field in sign in control channel */
#ifdef WAS_BEFOR_130917
   iml1 = 0;                                /* clear length of field   */
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml1 <<= 7;                            /* shift old value         */
     iml1 |= *achl_rp & 0X7F;               /* apply new bits          */
     iml_rl--;                              /* record length           */
     if (iml_rl <= 0) {                     /* NHASN exceeds record length */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag longer than record length",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length record NHASN too many digits",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
#endif
   iml1 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml1 < 0) {                          /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 == 0) {                         /* length field too short  */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN %d too short",
                   __LINE__, iml1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
#ifdef WAS_BEFOR_130917
   if (iml1 > iml_rl) {                     /* longer than remaining record */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field %d shorter remaining record %d.",
                   __LINE__, iml1, iml_rl );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml_rl -= iml1;                          /* decrement length of record */
   iml_st = 0;                              /* sub-tag of field        */
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag NHASN program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml_st <<= 7;                          /* shift old value         */
     iml_st |= *achl_rp & 0X7F;             /* apply new bits          */
     iml1--;                                /* field length            */
     if (iml1 <= 0) {                       /* NHASN exceeds field length */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag encoded NHASN longer than remaining field",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag encoded NHASN too many digits",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
#endif
   iml_rl -= iml1;                          /* decrement length of record */
   if (iml_rl < 0) {                        /* check length of record  */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
#ifdef XYZ1
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   if (iml2 > iml_rl) iml2 = iml_rl;        /* maximum length record   */
   iml_st = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml2 );
#endif
   iml_st = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml1 );
   if (iml_st < 0) {                        /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received data control channel program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   switch (iml_st) {                        /* sub-tag of field        */
     case 0:                                /* capabilities            */
       achl_w1 = (char *) &adsl_cl1->imc_capabilities;  /* capabilities client */
       goto p_client_rec_32;                /* decode content NHASN    */
     case 1:                                /* workstation id          */
       iml_len_workstation_id = iml1;       /* length workstation-id   */
       achl_workstation_id = achl_rp;       /* address workstation-id  */
       break;
     case 2:                                /* profile                 */
       iml_len_profile = iml1;              /* length profile          */
       achl_profile = achl_rp;              /* address profile         */
       break;
     case 3:                                /* keepalive               */
       achl_w1 = (char *) &adsl_cl1->imc_keepalive;  /* keepalive client */
       goto p_client_rec_32;                /* decode content NHASN    */
     case 4:                                /* active sub-channels     */
       achl_w1 = (char *) &adsl_cl1->imc_proc_active_channels;  /* need to process active channels client  */
       goto p_client_rec_32;                /* decode content NHASN    */
     case 5:                                /* current epoch at client */
// to-do 01.05.17 KB - problem with big endian
       achl_w1 = (char *) &ill_w1;          /* current epoch at client */
       goto p_client_rec_32;                /* decode content NHASN    */
     default:
       break;
   }
   /* overread content of field                                        */
   while (TRUE) {                           /* loop over input data    */
     iml2 = adsl_gai1_inp_1->achc_ginp_end - achl_rp;
     if (iml2 > iml1) iml2 = iml1;
     achl_rp += iml2;                       /* overread this part      */
     iml1 -= iml2;                          /* remaining length of field */
     if (iml1 <= 0) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content program illogic",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   if (iml_rl > 0) {                        /* check length of record  */
     goto p_client_rec_28;                  /* next field in sign in control channel */
   }
   goto p_cl_sign_in_00;                    /* packet sign in          */

   p_client_rec_32:                         /* decode content NHASN    */
   iml3 = 0;                                /* content                 */
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content NHASN program illogic",
                       __LINE__, iml_st );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml3 <<= 7;                            /* shift old value         */
     iml3 |= *achl_rp & 0X7F;               /* apply new bits          */
     iml1--;                                /* field length            */
     if (iml1 < 0) {                        /* NHASN exceeds field length */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content NHASN longer than remaining field",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag sub-tag %d content NHASN too many digits",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
   if (iml1 != 0) {                         /* remaining length of field */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content NHASN too short %d.",
                   __LINE__, iml_st, iml1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   *((int *) achl_w1) = iml3;               /* set content of field    */
   if (iml_rl > 0) {                        /* check length of record  */
     goto p_client_rec_28;                  /* next field in sign in control channel */
   }

   p_cl_sign_in_00:                         /* packet sign in          */
   if (iml_len_workstation_id == 0) {       /* length workstation-id   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel did not receive workstation-id",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   bol1 = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                  DEF_AUX_MEMGET,
                                  &adsl_cl1->achc_sign_in,  /* storage for sign in */
                                  iml_len_workstation_id + iml_len_profile );  /* length parameters */
   if (bol1 == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (TRUE) {                           /* loop over gather input */
     if (   (achl_workstation_id >= adsl_gai1_inp_2->achc_ginp_cur)
         && (achl_workstation_id < adsl_gai1_inp_2->achc_ginp_end)) {
       break;
     }
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control storage workstation-id program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
   }
   iml1 = iml_len_workstation_id;           /* length workstation-id   */
   while (TRUE) {                           /* loop over gather input  */
     iml2 = adsl_gai1_inp_2->achc_ginp_end - achl_workstation_id;
     if (iml2 > iml1) iml2 = iml1;
     memcpy( adsl_cl1->achc_sign_in + iml_len_workstation_id - iml1,
             achl_workstation_id,
             iml2 );
     iml1 -= iml2;                          /* decrement remaining length */
     if (iml1 == 0) break;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control storage workstation-id program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_workstation_id = adsl_gai1_inp_2->achc_ginp_cur;
   }
   adsl_cl1->achc_workstation_id = adsl_cl1->achc_sign_in;  /* address workstation-id */
   adsl_cl1->imc_len_workstation_id = iml_len_workstation_id;  /* length workstation-id */
   /* get profile                                                      */
   adsl_cl1->imc_len_profile = iml_len_profile;  /* length profile     */
   if (iml_len_profile == 0) {              /* length profile          */
     goto p_cl_sign_in_20;                  /* continue packet sign in */
   }
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (TRUE) {                           /* loop over gather input  */
     if (   (achl_profile >= adsl_gai1_inp_2->achc_ginp_cur)
         && (achl_profile < adsl_gai1_inp_2->achc_ginp_end)) {
       break;
     }
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control storage profile program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
   }
   iml1 = iml_len_profile;                  /* length profile          */
   while (TRUE) {                           /* loop over gather input  */
     iml2 = adsl_gai1_inp_2->achc_ginp_end - achl_profile;
     if (iml2 > iml1) iml2 = iml1;
     memcpy( adsl_cl1->achc_sign_in + iml_len_workstation_id + iml_len_profile - iml1,
             achl_profile,
             iml2 );
     iml1 -= iml2;                          /* decrement remaining length */
     if (iml1 == 0) break;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control storage profile program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_profile = adsl_gai1_inp_2->achc_ginp_cur;
   }
   adsl_cl1->achc_profile = adsl_cl1->achc_sign_in + iml_len_workstation_id;  /* address profile */

   p_cl_sign_in_20:                         /* continue packet sign in */
   /* consume input                                                    */
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;  /* scanning done up to here */
//
   adsl_cl1->iec_clst = ied_clst_rec_log_in;  /* receive log-in        */
   /* display data of client                                           */
   if (adsl_cl1->imc_len_profile <= 0) {    /* length profile          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client log in device \"%.*(u8)s\" no profile",
                   __LINE__,
                   adsl_cl1->imc_len_workstation_id, adsl_cl1->achc_workstation_id );
   } else {                                 /* with profile            */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client log in device \"%.*(u8)s\" profile \"%.*(u8)s\"",
                   __LINE__,
                   adsl_cl1->imc_len_workstation_id, adsl_cl1->achc_workstation_id,
                   adsl_cl1->imc_len_profile, adsl_cl1->achc_profile );
   }
   /* check current epoch at client                                    */
   if (ill_w1 != 0) {                       /* client did send current time */
     ill_w1 -= ill_epoch_cur / 1000;
     if (ill_w1 == 0) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client log in - clock client matches clock WSP",
                     __LINE__ );
       if (iml_seml >= 2) {                 /* <send-error-messages-level> */
         m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-I client log in - clock client matches clock WSP",
                       __LINE__ );
       }
     } else if (ill_w1 > 0) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client log in - clock client %d seconds too fast",
                     __LINE__, ill_w1 );
       if (iml_seml >= 2) {                 /* <send-error-messages-level> */
         m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-I client log in - clock client %d seconds too fast",
                       __LINE__, ill_w1 );
       }
     } else {
       ill_w1 *= -1;                        /* make positive           */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client log in - clock client %d seconds too slow",
                     __LINE__, ill_w1 );
       if (iml_seml >= 2) {                 /* <send-error-messages-level> */
         m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-I client log in - clock client %d seconds too slow",
                       __LINE__, ill_w1 );
       }
     }
   }
   /* read configuration from disk                                     */
   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );
   bol1 = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                  DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                  &dsl_g_idset1,
                                  sizeof(struct dsd_sdh_ident_set_1) );
   if (bol1 == FALSE) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_GET_IDENT_SETTINGS failed - returned FALSE",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_GET_IDENT_SETTINGS failed - ident unknown",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   achl_w1 = byrl_work1;
   if (adsl_conf->imc_len_dir_dpc) {      /* length directory name dash-proxy-configuration */
     memcpy( byrl_work1, adsl_conf + 1, adsl_conf->imc_len_dir_dpc );
     achl_w1 = byrl_work1 + adsl_conf->imc_len_dir_dpc;
#ifndef HL_UNIX
     *achl_w1++ = '\\';
#else
     *achl_w1++ = '/';
#endif
   }
   memcpy( achl_w1, ucrs_disk_dpc_start, sizeof(ucrs_disk_dpc_start) );
   achl_w1 += sizeof(ucrs_disk_dpc_start);
   if (dsl_g_idset1.dsc_user_group.imc_len_str != 0) {
     iml1 = m_cpy_vx_ucs( achl_w1, (byrl_work1 + sizeof(byrl_work1)) - achl_w1, ied_chs_utf_8,
                          &dsl_g_idset1.dsc_user_group );
     if (iml1 <= 0) {
       iml1 = __LINE__;
       goto p_error_int_error;              /* internal error has occured */
     }
     achl_w1 += iml1;
   }
   memcpy( achl_w1, ucrs_disk_separator, sizeof(ucrs_disk_separator) );
   achl_w1 += sizeof(ucrs_disk_separator);
   iml1 = m_cpy_vx_ucs( achl_w1, (byrl_work1 + sizeof(byrl_work1)) - achl_w1, ied_chs_utf_8,
                        &dsl_g_idset1.dsc_userid );
   if (iml1 <= 0) {
// to-do 01.04.14 KB - error message
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   achl_w1 += iml1;
   memcpy( achl_w1, ucrs_disk_separator, sizeof(ucrs_disk_separator) );
   achl_w1 += sizeof(ucrs_disk_separator);
   memcpy( achl_w1, adsl_cl1->achc_workstation_id, adsl_cl1->imc_len_workstation_id );
   achl_w1 += adsl_cl1->imc_len_workstation_id;
   if (adsl_cl1->imc_len_profile > 0) {     /* length profile          */
     memcpy( achl_w1, ucrs_disk_separator, sizeof(ucrs_disk_separator) );
     achl_w1 += sizeof(ucrs_disk_separator);
     memcpy( achl_w1, adsl_cl1->achc_profile, adsl_cl1->imc_len_profile );
     achl_w1 += adsl_cl1->imc_len_profile;
   }
   memcpy( achl_w1, ucrs_disk_dpc_end, sizeof(ucrs_disk_dpc_end) );
   achl_w1 += sizeof(ucrs_disk_dpc_end);

   memset( &dsl_fior1, 0, sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   dsl_fior1.iec_fioc = ied_fioc_compl_file_read;  /* read complete file */
   dsl_fior1.dsc_ucs_file_name.ac_str = byrl_work1;
   dsl_fior1.dsc_ucs_file_name.imc_len_str = achl_w1 - byrl_work1;
   dsl_fior1.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_FILE_IO,  /* file input-output */
                                    &dsl_fior1,
                                    sizeof(struct dsd_aux_file_io_req_1) );
   if (bol_rc == FALSE) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - returned FALSE",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }
   if (dsl_fior1.iec_fior != ied_fior_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - iec_dfar_def=%d.",
                   __LINE__, dsl_fior1.iec_fior );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - iec_dfar_def=%d.",
                     __LINE__, dsl_fior1.iec_fior );
     }
     iml1 = 0;
     if (adsl_conf->imc_len_dir_dpc) {      /* length directory name dash-proxy-configuration */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W directory: \"%.*(u8)s\"",
                     __LINE__, adsl_conf->imc_len_dir_dpc, byrl_work1 );
       if (iml_seml >= 4) {                 /* <send-error-messages-level> */
         m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W directory: \"%.*(u8)s\"",
                       __LINE__, adsl_conf->imc_len_dir_dpc, byrl_work1 );
       }
       iml1 = adsl_conf->imc_len_dir_dpc + 1;
     }
     *achl_w1 = 0;                          /* make zero-terminated    */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W file-name: \"%(u8)s\"",
                   __LINE__, byrl_work1 + iml1 );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W file-name: \"%(u8)s\"",
                     __LINE__, byrl_work1 + iml1 );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   bol_rc = m_proc_xml_conf( &dsl_sdh_call_1, adsl_cl1,
                             dsl_fior1.achc_data,
                             dsl_fior1.ilc_len_data );
   if (bol_rc == FALSE) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() failed - returned FALSE",
                   __LINE__ );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() failed - returned FALSE",
                     __LINE__ );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (adsl_cl1->dsc_cm.iec_s2at == ied_s2at_ask_user_pwd) {  /* ask user for password */
     iml_rc = m_get_stored_user_pwd( &dsl_sdh_call_1, &dsl_g_idset1 );
     if (iml_rc == 0) {                     /* succeeded               */
       goto p_cl_sign_in_40;                /* credentials SMB server have been prepared */
     }
     if (iml_rc > 0) {                      /* ask user for credentials */
       goto p_ask_user_cred_00;             /* ask user for credentials */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W error get user credentials for SMB-server",
                   __LINE__ );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W error get user credentials for SMB-server",
                     __LINE__ );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (adsl_cl1->dsc_cm.iec_s2at != ied_s2at_cred_cache) {  /* single sign on with WSP credentials */
     goto p_cl_sign_in_40;                  /* credentials SMB server have been prepared */
   }
   /* get encrypted password from CMA                                  */
   iml1 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_user_group )  /* unicode string user-group */
            * sizeof(HL_WCHAR);
   iml2 = m_len_vx_ucs( ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                        &dsl_g_idset1.dsc_userid )  /* unicode string userid */
            * sizeof(HL_WCHAR);
   memcpy( byrl_work1, chrs_cma_pwd_prefix, sizeof(chrs_cma_pwd_prefix) );
   iml3 = m_cpy_vx_ucs( byrl_work1 + sizeof(chrs_cma_pwd_prefix),
                        sizeof(byrl_work1) - sizeof(chrs_cma_pwd_prefix),
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_user_group );  /* unicode string user-group */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_cpy_vx_ucs() user-group returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 = byrl_work1 + sizeof(chrs_cma_pwd_prefix) + iml3 + 1;
   iml3 = m_cpy_vx_ucs( achl_w1,
                        (byrl_work1 + sizeof(byrl_work1)) - achl_w1,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_g_idset1.dsc_userid );  /* unicode string userid */
   if (iml3 < 0) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_cpy_vx_ucs() userid returned error",
                   __LINE__ );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
   achl_w1 += iml3;
   memset( &dsl_accma1, 0, sizeof(struct dsd_hl_aux_c_cma_1) );  /* command common memory area */
   dsl_accma1.ac_cma_name = byrl_work1;     /* cma name                */
   dsl_accma1.iec_chs_name = ied_chs_utf_8;  /* character set          */
   dsl_accma1.inc_len_cma_name = achl_w1 - byrl_work1;  /* length cma name in elements */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_COM_CMA,  /* command common memory area */
                                    &dsl_accma1,
                                    sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured - not found */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_48;                      /* end of password         */
   }
#ifdef B150317
   if (dsl_accma1.inc_len_cma_area == 0) {  /* length of cma area      */
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   if (dsl_accma1.inc_len_cma_area > MAX_PASSWORD) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W password from credential-store length %d too high",
                   __LINE__, dsl_accma1.inc_len_cma_area );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
#ifndef B150317
   iml3 = dsl_accma1.inc_len_cma_area;      /* length password         */
#endif
#endif
   iml3 = dsl_accma1.inc_len_cma_area;      /* length password         */
   if (iml3 == 0) {                         /* length of cma area      */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W password from credential-store length zero",
                   __LINE__ );
     goto p_cl_sta_44;                      /* do unlock               */
   }
   if (iml3 > MAX_PASSWORD) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W password from credential-store length %d too high",
                   __LINE__, iml3 );
     iml3 = 0;                              /* length password         */
     goto p_cl_sta_44;                      /* do unlock               */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = achl_w1 - (byrl_work1 + sizeof(chrs_cma_pwd_prefix));  /* length of post key string */
   dsl_asxor1.imc_len_xor = dsl_accma1.inc_len_cma_area;  /* length of string */
   dsl_asxor1.achc_post_key = byrl_work1 + sizeof(chrs_cma_pwd_prefix);  /* address of post key string */
   dsl_asxor1.achc_source = dsl_accma1.achc_cma_area;  /* address of source */
   dsl_asxor1.achc_destination = adsl_cl1->chrc_password;  /* address of destination */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                    &dsl_asxor1,
                                    sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
//   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
//   return;
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }

   p_cl_sta_44:                             /* unlock CMA              */
   dsl_accma1.iec_ccma_def = ied_ccma_lock_release;  /* release lock   */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_COM_CMA,  /* command common memory area */
                                    &dsl_accma1,
                                    sizeof(struct dsd_hl_aux_c_cma_1) );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_COM_CMA returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
//   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
//   return;
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }

   p_cl_sta_48:                             /* end of password         */
   if (iml3 == 0) {                         /* could not retrieve password */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W could not retrieve password from credential-store",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }
   adsl_cl1->dsc_cm.dsc_ucs_password.ac_str = adsl_cl1->chrc_password;  /* address of string */
   adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str = iml3;  /* length of string in elements */
   adsl_cl1->dsc_cm.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;  /* character set of string */

   if (adsl_cl1->dsc_cm.dsc_ucs_domain.imc_len_str == 0) {  /* length of domain in elements */
     adsl_cl1->dsc_cm.dsc_ucs_domain = dsl_g_idset1.dsc_user_group;
   }
   if (adsl_cl1->dsc_cm.dsc_ucs_userid.imc_len_str == 0) {  /* length of userid in elements */
     adsl_cl1->dsc_cm.dsc_ucs_userid = dsl_g_idset1.dsc_userid;
   }

   p_cl_sign_in_40:                         /* credentials SMB server have been prepared */
   /**
     keepalive configured on server
     has higher priority
     than keepalive configured on client
   */
   if (adsl_cl1->dsc_cm.imc_local_keepalive) {  /* local <time-keepalive> */
     adsl_cl1->imc_keepalive = adsl_cl1->dsc_cm.imc_local_keepalive;  /* local <time-keepalive> */
   }
   bol_put_cred = FALSE;                    /* put / write credendials */

   p_smb_conn_00:                           /* connect to SMB server   */
   memset( &dsl_atc1_1, 0, sizeof(dsl_atc1_1) );
   dsl_atc1_1.dsc_target_ineta = adsl_cl1->dsc_cm.dsc_ucs_server_ineta;
   dsl_atc1_1.imc_server_port = adsl_cl1->dsc_cm.imc_server_port;  /* server-port */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TCP_CONN,
                                    &dsl_atc1_1,
                                    sizeof(struct dsd_aux_tcp_conn_1) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T after DEF_AUX_TCP_CONN bol1=%d iec_tcpconn_ret=%d adsl_dwa=%p.",
                 __LINE__, bol_rc, dsl_atc1_1.iec_tcpconn_ret, adsl_dwa );
#endif
   if (dsl_atc1_1.iec_tcpconn_ret != ied_tcr_ok) {  /* connect successful */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E could not connect to SMB2 server - error %d.",
                   __LINE__, dsl_atc1_1.iec_tcpconn_ret );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E could not connect to SMB2 server - error %d.",
                     __LINE__, dsl_atc1_1.iec_tcpconn_ret );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_cl1->iec_scs = ied_scs_connected;   /* SMB connection connected */
   if (adsl_dwa) {                          /* all dash operations work area */
     goto p_client_rec_36;                  /* virus-checker o.k.      */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_dwa,  /* all dash operations work area */
                                    sizeof(struct dsd_dash_work_all) );  /* all dash operations work area */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef XYZ1
   adsl_dwa->imc_proc_active_channels = 0;  /* need to process active channels client  */
   adsl_dwa->boc_reconnect = FALSE;         /* reconnect from client successful */
#endif
   adsl_dwa->adsc_cf_backlog = NULL;        /* chain copy file backlog */
   adsl_dwa->adsc_cf_bl_cur = NULL;         /* current entry copy file backlog */
//#ifdef DEBUG_140823_01
   adsl_dwa->adsc_gai1_in_from_client = NULL;  /* input data from client */
//#endif
#ifndef B160115
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#endif
   adsl_cl1->ac_work_data = adsl_dwa;       /* all dash operations work area */
   adsl_dwa->umc_state = DWA_STATE_DIR_CLIENT | DWA_STATE_DIR_SERVER | DWA_STATE_XML_SYNC;  /* state of processing */
#ifndef B170106
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_notify_remote = FALSE;      /* notify from server received */
#endif
   if (adsl_cl1->ac_conf_file_control) {    /* configuration of file control */
     memset( &adsl_dwa->dsc_dfcexe, 0, sizeof(struct dsd_dash_fc_execute) );   /* execute DASH file control */
     adsl_dwa->dsc_dfcexe.chc_file_delimiter = '\\';  /* file delimiter */
     adsl_dwa->dsc_dfcexe.ac_conf = adsl_cl1->ac_conf_file_control;  /* configuration of file control */
   }
#ifdef B170106
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
#endif
#ifdef TRACEHL1
   adsl_a1->imc_trace_call = 0;             /* trace call number       */
   adsl_a1->imc_trace_line = 0;             /* line number for tracing */
#endif
   switch (adsl_cl1->dsc_cm.iec_syfu) {     /* synchronize function    */
     case ied_syfu_duplex:                  /* both-directions         */
       adsl_a1->boc_write_server = TRUE;    /* can write to SMB server */
       adsl_a1->boc_write_local = TRUE;     /* can write local         */
       adsl_dwa->boc_virch_local = adsl_conf->boc_virch_local;  /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = adsl_conf->boc_virch_server;  /* virus checking data from server / WSP */
       break;
     case ied_syfu_read_client:             /* read-from-client        */
       adsl_a1->boc_write_server = TRUE;    /* can write to SMB server */
       adsl_a1->boc_write_local = FALSE;    /* can write local         */
       adsl_dwa->boc_virch_local = adsl_conf->boc_virch_local;  /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = FALSE;  /* virus checking data from server / WSP */
       break;
     case ied_syfu_read_server:             /* read-from-server        */
       adsl_a1->boc_write_server = FALSE;   /* can write to SMB server */
       adsl_a1->boc_write_local = TRUE;     /* can write local         */
       adsl_dwa->boc_virch_local = FALSE;   /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = adsl_conf->boc_virch_server;  /* virus checking data from server / WSP */
       break;
     default:
#ifdef NOT_YET_130913
       m_hl1_printf( "xl-sdh-dash-01-l%05d-E dss_cm.iec_syfu invalid function",
                     __LINE__ );
       return -1;
#endif
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E dsc_cm.iec_syfu %d invalid function",
                     __LINE__, adsl_cl1->dsc_cm.iec_syfu );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }

   if (   (adsl_dwa->boc_virch_local == FALSE)  /* virus checking data from local / client */
       && (adsl_dwa->boc_virch_server == FALSE)) {  /* virus checking data from server / WSP */
     goto p_client_rec_36;                  /* virus-checker o.k.      */
   }
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_open;  /* service open connection */
#ifndef WSP_V24
   dsl_aux_sequ1.ac_service_name = (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred;
   dsl_aux_sequ1.imc_len_service_name = adsl_conf->imc_len_file_vch_serv;
   dsl_aux_sequ1.iec_chs_service_name = ied_chs_utf_8;
#endif
#ifdef WSP_V24
   dsl_aux_sequ1.dsc_ucs_name.ac_str = (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred;
   dsl_aux_sequ1.dsc_ucs_name.imc_len_str = adsl_conf->imc_len_file_vch_serv;
   dsl_aux_sequ1.dsc_ucs_name.iec_chs_str = ied_chs_utf_8;
#endif
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SERVICE_REQUEST,  /* service request */
                                    &dsl_aux_sequ1,
                                    sizeof(struct dsd_aux_service_query_1) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_aux_sequ1.iec_ret_service != ied_ret_service_ok) {  /* check service return code */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E Virus Checker Service %.*(u8)s could not be started - error %d.",
                   __LINE__, adsl_conf->imc_len_file_vch_serv, (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred,
                   dsl_aux_sequ1.iec_ret_service );
     if (iml_seml < 9) {                    /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E Virus Checker Service %.*(u8)s could not be started - error %d.",
                     __LINE__, adsl_conf->imc_len_file_vch_serv, (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred,
                     dsl_aux_sequ1.iec_ret_service );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa->vpc_sequ_handle = dsl_aux_sequ1.vpc_sequ_handle;  /* handle of service query */

   p_client_rec_36:                         /* virus-checker o.k.      */
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_start = TRUE;               /* start processing        */
   memset( &adsl_cl1->dsc_smbcl_ctrl, 0, sizeof(struct dsd_hl_smb_cl_ctrl) );  /* HOBLink SMB Client Control */
   adsl_dwa->boc_put_cred = bol_put_cred;   /* save put / write credendials */
#ifdef XYZ1
// to-do 23.12.13 KB - read synchronize file
   adsl_a1->adsc_db1_sync = NULL;           /* directory block 1 - synchonization */
#endif
#ifdef NOT_YET_130913
   ims_local_pos_fn_start = m_cpy_vx_ucs( wcrs_local_fn,
                                          sizeof(wcrs_local_fn) / sizeof(wcrs_local_fn[0]),
                                          ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                                          &adsl_cl1->dsc_cm.dsc_ucs_local_dir );  /* local directory */
   if (ims_local_pos_fn_start < 0) {
#ifdef NOT_YET_130913
     m_hl1_printf( "xl-sdh-dash-01-l%05d-E could not copy name of local directory",
                   __LINE__ );
     return -1;
#endif
   }
   if (ims_local_pos_fn_start > 0) {
     wcrs_local_fn[ ims_local_pos_fn_start++ ] = '\\';
   }
#endif
   adsl_dwa->imc_server_pos_fn_start = m_cpy_vx_ucs( adsl_dwa->byrc_server_fn,
                                                     sizeof(adsl_dwa->byrc_server_fn),
                                                     ied_chs_utf_8,  /* Unicode UTF-8 */
                                                     &adsl_cl1->dsc_cm.dsc_ucs_server_dir );  /* server SMB directory */
   if (adsl_dwa->imc_server_pos_fn_start < 0) {
#ifdef NOT_YET_130913
     m_hl1_printf( "xl-sdh-dash-01-l%05d-E could not copy name of SMB server directory",
                   __LINE__ );
     return -1;
#endif
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E could not copy name of SMB server directory",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_cl1->dsc_smbcl_ctrl.amc_aux = &m_sub_aux;  /* auxiliary callback routine */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
#define ADSL_SMBCC_IN_G ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
#define ADSL_SMBCC_IN_ST_G ((struct dsd_smbcc_in_start *) (ADSL_SMBCC_IN_G + 1))
   memset( ADSL_SMBCC_IN_G, 0, sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_start) );
   ADSL_SMBCC_IN_G->iec_smbcc_in = ied_smbcc_in_start;  /* command input start */
#ifdef WAS_BEFORE
   ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.ac_str = "HOBC01J022";  /* domain */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.ac_str );  /* domain */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.iec_chs_str = ied_chs_utf_8;  /* domain */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.ac_str = "prog01";  /* userid */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.ac_str );  /* userid */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.iec_chs_str = ied_chs_utf_8;  /* userid */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_password.ac_str = "p123p123";  /* password */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_password.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_password.ac_str );  /* password */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_password.iec_chs_str = ied_chs_utf_8;  /* password */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.ac_str = byrs_computername;
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.imc_len_str = dws_len_computername;
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.iec_chs_str = ied_chs_utf_16;
   ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.ac_str = "HOBC01J022.hob.de";
   ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.ac_str );
   ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.ac_str = "\\\\172.22.81.22\\disk_c";  /* name of tree to connect to */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.ac_str );
   ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.iec_chs_str = ied_chs_utf_8;
#endif
   ADSL_SMBCC_IN_ST_G->dsc_ucs_domain = adsl_cl1->dsc_cm.dsc_ucs_domain;  /* domain */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_userid = adsl_cl1->dsc_cm.dsc_ucs_userid;  /* userid */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_password = adsl_cl1->dsc_cm.dsc_ucs_password;  /* password */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.ac_str = adsl_cl1->achc_workstation_id;  /* address workstation-id */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.imc_len_str = adsl_cl1->imc_len_workstation_id;  /* length workstation-id */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta = adsl_cl1->dsc_cm.dsc_ucs_server_ineta;  /* server-ineta */
   ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name = adsl_cl1->dsc_cm.dsc_ucs_server_tree;  /* server SMB tree */
   if (adsl_cl1->dsc_cm.iec_s2at == ied_s2at_krb5) {  /* Kerberos 5    */
     ADSL_SMBCC_IN_ST_G->boc_krb5 = TRUE;   /* use Kerberos 5 authentication */
   }
#ifdef B150411
#ifdef TRY_KRB5
   ADSL_SMBCC_IN_ST_G->boc_krb5 = TRUE;     /* use Kerberos 5 authentication */
#endif
#endif
   if (adsp_hl_clib_1->imc_trace_level == 0) {  /* WSP trace level     */
     goto p_client_rec_38;                  /* WSP-trace done          */
   }
   memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
   memcpy( dsl_wtrh.chrc_wtrt_id, "DASMBS01", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
   dsl_wtrh.imc_wtrh_sno = adsp_hl_clib_1->imc_sno;  /* WSP session number */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) byrl_work1)
   dsl_wtrh.adsc_wtrh_chain = ADSL_WTR_G1;  /* chain of WSP trace records */
   memset( ADSL_WTR_G1, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G1->achc_content = (char *) (ADSL_WTR_G1 + 1);  /* content of text / data */
   ADSL_WTR_G1->imc_length = sprintf( (char *) (ADSL_WTR_G1 + 1),
                                      "xl-sdh-dash-01 l%05d start SMB client boc_krb5=%d.",
                                      __LINE__, ADSL_SMBCC_IN_ST_G->boc_krb5 );
   achl_w1 = (char *) (ADSL_WTR_G1 + 1) + ((ADSL_WTR_G1->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   aadsl_wtr_w1 = &ADSL_WTR_G1->adsc_next;
#undef ADSL_WTR_G1
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
   /* output dsc_ucs_domain                                            */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_domain );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_domain imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_domain.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
   /* output dsc_ucs_userid                                            */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_userid );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_userid imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_userid.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
   /* output dsc_ucs_password                                          */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_password );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_password imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_password.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_password.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_password.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
   /* output dsc_ucs_workstation                                       */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_workstation imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_workstation.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
   /* output dsc_ucs_target_ineta                                      */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_target_ineta imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_target_ineta.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
   /* output dsc_ucs_tree_name                                         */
   memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
   ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;   /* text passed             */
   ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
   iml1 = m_len_bytes_ucs( &ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name );
   ADSL_WTR_G2->imc_length = sprintf( (char *) (ADSL_WTR_G2 + 1),
                                      "*** dsc_ucs_tree_name imc_len_str=%d iec_chs_str=%d bytes=%d.",
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.imc_len_str,
                                      ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.iec_chs_str,
                                      iml1 );
   *aadsl_wtr_w1 = ADSL_WTR_G2;
   aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
   achl_w1 = (char *) (ADSL_WTR_G2 + 1) + ((ADSL_WTR_G2->imc_length + sizeof(void *) - 1) & (0 - sizeof(void *)));
   if (iml1 > 0) {                          /* with content            */
     memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
     ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed     */
     ADSL_WTR_G2->achc_content = (char *) ADSL_SMBCC_IN_ST_G->dsc_ucs_tree_name.ac_str;  /* content of text / data */
     ADSL_WTR_G2->imc_length = iml1;
     *aadsl_wtr_w1 = ADSL_WTR_G2;
     aadsl_wtr_w1 = &ADSL_WTR_G2->adsc_next;
     achl_w1 += sizeof(struct dsd_wsp_trace_record);
   }
#undef ADSL_WTR_G2
   *aadsl_wtr_w1 = NULL;                    /* end of chain            */

   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                    &dsl_wtrh,
                                    0 );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

#undef ADSL_SMBCC_IN_G
#undef ADSL_SMBCC_IN_ST_G

   p_client_rec_38:                         /* WSP-trace done          */
   bol_call_smb_cl = TRUE;                  /* call SMB client         */

   bol1 = TRUE;                             /* do not send remove old resources */
   if (adsl_cl1->imc_proc_active_channels == 0) {  /* no need to process active channels client */
     goto p_send_sel_dir_00;                /* send selected directories */
   }
   adsl_cl1->boc_reconnect = TRUE;          /* reconnect from client successful */
#ifdef XYZ1
   if (adsl_dwa->imc_proc_active_channels == 0) {  /* no need to process active channels client */
     goto p_send_sel_dir_00;                /* send selected directories */
   }
   adsl_dwa->boc_reconnect = TRUE;          /* reconnect from client successful */
#endif
   adsl_cl1->iec_clst = ied_clst_rec_active_channels;  /* receive active channels */
   goto p_client_rec_00;                    /* check received from client */

   p_client_rec_40:                         /* received data channel   */
   if (iml_tag != 0) {                      /* received data           */
     goto p_client_rec_60;                  /* received data           */
   }
#ifdef TRACEHL1
   adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   iml1 = 0;
   if (adsl_dwa) {
     iml1 = adsl_dwa->umc_state;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_client_rec_40: -1- adsl_cl1->iec_clst=%d adsl_dwa=%p ->umc_state=0X%08X.",
                 __LINE__, adsl_cl1->iec_clst, adsl_dwa, iml1 );
   if (adsl_dwa) {
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_client_rec_40: -2- boc_changed_local=%d boc_notify_local=%d.",
                   __LINE__, adsl_a1->boc_changed_local, adsl_a1->boc_notify_local );
   }
#endif
#ifdef WA_170113_01
   adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   if (adsl_dwa) {
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif
   /* consume input                                                    */
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   if (adsl_dwa) {                          /* all dash operations work area */
     adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsl_gai1_inp_2, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (adsl_dwa) {                          /* all dash operations work area */
     adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   }

   switch (adsl_cl1->iec_clst) {            /* state of connection to client */
#ifdef B160323
     case ied_clst_resp_file_control:       /* wait for response file-control */
#endif
#ifndef B160323
     case ied_clst_resp_file_control_w:     /* wait for response file-control */
#endif
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
#ifndef B160323
       adsl_cl1->iec_clst = ied_clst_resp_file_control_p;  /* process after response file-control */
#endif
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       if (adsl_cl1->boc_reconnect) {       /* client does reconnect   */
//     if (adsl_dwa->boc_reconnect) {       /* client does reconnect   */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_client_rec_40: client does reconnect",
                       __LINE__ );
#endif
         goto p_cont_client_reco_00;        /* continue client reconnect */
       }
#ifdef B151219
       if (adsl_a1->boc_write_server) {     /* can write to SMB server */
         adsl_cl1->boc_local_notify = TRUE;  /* notify local / client is active */
         goto p_cl_send_ch_notify_00;       /* send change notify      */
       }
       goto p_cl_send_get_all_dir_00;       /* get all directories     */
#endif
       break;
     case ied_clst_resp_set_ch_notify:      /* wait for response set change notify */
       if ((adsl_dwa->umc_state & DWA_STATE_DIR_CLIENT) == 0) {  /* state of processing */
#ifdef WA_160813_01
         if (adsl_cl1->iec_scs == ied_scs_query_dir) {  /* first query-directory */
           goto p_ret_00;                   /* return                  */
         }
#endif
         goto p_acs_done_20;                /* nothing on the way      */
       }
       goto p_cl_send_get_all_dir_00;       /* get all directories     */
     case ied_clst_resp_all_dir_1:          /* wait for response all directories - start */
     case ied_clst_resp_all_dir_2:          /* wait for response all directories - continue */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
     case ied_clst_resp_end:                /* wait for response end command */
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
       if ((adsl_dwa->umc_state & DWA_STATE_DIR_CLIENT) == 0) {  /* state of processing */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
#ifndef B150228
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
#ifdef DEBUG_170413_01                      /* address adsl_a1 invalid */
   if (adsl_dwa != ((struct dsd_dash_work_all *) adsl_cl1->ac_work_data)) {  /* all dash operations work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_dwa invalid - %p.",
                   __LINE__, adsl_dwa );
     adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   }
   if (adsl_a1 != &adsl_dwa->dsc_a1) {      /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_a1 invalid - %p.",
                   __LINE__, adsl_a1 );
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif  /* DEBUG_170413_01                     address adsl_a1 invalid */
       if (adsl_a1->boc_notify_local) {     /* notify from client received */
#ifdef TRACEHL1
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T case ied_clst_resp_end:",
                       __LINE__ );
#endif
#ifdef DEBUG_170410_01                      /* address adsc_file_1_parent invalid */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T case ied_clst_resp_end: notify from client",
                       __LINE__ );
#endif  /* DEBUG_170410_01                     address adsc_file_1_parent invalid */
#ifdef XYZ1
// 28.02.15 KB - do we have a memory leak ???
         adsl_work_idc = &adsl_dwa->dsc_work_idc;  /* data for work    */
         dsl_dw1 = adsl_work_idc->dsc_dw1;  /* restore directory operations work area */
         if (dsl_dw1.adsc_db1_start) {
           bol_rc = m_dir_free( &dsl_sdh_call_1, dsl_dw1.adsc_db1_start );
           if (bol_rc == FALSE) {           /* returned error          */
             iml1 = __LINE__;
             goto p_abend_00;               /* abend of program        */
           }
           dsl_dw1.adsc_db1_start = NULL;
         }
#endif
         if (adsl_a1->adsc_db1_local) {     /* directory block 1 - local */
#ifdef B150304
           bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_local );
           if (bol_rc == FALSE) {           /* returned error          */
             iml1 = __LINE__;
             goto p_abend_00;               /* abend of program        */
           }
#endif
#ifndef B150304
           if (adsl_a1->adsc_db1_local != adsl_a1->adsc_db1_sync) {  /* not table sync the same */
             bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_local );
             if (bol_rc == FALSE) {         /* returned error          */
               iml1 = __LINE__;
               goto p_abend_00;             /* abend of program        */
             }
           }
#endif
           adsl_a1->adsc_db1_local = NULL;  /* directory block 1 - local */
         }
#ifdef DEBUG_170410_01                      /* address adsc_file_1_parent invalid */
         if (adsl_a1->adsc_db1_sync) {
           m_check_parent_1( &dsl_sdh_call_1,
                             adsl_a1->adsc_db1_sync,
                             "notify from client 1", __LINE__ );
         }
#endif  /* DEBUG_170410_01                     address adsc_file_1_parent invalid */
         goto p_cl_send_get_all_dir_00;     /* get all directories     */
       }
#endif
       adsl_dwa->umc_state &= -1 - DWA_STATE_DIR_CLIENT;  /* state of processing */
       if (adsl_dwa->umc_state & (DWA_STATE_DIR_SERVER | DWA_STATE_XML_SYNC)) break;  /* state of processing */
#ifdef B150228
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
#endif
       adsl_cl1->iec_clst = ied_clst_idle;  /* client is idle          */
       if (adsl_dwa->adsc_cf_bl_cur) {      /* current entry copy file backlog - processing backlog */
         goto p_proc_bl_40;                 /* delete backlog entry    */
       }
#ifdef XYZ1
#ifndef B150304
       adsl_a1->boc_start = TRUE;           /* start processing        */
#endif
#endif
       goto p_next_action_00;               /* check for next action   */
     case ied_clst_resp_read_file_normal:   /* wait for read file normal */
     case ied_clst_resp_read_file_compressed:  /* wait for read file compressed */
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
#ifdef XYZ1
       if (adsl_dwa->boc_virch_local) {     /* virus checking data from local / client */
         goto p_client_rec_44;              /* received end input data with virus checking */
       }
#endif
       if (adsl_dwa->umc_state & DWA_STATE_VCH_STARTED) {  /* state of processing - virus checking started */
         goto p_client_rec_44;              /* received end input data with virus checking */
       }
       adsl_cl1->iec_clst = ied_clst_end_read_file;  /* received end read file */
#ifndef B150127
       if (adsl_conf->boc_virch_local) {    /* virus checking data from local / client */
         goto p_ss2smb_00;                  /* copy from Swap Storage to SMB */
       }
#endif
       goto p_cf_cl2se_80;                  /* received end of input file */
     case ied_clst_resp_del_ch_notify_normal:  /* wait for response delete change notify - normal */
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       adsl_cl1->iec_clst = ied_clst_idle;  /* client is idle          */
       goto p_next_action_20;               /* check what to do for next action */
     case ied_clst_resp_del_ch_notify_vc:   /* wait for response delete change notify - virus checking */
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
       adsl_cl1->iec_clst = ied_clst_idle;  /* client is idle          */
       goto p_ss2cl_00;                     /* copy from Swap Storage to client */
     case ied_clst_resp_write_file:         /* wait for response write file */
     case ied_clst_resp_misc:               /* wait for response miscellaneous command */
       if (adsl_dwa == NULL) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         iml1 = __LINE__;
         goto p_error_received_from_client;  /* invalid data received from client */
       }
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       adsl_cl1->iec_clst = ied_clst_idle;  /* client is idle          */
       if (adsl_dwa->adsc_cf_bl_cur) {      /* current entry copy file backlog - processing backlog */
         goto p_proc_bl_40;                 /* delete backlog entry    */
       }
       goto p_next_action_00;               /* check for next action   */
   }
   goto p_ret_00;                           /* return                  */

   p_client_rec_44:                         /* received end input data with virus checking */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_client_rec_44: received end input data with virus checking",
                 __LINE__ );
#endif
   adsl_dwa->umc_state &= -1 - DWA_STATE_VCH_STARTED;  /* state of processing */
   adsl_dwifvc = &adsl_dwa->dsc_work_ifvc;  /* input file with virus-checking */
   adsl_wvc1 = &adsl_dwifvc->dsc_wvc1;      /* virus-checking          */
   if (adsl_cl1->iec_clst == ied_clst_resp_read_file_compressed) {  /* wait for read file compressed */
     goto p_client_rec_48;                  /* received end input data with virus checking - compressed */
   }
   adsl_cl1->iec_clst = ied_clst_end_read_file;  /* received end read file */
   adsl_wvc1->iec_vcend = ied_vcend_recv_end;  /* end input received   */
   bol_rc = m_work_vc_end( &dsl_sdh_call_1,
                           adsl_wvc1,       /* virus-checking          */
                           adsl_dwa,        /* all dash operations work area */
                           adsl_dwifvc->achc_out,
                           &bol_call_vc );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   goto p_ret_00;                           /* return                  */

   p_client_rec_48:                         /* received end input data with virus checking - compressed */
   if (adsl_dwifvc->dsc_cdf_ctrl.imc_return != DEF_IRET_END) {  /* compression not ended normal */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received end input file compressed from client but compression not ended",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_received_from_client;     /* invalid data received from client */
   }
// to-do 21.12.14 KB - maybe file already written to SMB or virus found
//   needs to process next action
   adsl_cl1->iec_clst = ied_clst_end_read_file;  /* received end read file */
   goto p_ret_00;                           /* return                  */
//-------------- 20.12.14 KB

   p_cl_act_ch_00:                          /* received active channel from client */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_act_ch_00:",
                 __LINE__ );
#endif
   if (adsl_cl1->imc_proc_active_channels == 0) {  /* need to process active channels client */
// if (adsl_dwa->imc_proc_active_channels == 0) {  /* need to process active channels client */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
//----------------
   iml_flags = 0;                           /* flags                   */
   iml_len_directory = 0;                   /* length of directory     */

   p_cl_act_ch_20:                          /* get sub-tag             */
   iml1 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml1 < 0) {                          /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 == 0) {                         /* length field too short  */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received UUUUUUUUUUUUUUU length field NHASN %d too short",
                   __LINE__, iml1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml_rl -= iml1;                          /* decrement length of record */
   if (iml_rl < 0) {                        /* check length of record  */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   iml_st = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml1 );
   if (iml_st < 0) {                        /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received data reconnect channel program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   achl_w1 = NULL;                          /* no output               */
   switch (iml_st) {                        /* sub-tag of field        */
     case 0:                                /* flags                   */
       achl_w1 = (char *) &iml_flags;       /* flags                   */
       goto p_cl_act_ch_40;                 /* decode content NHASN    */
     case 1:                                /* workstation id          */
       if (iml1 > sizeof(byrl_work1)) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received data UUUUcontrol channel program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       if (iml_len_directory > 0) {         /* length of directory     */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received data UUUUcontrol channel program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       iml_len_directory = iml1;            /* length of directory     */
       achl_w1 = byrl_work1;                /* output to work area     */
       break;
   }
   /* copy content of field                                            */
   while (TRUE) {                           /* loop over input data    */
     iml2 = adsl_gai1_inp_1->achc_ginp_end - achl_rp;
     if (iml2 > iml1) iml2 = iml1;
     if (achl_w1) {                         /* copy field              */
       memcpy( achl_w1, achl_rp, iml2 );
       achl_w1 += iml2;
     }
     achl_rp += iml2;                       /* overread this part      */
     iml1 -= iml2;                          /* remaining length of field */
     if (iml1 <= 0) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content program illogic",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   if (iml_rl > 0) {                        /* check length of record  */
     goto p_cl_act_ch_20;                   /* next field in reconnect channel */
   }
   goto p_cl_act_ch_60;                     /* fields decoded          */

   p_cl_act_ch_40:                          /* decode content NHASN    */
   iml3 = 0;                                /* content                 */
   iml2 = MAX_LEN_NHASN;                    /* maximum length NHASN    */
   while (TRUE) {                           /* loop over input data    */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received UUUUUol channel sub-tag %d content NHASN program illogic",
                       __LINE__, iml_st );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
     iml3 <<= 7;                            /* shift old value         */
     iml3 |= *achl_rp & 0X7F;               /* apply new bits          */
     iml1--;                                /* field length            */
     if (iml1 < 0) {                        /* NHASN exceeds field length */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received UUUUUol channel sub-tag %d content NHASN longer than remaining field",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     if (*((signed char *) achl_rp) >= 0) break;  /* more bit not set  */
     if (iml2 <= 0) {                       /* too many digits         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received UUUUrol channel sub-tag sub-tag %d content NHASN too many digits",
                     __LINE__, iml_st );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
     }
     iml2--;                                /* decrement count maximum length NHASN */
     achl_rp++;                             /* next input character    */
   }
   achl_rp++;                               /* next input character    */
   if (iml1 != 0) {                         /* remaining length of field */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel sub-tag %d content NHASN too short %d.",
                   __LINE__, iml_st, iml1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   *((int *) achl_w1) = iml3;               /* set content of field    */
   if (iml_rl > 0) {                        /* check length of record  */
     goto p_cl_act_ch_20;                   /* next field in reconnect channel */
   }

   p_cl_act_ch_60:                          /* fields decoded          */
#ifdef DEBUG_160810_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_act_ch_60: adsl_cl1->iec_clst=%d ->boc_smb_connected=%d ->boc_reconnect=%d.",
                 __LINE__,
                 adsl_cl1->iec_clst,
                 adsl_cl1->boc_smb_connected,
                 adsl_cl1->boc_reconnect );
#endif
   /* consume input                                                    */
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;  /* scanning done up to here */

   dsl_ucs_file_l.ac_str = byrl_work1;      /* address of string       */
   dsl_ucs_file_l.imc_len_str = iml_len_directory;  /* length string in elements */
   dsl_ucs_file_l.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8       */
   bol_rc = m_cmp_ucs_ucs( &iml_cmp,
                           &adsl_cl1->dsc_cm.dsc_ucs_local_dir,  /* local directory */
                           &dsl_ucs_file_l );
#ifdef DEBUG_160810_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_act_ch_60: iml_cn=%d DASH_CHANNEL=%d iml_flags=%d bol_rc=%d iml_cmp=%d.",
                 __LINE__,
                 iml_cn, DASH_CHANNEL, iml_flags, bol_rc, iml_cmp );
#endif
   if (   (iml_cn != DASH_CHANNEL)          /* DASH channel used       */
       || ((iml_flags & 1) == 0)            /* flags - not synchonized */
       || (bol_rc == FALSE)
       || (iml_cmp != 0)) {
     adsl_cl1->boc_reconnect = FALSE;       /* reconnect from client successful */
#ifdef XYZ1
     adsl_dwa->boc_reconnect = FALSE;       /* reconnect from client successful */
#endif
   }

   adsl_cl1->imc_proc_active_channels--;    /* decrement process active channels client */
   if (adsl_cl1->imc_proc_active_channels > 0) {  /* more process active channels client */
     goto p_client_rec_00;                  /* check received from client */
   }
#ifdef XYZ1
   adsl_dwa->imc_proc_active_channels--;    /* decrement process active channels client */
   if (adsl_dwa->imc_proc_active_channels > 0) {  /* more process active channels client */
     goto p_client_rec_00;                  /* check received from client */
   }
#endif
#ifdef XYZ1
   if (adsl_cl1->boc_send_delete_resources == FALSE) {  /* send delete resources to client */
     goto p_client_rec_00;                  /* check received from client */
   }
#endif
// to-do 30.08.14 KB - check if more input from client, invalid
   adsl_dwa->adsc_gai1_in_from_client = NULL;  /* do not save input data from client */
#ifndef B160115
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#endif
   bol1 = adsl_cl1->boc_reconnect;          /* set if send remove old resources */
#ifdef XYZ1
   bol1 = adsl_dwa->boc_reconnect;          /* set if send remove old resources */
#endif

   /* send select directory to client                                  */
   p_send_sel_dir_00:                       /* send selected directories */
   /* if bol1 == FALSE send remove old resources to client             */
#define CHRL_WORK_1 dsl_sdh_call_1.achc_lower
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   /* achl_w1 is end of packet, achl_w2 is start of packet             */
   achl_w1 = CHRL_WORK_1 + 8 + 4 + 8 + 4 + 1;
   iml1 = m_cpy_vx_ucs( achl_w1, LEN_FILE_NAME, ied_chs_utf_8,
                        &adsl_cl1->dsc_cm.dsc_ucs_local_dir );
   if (iml1 <= 0) {
// to-do 03.04.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   achl_w2 = achl_w1;                       /* get start directory name */
   *(--achl_w2) = 0;                        /* tag file-name           */
   iml2 = 1 + iml1;                         /* compute length          */
   iml3 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* remove bits             */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
   achl_w1 += iml1;                         /* end of directory name   */
   iml1 = m_len_vx_ucs( ied_chs_utf_8,
                        &adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn );  /* local temporary file-name */
#ifdef WA_150302_01                         /* problem Unicode library */
   if (iml1 < 0) iml1 = 0;
#endif
   if (iml1 < 0) {
// to-do 03.04.14 KB error message
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (iml1 == 0) {                         /* no temporary file-name  */
     goto p_send_sel_dir_20;                /* end of temporary file-name */
   }
   iml2 = iml3 = 1 + iml1;                  /* compute length          */
   do {                                     /* loop to find length     */
     achl_w1++;                             /* space for digit         */
     iml2 >>= 7;                            /* shift bits              */
   } while (iml2 > 0);
   achl_w3 = achl_w1;                       /* end of number NHASN     */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl_w3) = (unsigned char) ((iml3 & 0X7F) | iml2);
     iml3 >>= 7;                            /* remove bits             */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml3 > 0);
   *achl_w1++ = 1;                          /* tag                     */
   m_cpy_vx_ucs( achl_w1, iml1, ied_chs_utf_8,
                 &adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn );  /* local temporary file-name */
   achl_w1 += iml1;                         /* end of temporary file-name */

   p_send_sel_dir_20:                       /* end of temporary file-name */
   if (adsl_cl1->dsc_cm.boc_local_create_shared_dir) {  /* local create shared directory */
     /* tag options                                                    */
     *achl_w1++ = 2;                        /* length                  */
     *achl_w1++ = 2;                        /* tag options             */
     *achl_w1++ = DASH_SECH_OPT_CREATE_SHARED;  /* options             */
   }
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w1;
   dsl_sdh_call_1.achc_lower = achl_w1;
   *(--achl_w2) = DASH_DCH_SELECT_DIRECTORY;
   *(--achl_w2) = DASH_CHANNEL;
   iml2 = achl_w1 - achl_w2;                /* length of packet        */
   iml3 = 0;                                /* clear more bit          */
   do {                                     /* loop output NHASN       */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* remove bits             */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);

   if (bol1 == FALSE) {                     /* send remove old resources */
     *(--achl_w2) = (unsigned char) 2;      /* tag remove old resources */
     *(--achl_w2) = (unsigned char) 0;      /* channel number - control channel */
     *(--achl_w2) = (unsigned char) 2;      /* length net of data      */
   }

   /* send keepalive on control channel                                */
   if (adsl_cl1->imc_keepalive) {           /* value for keepalive set */
     achl_w3 = achl_w2;                     /* save end of packet      */
     iml2 = adsl_cl1->imc_keepalive;        /* value for keepalive set */
     iml3 = 0;                              /* clear more bit          */
     do {                                   /* loop output NHASN       */
       *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
       iml2 >>= 7;                          /* remove bits             */
       iml3 = 0X80;                         /* set more bit            */
     } while (iml2 > 0);
     *(--achl_w2) = 1;                      /* keepalive               */
     *(--achl_w2) = 0;                      /* control channel         */
     iml1 = achl_w3 - achl_w2;              /* length of packet        */
     *(--achl_w2) = (unsigned char) iml1;   /* length of packet        */
   }
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140106
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef CHRL_WORK_1
#undef ADSL_GAI1_OUT_W
#ifdef B160323
   adsl_cl1->iec_clst = ied_clst_resp_file_control;  /* wait for response file-control */
#endif
#ifndef B160323
   adsl_cl1->iec_clst = ied_clst_resp_file_control_w;  /* wait for response file-control */
#endif
// to-do 28.08.14 KB - error, not input from server, jump elsewhere
// goto p_smb_rec_00;                       /* call SMB client component */
   goto p_ret_00;                           /* return                  */

   p_cont_client_reco_00:                   /* continue client reconnect */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cont_client_reco_00:",
                 __LINE__ );
#endif
   if (adsl_a1->boc_write_server) {         /* can write to SMB server */
     adsl_cl1->boc_local_notify = TRUE;     /* notify local / client is active */
   }
#ifdef B150207
   bol_rc = m_read_xml_sync_file( &dsl_sdh_call_1,
                                  &adsl_cl1->dsc_cm.dsc_ucs_sync_fn,  /* synchronize file-name */
                                  &adsl_dwa->dsc_a1.adsc_db1_sync,  /* directory block 1 - synchonization */
                                  &adsl_a1->ilc_sum_size_local );  /* sum file size client    */
#endif
#ifndef B150207
   bol_rc = m_read_xml_sync_file( &dsl_sdh_call_1,
                                  &adsl_cl1->dsc_cm.dsc_ucs_sync_fn,  /* synchronize file-name */
                                  &adsl_dwa->dsc_a1.adsc_db1_sync,  /* directory block 1 - synchonization */
                                  &adsl_cl1->ilc_sum_size_local );  /* sum file size client */
#endif
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa->umc_state &= -1 - DWA_STATE_XML_SYNC;  /* state of processing */
   if (adsl_dwa->umc_state & DWA_STATE_XML_WRITE) {  /* state of processing */
     goto p_cl_send_get_all_dir_00;         /* get all directories     */
   }
   adsl_a1->adsc_db1_local = adsl_a1->adsc_db1_sync;  /* client contains same as synchonize file */
// adsl_a1->boc_unix_local = FALSE;         /* local is Unix file system */
   adsl_dwa->umc_state &= -1 - DWA_STATE_DIR_CLIENT;  /* state of processing */
   if ((adsl_dwa->umc_state & (DWA_STATE_DIR_CLIENT | DWA_STATE_DIR_SERVER | DWA_STATE_XML_SYNC)) == 0) {  /* state of processing */
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
     goto p_next_action_00;                 /* check for next action   */
   }
   goto p_ret_00;                           /* return                  */

   p_cl_send_ch_notify_00:                  /* send change notify      */
#ifdef DEBUG_160810_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_send_ch_notify_00: adsl_cl1->iec_clst=%d ->boc_smb_connected=%d ->boc_reconnect=%d.",
                 __LINE__,
                 adsl_cl1->iec_clst,
                 adsl_cl1->boc_smb_connected,
                 adsl_cl1->boc_reconnect );
#endif
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = (char *) ucrs_dash_send_set_ch_notify;
   ADSL_GAI1_OUT_W->achc_ginp_end = (char *) ucrs_dash_send_set_ch_notify + sizeof(ucrs_dash_send_set_ch_notify);
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140106
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_resp_set_ch_notify;  /* wait for response set change notify */
   if (iel_prco == ied_prco_smb_change_ntfy) {  /* SMB send change notify request */
#ifdef DEBUG_170119_01
     iml1 = __LINE__;
#endif
     goto p_smb_change_ntfy_00;             /* SMB send change notify request */
   }
   goto p_ret_00;                           /* return                  */

   p_cl_send_del_chnot_00:                  /* send delete change notify */
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) (adsp_hl_clib_1->achc_work_area + adsp_hl_clib_1->inc_len_work_area - sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_OUT_W->achc_ginp_cur = (char *) ucrs_dash_send_del_ch_notify;
   ADSL_GAI1_OUT_W->achc_ginp_end = (char *) ucrs_dash_send_del_ch_notify + sizeof(ucrs_dash_send_del_ch_notify);
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140106
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W
#ifdef XYZ1
   adsl_cl1->iec_clst = ied_clst_resp_del_ch_notify;  /* wait for response delete change notify */
#endif
   goto p_ret_00;                           /* return                  */

   p_cl_send_get_all_dir_00:                /* get all directories     */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_send_get_all_dir_00: adsl_cl1->iec_clst=%d.",
                 __LINE__, adsl_cl1->iec_clst );
#endif
   adsl_dwa->dsc_a1.boc_notify_local = FALSE;  /* notify from client received */
#ifndef B150207
   adsl_cl1->ilc_sum_size_local = 0;        /* sum file size client    */
#endif
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = (char *) ucrs_dash_send_all_dir;
   ADSL_GAI1_OUT_W->achc_ginp_end = (char *) ucrs_dash_send_all_dir + sizeof(ucrs_dash_send_all_dir);
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140106
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_resp_all_dir_1;  /* wait for response all directories */
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 2) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
     m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                       "xl-sdh-dash-01-l%05d-I command to client: send all directory information",
                       __LINE__ );
   }
   goto p_ret_00;                           /* return                  */

   p_client_rec_60:                         /* received data           */
#ifdef XYZ1
   if (iml_tag != DASH_DCH_CL2SE_DIR_COMPR) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
#endif
   if (adsl_dwa) {                          /* normal flow             */
     goto p_client_rec_64;                  /* ready for processing command */
   }
   if (iml_tag != DASH_DCH_CL2SE_CHANGE_NOTIFY) {  /* received change notify */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W waiting only for change notify from client - received command %d.",
                   __LINE__, iml_tag );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   /* consume token from input stream                                  */
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, byrl_work1, iml_rl );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_resync_lo_re = FALSE;                /* TRUE means remote       */
   goto p_resync_00;                        /* start resync - something has changed */

   p_client_rec_64:                         /* ready for processing command */
   if (iml_tag == DASH_DCH_CL2SE_ACT_CHANNEL) {  /* input active channel */
     goto p_cl_act_ch_00;                   /* received active channel from client */
   }
   if (iml_cn != DASH_CHANNEL) {            /* DASH channel used       */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E received invalid channel %d from client",
                     __LINE__, iml_cn );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
   if (adsl_cl1->imc_proc_active_channels != 0) {  /* need to process active channels client  */
// if (adsl_dwa->imc_proc_active_channels != 0) {  /* need to process active channels client  */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   switch (iml_tag) {                       /* command received        */
     case DASH_DCH_CL2SE_ERROR:             /* error from client       */
       goto p_cl_error_00;                  /* received error from client */
     case DASH_DCH_CL2SE_MSG1:              /* received message 1 from client */
       goto p_cl_msg1_00;                   /* received DASH_DCH_CL2SE_MSG1 */
     case DASH_DCH_CL2SE_DIR_COMPR:
       break;
     case DASH_DCH_CL2SE_FILE_NORMAL:
       goto p_cl_rfn_00;                    /* read file normal        */
     case DASH_DCH_CL2SE_FILE_COMPR:
       goto p_cl_rfc_00;                    /* read file compressed    */
     case DASH_DCH_CL2SE_CHANGE_NOTIFY:     /* received change notify  */
       goto p_cl_rcn_00;                    /* received change notify  */
     default:
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - tag=%d.",
                     __LINE__, iml_tag );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
   if (iml_rl <= 0) {                       /* no more data received   */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
   if (adsl_cl1->iec_clst == ied_clst_resp_all_dir_2) {  /* wait for response all directories - continue */
     adsl_work_idc = &adsl_dwa->dsc_work_idc;  /* data for work        */
     dsl_dw1 = adsl_work_idc->dsc_dw1;      /* restore directory operations work area */
     bol1 = TRUE;                           /* received continue block */
#ifdef TRACEHL1
     adsl_work_idc->dsc_cdf_ctrl.vpc_userfld = (void *) 3;  /* User Field Subroutine */
#endif
     goto p_cl_dir_co_08;                   /* process response all directories */
   }
   if (adsl_cl1->iec_clst != ied_clst_resp_all_dir_1) {  /* wait for response all directories */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
#ifdef XYZ1
   if (adsl_dwa) {                          /* all dash operations work area */
     adsl_work_idc = &adsl_dwa->dsc_work_idc;  /* data for work        */
     dsl_dw1 = adsl_work_idc->dsc_dw1;      /* restore directory operations work area */
     bol1 = TRUE;                           /* received continue block */
     goto p_cl_dir_co_08;                   /* process response all directories */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_dwa,  /* all dash operations work area */
                                    sizeof(struct dsd_dash_work_all) );  /* all dash operations work area */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_cl1->ac_work_data = adsl_dwa;       /* all dash operations work area */
#endif
   adsl_cl1->iec_clst = ied_clst_resp_all_dir_2;  /* wait for response all directories - continue */
   adsl_work_idc = &adsl_dwa->dsc_work_idc;  /* data for work          */
#ifdef WAS_B130917
// adsl_dwa->dsc_dfcexe.chc_file_delimiter = '/';  /* file delimiter   */
   adsl_dwa->dsc_dfcexe.chc_file_delimiter = '\\';  /* file delimiter  */
#endif
   memset( &adsl_work_idc->dsc_cdf_ctrl, 0, sizeof(struct dsd_cdf_ctrl) );  /* compress data file oriented control */
   memcpy( adsl_work_idc->dsc_cdf_ctrl.chrc_eye_catcher, ucrs_eye_catcher, sizeof(ucrs_eye_catcher) );
   adsl_work_idc->dsc_cdf_ctrl.amc_aux = &m_sub_aux;  /* auxiliary callback routine */
   adsl_work_idc->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   m_cdf_dec( &adsl_work_idc->dsc_cdf_ctrl );
   if (adsl_work_idc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   adsl_work_idc->imc_ds1_index = 0;        /* index of stack entry directory */
   dsl_dw1.adsc_db1_start = NULL;           /* directory block 1 - chaining - start */
   dsl_dw1.adsc_file_1_parent = NULL;       /* entry of parent directory */
   dsl_dw1.adsc_f1_used = NULL;             /* last used single file   */
   bol1 = FALSE;                            /* received continue block */

   p_cl_dir_co_08:                          /* process response all directories */
#ifdef WAS_B130917
// adsl_dwa->dsc_dfcexe.chc_file_delimiter = '/';  /* file delimiter   */
   adsl_dwa->dsc_dfcexe.chc_file_delimiter = '\\';  /* file delimiter  */
#endif
   adsl_dwa->dsc_dfcexe.amc_aux = &m_sub_aux;  /* aux-call routine pointer */
   adsl_dwa->dsc_dfcexe.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   adsl_work_idc->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */

   /* consume input till this position                                 */
#ifdef B140824
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
#endif
#ifndef B140824
   adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
#endif
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
   adsl_gai1_w1 = dsrl_gai1_work;           /* copy gather here        */
   iml1 = MAX_INP_GATHER;                   /* number of input gather to be processed */
   while (TRUE) {                           /* loop to fill gather structures for compression */
     iml2 = adsl_gai1_inp_1->achc_ginp_end - achl_rp;
     if (iml2 > 0) {                        /* data found              */
       if (iml2 > iml_rl) iml2 = iml_rl;
       adsl_gai1_w1->achc_ginp_cur = achl_rp;
       adsl_gai1_w1->achc_ginp_end = achl_rp + iml2;
       adsl_gai1_w1->adsc_next = NULL;
       achl_rp += iml2;
       adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
       iml_rl -= iml2;
       if (iml_rl <= 0) break;
#ifdef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
       adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
       adsl_gai1_w1++;
       iml1--;
#ifndef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - too many input gather",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
// to-do 27.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   adsl_work_idc->dsc_cdf_ctrl.adsc_gai1_in = dsrl_gai1_work;  /* input data */
   if (bol1) {                              /* received continue block */
     goto p_cl_dir_co_a2;                   /* de-compress data        */
   }
   adsl_work_idc->dsc_cdf_ctrl.achc_out_cur = adsl_work_idc->byrc_deco;  /* decompressed data */
   adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + sizeof(adsl_work_idc->byrc_deco);  /* decompressed data */
#ifdef XYZ1
   adsl_work_idc->dsrc_gai1_data[ 0 ].achc_ginp_cur = adsl_work_idc->dsrc_gai1_data[ 0 ].achc_ginp_end = NULL;  /* output from compression */
   adsl_gai1_w1 = adsl_work_idc->dsrc_gai1_data;  /* output from compression */
   if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
     adsl_gai1_w1->adsc_next = NULL;
     adsl_gai1_w1++;
   }
   adsl_gai1_w1->achc_ginp_cur = adsl_work_idc->byrc_deco;  /* decompressed data */
#endif
   memset( &adsl_work_idc->dsrc_gai1_data, 0, sizeof(adsl_work_idc->dsrc_gai1_data) );
   adsl_gai1_w1 = adsl_gai1_w2 = adsl_work_idc->dsrc_gai1_data;  /* output from compression */
   adsl_gai1_w1->achc_ginp_cur = adsl_work_idc->byrc_deco;  /* decompressed data */
   m_cdf_dec( &adsl_work_idc->dsc_cdf_ctrl );
   if (adsl_work_idc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error adsl_work_idc->dsc_cdf_ctrl.imc_return=%d.",
                     __LINE__, adsl_work_idc->dsc_cdf_ctrl.imc_return );
//     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
//   return;
   }
   adsl_gai1_w1->achc_ginp_end = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;  /* end decompressed data */
   if (adsl_gai1_w1->achc_ginp_end > (adsl_work_idc->byrc_deco + LEN_CHUNK_DECO)) {
     adsl_gai1_w1->achc_ginp_end = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
     (adsl_gai1_w1 + 1)->achc_ginp_cur = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;
     (adsl_gai1_w1 + 1)->achc_ginp_end = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;  /* end decompressed data */
   }
#ifdef XYZ1
   adsl_gai1_w1->adsc_next = NULL;
   adsl_gai1_w1 = adsl_work_idc->dsrc_gai1_data;  /* output from compression */
#endif
   achl_rp = adsl_gai1_w1->achc_ginp_cur;   /* start scanning here     */

#ifndef HELP_DEBUG
#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (dsl_dw1.adsc_db1_start + 1))
#endif

   p_cl_dir_co_20:                          /* process output from compression */
   if (adsl_gai1_w1 == NULL) {              /* end of input data       */
     goto p_cl_dir_co_a0;                   /* not enough input data   */
   }
   iml1 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp, NULL );
   if (iml1 <= 0) {                         /* not valid length        */
     if (iml1 < 0) {                        /* check if error          */
       goto p_cl_dir_co_a0;                 /* not enough input data   */
     }
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   bol_rc = m_check_input_complete( &dsl_sdh_call_1, adsl_gai1_w1, achl_rp, iml1 );
   if (bol_rc == FALSE) {                   /* check what returned     */
     goto p_cl_dir_co_a0;                   /* not enough input data   */
   }
   iml2 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp, &iml1 );
   if (iml2 < 0) {                          /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
#ifdef TRACEHL1
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T type 0X%X.",
                     __LINE__, (unsigned char) iml2 );
#endif
   switch (iml2) {                          /* check tag               */
     case 1:                                /* file name               */
     case 2:                                /* directory name          */
       goto p_cl_dir_co_24;                 /* file or directory found */
     case 3:                                /* end of sub directory    */
       goto p_cl_dir_co_80;                 /* end of sub directory    */
     case 0X10:
       goto p_cl_dir_co_40;                 /* found attributes of file */
     case 0X11:
       goto p_cl_dir_co_44;                 /* found attributes of directory */
     case 0X20:
       goto p_cl_dir_co_48;                 /* found attributes of Unix file */
     case 0X21:
       goto p_cl_dir_co_56;                 /* found attributes of Unix directory */
   }
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
#ifdef XYZ1
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
#endif

   p_cl_dir_co_24:                          /* file or directory found */
   if (dsl_dw1.adsc_f1_used != NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   dsl_dw1.imc_file_tag = iml2;             /* save tag of file / directory */
   if (   (dsl_dw1.adsc_db1_start == NULL)  /* directory block 1 - chaining - start */
       || (((char *) (dsl_dw1.adsc_f1_cur + 1)) > (dsl_dw1.achc_fn_low - iml1))) {
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_MEMGET,
                                      &dsl_dw1.adsc_db1_cur,
                                      LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     if (dsl_dw1.adsc_db1_start == NULL) {  /* directory block 1 - chaining - start */
       dsl_dw1.adsc_db1_start = dsl_dw1.adsc_db1_cur;  /* directory block 1 - chaining - start */
#ifdef HELP_DEBUG
       ADSL_DB2_G = (struct dsd_dir_bl_2 *) (dsl_dw1.adsc_db1_start + 1);
#endif
       dsl_dw1.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (dsl_dw1.adsc_db1_start + 1) + sizeof(struct dsd_dir_bl_2));
       ADSL_DB2_G->imc_no_files = 0;        /* number of files         */
       ADSL_DB2_G->imc_no_dir = 0;          /* number of directories   */
       ADSL_DB2_G->boc_unix = FALSE;        /* is Unix filesystem      */
       if (adsl_cl1->imc_capabilities & 2) {  /* capabilities client */
         ADSL_DB2_G->boc_unix = TRUE;       /* is Unix filesystem      */
       }
       bol_rc = m_htree1_avl_init( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                   &m_cmp_file );
       if (bol_rc == FALSE) {               /* error occured           */
//       m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_dir_local() m_htree1_avl_init() failed",
//                     __LINE__ );
//       return FALSE;
       }
#ifdef B150207
       dsl_dw1.ilc_sum_size_local = 0;      /* sum file size client    */
#endif
     } else {
       dsl_dw1.adsc_db1_last->adsc_next = dsl_dw1.adsc_db1_cur;  /* directory block 1 - chaining */
       dsl_dw1.adsc_db1_last->achc_end_file = (char *) dsl_dw1.adsc_f1_cur;  /* end of files */
       dsl_dw1.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (dsl_dw1.adsc_db1_cur + 1));
     }
     dsl_dw1.adsc_db1_last = dsl_dw1.adsc_db1_cur;  /* directory block 1 - chaining - last */
     dsl_dw1.achc_fn_low = (char *) dsl_dw1.adsc_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
#ifdef HELP_DEBUG
   ADSL_DB2_G = (struct dsd_dir_bl_2 *) (dsl_dw1.adsc_db1_start + 1);
#endif
   dsl_dw1.achc_fn_low -= iml1;             /* space for file name     */
   memset( dsl_dw1.adsc_f1_cur, 0, sizeof(struct dsd_file_1) );  /* entry of a single file */
   dsl_dw1.adsc_f1_cur->adsc_file_1_parent = dsl_dw1.adsc_file_1_parent;  /* entry of parent directory */
// dsl_dw1.adsc_f1_cur->adsc_file_1_same_n = NULL;  /* chain of entries same name */
   dsl_dw1.adsc_f1_cur->dsc_ucs_file.ac_str = dsl_dw1.achc_fn_low;
   dsl_dw1.adsc_f1_cur->dsc_ucs_file.imc_len_str = iml1;
   dsl_dw1.adsc_f1_cur->dsc_ucs_file.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
// adsl_f1_cur->dwc_file_attributes = dsl_win_find_data.dwFileAttributes;
// adsl_f1_cur->dsc_last_write_time = dsl_win_find_data.ftLastWriteTime;
// adsl_f1_cur->ilc_file_size = (HL_LONGLONG) (dsl_win_find_data.nFileSizeHigh << 32) | dsl_win_find_data.nFileSizeLow;
#ifdef B131223
   dsl_dw1.adsc_f1_cur->achc_virus = NULL;  /* virus found             */
#endif
// dsl_dw1.adsc_f1_cur->umc_flags = 0;      /* flags for processing    */
// dsl_dw1.adsc_f1_cur->achc_virus_client = NULL;  /* virus found on client */
// dsl_dw1.adsc_f1_cur->achc_virus_server = NULL;  /* virus found on server */
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp, dsl_dw1.achc_fn_low, iml1 );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsl_gai1_w2, adsl_gai1_w1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   dsl_dw1.adsc_f1_used = dsl_dw1.adsc_f1_cur;  /* last used single file */
   dsl_dw1.adsc_f1_cur++;                   /* space of next file      */
   goto p_cl_dir_co_20;                     /* process output from compression */

   p_cl_dir_co_40:                          /* found attributes of file */
   if (dsl_dw1.adsc_f1_used == NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 != (sizeof(dsl_dw1.adsc_f1_used->dwc_file_attributes)
                  + sizeof(dsl_dw1.adsc_f1_used->dsc_last_write_time)
                  + sizeof(dsl_dw1.adsc_f1_used->ilc_file_size))) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
// to-do 29.12.13 KB dwc_file_attributes sometimes needs to be big endian ???
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                (char *) &dsl_dw1.adsc_f1_used->dwc_file_attributes,
                                sizeof(dsl_dw1.adsc_f1_used->dwc_file_attributes) );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   dsl_dw1.adsc_f1_used->dwc_file_attributes &= -1 - FILE_ATTRIBUTE_ARCHIVE;
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                (char *) &dsl_dw1.adsc_f1_used->dsc_last_write_time,
                                sizeof(dsl_dw1.adsc_f1_used->dsc_last_write_time) );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
#ifdef B140102
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                (char *) &dsl_dw1.adsc_f1_used->ilc_file_size,
                                sizeof(dsl_dw1.adsc_f1_used->ilc_file_size) );
#endif
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                byrl_work1,
                                sizeof(dsl_dw1.adsc_f1_used->ilc_file_size) );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_get_le8( &dsl_dw1.adsc_f1_used->ilc_file_size, byrl_work1 );
#ifdef B150207
   dsl_dw1.ilc_sum_size_local += dsl_dw1.adsc_f1_used->ilc_file_size;  /* sum file size client */
#endif
#ifndef B150207
   adsl_cl1->ilc_sum_size_local += dsl_dw1.adsc_f1_used->ilc_file_size;  /* sum file size client */
#endif
   goto p_cl_dir_co_60;                     /* end processing file or directory */

   p_cl_dir_co_44:                          /* found attributes of directory */
   if (dsl_dw1.adsc_f1_used == NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 != sizeof(dsl_dw1.adsc_f1_used->dwc_file_attributes)) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                (char *) &dsl_dw1.adsc_f1_used->dwc_file_attributes,
                                sizeof(dsl_dw1.adsc_f1_used->dwc_file_attributes) );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if ((dsl_dw1.adsc_f1_used->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   ADSL_DB2_G->imc_no_dir++;                /* number of directories   */
   goto p_cl_dir_co_60;                     /* end processing file or directory */

   p_cl_dir_co_48:                          /* found attributes of Unix file */
   if (dsl_dw1.adsc_f1_used == NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 != (LEN_UNIX_DIR_ATTR            /* length of Unix directory attribute */
                  + LEN_UNIX_FILETIME
                  + sizeof(dsl_dw1.adsc_f1_used->ilc_file_size))) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                byrl_work1,
                                LEN_UNIX_DIR_ATTR  /* length of Unix directory attribute */
                                  + LEN_UNIX_FILETIME
                                  + sizeof(dsl_dw1.adsc_f1_used->ilc_file_size) );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_get_le4( &iml1, byrl_work1 );
   if (iml1 & CHECK_UNIX_ISDIR) {           /* check Unix S_ISDIR(m)   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_get_le4( &iml1, byrl_work1 + LEN_UNIX_DIR_ATTR );
#ifdef B150228
   *((HL_LONGLONG *) &dsl_dw1.adsc_f1_used->dsc_last_write_time)
     = (HL_LONGLONG)
         ((unsigned int) iml1) * 1000 * 1000 * 10
           + 116444736000000000;
#endif
   *((HL_LONGLONG *) &dsl_dw1.adsc_f1_used->dsc_last_write_time)
     = (HL_LONGLONG)
         ((unsigned int) iml1) * 1000 * 1000 * 10
           + TIME_ADJUST;
   m_get_le8( &dsl_dw1.adsc_f1_used->ilc_file_size, byrl_work1 + LEN_UNIX_DIR_ATTR + LEN_UNIX_FILETIME );
#ifdef B150207
   dsl_dw1.ilc_sum_size_local += dsl_dw1.adsc_f1_used->ilc_file_size;  /* sum file size client */
#endif
#ifndef B150207
   adsl_cl1->ilc_sum_size_local += dsl_dw1.adsc_f1_used->ilc_file_size;  /* sum file size client */
#endif
   goto p_cl_dir_co_60;                     /* end processing file or directory */

   p_cl_dir_co_56:                          /* found attributes of Unix directory */
   if (dsl_dw1.adsc_f1_used == NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 != LEN_UNIX_DIR_ATTR) {         /* length of Unix directory attribute */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_w1, &achl_rp,
                                byrl_work1,
                                LEN_UNIX_DIR_ATTR );  /* length of Unix directory attribute */
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_get_le4( &iml1, byrl_work1 );
   if ((iml1 & CHECK_UNIX_ISDIR) == 0) {    /* check Unix S_ISDIR(m)   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   dsl_dw1.adsc_f1_used->dwc_file_attributes = FILE_ATTRIBUTE_DIRECTORY;
   ADSL_DB2_G->imc_no_dir++;                /* number of directories   */

   p_cl_dir_co_60:                          /* end processing file or directory */
   ADSL_DB2_G->imc_no_files++;              /* number of files         */
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsl_gai1_w2, adsl_gai1_w1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   dsl_dw1.adsc_f1_used->iec_dac = ied_dac_read_write;  /* access      */
   dsl_dw1.adsc_f1_used->boc_exclude_compression = FALSE;  /* <exclude-compression> */
   if (adsl_cl1->ac_conf_file_control) {    /* configuration of file control */
     adsl_dwa->dsc_dfcexe.dsc_ucs_filename = dsl_dw1.adsc_f1_used->dsc_ucs_file;
     if (dsl_dw1.adsc_f1_used->adsc_file_1_parent) {  /* entry of parent directory */
       adsl_dwa->dsc_dfcexe.dsc_ucs_filename.ac_str = byrl_server_fn;
       adsl_dwa->dsc_dfcexe.dsc_ucs_filename.imc_len_str
         = m_build_file_name_utf8( &dsl_sdh_call_1, dsl_dw1.adsc_f1_used, byrl_server_fn, '\\' );
       if (adsl_dwa->dsc_dfcexe.dsc_ucs_filename.imc_len_str <= 0) {
         iml1 = __LINE__;                   /* set line of error       */
         goto p_cl_illogic;                 /* illogic processing of data received from client */
       }
     }
     bol_rc = m_dash_file_control_execute( &adsl_dwa->dsc_dfcexe );
     if (bol_rc == FALSE) {                 /* error occured           */
       iml1 = __LINE__;                     /* set line of error       */
       goto p_cl_illogic;                   /* illogic processing of data received from client */
     }
     dsl_dw1.adsc_f1_used->iec_dac = adsl_dwa->dsc_dfcexe.iec_dac;  /* access */
     dsl_dw1.adsc_f1_used->boc_exclude_compression = adsl_dwa->dsc_dfcexe.boc_exclude_compression;  /* <exclude-compression> */
#ifdef B150111
     if (adsl_dwa->dsc_dfcexe.ilc_max_file_size) {  /* if not zero found <max-file-size> */
#ifdef B140102
       iml_cmp = m_cmp_longlong_2( (char *) &dsl_dw1.adsc_f1_cur->ilc_file_size, adsl_dwa->dsc_dfcexe.ilc_max_file_size );
       if (iml_cmp > 0) {                   /* file too big            */
         dsl_dw1.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
       }
#endif
       if (dsl_dw1.adsc_f1_cur->ilc_file_size > adsl_dwa->dsc_dfcexe.ilc_max_file_size) {
         dsl_dw1.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
       }
     }
#endif
#ifdef B150827
#ifndef B150111
     if (   (dsl_dw1.adsc_f1_used->iec_dac != ied_dac_read_write)  /* access read-write */
         && (dsl_dw1.adsc_f1_used->iec_dac != ied_dac_write_only)) {  /* access write-only */
       dsl_dw1.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_ACCESS;  /* access not allowed */
     }
     if (   (adsl_dwa->dsc_dfcexe.ilc_max_file_size)  /* if not zero found <max-file-size> */
         && (dsl_dw1.adsc_f1_used->umc_flags == 0)  /* access not allowed */
         && (dsl_dw1.adsc_f1_used->ilc_file_size > adsl_dwa->dsc_dfcexe.ilc_max_file_size)) {
       dsl_dw1.adsc_f1_used->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
     }
#endif
#endif
#ifndef B150827
     if (   (dsl_dw1.adsc_f1_used->iec_dac != ied_dac_read_write)  /* access read-write */
         && (dsl_dw1.adsc_f1_used->iec_dac != ied_dac_write_only)) {  /* access write-only */
       dsl_dw1.adsc_f1_used->umc_flags |= D_FILE_1_FLAG_ACCESS;  /* access not allowed */
     }
     if (   (adsl_dwa->dsc_dfcexe.ilc_max_file_size)  /* if not zero found <max-file-size> */
         && (dsl_dw1.adsc_f1_used->umc_flags == 0)  /* access not allowed */
         && (dsl_dw1.adsc_f1_used->ilc_file_size > adsl_dwa->dsc_dfcexe.ilc_max_file_size)) {
       dsl_dw1.adsc_f1_used->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
     }
#endif
   }
   if (   (adsl_conf->ilc_max_file_size)    /* maximum file-size       */
       && (adsl_conf->boc_virch_local)) {   /* virus checking data from local / client */
#ifdef B140102
     iml_cmp = m_cmp_longlong_2( (char *) &dsl_dw1.adsc_f1_cur->ilc_file_size, adsl_conf->ilc_max_file_size );
     if (iml_cmp > 0) {                     /* file too big            */
       dsl_dw1.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
     }
#endif
     if (dsl_dw1.adsc_f1_used->ilc_file_size > adsl_conf->ilc_max_file_size) {
       dsl_dw1.adsc_f1_used->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
     }
   }

   /* add file to AVL-tree                                             */
   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &dsl_dw1.adsc_f1_used->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
     if (ADSL_F1_SORT->adsc_file_1_same_n == NULL) {  /* chain of entries same name */
       ADSL_F1_SORT->adsc_file_1_same_n = dsl_dw1.adsc_f1_used;  /* chain of entries same name */
     } else {                               /* already files with same name */
       adsl_f1_w1 = ADSL_F1_SORT->adsc_file_1_same_n;  /* get chain of entries same name */
       while (adsl_f1_w1->adsc_file_1_same_n) {  /* check chain of entries same name */
         adsl_f1_w1 = adsl_f1_w1->adsc_file_1_same_n;  /* next in chain of entries same name */
       }
       adsl_f1_w1->adsc_file_1_same_n = dsl_dw1.adsc_f1_used;  /* append to chain of entries same name */
     }
     goto p_cl_dir_co_72;                   /* continue processing end file or directory */
#undef ADSL_F1_SORT
   }
   bol_rc = m_htree1_avl_insert( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &dsl_dw1.adsc_f1_used->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }

   p_cl_dir_co_72:                          /* continue processing end file or directory */
// to-do 28.08.13 - file-control
   if (dsl_dw1.imc_file_tag == 1) {         /* was normal file         */
     dsl_dw1.adsc_f1_used = NULL;           /* last used single file   */
     goto p_cl_dir_co_20;                   /* process output from compression */
   }
   if (adsl_work_idc->imc_ds1_index >= MAX_DIR_STACK) {  /* index of stack entry directory */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   adsl_work_idc->adsrc_f1_dir_nesting[ adsl_work_idc->imc_ds1_index ] = dsl_dw1.adsc_file_1_parent;
   adsl_work_idc->imc_ds1_index++;          /* index of stack entry directory */
   dsl_dw1.adsc_file_1_parent = dsl_dw1.adsc_f1_used;  /* entry of parent directory */
   dsl_dw1.adsc_f1_used = NULL;             /* last used single file   */
   goto p_cl_dir_co_20;                     /* process output from compression */

   p_cl_dir_co_80:                          /* end of sub directory    */
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsl_gai1_w2, adsl_gai1_w1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (dsl_dw1.adsc_f1_used != NULL) {      /* last used single file   */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (adsl_work_idc->imc_ds1_index == 0) {  /* index of stack entry directory */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   adsl_work_idc->imc_ds1_index--;          /* index of stack entry directory */
   dsl_dw1.adsc_file_1_parent = adsl_work_idc->adsrc_f1_dir_nesting[ adsl_work_idc->imc_ds1_index ];
   goto p_cl_dir_co_20;                     /* process output from compression */

   p_cl_dir_co_a0:                          /* not enough input data   */
   if (adsl_work_idc->dsrc_gai1_data[0].achc_ginp_cur >= adsl_work_idc->dsrc_gai1_data[0].achc_ginp_end) {
     memcpy( &adsl_work_idc->dsrc_gai1_data[0], &adsl_work_idc->dsrc_gai1_data[1], sizeof(struct dsd_gather_i_1) );
     memset( &adsl_work_idc->dsrc_gai1_data[1], 0, sizeof(struct dsd_gather_i_1) );
#ifdef TRACEHL1
   } else {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_dir_co_a0: first gather not processed",
                   __LINE__ );
#endif
   }
   adsl_gai1_w1 = dsrl_gai1_work;           /* copy gather here        */
   while (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     if (adsl_gai1_w1 == NULL) {            /* end of input data       */
       goto p_cl_dir_co_a8;                 /* we need more input for de-compression */
     }
   }
   /* de-compression has not yet processed all input                   */
   if (adsl_work_idc->dsrc_gai1_data[0].adsc_next) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (adsl_work_idc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* de-compression end */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }

   p_cl_dir_co_a2:                          /* de-compress data        */
   if (adsl_work_idc->dsrc_gai1_data[0].adsc_next) {
     adsl_gai1_w1 = &adsl_work_idc->dsrc_gai1_data[1];  /* output from compression */
     adsl_work_idc->dsc_cdf_ctrl.achc_out_cur = adsl_work_idc->dsrc_gai1_data[1].achc_ginp_end;  /* decompressed data */
     adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;  /* decompressed data */
     if (adsl_work_idc->dsc_cdf_ctrl.achc_out_cur >= (adsl_work_idc->byrc_deco + LEN_CHUNK_DECO)) {  /* is in second halve of buffer */
       adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + sizeof(adsl_work_idc->byrc_deco);  /* decompressed data */
     }
     goto p_cl_dir_co_a6;                    /* gather output for de-compression set */
   }
   if (adsl_work_idc->dsrc_gai1_data[0].achc_ginp_cur >= adsl_work_idc->dsrc_gai1_data[0].achc_ginp_end) {
     adsl_work_idc->dsc_cdf_ctrl.achc_out_cur = adsl_work_idc->byrc_deco;  /* decompressed data */
     adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + sizeof(adsl_work_idc->byrc_deco);  /* decompressed data */
     adsl_gai1_w1 = adsl_work_idc->dsrc_gai1_data;  /* output from compression */
     goto p_cl_dir_co_a4;                   /* output area for for de-compression set */
   }
   adsl_gai1_w1 = &adsl_work_idc->dsrc_gai1_data[1];  /* output from compression */
   adsl_work_idc->dsrc_gai1_data[0].adsc_next = adsl_gai1_w1;
   if (adsl_work_idc->dsrc_gai1_data[0].achc_ginp_cur < (adsl_work_idc->byrc_deco + LEN_CHUNK_DECO)) {
     adsl_work_idc->dsc_cdf_ctrl.achc_out_cur = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;  /* decompressed data */
     adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + sizeof(adsl_work_idc->byrc_deco);  /* decompressed data */
     goto p_cl_dir_co_a4;                   /* output area for for de-compression set */
   }
   adsl_work_idc->dsc_cdf_ctrl.achc_out_cur = adsl_work_idc->byrc_deco;  /* decompressed data */
   adsl_work_idc->dsc_cdf_ctrl.achc_out_end = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;  /* decompressed data */

   p_cl_dir_co_a4:                          /* output area for for de-compression set */
   adsl_gai1_w1->achc_ginp_cur = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;  /* decompressed data */

   p_cl_dir_co_a6:                          /* gather output for de-compression set */
#ifdef TRACEHL1
   achl_w1 = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;
   iml1 = adsl_work_idc->dsc_cdf_ctrl.achc_out_end - achl_w1;
#endif
   m_cdf_dec( &adsl_work_idc->dsc_cdf_ctrl );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_dir_co_a6: imc_return=%d de-compr %p till %p length %p space %p.",
                 __LINE__,
                 adsl_work_idc->dsc_cdf_ctrl.imc_return,
                 achl_w1, adsl_work_idc->dsc_cdf_ctrl.achc_out_cur, adsl_work_idc->dsc_cdf_ctrl.achc_out_cur - achl_w1,
                 iml1 );
#endif
   if (adsl_work_idc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
//     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
//   return;
   }
   adsl_gai1_w1->achc_ginp_end = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;  /* end decompressed data */
   if (   (adsl_gai1_w1 == adsl_work_idc->dsrc_gai1_data)  /* strategy to fill buffer */
       && (adsl_gai1_w1->achc_ginp_end > (adsl_work_idc->byrc_deco + LEN_CHUNK_DECO))) {
     adsl_gai1_w1->achc_ginp_end = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
     (adsl_gai1_w1 + 1)->achc_ginp_cur = adsl_work_idc->byrc_deco + LEN_CHUNK_DECO;
     (adsl_gai1_w1 + 1)->achc_ginp_end = adsl_work_idc->dsc_cdf_ctrl.achc_out_cur;  /* end decompressed data */
   }
   adsl_gai1_w1 = adsl_gai1_w2 = adsl_work_idc->dsrc_gai1_data;  /* output from compression */
   achl_rp = adsl_gai1_w1->achc_ginp_cur;   /* start scanning here     */
   goto p_cl_dir_co_20;                     /* process output from compression */

   p_cl_dir_co_a8:                          /* we need more input for de-compression */
   if (adsl_work_idc->dsc_cdf_ctrl.imc_return == DEF_IRET_NORMAL) {  /* continue processing */
     adsl_work_idc->dsc_dw1 = dsl_dw1;      /* save directory operations work area */
     goto p_client_rec_00;                  /* check received from client */
   }
#ifdef B140104
   if (adsl_gai1_w2) {                      /* part not decoded        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
#endif
#ifndef TO_BE_DELETED_141210
   if (   (adsl_gai1_w2)                    /* part not decoded        */
       && (   (adsl_gai1_w2->achc_ginp_cur)
           || (adsl_gai1_w2->achc_ginp_end))) {
#ifdef B141210
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
#endif
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T end of compression and more data received from client",
                     __LINE__ );
   }
#endif
#ifndef B131223
   if (dsl_dw1.adsc_db1_start) {            /* found files             */
     dsl_dw1.adsc_db1_last->adsc_next = NULL;  /* directory block 1 - chaining */
     dsl_dw1.adsc_db1_last->achc_end_file = (char *) dsl_dw1.adsc_f1_cur;  /* end of files */
   }
#endif
#ifdef TRACEHL1
   if (dsl_dw1.adsc_db1_start) {            /* found files             */
     m_trace_dir( &dsl_sdh_call_1, dsl_dw1.adsc_db1_start, "received directory" );
   } else {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T no files found on client",
                   __LINE__ );
   }
#endif
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 2) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
     if (dsl_dw1.adsc_db1_start) {          /* found files             */
       m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                         "xl-sdh-dash-01-l%05d-I end scanning client - files %(dec1,)d / directories %(dec1,)d / size %(sci-data)lldB.",
                         __LINE__,
                         ADSL_DB2_G->imc_no_files - ADSL_DB2_G->imc_no_dir,  /* number of files */
                         ADSL_DB2_G->imc_no_dir,  /* number of directories */
                         adsl_cl1->ilc_sum_size_local );  /* sum file size client */
     } else {                               /* no files found on client */
       m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                         "xl-sdh-dash-01-l%05d-I end scanning client - no files found",
                         __LINE__ );
     }
   }
#ifdef WAS_BEFORE_130916
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &adsl_work_idc,
                                    sizeof(struct dsd_work_in_dir_compr) );
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_cl1->ac_work_data = NULL;           /* data for work           */
#endif
#ifndef B150228
#ifdef TRACEHL1
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   if (adsl_a1->boc_notify_local) {         /* notify from client received */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_dir_co_a8: boc_notify_local adsl_cl1->iec_clst=%d.",
                   __LINE__, adsl_cl1->iec_clst );
   }
#endif
   adsl_cl1->iec_clst = ied_clst_resp_end;  /* wait for response end command */
#endif
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
#ifdef DEBUG_170413_01                      /* address adsl_a1 invalid */
   if (adsl_dwa != ((struct dsd_dash_work_all *) adsl_cl1->ac_work_data)) {  /* all dash operations work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_dwa invalid - %p.",
                   __LINE__, adsl_dwa );
     adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   }
   if (adsl_a1 != &adsl_dwa->dsc_a1) {      /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_a1 invalid - %p.",
                   __LINE__, adsl_a1 );
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif  /* DEBUG_170413_01                     address adsl_a1 invalid */
   if (adsl_a1->boc_notify_local) {         /* notify from client received */
#ifdef B150228
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_dir_co_a8: boc_notify_local adsl_cl1->iec_clst=%d.",
                   __LINE__, adsl_cl1->iec_clst );
#endif
     bol_rc = m_dir_free( &dsl_sdh_call_1, dsl_dw1.adsc_db1_start );
     if (bol_rc == FALSE) {                 /* returned error          */
       iml1 = __LINE__;
       goto p_abend_00;                     /* abend of program        */
     }
     dsl_dw1.adsc_db1_start = NULL;
     goto p_cl_send_get_all_dir_00;         /* get all directories     */
#endif
#ifndef B150228
     goto p_client_rec_00;                  /* check received from client */
#endif
   }
   adsl_a1->adsc_db1_local = dsl_dw1.adsc_db1_start;  /* directory block 1 - local */
// adsl_a1->boc_unix_local = dsl_dw1.boc_unix;  /* local is Unix file system */
#ifdef B150207
   adsl_a1->ilc_sum_size_local = 0;         /* sum file size client    */
   if (dsl_dw1.adsc_db1_start) {            /* files received from client */
     adsl_a1->ilc_sum_size_local = dsl_dw1.ilc_sum_size_local;  /* sum file size client */
   }
#endif
#ifdef B150228
   adsl_cl1->iec_clst = ied_clst_resp_end;  /* wait for response end command */
#endif
   goto p_client_rec_00;                    /* check received from client */

#ifndef HELP_DEBUG
#undef ADSL_DB2_G
#endif

   p_cl_rfc_00:                             /* read file compressed    */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_00:",
                 __LINE__ );
#endif
// to-do 20.12.14 KB - check start input from client and jump to other label
#ifndef B140202
   if (adsl_cl1->iec_clst != ied_clst_resp_read_file_compressed) {  /* wait for read file compressed */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
   }
#endif
#ifndef B150307
   if (adsl_cl1->iec_scs == ied_scs_closed) {  /* SMB connection closed */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - server closed",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
   }
#endif
   if (adsl_dwa->boc_virch_local) {         /* virus checking data from local / client */
// to-do 22.05.14 KB - check if virus-checking already started
     adsl_dwifvc = &adsl_dwa->dsc_work_ifvc;  /* input file with virus-checking */
     adsl_wvc1 = &adsl_dwifvc->dsc_wvc1;    /* virus-checking          */
     if ((adsl_dwa->umc_state & DWA_STATE_VCH_ACT) == 0) {  /* state of processing - virus checking not yet started */
       goto p_cl_vch_sta_00;                /* start virus-checking with data received from client */
     }
     if (adsl_wvc1->imc_ss_ahead > 1) {     /* swap storage in use     */
       goto p_ret_00;                       /* return, wait till virus-checking is more advanced */
     }
     adsl_cdf_ctrl = &adsl_dwifvc->dsc_cdf_ctrl;  /* compress data file oriented control */
     goto p_cl_rfc_08;                      /* de-compression started  */
   }
   if (adsl_cl1->iec_scs == ied_scs_idle) {  /* idle, nothing to do    */
     goto p_cf_cl2se_20;                    /* copy client to server normal, no virus checking, no swap storage */
   }
   if (adsl_cl1->iec_scs != ied_scs_write_wait) {  /* write file / wait for next input */
     goto p_ret_00;                         /* return                  */
   }
   adsl_wcl2smb = &adsl_dwa->dsc_work_cl2smb;  /* copy client to server SMB */
   adsl_cdf_ctrl = &adsl_wcl2smb->dsc_cdf_ctrl;  /* compress data file oriented control */
   if (adsl_cdf_ctrl->amc_aux) {            /* de-compression already started */
     goto p_cl_rfc_08;                      /* de-compression started  */
   }

   /* start de-compression                                             */
   memset( adsl_cdf_ctrl, 0, sizeof(struct dsd_cdf_ctrl) );  /* compress data file oriented control */
   memcpy( adsl_cdf_ctrl->chrc_eye_catcher, ucrs_eye_catcher, sizeof(ucrs_eye_catcher) );
   adsl_cdf_ctrl->amc_aux = &m_sub_aux;     /* auxiliary callback routine */
   adsl_cdf_ctrl->vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   m_cdf_dec( adsl_cdf_ctrl );
   if (adsl_cdf_ctrl->imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }

   p_cl_rfc_08:                             /* de-compression started  */
   /* consume input till this position                                 */
   adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
   aadsl_gai1_ch1 = &adsl_cdf_ctrl->adsc_gai1_in;  /* chain of gather - input data */
// adsl_gai1_w1 = (struct dsd_gather_i_1 *) byrl_work1;  /* build input here */
   adsl_gai1_w1 = dsrl_gai1_work;           /* copy gather here        */
   iml1 = MAX_INP_GATHER;                   /* number of input gather to be processed */
   iml3 = iml_rl;                           /* get remainder in record */
   achl_w1 = achl_rp;                       /* get read pointer        */
   while (TRUE) {                           /* loop to fill gather structures for de-compression */
     iml2 = adsl_gai1_inp_2->achc_ginp_end - achl_w1;
     if (iml2 > 0) {                        /* data found              */
       if (iml2 > iml3) iml2 = iml3;
       adsl_gai1_w1->achc_ginp_cur = achl_w1;
       adsl_gai1_w1->achc_ginp_end = achl_w1 + iml2;
       *aadsl_gai1_ch1 = adsl_gai1_w1;      /* append to chain         */
       aadsl_gai1_ch1 = &adsl_gai1_w1->adsc_next;
       achl_w1 += iml2;
       iml3 -= iml2;
       if (iml3 <= 0) break;
#ifdef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 29.11.14 KB - just break and continue decompression later
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - too many input gather",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
       adsl_gai1_w1++;
       iml1--;
#ifndef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 29.11.14 KB - just break and continue decompression later
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - too many input gather",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
     }
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_2 == NULL) {         /* program illogic         */
// to-do 27.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_w1 = adsl_gai1_inp_2->achc_ginp_cur;  /* start scanning here */
   }
   *aadsl_gai1_ch1 = NULL;                  /* end of chain            */
   if (adsl_cdf_ctrl->adsc_gai1_in == NULL) {  /* chain of gather - input data */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
   }
   iml_in_gather = iml_rl - iml3;           /* count data in gather    */

#ifdef TRY_141129_DOES_NOT_WORK
   p_cl_rfc_10:                             /* continue de-compression */
#endif
   adsl_cdf_ctrl->vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   if (adsl_dwa->boc_virch_local) {         /* virus checking data from local / client */
     goto p_cl_rfc_20;                      /* de-compress data        */
   }
   /* prepare SMB command                                              */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_write) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_write;  /* command SMB2 write data */
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G1 + 1;
   memcpy( ADSL_SMBCC_IN_WRITE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_WRITE_G->chrc_file_id) );  /* FileId */
   ADSL_SMBCC_IN_WRITE_G->ulc_offset = adsl_dwa->ulc_offset;  /* Offset */
   /* prepare gather write                                             */
   aadsl_gai1_ch1 = &ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data;  /* chain of gather - write data */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_WRITE_G

   iml_send = MAX_LEN_SMB2_DATA;            /* count data to send      */

   p_cl_rfc_12:                             /* prepare output decompression to SMB */
   if ((dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower) > (sizeof(struct dsd_gather_i_1) + 64)) {
     goto p_cl_rfc_16;                      /* space in work-area      */
   }
   /* no space in work area, acquire additional work area              */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_aux_get_workarea,
                                    sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   dsl_sdh_call_1.achc_lower = dsl_aux_get_workarea.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;

   p_cl_rfc_16:                             /* space in work-area      */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
   adsl_cdf_ctrl->achc_out_cur = dsl_sdh_call_1.achc_lower;  /* decompressed data */
#ifdef B141126
   adsl_cdf_ctrl->achc_out_end = dsl_sdh_call_1.achc_upper;  /* decompressed data */
#endif
   iml1 = dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower;
#ifdef B141129
   if (iml1 > MAX_LEN_SMB2_DATA) {          /* maximum length of SMB2 in one block */
     iml1 = MAX_LEN_SMB2_DATA;              /* maximum length of SMB2 in one block */
   }
#endif
   if (iml1 > iml_send) {                   /* maximum length of SMB2 in one block */
     iml1 = iml_send;                       /* maximum length of SMB2 in one block */
   }
   adsl_cdf_ctrl->achc_out_end = dsl_sdh_call_1.achc_lower + iml1;  /* decompressed data */
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = dsl_sdh_call_1.achc_lower;
#undef ADSL_OUT_W

   p_cl_rfc_20:                             /* de-compress data        */
   achl_w1 = adsl_cdf_ctrl->achc_out_cur;
#ifdef TRACEHL1
   iml1 = adsl_cdf_ctrl->achc_out_end - achl_w1;
#endif
#ifdef DEBUG_141129_01
   if (adsl_cdf_ctrl->ac_ext) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: dec before %d %d %d %d.",
                   __LINE__,
                   *((int *) adsl_cdf_ctrl->ac_ext + 0),
                   *((int *) adsl_cdf_ctrl->ac_ext + 1),
                   *((int *) adsl_cdf_ctrl->ac_ext + 2),
                   *((int *) adsl_cdf_ctrl->ac_ext + 3) );
   }
   iml2 = 0;
   adsl_gai1_w1 = adsl_cdf_ctrl->adsc_gai1_in;  /* chain of gather - input data */
   while (adsl_gai1_w1) {                   /* loop over data not de-compressed */
     iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: dec before input %d iml_rl %d/0X%X.",
                 __LINE__, iml2, iml_rl, iml_rl );
#endif
   m_cdf_dec( adsl_cdf_ctrl );
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: imc_return=%d de-compr %p till %p length %p space %p.",
                 __LINE__,
                 adsl_cdf_ctrl->imc_return,
                 achl_w1, adsl_cdf_ctrl->achc_out_cur, adsl_cdf_ctrl->achc_out_cur - achl_w1,
                 iml1 );
#endif
#ifdef DEBUG_141129_01
   if (adsl_cdf_ctrl->ac_ext) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: dec after  %d %d %d %d.",
                   __LINE__,
                   *((int *) adsl_cdf_ctrl->ac_ext + 0),
                   *((int *) adsl_cdf_ctrl->ac_ext + 1),
                   *((int *) adsl_cdf_ctrl->ac_ext + 2),
                   *((int *) adsl_cdf_ctrl->ac_ext + 3) );
   }
   iml2 = 0;
   adsl_gai1_w1 = adsl_cdf_ctrl->adsc_gai1_in;  /* chain of gather - input data */
   while (adsl_gai1_w1) {                   /* loop over data not de-compressed */
     iml2 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: dec after  input %d iml_rl %d.",
                 __LINE__, iml2, iml_rl );
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: dec output %d.",
                 __LINE__,
                 adsl_cdf_ctrl->achc_out_cur - achl_w1 );
#endif
   if (adsl_cdf_ctrl->imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_cdf_dec() returned %d.",
                     __LINE__, adsl_cdf_ctrl->imc_return );
//     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
//   return;
     if (adsl_dwa->boc_virch_local == FALSE) {  /* virus checking data from local / client */
       adsl_cdf_ctrl->amc_aux = NULL;       /* de-compression no more active */
     }
   }
//#ifdef B141129
   /* check if input data consumed                                     */
   while (adsl_cdf_ctrl->adsc_gai1_in) {    /* chain of gather - input data */
     if (adsl_cdf_ctrl->adsc_gai1_in->achc_ginp_cur
           < adsl_cdf_ctrl->adsc_gai1_in->achc_ginp_end) {  /* data not processed */
       break;
     }
     adsl_cdf_ctrl->adsc_gai1_in
       = adsl_cdf_ctrl->adsc_gai1_in->adsc_next;
   }
//#endif
   /* consume input from client                                        */
   adsl_gai1_w1 = adsl_cdf_ctrl->adsc_gai1_in;  /* chain of gather - input data */
   iml1 = 0;                                /* clear count             */
   while (adsl_gai1_w1) {                   /* loop over data not de-compressed */
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
#ifdef XYZ1
#ifndef B160115
     iml_rl += iml1;                        /* remainder record not yet processed */
#endif
#endif
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: adsp_hl_clib_1->inc_func=%d adsl_dwa->adsc_gai1_in_from_client=%p ->imc_rl=%d iml_rl=%d iml_in_gather=%d iml1=%d.",
                 __LINE__,
                 adsp_hl_clib_1->inc_func,
                 adsl_dwa->adsc_gai1_in_from_client,
                 adsl_dwa->imc_rl,
                 iml_rl, iml_in_gather, iml1 );
#endif
   iml2 = iml_in_gather - iml1;             /* consumed in this path   */
//#ifdef B160115
   iml_in_gather = iml1;                    /* count data in gather    */
//#endif
   if (iml2 > 0) {                          /* data consumed           */
     iml_rl -= iml2;                        /* record length           */
     while (TRUE) {
       iml1 = adsl_gai1_inp_1->achc_ginp_end - achl_rp;
       if (iml1 > iml2) iml1 = iml2;
       achl_rp += iml1;
       adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
       iml2 -= iml1;                        /* data to get consumed    */
       if (iml2 <= 0) break;                /* no more data to get consumed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) {       /* program illogic         */
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN program illogic",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
         return;
       }
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
   }
#ifndef B160115
#ifdef XYZ1
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = iml_rl;               /* remainder record not yet processed */
#endif
#ifdef XYZ1
   adsl_gai1_inp_1 = adsl_dwa->adsc_gai1_in_from_client;
   while (adsl_gai1_inp_1) {
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
   }
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = iml_rl;               /* remainder record not yet processed */
#endif
#ifdef TRACEHL1
   {
     char chh1;
     chh1 = 0;
     if (achl_rp) chh1 = *achl_rp;
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_20: adsp_hl_clib_1->inc_func=%d adsl_dwa->adsc_gai1_in_from_client=%p ->imc_rl=%d iml_rl=%d achl_rp=%p->0X%02X.",
                     __LINE__,
                     adsp_hl_clib_1->inc_func,
                     adsl_dwa->adsc_gai1_in_from_client,
                     adsl_dwa->imc_rl,
                     iml_rl,
                     achl_rp,
                     (unsigned char) chh1 );
   }
#ifdef DEBUG_140823_01
   m_print_gather( &dsl_sdh_call_1, __LINE__, "p_cl_rfc_20", adsl_dwa->adsc_gai1_in_from_client );
#endif
#endif
#endif
   iml_send -= adsl_cdf_ctrl->achc_out_cur - dsl_sdh_call_1.achc_lower;  /* count data to send */
#ifdef XYZ1
#ifndef B140823
   adsl_dwa->adsc_gai1_in_from_client = adsl_cdf_ctrl->adsc_gai1_in;  /* input data from client */
#endif
#endif
   if (adsl_dwa->boc_virch_local) {         /* virus checking data from local / client */
     goto p_cl_rfc_32;                      /* de-compress data virus-checking */
   }
   /* after de-compression no virus-checking                           */
   dsl_sdh_call_1.achc_lower = adsl_cdf_ctrl->achc_out_cur;
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   iml1 = dsl_sdh_call_1.achc_lower - achl_w1;
   if (   (iml1 == 0)
       && (adsl_cdf_ctrl->adsc_gai1_in)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E de-compression no output but still input",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (iml1) {
     ADSL_GAI1_OUT_W->achc_ginp_end = dsl_sdh_call_1.achc_lower;
     adsl_dwa->ulc_offset += iml1;          /* increment offset        */
     *aadsl_gai1_ch1 = ADSL_GAI1_OUT_W;
     aadsl_gai1_ch1 = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
   }
#undef ADSL_OUT_W
#ifdef B141129
   if (adsl_cdf_ctrl->adsc_gai1_in) {       /* input not yet consumed  */
     if (adsl_cdf_ctrl->amc_aux) {          /* de-compression still active */
       goto p_cl_rfc_12;                    /* prepare output decompression to SMB */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E de-compression ended but still input",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#endif
   while (adsl_cdf_ctrl->adsc_gai1_in) {    /* input not yet consumed  */
     if (adsl_cdf_ctrl->amc_aux) {          /* de-compression still active */
       if (iml_send <= 0) {                 /* count data to send      */
         break;                             /* send to server now      */
       }
       goto p_cl_rfc_12;                    /* prepare output decompression to SMB */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E de-compression ended but still input",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   *aadsl_gai1_ch1 = NULL;                  /* end of chain            */
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   if (ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data == NULL) {  /* chain of gather - write data */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T write empty iml_rl=%d iml_in_gather=%d iml1=%d.",
                   __LINE__,
                   iml_rl, iml_in_gather, iml1 );
#ifdef DEBUG_140823_01
     m_print_gather( &dsl_sdh_call_1, __LINE__, "write empty", adsl_dwa->adsc_gai1_in_from_client );
#endif
#endif
     goto p_cl_rfc_80;                      /* de-compression done     */
   }
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_WRITE_G
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) break;
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = iml_rl;               /* remainder record not yet processed */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T before write adsp_hl_clib_1->inc_func=%d adsl_gai1_inp_1=%p.",
                 __LINE__,
                 adsp_hl_clib_1->inc_func,
                 adsl_gai1_inp_1 );
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T before write iml_rl=%d iml_in_gather=%d iml1=%d.",
                 __LINE__,
                 iml_rl, iml_in_gather, iml1 );
#ifdef DEBUG_140823_01
   m_print_gather( &dsl_sdh_call_1, __LINE__, "before write", adsl_dwa->adsc_gai1_in_from_client );
#endif
#endif
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_cl2smb_02;             /* write file / write      */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_cl_rfc_32:                             /* de-compress data virus-checking */
   adsl_dwifvc->ilc_read_position           /* progress content received from client */
     += adsl_cdf_ctrl->achc_out_cur - achl_w1;
#ifdef B150101
   bol1 = FALSE;                            /* not written to virus-checker */
#endif
   if (adsl_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     goto p_cl_rfc_40;                      /* send to virus-checker done */
   }
   if (adsl_wvc1->achc_vc_written == adsl_cdf_ctrl->achc_out_cur) {  /* address written to virus-checking */
#ifdef B150101
     bol1 = TRUE;                           /* written to virus-checker */
#endif
     goto p_cl_rfc_40;                      /* send to virus-checker done */
   }
   iml1 = 0;                                /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_stat) < 0) break;  /* check unused */
     iml1++;                                /* increment index         */
   } while (iml1 < NO_VC_REQ1);             /* number of concurrent requests */
   if (iml1 >= NO_VC_REQ1) {                /* number of concurrent requests */
     adsl_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     bol_call_vc = TRUE;                    /* call virus-checking     */
     goto p_cl_rfc_40;                      /* send to virus-checker done */
   }
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur = adsl_wvc1->achc_vc_written;  /* address written to virus-checking */
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end = adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur;
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].adsc_next = NULL;
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur >= adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   adsl_wvc1->achrc_stor_addr_vc[ iml1 ] = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   memset( &adsl_wvc1->dsrc_sevchreq1[ iml1 ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].adsc_gai1_data = &adsl_wvc1->dsrc_gai1_vch_data[ iml1 ];
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_vchreq1 = ied_vchreq_content;  /* content of file */
   if (adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   }
   adsl_wvc1->dsc_sevchcontr1.ilc_window_1
     += adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur - adsl_wvc1->achc_vc_written;
   bol_call_vc = TRUE;                      /* call virus-checking     */
   adsl_wvc1->achc_vc_written = adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur;  /* address written to virus-checking */
#ifdef B150101
   bol1 = TRUE;                             /* written to virus-checker */
#endif

   p_cl_rfc_40:                             /* send to virus-checker done */
   if (adsl_dwifvc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
     goto p_cl_rfc_60;                      /* end of input file reached */
   }
   if (adsl_dwifvc->dsc_cdf_ctrl.adsc_gai1_in == NULL) {  /* chain of gather - input data */
     goto p_cl_rfc_80;                      /* de-compression done     */
   }
   /* we need more output area for de-compression                      */
   if (adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur
         != adsl_dwifvc->dsc_cdf_ctrl.achc_out_end) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
   }
#ifdef B150101
   if (bol1 == FALSE) {                     /* not written to virus-checker */
     goto p_cl_rfc_48;                      /* get new block from swap storage */
   }
   /* release block for buffering in swap storage                      */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_write;     /* write swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.achc_stor_addr = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_wr;  /* index of dataset / chunk - write */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wvc1->imc_index_wr++;               /* index of dataset / chunk - write */
   adsl_wvc1->imc_ss_ahead--;               /* swap storage in use     */

   p_cl_rfc_48:                             /* get new block from swap storage */
#endif
   if (adsl_wvc1->imc_ss_ahead >= NO_SS_AHEAD) {  /* number of swap storage ahead */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W de-compression output needs too many buffers achrc_stor_addr_ss",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wvc1->imc_index_re++;               /* index of dataset / chunk - read */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_get_buf;  /* acquire swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wvc1->achrc_stor_addr_ss[ adsl_wvc1->imc_ss_ahead ] = dsl_astr1.achc_stor_addr;  /* storage address */
   if (adsl_wvc1->imc_ss_ahead == 0) {      /* also start virus-checking */
     adsl_wvc1->achc_vc_written = dsl_astr1.achc_stor_addr;  /* address written to virus-checking */
   }
   adsl_wvc1->imc_ss_ahead++;               /* swap storage in use     */
   adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur = dsl_astr1.achc_stor_addr;  /* decompressed data */
   adsl_dwifvc->dsc_cdf_ctrl.achc_out_end = dsl_astr1.achc_stor_addr + LEN_BLOCK_SWAP;  /* decompressed data */
   goto p_cl_rfc_20;                        /* de-compress data        */

   p_cl_rfc_60:                             /* end of input file reached */
   if (adsl_dwifvc->dsc_cdf_ctrl.adsc_gai1_in) {  /* chain of gather - input data */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#ifdef XYZ1
   adsl_wvc1->boc_eof = TRUE;               /* end-of-file reached     */
   if (adsl_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     goto p_cl_rfc_80;                      /* de-compression done     */
   }
#endif
   adsl_wvc1->iec_vcend = ied_vcend_recv_end;  /* end input received   */
   bol_rc = m_work_vc_end( &dsl_sdh_call_1,
                           adsl_wvc1,       /* virus-checking          */
                           adsl_dwa,        /* all dash operations work area */
                           adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur,
                           &bol_call_vc );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }

   p_cl_rfc_80:                             /* de-compression done     */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfc_80: adsl_gai1_inp_1=%p achl_rp=%p.",
                 __LINE__, adsl_gai1_inp_1, achl_rp );
#endif
#ifdef B141129
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) break;
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
#endif
   if (adsl_gai1_inp_1) {                   /* still input data        */
     while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       if (adsl_gai1_inp_1 == NULL) break;
       achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
     }
   }
#ifndef B140823
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
#endif
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#ifdef DEBUG_140823_01
   m_print_gather( &dsl_sdh_call_1, __LINE__, "p_cl_rfc_80", adsl_dwa->adsc_gai1_in_from_client );
#endif
   if (adsl_gai1_inp_1) {                   /* more input data         */
     goto p_client_rec_20;                  /* continue received from client */
   }
   goto p_ret_00;                           /* return                  */

   p_cl_rfn_00:                             /* read file normal        */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfn_00:",
                 __LINE__ );
#endif
   if (adsl_cl1->iec_clst != ied_clst_resp_read_file_normal) {  /* wait for read file normal */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
   }
#ifndef B150307
   if (adsl_cl1->iec_scs == ied_scs_closed) {  /* SMB connection closed */
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - server closed",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
   }
#endif
// to-do 20.12.14 KB - check start input from client and jump to other label
   if (adsl_dwa->boc_virch_local) {         /* virus checking data from local / client */
// to-do 22.05.14 KB - check if virus-checking already started
     adsl_dwifvc = &adsl_dwa->dsc_work_ifvc;  /* input file with virus-checking */
     adsl_wvc1 = &adsl_dwifvc->dsc_wvc1;    /* virus-checking          */
     if ((adsl_dwa->umc_state & DWA_STATE_VCH_ACT) == 0) {  /* state of processing - virus checking not yet started */
       goto p_cl_vch_sta_00;                /* start virus-checking with data received from client */
     }
     if (adsl_wvc1->imc_ss_ahead > 1) {     /* swap storage in use     */
       goto p_ret_00;                       /* return, wait till virus-checking is more advanced */
     }
     goto p_cl_rfn_40;                      /* read file normal - with virus-checking */
   }
#ifdef TRACEHL1
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_TOSERVER) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfn_00: UUUU bug UUUU consume input from client ->inc_func=%d.",
                   __LINE__,
                   adsp_hl_clib_1->inc_func );
   }
#endif
#ifdef B141221
   adsl_wcl2smb = &adsl_dwa->dsc_work_cl2smb;  /* copy client to server SMB */
#endif
#ifndef B141221
   if (adsl_cl1->iec_scs == ied_scs_idle) {  /* idle, nothing to do    */
     goto p_cf_cl2se_20;                    /* copy client to server normal, no virus checking, no swap storage */
   }
   if (adsl_cl1->iec_scs != ied_scs_write_wait) {  /* write file / wait for next input */
     goto p_ret_00;                         /* return                  */
   }
   adsl_wcl2smb = &adsl_dwa->dsc_work_cl2smb;  /* copy client to server SMB */
#endif
   /* consume input till this position                                 */
#ifdef B140824
   adsl_gai1_inp_2 = adsp_hl_clib_1->adsc_gather_i_1_in;
#endif
#ifndef B140824
   adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
#endif
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
#ifndef B140824
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) break;    /* end of input            */
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
#endif
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
   /* prepare SMB command                                              */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_write) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_write;  /* command SMB2 write data */
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G1 + 1;
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_WRITE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_WRITE_G->chrc_file_id) );  /* FileId */
   ADSL_SMBCC_IN_WRITE_G->ulc_offset = adsl_dwa->ulc_offset;  /* Offset */
   ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data = &adsl_wss2smb->dsc_gai1_data;  /* data to be written */
   /* prepare gather write                                             */
   aadsl_gai1_ch1 = &ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data;  /* chain of gather - write data */
// adsl_gai1_w1 = (struct dsd_gather_i_1 *) byrl_work1;  /* build input here */
   adsl_gai1_w1 = adsl_wcl2smb->dsrc_gai1_write;  /* copy gather here  */
   iml1 = MAX_INP_GATHER;                   /* number of input gather to be processed */
   while (TRUE) {                           /* loop to fill gather structures for compression */
     iml2 = adsl_gai1_inp_1->achc_ginp_end - achl_rp;
     if (iml2 > 0) {                        /* data found              */
       if (iml2 > iml_rl) iml2 = iml_rl;
       adsl_gai1_w1->achc_ginp_cur = achl_rp;
       adsl_gai1_w1->achc_ginp_end = achl_rp + iml2;
       *aadsl_gai1_ch1 = adsl_gai1_w1;      /* append to chain         */
       aadsl_gai1_ch1 = &adsl_gai1_w1->adsc_next;
       achl_rp += iml2;
       adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
       adsl_dwa->ulc_offset += iml2;        /* increment offset        */
       iml_rl -= iml2;
       if (iml_rl <= 0) break;
#ifdef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
       adsl_gai1_w1++;
       iml1--;
#ifndef B150428
       if (iml1 <= 0) {                     /* all gather exhausted    */
// to-do 27.08.13 KB error message
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error - too many input gather",
                       __LINE__ );
         adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
         return;
       }
#endif
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
// to-do 27.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   *aadsl_gai1_ch1 = NULL;                  /* end of chain            */
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) break;
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_WRITE_G
#ifdef XYZ1
   adsl_dwa->ulc_offset += iml1;            /* increment offset        */
#endif
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_cl2smb_02;             /* write file / write      */
#ifdef DEBUG_131228_01
   bol1 = FALSE;
#endif
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_cl_rfn_40:                             /* read file normal - with virus-checking */
   adsl_gai1_inp_2 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
   while (adsl_gai1_inp_2 != adsl_gai1_inp_1) {  /* not current gather */
     adsl_gai1_inp_2->achc_ginp_cur = adsl_gai1_inp_2->achc_ginp_end;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   adsl_gai1_inp_1->achc_ginp_cur = achl_rp;
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* end of input            */
       iml1 = __LINE__;
       goto p_error_int_error;              /* internal error has occured */
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }

   p_cl_rfn_44:                             /* read file normal - copy to swap storage */
   iml2 = adsl_dwifvc->achc_end - adsl_dwifvc->achc_out;
   if (iml2 <= 0) {                         /* no space - needs new buffer */
     goto p_cl_rfn_48;                      /* read file normal - data copied */
   }
   if (iml2 > iml_rl) iml2 = iml_rl;        /* only as much as received */
   iml_rl -= iml2;                          /* this part processed     */
   adsl_dwifvc->ilc_read_position           /* progress content received from client */
     += iml2;
// ---- 21.12.14
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, adsl_dwifvc->achc_out, iml2 );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   adsl_dwifvc->achc_out += iml2;           /* increment address output */
// ---- 21.12.14

   p_cl_rfn_48:                             /* read file normal - data copied */
#ifdef B150101
   bol1 = FALSE;                            /* not written to virus-checker */
#endif
   if (adsl_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     goto p_cl_rfn_60;                      /* send to virus-checker done */
   }
   if (adsl_wvc1->achc_vc_written == adsl_dwifvc->achc_out) {  /* address written to virus-checking */
#ifdef B150101
     bol1 = TRUE;                           /* written to virus-checker */
#endif
     goto p_cl_rfn_60;                      /* send to virus-checker done */
   }
   iml1 = 0;                                /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_stat) < 0) break;  /* check unused */
     iml1++;                                /* increment index         */
   } while (iml1 < NO_VC_REQ1);             /* number of concurrent requests */
   if (iml1 >= NO_VC_REQ1) {                /* number of concurrent requests */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rfn_48: buffer full, wait virus-checker, set boc_wait_window",
                   __LINE__ );
#endif
     adsl_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     bol_call_vc = TRUE;                    /* call virus-checking     */
     goto p_cl_rfn_60;                      /* send to virus-checker done */
   }
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur = adsl_wvc1->achc_vc_written;  /* address written to virus-checking */
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end = adsl_dwifvc->achc_out;
   adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].adsc_next = NULL;
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_cur >= adsl_wvc1->dsrc_gai1_vch_data[ iml1 ].achc_ginp_end) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   adsl_wvc1->achrc_stor_addr_vc[ iml1 ] = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   memset( &adsl_wvc1->dsrc_sevchreq1[ iml1 ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].adsc_gai1_data = &adsl_wvc1->dsrc_gai1_vch_data[ iml1 ];
   adsl_wvc1->dsrc_sevchreq1[ iml1 ].iec_vchreq1 = ied_vchreq_content;  /* content of file */
   if (adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsl_wvc1->dsrc_sevchreq1[ iml1 ];
   }
   adsl_wvc1->dsc_sevchcontr1.ilc_window_1
     += adsl_dwifvc->achc_out - adsl_wvc1->achc_vc_written;
   bol_call_vc = TRUE;                      /* call virus-checking     */
   adsl_wvc1->achc_vc_written = adsl_dwifvc->achc_out;  /* address written to virus-checking */
#ifdef B150101
   bol1 = TRUE;                             /* written to virus-checker */
#endif

   p_cl_rfn_60:                             /* send to virus-checker done */
   if (iml_rl <= 0) {                       /* all data copied         */
     goto p_cl_rfn_80;                      /* all data copied         */
   }
#ifdef B150101
   if (bol1 == FALSE) {                     /* not written to virus-checker */
     goto p_cl_rfn_68;                      /* get new block from swap storage */
   }
   /* release block for buffering in swap storage                      */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_write;     /* write swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.achc_stor_addr = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_wr;  /* index of dataset / chunk - write */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wvc1->imc_index_wr++;               /* index of dataset / chunk - write */
   adsl_wvc1->imc_ss_ahead--;               /* swap storage in use     */

   p_cl_rfn_68:                             /* get new block from swap storage */
#endif
   if (adsl_wvc1->imc_ss_ahead >= NO_SS_AHEAD) {  /* number of swap storage ahead */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W normal output needs too many buffers achrc_stor_addr_ss",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wvc1->imc_index_re++;               /* index of dataset / chunk - read */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_get_buf;  /* acquire swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wvc1->achrc_stor_addr_ss[ adsl_wvc1->imc_ss_ahead ] = dsl_astr1.achc_stor_addr;  /* storage address */
   if (adsl_wvc1->imc_ss_ahead == 0) {      /* also start virus-checking */
     adsl_wvc1->achc_vc_written = dsl_astr1.achc_stor_addr;  /* address written to virus-checking */
   }
   adsl_wvc1->imc_ss_ahead++;               /* swap storage in use     */
   adsl_dwifvc->achc_out = dsl_astr1.achc_stor_addr;  /* space for new output data */
   adsl_dwifvc->achc_end = dsl_astr1.achc_stor_addr + LEN_BLOCK_SWAP;  /* end of output data */
   goto p_cl_rfn_44;                        /* read file normal - copy to swap storage */
// ---- 21.12.14

   p_cl_rfn_80:                             /* all data copied         */
   adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;  /* input data from client */
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#ifdef DEBUG_140823_01
   m_print_gather( &dsl_sdh_call_1, __LINE__, "p_cl_rfn_80", adsl_dwa->adsc_gai1_in_from_client );
#endif
   if (adsl_gai1_inp_1) {                   /* more input data         */
     goto p_client_rec_20;                  /* continue received from client */
   }
   goto p_ret_00;                           /* return                  */
// ---- 21.12.14

   p_cl_rcn_00:                             /* received change notify  */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rcn_00:",
                 __LINE__ );
#endif
#ifdef DEBUG_160115_01                      /* show notify             */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_rcn_00: DEBUG_160115_01 received change notify from client",
                 __LINE__ );
#endif
   /* consume token from input stream                                  */
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, byrl_work1, iml_rl );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_changed_local = TRUE;       /* changes local           */
   adsl_a1->boc_notify_local = TRUE;        /* notify from client received */
#ifndef B150228
   if (adsl_gai1_inp_1) {                   /* more input data         */
     goto p_client_rec_20;                  /* continue received from client */
   }
#endif
   goto p_ret_00;                           /* return                  */

   p_cl_vch_sta_00:                         /* start virus-checking with data received from client */
   adsl_dwifvc->ilc_read_position = 0;      /* progress content received from client */
   bol_rc = m_work_vc_init( &dsl_sdh_call_1,
                            adsl_wvc1,      /* virus-checking          */
                            adsl_dwa,       /* all dash operations work area */
                            adsl_dwifvc->byrc_fn, adsl_dwifvc->imc_len_fn );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }
// to-do 20.12.14 KB - check start input from client and jump to other label
// if (iml_tag == DASH_DCH_CL2SE_FILE_NORMAL) {  /* command received   */
   if (adsl_cl1->iec_clst == ied_clst_resp_read_file_normal) {  /* wait for read file normal */
     adsl_dwifvc->achc_out = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* space output data */
     adsl_dwifvc->achc_end = adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP;  /* end of output data */
     goto p_cl_rfn_00;                      /* read file normal        */
   }
   /* start de-compression                                             */
   memset( &adsl_dwifvc->dsc_cdf_ctrl, 0, sizeof(struct dsd_cdf_ctrl) );  /* compress data file oriented control */
   memcpy( adsl_dwifvc->dsc_cdf_ctrl.chrc_eye_catcher, ucrs_eye_catcher, sizeof(ucrs_eye_catcher) );
   adsl_dwifvc->dsc_cdf_ctrl.amc_aux = &m_sub_aux;  /* auxiliary callback routine */
   adsl_dwifvc->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   m_cdf_dec( &adsl_dwifvc->dsc_cdf_ctrl );
   if (adsl_dwifvc->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
// to-do 26.08.13 KB error message
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }
   adsl_dwifvc->dsc_cdf_ctrl.achc_out_cur = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* decompressed data */
   adsl_dwifvc->dsc_cdf_ctrl.achc_out_end = adsl_wvc1->achrc_stor_addr_ss[ 0 ] + LEN_BLOCK_SWAP;  /* decompressed data */
// to-do 20.12.14 KB - check start input from client and jump to other label
   goto p_cl_rfc_00;                        /* read file compressed    */
//--------------- 20.12.14 - end

   p_cl_error_00:                           /* received error from client */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cl_error_00: iml_rl=%d ...->iec_clst=%d.",
                 __LINE__, iml_rl, adsl_cl1->iec_clst );
#endif
   if (iml_rl <= 0) {                       /* no more data received   */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
   /* retrieve three error numbers                                     */
   iml_error_1 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml_error_1 < 0) {                   /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   iml_error_2 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml_error_2 < 0) {                   /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   iml_error_3 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml_error_3 < 0) {                   /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml_rl != 0) {                       /* record not consumed     */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W client reported error %d %d %d.",
                 __LINE__, iml_error_1, iml_error_2, iml_error_3 );
// to-do 22.05.14 KB - print filename
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   if (iml_error_2 == DASH_DCH_SE2CL_FILE_INFO) {  /* error end of copy server to client */
     /* we need to wait some time and start from reading the client's directory again */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (iml_error_2 == DASH_DCH_READ_FILE) {  /* error end of copy server to client */
     if (iml_error_1 != DASH_ERROR_ACCESS_DENIED) {  /* error end of copy server to client */
       iml1 = __LINE__;                       /* set line of error       */
       goto p_cl_illogic;                     /* illogic processing of data received from client */
     }
     if (   (adsl_cl1->iec_clst != ied_clst_resp_read_file_normal)  /* wait for read file normal */
         && (adsl_cl1->iec_clst != ied_clst_resp_read_file_compressed)) {  /* wait for read file compressed */
       iml1 = __LINE__;                       /* set line of error       */
       goto p_cl_illogic;                     /* illogic processing of data received from client */
     }
     if (adsl_dwa->boc_virch_local == FALSE) {  /* virus checking data from local / client */
       if (adsl_cl1->iec_scs != ied_scs_idle) {  /* idle, nothing to do */
         iml1 = __LINE__;                       /* set line of error       */
         goto p_cl_illogic;                     /* illogic processing of data received from client */
       }
     } else {                                 /* with virus checking     */
// to-do 22.05.14 KB - check if virus-checking already started
     }
     goto p_put_bl_00;                      /* put action to backlog   */
   }
#ifdef B150303
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
#endif
   if (adsl_gai1_inp_1) {                   /* more input data         */
     goto p_client_rec_20;                  /* continue received from client */
   }
   goto p_ret_00;                           /* return                  */

   p_put_bl_00:                             /* put action to backlog   */
   /* try later                                                        */
   if (adsl_dwa->adsc_cf_bl_cur) {          /* current entry copy file backlog - already processing backlog */
     adsl_dwa->adsc_cf_bl_cur = adsl_dwa->adsc_cf_bl_cur->adsc_next;  /* remove from chain */
     goto p_proc_bl_00;                     /* process backlog         */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_cf_backlog_w1,  /* copy file backlog */
                                    sizeof(struct dsd_cf_backlog) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_cf_backlog_w1->adsc_f1_action = adsl_a1->adsc_f1_action;  /* entry of file current action */
   adsl_cf_backlog_w1->iec_acs = adsl_a1->iec_acs;  /* state of action */
   adsl_cf_backlog_w1->adsc_next = adsl_dwa->adsc_cf_backlog;  /* chain copy file backlog */
   adsl_dwa->adsc_cf_backlog = adsl_cf_backlog_w1;  /* set new chain copy file backlog */
   goto p_next_action_00;                   /* check for next action   */

   p_cl_msg1_00:                            /* received DASH_DCH_CL2SE_MSG1 */
   /* retrieve message text, UTF-8                                     */
   if (iml_rl <= 0) {                       /* no more data received   */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received error",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
       return;
   }
// to-do 03.03.15 KB - other function would be better, see xbdas02.cpp m_get_input_char()
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, byrl_work1, iml_rl );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I client MSG1 %.*(u8)s",
                 __LINE__, iml_rl, byrl_work1 );
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (adsl_gai1_inp_1) {                   /* more input data         */
     goto p_client_rec_20;                  /* continue received from client */
   }
   goto p_ret_00;                           /* return                  */

   goto p_client_rec_20;                    /* continue received from client */

   p_ret_00:                                /* return                  */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: adsl_cl1->iec_clst=%d ->boc_smb_connected=%d ->boc_reconnect=%d.",
                 __LINE__,
                 adsl_cl1->iec_clst,
                 adsl_cl1->boc_smb_connected,
                 adsl_cl1->boc_reconnect );
#endif
#ifdef B160323
#ifndef B151219
   if (   (adsl_cl1->iec_clst == ied_clst_resp_file_control)  /* wait for response file-control */
       && (adsl_cl1->boc_smb_connected)) {  /* connected to SMB server */
     if (adsl_a1->boc_write_server) {       /* can write to SMB server */
       adsl_cl1->boc_local_notify = TRUE;   /* notify local / client is active */
       goto p_cl_send_ch_notify_00;         /* send change notify      */
     }
     goto p_cl_send_get_all_dir_00;         /* get all directories     */
   }
#endif
#endif
#ifndef B160323
#ifdef B160813
   if (   (adsl_cl1->iec_clst == ied_clst_resp_file_control_p)  /* process after response file-control */
       && (adsl_cl1->boc_smb_connected)) {  /* connected to SMB server */
     if (adsl_a1->boc_write_server) {       /* can write to SMB server */
       adsl_cl1->boc_local_notify = TRUE;   /* notify local / client is active */
       goto p_cl_send_ch_notify_00;         /* send change notify      */
     }
     goto p_cl_send_get_all_dir_00;         /* get all directories     */
   }
#endif
   if (   (adsl_cl1->iec_clst == ied_clst_resp_file_control_p)  /* process after response file-control */
       && (adsl_cl1->boc_smb_connected)) {  /* connected to SMB server */
     if (adsl_cl1->boc_reconnect) {
       if ((adsl_dwa->umc_state & DWA_STATE_DIR_SERVER) == 0) {  /* state of processing */
         adsl_cl1->iec_clst = ied_clst_idle;  /* client is idle        */
//       adsl_cl1->boc_local_notify = TRUE;  /* notify local / client is active */
         adsl_a1->adsc_db1_local = adsl_a1->adsc_db1_sync;  /* table sync is at client */
         adsl_cl1->boc_reconnect = FALSE;   /* processing normal from now on */
#ifdef XYZ1
         if (adsl_a1->boc_write_server) {   /* can write to SMB server */
           adsl_cl1->boc_local_notify = TRUE;  /* notify local / client is active */
           goto p_cl_send_ch_notify_00;     /* send change notify      */
         }
//       goto p_acs_done_00;                /* action done             */
         goto p_next_action_00;             /* check for next action   */
#endif
         if (adsl_a1->boc_write_server) {   /* can write to SMB server */
           adsl_cl1->boc_local_notify = TRUE;  /* notify local / client is active */
           goto p_cl_send_ch_notify_00;     /* send change notify      */
         }
       }
     } else {                               /* not reconnect           */
       if (adsl_a1->boc_write_server) {     /* can write to SMB server */
         adsl_cl1->boc_local_notify = TRUE;  /* notify local / client is active */
         goto p_cl_send_ch_notify_00;       /* send change notify      */
       }
       goto p_cl_send_get_all_dir_00;       /* get all directories     */
     }
   }
#endif
#ifdef TRACEHL1
   if (adsl_dwa) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: adsp_hl_clib_1->inc_func=%d adsl_dwa->adsc_gai1_in_from_client=%p ->imc_rl=%d.",
                   __LINE__,
                   adsp_hl_clib_1->inc_func,
                   adsl_dwa->adsc_gai1_in_from_client,
                   adsl_dwa->imc_rl );
#ifdef DEBUG_140823_01
     adsl_gai1_inp_1 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
     while (adsl_gai1_inp_1) {
       if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) {
         break;
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: adsl_dwa->adsc_gai1_in_from_client adsl_gai1_inp_1=%p empty UUUU",
                     __LINE__, adsl_gai1_inp_1 );
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     adsl_gai1_inp_1 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
     iml1 = 0;
     while (adsl_gai1_inp_1) {
       iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_check;  /* check input data       */
     iml2 = 0;
     while (adsl_gai1_inp_1) {
       iml2 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     if (iml2 > iml1) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: not consumed: %d adsc_gai1_in_from_client %d UUUU",
                     __LINE__, iml2, iml1 );
     }
#endif
     if (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER) {
       adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
       while (adsl_gai1_inp_1) {
         if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
         adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
       }
       if (adsl_gai1_inp_1 != adsl_dwa->adsc_gai1_in_from_client) {
         m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: adsl_dwa->adsc_gai1_in_from_client invalid UUUU",
                       __LINE__ );
       }
       iml1 = 0;
       while (adsl_gai1_inp_1) {
         iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
         adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       }
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: remaining input data %d/0X%X.",
                     __LINE__, iml1, iml1 );
     }
   }
#endif
#ifndef B140823
// to-do 23.08.14 KB - only temporary, need to set correct in upper routines
   if (   (adsl_dwa)                        /* all dash operations work area */
       && (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)) {
     adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     while (adsl_gai1_inp_1) {
       if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     }
     adsl_dwa->adsc_gai1_in_from_client = adsl_gai1_inp_1;
#ifdef B160115
     adsl_dwa->imc_rl = 0;                  /* remainder record not yet processed */
#endif
   }
#endif
   if (bol_call_smb_cl) {                   /* call SMB client         */
     goto p_smb_rec_08;                     /* call SMB client component */
   }
   ill_epoch_smb = 0;                       /* time when SMB2 Echo needs to be sent */
   if (   (adsl_cl1->boc_smb_connected)     /* connected to SMB server */
       && (adsl_cl1->ilc_epoch_smb)         /* epoch last call to SMB */
       && (adsl_cl1->dsc_cm.imc_server_echo != 0)) {  /* server <interval-echo> */
     ill_epoch_smb = adsl_cl1->dsc_cm.imc_server_echo;  /* server <interval-echo> */
     if (ill_epoch_smb < 0) {               /* set default value       */
       ill_epoch_smb = D_SMB2_ECHO;         /* default SMB2 <interval-echo> */
     }
     ill_epoch_smb *= 1000;                 /* make milliseconds       */
     ill_epoch_smb += adsl_cl1->ilc_epoch_smb;  /* time when SMB2 Echo needs to be sent */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_00: ill_epoch_cur=%lld ill_epoch_smb=%lld.",
                   __LINE__,
                   ill_epoch_cur, ill_epoch_smb );
#endif
   }
   if (   (adsl_cl1->dsc_cm.boc_server_always_echo == FALSE)  /* server <always-send-echo> */
       && (   (adsl_cl1->iec_scs != ied_scs_idle)  /* idle, nothing to do */
           || (adsl_cl1->boc_server_notify)  /* notify SMB server is active */
           || (adsl_cl1->iec_clst == ied_clst_idle))) {  /* client is idle */
     ill_epoch_smb = 0;                     /* do not send SMB2 Echo   */
   }
#ifdef B150411
   if (   (adsl_cl1->imc_epoch_keepalive == 0)   /* time to send keepalive */
       && (adsl_cl1->imc_epoch_backlog == 0)) {  /* time to process backlog */
     goto p_ret_40;                         /* timer processed         */
   }
   if (iml_epoch_cur == 0) {                /* time when called        */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_GET_TIME,  /* get current time */
                                      &iml_epoch_cur,  /* time when called */
                                      sizeof(int) );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
#endif
   if (   (adsl_cl1->ilc_epoch_keepalive == 0)   /* time to send keepalive */
       && (adsl_cl1->ilc_epoch_backlog == 0)  /* time to process backlog */
       && (ill_epoch_smb == 0)) {           /* time when SMB2 Echo needs to be sent */
     goto p_ret_40;                         /* timer processed         */
   }
   if (   (ill_epoch_smb == 0)              /* time when SMB2 Echo needs to be sent */
       || (ill_epoch_smb > ill_epoch_cur)) {  /* do not yet sent SMB2 Echo */
     goto p_ret_12;                         /* do not send SMB2 Echo   */
   }
   /* prepare SMB command                                              */
#ifdef XYZ1
// to-do 12.04.15 KB - maybe adsl_dwa == NULL - should use storage in struct dsd_clib1_data_1
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_echo;  /* command echo - keepalive */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_echo;                        /* sent Echo - keep-alive  */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */
#undef ADSL_SMBCC_IN_G1
#endif
   memset( &adsl_cl1->dsc_smbcc_in_cmd,
           0,
           sizeof(struct dsd_smbcc_in_cmd) );
   adsl_cl1->dsc_smbcc_in_cmd.iec_smbcc_in = ied_smbcc_in_echo;  /* command echo - keepalive */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = &adsl_cl1->dsc_smbcc_in_cmd;         /* HOBLink SMB Client Control - input command */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_echo;                        /* sent Echo - keep-alive  */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ret_12:                                /* do not send SMB2 Echo   */
   if (adsp_hl_clib_1->adsc_gai1_out_to_client) {  /* already output to client */
#ifdef B150411
     if (adsl_cl1->imc_epoch_keepalive) {   /* time to send keepalive */
       adsl_cl1->imc_epoch_keepalive        /* time to send keepalive  */
         = iml_epoch_cur + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
     }
#endif
     if (adsl_cl1->ilc_epoch_keepalive) {   /* time to send keepalive */
       adsl_cl1->ilc_epoch_keepalive        /* time to send keepalive  */
         = ill_epoch_cur / 1000 + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
     }
     goto p_ret_20;                         /* set new timer           */
   }
#ifdef B150411
   if (   (adsl_cl1->imc_epoch_keepalive == 0)  /* time to send keepalive */
       || ((iml_epoch_cur - adsl_cl1->imc_epoch_keepalive) < 0)) {  /* time to send keepalive not yet elapsed */
     goto p_ret_20;                         /* set new timer           */
   }
#endif
   if (   (adsl_cl1->ilc_epoch_keepalive == 0)  /* time to send keepalive */
       || ((ill_epoch_cur / 1000 - adsl_cl1->ilc_epoch_keepalive) < 0)) {  /* time to send keepalive not yet elapsed */
     goto p_ret_20;                         /* set new timer           */
   }

   /* send keepalive to client                                         */
#ifdef B150411
   adsl_cl1->imc_epoch_keepalive            /* time to send keepalive  */
     = iml_epoch_cur + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
#endif
   adsl_cl1->ilc_epoch_keepalive            /* time to send keepalive  */
     = ill_epoch_cur / 1000 + adsl_cl1->imc_keepalive + D_KEEPALIVE_DEVIATION;
   if ((dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower) < (sizeof(struct dsd_gather_i_1))) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = (char *) ucrs_keepalive;
   ADSL_GAI1_OUT_W->achc_ginp_end = (char *) ucrs_keepalive + sizeof(ucrs_keepalive);
   ADSL_GAI1_OUT_W->adsc_next = NULL;       /* chain of gather         */
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* new output to client */
#undef ADSL_OUT_W

   p_ret_20:                                /* set new timer           */
#ifdef TRACEHL1
#ifdef B150411
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_20: iml_epoch_cur=%d ->imc_epoch_keepalive=%d ->imc_epoch_backlog=%d.",
                 __LINE__,
                 iml_epoch_cur, adsl_cl1->imc_epoch_keepalive, adsl_cl1->imc_epoch_backlog );
#endif
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ret_20: ill_epoch_cur=%lld ->imc_epoch_keepalive=%lld ->imc_epoch_backlog=%lld ->ilc_epoch_smb=%lld.",
                 __LINE__,
                 ill_epoch_cur, adsl_cl1->ilc_epoch_keepalive, adsl_cl1->ilc_epoch_backlog, adsl_cl1->ilc_epoch_smb );
#endif
#ifdef B150411
   if (   (iml_epoch_cur == 0)              /* time when called        */
       && (   (adsl_cl1->imc_epoch_keepalive)   /* time to send keepalive */
           || (adsl_cl1->imc_epoch_backlog))) {  /* time to process backlog */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_GET_TIME,  /* get current time */
                                      &iml_epoch_cur,  /* time when called */
                                      sizeof(int) );
     if (bol_rc == FALSE) {
       iml1 = __LINE__;
       goto p_error_int_error;              /* internal error has occured */
     }
//   if (iml_epoch_cur == 0) iml_epoch_cur = 1;  /* January 18th 2038  */
   }
   iml1 = adsl_cl1->imc_epoch_keepalive;    /* time to send keepalive  */
   if (   (iml1 == 0)                       /* timer not set           */
       || (   (adsl_cl1->imc_epoch_backlog != 0)  /* time to process backlog */
           && ((adsl_cl1->imc_epoch_backlog - iml1) < 0))) {  /* time to process backlog */
     iml1 = adsl_cl1->imc_epoch_backlog;    /* time to process backlog */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TIMER1_SET,  /* set timer in milliseconds */
                                    NULL,
                                    (iml1 - iml_epoch_cur) * 1000 );  /* timer in seconds to set the timer */
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
#ifdef B150411
   iml1 = adsl_cl1->imc_epoch_keepalive;    /* time to send keepalive  */
   if (   (iml1 == 0)                       /* timer not set           */
       || (   (adsl_cl1->imc_epoch_backlog != 0)  /* time to process backlog */
           && ((adsl_cl1->imc_epoch_backlog - iml1) < 0))) {  /* time to process backlog */
     iml1 = adsl_cl1->imc_epoch_backlog;    /* time to process backlog */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TIMER1_SET,  /* set timer in milliseconds */
                                    NULL,
                                    (iml1 - iml_epoch_cur) * 1000 );  /* timer in seconds to set the timer */
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   ill_w1 = adsl_cl1->ilc_epoch_keepalive;  /* time to send keepalive  */
   if (   (ill_w1 == 0)                     /* timer not set           */
       || (   (adsl_cl1->ilc_epoch_backlog != 0)  /* time to process backlog */
           && ((adsl_cl1->ilc_epoch_backlog - ill_w1) < 0))) {  /* time to process backlog */
     ill_w1 = adsl_cl1->ilc_epoch_backlog;  /* time to process backlog */
   }
   ill_w1 *= 1000;                          /* make milliseconds       */
   if (   (ill_w1 == 0)                     /* timer not set           */
       || (   (ill_epoch_smb != 0)          /* time to send SMB2 Echo  */
           && ((ill_epoch_smb - ill_w1) < 0))) {  /* time to send SMB2 Echo */
     ill_w1 = ill_epoch_smb;                /* time to send SMB2 Echo  */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TIMER1_SET,  /* set timer in milliseconds */
                                    NULL,
                                    ill_w1 - ill_epoch_cur );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }

   p_ret_40:                                /* timer processed         */
   if (   (adsp_hl_clib_1->inc_func == DEF_IFUNC_REFLECT)
       || (adsp_hl_clib_1->inc_func == DEF_IFUNC_TOSERVER)) {
     adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
     adsl_cl1->imc_len_data_from_client = 0;  /* input length data received from client */
     while (adsl_gai1_inp_1) {
       adsl_cl1->imc_len_data_from_client += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
   }
   if (bol_call_vc == FALSE) return;        /* call virus-checking     */
   /* request to virus-checking service                                */
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_requ;  /* service request */
   dsl_aux_sequ1.vpc_sequ_handle = adsl_dwa->vpc_sequ_handle;  /* handle of service query */
   dsl_aux_sequ1.ac_control_area = &adsl_wvc1->dsc_sevchcontr1;  /* control area request */
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SERVICE_REQUEST,  /* service request */
                                    &dsl_aux_sequ1,
                                    sizeof(struct dsd_aux_service_query_1) );
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   return;

   p_cl_inv_dat:                            /* invalid data received from client */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received invalid data from client - processing l%05d.",
                 __LINE__, iml1 );
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W received invalid data from client - processing l%05d.",
                   __LINE__, iml1 );
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;

   p_cl_illogic:                            /* illogic processing of data received from client */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W illogic processing of data received from client - processing l%05d.",
                 __LINE__, iml1 );
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W illogic processing of data received from client - processing l%05d.",
                   __LINE__, iml1 );
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;
#ifdef XYZ1

   p_smb_next_f_20:                         /* save file in directory block */
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_ucs_file_l );
   /* check if pseudo-entries . or ..                                  */
   if (   (iml1 <= 2)
       && (!memcmp( dsl_win_find_data.cFileName, wcrs_ignore_fn, iml1 * sizeof(HL_WCHAR) ))) {
     goto p_smb_next_f_60;                  /* retrieve next file      */
   }
   if (   (adsl_db1_start == NULL)          /* directory block 1 - chaining - start */
       || (((char *) (dsl_dw2.adsc_f1_cur + 1)) > (achl_fn_low - iml1))) {
     adsl_db1_cur = (struct dsd_dir_bl_1 *) malloc( LEN_DIR_BLOCK );
     if (adsl_db1_start == NULL) {          /* directory block 1 - chaining - start */
       adsl_db1_start = adsl_db1_cur;       /* directory block 1 - chaining - start */
       dsl_dw2.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (adsl_db1_start + 1) + sizeof(struct dsd_dir_bl_2));
       ADSL_DB2_G->imc_no_files = 0;        /* number of files         */
       ADSL_DB2_G->imc_no_dir = 0;          /* number of directories   */
       ADSL_DB2_G->boc_unix = FALSE;        /* is Unix filesystem      */
       bol_rc = m_htree1_avl_init( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                   &m_cmp_file );
       if (bol_rc == FALSE) {               /* error occured           */
         m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_dir_local() m_htree1_avl_init() failed",
                       __LINE__ );
         return FALSE;
       }
     } else {
       adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
       adsl_db1_last->achc_end_file = (char *) dsl_dw2.adsc_f1_cur;  /* end of files */
       dsl_dw2.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
     }
     adsl_db1_last = adsl_db1_cur;          /* directory block 1 - chaining - last */
     achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   achl_fn_low -= iml1;                     /* space for file name     */
   dsl_dw2.adsc_f1_cur->adsc_file_1_parent = adsl_file_1_parent;  /* entry of parent directory */
   dsl_dw2.adsc_f1_cur->adsc_file_1_same_n = NULL;  /* chain of entries same name */
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.ac_str = achl_fn_low;
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.imc_len_str = iml1;
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
#endif
// end 27.08.13 KB

   p_smb_rec_00:                            /* received from SMB server */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_00: adsl_cl1->iec_scs=%d adsl_dwa=%p.",
                 __LINE__, adsl_cl1->iec_scs, adsl_dwa );
#endif
#ifdef DEBUG_140823_01
   if (adsl_dwa) {
     adsl_gai1_inp_1 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
     iml1 = 0;
     while (adsl_gai1_inp_1) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_00: adsl_dwa->adsc_gai1_in_from_client adsl_gai1_inp_1=%p.",
                     __LINE__, adsl_gai1_inp_1 );
       iml1 += adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_00: adsl_dwa->adsc_gai1_in_from_client data=%d/0X%X.",
                   __LINE__, iml1, iml1 );
   }
#endif
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) {  /* received from the network */
     goto p_ret_00;                         /* return                  */
   }
   if (adsp_hl_clib_1->boc_send_client_blocked) {  /* sending to the client is blocked */
     adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;  /* notify SDH when sending to the client is possible */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_00: boc_send_client_blocked",
                   __LINE__ );
#endif
     goto p_ret_00;                         /* return                  */
   }
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv = adsp_hl_clib_1->adsc_gather_i_1_in;  /* received from the network */
   if (adsl_dwa == NULL) {                  /* wait for resync - change notify */
     goto p_smb_rec_08;                     /* call SMB component      */
   }
   /* flow control SMB with Virus-Checking                             */
   if (   (adsl_dwa->umc_state & DWA_STATE_VCH_ACT)  /* state of processing */
       && (adsl_wvc1->imc_ss_ahead > 1)) {  /* swap storage in use     */
     goto p_ret_00;                         /* return                  */
   }
#ifdef DEBUG_131228_01
   if (adsl_cl1->iec_scs == ied_scs_write_ss2smb_02) {  /* write file / write */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_131228_01",
                   __LINE__ );
//   return;
     bol1 = TRUE;
   }
#endif
#ifdef B140114
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv = adsp_hl_clib_1->adsc_gather_i_1_in;  /* received from the network */
#endif
// to-do 16.09.13 KB - check if adsl_dwa is NULL
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   if (adsl_cl1->iec_scs == ied_scs_query_dir) {  /* first query-directory */
     dsl_dw2 = adsl_dwa->dsc_dw2;           /* directory operations work area */
   }

   p_smb_rec_08:                            /* call SMB client component */
   bol_call_smb_cl = FALSE;                 /* call SMB client         */
   adsl_cl1->ilc_epoch_smb = ill_epoch_cur;  /* epoch last call to SMB */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_08: adsl_cl1->iec_scs=%d.",
                 __LINE__, adsl_cl1->iec_scs );
#endif
#ifdef XYZ1
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch = NULL;  /* clear chain of output commands */
#endif
   m_smb_cl_call( &adsl_cl1->dsc_smbcl_ctrl );
#ifdef DEBUG_131228_01
   if (   (adsl_cl1->iec_scs == ied_scs_write_ss2smb_02)  /* write file / write */
       && (bol1)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T DEBUG_131228_01",
                   __LINE__ );
//   return;
   }
#endif
   if (adsl_cl1->dsc_smbcl_ctrl.imc_ret_error) {  /* SMB returned error */
     if (   (adsl_cl1->dsc_smbcl_ctrl.imc_ret_error == 2)  /* SMB authentication error */
         && (adsl_cl1->dsc_cm.iec_s2at == ied_s2at_ask_user_pwd)) {  /* ask user for password */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E credentials for SMB server did not work",
                     __LINE__ );
       goto p_ask_user_cred_00;             /* ask user for credentials */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E m_smb_cl_call() returned error %d.",
                   __LINE__, adsl_cl1->dsc_smbcl_ctrl.imc_ret_error );
     if (iml_seml >= 4) {                   /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E m_smb_cl_call() returned error %d.",
                     __LINE__, adsl_cl1->dsc_smbcl_ctrl.imc_ret_error );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef TRACEHL1
   adsl_smbcc_out_w1 = adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch;  /* chain of output commands */
   iml1 = 0;                                /* clear count             */
   while (adsl_smbcc_out_w1) {              /* loop over output commands */
     iml1++;                                /* increment count         */
     adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_08: adsl_cl1->iec_scs=%d chain-output=%d adsc_gai1_nw_send=%p.",
                 __LINE__, adsl_cl1->iec_scs, iml1, adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send );
   if (   (adsl_cl1->iec_scs == ied_scs_read_smb2cl_01)  /* read file from server / open */
       && (iml1 > 5)) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_08: many output commands",
                   __LINE__ );
   }
#endif
   if (adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send) {  /* send over network */
#ifdef B140429
     if (adsp_hl_clib_1->adsc_gai1_out_to_server != NULL) {
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E adsc_gai1_out_to_server double",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
     adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send;  /* chain of data */
#endif
//#ifdef XYZ1
     if (adsp_hl_clib_1->adsc_gai1_out_to_server == NULL) {
       adsp_hl_clib_1->adsc_gai1_out_to_server = adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send;  /* chain of data */
     } else {                               /* append to chain         */
       adsl_gai1_w1 = adsp_hl_clib_1->adsc_gai1_out_to_server;  /* get old output */
       while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       adsl_gai1_w1->adsc_next = adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send;  /* chain of data */
     }
//#endif
     adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_send = NULL;  /* clear send over network */
   }
//--- new 14.01.14 KB - start
   adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv = NULL;  /* received from the network */
//--- new 12.09.13 KB - start
   if (adsl_dwa == NULL) {
#ifndef B141222
     if (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch == NULL) {
       goto p_ret_00;                       /* return                  */
     }
#endif
     iml1 = 0;
     while (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch) {
       iml1 = adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch->iec_smbcc_out;
       if (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch->iec_smbcc_out != ied_smbcc_out_change_notify) break;  /* change notify received */
#ifdef B170124
#ifndef B170118
       adsl_cl1->boc_server_notify = FALSE;  /* notify SMB server is no more active */
#endif
#endif
// to-do 10.01.14 KB - start new
       bol_resync_lo_re = TRUE;             /* TRUE means remote       */
       goto p_resync_00;                    /* start resync - something has changed */
     }
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W waiting only for change notify from server - received command %d.",
                   __LINE__, iml1 );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_smbcc_out_w1 = adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch;  /* chain of output commands */
#ifdef XYZ1
   if (adsl_smbcc_out_w1 == NULL) {         /* chain of output commands */
     goto p_smb_rec_20;                     /* SMB output commands processed */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output commands %p ->iec_smbcc_out %d.",
                 __LINE__, adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch, adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch->iec_smbcc_out );
#endif
#endif
   p_smb_rec_12:                            /* check output command    */
   if (adsl_smbcc_out_w1 == NULL) {         /* chain of output commands */
     goto p_smb_rec_20;                     /* SMB output commands processed */
   }
#ifndef B170105

   p_smb_rec_16:                            /* output command available */
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output commands %p ->iec_smbcc_out %d.",
                 __LINE__, adsl_smbcc_out_w1, adsl_smbcc_out_w1->iec_smbcc_out );
#endif
   if (adsl_smbcc_out_w1->iec_smbcc_out == ied_smbcc_out_change_notify) {  /* change notify received */
#ifdef DEBUG_160115_01                      /* show notify             */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_12: DEBUG_160115_01 received change notify from SMB2",
                   __LINE__ );
#endif
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
     adsl_a1->boc_changed_remote = TRUE;    /* changes remote          */
     adsl_a1->boc_notify_remote = TRUE;     /* notify from server received */
#ifdef B170124
#ifndef B170118
     adsl_cl1->boc_server_notify = FALSE;   /* notify SMB server is no more active */
#endif
#endif
     adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
     goto p_smb_rec_12;                     /* check output command    */
   }

   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
     case ied_scs_query_dir:                /* first query-directory   */
#ifndef B141213
// to-do 13.12.14 KB - should be at other position
       dsl_dw2 = adsl_dwa->dsc_dw2;         /* directory operations work area */
#endif
       goto p_smb_out_cmd_dir_00;           /* SMB output command dir  */
     case ied_scs_read_file:                /* read file from server   */
     case ied_scs_read_smb2ss_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_02:           /* read file from server / data */
       goto p_smb_out_cmd_read_20;          /* SMB output command read */
     case ied_scs_write_ss2smb_01:          /* write file / open       */
     case ied_scs_write_ss2smb_02:          /* write file / write      */
     case ied_scs_write_ss2smb_03:          /* write file / rename     */
     case ied_scs_write_ss2smb_04:          /* write file / do close   */
#ifdef XYZ1
//   case ied_scs_write_ss2smb_05:          /* write file / did close  */
     case ied_scs_write_01:                 /* write file / open       */
#endif
     case ied_scs_write_cl2smb_01:          /* write file / open       */
     case ied_scs_write_cl2smb_02:          /* write file / write      */
       goto p_smb_out_cmd_write_00;         /* SMB output command write */
   }
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */

   p_smb_out_cmd_dir_00:                    /* SMB output command dir  */
   if (adsl_smbcc_out_w1->iec_smbcc_out == ied_smbcc_out_close_info) {  /* close information */
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }
#ifdef XYZ1
#ifndef B170105
   if (adsl_smbcc_out_w1->iec_smbcc_out == ied_smbcc_out_change_notify) {  /* change notify received */
#ifdef DEBUG_160115_01                      /* show notify             */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_out_cmd_dir_00: DEBUG_160115_01 received change notify from SMB2",
                   __LINE__ );
#endif
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
     adsl_a1->boc_changed_remote = TRUE;    /* changes remote          */
     adsl_a1->boc_notify_remote = TRUE;     /* notify from server received */
     adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
     goto p_smb_rec_12;                     /* check output command    */
   }
#endif
#endif
   if (adsl_smbcc_out_w1->iec_smbcc_out != ied_smbcc_out_dir) {  /* not directory information */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_smb_cl_call() output command %p error.",
                   __LINE__, adsl_smbcc_out_w1 );
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }
#define ADSL_OD_G ((struct dsd_smbcc_out_dir *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 query-directory */
#ifndef HELP_DEBUG
#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (dsl_dw2.adsc_db1_start + 1))
#endif
#ifdef HELP_DEBUG
   ADSL_DB2_G = (struct dsd_dir_bl_2 *) (dsl_dw2.adsc_db1_start + 1);
#endif
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &ADSL_OD_G->dsc_ucs_file_name );
   /* check if pseudo-entries . or ..                                  */
   if (   (iml1 <= 2)
       && (!memcmp( ADSL_OD_G->dsc_ucs_file_name.ac_str, wcrs_ignore_fn, iml1 * sizeof(HL_WCHAR) ))) {
     goto p_smb_next_f_60;                  /* retrieve next file      */
   }
   /* check if temporary file local or server                          */
   if (ADSL_OD_G->umc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     goto p_smb_next_f_20;                  /* save file in directory block */
   }
   if (dsl_dw2.imc_ds1_index != dsl_dw2.imc_l_fn_exclude_index) {  /* local index directory compare filename to exclude */
     goto p_smb_next_f_12;                  /* compare temporary file server */
   }
   bol_rc = m_cmpi_vx_vx( &iml_cmp,
                          ADSL_OD_G->dsc_ucs_file_name.ac_str,
                          -1,
                          ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                          dsl_dw2.achc_l_fn_exclude + dsl_dw2.imc_l_fn_exclude_this,
                          dsl_dw2.imc_l_fn_exclude_end - dsl_dw2.imc_l_fn_exclude_this,
                          adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.iec_chs_str );  /* character set of string */
   if ((bol_rc) && (iml_cmp == 0)) {        /* is local temporary file */
     goto p_smb_next_f_60;                  /* retrieve next file      */
   }

   p_smb_next_f_12:                         /* compare temporary file server */
   if (dsl_dw2.imc_ds1_index != dsl_dw2.imc_s_fn_exclude_index) {  /* server index directory compare filename to exclude */
     goto p_smb_next_f_20;                  /* save file in directory block */
   }
   bol_rc = m_cmpi_vx_vx( &iml_cmp,
                          ADSL_OD_G->dsc_ucs_file_name.ac_str,
                          -1,
                          ied_chs_le_utf_16,  /* Unicode UTF-16 little endian */
                          dsl_dw2.achc_s_fn_exclude + dsl_dw2.imc_s_fn_exclude_this,
                          dsl_dw2.imc_s_fn_exclude_end - dsl_dw2.imc_s_fn_exclude_this,
                          adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.iec_chs_str );  /* character set of string */
   if ((bol_rc) && (iml_cmp == 0)) {        /* is server temporary file */
     goto p_smb_next_f_60;                  /* retrieve next file      */
   }

   p_smb_next_f_20:                         /* save file in directory block */
   if (   (dsl_dw2.adsc_db1_start == NULL)  /* directory block 1 - chaining - start */
       || (((char *) (dsl_dw2.adsc_f1_cur + 1)) > (dsl_dw2.achc_fn_low - iml1))) {
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_MEMGET,
                                      &dsl_dw2.adsc_db1_cur,
                                      LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
#ifndef B141213
     dsl_dw2.adsc_db1_cur->adsc_next = NULL;
#endif
     if (dsl_dw2.adsc_db1_start == NULL) {  /* directory block 1 - chaining - start */
       dsl_dw2.adsc_db1_start = dsl_dw2.adsc_db1_cur;  /* directory block 1 - chaining - start */
#ifdef HELP_DEBUG
       ADSL_DB2_G = (struct dsd_dir_bl_2 *) (dsl_dw2.adsc_db1_start + 1);
#endif
       dsl_dw2.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (dsl_dw2.adsc_db1_start + 1) + sizeof(struct dsd_dir_bl_2));
       ADSL_DB2_G->imc_no_files = 0;        /* number of files         */
       ADSL_DB2_G->imc_no_dir = 0;          /* number of directories   */
       ADSL_DB2_G->boc_unix = FALSE;        /* is Unix filesystem      */
       bol_rc = m_htree1_avl_init( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                   &m_cmp_file );
       if (bol_rc == FALSE) {               /* error occured           */
// to-do 12.06.13 KB
#ifdef NOT_YET_130912
         m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_dir_local() m_htree1_avl_init() failed",
                       __LINE__ );
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output command %p error.",
                   __LINE__, adsl_smbcc_out_w1 );
#endif
     goto p_smb_out_cmd_80;                         /* SMB output commands processed */
       }
#ifdef B150207
       dsl_dw2.ilc_sum_size_server = 0;     /* sum file size SMB server */
#endif
     } else {
       dsl_dw2.adsc_db1_last->adsc_next = dsl_dw2.adsc_db1_cur;  /* directory block 1 - chaining */
       dsl_dw2.adsc_db1_last->achc_end_file = (char *) dsl_dw2.adsc_f1_cur;  /* end of files */
       dsl_dw2.adsc_f1_cur = (struct dsd_file_1 *) ((char *) (dsl_dw2.adsc_db1_cur + 1));
     }
     dsl_dw2.adsc_db1_last = dsl_dw2.adsc_db1_cur;  /* directory block 1 - chaining - last */
     dsl_dw2.achc_fn_low = (char *) dsl_dw2.adsc_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   dsl_dw2.achc_fn_low -= iml1;             /* space for file name     */
   dsl_dw2.adsc_f1_cur->adsc_file_1_parent = dsl_dw2.adsc_file_1_parent;  /* entry of parent directory */
   dsl_dw2.adsc_f1_cur->adsc_file_1_same_n = NULL;  /* chain of entries same name */
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.ac_str = dsl_dw2.achc_fn_low;
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.imc_len_str = iml1;
   dsl_dw2.adsc_f1_cur->dsc_ucs_file.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
#ifdef B131229
   dsl_dw2.adsc_f1_cur->dwc_file_attributes = ADSL_OD_G->umc_file_attributes;
#endif
   dsl_dw2.adsc_f1_cur->dwc_file_attributes = ADSL_OD_G->umc_file_attributes & (-1 - FILE_ATTRIBUTE_ARCHIVE);
   memcpy( &dsl_dw2.adsc_f1_cur->dsc_last_write_time,
           &ADSL_OD_G->adsc_fdi->ilc_last_write_time,
           sizeof(FILETIME) );
#ifdef B140102
   dsl_dw2.adsc_f1_cur->ilc_file_size = ADSL_OD_G->adsc_fdi->ilc_end_of_file;  /* EndOfFile */
#endif
   m_get_le8( &dsl_dw2.adsc_f1_cur->ilc_file_size,
              (char *) &ADSL_OD_G->adsc_fdi->ilc_end_of_file );
#ifdef B150207
   dsl_dw2.ilc_sum_size_server += dsl_dw2.adsc_f1_cur->ilc_file_size;  /* sum file size SMB server */
#endif
#ifndef B150207
   adsl_cl1->ilc_sum_size_server += dsl_dw2.adsc_f1_cur->ilc_file_size;  /* sum file size SMB server */
#endif
#ifdef B131223
   dsl_dw2.adsc_f1_cur->achc_virus = NULL;  /* virus found             */
#endif
   dsl_dw2.adsc_f1_cur->umc_flags = 0;      /* flags for processing    */
   dsl_dw2.adsc_f1_cur->achc_virus_client = NULL;  /* virus found on client */
   dsl_dw2.adsc_f1_cur->achc_virus_server = NULL;  /* virus found on server */
   m_cpy_vx_ucs( dsl_dw2.achc_fn_low, iml1, ied_chs_utf_8,  /* Unicode UTF-8 */
                 &ADSL_OD_G->dsc_ucs_file_name );
   if (ADSL_OD_G->umc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_last = dsl_dw2.adsc_f1_cur;  /* entry of file last directory */
     if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur == NULL) {  /* no directory block current */
       adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur = dsl_dw2.adsc_db1_cur;  /* directory block current */
       adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur = dsl_dw2.adsc_f1_cur;  /* entry of file currently directory */
     }
     ADSL_DB2_G->imc_no_dir++;              /* number of directories   */
   }
   ADSL_DB2_G->imc_no_files++;              /* number of files         */

   dsl_dw2.adsc_f1_cur->iec_dac = ied_dac_read_write;  /* access       */
   dsl_dw2.adsc_f1_cur->boc_exclude_compression = FALSE;  /* <exclude-compression> */
   if (adsl_cl1->ac_conf_file_control) {    /* configuration of file control */
     adsl_dwa->dsc_dfcexe.dsc_ucs_filename = dsl_dw2.adsc_f1_cur->dsc_ucs_file;
     if (dsl_dw2.adsc_f1_cur->adsc_file_1_parent) {  /* entry of parent directory */
       if ((adsl_dwa->imc_server_pos_fn_end + 1 + iml1) > LEN_FILE_NAME) {  /* filename too long */
         iml1 = __LINE__;                   /* set line of error       */
         goto p_cl_illogic;                 /* illogic processing of data received from client */
       }
       memcpy( adsl_dwa->byrc_server_fn + adsl_dwa->imc_server_pos_fn_end + 1,
               dsl_dw2.achc_fn_low,
               iml1 );
       adsl_dwa->dsc_dfcexe.dsc_ucs_filename.ac_str
         = adsl_dwa->byrc_server_fn + adsl_dwa->imc_server_pos_fn_start;
       adsl_dwa->dsc_dfcexe.dsc_ucs_filename.imc_len_str
         = adsl_dwa->imc_server_pos_fn_end - adsl_dwa->imc_server_pos_fn_start + 1 + iml1;
     }
     bol_rc = m_dash_file_control_execute( &adsl_dwa->dsc_dfcexe );
     if (bol_rc == FALSE) {                 /* error occured           */
       iml1 = __LINE__;                     /* set line of error       */
       goto p_cl_illogic;                   /* illogic processing of data received from client */
     }
     dsl_dw2.adsc_f1_cur->iec_dac = adsl_dwa->dsc_dfcexe.iec_dac;  /* access */
     dsl_dw2.adsc_f1_cur->boc_exclude_compression = adsl_dwa->dsc_dfcexe.boc_exclude_compression;  /* <exclude-compression> */
#ifdef B150111
     if (adsl_dwa->dsc_dfcexe.ilc_max_file_size) {  /* if not zero found <max-file-size> */
#ifdef B140102
       iml_cmp = m_cmp_longlong_2( (char *) &dsl_dw2.adsc_f1_cur->ilc_file_size, adsl_dwa->dsc_dfcexe.ilc_max_file_size );
       if (iml_cmp > 0) {                   /* file too big            */
         dsl_dw2.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
       }
#endif
       if (dsl_dw2.adsc_f1_cur->ilc_file_size > adsl_dwa->dsc_dfcexe.ilc_max_file_size) {
         dsl_dw2.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
       }
     }
#endif
#ifndef B150111
     if (   (dsl_dw2.adsc_f1_cur->iec_dac != ied_dac_read_write)  /* access read-write */
         && (dsl_dw2.adsc_f1_cur->iec_dac != ied_dac_read_only)) {  /* access read-only */
       dsl_dw2.adsc_f1_cur->umc_flags
         |= D_FILE_1_FLAG_ACCESS            /* access not allowed      */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
     }
     if (   (adsl_dwa->dsc_dfcexe.ilc_max_file_size)  /* if not zero found <max-file-size> */
         && (dsl_dw2.adsc_f1_cur->umc_flags == 0)  /* access not allowed */
         && (dsl_dw2.adsc_f1_cur->ilc_file_size > adsl_dwa->dsc_dfcexe.ilc_max_file_size)) {
       dsl_dw2.adsc_f1_cur->umc_flags
         |= D_FILE_1_FLAG_SIZE              /* file too big            */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
     }
#endif
   }
   if (   (adsl_conf->ilc_max_file_size)    /* maximum file-size       */
       && (adsl_conf->boc_virch_server)) {  /* virus checking data from server / WSP */
#ifdef B140102
     iml_cmp = m_cmp_longlong_2( (char *) &dsl_dw2.adsc_f1_cur->ilc_file_size, adsl_conf->ilc_max_file_size );
     if (iml_cmp > 0) {                     /* file too big            */
       dsl_dw2.adsc_f1_cur->umc_flags |= D_FILE_1_FLAG_SIZE;  /* file too big */
     }
#endif
     if (dsl_dw2.adsc_f1_cur->ilc_file_size > adsl_conf->ilc_max_file_size) {
       dsl_dw2.adsc_f1_cur->umc_flags
         |= D_FILE_1_FLAG_SIZE              /* file too big            */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
     }
   }

   /* add file to AVL-tree                                             */
   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &dsl_dw2.adsc_f1_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
// to-do 12.06.13 KB
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_dir_local() m_htree1_avl_search() failed",
                   __LINE__ );
#ifdef NOT_YET_130912
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_dir_local() m_htree1_avl_search() failed",
                   __LINE__ );
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output command %p error.",
                   __LINE__, adsl_smbcc_out_w1 );
#endif
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
     if (ADSL_F1_SORT->adsc_file_1_same_n == NULL) {  /* chain of entries same name */
       ADSL_F1_SORT->adsc_file_1_same_n = dsl_dw2.adsc_f1_cur;  /* chain of entries same name */
     } else {                               /* already files with same name */
       adsl_f1_w1 = ADSL_F1_SORT->adsc_file_1_same_n;  /* get chain of entries same name */
       while (adsl_f1_w1->adsc_file_1_same_n) {  /* check chain of entries same name */
         adsl_f1_w1 = adsl_f1_w1->adsc_file_1_same_n;  /* next in chain of entries same name */
       }
       adsl_f1_w1->adsc_file_1_same_n = dsl_dw2.adsc_f1_cur;  /* append to chain of entries same name */
     }
     goto p_smb_next_f_40;                  /* end of this file        */
#undef ADSL_F1_SORT
   }
   bol_rc = m_htree1_avl_insert( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &dsl_dw2.adsc_f1_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
// to-do 12.06.13 KB
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_dir_local() m_htree1_avl_insert() failed",
                   __LINE__ );
#ifdef NOT_YET_130912
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_dir_local() m_htree1_avl_insert() failed",
                   __LINE__ );
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output command %p error.",
                   __LINE__, adsl_smbcc_out_w1 );
#endif
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }

   p_smb_next_f_40:                         /* end of this file        */
   dsl_dw2.adsc_f1_cur++;                   /* entry of a single file  */

   p_smb_next_f_60:                         /* retrieve next file      */
   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
   if (adsl_smbcc_out_w1) {                 /* more command output     */
#ifdef B170105
     goto p_smb_out_cmd_dir_00;             /* SMB output command dir  */
#endif
#ifndef B170105
     if (adsl_smbcc_out_w1->iec_smbcc_out == ied_smbcc_out_dir) {  /* not directory information */
       goto p_smb_out_cmd_dir_00;           /* SMB output command dir  */
     }
     goto p_smb_rec_16;                     /* output command available */
#endif
   }
   goto p_smb_out_cmd_80;                   /* SMB output commands processed */
#ifndef HELP_DEBUG
#undef ADSL_DB2_G
#endif
#undef ADSL_OD_G

   p_smb_out_cmd_read_00:                   /* next SMB output command */
   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
   if (adsl_smbcc_out_w1 == NULL) {         /* no more command output  */
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }

   p_smb_out_cmd_read_20:                   /* SMB output command read */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_smb_cl_call() output commands %p ->iec_smbcc_out %d.",
                 __LINE__, adsl_smbcc_out_w1, adsl_smbcc_out_w1->iec_smbcc_out );
#endif
   switch (adsl_smbcc_out_w1->iec_smbcc_out) {
     case ied_smbcc_out_read:               /* data read               */
       goto p_smb_out_cmd_read_40;          /* SMB output command read data */
     case ied_smbcc_out_change_notify:      /* change notify received  */
       break;
     case ied_smbcc_out_close_info:         /* close information       */
// to-do 29.12.13 KB - ignore close info
//     break;
       adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
       if (adsl_smbcc_out_w1 == NULL) {     /* chain of output commands */
//       goto p_smb_rec_20;                 /* SMB output commands processed */
         goto p_smb_out_cmd_80;             /* SMB output commands processed */
       }
   }
#ifdef NOT_YET_130913
       sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E abend",
                __LINE__ );
       goto p_abend_00;                     /* abend of program        */
#endif
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;

   p_smb_out_cmd_read_40:                   /* SMB output command read data */
   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
     case ied_scs_read_smb2ss_01:           /* read file from server / open */
       goto p_cf_se2cl_vc_20;               /* copy server to client, something read */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
#ifdef B141101
       goto p_cf_se2cl_no_20;               /* copy server to client normal, something read */
#endif
       goto p_cf_se2cl_no_00;               /* start copy server to client normal */
     case ied_scs_read_smb2cl_02:           /* read file from server / data */
#ifndef B141213
       adsl_wsmb2cl = &adsl_dwa->dsc_work_smb2cl;  /* copy from SMB to client */
#endif
       goto p_cf_se2cl_no_40;               /* process what has been read */
   }
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
#ifdef NOT_YET_130913
   if (dsl_h_local_file != INVALID_HANDLE_VALUE) {  /* handle of local file */
     goto p_smb_out_cmd_read_60;            /* data read - write data  */
   }
   dsl_h_local_file = CreateFileW( (WCHAR *) wcrs_local_fn, GENERIC_WRITE, 0, 0,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_h_local_file == INVALID_HANDLE_VALUE) {
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E CreateFileW() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
#endif

   p_smb_out_cmd_read_60:                   /* data read - write data  */
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
#ifdef NOT_YET_130913
   bol_rc = WriteFile( dsl_h_local_file, ADSL_SOR_G->achc_data, ADSL_SOR_G->imc_length, &dwl_write, 0 );
   if (bol_rc == FALSE) {
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E WriteFile Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
#endif
#undef ADSL_SOR_G

   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
   if (adsl_smbcc_out_w1) {                 /* more command output     */
     goto p_smb_out_cmd_read_20;            /* SMB output command read */
   }
   goto p_smb_out_cmd_80;                   /* SMB output commands processed */

   p_smb_out_cmd_write_00:                  /* SMB output command write */
   switch (adsl_smbcc_out_w1->iec_smbcc_out) {
     case ied_smbcc_out_create:             /* response to create      */
#define ADSL_SOC_G ((struct dsd_smbcc_out_create *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 create */
       memcpy( adsl_dwa->chrc_file_id, ADSL_SOC_G->chrc_file_id, sizeof(adsl_dwa->chrc_file_id) );
#undef ADSL_SOC_G
       break;
     case ied_smbcc_out_change_notify:      /* change notify received  */
     default:
#ifdef NOT_YET_130913
       sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E abend",
                __LINE__ );
       goto p_abend_00;                     /* abend of program        */
#endif
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next in chain */
   if (adsl_smbcc_out_w1) {                 /* more command output     */
     goto p_smb_out_cmd_write_00;           /* SMB output command write */
   }

   p_smb_out_cmd_80:                        /* SMB output commands processed */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_out_ch = NULL;  /* clear chain of output commands */

   p_smb_rec_20:                            /* SMB output commands processed */
#ifdef NOT_YET_130913
   if (adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv == NULL) {  /* received from the network */
     while (adsl_commbl_recv) {             /* free receive blocks     */
       adsl_commbl_w1 = adsl_commbl_recv;   /* get first block         */
       adsl_commbl_recv = adsl_commbl_w1->adsc_next;  /* remove from chain */
       m_proc_free( adsl_commbl_w1 );       /* free the buffer         */
     }
   }
#endif
#ifdef B141027
   if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch == NULL)
       || (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->boc_processed == FALSE)) {  /* the command has been processed */
     goto p_smb_rec_40;                     /* SMB command processed   */
   }
#endif
   if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch == NULL)
       || (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r == ied_smbcc_in_r_new)) {  /* new command */
     goto p_smb_rec_40;                     /* SMB command processed   */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_smb_cl_call() command processed ->iec_scs=%d ->iec_smbcc_in_r=%d.",
                 __LINE__, adsl_cl1->iec_scs, adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r );
#endif
   if (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r != ied_smbcc_in_r_ok) {  /* command processed without error */
     goto p_smb_rec_28;                     /* SMB command with error  */
   }
#ifndef B170105
   if (   (adsl_a1)
       && (adsl_a1->boc_notify_remote)) {   /* notify from server received */
#ifdef XYZ1
     bol_resync_lo_re = TRUE;               /* TRUE means remote       */
     goto p_resync_00;                      /* start resync - something has changed */
#endif
     adsl_dwa->umc_state |= DWA_STATE_DIR_SERVER;  /* state of processing */
#ifdef B170116
     if (adsl_a1->adsc_db1_local) {         /* already directory from server */
#ifdef B170110
       bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_local );
       if (bol_rc == FALSE) {               /* returned error          */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
#endif
#ifndef B170110
       if (adsl_a1->adsc_db1_local          /* directory block 1 - local */
             != adsl_a1->adsc_db1_sync) {   /* directory block 1 - synchonization */
         bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_local );
         if (bol_rc == FALSE) {             /* returned error          */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
       }
#endif
       adsl_a1->adsc_db1_local = NULL;      /* directory block 1 - local */
     }
#endif
#ifndef B170116
     if (adsl_a1->adsc_db1_remote) {        /* already directory from server */
       if (adsl_a1->adsc_db1_remote         /* directory block 1 - remote */
             != adsl_a1->adsc_db1_sync) {   /* directory block 1 - synchonization */
         bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_remote );
         if (bol_rc == FALSE) {             /* returned error          */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
           return;
         }
       }
       adsl_a1->adsc_db1_remote = NULL;     /* do not free table remote */
     }
#endif
#ifdef B170118
     goto p_smb_scan_00;                    /* start directory scanning */
#endif
#ifndef B170118
     if (   (adsl_a1->boc_write_local == FALSE)  /* can write local    */
         || (adsl_cl1->boc_server_notify)) {  /* notify SMB server is active */
       goto p_smb_scan_00;                  /* start directory scanning */
     }
#ifdef DEBUG_170119_01
     iml1 = __LINE__;
#endif
     goto p_smb_change_ntfy_00;             /* SMB send change notify request */
#endif
   }
#endif
   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
//   case ied_scs_start:                    /* start SMB connection    */
     case ied_scs_connected:                /* SMB connection connected */
#ifdef WAS_BEFORE
       free( adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch );
#endif
       adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
#ifdef TRY
       goto p_smb_scan_00;                  /* start directory scanning */
       goto p_smb_read_copy_00;             /* read and copy a file    */
#endif
       adsl_cl1->boc_smb_connected = TRUE;  /* connected to SMB server */
       if (adsl_dwa->boc_put_cred) {        /* save put / write credendials */
         adsl_dwa->boc_put_cred = FALSE;    /* reset save put / write credendials */
         bol_rc = m_put_stored_user_pwd( &dsl_sdh_call_1 );
         if (bol_rc == FALSE) {             /* returned error          */
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W could not store password of SMB server",
                         __LINE__ );
           if (iml_seml >= 4) {             /* <send-error-messages-level> */
             m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-W could not store password of SMB server",
                           __LINE__ );
           }
         } else {
           m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-I stored password of SMB server",
                         __LINE__ );
           if (iml_seml >= 4) {             /* <send-error-messages-level> */
             m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_MESSAGE, "xl-sdh-dash-01-l%05d-I stored password of SMB server",
                           __LINE__ );
           }
         }
       }
// to-do 24.05.14 KB - check if received change notification from client
       if (adsl_dwa->adsc_cf_backlog) {     /* need to process chain copy file backlog */
         adsl_dwa->adsc_cf_bl_cur = adsl_dwa->adsc_cf_backlog;  /* process chain copy file backlog */
         adsl_a1 = &adsl_dwa->dsc_a1;       /* what action to do       */
         goto p_proc_bl_00;                 /* process backlog         */
       }
       if (adsl_a1->boc_write_local == FALSE) {  /* can write local    */
         goto p_smb_scan_00;                /* start directory scanning */
       }
#ifdef DEBUG_170119_01
       iml1 = __LINE__;
#endif
       goto p_smb_change_ntfy_00;           /* SMB send change notify request */
     case ied_scs_echo:                     /* sent Echo - keep-alive  */
       adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
       adsl_cl1->iec_scs = ied_scs_idle;    /* idle, nothing to do     */
       goto p_ret_00;                       /* return                  */
     case ied_scs_query_dir:                /* first query-directory   */
       goto p_smb_scan_40;                  /* directory has been scanned */
     case ied_scs_read_file:                /* read file from server   */
       goto p_smb_read_copy_20;             /* end of read and copy a file */
     case ied_scs_read_smb2ss_01:           /* read file from server / open */
       goto p_cf_se2cl_vc_80;               /* copy server to client, e-o-f */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_02:           /* read file from server / data */
       goto p_cf_se2cl_no_80;               /* end of file from SMB    */
#ifdef WAS_BEFORE
     case ied_scs_next_action:              /* check for next action   */
       goto p_smp_next_action_00;           /* check for next action   */
#endif
     case ied_scs_write_ss2smb_01:          /* write file / open       */
       goto p_ss2smb_40;                    /* write next chunk Swap Storage */
     case ied_scs_write_ss2smb_02:          /* write file / write      */
       goto p_ss2smb_20;                    /* chunk Swap Storage written */
     case ied_scs_write_ss2smb_03:          /* write file / rename     */
       goto p_ss2smb_80;                    /* rename file over SMB    */
     case ied_scs_write_ss2smb_04:          /* write file / do close   */
       goto p_ss2smb_88;                    /* close file over SMB     */
     case ied_scs_write_ss2smb_05:          /* write file / did close  */
       goto p_ss2smb_end;                   /* did close file over SMB */
     case ied_scs_write_cl2smb_01:          /* write file / open       */
     case ied_scs_write_cl2smb_02:          /* write file / write      */
       goto p_cf_cl2se_40;                  /* end of SMB command      */
#ifdef XYZ1
     case ied_scs_write_01:                 /* write file / open       */
     case ied_scs_write_02:                 /* write file / write      */
       goto p_smb_write_20;                 /* copy local to remote / write */
     case ied_scs_write_03:                 /* write file / set file info */
       goto p_smb_write_40;                 /* copy local to remote / set info file */
     case ied_scs_write_04:                 /* write file / do close   */
       goto p_smb_write_60;                 /* copy local to remote / close */
     case ied_scs_write_05:                 /* write file / did close  */
#ifdef XYZ1
       bol_next_action = TRUE;              /* find the next action to do */
#endif
       goto p_smb_rec_40;                   /* SMB command processed   */
#endif
#ifdef XYZ1
     case ied_scs_create_dir:               /* create directory        */
       bol_next_action = TRUE;              /* find the next action to do */
       goto p_smb_rec_40;                   /* SMB command processed   */
     case ied_scs_delete:                   /* delete file / directory */
       bol_next_action = TRUE;              /* find the next action to do */
       goto p_smb_rec_40;                   /* SMB command processed   */
#endif
     case ied_scs_create_misc:              /* SMB miscellaneous command */
// to-do 15.01.14 KB - is necessary ???
//     adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
#ifndef B140902
       adsl_cl1->iec_scs = ied_scs_idle;    /* idle, nothing to do     */
#endif
       if (adsl_dwa->adsc_cf_bl_cur) {      /* current entry copy file backlog - processing backlog */
         goto p_proc_bl_40;                 /* delete backlog entry    */
       }
       goto p_next_action_00;               /* check for next action   */
     case ied_scs_set_change_ntfy:          /* set change notify       */
#ifdef WAS_B_130612
       goto p_smb_rec_cancel_ntfy_00;           /* SMB send cancel notify request */
#endif
       goto p_smb_scan_00;                  /* start directory scanning */
     case ied_scs_del_change_ntfy:          /* delete change notify    */
#ifdef XYZ1
#ifdef XYZ1
       bol_next_action = TRUE;              /* find the next action to do */
#endif
       goto p_smb_rec_40;                   /* SMB command processed   */
#endif
       adsl_cl1->iec_scs = ied_scs_idle;    /* idle, nothing to do     */
       adsl_cl1->boc_server_notify = FALSE;  /* notify SMB server is active */
       if (adsl_a1->iec_acs == ied_acs_copy_lo2re) {  /* copy from local to remote */
         if (adsl_dwa->boc_virch_local == FALSE) {  /* virus checking data from local / client */
           goto p_cf_cl2se_00;              /* copy client to server   */
         }
         goto p_ss2smb_00;                  /* copy from Swap Storage to SMB */
       }
       goto p_next_action_20;               /* check what to do for next action */
   }
#ifdef WAS_BEFORE_130620
   goto p_smb_rec_40;                           /* SMB command processed   */
#endif
#ifdef NOT_YET_130913
   sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E state adsl_cl1->iec_scs %d illogic",
            __LINE__, adsl_cl1->iec_scs );
   goto p_abend_00;                         /* abend of program        */
#endif
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;

   p_smb_rec_28:                            /* SMB command with error  */
   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
     case ied_scs_read_smb2ss_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
       if (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r == ied_smbcc_in_r_locked) {  /* file is locked */
#ifndef B151127
         adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;  /* no more command */
#endif
         goto p_put_bl_00;                  /* put action to backlog   */
       }
       break;
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E operation SMB-server %d failed - ret %d NT-STATUS %08X.",
                 __LINE__,
                 adsl_cl1->iec_scs,
                 adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r,
                 adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->umc_nt_status );
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E operation SMB-server %d failed - ret %d NT-STATUS %08X.",
                   __LINE__,
                   adsl_cl1->iec_scs,
                   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r,
                   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->umc_nt_status );
   }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;

   p_smb_scan_00:                           /* start directory scanning */
   adsl_a1->boc_notify_remote = FALSE;      /* notify from server received */
   dsl_dw2.imc_ds1_index = 0;               /* index of stack entry directory */
   dsl_dw2.adsc_db1_start = NULL;           /* directory block 1 - chaining - start */
   dsl_dw2.adsc_file_1_parent = NULL;       /* entry of parent directory */
#ifdef XYZ1
   dsl_ucs_file_l.ac_str = dsl_win_find_data.cFileName;
   dsl_ucs_file_l.imc_len_str = -1;         /* length string in elements - zero-terminated */
   dsl_ucs_file_l.iec_chs_str = ied_chs_utf_16;
#endif
// iml_pos_dn = 0;
#ifdef XYZ1
   adsl_ucs_dir_w1 = &adsp_dir_cmd->dsc_ucs_dir;  /* pointer to directory name */
#endif
#ifdef WAS_BEFORE_130620
   memcpy( byrs_file_name, DASH_DIR_REMOTE, sizeof(DASH_DIR_REMOTE) );
   iml_pos_dn = strlen(byrs_file_name);
#endif
   memset( &adsl_dwa->dsrc_ds1[ 0 ], 0, sizeof(struct dsd_dir_stack_1) );
#ifdef WAS_BEFORE_130620
   iml1 = iml_pos_dn;
#endif
   iml1 = adsl_dwa->imc_server_pos_fn_end = adsl_dwa->imc_server_pos_fn_start;
#ifdef WAS_BEFORE_130620
   byrs_file_name[ iml1++ ] = '\\';
#endif
   adsl_dwa->byrc_server_fn[ iml1++ ] = '\\';
   adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].imc_pos_dn = iml1;  /* position in directory name */

#ifdef WAS_BEFORE
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch          /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) malloc( sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create)
                                             + sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_query_directory) );
#define ADSL_SMBCC_IN_G1 adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch
#endif
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   memset( ADSL_SMBCC_IN_G1, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memset( ADSL_SMBCC_IN_CREATE_G, 0, sizeof(struct dsd_smbcc_in_create) );
#ifdef WAS_BEFORE_130620
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = byrs_file_name;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = iml_pos_dn;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_end;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100081;  /* DesiredAccess */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X21;  /* CreateOptions */
#define ADSL_SMBCC_IN_G2 ((struct dsd_smbcc_in_cmd *) (ADSL_SMBCC_IN_CREATE_G + 1))
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G2;
   memset( ADSL_SMBCC_IN_G2, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G2->iec_smbcc_in = ied_smbcc_in_query_directory;  /* command SMB2 query-directory */
#define ADSL_SMBCC_IN_QD_G ((struct dsd_smbcc_in_query_directory *) (ADSL_SMBCC_IN_G2 + 1))
   memset( ADSL_SMBCC_IN_QD_G, 0, sizeof(struct dsd_smbcc_in_query_directory) );
   ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern.ac_str = (void *) "*";
   ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern.ac_str );
   ADSL_SMBCC_IN_QD_G->dsc_ucs_pattern.iec_chs_str = ied_chs_utf_8;
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
#undef ADSL_SMBCC_IN_G2
#undef ADSL_SMBCC_IN_QD_G
   /* prepare that we do not read files which are the temporary files  */
   dsl_dw2.imc_l_fn_exclude_index = -1;     /* local index directory compare filename to exclude */
   if (adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.imc_len_str <= 0) {  /* no local temporary file */
     goto p_smb_scan_20;                    /* end prepare local temporary file */
   }
   /* check if local directory name is longer compared to temporary file */
   if (adsl_cl1->dsc_cm.dsc_ucs_local_dir.imc_len_str >= adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.imc_len_str) {
     goto p_smb_scan_20;                    /* end prepare local temporary file */
   }
   dsl_ucs_file_l = adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn;  /* get name local temporary file */
   dsl_ucs_file_l.imc_len_str = adsl_cl1->dsc_cm.dsc_ucs_local_dir.imc_len_str;
   bol_rc = m_cmpi_ucs_ucs( &iml_cmp, &dsl_ucs_file_l, &adsl_cl1->dsc_cm.dsc_ucs_local_dir );
   if ((bol_rc == FALSE) || (iml_cmp != 0)) {
     goto p_smb_scan_20;                    /* end prepare local temporary file */
   }
   if (*((char *) dsl_ucs_file_l.ac_str + dsl_ucs_file_l.imc_len_str) != '\\') {  /* not end of directory name */
     goto p_smb_scan_20;                    /* end prepare local temporary file */
   }
   dsl_dw2.achc_l_fn_exclude = (char *) adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.ac_str;  /* local filename to exclude */
   dsl_dw2.imc_l_fn_exclude_end = adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.imc_len_str;  /* local end filename to exclude */
   dsl_dw2.imc_l_fn_exclude_this = dsl_ucs_file_l.imc_len_str + 1;  /* local position compare filename to exclude */
   dsl_dw2.imc_l_fn_exclude_next = adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.imc_len_str;
   dsl_dw2.imc_l_fn_exclude_index = 0;      /* local index directory compare filename to exclude */
   achl_w1 = (char *) memchr( dsl_dw2.achc_l_fn_exclude + dsl_dw2.imc_l_fn_exclude_this,
                              '\\',
                              dsl_dw2.imc_l_fn_exclude_next
                                - dsl_dw2.imc_l_fn_exclude_this );
   if (achl_w1) {                           /* was not last directory  */
     dsl_dw2.imc_l_fn_exclude_next
       = achl_w1 - dsl_dw2.achc_l_fn_exclude;
   }

   p_smb_scan_20:                           /* end prepare local temporary file */
   dsl_dw2.imc_s_fn_exclude_index = -1;     /* server index directory compare filename to exclude */
   if (adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str <= 0) {  /* no server temporary file */
     goto p_smb_scan_28;                    /* end prepare server temporary file */
   }
   /* check if server directory name is longer compared to temporary file */
   if (adsl_cl1->dsc_cm.dsc_ucs_server_dir.imc_len_str >= adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str) {
     goto p_smb_scan_28;                    /* end prepare server temporary file */
   }
   dsl_ucs_file_l = adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn;  /* get name server temporary file */
   dsl_ucs_file_l.imc_len_str = adsl_cl1->dsc_cm.dsc_ucs_server_dir.imc_len_str;
   bol_rc = m_cmpi_ucs_ucs( &iml_cmp, &dsl_ucs_file_l, &adsl_cl1->dsc_cm.dsc_ucs_server_dir );
   if ((bol_rc == FALSE) || (iml_cmp != 0)) {
     goto p_smb_scan_28;                    /* end prepare server temporary file */
   }
   if (*((char *) dsl_ucs_file_l.ac_str + dsl_ucs_file_l.imc_len_str) != '\\') {  /* not end of directory name */
     goto p_smb_scan_28;                    /* end prepare server temporary file */
   }
   dsl_dw2.achc_s_fn_exclude = (char *) adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.ac_str;  /* server filename to exclude */
   dsl_dw2.imc_s_fn_exclude_end = adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str;  /* server end filename to exclude */
   dsl_dw2.imc_s_fn_exclude_this = dsl_ucs_file_l.imc_len_str + 1;  /* server position compare filename to exclude */
   dsl_dw2.imc_s_fn_exclude_next = adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str;
   dsl_dw2.imc_s_fn_exclude_index = 0;      /* server index directory compare filename to exclude */
   achl_w1 = (char *) memchr( dsl_dw2.achc_s_fn_exclude + dsl_dw2.imc_s_fn_exclude_this,
                              '\\',
                              dsl_dw2.imc_s_fn_exclude_next
                                - dsl_dw2.imc_s_fn_exclude_this );
   if (achl_w1) {                           /* was not last directory  */
     dsl_dw2.imc_s_fn_exclude_next
       = achl_w1 - dsl_dw2.achc_s_fn_exclude;
   }

   p_smb_scan_28:                           /* end prepare server temporary file */
   adsl_cl1->iec_scs = ied_scs_query_dir;   /* first query-directory   */
#ifndef B150207
   adsl_cl1->ilc_sum_size_server = 0;       /* sum file size SMB server */
#endif
#ifdef NOT_YET_130913
   bol_call_smb_cl = TRUE;                  /* call SMB client         */
   goto p_smb_rec_40;                       /* SMB command processed   */
#endif
   goto p_smb_rec_08;                       /* call SMB component      */

   p_smb_scan_40:                           /* directory has been scanned */
#ifdef B140104
   dsl_dw2.adsc_db1_cur->achc_end_file = (char *) dsl_dw2.adsc_f1_cur;  /* end of files */
   if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur != adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_last) {
//   goto p_smb_dir_60;                         /* search files in this sub-directory */
     goto p_smb_dir_40;                     /* search for next directory */
   }
#endif
   if (dsl_dw2.adsc_db1_start) {            /* directory block 1 - chaining - start */
#ifdef B140902
     if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur != adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_last) {
//     goto p_smb_dir_60;                         /* search files in this sub-directory */
       goto p_smb_dir_40;                   /* search for next directory */
     }
#endif
#ifndef B140902
     if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur != NULL) {
//     goto p_smb_dir_60;                         /* search files in this sub-directory */
#ifndef B150113
       dsl_dw2.adsc_db1_last->achc_end_file = (char *) dsl_dw2.adsc_f1_cur;  /* end of files */
#endif
       goto p_smb_dir_40;                   /* search for next directory */
     }
#endif
   }

   p_smb_dir_20:                            /* all sub-directories processed */
#ifdef DEBUG_170413_01                      /* address adsl_a1 invalid */
   if (adsl_dwa != ((struct dsd_dash_work_all *) adsl_cl1->ac_work_data)) {  /* all dash operations work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_dwa invalid - %p.",
                   __LINE__, adsl_dwa );
     adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   }
   if (adsl_a1 != &adsl_dwa->dsc_a1) {      /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_a1 invalid - %p.",
                   __LINE__, adsl_a1 );
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif  /* DEBUG_170413_01                     address adsl_a1 invalid */
   if (adsl_a1->boc_notify_remote) {        /* notify from server received */
     if (dsl_dw2.adsc_db1_start == NULL) {
       goto p_smb_scan_00;                  /* start directory scanning */
     }
     bol_rc = m_dir_free( &dsl_sdh_call_1, dsl_dw2.adsc_db1_start );
     if (bol_rc == FALSE) {                 /* returned error          */
       iml1 = __LINE__;
       goto p_abend_00;                     /* abend of program        */
     }
     dsl_dw2.adsc_db1_start = NULL;
     goto p_smb_scan_00;                    /* start directory scanning */
   }
   if (dsl_dw2.imc_ds1_index == 0) {
#ifdef XYZ1
     if (adsl_db1_start == NULL) return TRUE;  /* directory block 1 - chaining - start */
     adsl_db1_last->adsc_next = NULL;       /* directory block 1 - chaining */
     return TRUE;
#endif
     if (dsl_dw2.adsc_db1_start) {          /* directory block 1 - chaining - start */
       dsl_dw2.adsc_db1_last->adsc_next = NULL;  /* directory block 1 - chaining */
#ifndef B131223
       dsl_dw2.adsc_db1_last->achc_end_file = (char *) dsl_dw2.adsc_f1_cur;  /* end of files */
#endif
     }
#ifdef WAS_BEFORE
     free( adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch );
#endif
     adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
#ifdef NOT_YET_130912
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T all files of directory found",
                   __LINE__ );
#endif
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T all files of directory found",
                   __LINE__ );
#endif
#ifdef WAS_BEFORE
     adsl_cl1->iec_scs = ied_scs_next_action;         /* check for next action   */
#endif
     adsl_a1->adsc_db1_remote
#ifdef XYZ1
       = adsl_cl1->adsc_db1_remote
#endif
         = dsl_dw2.adsc_db1_start;          /* table remote            */
#ifdef B150207
     adsl_a1->ilc_sum_size_server = 0;      /* sum file size SMB server */
#endif
     adsl_a1->boc_start = TRUE;             /* start processing        */
     adsl_dwa->umc_state &= -1 - DWA_STATE_DIR_SERVER;  /* state of processing */
#ifdef WAS_BEFORE
     bol_call_smb_cl = TRUE;                /* call SMB client         */
#endif
#ifdef XYZ1
     bol_next_action = TRUE;                /* find the next action to do */
#endif
     if (dsl_dw2.adsc_db1_start == NULL) {
       goto p_smb_rec_40;                   /* SMB command processed   */
     }
#ifdef B150207
     adsl_a1->ilc_sum_size_server = dsl_dw2.ilc_sum_size_server;  /* sum file size SMB server */
#endif
#ifndef HELP_DEBUG
#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (dsl_dw2.adsc_db1_start + 1))
#endif
#ifdef HELP_DEBUG
     ADSL_DB2_G = (struct dsd_dir_bl_2 *) (dsl_dw2.adsc_db1_start + 1);
#endif
#ifdef NOT_YET_130912
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T found %d files %d directories",
                   __LINE__,
                   ADSL_DB2_G->imc_no_files,  /* number of files       */
                   ADSL_DB2_G->imc_no_dir );  /* number of directories */
#endif
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T found %d files %d directories",
                   __LINE__,
                   ADSL_DB2_G->imc_no_files,  /* number of files       */
                   ADSL_DB2_G->imc_no_dir );  /* number of directories */
#endif
     bol1 = FALSE;                          /* do not write to log     */
     if (iml_use_log_ls >= 4) {             /* use log-level-share     */
       bol1 = TRUE;                         /* do write to log         */
     }
     if (   (bol1)                          /* write to log            */
         || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
       m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                         "xl-sdh-dash-01-l%05d-I end scanning SMB-server - files %(dec1,)d / directories %(dec1,)d / size %(sci-data)lldB.",
                         __LINE__,
                         ADSL_DB2_G->imc_no_files - ADSL_DB2_G->imc_no_dir,  /* number of files */
                         ADSL_DB2_G->imc_no_dir,  /* number of directories */
                         adsl_cl1->ilc_sum_size_server );  /* sum file size SMB server */
     }
#ifndef HELP_DEBUG
#undef ADSL_DB2_G
#endif
#ifdef TRACEHL1
#ifdef NOT_YET_130912
     m_trace_dir( adsl_db1_start, "SMB-server" );
#endif
     m_trace_dir( &dsl_sdh_call_1, dsl_dw2.adsc_db1_start, "SMB-server" );
#endif
#ifdef WAS_B_130612
     bol_rc = m_create_xml_dir( &adsl_xdb_w1, adsl_db1_start );
     while (adsl_xdb_w1) {
       printf( "%.*s", adsl_xdb_w1->achc_end_data - ((char *) (adsl_xdb_w1 + 1)), adsl_xdb_w1 + 1 );
       adsl_xdb_w1 = adsl_xdb_w1->adsc_next;
     }
#endif
     goto p_smb_rec_40;                     /* SMB command processed   */
   }
   dsl_dw2.imc_ds1_index--;                 /* index of stack entry directory */
   if (dsl_dw2.imc_ds1_index < dsl_dw2.imc_l_fn_exclude_index) {  /* local index directory compare filename to exclude */
     dsl_dw2.imc_l_fn_exclude_index = -1;   /* no more local index directory compare filename to exclude */
   }
   if (dsl_dw2.imc_ds1_index < dsl_dw2.imc_s_fn_exclude_index) {  /* server index directory compare filename to exclude */
     dsl_dw2.imc_s_fn_exclude_index = -1;   /* no more server index directory compare filename to exclude */
   }
#ifdef XYZ1
   if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur == adsl_dwa->dsrc_ds1[ iml_ds1_index ].adsc_f1_dir_last) {
     goto p_smb_dir_20;                     /* all sub-directories processed */
   }
#endif
#ifndef XYZ1
   if (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur == NULL) {
     goto p_smb_dir_20;                     /* all sub-directories processed */
   }
#endif

   p_smb_dir_40:                            /* search for next directory */
#ifdef XYZ1
   adsl_dwa->dsrc_ds1[ iml_ds1_index ].adsc_f1_dir_cur++;  /* entry of parent directory */
#endif
   if (((char *) adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur)
         >= adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur->achc_end_file) {
     adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur = adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur->adsc_next;
     adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur = (struct dsd_file_1 *) ((char *) (adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_db1_cur + 1));
   }
   if ((adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
#ifndef XYZ1
     adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur++;  /* entry of parent directory */
#endif
     goto p_smb_dir_40;                     /* search for next directory */
   }

// p_smb_dir_60:                            /* search files in this sub-directory */
#ifdef WAS_BEFORE_130620
   iml_pos_dn = adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].imc_pos_dn;  /* position in directory name */
#endif
   adsl_dwa->imc_server_pos_fn_end = adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].imc_pos_dn;  /* position in directory name */
   dsl_dw2.adsc_file_1_parent = adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur;  /* entry of parent directory */
#ifndef XYZ1
   adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur++;  /* entry of parent directory */
   if (dsl_dw2.adsc_file_1_parent == adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_last) {
     adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].adsc_f1_dir_cur = NULL;  /* entry of parent directory */
   }
#endif
// adsl_ucs_dir_w1 = &adsl_file_1_parent->dsc_ucs_file;  /* pointer to directory name */
   dsl_dw2.imc_ds1_index++;
   if (dsl_dw2.imc_ds1_index >= MAX_DIR_STACK) {  /* in valid area     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W nesting of directories %d too high - files ignored",
                   __LINE__, MAX_DIR_STACK );
#ifdef NOT_YET_130913
     m_hl1_printf( "xl-sdh-dash-01-l%05d-W nesting of directories %d too high - files ignored",
                   __LINE__, MAX_DIR_STACK );
#endif
     goto p_smb_dir_20;                     /* all sub-directories processed */
   }

   memset( &adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ], 0, sizeof(struct dsd_dir_stack_1) );
#ifdef XYZ1
   iml1 = m_cpy_vx_ucs( &wcrs_local_fn[ iml_pos_dn ], LEN_FILE_NAME - iml_pos_dn, ied_chs_utf_16,
                        adsl_ucs_dir_w1 );
   if (iml1 <= 0) {
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_dir_local() p_smb_next_f_00: could not resolve file-name",
                   __LINE__ );
     goto p_smb_dir_20;                         /* all sub-directories processed */
   }
#endif
   iml1 = dsl_dw2.adsc_file_1_parent->dsc_ucs_file.imc_len_str;
#ifdef WAS_BEFORE_130620
   if ((iml_pos_dn + iml1) >= LEN_FILE_NAME) {
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_smb_cl_call() scan directory error",
                   __LINE__ );
     goto p_smb_rec_40;                         /* SMB command processed   */
   }
   memcpy( byrs_file_name + iml_pos_dn, dsl_dw2.adsc_file_1_parent->dsc_ucs_file.ac_str, iml1 );
   iml1 += iml_pos_dn;
#endif
   if ((adsl_dwa->imc_server_pos_fn_end + iml1) >= LEN_FILE_NAME) {
#ifdef NOT_YET_130913
     m_hl1_printf( "xl-sdh-dash-01-l%05d-T m_smb_cl_call() scan directory error",
                   __LINE__ );
#endif
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_smb_cl_call() scan directory error",
                   __LINE__ );
     goto p_smb_rec_40;                     /* SMB command processed   */
   }
   memcpy( adsl_dwa->byrc_server_fn + adsl_dwa->imc_server_pos_fn_end, dsl_dw2.adsc_file_1_parent->dsc_ucs_file.ac_str, iml1 );
#ifdef B140927
   iml1 += adsl_dwa->imc_server_pos_fn_end;
   iml2 = iml1;                             /* save position end of file name */
#ifdef WAS_BEFORE_130620
   byrs_file_name[ iml1++ ] = '\\';
#endif
   adsl_dwa->byrc_server_fn[ iml1++ ] = '\\';
   adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].imc_pos_dn = iml1;  /* position in directory name */
#endif
#ifndef B140927
   iml1 += adsl_dwa->imc_server_pos_fn_end;
   adsl_dwa->imc_server_pos_fn_end = iml1;
   adsl_dwa->byrc_server_fn[ iml1 ] = '\\';
   adsl_dwa->dsrc_ds1[ dsl_dw2.imc_ds1_index ].imc_pos_dn = iml1 + 1;  /* position in directory name */
#endif
#define ADSL_SMBCC_IN_G1 adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch
#ifdef B141027
   ADSL_SMBCC_IN_G1->boc_processed = FALSE;  /* the command has been processed */
#endif
   ADSL_SMBCC_IN_G1->iec_smbcc_in_r = ied_smbcc_in_r_new;  /* new command */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifdef WAS_BEFORE_130620
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = byrs_file_name;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
#ifdef B140927
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = iml2;
#endif
#ifndef B140927
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = iml1;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
#define ADSL_SMBCC_IN_G2 ((struct dsd_smbcc_in_cmd *) (ADSL_SMBCC_IN_CREATE_G + 1))
#ifdef B141027
   ADSL_SMBCC_IN_G2->boc_processed = FALSE;  /* the command has been processed */
#endif
   ADSL_SMBCC_IN_G2->iec_smbcc_in_r = ied_smbcc_in_r_new;  /* new command */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
#undef ADSL_SMBCC_IN_G2
#ifdef NOT_YET_130913
   bol_call_smb_cl = TRUE;                  /* call SMB client         */
   goto p_smb_rec_40;                           /* SMB command processed   */
#endif
   /* prepare compare temporary files local and server                 */
   if ((dsl_dw2.imc_ds1_index - 1) != dsl_dw2.imc_l_fn_exclude_index) {  /* local index directory compare filename to exclude */
     goto p_smb_dir_60;                     /* prepare compare temporary file server */
   }
   bol_rc = m_cmpi_vx_vx( &iml_cmp,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.ac_str,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.imc_len_str,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.iec_chs_str,  /* character set of string */
                          dsl_dw2.achc_l_fn_exclude + dsl_dw2.imc_l_fn_exclude_this,
                          dsl_dw2.imc_l_fn_exclude_next - dsl_dw2.imc_l_fn_exclude_this,
                          adsl_cl1->dsc_cm.dsc_ucs_local_temp_fn.iec_chs_str );  /* character set of string */
   if ((bol_rc == FALSE) || (iml_cmp != 0)) {  /* not this local temporary file */
     goto p_smb_dir_60;                     /* prepare compare temporary file server */
   }
   /* found directory of local temporary file                          */
   dsl_dw2.imc_l_fn_exclude_index++;        /* local index directory compare filename to exclude */
   dsl_dw2.imc_l_fn_exclude_this = dsl_dw2.imc_l_fn_exclude_next + 1;  /* local position compare filename to exclude */
   dsl_dw2.imc_l_fn_exclude_next = dsl_dw2.imc_l_fn_exclude_end;  /* local position end compare filename to exclude */
   if (dsl_dw2.imc_l_fn_exclude_this >= dsl_dw2.imc_l_fn_exclude_end) {
// to-do 08.04.14 KB - error message
     dsl_dw2.imc_l_fn_exclude_index = -1;   /* local index directory compare filename to exclude */
     goto p_smb_dir_60;                     /* prepare compare temporary file server */
   }
   achl_w1 = (char *) memchr( dsl_dw2.achc_l_fn_exclude + dsl_dw2.imc_l_fn_exclude_this,
                              '\\',
                              dsl_dw2.imc_l_fn_exclude_end - dsl_dw2.imc_l_fn_exclude_this );
   if (achl_w1) {                           /* was not last part       */
     dsl_dw2.imc_l_fn_exclude_next = achl_w1 - dsl_dw2.achc_l_fn_exclude;  /* position local end compare filename to exclude */
   }

   p_smb_dir_60:                            /* prepare compare temporary file server */
   if ((dsl_dw2.imc_ds1_index - 1) != dsl_dw2.imc_s_fn_exclude_index) {  /* server index directory compare filename to exclude */
     goto p_smb_rec_08;                     /* call SMB component      */
   }
   bol_rc = m_cmpi_vx_vx( &iml_cmp,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.ac_str,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.imc_len_str,
                          dsl_dw2.adsc_file_1_parent->dsc_ucs_file.iec_chs_str,  /* character set of string */
                          dsl_dw2.achc_s_fn_exclude + dsl_dw2.imc_s_fn_exclude_this,
                          dsl_dw2.imc_s_fn_exclude_next - dsl_dw2.imc_s_fn_exclude_this,
                          adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.iec_chs_str );  /* character set of string */
   if ((bol_rc == FALSE) || (iml_cmp != 0)) {  /* not this server temporary file */
     goto p_smb_rec_08;                     /* call SMB component      */
   }
   /* found directory of server temporary file                         */
   dsl_dw2.imc_s_fn_exclude_index++;        /* server index directory compare filename to exclude */
   dsl_dw2.imc_s_fn_exclude_this = dsl_dw2.imc_s_fn_exclude_next + 1;  /* server position compare filename to exclude */
   dsl_dw2.imc_s_fn_exclude_next = dsl_dw2.imc_s_fn_exclude_end;  /* server position end compare filename to exclude */
   if (dsl_dw2.imc_s_fn_exclude_this >= dsl_dw2.imc_s_fn_exclude_end) {
// to-do 08.04.14 KB - error message
     dsl_dw2.imc_s_fn_exclude_index = -1;   /* server index directory compare filename to exclude */
     goto p_smb_rec_08;                     /* call SMB component      */
   }
   achl_w1 = (char *) memchr( dsl_dw2.achc_s_fn_exclude + dsl_dw2.imc_s_fn_exclude_this,
                              '\\',
                              dsl_dw2.imc_s_fn_exclude_end - dsl_dw2.imc_s_fn_exclude_this );
   if (achl_w1) {                           /* was not last part       */
     dsl_dw2.imc_s_fn_exclude_next = achl_w1 - dsl_dw2.achc_s_fn_exclude;  /* position server end compare filename to exclude */
   }
   goto p_smb_rec_08;                       /* call SMB component      */

   p_smb_read_copy_00:                      /* read and copy a file    */
#ifdef XYZ1
   if (adsl_a1->boc_changed_local == FALSE) {  /* changes local          */
#ifdef NOT_YET_130912
     if (ims_event_local_notify >= 0) {     /* number of event local notify */
       bol_rc = m_del_local_notify();
// to-do 14.06.13 KB
     }
#endif
     if (adsl_cl1->boc_local_notify) {      /* notify local / client is active */
     }
     adsl_a1->boc_changed_local = TRUE;     /* changes local           */
   }
#endif
#ifdef B140106
   if (adsl_cl1->boc_local_notify) {        /* notify local / client is active */
     adsl_cl1->boc_local_notify = FALSE;    /* notify local / client is active */
     goto p_cl_send_del_chnot_00;           /* send delete change notify */
   }
#endif
#ifdef NOT_YET_130912
   dsl_h_local_file = INVALID_HANDLE_VALUE;  /* handle of local file   */
#endif
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch          /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   memset( ADSL_SMBCC_IN_G1, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memset( ADSL_SMBCC_IN_CREATE_G, 0, sizeof(struct dsd_smbcc_in_create) );
#ifdef WAS_B_130612
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = "AKBIX1\\TEST01\\file01.txt";
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str );
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
#endif
#ifdef NOT_YET_130913
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = ims_server_pos_fn_end;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00120089;  /* DesiredAccess */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00000060;  /* CreateOptions */
#define ADSL_SMBCC_IN_G2 ((struct dsd_smbcc_in_cmd *) (ADSL_SMBCC_IN_CREATE_G + 1))
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G2;
   memset( ADSL_SMBCC_IN_G2, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G2->iec_smbcc_in = ied_smbcc_in_complete_file_read;  /* command read complete file */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
#undef ADSL_SMBCC_IN_G2
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_file;                   /* read file from server   */
   bol_call_smb_cl = TRUE;                  /* call SMB client         */
   goto p_smb_rec_40;                           /* SMB command processed   */

   p_smb_read_copy_20:                      /* end of read and copy a file */
#ifdef NOT_YET_130913
   if (dsl_h_local_file != INVALID_HANDLE_VALUE) {
     goto p_smb_read_copy_40;               /* local file was created  */
   }
       sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E abend",
                __LINE__ );
       goto p_abend_00;                     /* abend of program        */
#endif
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;

   p_smb_read_copy_40:                      /* local file was created  */
#ifdef NOT_YET_130913
   bol_rc = SetFileTime( dsl_h_local_file, NULL, NULL, &adsl_a1->adsc_f1_action->dsc_last_write_time );
   if (bol_rc == FALSE) {
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E SetFileTime() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
   bol_rc = CloseHandle( dsl_h_local_file );
   if (bol_rc == FALSE) {
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E CloseHandle() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
#endif
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
#ifdef NOT_YET_130913
   m_hl1_printf( "xl-sdh-dash-01-l%05d-T file has been read",
                 __LINE__ );
#endif
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T file has been read",
                 __LINE__ );
#ifdef XYZ1
   bol_next_action = TRUE;                  /* find the next action to do */
#endif
   goto p_smb_rec_40;                       /* SMB command processed   */

#ifdef XYZ1
   p_smb_write_00:                          /* copy local to remote    */
#ifdef NOT_YET_130913
   dsl_h_local_file = CreateFileW( (WCHAR *) wcrs_local_fn, GENERIC_READ, FILE_SHARE_READ, 0,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_h_local_file == INVALID_HANDLE_VALUE) {  /* error occured   */
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E CreateFileW() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
#endif
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifdef NOT_YET_130913
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = ims_server_pos_fn_end;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00130197;  /* DesiredAccess */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
// ADSL_SMBCC_IN_CREATE_G->umc_share_access = 0;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 5;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00000044;  /* CreateOptions */
   ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_keep_open;  /* keep file open for following operations */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
   adsl_dwa->ulc_offset = 0;                /* Offset                  */
#ifdef NOT_YET_130913
   bos_local_read = TRUE;                   /* read from local file    */
#endif
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_01;                    /* write file / open       */
   goto p_smb_rec_08;                       /* call SMB component      */
#endif

#ifdef XYZ1
   p_smb_write_20:                          /* copy local to remote / write */
#ifdef NOT_YET_130913
   if (dwl_read == 0) {                     /* reached eof - end-of-file */
     goto p_smb_write_40;                   /* copy local to remote / set info file */
   }
#endif
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_write) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_write;  /* command SMB2 write data */
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_WRITE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_WRITE_G->chrc_file_id) );  /* FileId */
   ADSL_SMBCC_IN_WRITE_G->ulc_offset = adsl_dwa->ulc_offset;  /* Offset */
#ifdef NOT_YET_130913
   dss_gai1_data.achc_ginp_cur = byrs_local_data;
   dss_gai1_data.achc_ginp_end = byrs_local_data + dwl_read;
   dss_gai1_data.adsc_next = NULL;
   ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data = &dss_gai1_data;  /* data to be written */
#endif
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_WRITE_G
#ifdef NOT_YET_130913
   adsl_dwa->ulc_offset += dwl_read;        /* increment offset        */
#endif
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_03;                    /* write file / set file info */
#ifdef NOT_YET_130913
   if (dwl_read == LEN_LOCAL_DATA) {
     bos_local_read = TRUE;                 /* read from local file    */
     adsl_cl1->iec_scs                      /* state of SMB connection */
       = ied_scs_write_02;                  /* write file / write      */
   }
#endif
   goto p_smb_rec_08;                       /* call SMB component      */

   p_smb_write_40:                          /* copy local to remote / set info file */
#ifdef NOT_YET_130913
   bol_rc = GetFileInformationByHandle( dsl_h_local_file, &dsl_fi_l );
   if (bol_rc == FALSE) {                   /* error occured           */
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E GetFileInformationByHandle() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
   bol_rc = CloseHandle( dsl_h_local_file );
   if (bol_rc == FALSE) {                   /* error occured           */
     sprintf( chrs_error_msg, "xl-sdh-dash-01-l%05d-E CloseHandle() Error %d.",
              __LINE__, GetLastError() );
     goto p_abend_00;                       /* abend of program        */
   }
   adsl_a1->adsc_f1_action->dsc_last_write_time = dsl_fi_l.ftLastWriteTime;
   adsl_a1->adsc_f1_action->dwc_file_attributes = dsl_fi_l.dwFileAttributes;
#endif

   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_set_info_file) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_set_info_file;  /* command SMB2 set-info file */
#define ADSL_SMBCC_IN_SIF_G ((struct dsd_smbcc_in_set_info_file *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_SIF_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_SIF_G->chrc_file_id) );  /* FileId */
   *((FILETIME *) &ADSL_SMBCC_IN_SIF_G->dsc_fs_file_basic_information.ilc_last_write_time) = adsl_a1->adsc_f1_action->dsc_last_write_time;
   ADSL_SMBCC_IN_SIF_G->dsc_fs_file_basic_information.umc_file_attributes = adsl_a1->adsc_f1_action->dwc_file_attributes;
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_SIF_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_04;                    /* write file / do close   */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_smb_write_60:                          /* copy local to remote / close */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
// memset( adsl_dwa->byrc_smbcc_in,
//         0,
//         sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_close) );
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_close;  /* command SMB2 close */
#define ADSL_SMBCC_IN_CLOSE_G ((struct dsd_smbcc_in_close *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_CLOSE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_CLOSE_G->chrc_file_id) );  /* FileId */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CLOSE_G
   adsl_cl1->iec_scs                    /* state of SMB connection */
     = ied_scs_write_05;                    /* write file / did close  */
   goto p_smb_rec_08;                       /* call SMB component      */
#endif

#ifdef XYZ1
   p_smb_create_dir_00:                     /* SMB create directory    */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifdef NOT_YET_130913
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = ims_server_pos_fn_end;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100081;  /* DesiredAccess */
// ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = FILE_ATTRIBUTE_DIRECTORY;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 3;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 2;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200021;  /* CreateOptions */
   ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_close;  /* close immediately */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
// to-do 20.06.13 KB
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_create_dir;                  /* create directory        */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_smb_delete_00:                         /* SMB delete file / directory */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifdef NOT_YET_130913
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = ims_server_pos_fn_end;
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100080;  /* DesiredAccess */
// ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000000;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200040;  /* CreateOptions */
   if (adsl_a1->iec_acs == ied_acs_delete_dir_remote) {  /* delete directory remote */
     ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00110080;  /* DesiredAccess */
     ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200021;  /* CreateOptions */
   }
   ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_delete;  /* delete file / directory */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_delete;                      /* delete file / directory */
   goto p_smb_rec_08;                       /* call SMB component      */
#endif

   p_smb_change_ntfy_00:                    /* SMB send change notify request */
#ifdef DEBUG_170119_01
   if (adsl_cl1->boc_server_notify) {       /* notify SMB server is active */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_change_ntfy_00: boc_server_notify set - from l%05d.",
                   __LINE__, iml1 );
   }
#endif
   adsl_cl1->boc_server_notify = TRUE;      /* notify SMB server is active */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create)
             + sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_set_ntfy) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifdef WAS_BEFORE_130620
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = "AKBIX1\\TEST01";
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = strlen( (char *) ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str );
#endif
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_start;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100081;  /* DesiredAccess */
// ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000000;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00000001;  /* CreateOptions */
#define ADSL_SMBCC_IN_G2 ((struct dsd_smbcc_in_cmd *) (ADSL_SMBCC_IN_CREATE_G + 1))
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G2;
   ADSL_SMBCC_IN_G2->iec_smbcc_in
    = ied_smbcc_in_set_notify;              /* command set notify - FindFirstChangeNotification */
#define ADSL_SMBCC_IN_SET_NTFY_G ((struct dsd_smbcc_in_set_ntfy *) (ADSL_SMBCC_IN_G2 + 1))
   ADSL_SMBCC_IN_SET_NTFY_G->usc_flags = HL_SMB2_WATCH_TREE;  /* 0X0001 */
#ifdef B150113
   ADSL_SMBCC_IN_SET_NTFY_G->umc_completion_filter
     = HL_FILE_NOTIFY_CHANGE_FILE_NAME | HL_FILE_NOTIFY_CHANGE_DIR_NAME
         | HL_FILE_NOTIFY_CHANGE_SIZE | HL_FILE_NOTIFY_CHANGE_LAST_WRITE;
#endif
   ADSL_SMBCC_IN_SET_NTFY_G->umc_completion_filter
     = HL_FILE_NOTIFY_CHANGE_FILE_NAME | HL_FILE_NOTIFY_CHANGE_DIR_NAME
         | HL_FILE_NOTIFY_CHANGE_SIZE | HL_FILE_NOTIFY_CHANGE_LAST_WRITE
         | HL_FILE_NOTIFY_CHANGE_CREATION;
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
#undef ADSL_SMBCC_IN_G2
#undef ADSL_SMBCC_IN_SET_NTFY_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_set_change_ntfy;             /* set change notify       */
#ifdef NOT_YET_130913
   bol_call_smb_cl = TRUE;                  /* call SMB client         */
   goto p_smb_rec_40;                       /* SMB command processed   */
#endif
#ifndef B140607
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
#endif
   goto p_smb_rec_08;                       /* call SMB component      */

#ifdef WAS_BEFORE_130620
   p_smb_rec_cancel_ntfy_00:                /* SMB send cancel notify request */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_del_ntfy) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_del_notify;  /* command delete notify - FindCloseChangeNotification */
#undef ADSL_SMBCC_IN_G1
   adsl_cl1->iec_scs                                  /* state of SMB connection */
     = ied_scs_del_change_ntfy;             /* delete change notify    */
   bol_call_smb_cl = TRUE;                  /* call SMB client         */
   goto p_smb_rec_40;                           /* SMB command processed   */
#endif

   p_smb_rec_cancel_ntfy_00:                /* SMB send cancel notify request */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_del_ntfy) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_del_notify;  /* command delete notify - FindCloseChangeNotification */
#undef ADSL_SMBCC_IN_G1
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_del_change_ntfy;             /* delete change notify    */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

#ifdef WAS_BEFOR
   p_smp_next_action_00:                    /* check for next action   */
   bol_rc = m_next_action();                /* find the next action to do */
#ifdef TRACEHL1
   m_get_date_time( chrl_date_time );
   m_hl1_printf( "xl-sdh-dash-01-l%05d-T %s m_next_action() returned bol_rc=%d adsl_a1->iec_acs=%d.",
                 __LINE__, chrl_date_time, bol_rc, adsl_a1->iec_acs );
#endif
   switch (adsl_a1->iec_acs) {                /* state of action         */
     case ied_acs_copy_lo2re:               /* copy from local to remote */
     case ied_acs_copy_re2lo:               /* copy from remote to local */
     case ied_acs_delete_file_local:        /* delete file local       */
     case ied_acs_delete_file_remote:       /* delete file remote      */
     case ied_acs_delete_dir_local:         /* delete directory local  */
     case ied_acs_delete_dir_remote:        /* delete directory remote */
     case ied_acs_done:                     /* all done                */
       break;
   }
#endif

   p_smb_rec_40:                            /* SMB command processed   */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_smb_rec_40:",
                 __LINE__ );
#endif
#ifdef B141027
#ifndef B140905
   if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch)
       && (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->boc_processed)) {  /* the command has not been processed */
     adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;  /* no more command */
   }
#endif
#endif
   if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch)
       && (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r != ied_smbcc_in_r_new)) {  /* not new command */
     adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;  /* no more command */
   }
   if (adsl_cl1->iec_scs == ied_scs_query_dir) {  /* first query-directory */
     adsl_dwa->dsc_dw2 = dsl_dw2;           /* directory operations work area */
#ifdef B141027
#ifndef B140902
     if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch)
         && (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->boc_processed == FALSE)) {  /* the command has not been processed */
//     goto p_smb_rec_08;                   /* call SMB component      */
       goto p_ret_00;                       /* return                  */
     }
#endif
#endif
     if (   (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch)
         && (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch->iec_smbcc_in_r == ied_smbcc_in_r_new)) {  /* new command */
       goto p_ret_00;                       /* return                  */
     }
#ifdef B131228
     adsl_dwa->umc_state &= -1 - DWA_STATE_DIR_SERVER;  /* state of processing */
     if ((adsl_dwa->umc_state & DWA_STATE_DIR_CLIENT) == 0) {  /* state of processing */
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       goto p_next_action_00;           /* check for next action   */
     }
#endif
#ifdef XYZ1
     if (dsl_dw2.imc_ds1_index == 0) {
       adsl_dwa->umc_state &= -1 - DWA_STATE_DIR_SERVER;  /* state of processing */
       if ((adsl_dwa->umc_state & DWA_STATE_DIR_CLIENT) == 0) {  /* state of processing */
         adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
         goto p_next_action_00;           /* check for next action   */
       }
     }
#endif
// to-do 03.09.14 KB - are the following statements ever called, or is this dead code?
     if (   ((adsl_dwa->umc_state & DWA_STATE_DIR_SERVER) == 0)  /* state of processing */
         && (adsl_dwa->umc_state & DWA_STATE_XML_SYNC)) {  /* state of processing */
       bol_rc = m_read_xml_sync_file( &dsl_sdh_call_1,
                                      &adsl_cl1->dsc_cm.dsc_ucs_sync_fn,  /* synchronize file-name */
                                      &adsl_dwa->dsc_a1.adsc_db1_sync,  /* directory block 1 - synchonization */
                                      NULL );
       if (bol_rc == FALSE) {
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
         return;
       }
       adsl_dwa->umc_state &= -1 - DWA_STATE_XML_SYNC;  /* state of processing */
     }
     if ((adsl_dwa->umc_state & (DWA_STATE_DIR_CLIENT | DWA_STATE_DIR_SERVER | DWA_STATE_XML_SYNC)) == 0) {  /* state of processing */
       adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       goto p_next_action_00;               /* check for next action   */
     }
   }
#ifdef XYZ1
   if (   (adsl_cl1->iec_scs == ied_scs_echo)  /* sent Echo - keep-alive */
       && (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch == NULL)) {
     adsl_cl1->iec_scs = ied_scs_idle;      /* idle, nothing to do     */
   }
//--- new 12.09.13 KB - end
// return;
#endif
   goto p_ret_00;                           /* return                  */

   p_proc_bl_00:                            /* process backlog         */
   adsl_cf_backlog_w1 = adsl_dwa->adsc_cf_bl_cur;  /* current entry copy file backlog */
   if (adsl_cf_backlog_w1 == NULL) {        /* current entry copy file backlog */
     goto p_acs_done_00;                    /* action done             */
   }
   if (adsl_cf_backlog_w1->adsc_f1_action == NULL) {  /* pseudo entry of file current action */
     goto p_proc_bl_60;                     /* backlog entry processed */
   }
   adsl_a1->iec_acs = adsl_cf_backlog_w1->iec_acs;  /* state of action */
   adsl_a1->adsc_f1_action = adsl_cf_backlog_w1->adsc_f1_action;  /* entry of file current action */
   goto p_next_action_20;                   /* check what to do for next action */

   p_proc_bl_40:                            /* delete backlog entry    */
   adsl_cf_backlog_w1 = adsl_dwa->adsc_cf_bl_cur;  /* current entry copy file backlog */

   p_proc_bl_60:                            /* backlog entry processed */
   if (adsl_dwa->adsc_cf_backlog == adsl_cf_backlog_w1) {  /* at start of chain copy file backlog */
     adsl_dwa->adsc_cf_backlog = adsl_dwa->adsc_cf_backlog->adsc_next;  /* remove from chain */
   } else {                                 /* middle in chain         */
     adsl_cf_backlog_w2 = adsl_dwa->adsc_cf_backlog;  /* get chain copy file backlog */
     if (adsl_cf_backlog_w2 == NULL) {
         iml1 = __LINE__;                       /* set line of error       */
         goto p_cl_illogic;                     /* illogic processing of data received from client */
     }
     while (adsl_cf_backlog_w2->adsc_next != adsl_cf_backlog_w1) {
       if (adsl_cf_backlog_w2->adsc_next == NULL) {
         iml1 = __LINE__;                       /* set line of error       */
         goto p_cl_illogic;                     /* illogic processing of data received from client */
       }
       adsl_cf_backlog_w2 = adsl_cf_backlog_w2->adsc_next;  /* get next in chain */
     }
     adsl_cf_backlog_w2->adsc_next = adsl_cf_backlog_w1->adsc_next;  /* remove from chain */
   }
   adsl_dwa->adsc_cf_bl_cur = adsl_cf_backlog_w1->adsc_next;  /* remove from chain */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMFREE,  /* release a block of memory */
                                    &adsl_cf_backlog_w1,  /* saved copy file backlog */
                                    sizeof(struct dsd_cf_backlog) );
   if (bol_rc == FALSE) {                   /* error occured           */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   goto p_proc_bl_00;                       /* process backlog         */

   p_next_action_00:                        /* check for next action   */
#ifndef B150127
   adsl_cl1->iec_scs = ied_scs_idle;        /* idle, nothing to do     */
#endif
#ifdef DEBUG_141101_01
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_next_action_00: adsl_cl1->iec_clst=%d.",
                 __LINE__, adsl_cl1->iec_clst );
   Sleep( 500 );
#endif
   bol_rc = m_next_action( &dsl_sdh_call_1, adsl_a1 );  /* find the next action to do */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() returned bol_rc=%d adsl_a1->iec_acs=%d.",
                 __LINE__, bol_rc, adsl_a1->iec_acs );
#endif
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   p_next_action_20:                        /* check what to do for next action */
   switch (adsl_a1->iec_acs) {              /* state of action         */
     case ied_acs_copy_lo2re:               /* copy from local to remote */
       goto p_cf_cl2se_00;                  /* copy client to server   */
     case ied_acs_copy_re2lo:               /* copy from remote to local */
       goto p_cf_se2cl_00;                  /* copy server to client   */
     case ied_acs_create_dir_local:         /* create directory local  */
       iml1 = DASH_DCH_CREATE_DIR;
       goto p_misc_se2cl_00;                /* send miscellaneous command to client */
     case ied_acs_create_dir_remote:        /* create directory remote */
       goto p_smb_misc_00;                  /* SMB miscellaneous commands */
     case ied_acs_delete_file_local:        /* delete file local       */
       iml1 = DASH_DCH_DELETE_FILE;
       goto p_misc_se2cl_00;                /* send miscellaneous command to client */
     case ied_acs_delete_file_remote:       /* delete file remote      */
       goto p_smb_misc_00;                  /* SMB miscellaneous commands */
     case ied_acs_delete_dir_local:         /* delete directory local  */
       iml1 = DASH_DCH_DELETE_DIR;
       goto p_misc_se2cl_00;                /* send miscellaneous command to client */
     case ied_acs_delete_dir_remote:        /* delete directory remote */
       goto p_smb_misc_00;                  /* SMB miscellaneous commands */
     case ied_acs_done:                     /* all done                */
       goto p_acs_done_00;                  /* action done             */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() returned invalid state %d.",
                 __LINE__, adsl_a1->iec_acs );
   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
   return;

   p_acs_done_00:                           /* action done             */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_acs_done_00: ->adsc_db1_new_start=%p ->adsc_db1_local=%p ->adsc_db1_remote=%p ->adsc_db1_sync=%p ->adsc_cf_backlog=%p.",
                 __LINE__, adsl_a1->adsc_db1_new_start, adsl_a1->adsc_db1_local, adsl_a1->adsc_db1_remote, adsl_a1->adsc_db1_sync, adsl_dwa->adsc_cf_backlog );
#endif
#ifndef B160813
   if (adsl_cl1->boc_reconnect) {           /* client does reconnect   */
     goto p_ret_00;                         /* return                  */
   }
#endif
#ifdef DEBUG_170413_01                      /* address adsl_a1 invalid */
   if (adsl_dwa != ((struct dsd_dash_work_all *) adsl_cl1->ac_work_data)) {  /* all dash operations work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_dwa invalid - %p.",
                   __LINE__, adsl_dwa );
     adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   }
   if (adsl_a1 != &adsl_dwa->dsc_a1) {      /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_a1 invalid - %p.",
                   __LINE__, adsl_a1 );
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif  /* DEBUG_170413_01                     address adsl_a1 invalid */
   if (adsl_dwa->adsc_cf_backlog) {         /* we have chain copy file backlog */
     goto p_backlog_start_00;               /* start processing backlog */
   }
   if (adsl_a1->boc_changed_local) {        /* changes local           */
     adsl_dwa->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing */
   }
   if (adsl_a1->boc_changed_remote) {       /* changes remote          */
     adsl_dwa->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing */
   }
#ifndef B150110
   if (adsl_a1->boc_changed_sync) {         /* need to write synchronize file */
     adsl_dwa->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing */
   }
#endif
   if (adsl_a1->adsc_db1_local == adsl_a1->adsc_db1_sync) {  /* table local same as sync */
     adsl_a1->adsc_db1_local = NULL;        /* do not free table local */
   }
   if (adsl_a1->adsc_db1_remote == adsl_a1->adsc_db1_sync) {  /* table remote same as sync */
     adsl_a1->adsc_db1_remote = NULL;       /* do not free table remote */
   }
   if (adsl_a1->adsc_db1_local) {           /* table local             */
     bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_local );
     if (bol_rc == FALSE) {                 /* returned error          */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
//   adsl_a1->adsc_db1_local = NULL;
   }
   if (adsl_a1->adsc_db1_remote) {          /* table remote            */
     bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_remote );
     if (bol_rc == FALSE) {                 /* returned error          */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
//   adsl_a1->adsc_db1_remote = NULL;
   }
   if (adsl_a1->adsc_db1_sync) {            /* table sync              */
     bol_rc = m_dir_free( &dsl_sdh_call_1, adsl_a1->adsc_db1_sync );
     if (bol_rc == FALSE) {                 /* returned error          */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
//   adsl_a1->adsc_db1_sync = NULL;
   }
   adsl_a1->adsc_db1_local
     = adsl_a1->adsc_db1_remote
     = adsl_a1->adsc_db1_sync
     = adsl_cl1->adsc_db1_resync            /* directory block 1 - state for resync */
         = adsl_a1->adsc_db1_new_start;     /* directory block 1 - new */
// adsl_a1->boc_unix_local = FALSE;         /* local is Unix file system */
   adsl_a1->boc_start = TRUE;               /* start processing        */
   if (   (adsl_a1->boc_changed_remote)     /* changes remote          */
       && (adsl_a1->boc_write_local)        /* can write local         */
       && (adsl_cl1->boc_server_notify == FALSE)) {  /* notify SMB server is active */
     adsl_dwa->umc_state |= DWA_STATE_DIR_SERVER;  /* state of processing */
     iel_prco = ied_prco_smb_change_ntfy;   /* SMB send change notify request */
   }
   if (   (adsl_a1->boc_changed_local)      /* changes local           */
       && (adsl_a1->boc_write_server)       /* can write to SMB server */
       && (adsl_cl1->boc_local_notify == FALSE)) {  /* notify local / client is active */
     adsl_dwa->umc_state |= DWA_STATE_DIR_CLIENT;  /* state of processing */
     adsl_cl1->boc_local_notify = TRUE;     /* notify local / client is active */
     goto p_cl_send_ch_notify_00;           /* send change notify      */
   }
   if (iel_prco == ied_prco_smb_change_ntfy) {  /* SMB send change notify request */
#ifdef DEBUG_170119_01
     iml1 = __LINE__;
#endif
     goto p_smb_change_ntfy_00;             /* SMB send change notify request */
   }
   if (adsl_cl1->iec_clst == ied_clst_resp_set_ch_notify) {  /* wait for response set change notify */
#ifdef B150412
     return;                                /* wait for response from client */
#endif
     goto p_ret_00;                         /* return                  */
   }

   p_acs_done_20:                           /* nothing on the way      */
#ifdef TRACEHL1
#define ADSL_DB2_NEW ((struct dsd_dir_bl_2 *) (adsl_a1->adsc_db1_new_start + 1))
   iml1 = iml2 = 0;
   if (   (adsl_a1)
       && (adsl_a1->adsc_db1_new_start)) {  /* directory block 1 - new */
     iml1 = ADSL_DB2_NEW->imc_no_files;     /* number of files         */
     iml2 = ADSL_DB2_NEW->imc_no_dir;       /* number of directories   */
   }
#undef ADSL_DB2_NEW
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_acs_done_20: synchronzied files=%d dirs=%d errors=%d.",
                 __LINE__, iml1, iml2, adsl_a1->imc_errors );
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_acs_done_20: adsl_dwa=%p adsl_a1=%p.",
                 __LINE__, adsl_dwa, adsl_a1 );
#endif
   /* send files synchronized to client                                */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = (unsigned char) DASH_DCH_SYNC_DONE;  /* command        */
#define ADSL_DB2_NEW ((struct dsd_dir_bl_2 *) (adsl_a1->adsc_db1_new_start + 1))
#ifdef B160810
   iml1 = 0;
   if (adsl_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     iml1 = ADSL_DB2_NEW->imc_no_files;     /* number of files         */
   }
#endif
#ifndef B160810
   iml3 = 0;
   if (   (adsl_a1)
       && (adsl_a1->adsc_db1_new_start)) {  /* directory block 1 - new */
     iml3 = ADSL_DB2_NEW->imc_no_files;     /* number of files         */
   }
   iml1 = iml3;
#endif
   do {                                     /* loop to count digits    */
     achl_w1++;                             /* space for digit         */
     iml1 >>= 7;                            /* shift bits              */
   } while (iml1 > 0);
   achl_w3 = achl_w1;                       /* end of digits           */
#ifdef B160810
   iml1 = 0;
   if (adsl_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     iml1 = ADSL_DB2_NEW->imc_no_files;     /* number of files         */
   }
#endif
#ifndef B160810
   iml1 = iml3;
#endif
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w3) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#ifdef B160810
   iml1 = 0;
   if (adsl_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     iml1 = ADSL_DB2_NEW->imc_no_dir;       /* number of directories   */
   }
#endif
#ifndef B160810
   iml3 = 0;
   if (   (adsl_a1)
       && (adsl_a1->adsc_db1_new_start)) {  /* directory block 1 - new */
     iml3 = ADSL_DB2_NEW->imc_no_dir;       /* number of directories   */
   }
   iml1 = iml3;
#endif
   do {                                     /* loop to count digits    */
     achl_w1++;                             /* space for digit         */
     iml1 >>= 7;                            /* shift bits              */
   } while (iml1 > 0);
   achl_w3 = achl_w1;                       /* end of digits           */
   iml1 = 0;
#ifdef B160810
   iml1 = 0;
   if (adsl_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     iml1 = ADSL_DB2_NEW->imc_no_dir;       /* number of directories   */
   }
#endif
#ifndef B160810
   iml1 = iml3;
#endif
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w3) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#ifdef B160810
   iml1 = adsl_a1->imc_errors;              /* files with errors       */
#endif
#ifndef B160810
   iml3 = 0;
   if (adsl_a1) {
     iml3 = adsl_a1->imc_errors;            /* files with errors       */
   }
   iml1 = iml3;
#endif
   do {                                     /* loop to count digits    */
     achl_w1++;                             /* space for digit         */
     iml1 >>= 7;                            /* shift bits              */
   } while (iml1 > 0);
   achl_w3 = achl_w1;                       /* end of digits           */
#ifdef B160810
   iml1 = adsl_a1->imc_errors;              /* files with errors       */
#endif
#ifndef B160810
   iml1 = iml3;
#endif
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w3) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#undef ADSL_DB2_NEW
// dsl_sdh_call_1.achc_lower = achl_w1;
   iml1 = achl_w1 - achl_w2;                /* length of block         */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w1;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W
#ifdef DEBUG_170413_01                      /* address adsl_a1 invalid */
   if (adsl_dwa != ((struct dsd_dash_work_all *) adsl_cl1->ac_work_data)) {  /* all dash operations work area */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_dwa invalid - %p.",
                   __LINE__, adsl_dwa );
     adsl_dwa = (struct dsd_dash_work_all *) adsl_cl1->ac_work_data;  /* all dash operations work area */
   }
   if (adsl_a1 != &adsl_dwa->dsc_a1) {      /* what action to do       */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_170413_01 adsl_a1 invalid - %p.",
                   __LINE__, adsl_a1 );
     adsl_a1 = &adsl_dwa->dsc_a1;           /* what action to do       */
   }
#endif  /* DEBUG_170413_01                     address adsl_a1 invalid */
   if ((adsl_dwa->umc_state & DWA_STATE_XML_WRITE) == 0) {  /* state of processing */
     goto p_acs_done_40;                    /* wait for change notify  */
   }
   bol_rc = m_create_xml_dir( &dsl_sdh_call_1,
                              &adsl_xdb_w1,  /* XML directory block - chaining */
                              adsl_a1->adsc_db1_new_start );  /* directory block 1 - new */
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_create_xml_dir() returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   bol_rc = m_write_xml_sync_file( &dsl_sdh_call_1,
                                   &adsl_cl1->dsc_cm.dsc_ucs_sync_fn,  /* synchronize file-name */
                                   adsl_xdb_w1 );  /* XML directory block - chaining */
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_write_xml_sync_file() returned error",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa->umc_state &= -1 - DWA_STATE_XML_WRITE;  /* state of processing */

   p_acs_done_40:                           /* wait for change notify  */
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 1) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
#define ADSL_DB2_NEW ((struct dsd_dir_bl_2 *) (adsl_a1->adsc_db1_new_start + 1))
     iml1 = 0;
     if (adsl_a1->adsc_db1_new_start) {     /* directory block 1 - new */
       iml1 = ADSL_DB2_NEW->imc_no_files;   /* number of files         */
     }
     iml2 = 0;
     if (adsl_a1->adsc_db1_new_start) {     /* directory block 1 - new */
       iml2 = ADSL_DB2_NEW->imc_no_dir;     /* number of directories   */
     }
#undef ADSL_DB2_NEW
     m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                       "xl-sdh-dash-01-l%05d-I synchronization done - files %(dec1,)d / directories %(dec1,)d / files-with-error %(dec1,)d.",
                       __LINE__, iml1 - iml2, iml2, adsl_a1->imc_errors );
   }

   if (   (adsl_dwa->boc_virch_local == FALSE)  /* virus checking data from local / client */
       && (adsl_dwa->boc_virch_server == FALSE)) {  /* virus checking data from server / WSP */
     goto p_acs_done_60;                    /* virus-checker o.k.      */
   }
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.vpc_sequ_handle = adsl_dwa->vpc_sequ_handle;  /* handle of service query */
   dsl_aux_sequ1.iec_co_service = ied_co_service_close;  /* service close connection */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SERVICE_REQUEST,  /* service request */
                                    &dsl_aux_sequ1,
                                    sizeof(struct dsd_aux_service_query_1) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_aux_sequ1.iec_ret_service != ied_ret_service_ok) {  /* check service return code */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W Virus Checker Service close returned error %d.",
                   __LINE__, dsl_aux_sequ1.iec_ret_service );
   }

   p_acs_done_60:                           /* virus-checker o.k.      */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMFREE,
                                    &adsl_dwa,  /* all dash operations work area */
                                    sizeof(struct dsd_dash_work_all) );  /* all dash operations work area */
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa = NULL;
   adsl_cl1->ac_work_data = NULL;           /* data for work           */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_idle;                        /* idle, nothing to do     */
   adsl_cl1->iec_clst = ied_clst_idle;      /* client is idle          */
   goto p_ret_00;                           /* return                  */

   p_backlog_start_00:                      /* start processing backlog */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_backlog_start_00:",
                 __LINE__ );
#endif
#ifdef B140826
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TIMER1_SET,  /* set timer in milliseconds */
                                    NULL,
                                    D_TIME_BACKLOG * 1000 );  /* timer in seconds when to try backlog operations again */
   if (bol_rc == FALSE) {                   /* returned error          */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   return;
#endif
#ifdef B150411
   if (iml_epoch_cur == 0) {                /* time when called        */
     bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                      DEF_AUX_GET_TIME,  /* get current time */
                                      &iml_epoch_cur,  /* time when called */
                                      sizeof(int) );
     if (bol_rc == FALSE) {
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
     }
   }
#endif
#ifdef B150411
   adsl_cl1->imc_epoch_backlog = iml_epoch_cur + D_TIME_BACKLOG;  /* time to process backlog */
#endif
   adsl_cl1->ilc_epoch_backlog = ill_epoch_cur / 1000 + D_TIME_BACKLOG;  /* time to process backlog */
   goto p_ret_00;                           /* return                  */

   p_smb_misc_00:                           /* SMB miscellaneous commands */
/**
   ied_acs_create_dir_remote                create directory remote
   ied_acs_delete_dir_remote                delete directory remote
   ied_acs_delete_file_remote               delete file remote
*/
   if (adsl_cl1->boc_server_notify) {       /* notify SMB server is active */
     goto p_smb_rec_cancel_ntfy_00;         /* SMB send cancel notify request */
   }
   adsl_a1->boc_changed_remote = TRUE;      /* changes remote          */
   iml1 = adsl_dwa->imc_server_pos_fn_start;
   if (iml1 > 0) {
     adsl_dwa->byrc_server_fn[ iml1++ ] = '\\';
   }
   iml2 = m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, &adsl_dwa->byrc_server_fn[ iml1 ], '\\' );
   adsl_dwa->imc_server_pos_fn_end = iml1 + iml2;
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   memset( ADSL_SMBCC_IN_G1, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memset( ADSL_SMBCC_IN_CREATE_G, 0, sizeof(struct dsd_smbcc_in_create) );
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_end;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   switch (adsl_a1->iec_acs) {              /* state of action         */
     case ied_acs_create_dir_remote:        /* create directory remote */
       ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100081;  /* DesiredAccess */
//     ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = FILE_ATTRIBUTE_DIRECTORY;  /* FileAttributes */
       ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
       ADSL_SMBCC_IN_CREATE_G->umc_share_access = 3;  /* ShareAccess   */
       ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 2;  /* CreateDisposition */
       ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200021;  /* CreateOptions */
       ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_close;  /* close immediately */
       break;
     case ied_acs_delete_file_remote:       /* delete file remote      */
#ifdef B140513
       ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00100080;  /* DesiredAccess */
//     ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000000;  /* FileAttributes */
       ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess   */
       ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
       ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200040;  /* CreateOptions */
       ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_delete;  /* delete file / directory */
#endif
       ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00010080;  /* DesiredAccess */
//     ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000000;  /* FileAttributes */
       ADSL_SMBCC_IN_CREATE_G->umc_share_access = 4;  /* ShareAccess   */
       ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
       ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00001040;  /* CreateOptions */
       ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_close;  /* close immediately */
       break;
     case ied_acs_delete_dir_remote:        /* delete directory remote */
       ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00110080;  /* DesiredAccess */
//     ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000000;  /* FileAttributes */
       ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess   */
       ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
       ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00200021;  /* CreateOptions */
       ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_delete_dir;  /* delete directory */
       break;
   }
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_create_misc;                 /* SMB miscellaneous command */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_cf_cl2se_00:                           /* copy client to server   */
   if (   (adsl_dwa->boc_virch_local == FALSE)  /* virus checking data from local / client */
       && (adsl_cl1->boc_server_notify)) {  /* notify SMB server is active */
     goto p_smb_rec_cancel_ntfy_00;         /* SMB send cancel notify request */
   }
   chl1 = '\\';
   if (adsl_cl1->imc_capabilities & 2) {    /* capabilities client     */
     chl1 = '/';                            /* client is Unix          */
   }
   iml1 = m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, byrl_server_fn, chl1 );
// to-do 27.12.13 KB - other memory - start
   iml2 = adsl_dwa->imc_server_pos_fn_start;
   if (iml2 > 0) {
     adsl_dwa->byrc_server_fn[ iml2++ ] = '\\';
   }
// to-do 26.09.14 KB - overflow
   if ((iml2 + iml1) > LEN_FILE_NAME) {     /* filename too long       */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if ((adsl_cl1->imc_capabilities & 2) == 0) {  /* capabilities client */
     memcpy( &adsl_dwa->byrc_server_fn[ iml2 ], byrl_server_fn, iml1 );
   } else {                                 /* client is Unix          */
     m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, &adsl_dwa->byrc_server_fn[ iml2 ], '\\' );
   }
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 4) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
     achl_wc1 = "compressed";
     if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
       achl_wc1 = "un-compressed";
     }
     m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                       "xl-sdh-dash-01-l%05d-I command to client: transfer %s file %.*(u8)s",
                       __LINE__, achl_wc1, iml1, byrl_server_fn );
   }
// to-do 27.12.13 KB - other memory - end
   adsl_dwa->imc_server_pos_fn_end = iml2 + iml1;
#define ADSL_OUT_W adsp_hl_clib_1->achc_work_area
   achl_w1 = achl_w2 = ADSL_OUT_W + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_READ_FILE;         /* command read file       */
   iml2 = iml3 = iml1 + 1;                  /* length tag + filename   */
   do {                                     /* loop to find length     */
     achl_w1++;                             /* space for digit         */
     iml2 >>= 7;                            /* shift bits              */
   } while (iml2 > 0);
   *achl_w1 = 0;                            /* tag                     */
   memcpy( achl_w1 + 1, byrl_server_fn, iml1 );
   achl_w3 = achl_w1 + 1 + iml1;            /* end of this sub-tag     */
// iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w1) = (unsigned char) ((iml3 & 0X7F) | iml2);
     iml3 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml3 > 0);
   *achl_w3++ = 0X02;                       /* length options          */
   *achl_w3++ = 0X01;                       /* sub-tag options         */
   *achl_w3++ = 0X01;                       /* with compression        */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     *(achl_w3 - 1) = 0;                    /* no compression          */
   }
   iml2 = achl_w3 - achl_w2;                /* length of block         */
// iml3 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* shift bits              */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) (adsp_hl_clib_1->achc_work_area + adsp_hl_clib_1->inc_len_work_area - sizeof(struct dsd_gather_i_1)))
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w3;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_OUT_W
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_resp_read_file_compressed;  /* wait for read file compressed */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     adsl_cl1->iec_clst = ied_clst_resp_read_file_normal;  /* wait for read file normal */
   }
#ifdef B150412
   if (adsl_dwa->boc_virch_local == FALSE) return;  /* virus checking data from local / client */
#endif
   if (adsl_dwa->boc_virch_local == FALSE) {  /* virus checking data from local / client */
     goto p_ret_00;                         /* return                  */
   }
   adsl_dwa->dsc_work_ifvc.imc_len_fn = iml1;  /* length filename      */
   memcpy( adsl_dwa->dsc_work_ifvc.byrc_fn, byrl_server_fn, iml1 );
#ifdef B150412
   return;                                  /* wait for data from client */
#endif
   goto p_ret_00;                           /* return                  */

   /* copy client to server normal, no virus checking, no swap storage */
   p_cf_cl2se_20:                           /* start copy file         */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_20: start copy file",
                 __LINE__ );
#endif
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_dwa->dsc_work_cl2smb.dsc_cdf_ctrl.amc_aux = NULL;  /* de-compression not yet started */
#ifdef B140522
   adsl_dwa->adsc_gai1_in_from_client = NULL;  /* input data from client */
#endif
   adsl_dwa->ulc_offset = 0;                /* Offset                  */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_cl2smb_01;             /* write file / open       */
   goto p_ss2smb_04;                        /* open output file        */

   p_cf_cl2se_40:                           /* end of SMB command      */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_wait;                  /* write file / wait for next input */
   if (adsl_cl1->iec_clst == ied_clst_end_read_file) {  /* received end read file */
     goto p_cf_cl2se_80;                    /* received end of input file */
   }
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_40: adsl_dwa->adsc_gai1_in_from_client=%p.",
                 __LINE__, adsl_dwa->adsc_gai1_in_from_client );
#endif
   adsl_gai1_inp_1 = adsl_dwa->adsc_gai1_in_from_client;  /* input data from client */
   if (adsl_gai1_inp_1 == NULL) {           /* no input from client    */
#ifdef B150412
     return;
#endif
     goto p_ret_00;                         /* return                  */
   }
#ifdef TRACEHL1
   adsl_gai1_inp_2 = adsl_gai1_inp_1;       /* get current gather      */
   iml1 = 0;
#ifdef DEBUG_140925_01
   iml2 = 0;
#endif
   do {
#ifdef DEBUG_140925_01
     iml3 = adsl_gai1_inp_2->achc_ginp_end - adsl_gai1_inp_2->achc_ginp_cur;
     iml2++;                                /* count gather            */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T adsc_gai1_in_from_client %d. gai1=%p len=%d/0X%X.",
                   __LINE__, iml2, adsl_gai1_inp_2, iml3, iml3 );
#endif
     iml1 += adsl_gai1_inp_2->achc_ginp_end - adsl_gai1_inp_2->achc_ginp_cur;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   } while (adsl_gai1_inp_2);
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_40: adsl_gai1_inp_1=%p ->achc_ginp_cur=%p ->achc_ginp_end=%p ->adsc_next=%p data=%d/0X%X.",
                 __LINE__,
                 adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, adsl_gai1_inp_1->achc_ginp_end, adsl_gai1_inp_1->adsc_next,
                 iml1, iml1 );
#endif
#ifdef B141129
   goto p_client_rec_20;                    /* continue received from client */
#endif
   if (adsl_dwa->imc_rl == 0) {             /* remainder record not yet processed */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_40: adsp_hl_clib_1->inc_func=%d adsl_gai1_inp_1=%p.",
                   __LINE__,
                   adsp_hl_clib_1->inc_func,
                   adsl_gai1_inp_1 );
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_40: iml_rl=%d iml_in_gather=%d iml1=%d.",
                   __LINE__,
                   iml_rl, iml_in_gather, iml1 );
#ifdef DEBUG_140823_01
     m_print_gather( &dsl_sdh_call_1, __LINE__, "p_cf_cl2se_40", adsl_dwa->adsc_gai1_in_from_client );
#endif
#endif
     goto p_client_rec_20;                  /* continue received from client */
   }
   iml_rl = adsl_dwa->imc_rl;               /* remainder record not yet processed */
   achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here   */
   goto p_cl_rfc_00;                        /* read file compressed    */

#ifdef NOT_YET_140806
   problem copy file from client to server with length zero
   compression has already started?
   how to find out that we received end immediately,
   without prior content
     if (adsl_cl1->iec_scs == ied_scs_idle) {  /* idle, nothing to do  */
       goto p_cf_cl2se_20;                  /* copy client to server normal, no virus checking, no swap storage */
     }
   normal end; adsl_cl1->iec_scs=15
   ied_scs_write_cl2smb_02,                 /* write file / write      */
    ied_scs_write_wait  /* write file / wait for next input */
06.08.14  KB
#endif
   p_cf_cl2se_80:                           /* received end of input file */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_80: adsl_dwa->adsc_gai1_in_from_client=%p.",
                 __LINE__, adsl_dwa->adsc_gai1_in_from_client );
#endif
#ifdef DEBUG_140823_01
   adsl_gai1_inp_2 = adsl_gai1_inp_check;   /* check input data        */
   iml1 = 0;
   while (adsl_gai1_inp_2) {
     iml2 = adsl_gai1_inp_2->achc_ginp_end - adsl_gai1_inp_2->achc_ginp_cur;
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_80: gather %p not consumed: %d.",
                   __LINE__, adsl_gai1_inp_2, iml2 );
     iml1 += iml2;
     adsl_gai1_inp_2 = adsl_gai1_inp_2->adsc_next;  /* get next in chain */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_cl2se_80: not consumed: %d.",
                 __LINE__, iml1 );
#endif
   if (adsl_cl1->iec_scs != ied_scs_idle) {  /* file transfer already started */
     goto p_cf_cl2se_88;                    /* continue end of input file */
   }
   goto p_cf_cl2se_20;                      /* copy client to server normal, no virus checking, no swap storage */

   p_cf_cl2se_88:                           /* continue end of input file */
   if (   (adsl_cl1->iec_scs != ied_scs_write_cl2smb_01)  /* write file / open */
       && (adsl_cl1->iec_scs != ied_scs_write_cl2smb_02)  /* write file / write */
       && (adsl_cl1->iec_scs != ied_scs_write_wait)) {  /* write file / wait for next input */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E end of input file from client compressed but SMB invalid state iec_scs=%d.",
                   __LINE__, adsl_cl1->iec_scs );
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
   }
   if (adsl_dwa->dsc_work_cl2smb.dsc_cdf_ctrl.amc_aux) {  /* de-compression not ended */
//#ifdef B141129
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E end of input file from client compressed but compression invalid state",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_abend_00;                       /* abend of program        */
//#endif
#ifdef TRY_141129_DOES_NOT_WORK
     /* still data in de-compression engine                            */
     adsl_wcl2smb = &adsl_dwa->dsc_work_cl2smb;  /* copy client to server SMB */
     adsl_cdf_ctrl = &adsl_wcl2smb->dsc_cdf_ctrl;  /* compress data file oriented control */
     adsl_cdf_ctrl->adsc_gai1_in = NULL;    /* chain of gather - input data */
     goto p_cl_rfc_10;                      /* continue de-compression */
#endif
   }
// to-do 26.09.14 KB - field already set ???
   adsl_dwa->adsc_gai1_in_from_client = NULL;  /* input data from client */
   if (adsl_cl1->iec_scs != ied_scs_write_wait) {  /* write file / wait for next input */
#ifdef B150412
     return;
#endif
     goto p_ret_00;                         /* return                  */
   }
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_ss2smb_68;                        /* end of file - do close stuff */

   p_ss2smb_00:                             /* copy from Swap Storage to SMB */
   if (adsl_cl1->boc_server_notify) {       /* notify SMB server is active */
     goto p_smb_rec_cancel_ntfy_00;         /* SMB send cancel notify request */
   }
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
#ifndef B150127
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_01;             /* write file / open       */
   adsl_wss2smb = &adsl_dwa->dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
   if (adsl_cl1->iec_clst != ied_clst_end_virus_checked) {  /* received end read file and virus checked */
     adsl_wss2smb->ilc_read_position = 0;   /* progress content received from client */
     adsl_wss2smb->imc_index_re = 0;        /* index of dataset / chunk - read */
     goto p_ss2smb_04;                      /* open output file        */
   }
#endif
#ifndef B141221
   adsl_dwifvc = &adsl_dwa->dsc_work_ifvc;  /* input file with virus-checking */
   adsl_wvc1 = &adsl_dwifvc->dsc_wvc1;      /* virus-checking          */
#endif
#ifdef B150127
// to-do 27.12.13 KB - file empty
   adsl_wss2smb = &adsl_dwa->dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
#endif
#define ADSL_G_WSS2SMB ((struct dsd_work_ss2smb *) byrl_work1)
   ADSL_G_WSS2SMB->ilc_read_position = adsl_dwifvc->ilc_read_position;  /* progress content received from client */
   ADSL_G_WSS2SMB->vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   ADSL_G_WSS2SMB->imc_index_re = 0;        /* index of dataset / chunk - read */
   *adsl_wss2smb = *ADSL_G_WSS2SMB;
#undef ADSL_G_WSS2SMB
#ifdef B150127
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_01;             /* write file / open       */
#endif

   p_ss2smb_04:                             /* open output file        */
   adsl_a1->boc_changed_remote = TRUE;      /* changes remote          */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_create) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   if (adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str == 0) {
     ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
     ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_end;
     ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   } else {
     ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name = adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn;
   }
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00130197;  /* DesiredAccess */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
// ADSL_SMBCC_IN_CREATE_G->umc_share_access = 0;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 5;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00000044;  /* CreateOptions */
   ADSL_SMBCC_IN_CREATE_G->iec_sicd = ied_sicd_keep_open;  /* keep file open for following operations */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
   adsl_dwa->ulc_offset = 0;                /* Offset                  */
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ss2smb_20:                             /* chunk Swap Storage written */
   adsl_wss2smb = &adsl_dwa->dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
   if (adsl_dwa->ulc_offset >= adsl_wss2smb->ilc_read_position) {  /* progress content received from client */
     goto p_ss2smb_60;                      /* end of Swap Storage reached */
   }
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_release;   /* release swap storage chunk */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2smb->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2smb->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wss2smb->imc_index_re++;            /* index of dataset / chunk - read */

   p_ss2smb_40:                             /* write next chunk Swap Storage */
   adsl_wss2smb = &adsl_dwa->dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
   iml1 = LEN_BLOCK_SWAP;
   if (((HL_LONGLONG) (adsl_wss2smb->imc_index_re + 1) * (HL_LONGLONG) LEN_BLOCK_SWAP)
         > adsl_wss2smb->ilc_read_position) {  /* progress content received from client */
     iml1
       = adsl_wss2smb->ilc_read_position    /* progress content received from client */
           - (HL_LONGLONG) adsl_wss2smb->imc_index_re * (HL_LONGLONG) LEN_BLOCK_SWAP;
     if (iml1 <= 0) {                       /* end of file reached     */
       goto p_ss2smb_60;                    /* end of Swap Storage reached */
     }
   }
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_read;      /* read swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2smb->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2smb->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_wss2smb->dsc_gai1_data.achc_ginp_cur = dsl_astr1.achc_stor_addr;
   adsl_wss2smb->dsc_gai1_data.achc_ginp_end = dsl_astr1.achc_stor_addr + iml1;
   adsl_wss2smb->dsc_gai1_data.adsc_next = NULL;
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_write) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_write;  /* command SMB2 write data */
#define ADSL_SMBCC_IN_WRITE_G ((struct dsd_smbcc_in_write *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
#ifndef B140202
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G1 + 1;
#endif
   memcpy( ADSL_SMBCC_IN_WRITE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_WRITE_G->chrc_file_id) );  /* FileId */
   ADSL_SMBCC_IN_WRITE_G->ulc_offset = adsl_dwa->ulc_offset;  /* Offset */
   ADSL_SMBCC_IN_WRITE_G->adsc_gai1_data = &adsl_wss2smb->dsc_gai1_data;  /* data to be written */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_WRITE_G
   adsl_dwa->ulc_offset += iml1;            /* increment offset        */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_02;             /* write file / write      */
#ifdef DEBUG_131228_01
   bol1 = FALSE;
#endif
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ss2smb_60:                             /* end of Swap Storage reached */
#ifndef B150127
   if (adsl_wss2smb->ilc_read_position == 0) {  /* progress content received from client */
     goto p_ss2smb_68;                      /* end of file - do close stuff */
   }
#endif
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_close;     /* close swap storage      */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2smb->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }

   p_ss2smb_68:                             /* end of file - do close stuff */
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) + sizeof(struct dsd_smbcc_in_set_info_file) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_set_info_file;  /* command SMB2 set-info file */
#define ADSL_SMBCC_IN_SIF_G ((struct dsd_smbcc_in_set_info_file *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_SIF_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_SIF_G->chrc_file_id) );  /* FileId */
   *((FILETIME *) &ADSL_SMBCC_IN_SIF_G->dsc_fs_file_basic_information.ilc_last_write_time) = adsl_a1->adsc_f1_action->dsc_last_write_time;
   ADSL_SMBCC_IN_SIF_G->dsc_fs_file_basic_information.umc_file_attributes = adsl_a1->adsc_f1_action->dwc_file_attributes;
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_SIF_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_03;             /* write file / rename     */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ss2smb_80:                             /* rename file over SMB    */
   if (adsl_cl1->dsc_cm.dsc_ucs_server_temp_fn.imc_len_str == 0) {
     goto p_ss2smb_88;                      /* close file over SMB     */
   }
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_rename_file;  /* command SMB2 rename open file */
#define ADSL_SMBCC_IN_RENAME_G ((struct dsd_smbcc_in_rename_file *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_RENAME_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_RENAME_G->chrc_file_id) );  /* FileId */
   /* new filename                                                     */
   ADSL_SMBCC_IN_RENAME_G->dsc_ucs_new_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_RENAME_G->dsc_ucs_new_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_end;
   ADSL_SMBCC_IN_RENAME_G->dsc_ucs_new_file_name.iec_chs_str = ied_chs_utf_8;
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_RENAME_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_04;             /* write file / do close   */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ss2smb_88:                             /* close file over SMB     */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch  /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
   memset( adsl_dwa->byrc_smbcc_in,
           0,
           sizeof(struct dsd_smbcc_in_cmd) );
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_close;  /* command SMB2 close */
#define ADSL_SMBCC_IN_CLOSE_G ((struct dsd_smbcc_in_close *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memcpy( ADSL_SMBCC_IN_CLOSE_G->chrc_file_id, adsl_dwa->chrc_file_id, sizeof(ADSL_SMBCC_IN_CLOSE_G->chrc_file_id) );  /* FileId */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CLOSE_G
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_write_ss2smb_05;             /* write file / did close  */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_ss2smb_end:                            /* did close file over SMB */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2smb_end: - end copy from Swap Storage to SMB",
                 __LINE__ );
#endif
   adsl_wss2smb = &adsl_dwa->dsc_work_ss2smb;  /* copy from Swap Storage to SMB */
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   if (adsl_dwa->boc_virch_local == FALSE) {  /* virus checking data from local / client */
     adsl_a1->adsc_f1_action->ilc_file_size  /* size of file           */
       = adsl_dwa->ulc_offset;              /* progress content written to SMB */
#ifdef B150207
     adsl_a1->ilc_sum_size_server           /* sum file size SMB server */
       += adsl_dwa->ulc_offset              /* progress content written to SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_server          /* sum file size SMB server */
       += adsl_dwa->ulc_offset              /* progress content written to SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
   } else {                                 /* with virus checking     */
     adsl_a1->adsc_f1_action->ilc_file_size  /* size of file           */
       = adsl_wss2smb->ilc_read_position;   /* progress content received from client */
#ifdef B150207
     adsl_a1->ilc_sum_size_server           /* sum file size SMB server */
       += adsl_wss2smb->ilc_read_position   /* progress content received from client */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_server          /* sum file size SMB server */
       += adsl_wss2smb->ilc_read_position   /* progress content received from client */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
   }
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_idle;                        /* idle, nothing to do     */
   if (adsl_dwa->adsc_cf_bl_cur) {          /* current entry copy file backlog - processing backlog */
     goto p_proc_bl_40;                     /* delete backlog entry    */
   }
   goto p_next_action_00;                   /* check for next action   */

   p_cf_se2cl_00:                           /* copy server to client   */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_se2cl_00: - copy server to client",
                 __LINE__ );
#endif
#ifdef XYZ1
   if (adsl_cl1->boc_local_notify) {        /* notify local / client is active */
     adsl_cl1->boc_local_notify = FALSE;    /* notify local / client is active */
     goto p_cl_send_del_chnot_00;           /* send delete change notify */
   }
#endif
   if (   (adsl_dwa->boc_virch_server == FALSE)  /* virus checking data from server / WSP */
       && (adsl_cl1->boc_local_notify)) {   /* notify local / client is active */
     adsl_cl1->boc_local_notify = FALSE;    /* notify local / client is active */
     adsl_cl1->iec_clst = ied_clst_resp_del_ch_notify_normal;  /* wait for response delete change notify - normal */
     goto p_cl_send_del_chnot_00;           /* send delete change notify */
   }
#ifdef B141217
   adsl_dwa->dsc_work_smb2ss.dsc_wvc1.imc_ss_ahead = 0;  /* swap storage in use */
#endif
#ifndef B141217
   if (adsl_dwa->boc_virch_server == FALSE) {  /* virus checking data from server / WSP */
     adsl_dwa->dsc_work_smb2cl.ilc_read_position = 0;  /* progress content received from SMB */
     adsl_cl1->iec_scs                      /* state of SMB connection */
       = ied_scs_read_smb2cl_01;            /* read file from server / open */
   } else {                                 /* with virus checking     */
     adsl_dwa->dsc_work_smb2ss.ilc_read_position = 0;  /* progress content received from SMB */
     adsl_dwa->dsc_work_smb2ss.dsc_wvc1.imc_ss_ahead = 0;  /* swap storage in use */
     adsl_cl1->iec_scs                      /* state of SMB connection */
       = ied_scs_read_smb2ss_01;            /* read file from server / open */
   }
#endif
   iml1 = adsl_dwa->imc_server_pos_fn_start;
   if (iml1 > 0) {
     adsl_dwa->byrc_server_fn[ iml1++ ] = '\\';
   }
   iml2 = m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, &adsl_dwa->byrc_server_fn[ iml1 ], '\\' );
   adsl_dwa->imc_server_pos_fn_end = iml1 + iml2;
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch          /* chain of input commands */
     = (struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in;
#define ADSL_SMBCC_IN_G1 ((struct dsd_smbcc_in_cmd *) adsl_dwa->byrc_smbcc_in)
   memset( ADSL_SMBCC_IN_G1, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G1->iec_smbcc_in = ied_smbcc_in_create;  /* command SMB2 create */
#define ADSL_SMBCC_IN_CREATE_G ((struct dsd_smbcc_in_create *) (adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch + 1))
   memset( ADSL_SMBCC_IN_CREATE_G, 0, sizeof(struct dsd_smbcc_in_create) );
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.ac_str = adsl_dwa->byrc_server_fn;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.imc_len_str = adsl_dwa->imc_server_pos_fn_end;
   ADSL_SMBCC_IN_CREATE_G->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   ADSL_SMBCC_IN_CREATE_G->umc_desired_access = 0X00120089;  /* DesiredAccess */
   ADSL_SMBCC_IN_CREATE_G->umc_file_attributes = 0X00000080;  /* FileAttributes */
   ADSL_SMBCC_IN_CREATE_G->umc_share_access = 7;  /* ShareAccess       */
   ADSL_SMBCC_IN_CREATE_G->umc_create_disposition = 1;  /* CreateDisposition */
   ADSL_SMBCC_IN_CREATE_G->umc_create_options = 0X00000060;  /* CreateOptions */
#define ADSL_SMBCC_IN_G2 ((struct dsd_smbcc_in_cmd *) (ADSL_SMBCC_IN_CREATE_G + 1))
   ADSL_SMBCC_IN_G1->adsc_next = ADSL_SMBCC_IN_G2;
   memset( ADSL_SMBCC_IN_G2, 0, sizeof(struct dsd_smbcc_in_cmd) );
   ADSL_SMBCC_IN_G2->iec_smbcc_in = ied_smbcc_in_complete_file_read;  /* command read complete file */
#undef ADSL_SMBCC_IN_G1
#undef ADSL_SMBCC_IN_CREATE_G
#undef ADSL_SMBCC_IN_G2
   adsl_cl1->dsc_smbcl_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
#ifdef B141101
   if (adsl_dwa->boc_virch_server == FALSE) {  /* virus checking data from server / WSP */
     goto p_cf_se2cl_no_00;                 /* start copy server to client normal */
   }
#endif
#ifdef B141217
   if (adsl_dwa->boc_virch_server == FALSE) {  /* virus checking data from server / WSP */
     adsl_cl1->iec_scs                      /* state of SMB connection */
       = ied_scs_read_smb2cl_01;            /* read file from server / open */
     goto p_smb_rec_08;                     /* call SMB component      */
   }
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_smb2ss_01;              /* read file from server / open */
#endif
   goto p_smb_rec_08;                       /* call SMB component      */

   p_cf_se2cl_vc_20:                        /* copy server to client, something read */
   adsl_wsmb2ss = &adsl_dwa->dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
   adsl_wvc1 = &adsl_wsmb2ss->dsc_wvc1;     /* virus-checking          */
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_se2cl_vc_20: ADSL_SOR_G->imc_length=%d adsl_wvc1->imc_ss_ahead=%d.",
                 __LINE__, ADSL_SOR_G->imc_length, adsl_wvc1->imc_ss_ahead );
#endif
#ifdef XYZ1
   if (ADSL_SOR_G->imc_length == 0) {       /* nothing read            */
     goto p_cf_se2cl_vc_80;                    /* copy server to client, e-o-f */
   }
#endif
#ifdef B141222$XXX
   if (ADSL_SOR_G->imc_length == 0) {       /* nothing read            */
     if (adsl_wvc1->imc_ss_ahead > 0) {     /* swap storage in use     */
       goto p_cf_se2cl_vc_80;               /* copy server to client, e-o-f */
     }
   }
#endif
   if (adsl_wvc1->imc_ss_ahead > 0) {       /* swap storage in use     */
     goto p_cf_se2cl_vc_28;                 /* copy content to Swap Storage */
   }
   iml1 = adsl_dwa->imc_server_pos_fn_start;
   if (iml1 > 0) iml1++;                    /* after separator         */
   bol_rc = m_work_vc_init( &dsl_sdh_call_1,
                            adsl_wvc1,      /* virus-checking          */
                            adsl_dwa,       /* all dash operations work area */
                            &adsl_dwa->byrc_server_fn[ iml1 ],
                            adsl_dwa->imc_server_pos_fn_end - iml1 );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#ifdef B141222
   adsl_wsmb2ss->ilc_read_position = 0;     /* progress content received from SMB */
#endif
   adsl_wsmb2ss->achc_output = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* output data till here */
   bol_call_vc = TRUE;                      /* call virus-checking     */

   p_cf_se2cl_vc_28:                        /* copy content to Swap Storage */
   achl_w1 = ADSL_SOR_G->achc_data;         /* start of data           */
   iml1 = ADSL_SOR_G->imc_length;           /* length of data          */
#undef ADSL_SOR_G
   adsl_wsmb2ss->ilc_read_position += iml1;  /* progress content received from SMB */

   p_cf_se2cl_vc_32:                        /* copy data, if possible  */
   iml2
     = adsl_wvc1->achrc_stor_addr_ss[ adsl_wvc1->imc_ss_ahead - 1 ] + LEN_BLOCK_SWAP
         - adsl_wsmb2ss->achc_output;       /* output data till here   */
   bol1 = FALSE;                            /* not written to virus-checker */
   if (iml2 <= 0) {                         /* no space in output area */
     goto p_cf_se2cl_vc_36;                 /* send to virus-checker done */
   }
   if (iml2 > iml1) iml2 = iml1;
   memcpy( adsl_wsmb2ss->achc_output, achl_w1, iml2 );
   iml1 -= iml2;                            /* bytes copied            */
   adsl_wsmb2ss->achc_output += iml2;       /* output data till here   */
   achl_w1 += iml2;                         /* input consumed          */

   if (adsl_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     goto p_cf_se2cl_vc_36;                 /* send to virus-checker done */
   }
   if (adsl_wvc1->achc_vc_written == adsl_wsmb2ss->achc_output) {  /* address written to virus-checking */
     bol1 = TRUE;                           /* written to virus-checker */
     goto p_cf_se2cl_vc_36;                 /* send to virus-checker done */
   }
   iml2 = 0;                                /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsl_wvc1->dsrc_sevchreq1[ iml2 ].iec_stat) < 0) break;  /* check unused */
     iml2++;                                /* increment index         */
   } while (iml2 < NO_VC_REQ1);             /* number of concurrent requests */
   if (iml2 >= NO_VC_REQ1) {                /* number of concurrent requests */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_cf_se2cl_vc_32: buffer full, wait virus-checker, set boc_wait_window",
                   __LINE__ );
#endif
     adsl_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     bol_call_vc = TRUE;                    /* call virus-checking     */
     goto p_cf_se2cl_vc_36;                 /* send to virus-checker done */
   }
   adsl_wvc1->dsrc_gai1_vch_data[ iml2 ].achc_ginp_cur = adsl_wvc1->achc_vc_written;  /* address written to virus-checking */
   adsl_wvc1->dsrc_gai1_vch_data[ iml2 ].achc_ginp_end = adsl_wsmb2ss->achc_output;
   adsl_wvc1->dsrc_gai1_vch_data[ iml2 ].adsc_next = NULL;
#ifdef DEBUG_141231_02                      /* gather to virus-checker empty */
   if (adsl_wvc1->dsrc_gai1_vch_data[ iml2 ].achc_ginp_cur >= adsl_wvc1->dsrc_gai1_vch_data[ iml2 ].achc_ginp_end) {
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEBUG_141231_02",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#endif
   adsl_wvc1->achrc_stor_addr_vc[ iml2 ] = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   memset( &adsl_wvc1->dsrc_sevchreq1[ iml2 ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsl_wvc1->dsrc_sevchreq1[ iml2 ].adsc_gai1_data = &adsl_wvc1->dsrc_gai1_vch_data[ iml2 ];
   adsl_wvc1->dsrc_sevchreq1[ iml2 ].iec_vchreq1 = ied_vchreq_content;  /* content of file */
   if (adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsl_wvc1->dsrc_sevchreq1[ iml2 ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsl_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsl_wvc1->dsrc_sevchreq1[ iml2 ];
   }
   adsl_wvc1->dsc_sevchcontr1.ilc_window_1
     += adsl_wsmb2ss->achc_output - adsl_wvc1->achc_vc_written;
   bol_call_vc = TRUE;                      /* call virus-checking     */
   adsl_wvc1->achc_vc_written = adsl_wsmb2ss->achc_output;  /* address written to virus-checking */
   bol1 = TRUE;                             /* written to virus-checker */

   p_cf_se2cl_vc_36:                        /* send to virus-checker done */
   if (iml1 <= 0) {                         /* no more data to copy    */
     goto p_cf_se2cl_vc_60;                 /* this chunk has been copied */
   }
   if (bol1 == FALSE) {                     /* not written to virus-checker */
     goto p_cf_se2cl_vc_40;                 /* get new block from swap storage */
   }
   /* release block for buffering in swap storage                      */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_write;     /* write swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.achc_stor_addr = adsl_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_wr;  /* index of dataset / chunk - write */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wvc1->imc_index_wr++;               /* index of dataset / chunk - write */
   adsl_wvc1->imc_ss_ahead--;               /* swap storage in use     */

   p_cf_se2cl_vc_40:                        /* get new block from swap storage */
   if (adsl_wvc1->imc_ss_ahead >= NO_SS_AHEAD) {  /* number of swap storage ahead */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W input from SMB needs too many buffers achrc_stor_addr_ss",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wvc1->imc_index_re++;               /* index of dataset / chunk - read */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_get_buf;  /* acquire swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wvc1->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wsmb2ss->achc_output = dsl_astr1.achc_stor_addr;  /* output data till here   */
   adsl_wvc1->achrc_stor_addr_ss[ adsl_wvc1->imc_ss_ahead ] = dsl_astr1.achc_stor_addr;  /* storage address */
   if (adsl_wvc1->imc_ss_ahead == 0) {      /* also start virus-checking */
     adsl_wvc1->achc_vc_written = dsl_astr1.achc_stor_addr;  /* address written to virus-checking */
   }
   adsl_wvc1->imc_ss_ahead++;               /* swap storage in use     */
   goto p_cf_se2cl_vc_32;                   /* copy data, if possible  */

   p_cf_se2cl_vc_60:                        /* this chunk has been copied */
   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next output from SMB */
   if (adsl_smbcc_out_w1 == NULL) {         /* end of output reached   */
//   goto p_ret_00;                         /* return                  */
     goto p_smb_out_cmd_80;                 /* SMB output commands processed */
   }
   if (adsl_smbcc_out_w1->iec_smbcc_out != ied_smbcc_out_read) {  /* data read */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB read returned iec_smbcc_out %d.",
                   __LINE__, adsl_smbcc_out_w1->iec_smbcc_out );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   goto p_cf_se2cl_vc_28;                   /* copy content to Swap Storage */

   p_cf_se2cl_vc_80:                        /* copy server to client, e-o-f */
   adsl_cl1->dsc_smbcl_ctrl.adsc_smbcc_in_ch = NULL;
   adsl_wsmb2ss = &adsl_dwa->dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
   adsl_wvc1 = &adsl_wsmb2ss->dsc_wvc1;     /* virus-checking          */
   if (adsl_wvc1->imc_ss_ahead == 0) {      /* swap storage in use     */
#ifdef B141222
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB read nothing read",
                   __LINE__ );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
#endif
//   goto p_cf_se2cl_no_00;                 /* start copy server to client normal */
     goto p_ss2cl_00;                       /* copy from Swap Storage to client */
   }
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_smb2ss_end;             /* read file from server / end */
   adsl_wvc1->iec_vcend = ied_vcend_recv_end;  /* end input received   */
   bol_rc = m_work_vc_end( &dsl_sdh_call_1,
                           adsl_wvc1,       /* virus-checking          */
                           adsl_dwa,        /* all dash operations work area */
                           adsl_wsmb2ss->achc_output,
                           &bol_call_vc );
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   goto p_ret_00;                           /* return                  */

   p_ss2cl_00:                              /* copy from Swap Storage to client */
   if (adsl_cl1->boc_local_notify) {        /* notify local / client is active */
     adsl_cl1->boc_local_notify = FALSE;    /* notify local / client is active */
     adsl_cl1->iec_clst = ied_clst_resp_del_ch_notify_vc;  /* wait for response delete change notify - virus checking */
     goto p_cl_send_del_chnot_00;           /* send delete change notify */
   }
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_changed_local = TRUE;       /* changes local           */
#ifdef B141222
   if (adsl_dwa->boc_virch_server) {        /* virus checking data from server / WSP */
     adsl_wss2cl = &adsl_dwa->dsc_work_ss2cl;  /* copy from Swap Storage to client */
//   adsl_wsmb2ss = &adsl_dwa->dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
#define ADSL_G_WSS2CL ((struct dsd_work_ss2cl *) byrl_work1)
     ADSL_G_WSS2CL->ilc_read_position = adsl_wsmb2ss->ilc_read_position;  /* progress content read from SMB */
     ADSL_G_WSS2CL->vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
     ADSL_G_WSS2CL->imc_index_re = 0;       /* index of dataset / chunk - read */
     *adsl_wss2cl = *ADSL_G_WSS2CL;
#undef ADSL_G_WSS2CL
   }
#endif
   adsl_wss2cl = &adsl_dwa->dsc_work_ss2cl;  /* copy from Swap Storage to client */
   adsl_wsmb2ss = &adsl_dwa->dsc_work_smb2ss;  /* copy from SMB to Swap Storage */
   adsl_wvc1 = &adsl_wsmb2ss->dsc_wvc1;     /* virus-checking          */
#define ADSL_G_WSS2CL ((struct dsd_work_ss2cl *) byrl_work1)
   ADSL_G_WSS2CL->ilc_read_position = adsl_wsmb2ss->ilc_read_position;  /* progress content read from SMB */
   ADSL_G_WSS2CL->vpc_aux_swap_stor_handle = adsl_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   ADSL_G_WSS2CL->imc_index_re = 0;         /* index of dataset / chunk - read */
   *adsl_wss2cl = *ADSL_G_WSS2CL;
#undef ADSL_G_WSS2CL

   /* send start write file to client                                  */
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 4) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
     achl_wc1 = "compressed";
     if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
       achl_wc1 = "un-compressed";
     }
     m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                       "xl-sdh-dash-01-l%05d-I send to client %s file %.*(u8)s",
                       __LINE__, achl_wc1, adsl_dwa->imc_server_pos_fn_end - iml1, &adsl_dwa->byrc_server_fn[ iml1 ] );
   }
   iml1 = adsl_dwa->imc_server_pos_fn_start;
   if (iml1 > 0) iml1++;                    /* after separator         */
#define ADSL_OUT_W dsl_sdh_call_1.achc_lower
   achl_w1 = achl_w2 = ADSL_OUT_W + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_WRITE_FILE;        /* command write file      */
   iml2 = iml3 = (adsl_dwa->imc_server_pos_fn_end - iml1) + 1;  /* length tag + filename */
   do {                                     /* loop to find length     */
     achl_w1++;                             /* space for digit         */
     iml2 >>= 7;                            /* shift bits              */
   } while (iml2 > 0);
   *achl_w1 = 0;                            /* tag                     */
   memcpy( achl_w1 + 1, &adsl_dwa->byrc_server_fn[ iml1 ], adsl_dwa->imc_server_pos_fn_end - iml1 );
   achl_w3 = achl_w1 + 1 + adsl_dwa->imc_server_pos_fn_end - iml1;  /* end of this sub-tag */
   if (adsl_cl1->imc_capabilities & 2) {    /* capabilities client     */
     achl_w4 = achl_w1 + 1;
     while (TRUE) {
       achl_w5 = (char *) memchr( achl_w4, '\\', achl_w3 - achl_w4 );
       if (achl_w5 == NULL) break;
       *achl_w5 = '/';                      /* delimiter Unix          */
       achl_w4 = achl_w5 + 1;
       if (achl_w4 >= achl_w3) break;
     }
   }
// iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w1) = (unsigned char) ((iml3 & 0X7F) | iml2);
     iml3 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml3 > 0);
   *achl_w3++ = 0X02;                       /* length options          */
   *achl_w3++ = 0X01;                       /* sub-tag options         */
   *achl_w3++ = 0X01;                       /* with compression        */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     *(achl_w3 - 1) = 0;                    /* no compression          */
   }
   /* starting with protocol version 2, send size of file              */
   if (adsl_cl1->imc_client_protocol >= 2) {  /* protocol of client    */
     ill_w1 = adsl_a1->adsc_f1_action->ilc_file_size;  /* size of file */
     iml1 = 0;
     do {                                   /* loop to compute length HASN */
       iml1++;
       ill_w1 >>= 7;
     } while (ill_w1 > 0);
#ifdef B170303
     *(achl_w3 - 3) = (unsigned char) (2 + 1 + iml1);  /* length options */
#endif
#ifndef B170303
     *achl_w3++ = (unsigned char) (1 + iml1);  /* length options   */
#endif
     *achl_w3++ = 0X02;                     /* sub-tag length          */
#ifdef B170303
     achl_w4 = achl_w3 + iml1;
#endif
#ifndef B170303
     achl_w3 += iml1;                       /* after length            */
     achl_w4 = achl_w3;                     /* here is end             */
#endif
//   iml3 = 0;                              /* clear more bit          */
     ill_w1 = adsl_a1->adsc_f1_action->ilc_file_size;  /* size of file */
     do {                                     /* output length           */
       *(--achl_w4) = (unsigned char) ((ill_w1 & 0X7F) | iml3);
       ill_w1 >>= 7;                        /* shift bits              */
       iml3 = 0X80;                         /* set more bit            */
     } while (ill_w1 > 0);
     iml3 = 0;                              /* clear more bit          */
   }
   dsl_sdh_call_1.achc_lower = achl_w3;     /* space used till here    */
   iml2 = achl_w3 - achl_w2;                /* length of block         */
// iml3 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* shift bits              */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w3;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140102
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
   aadsl_gai1_ch1 = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather   */
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_OUT_W
#undef ADSL_GAI1_OUT_W
   if (adsl_wsmb2ss->ilc_read_position == 0) {  /* progress content read from SMB */
     goto p_se2cl_end_00;                   /* send file info and end  */
   }
   adsl_cl1->iec_clst = ied_clst_write_file_compressed;  /* write file compressed */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     adsl_cl1->iec_clst = ied_clst_write_file_normal;  /* write file normal */
     adsl_dwa->umc_state |= DWA_STATE_2CL_NORMAL;  /* send to client normal */
//   goto p_ss2cl_20;                       /* copy from something to client */
     goto p_ss2cl_64;                       /* send chunk Swap Storage without compression */
   }
   /* start compression                                                */
   memset( &adsl_wss2cl->dsc_cdf_ctrl, 0, sizeof(struct dsd_cdf_ctrl) );  /* compress data file oriented control */
   adsl_wss2cl->dsc_cdf_ctrl.amc_aux = &m_sub_aux;  /* auxiliary callback routine */
   adsl_wss2cl->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   m_cdf_enc( &adsl_wss2cl->dsc_cdf_ctrl );
   if (adsl_wss2cl->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_cdf_enc() start returned error %d.",
                   __LINE__, adsl_wss2cl->dsc_cdf_ctrl.imc_return );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
#ifdef TRACEHL1
   adsl_cl1->imh_len_inp_compr = 0;
   adsl_cl1->imh_len_out_compr = 0;
#endif
   adsl_dwa->umc_state |= DWA_STATE_2CL_COMPR;  /* send to client compressed */

   p_ss2cl_20:                              /* copy something from SWAP-STOR to client */
   adsl_wss2cl = &adsl_dwa->dsc_work_ss2cl;  /* copy from Swap Storage to client */
   adsl_wss2cl->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
#ifdef B141222
   if (adsl_dwa->boc_virch_server == FALSE) {  /* virus checking data from server / WSP */
   }
#endif
#ifdef XYZ1
   goto p_ss2cl_20;                         /* prepared send chunk Swap Storage */

   p_ss2cl_40:                              /* send next chunk Swap Storage */
   adsl_wss2cl = &adsl_dwa->dsc_work_ss2cl;  /* copy from Swap Storage to client */
   adsl_wss2cl->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
#endif
#ifdef B141222

   p_ss2cl_20:                              /* prepared send chunk Swap Storage */
#endif
   achl_w3 = NULL;                          /* not read chunk Swap Storage */
   iml1 = LEN_BLOCK_SWAP;
   if (((HL_LONGLONG) (adsl_wss2cl->imc_index_re + 1) * (HL_LONGLONG) LEN_BLOCK_SWAP)
         > adsl_wss2cl->ilc_read_position) {  /* progress content read from SMB */
     iml1
       = adsl_wss2cl->ilc_read_position     /* progress content read from SMB */
           - (HL_LONGLONG) adsl_wss2cl->imc_index_re * (HL_LONGLONG) LEN_BLOCK_SWAP;
     if (iml1 <= 0) {                       /* end of file reached     */
//     goto p_ss2cl_40;                     /* end of Swap Storage reached */
       adsl_wss2cl->dsc_cdf_ctrl.boc_eof = TRUE;  /* end of file input */
       adsl_wss2cl->dsc_cdf_ctrl.adsc_gai1_in = NULL;  /* chain of gather - input data */
#ifdef TRACEHL1
       imh_len_compr = 0;
#endif
       goto p_ss2cl_28;                     /* compress chunk Swap Storage */
     }
   }
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_read;      /* read swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2cl->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2cl->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   achl_w3 = dsl_astr1.achc_stor_addr;      /* read chunk Swap Storage */
   dsrl_gai1_work[ 0 ].achc_ginp_cur = dsl_astr1.achc_stor_addr;  /* storage address */
   dsrl_gai1_work[ 0 ].achc_ginp_end = dsl_astr1.achc_stor_addr + iml1;  /* end address */
   dsrl_gai1_work[ 0 ].adsc_next = NULL;
   adsl_wss2cl->dsc_cdf_ctrl.adsc_gai1_in = &dsrl_gai1_work[ 0 ];  /* chain of gather - input data */
   adsl_cdf_ctrl = &adsl_wss2cl->dsc_cdf_ctrl;  /* compress data file oriented control */
#ifdef TRACEHL1
   imh_len_compr = 0;
#endif

   p_ss2cl_28:                              /* compress chunk Swap Storage */
   /* used for Swap Storage and also directly from SMB                 */
#ifdef TRACEHL1
   adsl_gai1_w1 = adsl_cdf_ctrl->adsc_gai1_in;
   iml1 = 0;
   while (adsl_gai1_w1) {
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2cl_28: compression input %d/0X%X output %d/0X%X.",
                 __LINE__, iml1, iml1, imh_len_compr, imh_len_compr );
#ifdef XYZ1
   adsl_cl1->imh_len_compr_in += iml1;
#endif
#endif
   iml1 = dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower
            - MAX_LEN_NHASN - 1 - 1 - sizeof(struct dsd_gather_i_1);
   if (iml1 > 0) {                          /* enough space in work area */
     goto p_ss2cl_40;                       /* space in work area      */
   }

   /* no space in work area, acquire additional work area              */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_aux_get_workarea,
                                    sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   dsl_sdh_call_1.achc_lower = dsl_aux_get_workarea.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;

   p_ss2cl_40:                              /* space in work area      */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_SE2CL_FILE_COMPR;  /* command send file compressed */
   adsl_cdf_ctrl->achc_out_cur = achl_w1;   /* compress data           */
   adsl_cdf_ctrl->achc_out_end = dsl_sdh_call_1.achc_upper;  /* compress data */
   m_cdf_enc( adsl_cdf_ctrl );
#ifdef DEBUG_170209_01                      /* server to client, data at end missing */
   adsl_gai1_w1 = adsl_cdf_ctrl->adsc_gai1_in;
   iml1 = 0;
   while (adsl_gai1_w1) {
     iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2cl_40: remaining compression input %d/0X%X.",
                 __LINE__, iml1, iml1 );
#endif /* DEBUG_170209_01                      server to client, data at end missing */
   if (adsl_cdf_ctrl->imc_return != DEF_IRET_NORMAL) {  /* continue processing */
#ifdef TRACEHL1
// to-do 26.08.13 KB error message
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W compression adsl_cdf_ctrl->imc_return %d.",
                     __LINE__, adsl_cdf_ctrl->imc_return );
#endif
     if (adsl_cdf_ctrl->imc_return != DEF_IRET_END) {  /* subroutine has ended processing */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W compression returned %d - program illogic",
                     __LINE__, adsl_cdf_ctrl->imc_return );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     if (adsl_cdf_ctrl->boc_eof == FALSE) {  /* end of file input      */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W compression returned DEF_IRET_END but boc_eof not set - program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
   }
   if (adsl_cdf_ctrl->achc_out_cur == achl_w1) {  /* no compressed data */
     dsl_sdh_call_1.achc_upper += sizeof(struct dsd_gather_i_1);
     goto p_ss2cl_48;                       /* compression done        */
   }
#ifdef TRACEHL1
   iml1 = adsl_cdf_ctrl->achc_out_cur - achl_w1;  /* length of block   */
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2cl_40: output from compression length %d/0X%X.",
                 __LINE__, iml1, iml1 );
   imh_len_compr += iml1;
   adsl_cl1->imh_len_out_compr += iml1;
#endif
   dsl_sdh_call_1.achc_lower = adsl_cdf_ctrl->achc_out_cur;  /* space used till here */
   iml1 = dsl_sdh_call_1.achc_lower - achl_w2;  /* length of block     */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = dsl_sdh_call_1.achc_lower;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140102
   *aadsl_gai1_ch1 = ADSL_GAI1_OUT_W;
   aadsl_gai1_ch1 = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather   */
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W

   p_ss2cl_48:                              /* compression done        */
#ifdef B141213
   if (   (adsl_cdf_ctrl->imc_return == DEF_IRET_NORMAL)  /* continue processing */
       && (   (adsl_cdf_ctrl->adsc_gai1_in == NULL)  /* chain of gather - input data */
           || (dsrl_gai1_work[ 0 ].achc_ginp_cur < dsrl_gai1_work[ 0 ].achc_ginp_end))) {
     goto p_ss2cl_28;                       /* compress chunk Swap Storage */
   }
#endif
   while (   (adsl_cdf_ctrl->adsc_gai1_in)
          && (adsl_cdf_ctrl->adsc_gai1_in->achc_ginp_cur >= adsl_cdf_ctrl->adsc_gai1_in->achc_ginp_end)) {
     adsl_cdf_ctrl->adsc_gai1_in = adsl_cdf_ctrl->adsc_gai1_in->adsc_next;
   }
#ifdef B170209
   if (   (adsl_cdf_ctrl->imc_return == DEF_IRET_NORMAL)  /* continue processing */
       && (adsl_cdf_ctrl->adsc_gai1_in)) {  /* chain of gather - input data */
     goto p_ss2cl_28;                       /* compress chunk Swap Storage */
   }
#endif
#ifndef B170209
   if (   (adsl_cdf_ctrl->imc_return == DEF_IRET_NORMAL)  /* continue processing */
       && (   (adsl_cdf_ctrl->adsc_gai1_in)  /* chain of gather - input data */
           || (adsl_cdf_ctrl->boc_eof))) {  /* end of file input       */
     goto p_ss2cl_28;                       /* compress chunk Swap Storage */
   }
#endif
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2cl_48: total output compression length %d/0X%X.",
                 __LINE__, imh_len_compr, imh_len_compr );
#endif
#ifdef B141222
   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_02:           /* read file from server / data */
#ifdef B141213
       goto p_smb_out_cmd_read_00;          /* next SMB output command */
#endif
       goto p_smb_out_cmd_80;               /* SMB output commands processed */
     case ied_scs_read_smb2cl_03:           /* read file from server / close */
       goto p_se2cl_end_00;                     /* send file info and end  */
   }
#endif
#ifndef B150108
   switch (adsl_cl1->iec_scs) {             /* state of SMB connection */
     case ied_scs_read_smb2cl_01:           /* read file from server / open */
     case ied_scs_read_smb2cl_02:           /* read file from server / data */
       goto p_smb_out_cmd_80;               /* SMB output commands processed */
     case ied_scs_read_smb2cl_03:           /* read file from server / close */
       goto p_se2cl_end_00;                 /* send file info and end  */
   }
#endif
   if (achl_w3 == NULL) {                   /* not read chunk Swap Storage */
     goto p_ss2cl_80;                       /* complete file sent      */
   }
   if (adsl_wss2cl->ilc_read_position       /* progress content read from SMB */
         <= ((HL_LONGLONG) (adsl_wss2cl->imc_index_re + 1) * (HL_LONGLONG) LEN_BLOCK_SWAP)) {
     goto p_ss2cl_80;                       /* complete file sent      */
   }
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_release;   /* release swap storage chunk */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2cl->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2cl->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wss2cl->imc_index_re++;             /* index of dataset / chunk - read */
   adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;  /* notify SDH when sending to the client is possible */
// return;                                  /* send and wait till sending is possible again */
   goto p_ret_00;                           /* return                  */

//-----------------
   p_ss2cl_60:                              /* chunk Swap Storage without compression sent */
   if (adsp_hl_clib_1->boc_send_client_blocked) {  /* sending to the client is blocked */
     adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;  /* notify SDH when sending to the client is possible */
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ss2cl_60: boc_send_client_blocked",
                   __LINE__ );
#endif
     goto p_ret_00;                         /* return                  */
   }
   adsl_wss2cl = &adsl_dwa->dsc_work_ss2cl;  /* copy from Swap Storage to client */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_release;   /* release swap storage chunk */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2cl->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2cl->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_wss2cl->imc_index_re++;             /* index of dataset / chunk - read */

   p_ss2cl_64:                              /* send chunk Swap Storage without compression */
   iml1 = dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower
            - MAX_LEN_NHASN - 1 - 1 - 2 * sizeof(struct dsd_gather_i_1);
   if (iml1 > 0) {                          /* enough space in work area */
     goto p_ss2cl_68;                       /* space in work area      */
   }

   /* no space in work area, acquire additional work area              */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_aux_get_workarea,
                                    sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   dsl_sdh_call_1.achc_lower = dsl_aux_get_workarea.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;

   p_ss2cl_68:                              /* space in work area to send chunk */
   iml1 = LEN_BLOCK_SWAP;
   if (((HL_LONGLONG) (adsl_wss2cl->imc_index_re + 1) * (HL_LONGLONG) LEN_BLOCK_SWAP)
         > adsl_wss2cl->ilc_read_position) {  /* progress content read from SMB */
     iml1
       = adsl_wss2cl->ilc_read_position     /* progress content read from SMB */
           - (HL_LONGLONG) adsl_wss2cl->imc_index_re * (HL_LONGLONG) LEN_BLOCK_SWAP;
     if (iml1 <= 0) {                       /* end of file reached     */
//     adsl_dwa->umc_state &= -1 - DWA_STATE_2CL_NORMAL;  /* state of processing */
//     adsl_a1 = &adsl_dwa->dsc_a1;         /* what action to do       */
       goto p_ss2cl_84;                     /* free swap storage       */
     }
   }
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_read;      /* read swap storage buffer */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2cl->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsl_wss2cl->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   dsl_sdh_call_1.achc_upper -= 2 * sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_SE2CL_FILE_NORMAL;  /* command send file normal*/
   dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
   iml2 = (achl_w1 - achl_w2) + iml1;       /* length of block         */
   iml3 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* shift bits              */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
#define ADSL_GAI1_OUT_1_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper + 1)
#define ADSL_GAI1_OUT_2_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_1_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_1_W->achc_ginp_end = achl_w1;
   ADSL_GAI1_OUT_1_W->adsc_next = ADSL_GAI1_OUT_2_W;
   ADSL_GAI1_OUT_2_W->achc_ginp_cur = dsl_astr1.achc_stor_addr;  /* storage address */
   ADSL_GAI1_OUT_2_W->achc_ginp_end = dsl_astr1.achc_stor_addr + iml1;  /* end address */
   ADSL_GAI1_OUT_2_W->adsc_next = NULL;
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_1_W;  /* output data to client */
// dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_2_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_1_W
#undef ADSL_GAI1_OUT_2_W
   adsp_hl_clib_1->boc_notify_send_client_possible = TRUE;  /* notify SDH when sending to the client is possible */
// return;                                  /* send and wait till sending is possible again */
   goto p_ret_00;                           /* send and wait till sending is possible again */

   p_ss2cl_80:                              /* complete file sent      */
   if (adsl_wss2cl->dsc_cdf_ctrl.imc_return == DEF_IRET_NORMAL) {  /* continue processing */
     adsl_wss2cl->dsc_cdf_ctrl.boc_eof = TRUE;  /* end of file input   */
     adsl_wss2cl->dsc_cdf_ctrl.adsc_gai1_in = NULL;  /* chain of gather - input data */
     adsl_cdf_ctrl = &adsl_wss2cl->dsc_cdf_ctrl;  /* compress data file oriented control */
#ifdef TRACEHL1
   imh_len_compr = 0;
#endif
     goto p_ss2cl_28;                       /* compress chunk Swap Storage */
   }

   p_ss2cl_84:                              /* free swap storage       */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_close;     /* close swap storage      */
   dsl_astr1.vpc_aux_swap_stor_handle = adsl_wss2cl->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                    &dsl_astr1,  /* swap storage request */
                                    sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_dwa->umc_state &= -1 - DWA_STATE_2CL_NORMAL - DWA_STATE_2CL_COMPR;  /* state of processing */
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */

   p_se2cl_end_00:                          /* send file info and end  */
   /* used for copy swap-storage and also copy SMB2 to client          */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_se2cl_end_00: imh_len_inp_compr=%d imh_len_out_compr=%d.",
                 __LINE__, adsl_cl1->imh_len_inp_compr, adsl_cl1->imh_len_out_compr );
#endif
   iml1 = dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower
            - MAX_LEN_NHASN - 1 - 1
            - sizeof(adsl_a1->adsc_f1_action->dsc_last_write_time)
            - sizeof(adsl_a1->adsc_f1_action->dwc_file_attributes)
            - sizeof(struct dsd_gather_i_1);
   if (iml1 >= 0) {                         /* enough space in work area */
     goto p_se2cl_end_20;                   /* space in work area      */
   }

   /* no space in work area, acquire additional work area              */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_aux_get_workarea,
                                    sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* aux returned error      */
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   dsl_sdh_call_1.achc_lower = dsl_aux_get_workarea.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;

   p_se2cl_end_20:                          /* space in work area      */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_SE2CL_FILE_INFO;   /* command file info and end */
   if ((adsl_cl1->imc_capabilities & 2) == 0) {  /* capabilities client */
     memcpy( achl_w1,
             &adsl_a1->adsc_f1_action->dsc_last_write_time,
             sizeof(adsl_a1->adsc_f1_action->dsc_last_write_time) );
     achl_w1 += sizeof(adsl_a1->adsc_f1_action->dsc_last_write_time);
     memcpy( achl_w1,
             &adsl_a1->adsc_f1_action->dwc_file_attributes,
             sizeof(adsl_a1->adsc_f1_action->dwc_file_attributes) );
     achl_w1 += sizeof(adsl_a1->adsc_f1_action->dwc_file_attributes);
   } else {                                 /* client is Unix          */
#ifdef B150228
     iml1 = m_unix_file_time( &adsl_a1->adsc_f1_action->dsc_last_write_time );
     /* output little endian                                           */
     *achl_w1++ = (unsigned char) iml1;
     *achl_w1++ = (unsigned char) (iml1 >> 8);
     *achl_w1++ = (unsigned char) (iml1 >> 16);
     *achl_w1++ = (unsigned char) (iml1 >> 24);
#endif
     m_get_le8( &ill_w1, (char *) &adsl_a1->adsc_f1_action->dsc_last_write_time );
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_se2cl_end_20: -1- ill_w1 %lld/0X%llX.",
                   __LINE__, ill_w1, ill_w1 );
#endif
     /* send epoch in microseconds                                     */
     ill_w1 -= TIME_ADJUST;
     ill_w1 /= 10;
#ifdef TRACEHL1
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_se2cl_end_20: -2- ill_w1 %lld/0X%llX.",
                   __LINE__, ill_w1, ill_w1 );
#endif
     /* output little endian                                           */
     *achl_w1++ = (unsigned char) ill_w1;
     *achl_w1++ = (unsigned char) (ill_w1 >> 8);
     *achl_w1++ = (unsigned char) (ill_w1 >> 16);
     *achl_w1++ = (unsigned char) (ill_w1 >> 24);
     *achl_w1++ = (unsigned char) (ill_w1 >> 32);
     *achl_w1++ = (unsigned char) (ill_w1 >> 40);
     *achl_w1++ = (unsigned char) (ill_w1 >> 48);
     *achl_w1++ = (unsigned char) (ill_w1 >> 56);
     memset( achl_w1, 0, sizeof(int) );     /* st_mode                 */
     achl_w1 += sizeof(int);
   }
// dsl_sdh_call_1.achc_lower = achl_w1;
   iml1 = achl_w1 - achl_w2;                /* length of block         */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w1;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140102
   *aadsl_gai1_ch1 = ADSL_GAI1_OUT_W;
// aadsl_gai1_ch1 = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather   */
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
// dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_OUT_W
   if (adsl_dwa->boc_virch_server == FALSE) {  /* virus checking data from server / WSP */
     adsl_wsmb2cl = &adsl_dwa->dsc_work_smb2cl;  /* copy from SMB to client */
     adsl_a1->adsc_f1_action->ilc_file_size  /* size of file           */
       = adsl_wsmb2cl->ilc_read_position;   /* progress content read from SMB */
#ifdef B150207
     adsl_a1->ilc_sum_size_local            /* sum file size client    */
       += adsl_wsmb2cl->ilc_read_position   /* progress content read from SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_local           /* sum file size client    */
       += adsl_wsmb2cl->ilc_read_position   /* progress content read from SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
   } else {                                 /* with virus checking     */
     adsl_a1->adsc_f1_action->ilc_file_size  /* size of file           */
       = adsl_wss2cl->ilc_read_position;    /* progress content read from SMB */
#ifdef B150207
     adsl_a1->ilc_sum_size_local            /* sum file size client    */
       += adsl_wss2cl->ilc_read_position    /* progress content read from SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_local           /* sum file size client    */
       += adsl_wss2cl->ilc_read_position    /* progress content read from SMB */
            - adsl_a1->ilc_size_replaced;   /* size of file that is being replaced */
#endif
   }
   adsl_cl1->iec_clst = ied_clst_resp_write_file;  /* wait for response write file */
#ifdef B150412
   return;
#endif
   goto p_ret_00;                           /* return                  */

   p_cf_se2cl_no_00:                        /* start copy server to client normal */
// adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_changed_local = TRUE;       /* changes local           */
   adsl_wsmb2cl = &adsl_dwa->dsc_work_smb2cl;  /* copy from SMB to client */
#ifdef B141217
   adsl_wsmb2cl->ilc_read_position = 0;     /* progress content received from SMB */
#endif

   /* send start write file to client                                  */
   iml1 = adsl_dwa->imc_server_pos_fn_start;
   if (iml1 > 0) iml1++;                    /* after separator         */
#define ADSL_OUT_W dsl_sdh_call_1.achc_lower
   achl_w1 = achl_w2 = ADSL_OUT_W + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_WRITE_FILE;        /* command write file      */
   iml2 = iml3 = (adsl_dwa->imc_server_pos_fn_end - iml1) + 1;  /* length tag + filename */
   do {                                     /* loop to find length     */
     achl_w1++;                             /* space for digit         */
     iml2 >>= 7;                            /* shift bits              */
   } while (iml2 > 0);
   *achl_w1 = 0;                            /* tag                     */
   memcpy( achl_w1 + 1, &adsl_dwa->byrc_server_fn[ iml1 ], adsl_dwa->imc_server_pos_fn_end - iml1 );
   achl_w3 = achl_w1 + 1 + adsl_dwa->imc_server_pos_fn_end - iml1;  /* end of this sub-tag */
   if (adsl_cl1->imc_capabilities & 2) {    /* capabilities client     */
     achl_w4 = achl_w1 + 1;
     while (TRUE) {
       achl_w5 = (char *) memchr( achl_w4, '\\', achl_w3 - achl_w4 );
       if (achl_w5 == NULL) break;
       *achl_w5 = '/';                      /* delimiter Unix          */
       achl_w4 = achl_w5 + 1;
       if (achl_w4 >= achl_w3) break;
     }
   }
// iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w1) = (unsigned char) ((iml3 & 0X7F) | iml2);
     iml3 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml3 > 0);
   *achl_w3++ = 0X02;                       /* length options          */
   *achl_w3++ = 0X01;                       /* sub-tag options         */
   *achl_w3++ = 0X01;                       /* with compression        */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     *(achl_w3 - 1) = 0;                    /* no compression          */
   }
   dsl_sdh_call_1.achc_lower = achl_w3;     /* space used till here    */
   iml2 = achl_w3 - achl_w2;                /* length of block         */
// iml3 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* shift bits              */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
#ifdef XYZ1
   dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
#endif
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w3;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140102
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
   aadsl_gai1_ch1 = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather   */
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_OUT_W
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_write_file_compressed;  /* write file compressed */
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     adsl_cl1->iec_clst = ied_clst_write_file_normal;  /* write file normal */
   }
#ifdef B141101
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_smb2cl_01;              /* read file from server / open */
   goto p_smb_rec_08;                       /* call SMB component      */

   p_cf_se2cl_no_20:                        /* copy server to client normal, something read */
   adsl_wsmb2cl = &adsl_dwa->dsc_work_smb2cl;  /* copy from SMB to client */
   if (adsl_wsmb2cl->ilc_read_position > 0) {  /* progress content received from SMB */
     goto p_cf_se2cl_no_40;                 /* process what has been read */
   }
#endif
#ifdef XYZ1
#ifndef B141217
   if (adsl_cl1->iec_scs == ied_scs_read_smb2cl_03) {  /* read file from server / close */
     goto p_se2cl_end_00;                       /* send file info and end  */
   }
   if (adsl_smbcc_out_w1 == NULL) {         /* no content              */
     goto p_cf_se2cl_no_00;                 /* start copy server to client normal */
   }
#endif
#endif
#ifndef B141217
   if (adsl_cl1->iec_scs == ied_scs_read_smb2cl_03) {  /* read file from server / close */
     goto p_se2cl_end_00;                   /* send file info and end  */
   }
#endif
#ifndef B150110
   adsl_cl1->iec_scs = ied_scs_read_smb2cl_02;  /* read file from server / data */
#endif
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     goto p_cf_se2cl_no_40;                 /* process what has been read */
   }
   /* start compression                                                */
   memset( &adsl_wsmb2cl->dsc_cdf_ctrl, 0, sizeof(struct dsd_cdf_ctrl) );  /* compress data file oriented control */
   adsl_wsmb2cl->dsc_cdf_ctrl.amc_aux = &m_sub_aux;  /* auxiliary callback routine */
   adsl_wsmb2cl->dsc_cdf_ctrl.vpc_userfld = &dsl_sdh_call_1;  /* User Field Subroutine */
   m_cdf_enc( &adsl_wsmb2cl->dsc_cdf_ctrl );
   if (adsl_wsmb2cl->dsc_cdf_ctrl.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_cdf_enc() start returned error %d.",
                   __LINE__, adsl_wss2cl->dsc_cdf_ctrl.imc_return );
     iml1 = __LINE__;
     goto p_error_int_error;                /* internal error has occured */
   }
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_smb2cl_02;              /* read file from server / data */

   p_cf_se2cl_no_40:                        /* process what has been read */
#ifdef B141213
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
// achl_w1 = ADSL_SOR_G->achc_data;         /* start of data           */
   iml1 = ADSL_SOR_G->imc_length;           /* length of data          */
#undef ADSL_SOR_G
   adsl_wsmb2cl->ilc_read_position += iml1;  /* progress content received from SMB */
// continue 29.01.14 KB
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     goto p_cf_se2cl_no_60;                 /* send data no compression */
   }
// to-do 01.02.14 KB - compression
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
   dsrl_gai1_work[ 0 ].achc_ginp_cur = ADSL_SOR_G->achc_data;
   dsrl_gai1_work[ 0 ].achc_ginp_end = ADSL_SOR_G->achc_data + iml1;  /* end address */
   dsrl_gai1_work[ 0 ].adsc_next = NULL;
#undef ADSL_SOR_G
   adsl_wsmb2cl->dsc_cdf_ctrl.adsc_gai1_in = &dsrl_gai1_work[ 0 ];  /* chain of gather - input data */
   adsl_cdf_ctrl = &adsl_wsmb2cl->dsc_cdf_ctrl;  /* compress data file oriented control */
#ifdef TRACEHL1
   imh_len_compr = 0;
#endif
   goto p_ss2cl_28;                         /* compress chunk Swap Storage */
#endif
#ifdef XYZ1
#ifndef B141217
   if (adsl_smbcc_out_w1 == NULL) {         /* no content              */
   }
#endif
#endif
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
   iml1 = ADSL_SOR_G->imc_length;           /* length of data          */
#undef ADSL_SOR_G
   adsl_wsmb2cl->ilc_read_position += iml1;  /* progress content received from SMB */
// continue 29.01.14 KB
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     goto p_cf_se2cl_no_60;                 /* send data no compression */
   }
   adsl_gai1_w1 = dsrl_gai1_work;           /* copy gather here        */
   iml2 = MAX_INP_GATHER;                   /* number of input gather to be processed */

   p_cf_se2cl_no_44:                        /* process this chunk of data */
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
   adsl_gai1_w1->achc_ginp_cur = ADSL_SOR_G->achc_data;
   adsl_gai1_w1->achc_ginp_end = ADSL_SOR_G->achc_data + iml1;  /* end address */
   adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;
#undef ADSL_SOR_G
#ifdef TRACEHL1
   adsl_cl1->imh_len_inp_compr += iml1;
#endif
   adsl_gai1_w1++;                          /* copy gather here        */
   iml2--;                                  /* number of input gather to be processed */

// p_cf_se2cl_no_48:                        /* process next part input */
   adsl_smbcc_out_w1 = adsl_smbcc_out_w1->adsc_next;  /* get next output from SMB */
   if (adsl_smbcc_out_w1) {                 /* more input data         */
     if (adsl_smbcc_out_w1->iec_smbcc_out != ied_smbcc_out_read) {  /* data read */
// to-do 13.12.14 KB - move to beginning of chain and process later
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB read returned iec_smbcc_out %d.",
                     __LINE__, adsl_smbcc_out_w1->iec_smbcc_out );
       iml1 = __LINE__;
       goto p_abend_00;                     /* abend of program        */
     }
     if (iml2 <= 0) {                       /* too many chunks output  */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W SMB read returned too many chunks of data",
                     __LINE__, adsl_smbcc_out_w1->iec_smbcc_out );
       iml1 = __LINE__;
       goto p_abend_00;                     /* abend of program        */
     }
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
     iml1 = ADSL_SOR_G->imc_length;         /* length of data          */
#undef ADSL_SOR_G
     adsl_wsmb2cl->ilc_read_position += iml1;  /* progress content received from SMB */
     goto p_cf_se2cl_no_44;                 /* process this chunk of data */
   }
   (adsl_gai1_w1 - 1)->adsc_next = NULL;    /* set end of input data   */
   adsl_wsmb2cl->dsc_cdf_ctrl.adsc_gai1_in = &dsrl_gai1_work[ 0 ];  /* chain of gather - input data */
   adsl_cdf_ctrl = &adsl_wsmb2cl->dsc_cdf_ctrl;  /* compress data file oriented control */
#ifdef TRACEHL1
   imh_len_compr = 0;
#endif
   goto p_ss2cl_28;                         /* compress chunk Swap Storage */

   p_cf_se2cl_no_60:                        /* send data no compression */
   if ((dsl_sdh_call_1.achc_upper - dsl_sdh_call_1.achc_lower)
         >= (MAX_LEN_NHASN + 1 + 1 + 2 * sizeof(struct dsd_gather_i_1))) {
     goto p_cf_se2cl_no_68;                 /* space in work area      */
   }

   /* no space in work area, acquire additional work area              */
   memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                    &dsl_aux_get_workarea,
                                    sizeof(struct dsd_aux_get_workarea) );
   if (bol_rc == FALSE) {                   /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   dsl_sdh_call_1.achc_lower = dsl_aux_get_workarea.achc_work_area;
   dsl_sdh_call_1.achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;

   p_cf_se2cl_no_68:                        /* space in work area      */
   dsl_sdh_call_1.achc_upper -= 2 * sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = DASH_DCH_SE2CL_FILE_NORMAL;  /* command send file normal */
   dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
   iml2 = iml1 + 2;                         /* compute length          */
   iml3 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml2 & 0X7F) | iml3);
     iml2 >>= 7;                            /* shift bits              */
     iml3 = 0X80;                           /* set more bit            */
   } while (iml2 > 0);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
#define ADSL_SOR_G ((struct dsd_smbcc_out_read *) (adsl_smbcc_out_w1 + 1))  /* command output SMB2 read */
   (ADSL_GAI1_OUT_W + 1)->achc_ginp_cur = ADSL_SOR_G->achc_data;
   (ADSL_GAI1_OUT_W + 1)->achc_ginp_end = ADSL_SOR_G->achc_data + iml1;
   (ADSL_GAI1_OUT_W + 1)->adsc_next = NULL;
#undef ADSL_SOR_G
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = dsl_sdh_call_1.achc_lower;
   ADSL_GAI1_OUT_W->adsc_next = ADSL_GAI1_OUT_W + 1;
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
// dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &(ADSL_GAI1_OUT_W + 1)->adsc_next;  /* chain of gather */
#undef ADSL_OUT_W
#undef ADSL_GAI1_OUT_W
   goto p_smb_out_cmd_read_00;              /* next SMB output command */

   p_cf_se2cl_no_80:                        /* end of file from SMB    */
#ifdef B150121
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     goto p_se2cl_end_00;                       /* send file info and end  */
   }
#endif
   adsl_wsmb2cl = &adsl_dwa->dsc_work_smb2cl;  /* copy from SMB to client */
   /* check if compression not started                                 */
   if (adsl_wsmb2cl->ilc_read_position == 0) {  /* progress content received from SMB */
#ifdef B141217
     goto p_se2cl_end_00;                       /* send file info and end  */
#endif
     adsl_cl1->iec_scs                      /* state of SMB connection */
       = ied_scs_read_smb2cl_03;            /* read file from server / close */
     goto p_cf_se2cl_no_00;                 /* start copy server to client normal */
   }
#ifndef B150121
   if (adsl_a1->adsc_f1_action->boc_exclude_compression) {  /* <exclude-compression> */
     goto p_se2cl_end_00;                       /* send file info and end  */
   }
#endif
   adsl_cdf_ctrl = &adsl_wsmb2cl->dsc_cdf_ctrl;  /* compress data file oriented control */
   if (adsl_cdf_ctrl->imc_return != DEF_IRET_NORMAL) {  /* not continue processing */
     goto p_se2cl_end_00;                   /* send file info and end  */
   }
   adsl_cdf_ctrl->boc_eof = TRUE;           /* end of file input       */
   adsl_cdf_ctrl->adsc_gai1_in = NULL;      /* chain of gather - input data */
   adsl_cl1->iec_scs                        /* state of SMB connection */
     = ied_scs_read_smb2cl_03;              /* read file from server / close */
#ifdef TRACEHL1
   imh_len_compr = 0;
#endif
   goto p_ss2cl_28;                         /* compress chunk Swap Storage */

   p_misc_se2cl_00:                         /* send miscellaneous command to client */
   if (adsl_cl1->boc_local_notify) {        /* notify local / client is active */
     adsl_cl1->boc_local_notify = FALSE;    /* notify local / client is active */
     adsl_cl1->iec_clst = ied_clst_resp_del_ch_notify_normal;  /* wait for response delete change notify - normal */
     goto p_cl_send_del_chnot_00;           /* send delete change notify */
   }
   adsl_a1->boc_changed_local = TRUE;       /* changes local           */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = dsl_sdh_call_1.achc_lower + MAX_LEN_NHASN;
   *achl_w1++ = 0X01;                       /* channel number          */
   *achl_w1++ = (unsigned char) iml1;       /* command as set          */
   chl1 = '\\';
   if (adsl_cl1->imc_capabilities & 2) {    /* capabilities client     */
     chl1 = '/';                            /* client is Unix          */
   }
   iml1 = m_build_file_name_utf8( &dsl_sdh_call_1, adsl_a1->adsc_f1_action, achl_w1, chl1 );
   achl_w1 += iml1;                         /* after filename          */
// dsl_sdh_call_1.achc_lower = achl_w1;
   iml1 = achl_w1 - achl_w2;                /* length of block         */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
// dsl_sdh_call_1.achc_lower = achl_w1;     /* memory occupied         */
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w1;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
#ifdef B140106
   adsp_hl_clib_1->adsc_gai1_out_to_client = ADSL_GAI1_OUT_W;
#endif
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
#undef ADSL_OUT_W
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_resp_misc;  /* wait for response miscellaneous command */
#ifdef B150412
   return;
#endif
   goto p_ret_00;                           /* return                  */

   p_ask_user_cred_00:                      /* ask user for credentials */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_ask_user_cred_00: adsl_cl1->iec_clst=%d.",
                 __LINE__, adsl_cl1->iec_clst );
#endif
   if (adsl_cl1->imc_client_protocol < 2) {  /* protocol of client     */
     goto p_ask_user_cred_20;               /* client does not support ask user for credentials */
   }
   if (adsl_cl1->iec_scs == ied_scs_start) {  /* start SMB connection  */
     goto p_ask_user_cred_08;               /* connection to SMB server closed */
   }
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_TCP_CLOSE,
                                    NULL,
                                    0 );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   /* consume input - is from server                                   */
   adsl_gai1_w1 = adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv;  /* received from the network */
   while (adsl_gai1_w1) {                   /* loop over all gather input */
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   }

   p_ask_user_cred_08:                      /* connection to SMB server closed */
   dsl_sdh_call_1.achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) dsl_sdh_call_1.achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = (char *) ucrs_dash_send_cred;
   ADSL_GAI1_OUT_W->achc_ginp_end = (char *) ucrs_dash_send_cred + sizeof(ucrs_dash_send_cred);
   ADSL_GAI1_OUT_W->adsc_next = NULL;
   *dsl_sdh_call_1.aadsc_gai1_out_to_client = ADSL_GAI1_OUT_W;  /* output data to client */
   dsl_sdh_call_1.aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* chain of gather */
#undef ADSL_GAI1_OUT_W
   adsl_cl1->iec_clst = ied_clst_resp_cred_1;  /* wait for response credentials */
   bol1 = FALSE;                            /* do not write to log     */
   if (iml_use_log_ls >= 2) {               /* use log-level-share     */
     bol1 = TRUE;                           /* do write to log         */
   }
   if (   (bol1)                            /* write to log            */
       || (adsp_hl_clib_1->imc_trace_level > 0)) {  /* WSP trace level */
     m_sdh_msg_log_tr( &dsl_sdh_call_1, bol1,
                       "xl-sdh-dash-01-l%05d-I command to client: send credentials for SMB server",
                       __LINE__ );
   }
   goto p_ret_00;                           /* return                  */

   p_ask_user_cred_20:                      /* client does not support ask user for credentials */
   m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "l%05d credentials for SMB server invalid - use newer version of the HOBLink DASH client",
                 __LINE__ );
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;

   p_ask_user_cred_40:                      /* process response ask user for credentials */
   if (adsl_cl1->iec_clst != ied_clst_resp_cred_1) {  /* wait for response credentials */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   iml1 = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml_rl );
   if (iml1 < 0) {                          /* not valid length        */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   if (iml1 == 0) {                         /* length field too short  */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received control channel length field NHASN %d too short",
                   __LINE__, iml1 );
     adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
     return;
   }
   iml_rl -= iml1;                          /* decrement length of record */
   if (iml_rl != 0) {                       /* check length of record  */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   iml_st = m_get_input_nhasn( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, &iml1 );
// if (iml_st < 0) {                        /* not valid sub-tag       */
   if (iml_st != 0) {                       /* not expected sub-tag    */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   while (achl_rp >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) {         /* program illogic         */
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-W received data control channel program illogic",
                     __LINE__ );
       adsp_hl_clib_1->inc_return = DEF_IRET_INT_ERROR;  /* internal error occured */
       return;
     }
     achl_rp = adsl_gai1_inp_1->achc_ginp_cur;  /* start scanning here */
   }
   if (iml1 > sizeof(adsl_cl1->chrc_password)) {
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   /* copy content of field                                            */
   bol_rc = m_copy_from_gather( &dsl_sdh_call_1, &adsl_gai1_inp_1, &achl_rp, adsl_cl1->chrc_password, iml1 );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   bol_rc = m_consume_input_gather( &dsl_sdh_call_1, adsp_hl_clib_1->adsc_gather_i_1_in, adsl_gai1_inp_1, achl_rp );
   if (bol_rc == FALSE) {                   /* returned error          */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_illogic;                     /* illogic processing of data received from client */
   }
   if (adsl_gai1_inp_1) {                   /* more input data         */
     iml1 = __LINE__;                       /* set line of error       */
     goto p_cl_inv_dat;                     /* invalid data received from client */
   }
   adsl_cl1->dsc_cm.dsc_ucs_password.ac_str = adsl_cl1->chrc_password;  /* address of string */
   adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str = iml1;  /* length of string in elements */
   adsl_cl1->dsc_cm.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;  /* character set of string */
   adsl_cl1->dsc_smbcl_ctrl.adsc_gai1_nw_recv = NULL;  /* received from the network */
   if (adsl_dwa) {                          /* all dash operations work area */
     adsl_dwa->adsc_gai1_in_from_client = NULL;  /* no input from client */
#ifndef B160115
     adsl_dwa->imc_rl = 0;                  /* remainder record not yet processed */
#endif
   }
   bol_put_cred = TRUE;                     /* put / write credendials */
   goto p_smb_conn_00;                      /* connect to SMB server   */

   p_resync_00:                             /* start resync - something has changed */
#ifdef TRACEHL1
   m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_resync_00: - start resync",
                 __LINE__ );
#endif
   /* bol_resync_lo_re set                                             */
#ifndef B170106
   if (adsl_cl1->ac_work_data) {            /* state of processing     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E adsl_cl1->ac_work_data %p - should not acquire work area",
                   __LINE__, adsl_cl1->ac_work_data );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#endif
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_dwa,  /* all dash operations work area */
                                    sizeof(struct dsd_dash_work_all) );  /* all dash operations work area */
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa->adsc_cf_backlog = NULL;        /* chain copy file backlog */
   adsl_dwa->adsc_cf_bl_cur = NULL;         /* current entry copy file backlog */
#ifdef DEBUG_140823_01
   adsl_dwa->adsc_gai1_in_from_client = NULL;  /* input data from client */
#endif
#ifndef B160115
   adsl_dwa->imc_rl = 0;                    /* remainder record not yet processed */
#endif
#ifndef B170106
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
   adsl_a1->boc_notify_remote = FALSE;      /* notify from server received */
#endif
   adsl_cl1->ac_work_data = adsl_dwa;       /* all dash operations work area */
#ifndef B150129
   adsl_dwa->umc_state = 0;                 /* clear state of processing */
#endif
   if (adsl_cl1->ac_conf_file_control) {    /* configuration of file control */
     memset( &adsl_dwa->dsc_dfcexe, 0, sizeof(struct dsd_dash_fc_execute) );   /* execute DASH file control */
     adsl_dwa->dsc_dfcexe.chc_file_delimiter = '\\';  /* file delimiter */
     adsl_dwa->dsc_dfcexe.ac_conf = adsl_cl1->ac_conf_file_control;  /* configuration of file control */
   }
#ifdef B170106
   adsl_a1 = &adsl_dwa->dsc_a1;             /* what action to do       */
#endif
#ifdef TRACEHL1
   adsl_a1->imc_trace_call = 0;             /* trace call number       */
   adsl_a1->imc_trace_line = 0;             /* line number for tracing */
#endif
   switch (adsl_cl1->dsc_cm.iec_syfu) {     /* synchronize function    */
     case ied_syfu_duplex:                  /* both-directions         */
       adsl_a1->boc_write_server = TRUE;    /* can write to SMB server */
       adsl_a1->boc_write_local = TRUE;     /* can write local         */
       adsl_dwa->boc_virch_local = adsl_conf->boc_virch_local;  /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = adsl_conf->boc_virch_server;  /* virus checking data from server / WSP */
       break;
     case ied_syfu_read_client:             /* read-from-client        */
       adsl_a1->boc_write_server = TRUE;    /* can write to SMB server */
       adsl_a1->boc_write_local = FALSE;    /* can write local         */
       adsl_dwa->boc_virch_local = adsl_conf->boc_virch_local;  /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = FALSE;  /* virus checking data from server / WSP */
       break;
     case ied_syfu_read_server:             /* read-from-server        */
       adsl_a1->boc_write_server = FALSE;   /* can write to SMB server */
       adsl_a1->boc_write_local = TRUE;     /* can write local         */
       adsl_dwa->boc_virch_local = FALSE;   /* virus checking data from local / client */
       adsl_dwa->boc_virch_server = adsl_conf->boc_virch_server;  /* virus checking data from server / WSP */
       break;
     default:
#ifdef NOT_YET_130913
       m_hl1_printf( "xl-sdh-dash-01-l%05d-E dss_cm.iec_syfu invalid function",
                     __LINE__ );
       return -1;
#endif
       m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E dsc_cm.iec_syfu %d invalid function",
                     __LINE__, adsl_cl1->dsc_cm.iec_syfu );
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
       return;
   }
   if (   (adsl_dwa->boc_virch_local == FALSE)  /* virus checking data from local / client */
       && (adsl_dwa->boc_virch_server == FALSE)) {  /* virus checking data from server / WSP */
     goto p_resync_20;                      /* virus-checker o.k.      */
   }
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_open;  /* service open connection */
#ifndef WSP_V24
   dsl_aux_sequ1.ac_service_name = (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred;
   dsl_aux_sequ1.imc_len_service_name = adsl_conf->imc_len_file_vch_serv;
   dsl_aux_sequ1.iec_chs_service_name = ied_chs_utf_8;
#endif
#ifdef WSP_V24
   dsl_aux_sequ1.dsc_ucs_name.ac_str = (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred;
   dsl_aux_sequ1.dsc_ucs_name.imc_len_str = adsl_conf->imc_len_file_vch_serv;
   dsl_aux_sequ1.dsc_ucs_name.iec_chs_str = ied_chs_utf_8;
#endif
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol_rc = dsl_sdh_call_1.amc_aux( dsl_sdh_call_1.vpc_userfld,
                                    DEF_AUX_SERVICE_REQUEST,  /* service request */
                                    &dsl_aux_sequ1,
                                    sizeof(struct dsd_aux_service_query_1) );
   if (bol_rc == FALSE) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   if (dsl_aux_sequ1.iec_ret_service != ied_ret_service_ok) {  /* check service return code */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E Virus Checker Service %.*(u8)s could not be started - error %d.",
                   __LINE__, adsl_conf->imc_len_file_vch_serv, (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred,
                   dsl_aux_sequ1.iec_ret_service );
     if (iml_seml < 9) {                    /* <send-error-messages-level> */
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
     } else {
       m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "xl-sdh-dash-01-l%05d-E Virus Checker Service %.*(u8)s could not be started - error %d.",
                     __LINE__, adsl_conf->imc_len_file_vch_serv, (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc + adsl_conf->imc_len_dir_cred,
                     dsl_aux_sequ1.iec_ret_service );
     }
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_dwa->vpc_sequ_handle = dsl_aux_sequ1.vpc_sequ_handle;  /* handle of service query */

   p_resync_20:                             /* virus-checker o.k.      */
   adsl_dwa->imc_server_pos_fn_start = m_cpy_vx_ucs( adsl_dwa->byrc_server_fn,
                                                     sizeof(adsl_dwa->byrc_server_fn),
                                                     ied_chs_utf_8,  /* Unicode UTF-8 */
                                                     &adsl_cl1->dsc_cm.dsc_ucs_server_dir );  /* server SMB directory */
   if (adsl_dwa->imc_server_pos_fn_start < 0) {
#ifdef NOT_YET_130913
     m_hl1_printf( "xl-sdh-dash-01-l%05d-E could not copy name of SMB server directory",
                   __LINE__ );
     return -1;
#endif
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E could not copy name of SMB server directory",
                   __LINE__ );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
   adsl_a1->adsc_db1_local
     = adsl_a1->adsc_db1_remote
     = adsl_a1->adsc_db1_sync
         = adsl_cl1->adsc_db1_resync;       /* directory block 1 - state for resync */
// adsl_a1->boc_unix_local = FALSE;         /* local is Unix file system */
   if (adsl_cl1->iec_scs == ied_scs_closed) {  /* SMB connection closed */
     adsl_cl1->iec_scs = ied_scs_start;     /* start SMB connection    */
     adsl_cl1->boc_smb_connected = FALSE;   /* connected to SMB server */
     bol_put_cred = FALSE;                  /* put / write credendials */
     goto p_smb_conn_00;                    /* connect to SMB server   */
   }
//#ifdef NOT_NEEDED_140115
   adsl_a1->boc_start = TRUE;               /* start processing        */
//#endif
#ifndef B170106
   if (adsl_dwa->umc_state) {               /* state of processing     */
     m_sdh_printf( &dsl_sdh_call_1, "xl-sdh-dash-01-l%05d-E adsl_dwa->umc_state 0X%X invalid state",
                   __LINE__, adsl_dwa->umc_state );
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return;
   }
#endif
   if (bol_resync_lo_re == FALSE) {         /* TRUE means remote       */
     adsl_dwa->umc_state = DWA_STATE_DIR_CLIENT;  /* state of processing */
     goto p_cl_send_get_all_dir_00;         /* get all directories     */
   }
   adsl_dwa->umc_state = DWA_STATE_DIR_SERVER;  /* state of processing */
   goto p_smb_scan_00;                      /* start directory scanning */

   p_error_received_from_client:            /* invalid data received from client */
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "invalid data received from client line %05d.",
                   iml1 );
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;

   p_error_int_error:                       /* internal error has occured */
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "SDH internal error line %05d.",
                   iml1 );
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_INV_CLIENT_DATA;  /* invalid data from client */
   return;

   p_abend_00:                              /* abend of program        */
   if (iml_seml < 9) {                      /* <send-error-messages-level> */
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, MSG_ERROR_01 );
   } else {
     m_sdh_msg_cl( &dsl_sdh_call_1, 0, DASH_DCH_SE2CL_ERRMSG, "abend server line %05d.",
                   iml1 );
   }
   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
   return;
} /* end m_hlclib01()                                                  */

#define M_BIT_OF( IMP ) (1 << IMP)

/** process the XML configuration                                      */
static BOOL m_proc_xml_conf( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                             struct dsd_clib1_data_1 *adsp_cl1d1_1,
                             char *achp_file, int imp_len_file ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_rc;                       /* return code             */
   int        iml_cmp;                      /* compare values          */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_tab_lx;                   /* index table level one   */
   int        iml_tab_ly;                   /* index table level two   */
   int        iml_l2_flags;                 /* flags level two         */
   BOOL       bol_double_log_ls;            /* double <log-level-share> */
   enum ied_nodetype iel_nt;                /* DOM node type           */
   enum ied_sync_file_type iel_syft;        /* synchronize-file type   */
   char       *achl_error;                  /* error message           */
   void *     al_parser;
   void *     al_node_l0;
   void *     al_node_l1;
   void *     al_node_server;               /* node of SMB-server      */
   void *     al_node_local;                /* node of local           */
   void *     al_node_sync_file;            /* node of synchronize-file */
   void *     al_node_sync_fu;              /* node of synchronize-function */
   void *     al_node_file_ctrl;            /* node of file-control    */
   void *     al_node_l2;
   void *     al_node_l3;
   struct dsd_unicode_string *adsl_ucs_w1;  /* working variable        */
   struct dsd_unicode_string *adsl_ucs_w2;  /* working variable        */
   struct dsd_unicode_string dsl_ucs_l;     /* working variable        */
   union {
     struct dsd_dash_fc_dom_conf dsl_dash_fc_dc;  /* structure DASH file control DOM configuration */
#ifdef XYZ1
     struct dsd_xml_2_mem dsl_xml2mem;      /* convert XML / DOM to memory */
#endif
   };
   struct dsd_xml_parser_cbs dsl_xml_parser_cbs;

   memset( &dsl_xml_parser_cbs, 0, sizeof(struct dsd_xml_parser_cbs) );
   dsl_xml_parser_cbs.avc_usrfld = adsp_sdh_call_1;  /* user field for callbacks */
   dsl_xml_parser_cbs.amc_alloc = &m_sub_alloc;
   dsl_xml_parser_cbs.amc_free = &m_sub_free;

   al_parser = m_new_xml_parser( &dsl_xml_parser_cbs );
   if (al_parser == NULL) {                 /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() m_new_xml_parser() failed",
                   __LINE__ );
     return FALSE;
   }

   al_node_l0 = m_parse_xml( al_parser, achp_file, imp_len_file );
   if (al_node_l0 == NULL) {                   /* error occured           */
     achl_error = m_get_lasterror( al_parser );
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() m_parse_xml() failed %s.",
                   __LINE__, achl_error );
     m_delete_xml_parser( &al_parser );
     return FALSE;
   }
// memset( &adsp_cl1d1_1->dsc_cm, 0, sizeof(struct dsd_conf_main) );  /* configuration */
   adsp_cl1d1_1->dsc_cm.imc_server_echo = -1;  /* server <interval-echo> */
   adsp_cl1d1_1->dsc_cm.imc_seml = -1;      /* <send-error-messages-level> */

   p_l0_00:                                 /* get node level zero     */
   iel_nt = m_get_nodetype( al_node_l0 );
   if (iel_nt != ied_nt_node) {
     al_node_l0 = m_get_nextsibling( al_node_l0 );
     if (al_node_l0) {
       goto p_l0_00;                        /* get node level zero     */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find node level zero",
                   __LINE__ );
     m_delete_xml_parser( &al_parser );
     return FALSE;
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l0 );
   dsl_ucs_l.ac_str = (void *) CONF_NODE_L0;
   dsl_ucs_l.imc_len_str = -1;
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* Unicode UTF-8           */
   bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
   if ((bol_rc == FALSE) || (iml_rc)) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level zero \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     m_delete_xml_parser( &al_parser );
     return FALSE;
   }
   al_node_l1 = m_get_firstchild( al_node_l0 );
   if (al_node_l1 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find node level one",
                   __LINE__ );
     m_delete_xml_parser( &al_parser );
     return FALSE;
   }
   al_node_server = NULL;                   /* node of SMB-server      */
   al_node_local = NULL;                    /* node of local           */
   al_node_sync_file = NULL;                /* node of synchronize-file */
   al_node_sync_fu = NULL;                  /* node of synchronize-function */
   al_node_file_ctrl = NULL;                /* node of file-control    */
   bol_double_log_ls = FALSE;               /* double <log-level-share> */

   p_l1_00:                                 /* get node level one      */
   iel_nt = m_get_nodetype( al_node_l1 );
   if (iel_nt != ied_nt_node) {
     goto p_l1_80;                          /* end of node level one   */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l1 );
   iml_tab_lx = sizeof(achrs_conf_level_1) / sizeof(achrs_conf_level_1[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_level_1[ iml_tab_lx ];
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level one \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_l1_80;                          /* end of node level one   */
   }
   switch (iml_tab_lx) {                    /* node found              */
     case KW_CONF_L1_SERVER:
       if (al_node_server) {                /* node of SMB-server      */
         goto p_l1_60;                      /* node level one double   */
       }
       al_node_server = al_node_l1;         /* node of SMB-server      */
       goto p_l1_80;                        /* end of node level one   */
     case KW_CONF_L1_LOCAL:
       if (al_node_local) {                 /* node of local           */
         goto p_l1_60;                      /* node level one double   */
       }
       al_node_local = al_node_l1;          /* node of local           */
       goto p_l1_80;                        /* end of node level one   */
     case KW_CONF_L1_SYNC_FILE:
       if (al_node_sync_file) {             /* node of synchronize-file */
         goto p_l1_60;                      /* node level one double   */
       }
       al_node_sync_file = al_node_l1;      /* node of synchronize-file */
       goto p_l1_80;                        /* end of node level one   */
     case KW_CONF_L1_SYNC_FN:
       if (al_node_sync_fu) {               /* node of synchronize-function */
         goto p_l1_60;                      /* node level one double   */
       }
       al_node_sync_fu = al_node_l1;        /* node of synchronize-function */
       goto p_l1_80;                        /* end of node level one   */
     case KW_CONF_L1_FILE_CTRL:             /* node of file-control    */
       if (al_node_file_ctrl) {             /* node level one double   */
         goto p_l1_60;                      /* node level one double   */
       }
       al_node_file_ctrl = al_node_l1;      /* node of file-control    */
       goto p_l1_80;                        /* end of node level one   */
     case KW_CONF_L1_SEML:                  /* node of send-error-messages-level */
       if (adsp_cl1d1_1->dsc_cm.imc_seml >= 0) {  /* node level one double */
         goto p_l1_60;                      /* node level one double   */
       }
       goto p_l1_40;                        /* node level one numeric  */
     case KW_CONF_L1_LOG_LS:                /* node of log-level-share */
       if (bol_double_log_ls) {             /* double <log-level-share> */
         goto p_l1_60;                      /* node level one double   */
       }
       goto p_l1_40;                        /* node level one numeric  */
   }
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"%.*s\" illogic",
                 __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
   goto p_ret_error;                        /* return error            */

   p_l1_40:                                 /* node level one numeric  */
   al_node_l2 = m_get_firstchild( al_node_l1 );  /* node of child      */
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two child of \"%(ucs)s\" missing",
                   __LINE__, adsl_ucs_w1 );
     goto p_ret_error;                      /* return error            */
   }

   p_l1_44:                                 /* node level two numeric  */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_text) {
     al_node_l2 = m_get_nextsibling( al_node_l2 );
     if (al_node_l2) {
       goto p_l1_44;                        /* node level two numeric  */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find text level two child of \"%(ucs)s\"",
                   __LINE__, adsl_ucs_w1 );
     goto p_ret_error;                      /* return error            */
   }
   adsl_ucs_w2 = m_get_node_value( al_node_l2 );
   iml1 = m_get_ucs_number( adsl_ucs_w2 );
   if (iml1 < 0) {                          /* returned error          */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() level two child of \"%(ucs)s\" value \"%(ucs)s\" not numeric",
                   __LINE__, adsl_ucs_w1, adsl_ucs_w2 );
     goto p_ret_error;                      /* return error            */
   }
   switch (iml_tab_lx) {                    /* node found              */
     case KW_CONF_L1_SEML:                  /* node of send-error-messages-level */
       adsp_cl1d1_1->dsc_cm.imc_seml = iml1;  /* <send-error-messages-level> */
       break;
     case KW_CONF_L1_LOG_LS:                /* node of log-level-share */
       adsp_cl1d1_1->dsc_cm.imc_log_ls = iml1;  /* <log-level-share>   */
       bol_double_log_ls = TRUE;            /* double <log-level-share> */
       break;
   }
   goto p_l1_80;                            /* end of node level one   */

   p_l1_60:                                 /* node level one double   */
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"%.*s\" double - ignored",
                 __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );

   p_l1_80:                                 /* end of node level one   */
   al_node_l1 = m_get_nextsibling( al_node_l1 );
   if (al_node_l1) {
     goto p_l1_00;                          /* get node level one      */
   }

   if (al_node_server == NULL) {            /* node of SMB-server      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"SMB-server\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (al_node_local == NULL) {             /* node of local           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"local\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (al_node_sync_file == NULL) {         /* node of synchronize-file */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"synchronize-file\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (al_node_sync_fu == NULL) {           /* node of synchronize-function */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level one \"synchronize-function\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   al_node_l2 = m_get_firstchild( al_node_sync_fu );  /* node of synchronize-function */
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two child of \"synchronize-function\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   p_sync_fu_00:                            /* get synchronize-function */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_text) {
     al_node_l2 = m_get_nextsibling( al_node_l2 );
     if (al_node_l2) {
       goto p_sync_fu_00;                   /* get text level two      */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find text level two child of \"synchronize-function\"",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l2 );
   iml_tab_lx = sizeof(achrs_conf_sync_fu_l_2) / sizeof(achrs_conf_sync_fu_l_2[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_sync_fu_l_2[ iml_tab_lx ];
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node \"%.*s\" level two child of \"synchronize-function\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_ret_error;                      /* return error            */
   }
   switch (iml_tab_lx) {                    /* node found              */
     case KW_CONF_L2_SF_DUPLEX:
       adsp_cl1d1_1->dsc_cm.iec_syfu = ied_syfu_duplex;   /* both-directions */
       break;
     case KW_CONF_L2_SF_READ_C:
       adsp_cl1d1_1->dsc_cm.iec_syfu = ied_syfu_read_client;  /* read-from-client */
       break;
     case KW_CONF_L2_SF_READ_S:
       adsp_cl1d1_1->dsc_cm.iec_syfu = ied_syfu_read_server;  /* read-from-server */
       break;
     default:
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two \"%.*s\" illogic",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_ret_error;                    /* return error            */
   }

   al_node_l2 = m_get_firstchild( al_node_server );  /* node of SMB-server */
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two child of \"SMB-server\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   iml_l2_flags = 0;                        /* flags level two         */

   p_server_l2_00:                          /* get SMB-server child    */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_node) {
     goto p_server_l2_40;                   /* get next node SMB-server level two */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l2 );
   iml_tab_lx = sizeof(achrs_conf_server_l_2) / sizeof(achrs_conf_server_l_2[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_server_l_2[ iml_tab_lx ];
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level two \"%.*s\" child of \"SMB-server\" - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_server_l2_40;                   /* get next node SMB-server level two */
   }
   if (iml_l2_flags & M_BIT_OF( iml_tab_lx )) {  /* flags level two    */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two \"%.*s\" child of \"SMB-server\" double - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_server_l2_40;                   /* get next node SMB-server level two */
   }
   al_node_l3 = m_get_firstchild( al_node_l2 );
   if (al_node_l3 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of node level two \"%.*s\" child of \"SMB-server\" missing - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_server_l2_40;                   /* get next node SMB-server level two */
   }

   p_server_l3_00:                          /* get text SMB-server level three */
   iel_nt = m_get_nodetype( al_node_l3 );
   if (iel_nt != ied_nt_text) {
     al_node_l3 = m_get_nextsibling( al_node_l3 );
     if (al_node_l3) {
       goto p_server_l3_00;                 /* get text SMB-server level three */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find text level three node \"%.*s\" child of \"SMB-server\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_ret_error;                      /* return error            */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l3 );
   switch (iml_tab_lx) {                    /* node found              */
     case KW_CONF_L2_SE_SINETA:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_server_ineta = *adsl_ucs_w1;  /* server-ineta */
       break;
     case KW_CONF_L2_SE_SPORT:
       iml1 = m_get_ucs_int( adsl_ucs_w1 );
       if (   (iml1 <= 0)
           || (iml1 >= 0X010000)) {
         m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" node \"serverport\" value \"%.*s\" invalid - ignored",
                       __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
         goto p_server_l2_40;               /* get next node SMB-server level two */
       }
       adsp_cl1d1_1->dsc_cm.imc_server_port = iml1;  /* server-port    */
       break;
     case KW_CONF_L2_SE_SOCRED:             /* sign-on-credentials     */
       goto p_server_l2_20;                 /* node SMB-server sign-on-credentials */
     case KW_CONF_L2_SE_DOMAIN:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_domain = *adsl_ucs_w1;  /* domain  */
       break;
     case KW_CONF_L2_SE_USERID:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_userid = *adsl_ucs_w1;  /* userid  */
       break;
     case KW_CONF_L2_SE_PWD_PL:
       if (iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_PWD_EN )) {  /* flags level two */
         m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" found \"password-plain\" but \"password-encrypted\" defined before - ignored",
                       __LINE__ );
         goto p_server_l2_40;               /* get next node SMB-server level two */
       }
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password = *adsl_ucs_w1;  /* password */
       break;
     case KW_CONF_L2_SE_PWD_EN:
// to-do 26.05.13 KB - base64
       if (iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_PWD_PL )) {  /* flags level two */
         m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" found \"password-encrypted\" but \"password-plain\" defined before - ignored",
                       __LINE__ );
         goto p_server_l2_40;               /* get next node SMB-server level two */
       }
       iml1 = m_get_ucs_base64( &iml2, &iml3,
                                adsp_cl1d1_1->chrc_password, MAX_PASSWORD,
                                adsl_ucs_w1 );
       if (iml1 <= 0) {                     /* nothing found           */
         m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" found \"password-encrypted\" but \"password-encrypted\" base64 error %d position %d in string \"%(ux)s\" - ignored",
                       __LINE__, iml2, iml3, adsl_ucs_w1 );
         goto p_server_l2_40;               /* get next node SMB-server level two */
       }
       bol_rc = m_check_vx( adsp_cl1d1_1->chrc_password, iml1, ied_chs_utf_8 );  /* check Unicode UTF-8 */
       if (bol_rc == FALSE) {               /* not valid               */
         m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" found \"password-encrypted\" but \"password-encrypted\" string \"%(ux)s\" decoded no valid UTF-8 - ignored",
                       __LINE__, adsl_ucs_w1 );
         goto p_server_l2_40;               /* get next node SMB-server level two */
       }
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password.ac_str = adsp_cl1d1_1->chrc_password;  /* address of string */
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password.imc_len_str = iml1;  /* length of string in elements */
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;  /* character set of string */
       break;
     case KW_CONF_L2_SE_WIN_FS:             /* Windows-file-system     */
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "YES", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         adsp_cl1d1_1->dsc_cm.boc_windows_fs = TRUE;  /* is Windows file system */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "NO", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         break;
       }
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"Windows-file-system\" child of \"SMB-server\" value \"%(ucs)s\" neither \"YES\" nor \"NO\" - invalid",
                     __LINE__, adsl_ucs_w1 );
       goto p_server_l2_40;                 /* get next node SMB-server level two */
     case KW_CONF_L2_SE_TREE:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_server_tree = *adsl_ucs_w1;  /* server SMB tree  */
       break;
     case KW_CONF_L2_SE_DIR:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_server_dir = *adsl_ucs_w1;  /* server SMB directory */
       break;
     case KW_CONF_L2_SE_CSD:                /* create-shared-directory */
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "YES", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         adsp_cl1d1_1->dsc_cm.boc_server_create_shared_dir = TRUE;  /* server create shared directory */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "NO", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         break;
       }
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"create-shared-directory\" child of \"SMB-server\" value \"%(ucs)s\" neither \"YES\" nor \"NO\" - invalid",
                     __LINE__, adsl_ucs_w1 );
       goto p_server_l2_40;                 /* get next node SMB-server level two */
     case KW_CONF_L2_SE_TEMP_F:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_server_temp_fn = *adsl_ucs_w1;  /* server SMB temporary file-name */
       break;
     case KW_CONF_L2_SE_D_QUOTA:
       adsp_cl1d1_1->dsc_cm.ilc_quota_server = m_get_ucs_bytes_no( adsl_ucs_w1 );  /* disk quota on SMB server */
       if (adsp_cl1d1_1->dsc_cm.ilc_quota_server > 0) break;  /* value valid */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"disk-quota\" child of \"SMB-server\" value \"%(ucs)s\" invalid",
                     __LINE__, adsl_ucs_w1 );
       adsp_cl1d1_1->dsc_cm.ilc_quota_server = 0;  /* as initialized   */
       goto p_server_l2_40;                 /* get next node SMB-server level two */
     case KW_CONF_L2_SE_AS_ECHO:            /* <always-send-echo>      */
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "YES", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         adsp_cl1d1_1->dsc_cm.boc_server_always_echo = TRUE;  /* server <always-send-echo> */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "NO", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         break;
       }
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"always-send-echo\" child of \"SMB-server\" value \"%(ucs)s\" neither \"YES\" nor \"NO\" - invalid",
                     __LINE__, adsl_ucs_w1 );
       goto p_server_l2_40;                 /* get next node SMB-server level two */
     case KW_CONF_L2_SE_INTV_ECHO:          /* <interval-echo>         */
       adsp_cl1d1_1->dsc_cm.imc_server_echo = m_get_ucs_number( adsl_ucs_w1 );  /* server <interval-echo> */
       if (adsp_cl1d1_1->dsc_cm.imc_server_echo >= 0) break;  /* value valid */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"interval-echo\" child of \"SMB-server\" value \"%(ucs)s\" invalid",
                     __LINE__, adsl_ucs_w1 );
       adsp_cl1d1_1->dsc_cm.imc_server_echo = -1;  /* as initialized   */
       goto p_server_l2_40;                 /* get next node SMB-server level two */
   }
   goto p_server_l2_32;                     /* node SMB-server valid   */

   p_server_l2_20:                          /* node SMB-server sign-on-credentials */
   iml_tab_ly = sizeof(dsrs_conf_s2at_type_tab) / sizeof(dsrs_conf_s2at_type_tab[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) dsrs_conf_s2at_type_tab[ iml_tab_ly ].achc_name;
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_ly--;                          /* decrement index         */
   } while (iml_tab_ly >= 0);
   if (iml_tab_ly < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"sign-on-credentials\" child of \"SMB-server\" value \"%(ucs)s\" - invalid",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_server_l2_40;                   /* get next node SMB-server level two */
   }
   adsp_cl1d1_1->dsc_cm.iec_s2at = dsrs_conf_s2at_type_tab[ iml_tab_ly ].iec_s2at;  /* SMB2 authentication type */

   p_server_l2_32:                          /* node SMB-server valid   */
   iml_l2_flags |= M_BIT_OF( iml_tab_lx );  /* flags level two         */

   p_server_l2_40:                          /* get next node SMB-server level two */
   al_node_l2 = m_get_nextsibling( al_node_l2 );
   if (al_node_l2) {
     goto p_server_l2_00;                   /* get SMB-server child    */
   }
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_SINETA )) == 0) {  /* serverineta */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"serverineta\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_SPORT )) == 0) {  /* serverport */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"serverport\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   if (adsp_cl1d1_1->dsc_cm.iec_s2at == ied_s2at_cred_cache) {  /* single sign on with WSP credentials */
     if (iml_l2_flags & (M_BIT_OF( KW_CONF_L2_SE_PWD_PL ) | M_BIT_OF( KW_CONF_L2_SE_PWD_EN ))) {  /* password */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" node \"sign-on-credentials\" value \"credential-cache\" but password configured - ignored",
                     __LINE__ );
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password.imc_len_str = 0;  /* length of password in elements */
     }
     goto p_server_l2_60;                   /* sign-on-credentials valid */
   }
   if (adsp_cl1d1_1->dsc_cm.iec_s2at == ied_s2at_krb5) {  /* Kerberos 5 */
     if (iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_DOMAIN )) {  /* domain */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" node \"sign-on-credentials\" value \"Kerberos-5\" but domain configured - ignored",
                     __LINE__ );
       adsp_cl1d1_1->dsc_cm.dsc_ucs_domain.imc_len_str = 0;  /* length of domain in elements */
     }
     if (iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_USERID )) {  /* userid */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" node \"sign-on-credentials\" value \"Kerberos-5\" but userid configured - ignored",
                     __LINE__ );
       adsp_cl1d1_1->dsc_cm.dsc_ucs_userid.imc_len_str = 0;  /* length of userid in elements */
     }
     if (iml_l2_flags & (M_BIT_OF( KW_CONF_L2_SE_PWD_PL ) | M_BIT_OF( KW_CONF_L2_SE_PWD_EN ))) {  /* password */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of \"SMB-server\" node \"sign-on-credentials\" value \"Kerberos-5\" but password configured - ignored",
                     __LINE__ );
       adsp_cl1d1_1->dsc_cm.dsc_ucs_password.imc_len_str = 0;  /* length of password in elements */
     }
     goto p_server_l2_60;                   /* sign-on-credentials valid */
   }

   if (adsp_cl1d1_1->dsc_cm.iec_s2at == ied_s2at_ask_user_pwd) {  /* ask user for password */
     goto p_server_l2_60;                   /* sign-on-credentials valid */
   }

   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_DOMAIN )) == 0) {  /* domain */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"domain\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_USERID )) == 0) {  /* userid */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"userid\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if ((iml_l2_flags & (M_BIT_OF( KW_CONF_L2_SE_PWD_PL ) | M_BIT_OF( KW_CONF_L2_SE_PWD_EN ))) == 0) {  /* password */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() neither \"password-plain\" nor \"password-encrypted\", child of \"SMB-server\", defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   p_server_l2_60:                          /* sign-on-credentials valid */
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_TREE )) == 0) {  /* SMB-tree-name */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"SMB-tree-name\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_SE_DIR )) == 0) {  /* directory */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"directory\" child of \"SMB-server\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

// p_local_l2_00:                           /* process local child     */
   al_node_l2 = m_get_firstchild( al_node_local );  /* node of local   */
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two child of \"local\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   iml_l2_flags = 0;                        /* flags level two         */

   p_local_l2_20:                           /* get local child         */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_node) {
     goto p_local_l2_40;                    /* get next node local level two */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l2 );
   iml_tab_lx = sizeof(achrs_conf_local_l_2) / sizeof(achrs_conf_local_l_2[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_local_l_2[ iml_tab_lx ];
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level two \"%.*s\" child of \"local\" - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_local_l2_40;                    /* get next node local level two */
   }
   if (iml_l2_flags & M_BIT_OF( iml_tab_lx )) {  /* flags level two    */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two \"%.*s\" child of \"local\" double - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_local_l2_40;                    /* get next node local level two */
   }
   al_node_l3 = m_get_firstchild( al_node_l2 );
   if (al_node_l3 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of node level two \"%.*s\" child of \"local\" missing - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_local_l2_40;                    /* get next node local level two */
   }

   p_local_l3_00:                           /* get text local level three */
   iel_nt = m_get_nodetype( al_node_l3 );
   if (iel_nt != ied_nt_text) {
     al_node_l3 = m_get_nextsibling( al_node_l3 );
     if (al_node_l3) {
       goto p_local_l3_00;                  /* get text local level three */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find text level three node \"%.*s\" child of \"local\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_ret_error;                      /* return error            */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l3 );
   switch (iml_tab_lx) {                    /* node found              */
#ifdef XYZ1
     case KW_CONF_L2_LO_SY_FN:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_sync_fn = *adsl_ucs_w1;  /* synchronize file-name */
       break;
#endif
     case KW_CONF_L2_LO_DIR:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_local_dir = *adsl_ucs_w1;  /* local directory */
       break;
     case KW_CONF_L2_LO_CSD:                /* create-shared-directory */
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "YES", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         adsp_cl1d1_1->dsc_cm.boc_local_create_shared_dir = TRUE;  /* local create shared directory */
         break;
       }
       bol_rc = m_cmp_vx_vx( &iml_cmp,
                             adsl_ucs_w1->ac_str,
                             adsl_ucs_w1->imc_len_str,
                             adsl_ucs_w1->iec_chs_str,  /* character set of string */
                             "NO", -1, ied_chs_utf_8 );  /* character set of string */
       if ((bol_rc) && (iml_cmp == 0)) {    /* string do compare       */
         break;
       }
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"create-shared-directory\" child of \"local\" value \"%(ucs)s\" neither \"YES\" nor \"NO\" - invalid",
                     __LINE__, adsl_ucs_w1 );
       goto p_local_l2_40;                  /* get next node local level two */
     case KW_CONF_L2_LO_TEMP_F:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_local_temp_fn = *adsl_ucs_w1;  /* local temporary file-name */
       break;
     case KW_CONF_L2_LO_D_QUOTA:
// to-do 01.04.14 KB - number
       adsp_cl1d1_1->dsc_cm.ilc_quota_local = m_get_ucs_bytes_no( adsl_ucs_w1 );  /* disk quota on client */
       if (adsp_cl1d1_1->dsc_cm.ilc_quota_local > 0) break;  /* value valid */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"disk-quota\" child of \"local\" value \"%(ucs)s\" invalid",
                     __LINE__, adsl_ucs_w1 );
       adsp_cl1d1_1->dsc_cm.ilc_quota_local = 0;  /* as initialized    */
       goto p_local_l2_40;                  /* get next node local level two */
     case KW_CONF_L2_LO_KEEP_A:             /* local <time-keepalive>  */
       adsp_cl1d1_1->dsc_cm.imc_local_keepalive = m_get_ucs_number( adsl_ucs_w1 );  /* local <time-keepalive> */
       if (adsp_cl1d1_1->dsc_cm.imc_local_keepalive > 0) break;  /* value valid */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"time-keepalive\" child of \"local\" value \"%(ucs)s\" invalid",
                     __LINE__, adsl_ucs_w1 );
       adsp_cl1d1_1->dsc_cm.imc_local_keepalive = 0;  /* as initialized */
       goto p_local_l2_40;                  /* get next node local level two */
   }
   iml_l2_flags |= M_BIT_OF( iml_tab_lx );  /* flags level two         */

   p_local_l2_40:                           /* get next node local level two */
   al_node_l2 = m_get_nextsibling( al_node_l2 );
   if (al_node_l2) {
     goto p_local_l2_20;                    /* get local               */
   }
#ifdef XYZ1
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_LO_SY_FN )) == 0) {  /* serverineta */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"synchronize-file\" child of \"local\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
#endif
   if ((iml_l2_flags & M_BIT_OF( KW_CONF_L2_LO_DIR )) == 0) {  /* serverineta */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() \"directory\" child of \"local\" not defined",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
// to-do 01.04.14 KB - synchronize-file
//----------------------------
   al_node_l2 = m_get_firstchild( al_node_sync_file );  /* node of synchronize-file */
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two child of \"synchronize-file\" missing",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   iml_l2_flags = 0;                        /* flags level two         */
   iel_syft = ied_syft_invalid;             /* synchronize-file type   */

   p_sync_file_l2_00:                       /* get parameters synchronize-file child */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_node) {
     goto p_sync_file_l2_40;                /* get next node local level two */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l2 );
   iml_tab_lx = sizeof(achrs_conf_sync_f_l_2) / sizeof(achrs_conf_sync_f_l_2[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_sync_f_l_2[ iml_tab_lx ];
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level two \"%.*s\" child of \"synchronize-file\" - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_sync_file_l2_40;                /* get next node local level two */
   }
   if (iml_l2_flags & M_BIT_OF( iml_tab_lx )) {  /* flags level two    */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() node level two \"%.*s\" child of \"synchronize-file\" double - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_local_l2_40;                    /* get next node local level two */
   }
   al_node_l3 = m_get_firstchild( al_node_l2 );
   if (al_node_l3 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() child of node level two \"%.*s\" child of \"synchronize-file\" missing - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_sync_file_l2_40;                /* get next node local level two */
   }

   p_sync_file_l3_00:                       /* get text local level three */
   iel_nt = m_get_nodetype( al_node_l3 );
   if (iel_nt != ied_nt_text) {
     al_node_l3 = m_get_nextsibling( al_node_l3 );
     if (al_node_l3) {
       goto p_sync_file_l3_00;              /* get text local level three */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() did not find text level three node \"%.*s\" child of \"synchronize-file\" \"type\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_ret_error;                      /* return error            */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l3 );
   switch (iml_tab_lx) {                    /* node found              */
     case KW_CONF_L2_SYNCF_TYPE:
       goto p_sync_file_l3_20;              /* found type              */
     case KW_CONF_L2_SYNCF_FN:
       adsp_cl1d1_1->dsc_cm.dsc_ucs_sync_fn = *adsl_ucs_w1;  /* synchronize file-name */
       break;
   }
   goto p_sync_file_l2_40;                  /* get next node local level two */

   p_sync_file_l3_20:                       /* found type              */
   iml_tab_lx = sizeof(dsrs_conf_syncf_type_tab) / sizeof(dsrs_conf_syncf_type_tab[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) dsrs_conf_syncf_type_tab[ iml_tab_lx ].achc_name;
     bol_rc = m_cmp_ucs_ucs( &iml_rc, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_rc == 0)) break;
     iml_tab_lx--;                          /* decrement index         */
   } while (iml_tab_lx >= 0);
   if (iml_tab_lx < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() invalid node level three \"%.*s\" child of \"synchronize-file\" \"type\" - ignored",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_sync_file_l2_40;                /* get next node local level two */
   }
   iel_syft = dsrs_conf_syncf_type_tab[ iml_tab_lx ].iec_syft;  /* synchronize-file type */

   p_sync_file_l2_40:                       /* get next node local level two */
   al_node_l2 = m_get_nextsibling( al_node_l2 );
   if (al_node_l2) {
     goto p_sync_file_l2_00;                /* get parameters synchronize-file child */
   }
   if (iel_syft != ied_syft_local_file_01) {  /* type local-file-01    */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() no \"synchronize-file\" \"local\" not equal \"local-file-01\" - not yet supported",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (adsp_cl1d1_1->dsc_cm.dsc_ucs_sync_fn.imc_len_str == 0) {  /* synchronize file-name */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() no \"synchronize-file\" \"filename\" configured",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   if (al_node_file_ctrl == NULL) {         /* no file-control         */
     goto p_end_00;                         /* end of parsing          */
   }
   memset( &dsl_dash_fc_dc, 0, sizeof(struct dsd_dash_fc_dom_conf) );  /* structure DASH file control DOM configuration */
   dsl_dash_fc_dc.vpc_node_conf = al_node_file_ctrl;  /* part of configuration */
   dsl_dash_fc_dc.amc_aux = m_xml_aux;      /* aux-call routine pointer */
   dsl_dash_fc_dc.vpc_userfld = adsp_sdh_call_1;  /* User Field Subroutine */
   dsl_dash_fc_dc.amc_call_dom = &m_call_xml_dom;  /* call DOM         */
// dsl_dash_fc_dc.aac_conf = &adsp_sdh_call_1->adsc_cl1d1_1->dsc_dfcexe.ac_conf;  /* return data from conf */
   dsl_dash_fc_dc.aac_conf = &adsp_sdh_call_1->adsc_cl1d1_1->ac_conf_file_control;  /* configuration of file control */
//#ifdef XYZ1
   bol_rc = m_dash_file_control_conf( &dsl_dash_fc_dc );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() could not process file-control",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
//#endif
#ifdef XYZ1
   memset( &dsl_xml2mem, 0, sizeof(struct dsd_xml_2_mem) );  /* convert XML / DOM to memory */
   dsl_xml2mem.vpc_node_conf = al_node_file_ctrl;  /* part of configuration */
   dsl_xml2mem.amc_aux = m_xml_aux;         /* aux-call routine pointer */
   dsl_xml2mem.vpc_userfld = adsp_sdh_call_1;  /* User Field Subroutine */
   dsl_xml2mem.amc_call_dom = &m_call_xml_dom;  /* call DOM            */
   bol_rc = m_xml_2_mem( &dsl_xml2mem );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_proc_xml_conf() could not copy file-control to memory",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
#endif

   p_end_00:                                /* end of parsing          */
   m_delete_xml_parser( &al_parser );
#ifdef DEBUG_150302_01                      /* simulate configuration create shared directory */
   adsp_cl1d1_1->dsc_cm.boc_local_create_shared_dir = TRUE;  /* local create shared directory */
   adsp_cl1d1_1->dsc_cm.boc_server_create_shared_dir = TRUE;  /* server create shared directory */
#endif
   return TRUE;

   p_ret_error:                             /* return error            */
   m_delete_xml_parser( &al_parser );
   return FALSE;
} /* end m_proc_xml_conf()                                             */

/** call DOM for XML                                                   */
static void * m_call_xml_dom( void * vpp_userfld, void * vpp_node, ied_hlcldom_def iep_hlcldom_def ) {
#ifdef TRACEHL1
   m_sdh_printf( (struct dsd_sdh_call_1 *) vpp_userfld, "xl-sdh-dash-01-l%05d-T m_call_xml_dom( %p , %p , %d ) called",
                 __LINE__, vpp_userfld, vpp_node, iep_hlcldom_def );
#endif
   switch (iep_hlcldom_def) {               /* which function called   */
     case ied_hlcldom_get_first_child:      /* getFirstChild()         */
       return m_get_firstchild( vpp_node );
     case ied_hlcldom_get_next_sibling:     /* getNextSibling()        */
#ifdef XYZ1
       if (adsp_domnode == dsg_cdaux_control.adsc_node_conf) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPD001W m_call_dom() call getNextSibling( conf ) forbidden" );
         return NULL;
       }
       return adsp_domnode->getNextSibling();
#endif
      return m_get_nextsibling( vpp_node );
     case ied_hlcldom_get_node_type:        /* getNodeType()           */
       return (void *) m_get_nodetype( vpp_node );
     case ied_hlcldom_get_node_value:       /* getNodeValue()          */
       return (void *) m_get_node_value( vpp_node );
     case ied_hlcldom_get_node_name:        /* getNodeName()           */
       return (void *) m_get_node_value( vpp_node );
//     return (void *) adsp_domnode->getNodeName();
#ifdef XYZ1
     case ied_hlcldom_get_file_line:        /* get line in file        */
       return (void *) ((int) GET_LINE( adsp_domnode ));
     case ied_hlcldom_get_file_column:      /* get column in file      */
       return (void *) ((int) GET_COLUMN( adsp_domnode ));
#endif
   }
   return NULL;
} /* end m_call_xml_dom()                                              */

/** auxiliary callback routine for XML parsing                         */
static BOOL m_xml_aux( void * vpp_userfld, int iml_func, void * adsp_param, int imp_length ) {
   return (((struct dsd_sdh_call_1 *) vpp_userfld)->amc_aux)( ((struct dsd_sdh_call_1 *) vpp_userfld)->vpc_userfld,
                                                              iml_func, adsp_param, imp_length );
} /* end m_xml_aux()                                                   */

/** retrieve the stored password                                       */
static int m_get_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                  struct dsd_sdh_ident_set_1 *adsp_g_idset1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_ret;                      /* how to return           */
   int        iml1;                         /* working variable        */
   int        iml_len_fn;                   /* length filename         */
   char       *achl_w1;                     /* working variable        */
   char       *achl_fn_last;                /* last part of file name  */
   struct dsd_clib1_data_1 *adsl_cl1;       /* for addressing          */
   struct dsd_clib1_conf_1 *adsl_conf;      /* structure configuration */
   union {
     struct dsd_aux_file_io_req_1 dsl_fior1;  /* file IO request       */
     struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR      */
   };
   char       byrl_len[ 2 ];                /* length of password      */
   char       byrl_fn[ 2048 ];              /* filename                */

   iml_ret = -1;                            /* how to return           */

   adsl_cl1 = adsp_sdh_call_1->adsc_cl1d1_1;  /* structure session     */
   adsl_conf = adsp_sdh_call_1->adsc_conf;  /* structure configuration */

   iml_len_fn = m_filename_stored_user_pwd( adsp_sdh_call_1, adsp_g_idset1, &achl_fn_last, byrl_fn, byrl_fn + sizeof(byrl_fn) );
   if (iml_len_fn < 0) return -1;

   memset( &dsl_fior1, 0, sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   dsl_fior1.iec_fioc = ied_fioc_compl_file_read;  /* read complete file */
   dsl_fior1.dsc_ucs_file_name.ac_str = byrl_fn;
   dsl_fior1.dsc_ucs_file_name.imc_len_str = iml_len_fn;
   dsl_fior1.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_FILE_IO,  /* file input-output */
                                      &dsl_fior1,
                                      sizeof(struct dsd_aux_file_io_req_1) );
   if (bol_rc == FALSE) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - returned FALSE",
                   __LINE__ );
     return -1;
   }
   if (dsl_fior1.iec_fior == ied_fior_file_not_found) {  /* The system cannot find the file specified. ERROR_FILE_NOT_FOUND */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-I file for user-credentials SMB-server not found",
                   __LINE__ );
     return 1;
   }
   if (dsl_fior1.iec_fior != ied_fior_ok) {  /* o.k.                   */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - iec_dfar_def=%d.",
                   __LINE__, dsl_fior1.iec_fior );
     return -1;
   }
   achl_w1 = (char *) memchr( dsl_fior1.achc_data, CHAR_CR, dsl_fior1.ilc_len_data );
   if (achl_w1 == NULL) {                   /* no carriage-return      */
     goto p_file_inv;                       /* file invalid            */
   }
   iml1 = achl_w1 - dsl_fior1.achc_data;
   if (iml1 == 0) {                         /* eye-cather              */
     goto p_file_inv;                       /* file invalid            */
   }
   if (   (iml1 != sizeof(ucrs_cred_file_eyecatcher))
       || (memcmp( dsl_fior1.achc_data, ucrs_cred_file_eyecatcher, sizeof(ucrs_cred_file_eyecatcher) ))) {
     if (iml1 > 64) iml1 = 64;              /* shorten text            */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W file with credentials content \"%.*(u8)s\" - not expected",
                   __LINE__, iml1, dsl_fior1.achc_data );
     iml_ret = 1;                           /* can ask for new password */
     goto p_ret_00;                         /* all done                */
   }
   if (dsl_fior1.ilc_len_data != (sizeof(ucrs_cred_file_eyecatcher) + sizeof(ucrs_cred_file_separator) + LEN_SECURE_XOR_PWD)) {
     goto p_file_inv;                       /* file invalid            */
   }
   if (memcmp( dsl_fior1.achc_data + sizeof(ucrs_cred_file_eyecatcher), ucrs_cred_file_separator, sizeof(ucrs_cred_file_separator) )) {
     goto p_file_inv;                       /* file invalid            */
   }
#define ACHL_PWD_G (dsl_fior1.achc_data + sizeof(ucrs_cred_file_eyecatcher) + sizeof(ucrs_cred_file_separator))
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
#ifdef B160406
   dsl_asxor1.imc_len_post_key = iml_len_fn;  /* length of post key string */
#endif
   dsl_asxor1.imc_len_post_key = (byrl_fn + iml_len_fn) - achl_fn_last;  /* length of post key string */
   dsl_asxor1.imc_len_xor = 2;              /* length of string        */
#ifdef B160406
   dsl_asxor1.achc_post_key = byrl_fn;      /* address of post key string */
#endif
   dsl_asxor1.achc_post_key = achl_fn_last;  /* address of post key string */
   dsl_asxor1.achc_source = ACHL_PWD_G;     /* address of source       */
   dsl_asxor1.achc_destination = byrl_len;  /* address of destination  */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                      &dsl_asxor1,
                                      sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     goto p_file_inv;                       /* file invalid            */
   }
   iml1 = *((unsigned char *) byrl_len + 0) << 8
            | *((unsigned char *) byrl_len + 1);
   if (   (iml1 == 0)
       || (iml1 > (LEN_SECURE_XOR_PWD - 2))
       || (iml1 > sizeof(adsl_cl1->chrc_password))) {
     goto p_file_inv;                       /* file invalid            */
   }
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
#ifdef B160406
   dsl_asxor1.imc_len_post_key = iml_len_fn;  /* length of post key string */
#endif
   dsl_asxor1.imc_len_post_key = (byrl_fn + iml_len_fn) - achl_fn_last;  /* length of post key string */
   dsl_asxor1.imc_len_xor = iml1;           /* length of string        */
#ifdef B160406
   dsl_asxor1.achc_post_key = byrl_fn;      /* address of post key string */
#endif
   dsl_asxor1.achc_post_key = achl_fn_last;  /* address of post key string */
   dsl_asxor1.achc_source = ACHL_PWD_G + 2;  /* address of source      */
   dsl_asxor1.achc_destination = adsl_cl1->chrc_password;  /* address of destination */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                      &dsl_asxor1,
                                      sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     goto p_file_inv;                       /* file invalid            */
   }
#undef ACHL_PWD_G
   adsl_cl1->dsc_cm.dsc_ucs_password.ac_str = adsl_cl1->chrc_password;  /* address of string */
   adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str = iml1;  /* length of string in elements */
   adsl_cl1->dsc_cm.dsc_ucs_password.iec_chs_str = ied_chs_utf_8;  /* character set of string */

   if (adsl_cl1->dsc_cm.dsc_ucs_domain.imc_len_str == 0) {  /* length of domain in elements */
     adsl_cl1->dsc_cm.dsc_ucs_domain = adsp_g_idset1->dsc_user_group;
   }
   if (adsl_cl1->dsc_cm.dsc_ucs_userid.imc_len_str == 0) {  /* length of userid in elements */
     adsl_cl1->dsc_cm.dsc_ucs_userid = adsp_g_idset1->dsc_userid;
   }
   iml_ret = 0;                             /* password decrypted      */
   goto p_ret_00;                           /* all done                */

   p_file_inv:                              /* file invalid            */
   iml_ret = 1;                             /* can ask for new password */
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W file with credentials has invalid content",
                 __LINE__ );

   p_ret_00:                                /* all done                */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_MEMFREE,
                                      &dsl_fior1.achc_data,
                                      dsl_fior1.ilc_len_data );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_MEMFREE failed - returned FALSE",
                   __LINE__ );
     return -1;
   }
   return iml_ret;                          /* succeeded               */
} /* end m_get_stored_user_pwd()                                       */

/** store the new password                                             */
static BOOL m_put_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   int        iml_len_fn;                   /* length filename         */
   struct dsd_clib1_data_1 *adsl_cl1;       /* for addressing          */
// struct dsd_clib1_conf_1 *adsl_conf;      /* structure configuration */
   char       *achl_w1;                     /* working variable        */
   char       *achl_fn_last;                /* last part of file name  */
   union {
     struct dsd_aux_secure_xor_1 dsl_asxor1;  /* apply secure XOR      */
     struct dsd_sdh_ident_set_1 dsl_g_idset1;  /* settings for given ident */
     struct dsd_aux_file_io_req_1 dsl_fior1;  /* file IO request       */
   };
   struct dsd_gather_i_1 dsrl_gai1_data[ 3 ];  /* content of file      */
   char       byrl_fn[ 2048 ];              /* filename                */
   char       byrl_pwd[ LEN_SECURE_XOR_PWD ];  /* password             */

   adsl_cl1 = adsp_sdh_call_1->adsc_cl1d1_1;  /* structure session     */
// adsl_conf = adsp_sdh_call_1->adsc_conf;  /* structure configuration */

   if (adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str > (LEN_SECURE_XOR_PWD - 2)) {
     return FALSE;
   }

   memset( &dsl_g_idset1, 0, sizeof(struct dsd_sdh_ident_set_1) );
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_GET_IDENT_SETTINGS,  /* return settings of this user */
                                      &dsl_g_idset1,
                                      sizeof(struct dsd_sdh_ident_set_1) );
   if (bol_rc == FALSE) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_GET_IDENT_SETTINGS failed - returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   if (dsl_g_idset1.iec_ret_g_idset1 != ied_ret_g_idset1_ok) {  /* ident known, parameters returned, o.k. */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_GET_IDENT_SETTINGS failed - ident unknown",
                   __LINE__ );
     return FALSE;
   }

   iml_len_fn = m_filename_stored_user_pwd( adsp_sdh_call_1, &dsl_g_idset1, &achl_fn_last, byrl_fn, byrl_fn + sizeof(byrl_fn) );
   if (iml_len_fn <= 0) return FALSE;

   byrl_pwd[ 0 ] = (unsigned char) (adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str << 8);
   byrl_pwd[ 1 ] = (unsigned char) adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str;
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
#ifdef B160406
   dsl_asxor1.imc_len_post_key = iml_len_fn;  /* length of post key string */
#endif
   dsl_asxor1.imc_len_post_key = (byrl_fn + iml_len_fn) - achl_fn_last;  /* length of post key string */
   dsl_asxor1.imc_len_xor = 2;              /* length of string        */
#ifdef B160406
   dsl_asxor1.achc_post_key = byrl_fn;      /* address of post key string */
#endif
   dsl_asxor1.achc_post_key = achl_fn_last;  /* address of post key string */
   dsl_asxor1.achc_source = byrl_pwd;       /* address of source       */
   dsl_asxor1.achc_destination = byrl_pwd;  /* address of destination  */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                      &dsl_asxor1,
                                      sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }

#ifdef B151221
   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
   dsl_asxor1.imc_len_post_key = iml_len_fn;  /* length of post key string */
   dsl_asxor1.imc_len_xor = adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str;  /* length of string */
   dsl_asxor1.achc_post_key = byrl_fn;      /* address of post key string */
   dsl_asxor1.achc_source = (char *) adsl_cl1->dsc_cm.dsc_ucs_password.ac_str;  /* address of source */
   dsl_asxor1.achc_destination = byrl_pwd + 2;  /* address of destination  */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                      &dsl_asxor1,
                                      sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str >= (LEN_SECURE_XOR_PWD - 2)) {
     goto p_put_20;                         /* continue put            */
   }
   /* fill remaining area with random                                  */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_RANDOM_RAW,  /* calcalute random */
                                      byrl_pwd + 2 + adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str,
                                      LEN_SECURE_XOR_PWD - 2 - adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str );
   if (bol_rc == FALSE) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_RANDOM_RAW failed - returned FALSE",
                   __LINE__ );
     return FALSE;
   }

   p_put_20:                                /* continue put            */
#endif
   /* fill area with repeated password                                 */
   achl_w1 = byrl_pwd + 2;
   do {
     iml1 = adsl_cl1->dsc_cm.dsc_ucs_password.imc_len_str;
     if (iml1 > ((byrl_pwd + sizeof(byrl_pwd)) - achl_w1)) {
       iml1 = (byrl_pwd + sizeof(byrl_pwd)) - achl_w1;
     }
     memcpy( achl_w1,
             adsl_cl1->dsc_cm.dsc_ucs_password.ac_str,  /* address of source */
             iml1 );
     achl_w1 += iml1;
   } while (achl_w1 < (byrl_pwd + sizeof(byrl_pwd)));

   memset( &dsl_asxor1, 0, sizeof(struct dsd_aux_secure_xor_1) );  /* apply secure XOR */
#ifdef B160406
   dsl_asxor1.imc_len_post_key = iml_len_fn;  /* length of post key string */
#endif
   dsl_asxor1.imc_len_post_key = (byrl_fn + iml_len_fn) - achl_fn_last;  /* length of post key string */
   dsl_asxor1.imc_len_xor = sizeof(byrl_pwd) - 2;  /* length of string */
#ifdef B160406
   dsl_asxor1.achc_post_key = byrl_fn;      /* address of post key string */
#endif
   dsl_asxor1.achc_post_key = achl_fn_last;  /* address of post key string */
   dsl_asxor1.achc_source = byrl_pwd + 2;   /* address of source       */
   dsl_asxor1.achc_destination = byrl_pwd + 2;  /* address of destination */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_SECURE_XOR,  /* apply secure XOR */
                                      &dsl_asxor1,
                                      sizeof(struct dsd_aux_secure_xor_1) );
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T aux-call() DEF_AUX_SECURE_XOR returned %d.",
                 __LINE__, bol_rc );
#endif
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   /* write content to disk file                                       */
   dsrl_gai1_data[ 0 ].achc_ginp_cur = (char *) ucrs_cred_file_eyecatcher;
   dsrl_gai1_data[ 0 ].achc_ginp_end = (char *) ucrs_cred_file_eyecatcher + sizeof(ucrs_cred_file_eyecatcher);
   dsrl_gai1_data[ 0 ].adsc_next = &dsrl_gai1_data[ 1 ];
   dsrl_gai1_data[ 1 ].achc_ginp_cur = (char *) ucrs_cred_file_separator;
   dsrl_gai1_data[ 1 ].achc_ginp_end = (char *) ucrs_cred_file_separator + sizeof(ucrs_cred_file_separator);
   dsrl_gai1_data[ 1 ].adsc_next = &dsrl_gai1_data[ 2 ];
   dsrl_gai1_data[ 2 ].achc_ginp_cur = byrl_pwd;
   dsrl_gai1_data[ 2 ].achc_ginp_end = byrl_pwd + LEN_SECURE_XOR_PWD;
   dsrl_gai1_data[ 2 ].adsc_next = NULL;

   memset( &dsl_fior1, 0, sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   dsl_fior1.iec_fioc = ied_fioc_compl_file_write;  /* write complete file */
   dsl_fior1.dsc_ucs_file_name.ac_str = byrl_fn;
   dsl_fior1.dsc_ucs_file_name.imc_len_str = iml_len_fn;
   dsl_fior1.dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
   dsl_fior1.adsc_gai1_data = dsrl_gai1_data;  /* input and output data */
   bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                      DEF_AUX_FILE_IO,  /* file input-output */
                                      &dsl_fior1,
                                      sizeof(struct dsd_aux_file_io_req_1) );
   if (bol_rc == FALSE) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   if (dsl_fior1.iec_fior != ied_fior_ok) {  /* o.k.                   */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_FILE_IO failed - iec_dfar_def=%d.",
                   __LINE__, dsl_fior1.iec_fior );
     return FALSE;
   }
   return TRUE;                             /* all done                */
} /* end m_put_stored_user_pwd()                                       */

/** set the filename for the stored password                           */
static int m_filename_stored_user_pwd( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                       struct dsd_sdh_ident_set_1 *adsp_g_idset1,
                                       char **aachp_fn_last,
                                       char *achp_buf_start, char *achp_buf_end ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   char       *achl_w1, *achl_w2;           /* working variables       */
   struct dsd_clib1_data_1 *adsl_cl1;       /* for addressing          */
   struct dsd_clib1_conf_1 *adsl_conf;      /* structure configuration */

   adsl_cl1 = adsp_sdh_call_1->adsc_cl1d1_1;  /* structure session     */
   adsl_conf = adsp_sdh_call_1->adsc_conf;  /* structure configuration */

   achl_w1 = achp_buf_start;
   if (adsl_conf->imc_len_dir_cred) {       /* length directory name dash-server-credentials */
     if ((adsl_conf->imc_len_dir_cred + 1) > (achp_buf_end - achl_w1)) {
       return -1;
     }
     memcpy( achl_w1, (char *) (adsl_conf + 1) + adsl_conf->imc_len_dir_dpc, adsl_conf->imc_len_dir_cred );
     achl_w1+= adsl_conf->imc_len_dir_dpc;
#ifndef HL_UNIX
     *achl_w1++ = '\\';
#else
     *achl_w1++ = '/';
#endif
   }
   if (sizeof(ucrs_disk_cred_start) > (achp_buf_end - achl_w1)) {
     return -1;
   }
   *aachp_fn_last = achl_w1;
   memcpy( achl_w1, ucrs_disk_cred_start, sizeof(ucrs_disk_cred_start) );
   achl_w1 += sizeof(ucrs_disk_cred_start);
   if (adsp_g_idset1->dsc_user_group.imc_len_str != 0) {
     iml1 = m_cpy_vx_ucs( achl_w1, achp_buf_end - achl_w1, ied_chs_utf_8,
                          &adsp_g_idset1->dsc_user_group );
     if (iml1 <= 0) {
       return -1;
     }
     achl_w1 += iml1;
   }
   if (sizeof(ucrs_disk_separator) > (achp_buf_end - achl_w1)) {
     return -1;
   }
   memcpy( achl_w1, ucrs_disk_separator, sizeof(ucrs_disk_separator) );
   achl_w1 += sizeof(ucrs_disk_separator);
   iml1 = m_cpy_vx_ucs( achl_w1, achp_buf_end - achl_w1, ied_chs_utf_8,
                        &adsp_g_idset1->dsc_userid );
   if (iml1 <= 0) {
     return -1;
   }
   achl_w1 += iml1;
   if (sizeof(ucrs_disk_separator) > (achp_buf_end - achl_w1)) {
     return -1;
   }
   memcpy( achl_w1, ucrs_disk_separator, sizeof(ucrs_disk_separator) );
   achl_w1 += sizeof(ucrs_disk_separator);
   iml1 = m_cpy_vx_ucs( achl_w1, achp_buf_end - achl_w1, ied_chs_utf_8,
                        &adsl_cl1->dsc_cm.dsc_ucs_server_ineta );  /* server-ineta */
   if (iml1 <= 0) {
     return -1;
   }
   achl_w2 = achl_w1;                       /* get start of string     */
   achl_w1 += iml1;                         /* end of string           */
   do {                                     /* loop to replace dots    */
     achl_w2 = (char *) memchr( achl_w2, '.', achl_w1 - achl_w2 );
     if (achl_w2 == NULL) break;
     *achl_w2++ = '-';                      /* replace dot             */
   } while (achl_w2 < achl_w1);
   if ((1 + 1) > (achp_buf_end - achl_w1)) {
     return -1;
   }
   *achl_w1++ = '-';                        /* separator port          */
   iml1 = adsl_cl1->dsc_cm.imc_server_port;  /* server-port            */
   do {                                     /* loop to decode port decimal */
     achl_w1++;                             /* count this digit        */
     iml1 /= 10;                            /* remove digit            */
   } while (iml1 > 0);
   if (achl_w1 > achp_buf_end) {
     return -1;
   }
   iml1 = adsl_cl1->dsc_cm.imc_server_port;  /* server-port            */
   achl_w2 = achl_w1;                       /* get end of number       */
   do {                                     /* loop to decode port decimal */
     *(--achl_w2) = (unsigned char) ((iml1 % 10) + '0');  /* output this digit */
     iml1 /= 10;                            /* remove digit            */
   } while (iml1 > 0);
   if (sizeof(ucrs_disk_cred_end) > (achp_buf_end - achl_w1)) {
     return -1;
   }
   memcpy( achl_w1, ucrs_disk_cred_end, sizeof(ucrs_disk_cred_end) );
   achl_w1 += sizeof(ucrs_disk_dpc_end);
   return achl_w1 - achp_buf_start;
} /* end m_filename_stored_user_pwd()                                  */

#ifdef XYZ1
static BOOL m_xml_2_mem( struct dsd_xml_2_mem *adsp_xml2mem ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_write_end;                /* needs to write end of line */
   int        iml1;                         /* working variable        */
   int        iml_nesting;                  /* counter for nesting     */
   int        iml_len_node;                 /* length of node          */
   enum ied_nodetype iel_nt;                /* DOM node type           */
   void *     al_node_cur;                  /* current node            */
   void *     al_node_child;                /* child of current node   */
   char       *achl_out_cur;                /* current output          */
   char       *achl_w1;                     /* working variable        */
   struct dsd_unicode_string *adsl_ucs_node;  /* node found            */
   struct dsd_unicode_string *adsl_ucs_value;  /* value retrieved      */
   struct dsd_unicode_string *adsl_ucs_end;  /* node to print at end   */
   struct dsd_mem_manage *adsl_mem_m_w1;    /* manage memory           */
   struct dsd_xml_nesting dsrl_xml_n[ MAX_XML_DOM_STACK ];  /* XML / DOM nesting */

   bol_rc = adsp_xml2mem->amc_aux( adsp_xml2mem->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsl_mem_m_w1,
                                   LEN_MEM_BLOCK );
   if (bol_rc == FALSE) {                   /* error occured           */
//   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   achl_out_cur = (char *) (adsl_mem_m_w1 + 1) + sizeof(struct dsd_gather_i_1);  /* current output */
   iml_nesting = 0;                         /* counter for nesting     */
   al_node_cur = adsp_xml2mem->vpc_node_conf;  /* get parent node      */
   adsl_ucs_end = NULL;                     /* node to print at end    */

   p_out_00:                                /* start output of node    */
   iel_nt = (enum ied_nodetype) ((int) adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_node_type ));  /* getNodeType() */
   switch (iel_nt) {                        /* type of node            */
     case ied_nt_node:
       goto p_out_40;                       /* output of node          */
//#ifdef XYZ1
     case ied_nt_text:
       goto p_out_20;                       /* output of text          */
//#endif
   }
   al_node_cur = adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_cur) {                       /* node found              */
     goto p_out_00;                         /* start output of node    */
   }
   return TRUE;

   p_out_20:                                /* output of text          */
   adsl_ucs_value = (struct dsd_unicode_string *) adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_node_value );  /* getNodeValue() */
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        adsl_ucs_value );
// check memory
   m_cpy_vx_ucs( achl_out_cur, 512, ied_chs_utf_8,  /* Unicode UTF-8           */
                 adsl_ucs_value );
   achl_w1 = achl_out_cur;
   while (achl_w1 < (achl_out_cur + iml1)) {
     if (*achl_w1 > 0X20) break;
     achl_w1++;                             /* increment address       */
   }
   if (achl_w1 < (achl_out_cur + iml1)) {
     achl_out_cur += iml1;
// check memory
     memcpy( achl_out_cur, ucrs_node_separator, sizeof(ucrs_node_separator) );
     achl_out_cur += sizeof(ucrs_node_separator);
     m_cpy_vx_ucs( achl_out_cur, 512, ied_chs_utf_8,  /* Unicode UTF-8 */
                   adsl_ucs_node );
     achl_out_cur += iml_len_node;
     *achl_out_cur++ = '>';
     adsl_ucs_end = NULL;                   /* node to print at end    */
     dsrl_xml_n[ iml_nesting - 1 ].adsc_ucs_node = NULL;  /* node to print at end - previous */
     bol_write_end = TRUE;                  /* needs to write end of line */
   }
   if (bol_write_end) {                     /* needs to write end of line */
     memcpy( achl_out_cur, ucrs_node_end, sizeof(ucrs_node_end) );
     achl_out_cur += sizeof(ucrs_node_end);
     bol_write_end = FALSE;                 /* needs to write end of line */
   }
#ifdef XYZ1
   al_node_child = adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_child) {                     /* node found              */
     goto p_out_60;                         /* child found             */
//   al_node_cur = al_node_child;
//   goto p_out_40;                         /* output of node          */
   }
#endif

   p_out_28:                                /* get next sibling        */
   al_node_cur = adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_cur) {                       /* node found              */
     goto p_out_00;                         /* start output of node    */
   }

   p_out_32:                                /* no more sibling         */
   if (adsl_ucs_end) {                      /* node to print at end    */
     iml1 = m_len_vx_ucs( ied_chs_utf_8,    /* Unicode UTF-8           */
                          adsl_ucs_end );
// check memory
     if (iml_nesting > 0) {
       memset( achl_out_cur, ' ', iml_nesting * 2 );
       achl_out_cur += iml_nesting * 2;
     }
     memcpy( achl_out_cur, ucrs_node_separator, sizeof(ucrs_node_separator) );
     achl_out_cur += sizeof(ucrs_node_separator);
     m_cpy_vx_ucs( achl_out_cur, 512, ied_chs_utf_8,  /* Unicode UTF-8   */
                   adsl_ucs_end );
     achl_out_cur += iml1;
     *achl_out_cur++ = '>';
     memcpy( achl_out_cur, ucrs_node_end, sizeof(ucrs_node_end) );
     achl_out_cur += sizeof(ucrs_node_end);
     bol_write_end = FALSE;                 /* needs to write end of line */
   }
   if (iml_nesting == 0) {
     return TRUE;
   }
   iml_nesting--;                           /* upwards                 */
   al_node_cur = dsrl_xml_n[ iml_nesting ].ac_node;  /* node           */
   adsl_ucs_end = dsrl_xml_n[ iml_nesting ].adsc_ucs_node;  /* node to print at end */
   if (iml_nesting > 0) {                   /* still node to process   */
     goto p_out_28;                         /* get next sibling        */
   }
   goto p_out_32;                           /* no more sibling         */

   p_out_40:                                /* output of node          */
   adsl_ucs_node = (struct dsd_unicode_string *) adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_node_name );  /* getNodeName() */
   iml_len_node = m_len_vx_ucs( ied_chs_utf_8,  /* Unicode UTF-8       */
                                adsl_ucs_node );
// check memory
   if (iml_nesting > 0) {
     memset( achl_out_cur, ' ', iml_nesting * 2 );
     achl_out_cur += iml_nesting * 2;
   }
   *achl_out_cur++ = '<';
   m_cpy_vx_ucs( achl_out_cur, 512, ied_chs_utf_8,  /* Unicode UTF-8   */
                 adsl_ucs_node );
   achl_out_cur += iml_len_node;
   *achl_out_cur++ = '>';
   bol_write_end = TRUE;                    /* needs to write end of line */
   al_node_child = adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (al_node_child) {                     /* node found              */
     goto p_out_60;                         /* child found             */
   }
   al_node_cur = adsp_xml2mem->amc_call_dom( adsp_xml2mem->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_cur) {                       /* node found              */
     goto p_out_00;                         /* start output of node    */
   }
   return FALSE;

   p_out_60:                                /* child found             */
// memcpy( achl_out_cur, ucrs_node_end, sizeof(ucrs_node_end) );
// achl_out_cur += sizeof(ucrs_node_end);
   dsrl_xml_n[ iml_nesting ].ac_node = al_node_cur;  /* node           */
   dsrl_xml_n[ iml_nesting ].adsc_ucs_node = adsl_ucs_node;  /* name of node */
   if (adsl_ucs_end) {
     dsrl_xml_n[ iml_nesting ].adsc_ucs_node = adsl_ucs_end;  /* node to print at end */
   }
   iml_nesting++;                           /* counter for nesting     */
   al_node_cur = al_node_child;             /* child is current node   */
   adsl_ucs_end = NULL;                     /* node to print at end    */
   goto p_out_00;                           /* start output of node    */
} /* end m_xml_2_mem()                                                 */
#endif

/** build the file-name from a file entry                              */
static int m_build_file_name_utf8( struct dsd_sdh_call_1 *adsp_sdh_call_1, struct dsd_file_1 *adsp_f1, char *achp_server_fn, char chp_separator ) {
   int        iml_nesting;                  /* nesting of directories  */
   int        iml_pos_fn_end;               /* position end of file name */
   int        iml1;                         /* working variable        */
   struct dsd_file_1 *adsl_f1_dir;          /* entry of a single file  */

   iml_nesting = 0;                         /* nesting of directories  */
   adsl_f1_dir = adsp_f1;                   /* get inner entry         */
   while (adsl_f1_dir->adsc_file_1_parent) {  /* entry of parent directory */
     adsl_f1_dir = adsl_f1_dir->adsc_file_1_parent;  /* get entry of parent directory */
     iml_nesting++;                         /* nesting of directories  */
   }
   iml_pos_fn_end = 0;                      /* position end of file name */

   p_cxd_fn:                                /* output of directory or file name */
   adsl_f1_dir = adsp_f1;                   /* get inner entry         */
   iml1 = iml_nesting;                      /* nesting of directories  */
   while (iml1 > 0) {                       /* need to get parent directory */
     adsl_f1_dir = adsl_f1_dir->adsc_file_1_parent;  /* get entry of parent directory */
     iml1--;                                /* nesting of directories  */
   }
   if ((iml_pos_fn_end + adsl_f1_dir->dsc_ucs_file.imc_len_str) >= LEN_FILE_NAME) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_build_file_name_utf8() file-name local too long",
                   __LINE__ );
     return -1;
   }
   iml1 = m_cpy_vx_ucs( achp_server_fn + iml_pos_fn_end,
                        LEN_FILE_NAME - iml_pos_fn_end,
                        ied_chs_utf_8,      /* Unicode UTF-8           */
                        &adsl_f1_dir->dsc_ucs_file );
   if (iml1 <= 0) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_build_file_name_utf8() file-name server too long",
                   __LINE__ );
     return -1;
   }
   iml_pos_fn_end += iml1;
   if (iml_nesting > 0) {                   /* nesting of directories  */
     iml_nesting--;                         /* nesting of directories  */
#ifdef WAS_B130917
     achp_server_fn[ iml_pos_fn_end++ ] = '\\';
#endif
     achp_server_fn[ iml_pos_fn_end++ ] = chp_separator;
     goto p_cxd_fn;                         /* output of directory or file name */
   }
// to-do 13.06.13 KB - return TRUE;
   return iml_pos_fn_end;
} /* end m_build_file_name_utf8()                                      */

/** retrieve a numeric field, NHASN                                    */
static int m_get_input_nhasn( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_gather_i_1 **aadsp_gai1_inp_rp,
                              char **aachp_rp,
                              int *aimp_rec_len ) {
   BOOL       bol_done;                     /* scanning has been done  */
   int        iml1;                         /* working variable        */
   int        iml_result;                   /* result of input         */
   int        iml_max_len;                  /* maximum length NHASN    */
   int        iml_save_max_len;             /* save maximum length NHASN */
   char       *achl_rp;                     /* read pointer            */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* gather input read pointer */

   iml_max_len = MAX_LEN_NHASN;             /* maximum length NHASN    */
   if (aimp_rec_len != NULL) {              /* with passed record length */
     iml1 = *aimp_rec_len;                  /* get length passed       */
     if (iml1 < MAX_LEN_NHASN) {            /* check if smaller        */
       iml_max_len = iml1;                  /* maximum length NHASN    */
     }
   }
   iml_save_max_len = iml_max_len;          /* save maximum length NHASN */
   iml_result = 0;                          /* result of input         */
   bol_done = FALSE;                        /* scanning has been done  */
   achl_rp = *aachp_rp;                     /* get passed read pointer */
   adsl_gai1_inp_rp = *aadsp_gai1_inp_rp;   /* gather input read pointer */
#ifndef B150101
   if (adsl_gai1_inp_rp == NULL) {          /* no input data           */
// to-do 27.08.13 KB - error message
     return -1;
   }
#endif

   p_num_20:                                /* process gather          */
   if (achl_rp < adsl_gai1_inp_rp->achc_ginp_end) {  /* valid data found */
     goto p_num_60;                         /* we have valid bytes     */
   }
   adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
   if (adsl_gai1_inp_rp == NULL) {          /* empty received from the network */
     if (bol_done) {                        /* scanning has been done  */
       goto p_num_80;                       /* scanning has been done  */
     }
// to-do 27.08.13 KB - error message
     return -1;
   }
   achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   goto p_num_20;                           /* check gather            */

   p_num_60:                                /* we have valid bytes     */
   if (bol_done) {                          /* scanning has been done  */
     goto p_num_80;                         /* scanning has been done  */
   }
   if (iml_max_len <= 0) {                  /* NHASN too long          */
// to-do 27.08.13 KB - error message
     return -1;
   }
   iml_max_len--;                           /* subtract digit NHASN    */
   iml_result <<= 7;                        /* shift old value         */
   iml_result |= *achl_rp & 0X7F;           /* apply new bits          */
   if (*((signed char *) achl_rp) < 0) {    /* more bit set            */
     achl_rp++;                             /* next input character    */
     goto p_num_20;                         /* process gather          */
   }
   achl_rp++;                               /* next input character    */
   bol_done = TRUE;                         /* scanning has been done  */
   goto p_num_20;                           /* process gather          */

   p_num_80:                                /* scanning has been done  */
   if (aimp_rec_len != NULL) {              /* with passed record length */
     *aimp_rec_len -= iml_save_max_len - iml_max_len;  /* subtract length NHASN */
   }
   *aachp_rp = achl_rp;                     /* set passed read pointer */
   *aadsp_gai1_inp_rp = adsl_gai1_inp_rp;   /* gather input read pointer */
   return iml_result;                       /* return what parsed      */
} /* end m_get_input_nhasn()                                           */

/** copy bytes in gather structures                                    */
static BOOL m_copy_from_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                struct dsd_gather_i_1 **aadsp_gai1_inp_rp,
                                char **aachp_rp,
                                char *achp_target,
                                int imp_len ) {
   int        iml1;                         /* working variable        */
   int        iml_len;                      /* length remaining bytes  */
   char       *achl_target;                 /* address of target       */
   char       *achl_rp;                     /* read pointer            */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* gather input read pointer */

/**
   imp_len should not be zero
*/
   adsl_gai1_inp_rp = *aadsp_gai1_inp_rp;   /* gather input read pointer */
   if (adsl_gai1_inp_rp == NULL) return FALSE;
   iml_len = imp_len;                       /* length remaining bytes  */
   achl_target = achp_target;               /* address of target       */
   achl_rp = *aachp_rp;                     /* get passed read pointer */
   while (TRUE) {                           /* loop over gather input  */
     iml1 = adsl_gai1_inp_rp->achc_ginp_end - achl_rp;  /* length in this gather */
     if (iml1 > 0) {                        /* data found              */
       if (iml1 > iml_len) iml1 = iml_len;
       memcpy( achl_target, achl_rp, iml1 );
       achl_rp += iml1;
       iml_len -= iml1;
       if (iml_len <= 0) break;             /* end of copying          */
       achl_target += iml1;
     }
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* was last gather         */
       return FALSE;
     }
     achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   }
   while (achl_rp >= adsl_gai1_inp_rp->achc_ginp_end) {  /* no more data in this gather */
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) break;   /* was last gather         */
     achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   }
   *aachp_rp = achl_rp;                     /* set passed read pointer */
   *aadsp_gai1_inp_rp = adsl_gai1_inp_rp;   /* gather input read pointer */
   return TRUE;                             /* all done                */
} /* end m_copy_from_gather()                                          */

/** check if number of bytes in input stream                           */
static BOOL m_check_input_complete( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_rp,
                                    char *achp_rp,
                                    int imp_rec_len ) {
   int        iml1;                         /* working variable        */
   int        iml_count;                    /* count remaining bytes   */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* gather input read pointer */
   char       *achl_rp;                     /* read pointer            */

/**
   imp_rec_len should not be zero
*/
   if (adsp_gai1_inp_rp == NULL) return FALSE;
   iml_count = imp_rec_len;                 /* count remaining bytes   */
   adsl_gai1_inp_rp = adsp_gai1_inp_rp;     /* gather input read pointer */
   achl_rp = achp_rp;                       /* read pointer            */
   while (TRUE) {                           /* loop over gather input  */
     iml1 = adsl_gai1_inp_rp->achc_ginp_end - achl_rp;  /* bytes in this gather */
     iml_count -= iml1;                     /* count remaining bytes   */
     if (iml_count <= 0) return TRUE;       /* all content found       */
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* was last gather         */
       return FALSE;
     }
     achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   }
} /* end m_check_input_complete()                                      */

#ifdef XYZ1
/** consume input from gather                                          */
static BOOL m_consume_input_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                    struct dsd_gather_i_1 **aadsp_gai1_inp_all,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_rp,
                                    char *achp_rp ) {
   while (*aadsp_gai1_inp_all != adsp_gai1_inp_rp) {
     if (*aadsp_gai1_inp_all == NULL) {
       return FALSE;
     }
     (*aadsp_gai1_inp_all)->achc_ginp_cur = (*aadsp_gai1_inp_all)->achc_ginp_end;
     *aadsp_gai1_inp_all = (*aadsp_gai1_inp_all)->adsc_next;
   }
   if (adsp_gai1_inp_rp) {                  /* still gather            */
     adsp_gai1_inp_rp->achc_ginp_cur = achp_rp;
   }
   return TRUE;
} /* end m_consume_input_gather()                                      */
#endif

/** consume input from gather                                          */
static BOOL m_consume_input_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_all,
                                    struct dsd_gather_i_1 *adsp_gai1_inp_rp,
                                    char *achp_rp ) {
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working variable        */

   adsl_gai1_w1 = adsp_gai1_inp_all;        /* get input               */
   while (adsl_gai1_w1 != adsp_gai1_inp_rp) {
     if (adsl_gai1_w1 == NULL) {
       return FALSE;
     }
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   }
   if (adsp_gai1_inp_rp) {                  /* still gather            */
     adsp_gai1_inp_rp->achc_ginp_cur = achp_rp;
   }
   return TRUE;
} /* end m_consume_input_gather()                                      */

/** find the next action to do                                         */
// to-do 24.05.13 KB - adsc_file_1_same_n;   /* chain of entries same name */ not used
#ifdef TO_DO_130525
when on one side, a directory was deleted,
and on the other side, a file in this directory was updated,
the directory cannot be deleted on the first side.
So, thru directory deleting, adsp_a1->imc_dir_delete
gives the level which directories can be deleted;
not below this number.
#endif
static BOOL m_next_action( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                           struct dsd_action_1 *adsp_a1 ) {
   BOOL       bol_rc;                       /* return code             */
#ifdef XYZ1
   BOOL       bol_fn;                       /* file-name generated     */
#endif
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* for compare             */
#ifdef B150206_XXX
   HL_LONGLONG ill_w1;                      /* working variable        */
#endif
#ifndef B150207
   struct dsd_clib1_data_1 *adsl_cl1;       /* for addressing          */
#endif
   struct dsd_file_1 *adsl_f1_w1;           /* entry of a single file  */
#ifdef HELP_DEBUG
   struct dsd_file_1 *adsl_f1s_sync_l;
   struct dsd_file_1 *adsl_f1s_local_l;
   struct dsd_file_1 *adsl_f1s_remote_l;
#endif

#ifndef B150207
   adsl_cl1 = adsp_sdh_call_1->adsc_cl1d1_1;  /* structure session     */
#endif
   if (adsp_a1->boc_start == FALSE) {       /* start processing        */
     goto p_na_norm_00;                     /* normal processing       */
   }
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() adsp_a1->boc_start TRUE",
                 __LINE__ );
#endif
#ifndef B131223
   adsp_a1->adsc_db1_new_start = NULL;      /* directory block 1 - new */
#endif
   adsp_a1->boc_changed_local = FALSE;      /* changes local           */
   adsp_a1->boc_changed_remote = FALSE;     /* changes remote          */
   adsp_a1->boc_changed_sync = FALSE;       /* need to write synchronize file */
   adsp_a1->boc_valid_sync = FALSE;         /* valid AVL-entry sync    */
   if (adsp_a1->adsc_db1_sync == NULL) {    /* no table sync available */
     adsp_a1->boc_valid_sync = TRUE;        /* valid AVL-entry sync    */
     adsp_a1->dsc_htree1_work_sync.adsc_found = NULL;  /* not found in tree */
   }
   adsp_a1->boc_valid_local = FALSE;        /* valid AVL-entry local   */
   if (adsp_a1->adsc_db1_local == NULL) {   /* no table local available */
     adsp_a1->boc_valid_local = TRUE;       /* valid AVL-entry local   */
     adsp_a1->dsc_htree1_work_local.adsc_found = NULL;  /* not found in tree */
#ifdef B150207
#ifndef B150206
     adsp_a1->ilc_sum_size_local = 0;       /* sum file size client    */
#endif
#endif
   }
   adsp_a1->boc_valid_remote = FALSE;       /* valid AVL-entry remote  */
   if (adsp_a1->adsc_db1_remote == NULL) {  /* no table remote available */
     adsp_a1->boc_valid_remote = TRUE;      /* valid AVL-entry remote  */
     adsp_a1->dsc_htree1_work_remote.adsc_found = NULL;  /* not found in tree */
#ifdef B150207
#ifndef B150206
     adsp_a1->ilc_sum_size_server = 0;      /* sum file size SMB server */
#endif
#endif
   }
   adsp_a1->imc_errors = 0;                 /* files with errors       */
   adsp_a1->imc_dir_nesting = 0;            /* counter directory nesting */
#ifdef NOT_USEFUL
   adsp_a1->adsc_f1_save_01 = NULL;           /* save entry to continue  */
#endif

// adsp_a1->dsc_htree1_work_sync;  /* work-area for AVL-Tree */
// adsp_a1->dsc_htree1_work_local;  /* work-area for AVL-Tree */
// adsp_a1->dsc_htree1_work_remote;  /* work-area for AVL-Tree */
#define ADSL_DB2_SYNC ((struct dsd_dir_bl_2 *) (adsp_a1->adsc_db1_sync + 1))
#define ADSL_DB2_LOCAL ((struct dsd_dir_bl_2 *) (adsp_a1->adsc_db1_local + 1))
#define ADSL_DB2_REMOTE ((struct dsd_dir_bl_2 *) (adsp_a1->adsc_db1_remote + 1))
#define ADSL_F1S_SYNC ((struct dsd_file_1 *) ((char *) adsp_a1->dsc_htree1_work_sync.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
#define ADSL_F1S_LOCAL ((struct dsd_file_1 *) ((char *) adsp_a1->dsc_htree1_work_local.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
#define ADSL_F1S_REMOTE ((struct dsd_file_1 *) ((char *) adsp_a1->dsc_htree1_work_remote.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
// if (dsl_htree1_work.adsc_found)          /* found in tree           */

   p_na_norm_00:                            /* normal processing       */
#ifdef HELP_DEBUG
   adsl_f1s_sync_l = ADSL_F1S_SYNC;
   adsl_f1s_local_l = ADSL_F1S_LOCAL;
   adsl_f1s_remote_l = ADSL_F1S_REMOTE;
#endif
#ifdef XYZ1
   bol_fn = FALSE;                          /* file-name generated     */
#endif
#ifdef TRACEHL1
   adsp_a1->imc_trace_call++;               /* trace call number       */
#endif
   if (adsp_a1->boc_valid_sync == FALSE) {  /* valid AVL-entry sync    */
     bol_rc = m_htree1_avl_getnext( NULL, &ADSL_DB2_SYNC->dsc_htree1_avl_file,
                                    &adsp_a1->dsc_htree1_work_sync, adsp_a1->boc_start );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() SYNC m_htree1_avl_getnext() failed",
                     __LINE__ );
       return FALSE;
     }
     adsp_a1->boc_valid_sync = TRUE;        /* valid AVL-entry sync    */
   }
   if (adsp_a1->boc_valid_local == FALSE) {  /* valid AVL-entry local  */
     bol_rc = m_htree1_avl_getnext( NULL, &ADSL_DB2_LOCAL->dsc_htree1_avl_file,
                                    &adsp_a1->dsc_htree1_work_local, adsp_a1->boc_start );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() LOCAL m_htree1_avl_getnext() failed",
                     __LINE__ );
       return FALSE;
     }
     adsp_a1->boc_valid_local = TRUE;       /* valid AVL-entry local   */
   }
   if (adsp_a1->boc_valid_remote == FALSE) {  /* valid AVL-entry remote */
     bol_rc = m_htree1_avl_getnext( NULL, &ADSL_DB2_REMOTE->dsc_htree1_avl_file,
                                    &adsp_a1->dsc_htree1_work_remote, adsp_a1->boc_start );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() REMOTE m_htree1_avl_getnext() failed",
                     __LINE__ );
       return FALSE;
     }
     adsp_a1->boc_valid_remote = TRUE;      /* valid AVL-entry remote  */
   }
#ifdef HELP_DEBUG
   adsl_f1s_sync_l = ADSL_F1S_SYNC;
   adsl_f1s_local_l = ADSL_F1S_LOCAL;
   adsl_f1s_remote_l = ADSL_F1S_REMOTE;
#endif
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() imc_trace_call=%d. imc_dir_nesting=%d",
                 __LINE__,
                 adsp_a1->imc_trace_call,   /* trace call number       */
                 adsp_a1->imc_dir_nesting );
#ifdef HELP_DEBUG
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() sync   fn:\"%.*s\"",
                   __LINE__, adsl_f1s_sync_l->dsc_ucs_file.imc_len_str, adsl_f1s_sync_l->dsc_ucs_file.ac_str );
   }
   if (adsp_a1->dsc_htree1_work_local.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() local  fn:\"%.*s\"",
                   __LINE__, adsl_f1s_local_l->dsc_ucs_file.imc_len_str, adsl_f1s_local_l->dsc_ucs_file.ac_str );
   }
   if (adsp_a1->dsc_htree1_work_remote.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() remote fn:\"%.*s\"",
                   __LINE__, adsl_f1s_remote_l->dsc_ucs_file.imc_len_str, adsl_f1s_remote_l->dsc_ucs_file.ac_str );
   }
#endif
#ifndef HELP_DEBUG
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() sync   fn:\"%.*s\"",
                   __LINE__, ADSL_F1S_SYNC->dsc_ucs_file.imc_len_str, ADSL_F1S_SYNC->dsc_ucs_file.ac_str );
   }
   if (adsp_a1->dsc_htree1_work_local.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() local  fn:\"%.*s\"",
                   __LINE__, ADSL_F1S_LOCAL->dsc_ucs_file.imc_len_str, ADSL_F1S_LOCAL->dsc_ucs_file.ac_str );
   }
   if (adsp_a1->dsc_htree1_work_remote.adsc_found) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_next_action() remote fn:\"%.*s\"",
                   __LINE__, ADSL_F1S_REMOTE->dsc_ucs_file.imc_len_str, ADSL_F1S_REMOTE->dsc_ucs_file.ac_str );
   }
#endif
#endif
   adsp_a1->boc_start = FALSE;              /* start processing        */
   if (adsp_a1->imc_dir_nesting) {          /* counter directory nesting */
     if (adsp_a1->boc_dir_ne_lo_re == FALSE) {  /* TRUE means remote   */
       goto p_na_del_lo_20;                 /* delete local directory  */
     }
     goto p_na_del_re_20;                   /* delete remote directory */
   }

   adsp_a1->ilc_size_replaced = 0;          /* size of file that is being replaced */
   if (adsp_a1->dsc_htree1_work_local.adsc_found) {  /* local found in tree */
     goto p_na_cmp_20;                      /* continue compare       */
   }
   if (adsp_a1->dsc_htree1_work_remote.adsc_found) {  /* remote found in tree not EOF */
     goto p_na_cmp_40;                      /* remote entry is lower   */
   }
#ifndef B15017
   /* files can have been deleted on both sides                        */
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {
     ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
       ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing     */
   }
#endif
   if (adsp_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     adsp_a1->adsc_db1_new_last->adsc_next = NULL;  /* directory block 1 - chaining */
     adsp_a1->adsc_db1_new_last->achc_end_file = (char *) adsp_a1->adsc_f1_new_cur;  /* end of files */
   }
   adsp_a1->iec_acs = ied_acs_done;         /* all done                */
#ifdef TRACEHL1
   adsp_a1->imc_trace_line = __LINE__;      /* line number for tracing */
#endif
   return TRUE;                             /* all done                */

   p_na_cmp_20:                             /* continue compare        */
   if (adsp_a1->dsc_htree1_work_remote.adsc_found == NULL) {  /* remote found in tree also EOF */
     goto p_na_cmp_28;                      /* local entry is lower    */
   }
   iml_cmp = m_cmp_file( NULL,
                         adsp_a1->dsc_htree1_work_local.adsc_found,
                         adsp_a1->dsc_htree1_work_remote.adsc_found );
   if (iml_cmp < 0) {                       /* check result            */
     goto p_na_cmp_28;                      /* local entry is lower    */
   }
   if (iml_cmp > 0) {                       /* check result            */
     goto p_na_cmp_40;                      /* remote entry is lower   */
   }

   /* same file local and remote                                       */
   iml_cmp = -1;                            /* set before sync entry   */
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {  /* sync found in tree EOF */
     iml_cmp = m_cmp_file( NULL,
                           adsp_a1->dsc_htree1_work_local.adsc_found,
                           adsp_a1->dsc_htree1_work_sync.adsc_found );
     if (iml_cmp > 0) {                     /* check result            */
       adsp_a1->boc_valid_sync = FALSE;     /* valid AVL-entry sync    */
#ifndef B15017
       /* files can have been deleted on both sides                    */
       ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
         ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing   */
#endif
       goto p_na_norm_00;                   /* normal processing       */
     }
   }
   if (iml_cmp == 0) {                      /* check result            */
     adsp_a1->boc_valid_sync = FALSE;       /* valid AVL-entry sync    */
   }
   adsp_a1->boc_valid_local = FALSE;        /* valid AVL-entry local   */
   adsp_a1->boc_valid_remote = FALSE;       /* valid AVL-entry remote  */
   if (ADSL_F1S_LOCAL->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     if (ADSL_F1S_REMOTE->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
       adsp_a1->imc_trace_line = __LINE__;  /* line number for tracing */
#endif
       goto p_new_00;                       /* create entry in new     */
     }
// to-do 13.06.13 KB
   }
   if (ADSL_F1S_REMOTE->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
// to-do 13.06.13 KB
   }
   if (ADSL_DB2_LOCAL->boc_unix == FALSE) {  /* local is Unix file system */
#ifdef B150411
     iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_LOCAL->dsc_last_write_time,
                                 (char *) &ADSL_F1S_REMOTE->dsc_last_write_time );
#endif
     iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_LOCAL->dsc_last_write_time,
                                                       &ADSL_F1S_REMOTE->dsc_last_write_time );
   } else {
     iml_cmp
       = m_unix_file_time( &ADSL_F1S_LOCAL->dsc_last_write_time )
           - m_unix_file_time( &ADSL_F1S_REMOTE->dsc_last_write_time );
   }
   if (iml_cmp < 0) {                       /* check result            */
     adsp_a1->iec_acs = ied_acs_copy_re2lo;  /* copy from remote to local */
     adsp_a1->ilc_size_replaced = ADSL_F1S_LOCAL->ilc_file_size;  /* size of file that is being replaced */
     if (adsp_a1->boc_write_local == FALSE) {  /* can write local      */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     if (ADSL_F1S_REMOTE->umc_flags) {      /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
#ifdef B150411
       iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                   (char *) &ADSL_F1S_REMOTE->dsc_last_write_time );
#endif
       iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                         &ADSL_F1S_REMOTE->dsc_last_write_time );
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_server == NULL) break;  /* no virus found on server */
       ADSL_F1S_REMOTE->achc_virus_server = ADSL_F1S_SYNC->achc_virus_server;  /* do not check virus on server */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150207
#ifdef B150110
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_REMOTE->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150110
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_local   /* sum file size client    */
                  + ADSL_F1S_REMOTE->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags
         |= D_FILE_1_FLAG_QUOTA             /* disk quota exceeded     */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#endif
#ifndef B150207
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsl_cl1->ilc_sum_size_local   /* sum file size client    */
                  + ADSL_F1S_REMOTE->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags
         |= D_FILE_1_FLAG_QUOTA             /* disk quota exceeded     */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
     if (adsp_a1->boc_write_local) {        /* can write local         */
       if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state    */
         adsp_a1->imc_errors++;             /* count files with errors */
#ifdef B140106
       } else {
         adsp_a1->boc_changed_local = TRUE;  /* changes local          */
#endif
       }
     }
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   if (iml_cmp > 0) {                       /* check result            */
     adsp_a1->iec_acs = ied_acs_copy_lo2re;  /* copy from local to remote */
     adsp_a1->ilc_size_replaced = ADSL_F1S_REMOTE->ilc_file_size;  /* size of file that is being replaced */
     if (adsp_a1->boc_write_server == FALSE) {  /* can write to SMB server */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     if (ADSL_F1S_LOCAL->umc_flags) {       /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
       if (ADSL_DB2_LOCAL->boc_unix == FALSE) {  /* local is Unix file system */
#ifdef B150411
         iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                     (char *) &ADSL_F1S_LOCAL->dsc_last_write_time );
#endif
         iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                           &ADSL_F1S_LOCAL->dsc_last_write_time );
       } else {
         iml_cmp
           = m_unix_file_time( &ADSL_F1S_SYNC->dsc_last_write_time )
               - m_unix_file_time( &ADSL_F1S_LOCAL->dsc_last_write_time );
       }
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_client == NULL) break;  /* no virus found on client */
       ADSL_F1S_LOCAL->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* do not check virus on client */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150207
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150207
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsl_cl1->ilc_sum_size_server  /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
     if (adsp_a1->boc_write_server) {       /* can write to SMB server */
       if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state    */
         adsp_a1->imc_errors++;             /* count files with errors */
#ifdef B140106
       } else {
         adsp_a1->boc_changed_remote = TRUE;  /* changes remote        */
#endif
       }
     }
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   if (memcmp( &ADSL_F1S_LOCAL->ilc_file_size,
               &ADSL_F1S_REMOTE->ilc_file_size,
               sizeof(HL_LONGLONG) )) {
// to-do 23.05.13 KB - filename in error message
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() file-size changed but still same last-write-time",
                   __LINE__ );
   }
   adsp_a1->iec_acs = ied_acs_invalid;      /* invalid state           */
   adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
   if (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
       && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
     ADSL_F1S_LOCAL->achc_virus_server = ADSL_F1S_SYNC->achc_virus_server;  /* virus found on server */
     ADSL_F1S_LOCAL->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* virus found on client */
   }
   if (   (ADSL_F1S_LOCAL->achc_virus_client)
       || (ADSL_F1S_LOCAL->achc_virus_server)
       || (ADSL_F1S_LOCAL->umc_flags)       /* flags for processing    */
       || (ADSL_F1S_REMOTE->achc_virus_client)
       || (ADSL_F1S_REMOTE->achc_virus_server)
       || (ADSL_F1S_REMOTE->umc_flags)) {   /* flags for processing    */
     adsp_a1->imc_errors++;                 /* count files with errors */
   }
#ifdef TRACEHL1
   adsp_a1->imc_trace_line = __LINE__;      /* line number for tracing */
#endif
   goto p_new_00;                           /* create entry in new     */

   p_na_cmp_28:                             /* local entry is lower    */
#ifdef B150207
//#ifdef B150206
#ifndef B150111
   if ((ADSL_F1S_LOCAL->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_LOCAL->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_LOCAL->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
     }
   }
#endif
//#endif
#endif
#ifdef B150206_XXX
   if ((ADSL_F1S_LOCAL->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_LOCAL->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_LOCAL->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ill_w1 = 0;
       if (adsp_a1->adsc_db1_remote) {      /* table remote available  */
         ill_w1 = adsp_a1->ilc_sum_size_server;  /* sum file size SMB server */
       }
       if ((ill_w1                          /* sum file size SMB server */
               + ADSL_F1S_LOCAL->ilc_file_size
               - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
             > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server) {  /* disk quota on SMB server */
         ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       }
     }
   }
#endif
#ifndef B150207
   if ((ADSL_F1S_LOCAL->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_LOCAL->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_LOCAL->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && ((adsl_cl1->ilc_sum_size_server  /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
     }
   }
#endif
   iml_cmp = -1;                            /* set before sync entry   */
   if (adsp_a1->dsc_htree1_work_sync.adsc_found == NULL) {  /* sync found in tree EOF */
     goto p_na_cmp_32;                      /* local entry is lower    */
   }
   iml_cmp = m_cmp_file( NULL,
                         adsp_a1->dsc_htree1_work_local.adsc_found,
                         adsp_a1->dsc_htree1_work_sync.adsc_found );
   if (iml_cmp > 0) {                       /* check result            */
     adsp_a1->boc_valid_sync = FALSE;       /* valid AVL-entry sync    */
#ifndef B15017
     /* files can have been deleted on both sides                      */
     ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
       ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing     */
#endif
     goto p_na_norm_00;                     /* normal processing       */
   }

   p_na_cmp_32:                             /* local entry is lower    */
   if (iml_cmp == 0) {                      /* remote has been deleted */
     goto p_na_cmp_36;                      /* remote has been deleted */
   }
   /* local is new file, not known before                              */
   adsp_a1->boc_valid_local = FALSE;        /* valid AVL-entry local   */
   if (adsp_a1->boc_write_server == FALSE) {  /* can write to SMB server */
     goto p_na_norm_00;                     /* normal processing       */
   }
#ifdef XYZ1
   adsp_a1->iec_acs = ied_acs_copy_lo2re;   /* copy from local to remote */
#endif
   if (ADSL_F1S_LOCAL->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     adsp_a1->iec_acs = ied_acs_create_dir_remote;  /* create directory remote */
#ifdef B140106
     adsp_a1->boc_changed_remote = TRUE;    /* changes remote          */
#endif
   } else {
     adsp_a1->iec_acs = ied_acs_copy_lo2re;  /* copy from local to remote */
     if (ADSL_F1S_LOCAL->umc_flags) {       /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
       if (ADSL_DB2_LOCAL->boc_unix == FALSE) {  /* local is Unix file system */
#ifdef B150411
         iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                     (char *) &ADSL_F1S_LOCAL->dsc_last_write_time );
#endif
         iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                           &ADSL_F1S_LOCAL->dsc_last_write_time );
       } else {
         iml_cmp
           = m_unix_file_time( &ADSL_F1S_SYNC->dsc_last_write_time )
               - m_unix_file_time( &ADSL_F1S_LOCAL->dsc_last_write_time );
       }
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_client == NULL) break;  /* no virus found on client */
       ADSL_F1S_LOCAL->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* do not check virus on client */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150207
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150207
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsl_cl1->ilc_sum_size_server  /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
     if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state      */
#ifndef B150228
       /* new file, but has error                                      */
       ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
         ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing   */
#endif
       adsp_a1->imc_errors++;               /* count files with errors */
#ifdef B140106
     } else {
       adsp_a1->boc_changed_remote = TRUE;  /* changes remote          */
#endif
     }
   }
   adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
   adsp_a1->imc_trace_line = __LINE__;      /* line number for tracing */
#endif
   goto p_new_00;                           /* create entry in new     */

   p_na_cmp_36:                             /* remote has been deleted */
   adsp_a1->boc_valid_sync = FALSE;         /* valid AVL-entry sync    */
   adsp_a1->boc_valid_local = FALSE;        /* valid AVL-entry local   */
#ifdef XYZ1
   iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_LOCAL->dsc_last_write_time,
                               (char *) &ADSL_F1S_SYNC->dsc_last_write_time );
#endif
   iml_cmp = 0;                             /* last write time is equal */
   if (   ((ADSL_F1S_SYNC->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
       && ((ADSL_F1S_LOCAL->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
     if (ADSL_DB2_LOCAL->boc_unix == FALSE) {  /* local is Unix file system */
#ifdef B150411
       iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_LOCAL->dsc_last_write_time,
                                   (char *) &ADSL_F1S_SYNC->dsc_last_write_time );
#endif
       iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_LOCAL->dsc_last_write_time,
                                                         &ADSL_F1S_SYNC->dsc_last_write_time );
     } else {
       iml_cmp
         = m_unix_file_time( &ADSL_F1S_LOCAL->dsc_last_write_time )
             - m_unix_file_time( &ADSL_F1S_SYNC->dsc_last_write_time );
     }
   }
   if (iml_cmp > 0) {                       /* local is newer          */
     if (adsp_a1->boc_write_server == FALSE) {  /* can write to SMB server */
       goto p_na_norm_00;                   /* normal processing       */
     }
     adsp_a1->iec_acs = ied_acs_copy_lo2re;   /* copy from local to remote */
#ifdef B150111
     if (ADSL_F1S_LOCAL->umc_flags) {       /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
       if (ADSL_DB2_LOCAL->boc_unix == FALSE) {  /* local is Unix file system */
#ifdef B150411
         iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                     (char *) &ADSL_F1S_LOCAL->dsc_last_write_time );
#endif
         iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                           &ADSL_F1S_LOCAL->dsc_last_write_time );
       } else {
         iml_cmp
           = m_unix_file_time( &ADSL_F1S_SYNC->dsc_last_write_time )
               - m_unix_file_time( &ADSL_F1S_LOCAL->dsc_last_write_time );
       }
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_client == NULL) break;  /* no virus found on client */
       ADSL_F1S_LOCAL->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* do not check virus on client */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150111
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)  /* disk quota on SMB server */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_LOCAL->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_server)) {  /* disk quota on SMB server */
       ADSL_F1S_LOCAL->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150111
     if (ADSL_F1S_LOCAL->umc_flags != 0) {  /* file not valid          */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
#endif
     if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state      */
       adsp_a1->imc_errors++;               /* count files with errors */
#ifdef B140106
     } else {
       adsp_a1->boc_changed_remote = TRUE;  /* changes remote          */
#endif
     }
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   if (ADSL_F1S_SYNC->achc_virus_client) {  /* before virus found on client */
     ADSL_F1S_LOCAL->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* do not check virus on client */
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#ifdef B150111
   if (ADSL_F1S_SYNC->umc_flags) {          /* special handling        */
     ADSL_F1S_LOCAL->umc_flags = ADSL_F1S_SYNC->umc_flags;  /* copy special handling */
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#endif
#ifndef B151220
   if (adsp_a1->boc_write_local == FALSE) {  /* cannot write local     */
     ADSL_F1S_LOCAL->umc_flags
       |= D_FILE_1_FLAG_NOT_SE;             /* file not on server      */
   }
#endif
#ifndef B150111
// if (ADSL_F1S_LOCAL->umc_flags) {         /* special handling        */
// if (ADSL_F1S_LOCAL->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) {  /* special handling */
   if (ADSL_F1S_LOCAL->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL - D_FILE_1_FLAG_NOT_SE)) {  /* special handling */
     if (ADSL_F1S_LOCAL->umc_flags != ADSL_F1S_SYNC->umc_flags) {  /* flags changed */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   if (ADSL_F1S_SYNC->umc_flags) {          /* was locked before       */
     if (ADSL_F1S_LOCAL->umc_flags) {       /* still disk quota        */
       if (ADSL_F1S_LOCAL->umc_flags != ADSL_F1S_SYNC->umc_flags) {  /* flags changed */
         adsp_a1->boc_changed_sync = TRUE;  /* need to write synchronize file */
       }
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->imc_errors++;               /* count files with errors */
       adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
       adsp_a1->imc_trace_line = __LINE__;  /* line number for tracing */
#endif
       goto p_new_00;                       /* create entry in new     */
     }
     /* file no more locked, so copy now                               */
     adsp_a1->iec_acs = ied_acs_copy_lo2re;   /* copy from local to remote */
     adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#endif

   /* we need to delete the local file                                 */
   /* if this is a directory, we need to delete all files in the directory */

   adsp_a1->imc_dir_delete = 0;             /* number to delete directory */

   p_na_del_lo_00:                          /* found delete local directory */
   adsp_a1->iec_acs = ied_acs_delete_file_local;   /* delete file local */
   adsp_a1->adsc_f1_action = ADSL_F1S_LOCAL;  /* entry of file current action */
   if ((ADSL_F1S_LOCAL->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
#ifdef B140106
     adsp_a1->boc_changed_local = TRUE;     /* changes local           */
#endif
#ifdef B150207
#ifndef B150111
     adsp_a1->ilc_sum_size_local            /* sum file size client    */
       -= ADSL_F1S_LOCAL->ilc_file_size;
#endif
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_local           /* sum file size client    */
       -= ADSL_F1S_LOCAL->ilc_file_size;
#endif
     goto p_ret_00;                         /* all done                */
   }
   adsp_a1->boc_dir_ne_lo_re = FALSE;       /* TRUE means remote       */
   if (adsp_a1->imc_dir_nesting >= MAX_DIR_STACK) {  /* counter directory nesting */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() overflow directory nesting",
                   __LINE__ );
     return FALSE;
   }
   adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting ] = ADSL_F1S_LOCAL;  /* stack entry directory */
   adsp_a1->imc_dir_nesting++;              /* counter directory nesting */
   goto p_na_norm_00;                       /* normal processing       */

   p_na_del_lo_20:                          /* delete local directory  */
   if (adsp_a1->dsc_htree1_work_local.adsc_found == NULL) {  /* local found in tree EOF */
     goto p_na_del_lo_40;                   /* continue delete local directory */
   }
   if (ADSL_F1S_LOCAL->adsc_file_1_parent != adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting - 1 ]) {  /* entry of parent directory */
     goto p_na_del_lo_40;                   /* continue delete local directory */
   }
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {  /* SYNC not EOF    */
     iml_cmp = m_cmp_file( NULL,
                           adsp_a1->dsc_htree1_work_local.adsc_found,
                           adsp_a1->dsc_htree1_work_sync.adsc_found );
     if (iml_cmp > 0) {                     /* check result            */
       adsp_a1->boc_valid_sync = FALSE;     /* valid AVL-entry sync    */
       goto p_na_norm_00;                   /* normal processing       */
     }
     if (iml_cmp == 0) {                    /* needs to overread sync  */
       adsp_a1->boc_valid_sync = FALSE;     /* valid AVL-entry sync    */
     }
   }
   adsp_a1->boc_valid_local = FALSE;        /* valid AVL-entry local   */
   goto p_na_del_lo_00;                     /* found delete local directory */

   p_na_del_lo_40:                          /* continue delete local directory */
#ifdef NOT_USEFUL
   adsp_a1->adsc_f1_save_01 = ADSL_F1S_LOCAL;  /* save entry to continue */
#endif
   adsp_a1->iec_acs = ied_acs_delete_dir_local;  /* delete directory local */
   adsp_a1->imc_dir_nesting--;              /* counter directory nesting */
   adsp_a1->adsc_f1_action = adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting ];  /* stack entry directory */
   if (adsp_a1->imc_dir_nesting >= adsp_a1->imc_dir_delete) {  /* number to delete directory */
#ifdef B140106
     adsp_a1->boc_changed_local = TRUE;     /* changes local           */
#endif
     goto p_ret_00;                         /* all done                */
   }

   /* the directory is not deleted since remote there is a newer file  */
   if (adsp_a1->imc_dir_delete > adsp_a1->imc_dir_nesting) {  /* number to delete directory */
     adsp_a1->imc_dir_delete = adsp_a1->imc_dir_nesting;  /* adjust number to delete directory */
   }
   goto p_na_norm_00;                       /* normal processing       */

   p_na_cmp_40:                             /* remote entry is lower   */
#ifdef B150207
//#ifdef B150206
#ifndef B150111
   if ((ADSL_F1S_REMOTE->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_REMOTE->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_REMOTE->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && ((adsp_a1->ilc_sum_size_local   /* sum file size client    */
                  + ADSL_F1S_REMOTE->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags
        |= D_FILE_1_FLAG_QUOTA              /* disk quota exceeded     */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
     }
   }
#endif
//#endif
#endif
#ifdef B150206_XXX
   if ((ADSL_F1S_REMOTE->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_REMOTE->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_REMOTE->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ill_w1 = 0;
       if (adsp_a1->adsc_db1_local) {       /* table local available   */
         ill_w1 = adsp_a1->ilc_sum_size_local;  /* sum file size client */
       }
       if ((ill_w1                          /* sum file size client    */
               + ADSL_F1S_REMOTE->ilc_file_size
               - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
             > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local) {  /* disk quota on client */
         ADSL_F1S_REMOTE->umc_flags
          |= D_FILE_1_FLAG_QUOTA            /* disk quota exceeded     */
                | D_FILE_1_FLAG_NOT_CL;     /* file not on client      */
       }
     }
   }
#endif
#ifndef B150207
   if ((ADSL_F1S_REMOTE->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) == 0) {  /* still valid */
     ADSL_F1S_REMOTE->umc_flags &= -1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL;  /* reset disk quota exceeded */
     if (   (ADSL_F1S_REMOTE->achc_virus_server == NULL)  /* no virus  */
         && (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && ((adsl_cl1->ilc_sum_size_local  /* sum file size client    */
                  + ADSL_F1S_REMOTE->ilc_file_size
                  - adsp_a1->ilc_size_replaced)  /* size of file that is being replaced */
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags
        |= D_FILE_1_FLAG_QUOTA              /* disk quota exceeded     */
              | D_FILE_1_FLAG_NOT_CL;       /* file not on client      */
     }
   }
#endif
   iml_cmp = -1;                            /* set before sync entry   */
   if (adsp_a1->dsc_htree1_work_sync.adsc_found == NULL) {  /* sync found in tree EOF */
     goto p_na_cmp_48;                      /* remote entry is lower   */
   }
   iml_cmp = m_cmp_file( NULL,
                         adsp_a1->dsc_htree1_work_remote.adsc_found,
                         adsp_a1->dsc_htree1_work_sync.adsc_found );
   if (iml_cmp > 0) {                       /* check result            */
     adsp_a1->boc_valid_sync = FALSE;       /* valid AVL-entry sync    */
#ifndef B15017
     /* files can have been deleted on both sides                      */
     ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
       ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing     */
#endif
     goto p_na_norm_00;                     /* normal processing       */
   }

   p_na_cmp_48:                             /* remote entry is lower   */
   if (iml_cmp == 0) {                      /* local has been deleted  */
     goto p_na_cmp_76;                      /* local has been deleted  */
   }
   /* remote is new file, not known before                             */
   adsp_a1->boc_valid_remote = FALSE;       /* valid AVL-entry remote  */
   if (adsp_a1->boc_write_local == FALSE) {  /* can write local        */
     goto p_na_norm_00;                     /* normal processing       */
   }
   adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
   adsp_a1->iec_acs = ied_acs_copy_re2lo;   /* copy from remote to local */
   if ((ADSL_F1S_REMOTE->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
#ifdef B150111
     if (ADSL_F1S_REMOTE->umc_flags) {      /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
#ifdef B150411
       iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                   (char *) &ADSL_F1S_REMOTE->dsc_last_write_time );
#endif
       iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                         &ADSL_F1S_REMOTE->dsc_last_write_time );
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_server == NULL) break;  /* no virus found on server */
       ADSL_F1S_REMOTE->achc_virus_server = ADSL_F1S_SYNC->achc_virus_server;  /* do not check virus on server */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150111
#ifdef B150110
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_REMOTE->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150110
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_local   /* sum file size client    */
                  + ADSL_F1S_REMOTE->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
#endif
#endif
#ifndef B150111
     if (ADSL_F1S_REMOTE->umc_flags != 0) {  /* file not valid         */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
#endif
     if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state      */
       adsp_a1->imc_errors++;               /* count files with errors */
#ifdef B140106
     } else {
       adsp_a1->boc_changed_local = TRUE;   /* changes local           */
#endif
     }
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   adsp_a1->iec_acs = ied_acs_create_dir_local;  /* create directory local */
#ifdef B140106
   adsp_a1->boc_changed_local = TRUE;       /* changes local           */
#endif
#ifdef TRACEHL1
   adsp_a1->imc_trace_line = __LINE__;      /* line number for tracing */
#endif
   goto p_new_00;                           /* create entry in new     */

   p_na_cmp_76:                             /* local has been deleted  */
   adsp_a1->boc_valid_sync = FALSE;         /* valid AVL-entry sync    */
   adsp_a1->boc_valid_remote = FALSE;       /* valid AVL-entry remote  */
#ifdef XYZ1
   iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_REMOTE->dsc_last_write_time,
                               (char *) &ADSL_F1S_SYNC->dsc_last_write_time );
#endif
   iml_cmp = 0;                             /* last write time is equal */
   if (   ((ADSL_F1S_SYNC->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
       && ((ADSL_F1S_REMOTE->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
#ifdef B150411
     iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_REMOTE->dsc_last_write_time,
                                 (char *) &ADSL_F1S_SYNC->dsc_last_write_time );
#endif
     iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_REMOTE->dsc_last_write_time,
                                                       &ADSL_F1S_SYNC->dsc_last_write_time );
   }
   if (iml_cmp > 0) {                       /* remote is newer         */
     if (adsp_a1->boc_write_local == FALSE) {  /* can write local      */
       goto p_na_norm_00;                   /* normal processing       */
     }
     adsp_a1->iec_acs = ied_acs_copy_re2lo;  /* copy from remote to local */
     if (ADSL_F1S_REMOTE->umc_flags) {      /* flags for processing    */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
     while (   (adsp_a1->dsc_htree1_work_sync.adsc_found)  /* sync found in tree EOF */
            && (adsp_a1->boc_valid_sync == FALSE)) {  /* valid AVL-entry sync */
#ifdef XYZ1
       if (adsp_a1->iec_acs == ied_acs_invalid) break;  /* invalid state */
#endif
#ifdef B150411
       iml_cmp = m_cmp_longlong_1( (char *) &ADSL_F1S_SYNC->dsc_last_write_time,
                                   (char *) &ADSL_F1S_REMOTE->dsc_last_write_time );
#endif
       iml_cmp = (*adsp_sdh_call_1->amc_cmp_time_var_1)( &ADSL_F1S_SYNC->dsc_last_write_time,
                                                         &ADSL_F1S_REMOTE->dsc_last_write_time );
       if (iml_cmp != 0) break;             /* not the same            */
#ifdef XYZ1
       if (ADSL_F1S_SYNC->umc_flags) {      /* flags for processing    */
         adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state         */
       }
#endif
       if (ADSL_F1S_SYNC->achc_virus_server == NULL) break;  /* no virus found on server */
       ADSL_F1S_REMOTE->achc_virus_server = ADSL_F1S_SYNC->achc_virus_server;  /* do not check virus on server */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       break;
     }
#ifdef B150111
     if (   (adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)  /* disk quota on client */
         && (adsp_a1->iec_acs != ied_acs_invalid)  /* valid state      */
         && ((adsp_a1->ilc_sum_size_server    /* sum file size SMB server */
                  + ADSL_F1S_REMOTE->ilc_file_size)
                > adsp_sdh_call_1->adsc_cl1d1_1->dsc_cm.ilc_quota_local)) {  /* disk quota on client */
       ADSL_F1S_REMOTE->umc_flags |= D_FILE_1_FLAG_QUOTA;  /* disk quota exceeded */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
     }
#endif
#ifndef B150111
     if (ADSL_F1S_REMOTE->umc_flags != 0) {  /* file not valid         */
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
#endif
     if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state      */
       adsp_a1->imc_errors++;               /* count files with errors */
#ifdef B140106
     } else {
       adsp_a1->boc_changed_local = TRUE;   /* changes local           */
#endif
     }
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
   if (ADSL_F1S_SYNC->achc_virus_client) {  /* before virus found on client */
     ADSL_F1S_REMOTE->achc_virus_client = ADSL_F1S_SYNC->achc_virus_client;  /* do not check virus on client */
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#ifdef B150111
   if (ADSL_F1S_SYNC->umc_flags) {          /* special handling        */
#ifndef B150111
     if (ADSL_F1S_REMOTE->umc_flags != ADSL_F1S_SYNC->umc_flags) {  /* flags changed */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
#endif
     ADSL_F1S_REMOTE->umc_flags = ADSL_F1S_SYNC->umc_flags;  /* copy special handling */
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#endif
#ifndef B151220
   if (adsp_a1->boc_write_server == FALSE) {  /* cannot write to SMB server */
     ADSL_F1S_REMOTE->umc_flags
       |= D_FILE_1_FLAG_NOT_CL;             /* file not on client      */
   }
#endif
#ifndef B150111
// if (ADSL_F1S_REMOTE->umc_flags) {        /* special handling        */
   if (ADSL_F1S_REMOTE->umc_flags & (-1 - D_FILE_1_FLAG_QUOTA - D_FILE_1_FLAG_NOT_CL)) {  /* special handling */
     if (ADSL_F1S_REMOTE->umc_flags != ADSL_F1S_SYNC->umc_flags) {  /* flags changed */
       adsp_a1->boc_changed_sync = TRUE;    /* need to write synchronize file */
     }
     adsp_a1->iec_acs = ied_acs_invalid;    /* invalid state           */
     adsp_a1->imc_errors++;                 /* count files with errors */
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }

   if (ADSL_F1S_SYNC->umc_flags) {          /* was locked before       */
     if (ADSL_F1S_REMOTE->umc_flags) {      /* still disk quota        */
       if (ADSL_F1S_REMOTE->umc_flags != ADSL_F1S_SYNC->umc_flags) {  /* flags changed */
         adsp_a1->boc_changed_sync = TRUE;  /* need to write synchronize file */
       }
       adsp_a1->iec_acs = ied_acs_invalid;  /* invalid state           */
       adsp_a1->imc_errors++;               /* count files with errors */
       adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
       adsp_a1->imc_trace_line = __LINE__;  /* line number for tracing */
#endif
       goto p_new_00;                       /* create entry in new     */
     }
     /* file no more locked, so copy now                               */
     adsp_a1->iec_acs = ied_acs_copy_re2lo;  /* copy from remote to local */
     adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
#ifdef TRACEHL1
     adsp_a1->imc_trace_line = __LINE__;    /* line number for tracing */
#endif
     goto p_new_00;                         /* create entry in new     */
   }
#endif

   /* we need to delete the remote file                                */
   /* if this is a directory, we need to delete all files in the directory */

   adsp_a1->imc_dir_delete = 0;             /* number to delete directory */

   p_na_del_re_00:                          /* found delete remote directory */
   adsp_a1->iec_acs = ied_acs_delete_file_remote;   /* delete file remote */
   adsp_a1->adsc_f1_action = ADSL_F1S_REMOTE;  /* entry of file current action */
   if ((ADSL_F1S_REMOTE->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
#ifdef B140106
     adsp_a1->boc_changed_remote = TRUE;    /* changes remote          */
#endif
#ifdef B150207
#ifndef B150111
     adsp_a1->ilc_sum_size_server           /* sum file size SMB server */
       -= ADSL_F1S_REMOTE->ilc_file_size;
#endif
#endif
#ifndef B150207
     adsl_cl1->ilc_sum_size_server          /* sum file size SMB server */
       -= ADSL_F1S_REMOTE->ilc_file_size;
#endif
     goto p_ret_00;                         /* all done                */
   }
   adsp_a1->boc_dir_ne_lo_re = TRUE;        /* TRUE means remote       */
   if (adsp_a1->imc_dir_nesting >= MAX_DIR_STACK) {  /* counter directory nesting */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() overflow directory nesting",
                   __LINE__ );
     return FALSE;
   }
   adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting ] = ADSL_F1S_REMOTE;  /* stack entry directory */
   adsp_a1->imc_dir_nesting++;              /* counter directory nesting */
   goto p_na_norm_00;                       /* normal processing       */

   p_na_del_re_20:                          /* delete remote directory */
   if (adsp_a1->dsc_htree1_work_remote.adsc_found == NULL) {  /* remote found in tree EOF */
     goto p_na_del_re_40;                   /* continue delete remote directory */
   }
   if (ADSL_F1S_REMOTE->adsc_file_1_parent != adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting - 1 ]) {  /* entry of parent directory */
     goto p_na_del_re_40;                   /* continue delete remote directory */
   }
   if (adsp_a1->dsc_htree1_work_sync.adsc_found) {  /* SYNC not EOF    */
     iml_cmp = m_cmp_file( NULL,
                           adsp_a1->dsc_htree1_work_remote.adsc_found,
                           adsp_a1->dsc_htree1_work_sync.adsc_found );
     if (iml_cmp > 0) {                     /* check result            */
       adsp_a1->boc_valid_sync = FALSE;     /* valid AVL-entry sync    */
       goto p_na_norm_00;                   /* normal processing       */
     }
     if (iml_cmp == 0) {                    /* needs to overread sync  */
       adsp_a1->boc_valid_sync = FALSE;     /* valid AVL-entry sync    */
     }
   }
   adsp_a1->boc_valid_remote = FALSE;       /* valid AVL-entry remote  */
   goto p_na_del_re_00;                     /* found delete remote directory */

   p_na_del_re_40:                          /* continue delete remote directory */
#ifdef NOT_USEFUL
   adsp_a1->adsc_f1_save_01 = ADSL_F1S_LOCAL;  /* save entry to continue */
#endif
   adsp_a1->iec_acs = ied_acs_delete_dir_remote;  /* delete directory remote */
   adsp_a1->imc_dir_nesting--;              /* counter directory nesting */
   adsp_a1->adsc_f1_action = adsp_a1->adsrc_f1_dir_nesting[ adsp_a1->imc_dir_nesting ];  /* stack entry directory */
   if (adsp_a1->imc_dir_nesting >= adsp_a1->imc_dir_delete) {  /* number to delete directory */
#ifdef B140106
     adsp_a1->boc_changed_remote = TRUE;    /* changes remote          */
#endif
     goto p_ret_00;                         /* all done                */
   }

   /* the directory is not deleted since local there is a newer file   */
   if (adsp_a1->imc_dir_delete > adsp_a1->imc_dir_nesting) {  /* number to delete directory */
     adsp_a1->imc_dir_delete = adsp_a1->imc_dir_nesting;  /* adjust number to delete directory */
   }
   goto p_na_norm_00;                       /* normal processing       */

#undef ADSL_DB2_SYNC
#undef ADSL_DB2_LOCAL
#undef ADSL_DB2_REMOTE

#define ADSL_DB2_NEW ((struct dsd_dir_bl_2 *) (adsp_a1->adsc_db1_new_start + 1))

   p_new_00:                                /* create entry in new     */
   if (adsp_a1->adsc_db1_new_start) {       /* directory block 1 - new */
     goto p_new_20;                         /* continue entry in new   */
   }
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_MEMGET,  /* get some memory */
                                         &adsp_a1->adsc_db1_new_cur,
                                         LEN_DIR_BLOCK );
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   adsp_a1->adsc_db1_new_start = adsp_a1->adsc_db1_new_last = adsp_a1->adsc_db1_new_cur;
   adsp_a1->adsc_f1_new_cur = (struct dsd_file_1 *) ((char *) (adsp_a1->adsc_db1_new_start + 1) + sizeof(struct dsd_dir_bl_2));
   ADSL_DB2_NEW->imc_no_files = 0;          /* number of files         */
   ADSL_DB2_NEW->imc_no_dir = 0;            /* number of directories   */
   ADSL_DB2_NEW->boc_unix = FALSE;          /* is Unix filesystem      */
   bol_rc = m_htree1_avl_init( NULL, &ADSL_DB2_NEW->dsc_htree1_avl_file,
                               &m_cmp_file );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() m_htree1_avl_init() failed",
                   __LINE__ );
     return FALSE;
   }
   adsp_a1->achc_fn_new_low = (char *) adsp_a1->adsc_db1_new_cur + LEN_DIR_BLOCK;  /* low address of file names */

   p_new_20:                                /* continue entry in new   */
#ifdef XYZ1
   ims_local_pos_fn_end = m_build_file_name_utf8( adsp_a1->adsc_f1_action );
   if (ims_local_pos_fn_end <= 0) return FALSE;
   bol_fn = TRUE;                           /* file-name generated     */
#endif
   iml1 = adsp_a1->adsc_f1_action->dsc_ucs_file.imc_len_str;
   if (adsp_a1->adsc_f1_action->achc_virus_client) {  /* virus found on client */
     iml1 += strlen( adsp_a1->adsc_f1_action->achc_virus_client ) + 1;
   }
   if (adsp_a1->adsc_f1_action->achc_virus_server) {  /* virus found on server */
     iml1 += strlen( adsp_a1->adsc_f1_action->achc_virus_server ) + 1;
   }
// if (((char *) (adsp_a1->adsc_f1_new_cur + 1)) > (adsp_a1->achc_fn_new_low - adsp_a1->adsc_f1_action->dsc_ucs_file.imc_len_str)) {
   if (((char *) (adsp_a1->adsc_f1_new_cur + 1)) > (adsp_a1->achc_fn_new_low - iml1)) {
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMGET,  /* get some memory */
                                           &adsp_a1->adsc_db1_new_cur,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       return FALSE;
     }
     adsp_a1->adsc_db1_new_last->adsc_next = adsp_a1->adsc_db1_new_cur;  /* directory block 1 - chaining */
     adsp_a1->adsc_db1_new_last->achc_end_file = (char *) adsp_a1->adsc_f1_new_cur;  /* end of files */
     adsp_a1->adsc_f1_new_cur = (struct dsd_file_1 *) ((char *) (adsp_a1->adsc_db1_new_cur + 1));
     adsp_a1->adsc_db1_new_last = adsp_a1->adsc_db1_new_cur;  /* directory block 1 - chaining - last */
     adsp_a1->achc_fn_new_low = (char *) adsp_a1->adsc_db1_new_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
// memcpy( adsp_a1->adsc_f1_new_cur, adsp_a1->adsc_f1_action, sizeof(struct dsd_file_1) );
   *adsp_a1->adsc_f1_new_cur = *adsp_a1->adsc_f1_action;
   adsp_a1->achc_fn_new_low -= adsp_a1->adsc_f1_action->dsc_ucs_file.imc_len_str;
   memcpy( adsp_a1->achc_fn_new_low,
           adsp_a1->adsc_f1_action->dsc_ucs_file.ac_str,
           adsp_a1->adsc_f1_action->dsc_ucs_file.imc_len_str );
   adsp_a1->adsc_f1_new_cur->dsc_ucs_file.ac_str = adsp_a1->achc_fn_new_low;
   if (adsp_a1->adsc_f1_action->achc_virus_client) {  /* virus found on client */
     iml1 = strlen( adsp_a1->adsc_f1_action->achc_virus_client ) + 1;
     adsp_a1->achc_fn_new_low -= iml1;
     memcpy( adsp_a1->achc_fn_new_low,
             adsp_a1->adsc_f1_action->achc_virus_client,
             iml1 );
     adsp_a1->adsc_f1_new_cur->achc_virus_client = adsp_a1->achc_fn_new_low;  /* virus found on client */
   }
   if (adsp_a1->adsc_f1_action->achc_virus_server) {  /* virus found on server */
     iml1 = strlen( adsp_a1->adsc_f1_action->achc_virus_server ) + 1;
     adsp_a1->achc_fn_new_low -= iml1;
     memcpy( adsp_a1->achc_fn_new_low,
             adsp_a1->adsc_f1_action->achc_virus_server,
             iml1 );
     adsp_a1->adsc_f1_new_cur->achc_virus_server = adsp_a1->achc_fn_new_low;  /* virus found on server */
   }
   if (adsp_a1->adsc_f1_new_cur->adsc_file_1_parent == NULL) {  /* entry of parent directory */
     goto p_new_60;                         /* directory information complete */
   }
   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_NEW->dsc_htree1_avl_file,
                                 &adsp_a1->dsc_htree1_work_new, &adsp_a1->adsc_f1_action->adsc_file_1_parent->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() m_htree1_avl_search() failed",
                   __LINE__ );
     return FALSE;                          /* return error            */
   }
   if (adsp_a1->dsc_htree1_work_new.adsc_found == NULL) {  /* not found in tree */
//   m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" nesting of directories not defined",
//                 __LINE__, iml_len_fn, byrl_file_name );
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() file / directory nesting of directories not defined",
                   __LINE__ );
     return FALSE;                          /* return error            */
   }
   adsp_a1->adsc_f1_new_cur->adsc_file_1_parent  /* entry of parent directory */
     = (struct dsd_file_1 *) ((char *) adsp_a1->dsc_htree1_work_new.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 ));
   if ((adsp_a1->adsc_f1_new_cur->adsc_file_1_parent->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
//   m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" nesting of directories found normal file",
//                 __LINE__, iml_len_fn, byrl_file_name );
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() file / directory nesting of directories found normal file",
                   __LINE__ );
     return FALSE;                          /* return error            */
   }

   p_new_60:                                /* directory information complete */
   if (adsp_a1->adsc_f1_new_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     ADSL_DB2_NEW->imc_no_dir++;            /* number of directories   */
   }
   ADSL_DB2_NEW->imc_no_files++;            /* number of files         */

// to-do 13.06.13 KB - temporary
   adsp_a1->adsc_f1_action = adsp_a1->adsc_f1_new_cur;

#ifndef B170321
/*
 * adsc_f1_new_cur is used later for output of XML data,
 * but adsc_file_1_parent points to an area which will be freed.
*/
   if (adsp_a1->imc_dir_nesting > 0) {
     adsp_a1->adsc_f1_new_cur
       = adsp_a1->adsrc_f1_outdir_nesting[ adsp_a1->imc_dir_nesting - 1 ];  /* get old entry */
   }
   adsp_a1->adsrc_f1_outdir_nesting[ adsp_a1->imc_dir_nesting ] = adsp_a1->adsc_f1_new_cur;  /* stack entry directory */
#endif

   /* add file to AVL-tree                                             */
   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_NEW->dsc_htree1_avl_file,
                                 &adsp_a1->dsc_htree1_work_new, &adsp_a1->adsc_f1_new_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() m_htree1_avl_search() failed",
                   __LINE__ );
     return FALSE;                          /* return error            */
   }
   if (adsp_a1->dsc_htree1_work_new.adsc_found) {  /* found in tree      */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) adsp_a1->dsc_htree1_work_new.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
     if (ADSL_F1_SORT->adsc_file_1_same_n == NULL) {  /* chain of entries same name */
       ADSL_F1_SORT->adsc_file_1_same_n = adsp_a1->adsc_f1_new_cur;  /* chain of entries same name */
     } else {                               /* already files with same name */
       adsl_f1_w1 = ADSL_F1_SORT->adsc_file_1_same_n;  /* get chain of entries same name */
       while (adsl_f1_w1->adsc_file_1_same_n) {  /* check chain of entries same name */
         adsl_f1_w1 = adsl_f1_w1->adsc_file_1_same_n;  /* next in chain of entries same name */
       }
       adsl_f1_w1->adsc_file_1_same_n = adsp_a1->adsc_f1_new_cur;  /* append to chain of entries same name */
     }
     goto p_new_68;                         /* end of this file        */
#undef ADSL_F1_SORT
   }
   bol_rc = m_htree1_avl_insert( NULL, &ADSL_DB2_NEW->dsc_htree1_avl_file,
                                 &adsp_a1->dsc_htree1_work_new, &adsp_a1->adsc_f1_new_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_next_action() m_htree1_avl_insert() failed",
                   __LINE__ );
     return FALSE;                          /* return error            */
   }
#ifdef DEBUG_170410_01                      /* address adsc_file_1_parent invalid */
   m_check_parent_1( adsp_sdh_call_1,
                     adsp_a1->adsc_db1_new_start,
                     "m_next_action() 1", __LINE__ );
#endif  /* DEBUG_170410_01                     address adsc_file_1_parent invalid */

   p_new_68:                                /* end of this file        */
   adsp_a1->adsc_f1_new_cur++;              /* entry of a single file  */
   if (adsp_a1->iec_acs == ied_acs_invalid) {  /* invalid state        */
     goto p_na_norm_00;                     /* normal processing       */
   }

   p_ret_00:                                /* all done                */
#ifdef XYZ1
   if (bol_fn) return TRUE;                 /* file-name generated     */
#endif
#ifdef NOT_YET_130718
   ims_local_pos_fn_end = m_build_file_name_utf8( adsp_a1->adsc_f1_action );
   if (ims_local_pos_fn_end <= 0) return FALSE;
#endif
   return TRUE;
#undef ADSL_F1S_SYNC
#undef ADSL_F1S_LOCAL
#undef ADSL_F1S_REMOTE
} /* end m_next_action()                                               */

/** initialze the work area for virus-checking                         */
static BOOL m_work_vc_init( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                            struct dsd_work_vch_1 *adsp_wvc1,  /* virus-checking */
                            struct dsd_dash_work_all *adsp_dwa,  /* all dash operations work area */
                            char *achp_filename, int imp_len_filename ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   union {
     struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query   */
     struct dsd_aux_swap_stor_req_1 dsl_astr1;  /* swap storage request */
   };

#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_work_vc_init()",
                 __LINE__ );
#endif
   /* data for virus-checking                                          */
   adsp_wvc1->dsrc_gai1_vch_data[ 0 ].achc_ginp_cur = achp_filename;
   adsp_wvc1->dsrc_gai1_vch_data[ 0 ].achc_ginp_end = achp_filename + imp_len_filename;
   adsp_wvc1->dsrc_gai1_vch_data[ 0 ].adsc_next = NULL;
   memset( &adsp_wvc1->dsrc_sevchreq1[ 0 ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsp_wvc1->dsrc_sevchreq1[ 0 ].adsc_gai1_data = &adsp_wvc1->dsrc_gai1_vch_data[ 0 ];
   adsp_wvc1->dsrc_sevchreq1[ 0 ].iec_vchreq1 = ied_vchreq_filename;  /* filename */
   /* set other requests to unused                                     */
   iml1 = 1;                                /* index start             */
   do {                                     /* loop to set elements unused */
     *((int *) &adsp_wvc1->dsrc_sevchreq1[ iml1++ ].iec_stat) = -1;  /* set unused */
   } while (iml1 < NO_VC_REQ1);             /* number of concurrent requests */
   memset( &adsp_wvc1->dsc_sevchcontr1, 0, sizeof(struct dsd_se_vch_contr_1) );
   adsp_wvc1->dsc_sevchcontr1.imc_max_diff_window = MAX_VC_WINDOW;  /* maximum difference window */
   adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsp_wvc1->dsrc_sevchreq1[ 0 ];
   /* start request to service                                         */
   memset( &dsl_aux_sequ1, 0, sizeof(struct dsd_aux_service_query_1) );
   dsl_aux_sequ1.iec_co_service = ied_co_service_requ;  /* service request */
   dsl_aux_sequ1.vpc_sequ_handle = adsp_dwa->vpc_sequ_handle;  /* handle of service query */
   dsl_aux_sequ1.ac_control_area = &adsp_wvc1->dsc_sevchcontr1;  /* control area request */
   dsl_aux_sequ1.imc_signal = HL_AUX_SIGNAL_IO_1;  /* signal to set    */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_SERVICE_REQUEST,  /* service request */
                                         &dsl_aux_sequ1,
                                         sizeof(struct dsd_aux_service_query_1) );
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (dsl_aux_sequ1.iec_ret_service != ied_ret_service_ok) {  /* check service return code */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W Virus Checker Service request returned error %d.",
                   __LINE__, dsl_aux_sequ1.iec_ret_service );
     return FALSE;
   }
   adsp_dwa->umc_state |= DWA_STATE_VCH_STARTED | DWA_STATE_VCH_ACT;  /* state of processing */
   /* start buffering in swap storage                                  */
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_open;      /* open swap storage       */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                         &dsl_astr1,  /* swap storage request */
                                         sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     return FALSE;
   }
   dsl_astr1.iec_swsc = ied_swsc_get_buf;  /* acquire swap storage buffer */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                         &dsl_astr1,  /* swap storage request */
                                         sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     return FALSE;
   }
   adsp_wvc1->vpc_aux_swap_stor_handle = dsl_astr1.vpc_aux_swap_stor_handle;  /* handle of swap storage */
   adsp_wvc1->achrc_stor_addr_ss[ 0 ] = dsl_astr1.achc_stor_addr;  /* storage address */
   adsp_wvc1->imc_ss_ahead = 1;             /* swap storage in use     */
   adsp_wvc1->achc_vc_written = dsl_astr1.achc_stor_addr;  /* address written to virus-checking */
   adsp_wvc1->imc_index_re = 0;             /* index of dataset / chunk - read */
   adsp_wvc1->imc_index_wr = 0;             /* index of dataset / chunk - write */
#ifdef XYZ1
   adsp_wvc1->boc_eof = FALSE;              /* end-of-file reached     */
#endif
   adsp_wvc1->iec_vcend = ied_vcend_normal;  /* normal state, not yet end */
   return TRUE;
} /* end m_work_vc_init()                                              */

/** end of virus-checking                                              */
static BOOL m_work_vc_end( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                           struct dsd_work_vch_1 *adsp_wvc1,  /* virus-checking */
                           struct dsd_dash_work_all *adsp_dwa,  /* all dash operations work area */
                           char *achp_end, BOOL *abop_call_vc ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml_ind_req;                  /* index of request        */
   struct dsd_se_vch_req_1 *adsl_sevchreq1_w1;  /* temporary element in chain */
   union {
#ifdef XYZ1
     struct dsd_aux_service_query_1 dsl_aux_sequ1;  /* service query   */
#endif
     struct dsd_aux_swap_stor_req_1 dsl_astr1;  /* swap storage request */
   };

#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_work_vc_end() ->iec_vcend=%d",
                 __LINE__, adsp_wvc1->iec_vcend );
#endif
   if (adsp_wvc1->iec_vcend == ied_vcend_wait_send_end) {  /* wait to send end to virus-checker */
     goto p_wvce_40;                        /* send end to virus-checker */
   }
   if (adsp_wvc1->iec_vcend != ied_vcend_recv_end) {  /* end input received   */
     return TRUE;
   }
   if (adsp_wvc1->imc_ss_ahead > 1) {       /* swap storage in use     */
     return TRUE;
   }
   if (achp_end != adsp_wvc1->achrc_stor_addr_ss[ 0 ]) {
     goto p_wvce_20;                        /* continue end            */
   }
// to-do 01.01.15 KB - may never happen, as virus-checking is only started when really data read
   memset( &dsl_astr1, 0, sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   dsl_astr1.iec_swsc = ied_swsc_release;  /* release swap storage chunk */
   dsl_astr1.vpc_aux_swap_stor_handle = adsp_wvc1->vpc_aux_swap_stor_handle;  /* handle of swap storage */
   dsl_astr1.imc_index = adsp_wvc1->imc_index_re;  /* index of dataset / chunk - read */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_SWAP_STOR,  /* manage swap storage */
                                         &dsl_astr1,  /* swap storage request */
                                         sizeof(struct dsd_aux_swap_stor_req_1) );  /* swap storage request */
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   if (dsl_astr1.iec_swsr != ied_swsr_ok) {  /* o.k.                   */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W DEF_AUX_SWAP_STOR returned error %d.",
                   __LINE__, dsl_astr1.iec_swsr );
     return FALSE;
   }
   adsp_wvc1->imc_index_re--;               /* index of dataset / chunk - read */
   adsp_wvc1->imc_ss_ahead = 0;             /* swap storage in use     */
   adsp_wvc1->iec_vcend = ied_vcend_wait_send_end;  /* wait to send end to virus-checker */
   goto p_wvce_40;                          /* send end to virus-checker */

   p_wvce_20:                               /* continue end            */
   if (adsp_wvc1->achc_vc_written == achp_end) {  /* address written to virus-checking */
     goto p_wvce_32;                        /* last output sent to virus-checker */
   }
   iml_ind_req = 0;                         /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ].iec_stat) < 0) break;  /* check unused */
     iml_ind_req++;                         /* increment index         */
   } while (iml_ind_req < NO_VC_REQ1);      /* number of concurrent requests */
   if (iml_ind_req >= NO_VC_REQ1) {         /* number of concurrent requests */
#ifdef TRACEHL1
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_wvce_20: buffer full, wait virus-checker, set boc_wait_window",
                   __LINE__ );
#endif
     adsp_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     *abop_call_vc = TRUE;                  /* call virus-checking     */
     return TRUE;                           /* wait till virus-checker has processed more */
   }
   adsp_wvc1->dsrc_gai1_vch_data[ iml_ind_req ].achc_ginp_cur = adsp_wvc1->achc_vc_written;  /* address written to virus-checking */
   adsp_wvc1->dsrc_gai1_vch_data[ iml_ind_req ].achc_ginp_end = achp_end;
   adsp_wvc1->dsrc_gai1_vch_data[ iml_ind_req ].adsc_next = NULL;
   adsp_wvc1->achrc_stor_addr_vc[ iml_ind_req ] = adsp_wvc1->achrc_stor_addr_ss[ 0 ];  /* storage address */
   memset( &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ].adsc_gai1_data = &adsp_wvc1->dsrc_gai1_vch_data[ iml_ind_req ];
   adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ].iec_vchreq1 = ied_vchreq_content;  /* content of file */
   if (adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ];
   }
   adsp_wvc1->dsc_sevchcontr1.ilc_window_1
     += achp_end - adsp_wvc1->achc_vc_written;
   *abop_call_vc = TRUE;                    /* call virus-checking     */

   p_wvce_32:                               /* last output sent to virus-checker */
   adsp_wvc1->iec_vcend = ied_vcend_wait_send_end;  /* wait to send end to virus-checker */

   p_wvce_40:                               /* send end to virus-checker */
#ifdef TRACEHL1
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_work_vc_end() p_wvce_40: send end to virus-checker",
                 __LINE__ );
#endif
   iml_ind_req = 0;                         /* index start             */
   do {                                     /* loop to set elements unused */
     if (*((int *) &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ].iec_stat) < 0) break;  /* check unused */
     iml_ind_req++;                         /* increment index         */
   } while (iml_ind_req < NO_VC_REQ1);      /* number of concurrent requests */
   if (iml_ind_req >= NO_VC_REQ1) {         /* number of concurrent requests */
#ifdef TRACEHL1
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T p_wvce_40: buffer full, wait virus-checker, set boc_wait_window",
                   __LINE__ );
#endif
     adsp_wvc1->dsc_sevchcontr1.boc_wait_window = TRUE;  /* wait till window smaller */
     *abop_call_vc = TRUE;                  /* call virus-checking     */
     return TRUE;                           /* wait till virus-checker has processed more */
   }
   memset( &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ], 0, sizeof(struct dsd_se_vch_req_1) );  /* service virus checking request */
   adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ].iec_vchreq1 = ied_vchreq_eof;  /* End-of-File */
   if (adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1 == NULL) {
     adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1 = &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ];
   } else {                                 /* append to chain         */
     adsl_sevchreq1_w1 = adsp_wvc1->dsc_sevchcontr1.adsc_sevchreq1;
     while (adsl_sevchreq1_w1->adsc_next) adsl_sevchreq1_w1 = adsl_sevchreq1_w1->adsc_next;
     adsl_sevchreq1_w1->adsc_next = &adsp_wvc1->dsrc_sevchreq1[ iml_ind_req ];
   }
   *abop_call_vc = TRUE;                    /* call virus-checking     */
   adsp_wvc1->iec_vcend = ied_vcend_end_sent;  /* end sent to virus-checker */
   return TRUE;
} /* end m_work_vc_end()                                               */

/** read the synchronize file                                          */
static BOOL m_read_xml_sync_file( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                  struct dsd_unicode_string *adsp_ucs_fn,
                                  struct dsd_dir_bl_1 **aadsp_db1,
                                  HL_LONGLONG *ailc_sum_size_local ) {
   BOOL       bol_rc;                       /* return code             */
#ifdef XYZ1
   int        iml_rc;                       /* return code             */
#endif
   int        iml1, iml2;                   /* working variables       */
   int        iml_cmp;                      /* compare value           */
   int        iml_tab_l1;                   /* index table level one   */
   int        iml_tab_l2;                   /* index table level two   */
   int        iml_l2_flags;                 /* flags level two         */
   int        iml_len_fn;                   /* length file-name        */
   int        iml_len_dir;                  /* length directory-name   */
   int        iml_dir_nesting;              /* count directory nesting */
   enum ied_nodetype iel_nt;                /* DOM node type           */
   DWORD      dwl_error;                    /* return errors           */
   unsigned int uml_len_file;               /* length of file          */
   char       *achl_w1;                     /* working variable        */
   char       *achl_file;                   /* content of file         */
   char       *achl_error;                  /* error message           */
   void *     al_parser;
   void *     al_node_l0;
   void *     al_node_l1;
   void *     al_node_l2;
   void *     al_node_l3;
   struct dsd_dir_bl_1 *adsl_db1_start;     /* directory block 1 - chaining - start */
   struct dsd_dir_bl_1 *adsl_db1_cur;       /* directory block 1 - chaining - current */
   struct dsd_dir_bl_1 *adsl_db1_last;      /* directory block 1 - chaining - last */
   struct dsd_file_1 *adsl_f1_cur;          /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_next;         /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_w1;           /* entry of a single file  */
   struct dsd_file_1 *adsl_file_1_parent;   /* entry of parent directory */
   char       *achl_fn_low;                 /* low address of file names */
   struct dsd_unicode_string *adsl_ucs_w1;  /* working variable        */
#ifdef XYZ1
   struct dsd_unicode_string dsl_ucs_virus;  /* virus name             */
#endif
   struct dsd_unicode_string dsl_ucs_virus_client;  /* client virus name */
   struct dsd_unicode_string dsl_ucs_virus_server;  /* server virus name */
   struct dsd_unicode_string dsl_ucs_l;     /* working variable        */
   struct dsd_file_1 dsl_file_1_dir;        /* entry of parent directory for searching */
#ifdef XYZ1
   class dsd_file_read_1 dsl_file_read_1;   /* class read input file   */
#endif
   struct dsd_xml_parser_cbs dsl_xml_parser_cbs;
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   int        imrl_dir_nesting[ MAX_DIR_STACK ];  /* stack entry directory */
   union {
     HL_WCHAR wcrl_file_name[ LEN_FILE_NAME ];
     char     byrl_file_name[ LEN_FILE_NAME ];
     struct dsd_aux_file_io_req_1 dsl_afior1;  /* file IO request      */
   };
   char       byrl_directory_name[ LEN_FILE_NAME ];

   *aadsp_db1 = NULL;                       /* nothing to return yet   */
   if (ailc_sum_size_local) {
     *ailc_sum_size_local = NULL;
   }
   memset( &dsl_afior1, 0, sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   dsl_afior1.dsc_ucs_file_name = *adsp_ucs_fn;  /* name of file       */
   dsl_afior1.iec_fioc = ied_fioc_compl_file_read;  /* read complete file */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_FILE_IO,  /* file input-output */
                                         &dsl_afior1,  /* file IO request */
                                         sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   if (bol_rc == FALSE) {                   /* returned error          */
     return FALSE;
   }
   if (dsl_afior1.iec_fior == ied_fior_file_not_found) {  /* The system cannot find the file specified. ERROR_FILE_NOT_FOUND */
     ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
       ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing     */
     return TRUE;                           /* nothing to do           */
   }
   if (dsl_afior1.iec_fior != ied_fior_ok) {  /* o.k.                  */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() synchonize file DEF_AUX_FILE_IO read error %d/%d.",
                   __LINE__, dsl_afior1.iec_fior, dsl_afior1.imc_error );
     return FALSE;
   }
   if (dsl_afior1.ilc_len_data == 0) {      /* length of data NULL     */
     ((struct dsd_dash_work_all *) adsp_sdh_call_1->adsc_cl1d1_1->ac_work_data)  /* all dash operations work area */
       ->umc_state |= DWA_STATE_XML_WRITE;  /* state of processing     */
     return TRUE;                           /* nothing to do           */
   }
   achl_file = dsl_afior1.achc_data;        /* address of data         */
   uml_len_file = dsl_afior1.ilc_len_data;  /* length of data          */
#ifdef XYZ1
   iml_rc = m_cpy_vx_ucs( wcrl_file_name, LEN_FILE_NAME,  ied_chs_utf_16,
                          adsp_ucs_fn );
   if (iml_rc <= 0) {
     m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() synchonize file file-name too long",
                   __LINE__ );
     return FALSE;
   }
   bol_rc = dsl_file_read_1.m_readfile( wcrl_file_name,
                                        &achl_file,
                                        &uml_len_file,
                                        &dwl_error );
   if (bol_rc == FALSE) {                   /* no file loaded          */
     if (dwl_error == ERROR_FILE_NOT_FOUND) {
       return TRUE;
     }
     m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() synchonize file read error %d.",
                   __LINE__, dwl_error );
     return FALSE;
   }
#endif
   memset( &dsl_xml_parser_cbs, 0, sizeof(struct dsd_xml_parser_cbs) );
   dsl_xml_parser_cbs.amc_alloc = &m_sub_alloc;
   dsl_xml_parser_cbs.amc_free = &m_sub_free;
   dsl_xml_parser_cbs.avc_usrfld = adsp_sdh_call_1;  /* user field for callbacks */

   al_parser = m_new_xml_parser( &dsl_xml_parser_cbs );
   if (al_parser == NULL) {                 /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_new_xml_parser() failed",
                   __LINE__ );
#ifdef XYZ1
     free( achl_file );                     /* free content of file again */
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &achl_file,
                                           0 );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
     return FALSE;
   }

   al_node_l0 = m_parse_xml( al_parser, achl_file, uml_len_file );
   if (al_node_l0 == NULL) {                /* error occured           */
     achl_error = m_get_lasterror( al_parser );
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_parse_xml() failed %s.",
                   __LINE__, achl_error );
     m_delete_xml_parser( &al_parser );
#ifdef XYZ1
     free( achl_file );                     /* free content of file again */
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &achl_file,
                                           0 );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
     return FALSE;
   }
   adsl_f1_cur = NULL;                      /* entry of a single file  */
   adsl_db1_start = NULL;                   /* directory block 1 - chaining - start */
   iml_len_dir = 0;                         /* length directory-name   */

#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (adsl_db1_start + 1))

   p_l0_00:                                 /* get node level zero     */
   iel_nt = m_get_nodetype( al_node_l0 );
   if (iel_nt != ied_nt_node) {
     al_node_l0 = m_get_nextsibling( al_node_l0 );
     if (al_node_l0) {
       goto p_l0_00;                        /* get node level zero     */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() did not find node level zero",
                   __LINE__ );
     m_delete_xml_parser( &al_parser );
#ifdef XYZ1
     free( achl_file );                     /* free content of file again */
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &achl_file,
                                           0 );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
     return FALSE;
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l0 );
   dsl_ucs_l.ac_str = (void *) XML_NODE_L0;
   dsl_ucs_l.imc_len_str = -1;
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* Unicode UTF-8           */
   bol_rc = m_cmp_ucs_ucs( &iml_cmp, adsl_ucs_w1, &dsl_ucs_l );
   if ((bol_rc == FALSE) || (iml_cmp)) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() invalid node level zero \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     m_delete_xml_parser( &al_parser );
#ifdef XYZ1
     free( achl_file );                     /* free content of file again */
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &achl_file,
                                           0 );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
     return FALSE;
   }
   al_node_l1 = m_get_firstchild( al_node_l0 );
   if (al_node_l1 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() did not find node level one",
                   __LINE__ );
     m_delete_xml_parser( &al_parser );
#ifdef XYZ1
     free( achl_file );                     /* free content of file again */
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &achl_file,
                                           0 );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
     return FALSE;
   }

   p_l1_00:                                 /* get node level one      */
   iel_nt = m_get_nodetype( al_node_l1 );
   if (iel_nt != ied_nt_node) {
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l1 );
   iml_tab_l1 = sizeof(achrs_kw_level_1) / sizeof(achrs_kw_level_1[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_kw_level_1[ iml_tab_l1 ];
     bol_rc = m_cmp_ucs_ucs( &iml_cmp, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_cmp == 0)) break;
     iml_tab_l1--;                          /* decrement index         */
   } while (iml_tab_l1 >= 0);
   if (iml_tab_l1 < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() invalid node level one \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   al_node_l2 = m_get_firstchild( al_node_l1 );
   if (al_node_l2 == NULL) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() did not find node level two",
                   __LINE__ );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   iml_l2_flags = 0;                        /* flags level two         */
   if (adsl_f1_cur == NULL) {               /* entry of a single file  */
     if (   (adsl_db1_start == NULL)        /* directory block 1 - chaining - start */
         || (((char *) (adsl_f1_next + 1)) > achl_fn_low)) {
       bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                          DEF_AUX_MEMGET,
                                          &adsl_db1_cur,
                                          LEN_DIR_BLOCK );
       if (bol_rc == FALSE) {               /* error occured           */
         return FALSE;
       }
       if (adsl_db1_start == NULL) {        /* directory block 1 - chaining - start */
         adsl_db1_start = adsl_db1_cur;     /* directory block 1 - chaining - start */
         adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_start + 1) + sizeof(struct dsd_dir_bl_2));
         ADSL_DB2_G->imc_no_files = 0;      /* number of files         */
         ADSL_DB2_G->imc_no_dir = 0;        /* number of directories   */
         ADSL_DB2_G->boc_unix = FALSE;      /* is Unix filesystem      */
         bol_rc = m_htree1_avl_init( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                     &m_cmp_file );
         if (bol_rc == FALSE) {             /* error occured           */
           m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_htree1_avl_init() failed",
                         __LINE__ );
           return FALSE;
         }
       } else {
         adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
         adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
         adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
       }
       adsl_db1_last = adsl_db1_cur;        /* directory block 1 - chaining - last */
       achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
     }
     adsl_f1_cur = adsl_f1_next;            /* get next file entry     */
   }
   memset( adsl_f1_cur, 0, sizeof(struct dsd_file_1) );  /* entry of a single file  */

   p_l2_00:                                 /* get node level two      */
   iel_nt = m_get_nodetype( al_node_l2 );
   if (iel_nt != ied_nt_node) {
     goto p_l2_40;                          /* get next node level two */
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l2 );
   iml_tab_l2 = sizeof(achrs_kw_level_2) / sizeof(achrs_kw_level_2[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_kw_level_2[ iml_tab_l2 ];
     bol_rc = m_cmp_ucs_ucs( &iml_cmp, adsl_ucs_w1, &dsl_ucs_l );
     if ((bol_rc) && (iml_cmp == 0)) break;
     iml_tab_l2--;                          /* decrement index         */
   } while (iml_tab_l2 >= 0);
   if (iml_tab_l2 < 0) {                    /* not found in table      */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() invalid node level two \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
   }
   if (iml_l2_flags & M_BIT_OF( iml_tab_l2 )) {  /* flags level two    */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() node level one \"%.*s\" double",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
     goto p_l2_40;                          /* get next node level two */
   }
   al_node_l3 = m_get_firstchild( al_node_l2 );

   p_l3_00:                                 /* get text level three    */
   iel_nt = m_get_nodetype( al_node_l3 );
   if (iel_nt != ied_nt_text) {
     al_node_l3 = m_get_nextsibling( al_node_l3 );
     if (al_node_l3) {
       goto p_l3_00;                        /* get text level three    */
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() did not find text level three node \"%.*s\"",
                   __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
   }
   adsl_ucs_w1 = m_get_node_value( al_node_l3 );
   switch (iml_tab_l2) {                    /* index table level two   */
     case KW_L2_NAME:
       iml_len_fn = m_cpy_vx_ucs( byrl_file_name, sizeof(byrl_file_name), ied_chs_utf_8,  /* Unicode UTF-8   */
                                  adsl_ucs_w1 );
       if (iml_len_fn > 0) break;
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file-name \"%.*s\" invalid",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_l2_40;                        /* get next node level two */
     case KW_L2_ATTR:
       bol_rc = m_get_ucs_hex( (unsigned int *) &adsl_f1_cur->dwc_file_attributes, adsl_ucs_w1 );
       if (bol_rc) break;
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() attributes \"%.*s\" invalid",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_l2_40;                        /* get next node level two */
     case KW_L2_LWT:
       bol_rc = m_get_ucs_longlong( (HL_LONGLONG *) &adsl_f1_cur->dsc_last_write_time, adsl_ucs_w1 );
       if (bol_rc) break;
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() time-last-write \"%.*s\" invalid",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_l2_40;                        /* get next node level two */
     case KW_L2_SIZE:
       bol_rc = m_get_ucs_longlong( &adsl_f1_cur->ilc_file_size, adsl_ucs_w1 );
       if (bol_rc) break;
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() size \"%.*s\" invalid",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_l2_40;                        /* get next node level two */
     case KW_L2_STATE:
       bol_rc = m_get_ucs_hex( (unsigned int *) &adsl_f1_cur->umc_flags, adsl_ucs_w1 );
       if (bol_rc) break;
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() error-state \"%.*s\" invalid",
                     __LINE__, adsl_ucs_w1->imc_len_str, adsl_ucs_w1->ac_str );
       goto p_l2_40;                        /* get next node level two */
#ifdef XYZ1
     case KW_L2_VIRUS:
       dsl_ucs_virus = *adsl_ucs_w1;        /* virus name              */
       break;
#endif
     case KW_L2_VIR_CL:
       dsl_ucs_virus_client = *adsl_ucs_w1;  /* client virus name      */
       break;
     case KW_L2_VIR_SE:
       dsl_ucs_virus_server = *adsl_ucs_w1;  /* server virus name      */
       break;
   }
   iml_l2_flags |= M_BIT_OF( iml_tab_l2 );  /* flags level two         */

   p_l2_40:                                 /* get next node level two */
   al_node_l2 = m_get_nextsibling( al_node_l2 );
   if (al_node_l2) {
     goto p_l2_00;                          /* get node level two      */
   }

   p_l2_60:                                 /* end of nodes level two  */
#ifdef XYZ1
   if ((iml_l2_flags & (M_BIT_OF( KW_L2_NAME ) | M_BIT_OF( KW_L2_ATTR ) | M_BIT_OF( KW_L2_LWT ) | M_BIT_OF( KW_L2_SIZE )))  /* flags level two */
         != (M_BIT_OF( KW_L2_NAME ) | M_BIT_OF( KW_L2_ATTR ) | M_BIT_OF( KW_L2_LWT ) | M_BIT_OF( KW_L2_SIZE ))) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory information missing",
                   __LINE__ );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
#endif
   iml1 = M_BIT_OF( KW_L2_NAME ) | M_BIT_OF( KW_L2_ATTR ) | M_BIT_OF( KW_L2_LWT ) | M_BIT_OF( KW_L2_SIZE );
   if (   (iml_l2_flags & M_BIT_OF( KW_L2_ATTR ))
       && (adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
     iml1 = M_BIT_OF( KW_L2_NAME ) | M_BIT_OF( KW_L2_ATTR );
   }
   if ((iml_l2_flags & iml1) != iml1) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory information missing",
                   __LINE__ );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   while (   (iml_len_fn > 0)
          && (*(byrl_file_name + iml_len_fn) == '/')) {
     iml_len_fn--;
   }
   if (iml_len_fn <= 0) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory invalid file-name",
                   __LINE__ );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   dsl_file_1_dir.dwc_file_attributes = 0;
   if (iml_tab_l1 == 0) {                   /* node directory          */
     dsl_file_1_dir.dwc_file_attributes = FILE_ATTRIBUTE_DIRECTORY;
   }
   if ((adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != (dsl_file_1_dir.dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" directory information FILE_ATTRIBUTE_DIRECTORY invalid",
                   __LINE__, iml_len_fn, byrl_file_name );
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   iml_dir_nesting = 0;                     /* count directory nesting */
   iml1 = 0;                                /* clear position          */

   p_fi_dir_20:                             /* get directory nesting   */
   achl_w1 = (char *) memchr( byrl_file_name + iml1, '/', iml_len_fn - iml1 );
   if (achl_w1) {                           /* character found         */
     if (achl_w1 == (byrl_file_name + iml1)) {
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" directory nesting double slashes",
                     __LINE__, iml_len_fn, byrl_file_name );
       goto p_fi_dir_80;                    /* end of file / directory */
     }
     if (iml_dir_nesting >= MAX_DIR_STACK) {  /* check directory nesting */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" nesting of directories too deep",
                     __LINE__, iml_len_fn, byrl_file_name );
       goto p_fi_dir_80;                    /* end of file / directory */
     }
     iml1 = achl_w1 - byrl_file_name;       /* compute position        */
     imrl_dir_nesting[ iml_dir_nesting ] = iml1;
     iml_dir_nesting++;                     /* count directory nesting */
     iml1++;                                /* after slash             */
     goto p_fi_dir_20;                      /* get directory nesting   */
   }
   iml1 = 0;                                /* start of file-name      */
   if (iml_dir_nesting > 0) {               /* check directory nesting */
     iml1 = imrl_dir_nesting[ iml_dir_nesting - 1 ] + 1;  /* start of file-name */
   }
   adsl_f1_cur->dsc_ucs_file.ac_str = byrl_file_name + iml1;
   adsl_f1_cur->dsc_ucs_file.imc_len_str = iml_len_fn - iml1;
   adsl_f1_cur->dsc_ucs_file.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   if (iml_dir_nesting == 0) {              /* check directory nesting */
     goto p_fi_dir_40;                      /* directory information complete */
   }
   if (   (iml_len_dir == imrl_dir_nesting[ iml_dir_nesting - 1 ])  /* length directory-name */
       && (!memcmp( byrl_file_name, byrl_directory_name, iml_len_dir ))) {
     adsl_f1_cur->adsc_file_1_parent = adsl_file_1_parent;  /* entry of parent directory */
     goto p_fi_dir_40;                      /* directory information complete */
   }

   iml_len_dir = imrl_dir_nesting[ iml_dir_nesting - 1 ];  /* length directory-name */
   memcpy( byrl_directory_name, byrl_file_name, iml_len_dir );

   /* search all directories                                           */
   iml1 = 0;                                /* start at root           */
   adsl_file_1_parent = NULL;               /* entry of parent directory */

   p_fi_dir_28:                             /* get next nested directory */
   iml2 = 0;                                /* set start               */
   if (iml1 > 0) {                          /* check directory nesting */
     iml2 = imrl_dir_nesting[ iml1 - 1 ] + 1;  /* start of file-name   */
   }

   dsl_file_1_dir.dsc_ucs_file.ac_str = byrl_file_name + iml2;
   dsl_file_1_dir.dsc_ucs_file.imc_len_str = imrl_dir_nesting[ iml1 ] - iml2;
   dsl_file_1_dir.dsc_ucs_file.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8 */
   dsl_file_1_dir.adsc_file_1_parent = adsl_file_1_parent;  /* entry of parent directory */

   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &dsl_file_1_dir.dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_htree1_avl_search() failed",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree     */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" nesting of directories not defined",
                   __LINE__, iml_len_fn, byrl_file_name );
     iml_len_dir = 0;                       /* length directory-name   */
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   adsl_file_1_parent = (struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 ));
   if ((adsl_file_1_parent->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() file / directory \"%.*s\" nesting of directories found normal file",
                   __LINE__, iml_len_fn, byrl_file_name );
     iml_len_dir = 0;                       /* length directory-name   */
     goto p_fi_dir_80;                      /* end of file / directory */
   }
   iml1++;                                  /* next stage              */
   if (iml1 < iml_dir_nesting) {            /* check directory nesting */
     goto p_fi_dir_28;                      /* get next nested directory */
   }
   adsl_f1_cur->adsc_file_1_parent = adsl_file_1_parent;  /* entry of parent directory */

   p_fi_dir_40:                             /* directory information complete */
   if (adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     ADSL_DB2_G->imc_no_dir++;              /* number of directories   */
   }
   ADSL_DB2_G->imc_no_files++;              /* number of files         */
   if (   (ailc_sum_size_local)
       && ((adsl_f1_cur->umc_flags & D_FILE_1_FLAG_NOT_CL) == 0)) {  /* file not on client */
     *ailc_sum_size_local += adsl_f1_cur->ilc_file_size;  /* size of file */
   }

   /* add file to AVL-tree                                             */
   bol_rc = m_htree1_avl_search( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &adsl_f1_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_htree1_avl_search() failed",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }
   if (dsl_htree1_work.adsc_found) {        /* found in tree           */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
     if (ADSL_F1_SORT->adsc_file_1_same_n == NULL) {  /* chain of entries same name */
       ADSL_F1_SORT->adsc_file_1_same_n = adsl_f1_cur;  /* chain of entries same name */
     } else {                               /* already files with same name */
       adsl_f1_w1 = ADSL_F1_SORT->adsc_file_1_same_n;  /* get chain of entries same name */
       while (adsl_f1_w1->adsc_file_1_same_n) {  /* check chain of entries same name */
         adsl_f1_w1 = adsl_f1_w1->adsc_file_1_same_n;  /* next in chain of entries same name */
       }
       adsl_f1_w1->adsc_file_1_same_n = adsl_f1_cur;  /* append to chain of entries same name */
     }
     goto p_fi_dir_48;                      /* end of this file        */
#undef ADSL_F1_SORT
   }
   bol_rc = m_htree1_avl_insert( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                 &dsl_htree1_work, &adsl_f1_cur->dsc_sort_1 );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_read_xml_sync_file() m_htree1_avl_insert() failed",
                   __LINE__ );
     goto p_ret_error;                      /* return error            */
   }

   p_fi_dir_48:                             /* end of this file        */
   adsl_f1_next++;                          /* entry of a single file  */
   /* set correct file-name                                            */
   if (((char *) adsl_f1_next) > (achl_fn_low - adsl_f1_cur->dsc_ucs_file.imc_len_str)) {
#ifdef XYZ1
     adsl_db1_cur = (struct dsd_dir_bl_1 *) malloc( LEN_DIR_BLOCK );
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMGET,  /* get some memory */
                                           &adsl_db1_cur,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       return FALSE;
     }
     adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
     adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
     adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
     adsl_db1_last = adsl_db1_cur;          /* directory block 1 - chaining - last */
     achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   achl_fn_low -= adsl_f1_cur->dsc_ucs_file.imc_len_str;
   memcpy( achl_fn_low, adsl_f1_cur->dsc_ucs_file.ac_str, adsl_f1_cur->dsc_ucs_file.imc_len_str );
   adsl_f1_cur->dsc_ucs_file.ac_str = achl_fn_low;
#ifdef XYZ1
   if ((iml_l2_flags & M_BIT_OF( KW_L2_VIRUS )) == 0) {  /* flags level two - virus */
     goto p_fi_dir_60;                      /* all fields set          */
   }
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_ucs_virus )
            + 1;
   if (((char *) adsl_f1_next) > (achl_fn_low - iml1)) {
     adsl_db1_cur = (struct dsd_dir_bl_1 *) malloc( LEN_DIR_BLOCK );
     adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
     adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
     adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
     adsl_db1_last = adsl_db1_cur;          /* directory block 1 - chaining - last */
     achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   achl_fn_low -= iml1;
   m_cpy_vx_ucs( achl_fn_low, iml1, ied_chs_utf_8,  /* Unicode UTF-8   */
                 &dsl_ucs_virus );
// adsl_f1_cur->achc_virus = achl_fn_low;   /* virus found             */
#endif
   if ((iml_l2_flags & M_BIT_OF( KW_L2_VIR_CL )) == 0) {  /* flags level two - virus client */
     goto p_fi_dir_52;                      /* check virus server      */
   }
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_ucs_virus_client )
            + 1;
   if (((char *) adsl_f1_next) > (achl_fn_low - iml1)) {
#ifdef XYZ1
     adsl_db1_cur = (struct dsd_dir_bl_1 *) malloc( LEN_DIR_BLOCK );
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMGET,  /* get some memory */
                                           &adsl_db1_cur,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       return FALSE;
     }
     adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
     adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
     adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
     adsl_db1_last = adsl_db1_cur;          /* directory block 1 - chaining - last */
     achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   achl_fn_low -= iml1;
   m_cpy_vx_ucs( achl_fn_low, iml1, ied_chs_utf_8,  /* Unicode UTF-8   */
                 &dsl_ucs_virus_client );
   adsl_f1_cur->achc_virus_client = achl_fn_low;  /* virus found on client */

   p_fi_dir_52:                             /* check virus server      */
   if ((iml_l2_flags & M_BIT_OF( KW_L2_VIR_SE )) == 0) {  /* flags level two - virus server */
     goto p_fi_dir_60;                      /* all fields set          */
   }
   iml1 = m_len_vx_ucs( ied_chs_utf_8,      /* Unicode UTF-8           */
                        &dsl_ucs_virus_server )
            + 1;
   if (((char *) adsl_f1_next) > (achl_fn_low - iml1)) {
#ifdef XYZ1
     adsl_db1_cur = (struct dsd_dir_bl_1 *) malloc( LEN_DIR_BLOCK );
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMGET,  /* get some memory */
                                           &adsl_db1_cur,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* error occured           */
       return FALSE;
     }
     adsl_db1_last->adsc_next = adsl_db1_cur;  /* directory block 1 - chaining */
     adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
     adsl_f1_next = (struct dsd_file_1 *) ((char *) (adsl_db1_cur + 1));
     adsl_db1_last = adsl_db1_cur;          /* directory block 1 - chaining - last */
     achl_fn_low = (char *) adsl_db1_cur + LEN_DIR_BLOCK;  /* low address of file names */
   }
   achl_fn_low -= iml1;
   m_cpy_vx_ucs( achl_fn_low, iml1, ied_chs_utf_8,  /* Unicode UTF-8   */
                 &dsl_ucs_virus_server );
   adsl_f1_cur->achc_virus_server = achl_fn_low;  /* virus found on server */

   p_fi_dir_60:                             /* all fields set          */
   adsl_f1_cur = NULL;                      /* entry of a single file  */

   p_fi_dir_80:                             /* end of file / directory */
   al_node_l1 = m_get_nextsibling( al_node_l1 );
   if (al_node_l1) {
     goto p_l1_00;                          /* get node level one      */
   }

   m_delete_xml_parser( &al_parser );
#ifdef XYZ1
   free( achl_file );                       /* free content of file again */
#endif
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,
                                         &achl_file,
                                         0 );
   if (bol_rc == FALSE) {                   /* returned error          */
     return FALSE;
   }
   if (adsl_db1_start == NULL) return TRUE;  /* directory block 1 - chaining - start */
   adsl_db1_last->adsc_next = NULL;         /* directory block 1 - chaining */
   adsl_db1_last->achc_end_file = (char *) adsl_f1_next;  /* end of files */
   *aadsp_db1 = adsl_db1_start;             /* set what to return      */
   return TRUE;

   p_ret_error:                             /* return error            */
   m_delete_xml_parser( &al_parser );
#ifdef XYZ1
   free( achl_file );                       /* free content of file again */
#endif
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,
                                         &achl_file,
                                         0 );
   if (bol_rc == FALSE) {                   /* returned error          */
     return FALSE;
   }
   while (adsl_db1_start) {                 /* directory block 1 - chaining - start */
     adsl_db1_cur = adsl_db1_start;
     adsl_db1_start = adsl_db1_cur->adsc_next;
#ifdef XYZ1
     free( adsl_db1_cur );
#endif
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &adsl_db1_cur,
                                           LEN_DIR_BLOCK );
//   if (bol_rc == FALSE) {                 /* returned error          */
//     return FALSE;
//   }
   }
   return FALSE;
#undef ADSL_DB2_G
} /* end m_read_xml_sync_file()                                        */

#define M_CPY_XML_TEXT( ACHL_P, IML_P ) \
   if (IML_P > (achl_out_end - achl_out_cur)) { \
     adsl_xdb_last->achc_end_data = achl_out_cur;  /* end of data      */ \
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld, \
                                           DEF_AUX_MEMGET,  /* get some memory */ \
                                           &adsl_xdb_cur, \
                                           LEN_DIR_BLOCK ); \
     if (bol_rc == FALSE) {                 /* error occured           */ \
       return FALSE; \
     } \
     adsl_xdb_last->adsc_next = adsl_xdb_cur; \
     adsl_xdb_last = adsl_xdb_cur;  \
     achl_out_cur                           /* current output          */ \
       = (char *) (adsl_xdb_cur + 1) + sizeof(ucrs_xml_start); \
     achl_out_end = (char *) adsl_xdb_cur + LEN_DIR_BLOCK;  /* end of output */ \
   } \
/* to-do 03.01.14 KB - use Unicode-library for XML encoding */ \
   memcpy( achl_out_cur, ACHL_P, IML_P ); \
   achl_out_cur += IML_P;

#define M_CPY_XML_UCS \
   iml1 = m_len_vx_ucs( ied_chs_xml_utf_8,  /* XML Unicode UTF-8       */ \
                        &dsl_ucs_l ); \
   if (iml1 > (achl_out_end - achl_out_cur)) { \
     adsl_xdb_last->achc_end_data = achl_out_cur;  /* end of data      */ \
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld, \
                                           DEF_AUX_MEMGET,  /* get some memory */ \
                                           &adsl_xdb_cur, \
                                           LEN_DIR_BLOCK ); \
     if (bol_rc == FALSE) {                 /* error occured           */ \
       return FALSE; \
     } \
     adsl_xdb_last->adsc_next = adsl_xdb_cur; \
     adsl_xdb_last = adsl_xdb_cur;  \
     achl_out_cur                           /* current output          */ \
       = (char *) (adsl_xdb_cur + 1) + sizeof(ucrs_xml_start); \
     achl_out_end = (char *) adsl_xdb_cur + LEN_DIR_BLOCK;  /* end of output */ \
   } \
/* to-do 03.01.14 KB - use Unicode-library for XML encoding */ \
   m_cpy_vx_ucs( achl_out_cur, iml1, ied_chs_xml_utf_8, \
                        &dsl_ucs_l ); \
   achl_out_cur += iml1;

/** create the XML synchronize file                                    */
static BOOL m_create_xml_dir( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_xml_dir_bl **aadsp_xdb, struct dsd_dir_bl_1 *adsp_db1 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_first;                    /* AVL retrieve first entry */
   int        iml1;                         /* working variable        */
   int        iml_nesting;                  /* nesting of directories  */
   int        iml_pos_dn;                   /* position in directory name */
   unsigned int uml_w1;                     /* working variable        */
   HL_LONGLONG ill_w1;                      /* working variable        */
   char       *achl_w1;                     /* working variable        */
   char       *achl_out_cur;                /* current output          */
   char       *achl_out_end;                /* end of output           */
   struct dsd_xml_dir_bl *adsl_xdb_start;   /* XML directory block - chaining */
   struct dsd_xml_dir_bl *adsl_xdb_cur;     /* XML directory block - chaining */
   struct dsd_xml_dir_bl *adsl_xdb_last;    /* XML directory block - chaining */
#ifdef XYZ1
   struct dsd_dir_bl_1 *adsl_db1_cur;       /* directory block 1 - chaining - current */
#endif
   struct dsd_file_1 *adsl_f1_cur;          /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_dir;          /* entry of a single file  */
   struct dsd_unicode_string dsl_ucs_l;     /* working variable        */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   union {
     char     byrl_file_name[ LEN_FILE_NAME ];
     char     byrl_work1[ 128 ];
   };

#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (adsp_db1 + 1))

   *aadsp_xdb = NULL;                       /* nothing to return yet   */
#ifdef XYZ1
   adsl_xdb_start = adsl_xdb_cur = adsl_xdb_last
     = (struct dsd_xml_dir_bl *) malloc( LEN_DIR_BLOCK );
#endif
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_MEMGET,  /* get some memory */
                                         &adsl_xdb_start,
                                         LEN_DIR_BLOCK );
   if (bol_rc == FALSE) {                   /* error occured           */
     return FALSE;
   }
   adsl_xdb_cur = adsl_xdb_last = adsl_xdb_start;
   memcpy( adsl_xdb_start + 1,
           ucrs_xml_start,
           sizeof(ucrs_xml_start) );
   achl_out_cur                             /* current output          */
     = (char *) (adsl_xdb_start + 1) + sizeof(ucrs_xml_start);
   achl_out_end = (char *) adsl_xdb_start + LEN_DIR_BLOCK;  /* end of output */
   if (adsp_db1 == NULL) {                  /* no files found          */
     goto p_cxd_80;                         /* all files read          */
   }
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* Unicode UTF-8           */
   bol_first = TRUE;                        /* AVL retrieve first entry */

   p_cxd_00:                                /* start / continue reading files */
   bol_rc = m_htree1_avl_getnext( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                  &dsl_htree1_work, bol_first );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_create_xml_dir() m_htree1_avl_getnext() failed",
                   __LINE__ );
     return FALSE;
   }
   bol_first = FALSE;                       /* AVL retrieve first entry */
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file found     */
     goto p_cxd_80;                         /* all files read          */
   }
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
   adsl_f1_cur = ADSL_F1_SORT;              /* get entry found         */
#undef ADSL_F1_SORT

   p_cxd_20:                                /* output of entry         */
   if (adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     M_CPY_XML_TEXT( ucrs_xml_dir_start, sizeof(ucrs_xml_dir_start) )
   } else {
     M_CPY_XML_TEXT( ucrs_xml_file_start, sizeof(ucrs_xml_file_start) )
   }
   M_CPY_XML_TEXT( ucrs_xml_entry_t01, sizeof(ucrs_xml_entry_t01) )

   iml_nesting = 0;                         /* nesting of directories  */
   adsl_f1_dir = adsl_f1_cur;               /* get inner entry         */
   while (adsl_f1_dir->adsc_file_1_parent) {  /* entry of parent directory */
     adsl_f1_dir = adsl_f1_dir->adsc_file_1_parent;  /* get entry of parent directory */
     iml_nesting++;                         /* nesting of directories  */
   }
   iml_pos_dn = 0;                          /* position in directory name */

   p_cxd_fn:                                /* output of directory or file name */
   adsl_f1_dir = adsl_f1_cur;               /* get inner entry         */
   iml1 = iml_nesting;                      /* nesting of directories  */
   while (iml1 > 0) {                       /* need to get parent directory */
     adsl_f1_dir = adsl_f1_dir->adsc_file_1_parent;  /* get entry of parent directory */
     iml1--;                                /* nesting of directories  */
   }
   if ((iml_pos_dn + adsl_f1_dir->dsc_ucs_file.imc_len_str) >= sizeof(byrl_file_name)) {
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_create_xml_dir() file-name too long",
                   __LINE__ );
     return FALSE;
   }
   memcpy( byrl_file_name + iml_pos_dn,
           adsl_f1_dir->dsc_ucs_file.ac_str,
           adsl_f1_dir->dsc_ucs_file.imc_len_str );
   iml_pos_dn += adsl_f1_dir->dsc_ucs_file.imc_len_str;
   if (iml_nesting > 0) {                   /* nesting of directories  */
     iml_nesting--;                         /* nesting of directories  */
     byrl_file_name[ iml_pos_dn++ ] = '/';
     goto p_cxd_fn;                         /* output of directory or file name */
   }
#ifdef XYZ1
   M_CPY_XML_TEXT( byrl_file_name, iml_pos_dn )
#endif
   dsl_ucs_l.ac_str = byrl_file_name;
   dsl_ucs_l.imc_len_str = iml_pos_dn;
   M_CPY_XML_UCS

   M_CPY_XML_TEXT( ucrs_xml_entry_t02, sizeof(ucrs_xml_entry_t02) )
   uml_w1 = adsl_f1_cur->dwc_file_attributes;
   iml1 = 8;                                /* set counter             */
   do {
     iml1--;                                /* decrement counter       */
     byrl_work1[ iml1 ] = chrstrans[ uml_w1 & 0X0F ];
     uml_w1 >>= 4;                          /* remove half-byte        */
   } while (iml1 > 0);
   M_CPY_XML_TEXT( byrl_work1, 8 )
   M_CPY_XML_TEXT( ucrs_xml_entry_t03, sizeof(ucrs_xml_entry_t03) )

   if (adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     goto p_cxd_40;                         /* next part of output     */
   }
   M_CPY_XML_TEXT( ucrs_xml_entry_t04, sizeof(ucrs_xml_entry_t04) )
   ill_w1 = *((HL_LONGLONG *) &adsl_f1_cur->dsc_last_write_time);
   achl_w1 = byrl_work1 + sizeof(byrl_work1);
   do {
     *(--achl_w1) = (ill_w1 % 10) + '0';
     ill_w1 /= 10;
   } while (ill_w1 > 0);
   iml1 = (byrl_work1 + sizeof(byrl_work1)) - achl_w1;
   M_CPY_XML_TEXT( achl_w1, iml1 )
   M_CPY_XML_TEXT( ucrs_xml_entry_t05, sizeof(ucrs_xml_entry_t05) )
   ill_w1 = adsl_f1_cur->ilc_file_size;
   achl_w1 = byrl_work1 + sizeof(byrl_work1);
   do {
     *(--achl_w1) = (ill_w1 % 10) + '0';
     ill_w1 /= 10;
   } while (ill_w1 > 0);
   iml1 = (byrl_work1 + sizeof(byrl_work1)) - achl_w1;
   M_CPY_XML_TEXT( achl_w1, iml1 )
   M_CPY_XML_TEXT( ucrs_xml_entry_t06, sizeof(ucrs_xml_entry_t06) )
#ifdef XYZ1
// to-do 12.05.13 KB - virus
   if (adsl_f1_cur->achc_virus) {           /* virus found             */
     iml1 = strlen( adsl_f1_cur->achc_virus );  /* get length virus name */
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_sta, sizeof(ucrs_xml_entry_virus_sta) )
     M_CPY_XML_TEXT( adsl_f1_cur->achc_virus, iml1 );
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_end, sizeof(ucrs_xml_entry_virus_end) )
   }
#endif

   p_cxd_40:                                /* next part of output     */
   if (adsl_f1_cur->umc_flags) {            /* flags for processing    */
     M_CPY_XML_TEXT( ucrs_xml_entry_state_sta, sizeof(ucrs_xml_entry_state_sta) )
     uml_w1 = adsl_f1_cur->umc_flags;
     iml1 = 8;                              /* set counter             */
     do {
       iml1--;                              /* decrement counter       */
       byrl_work1[ iml1 ] = chrstrans[ uml_w1 & 0X0F ];
       uml_w1 >>= 4;                        /* remove half-byte        */
     } while (iml1 > 0);
     M_CPY_XML_TEXT( byrl_work1, 8 )
#ifdef XYZ1
     iml1 = 8;                              /* set counter             */
     do {
       iml1--;                              /* decrement counter       */
       byrl_work1[ 2 + iml1 ] = chrstrans[ uml_w1 & 0X0F ];
       uml_w1 >>= 4;                        /* remove half-byte        */
     } while (iml1 > 0);
     byrl_work1[ 0 ] = '0';
     byrl_work1[ 1 ] = 'X';
     M_CPY_XML_TEXT( byrl_work1, 10 )
#endif
     M_CPY_XML_TEXT( ucrs_xml_entry_state_end, sizeof(ucrs_xml_entry_state_end) )
   }
   if (adsl_f1_cur->achc_virus_client) {    /* virus found on client   */
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_client_sta, sizeof(ucrs_xml_entry_virus_client_sta) )
     dsl_ucs_l.ac_str = adsl_f1_cur->achc_virus_client;
     dsl_ucs_l.imc_len_str = strlen( adsl_f1_cur->achc_virus_client );  /* get length virus name */
     M_CPY_XML_UCS
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_client_end, sizeof(ucrs_xml_entry_virus_client_end) )
   }
   if (adsl_f1_cur->achc_virus_server) {    /* virus found on server   */
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_server_sta, sizeof(ucrs_xml_entry_virus_server_sta) )
     dsl_ucs_l.ac_str = adsl_f1_cur->achc_virus_server;
     dsl_ucs_l.imc_len_str = strlen( adsl_f1_cur->achc_virus_server );  /* get length virus name */
     M_CPY_XML_UCS
     M_CPY_XML_TEXT( ucrs_xml_entry_virus_server_end, sizeof(ucrs_xml_entry_virus_server_end) )
   }
   if (adsl_f1_cur->dwc_file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
     M_CPY_XML_TEXT( ucrs_xml_dir_end, sizeof(ucrs_xml_dir_end) )
   } else {
     M_CPY_XML_TEXT( ucrs_xml_file_end, sizeof(ucrs_xml_file_end) )
   }

   adsl_f1_cur = adsl_f1_cur->adsc_file_1_same_n;  /* chain of entries same name */
   if (adsl_f1_cur) {                       /* entry found             */
     goto p_cxd_20;                         /* output of entry         */
   }
   goto p_cxd_00;                           /* start / continue reading files */

   p_cxd_80:                                /* all files read          */
   M_CPY_XML_TEXT( ucrs_xml_end, sizeof(ucrs_xml_end) )
   adsl_xdb_last->achc_end_data = achl_out_cur;  /* end of data        */
   adsl_xdb_last->adsc_next = NULL;
   *aadsp_xdb = adsl_xdb_start;             /* set what to return      */
   return TRUE;
#undef ADSL_DB2_G
} /* end m_create_xml_dir()                                            */

/** write the synchronize file                                         */
static BOOL m_write_xml_sync_file( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                                   struct dsd_unicode_string *adsp_ucs_fn, struct dsd_xml_dir_bl *adsp_xdb ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   struct dsd_xml_dir_bl *adsl_xdb_cur;     /* XML directory block - chaining */
   struct dsd_xml_dir_bl *adsl_xdb_w1;      /* XML directory block - chaining - working variable */
   struct dsd_gather_i_1 dsrl_gai1_work[ MAX_INP_GATHER ];  /* input data */
   struct dsd_aux_file_io_req_1 dsl_afior1;  /* file IO request        */

   adsl_xdb_cur = adsp_xdb;                 /* XML directory block - chaining - current */
   iml1 = 0;                                /* clear index             */
   while (TRUE) {                           /* loop to fill gather     */
     dsrl_gai1_work[ iml1 ].achc_ginp_cur = (char *) (adsl_xdb_cur + 1);
     dsrl_gai1_work[ iml1 ].achc_ginp_end = adsl_xdb_cur->achc_end_data;
     adsl_xdb_cur = adsl_xdb_cur->adsc_next;  /* get next in chain     */
     if (adsl_xdb_cur == NULL) break;       /* end of chain input      */
     dsrl_gai1_work[ iml1 ].adsc_next = &dsrl_gai1_work[ iml1 + 1 ];
     iml1++;                                /* increment index         */
     if (iml1 >= MAX_INP_GATHER) {          /* overflow                */
       m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_write_xml_sync_file() overflow gather",
                     __LINE__ );
       return FALSE;
     }
   }
   dsrl_gai1_work[ iml1 ].adsc_next = NULL;  /* set end of chain       */
   memset( &dsl_afior1, 0, sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   dsl_afior1.adsc_gai1_data = dsrl_gai1_work;  /* input and output data */
   dsl_afior1.dsc_ucs_file_name = *adsp_ucs_fn;  /* name of file       */
   dsl_afior1.boc_create_directory = TRUE;  /* create directory if missing */
   dsl_afior1.iec_fioc = ied_fioc_compl_file_write;  /* write complete file */
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_FILE_IO,  /* file input-output */
                                         &dsl_afior1,  /* file IO request */
                                         sizeof(struct dsd_aux_file_io_req_1) );  /* file IO request */
   if (bol_rc == FALSE) {                   /* returned error          */
     return FALSE;
   }
   if (dsl_afior1.iec_fior != ied_fior_ok) {  /* o.k.                  */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_write_xml_sync_file() synchonize file DEF_AUX_FILE_IO write error %d/%d.",
                   __LINE__, dsl_afior1.iec_fior, dsl_afior1.imc_error );
     return FALSE;
   }
   /* free all input buffers                                           */
   adsl_xdb_cur = adsp_xdb;                 /* XML directory block - chaining - current */
   while (TRUE) {                           /* loop to free storage    */
     adsl_xdb_w1 = adsl_xdb_cur;            /* get current buffer      */
     adsl_xdb_cur = adsl_xdb_cur->adsc_next;  /* get next in chain     */
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &adsl_xdb_w1,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* returned error          */
       return FALSE;
     }
     if (adsl_xdb_cur == NULL) break;       /* end of chain input      */
   }
   return TRUE;
} /* end m_write_xml_sync_file()                                       */

/** free directory - chain of buffers                                  */
static BOOL m_dir_free( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                        struct dsd_dir_bl_1 *adsp_db1 ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_dir_bl_1 *adsl_db1_cur;       /* directory block 1 - chaining - current */
   struct dsd_dir_bl_1 *adsl_db1_free;      /* directory block 1 - chaining - free */

   adsl_db1_cur = adsp_db1;                 /* directory block 1 - chaining - current */
   while (adsl_db1_cur) {                   /* loop over directory block 1 chain */
     adsl_db1_free = adsl_db1_cur;          /* directory block 1 - chaining - free */
     adsl_db1_cur = adsl_db1_cur->adsc_next;  /* get next in chain     */
     bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                           DEF_AUX_MEMFREE,
                                           &adsl_db1_free,
                                           LEN_DIR_BLOCK );
     if (bol_rc == FALSE) {                 /* returned error          */
       return FALSE;
     }
   }
   return TRUE;
} /* end m_dir_free()                                                  */

/** compare entries in AVL tree of files                               */
static int m_cmp_file( void *ap_option,
                       struct dsd_htree1_avl_entry *adsp_entry_1,
                       struct dsd_htree1_avl_entry *adsp_entry_2 ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   int        iml_cmp;                      /* for compare             */
   int        iml_nesting_p1;               /* nesting of directories  */
   int        iml_nesting_p2;               /* nesting of directories  */
   struct dsd_file_1 *adsl_f1_m_p1;         /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_m_p2;         /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_d_p1;         /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_d_p2;         /* entry of a single file  */

   adsl_f1_m_p1 = ((struct dsd_file_1 *) ((char *) adsp_entry_1 - offsetof( struct dsd_file_1, dsc_sort_1 )));
   iml_nesting_p1 = 0;                      /* nesting of directories  */
   adsl_f1_d_p1 = adsl_f1_m_p1;             /* get inner entry         */
   while (adsl_f1_d_p1->adsc_file_1_parent) {  /* entry of parent directory */
     adsl_f1_d_p1 = adsl_f1_d_p1->adsc_file_1_parent;  /* get entry of parent directory */
     iml_nesting_p1++;                      /* nesting of directories  */
   }

   adsl_f1_m_p2 = ((struct dsd_file_1 *) ((char *) adsp_entry_2 - offsetof( struct dsd_file_1, dsc_sort_1 )));
   iml_nesting_p2 = 0;                      /* nesting of directories  */
   adsl_f1_d_p2 = adsl_f1_m_p2;             /* get inner entry         */
   while (adsl_f1_d_p2->adsc_file_1_parent) {  /* entry of parent directory */
     adsl_f1_d_p2 = adsl_f1_d_p2->adsc_file_1_parent;  /* get entry of parent directory */
     iml_nesting_p2++;                      /* nesting of directories  */
   }

   p_cmp_00:                                /* compare outer files     */
   if (adsl_f1_d_p1 == adsl_f1_d_p2) {      /* same file / directory   */
     goto p_cmp_20;                         /* file names are equal    */
   }
   bol_rc = m_cmpi_ucs_ucs( &iml_cmp,
                            &adsl_f1_d_p1->dsc_ucs_file,
                            &adsl_f1_d_p2->dsc_ucs_file );
   if (bol_rc == FALSE) {                   /* error occured           */
#ifdef XYZ1
     m_hl1_printf( "xl-sdh-dash-01-l%05d-W m_cmp_file() m_cmpi_ucs_ucs() returned error",
                   __LINE__ );
#endif
     return 0;
   }
   if (iml_cmp != 0) return iml_cmp;        /* file names not equal    */

   p_cmp_20:                                /* file names are equal    */
   if (   (iml_nesting_p1 == 0)
       || (iml_nesting_p2 == 0)) {
     return iml_nesting_p1 - iml_nesting_p2;
   }
   iml_nesting_p1--;                        /* nesting of directories  */
   iml1 = iml_nesting_p1;                   /* nesting of directories  */
   adsl_f1_d_p1 = adsl_f1_m_p1;             /* get inner entry         */
   while (iml1 > 0) {                       /* check if we go deeper   */
     adsl_f1_d_p1 = adsl_f1_d_p1->adsc_file_1_parent;  /* get entry of parent directory */
     iml1--;                                /* nesting of directories  */
   }
   iml_nesting_p2--;                        /* nesting of directories  */
   iml1 = iml_nesting_p2;                   /* nesting of directories  */
   adsl_f1_d_p2 = adsl_f1_m_p2;             /* get inner entry         */
   while (iml1 > 0) {                       /* check if we go deeper   */
     adsl_f1_d_p2 = adsl_f1_d_p2->adsc_file_1_parent;  /* get entry of parent directory */
     iml1--;                                /* nesting of directories  */
   }
   goto p_cmp_00;                           /* compare outer files     */
} /* end m_cmp_file()                                                  */

#ifdef B150411
/** compare longlong values in little endian                           */
static int m_cmp_longlong_1( char *achp_p1, char *achp_p2 ) {
   int        iml1;                         /* working variable        */

   iml1 = sizeof(HL_LONGLONG);
   do {
     iml1--;                                /* decrement index         */
     if (*(achp_p1 + iml1) != *(achp_p2 + iml1)) {
       if (*((unsigned char *) achp_p1 + iml1) > *((unsigned char *) achp_p2 + iml1)) {
         return sizeof(HL_LONGLONG) - iml1 + 1;
       }
       return 0 - (sizeof(HL_LONGLONG) - iml1 + 1);
     }
   } while (iml1 > 0);
   return 0;                                /* fields are equal        */
} /* end m_cmp_longlong_1()                                            */
#endif

/** compare Windows time values in little endian                       */
static int m_cmp_time_win_1( FILETIME *achp_p1, FILETIME *achp_p2 ) {
   int        iml1;                         /* working variable        */

   iml1 = sizeof(HL_LONGLONG);
   do {
     iml1--;                                /* decrement index         */
     if (*((unsigned char *) achp_p1 + iml1) != *((unsigned char *) achp_p2 + iml1)) {
       if (*((unsigned char *) achp_p1 + iml1) > *((unsigned char *) achp_p2 + iml1)) {
         return sizeof(HL_LONGLONG) - iml1 + 1;
       }
       return 0 - (sizeof(HL_LONGLONG) - iml1 + 1);
     }
   } while (iml1 > 0);
   return 0;                                /* fields are equal        */
} /* end m_cmp_time_win_1()                                            */

/** compare Unix time values in little endian                          */
static int m_cmp_time_unix_1( FILETIME *achp_p1, FILETIME *achp_p2 ) {
   return m_unix_file_time( achp_p1 ) - m_unix_file_time( achp_p2 );
} /* end m_cmp_time_unix_1()                                           */

#ifdef B140102
/** compare longlong value in little endian with host-based number     */
static int m_cmp_longlong_2( char *achp_p1, HL_LONGLONG ilp_p ) {
   int        iml1;                         /* working variable        */

   iml1 = sizeof(HL_LONGLONG);
   do {
     iml1--;                                /* decrement index         */
     if (*((unsigned char *) achp_p1 + iml1) != ((ilp_p >> (iml1 << 3)) & 0XFF)) {
       if (*((unsigned char *) achp_p1 + iml1) > ((ilp_p >> (iml1 << 3)) & 0XFF)) {
         return sizeof(HL_LONGLONG) - iml1 + 1;
       }
       return 0 - (sizeof(HL_LONGLONG) - iml1 + 1);
     }
   } while (iml1 > 0);
   return 0;                                /* fields are equal        */
} /* end m_cmp_longlong_2()                                            */
#endif

/** input four bytes little endian                                     */
static inline void m_get_le4( int *aimp_out, char *achp_source ) {
   int        iml1;                         /* working variable        */

   *aimp_out = 0;                           /* clear result            */
   iml1 = 0;
   do {
     *aimp_out |= *((unsigned char *) achp_source + iml1) << (iml1 << 3);  /* get new bits for result */
     iml1++;                                /* increment index         */
   } while (iml1 < sizeof(int));
   return;
} /* end m_get_le4()                                                   */

/** input eight bytes little endian                                    */
static inline void m_get_le8( HL_LONGLONG *ailp_out, char *achp_source ) {
   int        iml1;                         /* working variable        */

   *ailp_out = 0;                           /* clear result            */
   iml1 = 0;
   do {
     *ailp_out |= (HL_LONGLONG) *((unsigned char *) achp_source + iml1) << (iml1 << 3);  /* get new bits for result */
     iml1++;                                /* increment index         */
   } while (iml1 < sizeof(HL_LONGLONG));
   return;
} /* end m_get_le8()                                                   */

/** get int variable from Unicode string                               */
static int m_get_ucs_int( struct dsd_unicode_string *adsp_ucs_p ) {
   int        iml_len;                      /* length                  */
   int        iml_w1;                       /* working variable        */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of number           */
   char       byrl_work1[ 64 ];             /* work area               */

   iml_len = m_cpy_vx_ucs( byrl_work1, sizeof(byrl_work1), ied_chs_utf_8,  /* Unicode UTF-8   */
                           adsp_ucs_p );
   if ((iml_len <= 0) || (iml_len > 8)) {
     return -1;
   }
   iml_w1 = 0;
   achl_rp = byrl_work1;                    /* read pointer            */
   achl_end = byrl_work1 + iml_len;         /* end of number           */
   do {                                     /* loop over all digits    */
     if (*achl_rp < '0') return -1;
     if (*achl_rp > '9') return -1;
     iml_w1 *= 10;
     iml_w1 += *achl_rp - '0';
     achl_rp++;                             /* next digit              */
   } while (achl_rp < achl_end);
   return iml_w1;
} /* end m_get_ucs_int()                                               */

/** get unsigned int = 32-bit variable from Unicode string, coded as hexadecimal */
static BOOL m_get_ucs_hex( unsigned int *aump_p, struct dsd_unicode_string *adsp_ucs_p ) {
   int        iml_len;                      /* length                  */
   unsigned int uml_w1;                     /* working variable        */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of number           */
   char       byrl_work1[ 64 ];             /* work area               */

   iml_len = m_cpy_vx_ucs( byrl_work1, sizeof(byrl_work1), ied_chs_utf_8,  /* Unicode UTF-8   */
                           adsp_ucs_p );
   if (iml_len < 3) {
     return FALSE;
   }
   if (iml_len > (2 + 8)) {
     return FALSE;
   }
   if (byrl_work1[ 0 ] != '0') return FALSE;
   if ((byrl_work1[ 1 ] != 'X') && (byrl_work1[ 1 ] != 'x')) return FALSE;
   uml_w1 = 0;
   achl_rp = byrl_work1 + 2;                /* read pointer            */
   achl_end = byrl_work1 + iml_len;         /* end of number           */
   do {                                     /* loop over all digits    */
     uml_w1 <<= 4;                          /* shift one digit         */
     if ((*achl_rp >= '0') && (*achl_rp <= '9')) {
       uml_w1 |= *achl_rp - '0';
     } else if ((*achl_rp >= 'A') && (*achl_rp <= 'F')) {
       uml_w1 |= *achl_rp - 'A' + 10;
     } else if ((*achl_rp >= 'a') && (*achl_rp <= 'f')) {
       uml_w1 |= *achl_rp - 'a' + 10;
     } else {
       return FALSE;
     }
     achl_rp++;                             /* next digit              */
   } while (achl_rp < achl_end);
   *aump_p = uml_w1;                        /* return result           */
   return TRUE;
} /* end m_get_ucs_hex()                                               */

/** get longlong = 64-bit variable from Unicode string                 */
static BOOL m_get_ucs_longlong( HL_LONGLONG *ailp_p, struct dsd_unicode_string *adsp_ucs_p ) {
   int        iml_len;                      /* length                  */
   HL_LONGLONG ill_w1;                      /* working variable        */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of number           */
   char       byrl_work1[ 64 ];             /* work area               */

   iml_len = m_cpy_vx_ucs( byrl_work1, sizeof(byrl_work1), ied_chs_utf_8,  /* Unicode UTF-8   */
                           adsp_ucs_p );
   if (iml_len <= 0) {
     return FALSE;
   }
   ill_w1 = 0;
   achl_rp = byrl_work1;                    /* read pointer            */
   achl_end = byrl_work1 + iml_len;         /* end of number           */
   do {                                     /* loop over all digits    */
     if (*achl_rp < '0') return FALSE;
     if (*achl_rp > '9') return FALSE;
     ill_w1 *= 10;
     ill_w1 += *achl_rp - '0';
     achl_rp++;                             /* next digit              */
   } while (achl_rp < achl_end);
   *ailp_p = ill_w1;                        /* return result           */
   return TRUE;
} /* end m_get_ucs_longlong()                                          */

/** retrieve file time for Unix                                        */
static unsigned int m_unix_file_time( FILETIME *adsp_ft ) {
   HL_LONGLONG ill1;                        /* working variable        */
   m_get_le8( &ill1, (char *) adsp_ft );
#ifdef B150121
   return (unsigned int) ((ill1 - 116444736000000000) / 1000 * 1000 * 10);
#endif
#ifdef B150228
   return (unsigned int) ((ill1 - 116444736000000000) / (1000 * 1000 * 10));
#endif
   return (unsigned int) ((HL_LONGLONG) (ill1 - TIME_ADJUST) / (1000 * 1000 * 10));
} /* end m_unix_file_time()                                            */

/** callback memory allocation for XML-parser                          */
static void * m_sub_alloc( void *vpp_userfld, size_t imp_size ) {
   BOOL       bol_rc;                       /* return code             */
   void *     al_buffer;

#define ADSL_SDH_CALL_1 ((struct dsd_sdh_call_1 *) vpp_userfld)

   bol_rc = (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
                                         DEF_AUX_MEMGET,  /* get some memory */
                                         &al_buffer,
                                         imp_size );
   if (bol_rc) {                            /* call succeeded          */
     return al_buffer;
   }
   return NULL;

#undef ADSL_SDH_CALL_1
} /* end m_sub_alloc()                                                 */

/** callback memory deallocation callback for XML-parser               */
static void m_sub_free( void *vpp_userfld, void * ap_mem ) {
   BOOL       bol_rc;                       /* return code             */

#define ADSL_SDH_CALL_1 ((struct dsd_sdh_call_1 *) vpp_userfld)
   bol_rc = (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
                                         DEF_AUX_MEMFREE,  /* free memory */
                                         &ap_mem,
                                         0 );
   if (bol_rc) return;                      /* call succeeded          */
   return;

#undef ADSL_SDH_CALL_1
} /* end m_sub_free()                                                  */

/** auxiliary callback routine for the SMB client component            */
static BOOL m_sub_aux( void * vpp_userfld, int iml_func, void * adsp_param, int imp_length ) {
   BOOL       bol_rc;                       /* return code             */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */

#define ADSL_SDH_CALL_1 ((struct dsd_sdh_call_1 *) vpp_userfld)

   switch (iml_func) {                      /* depend on function      */
     case DEF_AUX_GET_SEND_BUFFER:          /* get send buffer         */
       if (imp_length != sizeof(struct dsd_aux_get_send_buffer)) return FALSE;  /* invalid size */
#define ADSL_GSB_G ((struct dsd_aux_get_send_buffer *) adsp_param)
       memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
       bol_rc = (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
                                             DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                             &dsl_aux_get_workarea,
                                             sizeof(struct dsd_aux_get_workarea) );
       if (bol_rc == FALSE) {               /* error occured           */
         return FALSE;                      /* return error            */
       }
       ADSL_GSB_G->achc_send_buffer = dsl_aux_get_workarea.achc_work_area;
       ADSL_GSB_G->imc_len_send_buffer = dsl_aux_get_workarea.imc_len_work_area;  /* length allocated memory piece */
       return TRUE;
#undef ADSL_GSB_G
     default:
       return (*ADSL_SDH_CALL_1->amc_aux)( ADSL_SDH_CALL_1->vpc_userfld,
                                           iml_func, adsp_param, imp_length );
   }
   return FALSE;
#undef ADSL_SDH_CALL_1
} /* end m_sub_aux()                                                   */

#ifdef TRACEHL1
static void m_trace_dir( struct dsd_sdh_call_1 *adsp_sdh_call_1, struct dsd_dir_bl_1 *adsp_db1, char *achp_msg ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   BOOL       bol_first;                    /* retrieve first record   */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   char       byrl_server_fn[ LEN_FILE_NAME ];

   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_trace_dir( %p , \"%s\" )",
                 __LINE__, adsp_db1, achp_msg );
   bol_first = TRUE;                        /* retrieve first record   */
   iml1 = 0;                                /* clear count             */

#define ADSL_DB2_G ((struct dsd_dir_bl_2 *) (adsp_db1 + 1))

   p_file_00:                               /* retrieve file           */
   bol_rc = m_htree1_avl_getnext( NULL, &ADSL_DB2_G->dsc_htree1_avl_file,
                                  &dsl_htree1_work, bol_first );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_trace_dir() m_htree1_avl_getnext() failed",
                   __LINE__ );
     return;
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file found     */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_trace_dir( ... \"%s\" ) end index=%d.",
                   __LINE__, achp_msg, iml1 );
     return;
   }
   bol_first = FALSE;                       /* retrieve first record   */
   iml1++;                                  /* increment count         */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
   m_build_file_name_utf8( adsp_sdh_call_1, ADSL_F1_SORT, byrl_server_fn, '\\' );
   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T %06d \"%s\"",
                 __LINE__, iml1, byrl_server_fn );
#undef ADSL_F1_SORT
   goto p_file_00;                          /* retrieve file           */

#undef ADSL_DB2_G

} /* end m_trace_dir()                                                 */
#endif

/** subroutine to send a text message to the client                    */
static int m_sdh_msg_cl( struct dsd_sdh_call_1 *adsp_sdh_call_1, int imp_cn, int imp_tag, const char *achptext, ... ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2;                   /* working variables       */
   int        iml_len;                      /* length variable texte   */
   char       *achl_w1, *achl_w2;           /* working variables       */
   va_list    dsl_argptr;
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */

   if ((adsp_sdh_call_1->achc_upper - adsp_sdh_call_1->achc_lower)
         < (sizeof(struct dsd_gather_i_1) + 3 * MAX_LEN_NHASN + MAX_LEN_MSG_CLIENT)) {
     /* no space in work area, acquire additional work area            */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol_rc = adsp_sdh_call_1->amc_aux( adsp_sdh_call_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol_rc == FALSE) {                 /* aux returned error      */
       return -1;
     }
     adsp_sdh_call_1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     adsp_sdh_call_1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   adsp_sdh_call_1->achc_upper -= sizeof(struct dsd_gather_i_1);
   achl_w1 = achl_w2 = adsp_sdh_call_1->achc_lower + 3 * MAX_LEN_NHASN;
   va_start( dsl_argptr, achptext );
   iml_len = m_hlvsnprintf( achl_w1, adsp_sdh_call_1->achc_upper - achl_w1, ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   if (iml_len <= 0) {                      /* returned error          */
// to-do 06.12.14 KB - error message
     return -1;
   }
   achl_w1 += iml_len;                      /* end of message          */
   adsp_sdh_call_1->achc_lower = achl_w1;   /* storage occupied        */
   iml1 = imp_tag;                          /* get tag                 */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   iml1 = imp_cn;                           /* get channel-number      */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
   iml1 = achl_w1 - achl_w2;                /* length of block         */
   iml2 = 0;                                /* clear more bit          */
   do {                                     /* output length           */
     *(--achl_w2) = (unsigned char) ((iml1 & 0X7F) | iml2);
     iml1 >>= 7;                            /* shift bits              */
     iml2 = 0X80;                           /* set more bit            */
   } while (iml1 > 0);
#define ADSL_GAI1_OUT_W ((struct dsd_gather_i_1 *) adsp_sdh_call_1->achc_upper)
   ADSL_GAI1_OUT_W->achc_ginp_cur = achl_w2;
   ADSL_GAI1_OUT_W->achc_ginp_end = achl_w1;
   ADSL_GAI1_OUT_W->adsc_next = NULL;
   *(adsp_sdh_call_1->aadsc_gai1_out_to_client) = ADSL_GAI1_OUT_W;  /* output data to client */
   adsp_sdh_call_1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_W->adsc_next;  /* output data to client */
#undef ADSL_GAI1_OUT_W
   return iml_len;
} /* end m_sdh_msg_cl()                                                */

/** subroutine for output to console                                   */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
#ifdef LOG_INSURE_01
#ifdef __INSURE__
   *((char *) chrl_out1 + iml1) = 0;        /* make zero-terminated    */
   _Insure_trace_enable( 1 );
   _Insure_trace_annotate( 1, "%s\n", chrl_out1 );
   _Insure_trace_enable( 0 );
#endif
#endif
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_CONSOLE_OUT,  /* output to console */
                                         chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()                                                */

/** subroutine to put a text message to the log or the WSP-trace       */
static void m_sdh_msg_log_tr( struct dsd_sdh_call_1 *adsp_sdh_call_1, BOOL bop_log, const char *achptext, ... ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   struct dsd_wsp_trace_header dsl_wtrh;    /* WSP trace header        */
   struct dsd_wsp_trace_record dsl_wtr_l;   /* WSP trace record        */
   char       chrl_out1[2048];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );

   if (bop_log == FALSE) {                  /* check if write to log   */
     goto p_wsp_tr;                         /* output WSP-trace        */
   }
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_CONSOLE_OUT,  /* output to console */
                                         chrl_out1, iml1 );

   if (adsp_sdh_call_1->adsc_hl_clib_1->imc_trace_level == 0) return;  /* WSP trace level */

   p_wsp_tr:                                /* output WSP-trace        */
   memset( &dsl_wtrh, 0, sizeof(struct dsd_wsp_trace_header) );  /* WSP trace header */
   memcpy( dsl_wtrh.chrc_wtrt_id, "DAMSG001", sizeof(dsl_wtrh.chrc_wtrt_id) );  /* Id of trace record */
   dsl_wtrh.imc_wtrh_sno = adsp_sdh_call_1->adsc_hl_clib_1->imc_sno;  /* WSP session number */
   dsl_wtrh.adsc_wtrh_chain = &dsl_wtr_l;   /* chain of WSP trace records */
   memset( &dsl_wtr_l, 0, sizeof(struct dsd_wsp_trace_record) );
   dsl_wtr_l.iec_wtrt = ied_wtrt_text;      /* text passed             */
   dsl_wtr_l.achc_content = chrl_out1;      /* content of text / data  */
   dsl_wtr_l.imc_length = iml1;
   bol_rc = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                         DEF_AUX_WSP_TRACE,  /* write WSP trace */
                                         &dsl_wtrh,
                                         0 );
};
#ifdef DEBUG_140823_01
static void m_print_gather( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                            int imp_line, char *achp_comment,
                            struct dsd_gather_i_1 *adsp_gai1_in ) {
   int        iml1;                         /* working variable        */
   char       *achl_w1;                     /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;
   char       byrl_work1[ 32 ];

   m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_print_gather() %05d %s gather=%p.",
                 __LINE__, imp_line, achp_comment, adsp_gai1_in );
   adsl_gai1_w1 = adsp_gai1_in;
   while (adsl_gai1_w1) {
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     byrl_work1[ 0 ] = 0;
     achl_w1 = ".";
     if (iml1 == 0) {
       achl_w1 = " empty";
     } else {
       sprintf( byrl_work1, " <%p>=%02X", adsl_gai1_w1->achc_ginp_cur, (unsigned char) *adsl_gai1_w1->achc_ginp_cur );
     }
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-T m_print_gather() gather=%p length=%d/0X%X%s%s",
                   __LINE__, adsl_gai1_w1, iml1, iml1, byrl_work1, achl_w1 );
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
   }
} /* end m_print_gather()                                              */
#endif
#ifdef DEBUG_170410_01                      /* address adsc_file_1_parent invalid */
static void m_check_parent_1( struct dsd_sdh_call_1 *adsp_sdh_call_1,
                              struct dsd_dir_bl_1 *adsp_db1_check,  /* directory block 1 */
                              char *achp_text, int imp_line ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   BOOL       bol_first;                    /* AVL retrieve first entry */
   int        iml_nesting;                  /* nesting of directories  */
   int        iml_comp_nesting;             /* check nesting of directories */
   struct dsd_dir_bl_2 *adsl_db2_check;     /* directory block 2       */
   struct dsd_file_1 *adsl_f1_cur;          /* entry of a single file  */
   struct dsd_file_1 *adsl_f1_dir;          /* entry of a single file  */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   char       byrl_eye_catcher[ 128 ];

   memcpy( byrl_eye_catcher + 0, "m_check_parent_1() *", 20 );
   iml1 = strlen( achp_text );
   memcpy( byrl_eye_catcher + 20, achp_text, iml1 );
   sprintf( byrl_eye_catcher + 20 + iml1, "* *%d*", imp_line );

   adsl_db2_check = (struct dsd_dir_bl_2 *) (adsp_db1_check + 1);
   bol_first = TRUE;                        /* AVL retrieve first entry */
   iml_comp_nesting = 0;                    /* check nesting of directories */

   p_check_20:                              /* loop to check entries   */
   bol_rc = m_htree1_avl_getnext( NULL, &adsl_db2_check->dsc_htree1_avl_file,
                                  &dsl_htree1_work, bol_first );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_check_parent_1() m_htree1_avl_getnext() failed",
                   __LINE__ );
     return;
   }
   if (dsl_htree1_work.adsc_found == NULL) {  /* end-of-file found     */
     return;                                /* all files read          */
   }
   bol_first = FALSE;                       /* AVL retrieve first entry */
#define ADSL_F1_SORT ((struct dsd_file_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_file_1, dsc_sort_1 )))
   adsl_f1_cur = ADSL_F1_SORT;              /* get entry found         */
#undef ADSL_F1_SORT

   iml_nesting = 0;                         /* nesting of directories  */
   adsl_f1_dir = adsl_f1_cur;               /* get inner entry         */
   while (adsl_f1_dir->adsc_file_1_parent) {  /* entry of parent directory */
     adsl_f1_dir = adsl_f1_dir->adsc_file_1_parent;  /* get entry of parent directory */
     iml_nesting++;                         /* nesting of directories  */
   }
   if (iml_nesting > (iml_comp_nesting + 1)) {  /* check nesting of directories */
     m_sdh_printf( adsp_sdh_call_1, "xl-sdh-dash-01-l%05d-W m_check_parent_1() iml_nesting=%d iml_comp_nesting=%d.",
                   __LINE__, iml_nesting, iml_comp_nesting );
   }
   iml_comp_nesting = iml_nesting;          /* check nesting of directories */
   goto p_check_20;                         /* loop to check entries   */
} /* end m_check_parent_1()                                            */
#endif  /* DEBUG_170410_01                     address adsc_file_1_parent invalid */
