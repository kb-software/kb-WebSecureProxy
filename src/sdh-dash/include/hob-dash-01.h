/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-dash-01.h                                       |*/
/*| -------------                                                     |*/
/*|  Header File for DASH - HOBLink data share                        |*/
/*|  part of HOB Framework                                            |*/
/*|  KB 05.07.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* see HOBTEXT SOFTWARE.HLSEC.DASH-PR1                                 */

#ifndef DEF_HL_DASH
/**
   hob-dash-01.h
   hob-xsclib01.h
*/
#define DEF_HL_DASH

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

enum ied_dash_open_flags {                  /* open flags              */
   ied_dof_invalid = 0,                     /* value is invalid        */
   ied_dof_read_share_all,                  /* open read and share all */
   ied_dof_read_share_read,                 /* open read and share read */
   ied_dof_param_inv                        /* input paramater invalid */
};

enum ied_dash_access {                      /* access                  */
   ied_dac_deny = 0,                        /* access denied           */
   ied_dac_read_only,                       /* access read-only        */
   ied_dac_read_write,                      /* access read-write       */
   ied_dac_write_only,                      /* access write-only       */
   ied_dac_dummy                            /* dummy entry             */
};
#endif

#define DASH_DCH_SE2CL_CREDENTIALS   0X03
#define DASH_DCH_SE2CL_MESSAGE       0X04
#define DASH_DCH_SE2CL_WARNING       0X05
#define DASH_DCH_SE2CL_ERRMSG        0X06
#define DASH_DCH_SELECT_DIRECTORY    0
#define DASH_DCH_SYNC_DONE           0X08
#define DASH_DCH_CL2SE_ERROR         0X01
#define DASH_DCH_CL2SE_ACT_CHANNEL   0X02
#define DASH_DCH_CL2SE_CREDENTIALS   0X03
#define DASH_DCH_CL2SE_MSG1          0X04
#define DASH_DCH_CL2SE_DIR_NORMAL    0X16
#define DASH_DCH_CL2SE_DIR_COMPR     0X17
#define DASH_DCH_READ_FILE           0X20
#define DASH_DCH_CL2SE_FILE_NORMAL   0X21
#define DASH_DCH_CL2SE_FILE_COMPR    0X22
#define DASH_DCH_WRITE_FILE          0X30
#define DASH_DCH_SE2CL_FILE_NORMAL   0X31
#define DASH_DCH_SE2CL_FILE_COMPR    0X32
#define DASH_DCH_SE2CL_FILE_INFO     0X33
#define DASH_DCH_DELETE_FILE         0X40
#define DASH_DCH_DELETE_DIR          0X41
#define DASH_DCH_SE2CL_SET_CH_NOTIFY 0X42
#define DASH_DCH_SE2CL_DEL_CH_NOTIFY 0X43
#define DASH_DCH_CL2SE_CHANGE_NOTIFY 0X44
#define DASH_DCH_CREATE_DIR          0X48

#define DASH_ERROR_FILE_NOT_FOUND    1
#define DASH_ERROR_ACCESS_DENIED     2
#define DASH_ERROR_MISC              999

#define DASH_SECH_OPT_CREATE_SHARED  1

/**
   UTF-32 for easy parsing
   - no: UTF-8 for easy parsing
   flag case-sensitive
   character file-delimiter
   array with position file-delimiter
   int position last dot
*/

#ifndef DEF_HL_INCL_DOM_COMMAND_DONE
#define DEF_HL_INCL_DOM_COMMAND_DONE

enum ied_hlcldom_def { ied_hlcldom_invalid,  /* invalid function       */
                       ied_hlcldom_get_first_child,  /* getFirstChild() */
                       ied_hlcldom_get_next_sibling,  /* getNextSibling() */
                       ied_hlcldom_get_node_type,  /* getNodeType()    */
                       ied_hlcldom_get_node_value,  /* getNodeValue()  */
                       ied_hlcldom_get_node_name,  /* getNodeName()    */
                       ied_hlcldom_get_file_line,  /* get line in file */
                       ied_hlcldom_get_file_column  /* get column in file */
};

#endif

struct dsd_dash_fc_dom_conf {               /* structure DASH file control DOM configuration */
   void *     vpc_node_conf;                /* part of configuration   */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* aux-call routine pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   void * (* amc_call_dom) ( void * vpp_userfld, void * vpp_node, enum ied_hlcldom_def );  /* call DOM */
   void **    aac_conf;                     /* return data from conf   */
   BOOL       boc_case_sensitive;           /* do parsing case sensitive */
};

struct dsd_dash_fc_execute {                /* execute DASH file control */
   void *     ac_conf;                      /* data from configuration */
// void *     ac_ext;                       /* attached buffer pointer */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* aux-call routine pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   char       chc_file_delimiter;           /* file delimiter          */
   struct dsd_unicode_string dsc_ucs_filename;  /* file name           */
   enum ied_dash_access iec_dac;            /* access                  */
   BOOL       boc_exclude_compression;      /* <exclude-compression>   */
   HL_LONGLONG ilc_max_file_size;           /* if not zero found <max-file-size> */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE BOOL m_dash_file_control_conf( struct dsd_dash_fc_dom_conf * );
extern PTYPE BOOL m_dash_file_control_execute( struct dsd_dash_fc_execute * );
extern PTYPE BOOL m_dash_file_control_end( struct dsd_dash_fc_execute * );
