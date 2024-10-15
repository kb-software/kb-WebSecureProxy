/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-smb-01.h                                        |*/
/*| -------------                                                     |*/
/*|  Header File for processing of SMB                                |*/
/*|    MS Server Message Block                                        |*/
/*|    also CIFS                                                      |*/
/*|  part of HOB Framework                                            |*/
/*|  KB 01.01.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

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

#define HL_SMB1_CMD_NEGOTIATE_PROTOCOL      0X72
#define HL_SMB2_XYZ1                        0X0001
#define HL_SMB2_TREE_CONNECT                0X0003
#define HL_SMB2_CREATE                      0X0005
#define HL_SMB2_CLOSE                       0X0006
#define HL_SMB2_FLUSH                       0X0007
#define HL_SMB2_READ                        0X0008
#define HL_SMB2_WRITE                       0X0009
#define HL_SMB2_CANCEL                      0X000C
#define HL_SMB2_ECHO                        0X000D
#define HL_SMB2_QUERY_DIRECTORY             0X000E
#define HL_SMB2_CHANGE_NOTIFY               0X000F
#define HL_SMB2_SET_INFO                    0X0011
#define HL_SMB2_QD_FILE_DIRECTORY_INFORMATION 0X01
#define HL_SMB2_QD_FILE_ID_BOTH_DIRECTORY_INFORMATION 0X25
#define HL_SMB2_FLAGS_ASYNC_COMMAND         0X00000002
#define HL_SMB2_FLAGS_RELATED_OPERATIONS    0X00000004
#define HL_SMB2_FLAGS_SIGNED                0X00000008
#define HL_FILE_NOTIFY_CHANGE_FILE_NAME     0X00000001
#define HL_FILE_NOTIFY_CHANGE_DIR_NAME      0X00000002
#define HL_FILE_NOTIFY_CHANGE_ATTRIBUTES    0X00000004
#define HL_FILE_NOTIFY_CHANGE_SIZE          0X00000008
#define HL_FILE_NOTIFY_CHANGE_LAST_WRITE    0X00000010
#define HL_FILE_NOTIFY_CHANGE_LAST_ACCESS   0X00000020
#define HL_FILE_NOTIFY_CHANGE_CREATION      0X00000040
#define HL_FILE_NOTIFY_CHANGE_EA            0X00000080
#define HL_FILE_NOTIFY_CHANGE_SECURITY      0X00000100
#define HL_FILE_NOTIFY_CHANGE_STREAM_NAME   0X00000200
#define HL_FILE_NOTIFY_CHANGE_STREAM_SIZE   0X00000400
#define HL_FILE_NOTIFY_CHANGE_STREAM_WRITE  0X00000800
#define HL_SMB2_WATCH_TREE                  0X0001
#define HL_SMB2_0_INFO_FILE                 0X01
#define HL_SMB2_0_INFO_FILESYSTEM           0X02
#define HL_SMB2_0_INFO_SECURITY             0X03
#define HL_SMB2_0_INFO_QUOTA                0X04
#define HL_SMB2_FILE_BASIC_INFO             0X04
#define HL_SMB2_FILE_RENAME_INFO            0X0A
#define HL_SMB2_FILE_DISPOSITION_INFO       0X0D
//#define HL_STATUS_NO_MORE_ITEMS             0X00000103
#define HL_STATUS_PENDING                   0X00000103
#define HL_STATUS_NOTIFY_CLEANUP            0X0000010B
#define HL_STATUS_NOTIFY_ENUM_DIR           0X0000010C
#define HL_STATUS_NO_MORE_FILES             0X80000006
#define HL_STATUS_INFO_LENGTH_MISMATCH      0XC0000004
#define HL_STATUS_END_OF_FILE               0XC0000011
#define HL_STATUS_MORE_PROCESSING_REQUIRED  0XC0000016
#define HL_STATUS_ACCESS_DENIED             0XC0000022
#define HL_STATUS_OBJECT_NAME_NOT_FOUND     0XC0000034
#define HL_STATUS_SHARING_VIOLATION         0XC0000043
#define HL_STATUS_QUOTA_EXCEEDED            0XC0000044
#define HL_STATUS_STATUS_CANCELLED          0XC0000120
#define HL_STATUS_FILE_CLOSED               0XC0000128

#define HL_ERROR_NO_MORE_ITEMS              0X00000103

#define LEN_SMB2_SIGN_KEY        16         /* length sign key of SMB2 */

#define MAX_LEN_SMB2_DATA        (64 * 1024)  /* maximum length of SMB2 in one block */

#define SMBCC_REQU_1_USERFLD     3          /* number of userfld fields */

#ifdef HL_UNIX
#define FILE_ATTRIBUTE_DIRECTORY            0X00000010
#define FILE_ATTRIBUTE_ARCHIVE              0X00000020
#ifndef DWORD
#define DWORD unsigned int
#endif
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;
#endif

struct dsd_smb1_hdr {                       /* SMB1 header             */
   char       chrc_eye_catcher[ 4 ];
   char       chc_command;
   char       chrc_filler     [ 27 ];
};

struct dsd_smb2_hdr_sync {                  /* SMB2 header SYNC        */
   char       chrc_eye_catcher[ 4 ];
   unsigned short int usc_header_length;
   unsigned short int usc_credit_charge;
   unsigned int umc_nt_status;
   unsigned short int usc_command;
   unsigned short int usc_credits_granted;
   unsigned int umc_flags;
   unsigned int umc_chain_offset;
   HL_LONGLONG ulc_command_sequence_number;
   unsigned int umc_process_id;
   unsigned int umc_tree_id;
   char       chrc_session_id[ 8 ];
   char       chrc_signature[ 16 ];
};

struct dsd_smb2_hdr_async {                 /* SMB2 header ASYNC       */
   char       chrc_eye_catcher[ 4 ];
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_credit_charge;    /* CreditCharge            */
   unsigned int umc_nt_status;
   unsigned short int usc_command;          /* Command                 */
   unsigned short int usc_credits_granted;  /* CreditRequest/CreditResponse */
   unsigned int umc_flags;                  /* Flags                   */
   unsigned int umc_chain_offset;           /* NextCommand             */
   HL_LONGLONG ulc_message_id;              /* MessageId               */
   HL_LONGLONG ulc_async_id;                /* AsyncId                 */
   char       chrc_session_id[ 8 ];
   char       chrc_signature[ 16 ];
};

struct dsd_smb2_tree_connect_request {      /* SMB2 TREE_CONNECT Request */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chrc_reserved[2];             /* Reserved                */
   unsigned short int usc_path_offset;      /* PathOffset              */
   unsigned short int usc_path_length;      /* PathLength              */
};

struct dsd_smb2_tree_connect_response {     /* SMB2 TREE_CONNECT Response */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chc_share_type;               /* ShareType               */
   char       chrc_reserved[1];             /* Reserved                */
   unsigned int umc_share_flags;            /* ShareFlags              */
   unsigned int umc_capabilities;           /* Capabilities            */
   unsigned int umc_maximal_access;         /* MaximalAccess           */
};

struct dsd_smb2_create_request {            /* SMB2 CREATE Request     */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chc_security_flags;           /* SecurityFlags           */
   char       chc_requested_oplock_level;   /* RequestedOplockLevel    */
   unsigned int umc_impersonation_level;    /* ImpersonationLevel      */
   char       chrc_smb_create_flags[ 8 ];   /* SmbCreateFlags          */
   char       chrc_reserved[ 8 ];           /* Reserved                */
   unsigned int umc_desired_access;         /* DesiredAccess           */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   unsigned int umc_share_access;           /* ShareAccess             */
   unsigned int umc_create_disposition;     /* CreateDisposition       */
   unsigned int umc_create_options;         /* CreateOptions           */
   unsigned short int usc_name_offset;      /* NameOffset              */
   unsigned short int usc_name_length;      /* NameLength              */
   unsigned int umc_create_contexts_offset;  /* CreateContextsOffset   */
   unsigned int umc_create_contexts_length;  /* CreateContextsLength   */
};

struct dsd_smb2_create_response {           /* SMB2 CREATE Response    */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chc_requested_oplock_level;   /* RequestedOplockLevel    */
   char       chc_flags;                    /* Flags                   */
   unsigned int umc_create_action;          /* CreateAction            */
   char       chrc_creation_time[ 8 ];      /* CreationTime            */
   char       chrc_last_access_time[ 8 ];   /* LastAccessTime          */
   char       chrc_last_write_time[ 8 ];    /* LastWriteTime           */
   char       chrc_change_time[ 8 ];        /* ChangeTime              */
   HL_LONGLONG ulc_allocation_size;         /* AllocationSize          */
   HL_LONGLONG ulc_end_of_file;             /* EndofFile               */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   char       chrc_reserved2[ 4 ];          /* Reserved2               */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   unsigned int umc_create_contexts_offset;  /* CreateContextsOffset   */
   unsigned int umc_create_contexts_length;  /* CreateContextsLength   */
};

struct dsd_smb2_close_request {             /* SMB2 CLOSE Request      */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_flags;            /* Flags                   */
   char       chrc_reserved[ 4 ];           /* Reserved                */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smb2_close_response {            /* SMB2 CLOSE Response     */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_flags;            /* Flags                   */
   char       chrc_reserved[ 4 ];           /* Reserved                */
   char       chrc_creation_time[ 8 ];      /* CreationTime            */
   char       chrc_last_access_time[ 8 ];   /* LastAccessTime          */
   char       chrc_last_write_time[ 8 ];    /* LastWriteTime           */
   char       chrc_change_time[ 8 ];        /* ChangeTime              */
#ifdef ERROR_ALIGNMENT
   HL_LONGLONG ulc_allocation_size;         /* AllocationSize          */
   HL_LONGLONG ulc_end_of_file;             /* EndofFile               */
#endif
   char       chrc_allocation_size[ 8 ];    /* AllocationSize          */
   char       chrc_end_of_file[ 8 ];        /* EndofFile               */
   unsigned int umc_file_attributes;        /* FileAttributes          */
};

struct dsd_smb2_read_request {              /* SMB2 READ Request       */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chc_padding;                  /* Padding                 */
   char       chrc_reserved[ 1 ];           /* Reserved                */
   unsigned int umc_length;                 /* Length                  */
   HL_LONGLONG ulc_offset;                  /* Offset                  */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   unsigned int umc_minimum_count;          /* MinimumCount            */
   unsigned int umc_channel;                /* Channel                 */
   unsigned int umc_remaining_bytes;        /* RemainingBytes          */
   unsigned short int usc_read_channel_info_offset;  /* ReadChannelInfoOffset */
   unsigned short int usc_read_channel_info_length;  /* ReadChannelInfoLength */
};


struct dsd_smb2_read_response {             /* SMB2 READ Response      */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned char ucc_data_offset;           /* DataOffset              */
   char       chrc_reserved[ 1 ];           /* Reserved                */
   unsigned int umc_data_length;            /* DataLength              */
   unsigned int umc_data_remaining;         /* DataRemaining           */
   char       chrc_reserved2[ 4 ];          /* Reserved2               */
};

struct dsd_smb2_write_request {             /* SMB2 WRITE Request      */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_data_offset;      /* DataOffset              */
   unsigned int umc_length;                 /* Length                  */
   HL_LONGLONG ulc_offset;                  /* Offset                  */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   unsigned int umc_channel;                /* Channel                 */
   unsigned int umc_remaining_bytes;        /* RemainingBytes          */
   unsigned short int usc_write_channel_info_offset;  /* WriteChannelInfoOffset */
   unsigned short int usc_write_channel_info_length;  /* WriteChannelInfoLength */
   unsigned int umc_flags;                  /* Flags                   */
};

struct dsd_smb2_write_response {            /* SMB2 WRITE Response     */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chrc_reserved[ 2 ];           /* Reserved                */
   unsigned int umc_count;                  /* Count                   */
   unsigned int umc_remaining;              /* Remaining               */
   unsigned short int usc_write_channel_info_offset;  /* WriteChannelInfoOffset */
   unsigned short int usc_write_channel_info_length;  /* WriteChannelInfoLength */
};

struct dsd_smb2_cancel_request {            /* SMB2 CANCEL Request     */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chrc_reserved[ 2 ];           /* Reserved                */
};

struct dsd_smb2_query_directory_request {   /* SMB2 QUERY_DIRECTORY Request */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chc_file_information_class;   /* FileInformationClass    */
   char       chc_flags;                    /* Flags                   */
   char       chrc_file_index[ 4 ];         /* FileIndex               */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   unsigned short int usc_file_name_offset;  /* FileNameOffset         */
   unsigned short int usc_file_name_length;  /* FileNameLength         */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
};

struct dsd_smb2_query_directory_response {  /* SMB2 QUERY_DIRECTORY Response */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_output_buffer_offset;  /* OutputBufferOffset */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
};

struct dsd_smb2_change_notify_request {     /* SMB2 CHANGE_NOTIFY Request */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_flags;            /* Flags                   */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   unsigned int umc_completion_filter;      /* CompletionFilter        */
   char       chrc_reserved[ 4 ];           /* Reserved                */
};

struct dsd_smb2_change_notify_response {    /* SMB2 CHANGE_NOTIFY Response */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_output_buffer_offset;  /* OutputBufferOffset */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
};

#ifdef XYZ1
struct dsd_smb2_set_info_request {          /* SMB2 SET_INFO Request   */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned char ucc_info_type;             /* InfoType                */
   unsigned char ucc_file_info_class;       /* FileInfoClass           */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
   unsigned short int usc_input_buffer_offset;  /* InputBufferOffset   */
   char       chrc_reserved[ 2 ];           /* Reserved                */
   unsigned int umc_input_buffer_length;    /* InputBufferLength       */
   unsigned int umc_additional_information;  /* AdditionalInformation  */
   unsigned int umc_flags;                  /* Flags                   */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smb2_set_info_response {         /* SMB2 SET_INFO Response  */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_output_buffer_offset;  /* OutputBufferOffset */
   unsigned int umc_output_buffer_length;   /* OutputBufferLength      */
};
#endif

struct dsd_smb2_set_info_request {          /* SMB2 SET_INFO Request   */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned char ucc_info_type;             /* InfoType                */
   unsigned char ucc_file_info_class;       /* FileInfoClass           */
   unsigned int umc_buffer_length;          /* BufferLength            */
   unsigned short int usc_buffer_offset;    /* BufferOffset            */
   char       chrc_reserved[ 2 ];           /* Reserved                */
   unsigned int umc_additional_information;  /* AdditionalInformation  */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smb2_set_info_response {         /* SMB2 SET_INFO Response  */
   unsigned short int usc_structure_size;   /* StructureSize           */
};

struct dsd_smb2_echo_request {              /* SMB2 ECHO Request       */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chrc_reserved[ 2 ];           /* Reserved                */
};

struct dsd_smb2_echo_response {             /* SMB2 ECHO Response      */
   unsigned short int usc_structure_size;   /* StructureSize           */
   char       chrc_reserved[ 2 ];           /* Reserved                */
};

struct dsd_smb2_session_setup_response {    /* SMB2 SESSION_SETUP Response */
   unsigned short int usc_structure_size;   /* StructureSize           */
   unsigned short int usc_session_flags;    /* SessionFlags            */
   unsigned short int usc_security_buffer_offset;  /* SecurityBufferOffset */
   unsigned short int usc_security_buffer_length;  /* SecurityBufferLength */
};

struct dsd_fs_file_basic_information {      /* File System FileBasicInformation */
   HL_LONGLONG ilc_creation_time;           /* CreationTime            */
   HL_LONGLONG ilc_last_access_time;        /* LastAccessTime          */
   HL_LONGLONG ilc_last_write_time;         /* LastWriteTime           */
   HL_LONGLONG ilc_change_time;             /* ChangeTime              */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   char       chrc_reserved[ 4 ];           /* Reserved                */
};

struct dsd_fs_file_directory_information {  /* File System FileDirectoryInformation */
   unsigned int umc_next_entry_offset;      /* NextEntryOffset         */
   unsigned int umc_file_index;             /* FileIndex               */
   HL_LONGLONG ilc_creation_time;           /* CreationTime            */
   HL_LONGLONG ilc_last_access_time;        /* LastAccessTime          */
   HL_LONGLONG ilc_last_write_time;         /* LastWriteTime           */
   HL_LONGLONG ilc_change_time;             /* ChangeTime              */
   HL_LONGLONG ilc_end_of_file;             /* EndOfFile               */
   HL_LONGLONG ilc_allocation_size;         /* AllocationSize          */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   unsigned int umc_file_name_length;       /* FileNameLength          */
};

struct dsd_fs_file_rename_information_type_2 {  /* File System FileRenameInformation for SMB2 */
   char       chc_replace_if_exists;        /* ReplaceIfExists         */
   char       chrc_reserved[ 7 ];           /* Reserved                */
   char       chrc_root_directory[ 8 ];     /* RootDirectory           */
   unsigned int umc_file_name_length;       /* FileNameLength          */
};

enum ied_smbcc_in_command {                 /* command input to SMB component */
   ied_smbcc_in_invalid = 0,
   ied_smbcc_in_start,                      /* command input start     */
#ifdef SMB_CL_EXT1
   ied_smbcc_in_treeconnect,                /* command treeconnect     */
#endif
   ied_smbcc_in_create,                     /* command SMB2 create     */
   ied_smbcc_in_query_directory,            /* command SMB2 query-directory */
   ied_smbcc_in_complete_file_read,         /* command read complete file */
// to-do 29.12.13 KB - complete_file_read a flag is needed to abend reading - passed from calling program
   ied_smbcc_in_write,                      /* command SMB2 write data */
   ied_smbcc_in_set_info_file,              /* command SMB2 set-info file */
   ied_smbcc_in_rename_file,                /* command SMB2 rename open file */
   ied_smbcc_in_close,                      /* command SMB2 close      */
   ied_smbcc_in_set_notify,                 /* command set notify - FindFirstChangeNotification */
   ied_smbcc_in_del_notify,                 /* command delete notify - FindCloseChangeNotification */
   ied_smbcc_in_echo,                       /* command echo - keepalive */
   ied_smbcc_in_xyz
};


enum ied_smbcc_in_cmd_ret {                 /* return SMB input command */
// to-do 19.08.15 KB - rename to iec_smbcc_r_in
   ied_smbcc_in_r_new = 0,                  /* new command             */
#ifdef SMB_CL_EXT1
   ied_smbcc_in_r_in_prog,                  /* command in progress     */
   ied_smbcc_in_r_in_delayed,               /* delayed, waiting for other command to succeed */
#endif
   ied_smbcc_in_r_ok,                       /* command processed without error */
   ied_smbcc_in_r_not_found,                /* file not found or simular */
   ied_smbcc_in_r_access_denied,            /* access denied           */
   ied_smbcc_in_r_locked,                   /* file is locked          */
   ied_smbcc_in_r_misc_error                /* miscellaneous error     */
};

struct dsd_smbcc_in_cmd {                   /* HOBLink SMB Client Control - input command */
   struct dsd_smbcc_in_cmd *adsc_next;      /* for chaining            */
   enum ied_smbcc_in_command iec_smbcc_in;  /* command input to SMB component */
#ifdef B141027
   BOOL       boc_processed;                /* the command has been processed */
#endif
// to-do 19.08.15 KB - rename to iec_smbcc_r_in
   enum ied_smbcc_in_cmd_ret iec_smbcc_in_r;  /* return SMB input command */
   unsigned int umc_nt_status;              /* returned SMB state      */
};

enum ied_smbcc_out_command {                /* command output from SMB component */
   ied_smbcc_out_invalid = 0,
   ied_smbcc_out_create,                    /* response to create      */
   ied_smbcc_out_dir,                       /* directory information   */
   ied_smbcc_out_read,                      /* data read               */
   ied_smbcc_out_change_notify,             /* change notify received  */
   ied_smbcc_out_close_info,                /* close information       */
   ied_smbcc_out_xyz1
};

struct dsd_smbcc_out_cmd {                  /* HOBLink SMB Client Control - output command */
   struct dsd_smbcc_out_cmd *adsc_next;     /* for chaining            */
   enum ied_smbcc_out_command iec_smbcc_out;  /* command output from SMB component */
};

struct dsd_hl_smb_cl_ctrl {                 /* HOBLink SMB Client Control */
   int        imc_ret_error;                /* return error            */
   void *     ac_ext;                       /* attached buffer pointer */
   struct dsd_smbcc_in_cmd *adsc_smbcc_in_ch;  /* chain of input commands */
   struct dsd_smbcc_out_cmd *adsc_smbcc_out_ch;  /* chain of output commands */
   struct dsd_gather_i_1 *adsc_gai1_nw_recv;  /* received from the network */
   struct dsd_gather_i_1 *adsc_gai1_nw_send;  /* send over network     */
#ifdef XYZ1
   amd_hlsmbcl_get_work_area amc_get_work_area;
   amd_hlsmbcl_get_send_buffer amc_get_send_buffer;
#endif
   BOOL (* amc_aux) ( void *, int, void *, int );  /* auxiliary callback routine */
   void *     vpc_userfld;                  /* User Field Subroutine   */
#ifdef XYZ1
   volatile int imc_signal;                 /* signals occured         */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
#endif
};

#ifdef SMB_CL_EXT1
/** the structure struct dsd_smbcc_tree_1 is followed
   by the tree (share) name UTF-16 little endian.
*/
struct dsd_smbcc_tree_1 {                   /* open tree               */
   struct dsd_smbcc_tree_1 *adsc_next;      /* chaining                */
   void *     vpc_userfld;                  /* user-field              */
   HL_WCHAR   *awcc_tree;                   /* tree name               */
   int        imc_len_tree;                 /* length of tree name in bytes */
   BOOL       boc_done;                     /* treeconnect has been done */
   char       chrc_tree_id[ 4 ];
};

/** the structure struct dsd_smbcc_file_1 is followed
   by the path and file name UTF-16 little endian.
   - no -
*/
struct dsd_smbcc_file_1 {                   /* open files and directories */
   struct dsd_smbcc_file_1 *adsc_next;      /* chaining                */
   struct dsd_smbcc_tree_1 *adsd_smbcc_tree_1;  /* included in tree    */
   void *     vprc_userfld[ 1 ];            /* number of userfld fields */
   HL_WCHAR   *awcc_fn;                     /* file name including path */
   int        imc_len_fn;                   /* length path and file name in bytes */
   BOOL       boc_is_dir;                   /* is directory            */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smbcc_requ_1 {                   /* HOBLink SMB Client Control - request */
   struct dsd_smbcc_requ_1 *adsc_next;      /* for chaining            */
   void *     vprc_userfld[ SMBCC_REQU_1_USERFLD ];  /* number of userfld fields */
   struct dsd_smbcc_file_1 *adsc_smb_file_1;  /* file or directory     */
// struct dsd_smbcc_in_cmd *adsc_smbcc_in;  /* input command           */
   void *     ac_smbcc_in_1;                /* command input           */
   void *     ac_smbcc_in_2;                /* command input appended command */
   struct dsd_smbcc_out_cmd *adsc_smbcc_out_ch;  /* chain of output commands */
   struct dsd_smbcc_out_cmd *adsc_pass_smbcc_out_ch;  /* chain of passed output commands */
   void *     ac_pass_wa_ch;                /* chain of passed workareas */
   enum ied_smbcc_in_command iec_smbcc_in_1;  /* command input to SMB component */
   enum ied_smbcc_in_command iec_smbcc_in_2;  /* command input to SMB component */
// to-do 19.08.15 KB - rename to iec_smbcc_r_in
   enum ied_smbcc_in_cmd_ret iec_smbcc_in_r;  /* return SMB input command */
   unsigned int umc_nt_status;              /* returned SMB state      */
   HL_LONGLONG ulc_command_sequence_number;
};

struct dsd_hl_smb_cl_params {               /* HOBLink SMB Client Control */
   int        imc_ret_error;                /* return error            */
   void *     ac_ext;                       /* attached buffer pointer */
   struct dsd_smbcc_requ_1 *adsc_smbcc_requ_1_ch;  /* HOBLink SMB Client Control - request chain */
// to-do 19.08.15 KB - adsc_smbcc_in_ch to be removed
   struct dsd_smbcc_in_cmd *adsc_smbcc_in_ch;  /* chain of input commands */
   struct dsd_smbcc_out_cmd *adsc_smbcc_out_ch;  /* chain of output commands */
   struct dsd_gather_i_1 *adsc_gai1_nw_recv;  /* received from the network */
   struct dsd_gather_i_1 *adsc_gai1_nw_send;  /* send over network     */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* auxiliary callback routine */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   struct dsd_smbcc_tree_1 *adsc_smbcc_tree_1_ch;  /* chain of open trees */
   struct dsd_smbcc_file_1 *adsc_smbcc_file_1_ch;  /* chain of open files and directories */
};
#endif

#ifdef XYZ1
struct dsd_hlsmbcl_get_work_area {          /* get work area           */
   char       chrc_signature[ 16 ];
};

struct dsd_hlsmbcl_get_send_buffer {        /* get send buffer         */
   char       chrc_signature[ 16 ];
};
#endif

/**
   attention;
   for struct dsd_smbcc_out_file_directory_information
   there is a mapping to struct dsd_fs_file_directory_information
   all values are little endian, exception dsc_ucs_file_name
   ??? should _out_ in the name be removed,
       so that this structure can also be used for input ???
*/
struct dsd_smbcc_file_directory_information {  /* FileDirectoryInformation */
   HL_LONGLONG ilc_creation_time;           /* CreationTime            */
   HL_LONGLONG ilc_last_access_time;        /* LastAccessTime          */
   HL_LONGLONG ilc_last_write_time;         /* LastWriteTime           */
   HL_LONGLONG ilc_change_time;             /* ChangeTime              */
   HL_LONGLONG ilc_end_of_file;             /* EndOfFile               */
   HL_LONGLONG ilc_allocation_size;         /* AllocationSize          */
};

struct dsd_smbcc_in_start {                 /* command input start     */
   BOOL       boc_krb5;                     /* use Kerberos 5 authentication */
   struct dsd_unicode_string dsc_ucs_domain;  /* domain                */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid                */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
   struct dsd_unicode_string dsc_ucs_workstation;  /* workstation      */
   struct dsd_unicode_string dsc_ucs_target_ineta;  /* INETA of target */
   struct dsd_unicode_string dsc_ucs_tree_name;  /* name of tree to connect to */
// struct dsd_unicode_string dsc_ucs_prot_target;  /* protocol and target */
};

enum ied_smbcc_in_create_disp {             /* command input create disposition */
   ied_sicd_appended = 0,                   /* see command appended    */
   ied_sicd_close,                          /* close immediately       */
#ifdef B140513
   ied_sicd_delete,                         /* delete file / directory */
#endif
/* to-do 13.05.14 - delete-file is normal close */
   ied_sicd_delete_file,                    /* delete file             */
   ied_sicd_delete_dir,                     /* delete directory        */
   ied_sicd_keep_open                       /* keep file open for following operations */
};

struct dsd_smbcc_in_create {                /* command input SMB2 create */
   struct dsd_unicode_string dsc_ucs_file_name;  /* filename           */
#ifdef XYZ1
   unsigned int umc_impersonation_level;    /* ImpersonationLevel      */
   char       chrc_smb_create_flags[ 8 ];   /* SmbCreateFlags          */
#endif
   unsigned int umc_desired_access;         /* DesiredAccess           */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   unsigned int umc_share_access;           /* ShareAccess             */
   unsigned int umc_create_disposition;     /* CreateDisposition       */
   unsigned int umc_create_options;         /* CreateOptions           */
   enum ied_smbcc_in_create_disp iec_sicd;  /* command input create disposition */
};

struct dsd_smbcc_in_query_directory {       /* command input SMB2 query-directory */
   struct dsd_unicode_string dsc_ucs_pattern;  /* pattern to search for */
};

struct dsd_smbcc_in_set_ntfy {              /* command input SMB2 CHANGE_NOTIFY */
   unsigned short int usc_flags;            /* Flags                   */
   unsigned int umc_completion_filter;      /* CompletionFilter        */
   void *     vpc_userfld;                  /* userfield               */
};

struct dsd_smbcc_in_del_ntfy {              /* command input SMB2 cancel CHANGE_NOTIFY */
   void *     vpc_userfld;                  /* userfield               */
};

struct dsd_smbcc_in_write {                 /* command input SMB2 write */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   HL_LONGLONG ulc_offset;                  /* Offset                  */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* data to be written      */
};

struct dsd_smbcc_in_set_info_file {         /* command input SMB2 set-info file */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   struct dsd_fs_file_basic_information dsc_fs_file_basic_information;  /* File System FileBasicInformation */
};

struct dsd_smbcc_in_rename_file {           /* command input SMB2 rename open file */
   char       chrc_file_id[ 16 ];           /* FileId                  */
   struct dsd_unicode_string dsc_ucs_new_file_name;  /* new filename   */
};

struct dsd_smbcc_in_close {                 /* command input SMB2 close */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smbcc_out_create {               /* command output SMB2 create */
   char       chrc_file_id[ 16 ];           /* FileId                  */
};

struct dsd_smbcc_out_dir {                  /* command output SMB2 query-directory */
   struct dsd_smbcc_file_directory_information *adsc_fdi;  /* FileDirectoryInformation */
   unsigned int umc_file_attributes;        /* FileAttributes          */
   struct dsd_unicode_string dsc_ucs_file_name;  /* name of file found */
};

struct dsd_smbcc_out_read {                 /* command output SMB2 read */
   char       *achc_data;                   /* address of data         */
   int        imc_length;                   /* length of the data      */
};


struct dsd_smbcc_out_change_notify {        /* command output SMB2 change notify */
   void *     vpc_userfld;                  /* userfield               */
};

struct dsd_smbcc_out_close_info {           /* command output SMB2 close information */
   struct dsd_smbcc_file_directory_information *adsc_fdi;  /* FileDirectoryInformation */
   unsigned int umc_file_attributes;        /* FileAttributes          */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE void m_smb_cl_call( struct dsd_hl_smb_cl_ctrl * );
#ifdef SMB_CL_EXT1
extern PTYPE void m_smb_cl_ext1( struct dsd_hl_smb_cl_params * );
#endif

