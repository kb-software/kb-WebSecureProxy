// 2017.03.06 DD:
//  If you need to use the old HELP_DEBUG facilities, please uncomment the
//      following definition. This way all compilation units that include this
//      header will have exactly the same definitions.
// #define HL_RDPACC_HELP_DEBUG
#define INFO_MOUSE                        0X00000001
#define INFO_DISABLECTRLALTDEL            0X00000002
#define INFO_AUTOLOGON                    0X00000008
#define INFO_UNICODE                      0X00000010
#define INFO_MAXIMIZESHELL                0X00000020
#define INFO_LOGONNOTIFY                  0X00000040
#define INFO_ENABLEWINDOWSKEY             0X00000100
#define INFO_FORCE_ENCRYPTED_CS_PDU       0X00004000
#define INFO_LOGONERRORS                  0X00010000
#define INFO_MOUSE_HAS_WHEEL              0X00020000
#define INFO_NOAUDIOPLAYBACK              0X00080000

#define PTRFLAGS_HWHEEL         0x0400
#define PTRFLAGS_WHEEL          0x0200
#define PTRFLAGS_WHEEL_NEGATIVE 0x0100
#define PTRMASK_WHEEL_ROTATION  0x01FF
#define PTRFLAGS_MOVE           0x0800
#define PTRFLAGS_DOWN           0x8000
#define PTRFLAGS_BUTTON1        0x1000
#define PTRFLAGS_BUTTON2        0x2000
#define PTRFLAGS_BUTTON3        0x3000


#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#define HL_RDP_ACC_DEF

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


#define INFO_MOUSE                       0X00000001
#define INFO_DISABLECTRLALTDEL           0X00000002
#define INFO_AUTOLOGON                   0X00000008
#define INFO_UNICODE                     0X00000010
#define INFO_MAXIMIZESHELL               0X00000020
#define INFO_LOGONNOTIFY                 0X00000040
#define INFO_COMPRESSION                 0X00000080
#define INFO_ENABLEWINDOWSKEY            0X00000100
#define INFO_REMOTECONSOLEAUDIO          0X00002000
#define INFO_FORCE_ENCRYPTED_CS_PDU      0X00004000
#define INFO_RAIL                        0X00008000
#define INFO_LOGONERRORS                 0X00010000
#define INFO_MOUSE_HAS_WHEEL             0X00020000
#define INFO_PASSWORD_IS_SC_PIN          0X00040000
#define INFO_NOAUDIOPLAYBACK             0X00080000
#define INFO_USING_SAVED_CREDS           0X00100000
#define RNS_INFO_AUDIOCAPTURE            0X00200000
#define RNS_INFO_VIDEO_DISABLE           0X00400000
#define INFO_RESERVED1                   0X00800000 // Unused as of 20.12.2016
#define INFO_HIDEF_RAIL_SUPPORTED        0x02000000

#define PERF_DISABLE_WALLPAPER           0X00000001
#define PERF_DISABLE_FULLWINDOWDRAG      0X00000002
#define PERF_DISABLE_MENUANIMATIONS      0X00000004
#define PERF_DISABLE_THEMING             0X00000008
#define PERF_DISABLE_CURSOR_SHADOW       0X00000020
#define PERF_DISABLE_CURSORSETTINGS      0X00000040
#define PERF_ENABLE_FONT_SMOOTHING       0X00000080
#define PERF_ENABLE_DESKTOP_COMPOSITION  0X00000100


// 2.2.1.1.1 RDP Negotiation Request (RDP_NEG_REQ)
// flags:
#define RESTRICTED_ADMIN_MODE_REQUIRED          0x01
#define REDIRECTED_AUTHENTICATION_MODE_REQUIRED 0x02
#define CORRELATION_INFO_PRESENT                0x08
// requestedProtocols:
#define PROTOCOL_RDP        0x00000000
#define PROTOCOL_SSL        0x00000001
#define PROTOCOL_HYBRID     0x00000002
#define PROTOCOL_RDSTLS     0x00000004
#define PROTOCOL_HYBRID_EX  0x00000008

// 2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP)
#define TYPE_RDP_NEG_RSP 0x02
// flags
#define EXTENDED_CLIENT_DATA_SUPPORTED              0x01
#define DYNVC_GFX_PROTOCOL_SUPPORTED                0x02
#define NEGRSP_FLAG_RESERVED                        0x04
#define RESTRICTED_ADMIN_MODE_SUPPORTED             0x08
#define REDIRECTED_AUTHENTICATION_MODE_SUPPORTED    0x10
// selectedProtocols (as requestedProtocols in RDP_NEG_REQ)

// 2.2.1.2.2 RDP Negotiation Failure (RDP_NEG_FAILURE)
#define TYPE_RDP_NEG_FAILURE 0x03
// failureCode
#define SSL_REQUIRED_BY_SERVER                  0x00000001
#define SSL_NOT_ALLOWED_BY_SERVER               0x00000002
#define SSL_CERT_NOT_ON_SERVER                  0x00000003
#define INCONSISTENT_FLAGS                      0x00000004
#define HYBRID_REQUIRED_BY_SERVER               0x00000005
#define SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER   0x00000006

// 2.2.1.3.1 User Data Header (TS_UD_HEADER)
#define CS_CORE             0xC001
#define CS_SECURITY         0xC002
#define CS_NET              0xC003
#define CS_CLUSTER          0xC004
#define CS_MONITOR          0xC005
#define CS_MCS_MSGCHANNEL   0xC006
#define CS_MONITOR_EX       0xC008
#define CS_MULTITRANSPORT   0xC00A
#define SC_CORE             0x0C01
#define SC_SECURITY         0x0C02
#define SC_NET              0x0C03
#define SC_MCS_MSGCHANNEL   0x0C04
#define SC_MULTITRANSPORT   0x0C08

// 2.2.1.3.8 Client Multitransport Channel Data (TS_UD_CS_MULTITRANSPORT)
#define TRANSPORTTYPE_UDPFECR       0x01
#define TRANSPORTTYPE_UDPFECL       0x02
#define TRANSPORTTYPE_UDP_PREFERRED 0x100
#define SOFTSYNC_TCP_TO_UDP         0x200

// 2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1)
#define ENCRYPTION_METHOD_NONE      0x00000000
// When Enhanced RDP Security (section 5.4) is being used, this field MUST be set 
//     to ENCRYPTION_METHOD_NONE (0).
#define ENCRYPTION_METHOD_40BIT     0x00000001
// 40-bit session keys will be used to encrypt data (with RC4) and generate MACs. 
#define ENCRYPTION_METHOD_128BIT    0x00000002
// 128-bit session keys will be used to encrypt data (with RC4) and generate MACs.
#define ENCRYPTION_METHOD_56BIT     0x00000008
// 56-bit session keys will be used to encrypt data (with RC4) and generate MACs.
#define ENCRYPTION_METHOD_FIPS      0x00000010
// All encryption and Message Authentication Code generation routines will be 
//     FIPS 140-1 compliant. 

// 5.3.2 Negotiating the Cryptographic Configuration
//     The Encryption Method and Encryption Level (section 5.3.1) are closely related. 
//     If the Encryption Level is zero, then the Encryption Method is zero 
//     (the converse is also true).
#define ENCRYPTION_LEVEL_NONE               0x00000000
// When Enhanced RDP Security (section 5.4) is being used, this field MUST be set 
//     to ENCRYPTION_LEVEL_NONE
#define ENCRYPTION_LEVEL_LOW                0x00000001
// Low: All data sent from the client to the server is protected by encryption based 
//     on the maximum key strength supported by the client.
#define ENCRYPTION_LEVEL_CLIENT_COMPATIBLE  0x00000002
// Client Compatible: All data sent between the client and the server is protected by
//     encryption based on the maximum key strength supported by the client.
#define ENCRYPTION_LEVEL_HIGH               0x00000003
// High: All data sent between the client and server is protected by encryption based 
//     on the server's maximum key strength.
#define ENCRYPTION_LEVEL_FIPS               0x00000004
// FIPS: All data sent between the client and server is protected using Federal 
//     Information Processing Standard 140-1 validated encryption methods.


#define CHANNEL_OPTION_INITIALIZED   0x80000000   // Absence of this flag indicates that this channel is a placeholder and that the server MUST NOT set it up.
#define CHANNEL_OPTION_ENCRYPT_RDP   0x40000000   // This flag is unused and its value MUST be ignored by the server.
#define CHANNEL_OPTION_ENCRYPT_SC    0x20000000   // This flag is unused and its value MUST be ignored by the server.
#define CHANNEL_OPTION_ENCRYPT_CS    0x10000000   // This flag is unused and its value MUST be ignored by the server.
#define CHANNEL_OPTION_PRI_HIGH      0x08000000   // Channel data MUST be sent with high MCS priority.
#define CHANNEL_OPTION_PRI_MED       0x04000000   // Channel data MUST be sent with medium MCS priority.
#define CHANNEL_OPTION_PRI_LOW       0x02000000   // Channel data MUST be sent with low MCS priority.
#define CHANNEL_OPTION_COMPRESS_RDP  0x00800000   // Virtual channel data MUST be compressed if RDP data is being compressed.
#define CHANNEL_OPTION_COMPRESS      0x00400000   // Virtual channel data MUST be compressed, regardless of RDP compression settings.
#define CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000   // The value of this flag MUST be ignored by the server. 
                                                    // The visibility of the Channel PDU Header (section 2.2.6.1.1) is determined by the 
                                                    // CHANNEL_FLAG_SHOW_PROTOCOL (0x00000010) flag as defined in the flags field (section 2.2.6.1.1).
#define REMOTE_CONTROL_PERSISTENT    0x00100000   // Channel MUST be persistent across remote control transactions.

#define CHANNEL_FLAG_FIRST          0X00000001  /* Indicates that the chunk is the first in a sequence. */
#define CHANNEL_FLAG_LAST           0X00000002  /* Indicates that the chunk is the last in a sequence. */
#define CHANNEL_FLAG_SHOW_PROTOCOL  0X00000010  /* The Channel PDU Header MUST be visible to the application endpoint */
#define CHANNEL_FLAG_SUSPEND        0X00000020  /* All virtual channel traffic MUST be suspended. */
#define CHANNEL_FLAG_RESUME         0X00000040  /* All virtual channel traffic MUST be resumed. */
#define CHANNEL_PACKET_COMPRESSED   0X00200000  /* The virtual channel data is compressed. */
#define CHANNEL_PACKET_AT_FRONT     0X00400000  /* The decompressed packet MUST be placed at the beginning of the history buffer. */
#define CHANNEL_PACKET_FLUSHED      0X00800000  /* The decompressor MUST reinitialize the history buffer */


struct dsd_rdp_neg_req {
    unsigned short int usc_flags;
    unsigned int umc_requested_protocols;
};

struct dsd_rdp_neg_resp {
    unsigned short int usc_type;
    unsigned short int usc_flags;
    unsigned int umc_selected_protocol;
    unsigned int umc_failure_code;
};


enum ied_cc_command {                       /* client component command */
   ied_ccc_invalid,                         /* command is invalid      */
   ied_ccc_start_rdp_client,                /* start the RDP client    */
   ied_ccc_continue_after_ext,              /* continue after external security negotiation */
   ied_ccc_dyn_connect,                     /* dynamic connect         */
   ied_ccc_pass_license,                    /* pass the license information */
   ied_ccc_reconnect,                       /* reconnect the RDP client */
   ied_ccc_events_mouse_keyb,               /* events from mouse or keyboard */
   ied_ccc_send_confirm_active_pdu,         /* send Confirm Active PDU */
   ied_ccc_msc_msgchannel_out,              // send data through the MSC MSGCHANNEL
   ied_ccc_vch_out                          /* output to virtual channel */
};

enum ied_se_command {                       /* command from server     */
   ied_sec_invalid,                         /* command is invalid      */
   ied_sec_rdp_neg_resp,                    /* connection confirm PDU has been received */
   ied_sec_req_dyn_connect,                 /* request parameters for dynamic connect */
   ied_sec_dyn_connect_ok,                  /* dynamic connect succeeded */
   ied_sec_dyn_connect_error,               /* dynamic connect error   */
   ied_sec_update_screen,                   /* update the screen       */
   ied_sec_vch_in,                          /* input from virtual channel */
   ied_sec_msc_msgchannel_in,               // data received through the MSC MSGCHANNEL
   ied_sec_recv_demand_active_pdu,          /* received Demand Active PDU */
   ied_sec_d_deact_pdu,                     /* received demand de-active PDU */
   ied_sec_switch_server,                   /* received connect to other RDP server */
   ied_sec_request_license,                 /* request the licence     */
   ied_sec_save_license,                    /* save the licence        */
   ied_sec_monitor_layout_pdu,              // 2.2.12.1 Monitor Layout PDU
   ied_sec_synchronize_pdu,                 // 2.2.1.14.1 Synchronize PDU Data (TS_SYNCHRONIZE_PDU)
   //ied_sec_save_session_info_pdu,           // 2.2.10.1.1 Save Session Info PDU Data (TS_SAVE_SESSION_INFO_PDU_DATA)
   ied_sec_end_session,                     /* end of session server side */
   ied_sec_end_shutdown                     /* shutdown of server      */
};

struct dsd_cc_co1 {                         /* client component command */
   struct dsd_cc_co1 *adsc_next;            /* next in chain           */
   enum ied_cc_command iec_cc_command;      /* command type            */
};

struct dsd_se_co1 {                         /* command from server     */
   struct dsd_se_co1 *adsc_next;            /* next in chain           */
   enum ied_se_command iec_se_command;      /* command type            */
};

#define TS_MONITOR_PRIMARY      0x00000001

// 2.2.1.3.6.1 Monitor Definition (TS_MONITOR_DEF):
struct dsd_ts_monitor_def {
    int imc_left;           // x-coordinate of the upper-left corner of the display monitor
    int imc_top;            // y-coordinate of the upper-left corner of the display monitor
    int imc_right;          // inclusive x-coordinate of the lower-right corner of the display monitor
    int imc_bottom;         // inclusive y-coordinate of the lower-right corner of the display monitor
    unsigned int umc_flags; // Monitor configuration flags (TS_MONITOR_PRIMARY for the primary display)
};

#define ORIENTATION_LANDSCAPE           0
#define ORIENTATION_PORTRAIT            90
#define ORIENTATION_LANDSCAPE_FLIPPED   180
#define ORIENTATION_PORTRAIT_FLIPPED    270

// 2.2.1.3.9.1 Monitor Attributes (TS_MONITOR_ATTRIBUTES)
struct dsd_ts_monitor_attributes {
    unsigned int umc_physical_width;
    unsigned int umc_physical_height;
    unsigned int umc_orientation;
    unsigned int umc_desktop_scale_factor;
    unsigned int umc_device_scale_factor;
};

struct dsd_sc_monitor_layout_pdu {
   int imc_monitor_count;                           // Number of monitor structures
   struct dsd_ts_monitor_def* adsrc_ts_monitor;     // Monitor Definition (TS_MONITOR_DEF)
};

// 2.2.1.14.1 Synchronize PDU Data (TS_SYNCHRONIZE_PDU)
struct dsd_sc_synchronize_pdu {
    unsigned short int usc_target_user;     // targetUser: The MCS channel ID of the target user.
};

// 2.2.10.1.1.1 Logon Info Version 1 (TS_LOGON_INFO)
struct dsd_ts_logon_info {
    unsigned int umc_cb_domain;
    char chrc_domain[52];
    unsigned int umc_cb_user_name;
    char chrc_user_name[512];
    unsigned int umc_session_id;
};

// 2.2.10.1.1.2 Logon Info Version 2 (TS_LOGON_INFO_VERSION_2)
#define SAVE_SESSION_PDU_VERSION_ONE 0x0001
#define TS_LOGON_INFO_VERSION_2_PAD_LEN 558
struct dsd_ts_logon_info_version_2 {
    unsigned short int usc_version;
    unsigned int umc_size;
    unsigned int umc_cb_domain;
    unsigned int umc_cb_user_name;
    struct dsd_unicode_string dsc_domain;
    struct dsd_unicode_string dsc_user_name;
};

// 2.2.10.1.1.3 Plain Notify (TS_PLAIN_NOTIFY)
#define TS_PLAIN_NOTIFY_PAD_LEN 576

// 2.2.10.1.1.4.1 Logon Info Field (TS_LOGON_INFO_FIELD)
struct dsd_ts_logon_info_field {
    unsigned int umc_cb_field_data;
    char* achc_field_data;
};

// 2.2.10.1.1.4.1.1 Logon Errors Info (TS_LOGON_ERRORS_INFO)
struct dsd_ts_logon_errors_info {
    unsigned int umc_error_notification_type;
    unsigned int umc_error_notification_data;
};

// 2.2.4.2 Server Auto-Reconnect Packet (ARC_SC_PRIVATE_PACKET)
#define AUTO_RECONNECT_VERSION_1 0x00000001
#define AUTO_RECONNECT_VERSION_1_LEN 0x0000001C 
struct dsd_arc_sc_private_packet {
    unsigned int umc_cb_len;
    unsigned int umc_cb_version;
    unsigned int umc_cb_logon_id;
    char chrc_arc_random_bits[16];
};

// 2.2.10.1.1.4 Logon Info Extended (TS_LOGON_INFO_EXTENDED)
#define LOGON_EX_AUTORECONNECTCOOKIE 0x00000001
#define LOGON_EX_LOGONERRORS 0x00000002
#define TS_LOGON_INFO_EXTENDED_PAD_LEN 570
struct dsd_ts_logon_info_extended {
    BOOL boc_has_autoreconnect_cookie;
    BOOL boc_has_logon_errors_info;
    struct dsd_arc_sc_private_packet dsc_autoreconnect_cookie;
    struct dsd_ts_logon_errors_info dsc_logon_errors_info;
};

// 2.2.10.1.1 Save Session Info PDU Data (TS_SAVE_SESSION_INFO_PDU_DATA)
#define INFOTYPE_LOGON                  0x00000000
#define INFOTYPE_LOGON_LONG             0x00000001
#define INFOTYPE_LOGON_PLAINNOTIFY      0x00000002
#define INFOTYPE_LOGON_EXTENDED_INFO    0x00000003

struct dsd_ts_save_session_info_pdu_data {
    unsigned int umc_info_type;
    char* achc_info_data;
};

struct dsd_cc_start_rdp_client {            /* start the RDP client    */
   BOOL boc_multimonitor_support;                   // Activates multimonitor support
   int imc_monitor_count;                           // Number of monitor structures
   struct dsd_ts_monitor_def* adsrc_ts_monitor;     // Monitor Definition (TS_MONITOR_DEF)
   int imc_monitor_attributes_count;                // Number of monitor attributes structures
   struct dsd_ts_monitor_attributes*
       adsrc_ts_monitor_attributes;
   BOOL       boc_compression;              /* with compression        */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_coldep;                   /* colour depth            */
   int        imc_keyboard_layout;          /* Keyboard Layout         */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
// to-do 10.04.12 KB - should RDP-client generate umc_loinf_options from other values - like compression ???
   unsigned int umc_loinf_options;          /* Logon Info Options      */
#ifdef HL_USE_UNICODE_STRINGS
   struct dsd_unicode_string dsc_ucs_domain;
   struct dsd_unicode_string dsc_ucs_username;
   struct dsd_unicode_string dsc_ucs_password;
   struct dsd_unicode_string dsc_ucs_loinf_altsh;
   struct dsd_unicode_string dsc_ucs_loinf_wodir;
#else // HL_USE_UNICODE_STRINGS
   unsigned short int usc_loinf_domna_len;  /* Domain Name Length      */
   unsigned short int usc_loinf_userna_len;  /* User Name Length       */
   unsigned short int usc_loinf_pwd_len;    /* Password Length         */
   unsigned short int usc_loinf_altsh_len;  /* Alt Shell Length        */
   unsigned short int usc_loinf_wodir_len;  /* Working Directory Length */
   HL_WCHAR   *awcc_loinf_domna_a;          /* Domain Name             */
   HL_WCHAR   *awcc_loinf_userna_a;         /* User Name               */
   HL_WCHAR   *awcc_loinf_pwd_a;            /* Password                */
   HL_WCHAR   *awcc_loinf_altsh_a;          /* Alt Shell               */
   HL_WCHAR   *awcc_loinf_wodir_a;          /* Working Directory       */
#endif // HL_USE_UNICODE_STRINGS
   unsigned short int usc_loinf_no_a_par;   /* number of additional parameters */
   unsigned short int usc_loinf_ineta_len;  /* INETA Length            */
   unsigned short int usc_loinf_path_len;   /* Client Path Length      */
   unsigned short int usc_loinf_extra_len;  /* Extra Parameters Length */
   HL_WCHAR   *awcc_loinf_ineta_a;          /* INETA                   */
   HL_WCHAR   *awcc_loinf_path_a;           /* Client Path             */
   void       *awcc_loinf_extra_a;          /* Extra Parameters        */
   struct dsd_unicode_string dsc_ucs_computer_name;  /* computer-name  */
   int        imc_no_virt_ch;               /* number of virtual channels */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual channels */
//#ifdef XYZ1
   int        imc_platform_id;              /* The platform ID of the client */
   char       *achc_machine_name;           /* Name of clients machine, zero-terminated */
//#endif
   char       chrc_client_hardware_data[ 16 ];  /* Mr. Bauer knows     */
   BOOL       boc_allow_hob_rdp_ext1;       /* allow protocol HOB-RDP-EXT1 */
   struct dsd_rdp_neg_req dsc_rdp_neg_req;
   // The MCS message channel will be automatically enabled if any of the following flags is TRUE:
   // Client supports network characteristics detection PDUs [MS-RDPBCGR] 2.2.14:
   BOOL boc_enable_support_netchar_autodetect;
   // Client supports the heartbeat PDU [MS-RDPBCGR] 2.2.16.1:
   BOOL boc_enable_support_heartbeat_pdu;
};

/** the structure dsd_cc_dyn_connect is followed by the UTF-8 command  */
struct dsd_cc_dyn_connect {                 /* dynamic connect         */
   int        imc_len_cmd;                  /* length of command       */
};

struct dsd_cc_pass_license {                /* pass the license information */
   char       *achc_content;                /* address of content      */
   int        imc_len_content;              /* length of content       */
};

struct dsd_cc_events_mouse_keyb {           /* events from mouse or keyboard */
   char *     achc_event_buf;               /* buffer with events      */
   int        imc_events_len;               /* length of events        */
   int        imc_no_order;                 /* number of orders        */
};

struct dsd_se_switch_server {               /* switch to other RDP server - session broker */
    // This part of the structure remains the same as previous versions
    int        imc_len_ineta;                /* length of INETA         */
    char       chrc_ineta[ 16 ];             /* INETA IPV4 / IPV6 to connect to */
    // This part of the structure based on 2.2.13.1 Server Redirection Packet 
    //    (RDP_SERVER_REDIRECTION_PACKET) as of 29.09.2017
    unsigned int umc_session_id;                    // SessionID
    unsigned int umc_redir_flags;                   // RedirFlags
    
    BOOL boc_lb_dont_store_username;                // RedirFlags.LB_DONTSTOREUSERNAME
    BOOL boc_lb_smartcard_logon;                    // RedirFlags.LB_SMARTCARD_LOGON
    BOOL boc_lb_no_redirect;                        // RedirFlags.LB_NOREDIRECT
    BOOL boc_lb_server_tsv_capable;                 // RedirFlags.LB_SERVER_TSV_CAPABLE
    BOOL boc_lb_password_is_pk_encrypted;           // RedirFlags.LB_PASSWORD_IS_PK_ENCRYPTED
    
    unsigned int umc_target_net_address_length;     // TargetNetAddressLength 
    char* achc_target_net_address;                  // TargetNetAddress 
    
    unsigned int umc_load_balance_info_length;      // LoadBalanceInfoLength  
    char* achc_load_balance_info;                   // LoadBalanceInfo 
    
    unsigned int umc_username_length;               // UserNameLength   
    char* achc_username;                            // UserName 
    
    unsigned int umc_domain_length;                 // DomainLength
    char* achc_domain;                              // Domain 
    
    unsigned int umc_password_length;               // PasswordLength
    char* achc_password;                            // Password 
    
    unsigned int umc_target_fqdn_length;            // TargetFQDNLength 
    char* achc_target_fqdn;                         // TargetFQDN 
    
    unsigned int umc_target_netbios_name_length;    // TargetNetBiosNameLength
    char* achc_target_netbios_name;                 // TargetNetBiosName
    
    unsigned int umc_target_net_addresses_length;   // TargetNetAddressesLength   
    char* achc_target_net_addresses;                // TargetNetAddresses

    unsigned int umc_tsv_url_length;                // TsvUrlLength 
    char* achc_tsv_url;                             // TsvUrl

    unsigned int umc_redirection_guid_length;       // RedirectionGuidLength  
    char* achc_redirection_guid;                    // RedirectionGuid

    unsigned int umc_target_certificate_length;     // TargetCertificateLength   
    char* achc_target_certificate;                  // TargetCertificate 
};

struct dsd_se_req_dyn_connect {             /* request parameters for dynamic connect */
   int        imc_options;                  /* options as sent from WSP */
};

/** the structure dsd_se_dyn_connect_error is followed by the UTF-8 error message */
struct dsd_se_dyn_connect_error {           /* dynamic connect error   */
   int        iml_len_msg;                  /* length of error message */
};

struct dsd_sc_request_license {             /* request a license       */
   /* [MS-RDPELE] 2.2.2.6.1 New License Information */
   int        imc_version;                  /* Version                 */
   int        im_num_scopes;                /* number of scopes in list */
   char       **ach_scope;                  /* issuer of license       */
   HL_WCHAR   *awsc_companyname;            /* Company name */
   HL_WCHAR   *awsc_productid;              /* Product id */
};

struct dsd_sc_save_license {                /* save the license        */
   /* [MS-RDPELE] 2.2.2.6.1 New License Information */
   BOOL       boc_new_license;              /* TRUE, if this was a new license request, FALSE, if it was an update license */
   int        imc_version;                  /* Version                 */
   char       *ach_scope;                   /* issuer of license       */
   HL_WCHAR   *awsc_companyname;            /* Company name */
   HL_WCHAR   *awsc_productid;              /* Product id */
   int        imc_len_license_info;         /* length of content       */
   char       *achc_license_info;           /* address of content      */
};

// to-do 07.04.12 KB structure double in .pre file - remove
//struct dsd_sc_vch_out {                     /* server sends output to virtual channel */
struct dsd_rdp_vch_io {                     /* IO RDP virtual channel  */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
// struct dsd_gather_i_1 *adsc_gai1_out;    /* output data             */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
#ifdef B160404
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
#else // B160404
   char       chrc_vch_flags[4];            /* virtual channel flags   */
#endif // B160404
};
struct dsd_rdp_encry {                      /* rdp encryption          */
   char       chrc_cl_pkd[16];              /* pre key data            */
   char       chrc_orig_pkd[16];            /* first key before update */
   char       chrc_rc4_state[ RC4_STATE_SIZE ];  /* RC4 state array    */
   int        imc_count_sent;               /* count blocks sent       */
};

struct dsd_rdp_lic_bb {                     /* licencing binary blob   */
   unsigned short int usc_bb_type;          /* blob type, 2.2.1.12.1.2 */
   unsigned short int usc_bb_len;           /* length of data in byte  */
   char *     achc_bb_data;                 /* content                 */
};

struct dsd_rdp_lic_d {                      /* licensing protocol data */
   char       chc_lic_clcertway;            /* type of first client lic.packet */
   char       chc_lic_vers;                 /* licensing version and some flag */
   int        imc_lic_pkea;                 /* preferred key algorithm */
   int        imc_lic_platform;             /* platform ID             */
   char       chrc_lic_clrand[32];          /* licensing client random */
   struct dsd_rdp_lic_bb dsc_lic_pms;       /* lic. premaster secret   */
   char       chrc_lic_serand[32];          /* licensing server random */
// 08.08.09 KB rename to achc
   char *     chrc_lic_1;                   /* data temporarily needed */
   int        imc_lic_1_len;                /* length of temporary data */
   int        imc_lic_cert_key_len;         /* length of certificate modulus */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_key;            /* certificate modulus     */
   int        imc_lic_cert_exp_len;         /* length of certificate exponent */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_exp;            /* certificate exponent    */
   char       chrc_rc4_state_se2cl[RC4_STATE_SIZE]; /* RC4 state array */
   char       chrc_rc4_state_cl2se[RC4_STATE_SIZE]; /* RC4 state array */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
};

typedef struct {
   unsigned short int ibc_contchno : 1;     /* control channel defined */
   unsigned short int filler : 15;          /* filler                  */
} dtd_rdpfl_1;

#define D_SIZE_HASH          8              /* size of hash            */
#define D_SIZE_HASH_ENHANCED_SECURITY   0

#define D_SEC_HEADER_LEN_ENHANCED_SECURITY  0
#define D_SEC_HEADER_LEN_RDP                4
#define D_SEC_HEADER_LEN_FIPS               8

struct dsd_rdp_vc_1 {                       /* RDP virtual channel     */
   char       byrc_name[8];                 /* name of channel         */
   int        imc_flags;                    /* flags                   */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
// to-do 18.11.15 KB - the following fields are not needed
   char       chc_hob_vch;                  /* virtual channel HOB special */
   char       chc_tose_segfl;               /* to server segmentation flag */
   char       chc_tose_stat_1;              /* to server status 1      */
   int        imc_tose_stat_2;              /* to server status 2      */
   int        imc_tose_stat_3;              /* to server status 3      */
   int        imc_tose_stat_4;              /* to server status 4      */
   void *     ac_tose_pch_save_1_save;      /* save data from this channel */
};

struct dsd_rdp_co_client {                  /* rdp communication       */
   struct dsd_rdp_neg_req dsc_rdp_neg_req;
   struct dsd_rdp_neg_resp dsc_rdp_neg_resp;
   BOOL boc_licensing_done;
   unsigned char ucc_prot_vers;             /* protocol version        */
   int        imc_cl_coldep;                /* client capabilities colour depth */
   unsigned short int usc_cl_supported_color_depth;  /* client capabilities */
   unsigned short int usc_cl_early_capability_flag;  /* client capabilities */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_s_coldep;                 /* session colour depth    */
   int        imc_bpp;                      /* number of bytes per pixel */
   int        imc_keyboard_layout;          /* Keyboard Layout         */
   int        imc_build_number;             /* MS Build Number         */
#ifndef B110722
   int        imc_shareid;                  /* share id, parsed from Demand active PDU */
#endif
   HL_WCHAR   wcrc_computer_name[16];       /* computer name           */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
   int        imc_sec_method;               // encryptionMethod (2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1))
   int        imc_sec_used_keylen;          /* used keylen 03.01.05    */
   // TODO - DD 2017.04.03.: substitute calculated on the fly iml_security_header_len and iml_size_hash
   //    for the following two one-time calculated variables.
   int        imc_sec_header_len;           // Size of the security header part in the PDU
   int        imc_sec_hash_size;            // Size of the HASH
   // imc_sec_level is the equivalent to encryptionLevel in the Server Security Data (TS_UD_SC_SEC1) in the
   //    Server MCS Connect Response PDU with GCC Conference Create Response:
   //    When Enhanced RDP Security (section 5.4) is being used, this field MUST be set to ENCRYPTION_LEVEL_NONE
   int        imc_sec_level;                /* security level          */
   int        imc_l_pub_par;                /* length public parameters */
   int        imc_no_virt_ch;               /* number of virtual channels */
   unsigned short int usc_chno_disp;        /* channel number display  */
   unsigned short int usc_chno_cont;        /* channel number control  */
   unsigned short int usc_chno_mcs_msgchannel; // MCS message channel number
   unsigned short int usc_userid_cl2se;     /* userid client to server */
   dtd_rdpfl_1 dtc_rdpfl_1;                 /* RDP flags               */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual channels */
   struct dsd_progaddr_1 *adsc_progaddr_1;  /* program addresses       */
   struct dsd_cdr_ctrl dsc_cdrf_dec;        /* compression decoding    */
   struct dsd_cdr_ctrl dsc_cdrf_enc;        /* compression encoding    */
   amd_cdr_dec amc_cdr_dec;                 /* routine compression decoding */
   amd_cdr_enc amc_cdr_enc;                 /* routine compression encoding */
   char       chrc_sig[16];                 /* signature               */
   struct dsd_rdp_encry dsc_encry_se2cl;    /* rdp encryption server to client */
   struct dsd_rdp_encry dsc_encry_cl2se;    /* rdp encryption client to server */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
/* new 25.03.07 KB */
   unsigned int umc_loinf_options;          /* Logon Info Options      */
   unsigned short int usc_loinf_domna_len;  /* Domain Name Length      */
   unsigned short int usc_loinf_userna_len;  /* User Name Length       */
   unsigned short int usc_loinf_pwd_len;    /* Password Length         */
   unsigned short int usc_loinf_altsh_len;  /* Alt Shell Length        */
   unsigned short int usc_loinf_wodir_len;  /* Working Directory Length */
   unsigned short int usc_loinf_no_a_par;   /* number of additional parameters */
   unsigned short int usc_loinf_ineta_len;  /* INETA Length            */
   unsigned short int usc_loinf_path_len;   /* Client Path Length      */
   unsigned short int usc_loinf_extra_len;  /* Extra Parameters Length */
   HL_WCHAR   *awcc_loinf_domna_a;          /* Domain Name             */
   HL_WCHAR   *awcc_loinf_userna_a;         /* User Name               */
   HL_WCHAR   *awcc_loinf_pwd_a;            /* Password                */
   HL_WCHAR   *awcc_loinf_altsh_a;          /* Alt Shell               */
   HL_WCHAR   *awcc_loinf_wodir_a;          /* Working Directory       */
   HL_WCHAR   *awcc_loinf_ineta_a;          /* INETA                   */
   HL_WCHAR   *awcc_loinf_path_a;           /* Client Path             */
   void       *awcc_loinf_extra_a;          /* Extra Parameters        */
   struct dsd_rdp_lic_d * adsc_lic_neg;     /* for license negotiation */
   char       *achc_server_capabilities;    /* address storage server capabilities */
   int        imc_len_server_capabilities;  /* length server capabilities */
#ifdef XYZ1
*if def D$RDP$VCH;
*if def B091207B;
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob1;   /* RDP virtual channel HOB1 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob2;   /* RDP virtual channel HOB2 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_rdpdr;  /* RDP virtual channel rdpdr */
*cend;
*cend;
*if def D$RDP$TRAC;
   char       chrc_start_rec[ 4 + D_SIZE_HASH ];  /* start of record   */
   int        imc_len_start_rec;            /* length start of record  */
   int        imc_len_record;               /* length of record        */
   int        imc_len_part;                 /* length of part          */
*cend;
#endif
// if def D$RDP$TRAC;
   char       chrc_start_rec[ 4 + D_SIZE_HASH ];  /* start of record   */
   int        imc_len_start_rec;            /* length start of record  */
   int        imc_len_record;               /* length of record        */
   int        imc_len_part;                 /* length of part          */
// cend;
   int        imc_platform_id;              /* The platform ID of the client */
   char       *achc_machine_name;           /* Name of clients machine, zero-terminated */
   char       chrc_client_hardware_data[16];  /* unique hardware data of the client */
   // TS_UD_CS_CORE::earlyCapabilityFlags:
   unsigned short int usc_cc_early_capability_flags;
   BOOL boc_multimonitor_support;                   // Activates multimonitor support
   int imc_monitor_count;                           // Number of monitor structures
   struct dsd_ts_monitor_def* adsrc_ts_monitor;     // Monitor Definition (TS_MONITOR_DEF)
   int imc_monitor_attributes_count;                // Number of monitor attributes structures
   struct dsd_ts_monitor_attributes*
       adsrc_ts_monitor_attributes;
   // To enable the MCS message channel:
   BOOL boc_enable_mcs_message_channel;
   BOOL boc_mcs_message_channel_active;     // MCS message channel is active
   // Client supports network characteristics detection PDUs [MS-RDPBCGR] 2.2.14:
   BOOL boc_enable_support_netchar_autodetect;
   // Client supports the heartbeat PDU [MS-RDPBCGR] 2.2.16.1:
   BOOL boc_enable_support_heartbeat_pdu;
#ifdef HL_RDPACC_HELP_DEBUG
   int        imc_debug_reclen;
   int        imc_debug_count_event;
#endif
};
#define HL_EXTRA_MCS_CHANNELS 0x1000
enum ied_rdp_mcs_msgchannel_subtype{
    ied_rmms_connection_health_monitoring = 0,
    ied_rmms_network_characteristics_detection
};

struct dsd_rdp_mcs_msgchannel_io {                     // MCS MSGChannel I/O
   enum ied_rdp_mcs_msgchannel_subtype iec_rmms;
   unsigned int umc_data_ulen;
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
};

#define WT_RDP_RT_UPDATE_ORDER    0X10
#define WT_RDP_RT_UPDATE_BITMAP   0X11
#define WT_RDP_RT_SYNCHRONIZE     0X13      /* TS_FP_UPDATE_SYNCHRONIZE */
#define WT_RDP_RT_UPDATE_PTR_NULL 0X15      /* FASTPATH_UPDATETYPE_PTR_NULL */
#define WT_RDP_RT_UPDATE_PTR_DEF  0X16      /* FASTPATH_UPDATETYPE_PTR_DEFAULT */
#define WT_RDP_RT_UPDATE_PTR_POS  0X18      /* FASTPATH_UPDATETYPE_PTR_POSITION */
#define WT_RDP_RT_UPDATE_PTR_COL  0X19      /* FASTPATH_UPDATETYPE_COLOR */
#define WT_RDP_RT_UPDATE_PTR_CACH 0X1A      /* FASTPATH_UPDATETYPE_CACHED */
#define WT_RDP_RT_UPDATE_POINTER  0X1A      /* FASTPATH_UPDATETYPE_POINTER */

struct dsd_wt_record_1 {                    /* WebTerm record          */
   struct dsd_wt_record_1 *adsc_next;       /* for chaining            */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* output data be be sent to client */
   unsigned char ucc_record_type;           /* record type             */
};


struct dsd_call_wt_rdp_client_1 {           /* pass parameters to subroutine */
   int        inc_func;                     /* called function         */
   int        inc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
#ifdef B120310
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */
#else
   struct dsd_gather_i_1 *adsc_gai1_out_to_server;  /* output data to server */
#endif
   struct dsd_wt_record_1 *adsc_wtr1_out;   /* chain of WebTerm records to be sent to client */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer

   void *     ac_ext;                       // attached buffer pointer
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
   BOOL       boc_callrevdir;               /* call on reverse direction */
   BOOL       boc_no_conn_s;                /* do not connect to server */
#ifdef B120310
   BOOL       boc_eof_client;               /* End-of-File Client      */
#else
   BOOL       boc_eof_server;               /* End-of-File Server      */
#endif
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   struct dsd_rdp_co_client *adsc_rdp_co;   /* RDP communication       */
// to-do 23.10.13 KB - remove
   void *     ac_screen_buffer;             /* screen buffer           */
   struct dsd_stor_sdh_1 *adsc_stor_sdh_1;  /* storage management      */
   void *     ac_sub_area;                  /* storage subroutine      */
   struct dsd_cc_co1 *adsc_cc_co1_ch;       /* chain of client commands, input */
   struct dsd_se_co1 *adsc_se_co1_ch;       /* chain of commands from server, output */
   char       *achc_capabilities_client;    /* capabilities of client  */
   int        imc_len_capabilities_client;  /* length capabilities of client */
   BOOL boc_input_pdu_allowed;
};

extern PTYPE void m_wt_rdp_client_1( struct dsd_call_wt_rdp_client_1 * );
