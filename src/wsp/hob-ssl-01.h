#ifndef __HOB_SSL_01__
#define __HOB_SSL_01__
// Required headers: Windows.h(WIN32_LEAN_AND_MEAN possible), hob-unix01.h, hob-xslunic1.h

/** @addtogroup hssl
@{
@file

As this header is public and hob-xsclib01.h does not have include guards, it 
cannot be included here.

This header contains defines and structures needed by the WSP C interface
for the SSL module, Version 3 (WSP 2.3). It combines the headers hob-xshlse03.h,
hob-xshlcl01.h and HOBSSLTP.H.

@}
*/

#ifndef HL_LONGLONG
#ifdef _WIN32
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

struct dsd_gather_i_1;
struct dsd_hl_ocsp_rec;
struct dsd_unicode_string;

#if 0
// Caller Function codes
#endif

#ifndef HSSL_OP_OK
#define HSSL_OP_OK 0
#endif

#if 0
// NOTE: All negative returncodes also indicate a fatal error
// -----
#endif

#ifndef DEF_HL_SSL_S_3
#define DEF_HL_SSL_S_3
#define DEF_SSL_LEN_FINGERPRINT  20
/** @addtogroup hssl
* @{
*/
/** parameters SSL callback */
struct dsd_hl_ssl_ccb_1 {
   void *     vpc_userfld;                  /**< User Field Subroutine   */
   void *     ac_conndata;                  /**< Connect data            */
   char *     achc_fingerprint;             /**< Address fingerprint     */
   char *     achc_certificate;             /**< Address certificate     */
   int        inc_len_certificate;          /**< Length certificate      */
   BOOL       boc_pfs_used;                 /**< Was a key exchange with PFS used? */
};

/**
This specifies the interface for ALPN.

If no callback is specified, the SSL module will assume, that no ALPN is configured.
This means, the client will not send ALPN extensions and the server will not 
answer ALPN extensions.

The context is specified by the caller of the SSL functions. The SSL module will
just hand it to the callback and not evaluate it any further.
*/
struct dsd_alpn_config {
    /**
    The actual callback function.

    This is used to perform a selection on the offered protocols on server side.
    Input is set to the length byte of the first protocol. The list is as received
    by the client. The output parameter is set to the length byte of the selected
    protocol or NULL, if none is to be selected.

    On client side, achp_protocols holds the answer from the server, including a
    possible NULL.

    On error, the SSL will generate a fatal alert.

    If the callback is NULL, a server will continue without selecting any protocol.
    A client will continue and ignore any possible answer from the server.

    @param[out]     aachp_selected      For returning the selected protocol.
    @param[inout]   ap_context          Working context for the ALPN processing.
    @param[in]      achp_protocols      List of protocols in the original TLS encoding.
    @param[in]      unp_input_len       Input length in bytes.

    @return 0 on a selection (including NULL), != 0 on error.
    */
    int (*amc_callback)(const char** aachp_selected,
                        void* ap_context,
                        const char* achp_protocols,
                        unsigned int unp_input_len);

    /**
    Context for the callback. Not modified by HOB SSL.
    */
    void* ac_context;

    /**
    List of possible protocols as array of \0-terminated strings. This is for the client side only.
    */
    char** aachc_protocols;

    /**
    Number of entries in aachc_protocols.
    */
    unsigned int unc_protocol_count;
};

struct dsd_server_sni_config {
    /**
    Callback for the Server Name Indication Extension.

    This callback is ONLY handing over a host name. It is not meant for any other
    server name type. As no other name types are currently used, a more extensible
    interface will be done in future versions of HOB SSL.

    It will be used by the server side only.

    aap_target_cfg can take a config ID as returned by m_se_registerconfig. This
    allows servers to load host-specific configurations. NULL means to keep the
    current configuration.

    On error, the server will send a fatal unrecognized_name alert.

    @param[out] aap_target_cfg      Pointer to new configuration. NULL to keep current.
    @param[in]  ap_context          Working context for the SNI processing.
    @param[in]  adsp_ucs_host_name  Received host name.

    @return 0 on correct processing, != 0 on error.
    */
    int (*amc_callback)(void** aap_target_cfg,
                        void* ap_context,
                        const struct dsd_unicode_string* adsp_ucs_host_name);
    /**
    Context for the SNI callback. Not modified by HOB SSL.
    */
    void* ac_context;
};

#ifndef DEF_HL_OCSP_D_1
#define DEF_HL_OCSP_D_1
/** HOBLink OCSP definition */
struct dsd_hl_ocsp_d_1 {
   struct dsd_hl_ocsp_d_1 *adsc_next;       /**< Next in chain           */
   char       *achc_url;                    /**< URL of OCSP responder   */
   int        inc_url_len;                  /**< Length URL              */
};
#endif

/** 
This struct holds all parameters for m_hlse03.

The gather structs used for the input are handled as follows:

The function m_hlse03 increments the achc_ginp_cur pointer, as it processes the data.
If achc_ginp_cur == achc_ginp_end after the call, all data has been processed
and the gather can be removed from the chain. Otherwise, there is unprocessed 
data left and the remaining data must be present at the next call to m_hlse03.

Example:
achc_ginp_cur is 0x0001 before calling m_hlse03 and 0x00f0 after the call.
achc_ginp_end is 0x0100. With the next call, the data from 0x00f0 to 0x0100 MUST
be the first input again!

New input may be attached to the end of the gather chain between calls.

The start pointers of the output buffers are updated to signal, how far m_hlse03 
has written.

Example:
achc_tocl_cur is 0x0001 before the call to m_hlse03 and 0x00f1 after the call. 
That means, there is data to be sent from 0x0001 to 0x00f0, total 0x00f0 bytes.
*/
struct dsd_hl_ssl_s_3 {
    /** Called function. Expected initial value: DEF_IFUNC_START.
        This must not be modified by the caller after the initial call. */
    int        inc_func;
    /** Return code. DEF_IRET_NORMAL if further processing is possible. 
        DEF_IRET_END on Session end. Error code otherwise.*/
    int        inc_return;

    /** stored return code to assure, that processed data at a session end are using DEF_IRET_NORMAL
        as normal return. */
    int        inc_delay_return;

    /** End-of-File Client. Set this to signal, that the client has closed the socket. */
    BOOL       boc_eof_client;
    /** End-of-File Server. Set this to initiate a normal end of session. */
    BOOL       boc_eof_server;

    /** Data from socket / client.*/
    struct dsd_gather_i_1 *adsc_gai1_fromcl;

    /** Data from applic. / server. */
    struct dsd_gather_i_1 *adsc_gai1_fromse;

    /** Current position of output pointer for received application data.*/
    char *     achc_tose_cur;
    /** End of output buffer for received data.*/
    char *     achc_tose_end;
    
    /** Current position of output pointer for data to be sent.*/
    char *     achc_tocl_cur;
    /** End of output buffer for data to be sent.*/
    char *     achc_tocl_end;

    /** Pointer to the aux function to be used. */
    BOOL (* amc_aux) ( void *vpp_userfld, int, void *, int );
    /** Storage pointer for the SSL module. Initialize with NULL, then do not modify this! */
    void *     ac_ext;
    /** Pointer to configuration. Value from m_se_registerconfig. */
    void *     ac_config_id;
    /** Optional. If set, this function is called, after the handshake is completed. */
    void (* amc_conn_callback) ( struct dsd_hl_ssl_ccb_1 * );
    int (* amc_ocsp_start) ( void * vpp_userfld, struct dsd_hl_ocsp_d_1 * );  //!< OCSP start
    int (* amc_ocsp_send) ( void * vpp_userfld, char *achp_buf, int inp_len );  //!< OCSP send
    struct dsd_hl_ocsp_rec * (* amc_ocsp_recv) ( void * vpp_userfld );  //!< OCSP receive
    void (* amc_ocsp_stop) ( void * vpp_userfld );  //!< OCSP stop
    /** User field for aux function. */
    void *     vpc_userfld;
    /** Session number. Set by the caller. This is added to logging entries. */
    int        imc_sno;
    /** WSP trace level. */
    int        imc_trace_level;
    /** Seed for random. Optional. */
    HL_LONGLONG ilc_entropy;

    /** Pointer to ALPN configuration. If NULL, ALPN will be ignored. Must remain valid for the session. */
    struct dsd_alpn_config* adsc_alpn_cfg;
    
    /** Pointer to SNI configuration. If NULL, SNI will be ignored. Must remain valid for the session. */
    struct dsd_server_sni_config* adsc_sni_cfg;
};
#endif

#ifndef DEF_HL_OCSP_REC
#define DEF_HL_OCSP_REC
/** HOBLink OCSP received. The received data are directly behind
* this structure in memory.   */
struct dsd_hl_ocsp_rec {
   int        inp_data_len;                 /**< length data received    */
   /**< zero = end of connection,
   -1 (or < 0) is error    */
};
/** @} */
#endif
#ifndef DEF_HL_SSL_C_CSSL_1
#define DEF_HL_SSL_C_CSSL_1
/** @addtogroup hssl
* @{
*/
/** Client side SSL options */
struct dsd_cs_ssl_options {
   unsigned int ibc_cs_ssl_no_compression : 1;  /**< Do not use compression */
   unsigned int filler : 31;                /**< Filler                  */
};
/**
This struct holds all parameters for m_hlcl01.

Use of buffers is same as for struct dsd_hl_ssl_s_3.

@see struct dsd_hl_ssl_s_3
*/
struct dsd_hl_ssl_c_1 {
    /** Called function. Expected initial value: DEF_IFUNC_START.
        This must not be modified by the caller after the initial call. */
    int        inc_func;
    /** Return code. DEF_IRET_NORMAL if further processing is possible. 
        DEF_IRET_END on Session end. Error code otherwise.*/
    int        inc_return;
    
    /** stored return code to assure, that processed data at a session end are using DEF_IRET_NORMAL
        as normal return. */
    int        inc_delay_return;

    /** End-of-File Client. Set this to initiate a normal end of session. */
    BOOL       boc_eof_client;
    /** End-of-File Server. Set this to signal, that the server has closed the socket. */
    BOOL       boc_eof_server;

    /** Data from application / client. */
    struct dsd_gather_i_1 *adsc_gai1_in_cl;
    /** Data from socket / server. */
    struct dsd_gather_i_1 *adsc_gai1_in_se;
    
    /** Current position of output pointer for received application data.*/
    char *     achc_out_cl_cur;
    /** End of output buffer for received data.*/
    char *     achc_out_cl_end;
    
    /** Current position of output pointer for data to be sent.*/
    char *     achc_out_se_cur;
    /** End of output buffer for data to be sent.*/
    char *     achc_out_se_end;

    /** Pointer to the aux function to be used. */
    BOOL (* amc_aux) ( void *vpp_userfld, int, void *, int );
    /** Storage pointer for the SSL module. Initialize with NULL, then do not modify this! */
    void *     vpc_ext;
    /** Pointer to configuration. Value from m_se_registerconfig. */
    void *     vpc_config_id;
#ifdef BESPRECHUNG_160822
   BOOL       boc_ignore_unknown_certificate_root;  /* SSL / TLS, IPsec certificate root */
   BOOL       boc_show_certificate_warning_dialogue;  /* SSL / TLS, IPsec show certificate-warning-dialogue */
#endif
    /** Optional. If set, this function is called, after the handshake is completed. */
    void (* amc_conn_callback) ( struct dsd_hl_ssl_ccb_1 * );
    int (* amc_ocsp_start) ( void * vpp_userfld, struct dsd_hl_ocsp_d_1 * );  //!< OCSP start
    int (* amc_ocsp_send) ( void * vpp_userfld, char *achp_buf, int inp_len );  //!< OCSP send
    struct dsd_hl_ocsp_rec * (* amc_ocsp_recv) ( void * vpp_userfld );  //!< OCSP receive
    void (* amc_ocsp_stop) ( void * vpp_userfld );  //!< OCSP stop
    /** User field for aux function. */
    void *     vpc_userfld;
    /** Additional options for client side SSL. */
    struct dsd_cs_ssl_options dsc_cs_ssl_options;
    /** Session number. Set by the caller. This is added to logging entries. */
    int        imc_sno;
    /** WSP trace level. */
    int        imc_trace_level;
    /** Seed for random. Optional. */
    HL_LONGLONG ilc_entropy;

    /** Configuration for ALPN. If NULL, no ALPN will be sent. Must remain valid. */
    struct dsd_alpn_config* adsc_alpn_cfg;
    /**
    Target host name for SNI. If empty, no SNI is sent. This string must be convertible to UTF-8 using m_len_vx_vx/m_cpy_vx_vx.
    */
    struct dsd_unicode_string dsc_ucs_target_host;
};
/** @} */
#endif
#ifndef __XHSERVIF__

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif
/**
Fills the given array of unicode strings with the DNS names of the end 
certificates from the provided configuration.

Names in multiple certificates are put only once. If the array is to small, it
is filled completely and returns the total number of DNS names in the 
certificates. If it is of length 0, it is treated as error. Encoding is 
maintained, as it is.

The strings are only valid, while the configuration is registered.

Only a maximum of 100 names per certificate (Including other types of subject 
alternative names) and 512 different DNS names per configuration can be processed 
by this routine.

@note m_cmpi_vx_vx is used to filter out double names from different certs. Since
      DNS names are generally assumed to be IDNA coding, doubles may appear, 
      while INDA isn't supported by this function.

@param vpp_config_id       Configuration ID pointer returned by m_registerconfig.
@param adsp_ucs_dns_name   Array to which the names are written.
@param imp_no_dns_name     Size of adsrp_ucs_dns_name.

@return Total number of DNS names in the certificates. <0 on error.
*/
extern PTYPE int m_get_ssl_server_cert_dns_names( void * vpp_config_id, 
                                     struct dsd_unicode_string *adsp_ucs_dns_name, 
                                     int imp_no_dns_name );

/** 
This function is the main interface function for server side SSL operations 
of the WSP, version 3.

To start a session, set inc_func to DEF_IFUNC_START and vpc_ext NULL.

The basic processing loop is as follows:

<ol>
    <li> Read new data from the client.
    <li> Add new data from the application.
    <li> Set new output buffers.
    <li> Call m_hlse03.
    <li> Check inc_return. Handle errors as needed.
    <li> Process received data, send data to client.
    <li> Repeat from step 3 (Set new output buffers), until no further output is generated.
    <li> Now, remove FULLY processed input gathers as needed (see Doc of struct dsd_hl_ssl_s_3)
</ol>

Any return value other than DEF_IRET_NORMAL indicates an end of the session.
DEF_IRET_END signals a regular session end. This may be triggered by the client
or by using the EOF flags. Other return values signal an irregular end. This can be 
a Fatal Alert or an internal error.

For more details on the EOF flags and the buffer handling, see struct dsd_hl_ssl_s_3.

When not using the callback, there are two possible signs, that the initial handshake is done:
When m_hlse03 starts using the output for received data, or when m_hlse03 starts 
consuming the data from the application.

@see struct dsd_hl_ssl_s_3

@param pXIF3Struct The control structure for this connection.
*/
extern PTYPE void m_hlse03( struct dsd_hl_ssl_s_3 * pXIF3Struct );
extern PTYPE int m_hssl_getversioninfo( int *, char *, int * );

/**
* Initializes a SSL/TLS configuration and writes it to the configuration array.
*
* Also prepares OCSP and session caching as possible.
*
* Server side only.
*
*  @param pConfigDataBuf        Configuration file buffer
*  @param ConfigDataLen         Length of configuration data
*  @param pCertDataBuf          Certificates file buffer
*  @param CertDataLen           Length of certificate data
*  @param pPwdBuf               Password Buffer
*  @param PwdLen                Length of password Data
*  @param PwdFileFlag           True: Password is from a file
*  @param OcspList              OCSP configuration
*  @param amp_aux               Pointer to auxilery function
*  @param vpp_userfld           User field for amp_aux
*  @param ppConfigID            Pointer to return the generated configuration.
*  @param bop_use_aux_seeding   If true, use m_init_random_aux to initialize the DRBG.
*
*  @return 0 - o.k., else error occured
*/
extern PTYPE int m_se_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                     char * achp_certdatabuf, int inp_certdatalen,
                                     char * achp_pdwbuf, int inp_pdwlen,
                                     BOOL boc_pwdfileflag,
                                     struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                     BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                     void * vpp_userfld,
                                     void ** avpp_config_id,
                                     BOOL bop_use_aux_seeding);
extern PTYPE int m_se_get_conf_timeout( void *vpp_config_id );

/** 
This function is the main interface function for client side SSL operations 
of the WSP.

It works basically just like m_hlse03, with one main difference. In the first 
processing loop, do NOT try to receive data from the server. This is because 
in TLS, the client ALWAYS sends the first message.

Otherwise, use is exactly like m_hlse03.

@see m_hlse03
@see struct dsd_hl_ssl_c_1 

@param pXIFCLStructu The control structure for this connection.
*/
extern PTYPE void m_hlcl01( struct dsd_hl_ssl_c_1 * pXIFCLStructu );

/**
* Initializes a SSL/TLS configuration and writes it to the configuration array.
*
* Also prepares OCSP and session caching as possible.
*
* Entity type is read from the configuration file.
*
* @see HSSL_Init
*
*  @param pConfigDataBuf        Configuration File Buffer.
*  @param ConfigDataLen         Length of Data in Buffer.
*  @param pCertDataBuf          Certificates File Buffer.
*  @param CertDataLen           Length of Data in Buffer.
*  @param pPwdBuf               Password Buffer.
*  @param PwdLen                Length of Password Data.
*  @param PwdFileFlag           True: Password is from a File.
*  @param OcspList              Linked list of OCSP responder URLs.
*  @param amp_aux               Aux function used for memory allocation and other tasks.
*  @param vpp_userfld           User field for aux function.
*  @param ppConfigID            Pointer to return the generated configuration.
*  @param bop_use_aux_seeding   If true, use m_init_random_aux to initialize the DRBG.
*
*  @return int Status 0 - o.k., else error occured
*/
extern PTYPE int m_cl_registerconfig( char * achp_configdatabuf, int inp_configdatalen,
                                     char * achp_certdatabuf, int inp_certdatalen,
                                     char * achp_pdwbuf, int inp_pdwlen,
                                     BOOL boc_pwdfileflag,
                                     struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                     BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                     void * vpp_userfld,
                                     void ** avpp_config_id,
                                     BOOL bop_use_aux_seeding );
extern PTYPE int m_cl_get_conf_timeout( void *vpp_config_id );
extern PTYPE int m_secdrbg_randbytes( char *abyp_dstbuf, int imp_dstlen );

/**
Releases a configuration and all resources associated with it.

It must be assured, that no one uses the configuration anymore before releasing it!
Most importantly, ALL SSL/TLS sessions started with the configuration MUST be 
finished!
This works for both client and server configurations.

@param  amp_aux         Pointer to the aux function, used to release the configuration.
@param  vpp_userfld     User field for the aux function.
@param  vpp_config_id   Pointer to the configuration.

@return HSSL_OP_OK on success, Error code, if amp_aux or vpp_config_id are NULL.
*/
extern PTYPE int m_release_config( BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                   void * vpp_userfld,
                                   void * vpp_config_id );
/**
Fetches the End certificate, that was used by the server during the handshake of the session.

@param[out] aap_addr       Return for the pointer to the certificate.
@param[out] aimp_len       Return for the length of the certificate.
@param[in]  avop_ssl_con   Pointer to the structure of the connection. ac_ext in dsd_hl_ssl_s_3.

@return TRUE on success, FALSE on error.
*/
extern PTYPE BOOL m_get_server_certificate( void **aap_addr,
                                           int *aimp_len,
                                           void * avop_ssl_con );

#endif // __XHSERVIF__

#ifndef __HOB_SSLTP_HEADER__

#define AF_HOBTSSL      1005    // temporary chosen !!

#define HSSL_ONE_PW  (int)-1

#define HSSL_CLIENT  (int)1
#define HSSL_SERVER  (int)0

//
// configuration, certificate and password file
//
#define  SSL_CLIENT_CFG    "hclient.cfg"     // Client configuration file
#define  SSL_CLIENT_PWD    "hclient.pwd"     // Client configuration password file
#define  SSL_CLIENT_CER    "hclient.cdb"     // Client Certificate Data base
#define  SSL_SERVER_CFG    "hserver.cfg"     // server configuration file
#define  SSL_SERVER_PWD    "hserver.pwd"     // server configuration password file
#define  SSL_SERVER_CER    "hserver.cdb"     // server Certificate Data base

#define  HSSL_ERROR_INFO_FILE    "hsec_err.us"
#define  HSSL_ERROR_INFO_FILE_GR "hsec_err.gr"
#define  HSSL_ERROR_SECTION      "error_codes"

// Provider DLL
#define  HOBSSLTP_DLL        "hobssltp.dll"
#define  HOBSSLTP_INIT_PROC  "WSPHSSLInit"
#define  HOBSSLTP_QUERY_PROC "WSPHSSLQuery"


//  The director of the files are in the User path + SETTINGS_SSL_DIR
//  If not the file aren't there the look for Emulation path + SETTINGS_SSL_DIR
//  else error warning and comm-error.
#define SETTINGS_SSL_DIR  "sslsettings\\"

// Password type
#define HSSL_PW_TEXT   0
#define HSSL_PW_FILE   1

#define HSSL_CLIENT_PW_TYPE  8;
#define HSSL_SERVER_PW_TYPE  7;

#if 0
//
// Returned error code
//
#define HSSL_PW_DECODE_ERROR  (int)-200
#define HSSL_PW_ERROR         (int)-201
#define HSSL_OK               (int)0
#define HSSL_BASE_ERROR       WSABASEERR + 400

//
//  init function declaration.
//
// function prototype...
int WINAPI WSPHSSLInit( char* ConfigDataBuf,     // Pointer to the Configuration data
                       int   iConfigDataLen,    // Length of the Configuration data
                       char* CertDataBuf,       // Pointer to the Certification database
                       initializer int   iCertDataLen,      // Length of the Certification database
                       char* PwdBuf,            // Pointer to the password data
                       int   iPwdLen,           // Length of the password data
                       char* reserved,          // reserved (NULL)
                       int   ireservedLen,      // reserved (0)
                       int   iPwdType,          // Password type (HSSL_PW_TEXT or HSSL_PW_FILE)
                       int   iOnlyOnePW,        // reserved (HSSL_ONE_PW)
                       int   iServiceType );    // Service type (HSSL_CLIENT or HSSL_SERVER)

// Pointer to the function "WSPHSSLInit"...
typedef int (WINAPI *_WSPHSSLINIT)( char* ConfigDataBuf,     // Pointer to the Configuration data
                                   int   iConfigDataLen,    // Length of the Configuration data
                                   char* CertDataBuf,       // Pointer to the Certification database
                                   int   iCertDataLen,      // Length of the Certification database
                                   char* PwdBuf,            // Pointer to the password data
                                   int   iPwdLen,           // Length of the password data
                                   char* reserved,          // reserved (NULL)
                                   int   ireservedLen,      // reserved (0)
                                   int   iPwdType,          // Password type (HSSL_PW_TEXT or HSSL_PW_FILE)
                                   int   iOnlyOnePW,        // reserved (HSSL_ONE_PW)
                                   int   iServiceType );    // Service type (HSSL_CLIENT or HSSL_SERVER)
#endif
/*
int WINAPI WSPHSSLQuery( SOCKET Socket,      // Socket to get information
BYTE byInforBuffer [],    // Buffer to receive information
int iInfoLength []);       // Lenght of buffer in array.

*/

struct dsd_ssl_query_info {
   unsigned int   unc_app_tx_data_msw;    //!<  Big-endian Format MSW count, Application send Data;
   unsigned int   unc_app_tx_data_lsw;    //!<  Big-endian Format LSW count,
   unsigned int   unc_app_rx_data_msw;    //!<  Big-endian Format MSW countt, Application received data
   unsigned int   unc_app_rx_data_lsw;    //!<  Big-endian Format LSW count,
   unsigned int   unc_comp_tx_data_msw;   //!<  Big-endian Format MSW count, send Data after compression
   unsigned int   unc_comp_tx_data_lsw;   //!<  Big-endian Format LSW count,
   unsigned int   unc_comp_rx_data_msw;   //!<  Big-endian Format MSW count, received data before decompression
   unsigned int   unc_comp_rx_data_lsw;   //!<  Big-endian Format LSW count,
   unsigned int   unc_pure_tx_data_msw;   //!<  Big-endian Format MSW count, Gross data send on network
   unsigned int   unc_pure_tx_data_lsw;   //!<  Big-endian Format LSW count,
   unsigned int   unc_pure_rx_data_msw;   //!<  Big-endian Format MSW count, Gross data received from network
   unsigned int   unc_pure_rx_data_lsw;   //!<  Big-endian Format LSW count,
   unsigned char  ucc_protocol;           //!<  0=unknown yet, 1=SLL, 2=TLS, 3=TLS1.1, 4=TLS1.2
   unsigned char  ucc_compr_method;       //!<  -1=unknown, 0=none, 0xF4=V42Bis
   unsigned short usc_cipher_suite;       //!<  for intern use.
   unsigned char  ucc_key_exchange;       //!<  0=unknown, 1=RSA, 2=DH-DSS, 3=DH-RSA
   unsigned char  ucc_cipher_algo;        //!<  0=unknown, 1=RC4 128/40 , 2=RC240, 3=DES, 4=3DES, 7=AES
   unsigned char  ucc_cipher_type;        //!<  0= Stream cipher, 1=Block Cipher
   unsigned char  ucc_mac_algo;           //!<  0=unknown, 1=MD5, 2=SHA1, 3=SHA256
   unsigned char  ucc_us_export;          //!<  -1 = unknown, 0=exportable, 1=non exportable
                                          //!< if 1 then RC4 and DES have keys of 40 Bit only
   unsigned char  ucc_authenticate;       //!<  lsb Bit 0 =  1 = Server authenticated
                                          //!<  bit 1 =  1  = Client authenticated
                                          //!<  rest are internally used
   int            imc_ssl_tls_prot_vers;  //!< SSL / TLS protocol version
                                          /**<  Encoding: 0X0001nnnn SSL
                                                0X0002nnnn TLS
                                                0X....nn.. major protocol version
                                                0X......nn minor protocol version
                                          */
   unsigned char  ucc_session_init_mode;  //!<  for intern use
   unsigned char  ucc_server_port_h;      //!<  Server Port number
   unsigned char  ucc_server_port_l;      //!<  Server Port number
   unsigned char  ucrc_server_ip_address[17];   //!<  ServerIPAddress
   unsigned char  ucrc_client_ip_address[17];   //!< ClientIPAddress
   unsigned char  ucrc_session_id [33];         //!<  for intern use
   unsigned char  ucc_partner_name_length_high_byte;  //!< not in used since Partner name is max 127
   unsigned char  ucc_partner_name_length;   //!< MAX 127 Characters
   unsigned char  ucrc_partner_name[256];    //!< Partner Certificate Common Name

};

#endif

#ifdef _WIN32
/**
Sets the path of HOBsecCTE.dll.

This function can be called before invoking m_cl_registerconfig or 
m_se_registerconfig. When setting the path, only this path will be searched
for the DLL. Otherwise, the standard Windows search pattern will be used.

The string must be 0-terminated, non-null and delimited by \.

Example: "C:\\Projects\\ssl\\dlls\\x64\\", not "C:\\Projects\\ssl\\dlls\\x64"

@param[in] awcp_path    Pointer to the wide char string containing the path.
@param[in] szp_len      Length of the path string in wchars, including \0 termination.

@return HSSL_OP_OK on success, error code otherwise.
*/
extern PTYPE int m_set_hssl_dll_path(const LPWSTR awcp_path,
                                     size_t szp_len);

/**
Resets the path set by m_set_hssl_dll_path.
*/
extern PTYPE void m_reset_hssl_dll_path();
#endif

#endif // !__HOB_SSL_01__
