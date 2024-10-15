#ifndef __HOB_SSL_INTERN__
#define __HOB_SSL_INTERN__
// Required headers: Windows.h(WIN32_LEAN_AND_MEAN possible), hob-unix01.h, hob-xsclib01.h, stdlib.h, hob-encry-1.h, hob-cert-ext.h
#ifdef _WIN32
#pragma once
#endif

struct dsd_ecc_keypair;
struct dsd_mem_pool_ele;
struct dsd_memory;

#ifdef XH_INTERFACE
// Version 3.00 is default version
#ifndef XH_INTF_VERSION
#define XH_INTF_VERSION 300
#endif // !XH_INTF_VERSION
#endif

typedef struct HOCSPPAR_t HOCSPPAR;
struct dsd_alpn_config;
typedef struct HEXTCST_t HEXTCST;

#define BIGchar2word(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
        i +=2; \
  }

#define BIGchar2wordn(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
  }

#define BIGword2charn(w,c,i) c[i+1] = (char)((unsigned char) (w        & (unsigned char) 0xFF));\
                             c[i]   = (char)((unsigned char) ((w >> 8) & (unsigned char) 0xFF));

#define BIGchar2longn(c,l,i) \
  {\
    l = ((int)  ((short) c[i+3] & (short) 0xFF)         & (int) 0xFFFF) | \
        ((int) (((short) c[i+2] & (short) 0xFF)  <<  8) & (int) 0xFFFF) | \
        ((int)  ((short) c[i+1] & (short) 0xFF)  << 16) | \
        ((int) (((short) c[i]   & (short) 0xFF)  <<  8) << 16); \
  }

#define BIGlong2charn(l,c,i) c[i+3] = (char) (l       & 0x0FF);\
                             c[i+2] = (char) ((l>> 8) & 0x0FF);\
                             c[i+1] = (char) ((l>>16) & 0x0FF);\
                             c[i]   = (char) ((l>>24) & 0x0FF);

#define BIGlong2char(l,c,i)  c[i+3] = (char) (l       & 0x0FF);\
                             c[i+2] = (char) ((l>> 8) & 0x0FF);\
                             c[i+1] = (char) ((l>>16) & 0x0FF);\
                             c[i]   = (char) ((l>>24) & 0x0FF);\
                             i += 4;
#define	COMPR_TYPES_MAX_COUNT		16		
#define	CIPHER_SUITES_MAX_COUNT		50

enum ied_ec_curve_id {
    ied_ec_curve_none = 0,
    ied_ec_curve_secp256k1 = 22,
    ied_ec_curve_secp256r1,
    ied_ec_curve_secp384r1,
    ied_ec_curve_secp521r1,
    ied_ec_curve_brainpoolP256r1,
    ied_ec_curve_brainpoolP384r1,
    ied_ec_curve_brainpoolP512r1,

};
/**
Writes the current user name to buffer.

The name must be encoded to comply with RFC 5054.
The buffer will be newly allocated, using the provided aux function.
It must be released by the caller.
If an error should occur, an empty string is returned.

@param[out] aachp_name  Pointer for returning the name buffer.
@param[in]  amp_aux     Pointer to the aux function used for allocation.
@param[in]  vpp_userfld Pointer to the user field for the aux function.

@return Length of the user name in bytes, <0 in case of error.
*/
typedef int (* am_get_srp_user_name)(char** aachp_name, 
                       BOOL (* amp_aux) (void *vpp_userfld,int,void *, int),
                       void * vpp_userfld);

/**
Fetches the TLS SRP parameters for a specific user from the password file.

All buffers are allocated using the provided aux function.
They must be released by the caller.

@param[in]  achp_user      Buffer containing the user name.
@param[in]  szp_user_len   Length of the user name in bytes.
@param[out] adsp_dest      Pointer to the structure to be filled.
@param[in]  amp_aux        Pointer to the aux function for allocation.
@param[in]  vpp_userfld    Pointer to the user field for the aux function.

@return 0 on success, <0 otherwise (error code)
*/
typedef int (* am_get_srp_params)(const char* achp_user, size_t szp_user_len, 
                          struct tls_srp_pw_file_params* adsp_dest, 
                          BOOL (* amp_aux) (void *vpp_userfld,int,void *, int),
                          void * vpp_userfld);

/**
Fetches the users SRP password.

The salt is the one sent by the server and may be used to select the correct password.
The password will be encoded conforming to RFC 5054. Unlike the other functions, 
this one gives a buffer for the password. This is for the case, that the used 
password is derived from the actual user password using a KDF. In this case, the buffer
will be completely filled.

@param[in]  achp_salt      Salt used for the key derivation.
@param[in]  szp_salt_len   Length of the salt in bytes.
@param[out] achp_password  Buffer to be filled with the password.
@param[in]  szp_pw_len     Length of the password buffer in bytes.

@return Number of bytes written, <0 Error code on error.
*/
typedef int (* am_get_srp_pw)(const char* achp_salt, size_t szp_salt_len, 
                      char* achp_password, size_t szp_pw_len);

//-------------------------------------------------------------
// Defines Required for the Structures
//-------------------------------------------------------------

#define	RECORD_HDR_SIZE			5	// SSL Record Layer
#define	HT_RECORD_HDR_SIZE		4	// Handshake Msg. header

#define	IP_ADR_MAXLEN			16
#define	MAX_SESSION_ID_LEN		32

#define	HELLO_RANDOM_LEN		28
#define	CLIENT_HELLO_RANDOM_LEN		HELLO_RANDOM_LEN+4	// 32 bytes
#define	SERVER_HELLO_RANDOM_LEN		HELLO_RANDOM_LEN+4	// 32 bytes
#define MASTER_SECRET_LEN		48

#define MAX_MAC_SECRET_LEN		32		// SHA256
#define	MAX_WRITE_KEY_LEN		32		// AES: 32 (256 Bit)
#define	MAX_IV_LEN			16		// 8 used, +8 for MD5
#define MAX_EXPANDED_KEY_LEN		16		// 16 / 8 (DES)

#define EXPECTED_MSG_CNT 3           // Maximum possible handshake messages, following a specific message

#define	SEQUENCE_NUM_LEN		 8

#define	MAX_MD5_SHA1_STATE_SIZE		28
#define	MAX_VERIFY_DATA_LEN		37

#define	COMPR_TYPES_MAX_COUNT		16
#define  SIG_ALGOR_MAX_COUNT         6

#define	EXTCERT_STORE_USED_BIT		0x01	// Flags, Bit 0
#define	EXTCERT_NO_CBD_USED_BIT		0x02	// Flags, Bit 1
#define	EXTCERT_CLNTAUTH_FROM_EXT_BIT	0x04	// Flags, Bit 2

#define	SERVER_CACHE_TYPE		0
#define	CLIENT_CACHE_TYPE		1

#define	SRVR_SESS_CACHE_INITIAL_ELEMENTS_ALLOC_COUNT	10
#define	SRVR_SESS_CACHE_MIN_TIME_TO_LIVE		30	// in seconds

#define	SRVR_SESS_CACHE_DEFAULT_DELTA_EXPIRE_TIME	1800	// 30 min
#define	SRVR_SESS_CACHE_DEFAULT_MAX_ELEMENT_COUNT	2048

#define	CLNT_SESS_CACHE_INITIAL_ELEMENTS_ALLOC_COUNT	10
#define	CLNT_SESS_CACHE_MIN_TIME_TO_LIVE		30	// in seconds

#define	CLNT_SESS_CACHE_DEFAULT_DELTA_EXPIRE_TIME	1800	// 30 min
#define	CLNT_SESS_CACHE_DEFAULT_MAX_ELEMENT_COUNT	1024

#define	CACHE_SESSION_CREATE_NEW		0
#define	CACHE_SESSION_CREATE_USE_EXISTING	1

#define	CACHE_SESSION_TYPE_NON_CACHE	0
#define	CACHE_SESSION_TYPE_NEW		1
#define	CACHE_SESSION_TYPE_RESUMED	2
#define	CACHE_SESSION_TYPE_CLONED	3

#define	CLNT_CACHE_DST_ADR_IPV6_BIT	0x01		// Flag bit 0
#define	CLNT_CACHE_SRC_ADR_IPV6_BIT	0x02		// Flag bit 1
#define	CLNT_CACHE_DST_ADR_PRESENT_BIT	0x04		// Flag bit 2

#define MAX_CONNECTION_ID_LEN		(1+2*16+2*2)	// Flags,2*IPV6,2*Port

#define CLNT_CACHE_FLG_CLONE_INHIBIT	0x01		// Flag bit 0

#ifndef __HOB_V42_BIS__
#define __HOB_V42_BIS__

// Function codes for the En-/Decoder

#define DEF_IFUNC_START 0
#define DEF_IFUNC_CONT  1
#define DEF_IFUNC_RESET 2
#define DEF_IFUNC_END   3

// returncodes from En-/Decoder

#define DEF_IRET_NORMAL 0
#define DEF_IRET_END    1
#if !defined DEF_IRET_ERRAU
#define DEF_IRET_ERRAU  2                   /* error in auxiliary prog */
#endif
#define DEF_IRET_INVDA  3                   /* invalid data found      */
#define DEF_IRET_OVERFLOW 4
#define DEF_IRET_UNDERRUN 4

/*-------------------------------------------------------------------*/
/* Application header files.                                         */
/*-------------------------------------------------------------------*/

/* V.42bis Parameters                                                  */

#define VAL_N3          8                   /* character size (bits)   */
#define VAL_N4          256                 /* number of char alphabet */
#define VAL_N5          (256 + 3)           /* index number first dict */
#define VAL_N6          3                   /* number of control codwo */
#define UNUSED          (-1)                /* this element not used   */

#define CODE_ETM        0                   /* enter transparent mode  */
#define CODE_FLUSH      1                   /* flush data              */
#define CODE_SETUP      2                   /* set up codeword size    */
#define CODE_ECM        0                   /* enter compression mode  */
#define CODE_EID        1                   /* escape character in dat */
#define CODE_RESET      2                   /* force reinitialization  */

#define ESCAPE_MOD      51                  /* modify escape character */

#define LEN_AUX_STOR    4192                /* length auxiliary stor   */

#define UNCOMPRESSED	0
#define COMPRESSED	1

#define DONT_ADD_TREE	0		// default !!
#define MUST_ADD_TREE	1

#define TREE_NOT_FULL	0		// default !!
#define TREE_FULL	1

#define DONT_IGNORE_NEXT_CHAR	0	// default !!
#define IGNORE_NEXT_CHAR	1

#define ENC_CHECK_OK		0
#define ENC_CHECK_ERR		1

//-----------------------------------------------------------------
// Access indices for Dictionary 2 entries: NOTE: Correction for
// direct access from 1st necessary: reduce indices by (N5 * size) !!
//-----------------------------------------------------------------

#ifndef TRACEHL1
#define DIC2_ELEN	4		// number of Entries
#else
#define DIC2_ELEN	5		// number of Entries
#endif

#define ISCHNEXT_INDEX	(0-VAL_N5*DIC2_ELEN)	// same in tree
#define ISCHUP_INDEX	(1-VAL_N5*DIC2_ELEN)	// up in tree
#define ISCHDOWN_INDEX	(2-VAL_N5*DIC2_ELEN)	// down in tree
#define CHVAL_INDEX	(3-VAL_N5*DIC2_ELEN)	// stored node character
#ifdef TRACEHL1
#define CH_TRACE_FLAG_1_INDEX	(4-VAL_N5*DIC2_ELEN)	// traceflag
#endif

// Continue addresses for the decoder

#define DEF_C_DCBU00  0
#define DEF_C_DCCO00  1

// structures for Encoder / Decoder

typedef struct {
  char   bo_compressed;                     /**< state transp / compr    */
  char   ch_escape;                         /**< escape character        */
  short* addic2;                           /**< addr dictionary part 2  */
  char   uscodews_e; 			    /**< C2 no of bits codewo en */
  char   uscodews_d;		            /**< C2 no of bits codewo de */
  short  iscwthreshold; 	            /**< C3 threshold code w s c */
  short  isnextfree;	                    /**< C1 search next free ent */
  short  ispostree;     	            /**< position in tree        */
  short  ilenstr;                           /**< length string found     */
  char   bo_treefull;                       /**< tree is full            */
  char   bo_add_tree;                       /**< add to tree             */
  int  i_shift_v;                         /**< shift-value             */
  char   i_shift_c;                         /**< shift-count             */
  char   bo_ignore_nch;                     /**< ignore next character   */
  /**< save temorary values for transparent mode                         */
  int    ai_st_start_index;                 /**< start of input          */
  int    ao_st_start;                      /**< start of output         */
  char   bo_st_compressed;                  /**< state transp / compr    */
  char   ch_st_escape_1;                    /**< escape character        */
  char   ch_st_escape_2;                    /**< escape character last c */
  char   ch_st_escape_3;                    /**< escape character last c */
  char   us_st_codews;			    /**< save C2 no of bits codw */
  int  i_st_shift_v;                      /**< shift-value             */
  char   i_st_shift_c;                      /**< shift-count             */
  short  i_add_transparent;                 /**< add to transparent len  */
  short ddic1[VAL_N4];                   /**< dictionary part 1       */
} DENC;

typedef struct {
  char   icont;                             /**< address to continue     */
  char   ch_escape;                         /**< escape character        */
  short* addic2;                           /**< addr dictionary part 2  */
  char   uscodews_d;                        /**< C2 no of bits codewo de */
  char   uscodews_e;		            /**< C2 no of bits codewo en */
  short  iscwthreshold; 	            /**< C3 threshold code w s c */
  short  isnextfree;	                    /**< C1 search next free ent */
  short  ispostree;	                    /**< position in tree        */
  short  ilenstr;                           /**< length string found     */
  short  ilenssave;
  int  i_shift_v;                         /**< shift-value             */
  char   i_shift_c;                         /**< shift-count             */
  char   bo_treefull;                       /**< tree is full            */
  short  iswork1;                        /**< save value              */
  char   savedInpByte;                           /**< save last character     */
  char* awork1;                           /**< save value              */
  int	 aindex1;			//!< index
  short ddic1[VAL_N4];                   /**< dictionary part 1       */
} DDEC;

//---------------------------------------------------
// Access Macros for Encoder/Decoder Structures
//---------------------------------------------------

/** @addtogroup v42bis
*@{
*/
/**
* This structure conveys required data / pointers needed to compress/decompress
* given block of data.
*/
typedef struct {
  int   ifunc;                              /**< function of subroutine  */
  int   ireturn;                            /**< return from function    */
  char  bo_sr_flush;                        /**< end-of-record output    */
                                            /**< set by subroutine       */
  char* SrcBuf;			//!< Input Buffer
  int	  SrcStartIndex;		//!< Start of Data, updated !!
  int	  SrcEndIndex;			//!< End of Data + 1
  char* DstBuf;			//!< Output buffer
  int	  DstStartIndex;		//!< Start of Data, updated !!
  int	  DstEndIndex;			//!< End of Data + 1
  DENC* penc;			//!< for Encoder
  DDEC* pdec;			//!< for Decoder
  int ul_param_1;                         /**< parameter value 1       */
  int ul_param_2;                         /**< parameter value 2       */
} DCDR;

#endif // !__HOB_V42_BIS__

#ifndef __HOB_SSL_LOGGING__
#define __HOB_SSL_LOGGING__
/** @addtogroup ssllog
*  @{
*  @file
*  This header defines the class interface used for logging in the HOB SSL
*  module.
*/
/**
*  This abstract class represents a generic interface for generating log entries.
*  A tace level of the object is set at object creation. Generating a log entry
*  is done by the following procedure:
*<ol>
*  <li> Set the trace level of the event with m_event_trace_lvl().
*  <li> Add text and/or binary data with m_add_text_data() and 
*        m_add_binary_data().
*  <li> Generate the entry itself with m_make_log_entry().
*</ol>
*
*  The interpretation of the trace level, for example, if it is a set of flags,
*  or a numerical order depends on the concrete logger.
*  Restrictions, like number and length of text and data blocks or character 
*  count and encoding of the log tag depend on the concrete logger.
*
*  Generally, loggers are not thread safe.
*
*  @author Schulze, Stephan
*  @date 17/10/2012
*/
struct dsd_logger {
public:
   /**
   *  Generates a log entry from the input data and log tag.
   *
   *  Buffers handed to this instance by m_add_text_data and m_add_binary_data
   *  must not be used by this instance after this call, so they can be released.
   *
   *  @param achp_log_tag  Tag string, specifying how the log entry is made
   */
   virtual void m_make_log_entry(const char* achp_log_tag) =0;
   /**
   *  Adds a field of text to be added to next log entry.
   *
   *  This method may just keep a reference to the data buffer, so it should
   *  not be modified untill the log entry is written.
   *
   *  @param achp_data_buf Pointer to the buffer containing the text data
   *  @param inp_len       Length of the text data in the buffer, generally not
   *                       including a terminating 0
   */
   virtual void m_add_text_data(const char* achp_data_buf, int inp_len) =0;
   /**
   *  Adds a field of binary data to be added to next log entry.
   *
   *  This method may just keep a reference to the data buffer, so it should
   *  not be modified untill the log entry is written.
   *
   *  @param achp_data_buf Pointer to the buffer containing the data
   *  @param inp_len       Length of the text data in the buffer
   */
   virtual void m_add_binary_data(char* achp_data_buf, int inp_len) =0;
   /**
   *  Sets the trace level of the upcomming event.
   *
   *  @param inp_target_trace_level Trace level to be set
   */
   virtual void m_event_trace_lvl(int inp_target_trace_lvl) =0;
   virtual ~dsd_logger(){};
};

/**
*  This class writes WSP Trace log entries, using HOB WSP aux interface.
*
*  Pointers to the aux function and user field must be kept valid. They can be
*  updated using the m_reload_field() method.
*
*  Currently, this logger is limited to 2 data blocks, text or binary, per 
*  entry. This may be changed at compile time by changing the field 
*  incc_max_records.
*
*  This logger is not thread safe and should not be reused in new sessions.
*
*  Otherwise, all restrictions of WSP trace apply here as well.
*
*  @author Schulze, Stephan
*  @date 17/10/2012
*/
class dsd_wsp_trace_log : public dsd_logger {
public:
   /**
   *  Generates a new instance of dsd_wsp_trace_log.
   *
   *  If it is specified as client instance, the last 2 of the 8 tag characters
   *  will be "CL", else they will be "SE". The tag is written to the 
   *  chrc_wtrt_id field in the record header structure.
   *
   *  @param inp_trace_lvl    The trace level set by the WSP.
   *  @param bop_is_client    If true, this is generated as client instance
   *  @param inp_session_nr   Session number to be set in the log entries
   *  @param amp_aux          Pointer to the used auxilliary function
   *  @param avop_usr_field   Pointer to the user field for the aux function
   */
   dsd_wsp_trace_log(int inp_trace_lvl, bool bop_is_client, int inp_session_nr,
                     BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ), 
                     void* avop_usr_field);
   /**
   *  Generates the log entry.
   *
   *  The first 6 characters from achp_log_tag are used as the first 6 tag 
   *  characters. No length check is performed on achp_log_tag.
   *
   *  @param achp_log_tag  Tag string to be used
   */
   void m_make_log_entry(const char* achp_log_tag);
   void m_add_text_data(const char* achp_data_buf, int inp_len);
   void m_add_binary_data(char* achp_data_buf, int inp_len);
   void m_event_trace_lvl(int inp_target_trace_lvl);
   /**
   *  Reloads the aux function and user field.
   *
   *  This is specific to this type of logging, so a type cast may be necessary.
   *
   *  The old aux function pointer and user field pointer are replaced.
   *
   *  @param amp_aux          The new aux function pointer to be used
   *  @param avop_usr_field   The new user field pointer to be used
   */
   void m_reload_field(BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ), void* avop_usr_field);
   virtual ~dsd_wsp_trace_log();
private:
   // Prevent copying
   dsd_wsp_trace_log& operator=(const dsd_wsp_trace_log&) const;
   dsd_wsp_trace_log(const dsd_wsp_trace_log&);

   /** Specifies the maximum number of records per entry */
   static const int incc_max_records = 2;
   /** Used trace header structure */
   struct dsd_wsp_trace_header dsc_trace_header;
   /** Trace level of the session */
   const int inc_session_trace_level;
   /** Trace level of the event */
   int inc_event_trace_lvl;
   /** Array of usable trace records */
   struct dsd_wsp_trace_record adsc_trace_record[incc_max_records];
   /** Stored aux function pointer */
   BOOL (* amc_aux) ( void *vpp_userfld, int, void *, int );
   /** Stored user field pointer */
   void* avoc_usr_field;
   /** Array index of the next record to be used by the current event */
   int inc_next_record_index;

};
/** @} */
#endif // !__HOB_SSL_LOGGING__

#ifndef __HOB_SSL_STRUCTURES__
#define __HOB_SSL_STRUCTURES__
/**
* This structure is the internal representation of a configuration for SSL.
*/
typedef struct CFG_STRU_t {
   int Entity;			//!< Client / server type
   int Flags;			//!< Special processing Flags
   char CmprMethodsList[COMPR_TYPES_MAX_COUNT+1]; //!< List of compression methods
   char* CipherSuitesList; //!< List of cipher suites
   char ProtFlags;			//!< TLS/SSL authentication etc.: <br>
   //!<  Bit 0: 1 - Enable SSL 3.0 <br>
   //!<  Bit 1: 1 - Enable TLS 1.0 <br>
   //!<  Bit 2: 1 - Enable client authenticate (Server) <br>
   //!<  Bit 3: 1 - Use server authentication list (Client) <br>
   //!<  Bit 4: 1 - Included Clnt Subj. list (Server) <br>
   //!<  Bit 5: 1 - Excluded Clnt Subj. list (Server) <br>
   //!<  Bit 6: 1 - Allow empty reply to cert request (Server) <br>
   //!<  Bit 7: reserved
   char ExtConfigFlags;		//!< Additional flags: <br>
   //!<  Bit 0: 1 - Enable session caching <br>
   //!<  Bit 1, 2: reserved <br>
   //!<  Bit 3: 1 - Enable TLS 1.2 <br>
   //!<  Bit 4: 1 - Enable TLS 1.1 <br>
   //!<  Bit 5: 1 - Enable remote renegotiate <br>
   //!<  Bit 6: 1 - Enable local renegotiate <br>
   //!<  Bit 7: 1 - Shutdown on renegotiation reject
   short ExtConf2Flags;		//!< Additional flags: <br>
   //!<  Bit 0: 1 - do not send hello request (Server) <br>
   //!<  Bit 1: 1 - accept SSL V2.0 client hello (Server) <br>
   //!<  Bit 2: 1 - embed RDNs in sequence (Server) <br>
   //!<  Bit 3: 1 - do not sort certificate RDNs (Server) <br>
   //!<  Bit 4: 1 - process certificate extensions <br>
   //!<  Bit 5: 1 - allow overlapped time validity <br>
   //!<  Bit 6: 1 - use OCSP for cert. verification <br>
   //!<  Bit 7: 1 - do not use OCSP nonce data <br>
   //!<  Bit 8: 1 - certificates in external store (Client) <br>
   //!<  Bit 9: 1 - additional cert. in database (Client) <br>
   //!<  Bit 10:  1 - interface info in ext. data (Client) <br>
   //!<  Bit 11-13: reserved (cert. store ID) <br>
   //!<  Bit 14: 1 - external cert. dialog always <br>
   //!<  Bit 15: 1 - ignore OCSP produced at time
   char ExtCfgArr[16];	//!< Additional flags
   int CacheAgingTime;		//!< Not yet used
   int RenegotiateTime;		//!< Not yet used
   short CertPolicyFlags;		//!< Processing of invalid certificates. 2 Bits per policy: <br>
   //!<  0 - always reject <br>
   //!<  1 - ask user <br>
   //!<  2 - always accept <br>
   //!<  3 - reserved <br>
   //!<  Bit 0,1: Revoked certificate <br>
   //!<  Bit 2,3: Not yet valid certificate <br>
   //!<  Bit 4,5: Expired certificate <br>
   //!<  Bit 6,7: Expired certificate chain <br>
   //!<  Bit 8,9: Expired root certificate <br>
   //!<  Bit 10,11: No trusted root <br>
   //!<  Bit 12,13: Unknown OCSP status <br>
   //!<  Bit 14,15: WTS generated certificate
   short ConnectTimeout;		//!< Wait time in seconds
   int   MaxConnCount;		//!< Number of connections
   int	ExtConfigDataLen;	//!< Extended config datasize
   char*	pExtConfigData;		//!< Extended configuration buffer/NULL
   int	OcspUrlsDataLen;	//!< Length of OCSP URL buffer  / NOT XH!
   char*	pOcspUrlsBuffer;	//!< URLs for OCSP multi ASCIIz / NOT XH!
   char* SubjCNamesListPtr;	//!< Subject common names list
   CTREESTR * pCertTreeStruc;	//!< Certificates tree pointer
   IDATPARR* pRootRdnArray;	//!< Root RDN array pointer
   int ExtCertsFlags;		//!< Flags for external certificates
   HEXTCST * pExtCertStruc;	//!< Extension structure / NULL
   void (*pAskUserCertsCb)();	//!< Callback function for certificates
#if defined XH_INTERFACE
   struct dsd_hl_ocsp_d_1 * pXhConnStrucList; //!< Connection structures
   ds__hmem CfgMemCtxStruc;	//!< Context structure (copy !!)
   ds__hmem * pCfgMemCtx;		//!< Pointer to structure above
#endif
   int	InitFlags;		//!< Flags from Init
   int	in_usepkcs11;		//!< Flag that PKCS11 (client) to use
   char *  ach_pkcs11dllname;	//!< Path for PKCS11 dll
   char* achc_tls_12_sig_algs; //!< Permitted signature algorithms in internal notation
   int   in_use_cpu_aes;   //!< Flag, indicating permission to use CPU AES
   am_get_srp_user_name amc_get_srp_name;
   am_get_srp_params amc_get_srp_server_params;
   am_get_srp_pw amc_get_srp_pw;
   bool boc_ecc_configured;     //!< shows, ifr ECC ciphers are configured
} CFG_STRU;
   
/**
* This structure is the internal representation of a TX queue element.
*/
typedef struct TX_QEL_st {
	struct TX_QEL_st * pNextTxQel;	//!< NULL if last
	char* pBuf;			//!< Send data buffer, w/o. record hdr
	int	DataLen;		//!< Length of data to send
	int	DataIndex;		//!< Actual index into data
	char	Type;			//!< Type of entry: <br>
					//!< 0 - Application data <br>
					//!< 1 - Change cipher spec <br>
					//!< 2 - Alert, warning only <br>
					//!< 3 - Alert, fatal, close down <br>
					//!< 4 - Handshake message <br>
					//!< 5 - Shutdown message
	char	ProtocolType;		//!< 0 - unknown <br>
					//!< 1 - SSL <br>
					//!< 2 - TLS
} TX_QEL;

/**
* This structure is the internal representation of a RX queue element.
*/
typedef struct RX_QEL_st {
	struct RX_QEL_st * pNextRxQel;	//!< NULL if last
	char* pBuf;			//!< Receive data buffer
	int	DataLen;		//!< Length of data in buffer
	int	DataIndex;		//!< Actual index into data
} RX_QEL;

typedef struct dsd_srp_session_params {
   WLARGENUM* adsc_srv_pub_key;
   WLARGENUM* adsc_cl_pub_key;
   WLARGENUM* adsc_own_priv_key;
   WLARGENUM* adsc_n;
   WLARGENUM* adsc_g;
   WLARGENUM* adsc_verifier;
   char* achc_cl_name;
   int inc_name_len;
   char* achc_salt;
   int inc_salt_len;
}SRP_SESSION_PARAMS ;

/**
* This structure is the internal representation of a RX packet list element.
*/
typedef struct RX_PKT_STRUC_t {
	char *	pDataBuf;		//!< Data buffer start
	int	Offset;			//!< current offset to data
	int	RemainingLen;		//!< Remaining data length in buffer
	int	TotalLen;		//!< Size of buffer
	struct dsd_gather_i_1 * pGatherStruc;//!< associated gather structure
	struct RX_PKT_STRUC_t * pNext;	//!< Next pointer
} RX_PKT_STRUC, * RX_PKT_PTR;

/**
   * This structure contains all data of a single SSL session.
   */
   typedef struct CONNSTRU_st {
      int AppRXDataMSW; //!< Data transferred TO application (MSW)
      int AppRXDataLSW; //!< Data transferred TO application (LSW)
      int ComprRXDataMSW;		//!< Data before decompression (MSW)
      int ComprRXDataLSW;//!< Data before decompression (LSW)
      int RXDataMSW;		//!< Encrypted/compressed (TCP) (MSW)
      int RXDataLSW;//!< Encrypted/compressed (TCP) (LSW)

      int AppTXDataMSW;		//!< Data transferred FROM application (MSW)
      int AppTXDataLSW;//!< Data transferred FROM application (LSW)
      int ComprTXDataMSW;		//!< Data before decompression (MSW)
      int ComprTXDataLSW;//!< Data before decompression (LSW)
      int TXDataMSW;		//!< Encrypted/compressed (TCP) (MSW)
      int TXDataLSW;//!< Encrypted/compressed (TCP) (LSW)

      struct dsd_logger* adsc_logger; //!< Pointer to logger instance
#if (defined _WIN32) && defined PKCS11
      ds_pkcs11_struc pP11Struc;	//!< PKCS11 structure
      unsigned long in_p11certid;	//!< Certificate ID / -1 if none
      X509CERT * ads_p11cert;		//!< Certificate in internal notation
#endif //!< defined _WIN32

#if defined XH_INTERFACE
      ds__hmem MemCtxStruc;		//!< Memory context structure
      ds__hmem * pMemCtxStruc;	//!< Memory context structure pointer
      XH_OCSP_STRUC * pOcspCtxStruc;	//!< OCSP context structure pointer
#endif
      HOCSPPAR * pOcspParamStruc;//!< Parameter structure for OCSP

      CFG_STRU * pCfgStruc;	//!< Associated configuration struct.
      char* pPartnerName;		//!< Name of other side from cert.
      char* pPartnerCert;		//!< Certificate from partner
      int PartnerCertLen;		//!< Size of the certificate
      char PartnerCertHash[SHA_DIGEST_LEN];//!< SHA-1 hash of the certificate

      int  SocketIndex;		//!< Index of the socket from Interface, rel.1 !
      int  SocketMode;		//!< == 0 Blocking <br>
      //!< != 0 Non Blocking
      int  SessionIndex;		//!< Index from Helper, rel.1 !,
      //!< 0 -> none in use
      char  CacheMode;		//!< 0-non cache, 1-new,2-resume,3-clone
      char  HandshakeMode;		//!< 0 -> Normal (Long), else short
      char  RenegotiateMode;		//!< 0-none,1-active

      int DefApplRxTimeout;		//!< 0 - none, > 0 in milliseconds
      int ActApplRxTimeout;		//!< -1 : not set, 0 - none

      char ConnectionState;		//!< Current connection status
      char LockFlag;			//!< Structure lock flag

      short ServerPort;			//!< Port of server
      char ServerIPAdr[IP_ADR_MAXLEN+1];	//!< 16+1 bytes(IP4/6)
      char ClientIPAdr[IP_ADR_MAXLEN+1];	//!< 16+1 bytes(IP4/6)

      char SessionID[MAX_SESSION_ID_LEN+1]; //!< 32+1 bytes
      char ConnectionID[MAX_CONNECTION_ID_LEN+1]; //!< 37+1 bytes

      char CacheFlags;		//!< Bit0: 1-Fast reconnect

      char Entity;			//!< 0-ServerEntity, 1-ClientEntity

      char SupportedProtocolsFlags;	//!< Which protocols are possible <br>
      //!< Bit 0: 1-SSL possible <br>
      //!< Bit 1: 1-TLS possible <br>
      //!< Bit 2: 1-TLS V1.1 possible <br>
      //!< Bit 3: 1-TLS V1.2 possible <br>
      //!< Bit 4-7 reserved

      char AuthFlags;			//!< Bit 0,1 reserved <br>
      //!< Bit 2: 1-Client auth enabled <br>
      //!< Bit 3: 1-Server authlist enabled <br>
      //!< Bit 4: 1-Authlist is include type <br>
      //!< Bit 5: 1-Authlist is exclude type <br>
      //!< Bit 6: 1-Do not end if no clnt cert <br>
      //!< Bit 7: 1-Tryout generated config

      char ExtendedConfigFlags;	//!< Bit 0: 1-Session caching enabled <br>
      //!< Bit 1: reserved <br>
      //!< Bit 2: reserved <br>
      //!< Bit 3: 1-CiphSuit top priority match <br>
      //!< Bit 4: 1-CmprMeth top priority match <br>
      //!< Bit 5: 1-Remote renegotiate enabled <br>
      //!< Bit 6: 1-Local renegotiate enabled <br>
      //!< Bit 7: 1-Shutdown on renegot. reject

      short	ExtendedConf2Flags;	//!< Bit 0: 1-Hello request send disable
      //!< Bit 1: 1-SSLV2 ClientHello accept
      //!< Bit 2-15 reserved

      uint32_t	RenegotiateTime;	//!< Time for renegotiation, 0 -> none
      uint32_t	ActualRenegotiateTimer;	//!< Timer for renegotiate (seconds)

      char	MaximumProtocol;	//!< Max. protocol (Client)
      char	ActualProtocol;		//!< Selected protocol, -1 -> none
      char	ActualComprMethod;	//!< Selected compression,   -1 -> none
      int   ActualCipherSuite;	//!< Selected suite,    -1 -> none
      //-------------------------------------------------------
      //!< Certificate related variables
      //-------------------------------------------------------
      char CertifiedFlags;		//!< Bit 0: 1-Server certified <br>
      //!< Bit 1: 1-Client certified <br>
      //!< Bit 2: 1-Client cert requested <br>
      //!< Bit 3: 1-Server key exch. required <br>
      //!< Bit 4: 1-Client cert verify required

      int RemoteCertPublicAlgor;	//!< Type of remote signature algoritm
      int LocalCertPublicAlgor;	//!< Type of own signature algoritm
      int LocalCNIndex;		//!< Index of local end certificate
      char* abyc_remote_sig_algs;   //!< Remote side signature algorithms.
      //!< Uses signature types as defined in hasn1.h.
      //!< First byte is the number of listed algorithms

      RSA_STRUC* pRemoteRsaStruc;	//!< Remote side RSA structure
      RSA_STRUC* pLocalRsaStruc;		//!< Own RSA structure

      DSA_STRUC* pRemoteDsaStruc;	//!< Remote side DSA structure
      DSA_STRUC* pLocalDsaStruc;		//!< Own DSA structure

      DH_STRUC* pRemoteDhStruc;		//!< Remote side DH structure
      DH_STRUC* pLocalDhStruc;		//!< Own DSA structure

      RSA_STRUC* pTmpRsaStruc;		//!< For ephemeral RSA
      DH_STRUC* pTmpDhStruc;		//!< For ephemeral DH

      //--------------------------------------------------
      //!< key exchange parameters
      //--------------------------------------------------
      char ServerRandom[SERVER_HELLO_RANDOM_LEN];//!< 32 bytes
      char ClientRandom[CLIENT_HELLO_RANDOM_LEN];//!< 32 bytes

      int  PreMasterSecrLen;		//!< Length of actual pre-master secret

      char* PreMasterSecrPtr;	//!< Pointer to pre-master secret
      char MasterSecret[MASTER_SECRET_LEN]; //!< 48 bytes master secret

      char KeyExchgMode;		//!< From ciphersuite: NULL/RSA/DH/DHE
      char KeyMaterialSize;		//!< Size of key material

      char CipherAlgor;		//!< NULL/RC2/RC4/IDEA/DES....
      char CipherType;		//!< Stream [0]/Block [1]
      char KeyLen;			//!< Length of symmetric key
      char IVLen;			//!< Length of Initialization Vector
      char BlockLen;			//!< Length of block

      char MacAlgorType;		//!< NULL / MD5 / SHA1...
      char MACSecretLen;		//!< Length of the MAC secret
      char HashSize;			//!< Size of the hash

      char IsExportable;		//!< Exportable [0], non exportable [1]

      //---------------------------------------------------
      //!< Handshake Hash variables and Hash buffers
      //---------------------------------------------------
      int HandshakeMD5_State[MD5_ARRAY_SIZE]; //!< State array for MD5 hash of handshake messages
      int HandshakeSHA1_State[SHA_ARRAY_SIZE];//!< State array for SHA1 hash of handshake messages
      int HandshakeSHA256_State[SHA256_ARRAY_SIZE];//!< State array for SHA256 hash of handshake messages
      long long HandshakeSHA384_State[SHA384_ARRAY_SIZE];//!< State array for SHA384 hash of handshake messages
      long long HandshakeSHA512_State[SHA512_ARRAY_SIZE];//!< State array for SHA512 hash of handshake messages
      char HandshakeMD5_FinalHash[MD5_DIGEST_LEN];
      //---------------------------------------------------
      //!< Finished verify data buffers / flags
      //---------------------------------------------------
      char HandshakeClntFinished[MAX_VERIFY_DATA_LEN]; //!< Last client finished verify data
      char HandshakeSrvrFinished[MAX_VERIFY_DATA_LEN]; //!< Last server finished verify data
      char SecureRenegotiateFlag;	//!< Secure renegotiation flag
      char* pHandshakeRenegotExt;	//!< Renegotiation extension (sized)
      //===================================================
      //!< Active Cipher States for the record layer
      //===================================================
      //---------------------------------------------------
      //!< a) Receive from the Remote Site
      //---------------------------------------------------
      char ActRX_ComprAlgor;		//!< Active compr. method
      char ActRX_EncAlgor;		//!< Active cipher algor
      char ActRX_MACAlgor;		//!< Active MAC algor

      char ActRX_MACSecret[MAX_MAC_SECRET_LEN];	//!< MAC secret
      char ActRX_Key[MAX_WRITE_KEY_LEN];		//!< Key
      char ActRX_IV[MAX_IV_LEN];			//!< Initialization vect.
      char ActRX_SeqNumber[SEQUENCE_NUM_LEN];	//!< Sequence number

      int ActRX_MAC_I_Array[MAX_MD5_SHA1_STATE_SIZE];	//!< Inner state array for RX MAC
      int ActRX_MAC_O_Array[MAX_MD5_SHA1_STATE_SIZE];	//!< Outer state array for RX MAC

      char*	 ActRX_RC4StateArrayPtr;		//!< *(258 bytes)
      short* ActRX_RC2KeyArrayPtr;			//!< *(128 bytes)
      int* ActRX_DESSubkey1TabPtr;		//!< *(128 bytes)
      int* ActRX_DESSubkey2TabPtr;		//!< *(128 bytes)
      int* ActRX_DESSubkey3TabPtr;		//!< *(128 bytes)
      int* ActRX_AESKeyArrayPtr;			//!< *(240 bytes max.)
      int* ActRX_AESKeyArrayPtrRaw;		//!< *(240 bytes max.)
      void* avoc_recv_gcm_base;
      struct dsd_aes_gcm_state* adsc_recv_gcm_state;
      char chrc_aes_gcm_recv_temp[AES_BLOCK_SIZE+1];

      DCDR*	ActRX_V42BisCdrPtr; //!< V42.bis state structure
      //---------------------------------------------------
      //!< b) Send to the Remote Site
      //---------------------------------------------------
      char ActTX_ComprAlgor;		//!< Active compr. method
      char ActTX_EncAlgor;		//!< Active cipher algor
      char ActTX_MACAlgor;		//!< Active MAC algor

      char ActTX_MACSecret[MAX_MAC_SECRET_LEN];	//!< MAC secret
      char ActTX_Key[MAX_WRITE_KEY_LEN];		//!< Key
      char ActTX_IV[MAX_IV_LEN];			//!< Initialization vect.
      char ActTX_SeqNumber[SEQUENCE_NUM_LEN];	//!< Sequence number

      int ActTX_MAC_I_Array[MAX_MD5_SHA1_STATE_SIZE]; //!< Inner state array for TX MAC
      int ActTX_MAC_O_Array[MAX_MD5_SHA1_STATE_SIZE]; //!< Outer state array for TX MAC

      char*	 ActTX_RC4StateArrayPtr;		//!< (258 bytes)
      short* ActTX_RC2KeyArrayPtr;			//!< (128 bytes)
      int* ActTX_DESSubkey1TabPtr;		//!< (128 bytes)
      int* ActTX_DESSubkey2TabPtr;		//!< (128 bytes)
      int* ActTX_DESSubkey3TabPtr;		//!< (128 bytes)
      int* ActTX_AESKeyArrayPtr;			//!< (240 bytes max.)
      int* ActTX_AESKeyArrayPtrRaw;			//!< (240 bytes max.)
      void* avoc_send_gcm_base;
      struct dsd_aes_gcm_state* adsc_send_gcm_state;
      char chrc_aes_gcm_send_temp[AES_BLOCK_SIZE+1];

      DCDR*	ActTX_V42BisCdrPtr; //!< V42.bis state structure
      //===================================================
      //!< Pending Cipher States for the record layer
      //===================================================
      //---------------------------------------------------
      //!< a) Receive from the Remote Site
      //---------------------------------------------------
      char PendRX_ValidFlag;			//!< != 0 -> states are valid

      char PendRX_ComprAlgor;			//!< Pending compr. method
      char PendRX_EncAlgor;			//!< Pending cipher algor
      char PendRX_MACAlgor;			//!< Pending MAC algorithm

      char PendRX_MACSecret[MAX_MAC_SECRET_LEN];	//!< 20 bytes
      char PendRX_Key[MAX_WRITE_KEY_LEN];	//!< 32 bytes
      char PendRX_IV[MAX_IV_LEN];		//!< 16 bytes (MD5!!)
      //---------------------------------------------------
      //!< b) Send to the Remote Site
      //---------------------------------------------------
      char PendTX_ValidFlag;			//!< != 0 -> states are valid

      char PendTX_ComprAlgor;			//!< Pending compr. method
      char PendTX_EncAlgor;			//!< Pending cipher algor
      char PendTX_MACAlgor;			//!< Pending MAC algorithm

      char PendTX_MACSecret[MAX_MAC_SECRET_LEN];//!< 20 bytes
      char PendTX_Key[MAX_WRITE_KEY_LEN];	//!< 32 bytes
      char PendTX_IV[MAX_IV_LEN];		//!< 16 bytes (MD5!!)
      //===================================================
      //!< Socket Interface Variables
      //===================================================
      //---------------------------------------------------
      //!< a) Receive from the Remote Site
      //---------------------------------------------------
      int  RX_State;				//!< 0 - wait for header <br>
      //!< 1 - reading header <br>
      //!< 2 - wait for fragment <br>
      //!< 3 - reading fragment
      char RX_HeaderBuffer[RECORD_HDR_SIZE]; //!< Received header
      int RxHeaderIndex;			//!< Index into buffer
      int RxHeaderSSLV2CheckEnable;		//!< 0 - no V2 headers allowed

      char* pRxFragmentBuffer;		//!< Received fragment
      int RxFragmentIndex;			//!< Index into buffer
      int RxFragmentOffset;			//!< Start of decrypted fragment
      int RxFragmentSize;			//!< Size of fragment
      int RxFragmentToReadCount;		//!< Bytes still to receive
      //---------------------------------------------------
      //!< b) Send to the Remote Site
      //---------------------------------------------------
      int  TX_State;				//!< 0 - no TX active <br>
      //!< 1 - TX wait buffer <br>
      //!< 2 - TX in progress

      TX_QEL * pPriorityTxQueueHead;	//!< Pointer to start of queue for handshake/CCS/alerts
      TX_QEL * pPriorityTxQueueTail;	//!< Pointer to end of queue for handshake/CCS/alerts
      TX_QEL * pApplicationTxQueueHead;	//!< Pointer to start of queue for User Data	
      TX_QEL * pApplicationTxQueueTail;	//!< Pointer to end of queue for User Data	

      char* pTxFragmentBuffer;		//!< Actual fragment in TX state
      int	TxFragmentOffset;		//!< Start of data to hash
      int	TxFragmentIndex;		//!< Index into buffer
      int	TxFragSrcBufLen;		//!< Length of buffer
      int	TxFragmentToWriteCount;		//!< Count of bytes still to send
      char	TxFragmentType;			//!< Copy of TX-QEL type
      char	TxFragmentProt;			//!< Copy of TX-QEL protocol
      //===================================================
      //!< Handshake Layer Assemble Variables
      //===================================================
      //---------------------------------------------------
      //!< Alert Receive from the Remote Site
      //---------------------------------------------------
      char Alert_RX_State;			//!< 0 - Wait 1st byte <br>
      //!< 1 - Wait 2nd byte
      char Alert_RxLevel;			//!< Warning/fatal
      char Alert_RxDescr;			//!< Alert number
      //---------------------------------------------------
      //!< Handshake Receive from the Remote Site
      //---------------------------------------------------
      int  Handshake_RX_State;		//!< 0 - wait for header <br>
      //!< 1 - reading header <br>
      //!< 2 - wait for data <br>
      //!< 3 - reading data

      char Handshake_RX_LastMessage;		//!< 0 -idle/Hello Request,
      //!< else last handshake
      //!< message processed. NOTE:
      //!< Certverify gets internal
      //!< number 17 instead of 15 !!

      char Handshake_RX_HdrBuffer[HT_RECORD_HDR_SIZE]; //!< Record header
      int Handshake_RxHdrIndex;		//!< Index into header

      char* pHandshake_RxMsgDataBuffer;	//!< Received data
      int HandshakeRxDataIndex;		//!< Index into buffer
      int HandshakeRxDataSize;		//!< Size of fragment
      int HandshakeRxDataToReadCount;	//!< Bytes still to receive
      //---------------------------------------------------
      //!< Application Data Receive from the Remote Site
      //!< NOTE: will not be assembled !!
      //---------------------------------------------------
      RX_QEL * pApplicationRxQueueHead;	//!< Pointer to start of queue for user data	
      RX_QEL * pApplicationRxQueueTail;	//!< Pointer to end of queue for user data	

#if defined XH_INTERFACE
      //!< NEW NEW NEW FOR XH-Interface, no Macros !!!
      RX_PKT_PTR pSSLRxPktInUseAnchor;	//!< In use packet list
      RX_PKT_PTR pSSLRxPktToFreeAnchor;	//!< To free packet list anchor
      RX_PKT_PTR pSSLRxPktToFreeTail;		//!< To free packet list tail
      RX_PKT_PTR pSSLActRxPkt;		//!< Actual SSL RX packet

      RX_PKT_PTR pAPPRxPktInUseAnchor;	//!< In use packet list
      RX_PKT_PTR pAPPRxPktToFreeAnchor;	//!< To free packet list anchor
      RX_PKT_PTR pAPPRxPktToFreeTail;		//!< To free packet list tail
      RX_PKT_PTR pAPPActRxPkt;		//!< Actual application RX pack.

      int  SSLPktRxState;			//!< Receive state for packet

#define	SSL_PKT_FIRST_GET	0
#define	SSL_PKT_HDR_GET		1
#define	SSL_PKT_DECRYPT		2
#define	SSL_PKT_PROCESS		3
#define SSL_PKT_INIT_DEC    4

      int  RecordSkipFlag;			//!< Record data shall be skipped
      int  RecordSkipLen;			//!< Data to skip count

      char BlockBuffer[16];			//!< Buffer for decrypt
      int  BlockBufOffset;			//!< Offset into buffer
      int  BlockBufDataLen;			//!< Data length in buffer
      int  BlockBufInUse;			//!< Block buffer is in use

      char * pDecryptBuf;			//!< Decryption dest. buffer
      int  DecryptOffset;			//!< Index into buffer
      int  DecryptRequiredLen;		//!< still required datacount
      int  DecryptLen;			//!< total size
      int  SSLV2Flag;				//!< SSL-V2 received

      int  APPPktTxState;			//!< Transmit state for packet

#define	APP_PKT_FIRST_GET	0
#define	APP_PKT_PROCESS		1
#define	APP_PKT_HDR_SEND	2
#define	APP_PKT_PREFIX_SEND	3
#define	APP_PKT_DATA_SEND	4
#define	APP_PKT_POSTPROCESS	5

      char EncTxHeader[RECORD_HDR_SIZE];	//!< Application transmit header
      int  EncHdrSendLen;			//!< length of data to send
      int  EncHdrSendIndex;			//!< offset into header

      char EncBlockBuffer[16];		//!< for TLS V1.1
      int  EncBlockIndex;			//!< dto.
      int  EncBlockLen;			//!< dto.

      char MacPadBuffer[48];			//!< MAC/Padding buffer
      int  MacPadOffset;			//!< Offset into buffer
      int  MacPadLen;				//!< Length of MAC/Padding

      char PartialEncBuf[16];			//!< Encryptblock buffer
      int  PartialEncOff;			//!< Offset into buffer
      int  PartialEncLen;			//!< Size of data in buffer

      char * pEncSrcBuf;			//!< Encryption source buffer
      int  EncSrcOffset;			//!< Actual offset to data
      int  EncSrcLen;				//!< Size of data

      char * pEncryptBuf;			//!< Encryption dest. buffer
      //!< int  EncryptOffset;			//!< Offset into buffer
      //!< int  EncryptLen;			//!< Size for encryption

      char ** pEncDstStart;			//!< Start of output buffer
      char * pEncDstEnd;			//!< End of output buffer

      //!< NEW NEW NEW
#endif //!< XH_NEW_INTERFACE
      // This entry holds parameters for SRP
      SRP_SESSION_PARAMS* adsc_srp_params;
      uint16_t usrc_expected_handshake_messages[EXPECTED_MSG_CNT+1];
      
      struct dsd_alpn_config* adsc_alpn_cfg;            //<! Configuration for ALPN extension
      char* achc_selected_alpn;                         //<! String for the selected protocol during ALPN
      
      struct dsd_unicode_string dsc_ucs_se_host_name;   //<! Server host name
      struct dsd_server_sni_config* adsc_sni_cfg;       //<! Configuration for SNI extension
      
      enum ied_ec_curve_id iec_selected_curve;          //<! Internal identifier for selected EC curve
      bool boc_ecc_possible;                            //<! Signal, if this connection may do ECC
      struct dsd_ecc_keypair dsc_ecc_keypair;           //<! Key pair structure for ECDHE
      struct dsd_mem_pool_ele* adsc_mem_pool;           //<! Memory pool for ECC operations
      unsigned int unc_pool_ele_size;                   //<! Byte size of a single pool element
      struct dsd_memory dsc_mem_mgr;                    //<! Memory manager for ECC operations
} CONNSTRU;

#endif // !__HOB_SSL_STRUCTURES__

#ifndef __HOB_SSL_DEFINES__
#define __HOB_SSL_DEFINES__

//-------------------------------------------------------------
// Definitions from hssl.h
//-------------------------------------------------------------

//-------------------------------------------------------------
// General Definitions
//-------------------------------------------------------------

#define HSSL_VERSION			1
#define HSSL_REVISION			0

#ifndef SERVER_ENTITY
#define	SERVER_ENTITY			0	// NOTE: same in HASN1.H
#define CLIENT_ENTITY			1	// dto.
#endif

#define	ENTITY_BIT_MASK			0x01	// Bit 0 is entity !! --> VPN!

#define	SERVER_DEFAULT_CONNECTIONS	512	// use if count in config is 0
#define	CLIENT_DEFAULT_CONNECTIONS	32	// use if count in config is 0

#define	DEFAULT_CONNECT_TIMEOUT		60	// 60 seconds

#define	DELAYED_RND_INIT_BIT		0x01	// Bit 0 for JAVA DBRG init

//------------------------------------------------------
// TCP Interface Definitions
//------------------------------------------------------

#define	CONN_STATE_NOT_INITIALIZED	0
#define CONN_STATE_HANDSHAKE_PHASE	1
#define CONN_STATE_CONNECTED		2
#define	CONN_STATE_REMOTE_CLOSE_PENDING	3
#define CONN_STATE_LOCAL_CLOSE_PENDING	3
#define	CONN_STATE_CLOSED		4

#define	BLOCKING_MODE			0
#define NON_BLOCKING_MODE		1
#define BLOCKING_MODE_MASK		0x01

#define TCP_SEND_FUNCTION		1
#define TCP_RECEIVE_FUNCTION		2
#define	TCP_SELECT_RECV_FUNCTION	3
#define	TCP_SHUTDOWN_FUNCTION		4
#define	TCP_TIMEOUT_FUNCTION		5

#define	TCP_TX_TIMEOUT_GET		0
#define	TCP_TX_TIMEOUT_SET		1
#define	TCP_RX_TIMEOUT_GET		2
#define	TCP_RX_TIMEOUT_SET		3

#define	TCP_OPERATION_TIMEOUT		1000	// 1 second (1000 msec)

#define UNGRACEFUL			0
#define GRACEFUL			1

// Shutdown Errorcodes

#define ALERT_GENERATE_FAILURE		-20000
#define GATHER_FAILURE			-20001
#define COMPRESS_FAILURE		-20002
#define MAC_APPEND_FAILURE		-20003
#define ENCRYPT_FAILURE			-20004
#define TX_CHG_CIPHERSUITE_ERR		-20005
#define REMOTE_SHUTDOWN_FAILURE		-20006
#define	SRCBUF_GET_FAILURE		-20007
#define	DSTBUF_GET_FAILURE		-20008
#define	RAND_PREPEND_FAILURE		-20009

#define TX_FATAL_ALERT			-30000	// special case: graceful

#define TCP_RX_HDR_WAIT			0	// Wait for SSL Record Header
#define TCP_RX_HDR_READ			1	// Reading header
#define TCP_RX_FRAGMENT_BUF_WAIT	2	// Wait for Fragment buffer
#define TCP_RX_FRAGMENT_READ		3	// Reading Fragment
#define TCP_RX_DSTBUF_WAIT		4	// Waiting for Decompress Buf.

#define TCP_TX_INACTIVE			0	// nothing waiting
#define TCP_TX_SRCBUF_WAIT		1	// waiting for source buffer
#define TCP_TX_DSTBUF_WAIT		2	// waiting for temp. buffer
#define	TCP_TX_FRAGMENT_WRITE		3	// sending data
#define	TCP_TX_FRAGMENT_POSTPROCESS	4	// postprocessing

//------------------------------------------------------
// Alert Client Interface Definitions
//------------------------------------------------------

#define	ALERT_WAIT_1ST_BYTE		0	// Wait for 1st byte
#define	ALERT_WAIT_2ND_BYTE		1	// Wait for 2nd byte

//------------------------------------------------------
// Ciphersuite definitions
//------------------------------------------------------

#define	CIPH_TLS10_SSL			0x01	// useable for TLS V1.0/SSL
#define	CIPH_TLS11			0x02	// useable for TLS V1.1
#define	CIPH_TLS12			0x04	// useable for TLS V1.2

//------------------------------------------------------
// Handshake Client Interface Definitions
//------------------------------------------------------

#define	HS_RX_HDR_WAIT			0	// Wait for start of header
#define HS_RX_HDR_READ			1	// Reading Header
#define HS_RX_MSG_READ			2	// Reading Message

//------------------------------------------------------
// Transmit Queues Data-Type definitions
//------------------------------------------------------

#define TX_TYPE_APPLICATION_DATA	0	// may be combined
#define TX_TYPE_CHANGE_CIPHER_SPEC	1	// not combinable
#define TX_TYPE_ALERT_WARNING		2	// not combinable
#define TX_TYPE_ALERT_FATAL		3	// not combinable
#define TX_TYPE_HANDSHAKE_MSG		4	// may be combined
#define TX_TYPE_SHUTDOWN		5	// not combinable, no send !

//-------------------------------------------------------
// SSL V2 Hello Message definitions
// NOTE: Data Starts with Record Header (5 bytes, offset 0)
//-------------------------------------------------------

#define	SSL_V2_CIPHER_SPEC_LEN_INDEX	5	// Cipherspec Length
#define	SSL_V2_SESSION_ID_LEN_INDEX	7	// Session-ID Index
#define	SSL_V2_CHALLANGE_LEN_INDEX	9	// Challenge Length

#define	SSL_V2_HDR_LEN			5	// len, MsgType, Version
#define	SSL_V2_CLIENT_HELLO_FIXED_LEN	6	// sizes

#define	SSL_V2_CHALLENGE_MIN_LEN	0x10	// minimum length
#define	SSL_V2_CHALLENGE_MAX_LEN	0x20	// maximum length

#define	SSL_V2_MIN_CLIENT_HELLO_LEN	28	// minimum required
#define	SSL_V2_MAX_CLIENT_HELLO_LEN	256	// maximum assumed (50 suites)

//-------------------------------------------------------
// SSL Record max. lengths
//-------------------------------------------------------

#define	SSL_V2_MIN_RECORD_LEN		11
#define	SSL_V2_MAX_RECORD_LEN		32767

#define SSL_PLAIN_RECORD_MAX_LEN	16384
#define SSL_COMPR_RECORD_MAX_LEN	(16384+1024)
#define SSL_CIPH_RECORD_MAX_LEN		(16384+2048)
#define SSL_RECORD_ADDITIONAL_LEN	2048
#define SSL_COMPR_ADDITIONAL_LEN	1024

#define	COMPR_TYPES_MAX_COUNT		16	

#define DEFAULT_SESS_ID_LEN		32
#define SESS_ID_GEN_RETRY_COUNT		100

//#define	RESERVED			255

#define TLS_SSL_MAJOR_VERSION		3		// SSL/TLS1.0/1.1/1.2
#define TLS12_MINOR_VERSION		3
#define TLS11_MINOR_VERSION		2
#define TLS10_MINOR_VERSION		1
#define SSL_MINOR_VERSION		0

#define	VERSION_SIZE			2

#define	SESSION_ID_LEN_SIZE		1		// 1 Byte
#define	HELLO_RANDOM_LEN		28
#define	UTC_TIME_LEN			4
#define	CLIENT_HELLO_RANDOM_LEN		HELLO_RANDOM_LEN+4	// 32 bytes
#define	SERVER_HELLO_RANDOM_LEN		HELLO_RANDOM_LEN+4	// 32 bytes
#define HMAC_BLOCKLEN			64
#define TLS_VERIFY_DATA_LEN		12
#define MAX_VERIFY_DATA_LEN		37		// 16+20+1 bytes

//-------------------------------------------------------------
// SSL Record Header Definitions (Offsets, Sizes)
//-------------------------------------------------------------

#define	RH_TYPE			0
#define	RH_VERSION		1
#define	RH_VERSION_MSB		1
#define	RH_VERSION_LSB		2
#define	RH_LENGTH		3
#define	RH_LENGTH_MSB		3
#define	RH_LENGTH_LSB		4

#define	RH_LENGTH_MSB_V2	0
#define	RH_LENGTH_LSB_V2	1
#define	RH_MSG_TYPE_V2		2
#define	RH_VERSION_MSB_V2	3
#define	RH_VERSION_LSB_V2	4
#define	RH_LENGTH_MASK_V2	0x7FFF

#define	RH_VERSION_SIZE		2
#define	RH_LENGTH_SIZE		2

//-------------------------------------------------------------
// MAC/Cipher Algorithm definitions 
//-------------------------------------------------------------

#define SIGNAT_VECTOR_LEN		2		// size of signat.field
#define PARAM_VECTOR_LEN		2		// size of RSA/DH-Param
#define SECRET_VECTOR_LEN		2		// size pre-master fld

#define	MAX_MD5_SHA_DIGEST_LEN		32		// SHA256 is longest

#define AES_GCM_EXPL_IV_LEN     8
#define AES_GCM_IMPLICIT_IV_LEN 4
#define AES_GCM_IV_TOTAL_LEN    12

#define ECDHE_KEYEX_HDR_LEN     4       // Length of ECDHE key exchange header, including public key len field
#define ECDHE_NAME_CURVE_TYPE   3

#define	CIPHER_SUITE_ENTRY_SIZE		2
#define	CIPHER_SUITES_LEN_SIZE		2		// 2 Bytes

#define	MAX_KEY_BYTE_SIZE          160   // AES with SHA256
#define	MAX_KEY_BLOCK_LEN		MAX_KEY_BYTE_SIZE + MAX_MD5_SHA_DIGEST_LEN // To be safe, used only for key generation
#define	MAX_MD5_SHA1_STATE_SIZE		28
#define  MAX_SIG_EXT_LEN      14    // RSA with MD5,SHA1,SHA256,SHA384,SHA512 and DSA, plus length bytes

#define MAC_ALGOR_NULL          0
#define MAC_ALGOR_MD5           1
#define MAC_ALGOR_SHA1          2
#define MAC_ALGOR_SHA256        3
#define MAC_ALGOR_AES_GCM       4

#define CIPHER_ALGOR_NULL		0
#define CIPHER_ALGOR_RC4		1
#define CIPHER_ALGOR_RC2_CBC		2
#define CIPHER_ALGOR_DES_CBC		3
#define CIPHER_ALGOR_3DES_EDE_CBC	4
#define CIPHER_ALGOR_IDEA_CBC		5
#define CIPHER_ALGOR_FORTEZZA_CBC	6
#define CIPHER_ALGOR_AES_CBC		7
#define CIPHER_ALGOR_AES_GCM		8

#define ALGOR_TYPE_STREAM		0
#define ALGOR_TYPE_BLOCK		1
#define ALGOR_TYPE_AEAD         2
#define ALGOR_TYPE_UNKNOWN		-1

#define HASH_ALGOR_NONE         0
#define HASH_ALGOR_MD5          1
#define HASH_ALGOR_SHA1         2
#define HASH_ALGOR_SHA224       3
#define HASH_ALGOR_SHA256       4
#define HASH_ALGOR_SHA384       5
#define HASH_ALGOR_SHA512       6

#define SIG_ALGOR_RSA           1
#define SIG_ALGOR_DSA           2
#define SIG_ALGOR_ECDSA         3

#define	IS_EXPORTABLE			0
#define	IS_NOT_EXPORTABLE		1

#define RSA_EXPORT_MAX_BITS		1024
#define DH_EXPORT_MAX_P_BITS		512
#define DH_EXPORT_MAX_Q_BITS		500	// heuristic !!!

#define DH_MIN_P_BITS           1024
#define	DHE_DEFAULT_P_BITS		2048	// 32 Bit Number System
#define	DHE_DEFAULT_Q_BITS		256	// 32 Bit Number System

#define	KEY_EXCHANGE_NULL		0
#define	KEY_EXCHANGE_RSA		1
#define	KEY_EXCHANGE_DH_DSS		2
#define	KEY_EXCHANGE_DH_RSA		3
#define	KEY_EXCHANGE_DHE_DSS		4
#define	KEY_EXCHANGE_DHE_RSA		5
#define	KEY_EXCHANGE_DH_anon		6
#define	KEY_EXCHANGE_FORTEZZA		7
#define  KEY_EXCHANGE_SRP       8
#define KEY_EXCHANGE_ECDHE_RSA      9

//-------------------------------------------------------------

#define	SSL_NULL_NULL_NULL			0x00	// N.A.
#define	SSL_RSA_NULL_MD5			0x01
#define	SSL_RSA_NULL_SHA			0x02
#define	SSL_RSA_EXP_RC4_40_MD5			0x03
#define	SSL_RSA_RC4_128_MD5			0x04
#define	SSL_RSA_RC4_128_SHA			0x05
#define	SSL_RSA_EXP_RC2_CBC_40_MD5		0x06
#define	SSL_RSA_IDEA_CBC_SHA			0x07	// N.A.
#define	SSL_RSA_EXP_DES40_CBC_SHA		0x08
#define	SSL_RSA_DES_CBC_SHA			0x09
#define	SSL_RSA_3DES_EDE_CBC_SHA		0x0A

#define	SSL_DH_DSS_EXP_DES40_CBC_SHA		0x0B
#define	SSL_DH_DSS_DES_CBC_SHA			0x0C
#define	SSL_DH_DSS_3DES_EDE_CBC_SHA		0x0D
#define	SSL_DH_RSA_EXP_DES40_CBC_SHA		0x0E
#define	SSL_DH_RSA_DES_CBC_SHA			0x0F
#define	SSL_DH_RSA_3DES_EDE_CBC_SHA		0x10

#define	SSL_DHE_DSS_EXP_DES40_CBC_SHA		0x11
#define	SSL_DHE_DSS_DES_CBC_SHA			0x12
#define	SSL_DHE_DSS_3DES_EDE_CBC_SHA		0x13
#define	SSL_DHE_RSA_EXP_DES40_CBC_SHA		0x14
#define	SSL_DHE_RSA_DES_CBC_SHA			0x15
#define	SSL_DHE_RSA_3DES_EDE_CBC_SHA		0x16

#define	SSL_DH_anon_EXP_RC4_40_MD5		0x17	// N.A.
#define	SSL_DH_anon_RC4_128_MD5			0x18	// N.A.
#define	SSL_DH_anon_EXP_DES_40_CBC_SHA		0x19	// N.A.
#define	SSL_DH_anon_DES_CBC_SHA			0x1A	// N.A.
#define	SSL_DH_anon_3DES_EDE_CBC_SHA		0x1B	// N.A.

#define	SSL_FORTEZZA_KEA_NULL_SHA		0x1C	// N.A.
#define	SSL_FORTEZZA_KEA_FORT_CBC_SHA		0x1D	// N.A.
#define	SSL_FORTEZZA_KEA_RC4_128_SHA		0x1E	// N.A.

#define	SSL_RSA_AES_128_CBC_SHA			0x2F
#define	SSL_DH_DSS_AES_128_CBC_SHA		0x30
#define	SSL_DH_RSA_AES_128_CBC_SHA		0x31
#define	SSL_DHE_DSS_AES_128_CBC_SHA		0x32
#define	SSL_DHE_RSA_AES_128_CBC_SHA		0x33
#define	SSL_DH_anon_AES_128_CBC_SHA		0x34	// N.A.

#define	SSL_RSA_AES_256_CBC_SHA			0x35
#define	SSL_DH_DSS_AES_256_CBC_SHA		0x36
#define	SSL_DH_RSA_AES_256_CBC_SHA		0x37
#define	SSL_DHE_DSS_AES_256_CBC_SHA		0x38
#define	SSL_DHE_RSA_AES_256_CBC_SHA		0x39
#define	SSL_DH_anon_AES_256_CBC_SHA		0x3A	// N.A.

#define TLS_RSA_NULL_SHA256			0x3B
#define	TLS_RSA_AES_128_CBC_SHA256		0x3C
#define	TLS_RSA_AES_256_CBC_SHA256		0x3D
#define TLS_DH_DSS_AES_128_CBC_SHA256		0x3E
#define	TLS_DH_RSA_AES_128_CBC_SHA256		0x3F
#define	TLS_DHE_DSS_AES_128_CBC_SHA256		0x40

#define	TLS_DHE_RSA_AES_128_CBC_SHA256		0x67
#define	TLS_DH_DSS_AES_256_CBC_SHA256		0x68
#define	TLS_DH_RSA_AES_256_CBC_SHA256		0x69
#define	TLS_DHE_DSS_AES_256_CBC_SHA256		0x6A
#define	TLS_DHE_RSA_AES_256_CBC_SHA256		0x6B

#define TLS_RSA_WITH_AES_128_GCM_SHA256         0x9C
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     0x9E
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256     0xA2

#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      0xC013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      0xC014
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   0xC027
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F

#define TLS_SRP_SHA_WITH_AES_128_CBC_SHA 0x1D   // same as SSL_FORTEZZA_KEA_FORT_CBC_SHA, which however is not used!

#define TLS_FALLBACK_SCSV           0x5600

#define	MAX_DEFINED_SUITES			50	// TLS1.2

//-------------------------------------------------------------
// Compression Methods Definitions/V42bis header definitions
//-------------------------------------------------------------

#define	COMPR_NULL			0x00
#define COMPR_V42BIS			0xF4		// V42 bis (selfdef.)
#define	COMPR_RESERVED			0xFF
#define	COMPR_METHODS_ENTRY_SIZE	1
#define	COMPR_METHODS_LEN_SIZE		1		// 1 byte

#define COMPR_V42_LEN_INDEX_MSB		0		// MSB of uncompr. len
#define COMPR_V42_LEN_INDEX_LSB		1		// LSB.

#define COMPR_V42_LEN_SIZE		2		// length of field

#define COMPR_V42_N1_VAL		12		// max. codeword size
#define COMPR_V42_N2_VAL		250		// numb. of codewords

//-------------------------------------------------------------
// TLS Extension Type definitions
//-------------------------------------------------------------

#define TLS_MAX_EXTENSIONS   32

#define TLS_SNI_EXT_TYPE            0
#define TLS_EC_CURVE_EXT_TYPE       0x0a
#define TLS_EC_POINT_FORMAT_EXT_TYPE    0x0B
#define TLS_SIG_ALG_EXT_TYPE        13
#define TLS_SRP_EXT_TYPE            12
#define TLS_ALPN_EXT_TYPE           16
#define	TLS_SECURE_RENEG_EXT_TYPE   0xFF01

#define TLS_SNI_HOST_NAME_TYPE      0

//-------------------------------------------------------------
// Certificate Definitions
//-------------------------------------------------------------

#define SERVER_CERTIFIED_MASK		0x01		// Bit 0
#define CLIENT_CERTIFIED_MASK		0x02		// Bit 1
#define CLIENT_CERT_REQ_MASK		0x04		// Bit 2
#define SERVER_KEY_EXCHG_REQ_MASK	0x08		// Bit 3
#define CLIENT_CERT_VERIFY_MASK		0x10		// Bit 4

#define	CERT_TYPE_NONE			0
#define	CERT_TYPE_RSA_SIGN		1
#define	CERT_TYPE_DSS_SIGN		2
#define	CERT_TYPE_RSA_FIXED_DH		3
#define	CERT_TYPE_DSS_FIXED_DH		4
#define	CERT_TYPE_RSA_EPHEMERAL_DH	5
#define	CERT_TYPE_DSS_EPHEMERAL_DH	6
#define	CERT_TYPE_ECDSA_SIGN		64
#define	CERT_TYPE_RSA_FIXED_ECDH		65
#define	CERT_TYPE_ECDSA_FIXED_ECDH		66
#define	CERT_TYPE_NONSTD_RANGE_START	64		// TLS 1.1, Server2008!
#define	CERT_TYPE_UNKNOWN		(BYTE) 0xFF

#define	CERT_TYPES_MIN_LEN		1		// 1 byte required
#define	CERT_TYPES_LEN_SIZE		1		// 1 byte
#define	CERT_LENGTH_SIZE		3		// 3 byte
#define	CERT_LIST_LENGTH_SIZE		3		// 3 byte

#define	CERT_RDN_MIN_LEN		3		// 3 bytes required
#define	CERT_RDN_LEN_SIZE		3		// 3 bytes

#define	IBM_CONT_FLAG_HOB_SW_USED	0x01		// Cert generated HOB
#define	IBM_CONT_FLAG_EXT_PRIV_KEY	0x02		// Key from external

//-------------------------------------------------------------
// SSL Record Layer Content Type Definitions
//-------------------------------------------------------------

#define	CT_CHANGE_CIPHER_SPEC		0x14
#define	CT_ALERT			0x15
#define	CT_HANDSHAKE			0x16
#define	CT_APPLICATION_DATA		0x17
#define	CT_RESERVED			0xFF

//-------------------------------------------------------------
// SSL Alert Message Definitions
//-------------------------------------------------------------

#define	ALERT_LEVEL_WARNING		1
#define	ALERT_LEVEL_FATAL		2
#define	ALERT_LEVEL_RESERVED		255

// Alert Descriptions

#define	AD_CLOSE_NOTIFY			0x00
#define	AD_UNEXPECTED_MSG		0x0A
#define	AD_BAD_RECORD_MAC		0x14
#define	AD_DECRYPT_FAILURE		0x15		// TLS1.0
#define	AD_RECORD_OVERFLOW		0x16		// TLS1.0
#define	AD_DECOMPRESS_FAILURE		0x1E
#define	AD_HSHAKE_FAILURE		0x28
#define	AD_NO_CERTIFICATE		0x29
#define	AD_BAD_CERTIFICATE		0x2A
#define	AD_UNSUP_CERTIFICATE		0x2B
#define	AD_CERTIFICATE_REVOKED		0x2C
#define	AD_CERTIFICATE_EXPIRED		0x2D
#define	AD_CERTIFICATE_UNKNOWN		0x2E
#define	AD_ILLEGAL_PARAMETER		0x2F
#define	AD_UNKNOWN_CA			0x30		// TLS1.0
#define	AD_ACCESS_DENIED		0x31		// TLS1.0
#define	AD_DECODE_ERROR			0x32		// TLS1.0
#define	AD_DECRYPT_ERROR		0x33		// TLS1.0
#define	AD_EXP_RESTRICTION		0x3C		// TLS1.0
#define	AD_PROTOCOL_VERSION		0x46		// TLS1.0
#define	AD_INSUFF_SECURITY		0x47		// TLS1.0
#define	AD_INTERNAL_ERROR		0x50		// TLS1.0
#define AD_INAPPROPRIATE_FALLBACK   0x56
#define	AD_USER_CANCELED		0x5A		// TLS1.0
#define	AD_NO_RENEGOTIATION		0x64		// TLS1.0
#define  AD_UNSUP_EXTENSION   0x6E

#define AD_UNREC_NAME           0x70
#define  AD_UNKN_PSK_ID 0x73  
#define AD_NO_APPL_PROTOCOL     0x78

#define	AD_RESERVED			0xFF

//-------------------------------------------------------------
// SSL Change Cipher Spec Definitions
//-------------------------------------------------------------

#define	CS_CHANGE_CIPHER_SPEC		0x01
#define	CS_RESERVED			0xFF

//-------------------------------------------------------------
// SSL Handshake Type Definitions
//-------------------------------------------------------------

#define	HT_CLIENT_HELLO_V2		0x01

#define	HT_HELLO_REQUEST		0x00
#define	HT_CLIENT_HELLO			0x01
#define	HT_SERVER_HELLO			0x02
#define	HT_CERTIFICATE			0x0B
#define	HT_SERVER_KEY_EXCHANGE		0x0C
#define	HT_CERTIFICATE_REQUEST		0x0D
#define	HT_SERVER_HELLO_DONE		0x0E
#define	HT_CERTIFICATE_VERIFY		0x0F
#define	HT_CLIENT_KEY_EXCHANGE		0x10
#define	HT_FINISHED			0x14
#define	HT_RESERVED			0xFF

#define	HT_CERTIFICATE_VERIFY_LCL	0x12		// for state process.
#define	HT_CLIENT_HELLO_V2_LCL		0x11		// dto.

#define	HT_MESSAGE_SIZE			1		// 1 byte
#define	HT_LENGTH_SIZE			3		// 3 bytes

//-------------------------------------------------------------
// Definition of special config flags (from INIT requests)
//-------------------------------------------------------------

#define	SPC_CFG_SRVR_FETCH_CERTS_FLAG	0x02		// Bit 1
#define	SPC_CFG_CLNT_COMPRESS_OFF_FLAG	0x04		// Bit 2
#define	SPC_CFG_MUST_SYNC_FLAG		0x08		// Bit 3, JAVA only

//-------------------------------------------------------------
// Definition of Extended Configuration Bitmasks
//-------------------------------------------------------------
// NOTE: Now protocol and authentication are separated to 2
// ----- variables in connection structure !!

#define	TLS_V1_BIT_MASK			0x04	// Bit 2 !!!
#define	TLS_V2_BIT_MASK			0x08	// Bit 3 !!!
#define	CFG_PROTOCOLS_MASK		0x03	// Bit 0,1 from configuration

#define SSL_BIT_MASK			0x01 //  0: 1- enable SSL
#define TLS_BIT_MASK			0x02 //  1: 1- enable TLS
#define CLNT_AUTH_BIT_MASK		0x04 //  2: 1- enable clnt. auth.
#define SRVR_AUTH_BIT_MASK		0x08 //  3: 1- enable srvr. auth. list
#define INCL_CLNT_SUBJ_LIST_BIT_MASK	0x10 //  4: 1- Included Clnt Subj. list
#define	EXCL_CLNT_SUBJ_LIST_BIT_MASK	0x20 //  5: 1- excluded Clnt Subj. list
#define	SRVR_REQ_CERT_IF_AVAIL_BIT_MASK	0x40 //  6: 1- request cert but
#define	TRY_OUT_VERS_BIT_MASK		0x80 //	 7: 1- is a config file created
					     //	       from try-out version

#define	SESS_CACHE_BIT_MASK		0x01 //  8: 1- enable sess. cache
#define CFG_USE_CPU_AES_MASK     0x04 // 10: 1- Use CPU AES if available
#define	CFG_TLS_V2_BIT_MASK		0x08 // 11: 1- Enable TLS V1.2
#define	CFG_TLS_V1_BIT_MASK		0x10 // 12: 1- Enable TLS V1.1
#define REMOTE_RENEGOTIATE_BIT_MASK	0x20 // 13: 1- Remote reneg. enable
#define LOCAL_RENEGOTIATE_BIT_MASK	0x40 // 14: 1- Local reneg. enable
#define RENEG_REJ_SHUTDOWN_BIT_MASK	0x80 // 15: 1- Shutdown on Reject

#define DEFAULT_EXT_CONF	0x25

//-----------------------------------------------------------------
// Definition of Additional Extended Configuration (Conf2) Bitmasks 
//-----------------------------------------------------------------

// Server Control Flags

#define	SRVR_NO_HELLO_REQ_BIT_MASK	0x01 //  0: 1 - don't send HELLO REQ.
#define	SRVR_SSLV2_ACCEPT_BIT_MASK	0x02 //  1: 1 - accept V2 comp. Header
#define	SRVR_RDN_LIST_WITH_SEQ_MASK	0x04 //  2: 1 - embed RDNs in Sequence

// Certificate processing Flags

#define	CERT_PROCESS_FLAGS_SHIFT	3
#define	DONT_SORT_RDNS_BIT_MASK		0x08 //  3: 1 - don't sort RDNs
#define	PROCESS_CERT_EXTS_BIT_MASK	0x10 //	 4: 1 - process Cert. Extens.
#define	VALIDITY_CHK_OVERLAP_BIT_MASK	0x20 //  5: 1 - Time val. overlap only
#define	ENABLE_USE_OCSP_BIT_MASK	0x40 //  6: 1 - enable OCSP checking
#define	NO_OCSP_NONCE_BIT_MASK		0x80 //  7: 1 - do not use OCSP nonces
// Certificate location control flags (Smartcard etc.)

#define	CFG2_CERTS_EXT_STORE_BIT_MASK 0x0100 //  8: 1 - Certificates external
#define	CFG2_ADD_CERT_IN_CDB_BIT_MASK 0x0200 //  9: 1 - add. certs in CDB
#define	CFG2_CFG_DATA_INF_OK_BIT_MASK 0x0400 // 10: 1 - interf. info in Ext.
#define	CFG2_EXT_CERT_STORE_ID_MASK   0x3800 // 11-13: predefined StorageID
#define	CFG2_EXT_ALWAYS_DLG_BIT_MASK  0x4000 // 14: 1 - always show ext. dialog
#define	IGNORE_OCSP_PRODUCED_BIT_MASK 0x8000 // 15: 1 - do not check prod. AT

#define	CFG2_ALL_EXT_STORE_BITS_MASK	0x3F00 // High Byte of Conf2 ???

//-------------------------------------------------------------------
// Definition for extended config array bytes/bits
//-------------------------------------------------------------------

#define	CFGA0_USE_PKCS11_BIT_MASK	0x01 // Byte 0, Bit 0:1 - use PKCS11

//------------------------------------------------------------------
// Parameters for Session Status Structure (within Helper Process !)
//------------------------------------------------------------------

#define	SESSION_NOT_RESUMABLE		0
#define	SESSION_RESUMABLE		1

#define	SESSION_NOT_YET_NEGOTIATED	0
#define	SESSION_NEGOTIATED		1

#define	HSSL_RENEGOTIATE_COMPLETE_MAX_WAIT 300	// seconds

#define UNKNOWN_PROT_TYPE		0
#define SSL_PROT_TYPE			0x01
#define TLS_PROT_TYPE			0x02	// TLS 1.0
#define TLS_V1_PROT_TYPE		0x03	// TLS 1.1
#define TLS_V2_PROT_TYPE		0x04	// TLS 1.2

#define RSA_PRE_MASTER_SECRET_LEN	48
#define	DH_MAX_PRE_MASTER_SECRET_LEN	256

//-------------------------------------------------------------
// Parameters for SSL Connection Structure
//-------------------------------------------------------------

#define	PENDING_STATES_NOT_INIT	 0
#define	PENDING_STATES_INIT	 1
#define MAX_CONNECTIONS		1024		// for fixed access field

#define	SSL_NORMAL_HANDSHAKE_MODE	0	// full handshake in progress
#define	SSL_SHORT_HANDSHAKE_MODE	1	// short handshake in progress

#define	SSL_RENEGOTIATE_NOT_ACTIVE	0	// no renegotiation in process
#define	SSL_RENEGOTIATE_ACTIVE		1	// renegotiation in process

//------------------------------------------------------------
// Certificate Policies parameters
//------------------------------------------------------------

#define	CERT_POLICY_REJECT		0
#define CERT_POLICY_ASK			1
#define	CERT_POLICY_ACCEPT		2

#define CERT_POLICY_MASK		0x03

#define	CERT_REVOKED_POLICY_MASK	0x0003	// Bits 1,0
#define	CERT_NOT_YET_VALID_POLICY_MASK	0x000C	// Bits 3,2
#define	CERT_EXPIRED_POLICY_MASK	0x0030	// Bits 5,4
#define CERT_CHAIN_EXPIRED_POLICY_MASK	0x00C0	// Bits 7,6
#define CERT_ROOT_EXPIRED_POLICY_MASK	0x0300	// Bits 9,8
#define	CERT_NO_TRUST_ROOT_POLICY_MASK	0x0C00	// Bits 11,10
#define	CERT_UNKNOWN_OCSTAT_POLICY_MASK	0x3000	// Bits 13,12
#define	CERT_WTS_CERTIFICATE_POLICY_MASK	0xC000	// Bits 15,14

#define	CERT_REVOKED_POLICY_SHIFT	0
#define	CERT_NOT_YET_VALID_POLICY_SHIFT	2
#define	CERT_EXPIRED_POLICY_SHIFT	4
#define CERT_CHAIN_EXPIRED_POLICY_SHIFT	6
#define CERT_ROOT_EXPIRED_POLICY_SHIFT	8
#define	CERT_NO_TRUST_ROOT_POLICY_SHIFT 10
#define	CERT_UNKNOWN_OCSTA_POLICY_SHIFT	12
#define	CERT_WTS_CERTIFICATE_POLICY_SHIFT   14

//-------------------------------------------------------------
// Index Definitions for Connection-/Configuration data queries
//-------------------------------------------------------------
// 1. Connection data query structure

#define Q_APP_TX_DATA_MSW_IND	0	// data transferred FROM Application 
#define Q_APP_TX_DATA_LSW_IND	4	// dto.
#define Q_APP_RX_DATA_MSW_IND	8	// data transferred TO   Application
#define Q_APP_RX_DATA_LSW_IND	12	// dto.
#define Q_CMPR_TX_DATA_MSW_IND	16	// data after compression executed
#define Q_CMPR_TX_DATA_LSW_IND	20	// dto.
#define Q_CMPR_RX_DATA_MSW_IND	24	// data before decompression executed
#define Q_CMPR_RX_DATA_LSW_IND	28	// dto.
#define Q_PURE_TX_DATA_MSW_IND	32	// data sent on TCP (excl. Handshakes)
#define Q_PURE_TX_DATA_LSW_IND	36	// dto.
#define Q_PURE_RX_DATA_MSW_IND	40	// data recv. on TCP (excl. Handshakes)
#define Q_PURE_RX_DATA_LSW_IND	44	// dto.

#define Q_ACT_PROTOCOL_IND	48	// actual selected protocol
#define Q_ACT_COMPR_METH_IND	49	// actual selected compression method
#define Q_ACT_CIPH_SUITE_IND	50	// actual selected cipher suite
#define Q_KEY_EXCHANGE_MODE_IND 52	// decoded from act. cipher suite
#define Q_CIPHER_ALGOR_IND	53	// dto.
#define Q_CIPHER_TYPE_IND	54	// dto.
#define Q_MAC_ALGOR_TYPE_IND	55	// dto.
#define Q_IS_EXPORTABLE_IND	56	// dto.
#define Q_CERTIFIED_FLAGS_IND	57	// certification state flags
#define Q_RESUME_STAT_FLAGS_IND 58	// resume state flags
// from 59-63 and 64-95 reserved
#define Q_SERVER_PORT_IND	96	// number of server port
#define Q_SERVER_IP_ADR_IND	98	// buffer with leading length byte
#define Q_CLIENT_IP_ADR_IND	115	// dto.
#define Q_SESSION_ID_IND	132	// dto.
// from 165-167 and 168-191 reserved
#define Q_PARTNER_COM_NAME_IND	192	// partners common name from cert.

#define Q_CONNDAT_FIXED_PARAMS_SIZE	Q_PARTNER_COM_NAME_IND

// 2. Configuration data query structure

#define Q_VERSION_IND		0	// Version of this interface (1.0)
#define Q_SUPPORTED_PROTOS_IND	2	// protocols supported
#define Q_EXTENDED_CONF_IND	3	// extended configuration flags
#define Q_CERT_POLICIES_FLG_IND	4	// certificate handling policy flags
#define	Q_MAX_CONNECTIONS_IND	6	// supported connection count
#define Q_CONNECT_TIMEOUT_IND	8	// connect timeout in seconds
#define	Q_EXTENDED_CONF2_IND	10	// additional extended flags (16 Bit)
// from 12-63 reserved, variable data follows
#define Q_CMPR_METH_LIST_IND	64	// Compression methods list

#define Q_CONFDAT_FIXED_PARAMS_SIZE	Q_CMPR_METH_LIST_IND

#endif // !__HOB_SSL_DEFINES__

#if !(defined __HOB_SSL_EXTCERT_INTERN__) && (defined _WIN32)
#define __HOB_SSL_EXTCERT_INTERN__

/**
* This structure is used for communication with the external libraries.
*/
typedef struct HEXTCST_t {
	int	IntfLoadedFlag;		//!< Interface loaded flag
	int	MaxCCAllocLen;		//!< Maximum allocation size
	HMODULE	hExtCertLib;		//!< Handle of the external library
	int (**pFunctPtrArr)();		//!< External function address array
} HEXTCST;

typedef int (* LPInitCryptoApiDll)(int nOpMode, char pbyWrDirBuf[],
		int nWrDirBufOff, int nWrDirBufLen, char pbyAddInBuf[],
		int nAddInBufOff, int nAddInBufLen, int pnCrApiType[]);

typedef int (* LPGetCChainForSrvrVerify)(char pbyInputDataBuf[],
		int nIDOffset, int nIDLength, int nOpMode,
		char* ppbyDestBuf[], int pnNmbOfCerts[], int pnMaxDataLen[]);

typedef int (* LPGetClntCChainForAuthent)(char pbyRdnInput[],
		int nRdnDOffset, int nRdnDLength, char pbySigAlgInput[],
		int nSAlgDOffset, int nSAlgDLength,
		char pbySubjectSelIn[], int nSubSelOffset,
		int nSubSelLength, int nOpMode,
		int pnPrevCertID[], int pnPrevStoreID[],
		char* ppbyDestBuf[], int pnNmbOfCerts[],
		int pnMaxDataLen[]);

typedef int (* LPSignDataWithCPrivKey)(char pbyCertDInput[],
		int nCertDOffset, int nCertDLength,
		char pbyDataInput[], int nDataOffset, int nDataLength,
		int nOpMode, char* ppbyDestBuf[], int pnMaxDataLen[]);

typedef int (* LPForgetCertIniEntry)(int nOpMode);

#if defined __VPN_INTERFACE__
typedef int (* LPVpnStartup)(void);
typedef int (* LPVpnCleanup)(void);
typedef int (* LPVpnConnState)(int WaitTimeMillis);
#endif // __VPN_INTERFACE__

#if !defined __VPN_INTERFACE__

#define	HSSL_EX_MODULE_DLLNAME		L"HOBsecCTE.dll"

#define	INIT_CRAPI_PROC_NAME		"InitCryptoApiDll"
#define	GET_SRVR_VERIFY_CCHAIN_NAME	"GetCChainForSrvrVerify"
#define	GET_CLNT_AUTHENT_CCHAIN_NAME	"GetClntCChainForAuthent"
#define	SIGN_DATA_CLNT_PRIVKEY_NAME	"SignDataWithCPrivKey"
#define	CRAPI_FORGET_INI_NAME		"ForgetCertIniEntry"

#else						// for VPN

#define	HSSL_EX_MODULE_DLLNAME		L"hvpnmstr.dll"

#define	INIT_CRAPI_PROC_NAME		"VPNInitCryptoApiDll"
#define	GET_SRVR_VERIFY_CCHAIN_NAME	"VPNGetCChainForSrvrVerify"
#define	GET_CLNT_AUTHENT_CCHAIN_NAME	"VPNGetClntCChainForAuthent"
#define	SIGN_DATA_CLNT_PRIVKEY_NAME	"VPNSignDataWithCPrivKey"
#define	CRAPI_FORGET_INI_NAME		"VPNForgetCertIniEntry"
#define	EXT_DLL_STARTUP_NAME		"VPNMasterStartup"
#define	EXT_DLL_CLEANUP_NAME		"VPNMasterCleanup"
#define	EXT_DLL_CONNCHK_NAME		"VPNMasterGetConnState"
#endif // !defined __VPN_INTERFACE__

//-------------------------------------------------------------
// Indices into Function Pointer Array for call (C only)
//-------------------------------------------------------------

#define	INIT_CRYPTO_API_DLL_IND		0
#define	GET_CCHAIN_FOR_SRVR_VERIFY_IND	1
#define	GET_CLIENT_CCHAIN_FOR_AUTH_IND	2
#define	SIGN_DATA_WITH_CPRIVKEY_IND	3
#define	FORGET_CERT_INI_ENTRY_IND	4
#if !defined __VPN_INTERFACE__
#define	EXT_CERT_MAX_FUNCT_CNT		5
#else
#define	STARTUP_ENTRY_IND		5
#define	CLEANUP_ENTRY_IND		6
#define	CONN_CHECK_ENTRY_IND		7
#define	EXT_CERT_MAX_FUNCT_CNT		8
#endif // __VPN_INTERFACE__

#endif // !__HOB_SSL_EXTCERT_INTERN__

#if !defined(DEFMCAPI_H_HOB250902__INCLUDED)
#define DEFMCAPI_H_HOB250902__INCLUDED
//-------------------------------------------------------------------------
// from DefMCapi.h
//-------------------------------------------------------------------------
/** @addtogroup hssl
* @{
* @file
* This header contains definitionsfor several interface calls.
* @}
*/
/************************************************************************/
/* Definitions for HOBmscrAp                                            */
/************************************************************************/

/*----------------------------------------------------------------------*/
/* Definitions for GetCertChainForServerVerify modes                    */
/*----------------------------------------------------------------------*/

// Mode 1: Find a certificate with the same subject as issuer in certificate
#define	GETCERTCHAIN_FULLCERT      0x01

// Mode 2: Find a certificate with the same subject
#define	GETCERTCHAIN_FINDSUBJ      0x02

// Mode 3: Find a certificate with the same issuer and serial number
#define	GETCERTCHAIN_FINDISSN      0x03

// Mode 4: Find a certificate with the same algorithm and the same public key
#define	GETCERTCHAIN_FINDPUBK      0x04

/*----------------------------------------------------------------------*/
/* Definitions for GetClientCertChainForAuthent modes                   */
/*----------------------------------------------------------------------*/

// Mode switch Bit 0:  external collect / internal collect
#define GETCLNCCAUTH_MODECOLL      0x0001  // bit 0

// Mode switch Bit 1:  1 = show selection dialog always, if bit 0 is set
#define GETCLNCCAUTH_SHOWSDLG      0x0002  // bit 1

// Mode switch Bit 4:  1 = ignore preselected certificate from ini-file
#define GETCLNCCAUTH_IGNORPSC      0x0010  // bit 4

// Mode switch Bit 5:  1 = clear certificate entry in ini-file
#define GETCLNCCAUTH_CLRCINIF      0x0020  // bit 5

// Mode switch Bit 6:  1 = only the preselected certificate is checked
#define GETCLNCCAUTH_TESTSELC      0x0040  // bit 6  (not used)

// Mode switch Bit 8:  1 = ignore chain is partial chain error
#define GETCLNCCAUTH_ACPTPTCH      0x0100  // bit 8

// Certificate Preselection switch Bit 0:
//             1 = certificate selection by user intervention
#define CERTSELTAKEN_USERCTRL      0x0001  // bit 0

// Certificate Preselection switch Bit 4:
//             1 = certificate selection was loaded from existing ini file
#define CERTSELTAKEN_INILOADD      0x0010  // bit 4

/*----------------------------------------------------------------------*/
/* Definitions for SignDataWithCertPrivKey modes                        */
/*----------------------------------------------------------------------*/

// Mode Flags Bits 0 - 3: Type of Hash
#define SIGDAPVKEY_HASHTYMASK      0x000F
#define SIGDAPVKEY_HASHTY_MD2      0x0001  // MD2 not used
#define SIGDAPVKEY_HASHTY_MD5      0x0002  // MD5
#define SIGDAPVKEY_HASHTY_SHA      0x0003  // SHA1
#define SIGDAPVKEY_HASHTY_SSL      0x0004  // SSL3_SHAMD5

// Mode Flags Bit 8: ASN1 encoded output
#define SIGDAPVKEY_ASN1_ENCOP      0x0100  // ignored with SSL3_SHAMD5

/*----------------------------------------------------------------------*/
/* Definitions for GetClientCertChainForAuthent                         */
/*             and SignDataWithCertPrivKey modes                        */
/*----------------------------------------------------------------------*/

#define DEFSMS_SEARCHCRITMASK      0xF000
#define DEFSMS_SEARCRITKEYENC      0x1000  // Key encipherment
#define DEFSMS_SEARCRITDIGSIG      0x2000  // Digital signature
#define DEFSMS_SEARCRITKYEDSG      0x4000  // Key encipherment & digital signature
#define DEFSMS_SEARCRITDSGKYE      0x8000  // Digital signature & key encipherment

/************************************************************************/
/* Definitions for HOBsecJNI                                            */
/************************************************************************/

/*----------------------------------------------------------------------*/
/* Definitions for InitCryptoApiDll                                     */
/*----------------------------------------------------------------------*/

// Undefined Crypto API, should result in an error condition
#define	ICAD_NOCRYPAPI        0x00

// Microsoft Crypto API
#define	ICAD_MISOCRAPI        0x01

// HOB internal Crypto Interface (*.cdb file), not available
#define	ICAD_HOBCRYAPI        0x02

// TIKS Classic Crypto API from T-Nova
#define	ICAD_TNOVACAPI        0x03

/************************************************************************/
/* Error Definitions                                                    */
/*                                                                      */
/* Error Range from                                                     */
/*       6200 ... 6219 for InitCryptoApiDll (max. 20)                   */
/*       6220 ... 6289 for GetCertChainForServerVerify (max. 70)        */
/*       6290 ... 6359 for GetClientCertChainForAuthent (max. 70)       */
/*       6360 ... 6429 for SignDataWithCertPrivKey (max. 70)            */
/*       6430 ...      for GetPubKeyFromBinX509                         */
/*                                                                      */
/************************************************************************/
// Free error numbers: 16, 38, 39, 49, 50, 56...59

/*----------------------------------------------------------------------*/
/* Error Definitions for HOBsecJNI                                      */
/*----------------------------------------------------------------------*/

#define	HOB_SECJNI_ERRORBASE          6100

// Error Definitions for InitCryptoApiDll
// --------------------------------------

#define	ICADLL_ERROROFFSET            100

#define	ICADLL_NOINPUTDATA_ERR        1  // input parameter not set
#define	ICADLL_NONAMEBUFF_ERR         2  // no valid buffer containing the DLL name accessible
#define	ICADLL_BUFF2SMALL_ERR         3  // buffer too small to copy DLL name
#define	ICADLL_LOADLIBFAIL_ERR        4  // the function LoadLibrary failed

// the function GetProcAddress failed
#define	ICADLL_GPA_GCCFSV_ERR         10
#define	ICADLL_GPA_GCCCFA_ERR         11
#define	ICADLL_GPA_SDWCPK_ERR         12
#define	ICADLL_GPA_GCATYP_ERR         13
#define	ICADLL_GPA_GPKFBX_ERR         14

/*----------------------------------------------------------------------*/
/* Error Definitions for HOBmscrAp                                      */
/*----------------------------------------------------------------------*/

#define	HOB_MSCAPI_ERRORBASE          6100

// input parameter not set

#define	HOB_MSCAPI_NOINPUTDATA_ERR    1
#define	HOB_MSCAPI_NORETURNPTR_ERR    2

// exception has been thrown in a DLLExport function
#define	HOB_MSCAPI_EXCEPTHROWN_ERR    9

// open predefined Store, CertOpenStore failed
#define	HOB_MSCAPI_OPDS_COS_ERR       18

// erroneous input parameters for CheckClientCertGcccfaOk
#define	HOB_MSCAPI_CCCGO_EI_ERR       30
#define	HOB_MSCAPI_CCCGO_WP_ERR       31

#define	HOB_MSCAPI_CCCGO_KU_ERR       35  // key usage not set for the current certificate
#define	HOB_MSCAPI_PK_ALGOI_ERR       36  // public key algorithm OID of certificate not available

// erroneous input parameters for GetCertChainFromContext
#define	HOB_MSCAPI_GCCFC_EI_ERR       40

// create a certificate chain engine, CertCreateCertificateChainEngine failed
#define	HOB_MSCAPI_CC_CCCCE_ERR       41

// search for a certificate chain, CertGetCertificateChain failed
#define	HOB_MSCAPI_SCC_CGCC_ERR       42

// certificate chain returned, (pChainContext->TrustStatus.dwErrorStatus) is set  (warning !)
#define	HOB_MSCAPI_CCR_TSES_ERR       43

// certificate chain returned, internal integrity of structure is violated
#define	HOB_MSCAPI_CCR_IISV_ERR       44

// certificate chain, no simple chains in the array
#define	HOB_MSCAPI_CC_NSCIA_ERR       45

// certificate chain has wrong encoding type  (warning !)
#define	HOB_MSCAPI_CC_WENCT_ERR       46

// certificate chain ready, destination buffer too small
#define	HOB_MSCAPI_CCR_DBTS_ERR       47

// certificate chain ready, destination buffer not found
#define	HOB_MSCAPI_CCR_DBNF_ERR	      48

// errors in GetCertChainFromCCFInfo
// Input parameters not specified
#define	HOB_MSCAPI_GCI_NOIN_ERR	      51

// CertOpenStore with CERT_STORE_PROV_MEMORY failed
#define	HOB_MSCAPI_GCI_COMS_ERR	      52

// CertAddEncodedCertificateToStore failed
#define	HOB_MSCAPI_GCI_AECS_ERR	      53

// CertOpenStore with (CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER) failed
#define	HOB_MSCAPI_GCI_COES_ERR	      54

// CertFindCertificateInStore failed
#define	HOB_MSCAPI_GCI_CFCS_ERR	      55

// Error Definitions for GetCertChainForServerVerify
// -------------------------------------------------

#define	GCCFSV_ERROROFFSET            120

// mode GETCERTCHAIN_FULLCERT, CertOpenStore failed
#define	GCCFSV_GCCFC_COS_ERR          10

// mode GETCERTCHAIN_FULLCERT, CertAddEncodedCertificateToStore failed
#define	GCCFSV_GCCFC_CAECTS_ERR       11

// mode GETCERTCHAIN_FINDISSN, not supported
#define	GCCFSV_GCCFISN_NSUP_ERR       15

// unknown GetCertChainForServerVerify mode
#define	GCCFSV_UNKNO_MODE_ERR         17

// internal GetCertChainForServerVerify error
#define	GCCFSV_INTERNAL_ERR           20

// search predefined Store, CertFindCertificateInStore failed
#define	GCCFSV_SPS_CFCIS_ERR          21

// certificate not found in the searched CertStores
#define	GCCFSV_CERT_NOTF_ERR          22

// no certificate data found to be copied
#define	GCCFSV_NOCERTDFND_ERR         23

// Error Definitions for GetClientCertChainForAuthent
// --------------------------------------------------

#define	GCCCFA_ERROROFFSET            190

// input parameter (previous store, certificate) not available
#define	GCCCFA_NOPREVPTR_ERR          3

// value of previous store exceeds maximum number of stores
#define	GCCCFA_PREVSTBIG_ERR          4

// input data for the list of RDN compare data not set up correctly
#define	GCCCFA_RDNDLINUL_ERR          5

// input data for the list of Sig.Algs. compare data not set up correctly
#define	GCCCFA_SALGLINUL_ERR          6

// input data for the additional cert. selection info not set up correctly
#define	GCCCFA_ACSELINUL_ERR          7

// CertOpenStore failed, SystemStore, no cryptographic provider,
#define	GCCCFA_CEOST_SYS_ERR          10

// Certificate collection store size is too small
#define	GCCCFA_CCOLSSITS_ERR          24

// No reasonable certificates found on collection
#define	GCCCFA_NOCOLLCFD_ERR          25

// No memory allocation for the name of the additional DLL
#define	GCCCFA_NODLLMEMA_ERR          26

// Trying to load the library HOBmscaCS.dll
#define	GCCCFA_LDLIBCSDL_ERR          27

// Any necessary part to locate the library HOBmscaCS.dll could not be found
#define	GCCCFA_NODLLPNAM_ERR          28

// GetProcAddress could not find the function DisplayCertificates in HOBmscaCS.dll
#define	GCCCFA_GPA_DPCER_ERR          29

// The dialog DisplayCertificates was canceled by the user
#define	GCCCFA_DC_CCBYUS_ERR          32

// The function DisplayCertificates returned an illegal index
#define	GCCCFA_DC_ILLIDX_ERR          33

// The function CryptAcquireCertificatePrivateKey returned user cancellation
#define	GCCCFA_CACPKUCNC_ERR          34

// Error Definitions for SignDataWithCertPrivKey
// ---------------------------------------------

#define	SDWCPK_ERROROFFSET            260

// input parameter (select certificate with private key) not available
#define	SDWCPK_NOCERTDATA_ERR         8

// no suitable signature algorithm found
#define	SDWCPK_NOSIGALGFND_ERR        37

// no suitable certificate found, which shall be used
#define	SDWCPK_NOCERTFOUND_ERR        60

// error returned from hash function CryptCreateHash
#define	SDWCPK_CRCREATHASH_ERR        62

// error returned from hash function CryptGetHashParam
#define	SDWCPK_CRGETHASHPA_ERR        63

// inconsistent length values
#define	SDWCPK_HASHLENWRNG_ERR        64
#define	SDWCPK_INPTLENWRNG_ERR        65

// error returned from hash function CryptSetHashParam
#define	SDWCPK_CRSETHASHPA_ERR        66

// error returned from hash function CryptSignHash returning length
#define	SDWCPK_CRSIGNHASHL_ERR        67

// error returned from hash function CryptSignHash returning data
#define	SDWCPK_CRSIGNHASHD_ERR        68

// no data returned, no input buffer or buffer length too small
#define	SDWCPK_BUFBUFLEN_ERR          69

// Error Definitions for GetPubKeyFromBinX509
// ------------------------------------------

#define	GPKFBX_ERROROFFSET            330

// error returned from crypto function CryptDecodeObject
#define	GPKFBX_CRYDECOBJ_ERR          19

// no data returned, no input buffer or buffer length too small
#define	GPKFBX_BUFBUFLEN_ERR          57

// Error Definitions for GetLastError
// ----------------------------------

#define	HOB_MSCAPI_FILNFD_ERR       1   // ERROR_FILE_NOT_FOUND
#define	HOB_MSCAPI_INVHDL_ERR       2   // ERROR_INVALID_HANDLE
#define	HOB_MSCAPI_INVPAR_ERR       3   // ERROR_INVALID_PARAMETER
#define	HOB_MSCAPI_MODNFD_ERR       4   // ERROR_MOD_NOT_FOUND
#define	HOB_MSCAPI_MORDAT_ERR       5   // ERROR_MORE_DATA

#define	HOB_MSCAPI_OOFMEM_ERR       6   // E_OUTOFMEMORY
#define	HOB_MSCAPI_INVARG_ERR       7   // E_INVALIDARG

#define	HOB_MSCAPI_BADUID_ERR       8   // NTE_BAD_UID
#define	HOB_MSCAPI_BADHSH_ERR       9   // NTE_BAD_HASH
#define	HOB_MSCAPI_BADKEY_ERR      10   // NTE_BAD_KEY
#define	HOB_MSCAPI_BADLEN_ERR      11   // NTE_BAD_LEN
#define	HOB_MSCAPI_BADDAT_ERR      12   // NTE_BAD_DATA
#define	HOB_MSCAPI_BADSIG_ERR      13   // NTE_BAD_SIGNATURE
#define	HOB_MSCAPI_BADVER_ERR      14   // NTE_BAD_VER
#define	HOB_MSCAPI_BADALG_ERR      15   // NTE_BAD_ALGID
#define	HOB_MSCAPI_BADFLG_ERR      16   // NTE_BAD_FLAGS
#define	HOB_MSCAPI_BADTYP_ERR      17   // NTE_BAD_TYPE
#define	HOB_MSCAPI_BADKST_ERR      18   // NTE_BAD_KEY_STATE
#define	HOB_MSCAPI_BADHST_ERR      19   // NTE_BAD_HASH_STATE
#define	HOB_MSCAPI_NO_KEY_ERR      20   // NTE_NO_KEY
#define	HOB_MSCAPI_NO_MEM_ERR      21   // NTE_NO_MEMORY
#define	HOB_MSCAPI_EXISTS_ERR      22   // NTE_EXISTS
#define	HOB_MSCAPI_PERM_ERR        23   // NTE_PERM
#define	HOB_MSCAPI_NOTFND_ERR      24   // NTE_NOT_FOUND
#define	HOB_MSCAPI_BADPRV_ERR      25   // NTE_BAD_PROVIDER
#define	HOB_MSCAPI_BADPTY_ERR      26   // NTE_BAD_PROV_TYPE
#define	HOB_MSCAPI_BADPUK_ERR      27   // NTE_BAD_PUBLIC_KEY
#define	HOB_MSCAPI_BADKYS_ERR      28   // NTE_BAD_KEYSET
#define	HOB_MSCAPI_PRVTND_ERR      29   // NTE_PROV_TYPE_NOT_DEF
#define	HOB_MSCAPI_PRVTEB_ERR      30   // NTE_PROV_TYPE_ENTRY_BAD
#define	HOB_MSCAPI_KEYSND_ERR      31   // NTE_KEYSET_NOT_DEF
#define	HOB_MSCAPI_KEYSEB_ERR      32   // NTE_KEYSET_ENTRY_BAD
#define	HOB_MSCAPI_PRVTNM_ERR      33   // NTE_PROV_TYPE_NO_MATCH
#define	HOB_MSCAPI_PRVDFL_ERR      34   // NTE_PROVIDER_DLL_FAIL
#define	HOB_MSCAPI_PRVDNF_ERR      35   // NTE_PROV_DLL_NOT_FOUND
#define	HOB_MSCAPI_BADKSP_ERR      36   // NTE_BAD_KEYSET_PARAM
#define	HOB_MSCAPI_FAIL_ERR        37   // NTE_FAIL
#define	HOB_MSCAPI_SYSERR_ERR      38   // NTE_SYS_ERR
#define	HOB_MSCAPI_ALREXI_ERR      39   // ERROR_ALREADY_EXISTS

#define	HOB_MSCAPI_CRUNAL_ERR      50   // CRYPT_E_UNKNOWN_ALGO
#define	HOB_MSCAPI_CRIMGT_ERR      51   // CRYPT_E_INVALID_MSG_TYPE
#define	HOB_MSCAPI_CRUNEN_ERR      52   // CRYPT_E_UNEXPECTED_ENCODING
#define	HOB_MSCAPI_CRAATM_ERR      53   // CRYPT_E_AUTH_ATTR_MISSING
#define	HOB_MSCAPI_CRHSHV_ERR      54   // CRYPT_E_HASH_VALUE
#define	HOB_MSCAPI_CRSINF_ERR      55   // CRYPT_E_SIGNER_NOT_FOUND

#define	HOB_MSCAPI_CRBLEN_ERR      60   // CRYPT_E_BAD_LEN
#define	HOB_MSCAPI_CRBENC_ERR      61   // CRYPT_E_BAD_ENCODE
#define	HOB_MSCAPI_CRFLER_ERR      62   // CRYPT_E_FILE_ERROR
#define	HOB_MSCAPI_CRNOTF_ERR      63   // CRYPT_E_NOT_FOUND
#define	HOB_MSCAPI_CREXIS_ERR      64   // CRYPT_E_EXISTS
#define	HOB_MSCAPI_CRNOPR_ERR      65   // CRYPT_E_NO_PROVIDER
#define	HOB_MSCAPI_CRDELP_ERR      66   // CRYPT_E_DELETED_PREV
#define	HOB_MSCAPI_CRNOMA_ERR      67   // CRYPT_E_NO_MATCH
#define	HOB_MSCAPI_CRNOKP_ERR      68   // CRYPT_E_NO_KEY_PROPERTY
#define	HOB_MSCAPI_CRNODC_ERR      69   // CRYPT_E_NO_DECRYPT_CERT
#define	HOB_MSCAPI_CRBMSG_ERR      79   // CRYPT_E_BAD_MSG
#define	HOB_MSCAPI_CRNOSI_ERR      71   // CRYPT_E_NO_SIGNER
#define	HOB_MSCAPI_CRPDCL_ERR      72   // CRYPT_E_PENDING_CLOSE
#define	HOB_MSCAPI_CRREVO_ERR      73   // CRYPT_E_REVOKED
#define	HOB_MSCAPI_CRSESE_ERR      74   // CRYPT_E_SECURITY_SETTINGS

#define	HOB_MSCAPI_CROSSE_ERR      90   // CRYPT_E_OSS_ERROR
#define	HOB_MSCAPI_CA1ERR_ERR      91   // CRYPT_E_ASN1_ERROR
#define	HOB_MSCAPI_CA1INT_ERR      92   // CRYPT_E_ASN1_INTERNAL
#define	HOB_MSCAPI_CA1EOD_ERR      93   // CRYPT_E_ASN1_EOD
#define	HOB_MSCAPI_CA1COR_ERR      94   // CRYPT_E_ASN1_CORRUPT
#define	HOB_MSCAPI_CA1LAG_ERR      95   // CRYPT_E_ASN1_LARGE
#define	HOB_MSCAPI_CA1CST_ERR      96   // CRYPT_E_ASN1_CONSTRAINT
#define	HOB_MSCAPI_CA1MEM_ERR      97   // CRYPT_E_ASN1_MEMORY
#define	HOB_MSCAPI_CA1OFL_ERR      98   // CRYPT_E_ASN1_OVERFLOW
#define	HOB_MSCAPI_CA1BPD_ERR      99   // CRYPT_E_ASN1_BADPDU
#define	HOB_MSCAPI_CA1BAR_ERR     100   // CRYPT_E_ASN1_BADARGS
#define	HOB_MSCAPI_CA1BRE_ERR     101   // CRYPT_E_ASN1_BADREAL
#define	HOB_MSCAPI_CA1BTG_ERR     102   // CRYPT_E_ASN1_BADTAG
#define	HOB_MSCAPI_CA1CHC_ERR     103   // CRYPT_E_ASN1_CHOICE
#define	HOB_MSCAPI_CA1RUL_ERR     104   // CRYPT_E_ASN1_RULE
#define	HOB_MSCAPI_CA1UTF_ERR     105   // CRYPT_E_ASN1_UTF8
#define	HOB_MSCAPI_CA1PDT_ERR     106   // CRYPT_E_ASN1_PDU_TYPE
#define	HOB_MSCAPI_CA1NYI_ERR     107   // CRYPT_E_ASN1_NYI
#define	HOB_MSCAPI_CA1EXT_ERR     108   // CRYPT_E_ASN1_EXTENDED
#define	HOB_MSCAPI_CA1NED_ERR     109   // CRYPT_E_ASN1_NOEOD

#define	HOB_MSCAPI_UNSPEC_ERR     119   // unspecified error

#define	HOB_MSCAPI_CETNTV_ERR     130   // CERT_TRUST_IS_NOT_TIME_VALID
#define	HOB_MSCAPI_CETNTN_ERR     131   // CERT_TRUST_IS_NOT_TIME_NESTED
#define	HOB_MSCAPI_CETREV_ERR     132   // CERT_TRUST_IS_REVOKED
#define	HOB_MSCAPI_CETNSV_ERR     133   // CERT_TRUST_IS_NOT_SIGNATURE_VALID
#define	HOB_MSCAPI_CETNVU_ERR     134   // CERT_TRUST_IS_NOT_VALID_FOR_USAGE
#define	HOB_MSCAPI_CETUNR_ERR     135   // CERT_TRUST_IS_UNTRUSTED_ROOT
#define	HOB_MSCAPI_CETRSU_ERR     136   // CERT_TRUST_REVOCATION_STATUS_UNKNOWN
#define	HOB_MSCAPI_CETCYC_ERR     137   // CERT_TRUST_IS_CYCLIC
#define	HOB_MSCAPI_CETPTC_ERR     138   // CERT_TRUST_IS_PARTIAL_CHAIN
#define	HOB_MSCAPI_CTCNTV_ERR     139   // CERT_TRUST_CTL_IS_NOT_TIME_VALID
#define	HOB_MSCAPI_CTCNSV_ERR     140   // CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID
#define	HOB_MSCAPI_CTCNVU_ERR     141   // CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE

/************************************************************************/
/* EOF Defines                                                          */
/************************************************************************/

#endif                                /* DEFMCAPI_H_HOB250902__INCLUDED */
#ifndef _HSSL_FILE_HEADER
#define _HSSL_FILE_HEADER
/** @addtogroup hssl
* @{
* @file
* This header contains some additional defines used in the SSL protocol module.
* @}
*/

//-------------------------------------------------------------
// Definitions for configuration/cdb file header Query function
//-------------------------------------------------------------

#define HQRY_FILE_VERSION	0	// meaningful for all types
#define	HQRY_CFG_FILETYPE	1	// meaningful for all types
#define	HQRY_CFG_CFGFLAGS	2	// CFG files only
#define	HQRY_CFG_EXTCFGFLAGS	3	// CFG files only
#define	HQRY_CFG_CFGEXTCFGFL	4	// CFG files only
#define	HQRY_CFG_ADDEXTCFGFL	5	// CFG files only
#define HQRY_CFG_FULLFLAGS	6	// CFG files only

//-------------------------------------------------------------
// Definitions for the config., Cert/CertReq and password files
//-------------------------------------------------------------

#define	FILE_TYPE_SRVR_CFG	1
#define	FILE_TYPE_CLNT_CFG	2
#define FILE_TYPE_SRVR_CERT	3
#define FILE_TYPE_CLNT_CERT	4
#define FILE_TYPE_SRVR_CERT_REQ	5
#define FILE_TYPE_CLNT_CERT_REQ	6
#define FILE_TYPE_SRVR_PWD	7
#define FILE_TYPE_CLNT_PWD	8
#define FILE_TYPE_SRVR_CERT_PWD	9
#define FILE_TYPE_CLNT_CERT_PWD	10
#define	FILE_TYPE_VPN_CERT_PWD	11
#define	FILE_TYPE_VPN_CERT	12
#define	FILE_TYPE_VPN_CERT_REQ	13

#define	FILE_MAGIC_NUMBER	0xA35B
#define FILE_VERSION1_REV0	0x0100		// 1.0
#define FILE_VERSION1_REV1	0x0101		// 1.1
#define FILE_VERSION1_REV2	0x0102		// 1.2 with ext. config blob
#define FILE_VERSION1_REV3 0x0103      // 1.3

#define	FILE_HEADER_LEN		0x50		// full header, 80 bytes
#define	FILE_HEADER_LEN1	0x30		// for header hash
#define	FILE_HEADER_LEN2	0x40		// for date hash

#define FILE_HDR_ID_LEN		8

#define	FILE_HDR_MAGIC_INDEX		0
#define	FILE_HDR_VERSION_INDEX		2
#define	FILE_HDR_PWD_EXPIRE_TIME_INDEX	4
#define	FILE_HDR_FILE_ID_INDEX		8
#define FILE_HDR_PWD_HDR_HASH_INDEX	0x30
#define FILE_HDR_PWD_DATA_HASH_INDEX	0x40

#define	FILE_DATA_START_INDEX		0x50

// specific for configuration file

#define	FILE_HDR_PROTO_INDEX		0x10	// Protokoll-Bits
#define	FILE_HDR_CIPHSUITES_LEN_INDEX	0x12	// list length
#define	FILE_HDR_CMPRMETHODS_LEN_INDEX	0x14	// list length
#define	FILE_HDR_CACHE_AGING_TIME_INDEX	0x16	// Cache aging time
#define	FILE_HDR_RENEGOTIATE_TIME_INDEX	0x1A	// Renegotiation time
//#define FILE_HDR_CERT_POLICIES_INDEX	0x1E	// Certificate acceptance
// due to Solaris Compiler: (1E is misinterpreted)
#define FILE_HDR_CERT_POLICIES_INDEX	30	// Certificate acceptance
#define FILE_HDR_SUBJ_NAMELST_LEN_INDEX 0x20	// Subject common name list len
#define FILE_HDR_MAX_CONNECTIONS_INDEX	0x24	// number of connections
#define	FILE_HDR_CONNECT_TIMEOUT_INDEX	0x26	// connection timeout
#define	FILE_HDR_EXT_CFG2_FLAGS_INDEX	0x28	// extended config2 flags
#define	FILE_HDR_EXT_CFG_LEN_INDEX	0x2A	// extended config. length

// specific for password file

#define FILE_DATA_PWD_LEN		144	// formatted password
#define FILE_DATA_PWD_BLOCKTYPE		0x03	// start of formatting
#define	FILE_DATA_PWD_DELIM		0x00	// delimiter
#define FILE_DATA_PWD_PADDING_LEN	13	// random padding bytes
#define	FILE_DATA_MAX_SALT_LEN		128	// salt byte count

#define	FILE_HDR_PWD_DATALEN_INDEX	0x10	// length of data to follow

#define MAX_PASSWORD_LEN		128

// specific for certificate/certificate request file

#define FILE_HDR_ENTRY_CNT_INDEX	0x10	// Entry Counter

#define ENTRY_ID			1	// ID for Certificate/Certreq.

#define ENTRY_HDR_LEN			12	// length of header

#define ENTRY_HDR_ID_INDEX		0	// ID for Entry Header (1)
#define ENTRY_HDR_REL_INDEX_INDEX	4	// relativ Index of Entry
#define ENTRY_HDR_CONT_LEN_INDEX	8	// ASN.1 Container len(excl.)

#define MAX_CONTAINER_LEN		(1024 * 128)
#if defined _WIN32

#define FINP_HANDLE	int
#define FOUTP_HANDLE	int
#endif // JAVA

#define MAX_CONT_COUNT			1000	// number of containers
#define MAX_CONT_ALIAS_NAME_LEN		256

//==============================================================
// Include Data for local Helper Libraries
//==============================================================

//-------------------------------------------------------
// Configuration File Names / ID-Strings
//-------------------------------------------------------

#define	SRVRCFG_DEF_FNAME_LEN	12
#define	CLNTCFG_DEF_FNAME_LEN	12

//-------------------------------------------------------
// Certificate File Names / ID-Strings
//-------------------------------------------------------

#define	SRVRCERTS_DEF_FNAME_LEN		12
#define	CLNTCERTS_DEF_FNAME_LEN		12
#define	SRVRCERTREQ_DEF_FNAME_LEN	12
#define	CLNTCERTREQ_DEF_FNAME_LEN	12
#define	VPNCERTS_DEF_FNAME_LEN		12
#define	VPNCERTREQ_DEF_FNAME_LEN	12

//-------------------------------------------------------
// Password File Names / ID-Strings
//-------------------------------------------------------

#define	SRVRPWD_DEF_FNAME_LEN		12	// Configuration
#define	CLNTPWD_DEF_FNAME_LEN		12	// Configuration
#define SRVRCERTPWD_DEF_FNAME_LEN	12	// Certificates/Cert-Requests
#define CLNTCERTPWD_DEF_FNAME_LEN	12	// Certificates/Cert-Requests
#define	VPNCERTPWD_DEF_FNAME_LEN	12	// VPN Certificates

#endif // _HSSL_FILE_HEADER

/**
* Server side session cache element for session resume purpose.
* One element needed per session to resume/duplicate. <br>
* NOTE: Elements will be allocated in GLOBAL heap (session independent).
*/
typedef struct HSERV_CACHE_ELEM_t {
	char SessionID[MAX_SESSION_ID_LEN+1];	 //!<     32+1 bytes
	char	SelectedProtocol;	//!< selected Protocol	     1 byte
	char	Reserved1;		//!< unused	             1 byte
	char	SelectedComprMethod;	//!< selected Compr. Method    1 byte
	short	SelectedCipherSuite;	//!< selected Ciph.Suite,      2 byte
	char	CertifiedFlags;		//!< certificate status	     1 byte
	char	ReferenceCount;		//!< number of refs. active    1 byte
	char MasterSecret[MASTER_SECRET_LEN]; //!< Master Secret 48 byte
	uint32_t	ExpireUtcMsw;		//!< Element expire time MSW   4 byte
	uint32_t  ExpireUtcLsw;		//!< dto. LSW		     4 byte
        char PartnerCertHash[SHA_DIGEST_LEN];//!<  SHA-1 hash    20 byte
} HSERV_CACHE_ELEM;

/**
* Client side session cache element for session resume purpose.
* One element needed per session to resume/duplicate. <br>
* NOTE: Elements will be allocated in GLOBAL heap (session independent).
*       Same layout as server, additional IP-Address/Port buffer.
*/
typedef struct HCLNT_CACHE_ELEM_t {
	char SessionID[MAX_SESSION_ID_LEN+1];	 //!<     32+1 bytes
	char	SelectedProtocol;	//!< selected Protocol	     1 byte
	char	Flags;			//!< for cloning etc.          1 byte
	char	SelectedComprMethod;	//!< selected Compr. Method    1 byte
	short	SelectedCipherSuite;	//!< selected Ciph.Suite,      2 byte
	char	CertifiedFlags;		//!< certificate status	     1 byte
	char	ReferenceCount;		//!< number of refs. active    1 byte
	char MasterSecret[MASTER_SECRET_LEN]; //!< Master Secret 48 byte
	uint32_t	ExpireUtcMsw;		//!< Element expire time MSW   4 byte
	uint32_t  ExpireUtcLsw;		//!< dto. LSW		     4 byte
        char PartnerCertHash[SHA_DIGEST_LEN];//!<  SHA-1 hash    20 byte
	char ConnectionID[MAX_CONNECTION_ID_LEN+1]; //IP/Port  38 byte
} HCLNT_CACHE_ELEM;

typedef struct HSESSCACHE_CTL_DESC_t HSESSCACHE_CTL_DESC;

#if defined __cplusplus
extern "C" {
#endif

extern int CheckAuxCMASupport(HMEM_CTX_DEF int CacheType);

extern int SetSessionCacheInitParams(int CacheType,
				     uint32_t CacheMaxEntriesCount,
				     uint32_t CacheElementTimeToLive);

extern int ServerCacheSessionCreate(HMEM_CTX_DEF
			      HSERV_CACHE_ELEM * pElementTemplate,
			      char* pNewSessionID,
			      int CreateMode,
			      char* pCipherSuitesList,
			      char* pComprMethodsList);

extern int ServerCacheSessionAbort(HMEM_CTX_DEF
			     char* pSessionID, int CacheMode);

extern int ServerCacheSessionEstablished(HMEM_CTX_DEF
				   HSERV_CACHE_ELEM * pElementTemplate,
				   int CacheMode);

extern int ServerCacheSessionClosed(HMEM_CTX_DEF
			      HSERV_CACHE_ELEM * pElementTemplate,
			      int CacheMode);

extern int ClientCacheSessionCreate(HMEM_CTX_DEF
			      HCLNT_CACHE_ELEM * pElementTemplate,
			      char* pCipherSuitesList,
			      char* pComprMethodsList);

extern int ClientCacheSessionAbort(HMEM_CTX_DEF
				   char* pConnectionID, char* pSessionID,
			           int CacheMode);

extern int ClientCacheSessionModify(HMEM_CTX_DEF
			           HCLNT_CACHE_ELEM * pElementTemplate,
				   char* pSessionID,
			           int CacheMode);

extern int ClientCacheSessionEstablished(HMEM_CTX_DEF
				   HCLNT_CACHE_ELEM * pElementTemplate,
				   int CacheMode);

extern int ClientCacheSessionClosed(HMEM_CTX_DEF
			      HCLNT_CACHE_ELEM * pElementTemplate,
			      int CacheMode, int CacheRemove);

extern int FreeSessionCache(HMEM_CTX_DEF int CacheType);

#if defined __cplusplus
}
#endif
extern "C"  int AppendMacEncryptRecord(CONNSTRU * pConnStruc,
		char* pInpData, int* pDataLen);

extern "C"  int  GenerateCertData(HMEM_CTX_DEF
		char* PwdBuf, int PwdOff,
		int PwdLen, int ExpireTime, int Type,
		int ContainerCnt, int* IndexArray,
		IDATPARR* pAsn1ContDesc,
		IDATPARR* pNameDesc,
		char** ppDst, int* pDstLen);

//-------------------------------------------------------------
// Processing flag definitions for Endcert selection
//-------------------------------------------------------------

#define HSSL_EXT_CERTSEL_FORCE_DLG_BIT	0x01	// force Cr-API dialog
#define	HSSL_EXT_CERTSEL_IGN_INIF_BIT	0x02	// ignore Cr-API INI file
#define	HSSL_EXT_CERTSEL_CLR_INIF_BIT   0x04	// clear Cr-API INI file

#define	HSSL_EXT_CERTSEL_NEVER_DLG_BIT  0x0400	// No Dialog from Cr-API !!

/**
This structure holds all parameters used during generation of SRP verifiers.
*/
struct dsd_tls_srp_verifier_params {
   char* achc_name;
   size_t szc_name_len;
   char* achc_password;
   size_t szc_pw_len;
   char* achc_salt;
   size_t szc_salt_len;
   unsigned char* aucc_n;
   size_t szc_n_len;
   unsigned char* aucc_g;
   size_t szc_g_len;
   unsigned char* aucc_verifier;
   size_t szc_ver_len;
};

/**
This structure holds the parameters for TLS SRP, that are read from
the password file.

Length restrictions are :
All must be at least 1 byte long.
Name and Salt must be at most 255 bytes.
All others must be at most 2^16-1 bytes.
*/
struct tls_srp_pw_file_params {
   /** Buffer holding the group prime N as bytewise big endian number. */
   unsigned char* aucc_n;
   /** Length of the prime N in bytes. */
   int inc_n_len;
   /** Buffer holding the group generator g as bytewise big endian number. */
   unsigned char* aucc_g;
   /** Length of the generator g in bytes. */
   int inc_g_len;
   /** Buffer containing the salt to be used. */
   char* achc_salt;
   /** Length of the salt without 0 termination. */
   int szc_salt_len;
   /** Buffer containing the SRP verifier as bytewise big endian number. */
   unsigned char* aucc_verifier;
   /** Length of the verifier in bytes. */
   int inc_ver_len;
};

extern "C" void CdrEnc(HMEM_CTX_DEF DCDR*);
extern "C" void CdrDec(HMEM_CTX_DEF DCDR*);

#ifndef HSSL_LOGGING_H
#define HSSL_LOGGING_H
#ifdef XH_INTERFACE
#define LOG_PTR struct dsd_logger*

#define GEN_WSP_TRACER(ctx,log,sess_nr,aux,usr_fld) m_gen_wsp_tracer(ctx,log,sess_nr,aux,usr_fld)

#define MAKE_LOG(log,tag) m_make_log_entry(log,tag)
#define ADD_LOG_TEXT(log,text,len) m_add_text_data(log,text,len)
#define ADD_LOG_DATA(log,data,len) m_add_binary_data(log,data,len)
#define EVENT_TRACE_LVL(log,lvl) m_event_trace_lvl(log,lvl)
#define FREE_LOG(ctx,log) m_destroy_logger(ctx,log)
#else
#define LOG_PTR struct dsd_logger*

#define GEN_WSP_TRACER(ctx,log,sess_nr,aux,usr_fld) 

#define MAKE_LOG(log,tag) 
#define ADD_LOG_TEXT(log,text,len) 
#define ADD_LOG_DATA(log,data,len)
#define EVENT_TRACE_LVL(log,lvl)
#define FREE_LOG(ctx,log)

#endif
#endif

extern "C" void  FreeExtCertStruc(HMEM_CTX_DEF
					 HEXTCST * pExtStruc);

#define ADD_64(SumMsw, SumLsw, Summand) \
  if((uint32_t) SumLsw > \
     ((uint32_t) SumLsw + (uint32_t) Summand)) SumMsw++; \
  SumLsw += Summand;

extern "C"  int  HSSL_GetIssuerCertChainFromExt(HMEM_CTX_DEF
		HEXTCST * pExtStruc,
                X509CERT ** pInpCertChain, int nInpCertCount,
                CTREESTR ** pRetTreeStruc);

extern "C"  int  HSSL_GetSpecifEndCertFromListTLS12(HMEM_CTX_DEF
                  HEXTCST * adsp_ext_c_struc, CTREESTR * adsp_tree_struc,
                  int inp_public_alg, char* abyp_sig_types, 
                  int inp_process_flags, X501_DN* aadsp_dn_list[], 
                  int inp_dn_count, IDATPARR* adsp_dh_params, 
                  int ainp_result[]);

extern "C"  int  HSSL_GenSignatWithExtPrivKey(HMEM_CTX_DEF
		HEXTCST * pExtStruc,
		char* pbyInpBuf, int nInpOff, int nInpLen,
                char* pbyDstBuf, int nDstOffset, int* pnDstLen,
                char* pbyCertData, int nCertOffset, int nCertLen,
                int nCertPty, int nMode, int nZeroFlag);

extern "C"  int  HSSL_PurgeExtCertIniFile(HEXTCST * pExtStruc);

/**
* This structure is used to hold parameters during initialization of the SSL module.
*/
typedef struct HSISTR_t {
	char*		pCfgDataBuf;	//!< Configuration data buffer
	int		CfgDataLen;	//!< Size of config data
	char*		pCfgPwdBuf;	//!< Config password buffer
	int		CfgPwdLen;	//!< Size of config. password data
	int		CfgPwdType;	//!< Type of password data, 0 == direct
	char*		pCertDataBuf;	//!< Certificates data buffer
	int		CertDataLen;	//!< Size of cert data
	char*		pCertPwdBuf;	//!< Certificates password buffer
	int		CertPwdLen;	//!< Size of cert. password data
	int		CertPwdType;	//!< Type of password data, 0 == direct
	int		Entity;		//!< Bit 0: Server / client Mode
					//!< Bit 1: Server cert reply mode
	int		Retcode;	//!< Returncode from constructor
	int		InitFlags;	//!< Initialization flags
	int		Mode;		//!< Reserved (XHSERVER)
	struct CFG_STRU_t * pCfgStruc;	//!< Reserved (XHSERVER)
	void (*pAskUserCertsCb)();	//!< Callback function for certificates
}HSISTR;

extern "C"  int HSSL_GetVersionInfo(int* pVersion,  
				      char* pDstBuf, int* pDstLen);

extern "C"  int  DecodePasswdData(HMEM_CTX_DEF
		char* HdrBuf, int HdrOff,
		int HdrLen, char* DataBuf, int DataOff, int DataLen,
		int Type, char** ppDst, int* pPwdLen);

#if defined __cplusplus
extern "C" {
#endif

#ifndef _WIN32
typedef void * HINSTANCE;
typedef void * HMODULE;
#endif
extern  int  GenVfyPwdMD5Hashes(char HdrBuf[], int HdrOff,
		int HdrLen, char DataBuf[], int DataOff, int DataLen,
		char PwdBuf[], int PwdOff, int PwdLen, int Mode);

extern  int  GenVfyFixedFileHdrs(char HdrBuf[], int HdrOff,
		int HdrLen, int Type, int Mode);

extern int  GenerateCertData(HMEM_CTX_DEF
		char PwdBuf[], int PwdOff,
		int PwdLen, int ExpireTime, int Type,
		int ContainerCnt, int IndexArray[],
		IDATPARR* pAsn1ContDesc,
		IDATPARR* pNameDesc,
		char** ppDst, int pDstLen[]);

extern int  GeneratePasswdData(HMEM_CTX_DEF
		char PwdBuf[], int PwdOff,
		int PwdLen, int ExpireTime, int Type,
	        char**(ppDst), int pDstLen[]);

extern int  DecodePasswdData(HMEM_CTX_DEF
		char HdrBuf[], int HdrOff,
		int HdrLen, char DataBuf[], int DataOff, int DataLen,
		int Type, char**(ppDst), int pPwdLen[]);

extern  int  ExtractConfigData(HMEM_CTX_DEF
			char HdrBuf[], int HdrOff, int HdrLen,
			char DataBuf[], int DataOff, int DataLen,
			char PwdBuf[], int PwdOff, int PwdLen, int Type,
			int pConfigFlags[], int pExtConfigFlags[],
			int pExtConf2Flags[],
			int pCertPolicyFlags[],
			char** ppCiphSuiteList,
			char** ppCmprMethList,
			char** ppSubjNamesList,
			int pCacheAgingTime[],
			int pRenegotiateTime[],
			int pPwdExpireTime[],
			int pMaxConnCnt[],
			int pConnectTimeOut[]);

extern  int  ExtractCertData(HMEM_CTX_DEF
			char HdrBuf[], int HdrOff, int HdrLen,
			char DataBuf[], int DataOff, int DataLen,
			char PwdBuf[], int PwdOff, int PwdLen, int Type,
			int pPwdExpireTime[],
			int* ppIndexArray[],
			IDATPARR* ppAsn1ContDescArr[],
			IDATPARR* ppNameDescArr[],
			int pEntryCnt[]);

extern  int  ExtractConfigDataEx(HMEM_CTX_DEF
			char DataBuf[], int DataOff,
			int DataLen, char PwdBuf[], int PwdOff, int PwdLen,
			int Type, CFG_STRU * ppCfgStr[],
			char* ppExtCfgBuf[], int pExtCfgLen[],
			int pPwdExpireTime[]);

extern  int  GetConfigHeaderInfo(char HdrBuf[], int HdrOff,
		int HdrLen, int QueryType, int pQueryRetValue[]);

extern  int  IsSingleConfig(char* pDataBuf, int DataLen,
                                      int* pRetValue);

extern  int HSSL_GetVersionInfo(int pVersion[],  
				      char pDstBuf[], int pDstLen[]);

extern  int  GetExtCfgDataByTag(HMEM_CTX_DEF
   int ExtensionTagID,
   char pExtensionData[], int ExtensionOff, int ExtensionLen,
   char* ppTagDataBuf[], int pTagDataLen[]);

extern  void  FreeExtCertStruc(HMEM_CTX_DEF
					 HEXTCST * pExtStruc);

extern  int  HSSL_InitExtCertLib(HMEM_CTX_DEF
					   CFG_STRU * pCfgStruc,
					   HINSTANCE hModuleInst);

extern  int  HSSL_CreateExtStoreCertTree(HMEM_CTX_DEF
		HEXTCST * pExtStruc,
		char* ppbyCertsDataBuf[], int pnCertsDataLen[],
		char* ppbyCertsPwdBuf[], int pnCertsPwdLen[],
		int pnCertsPwdType[]);

extern  int  HSSL_GetIssuerCertChainFromExt(HMEM_CTX_DEF
		HEXTCST * pExtStruc,
                X509CERT ** pInpCertChain, int nInpCertCount,
                CTREESTR **(pRetTreeStruc));

extern  int  HSSL_GetSpecifEndCertFromListEx(HMEM_CTX_DEF
                        HEXTCST * pExtStruc,
                        CTREESTR * pTreeStruc,
                        int PublicAlgor, int SignatAlgor, int ProcessFlags,
                        X501_DN* pDNList[], int DnCount,
                        IDATPARR* pDHParams,
                        int pResult[]);

extern  int  HSSL_GetSpecifEndCertFromListTLS12(HMEM_CTX_DEF
                        HEXTCST * adsp_ext_c_struc, CTREESTR * adsp_tree_struc,
                        int inp_public_alg, char* abyp_sig_types, 
                        int inp_process_flags, X501_DN* aadsp_dn_list[], int inp_dn_count,
                        IDATPARR* adsp_dh_params, int ainp_result[]);

extern  int  HSSL_GenSignatWithExtPrivKey(HMEM_CTX_DEF
		HEXTCST * pExtStruc,
		char pbyInpBuf[], int nInpOff, int nInpLen,
                char pbyDstBuf[], int nDstOffset, int pnDstLen[],
                char pbyCertData[], int nCertOffset, int nCertLen,
                int nCertPty, int nMode, int nZeroFlag);

extern  int  HSSL_PurgeExtCertIniFile(HEXTCST * pExtStruc);

/**
Filters the given cipher list to contain only supported ciphers.

Input must be non-NULL and in the format of a TLS cipher list.
There will be no NULL check!
The order of the ciphers will be maintained.

@param[in,out]  achp_cipher_list    List to be filtered.

@return Number of ciphers remaining in the list, -1 if the list is malformed.
*/
extern int m_filter_cipher_list(char* achp_cipher_list);

#if defined __cplusplus
}
#endif

#if !defined(CFGEXTDATATAGS_H_HOB131202__INC)
#define CFGEXTDATATAGS_H_HOB131202__INC

/************************************************************************/
/* Definitions for HOBmscrAp                                            */
/************************************************************************/

/*----------------------------------------------------------------------*/
/* Definitions for Tags of the Extended Configuration Data              */
/*----------------------------------------------------------------------*/

// Tag for identification of Key Usage Search Criteria
#define	EXTCFG_TAG_SEARCHCRIT      0x0010
// Tag for identification of signature algorithms used in TLS v1.2
#define EXTCFG_TAG_TLS12_SIG_ALGS  0x0013
// Tag for unspecific file information to access CrypAPI
#define EXTCFG_TAG_UNSPECFILE      0x0020
// Tag for DLL file information to access CrypAPI
#define EXTCFG_TAG_DLLFILEINF      0x0021
// Tag for INI file information how to access CrypAPI
#define EXTCFG_TAG_INIFILEINF      0x0022
// Tag for DLL path information to access Default CrypAPI
#define EXTCFG_TAG_DLLPATHINF      0x0023
// Tag for INI-file path information to get Default-Ini-File how to access CrypAPI
#define EXTCFG_TAG_INIPATHINF      0x0024

// Tag for OCSP URL information
#define EXTCFG_TAG_OCSP_URLINF	   0x0030

// Tag for PKCS11 DLLname information
#define EXTCFG_TAG_PKCS11_DLLNAME  0x0040

// Tag for Extended Config Array
#define EXTCFG_TAG_EXTCFG_ARRAY    0x0050

// Tag for CPU-based AES support activation
#define EXTCFG_TAG_USE_CPU_AES     0x0060

/*----------------------------------------------------------------------*/
/* Definitions for data values of Key Usage Search Criteria             */
/*----------------------------------------------------------------------*/
#define	EXTCFG_KYUS_SCRT_INVALID     0x00  // Invalid Search Criteria
#define	EXTCFG_KYUS_SCRT_KEYENCM     0x01  // Key Encipherment
#define	EXTCFG_KYUS_SCRT_DIGSIGN     0x02  // Digital Signature

/************************************************************************/
/* EOF Defines                                                          */
/************************************************************************/

#endif                          /* CFGEXTDATATAGS_H_HOB131202__INCLUDED */

#if !defined XH_INTERFACE
#define	CONN_pMemCtx(a)
#define	CONN_pOcspCtx(a)
#else
#define	CONN_pMemCtx(a)		a->pMemCtxStruc
#define	CONN_pOcspCtx(a)	a->pOcspCtxStruc
#endif
#if !defined __XIF_HEADER__
#define __XIF_HEADER__

//--------------------------------------------------------
// The control structure used per server/client connection
//--------------------------------------------------------

typedef struct XHCONNSTRUC_t{
    int		XHConnState;		// current connect state
    int		DeferredRetcode;	// Returncode from Alert send
    CONNSTRU *	pConnStruc;		// HSSL Connection Structure
} XHCONNSTRUC;

//----------------------------------------------------------------
// Internal State Codes for the XHServer interface and the
// XHClient interface
//----------------------------------------------------------------

#define	XH_STATE_NORMAL			0	// normal processing
#define	XH_STATE_CONNECT_START		1	// Connect initiated
#define	XH_STATE_CONNECT_SEND		2	// Sending connect
#define	XH_STATE_CONNECT_WAIT		3	// Connect in progress
#define	XH_STATE_CONNECT_ALERT		4	// Send Connect alert
#define	XH_STATE_CONNECT_CLOSING	5	// Send Connect alert
#define	XH_STATE_CLOSING		6	// is in closing state
#define	XH_STATE_CLOSED			7	// is closed

#endif // __XIF_HEADER__

#ifdef __cplusplus
extern"C"{
#endif

   /** @addtogroup ssllog
*  @{
*  @file
*  This header declares the C interface used by the WSP trace wrapper for SSL.
*/
struct dsd_logger; // Forward declaration (no definition needed)
/**
*  Generates a dsd_wsp_trace_log instance, using SSL memory management and 
*  placement new.
*
*  @see dsd_wsp_trace_log::dsd_wsp_trace_log
*
*  @param inp_trace_lvl    The trace level set by the WSP.
*  @param inp_is_client    If != 0, this is generated as client instance
*  @param inp_session_nr   Session number to be set in the log entries
*  @param amp_aux          Pointer to the used auxilliary function
*  @param avop_usr_field   Pointer to the user field for the aux function
*/

struct dsd_logger* m_gen_wsp_tracer(HMEM_CTX_DEF int inp_trace_lvl, int inp_is_client, int inp_session_nr, BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ), void* avop_usr_field);
/**
*  Wrapper for dsd_logger::m_make_log_entry.
*
*  @param adsp_log_inst    Pointer to the logger instance
*  @param achp_log_tag     Tag string to be used
*/
void m_make_log_entry(struct dsd_logger* adsp_log_inst, const char* achp_log_tag);
/**
*  Wrapper for dsd_logger::m_add_text_data.
*
*  @param adsp_log_inst    Pointer to the logger instance
*  @param achp_data_buf    Pointer to the buffer containing the data
*  @param inp_len          Length of the text data in the buffer
*/
void m_add_text_data(struct dsd_logger* adsp_log_inst, const char* achp_data_buf, int inp_len);
/**
*  Wrapper for dsd_logger::m_add_binary_data.
*
*  @param adsp_log_inst    Pointer to the logger instance
*  @param achp_data_buf    Pointer to the buffer containing the data
*  @param inp_len          Length of the text data in the buffer
*/
void m_add_binary_data(struct dsd_logger* adsp_log_inst, char* achp_data_buf, int inp_len);
/**
*  Wrapper for dsd_logger::m_event_trace_lvl.
*
*  @param adsp_log_inst    Pointer to the logger instance
*/
void m_event_trace_lvl(struct dsd_logger* adsp_log_inst, int inp_target_trace_lvl);
/**
*  Calls the destructor and then releases the memory of the instance.
*
*  The instance must have been created with m_gen_wsp_tracer, using the same
*  memory manager instance.
*
*  @param adsp_log_inst    Pointer to the logger instance
*/
void m_destroy_logger(HMEM_CTX_DEF struct dsd_logger* adsp_log_inst);
/**
*  Wrapper for dsd_wsp_trace_log::m_reload_field.
*
*  @param adsp_log_inst    Pointer to the logger instance
*  @param amp_aux          The new aux function pointer to be used
*  @param avop_usr_field   The new user field pointer to be used
*/
void m_reload_field(struct dsd_logger* adsp_log_inst, BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ), void* avop_usr_field);
/** @}*/

   
#ifdef __cplusplus
}
#endif
struct dsd_hl_ssl_s_2 {                     /* HOBLink SSL Server 2    */
   int        inc_func;                     /* called function         */
   int        inc_return;                   /* return code             */
#define B050814
#ifndef B050814
   BOOL       boc_socket_alive;             // socket is still open, when
                                            // called with close request
#else
   BOOL       boc_eof_client;               /* End-of-File Client      */
   BOOL       boc_eof_server;               /* End-of-File Server      */
#endif
   char *     achc_inp_cur;                 // RX-Data from Socket, Start
   char *     achc_inp_end;                 // Top of buffer

   struct dsd_gather_i_1 *adsc_gather_i_1;  // TX-Data from Applic.

   char *     achc_out_cur;                 // RX-Data to Applic., Start
   char *     achc_out_end;                 // Top of buffer

   char *     achc_send_cur;                // TX-Data to Socket, Start
   char *     achc_send_end;                // Top of buffer

   BOOL (* amc_aux) ( void *vpp_userfld, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       // attached buffer pointer
   void *     ac_config_id;                 // ID of Configuration to use
#ifndef OLD_0410
   void (* amc_conn_callback) ( struct dsd_hl_ssl_ccb_1 * );  // Connect Callback
#else
   void (* amc_conn_callback) ( void * vpp_userfld, void *, void * );  // Connect Callback
#endif
   int (* amc_ocsp_start) ( void * vpp_userfld, struct dsd_hl_ocsp_d_1 * );  // OCSP start
   int (* amc_ocsp_send) ( void * vpp_userfld, char *achp_buf, int inp_len );  // OCSP send
   struct dsd_hl_ocsp_rec * (* amc_ocsp_recv) ( void * vpp_userfld );  // OCSP receive
   void (* amc_ocsp_stop) ( void * vpp_userfld );  // OCSP stop
   void *     vpc_userfld;                  /* User Field Subroutine   */
   HL_LONGLONG ilc_entropy;                 /* seed for random         */
};

#if HOB_WIN64_ASM != 1
//IncSequenceNumber
inline void IncSequenceNumber(char* pSeqNumber)
{
  int i = SEQUENCE_NUM_LEN-1;			// get Count/Index
  int Carry=1;
  do
  {
    Carry += (int) pSeqNumber[i] & 0xFF;	// add up
    pSeqNumber[i] = (char) Carry;		// store  
    Carry = (Carry >> 8) & 0xFF;		// shift down carry
    i--;
  }while(i >= 0);
}
#else // we ARE on a little endian machine !!
//IncSequenceNumber
static  __inline void IncSequenceNumber(char* pSeqNumber)
{
   _int64 Tmp;

   Tmp = _byteswap_uint64(((_int64 *) pSeqNumber)[0]) + 1;
   ((_int64 *) pSeqNumber)[0] = _byteswap_uint64(Tmp);
}
#endif // !defined WIN_EM64T_ASSEMBLER

#endif // !__HOB_SSL_INTERN__

#if !defined XH_INTERFACE // not used with alternate
#ifdef __cplusplus
extern "C" {
#endif
/**
* Disconnects an existing SSL protected TCP connection (HLSSL_Disconnect).
*
* The connection is identified by the socket index in the global configuration.
* A close notification is sent, remaining queued TX data is sent, the 
* connection is removed from the list and the socket is closed.
*
*  @param SocketID Index to socket array, rel. 1
*  @return 0 on success, error code otherwise
*/
extern int HLSSL_Disconnect(int SocketID);
/**
* Initializes a new connection structure for a client entity (HLSSL_Connect).
*
* Initialization is based on the global configuration, the generated connection
* structure is placed at the given socket index.
*
* The TCP connection is already established.
*
* See InitializeNewConnection
*
*  @param SocketID Index to socket array, rel. 1
*  @param ServerIpAdr IP-Address of server, 4 bytes
*  @param ServerPort Port of server 
*  @param ClientIpAdr IP-Address of client, 4 bytes
*
*  @return == 0 on success
* <br>            < 0 rejected
*/
extern int HLSSL_Connect(int SocketID,
                         char* ServerIpAdr,
			             int ServerPort, 
                         char* ClientIpAdr);

/**
* Initializes a new connection structure for a server entity (HLSSL_Accept).
*
* Initialization is based on the global configuration, the generated connection
* structure is placed at the given socket index.
*
* The TCP connection is already established.
*
* See InitializeNewConnection
*
*  @param SocketID Index to socket array, rel. 1
*  @param ServerIpAdr IP-Address of server, 4 bytes
*  @param ServerPort Port of server 
*  @param ClientIpAdr IP-Address of client, 4 bytes
*
*  @return == 0 on success
* <br>            < 0 rejected
*/
extern int HLSSL_Accept(int SocketID,
                        char* ServerIpAdr,
                        int ServerPort,
                        char* ClientIpAdr);

/**
* Receives application data, if available (HLSSL_SelectRecv). If not, checks if the socket
* has data available and processes them.
*
*  The SSL interface must already have a connection structure.
*
*  @param SocketID Index to socket array, rel. 1
*  @return  0 - no data
* <br>            1 - data/remote(lcl) close 
* <br>            -1 - invalid socket ID
*/
extern int HLSSL_SelectRecv(int SocketID);

/**
* Transmits/buffers application data from the upper layer (HLSSL_Send).
*
* If the SSL instance is still in the handshake phase, an attept is made to
* finish the handshake.
* If the data cannot be sent, it will be buffered for later sending.
*
*  @param SocketID Index to socket array, rel. 1
*  @param SrcBuf Source buffer base
*  @param SrcOff Start of data
*  @param SrcLen Length of buffer
*  @return Bytes sent, < 0 - WouldBlock or Error
*/
extern int HLSSL_Send(int SocketID, 
                      char* SrcBuf, 
                      int SrcOff,
                      int SrcLen);

/**
* Receives application for the upper layer (HLSSL_Recv).
*
* Ignores handshake data.
*
* Tries to transmit outgoing data, if no data can be received.
*
*  @param SocketID Index to socket array, rel. 1
*  @param DstBuf Destination buffer
*  @param DstOff Start of data
*  @param DstLen Length of buffer
*  @return 0 - closed by remote or buffer length 0
* <br>            > 0 - DataCount
* <br>            < 0 - WouldBlock/Error/Timeout
*/
extern int HLSSL_Recv(int SocketID, 
                      char* DstBuf,
                      int DstOff,
                      int DstLen);

/**
* Resets initialization flag and frees the connection structure array and the 
* global configuration structure (HSSL_DeInit).
*
* Does not free possible connection structures in the array.
*/
extern void  HSSL_DeInit(HMEM_CTX_DEF1);

/**
* Reads configuration data and certificates and initializes the SSL/TLS module (HSSL_Init).
*
* @see HSSL_PrivExtInit
*
*  @param ConfigDataBuf Configuration data
*  @param ConfigDataLen Length of configuration data
*  @param CertsDataBuf Certificate database data
*  @param CertsDataLen length of certificate data
*  @param CfgPwdBuf Configuration password data
*  @param CfgPwdLen Configuration password length
*  @param CertsPwdBuf Certificate password data
*  @param CertsPwdLen Certificate password length
*  @param ConfigPwdType == 0 - pure password <br>
*               <> 0 - from file, decode
*  @param CertsPwdType == 0 - pure password <br>
*               > 0 - from file, decode <br>
*               < 0 - use same as config pwd.
*  @param Entity Bit 0: Server / Client entity <br>
*               Bit 1: Server cert request mode <br>
*               Bit 2: Client disable compress <br>
*
*  @return HSSL_OP_OK on success, error code otherwise
*/
extern int HSSL_Init(HMEM_CTX_DEF
                     char* ConfigDataBuf,
                     int ConfigDataLen,
                     char* CertsDataBuf, 
                     int CertsDataLen,
                     char* CfgPwdBuf, 
                     int CfgPwdLen,
                     char* CertsPwdBuf,
                     int CertsPwdLen,
                     int ConfigPwdType, 
                     int CertsPwdType,
                     int Entity);


/**
* Loads a new subject name list into the global configuration (HLSSL_ReloadSubjNamesList).
* Reads configuration data,
* checks if name list in configuration is of same type and not empty.
* If used, if everything is fine, releases the current list and
* replaces with newly loaded one.
*
*  @param ConfigDataBuf Configuration data
*  @param ConfigDataLen Length of configuration data
*  @param CfgPwdBuf Password Base
*  @param CfgPwdLen Password length
*  @param ConfigPwdType == 0 - pure password<br>
*               <> 0 - from file, decode
*  @return HSSL_OP_OK on success, error code otherwise
*/
extern int HLSSL_ReloadSubjNamesList(HMEM_CTX_DEF
                                     char* ConfigDataBuf,
                                     int ConfigDataLen,
                                     char* CfgPwdBuf,
                                     int CfgPwdLen,
                                     int ConfigPwdType);

/**
* Gets length/copies data related to a connection to user buffer (HLSSL_GetConnectionQueryData).
*
* If a buffer is provided, tries to copy, else it returns the required length.
*
* The general layout of the data in the buffer, going by indices, is:
*<ul>
* <li> 0-47: Data transfer statistics.
* <li> 48-62: Information about active state (prot. version, cipher suite and
*           so on).
* <li> 96-164: Server and client IP, session ID.
* <li> 192 and higher: Certificate information.
*</ul>
*
*  @param SocketID Index to socket array, rel. 1
*  @param DstBuf Destination buffer. Optional
*  @param pDstLen length of data (copied / required)
*  @return HSSL_OP_OK on success, error code otherwise
*/
extern int HLSSL_GetConnectionQueryData(int SocketID, 
                                        char* DstBuf,
                                        int* pDstLen);

/**
* Gets length/copies data related to the global configuration to user buffer (HLSSL_GetConfigQueryData).
*
* If a buffer is provided, tries to copy, else it returns the required length.
*
*  @param DstBuf Destination buffer. Optional
*  @param pDstLen Length of data (copied/required)
*  @return HSSL_OP_OK on success, error code otherwise
*/
extern int HLSSL_GetConfigQueryData(char* DstBuf,
                                    int* pDstLen);
#ifdef __cplusplus
};
#endif
#endif // !XH_INTERFACE
