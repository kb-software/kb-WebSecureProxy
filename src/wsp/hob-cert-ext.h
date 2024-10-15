#ifndef __HOB_CERT_EXT__
#define __HOB_CERT_EXT__
#ifdef _WIN32
#pragma once
#endif

/**
This header contains the externals of the HOBLink Secure 3 Certificate Module

Required includes: hob-encry-1.h
*/


// The following structure is defined in "hob_cert_intern.h".
typedef struct PKCS10_CERTREQ_t  PKCS10_CERTREQ;
// The following structure is defined in "hob_cert_intern.h".
typedef struct CERTPARR_t  CERTPARR;
// The following structure is defined in "hob_ssl_intern.h".
typedef struct CFG_STRU_t  CFG_STRU;


/** @addtogroup pkcs5
@{
*/
//-----------------------------------------------------------------------------
// PKCS5
//-----------------------------------------------------------------------------

#define pbeWithMD2AndDES_CBC	 1
#define pbeWithMD5AndDES_CBC	 3
#define pbeWithAES128AndSHA224_CBC   8
#define pbeWithAES128AndSHA256_CBC   9
#define pbeWithAES128AndSHA384_CBC   10
#define pbeWithAES128AndSHA512_CBC   11

#define PKCS5_MIN_PRIV_SEQ_LEN	27			// minimum length
#define PKCS5_MIN_ALGOR_SEQ_LEN	26			// minimum length
#define PKCS5_SALT_LENGTH	8

#define PKCS5_OP_OK			0
#define PKCS5_INVALID_INPUT_DATA	-1
#define PKCS5_NOT_ENOUGH_ASN1_DATA	-2
#define PKCS5_INVALID_ASN1_DATA		-3
#define PKCS5_INVALID_ALGOR_ID		-4
#define PKCS5_INVALID_ALGOR_PARAMS	-5
#define PKCS5_DST_BUF_ALLOC_ERR		-6
#define PKCS5_INVALID_DECRYPTED_DATA	-7


/** Structure for PKCS#5 PBES2 encryption and decryption functions */
struct  dsd_pkcs5_pbes_params
{
   char *              achc_input_data_buf;        //!< pointer to a char buffer containing the input data to be encrypted or decrypted
   size_t              szc_input_buf_size;         //!< length of the data contained in achc_input_data_buf
   char *              achc_password_buf;          //!< pointer to a char buffer containing the password to be used for encryption
   size_t              szc_pwd_buf_size;           //!< length of the data contained in achc_password_buf
   unsigned int        unc_iteration_count;        //!< number of iterations to be performed by the key derivation function
   enum ie_hmac_types  iec_enc_hash_type;          //!< type of hash function to be used by the key derivation function and MAC creation
                                                   //!< Possible values: HMAC_SHA1_ID, HMAC_SHA256_ID, HMAC_SHA384_ID, HMAC_SHA512_ID
                                                   //!< Note: SHA-224 is not supported, HMAC_SHA224_ID not available
   char *              achc_salt_buf;              //!< pointer to a char buffer containing the salt for the key derivation function
   size_t              szc_salt_buf_size;          //!< length of the data contained in achc_salt_buf
   int                 inc_encr_aes_size;          //!< size of the aes key (in bytes) to be used for AES CBC encryption, values are 16, 24 or 32
   char *              achc_initializ_vector_buf;  //!<  pointer to a char buffer containing the initialization vector for CBC encryption
   size_t              szc_initializ_vector_size;  //!<  length of the data contained in achc_initializ_vector_buf for AES CBC encryption
};
typedef struct dsd_pkcs5_pbes_params   dsd_stru_pkcs5_pbes_params;


#ifdef __cplusplus
extern "C" {
#endif
   
/**
* Encrypts and encodes a private key according to PKCS#5 (EncryptPrivateKey).
*
* The output is ASN.1 DER formatted. The output buffer is newly allocated by
* this function.
*
* A non-random salt can be given for testing purposes, this should not be done
* in practical applications! If none is given, a random salt is generated.
*
*  @param PrivateKey Buffer containing the private key
*  @param PrivKeyOff Starting offset of the private key data
*  @param PrivKeyLen Size of key in byte
*  @param Password Buffer containing the password
*  @param PasswdLen Length of the password
*  @param IteratCnt Number of hashes to be done. 
*               1 <= cnt <= 32767
*  @param HashType == 0 -> MD2
*               != 0 -> MD5
*  @param Salt Pointer to salt for testing. Optional
*  @param pDstBuf Pointer for placing the output buffer
*  @param pDstLen Length of the generated data
*
*  @return 0 on success, error code otherwise
*/
extern int EncryptPrivateKey(HMEM_CTX_DEF
                             char PrivateKey[],
                             int PrivKeyOff, 
                             int PrivKeyLen,
                             char Password[], 
                             int PasswdLen,
                             int IteratCnt, 
                             int HashType,
                             char Salt[],
                             char* DstBuf[], 
                             int DstLen[]);

/**
* Generates DES key and IV from given password, salt, iteration count and hash 
* type (GenPKCS5_DesKeyAndIV).
*
* The destination buffer must be allocated and at least 16 byte long. The key
* is written to the first 8 byte block from the offset, the IV to the second.
*
*  @param Password Buffer containing password
*  @param PasswdLen Length of password
*  @param Salt Buffer containing  salt
*  @param SaltOff Start offset of salt data
*  @param DstBuf Key/IV Destination buffer
*  @param IteratCnt number of hashes (<> 0)
*  @param HashType == pbeWithMD2AndDES_CBC -> MD2
*               == pbeWithMD5AndDES_CBC -> MD5
*
*/
extern void GenPKCS5_DesKeyAndIV(char Password[],
                                 int PasswdLen,
                                 char Salt[], 
                                 int SaltOff,
                                 char DstBuf[],
                                 int IteratCnt,
                                 int HashType);

/**
* Decrypts an ASN.1 encoded, PKCS5 formatted encrypted private key (DecryptPrivateKey).
*
* The decrypted key is stored in a newly allocated buffer.
*
*  @param KeyStruc Buffer containing the ASN.1 key data
*  @param KeyStrucOff Offset to start
*  @param KeyStrucLen Length of available input data
*  @param Password Buffer containing the Password
*  @param PasswdLen Length of password
*  @param pDstBuf Pointer where to place the output buffer
*  @param pDstLen Length of the output data
*  @param pIteratCnt Pointer for placing the iteration count of hashes during
*                    decryption. Optional.
*               1 <= cnt <= 32767
*  @param pHashType Pointer for placing used hash type. Optional
*
*  @return PKCS5_OP_OK on success, error code otherwise
*/
extern int DecryptPrivateKey(HMEM_CTX_DEF
                             char KeyStruc[],
                             int KeyStrucOff,
                             int KeyStrucLen,
                             char Password[],
                             int PasswdLen,
                             char* pDstBuf[],
                             int pDstLen[],
                             int pIteratCnt[],
                             int pHashType[]);

/**
 *  Subroutine m_create_pkcs5_aes_pbes2_pbmac1 writes data in encrypted form
 *  to a PKCS#5 data structure using PBES2 for encryption and PBMAC1 for the
 *  integrity check. The PBES2 encryption operation is used to define the
 *  data encryption that is based on AES. The AES key is created from the
 *  PBKDF2 function that uses a password and a salt value. The data processing
 *  is executed according to the PKCS#5 standard and the encrypted output data
 *  is enwraped in a PKCS#5-PBES2 structure that defines the parameters used
 *  to perform the encryption. The PBMAC1 operation is used to add an
 *  integrity check value to the end of the data that includes the PBES2 and
 *  PBMAC1 headers and the encrypted data.
 *  The salt value should have random character (e.g. output of a hash function).
 *  Input data must not already be padded to the required block size !
 *
 *
 *  @param[in]     adsp_pkcs5_params         This pointer to a dsd_stru_pkcs5_pbes_params structure
 *                                           defines all the input elements, such as input data array,
 *                                           iteration count, salt value and algorithms.
 *  @param[inout]  aucp_output_buf           This is the destination buffer address the data are
 *                                           written to.
 *  @param[in]     szp_output_buf_size       This parameter defines the available space in bytes
 *                                           where the data are to be written.
 *  @param[out]    aszp_used_output_length   This parameter is used to return the number of bytes
 *                                           that are actually written to the destination buffer.
 *
 *  @return        state of processing
 *  <br>             == 0 ok
 *  <br>             != 0 error condition
 */
extern int m_create_pkcs5_aes_pbes2_pbmac1(dsd_stru_pkcs5_pbes_params * adsp_pbes_params,
                                           unsigned char * achp_output_buf,
                                           size_t szp_output_buf_size,
                                           size_t * aszp_used_output_length);

/**
 *  Subroutine m_read_pkcs5_aes_pbes2_pbmac1 reads a PKCS#5 data structure and decrypts
 *  the containing data using PBES2, does a integrity check using PBMAC1 and compares it
 *  with the received hmac.
 *  <p><b>Attention:</b> After successful execution the dereferenced pointer of 
 *  <code>aachp_decrypted_data_buf</code> is an in-place pointer pointing to a part 
 *  of the passed <code>aucp_src_buf</code> pointer.</p>
 *
 *  @param[in]      aucp_src_buf                Source buffer pointer before reading.
 *  @param[in]      szp_src_len                 Length of source buffer.
 *  @param[in]      achp_pwd_buf                Password buffer pointer.
 *  @param[in]      achp_pwd_len                Length of password buffer.
 *  @param[out]     aachp_decrypted_data_buf    Decrypted data buffer pointer.
 *  @param[out]     aszp_decrypted_data_len     Length of decrypted data buffer.
 *  @param[out]     aszp_bytes_read             Number of bytes read
 
 *  @return         <code>PKCS5_OP_OK</code> on success, error code otherwise.
 */
extern int m_read_pkcs5_aes_pbes2_pbmac1(unsigned char* aucp_src_buf,
                                         size_t szp_src_len,
                                         char* achp_pwd_buf,
                                         size_t szp_pwd_len,
                                         char** aachp_decrypted_data_buf,
                                         size_t* aszp_decrypted_data_len,
                                         size_t* aszp_bytes_read);

/**
 *  Subroutine m_get_pkcs5_package_len calculates the required size of buffer space
 *  to write a PKCS#5 password-based AES-encrypted and HMAC-secured package to a buffer.
 *
 *  @param[in]   adsp_pkcs5_params     This pointer to a dsd_stru_pkcs5_pbes_params structure 
 *                                     defines all the input elements, such as input data array, 
 *                                     iteration count, salt value and algorithms.
 *
 *  @return      Required size of buffer space that contains the transport data.
 */
extern size_t m_get_pkcs5_package_len(dsd_stru_pkcs5_pbes_params* adsp_pkcs5_params);

/** @} */
//-----------------------------------------------------------------------------
// ASN1 processing
//-----------------------------------------------------------------------------
/** @addtogroup asn1 
@{
*/

//-----------------------------------------------------------------
// Processing Flag definitions for Certificate/Tree processing etc.
//-----------------------------------------------------------------
#define	ASN1_PROCFL_DONT_SORT_BIT	0x01	// do NOT sort RDNs
#define	ASN1_PROCFL_PROCESS_EXT_BIT	0x02	// process X509 Extensions
#define	ASN1_PROCFL_IGNORE_CRIT_EXT_BIT	0x04	// ignore unknown Critical Ext.
#define	ASN1_PROCFL_IGNORE_EXT_ERR_BIT	0x08	// ignore X509 Extension errors


typedef struct IDATA_t IDATA;
typedef struct IDATPARR_t IDATPARR;
typedef struct X501_DN_t X501_DN;
typedef struct X509CERT_t X509CERT;
typedef struct CTREESTR_t CTREESTR;
typedef struct HCERWTXT_t HCERWTXT;
/**
* This structure is a basic data buffer with offset and length.
*/
typedef struct IDATA_t {
  char* Base;				//!< Array base
  int	  Off;				//!< Offset to start
  int 	  Len;				//!< Length of data
} IDATA;

/**
* This structure is a container for <code>IDATA</code> elements.
*/
typedef struct IDATPARR_t {
  int		Cnt;			//!< Number of entries
  int		Flags;			//!< Bit 0: 1 must free entries
                        //!< Bit 1: 1 clear entries before free
  IDATA**	ppArr;			//!< Array pointer
} IDATPARR;

/**
* This structure is a container of <code>IDATPARR</code> structures, which
* represent the elements of a distinguished name.
*/
typedef struct X501_DN_t {
  int		Cnt;			//!< Number of RDN elements
  int		Flags;			//!< Reserved
  IDATPARR**	ppArr;			//!< Array pointer
} X501_DN;

/**
* This structure is the internal representation of a X.509 certificate.
*/
typedef struct X509CERT_t {
  IDATPARR*	Certificate;		//!< The certificate in full size
  IDATPARR*	TBS_Certificate;	//!< The portion to be signed
  IDATPARR*	CertSignature;		//!< (Algor/paras/)signat data, no hdr
  IDATPARR*	Version;		//!< Version number,	no header
  IDATPARR*	SerialNumber;		//!< Serial number,	no header
  IDATPARR*	IssuerNameOcsp;		//!< Issuer, full field, OCSP
  X501_DN*	Issuer;			//!< Issuer, sorted RDN-Chain
  IDATPARR*	NotBefore;		//!< Time, with header
  IDATPARR*	NotAfter;		//!< Time, with header
  X501_DN*	Subject;		//!< Subject, sorted RDN-chain no header
  IDATPARR*	SubjectNameOcsp;	//!< Subject, full field, OCSP
  IDATPARR*	SubjPubKeyParVal;	//!< (Algor/)param(s)/value(s) no header
  IDATPARR*	PubKeyValueOcsp;	//!< Value of public key, no header, OCSP
  IDATPARR*	IssuerUniqueID;		//!< Issuer unique ID,	no header
  IDATPARR*	SubjectUniqueID;	//!< Subject unique ID,	no header
  IDATPARR*	Extensions;		//!< Extensions with headers

  IDATPARR*	AuthorityKeyID;		//!< Authority key identifier with header
  IDATPARR*	SubjectKeyID;		//!< Subject key identifier with header
  IDATPARR*	KeyUsage;		//!< Key usage no header
  IDATPARR*	CertPolicies;		//!< Certificate policies with header
  IDATPARR*	SubjAltName;		//!< Subject altern. name with header
  IDATPARR*	IssuerAltName;		//!< Issuer altern. name with header
  IDATPARR*	BasicConstraints;	//!< Basic constraints no headers
  IDATPARR*	NameConstraints;	//!< Name constraints with header
  IDATPARR*	PolicyConstraints;	//!< Policy constraints	no headers
  IDATPARR*	ExtendedKeyUsage;	//!< Extended key usage	with headers
  IDATPARR*	CrlDistPoints;		//!< CRL distr. points with headers

  IDATPARR*	PrivKeyData;		//!< Decrypted priv. key data, COPY !
  int	PrivKeyUsageFlags;		//!< Private key usage

  int	VersionNumber;			//!< Decoded cert. version, 0,1 or 2
  int	SignatAlgor;			//!< Type of signature algorithm
  int	SignatType;			//!< Type of signature
  int	PublicKeyType;			//!< Type of public key
  int	PublicKeyPurpose;		//!< Purpose of public key
  int	PrivKeyType;			//!< Type of private key
  int* pNotBeforeTimeArray;		//!< Decoded not before time
  int* pNotAfterTimeArray;		//!< Decoded not after time
  int	DateTimeValidity;		//!< State of date/time validity
  int	Flags;				//!< Is root/trusted/CA/has key
  int	ContFlags;			//!< Flags from IBM Container (if any)

  int	ExtPresFlags;			//!< Extensions present
  int	KeyUsageFlags;			//!< Key usage flags
  int	ExtKeyUsageFlags;		//!< Extended key usage flags
  int	PkixKeyPurposeFlags;		//!< PKIX key purpose flags
  int	BasicConstrCAMode;		//!< CA type mode / critical flag
  int	BasicConstrPathLen;		//!< Path length

} X509CERT;

/**
* Frees all entries of an <code>IDATA</code> element array and the array itself (FreeIDATA_Array).
* Frees the buffer in the elements, if requested and clears it before the free,
* if requested. Clear is only checked, if free is requested.
*
*  @param DatArray Array base
*  @param ElementCount Length of array
*  @param FreeFlags Flag for buffer element free/clear <br>
*                       Bit 0 : 1 for buffer free <br>
*                       Bit 1 : 1 for buffer clear
*/
extern void FreeIDATA_Array(HMEM_CTX_DEF
                            IDATA* DatArray[],
                            int ElementCount,
                            int FreeFlag);

/**
* Allocates an array of empty <code>IDATA</code> structure elements of given count and the
* structures themself (AllocIDATA_Array).
*
*  @param pDatArray Return pointer for the new array
*  @param ElementCount Number of elements requested
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int AllocIDATA_Array(HMEM_CTX_DEF
                            IDATA** DatArray[],
                            int ElementCount);

/**
* Frees an <code>IDATPARR</code> structure and its content (FreeIDATPARR_Struc).
*
* The buffers in the <code>IDATA</code> entries are only freed, if the flags
* in the <code>IDATPARR</code> are set.
*
*  @param DatArrayDesc Pointer to <code>IDATPARR</code> to be freed
*/
extern void FreeIDATPARR_Struc(HMEM_CTX_DEF
                               IDATPARR* DatArrayDesc);

/**
* Allocates an <code>IDATPARR</code> structure with the requested number of 
* <code>IDATA</code> entries (AllocIDATPARR_Struc).
*
* The elements are empty.
*
*  @param pDatArrayDesc Return pointer for the <code>IDATPARR</code> structure
*  @param ElementCount Number of elements requested
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int AllocIDATPARR_Struc(HMEM_CTX_DEF
                               IDATPARR* pDatArrayDesc[],
                               int ElementCount);

/**
* Assures, than an <code>IDATPARR</code> structure has at least 
* the requested number of elements (EnlargeIDATPARR_Struc).
* Allocates new elements, as needed. New elements are 
* empty. Old elements will not be modified.
*
*  @param DatArrayDesc Target structure
*  @param NewElementCount Minimum number of elements requested
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int EnlargeIDATPARR_Struc(HMEM_CTX_DEF
                                      IDATPARR* DatArrayDesc,
                                      int NewElementCount);

/**
* Frees an X501 names <code>IDATPARR</code> structure and the RDN (aka  
* <code>IDATPARR</code>) elements, if marked as freeable (FreeX501DN_Struc).
*
* Marking is done by flags in the respective structures.
*
*  @param pNameStruc Target structure
*/
extern void FreeX501DN_Struc(HMEM_CTX_DEF
                             X501_DN* pNameStruc);

/**
* Allocates an X501 name structure for the RDNs and their entries (AllocX501DN_Struc).
* For each RDN Element an  <code>IDATPARR</code> structure with/without 
* <code>IDATA</code> elements will be allocated, if required.
*
*  @param RDNCount Number of RDN elements requested
*  @param ElementCnt Number of <code>IDATPARR</code> elements/entry
*  @param AllocFlag 0 - do not allocate <code>IDATPARR</code>s
*  @param FreeFlag 0 - do not mark as freeable
*  @return Pointer to the new structure, NULL on failure
*/
extern X501_DN* AllocX501DN_Struc(HMEM_CTX_DEF
                                  int RDNCount,
                                  int ElementCnt,
                                  int AllocFlag,
                                  int FreeFlag);

/**
* Stores a <code>WLARGENUM</code> in an <code>IDATPARR</code> structure (FromLnumToArrayDescElement).
* Converts the number to binary format and stores the new buffer in the element
* at the specified index, replacing any data there. The element must be marked
* as freeable.
*
* Makes a deep copy of the data.
*
*  @param DatArrayDesc Pointer to destination structure
*  @param Index Index to use
*  @param lplnum Large number to store
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromLnumToArrayDescElement(HMEM_CTX_DEF
                                      IDATPARR* DatArrayDesc,
                                      int Index,
                                      WLARGENUM*(lnum));

/**
* Extracts the array pointer, offset and length from the <code>IDATA</code>
* element at the given index (FromDatArrayToBuf).
*
* Doesn't copy.
*
*  @param DatArray Pointer to array of <code>IDATA</code>
*  @param Index Index of entry to read
*  @param Base Return pointer for array base
*  @param Offset Return pointer for offset
*  @param Length Return pointer for data length
*/
extern void FromDatArrayToBuf(IDATA** DatArray,
                              int Index,
                              char* Base [],
                              int Offset[], 
                              int Length[]);

/**
* Writes the array pointer, offset and length to the <code>IDATA</code>
* element at the given index (FromBufToDatArray).
* When direct store is requested, stores the given array pointer, overwriting
* the old pointer without freeing it. In copy mode, generates a deep copy and
* frees the old data array.
*
*  @param DatArray Pointer to array of <code>IDATA</code>
*  @param Index Index of entry to write to
*  @param SrcBuf Pointer to the array to be written
*  @param SrcOffset Offset to be written
*  @param SrcLen Length of data to be written
*  @param Mode == 0 direct store <br>
*               != 0 make copy of buffer
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromBufToDatArray(HMEM_CTX_DEF
                             IDATA** DatArray,
                             int Index,
                             char SrcBuf[],
                             int SrcOffset,
                             int SrcLen,
                             int Mode);

/**
* Writes the array pointer, offset, length from a <code>IDATA</code>
* element to explicit pointer variables (FromDescToBuf). 
*
*  @param ArrayDesc Pointer to source structure
*  @param Index Index of entry to read from
*  @param Pointer to a Base Array that is filled with the data
*  @param Offset Offset pointer that is set to the startoffset in ArrayDesc
*  @param Length Length pointer that is set to the length of data in ArrayDesc 
*/
extern void FromDescToBuf(IDATPARR* ArrayDesc,
                          int Index, char** Base,
                          int* Offset, int* Length);

/**
* Writes the array pointer, offset, length and flags to the <code>IDATA</code>
* element at the given index (FromBufToDesc). 
* If NULL is used as array pointer, nothing is 
* done. Allocates <code>IDATPARR</code> and the array of <code>IDATA</code>
* elements, if needed. Reports an error, if the <code>IDATA</code> array has
* to few elements.
*
* Overwrites the data in the target element, without freeing the target elements
* buffer.
*
*  @param Base Array pointer to be written
*  @param Offset Offset to be written
*  @param Length Length to be written
*  @param Index Index of entry to write to
*  @param FreeFlag Flag to set
*  @param pArrayDesc Pointer to target structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromBufToDesc(HMEM_CTX_DEF
                         char Base[], 
                         int Offset,
                         int Length,
                         int Index,
                         int FreeFlag,
                         IDATPARR** pArrayDesc);

/**
* Extracts the array pointer, offset and length from the <code>IDATA</code>
* element at the given index (FromDescToBuf).
*
* Doesn't copy.
*
*  @param ArrayDesc Structure holding the data array to be read
*  @param Index Index of entry to read
*  @param Base Return pointer for array base
*  @param Offset Return pointer for offset
*  @param Length Return pointer for data length
*/
extern void FromDescToBuf(IDATPARR* ArrayDesc,
                          int Index,
                          char* Base [],
                          int Offset[], 
                          int Length[]);

/**
* Shallow copies content of one <code>IDATA</code> element to another (CopyIdataContents).
*
*  @param DstStruc Destination element
*  @param SrcStruc Source element
*/
extern void CopyIdataContents(IDATA* DstStruc,
                              IDATA* SrcStruc);

/**
* Replaces all buffers in the elements of an <code>IDATPARR</code> with deep 
* copies of their content (CopyToLocalDatArrayDesc). Offset of the copies will be 0. Old buffers will 
* NOT be freed.
*
*  @param DatArrayDesc Structure to be transformed to a deep copy
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CopyToLocalDatArrayDesc(HMEM_CTX_DEF
                                   IDATPARR* DatArrayDesc);

/**
* Copies the content of a range of <code>IDATA</code> elements from one 
* array to another (AllocCopyDatArrayElements).
* Frees the buffers in the destination array only, if a deep copy is requested.
*
*  @param SrcDatArray Source array base
*  @param SrcIndex Starting source index
*  @param DstDatArray Dest. array base
*  @param DstIndex Starting destination index
*  @param ElementCnt Number of elements to copy
*  @param CopyMode == 0 shallow copy <br>
*               != 0 deep copy
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int AllocCopyDatArrayElements(HMEM_CTX_DEF
                                     IDATA* SrcDatArray[], 
                                     int SrcIndex,
                                     IDATA* DstDatArray[], 
                                     int DstIndex,
                                     int ElementCnt, 
                                     int CopyMode);

/**
* Copies the content of a range of <code>IDATA</code> elements from one 
* <code>IDATPARR</code> structure to another (AllocCopyDatArrayToDatArray).
* Frees the buffers in the destination array only, if a deep copy is requested.
*
*  @param SrcDatArrayDesc Source structure
*  @param SrcIndex Starting source index
*  @param DstDatArrayDesc Destination structure
*  @param DstIndex Starting destination index
*  @param ElementCnt Number of elements to copy
*  @param CopyMode == 0 shallow copy
*               != 0 deep copy
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int AllocCopyDatArrayToDatArray(HMEM_CTX_DEF
                                       IDATPARR* SrcDatArrayDesc, 
                                       int SrcIndex,
                                       IDATPARR* DstDatArrayDesc,
                                       int DstIndex,
                                       int ElementCnt,
                                       int CopyMode);


extern int FromArrayDescToRSAPubParams(HMEM_CTX_DEF
		                               IDATPARR* PubParValsDesc,
                                       RSA_STRUC** pRsaStruc);

extern int FromArrayDescToDSAPubParams(HMEM_CTX_DEF
                                       IDATPARR* PubParValsDesc, 
                                       DSA_STRUC** pDsaStruc);

extern int FromArrayDescToDHPubParams(HMEM_CTX_DEF
                                      IDATPARR* PubParValsDesc,
                                      DH_STRUC** pDhStruc);

extern int FromDHPubParamsToArrayDesc(HMEM_CTX_DEF
                                      DH_STRUC* DhStruc,
                                      IDATPARR** pPubParValsDesc);

extern int FromArrayDescToRSAPrivParams(HMEM_CTX_DEF
                                        IDATPARR* PrivParValsDesc,
                                        RSA_STRUC** pRsaStruc);

extern int FromArrayDescToRSAPrivParams(HMEM_CTX_DEF
                                        IDATPARR* PrivParValsDesc,
                                        RSA_STRUC** pRsaStruc);

extern int FromArrayDescToDSAPrivParams(HMEM_CTX_DEF
                                        IDATPARR* PrivParValsDesc,
                                        DSA_STRUC** pDsaStruc);

extern int FromArrayDescToDHPrivParams(HMEM_CTX_DEF
                                       IDATPARR* PrivParValsDesc,
                                       DH_STRUC** pDhStruc);


/**
* Writes an ASN.1 length field of up to 3 bytes (GenASN1_LenField).
* The destination must be large enough. Max len = 65535.
*
*  @param DstBuf Pointer to buffer base
*  @param DstOff Start offset for writing
*  @param DataLen Length to convert
*
*  @return Bytes written, <0 on error
*/
extern int GenASN1_LenField(char DstBuf[],
                            int DstOff,
                            int DataLen);

/**
* Decodes ASN.1 length field (DecodeASN1_LenField).
* Length value is limited to 0..65535 (16bit).
*
*  @param SrcBuf Pointer to source buffer base
*  @param SrcOff Start of data
*  @param SrcLen Length of available data
*  @param DataLen Return pointer for length value, in case of indefinite -> -1
*
*  @return Bytes read, <0 on error:
* <br>            -1 : indefinite length
* <br>            -2 : too few data
* <br>            -3 : length field too large
*/
extern int DecodeASN1_LenField(char SrcBuf[], 
                               int SrcOff,
                               int SrcLen, 
                               int DataLen[]);

/**
* Subroutine GetUCS4Char fetches/converts to UCS-4 Character from
* a given Character Cell sized string (GetUCS4Char).
*
*  @param StrData *               Array base
*  @param StrOffset *               Offset to Start
*  @param StrLen *               Length of data in bytes
*  @param StrCellSize *               1, 2, 4 and 0 (variable)
*  @param Char *               Character
*
*  @return int Charactersize == 0 - End of String
* <br>            < 0 - Not enough data/Error
* <br>            > 0 - size in bytes
*/

extern int GetUCS4Char(char StrData[],
                       int StrOffset,
                       int StrLen, 
                       int StrCellSize, 
                       int Char[]);

/**
* Writes structure of an ASN.1 datastream into an array of <code>IDATA</code>
* elements (FromASN1). 
* The basic description of the structure is given by a control
* structure array.
*
* Does not generate copies of the input data. DatArray must contain enough
* elements.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param CtlArray Base of control structure
*  @param EntryCnt number of entries in control structure
*  @param DatArray Array to be loaded with
*               data elements
*  @param DatArrayIndex First index to use
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1(HMEM_CTX_DEF
                    char InpBuf[],
                    int InpOffset, 
                    int InpLen,
                    char * CtlArray, 
                    int EntryCnt,
                    IDATA* DatArray[],
                    int DatArrayIndex);

/**
* Generates data structures in internal
* notation ('Data Elements') from given ASN.1 encoded IBM container
* input byte stream (FromASN1_IBMContainer). 
* The IBM container is split into: <ol>
* <li>   Container relativ Index number
* <li>	Container content/subfields (type from TAG)
* <li>   Container name
* <li>   Container flags
* <li>   Container unknown (seq.)
*</ol>
* The content of the container is further split according to the
* explicit tag: <ul>
* <li> [0] Certificate request container: <ol>
*       <li> X509 certificate request
*	 <li> PKCS5 PrivateKeyInfo </ol>
* <li> [1] Standard certificate:
*	 X509 certificate
* <li> [2] Certificate with private key: <ol>
*       <li> X509 certificate
*	 <li> PKCS5 PrivateKeyInfo </ol>
* </ul>
* This is used for server certificate processing.
* 
* No copy of the input datastream is made.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pDatArrayDesc Pointer to return the generated structure
*  @param DatArraySize Pointer to return the number of elements generated
*  @param SubErrCode Error from higher parser
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_IBMContainer(HMEM_CTX_DEF
                                 char InpBuf[],
                                 int InpOffset,
                                 int InpLen,
                                 IDATPARR* pDatArrayDesc[], 
                                 int DatArraySize[],
                                 int SubErrCode[]);

/**
* Generates data structures in internal
* notation ('Data Elements') from given ASN.1 encoded certificate
* input byte stream (FromASN1_Cert). 
* The certificate is split into: <ol>
* <li> TBS certificate
* <li> Signature algor ID
* <li> Signature algor params (not further parsed)
* <li> Signature
* </ol>
* This is used for certificate verification and as pre-parser
* for the TBS certificate.
*
* No copy of the input datastream is made.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pDatArrayDesc Array descriptor loaded with
*               data elements
*  @param DatArraySize Number of elements loaded
*  @param SubErrCode Error from higher parser
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_Cert(HMEM_CTX_DEF
                         char InpBuf[], 
                         int InpOffset,
                         int InpLen,
                         IDATPARR** pDatArray,
                         int DatArraySize[],
                         int SubErrCode[]);

/**
* Generates data structures in internal
* notation ('Data Elements') from given ASN.1 encoded 'To Be Signed'
* certificate input byte stream (FromASN1_TBS_Cert). 
* The certificate is split into: <ol>
* <li> Version		      	    (OPTIONAL)	Must be further processed
* <li> Serial number
* <li> Signature algor ID
* <li> Signature algor params	    (ANY)	Must be parsed further
* <li> Issuer RDN substring	    (OPTIONAL)
* <li> Validity: Not before	    (ANY)	Must be UTC or Genealized Time
* <li> Validity: Not after	    (ANY)	dto.
* <li> Subject RDN substring	    (OPTIONAL)  Must be parsed further
* <li> Subj.PublInfo: Algor ID 
* <li> Subj.PublInfo: Algor params  (ANY)
* <li> Subj.PublInfo: PublValue			Must be parsed further
* <li> IssuerUniqueID		    (BITSTRING, OPTIONAL)
* <li> SubjectUniqueID		    (BITSTRING, OPTIONAL)
* <li> Extensions substring	    (OPTIONAL)	Must be processed further
* </ol>
* This is used for certificate verification, matching and as pre-parser
* for the RDN-fields, algor params and extensions.
*
* Does not copy input data.     
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pDatArrayDesc Pointer for placing generated structure
*  @param DatArraySize Number of elements generated
*  @param SubErrCode Error from higher parser
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_TBS_Cert(HMEM_CTX_DEF
                             char InpBuf[],
                             int InpOffset,
                             int InpLen,
                             IDATPARR** pDatArray,
                             int DatArraySize[],
                             int SubErrCode[]);

/**
* Generates data structures in internal
* notation from given ASN.1 encoded distinguished name
* input byte stream (FromASN1_DN).
* 
* Does not copy source data.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param ppDnNameDesc Structure loaded with DN
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_DN(HMEM_CTX_DEF
                       char InpBuf[],
                       int InpOffset,
                       int InpLen,
                       X501_DN* ppDnNameDesc[]);

/**
* Generates data structures in internal
* notation ('Data Elements') from given ASN.1 encoded extensions
* substring input byte stream (FromASN1_EXT). 
* The entries must be of same type
* (SEQUENCE).
*
* Does not copy input data.     
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pDatArrayDesc Pointer for generated structure
*  @param DatArraySize Number of elements generated
*  @param SubErrCode Error code from higher level
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_EXT(HMEM_CTX_DEF
                        char InpBuf[], 
                        int InpOffset,
                        int InpLen,
                        IDATPARR* pDatArrayDesc[],
                        int DatArraySize[],
                        int SubErrCode[]);

/**
* Unwraps data structure in internal
* notation ('Data Elements') from given ASN.1 sequence (FromASN1_Sequence).
* 
* This is used for server RDN-List processing.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pDstOff Starting offset of data
*  @param pDstLen Length of data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_Sequence(HMEM_CTX_DEF
                             char InpBuf[],
                             int InpOffset,
                             int InpLen, 
                             int pDstOff[], 
                             int pDstLen[]);

/**
* Wraps given buffer to desired ASN.1
* encoded sequence (ToASN1_Sequence).
* 
* This is used for server RDN-List generation.
*
* The output buffer contains a deep copy of the input data.
*      
*  @param InpBuf Buffer with data
*  @param InpOffset Start ofd data
*  @param InpLen Length of data
*  @param pDstBuf Pointer for generated ASN.1 datastream
*  @param DstLen Length of generated data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToASN1_Sequence(HMEM_CTX_DEF
                           char InpBuf[], 
                           int InpOffset,
                           int InpLen,
                           char* pDstBuf[],
                           int DstLen[]);

/**
* Generates ASN.1 representation of a
* DN (distinguished name) from internal structures (ToASN1_DN).
*
* Generates a deep copy.     
*
*  @param pNameDesc RDN elements structure
*  @param ppDstBuf Generated ASN.1 stream
*  @param pDstLen Size of generated stream
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToASN1_DN(HMEM_CTX_DEF
                     X501_DN* pNameDesc,
                     char* ppDstBuf[],
                     int pDstLen[]);

/**
* Generates the ordinal number key element and puts in the descriptor array slot (SetIBMContainerOrdinal).
*
* The needed buffer will be allocated.
*
*  @param DatArray Array for data elements
*  @param IndexOffset Start index to add to base
*  @param OrdinalNum Number to set, > 0 !
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SetIBMContainerOrdinal(HMEM_CTX_DEF
                                  IDATA* DatArray[],
                                  int IndexOffset, 
                                  int OrdinalNum);

/**
* Puts certificate/certificate request key element to the descriptor array slot (SetIBMContainerCertOrReq).
*
* Makes a deep copy of the data and delets old data in the destination.
*
*  @param DatArray Array for data elements
*  @param IndexOffset Start index to add to base
*  @param SrcBuf Base of source buffer
*  @param SrcOff Start of data
*  @param SrcLen Length of data
*  @param Type 0 - Certificate Request <br>
*               1 - Certificate w.o. key <br>
*               2 - Certificate with key
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SetIBMContainerCertOrReq(HMEM_CTX_DEF
                                    IDATA* DatArray[],
                                    int IndexOffset,
                                    char SrcBuf[],
                                    int SrcOff,
                                    int SrcLen,
                                    int Type);

/**
* Generates the name key element and puts it in the descriptor array slot (SetIBMContainerName).
*
* Makes a deep copy of the data and delets old data in the destination.
*
*  @param DatArray Array for data elements
*  @param IndexOffset Start index to add to base
*  @param ContainerName Base of source name
*  @param ContainerNameLen Length of name
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SetIBMContainerName(HMEM_CTX_DEF
                               IDATA* DatArray[],
                               int IndexOffset, 
                               char ContainerName[],
                               int ContainerNameLen);

/**
* Converts 32 bit unsigned flag bits to an ASN.1 bitstring (BIT32FlagsToBitBuf).
*
* The bitstring will be newly allocated.
*
*  @param Flags Element to convert
*  @param UsedBits Number of bits used (from LSB)
*  @param pDstBuf Pointer for generated bitstring
*  @param pDstLen Length of generated data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BIT32FlagsToBitBuf(HMEM_CTX_DEF
                              int Flags,
                              int UsedBits,
                              char* pDstBuf[], 
                              int pDstLen[]);

/**
* Generates the flags key element and puts in the descriptor array slot (SetIBMContainerFlags).
*
* Allocates the needed buffer, but doesn't free the old ones.
*
*  @param DatArray Array for data elements
*  @param IndexOffset Start index to add to base
*  @param Flags Flags to put
*  @param UsedBits Number of bits used (from LSB)
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SetIBMContainerFlags(HMEM_CTX_DEF
                                IDATA* DatArray[],
                                int IndexOffset,
                                int Flags,
                                int UsedBits);

/**
* Generates IBM container from given container data array, frees the data array
* (even in case of error) (ToIBMContainer).
*
* The generated container is put to a newly allocated buffer.
*
*  @param DatArrayDesc Array of data elements
*  @param pDstBuf Pointer for generated container data
*  @param pDstLen Length of generated data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToIBMContainer(HMEM_CTX_DEF
                          IDATPARR* DatArrayDesc,
                          char* pDstBuf[],
                          int pDstLen[]);

/**
* Generates standard certificate container without private key (used for 
* external certificates) (GenIbmStdContainer).
*
* Container made from the following elements: <ol>
* <li> Ordinal number.
* <li> ASN.1 encoded certificate.
* <li> Container name.
* <li> Flags.
* </ol>
*
* The buffer for the container will be newly allocated.
*
*  @param SrcBuf Buffer with cert./cert. request
*  @param SrcOff Start of source data
*  @param SrcLen Data length
*  @param OrdinalNumber Ordinal number to use
*  @param ContainerName Name to use
*  @param ContNameLen Length of name
*  @param Flags Flags to set
*  @param UsedBits Used flagbits
*  @param pDstBuf Pointer for the generated container
*  @param pDstLen Length of the generated container
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GenIbmStdContainer(HMEM_CTX_DEF
                              char SrcBuf[], 
                              int SrcOff,
                              int SrcLen,
                              int OrdinalNumber,
                              char ContainerName[], 
                              int ContNameLen, 
                              int Flags,
                              int UsedBits,
                              char* pDstBuf[], 
                              int pDstLen[]);

/**
* Fills the destination array with  OBJID, an ASN.1 NULL
* element and a single signature value (SetSignatAlgAndData). 
*
* Makes deep copy of data. Frees old data buffers.
*
* Only the first element of the source array will be copied.
*
* NOTE: No checks done on input params.
*      
*
*  @param DatArray Destination array
*  @param IndexOffset Destination index to use
*  @param SrcArray Data array with signature data
*  @param ElementCnt Number of elements in array
*  @param SignatTypeAlgor Type of signature
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SetSignatAlgAndData(HMEM_CTX_DEF
                               IDATA* DatArray[],
                               int IndexOffset, 
                               IDATA* SrcArray[],
                               int ElementCnt,
                               int SignatTypeAlgor);

/**
* Generates signature for message to be signed (SignTBSData).
*
* Destination buffer will be allocated.
*
*  @param pMsgBuf Buffer with message
*  @param MsgOff Start of data in buffer
*  @param MsgLen Size of message
*  @param RsaStruc RSA structure. Optional
*  @param DsaStruc DSA structure. Optional
*  @param SignatTypeAlgor Type of signature
*  @param pDstBuf Return pointer for signature data
*  @param pDstLen Size of signature
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SignTBSData(HMEM_CTX_DEF
                       char pMsgBuf[], 
                       int MsgOff, 
                       int MsgLen,
                       RSA_STRUC* RsaStruc,
                       DSA_STRUC* DsaStruc,
                       int SignatTypeAlgor, 
                       char* pDstBuf[], 
                       int pDstLen[]);

/**
* Converts ASN.1 strings into internal representation (BIGwords with leading
* ElementCount) (FromASN1_String).
* 
* Supported ASN.1 types are: <ul>
* <li> UCS1 (1 Byte)<ul><li> T61 STRING (TELETEX STRING)
*		        <li> PRINTABLE STRING
*				  <li> VISIBLE STRING
*				  <li> IA5 STRING
*				  <li> NUMERIC STRING </ul>
* <li> UCS2 (2 Byte)<ul><li> BMP STRING </ul>
* <li> UCS4 (4 Byte)<ul><li> UNIVERSAL STRING </ul>
* <li> UCS0 (var. Bytes)<ul><li> UTF8 STRING </ul>
*</ul>
* The generated string is put to a newly allocated buffer.
* If elements do not fit into the internal format they are
* replaced with ASCII hyphen ('-').
* NOTE: Number of string elements is limited to 10000.
*      
*  @param SrcBuf Base of SrcBuf
*  @param SrcOff Start of source data
*  @param SrcLen Length of source data
*  @param ppDstBuf Pointer for generated string
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_String(HMEM_CTX_DEF
                           char SrcBuf[],
                           int SrcOff,
                           int SrcLen, 
                           char* pDstBuf[]);

/**
* Generates data structures in internal
* notation ('Data Elements') from given ASN.1 encoded substring
* input byte stream (FromASN1_SubStr). 
* The substrings must be of same type.
* This is used for RDN's, validity and extensions.
*
* Does not copy input data.     
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param CtlArray Control structure for 1 entry
*  @param EntryCnt Number of control entries
*  @param DatEntryCnt Number of data entries per ctl
*  @param pDatArrayDesc Pointer for generated structure
*  @param DatArraySize Number of elements generated
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_SubStr(HMEM_CTX_DEF
                           char InpBuf[],
                           int InpOffset,
                           int InpLen,
                           char * CtlArray,
                           int EntryCnt,
                           int DatEntryCnt, 
                           IDATPARR* pDatArrayDesc[],
                           int DatArraySize[]);

/**
* Converts ASN.1 bitstring to 32 bit unsigned flag bits (BitBuftoBIT32Flagsf).
*
*  @param SrcBuf Buffer base
*  @param SrcOff Start of data
*  @param SrcLen Length of data in buffer
*  @param pFlags Generated falg bits
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BitBuftoBIT32Flagsf(char SrcBuf[],
                               int SrcOff,
                               int SrcLen,
                               int pFlags[]);

/**
* Converts an ASN.1 encoded integer to a 32 bit unsigned number byte string (ByteBufToUnsignedBIT32Num). 
* Leading zero byte is ignored.
*
*  @param pSrcBuf Buffer base
*  @param SrcOff Start of data
*  @param SrcLen Length of data
*  @param pValue Return pointer for integer value
*  @return int Status 0 - o.k., else error occurred
*/
extern int ByteBufToUnsignedBIT32Num(char SrcBuf[],
                                     int SrcOff,
                                     int SrcLen, 
                                     int pNumber[]);

/**
* Converts a 32 bit unsigned number to a byte string in network order (UnsignedBIT32NumToByteBuf). 
* If leading byte is >= 0x80 inserts a zero. The byte string will be
* newly allocated. 
*
*  @param Number Element to convert
*  @param pDstBuf Allocated Buffer
*  @param pDstLen Length of data in buffer
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int UnsignedBIT32NumToByteBuf(HMEM_CTX_DEF
                                     int Number,
                                     char* pDstBuf[],
                                     int pDstLen[]);

/**
* Gets max. 32 bits from ASN1 BITSTRING, output the data MSB aligned (GetBit32MsbBitsFromBitstring).
*
* NOTE: No parameters checked
*      
*
*  @param pBuf Data buffer
*  @param Offset Start of data
*  @param Len Length of data
*  @param MaxBitCnt Maximum bits read
*  @param pBits Value read from bitstring
*  @return 0 on success, error code otherwise
*/
extern int GetBit32MsbBitsFromBitstring(char pBuf[],
                                        int Offset,
                                        int Len,
                                        int MaxBitCnt,
                                        int pBits[]);

/**
* Extracts data content from given ASN.1 type to internal notation 
* ('Data Elements') (FromASN1_Type).
* 
* No data will be copied.
*
*  @param InpBuf ASN.1 datastream base
*  @param InpOffset Start of data
*  @param InpLen Length of data
*  @param pCtlArray Split control array
*  @param CtlElementCnt Number of control elements
*  @param DataElementCnt Number of data elements
*  @param BaseErrorCode Error code to use
*  @param ppDstDesc Pointer for generated structure
*  @param SubErrCode Error from higher parser. Optional
*
*  @return int Status - 0 if o.k., else Error occurred
*/
extern int FromASN1_Type(HMEM_CTX_DEF
                         char InpBuf[],
                         int InpOffset,
                         int InpLen,
                         char * pCtlArray, 
                         int CtlElementCnt,
                         int DataElementCnt,
                         int BaseErrorCode,
                         IDATPARR* ppDstDesc[],
                         int SubErrCode[]);

/**
* Extracts data content to internal notation ('Data Elements')
* from given descriptor index buffer (FromASN1_DescToDesc).
* 
* If the return pointer points to a structure, it will be freed.
* No data is copied.
*
*  @param pSrcDesc Source data descriptor
*  @param SrcIndex Number of slots to use
*  @param pCtlArray Split control array
*  @param CtlElementCnt Number of control elements
*  @param DataElementCnt Number of data elements
*  @param BaseErrorCode Error code to use
*  @param ppDstDesc Pointer for generated structure
*  @param SubErrCode Error from higher parser. Optional
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_DescToDesc(HMEM_CTX_DEF
                               IDATPARR* pSrcDesc,
                               int SrcIndex,
                               char * pCtlArray,
                               int CtlElementCnt,
                               int DataElementCnt, 
                               int BaseErrorCode,
                               IDATPARR* ppDstDesc[],
                               int SubErrCode[]);

/**
* Searches for an ASN1 ObjectID (without header) among the known X509 
* extension OIDs (GetX509Ext_OidIndex).
* If found, the OID's Index is returned. 
*
*  @param ObjID_Desc ObjID-Descriptor
*  @param pExt_OidIndex Index of OID, -1 if not found
*
*  @return ASN1_OP_OK on success, error code otherwise, else Error occurred
*/
extern int GetX509Ext_OidIndex(IDATA* ObjID_Desc,
                               int pExt_OidIndex[]);

/**
* Generates an ASN.1 datastream from given data structures
* in internal notation ('Data Elements') and given control
* structures (ToASN1). 
* The destination buffer is allocated by this subroutine.
*
* Makes a deep copy of the data.
*
*  @param DatArray Array loaded with
*               data according to
*               control structure
*  @param DatArrayIndex First index to use
*  @param CtlArray Base of control structure
*  @param EntryCnt Number of entries in
*               control structure
*  @param DstBuf Pointer for generated ASN.1 datastream
*  @param DataLen Pointer for length of ASN.1 stream
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToASN1(HMEM_CTX_DEF
                  IDATA* DatArray[],
                  int DatArrayIndex,
                  char * CtlArray,
                  int EntryCnt,
                  char** DstBuf, 
                  int DataLen[]);

/**
* Converts data structures in given
* internal notation ('Data Elements' array) to desired ASN.1
* encoded substring output byte stream (ToASN1_SubStr). 
* The substrings will be
* of same ASN.1 type. This is used for RDN's, validity and extensions.
*
* Output will contain a deep copy of the inputs content.
*
*  @param DatArray Array loaded with
*               data elements
*  @param DatArrayIndex First index to use
*  @param DatArrayCnt Number of elements loaded
*  @param CtlArray Control structure for 1 Entry
*  @param EntryCnt Number of control entries
*  @param DatEntryCnt Number of data entries per ctl
*  @param pDstBuf Pointer for storing the generated datastream
*  @param DstLen Length of data returned
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToASN1_SubStr(HMEM_CTX_DEF
                         IDATA* DatArray[],
                         int DatArrayIndex,
                         int DatArrayCnt,
                         char * CtlArray,
                         int EntryCnt,
                         int DatEntryCnt,
                         char* pDstBuf[], 
                         int DstLen[]);

/**
* Compares two given ASN.1 object IDs in internal data format (without type and
* length fields) (CmpASN1_ObjIDs).
*
* Both must be present.
* 
* Comparison steps:
* <ol>
* <li><ol><li> Compare length, if same, continue, if not: <br>
*      if length OBJID1 < length OBJID2 then OBJID1 < OBJID2, exit.
*   <li> if both length == 0 then OBKID1 == OBJID2, exit. </ol>
*
* <li> Compare component count, if same, continue, if not: <br>
*    if count OBJID1  < count OBJID2  then OBJID1 < OBJID2, exit <br>
*    else OBJID1 > OBJID2, exit.
*
* <li> Compare component sizes beginning from the first
*    component: <br>
*    if all same size continue, if not: <br>
*      if OBJID1 current component size < OBJID2 current component size
*        then OBJID1 < OBJID2, exit <br>
*      else OBJID1 > OBJID2, exit.
*
* <li> Compare component contents beginning from the first
*    component: <br>
*    if OBJID1 curr. component contents < OBJID2 curr. component contents
*      then OBJID1 < OBJID2, exit <br>
*    if OBJID1 curr. component contents > OBJID2 curr. component contents
*      then OBJID1 > OBJID2, exit <br>
*    if same components then goto next component <br>
* </ol>
*
*  @param ObjID1Desc Description of first ID
*  @param ObjID2Desc Description of second ID
*  @param Result Pointer to return result: <br>
*               ASN1_1ST_GT_2ND <br>
*               ASN1_1ST_EQ_2ND <br>
*               ASN1_1ST_LT_2ND
*
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            ASN1_TOO_MANY_OBJID_COMPONENTS
* <br>            ASN1_TOO_LARGE_OBJID_COMPONENT
* <br>            ASN1_MISFORMED_OBJID
*/
extern int CmpASN1_ObjIDs(IDATA* ObjID1Desc,
                          IDATA* ObjID2Desc,
                          int Result[]);

/**
* Compares 2 ASN1 values (of ANY type)
* in internal representation for same contents (CmpASN1_Values). 
* The ASN.1 headers
* for both are included in the representation.
*
* Comparison is done as follows: <ol>
* <li> Class not UNIVERSAL: Byte per byte match.
* <li> Class UNIVERSAL but constructed: Byte per byte match.
* <li> Class UNIVERSAL not constructed: <ol>
*    <li> Not supported types: Byte per byte match.
*    <li> Supported types: Individual matching rules,
*		  but only DER encoding matching used. <ol>
*       <li> Boolean: Zero / not zero
*       <li> Integer: Leading zero byte suppressed, then byte by byte
*	     <li> Bitstring: Byte per byte match
*	     <li> OctetString: Byte per byte match
*	     <li> NULL: Same match
*	     <li> ObjectID: See object ID compare subroutine
*	     <li> UTF8, BMP, UNIVERSAL STRING:
*		Contents match, case sensitive
*	     <li> PRINTABLE, TELETEX STRING:
*		Contents match, case insensitive
*	     <li> UTC STRING: special case
*	     <li> GENERALTIME STRING: special case
*</ol></ol></ol>
*  @param Value1 Descriptor value 1
*  @param Value2 Descriptor value 2
*  @param Result Result of compare
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CmpASN1_Values(IDATA* Value1,
                          IDATA* Value2,
                          int Result[]);

/**
* Compares two ASN.1 values on a byte per byte basis (MatchASN1ValuesByteByByte). 
* Only if same length and contents are verified, an equivalence match is reported.
*
*  @param Base1 Data base 1
*  @param InpOffset1 Start data 1
*  @param DataLen1 Length data 1
*  @param Base2 Data base 2
*  @param InpOffset2 Start data 2
*  @param DataLen2 Length data 2
*
*  @return ASN1_SAME / ASN1_NOT_SAME
*/
extern int  MatchASN1ValuesByteByByte(char Base1[],
                                      int InpOffset1,
                                      int DataLen1,
                                      char Base2[], 
                                      int InpOffset2,
                                      int DataLen2);

/**
* Sorts a given DistinguishedName (DN) according to the first found object-IDs
* of its RDN elements (SortASN1_DN).
*
* NOTE:<ol>
* <li> This should not be done and is only implemented for
*          backward compatibility to earlier releases of the software.
* <li> An RDN element may consist of several ASN.1 AVA-Elements,
*	    but *NO* sorting within an RDN element will be performed.
* <li> The only sort criteria is the first AVA element of any RDN.
* <li> RDN elements must be formatted properly: <ul>
*	    <li> each subelement consists of an AVA entry: <br>
*		There is always an ASN.1 object ID (OID) element followed
*		by the associated ASN.1 value.
*	    <li> so the number of entries in the subelement array must
*	      be even any way.
* </ul></ol>
*  @param pDnNameStruc X.501 DN structue
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SortASN1_DN(X501_DN* pDnNameStruc);

/**
* Compares list of 2 AVA-Arrays in internal notation for equality (MatchAVA_SubStrings).
*
* The Substring arrays consist of paired entries of Attribute Type
* (Object-ID, without ASN.1 Header) and Attribute value (ANY, ASN.1
* header present). The first of a pair is the lower index.
*
* Equality is defined as follows:
* <ol>
* <li> The number of AVA components must be the same.
* <li> The AVA types must match on a 1:1 basis (after possible necessary sort).
* <li> The AVA values must match for equality as defined for the
*    ASN.1 type:<ol>
* <li> Class not UNIVERSAL: Byte per byte match.
* <li> Class UNIVERSAL but constructed: Byte per byte match.
* <li> Class UNIVERSAL not constructed: <ol>
*    <li> Not supported types: Byte per byte match.
*    <li> Supported types: Individual matching rules,
*		  but only DER encoding matching used. <ol>
*       <li> Boolean: Zero / not zero
*       <li> Integer: Leading zero byte suppressed, then byte by byte
*	     <li> Bitstring: Byte per byte match
*	     <li> OctetString: Byte per byte match
*	     <li> NULL: Same match
*	     <li> ObjectID: See object ID compare subroutine
*	     <li> UTF8, BMP, UNIVERSAL STRING:
*		Contents match, case sensitive
*	     <li> PRINTABLE, TELETEX STRING:
*		Contents match, case insensitive
*	     <li> UTC STRING: special case
*	     <li> GENERALTIME STRING: special case
*</ol></ol></ol></ol>
*
* NOTE: <ol>
* <li> All entries MUST be present.
* <li> The AVA-Arrays must have been sorted according to the Attribute types 
*       before.
*</ol>
*
*  @param AVA_Array1 AVA base array 1
*  @param IndexBase1 Start index array 1
*  @param IndexCnt1 Entry count array 1
*  @param AVA_Array2 AVA base array 2
*  @param IndexBase2 Start index array 2
*  @param IndexCnt2 Entry count array 2
*  @param Result Result of compare
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int MatchAVA_SubStrings(IDATA** AVA_Array1,
                               int IndexBase1,
                               int IndexCnt1,
                               IDATA** AVA_Array2,
                               int IndexBase2,
                               int IndexCnt2,
                               int Result[]);

/**
* Matches (alias compares for equality) 2 X.501 distinguished names according 
* to ASN.1 comparison rules for each RDN part, which consists of at least
* 1 AVA (attribute value association) of 2 Elements each (MatchX501_DNs).
*
*  @param pName1Desc 1st name descriptor
*  @param pName2Desc 2nd name descriptor
*  @param pResult Result of compare
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int MatchX501_DNs(X501_DN* pName1Desc,
                         X501_DN* pName2Desc,
                         int pResult[]);

/**
* Searches RDN in internal format for CommonName OID and generates internal
* string representation of the CommonName value if found (FromASN1_DNCommonNameToString).
*
* The string is placed in a newly allocated buffer.
*
*  @param pNameDesc RDN array descriptor
*  @param pDstNameBuf Pointer to generated string
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_DNCommonNameToString(HMEM_CTX_DEF
                                         X501_DN* pNameDesc,
                                         char* pDstNameBuf[]);

/**
* Checks, if an ASN1 ObjectID
* (without header) is a known X520 or X520 extension attribute (GetRDN_WellKnownIndex).
* If found and the type matches, finds the associated index into
* the associated string access table. This index is also used
* as 'Well Known ID' for the extended DN conversion routine.
*
*  @param pObjID_Desc ObjID-Descriptor
*  @param pAccessIndex Return index: <br>
*               >= 0 Table index/Well known ID <br>
*               < 0 OID not found/not in table
*  @return int Status 0 - o.k., else error occurred
*/
extern int GetRDN_WellKnownIndex(IDATA* pObjID_Desc,
                                 int pAccessIndex[]);

/**
* Processes internal
* representation of a DN (distinguished name) to internal
* RDN string array structure (FromASN1_DN_ToStringArray).
*  Object ID's that are unknown
* or not appropriate will silently be ignored.
*
* The generated strings are deep copies.
*
*  @param pNameDesc RDN Array Structure
*  @param ppDstArrDesc Pointer for generaed RDN string array structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1_DN_ToStringArray(HMEM_CTX_DEF
                                     X501_DN* pNameDesc,
                                     IDATPARR* ppDstArrDesc[]);

/**
* Checks, if the CommonName in a certificate's subject RDN exists and is 
* present in the list of recognized subject common names (for identification) (CheckKnownCertSubjCommonName).
*
* NOTE: The list must consist of at least one entry.
*      
*
*  @param CertStruc Certificate structure
*  @param pListBuf List to check
*  @param pResult ASN1_SAME -> found
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CheckKnownCertSubjCommonName(HMEM_CTX_DEF
                                        X509CERT * CertStruc,
                                        char* pListBuf, 
                                        int pResult[]);

/**
* Adds/subtracts a time array with given RELATIVE date/time values to/from
* a time array with given ABSOLUTE date/time values (AddTimeArrayDeltaTime).
* Result is corrected to valid time/date format.
*
* NOTE: <ol>
* <li> The ABSOLUTE time array may not contain the special
*          case of a switch second: <br>
*	    Month: 12, Day: 31, Hour: 23, Minute: 59, Second: 60
*	    This must be corrected before call to this routine.
* <li> The delta array may contain any values for each type;
*          only restriction: the resulting year may not be > 9999
*	    and may not be < 1970 (base of UTC).
* <li> If delta months is <> 0, 30 days per month are assumed.
* </ol>
*
*  @param AbsTimeArray Absolute time array
*  @param DeltaTimeArray Delta time array
*  @param Mode == 0 : Add delta <br>
*               <> 0 : Subtract delta
*
*  @return 0 on success, error code otherwise
*/
extern int AddTimeArrayDeltaTime(int AbsTimeArray[],
                                 int DeltaTimeArray[], 
                                 int Mode);

/**
* Converts an ASN.1 UTC/General Time
* string into a TimeArray structure (year, month, day, hour, minute,
* second) and checks the validity of the components (ConvChkASN1_TimeStr).
* Time differentials are also handled (+- Timezone values).
*
* Note: Only data field of ASN.1 Type is used.
* 
* The TimeArray must be allocated and large enough for the data.
*
*  @param InpData Source array base
*  @param InpOffset Offset to start of string
*  @param InpLen Length of available data 
*  @param TimeArray Array base for result
*  @param TimeType ASN1_TIME_TYPE_UTC /
*               ASN1_TIME_TYPE_GENTIME
*
*  @return ASN1_OP_OK UTC Time converted
* <br>            ASN1_INSUFFICIENT_DATA Datalength too short
* <br>            ASN1_INVALID_ASCII_DIGIT non Decimal ASCII found
* <br>            ASN1_INVALID_UTC_TIME malformed UTC-Time
* <br>            ASN1_INTERNAL_ERROR processing error
*/
extern int ConvChkASN1_TimeStr(char InpData[],
                               int InpOffset,
                               int InpLen,
                               int TimeArray[],
                               int TimeType);

/**
* Compares two time arrays and reports result (CompareTimeArrays).
*
* Note: The TimeArrays are not checked for validity or
*       NULL-Pointers, this must be done ahead.
*
*  @param TimeArray1 Array base 1st array
*  @param TimeArray2 Array base 2nd array
*
*  @return 1 : time 1 > time 2
* <br>            0 : time 1 == time 2
* <br>            -1 : time 1 < time 2
*/
extern int CompareTimeArrays(int TimeArray1[],
                             int TimeArray2[]);

/**
* Either converts given UTC
* or fetches current time and stores it into a TimeArray structure,
* checks for validity of time, corrects it if possible (for example correct
* leap seconds, in last hour,minute on month 12 day 31 or month 6 day 30)
* (GetCheckLocalTimeArray).
*
* NOTE: <ol>
* <li> Input array base must be valid, it is not checked.
* <li> As there are only 32 BITS for the C-Version, there
*	    are only about 132 years distance from 1970 possible.
* <li> Destination array must be allocated and large enough for the
*      generated structure.
*</ol>
*  @param UTCTime Given UTC time
*  @param Mode == 0 use current time
*               != 0 use given UTC
*  @param TimeArray Destination array
*
*  @return ASN1_OP_OK Boolean retrieved
* <br>            ASN1_INVALID_CURRENT_TIME error fetching/converting time
*/
extern int GetCheckLocalTimeArray(int UTCTime, 
                                  int Mode,
                                  int TimeArray[]);

/**
* Generates OBJID entry in internal representation from given OID index (GenOIDIdataEntry).
*
* Makes deep copy of data.
*
*  @param OID_Index Index of OID
*  @param ArrayIndex Element of array to use
*  @param pDatArray Target array
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GenOIDIdataEntry(HMEM_CTX_DEF
                            int OID_Index,
                            int ArrayIndex,
                            IDATA** pDatArray);

/**
* Gets ASN.1 BOOLEAN value from data buffer (GetBoolValueFromBuf).
*
*  @param pBuf Buffer with data
*  @param Offset Start of data
*  @param Len Length of data
*  @param pValue Value extracted: 0 - FALSE, 1 - TRUE
*  @return 0 on success, error code otherwise
*/
extern int GetBoolValueFromBuf(char pBuf[], 
                               int Offset, 
                               int Len,
                               int pValue[]);

/**
* Gets BOOLEAN (possible optional) value from ASN.1 data descriptor (GetOptBoolValueFromDesc).
*
*  @param pSrcDesc Descriptor with data
*  @param SrcIndex Descriptor index
*  @param OptionalFlag 0 - not optional, else opt.
*  @param DefaultValue 0 - FALSE, 1 - TRUE, -1 not default
*  @param pValue Value extracted: 0 - FALSE, 1 - TRUE, -1 not present
*  @return 0 on success, error code otherwise
*/
extern int GetOptBoolValueFromDesc(IDATPARR* pSrcDesc,
                                   int SrcIndex,
                                   int OptionalFlag,
                                   int DefaultValue,
                                   int pValue[]);

/**
*  Subroutine m_extract_alter_name,
*  processes Subject/Issuer Alternative Name extensions from a Certificate (m_extract_alter_name).
*  <br>
*  The IDATPARR_PTR dsp_i2_alt_name_inp defines the input of this function which contains 
*  the IDATA reference to a subject/issuer alternative name part within the data of a 
*  certificate. If the variable adsp_i2_split_name_out is passed as null, the content of 
*  the INTPTR ainp_len_i2_out returns the length of required IDATA elements in the 
*  IDATPARR_PTR adsp_i2_split_name_out that must be allocated and passed as a reference 
*  when the function is called a second time to return the data. The IDATA array in the 
*  adsp_i2_split_name_out reference contains pairs of IDATA elements which refer to the object 
*  identifier plus length information in the even array elements and the data value itself 
*  in the odd array elements.
*
*  @param dsp_i2_alt_name_inp  Descriptor input array
*  @param adsp_i2_split_name_out  Address of descriptor output array
*  @param ainp_len_i2_out  Address of integer to return the number of 
*                          elements in the descriptor output array
*               
*  @return 0 on success, error code otherwise
*/
extern int m_extract_alter_name(IDATPARR* dsp_i2_alt_name_inp,
                                IDATPARR** adsp_i2_split_name_out, int* ainp_len_i2_out);

/**
* Splits an ASN.1 certificate and generates an internal certificate structure (FromASN1CertToCertStruc).
* Wrapper for FromASN1CertToCertStrucEX.
*
*  @param SrcBuf Source buffer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @param CertType Type if certificate <br>
*               0 - pure ASN.1 <br>
*               1 - IBM enveloped cert,
*               private key not decoded
*               if present <br>
*               2 - IBM enveloped cert with
*               private key,
*               private key decoded <br>
*               3 - IBM enveloped cert with/
*               without private key,
*               private key decoded
*  @param SortFlag == 0 - do RDN Sort <br>
*               != 0 no RDN Sort
*  @param Pwd Password for key certs
*  @param PwdLen Length of password
*  @param pCertStruc Pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromASN1CertToCertStruc(HMEM_CTX_DEF
                                   char SrcBuf[],
                                   int SrcOffset, 
                                   int SrcLen,
                                   int CertType,
                                   int SortFlags,
                                   char* Pwd,
                                   int PwdLen,
                                   X509CERT * pCertStruc[]);

/**
* Splits an ASN.1 certificate and generates an internal certificate 
* structure (FromASN1CertToCertStrucEX).
* On request processes certificate extensions.
*<ol>
* <li>  Splits IBM container with certificate/private key, if requested.
* <li>  Checks known and valid signature algor and params.
* <li>  Compares TBS cert signat algor/params to cert.
* <li>  Subdecodes/checks subject public algor/params/value.
* <li>  Subdecodes and sorts issuer and subject RDNs.
* <li>  Subdecodes and sorts extensions.
* <li>  Checks if selfsigned certificate.
* <li>  Decodes, stores and checks validity of certificate.
*
* If a special certificate (with key) is presented:
* <li>  Checks/decrypts private key using given password.
* <li>  Checks the algor type and params against the certificates
*     public algor and params.
* <li> Subdecodes the private values and stores them.
*
* If requested:
* <li> Processes certificate extensions, checks for unknown critical
*     flagged extensions.
*</ol>
* NOTE: The buffers in the generated structure, including those for private 
* params are deep copies.
*
*  @param SrcBuf Source buffer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @param CertType Type if certificate <br>
*               0 - pure ASN.1 <br>
*               1 - IBM enveloped cert,
*               private key not decoded
*               if present <br>
*               2 - IBM enveloped cert with
*               private key,
*               private key decoded <br>
*               3 - IBM enveloped cert with/
*               without private key,
*               private key decoded
*  @param ProcessFlags Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               critical extensions <br>
*               Bit 3 - 1 : Ignore all extens.
*               errors <br>
*               Bit 4 - 1 : Set PrivateKey flag
*               if marked external <br>
*               Bit 5-31 - reserved
*  @param Pwd Password for key certs
*  @param PwdLen Length of password
*  @param pCertStruc Generated certificate structure
*
*  @return 0 on success, error code otherwise
*/
extern int FromASN1CertToCertStrucEX(HMEM_CTX_DEF
                                     char SrcBuf[],
                                     int SrcOffset, 
                                     int SrcLen,
                                     int CertType,
                                     int ProcessFlags,
                                     char Pwd[], 
                                     int PwdLen,
                                     X509CERT * pCertStruc[]);

/**
* Generates an RSA structure with the public parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToRSAPubParams).
*
* Makes deep copy of data.
*
*  @param PubParValsDesc Source structure
*  @param pRsaStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToRSAPubParams(HMEM_CTX_DEF
                                       IDATPARR* PubParValsDesc,
                                       RSA_STRUC* pRsaStruc[]);

/**
* Generates a DSA structure with the public parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToDSAPubParams).
*
* Makes deep copy of data.
*
*  @param PubParValsDesc Source structure
*  @param pDsaStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToDSAPubParams(HMEM_CTX_DEF
                                       IDATPARR* PubParValsDesc,
                                       DSA_STRUC* pDsaStruc[]);

/**
* Generates a DH structure with the public parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToDHPubParams).
*
* Makes deep copy of data.
*
*  @param PubParValsDesc Source structure
*  @param pDhStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToDHPubParams(HMEM_CTX_DEF
                                      IDATPARR* PubParValsDesc,
                                      DH_STRUC* pDhStruc[]);

/**
* Generates an <code>IDATPARR</code> structure from a DH structure, using 
* public values (FromDHPubParamsToArrayDesc).
*
* Makes deep copy of data.
*
*  @param DhStruc Source structure
*  @param pPubParValsDesc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromDHPubParamsToArrayDesc(HMEM_CTX_DEF
                                      DH_STRUC* DhStruc,
                                      IDATPARR* pPubParValsDesc[]);

/**
* Generates an RSA structure with public and private parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToRSAPrivParams).
*
* Makes deep copy of data.
*
*  @param PrivParValsDesc Source structure
*  @param pRsaStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToRSAPrivParams(HMEM_CTX_DEF
                                        IDATPARR* PrivParValsDesc,
                                        RSA_STRUC* pRsaStruc[]);

/**
* Generates a DSA structure with public and private parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToDSAPrivParams).
*
* Makes deep copy of data.
*
*  @param PrivParValsDesc Source structure
*  @param pDsaStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToDSAPrivParams(HMEM_CTX_DEF
                                        IDATPARR* PrivParValsDesc,
                                        DSA_STRUC* pDsaStruc[]);

/**
* Generates a DH structure with public and private parameters from an 
* <code>IDATPARR</code> structure (FromArrayDescToDHPrivParams).
*
* Makes deep copy of data.
*
*  @param PrivParValsDesc Source structure
*  @param pDhStruc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromArrayDescToDHPrivParams(HMEM_CTX_DEF
                                       IDATPARR* PrivParValsDesc,
                                       DH_STRUC* pDhStruc[]);

/**
* Compares two <code>IDATPARR</code> structures
* for equivalence (MatchIDATPARRStrucs).
*  All elements specified must have same content.
*
* NOTE: No checking on indices/sizes/counters is done.
*
*  @param DatArrayDesc1 Descriptor array 1
*  @param StartIndex1 Index for array 1
*  @param DatArrayDesc2 Descriptor array 2
*  @param StartIndex2 Index for array 2
*  @param ElementCount Number of elements to compare
*  @return ASN1_SAME or ASN1_NOT_SAME
*/
extern int MatchIDATPARRStrucs(IDATPARR* DatArrayDesc1,
                               int StartIndex1,
                               IDATPARR* DatArrayDesc2,
                               int StartIndex2,
                               int ElementCount);

/**
* Checks public key info for known types, checks parameters and splits them 
* to a combined internal format (SubDecodePubKeyInfo). 
* I.e. the algor params and public values are 
* condensed to one internal structures array. The type of the public key
* is reported separately.
*
* No data is copied.
*
*  @param ObjID_Desc ObjID-Descriptor
*  @param AlgorPar_Desc Params descriptor
*  @param PublicVal_Desc Public values descriptor
*  @param pDstDatArrayDesc Destination array
*  @param PubAlgorType Type of algorithm
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SubDecodePubKeyInfo(HMEM_CTX_DEF
                               IDATA* ObjID_Desc,
                               IDATA* AlgorPar_Desc,
                               IDATA* PublicVal_Desc,
                               IDATPARR* pDstDatArrayDesc[],
                               int PubAlgorType[]);

/**
* Extracts the private key data to condensed internal format (SubDecodeCopyPrivKeyInfo).
* NOTE: <ol>
* <li> A deep copy of the data is put to the destination array.
* <li> RSA has one leading empty parameter entry.
*</ol>
*  @param PrivKeyBuf Private key buffer
*  @param PrivKeyOffset Start of key data
*  @param PrivKeyLen Length of key
*  @param pPrivKeyType Algorithm type
*  @param pPrivKeyUsage Key usage
*  @param pDstDatArrayDesc Pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SubDecodeCopyPrivKeyInfo(HMEM_CTX_DEF
                                    char PrivKeyBuf[],
                                    int PrivKeyOffset, 
                                    int PrivKeyLen,
                                    int pPrivKeyType[],
                                    int pPrivKeyUsage[],
                                    IDATPARR* pDstDatArrayDesc[]);

/**
* Checks signature type and algorithm of an OID (and Params for DSA) and 
* reports them in internal IDs (GetChkSignatTypeAlg).
*
*  @param SignatTypeAlg_Desc Type/Algor OID descriptor
*  @param SignatAlgPar_Desc Params descriptor
*  @param pSignatAlgor Returned internal sig algor ID
*  @param pSignatType Returned internal sig type ID
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GetChkSignatTypeAlg(HMEM_CTX_DEF
                               IDATA* SignatTypeAlg_Desc,
                               IDATA* SignatAlgPar_Desc,
                               int pSignatAlgor[],
                               int pSignatType[]);

/**
* Extracts the signature data to condensed internal format (SubDecodeSignature).
*
* No data buffers are copied.
*
*  @param Signat_Desc Signature descriptor
*  @param SignatAlgor Signature algorithm
*  @param pDstDatArrayDesc Pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SubDecodeSignature(HMEM_CTX_DEF
                              IDATA* Signat_Desc,
                              int SignatAlgor,
                              IDATPARR* pDstDatArrayDesc[]);

/**
* Generates an <code>IDATARR</code> structure, containing OBJID, an ASN.1 NULL
* element and, if requested, signature values (SubEncodeSignature).
*
* All data in the new structure are deep copies and the free flag is set.
* Even when no signatures are requested, SrcDatArray must not be NULL.
*
*  @param SrcDatArray Signature data array
*  @param ElementCnt Number of elements
*  @param SignatTypeAlgor Type of algorithm
*  @param Mode == 0 no signature data <br>
*               != 0 with signature data
*  @param pDstArrayDesc Return pointer for generated structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int SubEncodeSignature(HMEM_CTX_DEF
                              IDATA* SrcDatArray[],
                              int ElementCnt,
                              int SignatTypeAlgor,
                              int Mode,
                              IDATPARR* pDstArrayDesc[]);

/**
* Frees list of internal represented X501 DN structures (FreeDnListArray).
* Frees the DNs content, if marked as freeable.
*
*  @param pDNListArray Array base
*  @param DNCount Number of elements
*/
extern void FreeDnListArray(HMEM_CTX_DEF
                            X501_DN* pDNListArray[],
                            int DNCount);

/**
* Frees certificate structure and its content (FreeCertStruc).
*
*  @param CertStruc Structure
*/
extern void FreeCertStruc(HMEM_CTX_DEF
                          X509CERT * CertStruc);

/**
* Allocates a certificate structure,
* initializes values to default and allocates <code>IDATPARR</code> elements
* (1 for each entry) (AllocCertStruc).
*
*  @param pCertStruc Pointer for new structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int AllocCertStruc(HMEM_CTX_DEF
                          X509CERT * pCertStruc[]);

/**
* Frees list of internal represented certificates, including all content (FreeCertList).
*
*  @param pCertArray Certificate array
*  @param CertCount Number of certificates
*/
extern void FreeCertList(HMEM_CTX_DEF
                         X509CERT ** pCertArray,
                         int CertCount);

/**
* Matches certificates in internal
* notation (MatchCerts). The certificates must have been preprocessed.
* The mode decides how the matching is done:
*
* Mode == CHAIN_MATCH:
*	      The Issuer RDN from Cert1 is compared to the
*	      Subject RDN of Cert2. This is used to find the
*	      root of a chain.
*
* Mode == IDENTITY_MATCH:
*	      Certificates are compared byte by byte
*
* Mode == Root matching(every other value):
*	      The Issuer RDN and Serial Nr. of Cert1 is
*	      compared to the Issuer RDN and Serial Nr.
*	      of Cert2. This is used to find a trusted root
*	      Certificate in the Database.
*
*  @param pCert1 Certificate 1
*  @param pCert2 Certificate 2 
*  @param Mode Matching rule
*  @param Result Result of match
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int MatchCerts(X509CERT * pCert1, 
                      X509CERT * pCert2,
                      int Mode,
                      int Result[]);

/**
* Subroutine GetCertChainEX converts list of (received/read in)
* ASN.1 encoded Certificates to a list of internal certificate
* structures (GetCertChainEX).
*  The Certificates are preprocessed (Date/Time
* validity, RDN sorted, selfsigned checked, PubAlgor/Signatalgor
* checked, Private Key extracted). If requested, Extensions are
* processed
*
*  @param InpCertsDesc Input Array
*  @param CertType Type of certificate
*               0 - pure ASN.1
*               1 - IBM enveloped Cert,
*               private key not decoded
*               if present
*               2 - IBM enveloped Cert
*               with private key,
*               3 - IBM enveloped Cert
*               with/without priv. key,
*               private key decoded
*  @param ProcessFlags Bit 0 - 1 : Do NOT sort RDNs
*               Bit 1 - 1 : Process Extensions
*               Bit 2 - 1 : Ignore unknown
*               Critical Extensions
*               Bit 3 - 1 : Ignore all Extens.
*               errors
*               Bit 4 - 1 : Set PrivateKey Flag
*               if marked external
*               Bit 5-31 - reserved
*  @param Pwd Password for key Certs
*  @param PwdLen Length of Password
*  @param pCerts Allocated Structures
*  @param pCertCnt number of certificates
*
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            - else Error occurred
*/
extern int GetCertChainEX(HMEM_CTX_DEF
                          IDATPARR* InpCertsDesc,
                          int CertType, 
                          int ProcessFlags,
                          char Pwd[],
                          int PwdLen,
                          X509CERT ** pCerts[],
                          int pCertCnt[]);

/**
* Verifies the signature of  a certificate from certificate structure and given
* public algor descriptor and type (VerifyCertSignat).
*
*  @param pCert Certificate to verify
*  @param pPubParVals Public params/values to use
*  @param PubAlgType Type of public algorithm
*  @param pResult Result of verify
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int VerifyCertSignat(HMEM_CTX_DEF
                            X509CERT * pCert,
                            IDATPARR* pPubParVals,
                            int PubAlgType,
                            int Result[]);

/**
* Subroutine GenCertTreeArray generates the Tree CNode array
* from a given Certificate List (GenCertTreeArray).
*
*  @param CertList Certificate List
*  @param TotalCertCount Number of Certs in List
*  @param ppCNodeArray Array pointer, allocated
*  @param pRootCertCount Number of Root Certificates
*  @param pRootRsaEndCount RSA roots with private key
*  @param pRootDssEndCount DSS roots with private key
*  @param pNonRootCertCount Number of Other Certificates
*  @param pMaxLevel Tree depth
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            else error occurred
*/
extern int GenCertTreeArray(HMEM_CTX_DEF
                            X509CERT ** CertList,
                            int TotalCertCount,
                            int** ppCNodeArray,
                            int* pRootCertCount,
                            int* pRootRsaEndCount,
                            int* pRootDssEndCount,
                            int* pNonRootCertCount, 
                            int* pMaxLevel);

/**
* Frees allocated CertTree structure (FreeCertTreeStruc).
*
*  @param pStruc Allocated structure
*/
extern void FreeCertTreeStruc(HMEM_CTX_DEF
                              CTREESTR *(pStruc));

/**
* Subroutine GenCertNodeAndIndexTabs from given Certificate List
* and Entity (Server/Client) the CNode Tree Array, the Root CA
* CNode Indextable, the SubCA CNode Indextable and the
* 4 End Certs CNode Indextables (RSA-Sign, DSS-Sign, DH-RSA, DH-DSS) (GenCertNodeAndIndexTabs).
*
* Notes: 1) Root CA/SubCA Certs may not be DH-Type but may have
*      -    private keys.
*
*  	  2) End Certs must satisfy additional conditions to be
*	     usable for the server or the client:
*	     a) DH-Certs must contain a private key both for
*		server and client
*	     b) RSA and DSS Certificates  m u s t  contain a private
*		key for the server (as the server must sign/decrypt)
*		and  m a y  contain a private key for the client.
* 
*  @param CertList Certificate List
*  @param TotalCertCount Number of Certs in List
*  @param Entity Server/Client NO LONGER NEEDED
*  @param ppTreeStruc Tree Desc Array
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            else error occurred
*/
extern int GenCertNodeAndIndexTabs(HMEM_CTX_DEF
                                   X509CERT ** CertList,
                                   int TotalCertCount,
                                   int Entity,
                                   CTREESTR **(ppTreeStruc));

/**
* Checks if a given certificate
* in internal format is in the list of well known trusted CA root
* certs in internal format (CheckTrustedRootCert). 
* The match is done on a byte by byte
* basis. To speed up the list search, first a search for same
* signature is done. If found, a complete compare is done
* (this could be omitted).
*
*  @param pCert Certificate structure
*  @param pTreeStruc Certificate tree struct
*  @param pResult Result of search
*  @param pCNIndex CNIndex to root if >=0
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CheckTrustedRootCert(X509CERT * pCert,
                                CTREESTR *(pTreeStruc),
                                int pResult[],
                                int pCNIndex[]);

/**
* Generates a certificate tree structure from given ASN1 certificate/container
* data array descriptor (GenTreeFromASN1DatArrayDesc).
*
* Is Wrapper to GenTreeFromASSN1DatArrayDescEX
*
* NOTE: The certificate entries are deep copies,
*       so the read buffer may be freed.
* 
*  @param pCertsDatArrayDesc Certificate/container data array
*  @param CertType Loaded type of certs <br>
*               0 - pure ASN.1, no
*               container <br>
*               1 - Container, with/without
*               private key, not decoded <br>
*               2 - Container, with/without
*               private key, decoded
*  @param SortFlag == 0 do sort the Cert RDNs <br>
*               <> 0 do NOT sort Cert RDNs
*  @param ReqEntity == 0 - Server tree structure <br>
*               <> 0 - Client tree structure
*  @param pPwdBuf Buffer for password for private
*               key processing. Optional
*  @param PwdLen Length of password
*  @param ppTreeStruc Generated tree structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GenTreeFromASN1DatArrayDesc(HMEM_CTX_DEF
                                       IDATPARR* pCertsDatArrayDesc,
                                       int CertType, 
                                       int SortFlag, 
                                       int ReqEntity,
                                       char pPwdBuf[], 
                                       int PwdLen,
                                       CTREESTR **(ppTreeStruc));

/**
* Generates a certificate tree structure from given ASN1 certificate/container
* data array descriptor (GenTreeFromASN1DatArrayDescEX).
*
* NOTE: The certificate entries are deep copies,
*       so the read buffer may be freed.
* 
*  @param pCertsDatArrayDesc Certificate/container data array
*  @param CertType Loaded type of certs <br>
*               0 - pure ASN.1, no
*               container <br>
*               1 - Container, with/without
*               private key, not decoded <br>
*               2 - Container, with/without
*               private key, decoded
*  @param ProcessFlags Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               critical extensions <br>
*               Bit 3 - 1 : Ignore all extens.
*               errors <br>
*               Bit 4 - 1 : Set PrivateKey flag
*               if marked external <br>
*               Bit 5-31 - reserved
*
*  @param ReqEntity == 0 - Server tree structure <br>
*               <> 0 - Client tree structure
*  @param pPwdBuf Buffer for password for private
*               key processing. Optional
*  @param PwdLen Length of password
*  @param ppTreeStruc Generated tree structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GenTreeFromASN1DatArrayDescEX(HMEM_CTX_DEF
                                         IDATPARR* pCertsDatArrayDesc,
                                         int CertType, 
                                         int ProcessFlags,
                                         int ReqEntity,
                                         char pPwdBuf[],
                                         int PwdLen,
                                         CTREESTR **(ppTreeStruc));

/**
* Builds a list of ASN.1 encoded
* certificates from a specific end certificate up
* to its trusted CAs root cert in internal notation (BuildCertChain).
*
* Is now a Wrapper to BuildCertChainEX
*
*
*  @param pTreeStruc Cert. tree structure
*  @param PublicAlgor Requested public algor
*  @param SignatAlgor Requested signat algor
*  @param pDNList Constraint CA issuer DN list. Optional
*  @param DnCount Number of DN list elements
*  @param pDHParams DH parameters. Optional
*  @param pCNIndex Index of endcert
*  @param pDstCertsDesc Pointer for the generated chain
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BuildCertChain(HMEM_CTX_DEF
                          CTREESTR * pTreeStruc,
                          int PublicAlgor, 
                          int SignatAlgor,
                          X501_DN* pDNList[],
                          int DnCount,
                          IDATPARR* pDHParams,
                          int pCNIndex[],
                          IDATPARR* pDstCertsDesc[]);

/**
* Builds a chain of ASN.1 encoded
* certificates from a specific end certificate up to its
* trusted CAs root cert in internal notation (BuildCertChainEX).
*
* If requested, selects only Endcertificates from the Tree
* who's chain verifies o.k.
*
*  @param pTreeStruc Cert. tree structure
*  @param VerifyEnable 0 - no verify required <br>
*               1 - Verify the chain
*  @param VerifyModeFlags SEE: VerifyCertsChainEX!
*  @param PublicAlgor Requested public algor
*  @param SignatAlgor Requested aignat algor
*  @param pDNList Constraint CA issuer DN list. Optional
*  @param DnCount Number of DN list elements
*  @param pDHParams DH parameters. Optional
*  @param pCNIndex Index of endcert
*  @param pDstCertsDesc Pointer for the generated chain
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BuildCertChainEX(HMEM_CTX_DEF
                            CTREESTR * pTreeStruc,
                            int VerifyEnable,
                            int VerifyModeFlags,
                            int PublicAlgor,
                            int SignatAlgor,
                            X501_DN* pDNList[], 
                            int DnCount,
                            IDATPARR* pDHParams,
                            int pCNIndex[],
                            IDATPARR* pDstCertsDesc[]);

/**
*  Builds a list of ASN.1 encoded
*  certificates from a specific end certificate up to its
*  trusted CAs root cert in internal notation (BuildCertChainFromSigList).
*
*  If requested, selects only endcertificates from the tree
*  who's chain verifies o.k.
*
*  Requested signature types are checked for the whole chain.
*  The first entry in the SignatAlgors array is the number of requested types.
*
*  @param   pTreeStruc        Cert. tree structure
*  @param   VerifyEnable      0 - no verify required <br>
*							         1 - Verify the chain
*  @param   VerifyModeFlags   See VerifyCertsChainEX
*  @param   PublicAlgor       Requested public algor
*  @param   SignatAlgors      Requested signat types
*  @param   pDNList           Constraint CA issuer DN list. Optional
*  @param   DnCount           Number of DN elements
*  @param   pDHParams         DH parameters. Optional
*  @param   pCNIndex          Index of endcert
*  @param   pDstCertsDesc     Pointer to destination structure
*
*  @return  ASN1_OP_OK on success, error code otherwise
*/
extern int BuildCertChainFromSigList(HMEM_CTX_DEF
                                     CTREESTR * pTreeStruc,
                                     int VerifyEnable,
                                     int VerifyModeFlags,
                                     int PublicAlgor,
                                     char* SignatAlgors,
                                     X501_DN* pDNList[],
                                     int DnCount, 
                                     IDATPARR* pDHParams,
                                     int pCNIndex[], 
                                     IDATPARR* pDstCertsDesc[]);

/**
* Builds a chain of ASN.1 encoded
* certificates from a specific given local end certificate up
* to its trusted CAs root cert in internal notation (BuildLclCertChain).
*
*  @param pTreeStruc Cert. tree structure
*  @param CNIndex Index of EndCert
*  @param pDstCertsDesc Pointer for placing the generated chain
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BuildLclCertChain(HMEM_CTX_DEF
                             CTREESTR *(pTreeStruc),
                             int CNIndex,
                             IDATPARR* pDstCertsDesc[]);

/**
* Gets date/time validity of a given certificate in internal format (GetCertDateTimeValidity).
*
* NOTE: No checks on pointers is done.
*      
*
*  @param pCert Certificate structure
*  @param pResult Result of search
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GetCertDateTimeValidity(X509CERT * pCert,	
                                   int pResult[]);

/**
* Makes a deep copy of an <code>IDATPARR</code> (AllocCopyDatArrayDesc).
*  (Re-)Allocation is done as
* required.
* 
*  @param SrcDatArrayDesc Pointer to source structure
*  @param DstDatArrayDesc Pointer to destination structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  AllocCopyDatArrayDesc(HMEM_CTX_DEF
                                  IDATPARR* SrcDatArrayDesc, 
                                  IDATPARR* DstDatArrayDesc);

/**
* Generates either
* pure signed ASN.1 X509 certificate or IBM container with/w.o. private key
* entry from given, loaded certificate structure (with private key) (FromCertStrucToASN1Cert).
*<ol>
* <li> Formats TBS cert from version, serial, signature algorithm,
*    issuer RDN array, validity, subject RDN array, subject public
*    key info and stores it to the TBS cert slot.
* <li> Signs TBS certificate.
* <li> Formats certificate from TBS certificate, signature algorithm
*    and signature string.
* <li> stores certificate slot.
*    If no container is requested, returns certificate buffer and length.
*    IF container is requested:
* <li> Formats container from certificate with/w.o. encrypted private key. 
*</ol>
*
* The result is stored in a newly allocated buffer.
*
*  @param CertStruc Pointer to certificate structure
*  @param CertType Type of certificate: <br>
*               0 - pure ASN.1 <br>
*               1 - IBM enveloped certificate,
*               private key not included <br>
*               2 - IBM enveloped certificate
*               with encr. private key
*  @param OrdinalNumber Number to use for container
*  @param RsaSignStruc Structure for RSA sign. data/NULL
*  @param DsaSignStruc Structure for DSA sign. data/NULL
*  @param Pwd Password buffer
*  @param PwdLen Length of password
*  @param IteratCount PKCS5 iteration count to use
*  @param HashType PKCS5 hash to use
*  @param ContainerName Name to use for container
*  @param ContNameLen Length of name
*  @param Flags Flags for container
*  @param UsedBits Number of bits used in flags (from LSB)
*  @param pDstBuf Pointer where to store destination buffer
*  @param pDstLen Length of data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromCertStrucToASN1Cert(HMEM_CTX_DEF 
                                    X509CERT * CertStruc,	
                                    int CertType, 
                                    int OrdinalNumber,
                                    RSA_STRUC* RsaSignStruc,
                                    DSA_STRUC* DsaSignStruc,
                                    char* Pwd,
                                    int PwdLen, 
                                    int IteratCount,
                                    int HashType,
                                    char* ContainerName,
                                    int ContNameLen,
                                    int Flags, 
                                    int UsedBits,	
                                    char** pDstBuf, 
                                    int* pDstLen);

/**
* Checks a certificate chain for usability (CheckCertificateChain).
*  The chain starts with the end certificate
* (lowest index in list array) and ends with either a self signed
* certificate (which can be a well known trusted root or not) or a
* certificate signed by a well known root CA.
* If requested, a detailed status report (an array of status words,
* one for each certificate) can be returned.
*
* An overall status will be returned signalling the usability
* of the endcertificate.
*
* Some of the status bits returned (critical bits) generally inhibit
* the use of the end certificate. These are:
*
* Chain broken, basic constraints violation, signature not checkable,
*   signature check failed, key usage violation.
*
* Other status bits indicate possibly recoverable conditions that could
* be accepted depending on policy configuration / user response:
*
* Not yet valid/expired end certificate, time invalid intermediate/root
*   certificate(s), no trusted root.
*
* NOTE: <ol>
* <li> No name constraints checking is done yet.
* <li> The last certificate in the certificate list *SHOULD* be
*	    a root certificate (but need not be a trusted root). If not
*	    a status bit reporting that the root is missing / signature
*	    cannot be checked is returned.
*</ol>
*  @param pCertChain Certificate array
*  @param CertCount Number of certificates
*  @param TestModeFlags Specific testmodes to apply: <br>
*               Bit 0: 1 - Extended time
*               check enable <br>
*               Bit 1: ignored <br>
*               Bit 2: 1 - No issuer/subj match
*               checking <br>
*               Bit 3: 1 - No signat./keyusage
*               checking <br>
*               Bit 4: 1 - No BasicConstraints
*               checking <br>
*               Bit 5: 1 - No time validity
*               checking <br>
*  @param pDeltaTimeArr Used for time validity check. See CheckCertsChainTimeValidities. Optional
*  @param pStatusArr Detailed status report. Optional
*  @param pResult Summary of check result
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CheckCertificateChain(HMEM_CTX_DEF
                                 X509CERT ** pCertChain,
                                 int CertCount,
                                 int TestModeFlags,
                                 int pDeltaTimeArr[],
                                 int pStatusArr[], 
                                 int pResult[]);

/**
* Completes a given, incomplete certificate chain from the certificate tree (CompleteCertChain).
*
* NOTE: <ol>
* <li> It is assumed that the chain is *REALLY* incomplete
*          i.e. the top most element is NOT a trusted root.
* <li> The completeing certificates are appended to the
*	    TOP of the chain from SubCAs (if any) down to the
*	    respective root certificate.
* <li> The appended certificates are *NOT* copies and may
*	    not be freed.
* <li> The completed list itself will be newly allocated.
*</ol>
*
*  @param pCertChain Certificate list array
*  @param CertCount Number of certificates in list
*  @param pCertTree Cert Tree struc. array
*  @param pCNIndex Index of the corresponding
*               root certificate,<0: none found
*  @param ppNewCertChain Pointer for completed chain list
*  @param pNewCertCount Number of elements returned
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int CompleteCertChain(HMEM_CTX_DEF
                             X509CERT ** pCertChain,
                             int CertCount,
                             CTREESTR * pCertTree,
                             int pCNIndex[],
                             X509CERT ** ppNewCertChain[], 
                             int pNewCertCount[]);

/**
* Checks a given list of certificates
* starting with the end certificate, down to a root certificate or
* a certificate derived from a well known root for usability (VerifyCertsChainEX).
* The following conditions are checked:
*<ul>
* <li> Chain ends with a root certificate: <br>
*     Check, if certificate is a well known root, get it's index.
* <li> Chain does not end with a root certificate: <br>
*     Find well known root certificate for the last certificate
*      in the chain, get its index, append it to the chain for
*	checking; if none found, check chain as is.
*</ul>
* In both cases the chain is checked for the following general
* conditions:
*<ol>
* <li> Correct subject/issuer matching.
* <li> Valid signatures.
* <li> Correctness of basic constraints.
* <li> Validity of 'NotBefore' / 'NotAfter' time states, normal/extended.
*</ol>
* NOTE: <ol>
* <li> No name constraints checking is done up to now.
* <li> If a status array is specified, its content SHOULD be
*	    cleared before this function is called.
*</ol>
*  @param pCertChain Certificate list array
*  @param CertCount Number of certificates in list
*  @param TestModeFlags Specific testmodes to apply: <br>
*               Bit 0: 1 - Extended time
*               check enable <br>
*               Bit 1: 1 - Do NOT check root
*               certs for trust <br>
*               Bit 2: 1 - No issuer/subj match
*               checking <br>
*               Bit 3: 1 - No signat./keyusage
*               checking <br>
*               Bit 4: 1 - No BasicConstraints
*               checking <br>
*               Bit 5: 1 - No time validity
*               checking
*  @param pDeltaTimeArr Used for time validity check. See CheckCertsChainTimeValidities. Optional
*  @param pStatusArr Detailed status report. Optional
*  @param pResult Result of verification
*  @param pTreeStruc Certificate tree structure for finding roots. Optional
*  @param pRootIndex Return pointer for root CNIndex, <0, if none found. Optional <br>
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int VerifyCertsChainEX(HMEM_CTX_DEF
                              X509CERT ** pCertChain,
                              int CertCount,
                              int TestModeFlags,
                              int pDeltaTimeArr[],
                              int pStatusArr[],
                              int pResult[],
                              CTREESTR * pTreeStruc, 
                              int pRootIndex[]);

/**
* Subroutine VerifyCertificateChainNew is a wrapper to
* VerifyCertsChainEX for SSL processing compatibility reasons (VerifyCertificateChainNew).
*
* See description of VerifyCertsChainEX.
* NOTE: <ol>
* <li> No name constraints checking is done up to now.
* <li><ul><li> If certificate chain is fully usable, both pReason[0] and
*	       pResult[0] will be set zero.
*	    <li> If situation occures that renders certificate chain totally
*	       unusable, pReason[0] will be non zero and contain a hint why,
*	       pResult[0] should be ignored.
*	    <li> If certificate chain could be used according to config
*	       policy or user reply, pReason[0] will be set zero and
*	       pResult[0] will contain the reason.
* </ul></ol>
*  @param pCertChain Certificate array
*  @param CertCount Number of certificates
*  @param pTreeStruc Certificate struc array
*  @param Flags Flags for special check
*               modes: <br>
*               Bit 0: 1 - Ext. time
*               check enable <br>
*               Bit 1: 1 - Map 'no root'
*               error <br>
*               other Bits: reserved
*  @param pResult Result of verify
*  @param pReason Reason of failure
*  @param pRootIndex Root CNIndex
*               OUT: < 0 no root Cert
*
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            - else Error occurred
*/
extern int VerifyCertificateChainNew(HMEM_CTX_DEF
                                     X509CERT ** pCertChain,
                                     int CertCount,
                                     CTREESTR * pTreeStruc,
                                     int Flags,
                                     int pResult[],
                                     int pReason[],
                                     int pRootIndex[]);

/**
* Verifies, if a valid chain can be built from a specified end certificate to 
* it's trusted root CA certificate (VerifyLclCertChain).
*
*  @param pTreeStruc Cert. tree structure
*  @param CNIndex Index of EndCert
*  @param TestModeFlags Specific testmodes to apply: <br>
*               Bit 0: 1 - Extended time
*               check enable <br>
*               Bit 1: 1 - Do NOT check root
*               certs for trust <br>
*               Bit 2: 1 - No issuer/subj match
*               checking <br>
*               Bit 3: 1 - No signat./keyusage
*               checking <br>
*               Bit 4: 1 - No BasicConstraints
*               checking <br>
*  @param pResult Result of verification
*
*  @return 0 on success, error code otherwise
*/
extern int VerifyLclCertChain(HMEM_CTX_DEF
                              CTREESTR * pTreeStruc,
                              int CNIndex,
                              int TestModeFlags,
                              int pResult[]);

/**
*  Verifies, that the specified certificate is signed with an allowed sig type.
*
*  @param adsp_target_cert_array Array, containing the target certificate
*  @param inp_cert_off           Offset of the target certificate in the array
*  @param abyp_sig_types         List of allowed sig types
*
*  @return 1, if the certificates sig type is an allowed type, 0 otherwise.
*/
extern int m_check_cert_from_array_sig_type(X509CERT ** adsp_target_cert_array,
                                            int inp_cert_off,
                                            char* abyp_sig_types);

/**
* Searches list of end certificates in internal format for specific public 
* algorithm, signature algorithm, constraint CA Issuer DN (if present)
* and in case of DH public algor for specific DH-params (if given) (GetSpecificEndCertFromList).
*
* NOTE: No check on pointers is done.
*      
* Is a Wrapper to Get SpecificEndCertFromListEX now !
*
*
*  @param pTreeStruc Cert tree structure
*  @param PublicAlgor Requested public Algor
*  @param SignatAlgor Requested signat Algor
*  @param pDNList Constraint CA issuer DN list. Optional
*  @param DnCount Number of DN list elements
*  @param pDHParams DH parameters. Optional
*  @param pResult Result of search:
*               < 0 not found, else
*               index into CNODE list
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GetSpecificEndCertFromList(HMEM_CTX_DEF
                                      CTREESTR * pTreeStruc,
                                      int PublicAlgor,
                                      int SignatAlgor,
                                      X501_DN* pDNList[],
                                      int DnCount,
                                      IDATPARR* pDHParams, 
                                      int pResult[]);

/**
* Searches list of end certificates in internal format for specific public 
* algorithm, signature algorithm, constraint CA Issuer DN (if present)
* and in case of DH public algor for specific DH-params (if given) (GetSpecificEndCertFromListEX).
*
* If requested, verification of the list from the endcertificate
* down to the root will be performed, and only correct verified
* certificates will be returned.
*
* NOTE: No check on pointers is done.
*
*  @param pTreeStruc Cert. tree structure
*  @param VerifyEnable 0 - no verify required <br>
*               1 - Verify the chain
*  @param VerifyModeFlags SEE: VerifyCertsChainEX!
*  @param PublicAlgor Requested public algor
*  @param SignatAlgor Requested aignat algor
*  @param pDNList Constraint CA issuer DN list. Optional
*  @param DnCount Number of DN list elements
*  @param pDHParams DH parameters. Optional
*  @param pResult Result of search:
*               < 0 not found, else
*               index into CNODE list
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int GetSpecificEndCertFromListEX(HMEM_CTX_DEF
                                        CTREESTR * pTreeStruc,
                                        int VerifyEnable,
                                        int VerifyModeFlags, 
                                        int PublicAlgor,
                                        int SignatAlgor,
                                        X501_DN* pDNList[], 
                                        int DnCount,
                                        IDATPARR* pDHParams,
                                        int pResult[]);

/**
*  Finds the CNode index of a specific end certificate (GetSpecificEndCertFromListTLS12).
*  Requested signature types are checked for the whole chain.
*  The first entry in the SignatAlgors array is the number of requested types.
*
*  @param   adsp_tree_struc   Tree Structure
*  @param   inp_verify_enable 0 - no verify required
*							         1 - Verify the chain
*  @param   inp_verfy_flags   SEE: VerifyCertsChainEX!
*  @param   inp_public_alg	   Requested public algor
*  @param   abyp_sig_types	   Requested signat types
*  @param   aadsp_dn_list     Constraint CA issuer DN list. Optional
*  @param   inp_dn_count      Number of DN list elements
*  @param   adsp_dh_params    DH parameters. Optional
*  @param   ainp_result		   result of search:
*							            < 0 not found, else
*							            index into CNODE list
*
*  @return  ASN1_OP_OK on success, error code otherwise
*/
extern int GetSpecificEndCertFromListTLS12(HMEM_CTX_DEF
                                           CTREESTR * pTreeStruc,
                                           int VerifyEnable, 
                                           int VerifyModeFlags, 
                                           int PublicAlgor, 
                                           char* SignatAlgors,
                                           X501_DN* pDNList[],
                                           int DnCount,
                                           IDATPARR* pDHParams,
                                           int pResult[]);

/**
* Builds a list of ASN.1 encoded
* RDNs from the subject name of the root certificates list (BuildRootRDNsList).
*
*  @param pTreeStruc Cert tree structure
*  @param pDstRDNsDesc Pointer for the generated RDN list
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int BuildRootRDNsList(HMEM_CTX_DEF
                             CTREESTR *(pTreeStruc),
                             IDATPARR* pDstRDNsDesc[]);

/**
* Converts SSL-List of ASN.1 encoded
* certificates to internal certificate and list (array of
* certificates) format (FromSSLCertList). 
* The certificates will be copied
* to local buffer structures so the basic buffer can be freed.
*
* Is a wrapper to FromSSLCertListEX
*
*  @param SrcBuf Base of buffer
*  @param SrcOffset Start of data
*  @param SrcLen length of data
*  @param pCertList Certificates list base
*  @param pCertCnt Number of certificates
*  @param pCertListLen Length of list incl. hdr.
*  @param SortFlag == 0 sort the RDNs <br>
*               != 0 don't sort RDNs
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromSSLCertList(HMEM_CTX_DEF
                           char SrcBuf[],
                           int SrcOffset, 
                           int SrcLen,
                           X509CERT ** pCertList[],
                           int pCertCnt[], 
                           int pCertListLen[],
                           int SortFlag);

/**
* Converts SSL-List of ASN.1 encoded
* certificates to internal certificate and list (array of
* certificates) format (FromSSLCertListEX). 
* The certificates will be copied
* to local buffer structures so the basic buffer can be freed.
* If requested processes certificate extensions.
*
*  @param SrcBuf Base of buffer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @param pCertList Return pointer for certificate list
*  @param pCertCnt Number of certificates
*  @param pCertListLen Length of list incl. hdr.
*  @param ProcessFlags Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               critical extensions <br>
*               Bit 3 - 1 : Ignore all extens.
*               errors <br>
*               Bit 4-31 - reserved
*
*  @return int Status 0 - o.k., else error occurred
*/
extern int FromSSLCertListEX(HMEM_CTX_DEF
                             char SrcBuf[],
                             int SrcOffset,
                             int SrcLen,
                             X509CERT ** pCertList[],
                             int pCertCnt[],
                             int pCertListLen[], 
                             int ProcessFlags);

/**
* Converts SSL-List of ASN.1 encoded
* DNs to internal structure array (<code>X501_DN_PTR</code> struc) (FromSSL_DNList).
*
* NOTE: The RDNs will not be copied to local buffers as
*       they are only used for certificate selection. Therefore
*	 the buffer containing the RDNs must not be freed until
*	 the selecting processing is complete.
*
* NOTE: There was a misinterpretation of the RDN-List;
*       we sent a list of sets of attributes,
*	 IBM sends a list of sequences of sets of attributes
*	 this seems to be the correct way to do it...
*
* NOTE: Sorting of DNs is available for compatibility, but should not be used
*
* NOTE: Empty DN entires are ignored.
*
*  @param SrcBuf Base of buffer
*  @param SrcOffset Start of data
*  @param SrcLen length of data
*  @param pDNList Array of DN structures
*  @param pDNCnt Number of DNs
*  @param pDNListLen Length of list. Optional
*  @param SortFlag == 0 - do sort <br>
*               != 0 - dont sort RDNs
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int FromSSL_DNList(HMEM_CTX_DEF
                          char SrcBuf[],
                          int SrcOffset, 
                          int SrcLen,
                          X501_DN** pDNList[],
                          int pDNCnt[], 
                          int pDNListLen[],
                          int SortFlag);

/**
* Converts certificate list in internal notation to a SSL certificate list (ToSSLCertList).
*
* Note: A buffer will be allocated for the destination list
*       so that it can be freed when no longer used without
*	 affecting the internal certificates.
*
*  @param pCertsDesc Certificates list base
*  @param HdrLen     Additional header
*  @param pDstBuf    Pointer to buffer
*  @param pDstLen    Length of list
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToSSLCertList(HMEM_CTX_DEF
                         IDATPARR* pCertsDesc,
                         int HdrLen,
                         char* pDstBuf[], 
                         int pDstLen[]);

/**
* Converts RDN list in internal notation to a SSL RDN list (ToSSL_RDNList).
*
* Note: A buffer will be allocated for the destination list
*       so that it can be freed when no longer used without
*	 affecting the internal certificates.
*
* Note: Now the new format, a sequence surrounded RDN Att/Value list
*       can be selected.
*
*  @param pRDNsDesc  RDN list base
*  @param HdrLen     Required additional buffer
*  @param pDstBuf    Pointer for returning destination buffer
*  @param pDstLen    Length of generated list
*  @param FormatType == 0 - old format, no SEQ <br>
*               <> 0 - use new format
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int ToSSL_RDNList(HMEM_CTX_DEF
                         IDATPARR* pRDNsDesc,
                         int Headerlen, 
                         char* pDstBuf[],
                         int pDstLen[],
                         int Format);

/**
* Frees a <code>BIT8PTR</code> array and all its elements (Free_BIT8PTR_Array).
*
*  @param pArr Array pointer
*  @param ElementCnt Length of array
*/
extern void Free_BIT8PTR_Array(HMEM_CTX_DEF
                               char** pArr, int ElementCnt);

/**
* Frees an array of <code>HCERWTXT</code> structures, and their elements (Free_HCERWTXT_StrucArr).
*
*  @param pCertWTxtStrucArr Pointer to structure array
*  @param ElementCnt Number of structures
*/
extern void Free_HCERWTXT_StrucArr(HMEM_CTX_DEF
                                   HCERWTXT ** pCertWTxtStrucArr, 
                                   int ElementCnt);

/**
* Allocs a <code>BIT8PTR</code> array (Alloc_BIT8PTR_Array).
*
*  @param ElementCnt Requested size of the array
*  @return New <code>BIT8PTR</code> array / NULL
*/
extern char** Alloc_BIT8PTR_Array(HMEM_CTX_DEF
                                  int ElementCnt);

/**
* Prepares a list of certificates in internal structure for
* user data display callback purposes (PrepCertWTxtsList).
*
* Generate a <code>HCERWTXT</code> structure from each certificate and report
* list of structures. Returns the generated structures
*
*  @param pCertList List of certificates
*  @param CertsCnt Number of certificates
*  @param ppCertsWTxtArr Array of generated structures
*  @param pChainDigest Digest over chain
*
*  @return 0 on success, error code otherwise
*/
extern int PrepCertWTxtsList(HMEM_CTX_DEF
                             X509CERT * pCertList[],
                             int CertsCnt,
                             HCERWTXT ** ppCertsWTxtArr[],
                             char* pChainDigest);

/**
* Generates a <code>X501_DN</code> structure from a given <code>IDATPARR</code>
* structure. The order of  the strings is fixed internally (FromStringArrayToASN1_DN). 
* Allocates the 
* <code>X501_DN</code> container structure and the elements needed, converts 
* the internal strings to ASN.1 encoding and stores the encoded data with the 
* appropriate object ID to the name  elements.
* Only those entries are generated that have non null string pointers.
*
*  @param SrcArrayDesc Pointer to <code>IDATA</code> container structure
*  @param UTF8_Flag == 0 use best match <br>
*               != 0 alwaqys use UTF8
*  @param ppDnNameDesc Pointer where to store allocated destination name structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromStringArrayToASN1_DN(HMEM_CTX_DEF
                                     IDATPARR* SrcArrayDesc, 
                                     int UTF8_Flag, 
                                     X501_DN** ppDnNameDesc);

/**
* Generates signed, ASN.1 encoded certificate
* from given TBS certificate, RSA/DSA private key and signature type (GenSignedCertificate).
*
* NOTE: Required data buffer will be allocated and filled.
*
*  @param SrcBuf Buffer containing ASN.1 encoded TBS certificate data
*  @param SrcOff Start of data
*  @param SrcLen Data length
*  @param SignatTypeAlgor Type of signature
*  @param rsa RSA structure / NULL
*  @param dsa DSA structure / NULL
*  @param pDstBuf Pointer where to store destination buffer
*  @param pDstLen Length of generated data
*
*  @return ASN1_OP_OK on success, error code otherwise
* <br>            - else Error occured
*/
extern int  GenSignedCertificate(HMEM_CTX_DEF
                                 char* SrcBuf, int SrcOff,
                                 int SrcLen, int SignatTypeAlgor, RSA_STRUC* rsa,
                                 DSA_STRUC* dsa, char** pDstBuf, int* pDstLen);

/**
* Stores the RSA parameters
* into a given parameter/value data array descriptor as newly allocated element (FromRSAPubParamsToArrayDesc).
*
*  @param RsaStruc RSA key structure
*  @param pPubParValsDesc Pointer to destination structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromRSAPubParamsToArrayDesc(HMEM_CTX_DEF
                                        RSA_STRUC* RsaStruc, IDATPARR** pPubParValsDesc);

/**
* Stores the DSA parameters
* into a given parameter/value data array descriptor as newly allocated element (FromDSAPubParamsToArrayDesc).
*
*  @param DsaStruc DSA key structure
*  @param pPubParValsDesc Pointer to destination structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromDSAPubParamsToArrayDesc(HMEM_CTX_DEF
                                        DSA_STRUC* DsaStruc,IDATPARR** pPubParValsDesc);

/**
* Stores the RSA algorithm
* parameters (NULL) and values for the private key
* into a given parameter/value data array descriptor as newly allocated element (FromRSAPrivParamsToArrayDesc).
*
* NOTE: Is also used for OPENSSL private key (PEM) files
*
*  @param RsaStruc RSA key structure
*  @param pPrivParValsDesc Pointer to destination structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromRSAPrivParamsToArrayDesc(HMEM_CTX_DEF
                                         RSA_STRUC* RsaStruc, IDATPARR** pPrivParValsDesc);

/**
* Stores the DSA algorithm
* parameters and the private key values
* into a given parameter/value data array descriptor as newly allocated element (FromDSAPrivParamsToArrayDesc).
*
* NOTE: Is also used for OPENSSL private key (PEM) files
*
*  @param DsaStruc DSA key structure
*  @param pPrivParValsDesc Pointer to destination structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromDSAPrivParamsToArrayDesc(HMEM_CTX_DEF
                                         DSA_STRUC* DsaStruc, IDATPARR** pPrivParValsDesc);

/**
* Stores the DH algorithm
* parameters and the public and private key values
* into a given parameter/value data array descriptor as newly allocated element (FromDHPrivParamsToArrayDesc).
*
*  @param DhStruc DH structure
*  @param pPrivParValsDesc Pointer to destination structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromDHPrivParamsToArrayDesc(HMEM_CTX_DEF
                                        DH_STRUC* DhStruc, IDATPARR** pPrivParValsDesc);

/**
* Frees certificate request structure content (FreeCertReqStruc).
*
* NOTE: The structure itsself must be freed separately
*
*  @param CertReqStruc Certificate request structure
*/
extern void  FreeCertReqStruc(HMEM_CTX_DEF
                              PKCS10_CERTREQ * CertReqStruc);

/**
* Allocates a certificate request structure, initializes values to default and
* allocates <code>IDATPARR</code> elements (1 for each entry).
*
*  @param pCertReqStruc Pointer where to store allocated certificate request 
                        structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
//AllocCertReqStruc
extern int  AllocCertReqStruc(HMEM_CTX_DEF
					               PKCS10_CERTREQ ** pCertReqStruc);

/**
* Generates new TreeInfo certificate lists from given certificate
* structures list (GenCertsTreeInfo).
* All TreeInfo lists start with the endcert/subCA/rootcert
* respectively and include the depending issuer certificates in
* increasing order.
* If PEM mode is selected, the first certificate in the
* certificate structures list is assumed to be the only endcert.
* 
* NOTE: In PEM mode, there will be only one TreeInfo list; possible
*       other certificates will be discarded.
*
*  @param pCertStrucList Array of certificate structure pointers
*  @param CertsCount Number of certificates
*  @param DataType Type of data: <br>
*               PEM_REQ_DATA_TYPE: PEM-Mode <br>
*               PEM_REPLY_DATA_TYPE: PEM-Mode <br>
*               PKCS7_DATA_TYPE: PKCS7-Mode <br>
*               PKCS12_DATA_TYPE: PKCS12-Mode
*  @param ppCertTreeList Pointer where to store array of certificate container
*                        structure pointers
*  @param pCertTreeCount Number of certificate trees generated
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  GenCertsTreeInfo(HMEM_CTX_DEF
                             X509CERT ** pCertStrucList,
                             int CertsCount, int DataType,
                             CERTPARR *** ppCertTreeList,
                             int* pCertTreeCount);

/**
* Generates configuration file
* header/databuffer and hashes (GenerateConfigData).
* The length of the lists are included in the first element.
* The Ciphersuite list consists of BIG16 elements,
* the CompressionMethods list consists of bytes.
*
*  @param PwdBuf Password base
*  @param PwdOff Start of password data
*  @param PwdLen Length of password
*  @param ExpireTime UTC time. if 0 never
*  @param ConfigFlags Protocol/Config. flags
*  @param ExtConfigFlags Extended configuration flags
*  @param ExtConf2Flags Additional ext. config. flags
*  @param CertPolicyFlags Policy flags
*  @param CacheAgingTime Timer for cache aging
*  @param RenegotiateTime Timer for renegotiate
*  @param CiphSuiteList Ciphersuite list base
*  @param CiphSuiteListOff Start of ciphersuite data
*  @param ComprMethList Comprssion methods list base
*  @param ComprMethListOff Start of comprssion methods data
*  @param SubjNamesList Auth. subjects name list / NULL
*  @param SubjNamesListOff Start of subjects name list data
*  @param Type 1 - Server <br>
*               2 - Client
*  @param ConnectionCount Number of connections supported
*  @param ConnectTimeout Timeout in seconds
*  @param ppDst Destination buffer pointer
*  @param pDstLen Length of generated file data
*
*  @return int Status 0 - o.k.
* <br>            <> 0 Error occured:
* <br>            -1 Null Pointer
* <br>            -2 invalid Type
* <br>            -3 invalid Data length
* <br>            -4 invalid flags
* <br>            -5 allocate error
*/
extern int  GenerateConfigData(HMEM_CTX_DEF
                               char PwdBuf[], int PwdOff,
                               int PwdLen, int ExpireTime,int ConfigFlags,
                               int ExtConfigFlags, int ExtConf2Flags,
                               int CertPolicyFlags,
                               int CacheAgingTime, int RenegotiateTime,
                               char CiphSuiteList[], int CiphSuiteListOff,
                               char ComprMethList[], int ComprMethListOff,
                               char SubjNamesList[], int SubjNamesListOff, int Type,
                               int ConnectionCount, int ConnectTimeout,
                               char** ppDst, int pDstLen[]);

/**
* Generates an ASN.1 encoded certificate request, standard certificate or 
* server certificate container (GenIbmContainer).
*
* The container made from the following elements:
* <ol>
* <li> Ordinal number
* <li> ASN.1 encoded certificate request / certificate
* <li> Private key if certificate request or server certificate
* <li> Container name
* <li> Flags
* </ol>
*
* The buffer for the container is newly allocated.
*
*  @param SrcBuf Buffer containing ASN.1 encoded certificate or certificate
*                 request data
*  @param SrcOff Start offset of source data
*  @param SrcLen Source data length
*  @param ContainerType Type of container to generate: <br>
*                 0 - Certificate req. (with key) <br>
*                 1 - Standard certificate <br>
*                 2 - Server cert. (with key)
*  @param OrdinalNumber Number for container
*  @param RsaStruc Pointer to RSA key structure/NULL
*  @param DsaStruc Pointer to DSA key structure/NULL
*  @param DhStruc Pointer to DH key structure/NULL
*  @param Passwd Buffer with password data
*  @param PasswdLen Length of password
*  @param PubAlgorType Public algorithm to use
*  @param IteratCount PKCS5 iteration count to use
*  @param HashType PKCS5 hash to use
*  @param ContainerName Buffer with name to attach to container
*  @param ContNameLen Length of the name
*  @param Flags Flags to set
*  @param UsedBits Number of bits used in flags (from LSB)
*  @param pDstBuf Pointer where to store destination buffer
*  @param pDstLen Length of generated container data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  GenIbmContainer(HMEM_CTX_DEF
                            char* SrcBuf, int SrcOff, int SrcLen,
                            int ContainerType, int OrdinalNumber,
                            RSA_STRUC* RsaStruc, DSA_STRUC* DsaStruc, DH_STRUC* DhStruc,
                            char* Passwd, int PasswdLen, int PubAlgorType,
                            int IteratCount, int HashType, char* ContainerName,
                            int ContNameLen, int Flags, int UsedBits,
                            char** pDstBuf, int* pDstLen);

/**
* Generates configuration file
* header/databuffer and hashes (GenerateConfigDataEx).
*
*  @param PwdBuf Password base
*  @param PwdOff Start of password data
*  @param PwdLen Length of password
*  @param ExpireTime UTC time. if 0 never
*  @param pCfgStruc Structure containing data
*  @param ExtCfgBuf Extended config. data. Optional
*  @param ExtCfgOff Start of ext cfg data
*  @param ExtCfgLen Length of ext cfg data. May be 0
*  @param ppDst Destination buffer pointer
*  @param pDstLen Length of generated file data
*
*  @return int Status 0 - o.k.
* <br>            <> 0 Error occured:
* <br>            -1 Null Pointer
* <br>            -2 invalid Type
* <br>            -3 invalid Data length
* <br>            -4 invalid flags
* <br>            -5 allocate error
*/
extern int  GenerateConfigDataEx(HMEM_CTX_DEF
                                 char PwdBuf[], int PwdOff,
                                 int PwdLen, int ExpireTime,
                                 CFG_STRU * pCfgStruc, char ExtCfgBuf[], int ExtCfgOff,
                                 int ExtCfgLen, char* ppDst[], int pDstLen[]);

/**
Fills an array of unicode strings with the DNS names of a certificate.

The strings are only valid as long, as the certificate is valid. If there are 
more DNS names, than the array has space, the array will be completely filled. 
The surplus DNS names are counted, but not put into the array.

The Subject Common Name is assumed to be a DNS name.

@param adsp_pcert           Pointer to the certificate.
@param adsp_ucs_name_array  Array of unicode strings for taking the DNS names.
@param szp_array_size       Size of the name array.

@return Total number of DNS names in the certificate. <0 on error.
*/
extern int m_get_cert_dns_names(X509CERT * adsp_pcert, 
                                struct dsd_unicode_string* adsp_ucs_name_array, 
                                size_t szp_array_size);

/**
Sets the given unicode string to point to the common name part of the RDN.

The set ac_str field will be set to a part of adsp_rdn. This will not be a copy!
That means, if adsp_rdn is released, ac_str will become invalid. It also must not be freed.
If ac_str was set to allocated memory, it may cause a leak, if not freed otherwise.

@param[in]  adsp_rdn        RDN for which the common shall be extracted.
@param[out] adsp_ucs_dest   Unicode string which will be set.

@return ASN1_OP_OK on success, error code otherwise.
*/
extern int m_write_cn_to_string(X501_DN* adsp_rdn, 
                                struct dsd_unicode_string* adsp_ucs_dest);

extern unsigned char X501AvaCtl[];
extern unsigned char IBMContainerCtl[];
extern unsigned char X509CertCtl[];
extern unsigned char X509_TBSCertCtl[];
extern unsigned char X509ExtCtl[];
extern unsigned char BasicConstraintsExtCtl[];
extern unsigned char ObjIDSplitCtl[];
extern unsigned char ExtKeyUsageExtCtl[];

extern unsigned char RSA_AlgorParamsCtl[];
extern unsigned char RSA_PublicValueCtl[];
extern unsigned char RSA_SignatValueCtl[];
extern unsigned char DSA_AlgorParamsCtl[];
extern unsigned char DSA_PublicValueCtl[];
extern unsigned char DH_AlgorParamsCtl[];
extern unsigned char DH_PublicValueCtl[];

extern unsigned char PKCS8_PrivKeyInfoCtl[];
extern unsigned char RSA_PrivKeyCtl[];
extern unsigned char DSA_PrivKeyCtl[];
extern unsigned char DH_PrivKeyCtl[];

extern unsigned char AuthKeyIdExtCtl[];
extern unsigned char AltNameExtCtl[];


// extern STATIC BIT8 X509CertCtl[];

extern unsigned char OID_Table[];
extern int OID_Offset_Table[];
extern char RDN_OidIndexArray[];

extern int X520_ATT_OffsetTab[];
extern int X520_ATT_IndexTab[];
extern int X520_EXT_ATT_OffsetTab[];
extern int X520_EXT_ATT_IndexTab[];
extern int PKIX_KEY_PURPOSE_OffsetTab[];
extern int PKIX_KEY_PURPOSE_IndexTab[];
/** @} */

//-----------------------------------------------------------------------------
// OCSP
//-----------------------------------------------------------------------------


#if !defined XH_INTERFACE

#define HOCSP_CTX_DEF
#define HOCSP_CTX_DEF1
#define HOCSP_CTX_REF
#define HOCSP_CTX_REF1
#define	LOAD_HOCSP_CTX_PTR(a)

#else // XH_INTERFACE

#define	HOCSP_CTX_DEF XH_OCSP_STRUC * vp__ocsp_ctx,
#define	HOCSP_CTX_DEF1 XH_OCSP_STRUC * vp__ocsp_ctx
#define	HOCSP_CTX_REF vp__ocsp_ctx
#define	HOCSP_CTX_REF1 vp__ocsp_ctx,
#define	LOAD_HOCSP_CTX_PTR(a)	vp__ocsp_ctx = a
#endif // XH_SERVER

typedef struct XH_OCSP_STRUC_t XH_OCSP_STRUC;

/** @addtogroup http 
@{ 
*/

typedef struct URL_STRUC_t URL_STRUC;
typedef struct HTTP_URLCONN_t HTTP_URLCONN;

/**
* Frees an URL structure, and all of its elements (FreeUrlStruc).
*
*  @param pUrlStruc Structure to be freed
*/
extern void  FreeUrlStruc(HMEM_CTX_DEF
                          URL_STRUC * pUrlStruc);

/**
* Allocates an URL structure, initializes it (AllocUrlStruc).
*
* @return New URL_STRUC_PTR / NULL on error
*/
extern URL_STRUC *  AllocUrlStruc(HMEM_CTX_DEF1);

/**
* Parses an URL into its parts and generates the URL structure (ParseUrl).
*
*  @param pFullName URL to parse, ASCIIz
*  @param ppUrlStruc Return pointer for allocated, filled URL
*  @return 0 o.k., else error occured
*/
extern int  ParseUrl(HMEM_CTX_DEF
                     char * pFullName, 
                     URL_STRUC * ppUrlStruc[]);

/**
* Frees a HTTP URL connection structure and its elements (FreeHttpUrlConnStruc).
*
*  @param pHttpUrlConnStruc Structure to be freed
*/
extern void  FreeHttpUrlConnStruc(HMEM_CTX_DEF
                                  HTTP_URLCONN * pHttpUrlConnStruc);

/**
* Allocates a HTTP URL connection structure, initializes it (AllocHttpUrlConnStruc).
*
* Note: No SADDRIN structure allocated yet !
*
*  @param pUrlStruc URL structure / NULL
*  @return New HTTP_URLCONN_STRUC_PTR / NULL on error
*/
extern HTTP_URLCONN *  AllocHttpUrlConnStruc(HMEM_CTX_DEF
                                             URL_STRUC * pUrlStruc);

/**
* Constructs a new HTTP Url connection object, initializes it (NewHttpUrlStrucFromUrl).
*
* NOTE: No SADDRIN Structure set up yet.
*
*  @param pUrlFullName URL name, ASCIIZ
*  @param ppHttpUrlConnStruc Return pointer for new structure
*  @return 0 on success, else error occured
*/
extern int  NewHttpUrlStrucFromUrl(HMEM_CTX_DEF
                                   char * pUrlFullName,
                                   HTTP_URLCONN * ppHttpUrlConnStruc[]);

/**
* Connects to destination host according to URL (HttpUrlConnect).
*
* NOTE: This will set up the SADDRIN structure, the socket and
*  set the connected flag if successful.
*
*  @param pHttpUrlConnStruc URL structure defining the destination
*  @return 0 on success, else error occured
*/
extern int  HttpUrlConnect(HTTP_URLCONN * pHttpUrlConnStruc);

/**
* Sets DoInput state for a HTTP UrlConnection (HttpUrlSetDoInput).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param NewState == 0 no response input allowed <br>
*               <> 0 allow response input
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlSetDoInput(HTTP_URLCONN * pHttpUrlConnStruc,
                              int NewState);

/**
* Sets DoOutput state for a HTTP UrlConnection (HttpUrlSetDoOutput).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param NewState == 0 no response input allowed <br>
*               <> 0 allow response input
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlSetDoOutput(HTTP_URLCONN * pHttpUrlConnStruc,
                               int NewState);

/**
* Sets request method for a HTTP UrlConnection (HttpUrlSetRequestMethod).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param pMethodName ASCIIz method name
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlSetRequestMethod(HTTP_URLCONN * pHttpUrlConnStruc,
                                    char pMethodName[]);

/**
* Sets request property name and value for a HTTP UrlConnection (HttpUrlSetRequestProperty).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param pPropertyName ASCIIz property name
*  @param pPropertyValue ASCIIz property value
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlSetRequestProperty(HTTP_URLCONN * pHttpUrlConnStruc,
                                      char pPropertyName[], 
                                      char pPropertyValue[]);

/**
* Writes data to the Request Output stream of a HTTP UrlConnection (HttpUrlWriteReqData).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param pSrcBuf Data buffer
*  @param SrcOff Start of Data in buffer
*  @param SrcLen Length of data
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlWriteReqData(HTTP_URLCONN * pHttpUrlConnStruc,
                                char pSrcBuf[], 
                                int SrcOff, 
                                int SrcLen);

/**
* Gets content type value from response for a HTTP UrlConnection (HttpUrlGetContentType).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param ppContentType ASCIIz content type / NULL
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlGetContentType(HTTP_URLCONN * pHttpUrlConnStruc,
                                  char* ppContentType[]);

/**
* Gets content length from response for a HTTP UrlConnection (HttpUrlGetContentLength).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param pContentLen length, < 0 not found
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlGetContentLength(HTTP_URLCONN * pHttpUrlConnStruc, 
                                    int pContentLen[]);

/**
* Sends request headers and additional data to destination (HttpUrlSendRequest).
*
*  @param pHttpUrlConnStruc HTTP connection
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlSendRequest(HTTP_URLCONN * pHttpUrlConnStruc);

/**
* Receives response headers from a HTTP UrlConnection (HttpUrlGetResponse).
*
*  @param pHttpUrlConnStruc HTTP connection
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlGetResponse(HTTP_URLCONN * pHttpUrlConnStruc);

/**
* Reads from input stream (socket) of a a HTTP UrlConnection (HttpUrlReadResponseData).
*
*  @param pHttpUrlConnStruc HTTP connection
*  @param pDstBuf Destination buffer
*  @param DstOff Start offset for writing
*  @param DstBufLen Max. Size of data to read
*  @param Timeout Timeout in seconds, 0 - none
*  @param pBytesRead Number of bytes read, -1 EOF
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlReadResponseData(HTTP_URLCONN * pHttpUrlConnStruc,
                                    char pDstBuf[], 
                                    int DstOff, 
                                    int DstBufLen,
                                    int Timeout,
                                    int pBytesRead[]);

/**
* Closes a HTTP UrlConnection (HttpUrlDisconnect).
*
*  @param pHttpUrlConnStruc HTTP connection
*
*  @return 0 on success, else error occured
*/
extern int  HttpUrlDisconnect(HTTP_URLCONN * pHttpUrlConnStruc);

/**
* Retrieves OCSP response for given request from given URL (GetUrlOcspResponse).
*
* Response data is put into a newly allocated buffer.
*
*  @param pUrlName URL to query, string
*  @param pRequestBuf Request data to send
*  @param RequestOff Start of data
*  @param RequestLen Size of Data
*  @param ppResponseBuf Return pointer for response buffer
*  @param pResponseLen Return pointer for length of response
*  @return 0 on success, else error occured
*/
extern int  GetUrlOcspResponse(HOCSP_CTX_DEF
                               char * pUrlName,
                               char pRequestBuf[], 
                               int RequestOff,
                               int RequestLen,
                               char* ppResponseBuf[],
                               int pResponseLen[]);
/** @} */

#if defined XH_INTERFACE
   /** @addtogroup hocsp
* @{
*/

/**
* Frees an OCSP XH interface structure. Release possibly present
* RX structure.
*
* @param pXhOcspStruc Structure to free
*/
extern void  FreeXhOcspStruc(XH_OCSP_STRUC * pXhOcspStruc);

/**
* Allocates an OCSP XH interface structure and preinitializes it.
* NOTE: No callback functions set, only the memory context is set.
*
*  @param pMemCtxStruc Memory manager context
*  @return new <code>XH_OCSP_STRUC_PTR</code> / NULL
*/
extern XH_OCSP_STRUC *  AllocXhOcspStruc(ds__hmem * pMemCtxStruc);

/**
* Connects to a destination system.
* NOTE: All required parameters are embedded in a dsd_hl_ocsp_d_1
*  structure (that came from the interface...)
*
*  @param pXhOcspStruc OCSP XH interface structure
* 
*  @return 0 on success, error code otherwise
*/
extern int  XH_OcspConnect(XH_OCSP_STRUC * pXhOcspStruc);

/**
* Sends data to a (connected) destination system.
* NOTE: It is assumed that send is blocking.
*
*  @param pXhOcspStruc OCSP XH interface structure
*  @param pSrcBuf Buffer with data to send
*  @param SrcOff Start of data
*  @param SrcLen Length of data
*  @param Timeout 0 - wait forever...
* 
*  @return Bytes sent >= 0 o.k., else error occured
*/
extern int  XH_OcspSend(XH_OCSP_STRUC * pXhOcspStruc,
                        char pSrcBuf[], 
                        int SrcOff, 
                        int SrcLen, 
                        int Timeout);

/**
* Receives data from the destination system.
* NOTE: We use internal buffer to satisfy single byte requests.
*
*  @param pXhOcspStruc OCSP XH interface structure
*  @param pDstBuf Buffer for received data
*  @param DstOff Start of data
*  @param DstBufLen Size of buffer given
*  @param Timeout Timeout in millis
* 
*  @return Bytes received > 0 o.k.
* <br>            == 0 closed by remote
* <br>            < 0 error occured
*/
extern int  XH_OcspReceive(XH_OCSP_STRUC * pXhOcspStruc,
                           char pDstBuf[], 
                           int DstOff, 
                           int DstBufLen, 
                           int Timeout);

/**
* Disconnects from destination system (close).
*
*  @param pXhOcspStruc OCSP XH interface structure
* 
*  @return 0 on success, error code otherwise
*/
extern int  XH_OcspDisconnect(XH_OCSP_STRUC * pXhOcspStruc);

/** @} */
#endif // XH_INTERFACE

#if !defined __HPKCS11_EXT_HEADER__
#define __HPKCS11_EXT_HEADER__


#if defined _WIN32

typedef struct ds_pkcs11_struc_t {
  HMODULE hlib;				// Handle of the interface DLL
  //CK_FUNCTION_LIST_PTR ap_fctlist;	// Function list pointer
  void * ap_fctlist;			// Function list pointer
  unsigned long ul_hsession;		// Used Session ID
  unsigned long ul_slotid;		// Used Slot-ID
  char by_pinbuffer[32];		// Saver for Pin
  int  in_pinlen;			// length of pin
} ds_pkcs11_struc;


extern int m_closepkcs11session(ds_pkcs11_struc * adsp_p11struc);

extern int m_extract_pkcs11cert(ds_pkcs11_struc * adsp_p11struc,
                                unsigned long ilp_hcert, 
                                char * achp_certbuf,
                                int * ainp_certlen);

extern int m_extract_pkcs11cert_subj(ds_pkcs11_struc * adsp_p11struc,
                                     unsigned long ulp_hcert,
                                     char * achp_subjbuf,
                                     int * ainp_subjlen);

extern int m_get_pkcs11rsakeylenforcert(HMEM_CTX_DEF 
                                        ds_pkcs11_struc * adsp_p11struc,
                                        unsigned long ulp_certobjid,
                                        int * ainp_len);

extern int m_pkcs11_rsasigndata(ds_pkcs11_struc * adsp_p11struc,
                                char * abyrp_pindll_name,
                                unsigned long ulp_certobjid,
                                char * achp_inpbuf,
                                int inp_inplen,
                                char * achp_outpbuf,
                                unsigned long * aulp_outplen);

extern int m_pkcs11_prelogin(ds_pkcs11_struc * adsp_p11struc,
                             char * abyrp_pindll_name);

extern int m_pkcs11_getcertforssl(ds_pkcs11_struc * adsp_p11struc,
                                  char * abyp_certtypeslist,
                                  int inp_certtypeslistlen,
                                  char * abyp_authoritieslist,
                                  int inp_authoritieslistlen,
                                  unsigned long * aulp_certobjid);

extern int m_pkcs11_getcertforvpn(ds_pkcs11_struc * adsp_p11struc,
                                  unsigned long * aulp_certobjid);

extern int m_get_pkcs11_labeledcert_ex(ds_pkcs11_struc * adsp_p11struc,
                                       char * abyrp_label, 
                                       int inp_labellen,
                                       unsigned long * aulp_certid);

extern int m_get_pkcs11_labeledcert(ds_pkcs11_struc * adsp_p11struc,
                                    char * abyrp_label, 
                                    int inp_labellen,
                                    unsigned long * aulp_certid);


extern int m_pkcs11_get_vpn_priv_sign_cert(ds_pkcs11_struc * adsp_p11struc,
                                           unsigned long * aulp_certid);

extern int m_pkcs11_check_ca_subca_certs(ds_pkcs11_struc * adsp_p11struc);

extern int m_pkcs11_get_ca_subca_certlist(ds_pkcs11_struc * adsp_p11struc,
                                          unsigned long * aulrp_certid_array,
                                          int * ainp_arraysize);


extern int m_pkcs11_init(ds_pkcs11_struc * adsp_p11struc,
                         char * achp_dllname,
                         int inp_kobilinit);

extern void m_pkcs11_close(ds_pkcs11_struc * adsp_p11struc);




#endif // defined _WIN32

#endif // !defined __HPKCS11_EXT_HEADER__

extern int GenCertChainForNameOrHash(HMEM_CTX_DEF
		X501_DN* pDNName,
		char* pHashBuf, int Mode, CTREESTR * pCertTree,
		X509CERT *** ppCertChain, int* pCertsCount);

typedef struct HOCSPPAR_t HOCSPPAR;

extern HOCSPPAR *  AllocOcspParamStruc(HMEM_CTX_DEF1);
extern int  OcspVerifyCertList(HOCSPPAR * pOcspParamStruc);


//-----------------------------------------------------------------------------
//  BASE 64
//-----------------------------------------------------------------------------
typedef struct PKCS10_CERTREQ_t PKCS10_CERTREQ;
/**
* Converts given binary buffer to
* base64 encoded ASCII-Data with appropriate header and Trailer
* encapsulation lines (ToEncapsulatedBase64).
*
*  @param SrcBuf Base of input buffer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @param Type Type to generate:
*               Cert-Req. or Certificate
*  @param Mode == 0 -> with leading spaces <br>
*               != 0 -> no leading spaces
*  @param pDstBuf Allocated destination buffer
*  @param pDstLen Length of generated data
*
*  @return int Status BASE64_OP_OK o.k. else error occured
*/
extern  int ToEncapsulatedBase64(HMEM_CTX_DEF
                                 char SrcBuf[],
                                 int SrcOffset,		
                                 int SrcLen, 
                                 int Type,
                                 int Mode,
                                 char* pDstBuf[],
                                 int pDstLen[]);

/**
* Converts given Base64 formatted
* ASCII buffer with known Encapsulation header and trailer string
* to binary data (FromEncapsulatedBase64).
* NOTE: PEM-Data are not decoded, require special processing !
*
*  @param SrcBuf Base of Input buffer
*  @param SrcOffset Start of Data
*  @param SrcLen Length of data
*  @param pDstBuf Allocated destination buffer
*  @param pDstLen Length of decoded data
*  @param pEncapType Type of decoded data
*
*  @return int Status FROM_BIT64_OP_OK o.k. else error occured
*/
extern  int FromEncapsulatedBase64(HMEM_CTX_DEF
                                   char SrcBuf[], 
                                   int SrcOffset,	
                                   int SrcLen, 
                                   char* pDstBuf[], 
                                   int pDstLen[],	
                                   int pEncapType[]);
/**
* Encodes a RSA/DSA structure
* with private key to OpenSSL PEM format (FromPrivKeyToOpenSslPEM).
* Either RSA or DSA structure must be given.
*
*  @param pRsaStruc RSA private key. Optional
*  @param pDsaStruc DSA private key. Optional
*  @param ppDstBuf Allocated destination buffer
*  @param pDstLen Length of generated data
*
*  @return int Status - ASN1_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  FromPrivKeyToOpenSslPEM(HMEM_CTX_DEF
                                     RSA_STRUC* pRsaStruc, 
                                     DSA_STRUC* pDsaStruc,	
                                     char* ppDstBuf[], 
                                     int pDstLen[]);

/**
* Decodes RSA / DSA private
* key in OpenSSL format to a RSA/DSA structure (FromOpenSslPEMToPrivKey).
* <ol>
* <li> If only type is needed both structure pointers may be NULL.
* <li> If no type is required the type may also be NULL.
* <li> If type not recognized no structures returned.
*</ol>
*  @param pSrcBuf PEM data buffer
*  @param SrcOff Start of data in buffer
*  @param SrcLen Size of data
*  @param pPemType Type of key found. Optioonal
*  @param ppRsaStruc RSA private key. Optioonal
*  @param ppDsaStruc DSA private key. Optioonal
*
*  @return int Status - 0 o.k., else error occured
*/
extern  int  FromOpenSslPEMToPrivKey(HMEM_CTX_DEF
                                     char pSrcBuf[], 
                                     int SrcOff, 
                                     int SrcLen, 
                                     int pPemType[],	
                                     RSA_STRUC* ppRsaStruc[], 
                                     DSA_STRUC* ppDsaStruc[]);

/**
* Generates from given,
* loaded certificate request structure - with private key -
* a PEM certificate request (FromCertReqStrucToPEMCertReq).
*
* <ul> <li> Only certificate requests with RSA public algorithm (and
*      params) can be converted to a PEM certificate request.
*	 <li> The signature for the self signed certificate should
*	    be of type PKCS1-MD2 or PKCS1-MD5 (not PKCS1-SHA1).
* </ul>
*<ol>
* <li> Generates a self signed certificate as the originator
*     certificate:<ol>
* <li> Sets X509 version 0, certificate serial = UTC-Time,
*     ISSUER-RDN = SUBJECT-RDN, validity not before to current
*     time, validity not after to current time + 60 days.
* <li> Signs the certificate with the private parameters. </ol>
* <li> Generates the PEM Certificate request format from: <ul>
*    <li> PEM encapsulation starting boundary
*    <li> General PEM header fields
*    <li> Originator Certificate
*    <li> MIC-Info [MD2 / MD5 digest of TextInfo, RSA-Encrypted]
*    <li> Empty line, followed by TextInfo
*    <li> PEM encapsulation ending boundary
*</ul></ol>
*  @param CertReq Pointer to request structure
*  @param TimeType General / UTC
*  @param DeltaTimeDays Validity from current UTC
*  @param pDstBuf Allocated destination buffer
*  @param pDstLen Length of generated data
*
*  @return int Status - ASN1_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  FromCertReqStrucToPEMCertReq(HMEM_CTX_DEF	
                                          PKCS10_CERTREQ*(CertReq),		
                                          int TimeType, 
                                          int DeltaTimeDays,	
                                          char* pDstBuf[], 
                                          int pDstLen[]);

/**
* Decodes PEM encoded
* certificate reply and loads components to internal certificate
* array (FromPEMCertsToCertsArray). 
* @see #FromPEMCertsToCertsArray
*
*  @param OrigCertBuf Decoded request data
*  @param OrigCertLen Length of request data
*  @param IssuerCertsDesc Issuer certificates
*  @param SignatType Type of MIC signature
*  @param SignatAlgor MIC signature algorithm
*  @param MicBuf Signed text data
*  @param MicLen Length of MIC data
*  @param TextBuf Decoded text buffer
*  @param TextLen Length of text data
*  @param ppCertStrucList Generated certificate array
*  @param pCertCnt Number of certificates
*
*  @return int Status - ASN1_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  FromPEMCertsToCertsArray(HMEM_CTX_DEF
                                      char OrigCertBuf[],
                                      int OrigCertLen,
                                      IDATPARR IssuerCertsDesc[],	
                                      int SignatType,
                                      int SignatAlgor,
                                      char MicBuf[], 
                                      int MicLen, 
                                      char TextBuf[], 
                                      int TextLen,	
                                      X509CERT** ppCertStrucList[],
                                      int pCertCnt[]);
#ifndef XH_INTERFACE
/**
* Tries to determine
* the type of given data (X509, PKCS10, PKCS7-Certs, PEM-Data),
* decodes types and converts to internal structures (GetDecodeCertOrCertRequestData).
* @see #GetDecodeCertOrCertReqDataEX
*
*  @param SrcBuf Source buffer
*  @param SrcOffset Start of source data
*  @param SrcLen Length of source data
*  @param pCertStruc Converted cert
*  @param pCertReqStruc Converted cert. request
*  @param ppCertList List of PKCS7 / PEM certs
*  @param pCertListCount Number in list
*  @param pDataType Type of encountered data
*  @param pFileType Type of source data. Optional
*
*  @return int Status - BASE64_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  GetDecodeCertOrCertRequestData(HMEM_CTX_DEF
                                            char SrcBuf[],
                                            int SrcOffset, 
                                            int SrcLen,		
                                            X509CERT* pCertStruc[],
                                            PKCS10_CERTREQ*(pCertReqStruc)[],	
                                            X509CERT** ppCertList[],		
                                            int pCertListCount[],		
                                            int pDataType[],
                                            int pFileType[]);

/**
* Tries to determine
* the type of given data (X509, PKCS10, PKCS7-Certs, PEM-Data),
* decodes types and converts to internal structures (GetDecodeCertOrCertReqDataEX).
*
*  @param SrcBuf Source buffer
*  @param SrcOffset Start of source data
*  @param SrcLen Length of source data
*  @param ProcessFlags Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process Extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               Critical Extensions <br>
*               Bit 3 - 1 : Ignore all Extens.
*               errors <br>
*               Bit 4-31 - reserved
*  @param pCertStruc Converted cert
*  @param pCertReqStruc Converted cert. request
*  @param ppCertList List of PKCS7 / PEM certs
*  @param pCertListCount Number in list
*  @param pDataType Type of encountered data
*  @param pFileType Type of source data. Optional
*  @param ppDstBuf PKCS12, Source/ Base64 decoded
*  @param pDstLen PKCS12, size of Source/B64 Data
*
*  @return int Status - BASE64_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  GetDecodeCertOrCertReqDataEX(HMEM_CTX_DEF
                                          char SrcBuf[],		
                                          int SrcOffset, 
                                          int SrcLen, 
                                          int ProcessFlags,
                                          X509CERT* pCertStruc[],
                                          PKCS10_CERTREQ* pCertReqStruc[],	
                                          X509CERT** ppCertList[],		
                                          int pCertListCount[],		
                                          int pDataType[], 
                                          int pFileType[],	
                                          char* ppDstBuf[], 
                                          int pDstLen[]);
#endif
/**
* Converts given
* certificate request / certificate / certificates list
* to specified output format (PutEncodeCertOrCertRequestData). Possible formats are:
* Binary (DER/BER), Encapsulated B64, PKCS7 and PEM (no SMIME !)
* 
* The input data must already have been converted to ASN.1 format.
*
*  @param DataType PKCS10/X509/PKCS7/PEMREQ/
*               PEMREP
*  @param DataFormat Binary/BASE64/PEM-File
*  @param CertStruc Single certificate
*  @param CertReqStruc Certificate request
*  @param CertList Multiple certificates
*  @param CertListCount number of certs in list
*  @param MicData PEM-MIC data (Cert-Reply)
*  @param MicLen Length of the PEM MIC-Data
*  @param TextData PEM text data (Cert-Reply)
*  @param TextLen Length of the PEM text data
*  @param SignatAlgor PEM signature alg.
*  @param SignatType PEM signature type
*  @param pDstBuf Allocated destination buffer
*  @param pDstLen Length of destination buffer
*
*  @return int Status - BASE64_OP_OK: o.k.
* <br>            - else Error occured
*/
extern  int  PutEncodeCertOrCertRequestData(HMEM_CTX_DEF	
                                            int DataType,	
                                            int DataFormat,
                                            X509CERT* CertStruc,
                                            PKCS10_CERTREQ*(CertReqStruc),	
                                            X509CERT** CertList,
                                            int CertListCount,	
                                            char MicData[], 
                                            int MicLen,
                                            char TextData[], 
                                            int TextLen,	
                                            int SignatAlgor, 
                                            int SignatType,		
                                            char* pDstBuf[], 
                                            int pDstLen[]);

/**
* Subroutine ConvStoreB64ToHex converts input data in B64 format
* (whitespaces/CR/LFs stripped) to hex data (ConvStoreB64ToHex).
* NOTE: Destination Buffer may be same as source
* ----- (the source is 4/3 the size of the destination..)
*
*  @param SrcBuf Base of Input buffer
*  @param SrcOffset Start of Data
*  @param SrcLen Length of data
*  @param DstBuf Base of Output Buffer
*  @param DstOffset Start of Data
*  @param pDstLen output data length in Buffer
*
*  @return int Status BASE64_OP_OK - o.k. else conversion error
*/
extern int ConvStoreB64ToHex(char SrcBuf[],
                             int SrcOffset, 
                             int SrcLen,
                             char DstBuf[], 
                             int DstOffset, 
                             int pDstLen[]);

/**
* Subroutine ConvStoreHexToB64 converts given hex-values buffer to base64
* formatted ASCII lines in destination buffer (ConvStoreHexToB64). The destination buffer
* must already be allocated and the necessary remaining size is
* checked against the required length
*
*  @param SrcBuf Base of Input buffer
*  @param SrcOffset Start of Data
*  @param SrcLen Length of data
*  @param Mode == 0 -> with continuation
*               != 0 -> no continuation chars
*  @param DstBuf Base of Output Buffer
*  @param pDstOff Start of data
*  @param pDstLen remaining length of buffer
*
*  @return int Status 0 - o.k. else buffer too small error
*/
extern int ConvStoreHexToB64(char SrcBuf[], 
                             int SrcOffset, 
                             int SrcLen, 
                             int Mode, 
                             char DstBuf[], 
                             int pDstOff[], 
                             int pDstLen[]);

/**
* Generates either
* pure signed ASN.1 PKCS10 certificate request or IBM container
* with/w.o. private key entry from given,
* loaded certificate request structure (with private key) (FromCertReqStrucToASN1CertReq).
*<ol>
* <li> Formats certificate request info from version, subject RDN array,
*    subject public key info [, attributes] and stores it to the
*    certificate request info slot.
* <li> Signs certificate request info
* <li> Formats certificate request from certificate request info,
*    signature algorithm and signature string
* <li> Stores certificate request slot.
*    If no container is requested, returns certificate request buffer
*    and length. IF container is requested:
* <li> Formats container from certificate request with/w.o. encrypted
*    private key. 
*</ol>
*
*  Stores the result in a newly allocated buffer.
*
*  @param CertReqStruc Pointer to certificate request structure
*  @param CertReqType Type of certificate request: <br>
*               0 - pure ASN.1 <br>
*               1 - IBM enveloped certificate,
*               private key not included <br>
*               2 - IBM enveloped certificate
*               with encr. private key
*  @param RsaSignStruc RSA structure / NULL
*  @param DsaSignStruc DSA structure / NULL
*  @param Pwd Password for container key
*  @param PwdLen Length of password
*  @param pDstBuf Pointer for new destination buffer
*  @param pDstLen Length of data
*
*  @return ASN1_OP_OK  on success, error code otherwise
*/
extern int FromCertReqStrucToASN1CertReq(HMEM_CTX_DEF
                                         PKCS10_CERTREQ * CertReqStruc,
                                         int CertReqType,	
                                         RSA_STRUC* RsaSignStruc,
                                         DSA_STRUC* DsaSignStruc,
                                         char* Pwd,
                                         int PwdLen,    
                                         int IteratCount, 
                                         int HashType,	
                                         int OrdinalNumber,	
                                         char* ContainerName,
                                         int ContNameLen,
                                         int Flags, 
                                         int UsedBits,
                                         char** pDstBuf, 
                                         int* pDstLen);

/**
* Generate PKCS12 V3/V1 PFX PDU from given Certificate List (PKCS12_Encode).
*
*  @param pCertList Certificate List
*  @param CertsCnt
*  @param PDUType 0 - V3, 1 - V1
*  @param SecurityLevel 0 - low, 1 - medium, 2 - high
*  @param pPwd Password (ASCII)
*  @param PwdOff Start of data
*  @param PwdLen size of data
*  @param ppDstBuf Allocated buffer
*  @param pDstLen Size of Data generated
*  @return int Status - 0 o.k., else error occured
*/
extern int PKCS12_Encode(X509CERT ** pCertList,
                         int CertsCnt,
                         int PDUType, 
                         int SecurityLevel,
                         char* pPwd,
                         int PwdOff,
                         int PwdLen,
                         char** ppDstBuf,
                         int* pDstLen);

#ifdef __cplusplus
}
#endif

#endif // !__HOB_CERT_EXT__
