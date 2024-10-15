#ifndef __HOB_ENCRYPT_HEADER__
#define __HOB_ENCRYPT_HEADER__
#ifdef _WIN32
#pragma once
#endif
/**
* @file
* This is the header for the general HOB cryptographic module.
*
* Source files:
* xs_encry_1.cpp                - main C source
* aescpu86.asm                  - CPU AES routines for 32 bit Windows
* is-random-cas-02-32-win.asm   - Random CAS for  32 bit Windows
* islock03-32-win.asm           - Locking for random CAS 32 bit Windows
* aescpu64.asm                  - CPU AES routines for 64 bit Windows
* aesasm.asm                    - AES assembler implementation for 64 bit Windows
* shaasm.asm                    - SHA 1 assembler implementation for 64 bit Windows
* is-random-cas-02-64-win.asm   - Random CAS for 64 bit Windows
* islock03-64-win.asm           - Locking for random CAS 64 bit Windows
* aescpu86.s                    - CPU AES routines for 32 bit UNIX
* is-random-cas-02-32-nasm.s    - Random CAS for 32 bit UNIX
* islock03-32-nasm.s            - Locking for random CAS 32 bit UNIX
* aescpu64.s                    - CPU AES routines for 64 bit UNIX
* is-random-cas-02-64-nasm.s    - Random CAS for 64 bit UNIX
* islock03-64-nasm.s            - Locking for random CAS 64 bit UNIX
*
* The following preprocessor defines can be used to change compilation behavior 
* and interface:
*
* XH_INTERFACE    - If set, compiles with XH interface for WSP. HMEM_CTX_DEF is 
*                   mapped to the memory management structure (affects RSA, DSA, 
*                   DH and generally LNUM32)
*
* USE_ASSEMBLER_SOURCES     - Compilation for use with the assembler sources. CPU hardware 
*                   support for AES can be used. UNIX assembler sources are using 
*                   Intel Syntax and should be build with NASM v 2.09 or higher.
*                   Building with this flag, but without the assembler sources 
*                   will cause an error at link time.
*
* HOB_WIN64_ASM   - When USE_ASSEMBLER_SOURCES is set, this can be set to 0 to
*                   still use the C implementations of Software AES and SHA1 
*                   (sources aesasm.asm and shaasm.asm). This is a workaround 
*                   for 'ADDR32' relocation linker errors, if LARGEADDRESSAWARE:NO 
*                   is not an option.
*
* NO_RSA_BLINDING - Compilation without RSA blinding. Works only with debug
*                   builds (_DEBUG or DEBUG defined).
*
* The following headers are required for this header: stdint.h, stddef.h, Windows.h(WIN32_LEAN_AND_MEAN is sufficient), hob-unix01.h, TargetConditionals.h for Apple systems
*/

#if defined(__GNUC__)
# if defined(__GNUC_PATCHLEVEL__)
#  define __GNUC_VERSION__ (__GNUC__ * 10000 \
    + __GNUC_MINOR__ * 100 \
    + __GNUC_PATCHLEVEL__)
# else
#  define __GNUC_VERSION__ (__GNUC__ * 10000 \
    + __GNUC_MINOR__ * 100)
# endif
#else
#  define __GNUC_VERSION__ 0
#endif

#ifndef OPTIMIZE_OFF_ATTRIBUTE
#if __GNUC_VERSION__ >= 40400
#define OPTIMIZE_OFF_ATTRIBUTE __attribute__ ((optimize("0")))
#else 
#define OPTIMIZE_OFF_ATTRIBUTE 
#endif
#endif

#ifdef USE_ASSEBLER_SOURCES
#define USE_ASSEMBLER_SOURCES
#endif

#if defined NO_RSA_BLINDING
// only allow deactivating RSA blinding during tests
#if !defined(_DEBUG) && !defined(DEBUG)
#error "Deactivated RSA blinding in release code."
#endif
#endif

/** @addtogroup md2
* @{
*/
//==============================================================
// MD2
//==============================================================

#define MD2_DIGEST_LEN 16  //!< MD2 digest length in bytes
#define MD2_ARRAY_SIZE 81  //!< MD2 State Array Size (in 32 bit ints)

#ifdef __cplusplus
extern"C"{
#endif

/**
* Initializes the MD2 state array for MD2 hashing (MD2_Init). It must be allocated.
*        
* @param MD2_Array Pointer to MD2 state structure       
*/
extern void MD2_Init(int MD2_Array[]);

/**
* Processes given data to update the MD 2 state array (MD2_Update). 
* This is done by loading
* the data into the helper buffer (in the state array) until an entire MD2
* block is filled and then processing that MD2 block (from the MD2 State Array).
*        
* NOTE: Length of data must be <= 0x7FFFFFFF to avoid  
*       overflow.
*  @param MD2_Array Pointer to MD2 state array 
*  @param data Data buffer with to be hashed data
*  @param Offset Starting offset of the data 
*  @param len Length of data 
*/
extern void MD2_Update(int MD2_Array[], 
                       const char data[], 
                       int offset, 
                       size_t len);

/**
* Performs final MD2 operation and generates the MD2 digest (MD2_Final). 
* The state array
* is not cleared by this operation. It is assumed, that the destination is
* large enough for the digest.
*        
*  @param MD2_Array Pointer to MD2 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void MD2_Final(int MD2_Array[],
                      char Digest[],
                      int Offset);

/** @} */
/** @addtogroup md4
* @{
*/
//==============================================================
// MD4
//==============================================================

#define MD4_DIGEST_LEN 16  //!< Number of MD4 digest bytes
#define MD4_ARRAY_SIZE 24  //!< MD4 State Array Size (32 bit integers)

/**
* Initializes startvalues needed for MD4 processing (MD4_Init). 
* The state array must be allocated with sufficient length.
*
* @param MD4_Array The state array to be initialized.
*/
extern void MD4_Init(int MD4_Array[]);

/**
* Processes given data to generate
* new MD4 digest (MD4_Update). This is done by loading the data into the
* helper buffer until an entire MD4 block is filled and then
* processing that MD4 block.
*
* NOTE: length of data must be <= 0x3FFFFFFF to avoid
*       overflow
*
*  @param MD4_Array Pointer to MD4
*               state structure
*  @param data Data buffer
*  @param offset Start of data
*  @param len Length of data
*/
extern void MD4_Update(int MD4_Array[], 
                       const char data[], 
                       int offset,
                       size_t len);

/**
* Subroutine MD4_Final, pads remaining buffer data and
* appends total message bit length (low/high) (MD4_Final). Processes
* last block(s) and stores message digest.
*
* NOTE: by definition of previous functions, the block buffer
* has at least one free byte (otherwise the blockbuffer would
* have been processed in the update step !!!)
*
*  @param MD4_Array Pointer to MD4
*               State structure
*  @param Digest Digest buffer
*  @param Offset StartIndex into
*               digest buffer
*/
extern void MD4_Final(int MD4_Array[], 
                      char Digest[],
                      int Offset);

/** @} */
/** @addtogroup md5
* @{
*/
//==============================================================
// MD5
//==============================================================

#define MD5_DIGEST_LEN 16  //!< Number of MD5 digest bytes
#define MD5_ARRAY_SIZE 24  //!< MD5 State Array Size (32 bit integers)

/**
* Initializes the MD5 state array for MD5 hashing (MD5_Init). It must be allocated.
*        
* @param MD5_Array MD5 state array
*/
extern void MD5_Init(int MD5_Array[]);

/**
* Processes given data to update the MD5 state array (MD5_Update). 
* This is done by loading
* the data into the helper buffer (in the state array) until an entire MD5
* block is filled and then processing that MD5 block (from the MD5 State Array).
*
* NOTE: Length of data must be <= 0x7FFFFFFF to avoid  
*       overflow.
*        
*  @param MD5_Array Pointer to MD5 state array 
*  @param data Data buffer with to be hashed data
*  @param offset Starting offset of the data 
*  @param len Length of data 
*/
extern void MD5_Update(int MD5_Array[], 
                       const char data[], 
                       int offset, 
                       size_t len);

/**
* Performs final MD5 operation and generates the MD5 digest (MD5_Final). 
* It is assumed,
* that the destination is large enough for the digest.
*        
*  @param MD5_Array Pointer to MD5 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void MD5_Final(int MD5_Array[], 
                      char Digest[], 
                      int Offset);

/** @} */
/** @addtogroup sha1
* @{
*/
//==============================================================
// SHA-1
//==============================================================

#define SHA_DIGEST_LEN 20  //!< SHA-1 digest length in bytes
#define SHA_ARRAY_SIZE 24  //!< SHA-1 size of state array (32 bit integers)

/**
* Initializes the SHA state array for SHA hashing (SHA1_Init). It must be allocated.
*        
* @param SHA_Array SHA state array
*/
extern void SHA1_Init(int SHA_Array[]);

/**
* Processes given data to update the SHA state array (SHA1_Update). 
* This is done by loading
* the data into the helper buffer (in the state array) until an entire SHA
* block is filled and then processing that SHA block (from the SHA State Array).
*
* NOTE: length of data must be <= 0x3FFFFFFF to avoid  
*       overflow.
*        
*  @param SHA_Array Pointer to SHA state array 
*  @param data Data buffer with to be hashed data
*  @param Offset Starting offset of the data 
*  @param len Length of data
*/
extern void SHA1_Update(int SHA_Array[], 
                        const char data[],
                        int Offset,
                        size_t len);

/**
* Performs final SHA operation and generates the SHA digest (SHA1_Final). 
* It is assumed, 
* that the destination is large enough for the digest.
*        
*  @param SHA_Array Pointer to SHA state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void SHA1_Final(int SHA_Array[],
                       char Digest[],
                       int Offset);

/** @} */
/** @addtogroup sha2
* @{
*/
//==============================================================
// SHA-2
//==============================================================

#define SHA224_ARRAY_SIZE 27    //!< SHA-224 size of state array (32 bit integers)
#define SHA256_ARRAY_SIZE 27    //!< SHA-256 size of state array (32 bit integers) 
#define SHA384_ARRAY_SIZE 27    //!< SHA-384 size of state array (64 bit integers)
#define SHA512_ARRAY_SIZE 27    //!< SHA-512 size of state array (64 bit integers)

#define SHA224_DIGEST_LEN 28    //!< SHA-224 digest length in bytes
#define SHA256_DIGEST_LEN 32    //!< SHA-256 digest length in bytes
#define SHA384_DIGEST_LEN 48    //!< SHA-384 digest length in bytes
#define SHA512_DIGEST_LEN 64    //!< SHA-512 digest length in bytes

/**
* Initializes the SHA224 state array for SHA224 hashing (SHA224_Init). It must be allocated.
*        
* @param ShaArray SHA224 state array
*/
extern void SHA224_Init(int* SHA_Array);

/**
* Initializes the SHA256 state array for SHA256 hashing (SHA256_Init). It must be allocated.
*        
* @param ShaArray SHA256 state array
*/
extern void SHA256_Init(int* SHA_Array);

/**
* Initializes the SHA384 state array for SHA384 hashing (SHA384_Init). It must be allocated.
*        
* @param ShaArray SHA384 state array.
*/
extern void SHA384_Init(long long* SHA_Array);

/**
* Initializes the SHA512 state array for SHA512 hashing (SHA512_Init). It must be allocated.
*        
* @param ShaArray SHA512 state array
*/
extern void SHA512_Init(long long* SHA_Array);

/**
* Processes given data to update the SHA256 state array (SHA256_Update). 
* This is done by
* loading the data into the helper buffer (in the state array) until an 
* entire SHA256 block is filled and then processing that SHA256 block (from the
* state array).
*
* This update routine is used by both SHA224 and SHA256.
*
* NOTE: length of data must be <= 0x3FFFFFFF to avoid  
*       overflow.
*        
*  @param SHA_Array Pointer to SHA256 state array 
*  @param data Data buffer with to be hashed data
*  @param Offset Starting offset of the data 
*  @param len Length of data 
*/
extern void SHA256_Update(int* SHA_Array,
                          const char* data,
                          int Offset, 
                          size_t len);

/**
* Processes given data to update the SHA512 state array (SHA384_512_Update). 
* This is done by
* loading the data into the helper buffer (in the state array) until an 
* entire SHA512 block is filled and then processing that SHA512 block (from the
* state array).
*
* This update routine is used by both SHA384 and SHA512.
*
*  @param SHA_Array Pointer to SHA512 state array 
*  @param data Data buffer with to be hashed data
*  @param Offset Starting offset of the data 
*  @param len Length of data 
*/
extern void SHA384_512_Update(long long* SHA_Array,
                              const char* data, 
                              int Offset, 
                              size_t len);

/**
* Performs final SHA224 operation and generates the SHA224 digest (SHA224_Final). 
* It is 
* assumed, that the destination is large enough for the digest.
*        
*  @param SHA_Array Pointer to SHA224 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void SHA224_Final(int* SHA_Array, 
                         char* Digest,
                         int Offset);

/**
* Performs final SHA256 operation and generates the SHA256 digest (SHA256_Final). 
* It is 
* assumed, that the destination is large enough for the digest.
*        
*  @param SHA_Array Pointer to SHA256 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void SHA256_Final(int* SHA_Array,
                         char* Digest, 
                         int Offset);

/**
* Performs final SHA384 operation and generates the SHA384 digest (SHA384_Final). 
* It is 
* assumed, that the destination is large enough for the digest.
*        
*  @param SHA_Array Pointer to SHA384 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void SHA384_Final(long long* SHA_Array,
                         char* Digest, 
                         int Offset);

/**
* Performs final SHA512 operation and generates the SHA512 digest (SHA512_Final). 
* It is 
* assumed, that the destination is large enough for the digest.
*        
*  @param SHA_Array Pointer to SHA512 state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void SHA512_Final(long long* SHA_Array,
                         char* Digest,
                         int Offset);

/** @} */
/** @addtogroup sha3
* @{
*/
//==============================================================
// SHA-3
//==============================================================


/**
*  struct of a SHA3 state array. 
*  Using this struct, the caller does not need to worry about specifying the array size.
*
*  All hash sizes of SHA3 use the same state array size
*  The state can be addressed both as a char and as a uint64 array
*/
struct dsd_sha3_state_array {
    union {
        char achc_array[200];
        uint64_t aulc_array[25];
    };
    int imc_current_pos; //current offset for new updates
    int imc_rate_size;   //rate size in bytes
    int imc_hash_size;   //hash size in bytes
};

#define SHA3_ARRAY_SIZE (sizeof (struct dsd_sha3_state_array)/sizeof (int)) //!< SHA-3 size of state array struct in int32 units, for backwards compatibility if the caller allocates an array analogously to SHA1 and SHA2 methods

#define SHA3_224_DIGEST_LEN 28    //!< SHA-224 digest length in bytes
#define SHA3_256_DIGEST_LEN 32    //!< SHA-256 digest length in bytes
#define SHA3_384_DIGEST_LEN 48    //!< SHA-384 digest length in bytes
#define SHA3_512_DIGEST_LEN 64    //!< SHA-512 digest length in bytes

/**
* Initializes the SHA3 state array for SHA3-224 hashing.
* 
* @param adsp_sha_state SHA3 state array
*/
extern void m_sha3_224_init(struct dsd_sha3_state_array* adsp_sha_state);

/**
* Initializes the SHA3 state array for SHA3-256 hashing.
* 
* @param adsp_sha_state SHA3 state array
*/
extern void m_sha3_256_init(struct dsd_sha3_state_array* adsp_sha_state);

/**
* Initializes the SHA3 state array for SHA3-384 hashing.
* 
* @param adsp_sha_state SHA3 state array
*/
extern void m_sha3_384_init(struct dsd_sha3_state_array* adsp_sha_state);

/**
* Initializes the SHA3 state array for SHA3-512 hashing.
* 
* @param adsp_sha_state SHA3 state array
*/
extern void m_sha3_512_init(struct dsd_sha3_state_array* adsp_sha_state);

/**
* Processes given data to update the SHA3 state array (m_sha3_update). 
* Accumulated entire blocks are processed as they arrive
*        
*  @param adsp_sha_state Pointer to SHA3 state array 
*  @param achp_data Data buffer with to be hashed data
*  @param imp_offset Starting offset of the data 
*  @param szp_len Length of data 
*/
extern void  m_sha3_update(struct dsd_sha3_state_array* adsp_sha_state,
                           const char* achp_data,
                           int imp_offset, 
                           size_t szp_len);

/**
* Performs final SHA3 processing and generates the SHA3 digest. 
* It is assumed that the destination is large enough for the digest,
* whose size is equal to the value given to m_sha3_init in bits.
*        
*  @param adsp_sha_state Pointer to SHA3 state array 
*  @param achp_digest Pointer to destination buffer for digest
*  @param imp_offset Offset at which to start writing
*/

extern void m_sha3_final(struct dsd_sha3_state_array* adsp_sha_state,
                         char* achp_digest,
                         int imp_offset);


/** @} */
/** @addtogroup ripemd
* @{
*/
//==============================================================
// Ripemd
//==============================================================

//-----------------------------------------------------
// Constants
//-----------------------------------------------------
#define RMD160_DIGEST_LEN 20    //!< RIPEMD160 digest length in bytes
#define RPMD_ARRAY_SIZE 24  //!< RIPEMD160 size of state array (32 bit integers)

/**
* Initializes the RIPEMD state array for RIPEMD hashing (RMD160_Init). It must be allocated.
*
*  @param RPMD_Array Pointer to RIPEMD atate array
*/
extern void RMD160_Init(int RPMD_Array[]);

/**
* Processes given data to update the RIPEMD state array (RMD160_Update). 
* This is done by loading
* the data into the helper buffer (in the state array) until an entire RIPEMD
* block is filled and then processing that RIPEMD block (from the RIPEMD state array).
*
* NOTE: Length of data must be <= 0x3FFFFFFF to avoid
*       overflow
*
*  @param RPMD_Array Pointer to RIPEMD state array
*  @param data Data buffer with to be hashed data
*  @param Offset Starting offset of the data 
*  @param len Length of data 
*/
extern void RMD160_Update(int RPMD_Array[],
                          const char data[],
                          int Offset,
                          size_t len);

/**
* Performs final RIPEMD operation and generates the RIPEMD digest (RMD160_Final). 
* It is 
* assumed, that the destination is large enough for the digest.
*        
*  @param RPMD_Array Pointer to RIPEMD state array 
*  @param Digest Pointer to destination buffer for digest
*  @param Offset Offset at which to start writing
*/
extern void RMD160_Final(int RPMD_Array[],
                         char Digest[], 
                         int Offset);

/** @} */
/** @addtogroup hmac
* @{
*/
//==============================================================
// HMAC
//==============================================================

typedef enum ie_hmac_types {
    HMAC_MD5_ID = 0,           //!< Use MD5 for HMAC
    HMAC_SHA1_ID = 1,          //!< Use SHA1 for HMAC
    HMAC_RMD160_ID = 2,        //!< Use RIPEMD160 for HMAC
    HMAC_SHA256_ID = 3,        //!< Use SHA256 for HMAC
    HMAC_SHA384_ID = 4,        //!< Use SHA384 for HMAC
    HMAC_SHA512_ID = 5,        //!< Use SHA512 for HMAC
}ie_hmac_types;

#define HMAC_MAX_DIGEST_LEN     SHA512_DIGEST_LEN //<! Longest possible HMAC (in bytes)


#if !defined DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1

// gather input data
struct dsd_gather_i_1
{
  struct dsd_gather_i_1 *adsc_next;          // next in chain
  char *                achc_ginp_cur;       // current position
  char *                achc_ginp_end;       // end of input data
};

#endif

/**
* Generates HMAC with the requested hash as defined in RFC 2104 (GenHMAC).
*
* Note, that input buffers must not be NULL, even if Key length or message 
* length is 0.
*
*  @param pKeyData Pointer to buffer with the key to be used
*  @param KeyDataOff Start offset of the key data
*  @param KeyDataLen Size of key
*  @param pHashData Pointer to the data over which the MAC should be generated
*  @param HashDataOff Start offset of the data
*  @param HashDataLen Size of data
*  @param HashType Hash to use:
*                  MD5 = 0, SHA1 = 1, RIPEMD 160 = 2, SHA256 = 3, SHA384 = 4, SHA512 = 5
*  @param pDstBuf Buffer for MAC output
*  @param DstOff Start offset for writing MAC tag
*  @param pDstLen IN: Output buffer size <br> OUT: Length of generated MAC tag
*  @return 0 on success, error code otherwise
*/
extern int GenHMAC(const char pKeyData[], 
                   int KeyDataOff,
                   size_t KeyDataLen,
                   const char pHashData[], 
                   int HashDataOff,
                   size_t HashDataLen,
                   int HashType, 
                   char pDstBuf[],
                   int DstOff,
                   int pDstLen[]);

/**
* Generates HMAC with the requested hash as defined in RFC 2104 (GenHMACGath).
*
* This function treats all data in the chain of gather structures as a single
* message.
*
* pKeyData must not be null, even if KeyDataLen is 0.
* Supports MD5, SHA1, RIPEMD160, SHA256, SHA384 and SHA512.
*
*  @param pKeyData Pointer to buffer with the key to be used
*  @param KeyDataOff Start offset of the key data
*  @param KeyDataLen Size of key
*  @param ads_gath base of gather data to hash
*  @param HashType Hash to use:
*                  MD5 = 0, SHA1 = 1, RIPEMD 160 = 2, SHA256 = 3, SHA384 = 4, SHA512 = 5
*  @param pDstBuf Buffer for MAC output
*  @param DstOff Start offset for writing MAC tag
*  @param pDstLen IN: Output buffer size <br> OUT: Length of generated MAC tag
*  @return 0 on success, error code otherwise
*/
extern int GenHMACGath(const char pKeyData[], 
                       int KeyDataOff, 
                       size_t KeyDataLen,
                       const struct dsd_gather_i_1* ads_gath, 
                       int HashType,
                       char pDstBuf[],
                       int DstOff, 
                       int pDstLen[]);


/** @} */
/** @addtogroup rc2
* @{
*/
//==============================================================
// RC2
//==============================================================

#define RC2_ENCRYPT 1           //!< Call RC2_cbc_encdecrypt with this for encryption
#define RC2_DECRYPT 0           //!< Call RC2_cbc_encdecrypt with this for decryption

#define RC2_BLOCK 8
#define RC2_KEY_LENGTH 16

#define RC2_MAX_KEY_WORDS 64  //!< Maximum RC2 key length in 16 bit words
#define RC2_MAX_KEY_BYTES 128 //!< Maximum RC2 key length in bytes

/**
* Sets up the RC2 key array from given key data (RC2_SetKey).
*
*  @param KeyArr RC2 keydata array
*  @param KeyData Key array base
*  @param KeyLen Key data length (bytes)
*  @param KeyBits if 0, no key reduction used
*/
extern void RC2_SetKey(short Key[],
                       const char data[], 
                       size_t len,
                       int bits);

/**
* Encrypts/decrypts a data block using RC2 in CBC mode, the IV-Vektor is 
* updated each time (RC2_cbc_encdecrypt).
*
* The data length must be a multiple of 8 bytes, i.e.:
*   When doing encryption padding has to be done first if necessary.
*  When doing decryption padding must be removed if necessary
*  after decryption.
*
* The destination must be long enough to take the result.
*
*  @param pInp Source data array base
*  @param InpOffset Start of source data
*  @param pOutp Destination bufffer base
*  @param OutpOffset Start of data
*  @param length Length of input data in bytes
*  @param key RC2 keydata array
*  @param iv Initialization vector (8 bytes)
*  @param mode RC2_ENCRYPT -> do encryption <br>
*               RC2_DECRYPT -> do decryption
*/
extern void RC2_cbc_encdecrypt(const char in[], 
                               int InpOffset,
                               char out[], 
                               int OutpOffset,
                               size_t length,
                               const short key[],
                               char iv[], 
                               int mode);


/** @} */
/** @addtogroup rc4
* @{
*/
//==============================================================
// RC4
//==============================================================

#define RC4_STATE_SIZE 258      //!< Size of RC4 state array in bytes

/**
* Generates RC4 key state array from given encryption key (RC4_SetKey).
* The state array is assumed to be allocated and large enough.
*
*  @param state Pointer to RC4 key state array
*  @param data Pointer to key data
*  @param Offset Start offset of key Data
*  @param len Length of key data
*
*/
extern void RC4_SetKey(char state[], 
                       const char data[], 
                       int Offset,
                       size_t len);

/**
* Encrypts/decrypts the content of a byte array, using RC4 with a given key
* state array (RC4). 
* Input- and outputbuffer may be the same, but if they are,
* then InputOffset should be >= OutputOffset to avoid corrupting the encryption
* (is done in ascending order)
*
*  @param indata Pointer to input data array
*  @param InpOffset Start offset of input data
*  @param len Length of data
*  @param outdata Pointer to input data array
*  @param OutpOffset Offset to start writing 
*  @param key Key state array
*/
extern void RC4(const char indata[], 
                int InpOffset,
                size_t len, 
                char outdata[], 
                int OutpOffset,
                char state[]);

/**
* Encrypt a datablock with given key, single pass. This combines RC4_SetKey and
* RC4 (m_rc4_singlepass).
*
*  @param byrp_indata Data to encrypt
*  @param imp_inpoffset start of data in buffer
*  @param szp_inplen length of data
*  @param byrp_key Key to use
*  @param imp_keyoffset start of key in buffer
*  @param szp_keylen size of key data
*  @param byrp_outdata result buffer
*  @param imp_outpoffset start of result in buffer
*/
extern void m_rc4_singlepass(const char* byrp_indata, 
                             int imp_inpoffset,
                             size_t szp_inplen, 
                             const char* byrp_key,
                             int imp_keyoffset,
                             size_t szp_keylen, 
                             char* byrp_outdata, 
                             int imp_outpoffset);

/** @} */
/** @addtogroup des
* @{
*/
//==============================================================
// DES
//==============================================================

#define DES_ENCRYPT 0   //!< do DES encryption
#define DES_DECRYPT 1   //!< do DES decryption
#define DES_KEY_BYTES 8   //!< Required number of key bytes
#define DES_SUBKEY_ARRAY_SIZE 32  //!< Length of sub key tab in 32 bit integers
#define DES_BLOCK_SIZE 8   //!< DES block size in bytes. Input data must be a multiple of this

/**
* Encrypts/decrypts a single DES block (64 bit) with standard DES.
*
*  @param data Pointer to input data
*               (2 unsigned int values)
*  @param SubKeyTab Pointer to precomputed
*               DES subkeys
*  @param mode Encrypt (0) or
*               decrypt (<>0) mode
*/
extern void DES_encrypt_decrypt(unsigned int * data,
                                const unsigned int * SubKeyTab,
                                int mode);
/**
* Generates 16 * 2 subkeys C''/ D'' required for encryption/decryption
* from a given DES key.
*
*  @param DesKey 64 Bit (8*8 Byte) DES key
*               in FIPS46 bit order
*  @param SubKeyTab Subkey table for storing
*               16 *               2 *               4 byte C''/D''
*               SubKeys
*/
extern void GenDESSubKeys(const unsigned char * DesKey,
                          unsigned int * SubKeyTab);

/**
* Encrypts/decrypts a data block with DES in CBC mode with IV store back.
*
* Input length must be a multiple of 8 byte.
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param SubKeyTab Pointer to precomputed
*               DES subkeys
*  @param BlkCnt Number of 8 byte blocks
*  @param IVector Initialization vector
*  @param mode Encrypt (0) or
*               decrypt (<>0) mode
*/
extern void DES_cbc_encrypt_decrypt(const unsigned char * input, 
                                    unsigned char * output,
                                    const unsigned int * DES_SubkeyTab,
                                    size_t BlkCnt, 
                                    unsigned char * IVector, 
                                    int mode);

/**
* Encrypts/decrypts a data block with DES in ECB mode.
*
* Input length must be a multiple of 8 byte.
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param SubKeyTab Pointer to precomputed
*               DES subkeys
*  @param BlkCnt Number of 8 byte blocks
*  @param mode Encrypt (0) or
*               decrypt (<>0) mode
*/
extern void DES_ecb_encrypt_decrypt(const unsigned char * input, 
                                    unsigned char * output, 
                                    const unsigned int * DES_SubkeyTab,
                                    size_t BlkCnt, 
                                    int mode);

/**
* Encrypts a single DES block (64 bit) in 3DES EDE mode.
*
*  @param data Pointer to input data
*               (2 unsigned int values)
*  @param SubKeyTab1 Pointer to precomputed
*               DES subkeys from key 1
*  @param SubKeyTab2 Pointer to precomputed
*               DES subkeys from key 2
*  @param SubKeyTab3 Pointer to precomputed
*               DES subkeys from key 3
*/
extern void DES_encrypt3(unsigned int * data,
                         const unsigned int * SubKeyTab1, 
                         const unsigned int * SubKeyTab2, 
                         const unsigned int * SubKeyTab3);

/**
* Decrypts a single DES block (64 bit) in 3DES EDE mode.
*
*  @param data Pointer to input data
*               (2 unsigned int values)
*  @param SubKeyTab1 Pointer to precomputed
*               DES subkeys from key 1
*  @param SubKeyTab2 Pointer to precomputed
*               DES subkeys from key 2
*  @param SubKeyTab3 Pointer to precomputed
*               DES subkeys from key 3
*/
extern void DES_decrypt3(unsigned int * data, 
                         const  unsigned int * SubKeyTab1, 
                         const  unsigned int * SubKeyTab2,
                         const unsigned int * SubKeyTab3);

/**
* Encrypts/decrypts a data block with 3DES EDE in CBC mode with IV store back.
*
* Input length must be a multiple of 8 byte.
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param SubKeyTab1 Pointer to Subkey1 Table
*  @param SubKeyTab2 Pointer to Subkey2 Table
*  @param SubKeyTab3 Pointer to Subkey3 Table
*  @param BlkCnt Number of 8 byte blocks
*  @param IVector Initialization vector
*  @param mode Encrypt (0) or
*               decrypt (<>0) mode
*/
extern void DES3_ede_cbc_encrypt_decrypt(const unsigned char * input,
                                         unsigned char * output, 
                                         const unsigned int * DES_SubkeyTab1, 
                                         const unsigned int * DES_SubkeyTab2, 
                                         const unsigned int * DES_SubkeyTab3, 
                                         size_t BlkCnt, 
                                         unsigned char * IVector, 
                                         int mode);


/** @} */
/** @addtogroup aes
* @{
*/
//==============================================================
// AES
//==============================================================

//-----------------------------------------------------------
// Preprocessing macro definitions
//-----------------------------------------------------------
#if defined USE_ASSEMBLER_SOURCES

#ifdef _WIN64
#ifndef HOB_WIN64_ASM
#define HOB_WIN64_ASM 1

#endif // !HOB_WIN64_ASM
#endif

#endif // USE_ASSEMBLER_SOURCES

//-----------------------------------------------------------
// Align macro
//-----------------------------------------------------------
#if !defined (ALIGN16)
# if defined (__GNUC__)
#  define ALIGN16 __attribute__ ( (aligned (16)))
# elif defined _WIN32
#  define ALIGN16 __declspec (align (16))
# else
#  define ALIGN16
# endif
#endif

//-----------------------------------------------------------
// Constants
//-----------------------------------------------------------
#define AES_ENCRYPT 0        //!< Perform AES encryption
#define AES_DECRYPT 1        //!< Perform AES decryption

#define AES_BLOCK_SIZE 16  //!< Block size in bytes. Input data must be a multiple of this
#define AES_NB  4  //!< Block size in 32 bit integers
#define AES_NK_MIN 4  //!< min. keysize in 32 bit integers
#define AES_NK_MID 6  //!< mid. keysize in 32 bit integers
#define AES_NK_MAX 8  //!< max. keysize in 32 bit integers
#define AES_NR_MIN (AES_NK_MIN + 6) //!< min. Rounds
#define AES_NR_MAX (AES_NK_MAX + 6) //!< max. Rounds

extern const int AES128_KEY_SIZE;
extern const int AES192_KEY_SIZE;
extern const int AES256_KEY_SIZE;

//---------------------------------------------------
// Key structure for new/old routines
//---------------------------------------------------
typedef struct ds_aes_key_t {
  ALIGN16 unsigned char byr_key[15*16]; // key array
  int im_flags;    // flags
  char byr_alignfill[16];  // filler
} ds_aes_key;

#define AES_KEY_ARRAY_SIZE_BIT32  (64+4) // total size of structure


#define USE_CPU_AES_FLAG 0x01 // use AES from x86/64 CPU
#define USE_CPU_AES_GCM_FLAG 0x04 // use AES-GCM from x86/64 or ARM64 CPU

#define  CHECK_CPU_AES_FLAG  0x02  // check, if any CPU AES support is available

/**
This struct serves as state for the AES GCM multistep processing functions.

For use with CPU support, it must be aligned on 16 byte boundary (AES_BLOCK_SIZE).
*/
struct dsd_aes_gcm_state {
    char chrc_ghash_state[ AES_BLOCK_SIZE ];    // State array of the GHASH
    char chrc_ghash_key[ AES_BLOCK_SIZE ];      // Hash key for the GHASH
    char chrc_counter_block[ AES_BLOCK_SIZE ];  // Current counter block
    char chrc_partial_block[ AES_BLOCK_SIZE ];  // Buffer for storing partial CTR blocks between two Update calls.
												//If the message length is not a multiple of 16, contains:
												// -by encryption: (encrypted counter) xor (partial message||0...0)
												// -by decryption: (partial ciper||0..0) and (LSBs of encrypted counter)
												//If message length is multiple of 16, does not contain meaningful data.
	char chrc_ctr_0_block[ AES_BLOCK_SIZE ];    // Encrypted first CTR block, needed for final step
    struct ds_aes_key_t dsc_key;                // Key in use
    unsigned int unc_rounds;                    // Number of rounds (direct relation to key length)
    unsigned int unc_counter;                   // last word of current counter block
    unsigned long long ulc_add_data_len;        // Length of additional data
    unsigned long long ulc_message_len;         // (Accumulated) length of plaintext/ciphertext
    unsigned int unc_partial_bytes;             // Number of bytes used in chrc_partial_block. May be 0-15.
};
// Note: There are optimizations for GHASH, which would make chrc_ghash_key larger.

//-----------------------------------------------------------
// Macros
//-----------------------------------------------------------

#if !defined USE_ASSEMBLER_SOURCES
#define m_aes_set_encrypt_key(a,b,c) m_gen_aes_encrypt_keys(a,b,c)
#define m_aes_set_decrypt_key(a,b,c) m_gen_aes_decrypt_keys(a,b,c)

#define m_aes_cbc_encrypt(a,b,c,d,e,f) AES_Fast_cbc_encrypt(a,b,c,d,e,f)
#define m_aes_cbc_decrypt(a,b,c,d,e,f) AES_Fast_cbc_decrypt(a,b,c,d,e,f)
#define m_aes_ecb_encrypt(a,b,c,d,e) AES_Fast_ecb_encrypt(a,b,c,d,e)
#define m_aes_ecb_decrypt(a,b,c,d,e) AES_Fast_ecb_decrypt(a,b,c,d,e)
#endif // !defined USE_ASSEMBLER_SOURCES

/**
Encrypts a single AES block with the given key.

Effectively ECB with 1 block.

@param aucp_input    Pointer to input data buffer
@param aucp_output   Pointer to output data buffer
@param adsp_enc_key  Pointer to precomputed AES encrypt subkey structure
@param inp_rounds    Number of rounds
*/
extern void m_aes_raw_encrypt(const unsigned char * aucp_input,
                              unsigned char * aucp_output,
                              const  ds_aes_key * adsp_enc_key,
                              int inp_rounds);

/**
Decrypts a single AES block with the given key.

Effectively ECB with 1 block.

@param aucp_input    Pointer to input data buffer
@param aucp_output   Pointer to output data buffer
@param adsp_enc_key  Pointer to precomputed AES decrypt subkey structure
@param inp_rounds    Number of rounds
*/
extern void m_aes_raw_decrypt(const unsigned char * aucp_input,
                              unsigned char * aucp_output,
                              const ds_aes_key * adsp_dec_key,
                              int inp_rounds);

/**
* Encrypts a data block with AES in CFB8 mode of operation.
*
* The data may be of arbitrary length (not a multiple of block length). 
* The output buffer must be at least as long, as the data.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES encrypt subkey structure
*  @param szp_byte_count Number of 16 byte AES blocks
*  @param abyp_iv Initialization vector
*  @param imp_rounds Number of rounds
*/
extern void m_aes_cfb8_encrypt(const unsigned char * abyp_input,
                               unsigned char * abyp_output,
                               const ds_aes_key * adsp_key,
                               size_t szp_byte_count,
                               const unsigned char * abyp_iv,
                               int imp_rounds);

/**
* Decrypts a data block with AES in CFB8 mode of operation.
*
* The data may be of arbitrary length (not a multiple of block length). 
* The output buffer must be at least as long, as the data.
*
* The key is the same as for encryption, meaining it must be generated using 
* {@link m_gen_aes_encrypt_keys}, NOT {@link m_gen_aes_decrypt_keys}.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES encrypt subkey structure
*  @param szp_byte_count Number of 16 byte AES blocks
*  @param abyp_iv Initialization vector
*  @param imp_rounds Number of rounds
*/
extern void m_aes_cfb8_decrypt(const unsigned char * abyp_input,
                               unsigned char * abyp_output,
                               const ds_aes_key * adsp_key,
                               size_t szp_byte_count,
                               unsigned char * abyp_iv,
                               int imp_rounds);

extern void m_aes_cfb128_encrypt(const unsigned char * abyp_input,
                                 unsigned char * abyp_output,
                                 const ds_aes_key * adsp_key,
                                 size_t szp_block_count,
                                 unsigned char * abyp_iv,
                                 int imp_rounds);

extern void m_aes_cfb128_decrypt(const unsigned char * abyp_input,
                                 unsigned char * abyp_output,
                                 const ds_aes_key * adsp_key,
                                 size_t szp_block_count,
                                 unsigned char * abyp_iv,
                                 int imp_rounds);

/**
* Generates the AES encryption round keys from the given key bytes.
*
*  @param AesKey Key byte array
*  @param AesKeyLen Number of 32 bit blocks to use (nk=4,6,8)
*  @param pEncKeyStruc Pointer to preallocated
*               encrypt AES Subkeys
*  @return 0 on success, error code otherwise
*/
extern int m_gen_aes_encrypt_keys(const unsigned char * AesKey, 
                                  size_t AesKeyLen,
                                  ds_aes_key * pEncKeyStruc);

/**
* Generate the AES decryption subkey tab from the given key bytes
* (Keys are pre-inverse mixed for Table accesses).
*
*  @param AesKey Key Bytes Array
*  @param AesKeyLen Number of int to use (nk=4,6,8)
*  @param pDecKeyStruc Pointer to preallocated
*               AES decrypt subkey structure
*  @return 0 on success, error code otherwise
*/
extern int m_gen_aes_decrypt_keys(const unsigned char * AesKey,
                                  size_t AesKeyLen,
                                  ds_aes_key * pDecKeyStruc);

/**
* Encrypts a data block with AES in CBC mode of operation.
*
* The data has to be padded to a multiple of 16 byte.
*
*  @note The IV will be overwritten with the last block of the output!
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param pEncKeyStruc Pointer to precomputed
*               AES encrypt subkey structure
*  @param BlkCnt Number of 16 byte AES blocks
*  @param IVector Initialization vector
*  @param Rounds Number of rounds
*/
extern void AES_Fast_cbc_encrypt(const unsigned char * input,
                                 unsigned char * output,
                                 const ds_aes_key * pEncKeyStruc,
                                 size_t BlkCnt,
                                 unsigned char * IVector,
                                 int Rounds);

/**
* Decrypts a data block with AES in CBC mode of operation.
*
* The length of the input data must be a multiple of the AES block length.
*
*  @note The IV will be overwritten with the last block of the input!
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param pDecKeyStruc Pointer to precomputed
*               AES decrypt subkey structure
*  @param BlkCnt Number of 16 byte AES blocks
*  @param IVector Initialization vector
*  @param Rounds Number of rounds
*/
extern void AES_Fast_cbc_decrypt(const unsigned char * input,
                                 unsigned char * output,
                                 const ds_aes_key * pDecKeyStruc,
                                 size_t BlkCnt,
                                 unsigned char * IVector,
                                 int Rounds);

/**
Encrypts data with AES in CBC CTS mode of operation.

The input must be at least 1 AES block (16 bytes), but may otherwise be of 
arbitrary length. If input is exactly 1 block, it is encrypted directly as 
with ECB mode. The output is as long, as the input.

Input and output may be identical.

@note The IV will be overwritten!

@param[in]  abyp_input     Input buffer.
@param[out] abyp_output    Output buffer.
@param[in]  adsp_key       AES encrypt subkey.
@param[in]  szp_input_len  Length of the input in bytes.
@param[in]  abyp_iv        IV to be used.
@param[in]  imp_rounds     Number of rounds (10,12 or 14, depending on key size)
*/
extern void m_aes_cbc_cts_encrypt(const unsigned char * abyp_input,
                                  unsigned char * abyp_output,
                                  const ds_aes_key * adsp_key,
                                  size_t szp_input_len,
                                  unsigned char * abyp_iv,
                                  int imp_rounds);

/**
Decrypts data with AES in CBC CTS mode of operation.

The input must be at least 1 AES block (16 bytes), but may otherwise be of 
arbitrary length. If input is exactly 1 block, it is decrypted directly as 
with ECB mode. The output is as long, as the input.

Input and output may be identical.

@note The IV will be overwritten!

@param[in]  abyp_input     Input buffer.
@param[out] abyp_output    Output buffer.
@param[in]  adsp_key       AES decrypt subkey.
@param[in]  szp_input_len  Length of the input in bytes.
@param[in]  abyp_iv        IV to be used.
@param[in]  imp_rounds     Number of rounds (10,12 or 14, depending on key size)
*/
extern void m_aes_cbc_cts_decrypt(const unsigned char * abyp_input,
                                  unsigned char * abyp_output,
                                  const ds_aes_key * adsp_key,
                                  size_t szp_input_len,
                                  unsigned char * abyp_iv,
                                  int imp_rounds);


/**
* Encrypts a data block with AES in CTR counter mode of operation.
*
* @note The IV is NOT updated by this function.
*
*  @param [in] input Pointer to input data buffer
*  @param [in] input_length in bytes 
*  @param [in,out] output Pointer to output data buffer
*  @param [in] pEncKeyStruc Pointer to precomputed
*               AES encrypt subkey structure
*  @param [in] IVector Initialization vector/ICB Initial counter block
*  @param [in] Rounds Number of rounds
*/
extern void m_aes_ctr( const unsigned char * input,
                      size_t input_length,
                      unsigned char * output,
                      const  ds_aes_key * pEncKeyStruc,
                      const unsigned char * IVector,
                      int Rounds);


/**
  AES authenticated encryption in GCM mode
 
  RESTRICTIONS 
    - 0 <= plaintext length <= 2^39-256
 	- length autentification data <= 2^64-1
 	- 1 <= IV length <= 2^64-1
    - key length == 128,192,256
 	- mac tag bits == 128,120,112,104,96,64,32
 	- all parameters should be bytes long -> should be divisible by 8

   @note if no plaintext/ciphertext is present then the function acts as the 
         special mode of operation called GMAC. Only an authentication tag will 
         be generated and no ciphertext. Output codes can bee found in the 
         "m_aes_gcm_auth_enc" function notes
 
   @param [in]  abyr_iv             Initialization vector
   @param [in]  sz_iv_len           IV length in bytes
 
   @param [in]  abyr_auth_data      authenticated data 
   @param [in]  sz_auth_data_len    authenticated data in bytes
 
   @param [in]  c_enc_key           keyset to use
   @param [in]  um_key_len          length of the key in bytes
 
   @param [in]  abyr_plaintext      plaintext to encrypt
   @param [in]  sz_plaintext_len    plaintext length in bytes
 
   @param [out] abyr_ciphertext     output ciphertext
   @param [in]  sz_dest_buff_len    ciphertext should have same space reserved as the plaintext
 
   @param [out] abyr_mac_tag        output authentication tag
   @param [in]  um_mac_tag_len      tag length in bytes
 
   @return output  error code or "ok" code, ciphertext, and the authentication tag if success
 
 		return values:
    			GCM_OK	0 - everything ok
 				GCM_NULL_PTR -1 - some input is missing/empty
				GCM_PARAM_ERR -3 - parameters given do not match the requirements
				GCM_DST_BUFFER_TOO_SMALL -4 - allocated buffer cannot hold the whole output
				GCM_AUTH_FAIL -5 - tag mismatch

*/
extern int m_aes_gcm_auth_enc(unsigned char* abyr_iv,
                       size_t sz_iv_len,
                       unsigned char* abyr_auth_data,
			           size_t sz_auth_data_len,
                       const  ds_aes_key* c_enc_key,
			           unsigned int um_key_len,
                       unsigned char* abyr_plaintext,
                       size_t sz_plaintext_len,
			           unsigned char* abyr_ciphertext,
                       size_t sz_dest_buff_len,
			           unsigned char* abyr_mac_tag,
                       unsigned int um_mac_tag_len);

/**
  AES authenticated decryption in GCM mode
 
  RESTRICTIONS 
    - 0 <= ciphertext length <= 2^39-256
 	- length autentification data <= 2^64-1
 	- 1 <= IV length <= 2^64-1
    - key length == 128,192,256
 	- mac tag bits == 128,120,112,104,96,64,32
 	- all parameters should be bytes long -> should be divisible by 8
 
   @note if no plaintext/ciphertext is present then the function acts as the 
         special mode of operation called GMAC. Only an authentication tag will 
         be generated and no ciphertext. Output codes can bee found in the 
         "m_aes_gcm_auth_enc" function notes

   @param [in]  abyr_iv             Initialization vector
   @param [in]  sz_iv_len           IV length in bytes
   @param [in]  abyr_auth_data      authenticated data 
   @param [in]  sz_auth_data_len    authenticated data in bytes
   @param [in]  c_enc_key           keyset to use
   @param [in]  um_key_len          length of the key in bytes
   @param [in]  abyr_ciphertext     ciphertext to retrieve plaintext from
   @param [in]  sz_ciphertext_len   ciphertext length in bytes
   @param [out] abyr_plaintext      output plaintext
   @param [in]  sz_dest_buff_len    plaintext should have same space reserved as the ciphertext
   @param [in]  abyr_mac_tag        tag to check authenticity
   @param [in]  um_mac_tag_len      tag length in bytes
 
   @return output  error code or "ok" code and plaintext if success
 
 		return values:
 				GCM_OK	0 - everything ok
 				GCM_NULL_PTR -1 - some input is missing/empty
 				GCM_PARAM_ERR -3 - parameters given do not match the requirements
 				GCM_DST_BUFFER_TOO_SMALL -4 - allocated buffer cannot hold the whole output
 				GCM_AUTH_FAIL -5 - tag mismatch
 
*/
extern int m_aes_gcm_auth_dec(unsigned char* abyr_iv,
                       size_t sz_iv_len,
                       unsigned char* abyr_auth_data,
			           size_t sz_auth_data_len,
                       const ds_aes_key* c_enc_key,
			           unsigned int um_key_len,
                       unsigned char* abyr_ciphertext,
                       size_t sz_ciphertext_len,
			           unsigned char* abyr_plaintext,
                       size_t sz_dest_buff_len,
			           unsigned char* abyr_mac_tag,
                       unsigned int um_mac_tag_len);
/**
*  Get a mac for the given authenticated data in AES GCM mode.
*
*  @param [in] abyr_iv  Initialitation vector
*  @param [in] sz_iv_len  IV length in bytes
*  @param [in] abyr_auth_data  authenticated data 
*  @param [in] sz_auth_data_len  authenticated data in bytes
*  @param [in] c_enc_key  keyset to use
*  @param [in] um_key_len  length of the key in bytes
*  @param [in,out] abyr_mac_tag  output authentication tag
*  @param [in] um_mac_tag_len  tag length in bytes
*
*  @return output  error code or "ok" code and tag if success
*
*	will yield error code if something goes wrong and 0 otherwise.
*	If everything is correct an authentication tag for the input will be handed back
*	
*		return values:
*				GCM_OK	0 - everything ok
*				GCM_NULL_PTR -1 - some input is missing/empty
*				GCM_PARAM_ERR -3 - parameters given do not match the requirements
*
*/
extern int m_aes_gcm_mac (unsigned char* abyr_iv,
                   size_t sz_iv_len,
                   unsigned char* abyr_auth_data,
		           size_t sz_auth_data_len,
                   const ds_aes_key* c_enc_key,
                   unsigned int um_key_len,
		           unsigned char* abyr_mac_tag,
                   unsigned int um_mac_tag_len);

/**
*  Calculate mac in AES GCM mode for the given authenticated data and compare it
*  with a given mac.
*
*  @param [in] abyr_iv  Initialitation vector
*  @param [in] sz_iv_len  IV length in bytes
*  @param [in] abyr_auth_data  authenticated data 
*  @param [in] sz_auth_data_len  authenticated data in bytes
*  @param [in] c_enc_key keyset to use
*  @param [in] um_key_len  length of the key in bytes
*  @param [in] abyr_mac_tag  output authentication tag
*  @param [in] um_mac_tag_len  tag length in bytes
*
*  @return output  error code or "ok" code if success
*
*		return values:
*				GCM_OK	0 - tags match
*				GCM_NULL_PTR -1 - some input is missing/empty
*				GCM_PARAM_ERR -3 - parameters given do not match the requirements
*				GCM_AUTH_FAIL -5 - tag mismatch
*
*/
extern int m_aes_gcm_mac_verify(unsigned char* abyr_iv,
                         size_t sz_iv_len,
                         unsigned char* abyr_auth_data,
		                 size_t sz_auth_data_len,
                         const ds_aes_key* c_enc_key,
                         unsigned int um_key_len,
		                 unsigned char* abyr_mac_tag,
                         unsigned int um_mac_tag_len);

/**
Initializes a multi-step AES GCM processing.

This function is used for both encryption and decryption.
It needs to be called, before any uses of m_enc_update_aes_gcm_1 and
m_dec_update_aes_gcm_1.

Note, that the additional data pointer may be NULL, if the length is 0.

@param[out] adsp_state              State structure to be initialized. Must be 16 byte aligned.
@param[in]  achp_additional_data    Buffer with the additional data.
@param[in]  inp_data_len            Length of the additional data. May be 0.
@param[in]  achp_iv                 Buffer with the IV.
@param[in]  inp_iv_len              Length of the IV. Must be > 0.
@param[in]  adsp_key                The key structure. Must be 16 byte aligned.
*/
extern void m_init_aes_gcm_1(struct dsd_aes_gcm_state* adsp_state,
                             const char* achp_additional_data,
                             int inp_data_len,
                             const char* achp_iv,
                             int inp_iv_len,
                             const struct ds_aes_key_t* adsp_key,
                             int inp_key_len);

/**
Performs one encryption step of a multi-step AES GCM encryption.

The generated ciphertext will be as long as the plaintext.
Length is not restricted.
achp_ciphertext and achp_plaintext may be identical.
This function can be called any number of times, including 0 times.
m_init_aes_gcm_1 must be called beforehand.

@param[inout]   adsp_state      State structure. Must be 16 byte aligned.
@param[out]     achp_ciphertext Buffer for the ciphertext.
@param[in]      achp_plaintext  Buffer with the plaintext.
@param[in]      inp_data_len    Length of plaintext.
@param[in]      adsp_key        The key structure. Must be 16 byte aligned.
*/
extern void m_enc_update_aes_gcm_1(struct dsd_aes_gcm_state* adsp_state,
                                   char* achp_ciphertext,
                                   const char* achp_plaintext,
                                   int inp_data_len);

/**
Performs one decryption step of a multi-step AES GCM decryption.

The generated plaintext will be as long as the ciphertext.
Length is not restricted.
achp_ciphertext and achp_plaintext may be identical.
This function can be called any number of times, including 0 times.
m_init_aes_gcm_1 must be called beforehand.

@param[inout] adsp_state      State structure. Must be 16 byte aligned.
@param[out]   achp_plaintext  Buffer for the plaintext.
@param[in]    achp_ciphertext Buffer with the ciphertext.
@param[in]    inp_data_len    Length of ciphertext.
@param[in]    adsp_key        The key structure. Must be 16 byte aligned.
*/
extern void m_dec_update_aes_gcm_1(struct dsd_aes_gcm_state* adsp_state,
                                   char* achp_plaintext,
                                   const char* achp_ciphertext,
                                   int inp_data_len);

/**
Performs the final steps of a multi-step AES GCM encryption, generating the MAC tag.

Valid tag length are 16, 15, 14, 13, 12, 8 and 4 bytes.
After calling this function, m_enc_update_aes_gcm_1 may no longer be called.

Security-critical data in the state will be cleared by this function.

@param[inout] adsp_state    Pointer to the state structure. Must be 16 byte aligned.
@param[out]   achp_tag      Buffer to write the tag to.
@param[in]    inp_tag_len   Requested tag length.
*/
extern void m_enc_final_aes_gcm_1(struct dsd_aes_gcm_state* adsp_state,
                                  char* achp_tag,
                                  int inp_tag_len);

/**
Performs the final steps of a multi-step AES GCM encryption, validating the MAC tag.

Valid tag length are 16, 15, 14, 13, 12, 8 and 4 bytes.
After calling this function, m_dec_update_aes_gcm_1 may no longer be called.

Security-critical data in the state will be cleared by this function.

@param[inout] adsp_state    Pointer to the state structure. Must be 16 byte aligned.
@param[out]   achp_tag      Buffer with the tag.
@param[in]    inp_tag_len   Length of the tag.

@return FALSE, if the tag is not valid.
*/
extern BOOL m_dec_final_aes_gcm_1(struct dsd_aes_gcm_state* adsp_state,
                                  const char* achp_tag,
                                  int inp_tag_len);

/**
* Encrypts a data block with AES in ECB mode of operation.
*
* The data has to be padded to a multiple of 16 byte.
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param pEncKeyStruc Pointer to precomputed
*               AES encrypt subkey structure
*  @param BlkCnt Number of 16 byte AES blocks
*  @param Rounds Number of rounds
*/
extern void AES_Fast_ecb_encrypt(const unsigned char * input,
                                 unsigned char * output,
                                 const ds_aes_key * pEncKeyStruc,
                                 size_t BlkCnt,
                                 int Rounds);

/**
* Decrypts a data block with AES in ECB mode of operation.
*
* The length of the input data must be a multiple of the AES block length.
*
*  @param input Pointer to input data buffer
*  @param output Pointer to output data buffer
*  @param pDecKeyStruc Pointer to precomputed
*               AES decrypt subkey structure
*  @param BlkCnt Number of 16 byte AES blocks
*  @param Rounds Number of rounds
*/
extern void AES_Fast_ecb_decrypt(const unsigned char * input,
                                 unsigned char * output,
                                 const ds_aes_key * pDecKeyStruc,
                                 size_t BlkCnt,
                                 int Rounds);


#if defined USE_ASSEMBLER_SOURCES

/**
* Checks, if the CPU has AES support.
*
* @return 0, if no CPU AES is available, non-0 otherwise
*/
extern int m_check_cpu_support_aes(void);
extern void m_aes_cbc_cpu_encrypt(const unsigned char * abyp_in,
                                  unsigned char * abyp_out,
                                  unsigned char * abyp_key,
                                  size_t szp_block_count,
                                  unsigned char * abyp_ivec,
                                  int imp_number_of_rounds);

extern void m_aes_cbc_cpu_decrypt(const unsigned char * abyp_in,
                                  unsigned char * abyp_out,
                                  unsigned char * abyp_key,
                                  size_t szp_block_count,
                                  unsigned char * abyp_ivec,
                                  int imp_number_of_rounds);

extern void m_aes_ecb_cpu_encrypt(const unsigned char * abyp_in,
                                  unsigned char * abyp_out,
                                  unsigned char * abyp_key,
                                  size_t szp_block_count,
                                  int imp_number_of_rounds);

extern void m_aes_ecb_cpu_decrypt(const unsigned char * abyp_in,
                                  unsigned char * abyp_out,
                                  unsigned char * abyp_key,
                                  size_t szp_block_count,
                                  int imp_number_of_rounds);

extern void m_aes_128_cpu_key_expansion(const unsigned char * abyp_userkey,
                                        unsigned char * abyp_key);

extern void m_aes_192_cpu_key_expansion(const unsigned char * abyp_userkey,
                                        unsigned char * abyp_key);

extern void m_aes_256_cpu_key_expansion(const unsigned char * abyp_userkey,
                                        unsigned char * abyp_key);

/**
* Generates AES encryption subkey tab, using CPU AES routines.
*
*  @param abyp_userkey Pointer to buffer containing key bytes
*  @param szp_dwords Number of 32 bit words in the key buffer
*  @param adsp_keytab Preallocated keytab to be filled
*/
extern void m_aes_cpu_set_encrypt_key(const unsigned char * abyp_userkey,
                                      const size_t szp_dwords,
                                      ds_aes_key * adsp_key);

/**
* Generates AES decryption subkey tab, using CPU AES routines.
*
*  @param abyp_userkey Pointer to buffer containing key bytes
*  @param szp_dwords Number of 32 bit words in the key buffer
*  @param adsp_keytab Preallocated keytab to be filled
*/
extern void m_aes_cpu_set_decrypt_key(const unsigned char * abyp_userkey,
                                      const size_t szp_dwords,
                                      ds_aes_key * adsp_key);

/**
* Generates an AES encryption subkey tab. A check is done, if the CPU supports
* AES and if so, sets a respective flag for later encryption operations.
*
*  @param abyp_userkey Pointer to buffer containing key bytes
*  @param szp_dwords Number of 32 bit words in the key buffer
*  @param adsp_keytab Preallocated keytab to be filled
*/
extern void m_aes_set_encrypt_key(const unsigned char * abyp_userkey,
                                  size_t szp_dwords,
                                  ds_aes_key * adsp_keytab);

/**
* Generates an AES decryption subkey tab. A check is done, if the CPU supports
* AES and if so, sets a respective flag for later decryption operations.
*
*  @param abyp_userkey Pointer to buffer containing key bytes
*  @param szp_dwords Number of 32 bit words in the key buffer
*  @param adsp_keytab Preallocated keytab to be filled
*/
extern void m_aes_set_decrypt_key(const unsigned char * abyp_userkey,
                                  size_t szp_dwords,
                                  ds_aes_key * adsp_keytab);

/**
* Encrypts a data block with AES in CBC mode of operation, using CPU AES, if
* it is available.
*
* The data has to be padded to a multiple of 16 byte.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES encrypt subkey structure
*  @param szp_block_count Number of 16 byte AES blocks
*  @param abyp_iv Initialization vector
*  @param imp_rounds Number of rounds
*/
extern void m_aes_cbc_encrypt(const unsigned char * abyp_input,
                              unsigned char * abyp_output,
                              const ds_aes_key * adsp_key,
                              size_t szp_block_count,
                              unsigned char * abyp_iv,
                              int imp_rounds);

/**
* Decrypts a data block with AES in CBC mode of operation, using CPU AES, if
* it is available.
*
* The length of the input data must be a multiple of the AES block length.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES decrypt subkey structure
*  @param szp_block_count Number of 16 byte AES blocks
*  @param abyp_iv Initialization vector
*  @param imp_rounds Number of rounds
*/
extern void m_aes_cbc_decrypt(const unsigned char * abyp_input,
                              unsigned char * abyp_output,
                              const ds_aes_key * adsp_key,
                              size_t szp_block_count,
                              unsigned char * abyp_iv,
                              int imp_rounds);

/**
* Encrypts a data block with AES in ECB mode of operation, using CPU AES, if
* it is available.
*
* The data has to be padded to a multiple of 16 byte.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES encrypt subkey structure
*  @param szp_block_count Number of 16 byte AES blocks
*  @param imp_rounds Number of rounds
*/
extern void m_aes_ecb_encrypt(const unsigned char * abyp_input,
                              unsigned char * abyp_output,
                              const ds_aes_key * adsp_key,
                              size_t szp_block_count,
                              int imp_rounds);

/**
* Decrypts a data block with AES in ECB mode of operation, using CPU AES, if
* it is available.
*
* The length of the input data must be a multiple of the AES block length.
*
*  @param abyp_input Pointer to input data buffer
*  @param abyp_output Pointer to output data buffer
*  @param adsp_key Pointer to precomputed
*               AES decrypt subkey structure
*  @param szp_block_count Number of 16 byte AES blocks
*  @param imp_rounds Number of rounds
*/
extern void m_aes_ecb_decrypt(const unsigned char * abyp_input,
                              unsigned char * abyp_output,
                              const ds_aes_key * adsp_key,
                              size_t szp_block_count,
                              int imp_rounds);

extern void m_aes_cpu_revert_key(unsigned char * adsp_key,
                                 unsigned char * adsp_rev_key,
                                 size_t szp_rounds);

#endif // USE_ASSEMBLER_SOURCES


#if HOB_WIN64_ASM == 1

extern int GenAESEncryptKeys(const unsigned char * AesKey, 
                             int Offset,
                             size_t AesKeyLen, 
                             unsigned int * EncKeyTab);

extern int GenAESDecryptKeys(const unsigned char * AesKey, 
                             int Offset,
                             size_t AesKeyLen, 
                             unsigned int * DecKeyTab);

#endif //HOB_WIN64_ASM == 1


/** @} */
/** @addtogroup hmem
* @{
*/
//==============================================================
// Memory manager for Largenumber System/RSA/DSA
//==============================================================
 
/**
* This structure is used for information passing during memory initialization.
* Used with the Callback function (if supplied).
*/
typedef struct HMEMINFO_t {
  int InfoStrucSize;   //!< for versioning
  int InitialByte16BlockCount; //!< number of 16  Byte blocks to use
  int InitialByte32BlockCount; //!< number of 32  Byte blocks to use
  int InitialByte64BlockCount; //!< number of 64  Byte blocks to use
  int InitialByte256BlockCount; //!< number of 256 Byte blocks to use
  int InitialByte512BlockCount; //!< number of 512 Byte blocks to use
  int InitialPoolSize;  //!< initial pool buffer size
  int InitialPoolCount;  //!< initial pool count
} HMEMINFO;

/**
* This structure transports the information needed for the local memory manager
* throughout all functions dealing with memory allocations / freeing.
*/
typedef struct ds__hmem_t {
   int in__struc_size;         //!< for version control
   int in__flags;  //!< control flags
   int in__aux_up_version; //!< 0 - V1, 1 - V2
   int (* pMemSizeInfoCallback)(struct HMEMINFO_t *); //!< info callback/NULL
   struct HMEMDESC_t * pHmemDesc; //!< internal memory manager desc.
   void * vp__context;             //!< context for allocation function
   BOOL (* am__aux1)(int in__funct,
                     void * vp__p_mem,
                     int  in__size);  //!< allocation / free function (old)
   BOOL (* am__aux2)(void * vp__p_ctx,
                     int in__funct,
                     void * vp__p_mem,
                     int  in__size);  //!< allocation / free function (new)
} ds__hmem;

/**
* Frees management buffer structures (HMemMgrFree).
*
*  @param vp__ctx Pointer to the used memory information structure
*/
extern void HMemMgrFree(ds__hmem * vp__ctx);

/**
* Frees a buffer from the buffer pool (or small buffers/direct) (m__hpoolfree).
* Mode of operation: TBD !!!
*
*  @param vp__ctx Pointer to the used memory information structure
*  @param ach_ppool_mem
*/
extern void m__hpoolfree(ds__hmem * vp__ctx,
                         void * ach_ppool_mem);

/**
* Allocates a buffer from the buffer pool (m__hpoolmalloc).
* Mode of operation: TBD !!!
*
*  @param vp__ctx Pointer to the used memory information structure
*  @param in__memory_size requested amount of storage
*  @return BIT8PTR ach__pmem / NULL
*/
extern char * m__hpoolmalloc(ds__hmem * vp__ctx,
                             int in__memory_size);

/** 
* Acts as malloc().
*
* The memory is associated with the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param in__memory_size Bytes to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hextmalloc(ds__hmem * ads__p_hmem_struc,
                            int in__memory_size);

/**
* Acts as malloc().
*
* The memory is independent from the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param in__memory_size Bytes to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hextmalloc_glbl(ds__hmem * ads__p_hmem_struc,
                                 int in__memory_size);

/** 
* Acts as calloc().
*
* The memory is associated with the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param in__element_cnt Element count to be allocated
* @param in__element_size Element size to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hextcalloc(ds__hmem * ads__p_hmem_struc,
                            int in__element_cnt,
                            int in__element_size);

/** 
* Acts as calloc().
*
* The memory is independent from the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param in__element_cnt Element count to be allocated
* @param in__element_size Element size to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hextcalloc_glbl(ds__hmem * ads__p_hmem_struc,
                                 int in__element_cnt,
                                 int in__element_size);

/**
* Acts as free().
*
* The memory must be associated with the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param vp__p_mem Pointer to memory to be freed
*/
extern void m__hextfree(ds__hmem * ads__p_hmem_struc,
                        void * vp__p_mem);

/**
* Acts as free().
*
* The memory must be independent from the current session.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param vp__p_mem Pointer to memory to be freed
*/
extern void m__hextfree_glbl(ds__hmem * ads__p_hmem_struc,
                             void * vp__p_mem);

/** 
* Acts as malloc(). 
*
* The memory is either from the local pools or from the WSP.
*
* @param ads__p_hmem_struc Pointer to context structure
* @param in__memory_size Bytes to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hmalloc(ds__hmem * ads__p_hmem_struc,
                         int in__memory_size);

/** 
* Acts as calloc().
*
* The memory is either from the local pools or from the WSP.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param in__element_cnt Element count to be allocated
* @param in__element_size Element size to be allocated
* @return Pointer to newly allocated memory */
extern void * m__hcalloc(ds__hmem * ads__p_hmem_struc,
                         int in__element_cnt,
                         int in__element_size);

/**
* Acts as free().
*
* The memory must be either from the local pools or from the WSP.
*
* @author goe
* @version 1.0
* @param ads__p_hmem_struc Pointer to context structure
* @param vp__p_mem Pointer to memory to be freed
*/
extern void m__hfree(ds__hmem * ads__p_hmem_struc,
                     void * vp__p_mem);

/**
* Allocate a control structure, fill with appropriate values
*
*  @param InterfaceMode 0- V1, else V2
*  @return Allocated, filled structure / NULL
*/
extern ds__hmem * AllocFillMemCtxStruc(int InterfaceMode);

//-------------------------------------------------------
// Macros for memory allocation
//-------------------------------------------------------
#if !defined XH_INTERFACE
#define HMEM_CTX_DEF
#define HMEM_CTX_DEF1
#define HMEM_CTX_REF
#define HMEM_CTX_REF1
#define LOAD_HMEM_CTX_PTR(a)

#define BIT8_ARRAY_ALLOC(Ctx,Size)  (char *) malloc(Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)     (char *) malloc(Size)
#define BIT8_ARRAY_ALLOCEX_GLBL(Ctx,Size) (char *) malloc(Size)
#define BIT8_ARRAY_ALLOC_POOL(Ctx,Size)  (char *) malloc(Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)  (char *) calloc(Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size) (char *) calloc(Cnt,Size)
#define BIT8_ARRAY_CALLOCEX_GLBL(Ctx,Cnt,Size) (char *) calloc(Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)  (short *) malloc((Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)  (short *) malloc((Size)*2)
#define BIT16_ARRAY_ALLOC_POOL(Ctx,Size) (short *) malloc((Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)  (int *) malloc((Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size)       (int *) malloc((Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size)     (int *) malloc((Size)*sizeof(int))
#else // XH_INTERFACE

#define HMEM_CTX_DEF ds__hmem * vp__ctx,
#define HMEM_CTX_DEF1 ds__hmem * vp__ctx

#define HMEM_CTX_REF vp__ctx
#define HMEM_CTX_REF1 vp__ctx,
#define LOAD_HMEM_CTX_PTR(a) vp__ctx = a

#define BIT8_ARRAY_ALLOC(Ctx,Size)   (char *) m__hmalloc(Ctx,Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)      (char *) m__hextmalloc(Ctx,Size)
#define BIT8_ARRAY_ALLOCEX_GLBL(Ctx,Size) (char *) m__hextmalloc_glbl(Ctx,Size)
#define BIT8_ARRAY_ALLOC_POOL(Ctx,Size)   (char *) m__hpoolmalloc(Ctx,Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)   (char *) m__hcalloc(Ctx,Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size) (char *) m__hextcalloc(Ctx,Cnt,Size)
#define BIT8_ARRAY_CALLOCEX_GLBL(Ctx,Cnt,Size) (char *) m__hextcalloc_glbl(Ctx,Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)   (short *) m__hmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)   (short *) m__hextmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOC_POOL(Ctx,Size)  (short *) m__hpoolmalloc(Ctx,(Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)   (int *) m__hmalloc(Ctx,(Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size) \
          (int *) m__hmalloc(Ctx,(Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size) \
          (int *) m__hextmalloc(Ctx,(Size)*sizeof(int))
#endif // XH_INTERFACE
//--------------------------------------------------------
// Macros for freeing allocated arrays
//--------------------------------------------------------
#if !defined XH_INTERFACE
#define FREE_ARRAY(ctx,a)      if((a) != 0) {free(a);a = 0;}
#define FREE_ARRAYEX(ctx,a)    if((a) != 0) {free(a);a = 0;}
#define FREE_ARRAYEX_GLBL(ctx,a) if((a) != 0) {free(a);a = 0;}
#define FREE_ARRAY_POOL(ctx,a) if((a) != 0) {free(a);a = 0;}
#define FREE_CARRAY(ctx,a)     if((a) != 0) {free(a);a = 0;}
#define FREE_CARRAYEX(ctx,a)   if((a) != 0) {free(a);a = 0;}
#define MEMMGR_FREE(ctx)
#else
#define FREE_ARRAY(ctx,a)      if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define FREE_ARRAYEX(ctx,a)    if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define FREE_ARRAYEX_GLBL(ctx,a) if((a) != 0) {m__hextfree_glbl(ctx,a);a = 0;}
#define FREE_ARRAY_POOL(ctx,a) if((a) != 0) {m__hpoolfree(ctx,a);a = 0;}
#define FREE_CARRAY(ctx,a)     if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define FREE_CARRAYEX(ctx,a)   if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define MEMMGR_FREE(ctx)     HMemMgrFree(ctx);
#endif // XH_INTERFACE

/** @} */
/** @addtogroup rand
* @{
*/
//==============================================================
// Random generator
//==============================================================

/**
* SecGetSystemTimeUTC - Get system time in 
* UTC format (seconds rel 00:00 01.01.1970).
*
*
*  @return  int time
*/
extern int SecGetSystemTimeUTC(void);

/**
* SecDrbgInit - Initialize the secure random generator.
* <br><br>
* Fetch 32 bytes entropy from the system, initialize structure
* and set global initialized flag.
*
* This function is thread-safe. It is implemented by SecDrbgInit_impl.
*
*  @return int state 
*  <br>         > 0 o.k.
*  <br>         <= 0 fetch entropy failed
*/
extern int SecDrbgInit(HMEM_CTX_DEF1);

/**
* SecDrbgRandBytes - Get random data output.
* <br><br>
* Fetch random bytes from secure random generator. 
* If reseed is required, fetch 32 byte entropy from 
* system and reseed the generator.
*
* This function is thread-safe. It is implemented by SecDrbgRandBytes.
* 
*  @param ainp_pdstbuf Destination for output
*  @param inp_dstoff start of data in buffer
*  @param inp_dstlen size of data requested
*  @return int state 
*  <br>         == 0 o.k.
*  <br>         < 0 fetch entropy failed/DRBG not initialized
*/
extern int SecDrbgRandBytes(HMEM_CTX_DEF
                            char * pOutData,
                            int OutOff,
                            int OutLen);

/**
* SecDrbgRandBytes_Test
* Fetch random bytes from secure random generator without 
* reseed checking or update. 
* This function/method is for testing purposes only !!!
*
* This function is thread-safe. It is implemented by SecDrbgRandBytes_Test_impl.
*
*  @param ainp_pdstbuf Destination for output
*  @param inp_dstoff Start of data in buffer
*  @param inp_dstlen Size of data requested
*  @return int state 
*  <br>            == 0 o.k.
*  <br>            != 0 fetch entropy failed/
*                       DRBG not initialized
*/
extern int SecDrbgRandBytes_Test(HMEM_CTX_DEF 
                                 char * pDstBuf,
                                 int DstOff, 
                                 int DstLen);

/**
* m_secdrbg_randbytes  <br>
* Fetch random bytes from secure random generator and 
* seed or reseed the generator if required.
*
* This function is thread-safe. It is implemented by m_secdrbg_randbytes_impl.
*
*  @param abyrp_dstbuf Destination for output
*  @param imp_dstlen Size of data requested
*  @return int state  
*  <br>        == 0 o.k.
*  <br>        != 0 fetch Entropy failed/DRBG not initialized
*/
extern int m_secdrbg_randbytes(char * abyrp_dstbuf,
                               int imp_dstlen);


/**
* CTR_DRBG_AddSeed256 - Add extra entropy data.
* <br><br>
* Adds given entropy to DRBG, hashes Input data and 
* updates the DRBG Key and Count.  <br>
* The reseed counter stays unaffected. The passed data 
* array must be cleared after calling this function !!  <br>
*
* This function is thread-safe. it is implemented by CTR_DRBG_AddSeed256_impl.
* 
*  @param abyrp_newentropy  entropy input
*  @param imp_entropylen  size of input
*  @return int state - 0 o.k., else error occurred
*/
extern int  CTR_DRBG_AddSeed256(char* abyrp_newentropy,
                                int imp_entropylen);

/**
Function pointer definition for accessing RNG.

The entire buffer will be filled with random bytes.

@param[in]  vpp_user_field Pointer to 'user field'.
@param[out] achp_dest      Pointer to buffer to be filled.
@param[in]  inp_dest_len   Length of buffer in bytes.

@return TRUE on success, FALSE on error.
*/
typedef BOOL ( * amd_get_random )( void * vpp_user_field, char * achp_dest, int inp_dest_len);


/**
* m_add_qualified_seed - fetch entropy from the system or a proper 
* alternative seed source.
* <br><br>
* This function fetches 32 bytes entropy from the seeder, checks return 
* values from the entropy estimation process and passes the seed data 
* to the instantiation or the reseeding function.
* The seeder is determined by compiler switch "ALT_SEEDING_SOURCE".
*
*
*  @param imp_init   Initialization mode: 0=reseed, 1=instantiation
*  @param achp_caller_func_name   the name of the caller function as 
*                                 'const char' array that is added to 
*                                  the message output.
*  @return int state 
*  <br>         > 0 o.k.
*  <br>         <= 0 fetch entropy failed
*/
extern int m_add_qualified_seed(HMEM_CTX_DEF 
                                int imp_init, 
                                const char * achp_caller_func_name);

#ifdef XH_INTERFACE
/**
Initializes the DRBG to use the aux function for seeding.

32 byte of entropy are fetched by the aux function DEF_AUX_SECURE_RANDOM_SEED
and used to seed the DRBG. The DRBG can then be used as normal. 
DEF_AUX_SECURE_RANDOM_SEED is used for reseeding. Since m_secdrbg_randbytes
does not provide parameters for the aux function or user field, the internal 
seeder is used as fall-back, should this function trigger a reseed.
If the DRBG is already initialized, an error is returned.

@param[in]  amp_aux         Aux function for the seeding process.
@param[in]  avop_user_field User field to be used with the aux function.

@return >0 on success, <= 0 if initialization failed.
*/
extern int m_init_random_aux(BOOL (* amp_aux)(void * vp__p_ctx,
                                              int in__funct,
                                              void * vp__p_mem,
                                              int  in__size),
                             void* avop_user_field);
#endif

/** @} */
/** @addtogroup lnum32
* @{
*/
//==============================================================
// Large number system
//==============================================================
   
/**
* This structure is the internal representation of a large unsigned integer 
* number (called 'large number'). 
*
* NOTE: The representation of the number zero is a large number structure with 
* used element size == 0.
*/
typedef struct WLARGENUM_t {
  /** Number of allocated <code>int</code> elements in lpEl. */
  int AllocSize;
  /** Number of actually used <code>int</code> elements in lpEl. */
  int UsedSize;
  /** Pointer to the actual <code>int</code> array, holding the number 
  *   itself. */
  int * lpEl;
}WLARGENUM;

/**
* This structure is used to hold large number structures that are needed for
* temporary usage during calculations. This reduces the overhead of repeated 
* allocating/freeing of these structures.
*/
typedef struct WLNUM_CONTEXT_t {
  /** Number of allocated <code>WLARGENUM</code> structures in this context. */
  int AllocedNumCnt;
  /** Index of the next available element. */
  int NextFreeIndex;
  /** Array of pointers to the allocated <code>WLARGENUM</code> structures. */
  WLARGENUM** pWLnumArr;
} WLNUM_CONTEXT;


/**
* This structure is used for calculations using Montgomery multiplication.
*/
typedef struct MONT_CONTEXT_t {
  /** Modulus n saver. */
  WLARGENUM* pModN;
  /** Associated r**2 (mod n). */
  WLARGENUM* pRSquare;
  /** Temporary number for processing. */
  WLARGENUM* pTmpLnum;
  /** Temporary number for processing. */
  WLARGENUM* pTmpMontLnum;
  /** Element count of r. */
  int sLen;
  /** Inverse of n[0]. */
  int Ni0;
} MONT_CONTEXT;

//---------------------------------------------------------------
// These defines are used for compatibility to older header versions
//---------------------------------------------------------------

#define MONT_CTX MONT_CONTEXT
#define WLNUM WLARGENUM
#define WLNUM_CTX WLNUM_CONTEXT

// Comparison codes

#define WLNUM_1ST_GT_2ND 1 // 1st is > 2nd
#define WLNUM_1ST_EQ_2ND 0 // 1st is same as 2nd
#define WLNUM_1ST_LT_2ND -1 // 1st is < 2nd

// Flags for types of blinding for exponentiation

#define  WLNUM_USE_BASE_BLINDING 0x01  // Apply base blinding
#define  WLNUM_USE_MOD_BLINDING  0x02  // Apply modulus blinding
#define  WLNUM_USE_EXP_BLINDING  0x04  // Apply exponent blinding


//===========================================
// Global Returncodes
//===========================================
#define LNUM_OP_OK  0 // operation o.k.

//===============================================
// Specific Returncodes, range from -600 ... -619
//===============================================
//-------------------------------------------
// Returncodes from all the functions
//-------------------------------------------
#define LNUM_OP_NULL_PTR -600 // no structure Pointer (NULL)
#define LNUM_OP_ALLOC_ERR -601 // Element/Struct alloc error
#define LNUM_OP_ZERO_DIV -602 // Division by zero
#define LNUM_OP_RECIP_ERR -603 // Reciprocal error
#define LNUM_OP_NO_INVERSE -604 // Inverse mod. not declared
#define LNUM_OP_ZERO_SIZE -605 // invalid bitcount/bytecount
#define LNUM_OP_INVALID_PRIME -606 // a prime <> 2 is even, etc.

#define LNUM_OP_INVALID_MONT_MODULUS -607 // montgomery modulus even/0

#define LNUM_OP_PARAM_ERR -610
#define LNUM_OP_CTX_FULL -611

//---------------------------------------------------------
// Externals
//---------------------------------------------------------

/**
* Calculates the number of 'used'
* byte positions within an <code>int</code> element (HardGetByteCntWLnumElem).
* Used for conversion
* routines.
* Example: If no bits set     -> 0
*     If top most bit set (and probably others) -> 4
*
*  @param WElement <code>int</code> element to be checked
*  @return Number of used bytes
*/
extern int HardGetByteCntWLnumElem(int WElement);

/**
* Calculates the number of 'used'
* bit positions within an <code>int</code> Element (HardGetBitCntWLnumElem).
* Used for normalization
* purposes and shifting routines.
* Example: If no bits set     -> 0
*     If top most bit set (and propably others) -> 32
*
*  @param WElement <code>int</code> element to be checked
*  @return Number of used bits
*/
extern int HardGetBitCntWLnumElem(int WElement);

/**
* Clears WLarge Number buffer and sets used size = 0 (ClearWLnumElements).
*
*  @param pWLnum Structure pointer
*/
extern void ClearWLnumElements(WLARGENUM* pWLnum);

/**
* Calculates the number of used bytes in a
* a <code>WLARGENUM</code> (GetByteCntWLnum).
*
*  @param pNum Pointer to number structure
*  @return Number of used bytes
*/
extern int GetByteCntWLnum(WLARGENUM* pNum);

/**
* Calculates the number of used bits in a
* a <code>WLARGENUM</code> (GetBitCntWLnum).
*
*  @param pNum Pointer to number structure
*  @return Number of used bits
*/
extern int GetBitCntWLnum(WLARGENUM* pNum);

/**
* Compares the content of two WLarge numbers (UcompWLnum).
* NOTE:
* <ul>
* <li> Structure pointers must be valid, not checked !!
* <li> No leading 0 Elements are allowed !!!
* </ul>
*
*  @param pU Pointer to number u
*  @param pV Pointer to number v
*  @return LNUM_1ST_GT_2ND (1) u > v
* <br>            LNUM_1ST_LT_2ND(-1) u < v
* <br>            LNUM_1ST_EQ_2ND (0) u = v
*/
extern int UcompWLnum(WLARGENUM* pU, 
                      WLARGENUM* pV);

/**
* Checks if a WLarge number u is 0 (IsZeroWLnum).
*
*  @param pU Pointer to number u
*  @return == 0 -> u is not 0
* <br>            != 0 -> u is 0
*/
extern int IsZeroWLnum(WLARGENUM* pU);

/**
* Checks if a WLarge number u is 1 (IsOneWLnum).
*
*  @param pU Pointer to number u
*  @return == 0 -> u is not equal 1
* <br>            != 0 -> u is equal 1
*/
extern int IsOneWLnum(WLARGENUM* pU);

/**
* Allocates control structure and <code>int</code> buffer
* (if requested) for a new WLarge number (AllocNewWLnum).
*
*  @param Size Required element count
*  @return Pointer to the new large number structure <br> NULL on error
*/
extern WLARGENUM* AllocNewWLnum(HMEM_CTX_DEF
                                int Size);

/**
* Frees buffer and control structure for a
* WLarge number (FreeWLnum). 
* If a NULL pointer is passed, no action is
* performed.
*
*  @param pWLnum Structure pointer
*/
extern void FreeWLnum(HMEM_CTX_DEF
                      WLARGENUM* pWLnum);

/**
* Clears the content of a WLarge number structure and frees the buffers and
* the structure itself (ClearFreeWLnum).
* If a NULL pointer is passed, no action is performed.
*
*  @param pWLnum Structure pointer
*/
extern void ClearFreeWLnum(HMEM_CTX_DEF
                           WLARGENUM* pWLnum);

/**
* Allocates/reallocates the element buffer of a given WLarge number control 
* structure (AllocWLnumElements).
*
* NOTE: No parameters checked !!!
*
* NOTE: The content of an already allocated buffer is
*       maintained up to min(requested,allocated) Elements
*
*  @param pWLnum Structure pointer
*  @param NewSize New requested size
*  @return 0 on success, error code otherwise
*/
extern int AllocWLnumElements(HMEM_CTX_DEF
                              WLARGENUM* pWLnum, 
                              int NewSize);

/**
* Frees a WLarge number work context, its WLnum Structures and
* their Elements (FreeWLnumContext).
*
*  @param pCtx Pointer to context
*/
extern void FreeWLnumContext(HMEM_CTX_DEF
                             WLNUM_CONTEXT* pCtx);

/**
* Allocates a WLarge number work context with a number of preallocated elements (AllocWLnumContext).
*
*  @param NumCnt Number of elements to allocate
*  @param ElementSize Size of elements to allocate
*  @return New <code>WLNUM_CTX_PTR</code><br>NULL if alloc failed
*/
extern WLNUM_CONTEXT* AllocWLnumContext(HMEM_CTX_DEF
                                        int NumCnt,
                                        int ElementSize);

/**
* Gets a WLarge number structure of required size from a work context (GetWLnumFromContext).
* Reallocates element buffer if needed. Used size is set to 0.
*
*  @param pCtx Pointer to context
*  @param ElementSize Size of element needed
*  @param ppWLnum Pointer to return the number element to
*  @return 0 on success, error code otherwise
*/
extern int GetWLnumFromContext(HMEM_CTX_DEF
                               WLNUM_CONTEXT* pCtx, 
                               int ElementSize,
                               WLARGENUM* ppWLnum[]);

/**
* Gets a WLarge number structure of required size from a work context (GetWLnumPtrFromContext).
* Reallocates element buffer if needed. Used size is set to 0.
*
*  @param pCtx pointer to context
*  @param ElementSize Size of element needed
*  @return A <code>WLNUM_PTR</code>/ NULL on error
*/
extern WLARGENUM* GetWLnumPtrFromContext(HMEM_CTX_DEF
                                         WLNUM_CONTEXT* pCtx, 
                                         int ElementSize);

/**
* Release n WLarge numbers from work context, do NOT free (ReleaseWLnumsFromContext).
*
*  @param pCtx Pointer to Context
*  @param WLnumCnt Number of elements to release
*/
extern void ReleaseWLnumsFromContext(WLNUM_CONTEXT* pCtx, 
                                     int WLnumCnt);

/**
* Makes a deep copy of a <code>WLARGENUM</code>, reallocating if necessary (CopyWLnum).
* Destination must not be same as source.
*
*  @param pDst Pointer to destination
*  @param pSrc Pointer to source
*  @return 0 on success, error code otherwise
*/
extern int CopyWLnum(HMEM_CTX_DEF
                     WLARGENUM* pDst,
                     WLARGENUM* pSrc);

/**
* Shifts a WLarge number to the left u by n bits (LshiftWLnum).
* Destination and source may be the same.
*
*  @param pR Pointer to destination buffer
*  @param pU pointer to number u
*  @param sBitcnt Number of bits to shift, >= 0 !!
*  @return 0 on success, error code otherwise
*/
extern int LshiftWLnum(HMEM_CTX_DEF
                       WLARGENUM* pR, 
                       WLARGENUM* pU, 
                       int sBitcnt);

/**
* Shifts a WLarge number u one bit to the left (Lshift1WLnum).
* Destination and source may be the same.
*
*  @param pR Pointer to destination buffer
*  @param pU pointer to number u
*  @return 0 on success, error code otherwise
*/
extern int Lshift1WLnum(HMEM_CTX_DEF
                        WLARGENUM* pR,
                        WLARGENUM* pU);

/**
* Shifts a WLarge number u to the right by n bits (RshiftWLnum).
* Destination and source may be the same.
*
*  @param pR Pointer to destination buffer
*  @param pU pointer to number u
*  @param sBitcnt Number of bits to shift
*  @return 0 on success, error code otherwise
*/
extern int RshiftWLnum(HMEM_CTX_DEF
                       WLARGENUM* pR, 
                       WLARGENUM* pU, 
                       int sBitcnt);

/**
* shifts a WLarge number u 1 bit right (Rshift1WLnum).
* Destination and source may be the same.
*
*  @param pR Pointer to destination buffer
*  @param pU pointer to number u
*  @return 0 on success, error code otherwise
*/
extern int Rshift1WLnum(HMEM_CTX_DEF
                        WLARGENUM* pR, 
                        WLARGENUM* pU);

/**
* Adds two WLarge numbers u and v (AddWLnum).
* Destination and source may be the same.
*
*  @param pSum Pointer to destination buffer
*  @param pU Pointer to number u
*  @param pV Pointer to number v
*  @return 0 on success, error code otherwise
*/
extern int AddWLnum(HMEM_CTX_DEF
                    WLARGENUM* pSum,
                    WLARGENUM* pU,
                    WLARGENUM* pV);

/**
* Adds a <code>int</code> value to a WLarge number (AddElementWLnum).
* The Destination is also the source.
*
*  @param pWnumU Large number structure
*  @param Summand <code>int</code> summand
*  @return 0 on success, error code otherwise
*/
extern int AddElementWLnum(HMEM_CTX_DEF
                           WLARGENUM* pWnumU,
                           int Summand);

/**
* Calculates the absolute difference of two WLarge numbers u and v (SubWLnum).
* Destination and source may be the same.
*
*  @param pDif Pointer to destination buffer
*  @param pU Pointer to number u
*  @param pV Pointer to number v
*  @return 0 on success, error code otherwise
*/
extern int SubWLnum(HMEM_CTX_DEF
                    WLARGENUM* pDif, 
                    WLARGENUM* pU, 
                    WLARGENUM* pV);

/**
* Calculates the difference of a
* Wlarge number and a given <code>int</code> value (SubElementWLnum).
* The Destination is also the source.
*
* Note: It is assumed that the large number is larger/same than the subtrahend!!
*
*  @param pWnumU Large number structure
*  @param Subtrahend <code>int</code> subtrahend
*  @return 0 on success, error code otherwise
*/
extern int SubElementWLnum(WLARGENUM* pWnumU,
                           int Subtrahend);

/**
* Multiplies two WLarge numbers u and v (MulWLnum). Result parameter must be different from 
* input parameters.
*
*  @param pProd Pointer to destination buffer
*  @param pU Pointer to multiplicand u
*  @param pV Pointer to multiplier v
*  @return 0 on success, error code otherwise
*/
extern int MulWLnum(HMEM_CTX_DEF
                    WLARGENUM* pProd, 
                    WLARGENUM* pU,
                    WLARGENUM* pV);

/**
* Square WLarge number u (SquareWLnum). Result parameter must be different from 
* input parameters.
*
*  @param pProd Pointer to destination buffer
*  @param pU Pointer to multiplicand u
*  @return 0 on success, error code otherwise
*/
extern int SquareWLnum(HMEM_CTX_DEF
                       WLARGENUM* pProd, 
                       WLARGENUM* pU);

/**
* Divides WLarge number u by v, producing
* quotient (if requested) and remainder (if requested) (DivWLnum).
* If a destination pointer is NULL, this part of the
* result will not be generated/stored. At least one result
* pointer must be <> NULL.
* Destinations must be different from sources.
*
* Uses algorithm taken from D.E.Knuth (II).
*
*  @param pQuot Pointer to quotient or NULL
*  @param pRem Pointer to remainder or NULL
*  @param pU Pointer to dividend u
*  @param pV Pointer to divisor v
*  @param pCtx Work context. Optional
*  @return 0 on success, error code otherwise
*/
extern int DivWLnum(HMEM_CTX_DEF
                    WLARGENUM* pQuot, 
                    WLARGENUM* pRem,
                    WLARGENUM* pU,
                    WLARGENUM* pV, 
                    WLNUM_CONTEXT* pCtx);

/**
* Divides WLarge number u by v, producing
* quotient only (QuotWLnum).
* Destinations must be different from sources.
*
* Uses algorithm taken from D.E.Knuth (II).
*
*  @param pQuot Pointer to quotient or NULL
*  @param pU Pointer to dividend u
*  @param pV Pointer to divisor v
*  @param pCtx Work context. Optional
*  @return 0 on success, error code otherwise
*/
extern int QuotWLnum(HMEM_CTX_DEF
                     WLARGENUM* pQuot,
                     WLARGENUM* pU, 
                     WLARGENUM* pV, 
                     WLNUM_CONTEXT* pCtx);

/**
* Divides WLarge number u by v, producing
* remainder only (ModWLnum).
* Destinations must be different from sources.
* The context needs 2 elements.
*
* Uses algorithm taken from D.E.Knuth (II).
*
*  @param pRem Pointer to remainder or NULL
*  @param pU Pointer to dividend u
*  @param pV Pointer to divisor v
*  @param pCtx Work context. Optional
*  @return 0 on success, error code otherwise
*/
extern int ModWLnum(HMEM_CTX_DEF
                    WLARGENUM* pRem,
                    WLARGENUM* pU,
                    WLARGENUM* pV,
                    WLNUM_CONTEXT* pCtx);

/**
* Multiplies two WLarge numbers u and v modulo m (MulModWLnum).
* Destination and sources can be same.
* 3 temporary elements from the context are needed.
*
*  @param pRem Pointer to result
*  @param pU Pointer to number u
*  @param pV Pointer to number v
*  @param pMod Pointer to modulus m
*  @param pCtx Work context. Optional
*  @return 0 on success, error code otherwise
*/
extern int MulModWLnum(HMEM_CTX_DEF
                       WLARGENUM* pRem,
                       WLARGENUM* pU,
                       WLARGENUM* pV,
                       WLARGENUM* pMod, 
                       WLNUM_CONTEXT* pCtx);

/**
* Calculates (u ** v) mod m (ExpModWLnum).
* For evem modulus uses (slow) standard window algorithm,
* for odd modulus uses montgomery window algorithm.
* Destination and source must be different.
* 
* 4 CTX Elements required + max. 64 for table.
*
*  @param pRem pointer to destination
*  @param pU pointer to number u
*  @param pV pointer to power v
*  @param pMod pointer to modulus m
*  @param pCtx Work context. Optional
*  @param callback Callback pointer. Optional
*  @return 0 on success, error code otherwise
*/
extern int ExpModWLnum(HMEM_CTX_DEF
                       WLARGENUM* pRem, 
                       WLARGENUM* pU, 
                       WLARGENUM* pV,
                       WLARGENUM* pMod,
                       WLNUM_CONTEXT* pCtx,
                       void callback(int));

/**
* Calculates greatest common divisor of two
* WLarge numbers u and v using binary euclidian algorithm (GcdWLnum).
* Destination may be same as Source.
*
*  @param pRes Pointer to destination
*  @param pU Pointer to number u
*  @param pV Pointer to power v
*  @return 0 on success, error code otherwise
*/
extern int GcdWLnum(HMEM_CTX_DEF
                    WLARGENUM* pRes,
                    WLARGENUM* pU,
                    WLARGENUM* pV);

/**
* Calculates inverse of WLarge number u modulo m
* using (simplified) extended euclid algorithm (InvModWLnum). 
* See Knuth (II) exercises.
* Destination may be same as Source.
*
* 2 + 6 CTX elements needed.
*
* Slow version!
*
*  @param pUinv Pointer to result
*  @param pU Pointer to number u
*  @param pMod Pointer to modulus m
*  @param pCtx Work context. Optional
*  @return 0 on success, error code otherwise
*/
extern int InvModWLnum(HMEM_CTX_DEF
                       WLARGENUM* pUinv,
                       WLARGENUM* pU,
                       WLARGENUM* pMod,
                       WLNUM_CONTEXT* pCtx);

/**
* Converts binary number representation to a WLarge number (WLnum_bin2wlnum).
*
* NOTE: 
*<ol>
* <li> Binary number is in BIG ENDIAN format, i.e.
*   MSB is first byte in buffer, LSB is last byte.
* <li> The binary number is not checked for negative value.
* <li> The binary number may have leading zeroes.
*</ol>
*  @param pWLnum Pointer to destination
*  @param pSrcBuf Source buffer pointer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @return 0 on success, error code otherwise
*/
extern int WLnum_bin2wlnum(HMEM_CTX_DEF
                           WLARGENUM* pWLnum, 
                           char pSrcBuf[],
                           int SrcOffset, 
                           int SrcLen);

/**
* Converts binary number representation to a WLarge number.
*
* NOTE: 
*<ol>
* <li> Binary number is in LITTLE ENDIAN format, i.e.
*   MSB is last byte in buffer, LSB is first byte.
* <li> The binary number is not checked for negative value.
* <li> The binary number may have leading zeroes.
*</ol>
*  @param pWLnum Pointer to destination
*  @param pSrcBuf Source buffer pointer
*  @param SrcOffset Start of data
*  @param SrcLen Length of data
*  @return 0 on success, error code otherwise
*/
extern int WLnum_bin2wlnumLe(HMEM_CTX_DEF
                             WLARGENUM* pWLnum, 
                             char pSrcBuf[],
                             int SrcOffset,
                             int SrcLen);

/**
* Converts WLarge number to a binary number representation (WLnum_wlnum2bin).
*
* NOTE:
*<ol> 
* <li> The binary representation is in BIG ENDIAN format,
*     i.e. MSB is first byte in buffer, LSB is last.
* <li> The binary number will not  have leading zeroes,
*     if the flag is not set.
*</ol>
*  @param pDstBuf Destination buffer
*  @param DstIndex Start offset for writing
*  @param pDstLen Writable length/ written byte count
*  @param pWLnum Pointer to source
*  @param ZeroFlag <> 0: insert leading
*               zero byte if
*               necessary (MSB bit
*               of number=1) <br>
*               0 : do not insert
*               leading zero
*  @return 0 on success, error code otherwise
*/
extern int WLnum_wlnum2bin(char pDstBuf[], 
                           int DstIndex,
                           int pDstLen[],
                           WLARGENUM* pWLnum, 
                           int ZeroFlag);

/**
* Converts WLarge number to a binary number representation (WLnum_wlnum2bin).
*
* NOTE:
*<ol> 
* <li> The binary representation is in LITTLE ENDIAN format,
*     i.e. MSB is last byte in buffer, LSB is first.
* <li> The binary number will not  have leading zeroes,
*     if the flag is not set.
*</ol>
*  @param pDstBuf Destination buffer
*  @param DstIndex Start offset for writing
*  @param pDstLen Writable length/ written byte count
*  @param pWLnum Pointer to source
*  @param ZeroFlag <> 0: insert leading
*               zero byte if
*               necessary (MSB bit
*               of number=1) <br>
*               0 : do not insert
*               leading zero
*  @return 0 on success, error code otherwise
*/
extern int WLnum_wlnum2binLe(char pDstBuf[], 
                             int DstIndex,
                             int pDstLen[], 
                             WLARGENUM* pWLnum, 
                             int ZeroFlag);

/**
* Converts WLarge number to a binary number representation of definite length,
* filled with leading zeroes if needed (WLnum_wlnum2binFill).
*
* NOTE: The binary representation is in BIG ENDIAN format,
*       i.e. MSB is first byte in buffer, LSB is last
*
*  @param pDstBuf Destination buffer
*  @param DstIndex Start offset for writing
*  @param pDstLen Writable length/ written byte count
*  @param pWLnum Pointer to source
*  @param ReqNumLen Number of bytes to generate
*  @return 0 on success, error code otherwise
*/
extern int WLnum_wlnum2binFill(char* pDstBuf,
                               int DstIndex,
                               int* pDstLen, 
                               WLARGENUM* pWLnum, 
                               int ReqNumLen);

/**
* Gets a (pseudo-)random WLarge number of up to a specified bitlength (WLnumRand).
* If the TopFlag is set, the number is guaranteed to have exactly the
* requested length.
*
* Implemented by WLnumRand_impl with a wrapper around SecDrbgRandBytes.
*
*  @param pRnd Pointer for generated number
*  @param BitSize Number of bits required
*  @param TopFlag if <> 0 set topmost 2 bits
*  @param OddFlag if <> 0 return odd number
*
*  @return 0 on success, error code otherwise
*/
extern int WLnumRand(HMEM_CTX_DEF
                     WLARGENUM* pRnd, 
                     int BitSize,
                     int TopFlag, 
                     int OddFlag);


/**
* Implements function WLnumRand. The random number is fetched by the provided 
* random function.
*
*  @param pRnd Pointer for generated number
*  @param BitSize Number of bits required
*  @param TopFlag if <> 0 set topmost 2 bits
*  @param OddFlag if <> 0 return odd number
*  @param vpp_user_field   User field for the random function
*  @param amp_get_rand     Pointer to random function
*
*  @return 0 on success, error code otherwise
*/
extern int WLnumRand_impl(HMEM_CTX_DEF
                          WLARGENUM* pRnd,
                          int BitSize,
                          int TopFlag, 
                          int OddFlag,
                          void* vpp_user_field,
                          amd_get_random amp_get_rand);

/**
* Calculates the remainder of
* a WLarge number for a given 16 bit modulus (ModWordWLnum).
*
*  @param pWnumU Pointer to large number
*  @param Modulus Given modulus
*  @return Remainder/errorflag
* <br>            if < 0 Error occured
* <br>            if >=0 Remainder in low word
*/
extern int ModWordWLnum(WLARGENUM* pWnumU, 
                            short Modulus);

/**
* Calculates a set of small (16 bit, unsigned) prime numbers, using the sieve
* of Eratosthenes (DoEratosthenesWSieve). 
* Algorithmus taken from D.E. Knuth Vol. II, 4.5.4, solution of exercise 8 (slightly modified).
*
* NOTE:
*<ol>
* <li> Maximal requested number count is limited to 6552.
* <li> The estimate for N = 2*M for lower requested number
*     counts than 128 is approx. 2 times too large.
*     (But there is no way to predict primal number
*      distribution at all up to now)
* <li> The first prime number generated is 3, not 2.
*</ol>
*
*  @param pPrimesArr Prime number array to fill
*  @param MaxNums Max. number count requested
*  @return > 0 numbers stored
* <br>            == 0 helper field alloc failure
* <br>            < 0 number count too high
*/
extern int DoEratosthenesWSieve(HMEM_CTX_DEF
                                short pPrimesArr[], 
                                int MaxNums);

/**
* Performs Miller-Rabin checks for a WLarge
* number n (WLnumMillerRabin).
* For description of Algorithm see D.E.Knuth
* (Factoring into primes, Algorithm P) and B. Schneier (11.4,
*  factoring).
* Uses 3+4 +36 CTX Elements
*
*  @param pWnumN Number n to check
*  @param CheckCount count of checks to perform
*  @param pResult != 0 definitely not prime
*               == 0 probable prime
*  @param pCtx Large Number Workspace. Optional
*  @param callback Function for periodic call. Optional
*  @return 0 on success, error code otherwise
*/
extern int WLnumMillerRabin(HMEM_CTX_DEF
                            WLARGENUM* pWnumN,
                            int CheckCount,
                            int pResult[], 
                            WLNUM_CONTEXT* pCtx,
                            void callback(int));

/**
* Generates a prime number p of given size (GenPrimeWLnum).
* If Diffie-Hellman prime generation is requested, the prime
* will satisfy the condition (g ** a) mod p = b for all
* 1 <= b < p where g is a given generator.
* If a strong prime is requested (Diffie-Hellman only,
* (p-1)/2 is also prime) a check for stong prime is done.
*
* Uses 8+1 CTX Elements.
*
*  @param pPrime Preallocated structure
*               for number
*  @param Bits Requested size in bits
*  @param pStep Increment value for prime generation.
*               If <> 0, Diffie-Hellman 
*               specific generation.
*  @param pRem Remainder for Diffie-Hellman generator
*               condition checking
*  @param Strong if <> 0, strong prime is generated
*  @param pCtx Work Context. Optional
*  @param callback Callback function pointer. Optional
*  @return 0 on success, error code otherwise
*/
extern int GenPrimeWLnum(HMEM_CTX_DEF
                         WLARGENUM* pPrime,
                         int Bits,
                         WLARGENUM* pStep,
                         WLARGENUM* pRem,
                         int Strong, 
                         WLNUM_CONTEXT* pCtx,
                         void (*callback)(int));

/**
* Calculates the least common multiple of two WLarge numbers u and v, using
* the formula LCM(u,v) = (|u*v|)/GCD(u,v).
*
*  @param adsp_u        Pointer to parameter u
*  @param adsp_v        Pointer to parameter v
*  @param adsp_result   Pointer to structure for taking the LCM
*  @return LNUM_OP_OK on success, error code otherwise
*/
extern int m_lcm_wlnum(HMEM_CTX_DEF
                       WLARGENUM* adsp_u, 
                       WLARGENUM* adsp_v,
                       WLARGENUM* adsp_result);

/**
* Calculates (u ** v) mod m.
* For evem modulus uses (slow) standard window algorithm,
* for odd modulus uses montgomery window algorithm.
* Destination and source must be different.
*
* Blinding modes are: <ul>
*  <li> Additive base blinding (causes modulus blinding implicitly)
*  <li> Multiplicative modulus blinding
*  <li> Expononet splitting for exponent blinding
* </ul>
* 4 CTX Elements required + max. 32 for table.
*
* Implemented by m_exp_mod_blind_impl with a wrapper around SecDrbgRandBytes.
*
*  @param pRem pointer to destination
*  @param pU pointer to number u
*  @param pV pointer to power v
*  @param pMod pointer to modulus m
*  @param pCtx Work context. Optional
*  @param inp_flags Flags, specifying the requested blinding: <br>
*                    Bit 0: 1 - Do base (+ mod) blinding <br>
*                    Bit 1: 1 - Do modulus blinding <br>
*                    Bit 2: 1 - Do exponent blinding
*  @param callback Callback pointer. Optional
*  @return 0 on success, error code otherwise
*/
extern int m_exp_mod_blind(HMEM_CTX_DEF
                           WLARGENUM* pRem,
                           WLARGENUM* pU,
                           WLARGENUM* pV,
                           WLARGENUM* pMod, 
                           WLNUM_CONTEXT* pCtx,
                           int inp_flags,
                           void (*callback)(int));

/**
* Implements m_exp_mod_blind. 
*
* Uses WLnumRand_impl for blinding factors.
*
*  @param pRem pointer to destination
*  @param pU pointer to number u
*  @param pV pointer to power v
*  @param pMod pointer to modulus m
*  @param pCtx Work context. Optional
*  @param inp_flags Flags, specifying the requested blinding: <br>
*                    Bit 0: 1 - Do base (+ mod) blinding <br>
*                    Bit 1: 1 - Do modulus blinding <br>
*                    Bit 2: 1 - Do exponent blinding
*  @param callback Callback pointer. Optional
*  @param vpp_user_field   User field for the random function
*  @param amp_get_rand     Pointer to random function
*  @return 0 on success, error code otherwise
*/
extern int m_exp_mod_blind_impl(HMEM_CTX_DEF
                                WLARGENUM* pRem, 
                                WLARGENUM* pU,
                                WLARGENUM* pV,
                                WLARGENUM* pMod,
                                WLNUM_CONTEXT* pCtx,
                                int inp_flags,
                                void (*callback)(int),
                                void* vpp_user_field,
                                amd_get_random amp_get_rand);

/** @} */
/** @addtogroup rsa
* @{
*/
//==============================================================
// RSA
//==============================================================
//----------------------------------------------------
// Global Returncodes
//----------------------------------------------------
#define RSA_OP_OK     0

//----------------------------------------------------
// Specific Returncodes, Range is -700 ... -799
//----------------------------------------------------
//----------------------------------------------------
// Fast Exponentation Returncodes
//----------------------------------------------------
#define RSA_FAST_EXPMOD_FAILURE   -700

//----------------------------------------------------
// Public Encrypt Returncodes
//----------------------------------------------------
#define RSA_PUBENC_ALLOC_ERR   -710
#define RSA_PUBENC_DATA_TOO_LARGE  -711
#define RSA_PUBENC_KEY_SIZE_TOO_LARGE  -712
#define RSA_PUBENC_RANDOM_GET_FAILURE  -713
#define RSA_PUBENC_LNUM_ALLOC_ERR  -714
#define RSA_PUBENC_BYTES_TO_LNUM_ERR  -715
#define RSA_PUBENC_EXPMOD_ERR   -716
#define RSA_PUBENC_LNUM_TO_BYTES_ERR  -717
//----------------------------------------------------
// Private Encrypt Returncodes
//----------------------------------------------------
#define RSA_PRIVENC_ALLOC_ERR   -720
#define RSA_PRIVENC_SRCDATA_TOO_LARGE  -721
#define RSA_PRIVENC_DSTBUF_TOO_SMALL  -722
#define RSA_PRIVENC_LNUM_ALLOC_ERR  -723
#define RSA_PRIVENC_BYTES_TO_LNUM_ERR  -724
#define RSA_PRIVENC_FAST_EXPMOD_ERR  -725
#define RSA_PRIVENC_EXPMOD_ERR   -726
#define RSA_PRIVENC_LNUM_TO_BYTES_ERR  -727
//----------------------------------------------------
// Public Decrypt Returncodes
//----------------------------------------------------
#define RSA_PUBDEC_ALLOC_ERR   -730
#define RSA_PUBDEC_LNUM_ALLOC_ERR  -731
#define RSA_PUBDEC_BYTES_TO_LNUM_ERR  -732
#define RSA_PUBDEC_SRCDATA_TOO_LARGE  -733
#define RSA_PUBDEC_EXPMOD_ERR   -734
#define RSA_PUBDEC_LNUM_TO_BYTES_ERR  -735
#define RSA_PUBDEC_BLOCKTYPE_NOT_00_01  -736
#define RSA_PUBDEC_NO_DATA_BLOCK_DELIM  -737
#define RSA_PUBDEC_BAD_FF_HEADER  -738
#define RSA_PUBDEC_BAD_PAD_BYTE_COUNT  -739
#define RSA_PUBDEC_DSTBUF_TOO_SMALL  -740
#define RSA_PUBDEC_BLOCKTYPE_NOT_01  -741 // TLS
//----------------------------------------------------
// Private Decrypt Returncodes
//----------------------------------------------------
#define RSA_PRIVDEC_ALLOC_ERR   -750
#define RSA_PRIVDEC_LNUM_ALLOC_ERR  -751
#define RSA_PRIVDEC_BYTES_TO_LNUM_ERR  -752
#define RSA_PRIVDEC_SRCDATA_TOO_LARGE  -753
#define RSA_PRIVDEC_FAST_EXPMOD_ERR  -754
#define RSA_PRIVDEC_EXPMOD_ERR   -755
#define RSA_PRIVDEC_LNUM_TO_BYTES_ERR  -756
#define RSA_PRIVDEC_BLOCKTYPE_NOT_02  -757
#define RSA_PRIVDEC_NO_DATA_BLOCK_DELIM  -758
#define RSA_PRIVDEC_BAD_PAD_BYTE_COUNT  -759
#define RSA_PRIVDEC_DSTBUF_TOO_SMALL  -760
#define RSA_PRIVDEC_GET_RAND_ERR  -761
//----------------------------------------------------
// Signature Generate/Verify Returncodes
//----------------------------------------------------
#define RSA_SIG_PARAMS_MISSING   -770
#define RSA_SIG_DSTBUF_TOO_SMALL  -771
#define RSA_SIG_INVALID_SIGNATURE_LEN  -772
#define RSA_SIG_TMP_ALLOC_ERR   -773
#define RSA_SIG_UNKNOWN_ALGOR_TYPE  -774
#define RSA_SIG_PRIV_ENCRYPT_ERR  -775
#define RSA_SIG_PUBLIC_DECRYPT_ERR  -776
#define RSA_SIG_VERIFY_FAILURE   -777

//----------------------------------------------------------
// definitions for signature digests etc.
//----------------------------------------------------------
#define MD2_WITH_RSA_ALGOR  0
#define MD5_WITH_RSA_ALGOR  1
#define SHA1_WITH_RSA_ALGOR  2
#define RIPEMD160_WITH_RSA_ALGOR 3
#define SHA256_WITH_RSA_ALGOR  4
#define SHA384_WITH_RSA_ALGOR  5
#define SHA512_WITH_RSA_ALGOR  6
#define SHA224_WITH_RSA_ALGOR  7

#define RSA_DEFAULT_PUB_EXP  0x010001 // Fermat number F4

/**
* This structure holds all parameters of an RSA instance in <code>WLARGENUM</code>
* representation. The last three entries are used for chinese remainder theorem.
*/
typedef struct rsa_st
{
  /** Version, is always 0 */
  int Version;
  /** Modulus, n = p * q. */
  WLARGENUM* Modul;
  /** Public exponent. */
  WLARGENUM* PubExp;
  /** Private exponent. */
  WLARGENUM* PrivExp;
  /** Prime p. */
  WLARGENUM* Prime_p;
  /** Prime q. */
  WLARGENUM* Prime_q;
  /** d mod(p-1). */
  WLARGENUM* Dmodpm1;
  /** d mod(q-1). */
  WLARGENUM* Dmodqm1;
  /** q**(-1) mod p. */
  WLARGENUM* Invqmp;
} RSA_STRUC;

/**
* Gets modulus (n) size from stored value in bytes (RSA_Size).
*
*  @param rsa Pointer to structure
*  @return Modulus size in bytes
*/
extern int RSA_Size(RSA_STRUC* rsa);

/**
* Gets modulus (n) size from stored value in bits (RSA_BitSize).
*
*  @param rsa Pointer to structure
*  @return Modulus size in bits
*/
extern int RSA_BitSize(RSA_STRUC* rsa);

/**
* Clears the content of an RSA structure (destroying the contained key data)
* and frees the structure and used large numbers (RSA_Free).
*
*  @param rsa Pointer to structure
*/
extern void RSA_Free(HMEM_CTX_DEF
                     RSA_STRUC* rsa);

/**
* Allocate a new RSA data structure with large number elements of desired
* size (RSA_New). 
* The size is given in elements of 32 bit, so bitzise will be requested
* size*32.
* 
*  @param nElementcnt Modulus size
*  @param eElementcnt Public exponent size
*  @param dElementcnt Private exponent size
*  @param pElementcnt Prime p size 
*  @param qElementcnt Prime q size 
*  @return New <code>RSA_PTR</code>, NULL on allocation error.
*/
extern RSA_STRUC* RSA_New(HMEM_CTX_DEF
                          int nElementcnt,
                          int eElementCnt,
                          int dElementcnt,
                          int pElementcnt,
                          int qElementcnt);

/**
* Encrypts a message block according to RSAES-PKCS1-v1_5 using the public key (RSA_PublicEncrypt).
*
* If zerofill mode is selected, the ouput will be padded
*   with leading zeroes until buffersize is reached.
*  If standard mode is selected, a leading zero will be
*  inserted if the MSB bit is 1.
*
* The message may not be longer, than RSA_BitSize(rsa)-11 bits. RSA_Size(rsa)-3
* is a safe size in bytes.
*
*  @param MsgBuf Pointer to message buffer
*  @param MsgOff Starting offset of the message
*  @param MsgLen Length of input data block
*  @param DstBuf Pointer to output buffer
*  @param DstOff Starting offset for writing
*  @param pDstLen IN: Writable buffer length <br> OUT: Actually written bytes
*  @param rsa Pointer to used RSA structure
*  @param ZeroFill == 0 - Standard mode <br>
*               <> 0 - fill with leading zeroes
*
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PublicEncrypt(HMEM_CTX_DEF
                             char MsgBuf[], 
                             int MsgOff,
                             int  MsgLen,
                             char DstBuf[], 
                             int DstOff,
                             int  DstLen[],
                             RSA_STRUC* rsa, 
                             int ZeroFill);

/**
* Calls RSA_PrivateEncryptEx with the given parameters, but sets ZeroFlag = 1,
* if it is not 0 (RSA_PrivateEncrypt).
*
*  @param InpBuf Pointer to message buffer
*  @param InpLen Length of input data block
*  @param DstBuf Pointer to output buffer
*  @param DstOffset Starting offset for writing
*  @param pDstLen IN: Writable buffer length <br> OUT: Actually written bytes
*  @param rsa Pointer to used RSA structure
*  @param ZeroFlag see above
*
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PrivateEncrypt(HMEM_CTX_DEF
                              char InpBuf[],
                              int InpLen,
                              char DstBuf[],
                              int DstOffset,
                              int DstLen[],
                              RSA_STRUC* rsa,
                              int ZeroFlag);

/**
* Encrypts a message block, using RSASSA-PKCS1-v1_5 encoding and the private 
* key (RSA_PrivateEncryptEx). 
* If possible, uses chinese remainder theorem for speedup. To avoid timing 
* attacks, RSA blinding is applied to base, modulus and exponent both for 
* CRT and normal calculation.
*
* The message may not be longer, than RSA_BitSize(rsa)-11 bits. RSA_Size(rsa)-3
* is a safe size in bytes.
*
* Supports 3 modes of output number generation now:
* <ol>
* <li> ZeroFlag = 0: Do not insert any leading zeros anyway
*    (output may be also shorter than modulus size).
* <li> ZeroFlag > 0: Insert leading zero byte if MSB bit of
*    number is set (may be shorter/longer, ASN.1).
* <li> ZeroFlag < 0: Output size exact as modulus given, generate
*    leading zero bytes until size reached.
* </ol>
*  @param InpBuf Pointer to message buffer
*  @param InpLen Length of input data block
*  @param DstBuf Pointer to output buffer
*  @param DstOffset Starting offset for writing
*  @param pDstLen IN: Writable buffer length <br> OUT: Actually written bytes
*  @param rsa Pointer to used RSA structure
*  @param ZeroFlag see above
*
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PrivateEncryptEx(HMEM_CTX_DEF
                                char* InpBuf,
                                int InpLen,
                                char* DstBuf, 
                                int DstOffset,
                                int* pDstLen,
                                RSA_STRUC* rsa,
                                int ZeroFlag);

/**
* Calls RSA_PublicDecryptEx with the given parameters, allowing use of block 
* type 0 (Flags parameter 0) (RSA_PublicDecrypt).
*
*  @param Buflen Length of input data block
*  @param InpBuf Pointer to cipher block buffer
*  @param InputOffset Start of cipher data
*  @param OutpBuf Buffer for decrypted data
*  @param pMsgLen IN: Output buffer length <br> OUT: Decrypted message length
*  @param rsa Pointer to used RSA structure
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PublicDecrypt(HMEM_CTX_DEF
                             int Buflen, 
                             char InpBuf[],
                             int InputOffset,
                             char OutpBuf[], 
                             int MsgLen[] ,
                             RSA_STRUC* rsa);

/**
* Decrypts a RSASSA-PKCS1-v1_5 encrypted message block using the public key (RSA_PublicDecryptEx).
* The encoding will be checked. Type 0 encoding (leading 0 byte with 0 bytes 
* for padding) may additionally be permitted.
*
*  @param Buflen Length of input data block
*  @param InpBuf Pointer to cipher block buffer
*  @param InputOffset Start of cipher data
*  @param OutpBuf Buffer for decrypted data
*  @param pMsgLen IN: Output buffer length <br> OUT: Decrypted message length
*  @param rsa Pointer to used RSA structure
*  @param Flags Bit 0: 0 Allow block type 0 <br>
*               1 only block type1 valid <br>
*               Bit 31-1 reserved
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PublicDecryptEx(HMEM_CTX_DEF
                               int Buflen,
                               char InpBuf[],
                               int InputOffset,
                               char OutpBuf[],
                               int MsgLen[] ,
                               RSA_STRUC* rsa,
                               int Flags);

/**
* Decrypts a message block according to RSAES-PCKS1-v1_5, using the private key (RSA_PrivateDecrypt).
* If possible, uses chinese remainder theorem for speedup. To avoid timing 
* attacks, RSA blinding is applied to base, modulus and exponent both for 
* CRT and normal calculation.
*
*  @param InpBuf Pointer to cipher block buffer
*  @param InpOff Start of cipher data
*  @param Inplen Length of input data block
*  @param OutpBuf Buffer for decrypted data
*  @param pMsgLen IN: Output buffer length <br> OUT: Decrypted message length
*  @param rsa Pointer to used RSA structure
*  @return RSA_OP_OK on success, error code otherwise
*/
extern int RSA_PrivateDecrypt(HMEM_CTX_DEF
                              char InpBuf[], 
                              int InpOff,
                              int Inplen,
                              char OutpBuf[], 
                              int MsgLen[],
                              RSA_STRUC* rsa);

/**
* Calls RSA_signEx with the given parameters, setting the Flags parameter 0 (RSA_sign).
*
*  @param DigestType Type of message digest to use:
*               0 - MD2, 1 - MD5, 2 - SHA1,
*               3 - RIPEMD160, 4 - SHA256,
*               5 - SHA384, 6 - SHA512,
*               7 - SHA224
*  @param MessageBuf Pointer to message buffer
*  @param MsgBufOffset Start offset for message
*  @param MessageLen Length of message
*  @param SignatureBuf Pointer to signature buffer
*  @param SignatBufOffset Start offset of the signature
*  @param pSignatureLen Generate-Mode:<br>
*               IN: Length of signature buffer <br>
*               OUT: Length of the generated signature <br>
*               Verify-Mode: <br>
*               Length of given signature
*  @param rsa Pointer to used RSA structure
*  @param mode Type of requested operation: <br>
*               0 - generate signature <br>
*               <> 0 - verify given signature
*
*  @return 0 on success, error code otherwise
*/
extern int RSA_sign(HMEM_CTX_DEF
                    int DigestType,
                    char MessageBuf[],
                    int MsgBufOffset, 
                    int MessageLen,
                    char SignatureBuf[],
                    int SignatBufOffset,
                    int SignatureLen[],
                    RSA_STRUC* rsa, 
                    int mode);

/**
* Generates/verifies a signature according to RSASSA-PKCS1-v1_5 from a
* given message/signature (RSA_signEx).
* Block type 0 encoding (first byte 0, 0 bytes padding) may be allowed for
* verification. A signature will always be generated in RSASSA-PKCS1-v1_5
* encoding.
*
* For generation mode, the signature buffer must be at least 1 byte longer,
* than the RSA modulus. For verification, it must be no longer, than the
* RSA modulus.
*
* When verifying, a return of 0 signals a valid signature.
* When generating, the signature is verified, before returning.
*
*  @param DigestType Type of message digest to use:
*               0 - MD2, 1 - MD5, 2 - SHA1,
*               3 - RIPEMD160, 4 - SHA256,
*               5 - SHA384, 6 - SHA512,
*               7 - SHA224
*  @param MessageBuf Pointer to message buffer
*  @param MsgBufOffset Start offset for message
*  @param MessageLen Length of message
*  @param SignatureBuf Pointer to signature buffer
*  @param SignatBufOffset Start offset of the signature
*  @param pSignatureLen Generate-Mode:<br>
*               IN: Length of signature buffer <br>
*               OUT: Length of the generated signature <br>
*               Verify-Mode: <br>
*               Length of given signature
*  @param rsa Pointer to used RSA structure
*  @param mode Type of requested operation: <br>
*               0 - generate signature <br>
*               <> 0 - verify given signature
*  @param Flags Verify mode: Bit 0: 0 Allow block type 0 <br>
*               1 only block type1 valid <br>
*               Bit 31-1 reserved
*               Generate Mode: Serves as Zero flag for RSA_PrivateEncryptEx 
*
*  @return 0 on success, error code otherwise
*/
extern int RSA_signEx(HMEM_CTX_DEF
                      int DigestType,
                      char MessageBuf[],
                      int MsgBufOffset, 
                      int MessageLen,
                      char SignatureBuf[],
                      int SignatBufOffset,
                      int SignatureLen[],
                      RSA_STRUC* rsa,
                      int mode, 
                      int Flags);

/**
* Generates a random RSA key structure with a given modulus length, public
* exponent and prime number strength (m_rsa_genkey_impl). 
* If a fitting modulus size and public exponent is picked (not 
* checked!), the key will be compliant to FIPS PUB 186-3 Appendix B 3.1,
* Method A 2. See file/class description for detailed guarantees. The search
* is performed until an error occurs or key parameters are found.
*
* Values for using the chinese remainder theorem will be generated.
* An optional callback function can be provided for regular status updates.
*
*  @param bits Number of modulus bits to be generated
*  @param e_value Public exponent to use
*  @param inp_strength strength of prime numbers
*  @param callback Callback function. Optional
*  @return Pointer to generated RSA structure/NULL
*/
extern RSA_STRUC* m_rsa_genkey_impl(HMEM_CTX_DEF 
                                    int bits, 
                                    int e_value,
                                    int inp_strength,
                                    void (*callback)(int));

/**
* Generates a random RSA key structure with a given modulus length and public
* exponent (RSA_GenKey). 
* If a fitting modulus size and public exponent is picked (not 
* checked!), the key will be compliant to FIPS PUB 186-3 Appendix B 3.1,
* Method A 2. See file/class description for detailed guarantees. The search
* is performed until an error occurs or key parameters are found.
*
* Values for using the chinese remainder theorem will be generated.
* An optional callback function can be provided for regular status updates.
*
*  @param bits Number of modulus bits to be generated
*  @param e_value Public exponent to use
*  @param callback Callback function. Optional
*  @return Pointer to generated RSA structure/NULL
*/
extern RSA_STRUC* RSA_GenKey(HMEM_CTX_DEF 
                             int bits, 
                             int e_value,
                             void (*callback)(int));

/**
Performs a modular exponentiation on the input data.

All input is interpreted as big endian. Result is written as big endian.
No blinding is performed. Size of input must not be larger, than 512 byte (4096 bit).

@param[in]     abyp_rsa_data        Buffer containing the data.
@param[in]     imp_rsa_data_len     Length of data in bytes.
@param[in]     abyp_rsa_exp         Buffer containing the exponent.
@param[in]     imp_rsa_exp_len      Length of the exponent in bytes.
@param[in]     abyp_rsa_modulus     Buffer containing the modulus.
@param[in]     imp_rsa_modulus_len  Length of the modulus in bytes.
@param[out]    abyp_dst_buf         Buffer for writing the result.
@param[inout]  aimp_dst_buf_len     [in] Length of the result buffer in bytes.
                                    [out] Bytes written.

@return LNUM_OP_OK on success, error code otherwise.
*/
extern int m_rsa_crypt_raw_big(HMEM_CTX_DEF
                               unsigned char * abyp_rsa_data, 
                               int imp_rsa_data_len,
                               unsigned char * abyp_rsa_exp, 
                               int imp_rsa_exp_len,
                               unsigned char * abyp_rsa_modulus,
                               int imp_rsa_modulus_len,
                               unsigned char * abyp_dst_buf,
                               int * aimp_dst_len);

/**
Performs a modular exponentiation on the input data.

All input is interpreted as little endian. Result is written as little endian.
No blinding is performed. Size of input must not be larger, than 512 byte (4096 bit).

@param[in]     abyp_rsa_data        Buffer containing the data.
@param[in]     imp_rsa_data_len     Length of data in bytes.
@param[in]     abyp_rsa_exp         Buffer containing the exponent.
@param[in]     imp_rsa_exp_len      Length of the exponent in bytes.
@param[in]     abyp_rsa_modulus     Buffer containing the modulus.
@param[in]     imp_rsa_modulus_len  Length of the modulus in bytes.
@param[out]    abyp_dst_buf         Buffer for writing the result.
@param[inout]  aimp_dst_buf_len     [in] Length of the result buffer in bytes.
                                    [out] Bytes written.

@return LNUM_OP_OK on success, error code otherwise.
*/
extern int m_rsa_crypt_raw_little(HMEM_CTX_DEF
                                  unsigned char * abyp_rsa_data, 
                                  int imp_rsa_data_len,
                                  unsigned char * abyp_rsa_exp,  
                                  int imp_rsa_exp_len,
                                  unsigned char * abyp_rsa_modulus, 
                                  int imp_rsa_modulus_len,
                                  unsigned char * abyp_dst_buf,
                                  int * aimp_dst_len);

/**
Performs a modular exponentiation on the input data.

All input is interpreted as big endian. Result is written as big endian.
Size of input must not be larger, than 512 byte (4096 bit).
Blinding is performed, using the provided RNG function pointer.

@param[in]     abyp_rsa_data        Buffer containing the data.
@param[in]     imp_rsa_data_len     Length of data in bytes.
@param[in]     abyp_rsa_exp         Buffer containing the exponent.
@param[in]     imp_rsa_exp_len      Length of the exponent in bytes.
@param[in]     abyp_rsa_modulus     Buffer containing the modulus.
@param[in]     imp_rsa_modulus_len  Length of the modulus in bytes.
@param[out]    abyp_dst_buf         Buffer for writing the result.
@param[inout]  aimp_dst_buf_len     [in] Length of the result buffer in bytes.
                                    [out] Bytes written.
@param[in]     vpp_user_field       User field for amp_get_rand.
@param[in]     amp_get_rand         Function pointer for random number generation.

@return LNUM_OP_OK on success, error code otherwise.
*/
extern int m_rsa_crypt_raw_be_blind(HMEM_CTX_DEF 
                                    unsigned char * abyp_rsa_data, 
                                    int imp_rsa_data_len,
                                    unsigned char * abyp_rsa_exp,
                                    int imp_rsa_exp_len,
                                    unsigned char * abyp_rsa_modulus, 
                                    int imp_rsa_modulus_len,
                                    unsigned char * abyp_dst_buf,
                                    int * aimp_dst_len,
                                    void* vpp_user_field, 
                                    amd_get_random amp_get_rand);

/**
Performs a modular exponentiation on the input data.

All input is interpreted as little endian. Result is written as little endian.
Size of input must not be larger, than 512 byte (4096 bit).
Blinding is performed, using the provided RNG function pointer.

@param[in]     abyp_rsa_data        Buffer containing the data.
@param[in]     imp_rsa_data_len     Length of data in bytes.
@param[in]     abyp_rsa_exp         Buffer containing the exponent.
@param[in]     imp_rsa_exp_len      Length of the exponent in bytes.
@param[in]     abyp_rsa_modulus     Buffer containing the modulus.
@param[in]     imp_rsa_modulus_len  Length of the modulus in bytes.
@param[out]    abyp_dst_buf         Buffer for writing the result.
@param[inout]  aimp_dst_buf_len     [in] Length of the result buffer in bytes.
                                    [out] Bytes written.
@param[in]     vpp_user_field       User field for amp_get_rand.
@param[in]     amp_get_rand         Function pointer for random number generation.

@return LNUM_OP_OK on success, error code otherwise.
*/
extern int m_rsa_crypt_raw_le_blind(HMEM_CTX_DEF 
                                    unsigned char * abyp_rsa_data, 
                                    int imp_rsa_data_len,
                                    unsigned char * abyp_rsa_exp,
                                    int imp_rsa_exp_len,
                                    unsigned char * abyp_rsa_modulus, 
                                    int imp_rsa_modulus_len,
                                    unsigned char * abyp_dst_buf,
                                    int * aimp_dst_len,
                                    void* vpp_user_field, 
                                    amd_get_random amp_get_rand);

extern unsigned char RSA_Def_MD_Sign_Hdr[];

#define RSA_DEF_MD_SIGN_HDR_LEN  18 // length of header, MD2/MD5
#define RSA_DEF_SHA_SIGN_HDR_LEN 15 // length of header, SHA1
#define RSA_DEF_RIPEMD_SIGN_HDR_LEN 15 // length of header, RIPEMD160
#define RSA_DEF_SHA2_SIGN_HDR_LEN 19 // length of header, SHA2
#define RSA_MAX_SIGN_HDR_LEN  19 // max. length of header
/** Signature header for MD5withRSA PCKS1 Signature. Used for TLS 1.2 */
//BIT8ARRAYI
extern unsigned char RSA_Def_SHA_Sign_Hdr[];

//BIT8ARRAYI
extern unsigned char RSA_Def_RIPEMD_Sign_Hdr[];

//BIT8ARRAYI
extern unsigned char RSA_Def_SHA2_Sign_Hdr[];

/** @} */
/** @addtogroup dsadh
* @{
*/
//==============================================================
// DSA/Diffie Hellman
//==============================================================
//------------------------------------------------
// Global Returncodes
//------------------------------------------------
#define DSA_OP_OK    0
#define DH_OP_OK    0
#define DSA_DH_OP_OK    0 // same as LNUM_OP_OK

#define DSA_DH_NULL_PTR   -1
#define DSA_DH_ALLOC_ERR  -3

//------------------------------------------------
// Specific Returncodes, range is -800 ... -899
//------------------------------------------------
//------------------------------------------------------------------
// DSA/DH Key-/Parameter generation/check Returncodes, internal only
//------------------------------------------------------------------
#define DSA_DH_GEN_INV_BITSIZE   -800

#define DSA_DH_CHK_INV_BITSIZE  -805
#define DSA_DH_CHK_INVALID_PUBVAL -806

#define DSA_DH_KEY_SIZE_ERR  -810
#define DSA_DH_KEY_PRIV_GEN_ERR  -811
#define DSA_DH_KEY_PUBL_GEN_ERR  -812

//------------------------------------------------
// DSA Key generate Returncodes
//------------------------------------------------
#define DSA_GEN_NULL_PTR_ERR  -820
#define DSA_GEN_INV_BITSIZE_ERR  -821
#define DSA_GEN_ALLOC_ERR  -822

//------------------------------------------------
// DSA Signature generate/verify Returncodes
//------------------------------------------------

#define DSA_SIGN_R_DATA_TOO_LARGE -830
#define DSA_SIGN_S_DATA_TOO_LARGE -831
#define DSA_SIGN_DATA_TOO_LARGE  -832
#define DSA_SIGN_LNUM_ERR  -833
#define DSA_SIGN_BUFFER_TOO_SMALL -834
#define DSA_SIGN_INVALID_HASH_LEN -835
#define DSA_SIGN_R_S_ZERO  -836


#define DSA_VERIFY_SIGNAT_TOO_SMALL -840
#define DSA_VERIFY_ALLOC_ERR  -841
#define DSA_VERIFY_INVALID_SIGNAT_DATA -842
#define DSA_VERIFY_NO_R_VALUE  -843
#define DSA_VERIFY_NO_S_VALUE  -844
#define DSA_VERIFY_INVALID_SIGNAT -845
#define DSA_VERIFY_LNUM_ERR  -846
#define DSA_VERIFY_INVALID_HASH_LEN -847

//------------------------------------------------
// DH Params/Secret generate Returncodes
//------------------------------------------------
#define DH_GEN_NULL_PTR_ERR  -850
#define DH_GEN_INV_BITSIZE  -851
#define DH_GEN_ALLOC_ERR  -852

#define DH_COMPUTE_KEY_INV_DATA  -860
#define DH_COMPUTE_KEY_ALLOC_ERR -861
#define DH_COMPUTE_KEY_EXPMOD_ERR -862
#define DH_COMPUTE_KEY_LNUM_TO_BIN_ERR -863
//-------------------------------------------------------
// Defines
//-------------------------------------------------------
#define DSA_GEN_TYPE  0 // generate DSA parameters
#define DH_GEN_TYPE  1 // generate DH  parameters

#define MIN_DH_DSA_Q_BITS 160

/** 
* This structure is the internal representation used for DSA parameters, 
* public and/or private value.
*/
typedef struct DSA_STRUC_st
{
  /** prime p (modulus) */
  WLARGENUM* p;
  /** factor q */
  WLARGENUM* q;
  /** generator */
  WLARGENUM* g;
  /** public value */
  WLARGENUM* y;
  /** private value */
  WLARGENUM* x;
} DSA_STRUC;

/**
* This structure is the internal representation used for Diffie-Hellman 
* parameters, public and/or private value.
*/
typedef struct dh_st
{
  /** prime p */
  WLARGENUM* p;   
  /** prime q */
  WLARGENUM* q;
  /** base  g (Generator) */
  WLARGENUM* g;
  /** subgroup factor j */
  WLARGENUM* j;
  /** public key */
  WLARGENUM* PubKey;
  /** private key */
  WLARGENUM* PrivKey;
  /** generation seed */
  WLARGENUM* Seed;
  /** generation counter */
  int PgenCount;
  /** private Key length */
  int PrivLen;  
} DH_STRUC;

typedef enum ie_dh_named_groups {
    ied_dh_group_tls_ffdhe2048 = 0,
}ie_dh_named_groups;

/**
* Clears and frees an allocated DSA structure, including all large numbers (DSA_Free).
*
*  @param r Pointer to structure
*/
extern void DSA_Free(HMEM_CTX_DEF 
                     DSA_STRUC * r);

/**
* Allocates a new DSA structure and all required large number structures in
* sufficient size (DSA_New).
*
*  @param pElementcnt Size of prime p
*  @param qElementcnt Size of factor q
*  @param gElementcnt Size of generator g
*  @param yElementcnt Size of public value y
*  @param xElementcnt Size of private value x
*  @return Pointer to the new structure, NULL on error
*/
extern DSA_STRUC * DSA_New(HMEM_CTX_DEF
                           int pElementcnt,
                           int qElementcnt,
                           int gElementcnt,
                           int yElementcnt,
                           int xElementcnt);

/**
* Gets the size of DSA modulus in bits (DSA_BitSize).
*
*  @param dsa Start of structure
*  @return Length of prime p in bits, 0, if no prime/no structure are present
*/
extern int DSA_BitSize(DSA_STRUC * dsa);

/**
* Calculates required maximal buffer size for DSA signature for given DSA 
* parameters (DSA_SignatMaxLen).
*
* ASN.1 DSA-Signature: SEQUENCE { INTEGER r, INTEGER s}
*
*  @param dsa Pointer to structure
*  @return Required size, 0 on error
*/
extern int DSA_SignatMaxLen(DSA_STRUC * dsa);

/**
* This function generate the DSA signature for a message (DSA_Sign). 
*
* Depending on mode specified, input data is either already an SHA-1 hash or will be hashed
* by this function. The generated signature will be ASN.1 encoded and written
* to the output buffer. For testing purposes, a test number can be input that
* will be used in the signing process instead of generating a 160 bit random 
* value.
*
*  @param msgBuf     Message buffer array base
*  @param msgOffset  Start index of message
*  @param msgLen     Length of message
*  @param sigBuf     Signature buffer array base
*  @param sigOffset  Start index of signature
*  @param psigLen    Length of signature buffer
*  @param dsa        DSA structure base
*  @param kTest if <> 0, replaces random
*               number for test purposes
*  @param Mode == 0 do SHA1 hash of input<br>
*               != 0 use input as SHA1 hash
*
*  @return DSA_OP_OK on success, Error code otherwise
*/
extern int DSA_Sign(HMEM_CTX_DEF
                    char * msgBuf, 
                    int msgOffset, 
                    int msgLen,
                    char * sigBuf, 
                    int sigOffset, 
                    int * sigLen,
                    DSA_STRUC * dsa,
                    WLARGENUM * kTest, 
                    int Mode);

/**
* Verifies a signature for a message (DSA_Verify).
*
* Depending on mode specified,
* the input message data is either already an SHA-1 hash or will be hashed by 
* the function. The signature must be ASN.1 encoded.
*
*  @param msgBuf Message buffer array base
*  @param msgOffset Start index of message
*  @param msgLen length of message
*  @param sigBuf Signature buffer array base
*  @param sigOffset Start index of signature
*  @param sigLen length of signature buffer
*  @param dsa DSA structure base
*  @param Mode == 0 do SHA1 hash of input
*  <br>            != 0 use input as SHA1 hash
*
*  @return == DSA_OP_OK signature is valid, else error occured
*/
extern int DSA_Verify(HMEM_CTX_DEF
                      char * msgBuf,
                      int msgOffset,
                      int msgLen,
                      char * sigBuf, 
                      int sigOffset, 
                      int sigLen,
                      DSA_STRUC * dsa,
                      int Mode);
 
/**
* Generates DSA public and private values (DSA_GenKey).
* <ol>
* <li> Generate Random private value x (of desired length).
* <li> Calculate public value y = (g ** x) mod p.
* </ol>
*
*  This function is visible, but not used by other modules.
*
*  @param dsa Base of parameter structure
*  @return DSA_DH_OP_OK on success, else error occured
*/
extern int DSA_GenKey(HMEM_CTX_DEF 
                      DSA_STRUC * dsa);

/**
* Allocates DSA Parameter structure and generates random DSA parameters 
* p,q,g,y and x. The new structure is returned by the pdsa parameter.
*
*  @param pBits Bitcount prime p
*  @param pdsa returned parameter structure
*  @param CallBack Callback procedure. Optional.
*
*  @return DSA_DH_OP_OK on success, else error occured
*/
extern int DSA_GenParams(HMEM_CTX_DEF
                         int pBits,
                         DSA_STRUC ** pdsa,
                         void CallBack(int));

/**
* Generates DSA/DH parameters p, q, g, j and the associated verification values
* Seed and Counter as described in RFC 2631 (GenDsaDhParams). 
*
* Large number structures are enlarged as required.
*
*  @param L Bitsize prime p
*  @param m Bitsize prime q, >= 160
*  @param ncheck Number of Miller Rabin checks
*  @param Type == 0 -> DSA / <> 0 -> DH
*  @param p Generated prime p
*  @param q Generated prime q
*  @param g Generated group parameter g
*  @param j Subgroup factor. Optional.
*  @param Seed Used seed. Optional
*  @param pCounter Counter for p. Optional.
*  @param callback Callback Function. Optional.
*
*  @return LNUM_OP_OK on succes, error code otherwise
*/
extern int GenDsaDhParams(HMEM_CTX_DEF
                          int L, 
                          int m, 
                          int ncheck,
                          int Type,
                          WLARGENUM * p,
                          WLARGENUM * q,
                          WLARGENUM * g,
                          WLARGENUM * j, 
                          WLARGENUM * Seed, 
                          int * Counter,
                          void callback(int));

/**
* Generates DSA/DH public / private values x, y of appropriate length.
*
* Private key value requirements:<br>
* DSA-Mode: 0 < x < q is required, 2**159 < q < 2**160<br>
* DH-Mode: Two different modes:
* <ol>
*   <li> Classic mode (from PKCS3):
*        <ul>
*        <li> no Private key size l given then
*   0 < x < p-1 shall be satisfied.
*        <li> Private key size l given (limiting) then
*   2**(l-1) < x < 2**l.
*        </ul>
*   <li> Enhanced mode (from RFC 2631):
*        1 < x < q-1 shall be satisfied.
* </ol>
*
*  @param PrivKeyLen Desired Length of private Key,
*               if 0 calculate from length of p
*  @param KeyType 0 - DSA, else DH
*  @param Mode 0 - classic, else enhanced (DH only)
*  @param p prime p
*  @param q prime q / NULL (DH for SSH)
*  @param g group parameter g
*  @param y generated public value
*  @param x generated private value
*  @param callback Callback Function. Optional.
*
*
*  @return LNUM_OP_OK on success, error code otherwise
*/
extern int GenDsaDhKey(HMEM_CTX_DEF
                       int PrivKeyLen,
                       int KeyType,
                       int Mode,
                       WLARGENUM * p,
                       WLARGENUM * q,
                       WLARGENUM * g,
                       WLARGENUM * y,
                       WLARGENUM * x,
                       void callback(int));

/**
* Verifies correct generation of DSS/DH public according to given primes p 
* and q (CheckDsaDhPubValue). Used for testing only.
*
*  @param p Prime p
*  @param q Prime q
*  @param y Public value y
*
*  @return LNUM_OP_OK on success, error code otherwise
*/
extern int CheckDsaDhPubValue(HMEM_CTX_DEF
                              WLARGENUM * p, 
                              WLARGENUM * q, 
                              WLARGENUM * y);

/**
* Allocates a new DH structure and all required large number structures
* with sufficient size (DH_New).
*
*  @param pElementcnt Size of prime p
*  @param qElementcnt Size of prime q
*  @param gElementcnt Size of generator g
*  @param yElementcnt Size of public value y
*  @param xElementcnt Size of private value x
*  @return Pointer to the new structure, NULL on error
*/
extern DH_STRUC * DH_New(HMEM_CTX_DEF
                         int pElementcnt,
                         int qElementcnt,
                         int gElementcnt,
                         int yElementcnt,
                         int xElementcnt);

/**
* Clears/frees an allocated Diffie-Hellman parameter structure 
* and its elements (DH_Free).
*
*  @param r Start of structure
*/
extern void DH_Free(HMEM_CTX_DEF 
                    DH_STRUC * r);

/**
Generates a new DH structure, using a named group.

The structure must be released using DH_Free.

@param[in]  iep_group_name  Named group to be used.

@return Pointer to the new DH structure. NULL on error.
*/
extern DH_STRUC* m_dh_gen_named_group(HMEM_CTX_DEF
                                      ie_dh_named_groups iep_group_name);

/**
* Gets the size of a Diffie-Hellman parameter structures prime p
* length in bytes (DH_Size).
*
*  @param dh Start of structure
*  @return Length of prime p, 0, if no prime/no structure are present
*/
extern int DH_Size(DH_STRUC * dh);

/**
Makes a deep copy of the given DH struct.

This means a new struture is allocated and all contet of the input is copied 
to the new structure.

@param[in]  adsp_input  Pointer to the structure to be copied.
@param[out] adsp_output Pointer to the location, where the copy shall be placed.

@return 0 on success, error code otherwise.
*/
extern int m_copy_dh(HMEM_CTX_DEF
                     const DH_STRUC* adsp_input,
                     DH_STRUC** aadsp_output);
/**
* Gets the size of DH modulus in bits (DH_BitSize).
*
*  @param dh Start of structure
*  @return Length of prime p in bits, 0, if no prime/no structure are present
*/
extern int DH_BitSize(DH_STRUC * dh);

/**
* Compares two DH structures for same DH-Parameters p, q and g,
* which must all be of length <> 0 (DH_ParamCompare).
*
*  @param Dh1 Start of structure 1
*  @param Dh2 Start of structure 2
*
*  @return 0, if parameters are valid and identical.
*/
extern int DH_ParamCompare(DH_STRUC * Dh1,
                           DH_STRUC * Dh2);

/**
* Allocates DH parameter structure and
* generates DH parameters p,q,g,j,Seed and PgenCnt (DH_GenParams).
*
* NOTE: The public/private params elements are allocated but
*       not filled. This  M U S T be done separately.
*
*  @param pBits Bitcount prime p
*  @param qBits Bitcount prime q (the critical value!)
*  @param pdh returned parameter structure
*  @param CallBack Callback procedure. Optional.
*
*  @return DSA_DH_OP_OK on success, else error occured
*/
extern int DH_GenParams(HMEM_CTX_DEF
                        int pBits,
                        int qBits,
                        DH_STRUC ** pdh,
                        void CallBack(int));

/**
* Processes phase I of Diffie-Hellman key agreement:
* <ol>
* <li> Generate Random private value x (length and restrictions specified in dh)
* <li> Calculate public value y = (g ** x) mod p
* </ol>
*
* The public value must be sent to the other peer,
* the private value will be used in phase II to
* generate the agreed secret key z (DH_GenKey).
*
*  @param dh Base of parameter structure
*  @param callback Callback procedure. Optional.
*  @return DSA_DH_OP_OK on success, error code otherwise
*/
extern int DH_GenKey(HMEM_CTX_DEF 
                     DH_STRUC *dh,
                     void CallBack(int));

/**
* Processes phase II of Diffie-Hellman key agreement:
* <ol>
* <li> Calculate secret key z = (y'** x) mod p
* <li> Allocate a buffer, convert z to big endian format and write it to the 
*    buffer
* </ol>
*
* NOTE: The peer sides y value must be set as public key in dh (DH_GenSecret).
*
*  @param ppDstBuf Pointer for the result buffer
*  @param pDstLen Length of data
*  @param dh Base of parameter structure
*
*  @return DH_OP_OK on success, error code otherwise
*/
extern int DH_GenSecret(HMEM_CTX_DEF
                        char * pDstBuf[],
                        int pDstLen[],
                        DH_STRUC * dh);

/**
* Generates DSA signature from given message
* using SHA1 message digest (already hashed) (DSA_SignRaw).
* Output is NOT ASN.1 formatted.
*
*  @param pDgstBuf Digest buffer base
*  @param DgstOffset Start of digest
*  @param DgstLen Length of digest
*  @param pSigBuf Signature buffer array base
*  @param SigOffset Start index of signature
*  @param pSigLen Length of signature buffer
*  @param dsa DSA structure base
*  @param kTest if <> 0, replaces random
*               number for test purposes
*
*  @return Status == DSA_OP_OK - o.k.
* <br>            else: Error occured
*/
extern int DSA_SignRaw(HMEM_CTX_DEF
                       char * pDgstBuf, 
                       int DgstOffset,
                       int DgstLen,
                       char * pSigBuf,
                       int SigOffset,
                       int * pSigLen,
                       DSA_STRUC * dsa,
                       WLARGENUM * kTest);

/**
* Verifies given DSA signature for a
* given message digest (DSA_VerifyRaw).
* Signature is NOT ASN1 formatted.
*
*  @param pDgstBuf Digest buffer base
*  @param DgstOffset Start of digest
*  @param DgstLen Length of Digest
*  @param pSigBuf Signature buffer array base
*  @param SigOffset Start index of signature
*  @param SigLen Length of signature buffer
*  @param dsa DSA structure base
*
*  @return Status == 0 - o.k.
* <br>            < 0 Error occured
*/
extern int DSA_VerifyRaw(HMEM_CTX_DEF
                         char * pDgstBuf, 
                         int DgstOffset,
                         int DgstLen,
                         char * pSigBuf,
                         int SigOffset, 
                         int SigLen,
                         DSA_STRUC * dsa);
/**
* Checks, if the given group is safe.
* 
* This means, it is checked, if the prime p is large enough, and if 
* 2 <= g <= (p-1) is true (see NIST SP 800-56B, 5.6.2.4).
* 
* @param adsp_group         Group to be checked.
* @param inp_min_bit_len    Minimum bit length of the prime p.
* @return TRUE, if the group is safe according to the criteria.
*/
extern BOOL m_dh_group_is_safe(DH_STRUC* adsp_group, 
                               int inp_min_bit_len);
/** @} */


//==============================================================
// PBKDF2
//==============================================================

typedef struct dsd_pbkdf2_params {
    char* achc_password;
    size_t szc_password_len;
    char* achc_salt;
    size_t szc_salt_len;
    uint32_t umc_iterations;
    size_t szc_key_len;
    ie_hmac_types iec_hmac_id;
} dsd_pbkdf2_params;

/**
Performs PBKDF2 with HMAC.

The hash for the HMAC is selected by parameter as defined for function GenHMAC.

Length of password and salt are assumed to be without 0-termination.
Password and salt are used 'as they are', so encoding is not changed.
The entire destination buffer is filled.

Iterations must be greater 1, destination smaller, than 2^32.

@param[in]  achp_password  Buffer containing the password.
@param[in]  szp_pw_len     Length of the password in bytes.
@param[in]  achp_salt      Buffer containing the salt.
@param[in]  szp_salt_len   Length of the salt in bytes.
@param[in]  unp_iterations Iterations to be performed.
@param[out] aucp_dest      Buffer to write the derived key to.
@param[in]  szp_dest_len   Key bytes to be generated.
@param[in]  inp_hash_type  Hash type identifier for HMAC.

@return 0 on success, error code otherwise.
*/
extern int m_pbkdf2_hmac(const char* achp_password, 
                         size_t szp_pw_len, 
                         const char* achp_salt,
                         size_t szp_salt_len,
                         unsigned int unp_iterations,
                         unsigned char* aucp_dest,
                         size_t szp_dest_len, 
                         int inp_hash_type);

/**
Performs PBKDF2 with HMAC.

It works as m_pbkdf2_hmac, using parameters in the params struct. The member 
szc_key_len is ignored, the parameter szp_ouput_len determines the number 
of bytes generated.

@param[in]  adsp_params     Pointer to structure containing all parameters.
@param[out] abyp_output     Buffer to write the derived key to.
@param[in]  szp_output_len  Key bytes to be generated.

@return 0 on success, error code otherwise.
*/
extern int m_pbkdf2(const dsd_pbkdf2_params* adsp_params,
                    unsigned char* abyp_output,
                    size_t szp_output_len);

/**
* Returns version number information of the HOBLink Secure
* SSL software module as 32 bit int and/or ASCIIz string 
* (m_encry_getversioninfo).
*
* The required buffer size for the string will be returned when
* the supplied buffer pointer is NULL and the size pointer is
* non NULL.
* If Version number is not required, use NULL for ainp_version.
*
*  @param[inout] ainp_version   Version information, compact:
*  <br>                         Byte 0 - Version
*  <br>                         Byte 1 - Revision
*  <br>                         Byte 2 - Release Major
*  <br>                         Byte 3 - Release Minor
*  @param[inout] achp_dst_buf   Buffer for string data
*  @param[inout] ainp_dst_len   Size of string data buffer
*  @return 0 - o.k., else error occurred
*/
extern int m_encry_getversioninfo(int* ainp_version, 
                                  char* achp_dst_buf,
                                  int* ainp_dst_len);

/**
This function is used to securely zero out memory.

It behaves as memset(avop_mem, 0, szp_len), but will not be removed by 
compiler optimization.

@param[in]  avop_mem Pointer to the memory to be 0ed.
@param[in]  szp_len  Number of bytes to be 0ed.
*/
extern void m_sec_zero_mem(void* avop_mem, size_t szp_len) OPTIMIZE_OFF_ATTRIBUTE ;

/**
This is a version of memcmp, that works in constant time.

This is to prevent timing leak on critical comparisons.
Unlike memcmp, it only tells, if the two blocks are equal or not. The result
value does not allow an ordering of the memory blocks!

@param[in]  adsp_mem_1  First memory block to be compared.
@param[in]  adsp_mem_2  Second memory block to be compared.
@param[in]  szp_mem_len Length of the two memory blocks.
*/
extern int const_time_memcmp(const void *adsp_mem_1, 
                             const void *adsp_mem_2,
                             size_t szc_mem_len) OPTIMIZE_OFF_ATTRIBUTE ;

/**
Prints a message with printf-like syntax.

Maximum length 511 characters.

When building with XH_INTERFACE, the aux function is used with DEF_AUX_CONSOLE_OUT.
Otherwise printf is used.

@param ach_format Formating string
*/
extern void PrintAux(HMEM_CTX_DEF const char * ach_format,...);

#if defined __cplusplus
}
#endif

//==============================================================
// HOBLinkSecure version macros
// As this is the baseline module, used by every other part of 
// HLSec, they are defined here
//==============================================================

#define HSSL_VERSION_1_NO  3          // 'Product' high version
#define HSSL_VERSION_2_NO  2          // 'Product' low version
#define HSSL_VERSION_3_NO 01          // SSL Version
#define HSSL_VERSION_4_NO 32          // SSL Minor Version
#define HSSL_RELEASE_MAJ_NO  04         // SSL Release, Major
#define HSSL_RELEASE_MIN_NO  0          // SSL Release, Minor

#define HSSL_VERSION_DATE_TXT "27.09.2017"  // Date of Release


#define STR_EXPAND(tokval) #tokval
#define EXP_A_QU(tokval) STR_EXPAND(tokval)

#define HSSL_VERSION_1_STR     EXP_A_QU(HSSL_VERSION_1_NO)        // 'Product' version
#define HSSL_VERSION_2_STR     EXP_A_QU(HSSL_VERSION_2_NO)        // dto.
#define HSSL_VERSION_3_STR     EXP_A_QU(HSSL_VERSION_3_NO)        // SSL Version
#define HSSL_VERSION_4_STR     EXP_A_QU(HSSL_VERSION_4_NO)        // SSL Minor Version
#define HSSL_RELEASE_MAJ_STR   EXP_A_QU(HSSL_RELEASE_MAJ_NO)      // SSL Release, Major
#define HSSL_RELEASE_MIN_STR   EXP_A_QU(HSSL_RELEASE_MIN_NO)      // SSL Release, Minor


#define HSSL_VERSION_DESC_TXT "SSL Software Module" // Description
#define HSSL_VERSION_DLL_TXT "Hoblink Secure Socket Provider DLL"
#define HSSL_VERSION_ALTDLL_TXT "Hoblink Secure Socket Provider Alternate DLL"
#define HSSL_VERSION_PROD_TXT "HOBLink Secure" // Product name

#endif // __HOB_ENCRYPT_HEADER__
