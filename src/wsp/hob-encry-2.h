#ifndef __HOB_ENCRY_2_HEADER__
#define __HOB_ENCRY_2_HEADER__
#pragma once

/**
 * @file
 * This is the header for the HOB encryption v2 module.
 * The v2 module supplements the previous encryption module and will eventually supplant it.
 *
 * Source files:
 *   xs-encry-2.cpp       - C/C++ Source file
 *   is-encry-2-x64.asm   - Intel x86 (64 bit) Assembler source file for Microsoft Assembler
 *   is-encry-2-x64.s     - Intel x86 (64 bit) Assembler source file for NASM Assembler (for Linux/FreeBSD/MacOS)
 *   is-encry-2-arm64.s   - ARM Aarch64 Assembler source file for GCC and Clang/LLVM Assembler
 *   is-encry-2-s390x.s   - S390X Assembler source file
 *
 * All Assembler source files implement the same set of functions. Select and link the file appropriate for the current architecture.
 * For architectures where no such source exists, xs-encry-2.cpp contains a C implementation of the same content.
 * To explicitly not use assembler on a platform where it would be available, supply the macro #HL_ENCRY2_NO_ASSEMBLER when compiling.
 *
 * Related files:
 *   hob-encry-intern-2.h - Header file for internal data types and assembly functions
 *   is-encry-x64.pre    - HOB Precomp file producing both is-lnum-impl-x64.asm and is-lnum-impl-x64.s
 *
 * The following headers are required for this header:
 *   stdlib.h
 *   Windows.h on Windows systems
 *   hob-unix01.h on Unix systems
 */

/** @defgroup memory Memory functions
@brief
This group contains functions and structures to simplify memory management.
    
    + A plug-in structure of memory allocation and deallocation functions, to allow situation-dependent memory sourcing.
    + A memory pool that essentially creates a parallel memory stack, to use for temporary variable storage
    + Auxiliary functions to protect against security-relevant data leaks and side channel attacks

To use the memory pool:
    1. Create a memory pool using m_mem_pool_create(). The functions m_mem_pool_size() or m_mem_pool_ecc_size() may help to gauge the required size
    2. Use m_mem_pool_get_frame() to set a fixed frame.
    3. Use m_mem_pool_get_chunk(), m_mem_pool_get_lnum_byte_size(), and others to request sections of temporary memory
    4. It is possible to repeat steps 2.-5. recursively, for exampe in subfunction calls.
    5. Use m_mem_pool_restore_frame() to release all sections requested after step 2.
    6. Destroy the memory pool using m_mem_pool_free().

*/

/** @defgroup lnum Large Number functions
@brief
This group contains all functions and definitions needed to store and manipulate arbitrary precision integers and perform basic arithmetic.

*/

/** @defgroup ecc Elliptic Curve cryptography
@brief
This group contains all functions and definitions to use elliptic curve cryptography

The functions support a selection of named curves, based on either Weierstrass or Montgomery curves. Arbitrary curves are not supported.
    - FIPS 186-4 curves P192, P224, P256, P384, and P521
    - SEC 2 curves P192k1, P224k1, P256k1
    - Brainpool curves P256r1, P384r1, P512r1
    - X25519
    - X448

To use Elliptic Curve Diffie-Hellman algorithm:
    1. Ready a #dsd_ecc_keypair and a memory pool.
    2. Set dsd_ecc_keypair::adsc_params to a named curve. (can be obtained using m_ecc_init_named_curve())
    3. Generate a key pair with m_ecc_gen_rand_keypair() or load an existing key pair with m_ecc_gen_static_keypair()
    4. Generate the secret using m_ecc_gen_secret() with the peer's public key
    5. Call m_ecc_free_keypair()

To generate a signature with Elliptic Curve Digital Signature Algorithm:
    1. Ready a #dsd_ecc_keypair and a memory pool.
    2. Set dsd_ecc_keypair::adsc_params to a named curve. (can be obtained using m_ecc_init_named_curve())
    3. Generate a key pair with m_ecc_gen_rand_keypair() or load an existing key pair with m_ecc_gen_static_keypair()
    4. Generate the signature using m_ecc_gen_signature()
    5. Call m_ecc_free_keypair()

To verify a signature with Elliptic Curve Digital Signature Algorithm:
    1. Use m_ecc_verify_sig()

Important note: Please ensure that the memory provided to m_ecc_init_named_curve is persistent over the lifetime of the program.
*/

/** @defgroup rsa RSA functions
@brief
This group contains all functions and definitions for RSA asymmetric cryptography.

*/

/** @defgroup symcipher Symmetric encryption functions
@brief
This group contains all functions and definitions to handle symmetric key encryption and decryption.

The following block cipher algorithms are supported:
    - 3DES
    - AES in CBC mode
    - AES in CTR mode

The following AEAD algorithms are supported:
    - AES GCM

Use the \p *_init* function to perform key expansion and initialize #dsd_cipher_key structs.

If hardware acceleration is possible for a cipher, its functions will be available in three variants:
    1. \p _sw: Never use hardware acceleration.
    2. \p _hw: Always use hardware acceleration. If the platform does not actually support hardware acceleration, this will cause a fatal processor fault.
    3. \p _auto: Use hardware acceleration if available.

In addition, the dsd_cipher_key::boc_disallow_hardware_acceleration flag can be set at runtime to direct a \p _auto function to ignore hardware acceleration.
Functions that take dsd_gather_i_1 instead of a buffer as input always behave like \p _auto functions.
*/

/** @defgroup hashes Hash functions
@brief
This group contains all functions and definitions needed to handle cryptographic hashes.

In general generating hashes is done as follows:
    1. Get a state array (\p abyp_state parameter) of sufficient size and a digest array (\p abyp_digest) of sufficient size.
    2. Initialize the state array using the init function.
    3. Call the update function(s) over all the data that shall be hashed. Arbitrary calls (including 0) are allowed.
    4. Call the final function to generate the hash in \p abyp_digest. This will also clean the state array.

To know how large the state and hash array must be see the appropriate constant,
or use dsd_hash_profile. This also contains function pointers for all the needed
functions of each hash. Use #dsrg_hash_profiles to access the one for the required
hash. If the hash is fixed the functions can also be used directly.

MD5 and to a degree SHA1 are insecure and should only be used when absolutely necessary for compatibility!
*/

/** @defgroup hmac HMAC functions
@brief
This group contains all functions and definitions needed for HMAC authentication.

*/


/****************************************************************************************************/
/*                                                                                                  */
/*  Platform identification and preprocessor definitions                                            */
/*                                                                                                  */
/****************************************************************************************************/

#if (defined __s390__) || (defined __s390x__)
#define HL_BIG_ENDIAN
#endif

/* The word size used in large number arithmetic should correspond to the hardware's register size */
#if (defined(__x86_64__) || defined(_WIN64) || defined(__aarch64__) || defined(__s390x__)) && \
    (!defined(HL_ENCRY2_NO_ASSEMBLER))
#define HL_LNUM_64_BIT
#define LNUM_WORD unsigned long long
#define HL_ALIGNMENT (sizeof(char*))
#define HL_LNUM_ASM
#else
#define LNUM_WORD unsigned int
#define HL_ALIGNMENT (sizeof(char*))
#undef HL_LNUM_ASM
#endif


#if (defined(__x86_64__) || defined(_WIN64) || defined(__aarch64__)) && (!defined(HL_ENCRY2_NO_ASSEMBLER))
#define HL_AES_ASM
#else
#undef HL_AES_ASM
#endif

/* Version number (major) of HOB Encry-2 module */
extern const int ing_encry2_version_major;
/* Version number (minor) of HOB Encry-2 module */
extern const int ing_encry2_version_minor;
/* Revision of HOB Encry-2 module release */
extern const int ing_encry2_version_revision;
/* Version string of HOB Encry-2 module */
extern const char chrg_encry2_version_string[];
/* Length of version string (not including null terminator) */
extern const size_t szg_encry2_version_string_len;

/****************************************************************************************************/
/*                                                                                                  */
/*  Data types                                                                                      */
/*                                                                                                  */
/****************************************************************************************************/

/** @ingroup other
   Error codes

   If this data type must be extended, new error codes must be inserted at the end before ied_encry_error_count.
   Also remember to update achrg_encry_error_message and add the value of the new enum as Doxygen comment.
 */
enum ied_encry_return {
    ied_encry_success = 0,                          //!< 0
    ied_encry_null_pointer,                         //!< 1
    ied_encry_alloc_failure,                        //!< 2
    ied_encry_insufficient_buffer,                  //!< 3
    ied_encry_invalid_input,                        //!< 4
    ied_encry_pool_empty,                           //!< 5
    ied_encry_insufficient_input_buffer,            //!< 6
    ied_encry_rng_error,                            //!< 7
    ied_lnum_uninitialized,                         //!< 8
    ied_lnum_invalid_inplace,                       //!< 9
    ied_lnum_divide_by_zero,                        //!< 10
    ied_lnum_invalid_modulus,                       //!< 11
    ied_lnum_no_prime,                              //!< 12
    ied_ecc_representation_error,                   //!< 13
    ied_ecc_curve_empty,                            //!< 14
    ied_ecc_public_key_missing,                     //!< 15
    ied_ecc_input_len_invalid,                      //!< 16
    ied_ecc_input_unknown_curve,                    //!< 17
    ied_ecc_keypair_uninitialized,                  //!< 18
    ied_ecc_context_not_clean,                      //!< 19
    ied_ecc_point_not_on_curve,                     //!< 20
    ied_ecc_point_format_error,                     //!< 21
    ied_ecc_public_key_invalid,                     //!< 22
    ied_ecc_signature_invalid,                      //!< 23
    ied_ecc_secret_zero,                            //!< 24
    ied_ecc_ecdsa_again,                            //!< 25
    ied_encry_aborted,                              //!< 26
    ied_encry_miscellaneous,                        //!< 27
    ied_encry_internal_error,                       //!< 28
    ied_encry_not_implemented,                      //!< 29
    ied_encry_verify_failed,                        //!< 30

    ied_encry_error_count                           //!< Total number of return codes. Must stay the last. Must not be used as actual return code.
};
/** @ingroup other
  Cleartext error messages corresponding to ied_encry_return
*/
extern const char* achrg_encry_error_message[];

/** @ingroup lnum
   Comparison return codes
 */
enum ied_lnum_comparison {
    ied_equal = 0,
    ied_zero = 0,
    ied_larger = 1,
    ied_positive = 1,
    ied_smaller = -1,
    ied_negative = -1,
    ied_encry_null_pointer_cmp = -600
};

/** @ingroup memory
   LNUM functions that make use of a memory pool
 */
enum ied_encry_function {
    ied_m_lnum_barret_init,
    ied_m_lnum_barret_reduce,
    ied_m_lnum_divide,
    ied_m_lnum_exp_mod,
    ied_m_lnum_gcd,
    ied_m_lnum_inverse,
    ied_m_lnum_lcm,
    ied_m_lnum_mont_init,
    ied_m_lnum_mont_red,
    ied_m_lnum_mult,
    ied_m_lnum_square,
    ied_m_lnum_test_prime,
    ied_m_lnum_mont_conv,
};

/** @ingroup memory
   ECC functions that make use of a memory pool
 */
enum ied_ecc_function {
    ied_m_ecc_init_named_curve,
    ied_m_ecc_gen_rand_keypair,
    ied_m_ecc_gen_static_keypair,
    ied_m_ecc_gen_secret,
    ied_m_ecc_gen_signature,
    ied_m_ecc_verify_sig,
};

/** @ingroup ecc
   Named elliptic curves
 */
enum ied_ecc_named_curves {
    ied_P192,               //!< 
    ied_P224,               //!< 
    ied_P256,               //!< 
    ied_P384,               //!< 
    ied_P521,               //!< 
    ied_SECP192K1,          //!< 
    ied_SECP224K1,          //!< 
    ied_SECP256K1,          //!< 
    ied_brainpoolP256r1,    //!< 
    ied_brainpoolP384r1,    //!< 
    ied_brainpoolP512r1,    //!< 
    ied_X25519,             //!< 
    ied_X448,               //!< 

    ied_size_curves         //!< Value showing the total number of supported named curves. Must stay the last. Must not be used as actual indicator code.
};

/** @ingroup hashes
This enum specifies identifiers for all available hash functions.

ied_hash_count gives the total number of hashes and can be used for array initialization.
*/
enum ied_hash_function {
    ied_hash_sha_1,         //!< 
    ied_hash_sha_2_224,     //!< 
    ied_hash_sha_2_256,     //!< 
    ied_hash_sha_2_384,     //!< 
    ied_hash_sha_2_512,     //!< 
    ied_hash_sha_3_224,     //!< 
    ied_hash_sha_3_256,     //!< 
    ied_hash_sha_3_384,     //!< 
    ied_hash_sha_3_512,     //!< 
    ied_hash_md_5,          //!< 

    ied_hash_count          //!< Value showing the total number of supported hashes. Must stay the last. Must not be used as actual indicator code.
};

/** @ingroup memory
   Memory Provider.

   This structure allows to use different memory management systems in different use-cases
 */
struct dsd_memory {
    /** Malloc functionality */
    void* (*amc_malloc)(struct dsd_memory* adsp_memory, size_t szp_size);
    /** Free functionality */
    void (* amc_free)(struct dsd_memory* adsp_memory,
                      void* avop_ptr);
    /** Pointer to any metadata structures that the above functions might use*/
    void* avoc_context;
};
/** @ingroup memory
    Standard memory provider based on C Standard library \p malloc() and \p free()
*/
extern struct dsd_memory dsg_std_memory;

/** @ingroup lnum
   Large number object (Lnum)
 */
struct dsd_lnum {
    /** Pointer to the raw data buffer. May not be NULL.
        The content is logically organized in blocks of #LNUM_WORD (i.e. 4 bytes on 32bit systems, 8 bytes on 64bit systems).
        The word blocks are always arranged Little-Endian; the first word is always the least significant one.
        The bytes inside each word block are arranged system-dependent, either Little-Endian or Big-Endian.
        Leading zeroes are illegal; the most significant 4(8) bytes (as indicated by szc_used_size_bytes) must not be 0x00000000;
     */
    unsigned char* aucc_data;

    /**
       Size of the \p aucc_data buffer, given in bytes.
       Must be a nonzero multiple of LNUM_SIZE_ALIGN.
     */
    size_t szc_alloc_size_bytes;

    /** Extent of the actual numerical value inside the data buffer.
        Must be a multiple of the word size (4 on 32bit systems and 8 on 64bit systems)
        May not exceed \p szc_alloc_size_bytes.
        A value of zero designates a numerical value of 0 for the lnum
        Must be minimal and accurate; leading zero words are illegal.
     */
    size_t szc_used_size_bytes;

    /** Sign flag of the large number.
        Can be set either way for a zero value
     */
    BOOL boc_is_negative;
};

/** @ingroup memory
   Structure for the memory pool

   This implements a linked list of memory blocks, from which temporary memory chunks
   can be fetched and returned in a LIFO stack-similar manner
 */
struct dsd_mem_pool_ele {
    /** Pointer to next element in the linked list. */
    struct dsd_mem_pool_ele* adsc_next;
    /** Base pointer of the memory block. */
    char* achc_base;
    /** Limit of the memory block. Points one beyond the end. */
    char* achc_end;
    /** First currently usable address. */
    char* achc_current;
    /** Limit of the memory used during calculations. Points to the first block, that was never used. */
    char* achc_max_used;
};

/** @ingroup memory
   Stores information about the current state of a lnum pool.
 */
struct dsd_mem_pool_frame {
    /** current pool element. */
    struct dsd_mem_pool_ele* adsc_target;
    /** Current memory pointer. */
    char* achc_cur_mem;
};

/** @ingroup lnum
   Montogmery modulus and precomputed values for Montgomery modulo operations
 */
struct dsd_lnum_montgomery_ctx {
    /** The modulus of this Montgomery context. */
    struct dsd_lnum* adsc_mod;
    /** The value of R^2 mod n. Needed for montgomerizing numbers. */
    struct dsd_lnum* adsc_r_sqr;
    /** 1 in Montgomery form. Frequently needed for other purposes. */
    struct dsd_lnum* adsc_mont_one;
    /** The inverse of n[0]. */
    LNUM_WORD urc_n_0_inv;

};

/** @ingroup lnum
   Barret modulus and precomputed values for Barret modulo operations
 */
struct dsd_lnum_barret {
    unsigned int unc_n;
    struct dsd_lnum* adsc_modulus;
    struct dsd_lnum* adsc_mu;
};


/**
   Forward declaration of Elliptic curve parameter struct
 */
struct dsd_ec_curve_params;


/** @ingroup ecc
   ECC public/private key pair
 */
struct dsd_ecc_keypair {
    const struct dsd_ec_curve_params* adsc_params;
    struct dsd_lnum* adsc_priv_key;
    struct dsd_ec_point* adsc_pub_key;
};


/****************************************************************************************************/
/*                                                                                                  */
/*  Function declarations                                                                           */
/*                                                                                                  */
/****************************************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


/****************************************************************************************************/
/*                                                                                                  */
/*  Hash functions                                                                                  */
/*                                                                                                  */
/****************************************************************************************************/

/** @ingroup hashes
\brief Initializes the state of a hash function.

The state must be non-null and of sufficient size for the hash.

@param[out]  avop_state  Pointer to the hash state to be initialized
*/
typedef void (*amd_hash_init)(void* avop_state);

/** @ingroup hashes
\brief Updates a hash state with new data.

The state must have been initialized with the init function. 0-length input is valid.
This function can be called arbitrarily often.

@param[in,out]   avop_state      Hash state to be updated
@param[in]       abyp_input      Data to be added
@param[in]       szp_input_len   Length of data to be added
*/
typedef void (*amd_hash_update)(void* avop_state,
                                const unsigned char* abyp_input,
                                size_t szp_input_len);

/** @ingroup hashes
\brief Updates a hash state with new data.

The state must have been initialized with the init function. 0-length input is valid.
This function can be called arbitrarily often.

Operations are performed for \p szp_input_len bytes or to the end of adsp_input, whichever is shorter.

@param[in,out]   avop_state      Hash state to be updated
@param[in]       adsp_input      Data to be added
@param[in]       szp_input_len   Length of data to be added
*/
typedef void (*amd_hash_gather_update)(void* avop_state,
                                       struct dsd_gather_i_1* adsp_input,
                                       size_t szp_input_len);

/** @ingroup hashes
\brief Generates the digest (hash) from the current state.

The state will be cleared. The digest buffer must be large enough for the digest.

@param[in,out]   avop_state  Hash state
@param[out]      abyp_digest Output buffer for the generated digest
*/
typedef void (*amd_hash_final)(void* avop_state,
                               unsigned char* abyp_digest);

/** @ingroup hashes 
@copydoc amd_hash_init
*/
extern void m_sha_1_init(void* avop_state);

/** @ingroup hashes 
@copydoc amd_hash_update
*/
extern void m_sha_1_update(void* avop_state,
                           const unsigned char* abyp_input,
                           size_t szp_input_len);
/** @ingroup hashes 
@copydoc amd_hash_gather_update
*/
extern void m_sha_1_gather_update(void* avop_state,
                                  struct dsd_gather_i_1* adsp_input,
                                  size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_1_final(void* avop_state,
                          unsigned char* abyp_digest);

/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_2_224_init(void* avop_state);

/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_2_256_init(void* avop_state);

/** @ingroup hashes
@copydoc amd_hash_update
*/
extern void m_sha_2_224_256_update(void* avop_state,
                                   const unsigned char* abyp_input,
                                   size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_gather_update
*/
extern void m_sha_2_224_256_gather_update(void* avop_state,
                                          struct dsd_gather_i_1* adsp_input,
                                          size_t szp_input_len);

/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_2_224_final(void* avop_state,
                              unsigned char* abyp_digest);
/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_2_256_final(void* avop_state,
                              unsigned char* abyp_digest);

/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_2_384_init(void* avop_state);
/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_2_512_init(void* avop_state);

/** @ingroup hashes
@copydoc amd_hash_update
*/
extern void m_sha_2_384_512_update(void* avop_state,
                                   const unsigned char* abyp_input,
                                   size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_gather_update
*/
extern void m_sha_2_384_512_gather_update(void* avop_state,
                                          struct dsd_gather_i_1* adsp_input,
                                          size_t szp_input_len);

/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_2_384_final(void* avop_state,
                              unsigned char* abyp_digest);
/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_2_512_final(void* avop_state,
                              unsigned char* abyp_digest);

/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_3_224_init(void* avop_state);
/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_3_256_init(void* avop_state);
/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_3_384_init(void* avop_state);
/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_sha_3_512_init(void* avop_state);

/** @ingroup hashes
@copydoc amd_hash_update
*/
extern void m_sha_3_update(void* avop_state,
                           const unsigned char* abyp_input,
                           size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_gather_update
*/
extern void m_sha_3_gather_update(void* avop_state,
                                  struct dsd_gather_i_1* adsp_input,
                                  size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_sha_3_final(void* avop_state,
                          unsigned char* abyp_digest);

/** @ingroup hashes
@copydoc amd_hash_init
*/
extern void m_md_5_init(void* avop_state);
/** @ingroup hashes
@copydoc amd_hash_update
*/
extern void m_md_5_update(void* avop_state,
                          const unsigned char* abyp_input,
                          size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_gather_update
*/
extern void m_md_5_gather_update(void* avop_state,
                                 struct dsd_gather_i_1* adsp_input,
                                 size_t szp_input_len);
/** @ingroup hashes
@copydoc amd_hash_final
*/
extern void m_md_5_final(void* avop_state,
                         unsigned char* abyp_digest);

/** @ingroup hmac
Generates a HMAC tag for a data buffer.

The hash type is as specified by #ied_hash_function. Any of these enums
can be used as \p inp_hash_type. The tag is always as long as the digest of the
chosen hash. Key and data can be of any length.

All pointers must be non-null.

@param[out]     abyp_dest       Output buffer for the generated tag
@param[in,out]  aszp_dest_len   IN: Length of the output buffer\n
                                OUT: Length of the generated tag
@param[in]      abyp_data       Data of which the HMAC will be generated
@param[in]      szp_data_len    Length of the data
@param[in]      avop_key        Key used for generating the HMAC
@param[in]      szp_key_len     Length of the key in bytes
@param[in]      inp_hash_type   Hash type to be used by the HMAC

@return ::ied_encry_success or error code
*/
extern enum ied_encry_return m_hmac_gen(unsigned char* abyp_dest,
                                        size_t* aszp_dest_len,
                                        const unsigned char* abyp_data,
                                        size_t szp_data_len,
                                        const void* avop_key,
                                        size_t szp_key_len,
                                        int inp_hash_type);

/** @ingroup hmac
Generates a HMAC tag for a data buffer.

The hash type is as specified by #ied_hash_function. Any of these enums
can be used as \p inp_hash_type. The tag is always as long as the digest of the
chosen hash. Key and data can be of any length.

All pointers must be non-null.

@param[out]     abyp_dest       Output buffer for the generated tag
@param[in,out]  aszp_dest_len   IN: Length of the output buffer\n
                                OUT: Length of the generated tag
@param[in]      adsp_data       Data of which the HMAC will be generated
@param[in]      szp_data_len    Length of the data
@param[in]      avop_key        Key used for generating the HMAC
@param[in]      szp_key_len     Length of the key in bytes
@param[in]      inp_hash_type   Hash type to be used by the HMAC

@return ::ied_encry_success or error code
*/
extern enum ied_encry_return m_hmac_gather_gen(unsigned char* abyp_dest,
                                               size_t* aszp_dest_len,
                                               struct dsd_gather_i_1* adsp_data,
                                               size_t szp_data_len,
                                               const void* avop_key,
                                               size_t szp_key_len,
                                               int inp_hash_type);

/** @ingroup hmac
Verifies a HMAC tag for a data buffer.

The hash type is as specified by #ied_hash_function. Any of these enums
can be used as \p inp_hash_type. Verification is done in a side-channel resistant
manner.

All pointers must be non-null.

@param[in]  abyp_dest       Tag to be checked
@param[in]  aszp_dest_len   Length of the tag
@param[in]  abyp_data       Data to be checked
@param[in]  szp_data_len    Length of the data
@param[in]  avop_key        Key used for generating the HMAC
@param[in]  szp_key_len     Length of the key in bytes
@param[in]  inp_hash_type   Hash type to be used by the HMAC

@return ::ied_encry_success on success, ::ied_encry_verify_failed on verification failure or error code
*/
extern enum ied_encry_return m_hmac_verify(const unsigned char* abyp_tag,
                                           size_t szp_tag_len,
                                           const unsigned char* abyp_data,
                                           size_t szp_data_len,
                                           const void* avop_key,
                                           size_t szp_key_len,
                                           int inp_hash_type);

/** @ingroup hmac
Verifies a HMAC tag for a data buffer.

The hash type is as specified by #ied_hash_function. Any of these enums
can be used as \p inp_hash_type. Verification is done in a side-channel resistant
manner.

All pointers must be non-null.

@param[in]  abyp_dest       Tag to be checked
@param[in]  aszp_dest_len   Length of the tag
@param[in]  adsp_data       Data to be checked
@param[in]  szp_data_len    Length of the data
@param[in]  avop_key        Key used for generating the HMAC
@param[in]  szp_key_len     Length of the key in bytes
@param[in]  inp_hash_type   Hash type to be used by the HMAC

@return ::ied_encry_success on success, ::ied_encry_verify_failed on verification failure or error code
*/
extern enum ied_encry_return m_hmac_gather_verify(const unsigned char* abyp_tag,
                                                  size_t szp_tag_len,
                                                  struct dsd_gather_i_1* adsp_data,
                                                  size_t szp_data_len,
                                                  const void* avop_key,
                                                  size_t szp_key_len,
                                                  int inp_hash_type);


/** @ingroup lnum
   Allocates and initializes a Lnum.

   Allocates both the dsd_lnum struct and the data buffer on the heap.
   Use m_lnum_destroy() to deallocate it later

   For dsd_lnum structs located on the stack, use m_lnum_alloc().

   The given size is rounded up to a multiple of twice the word size.
   If the given size is zero, a non-zero length buffer will be allocated

   @param[in,out] adsp_memory       Memory Provider
   @param[in]     szp_size_bytes   Required size of the Lnum, given in bytes

   @return New struct dsd_lnum, or NULL if an error occurred
 */
extern struct dsd_lnum* m_lnum_create(struct dsd_memory* adsp_memory,
                                      size_t szp_size_bytes);



/** @ingroup lnum
   Allocates a Lnum and initializes it with the value of another.

   Allocates both the dsd_lnum struct and the data buffer on the heap.
   Use m_lnum_destroy() to deallocate it later.

   @param[in,out] adsp_memory    Memory Provider
   @param[in]     adsp_source    Lnum to be copied

   @return New struct dsd_lnum, or NULL if an error occurred
 */
extern struct dsd_lnum* m_lnum_clone(struct dsd_memory* adsp_memory,
                                     const struct dsd_lnum* adsp_source);


/** @ingroup lnum
   Initializes a Lnum.

   Allocates a buffer on the heap.
   Use m_lnum_free() to deallocate it later

   For dsd_lnum structs located on the heap, use m_lnum_create().

   The given size is rounded up to a multiple of twice the word size.
   If the given size is zero, a non-zero length buffer will be allocated

   @param[in,out] adsp_memory       Memory Provider
   @param[in,out] adsp_lnum         Lnum to be checked/reallocated.
   @param[in]     szp_size_bytes   New required size of the Lnum, given in bytes

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_alloc(struct dsd_memory* adsp_memory,
                                          struct dsd_lnum* adsp_lnum,
                                          size_t szp_size_bytes);





/** @ingroup lnum
   Deallocates the contents of a large number value.
   To be used in conjunction with m_lnum_alloc().

   Only deallocates the internal buffer. The struct dsd_lnum is left invalidated, but intact.
   Please see m_lnum_destroy() for contrast.

   @param[in,out] adsp_memory       Memory Provider
   @param[in,out] adsp_lnum         Lnum to be deleted.
 */
extern void m_lnum_free(struct dsd_memory* adsp_memory,
                        struct dsd_lnum* adsp_lnum);



/** @ingroup lnum
   Deallocates a large number value.
   To be used in conjunction with m_lnum_create() or m_lnum_clone().

   Calls free() on both the internal buffer and the struct dsd_lnum itself.
   Please see m_lnum_free() for contrast.

   @param[in,out] adsp_memory       Memory Provider
   @param[in,out] adsp_lnum         Lnum to be deleted.
 */
extern void m_lnum_destroy(struct dsd_memory* adsp_memory,
                           struct dsd_lnum* adsp_lnum);




/** @ingroup memory
   Creates and initializes a memory pool.

   Block size and count must be >0.

   @param[in]     adsp_memory      Memory Provider.
   @param[in]     szp_block_size   Size of the memory blocks.
   @param[in]     unp_block_count  Number of blocks.

   @return New struct dsd_mem_pool_ele, or NULL if an error occurred
 */
extern struct dsd_mem_pool_ele* m_mem_pool_create(struct dsd_memory* adsp_memory,
                                                  size_t szp_block_size,
                                                  unsigned int unp_block_count);

/** @ingroup memory
   Returns the minimum required pool size for any large number function that uses a pool.

   @param[in]  iep_function     Target function
   @param[in]  szp_input_size   Size of the input value that function will receive, in bytes\n
                                GCD and LCM: Input size in bytes
   @param[in]  szp_input2_size  Size of a secondary input value for some functions. Ignored for others\n
                                Division: Size of the divisor, in bytes\n
                                Modular exponentiation: Size of the exponent, in bytes

@return required pool size in bytes
 */
extern size_t m_mem_pool_size(enum ied_encry_function iep_function,
                              size_t szp_input_size,
                              size_t szp_input2_size);

/** @ingroup memory
Returns the minimum required pool size for an ecc function for a special curve.

@param[in]  iep_function    Target function
@param[in]  iep_curve       Curve

@return required pool size in bytes
*/
extern size_t m_mem_pool_ecc_size(enum ied_ecc_function iep_function,
                                  enum ied_ecc_named_curves iep_curve);

/** @ingroup memory
   Generates a stack frame for the given lnum pool.

   This stores the pool state for restoring it later. If the pool is invalid, the
   stack frame will be invalid.

   @param[in]  adsp_pool   Pool of which the state shall be stored.

   @return Generated stack frame
 */
extern struct dsd_mem_pool_frame m_mem_pool_get_frame(const struct dsd_mem_pool_ele* adsp_pool);

/** @ingroup memory
   Returns the lnum pool to the state of a stack frame.

   This returns all temporaries to the pool, that were fetched, after the frame was generated.
   If the frame is invalid, the pool will remain unchanged.
   \p aadsp_pool must not be NULL but may point to a NULL-pointer.

   @param[out] aadsp_pool  Destination for the restored pool pointer.
   @param[in]  dsp_frame   Stack frame which shall be restored.

   @return ied_encry_success on success, error code otherwise
 */
extern enum ied_encry_return m_mem_pool_restore_frame(struct dsd_mem_pool_ele** aadsp_pool,
                                                      struct dsd_mem_pool_frame dsp_frame);


/** @ingroup memory
   Fetches a block of memory from the pool.

   The pool reference will be moved to the next element as necessary.
   A failure of the fetch may still consume part of the pool.
   The memory will be aligned to the width of a pointer (usually 4 or 8).

   @param[in,out] aadsp_pool       IN: Current pool pointer.\n
                                   OUT: Pool pointer after the get.
   @param[in]      szp_size        Size of requested memory block.

   @return Pointer to the block of memory, or NULL if the pool is empty or an error occurred
 */
extern void* m_mem_pool_get_chunk(struct dsd_mem_pool_ele** aadsp_pool,
                                  size_t szp_size);

/** @ingroup lnum
   Fetches a lnum instance from the pool.

   The pool reference will be moved to the next element as necessary.
   The number will have an even alloc word size.
   A failure of the fetch may still consume part of the pool.

   @param[in,out] aadsp_pool       IN: Current pool pointer.\n
                                   OUT: Pool pointer after the get.
   @param[in]     szp_size_bytes   Minimum size in bytes.

   @return A struct dsd_lnum, or NULL if the pool is empty or an error occurred
 */
extern struct dsd_lnum* m_mem_pool_get_lnum_byte_size(struct dsd_mem_pool_ele** aadsp_pool,
                                                      size_t szp_size_bytes);


/** @ingroup lnum
   Fetches a lnum instance from the pool.

   The pool reference will be moved to the next element as necessary.
   The number will have an even alloc word size at least as large as
   the used size of the source.
   A failure of the fetch may still consume part of the pool.

   @param[in,out] aadsp_pool   IN: Current pool pointer.\n
                               OUT: Pool pointer after the get.
   @param[in]     adsp_match   Source value.

   @return A struct dsd_lnum, or NULL if the pool is empty or an error occurred
 */
extern struct dsd_lnum* m_mem_pool_get_lnum_same_size(struct dsd_mem_pool_ele** aadsp_pool,
                                                      const struct dsd_lnum* adsp_match);


/** @ingroup lnum
   Fetches a copy of the source from the pool.

   The pool reference will be moved to the next element as necessary.
   The number will have an even alloc word size at least as large as
   the used size of the source. Content will be a copy of the source.
   A failure of the fetch may still consume part of the pool.

   @param[in,out] aadsp_pool   IN: Current pool pointer.\n
                               OUT: Pool pointer after the get.
   @param[in]     adsp_src     Source value.

   @return A struct dsd_lnum, or NULL if the pool is empty or an error occurred
 */
extern struct dsd_lnum* m_mem_pool_get_lnum_copy(struct dsd_mem_pool_ele** aadsp_pool,
                                                 const struct dsd_lnum* adsp_src);


/** @ingroup memory
   Frees a Lnum pool and all Lnums currently contained therein.

   @param[in]     adsp_memory      Memory manager.
   @param[in,out] adsp_pool        Lnum pool to be deleted.
 */
extern void m_mem_pool_free(struct dsd_memory* adsp_memory,
                            struct dsd_mem_pool_ele* adsp_pool);

/** @ingroup lnum
   Copies a lnum value to another.

   Destination and source may be the same; no operation is performed in this case.

   @param[in,out] adsp_dest     Destination value
   @param[in]     adsp_src      Source value

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_copy(struct dsd_lnum* adsp_dest,
                                         const struct dsd_lnum* adsp_src);



/** @ingroup lnum
   Assigns a primitive integer value to an lnum

   @param[in,out] adsp_dest     Destination value
   @param[in] inp_value        Integer value

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_set(struct dsd_lnum* adsp_dest,
                                        const int inp_value);


/** @ingroup lnum
   Assigns a random value in the range [0..2**k[ to a lnum.
   The value is always assumed to be nonnegative.

   Using a callback function amp_random as random generator.
   The Callback function is supposed to write a string of equally-distributed random, bitwise independent data.
   It is given the arguments:
   - avop_userfld: user-defined data of any content
   - avop_dest: a void* address where the random string is written to
   - szp_size: the length of the random string
   A return value of 0 is interpreted as success, any other as failure.

   The added functionality of m_lnum_random_value() is to encapsulate the lnum internals, perform error checking and correctly set the metadata.

   @param[in,out]  adsp_dest       Target Lnum
   @param[in]      szp_size_bits   k Size of the desired random number, in bits
   @param[in]      amp_random      Callback function to a random generator
   @param[in,out]  avop_userfld    Any data to be passed on the the callback function. Optional.

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_random_value(struct dsd_lnum* adsp_dest,
                                                 size_t szp_size_bits,
                                                 int (* amp_random)(void* avop_userfld,
                                                                    void* avop_dest,
                                                                    size_t szp_size),
                                                 void* avop_userfld);


/** @ingroup lnum
   Assigns a random value in the range [1..n-1] to a lnum.
   The value is always assumed to be positive.

   Using a callback function amp_random as random generator.
   The Callback function is supposed to write a string of equally-distributed random, bitwise independent data.
   It is given the arguments:
   - avop_userfld: user-defined data of any content
   - avop_dest: a void* address where the random string is written to
   - szp_size: the length of the random string
   A return value of 0 is interpreted as success, any other as failure.

   @param[in,out]  adsp_dest       Target Lnum
   @param[in]      adsp_limit      Limit n
   @param[in]      amp_random      Callback function to a random generator
   @param[in,out]  avop_userfld    Any data to be passed on the the callback function. Optional.

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_random_less_than(struct dsd_lnum* adsp_dest,
                                                     const struct dsd_lnum* adsp_limit,
                                                     int (* amp_random)(void* avop_userfld,
                                                                        void* avop_dest,
                                                                        size_t szp_size),
                                                     void* avop_userfld);


/** @ingroup lnum
   Gets the number of bytes set in the given large number.

   Note, that the highest order word may be incomplete.
   It is the minimum number of bytes needed to store this number.

   @param[in]  adsp_src    Number to be checked.

   @return Number of bytes in the large number, <0 on error.
 */
extern int m_lnum_get_byte_count(const struct dsd_lnum* adsp_src);


/** @ingroup lnum
   Gets the number of bits set in the given large number.

   Note, that the highest order word may be incomplete.
   It is the minimum number of bits needed to store this number.

   @param[in]  adsp_src    Number to be checked.

   @return Number of bits in the large number, <0 on error.
 */
extern int m_lnum_get_bit_count(const struct dsd_lnum* adsp_src);


/** @ingroup lnum
   Loads an lnum value from a byte array
   Assumes the source array to be byte-wise little-endian
   The value is assumed to be positive, and the destination value set accordingly.

   @param[in,out] adsp_dest     Destination value
   @param[in]     achp_src      Source byte array
   @param[in]     szp_length    Length of the source in bytes

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_load_bytes_le(struct dsd_lnum* adsp_dest,
                                                  const char* achp_src,
                                                  size_t szp_length);


/** @ingroup lnum
   Loads an lnum value from a byte array
   Assumes the source array to be byte-wise big-endian
   The value is assumed to be positive, and the destination value set accordingly.

   @param[in,out] adsp_dest     Destination value
   @param[in]     achp_src      Source byte array
   @param[in]     szp_length    Length of the source in bytes

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_load_bytes_be(struct dsd_lnum* adsp_dest,
                                                  const char* achp_src,
                                                  size_t szp_length);



/** @ingroup lnum
   Stores a lnum value to a byte array
   The data is stored in byte-wise little-endian order.
   If the source Lnum is negative, the absolute value is stored.
   If the zero fill option is used, the written bytes will always be the full
   length of the destination array.

   If the destination buffer is too small, a ::ied_encry_insufficient_buffer error is returned.

   @param[in,out] achp_dst         Destination byte array
   @param[in,out] aszp_length      IN: Length of the destination\n
                                   OUT: Number of bytes written
   @param[in]     adsp_src         Source Lnum
   @param[in]     bop_zero_fill    TRUE to fill the destination with trailing zeroes

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_store_bytes_le(char* achp_dst,
                                                   size_t* aszp_length,
                                                   const struct dsd_lnum* adsp_src,
                                                   BOOL bop_zero_fill);



/** @ingroup lnum
   Stores a lnum value to a byte array
   The data is stored in byte-wise big-endian order.
   If the source Lnum is negative, the absolute value is stored.
   If the zero fill option is used, the written bytes will always be the full
   length of the destination array.

   If the destination buffer is too small, a ::ied_encry_insufficient_buffer error is returned.

   @param[in,out] achp_dst         Destination byte array
   @param[in,out] aszp_length      IN: Length of the destination\n
                                   OUT: Number of bytes written
   @param[in]     adsp_src         Source Lnum
   @param[in]     bop_zero_fill    TRUE to fill the destination with leading zeroes

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_store_bytes_be(char* achp_dst,
                                                   size_t* aszp_length,
                                                   const struct dsd_lnum* adsp_src,
                                                   BOOL bop_zero_fill);



/** @ingroup lnum
   Compares two large numbers, taking signedness into account

   @param[in]  adsp_a        Value A
   @param[in]  adsp_b        Value B

   @return ied_lnum_comparison value containing the result or an error code
 */
extern enum ied_lnum_comparison m_lnum_compare_signed(const struct dsd_lnum* adsp_a,
                                                      const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Compares the absolute values of two large numbers

   @param[in]  adsp_a        Value A
   @param[in]  adsp_b        Value B

   @return ied_lnum_comparison value containing the result or an error code
 */
extern enum ied_lnum_comparison m_lnum_compare_absolute(const struct dsd_lnum* adsp_a,
                                                        const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Checks if a number is positive, negative, or zero

   @param[in]  adsp_val        Input value

   @return ied_lnum_comparison value containing the result or an error code
 */
extern enum ied_lnum_comparison m_lnum_sign(const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Checks if a number is odd

   @param[in]  adsp_val        Input value

   @return TRUE if odd, FALSE if even or if invalid
 */
extern BOOL m_lnum_is_odd(const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Checks if a number is even

   @param[in]  adsp_val        Input value

   @return TRUE if even, FALSE if odd of if invalid
 */
extern BOOL m_lnum_is_even(const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Checks if a number is zero

   @param[in]  adsp_val        Input value

   @return TRUE if zero, FALSE if not or if invalid
 */
extern BOOL m_lnum_is_zero(const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Checks if a number is positive 1.

   @param[in]  adsp_val        Input value

   @return TRUE if one, FALSE if not or if invalid
 */
extern BOOL m_lnum_is_one(const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Changes the sign of a lnum

   @param[in,out] adsp_val     Lnum value

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_negate(struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Adds two large number values and writes the result to a third number.

   Allows inplace operations; the destination may be equal to one or both of the inputs.

   \p adsp_dest must have more words allocated, that a or b are using.
   e.g. if a uses 3 and b 4 words, dest must have at least 5 words allocated.

   @param[in,out] adsp_dest     Destination value.
   @param[in]     adsp_a        Summand A
   @param[in]     adsp_b        Summand B

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_add(struct dsd_lnum* adsp_dest,
                                        const struct dsd_lnum* adsp_a,
                                        const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Subtracts two large number values and writes the result to a third number.

   Allows inplace operations; the destination may be equal to one or both of the inputs.

   \p adsp_dest must have more words allocated, that a or b are using.
   e.g. if a uses 3 and b 4 words, dest must have at least 5 words allocated.

   @param[in,out] adsp_dest     Destination value.
   @param[in]     adsp_a        Minuend
   @param[in]     adsp_b        Subtrahend

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_sub(struct dsd_lnum* adsp_dest,
                                        const struct dsd_lnum* adsp_a,
                                        const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Shifts a large number value to the left.
   (binary shift)

   Allows inplace operations; the destination may be equal to the input.

   @param[in,out] adsp_dest     Destination value.
   @param[in]     adsp_val      Input value
   @param[in]     unp_shift     Shift distance in bits

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_lshift(struct dsd_lnum* adsp_dest,
                                           const struct dsd_lnum* adsp_a,
                                           size_t szp_shift);



/** @ingroup lnum
   Shifts a large number value to the right.
   (binary shift)

   Allows inplace operations; the destination may be equal to the input.

   @param[in,out] adsp_dest     Destination value.
   @param[in]     adsp_val      Input value
   @param[in]     unp_shift     Shift distance in bits

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_rshift(struct dsd_lnum* adsp_dest,
                                           const struct dsd_lnum* adsp_a,
                                           size_t unp_shift);



/** @ingroup lnum
   Multiplies two large number values and writes the result to a third number.

   No inplace; destination may not be equal to either of the inputs.

   @param[out]    adsp_dest       Destination value.
   @param[in,out] adsp_pool       Pool for temporary numbers. Optional.
   @param[in]     adsp_a          Factor A
   @param[in]     adsp_b          Factor B

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_mult(struct dsd_lnum* adsp_dest,
                                         struct dsd_mem_pool_ele* adsp_pool,
                                         const struct dsd_lnum* adsp_a,
                                         const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Squares a large number value

   No inplace; destination may not be equal to either of the inputs.

   @param[out]    adsp_dest   Destination value.
   @param[in,out] adsp_pool   Pool for temporary numbers. Optional.
   @param[in]     adsp_val    Input value.

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_square(struct dsd_lnum* adsp_dest,
                                           struct dsd_mem_pool_ele* adsp_pool,
                                           const struct dsd_lnum* adsp_val);



/** @ingroup lnum
   Divides two large number values.
   Outputs either of or both the quotient and the remainder, depending on whether destination values were given or NULL.

   Allows inplace operations; the destinations may be equal to either of the inputs.

   @param[in,out] adsp_quot  Quotient destination value. Optional.
   @param[in,out] adsp_mod   Remainder destination value. Optional.
   @param[in,out] adsp_pool  Pool for temporary numbers.
   @param[in]     adsp_a     Dividend
   @param[in]     adsp_b     Divisor

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_divide(struct dsd_lnum* adsp_quot,
                                           struct dsd_lnum* adsp_mod,
                                           struct dsd_mem_pool_ele* adsp_pool,
                                           const struct dsd_lnum* adsp_a,
                                           const struct dsd_lnum* adsp_b);



/** @ingroup lnum
   Calculates a large number's inverse with respect to a modulus.

   Destination must be 2 words larger, than the modulus.
   No inplace; destination may not be equal to either of the inputs.

   @param[in,out] adsp_inv     Inverse destination value.
   @param[in,out] adsp_pool    Pool for temporary numbers.
   @param[in]     adsp_val     Input value
   @param[in]     adsp_mod     Modulus

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_inverse(struct dsd_lnum* adsp_inv,
                                            struct dsd_mem_pool_ele* adsp_pool,
                                            const struct dsd_lnum* adsp_val,
                                            const struct dsd_lnum* adsp_mod);



/** @ingroup lnum
   Calculates the greatest common divisor (GCD) of two large number values.

   No inplace; destination may not be equal to either of the inputs.
   A and B must be non-0. The result must be as large, as the smaller input.
   The result will always be positive.

   @param[in,out] adsp_gcd     Greatest common divisor destination value
   @param[in,out] adsp_pool    Pool for temporary numbers.
   @param[in]     adsp_a       Value A
   @param[in]     adsp_b       Value B

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_gcd(struct dsd_lnum* adsp_gcd,
                                        struct dsd_mem_pool_ele* adsp_pool,
                                        const struct dsd_lnum* adsp_a,
                                        const struct dsd_lnum* adsp_b);


/** @ingroup lnum
   Calculates the least common multiple (LCM) of two large numbers.

   Not in-place capable. The destination must have a capacity of len a + len b.
   The inputs must not be 0. The result will always be positive.

   @param[out] adsp_lcm    LCM destination.
   @param[in]  adsp_pool   Pool for temporary numbers.
   @param[in]  adsp_a      Number a.
   @param[in]  adsp_b      Number b.

   @return ::ied_encry_success on success, error code otherwise.
 */
extern enum ied_encry_return m_lnum_lcm(struct dsd_lnum* adsp_lcm,
                                        struct dsd_mem_pool_ele* adsp_pool,
                                        const struct dsd_lnum* adsp_a,
                                        const struct dsd_lnum* adsp_b);

/** @ingroup lnum
   Performs a modular exponentiation.

   Not in-place capable. The destination must have a capacity of at least the modulus'
   length. Base and exponent may be 0. If the exponent is 0, the result is always 1,
   even if the base is 0. Neither may be negative. The base may not be larger,
   than the modulus. The modulus must be >0.

   @param[out] adsp_dest   Destination number.
   @param[in]  adsp_pool   Pool for temporary calculations.
   @param[in]  adsp_base   Base number.
   @param[in]  adsp_exp    Exponent number.
   @param[in]  adsp_mod    Modulus number.

   @return ::ied_encry_success on success, error code otherwise.
 */
extern enum ied_encry_return m_lnum_exp_mod(struct dsd_lnum* adsp_dest,
                                            struct dsd_mem_pool_ele* adsp_pool,
                                            const struct dsd_lnum* adsp_base,
                                            const struct dsd_lnum* adsp_exp,
                                            const struct dsd_lnum* adsp_mod);


/** @ingroup lnum
   Initialized a Montgomery context for the given modulus.

   The content of the context will be allocated using \p adsp_mem.
   The modulus must be odd, positive and greater than 1. It can be released
   after creating the context.

   @param[out] adsp_new_ctx    Return pointer for the new context.
   @param[in]  adsp_mem        Memory manager used to allocate the context.
   @param[in]  adsp_pool       Pool for temporary numbers.
   @param[in]  adsp_mod        Modulus for which the context shall be created.

   @return ::ied_encry_success on success, error code otherwise.
 */
extern enum ied_encry_return m_lnum_mont_init(struct dsd_lnum_montgomery_ctx* adsp_new_ctx,
                                              struct dsd_memory* adsp_mem,
                                              struct dsd_mem_pool_ele* adsp_pool,
                                              const struct dsd_lnum* adsp_mod);

/** @ingroup lnum
   Turns a large number into Montgomery form.

   This must be done before doing reduction with m_lnum_mont_red().

   Allows inplace operations; \p adsp_dest may be \p adsp_a.
   \p adsp_a must be positive, and must not have more words in length than the modulus.

   @param[out] adsp_dest       Output for the number in Montgomery form.
   @param[in]  adsp_pool       Pool for temporary numbers.
   @param[in]  adsp_a          Number to be montgomerized.
   @param[in]  adsp_context    Montgomery context to be used.

   @return ::ied_encry_success on success, error code otherwise.
 */
extern enum ied_encry_return m_lnum_mont_conv(struct dsd_lnum* adsp_dest,
                                              struct dsd_mem_pool_ele* adsp_pool,
                                              const struct dsd_lnum* adsp_a,
                                              const struct dsd_lnum_montgomery_ctx* adsp_context);
/** @ingroup lnum
   Performs a Montgomery reduction.

   This replaces m_lnum_div() during modular multiplication when multiplying numbers
   in Montgomery form. In this case, the result will also be in Montgomery form.

   When using this function on a number in Montgomery form or the result of
   addition/subtraction, the result will return to 'normal' (non-Montgomery) form.

   \p adsp_a must be smaller than the square of the modulus and positive.

   Allows inplace operations; \p adsp_dest may be \p adsp_a.

   @param[out] adsp_dest       Result of the reduction.
   @param[in]  adsp_pool       Pool for temporary numbers.
   @param[in]  adsp_a          Number to be reduced.
   @param[in]  adsp_context    Montgomery context to be used.

   @return ::ied_encry_success on success, error code otherwise.
 */
extern enum ied_encry_return m_lnum_mont_red(struct dsd_lnum* adsp_dest,
                                             struct dsd_mem_pool_ele* adsp_pool,
                                             const struct dsd_lnum* adsp_a,
                                             const struct dsd_lnum_montgomery_ctx* adsp_context);

/** @ingroup lnum
   Releases a Montgomery context.

   \p adsp_mem must be the same memory provider that was used to create the context.

   @param[in]  adsp_context    Context to be released.
   @param[in]  adsp_mem        Memory manager associated with the context.
 */
extern void m_lnum_mont_free(struct dsd_lnum_montgomery_ctx* adsp_context,
                             struct dsd_memory* adsp_mem);





/** @ingroup lnum
   @deprecated
   Performs a modulus reduction using the Barret algorithm

   No inplace; destination may not be equal to either of the inputs.

   @param[in,out] adsp_dest    Reduced destination value
   @param[in]     adsp_val     Input value
   @param[in]     adsp_modulus Modulus and precalculated constants

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_barret_reduce(struct dsd_lnum* adsp_dest,
                                                  struct dsd_mem_pool_ele* adsp_pool,
                                                  const struct dsd_lnum* adsp_val,
                                                  const struct dsd_lnum_barret* adsp_modulus);



/** @ingroup lnum
   @deprecated
   Prepares a modulus reduction with the Barret algorithm
   Calculates constants and initializes the dsd_lnum_barret structure

   @param[in,out] adsp_barret  Barret context
   @param[in,out] adsp_pool    Lnum pool
   @param[in]     adsp_modulus Modulus value

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_barret_init(struct dsd_lnum_barret* adsp_barret,
                                                struct dsd_memory* adsp_memory,
                                                struct dsd_mem_pool_ele* adsp_pool,
                                                const struct dsd_lnum* adsp_modulus);



/** @ingroup lnum
   @deprecated
   Releases the lnums in a dsd_lnum_barret to the pool.

   @param[in,out] adsp_barret  Barret context
   @param[in,out] adsp_pool    Lnum pool
 */
extern void m_lnum_barret_free(struct dsd_memory* adsp_memory,
                               struct dsd_lnum_barret* adsp_barret);



/** @ingroup lnum
   @deprecated
   Generates a random prime number of a given size.

   For the \p amp_random callback function, see m_lnum_random_value documentation.

   The \p amp_callback function receives one parameter, inp_status.
   [PLACEHOLDER what inp_status is good for]
   If the callback function returns a negative value, m_lnum_generate_prime will stop operating and return with a ied_encry_aborted code.

   @param[in,out] adsp_dest        Output of the generated prime
   @param[in,out] adsp_pool        Lnum pool
   @param[in]     aunp_size_bytes  Size of the prime number to be generated, in byts
   @param[in]     amp_random       Callback function to a random generator
   @param[in]     amp_callback     Callback function to communicate progress and abort signals. Optional.

   @return 0 on success, error code otherwise
 */
extern enum ied_encry_return m_lnum_dummy_get_prime();

/** @ingroup lnum
   Tests (probable) primality of an odd integer by Miller-Rabin

   Using a callback function \p amp_random which is specified in the declaration of m_lnum_random_less_than()

   @param[in] adsp_candidate    Odd integer to be tested
   @param[in] adsp_pool         Lnum pool
   @param[in] adsp_mont_ctx     Montgomery context of the candidate
   @param[in] unp_iterate       Iteration number used for Miller-Rabin (accuracy parameter)
   @param[in] amp_random        Callback function to a random generator
   @param[in,out] avop_userfld  Any data to be passed on the the callback function. Optional.

   @return ::ied_encry_success if (probable) prime, ::ied_lnum_no_prime if composite
 */

extern enum ied_encry_return m_lnum_test_prime(const struct dsd_lnum* adsp_candidate,
                                               struct dsd_mem_pool_ele* adsp_pool,
                                               const struct dsd_lnum_montgomery_ctx* adsp_mont_ctx,
                                               unsigned int unp_iterate,
                                               int (* amp_random)(void* avop_userfld,
                                                                  void* avop_dest,
                                                                  size_t szp_size),
                                               void* avop_userfld);

/** @ingroup ecc
   Returns a pointer to the elliptic curve parameters for a certain named curve
   On its first invocation for the specific curve, performs some precalculations and stores the results together with the curve parameters.

   These precomputations affect a hidden global state. It is very important that the memory provided by \p adsp_memory is persistent over the lifetime of the program.

   @param[in]      iep_curve_name  Curve name
   @param[in,out]  adsp_memory     Memory-provider to allocate memory for the precalculations. Optional if precomputations have been done in a previous call.
   @param[in]      adsp_pool       Lnum pool for temporary values. Optional.

   @returns struct dsd_ec_curve_params pointer on success, NULL on failure
 */
extern const struct dsd_ec_curve_params* m_ecc_init_named_curve(enum ied_ecc_named_curves iep_curve_name,
                                                                struct dsd_memory *adsp_memory,
                                                                struct dsd_mem_pool_ele *adsp_pool);

/** @ingroup ecc
   Frees any precomputed values allocated by m_ecc_init_named_curve().
   The raw curve parameters themselves remain available.

   @param[in,out] adsp_memory     Memory-provider
 */
extern void m_ecc_precomp_free(struct dsd_memory *adsp_memory);

/** @ingroup ecc
   Allocates the members of an ecdh context. Context has to be alread allocated,
   members set to zero, and member adsc_params set (using
   m_ecc_init_named_curve()). Before freeing context structure, call
   m_ecc_free_keypair().

   @param[in,out] adsp_memory          memory provider
   @param[in,out] adsp_ecc_keypair     ecdh context

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_init_keypair(struct dsd_memory *adsp_memory,
                                                struct dsd_ecc_keypair *adsp_ecc_keypair);

/** @ingroup ecc
   Generates a random key-pair in an already initialized context.
   Buffer for own public key (given to be sent via SSL) must
   be already allocated with same size as given in \p aszp_pub_buffer_len.

   @param[in,out] adsp_ecc_keypair     ecdh context
   @param[in,out] achp_public_key_out  buffer for own public key. NULL allowed, then key is only generated in \p adsp_ecc_keypair.
   @param[in,out] aszp_pub_buffer_len  IN: buffer size\n
                                       OUT: lengh of public key (in bytes)
   @param[in,out] adsp_pool            lnum pool
   @param[in]     amp_random           function that generates random bytes uniformly distributed
   @param[in,out] avop_userfld         Any data to be passed on the the \p amp_random function. Optional.

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_gen_rand_keypair(struct dsd_ecc_keypair *adsp_ecc_keypair,
                                                    char *achp_public_key_out,
                                                    size_t *aszp_pub_buffer_len,
                                                    struct dsd_mem_pool_ele *adsp_pool,
                                                    int (* amp_random)(void* avop_userfld,
                                                                       void* avop_dest,
                                                                       size_t szp_size),
                                                    void* avop_userfld);

/** @ingroup ecc
   Loads a given private key into ecdh context and generates the public key.
   Buffer for own public key (given to be sent via SSL) must be already
   allocated with same size as given in \p aszp_pub_buffer_len.

   @param[in,out] adsp_ecc_keypair     ecdh context
   @param[in,out] achp_public_key_out  buffer for own public key. NULL allowed, then key is only generated in keypair.
   @param[in,out] aszp_pub_buffer_len  IN: buffer size\n
                                       OUT: lengh of public key (in bytes)
   @param[in,out] adsp_pool            lnum pool
   @param[in]     achp_private_key     private key buffer
   @param[in]     szp_priv_key_len     length of private key

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_gen_static_keypair(struct dsd_ecc_keypair *adsp_ecc_keypair,
                                                      char *achp_public_key_out,
                                                      size_t *aszp_pub_buffer_len,
                                                      struct dsd_mem_pool_ele *adsp_pool,
                                                      const char *achp_private_key,
                                                      const size_t szp_priv_key_len);

/** @ingroup ecc
   Exports the already generated public key of a dsd_ecc_keypair into the
   given, already allocated buffer.

   @param[in,out] achp_public_key_out   Output buffer
   @param[in,out] aszp_pub_buffer_len   IN: buffer size\n
                                        OUT: lengh of public key (in bytes)
   @param[in]     adsp_ecc_keypair      keypair with already generated public key

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_export_pub_key(char *achp_public_key_out,
                                                  size_t *aszp_pub_buffer_len,
                                                  struct dsd_ecc_keypair *adsp_ecc_keypair);

/** @ingroup ecc
   Generates the shared ECDH secret given the peers public key and its length.
   Before calling this function, m_ecc_init_keypair() must be called and key pair
   must be generated using either m_ecc_gen_rand_keypair() or m_ecc_gen_static_keypair().
   \p achp_secret_out has to be already allocated and size of buffer be given in \p aszp_secret_len.

   @param[out]    achp_secret_out      output buffer for shared secret
   @param[in,out] aszp_secret_len      IN: length of buffer\n
                                       OUT: length of shared secret (in bytes)
   @param[in,out] adsp_ecc_keypair     ECDH context
   @param[in,out] adsp_pool            lnum pool
   @param[in]     achp_public_key      peers public key (bytewise big endian) from ssl
   @param[in]     szp_len_pub_key      size of peers public key (in bytes)

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_gen_secret(char *achp_secret_out,
                                              size_t *aszp_secret_len,
                                              struct dsd_ecc_keypair *adsp_ecc_keypair,
                                              struct dsd_mem_pool_ele *adsp_pool,
                                              const char *achp_public_key,
                                              const size_t szp_len_pub_key);

/** @ingroup ecc
   Generates the ECDSA signature.
   Before calling this function, m_ecc_init_keypair() must be called and key pair
   must be generated (e.g., using m_ecc_gen_static_keypair()).
   r and s out has to be allocated with size of n

   @param[out]    adsp_r_out           r
   @param[out]    adsp_s_out           s
   @param[in,out] adsp_pool            lnum pool
   @param[in]     achp_hash_buffer     buffer containing hash
   @param[in]     szp_hash_len         hash length
   @param[in]     adsp_ecc_keypair     keypair
   @param[in]     amp_random           random buffer generator
   @param[in]     avop_userfld         userfield (optional)

   @return 0 on success, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_gen_signature(struct dsd_lnum *adsp_r_out,
                                                 struct dsd_lnum *adsp_s_out,
                                                 struct dsd_mem_pool_ele *adsp_pool,
                                                 char *achp_hash_buffer,
                                                 size_t szp_hash_len,
                                                 struct dsd_ecc_keypair *adsp_ecc_keypair,
                                                 int (* amp_random)(void* avop_userfld,
                                                                    void* avop_dest,
                                                                    size_t szp_size),
                                                 void* avop_userfld);

/** @ingroup ecc
   Verifies an ECDSA signature.

   @param[in,out] adsp_pool            lnum pool
   @param[in]     achp_hash_buffer     buffer containing hash
   @param[in]     szp_hash_len         hash length
   @param[in]     adsp_public_key      public key of signature that has to be verified
   @param[in]     adsp_r               r
   @param[in]     adsp_s               s
   @param[in]     adsp_curve           curve parameters

   @return 0 if signature is valid, errorcode otherwise
 */
extern enum ied_encry_return m_ecc_verify_sig(struct dsd_mem_pool_ele *adsp_pool,
                                              char *achp_hash_buffer,
                                              size_t szp_hash_len,
                                              struct dsd_ec_point *adsp_public_key,
                                              struct dsd_lnum *adsp_r,
                                              struct dsd_lnum *adsp_s,
                                              const struct dsd_ec_curve_params *adsp_curve);

/** @ingroup ecc
   Prepares a context to be freed. Call this function only after m_ecc_init_keypair()
   was called and returned success.

   @param[in,out] adsp_memory         memory provider
   @param[in,out] adsp_ecc_keypair    ECDH context
 */
extern void m_ecc_free_keypair(struct dsd_memory *adsp_memory,
                               struct dsd_ecc_keypair *adsp_ecc_keypair);



/** @ingroup other
   Bit field characterizing the capabilities of the hardware platform
   with respect to cryptography extensions
   (some of which can not be reliably determined at compile time)
*/
extern const int ing_hardware_capabilities;

#define HL_HARDWARE_SUPPORT_FLAG_AES     0x01
#define HL_HARDWARE_SUPPORT_FLAG_PMUL    0x02
#define HL_HARDWARE_SUPPORT_FLAG_SHA1    0x10
#define HL_HARDWARE_SUPPORT_FLAG_SHA256  0x20

#define HL_HARDWARE_SUPPORT_AES     ((ing_hardware_capabilities & HL_HARDWARE_SUPPORT_FLAG_AES) != 0)
#define HL_HARDWARE_SUPPORT_PMUL    ((ing_hardware_capabilities & HL_HARDWARE_SUPPORT_FLAG_PMUL) != 0)
#define HL_HARDWARE_SUPPORT_SHA1    ((ing_hardware_capabilities & HL_HARDWARE_SUPPORT_FLAG_SHA1) != 0)
#define HL_HARDWARE_SUPPORT_SHA256  ((ing_hardware_capabilities & HL_HARDWARE_SUPPORT_FLAG_SHA256) != 0)

/** @ingroup symcipher
  Key struct for 3DES
  Used inside #dsd_cipher_key struct
 */
struct dsd_3des_subkey {
    unsigned int unrc_subkey1[32];              //!< 1st DES key
    unsigned int unrc_subkey2[32];              //!< 2nd DES key
    unsigned int unrc_subkey3[32];              //!< 3rd DES key
};

/** @ingroup symcipher
  Symmetric cipher key struct
  Used for AES128, AES192, AES256, and 3DES
*/
struct dsd_cipher_key {
    unsigned int unc_key_size;                  //!< size of the unexpanded key in bytes
    BOOL boc_disallow_hardware_acceleration;
    union {
        unsigned char byrc_aes_expkey[240];
        struct dsd_3des_subkey dsc_3des_subkey;
    };
};

/** @ingroup hashes
  SHA-3 internal state
*/
struct dsd_sha_3_state {
    union {
        unsigned char byrc_array[200];
        unsigned long long ulrc_array[25];
    };
    int imc_current_pos; //current offset for new updates
    int imc_rate_size;   //rate size in bytes
    int imc_hash_size;   //hash size in bytes
};

#if !defined DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1

struct dsd_gather_i_1 {
    struct dsd_gather_i_1 *adsc_next;        //!< next in chain
    char *                achc_ginp_cur;     //!< current position
    char *                achc_ginp_end;     //!< end of input data
};

#endif

/** @ingroup symcipher
\brief Initialize a cipher key, including key expansion

Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key remains unaffected.

No allocation is performed.

@param[out] adsp_key      Expanded key
@param[in]  abyp_key      Key data.
@param[in]  szp_key_len   Length of key data, in bytes.
*/
typedef void (*amd_init_cipher_key)(struct dsd_cipher_key* adsp_key,
                                    const unsigned char* abyp_key,
                                    size_t szp_key_len);

/** @ingroup symcipher
    Initialize AES encryption key using software implementation.

    Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

    @copydetails amd_init_cipher_key
*/
extern void m_aes_init_enc_key_sw(struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_key,
                                  size_t szp_key_len);

/** @ingroup symcipher
   Initialize AES encryption key using hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.
   
   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   @copydetails amd_init_cipher_key 
 */
extern void m_aes_init_enc_key_hw(struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_key,
                                  size_t szp_key_len);

/** @ingroup symcipher
    Initialize AES decryption key using software implementation.

    Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

    @copydetails amd_init_cipher_key
 */
extern void m_aes_init_dec_key_sw(struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_key,
                                  size_t szp_key_len);

/** @ingroup symcipher
   Initialize AES decryption key using hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.
   
   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   @copydetails amd_init_cipher_key
 */
extern void m_aes_init_dec_key_hw(struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_key,
                                  size_t szp_key_len);

/** @ingroup symcipher
   Initialize 3DES key.
   
   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   @copydetails amd_init_cipher_key
 */
extern void m_3des_init_key(struct dsd_cipher_key* adsp_key,
                            const unsigned char* abyp_key,
                            size_t szp_key_len);

/** @ingroup symcipher
   Initialize AES encryption key using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   @copydetails amd_init_cipher_key
 */

extern void m_aes_init_enc_key_auto(struct dsd_cipher_key* adsp_key,
                                    const unsigned char* abyp_key,
                                    size_t szp_key_len);
/** @ingroup symcipher
   Initialize AES decryption key using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   @copydetails amd_init_cipher_key
 */
extern void m_aes_init_dec_key_auto(struct dsd_cipher_key* adsp_key,
                                    const unsigned char* abyp_key,
                                    size_t szp_key_len);


/** @ingroup symcipher
\brief Encrypt or decrypt a message using a block cipher.

Allows inplace operations; abyp_output may be equal to abyp_input.

@param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
@param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
@param[in]  szp_len         Length of both input and output, given in bytes.
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector of fixed length.
*/
typedef void (*amd_block_crypt)(unsigned char* abyp_output,
                                const unsigned char* abyp_input,
                                size_t szp_len,
                                const struct dsd_cipher_key* adsp_key,
                                const unsigned char* abyp_iv);
    
/** @ingroup symcipher
   AES CBC encryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_encrypt_sw(unsigned char* abyp_output,
                                 const unsigned char* abyp_input,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC encryption using hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_encrypt_hw(unsigned char* abyp_output,
                                 const unsigned char* abyp_input,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC decryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_decrypt_sw(unsigned char* abyp_output,
                                 const unsigned char* abyp_input,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC decryption using hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_decrypt_hw(unsigned char* abyp_output,
                                 const unsigned char* abyp_input,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CTR encryption/decryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_ctr_crypt_sw(unsigned char* abyp_output,
                               const unsigned char* abyp_input,
                               size_t szp_len,
                               const struct dsd_cipher_key* adsp_key,
                               const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CTR encryption/decryption using hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_ctr_crypt_hw(unsigned char* abyp_output,
                               const unsigned char* abyp_input,
                               size_t szp_len,
                               const struct dsd_cipher_key* adsp_key,
                               const unsigned char* abyp_iv);

/** @ingroup symcipher
   3DES CBC encryption.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_3des_cbc_encrypt(unsigned char* abyp_output,
                               const unsigned char* abyp_input,
                               size_t szp_len,
                               const struct dsd_cipher_key* adsp_key,
                               const unsigned char* abyp_iv);

/** @ingroup symcipher
   3DES CBC decryption.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_3des_cbc_decrypt(unsigned char* abyp_output,
                               const unsigned char* abyp_input,
                               size_t szp_len,
                               const struct dsd_cipher_key* adsp_key,
                               const unsigned char* abyp_iv);


/** @ingroup symcipher
   CBC encryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_encrypt_auto(unsigned char* abyp_output,
                                   const unsigned char* abyp_input,
                                   size_t szp_len,
                                   const struct dsd_cipher_key* adsp_key,
                                   const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC decryption key using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   Note: the IV is not updated automatically.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_decrypt_auto(unsigned char* abyp_output,
                                   const unsigned char* abyp_input,
                                   size_t szp_len,
                                   const struct dsd_cipher_key* adsp_key,
                                   const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CTR  encryption/decryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Allows inplace operations; abyp_output may be equal to abyp_input.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  abyp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_ctr_crypt_auto(unsigned char* abyp_output,
                                 const unsigned char* abyp_input,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv);

/** @ingroup symcipher
\brief Encrypt and authenticate a message using a AEAD cipher.

Allows inplace operations; abyp_output may be equal to abyp_input.

@param[out] abyp_cipher     Ciphertext output
@param[in]  abyp_plain      Plaintext input
@param[in]  szp_len         Length of both input and output, given in bytes.
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector (IV).
@param[in]  szp_iv_len      IV length, in bytes.
@param[in]  abyp_adddata    Authentication data.
@param[in]  szp_adddata_len Authentication data length, in bytes.
@param[out] abyp_tag        Authentication tag.
@param[in]  szp_tag_len     Authentication tag length, in bytes.
*/
typedef void (*amd_aead_encrypt)(unsigned char* abyp_cipher,
                                 const unsigned char* abyp_plain,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv,
                                 size_t szp_iv_len,
                                 const unsigned char* abyp_adddata,
                                 size_t szp_adddata_len,
                                 unsigned char* abyp_tag,
                                 size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM encryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_cipher may be equal to abyp_plain.

   @param[out] abyp_cipher     Ciphertext output
   @param[in]  abyp_plain      Plaintext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[out] abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
 */
extern void m_aes_gcm_encrypt_sw(unsigned char* abyp_cipher,
                                 const unsigned char* abyp_plain,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv,
                                 size_t szp_iv_len,
                                 const unsigned char* abyp_adddata,
                                 size_t szp_adddata_len,
                                 unsigned char* abyp_tag,
                                 size_t szp_tag_len);


/** @ingroup symcipher
   AES GCM encryption using AES hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_cipher may be equal to abyp_plain.

   @param[out] abyp_cipher     Ciphertext output
   @param[in]  abyp_plain      Plaintext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[out] abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
 */
extern void m_aes_gcm_encrypt_hw1(unsigned char* abyp_cipher,
                                  const unsigned char* abyp_plain,
                                  size_t szp_len,
                                  const struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_iv,
                                  size_t szp_iv_len,
                                  const unsigned char* abyp_adddata,
                                  size_t szp_adddata_len,
                                  unsigned char* abyp_tag,
                                  size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM encryption using AES GCM hardware acceleration.

   If either #HL_HARDWARE_SUPPORT_AES or #HL_HARDWARE_SUPPORT_PMUL are FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_cipher may be equal to abyp_plain.

   @param[out] abyp_cipher     Ciphertext output
   @param[in]  abyp_plain      Plaintext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[out] abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
 */
extern void m_aes_gcm_encrypt_hw2(unsigned char* abyp_cipher,
                                  const unsigned char* abyp_plain,
                                  size_t szp_len,
                                  const struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_iv,
                                  size_t szp_iv_len,
                                  const unsigned char* abyp_adddata,
                                  size_t szp_adddata_len,
                                  unsigned char* abyp_tag,
                                  size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM encryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES, #HL_HARDWARE_SUPPORT_PMUL and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Allows inplace operations; abyp_cipher may be equal to abyp_plain.

   @param[out] abyp_cipher     Ciphertext output
   @param[in]  abyp_plain      Plaintext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[out] abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
 */
extern void m_aes_gcm_encrypt_auto(unsigned char* abyp_cipher,
                                   const unsigned char* abyp_plain,
                                   size_t szp_len,
                                   const struct dsd_cipher_key* adsp_key,
                                   const unsigned char* abyp_iv,
                                   size_t szp_iv_len,
                                   const unsigned char* abyp_adddata,
                                   size_t szp_adddata_len,
                                   unsigned char* abyp_tag,
                                   size_t szp_tag_len);




/** @ingroup symcipher
\brief Decrypt and verify a message using a AEAD cipher.

Allows inplace operations; abyp_output may be equal to abyp_input.

@param[out] abyp_plain      Plaintext output
@param[in]  abyp_cipher     Ciphertext input
@param[in]  szp_len         Length of both input and output, given in bytes.
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector (IV).
@param[in]  szp_iv_len      IV length, in bytes.
@param[in]  abyp_adddata    Authentication data.
@param[in]  szp_adddata_len Authentication data length, in bytes.
@param[in]  abyp_tag        Authentication tag.
@param[in]  szp_tag_len     Authentication tag length, in bytes.

@return TRUE if message authenticates, FALSE if not
*/
typedef BOOL (*amd_aead_decrypt)(unsigned char* abyp_plain,
                                 const unsigned char* abyp_cipher,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv,
                                 size_t szp_iv_len,
                                 const unsigned char* abyp_adddata,
                                 size_t szp_adddata_len,
                                 const unsigned char* abyp_tag,
                                 size_t szp_tag_len);


/** @ingroup symcipher
   AES GCM decryption using software implementation.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.
   
   @param[out] abyp_plain      Plaintext output
   @param[in]  abyp_cipher     Ciphertext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[in]  abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
   
   @return TRUE if message authenticates, FALSE if not
 */
extern BOOL m_aes_gcm_decrypt_sw(unsigned char* abyp_plain,
                                 const unsigned char* abyp_cipher,
                                 size_t szp_len,
                                 const struct dsd_cipher_key* adsp_key,
                                 const unsigned char* abyp_iv,
                                 size_t szp_iv_len,
                                 const unsigned char* abyp_adddata,
                                 size_t szp_adddata_len,
                                 const unsigned char* abyp_tag,
                                 size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM decryption using AES hardware acceleration.

   If #HL_HARDWARE_SUPPORT_AES is FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.
   
   @param[out] abyp_plain      Plaintext output
   @param[in]  abyp_cipher     Ciphertext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[in]  abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
   
   @return TRUE if message authenticates, FALSE if not
 */
extern BOOL m_aes_gcm_decrypt_hw1(unsigned char* abyp_plain,
                                  const unsigned char* abyp_cipher,
                                  size_t szp_len,
                                  const struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_iv,
                                  size_t szp_iv_len,
                                  const unsigned char* abyp_adddata,
                                  size_t szp_adddata_len,
                                  const unsigned char* abyp_tag,
                                  size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM decryption using AES GCM hardware acceleration.

   If either #HL_HARDWARE_SUPPORT_AES or #HL_HARDWARE_SUPPORT_PMUL are FALSE, calling this function will cause a fatal processor fault.

   Value of \p boc_disallow_hardware_acceleration flag in \p adsp_key is ignored.

   Allows inplace operations; abyp_output may be equal to abyp_input.
   
   @param[out] abyp_plain      Plaintext output
   @param[in]  abyp_cipher     Ciphertext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[in]  abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
   
   @return TRUE if message authenticates, FALSE if not
 */
extern BOOL m_aes_gcm_decrypt_hw2(unsigned char* abyp_plain,
                                  const unsigned char* abyp_cipher,
                                  size_t szp_len,
                                  const struct dsd_cipher_key* adsp_key,
                                  const unsigned char* abyp_iv,
                                  size_t szp_iv_len,
                                  const unsigned char* abyp_adddata,
                                  size_t szp_adddata_len,
                                  const unsigned char* abyp_tag,
                                  size_t szp_tag_len);


/** @ingroup symcipher
   AES GCM decryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES, #HL_HARDWARE_SUPPORT_PMUL and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Allows inplace operations; abyp_output may be equal to abyp_input.
   
   @param[out] abyp_plain      Plaintext output
   @param[in]  abyp_cipher     Ciphertext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[in]  abyp_tag        Authentication tag.
   @param[in]  szp_tag_len     Authentication tag length, in bytes.
   
   @return TRUE if message authenticates, FALSE if not
 */
extern BOOL m_aes_gcm_decrypt_auto(unsigned char* abyp_plain,
                                   const unsigned char* abyp_cipher,
                                   size_t szp_len,
                                   const struct dsd_cipher_key* adsp_key,
                                   const unsigned char* abyp_iv,
                                   size_t szp_iv_len,
                                   const unsigned char* abyp_adddata,
                                   size_t szp_adddata_len,
                                   const unsigned char* abyp_tag,
                                   size_t szp_tag_len);

/** @ingroup symcipher
\brief Encrypt or decrypt a message using a block cipher.

Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

@param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
@param[in]  adsp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
@param[in]  szp_len         Length of both input and output, given in bytes (Optional, if not needed, set -1).
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector of fixed length.
*/
typedef void (*amd_cbc_gather_crypt)(unsigned char* abyp_output,
                                     const struct dsd_gather_i_1* adsp_input,
                                     size_t szp_len,
                                     const struct dsd_cipher_key* adsp_key,
                                     const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC encryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  adsp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes (Optional, if not needed, set -1).
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_encrypt_gather(unsigned char* abyp_output,
                                     const struct dsd_gather_i_1* adsp_input,
                                     size_t szp_len,
                                     const struct dsd_cipher_key* adsp_key,
                                     const unsigned char* abyp_iv);

/** @ingroup symcipher
   AES CBC decryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  adsp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes (Optional, if not needed, set -1).
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_aes_cbc_decrypt_gather(unsigned char* abyp_output,
                                     const struct dsd_gather_i_1* adsp_input,
                                     size_t szp_len,
                                     const struct dsd_cipher_key* adsp_key,
                                     const unsigned char* abyp_iv);

/** @ingroup symcipher
   3DES CBC encryption.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  adsp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes (Optional, if not needed, set -1).
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_3des_cbc_encrypt_gather(unsigned char* abyp_output,
                                      const struct dsd_gather_i_1* adsp_input,
                                      size_t szp_len,
                                      const struct dsd_cipher_key* adsp_key,
                                      const unsigned char* abyp_iv);

/** @ingroup symcipher
   3DES CBC decryption.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

   @param[out] abyp_output     Output (Ciphertext in encryption operations, plaintext in decryption operations).
   @param[in]  adsp_input      Input (Plaintext in encryption operations, ciphertext in decryption operations).
   @param[in]  szp_len         Length of both input and output, given in bytes (Optional, if not needed, set -1).
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector of fixed length.
 */
extern void m_3des_cbc_decrypt_gather(unsigned char* abyp_output,
                                      const struct dsd_gather_i_1* adsp_input,
                                      size_t szp_len,
                                      const struct dsd_cipher_key* adsp_key,
                                      const unsigned char* abyp_iv);

/** @ingroup symcipher
\brief Encrypt and authenticate a message using a AEAD cipher.

Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

@param[out] abyp_cipher     Ciphertext output
@param[in]  adsp_plain      Plaintext input
@param[in]  szp_len         Length of output, given in bytes (Optional, if not needed, set -1).
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector (IV).
@param[in]  szp_iv_len      IV length, in bytes.
@param[in]  abyp_adddata    Authentication data.
@param[in]  szp_adddata_len Authentication data length, in bytes.
@param[out] abyp_iv         Authentication tag.
@param[in]  szp_iv_len      Authentication tag length, in bytes.
*/
typedef void (*amd_aead_gather_encrypt)(unsigned char* abyp_cipher,
                                        const struct dsd_gather_i_1* adsp_plain,
                                        size_t szp_len,
                                        const struct dsd_cipher_key* adsp_key,
                                        const unsigned char* abyp_iv,
                                        size_t szp_iv_len,
                                        const unsigned char* abyp_adddata,
                                        size_t szp_adddata_len,
                                        unsigned char* abyp_tag,
                                        size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM encryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES, #HL_HARDWARE_SUPPORT_PMUL and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.
   
   @param[out] abyp_cipher     Ciphertext output
   @param[in]  adsp_plain      Plaintext input
   @param[in]  szp_len         Length of output, given in bytes (Optional, if not needed, set -1).
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes.
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[out] abyp_iv         Authentication tag.
   @param[in]  szp_iv_len      Authentication tag length, in bytes.
 */
extern void m_aes_gcm_encrypt_gather(unsigned char* abyp_cipher,
                                     const struct dsd_gather_i_1* adsp_plain,
                                     size_t szp_len,
                                     const struct dsd_cipher_key* adsp_key,
                                     const unsigned char* abyp_iv,
                                     size_t szp_iv_len,
                                     const unsigned char* abyp_adddata,
                                     size_t szp_adddata_len,
                                     unsigned char* abyp_tag,
                                     size_t szp_tag_len);

/** @ingroup symcipher
\brief Decrypt and verify a message using a AEAD cipher.

Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.

@param[out] abyp_plain      Plaintext output
@param[in]  adsp_cipher     Ciphertext input
@param[in]  szp_len         Length of both input and output, given in bytes.
@param[in]  adsp_key        Key
@param[in]  abyp_iv         Initialization vector (IV).
@param[in]  szp_iv_len      IV length, in bytes (Optional, if not needed, set -1).
@param[in]  abyp_adddata    Authentication data.
@param[in]  szp_adddata_len Authentication data length, in bytes.
@param[in]  abyp_iv         Authentication tag.
@param[in]  szp_iv_len      Authentication tag length, in bytes.

@return TRUE if message authenticates, FALSE if not
*/
typedef BOOL (*amd_aead_gather_decrypt)(unsigned char* abyp_plain,
                                        const struct dsd_gather_i_1* adsp_cipher,
                                        size_t szp_len,
                                        const struct dsd_cipher_key* adsp_key,
                                        const unsigned char* abyp_iv,
                                        size_t szp_iv_len,
                                        const unsigned char* abyp_adddata,
                                        size_t szp_adddata_len,
                                        const unsigned char* abyp_tag,
                                        size_t szp_tag_len);

/** @ingroup symcipher
   AES GCM decryption using a suitable implementation.

   Implementation is chosen based on #HL_HARDWARE_SUPPORT_AES, #HL_HARDWARE_SUPPORT_PMUL and \p boc_disallow_hardware_acceleration in \p adsp_key.

   Operations are performed for \p szp_len bytes or to the end of adsp_input, whichever is shorter.
   
   @param[out] abyp_plain      Plaintext output
   @param[in]  adsp_cipher     Ciphertext input
   @param[in]  szp_len         Length of both input and output, given in bytes.
   @param[in]  adsp_key        Key
   @param[in]  abyp_iv         Initialization vector (IV).
   @param[in]  szp_iv_len      IV length, in bytes (Optional, if not needed, set -1).
   @param[in]  abyp_adddata    Authentication data.
   @param[in]  szp_adddata_len Authentication data length, in bytes.
   @param[in]  abyp_iv         Authentication tag.
   @param[in]  szp_iv_len      Authentication tag length, in bytes.
   
   @return TRUE if message authenticates, FALSE if not
 */
extern BOOL m_aes_gcm_decrypt_gather(unsigned char* abyp_plain,
                                     const struct dsd_gather_i_1* adsp_cipher,
                                     size_t szp_len,
                                     const struct dsd_cipher_key* adsp_key,
                                     const unsigned char* abyp_iv,
                                     size_t szp_iv_len,
                                     const unsigned char* abyp_adddata,
                                     size_t szp_adddata_len,
                                     const unsigned char* abyp_tag,
                                     size_t szp_tag_len);


/** @ingroup memory
Overwrite a section of memory with zeroes.
This can not be optimized away by the compiler.

@param[in]  avop_memory     Memory location
@param[in]  szp_len         Length of the block to be zeroed
*/
extern void m_sec_memzero(void* avop_memory,
                          size_t szp_len);


/** @ingroup memory
Compare two sections of memory.
The execution path is independent of the data.

Other than stdlib memcmp, the return value does not give any information beyond equal or inequal

@param[in]  avop_mem_1      Memory section 1
@param[in]  avop_mem_2      Memory section 2
@param[in]  szp_len         Length of data to be compared

@return 0 if equal, nonzero otherwise
*/
extern int m_sec_memcmp(const void* avop_mem_1,
                        const void* avop_mem_2,
                        size_t szp_len);

/** @ingroup hashes
    Profile of a hash algorithm

    Digest size and Block size are defined in the algorithm specification.
    State size is used for hash initialization.
*/
struct dsd_hash_profile {
    size_t szc_digest_size;                         //!< Digest size in bytes (abyp_digest of #amc_hash_final)
    size_t szc_state_size;                          //!< State size in bytes (avop_state of #amc_hash_init, #amc_hash_update, etc.)
    size_t szc_block_size;                          //!< Block size in bytes (used e.g. for hmac implementation)
    amd_hash_init amc_hash_init;                    //!< Hash initialize function
    amd_hash_update amc_hash_update;                //!< Hash update function for single buffer input
    amd_hash_gather_update amc_hash_gather_update;  //!< Hash update function for gather input
    amd_hash_final amc_hash_final;                  //!< Hash finalize function
};

/** @ingroup hashes
    Look up table of all hash profiles
*/
extern const struct dsd_hash_profile dsrg_hash_profiles[];

/** @ingroup hashes
    Size of all hash states in bytes.

    These can be used to initialize any hash states as arrays. ied_hash_max_state_size gives the biggest state size.
*/
enum {
    cind_state_size_sha_1 = 96,
    cind_state_size_sha_2_224 = 108,
    cind_state_size_sha_2_256 = 108,
    cind_state_size_sha_2_384 = 216,
    cind_state_size_sha_2_512 = 216,
    cind_state_size_sha_3_224 = sizeof(struct dsd_sha_3_state),
    cind_state_size_sha_3_256 = sizeof(struct dsd_sha_3_state),
    cind_state_size_sha_3_384 = sizeof(struct dsd_sha_3_state),
    cind_state_size_sha_3_512 = sizeof(struct dsd_sha_3_state),
    cind_state_size_md_5 = 96,

    cind_hash_max_state_size = ( 216 > sizeof(struct dsd_sha_3_state)) ? 216 : sizeof(struct dsd_sha_3_state)
};

/** @ingroup hashes
    Size of all hash digests in bytes.

    These can be used to initialize any digest destination arrays. ied_hash_max_state_size gives the biggest digest size.
*/
enum {
    cind_digest_size_sha_1 = 20,
    cind_digest_size_sha_2_224 = 28,
    cind_digest_size_sha_2_256 = 32,
    cind_digest_size_sha_2_384 = 48,
    cind_digest_size_sha_2_512 = 64,
    cind_digest_size_sha_3_224 = 28,
    cind_digest_size_sha_3_256 = 32,
    cind_digest_size_sha_3_384 = 48,
    cind_digest_size_sha_3_512 = 64,
    cind_digest_size_md_5 = 16,

    cind_hash_max_digest_size = 64
};

/** @ingroup hashes
    Block sizes of hash algorithms in bytes as defined in their specifications.

    ied_hash_max_state_size gives the biggest block size.
*/
enum {
    cind_block_size_sha_1 = 64,
    cind_block_size_sha_2_224 = 64,
    cind_block_size_sha_2_256 = 64,
    cind_block_size_sha_2_384 = 128,
    cind_block_size_sha_2_512 = 128,
    cind_block_size_sha_3_224 = 144,
    cind_block_size_sha_3_256 = 136,
    cind_block_size_sha_3_384 = 104,
    cind_block_size_sha_3_512 = 72,
    cind_block_size_md_5 = 64,

    cind_hash_max_block_size = 144
};

/** @ingroup symcipher
    Block size of symmetric block ciphers
*/
enum {
    cind_aes_block_size = 16,
    cind_3des_block_size = 8,
};

/** @ingroup ecc
    Length of public key and secret for ECDH. Use ied_ecc_named_curves as index.
 */
extern const size_t cszrg_ecdh_public_key_len[];
extern const size_t cszrg_ecdh_secret_len[];


#ifdef __cplusplus
};
#endif

#endif
