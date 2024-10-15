#ifndef HOB_ENCRY_INTERN_2_H__
#define HOB_ENCRY_INTERN_2_H__
#pragma once

/**
 * @file
 *
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
 *
 * Related files:
 *   hob-encry-2.h        - Main header file for the HOB encryption module
 *   is-encry-2-x64.pre   - HOB Precomp file producing both is-lnum-impl-x64.asm and is-lnum-impl-x64.s
 *
 * Table of contents:
 *  1) Preprocessor definitions
 *  2) Data type definitions
 *  3) Function declarations (Assembler-implemented functions)
 *  4) Function declarations (Other functions that need to be declared)
 *
 * @{
 */

/****************************************************************************************************/
/*                                                                                                  */
/*  Preprocessor definitions                                                                        */
/*                                                                                                  */
/****************************************************************************************************/

#define EXP_MOD_MAX_PRECALC     32
#define DEFAULT_WNAF_WIDTH      4
#define LNUM_SIZE_ALIGN         2*sizeof(LNUM_WORD)

inline size_t ms_u_max(size_t a,
                       size_t b)
{
    return (((a) > (b)) ? (a) : (b));
}
#define max3(a,b,c) ms_u_max(ms_u_max(a,b),c)
#define max4(a,b,c,d) ms_u_max(ms_u_max(ms_u_max(a,b),c),d)
#define max5(a,b,c,d,e) ms_u_max(ms_u_max(ms_u_max(ms_u_max(a,b),c),d),e)

#define TOP_WORD(lnum)                  ((LNUM_WORD*)(lnum->aucc_data))[(lnum->szc_used_size_bytes / sizeof(LNUM_WORD))- 1]

//input sizes are all assumed to be in bytes, and divisible by sizeof(LNUM_WORD)
#define REQSIZE_LNUM(inputsize)                                 ((inputsize) + sizeof(LNUM_WORD) + sizeof(struct dsd_lnum))
#define REQSIZE_ALIGNMENT                                       HL_ALIGNMENT

// REQSIZE macros for functions in xs-lnum-1.cpp
#define REQSIZE_m_lnum_barret_init(modsize)                     (REQSIZE_LNUM(2*(modsize) + 2*sizeof(LNUM_WORD)) + REQSIZE_m_lnum_divide(2*(modsize) + 2*sizeof(LNUM_WORD),modsize))
#define REQSIZE_m_lnum_barret_init_KEEP(modsize)                (0)
#define REQSIZE_m_lnum_barret_reduce(modsize)                   (2*REQSIZE_LNUM(2*(modsize) + 1*sizeof(LNUM_WORD)) + REQSIZE_m_lnum_mult(modsize))
#define REQSIZE_m_exp_mod_mont(basesize, expsize)               ((2*REQSIZE_LNUM(basesize)) + REQSIZE_LNUM(basesize*2) + REQSIZE_LNUM(basesize*2+1) + (EXP_MOD_MAX_PRECALC*REQSIZE_LNUM(basesize)))
#define REQSIZE_m_exp_mod_std_DYNAMIC(basesize, expsize)        (REQSIZE_LNUM((basesize)*2) + (EXP_MOD_MAX_PRECALC+1)*REQSIZE_LNUM(basesize) + max3(REQSIZE_m_lnum_mult(basesize),REQSIZE_m_lnum_square(basesize),REQSIZE_m_lnum_divide(basesize,basesize)))
#define REQSIZE_m_exp_mod_std(basesize, expsize)                (REQSIZE_LNUM((basesize)*2) + (EXP_MOD_MAX_PRECALC+1)*REQSIZE_LNUM(basesize) + REQSIZE_m_lnum_divide(basesize*2,basesize))
#define REQSIZE_m_lnum_exp_mod(basesize, expsize)               REQSIZE_m_lnum_exp_mod_DYNAMIC(basesize, expsize)
#define REQSIZE_m_lnum_exp_mod_DYNAMIC(basesize, expsize)       ms_u_max(REQSIZE_m_exp_mod_mont(basesize,expsize),REQSIZE_m_exp_mod_std(basesize,expsize))
#define REQSIZE_m_lnum_divide(numsize,divsize)                  (2*REQSIZE_LNUM(numsize + sizeof(LNUM_WORD)) + REQSIZE_LNUM(divsize + 2*sizeof(LNUM_WORD)))
#define REQSIZE_m_lnum_gcd(inputsize)                           (2*REQSIZE_LNUM(inputsize + 1 + sizeof(LNUM_WORD)))
#define REQSIZE_m_lnum_inverse(inputsize)                       (6*REQSIZE_LNUM(inputsize + 2*sizeof(LNUM_WORD)))
#define REQSIZE_m_lnum_lcm(inputsize)                           (REQSIZE_LNUM(inputsize) + max3(REQSIZE_m_lnum_mult(inputsize),REQSIZE_m_lnum_divide(inputsize,inputsize),REQSIZE_m_lnum_gcd(inputsize)))
#define REQSIZE_m_lnum_mont_init(modsize)                       REQSIZE_m_mont_init_impl(modsize)
#define REQSIZE_m_lnum_mont_init_KEEP(modsize)                  (0)
#define REQSIZE_m_lnum_mont_red(modsize)                        (REQSIZE_LNUM(2*(modsize)) + REQSIZE_LNUM(2*(modsize) + sizeof(LNUM_WORD)))
#define REQSIZE_m_lnum_mult(inputsize)                          REQSIZE_LNUM(2*inputsize)
#define REQSIZE_m_lnum_square(inputsize)                        REQSIZE_LNUM(2*inputsize)
#define REQSIZE_m_lnum_test_prime_DYNAMIC(inputsize)            (5*REQSIZE_LNUM(inputsize) + max4(REQSIZE_m_lnum_mont_conv(inputsize,inputsize), REQSIZE_m_exp_mod_mont(inputsize,inputsize), REQSIZE_m_lnum_square(inputsize), REQSIZE_m_lnum_mont_red(inputsize)))
#define REQSIZE_m_lnum_test_prime(inputsize)                    (8*REQSIZE_LNUM(inputsize) + 3*sizeof(LNUM_WORD) + REQSIZE_m_exp_mod_mont(inputsize,inputsize))
#define REQSIZE_m_lnum_mont_conv(inputsize,modsize)             (REQSIZE_LNUM((modsize)*2 + sizeof(LNUM_WORD)) + REQSIZE_m_lnum_mult(inputsize))
#define REQSIZE_m_mont_init_impl(modsize)                       ms_u_max(((REQSIZE_LNUM(2*(modsize)+sizeof(LNUM_WORD)) + REQSIZE_m_lnum_divide(2*(modsize)+sizeof(LNUM_WORD),modsize))), \
                                                                         (REQSIZE_m_lnum_mont_red(modsize)))
// auxmacro
#define SIZE_OF_TMP_VAR(inputsize)         (2*(inputsize)+sizeof(LNUM_WORD))

// REQSIZE macros for functions in xs-lnum-ec-1.cpp
#define REQSIZE_m_ecpt_weier_dblscamult_DYNAMIC(inputsize,input2size,width) (REQSIZE_ms_ecpt_weier_scamult_init_KEEP(inputsize) + (2*REQSIZE_ms_mem_pool_get_scamult_precomp_KEEP(inputsize,width)) + REQSIZE_ms_ecpt_montgomerize_KEEP(inputsize) + max4(REQSIZE_ms_ecpt_weier_scamult_init(inputsize),REQSIZE_ms_ecpt_weier_scamult_precomp(inputsize),REQSIZE_ms_ecpt_montgomerize(inputsize),REQSIZE_ms_ecpt_weier_dblscamult_algo(inputsize,input2size,width)))
#define REQSIZE_m_ecpt_weier_dblscamult(inputsize,input2size,width)         REQSIZE_m_ecpt_weier_dblscamult_DYNAMIC(inputsize,input2size,width)
#define REQSIZE_m_ecpt_weier_on_curve_DYNAMIC(inputsize)                    (3*REQSIZE_LNUM(SIZE_OF_TMP_VAR(inputsize)) + max3(REQSIZE_m_lnum_mult(SIZE_OF_TMP_VAR(inputsize)),REQSIZE_m_lnum_square(SIZE_OF_TMP_VAR(inputsize)),REQSIZE_m_lnum_divide(SIZE_OF_TMP_VAR(inputsize),inputsize)))
#define REQSIZE_m_ecpt_weier_on_curve(inputsize)                            (3*REQSIZE_LNUM(SIZE_OF_TMP_VAR(inputsize)) + REQSIZE_m_lnum_divide(SIZE_OF_TMP_VAR(inputsize),inputsize))
#define REQSIZE_m_ecpt_weier_scamult_DYNAMIC(inputsize,input2size,width)    (REQSIZE_ms_ecpt_weier_scamult_init_KEEP(inputsize) + REQSIZE_ms_mem_pool_get_scamult_precomp_KEEP(inputsize,width) + max3(REQSIZE_ms_ecpt_weier_scamult_init(inputsize),REQSIZE_ms_ecpt_weier_scamult_precomp(inputsize),REQSIZE_ms_ecpt_weier_scamult_algo(inputsize,input2size,width)))
#define REQSIZE_m_ecpt_weier_scamult(inputsize,input2size,width)            REQSIZE_m_ecpt_weier_scamult_DYNAMIC(inputsize,input2size,width)
#define REQSIZE_ms_ecpt_weier_dblscamult_algo(inputsize,input2size,width)   ((2*REQSIZE_ms_ec_gen_wNAF_KEEP(input2size)) + ms_u_max(REQSIZE_ms_ec_gen_wNAF(input2size),(12*REQSIZE_LNUM(SIZE_OF_TMP_VAR(inputsize)) + ms_u_max(REQSIZE_ms_ecpt_conv_to_aff(inputsize),REQSIZE_m_lnum_mont_red(inputsize)))))
#define REQSIZE_ms_ec_gen_wNAF(scalarsize)                                  (REQSIZE_LNUM((scalarsize) + sizeof(LNUM_WORD)) + REQSIZE_LNUM(1))
#define REQSIZE_ms_ec_gen_wNAF_KEEP(scalarsize)                             ((scalarsize) + 1 + HL_ALIGNMENT)
#define REQSIZE_ms_mem_pool_get_scamult_precomp_KEEP(primesize,width)       ((1 << (width))*(sizeof(dsd_ec_point) + 3*REQSIZE_LNUM(primesize)))
#define REQSIZE_ms_ecpt_weier_scamult_precomp(primesize)                    (12*REQSIZE_LNUM(SIZE_OF_TMP_VAR(primesize)) + 3*REQSIZE_LNUM(primesize) + REQSIZE_ms_ecpt_conv_to_aff(primesize))
#define REQSIZE_ms_ecpt_weier_scamult_algo(inputsize,input2size,width)      (12*REQSIZE_LNUM(SIZE_OF_TMP_VAR(inputsize)) + REQSIZE_ms_ec_gen_wNAF_KEEP(input2size) + max3(REQSIZE_ms_ec_gen_wNAF(input2size),REQSIZE_ms_ecpt_conv_to_aff(inputsize),REQSIZE_m_lnum_mont_red(inputsize)))
#define REQSIZE_ms_ecpt_conv_to_aff(inputsize)                              max3(REQSIZE_m_lnum_mont_red(inputsize),REQSIZE_m_lnum_inverse(inputsize),REQSIZE_m_lnum_mont_conv(inputsize,inputsize))
#define REQSIZE_ms_ec_montgomerize_params(primesize)                        REQSIZE_m_lnum_mont_conv(primesize,primesize)
#define REQSIZE_ms_ec_montgomerize_params_KEEP(primesize)                   (5*REQSIZE_LNUM(primesize))
#define REQSIZE_ms_ecpt_montgomerize(inputsize)                             REQSIZE_m_lnum_mont_conv(inputsize,inputsize)
#define REQSIZE_ms_ecpt_montgomerize_KEEP(inputsize)                        (2*REQSIZE_LNUM(inputsize))
#define REQSIZE_ms_ecpt_weier_scamult_init(inputsize)                       ms_u_max(REQSIZE_ms_ec_montgomerize_params(inputsize),REQSIZE_m_mont_init_impl(inputsize))
#define REQSIZE_ms_ecpt_weier_scamult_init_KEEP(inputsize)                  (REQSIZE_ms_ec_montgomerize_params_KEEP(inputsize) + (2*REQSIZE_LNUM(inputsize)))
#define REQSIZE_ms_ecc_precomp_curve_DYNAMIC(primesize)                     (REQSIZE_ms_ec_montgomerize_params_KEEP(primesize) + max4(REQSIZE_m_mont_init_impl(primesize),REQSIZE_ms_ec_montgomerize_params(primesize),REQSIZE_m_lnum_mont_conv(primesize,primesize),REQSIZE_ms_ecpt_weier_scamult_precomp(primesize)))
#define REQSIZE_ms_ecc_precomp_curve(primesize)                             (REQSIZE_ms_ec_montgomerize_params_KEEP(primesize) + REQSIZE_ms_ecpt_weier_scamult_precomp(primesize))
#define REQSIZE_m_ecpt_montgo_scamult(primesize)                            (6*REQSIZE_LNUM(primesize) + 8*REQSIZE_LNUM(SIZE_OF_TMP_VAR(primesize)) + max5(REQSIZE_m_lnum_mont_conv(primesize,primesize), REQSIZE_m_lnum_mont_red(primesize), REQSIZE_m_lnum_inverse(primesize), REQSIZE_m_lnum_mult(primesize), REQSIZE_m_lnum_divide(SIZE_OF_TMP_VAR(primesize),primesize)))

// REQSIZE macros for functions in xs-ecc-1.cpp
#define REQSIZE_m_ecc_init_named_curve(primesize)                           REQSIZE_ms_ecc_precomp_curve(primesize) // TODO: change to work with montgomery too
#define REQSIZE_ms_gen_static_keypair_weierstrass(primesize,subgroupsize)   REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH)               
#define REQSIZE_ms_gen_static_keypair_montgomery(primesize)                 REQSIZE_m_ecpt_montgo_scamult(primesize)
#define REQSIZE_ms_gen_rand_keypair_weierstrass(primesize,subgroupsize)     REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH)                  
#define REQSIZE_ms_gen_rand_keypair_montgomery(primesize)                   (primesize*sizeof(LNUM_WORD) + HL_ALIGNMENT + REQSIZE_ms_gen_static_keypair_montgomery(primesize))
#define REQSIZE_m_ecc_gen_rand_keypair(primesize,subgroupsize)              ms_u_max(REQSIZE_ms_gen_rand_keypair_weierstrass(primesize,subgroupsize),REQSIZE_ms_gen_rand_keypair_montgomery(primesize))
#define REQSIZE_m_ecc_gen_static_keypair(primesize,subgroupsize)            ms_u_max(REQSIZE_ms_gen_static_keypair_weierstrass(primesize,subgroupsize),REQSIZE_ms_gen_static_keypair_montgomery(primesize))
#define REQSIZE_ms_gen_secret_weierstrass(primesize,subgroupsize)           (5*REQSIZE_LNUM(primesize) + ms_u_max(REQSIZE_m_ecpt_weier_on_curve_DYNAMIC(primesize),REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH)))
#define REQSIZE_ms_gen_secret_montgomery(primesize)                         (REQSIZE_LNUM(primesize + sizeof(LNUM_WORD)) + REQSIZE_m_ecpt_montgo_scamult(primesize))
#define REQSIZE_m_ecc_gen_secret(primesize,subgroupsize)                    ms_u_max(REQSIZE_ms_gen_secret_weierstrass(primesize,subgroupsize), REQSIZE_ms_gen_secret_montgomery(primesize))
#define REQSIZE_ms_ecdsa_compute_signature_DYNAMIC(primesize,subgroupsize)  max4(REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH), REQSIZE_m_lnum_divide(primesize + subgroupsize + 2*sizeof(LNUM_WORD), subgroupsize), REQSIZE_m_lnum_mult(primesize + subgroupsize + 2*sizeof(LNUM_WORD)), REQSIZE_m_lnum_inverse(subgroupsize))
#define REQSIZE_ms_ecdsa_compute_signature(primesize,subgroupsize)          REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH)
#define REQSIZE_m_ecc_gen_signature(primesize,subgroupsize)                 (2 * REQSIZE_LNUM(subgroupsize) + 2 * REQSIZE_LNUM(subgroupsize + 2 * sizeof(LNUM_WORD)) + 3 * REQSIZE_LNUM(primesize) + REQSIZE_LNUM(primesize + subgroupsize + 2 * sizeof(LNUM_WORD)) + REQSIZE_ms_ecdsa_compute_signature(primesize,subgroupsize))
#define REQSIZE_ms_validate_signature_DYNAMIC(primesize,subgroupsize)       max4(REQSIZE_m_lnum_inverse(subgroupsize), REQSIZE_m_lnum_mult(subgroupsize + sizeof(LNUM_WORD)), REQSIZE_m_lnum_divide(2 * subgroupsize, subgroupsize), REQSIZE_m_ecpt_weier_dblscamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH))
#define REQSIZE_ms_validate_signature(primesize,subgroupsize)               REQSIZE_m_ecpt_weier_dblscamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH)
#define REQSIZE_m_ecc_verify_sig_DYNAMIC(primesize,subgroupsize)            ms_u_max(REQSIZE_m_ecpt_weier_on_curve_DYNAMIC(primesize), 3 * REQSIZE_LNUM(primesize) + REQSIZE_LNUM(subgroupsize) + REQSIZE_LNUM(subgroupsize + 2*sizeof(LNUM_WORD)) + 2 * REQSIZE_LNUM(2 * subgroupsize) + ms_u_max(REQSIZE_m_ecpt_weier_scamult(primesize,subgroupsize,DEFAULT_WNAF_WIDTH),REQSIZE_ms_validate_signature_DYNAMIC(primesize,subgroupsize)))
#define REQSIZE_m_ecc_verify_sig(primesize,subgroupsize)                    (3 * REQSIZE_LNUM(primesize) + REQSIZE_LNUM(subgroupsize) + REQSIZE_LNUM(subgroupsize + 2*sizeof(LNUM_WORD)) + 2 * REQSIZE_LNUM(2 * subgroupsize) + REQSIZE_ms_validate_signature(primesize,subgroupsize))


/****************************************************************************************************/
/*                                                                                                  */
/*  Data type definitions                                                                           */
/*                                                                                                  */
/****************************************************************************************************/


// Forward declarations for some functions
struct dsd_lnum_montgomery_ctx;
struct dsd_mem_pool_ele;
struct dsd_lnum;

/**
   Type of a elliptic curve
 */
enum ied_curve_type {
    ied_weierstr_cofactor_one,
    ied_weierstr_cofactor_non_one,
    ied_montgomery,
};

/**
   Representation type of a EC point
 */
enum ied_representation {
    ied_affine,
    ied_jacobian,
    ied_neutral,
};

/**
   Point on a elliptic curve
 */
struct dsd_ec_point {
    dsd_lnum *adsc_x;
    dsd_lnum *adsc_y;
    dsd_lnum *adsc_z;
    ied_representation iec_representation;
};

/** @ingroup ecc
   Elliptic Curve parameters, including some precomputated values
 */
struct dsd_ec_curve_params {
    /* Curve Parameter a */
    dsd_lnum *adsc_a;
    /* Curve Parameter b for Weierstrass curves, precomputed value a_24 for Montgomery curves */
    dsd_lnum *adsc_b_a24;
    /* Curve Parameter G_x */
    dsd_lnum *adsc_Gx;
    /* Curve Parameter G_y */
    dsd_lnum *adsc_Gy;
    /* Curve Field prime */
    dsd_lnum *adsc_prime;
    /* Curve Parameter n */
    dsd_lnum *adsc_n;
    /* Synchronization lock for precomputation in multi-threaded environments */
    dsd_hcla_critsect_1 dsc_precomp_lock;
    /* Boolean signing whether precomputed values have been set */
    volatile BOOL boc_precomps_set;
    /* Array of precomputed values for Weierstrass curves. Unused for Montgomery curves */
    dsd_ec_point *adsc_precomps;
    /* Montgomery context for the field prime */
    dsd_lnum_montgomery_ctx *adsc_mont_ctx;
    /* Name of the curve */
    enum ied_ecc_named_curves iec_name;
    /* Type of curve (Weierstrass or Montgomery) */
    enum ied_curve_type iec_type;
};




/****************************************************************************************************/
/*                                                                                                  */
/*  Function declarations (Assembler-implemented functions)                                         */
/*                                                                                                  */
/****************************************************************************************************/





/**
   Adds two large number values.

   The buffer pointed to by abyp_dest must offer as much space as 1 + max{szp_a_len, szp_b_len}.

   szp_a_len and/or szp_b_len may be zero.
   The pointers abyp_dest, abyp_a and abyp_b may be equal in any constellation.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Summand A
   @param[in]  szp_a_len   Length of summand A
   @param[in]  abyp_b        Summand B
   @param[in]  szp_b_len   Length of summand B

   @return Length of the result
 */
extern "C"
size_t m_impl_add(unsigned char* abyp_dest,
                  const unsigned char* abyp_a,
                  size_t szp_a_len,
                  const unsigned char* abyp_b,
                  size_t szp_b_len);


/**
   Add a single word to a large number. Overwrites the first input with the result.

   The buffer pointed to by abyp_dest_a must provide sufficient space for the carry to propagate.

   @param[in,out]  abyp_dest_a   Summand A/Destination buffer
   @param[in]      up_b        Summand B

   @return Length of the result
 */
extern "C"
void m_impl_add_word(unsigned char* abyp_dest_a,
                     LNUM_WORD up_b);


/**
   Subtracts one number value from another

   Minuend A must be greater than or equal to Subtrahend B.

   The buffer pointed to by abyp_dest must offer as much space as szp_a_len.

   szp_a_len and/or szp_b_len may be zero.
   The pointers abyp_dest, abyp_a and abyp_b may be equal in any constellation.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Minuend A
   @param[in]  szp_a_len   Length of minuend A
   @param[in]  abyp_b        Subtrahend B
   @param[in]  szp_b_len   Length of subtrahend B

   @return Length of the result
 */
extern "C"
size_t m_impl_sub(unsigned char* abyp_dest,
                  const unsigned char* abyp_a,
                  size_t szp_a_len,
                  const unsigned char* abyp_b,
                  size_t szp_b_len);


/**
   Adds two large number values and writes the result to a third number.
   Please consider the return value.

   The buffer pointed to by abyp_dest must offer as much space as szp_len.

   The pointers abyp_dest, abyp_a and abyp_b may be equal in any constellation.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Summand A
   @param[in]  abyp_b        Summand B
   @param[in]  szp_len   Length of summands A and B, and capacity of dest

   @return Last carry
 */
extern "C"
int m_impl_add_karatsuba(unsigned char* abyp_dest,
                         const unsigned char* abyp_a,
                         const unsigned char* abyp_b,
                         size_t szp_len);


/**
   Subtracts two large number values of the same length.
   Please consider the return value.

   The buffer pointed to by abyp_dest must offer as much space as szp_len.

   If A is smaller than B, the resulting negative value is given as 2's complement, and the return value is 1.

   The pointers abyp_dest, abyp_a and abyp_b may be equal in any constellation.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Minuend A
   @param[in]  abyp_b        Subtrahend B
   @param[in]  szp_len   Length of A and B, and capacity of dest

   @return 1 if B was larger, 0 otherwise
 */
extern "C"
int m_impl_sub_karatsuba(unsigned char* abyp_dest,
                         const unsigned char* abyp_a,
                         const unsigned char* abyp_b,
                         size_t szp_len);


/**
   Multiplies two large number values using the basic multiplication algorithm.

   The buffer pointed to by abyp_dest must offer as much space as szp_a_len + szp_b_len.
   szp_a_len and szp_b_len must NOT be 0.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Factor A
   @param[in]  szp_a_len   Length of factor A
   @param[in]  abyp_b        Factor B
   @param[in]  szp_b_len   Length of factor B

   @return Length of the result
 */
extern "C"
void m_impl_mult_basic(unsigned char* abyp_dest,
                       const unsigned char* abyp_a,
                       size_t szp_a_len,
                       const unsigned char* abyp_b,
                       size_t szp_b_len);


/**
   Squares a large number value.

   The buffer pointed to by abyp_dest must offer as much space as szp_a_len * 2.
   szp_a_len and szp_b_len must NOT be 0.

   @param[out] abyp_dest     Destination buffer
   @param[in]  abyp_a        Factor A
   @param[in]  szp_a_len   Length of factor A

   @return Length of the result
 */
extern "C"
void m_impl_square(unsigned char* abyp_dest,
                   const unsigned char* abyp_a,
                   size_t szp_a_len);


/**
   Compares two large number values.

   abyp_a may be equal to abyp_b.
   szp_len may be 0.

   @param[in]  abyp_a        Value A
   @param[in]  abyp_b        Value B
   @param[in]  szp_len     Length of both

   @return
    < 0 if A is smaller / B is larger
    = 0 if both are of the same value
    > 0 if A is larger / B is smaller
 */
extern "C"
int m_impl_cmp(const unsigned char* abyp_a,
               const unsigned char* abyp_b,
               size_t szp_len);


/**
   Multiply-Add suboperation of Montgomery reduction

   Result is witten in &abyp_dest[zp_mod_len/sizeof(LNUM_WORD)] and the lower-half should be ignored.

   @param[out] abyp_dest     Destination buffer (at leat 2*zp_mod_len + sizeof(LNUM_WORD) bytes large)
   @param[in]  urp_n_0_inv   N0_inv value (single word, representing -m[0]^{-1} mod R)
   @param[in]  abyp_mod      Modulus
   @param[in]  szp_mod_len   Length of modulus in bytes
   @param[in]  abyp_src      Reduction input value
 */
extern "C"
void m_impl_mont_mul_add(unsigned char* abyp_dest,
                         LNUM_WORD urp_n_0_inv,
                         const unsigned char* abyp_mod,
                         size_t szp_mod_len,
                         const unsigned char* abyp_src);

/**
   Find the first (i.e. least significant) set bit index in a word.
   urp_word must not be zero. Otherwise undefined behaviour.

   @param[in]  urp_word        Word

   @return     number of leading zeros
 */
extern "C"
size_t m_impl_first_bit(LNUM_WORD urp_word);


/**
   Find the last (i.e. most significant) set bit index in a word.
   urp_word must not be zero. Otherwise undefined behaviour.

   @param[in]  urp_word        Word

   @return     number of trailing zeros
 */
extern "C"
size_t m_impl_last_bit(LNUM_WORD urp_word);


/**
    Perform AES key schedule expansion for 128-bit keys

    @param[in]  abyp_userkey    Unexpanded key
    @param[out] abyp_key        Expanded key
 */
extern "C" void m_impl_aes_128_key_expansion(const unsigned char * abyp_userkey,
                                             unsigned char * abyp_key);

/**
    Perform AES key schedule expansion for 192-bit keys

    @param[in]  abyp_userkey    Unexpanded key
    @param[out] abyp_key        Expanded key
 */
extern "C" void m_impl_aes_192_key_expansion(const unsigned char * abyp_userkey,
                                             unsigned char * abyp_key);

/**
    Perform AES key schedule expansion for 256-bit keys

    @param[in]  abyp_userkey    Unexpanded key
    @param[out] abyp_key        Expanded key
 */
extern "C" void m_impl_aes_256_key_expansion(const unsigned char * abyp_userkey,
                                             unsigned char * abyp_key);

/**
    Reverts an expanded AES key to transform it from encryption to decryption expansion

    @param[in]  abyp_key            Expanded encryption key
    @param[out] abyp_rev_key        Expanded decryption key
    @param[in]  szp_rounds          Number of rounds the AES algorithm will perform (related to size of key)
 */
extern "C" void m_impl_aes_revert_key(unsigned char * abyp_key,
                                      unsigned char * abyp_rev_key,
                                      size_t szp_rounds);

/**
    Performs a block-wise AES CBC encryption using AES NI.

    Length is counted in block, NOT in bytes!

    @param[in]  abyp_in         Pointer to the input buffer.
    @param[out] abyp_output     Pointer to the output buffer.
    @param[in]  adsp_key        Pointer to the key structure.
    @param[in]  szp_block_count Number of 16 byte AES blocks.
    @param[in]  szp_rounds      Number of AES rounds.
    @param[in]  abyp_ivec       Pointer to the IV.
 */
extern "C" void m_impl_aes_cbc_encrypt(const unsigned char * abyp_in,
                                       unsigned char * abyp_out,
                                       const unsigned char * abyp_key,
                                       size_t szp_block_count,
                                       size_t szp_rounds,
                                       const unsigned char * abyp_ivec);

/**
    Performs a block-wise AES CBC decryption using AES NI.

    Length is counted in blocks, NOT in bytes!

    @param[in]  abyp_in         Pointer to the input buffer.
    @param[out] abyp_output     Pointer to the output buffer.
    @param[in]  adsp_key        Pointer to the key structure.
    @param[in]  szp_block_count Number of 16 byte AES blocks.
    @param[in]  szp_rounds      Number of AES rounds.
    @param[in]  abyp_ivec       Pointer to the IV.
 */
extern "C" void m_impl_aes_cbc_decrypt(const unsigned char * abyp_in,
                                       unsigned char * abyp_out,
                                       const unsigned char * abyp_key,
                                       size_t szp_block_count,
                                       size_t szp_rounds,
                                       const unsigned char * abyp_ivec);

/**
    Performs a block-wise AES CTR using AES NI.

    The IV input is overwritten with an extra counter block, that can be XORed into
    the last incomplete block. This greatly simplifies the assembler code.

    Length is counted in blocks, NOT in bytes!

    @param[in]      abyp_input      Pointer to the input buffer.
    @param[out]     abyp_output     Pointer to the output buffer.
    @param[in]      abyp_key        Pointer to the key structure.
    @param[in]      szp_block_count Number of 16 byte AES blocks.
    @param[in]      szp_rounds      Number of AES rounds.
    @param[inout]   abyp_iv         IN: Pointer to the IV.
                                    OUT: Filled with the last counter block.
 */
extern "C" void m_impl_aes_ctr(const unsigned char * abyp_input,
                               unsigned char * abyp_output,
                               const unsigned char * abyp_key,
                               size_t szp_block_count,
                               size_t szp_rounds,
                               unsigned char * abyp_iv);

/**
    Performs a block-wise AES ECB encryption using AES NI.

    Length is counted in blocks, NOT in bytes!

    @param[in]  abyp_in         Pointer to the input buffer.
    @param[out] abyp_output     Pointer to the output buffer.
    @param[in]  adsp_key        Pointer to the key structure.
    @param[in]  szp_block_count Number of 16 byte AES blocks.
    @param[in]  szp_rounds      Number of AES rounds.
 */
extern "C" void m_impl_aes_ecb_encrypt(const unsigned char * abyp_in,
                                       unsigned char * abyp_out,
                                       const unsigned char * abyp_key,
                                       size_t szp_block_count,
                                       size_t szp_rounds);

/**
    GHASH auxiliary function for AES GCM

    This function updates the current hash state by input data
    If the last block of input is incomplete (i.e. if inp_data_len % 16 > 0), zeros are appended

    @param[inout]   abyp_hash_state     Current GHASH state
    @param[in]      abyp_hash_key       GHASH key
    @param[in]      abyp_data           Input data
    @param[in]      szp_data_len        Data length
 */
extern "C" void m_impl_ghash_stream(unsigned char* abyp_hash_state,
                                    const unsigned char* abyp_hash_key,
                                    const unsigned char* abyp_data,
                                    size_t szp_data_len);

/****************************************************************************************************/
/*                                                                                                  */
/*  Function declarations (Other functions that need to be declared)                                */
/*                                                                                                  */
/****************************************************************************************************/


/**
   Initializes a prepared Montgomery context.

   The modulus must already be set, adsc_r_squared must be allocated with a size
   at least equal to the modulus. The modulus must be odd.
   The modulus will not be modified, so using a const parameter for it is fine!

   @param[in,out]  adsp_context    Montgomery context to be initialized.
   @param[in]      adsp_pool       Pool used for calculations.

   @return ied_encry_success on success, error code otherwise.
 */
enum ied_encry_return m_mont_init_impl(dsd_lnum_montgomery_ctx* adsp_context,
                                       dsd_mem_pool_ele* adsp_pool);

/**
   Performs a Montgomery squaring.

   This means a squaring using the karatsuba algorithm, followed by a Montgomery reduction.

   It is assumed, that adsp_src is 0-padded to the length of the modulus and in Montgomery form.
   adsp_src and adsp_dest may be identical.
   The result will be 0-padded to the length of the modulus.
   adsp_temp_prod must be twice the size of the modulus, adsp_temp_mont twice plus one word.
   Length and signs will be ignored!

   @param[out] adsp_dest       Result number.
   @param[in]  adsp_src        Number to be squared.
   @param[in]  adsp_ctx        Montgomery context for the reduction
   @param[in]  adsp_temp_prod  Temporary for storing the result of the squaring.
   @param[in]  adsp_temp_mont  Temporary for square and reduction,
 */
void m_square_mont(struct dsd_lnum* adsp_dest,
                   const struct dsd_lnum* adsp_src,
                   const struct dsd_lnum_montgomery_ctx* adsp_ctx,
                   struct dsd_lnum* adsp_temp_prod,
                   struct dsd_lnum* adsp_temp_mont);


/**
   Performs a Montgomery multiplication.

   This means a multiplying a and b using the karatsuba algorithm, followed by a Montgomery reduction.

   It is assumed, that adsp_a and adsp_b are 0-padded to the length of the modulus and in Montgomery form.
   adsp_src and adsp_dest may be identical.
   The result will be 0-padded to the length of the modulus.
   adsp_temp_prod must be twice the size of the modulus, adsp_temp_mont twice plus one word.
   Length and signs will be ignored!

   @param[out] adsp_dest       Result number.
   @param[in]  adsp_a          First number to be multiplied.
   @param[in]  adsp_b          Second number to be multiplied.
   @param[in]  adsp_ctx        Montgomery context for the reduction
   @param[in]  adsp_temp_prod  Temporary for storing the result of the squaring.
   @param[in]  adsp_temp_mont  Temporary for square and reduction,
 */
void m_mul_mont(struct dsd_lnum* adsp_dest,
                const struct dsd_lnum* adsp_a,
                const struct dsd_lnum* adsp_b,
                const struct dsd_lnum_montgomery_ctx* adsp_ctx,
                struct dsd_lnum* adsp_temp_prod,
                struct dsd_lnum* adsp_temp_mont);

/**
   Fetches a temporary lnum of requested size from the pool.

   Size is rounded up to a multiple of 2 words, minimum 2.
   If successful, the element and pointers in it are updated as necessary.
   This can cause aadsp_element to point to a new element.
   This function omits checks on aadsp_element, but will fail gracefully, if
   *aadsp_element is NULL.
   The temps used size and sign will not be initialized.
   The memory pointers will be aligned to the width of a pointer (usually 4 or 8).

   @param[in,out]  aadsp_element   IN: current pool element.
                                OUT: source pool element of temp.
   @param[in]      szp_byte_size   Size of requested temporary number.

   @return Pointer to the temporary lnum. NULL on failure.
 */
dsd_lnum* m_pool_get_lnum(dsd_mem_pool_ele** aadsp_element,
                          size_t szp_byte_size);


/**
   Initializes a single pool element.

   This means allocating the memory and setting all pointers. The 'next' pointer
   will be NULL. adsp_element must already be allocated. This function can be
   used to extend a pool, if necessary.

   @param[out] adsp_element    Pool element to be initialized.
   @param[in]  adsp_memory     Memory management.
   @param[in]  szp_block_size  Requested size of the memory block.
 */
extern "C" enum ied_encry_return m_mem_pool_init_ele(struct dsd_mem_pool_ele* adsp_element,
                                                     struct dsd_memory* adsp_memory,
                                                     size_t szp_block_size);


/**
   Fills a lnum with 0s if used words is smaller than the given number of words.
   Ensure that alloc size of point is not smaller than the given size when calling this function.

   @param[in,out] adsp_lnum      lnum
   @param[in]     szp_size       size in bytes the lnum will be filled up to
 */
inline static void ms_lnum_zero_fill(struct dsd_lnum *adsp_lnum,
                                     size_t szp_size)
{
    for (size_t szl_index = adsp_lnum->szc_used_size_bytes; szl_index <  szp_size; szl_index+=sizeof(LNUM_WORD))
    {
        ((LNUM_WORD*)(adsp_lnum->aucc_data))[szl_index / sizeof(LNUM_WORD)] = 0;
    }
}

/**
   sets member szc_used_size_bytes of an lnum that is filled with 0s.

   @param[in,out] adsp_lnum            lnum
 */
inline static void ms_lnum_set_used_words(struct dsd_lnum* adsp_lnum)
{
    for (int inl_i = (int)(adsp_lnum->szc_used_size_bytes / sizeof(LNUM_WORD)) - 1; inl_i >= 0; inl_i--)
    {
        if(((LNUM_WORD*)(adsp_lnum->aucc_data))[inl_i]==0) {
            adsp_lnum->szc_used_size_bytes-=sizeof(LNUM_WORD);
        } else{
            break;
        }
    }
}

// only for known answer tests
extern "C" void m_ecpt_weier_dbl(struct dsd_ec_point* adsp_result,
                                 struct dsd_lnum *adsp_tmp_1,
                                 struct dsd_lnum *adsp_tmp_2,
                                 struct dsd_lnum *adsp_tmp_3,
                                 struct dsd_lnum *adsp_tmp_4,
                                 struct dsd_lnum *adsp_tmp_5,
                                 struct dsd_lnum *adsp_tmp_6,
                                 struct dsd_lnum *adsp_tmp_7,
                                 struct dsd_lnum *adsp_tmp_8,
                                 struct dsd_lnum *adsp_tmp_impl_1,
                                 struct dsd_lnum *adsp_tmp_impl_2,
                                 const struct dsd_lnum_montgomery_ctx* adsp_mont_ctx,
                                 const struct dsd_ec_point* adsp_point_to_double,
                                 const struct dsd_ec_curve_params* adsp_ec_params);

// only for known answer tests
extern "C" void m_ecpt_weier_add(struct dsd_ec_point* adsp_result,
                                 struct dsd_lnum *adsp_tmp_1,
                                 struct dsd_lnum *adsp_tmp_2,
                                 struct dsd_lnum *adsp_tmp_3,
                                 struct dsd_lnum *adsp_tmp_4,
                                 struct dsd_lnum *adsp_tmp_5,
                                 struct dsd_lnum *adsp_tmp_6,
                                 struct dsd_lnum *adsp_tmp_7,
                                 struct dsd_lnum *adsp_tmp_8,
                                 struct dsd_lnum *adsp_tmp_9,
                                 struct dsd_lnum *adsp_tmp_10,
                                 struct dsd_lnum *adsp_tmp_impl_1,
                                 struct dsd_lnum *adsp_tmp_impl_2,
                                 const struct dsd_lnum_montgomery_ctx* adsp_mont_ctx,
                                 const struct dsd_ec_point* adsp_summand_1,
                                 const struct dsd_ec_point* adsp_summand_2,
                                 const struct dsd_ec_curve_params* adsp_ec_params);

// only for known answer tests
extern "C" void m_ecpt_set_used_words(struct dsd_ec_point* adsp_point);

// only for known answer tests
extern "C" void m_ecpt_zero_fill(struct dsd_ec_point *adsp_point,
                                 const struct dsd_lnum *adsp_prime);



/**
   Allocates the lnums in a dsd_ec_point structure. The dsd_ec_point sturcuture
   has to be already allocated.

   @param[in,out] adsp_memory          Memory manager
   @param[in,out] dsd_ec_point         EC point structure to be allocated
   @param[in]     szp_words_prime      used word size of prime

   @return 0 on success, error code otherwise
 */
extern "C" enum ied_encry_return m_ecpt_alloc(struct dsd_memory *adsp_memory,
                                              struct dsd_ec_point *adsp_ec_point,
                                              const size_t szp_words_prime);

/**
   Frees the lnums in a dsd_ec_point structure. The dsd_ec_point structure
   will not be freed.

   @param[in,out] adsp_memory          Memory manager
   @param[in,out] dsd_ec_point         EC point structure to be freed
 */
extern "C" void m_ecpt_free(struct dsd_memory *adsp_memory,
                            struct dsd_ec_point *adsp_ec_point);

/**
   Checks if point is on curve.

   @param[in]     adsp_point       Point to be checked
   @param[in]     adsp_pool        lnum pool
   @param[in]     adsp_ec_params   Parameters of curve

   @return ied_encry_success if on curve, ied_ecc_point_not_on_curve if not, errorcode otherwise
 */

extern "C" enum ied_encry_return m_ecpt_weier_on_curve(const struct dsd_ec_point* adsp_point,
                                                       struct dsd_mem_pool_ele* adsp_pool,
                                                       const struct dsd_ec_curve_params* adsp_ec_params);

// only for known answer tests
extern "C" enum ied_encry_return ms_ecpt_conv_to_aff(struct dsd_ec_point *adsp_point_to_scale,
                                                     struct dsd_mem_pool_ele *adsp_pool,
                                                     struct dsd_lnum *adsp_tmp_1,
                                                     struct dsd_lnum *adsp_tmp_2,
                                                     struct dsd_lnum *adsp_tmp_3,
                                                     struct dsd_lnum *adsp_tmpint_1,
                                                     struct dsd_lnum *adsp_tmpint_2,
                                                     const struct dsd_lnum_montgomery_ctx *adsp_mont_ctx,
                                                     const struct dsd_ec_curve_params *adsp_ec_params);

/**
   Scalar-multiplication of an EC point with a scalar. If either Qx/Qy is null
   and the other isn't, functions returns an error. If Qx and Qy are given,
   this functions computes k*Q. If Qx and Qy are null, it computes k*G and uses
   precomputations if they are available in adsp_ec_params. inp_width is ignored
   in this case. Montgomery context and one may or may not be available in
   adsp_ec_params. If not available, function will create it's own
   temporary context and one.

   @param[in,out] adsp_result          Destination
   @param[in,out] adsp_pool            lnum pool
   @param[in]     adsp_scalar          Scalar (k)
   @param[in]     adsp_ec_params       Curve-parameters
   @param[in]     adsp_Qx              Qx
   @param[in]     adsp_Qy              Qy
   @param[in]     inp_width            Width for wNAF algorithm

   @return 0 on success, error code otherwise
 */
extern "C" enum ied_encry_return m_ecpt_weier_scamult(struct dsd_ec_point *adsp_result,
                                                      struct dsd_mem_pool_ele *adsp_pool,
                                                      const struct dsd_lnum *adsp_scalar,
                                                      const struct dsd_ec_curve_params *adsp_ec_params,
                                                      const struct dsd_lnum *adsp_Qx,
                                                      const struct dsd_lnum *adsp_Qy,
                                                      const int inp_width);



/**
   Double-scalar-multiplication of EC points, that is, compute a*G+b*Q.

   @param[in,out] adsp_result          Destination
   @param[in,out] adsp_pool            lnum pool
   @param[in]     adsp_scalar_q        b
   @param[in]     adsp_q               Q
   @param[in]     adsp_scalar          Scalar (a)
   @param[in]     adsp_ec_params       Curve-parameters
   @param[in]     inp_width            Width for wNAF algorithm

   @return 0 on success, error code otherwise
 */
extern "C" enum ied_encry_return m_ecpt_weier_dblscamult(struct dsd_ec_point *adsp_result,
                                                         struct dsd_mem_pool_ele *adsp_pool,
                                                         const struct dsd_lnum *adsp_scalar_q,
                                                         const struct dsd_ec_point *adsp_q,
                                                         const struct dsd_lnum *adsp_scalar,
                                                         const struct dsd_ec_curve_params *adsp_ec_params,
                                                         const int inp_width);

/**
   Scalarmultiplication on montgomery curves (X25519 and X448) using X-coordinates only,
   that is, computing X_{k*P} given X_P and k.

   @param[in,out] adsp_x_out        lnum for X_out
   @param[in,out] adsp_pool         lnum pool
   @param[in]     adsp_k            scalar
   @param[in]     adsp_x_in         X_in
   @param[in]     adsp_params       curve params

   @return 0 on success, error code otherwise
 */
extern "C" enum ied_encry_return m_ecpt_montgo_scamult(struct dsd_lnum *adsp_x_out,
                                                       struct dsd_mem_pool_ele *adsp_pool,
                                                       const struct dsd_lnum *adsp_k,
                                                       const struct dsd_lnum *adsp_x_in,
                                                       const struct dsd_ec_curve_params *adsp_params);

/** @}*/

/**
Reads a byte buffer as big endian word.

Length is determined by the destination type.

@param[out] unp_dest Destination word.
@param[in]  abyp_src Source buffer to be read.
*/
inline void ms_read_big_endian(unsigned int& unp_dest,
                               const unsigned char* abyp_src)
{
#ifdef HL_BIG_ENDIAN
    unp_dest = *((unsigned int*)abyp_src);
#elif _WIN32
    // Windows byteswap
    unp_dest = _byteswap_ulong(*((unsigned int*)abyp_src));
#else
    // GCC and Clang built-in byteswap
    unp_dest = __builtin_bswap32(*((unsigned int*)abyp_src));
#endif
}

/**
Reads a byte buffer as big endian word.

Length is determined by the destination type.

@param[out] ulp_dest Destination word.
@param[in]  abyp_src Source buffer to be read.
*/
inline void ms_read_big_endian(unsigned long long& ulp_dest,
                               const unsigned char* abyp_src)
{
#ifdef HL_BIG_ENDIAN
    ulp_dest = *((unsigned long long*)abyp_src);
#elif _WIN32
    // Windows byteswap
    ulp_dest = _byteswap_uint64(*((unsigned long long*)abyp_src));
#else
    // GCC and Clang built-in byteswap
    ulp_dest = __builtin_bswap64(*((unsigned long long*)abyp_src));
#endif
}

/**
Writes a word into a byte buffer as big endian.

Length is determined by the word type.

@param[out] abyp_dest   Destination buffer to be written to.
@param[in]  unp_word    Word to be written.
*/
inline void ms_write_big_endian(unsigned char* abyp_dest,
                                unsigned int unp_word)
{
    ms_read_big_endian(((unsigned int*)abyp_dest)[0],
                       (const unsigned char*)(&unp_word));
}

/**
Writes a word into a byte buffer as big endian.

Length is determined by the word type.

@param[out] abyp_dest   Destination buffer to be written to.
@param[in]  ulp_word    Word to be written.
*/
inline void ms_write_big_endian(unsigned char* abyp_dest,
                                unsigned long long ulp_word)
{
    ms_read_big_endian(((unsigned long long*)abyp_dest)[0],
                       (const unsigned char*)(&ulp_word));
}

/**
Reads a byte buffer as little endian word.

Length is determined by the destination type.

@param[out] unp_dest Destination word.
@param[in]  abyp_src Source buffer to be read.
*/
inline void ms_read_little_endian(unsigned int& unp_dest,
                                  const unsigned char* abyp_src)
{
#ifdef HL_BIG_ENDIAN
    // GCC and Clang built-in byteswap
    unp_dest = __builtin_bswap32(*((unsigned int*)abyp_src));
#else
    unp_dest = *((unsigned int*)abyp_src);
#endif
}

/**
Reads a byte buffer as little endian word.

Length is determined by the destination type.

@param[out] ulp_dest Destination word.
@param[in]  abyp_src Source buffer to be read.
*/
inline void ms_read_little_endian(unsigned long long& ulp_dest,
                                  const unsigned char* abyp_src)
{
#ifdef HL_BIG_ENDIAN
    // GCC and Clang built-in byteswap
    ulp_dest = __builtin_bswap64(*((unsigned long long*)abyp_src));
#else
    ulp_dest = *((unsigned long long*)abyp_src);
#endif
}

/**
Writes a word into a byte buffer as little endian.

Length is determined by the word type.

@param[out] abyp_dest   Destination buffer to be written to.
@param[in]  unp_word    Word to be written.
*/
inline void ms_write_little_endian(unsigned char* abyp_dest,
                                   unsigned int unp_word)
{
    ms_read_little_endian(((unsigned int*)abyp_dest)[0],
                          (const unsigned char*)(&unp_word));
}

/**
Writes a word into a byte buffer as little endian.

Length is determined by the word type.

@param[out] abyp_dest   Destination buffer to be written to.
@param[in]  ulp_word    Word to be written.
*/
inline void ms_write_little_endian(unsigned char* abyp_dest,
                                   unsigned long long ulp_word)
{
    ms_read_little_endian(((unsigned long long*)abyp_dest)[0],
                          (const unsigned char*)(&ulp_word));
}

#endif // !HOB_ENCRY_INTERN_2_H__
