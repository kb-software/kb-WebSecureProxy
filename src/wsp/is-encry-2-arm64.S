### Assembler ##############
# Assembler: GNU assembler
# Reference version: GCC 4.9.2
# Recommended flags: -mcpu=cortex-a53+crypto
##############################

#ifdef __aarch64__

.global m_impl_add
.global _m_impl_add
.global m_impl_add_word
.global _m_impl_add_word
.global m_impl_sub
.global _m_impl_sub
.global m_impl_add_karatsuba
.global _m_impl_add_karatsuba
.global m_impl_sub_karatsuba
.global _m_impl_sub_karatsuba
.global m_impl_mult_basic
.global _m_impl_mult_basic
.global m_impl_square
.global _m_impl_square
.global m_impl_cmp
.global _m_impl_cmp
.global m_impl_mont_mul_add
.global _m_impl_mont_mul_add
.global m_impl_first_bit
.global _m_impl_first_bit
.global m_impl_last_bit
.global _m_impl_last_bit

.global m_impl_aes_cbc_encrypt
.global _m_impl_aes_cbc_encrypt
.global m_impl_aes_cbc_decrypt
.global _m_impl_aes_cbc_decrypt
.global m_impl_aes_128_key_expansion
.global _m_impl_aes_128_key_expansion
.global m_impl_aes_192_key_expansion
.global _m_impl_aes_192_key_expansion
.global m_impl_aes_256_key_expansion
.global _m_impl_aes_256_key_expansion
.global m_impl_aes_revert_key
.global _m_impl_aes_revert_key

.global m_impl_aes_ecb_encrypt
.global _m_impl_aes_ecb_encrypt
.global m_impl_aes_ctr
.global _m_impl_aes_ctr
.global m_impl_ghash_stream
.global _m_impl_ghash_stream

### Calling convention ####################################
# Input:    x0,x1,x2,...
# Output:   x0
###########################################################

//-----------------------------------------------------------
// Lnum functions
//-----------------------------------------------------------

### General remarks #######################################
# 1.Input/Output data are given as unsigned char arrays
# 2.Internally, they are ALWAYS considered as LNUM_WORD arrays
# 3.Given (byte-)lenghts are supposed to be multiple of sizeof(LNUM_WORD) and
#  should be converted to LNUM_WORD-lengths at beginnings
### References ############################################
# [handbook] Handbook of Applied Cryptography by J. Menezes et.al
###########################################################

# Addition
# size_t
# m_impl_add(unsigned char* aurp_dest,
#            const unsigned char* aurp_a,
#            size_t szp_a_len,
#            const unsigned char* aurp_b,
#            size_t szp_b_len)
# Note: The possible last carry is only then written if exists
.balign 16
m_impl_add:
_m_impl_add:
# Sort: num1, num2 into [x3,w4], [x5,w6] s.t. w4 >= w6
    lsr     w2, w2, #3
    lsr     w4, w4, #3              // byte2word
    cmp     w2, w4
    csel    w6, w2, w4, ls
    csel    w4, w4, w2, ls
    csel    x5, x1, x3, ls
    csel    x3, x3, x1, ls          // END Sort
    adds    w1, w6, wzr             // w1   sum len of loop1, cflag =0
    sub     w2, w4, w6              // w2   sum len of loop2
    lsr     w6, w1, #2              // w6   [w1 /4] ctr for loop1
    lsr     w7, w2, #2              // w7   [w2 /4] ctr for loop2
    cbz     w6, step128_1_ad4       // while w6 > 0, add next 256 bit
loop256_1_ad4:
    ldp     x12, x13, [x3], #16
    ldp     x14, x15, [x5], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    ldp     x12, x13, [x3], #16
    stp     x10, x11, [x0], #16
    ldp     x14, x15, [x5], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    sub     w6, w6, #1
    stp     x10, x11, [x0], #16
    cbnz    w6, loop256_1_ad4       // END loop256_1
step128_1_ad4:                      // Extra step if w1 % 4 >1
    tbz     w1, #1, step64_1_ad4
    ldp     x12, x13, [x3], #16
    ldp     x14, x15, [x5], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    stp     x10, x11, [x0], #16
step64_1_ad4:                       // Extra step if w1 % 2 >0
    tbz     w1, #0, begin_cpro_ad4
    ldr     x14, [x3], #8
    ldr     x15, [x5]
    adcs    x13, x14, x15
    str     x13, [x0], #8
begin_cpro_ad4:                     // (carry propagation)
    cbz     w7, step128_2_ad4       // loop2 while w7 >0
loop256_2_ad4:
    ldp     x14, x15, [x3], #16
    adcs    x12, x14, xzr
    adcs    x13, x15, xzr
    ldp     x10, x11, [x3], #16
    stp     x12, x13, [x0], #16
    adcs    x14, x10, xzr
    adcs    x15, x11, xzr
    sub     w7, w7, #1
    stp     x14, x15, [x0], #16
    cbnz    w7, loop256_2_ad4       // END loop256_2
step128_2_ad4:                      // Extra step of w2 % 4 >1
    tbz     w2, #1, step64_2_ad4
    ldp     x14, x15, [x3], #16
    adcs    x12, x14, xzr
    adcs    x13, x15, xzr
    stp     x12, x13, [x0], #16
step64_2_ad4:
    tbz     w2, #0, last_c_ad4      // Extra step if w2 % 2 >0
    ldr     x15, [x3]
    adcs    x14, x15, xzr
    str     x14, [x0], #8
last_c_ad4:
    b.cc    ret_ad4                 // If cflag = 0, goto ret
    mov     x15, #1
    str     x15, [x0]               // Otherwise, store #1
ret_ad4:
    cinc    w0, w4, cs              // Return size
    lsl     w0, w0, #3              // word2byte
    ret                             // END m_impl_add


# Subtraction
# size_t
# m_impl_sub(unsigned char* aurp_dest,
#            const unsigned char* aurp_a,
#            size_t szp_a_len,
#            const unsigned char* aurp_b,
#            size_t szp_b_len)
# Note: The result size is checked alongside the mian calculation (by update)
.balign 16
m_impl_sub:
_m_impl_sub:
    lsr     w2, w2, #3
    lsr     w4, w4, #3              // byte2word
    sub     w5, w2, w4              // w5 = w2 - w4 for loop2
    subs    x2, x0, xzr             // x2 = dest_arr, cflag =1
    lsr     w6, w4, #2              // w6 = [w4 /4] ctr for loop1
    lsr     w7, w5, #2              // w7 = [w5 /4] ctr for loop2
    mov     w0, wzr                 // w0   last nonzero position
    mov     w9, wzr                 // w9  size counter
    cbz     w6, step128_1_sub3      // loop while w6 > 0, subt next 256 bit
loop256_1_sub3:
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x3], #16
    sbcs    x10, x12, x14
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x10 != 0
    sbcs    x11, x13, x15
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x11 != 0
    ldp     x12, x13, [x1], #16
    stp     x10, x11, [x2], #16
    ldp     x14, x15, [x3], #16
    sbcs    x10, x12, x14
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if 
    sbcs    x11, x13, x15
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if 
    sub     w6, w6, #1
    stp     x10, x11, [x2], #16
    cbnz    w6, loop256_1_sub3      // END loop256_1
step128_1_sub3:
    tbz     w4, #1,step64_1_sub3    // Extra step if w4 % 4 >2
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x3], #16
    sbcs    x10, x12, x14
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x10 != 0
    sbcs    x11, x13, x15
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x11 != 0
    stp     x10, x11, [x2], #16
step64_1_sub3:
    tbz     w4, #0, begin_cpro_sub3
    ldr     x14, [x1], #8
    ldr     x15, [x3]
    sbcs    x13, x14, x15
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x13 != 0
    str     x13, [x2], #8
begin_cpro_sub3:                    // (carry propagation)
    cbz     w7, step128_2_sub3      // loop while w7 > 0, subtract zeros
loop256_2_sub3:
    ldp     x14, x15, [x1], #16
    sbcs    x12, x14, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x12 != 0
    sbcs    x13, x15, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x13 != 0
    ldp     x14, x15, [x1], #16
    stp     x12, x13, [x2], #16
    sbcs    x10, x14, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x10 != 0
    sbcs    x11, x15, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x11 != 0
    sub     w7, w7, #1
    stp     x10, x11, [x2], #16
    cbnz    w7, loop256_2_sub3      // END loop256_2
step128_2_sub3:
    tbz     w5, #1, step64_2_sub3   // Exstra step of w5 % 4 >2
    ldp     x14, x15, [x1], #16
    sbcs    x12, x14, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x12 != 0
    sbcs    x13, x15, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x13 != 0
    stp     x12, x13, [x2], #16
step64_2_sub3:
    tbz     w5, #0, end_sub3        // Extra step if w5 % 2 >0
    ldr     x15, [x1]
    sbcs    x14, x15, xzr
    add     w9, w9, #1
    csel    w0, w9, w0, ne          // Update w0 if x14 != 0
    str     x14, [x2]
end_sub3:
    lsl     w0, w0, #3              // word2byte
    ret                             // END m_impl_sub

# Macros for m_impl_mult_basic
# Calculate (c1,c0) += a0 * b0 and set flags
.macro  MADDs   a0, b0, c0, c1, tp, tp2
    mul     \tp, \a0, \b0
    adds    \c0, \c0, \tp
    umulh   \tp2, \a0, \b0
    adcs    \c1, \c1, \tp2
.endm
# Calculate (c1,c0) += a0 * (b1,b0) and set flags
.macro MADD_1_2s    a0, b0, b1, c0, c1, c2, tp, tp2
    mul     \tp, \a0, \b0
    umulh   \tp2, \a0, \b0
    adds    \c0, \c0, \tp
    adcs    \c1, \c1, \tp2
    mul     \tp, \a0, \b1
    umulh   \tp2, \a0, \b1
    adc     \tp2, \tp2, xzr
    adds    \c1, \c1, \tp
    adcs    \c2, \c2, \tp2
.endm
# Same as MADD_1_2s but b0 will be destroyed
.macro MADD_1_2s_eco    a0, b0, b1, c0, c1, c2, tp
    mul     \tp, \a0, \b0
    adds    \c0, \c0, \tp
    umulh   \tp, \a0, \b0
    adcs    \c1, \c1, \tp
    mul     \tp, \a0, \b1
    umulh   \b0, \a0, \b1
    adc     \b0, \b0, xzr
    adds    \c1, \c1, \tp
    adcs    \c2, \c2, \b0
.endm

# Multiplication
# void
# m_impl_mult_basic(unsigned char* aurp_dest,
#                   const unsigned char* aurp_a,
#                   size_t szp_a_len,
#                   const unsigned char* aurp_b,
#                   size_t szp_b_len)
# Cache algorithm from:
# Fast Multi-Precision Multiplication for Public-Key Cryptography on Embedded Microprocessors
# by Michael Hutter and Erich Wenger
# Note: Notations are based on Fig.8 (not their poseudocode)
# Note: Small modificationsa are done, expecially for the case a_len != b_len
.balign 16
m_impl_mult_basic:
_m_impl_mult_basic:
    lsr     w2, w2, #3
    lsr     w4, w4, #3                  // word2byte
# Pre-calc for case w2 != w4
    cmp     w2, w4
    csel    x11, x1, x3, hi
    csel    w12, w2, w4, hi
    csel    x13, x1, x3, ls
    csel    w14, w2, w4, ls
    add     x5, x11, x14, lsl #3 
    sub     w6, w12, w14                // [x5,w6] tail
    stp     x29, x30, [sp, #-128]!
    mov     x29, sp
    stp     w6, w14, [sp, #96]
    stp     x5, x13, [sp, #112]
# Caching algorithm with shorter length, leaving tail until end
# i.e. [x1,w14]*[x3,w14]
    add     x0, x0, x14, lsl #3
    add     x1, x1, x14, lsl #3
    mov     w2, w14                     // x2   [n-i,i], i=0
    ands    w7, w14, #7                 // w7   n % 8
    b.eq    end_b_init_mulcb2
# Step b_init via school book
# (the extra step needed if w2 % 8 > 0)
    sub     x0, x0, x7, lsl #3 
    sub     x1, x1, x7, lsl #3 
    mov     w15, w7
    mov     x2, x0
loop_b_init_0_mulcb2:
    stp     xzr, xzr, [x2], #16
    subs    w15, w15, #2
    b.hi    loop_b_init_0_mulcb2
    mov     x5, x1
loop_out_b_init_mulcb2:
    ldr     x4, [x5], #8
    mov     x9, x0
    mov     x6, x3
    and     w2, w14, #7
    mov     x10, xzr                    // Carry =0
loop_in_b_init_mulcb2:
    ldr     x13, [x9]
    ldr     x15, [x6], #8
    mul     x11, x4, x15
    umulh   x12, x4, x15
    adds    x13, x13, x10
    adc     x12, x12, xzr
    adds    x13, x13, x11
    adc     x10, x12, xzr
    subs    w2, w2, #1
    str     x13, [x9], #8
    b.ne    loop_in_b_init_mulcb2
    add     x0, x0, #8
    subs    w7, w7, #1
    str     x10, [x9]                   // Store last carry
    b.ne    loop_out_b_init_mulcb2
// Re-positioning
    and     w7, w14, #7
    eor     w2, w14, w7
    eor     x2, x2, x7, lsl #32         // x2   [n-i,i], i=len%8
    add     x0, x0, x7, lsl #3          // END b_init
# Step r (phase1, phase2, phase3, phase4)
end_b_init_mulcb2:
    cbz     w2, check_asymm_mulcb2      // If w2=0, done
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]
////////// Plan of register use ////////////////////
// x0,x1,x3                             addrs
// x2                                   [n-i,i]
// [x10,x11,x12,x13,x14,x15,x6,x7]      Cache of A
// [x20,x21,x22,x23,x24,x25,x26,x27]    Cache of B
// (x5,x4)                              carry
// x9,x10,x28                           tmps
// x29                                  tmp (not FP anymore)
////////////////////////////////////////////////////
loop_r_mulcb2:
# Cache 8 words from a
    ldp     x10, x11, [x1, #-64]
    ldp     x12, x13, [x1, #-48]
    ldp     x14, x15, [x1, #-32]
    ldp     x6, x7, [x1, #-16]
# Cache 8 words from b
    ldp     x20, x21, [x3], #64
    ldp     x22, x23, [x3, #-48]
    ldp     x24, x25, [x3, #-32]
    ldp     x26, x27, [x3, #-16]
# Set writing pos
    mov     x9, #8
    add     x9, x9, x2, lsr #31         // 2*i + e, e=8
    sub     x0, x0, x9, lsl #3
# Phase 1 :using [x28,x19] for stp
//0
    mul     x28, x10, x20
    umulh   x19, x10, x20
//1
    mov     x4, xzr
    MADDs   x11, x20, x19, x4, x9, x9
    MADDs   x10, x21, x19, x4, x9, x9
    adc     w5, wzr, wzr                // New carry (w5,x4)
    stp     x28, x19, [x0], #16
//2
    mov     x28, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x28)
    MADDs   x12, x20, x28, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x11, x21, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x10, x22, x28, x4, x9, x9
    adc     w5, w5, wzr
//3
    mov     x19, x4                     // Move carry into ((x5),x4,x19)
    mov     x4, x5
    MADDs   x13, x20, x19, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x12, x21, x19, x4, x9, x9
    adc     x5, x5, xzr
    MADDs   x11, x22, x19, x4, x9, x9
    adc     x5, x5, xzr
    MADDs   x10, x23, x19, x4, x9, x9
    adc     w5, w5, wzr
    stp     x28, x19, [x0], #16
//4
    mov     x28, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x28)
    MADDs   x14, x20, x28, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x13, x21, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x22, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x11, x23, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x10, x24, x28, x4, x9, x9
    adc     w5, w5, wzr
//5
    mov     x19, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x19)
    MADDs   x15, x20, x19, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x14, x21, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x22, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x23, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x11, x24, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x10, x25, x19, x4, x9, x9
    adc     w5, w5, wzr
    stp     x28, x19, [x0], #16
//6
    mov     x28, x4                     // Move carry into ((x5),x4,x28)
    mov     x4, x5
    MADDs   x6, x20, x28, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x15, x21, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x22, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x23, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x24, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x11, x25, x28, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x10, x26, x28, x4, x9, x9
    adc     w5, w5, wzr
//7
    mov     x19, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x19)
    MADDs   x7, x20, x19, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x21, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x22, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x23, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x24, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x25, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x11, x26, x19, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x10, x27, x19, x4, x9, x9
    adc     w5, w5, wzr
    stp     x28, x19, [x0], #16
# Phase 2
    lsr     x19, x2, #32                    // w19  ctr
    cbz     w19, begin_phase4_mulcb2        // if 0, skip both phase2 and 3
    subs    w19, w19, #1
    b.eq    step_phase2_mulcb2
loop_phase2_mulcb2:                         // loop by 2 words (unrolled)
    ldp     x9, x20, [x3], #16
    ldp     x28, x29, [x0]
// 10,11,12,13,14,15, 6, 7      Cache of A
// 21,22,23,24,25,26,27, 9,20   Cache of B
    adds    x28, x28, x4
    adcs    x29, x29, x5
    adc     w4, wzr, wzr
    lsl     x19, x19, #32                   // Keep the value in upper half, free the lower
    MADD_1_2s_eco   x7,  x21, x22, x28, x29, x4, x5
    adc             x19, x19, xzr           // (w19,x4) temporary used for carry
    MADD_1_2s       x6,  x22, x23, x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x15, x23, x24, x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x14, x24, x25, x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x13, x25, x26, x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x12, x26, x27, x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x11, x27, x9,  x28, x29, x4, x21, x5
    adc             x19, x19, xzr
    MADD_1_2s       x10, x9,  x20, x28, x29, x4, x21, x5
    adc     w5, w19, wzr                    // (w5,x4)  new carry
    lsr     x19, x19, #32                   // Restore the value
    mov     x21, x23
    mov     x23, x25
    mov     x25, x27
    mov     x27, x20
    mov     x20, x22
    mov     x22, x24
    mov     x24, x26
    mov     x26, x9                         //  x20-x27 current Cache of B
    subs    w19, w19, #2
    stp     x28, x29, [x0], #16
    b.hi    loop_phase2_mulcb2
    b.ne    end_phase_2_mulcb2
step_phase2_mulcb2:                         // exstra step in odd case
    ldr     x9, [x0]
    mov     x20, x21
    mov     x21, x22
    mov     x22, x23
    mov     x23, x24
    mov     x24, x25
    mov     x25, x26
    mov     x26, x27
    ldr     x27, [x3], #8
    adds    x28, x9, x4
    adc     w4, wzr, w5                     // Initialise ((x5),x4,x28)
    MADDs   x7, x20, x28, x4, x9, x19
    adc     w5, wzr, wzr
    MADDs   x6, x21, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x15, x22, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x14, x23, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x13, x24, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x12, x25, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x11, x26, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x10, x27, x28, x4, x9, x19
    adc     w5, w5, wzr                     // (w5,x4)  new carry
    str     x28, [x0], #8
end_phase_2_mulcb2:
#Phase3, similar to phase 2
    lsr     x19, x2, #32
    subs    w19, w19, #1
    b.eq    step_phase3_mulcb2
loop_phase3_mulcb2:
    ldp     x9, x10, [x1], #16
    ldp     x28, x29, [x0]
// 11,12,13,14,15, 6, 7, 9, 10  Cache of A
// 20,21,22,23,24,25,26,27      Cache of B
    adds    x28, x28, x4
    adcs    x29, x29, x5
    adc     w4, wzr, wzr
    lsl     x19, x19, #32
    MADD_1_2s_eco   x27, x11, x12, x28, x29, x4, x5
    adc             x19, x19, xzr
    MADD_1_2s       x26, x12, x13, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x25, x13, x14, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x24, x14, x15, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x23, x15, x6, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x22, x6, x7, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x21, x7, x9, x28, x29, x4, x11, x5
    adc             x19, x19, xzr
    MADD_1_2s       x20, x9, x10, x28, x29, x4, x11, x5
    adc     w5, w19, wzr
    lsr     x19, x19, #32
    mov     x11, x13
    mov     x13, x15
    mov     x15, x7
    mov     x7, x10
    mov     x12, x14
    mov     x14, x6
    mov     x6, x9
    subs    w19, w19, #2
    stp     x28, x29, [x0], #16
    b.hi    loop_phase3_mulcb2
    b.ne    begin_phase4_mulcb2
step_phase3_mulcb2:
    ldr     x9, [x0]
    mov     x10, x11
    mov     x11, x12
    mov     x12, x13
    mov     x13, x14
    mov     x14, x15
    mov     x15, x6
    mov     x6, x7
    ldr     x7, [x1], #8
    adds    x28, x9, x4
    adc     w4, wzr, w5
    MADDs   x7, x20, x28, x4, x9, x19
    adc     w5, wzr, wzr
    MADDs   x6, x21, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x15, x22, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x14, x23, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x13, x24, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x12, x25, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x11, x26, x28, x4, x9, x19
    adc     w5, w5, wzr
    MADDs   x10, x27, x28, x4, x9, x19
    adc     w5, w5, wzr
    str     x28, [x0], #8
# Phase 4, similar to phase 1
begin_phase4_mulcb2:
//8
    mov     x20, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x20)
    MADDs   x7, x21, x20, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x22, x20, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x23, x20, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x24, x20, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x25, x20, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x26, x20, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x11, x27, x20, x4, x9, x9
    adc     w5, w5, wzr
//9
    mov     x21, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x21)
    MADDs   x7, x22, x21, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x23, x21, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x24, x21, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x25, x21, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x26, x21, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x12, x27, x21, x4, x9, x9
    adc     w5, w5, wzr
//10
    mov     x22, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x22)
    MADDs   x7, x23, x22, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x24, x22, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x25, x22, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x26, x22, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x13, x27, x22, x4, x9, x9
    adc     w5, w5, wzr
//11
    mov     x23, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x23)
    MADDs   x7, x24, x23, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x25, x23, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x26, x23, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x14, x27, x23, x4, x9, x9
    adc     w5, w5, wzr
//12
    mov     x24, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x24)
    MADDs   x7, x25, x24, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x26, x24, x4, x9, x9
    adc     w5, w5, wzr
    MADDs   x15, x27, x24, x4, x9, x9
    adc     w5, w5, wzr
//13
    mov     x25, x4
    mov     x4, x5                      // Move carry into ((x5),x4,x25)
    MADDs   x7, x26, x25, x4, x9, x9
    adc     w5, wzr, wzr
    MADDs   x6, x27, x25, x4, x9, x9
    adc     w5, w5, wzr
//14 and 15
    mul     x26, x7, x27
    umulh   x9, x7, x27
    adds    x26, x26, x4
    adc     x27, x9, x5
// Re-positioning
    mov     x10, #0x7fffffff8
    add     x2, x2, x10                 // [n-i,i] += [-8,+8]
    lsr     x9, x2, #32
    lsl     w9, w9, #3
    sub     x1, x1, x9                  // *x1 = a[n-i]
    sub     x3, x3, x9                  // *x3 = b[0]
    stp     x20, x21, [x0], #64
    stp     x22, x23, [x0, #-48]
    stp     x24, x25, [x0, #-32]
    stp     x26, x27, [x0, #-16]
    cbnz    w2, loop_r_mulcb2           // END loop_r
end_cache_mulcb2:
    mov     x29, sp
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]         // END Caching algorithm
check_asymm_mulcb2:
    ldp     w12, w14, [sp, #96]
    cbz     w12, ret_mulcb2             // If input lenghs were equal, done
# Special initialisation for school book
    ldp     x11, x13, [sp, #112]
    cmp     w12, w14
    lsr     x9, x2, #32
    mov     x5, x0
    csel    w2, w12, w14, hi
    csel    x1, x11, x13, hi
    csel    w4, w12, w14, ls
    csel    x3, x11, x13, ls
    sub     x0, x0, x9, lsl #3
    lsr     w7, w12, #1
    cbz     w7, loop_outer_sb_mulcb2
loop0_sb_mulcb2:
    stp     xzr, xzr, [x5], #16
    subs    w7, w7, #1
    b.ne    loop0_sb_mulcb2
# School book multiplication, nested loop part
# x0        dst (initialised)
# x1, w2    num_a
# x3, w4    num_b
# Assumed 1 < w4 <= w2
loop_outer_sb_mulcb2:               // Loop_outer(while w4>0) over words of b
    ldr     x11, [x3], #8           // x11      current word in b
    mov     x5, x0                  // x5       writing pos
    mov     x6, x1                  // x6       ap_a
    sub     w7, w2, #1              // w7       ctr for loop_inner = a_len - 1
    mov     x10, xzr                // x10      carry
# To be done: num1*(x11)
    cbz     w7, step_inner_sb_mulcb2
loop_inner_sb_mulcb2:               // Loop_inner(while w7>1) over d_words of a
    ldp     x14, x15, [x6], #16
    ldp     x12, x13, [x5]          // (x13,x12)    curr. content at writing pos
# Calculation: (x10,x13,x12) = (x13,x12) + x10 + x11*(x15,x14)
    adds    x12, x12, x10
    mul     x9, x11, x15
    umulh   x10, x11, x15
    adcs    x13, x13, x9
    adc     x10, x10, xzr           // (x10|x13,x12)=(x13,x12)+(x11*x15,x10)
    mul     x9, x11, x14
    umulh   x15, x11, x14
    adds    x12, x12, x9
    adcs    x13, x13, x15
    adc     x10, x10, xzr           // (x10|x13,x12)+=x11*x14, x10 new carry
    subs    w7, w7, #2
    stp     x12, x13, [x5], #16
    b.hi    loop_inner_sb_mulcb2    // END loop_inner
step_inner_sb_mulcb2:
    b.ne    last_c_inner_sb_mulcb2
    ldr     x14, [x6]
    ldr     x12, [x5]
# Calculation: (x10,x12) = x12 + x10 + x11*X14
    adds    x12, x12, x10
    mul     x9, x11, x14
    umulh   x10, x11, x14
    adc     x10, x10, xzr
    adds    x12, x12, x9
    adc     x10, x10, xzr           // new carry
    str     x12, [x5], #8
last_c_inner_sb_mulcb2:
    subs    w4, w4, #1
    add     x0, x0, #8              // w4--, x0+=8 for outer loop
    str     x10, [x5]               // Store last carry
    b.ne    loop_outer_sb_mulcb2    // END loop_outer
ret_mulcb2:
    ldp     x29, x30, [sp], #128
    ret 

# Macros for m_impl_square
# Calculate (c3,c2,c1,c0)=(a1,a0)*(b1,b0) with two tmps
.macro  MULT_2_rapid    a0, a1, b0, b1, c0, c1, c2, c3, tp, tp2
    mul     \c0, \a0, \b0
    umulh   \c1, \a0, \b0
    mul     \c2, \a1, \b1
    umulh   \c3, \a1, \b1
    mul     \tp, \a0, \b1
    umulh   \tp2, \a0, \b1
    adds    \c1, \c1, \tp
    adcs    \c2, \c2, \tp2
    adc     \c3, \c3, xzr
    mul     \tp, \a1, \b0
    umulh   \tp2, \a1, \b0
    adds    \c1, \c1, \tp
    adcs    \c2, \c2, \tp2
    adc     \c3, \c3, xzr
.endm
# Calculate (c3,c2,c1,c0)=(a1,a0)^2 with two tmps
.macro  SQ_2_rapid  a0, a1, c0, c1, c2, c3, tp, tp2
    mul     \c0, \a0, \a0
    umulh   \c1, \a0, \a0
    mul     \c2, \a1, \a1
    umulh   \c3, \a1, \a1
    mul     \tp, \a0, \a1
    umulh   \tp2, \a0, \a1
    adds    \c1, \c1, \tp, lsl #1
    lsr     \tp, \tp, #63
    orr     \tp, \tp, \tp2, lsl #1
    adcs    \c2, \c2, \tp
    lsr     \tp2, \tp2, #63
    adc     \c3, \c3, \tp2
.endm
# (c3,c2,c1,c0)+=(a1,a0)*(b1,b0) and return carry in ac, tp=t2 is possible
.macro  MULT_2_comba_ows    a0, a1, b0, b1, c0, c1, c2, c3, ac, tp, tp2
// (c2,c1,c0) += a0*b0
    mul     \tp, \a0, \b0
    adds    \c0, \c0, \tp
    umulh   \tp2, \a0, \b0
    adcs    \c1, \c1, \tp2
    adcs    \c2, \c2, xzr
    adc     \ac, xzr, xzr
// (c3,c2,c1) += a0*b1 + a1*b0
    mul     \tp, \a0, \b1
    adds    \c1, \c1, \tp
    umulh   \tp2, \a0, \b1
    adcs    \c2, \c2, \tp2
    adc     \ac, \ac, xzr
    mul     \tp, \a1, \b0
    adds    \c1, \c1, \tp
    umulh   \tp2, \a1, \b0
    adcs    \c2, \c2, \tp2
    adcs    \c3, \c3, \ac
    adc     \ac, xzr, xzr
// (c3,c2) += a1*b1
    mul     \tp, \a1, \b1
    adds    \c2, \c2, \tp
    umulh   \tp2, \a1, \b1
    adcs    \c3, \c3, \tp2
    adc     \ac, \ac, xzr
.endm
# (c3,c2,c1,c0)+=(a1,a0)^2 and return carry in ac
.macro  SQ_2_comba_ows      a0, a1, c0, c1, c2, c3, ac, tp, tp2
// (c2,c1,c0) += a0*a0
    mul     \tp, \a0, \a0
    umulh   \tp2, \a0, \a0
    adds    \c0, \c0, \tp
    adcs    \c1, \c1, \tp2
    adcs    \c2, \c2, xzr
    adc     \ac, xzr, xzr
// (c3,c2,c1) += 2*a0*a1
    mul     \tp, \a0, \a1
    umulh   \tp2, \a0, \a1
    adds    \c1, \c1, \tp, lsl #1
    lsr     \tp, \tp, #63
    orr     \tp, \tp, \tp2, lsl #1
    adcs    \c2, \c2, \tp
    add     \ac, \ac, \tp2, lsr #63
    adcs    \c3, \c3, \ac
    adc     \ac, xzr, xzr
// (c3,c2) += a1*a1
    mul     \tp, \a1, \a1
    umulh   \tp2, \a1, \a1
    adds    \c2, \c2, \tp
    adcs    \c3, \c3, \tp2
    adc     \ac, \ac, xzr
.endm

# Squaring (Basic Comba's algorithm:double-word base)
# void
# m_impl_square(unsigned char* aurp_dest,
#               const unsigned char* aurp_a,
#               size_t szp_a_len);
.balign 16
m_impl_square:
_m_impl_square:
    lsr     w2, w2, #3              // byte2word
    cmp     w2, #8
    b.eq    m_impl_sqr_8
    cmp     w2, #2
    b.hi    body_sqcdw2
    b.lo    word_case_sqcdw2
// len = 2
    ldp     x6, x7, [x1]
    SQ_2_rapid  x6, x7, x9, x10, x11, x12, x14, x15
    stp     x9, x10, [x0], #16
    stp     x11, x12, [x0]
    ret                             // END double word case
    b       body_sqcdw2
word_case_sqcdw2:
// len = 1
    ldr     x6, [x1]
    mul     x9, x6, x6
    umulh   x10, x6, x6
    stp     x9, x10, [x0]
    ret                             // END word case
body_sqcdw2:
# len > 2: Nested double-word based comba
# Notaton: a[0],..,a[n-1] double-word array with n = [len/2], a[n-1] may be single-word-size
    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    sub     w9, w2, #2
    add     x5, x1, x9, lsl #3      // x5  points the last word, loop stopper
    mov     x2, x1                  // *x2  a[i], i=0
    ldp     x14, x15, [x2], #16     // BEGIN calculation for i=0
    SQ_2_rapid  x14, x15, x22, x23, x19, x20, x12, x13
    stp     x22, x23, [x0], #16     // END calculation for i=0
    mov     x21, xzr                // (x21,x20,x19)    carry 
loop_low_sqcdw2:                    // Loop for i=1,..,n-2
    cmp     x2, x5
    b.hs    begin_high_sqcdw2
    mov     x3, x1                  // *x3 = a[0]
    mov     x4, x2                  // *x4 = a[i]
    mov     x6, xzr
    mov     x7, xzr
    mov     x9, xzr
    mov     x10, xzr
    mov     x11, xzr                // (x11|x10,x9|x7,x6)=0 acc
loop_low_in_sqcdw2:                 // Loop for convolution
    cmp     x3, x4
    b.hs    double_low_in_sqcdw2
    ldp     x12, x13, [x3], #16
    ldp     x14, x15, [x4], #-16
    MULT_2_comba_ows    x12, x13, x14, x15, x6, x7, x9, x10, x22, x23, x24
    add     x11, x11, x22           // acc += 
    b       loop_low_in_sqcdw2      // END loop_low_in
double_low_in_sqcdw2:
    lsl     x11, x11, #1
    orr     x11, x11, x10, lsr #63
    lsl     x10, x10, #1
    orr     x10, x10, x9, lsr #63
    lsl     x9, x9, #1
    orr     x9, x9, x7, lsr #63
    lsl     x7, x7, #1
    orr     x7, x7, x6, lsr #63
    lsl     x6, x6, #1              // acc *= 2
    b.ne    add_low_sqcdw2
middle_low_in_sqcdw2:               // If i is even, then
    ldp     x14, x15, [x3]
    SQ_2_comba_ows  x14, x15, x6, x7, x9, x10, x22, x12, x13
    add     x11, x11, x22           // acc +=
add_low_sqcdw2:                     // acc += carry
    adds    x22, x6, x19
    adcs    x23, x7, x20
    stp     x22, x23, [x0], #16
    adcs    x19, x9, x21
    adcs    x20, x10, xzr
    adc     x21, x11, xzr           // (x21,x20,x19) new carry
    add     x2, x2, #16
    b       loop_low_sqcdw2         // END loop_low
begin_high_sqcdw2:                  //Beginning of high part
# Distinguish the even and odd cases related to input array length
    b.eq    ldp_lastdw_sqcdw2
    ldr     x23, [x2]
    b       loop_high_odd_sqcdw2    // Load single-word for a[n-1] if odd
ldp_lastdw_sqcdw2:
    ldp     x23, x24, [x2]          // Load double-word for a[n-1] if even
# Even case
# *x1 = a[0]
# *x2 = a[n-1]
# (x24,x23) = a[n-1]
loop_high_even_sqcdw2:              // Loop for i=n-1,..,2n-1
    ldp     x14, x15, [x1], #16
    mov     x3, x1
    add     x4, x2, #-16
    MULT_2_rapid    x23, x24, x14, x15, x6, x7, x9, x10, x12, x13
    mov     x11, xzr                // (x11|x10,x9|x7,x6)   acc with first elem
loop_high_even_in_sqcdw2:           // Loop for convolution
    cmp     x3, x4
    b.hs    double_high_even_in_sqcdw2
    ldp     x12, x13, [x3], #16
    ldp     x14, x15, [x4], #-16
    MULT_2_comba_ows    x12, x13, x14, x15, x6, x7, x9, x10, x22, x5, x5
    add     x11, x11, x22
    b       loop_high_even_in_sqcdw2
double_high_even_in_sqcdw2:
    lsl     x11, x11, #1
    orr     x11, x11, x10, lsr #63
    lsl     x10, x10, #1
    orr     x10, x10, x9, lsr #63
    lsl     x9, x9, #1
    orr     x9, x9, x7, lsr #63
    lsl     x7, x7, #1
    orr     x7, x7, x6, lsr #63
    lsl     x6, x6, #1              // acc *= 2
    b.ne    add_high_even_sqcdw2
middle_high_even_in_sqcdw2:
    ldp     x14, x15, [x3]
    SQ_2_comba_ows  x14, x15, x6, x7, x9, x10, x22, x12, x13
    add     x11, x11, x22           // acc +=
add_high_even_sqcdw2:               // acc += carry
    adds    x12, x6, x19
    adcs    x13, x7, x20
    adcs    x19, x9, x21
    adcs    x20, x10, xzr
    adc     x21, x11, xzr           // (x21,x20,x19) new carry
    cmp     x1, x2
    stp     x12, x13, [x0], #16
    b.ne    loop_high_even_sqcdw2
last_high_even_sqcdw2:
    SQ_2_rapid  x23, x24, x6, x7, x9, x10, x14, x15
    adds    x12, x6, x19
    adcs    x13, x7, x20
    adcs    x14, x9, x21
    adc     x15, x10, xzr
    stp     x12, x13, [x0], #16
    stp     x14, x15, [x0]
    b       ret_sqcdw2
# Odd case
# *x1 = a[0]
# *x2 = a[n-1]
# x23 = a[n-1] (single word size, so x24 is free)
loop_high_odd_sqcdw2:               // Loop for i=n-1,..,2n-1
    ldp     x14, x15, [x1], #16
    mov     x3, x1
    add     x4, x2, #-16
    mul     x6, x23, x14
    umulh   x7, x23, x14
    mul     x12, x23, x15
    umulh   x9, x23, x15
    adds    x7, x7, x12
    adc     x9, x9, xzr
    mov     x10, xzr 
    mov     x11, xzr                // (x11|x10,x9|x7,x6)   acc with first elem
loop_high_odd_in_sqcdw2:            // Loop for convolution
    cmp     x3, x4
    b.hs    double_high_odd_in_sqcdw2
    ldp     x12, x13, [x3], #16
    ldp     x14, x15, [x4], #-16
    MULT_2_comba_ows    x12, x13, x14, x15, x6, x7, x9, x10, x22, x5, x24
    add     x11, x11, x22
    b       loop_high_odd_in_sqcdw2
double_high_odd_in_sqcdw2:
    lsl     x11, x11, #1
    orr     x11, x11, x10, lsr #63
    lsl     x10, x10, #1
    orr     x10, x10, x9, lsr #63
    lsl     x9, x9, #1
    orr     x9, x9, x7, lsr #63
    lsl     x7, x7, #1
    orr     x7, x7, x6, lsr #63
    lsl     x6, x6, #1              // acc *= 2
    b.ne    add_high_odd_sqcdw2
middle_high_odd_in_sqcdw2:
    ldp     x14, x15, [x3]
    SQ_2_comba_ows  x14, x15, x6, x7, x9, x10, x22, x12, x13
    add     x11, x11, x22           // acc +=
add_high_odd_sqcdw2:                // acc += carry
    adds    x12, x6, x19
    adcs    x13, x7, x20
    adcs    x19, x9, x21
    adcs    x20, x10, xzr
    adc     x21, x11, xzr           // (x21,x20,x19) new carry
    cmp     x1, x2
    stp     x12, x13, [x0], #16
    b.ne    loop_high_odd_sqcdw2
last_high_odd_sqcdw2:
    mul     x9, x23, x23
    umulh   x10, x23, x23
    adds    x14, x19, x9
    adc     x15, x20, x10
    stp     x14, x15, [x0]
    b       ret_sqcdw2
ret_sqcdw2:
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x29, x30, [sp], #64
    ret                             // END m_impl_square

# Addition for Karatsuba
# int
# m_impl_add_karatsuba(unsigned char* aurp_dest,
#                      const unsigned char* aurp_a,
#                      const unsigned char* aurp_b,
#                      size_t szp_len)
.balign 16
m_impl_add_karatsuba:
_m_impl_add_karatsuba:
    lsr     w3, w3, #3              // byte2word
    lsr     w4, w3, #2              // [len/4]
    and     w5, w3, #3              // Mask 2 lowest bits
    adds    w6, wzr, wzr            // Clear carry
    cbz     w4, step_128_add_k
loop_256_add_k:
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x2], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    ldp     x12, x13, [x1], #16
    stp     x10, x11, [x0], #16
    ldp     x14, x15, [x2], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    sub     w4, w4, #1
    stp     x10, x11, [x0], #16
    cbnz    w4, loop_256_add_k
step_128_add_k:
    tbz     w5, #1, step_64_add_k
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x2], #16
    adcs    x10, x12, x14
    adcs    x11, x13, x15
    stp     x10, x11, [x0], #16
step_64_add_k:
    tbz     w5, #0, ret_add_k2
    ldr     x12, [x1]
    ldr     x14, [x2]
    adcs    x10, x12, x14
    str     x10, [x0]
ret_add_k2: 
    adc     x0, xzr, xzr            // Return carry over
    ret                             // END m_impl_add_karatsuba

# Subtraction for Karatsuba
# int
# m_impl_sub_karatsuba(unsigned char* aurp_dest,
#                      const unsigned char* aurp_a,
#                      const unsigned char* aurp_b,
#                      size_t szp_len);
.balign 16
m_impl_sub_karatsuba:
_m_impl_sub_karatsuba:
    lsr     w3, w3, #3              // byte2word
    lsr     w4, w3, #2              // [len/4]
    and     w5, w3, #3              // Mask 2 lowest bits
    subs    w6, wzr, wzr            // Clear carry
    cbz     w4, step_128_sub_k
loop_256_sub_k:
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x2], #16
    sbcs    x10, x12, x14
    sbcs    x11, x13, x15
    ldp     x12, x13, [x1], #16
    stp     x10, x11, [x0], #16
    ldp     x14, x15, [x2], #16
    sbcs    x10, x12, x14
    sbcs    x11, x13, x15
    sub     w4, w4, #1
    stp     x10, x11, [x0], #16
    cbnz    w4, loop_256_sub_k
step_128_sub_k:
    tbz     w5, #1, step_64_sub_k
    ldp     x12, x13, [x1], #16
    ldp     x14, x15, [x2], #16
    sbcs    x10, x12, x14
    sbcs    x11, x13, x15
    stp     x10, x11, [x0], #16
step_64_sub_k:
    tbz     w5, #0, ret_sub_k2
    ldr     x12, [x1]
    ldr     x14, [x2]
    sbcs    x10, x12, x14
    str     x10, [x0]
ret_sub_k2: 
    cset    w0, cc                  // Check if a<b
    ret                             // END m_impl_sub_karatsuba


# Add one word
# void
# m_impl_add_word(unsigned char* aurp_dest_a,
#                 LNUM_WORD up_b)
.balign 16
m_impl_add_word:
_m_impl_add_word:
    ldr     x15, [x0]
    adds    x14, x15, x1
    b.cc    ret_aw
loop_aw:                            // Infinit loop for carry handling
    ldr     x15, [x0]               // Load next word
    str     x14, [x0], #8           // Store prev result
    adcs    x14, x15, xzr
    b.cs    loop_aw
ret_aw:
    str     x14, [x0], #8           // Store last result
    ret                             // m_impl_add_word


# Comparison
# int
# m_impl_cmp(const unsigned char* aurp_a,
#            const unsigned char* aurp_b,
#            size_t szp_len)
.balign 16
m_impl_cmp:
_m_impl_cmp:
    lsr     w2, w2, #3              // byte2word
    add     x0, x0, x2, lsl #3
    add     x1, x1, x2, lsl #3      // Set pointers to the last positions
    cmp     wzr, wzr                // Clear carry
loop_cmp:                           // (128-bit unrolled loop)
    cbz     w2, ret_cmp             // Check if w2 = 0
    lsr     w6, w2, #1
    cbz     w6, step_cmp            // Check if w2 >= 2, otherwise w2 = 1
    ldp     x9, x10, [x0, #-16]!
    ldp     x11, x12, [x1, #-16]!
    cmp     x10, x12
    b.ne    ret_cmp
    cmp     x9, x11
    b.ne    ret_cmp
    sub     w2, w2, #2              // w2--
    b       loop_cmp                // END loop
step_cmp:
    ldr     x9, [x0, #-8]!          // Exstra step if w2 % 2 = 1
    ldr     x11, [x1, #-8]!
    cmp     x9, x11
ret_cmp:
    cset    w1, hi                  // Set 1 if a>b, 0 otherwise
    cset    w2, lo                  // Set 1 if a<b, 0 otherwise
    sub w0, w1, w2                  // w0 is -1, 0, or 1
    ret                             // m_impl_cmp


# MACROs for m_impl_sqr_8
# which work on [x10,x11,x12,x13] using [x14,x15] as temps
// (x13,x12,x11,x10) = reg*reg + (x13,x12)
.macro  SQADD_C    reg
    mul     x14, \reg, \reg
    umulh   x15, \reg, \reg
    adds    x10, x14, x12
    adcs    x11, x15, x13
    adc     x12, xzr, xzr
    mov     x13, xzr
.endm
// (x12,x11,x10) += 2*reg1*reg2
.macro  MADD_C2_10    reg1, reg2
    mul     x14, \reg1, \reg2
    umulh   x15, \reg1, \reg2
    adds    x10, x10, x14, lsl #1
    add     x12, x12, x15, lsr #63
    lsl     x15, x15, #1
    orr     x15, x15, x14, lsr #63
    adcs    x11, x11, x15
    adc     x12, x12, xzr
.endm
// (x13,x12,x11) += 2*reg1*reg2
.macro  MADD_C2_11    reg1, reg2
    mul     x14, \reg1, \reg2
    umulh   x15, \reg1, \reg2
    adds    x11, x11, x14, lsl #1
    add     x13, x13, x15, lsr #63
    lsl     x15, x15, #1
    orr     x15, x15, x14, lsr #63
    adcs    x12, x12, x15
    adc     x13, x13, xzr
.endm
 
# 8 words squaring
# void
# m_impl_sqr_8(LNUM_WORD* aurp_dest, const LNUM_WORD* aurp_src)
# Simple Comba's algorithm
.balign 16
m_impl_sqr_8:
_m_impl_sqr_8:
    mov         x9, x0
    mov         x10, x1
    ldp         x0, x1, [x10], #16
    ldp         x2, x3, [x10], #16
    ldp         x4, x5, [x10], #16
    ldp         x6, x7, [x10], #16      // src is loaded on (x7,...,x0)
    mov         x12, xzr                // Set carry (x13,x12)=0
    mov         x13, xzr
//dest[0] and dest[1]
    SQADD_C     x0
    MADD_C2_11  x0, x1
    stp         x10, x11, [x9], #16
//dest[2] and dest[3]
    SQADD_C     x1
    MADD_C2_10  x0, x2
    MADD_C2_11  x0, x3
    MADD_C2_11  x1, x2
    stp         x10, x11, [x9], #16
//dest[4] and dest[5]
    SQADD_C     x2
    MADD_C2_10  x0, x4
    MADD_C2_10  x1, x3
    MADD_C2_11  x0, x5
    MADD_C2_11  x1, x4
    MADD_C2_11  x2, x3
    stp         x10, x11, [x9], #16
//dest[6] and dest[7]
    SQADD_C     x3
    MADD_C2_10  x0, x6
    MADD_C2_10  x1, x5
    MADD_C2_10  x2, x4
    MADD_C2_11  x0, x7
    MADD_C2_11  x1, x6
    MADD_C2_11  x2, x5
    MADD_C2_11  x3, x4
    stp         x10, x11, [x9], #16
//dest[8] and dest[9]
    SQADD_C     x4
    MADD_C2_10  x1, x7
    MADD_C2_10  x2, x6
    MADD_C2_10  x3, x5
    MADD_C2_11  x2, x7
    MADD_C2_11  x3, x6
    MADD_C2_11  x4, x5
    stp         x10, x11, [x9], #16
//dest[10] and dest[11]
    SQADD_C     x5
    MADD_C2_10  x3, x7
    MADD_C2_10  x4, x6
    MADD_C2_11  x4, x7
    MADD_C2_11  x5, x6
    stp         x10, x11, [x9], #16
//dest[12] and dest[13]
    SQADD_C     x6
    MADD_C2_10  x5, x7
    MADD_C2_11  x6, x7
    stp         x10, x11, [x9], #16
//dest[14] and dest[15]
    SQADD_C     x7
    stp         x10, x11, [x9], #16
    ret                                     // END m_impl_sqr_8

# Helper function for montgomery reduction
# void
# m_impl_mont_mul_add(unsigned char* aurp_dest,
#                     LNUM_WORD urp_n_0_inv,
#                     const unsigned char* aurp_mod,
#                     size_t szp_mod_len,
#                     const unsigned char* aurp_src)
# Algorithm: Comba method
# A 2-words based extension (i.e. computing 2 colums at the same time) of Algorithm 3 of
# New Speed Records for Montgomery Modular Multiplication on 8-bit AVR Microcontrollers
# by Zhe Liu and Johann Groessschaedl
.balign 16
m_impl_mont_mul_add:
_m_impl_mont_mul_add:
    cmp     w3, #64
    b.eq    ms_mont_mul_add_8       // Unrolled implementation for s=8
    ands    w9, w3, #63
    b.eq    ms_mont_mul_add_os8     // Special case s%8=0
    add     x0, x0, x3              // Adjust dst addr
    lsr     w3, w3, #3              // byte2word
    subs    w3, w3, #1              // s-1
    b.eq    s_1_mma                 // Special case s=1
    stp     x19, x20, [sp, #-80]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x27, x28, [sp, #64]
    ldp     x27, x28, [x2]          // m[0],m[1]
    // add src
    ldp     x9, x10, [x4], #16
    mul     x14, x9, x1             // z[0]
    // z[0]*(m[1],m[0])
    umulh   x6, x14, x27
    mul     x19, x14, x28
    umulh   x7, x14, x28
    adds    x6, x6, x19
    adc     x7, x7, xzr             // result in (x7,x6,x5)
    // accumulate 
    cmp     x9, #1                  // Set carry flag from x14*x27+x9
    adcs    x10, x10, x6
    adcs    x11, xzr, x7
    adc     x12, xzr, xzr           // (x12,x11|x10,x9) Accumulator
    mul     x15, x10, x1            // z[1]
    // z1*m[0]
    umulh   x6, x15, x27
    // accumulate
    cmp     x10, #1                 // Set carry flag from x15*x27+x10
    adcs    x9, x11, x6
    adc     x10, x12, xzr
    mov     x11, xzr
    mov     x12, xzr                // new carry
    stp     x14, x15, [x0]
    mov     w24, #2                 // ctr i=2,4,6,..
    cmp     w3, w24 
    b.lo    begin_shrinking_mma     // Special case s=2
    b.eq    xtr_columns_mma         // Special case s=3
loop_growing_outer_mma:
    sub     w15, w24, #2
    add     x5, x0, x15, lsl #3     // &z[i-2]
    add     x6, x2, #16             // &m[2]
    mov     x7, x28                 // Cache m[1]
    lsr     w13, w24, #1            // inner loop counter
loop_growing_inner_mma:
    ldp     x14, x15, [x5], #-16    // z1,z2
    ldp     x20, x21, [x6], #16     // m1,m2
    // z2*(m1,cache)
    mul     x19, x15, x7
    umulh   x7, x15, x7
    mul     x22, x15, x20
    umulh   x15, x15, x20
    adds    x7, x7, x22
    adc     x15, x15, xzr           // result in (x15,x7,x19)
    // z1*(m2,m1)
    mul     x22, x14, x20
    umulh   x20, x14, x20
    mul     x23, x14, x21
    umulh   x14, x14, x21
    adds    x20, x20, x23
    adc     x14, x14, xzr           // result in (x14,x20,x22)
    // combine
    adds    x19, x19, x22
    adcs    x20, x7, x20
    adcs    x15, x15, x14           // result in (x15,x20,x19)
    // accumulate
    adc     x12, x12, xzr
    adds    x9, x9, x19
    adcs    x10, x10, x20
    adcs    x11, x11, x15
    adc     x12, x12, xzr
    mov     x7, x21                 // Cache m2
    subs    w13, w13, #1
    b.ne    loop_growing_inner_mma  // END loop_growing_inner
calc_z_mma:
    // add src
    ldp     x14, x15, [x4], #16
    adds    x9, x9, x14
    adcs    x10, x10, x15
    adcs    x11, x11, xzr
    adc     x12, x12, xzr
    mul     x14, x9, x1             // z[i]
    // z0*(m[1],m[0])
    umulh   x6, x14, x27
    mul     x19, x14, x28
    umulh   x7, x14, x28
    adds    x6, x6, x19
    adc     x7, x7, xzr             // result in (x7,x6,x5)
    // accumulate
    cmp     x9, #1                  // Set carry flag from x14*x27+x9
    adcs    x10, x10, x6
    adcs    x11, x11, x7
    adc     x12, x12, xzr
    mul     x15, x10, x1            // z[i+1]
    // z1*m[0]
    umulh   x6, x15, x27
    // accumulate
    cmp     x10, #1                 // cmp used as above
    adcs    x9, x11, x6
    adc     x10, x12, xzr
    mov     x11, xzr
    mov     x12, xzr                // new carry
    add     x5, x0, x24, lsl #3
    stp     x14, x15, [x5]          // Store z[i],z[i+1]
    add     w24, w24, #2
    cmp     w24, w3
    b.lo    loop_growing_outer_mma
// s even, no extra loop
    b.ne    begin_shrinking_mma
// s odd, extra mid-loop
xtr_columns_mma:
    mov     x7, xzr                 // Cache 0
    mov     x5, x0                  // &z[0]
    lsl     w21, w3, #3             // 8*(s-1), unner loop counter
loop_xtr_inner_mma:
    ldr     x14, [x5], #8           // z
    ldr     x15, [x2, x21]          // m
// z*(cache,m)
    mul     x19, x14, x7
    umulh   x20, x14, x7
    mul     x6, x14, x15
    umulh   x7, x14, x15
    adds    x19, x19, x7
    adcs    x20, x20, xzr           // result in (x20,x19,x6)
// accumulate
    adds    x9, x9, x6
    adcs    x10, x10, x19
    adcs    x11, x11, x20
    adc     x12, x12, xzr
    mov     x7, x15                 // Cache m
    subs    w21, w21, #8
    b.hi    loop_xtr_inner_mma      // END loop_xtr_inner
// add src
    ldp     x14, x15, [x4], #16
    adds    x9, x9, x14
    adcs    x10, x10, x15
    adcs    x11, x11, xzr
    adc     x12, x12, xzr
// z[s-1]
    mul     x13, x9, x1             // z[s-1]
    str     x13, [x5]
// += z[s-1]*(m[1],[m0])
    mul     x19, x13, x28
    umulh   x20, x13, x28
    umulh   x7, x13, x27
    adds    x19, x19, x7
    adcs    x20, x20, xzr           // result in (x20,x19,x6)
    cmp     x9, #1                  // Set carry flag from x13*x27+x9
    adcs    x7, x10, x19
    str     x7, [x0], #8
    adcs    x9, x11, x20
    adc     x10, x12, xzr
    mov     x11, xzr
    mov     x12, xzr                // Set carry in (x12,x11|x10,x9)
// x0   &dst[(s%2)]
// x2   &m[0]
// w3   s-1
// x4   &src[s+(s%2)]
// (x12,x11|x10,x9) Accumulator containing carry
// z[(s%2)],...,z[s-1] are stored in dst[(s%2)],...,dst[s-1]
// If s%2 == 1, dst[0] is already done
begin_shrinking_mma:
    add     x2, x2, x3, lsl #3      // x2   &m[s-1]
    ldr     x1, [x2], #-16          // x1   m[s-1]
    sub     w3, w3, #1
    lsr     w3, w3, #1              // w3 >= 0 is the length of hybrid_loop
    cbz     w3, last_two_mma
loop_shrinking_outer_mma:
    add     x5, x0, #8              // &z[i]
    mov     x6, x2                  // &m[s-1]
    mov     x7, x1                  // Cache m[s-1]
    ldr     x13, [x5], #8
    mul     x14, x13, x7
    umulh   x15, x13, x7
    adds    x9, x9, x14
    adcs    x10, x10, x15
    adc     x11, x11, xzr
    mov     x12, xzr                // (x12,x11|x10,x9)
    mov     w13, w3                 // inner loop counter
loop_shrinking_inner_mma:
    ldp     x14, x15, [x5], #16     // z
    ldp     x20, x21, [x6], #-16    // m
// z1*(cache,m2)
    mul     x19, x14, x7
    umulh   x7, x14, x7
    mul     x22, x14, x21
    umulh   x14, x14, x21
    adds    x14, x14, x19
    adc     x7, x7, xzr             // result in (x7,x14,x22)
// z2*(m2,m1)
    mul     x19, x15, x20
    umulh   x23, x15, x20
    mul     x24, x15, x21
    umulh   x15, x15, x21
    adds    x23, x23, x24
    adc     x15, x15, xzr           // result in (x15,x23,x19)
// combine
    adds    x22, x22, x19
    adcs    x14, x14, x23
    adcs    x15, x15, x7
    adc     x12, x12, xzr
// accumulate
    adds    x9, x9, x22
    adcs    x10, x10, x14
    adcs    x11, x11, x15
    adc     x12, x12, xzr
    mov     x7, x20                 // Cache m1
    subs    w13, w13, #1
    b.ne    loop_shrinking_inner_mma // END loop_shrinking_inner
// add src
    ldp     x14, x15, [x4], #16
    adds    x14, x14, x9 
    adcs    x15, x15, x10
    adcs    x9, x11, xzr
    adc     x10, x12, xzr
    mov     x11, xzr                // New carry in (x11|x10,x9)
    stp     x14, x15, [x0], #16
    subs    w3, w3, #1
    b.ne    loop_shrinking_outer_mma
// Very last step
last_two_mma:
    ldr     x13, [x0, #8]
    ldp     x14, x15, [x4]
    mul     x6, x13, x1
    umulh   x7, x13, x1
    adds    x9, x9, x6
    adcs    x10, x10, x7
    adc     x11, x11, xzr
    adds    x9, x9, x14 
    adcs    x10, x10, x15
    adc     x11, x11, xzr
    stp     x9, x10, [x0]
    str     x11, [x0, #16]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x27, x28, [sp, #64]
    ldp     x19, x20, [sp], #80
    ret
// Special case s=1
s_1_mma:
    ldr     x7, [x2]                // m[0]
    ldp     x9, x10, [x4]           // p[0],p[1]
    mul     x5, x9, x1              // z[0]
    mul     x13, x5, x7
    umulh   x14, x5, x7
    adds    x13, x13, x9
    adcs    x14, x14, x10
    adc     x15, xzr, xzr
    stp     x14, x15, [x0]
    ret


# size_t m_impl_first_bit(LNUM_WORD urp_word)
.balign 16
m_impl_first_bit:
_m_impl_first_bit:
    rbit    x0, x0
    clz     x0, x0
    ret


# size_t m_impl_last_bit(LNUM_WORD urp_word)
.balign 16
m_impl_last_bit:
_m_impl_last_bit:
    clz     x0, x0
    eor     w0, w0, #63
    ret


# 8 words version of m_impl_mont_mul_add
# x0    dst
# x1    n0
# x2    m
# x4    src
# We call: m=(m7,..,m0), src=(p15,..,p0) and result=(r7,..,r0)
.balign 16
ms_mont_mul_add_8:
    add         x0, x0, #64             // Adjust dst pos
    ldp         x10, x11, [x2]          // m0,m1
    stp         x20, x21, [sp, #-64]!
    ldp         x12, x13, [x2, #16]     // m2,m3
    stp         x22, x23, [sp, #16]
    ldp         x14, x15, [x2, #32]     // m4,m5
    stp         x24, x25, [sp, #32]
    ldp         x6 , x7 , [x2, #48]     // m6,m7
    stp         x26, x27, [sp, #48]
    ldp         x22, x23, [x4], #16     // p0,p1
    ldp         x24, x25, [x4], #16     // p2,p3
# z0
    mul         x20, x22, x1
# += z0*(m1,m0)
    mul         x26, x20, x10
    umulh       x27, x20, x10
    adds        x2, x26, x22
    adcs        x3, x27, x23
    mul         x5, x20, x11
    umulh       x9, x20, x11
    adc         x9, x9, xzr
    adds        x3, x3, x5
    adc         x5, x9, xzr
# z1
    mul         x21, x3, x1
# += z1*m0
    mul         x26, x21, x10
    umulh       x27, x21, x10
    adds        x26, x3, x26
    adcs        x2, x5, x27
    adc         x3, xzr, xzr            // (x3,x2) carry
# += (p3,p2)
    adds        x2, x2, x24
    adcs        x3, x3, x25
    adc         x5, xzr, xzr            // (x9,x5|x3,x2) acc
# += z0*(m3,m2)
    MADD_1_2s   x20, x12, x13, x2, x3, x5, x26, x27
    adc         x9, xzr, xzr
# += z1*(m2,m1)
    MADD_1_2s   x21, x11, x12, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# z2
    mul         x22, x2, x1
# += z2*(m1,m0)
    MADD_1_2s   x22, x10, x11, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# z3
    mul         x23, x3, x1
# += z3*m0
    mul         x26, x23, x10
    umulh       x27, x23, x10
    adds        x26, x3, x26
    adcs        x2, x5, x27
    adc         x3, x9, xzr             // (x3,x2) carry
# += (p5,p4)
    ldp         x26, x27, [x4], #16
    adds        x2, x2, x26
    adcs        x3, x3, x27
    adc         x5, xzr, xzr            // (x9,x5|x3,x2) acc
# += z0*(m5,m4)
    MADD_1_2s   x20, x14, x15, x2, x3, x5, x26, x27
    adc         x9, xzr, xzr
# += z1*(m4,m3)
    MADD_1_2s   x21, x13, x14, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z2*(m3,m2)
    MADD_1_2s   x22, x12, x13, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z3*(m2,m1)
    MADD_1_2s   x23, x11, x12, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# z4
    mul         x24, x2, x1
# += z4*(m1,m0)
    MADD_1_2s   x24, x10, x11, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# z5
    mul         x25, x3, x1
# += z5*m0
    mul         x26, x25, x10
    umulh       x27, x25, x10
    adds        x26, x3, x26
    adcs        x2, x5, x27
    adc         x3, x9, xzr             // (x3,x2) carry
# += (p7,p6)
    ldp         x26, x27, [x4], #16
    adds        x2, x2, x26
    adcs        x3, x3, x27
    adc         x5, xzr, xzr            // (x9,x5|x3,x2) acc
# += z0*(m7,m6)
    MADD_1_2s   x20, x6, x7, x2, x3, x5, x26, x27
    adc         x9, xzr, xzr
# += z1*(m6,m5)
    MADD_1_2s   x21, x15, x6, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z2*(m5,m4)
    MADD_1_2s   x22, x14, x15, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z3*(m4,m3)
    MADD_1_2s   x23, x13, x14, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z4*(m3,m2)
    MADD_1_2s   x24, x12, x13, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# += z5*(m2,m1)
    MADD_1_2s   x25, x11, x12, x2, x3, x5, x26, x27
    adc         x9, x9, xzr
# z6
    mul         x26, x2, x1
# += z6*(m1,m0)
    MADD_1_2s   x26, x10, x11, x2, x3, x5, x20, x27
    adc         x9, x9, xzr
# z7
    mul         x27, x3, x1
# += z7*m0
    mul         x20, x27, x10
    umulh       x1, x27, x10
    adds        x20, x3, x20
    adcs        x2, x5, x1
    adc         x3, x9, xzr             // (x3,x2) carry
#### Register status ####
# x0                dst
# x4                src
# x11-x15,x6,x7     m1-m7
# x21-x27           z1-z7
# (x3,x2)           carry
############################
# += (p9,p8)
    ldp         x9, x10, [x4], #16
    adds        x2, x2, x9
    adcs        x3, x3, x10
    adc         x9, xzr, xzr            // (x10,X9|x3,x2) acc       
# += z7*(m2,m1)
    MADD_1_2s   x27, x11, x12, x2, x3, x9, x1, x5
    adc         x10, xzr, xzr
# += z6*(m3,m2)
    MADD_1_2s   x26, x12, x13, x2, x3, x9, x1, x5
    adc         x10, x10, xzr
# += z5*(m4,m3)
    MADD_1_2s   x25, x13, x14, x2, x3, x9, x1, x5
    adc         x10, x10, xzr
# += z4*(m5,m4)
    MADD_1_2s   x24, x14, x15, x2, x3, x9, x1, x5
    adc         x10, x10, xzr
# += z3*(m6,m5)
    MADD_1_2s   x23, x15, x6, x2, x3, x9, x1, x5
    adc         x10, x10, xzr
# += z2*(m7,m6)
    MADD_1_2s   x22, x6, x7, x2, x3, x9, x1, x5
    adc         x10, x10, xzr
# += z1*m7
    mul         x1, x21, x7
    umulh       x5, x21, x7
    adds        x1, x2, x1
    adcs        x11, x3, x5             // x1,x11  r0,r1
# += (p11,p10)
    ldp         x21, x22, [x4], #16
    adcs        x2, x9, x21
    adcs        x3, x10, x22
    adc         x9, xzr, xzr            // (x10,x9|x3,x2) acc
# += z7*(m4,m3)
    MADD_1_2s   x27, x13, x14, x2, x3, x9, x21, x22
    adc         x10, xzr, xzr
# += z6*(m5,m4)
    MADD_1_2s   x26, x14, x15, x2, x3, x9, x21, x22
    adc         x10, x10, xzr
# += z5*(m6,m5)
    MADD_1_2s   x25, x15, x6, x2, x3, x9, x21, x22
    adc         x10, x10, xzr
# += z4*(m7,m6)
    MADD_1_2s   x24, x6, x7, x2, x3, x9, x21, x22
    adc         x10, x10, xzr
# += z3*m7
    mul         x21, x23, x7
    umulh       x22, x23, x7
    adds        x12, x2, x21
    adcs        x13, x3, x22            // x12,x13  r2,r3
# += (p13,p12)
    ldp         x21, x22, [x4]
    ldp         x23, x24, [x4, #16]     // p14,x15 for later use
    adcs        x2, x9, x21
    adcs        x3, x10, x22
    adc         x9, xzr, xzr            // (x10,x9|x3,x2) acc
# += z7*(m6,m5)
    MADD_1_2s   x27, x15, x6, x2, x3, x9, x21, x22
    adc         x10, xzr, xzr
# += z6*(m7,m6)
    MADD_1_2s   x26, x6, x7, x2, x3, x9, x21, x22
    adc         x10, x10, xzr
# += z5*m7
    mul         x21, x25, x7
    umulh       x22, x25, x7
    adds        x14, x2, x21
    adcs        x15, x3, x22            // x14,x15  r4,r5
# += (p15,p14)
    adcs        x2, x9, x23
    adcs        x3, x10, x24
    adc         x9, xzr, xzr            // (x9,x3|x2) acc
# += z7*m7
    mul         x21, x27, x7
    umulh       x22, x27, x7
    adds        x6, x2, x21
    adcs        x7, x3, x22             // x6,x7  r6,r7
    adc         x9, x9, xzr             // x9       last carry
    stp         x1 , x11, [x0]          // r0,r1
    ldp         x20, x21, [sp], #16
    stp         x12, x13, [x0, #16]     // r2,r3
    ldp         x22, x23, [sp], #16
    stp         x14, x15, [x0, #32]     // r4,r5
    ldp         x24, x25, [sp], #16
    stp         x6 , x7 , [x0, #48]     // r6,r7
    ldp         x26, x27, [sp], #16
    str         x9 , [x0, #64]
    ret

# Calculates (c7,...,c0) += (c7,...,c1)+a0*(b6,...,b0)+d0
# d0 will be discarded
.macro  MADd_1_7 a0,b0,b1,b2,b3,b4,b5,b6,c0,c1,c2,c3,c4,c5,c6,c7,d0,tp
    adds    \c0, \c1, \d0
    mul     \d0, \a0, \b1
    umulh   \tp, \a0, \b1
    adcs    \c1, \c2, \d0
    adcs    \c2, \c3, \tp
    mul     \d0, \a0, \b3
    umulh   \tp, \a0, \b3
    adcs    \c3, \c4, \d0
    adcs    \c4, \c5, \tp
    mul     \d0, \a0, \b5
    umulh   \tp, \a0, \b5
    adcs    \c5, \c6, \d0
    adcs    \c6, \c7, \tp
    adc     \c7, xzr, xzr
    mul     \d0, \a0, \b0
    umulh   \tp, \a0, \b0
    adds    \c0, \c0, \d0
    adcs    \c1, \c1, \tp
    mul     \d0, \a0, \b2
    umulh   \tp, \a0, \b2
    adcs    \c2, \c2, \d0
    adcs    \c3, \c3, \tp
    mul     \d0, \a0, \b4
    umulh   \tp, \a0, \b4
    adcs    \c4, \c4, \d0
    adcs    \c5, \c5, \tp
    mul     \d0, \a0, \b6
    umulh   \tp, \a0, \b6
    adcs    \c6, \c6, \d0
    adc     \c7, \c7, \tp
.endm

# Calculates (c7,...,c0,pop)=(c7,..,c0)+a0*(b7,..,b0)
.macro  MADr_1_8 a0,b0,b1,b2,b3,b4,b5,b6,b7,c0,c1,c2,c3,c4,c5,c6,c7,tp,tp2,pop
    mul     \tp , \a0, \b0
    adds    \pop, \c0, \tp
    umulh   \tp2, \a0, \b0
    adc     \tp2, \tp2, xzr
    MADd_1_7    \a0,\b1,\b2,\b3,\b4,\b5,\b6,\b7,\c0,\c1,\c2,\c3,\c4,\c5,\c6,\c7,\tp2,\tp
.endm

# Calculates the same as MADr_1_8 but pop is not generated
# Works only under the special condition that pop is 0
.macro  MADr_1_8_zr  a0,b0,b1,b2,b3,b4,b5,b6,b7,c0,c1,c2,c3,c4,c5,c6,c7,tp,tp2
    cmp     \c0, #1
    umulh   \tp2, \a0, \b0
    adc     \tp2, \tp2, xzr
    MADd_1_7    \a0,\b1,\b2,\b3,\b4,\b5,\b6,\b7,\c0,\c1,\c2,\c3,\c4,\c5,\c6,\c7,\tp2,\tp
.endm

# Calculates (c7,..,c0)+=(a1,a0)
.macro  ADD_2_8 a0,a1,c0,c1,c2,c3,c4,c5,c6,c7
    adds    \c0, \c0, \a0
    adcs    \c1, \c1, \a1
    adcs    \c2, \c2, xzr
    adcs    \c3, \c3, xzr
    adcs    \c4, \c4, xzr
    adcs    \c5, \c5, xzr
    adcs    \c6, \c6, xzr
    adc     \c7, \c7, xzr
.endm

# x0    dst
# x1    n0
# x2    mod
# x3    mod_len
# x4    src
# Algorithm 1 of dev_doc with b=8
# Works only when WORD_len % 8 == 0
.balign 16
ms_mont_mul_add_os8:
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    lsr     w3, w3, #6              //mod_len related to blocks
// Copy first half of src into dst (to free x4)
    mov     x5, x0
    mov     w6, w3
loop_cp_mmaos8:
    ldp     x9, x10, [x4]
    stp     x9, x10, [x5]
    ldp     x11, x12, [x4, #16]
    stp     x11, x12, [x5, #16]
    ldp     x13, x14, [x4, #32]
    stp     x13, x14, [x5, #32]
    subs    w6, w6, #1
    ldp     x19, x20, [x4, #48]
    stp     x19, x20, [x5, #48]
    add     x4, x4, #64
    add     x5, x5, #64
    b.ne    loop_cp_mmaos8
    mov     x30, x4                 // x30 second half of src
    sub     w6, w3, #1
    mov     v0.S[0], w6             // Inner loop size = mod_len - 1
## Important remark ##################################################
# In the following, x3 contains two values as x3=(t|outer_ctr), i.e.
# the most significant 4 bits are the special carry t (which is 0 or 1, see dev_doc)
######################################################################
loop_outer_mmaos8:
// (x6,x15,x14,x13,x12,x11,x10,x9)      P_cur
// (x26,x25,x24,x23,x22,x21,x20,x19)    m values
    ldp     x19, x20, [x2]
    ldp     x21, x22, [x2, #16]
    ldp     x23, x24, [x2, #32]
    ldp     x25, x26, [x2, #48]
    add     x2, x2, #64
    mov     x11, xzr
    mov     x12, xzr
    mov     x13, xzr
    mov     x14, xzr
    mov     x15, xzr
    mov     x6, xzr
# Q generation (unrolled) loop, where z here is Q in dev_doc
// P_cur = (p0,p1)
    ldp         x9, x10, [x0]
// z0
    mul         x7, x9, x1
// P_cur = (P_cur + z0*(m7,..,m0))>>64
    MADr_1_8_zr x7, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x27, x28
// z1
    mul         x8, x9, x1
// P_cur = (P_cur + z1*(m7,..,m0))>>64
    MADr_1_8_zr x8, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x27, x28
.set    offset, 16
.rept   3
// P_cur += (p0,p1)
    ldp         x4, x5, [x0, #offset]
    ADD_2_8     x4, x5, x9, x10, x11, x12, x13, x14, x15, x6
// z0
    mul         x27, x9, x1
// P_cur = (P_cur + z0*(m7,..,m0))>>64
    MADr_1_8    x27, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x29, x5
// z1
    mul         x28, x9, x1
// P_cur = (P_cur + z1*(m7,..,m0))>>64
    MADr_1_8    x28, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x29, x5
    stp         x27, x28, [x0, #offset]
.set    offset, offset+16
.endr
    mov         x19, x7
    mov         x20, x8
    ldp         x21, x22, [x0, #16]
    ldp         x23, x24, [x0, #32]
    ldp         x25, x26, [x0, #48]
    add         x0, x0, #64
// (x26,x25,x24,x23,x22,x21,x20,x19) z
    mov         w7, v0.S[0]     // ctr_inner = mod_len - 1
loop_inner_mmaos8:
// P_cur += (p0,p1)
    ldp         x27, x28, [x0]
    ADD_2_8     x27, x28, x9, x10, x11, x12, x13, x14, x15, x6
// (P_cur,x29) = P_cur + m0*(z7,..,z0)
    ldp         x27, x28, [x2], #16
    MADr_1_8    x27, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x29
// (P_cur,x27) = P_cur + m1*(z7,..,z0)
    MADr_1_8    x28, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x27
    stp         x29, x27, [x0], #16
// P_cur += (p2,p3)
    ldp         x27, x28, [x0]
    ADD_2_8     x27, x28, x9, x10, x11, x12, x13, x14, x15, x6
// (P_cur,x29) = P_cur + m2*(z7,..,z0)
    ldp         x27, x28, [x2], #16
    MADr_1_8    x27, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x29
// (P_cur,x27) = P_cur + m3*(z7,..,z0)
    MADr_1_8    x28, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x27
    stp         x29, x27, [x0], #16
// P_cur += (p4,p5)
    ldp         x27, x28, [x0]
    ADD_2_8     x27, x28, x9, x10, x11, x12, x13, x14, x15, x6
// (P_cur,x29) = P_cur + m4*(z7,..,z0)
    ldp         x27, x28, [x2], #16
    MADr_1_8    x27, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x29
// (P_cur,x27) = P_cur + m5*(z7,..,z0)
    MADr_1_8    x28, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x27
    stp         x29, x27, [x0], #16
// P_cur += (p6,p7)
    ldp         x27, x28, [x0]
    ADD_2_8     x27, x28, x9, x10, x11, x12, x13, x14, x15, x6
// (P_cur,x29) = P_cur + m6*(z7,..,z0)
    ldp         x27, x28, [x2], #16
    MADr_1_8    x27, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x29
// (P_cur,x27) = P_cur + m7*(z7,..,z0)
    MADr_1_8    x28, x19, x20, x21, x22, x23, x24, x25, x26, x9, x10, x11, x12, x13, x14, x15, x6, x4, x5, x27
    stp         x29, x27, [x0], #16
    subs        w7, w7, #1
    b.ne        loop_inner_mmaos8
// (x6,x15,x14,x13,x12,x11,x10,x9) P_curr
    adds        x9, x9, x3, lsr #60   // Add last carry(i.e. P_cur += t) from prev
    adcs        x10, x10, xzr
    adcs        x11, x11, xzr
    adcs        x12, x12, xzr
    adcs        x13, x13, xzr
    adcs        x14, x14, xzr
    adcs        x15, x15, xzr
    adc         x6, x6, xzr
    ldp         x19, x20, [x30]
    ldp         x21, x22, [x30, #16]
    ldp         x23, x24, [x30, #32]
    ldp         x25, x26, [x30, #48]    // Load src=(p7,..,p0)
    add         x30, x30, #64
// P_cur += src
    adds        x19, x19, x9
    adcs        x20, x20, x10
    adcs        x21, x21, x11
    adcs        x22, x22, x12
    adcs        x23, x23, x13
    adcs        x24, x24, x14
    adcs        x25, x25, x15
    adcs        x26, x26, x6
    adc         x29, xzr, xzr           // Last carry out t
    stp         x19, x20, [x0]
    stp         x21, x22, [x0, #16]
    stp         x23, x24, [x0, #32]
    stp         x25, x26, [x0, #48]     // Store result
    bfi         x3, xzr, #60, #1        // Clear old t
    orr         x3, x3, x29, lsl #60    // Set new t for the next round
    mov         w13, v0.S[0]
    sub         x0, x0, x13, lsl #6
    add         w12, w13, #1
    sub         x2, x2, x12, lsl #6     // Set new positions
    sub         x3, x3, #1              // outer_ctr--
    cbnz        w3, loop_outer_mmaos8
    add         x0, x0, x13, lsl #6
    str         x29, [x0, #64]          // Store last carry out t
    ldp         x21, x22, [sp, #16]
    ldp         x23, x24, [sp, #32]
    ldp         x25, x26, [sp, #48]
    ldp         x27, x28, [sp, #64]
    ldp         x29, x30, [sp, #80]
    ldp         x19, x20, [sp], #96
    ret
 
//-----------------------------------------------------------
// AES functions
//-----------------------------------------------------------

#ifdef __APPLE__
#define LDADR  APPLELDADR
#else
#define LDADR  LINUXLDADR
#endif

#define AESE AESE3
#define AESMC AESMC3
#define AESD AESD3
#define AESIMC AESIMC3
#define XORKEY XORKEY3
#define CMP CMP3
#define SUBS SUBS3
#define SUB SUB3

.macro  LINUXLDADR register, label
    adr     \register, \label
.endm

.macro  APPLELDADR register, label
    adrp    \register, \label@PAGE
    add     \register, \register, \label@PAGEOFF
.endm

.macro	AESE3	key
	aese	v0.16b, \key
	aese 	v1.16b, \key
	aese	v2.16b, \key
.endm

.macro	AESMC3
	aesmc	v0.16b, v0.16b
	aesmc 	v1.16b, v1.16b
	aesmc	v2.16b, v2.16b
.endm

.macro	AESD3	key
	aesd	v0.16b, \key
	aesd 	v1.16b, \key
	aesd	v2.16b, \key
.endm

.macro	AESIMC3
	aesimc	v0.16b, v0.16b
	aesimc 	v1.16b, v1.16b
	aesimc	v2.16b, v2.16b
.endm

.macro	XORKEY3	key
	eor		v0.16b, v0.16b, \key
	eor 	v1.16b, v1.16b, \key
	eor		v2.16b, v2.16b, \key
.endm

.macro  CMP3 register
    cmp     \register, #3
.endm

.macro  SUB3 register
    sub     \register, \register, #3
.endm

.macro  SUBS3 register
    subs    \register, \register, #3
.endm

.macro  SUBS1 register
    subs    \register, \register, #1
.endm

.macro	AESE1	key
	aese	v0.16b, \key
.endm

.macro	AESMC1
	aesmc	v0.16b, v0.16b
.endm

.macro	AESD1	key
	aesd	v0.16b, \key
.endm

.macro	AESIMC1
	aesimc	v0.16b, v0.16b
.endm

.macro	XORKEY1	key
	eor		v0.16b, v0.16b, \key
.endm

.macro	AESE1v31	key
	aese	v31.16b, \key
.endm

.macro	AESMC1v31
	aesmc	v31.16b, v31.16b
.endm

.macro	XORKEY1v31	key
	eor		v31.16b, v31.16b, \key
.endm

.macro GCM_GHASH register
    // Performs a Galois Field polynomial multiplication
    // See Algorithm 5 in whitepaper:
    // Intel Carry-Less Multiplication and its Usage for Computing the GCM Mode
    // Shay Gueron, Michael E. Kounavis, Revision 2.02, April 2014, 323640-002
    //Input: \register Value 1, any-endian
    //Input: v31 Value 2, big-endian
    //Input: v15 Value 2, big-endian, low/high reversed
    //Input: v14 all-zero constant
    //Uses v8-v12 as intermediate values
    //Returns result in \register

#ifndef HL_BIG_ENDIAN
    rev64   v12.16b, \register
    ext     v12.16b, v12.16b, v12.16b, #8
#else
    mov     v12.16b, \register
#endif

    pmull   v8.1q, v12.1d, v15.1d            //low p* high
    pmull2  v9.1q, v12.2d, v15.2d            //high p* low
    pmull   v10.1q, v12.1d, v31.1d           //low p* low
    pmull2  v11.1q, v12.2d, v31.2d           //high p* high
    eor     v8.16b, v8.16b, v9.16b
    ext     v9.16b, v14.16b, v8.16b, #8      //high 8 from v14={0} as low, low 8 from v8 as high  ->00:00:w0:w1
    ext     v8.16b, v8.16b, v14.16b, #8      //high 8 from v8 as low, low 8 from v14={0} as high  ->w2:w3:00:00
    eor     v10.16b, v10.16b, v9.16b        //low   [X1:X0]
    eor     v11.16b, v11.16b, v8.16b        //high  [X3:X2]
    //v10, v11: carryless-multiplied

    //shift left vector pair
    shl    v8.2d, v10.2d, #1
    shl    v9.2d, v11.2d, #1
    ushr    v10.2d, v10.2d, #63
    ushr    v11.2d, v11.2d, #63
    ext     v12.16b, v10.16b, v14.16b, #8
    ext     v10.16b, v14.16b, v10.16b, #8
    ext     v11.16b, v14.16b, v11.16b, #8
    eor     v10.16b, v10.16b, v8.16b
    eor     v9.16b, v11.16b, v9.16b
    eor     v11.16b, v12.16b, v9.16b

    shl    v8.2d, v10.2d, #63
    shl    v9.2d, v10.2d, #62
    shl    v12.2d, v10.2d, #57
    eor     v8.16b, v8.16b, v9.16b
    eor     v8.16b, v8.16b, v12.16b

    ext     v8.16b, v14.16b, v8.16b, #8
    eor     v8.16b, v10.16b, v8.16b
    //v8 [D:X0]

    ushr    v9.2d, v8.2d, #1
    shl     v12.2d, v8.2d, #63
    ext     v12.16b, v12.16b, v14.16b, #8
    eor     v9.16b, v9.16b, v12.16b
    eor     v10.16b, v8.16b, v9.16b

    ushr    v9.2d, v8.2d, #2
    shl     v12.2d, v8.2d, #62
    ext     v12.16b, v12.16b, v14.16b, #8
    eor     v9.16b, v9.16b, v12.16b
    eor     v10.16b, v10.16b, v9.16b

    ushr    v9.2d, v8.2d, #7
    shl     v12.2d, v8.2d, #57
    ext     v12.16b, v12.16b, v14.16b, #8
    eor     v9.16b, v9.16b, v12.16b
    eor     v10.16b, v10.16b, v9.16b
    //v10 [D+E+F+G:X0+E+F+G]

    eor     \register, v11.16b, v10.16b
    //\register  [X3+H1:X2+H0]

#ifndef HL_BIG_ENDIAN
    rev64   \register, \register
    ext     \register, \register, \register, #8
#endif
.endm


.data

//should actually be endian-agnostic; but be careful until it's tested
//no need to reverse ShiftRows: (rows are columns in this representation) all bytes in a row are identical
keyexp_last_word_rotate_Lendian:
.byte	0x0d, 0x0e, 0x0f, 0x0c
.byte	0x0d, 0x0e, 0x0f, 0x0c
.byte	0x0d, 0x0e, 0x0f, 0x0c
.byte	0x0d, 0x0e, 0x0f, 0x0c

keyexp_last_word_192_rotate_Lendian:
.byte	0x05, 0x06, 0x07, 0x04
.byte	0x05, 0x06, 0x07, 0x04
.byte	0x05, 0x06, 0x07, 0x04
.byte	0x05, 0x06, 0x07, 0x04

keyexp_last_word_Lendian:
.byte	0x0c, 0x0d, 0x0e, 0x0f
.byte	0x0c, 0x0d, 0x0e, 0x0f
.byte	0x0c, 0x0d, 0x0e, 0x0f
.byte	0x0c, 0x0d, 0x0e, 0x0f

.text

.balign 16
m_impl_aes_128_key_expansion:
_m_impl_aes_128_key_expansion:
// Parameter1: const unsigned char * userkey
// Parameter2: unsigned char * key_schedule
	LDADR   x4, keyexp_last_word_rotate_Lendian // for simple logic use keyexp_reverse_shift_and_rotate_Lendian
	ld1		{v31.16b}, [x4]						//v31={keyexp_reverse_shift_and_rotate}
	eor		v30.16b, v30.16b, v30.16b			//v30={0}
	movi	v29.4s, #1							//v29=rcon[1]	//Little-Endian
	mov		x2, #8								//run 8 iterations at first, then set rcon to new value, then run another 2
	mov		x3, #1								//x3=first or second loop?
	ld1		{v0.16b}, [x0], #16				
	st1		{v0.16b}, [x1], #16

/*
reorder summands
w4 = mr(w3) ^ w0
w5 = w4 ^ w1 = (w0 ^ w1) ^ mr(w3)
w6 = w5 ^ w2 = (w0 ^ w1 ^ w2) ^ mr(w3)
w7 = w6 ^ w3 = (w0 ^ w1 ^ w2 ^ w3) ^ mr(w3)
*/
key_expand_loop_128:
	tbl		v2.16b, {v0.16b}, v31.16b		//distribute highest word, rotated, on all 4 lanes
	ext		v3.16b, v30.16b, v0.16b, #12	//high 4 from v30={0} as low, low 12 from v0 as high -> 00:w0:w1:w2
	aese	v2.16b, v30.16b					//apply S-Box. Since all 4 words are identical, no need to revert ShiftRows
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^w0 : w2^w1 : w3^w2
	ext		v3.16b, v30.16b, v3.16b, #12	//00:00:w0:w1
	eor		v2.16b, v2.16b, v29.16b			//apply rcon
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1
	ext		v3.16b, v30.16b, v3.16b, #12	//00:00:00:w0
	shl		v29.4s, v29.4s, #1				//next rcon
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1^0
	eor		v0.16b, v2.16b, v0.16b			// ^=mr(w3)
	subs	x2, x2, #1
	st1		{v0.16b}, [x1], #16
	bne		key_expand_loop_128

	subs	x3, x3, #1						//unset rerun flag
	mov		x2, #2							//reset iteration counter to 2
	movi	v29.4s, #0x1B					//v29=rcon[9]
	beq		key_expand_loop_128				//rerun iteration
    movi    v0.16b, #0                      //**Scrub**
    movi    v2.16b, #0
    movi    v3.16b, #0
    movi    v4.16b, #0
	ret                                     //END of m_impl_aes_128_key_expansion


.balign 16
m_impl_aes_192_key_expansion:
_m_impl_aes_192_key_expansion:
// Parameter1: const unsigned char * userkey
// Parameter2: unsigned char * key_schedule
	LDADR	x4, keyexp_last_word_192_rotate_Lendian
	ld1		{v31.16b}, [x4]				    //v31={keyexp_reverse_shift_and_rotate}
	eor		v30.16b, v30.16b, v30.16b		//v30={0}
	movi	v29.4s, #1						//v29=rcon[1]	//Little-Endian
	mov		x2, #8
	ld1		{v0.16b}, [x0], #16
	ld1		{v1.8b}, [x0], #8
	st1		{v0.16b}, [x1], #16				// w0 : w1 : w2 : w3
                                            // w4 : w5 :   stored as part of first iteration

	//see 128 for logic explanation
    //loop produces 8 bytes too many, so on last iteration, v1 isn't stored
key_expand_loop_192:
	st1		{v1.8b}, [x1], #8				// store w4 : w5 :   from last iteration
	tbl		v2.16b, {v1.16b}, v31.16b		//distribute highest word, rotated, on all 4 lanes
	ext		v3.16b, v30.16b, v0.16b, #12	// 00:w0:w1:w2
	ext		v4.8b,  v30.8b, v1.8b, #4		// 00:w4
	aese	v2.16b, v30.16b					//apply S-Box. Since all 4 words are identical, no need to revert ShiftRows
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^w0 : w2^w1 : w3^w2
	ext		v3.16b, v30.16b, v3.16b, #12	// 00:00:w0:w1
	eor		v2.16b, v2.16b, v29.16b			//apply rcon
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1
	ext		v3.16b, v30.16b, v3.16b, #12	// 00:00:00:w0
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1^0
	eor		v1.8b,  v4.8b,  v1.8b			// w4 : w5^4
	eor		v0.16b, v2.16b, v0.16b			// ^=mr(w3)
	shl		v29.4s, v29.4s, #1				//next rcon
	st1		{v0.16b}, [x1], #16
	dup		v4.4s,  v0.s[3]				    // w3^2^1^0^mr(w3) x4
	eor		v1.8b,  v4.8b,  v1.8b			// w4^w3^2^1^0^mr(w3) : w5^4^3^2^1^mr(w3) : 
	subs	x2, x2, #1
	bne		key_expand_loop_192
    movi    v0.16b, #0                      //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v3.16b, #0
    movi    v4.16b, #0
	ret                                     //END of m_impl_aes_192_key_expansion


.balign 16
m_impl_aes_256_key_expansion:
_m_impl_aes_256_key_expansion:
// Parameter1: const unsigned char * userkey
// Parameter2: unsigned char * key_schedule
	LDADR	x4, keyexp_last_word_rotate_Lendian
	LDADR	x5, keyexp_last_word_Lendian
	ld1		{v27.16b}, [x4]				    //v27={keyexp_reverse_shift_and_rotate}
	ld1		{v28.16b}, [x5]				    //v28={keyexp_reverse_shift}
	eor		v30.16b, v30.16b, v30.16b	    //v30={0}
	movi	v29.4s, #1					    //v29=rcon[1]	//Little-Endian
	mov		x2, #7
	ld1		{v0.16b}, [x0], #16
	ld1		{v1.16b}, [x0], #16
	st1		{v0.16b}, [x1], #16				// w0 : w1 : w2 : w3
                                            // w4 : w5 : w6 : w7  stored as part of first iteration

	//see 128 for logic explanation
    //loop produces 16 bytes too many, so on last iteration, v1 isn't stored
key_expand_loop_256:
	st1		{v1.16b}, [x1], #16				// w4 : w5 : w6 : w7   (from last iteration)
	tbl		v2.16b, {v1.16b}, v27.16b		//distribute w7 rotated on all 4 lanes
	ext		v3.16b, v30.16b, v0.16b, #12	// 00:w0:w1:w2
	ext		v4.16b, v30.16b, v1.16b, #12	// 00:w4:w5:w6
	aese	v2.16b, v30.16b					//apply S-Box. Since all 4 words are identical, no need to revert ShiftRows
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^w0 : w2^w1 : w3^w2
	eor		v1.16b, v4.16b, v1.16b			// w4 : w5^w4 : w6^w5 : w7^w6
	ext		v3.16b, v30.16b, v3.16b, #12	// 00:00:w0:w1
	ext		v4.16b, v30.16b, v4.16b, #12	// 00:00:w4:w5
	eor		v2.16b, v2.16b, v29.16b			//apply rcon
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1
	eor		v1.16b, v4.16b, v1.16b			// w4 : w5^4 : w6^5^4 : w7^6^5
	ext		v3.16b, v30.16b, v3.16b, #12	// 00:00:00:w0
	ext		v4.16b, v30.16b, v4.16b, #12	// 00:00:00:w4
	eor		v0.16b, v3.16b, v0.16b			// w0 : w1^0 : w2^1^0 : w3^2^1^0
	eor		v1.16b, v4.16b, v1.16b			// w4 : w5^4 : w6^5^4 : w7^6^5^4
	eor		v0.16b, v2.16b, v0.16b			// ^=mr(w3)
	shl		v29.4s, v29.4s, #1				//next rcon
	tbl		v2.16b, {v0.16b}, v28.16b		//distribute w11 on all 4 lanes
	st1		{v0.16b}, [x1], #16
	aese	v2.16b, v30.16b					//apply S-Box
	eor		v1.16b, v2.16b, v1.16b			// ^=m(w11)
	subs	x2, x2, #1
	bne		key_expand_loop_256
    movi    v0.16b, #0                      //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v3.16b, #0
    movi    v4.16b, #0
	ret                                     //END of m_impl_aes_256_key_expansion


.balign 16
m_impl_aes_revert_key:
_m_impl_aes_revert_key:
// Parameter1: normal key schedule		x0
// Parameter2: reverted key schedule	x1
// Parameter3: number of rounds			x2
	add		x1, x1, x2, lsl #4			//
	add		x1, x1, #-16				// move x1 address before second-to-last word in expanded key
	ldp		q0, q1, [x0], #32			// load first two words as v0, v1, and advance x0
	aesimc	v1.16b, v1.16b				// inverse mix columns on v1
	stp		q1, q0, [x1], #-32			// store v0 as last and v1 as second-to-last, and decrease x1 for next write
	sub		x2, x2, #2					// 
	revert_key_loop:					// begin loop
	ldp		q0, q1, [x0], #32			// load pair of words to v0,v1, and advance x0
	subs	x2, x2, #2					// decrement loop counter
	aesimc	v0.16b, v0.16b				// inverse mix columns on v0
	aesimc	v1.16b, v1.16b				// inverse mix columns on v1
	stp		q1, q0, [x1], #-32			// store v0,v1 in reverse order, and decrease x1 for next iteration's write
	bne		revert_key_loop				// end loop

	ldr		q0, [x0]					// load last word
	str		q0, [x1, #16]				// store as first word
    movi    v0.16b, #0                  //**Scrub**
    movi    v1.16b, #0
	ret                                 // END of m_impl_aes_revert_key


.balign 16
m_impl_aes_ecb_encrypt:
_m_impl_aes_ecb_encrypt:
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: Rounds       w4
	cbz		x3, ecb_enc_done //skip all if zero blocks
	//load key schedule into registers v16-v30
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w4, #12
	ld1		{v24.16b, v25.16b, v26.16b}, [x2], #48
	blt		ecb_enc_128
	ld1		{v27.16b, v28.16b}, [x2], #32
	beq		ecb_enc_192
	ld1		{v29.16b, v30.16b}, [x2], #32

	//loop unrolled threefold
	//registers available for up to 16-fold unroll, but fastest with 3
	CMP		x3
	blt		ecb_enc_loop_256

	ecb_enc_3x_loop_256:
	//load 3 plaintext blocks into registers v0-v2
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	SUB		x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	AESMC
	AESE	v26.16b
	AESMC
	AESE	v27.16b
	AESMC
	AESE	v28.16b
	AESMC
	AESE	v29.16b
	XORKEY	v30.16b
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP		x3
	bge		ecb_enc_3x_loop_256
    cbz     x3, ecb_enc_done

	ecb_enc_loop_256:
	ld1		{v0.16b}, [x0], #16
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	AESMC1
	AESE1	v28.16b
	AESMC1
	AESE1	v29.16b
	XORKEY1	v30.16b
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_enc_loop_256
    b       ecb_enc_done

	ecb_enc_192:
	CMP     x3
	blt		ecb_enc_loop_192

	ecb_enc_3x_loop_192:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	SUB		x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	AESMC
	AESE	v26.16b
	AESMC
	AESE	v27.16b
	XORKEY	v28.16b
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP		x3
	bge		ecb_enc_3x_loop_192
    cbz     x3, ecb_enc_done

	ecb_enc_loop_192:
	ld1		{v0.16b}, [x0], #16
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	XORKEY1	v28.16b
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_enc_loop_192
    b       ecb_enc_done

	ecb_enc_128:
	CMP		x3
	blt		ecb_enc_loop_128

	ecb_enc_3x_loop_128:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	SUB		x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	XORKEY	v26.16b
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP		x3
	bge		ecb_enc_3x_loop_128
    cbz     x3, ecb_enc_done

	ecb_enc_loop_128:
	ld1		{v0.16b}, [x0], #16
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	XORKEY1	v26.16b
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_enc_loop_128

ecb_enc_done:
    movi    v0.16b, #0                      //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v16.16b, #0
    movi    v17.16b, #0
    movi    v18.16b, #0
    movi    v19.16b, #0
    movi    v20.16b, #0
    movi    v21.16b, #0
    movi    v22.16b, #0
    movi    v23.16b, #0
    movi    v24.16b, #0
    movi    v25.16b, #0
    movi    v26.16b, #0
    movi    v27.16b, #0
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    ret


.balign 16
m_impl_aes_cbc_encrypt:
_m_impl_aes_cbc_encrypt:
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: Rounds       w4
// Parameter6: IVector      x5

//load IV
	ld1		{v0.16b}, [x5]
	cbz		x3, cbc_enc_done //skip all if zero blocks
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w4, #12
	ld1		{v24.16b, v25.16b, v26.16b}, [x2], #48
	blt		cbc_enc_loop_128
	ld1		{v27.16b, v28.16b}, [x2], #32
	beq		cbc_enc_loop_192
	ld1		{v29.16b, v30.16b}, [x2], #32

cbc_enc_loop_256:
	ld1		{v1.16b}, [x0], #16
	eor		v0.16b, v0.16b, v1.16b
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	AESMC1
	AESE1	v28.16b
	AESMC1
	AESE1	v29.16b
	XORKEY1	v30.16b
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		cbc_enc_loop_256
    b       cbc_enc_done

cbc_enc_loop_192:
	ld1		{v1.16b}, [x0], #16
	eor		v0.16b, v0.16b, v1.16b
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	XORKEY1	v28.16b
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		cbc_enc_loop_192
    b       cbc_enc_done

cbc_enc_loop_128:
	ld1		{v1.16b}, [x0], #16
	eor		v0.16b, v0.16b, v1.16b
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	XORKEY1	v26.16b
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		cbc_enc_loop_128

cbc_enc_done:
    movi    v0.16b, #0                      //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v16.16b, #0
    movi    v17.16b, #0
    movi    v18.16b, #0
    movi    v19.16b, #0
    movi    v20.16b, #0
    movi    v21.16b, #0
    movi    v22.16b, #0
    movi    v23.16b, #0
    movi    v24.16b, #0
    movi    v25.16b, #0
    movi    v26.16b, #0
    movi    v27.16b, #0
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    ret

.balign 16
m_impl_aes_cbc_decrypt:
_m_impl_aes_cbc_decrypt:
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: Rounds       w4
// Parameter6: IVector      x5

	cbz		x3, cbc_dec_done        //skip all if zero blocks
//load IV
	ld1		{v4.16b}, [x5]
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w4, #12
	ld1		{v24.16b, v25.16b, v26.16b}, [x2], #48
	blt		cbc_dec_128
	ld1		{v27.16b, v28.16b}, [x2], #32
	beq		cbc_dec_192
	ld1		{v29.16b, v30.16b}, [x2], #32

	CMP     x3
	blt		cbc_dec_loop_256

cbc_dec_3x_loop_256:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	mov		v5.16b, v0.16b
	mov		v6.16b, v1.16b
	mov		v31.16b, v2.16b
	SUB     x3
	AESD	v16.16b
	AESIMC
	AESD	v17.16b
	AESIMC
	AESD	v18.16b
	AESIMC
	AESD	v19.16b
	AESIMC
	AESD	v20.16b
	AESIMC
	AESD	v21.16b
	AESIMC
	AESD	v22.16b
	AESIMC
	AESD	v23.16b
	AESIMC
	AESD	v24.16b
	AESIMC
	AESD	v25.16b
	AESIMC
	AESD	v26.16b
	AESIMC
	AESD	v27.16b
	AESIMC
	AESD	v28.16b
	AESIMC
	AESD	v29.16b
	XORKEY	v30.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	mov		v4.16b, v31.16b
	bge		cbc_dec_3x_loop_256
    cbz     x3, cbc_dec_done        //skip second loop entirely if zero

cbc_dec_loop_256:
	ld1		{v0.16b}, [x0], #16
	mov		v31.16b, v0.16b
	AESD1	v16.16b
	AESIMC1
	AESD1	v17.16b
	AESIMC1
	AESD1	v18.16b
	AESIMC1
	AESD1	v19.16b
	AESIMC1
	AESD1	v20.16b
	AESIMC1
	AESD1	v21.16b
	AESIMC1
	AESD1	v22.16b
	AESIMC1
	AESD1	v23.16b
	AESIMC1
	AESD1	v24.16b
	AESIMC1
	AESD1	v25.16b
	AESIMC1
	AESD1	v26.16b
	AESIMC1
	AESD1	v27.16b
	AESIMC1
	AESD1	v28.16b
	AESIMC1
	AESD1	v29.16b
	XORKEY1	v30.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	mov		v4.16b, v31.16b
	bne		cbc_dec_loop_256
    b       cbc_dec_done

cbc_dec_192:
	CMP     x3
	blt		cbc_dec_loop_192

cbc_dec_3x_loop_192:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	mov		v5.16b, v0.16b
	mov		v6.16b, v1.16b
	mov		v31.16b, v2.16b
	SUB     x3
	AESD	v16.16b
	AESIMC
	AESD	v17.16b
	AESIMC
	AESD	v18.16b
	AESIMC
	AESD	v19.16b
	AESIMC
	AESD	v20.16b
	AESIMC
	AESD	v21.16b
	AESIMC
	AESD	v22.16b
	AESIMC
	AESD	v23.16b
	AESIMC
	AESD	v24.16b
	AESIMC
	AESD	v25.16b
	AESIMC
	AESD	v26.16b
	AESIMC
	AESD	v27.16b
	XORKEY	v28.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	mov		v4.16b, v31.16b
	bge		cbc_dec_3x_loop_192
    cbz     x3, cbc_dec_done        //skip second loop entirely if zero

cbc_dec_loop_192:
	ld1		{v0.16b}, [x0], #16
	mov		v31.16b, v0.16b
	AESD1	v16.16b
	AESIMC1
	AESD1	v17.16b
	AESIMC1
	AESD1	v18.16b
	AESIMC1
	AESD1	v19.16b
	AESIMC1
	AESD1	v20.16b
	AESIMC1
	AESD1	v21.16b
	AESIMC1
	AESD1	v22.16b
	AESIMC1
	AESD1	v23.16b
	AESIMC1
	AESD1	v24.16b
	AESIMC1
	AESD1	v25.16b
	AESIMC1
	AESD1	v26.16b
	AESIMC1
	AESD1	v27.16b
	XORKEY1	v28.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	mov		v4.16b, v31.16b
	bne		cbc_dec_loop_192
    b       cbc_dec_done

cbc_dec_128:
	CMP     x3
	blt		cbc_dec_loop_128

cbc_dec_3x_loop_128:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	mov		v5.16b, v0.16b
	mov		v6.16b, v1.16b
	mov		v31.16b, v2.16b
	SUB     x3
	AESD	v16.16b
	AESIMC
	AESD	v17.16b
	AESIMC
	AESD	v18.16b
	AESIMC
	AESD	v19.16b
	AESIMC
	AESD	v20.16b
	AESIMC
	AESD	v21.16b
	AESIMC
	AESD	v22.16b
	AESIMC
	AESD	v23.16b
	AESIMC
	AESD	v24.16b
	AESIMC
	AESD	v25.16b
	XORKEY	v26.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	mov		v4.16b, v31.16b
	bge		cbc_dec_3x_loop_128
    cbz     x3, cbc_dec_done

cbc_dec_loop_128:
	ld1		{v0.16b}, [x0], #16
	mov		v31.16b, v0.16b
	AESD1	v16.16b
	AESIMC1
	AESD1	v17.16b
	AESIMC1
	AESD1	v18.16b
	AESIMC1
	AESD1	v19.16b
	AESIMC1
	AESD1	v20.16b
	AESIMC1
	AESD1	v21.16b
	AESIMC1
	AESD1	v22.16b
	AESIMC1
	AESD1	v23.16b
	AESIMC1
	AESD1	v24.16b
	AESIMC1
	AESD1	v25.16b
	XORKEY1	v26.16b
	eor		v0.16b, v0.16b, v4.16b  // apply IV from previous block
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	mov		v4.16b, v31.16b
	bne		cbc_dec_loop_128

cbc_dec_done:
#	st1		{v4.16b}, [x4]                  // Store v4
    movi    v0.16b, #0                      //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v16.16b, #0
    movi    v17.16b, #0
    movi    v18.16b, #0
    movi    v19.16b, #0
    movi    v20.16b, #0
    movi    v21.16b, #0
    movi    v22.16b, #0
    movi    v23.16b, #0
    movi    v24.16b, #0
    movi    v25.16b, #0
    movi    v26.16b, #0
    movi    v27.16b, #0
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    ret


.balign 16
m_impl_aes_ctr:
_m_impl_aes_ctr:
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter6: Rounds       w4
// Parameter5: IV/Nonce     x5

//load Nonce
	ld1		{v31.16b}, [x5]
	mov		w6, v31.s[3]
#ifndef HL_BIG_ENDIAN
	rev		w6, w6
#endif
	//12-byte nonce and 4-byte counter (overflow does not affect nonce)
	//To instead use a 8-byte nonce and 8-byte counter, use .2d instead of .4s
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w4, #12
	ld1		{v24.16b, v25.16b, v26.16b}, [x2], #48
	blt		ctr_128
	ld1		{v27.16b, v28.16b}, [x2], #32
	beq		ctr_192
	ld1		{v29.16b, v30.16b}, [x2], #32
	cbz		x3, ctr_loop_256_done   //if zero blocks, skip both loops and do only n+1 block
	CMP     x3
	blt		ctr_loop_256            // if less than three, skip first loop

ctr_3x_loop_256:
	ld1		{v4.16b, v5.16b, v6.16b}, [x0], #48
	mov		v0.16b, v31.16b
	mov		v1.16b, v31.16b
	mov		v2.16b, v31.16b
#ifdef HL_BIG_ENDIAN
	mov		w10, w6
#endif
	add		w11, w6, #1
	add		w12, w6, #2
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	rev		w11, w11
	rev		w12, w12
#endif
	mov		v0.s[3], w10
	mov		v1.s[3], w11
	mov		v2.s[3], w12
	add		w6, w6, #3
	SUB     x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	AESMC
	AESE	v26.16b
	AESMC
	AESE	v27.16b
	AESMC
	AESE	v28.16b
	AESMC
	AESE	v29.16b
	XORKEY	v30.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	bge		ctr_3x_loop_256
	cbz		x3, ctr_loop_256_done   //skip second loop entirely if zero

ctr_loop_256:
	ld1		{v4.16b}, [x0], #16
	mov		v0.16b, v31.16b
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v0.s[3], w10
#else
	mov		v0.s[3], w6
#endif
	add		w6, w6, #1
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	AESMC1
	AESE1	v28.16b
	AESMC1
	AESE1	v29.16b
	XORKEY1	v30.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		ctr_loop_256

ctr_loop_256_done:
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v31.s[3], w10
#else
	mov		v31.s[3], w6
#endif
	AESE1v31	v16.16b
	AESMC1v31
	AESE1v31	v17.16b
	AESMC1v31
	AESE1v31	v18.16b
	AESMC1v31
	AESE1v31	v19.16b
	AESMC1v31
	AESE1v31	v20.16b
	AESMC1v31
	AESE1v31	v21.16b
	AESMC1v31
	AESE1v31	v22.16b
	AESMC1v31
	AESE1v31	v23.16b
	AESMC1v31
	AESE1v31	v24.16b
	AESMC1v31
	AESE1v31	v25.16b
	AESMC1v31
	AESE1v31	v26.16b
	AESMC1v31
	AESE1v31	v27.16b
	AESMC1v31
	AESE1v31	v28.16b
	AESMC1v31
	AESE1v31	v29.16b
	XORKEY1v31	v30.16b
b   ctr_done

ctr_192:
	cbz		x3, ctr_loop_192_done   //if zero blocks, skip both loops and do only n+1 block
	CMP     x3
	blt		ctr_loop_192

ctr_3x_loop_192:
	ld1		{v4.16b, v5.16b, v6.16b}, [x0], #48
	mov		v0.16b, v31.16b
	mov		v1.16b, v31.16b
	mov		v2.16b, v31.16b
#ifdef HL_BIG_ENDIAN
	mov		w10, w6
#endif
	add		w11, w6, #1
	add		w12, w6, #2
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	rev		w11, w11
	rev		w12, w12
#endif
	mov		v0.s[3], w10
	mov		v1.s[3], w11
	mov		v2.s[3], w12
	add		w6, w6, #3
	SUB     x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	AESMC
	AESE	v26.16b
	AESMC
	AESE	v27.16b
	XORKEY	v28.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	bge		ctr_3x_loop_192
	cbz		x3, ctr_loop_192_done   //skip second loop entirely if zero

ctr_loop_192:
	ld1		{v4.16b}, [x0], #16
	mov		v0.16b, v31.16b
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v0.s[3], w10
#else
	mov		v0.s[3], w6
#endif
	add		w6, w6, #1
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	AESMC1
	AESE1	v26.16b
	AESMC1
	AESE1	v27.16b
	XORKEY1	v28.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		ctr_loop_192

ctr_loop_192_done:
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v31.s[3], w10
#else
	mov		v31.s[3], w6
#endif
	AESE1v31	v16.16b
	AESMC1v31
	AESE1v31	v17.16b
	AESMC1v31
	AESE1v31	v18.16b
	AESMC1v31
	AESE1v31	v19.16b
	AESMC1v31
	AESE1v31	v20.16b
	AESMC1v31
	AESE1v31	v21.16b
	AESMC1v31
	AESE1v31	v22.16b
	AESMC1v31
	AESE1v31	v23.16b
	AESMC1v31
	AESE1v31	v24.16b
	AESMC1v31
	AESE1v31	v25.16b
	AESMC1v31
	AESE1v31	v26.16b
	AESMC1v31
	AESE1v31	v27.16b
	XORKEY1v31	v28.16b
    b       ctr_done

ctr_128:
	cbz		x3, ctr_loop_128_done   //if zero blocks, skip both loops and do only n+1 block
	CMP     x3
	blt		ctr_loop_128

ctr_3x_loop_128:
	ld1		{v4.16b, v5.16b, v6.16b}, [x0], #48
	mov		v0.16b, v31.16b
	mov		v1.16b, v31.16b
	mov		v2.16b, v31.16b
#ifdef HL_BIG_ENDIAN
	mov		w10, w6
#endif
	add		w11, w6, #1
	add		w12, w6, #2
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	rev		w11, w11
	rev		w12, w12
#endif
	mov		v0.s[3], w10
	mov		v1.s[3], w11
	mov		v2.s[3], w12
	add		w6, w6, #3
	SUB     x3
	AESE	v16.16b
	AESMC
	AESE	v17.16b
	AESMC
	AESE	v18.16b
	AESMC
	AESE	v19.16b
	AESMC
	AESE	v20.16b
	AESMC
	AESE	v21.16b
	AESMC
	AESE	v22.16b
	AESMC
	AESE	v23.16b
	AESMC
	AESE	v24.16b
	AESMC
	AESE	v25.16b
	XORKEY	v26.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	eor		v1.16b, v1.16b, v5.16b 
	eor		v2.16b, v2.16b, v6.16b 
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	bge		ctr_3x_loop_128
	cbz		x3, ctr_loop_128_done   //skip second loop entirely if zero

ctr_loop_128:
	ld1		{v4.16b}, [x0], #16
	mov		v0.16b, v31.16b
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v0.s[3], w10
#else
	mov		v0.s[3], w6
#endif
	add		w6, w6, #1
	AESE1	v16.16b
	AESMC1
	AESE1	v17.16b
	AESMC1
	AESE1	v18.16b
	AESMC1
	AESE1	v19.16b
	AESMC1
	AESE1	v20.16b
	AESMC1
	AESE1	v21.16b
	AESMC1
	AESE1	v22.16b
	AESMC1
	AESE1	v23.16b
	AESMC1
	AESE1	v24.16b
	AESMC1
	AESE1	v25.16b
	XORKEY1	v26.16b
	eor		v0.16b, v0.16b, v4.16b  // apply plaintext
	st1		{v0.16b}, [x1], #16
	SUBS1   x3
	bne		ctr_loop_128

ctr_loop_128_done:
#ifndef HL_BIG_ENDIAN
	rev		w10, w6
	mov		v31.s[3], w10
#else
	mov		v31.s[3], w6
#endif
	AESE1v31	v16.16b
	AESMC1v31
	AESE1v31	v17.16b
	AESMC1v31
	AESE1v31	v18.16b
	AESMC1v31
	AESE1v31	v19.16b
	AESMC1v31
	AESE1v31	v20.16b
	AESMC1v31
	AESE1v31	v21.16b
	AESMC1v31
	AESE1v31	v22.16b
	AESMC1v31
	AESE1v31	v23.16b
	AESMC1v31
	AESE1v31	v24.16b
	AESMC1v31
	AESE1v31	v25.16b
	XORKEY1v31	v26.16b

ctr_done:
	st1		{v31.16b}, [x5]         // Store v31
    movi    v0.16b, #0              //**Scrub**
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v16.16b, #0
    movi    v17.16b, #0
    movi    v18.16b, #0
    movi    v19.16b, #0
    movi    v20.16b, #0
    movi    v21.16b, #0
    movi    v22.16b, #0
    movi    v23.16b, #0
    movi    v24.16b, #0
    movi    v25.16b, #0
    movi    v26.16b, #0
    movi    v27.16b, #0
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    ret
 

// Polynomial multiplication of two 128bit vectors
// Input    \p1         polynomial1
// Input    \p2         polynomial2
// Input    \p2_rv      polynomial2, upper and lower half reversed
// Input    v16         0
// Return   \prd_lo     lower 128bit of product
// Return   \prd_hi     higher 128bit of product
// Uses v18,v19 as intermediate values
.macro  PMUL64  prd_lo, prd_hi, p1, p2, p2_rv
    pmull   v18.1q, \p1\().1d, \p2_rv\().1d         // low p1 * high p2
    pmull2  v19.1q, \p1\().2d, \p2_rv\().2d         // high p1 * low p2
    pmull   \prd_lo\().1q, \p1\().1d, \p2\().1d     // low p1 * low p2
    pmull2  \prd_hi\().1q, \p1\().2d, \p2\().2d     // high p1 * high p2
    eor     v19.16b, v18.16b, v19.16b               // Call w3:w2:w1:W0
    ext     v18.16b, v16.16b, v19.16b, #8           // w1:w0:00:00
    ext     v19.16b, v19.16b, v16.16b, #8           // 00:00:w3:w2
    eor     \prd_lo\().16b, \prd_lo\().16b, v18.16b // low of product
    eor     \prd_hi\().16b, \prd_hi\().16b, v19.16b // high of product
.endm
// Reduction of 256bit polynomial mod g(x)=x^128+x^7+x^2+x+1
// Algorithm5 of: Implementing GCM on ARMv8, Gouvea and Lopez
// Input \p_lo      lower 128 bit of input polynomial
// Input \p_hi      higher 128 bit of input polynomial
// Input v16        0
// Input v17        0x00000000000000870000000000000087
// Return \p_lo     result
// Uses v18,v19 as intermediate values
.macro  GRED    p_lo, p_hi
    pmull2  v18.1q, \p_hi\().2d, v17.2d
    ext     v19.16b, v18.16b, v16.16b, #8
    eor     \p_hi\().16b, \p_hi\().16b, v19.16b
    ext     v19.16b, v16.16b, v18.16b, #8
    eor     \p_lo\().16b, \p_lo\().16b, v19.16b
    pmull   v18.1q, \p_hi\().1d, v17.1d
    eor     \p_lo\().16b, \p_lo\().16b, v18.16b
.endm
// Conversion between Big and Little endian block
// i.e. reverse byte order of 16B vector
.macro  CNV_BIG_LTL reg
    rev64   \reg\().16b, \reg\().16b
    ext     \reg\().16b, \reg\().16b, \reg\().16b, #8
.endm


.balign 16
m_impl_ghash_stream:
_m_impl_ghash_stream:
// Lazy reduction in: Implementing GCM on ARMv8, Gouvea and Lopez
// Parameter1: GHASH state  x0
// Parameter2: GHASH key    x1
// Parameter3: Input data   x2
// Parameter4: Input size   w3
//*** macro setting ***
    movi    v16.16b, #0
    mov     x4, #0x87
    ins     v17.d[0], x4
    ins     v17.d[1], v17.d[0]
//*** Load hash key ***
    ld1     {v24.16b}, [x1]
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v24
#endif
    rbit    v24.16b, v24.16b 
    ext     v25.16b, v24.16b, v24.16b, #8   // v24,v25  h,h_rv
//*** Load the current hash state ***
    ld1     {v0.16b}, [x0]
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v0
#endif
    rbit    v0.16b, v0.16b
//*** Precompute h^2, h^3 and h^4 ***
    cmp     w3, #64
    b.lt    gcm_ghash_stream_loop16         // If Input size < 64, skip lazy loop
    PMUL64  v26, v27, v24, v24, v25
    GRED    v26, v27
    ext     v27.16b, v26.16b, v26.16b, #8   // v26,v27  h2,h2_rv
    PMUL64  v28, v29, v26, v24, v25
    GRED    v28, v29
    ext     v29.16b, v28.16b, v28.16b, #8   // v28,v29  h3,h3_rv
    PMUL64  v30, v31, v28, v24, v25
    GRED    v30, v31
    ext     v31.16b, v30.16b, v30.16b, #8   // v30,v31  h4,h4_rv
//*** Lazy reduction loop with 8 blocks (Used only for huge input) ***
    mov     w5, #1
    lsl     w5, w5, #11
    cmp     w3, w5                          // 2^11 is a threshold for this unroll
    b.lt    gcm_ghash_stream_skipped_lazy_8
    sub     sp, sp, #128
    mov     x4, sp
    st1     {v8.16b,v9.16b,v10.16b,v11.16b}, [x4], #64
    st1     {v12.16b,v13.16b,v14.16b,v15.16b}, [x4]
//*** Precompute h^5, h^5, h^6 and h^7 ***
    PMUL64  v8, v9, v30, v24, v25
    GRED    v8, v9
    ext     v9.16b, v8.16b, v8.16b, #8      // v8,v9    h5,h5_rv
    PMUL64  v10, v11, v8, v24, v25
    GRED    v10, v11
    ext     v11.16b, v10.16b, v10.16b, #8   // v10,v11  h6,h6_rv
    PMUL64  v12, v13, v10, v24, v25
    GRED    v12, v13
    ext     v13.16b, v12.16b, v12.16b, #8   // v12,v13  h7,h7_rv
    PMUL64  v14, v15, v12, v24, v25
    GRED    v14, v15
    ext     v15.16b, v14.16b, v14.16b, #8   // v14,v15  h8,h8_rv
gcm_ghash_stream_loop_lazy_8:
    ld1     {v20.16b,v21.16b,v22.16b,v23.16b}, [x2], #64
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v20
    CNV_BIG_LTL v21
    CNV_BIG_LTL v22
    CNV_BIG_LTL v23
#endif
    rbit    v20.16b, v20.16b
    rbit    v21.16b, v21.16b
    rbit    v22.16b, v22.16b
    rbit    v23.16b, v23.16b
    eor     v20.16b, v0.16b, v20.16b
    PMUL64  v0, v1, v20, v14, v15
    PMUL64  v2, v3, v21, v12, v13
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v22, v10, v11
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v23, v8, v9
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    ld1     {v20.16b,v21.16b,v22.16b,v23.16b}, [x2], #64
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v20
    CNV_BIG_LTL v21
    CNV_BIG_LTL v22
    CNV_BIG_LTL v23
#endif
    rbit    v20.16b, v20.16b
    rbit    v21.16b, v21.16b
    rbit    v22.16b, v22.16b
    rbit    v23.16b, v23.16b
    PMUL64  v2, v3, v20, v30, v31
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v21, v28, v29
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v22, v26, v27
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v23, v24, v25
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    GRED    v0, v1
    sub     w3, w3, #128
    cmp     w3, #128
    b.ge    gcm_ghash_stream_loop_lazy_8
    mov     x4, sp
    ld1     {v8.16b,v9.16b,v10.16b,v11.16b}, [x4], #64
    ld1     {v12.16b,v13.16b,v14.16b,v15.16b}, [x4]
    add     sp, sp, #128
gcm_ghash_stream_skipped_lazy_8:    // END Lazy loop with 8 blocks
//*** Lazy reduction loop, a reduction per 4 blocks ***
gcm_ghash_stream_loop_lazy:
    ld1     {v20.16b,v21.16b,v22.16b,v23.16b}, [x2], #64
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v20
    CNV_BIG_LTL v21
    CNV_BIG_LTL v22
    CNV_BIG_LTL v23
#endif
    rbit    v20.16b, v20.16b
    rbit    v21.16b, v21.16b
    rbit    v22.16b, v22.16b
    rbit    v23.16b, v23.16b
    eor     v20.16b, v0.16b, v20.16b
    PMUL64  v0, v1, v20, v30, v31
    PMUL64  v2, v3, v21, v28, v29
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v22, v26, v27
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    PMUL64  v2, v3, v23, v24, v25
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    GRED    v0, v1
    sub     w3, w3, #64
    cmp     w3, #64
    b.ge    gcm_ghash_stream_loop_lazy
//*** Rest block loop, maximum 3 times ***
gcm_ghash_stream_loop16:
    cmp     w3, #16
    b.lt    gcm_ghash_stream_last_block
    ld1     {v20.16b}, [x2], #16
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v20
#endif 
    rbit    v20.16b, v20.16b
    eor     v20.16b, v0.16b, v20.16b
    PMUL64  v0, v1, v20, v24, v25
    GRED    v0, v1
    sub     w3, w3, #16
    b       gcm_ghash_stream_loop16
//*** Byte loop for possible last incomplete block ***
gcm_ghash_stream_last_block:
    cbz     w3, gcm_ghash_stream_end 
    movi    v20.16b, #0
#ifndef HL_BIG_ENDIAN
    ldrb    w9, [x2], #1
    mov     v20.B[0], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[1], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[2], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[3], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[4], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[5], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[6], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[7], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[8], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[9], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[10], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[11], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[12], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[13], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2], #1
    mov     v20.B[14], w9
#else
    add     x2, x2, #16
    ldrb    w9, [x2, #-1]!
    mov     v20.B[0], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[1], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[2], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[3], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[4], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[5], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[6], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[7], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[8], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[9], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[10], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[11], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[12], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[13], w9
    subs    w3, w3, #1
    b.eq    gcm_ghash_last
    ldrb    w9, [x2, #-1]!
    mov     v20.B[14], w9
#endif
gcm_ghash_last:
    rbit    v20.16b, v20.16b
    eor     v20.16b, v0.16b, v20.16b
    PMUL64  v0, v1, v20, v24, v25
    GRED    v0, v1
gcm_ghash_stream_end:
    rbit    v0.16b, v0.16b
#ifdef HL_BIG_ENDIAN
    CNV_BIG_LTL v0
#endif 
    st1     {v0.16b}, [x0]                  // Save the new hash state
    movi    v0.16b, #0
    movi    v1.16b, #0
    movi    v2.16b, #0
    movi    v20.16b, #0
    movi    v21.16b, #0
    movi    v22.16b, #0
    movi    v23.16b, #0
    movi    v24.16b, #0
    movi    v25.16b, #0
    movi    v26.16b, #0
    movi    v27.16b, #0
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    ret


#endif
