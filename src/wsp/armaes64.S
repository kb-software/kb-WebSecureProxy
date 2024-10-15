#ifdef __aarch64__

#include <hob-encry-err-1.h>

#ifdef __APPLE__
#define HEADER APPLEHEADER
#define LDADR  APPLELDADR
#else
#define HEADER LINUXHEADER
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

.macro  LINUXHEADER function
.global \function
.type \function,%function
.balign 64
\function:
.endm

.macro  APPLEHEADER function
.globl _\function
.balign 64
_\function:
.endm

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

HEADER m_aes_128_cpu_key_expansion
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
	ret                                     //END of m_aes_128_cpu_key_expansion


HEADER m_aes_192_cpu_key_expansion
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
	ret                                     //END of m_aes_192_cpu_key_expansion


HEADER m_aes_256_cpu_key_expansion
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
	ret                                     //END of m_aes_256_cpu_key_expansion


HEADER m_aes_cpu_revert_key
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
	ret                                 // END of m_aes_cpu_revert_key


HEADER m_aes_ecb_cpu_encrypt
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: rounds       w4
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


HEADER m_aes_cbc_cpu_encrypt
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: IVector      x4
// Parameter6: rounds       w5

//load IV
	ld1		{v0.16b}, [x4]
	cbz		x3, cbc_enc_done //skip all if zero blocks
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w5, #12
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
	st1		{v0.16b}, [x4]
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
	st1		{v0.16b}, [x4]
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
	st1		{v0.16b}, [x4]

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


HEADER m_aes_ecb_cpu_decrypt
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: rounds       w4
    cbz		x3, ecb_dec_done    //skip all if zero blocks
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w4, #12
	ld1		{v24.16b, v25.16b, v26.16b}, [x2], #48
	blt		ecb_dec_128
	ld1		{v27.16b, v28.16b}, [x2], #32
	beq		ecb_dec_192
	ld1		{v29.16b, v30.16b}, [x2], #32

	//loop unrolled threefold
	//registers available for up to 16-fold unroll, but fastest with 3
	CMP     x3
	blt		ecb_dec_loop_256

	ecb_dec_3x_loop_256:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
	SUB		x3
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
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP		x3
	bge		ecb_dec_3x_loop_256
    cbz     x3, ecb_dec_done

	ecb_dec_loop_256:
	ld1		{v0.16b}, [x0], #16
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
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_dec_loop_256
    b       ecb_dec_done

	ecb_dec_192:
	CMP     x3
	blt		ecb_dec_loop_192

	ecb_dec_3x_loop_192:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
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
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	bge		ecb_dec_3x_loop_192
    cbz     x3, ecb_dec_done

	ecb_dec_loop_192:
	ld1		{v0.16b}, [x0], #16
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
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_dec_loop_192
    b       ecb_dec_done

	ecb_dec_128:
	CMP     x3
	blt		ecb_dec_loop_128

	ecb_dec_3x_loop_128:
	ld1		{v0.16b, v1.16b, v2.16b}, [x0], #48
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
	st1		{v0.16b, v1.16b, v2.16b}, [x1], #48
	CMP     x3
	bge		ecb_dec_3x_loop_128
    cbz     x3, ecb_dec_done

	ecb_dec_loop_128:
	ld1		{v0.16b}, [x0], #16
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
	st1		{v0.16b}, [x1], #16

	SUBS1   x3
	bne		ecb_dec_loop_128

ecb_dec_done:
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


HEADER m_aes_cbc_cpu_decrypt
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: IVector      x4
// Parameter6: rounds       w5

	cbz		x3, cbc_dec_done        //skip all if zero blocks
//load IV
	ld1		{v4.16b}, [x4]
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w5, #12
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
	st1		{v4.16b}, [x4]                  // Store v4
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


HEADER m_aes_ctr_cpu
// Parameter1: Input        x0
// Parameter2: Output       x1
// Parameter3: Key schedule x2
// Parameter4: Blockcount   x3
// Parameter5: IV/Nonce     x4
// Parameter6: rounds       w5

//load Nonce
	ld1		{v31.16b}, [x4]
	mov		w6, v31.s[3]
#ifndef HL_BIG_ENDIAN
	rev		w6, w6
#endif
	//12-byte nonce and 4-byte counter (overflow does not affect nonce)
	//To instead use a 8-byte nonce and 8-byte counter, use .2d instead of .4s
// load key
	ld1		{v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
	ld1		{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
	cmp		w5, #12
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
	st1		{v31.16b}, [x4]         // Store v31
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

HEADER m_cpu_ghash_stream
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
