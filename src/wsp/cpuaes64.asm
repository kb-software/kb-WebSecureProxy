_text segment

;;;     Note, that the actual AES instructions are written in OP-code, using the DB instruction. This is required to make it compatible with VS 2005, which doesn't understand the AES NI instructions.
;;;     These Macros are used for general processing steps, when handling 4 Blocks of AES at once.
;;;     This is done to use the pipelining capabilities of modern x64 CPUs

pushx       macro XMM          
            sub     rsp, 16
            movdqu  [rsp], XMM
            endm

popx        macro XMM
            movdqu  XMM, [rsp]
            add     rsp, 16
            endm

; Pushes all registers used by AES NI functions
pushall     macro
            push    rbp
            mov     rbp,rsp
            push    rbx
            push    rsi
            push    rdi
            push    r12
            push    r13
            push    r14
            push    r15
            pushx   xmm6
            pushx   xmm7
            pushx   xmm8
            pushx   xmm9
            pushx   xmm10
            pushx   xmm11
            pushx   xmm12
            pushx   xmm13
            pushx   xmm14
            pushx   xmm15
            endm

; Pops all registers used by AES NI functions
popall      macro
            popx    xmm15
            popx    xmm14
            popx    xmm13
            popx    xmm12
            popx    xmm11
            popx    xmm10
            popx    xmm9
            popx    xmm8
            popx    xmm7
            popx    xmm6
            pop     r15
            pop     r14
            pop     r13
            pop     r12
            pop     rdi
            pop     rsi
            pop     rbx
            pop     rbp
            endm

; Loads 4 AES blocks into registers XMM0-3 and XORs the round key into them
; BASE is the register, holding the address of the first block
; ROUND_KEY is the register or address of the round key
aes_load_4  macro BASE, ROUND_KEY
            movdqu  xmm0,[BASE]
            pxor    xmm0,ROUND_KEY
            movdqu  xmm1,[BASE+16]
            pxor    xmm1,ROUND_KEY
            movdqu  xmm2,[BASE+32]
            pxor    xmm2,ROUND_KEY
            movdqu  xmm3,[BASE+48]
            pxor    xmm3,ROUND_KEY
            endm

; Writes XMM0-3 back to memory
; BASE is the register with the destination address
aes_store_4 macro BASE
            movdqu  [BASE],xmm0
            movdqu  [BASE+16],xmm1
            movdqu  [BASE+32],xmm2
            movdqu  [BASE+48],xmm3
            endm


; Performs one AES decryption round on XMM0-3
; KEY specifies the XMM register or address of the subkey for this round
aes_4_dec   MACRO   KEY
            aesdec  xmm0,KEY
            aesdec  xmm1,KEY
            aesdec  xmm2,KEY
            aesdec  xmm3,KEY
            endm

; Performs the last AES decryption round on XMM0-3
; KEY specifies the XMM register or address of the subkey for this round
aes_4_dec_last  macro   KEY
                aesdeclast  xmm0,KEY
                aesdeclast  xmm1,KEY
                aesdeclast  xmm2,KEY
                aesdeclast  xmm3,KEY
                endm

; Reads the AES keys for the aes_dec_block and aes_enc_block functions
; Expected register at start:
; R8 and RBX pointing at the Key schedule
; RAX containing the number of rounds
; RCX and R9 the number of input blocks (16 byte each)
;
; After Processing, the following will be set:
; XMM9 will be filled with the last round key
; XMM11-15 will be filled with the keys for rounds 1-5
; RBX will be pointing at the key for round 6
; R10 will be pointing at the Key schedule
; R8 will be invalid
; RCX will contain the number of 64 byte blocks (4 AES blocks)
; R9 will contain the number of remaining AES blocks (total % 4)
aes_read_keys   proc
    ; Set R10
    mov     r10,r8
    
    ; Read the round keys to XMM11-15
    movdqu  xmm11,[r8+16]
    movdqu  xmm12,[r8+32]
    movdqu  xmm13,[r8+48]
    movdqu  xmm14,[r8+64]
    movdqu  xmm15,[r8+80]
    
    ; Read the final round key to XMM9, according to the number of rounds
    cmp     rax,12
    movdqu  xmm9,[r8+160]
    jl      aes_set_block_counters
    lea     r8,[r8+128]
    movdqu  xmm9,[r8+64]
    je      aes_set_block_counters
    movdqu  xmm9,[r8+96]

aes_set_block_counters:
    and r9, 3
    shr rcx,2
    lea rbx,[rbx+96]

    ret
aes_read_keys   endp
            
; This procedure performs the decryption of 4 AES blocks
;
; RDI: Address of the input
; R10: Base address of the key schedule (for round key)
; XMM0-7: The 4 AES input blocks
; XMM11-15: Keys for rounds 1-5
; RBX: Address of key for round 6
; XMM9: Final Round key
; Flags must be set by 'CMP RAX,12', with RAX holding the number of rounds
;
; only registers XMM0-3 will be changed. Flags will not be changed.
m_aes_dec_block_4   proc
align 16
    aes_load_4      rdi,[r10]

align 16    
    ;;aes_4_dec       xmm11
    ;;aes_4_dec       xmm12
    ;;aes_4_dec       xmm13
    ;;aes_4_dec       xmm14
    ;;aes_4_dec       xmm15
    ;;aes_4_dec       [rbx+0]
    ;;aes_4_dec       [rbx+16]
    ;;aes_4_dec       [rbx+32]
    ;;aes_4_dec       [rbx+48]
DB 66h,041h,00Fh,038h,0DEh,0C3h
DB 66h,041h,00Fh,038h,0DEh,0CBh
DB 66h,041h,00Fh,038h,0DEh,0D3h
DB 66h,041h,00Fh,038h,0DEh,0DBh

DB 66h,041h,00Fh,038h,0DEh,0C4h
DB 66h,041h,00Fh,038h,0DEh,0CCh
DB 66h,041h,00Fh,038h,0DEh,0D4h
DB 66h,041h,00Fh,038h,0DEh,0DCh

DB 66h,041h,00Fh,038h,0DEh,0C5h
DB 66h,041h,00Fh,038h,0DEh,0CDh
DB 66h,041h,00Fh,038h,0DEh,0D5h
DB 66h,041h,00Fh,038h,0DEh,0DDh

DB 66h,041h,00Fh,038h,0DEh,0C6h
DB 66h,041h,00Fh,038h,0DEh,0CEh
DB 66h,041h,00Fh,038h,0DEh,0D6h
DB 66h,041h,00Fh,038h,0DEh,0DEh

DB 66h,041h,00Fh,038h,0DEh,0C7h
DB 66h,041h,00Fh,038h,0DEh,0CFh
DB 66h,041h,00Fh,038h,0DEh,0D7h
DB 66h,041h,00Fh,038h,0DEh,0DFh

DB 66h,00Fh,038h,0DEh,003h
DB 66h,00Fh,038h,0DEh,00Bh
DB 66h,00Fh,038h,0DEh,013h
DB 66h,00Fh,038h,0DEh,01Bh

DB 66h,00Fh,038h,0DEh,043h,010h
DB 66h,00Fh,038h,0DEh,04Bh,010h
DB 66h,00Fh,038h,0DEh,053h,010h
DB 66h,00Fh,038h,0DEh,05Bh,010h

DB 66h,00Fh,038h,0DEh,043h,020h
DB 66h,00Fh,038h,0DEh,04Bh,020h
DB 66h,00Fh,038h,0DEh,053h,020h
DB 66h,00Fh,038h,0DEh,05Bh,020h

DB 66h,00Fh,038h,0DEh,043h,030h
DB 66h,00Fh,038h,0DEh,04Bh,030h
DB 66h,00Fh,038h,0DEh,053h,030h
DB 66h,00Fh,038h,0DEh,05Bh,030h
    jb              aes_dec_4_last
    ;;aes_4_dec       [rbx+64]
    ;;aes_4_dec       [rbx+80]
DB 66h,00Fh,038h,0DEh,043h,040h
DB 66h,00Fh,038h,0DEh,04Bh,040h
DB 66h,00Fh,038h,0DEh,053h,040h
DB 66h,00Fh,038h,0DEh,05Bh,040h

DB 66h,00Fh,038h,0DEh,043h,050h
DB 66h,00Fh,038h,0DEh,04Bh,050h
DB 66h,00Fh,038h,0DEh,053h,050h
DB 66h,00Fh,038h,0DEh,05Bh,050h
    je              aes_dec_4_last
    ;;aes_4_dec       [rbx+96]
    ;;aes_4_dec       [rbx+112]
DB 66h,00Fh,038h,0DEh,043h,060h
DB 66h,00Fh,038h,0DEh,04Bh,060h
DB 66h,00Fh,038h,0DEh,053h,060h
DB 66h,00Fh,038h,0DEh,05Bh,060h

DB 66h,00Fh,038h,0DEh,043h,070h
DB 66h,00Fh,038h,0DEh,04Bh,070h
DB 66h,00Fh,038h,0DEh,053h,070h
DB 66h,00Fh,038h,0DEh,05Bh,070h

aes_dec_4_last:
    ;;aes_4_dec_last  xmm9
DB 66h,041h,00Fh,038h,0DFh,0C1h
DB 66h,041h,00Fh,038h,0DFh,0C9h
DB 66h,041h,00Fh,038h,0DFh,0D1h
DB 66h,041h,00Fh,038h,0DFh,0D9h

    ret
m_aes_dec_block_4   endp

; This procedure performs the decryption of 1 AES block
; 
; Registers must be set as for m_aes_dec_block_4.
; Only XMM0 is processed as input.
m_aes_dec_block_1   proc
align 16

    movdqu          xmm0,[rdi]
    pxor            xmm0,[r10]

align 16    
    ;;aesdec          xmm0, xmm11
    ;;aesdec          xmm0, xmm12
    ;;aesdec          xmm0, xmm13
    ;;aesdec          xmm0, xmm14
    ;;aesdec          xmm0, xmm15
    ;;aesdec          xmm0, [rbx+0]
    ;;aesdec          xmm0, [rbx+16]
    ;;aesdec          xmm0, [rbx+32]
    ;;aesdec          xmm0, [rbx+48]
DB 66h,041h,00Fh,038h,0DEh,0C3h
DB 66h,041h,00Fh,038h,0DEh,0C4h
DB 66h,041h,00Fh,038h,0DEh,0C5h
DB 66h,041h,00Fh,038h,0DEh,0C6h
DB 66h,041h,00Fh,038h,0DEh,0C7h
DB 66h,00Fh,038h,0DEh,003h
DB 66h,00Fh,038h,0DEh,043h,010h
DB 66h,00Fh,038h,0DEh,043h,020h
DB 66h,00Fh,038h,0DEh,043h,030h
    jb              aes_dec_last
    ;;aesdec          xmm0, [rbx+64]
    ;;aesdec          xmm0, [rbx+80]

DB 66h,00Fh,038h,0DEh,043h,040h
DB 66h,00Fh,038h,0DEh,043h,050h

    je              aes_dec_last
    ;;aesdec          xmm0, [rbx+96]
    ;;aesdec          xmm0, [rbx+112]

DB 66h,00Fh,038h,0DEh,043h,060h
DB 66h,00Fh,038h,0DEh,043h,070h

aes_dec_last:
    ;;aesdeclast      xmm0,xmm9

DB 66h,041h,00Fh,038h,0DFh,0C1h

    ret
m_aes_dec_block_1     endp

; Performs one AES encryption round on XMM0-7
; KEY specifies the XMM register or address of the subkey for this round
aes_4_enc   MACRO   KEY
            aesenc  xmm0,KEY
            aesenc  xmm1,KEY
            aesenc  xmm2,KEY
            aesenc  xmm3,KEY
            endm

; Performs the last AES decryption round on XMM0-7
; KEY specifies the XMM register or address of the subkey for this round
aes_4_enc_last  macro   KEY
                aesenclast  xmm0,KEY
                aesenclast  xmm1,KEY
                aesenclast  xmm2,KEY
                aesenclast  xmm3,KEY
                endm

; This procedure performs the encryption of 4 AES blocks
;
; input and output behavior is as for m_aes_dec_block_4
m_aes_enc_block_4   proc
align 16
    aes_load_4      rdi,[r10]

align 16    
    ;;aes_4_enc       xmm11
    ;;aes_4_enc       xmm12
    ;;aes_4_enc       xmm13
    ;;aes_4_enc       xmm14
    ;;aes_4_enc       xmm15
    ;;aes_4_enc       [rbx+0]
    ;;aes_4_enc       [rbx+16]
    ;;aes_4_enc       [rbx+32]
    ;;aes_4_enc       [rbx+48]
DB 66h,041h,00Fh,038h,0DCh,0C3h
DB 66h,041h,00Fh,038h,0DCh,0CBh
DB 66h,041h,00Fh,038h,0DCh,0D3h
DB 66h,041h,00Fh,038h,0DCh,0DBh

DB 66h,041h,00Fh,038h,0DCh,0C4h
DB 66h,041h,00Fh,038h,0DCh,0CCh
DB 66h,041h,00Fh,038h,0DCh,0D4h
DB 66h,041h,00Fh,038h,0DCh,0DCh

DB 66h,041h,00Fh,038h,0DCh,0C5h
DB 66h,041h,00Fh,038h,0DCh,0CDh
DB 66h,041h,00Fh,038h,0DCh,0D5h
DB 66h,041h,00Fh,038h,0DCh,0DDh

DB 66h,041h,00Fh,038h,0DCh,0C6h
DB 66h,041h,00Fh,038h,0DCh,0CEh
DB 66h,041h,00Fh,038h,0DCh,0D6h
DB 66h,041h,00Fh,038h,0DCh,0DEh

DB 66h,041h,00Fh,038h,0DCh,0C7h
DB 66h,041h,00Fh,038h,0DCh,0CFh
DB 66h,041h,00Fh,038h,0DCh,0D7h
DB 66h,041h,00Fh,038h,0DCh,0DFh

DB 66h,00Fh,038h,0DCh,003h
DB 66h,00Fh,038h,0DCh,00Bh
DB 66h,00Fh,038h,0DCh,013h
DB 66h,00Fh,038h,0DCh,01Bh

DB 66h,00Fh,038h,0DCh,043h,010h
DB 66h,00Fh,038h,0DCh,04Bh,010h
DB 66h,00Fh,038h,0DCh,053h,010h
DB 66h,00Fh,038h,0DCh,05Bh,010h

DB 66h,00Fh,038h,0DCh,043h,020h
DB 66h,00Fh,038h,0DCh,04Bh,020h
DB 66h,00Fh,038h,0DCh,053h,020h
DB 66h,00Fh,038h,0DCh,05Bh,020h

DB 66h,00Fh,038h,0DCh,043h,030h
DB 66h,00Fh,038h,0DCh,04Bh,030h
DB 66h,00Fh,038h,0DCh,053h,030h
DB 66h,00Fh,038h,0DCh,05Bh,030h


    jb              aes_enc_4_last
    ;;aes_4_enc       [rbx+64]
    ;;aes_4_enc       [rbx+80]
DB 66h,00Fh,038h,0DCh,043h,040h
DB 66h,00Fh,038h,0DCh,04Bh,040h
DB 66h,00Fh,038h,0DCh,053h,040h
DB 66h,00Fh,038h,0DCh,05Bh,040h

DB 66h,00Fh,038h,0DCh,043h,050h
DB 66h,00Fh,038h,0DCh,04Bh,050h
DB 66h,00Fh,038h,0DCh,053h,050h
DB 66h,00Fh,038h,0DCh,05Bh,050h

    je              aes_enc_4_last
    ;;aes_4_enc       [rbx+96]
    ;;aes_4_enc       [rbx+112]
    
DB 66h,00Fh,038h,0DCh,043h,060h
DB 66h,00Fh,038h,0DCh,04Bh,060h
DB 66h,00Fh,038h,0DCh,053h,060h
DB 66h,00Fh,038h,0DCh,05Bh,060h

DB 66h,00Fh,038h,0DCh,043h,070h
DB 66h,00Fh,038h,0DCh,04Bh,070h
DB 66h,00Fh,038h,0DCh,053h,070h
DB 66h,00Fh,038h,0DCh,05Bh,070h

aes_enc_4_last:
    ;;aes_4_enc_last  xmm9
    
DB 66h,041h,00Fh,038h,0DDh,0C1h
DB 66h,041h,00Fh,038h,0DDh,0C9h
DB 66h,041h,00Fh,038h,0DDh,0D1h
DB 66h,041h,00Fh,038h,0DDh,0D9h

    ret
m_aes_enc_block_4   endp

; This procedure performs the encryption of 1 AES block
; 
; Works like m_aes_dec_block_1.
m_aes_enc_block_1   proc
align 16

    movdqu          xmm0,[rdi]
    pxor            xmm0,[r10]

align 16    
    ;;aesenc          xmm0, xmm11
    ;;aesenc          xmm0, xmm12
    ;;aesenc          xmm0, xmm13
    ;;aesenc          xmm0, xmm14
    ;;aesenc          xmm0, xmm15
    ;;aesenc          xmm0, [rbx+0]
    ;;aesenc          xmm0, [rbx+16]
    ;;aesenc          xmm0, [rbx+32]
    ;;aesenc          xmm0, [rbx+48]
DB 66h,041h,00Fh,038h,0DCh,0C3h
DB 66h,041h,00Fh,038h,0DCh,0C4h
DB 66h,041h,00Fh,038h,0DCh,0C5h
DB 66h,041h,00Fh,038h,0DCh,0C6h
DB 66h,041h,00Fh,038h,0DCh,0C7h
DB 66h,00Fh,038h,0DCh,003h
DB 66h,00Fh,038h,0DCh,043h,010h
DB 66h,00Fh,038h,0DCh,043h,020h
DB 66h,00Fh,038h,0DCh,043h,030h

    jb              aes_enc_last
    ;;aesenc          xmm0, [rbx+64]
    ;;aesenc          xmm0, [rbx+80]
DB 66h,00Fh,038h,0DCh,043h,040h
DB 66h,00Fh,038h,0DCh,043h,050h

    je              aes_enc_last
    ;;aesenc          xmm0, [rbx+96]
    ;;aesenc          xmm0, [rbx+112]
DB 66h,00Fh,038h,0DCh,043h,060h
DB 66h,00Fh,038h,0DCh,043h,070h

aes_enc_last:
    ;;aesenclast      xmm0,xmm9
    
DB 66h,041h,00Fh,038h,0DDh,0C1h

    ret
m_aes_enc_block_1     endp

m_prepare_roundkey_128	proc
	pshufd		xmm2,xmm2,255
	movdqa		xmm3,xmm1
	pslldq		xmm3,4
	pxor		xmm1,xmm3
	pslldq		xmm3,4
	pxor		xmm1,xmm3
	pslldq		xmm3,4
	pxor		xmm1,xmm3
	pxor		xmm1,xmm2
	ret
m_prepare_roundkey_128	endp

m_prepare_roundkey_192	proc
	pshufd		xmm2,xmm2,55h
	movdqu		xmm4,xmm1
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pxor		xmm1,xmm2
	pshufd		xmm2,xmm1,0FFh
	movdqu		xmm4,xmm3
	pslldq		xmm4,4
	pxor		xmm3,xmm4
	pxor		xmm3,xmm2
	ret
m_prepare_roundkey_192	endp

m_make_rk256_a	proc
	pshufd		xmm2,xmm2,0FFh
	movdqa		xmm4,xmm1
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pslldq		xmm4,4
	pxor		xmm1,xmm4
	pxor		xmm1,xmm2
	ret
m_make_rk256_a	endp

m_make_rk256_b	proc
	pshufd		xmm2,xmm2,0AAh
	movdqa		xmm4,xmm3
	pslldq		xmm4,4
	pxor		xmm3,xmm4
	pslldq		xmm4,4
	pxor		xmm3,xmm4
	pslldq		xmm4,4
	pxor		xmm3,xmm4
	pxor		xmm3,xmm2
	ret
m_make_rk256_b	endp



; Parameter1: const unsigned char * userkey
; Parameter2: unsigned char * key_schedule
m_aes_128_cpu_key_expansion proc
	movdqu		xmm1,[rcx]
	movdqa		[rdx],xmm1

;;;	aeskeygenassist	xmm2,xmm1,1
	DB 66h,0Fh,3Ah,0DFh,0D1h,01h
	call		m_prepare_roundkey_128
	movdqa		[rdx+16],xmm1
;;;	aeskeygenassist	xmm2,xmm1,2
	DB 66h,0Fh,3Ah,0DFh,0D1h,02h
	call		m_prepare_roundkey_128
	movdqa		[rdx+32],xmm1
;;;	aeskeygenassist	xmm2,xmm1,4
	DB 66h,0Fh,3Ah,0DFh,0D1h,04h
	call		m_prepare_roundkey_128
	movdqa		[rdx+48],xmm1
;;;	aeskeygenassist	xmm2,xmm1,8
	DB 66h,0Fh,3Ah,0DFh,0D1h,08h
	call		m_prepare_roundkey_128
	movdqa		[rdx+64],xmm1
;;;	aeskeygenassist	xmm2,xmm1,16
	DB 66h,0Fh,3Ah,0DFh,0D1h,10h
	call		m_prepare_roundkey_128
	movdqa		[rdx+80],xmm1
;;;	aeskeygenassist	xmm2,xmm1,32
	DB 66h,0Fh,3Ah,0DFh,0D1h,20h
	call		m_prepare_roundkey_128
	movdqa		[rdx+96],xmm1
;;;	aeskeygenassist	xmm2,xmm1,64
	DB 66h,0Fh,3Ah,0DFh,0D1h,40h
	call		m_prepare_roundkey_128
	movdqa		[rdx+112],xmm1
;;;	aeskeygenassist	xmm2,xmm1,80h
	DB 66h,0Fh,3Ah,0DFh,0D1h,80h
	call		m_prepare_roundkey_128
	movdqa		[rdx+128],xmm1
;;;	aeskeygenassist	xmm2,xmm1,1Bh
	DB 66h,0Fh,3Ah,0DFh,0D1h,1Bh
	call		m_prepare_roundkey_128
	movdqa		[rdx+144],xmm1
;;;	aeskeygenassist	xmm2,xmm1,36h
	DB 66h,0Fh,3Ah,0DFh,0D1h,36h
	call		m_prepare_roundkey_128
	movdqa		[rdx+160],xmm1
	ret
m_aes_128_cpu_key_expansion endp



; Parameter1: const unsigned char * userkey
; Parameter2: unsigned char * key_schedule
m_aes_192_cpu_key_expansion	proc
	movdqu		xmm1,[rcx]
	movdqu		xmm3,[rcx+16]

	movdqa		[rdx],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,1
	DB 66h,0Fh,3Ah,0DFh,0D3h,01h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[rdx+16],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[rdx+32],xmm6

;;;	aeskeygenassist	xmm2,xmm3,2
	DB 66h,0Fh,3Ah,0DFh,0D3h,02h
	call		m_prepare_roundkey_192
	movdqa		[rdx+48],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,4
	DB 66h,0Fh,3Ah,0DFh,0D3h,04h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[rdx+64],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[rdx+80],xmm6

;;;	aeskeygenassist	xmm2,xmm3,8
	DB 66h,0Fh,3Ah,0DFh,0D3h,08h
	call		m_prepare_roundkey_192
	movdqa		[rdx+96],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,16
	DB 66h,0Fh,3Ah,0DFh,0D3h,10h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[rdx+112],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[rdx+128],xmm6

;;;	aeskeygenassist	xmm2,xmm3,32
	DB 66h,0Fh,3Ah,0DFh,0D3h,20h
	call		m_prepare_roundkey_192
	movdqa		[rdx+144],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,64
	DB 66h,0Fh,3Ah,0DFh,0D3h,40h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[rdx+160],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[rdx+176],xmm6

;;;	aeskeygenassist	xmm2,xmm3,128
	DB 66h,0Fh,3Ah,0DFh,0D3h,80h
	call		m_prepare_roundkey_192
	movdqa		[rdx+192],xmm1
	movdqa		[rdx+208],xmm3
	ret
m_aes_192_cpu_key_expansion	endp


; Parameter1: const unsigned char * userkey
; Parameter2: unsigned char * key_schedule
m_aes_256_cpu_key_expansion	proc
	movdqu		xmm1,[rcx]
	movdqu		xmm3,[rcx+16]

	movdqa		[rdx],xmm1
	movdqa		[rdx+16],xmm3

;;;	aeskeygenassist	xmm2,xmm3,1
	DB 66h,0Fh,3Ah,0DFh,0D3h,01h
	call		m_make_rk256_a
	movdqa		[rdx+32],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+48],xmm3

;;;	aeskeygenassist	xmm2,xmm3,2
	DB 66h,0Fh,3Ah,0DFh,0D3h,02h
	call		m_make_rk256_a
	movdqa		[rdx+64],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+80],xmm3

;;;	aeskeygenassist	xmm2,xmm3,4
	DB 66h,0Fh,3Ah,0DFh,0D3h,04h
	call		m_make_rk256_a
	movdqa		[rdx+96],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+112],xmm3

;;;	aeskeygenassist	xmm2,xmm3,8
	DB 66h,0Fh,3Ah,0DFh,0D3h,08h
	call		m_make_rk256_a
	movdqa		[rdx+128],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+144],xmm3

;;;	aeskeygenassist	xmm2,xmm3,16
	DB 66h,0Fh,3Ah,0DFh,0D3h,10h
	call		m_make_rk256_a
	movdqa		[rdx+160],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+176],xmm3

;;;	aeskeygenassist	xmm2,xmm3,32
	DB 66h,0Fh,3Ah,0DFh,0D3h,20h
	call		m_make_rk256_a
	movdqa		[rdx+192],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[rdx+208],xmm3

;;;	aeskeygenassist	xmm2,xmm3,64
	DB 66h,0Fh,3Ah,0DFh,0D3h,40h
	call		m_make_rk256_a
	movdqa		[rdx+224],xmm1

	ret
m_aes_256_cpu_key_expansion	endp




; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: rounds
m_aes_ecb_cpu_encrypt	proc
    pushall

    mov         rdi,rcx           ; Input
    mov         rsi,rdx           ; Output
    mov         rbx,r8            ; Key
    mov         rcx,r9            ; Blockcount
    mov         eax,[rbp+16+32]   ; Rounds
    
    call        aes_read_keys
    cmp         rcx,0
    jz          ecb_enc_4_loop_end
    cmp         rax,12

align 16
ecb_enc_4_loop_start:
    call        m_aes_enc_block_4
    lea         rdi,[rdi+40h]
    aes_store_4 rsi
    lea         rsi,[rsi+40h]
    loop        ecb_enc_4_loop_start

ecb_enc_4_loop_end:

    cmp         r9,0
    je          ecb_enc_end_4
    mov         rcx, r9
    cmp         rax,12

ecb_enc_loop_4_2:
    call        m_aes_enc_block_1
    lea         rdi,[rdi+16]
    movdqu      [rsi],xmm0
    lea         rsi,[rsi+16]
    loop        ecb_enc_loop_4_2

ecb_enc_end_4:
    popall
    ret
m_aes_ecb_cpu_encrypt	endp



; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: rounds
m_aes_ecb_cpu_decrypt    proc
    pushall

    mov         rdi,rcx           ; Input
    mov         rsi,rdx           ; Output
    mov         rbx,r8            ; Key
    mov         rcx,r9            ; Blockcount
    mov         eax,[rbp+16+32]   ; Rounds
    
    call        aes_read_keys
    cmp         rcx,0
    jz          ecb_dec_4_loop_end
    cmp         rax,12

align 16
ecb_dec_4_loop_start:
    call        m_aes_dec_block_4
    lea         rdi,[rdi+40h]
    aes_store_4 rsi
    lea         rsi,[rsi+40h]
    loop        ecb_dec_4_loop_start

ecb_dec_4_loop_end:

    cmp         r9,0
    je          ecb_dec_end_4
    mov         rcx, r9
    cmp         rax,12

ecb_dec_loop_4_2:
    call        m_aes_dec_block_1
    lea         rdi,[rdi+16]
    movdqu      [rsi],xmm0
    lea         rsi,[rsi+16]
    loop        ecb_dec_loop_4_2

ecb_dec_end_4:
    popall
    ret
m_aes_ecb_cpu_decrypt    endp




; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
m_aes_cbc_cpu_encrypt	proc
	push		rbp
	mov		rbp,rsp
	push		rbx
	push		rsi
	push		rdi

	mov		rdi,rcx			; Input
	mov		rsi,rdx			; Output
	mov		rbx,r8			; Key
	mov		ecx,r9d			; Blockcount
	mov		rdx,[rbp+16+32]		; IV
	mov		eax,[rbp+24+32]		; Rounds

	cmp		ecx,0
	je		cbc_enc_end

	sub		rsi,16
	movdqu		xmm1,[rdx]

cbc_enc_loop:
	movdqu		xmm2,[rdi]
	pxor		xmm1,xmm2
	pxor		xmm1,[rbx]
	add		rsi,16
	add		rdi,16
;;;	aesenc		xmm1,[rbx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
;;;	aesenc		xmm1,[rbx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[rbx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
;;;	aesenc		xmm1,[rbx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[rbx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
;;;	aesenc		xmm1,[rbx+96]
	DB 66h,0Fh,38h,0DCh,4Bh,60h
;;;	aesenc		xmm1,[rbx+112]
	DB 66h,0Fh,38h,0DCh,4Bh,70h
	add		rbx,128
	cmp		eax,12
;;;	aesenc		xmm1,[rbx]
	DB 66h,0Fh,38h,0DCh,0Bh
;;;	aesenc		xmm1,[rbx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
	movdqa		xmm2,[rbx+32]
	jb		cbc_enc_last
	cmp		eax,14
;;;	aesenc		xmm1,[rbx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[rbx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
	movdqa		xmm2,[rbx+64]
	jb		cbc_enc_last
;;;	aesenc		xmm1,[rbx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[rbx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
	movdqa		xmm2,[rbx+96]
cbc_enc_last:
	sub		rbx,128
;;;	aesenclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DDh,0CAh
	dec		ecx
	movdqu		[rsi],xmm1
	jne		cbc_enc_loop

	movdqu		[rdx],xmm1		; store back IV


cbc_enc_end:
	pop		rdi
	pop		rsi
	pop		rbx
	pop		rbp
	ret
m_aes_cbc_cpu_encrypt	endp

m_xor_4_blocks          proc
    movdqu      xmm4,[rdi]
    movdqu      xmm5,[rdi+16]
    movdqu      xmm6,[rdi+32]
    pxor        xmm0,xmm8
    pxor        xmm1,xmm4
    pxor        xmm2,xmm5
    pxor        xmm3,xmm6
    movdqu      xmm8,[rdi+48]
    movdqa      xmm10,xmm8

    ret
m_xor_4_blocks          endp

; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
m_aes_cbc_cpu_decrypt	proc
    pushall

    mov         rdi,rcx         ; Input
    mov         rsi,rdx         ; Output
    mov         rbx,r8          ; Key
    mov         ecx,r9d         ; Blockcount
    mov         rdx,[rbp+16+32] ; IV
    mov         eax,[rbp+24+32] ; Rounds

    movdqu      xmm8,[rdx]
    movdqa      xmm10,xmm8
    call        aes_read_keys
    cmp         rcx,0
    jz          cbc_dec_4_loop_end
    cmp         rax,12

align 16
cbc_dec_4_loop_start:
    call        m_aes_dec_block_4
    call        m_xor_4_blocks
    lea         rdi,[rdi+40h]
    aes_store_4 rsi
    lea         rsi,[rsi+40h]
    loop        cbc_dec_4_loop_start

cbc_dec_4_loop_end:

    cmp         r9,0
    je          cbc_dec_end
    mov         rcx, r9
    cmp         rax,12

cbc_dec_loop_1:
    call        m_aes_dec_block_1
    pxor        xmm0,xmm8
    movdqu      xmm8,[rdi]
    movdqa      xmm10,xmm8
    lea         rdi,[rdi+16]
    movdqu      [rsi],xmm0
    lea         rsi,[rsi+16]
    loop        cbc_dec_loop_1

cbc_dec_end:
    movdqu      [rdx],xmm10
    popall
    ret
m_aes_cbc_cpu_decrypt	endp

increment_counters_4  proc
    inc         r12d
    bswap       r12d
    mov         [rdi+0Ch],r12d
    bswap       r12d
    inc         r12d
    bswap       r12d
    mov         [rdi+1Ch],r12d
    bswap       r12d
    inc         r12d
    bswap       r12d
    mov         [rdi+2Ch],r12d
    bswap       r12d
    inc         r12d
    bswap       r12d
    mov         [rdi+3Ch],r12d
    bswap       r12d
    
    ; restore needed flags
    cmp         rax,12
    ret
increment_counters_4  endp

ctr_xor_input_4     proc
    movdqu      xmm4,[r11]
    movdqu      xmm5,[r11+10h]
    movdqu      xmm6,[r11+20h]
    movdqu      xmm7,[r11+30h]
    pxor        xmm0,xmm4
    pxor        xmm1,xmm5
    pxor        xmm2,xmm6
    pxor        xmm3,xmm7

    ret
ctr_xor_input_4     endp

; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
m_aes_ctr_cpu  proc
    pushall

    mov         r11,rcx         ; Input
    mov         rsi,rdx         ; Output
    mov         rbx,r8          ; Key
    mov         rcx,r9          ; Blockcount
    mov         rdx,[rbp+16+32] ; IV
    mov         eax,[rbp+24+32] ; Rounds

    ; preload the first IV block, decrement the counter
    movdqu      xmm10,[rdx]
    mov         rdi,rsp
    sub         rdi,80h
    movdqu      [rdi],xmm10
    mov         r12d,[rdi+12]
    bswap       r12d
    dec         r12d

    call        aes_read_keys
    cmp         rcx,0
    jz          ctr_4_loop_end

    ; Load the remaining IVs
    movdqu      [rdi+010h],xmm10
    movdqu      [rdi+020h],xmm10
    movdqu      [rdi+030h],xmm10
    
align 16
ctr_4_loop_start:
    call        increment_counters_4
    call        m_aes_enc_block_4
    call        ctr_xor_input_4
    aes_store_4 rsi
    lea         rsi,[rsi+40h]
    lea         r11,[r11+40h]
    loop        ctr_4_loop_start

ctr_4_loop_end:

    cmp         r9,0
    je          ctr_end
    mov         rcx, r9
    cmp         rax,12

ctr_loop_1:
    inc         r12d
    bswap       r12d
    mov         [rdi+0Ch],r12d
    bswap       r12d
    cmp         rax,12
    call        m_aes_enc_block_1
    movdqu      xmm1,[r11]
    pxor        xmm0,xmm1
    movdqu      [rsi],xmm0
    lea         rsi,[rsi+16]
    lea         r11,[r11+16]
    loop        ctr_loop_1

ctr_end:

    inc         r12d
    bswap       r12d
    mov         [rdi+0Ch],r12d
    bswap       r12d
    cmp         rax,12
    call        m_aes_enc_block_1
    movdqu      [rdx],xmm0
    popall
    ret
m_aes_ctr_cpu  endp

; Parameter1: normal key schedule
; Parameter2: reverted key schedule
; Parameter3: number of rounds
m_aes_cpu_revert_key	proc
	push	rbp
	mov	rbp,rsp
	push	rbx

	mov	rax,rcx		; normal KS
	mov	rbx,rdx		; inverted KS
	mov	ecx,r8d		; nr

	sub	rdx,rdx
	mov	edx,ecx
	shl	rdx,4		; * 16
	add	rbx,rdx		; to topmost element

	movdqu	xmm1,[rax]
	movdqu	[rbx],xmm1
	add	rax,16
	sub	rbx,16
	dec	ecx

revert_loop:
	movdqu	xmm1,[rax]
;;;	aesimc	xmm1,xmm1
	DB 66h,0Fh,38h,0DBh,0C9h
	movdqu	[rbx],xmm1
	add	rax,16
	sub	rbx,16
	dec	ecx
	jnz	revert_loop

	movdqu	xmm1,[rax]
	movdqu	[rbx],xmm1

	pop	rbx
	pop	rbp
	ret
m_aes_cpu_revert_key	endp


GCM_BSWAP BYTE 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

; Code is taken from 'Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode'
; inputs have been modified and some registers renamed to reduce the register footprint
m_ghash_asm proc
;xmm15 holds Hash key H (128 bits)
;xmm1 holds new X (128 bits)
;xmm14 holds the old state and takes the new
    ;;pshufb      xmm1, [RSP+058H]    ; Byte-swap input
DB 066H,00FH,038H,000H,04CH,024H,058H

    pxor        xmm1, [rsp+048H]
    movdqa      xmm3, [RSP+038H]
    ;;pclmulqdq   xmm3, xmm1, 0       ; xmm3 holds D = a0*b0
DB 066H,00FH,03AH,044H,0D9H,000H

    movdqa      xmm6, [RSP+038H]
    ;;pclmulqdq   xmm6, xmm1, 17      ; xmm6 holds C= a1*b1
DB 066H,00FH,03AH,044H,0F1H,011H

    movdqa      xmm7, xmm1
    psrldq      xmm1, 8             ; b0 = b1
    pxor        xmm1, xmm7          ; b0 = b1+b0
    ;;pclmulqdq   xmm1, [RSP+008H], 0 ; xmm1 holds E = (a0+a1)*(b0+b1)
DB 066H,00FH,03AH,044H,04CH,024H,008H,000H

    pxor        xmm1, xmm3          ; E += D
    pxor        xmm1, xmm6          ; E += C
    movdqa      xmm4, xmm1          ; load E = E+D+C
    psrldq      xmm1, 8             ; get e1+d1+c1 in low DQword
    pslldq      xmm4, 8             ; get e0+c0+d0 in high DQword
    pxor        xmm6, xmm1          ; x2 = c0+e1+d1+c1, x3 = c1
    pxor        xmm3, xmm4          ; x1 = d1+e0+d0+c0, x0 = d0
        
    ; <xmm6:xmm3> holds the result of 
; the carry
; shift the result by one bit position to the left cope for the fact
; that bits are reversed
    movdqa      xmm7, xmm3
    movdqa      xmm1, xmm6
    pslld       xmm3, 1
    pslld       xmm6, 1
    psrld       xmm7, 31
    psrld       xmm1, 31
    movdqa      xmm4, xmm7
    pslldq      xmm1, 4
    pslldq      xmm7, 4
    psrldq      xmm4, 12
    por         xmm3, xmm7
    por         xmm6, xmm1
    por         xmm6, xmm4
; first phase of the reduction
    movdqa      xmm7, xmm3
    movdqa      xmm1, xmm3
    movdqa      xmm4, xmm3   
    pslld       xmm7, 31            ; packed right shifting << 31 
    pslld       xmm1, 30            ; packed right shifting shift << 30
    pslld       xmm4, 25            ; packed right shifting shift << 25 
    pxor        xmm7, xmm1          ; xor the shifted versions
    pxor        xmm7, xmm4  
    movdqa      xmm1, xmm7
    pslldq      xmm7, 12
    psrldq      xmm1, 4
    pxor        xmm3, xmm7          ; first phase of the reduction complete 
    movdqa      xmm2, xmm3          ; second phase of the reduction
    movdqa      xmm4, xmm3
    movdqa      xmm5, xmm3  
    psrld       xmm2, 1             ; packed left shifting >> 1
    psrld       xmm4, 2             ; packed left shifting >> 2
    psrld       xmm5, 7             ; packed left shifting >> 7   
    pxor        xmm2, xmm4          ; xor the shifted versions
    pxor        xmm2, xmm5
    pxor        xmm2, xmm1
    pxor        xmm3, xmm2 
    pxor        xmm6, xmm3          ; the result is in xmm6 
    movdqa      [rsp+048H], xmm6    ; store the result

    ret
m_ghash_asm endp

; This function does not generate a stack frame. 
; The block must be in XMM0
; Number of rounds must be in r8
; AES keytab must be in rdx and 16-byte aligned
aes_enc_block proc

    cmp             r8, 12                      ; compare number of rounds with 12 for later jump
    pxor            xmm0,[rdx]                  ; XOR first round key into block

align 16
    ; Perform all AES enc rounds
    ;;aesenc          xmm0, [rdx+010h]
    ;;aesenc          xmm0, [rdx+020h]
    ;;aesenc          xmm0, [rdx+030h]
    ;;aesenc          xmm0, [rdx+040h]
    ;;aesenc          xmm0, [rdx+050h]
    ;;aesenc          xmm0, [rdx+060h]
    ;;aesenc          xmm0, [rdx+070h]
    ;;aesenc          xmm0, [rdx+080h]
    ;;aesenc          xmm0, [rdx+090h]
DB  66h,0Fh,38h,0DCh,42h,10h
DB  66h,0Fh,38h,0DCh,42h,20h
DB  66h,0Fh,38h,0DCh,42h,30h
DB  66h,0Fh,38h,0DCh,42h,40h
DB  66h,0Fh,38h,0DCh,42h,50h
DB  66h,0Fh,38h,0DCh,42h,60h
DB  66h,0Fh,38h,0DCh,42h,70h
DB  66h,0Fh,38h,0DCh,82h,80h,00h,00h,00h
DB  66h,0Fh,38h,0DCh,82h,90h,00h,00h,00h

    jb              aes_block_enc_last          ; jump, if less than 12 rounds (128 bit AES)
    ;;aesenc          xmm0, [rdx+0a0h]
    ;;aesenc          xmm0, [rdx+0b0h]
DB 066h,00Fh,038h,0DCh,082h,0A0h,000h,000h,000h
DB 066h,00Fh,038h,0DCh,082h,0B0h,000h,000h,000h

    je              aes_block_enc_last          ; jump, if 12 rounds (196 bit AES)
    ;;aesenc          xmm0, [rdx+0c0h]
    ;;aesenc          xmm0, [rdx+0d0h]
DB 066h,00Fh,038h,0DCh,082h,0C0h,000h,000h,000h
DB 066h,00Fh,038h,0DCh,082h,0D0h,000h,000h,000h

aes_block_enc_last:
    ;;aesenclast      xmm0,[rdx+r10]
DB 66H,41h,0Fh,38H,0DDH,04h,12h

    ret
aes_enc_block endp

aesenc_8   macro KEY
    aesenc          xmm0, KEY
    aesenc          xmm1, KEY
    aesenc          xmm2, KEY
    aesenc          xmm3, KEY
    aesenc          xmm4, KEY
    aesenc          xmm5, KEY
    aesenc          xmm6, KEY
    aesenc          xmm7, KEY
    endm

; This function does not generate a stack frame. 
; The block must be in XMM0
; Number of rounds must be in r8
; AES keytab must be in rdx and 16-byte aligned
aes_enc_8_blocks macro

    cmp             r8, 12                      ; compare number of rounds with 12 for later jump
    pxor            xmm0,[rdx]                  ; XOR first round key into blocks
    pxor            xmm1,[rdx]                  ; XOR first round key into blocks
    pxor            xmm2,[rdx]                  ; XOR first round key into blocks
    pxor            xmm3,[rdx]                  ; XOR first round key into blocks
    pxor            xmm4,[rdx]                  ; XOR first round key into blocks
    pxor            xmm5,[rdx]                  ; XOR first round key into blocks
    pxor            xmm6,[rdx]                  ; XOR first round key into blocks
    pxor            xmm7,[rdx]                  ; XOR first round key into blocks

align 16
    ; Perform all AES enc rounds
    ;;aesenc_8        [rdx+010h]
    ;;aesenc_8        [rdx+020h]
    ;;aesenc_8        [rdx+030h]
    ;;aesenc_8        [rdx+040h]
    ;;aesenc_8        [rdx+050h]
    ;;aesenc_8        [rdx+060h]
    ;;aesenc_8        [rdx+070h]
    ;;aesenc_8        [rdx+080h]
    ;;aesenc_8        [rdx+090h]
DB 066H,00FH,038H,0DCH,042H,010H
DB 066H,00FH,038H,0DCH,04AH,010H
DB 066H,00FH,038H,0DCH,052H,010H
DB 066H,00FH,038H,0DCH,05AH,010H
DB 066H,00FH,038H,0DCH,062H,010H
DB 066H,00FH,038H,0DCH,06AH,010H
DB 066H,00FH,038H,0DCH,072H,010H
DB 066H,00FH,038H,0DCH,07AH,010H
DB 066H,00FH,038H,0DCH,042H,020H
DB 066H,00FH,038H,0DCH,04AH,020H
DB 066H,00FH,038H,0DCH,052H,020H
DB 066H,00FH,038H,0DCH,05AH,020H
DB 066H,00FH,038H,0DCH,062H,020H
DB 066H,00FH,038H,0DCH,06AH,020H
DB 066H,00FH,038H,0DCH,072H,020H
DB 066H,00FH,038H,0DCH,07AH,020H
DB 066H,00FH,038H,0DCH,042H,030H
DB 066H,00FH,038H,0DCH,04AH,030H
DB 066H,00FH,038H,0DCH,052H,030H
DB 066H,00FH,038H,0DCH,05AH,030H
DB 066H,00FH,038H,0DCH,062H,030H
DB 066H,00FH,038H,0DCH,06AH,030H
DB 066H,00FH,038H,0DCH,072H,030H
DB 066H,00FH,038H,0DCH,07AH,030H
DB 066H,00FH,038H,0DCH,042H,040H
DB 066H,00FH,038H,0DCH,04AH,040H
DB 066H,00FH,038H,0DCH,052H,040H
DB 066H,00FH,038H,0DCH,05AH,040H
DB 066H,00FH,038H,0DCH,062H,040H
DB 066H,00FH,038H,0DCH,06AH,040H
DB 066H,00FH,038H,0DCH,072H,040H
DB 066H,00FH,038H,0DCH,07AH,040H
DB 066H,00FH,038H,0DCH,042H,050H
DB 066H,00FH,038H,0DCH,04AH,050H
DB 066H,00FH,038H,0DCH,052H,050H
DB 066H,00FH,038H,0DCH,05AH,050H
DB 066H,00FH,038H,0DCH,062H,050H
DB 066H,00FH,038H,0DCH,06AH,050H
DB 066H,00FH,038H,0DCH,072H,050H
DB 066H,00FH,038H,0DCH,07AH,050H
DB 066H,00FH,038H,0DCH,042H,060H
DB 066H,00FH,038H,0DCH,04AH,060H
DB 066H,00FH,038H,0DCH,052H,060H
DB 066H,00FH,038H,0DCH,05AH,060H
DB 066H,00FH,038H,0DCH,062H,060H
DB 066H,00FH,038H,0DCH,06AH,060H
DB 066H,00FH,038H,0DCH,072H,060H
DB 066H,00FH,038H,0DCH,07AH,060H
DB 066H,00FH,038H,0DCH,042H,070H
DB 066H,00FH,038H,0DCH,04AH,070H
DB 066H,00FH,038H,0DCH,052H,070H
DB 066H,00FH,038H,0DCH,05AH,070H
DB 066H,00FH,038H,0DCH,062H,070H
DB 066H,00FH,038H,0DCH,06AH,070H
DB 066H,00FH,038H,0DCH,072H,070H
DB 066H,00FH,038H,0DCH,07AH,070H
DB 066H,00FH,038H,0DCH,082H,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,090H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,090H,000H,000H,000H

    jb              aes_8_block_enc_last        ; jump, if less than 12 rounds (128 bit AES)
    ;;aesenc_8        [rdx+0a0h]
    ;;aesenc_8        [rdx+0b0h]
DB 066H,00FH,038H,0DCH,082H,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,0B0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,0B0H,000H,000H,000H

    je              aes_8_block_enc_last        ; jump, if 12 rounds (196 bit AES)
    ;;aesenc_8        [rdx+0c0h]
    ;;aesenc_8        [rdx+0d0h]
DB 066H,00FH,038H,0DCH,082H,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,08AH,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,092H,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,09AH,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0A2H,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0AAH,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0B2H,0D0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,0BAH,0D0H,000H,000H,000H

aes_8_block_enc_last:
    ;;aesenclast      xmm0,[rdx+r10]
    ;;aesenclast      xmm1,[rdx+r10]
    ;;aesenclast      xmm2,[rdx+r10]
    ;;aesenclast      xmm3,[rdx+r10]
    ;;aesenclast      xmm4,[rdx+r10]
    ;;aesenclast      xmm5,[rdx+r10]
    ;;aesenclast      xmm6,[rdx+r10]
    ;;aesenclast      xmm7,[rdx+r10]
DB 066H,041H,00FH,038H,0DDH,004H,012H
DB 066H,041H,00FH,038H,0DDH,00CH,012H
DB 066H,041H,00FH,038H,0DDH,014H,012H
DB 066H,041H,00FH,038H,0DDH,01CH,012H
DB 066H,041H,00FH,038H,0DDH,024H,012H
DB 066H,041H,00FH,038H,0DDH,02CH,012H
DB 066H,041H,00FH,038H,0DDH,034H,012H
DB 066H,041H,00FH,038H,0DDH,03CH,012H

    endm

; This macro is used for preparing the IV, Hash key and process the authentication data for AES GCM.
; It generates no own stack frame, but uses the stack of the calling function.
aes_gcm_prepare macro
    pxor        xmm0, xmm0
    movdqa      [rsp+060H], xmm0
    movdqa      xmm14, xmm0                     ; Initialize GHASH state to 0
    movdqa      [RSP+040H], xmm14

    ; Store round count in r8 and offset for the final roundkey in R10
    mov         r10, r8                         ; Write rounds to offset register
    shl         r10,4                           ; Offset for the final round key is 16 bytes per round, left shift multiplies by 16

    ; Generate Hash Key H. XMM0 is 0
    call aes_enc_block

    lea         rcx, [GCM_BSWAP]                ; Load address of byte swap mask, avoids problems with largeaddressaware
    movdqu      xmm13, [rcx]                    ; Load byte swap mask
    ;;pshufb      xmm0, xmm13                     ; byte swap the key
DB 066H,041H,00FH,038H,000H,0C5H

    movdqa      [RSP+030H], xmm0                ; Write hash key to [RSP+030H]
    movdqa      [RSP+050H], xmm13               ; Store BSWAP mask on stack
    movdqa      xmm1, xmm0
    psrldq      xmm1, 8                         ; a0 = a1
    pxor        xmm1, xmm0                      ; a0 = a1+a0
    movdqa      [RSP], xmm1                     ; Store a1+a0 on the stack


    ; Prepare IV
    mov         rcx, [rbp+040H]                 ; Load IV len
    cmp         rcx, 12                         ; Check for standard length (12 byte = 96 bit)
    jne         gcm_long_iv
    
    ; standard IV length, just copy the IV to the stack (96 bit = 64+32 bit)
    mov         DWORD PTR[rsp+6cH], 01000000H   ; Preset counter part (Sets lowest byte 1, Endianess!)
    mov         rcx, [r9]                       ; copy high 64 bit
    mov         [RSP+060H], rcx
    mov         ebx, [r9+8]                     ; copy low 32 bit
    mov         [rsp+068H], ebx
    jmp         gcm_counter_ready
gcm_long_iv:
    ; IV is not 96 bit, do GHASH. State is already initialized
    pxor        xmm0, xmm0                      ; 0 out XMM0
    mov         r12, rcx                        ; Store IV len
    shr         rcx,4                           ; Get the number of 16 byte blocks
    cmp         rcx,0
    je          gcm_partial_iv_block

gcm_iv_full_blocks:
    ; Process full blocks
    movdqu      xmm1, [r9]                      ; Load Block
    call        m_ghash_asm
    lea         r9, [r9+010h]                   ; Next block
    loop        gcm_iv_full_blocks              ; loop over all blocks

gcm_partial_iv_block:
    mov         rcx, r12                        ; load stored IV len
    and         rcx, 0fH                        ; do MOD 16 to get the number of bytes in a possible incomplete block
    cmp         rcx, 0
    je          gcm_push_long_iv
    movdqa      [rsp+060H], xmm0                ; push a 0 block to stack to generate 0-padding
    xor         r11,r11                         ; Clear r11 as offset register

gcm_partial_iv_loop:
    ; Move the partial block to the stack, bytewise
    mov         bl, [r9+r11]
    mov         [rsp+r11+060H], bl
    inc         r11
    loop        gcm_partial_iv_loop

    movdqa      xmm1, [rsp+060H]                ; Load the 0-padded block for GHASH
    call        m_ghash_asm

gcm_push_long_iv:
    movdqa      [rsp+060H], xmm0                ; Clear the block again for the IV len
    shl         r12,3                           ; Multiply IV len by 8 to get length in bits
    bswap       r12                             ; To Big Endian
    mov         [rsp++068H],r12                 ; Write to the block
    movdqa      xmm1, [rsp+060H]                ; Load length for GHASH
    call        m_ghash_asm
    movdqa      xmm14, [RSP+040H]
    ;;pshufb      xmm14, [RSP+050H]               ; Byte-swap the GHASH
DB 066H,044H,00FH,038H,000H,074H,024H,050H

    movdqa      [rsp+060H], xmm14               ; Write from GHASH state to stack as counter block
    pxor        xmm14, xmm14                    ; Reset GHASH
    movdqa      [RSP+040H], xmm14

gcm_counter_ready:

    ; Prepare the first encryption block, used for Auth tag
    ; From here on, we can use r9, as the processed IV is on the stack
    movdqa      xmm0, [rsp+060H]                ; Load IV
    
    call aes_enc_block                          ; Generate first counter block
    
    movdqa      [RSP+010H], xmm0                ; Store result on stack [RSP+010h] of AES GCM main function
    mov         r9d, [rsp+06cH]                 ; Load Counter to r9d
    bswap       r9d                             ; Turn counter to LE

    ; Feed authentication data to GHASH
    mov         rcx, [RBP+050H]                 ; Load auth data len
    cmp         rcx,0
    je          gcm_prepare_end                 ; only process, if there are auth data

    mov         rbx, rcx                        ; Store Auth data len
    shr         rcx, 4                          ; Calculate number of full blocks
    mov         r11, [RBP+048H]                 ; load auth data pointer
    cmp         rcx, 0
    je          gcm_partial_auth_block          ; Skip to partial blocks, if no full block is available
gcm_full_auth_blocks:
    movdqu      xmm1,[r11]                      ; Load full block of auth data
    call        m_ghash_asm                     ; load and GHASH block
    lea         r11, [r11+010H]                 ; Load next block address
    loop        gcm_full_auth_blocks            ; loop over all full blocks

gcm_partial_auth_block:
    mov         rcx, rbx                        ; Load auth data len
    and         rcx, 0fH                        ; Reduce to bytes in the incomplete block
    cmp         rcx, 0
    je          gcm_prepare_end                 ; only process, if there are auth data
    pxor        xmm1,xmm1
    movdqa      [RSP+020H], xmm1                ; 0 out the block on the stack
    xor         r12,r12                         ; Prepare offset
gcm_partial_auth_loop:
    ; Copy bytewise from the auth data buffer to the stack block
    mov         bl, [r11+r12]
    mov         [rsp+r12+20H], bl
    lea         r12, [r12+1]
    loop        gcm_partial_auth_loop
    movdqa      xmm1, [RSP+020H]
    call        m_ghash_asm                     ; Load and GHASH the 0-padded partial block

gcm_prepare_end:
    endm


aes_inc_load_8_ctr macro
    ; increment the counters
    inc         r9d
    bswap       r9d
    mov         [rsp+06cH], r9d
    bswap       r9d
    movdqa      xmm0, [rsp+060H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+07cH], r9d
    bswap       r9d
    movdqa      xmm1, [rsp+070H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+08cH], r9d
    bswap       r9d
    movdqa      xmm2, [rsp+080H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+09cH], r9d
    bswap       r9d
    movdqa      xmm3, [rsp+090H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+0acH], r9d
    bswap       r9d
    movdqa      xmm4, [rsp+0a0H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+0bcH], r9d
    bswap       r9d
    movdqa      xmm5, [rsp+0b0H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+0ccH], r9d
    bswap       r9d
    movdqa      xmm6, [rsp+0c0H]        ; Load the counter

    inc         r9d
    bswap       r9d
    mov         [rsp+0dcH], r9d
    bswap       r9d
    movdqa      xmm7, [rsp+0d0H]        ; Load the counter

    endm

aes_load_8_in_blocks macro

    movdqu      xmm8, [rdi+r12]      
    movdqu      xmm9, [rdi+r12+010H] 
    movdqu      xmm10, [rdi+r12+020H]
    movdqu      xmm11, [rdi+r12+030H]
    movdqu      xmm12, [rdi+r12+040H]
    movdqu      xmm13, [rdi+r12+050H]
    movdqu      xmm14, [rdi+r12+060H]
    movdqu      xmm15, [rdi+r12+070H]

    endm

aes_gcm_ghash_8_blocks macro
    movdqa      xmm1, xmm8
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm9
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm10
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm11
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm12
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm13
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm14
    call        m_ghash_asm             ; Add current block to GHASH
    movdqa      xmm1, xmm15
    call        m_ghash_asm             ; Add current block to GHASH

    endm

aes_write_8_blocks_out macro

    movdqu      [rsi+r12], xmm8         ; write Block to the output
    movdqu      [rsi+r12+010H], xmm9    ; write Block to the output
    movdqu      [rsi+r12+020H], xmm10   ; write Block to the output
    movdqu      [rsi+r12+030H], xmm11   ; write Block to the output
    movdqu      [rsi+r12+040H], xmm12   ; write Block to the output
    movdqu      [rsi+r12+050H], xmm13   ; write Block to the output
    movdqu      [rsi+r12+060H], xmm14   ; write Block to the output
    movdqu      [rsi+r12+070H], xmm15   ; write Block to the output

    endm

aes_ctr_xor_8_blocks macro
    
    pxor        xmm8, xmm0              ; Perform XOR
    pxor        xmm9, xmm1              ; Perform XOR
    pxor        xmm10, xmm2             ; Perform XOR
    pxor        xmm11, xmm3             ; Perform XOR
    pxor        xmm12, xmm4             ; Perform XOR
    pxor        xmm13, xmm5             ; Perform XOR
    pxor        xmm14, xmm6             ; Perform XOR
    pxor        xmm15, xmm7             ; Perform XOR

    endm

STACK_BYTES = 0c8H

; Performs AES GCM authenticated encryption using AES NI and PCLMULQDQ special instructions
;
; Parameters (after 'pushall'):
; abyp_in                   : RCX           -> RDI
; abyp_out                  : RDX           -> RSI
; abyp_key                  : R8            -> RDX
; szp_len_bytes             : R9            -> RAX (not ECX, that is used for LOOP)
; inp_number_of_rounds      : [RBP+030H]    -> R8
; abyp_ivec                 : [RBP+038H]    -> R9
; szp_ivec_len_bytes        : [RBP+040H]
; abyp_auth_data            : [RBP+048H]
; szp_auth_data_len_bytes   : [RBP+050H]
; abyp_mac_tag              : [RBP+058H]
; unp_mac_tag_len           : [RBP+060H]
;
; Other Variables:
; Hash key H                : [RSP+030H]
; GHASH state               : [RSP+040H]
; BSWAP mask                : [RSP+050H]
; Counter blocks (8)        : [RSP+060H]
; Int32 counter             : r9d
; initial counter block     : [RSP+010H]
; Temporary 16 byte block   : [RSP+020H]
;
; Note, that the 32 bit counter is set, after processing of the IV, so it is ok to use that register.
m_aes_gcm_cpu_auth_enc proc
    pushall

    ; Change parameter registers to match Unix calling conventions
    mov         rdi, rcx                ; Output
    mov         rsi, rdx                ; Input
    mov         rdx, r8                 ; Keytab
    mov         rax, r9                 ; Input length
    mov         r8d, [RBP+030H]         ; Number of rounds
    mov         r9, [RBP+038H]          ; IV
    
    ; Generate space for stack variables. Assure, RSP is 16 byte aligned
    ; Set 0 as needed
    sub         rsp, STACK_BYTES
    
    aes_gcm_prepare

    ; Perform CTR with GHASH
    cmp         rax, 0                  ; Assure, that we have plaintext
    je          gcm_enc_ghash_len       ; no plaintext, go to GHASH lengths
    xor         r12,r12                 ; prepare r12 as offset counter
    mov         rcx, rax                ; load byte counter to RCX
    shr         rcx, 4                  ; turn to full AES Blocks
    cmp         rcx, 0
    je          gcm_enc_partial_block   ; no full blocks to process
    cmp         rcx, 8
    jl          gcm_enc_full_block      ; Less, than 8 full blocks

    ; Write 7 more Counter blocks to stack
    movdqa      xmm0, [rsp+060H]
    movdqa      [rsp+070H],xmm0
    movdqa      [rsp+080H],xmm0
    movdqa      [rsp+090H],xmm0
    movdqa      [rsp+0a0H],xmm0
    movdqa      [rsp+0b0H],xmm0
    movdqa      [rsp+0c0H],xmm0
    movdqa      [rsp+0d0H],xmm0
gcm_enc_8_block:
    aes_inc_load_8_ctr
    aes_enc_8_blocks                    ; encrypt the counters
    aes_load_8_in_blocks
    aes_ctr_xor_8_blocks
    aes_write_8_blocks_out
    aes_gcm_ghash_8_blocks
    lea         r12, [r12+080H]         ; move offset to next 8 blocks
    sub         rcx, 8
    cmp         rcx, 8
    jge         gcm_enc_8_block         ; Loop, till all blocks are processed

    cmp         rcx, 0
    je          gcm_enc_partial_block   ; no full blocks left to process
    
gcm_enc_full_block:
    ; increment the counter
    inc         r9d
    bswap       r9d
    mov         [rsp+06cH], r9d
    bswap       r9d
    movdqa      xmm0, [rsp+060H]        ; Load the counter
    call        aes_enc_block           ; encrypt the counter
    movdqu      xmm1, [rdi+r12]         ; Load current input block
    pxor        xmm1, xmm0              ; Perform XOR
    movdqu      [rsi+r12], xmm1         ; write Block to the output
    call        m_ghash_asm             ; Add current block to GHASH
    lea         r12, [r12+010H]         ; move offset to next Block
    loop        gcm_enc_full_block      ; Loop, till all blocks are processed

gcm_enc_partial_block:
    ; Process the partial block, if there is one
    mov         r11, rax
    and         r11, 0fH
    cmp         r11, 0
    je          gcm_enc_ghash_len

    ; Read the partial block
    lea         rdi, [rdi+r12-1]
    mov         rcx, r11
gcm_enc_read_partial:
    mov         bl, [rdi+rcx]
    mov         [rsp+rcx+01fH], bl
    loop        gcm_enc_read_partial

    ; increment the counter
    inc         r9d
    bswap       r9d
    mov         [rsp+06cH], r9d
    bswap       r9d
    movdqa      xmm0, [rsp+060H]        ; Load the counter
    call        aes_enc_block           ; encrypt the counter
    movdqa      xmm1, [RSP+020H]        ; Load current input block
    pxor        xmm1, xmm0              ; Perform XOR
    movdqa      [RSP+020H], xmm1        ; write Block to the temporary stack variable
    mov         rcx, 16                
    sub         rcx, r11                ; Calculate number of missing bytes for a full block
    lea         rsi, [rsi+r12]
    mov         r12, 00fh
gcm_enc_zero_block:
    ; Generate 0 padding for the partial Block. Needed for the GHASH
    mov         BYTE PTR[rsp+r12+020H],0
    dec         r12
    loop        gcm_enc_zero_block
    movdqa      xmm1, [RSP+020H]
    call        m_ghash_asm
    mov         rcx, r11
gcm_enc_write_partial:
    ; Write the encrypted partial block
    mov         bl, [RSP+rcx+01fH]
    mov         [rsi+RCX-1], bl
    loop        gcm_enc_write_partial

gcm_enc_ghash_len:
    ; Write Auth data len and plaintext len to stack in BITS!, big endian
    mov         rbx, [RBP+050H]         ; Load auth data len
    shl         rbx, 3                  ; Change bytes to bits
    bswap       rbx                     ; Change to big endian
    mov         [RSP+020H], rbx         ; Push to stack
    shl         rax, 3                  ; Change plaintext len from bytes to bits
    bswap       rax                     ; Change it to big endian
    mov         [RSP+028H], rax         ; Write it to the stack
    movdqa      xmm1, [RSP+020H]        ; Load the length block
    call        m_ghash_asm
    movdqa      xmm14, [RSP+040H]
    ;;pshufb      xmm14, [RSP+050H]       ; Byte-Swap the final GHASH state
DB 066H,044H,00FH,038H,000H,074H,024H,050H

    pxor        xmm14, [RSP+010H]       ; XOR the hash and the initial CTR Block
    movdqa      [RSP+020H], xmm14       ; Write back to the stack. Tag may be shorter, than a full block
    mov         rsi, [RBP+058H]         ; Load pointer to tag
    mov         ecx, [RBP+060H]         ; Load requested tag len
gcm_enc_write_tag:
    ; Copy the tag bytewise
    mov         bl, [RSP+rcx+01fH]
    mov         [rsi+RCX-1], bl
    loop        gcm_enc_write_tag

    add         rsp, STACK_BYTES        ; Release stack variables
    popall
    ret
m_aes_gcm_cpu_auth_enc endp


; Performs AES GCM authenticated decryption using AES NI and PCLMULQDQ special instructions
;
; Parameters (after 'pushall'):
; abyp_in                   : RCX           -> RDI
; abyp_out                  : RDX           -> RSI
; abyp_key                  : R8            -> RDX
; szp_len_bytes             : R9            -> RAX (not ECX, that is used for LOOP)
; inp_number_of_rounds      : [RBP+030H]    -> R8
; abyp_ivec                 : [RBP+038H]    -> R9
; szp_ivec_len_bytes        : [RBP+040H]
; abyp_auth_data            : [RBP+048H]
; szp_auth_data_len_bytes   : [RBP+050H]
; abyp_mac_tag              : [RBP+058H]
; unp_mac_tag_len           : [RBP+060H]
;
; Other Variables:
; Hash key H                : [RSP+030H]
; GHASH state               : XMM14
; BSWAP mask                : [RSP+050H]
; Counter block             : [RSP+060H]
; Int32 counter             : r9d
; initial counter block     : [RSP+010H]
; Temporary 16 byte block   : [RSP+020H]
;
; Note, that the 32 bit counter is set, after processing of the IV, so it is ok to use that register.
m_aes_gcm_cpu_auth_dec proc
    pushall

    ; Change parameter registers to match Unix calling conventions
    mov         rdi, rcx                ; Input
    mov         rsi, rdx                ; Output
    mov         rdx, r8                 ; Keytab
    mov         rax, r9                 ; Input length
    mov         r8d, [RBP+030H]         ; Number of rounds
    mov         r9, [RBP+038H]          ; IV
    
    ; Generate space for stack variables. Assure, RSP is 16 byte aligned
    ; Set 0 as needed
    sub         rsp, STACK_BYTES
    
    aes_gcm_prepare

    ; Perform CTR with GHASH
    cmp         rax, 0                  ; Assure, that we have plaintext
    je          gcm_dec_ghash_len       ; no plaintext, go to GHASH lengths
    xor         r12,r12                 ; prepare r12 as offset counter
    mov         rcx, rax                ; load byte counter to RCX
    shr         rcx, 4                  ; turn to full AES Blocks
    cmp         rcx, 0
    je          gcm_dec_partial_block   ; no full blocks to process

    cmp         rcx, 8
    jl          gcm_dec_full_block

    ; Write 7 more Counter blocks to stack
    movdqa      xmm0, [rsp+060H]
    movdqa      [rsp+070H],xmm0
    movdqa      [rsp+080H],xmm0
    movdqa      [rsp+090H],xmm0
    movdqa      [rsp+0a0H],xmm0
    movdqa      [rsp+0b0H],xmm0
    movdqa      [rsp+0c0H],xmm0
    movdqa      [rsp+0d0H],xmm0
gcm_dec_8_block:
    aes_load_8_in_blocks
    aes_gcm_ghash_8_blocks
    aes_inc_load_8_ctr
    aes_enc_8_blocks                    ; encrypt the counters
    aes_ctr_xor_8_blocks
    aes_write_8_blocks_out
    lea         r12, [r12+080H]         ; move offset to next 8 blocks
    sub         rcx, 8
    cmp         rcx, 8
    jge         gcm_dec_8_block         ; Loop, till all blocks are processed

    cmp         rcx, 0
    je          gcm_dec_partial_block   ; no full blocks left to process
    
gcm_dec_full_block:
    ; increment the counter
    inc         r9d
    bswap       r9d
    mov         [rsp+06cH], r9d
    bswap       r9d
    movdqa      xmm0, [rsp+060H]        ; Load the counter
    call        aes_enc_block           ; encrypt the counter
    movdqu      xmm1, [rdi+r12]         ; Load current input block
    pxor        xmm0, xmm1              ; Perform XOR
    call        m_ghash_asm             ; Add current cipher-block to GHASH
    movdqu      [rsi+r12], xmm0         ; write Block to the output
    lea         r12, [r12+010H]         ; move offset to next Block
    loop        gcm_dec_full_block      ; Loop, till all blocks are processed

gcm_dec_partial_block:
    ; Process the partial block, if there is one
    mov         r11, rax
    and         r11, 0fH
    cmp         r11, 0
    je          gcm_dec_ghash_len

    
    ; Read the partial block
    pxor        xmm0, xmm0
    movdqa      [RSP+020H], xmm0
    lea         rdi, [rdi+r12-1]
    mov         rcx, r11
gcm_dec_read_partial:
    mov         bl, [rdi+rcx]
    mov         [rsp+rcx+01fH], bl
    loop        gcm_dec_read_partial

    ; increment the counter
    inc         r9d
    bswap       r9d
    mov         [rsp+06cH], r9d
    bswap       r9d
    movdqa      xmm0, [rsp+060H]        ; Load the counter
    call        aes_enc_block           ; encrypt the counter
    movdqa      xmm1, [RSP+020H]        ; Load current input block
    pxor        xmm0, xmm1              ; Perform XOR
    call        m_ghash_asm
    movdqa      [RSP+020H], xmm0        ; write Block to the temporary stack variable
    mov         rcx, 16                
    sub         rcx, r11                ; Calculate number of missing bytes for a full block
    lea         rsi, [rsi+r12]
    
    mov         rcx, r11
gcm_dec_write_partial:
    ; Write the decrypted partial block
    mov         bl, [RSP+rcx+01fH]
    mov         [rsi+RCX-1], bl
    loop        gcm_dec_write_partial

gcm_dec_ghash_len:
    ; Write Auth data len and plaintext len to stack in BITS!, big endian
    mov         rbx, [RBP+050H]         ; Load auth data len
    shl         rbx, 3                  ; Change bytes to bits
    bswap       rbx                     ; Change to big endian
    mov         [RSP+020H], rbx         ; Push to stack
    shl         rax, 3                  ; Change plaintext len from bytes to bits
    bswap       rax                     ; Change it to big endian
    mov         [RSP+028H], rax         ; Write it to the stack
    movdqa      xmm1, [RSP+020H]        ; Load the length block
    call        m_ghash_asm
    movdqa      xmm14, [RSP+040H]
    ;;pshufb      xmm14, [RSP+050H]       ; Byte-Swap the final GHASH state
DB 066H,044H,00FH,038H,000H,074H,024H,050H
    pxor        xmm14, [RSP+010H]       ; XOR the hash and the initial CTR Block
    movdqa      [RSP+020H], xmm14       ; Write back to the stack. Tag may be shorter, than a full block
    mov         rsi, [RBP+058H]         ; Load pointer to tag
    mov         ecx, [RBP+060H]         ; Load requested tag len
    xor         rax,rax                 ; prepare return
gcm_dec_check_tag:
    ; Compare the tag bytewise
    mov         bl, [RSP+rcx+01fH]
    xor         bl, [rsi+RCX-1]
    or          al, bl
    loop        gcm_dec_check_tag

    cmp         rax,0
    je          gcm_dec_end
    mov         rax, -5                 ; Set return value to auth fail

gcm_dec_end:
    add         rsp, STACK_BYTES        ; Release stack variables
    popall
    ret
m_aes_gcm_cpu_auth_dec endp




; Performs the GHASH operation of AES GCM mode using AES NI and PCLMULQDQ special instructions
;
; achp_hash_state            : RCX
; achp_hash_key              : RDX
; achp_data                  : R8
; inp_data_len               : R9

m_cpu_ghash_stream proc
    
    pushx       xmm6
    pushx       xmm7

    lea         rax, [GCM_BSWAP]                ; Load address of byte swap mask, avoids problems with largeaddressaware
    movdqa      xmm0, [rcx]
    movdqa      xmm1, [rdx]
    ; move stack the same way as m_aes_gcm_cpu_auth_* do, so m_ghash_asm can be used
    ; we don't need the full space, just as far as m_ghash_asm requires
    sub         rsp, 068h                       
    mov         rdx, rcx                        ; 

    movdqu      xmm3, [rax]
    ;;pshufb      xmm1, xmm3                      ; byte swap the key
DB 066H,00FH,038H,000H,0CBH
	;;pshufb		xmm0, xmm3						; byte swap the state
DB 066H,00FH,038H,000H,0C3H
    movdqa      [rsp+040h], xmm0                ; state in RSP+040h (048h in m_ghash_asm)
    movdqa      [rsp+030h], xmm1                ; key in RSP+030h (038h in m_ghash_asm)
    movdqa      [rsp+050h], xmm3                ; swap mask in RSP+050h (058h in m_ghash_asm)
    movdqa      xmm2, xmm1
    psrldq      xmm2, 8                         ; a0 = a1
    pxor        xmm2, xmm1                      ; a0 = a1+a0
    movdqa      [RSP], xmm2                     ; self-added key in RSP+000h (008h in m_ghash_asm)

    mov         rcx, r9
    shr         rcx, 4                          ; number of complete 16-byte blocks
    and         r9, 0fH                         ; do MOD 16 to get the number of bytes in a possible incomplete block
    cmp         rcx, 0
    je          gcm_stream_partial

gcm_stream_block_loop:
    movdqu      xmm1, [r8]                      ; input to xmm1
    call    m_ghash_asm
    lea         r8, [r8+010h]
    loop    gcm_stream_block_loop
 
gcm_stream_partial:
    cmp         r9, 0
    je          gcm_stream_no_partial
    mov         rcx, r9
    pxor        xmm0, xmm0
    movdqa      [rsp+010H], xmm0                ; push a 0 block to stack to generate 0-padding

gcm_stream_partial_loop:
    mov         al, [r8+rcx-01h]
    mov         [rsp+rcx+00fh], al
    loop    gcm_stream_partial_loop
    movdqa      xmm1, [rsp+010h]
    call    m_ghash_asm

gcm_stream_no_partial:
    movdqa      xmm0, [rsp+040h]			; load state from stack
	;;pshufb		xmm0, [rsp+050h]			; byte swap the state
DB 066H,00FH,038H,000H,044H,024H,050H
    movdqu      [rdx], xmm0					; store state back to parameter

    lea         rsp, [rsp+068h]
    popx        xmm7
    popx        xmm6

    ret

m_cpu_ghash_stream endp



_text ends

end
