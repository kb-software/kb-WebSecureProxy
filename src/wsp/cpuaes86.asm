.686
.xmm
.model flat

_text segment



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
_m_aes_128_cpu_key_expansion proc
	mov		eax,[esp+4]
	movdqu		xmm1,[eax]

	mov		edx,[esp+8]

	movdqa		[edx],xmm1

;;;	aeskeygenassist	xmm2,xmm1,1
	DB 66h,0Fh,3Ah,0DFh,0D1h,01h
	call		m_prepare_roundkey_128
	movdqa		[edx+16],xmm1
;;;	aeskeygenassist	xmm2,xmm1,2
	DB 66h,0Fh,3Ah,0DFh,0D1h,02h
	call		m_prepare_roundkey_128
	movdqa		[edx+32],xmm1
;;;	aeskeygenassist	xmm2,xmm1,4
	DB 66h,0Fh,3Ah,0DFh,0D1h,04h
	call		m_prepare_roundkey_128
	movdqa		[edx+48],xmm1
;;;	aeskeygenassist	xmm2,xmm1,8
	DB 66h,0Fh,3Ah,0DFh,0D1h,08h
	call		m_prepare_roundkey_128
	movdqa		[edx+64],xmm1
;;;	aeskeygenassist	xmm2,xmm1,16
	DB 66h,0Fh,3Ah,0DFh,0D1h,10h
	call		m_prepare_roundkey_128
	movdqa		[edx+80],xmm1
;;;	aeskeygenassist	xmm2,xmm1,32
	DB 66h,0Fh,3Ah,0DFh,0D1h,20h
	call		m_prepare_roundkey_128
	movdqa		[edx+96],xmm1
;;;	aeskeygenassist	xmm2,xmm1,64
	DB 66h,0Fh,3Ah,0DFh,0D1h,40h
	call		m_prepare_roundkey_128
	movdqa		[edx+112],xmm1
;;;	aeskeygenassist	xmm2,xmm1,80h
	DB 66h,0Fh,3Ah,0DFh,0D1h,80h
	call		m_prepare_roundkey_128
	movdqa		[edx+128],xmm1
;;;	aeskeygenassist	xmm2,xmm1,1Bh
	DB 66h,0Fh,3Ah,0DFh,0D1h,1Bh
	call		m_prepare_roundkey_128
	movdqa		[edx+144],xmm1
;;;	aeskeygenassist	xmm2,xmm1,36h
	DB 66h,0Fh,3Ah,0DFh,0D1h,36h
	call		m_prepare_roundkey_128
	movdqa		[edx+160],xmm1
	ret
_m_aes_128_cpu_key_expansion endp



; Parameter1: const unsigned char * userkey
; Parameter2: unsigned char * key_schedule
_m_aes_192_cpu_key_expansion	proc
	mov		eax,[esp+4]
	movdqu		xmm1,[eax]
	movdqu		xmm3,[eax+16]

	mov		edx,[esp+8]

	movdqa		[edx],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,1
	DB 66h,0Fh,3Ah,0DFh,0D3h,01h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[edx+16],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[edx+32],xmm6

;;;	aeskeygenassist	xmm2,xmm3,2
	DB 66h,0Fh,3Ah,0DFh,0D3h,02h
	call		m_prepare_roundkey_192
	movdqa		[edx+48],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,4
	DB 66h,0Fh,3Ah,0DFh,0D3h,04h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[edx+64],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[edx+80],xmm6

;;;	aeskeygenassist	xmm2,xmm3,8
	DB 66h,0Fh,3Ah,0DFh,0D3h,08h
	call		m_prepare_roundkey_192
	movdqa		[edx+96],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,16
	DB 66h,0Fh,3Ah,0DFh,0D3h,10h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[edx+112],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[edx+128],xmm6

;;;	aeskeygenassist	xmm2,xmm3,32
	DB 66h,0Fh,3Ah,0DFh,0D3h,20h
	call		m_prepare_roundkey_192
	movdqa		[edx+144],xmm1
	movdqa		xmm5,xmm3

;;;	aeskeygenassist	xmm2,xmm3,64
	DB 66h,0Fh,3Ah,0DFh,0D3h,40h
	call		m_prepare_roundkey_192
	shufpd		xmm5,xmm1,0
	movdqa		[edx+160],xmm5
	movdqa		xmm6,xmm1
	shufpd		xmm6,xmm3,1
	movdqa		[edx+176],xmm6

;;;	aeskeygenassist	xmm2,xmm3,128
	DB 66h,0Fh,3Ah,0DFh,0D3h,80h
	call		m_prepare_roundkey_192
	movdqa		[edx+192],xmm1
	movdqa		[edx+208],xmm3
	ret
_m_aes_192_cpu_key_expansion	endp


; Parameter1: const unsigned char * userkey
; Parameter2: unsigned char * key_schedule
_m_aes_256_cpu_key_expansion	proc
	mov		eax,[esp+4]
	movdqu		xmm1,[eax]
	movdqu		xmm3,[eax+16]

	mov		edx,[esp+8]
	movdqa		[edx],xmm1
	movdqa		[edx+16],xmm3

;;;	aeskeygenassist	xmm2,xmm3,1
	DB 66h,0Fh,3Ah,0DFh,0D3h,01h
	call		m_make_rk256_a
	movdqa		[edx+32],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+48],xmm3

;;;	aeskeygenassist	xmm2,xmm3,2
	DB 66h,0Fh,3Ah,0DFh,0D3h,02h
	call		m_make_rk256_a
	movdqa		[edx+64],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+80],xmm3

;;;	aeskeygenassist	xmm2,xmm3,4
	DB 66h,0Fh,3Ah,0DFh,0D3h,04h
	call		m_make_rk256_a
	movdqa		[edx+96],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+112],xmm3

;;;	aeskeygenassist	xmm2,xmm3,8
	DB 66h,0Fh,3Ah,0DFh,0D3h,08h
	call		m_make_rk256_a
	movdqa		[edx+128],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+144],xmm3

;;;	aeskeygenassist	xmm2,xmm3,16
	DB 66h,0Fh,3Ah,0DFh,0D3h,10h
	call		m_make_rk256_a
	movdqa		[edx+160],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+176],xmm3

;;;	aeskeygenassist	xmm2,xmm3,32
	DB 66h,0Fh,3Ah,0DFh,0D3h,20h
	call		m_make_rk256_a
	movdqa		[edx+192],xmm1

;;;	aeskeygenassist	xmm2,xmm1,0
	DB 66h,0Fh,3Ah,0DFh,0D1h,00h
	call		m_make_rk256_b
	movdqa		[edx+208],xmm3

;;;	aeskeygenassist	xmm2,xmm3,64
	DB 66h,0Fh,3Ah,0DFh,0D3h,40h
	call		m_make_rk256_a
	movdqa		[edx+224],xmm1

	ret
_m_aes_256_cpu_key_expansion	endp




; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: rounds
_m_aes_ecb_cpu_encrypt	proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

	mov		edi,[ebp+8]		; Input
	mov		esi,[ebp+12]		; Output
	mov		ebx,[ebp+16]		; Key
	mov		ecx,[ebp+20]		; Blockcount
	mov		eax,[ebp+24]		; Rounds

	cmp		ecx,0
	je		ecb_enc_end_4

ecb_enc_loop_4_2:
	movdqu		xmm1,[edi]
	add		edi,16
	pxor		xmm1,[ebx]
	movdqu		xmm2,[ebx+160]

;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
;;;	aesenc		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DCh,4Bh,60h
;;;	aesenc		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DCh,4Bh,70h
	add		ebx,128
;;;	aesenc		xmm1,[ebx]
	DB 66h,0Fh,38h,0DCh,0Bh
;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
	cmp		eax,12
	jb		ecb_enc_last_4_2
	movdqu		xmm2,[ebx+64]
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
	cmp		eax,14
	jb		ecb_enc_last_4_2
	movdqu		xmm2,[ebx+96]
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
ecb_enc_last_4_2:
;;;	aesenclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DDh,0CAh
	movdqu		[esi],xmm1
	sub		ebx,128
	add		esi,16
	dec		ecx
	jnz		ecb_enc_loop_4_2


ecb_enc_end_4:
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_m_aes_ecb_cpu_encrypt	endp



; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: rounds
_m_aes_ecb_cpu_decrypt	proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

	mov		edi,[ebp+8]		; Input
	mov		esi,[ebp+12]		; Output
	mov		ebx,[ebp+16]		; Key
	mov		ecx,[ebp+20]		; Blockcount
	mov		eax,[ebp+24]		; Rounds

	cmp		ecx,0
	je		ecb_dec_end_4

ecb_dec_loop_4_2:
	movdqu		xmm1,[edi]
	add		edi,16
	pxor		xmm1,[ebx]
	movdqu		xmm2,[ebx+160]
;;;	aesdec		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DEh,4Bh,10h
;;;	aesdec		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DEh,4Bh,20h
;;;	aesdec		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DEh,4Bh,30h
;;;	aesdec		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DEh,4Bh,40h
;;;	aesdec		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DEh,4Bh,50h
;;;	aesdec		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DEh,4Bh,60h
;;;	aesdec		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DEh,4Bh,70h
	add		ebx,128
	cmp		eax,12
;;;	aesdec		xmm1,[ebx]
	DB 66h,0Fh,38h,0DEh,0Bh
;;;	aesdec		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DEh,4Bh,10h
	jb		ecb_dec_last_4_2
	cmp		eax,14
	movdqu		xmm2,[ebx+64]
;;;	aesdec		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DEh,4Bh,20h
;;;	aesdec		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DEh,4Bh,30h
	jb		ecb_dec_last_4_2
	movdqu		xmm2,[ebx+96]
;;;	aesdec		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DEh,4Bh,40h
;;;	aesdec		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DEh,4Bh,50h
ecb_dec_last_4_2:
;;;	aesdeclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DFh,0CAh
	movdqu		[esi],xmm1
	sub		ebx,128
	add		esi,16
	dec		ecx
	jnz		ecb_dec_loop_4_2

ecb_dec_end_4:
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_m_aes_ecb_cpu_decrypt	endp




; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
_m_aes_cbc_cpu_encrypt	proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

	mov		edi,[ebp+8]		; Input
	mov		esi,[ebp+12]		; Output
	mov		ebx,[ebp+16]		; Key
	mov		ecx,[ebp+20]		; Blockcount
	mov		edx,[ebp+24]		; IV
	mov		eax,[ebp+28]		; Rounds

	cmp		ecx,0
	je		cbc_enc_end

	sub		esi,16
	movdqu		xmm1,[edx]

cbc_enc_loop:
	movdqu		xmm2,[edi]
	pxor		xmm1,xmm2
	pxor		xmm1,[ebx]
	add		esi,16
	add		edi,16
;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
;;;	aesenc		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DCh,4Bh,60h
;;;	aesenc		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DCh,4Bh,70h
	add		ebx,128
	cmp		eax,12
;;;	aesenc		xmm1,[ebx]
	DB 66h,0Fh,38h,0DCh,0Bh
;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
	movdqa		xmm2,[ebx+32]
	jb		cbc_enc_last
	cmp		eax,14
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
	movdqa		xmm2,[ebx+64]
	jb		cbc_enc_last
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
	movdqa		xmm2,[ebx+96]
cbc_enc_last:
	sub		ebx,128
;;;	aesenclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DDh,0CAh
	dec		ecx
	movdqu		[esi],xmm1
	jne		cbc_enc_loop

	movdqu		[edx],xmm1		; store back IV


cbc_enc_end:
	pop		edi
	pop		esi
	pop		ebx
	pop		ebp
	ret
_m_aes_cbc_cpu_encrypt	endp



; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
_m_aes_cbc_cpu_decrypt	proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

	mov		edi,[ebp+8]		; Input
	mov		esi,[ebp+12]		; Output
	mov		ebx,[ebp+16]		; Key
	mov		ecx,[ebp+20]		; Blockcount
	mov		edx,[ebp+24]		; IV
	mov		eax,[ebp+28]		; Rounds

	cmp		ecx,0
	je		cbc_dec_end
	movdqu		xmm5,[edx]		; get IV

cbc_dec_loop_4_2:
	movdqu		xmm1,[edi]
	movdqa		xmm3,xmm1		; save IV
	add		edi,16
	pxor		xmm1,[ebx]		; KS
	movdqu		xmm2,[ebx+160]
;;;	aesdec		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DEh,4Bh,10h
;;;	aesdec		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DEh,4Bh,20h
;;;	aesdec		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DEh,4Bh,30h
;;;	aesdec		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DEh,4Bh,40h
;;;	aesdec		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DEh,4Bh,50h
;;;	aesdec		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DEh,4Bh,60h
;;;	aesdec		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DEh,4Bh,70h
	add		ebx,128
	cmp		eax,12
;;;	aesdec		xmm1,[ebx]
	DB 66h,0Fh,38h,0DEh,0Bh
;;;	aesdec		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DEh,4Bh,10h
	jb		cbc_dec_last_4_2
	movdqu		xmm2,[ebx+64]
	cmp		eax,14
;;;	aesdec		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DEh,4Bh,20h
;;;	aesdec		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DEh,4Bh,30h
	jb		cbc_dec_last_4_2
	movdqu		xmm2,[ebx+96]
;;;	aesdec		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DEh,4Bh,40h
;;;	aesdec		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DEh,4Bh,50h
cbc_dec_last_4_2:
;;;	aesdeclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DFh,0CAh
	pxor		xmm1,xmm5
	movdqa		xmm5,xmm3
	movdqu		[esi],xmm1
	sub		ebx,128
	add		esi,16
	dec		ecx
	jnz		cbc_dec_loop_4_2
	movdqu		[edx],xmm5		; Write back IV


cbc_dec_end:
	pop		edi
	pop		esi
	pop		ebx
	pop		ebp
	ret
_m_aes_cbc_cpu_decrypt	endp



; Parameter1: normal key schedule
; Parameter2: reverted key schedule
; Parameter3: number of rounds
_m_aes_cpu_revert_key	proc
	push	ebp
	mov	ebp,esp
	push	ebx

	mov	eax,[ebp+8]	; normal KS
	mov	ebx,[ebp+12]	; inverted KS
	mov	ecx,[ebp+16]	; nr

	mov	edx,ecx
	shl	edx,4		; * 16
	add	ebx,edx		; to topmost element

	movdqu	xmm1,[eax]
	movdqu	[ebx],xmm1
	add	eax,16
	sub	ebx,16
	dec	ecx

revert_loop:
	movdqu	xmm1,[eax]
;;;	aesimc	xmm1,xmm1
	DB 66h,0Fh,38h,0DBh,0C9h
	movdqu	[ebx],xmm1
	add	eax,16
	sub	ebx,16
	dec	ecx
	jnz	revert_loop

	movdqu	xmm1,[eax]
	movdqu	[ebx],xmm1

	pop	ebx
	pop	ebp
	ret
_m_aes_cpu_revert_key	endp


; Parameter1: Input
; Parameter2: Output
; Parameter3: Key schedule
; Parameter4: Blockcount
; Parameter5: IV
; Parameter6: rounds
_m_aes_ctr_cpu	proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

	mov		edi,[ebp+8]		; Input
	mov		esi,[ebp+12]		; Output
	mov		ebx,[ebp+16]		; Key
	mov		ecx,[ebp+20]		; Blockcount
	mov		edx,[ebp+24]		; IV
	mov		eax,[ebp+28]		; Rounds
    
	movdqu		xmm1,[edx]
    push        edx
    mov         edx,[edx+12]
    sub         esp, 16
    movdqu      [esp],xmm1

    cmp		ecx,0
	je		ctr_end

ctr_loop:
	pxor		xmm1,[ebx]
	movdqu		xmm2,[ebx+160]

;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
;;;	aesenc		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DCh,4Bh,60h
;;;	aesenc		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DCh,4Bh,70h
	add		ebx,128
;;;	aesenc		xmm1,[ebx]
	DB 66h,0Fh,38h,0DCh,0Bh
;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
	cmp		eax,12
	jb		ctr_loop_last
	movdqu		xmm2,[ebx+64]
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
	cmp		eax,14
	jb		ctr_loop_last
	movdqu		xmm2,[ebx+96]
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
ctr_loop_last:
;;;	aesenclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DDh,0CAh
	movdqu      xmm0,[edi]
    pxor        xmm1,xmm0
	movdqu		[esi],xmm1

    bswap       edx
    inc         edx
    bswap       edx
    mov         [esp+12],edx
    movdqu      xmm1,[esp]
	sub		ebx,128
	add		esi,16
	add		edi,16

	dec		ecx
	jnz		ctr_loop


ctr_end:
    add     esp,16
    pop     edx

	pxor		xmm1,[ebx]
	movdqu		xmm2,[ebx+160]

;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
;;;	aesenc		xmm1,[ebx+96]
	DB 66h,0Fh,38h,0DCh,4Bh,60h
;;;	aesenc		xmm1,[ebx+112]
	DB 66h,0Fh,38h,0DCh,4Bh,70h
	add		ebx,128
;;;	aesenc		xmm1,[ebx]
	DB 66h,0Fh,38h,0DCh,0Bh
;;;	aesenc		xmm1,[ebx+16]
	DB 66h,0Fh,38h,0DCh,4Bh,10h
	cmp		eax,12
	jb		ctr_end_last
	movdqu		xmm2,[ebx+64]
;;;	aesenc		xmm1,[ebx+32]
	DB 66h,0Fh,38h,0DCh,4Bh,20h
;;;	aesenc		xmm1,[ebx+48]
	DB 66h,0Fh,38h,0DCh,4Bh,30h
	cmp		eax,14
	jb		ctr_end_last
	movdqu		xmm2,[ebx+96]
;;;	aesenc		xmm1,[ebx+64]
	DB 66h,0Fh,38h,0DCh,4Bh,40h
;;;	aesenc		xmm1,[ebx+80]
	DB 66h,0Fh,38h,0DCh,4Bh,50h
ctr_end_last:
;;;	aesenclast	xmm1,xmm2
	DB 66h,0Fh,38h,0DDh,0CAh
	movdqu		[edx],xmm1
    
	pop		edi
	pop		esi
	pop		ebx
	pop		ebp
	ret
_m_aes_ctr_cpu	endp

; Code is taken from 'Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode'
; inputs have been modified and some registers renamed to reduce the register footprint
m_ghash_asm proc
;Input:
; xmm1 holds new X (128 bits)
;[ESP+014H] holds Hash key H (128 bits)
;[ESP+024H] holds the old state
;[ESP+034H] holds the byte-swap mask
;Output:
; xmm6 takes the new state
;[ESP+024H] takes the new state
; offset of 4 compared to calling function's specification: call pushes return address
    ;;pshufb      xmm1, [ESP+034H]    ; Byte-swap input
DB 066H,00FH,038H,000H,04CH,024H,034H

    pxor        xmm1, [ESP+024H]
    movdqa      xmm3, [ESP+014H]
    ;;pclmulqdq   xmm3, xmm1, 0       ; xmm3 holds a0*b0
DB 066H,00FH,03AH,044H,0D9H,000H
    
    movdqa      xmm4, [ESP+014H]
    ;;pclmulqdq   xmm4, xmm1, 16      ;xmm4 holds a0*b1
DB 066H,00FH,03AH,044H,0E1H,010H

    movdqa      xmm5, [ESP+014H]
    ;;pclmulqdq   xmm5, xmm1, 1       ; xmm5 holds a1*b0
DB 066H,00FH,03AH,044H,0E9H,001H

    movdqa      xmm6, [ESP+014H]
    ;;pclmulqdq   xmm6, xmm1, 17      ; xmm6 holds a1*b1
DB 066H,00FH,03AH,044H,0F1H,011H

    pxor        xmm4, xmm5          ; xmm4 holds a0*b1 + a1*b0
    movdqa      xmm5, xmm4
    psrldq      xmm4, 8
    pslldq      xmm5, 8
    pxor        xmm3, xmm5
    pxor        xmm6, xmm4          ; <xmm6:xmm3> holds the result of 
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
    movdqa      [ESP+024H], xmm6         ; store the result

    ret
m_ghash_asm endp

; This function does not generate a stack frame. 
; The block must be in XMM0
; Number of rounds must be in eax
; AES keytab must be in edx and 16-byte aligned
; Offset of last round key must be in ebx
aes_enc_block proc

    cmp             ebx, 192                    ; compare offset of final key for later jump
    pxor            xmm0,[edx]                  ; XOR first round key into block

align 16
    ; Perform all AES enc rounds
    ;;aesenc          xmm0, [edx+010h]
    ;;aesenc          xmm0, [edx+020h]
    ;;aesenc          xmm0, [edx+030h]
    ;;aesenc          xmm0, [edx+040h]
    ;;aesenc          xmm0, [edx+050h]
    ;;aesenc          xmm0, [edx+060h]
    ;;aesenc          xmm0, [edx+070h]
    ;;aesenc          xmm0, [edx+080h]
    ;;aesenc          xmm0, [edx+090h]
DB 066H,00FH,038H,0DCH,042H,010H
DB 066H,00FH,038H,0DCH,042H,020H
DB 066H,00FH,038H,0DCH,042H,030H
DB 066H,00FH,038H,0DCH,042H,040H
DB 066H,00FH,038H,0DCH,042H,050H
DB 066H,00FH,038H,0DCH,042H,060H
DB 066H,00FH,038H,0DCH,042H,070H
DB 066H,00FH,038H,0DCH,082H,080H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,090H,000H,000H,000H

    jb              aes_block_enc_last          ; jump, if offset is less, than 192 bytes (128 bit AES)
    ;;aesenc          xmm0, [edx+0a0h]
    ;;aesenc          xmm0, [edx+0b0h]
DB 066H,00FH,038H,0DCH,082H,0A0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,0B0H,000H,000H,000H

    je              aes_block_enc_last          ; jump, if offset is 192 bytes (192 bit AES)
    ;;aesenc          xmm0, [edx+0c0h]
    ;;aesenc          xmm0, [edx+0d0h]
DB 066H,00FH,038H,0DCH,082H,0C0H,000H,000H,000H
DB 066H,00FH,038H,0DCH,082H,0D0H,000H,000H,000H

aes_block_enc_last:
    ;;aesenclast      xmm0,[edx+ebx]
DB 066H,00FH,038H,0DDH,004H,013H

    ret
aes_enc_block endp

GCM_BSWAP BYTE 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0


; This macro is used for preparing the IV, Hash key and process the authentication data for AES GCM.
aes_gcm_prepare macro
    pxor        xmm0, xmm0
	movdqa      [ESP+020H], xmm0                 ; Initialize GHASH state to 0

    ; Store key address in edx and offset for the final roundkey in ebx
    mov         edx, [EBP+010H]                 ; Load key
    mov         ebx, [EBP+018H]                 ; load round count
    shl         ebx,4                           ; Offset for the final round key is 16 bytes per round, left shift multiplies by 16

    ; Generate Hash Key H. XMM0 is 0
    call aes_enc_block                          ; (xmm0, ebx, edx)
    
    lea         ecx, [GCM_BSWAP]                ; Load address of byte swap mask, avoids problems with largeaddressaware
    movdqu      xmm1, [ecx]                     ; Load byte swap mask
    ;;pshufb      xmm0, xmm1                      ; byte swap the key
DB 066H,00FH,038H,000H,0C1H

    movdqa      [ESP+030H], xmm1                ; Write byte swap mask to [ESP+050H]
    movdqa      [ESP+010H], xmm0                ; Write hash key to [ESP+030H]

    ; Prepare IV
    mov         esi, [EBP+01cH]                 ; Load IV
    mov         ecx, [EBP+020H]                 ; Load IV len
    cmp         ecx, 12                         ; Check for standard length (12 byte = 96 bit)
    jne         gcm_long_iv
    
    ; standard IV length, just copy the IV to the stack (96 bit = 64+32 bit)
    mov         DWORD PTR[ESP+04cH], 01000000H  ; Preset counter part (Sets lowest byte 1, Endianess!)
    mov         ebx, [esi]                      ; copy high dword
    mov         [ESP+040H], ebx
    mov         ebx, [esi+4]                    ; copy mid dword
    mov         [ESP+044H], ebx
    mov         ebx, [esi+8]                    ; copy low dword
    mov         [ESP+048H], ebx
    jmp         gcm_counter_ready
gcm_long_iv:
    ; IV is not 96 bit, do GHASH. State is already 0
    pxor        xmm0, xmm0                      ; 0 out XMM0
    mov         edi, ecx                        ; Store IV len
    shr         ecx,4                           ; Get the number of 16 byte blocks
    cmp         ecx,0
    je          gcm_partial_iv_block

gcm_iv_full_blocks:
    ; Process full blocks
    movdqu      xmm1, [esi]                     ; Load Block
    call        m_ghash_asm                     ; (xmm1-7, [ESP+010H,020H,030H])
    lea         esi, [esi+010h]                 ; Next block
    loop        gcm_iv_full_blocks              ; loop over all blocks

gcm_partial_iv_block:
    mov         ecx, edi                        ; load stored IV len
    and         ecx, 0fH                        ; do MOD 16 to get the number of bytes in a possible incomplete block
    cmp         ecx, 0
    je          gcm_push_long_iv
    movdqa      [esp+000h], xmm0                ; push a 0 block to stack to generate 0-padding

gcm_partial_iv_loop:
    ; Move the partial block to the stack, bytewise
    mov         al, [esi+ecx-1]
    mov         [esp+ecx-1], al
    loop        gcm_partial_iv_loop

    movdqa      xmm1, [esp]                      ; Load the 0-padded block for GHASH
    call        m_ghash_asm

gcm_push_long_iv:
    movdqa      [esp], xmm0                     ; Clear the block again for the IV len
    shl         edi,3                           ; Multiply IV len by 8 to get length in bits
    bswap       edi                             ; To Big Endian
    mov         [esp+12],edi                     ; Write to the block
    movdqa      xmm1, [esp]                     ; Load length for GHASH
    call        m_ghash_asm
    ;;pshufb      xmm6, [ESP+030H]                ; Byte-swap the GHASH
DB 066H,00FH,038H,000H,074H,024H,030H

    movdqa      [ESP+040H], xmm6                ; Write from GHASH state to stack as counter block

    movdqa      [esp+20h], xmm0                 ; Reset GHASH state to 0

gcm_counter_ready:

    ; Prepare the first encryption block, used for Auth tag
    ; From here on, we can use r9, as the processed IV is on the stack
    movdqa      xmm0, [ESP+040H]                ; Load IV
    
    ; Store key address in edx and offset for the final roundkey in ebx
    mov         edx, [EBP+010H]                 ; Load key
    mov         ebx, [EBP+018H]                 ; load round count
    shl         ebx,4                           ; Offset for the final round key is 16 bytes per round, left shift multiplies by 16

    call aes_enc_block                          ; Generate first counter block
    
    movdqa      [ESP+050H], xmm0                ; Store result on stack [RSP+010h] of AES GCM main function

    ; Feed authentication data to GHASH
    mov         ecx, [EBP+028H]                 ; Load auth data len
    cmp         ecx,0
    je          gcm_prepare_end                 ; only process, if there are auth data

    mov         eax, ecx                        ; store length
    shr         ecx, 4                          ; Calculate number of full blocks
    mov         ebx, [EBP+024H]                 ; load auth data pointer
    cmp         ecx, 0
    je          gcm_partial_auth_block          ; Skip to partial blocks, if no full block is available
gcm_full_auth_blocks:
    movdqu      xmm1,[ebx]                      ; Load full block of auth data
    call        m_ghash_asm                     ; load and GHASH block
    lea         ebx, [ebx+010H]                 ; Load next block address
    loop        gcm_full_auth_blocks            ; loop over all full blocks

gcm_partial_auth_block:
    mov         ecx, eax                        ; Load auth data len
    and         ecx, 0fH                        ; Reduce to bytes in the incomplete block
    cmp         ecx, 0
    je          gcm_prepare_end                 ; only process, if there are auth data

    pxor        xmm1,xmm1
    movdqa      [ESP+000H], xmm1                ; 0 out the block on the stack
gcm_partial_auth_loop:
    ; Copy bytewise from the auth data buffer to the stack block
    mov         al, [ebx+ecx-1]
    mov         [esp+ecx-1], al
    loop        gcm_partial_auth_loop
    movdqa      xmm1, [ESP+000H]
    call        m_ghash_asm                     ; Load and GHASH the 0-padded partial block

gcm_prepare_end:
    endm

AES_GCM_STACK_SPACE = 060H

; Performs AES GCM authenticated encryption using AES NI and PCLMULQDQ special instructions
;
; Parameters (after 'pushall'):
; abyp_in                   : [EBP+008H]
; abyp_out                  : [EBP+00cH]
; abyp_key                  : [EBP+010H]
; szp_len_bytes             : [EBP+014H]
; inp_number_of_rounds      : [EBP+018H]
; abyp_ivec                 : [EBP+01cH]
; szp_ivec_len_bytes        : [EBP+020H]
; abyp_auth_data            : [EBP+024H]
; szp_auth_data_len_bytes   : [EBP+028H]
; abyp_mac_tag              : [EBP+02cH]
; unp_mac_tag_len           : [EBP+030H]
;
; Other Variables:
; Hash key H                : [ESP+010H]
; GHASH state               : [ESP+020H]
; BSWAP mask                : [ESP+030H]
; Counter block             : [ESP+040H]
; initial counter block     : [ESP+050H]
; Temporary 16 byte block   : [ESP+000H]
;
_m_aes_gcm_cpu_auth_enc proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

    ; calculate offset to align the stack at 16 bytes
    mov         eax, ebp                ; Get base pointer
    and         eax, 0fH                ; Get the offset from 16 byte alignment
    sub         esp, eax                ; This will give the ESP a low nibble of 4
    push        eax                     ; push the offset. ESP will now have exactly 16 byte alignment

    ; Reserve stack space for this function.
    sub         esp, AES_GCM_STACK_SPACE
    
    aes_gcm_prepare
    ; eax = counter dword

    ; Perform CTR with GHASH
    
    ; Store key address in edx and offset for the final roundkey in ebx
    mov         edx, [EBP+010H]                 ; Load key
    mov         ebx, [EBP+018H]                 ; load round count
    shl         ebx,4                           ; Offset for the final round key is 16 bytes per round, left shift multiplies by 16

    ; load input and output pointers
    mov         edi, [EBP+008H]         ; Input
    mov         esi, [EBP+00CH]         ; Output

    mov         ecx, [EBP+014H]         ; Load input length
    cmp         ecx, 0                  ; Assure, that we have plaintext
    je          gcm_enc_ghash_len       ; no plaintext, go to GHASH lengths
    shr         ecx, 4                  ; turn to full AES Blocks
    cmp         ecx, 0
    je          gcm_enc_partial_block   ; no full blocks to process
gcm_enc_full_block:
    ; increment the counter
    mov         eax, [ESP+04CH]
    bswap       eax
    inc         eax
    bswap       eax
    mov         [ESP+04CH], eax
    movdqa      xmm0, [ESP+040H]        ; Load the counter
    call        aes_enc_block           ; encrypt the counter (operates using xmm0, ebx, edx)
    movdqu      xmm1, [edi]             ; Load current input block
    pxor        xmm1, xmm0              ; Perform XOR
    movdqu      [esi], xmm1             ; write Block to the output
    call        m_ghash_asm             ; Add current block to GHASH
    lea         edi, [edi+010H]         ; move input to next block
    lea         esi, [esi+010H]         ; move output to next block
    loop        gcm_enc_full_block      ; Loop, till all blocks are processed

gcm_enc_partial_block:
    mov         ecx, [EBP+014H]         ; Load input length
    and         ecx, 0fh                ; Mask to make it mod 16, so only incomplete blocks
    cmp         ecx, 0                  ; Assure, that we have plaintext
    je          gcm_enc_ghash_len       ; no plaintext, go to GHASH lengths
    ; increment the counter
    mov         eax, [ESP+04CH]
    bswap       eax
    inc         eax
    bswap       eax
    mov         [ESP+04CH], eax
    movdqa      xmm0, [ESP+040H]        ; Load the counter

    mov         eax, ecx
gcm_enc_read_partial:
    mov         dl, [edi+ecx-1]
    mov         [esp+ecx+03fH], dl
    loop        gcm_enc_read_partial
    
    mov         edx, [EBP+010H]         ; Load key
    call        aes_enc_block           ; encrypt the counter
    movdqu      xmm1, [ESP+040H]        ; Load partial input block from stack
    pxor        xmm1, xmm0              ; Perform XOR
    movdqu      [ESP+040H], xmm1        ; write Block back to stack

    mov         ecx, eax                ; load number of bytes to write
gcm_enc_write_partial:
    ; Write the encrypted partial block
    mov         bl, [esp+ecx+03fH]
    mov         [esi+ecx-1], bl
    loop        gcm_enc_write_partial

    mov         ecx, 010h               ; load 16 to ECX
    sub         ecx, eax                ; subtract number of bytes, giving number of 0 bytes
gcm_enc_zero_block:
    ; Generate 0 padding for the partial Block. Needed for the GHASH
    mov         BYTE PTR[esp+eax+040H],0
    inc         eax
    loop        gcm_enc_zero_block
    movdqa      xmm1, [ESP+040H]
    call        m_ghash_asm

gcm_enc_ghash_len:
    ; Write Auth data len and plaintext len to stack in BITS!, big endian
    pxor        xmm0,xmm0               ; 0 out XMM0
    movdqa      [ESP+040H], xmm0        ; 0 out Counter block on the stack
    mov         ecx, [EBP+028H]         ; Load auth data len
    shl         ecx, 3                  ; Shift multiplies by 8, length in bits
    bswap       ecx                     ; to BE
    mov         [ESP+044H],ecx          ; write to stack
    mov         ecx, [EBP+014H]         ; Load plaintext len
    shl         ecx, 3                  ; Shift multiplies by 8, length in bits
    bswap       ecx                     ; to BE
    mov         [ESP+04cH],ecx          ; write to stack

    movdqa      xmm1,[ESP+040H]         ; read the length block
    call        m_ghash_asm

    ; XOR with initial CTR block
    ;;pshufb      xmm6, [ESP+030H]
DB 066H,00FH,038H,000H,074H,024H,030H

    movdqa      xmm1, [ESP+050H]
    pxor        xmm1, xmm6
    movdqa      [ESP+020H], xmm1

    ; Write finished Tag to destination
    mov         ecx, [EBP+030H]         ; Auth Tag length
    mov         edi, [EBP+02cH]         ; Auth Tag destination adress
gcm_enc_write_tag:
    mov         bl, [ESP+ECX+01fH]
    mov         [EDI+ECX-1], bl
    loop        gcm_enc_write_tag

    add         esp, AES_GCM_STACK_SPACE
    
    ; restore the old ESP
    pop         eax
    add         esp, eax

    pop         edi
    pop         esi
    pop         ebx
    pop         ebp
    ret
_m_aes_gcm_cpu_auth_enc endp

_m_aes_gcm_cpu_auth_dec proc
	push		ebp
	mov		ebp,esp
	push		ebx
	push		esi
	push		edi

    ; calculate offset to align the stack at 16 bytes
    mov         eax, ebp                ; Get base pointer
    and         eax, 0fH                ; Get the offset from 16 byte alignment
    sub         esp, eax                ; This will give the ESP a low nibble of 4
    push        eax                     ; push the offset. ESP will now have exactly 16 byte alignment

    ; Reserve stack space for this function.
    sub         esp, AES_GCM_STACK_SPACE
    
    aes_gcm_prepare
    ; eax = counter dword

    ; Perform CTR with GHASH
    
    ; Store key address in edx and offset for the final roundkey in ebx
    mov         edx, [EBP+010H]                 ; Load key
    mov         ebx, [EBP+018H]                 ; load round count
    shl         ebx,4                           ; Offset for the final round key is 16 bytes per round, left shift multiplies by 16

    ; load input and output pointers
    mov         edi, [EBP+008H]         ; Input
    mov         esi, [EBP+00CH]         ; Output

    mov         ecx, [EBP+014H]         ; Load input length
    cmp         ecx, 0                  ; Assure, that we have plaintext
    je          gcm_dec_ghash_len       ; no plaintext, go to GHASH lengths
    shr         ecx, 4                  ; turn to full AES Blocks
    cmp         ecx, 0
    je          gcm_dec_partial_block   ; no full blocks to process
gcm_dec_full_block:
    ; increment the counter
    mov         eax, [ESP+04CH]
    bswap       eax
    inc         eax
    bswap       eax
    mov         [ESP+04CH], eax
    movdqa      xmm0, [ESP+040H]        ; Load the counter
    call        aes_enc_block           ; decrypt the counter (operates using xmm0, ebx, edx)
    movdqu      xmm1, [edi]             ; Load current input block
    pxor        xmm0, xmm1              ; Perform XOR
    movdqu      [esi], xmm0             ; write Block to the output
    call        m_ghash_asm             ; Add current block to GHASH
    lea         edi, [edi+010H]         ; move input to next block
    lea         esi, [esi+010H]         ; move output to next block
    loop        gcm_dec_full_block      ; Loop, till all blocks are processed

gcm_dec_partial_block:
    mov         ecx, [EBP+014H]         ; Load input length
    and         ecx, 0fh                ; Mask to make it mod 16, so only incomplete blocks
    cmp         ecx, 0                  ; Assure, that we have plaintext
    je          gcm_dec_ghash_len       ; no plaintext, go to GHASH lengths
    ; increment the counter
    mov         eax, [ESP+04CH]
    bswap       eax
    inc         eax
    bswap       eax
    mov         [ESP+04CH], eax
    movdqa      xmm0, [ESP+040H]        ; Load the counter

    mov         eax, ecx
gcm_dec_read_partial:
    mov         dl, [edi+ecx-1]
    mov         [esp+ecx-1], dl
    loop        gcm_dec_read_partial
    
    mov         edx, [EBP+010H]         ; Load key
    call        aes_enc_block           ; decrypt the counter
    movdqu      xmm1, [ESP+000H]        ; Load partial input block from stack
    pxor        xmm0, xmm1              ; Perform XOR
    movdqu      [ESP+040H], xmm0        ; write Block back to stack 
                                        ; overwriting the counter, we still need the input on [ESP+0]

    mov         ecx, eax                ; load number of bytes to write
gcm_dec_write_partial:
    ; Write the decrypted partial block
    mov         bl, [esp+ecx+03fH]
    mov         [esi+ecx-1], bl
    loop        gcm_dec_write_partial

    mov         ecx, 010h               ; load 16 to ECX
    sub         ecx, eax                ; subtract number of bytes, giving number of 0 bytes
gcm_dec_zero_block:
    ; Generate 0 padding for the partial Block. Needed for the GHASH
    mov         BYTE PTR[esp+eax],0
    inc         eax
    loop        gcm_dec_zero_block
    movdqa      xmm1, [ESP+000H]
    call        m_ghash_asm

gcm_dec_ghash_len:
    ; Write Auth data len and plaintext len to stack in BITS!, big endian
    pxor        xmm0,xmm0               ; 0 out XMM0
    movdqa      [ESP+040H], xmm0        ; 0 out Counter block on the stack
    mov         ecx, [EBP+028H]         ; Load auth data len
    shl         ecx, 3                  ; Shift multiplies by 8, length in bits
    bswap       ecx                     ; to BE
    mov         [ESP+044H],ecx          ; write to stack
    mov         ecx, [EBP+014H]         ; Load plaintext len
    shl         ecx, 3                  ; Shift multiplies by 8, length in bits
    bswap       ecx                     ; to BE
    mov         [ESP+04cH],ecx          ; write to stack

    movdqa      xmm1,[ESP+040H]         ; read the length block
    call        m_ghash_asm

    ; XOR with initial CTR block
    ;;pshufb      xmm6, [ESP+030H]
DB 066H,00FH,038H,000H,074H,024H,030H

    movdqa      xmm1, [ESP+050H]
    pxor        xmm1, xmm6
    movdqa      [ESP+020H], xmm1

    ; Compare finished Tag
    mov         ecx, [EBP+030H]         ; Auth Tag length
    mov         edi, [EBP+02cH]         ; Auth Tag destination adress
    xor         eax, eax
gcm_dec_compare_tag:
    mov         bl, [ESP+ECX+01fH]      ; 
    xor         bl, [EDI+ECX-1]         ; XOR the two bytes: result 0 if equal, non-0 if unequal
    or          al, bl                  ; OR-accumulate: if any were non-equal, al will be non-0
    loop        gcm_dec_compare_tag

    cmp         eax, 0                  ; if not zero (if any non-equal bytes)
    mov         edx, -5
    cmovnz      eax, edx                ; conditional mov -5

    add         esp, AES_GCM_STACK_SPACE
    
    ; restore the old ESP
    pop         edx
    add         esp, edx

    pop         edi
    pop         esi
    pop         ebx
    pop         ebp
    ret
_m_aes_gcm_cpu_auth_dec endp


; Performs the GHASH operation of AES GCM mode using AES NI and PCLMULQDQ special instructions
;
; achp_hash_state            : [EBP+008H]
; achp_hash_key              : [EBP+00cH]
; achp_data                  : [EBP+010H]
; inp_data_len               : [EBP+014H]
;
_m_cpu_ghash_stream proc
    
    push        ebp
    mov         ebp, esp
    mov         ecx, [EBP+008H]
    mov         edx, [EBP+00cH]

    mov         eax, esp
    and         eax, 0fh
    sub         esp, eax                        ; esp now has a 16-byte alignment (old esp is implicitly stored in ebp)

    lea         eax, [GCM_BSWAP]                ; Load address of byte swap mask, avoids problems with largeaddressaware
    movdqa      xmm0, [ecx]
    movdqa      xmm1, [edx]
    movdqu      xmm3, [eax]

;;  pshufb      xmm1, xmm3                      ; byte swap the key
    DB 66h,0Fh,38h,00h,0CBh
;;  pshufb		xmm0, xmm3						; byte swap the state
    DB 66h,0Fh,38h,00h,0C3h
    ; move stack the same way as m_aes_gcm_cpu_auth_* do, so m_ghash_asm can be used
    ; we don't need the full space, just as far as m_ghash_asm requires
    ; m_ghash expects
    ;   [ESP+014H] to hold Hash key H (128 bits)    ([ESP+010H] here)
    ;   [ESP+024H] to hold the old state            ([ESP+020H] here)
    ;   [ESP+034H] to hold the byte-swap mask       ([ESP+030H] here)
    sub         esp, 040h                       
    movdqa      [esp+020h], xmm0                ; state in RSP+020h (024h in m_ghash_asm)
    movdqa      [esp+010h], xmm1                ; key in RSP+010h (014h in m_ghash_asm)
    movdqa      [esp+030h], xmm3                ; swap mask in RSP+030h (034h in m_ghash_asm)

    mov         edx, [EBP+010H]
    mov         ecx, [EBP+014H]
    shr         ecx, 4                          ; number of complete 16-byte blocks
    cmp         ecx, 0
    je          gcm_stream_partial

gcm_stream_block_loop:
    movdqu      xmm1, [edx]                      ; input to xmm1
    call    m_ghash_asm
    lea         edx, [edx+010h]
    loop    gcm_stream_block_loop
 
gcm_stream_partial:
    mov         ecx, [EBP+014H]
    and         ecx, 0fh
    cmp         ecx, 0
    je          gcm_stream_no_partial
    pxor        xmm0, xmm0
    movdqa      [esp], xmm0                 ; push a 0 block to stack to generate 0-padding

gcm_stream_partial_loop:
    mov         al, [edx+ecx-01h]
    mov         [esp+ecx-01h], al
    loop    gcm_stream_partial_loop
    movdqa      xmm1, [esp]
    call    m_ghash_asm

gcm_stream_no_partial:
    mov         ecx, [EBP+008H]
    movdqa      xmm0, [esp+020h]
;;	pshufb		xmm0, [esp+030h]			; byte swap the state
    DB 66h,0Fh,38h,00h,44h,24h,30h
    movdqu      [ecx], xmm0

    mov         esp, ebp                    ; restore old stack pointer
    pop         ebp

    ret

_m_cpu_ghash_stream endp

_text ends

end
