;************************************************************************
; Assembler module for AES Encryption/Decryption on X64 processors.
; Replaces all functions of the C-Module aes.c
; 
; Author:  G. Oed, HOB Gmbh & Co KG
; Date:    22.12.2005
; Version: 1.0
; Checked o.k.
;************************************************************************ 


;-------------------------------------------------------------------------
; Public functions from this module
;-------------------------------------------------------------------------

public AES_Fast_cbc_encrypt
public AES_Fast_cbc_decrypt
public AES_cbc_encrypt_decrypt
public GenAESEncryptKeys
public GenAESDecryptKeys


;--------------------------------------------------------------------------
; Include tables needed for AES into the .text segment
; NOTE: Slightly better performance if tables are in .text and not .data
;--------------------------------------------------------------------------
.code

include fasttabs.inc
include sbox.inc

.code

;--------------------------------------------------------------------------
; AES Round function, encrypt mode
; Works on 4 DWORD variables A, B, C and D using 4 DWORD Tables TabEncT0-T3
; and a DWORD Key Table (max. 60 DWORDs, dependent on rounds count)
; Generates 4 DWORD output variables U, V, W and X
; Note: 1. Table Indices are always taken from low byte!
; ----- 2. N is the round index:
;		0..9  for 128 Bit AES,
;		0..11 for 192 Bit AES,
;		0..13 for 256 Bit AES
;	3. Round functions are used in pairs, last round is different
;
; Round N:
;
; U = TabEncT0[A] ^ TabEncT1[B>>8] ^ TabEncT2[C>>16] ^ TabEncT3[D>>24] ^
;     KeyTab[4+(N*4)+0]
; V = TabEncT0[B] ^ TabEncT1[C>>8] ^ TabEncT2[D>>16] ^ TabEncT3[A>>24] ^
;     KeyTab[4+(N*4)+1]
; W = TabEncT0[C] ^ TabEncT1[D>>8] ^ TabEncT2[A>>16] ^ TabEncT3[B>>24] ^
;     KeyTab[4+(N*4)+2]
; X = TabEncT0[D] ^ TabEncT1[A>>8] ^ TabEncT2[B>>16] ^ TabEncT3[C>>24] ^
;     KeyTab[4+(N*4)+3]
;
; Round N+1:
;
; A = TabEncT0[U] ^ TabEncT1[V>>8] ^ TabEncT2[W>>16] ^ TabEncT3[X>>24] ^
;     KeyTab[4+((N+1)*4)+0]
; B = TabEncT0[V] ^ TabEncT1[W>>8] ^ TabEncT2[X>>16] ^ TabEncT3[U>>24] ^
;     KeyTab[4+((N+1)*4)+1]
; C = TabEncT0[W] ^ TabEncT1[X>>8] ^ TabEncT2[U>>16] ^ TabEncT3[V>>24] ^
;     KeyTab[4+((N+1)*4)+2]
; D = TabEncT0[X] ^ TabEncT1[U>>8] ^ TabEncT2[V>>16] ^ TabEncT3[W>>24] ^
;     KeyTab[4+((N+1)*4)+3]
;
; The last encrypt round function (Index N=9,11,13) is different.
; Instead of TabEncT0-T3 the SBox-Table is used.
; 
; Notation as last round function, input U,V,W,X output A,B,C,D
;
; A = (SBox[U]            | (SBox[V>>8]  <<  8) |
;     (SBox[W>>16] << 16) | (SBox[X>>24] << 24)) ^ KeyTab[4+(N*4)+0]
;
; B = (SBox[V]            | (SBox[W>>8]  << 8)  |
;     (SBox[X>>16] << 16) | (SBox[U>>24] << 24)) ^ KeyTab[4+(N*4)+1]
;
; C = (SBox[W]            | (SBox[X>>8]  << 8)  |
;     (SBox[U>>16] << 16) | (SBox[V>>24] << 24)) ^ KeyTab[4+(N*4)+2]
;
; D = (SBox[X]            | (SBox[U>>8]  << 8)  |
;     (SBox[V>>16] << 16) | (SBox[W>>24] << 24)) ^ KeyTab[4+(N*4)+3]
;-----------------------------------------------------------------------------


;==============================================================
; Perform AES CBC-Encrypt operation
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - BYTE * pInput	 Source Data
;			rdx - BYTE * pOutput	 Destination buffer
;			r8  - DWORD * pEncKeytab Encryption key table
;			r9  - QWORD		 Block count
;			rsp+8  - BYTE * pIVector IVector buffer
;			rsp+16 - DWORD		 Rounds: 10,12,14
; Returns: nothing
; Volatile GP registers used: all
; Checked o.k., all round sizes
;==============================================================
AES_Fast_cbc_encrypt proc frame
	push	rbx
	.PUSHREG rbx
	push	rsi
	.PUSHREG rsi
	push	rdi
	.PUSHREG rdi
	push	rbp
	.PUSHREG rbp
	push	r12
	.PUSHREG r12
	push	r13
	.PUSHREG r13
	push	r14
	.PUSHREG r14
	push	r15
	.PUSHREG r15
.endprolog

BlkCount	EQU	[rsp+64+8]	; rcx saver

pIVector	EQU	[rsp+64+32 +8]	; Parameter 5, QWORD
Rounds		EQU	[rsp+64+32+16]	; Parameter 6, DWORD !!
;	--------------------------------------------------------
;	Save pointers, Block Counter
;	--------------------------------------------------------
	mov	r10,pIVector		; Pointer to buffer
	mov	r12d,DWORD PTR Rounds	; number of rounds (10,12,14)
	mov	r13,rcx			; Source buffer
	mov	r14,rdx			; Destination buffer
	mov	r15,r8			; Key Array
	mov	BlkCount,r9		; save BlockCount
    cmp r9,0
    je  AesCbcEnc_end
	sub	r12,12			; <0: 10, ==0: 12, >0: 14
;	--------------------------------------------------------
;	0. Fetch the IV-Vector for processing start
;	--------------------------------------------------------
	mov	esi,DWORD PTR[r10][0*4]	; fetch DWord 1
	mov	edi,DWORD PTR[r10][1*4]	; fetch DWord 2
	mov	ebp,DWORD PTR[r10][2*4]	; fetch DWord 3
	mov	r8d,DWORD PTR[r10][3*4]	; fetch DWord 4
;---------------------------------------------------------------
; Process rounds for blocks
;---------------------------------------------------------------
AesCbcEnc_NextBlock:
;	--------------------------------------------------------
;	1. Fetch next 4 DWords from input, xor with IV and Key
;	--------------------------------------------------------
	mov	eax,DWORD PTR[r13][0*4]		; fetch next A
	mov	ebx,DWORD PTR[r13][1*4]		; fetch next B
	mov	ecx,DWORD PTR[r13][2*4]		; fetch next C
	xor	eax,esi				; S0 = S[0] ^ Xor[0]
	xor	ebx,edi				; S1 = S[1] ^ Xor[1]
	mov	edx,DWORD PTR[r13][3*4]		; fetch next D

	xor	ecx,ebp				; S2 = S[2] ^ Xor[2]
	xor	edx,r8d				; S3 = S[3] ^ Xor[3]

	xor	eax,DWORD PTR[r15][0*4]		; ^ Key[0]
	xor	ebx,DWORD PTR[r15][1*4]		; ^ Key[1]
	xor	ecx,DWORD PTR[r15][2*4]		; ^ Key[2]
	ror	ebx,8				; prepare: B>>8
	movzx	r8,al				; A LSB
	xor	edx,DWORD PTR[r15][3*4]		; ^ Key[3]
;	--------------------------------------------------------
;	Setup A,B,C,D shift and index registers for round start
;	--------------------------------------------------------
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl				; B>>8 LSB
;	--------------------------------------------------------
;	Round 1:
;	A=eax, B=ebx, C=ecx, D=edx
;	U=esi, V=edi, W=ebp, X->edx
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][4*4]		; ^ Key[4]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][5*4]		; ^ Key[5]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][6*4]		; ^ Key[6]
	mov	ebx,edi				; V -> ebx = B
;	---------------------------------------------------------
;	Note: Now registers eax,ebx,ecx and edx are free !
;	----- r8-r11 hold the current table indices (A-D),
;	      esi,edi and ebp hold the values U, V and W
;	---------------------------------------------------------
						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][7*4]		; ^ Key[7]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 2:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][8*4]		; ^ Key[8]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][9*4]		; ^ Key[9]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][10*4]	; ^ Key[10]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][11*4]	; ^ Key[11]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 3:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][12*4]	; ^ Key[12]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][13*4]	; ^ Key[13]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][14*4]	; ^ Key[14]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][15*4]	; ^ Key[15]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 4:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][16*4]	; ^ Key[16]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][17*4]	; ^ Key[17]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][18*4]	; ^ Key[18]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][19*4]	; ^ Key[19]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 5:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][20*4]	; ^ Key[20]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][21*4]	; ^ Key[21]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][22*4]	; ^ Key[22]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][23*4]	; ^ Key[23]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 6:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][24*4]	; ^ Key[24]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][25*4]	; ^ Key[25]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][26*4]	; ^ Key[26]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][27*4]	; ^ Key[27]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 7:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][28*4]	; ^ Key[28]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][29*4]	; ^ Key[29]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][30*4]	; ^ Key[30]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][31*4]	; ^ Key[31]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 8:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][32*4]	; ^ Key[32]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][33*4]	; ^ Key[33]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][34*4]	; ^ Key[34]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][35*4]	; ^ Key[35]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 9:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	rol	edx,8				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][36*4]	; ^ Key[36]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][37*4]	; ^ Key[37]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][38*4]	; ^ Key[38]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][39*4]	; ^ Key[39]
	ror	ecx,16				; prepare: C>>16
	test	r12,r12				; 10 rounds only ?
	movzx	r9,bl
	js	AesCbcEnc_128_LastRound		; process last round for 128
;	--------------------------------------------------------
;	Round 10:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	ror	edx,24				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][40*4]	; ^ Key[40]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][41*4]	; ^ Key[41]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][42*4]	; ^ Key[42]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][43*4]	; ^ Key[43]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 11:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	ror	edx,24				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][44*4]	; ^ Key[44]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][45*4]	; ^ Key[45]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][46*4]	; ^ Key[46]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][47*4]	; ^ Key[47]
	ror	ecx,16				; prepare: C>>16
	test	r12,r12				; 12 rounds only ?
	movzx	r9,bl
	jz	AesCbcEnc_192_LastRound		; process last round for 192
;	--------------------------------------------------------
;	Round 12:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	ror	edx,24				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][48*4]	; ^ Key[48]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][49*4]	; ^ Key[49]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][50*4]	; ^ Key[50]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][51*4]	; ^ Key[51]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 13:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabEncT0[r8*4]		; TabEncT0[A]
	ror	edx,24				; prepare D>>24
	movzx	r10,cl				; set index for C
	xor	esi,TabEncT1[r9*4]		; ^ TabEncT1[B>>8]
	rol	eax,8				; next: A>>24
	movzx	r11,dl				; set index for D
	xor	esi,TabEncT2[r10*4]		; ^ TabEncT2[C>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabEncT3[r11*4]		; ^ TabEncT3[D>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][52*4]	; ^ Key[52]
	rol	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabEncT3[r8*4]		; TabEncT3[A>>24]
	rol	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabEncT0[r9*4]		; ^ TabEncT0[B]
	rol	ebx,8				; next: B>>24
	movzx	r8,al
	xor	edi,TabEncT1[r10*4]		; ^ TabEncT1[C>>8]
	rol	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabEncT2[r11*4]		; ^ TabEncT2[D>>16]
	rol	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][53*4]	; ^ Key[53]
	rol	eax,8				; next: A>>8
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabEncT2[r8*4]		; TabEncT2[A>>16]
	rol	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabEncT3[r9*4]		; ^ TabEncT3[B>>24]
	rol	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabEncT0[r10*4]		; ^ TabEncT0[C]
	rol	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabEncT1[r11*4]		; ^ TabEncT1[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][54*4]	; ^ Key[54]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabEncT1[r8*4]		; TabEncT1[A>>8]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabEncT2[r9*4]		; ^ TabEncT2[B>>16]
	ror	ebx,8				; prepare: B>>8
	xor	edx,TabEncT3[r10*4]		; ^ TabEncT3[C>>24]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabEncT0[r11*4]		; ^ TabEncT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][55*4]	; ^ Key[55]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 14:
;	Last round function for N=14
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
						; Calculate U
	movzx	esi,SBox[r8]			; SBox[A]
	rol	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	edi,SBox[r9]			; SBox[B>>8]
	movzx	r11,dl
	rol	eax,8				; next: A>>24
	movzx	ebp,SBox[r10]			; SBox[C>>16]
	shl	edi,8
	rol	ecx,8				; next: C>>8
	movzx	r8d,SBox[r11]			; SBox[D>>24]
	shl	ebp,16
	or	esi,edi
	shl	r8,24
	or	esi,ebp
	rol	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][56*4]	; ^ Key[56]
	movzx	r8,al

						; Calculate V
	movzx	edi,SBox[r8]			; SBox[A>>24]
	rol	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,SBox[r9]			; SBox[B]
	movzx	r11,dl
	rol	eax,8				; next: A>>16
	movzx	r8d,SBox[r10]			; SBox[C>>8]
	shl	edi,24
	movzx	r9d,SBox[r11]			; SBox[D>>16]
	shl	r8,8
	shl	r9,16
	or	edi,ebp
	rol	ebx,8				; next: B>>24
	or	edi,r8d
	rol	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][57*4]	; ^ Key[57]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,SBox[r8]			; SBox[A>>16]
	rol	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	r8,SBox[r9]			; SBox[B>>24]
	movzx	r11,dl
	rol	eax,8				; next: A>>8
	movzx	r9,SBox[r10]			; SBox[C]
	shl	ebp,16
	movzx	r10d,SBox[r11]			; SBox[D>>8]
	shl	r8,24
	shl	r10,8
	or	ebp,r8d
	rol	ebx,8				; next: B>>16
	or	ebp,r9d
	rol	ecx,8				; next: C>>24
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][58*4]	; ^ Key[58]
	movzx	r9,bl

						; Calculate X
	movzx	eax,SBox[r8]			; SBox[A>>8]
	rol	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,SBox[r9]			; SBox[B>>16]
	movzx	r11,dl
	movzx	ecx,SBox[r10]			; SBox[C>>24]
	shl	eax,8
	movzx	edx,SBox[r11]			; SBox[D]
	shl	ebx,16
	mov	DWORD PTR [r14][0*4],esi	; Store new A
	or	edx,eax	
	shl	ecx,24
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	or	edx,ebx
	add	r13,16
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	or	edx,ecx
	add	r14,16
	xor	edx,DWORD PTR[r15][59*4]	; ^ Key[59]
	sub	QWORD PTR BlkCount,1
	mov	DWORD PTR [r14][3*4-16],edx	; Store new D
	mov	r8d,edx				; save for next block
	jnz	AesCbcEnc_NextBlock

AesCbcEnc_StoreBackIV:
;	------------------------------------------------------
;	Store back IV data
;	------------------------------------------------------
	mov	r10,pIVector		; Pointer to buffer
	sub	eax,eax			; dummy
	mov	DWORD PTR[r10][0*4],esi	; Store DWord 1
	mov	DWORD PTR[r10][1*4],edi	; Store DWord 2
	mov	DWORD PTR[r10][2*4],ebp	; Store DWord 3
	mov	DWORD PTR[r10][3*4],edx	; Store DWord 4
AesCbcEnc_end:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rdi
	pop	rsi
	pop	rbx
	ret	


	align 16
;	--------------------------------------------------------
;	Last round function for N=10
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
AesCbcEnc_128_LastRound:
						; Calculate U
	movzx	esi,SBox[r8]			; SBox[A]
	rol	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	edi,SBox[r9]			; SBox[B>>8]
	movzx	r11,dl
	rol	eax,8				; next: A>>24
	movzx	ebp,SBox[r10]			; SBox[C>>16]
	shl	edi,8
	rol	ecx,8				; next: C>>8
	movzx	r8d,SBox[r11]			; SBox[D>>24]
	shl	ebp,16
	or	esi,edi
	shl	r8,24
	or	esi,ebp
	rol	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][40*4]	; ^ Key[40]
	movzx	r8,al

						; Calculate V
	movzx	edi,SBox[r8]			; SBox[A>>24]
	rol	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,SBox[r9]			; SBox[B]
	movzx	r11,dl
	rol	eax,8				; next: A>>16
	movzx	r8d,SBox[r10]			; SBox[C>>8]
	shl	edi,24
	movzx	r9d,SBox[r11]			; SBox[D>>16]
	shl	r8,8
	shl	r9,16
	or	edi,ebp
	rol	ebx,8				; next: B>>24
	or	edi,r8d
	rol	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][41*4]	; ^ Key[41]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,SBox[r8]			; SBox[A>>16]
	rol	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	r8,SBox[r9]			; SBox[B>>24]
	movzx	r11,dl
	rol	eax,8				; next: A>>8
	movzx	r9,SBox[r10]			; SBox[C]
	shl	ebp,16
	movzx	r10d,SBox[r11]			; SBox[D>>8]
	shl	r8,24
	shl	r10,8
	or	ebp,r8d
	rol	ebx,8				; next: B>>16
	or	ebp,r9d
	rol	ecx,8				; next: C>>24
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][42*4]	; ^ Key[42]
	movzx	r9,bl

						; Calculate X
	movzx	eax,SBox[r8]			; SBox[A>>8]
	rol	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,SBox[r9]			; SBox[B>>16]
	movzx	r11,dl
	movzx	ecx,SBox[r10]			; SBox[C>>24]
	shl	eax,8
	movzx	edx,SBox[r11]			; SBox[D]
	shl	ebx,16
	mov	DWORD PTR [r14][0*4],esi	; Store new A
	or	edx,eax	
	shl	ecx,24
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	or	edx,ebx
	add	r13,16
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	or	edx,ecx
	add	r14,16
	xor	edx,DWORD PTR[r15][43*4]	; ^ Key[43]
	sub	QWORD PTR BlkCount,1
	mov	DWORD PTR [r14][3*4-16],edx	; Store new D
	mov	r8d,edx				; save for next block
	jnz	AesCbcEnc_NextBlock
	jmp	AesCbcEnc_StoreBackIV


	align 16
;	--------------------------------------------------------
;	Last round function for N=12
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
AesCbcEnc_192_LastRound:
						; Calculate U
	movzx	esi,SBox[r8]			; SBox[A]
	rol	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	edi,SBox[r9]			; SBox[B>>8]
	movzx	r11,dl
	rol	eax,8				; next: A>>24
	movzx	ebp,SBox[r10]			; SBox[C>>16]
	shl	edi,8
	rol	ecx,8				; next: C>>8
	movzx	r8d,SBox[r11]			; SBox[D>>24]
	shl	ebp,16
	or	esi,edi
	shl	r8,24
	or	esi,ebp
	rol	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][48*4]	; ^ Key[48]
	movzx	r8,al

						; Calculate V
	movzx	edi,SBox[r8]			; SBox[A>>24]
	rol	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,SBox[r9]			; SBox[B]
	movzx	r11,dl
	rol	eax,8				; next: A>>16
	movzx	r8d,SBox[r10]			; SBox[C>>8]
	shl	edi,24
	movzx	r9d,SBox[r11]			; SBox[D>>16]
	shl	r8,8
	shl	r9,16
	or	edi,ebp
	rol	ebx,8				; next: B>>24
	or	edi,r8d
	rol	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][49*4]	; ^ Key[49]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,SBox[r8]			; SBox[A>>16]
	rol	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	r8,SBox[r9]			; SBox[B>>24]
	movzx	r11,dl
	rol	eax,8				; next: A>>8
	movzx	r9,SBox[r10]			; SBox[C]
	shl	ebp,16
	movzx	r10d,SBox[r11]			; SBox[D>>8]
	shl	r8,24
	shl	r10,8
	or	ebp,r8d
	rol	ebx,8				; next: B>>16
	or	ebp,r9d
	rol	ecx,8				; next: C>>24
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][50*4]	; ^ Key[50]
	movzx	r9,bl

						; Calculate X
	movzx	eax,SBox[r8]			; SBox[A>>8]
	rol	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,SBox[r9]			; SBox[B>>16]
	movzx	r11,dl
	movzx	ecx,SBox[r10]			; SBox[C>>24]
	shl	eax,8
	movzx	edx,SBox[r11]			; SBox[D]
	shl	ebx,16
	mov	DWORD PTR [r14][0*4],esi	; Store new A
	or	edx,eax	
	shl	ecx,24
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	or	edx,ebx
	add	r13,16
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	or	edx,ecx
	add	r14,16
	xor	edx,DWORD PTR[r15][51*4]	; ^ Key[51]
	sub	QWORD PTR BlkCount,1
	mov	r8d,edx				; save for next block
	mov	DWORD PTR [r14][3*4-16],edx	; Store new D
	jnz	AesCbcEnc_NextBlock
	jmp	AesCbcEnc_StoreBackIV

AES_Fast_cbc_encrypt endp


;--------------------------------------------------------------------------
; AES Round function, decrypt mode
; Works on 4 DWORD variables A, B, C and D using 4 DWORD Tables TabDecT0-T3
; and a DWORD Key Table (max. 60 DWORDs, dependent on rounds count)
; Generates 4 DWORD output variables U, V, W and X
; Note: 1. Table Indices are always taken from low byte!
; ----- 2. N is the round index:
;		0..9  for 128 Bit AES,
;		0..11 for 192 Bit AES,
;		0..13 for 256 Bit AES
;	3. Round functions are used in pairs, last round is different
;
; Round N:
;
; U = TabDecT0[A] ^ TabDecT1[D>>8] ^ TabDecT2[C>>16] ^ TabDecT3[B>>24] ^
;     KeyTab[4+(N*4)+0]
; V = TabDecT0[B] ^ TabDecT1[A>>8] ^ TabDecT2[D>>16] ^ TabDecT3[C>>24] ^
;     KeyTab[4+(N*4)+1]
; W = TabDecT0[C] ^ TabDecT1[B>>8] ^ TabDecT2[A>>16] ^ TabDecT3[D>>24] ^
;     KeyTab[4+(N*4)+2]
; X = TabDecT0[D] ^ TabDecT1[C>>8] ^ TabDecT2[B>>16] ^ TabDecT3[A>>24] ^
;     KeyTab[4+(N*4)+3]
;
; Round N+1:
;
; A = TabDecT0[U] ^ TabDecT1[X>>8] ^ TabDecT2[W>>16] ^ TabDecT3[V>>24] ^
;     KeyTab[4+((N+1)*4)+0]
; B = TabDecT0[V] ^ TabDecT1[U>>8] ^ TabDecT2[X>>16] ^ TabDecT3[W>>24] ^
;     KeyTab[4+((N+1)*4)+1]
; C = TabDecT0[W] ^ TabDecT1[V>>8] ^ TabDecT2[U>>16] ^ TabDecT3[X>>24] ^
;     KeyTab[4+((N+1)*4)+2]
; D = TabDecT0[X] ^ TabDecT1[W>>8] ^ TabDecT2[V>>16] ^ TabDecT3[U>>24] ^
;     KeyTab[4+((N+1)*4)+3]
;
; The last decrypt round function (Index N=9,11,13) is different.
; Instead of TabDecT0-T3 the InvSBox-Table is used.
; 
; Notation as last round function, input U,V,W,X output A,B,C,D
;
; A = (InvSBox[U]            | (InvSBox[X>>8]  <<  8) |
;     (InvSBox[W>>16] << 16) | (InvSBox[V>>24] << 24)) ^ KeyTab[4+(N*4)+0]
;
; B = (InvSBox[V]            | (InvSBox[U>>8]  << 8)  |
;     (InvSBox[X>>16] << 16) | (InvSBox[W>>24] << 24)) ^ KeyTab[4+(N*4)+1]
;
; C = (InvSBox[W]            | (InvSBox[V>>8]  << 8)  |
;     (InvSBox[U>>16] << 16) | (InvSBox[X>>24] << 24)) ^ KeyTab[4+(N*4)+2]
;
; D = (InvSBox[X]            | (InvSBox[W>>8]  << 8)  |
;     (InvSBox[V>>16] << 16) | (InvSBox[U>>24] << 24)) ^ KeyTab[4+(N*4)+3]
;-----------------------------------------------------------------------------


;==============================================================
; Perform AES CBC-Decrypt operation
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - BYTE * pInput	 Source Data
;			rdx - BYTE * pOutput	 Destination buffer
;			r8  - DWORD * pDecKeytab Decryption key table
;			r9  - QWORD		 Block count
;			rsp+8  - BYTE * pIVector IVector buffer
;			rsp+16 - DWORD		 Rounds: 10,12,14
; Returns: nothing
; Volatile GP registers used: all
; Checked o.k., all round sizes
;==============================================================
AES_Fast_cbc_decrypt proc frame
	push	rbx
	.PUSHREG rbx
	push	rsi
	.PUSHREG rsi
	push	rdi
	.PUSHREG rdi
	push	rbp
	.PUSHREG rbp
	push	r12
	.PUSHREG r12
	push	r13
	.PUSHREG r13
	push	r14
	.PUSHREG r14
	push	r15
	.PUSHREG r15
.endprolog

BlkCount	EQU	[rsp+64+8]	; rcx saver

pIVector	EQU	[rsp+64+32 +8]	; Parameter 5, QWORD
Rounds		EQU	[rsp+64+32+16]	; Parameter 6, DWORD !!
;	--------------------------------------------------------
;	Save pointers, Block Counter
;	--------------------------------------------------------
	mov	r12d,DWORD PTR Rounds	; number of rounds (10,12,14)
	mov	r13,rcx			; Source buffer
	mov	r14,rdx			; Destination buffer
	mov	r15,r8			; Key Array
	mov	BlkCount,r9		; save BlockCount
    cmp r9,0
    je  AesCbcDec_End
	sub	r12,12			; <0: 10, ==0: 12, >0: 14
;---------------------------------------------------------------
; Process rounds for blocks
; NOTE: Xor with IV is done past the round functions
;---------------------------------------------------------------
AesCbcDec_NextBlock:
;	--------------------------------------------------------
;	1. Fetch next 4 DWords from input, xor with Key
;	--------------------------------------------------------
	mov	eax,DWORD PTR[r13][0*4]		; fetch next A
	mov	ebx,DWORD PTR[r13][1*4]		; fetch next B
	mov	ecx,DWORD PTR[r13][2*4]		; fetch next C
	mov	edx,DWORD PTR[r13][3*4]		; fetch next D

	xor	eax,DWORD PTR[r15][0*4]		; ^ Key[0]
	xor	ebx,DWORD PTR[r15][1*4]		; ^ Key[1]
	xor	ecx,DWORD PTR[r15][2*4]		; ^ Key[2]
	rol	ebx,8				; prepare: B>>24
	movzx	r8,al				; A LSB
	xor	edx,DWORD PTR[r15][3*4]		; ^ Key[3]
;	--------------------------------------------------------
;	Setup A,B,C,D shift and index registers for round start
;	--------------------------------------------------------
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl				; B>>8 LSB
;	--------------------------------------------------------
;	Round 1:
;	A=eax, B=ebx, C=ecx, D=edx
;	U=esi, V=edi, W=ebp, X->edx
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][4*4]		; ^ Key[4]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>24
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][5*4]		; ^ Key[5]
	ror	eax,8				; next: A>>16
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B>>16
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>24]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][6*4]		; ^ Key[6]
	mov	ebx,edi				; V -> ebx = B
;	---------------------------------------------------------
;	Note: Now registers eax,ebx,ecx and edx are free !
;	----- r8-r11 hold the current table indices (A-D),
;	      esi,edi and ebp hold the values U, V and W
;	---------------------------------------------------------
						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][7*4]		; ^ Key[7]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 2:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][8*4]		; ^ Key[8]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][9*4]		; ^ Key[9]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][10*4]	; ^ Key[10]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][11*4]	; ^ Key[11]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 3:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][12*4]	; ^ Key[12]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][13*4]	; ^ Key[13]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][14*4]	; ^ Key[14]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][15*4]	; ^ Key[15]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 4:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][16*4]	; ^ Key[16]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][17*4]	; ^ Key[17]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][18*4]	; ^ Key[18]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][19*4]	; ^ Key[19]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 5:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][20*4]	; ^ Key[20]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][21*4]	; ^ Key[21]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][22*4]	; ^ Key[22]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][23*4]	; ^ Key[23]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 6:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][24*4]	; ^ Key[24]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][25*4]	; ^ Key[25]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][26*4]	; ^ Key[26]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][27*4]	; ^ Key[27]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 7:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][28*4]	; ^ Key[28]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][29*4]	; ^ Key[29]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][30*4]	; ^ Key[30]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][31*4]	; ^ Key[31]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 8:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][32*4]	; ^ Key[32]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][33*4]	; ^ Key[33]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][34*4]	; ^ Key[34]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][35*4]	; ^ Key[35]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 9:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][36*4]	; ^ Key[36]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][37*4]	; ^ Key[37]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][38*4]	; ^ Key[38]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][39*4]	; ^ Key[39]
	ror	ecx,16				; prepare: C>>16
	test	r12,r12				; 10 rounds only ?
	movzx	r9,bl
	js	AesCbcDec_128_LastRound		; process last round for 128
;	--------------------------------------------------------
;	Round 10:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][40*4]	; ^ Key[40]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][41*4]	; ^ Key[41]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][42*4]	; ^ Key[42]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][43*4]	; ^ Key[43]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 11:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][44*4]	; ^ Key[44]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][45*4]	; ^ Key[45]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][46*4]	; ^ Key[46]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][47*4]	; ^ Key[47]
	ror	ecx,16				; prepare: C>>16
	test	r12,r12				; 12 rounds only ?
	movzx	r9,bl
	jz	AesCbcDec_192_LastRound		; process last round for 192
;	--------------------------------------------------------
;	Round 12:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][48*4]	; ^ Key[48]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][49*4]	; ^ Key[49]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][50*4]	; ^ Key[50]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][51*4]	; ^ Key[51]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 13:
;	--------------------------------------------------------
						; Calculate U
	mov	esi,TabDecT0[r8*4]		; TabDecT0[A]
	ror	edx,8				; prepare D>>8
	movzx	r10,cl				; set index for C
	xor	esi,TabDecT3[r9*4]		; ^ TabDecT3[B>>24]
	ror	eax,8				; next: A>>8
	movzx	r11,dl				; set index for D
	xor	esi,TabDecT2[r10*4]		; ^ TabDecT2[C>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	esi,TabDecT1[r11*4]		; ^ TabDecT1[D>>8]
	ror	ecx,8				; next: C>>24
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][52*4]	; ^ Key[52]
	ror	edx,8				; next: D>>16
	movzx	r10,cl

						; Calculate V
	mov	edi,TabDecT1[r8*4]		; TabDecT1[A>>8]
	ror	eax,8				; next: A>>16
	movzx	r11,dl
	xor	edi,TabDecT0[r9*4]		; ^ TabDecT0[B]
	ror	ebx,8				; next: B>>8
	movzx	r8,al
	xor	edi,TabDecT3[r10*4]		; ^ TabDecT3[C>>24]
	ror	ecx,8				; next: C
	movzx	r9,bl
	xor	edi,TabDecT2[r11*4]		; ^ TabDecT2[D>>16]
	ror	edx,8				; next: D>>8
	movzx	r10,cl
	xor	edi,DWORD PTR[r15][53*4]	; ^ Key[53]
	ror	eax,8				; next: A>>24
	movzx	r11,dl

						; Calculate W
	mov	ebp,TabDecT2[r8*4]		; TabDecT2[A>>16]
	ror	ebx,8				; next: B
	movzx	r8,al
	xor	ebp,TabDecT1[r9*4]		; ^ TabDecT1[B>>8]
	ror	ecx,8				; next: C>>8
	movzx	r9,bl
	xor	ebp,TabDecT0[r10*4]		; ^ TabDecT0[C]
	ror	edx,8				; next: D
	movzx	r10,cl
	xor	ebp,TabDecT3[r11*4]		; ^ TabDecT3[D>>8]
	movzx	r11,dl
	xor	ebp,DWORD PTR[r15][54*4]	; ^ Key[54]
	mov	ebx,edi				; V -> ebx = B

						; Calculate X
	mov	edx,TabDecT3[r8*4]		; TabDecT3[A>>24]
	mov	ecx,ebp				; W -> ecx = C
	xor	edx,TabDecT2[r9*4]		; ^ TabDecT2[B>>16]
	rol	ebx,8				; prepare: B>>24
	xor	edx,TabDecT1[r10*4]		; ^ TabDecT1[C>>8]
	mov	eax,esi				; U -> eax = A
	xor	edx,TabDecT0[r11*4]		; ^ TabDecT0[D]
	movzx	r8,al
	xor	edx,DWORD PTR[r15][55*4]	; ^ Key[55]
	ror	ecx,16				; prepare: C>>16
	movzx	r9,bl
;	--------------------------------------------------------
;	Round 14:
;	Last round function for N=14
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
						; Calculate U
	movzx	esi,InvSBox[r8]			; InvSBox[A]
	ror	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	edi,InvSBox[r9]			; InvSBox[B>>24]
	movzx	r11,dl
	ror	eax,8				; next: A>>8
	movzx	ebp,InvSBox[r10]		; InvSBox[C>>16]
	shl	edi,24
	ror	ecx,8				; next: C>>24
	movzx	r8d,InvSBox[r11]		; InvSBox[D>>8]
	shl	ebp,16
	or	esi,edi
	shl	r8,8
	or	esi,ebp
	ror	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][56*4]	; ^ Key[56]
	movzx	r8,al

						; Calculate V
	movzx	edi,InvSBox[r8]			; InvSBox[A>>8]
	ror	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,InvSBox[r9]			; InvSBox[B]
	movzx	r11,dl
	ror	eax,8				; next: A>>16
	movzx	r8d,InvSBox[r10]		; InvSBox[C>>24]
	shl	edi,8
	movzx	r9d,InvSBox[r11]		; InvSBox[D>>16]
	shl	r8,24
	shl	r9,16
	or	edi,ebp
	ror	ebx,8				; next: B>>8
	or	edi,r8d
	ror	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][57*4]	; ^ Key[57]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,InvSBox[r8]			; InvSBox[A>>16]
	ror	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	r8,InvSBox[r9]			; InvSBox[B>>8]
	movzx	r11,dl
	ror	eax,8				; next: A>>24
	movzx	r9,InvSBox[r10]			; InvSBox[C]
	shl	ebp,16
	movzx	r10d,InvSBox[r11]		; InvSBox[D>>24]
	shl	r8,8
	shl	r10,24
	or	ebp,r8d
	ror	ebx,8				; next: B>>16
	or	ebp,r9d
	ror	ecx,8				; next: C>>8
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][58*4]	; ^ Key[58]
	movzx	r9,bl

						; Calculate X
	movzx	eax,InvSBox[r8]			; InvSBox[A>>24]
	ror	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,InvSBox[r9]			; InvSBox[B>>16]
	movzx	r11,dl
	movzx	ecx,InvSBox[r10]		; InvSBox[C>>8]
	shl	eax,24
	movzx	edx,InvSBox[r11]		; InvSBox[D]
	shl	ebx,16

	mov	r10,pIVector			; Pointer to IV/XOR-buffer
	or	edx,eax	
	shl	ecx,8
	or	edx,ebx
	xor	esi,DWORD PTR [r10][0*4]	; Xor[0] ^ A
	or	edx,ecx
	xor	edi,DWORD PTR [r10][1*4]	; Xor[1] ^ B
	xor	edx,DWORD PTR [r15][59*4]	; ^ Key[59]
	xor	ebp,DWORD PTR [r10][2*4]	; Xor[2] ^ C
	xor	edx,DWORD PTR [r10][3*4]	; Xor[3] ^ D


	mov	eax,DWORD PTR [r13][0*4]	; S[0]
	mov	ebx,DWORD PTR [r13][1*4]	; S[1]
	mov	ecx,DWORD PTR [r13][2*4]	; S[2]
	mov	r8d,DWORD PTR [r13][3*4]	; S[3]

	mov	DWORD PTR [r10][0*4],eax	; S[0]->Xor[0]
	mov	DWORD PTR [r10][1*4],ebx	; S[1]->Xor[1]
	mov	DWORD PTR [r10][2*4],ecx	; S[2]->Xor[2]
	mov	DWORD PTR [r10][3*4],r8d	; S[3]->Xor[3]


	mov	DWORD PTR [r14][0*4],esi	; Store new A
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	mov	DWORD PTR [r14][3*4],edx	; Store new D

	add	r13,16
	add	r14,16

	sub	QWORD PTR BlkCount,1
	jnz	AesCbcDec_NextBlock
;;;	jz	AesCbcDec_End

AesCbcDec_End:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rdi
	pop	rsi
	pop	rbx
	ret	


	align 16
;	--------------------------------------------------------
;	Last round function for N=10
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
AesCbcDec_128_LastRound:
						; Calculate U
	movzx	esi,InvSBox[r8]			; InvSBox[A]
	ror	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	edi,InvSBox[r9]			; InvSBox[B>>24]
	movzx	r11,dl
	ror	eax,8				; next: A>>8
	movzx	ebp,InvSBox[r10]		; InvSBox[C>>16]
	shl	edi,24
	ror	ecx,8				; next: C>>24
	movzx	r8d,InvSBox[r11]		; InvSBox[D>>8]
	shl	ebp,16
	or	esi,edi
	shl	r8,8
	or	esi,ebp
	ror	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][40*4]	; ^ Key[40]
	movzx	r8,al

						; Calculate V
	movzx	edi,InvSBox[r8]			; InvSBox[A>>8]
	ror	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,InvSBox[r9]			; InvSBox[B]
	movzx	r11,dl
	ror	eax,8				; next: A>>16
	movzx	r8d,InvSBox[r10]		; InvSBox[C>>24]
	shl	edi,8
	movzx	r9d,InvSBox[r11]		; InvSBox[D>>16]
	shl	r8,24
	shl	r9,16
	or	edi,ebp
	ror	ebx,8				; next: B>>8
	or	edi,r8d
	ror	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][41*4]	; ^ Key[41]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,InvSBox[r8]			; InvSBox[A>>16]
	ror	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	r8,InvSBox[r9]			; InvSBox[B>>8]
	movzx	r11,dl
	ror	eax,8				; next: A>>24
	movzx	r9,InvSBox[r10]			; InvSBox[C]
	shl	ebp,16
	movzx	r10d,InvSBox[r11]		; InvSBox[D>>24]
	shl	r8,8
	shl	r10,24
	or	ebp,r8d
	ror	ebx,8				; next: B>>16
	or	ebp,r9d
	ror	ecx,8				; next: C>>8
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][42*4]	; ^ Key[42]
	movzx	r9,bl

						; Calculate X
	movzx	eax,InvSBox[r8]			; InvSBox[A>>24]
	ror	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,InvSBox[r9]			; InvSBox[B>>16]
	movzx	r11,dl
	movzx	ecx,InvSBox[r10]		; InvSBox[C>>8]
	shl	eax,24
	movzx	edx,InvSBox[r11]		; InvSBox[D]
	shl	ebx,16

	mov	r10,pIVector			; Pointer to IV/XOR-buffer
	or	edx,eax	
	shl	ecx,8
	or	edx,ebx
	xor	esi,DWORD PTR [r10][0*4]	; Xor[0] ^ A
	or	edx,ecx
	xor	edi,DWORD PTR [r10][1*4]	; Xor[1] ^ B
	xor	edx,DWORD PTR [r15][43*4]	; ^ Key[43]
	xor	ebp,DWORD PTR [r10][2*4]	; Xor[2] ^ C
	xor	edx,DWORD PTR [r10][3*4]	; Xor[3] ^ D


	mov	eax,DWORD PTR [r13][0*4]	; S[0]
	mov	ebx,DWORD PTR [r13][1*4]	; S[1]
	mov	ecx,DWORD PTR [r13][2*4]	; S[2]
	mov	r8d,DWORD PTR [r13][3*4]	; S[3]

	mov	DWORD PTR [r10][0*4],eax	; S[0]->Xor[0]
	mov	DWORD PTR [r10][1*4],ebx	; S[1]->Xor[1]
	mov	DWORD PTR [r10][2*4],ecx	; S[2]->Xor[2]
	mov	DWORD PTR [r10][3*4],r8d	; S[3]->Xor[3]

	mov	DWORD PTR [r14][0*4],esi	; Store new A
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	mov	DWORD PTR [r14][3*4],edx	; Store new D

	add	r13,16
	add	r14,16

	sub	QWORD PTR BlkCount,1
	jnz	AesCbcDec_NextBlock
	jmp	AesCbcDec_End


	align 16
;	--------------------------------------------------------
;	Last round function for N=12
;	A=eax, B=ebx, C=ecx, D=edx
;	r8,r9, Index for round start loaded, r10,r11 to be loaded
;	--------------------------------------------------------
AesCbcDec_192_LastRound:
						; Calculate U
	movzx	esi,InvSBox[r8]			; InvSBox[A]
	ror	edx,8				; prepare: D>>8
	movzx	r10,cl
	movzx	edi,InvSBox[r9]			; InvSBox[B>>24]
	movzx	r11,dl
	ror	eax,8				; next: A>>8
	movzx	ebp,InvSBox[r10]		; InvSBox[C>>16]
	shl	edi,24
	ror	ecx,8				; next: C>>24
	movzx	r8d,InvSBox[r11]		; InvSBox[D>>8]
	shl	ebp,16
	or	esi,edi
	shl	r8,8
	or	esi,ebp
	ror	ebx,8				; next: B
	or	esi,r8d
	movzx	r9,bl
	xor	esi,DWORD PTR[r15][48*4]	; ^ Key[48]
	movzx	r8,al

						; Calculate V
	movzx	edi,InvSBox[r8]			; InvSBox[A>>8]
	ror	edx,8				; prepare: D>>16
	movzx	r10,cl
	movzx	ebp,InvSBox[r9]			; InvSBox[B]
	movzx	r11,dl
	ror	eax,8				; next: A>>16
	movzx	r8d,InvSBox[r10]		; InvSBox[C>>24]
	shl	edi,8
	movzx	r9d,InvSBox[r11]		; InvSBox[D>>16]
	shl	r8,24
	shl	r9,16
	or	edi,ebp
	ror	ebx,8				; next: B>>8
	or	edi,r8d
	ror	ecx,8				; next: C
	or	edi,r9d
	movzx	r8,al
	xor	edi,DWORD PTR[r15][49*4]	; ^ Key[49]
	movzx	r9,bl

						; Calculate W
	movzx	ebp,InvSBox[r8]			; InvSBox[A>>16]
	ror	edx,8				; prepare: D>>24
	movzx	r10,cl
	movzx	r8,InvSBox[r9]			; InvSBox[B>>8]
	movzx	r11,dl
	ror	eax,8				; next: A>>24
	movzx	r9,InvSBox[r10]			; InvSBox[C]
	shl	ebp,16
	movzx	r10d,InvSBox[r11]		; InvSBox[D>>24]
	shl	r8,8
	shl	r10,24
	or	ebp,r8d
	ror	ebx,8				; next: B>>16
	or	ebp,r9d
	ror	ecx,8				; next: C>>8
	or	ebp,r10d
	movzx	r8,al
	xor	ebp,DWORD PTR[r15][50*4]	; ^ Key[50]
	movzx	r9,bl

						; Calculate X
	movzx	eax,InvSBox[r8]			; InvSBox[A>>24]
	ror	edx,8				; prepare: D
	movzx	r10,cl
	movzx	ebx,InvSBox[r9]			; InvSBox[B>>16]
	movzx	r11,dl
	movzx	ecx,InvSBox[r10]		; InvSBox[C>>8]
	shl	eax,24
	movzx	edx,InvSBox[r11]		; InvSBox[D]
	shl	ebx,16

	mov	r10,pIVector			; Pointer to IV/XOR-buffer
	or	edx,eax	
	shl	ecx,8
	or	edx,ebx
	xor	esi,DWORD PTR [r10][0*4]	; Xor[0] ^ A
	or	edx,ecx
	xor	edi,DWORD PTR [r10][1*4]	; Xor[1] ^ B
	xor	edx,DWORD PTR [r15][51*4]	; ^ Key[51]
	xor	ebp,DWORD PTR [r10][2*4]	; Xor[2] ^ C
	xor	edx,DWORD PTR [r10][3*4]	; Xor[3] ^ D


	mov	eax,DWORD PTR [r13][0*4]	; S[0]
	mov	ebx,DWORD PTR [r13][1*4]	; S[1]
	mov	ecx,DWORD PTR [r13][2*4]	; S[2]
	mov	r8d,DWORD PTR [r13][3*4]	; S[3]

	mov	DWORD PTR [r10][0*4],eax	; S[0]->Xor[0]
	mov	DWORD PTR [r10][1*4],ebx	; S[1]->Xor[1]
	mov	DWORD PTR [r10][2*4],ecx	; S[2]->Xor[2]
	mov	DWORD PTR [r10][3*4],r8d	; S[3]->Xor[3]

	mov	DWORD PTR [r14][0*4],esi	; Store new A
	mov	DWORD PTR [r14][1*4],edi	; Store new B
	mov	DWORD PTR [r14][2*4],ebp	; Store new C
	mov	DWORD PTR [r14][3*4],edx	; Store new D

	add	r13,16
	add	r14,16

	sub	QWORD PTR BlkCount,1
	jnz	AesCbcDec_NextBlock
	jmp	AesCbcDec_End
AES_Fast_cbc_decrypt endp


;==============================================================
; Perform AES CBC-Encrypt/Decrypt operation
;
; Calling convention: X64 fastcall
; Input parameters:	rcx -  BYTE * pInput	 Source Data
;			rdx -  DWORD  InpOffset  Offset to start of data
;			r8  -  BYTE * pOutput	 Destination buffer
;			r9  -  DWORD  OutpOffset Offset to start of data
;			rsp+8  DWORD * pKeytab	 Enc/Decryption key table 
;			rsp+16 DWORD		 Block count
;			rsp+24 BYTE * pIVector   IVector buffer
;			rsp+32 DWORD		 IV-Offset
;			rsp+40 QWORD		 Rounds: 10,12,14
;			rsp+48 BYTE    Mode	 0 - encrypt, else decrypt
; Returns: nothing
; Volatile GP registers used: all
; Checked o.k., all round sizes
;==============================================================
AES_cbc_encrypt_decrypt proc frame

;---------------------------------------------------------------------
; Stack access definitions
; Note: 4 Savers are pushed on stack for rcx,rdx,r8 and r9 by compiler
; ----- ahead of the parameters !
;---------------------------------------------------------------------
pKeyTab		EQU	[rsp+32+56+ 8]
BlockCount	EQU	[rsp+32+56+16]
pIVector	EQU	[rsp+32+56+24]
IVOffset	EQU	[rsp+32+56+32]
Rounds		EQU	[rsp+32+56+40]
Mode		EQU	[rsp+32+56+48]

	sub	rsp,32+16+8		; reserve space for rcx,rdx,r8,r9,
					; and parameters to the UPs, align!!
	.ALLOCSTACK	56
.endprolog
;	------------------------------------------------------
;	Setup registers according to input parameters
;	------------------------------------------------------
	rol	edx,32			; clear upper half
	rol	r9d,32			; dto.
	add	rcx,rdx			; Input pointer
	add	r8,r9			; Output pointer
	mov	r9d,DWORD PTR BlockCount; Block counter
	mov	rdx,r8			; set output pointer
	mov	r8,pKeyTab		; set key table pointer
;	------------------------------------------------------
;	Setup calling parameters (esp+32 and up!)
;	NOTE: Calling convention adheres to Compiler !!
;	------------------------------------------------------
	mov	r10d,DWORD PTR Rounds	; rounds count
	mov	r11,pIVector		; pointer to IVector
	mov	eax,DWORD PTR IVOffset	; offset (DWORD)
	mov	QWORD PTR [rsp+40],r10	; param 2: Rounds
	add	r11,rax			; add offset to pointer
	movzx	eax,BYTE PTR Mode	; 0 - encrypt
	mov	QWORD PTR [rsp+32],r11	; param 1: pIVector
	test	eax,eax
	jnz	DoAesDecrypt
	call	AES_Fast_cbc_encrypt
	add	rsp,56
	ret

DoAesDecrypt:
	call	AES_Fast_cbc_decrypt
	add	rsp,56
	ret
AES_cbc_encrypt_decrypt endp

;==================================================================
; AES Key expansion, used for Encrypt and also Decrypt.
; For decrypt mode post processing must be done on the key elements
;
; Calling convention: X64 fastcall
; Input parameters:	rcx -  BYTE *  pKeyData	  Source Key Data
;			rdx -  DWORD   DataOffset Offset to start of data
;			r8  -  DWORD   KeyLen	  Number of DWORDS (4,6,8)
;			r9  -  DWORD * pKeyTab    Key table to load
; Returns: int Status - 0 o.k., -1 key length error
; Volatile GP registers used: all
; Checked o.k., all round sizes
;==============================================================
GenAESEncryptKeys proc frame
	push	rbx
	.PUSHREG rbx

.endprolog
;	---------------------------------------------
;	Check valid key length (fall through if good)
;	---------------------------------------------
	rol	edx,32			; clear upper half rdx (offset)
	cmp	r8d,8			; in range ?
	mov	r10,rcx			; pointer to key data
	ja	InvalidKeyLenAes	
	rol	r8d,3			; adjust to table (8 byte wide)
	add	r10,rdx			; add offset
	jmp	KeyGenLenJmpTab[r8]	; note upper half cleared !!

;----------------------------------------------------------------------
; Generate Keydata for 4 DWORD key data (10 rounds, 44 DWORDS expanded)
;----------------------------------------------------------------------
AesKeyGenLen_4:
;	-----------------------------------------------
;	1. Copy the 4 DWORD Input data to the Key array
;	-----------------------------------------------
	mov	eax,DWORD PTR [r10][0*4]
	mov	ecx,DWORD PTR [r10][1*4]

	mov	DWORD PTR [r9][0*4],eax		; Key[0]
	mov	DWORD PTR [r9][1*4],ecx		; Key[1]

	mov	edx,DWORD PTR [r10][2*4]
	mov	eax,DWORD PTR [r10][3*4]

	mov	DWORD PTR [r9][2*4],edx		; Key[2]
	mov	DWORD PTR [r9][3*4],eax		; Key[3]
;	------------------------------------------------------
;	2. Expand the Key material
;	------------------------------------------------------
	mov	ebx,1				; RCon
	mov	r11,10				; Counter
	add	r9,4*4				; start index of expansion
;	------------------------------------------------------
;	Process for 10 loops a 4 DWORDS
;	------------------------------------------------------
AesExpand4_Loop:
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	edx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shl	edx,24
	movzx	ecx,SBox[r10]			; SBox[s>>8]
	shr	eax,8				; next: s>>16
	xor	ecx,ebx				; SBox[s>>8] ^ RCon
	movzx	r10,al
	or	ecx,edx
	movzx	edx,SBox[r10]			; SBox[s>>16]
	shr	eax,8				; next: s>>24
	shl	edx,8
	movzx	r10,al
	or	edx,ecx
	movzx	ecx,SBox[r10]			; SBox[s>>24]
	add	ebx,ebx				; RCon << 1
	mov	eax,1Bh				; modified RCon round 9
	shl	ecx,16
	test	ebx,100h			; modify RCon (modulo 0x11B) ?
	cmovnz	ebx,eax				; yes

	or	edx,ecx
	mov	eax,DWORD PTR [r9][0*4-4*4]	; Key[i-KeyLen]

	xor	eax,edx				; Key[i-KeyLen] ^ s
	mov	DWORD PTR [r9][0*4],eax		; Key[i], next s

	mov	edx,DWORD PTR [r9][1*4-4*4]	; Key[i+1-KeyLen]
	xor	eax,edx				; Key[i+1-KeyLen] ^ s
	mov	DWORD PTR [r9][1*4],eax		; Key[i+1], next s

	mov	edx,DWORD PTR [r9][2*4-4*4]	; Key[i+2-KeyLen]
	xor	eax,edx				; Key[i+2-KeyLen] ^ s
	mov	DWORD PTR [r9][2*4],eax		; Key[i+2], next s

	mov	edx,DWORD PTR [r9][3*4-4*4]	; Key[i+3-KeyLen]
	xor	eax,edx				; Key[i+3-KeyLen] ^ s
	mov	DWORD PTR [r9][3*4],eax		; Key[i+3], next s

	add	r9,4*4				; next index range
	sub	r11,1
	jnz	AesExpand4_Loop
	xor	rax,rax

	pop	rbx
	ret
;----------------------------------------------------------------------
; Generate Keydata for 6 DWORD key data (7/8 rounds, 52 DWORDS expanded)
;----------------------------------------------------------------------
AesKeyGenLen_6:
;	-----------------------------------------------
;	1. Copy the 6 DWORD Input data to the Key array
;	-----------------------------------------------
	mov	eax,DWORD PTR [r10][0*4]
	mov	ecx,DWORD PTR [r10][1*4]

	mov	DWORD PTR [r9][0*4],eax		; Key[0]
	mov	DWORD PTR [r9][1*4],ecx		; Key[1]

	mov	edx,DWORD PTR [r10][2*4]
	mov	eax,DWORD PTR [r10][3*4]

	mov	DWORD PTR [r9][2*4],edx		; Key[2]
	mov	DWORD PTR [r9][3*4],eax		; Key[3]

	mov	ecx,DWORD PTR [r10][4*4]
	mov	eax,DWORD PTR [r10][5*4]

	mov	DWORD PTR [r9][4*4],ecx		; Key[4]
	mov	DWORD PTR [r9][5*4],eax		; Key[5]
;	------------------------------------------------------
;	2. Expand the Key material
;	------------------------------------------------------
	mov	ebx,1				; RCon
	mov	r11,7				; Counter
	add	r9,6*4				; start index of expansion
;	------------------------------------------------------
;	2.1. Process for 7 full loops a 6 DWORDS
;	------------------------------------------------------
AesExpand6_Loop:
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	edx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shl	edx,24
	movzx	ecx,SBox[r10]			; SBox[s>>8]
	shr	eax,8				; next: s>>16
	xor	ecx,ebx				; ^ RCon
	movzx	r10,al
	or	ecx,edx
	movzx	edx,SBox[r10]			; SBox[s>>16]
	shr	eax,8				; next: s>>24
	shl	edx,8
	movzx	r10,al
	or	edx,ecx
	movzx	ecx,SBox[r10]			; SBox[s>>24]

	shl	ecx,16
	add	ebx,ebx				; RCon << 1

	or	edx,ecx

	mov	eax,DWORD PTR [r9][0*4-6*4]	; Key[i-KeyLen]
	xor	eax,edx				; Key[i-KeyLen] ^ s
	mov	DWORD PTR [r9][0*4],eax		; Key[i], next s

	mov	edx,DWORD PTR [r9][1*4-6*4]	; Key[i+1-KeyLen]
	xor	eax,edx				; Key[i+1-KeyLen] ^ s
	mov	DWORD PTR [r9][1*4],eax		; Key[i+1], next s

	mov	edx,DWORD PTR [r9][2*4-6*4]	; Key[i+2-KeyLen]
	xor	eax,edx				; Key[i+2-KeyLen] ^ s
	mov	DWORD PTR [r9][2*4],eax		; Key[i+2], next s

	mov	edx,DWORD PTR [r9][3*4-6*4]	; Key[i+3-KeyLen]
	xor	eax,edx				; Key[i+3-KeyLen] ^ s
	mov	DWORD PTR [r9][3*4],eax		; Key[i+3], next s

	mov	edx,DWORD PTR [r9][4*4-6*4]	; Key[i+4-KeyLen]
	xor	eax,edx				; Key[i+4-KeyLen] ^ s
	mov	DWORD PTR [r9][4*4],eax		; Key[i+4], next s

	mov	edx,DWORD PTR [r9][5*4-6*4]	; Key[i+5-KeyLen]
	xor	eax,edx				; Key[i+5-KeyLen] ^ s
	mov	DWORD PTR [r9][5*4],eax		; Key[i+5], next s

	add	r9,6*4				; next index range
	sub	r11,1
	jnz	AesExpand6_Loop
;	------------------------------------------------------
;	2.2. Process last round, 4 DWORDS !
;	------------------------------------------------------
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	edx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shl	edx,24
	movzx	ecx,SBox[r10]			; SBox[s>>8]
	shr	eax,8				; next: s>>16
	xor	ecx,ebx				; ^ RCon
	movzx	r10,al
	or	ecx,edx
	movzx	edx,SBox[r10]			; SBox[s>>16]
	shr	eax,8				; next: s>>24
	shl	edx,8
	movzx	r10,al
	or	edx,ecx
	movzx	ecx,SBox[r10]			; SBox[s>>24]
	shl	ecx,16

	or	edx,ecx

	mov	eax,DWORD PTR [r9][0*4-6*4]	; Key[i-KeyLen]
	xor	eax,edx				; Key[i-KeyLen] ^ s
	mov	DWORD PTR [r9][0*4],eax		; Key[i], next s

	mov	edx,DWORD PTR [r9][1*4-6*4]	; Key[i+1-KeyLen]
	xor	eax,edx				; Key[i+1-KeyLen] ^ s
	mov	DWORD PTR [r9][1*4],eax		; Key[i+1], next s

	mov	edx,DWORD PTR [r9][2*4-6*4]	; Key[i+2-KeyLen]
	xor	eax,edx				; Key[i+2-KeyLen] ^ s
	mov	DWORD PTR [r9][2*4],eax		; Key[i+2], next s

	mov	edx,DWORD PTR [r9][3*4-6*4]	; Key[i+3-KeyLen]
	xor	eax,edx				; Key[i+3-KeyLen] ^ s
	mov	DWORD PTR [r9][3*4],eax		; Key[i+3], next s

	xor	rax,rax

	pop	rbx
	ret
;----------------------------------------------------------------------
; Generate Keydata for 8 DWORD key data (6/7 rounds, 60 DWORDS expanded)
;----------------------------------------------------------------------
AesKeyGenLen_8:
;	-----------------------------------------------
;	1. Copy the 8 DWORD Input data to the Key array
;	-----------------------------------------------
	mov	eax,DWORD PTR [r10][0*4]
	mov	ecx,DWORD PTR [r10][1*4]

	mov	DWORD PTR [r9][0*4],eax		; Key[0]
	mov	DWORD PTR [r9][1*4],ecx		; Key[1]

	mov	edx,DWORD PTR [r10][2*4]
	mov	eax,DWORD PTR [r10][3*4]

	mov	DWORD PTR [r9][2*4],edx		; Key[2]
	mov	DWORD PTR [r9][3*4],eax		; Key[3]

	mov	ecx,DWORD PTR [r10][4*4]
	mov	eax,DWORD PTR [r10][5*4]

	mov	DWORD PTR [r9][4*4],ecx		; Key[4]
	mov	DWORD PTR [r9][5*4],eax		; Key[5]

	mov	edx,DWORD PTR [r10][6*4]
	mov	eax,DWORD PTR [r10][7*4]

	mov	DWORD PTR [r9][6*4],edx		; Key[2]
	mov	DWORD PTR [r9][7*4],eax		; Key[3]
;	------------------------------------------------------
;	2. Expand the Key material
;	------------------------------------------------------
	mov	ebx,1				; RCon
	mov	r11,6				; Counter
	add	r9,8*4				; start index of expansion
;	------------------------------------------------------
;	2.1. Process for 6 full loops a 8 DWORDS
;	2.1.1. 4 Dwords with RCon xor
;	------------------------------------------------------
AesExpand8_Loop:
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	edx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shl	edx,24
	movzx	ecx,SBox[r10]			; SBox[s>>8]
	shr	eax,8				; next: s>>16
	xor	ecx,ebx				; ^ RCon
	movzx	r10,al
	or	ecx,edx
	movzx	edx,SBox[r10]			; SBox[s>>16]
	shr	eax,8				; next: s>>24
	shl	edx,8
	movzx	r10,al
	or	edx,ecx
	movzx	ecx,SBox[r10]			; SBox[s>>24]

	shl	ecx,16

	or	edx,ecx
	mov	eax,DWORD PTR [r9][0*4-8*4]	; Key[i-KeyLen]

	add	ebx,ebx				; RCon << 1
	xor	eax,edx				; Key[i-KeyLen] ^ s
	mov	DWORD PTR [r9][0*4],eax		; Key[i], next s

	mov	edx,DWORD PTR [r9][1*4-8*4]	; Key[i+1-KeyLen]
	xor	eax,edx				; Key[i+1-KeyLen] ^ s
	mov	DWORD PTR [r9][1*4],eax		; Key[i+1], next s

	mov	edx,DWORD PTR [r9][2*4-8*4]	; Key[i+2-KeyLen]
	xor	eax,edx				; Key[i+2-KeyLen] ^ s
	mov	DWORD PTR [r9][2*4],eax		; Key[i+2], next s

	mov	edx,DWORD PTR [r9][3*4-8*4]	; Key[i+3-KeyLen]
	xor	eax,edx				; Key[i+3-KeyLen] ^ s
	mov	DWORD PTR [r9][3*4],eax		; Key[i+3], next s
;	------------------------------------------------------
;	2.1.2. 4 Dwords with s-Shuffle only
;	------------------------------------------------------
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	ecx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shr	eax,8				; next: s>>16
	movzx	edx,SBox[r10]			; SBox[s>>8]
	movzx	r10,al
	shl	edx,8
	movzx	r8d,SBox[r10]			; SBox[s>>16]
	or	ecx,edx
	shr	eax,8				; next: s>>24
	movzx	r10,al
	shl	r8d,16
	movzx	eax,SBox[r10]			; SBox[s>>24]
	or	ecx,r8d
	shl	eax,24
	or	eax,ecx

	mov	edx,DWORD PTR [r9][4*4-8*4]	; Key[i+4-KeyLen]
	xor	eax,edx				; Key[i+4-KeyLen] ^ s
	mov	DWORD PTR [r9][4*4],eax		; Key[i+4], next s

	mov	edx,DWORD PTR [r9][5*4-8*4]	; Key[i+5-KeyLen]
	xor	eax,edx				; Key[i+5-KeyLen] ^ s
	mov	DWORD PTR [r9][5*4],eax		; Key[i+5], next s

	mov	edx,DWORD PTR [r9][6*4-8*4]	; Key[i+6-KeyLen]
	xor	eax,edx				; Key[i+6-KeyLen] ^ s
	mov	DWORD PTR [r9][6*4],eax		; Key[i+6], next s

	mov	edx,DWORD PTR [r9][7*4-8*4]	; Key[i+7-KeyLen]
	xor	eax,edx				; Key[i+7-KeyLen] ^ s
	mov	DWORD PTR [r9][7*4],eax		; Key[i+7], next s

	add	r9,8*4				; next index range
	sub	r11,1
	jnz	AesExpand8_Loop
;	------------------------------------------------------
;	2.2. Process last round 4 DWORDS
;	------------------------------------------------------
	movzx	r10,al
	shr	eax,8				; next: s>>8
	movzx	edx,SBox[r10]			; SBox[s]
	movzx	r10,al
	shl	edx,24
	movzx	ecx,SBox[r10]			; SBox[s>>8]
	shr	eax,8				; next: s>>16
	xor	ecx,ebx				; ^ RCon
	movzx	r10,al
	or	ecx,edx
	movzx	edx,SBox[r10]			; SBox[s>>16]
	shr	eax,8				; next: s>>24
	shl	edx,8
	movzx	r10,al
	or	edx,ecx
	movzx	ecx,SBox[r10]			; SBox[s>>24]

	shl	ecx,16

	or	edx,ecx

	mov	eax,DWORD PTR [r9][0*4-8*4]	; Key[i-KeyLen]
	xor	eax,edx				; Key[i-KeyLen] ^ s
	mov	DWORD PTR [r9][0*4],eax		; Key[i], next s

	mov	edx,DWORD PTR [r9][1*4-8*4]	; Key[i+1-KeyLen]
	xor	eax,edx				; Key[i+1-KeyLen] ^ s
	mov	DWORD PTR [r9][1*4],eax		; Key[i+1], next s

	mov	edx,DWORD PTR [r9][2*4-8*4]	; Key[i+2-KeyLen]
	xor	eax,edx				; Key[i+2-KeyLen] ^ s
	mov	DWORD PTR [r9][2*4],eax		; Key[i+2], next s

	mov	edx,DWORD PTR [r9][3*4-8*4]	; Key[i+3-KeyLen]
	xor	eax,edx				; Key[i+3-KeyLen] ^ s
	mov	DWORD PTR [r9][3*4],eax		; Key[i+3], next s

	sub	rax,rax
	pop	rbx
	ret


InvalidKeyLenAes:
	xor	rax,rax
	sub	rax,1

	pop	rbx
	ret



	align	16
KeyGenLenJmpTab	label	QWORD
	DQ	InvalidKeyLenAes	; 0
	DQ	InvalidKeyLenAes	; 1
	DQ	InvalidKeyLenAes	; 2
	DQ	InvalidKeyLenAes	; 3
	DQ	AesKeyGenLen_4		; 4
	DQ	InvalidKeyLenAes	; 5
	DQ	AesKeyGenLen_6		; 6
	DQ	InvalidKeyLenAes	; 7
	DQ	AesKeyGenLen_8		; 8

GenAESEncryptKeys endp

;==================================================================
; AES Key expansion for Decrypt
;
; Calling convention: X64 fastcall
; Input parameters:	rcx -  BYTE *  pKeyData	  Source Key Data
;			rdx -  DWORD   DataOffset Offset to start of data
;			r8  -  DWORD   KeyLen	  Number of DWORDS (4,6,8)
;			r9  -  DWORD * pKeyTab    Key table to load
; Returns: int Status - 0 o.k., -1 key length error
; Volatile GP registers used: all
; Checked o.k., all round sizes
;==============================================================
GenAESDecryptKeys proc frame
	push	rbx
	.PUSHREG rbx
	push	rsi
	.PUSHREG rsi
	push	r15
	.PUSHREG r15

	sub	rsp,32			; local savers for rcx,rdx,r8,r9
	.ALLOCSTACK 32			; stack is aligned now !
.endprolog
;	-------------------------------------------------------
;	Expand the key material, same as for encrypt
;	-------------------------------------------------------
	mov	rbx,r8			; save key length
	mov	r15,r9			; save table pointer
	call	GenAESEncryptKeys	; generate expanded array
	test	rax,rax			; check for key length error
	jnz	AESGenDecryptKeysEnd	; error occured !
;	-------------------------------------------------------
;	Reverse the key element order now
;	-------------------------------------------------------
	mov	r8,rbx			; key length
	mov	eax,ebx			; dto.
	mov	r9,r15			; pointer to first 4 elements
	shr	r8,1			; key length / 2
	shr	eax,1			; dto.
	add	r15,4*4			; prepare for Mix Start later
	add	eax,3			; number of quads
	add	r8,3			; number of Quad elements to xchange
	shl	eax,5			; *(8 * 4)
	add	rbx,5			; 4,6,8->9,11,13 used later...
	lea	r10,[r15+rax-4*4]	; pointer to top 4 elements

AesDecKey_ReverseLoop:
	mov	eax,DWORD PTR[r9][0*4]	; Key[i]
	mov	ecx,DWORD PTR[r9][1*4]	; Key[i+1]
	mov	edx,DWORD PTR[r10][0*4]	; Key[n-i]
	mov	r11d,DWORD PTR[r10][1*4]; Key[n-(i+1)]

	mov	DWORD PTR [r10][0*4],eax
	mov	DWORD PTR [r10][1*4],ecx
	mov	DWORD PTR [r9][0*4],edx
	mov	DWORD PTR [r9][1*4],r11d

	mov	eax,DWORD PTR[r9][2*4]	; Key[i+2]
	mov	ecx,DWORD PTR[r9][3*4]	; Key[i+3]
	mov	edx,DWORD PTR[r10][2*4]	; Key[n-(i+2)]
	mov	r11d,DWORD PTR[r10][3*4]; Key[n-(i+3)]

	mov	DWORD PTR [r10][2*4],eax
	mov	DWORD PTR [r10][3*4],ecx
	mov	DWORD PTR [r9][2*4],edx
	mov	DWORD PTR [r9][3*4],r11d

	sub	r10,4*4
	add	r9,4*4
	sub	r8,1
	jnz	AesDecKey_ReverseLoop
;	-------------------------------------------------------
;	Premix 2nd to last-1st round elements (4 DWords)
;	-------------------------------------------------------
AesDecKey_MixLoop:
	mov	eax,DWORD PTR[r15][0*4]	; Key[i]
	mov	edx,DWORD PTR[r15][1*4]	; Key[i+1]
	movzx	r8,al			; s0
	movzx	r9,dl			; s1
	shr	eax,8			; next: s0>>8
	shr	edx,8			; next: s1>>8
	movzx	r10,SBox[r8]		; SBox[s0]
	movzx	r11,SBox[r9]		; SBox[s1]
	movzx	r8,al
	movzx	r9,dl
	mov	ecx,TabDecT0[r10*4]	; TabDecT0[SBox[s0]]
	mov	esi,TabDecT0[r11*4]	; TabDecT0[SBox[s1]]

	shr	eax,8			; next: s0>>16
	shr	edx,8			; next: s1>>16
	movzx	r10,SBox[r8]		; SBox[s0>>8]
	movzx	r11,SBox[r9]		; SBox[s1>>8]
	movzx	r8,al
	movzx	r9,dl
	xor	ecx,TabDecT1[r10*4]	; TabDecT1[SBox[s0>>8]]
	xor	esi,TabDecT1[r11*4]	; TabDecT1[SBox[s1>>8]]

	shr	eax,8			; next: s0>>24
	shr	edx,8			; next: s1>>24
	movzx	r10,SBox[r8]		; SBox[s0>>16]
	movzx	r11,SBox[r9]		; SBox[s1>>16]
	movzx	r8,al
	movzx	r9,dl
	xor	ecx,TabDecT2[r10*4]	; TabDecT2[SBox[s0>>16]]
	xor	esi,TabDecT2[r11*4]	; TabDecT2[SBox[s1>>16]]

	movzx	r10,SBox[r8]		; SBox[s0>>24]
	movzx	r11,SBox[r9]		; SBox[s1>>24]
	xor	ecx,TabDecT3[r10*4]	; TabDecT3[SBox[s0>>24]]
	xor	esi,TabDecT3[r11*4]	; TabDecT3[SBox[s1>>24]]

	mov	DWORD PTR[r15][0*4],ecx	; Key[i]
	mov	DWORD PTR[r15][1*4],esi	; Key[i+1]


	mov	eax,DWORD PTR[r15][2*4]	; Key[i+2]
	mov	edx,DWORD PTR[r15][3*4]	; Key[i+3]
	movzx	r8,al			; s2
	movzx	r9,dl			; s3
	shr	eax,8			; next: s2>>8
	shr	edx,8			; next: s3>>8
	movzx	r10,SBox[r8]		; SBox[s2]
	movzx	r11,SBox[r9]		; SBox[s3]
	movzx	r8,al
	movzx	r9,dl
	mov	ecx,TabDecT0[r10*4]	; TabDecT0[SBox[s2]]
	mov	esi,TabDecT0[r11*4]	; TabDecT0[SBox[s3]]

	shr	eax,8			; next: s2>>16
	shr	edx,8			; next: s3>>16
	movzx	r10,SBox[r8]		; SBox[s2>>8]
	movzx	r11,SBox[r9]		; SBox[s3>>8]
	movzx	r8,al
	movzx	r9,dl
	xor	ecx,TabDecT1[r10*4]	; TabDecT1[SBox[s2>>8]]
	xor	esi,TabDecT1[r11*4]	; TabDecT1[SBox[s3>>8]]

	shr	eax,8			; next: s2>>24
	shr	edx,8			; next: s3>>24
	movzx	r10,SBox[r8]		; SBox[s2>>16]
	movzx	r11,SBox[r9]		; SBox[s3>>16]
	movzx	r8,al
	movzx	r9,dl
	xor	ecx,TabDecT2[r10*4]	; TabDecT2[SBox[s2>>16]]
	xor	esi,TabDecT2[r11*4]	; TabDecT2[SBox[s3>>16]]

	movzx	r10,SBox[r8]		; SBox[s2>>24]
	movzx	r11,SBox[r9]		; SBox[s3>>24]
	xor	ecx,TabDecT3[r10*4]	; TabDecT3[SBox[s2>>24]]
	xor	esi,TabDecT3[r11*4]	; TabDecT3[SBox[s3>>24]]

	mov	DWORD PTR[r15][2*4],ecx	; Key[i+2]
	mov	DWORD PTR[r15][3*4],esi	; Key[i+3]

	add	r15,4*4
	sub	ebx,1
	jnz	AesDecKey_MixLoop

	xor	rax,rax


AESGenDecryptKeysEnd:
	add	rsp,32
	pop	r15
	pop	rsi
	pop	rbx
	ret
GenAESDecryptKeys endp

end
