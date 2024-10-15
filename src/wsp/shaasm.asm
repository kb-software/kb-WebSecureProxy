;**************************************************************
;
; SHA-1 full assembler module
; Operation gain compared to pure C: max. 11%
;
; Is a full replacement for s1.c !
; (Either use s1.c OR use this assembler module!)
;
; NOTE NOTE NOTE:
; not all operations / paths tested !!!
;
; Author: Gerhard Oed, HOB Gmbh & Co. KG
; Date:   13.12.2005
;**************************************************************


;----------------------------------------------------------
; public procedure declarations
;----------------------------------------------------------
public sha1_block
public SHA1_Init
public SHA1_Update
public SHA1_Final


; SHA-1 Round constants
K_00_19	EQU	5A827999h
K_20_39	EQU	6ED9EBA1h
K_40_59	EQU	8F1BBCDCh
K_60_79	EQU	0CA62C1D6h


; SHA-1 Initial values for A-E
INIT_DATA_h0 EQU	67452301h
INIT_DATA_h1 EQU	0efcdab89h
INIT_DATA_h2 EQU	98badcfeh
INIT_DATA_h3 EQU	10325476h
INIT_DATA_h4 EQU	0c3d2e1f0h

;---------------------------------------------------------
; SHA Array definitions
; NOTE NOTE NOTE: Keep size same as for C definitions !!!
;---------------------------------------------------------
SHA_Array struct
SHA_Data	DD	16 DUP (?)	; Data gather / Wt save array
SHA_h0		DD	?		; Value A
SHA_h1		DD	?		; Value B
SHA_h2		DD	?		; Value C
SHA_h3		DD	?		; Value D
SHA_h4		DD	?		; Value E
SHA_Nl		DD	?		; Total length Low  Word
SHA_Nh		DD	?		; Total length High Word
SHA_Num		DD	?		; Stored Data length
SHA_Array ends


.code

;=======================================================
; Initialize the SHA-Array
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - UBIT32 * SHA_Array
; Returns: nothing
; Volatile GP registers used: rax
;
; Tested: o.k.
;=======================================================
SHA1_Init proc
	xor	eax,eax
	mov	SHA_Array.SHA_h0[rcx],INIT_DATA_h0
	mov	SHA_Array.SHA_h1[rcx],INIT_DATA_h1
	mov	SHA_Array.SHA_h2[rcx],INIT_DATA_h2
	mov	SHA_Array.SHA_h3[rcx],INIT_DATA_h3
	mov	SHA_Array.SHA_h4[rcx],INIT_DATA_h4
	mov	SHA_Array.SHA_Nl[rcx],eax
	mov	SHA_Array.SHA_Nh[rcx],eax
	mov	SHA_Array.SHA_Num[rcx],eax
	ret
SHA1_Init endp


;=======================================================
; Perform round operations on a SHA1 block (16 DWORDs)
; Full unrolled loop !
; NOTE: Byte swapping of data integrated in round functions
; -----
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - UBIT32 * SHA_Array
; Returns: nothing
; Volatile GP registers used: all
;
; Tested: o.k.
;=======================================================
sha1_block proc frame
;	------------------------------------------------------
;	Prologue code, save non volatile registers, alloc temp
;	------------------------------------------------------
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
	push	r15
	.PUSHREG r15
.endprolog

;	-----------------------------------------------
;	Fetch A,B,C,D and E
;	-----------------------------------------------
	mov	r15,rcx				; SHA_Array pointer

	mov	eax,SHA_Array.SHA_h0[rcx]	; A
	mov	ebx,SHA_Array.SHA_h1[r15]	; B
	mov	ecx,SHA_Array.SHA_h2[r15]	; C
	mov	edx,SHA_Array.SHA_h3[r15]	; D
	mov	esi,SHA_Array.SHA_h4[r15]	; E
;=================================================================
; Part 1, Rounds 1-20, F(b,c,d) = ((c^d)&b)^d, Kt = K_00_19
;=================================================================
;	----------------------------------------------------------
;	Round 1, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Data[0]
;	----------------------------------------------------------
	mov	r8d,SHA_Array.SHA_Data[0*4][r15]; D[0], save
	mov	ebp,edx				; d
	bswap	r8d
	mov	r11d,eax			; a
	xor	ebp,ecx				; c^d
	add	esi,r8d				; e + Wt	
	and	ebp,ebx				; (c^d)&b
	rol	r11d,5				; a<<<5
	xor	ebp,edx				; ((c^d)&b)^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 2, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Data[1]
;	----------------------------------------------------------
	mov	r9d,SHA_Array.SHA_Data[1*4][r15]; D[1], save
	mov	ebp,ecx				; d
	bswap	r9d
	mov	r11d,edi			; a
	xor	ebp,ebx				; c^d
	add	edx,r9d				; e + Wt	
	and	ebp,eax				; (c^d)&b
	rol	r11d,5				; a<<<5
	xor	ebp,ecx				; ((c^d)&b)^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 3, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Data[2]
;	----------------------------------------------------------
	mov	r10d,SHA_Array.SHA_Data[2*4][r15]; D[2], save
	mov	ebp,ebx				; d
	mov	r11d,esi			; a
	bswap	r10d
	xor	ebp,eax				; c^d
	add	ecx,r10d			; e + Wt	
	and	ebp,edi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[2*4][r15],r10d
	xor	ebp,ebx				; ((c^d)&b)^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 4, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Data[3]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[3*4][r15]
	mov	ebp,eax				; d
	bswap	r12d
	mov	r11d,edx			; a
	xor	ebp,edi				; c^d
	add	ebx,r12d			; e + Wt	
	and	ebp,esi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[3*4][r15],r12d
	xor	ebp,eax				; ((c^d)&b)^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 5, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Data[4]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[4*4][r15]
	mov	ebp,edi				; d
	bswap	r12d
	mov	r11d,ecx			; a
	xor	ebp,esi				; c^d
	add	eax,r12d			; e + Wt	
	and	ebp,edx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[4*4][r15],r12d
	xor	ebp,edi				; ((c^d)&b)^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 6, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Data[5]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[5*4][r15]
	mov	ebp,esi				; d
	bswap	r12d
	mov	r11d,ebx			; a
	xor	ebp,edx				; c^d
	add	edi,r12d			; e + Wt	
	and	ebp,ecx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[5*4][r15],r12d
	xor	ebp,esi				; ((c^d)&b)^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 7, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Data[6]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[6*4][r15]
	mov	ebp,edx				; d
	bswap	r12d
	mov	r11d,eax			; a
	xor	ebp,ecx				; c^d
	add	esi,r12d			; e + Wt	
	and	ebp,ebx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[6*4][r15],r12d
	xor	ebp,edx				; ((c^d)&b)^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 8, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Data[7]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[7*4][r15]
	mov	ebp,ecx				; d
	bswap	r12d
	mov	r11d,edi			; a
	xor	ebp,ebx				; c^d
	add	edx,r12d			; e + Wt	
	and	ebp,eax				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[7*4][r15],r12d
	xor	ebp,ecx				; ((c^d)&b)^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	----------------------------------------------------------
;	Round 9, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Data[8]
;	----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[8*4][r15]
	mov	ebp,ebx				; d
	bswap	r12d
	mov	r11d,esi			; a
	xor	ebp,eax				; c^d
	add	ecx,r12d			; e + Wt	
	and	ebp,edi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[8*4][r15],r12d
	xor	ebp,ebx				; ((c^d)&b)^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	-----------------------------------------------------------
;	Round 10, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Data[9]
;	-----------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[9*4][r15]
	mov	ebp,eax				; d
	bswap	r12d
	mov	r11d,edx			; a
	xor	ebp,edi				; c^d
	add	ebx,r12d			; e + Wt	
	and	ebp,esi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[9*4][r15],r12d
	xor	ebp,eax				; ((c^d)&b)^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 11, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Data[10]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[10*4][r15]
	mov	ebp,edi				; d
	bswap	r12d
	mov	r11d,ecx			; a
	xor	ebp,esi				; c^d
	add	eax,r12d			; e + Wt	
	and	ebp,edx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[10*4][r15],r12d
	xor	ebp,edi				; ((c^d)&b)^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 12, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Data[11]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[11*4][r15]
	mov	ebp,esi				; d
	bswap	r12d
	mov	r11d,ebx			; a
	xor	ebp,edx				; c^d
	add	edi,r12d			; e + Wt	
	and	ebp,ecx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[11*4][r15],r12d
	xor	ebp,esi				; ((c^d)&b)^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 13, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Data[12]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[12*4][r15]
	mov	ebp,edx				; d
	bswap	r12d
	mov	r11d,eax			; a
	xor	ebp,ecx				; c^d
	add	esi,r12d			; e + Wt	
	and	ebp,ebx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[12*4][r15],r12d
	xor	ebp,edx				; ((c^d)&b)^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 14, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Data[13]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[13*4][r15]
	mov	ebp,ecx				; d
	bswap	r12d
	mov	r11d,edi			; a
	xor	ebp,ebx				; c^d
	add	edx,r12d			; e + Wt	
	and	ebp,eax				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[13*4][r15],r12d
	xor	ebp,ecx				; ((c^d)&b)^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 15, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Data[14]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[14*4][r15]
	mov	ebp,ebx				; d
	bswap	r12d
	mov	r11d,esi			; a
	xor	ebp,eax				; c^d
	add	ecx,r12d			; e + Wt	
	and	ebp,edi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[14*4][r15],r12d
	xor	ebp,ebx				; ((c^d)&b)^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 16, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Data[15]
;	------------------------------------------------------------
	mov	r12d,SHA_Array.SHA_Data[15*4][r15]
	mov	ebp,eax				; d
	bswap	r12d
	mov	r11d,edx			; a
	xor	ebp,edi				; c^d
	add	ebx,r12d			; e + Wt	
	and	ebp,esi				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[15*4][r15],r12d
	xor	ebp,eax				; ((c^d)&b)^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;---------------------------------------------------------------
; NOTE: From Round 17 to 80 the Wts must be calculated different
; ----- if not using precalculated Wt-Data !!
;---------------------------------------------------------------
;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[2*4][r15]  ; D2
	xor	r9d,SHA_Array.SHA_Data[3*4][r15]  ; D3
	xor	r10d,SHA_Array.SHA_Data[4*4][r15] ; D4

	xor	r8d,SHA_Array.SHA_Data[8*4][r15]  ; D8
	xor	r9d,SHA_Array.SHA_Data[9*4][r15]  ; D9
	xor	r10d,SHA_Array.SHA_Data[10*4][r15]; D10

	xor	r8d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r9d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r10d,SHA_Array.SHA_Data[15*4][r15] ; D15

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1
;	------------------------------------------------------------
;	Round 17, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[16]
;	------------------------------------------------------------
	mov	ebp,edi				; d
	mov	r11d,ecx			; a
	xor	ebp,esi				; c^d
	add	eax,r8d				; e + Wt
	and	ebp,edx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[0*4][r15],r8d; save W0
	xor	ebp,edi				; ((c^d)&b)^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 18, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[17]
;	------------------------------------------------------------
	mov	ebp,esi				; d
	mov	r11d,ebx			; a
	xor	ebp,edx				; c^d
	add	edi,r9d				; e + Wt
	and	ebp,ecx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[1*4][r15],r9d; save W1
	xor	ebp,esi				; ((c^d)&b)^d = f()
	add	edi,r11d				; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 19, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[18]
;	------------------------------------------------------------
	mov	ebp,edx				; d
	mov	r11d,eax			; a
	xor	ebp,ecx				; c^d
	add	esi,r10d			; e + Wt
	and	ebp,ebx				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[2*4][r15],r10d; save W2
	xor	ebp,edx				; ((c^d)&b)^d = f()
	add	esi,r11d				; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[3*4][r15]  ; D3
	xor	r9d,SHA_Array.SHA_Data[4*4][r15]  ; D4
	xor	r10d,SHA_Array.SHA_Data[5*4][r15] ; D5

	xor	r8d,SHA_Array.SHA_Data[5*4][r15]  ; D5
	xor	r9d,SHA_Array.SHA_Data[6*4][r15]  ; D6
	xor	r10d,SHA_Array.SHA_Data[7*4][r15] ; D7

	xor	r8d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r9d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r10d,SHA_Array.SHA_Data[13*4][r15] ; D13

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 20, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[19]
;	------------------------------------------------------------
	mov	ebp,ecx				; d
	mov	r11d,edi				; a
	xor	ebp,ebx				; c^d
	add	edx,r8d				; e + Wt
	and	ebp,eax				; (c^d)&b
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[3*4][r15],r8d; save W3
	xor	ebp,ecx				; ((c^d)&b)^d = f()
	add	edx,r11d				; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_00_19]		; (a<<5) + f() + e + Wt + Kt
;-------------------------------------------------------------------
; Rounds 21-40, F(b,c,d) = b^c^d, Kt = K_20_39
;-------------------------------------------------------------------
;	------------------------------------------------------------
;	Round 21, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[20]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[4*4][r15],r9d; save W4
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 22, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[21]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[5*4][r15],r10d; save W5
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[6*4][r15]  ; D6
	xor	r9d,SHA_Array.SHA_Data[7*4][r15]  ; D7
	xor	r10d,SHA_Array.SHA_Data[8*4][r15] ; D8

	xor	r8d,SHA_Array.SHA_Data[8*4][r15]  ; D8
	xor	r9d,SHA_Array.SHA_Data[9*4][r15]  ; D9
	xor	r10d,SHA_Array.SHA_Data[10*4][r15] ; D10

	xor	r8d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r9d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r10d,SHA_Array.SHA_Data[0*4][r15] ; D0

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 23, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[22]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[6*4][r15],r8d; save W6
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d				; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 24, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[23]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[7*4][r15],r9d; save W7
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 25, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[24]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[8*4][r15],r10d; save W8
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r9d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r10d,SHA_Array.SHA_Data[11*4][r15] ; D11

	xor	r8d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r9d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r10d,SHA_Array.SHA_Data[13*4][r15] ; D13

	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r9d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r10d,SHA_Array.SHA_Data[3*4][r15]  ; D3

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 26, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[25]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[9*4][r15],r8d; save W9
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 27, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[26]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[10*4][r15],r9d; save W10
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 28, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[27]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[11*4][r15],r10d; save W11
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r9d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r10d,SHA_Array.SHA_Data[14*4][r15] ; D14

	xor	r8d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r9d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r10d,SHA_Array.SHA_Data[0*4][r15]  ; D0

	xor	r8d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r9d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r10d,SHA_Array.SHA_Data[6*4][r15]  ; D6

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 29, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[28]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[12*4][r15],r8d; save W12
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 30, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[29]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[13*4][r15],r9d; save W13
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 31, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[30]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[14*4][r15],r10d; save W14
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r9d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r10d,SHA_Array.SHA_Data[1*4][r15]  ; D1

	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r9d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r10d,SHA_Array.SHA_Data[3*4][r15]  ; D3

	xor	r8d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r9d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r10d,SHA_Array.SHA_Data[9*4][r15]  ; D9

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 32, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[31]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[15*4][r15],r8d; save W15
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 33, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[32]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[0*4][r15],r9d; save U0
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 34, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[33]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[1*4][r15],r10d; save U1
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r9d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r10d,SHA_Array.SHA_Data[4*4][r15]  ; D4

	xor	r8d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r9d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r10d,SHA_Array.SHA_Data[6*4][r15]  ; D6

	xor	r8d,SHA_Array.SHA_Data[10*4][r15]   ; D10
	xor	r9d,SHA_Array.SHA_Data[11*4][r15]   ; D11
	xor	r10d,SHA_Array.SHA_Data[12*4][r15]  ; D12

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 35, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[34]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[2*4][r15],r8d; save U2
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 36, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[35]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[3*4][r15],r9d; save U3
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 37, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[36]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax				; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[4*4][r15],r10d; save U4
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d				; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r9d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r10d,SHA_Array.SHA_Data[7*4][r15]  ; D7

	xor	r8d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r9d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r10d,SHA_Array.SHA_Data[9*4][r15]  ; D9

	xor	r8d,SHA_Array.SHA_Data[13*4][r15]   ; D13
	xor	r9d,SHA_Array.SHA_Data[14*4][r15]   ; D14
	xor	r10d,SHA_Array.SHA_Data[15*4][r15]  ; D15

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 38, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[37]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[5*4][r15],r8d; save U5
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 39, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[38]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[6*4][r15],r9d; save U6
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 40, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[39]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[7*4][r15],r10d; save U7
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_20_39]		; (a<<5) + f() + e + Wt + Kt
;-------------------------------------------------------------------
; Rounds 41-60, F(b,c,d) = (b&c) | ((b|c)&d), Kt = K_40_59
;-------------------------------------------------------------------
;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r9d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r10d,SHA_Array.SHA_Data[10*4][r15] ; D10

	xor	r8d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r9d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r10d,SHA_Array.SHA_Data[12*4][r15] ; D12

	xor	r8d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r9d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r10d,SHA_Array.SHA_Data[2*4][r15]  ; D2

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 41, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[40]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r12d,edx			; b
	and	ebp,esi				; (b&c)
	or	r12d,esi			; (b|c)
	mov	r11d,ecx			; a
	and	r12d,edi			; (b|c) & d
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[8*4][r15],r8d; save U8
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 42, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[41]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r12d,ecx			; b
	and	ebp,edx				; (b&c)
	or	r12d,edx			; (b|c)
	mov	r11d,ebx			; a
	and	r12d,esi			; (b|c) & d
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[9*4][r15],r9d; save U9
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 43, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[42]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r12d,ebx			; b
	and	ebp,ecx				; (b&c)
	or	r12d,ecx			; (b|c)
	mov	r11d,eax			; a
	and	r12d,edx			; (b|c) & d
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[10*4][r15],r10d; save U10
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r9d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r10d,SHA_Array.SHA_Data[13*4][r15] ; D13

	xor	r8d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r9d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r10d,SHA_Array.SHA_Data[15*4][r15] ; D15

	xor	r8d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r9d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r10d,SHA_Array.SHA_Data[5*4][r15]  ; D5

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 44, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[43]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r12d,eax			; b
	and	ebp,ebx				; (b&c)
	or	r12d,ebx			; (b|c)
	mov	r11d,edi			; a
	and	r12d,ecx			; (b|c) & d
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[11*4][r15],r8d; save U11
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 45, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[44]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r12d,edi			; b
	and	ebp,eax				; (b&c)
	or	r12d,eax			; (b|c)
	mov	r11d,esi			; a
	and	r12d,ebx			; (b|c) & d
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[12*4][r15],r9d; save U12
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 46, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[45]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r12d,esi			; b
	and	ebp,edi				; (b&c)
	or	r12d,edi			; (b|c)
	mov	r11d,edx			; a
	and	r12d,eax			; (b|c) & d
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[13*4][r15],r10d; save U13
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r9d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r10d,SHA_Array.SHA_Data[0*4][r15]  ; D0

	xor	r8d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r9d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r10d,SHA_Array.SHA_Data[2*4][r15]  ; D2

	xor	r8d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r9d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r10d,SHA_Array.SHA_Data[8*4][r15]  ; D8

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 47, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[46]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r12d,edx			; b
	and	ebp,esi				; (b&c)
	or	r12d,esi			; (b|c)
	mov	r11d,ecx			; a
	and	r12d,edi			; (b|c) & d
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[14*4][r15],r8d; save U14
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 48, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[47]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r12d,ecx			; b
	and	ebp,edx				; (b&c)
	or	r12d,edx			; (b|c)
	mov	r11d,ebx			; a
	and	r12d,esi			; (b|c) & d
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[15*4][r15],r9d; save U15
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 49, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[48]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r12d,ebx			; b
	and	ebp,ecx				; (b&c)
	or	r12d,ecx			; (b|c)
	mov	r11d,eax			; a
	and	r12d,edx			; (b|c) & d
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[0*4][r15],r10d; save V0
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r9d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r10d,SHA_Array.SHA_Data[3*4][r15]  ; D3

	xor	r8d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r9d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r10d,SHA_Array.SHA_Data[5*4][r15]  ; D5

	xor	r8d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r9d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r10d,SHA_Array.SHA_Data[11*4][r15] ; D11

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 50, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[49]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r12d,eax			; b
	and	ebp,ebx				; (b&c)
	or	r12d,ebx			; (b|c)
	mov	r11d,edi			; a
	and	r12d,ecx			; (b|c) & d
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[1*4][r15],r8d; save V1
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 51, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[50]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r12d,edi			; b
	and	ebp,eax				; (b&c)
	or	r12d,eax			; (b|c)
	mov	r11d,esi			; a
	and	r12d,ebx			; (b|c) & d
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[2*4][r15],r9d; save V2
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 52, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[51]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r12d,esi			; b
	and	ebp,edi				; (b&c)
	or	r12d,edi			; (b|c)
	mov	r11d,edx			; a
	and	r12d,eax			; (b|c) & d
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[3*4][r15],r10d; save V3
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r9d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r10d,SHA_Array.SHA_Data[6*4][r15]  ; D6

	xor	r8d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r9d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r10d,SHA_Array.SHA_Data[8*4][r15]  ; D8

	xor	r8d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r9d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r10d,SHA_Array.SHA_Data[14*4][r15] ; D14

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 53, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[52]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r12d,edx			; b
	and	ebp,esi				; (b&c)
	or	r12d,esi			; (b|c)
	mov	r11d,ecx			; a
	and	r12d,edi			; (b|c) & d
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[4*4][r15],r8d; save V4
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 54, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[53]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r12d,ecx			; b
	and	ebp,edx				; (b&c)
	or	r12d,edx			; (b|c)
	mov	r11d,ebx			; a
	and	r12d,esi			; (b|c) & d
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[5*4][r15],r9d; save V5
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 55, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[54]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r12d,ebx			; b
	and	ebp,ecx				; (b&c)
	or	r12d,ecx			; (b|c)
	mov	r11d,eax			; a
	and	r12d,edx			; (b|c) & d
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[6*4][r15],r10d; save V6
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r9d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r10d,SHA_Array.SHA_Data[9*4][r15]  ; D9

	xor	r8d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r9d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r10d,SHA_Array.SHA_Data[11*4][r15] ; D11

	xor	r8d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r9d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r10d,SHA_Array.SHA_Data[1*4][r15]  ; D1

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 56, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[55]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r12d,eax			; b
	and	ebp,ebx				; (b&c)
	or	r12d,ebx			; (b|c)
	mov	r11d,edi			; a
	and	r12d,ecx			; (b|c) & d
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[7*4][r15],r8d; save V7
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 57, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[56]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r12d,edi			; b
	and	ebp,eax				; (b&c)
	or	r12d,eax			; (b|c)
	mov	r11d,esi			; a
	and	r12d,ebx			; (b|c) & d
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[8*4][r15],r9d; save V8
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 58, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[57]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r12d,esi			; b
	and	ebp,edi				; (b&c)
	or	r12d,edi			; (b|c)
	mov	r11d,edx			; a
	and	r12d,eax			; (b|c) & d
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[9*4][r15],r10d; save V9
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r9d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r10d,SHA_Array.SHA_Data[12*4][r15] ; D12

	xor	r8d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r9d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r10d,SHA_Array.SHA_Data[14*4][r15] ; D14

	xor	r8d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r9d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r10d,SHA_Array.SHA_Data[4*4][r15]  ; D4

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 59, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[58]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r12d,edx			; b
	and	ebp,esi				; (b&c)
	or	r12d,esi			; (b|c)
	mov	r11d,ecx			; a
	and	r12d,edi			; (b|c) & d
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[10*4][r15],r8d; save V10
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 60, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[59]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r12d,ecx			; b
	and	ebp,edx				; (b&c)
	or	r12d,edx			; (b|c)
	mov	r11d,ebx			; a
	and	r12d,esi			; (b|c) & d
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[11*4][r15],r9d; save V11
	or	ebp,r12d			; (b&c)|((b|c)&d) = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_40_59]		; (a<<5) + f() + e + Wt + Kt
;-------------------------------------------------------------------
; Rounds 61-80, F(b,c,d) = b^c^d, Kt = K_60_79
;-------------------------------------------------------------------
;	------------------------------------------------------------
;	Round 61, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[60]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[12*4][r15],r10d; save V12
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r9d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r10d,SHA_Array.SHA_Data[15*4][r15] ; D15

	xor	r8d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r9d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r10d,SHA_Array.SHA_Data[1*4][r15]  ; D1

	xor	r8d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r9d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r10d,SHA_Array.SHA_Data[7*4][r15]  ; D7

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 62, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[61]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[13*4][r15],r8d; save V13
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 63, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[62]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[14*4][r15],r9d; save V14
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 64, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[63]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[15*4][r15],r10d; save V15
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[0*4][r15]   ; D0
	xor	r9d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r10d,SHA_Array.SHA_Data[2*4][r15]  ; D2

	xor	r8d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r9d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r10d,SHA_Array.SHA_Data[4*4][r15]  ; D4

	xor	r8d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r9d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r10d,SHA_Array.SHA_Data[10*4][r15] ; D10

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 65, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[64]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[0*4][r15],r8d; save Y0
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 66, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[65]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[1*4][r15],r9d; save Y1
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 67, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[66]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[2*4][r15],r10d; save Y2
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[3*4][r15]   ; D3
	xor	r9d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r10d,SHA_Array.SHA_Data[5*4][r15]  ; D5

	xor	r8d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r9d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r10d,SHA_Array.SHA_Data[7*4][r15]  ; D7

	xor	r8d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r9d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r10d,SHA_Array.SHA_Data[13*4][r15] ; D13

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 68, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[67]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[3*4][r15],r8d; save Y3
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 69, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[68]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[4*4][r15],r9d; save Y4
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 70, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[69]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[5*4][r15],r10d; save Y5
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[6*4][r15]   ; D6
	xor	r9d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	xor	r10d,SHA_Array.SHA_Data[8*4][r15]  ; D8

	xor	r8d,SHA_Array.SHA_Data[8*4][r15]   ; D8
	xor	r9d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r10d,SHA_Array.SHA_Data[10*4][r15] ; D10

	xor	r8d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r9d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r10d,SHA_Array.SHA_Data[0*4][r15]  ; D0

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 71, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[70]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[6*4][r15],r8d; save Y6
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 72, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[71]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[7*4][r15],r9d; save Y7
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 73, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[72]
;	------------------------------------------------------------
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
	mov	SHA_Array.SHA_Data[8*4][r15],r10d; save Y8
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	lea	edi,[esi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[9*4][r15]   ; D9
	xor	r9d,SHA_Array.SHA_Data[10*4][r15]  ; D10
	xor	r10d,SHA_Array.SHA_Data[11*4][r15] ; D11

	xor	r8d,SHA_Array.SHA_Data[11*4][r15]  ; D11
	xor	r9d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r10d,SHA_Array.SHA_Data[13*4][r15] ; D13

	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	xor	r9d,SHA_Array.SHA_Data[2*4][r15]   ; D2
	xor	r10d,SHA_Array.SHA_Data[3*4][r15]  ; D3

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 74, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[73]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[9*4][r15],r8d; save Y9 (not needed!)
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d			; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 75, T=edx, A=esi, B=edi, C=eax, D=ebx, E=ecx, Wt[74]
;	------------------------------------------------------------
	mov	ebp,edi				; b
	mov	r11d,esi			; a
	xor	ebp,eax				; b^c
	add	ecx,r9d				; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[10*4][r15],r9d; save Y10 (not needed!)
	xor	ebp,ebx				; b^c^d = f()
	add	ecx,r11d			; (a<<<5) + e + Wt
	rol	edi,30				; B<<<30
	lea	edx,[ecx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 76, T=ecx, A=edx, B=esi, C=edi, D=eax, E=ebx, Wt[75]
;	------------------------------------------------------------
	mov	ebp,esi				; b
	mov	r11d,edx			; a
	xor	ebp,edi				; b^c
	add	ebx,r10d			; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[11*4][r15],r10d; save Y11 (not needed!)
	xor	ebp,eax				; b^c^d = f()
	add	ebx,r11d			; (a<<<5) + e + Wt
	rol	esi,30				; B<<<30
	lea	ecx,[ebx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wts for next 3 rounds
;	------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[12*4][r15]  ; D12
	xor	r9d,SHA_Array.SHA_Data[13*4][r15]  ; D13
	xor	r10d,SHA_Array.SHA_Data[14*4][r15] ; D14

	xor	r8d,SHA_Array.SHA_Data[14*4][r15]  ; D14
	xor	r9d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	xor	r10d,SHA_Array.SHA_Data[0*4][r15]  ; D0

	xor	r8d,SHA_Array.SHA_Data[4*4][r15]   ; D4
	xor	r9d,SHA_Array.SHA_Data[5*4][r15]   ; D5
	xor	r10d,SHA_Array.SHA_Data[6*4][r15]  ; D6

	rol	r8d,1
	rol	r9d,1
	rol	r10d,1

;	------------------------------------------------------------
;	Round 77, T=ebx, A=ecx, B=edx, C=esi, D=edi, E=eax, Wt[76]
;	------------------------------------------------------------
	mov	ebp,edx				; b
	mov	r11d,ecx			; a
	xor	ebp,esi				; b^c
	add	eax,r8d				; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[12*4][r15],r8d; save Y12 (not needed!)
	xor	ebp,edi				; b^c^d = f()
	add	eax,r11d			; (a<<<5) + e + Wt
	rol	edx,30				; B<<<30
	lea	ebx,[eax+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 78, T=eax, A=ebx, B=ecx, C=edx, D=esi, E=edi, Wt[77]
;	------------------------------------------------------------
	mov	ebp,ecx				; b
	mov	r11d,ebx			; a
	xor	ebp,edx				; b^c
	add	edi,r9d				; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[13*4][r15],r9d; save Y13 (not needed!)
	xor	ebp,esi				; b^c^d = f()
	add	edi,r11d			; (a<<<5) + e + Wt
	rol	ecx,30				; B<<<30
	lea	eax,[edi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Round 79, T=edi, A=eax, B=ebx, C=ecx, D=edx, E=esi, Wt[78]
;	------------------------------------------------------------
	xor	r8d,SHA_Array.SHA_Data[15*4][r15]  ; D15
	mov	ebp,ebx				; b
	mov	r11d,eax			; a
	xor	ebp,ecx				; b^c
	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1
	add	esi,r10d			; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[14*4][r15],r10d; save Y14 (not needed!)
	xor	ebp,edx				; b^c^d = f()
	add	esi,r11d			; (a<<<5) + e + Wt
	rol	ebx,30				; B<<<30
	xor	r8d,SHA_Array.SHA_Data[7*4][r15]   ; D7
	lea	edi,[esi+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt

;	------------------------------------------------------
;	Precalculate Wt for last round -> MUST interleave !!
;	------------------------------------------------------
;;;	xor	r8d,SHA_Array.SHA_Data[15*4][r15]  ; D15, moved up

;;;	xor	r8d,SHA_Array.SHA_Data[1*4][r15]   ; D1, moved up

;;;	xor	r8d,SHA_Array.SHA_Data[7*4][r15]   ; D7, moved up


;	------------------------------------------------------------
;	Round 80, T=esi, A=edi, B=eax, C=ebx, D=ecx, E=edx, Wt[79]
;	------------------------------------------------------------
	mov	ebp,eax				; b
	mov	r11d,edi			; a
	rol	r8d,1				; Wt <<< 1
	xor	ebp,ebx				; b^c
	add	edx,r8d				; e + Wt
	rol	r11d,5				; a<<<5
;;	mov	SHA_Array.SHA_Data[15*4][r15],r8d; save Y15 (not needed!)
	xor	ebp,ecx				; b^c^d = f()
	add	edx,r11d				; (a<<<5) + e + Wt
	rol	eax,30				; B<<<30
	lea	esi,[edx+ebp+K_60_79]		; (a<<5) + f() + e + Wt + Kt
;	------------------------------------------------------------
;	Past Round 80, A=esi, B=edi, C=eax, D=ebx, E=ecx
;	------------------------------------------------------------
	xor	r8,r8				; dummy

;	-----------------------------------------------
;	Store back A,B,C,D and E
;	-----------------------------------------------
	add	SHA_Array.SHA_h0[r15],esi	; A
	add	SHA_Array.SHA_h1[r15],edi	; B
	add	SHA_Array.SHA_h2[r15],eax	; C
	add	SHA_Array.SHA_h3[r15],ebx	; D
	add	SHA_Array.SHA_h4[r15],ecx	; E

;	------------------------------------------------
;	Epilogue code (also used for SEH)
;	------------------------------------------------
	pop	r15
	pop	r12
	pop	rbp
	pop	rdi
	pop	rsi
	pop	rbx
	ret
sha1_block endp


;===========================================================
; Copy Data to the SHA-Array Data Elements, fast routine
; NOTE: data length MUST be <> 0 !!!
; -----
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - UBIT8 * pDst, Array data base
;			rdx - int     Length, in bytes
;			r8  - UBIT8 * pSrc, source data
; Returns: nothing
; Volatile registers used: rax,rcx,rdx,r8,r9,r10,r11
;===========================================================
sha_copy	proc
;	---------------------------------------------------------
;	Check if more than 7 data bytes given
;	---------------------------------------------------------
	mov	r10,rcx
	cmp	rdx,7
	mov	r9,rdx
	jbe	Sha_SmallCopy
;	----------------------------------------------------------
;	more than 7 data byte, check if destination DWORD aligned
;	----------------------------------------------------------
	and	ecx,3			; DWORD align ?
	jnz	Sha_Copy_StartAlign	; no, special case
;	----------------------------------------------------------
;	Get full Dword count to copy
;	----------------------------------------------------------
Sha_DWordCopy:
	mov	r11,r9			; save byte count
	shr	r9,2			; get DWord count, at least 1 present!
;	----------------------------------------------------------
;	Could unroll loop here !!!
;	----------------------------------------------------------
Sha_DWordCopyLoop:
	mov	eax,DWORD PTR[r8]
	add	r10,4
	add	r8,4			; advance Src. pointer
	sub	r9,1			; reduce count
	mov	DWORD PTR[r10-4],eax
	jnz	short Sha_DWordCopyLoop
;	----------------------------------------------------------
;	Check if remaining bytes to copy (max. 3)
;	----------------------------------------------------------
	and	r11,3			; remaining bytes to copy ??
	jnz	short Sha_Copy_EndBytes	; no, special case
	ret
;===============================================================
; unlikely cases go here...
;===============================================================

;---------------------------------------------------------------
; byte wide end copy, up to 3 byte
; r11: 1..3 remaining byte count
; r10: Destination pointer
; r8 : Source pointer
;---------------------------------------------------------------
Sha_Copy_EndBytes:
	jmp	SHA_EndBytesCopy_JmpTab[r11*8]	; distribute

Sha_EndBytesCopy3:
	mov	ax,WORD PTR[r8]		; get word
	mov	dl,BYTE PTR[r8+2]	; get byte
	mov	WORD PTR[r10],ax	; store
	mov	BYTE PTR[r10+2],dl	; dto.
	ret

Sha_EndBytesCopy2:
	mov	ax,WORD PTR[r8]		; get word
	mov	rdx,r10			; dummy
	mov	WORD PTR[r10],ax	; store
	ret

Sha_EndBytesCopy1:
	mov	al,BYTE PTR[r8]		; get byte
	mov	rdx,r10			; dummy
	mov	BYTE PTR[r10],al	; store
Sha_EndBytesCopy0:
	ret
;---------------------------------------------------------------
; byte wide align copy start, up to 4 byte
; r9:  byte count given
; rcx: 0..3 misalign count
; r10: Destination pointer
; r8 : Source pointer
;---------------------------------------------------------------
Sha_Copy_StartAlign:
	sub	r9,rcx			; reduce data length
	jmp	Sha_StartAlignCopy_JmpTab[rcx*8]	; distribute

Sha_StartAlignCopy3:
	mov	ax,WORD PTR[r8]		; get word
	mov	dl,BYTE PTR[r8+2]	; get byte
	add	r8,3			; advance Src. pointer
	mov	WORD PTR[r10],ax	; store
	mov	BYTE PTR[r10+2],dl	; dto.
	add	r10,3			; advance Dst. pointer
	jmp	Sha_DWordCopy

Sha_StartAlignCopy2:
	mov	ax,WORD PTR[r8]		; get word
	add	r8,2			; advance Src. pointer
	mov	WORD PTR[r10],ax	; store
	add	r10,2			; advance Dst. pointer
	jmp	Sha_DWordCopy

Sha_StartAlignCopy1:
	mov	al,BYTE PTR[r8]		; get byte
	add	r8,1			; advance Src. pointer
	mov	BYTE PTR[r10],al	; store
	add	r10,1			; advance Dst. pointer
Sha_StartAlignCopy0:
	jmp	Sha_DWordCopy

;---------------------------------------------------------------
; Only up to 7 data bytes given, copy special
;
; rdx: 0-7 according to byte count given
; r10: Destination pointer
; r8 : Source pointer
;---------------------------------------------------------------
Sha_SmallCopy:
	jmp	Sha_SmallCopy_JmpTab[rdx*8]	; distribute

Sha_SmallCopy7:
	mov	eax,DWORD PTR[r8]
	mov	cx,WORD PTR[r8+4]
	mov	dl,BYTE PTR[r8+6]
	mov	DWORD PTR[r10],eax
	mov	WORD PTR[r10+4],cx
	mov	BYTE PTR[r10+6],dl
	ret

Sha_SmallCopy6:
	mov	eax,DWORD PTR[r8]
	mov	cx,WORD PTR[r8+4]
	mov	DWORD PTR[r10],eax
	mov	WORD PTR[r10+4],cx
	ret

Sha_SmallCopy5:
	mov	eax,DWORD PTR[r8]
	mov	cl,BYTE PTR[r8+4]
	mov	DWORD PTR[r10],eax
	mov	BYTE PTR[r10+4],cl
	ret

Sha_SmallCopy4:
	mov	eax,DWORD PTR[r8]
	mov	rdx,r10			; dummy
	mov	DWORD PTR[r10],eax
	ret

Sha_SmallCopy3:
	mov	ax,WORD PTR[r8]		;get word
	mov	dl,BYTE PTR[r8+2]
	mov	WORD PTR[r10],ax
	mov	BYTE PTR[r10+2],dl
	ret

Sha_SmallCopy2:
	mov	ax,WORD PTR[r8]		;get word
	mov	rdx,r10			; dummy
	mov	WORD PTR[r10],ax
	ret

Sha_SmallCopy1:
	mov	al,BYTE PTR[r8]		;get byte
	mov	rdx,r10			; dummy
	mov	BYTE PTR[r10],al
Sha_SmallCopy0:
	ret


	align 16
Sha_SmallCopy_JmpTab label QWORD
	DQ	Sha_SmallCopy0			; filler
	DQ	Sha_SmallCopy1
	DQ	Sha_SmallCopy2
	DQ	Sha_SmallCopy3
	DQ	Sha_SmallCopy4
	DQ	Sha_SmallCopy5
	DQ	Sha_SmallCopy6
	DQ	Sha_SmallCopy7

SHA_StartAlignCopy_JmpTab label QWORD
	DQ	Sha_StartAlignCopy0		; filler
	DQ	Sha_StartAlignCopy1
	DQ	Sha_StartAlignCopy2
	DQ	Sha_StartAlignCopy3

SHA_EndBytesCopy_JmpTab label QWORD
	DQ	Sha_EndBytesCopy0		; filler
	DQ	Sha_EndBytesCopy1		; filler
	DQ	Sha_EndBytesCopy2		; filler
	DQ	Sha_EndBytesCopy3		; filler
sha_copy	endp


;=======================================================
; Process SHA-1 update operation
; NOTE: Works different than original C version
; ----- Data byte reversal is now done in the BLOCK subroutine
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - UBIT32 * SHA_Array
;			rdx - UBIT8  * pData
;			r8  - UINT     DataOffset
;			r9  - UINT     Datalength
; Returns: nothing
; Volatile GP registers used: all
; Not all checked!
;=======================================================
SHA1_Update proc frame

	push	rsi
	.PUSHREG rsi
	push	r14
	.PUSHREG r14
	push	r15
	.PUSHREG r15
				; NOTE: Stack IS aligned now
.endprolog
;---------------------------------------------------------------
	test	r9,r9				; data length zero ?
	mov	r15,rcx				; save Array pointer
	mov	rax,r9				; get data length in byte
	jz	short Sha_Update_End
;	--------------------------------------------------------
;	Data given, append data to array till filled/data end
;	--------------------------------------------------------
	shl	rax,3				; calculate bit length	
	add	r8,rdx				; Add the data offset
	add	QWORD PTR SHA_array.SHA_Nl[r15],rax ; add total bitlength L,H

	mov	r14,r8				; save data pointer

	mov	eax,SHA_Array.SHA_Num[r15]	; get stored length (index)
	mov	r14,r8				; save data pointer
	mov	ecx,eax				; save length, clear high DWord
	add	rax,r9				; stored size + given
	mov	rsi,r9				; save data length
	sub	rax,64				; more than one block ???
	ja	Sha_Update_MoreBlocks		; yes, other case
	mov	rdx,r9				; set copy length
;---------------------------------------------------------------
; Only single block, check if block can be filled
;---------------------------------------------------------------
	jz	Sha_Update_OneFullBlock		; block can be filled...
;	--------------------------------------------------------
;	Not enough data to fill block, copy data
;	--------------------------------------------------------
	add	eax,64				; get accumulated count back
	add	rcx,r15				; add SHA-Array base
	mov	SHA_Array.SHA_Num[r15],eax	; store byte count
						; r8:pSrc, rcx:pDst, rdx:Len
	call	sha_copy			; rax,rdx,r9,r10,r11 dead !!

Sha_Update_End:
	pop	r15
	pop	r14
	pop	rsi
	ret
;	-----------------------------------------------------------
;	Enough data to fill ONE block, copy data, process the block
;	-----------------------------------------------------------
Sha_Update_OneFullBlock:
	sub	eax,eax
	add	rcx,r15				; add SHA-Array base
;;	mov	rdx,r9				; set copy length
	mov	SHA_Array.SHA_Num[r15],eax	; clear stored byte count
						; r8:pSrc, rcx:pDst, rdx:Len
	call	sha_copy			; rax,rdx,r9,r10,r11 dead !!

	mov	rcx,r15
	call	sha1_block

	pop	r15
	pop	r14
	pop	rsi
	ret
;------------------------------------------------------------------
; At least one block can be filled up and processed
; rax - (DataLen + StoredLen - 64)
; rcx - Copy start dst. index/length stored
; rsi - total datalen
; r8,r14  - Data pointer
; r15 - Sha-Array pointer
;------------------------------------------------------------------
Sha_Update_MoreBlocks:
;	-----------------------------------------------------------
;	Fill, process the first block (may have stored data...)
;	-----------------------------------------------------------
	mov	rdx,rcx				; length stored
	xor	eax,eax
	neg	rdx				; -length stored
	test	rcx,rcx				; anything stored ??
	mov	SHA_Array.SHA_Num[r15],eax	; clear stored byte count
	jz	short Sha_Update_FullBlockLoop
	add	rdx,64				; amount to copy
	add	rcx,r15				; add SHA-Array base
	sub	rsi,rdx				; remaining data length

	add	r14,rdx				; advance data pointer
						; r8:pSrc, rcx:pDst, rdx:Len
	call	sha_copy			; rax,rdx,r9,r10,r11 dead !!

	mov	rcx,r15
	call	sha1_block
;	-------------------------------------------------------
;	Full blocks processing, check if enough data for block
;	-------------------------------------------------------
Sha_Update_FullBlockLoop:
	sub	rsi,64				; amount needed
	mov	eax,DWORD PTR[0*4][r14]
	jb	Sha_UpdateCheck_SaveLast	; not enough for full block
;	--------------------------------------------------
;	Copy full data block (64 bytes)
;	--------------------------------------------------
	mov	ecx,DWORD PTR[1*4][r14]
	mov	edx,DWORD PTR[2*4][r14]
	mov	r8d,DWORD PTR[3*4][r14]

	mov	DWORD PTR[0*4][r15],eax
	mov	DWORD PTR[1*4][r15],ecx
	mov	DWORD PTR[2*4][r15],edx
	mov	DWORD PTR[3*4][r15],r8d

	mov	eax,DWORD PTR[4*4][r14]
	mov	ecx,DWORD PTR[5*4][r14]
	mov	edx,DWORD PTR[6*4][r14]
	mov	r8d,DWORD PTR[7*4][r14]

	mov	DWORD PTR[4*4][r15],eax
	mov	DWORD PTR[5*4][r15],ecx
	mov	DWORD PTR[6*4][r15],edx
	mov	DWORD PTR[7*4][r15],r8d

	mov	eax,DWORD PTR[8*4][r14]
	mov	ecx,DWORD PTR[9*4][r14]
	mov	edx,DWORD PTR[10*4][r14]
	mov	r8d,DWORD PTR[11*4][r14]

	mov	DWORD PTR[8*4][r15],eax
	mov	DWORD PTR[9*4][r15],ecx
	mov	DWORD PTR[10*4][r15],edx
	mov	DWORD PTR[11*4][r15],r8d

	mov	eax,DWORD PTR[12*4][r14]
	mov	ecx,DWORD PTR[13*4][r14]
	mov	edx,DWORD PTR[14*4][r14]
	mov	r8d,DWORD PTR[15*4][r14]

	mov	DWORD PTR[12*4][r15],eax
	mov	DWORD PTR[13*4][r15],ecx
	mov	DWORD PTR[14*4][r15],edx
	mov	DWORD PTR[15*4][r15],r8d

	add	r14,64				; set next data pointer

	mov	rcx,r15
	call	sha1_block
	jmp	Sha_Update_FullBlockLoop
;	-------------------------------------------------------
;	No more/too few data for a full block
;	-------------------------------------------------------
Sha_UpdateCheck_SaveLast:
	add	rsi,64				; data bytes remaining
	mov	r8,r14				; get data pointer
	jz	short Sha_Update_End1		; no data to process
;	--------------------------------------------------------
;	Copy remaining data to array
;	--------------------------------------------------------
	mov	rcx,r15				; SHA-Array base
	mov	rdx,rsi				; set copy length
	mov	SHA_Array.SHA_Num[r15],esi	; store byte count
						; r8:pSrc, rcx:pDst, rdx:Len
	call	sha_copy			; rax,rdx,r9,r10,r11 dead !!
Sha_Update_End1:
;;;	jmp	short Sha_Update_End
	pop	r15
	pop	r14
	pop	rsi
	ret

SHA1_Update endp


;=======================================================
; Process SHA-1 Final operation
; NOTE: Works different than original C version
; ----- Data byte reversal is now done in the BLOCK subroutine
;
; Calling convention: X64 fastcall
; Input parameters:	rcx - UBIT32 * SHA_Array
;			rdx - UBIT8  * pDigest
;			r8  - UINT     DigestOffset
; Returns: nothing
; Volatile GP registers used: rax,rcx,rdx,r8
; Not all yet checked !!!
;=======================================================
	align 16
SHA_MaskPadTab	Label	DWORD
	DD	0			; Mask, Bytecount = 0
	DD	80h			; PAD value
	DD	0FFh			; Mask, Bytecount = 1
	DD	8000h			; PAD value
	DD	0FFFFh			; Mask, Bytecount = 2
	DD	800000h			; PAD value
	DD	0FFFFFFh		; Mask, Bytecount = 3
	DD	80000000h		; PAD value


	align 16
SHA1_Final proc frame
	push	rbx
	.PUSHREG rbx
	push	r14
	.PUSHREG r14
	push	r15
	.PUSHREG r15
					; NOTE: Stack IS already aligned now
.endprolog
;	--------------------------------------------------------
;	Prepare processing
;	--------------------------------------------------------
	add	r8,rdx			; Add the buffer offset
	mov	r15,rcx			; save Array pointer
;	-------------------------------------------------------------
;	1. Pad data with byte 0x80 and 0..3 bytes 0x00 (use table)
;	-------------------------------------------------------------
	mov	edx,SHA_Array.SHA_Num[r15]	; get byte count stored
	mov	r14,r8				; save digest pointer
	mov	ebx,edx				; save byte count stored
	mov	ecx,edx				; dto.
	shr	ebx,2				; get DWORD index, clear MSW
	and	ecx,3				; get BYTE in WORD index
	mov	eax,SHA_Array.SHA_Data[4*rbx][r15] ; get value DWORD stored
	mov	edx,ebx				; get DWORD count
	and	eax,SHA_MaskPadTab[rcx*8]	; clear unused bits
	add	edx,1				; add normal pad element
	or	eax,SHA_MaskPadTab[rcx*8+4]	; insert padding byte(s)
;	------------------------------------------------------------------
;	2.1 Check if there is enough space for SHA-1 size element (8 byte)
;	------------------------------------------------------------------
	sub	edx,14				; Check DWORD length
	mov	SHA_Array.SHA_Data[4*rbx][r15],eax ; store back padded result
	ja	SHA_Final_NoRoomForLen		; not enough space
	je	SHA_Final_AppendLen		; no zero padding required
;	---------------------------------------------------------
;	2.2 Clear Data up to length position
;	---------------------------------------------------------
	not	edx				; element count-1 to clear
	xor	eax,eax				; zero element
	jmp	SHA_FinalClr_JmpTab[rdx*8]

SHA_FinalClr13:
	mov	SHA_Array.SHA_Data[1*4][r15],eax
SHA_FinalClr12:
	mov	SHA_Array.SHA_Data[2*4][r15],eax
SHA_FinalClr11:
	mov	SHA_Array.SHA_Data[3*4][r15],eax
SHA_FinalClr10:
	mov	SHA_Array.SHA_Data[4*4][r15],eax
SHA_FinalClr9:
	mov	SHA_Array.SHA_Data[5*4][r15],eax
SHA_FinalClr8:
	mov	SHA_Array.SHA_Data[6*4][r15],eax
SHA_FinalClr7:
	mov	SHA_Array.SHA_Data[7*4][r15],eax
SHA_FinalClr6:
	mov	SHA_Array.SHA_Data[8*4][r15],eax
SHA_FinalClr5:
	mov	SHA_Array.SHA_Data[9*4][r15],eax
SHA_FinalClr4:
	mov	SHA_Array.SHA_Data[10*4][r15],eax
SHA_FinalClr3:
	mov	SHA_Array.SHA_Data[11*4][r15],eax
SHA_FinalClr2:
	mov	SHA_Array.SHA_Data[12*4][r15],eax
SHA_FinalClr1:
	mov	SHA_Array.SHA_Data[13*4][r15],eax
;	---------------------------------------------------------
;	3. Append the length (MSW,LSW byteswapped), process block
;	---------------------------------------------------------
SHA_Final_AppendLen:
	mov	eax,SHA_Array.SHA_Nl[r15]
	mov	ebx,SHA_Array.SHA_Nh[r15]
	bswap	eax
	bswap	ebx
	mov	SHA_Array.SHA_Data[14*4][r15],ebx
	mov	SHA_Array.SHA_Data[15*4][r15],eax

	mov	rcx,r15
	call	sha1_block
;	--------------------------------------------------------
;	4. Copy back digest
;	--------------------------------------------------------
	mov	eax,SHA_Array.SHA_h0[r15]
	mov	ebx,SHA_Array.SHA_h1[r15]
	mov	ecx,SHA_Array.SHA_h2[r15]
	bswap	eax
	bswap	ebx
	bswap	ecx
	mov	[0*4][r14],eax
	mov	[1*4][r14],ebx
	mov	[2*4][r14],ecx

	mov	eax,SHA_Array.SHA_h3[r15]
	mov	ebx,SHA_Array.SHA_h4[r15]
	bswap	eax
	bswap	ebx
	mov	[3*4][r14],eax
	mov	[4*4][r14],ebx

;	---------------------------------------------------
;	Clear the SHA-1 array now
;	---------------------------------------------------
	xor	eax,eax
	xor	ebx,ebx			; dummy
	mov	DWORD PTR SHA_Array.SHA_Data[0*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[1*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[2*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[3*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[4*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[5*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[6*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[7*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[8*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[9*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[10*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[11*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[12*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[13*4][r15],eax

	mov	DWORD PTR SHA_Array.SHA_h0[r15],eax
	mov	DWORD PTR SHA_Array.SHA_h1[r15],eax
	mov	DWORD PTR SHA_Array.SHA_h2[r15],eax
	mov	DWORD PTR SHA_Array.SHA_h3[r15],eax
	mov	DWORD PTR SHA_Array.SHA_h4[r15],eax

	mov	DWORD PTR SHA_Array.SHA_Nl[r15],eax
	mov	DWORD PTR SHA_Array.SHA_Nh[r15],eax
	mov	DWORD PTR SHA_Array.SHA_Num[r15],eax

	pop	r15
	pop	r14
	pop	rbx
	ret


	align 16
;=======================================================================
; Unlikely cases go here
;=======================================================================
;	-----------------------------------------------------------------
;	2.2 Length does not fit into array:
;	    - clear the rest of the data array
;	    - process block
;	    - generate zero data up to length position, continue...
;	-----------------------------------------------------------------
SHA_Final_NoRoomForLen:
;	edx: - 14-DataLen (DWORDS)
	xor	eax,eax
	sub	edx,1				; check if pad required at all
	cmovnz	eax,SHA_Array.SHA_Data[15*4][r15] ; don't pad (get old value)
	mov	rcx,r15				; set Array base (next SR)
	mov	SHA_Array.SHA_Data[15*4][r15],eax ; padi/copy last element

	call	sha1_block
;	---------------------------------------------------------
;	zero the data block up to length position
;	---------------------------------------------------------
	xor	rax,rax
	xor	rbx,rbx				; dummy
	mov	DWORD PTR SHA_Array.SHA_Data[0*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[1*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[2*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[3*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[4*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[5*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[6*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[7*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[8*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[9*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[10*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[11*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[12*4][r15],eax
	mov	DWORD PTR SHA_Array.SHA_Data[13*4][r15],eax
	jmp	SHA_Final_AppendLen


	align 16
SHA_FinalClr_JmpTab LABEL QWORD
	DQ	SHA_FinalClr1
	DQ	SHA_FinalClr2
	DQ	SHA_FinalClr3
	DQ	SHA_FinalClr4
	DQ	SHA_FinalClr5
	DQ	SHA_FinalClr6
	DQ	SHA_FinalClr7
	DQ	SHA_FinalClr8
	DQ	SHA_FinalClr9
	DQ	SHA_FinalClr10
	DQ	SHA_FinalClr11
	DQ	SHA_FinalClr12
	DQ	SHA_FinalClr13

SHA1_Final endp

end
