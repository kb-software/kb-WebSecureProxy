.text
		.align 8
#        islock02-64-s390-gcc.s
#        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
#        Copyright (C) HOB Germany 2012
#        Copyright (C) HOB Germany 2013
#        Copyright (C) HOB Germany 2015
#        derived from ISLOCK01.asm written 27.11.01 KB
#        28.08.12 KB
#        24.09.13 KB
#        11.10.13 KB
#        30.09.15 KB
#		 14.09.16 Tischhöfer

        .globl m_hl_lock_inc_1
        .globl m_hl_lock_dec_1
#        .globl m_hl_lock_inc_2
#        .globl m_hl_lock_dec_b
        .globl m_hl_lock_set_true_1
        .globl m_hl_get_chain
        .globl m_hl_put_chain

# S390 gereral registers
		.equ R00,0
		.equ R01,1
		.equ R02,2
		.equ R03,3
		.equ R04,4
		.equ R05,5
		.equ R06,6		
		.equ R07,7
		.equ R08,8
		.equ R09,9
		.equ R10,10
		.equ R11,11
		.equ R12,12
		.equ R13,13
		.equ R14,14
		.equ R15,15
		
#       extern "C" void m_hl_lock_inc_1( int * ) #R02 is 1st function parameter
		.type main,@function
m_hl_lock_inc_1:
		L	R01,0(0,R02)					#load *(int*) to R01 (32bit)
pinc1_00:
		LA	R00,1(0,R01)					#R00 is R01+1
        CS	R01,R00,0(R02)					#if R01 is still *(int*) store R00 there
		BC	7,pinc1_00						#else increment once more
		#BNE	pinc1_00 					#does this do the same?
        BR	R14                             #return to calling program
#       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
		L	R01,0(0,R02)					#load *(int*) to R01 (32bit)
pdec1_00:
		LR	R00,R01
		AHI	R00,-1							#decrement R00 (32bit)
        CS	R01,R00,0(R02)					#if R01 is still *(int*) store R00 there
		BC	7,pdec1_00						#else increment once more
        BR	R14                             #return to calling program
#       extern "C" BOOL m_hl_lock_dec_b( int * )#
#       return TRUE if value less than zero
#m_hl_lock_dec_b:
#        xor  rax,rax                        #clear return code
#        lock dec DWORD PTR[ rdi ];
#        jns  pdecb_40
#        inc  rax
#pdecb_40:
#        ret                                 #return to calling program
#       extern "C" void m_hl_lock_inc_2( int * )#
#m_hl_lock_inc_2:
#        lock inc QWORD PTR[ rdi ];
#        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
		L	R01,0(0,R02)
		XR	R00,R00							#clear register
		AHI	R00,1							#set to one / TRUE (32bit)
psettrue_00:
		CS	R01,R00,0(R02)					#if R01=*(int*), *(int*) = TRUE
		BC	7,psettrue_00					#else, try again
        BR	R14                             #return to calling program
        .equ DVOIDSI,8
#       extern "C" void * m_hl_get_chain( void **, int * );
#		R02 = void**, R03 = int *
m_hl_get_chain:
		LG	R00,0(0,R02)					#get first element in chain (64bit)
		LTGR R00,R00						#is the cache empty?
		BC	7,pgetc_40						#  no, get buffer from chain
		BR	R14								#return to calling program
pgetc_40:
		XR	R01,R01
		AHI R01,255
pgetc_60:
		XR	R00,R00							#clear register
		CS	R00,R01,0(R03)					#exchange operands (32bit)
		BC	7,pgetc_60						#jump, if not equal
		LG	R00,0(0,R02)					#get first element in chain (64bit)
		LTGR R00,R00						#is the cache empty?
		BC	8,pgetc_80						#jump, if equal(zero)
pgetc_68:
		LG	R01,0(0,R00)					#get second element in chain
		CSG	R00,R01,0(R02)					#exchange operands (64bit)
		BC	8,pgetc_80						#jump, if secceeded
		LTGR R00,R00						#is the cache empty?
		BC	7,pgetc_68						#no, try again
pgetc_80:
		L	R00,0(0,R03)					#load 32bit from address R03
		XR	R01,R01							#clear register
pgetc_90:
		CS	R00,R01,0(R03)					#if success, store R01 to R03 (32bit)
		BC	7,pgetc_90						#else try again with new R00
        BR	R14                             #return to calling program
#       extern "C" void m_hl_put_chain( void **, void * );
#		R02=void**, R03=void*
m_hl_put_chain:
		LG	R00,0(0,R02)					#get first element in chain
pputc_20:
		STG	R00,0(0,R03)					#anchor of chain gets next buffer
		CSG	R00,R03,0(R02)					#exchange operands
		BC	7,pputc_20						#jump, if not succeed
        BR R14                              #return to calling program
#        .end
