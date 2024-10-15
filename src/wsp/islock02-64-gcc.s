        .intel_syntax noprefix

.text
#        islock02-64.asm
#        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
#        Copyright (C) HOB Germany 2012
#        Copyright (C) HOB Germany 2013
#        Copyright (C) HOB Germany 2015
#        derived from ISLOCK01.asm written 27.11.01 KB
#        28.08.12 KB
#        24.09.13 KB
#        11.10.13 KB
#        30.09.15 KB
#
        .globl m_hl_lock_inc_1
        .globl m_hl_lock_dec_1
        .globl m_hl_lock_dec_b
        .globl m_hl_lock_dec_b
        .globl m_hl_lock_set_true_1
        .globl m_hl_get_chain
        .globl m_hl_put_chain
        .globl m_hl_spin_enter
        .globl m_hl_lock_set_zero_1

#       extern "C" void m_hl_lock_inc_1( int * )#
m_hl_lock_inc_1:
        lock inc DWORD PTR[ rdi ];
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
        lock dec DWORD PTR[ rdi ];
        ret                                 #return to calling program
#       extern "C" BOOL m_hl_lock_dec_b( int * )#
#       return TRUE if value less than zero
m_hl_lock_dec_b:
        xor  rax,rax                        #clear return code
        lock dec DWORD PTR[ rdi ];
        jns  pdecb_40
        inc  rax
pdecb_40:
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
        xor  eax,eax                        #clear register
        inc  eax                            #set to one / TRUE
        lock xchg eax,DWORD PTR[ rdi ]       #exchange operands
        ret                                 #return to calling program
#       extern "C" void * m_hl_get_chain( void **, int * );
m_hl_get_chain:
        mov  rax,QWORD PTR[ rdi ];          #get first element in chain
        cmp  rax,0                          #is the cache empty?
        jne  pgetc_40                       #  no, get buffer from chain
        ret                                 #return to calling program
pgetc_40:
        push rdx                            #save register
        mov  edx,255
pgetc_60:
        xor  eax,eax                        #clear register
        lock cmpxchg DWORD PTR[ rsi ],edx  #exchange operands
        jnz  pgetc_60
        mov  rax,QWORD PTR[ rdi ];          #get first element in chain
        cmp  rax,0                          #is the cache empty?
        je   pgetc_80                       #  yes
pgetc_68:
        mov  rdx,QWORD PTR[ rax ];          #get second element in chain
        lock cmpxchg QWORD PTR[ rdi ],rdx   #exchange operands
        jz   pgetc_80                       #  succeeded
        cmp  rax,0                          #is the cache empty?
        jne  pgetc_68                       #  no, try again
pgetc_80:
        xor  edx,edx                        #clear register
        lock xchg edx,DWORD PTR[ rsi ]  #exchange operands
        pop  rdx                            #restore register
        ret                                 #return to calling program
#       extern "C" void m_hl_put_chain( void **, void * );
m_hl_put_chain:
        mov  rax,QWORD PTR[ rdi ];          #get first element in chain
pputc_20:
        mov  QWORD PTR[ rsi ],rax           #anchor of chain gets next buffer
        lock cmpxchg QWORD PTR[ rdi ],rsi   #exchange operands
        jnz  pputc_20                       #  did not succeed
        ret                                 #return to calling program
#       extern "C" void m_hl_spin_enter( int * );
m_hl_spin_enter:
        push rdx
        mov  edx,255
p_spin_enter_20:
        xor  eax,eax                        #clear register
p_spin_enter_24:
        lock cmpxchg DWORD PTR[ rdi ],edx  #exchange operands
        jz   p_spin_enter_60
p_spin_enter_40:
        mov  eax,DWORD PTR[ rdi ]
        cmp  eax,0
        jne  p_spin_enter_40
        jmp  p_spin_enter_24
p_spin_enter_60:
        pop  rdx
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_zero_1( int * );
m_hl_lock_set_zero_1:
        xor  eax,eax                        #clear register
        lock xchg eax,DWORD PTR[ rdi ]  #exchange operands
        ret                                 #return to calling program
#       14.04.16 KB - changed because of CLANG
#       .end
