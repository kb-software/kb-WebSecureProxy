        .intel_syntax noprefix

.text
#        islock02-32.asm
#        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
#        Copyright (C) HOB Germany 2012
#        Copyright (C) HOB Germany 2013
#        derived from ISLOCK01.asm written 27.11.01 KB
#        27.08.12 KB
#
        .globl m_hl_lock_inc_1
        .globl m_hl_lock_dec_1
        .globl m_hl_lock_dec_b
        .globl m_hl_lock_set_true_1

#       extern "C" void m_hl_lock_inc_1( int * )#
m_hl_lock_inc_1:
        mov  eax,DWORD PTR[ esp + 4 ]       #get argument
        lock inc DWORD PTR[ eax ]#
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
        mov  eax,DWORD PTR[ esp + 4 ]       #get argument
        lock dec DWORD PTR[ eax ]
        ret                                 #return to calling program
#       extern "C" BOOL m_hl_lock_dec_b( int * )#
#       return TRUE if value less than zero
m_hl_lock_dec_b:
        push edx
        mov  edx,DWORD PTR[ esp + 8 ]       #get argument
        xor  eax,eax                        #clear return code
        lock dec DWORD PTR[ edx ]#
        jns  pdecb_40
        inc  eax
pdecb_40:
        pop  edx
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
        push edx
        mov  eax,DWORD PTR[ esp + 8 ]       #get argument
        xor  edx,edx                        #clear register
        inc  edx                            #set to one / TRUE
        xchg edx,DWORD PTR[ eax ]           #exchange operands
        pop  edx
        ret                                 #return to calling program
#       14.04.16 KB - changed because of CLANG
#       .end
