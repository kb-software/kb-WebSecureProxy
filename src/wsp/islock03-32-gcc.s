        .intel_syntax noprefix

.text
#use: xbprecomp01 islock03-32.pre islock03-32-gcc.s "xxSET UNIX$GCC=1;"
#     xx = double-percent
#        islock03-32.asm
#        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
#        Copyright (C) HOB Germany 2012
#        Copyright (C) HOB Germany 2013
#        Copyright (C) HOB Germany 2016
#        derived from ISLOCK01.asm written 27.11.01 KB
#        27.08.12 KB
#

        .globl m_hl_lock_inc_1
        .globl m_hl_lock_dec_1
        .globl m_hl_lock_dec_b
        .globl m_hl_lock_set_true_1
        .globl m_hl_lock_set_null_1
        .globl m_hl_lock_set_var_1
        .globl m_hl_cas_var_1
        .globl m_hl_cas_var_2
        .globl m_hl_get_chain
        .globl m_hl_put_chain
        .globl m_hl_check_chain

#       extern "C" void m_hl_lock_inc_1( int * )#
m_hl_lock_inc_1:
        mov  eax,DWORD PTR[ esp + 4 ];      #get argument
        lock inc DWORD PTR[ eax ];          #increment int
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
        mov  eax,DWORD PTR[ esp + 4 ]       #get argument
        lock dec DWORD PTR[ eax ]
        ret                                 #return to calling program
#       extern "C" BOOL m_hl_lock_dec_b( int * )#
#       return TRUE if value less than zero
m_hl_lock_dec_b:
        mov  edx,DWORD PTR[ esp + 4 ]       #get argument
        xor  eax,eax                        #clear return code
        lock dec DWORD PTR[ edx ]           #decrement int
        jns  pdecb_40
        inc  eax
pdecb_40:
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
        mov  eax,DWORD PTR[ esp + 4 ]       #get argument
        xor  edx,edx                        #clear register
        inc  edx                            #set to one / TRUE
        xchg  edx,DWORD PTR[ eax ]          #exchange operands
        ret                                 #return to calling program
#       extern "C" void m_hl_lock_set_null_1( void * );
m_hl_lock_set_null_1:
        mov  eax,DWORD PTR[ esp + 4 ]       #get argument
        xor  edx,edx                        #clear register
        xchg edx,DWORD PTR[ eax ]      #exchange operands
        ret                                 #return to calling program
        .equ DVOIDSI,4
#       extern "C" void m_hl_lock_set_var_1( void **, void * );
m_hl_lock_set_var_1:
        mov  eax,DWORD PTR[ esp + (1 * DVOIDSI) ]  #get first argument
        mov  edx,DWORD PTR[ esp + (2 * DVOIDSI) ]  #get second argument
        xchg edx,DWORD PTR[ eax ]           #exchange operands
        ret                                 #return to calling program
#       extern "C" BOOL m_hl_cas_var_1( void **, void **, void * );
m_hl_cas_var_1:
        push ebx;                           #save register
        mov  edx,DWORD PTR[ esp + (2 * DVOIDSI) ];  #get first argument
        mov  ecx,DWORD PTR[ esp + (3 * DVOIDSI) ];  #get second argument
        mov  ebx,DWORD PTR[ esp + (4 * DVOIDSI) ];  #get third argument
        mov  eax,DWORD PTR[ ecx ];          #get old content
        lock cmpxchg DWORD PTR[ edx ],ebx;  #exchange operands
        jz   pcasv1_20;                     #  did succeed
                                            #did not succeed
        mov  DWORD PTR[ ecx ],eax;          #set old content - return
        xor  eax,eax;                       #clear register - return value FALSE
        pop  ebx;                           #restore register
        ret;                                #return to calling program
pcasv1_20:                                  #did succeed
        xor  eax,eax;                       #clear register - return value
        inc  eax;                           #set register to one - return value TRUE
        pop  ebx;                           #restore register
        ret;                                #return to calling program
#       extern "C" BOOL m_hl_cas_var_2( void **, void **, void ** );
m_hl_cas_var_2:
        push ebx;                           #save register
        push esi;                           #save register
        push edi;                           #save register
        mov  esi,DWORD PTR[ esp + (4 * DVOIDSI) ]  #get address first parameter
        mov  edi,DWORD PTR[ esp + (5 * DVOIDSI) ]  #get address second parameter
        mov  eax,DWORD PTR[ edi ];          #get old content part one
        mov  edx,DWORD PTR[ edi + DVOIDSI ] #get old content part two
        mov  ecx,DWORD PTR[ esp + (6 * DVOIDSI) ]  #get address third parameter
        mov  ebx,DWORD PTR[ ecx ];          #get new content part one
        mov  ecx,DWORD PTR[ ecx + DVOIDSI ] #get new content part two
        lock cmpxchg8b QWORD PTR[ esi ]     #exchange operands
        jz   pcasv2_20;                     #  did succeed
                                            #did not succeed
        mov  DWORD PTR[ edi ],eax;          #set old content part one - return
        mov  DWORD PTR[ edi + DVOIDSI ],edx #set old content part two - return
        xor  eax,eax;                       #clear register - return value FALSE
        pop  edi;                           #restore register
        pop  esi;                           #restore register
        pop  ebx;                           #restore register
        ret;                                #return to calling program
pcasv2_20:                                  #did succeed
        xor  eax,eax;                       #clear register - return value
        inc  eax;                           #set register to one - return value TRUE
        pop  edi;                           #restore register
        pop  esi;                           #restore register
        pop  ebx;                           #restore register
        ret;                                #return to calling program
#       extern "C" void * m_hl_get_chain( void ** );
m_hl_get_chain:
        push esi
        mov  esi,DWORD PTR[ esp + (2 * DVOIDSI) ]  #get argument
        mov  eax,DWORD PTR[ esi ]           #get first element in chain
        test eax,eax                        #is the cache empty?
        jne  pgetc_40                       #  no, get buffer from chain
        pop  esi
        ret                                 #return to calling program
pgetc_40:
        push edx
        push ecx
#--- 21.07.16 KB - only ebx needs to get saved
        push ebx
        mov  eax,DWORD PTR[ esi ]           #get first element in chain
        test eax,eax                        #is the cache empty?
        jz   pgetc_80                       #  yes, no buffer in chain
        mov  edx,DWORD PTR[ esi + DVOIDSI ] #get count
pgetc_60:
        mov  ebx,DWORD PTR[ eax ]           #get second element in chain
        mov  ecx,edx                        #get count
        inc  ecx                            #increase count
        lock cmpxchg8b QWORD PTR[ esi ]     #exchange operands
        jz   pgetc_80                       #  succeeded
        test eax,eax                        #is the cache empty?
        jne  pgetc_60                       #  no, try again
pgetc_80:
        pop  ebx
#--- 21.07.16 KB - only ebx needs to get saved
        pop  ecx
        pop  edx
        pop  esi
        ret                                 #return to calling program
#       extern "C" void m_hl_put_chain( void **, void * );
m_hl_put_chain:
        push esi
        push edx
#--- 21.07.16 KB - only ebx needs to get saved
        mov  esi,DWORD PTR[ esp + (3 * DVOIDSI) ]  #get first argument
        mov  edx,DWORD PTR[ esp + (4 * DVOIDSI) ]  #get second argument
        mov  eax,DWORD PTR[ esi ]           #get first element in chain
pputc_20:
        mov  DWORD PTR[ edx ],eax           #anchor of chain gets next buffer
        lock cmpxchg DWORD PTR[ esi ],edx   #exchange operands
        jnz  pputc_20                       #  did not succeed
#--- 21.07.16 KB - only ebx needs to get saved
        pop  edx
        pop  esi
        ret                                 #return to calling program
#       extern "C" void * m_hl_check_chain( void ** );
m_hl_check_chain:
        push esi
        mov  esi,DWORD PTR[ esp + (2 * DVOIDSI) ]  #get argument
        mov  eax,DWORD PTR[ esi ]           #get first element in chain
        pop  esi
        ret                                 #return to calling program
        .end
