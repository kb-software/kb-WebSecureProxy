        .intel_syntax noprefix

.text
#use: xbprecomp01 is-random-cas-02-64.pre is-random-cas-02-64-gcc.s "xxSET UNIX$GCC=1;"
#     xx = double-percent
#        is-random-cas-02-64.asm
#        Copyright (C) HOB Germany 2016
#        09.06.16 KB
#
        .globl m_random_cas_get
        .globl m_random_cas_put
        .globl m_random_rdtsc

        .equ DVOIDSI,8
#       extern "C" void * m_random_cas_get( void ** );
m_random_cas_get:
        mov  rcx,QWORD PTR[ rdi ]           #get argument
        mov  rax,QWORD PTR[ rcx ]           #get first element in chain
        test rax,rax                        #is the cache empty?
        je   pgetc_80                       #  yes, return
pgetc_60:
        mov  rdx,QWORD PTR[ rax ]           #get second element in chain
        lock cmpxchg QWORD PTR[ rcx ],rdx   #exchange operands
        jz   pgetc_80                       #  succeeded
        test rax,rax                        #is the cache empty?
        jne  pgetc_60                       #  no, try again
pgetc_80:
        ret                                 #return to calling program
#       extern "C" void m_random_cas_put( void **, void * );
m_random_cas_put:
        mov  r8,rsi;                        #get second argument
        mov  rax,QWORD PTR[ rdi ];          #get first element in chain
pputc_20:
        mov  QWORD PTR[ r8 ],rax;           #anchor of chain gets next buffer
        lock cmpxchg QWORD PTR[ rdi ],r8;   #exchange operands
        jnz  pputc_20;                      #  did not succeed
        ret                                 #return to calling program
#       extern "C" void m_random_rdtsc( char * );
m_random_rdtsc:
        rdtsc;                              #read time-stamp counter
        mov  DWORD PTR[ rdi + 0 * 4 ],eax;  #store low-order 32 bits
        mov  DWORD PTR[ rdi + 1 * 4 ],edx;  #store high-order 32 bits
        ret;                                #return to calling program
        .end
