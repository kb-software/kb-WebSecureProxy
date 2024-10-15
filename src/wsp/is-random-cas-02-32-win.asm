;use: xbprecomp01 is-random-cas-02-32.pre is-random-cas-02-32-win.asm "xxSET WIN$VC=1;"
;     xx = double-percent
;     cmasm32 is-random-cas-02-32-win
;        is-random-cas-02-32.asm
;        Copyright (C) HOB Germany 2016
;        20.03.16 KB
;
        .586p
        public _m_random_cas_get
        public _m_random_cas_put
        public _m_random_rdtsc

_TEXT   segment dword public use32 'CODE'
_TEXT   ends
_DATA   segment dword public use32 'DATA'
_DATA   ends
_BSS    segment dword public use32 'BSS'
_BSS    ends
_TEXT   segment dword public use32 'CODE'
        assume cs:_TEXT
DVOIDSI equ 4
;       extern "C" void * m_random_cas_get( void ** );
_m_random_cas_get proc near
        push esi
        mov  esi,DWORD PTR[ esp + (2 * DVOIDSI) ]  ;get argument
        mov  eax,DWORD PTR[ esi ]           ;get first element in chain
        test eax,eax                        ;is the cache empty?
        jne  pgetc_40                       ;  no, get buffer from chain
        pop  esi
        ret                                 ;return to calling program
pgetc_40:
        push edx
        mov  eax,DWORD PTR[ esi ]           ;get first element in chain
        test eax,eax                        ;is the cache empty?
        je   pgetc_80                       ;  no, get buffer from chain
pgetc_60:
        mov  edx,DWORD PTR[ eax ]           ;get second element in chain
        lock cmpxchg DWORD PTR[ esi ],edx   ;exchange operands
        jz   pgetc_80                       ;  succeeded
        test eax,eax                        ;is the cache empty?
        jne  pgetc_60                       ;  no, try again
pgetc_80:
        pop  edx
        pop  esi
        ret                                 ;return to calling program
_m_random_cas_get endp
;       extern "C" void m_random_cas_put( void **, void * );
_m_random_cas_put proc near
        push esi
        push edx
        mov  esi,DWORD PTR[ esp + (3 * DVOIDSI) ]  ;get first argument
        mov  edx,DWORD PTR[ esp + (4 * DVOIDSI) ]  ;get second argument
        mov  eax,DWORD PTR[ esi ]           ;get first element in chain
pputc_20:
        mov  DWORD PTR[ edx ],eax           ;anchor of chain gets next buffer
        lock cmpxchg DWORD PTR[ esi ],edx   ;exchange operands
        jnz  pputc_20                       ;  did not succeed
        pop  edx
        pop  esi
        ret                                 ;return to calling program
_m_random_cas_put endp
;       extern "C" void m_random_rdtsc( char * );
_m_random_rdtsc proc near
        mov  ecx,DWORD PTR[ esp + 4 ];      ;get argument
        rdtsc;                              ;read time-stamp counter
        mov  DWORD PTR[ ecx + 0 * 4 ],eax;  ;store low-order 32 bits
        mov  DWORD PTR[ ecx + 1 * 4 ],edx;  ;store high-order 32 bits
        ret;                                ;return to calling program
_m_random_rdtsc endp
_TEXT   ends
        end
