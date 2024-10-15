        .386p
;        islock02-32.asm
;        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
;        Copyright (C) HOB Germany 2012
;        derived from ISLOCK01.asm written 27.11.01 KB
;        27.08.12 KB
;
        public _m_hl_lock_inc_1
        public _m_hl_lock_dec_1
        public _m_hl_lock_dec_b
        public _m_hl_lock_set_true_1

_TEXT   segment dword public use32 'CODE'
_TEXT   ends
_DATA   segment dword public use32 'DATA'
_DATA   ends
_BSS    segment dword public use32 'BSS'
_BSS    ends
ifdef OLD_1308
DGROUP  group _DATA,_BSS
        assume cs:_TEXT,ds:DGROUP
endif
_TEXT   segment dword public use32 'CODE'
        assume cs:_TEXT
;       extern "C" void m_hl_lock_inc_1( int * );
_m_hl_lock_inc_1 proc near
        mov  eax,DWORD PTR[ esp + 4 ]       ;get argument
        lock inc DWORD PTR[ eax ];
        ret                                 ;return to calling program
_m_hl_lock_inc_1 endp
;       extern "C" void m_hl_lock_dec_1( int * );
_m_hl_lock_dec_1 proc near
        mov  eax,DWORD PTR[ esp + 4 ]       ;get argument
        lock dec DWORD PTR[ eax ]
        ret                                 ;return to calling program
_m_hl_lock_dec_1 endp
;       extern "C" BOOL m_hl_lock_dec_b( int * );
;       return TRUE if value less than zero
_m_hl_lock_dec_b proc near
        push edx
        mov  edx,DWORD PTR[ esp + 8 ]       ;get argument
        xor  eax,eax                        ;clear return code
        lock dec DWORD PTR[ edx ];
        jns  pdecb_40
        inc  eax
pdecb_40:
        pop  edx
        ret                                 ;return to calling program
_m_hl_lock_dec_b endp
;       extern "C" void m_hl_lock_set_true_1( int * );
_m_hl_lock_set_true_1 proc near
        push edx
        mov  eax,DWORD PTR[ esp + 8 ]       ;get argument
        xor  edx,edx                        ;clear register
        inc  edx                            ;set to one / TRUE
        xchg edx,DWORD PTR[ eax ]           ;exchange operands
        pop  edx
        ret                                 ;return to calling program
_m_hl_lock_set_true_1 endp
_TEXT   ends
        end
