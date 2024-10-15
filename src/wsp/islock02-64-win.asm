;        islock02-64.asm
;        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
;        Copyright (C) HOB Germany 2012
;        Copyright (C) HOB Germany 2013
;        derived from ISLOCK01.asm written 27.11.01 KB
;        28.08.12 KB
;        24.09.13 KB
;        11.10.13 KB
;
        public m_hl_lock_inc_1
        public m_hl_lock_dec_1
        public m_hl_lock_dec_b
        public m_hl_lock_set_true_1

.code
;       extern "C" void m_hl_lock_inc_1( int * );
m_hl_lock_inc_1 proc
        lock inc DWORD PTR[ rcx ];
        ret                                 ;return to calling program
m_hl_lock_inc_1 endp
;       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1 proc
        lock dec DWORD PTR[ rcx ];
        ret                                 ;return to calling program
m_hl_lock_dec_1 endp
;       extern "C" BOOL m_hl_lock_dec_b( int * );
;       return TRUE if value less than zero
m_hl_lock_dec_b proc
        xor  rax,rax                        ;clear return code
        lock dec DWORD PTR[ rcx ];
        jns  pdecb_40
        inc  rax
pdecb_40:
        ret                                 ;return to calling program
m_hl_lock_dec_b endp
;       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1 proc
        xor  eax,eax                        ;clear register
        inc  eax                            ;set to one / TRUE
        xchg eax,DWORD PTR[ rcx ]           ;exchange operands
        ret                                 ;return to calling program
m_hl_lock_set_true_1 endp
        end
