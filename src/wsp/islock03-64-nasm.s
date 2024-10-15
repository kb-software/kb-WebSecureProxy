section .text
;use: xbprecomp01 islock03-64.pre islock03-64-nasm.s "xxSET UNIX$NASM=1;"
;     xx = double-percent
;        islock03-64.asm
;        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
;        Copyright (C) HOB Germany 2012
;        Copyright (C) HOB Germany 2013
;        Copyright (C) HOB Germany 2015
;        derived from ISLOCK01.asm written 27.11.01 KB
;        28.08.12 KB
;        24.09.13 KB
;        11.10.13 KB
;        30.09.15 KB
;

; This macro will generate the right symbols for the external functions, depending on output format
%ifidn __OUTPUT_FORMAT__,macho64
%macro global_function 1
global %1
global _%1
%endmacro
%else
%macro global_function 1
global %1:function
global _%1:function
%endmacro
%endif

; This define removes the PTR parts of the code, that NASM can't use
%define PTR

; NASM doesn't use OWORD. As this is only used with cmpxchg16b, width specifiers are unnecessary anyway.
%define OWORD
        global_function m_hl_lock_inc_1
        global_function m_hl_lock_dec_1
        global_function m_hl_lock_inc_2
        global_function m_hl_lock_dec_b
        global_function m_hl_lock_set_true_1
        global_function m_hl_lock_set_null_1
        global_function m_hl_lock_set_var_1
        global_function m_hl_cas_var_1
        global_function m_hl_cas_var_2
        global_function m_hl_get_chain
        global_function m_hl_put_chain
        global_function m_hl_check_chain
        global_function m_hl_spin_enter
        global_function m_hl_lock_set_zero_1
        global_function m_hl_get_fifo
        global_function m_hl_put_fifo
        global_function m_hl_check_fifo

;       extern "C" void m_hl_lock_inc_1( int * );
m_hl_lock_inc_1:
_m_hl_lock_inc_1:
        lock inc DWORD PTR[ rdi ];
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
_m_hl_lock_dec_1:
        lock dec DWORD PTR[ rdi ];
        ret                                 ;return to calling program
;       extern "C" BOOL m_hl_lock_dec_b( int * );
;       return TRUE if value less than zero
m_hl_lock_dec_b:
_m_hl_lock_dec_b:
        xor  rax,rax                        ;clear return code
        lock dec DWORD PTR[ rdi ];
        jns  pdecb_40
        inc  rax
pdecb_40:
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_inc_2( long long int * );
m_hl_lock_inc_2:
_m_hl_lock_inc_2:
        lock inc QWORD PTR[ rdi ];
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
_m_hl_lock_set_true_1:
        xor  eax,eax                        ;clear register
        inc  eax                            ;set to one / TRUE
        xchg eax,DWORD PTR[ rdi ]            ;exchange operands
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_set_null_1( void * );
m_hl_lock_set_null_1:
_m_hl_lock_set_null_1:
        xor  rax,rax                        ;clear register
        xchg rax,QWORD PTR[ rdi ]            ;exchange operands
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_set_var_1( void **, void * );
m_hl_lock_set_var_1:
_m_hl_lock_set_var_1:
        xchg rsi,QWORD PTR[ rdi ]            ;exchange operands
        ret                                 ;return to calling program
;       extern "C" BOOL m_hl_cas_var_1( void **, void **, void * );
m_hl_cas_var_1:
_m_hl_cas_var_1:
        mov  rax,QWORD PTR[ rsi ];          ;get old content
        lock cmpxchg QWORD PTR[ rdi ],rdx;  ;exchange operands
        jz   pcasv1_20;                     ;  did succeed
                                            ;did not succeed
        mov  QWORD PTR[ rsi ],rax;          ;set old content - return
        xor  rax,rax;                       ;clear register - return value FALSE
        ret;                                ;return to calling program
pcasv1_20:                                  ;did succeed
        xor  rax,rax;                       ;clear register - return value
        inc  rax;                           ;set register to one - return value TRUE
        ret;                                ;return to calling program
;       extern "C" BOOL m_hl_cas_var_2( void **, void **, void ** );
m_hl_cas_var_2:
_m_hl_cas_var_2:
        mov  r9,rbx                         ;save register
        mov  r10,rdx;                       ;get address third parameter
        mov  rax,QWORD PTR[ rsi ];          ;get old content part one
        mov  rdx,QWORD PTR[ rsi + DVOIDSI ] ;get old content part two
        mov  rbx,QWORD PTR[ r10 ];          ;get new content part one
        mov  rcx,QWORD PTR[ r10 + DVOIDSI ] ;get new content part two
        lock cmpxchg16b OWORD PTR[ rdi ];   ;exchange operands
        jz   pcasv2_20;                     ;  did succeed
                                            ;did not succeed
        mov  QWORD PTR[ rsi ],rax;          ;set old content part one - return
        mov  QWORD PTR[ rsi + DVOIDSI ],rdx ;set old content part two - return
        xor  rax,rax;                       ;clear register - return value FALSE
        mov  rbx,r9;                        ;restore register
        ret;                                ;return to calling program
pcasv2_20:                                  ;did succeed
        xor  rax,rax;                       ;clear register - return value
        inc  rax;                           ;set register to one - return value TRUE
        mov  rbx,r9;                        ;restore register
        ret;                                ;return to calling program
DVOIDSI equ (8)
;       extern "C" void * m_hl_get_chain( void ** );
m_hl_get_chain:
_m_hl_get_chain:
        mov  rax,QWORD PTR[ rdi ];    ;get first element in chain
        test rax,rax                        ;is the cache empty?
        jne  pgetc_40                       ;  no, get buffer from chain
        ret                                 ;return to calling program
pgetc_40:
        mov  r8,rbx                         ;save register
pgetc_60:
        lock inc QWORD PTR[ rdi + (2*DVOIDSI)];
        mov  rdx,QWORD PTR[ rdi + DVOIDSI ] ;get count
        mov  rax,QWORD PTR[ rdi + DVOIDSI ] ;get first element in chain
        test rax,rax                        ;is the cache empty?
        je   pgetc_80                       ;  no, get buffer from chain
        mov  rbx,QWORD PTR[ rax ];          ;get second element in chain
        mov  rcx,rdx                        ;get count
        inc  rcx                            ;increase count
        lock cmpxchg16b OWORD PTR[ rdi ]    ;exchange operands
        jz   pgetc_80                       ;  succeeded
        test rax,rax                        ;is the cache empty?
        jne  pgetc_60                       ;  no, try again
pgetc_80:
        lock dec QWORD PTR[ rdi + (2*DVOIDSI)];
        mov  rbx,r8                         ;restore register
        ret                                 ;return to calling program
;       extern "C" void m_hl_put_chain( void **, void * );
m_hl_put_chain:
_m_hl_put_chain:
        mov  rax,QWORD PTR[ rdi ];          ;get first element in chain
pputc_20:
        lock inc QWORD PTR[ rdi + (3*DVOIDSI)];
        mov  QWORD PTR[ rsi ],rax           ;anchor of chain gets next buffer
        lock cmpxchg QWORD PTR[ rdi ],rsi   ;exchange operands
        jnz  pputc_20                       ;  did not succeed
        lock dec QWORD PTR[ rdi + (3*DVOIDSI)];
        ret                                 ;return to calling program
;       extern "C" void * m_hl_check_chain( void ** );
m_hl_check_chain:
_m_hl_check_chain:
        mov  rax,QWORD PTR[ rdi ];          ;get first element in chain
        ret                                 ;return to calling program
;       extern "C" void * m_hl_get_fifo( void ** );
;       extern "C" void m_hl_put_fifo( void **, void * );
;       extern "C" void * m_hl_check_fifo( void ** );
;       extern "C" void m_hl_spin_enter( int * );
m_hl_spin_enter:
_m_hl_spin_enter:
        mov  edx,255
p_spin_enter_20:
        xor  eax,eax                        ;clear register
p_spin_enter_24:
        lock cmpxchg DWORD PTR[ rdi ],edx  ;exchange operands
        jz   p_spin_enter_60
p_spin_enter_40:
        mov  eax,DWORD PTR[ rdi ]
        cmp  eax,0
        jne  p_spin_enter_40
        jmp  p_spin_enter_24
p_spin_enter_60:
        ret                                 ;return to calling program
;       extern "C" void m_hl_lock_set_zero_1( int * );
m_hl_lock_set_zero_1:
_m_hl_lock_set_zero_1:
        xor  eax,eax                        ;clear register
        xchg eax,DWORD PTR[ rdi ]       ;exchange operands
        ret                                 ;return to calling program
;  KB 21.01.16

HEAD_STA equ (0*DVOIDSI)
HEAD_CNT equ (1*DVOIDSI)
TAIL_STA equ (2*DVOIDSI)
TAIL_CNT equ (3*DVOIDSI)
VALUE_XX equ (2*DVOIDSI)
;       extern "C" void * m_hl_get_fifo( void ** );
; parameters: pointer to queue
m_hl_get_fifo:
        mov  r8,rbx                          ; save register
get_loop:
;     rdi pointer to head
        mov  rdx,QWORD PTR[ rdi + HEAD_CNT ] ; get head counter
        mov  rax,QWORD PTR[ rdi + HEAD_STA ] ; get pointer to head element
        mov  rsi,QWORD PTR[ rdi + TAIL_CNT ] ; get tail counter
        mov  rcx,QWORD PTR[ rdi + TAIL_STA ] ; get pointer to tail element
        mov  rbx,QWORD PTR[ rax ]            ; get head->next
        cmp  rdx,QWORD PTR[ rdi + HEAD_CNT ] ; head counter still the same?
        jne  get_loop
        cmp  rcx,rax                         ; do head and tail point to the same node?
        je   p_same_node                     ;   yes
                                             ; always copy content from second element to first element
        mov  r11,QWORD PTR[ rbx + VALUE_XX ] ; get content
        mov  rcx,rdx                         ; get head counter
        inc  rcx
        lock cmpxchg16b OWORD PTR[ rdi +  HEAD_STA ]
        jne  get_loop                        ; if it did not succeed, another thread may have taken care of it
; return value rax already in right place
        mov  QWORD PTR[ rax +  VALUE_XX ],r11 ; set content
        mov  rbx,r8                          ; restore register
        ret                                  ; return former head element
p_same_node:                                 ; head and tail point to the same node
        test rbx,rbx                         ; is the next element NULL
;#       je   p_empty
        jne  p_get_fifo_correct_tail
        mov  rbx,r8                          ; restore register
        xor  rax,rax                         ; return NULL, queue empty
        ret                                  ; return NULL
; correct tail
p_get_fifo_correct_tail:
        mov  rax,rcx                         ; get pointer to tail element
;##     mov  rdx,QWORD PTR[ rdi + TAIL_CNT ]                 ; get tail count
;##        mov  rdx,QWORD PTR[ rdi +  TAIL_CNT ]                 ; get tail count
        mov  rdx,rsi                         ; get tail count
;##     mov  rbx,QWORD PTR[ rax ]                          ; get head->next
        mov  rcx,rdx                         ; get tail counter
        inc  rcx
        lock cmpxchg16b OWORD PTR[ rdi + TAIL_STA ]
        jmp  get_loop;
;
;       extern "C" void m_hl_put_fifo( void **, void * );
; parameters: pointer to the queue
;             memory for the new node
m_hl_put_fifo:
        mov  r10,rbx                         ; save register
        mov  QWORD PTR[ rsi ], 0             ; next and counter
put_loop:
        mov  r9,QWORD PTR[ rdi + TAIL_CNT ]  ; get tail counter
        mov  r8,QWORD PTR[ rdi + TAIL_STA ]  ; get pointer to tail
        mov  rdx,QWORD PTR[ r8 + DVOIDSI ]   ; get next counter
        mov  rax,QWORD PTR[ r8 ];            ; next element
        cmp  r9,QWORD PTR[ rdi + TAIL_CNT ]  ; tail counter still the same?
        jne  put_loop
        test rax,rax                         ; is the last element?
        jne  put_correct_tail                ; no, correct tail pointer
        mov  rbx,rsi                         ; get new element
        mov  rcx,rdx                         ; get head counter
        inc  rcx
        lock cmpxchg16b OWORD PTR[ r8 ]
        jne  put_loop                        ; didn't work, restart
;#       jmp  put_end;                                   ; done here
        ; Inserted new node. Now update tail pointer
        mov  rax,r8                          ; get pointer to tail
        mov  rdx,r9                          ; get tail counter
;#        mov  rbx,QWORD PTR[ rsi + DVOIDSI ]               ; get new element
        mov  rcx,rdx                         ; get head counter
        inc  rcx
        lock cmpxchg16b OWORD PTR[ rdi + TAIL_STA ]
        mov  rbx,r10                         ; restore register
        ret
put_correct_tail:
        mov  rbx,rax                                    ; next element
        mov  rax,r8                                     ; get pointer to tail
        mov  rdx,r9                                     ; get tail counter
        mov  rcx,rdx                                    ; get head counter
        inc  rcx
        lock cmpxchg16b OWORD PTR[ rdi + TAIL_STA ]
        jmp put_loop                                    ; and restart
;       extern "C" void m_hl_check_fifo( void ** );
; parameters: pointer to the queue
m_hl_check_fifo:
        mov  rax,QWORD PTR[ rdi + HEAD_STA ]  ;get pointer to head element
        cmp  rax,QWORD PTR[ rdi + TAIL_STA ]  ;compare pointer to tail element
        je   p_empty                        ;  same, queue is empty
        mov  rax,QWORD PTR [rax]            ;get head->next
        ret
p_empty:                                    ;queue is empty
        xor  rax,rax                        ;clear return code
        ret
