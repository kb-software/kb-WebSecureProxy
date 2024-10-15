.text
		.balign 8     //align to 8 bytes

#        islock02-64-aarch64-gcc.s
#        copyright (c) HOB electronic D-90556 Cadolzburg, Germany
#        Copyright (C) HOB Germany 2012
#        Copyright (C) HOB Germany 2013
#        Copyright (C) HOB Germany 2015
#        derived from ISLOCK01.asm written 27.11.01 KB
#        28.08.12 KB
#        24.09.13 KB
#        11.10.13 KB
#        30.09.15 KB
#		 05.04.17 Maxim Drabkin

        .globl m_hl_lock_inc_1
        .globl m_hl_lock_dec_1
        .globl m_hl_lock_set_true_1
        .globl m_hl_get_chain
        .globl m_hl_put_chain

#       extern "C" void m_hl_lock_inc_1( int * )
m_hl_lock_inc_1:
		LDAXR W7, [X0]						//load-acquire
		ADD W7, W7, #1						//increment the first program argument
		STLXR W9, W7, [X0]					//store-release
		CBNZ W9, m_hl_lock_inc_1			//repeat, if unsuccesful
        RET                                 //return to calling program
#       extern "C" void m_hl_lock_dec_1( int * );
m_hl_lock_dec_1:
		LDAXR W7, [X0]						//load-acquire
		ADD W7, W7, #-1						//decrement the first program argument
		MOV W9, #0
		STLXR W9, W7, [X0]					//store-release
		CBNZ W9, m_hl_lock_dec_1			//repeat, if unsuccesful
        RET                                 //return to calling programm
#       extern "C" void m_hl_lock_set_true_1( int * );
m_hl_lock_set_true_1:
		MOV W7, WZR							//set w8 to zero
		MOV W7, #1							//add one
		MOV W9, #0
		STLXR W9, W7, [X0]					//set true
		CBNZ W9, m_hl_lock_set_true_1		//repeat, if unsuccesful
		RET
#       extern "C" void * m_hl_get_chain( void **, int * );
m_hl_get_chain:
        LDXR X7, [X0]                   //get first element in chain
        CMP X7, XZR                     //is the cache empty?
        B.NE pgetc_40                   //no, get buffer from chain
        RET                             //return to calling program
pgetc_40:
        STR X00, [SP, #-16]!             //push/save register
        MOV X00, #255
pgetc_60:
        MOV X7, XZR                     //clear register
        MOV W9, #0
        STLXR W9, X00, [X2]             //exchange operands
        CBNZ W9, pgetc_60
        LDXR X7, [X0]                   //get first element in chain
        CMP X7, XZR                     //is the cache empty?
        B.EQ pgetc_80                   //yes
pgetc_68:
        LDXR X00, [X7]                  //get second element in chain
        MOV W9, #0
        STLXR W9, X00, [X0]             //exchange operands
        CBZ W9, pgetc_80                //succeeded
        CMP X7, XZR                     //is the cache empty?
        B.NE pgetc_68                   //no, try again
pgetc_80:
        MOV X00, XZR                    //clear register
        MOV W9, #0
        STLXR W9, X00, [X2]             //exchange operands
        LDR X00, [SP], #16              //restore register
        RET                             //return to calling program
#       extern "C" void m_hl_put_chain( void **, void * );
m_hl_put_chain:
        LDAXR X7, [X0] 	   			        //get first element in chain
pputc_20
		MOV W9, #0
        STR W9, X7, [X2]		            //anchor of chain gets next buffer
		CBNZ X9, pputc_20                   //repeat, if unsuccesful
		//CMP X7, [X0]						//compare
		//B.NE m_hl_put_chain
		MOV W9, #0
		STLXR W9, X2, [X0]					//and exchange
        CBNZ W9, pputc_20                   //repeat, if unsuccesful
        RET                                 //return to calling program	