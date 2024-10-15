/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: iswcord1                                            |*/
/*| -------------                                                     |*/
/*|  Subroutine for HOB Server Programs to produce a Core Dump.       |*/
/*|  This Core Dump will be used for Maintanance.                     |*/
/*|  KB 27.03.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual C++ 6.0                                                |*/
/*|  MS Linker                                                        |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/
//define _WIN32_WINNT 0X0501
//define WINVER 0X0501


#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif

extern PTYPE void m_hl_setdump();
extern PTYPE void m_hl_abend1( char * );

extern LONG __stdcall m_hl_toplevelexceptionfilter(PEXCEPTION_POINTERS adsExcepPointers);

#ifndef D_HL_WCORD1
#define D_HL_WCORD1

struct dsd_wcord1
{
    char *achc_wregpardir;                //Registry-Parameter-Directory or NULL
    char *achc_diskdirfd;                 //disk-directory for Dumps
    char *achc_ineta_mgw;                 //INETA mail-gateway
    char *achc_email_rcpt;                //e-mail recipient
    char *achc_email_sender;              //e-mail sender
    char *achc_password;                  //password
};

extern struct dsd_wcord1 dsg_wcord1;

#endif
