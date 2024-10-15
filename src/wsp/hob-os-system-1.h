/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-os-system-1.h                                      |*/
/*| ----------                                                        |*/
/*|  Header file for islsystem2 and nslsystem1                        |*/
/*|  subroutine for Windows system() / CreateProcess()                |*/
/*|  or for Unix / Linux system() / fork() execv()                    |*/
/*|    catches output from the program                                |*/
/*|    part of the HOB Common Library                                 |*/
/*|  KB 25.08.12                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   The subroutine islsystem2.cpp (using this header file)
   was developed to enable giving Windows commands like netsh
   and that it is possible to catch the output
   so that the calling program can write the output to the
   Windows event log for diagnosis.
   Please mind that the output from the program / function
   may be either ASCII 850 or wide characters / Unicode UTF-16 little endian.
   The Windows system does not provide an API to destinguish
   between these two formats.
   So the resulting output should be processed as binary trace output.
*/

struct dsd_os_sys_1 {                       /* Windows / Unix system command */
   int        imc_max_time_sec;             /* zero or maximum time in seconds */
   int        imc_proc_rc;                  /* return code of process  */
   int        imc_len_buffer;               /* length of buffer for returned messages */
   int        imc_len_ret;                  /* length returned messages */
   int        imc_buff_exceeded;            /* length buffer exceeded  */
   BOOL       boc_timed_out;                /* application timed out   */
   char       *achc_buffer;                 /* address of buffer for returned messages */
};

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE int m_call_system_1( struct dsd_os_sys_1 *, char *achp_command );

