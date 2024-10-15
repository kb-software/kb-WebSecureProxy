//#define TRACEHL1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: islsystem2                                          |*/
/*| -------------                                                     |*/
/*|  subroutine for Windows system() / CreateProcess()                |*/
/*|    catches output from the program                                |*/
/*|    part of the HOB Common Library                                 |*/
/*|  KB 25.08.12                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <time.h>
#include <windows.h>
#include <stdio.h>

#include "hob-os-system-1.h"

#define HL_PIPE_NAME "\\\\.\\pipe\\HOB-THR-SYSTEM-%010d"

/*+-------------------------------------------------------------------+*/
/*| External function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

extern "C" int m_hl1_printf( char *, ... );

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

extern "C" int m_call_system_1( struct dsd_os_sys_1 *adsp_os1, char *achp_command ) {
   BOOL       bol_rc;                       /* return code             */
   DWORD      dwl1;                         /* working variable        */
   DWORD      dwl_wait;                     /* returned from wait      */
   DWORD      dwl_read;                     /* bytes read              */
   int        iml1;                         /* working variable        */
   int        iml_no_event;                 /* number of events to wait for */
   int        iml_timeout;                  /* timeout in seconds      */
   int        iml_time_cur;                 /* current time            */
   int        iml_time_end;                 /* end time                */
   int        iml_buff_exceeded;            /* length buffer exceeded  */
   BOOL       bol_pipe_r_a;                 /* pipe read active        */
   BOOL       bol_pipe_ended;               /* pipe has ended          */
   HANDLE     dsl_hpipe_server;             /* handle of pipe server side */
   HANDLE     dsl_hpipe_client;             /* handle of pipe client side */
   HANDLE     dsrl_hwait[ 2 ];              /* wait multiple           */
   SECURITY_ATTRIBUTES dsl_sec_attr;        /* pipe security attributes */
   PROCESS_INFORMATION dsl_proc_info;       /* child process info      */
   STARTUPINFOA dsl_start_info;             /* child start info        */
   OVERLAPPED dsl_olstr_inp;                /* structure for overlapped IO input from pipe */
   char       chrl_pipe_name[ 128 ];        /* name of used Windows named pipe */
   char       chrl_inp_pipe[ 512 ];         /* input from pipe         */

   adsp_os1->imc_len_ret = 0;               /* clear length returned messages */
// adsp_os1->imc_proc_rc = 0;               /* clear return code of process */
   adsp_os1->boc_timed_out = FALSE;         /* clear application timed out */
   iml_buff_exceeded = 0;                   /* clear length buffer exceeded */

   memset( &dsl_sec_attr, 0, sizeof(SECURITY_ATTRIBUTES) );
   dsl_sec_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
   dsl_sec_attr.bInheritHandle = TRUE;      /* pipe handles are inherited */
// dsl_sec_attr.lpSecurityDescriptor = NULL;
   sprintf( chrl_pipe_name, HL_PIPE_NAME, GetCurrentThreadId() ) ;
   dsl_hpipe_server = CreateNamedPipeA( chrl_pipe_name,  // pointer to pipe name
                                        PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH  // pipe open mode
                                          | FILE_FLAG_OVERLAPPED,
                                        PIPE_WAIT | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,  //DWORD  dwPipeMode,	// pipe-specific modes
                                        1,  // maximum number of instances
                                        512,  // output buffer size, in bytes
                                        512,  // input buffer size, in bytes
                                        INFINITE,  // time-out time, in milliseconds
                                        &dsl_sec_attr );  // pointer to security attributes structure
//                                      NULL );  // pointer to security attributes structure
   if (chrl_pipe_name == INVALID_HANDLE_VALUE) {
     m_hl1_printf( "islsystem2-l%05d-W CreateNamedPipe Error %d.",
                   __LINE__, GetLastError() );
     return -1;
   }
   memset( &dsl_olstr_inp, 0, sizeof(dsl_olstr_inp) );
   dsl_olstr_inp.hEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
   if (dsl_olstr_inp.hEvent == NULL) {
     m_hl1_printf( "islsystem2-l%05d-E CreateEvent pipe overlapped input failed error %d.",
                   __LINE__, GetLastError() );
     CloseHandle( dsl_hpipe_server );
     return -1;
   }
// bol_pipe_r_a = FALSE;                    /* reset pipe read active  */
   bol_rc = ConnectNamedPipe( dsl_hpipe_server,
                              &dsl_olstr_inp );
   dwl1 = GetLastError();
   if ((bol_rc) || (dwl1 != ERROR_IO_PENDING)) {  /* error occured     */
     m_hl1_printf( "islsystem2-l%05d-E ConnectNamedPipe() failed error %d %d.",
                   __LINE__, bol_rc, GetLastError() );
     CloseHandle( dsl_hpipe_server );
     CloseHandle( dsl_olstr_inp.hEvent );
     return -1;
   }
   bol_pipe_r_a = TRUE;                     /* set pipe read active    */
   dsl_hpipe_client = CreateFileA( chrl_pipe_name,
                                   GENERIC_READ | GENERIC_WRITE,
                                   0, &dsl_sec_attr, OPEN_EXISTING,
//                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL );
   if (dsl_hpipe_client == INVALID_HANDLE_VALUE) {
     m_hl1_printf( "islsystem2-l%05d-E CreateFile pipe name %s failed error %d.",
                   __LINE__, chrl_pipe_name, GetLastError() );
     CloseHandle( dsl_hpipe_server );
     CloseHandle( dsl_olstr_inp.hEvent );
     return -1;
   }
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-T CreateFileA() pipe successful",
                 __LINE__ );
#endif

   memset( &dsl_proc_info, 0, sizeof(PROCESS_INFORMATION) );

   // specify the STDIN and STDOUT handles for redirection.
   memset( &dsl_start_info, 0, sizeof(STARTUPINFOA) );
   dsl_start_info.cb         = sizeof(STARTUPINFOA);
   dsl_start_info.hStdError  = dsl_hpipe_client;
   dsl_start_info.hStdOutput = dsl_hpipe_client;
   dsl_start_info.hStdInput  = dsl_hpipe_client;
   dsl_start_info.dwFlags = STARTF_USESTDHANDLES;

   bol_rc = CreateProcessA( NULL,
                            achp_command,       // child process TODO!
                            NULL,               // process security attributes
                            NULL,               // primary thread security attributes
                            TRUE,               // handles are inherited
                            0,                  // creation flags
                            NULL,               // use parent's environment
                            NULL,               // use parent's current directory
                            &dsl_start_info,    // STARTUPINFO pointer
                            &dsl_proc_info  );  // receives PROCESS_INFORMATION
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "islsystem2-l%05d-W CreateProcessA() returned error %d.",
                   __LINE__, GetLastError() );
     CloseHandle( dsl_hpipe_server );
     CloseHandle( dsl_olstr_inp.hEvent );
     CloseHandle( dsl_hpipe_client );
     return -1;
   }
   CloseHandle( dsl_hpipe_client );
   CloseHandle( dsl_proc_info.hThread  );
   dsrl_hwait[ 0 ] = dsl_olstr_inp.hEvent;  /* wait multiple           */
   dsrl_hwait[ 1 ] = dsl_proc_info.hProcess;
   iml_no_event = 2;
   bol_pipe_ended = FALSE;                  /* reset pipe has ended    */
   iml_timeout = adsp_os1->imc_max_time_sec;  /* zero or maximum time in seconds */
   if (iml_timeout > 0) {                   /* timeout in seconds      */
     iml_time_end = (int) time( NULL ) + iml_timeout;
   }

   p_wait_00:                               /* wait for event          */
   if (bol_pipe_r_a) goto p_wait_20;        /* pipe is in read state   */
   bol_pipe_r_a = TRUE;                     /* set pipe read active    */

   p_wait_08:                               /* read from pipe          */
   bol_rc = ReadFile( dsl_hpipe_server,
                      chrl_inp_pipe, sizeof(chrl_inp_pipe),
                      &dwl_read, &dsl_olstr_inp );
   dwl1 = GetLastError();
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-T ReadFile() returned %d error %d.",
                 __LINE__, bol_rc, dwl1 );
#endif
   if (bol_rc) {                            /* data read               */
#ifdef TRACEHL1
     m_hl1_printf( "islsystem2-l%05d-T ReadFile() returned TRUE - dwl_read=%d.",
                   __LINE__, dwl_read );
#endif
     if (dwl_read > 0) {                    /* data transfered         */
       iml1 = adsp_os1->imc_len_buffer - adsp_os1->imc_len_ret;
       if (iml1 > dwl_read) iml1 = dwl_read;
       if (iml1 > 0) {                      /* something to copy       */
         memcpy( adsp_os1->achc_buffer + adsp_os1->imc_len_ret,
                 chrl_inp_pipe,
                 iml1 );
         adsp_os1->imc_len_ret += iml1;
         dwl_read -= iml1;
       }
       iml_buff_exceeded += dwl_read;       /* add to length buffer exceeded */
#ifdef XYZ1
       goto p_wait_08;                      /* read from pipe          */
#endif
     }
#ifdef XYZ1
     /* read returned zero - end of file                               */
     if (iml_no_event > 1) {                /* process did not end     */
       m_hl1_printf( "islsystem2-l%05d-W ReadFile() returned zero but process not ended",
                     __LINE__ );
       goto p_wait_08;                      /* read from pipe          */
     }
     bol_rc = CloseHandle( dsl_hpipe_server );
     if (bol_rc == FALSE) {                 /* returned error          */
       m_hl1_printf( "islsystem2-l%05d-W CloseHandle() pipe returned error %d.",
                     __LINE__, GetLastError() );
     }
     bol_rc = CloseHandle( dsl_olstr_inp.hEvent );
     if (bol_rc == FALSE) {                 /* returned error          */
       m_hl1_printf( "islsystem2-l%05d-W CloseHandle() event returned error %d.",
                     __LINE__, GetLastError() );
     }
     goto p_end_00;                         /* end of program          */
#endif
     goto p_wait_08;                        /* read from pipe          */
   }
   if (dwl1 == ERROR_BROKEN_PIPE) {
     bol_pipe_ended = TRUE;                 /* pipe has ended          */
   }

   p_wait_20:                               /* pipe is in read state   */
   dwl1 = INFINITE;
   while (iml_timeout > 0) {                /* zero or maximum time in seconds */
     iml_time_cur = (int) time( NULL );
     if (iml_time_cur >= iml_time_end) {
// to-do 17.06.12 KB
       m_hl1_printf( "islsystem2-l%05d-W timelimit exceeded",
                     __LINE__ );
       iml_timeout = 0;
       if (iml_no_event == 1) break;        /* process already ended   */
       adsp_os1->boc_timed_out = TRUE;      /* set application timed out */
       bol_rc = TerminateProcess( dsl_proc_info.hProcess, 0 );
       if (bol_rc) break;                   /* no error occured        */
       m_hl1_printf( "islsystem2-l%05d-W TerminateProcess() returned error %d.",
                     __LINE__, GetLastError() );
       break;
     }
     dwl1 = (iml_time_end - iml_time_cur) * 1000;  /* timeout milliseconds */
     break;
   }
   dwl_wait = WaitForMultipleObjects( iml_no_event, dsrl_hwait, FALSE, dwl1 );
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-T WaitForMultipleObjects() returned %d - error %d.",
                 __LINE__, dwl_wait, GetLastError() );
#endif
   if (dwl_wait == (WAIT_OBJECT_0 + 1)) {
     goto p_wait_80;                        /* process has ended       */
   }
   if (dwl_wait != WAIT_OBJECT_0) {         /* not pipe                */
     Sleep( 500 );                          /* wait some time          */
     goto p_wait_20;                        /* pipe is in read state   */
   }
   bol_pipe_r_a = FALSE;                    /* reset pipe read active  */
   bol_rc = ResetEvent( dsl_olstr_inp.hEvent );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "islsystem2-l%05d-W ResetEvent Pipe Error %d.",
                   __LINE__, GetLastError() );
   }

   bol_rc = GetOverlappedResult( dsl_hpipe_server,
                                 &dsl_olstr_inp, &dwl_read, TRUE );
   if (bol_rc) {                            /* no error occured        */
#ifdef TRACEHL1
     m_hl1_printf( "islsystem2-l%05d-T GetOverlappedResult() returned TRUE - dwl_read=%d.",
                   __LINE__, dwl_read );
#endif
     if (dwl_read > 0) {                    /* data transfered         */
       iml1 = adsp_os1->imc_len_buffer - adsp_os1->imc_len_ret;
       if (iml1 > dwl_read) iml1 = dwl_read;
       if (iml1 > 0) {                      /* something to copy       */
         memcpy( adsp_os1->achc_buffer + adsp_os1->imc_len_ret,
                 chrl_inp_pipe,
                 iml1 );
         adsp_os1->imc_len_ret += iml1;
         dwl_read -= iml1;
       }
       iml_buff_exceeded += dwl_read;       /* add to length buffer exceeded */
     }
     goto p_wait_00;                        /* wait for event          */
   }
   dwl1 = GetLastError();
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-T GetOverlappedResult() returned error %d.",
                 __LINE__, dwl1 );
#endif
// switch (dwl1) {
// }
   goto p_wait_00;                          /* wait for event          */

   p_wait_80:                               /* process has ended       */
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-T process has ended",
                 __LINE__ );
#endif
// to-do 17.06.12 KB - return code
   bol_rc = GetExitCodeProcess( dsl_proc_info.hProcess, (DWORD *) &adsp_os1->imc_proc_rc );  /* return code of process */
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hl1_printf( "islsystem2-l%05d-W GetExitCodeProcess() returned error %d.",
                   __LINE__, GetLastError() );
   }
   bol_rc = CloseHandle( dsl_proc_info.hProcess );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hl1_printf( "islsystem2-l%05d-W CloseHandle() process returned error %d.",
                   __LINE__, GetLastError() );
   }
   iml_no_event = 1;                        /* number of events to wait for */
   if (bol_pipe_ended == FALSE) {           /* pipe has not yet ended  */
     goto p_wait_20;                        /* pipe is in read state   */
   }

   p_end_00:                                /* end of program          */
   bol_rc = CloseHandle( dsl_hpipe_server );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hl1_printf( "islsystem2-l%05d-W CloseHandle() pipe returned error %d.",
                   __LINE__, GetLastError() );
   }
   bol_rc = CloseHandle( dsl_olstr_inp.hEvent );
   if (bol_rc == FALSE) {                   /* returned error          */
     m_hl1_printf( "islsystem2-l%05d-W CloseHandle() event returned error %d.",
                   __LINE__, GetLastError() );
   }
   adsp_os1->imc_buff_exceeded = iml_buff_exceeded;  /* length buffer exceeded */
   if (iml_buff_exceeded > 0) {             /* length buffer exceeded */
     m_hl1_printf( "islsystem2-l%05d-W output of process exceeded buffer by %d bytes",
                   __LINE__, iml_buff_exceeded );
   }
//------------------------------------
#ifdef TRACEHL1
   m_hl1_printf( "islsystem2-l%05d-I program ended",
                 __LINE__ );
#endif
   return 0;                                /* all done                */
} /* end m_win_system_1()                                              */
