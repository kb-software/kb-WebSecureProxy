/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-unix01.h                                           |*/
/*| ----------                                                        |*/
/*|  C/C++ Header file for HOB Unix/Linux programs.                   |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

// to-do 02.06.11 KB - remove parts not needed

#ifndef SOLARIS_INC
#define SOLARIS_INC
#ifdef B110602
// G.Oed, 22.02.2007, SOLARIS confuses Xercesc includes with linux !!!
//#define SOLARIS
#include <string.h>
#include <stdarg.h>
#define _OPEN_THREADS                      /* enable threads          */
#include <pthread.h>
#define TerminateThread(hThread,e) pthread_cancel((unsigned)hThread)
#define ODBCVER  0x0300
#endif
#define TRUE 1
#define FALSE 0
#define far
#define __cdecl
#define _MAX_PATH 255
#define LPSTR char *
#define WINAPI
#define SOCKET_ERROR            (-1)
#ifdef B110602
#define WSABASEERR              10000
#endif

#ifndef ULONG
typedef unsigned long int ULONG;
#endif
#ifndef WCHAR
typedef unsigned short int WCHAR;
#endif
#ifndef UINT
typedef unsigned int UINT;
#endif
#ifndef BYTE
typedef char BYTE;
#endif
#define VOID void
#define WORD short
#ifdef B160909
#define DWORD long
#endif
#define DWORD unsigned int
#define LPWSTR char *
#define BOOL int
#define PUCHAR unsigned char *
#define SHORT short
#define CHAR char
#define PVOID void *
#define UNSIG_MED unsigned int
typedef PVOID HANDLE;
#define SOCKET int
#define __declspec(dllexport)
#ifdef HL_LINUX
#ifndef INFTIM
#define INFTIM -1
#endif
#endif
#ifdef HL_SOLARIS
#ifndef INFTIM
#define INFTIM -1
#endif
#endif
#endif

