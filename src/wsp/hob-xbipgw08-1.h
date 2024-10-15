/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: IBIPGW08                                            |*/
/*| -------------                                                     |*/
/*|  IP-Gateway Telnet for Win32 with SSL                             |*/
/*|  WebSecureProxy for Windows                                       |*/
/*|  KB 29.03.00                                                      |*/
/*|  Win64 KB 24.01.05                                                |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2000                                |*/
/*|  Copyright (C) HOB electronic 2001                                |*/
/*|  Copyright (C) HOB electronic 2002                                |*/
/*|  Copyright (C) HOB electronic 2003                                |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB 2005                                           |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  XERCES 2.6.0                                                     |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/


#define GHFW(str) ((unsigned int) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((unsigned short int) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifndef HL_HMODULE
#ifndef HL_UNIX
#define HL_HMODULE HMODULE
#else
#define HL_HMODULE void *
#endif
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifdef OLD01
#ifndef HL_UNIX
#ifndef WIN64
typedef long int dsd_time_1;
#else
typedef __int64 dsd_time_1;
#define NEW_VISUAL_C
#endif
#endif
#endif
typedef time_t dsd_time_1;
//#ifndef HL_UNIX
//typedef int socklen_t;
//#endif

