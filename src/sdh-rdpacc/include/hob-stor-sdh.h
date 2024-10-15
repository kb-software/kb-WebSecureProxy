/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-stor-sdh.h                                      |*/
/*| -------------                                                     |*/
/*|  HOB common library - storage for Server-Data-Hooks               |*/
/*|  Work Threads and Timers                                          |*/
/*|  KB 04.08.05                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HOB_STOR_SDH
#define HOB_STOR_SDH

#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        // get a block of memory
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        // release a block of memory
#endif
#ifndef DEF_AUX_CONSOLE_OUT
#define DEF_AUX_CONSOLE_OUT        2        // output to console
#endif
#ifndef DEF_AUX_CO_UNICODE
#define DEF_AUX_CO_UNICODE         3        // output to console Unicode
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

struct dsd_stor_sdh_1 {                     /* HOB control storage SDH structure */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   void *     ac_stor_anchor;               /* anchor of storage blocks */
   void *     ac_big_stor_anchor;           /* anchor of big storage blocks */
   int        imc_stor_size;                /* size of storage element */
};

extern "C" void m_aux_stor_start( struct dsd_stor_sdh_1 * );
extern "C" void * m_aux_stor_alloc( struct dsd_stor_sdh_1 *, int );
extern "C" void m_aux_stor_free( struct dsd_stor_sdh_1 *, void * );
extern "C" void * m_aux_stor_realloc( struct dsd_stor_sdh_1 *, void *, int );
extern "C" void m_aux_stor_end( struct dsd_stor_sdh_1 * );
#endif
