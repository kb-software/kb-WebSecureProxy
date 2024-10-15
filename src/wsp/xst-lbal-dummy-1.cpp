//#define DO_CONSTANT
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xst-lbal-dummy-1                                    |*/
/*| -------------                                                     |*/
/*| load-balancing subroutine dummy                                   |*/
/*|   for HOB WebSecureProxy (WSP)                                    |*/
/*|  KB 24.03.09                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifndef DO_CONSTANT
#ifndef NO_SRAND
#ifndef HL_UNIX
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#endif
#endif
#endif

extern "C" int m_get_random_number( int impmax );

extern "C" int m_get_load( void ) {
#ifndef DO_CONSTANT
#ifndef NO_SRAND
#ifndef HL_UNIX
   srand( (int) time( NULL ) | GetCurrentThreadId() );
#endif
#endif
   return m_get_random_number( 10000 + 1 );
#else
   return 1000;
#endif
}

extern "C" int m_set_lb_formula( char *achp_buffer, const unsigned int ump_len_buffer ) {
   return 0;
}


int m_get_perf_data( struct dsd_perf_data* dsp_perf ) {
	return 0;
}

extern "C" bool m_start_monitor_thread() {
	return true;
}

int m_get_perf_array(char* achp_data, int imp_length) {
	return 0;
}