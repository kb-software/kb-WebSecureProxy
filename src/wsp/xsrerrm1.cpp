 /*+--------------------------------------------------------------------+*/
  /*| PROGRAM NAME: xsrerrm1.cpp                                        |*/
  /*|  Source File of for SSL Errormessages                             |*/
  /*|  SR 03.02.05                                                      |*/
  /*|                                                                   |*/
  /*| COPYRIGHT:                                                        |*/
  /*| ----------                                                        |*/
  /*|  Copyright (C) HOB 2005                                           |*/
  /*|  Copyright (C) HOB Germany 2011                                   |*/
  /*|                                                                   |*/
  /*+-------------------------------------------------------------------+*/

#ifdef OLD01
#include <iostream>
#include <fstream>
#include <tchar.h>
#endif
#ifndef HL_UNIX
#include <windows.h>
#else
#include "hob-unix01.h"
#include <netinet/in.h>
#endif
#include "hob-xsrerrm1.h"
#define M_NTOHL(astrp) ((unsigned int) (*((unsigned char *) astrp + 0) << 24) \
        | (*((unsigned char *) astrp + 1) << 16) \
        | ((*((unsigned char *) astrp + 2) << 8)) \
        | *((unsigned char *) astrp + 3))

BOOL m_rerrm1(int inp_errno, char **aachp_output, int *ainp_len_output, const unsigned char *aucp_errmsg ) {

   int i_search = inp_errno;
// int in_top = ntohl(*((int *) aucp_errmsg));
   int in_top;
   int in_bottom = 0;
   int in_mid;
   in_top = M_NTOHL( aucp_errmsg + 0 );
   while( in_top >= 0)
   {
      in_mid = (in_bottom + in_top )/2;                              /* compute mid point. */
//    if(i_search > ntohl(*((int *) (aucp_errmsg + (in_mid * 3 +1 ) * 4))))
      if (i_search > M_NTOHL( aucp_errmsg + (in_mid * 3 + 1) * 4) )
         in_top = in_mid - 1;                                        /* repeat search in top half. */
      else
         in_bottom = in_mid + 1;                                     /* repeat search in bottom half.*/

//    if( i_search == ntohl(*((int*) (aucp_errmsg + (in_mid * 3 +1) * 4)))) {  /* found error number. */
//    }
      if( i_search == M_NTOHL( aucp_errmsg + (in_mid * 3 + 1) * 4)) {  /* found error number. */

//       int i_offset = ntohl(*((int*) (aucp_errmsg + (in_mid * 3 +2) * 4)));
         int i_offset = M_NTOHL( aucp_errmsg + (in_mid * 3 + 2) * 4 );
//       *ainp_len_output = ntohl(*((int*) (aucp_errmsg + (in_mid * 3 +3) * 4)));
         *ainp_len_output = M_NTOHL( aucp_errmsg + (in_mid * 3 + 3) * 4 );
         *aachp_output = (char *) aucp_errmsg + i_offset;

         return TRUE;
      }
      if((in_bottom == in_mid) || (in_top == in_mid)) {
         return FALSE;
      }
   }

   return FALSE;

}



