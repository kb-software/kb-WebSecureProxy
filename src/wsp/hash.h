/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/hash.h wurde automatisch veraendert! Phase 7*/

/*
 * Copyright (c) 1999 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */





#ifndef __hash_h__
#define __hash_h__
#ifndef HL_KRB5
               #ifndef HL_KRB5
                  
                  #include <stdlib.h>
               #else  /* HL_KRB5 */
                  #ifdef WITH_OWN_SYSTEMHAEDERN
                     #ifdef PLATTFORM
                       #include <stdlib.h>
                     #else
                       #include <stdlib.h_org>
                     #endif
                  #else
                     #include <stdlib.h>
                  #endif
               #endif  /* HL_KRB5 */
               
#ifndef HL_KRB5
   #include <string.h>
#else  /* HL_KRB5 */
   #ifdef WITH_OWN_SYSTEMHAEDERN
      #ifdef PLATTFORM
        #include <string.h>
      #else
        #include <string.h_org>
      #endif
   #else
      #include <string.h>
   #endif
#endif  /* HL_KRB5 */


#else  /* HL_KRB5 */


#endif  /* HL_KRB5 */
#include <stddef.h>
#ifdef KRB5
#include <krb5-types.h>
#endif

#ifndef min
#define min(a,b) (((a)>(b))?(b):(a))
#endif

/* Vector Crays doesn't have a good 32-bit type, or more precisely,
   int32_t as defined by <bind/bitypes.h> isn't 32 bits, and we don't
   want to depend in being able to redefine this type.  To cope with
   this we have to clamp the result in some places to [0,2^32); no
   need to do this on other machines.  Did I say this was a mess?
   */

#ifdef _CRAY
#define CRAYFIX(X) ((X) & 0xffffffff)
#else
#define CRAYFIX(X) (X)
#endif

static inline u_int32_t
cshift (u_int32_t x, unsigned int n)
{
    x = CRAYFIX(x);
    return CRAYFIX((x << n) | (x >> (32 - n)));
}

#endif 
