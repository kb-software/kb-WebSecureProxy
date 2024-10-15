/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/der_locl.h wurde automatisch veraendert! Phase 7*/

/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */



#ifndef __DER_LOCL_H__
#define __DER_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef HL_KRB5
               #ifndef HL_KRB5
                  
                  #include <assert.h>
               #else  /* HL_KRB5 */
                  #ifdef WITH_OWN_SYSTEMHAEDERN
                     #ifdef PLATTFORM
                       #include <assert.h>
                     #else
                       #include <assert.h_org>
                     #endif
                  #else
                     #include <assert.h>
                  #endif
               #endif  /* HL_KRB5 */
               
#ifndef HL_KRB5
   #include <stdio.h>
#else  /* HL_KRB5 */
   #ifdef WITH_OWN_SYSTEMHAEDERN
      #ifdef PLATTFORM
        #include <stdio.h>
      #else
        #include <stdio.h_org>
      #endif
   #else
      #include <stdio.h>
   #endif
#endif  /* HL_KRB5 */


#else  /* HL_KRB5 */


#endif  /* HL_KRB5 */
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

#ifndef HL_KRB5

#ifndef HL_KRB5
#include <limits.h>
#else  /* HL_KRB5 */

#endif  /* HL_KRB5 */

#else  /* HL_KRB5 */

#endif  /* HL_KRB5 */


#ifndef HL_KRB5
#include <ctype.h>
#else  /* HL_KRB5 */

#endif  /* HL_KRB5 */
                     #ifndef HL_KRB5
                        
                        #include <time.h>
                     #else  /* HL_KRB5 */
                        #ifdef WITH_OWN_SYSTEMHAEDERN
                           #ifdef PLATTFORM
                             #include <time.h>
                           #else
                             #include <time.h_org>
                           #endif
                        #else
                           #include <time.h>
                        #endif
                     #endif  /* HL_KRB5 */
                     
#ifndef HL_KRB5
   #include <errno.h>
#else  /* HL_KRB5 */
   #ifdef WITH_OWN_SYSTEMHAEDERN
      #ifdef PLATTFORM
        #include <errno.h>
      #else
        #include <errno.h_org>
      #endif
   #else
      #include <errno.h>
   #endif
#endif  /* HL_KRB5 */

#ifndef HL_KRB5

#include <roken.h>


#else  /* HL_KRB5 */


#endif  /* HL_KRB5 */
#include <asn1-common.h>
#include <asn1_err.h>
#include <der.h>

size_t _heim_len_unsigned (
                           #ifdef HL_KRB5
                           struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                           #endif  /* HL_KRB5 */
                           unsigned);
size_t _heim_len_int (
                      #ifdef HL_KRB5
                      struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                      #endif  /* HL_KRB5 */
                      int);

#endif 
