/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/des.h wurde automatisch veraendert! Phase 7*/

/*
 * Copyright (c) 2005 Kungliga Tekniska H�gskolan
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

#ifndef _DESperate_H
#define _DESperate_H 1

#define DES_CBLOCK_LEN 8
#define DES_KEY_SZ 8

typedef unsigned char DES_cblock[DES_CBLOCK_LEN];
typedef unsigned int DES_key_schedule[32];

int	DES_set_odd_parity(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );
int	DES_is_weak_key(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );
int	DES_new_random_key(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );
void	DES_string_to_key( const char *, DES_cblock * );

void	DES_rand_data(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *, int );
void	DES_set_random_generator_seed(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );
void	DES_generate_random_block(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );
void 	DES_init_random_number_generator(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock * );

#endif
