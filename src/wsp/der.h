/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/der.h wurde automatisch veraendert! Phase 7*/

/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska H�gskolan
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

#ifndef __DER_H__
#define __DER_H__

typedef enum {
    ASN1_C_UNIV = 0,
    ASN1_C_APPL = 1,
    ASN1_C_CONTEXT = 2 ,
    ASN1_C_PRIVATE = 3
} Der_class;

typedef enum {PRIM = 0, CONS = 1} Der_type;

enum {
    UT_Boolean		= 1,
    UT_Integer		= 2,
    UT_BitString	= 3,
    UT_OctetString	= 4,
    UT_Null		= 5,
    UT_OID		= 6,
    UT_Enumerated	= 10,
    UT_UTF8String	= 12,
    UT_Sequence	= 16,
    UT_Set		= 17,
    UT_PrintableString	= 19,
    UT_IA5String	= 22,
    UT_UTCTime		= 23,
    UT_GeneralizedTime	= 24,
    UT_VisibleString	= 26,
    UT_GeneralString	= 27
};

#define ASN1_INDEFINITE 0xdce0deed

#ifndef HAVE_TIMEGM
time_t timegm( struct tm * );
#endif

int time2generalizedtime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, time_t t, heim_octet_string *s );

int der_get_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, int *ret, size_t *size );
int der_get_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                    size_t *val, size_t *size );
int der_get_boolean( const unsigned char *p, size_t len,
                     int *data, size_t *size );
int der_get_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                            heim_general_string *str, size_t *size );
int der_get_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                          heim_octet_string *data, size_t *size );
int der_get_oid( const unsigned char *p, size_t len,
                 heim_oid *data, size_t *size );
int der_get_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                 Der_class *class, Der_type *type,
                 int *tag, size_t *size );

int der_match_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                   Der_class class, Der_type type,
                   int tag, size_t *size );
int der_match_tag_and_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                              Der_class class, Der_type type, int tag,
                              size_t *length_ret, size_t *size );

int decode_boolean( const unsigned char*, size_t, int*, size_t* );
int decode_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char*, size_t, int*, size_t* );
int decode_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char*, size_t, unsigned*, size_t* );
int decode_enumerated( const unsigned char*, size_t, unsigned*, size_t* );
int decode_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char*, size_t,
                           heim_general_string*, size_t* );
int decode_oid( const unsigned char *p, size_t len,
                heim_oid *k, size_t *size );
int decode_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char*, size_t,
                         heim_octet_string*, size_t* );
int decode_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char*, size_t, time_t*, size_t* );
int decode_nulltype( const unsigned char*, size_t, size_t* );
int decode_utf8string( const unsigned char*, size_t,
                       heim_utf8_string*, size_t* );

int der_put_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, int val, size_t* );
int der_put_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, size_t val, size_t* );
int der_put_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const int *data, size_t* );
int der_put_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                            const heim_general_string *str, size_t* );
int der_put_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                          const heim_octet_string *data, size_t* );
int der_put_oid( unsigned char *p, size_t len,
                 const heim_oid *data, size_t *size );
int der_put_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, Der_class class, Der_type type,
                 int tag, size_t* );
int der_put_length_and_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char*, size_t, size_t,
                            Der_class, Der_type, int, size_t* );

int encode_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                    const int *data, size_t* );
int encode_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                    const int *data, size_t* );
int encode_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                     const unsigned *data, size_t* );
int encode_enumerated( unsigned char *p, size_t len,
                       const unsigned *data, size_t* );
int encode_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                           const heim_general_string *data, size_t* );
int encode_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                         const heim_octet_string *k, size_t* );
int encode_oid( unsigned char *p, size_t len,
                const heim_oid *k, size_t* );
int encode_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                             const time_t *t, size_t* );
int encode_nulltype( unsigned char*, size_t, size_t* );
int encode_utf8string( unsigned char*, size_t,
                       const heim_utf8_string*, size_t* );

void free_integer( int *num );
void free_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, heim_general_string *str );
void free_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, heim_octet_string *k );
void free_oid( heim_oid *k );
void free_generalized_time( time_t *t );
void free_utf8string( heim_utf8_string* );

size_t length_len( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t len );
size_t length_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const int *data );
size_t length_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const int *data );
size_t length_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned *data );
size_t length_enumerated( const unsigned *data );
size_t length_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_general_string *data );
size_t length_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_octet_string *k );
size_t length_oid( const heim_oid *k );
size_t length_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const time_t *t );
size_t length_nulltype( void );
size_t length_utf8string( const heim_utf8_string* );

int copy_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_general_string *, heim_general_string * );
int copy_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_octet_string *, heim_octet_string * );
int copy_oid( const heim_oid *from, heim_oid *to );
int copy_nulltype( void *, void * );
int copy_utf8string( const heim_utf8_string*, heim_utf8_string* );

int heim_oid_cmp( const heim_oid *, const heim_oid * );
int heim_octet_string_cmp( const heim_octet_string *,const heim_octet_string * );

int fix_dce( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t reallen, size_t *len );
size_t _heim_len_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned );
size_t _heim_len_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int );

#endif
