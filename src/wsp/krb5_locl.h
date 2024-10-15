#define HL_KRB5
/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/krb5_locl.h wurde automatisch veraendert! Phase 7*/

/*
 * Copyright (c) 1997-2002 Kungliga Tekniska Högskolan
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

#ifndef __KRB5_LOCL_H__
#define __KRB5_LOCL_H__
#ifdef _WIN32
#pragma once
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#ifdef HAVE_PWD_H
#undef _POSIX_PTHREAD_SEMANTICS

#define _POSIX_PTHREAD_SEMANTICS

#endif

#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#ifdef _AIX
struct ether_addr;
struct mbuf;
struct sockaddr_dl;
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_CRYPT_H
#undef des_encrypt
#define des_encrypt wingless_pigs_mostly_fail_to_fly

#undef des_encrypt
#endif

#ifdef HAVE_DOOR_CREATE
#include <door.h>
#endif

#include <roken.h>

#ifdef KRB5
#include <krb5-types.h>
#elif defined(KRB4)
#include <ktypes.h>
#endif
#include <des.h>
#include "hob-encry-1.h"
#ifdef BOOL
#undef BOOL
typedef int BOOL;   /** @todo checkt, if this workaround is only required in windows */
#endif
struct krb5_pk_identity;
struct krb5_pk_cert;
struct ContentInfo;
typedef struct krb5_pk_init_ctx_data *krb5_pk_init_ctx;

struct _krb5_krb_auth_data;

#include <krb5.h>

#include <hob-krb5-asn1.h>

#define ALLOC(X, N) (X) = memset(m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,(N)*sizeof(*(X))),'\0',(N)*sizeof(*(X)))
#define ALLOC_SEQ(X, N) do { (X)->len = (N); ALLOC((X)->val, (N)); } while(0)
#define KEYTAB_DEFAULT "ANY:FILE:" SYSCONFDIR "/krb5.keytab,krb4:" SYSCONFDIR "/srvtab"
#define KEYTAB_DEFAULT_MODIFY "FILE:" SYSCONFDIR "/krb5.keytab"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define KRB5_BUFSIZ 1024

typedef enum {
    KRB5_PA_PAC_DONT_CARE = 0,
    KRB5_PA_PAC_REQ_TRUE,
    KRB5_PA_PAC_REQ_FALSE
} krb5_get_init_creds_req_pac;

struct _krb5_get_init_creds_opt_private {
    int refcount;

    const char *password;
    krb5_s2k_proc key_proc;

    krb5_get_init_creds_req_pac req_pac;

    krb5_pk_init_ctx pk_init_ctx;
    int canonicalize;
};

#endif
