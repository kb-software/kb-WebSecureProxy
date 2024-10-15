/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/krb5-types.h wurde automatisch veraendert! Phase 7*/

/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __krb5_types_h__
#define __krb5_types_h__
#ifdef _WIN32
#pragma once
#endif
#include "hob-krb5-defines.h"

#if defined(__HOB_KRB5_DEFINES) && defined(_WIN32) 
#include <hob-krb5-types.h>
#else
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef HL_SOLARIS
#include <sys/rds.h>
#endif

#ifndef _WIN32
typedef socklen_t krb5_socklen_t;
#endif

typedef ssize_t krb5_ssize_t;

#endif