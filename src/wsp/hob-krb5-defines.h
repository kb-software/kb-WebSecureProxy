#ifndef __HOB_KRB5_DEFINES
#define __HOB_KRB5_DEFINES
#ifdef _WIN32
#pragma once
#endif
#include "hob-krb5-asn1.h"

#define HL_KRB5
#define HL_KRB5_WSP_ACTIV
#ifdef HL_KRB5_WSP_ACTIV
#define WITH_OWN_NET_CONNECT
#endif
#define DEBUG_HOB   /* must be defined for development_building */
#define ROKEN_LIB_FUNCTION
#define ERROR_STRING_LENGTH 1024
#define MAX_NUMBER_OF_ERROR_STRINGS 100

#define WITHOUT_FILE
#define WITHOUT_ABORT_AND_EXIT

#define HOB_KERBEROS_CPP
#ifdef HOB_KERBEROS_CPP
//#define TEST_HOB_KERBEROS_CPP
#if defined TEST_HOB_KERBEROS_CPP
//#define TEST_ACTIVE_DIRECTORY
#endif
#else
//#define TEST_HOB_KERBEROS_C
#if defined TEST_HOB_KERBEROS_C
//#define TEST_ACTIVE_DIRECTORY
#endif
#endif

#if !defined WITHOUT_FILE || defined TEST_HOB_KERBEROS_C || defined TEST_HOB_KERBEROS_CPP
#define PATH_CCACHE "F:/Friedrich/Documents/My Documents/Kerberos/krb5cc_0"
#else
#define PATH_CCACHE ""
#endif
#ifndef __cplusplus

#ifdef _WIN32
#define __extension__
#define __value value
#define inline __inline
#define _export
#define _stdcall
#define _WINT_T
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct dsd_config_tgt {
    char * ach_princi_name;
    char * ach_passwd;
    char * ach_default_realm;
    char * ach_server;
    void * a_kdc_ip_address;
    int im_kdc_port;
    int im_ticket_life;
    int im_renew_life;
    int im_start_time;
    int im_max_retries;
    int im_fcache_version;
    int im_max_skew;
    int im_max_ticket_size;
#ifdef WITHOUT_FILE
    void * a_tgt;
    int im_length_tgt;
#endif
    void ** aa_memory_area;
    void ** aa_temp_memory_area;
    void * a_tracer;
    int in_trace_lvl;
    void * a_ip_address_context;
    int im_timeout;
};

struct dsd_config_ticket {
    char * ach_default_realm;
    char * ach_server;
    void * a_kdc_ip_address;
    int im_kdc_port;
    int im_ticket_life;
    int im_max_retries;
    int im_fcache_version;
    int im_max_skew;
    int im_max_ticket_size;
#ifdef WITHOUT_FILE
    void * a_tgt;
    int im_length_tgt;
#endif
    void ** aa_memory_area;
    void ** aa_temp_memory_area;
    void * a_tracer;
    int in_trace_lvl;
    void * a_ip_address_context;
    int im_timeout;
};

enum e_krb5_flags {
    AP_OPTS_MUTUAL_REQUIRED_e    = 1,
    NO_AP_OPTS_MUTUAL_REQUIRED_e = 2,
};
typedef enum e_krb5_flags e_krb5_flags;

struct dsd_config_client {
    int im_fcache_version;
#ifdef WITHOUT_FILE
    void * a_tgt;
    int im_length_tgt;
#endif
};
struct dsd_config_server_client {
    int im_max_skew;
    const char *ach_default_realm;
    char *ach_hostname;
    char *ach_service;
    const char **aach_additional_hostnames;
    int im_number_add_names;
    char ch_bool;
    void * a_ip_address_context;
    void ** aa_memory_area;
    void ** aa_temp_memory_area;
    void * a_tracer;
    int in_trace_lvl;
};

struct dsd_heimdal_context {
    void * ads_context;
    void * ads_auth_context;
    char *ach_hostname;
    char *ach_service;
    krb5_data  ds_data_init_in;
    krb5_data  ds_data_init_out;
    int im_switch;
    void * NAME_OF_MAIN_LOC_GLOB_P;
    void * a_gen_ptr;
};

struct dsd_config_server {
    int inc_max_skew;
    char* achc_keytab;
    int inc_keytab_len;
    krb5_data * adsc_in_data;
    krb5_data ** aadsc_out_data;
    void ** aa_temp_memory_area;
    void ** aa_memory_area;
    void * a_tracer;
    int in_trace_lvl;
    void* a_ip_address_context;
};



#ifdef __cplusplus
}
#endif
#endif
