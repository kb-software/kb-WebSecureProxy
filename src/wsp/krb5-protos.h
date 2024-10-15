/*_JF_Die Datei C:/Kerberos/auto_analyse_log_TGT/dateien/header/krb5-protos.h wurde automatisch veraendert! Phase 7*/

#ifndef __krb5_protos_h__
#define __krb5_protos_h__
#ifdef _WIN32
#pragma once
#endif
#include "krb5-types.h"
#include "krb5.h"

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(x)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KRB5_LIB_FUNCTION
#if defined(_WIN32)
#define KRB5_LIB_FUNCTION _stdcall
#else
#define KRB5_LIB_FUNCTION
#endif
#endif

    krb5_error_code KRB5_LIB_FUNCTION
    krb524_convert_creds_kdc(
        krb5_context ,
        krb5_creds *,
        struct credentials * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb524_convert_creds_kdc_ccache(
        krb5_context ,
        krb5_ccache ,
        krb5_creds *,
        struct credentials * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_425_conv_principal(
        krb5_context ,
        const char *,
        const char *,
        const char *,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_425_conv_principal_ext(
        krb5_context ,
        const char *,
        const char *,
        const char *,
        krb5_boolean( * )(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context, krb5_principal ),
        krb5_boolean ,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_524_conv_principal(
        krb5_context ,
        const krb5_principal ,
        char *,
        char *,
        char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_abort(
        krb5_context ,
        krb5_error_code ,
        const char *,
        ... )
    __attribute__(( noreturn, format( printf, 3, 4 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_abortx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                 const char * );
    krb5_error_code KRB5_LIB_FUNCTION
    krb5_acl_match_file(
        krb5_context ,
        const char *,
        const char *,
        ... );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_acl_match_string(
        krb5_context ,
        const char *,
        const char *,
        ... );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_add_et_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      void ( * )(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list ** ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_add_extra_addresses(
        krb5_context ,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_add_ignore_addresses(
        krb5_context ,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_addlog_dest(
        krb5_context ,
        krb5_log_facility *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_addlog_func(
        krb5_context ,
        krb5_log_facility *,
        int ,
        int ,
        krb5_log_log_func_t ,
        krb5_log_close_func_t ,
        void * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_address_compare(
        krb5_context ,
        const krb5_address *,
        const krb5_address * );

    int KRB5_LIB_FUNCTION
    krb5_address_order(
        krb5_context ,
        const krb5_address *,
        const krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_address_prefixlen_boundary(
        krb5_context ,
        const krb5_address *,
        unsigned long ,
        krb5_address *,
        krb5_address * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_address_search(
        krb5_context ,
        const krb5_address *,
        const krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_aname_to_localname(
        krb5_context ,
        krb5_const_principal ,
        size_t ,
        char * );

    void KRB5_LIB_FUNCTION
    krb5_appdefault_boolean(
        krb5_context ,
        const char *,
        krb5_const_realm ,
        const char *,
        krb5_boolean ,
        krb5_boolean * );

    void KRB5_LIB_FUNCTION
    krb5_appdefault_string(
        krb5_context ,
        const char *,
        krb5_const_realm ,
        const char *,
        const char *,
        char ** );

    void KRB5_LIB_FUNCTION
    krb5_appdefault_time(
        krb5_context ,
        const char *,
        krb5_const_realm ,
        const char *,
        time_t ,
        time_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_append_addresses(
        krb5_context ,
        krb5_addresses *,
        const krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_addflags(
        krb5_context ,
        krb5_auth_context ,
        int32_t ,
        int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_auth_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_genaddrs(
        krb5_context ,
        krb5_auth_context ,
        int ,
        int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_generatelocalsubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                       krb5_auth_context ,
                                       krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getaddrs(
        krb5_context ,
        krb5_auth_context ,
        krb5_address **,
        krb5_address ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getauthenticator(
        krb5_context ,
        krb5_auth_context ,
        krb5_authenticator * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getcksumtype(
        krb5_context ,
        krb5_auth_context ,
        krb5_cksumtype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getflags(
        krb5_context ,
        krb5_auth_context ,
        int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_auth_context ,
                          krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getkeytype(
        krb5_context ,
        krb5_auth_context ,
        krb5_keytype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getlocalseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                     krb5_auth_context ,
                                     int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getlocalsubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                  krb5_auth_context ,
                                  krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getrcache(
        krb5_context ,
        krb5_auth_context ,
        krb5_rcache * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_getremotesubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_auth_context ,
                                   krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_auth_context * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_removeflags(
        krb5_context ,
        krb5_auth_context ,
        int32_t ,
        int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setaddrs(
        krb5_context ,
        krb5_auth_context ,
        krb5_address *,
        krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setaddrs_from_fd(
        krb5_context ,
        krb5_auth_context ,
        void * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setcksumtype(
        krb5_context ,
        krb5_auth_context ,
        krb5_cksumtype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setflags(
        krb5_context ,
        krb5_auth_context ,
        int32_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setkey(
        krb5_context ,
        krb5_auth_context ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setkeytype(
        krb5_context ,
        krb5_auth_context ,
        krb5_keytype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setlocalseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                     krb5_auth_context ,
                                     int32_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setlocalsubkey(
        krb5_context ,
        krb5_auth_context ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setrcache(
        krb5_context ,
        krb5_auth_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setremoteseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                      krb5_auth_context ,
                                      int32_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setremotesubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_auth_context ,
                                   krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_con_setuserkey(
        krb5_context ,
        krb5_auth_context ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_auth_getremoteseqnumber(
        krb5_context ,
        krb5_auth_context ,
        int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_enctype ,
                       krb5_creds *,
                       krb5_flags ,
                       krb5_data ,
                       krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              krb5_auth_context ,
                              krb5_enctype ,
                              krb5_creds *,
                              Checksum *,
                              Authenticator **,
                              krb5_data *,
                              krb5_key_usage );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_principal(
        krb5_context ,
        krb5_principal *,
        int ,
        krb5_const_realm ,
        const char *,
        const char * );
    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_principal_ext(
        krb5_context ,
        krb5_principal *,
        int ,
        krb5_const_realm ,
        ... );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_principal_va( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_principal *,
                             int ,
                             krb5_const_realm ,
                             const char *,
                             const char * );
    krb5_error_code KRB5_LIB_FUNCTION
    krb5_build_principal_va_ext(
        krb5_context ,
        krb5_principal *,
        int ,
        krb5_const_realm ,
        va_list );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_block_size(
        krb5_context ,
        krb5_enctype ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_checksum_length(
        krb5_context ,
        krb5_cksumtype ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_decrypt(
        krb5_context ,
        const krb5_keyblock ,
        krb5_keyusage ,
        const krb5_data *,
        krb5_enc_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_encrypt(
        krb5_context ,
        const krb5_keyblock *,
        krb5_keyusage ,
        const krb5_data *,
        const krb5_data *,
        krb5_enc_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_encrypt_length(
        krb5_context ,
        krb5_enctype ,
        size_t ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_enctype_compare(
        krb5_context ,
        krb5_enctype ,
        krb5_enctype ,
        krb5_boolean * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_get_checksum(
        krb5_context ,
        const krb5_checksum *,
        krb5_cksumtype *,
        krb5_data ** );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_c_is_coll_proof_cksum( krb5_cksumtype );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_c_is_keyed_cksum( krb5_cksumtype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_make_checksum(
        krb5_context ,
        krb5_cksumtype ,
        const krb5_keyblock *,
        krb5_keyusage ,
        const krb5_data *,
        krb5_checksum * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_make_random_key(
        krb5_context ,
        krb5_enctype ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_set_checksum(
        krb5_context ,
        krb5_checksum *,
        krb5_cksumtype ,
        const krb5_data * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_c_valid_cksumtype( krb5_cksumtype );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_c_valid_enctype( krb5_enctype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_c_verify_checksum(
        krb5_context ,
        const krb5_keyblock *,
        krb5_keyusage ,
        const krb5_data *,
        const krb5_checksum *,
        krb5_boolean * );

    void KRB5_LIB_FUNCTION
    krb5_cc_clear_mcred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_close( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                   krb5_ccache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_copy_cache(
        krb5_context ,
        const krb5_ccache ,
        krb5_ccache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_copy_cache_match(
        krb5_context ,
        const krb5_ccache ,
        krb5_ccache ,
        krb5_flags ,
        const krb5_creds * ,
        unsigned int * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_default(
        krb5_context ,
        krb5_ccache * );

    const char* KRB5_LIB_FUNCTION
    krb5_cc_default_name( krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_destroy(
        krb5_context ,
        krb5_ccache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_end_seq_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         const krb5_ccache ,
                         krb5_cc_cursor * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_gen_new(
        krb5_context ,
        const krb5_cc_ops *,
        krb5_ccache * );

    const char* KRB5_LIB_FUNCTION
    krb5_cc_get_name(
        krb5_context ,
        krb5_ccache );

    const krb5_cc_ops *
    krb5_cc_get_ops(
        krb5_context ,
        krb5_ccache );

    const krb5_cc_ops *
    krb5_cc_get_prefix_ops(
        krb5_context ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_get_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                           krb5_ccache ,
                           krb5_principal * );

    const char* KRB5_LIB_FUNCTION
    krb5_cc_get_type(
        krb5_context ,
        krb5_ccache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_get_version(
        krb5_context ,
        const krb5_ccache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_initialize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_ccache ,
                        krb5_principal );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_new_unique(
        krb5_context ,
        const char *,
        const char *,
        krb5_ccache * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_next_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       const krb5_ccache ,
                       krb5_cc_cursor *,
                       krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_next_cred_match(
        krb5_context ,
        const krb5_ccache ,
        krb5_cc_cursor * ,
        krb5_creds * ,
        krb5_flags ,
        const krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_register(
        krb5_context ,
        const krb5_cc_ops *,
        krb5_boolean );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_remove_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_ccache ,
                         krb5_flags ,
                         krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_resolve( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     const char *,
                     krb5_ccache * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_retrieve_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                           krb5_ccache ,
                           krb5_flags ,
                           const krb5_creds *,
                           krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_set_default_name(
        krb5_context ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_set_flags(
        krb5_context ,
        krb5_ccache ,
        krb5_flags );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_start_seq_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                           const krb5_ccache ,
                           krb5_cc_cursor * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cc_store_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_ccache ,
                        krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_change_password(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
        krb5_context ,
        krb5_creds *,
        char *,
        int *,
        krb5_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_check_transited(
        krb5_context ,
        krb5_const_realm ,
        krb5_const_realm ,
        krb5_realm *,
        int ,
        int * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_check_transited_realms(
        krb5_context ,
        const char *const *,
        int ,
        int * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_checksum_disable(
        krb5_context ,
        krb5_cksumtype );

    void KRB5_LIB_FUNCTION
    krb5_checksum_free(
        krb5_context ,
        krb5_checksum * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_checksum_is_collision_proof( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                      krb5_cksumtype );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_checksum_is_keyed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            krb5_cksumtype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_checksumsize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_cksumtype ,
                       size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_cksumtype_valid(
        krb5_context ,
        krb5_cksumtype );

    void KRB5_LIB_FUNCTION
    krb5_clear_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_closelog(
        krb5_context ,
        krb5_log_facility * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_compare_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_flags ,
                        const krb5_creds * ,
                        const krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_config_file_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                           krb5_config_section * );

    void KRB5_LIB_FUNCTION
    krb5_config_free_strings( char ** );

    const void *
    krb5_config_get(
        krb5_context ,
        const krb5_config_section *,
        int ,
        ... );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_config_get_bool(
        krb5_context ,
        const krb5_config_section *,
        ... );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_config_get_bool_default(
        krb5_context ,
        const krb5_config_section *,
        krb5_boolean ,
        ... );

    int KRB5_LIB_FUNCTION
    krb5_config_get_int(
        krb5_context ,
        const krb5_config_section *,
        ... );

    int KRB5_LIB_FUNCTION
    krb5_config_get_int_default(
        krb5_context ,
        const krb5_config_section *,
        int ,
        ... );

    const krb5_config_binding *
    krb5_config_get_list(
        krb5_context ,
        const krb5_config_section *,
        ... );

    const void *
    krb5_config_get_next(
        krb5_context ,
        const krb5_config_section *,
        const krb5_config_binding **,
        int ,
        ... );

    const char* KRB5_LIB_FUNCTION
    krb5_config_get_string(
        krb5_context ,
        const krb5_config_section *,
        ... );

    const char* KRB5_LIB_FUNCTION
    krb5_config_get_string_default(
        krb5_context ,
        const krb5_config_section *,
        const char *,
        ... );

    char**
    krb5_config_get_strings(
        krb5_context ,
        const krb5_config_section *,
        ... );

    int KRB5_LIB_FUNCTION
    krb5_config_get_time(
        krb5_context ,
        const krb5_config_section *,
        ... );

    int KRB5_LIB_FUNCTION
    krb5_config_get_time_default(
        krb5_context ,
        const krb5_config_section *,
        int ,
        ... );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_config_parse_file(
        krb5_context ,
        const char *,
        krb5_config_section ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_config_parse_file_multi(
        krb5_context ,
        const char *,
        krb5_config_section ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_config_parse_string_multi(
        krb5_context ,
        const char *,
        krb5_config_section ** );

    const void *
    krb5_config_vget(
        krb5_context ,
        const krb5_config_section *,
        int ,
        va_list );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_config_vget_bool(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_config_vget_bool_default(
        krb5_context ,
        const krb5_config_section *,
        krb5_boolean ,
        va_list );

    int KRB5_LIB_FUNCTION
    krb5_config_vget_int(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    int KRB5_LIB_FUNCTION
    krb5_config_vget_int_default(
        krb5_context ,
        const krb5_config_section *,
        int ,
        va_list );

    const krb5_config_binding *
    krb5_config_vget_list(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    const void *
    krb5_config_vget_next(
        krb5_context ,
        const krb5_config_section *,
        const krb5_config_binding **,
        int ,
        va_list );

    const char* KRB5_LIB_FUNCTION
    krb5_config_vget_string(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    const char* KRB5_LIB_FUNCTION
    krb5_config_vget_string_default(
        krb5_context ,
        const krb5_config_section *,
        const char *,
        va_list );

    char ** KRB5_LIB_FUNCTION
    krb5_config_vget_strings(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    int KRB5_LIB_FUNCTION
    krb5_config_vget_time(
        krb5_context ,
        const krb5_config_section *,
        va_list );

    int KRB5_LIB_FUNCTION
    krb5_config_vget_time_default(
        krb5_context ,
        const krb5_config_section *,
        int ,
        va_list );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       const krb5_address *,
                       krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_addresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         const krb5_addresses *,
                         krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_checksum(
        krb5_context ,
        const krb5_checksum *,
        krb5_checksum ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     const krb5_creds *,
                     krb5_creds ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_creds_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              const krb5_creds *,
                              krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                    const krb5_data *,
                    krb5_data ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_host_realm(
        krb5_context ,
        const krb5_realm *,
        krb5_realm ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        const krb5_keyblock *,
                        krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_keyblock_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                 const krb5_keyblock *,
                                 krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_const_principal ,
                         krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_copy_ticket(
        krb5_context ,
        const krb5_ticket *,
        krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_create_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_crypto ,
                          krb5_key_usage ,
                          int ,
                          void *,
                          size_t ,
                          Checksum * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_destroy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_crypto );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_get_checksum_type( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_crypto ,
                                   krb5_cksumtype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_get_params(
        krb5_context ,
        const krb5_crypto ,
        const krb5_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_getblocksize(
        krb5_context ,
        krb5_crypto ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_getconfoundersize(
        krb5_context ,
        krb5_crypto ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_getenctype(
        krb5_context ,
        krb5_crypto ,
        krb5_enctype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_getpadsize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            krb5_crypto ,
                            size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      const krb5_keyblock *,
                      krb5_enctype ,
                      krb5_crypto * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_crypto_set_params(
        krb5_context ,
        const krb5_crypto ,
        const krb5_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_data_alloc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *,
                     int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_data_copy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *,
                    const void *,
                    size_t );

    void KRB5_LIB_FUNCTION
    krb5_data_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_data_realloc(
        krb5_data *,
        int );

    void KRB5_LIB_FUNCTION
    krb5_data_zero( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                               const void *,
                               size_t ,
                               Authenticator *,
                               size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_ETYPE_INFO(
        krb5_context ,
        const void *,
        size_t ,
        ETYPE_INFO *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_ETYPE_INFO2(
        krb5_context ,
        const void *,
        size_t ,
        ETYPE_INFO2 *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              const void *,
                              size_t ,
                              EncAPRepPart *,
                              size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_EncASRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              const void *,
                              size_t ,
                              EncASRepPart *,
                              size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_EncKrbCredPart(
        krb5_context ,
        const void *,
        size_t ,
        EncKrbCredPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_EncTGSRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                               const void *,
                               size_t ,
                               EncTGSRepPart *,
                               size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_EncTicketPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                               const void *,
                               size_t ,
                               EncTicketPart *,
                               size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decode_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        const krb5_data *,
                        krb5_ap_req * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_crypto ,
                  unsigned ,
                  void *,
                  size_t ,
                  krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decrypt_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                krb5_crypto ,
                                unsigned ,
                                const EncryptedData *,
                                krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decrypt_ivec( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_crypto ,
                       unsigned ,
                       void *,
                       size_t ,
                       krb5_data *,
                       void * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_decrypt_ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         Ticket *,
                         krb5_keyblock *,
                         EncTicketPart *,
                         krb5_flags );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_derive_key(
        krb5_context ,
        const krb5_keyblock *,
        krb5_enctype ,
        const void *,
        size_t ,
        krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_domain_x500_decode(
        krb5_context ,
        krb5_data ,
        char ***,
        int *,
        const char *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_domain_x500_encode(
        char **,
        int ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_eai_to_heim_errno(
        int ,
        int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_Authenticator(
        krb5_context ,
        void *,
        size_t ,
        Authenticator *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_ETYPE_INFO(
        krb5_context ,
        void *,
        size_t ,
        ETYPE_INFO *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_ETYPE_INFO2(
        krb5_context ,
        void *,
        size_t ,
        ETYPE_INFO2 *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_EncAPRepPart(
        krb5_context ,
        void *,
        size_t ,
        EncAPRepPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_EncASRepPart(
        krb5_context ,
        void *,
        size_t ,
        EncASRepPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_EncKrbCredPart(
        krb5_context ,
        void *,
        size_t ,
        EncKrbCredPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_EncTGSRepPart(
        krb5_context ,
        void *,
        size_t ,
        EncTGSRepPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encode_EncTicketPart(
        krb5_context ,
        void *,
        size_t ,
        EncTicketPart *,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_crypto ,
                  unsigned ,
                  void *,
                  size_t ,
                  krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encrypt_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                krb5_crypto ,
                                unsigned ,
                                void *,
                                size_t ,
                                int ,
                                EncryptedData * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_encrypt_ivec( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_crypto ,
                       unsigned ,
                       void *,
                       size_t ,
                       krb5_data *,
                       void * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_disable(
        krb5_context ,
        krb5_enctype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_keysize(
        krb5_context ,
        krb5_enctype ,
        size_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_to_keytype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_enctype ,
                             krb5_keytype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_to_oid(
        krb5_context ,
        krb5_enctype ,
        heim_oid * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_to_string(
        krb5_context ,
        krb5_enctype ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_enctype_valid( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_enctype );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_enctypes_compatible_keys( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_enctype ,
                                   krb5_enctype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_err( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
              int ,
              krb5_error_code ,
              const char * );
    krb5_error_code KRB5_LIB_FUNCTION
    krb5_error_from_rd_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              const krb5_error *,
                              const krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_errx(
        krb5_context ,
        int ,
        const char *,
        ... )
    __attribute__(( noreturn, format( printf, 3, 4 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_expand_hostname(
        krb5_context ,
        const char *,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_expand_hostname_realms(
        krb5_context ,
        const char *,
        char **,
        char *** );

    PA_DATA *
    krb5_find_padata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PA_DATA *,
                      unsigned ,
                      int ,
                      int * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_format_time(
        krb5_context ,
        time_t ,
        char *,
        size_t ,
        krb5_boolean );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_addresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_addresses * );

    void KRB5_LIB_FUNCTION
    krb5_free_ap_rep_enc_part( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                               krb5_ap_rep_enc_part * );

    void KRB5_LIB_FUNCTION
    krb5_free_authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_authenticator * );

    void KRB5_LIB_FUNCTION
    krb5_free_checksum(
        krb5_context ,
        krb5_checksum * );

    void KRB5_LIB_FUNCTION
    krb5_free_checksum_contents(
        krb5_context ,
        krb5_checksum * );

    void KRB5_LIB_FUNCTION
    krb5_free_config_files( char ** );

    void KRB5_LIB_FUNCTION
    krb5_free_context( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_cred_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_creds_contents(
        krb5_context ,
        krb5_creds * );

    void KRB5_LIB_FUNCTION
    krb5_free_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                    krb5_data * );

    void KRB5_LIB_FUNCTION
    krb5_free_data_contents(
        krb5_context ,
        krb5_data * );

    void KRB5_LIB_FUNCTION
    krb5_free_error(
        krb5_context ,
        krb5_error * );

    void KRB5_LIB_FUNCTION
    krb5_free_error_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              krb5_error * );

    void KRB5_LIB_FUNCTION
    krb5_free_error_string(
        krb5_context ,
        char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_host_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_realm * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_kdc_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_kdc_rep * );

    void KRB5_LIB_FUNCTION
    krb5_free_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_keyblock * );

    void KRB5_LIB_FUNCTION
    krb5_free_keyblock_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                 krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_krbhst(
        krb5_context ,
        char ** );

    void KRB5_LIB_FUNCTION
    krb5_free_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_principal );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                    krb5_salt );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_free_ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      krb5_ticket * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_fwd_tgt_creds(
        krb5_context ,
        krb5_auth_context ,
        const char *,
        krb5_principal ,
        krb5_principal ,
        krb5_ccache ,
        int ,
        krb5_data * );

    void KRB5_LIB_FUNCTION
    krb5_generate_random_block( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *,
                                size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_generate_random_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_enctype ,
                                   krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_generate_seq_number( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              const krb5_keyblock *,
                              u_int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_generate_subkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          const krb5_keyblock *,
                          krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_generate_subkey_extended( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   const krb5_keyblock *,
                                   krb5_enctype ,
                                   krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_all_client_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                               krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_all_server_addrs(
        krb5_context ,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_cred_from_kdc(
        krb5_context ,
        krb5_ccache ,
        krb5_creds *,
        krb5_creds **,
        krb5_creds *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_cred_from_kdc_opt(
        krb5_context ,
        krb5_ccache ,
        krb5_creds *,
        krb5_creds **,
        krb5_creds ***,
        krb5_flags );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_credentials( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_flags ,
                          krb5_ccache ,
                          krb5_creds *,
                          krb5_creds ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_credentials_with_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                     krb5_flags ,
                                     krb5_kdc_flags ,
                                     krb5_ccache ,
                                     krb5_creds *,
                                     krb5_creds ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_default_config_files( char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_default_in_tkt_etypes( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                    krb5_enctype ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_default_principal(
        krb5_context ,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_default_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            krb5_realm * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_default_realms(
        krb5_context ,
        krb5_realm ** );

    const char* KRB5_LIB_FUNCTION
    krb5_get_err_text( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_error_code );

    char * KRB5_LIB_FUNCTION
    krb5_get_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_extra_addresses(
        krb5_context ,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_fcache_version(
        krb5_context ,
        int * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_forwarded_creds(
        krb5_context ,
        krb5_auth_context ,
        krb5_ccache ,
        krb5_flags ,
        const char *,
        krb5_creds *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_host_realm(
        krb5_context ,
        const char *,
        krb5_realm ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_ignore_addresses(
        krb5_context ,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_in_cred(
        krb5_context ,
        krb5_flags ,
        const krb5_addresses *,
        const krb5_enctype *,
        const krb5_preauthtype *,
        const krb5_preauthdata *,
        krb5_key_proc ,
        krb5_const_pointer ,
        krb5_decrypt_proc ,
        krb5_const_pointer ,
        krb5_creds *,
        krb5_kdc_rep * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_in_tkt(
        krb5_context ,
        krb5_flags ,
        const krb5_addresses *,
        const krb5_enctype *,
        const krb5_preauthtype *,
        krb5_key_proc ,
        krb5_const_pointer ,
        krb5_decrypt_proc ,
        krb5_const_pointer ,
        krb5_creds *,
        krb5_ccache ,
        krb5_kdc_rep * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_in_tkt_with_keytab(
        krb5_context ,
        krb5_flags ,
        krb5_addresses *,
        const krb5_enctype *,
        const krb5_preauthtype *,
        krb5_keytab ,
        krb5_ccache ,
        krb5_creds *,
        krb5_kdc_rep * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_in_tkt_with_password(
        krb5_context ,
        krb5_flags ,
        krb5_addresses *,
        const krb5_enctype *,
        const krb5_preauthtype *,
        const char *,
        krb5_ccache ,
        krb5_creds *,
        krb5_kdc_rep * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_in_tkt_with_skey(
        krb5_context ,
        krb5_flags ,
        krb5_addresses *,
        const krb5_enctype *,
        const krb5_preauthtype *,
        const krb5_keyblock *,
        krb5_ccache ,
        krb5_creds *,
        krb5_kdc_rep * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_creds *,
                         krb5_principal ,
                         krb5_prompter_fct ,
                         void *,
                         krb5_deltat ,
                         const char *,
                         krb5_get_init_creds_opt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_keyblock(
        krb5_context ,
        krb5_creds *,
        krb5_principal ,
        krb5_keyblock *,
        krb5_deltat ,
        const char *,
        krb5_get_init_creds_opt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_keytab(
        krb5_context ,
        krb5_creds *,
        krb5_principal ,
        krb5_keytab ,
        krb5_deltat ,
        const char *,
        krb5_get_init_creds_opt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_alloc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                   krb5_get_init_creds_opt ** );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_address_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
            krb5_addresses * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_anonymous( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
                                           int );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_default_flags(
        krb5_context ,
        const char *,
        krb5_const_realm ,
        krb5_get_init_creds_opt * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_etype_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
                                            krb5_enctype *,
                                            int );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_forwardable( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
            int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_pa_password( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
            krb5_get_init_creds_opt *,
            const char *,
            krb5_s2k_proc );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_pac_request(
        krb5_context ,
        krb5_get_init_creds_opt *,
        krb5_boolean );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_pkinit(
        krb5_context ,
        krb5_get_init_creds_opt *,
        krb5_principal ,
        const char *,
        const char *,
        int ,
        krb5_prompter_fct ,
        void *,
        char * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_preauth_list(
        krb5_get_init_creds_opt *,
        krb5_preauthtype *,
        int );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_proxiable( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
                                           int );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_renew_life( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
                                            krb5_deltat );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_salt(
        krb5_get_init_creds_opt *,
        krb5_data * );

    void KRB5_LIB_FUNCTION
    krb5_get_init_creds_opt_set_tkt_life( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *,
                                          krb5_deltat );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_init_creds_password( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                  krb5_creds *,
                                  krb5_principal ,
                                  const char *,
                                  krb5_prompter_fct ,
                                  void *,
                                  krb5_deltat ,
                                  const char *,
                                  krb5_get_init_creds_opt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_kdc_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_ccache ,
                       krb5_kdc_flags ,
                       krb5_addresses *,
                       Ticket *,
                       krb5_creds *,
                       krb5_creds **out_creds );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_krb524hst(
        krb5_context ,
        const krb5_realm *,
        char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_krb_admin_hst(
        krb5_context ,
        const krb5_realm *,
        char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_krb_changepw_hst(
        krb5_context ,
        const krb5_realm *,
        char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_krbhst(
        krb5_context ,
        const krb5_realm *,
        char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_pw_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      krb5_const_principal ,
                      krb5_salt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_get_server_rcache(
        krb5_context ,
        const krb5_data *,
        krb5_rcache * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_get_use_admin_kdc( krb5_context );

    size_t
    krb5_get_wrapped_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_crypto ,
                             size_t );

    int KRB5_LIB_FUNCTION
    krb5_getportbyname(
        krb5_context ,
        const char *,
        const char *,
        int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_h_addr2addr(
        krb5_context ,
        int ,
        const char *,
        krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_h_errno_to_heim_errno( int );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_have_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_hmac( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
               krb5_cksumtype ,
               const void *,
               size_t ,
               unsigned ,
               krb5_keyblock *,
               Checksum * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_init_context( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context * );

    void KRB5_LIB_FUNCTION
    krb5_init_ets( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_init_etype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     unsigned *,
                     krb5_enctype **,
                     const krb5_enctype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_initlog(
        krb5_context ,
        const char *,
        krb5_log_facility ** );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_is_thread_safe( void );

    krb5_enctype
    krb5_keyblock_get_enctype( const krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keyblock_init(
        krb5_context ,
        krb5_enctype ,
        const void *,
        size_t ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keyblock_key_proc(
        krb5_context ,
        krb5_keytype ,
        krb5_data *,
        krb5_const_pointer ,
        krb5_keyblock ** );

    void KRB5_LIB_FUNCTION
    krb5_keyblock_zero( krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keytab_key_proc(
        krb5_context ,
        krb5_enctype ,
        krb5_salt ,
        krb5_const_pointer ,
        krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keytype_to_enctypes(
        krb5_context ,
        krb5_keytype ,
        unsigned *,
        krb5_enctype ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keytype_to_enctypes_default(
        krb5_context ,
        krb5_keytype ,
        unsigned *,
        krb5_enctype ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_keytype_to_string(
        krb5_context ,
        krb5_keytype ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_format_string(
        krb5_context ,
        const krb5_krbhst_info *,
        char *,
        size_t );

    void KRB5_LIB_FUNCTION
    krb5_krbhst_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      krb5_krbhst_handle );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_get_addrinfo(
        krb5_context ,
        krb5_krbhst_info *,
        struct addrinfo ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_init(
        krb5_context ,
        const char *,
        unsigned int ,
        krb5_krbhst_handle * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_init_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            const char *,
                            unsigned int ,
                            int ,
                            krb5_krbhst_handle * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_next(
        krb5_context ,
        krb5_krbhst_handle ,
        krb5_krbhst_info ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_krbhst_next_as_string(
        krb5_context ,
        krb5_krbhst_handle ,
        char *,
        size_t );

    void KRB5_LIB_FUNCTION
    krb5_krbhst_reset(
        krb5_context ,
        krb5_krbhst_handle );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_add_entry(
        krb5_context ,
        krb5_keytab ,
        krb5_keytab_entry * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_close(
        krb5_context ,
        krb5_keytab );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_kt_compare(
        krb5_context ,
        krb5_keytab_entry *,
        krb5_const_principal ,
        krb5_kvno ,
        krb5_enctype );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_copy_entry_contents(
        krb5_context ,
        const krb5_keytab_entry *,
        krb5_keytab_entry * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_default(
        krb5_context ,
        krb5_keytab * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_default_modify_name(
        krb5_context ,
        char *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_default_name(
        krb5_context ,
        char *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_end_seq_get(
        krb5_context ,
        krb5_keytab ,
        krb5_kt_cursor * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_free_entry( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_keytab_entry * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_get_entry( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_keytab ,
                       krb5_const_principal ,
                       krb5_kvno ,
                       krb5_enctype ,
                       krb5_keytab_entry * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_get_name(
        krb5_context ,
        krb5_keytab ,
        char *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_get_type(
        krb5_context ,
        krb5_keytab ,
        char *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_next_entry(
        krb5_context ,
        krb5_keytab ,
        krb5_keytab_entry *,
        krb5_kt_cursor * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_read_service_key(
        krb5_context ,
        krb5_pointer ,
        krb5_principal ,
        krb5_kvno ,
        krb5_enctype ,
        krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_register(
        krb5_context ,
        const krb5_kt_ops * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_remove_entry(
        krb5_context ,
        krb5_keytab ,
        krb5_keytab_entry * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_resolve(
        krb5_context ,
        const char *,
        krb5_keytab * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_kt_start_seq_get(
        krb5_context ,
        krb5_keytab ,
        krb5_kt_cursor * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_kuserok(
        krb5_context ,
        krb5_principal ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_log(
        krb5_context ,
        krb5_log_facility *,
        int ,
        const char *,
        ... )
    __attribute__(( format( printf, 4, 5 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_log_msg(
        krb5_context ,
        krb5_log_facility *,
        int ,
        char **,
        const char *,
        ... )
    __attribute__(( format( printf, 5, 6 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_make_addrport(
        krb5_context ,
        krb5_address **,
        const krb5_address *,
        int16_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_make_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_principal *,
                         krb5_const_realm ,
                         const char *,
                         const char * );
    size_t KRB5_LIB_FUNCTION
    krb5_max_sockaddr_size( void );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                   krb5_error_code ,
                   const char *,
                   const krb5_data *,
                   const krb5_principal ,
                   const krb5_principal ,
                   time_t *,
                   int *,
                   krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_priv( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_auth_context ,
                  const krb5_data *,
                  krb5_data *,
                  krb5_replay_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                 krb5_auth_context ,
                 krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_req(
        krb5_context ,
        krb5_auth_context *,
        const krb5_flags ,
        const char *,
        const char *,
        krb5_data *,
        krb5_ccache ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_req_exact(
        krb5_context ,
        krb5_auth_context *,
        const krb5_flags ,
        const krb5_principal ,
        krb5_data *,
        krb5_ccache ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_req_extended( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_auth_context *,
                          const krb5_flags ,
                          krb5_data *,
                          krb5_creds *,
                          krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_mk_safe( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_auth_context ,
                  const krb5_data *,
                  krb5_data *,
                  krb5_replay_data * );

    krb5_ssize_t KRB5_LIB_FUNCTION
    krb5_net_read(
        krb5_context ,
        void *,
        void *,
        size_t );

    krb5_ssize_t KRB5_LIB_FUNCTION
    krb5_net_write(
        krb5_context ,
        void *,
        const void *,
        size_t );

    krb5_ssize_t KRB5_LIB_FUNCTION
    krb5_net_write_block(
        krb5_context ,
        void *,
        const void *,
        size_t ,
        time_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_openlog(
        krb5_context ,
        const char *,
        krb5_log_facility ** );

    int KRB5_LIB_FUNCTION
    krb5_padata_add( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     METHOD_DATA *,
                     int ,
                     void *,
                     size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_parse_address(
        krb5_context ,
        const char *,
        krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_parse_name( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                     const char *,
                     krb5_principal * );

    const char* KRB5_LIB_FUNCTION
    krb5_passwd_result_to_string(
        krb5_context ,
        int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_password_key_proc(
        krb5_context ,
        krb5_enctype ,
        krb5_salt ,
        krb5_const_pointer ,
        krb5_keyblock ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_prepend_config_files(
        const char *,
        char **,
        char *** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_prepend_config_files_default(
        const char *,
        char *** );

    krb5_realm*
    krb5_princ_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                      krb5_principal );

    void KRB5_LIB_FUNCTION
    krb5_princ_set_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_principal ,
                          krb5_realm * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_principal_compare( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            krb5_const_principal ,
                            krb5_const_principal );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_principal_compare_any_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                      krb5_const_principal ,
                                      krb5_const_principal );

    const char* KRB5_LIB_FUNCTION
    krb5_principal_get_comp_string(
        krb5_context ,
        krb5_principal ,
        unsigned int );

    const char* KRB5_LIB_FUNCTION
    krb5_principal_get_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                              krb5_principal );

    int KRB5_LIB_FUNCTION
    krb5_principal_get_type(
        krb5_context ,
        krb5_principal );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_principal_match(
        krb5_context ,
        krb5_const_principal ,
        krb5_const_principal );

    void KRB5_LIB_FUNCTION
    krb5_principal_set_type(
        krb5_context ,
        krb5_principal ,
        int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_print_address(
        const krb5_address *,
        char *,
        size_t ,
        size_t * );

    int KRB5_LIB_FUNCTION
    krb5_program_setup(
        krb5_context *,
        int ,
        char **,
        struct getargs *,
        int ,
        void ( * )(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int, struct getargs*, int ) );

    int KRB5_LIB_FUNCTION
    krb5_prompter_posix(
        krb5_context ,
        void *,
        const char *,
        const char *,
        int ,
        krb5_prompt prompts[] );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_random_to_key(
        krb5_context ,
        krb5_enctype ,
        const void *,
        size_t ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_close(
        krb5_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_default(
        krb5_context ,
        krb5_rcache * );

    const char* KRB5_LIB_FUNCTION
    krb5_rc_default_name( krb5_context );

    const char* KRB5_LIB_FUNCTION
    krb5_rc_default_type( krb5_context );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_destroy(
        krb5_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_expunge(
        krb5_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_get_lifespan(
        krb5_context ,
        krb5_rcache ,
        krb5_deltat * );

    const char* KRB5_LIB_FUNCTION
    krb5_rc_get_name(
        krb5_context ,
        krb5_rcache );

    const char* KRB5_LIB_FUNCTION
    krb5_rc_get_type(
        krb5_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_initialize(
        krb5_context ,
        krb5_rcache ,
        krb5_deltat );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_recover(
        krb5_context ,
        krb5_rcache );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_resolve(
        krb5_context ,
        krb5_rcache ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_resolve_full(
        krb5_context ,
        krb5_rcache *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_resolve_type(
        krb5_context ,
        krb5_rcache *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rc_store(
        krb5_context ,
        krb5_rcache ,
        krb5_donot_replay * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_cred(
        krb5_context ,
        krb5_auth_context ,
        krb5_data *,
        krb5_creds ***,
        krb5_replay_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_cred2(
        krb5_context ,
        krb5_auth_context ,
        krb5_ccache ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                   krb5_data *,
                   KRB_ERROR * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_priv( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_auth_context ,
                  const krb5_data *,
                  krb5_data *,
                  krb5_replay_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                 krb5_auth_context ,
                 const krb5_data *,
                 krb5_ap_rep_enc_part ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                 krb5_auth_context *,
                 const krb5_data *,
                 krb5_const_principal ,
                 krb5_keytab ,
                 krb5_flags *,
                 krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_req_with_keyblock(
        krb5_context ,
        krb5_auth_context *,
        const krb5_data *,
        krb5_const_principal ,
        krb5_keyblock *,
        krb5_flags *,
        krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_rd_safe( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                  krb5_auth_context ,
                  const krb5_data *,
                  krb5_data *,
                  krb5_replay_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_read_message(
        krb5_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_read_priv_message(
        krb5_context ,
        krb5_auth_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_read_safe_message(
        krb5_context ,
        krb5_auth_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_realm_compare( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_const_principal ,
                        krb5_const_principal );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_recvauth(
        krb5_context ,
        krb5_auth_context *,
        krb5_pointer ,
        const char *,
        krb5_principal ,
        int32_t ,
        krb5_keytab ,
        krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_recvauth_match_version(
        krb5_context ,
        krb5_auth_context *,
        krb5_pointer ,
        krb5_boolean( * )(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const void *, const char* ),
        const void *,
        krb5_principal ,
        int32_t ,
        krb5_keytab ,
        krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                    krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_authdata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                       krb5_authdata * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                    krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_creds_tag(
        krb5_storage *,
        krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                   krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_int16( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                    int16_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_int32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                    int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_int8( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                   int8_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                       krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                     char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_stringz(
        krb5_storage *,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ret_times( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                    krb5_times * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_salttype_to_string(
        krb5_context ,
        krb5_enctype ,
        krb5_salttype ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sendauth(
        krb5_context ,
        krb5_auth_context *,
        krb5_pointer ,
        const char *,
        krb5_principal ,
        krb5_principal ,
        krb5_flags ,
        krb5_data *,
        krb5_creds *,
        krb5_ccache ,
        krb5_error **,
        krb5_ap_rep_enc_part **,
        krb5_creds ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sendto( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                 const krb5_data *,
                 krb5_krbhst_handle ,
                 krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sendto_kdc(
        krb5_context ,
        const krb5_data *,
        const krb5_realm *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sendto_kdc_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                           const krb5_data *,
                           const krb5_realm *,
                           krb5_data *,
                           int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_config_files(
        krb5_context ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_default_in_tkt_etypes(
        krb5_context ,
        const krb5_enctype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_default_realm(
        krb5_context ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, const char *fmt, const char *file );
    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_extra_addresses(
        krb5_context ,
        const krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_fcache_version( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             int );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_ignore_addresses(
        krb5_context ,
        const krb5_addresses * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_password(
        krb5_context ,
        krb5_creds *,
        char *,
        krb5_principal ,
        int *,
        krb5_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_password_using_ccache(
        krb5_context ,
        krb5_ccache ,
        char *,
        krb5_principal ,
        int *,
        krb5_data *,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_real_time(
        krb5_context ,
        krb5_timestamp ,
        int32_t );

    void KRB5_LIB_FUNCTION
    krb5_set_use_admin_kdc(
        krb5_context ,
        krb5_boolean );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_set_warn_dest(
        krb5_context ,
        krb5_log_facility * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sname_to_principal(
        krb5_context ,
        const char *,
        const char *,
        int32_t ,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sock_to_principal(
        krb5_context ,
        int ,
        const char *,
        int32_t ,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sockaddr2address(
        krb5_context ,
        const struct sockaddr *,
        krb5_address * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_sockaddr2port(
        krb5_context ,
        const struct sockaddr *,
        int16_t * );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_sockaddr_uninteresting( const struct sockaddr * );

    void KRB5_LIB_FUNCTION
    krb5_std_usage(
        int ,
        struct getargs *,
        int );

    void KRB5_LIB_FUNCTION
    krb5_storage_clear_flags(
        krb5_storage *,
        krb5_flags );

    krb5_storage * KRB5_LIB_FUNCTION
    krb5_storage_emem( void );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_storage_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage * );

    krb5_storage * KRB5_LIB_FUNCTION
    krb5_storage_from_data( krb5_data * );

    krb5_storage * KRB5_LIB_FUNCTION
    krb5_storage_from_fd( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int );

    krb5_storage * KRB5_LIB_FUNCTION
    krb5_storage_from_mem(
        void *,
        size_t );

    krb5_flags KRB5_LIB_FUNCTION
    krb5_storage_get_byteorder(
        krb5_storage *,
        krb5_flags );

    krb5_boolean KRB5_LIB_FUNCTION
    krb5_storage_is_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                           krb5_flags );

    krb5_ssize_t KRB5_LIB_FUNCTION
    krb5_storage_read(
        krb5_storage *,
        void *,
        size_t );

    void KRB5_LIB_FUNCTION
    krb5_storage_set_byteorder(
        krb5_storage *,
        krb5_flags );

    void KRB5_LIB_FUNCTION
    krb5_storage_set_eof_code( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                               int );

    void KRB5_LIB_FUNCTION
    krb5_storage_set_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                            krb5_flags );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_storage_to_data(
        krb5_storage *,
        krb5_data * );

    krb5_ssize_t KRB5_LIB_FUNCTION
    krb5_storage_write(
        krb5_storage *,
        const void *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                        krb5_address );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      krb5_addresses );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_authdata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                         krb5_authdata );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_creds_tag(
        krb5_storage *,
        krb5_creds * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                     krb5_data );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_int16( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      int16_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_int32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      int32_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_int8( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                     int8_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                         krb5_keyblock );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                          krb5_principal );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                       const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_stringz(
        krb5_storage *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_store_times( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *,
                      krb5_times );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_deltat(
        const char *,
        krb5_deltat * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_enctype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                            const char *,
                            krb5_enctype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key(
        krb5_context ,
        krb5_enctype ,
        const char *,
        krb5_principal ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_data(
        krb5_context ,
        krb5_enctype ,
        krb5_data ,
        krb5_principal ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_data_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                  krb5_enctype ,
                                  krb5_data ,
                                  krb5_salt ,
                                  krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_data_salt_opaque( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                         krb5_enctype ,
                                         krb5_data ,
                                         krb5_salt ,
                                         krb5_data ,
                                         krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_derived( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                                const void *,
                                size_t ,
                                krb5_enctype ,
                                krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_enctype ,
                             const char *,
                             krb5_salt ,
                             krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_key_salt_opaque(
        krb5_context ,
        krb5_enctype ,
        const char *,
        krb5_salt ,
        krb5_data ,
        krb5_keyblock * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_keytype(
        krb5_context ,
        const char *,
        krb5_keytype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_string_to_salttype(
        krb5_context ,
        krb5_enctype ,
        const char *,
        krb5_salttype * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ticket_get_authorization_data_type(
        krb5_context ,
        krb5_ticket *,
        int ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ticket_get_client(
        krb5_context ,
        const krb5_ticket *,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_ticket_get_server(
        krb5_context ,
        const krb5_ticket *,
        krb5_principal * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_timeofday( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                    krb5_timestamp * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_unparse_name(
        krb5_context ,
        krb5_const_principal ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_unparse_name_fixed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                             krb5_const_principal ,
                             char *,
                             size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_unparse_name_fixed_short(
        krb5_context ,
        krb5_const_principal ,
        char *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_unparse_name_short(
        krb5_context ,
        krb5_const_principal ,
        char ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_us_timeofday( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                       krb5_timestamp *,
                       int32_t * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vabort(
        krb5_context ,
        krb5_error_code ,
        const char *,
        va_list )
    __attribute__(( noreturn, format( printf, 3, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vabortx(
        krb5_context ,
        const char *,
        va_list )
    __attribute__(( noreturn, format( printf, 2, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                        krb5_auth_context *,
                        krb5_ap_req *,
                        krb5_const_principal ,
                        krb5_keyblock *,
                        krb5_flags ,
                        krb5_flags *,
                        krb5_ticket ** );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_ap_req2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                         krb5_auth_context *,
                         krb5_ap_req *,
                         krb5_const_principal ,
                         krb5_keyblock *,
                         krb5_flags ,
                         krb5_flags *,
                         krb5_ticket **,
                         krb5_key_usage );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_authenticator_checksum(
        krb5_context ,
        krb5_auth_context ,
        void *,
        size_t );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context ,
                          krb5_crypto ,
                          krb5_key_usage ,
                          void *,
                          size_t ,
                          Checksum * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_init_creds(
        krb5_context ,
        krb5_creds *,
        krb5_principal ,
        krb5_keytab ,
        krb5_ccache *,
        krb5_verify_init_creds_opt * );

    void KRB5_LIB_FUNCTION
    krb5_verify_init_creds_opt_init( krb5_verify_init_creds_opt * );

    void KRB5_LIB_FUNCTION
    krb5_verify_init_creds_opt_set_ap_req_nofail(
        krb5_verify_init_creds_opt *,
        int );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_init( krb5_verify_opt * );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_set_ccache(
        krb5_verify_opt *,
        krb5_ccache );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_set_flags(
        krb5_verify_opt *,
        unsigned int );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_set_keytab(
        krb5_verify_opt *,
        krb5_keytab );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_set_secure(
        krb5_verify_opt *,
        krb5_boolean );

    void KRB5_LIB_FUNCTION
    krb5_verify_opt_set_service(
        krb5_verify_opt *,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_user(
        krb5_context ,
        krb5_principal ,
        krb5_ccache ,
        const char *,
        krb5_boolean ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_user_lrealm(
        krb5_context ,
        krb5_principal ,
        krb5_ccache ,
        const char *,
        krb5_boolean ,
        const char * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verify_user_opt(
        krb5_context ,
        krb5_principal ,
        const char *,
        krb5_verify_opt * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verr(
        krb5_context ,
        int ,
        krb5_error_code ,
        const char *,
        va_list )
    __attribute__(( noreturn, format( printf, 4, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_verrx(
        krb5_context ,
        int ,
        const char *,
        va_list )
    __attribute__(( noreturn, format( printf, 3, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vlog(
        krb5_context ,
        krb5_log_facility *,
        int ,
        const char *,
        va_list )
    __attribute__(( format( printf, 4, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vlog_msg(
        krb5_context ,
        krb5_log_facility *,
        char **,
        int ,
        const char *,
        va_list )
    __attribute__(( format( printf, 5, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vset_error_string(
        krb5_context ,
        const char *,
        va_list )
    __attribute__(( format( printf, 2, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vwarn(
        krb5_context ,
        krb5_error_code ,
        const char *,
        va_list )
    __attribute__(( format( printf, 3, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_vwarnx(
        krb5_context ,
        const char *,
        va_list )
    __attribute__(( format( printf, 2, 0 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_warn(
        krb5_context ,
        krb5_error_code ,
        const char *,
        ... )
    __attribute__(( format( printf, 3, 4 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_warnx(
        krb5_context ,
        const char *,
        ... )
    __attribute__(( format( printf, 2, 3 ) ) );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_write_message(
        krb5_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_write_priv_message(
        krb5_context ,
        krb5_auth_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_write_safe_message(
        krb5_context ,
        krb5_auth_context ,
        krb5_pointer ,
        krb5_data * );

    krb5_error_code KRB5_LIB_FUNCTION
    krb5_xfree( void * );
    
    krb5_error_code
    change_password (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
         krb5_context context,
		 krb5_principal client,
		 const char *password,
		 char *newpw,
		 size_t newpw_sz,
		 int inp_kdc_change_pw_port,
		 void *data,
		 krb5_get_init_creds_opt *old_options);

    krb5_error_code m_krb5_search_heimdal_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                krb5_context adsp_context,
                krb5_ap_req     *adsp_ap_req,
                krb5_const_principal   adsp_server,
                krb5_keyblock  **aadsp_keyblock);
             
    krb5_error_code m_krb5_search_AD_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                krb5_context adsp_context,
                krb5_ap_req     *adsp_ap_req,
                krb5_const_principal   adsp_server,
                krb5_keyblock  **aadsp_keyblock);
                
    static inline u_int16_t m_bswap16_init( u_int16_t unp_in );
    static inline u_int32_t m_bswap32_init( u_int32_t unp_in );

#ifdef __cplusplus
}
#endif

#endif
