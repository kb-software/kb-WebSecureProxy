#define HL_KRB5
#ifdef HL_UNIX
#include <stdarg.h>
#endif
#include <stddef.h>
#ifndef B160501
#ifndef HL_UNIX
#include <stdint.h>
#include <windows.h>
#endif
#endif
#ifdef HL_UNIX
#include <hob-unix01.h>
#endif
#include "hob-krb5-defines.h"
#include "hob-krb5-decl.h"
#include "kuser_locl.h"
#include "gssapi.h"
#include "gssapi_locl.h"
#include "krb5-protos.h"

#ifdef _WIN32
#define strncpy(dest, src, len) strncpy_s(dest, len, src, len)
#define strncat(dest, src, len) strncat_s(dest, len, src, len)
#endif

extern char* m_krb5_strcat( void ** aap_mem_addr,
                            char* achl_dest,
                            char* achl_src )
{
   size_t szl_total_len = strlen( achl_dest ) +strlen( achl_src )+1;
   achl_dest=m_aux_stor_realloc( aap_mem_addr, achl_dest, szl_total_len );
   strncat( achl_dest, achl_src, szl_total_len );
   return achl_dest;
}//char* m_krb5_strcat(void** aap_memory_ptr, char* achl_dest, char* achl_src);

void m_free_arrays_file_h_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P );
void m_aux_stor_start( void **aap_anchor );
void m_aux_stor_end( void **aap_anchor );
extern const char *krb5_error_strings[250];

static int m_init_enctypes( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                            krb5_context ads_context )
{
   krb5_error_code im_ret;
   struct getarg_strings ds_etype_str;
   ds_etype_str.num_strings = 7;
   ds_etype_str.strings = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
      ( 7 ) * ( sizeof( char* ) ) );

   ds_etype_str.strings[0] = "aes256-cts-hmac-sha1-96";
   ds_etype_str.strings[1] = "aes128-cts-hmac-sha1-96";
   ds_etype_str.strings[2] = "aes256-cbc-none";
   ds_etype_str.strings[3] = "aes192-cbc-none";
   ds_etype_str.strings[4] = "aes128-cbc-none";
   ds_etype_str.strings[5] = "arcfour-hmac-md5";
   ds_etype_str.strings[6] = "des3-cbc-sha1";
   if( ds_etype_str.num_strings ) {
      int i;
      ads_context->etypes = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
         ds_etype_str.num_strings * sizeof( *( ads_context->etypes ) ) );
      for( i = 0; i < ds_etype_str.num_strings; i++ ) {
         im_ret = krb5_string_to_enctype( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
            ds_etype_str.strings[i],
            &( ads_context->etypes )[i] );
         if( im_ret ) {
            //StSch Trace Point
            krb5_err( NAME_OF_MAIN_LOC_GLOB_P, ads_context, 1, im_ret,
               "init_krb5_context: unrecognized enctype" );
         }
      }
   }
   return ds_etype_str.num_strings;
}

void m_krb5_sha1( const void *data, size_t len, void *dest, void **aa_temp_memory )
{
    Checksum* ds_pw_cs=( Checksum* )m_aux_stor_alloc( aa_temp_memory, sizeof( Checksum ) );
    ds_pw_cs->cksumtype=CKSUMTYPE_SHA1;
    ds_pw_cs->checksum.data=dest;
    SHA1_checksum( NULL, NULL,
        NULL,
        data,
        len,
        0,
        ds_pw_cs );
    m_aux_stor_free( aa_temp_memory, ds_pw_cs );
}//void m_krb5_sha1(const void *data, size_t len, unsigned usage, Checksum *C );

static struct dsd_global_and_static m_init_dsd_global_and_static(
                                          void** aavop_temp_mem,
                                          void** aavop_mem,
                                          void* avop_tracer,
                                          int inp_trace_lvl,
                                          void* avop_addr_context)
{
   struct dsd_global_and_static dsl_struct;
   memset(&dsl_struct, 0, sizeof(struct dsd_global_and_static));

   dsl_struct.im_counter_array_free_posi = -1;
   dsl_struct._krb5_AES_string_to_default_iterator = 4096;
   dsl_struct.im_control_1 = 1;
   dsl_struct.im_control_2 = 1;
   dsl_struct.im_control_3 = 1;
   dsl_struct.im_control_4 = 1;
   dsl_struct.im_control_5 = 1;

   dsl_struct.aa_temp_memory_area = aavop_temp_mem;
   dsl_struct.aa_memory_area = aavop_mem;
   dsl_struct.a_tracer = avop_tracer;
   dsl_struct.in_trace_lvl = inp_trace_lvl;
   dsl_struct.a_ip_address_context = avop_addr_context;

   return dsl_struct;
}

static krb5_error_code
get_new_tickets( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_principal principal,
                krb5_ccache ccache,
                krb5_deltat ticket_life)
{
    krb5_error_code ret;
    krb5_get_init_creds_opt *opt;
    krb5_creds cred;
    int number;
    krb5_addresses no_addrs;
    memset( &cred, 0, sizeof( cred ) );
    ret = krb5_get_init_creds_opt_alloc( NAME_OF_MAIN_LOC_GLOB_P, context, &opt );
    if( ret ){
        return ret;
    }
    krb5_get_init_creds_opt_set_forwardable( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->forwardable_flag );
    krb5_get_init_creds_opt_set_proxiable( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->proxiable_flag );
    krb5_get_init_creds_opt_set_anonymous( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->anonymous_flag );
    no_addrs.len = 0;
    no_addrs.val = NULL;
    krb5_get_init_creds_opt_set_address_list( NAME_OF_MAIN_LOC_GLOB_P, opt,          &no_addrs );
    krb5_get_init_creds_opt_set_renew_life( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->renew_life );
    krb5_get_init_creds_opt_set_tkt_life( NAME_OF_MAIN_LOC_GLOB_P, opt,          ticket_life );
    number = m_init_enctypes( NAME_OF_MAIN_LOC_GLOB_P, context );
    krb5_get_init_creds_opt_set_etype_list( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->etypes, number );
    //StSch Trace Point 4001
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        struct dsd_memory_traces* adsl_trace;
        void* a_chcksum_pw;
        char* achl_principal=0;
        char* achl_trace_format="tkt_l=%lli, ren_l=%lli, "
            "princ=%s, skew=%lli, ret=%u, max_size=%i, def_realm=%s";
//        int inl_in1=1;
//        const int inl_in2=principal->name.name_string.len;
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        a_chcksum_pw=m_aux_stor_alloc( &a_temp_memory,20 );
        achl_principal=m_krb5_principalname2string( &a_temp_memory, achl_principal, &principal->name );
        achl_principal=m_krb5_strcat( &a_temp_memory, achl_principal, "@" );
        achl_principal=m_krb5_strcat( &a_temp_memory, achl_principal, principal->realm );
        m_krb5_sha1( context->passwd, strlen( context->passwd ), a_chcksum_pw, &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory,adsl_trace,a_chcksum_pw,20,"P-Hash:" );
        if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=3 ) {
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,NAME_OF_MAIN_LOC_GLOB_P,
                sizeof( struct dsd_global_and_static ),"NAME_OF_MAIN_LOC_GLOB_P:" );
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,context, sizeof( krb5_context_data ),
                "context:" );
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,opt,sizeof( krb5_get_init_creds_opt ),
                "opt:" );
        }
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',4001,
            adsl_trace, &a_temp_memory, achl_trace_format, opt->tkt_life, opt->renew_life,
            achl_principal, context->max_skew, context->max_retries, context->max_ticket_size,
            *( context->default_realms ) );
        m_aux_stor_end( &a_temp_memory );
    }
    ret = krb5_get_init_creds_password( NAME_OF_MAIN_LOC_GLOB_P, context,
        &cred,
        principal,
        context->passwd,
        NULL,
        NULL,
        context->start_time,
        context->server,
        opt );
    memset( context->passwd,0,strlen( context->passwd ) );
    krb5_get_init_creds_opt_free( NAME_OF_MAIN_LOC_GLOB_P, opt );
    if( ret ) {
        return ret;
    }
    ret = krb5_cc_initialize( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, cred.client );
    if( ret ){
        return ret;
    }
    ret = krb5_cc_store_cred( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, &cred );
    if( ret ){
        return ret;
    }
    krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &cred );
    m_free_arrays_file_h_hl( NAME_OF_MAIN_LOC_GLOB_P );
    return 0;
}

int
m_get_tgt( struct dsd_config_tgt * ads_conf )
{
   krb5_error_code ret;
   krb5_context context;
   krb5_ccache  ccache;
   krb5_principal principal;
   char * ach_cred_cache = PATH_CCACHE;
   struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
      ads_conf->aa_temp_memory_area,
      ads_conf->aa_memory_area,
      ads_conf->a_tracer,
      ads_conf->in_trace_lvl,
      ads_conf->a_ip_address_context);
   struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
   size_t szl_buf_len = strlen( ads_conf->ach_passwd )+1;

   ret = krb5_init_context( NAME_OF_MAIN_LOC_GLOB_P, &context );
   context->passwd = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len);
   strncpy( context->passwd,ads_conf->ach_passwd, szl_buf_len );
   context->renew_life     = ads_conf->im_renew_life;
   context->start_time     = ads_conf->im_start_time;
   context->server         = ads_conf->ach_server;
   context->max_retries    = ads_conf->im_max_retries;
   context->kdc_port       = ads_conf->im_kdc_port;
   context->max_skew       = ads_conf->im_max_skew;
   context->max_ticket_size= ads_conf->im_max_ticket_size;
   context->kdc_ip_address = ads_conf->a_kdc_ip_address;
   context->kdc_timeout    = ads_conf->im_timeout;
#ifdef WITHOUT_FILE
   context->tgt            = NULL;
   context->length_tgt     = 0;
#endif
   krb5_free_host_realm( NAME_OF_MAIN_LOC_GLOB_P, context, context->default_realms );
   context->default_realms    =
      memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 2 ) * ( sizeof( char* ) ) ),'\0',( 2 ) * ( sizeof( char* ) ) )
      ;
   szl_buf_len = strlen( ads_conf->ach_default_realm )+1;
   context->default_realms[0] =m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len );
   context->default_realms[1] = NULL;
   strncpy( context->default_realms[0],ads_conf->ach_default_realm, szl_buf_len );
   if( ret == KRB5_CONFIG_BADFORMAT ) {
      return ret;
   } else if( ret ) {
      return ret;
   }
   if( ads_conf->ach_princi_name ) {
      ret = krb5_parse_name( NAME_OF_MAIN_LOC_GLOB_P, context, ads_conf->ach_princi_name, &principal );
      if( ret ) {
         return ret;
      }
   } else {
      return 2;
   }
   krb5_set_fcache_version( NAME_OF_MAIN_LOC_GLOB_P, context, ads_conf->im_fcache_version );
   if( ach_cred_cache )
      ret = krb5_cc_resolve( NAME_OF_MAIN_LOC_GLOB_P, context, ach_cred_cache, &ccache );
   else
      return 2;
   if( ret ){
      return ret;
   }
   ret = get_new_tickets( NAME_OF_MAIN_LOC_GLOB_P, context, principal, ccache, ads_conf->im_ticket_life );
   if(ret){
      return ret;
   }
#ifdef WITHOUT_FILE
   ads_conf->a_tgt           = context->tgt;
   ads_conf->im_length_tgt   = context->length_tgt;
#endif
   krb5_cc_close( NAME_OF_MAIN_LOC_GLOB_P, context, ccache );
   ret = 0;
   //out:
   memset( context->passwd,0,strlen( ads_conf->ach_passwd ) );
   m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->passwd )
      ;
   context->passwd            = NULL;
   context->server            = NULL;
   context->kdc_ip_address    = 0;
   ach_cred_cache             = NULL;
   krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, principal );
#ifdef WITHOUT_FILE
   ads_conf->im_length_tgt = context->length_tgt;
   ads_conf->a_tgt        = m_aux_stor_alloc(( NAME_OF_MAIN_LOC_GLOB_P->aa_memory_area ),ads_conf->im_length_tgt );
   memcpy( ads_conf->a_tgt,context->tgt,ads_conf->im_length_tgt );
#endif
   return ret;
}

int
m_get_ticket( struct dsd_config_ticket * ads_conf )
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache cache;
    krb5_creds in, *out;
    krb5_kdc_flags flags;
    char * ach_cred_cache = PATH_CCACHE;
    struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
       ads_conf->aa_temp_memory_area,
       ads_conf->aa_memory_area,
       ads_conf->a_tracer,
       ads_conf->in_trace_lvl,
       ads_conf->a_ip_address_context);
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
    size_t szl_def_realm_len = strlen( ads_conf->ach_default_realm )+1;
    NAME_OF_MAIN_LOC_GLOB_P->im_control_1 = 0;
    ret = krb5_init_context( NAME_OF_MAIN_LOC_GLOB_P, &context );
    m_init_enctypes( NAME_OF_MAIN_LOC_GLOB_P, context );
    flags.i = 0;
    context->passwd         = NULL;
    context->server         = ads_conf->ach_server;
    context->max_retries    = ads_conf->im_max_retries;
    context->kdc_port       = ads_conf->im_kdc_port;
    context->max_skew       = ads_conf->im_max_skew;
    context->max_ticket_size= ads_conf->im_max_ticket_size;
    context->kdc_ip_address = ads_conf->a_kdc_ip_address;
    context->kdc_timeout    = ads_conf->im_timeout;
#ifdef WITHOUT_FILE
    context->tgt            =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( ads_conf->im_length_tgt ) * ( 1 ) ),'\0',( ads_conf->im_length_tgt ) * ( 1 ) )
        ;
    memcpy( context->tgt, ads_conf->a_tgt, ( ads_conf->im_length_tgt ) );
    context->length_tgt     = ads_conf->im_length_tgt;
#endif
    krb5_free_host_realm( NAME_OF_MAIN_LOC_GLOB_P, context, context->default_realms );
    context->default_realms    =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 2 ) * ( sizeof( char* ) ) ),'\0',( 2 ) * ( sizeof( char* ) ) )
        ;
    context->default_realms[0] = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_def_realm_len );
    context->default_realms[1] = NULL;
    strncpy( context->default_realms[0],ads_conf->ach_default_realm, szl_def_realm_len );
    if( ret ) {
        return 2;
    }
    if( ach_cred_cache ) {
        ret = krb5_cc_resolve( NAME_OF_MAIN_LOC_GLOB_P, context, ach_cred_cache, &cache );
    } else {
        return 2;
    }
    if( ret ){
        return ret;
    }
    memset( &in, 0, sizeof( in ) );
    ret = krb5_cc_get_principal( NAME_OF_MAIN_LOC_GLOB_P, context, cache, &in.client );
    if( ret ){
        return ret;
    }
    ret = krb5_parse_name( NAME_OF_MAIN_LOC_GLOB_P, context, context->server, &in.server );
    if( ret ){
        return ret;
    }
    in.times.endtime   = time(( void* )0 ) + ads_conf->im_ticket_life;
    //StSch Trace Point
    ret = krb5_get_credentials_with_flags( NAME_OF_MAIN_LOC_GLOB_P, context, 0, flags, cache, &in, &out );
    if( ret ){
        return ret;
    }
#ifdef WITHOUT_FILE
    ads_conf->im_length_tgt = context->length_tgt;
    ads_conf->a_tgt         = m_aux_stor_alloc(( NAME_OF_MAIN_LOC_GLOB_P->aa_memory_area ),ads_conf->im_length_tgt );
    memcpy( ads_conf->a_tgt,context->tgt,ads_conf->im_length_tgt );
#endif
    return 0;
}



int m_init_sec_context_client( struct dsd_heimdal_context*,const e_krb5_flags );
int m_init_sec_context_server( struct dsd_heimdal_context* , struct dsd_config_server *);

int m_init_krb5_context( struct dsd_heimdal_context*,
struct dsd_config_server_client*,void* );
int m_krb5_data_free( struct dsd_heimdal_context*,
                     krb5_data* );

int m_init_sec_context_server( struct dsd_heimdal_context * ads_context_main, struct dsd_config_server * ads_conf )
{
    krb5_error_code im_ret;
    krb5_principal_data ds_serv;
    krb5_flags ap_options;
    krb5_ticket *a_ticket;
    krb5_context ads_context;
    krb5_auth_context * aads_auth_context;
    krb5_data  * ads_data_i;
    krb5_data  * ads_data_o;
    struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
       ads_conf->aa_temp_memory_area,
       ads_conf->aa_memory_area,
       ads_conf->a_tracer,
       ads_conf->in_trace_lvl,
       ads_conf->a_ip_address_context);
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
    ads_context_main->NAME_OF_MAIN_LOC_GLOB_P =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( struct dsd_global_and_static ) )
        ;
    memcpy( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P,NAME_OF_MAIN_LOC_GLOB_P,sizeof( struct dsd_global_and_static ) );
    NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    NAME_OF_MAIN_LOC_GLOB_P->im_control_4 = 0;
    im_ret = krb5_init_context( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context ) );
    if( im_ret ) {
        return im_ret;
    }
    m_init_enctypes( NAME_OF_MAIN_LOC_GLOB_P, ads_context );
    ads_context->default_realms     =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 2 ) * ( sizeof( char* ) ) ),'\0',( 2 ) * ( sizeof( char* ) ) )
        ;
    ads_context->default_realms[1]  = NULL;
    ads_context->default_realms[0] = NULL; /** @todo check, which data is acutally used/available */
    ads_context->max_skew           = ads_conf->inc_max_skew;
    ads_context->client_server      = ads_conf->inc_keytab_len; /* Use this field to transfer Keytab len */
    ads_context->default_cc_name    = NULL;
    ads_context->default_keytab = ads_conf->achc_keytab ;
    im_ret = krb5_auth_con_init( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
        ( krb5_auth_context* )&( ads_context_main->ads_auth_context ) );
    if( im_ret ){
        return im_ret;
    }
//    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context_main->ds_data_init_in ) );
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context_main->ds_data_init_out ) );
    ads_context_main->ads_context = ads_context;
    memset(&ds_serv, 0, sizeof(struct Principal));

    aads_auth_context = ( krb5_auth_context* )&( ads_context_main->ads_auth_context );
    ads_data_i              = &( ads_context_main->ds_data_init_in );
    ads_data_o              = &( ads_context_main->ds_data_init_out );
    im_ret = krb5_rd_req( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
        aads_auth_context,
        ads_data_i,
        &ds_serv,
        NULL,
        &ap_options,
        &a_ticket );
    if( im_ret ) {
        krb5_error_code im_ret2;
        im_ret2 = krb5_mk_error( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
            im_ret,
            NULL,
            NULL,
            NULL,
            &ds_serv,
            NULL,
            NULL,
            ads_data_o );
        if( im_ret2 != 0 ) {
            krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, ads_data_o );
        }
        return im_ret;
    } else if( ap_options & AP_OPTS_MUTUAL_REQUIRED ) {
        im_ret = krb5_mk_rep( NAME_OF_MAIN_LOC_GLOB_P, ads_context, *aads_auth_context, ads_data_o );
        if( im_ret ) {
            krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, ads_data_o );
            return im_ret;
        }
        if(a_ticket->client){
            ads_context_main->ach_hostname = (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,ads_conf->inc_keytab_len);
            krb5_unparse_name_fixed(NAME_OF_MAIN_LOC_GLOB_P, ads_context,a_ticket->client,ads_context_main->ach_hostname,ads_conf->inc_keytab_len);
        }
        if(a_ticket->server){
            ads_context_main->ach_service = (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ads_conf->inc_keytab_len);
            krb5_unparse_name_fixed(NAME_OF_MAIN_LOC_GLOB_P, ads_context,a_ticket->server, ads_context_main->ach_service, ads_conf->inc_keytab_len);
        }
    } else
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, ads_data_o );
    ads_context_main->a_gen_ptr=NAME_OF_MAIN_LOC_GLOB_P->a_krb5_auth_hash;
    return 0;
}

int m_init_sec_context_client( struct dsd_heimdal_context * ads_context_main,
                              const e_krb5_flags ap_req_options )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_error_code im_ret, im_ret_2;
    krb5_principal ads_serv;
    krb5_creds ds_this_cred;
    krb5_creds *ads_creds;
    krb5_ccache ads_ccache     = NULL;
    krb5_principal ads_client  = NULL;
    krb5_creds *ads_in_creds   = NULL;
    krb5_context ads_context             = ( krb5_context )( ads_context_main->ads_context );
    krb5_auth_context * aads_auth_context = ( krb5_auth_context* )&( ads_context_main->ads_auth_context );
    if( ads_context_main->im_switch ) {
        krb5_data  * ads_ap_req   = &( ads_context_main->ds_data_init_out );
        const char * ach_hostname = ads_context_main->ach_hostname;
        const char * ach_service  = ads_context_main->ach_service;
        Checksum c_opt;
        im_ret = krb5_make_principal( NAME_OF_MAIN_LOC_GLOB_P, ads_context, &ads_serv,
            ads_context->default_realms[0],
            ach_service, ach_hostname );
        if( im_ret ){
            return im_ret;
        }
        if( ads_context->default_cc_name ) {
            im_ret = krb5_cc_resolve( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_context->default_cc_name, &ads_ccache );
        } else{
            return 2;
        }
        if( im_ret ){
            return im_ret;
        }
        im_ret = krb5_cc_get_principal( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_ccache, &ads_client );
        if( im_ret ) {
            krb5_cc_close( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_ccache );
            return im_ret;
        }
        memset( &ds_this_cred, 0, sizeof( ds_this_cred ) );
        ds_this_cred.client = ads_client;
        ds_this_cred.server = ads_serv;
        ds_this_cred.times.endtime = 0;
        ds_this_cred.ticket.length = 0;
        ads_in_creds = &ds_this_cred;
        im_ret = krb5_get_credentials( NAME_OF_MAIN_LOC_GLOB_P, ads_context, 0, ads_ccache,
            ads_in_creds, &ads_creds );
        krb5_cc_close( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_ccache );
        if( im_ret ){
            return im_ret;
        }
        ads_context->c_opt = &c_opt;
        {
            OM_uint32 minor_status = 0;
            krb5_data fwd_data;
            u_int32_t flags = 0;
            krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &fwd_data );
            flags |= GSS_C_SEQUENCE_FLAG;
            flags |= GSS_C_CONF_FLAG;
            flags |= GSS_C_INTEG_FLAG;
            flags |= GSS_C_TRANS_FLAG;
            if( ap_req_options == AP_OPTS_MUTUAL_REQUIRED_e )
                flags |= GSS_C_MUTUAL_FLAG;
            im_ret = gssapi_krb5_create_8003_checksum( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
                (( gss_channel_bindings_t ) 0 ),
                flags,
                &fwd_data,
                &c_opt );
            if( im_ret ){
                return im_ret;
            }
        }
        im_ret = krb5_mk_req_extended( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
            aads_auth_context,
            ap_req_options == AP_OPTS_MUTUAL_REQUIRED_e ? AP_OPTS_MUTUAL_REQUIRED : 0,
            NULL,
            ads_creds,
            ads_ap_req );
        //StSch Trace Point
        krb5_free_creds( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_creds );
        krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_client );
        if( im_ret ){
            return im_ret;
        }
        ads_context_main->im_switch = 0;
    } else if( ap_req_options == AP_OPTS_MUTUAL_REQUIRED_e ) {
        krb5_data  * ads_ap_req     = &( ads_context_main->ds_data_init_in );
        krb5_ap_rep_enc_part *a_ignore;
        im_ret = krb5_rd_rep( NAME_OF_MAIN_LOC_GLOB_P, ads_context, *aads_auth_context, ads_ap_req, &a_ignore );
        if( im_ret ) {
            //StSch Trace Point 4002
            KRB_ERROR ds_error;
            im_ret_2 = krb5_rd_error( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_ap_req, &ds_error );
            if( !im_ret_2 ) {
                im_ret_2 = krb5_error_from_rd_error( NAME_OF_MAIN_LOC_GLOB_P, ads_context, &ds_error, NULL );
                if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
                    void* a_temp_memory=0;
                    struct dsd_memory_traces* adsl_trace;
                    char* achl_cname=0;
                    char* achl_sname=0;
                    char* achl_crealm="";
                    long long ill_ctime=0;
                    int inl_cusec=0;
                    char* achl_msg_format="KRB-ERROR: pvno=%i, msg-type=%i, ctime=%lli, cusec=%i, "
                        "stime=%lli, susec=%i, e-code=%i, crealm=%s, cname=%s, "
                        "realm=%s, sname=%s";
                    m_aux_stor_start( &a_temp_memory );
                    adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
                    achl_cname=m_krb5_principalname2string( &a_temp_memory, achl_cname, ds_error.cname );
                    achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &ds_error.sname );
                    if( ds_error.crealm!=NULL ) {
                        achl_crealm=*ds_error.crealm;
                    }
                    if( ds_error.ctime!=NULL ) {
                        ill_ctime=*ds_error.ctime;
                    }
                    if( ds_error.cusec!=NULL ) {
                        inl_cusec=*ds_error.cusec;
                    }
                    m_krb5_trace(( struct krb5_tracer* )NAME_OF_MAIN_LOC_GLOB_P->a_tracer,'T',
                        4002, adsl_trace,&a_temp_memory, achl_msg_format,
                        ds_error.pvno,ds_error.msg_type,ill_ctime,inl_cusec,ds_error.stime,
                        ds_error.susec, ds_error.error_code, achl_crealm,achl_cname,
                        ds_error.realm,achl_sname );
                    m_aux_stor_end( &a_temp_memory );
                }
                krb5_free_error_contents( NAME_OF_MAIN_LOC_GLOB_P, ads_context, &ds_error );
                return im_ret_2;
            }
        }
        if( im_ret ) {
            return im_ret;
        }
        krb5_free_ap_rep_enc_part( NAME_OF_MAIN_LOC_GLOB_P, ads_context, a_ignore );
        ads_context_main->im_switch = 1;
    }
    return 0;
}

int m_init_krb5_context( struct dsd_heimdal_context * ads_context_main,
struct dsd_config_server_client * ads_conf,
    void * a_add_conf )
{
    krb5_error_code im_ret;
    krb5_context ads_context;
    struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
       ads_conf->aa_temp_memory_area,
       ads_conf->aa_memory_area,
       ads_conf->a_tracer,
       ads_conf->in_trace_lvl,
       ads_conf->a_ip_address_context);
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
    size_t szl_buf_len = strlen( ads_conf->ach_default_realm )+1;
    ads_context_main->NAME_OF_MAIN_LOC_GLOB_P =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( struct dsd_global_and_static ) )
        ;
    memcpy( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P,NAME_OF_MAIN_LOC_GLOB_P,sizeof( struct dsd_global_and_static ) );
    NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    NAME_OF_MAIN_LOC_GLOB_P->im_control_4 = 0;
    im_ret = krb5_init_context( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context ) );
    if( im_ret ) {
        return im_ret;
    }
    m_init_enctypes( NAME_OF_MAIN_LOC_GLOB_P, ads_context );
    ads_context->default_realms     =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 2 ) * ( sizeof( char* ) ) ),'\0',( 2 ) * ( sizeof( char* ) ) )
        ;
    ads_context->default_realms[0]  = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len);
    ads_context->default_realms[1]  = NULL;
    strncpy( ads_context->default_realms[0],ads_conf->ach_default_realm, szl_buf_len );
    ads_context->max_skew           = ads_conf->im_max_skew;
    ads_context->client_server      = 1;
    ads_context_main->ach_hostname = ads_conf->ach_hostname;
    ads_context_main->ach_service = ads_conf->ach_service;
    ads_context->add_serv_realms    =
        ads_conf->aach_additional_hostnames;
    ads_context->number_add_ser_rea = ads_conf->im_number_add_names;
    if( ads_conf->ch_bool == 'c' ) {
        struct dsd_config_client * ads_conf_cli = ( struct dsd_config_client * )a_add_conf;
        ads_context->passwd             = NULL;
        ads_context->default_cc_name    = PATH_CCACHE;
        krb5_set_fcache_version( NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_conf_cli->im_fcache_version );
        ads_context_main->im_switch                       = 1;
#ifdef WITHOUT_FILE
        ads_context->tgt               =
            memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( ads_conf_cli->im_length_tgt ) * ( 1 ) ),'\0',( ads_conf_cli->im_length_tgt ) * ( 1 ) )
            ;
        memcpy( ads_context->tgt, ads_conf_cli->a_tgt, ( ads_conf_cli->im_length_tgt ) );
        ads_context->length_tgt        = ads_conf_cli->im_length_tgt;
#endif
    } else if( ads_conf->ch_bool == 's' ) {
       szl_buf_len = strlen(( char* )a_add_conf )+1;
        ads_context->passwd= m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len );
        strncpy( ads_context->passwd, ( char* )a_add_conf, szl_buf_len );
        ads_context->default_cc_name    = NULL;
    } else {
        return 2;
    }
    if( !ads_context_main->ach_service || !ads_context_main->ach_hostname ){
        return 2;
    }
    if( !strcmp( ads_context_main->ach_service,"" ) || !strcmp( ads_context_main->ach_hostname,"" ) ){
        return 2;
    }
    im_ret = krb5_auth_con_init( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
        ( krb5_auth_context* )&( ads_context_main->ads_auth_context ) );
    if( im_ret ){
        return im_ret;
    }
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context_main->ds_data_init_in ) );
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &( ads_context_main->ds_data_init_out ) );
    ads_context_main->ads_context = ads_context;
    return 0;
}

int m_krb5_data_free( struct dsd_heimdal_context * ads_context_main,
                     krb5_data * ads_pac )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, ads_pac );
    return 0;
}

int m_gss_encapsulate( struct dsd_heimdal_context * ads_context_main,
                      krb5_data * ads_outbuf, krb5_data * ads_outbuf_gss,
                      const char * ach_token_id )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_error_code im_ret;
    OM_uint32 minor_status = 0;
    gss_OID_desc gss_krb5_mechanism_oid_desc =
    {9, ( void * )"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
    im_ret = gssapi_krb5_encapsulate( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
        ads_outbuf,
        ( gss_buffer_t )ads_outbuf_gss,
        ach_token_id,
        &gss_krb5_mechanism_oid_desc );
    //StSch Trace Point 4003
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        char* achl_trace_format="";
        struct dsd_memory_traces* adsl_trace;
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ads_outbuf_gss->data,32,"GSS Header:" );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',4003,
            adsl_trace, &a_temp_memory, achl_trace_format );
        m_aux_stor_end( &a_temp_memory );
    }
    if( im_ret ){
        return im_ret;
    }
    return 0;
}

int m_gss_decapsulate( struct dsd_heimdal_context * ads_context_main,
                      krb5_data * ads_input_token, krb5_data * ads_input_token_gss,
                      const char * ach_token_id,
                      const char * ach_token_id_2 )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_error_code im_ret;
    OM_uint32 minor_status = 0;
    gss_OID_desc gss_krb5_mechanism_oid_desc =
    {9, ( void * )"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
    //StSch Trace Point 4004
    if( NAME_OF_MAIN_LOC_GLOB_P != NULL && NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl >= 2 ) {
        void * a_temp_memory;
        char* achl_trace_format="";
        struct dsd_memory_traces* adsl_trace;
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ads_input_token_gss->data,32,"GSS Header:" );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',4004,
            adsl_trace, &a_temp_memory, achl_trace_format );
        m_aux_stor_end( &a_temp_memory );
    }
    im_ret = gssapi_krb5_decapsulate( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
        ( gss_buffer_t )ads_input_token_gss,
        ads_input_token,
        ach_token_id,
        &gss_krb5_mechanism_oid_desc );
    if( im_ret == GSS_S_DEFECTIVE_TOKEN && ach_token_id_2 )
        //StSch Trace Point
        im_ret = gssapi_krb5_decapsulate( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
        ( gss_buffer_t )ads_input_token_gss,
        ads_input_token,
        ach_token_id_2,
        &gss_krb5_mechanism_oid_desc );
    if( im_ret ){
        return im_ret;
    }
    return 0;
}

extern krb5_context gssapi_krb5_context;
struct gss_msg_order;

int m_get_gss_session_key(struct dsd_heimdal_context * adsp_context_main, char* achp_out_buf, int inp_out_len, int* ainp_key_len){
   struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( adsp_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    OM_uint32 minor_status = 0;
    struct gss_ctx_id_t_desc_struct context_handle;
    krb5_keyblock * adsl_key = NULL;
    int inl_ret = 0;

    // Check, if context is propperly initialized
    if ( (NULL == adsp_context_main->ads_auth_context) ||
         ( NULL == adsp_context_main->ads_context))
    {
       return -4;
    }
    context_handle.auth_context = ( krb5_auth_context )( adsp_context_main->ads_auth_context );
    context_handle.flags        = 0;
    context_handle.lifetime     = 0;
    context_handle.more_flags   = 0;
    context_handle.ticket       = NULL;
    context_handle.order        = NULL;
    context_handle.source       = NULL;
    context_handle.target       = NULL;
    NAME_OF_MAIN_LOC_GLOB_P->
        gssapi_krb5_context = ( krb5_context )( adsp_context_main->ads_context );

    // fetch subkey
    inl_ret = gss_krb5_get_subkey( NAME_OF_MAIN_LOC_GLOB_P, &context_handle, &adsl_key);

    if(0 == inl_ret){
       // Copy key, if sufficient buffer is there. Set key length
       *ainp_key_len = adsl_key->keyvalue.length;
       if(adsl_key->keyvalue.length <= inp_out_len){
          memcpy(achp_out_buf, adsl_key->keyvalue.data, *ainp_key_len);
       } else {
          inl_ret = -1;
       }
    } else {
       // no key error
       inl_ret = -2;
    }

    // Release key structure as necessary
    if(NULL != adsl_key){
       free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, adsl_key);
       m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, adsl_key );
    }

    return inl_ret;
}

int m_gss_wrap( struct dsd_heimdal_context * ads_context_main,
               krb5_data * ads_inbuf, krb5_data * ads_outbuf )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_error_code im_ret;
    OM_uint32 minor_status = 0;
    struct gss_ctx_id_t_desc_struct context_handle;
    context_handle.auth_context = ( krb5_auth_context )( ads_context_main->ads_auth_context );
    context_handle.flags        = 0;
    context_handle.lifetime     = 0;
    context_handle.more_flags   = 0;
    context_handle.ticket       = NULL;
    context_handle.order        = NULL;
    context_handle.source       = NULL;
    context_handle.target       = NULL;
    NAME_OF_MAIN_LOC_GLOB_P->
        gssapi_krb5_context = ( krb5_context )( ads_context_main->ads_context );
    im_ret = gss_wrap( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
        &context_handle,
        1,
        GSS_C_QOP_DEFAULT,
        ( gss_buffer_t )ads_inbuf,
        NULL,
        ( gss_buffer_t )ads_outbuf
        );
    //StSch Trace Point 4005
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        char* achl_trace_format="";
        struct dsd_memory_traces* adsl_trace;
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ads_outbuf->data,16,"GSS Header:" );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',4005,
            adsl_trace, &a_temp_memory, achl_trace_format );
        m_aux_stor_end( &a_temp_memory );
    }
    if( im_ret ){
        return im_ret;
    }
    return 0;
}

int m_gss_unwrap( struct dsd_heimdal_context * ads_context_main,
                 krb5_data * ads_inbuf, krb5_data * ads_outbuf )
{
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_error_code im_ret;
    OM_uint32 minor_status = 0;
    int conf_flag;
    struct gss_ctx_id_t_desc_struct context_handle;
    context_handle.auth_context = ( krb5_auth_context )( ads_context_main->ads_auth_context );
    context_handle.flags        = 0;
    context_handle.lifetime     = 0;
    context_handle.more_flags   = LOCAL;
    context_handle.ticket       = NULL;
    context_handle.order        = NULL;
    context_handle.source       = NULL;
    context_handle.target       = NULL;
    NAME_OF_MAIN_LOC_GLOB_P->
        gssapi_krb5_context = ( krb5_context )( ads_context_main->ads_context );
    NAME_OF_MAIN_LOC_GLOB_P->im_control_5 = 0;
    im_ret = gss_unwrap( NAME_OF_MAIN_LOC_GLOB_P, &minor_status,
        &context_handle,
        ( gss_buffer_t )ads_inbuf,
        ( gss_buffer_t )ads_outbuf,
        &conf_flag,
        NULL
        );
    NAME_OF_MAIN_LOC_GLOB_P->im_control_5 = 1;
    if( im_ret ){
        return im_ret;
    }
    return 0;
}

struct dsd_config_pw {
    char * ach_princi_name;
    char * ach_passwd;
    char * ach_new_passwd;
    char * ach_default_realm;
    char * ach_server;
    void * a_kdc_ip_address;
    int im_kdc_port;
    int im_kdc_pw_change_port;
    int im_max_retries;
    int im_fcache_version;
    int im_max_skew;
    int im_max_ticket_size;
    void ** aa_memory_area;
    void ** aa_temp_memory_area;
    void * a_tracer;
    int in_trace_lvl;
    void * a_ip_address_context;
    int im_timeout;
};

int
m_change_pw( struct dsd_config_pw * ads_conf )
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache  ccache;
    krb5_principal principal;
    char * ach_cred_cache = PATH_CCACHE;
    krb5_get_init_creds_opt *opt;
    krb5_creds cred;
    int number;
    krb5_addresses no_addrs;
    struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
       ads_conf->aa_temp_memory_area,
       ads_conf->aa_memory_area,
       ads_conf->a_tracer,
       ads_conf->in_trace_lvl,
       ads_conf->a_ip_address_context);
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
    size_t szl_buf_len = strlen( ads_conf->ach_passwd )+1;
    ret = krb5_init_context( NAME_OF_MAIN_LOC_GLOB_P, &context );
    context->passwd = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len );
    strncpy( context->passwd,ads_conf->ach_passwd, szl_buf_len );
    context->renew_life     = 0;
    context->start_time     = 0;
    context->server         = ads_conf->ach_server;
    context->max_retries    = ads_conf->im_max_retries;
    context->kdc_port       = ads_conf->im_kdc_port;
    context->max_skew       = ads_conf->im_max_skew;
    context->max_ticket_size= ads_conf->im_max_ticket_size;
    context->kdc_ip_address = ads_conf->a_kdc_ip_address;
    context->kdc_timeout    = ads_conf->im_timeout;
#ifdef WITHOUT_FILE
    context->tgt            = NULL;
    context->length_tgt     = 0;
#endif
    krb5_free_host_realm( NAME_OF_MAIN_LOC_GLOB_P, context, context->default_realms );
    context->default_realms    =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 2 ) * ( sizeof( char* ) ) ),'\0',( 2 ) * ( sizeof( char* ) ) )
        ;
    szl_buf_len = strlen( ads_conf->ach_default_realm )+1;
    context->default_realms[0] = m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, szl_buf_len );
    context->default_realms[1] = NULL;
    strncpy( context->default_realms[0],ads_conf->ach_default_realm, szl_buf_len );
    if( ret == KRB5_CONFIG_BADFORMAT ) {
        ;
        goto out;
    } else if( ret ) {
        ;
        goto out;
    }
    if( ads_conf->ach_princi_name ) {
        ret = krb5_parse_name( NAME_OF_MAIN_LOC_GLOB_P, context, ads_conf->ach_princi_name, &principal );
        if( ret ){
            return ret;
        }
    } else {
        return 2;
    }
    krb5_set_fcache_version( NAME_OF_MAIN_LOC_GLOB_P, context, ads_conf->im_fcache_version );
    if( ach_cred_cache )
        ret = krb5_cc_resolve( NAME_OF_MAIN_LOC_GLOB_P, context, ach_cred_cache, &ccache );
    else{
        return 2;
    }
    if( ret ){
        return ret;
    }
    memset( &cred, 0, sizeof( cred ) );
    ret = krb5_get_init_creds_opt_alloc( NAME_OF_MAIN_LOC_GLOB_P, context, &opt );
    if( ret ){
        return ret;
    }
    krb5_get_init_creds_opt_set_forwardable( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->forwardable_flag );
    krb5_get_init_creds_opt_set_proxiable( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->proxiable_flag );
    krb5_get_init_creds_opt_set_anonymous( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->anonymous_flag );
    no_addrs.len = 0;
    no_addrs.val = NULL;
    krb5_get_init_creds_opt_set_address_list( NAME_OF_MAIN_LOC_GLOB_P, opt,          &no_addrs );
    krb5_get_init_creds_opt_set_renew_life( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->renew_life );
    krb5_get_init_creds_opt_set_tkt_life( NAME_OF_MAIN_LOC_GLOB_P, opt, 6000 );
    number = m_init_enctypes( NAME_OF_MAIN_LOC_GLOB_P, context );
    krb5_get_init_creds_opt_set_etype_list( NAME_OF_MAIN_LOC_GLOB_P, opt,          context->etypes, number );
    //StSch Trace Point 4006
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        struct dsd_memory_traces* adsl_trace;
        void* a_chcksum_pw;
        char* achl_principal=0;
        char* achl_trace_format="tkt_l=%lli, ren_l=%lli, "
            "princ=%s, skew=%lli, ret=%u, max_size=%i, def_realm=%s";
//        int inl_in1=1;
//        const int inl_in2=principal->name.name_string.len;
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        a_chcksum_pw=m_aux_stor_alloc( &a_temp_memory,20 );
        achl_principal=m_krb5_principalname2string( &a_temp_memory, achl_principal, &principal->name );
        achl_principal=m_krb5_strcat( &a_temp_memory, achl_principal, "@" );
        achl_principal=m_krb5_strcat( &a_temp_memory, achl_principal, principal->realm );
        m_krb5_sha1( context->passwd, strlen( context->passwd ), a_chcksum_pw, &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory,adsl_trace,a_chcksum_pw,20,"P-Hash:" );
        if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=3 ) {
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,NAME_OF_MAIN_LOC_GLOB_P,
                sizeof( struct dsd_global_and_static ),"NAME_OF_MAIN_LOC_GLOB_P:" );
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,context, sizeof( krb5_context_data ),
                "context:" );
            m_krb5_trace_memcat( &a_temp_memory,adsl_trace,opt,sizeof( krb5_get_init_creds_opt ),
                "opt:" );
        }
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',4006,
            adsl_trace, &a_temp_memory, achl_trace_format, opt->tkt_life, opt->renew_life,
            achl_principal, context->max_skew, context->max_retries, context->max_ticket_size,
            *( context->default_realms ) );
        m_aux_stor_end( &a_temp_memory );
    }
    ret = change_password (NAME_OF_MAIN_LOC_GLOB_P,
        context,
        principal,
        context->passwd,
        ads_conf->ach_new_passwd,
        strlen(ads_conf->ach_new_passwd),
        ads_conf->im_kdc_pw_change_port,
        NULL,
        opt);
    memset( context->passwd,0,strlen( context->passwd ) );
    krb5_get_init_creds_opt_free( NAME_OF_MAIN_LOC_GLOB_P, opt );
    if( ret ){
        return ret;
    }
    krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &cred );
    m_free_arrays_file_h_hl( NAME_OF_MAIN_LOC_GLOB_P );
    krb5_cc_close( NAME_OF_MAIN_LOC_GLOB_P, context, ccache );
    ret = 0;
out:
    memset( context->passwd,0,strlen( ads_conf->ach_passwd ) );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->passwd )
        ;
    context->passwd            = NULL;
    context->server            = NULL;
    context->kdc_ip_address    = 0;
    ach_cred_cache             = NULL;
//    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, principal );
    return ret;
}

void m_krb5_trace_memcat( void ** aap_mem_addr, struct dsd_memory_traces* dsp_trace,
                         void* ap_memory_area, int inp_mem_length, const char* achp_mem_name )
{
    dsp_trace->in_mem_count++;
    dsp_trace->aa_memory_area=( const void** )m_aux_stor_realloc( aap_mem_addr,dsp_trace->aa_memory_area,
        ( dsp_trace->in_mem_count )*sizeof( void* ) );
    dsp_trace->ain_mem_len=( int* )m_aux_stor_realloc( aap_mem_addr,dsp_trace->ain_mem_len,
        ( dsp_trace->in_mem_count )*sizeof( int ) );
    dsp_trace->aach_mem_names=( char** )m_aux_stor_realloc( aap_mem_addr,dsp_trace->aach_mem_names,
        ( dsp_trace->in_mem_count )*sizeof( char* ) );
    *( dsp_trace->aa_memory_area+dsp_trace->in_mem_count-1 )=ap_memory_area;
    *( dsp_trace->ain_mem_len+dsp_trace->in_mem_count-1 )=inp_mem_length;
    *( dsp_trace->aach_mem_names+dsp_trace->in_mem_count-1 )=achp_mem_name;
}//void m_krb5_trace_memcat(void** aap_memory_ptr, struct dsd_memory_traces* dsp_trace, void* ap_memory_area, int inp_mem_length, char* achp_mem_name);

struct dsd_memory_traces* m_init_krb5_mem_trace( void ** aap_mem_addr ) {
    struct dsd_memory_traces* ds_mem_trace;
    ds_mem_trace=( struct dsd_memory_traces* )m_aux_stor_alloc( aap_mem_addr, sizeof( struct dsd_memory_traces ) );
    ds_mem_trace->aa_memory_area=( void** )m_aux_stor_alloc( aap_mem_addr, sizeof( void* ) );
    ds_mem_trace->ain_mem_len=( int* )m_aux_stor_alloc( aap_mem_addr, sizeof( int ) );
    ds_mem_trace->aach_mem_names=( char** )m_aux_stor_alloc( aap_mem_addr, sizeof( char* ) );
    ds_mem_trace->in_mem_count=0;
    return ds_mem_trace;
}//struct dsd_memory_traces* m_init_krb5_mem_trace(void** aap_memory_ptr);

void m_free_krb5_mem_trace( void ** aap_mem_addr, struct dsd_memory_traces* adsl_trace )
{
    m_aux_stor_free( aap_mem_addr, adsl_trace->aa_memory_area );
    m_aux_stor_free( aap_mem_addr, adsl_trace->aach_mem_names );
    m_aux_stor_free( aap_mem_addr, adsl_trace->ain_mem_len );
    m_aux_stor_free( aap_mem_addr, adsl_trace );
}//void m_free_krb5_mem_trace(void** aap_memory_ptr, struct dsd_memory_traces* adsl_trace);

char* m_krb5_principalname2string( void ** aap_mem_addr, char* achp_dest, struct PrincipalName* ads_src )
{
    int inl_in1=1;
    if( achp_dest==NULL ) {
        achp_dest=( char* )m_aux_stor_alloc( aap_mem_addr,1 );
    }
    memset( achp_dest,'\0',1 );
    if( ads_src==NULL ) {
        return achp_dest;
    }
    achp_dest=m_krb5_strcat( aap_mem_addr, achp_dest, *ads_src->name_string.val );
    for( ; inl_in1<ads_src->name_string.len; inl_in1++ ) {
        achp_dest=m_krb5_strcat( aap_mem_addr, achp_dest, "/" );
        achp_dest=m_krb5_strcat( aap_mem_addr, achp_dest, *( ads_src->name_string.val+inl_in1 ) );
    }
    return achp_dest;
}//void m_krb5_principalname2string(void** aap_memory_ptr, char* achp_dest, struct PrincipalName* ads_src);

int m_krb5_mk_error(struct dsd_heimdal_context * ads_context_main, krb5_data** aadsp_out_buf, int inp_error_code ){
    krb5_principal_data dsl_principal;
    struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P = ( struct dsd_global_and_static* )( ads_context_main->NAME_OF_MAIN_LOC_GLOB_P );
    krb5_context ads_context             = ( krb5_context )( ads_context_main->ads_context );

    krb5_parse_name(NAME_OF_MAIN_LOC_GLOB_P, ads_context, ads_context_main->ach_service, &dsl_principal);
    return krb5_mk_error( NAME_OF_MAIN_LOC_GLOB_P, ads_context,
            inp_error_code,
            NULL,
            NULL,
            NULL,
            &dsl_principal,
            NULL,
            NULL,
            *aadsp_out_buf );
}//int m_krb5_mk_error(struct dsd_heimdal_context * ads_context_main, krb5_data** aadsp_out_buf, int inp_error_code );
#undef MALLOC
#undef FREE
